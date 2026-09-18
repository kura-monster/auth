const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');

const { renderTemplate } = require('./security/render');
const { signPayload, verifyPayload, randomToken, fingerprint, timingSafeEqualStr } = require('./security/crypto');
const { resolveClientIp, subnetKey, expressTrustProxyFn, describeTrustConfig, diagnoseTrustConfig } = require('./security/net');
const { assessNetwork, stats: reputationStats } = require('./security/reputation');
const challenge = require('./security/challenge');
const { securityHeaders, issueSessionCookie, readSessionCookie, clearSessionCookie, isSecureDeployment } = require('./security/http');
const { TtlMap, SlidingWindowLimiter, register, startSweeper } = require('./security/store');
const { getBannedGuilds } = require('./bannedGuilds');

const VIEWS = path.join(__dirname, 'views');
const DISCORD_API = 'https://discord.com/api/v10';
const USER_FLAG_SPAMMER = 1 << 20;

const stateNonces = register(new TtlMap('oauth-state', 20000));
const pendingVerifications = register(new TtlMap('pending-verification', 20000));
const resultTokens = register(new TtlMap('result-token', 20000));

const limiters = {
  start: register(new SlidingWindowLimiter('start', { windowMs: 10 * 60 * 1000, limit: 30 })),
  callback: register(new SlidingWindowLimiter('callback', { windowMs: 10 * 60 * 1000, limit: 30 })),
  verify: register(new SlidingWindowLimiter('verify', { windowMs: 10 * 60 * 1000, limit: 40 })),
  logNotify: register(new SlidingWindowLimiter('log-notify', { windowMs: 60 * 1000, limit: 20 }))
};

const admissionTracker = { successes: 0, windowStart: Date.now() };

const metrics = {
  started: 0,
  succeeded: 0,
  blockedNetwork: 0,
  blockedChallenge: 0,
  blockedGuild: 0,
  blockedRate: 0,
  blockedState: 0,
  errors: 0,
  bootedAt: Date.now()
};

startSweeper(60000);

function publicBaseUrl() {
  if (process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL.replace(/\/+$/, '');
  try {
    const url = new URL(process.env.REDIRECT_URI);
    return url.origin;
  } catch {
    return `http://localhost:${process.env.PORT || 3000}`;
  }
}

function sessionTtlMs() {
  return parseInt(process.env.CHALLENGE_TTL_SECONDS || '600', 10) * 1000;
}

function checkGlobalAdmission() {
  if (process.env.BLOCK_NEW_ADMISSIONS === 'true') {
    return { allowed: false, reason: '現在、管理者の設定により新規の認証受付を停止しています。' };
  }

  if (Date.now() - admissionTracker.windowStart >= 60000) {
    admissionTracker.successes = 0;
    admissionTracker.windowStart = Date.now();
  }

  const max = parseInt(process.env.MAX_USERS_PER_MINUTE || '20', 10);
  if (admissionTracker.successes >= max) {
    return { allowed: false, reason: 'アクセスが集中しているため、一時的に認証を制限しています。しばらく経ってから再度お試しください。' };
  }
  return { allowed: true };
}

let botRef = null;

function log(level, event, detail = {}) {
  const line = { ts: new Date().toISOString(), level, event, ...detail };
  const method = level === 'error' ? console.error : console.log;
  method(`[Auth] ${JSON.stringify(line)}`);
}

async function notifyDiscord(title, fields, color) {
  const channelId = process.env.LOG_CHANNEL_ID;
  if (!channelId || !botRef) return;
  if (!limiters.logNotify.consume('global').allowed) return;

  try {
    const channel = await botRef.channels.fetch(channelId);
    if (!channel?.isTextBased?.()) return;
    await channel.send({
      embeds: [{
        title,
        color,
        fields: Object.entries(fields).map(([name, value]) => ({
          name,
          value: String(value ?? '-').slice(0, 1024),
          inline: true
        })),
        timestamp: new Date().toISOString()
      }]
    });
  } catch (err) {
    log('warn', 'log_channel_failed', { message: err.message });
  }
}

const USER_MESSAGES = {
  rate: 'リクエストが多すぎます。しばらく時間を置いてからやり直してください。',
  session: 'セッションが無効か、有効期限が切れています。Discord のボタンから最初からやり直してください。',
  state: '認証リクエストの整合性を確認できませんでした。Discord のボタンから改めて開始してください。',
  challenge: '人間による操作であることを確認できませんでした。ページを再読み込みして、もう一度お試しください。',
  system: '認証処理中にエラーが発生しました。時間をおいて再度お試しください。'
};

function buildResultToken(payload) {
  const id = randomToken(18);
  resultTokens.set(id, payload, 5 * 60 * 1000);
  return id;
}

function renderResult(res, status, payload) {
  const html = renderTemplate(path.join(VIEWS, 'verify.html'), {
    nonce: res.locals.cspNonce,
    username: payload.username || 'Anonymous',
    avatarUrl: payload.avatarUrl || 'https://cdn.discordapp.com/embed/avatars/0.png',
    roleName: payload.roleName || '-',
    errorMessage: payload.errorMessage || '',
    bootstrap: {
      success: Boolean(payload.success),
      failStep: payload.failStep || '',
      code: payload.code || ''
    }
  });
  res.status(status).type('html').send(html);
}

function errorRedirect(step, code, message) {
  const token = buildResultToken({ success: false, failStep: step, code, errorMessage: message });
  return `/api/auth/result?t=${encodeURIComponent(token)}`;
}

function fail(res, { step = 'system', code, message, logDetail }) {
  log('warn', 'auth_blocked', { code, step, ...logDetail });
  clearSessionCookie(res);
  return res.redirect(302, errorRedirect(step, code, message));
}

function failJson(res, { status = 400, step = 'system', code, message, logDetail }) {
  log('warn', 'auth_blocked', { code, step, ...logDetail });
  return res.status(status).json({ ok: false, redirect: errorRedirect(step, code, message) });
}

async function exchangeCode(code) {
  const { data } = await axios.post(
    `${DISCORD_API}/oauth2/token`,
    new URLSearchParams({
      client_id: process.env.CLIENT_ID,
      client_secret: process.env.CLIENT_SECRET,
      grant_type: 'authorization_code',
      code,
      redirect_uri: process.env.REDIRECT_URI
    }),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 8000 }
  );
  return data;
}

async function revokeToken(token) {
  if (!token) return;
  try {
    await axios.post(
      `${DISCORD_API}/oauth2/token/revoke`,
      new URLSearchParams({
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        token,
        token_type_hint: 'access_token'
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 5000 }
    );
  } catch (err) {
    log('warn', 'token_revoke_failed', { message: err.message });
  }
}

async function fetchDiscordUser(accessToken) {
  const { data } = await axios.get(`${DISCORD_API}/users/@me`, {
    headers: { Authorization: `Bearer ${accessToken}` },
    timeout: 8000
  });
  return data;
}

async function fetchUserGuilds(accessToken) {
  const { data } = await axios.get(`${DISCORD_API}/users/@me/guilds`, {
    headers: { Authorization: `Bearer ${accessToken}` },
    timeout: 8000
  });
  return Array.isArray(data) ? data : [];
}

function snowflakeToDate(id) {
  return new Date(Number((BigInt(id) >> 22n) + 1420070400000n));
}

function inspectAccount(user) {
  if (user.bot || user.system) {
    return { ok: false, code: 'account_bot', message: 'Bot アカウントでは認証できません。' };
  }

  const flags = Number(user.public_flags || 0) | Number(user.flags || 0);
  if (flags & USER_FLAG_SPAMMER) {
    return { ok: false, code: 'account_quarantined', message: 'このアカウントは Discord 側で迷惑行為の対象として制限されています。' };
  }

  const minAgeDays = parseInt(process.env.MIN_ACCOUNT_AGE_DAYS || '0', 10);
  if (minAgeDays > 0) {
    const ageDays = (Date.now() - snowflakeToDate(user.id).getTime()) / 86400000;
    if (ageDays < minAgeDays) {
      return {
        ok: false,
        code: 'account_too_new',
        message: `アカウント作成から ${minAgeDays} 日以上経過している必要があります。（現在 ${Math.floor(ageDays)} 日）`
      };
    }
  }

  return { ok: true };
}

function displayName(user) {
  if (user.discriminator && user.discriminator !== '0') {
    return `${user.username}#${user.discriminator}`;
  }
  return user.global_name || user.username;
}

function avatarUrlFor(user) {
  if (user.avatar) {
    return `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=128`;
  }
  const index = user.discriminator && user.discriminator !== '0'
    ? Number(user.discriminator) % 5
    : Number((BigInt(user.id) >> 22n) % 6n);
  return `https://cdn.discordapp.com/embed/avatars/${index}.png`;
}

function bindingKey(ip) {
  const mode = (process.env.SESSION_IP_BINDING || 'subnet').toLowerCase();
  if (mode === 'off') return 'off';
  if (mode === 'strict') return ip;
  return subnetKey(ip);
}

let trustDiagnosed = false;

function diagnoseOnce(req, resolved) {
  if (trustDiagnosed) return;
  trustDiagnosed = true;

  const diagnosis = diagnoseTrustConfig(req, resolved);
  log('info', 'trust_config_diagnosis', {
    socketIp: diagnosis.socketIp,
    resolvedIp: diagnosis.resolvedIp,
    trustedProxies: describeTrustConfig(),
    proxyHeaders: Object.entries(diagnosis.headers)
      .filter(([, v]) => v)
      .map(([k]) => k)
  });

  for (const issue of diagnosis.issues) {
    console.warn(`[Security] ${issue}`);
  }
}

function gate(req, res, limiter) {
  const resolved = resolveClientIp(req);
  diagnoseOnce(req, resolved);

  if (!resolved?.ip) {
    return { blocked: true, response: () => fail(res, { step: 'network', code: 'no_client_ip', message: USER_MESSAGES.system }) };
  }

  const { ip, spoofAttempt } = resolved;
  const ipKey = subnetKey(ip);
  const bindKey = bindingKey(ip);

  if (spoofAttempt) {
    log('warn', 'proxy_header_spoof_attempt', { ip });
  }

  const rate = limiter.consume(ipKey);
  if (!rate.allowed) {
    metrics.blockedRate++;
    return {
      blocked: true,
      ip,
      ipKey,
      bindKey,
      response: () => {
        res.setHeader('Retry-After', Math.ceil(rate.retryAfterMs / 1000));
        return fail(res, {
          step: 'rate',
          code: 'rate_limited',
          message: USER_MESSAGES.rate,
          logDetail: { ip }
        });
      }
    };
  }

  return { blocked: false, ip, ipKey, bindKey, userAgent: String(req.headers['user-agent'] || '') };
}

function startWebServer(botClient) {
  botRef = botClient;

  const app = express();
  const PORT = process.env.PORT || 3000;

  app.disable('x-powered-by');
  app.disable('etag');
  app.set('trust proxy', expressTrustProxyFn());

  app.use(securityHeaders());
  app.use(express.json({ limit: '16kb' }));

  app.get('/api/auth/start', async (req, res) => {
    const check = gate(req, res, limiters.start);
    if (check.blocked) return check.response();

    const { ip, ipKey, bindKey, userAgent } = check;

    const admission = checkGlobalAdmission();
    if (!admission.allowed) {
      metrics.blockedRate++;
      return fail(res, { step: 'rate', code: 'admission_closed', message: admission.reason, logDetail: { ip } });
    }

    const network = await assessNetwork(ip);
    if (network.verdict === 'block') {
      metrics.blockedNetwork++;
      await notifyDiscord('認証ブロック: ネットワーク', { IP: ip, ASN: network.asn || '-', 組織: network.org || '-', シグナル: (network.signals || []).join(', ') || '-' }, 0xef4444);
      return fail(res, {
        step: 'network',
        code: 'network_blocked',
        message: network.reason,
        ipKey,
        logDetail: { ip, score: network.score, signals: network.signals }
      });
    }

    const nonce = randomToken(24);
    stateNonces.set(nonce, { bindKey, uaFp: fingerprint(userAgent) }, 10 * 60 * 1000);

    const state = signPayload({ typ: 'state', n: nonce, iat: Date.now() });
    issueSessionCookie(res, { typ: 'sess', n: nonce, ipk: bindKey, ua: fingerprint(userAgent) }, 10 * 60 * 1000);

    metrics.started++;
    log('info', 'auth_started', { ip, asn: network.asn });

    const authorizeUrl = new URL('https://discord.com/oauth2/authorize');
    authorizeUrl.searchParams.set('client_id', process.env.CLIENT_ID);
    authorizeUrl.searchParams.set('redirect_uri', process.env.REDIRECT_URI);
    authorizeUrl.searchParams.set('response_type', 'code');
    authorizeUrl.searchParams.set('scope', 'identify guilds');
    authorizeUrl.searchParams.set('state', state);
    authorizeUrl.searchParams.set('prompt', 'consent');

    res.redirect(302, authorizeUrl.toString());
  });

  app.get('/api/auth/callback', async (req, res) => {
    const check = gate(req, res, limiters.callback);
    if (check.blocked) return check.response();

    const { ip, ipKey, bindKey, userAgent } = check;
    const { code, state, error: oauthError } = req.query;

    if (oauthError) {
      return fail(res, { step: 'account', code: 'oauth_denied', message: 'Discord 側で連携が許可されませんでした。もう一度お試しください。', logDetail: { ip, oauthError } });
    }

    if (typeof code !== 'string' || code.length === 0 || code.length > 512) {
      return fail(res, { step: 'state', code: 'code_missing', message: USER_MESSAGES.state, logDetail: { ip } });
    }

    const statePayload = typeof state === 'string' ? verifyPayload(state, 10 * 60 * 1000) : null;
    if (!statePayload || statePayload.typ !== 'state' || typeof statePayload.n !== 'string') {
      metrics.blockedState++;
      return fail(res, { step: 'state', code: 'state_invalid', message: USER_MESSAGES.state, logDetail: { ip } });
    }

    const nonceRecord = stateNonces.take(statePayload.n);
    if (!nonceRecord) {
      metrics.blockedState++;
      return fail(res, { step: 'state', code: 'state_replayed', message: USER_MESSAGES.state, logDetail: { ip } });
    }

    const cookie = readSessionCookie(req);
    if (!cookie || cookie.typ !== 'sess' || !timingSafeEqualStr(cookie.n, statePayload.n)) {
      metrics.blockedState++;
      return fail(res, { step: 'state', code: 'cookie_mismatch', message: USER_MESSAGES.state, logDetail: { ip } });
    }

    if (cookie.ipk !== bindKey) {
      metrics.blockedState++;
      return fail(res, { step: 'state', code: 'network_changed', message: '認証の途中で接続元ネットワークが変わりました。同じ回線のまま、最初からやり直してください。', logDetail: { ip } });
    }

    try {
      const network = await assessNetwork(ip);
      if (network.verdict === 'block') {
        metrics.blockedNetwork++;
        return fail(res, { step: 'network', code: 'network_blocked', message: network.reason, logDetail: { ip, signals: network.signals } });
      }

      const tokenData = await exchangeCode(code).catch(() => null);
      if (!tokenData?.access_token) {
        return fail(res, { step: 'account', code: 'token_exchange_failed', message: 'Discord との連携に失敗しました。時間をおいて最初からやり直してください。', logDetail: { ip } });
      }

      const grantedScopes = String(tokenData.scope || '').split(' ');
      if (!grantedScopes.includes('identify') || !grantedScopes.includes('guilds')) {
        await revokeToken(tokenData.access_token);
        return fail(res, { step: 'account', code: 'scope_insufficient', message: '必要な連携範囲が許可されませんでした。すべての項目を許可して再度お試しください。', logDetail: { ip, scope: tokenData.scope } });
      }

      const user = await fetchDiscordUser(tokenData.access_token).catch(() => null);
      if (!user?.id) {
        await revokeToken(tokenData.access_token);
        return fail(res, { step: 'account', code: 'user_fetch_failed', message: USER_MESSAGES.system, logDetail: { ip } });
      }

      const accountCheck = inspectAccount(user);
      if (!accountCheck.ok) {
        await revokeToken(tokenData.access_token);
        return fail(res, { step: 'account', code: accountCheck.code, message: accountCheck.message, logDetail: { ip, userId: user.id } });
      }

      const sessionId = randomToken(24);
      const powChallenge = challenge.issuePowChallenge({ sessionId, ipKey: bindKey });

      pendingVerifications.set(sessionId, {
        userId: user.id,
        username: displayName(user),
        avatarUrl: avatarUrlFor(user),
        accessToken: tokenData.access_token,
        bindKey,
        uaFp: fingerprint(userAgent),
        issuedAt: Date.now()
      }, sessionTtlMs());

      issueSessionCookie(res, { typ: 'chal', sid: sessionId, ipk: bindKey, ua: fingerprint(userAgent) }, sessionTtlMs());

      log('info', 'challenge_issued', { ip, userId: user.id, powBits: powChallenge.bits });

      const html = renderTemplate(path.join(VIEWS, 'captcha.html'), {
        nonce: res.locals.cspNonce,
        bootstrap: {
          sessionId,
          challenge: powChallenge.challenge,
          seed: powChallenge.seed,
          bits: powChallenge.bits,
          turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || '',
          minHoldMs: challenge.config().minHumanMs
        }
      });
      res.type('html').send(html);

    } catch (err) {
      metrics.errors++;
      log('error', 'callback_error', { ip, message: err.message });
      return fail(res, { step: 'system', code: 'callback_error', message: USER_MESSAGES.system, logDetail: { ip } });
    }
  });

  app.post('/api/auth/verify', async (req, res) => {
    const check = gate(req, res, limiters.verify);
    if (check.blocked) {
      return res.status(429).json({ ok: false, redirect: '/api/auth/result?t=' + encodeURIComponent(buildResultToken({ success: false, failStep: 'rate', code: 'rate_limited', errorMessage: USER_MESSAGES.rate })) });
    }

    const { ip, ipKey, bindKey, userAgent } = check;
    const { sessionId, powNonce, turnstileToken, signals } = req.body || {};

    if (typeof sessionId !== 'string' || sessionId.length > 128) {
      return failJson(res, { step: 'session', code: 'session_malformed', message: USER_MESSAGES.session, logDetail: { ip } });
    }

    const cookie = readSessionCookie(req);
    if (!cookie || cookie.typ !== 'chal' || !timingSafeEqualStr(cookie.sid, sessionId)) {
      return failJson(res, { step: 'session', code: 'session_cookie_mismatch', message: USER_MESSAGES.session, logDetail: { ip } });
    }

    const session = pendingVerifications.take(sessionId);
    if (!session) {
      return failJson(res, { step: 'session', code: 'session_expired', message: USER_MESSAGES.session, logDetail: { ip } });
    }

    const accessToken = session.accessToken;

    try {
      if (session.bindKey !== bindKey) {
        return failJson(res, { status: 403, step: 'network', code: 'session_network_mismatch', message: '認証の途中で接続元ネットワークが変わりました。最初からやり直してください。', logDetail: { ip } });
      }

      if (session.uaFp !== fingerprint(userAgent)) {
        return failJson(res, { status: 403, step: 'session', code: 'session_ua_mismatch', message: USER_MESSAGES.session, logDetail: { ip } });
      }

      const behavior = challenge.evaluateBehavior(signals);
      if (!behavior.ok) {
        metrics.blockedChallenge++;
        return failJson(res, { status: 403, step: 'challenge', code: 'behavior_rejected', message: USER_MESSAGES.challenge, logDetail: { ip, flags: behavior.flags, score: behavior.score } });
      }

      const pow = challenge.verifyPowSolution({
        challenge: req.body?.challenge,
        nonce: powNonce,
        sessionId,
        ipKey: bindKey
      });
      if (!pow.ok) {
        metrics.blockedChallenge++;
        return failJson(res, { status: 403, step: 'challenge', code: pow.reason, message: USER_MESSAGES.challenge, logDetail: { ip } });
      }

      const cfg = challenge.config();
      if (cfg.requireTurnstile && !challenge.turnstileConfigured()) {
        metrics.errors++;
        log('error', 'turnstile_required_but_unconfigured', {});
        return failJson(res, { status: 500, step: 'system', code: 'turnstile_unconfigured', message: USER_MESSAGES.system, logDetail: { ip } });
      }

      if (challenge.turnstileConfigured()) {
        const turnstile = await challenge.verifyTurnstile({
          token: turnstileToken,
          ip,
          idempotencyKey: crypto.createHash('sha256').update(sessionId).digest('hex').slice(0, 32)
        });
        if (!turnstile.ok) {
          metrics.blockedChallenge++;
          return failJson(res, { status: 403, step: 'challenge', code: turnstile.reason, message: USER_MESSAGES.challenge, logDetail: { ip, codes: turnstile.codes } });
        }
      }

      const network = await assessNetwork(ip);
      if (network.verdict === 'block') {
        metrics.blockedNetwork++;
        return failJson(res, { status: 403, step: 'network', code: 'network_blocked', message: network.reason, logDetail: { ip, signals: network.signals } });
      }

      const admission = checkGlobalAdmission();
      if (!admission.allowed) {
        metrics.blockedRate++;
        return failJson(res, { status: 503, step: 'rate', code: 'admission_closed', message: admission.reason, logDetail: { ip } });
      }

      const bannedGuildIds = getBannedGuilds();
      if (bannedGuildIds.length > 0) {
        const userGuilds = await fetchUserGuilds(accessToken).catch(() => null);
        if (!userGuilds) {
          return failJson(res, { status: 502, step: 'account', code: 'guilds_fetch_failed', message: '所属サーバー情報を取得できませんでした。時間をおいて再度お試しください。', logDetail: { ip } });
        }

        const matched = userGuilds.find(g => bannedGuildIds.includes(g.id));
        if (matched) {
          metrics.blockedGuild++;
          await notifyDiscord('認証ブロック: 拒否サーバー所属', { ユーザー: session.username, ID: session.userId, サーバー: `${matched.name} (${matched.id})` }, 0xef4444);
          return failJson(res, {
            status: 403,
            step: 'account',
            code: 'banned_guild',
            message: `あなたが所属しているサーバー「${matched.name}」は、当サーバーのポリシーにより拒否対象に指定されています。該当サーバーから脱退したうえで、再度認証を行ってください。`,
            ipKey,
            logDetail: { ip, userId: session.userId, guildId: matched.id }
          });
        }
      }

      const guildId = process.env.GUILD_ID;
      const roleId = process.env.ROLE_ID;

      if (!roleId) {
        metrics.errors++;
        log('error', 'role_id_missing', {});
        return failJson(res, { status: 500, step: 'system', code: 'role_unconfigured', message: USER_MESSAGES.system, logDetail: { ip } });
      }

      const guild = await botClient.guilds.fetch(guildId).catch(() => null);
      if (!guild) {
        metrics.errors++;
        return failJson(res, { status: 500, step: 'system', code: 'guild_fetch_failed', message: 'サーバー情報を取得できませんでした。管理者にお問い合わせください。', logDetail: { ip } });
      }

      const member = await guild.members.fetch(session.userId).catch(() => null);
      if (!member) {
        return failJson(res, { status: 403, step: 'account', code: 'not_a_member', message: 'サーバー内にあなたのアカウントが見つかりませんでした。先にサーバーへ参加した状態で認証してください。', logDetail: { ip, userId: session.userId } });
      }

      const role = guild.roles.cache.get(roleId) || await guild.roles.fetch(roleId).catch(() => null);
      if (!role) {
        metrics.errors++;
        return failJson(res, { status: 500, step: 'system', code: 'role_not_found', message: 'ロール設定に問題があります。管理者にお問い合わせください。', logDetail: { ip, roleId } });
      }

      if (!member.roles.cache.has(roleId)) {
        const added = await member.roles.add(role, `Verified via auth gateway (${ip})`).then(() => true).catch(err => {
          log('error', 'role_add_failed', { message: err.message, userId: session.userId });
          return false;
        });
        if (!added) {
          metrics.errors++;
          return failJson(res, { status: 500, step: 'system', code: 'role_add_failed', message: 'ロールの付与に失敗しました。Bot のロール順位や権限を管理者にご確認ください。', logDetail: { ip } });
        }
      }

      admissionTracker.successes++;
      metrics.succeeded++;

      log('info', 'auth_success', { ip, userId: session.userId, username: session.username, asn: network.asn, powBits: pow.bits });
      await notifyDiscord('認証成功', { ユーザー: session.username, ID: session.userId, ASN: network.asn || '-', 組織: network.org || '-' }, 0x10b981);

      const token = buildResultToken({
        success: true,
        username: session.username,
        avatarUrl: session.avatarUrl,
        roleName: role.name
      });
      clearSessionCookie(res);
      return res.json({ ok: true, redirect: `/api/auth/result?t=${encodeURIComponent(token)}` });

    } catch (err) {
      metrics.errors++;
      log('error', 'verify_error', { ip, message: err.message });
      return failJson(res, { status: 500, step: 'system', code: 'verify_error', message: USER_MESSAGES.system, logDetail: { ip } });
    } finally {
      revokeToken(accessToken);
    }
  });

  app.get('/api/auth/result', (req, res) => {
    const token = req.query.t;
    const payload = typeof token === 'string' ? resultTokens.get(token) : null;

    if (!payload) {
      return renderResult(res, 400, {
        success: false,
        failStep: 'session',
        code: 'result_expired',
        errorMessage: '表示できる結果がありません。Discord のボタンから認証をやり直してください。'
      });
    }

    return renderResult(res, payload.success ? 200 : 403, payload);
  });

  app.get('/healthz', (req, res) => {
    res.json({ ok: true, uptimeSec: Math.floor((Date.now() - metrics.bootedAt) / 1000) });
  });

  app.use((req, res) => {
    res.status(404).json({ ok: false, error: 'not_found' });
  });

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (res.headersSent) return;

    if (err.type === 'entity.parse.failed' || err.type === 'entity.too.large' || err.status === 400) {
      return res.status(400).json({ ok: false, error: 'bad_request' });
    }

    metrics.errors++;
    log('error', 'unhandled', { message: err.message });
    res.status(500).json({ ok: false, error: 'internal_error' });
  });

  const server = app.listen(PORT, () => {
    log('info', 'server_started', {
      port: PORT,
      baseUrl: publicBaseUrl(),
      secureCookies: isSecureDeployment(),
      trustedProxies: describeTrustConfig(),
      challenge: challenge.describe(),
      reputation: reputationStats()
    });

    if (!process.env.SESSION_SECRET) {
      console.warn('[Security] SESSION_SECRET を .env に設定してください（32文字以上のランダム文字列）。');
    }
    if (!challenge.turnstileConfigured()) {
      console.warn('[Security] Turnstile 未設定です。Proof-of-Work のみで動作します。TURNSTILE_SITE_KEY / TURNSTILE_SECRET_KEY の設定を推奨します。');
    }
    if (!isSecureDeployment()) {
      console.warn('[Security] HTTPS 以外で動作しています。本番では必ず HTTPS 経由で公開してください。');
    }
  });

  return server;
}

function getMetrics() {
  return {
    ...metrics,
    uptimeSec: Math.floor((Date.now() - metrics.bootedAt) / 1000),
    pendingSessions: pendingVerifications.size,
    reputation: reputationStats(),
    challenge: challenge.describe()
  };
}

module.exports = { startWebServer, getMetrics, publicBaseUrl };
