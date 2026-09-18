const crypto = require('crypto');
const axios = require('axios');
const { signPayload, verifyPayload, randomToken } = require('./crypto');

const TURNSTILE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

function config() {
  return {
    powBits: clamp(parseInt(process.env.POW_DIFFICULTY_BITS || '18', 10), 8, 26),
    powTtlMs: parseInt(process.env.CHALLENGE_TTL_SECONDS || '600', 10) * 1000,
    minHumanMs: parseInt(process.env.MIN_INTERACTION_MS || '1800', 10),
    requireTurnstile: process.env.REQUIRE_TURNSTILE === 'true',
    turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || '',
    turnstileSecret: process.env.TURNSTILE_SECRET_KEY || '',
    behaviorEnabled: process.env.BEHAVIOR_CHECKS !== 'false'
  };
}

function clamp(value, min, max) {
  if (Number.isNaN(value)) return min;
  return Math.min(max, Math.max(min, value));
}

function turnstileConfigured() {
  const cfg = config();
  return Boolean(cfg.turnstileSiteKey && cfg.turnstileSecret);
}

function issuePowChallenge({ sessionId, ipKey }) {
  const cfg = config();
  const seed = randomToken(16);

  const challenge = signPayload({
    typ: 'pow',
    seed,
    bits: cfg.powBits,
    sid: sessionId,
    ipk: ipKey,
    iat: Date.now()
  });

  return { challenge, seed, bits: cfg.powBits };
}

function countLeadingZeroBits(buffer) {
  let bits = 0;
  for (const byte of buffer) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    bits += Math.clz32(byte) - 24;
    break;
  }
  return bits;
}

function verifyPowSolution({ challenge, nonce, sessionId, ipKey }) {
  const cfg = config();

  const payload = verifyPayload(challenge, cfg.powTtlMs);
  if (!payload || payload.typ !== 'pow') {
    return { ok: false, reason: 'challenge_invalid' };
  }
  if (payload.sid !== sessionId) {
    return { ok: false, reason: 'challenge_session_mismatch' };
  }
  if (payload.ipk !== ipKey) {
    return { ok: false, reason: 'challenge_network_mismatch' };
  }
  if (typeof nonce !== 'string' || nonce.length === 0 || nonce.length > 64 || !/^[0-9]+$/.test(nonce)) {
    return { ok: false, reason: 'nonce_malformed' };
  }

  const digest = crypto.createHash('sha256').update(`${payload.seed}:${nonce}`).digest();
  const zeroBits = countLeadingZeroBits(digest);

  if (zeroBits < payload.bits) {
    return { ok: false, reason: 'pow_insufficient' };
  }

  return { ok: true, bits: payload.bits, issuedAt: payload.iat };
}

async function verifyTurnstile({ token, ip, idempotencyKey }) {
  const cfg = config();

  if (!cfg.turnstileSecret) {
    return { ok: true, skipped: true, reason: 'not_configured' };
  }

  if (!token || typeof token !== 'string' || token.length > 2048) {
    return { ok: false, reason: 'turnstile_missing' };
  }

  const form = new URLSearchParams({
    secret: cfg.turnstileSecret,
    response: token
  });
  if (ip) form.append('remoteip', ip);
  if (idempotencyKey) form.append('idempotency_key', idempotencyKey);

  try {
    const { data } = await axios.post(TURNSTILE_VERIFY_URL, form, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 6000
    });

    if (data?.success) {
      return { ok: true, hostname: data.hostname, action: data.action };
    }
    return { ok: false, reason: 'turnstile_rejected', codes: data?.['error-codes'] || [] };
  } catch (err) {
    return { ok: false, reason: 'turnstile_unreachable', detail: err.message };
  }
}

function evaluateBehavior(signals) {
  const cfg = config();
  if (!cfg.behaviorEnabled) return { ok: true, score: 0, flags: ['disabled'] };

  const flags = [];
  let score = 0;

  if (!signals || typeof signals !== 'object') {
    return { ok: false, score: 100, flags: ['telemetry_missing'] };
  }

  if (signals.webdriver === true) {
    return { ok: false, score: 100, flags: ['webdriver'] };
  }

  const holdMs = Number(signals.holdMs);
  if (!Number.isFinite(holdMs) || holdMs < cfg.minHumanMs) {
    score += 45;
    flags.push('hold_too_short');
  }

  const pointerEvents = Number(signals.pointerEvents);
  if (!Number.isFinite(pointerEvents) || pointerEvents < 3) {
    score += 25;
    flags.push('no_pointer_activity');
  }

  const jitter = Number(signals.frameJitter);
  if (!Number.isFinite(jitter) || jitter <= 0.05) {
    score += 20;
    flags.push('no_frame_jitter');
  }

  if (!signals.screen || typeof signals.screen !== 'string' || !/^\d+x\d+$/.test(signals.screen)) {
    score += 15;
    flags.push('screen_missing');
  } else {
    const [width, height] = signals.screen.split('x').map(Number);
    if (width < 200 || height < 200) {
      score += 20;
      flags.push('screen_implausible');
    }
  }

  if (typeof signals.tz !== 'string' || signals.tz.length === 0) {
    score += 10;
    flags.push('tz_missing');
  }

  const threshold = parseInt(process.env.BEHAVIOR_BLOCK_SCORE || '70', 10);
  return { ok: score < threshold, score, flags };
}

function describe() {
  const cfg = config();
  return {
    powBits: cfg.powBits,
    expectedHashes: Math.pow(2, cfg.powBits),
    turnstile: turnstileConfigured() ? 'enabled' : (cfg.requireTurnstile ? 'REQUIRED_BUT_UNCONFIGURED' : 'disabled'),
    behaviorChecks: cfg.behaviorEnabled
  };
}

module.exports = {
  config,
  issuePowChallenge,
  verifyPowSolution,
  verifyTurnstile,
  evaluateBehavior,
  turnstileConfigured,
  describe
};
