process.env.SESSION_SECRET = 'test-secret-value-that-is-long-enough-for-hmac-usage';
process.env.TRUSTED_PROXY_CIDRS = 'private';
process.env.POW_DIFFICULTY_BITS = '12';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  ok  ${name}`);
  } catch (err) {
    failed++;
    console.error(`  FAIL ${name}\n       ${err.message}`);
  }
}

function section(title) {
  console.log(`\n${title}`);
}

section('render — テンプレート注入');
const { escapeHtml, escapeJson, renderTemplate } = require('../src/security/render');

test('HTML 特殊文字をエスケープする', () => {
  const out = escapeHtml('<script>alert(1)</script>');
  assert.ok(!out.includes('<script>'), 'script タグが生のまま残っている');
  assert.ok(out.includes('&lt;script&gt;'));
});

test('script 脱出を許さない', () => {
  const out = escapeJson('</script><img src=x onerror=alert(1)>');
  assert.ok(!out.includes('</script>'), 'script の閉じタグが残っている');
  assert.ok(out.includes('\\u003c'));
});

test('U+2028 / U+2029 を無害化する', () => {
  const out = escapeJson(String.fromCharCode(0x2028) + String.fromCharCode(0x2029));
  assert.ok(out.includes('\\u2028') && out.includes('\\u2029'));
  assert.ok(!out.includes(String.fromCharCode(0x2028)));
});

test('埋め込んだ値が再度テンプレートとして解釈されない', () => {
  const tmp = path.join(__dirname, '.tmp-template.html');
  fs.writeFileSync(tmp, '<p><%= a %></p><p><%= b %></p>');
  try {
    const out = renderTemplate(tmp, { a: '<%= b %>', b: 'SECRET' });
    const occurrences = out.split('SECRET').length - 1;
    assert.strictEqual(occurrences, 1, '注入されたプレースホルダが展開された');
  } finally {
    fs.unlinkSync(tmp);
  }
});

test('$& などの置換特殊パターンが誤作動しない', () => {
  const tmp = path.join(__dirname, '.tmp-template2.html');
  fs.writeFileSync(tmp, '<p><%= a %></p>');
  try {
    const out = renderTemplate(tmp, { a: "$&$'$`" });
    assert.ok(out.includes('&#36;') || out.includes('$&amp;'), `想定外の出力: ${out}`);
    assert.ok(!out.includes('<p><p>'), '置換パターンが展開された');
  } finally {
    fs.unlinkSync(tmp);
  }
});

section('crypto — 署名トークン');
const { signPayload, verifyPayload, timingSafeEqualStr, fingerprint } = require('../src/security/crypto');

test('正しい署名は検証を通る', () => {
  const token = signPayload({ typ: 'state', n: 'abc', iat: Date.now() });
  const payload = verifyPayload(token, 60000);
  assert.strictEqual(payload.n, 'abc');
});

test('本文を書き換えると検証に失敗する', () => {
  const token = signPayload({ typ: 'state', n: 'abc', iat: Date.now() });
  const [body, sig] = token.split('.');
  const tampered = Buffer.from(JSON.stringify({ typ: 'state', n: 'EVIL', iat: Date.now() }))
    .toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  assert.strictEqual(verifyPayload(`${tampered}.${sig}`, 60000), null);
  assert.ok(body.length > 0);
});

test('期限切れは拒否する', () => {
  const token = signPayload({ typ: 'state', iat: Date.now() - 120000 });
  assert.strictEqual(verifyPayload(token, 60000), null);
});

test('未来の発行時刻は拒否する', () => {
  const token = signPayload({ typ: 'state', iat: Date.now() + 600000 });
  assert.strictEqual(verifyPayload(token, 60000), null);
});

test('長さの違う文字列比較で例外を出さない', () => {
  assert.strictEqual(timingSafeEqualStr('a', 'abcdef'), false);
  assert.strictEqual(timingSafeEqualStr('abc', 'abc'), true);
});

test('fingerprint は同じ入力に同じ値を返す', () => {
  assert.strictEqual(fingerprint('Mozilla/5.0'), fingerprint('Mozilla/5.0'));
  assert.notStrictEqual(fingerprint('Mozilla/5.0'), fingerprint('curl/8.0'));
});

section('net — 接続元IPの詐称対策');
const { resolveClientIp, subnetKey, isTrustedProxy } = require('../src/security/net');

function fakeReq(remoteAddress, headers = {}) {
  return { socket: { remoteAddress }, headers };
}

test('信頼していない接続元のプロキシヘッダは無視する', () => {
  const result = resolveClientIp(fakeReq('203.0.113.9', {
    'cf-connecting-ip': '1.1.1.1',
    'x-forwarded-for': '8.8.8.8'
  }));
  assert.strictEqual(result.ip, '203.0.113.9', 'ヘッダによる詐称が通ってしまった');
  assert.strictEqual(result.spoofAttempt, true);
});

test('信頼済みプロキシ経由なら XFF を採用する', () => {
  const result = resolveClientIp(fakeReq('127.0.0.1', { 'x-forwarded-for': '198.51.100.7' }));
  assert.strictEqual(result.ip, '198.51.100.7');
  assert.strictEqual(result.viaProxy, true);
});

test('XFF は右端から辿り、前置きされた偽アドレスを採用しない', () => {
  const result = resolveClientIp(fakeReq('127.0.0.1', {
    'x-forwarded-for': '1.1.1.1, 198.51.100.7'
  }));
  assert.strictEqual(result.ip, '198.51.100.7');
});

test('IPv4-mapped IPv6 を正規化する', () => {
  const result = resolveClientIp(fakeReq('::ffff:203.0.113.5'));
  assert.strictEqual(result.ip, '203.0.113.5');
});

test('ローカルアドレスのみ信頼する既定設定', () => {
  assert.strictEqual(isTrustedProxy('127.0.0.1'), true);
  assert.strictEqual(isTrustedProxy('10.0.0.5'), true);
  assert.strictEqual(isTrustedProxy('203.0.113.9'), false);
});

test('既定 (TRUSTED_PROXY_CIDRS 未設定) ではプロキシヘッダを一切信じない', () => {
  const script = [
    'delete process.env.TRUSTED_PROXY_CIDRS;',
    "const { resolveClientIp } = require('./src/security/net');",
    "const r = resolveClientIp({ socket: { remoteAddress: '127.0.0.1' }, headers: { 'x-forwarded-for': '8.8.8.8' } });",
    'console.log(r.ip);'
  ].join('\n');

  const out = require('child_process')
    .execFileSync(process.execPath, ['-e', script], { cwd: path.join(__dirname, '..'), encoding: 'utf8' })
    .trim();

  assert.strictEqual(out, '127.0.0.1', '既定でプロキシヘッダを信用してしまっている');
});

test('サブネットキーが /24 で丸められる', () => {
  assert.strictEqual(subnetKey('203.0.113.9'), subnetKey('203.0.113.200'));
  assert.notStrictEqual(subnetKey('203.0.113.9'), subnetKey('203.0.114.9'));
});

section('challenge — Proof of Work');
const challenge = require('../src/security/challenge');

function solveServerSide(seed, bits) {
  let nonce = 0;
  for (;;) {
    const digest = crypto.createHash('sha256').update(`${seed}:${nonce}`).digest();
    let zero = 0;
    for (const byte of digest) {
      if (byte === 0) { zero += 8; continue; }
      zero += Math.clz32(byte) - 24;
      break;
    }
    if (zero >= bits) return String(nonce);
    nonce++;
  }
}

test('正しい解を受理する', () => {
  const issued = challenge.issuePowChallenge({ sessionId: 'sid-1', ipKey: 'net-1' });
  const nonce = solveServerSide(issued.seed, issued.bits);
  const result = challenge.verifyPowSolution({
    challenge: issued.challenge, nonce, sessionId: 'sid-1', ipKey: 'net-1'
  });
  assert.ok(result.ok, `拒否された: ${result.reason}`);
});

test('誤った解を拒否する', () => {
  const issued = challenge.issuePowChallenge({ sessionId: 'sid-1', ipKey: 'net-1' });
  const result = challenge.verifyPowSolution({
    challenge: issued.challenge, nonce: '1', sessionId: 'sid-1', ipKey: 'net-1'
  });
  if (result.ok) return;
  assert.strictEqual(result.reason, 'pow_insufficient');
});

test('別セッションのチャレンジを使い回せない', () => {
  const issued = challenge.issuePowChallenge({ sessionId: 'sid-1', ipKey: 'net-1' });
  const nonce = solveServerSide(issued.seed, issued.bits);
  const result = challenge.verifyPowSolution({
    challenge: issued.challenge, nonce, sessionId: 'sid-OTHER', ipKey: 'net-1'
  });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.reason, 'challenge_session_mismatch');
});

test('別ネットワークからは使えない', () => {
  const issued = challenge.issuePowChallenge({ sessionId: 'sid-1', ipKey: 'net-1' });
  const nonce = solveServerSide(issued.seed, issued.bits);
  const result = challenge.verifyPowSolution({
    challenge: issued.challenge, nonce, sessionId: 'sid-1', ipKey: 'net-EVIL'
  });
  assert.strictEqual(result.reason, 'challenge_network_mismatch');
});

test('難易度を書き換えたチャレンジは署名検証で落ちる', () => {
  const issued = challenge.issuePowChallenge({ sessionId: 'sid-1', ipKey: 'net-1' });
  const [body, sig] = issued.challenge.split('.');
  const decoded = JSON.parse(Buffer.from(body.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString());
  decoded.bits = 1;
  const forged = Buffer.from(JSON.stringify(decoded)).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const result = challenge.verifyPowSolution({
    challenge: `${forged}.${sig}`, nonce: '1', sessionId: 'sid-1', ipKey: 'net-1'
  });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.reason, 'challenge_invalid');
});

test('数字以外の nonce を拒否する', () => {
  const issued = challenge.issuePowChallenge({ sessionId: 'sid-1', ipKey: 'net-1' });
  const result = challenge.verifyPowSolution({
    challenge: issued.challenge, nonce: '1e9', sessionId: 'sid-1', ipKey: 'net-1'
  });
  assert.strictEqual(result.reason, 'nonce_malformed');
});

section('challenge — ブラウザ側 SHA-256 の一致確認');

function loadBrowserPow(seed) {
  const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'views', 'captcha.html'), 'utf8');
  const start = html.indexOf('var K = new Uint32Array([');
  const end = html.indexOf('var BATCH = 4096;');
  assert.ok(start > 0 && end > start, 'captcha.html から PoW 実装を抽出できなかった');

  const source = html.slice(start, end);
  const factory = new Function('BOOT', `${source}\nreturn { hashNonce: hashNonce, prefixLen: prefixLen };`);
  return factory({ seed });
}

test('ブラウザ実装の SHA-256 が Node の crypto と一致する', () => {
  const seed = 'abcdefghijklmnopqrstuv';
  const { hashNonce } = loadBrowserPow(seed);

  for (const nonce of ['0', '1', '42', '999999999', '1234567890']) {
    const browserWord = hashNonce(nonce);
    const nodeWord = crypto.createHash('sha256').update(`${seed}:${nonce}`).digest().readUInt32BE(0);
    assert.strictEqual(
      browserWord >>> 0,
      nodeWord >>> 0,
      `nonce=${nonce} でダイジェストが不一致 (browser=${(browserWord >>> 0).toString(16)}, node=${nodeWord.toString(16)})`
    );
  }
});

test('ブラウザが見つけた解をサーバーが受理する', () => {
  const issued = challenge.issuePowChallenge({ sessionId: 'sid-x', ipKey: 'net-x' });
  const { hashNonce } = loadBrowserPow(issued.seed);

  const shift = 32 - issued.bits;
  let nonce = 0;
  while ((hashNonce(String(nonce)) >>> shift) !== 0) {
    nonce++;
    if (nonce > 5000000) throw new Error('解が見つからない');
  }

  const result = challenge.verifyPowSolution({
    challenge: issued.challenge, nonce: String(nonce), sessionId: 'sid-x', ipKey: 'net-x'
  });
  assert.ok(result.ok, `サーバーが拒否した: ${result.reason}`);
});

section('challenge — 操作シグナル');

test('webdriver を即座に拒否する', () => {
  const result = challenge.evaluateBehavior({ webdriver: true, holdMs: 5000, pointerEvents: 50, frameJitter: 2, screen: '1920x1080', tz: 'Asia/Tokyo' });
  assert.strictEqual(result.ok, false);
  assert.ok(result.flags.includes('webdriver'));
});

test('シグナルが無い場合は拒否する', () => {
  assert.strictEqual(challenge.evaluateBehavior(null).ok, false);
});

test('人間らしいシグナルを受理する', () => {
  const result = challenge.evaluateBehavior({
    holdMs: 2600, pointerEvents: 25, frameJitter: 1.8, screen: '1920x1080', tz: 'Asia/Tokyo', webdriver: false
  });
  assert.ok(result.ok, `誤検知: ${result.flags.join(',')}`);
});

test('自動化らしいシグナルを拒否する', () => {
  const result = challenge.evaluateBehavior({
    holdMs: 5, pointerEvents: 0, frameJitter: 0, screen: '', tz: '', webdriver: false
  });
  assert.strictEqual(result.ok, false);
});

section('store — レート制限と一時ストア');
const { SlidingWindowLimiter, TtlMap } = require('../src/security/store');

test('上限を超えた要求を拒否する', () => {
  const limiter = new SlidingWindowLimiter('t', { windowMs: 60000, limit: 3 });
  assert.ok(limiter.consume('k').allowed);
  assert.ok(limiter.consume('k').allowed);
  assert.ok(limiter.consume('k').allowed);
  assert.strictEqual(limiter.consume('k').allowed, false);
  assert.ok(limiter.consume('other').allowed, 'キーごとに独立していない');
});

test('take は単回使用になる', () => {
  const map = new TtlMap('t');
  map.set('k', 'v', 60000);
  assert.strictEqual(map.take('k'), 'v');
  assert.strictEqual(map.take('k'), undefined, 'トークンが再利用できてしまう');
});

test('TTL 経過後は取得できない', () => {
  const map = new TtlMap('t');
  map.set('k', 'v', -1);
  assert.strictEqual(map.get('k'), undefined);
});

test('件数上限を超えても無制限に増えない', () => {
  const map = new TtlMap('t', 10);
  for (let i = 0; i < 100; i++) map.set(`k${i}`, i, 60000);
  assert.ok(map.size <= 10, `上限を超えている: ${map.size}`);
});

console.log(`\n${'-'.repeat(50)}`);
console.log(`${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
