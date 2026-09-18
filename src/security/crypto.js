const crypto = require('crypto');

let cachedSecret = null;

function getSecret() {
  if (cachedSecret) return cachedSecret;

  const fromEnv = process.env.SESSION_SECRET;
  if (fromEnv && fromEnv.length >= 32) {
    cachedSecret = crypto.createHash('sha256').update(fromEnv).digest();
    return cachedSecret;
  }

  if (fromEnv) {
    console.warn('[Security] SESSION_SECRET が短すぎます (32文字以上を推奨)。起動ごとに変わる一時鍵を使用します。');
  } else {
    console.warn('[Security] SESSION_SECRET が未設定です。起動ごとに変わる一時鍵を使用します。再起動すると進行中の認証セッションは無効になります。');
  }
  cachedSecret = crypto.randomBytes(32);
  return cachedSecret;
}

function b64urlEncode(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(str) {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(padded, 'base64');
}

function hmac(data) {
  return crypto.createHmac('sha256', getSecret()).update(data).digest();
}

function signPayload(payload) {
  const body = b64urlEncode(Buffer.from(JSON.stringify(payload), 'utf8'));
  const sig = b64urlEncode(hmac(body));
  return `${body}.${sig}`;
}

function verifyPayload(token, maxAgeMs) {
  if (typeof token !== 'string' || token.length > 4096) return null;

  const dot = token.indexOf('.');
  if (dot <= 0) return null;

  const body = token.slice(0, dot);
  const sig = token.slice(dot + 1);

  const expected = b64urlEncode(hmac(body));
  if (!timingSafeEqualStr(sig, expected)) return null;

  let payload;
  try {
    payload = JSON.parse(b64urlDecode(body).toString('utf8'));
  } catch {
    return null;
  }

  if (maxAgeMs != null) {
    if (typeof payload.iat !== 'number') return null;
    const age = Date.now() - payload.iat;
    if (age < -30000 || age > maxAgeMs) return null;
  }

  return payload;
}

function timingSafeEqualStr(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function randomToken(bytes = 32) {
  return b64urlEncode(crypto.randomBytes(bytes));
}

function sha256hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function fingerprint(input) {
  return b64urlEncode(hmac(String(input))).slice(0, 22);
}

module.exports = {
  getSecret,
  signPayload,
  verifyPayload,
  timingSafeEqualStr,
  randomToken,
  sha256hex,
  fingerprint,
  b64urlEncode,
  b64urlDecode
};
