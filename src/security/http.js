const crypto = require('crypto');
const { signPayload, verifyPayload } = require('./crypto');

function isSecureDeployment() {
  if (process.env.SECURE_COOKIES === 'true') return true;
  if (process.env.SECURE_COOKIES === 'false') return false;
  return String(process.env.REDIRECT_URI || '').startsWith('https://');
}

function cookieName() {
  return isSecureDeployment() ? '__Host-rula_auth' : 'rula_auth';
}

function parseCookies(req) {
  const header = req.headers.cookie;
  if (!header) return {};

  const out = {};
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (!key) continue;
    try {
      out[key] = decodeURIComponent(value);
    } catch {
      out[key] = value;
    }
  }
  return out;
}

function setSessionCookie(res, value, maxAgeMs) {
  const secure = isSecureDeployment();
  const attrs = [
    `${cookieName()}=${encodeURIComponent(value)}`,
    'HttpOnly',
    'SameSite=Lax',
    'Path=/',
    `Max-Age=${Math.floor(maxAgeMs / 1000)}`
  ];
  if (secure) attrs.push('Secure');
  appendHeader(res, 'Set-Cookie', attrs.join('; '));
}

function clearSessionCookie(res) {
  const attrs = [`${cookieName()}=`, 'HttpOnly', 'SameSite=Lax', 'Path=/', 'Max-Age=0'];
  if (isSecureDeployment()) attrs.push('Secure');
  appendHeader(res, 'Set-Cookie', attrs.join('; '));
}

function readSessionCookie(req) {
  const raw = parseCookies(req)[cookieName()];
  if (!raw) return null;
  return verifyPayload(raw, 30 * 60 * 1000);
}

function issueSessionCookie(res, payload, maxAgeMs) {
  const token = signPayload({ ...payload, iat: Date.now() });
  setSessionCookie(res, token, maxAgeMs);
  return token;
}

function appendHeader(res, name, value) {
  const existing = res.getHeader(name);
  if (!existing) res.setHeader(name, value);
  else if (Array.isArray(existing)) res.setHeader(name, existing.concat(value));
  else res.setHeader(name, [existing, value]);
}

function securityHeaders() {
  const secure = isSecureDeployment();

  return (req, res, next) => {
    const nonce = crypto.randomBytes(16).toString('base64');
    res.locals = res.locals || {};
    res.locals.cspNonce = nonce;

    const scriptSrc = [`'self'`, `'nonce-${nonce}'`, `'strict-dynamic'`];
    const connectSrc = [`'self'`];
    const frameSrc = [];

    if (process.env.TURNSTILE_SITE_KEY) {
      scriptSrc.push('https://challenges.cloudflare.com');
      frameSrc.push('https://challenges.cloudflare.com');
      connectSrc.push('https://challenges.cloudflare.com');
    }

    const csp = [
      `default-src 'none'`,
      `base-uri 'none'`,
      `form-action 'self'`,
      `frame-ancestors 'none'`,
      `img-src 'self' https://cdn.discordapp.com data:`,
      `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com`,
      `font-src https://fonts.gstatic.com`,
      `script-src ${scriptSrc.join(' ')}`,
      `connect-src ${connectSrc.join(' ')}`,
      frameSrc.length ? `frame-src ${frameSrc.join(' ')}` : `frame-src 'none'`
    ].join('; ');

    res.setHeader('Content-Security-Policy', csp);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), payment=(), usb=()');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');

    if (secure) {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    }

    next();
  };
}

module.exports = {
  securityHeaders,
  issueSessionCookie,
  readSessionCookie,
  clearSessionCookie,
  isSecureDeployment,
  cookieName
};
