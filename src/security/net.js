const ipaddr = require('ipaddr.js');

const CLOUDFLARE_CIDRS = [
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
  '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
  '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
  '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
  '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
  '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32'
];

const PRIVATE_RANGES = ['loopback', 'private', 'linkLocal', 'uniqueLocal', 'unspecified'];

let trustedRanges = null;
let trustsCloudflare = false;

function parseCidr(entry) {
  try {
    return ipaddr.parseCIDR(entry.includes('/') ? entry : `${entry}/${entry.includes(':') ? 128 : 32}`);
  } catch {
    console.warn(`[Security] TRUSTED_PROXY_CIDRS の値を解釈できません: ${entry}`);
    return null;
  }
}

function loadTrustedRanges() {
  if (trustedRanges) return trustedRanges;

  const raw = (process.env.TRUSTED_PROXY_CIDRS || 'none').trim();
  const entries = raw.split(',').map(s => s.trim()).filter(Boolean);
  const ranges = [];

  for (const entry of entries) {
    const lower = entry.toLowerCase();
    if (lower === 'cloudflare') {
      trustsCloudflare = true;
      for (const cidr of CLOUDFLARE_CIDRS) {
        const parsed = parseCidr(cidr);
        if (parsed) ranges.push(parsed);
      }
    } else if (lower === 'private') {
      ranges.push('PRIVATE');
    } else if (lower === 'none') {
      // do nothing
    } else {
      const parsed = parseCidr(entry);
      if (parsed) ranges.push(parsed);
    }
  }

  trustedRanges = ranges;
  return trustedRanges;
}

function normalizeIp(ip) {
  if (!ip) return null;
  let value = String(ip).trim();

  if (value.startsWith('[')) {
    const close = value.indexOf(']');
    if (close > 0) value = value.slice(1, close);
  } else {
    const parts = value.split(':');
    if (parts.length === 2) value = parts[0];
  }

  if (!ipaddr.isValid(value)) return null;

  const addr = ipaddr.parse(value);
  if (addr.kind() === 'ipv6' && addr.isIPv4MappedAddress()) {
    return addr.toIPv4Address().toString();
  }
  return addr.toString();
}

function isPrivateIp(ip) {
  const normalized = normalizeIp(ip);
  if (!normalized) return false;
  try {
    return PRIVATE_RANGES.includes(ipaddr.parse(normalized).range());
  } catch {
    return false;
  }
}

function isTrustedProxy(ip) {
  const normalized = normalizeIp(ip);
  if (!normalized) return false;

  const ranges = loadTrustedRanges();
  if (ranges.length === 0) return false;

  let addr;
  try {
    addr = ipaddr.parse(normalized);
  } catch {
    return false;
  }

  for (const range of ranges) {
    if (range === 'PRIVATE') {
      if (PRIVATE_RANGES.includes(addr.range())) return true;
      continue;
    }
    const [rangeAddr] = range;
    if (rangeAddr.kind() !== addr.kind()) continue;
    if (addr.match(range)) return true;
  }
  return false;
}

function resolveClientIp(req) {
  const socketIp = normalizeIp(req.socket?.remoteAddress);
  if (!socketIp) return null;

  if (!isTrustedProxy(socketIp)) {
    return { ip: socketIp, viaProxy: false, spoofAttempt: hasProxyHeaders(req) };
  }

  if (trustsCloudflare) {
    const cfIp = normalizeIp(req.headers['cf-connecting-ip']);
    if (cfIp) return { ip: cfIp, viaProxy: true, spoofAttempt: false };
  }

  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const chain = String(forwarded).split(',').map(s => normalizeIp(s)).filter(Boolean);
    for (let i = chain.length - 1; i >= 0; i--) {
      if (!isTrustedProxy(chain[i])) {
        return { ip: chain[i], viaProxy: true, spoofAttempt: false };
      }
    }
  }

  const realIp = normalizeIp(req.headers['x-real-ip']);
  if (realIp) return { ip: realIp, viaProxy: true, spoofAttempt: false };

  return { ip: socketIp, viaProxy: true, spoofAttempt: false };
}

function hasProxyHeaders(req) {
  return Boolean(
    req.headers['cf-connecting-ip'] ||
    req.headers['x-real-ip'] ||
    req.headers['x-forwarded-for']
  );
}

function subnetKey(ip) {
  const normalized = normalizeIp(ip);
  if (!normalized) return 'unknown';
  try {
    const addr = ipaddr.parse(normalized);
    if (addr.kind() === 'ipv4') {
      const octets = addr.toByteArray();
      return `${octets[0]}.${octets[1]}.${octets[2]}.0/24`;
    }
    const bytes = addr.toByteArray().slice(0, 6);
    return `${Buffer.from(bytes).toString('hex')}::/48`;
  } catch {
    return normalized;
  }
}

function expressTrustProxyFn() {
  return (ip) => isTrustedProxy(ip);
}

function describeTrustConfig() {
  const raw = (process.env.TRUSTED_PROXY_CIDRS || 'none').trim();
  const ranges = loadTrustedRanges();
  if (ranges.length === 0) return 'none (プロキシヘッダを無視)';
  return raw;
}

function diagnoseTrustConfig(req, resolved) {
  const socketIp = normalizeIp(req.socket?.remoteAddress);
  const headers = {
    'cf-connecting-ip': req.headers['cf-connecting-ip'],
    'x-real-ip': req.headers['x-real-ip'],
    'x-forwarded-for': req.headers['x-forwarded-for']
  };
  const present = Object.entries(headers).filter(([, v]) => v);

  const issues = [];

  if (present.length > 0 && !isTrustedProxy(socketIp)) {
    const suggestion = headers['cf-connecting-ip']
      ? 'TRUSTED_PROXY_CIDRS=cloudflare'
      : (isPrivateIp(socketIp) ? 'TRUSTED_PROXY_CIDRS=private' : `TRUSTED_PROXY_CIDRS=${socketIp}/32`);

    issues.push(
      `プロキシ系ヘッダ (${present.map(([k]) => k).join(', ')}) が届いていますが、` +
      `接続元 ${socketIp} を信頼していないため無視しています。` +
      `全利用者が ${socketIp} として扱われている場合、この設定は誤りです。正しければ .env に ${suggestion} を設定してください。`
    );
  }

  if (present.length === 0 && isPrivateIp(socketIp)) {
    issues.push(
      `接続元がプライベートアドレス (${socketIp}) ですが、プロキシヘッダが付いていません。` +
      `手前のリバースプロキシが X-Forwarded-For を転送していない可能性があります。`
    );
  }

  return { socketIp, resolvedIp: resolved?.ip, headers, issues };
}

module.exports = {
  resolveClientIp,
  isTrustedProxy,
  isPrivateIp,
  normalizeIp,
  subnetKey,
  expressTrustProxyFn,
  describeTrustConfig,
  diagnoseTrustConfig
};
