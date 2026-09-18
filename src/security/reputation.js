const axios = require('axios');
const { TtlMap, register } = require('./store');
const { isPrivateIp } = require('./net');

const cache = register(new TtlMap('ip-reputation', 20000));
const inflight = new Map();

const HOSTING_KEYWORDS = [
  'ovh', 'digitalocean', 'digital ocean', 'hetzner', 'linode', 'akamai connected cloud',
  'vultr', 'choopa', 'amazon', 'aws', 'google cloud', 'google llc', 'microsoft', 'azure',
  'oracle cloud', 'alibaba', 'aliyun', 'tencent', 'huawei cloud', 'contabo', 'leaseweb',
  'm247', 'datacamp', 'cdn77', 'g-core', 'gcore', 'scaleway', 'online s.a.s', 'hostinger',
  'namecheap', 'godaddy', 'ionos', '1&1', 'rackspace', 'softlayer', 'ibm cloud',
  'server', 'hosting', 'datacenter', 'data center', 'dedicated', 'colocation', 'colo',
  'cloud', 'vps', 'virtual private server', 'psychz', 'quadranet', 'phoenixnap',
  'zenlayer', 'clouvider', 'servers.com', 'melbicom', 'flokinet', 'privex',
  'xtom', 'vpsserver', 'heficed', 'evoxt', 'racknerd', 'buyvm', 'frantech'
];

const VPN_KEYWORDS = [
  'nordvpn', 'expressvpn', 'surfshark', 'cyberghost', 'private internet access',
  'protonvpn', 'proton ag', 'mullvad', 'ipvanish', 'purevpn', 'hidemyass', 'hma',
  'windscribe', 'tunnelbear', 'vyprvpn', 'strongvpn', 'torguard', 'perfect privacy',
  'privatevpn', 'zenmate', 'hotspot shield', 'anchorfree', 'pango', 'aura',
  'vpn', 'proxy', 'anonymous', 'tor exit', 'relay'
];

function config() {
  return {
    blockScore: parseInt(process.env.NETWORK_BLOCK_SCORE || '60', 10),
    cacheTtlMs: parseInt(process.env.NETWORK_CACHE_TTL_MINUTES || '360', 10) * 60 * 1000,
    timeoutMs: parseInt(process.env.NETWORK_LOOKUP_TIMEOUT_MS || '4000', 10),
    failMode: (process.env.VPN_FAIL_MODE || 'auto').toLowerCase(),
    allowedCountries: splitList(process.env.ALLOWED_COUNTRIES),
    blockedCountries: splitList(process.env.BLOCKED_COUNTRIES),
    blockedAsns: splitList(process.env.BLOCKED_ASNS),
    allowedAsns: splitList(process.env.ALLOWED_ASNS),
    allowHosting: process.env.ALLOW_HOSTING_PROVIDERS === 'true'
  };
}

function splitList(raw) {
  if (!raw) return [];
  return raw.split(',').map(s => s.trim().toUpperCase()).filter(Boolean);
}

function hasKeyedProvider() {
  return Boolean(process.env.VPNAPI_KEY || process.env.IPQS_KEY || process.env.PROXYCHECK_KEY);
}

function matchKeyword(text, keywords) {
  if (!text) return null;
  const lower = String(text).toLowerCase();
  return keywords.find(keyword => lower.includes(keyword)) || null;
}

async function queryVpnApi(ip, timeoutMs) {
  const key = process.env.VPNAPI_KEY;
  if (!key) return null;

  const { data } = await axios.get(`https://vpnapi.io/api/${encodeURIComponent(ip)}`, {
    params: { key },
    timeout: timeoutMs
  });
  if (!data?.security) return null;

  const signals = [];
  let score = 0;
  if (data.security.vpn) { score = Math.max(score, 100); signals.push('vpnapi:vpn'); }
  if (data.security.proxy) { score = Math.max(score, 100); signals.push('vpnapi:proxy'); }
  if (data.security.tor) { score = Math.max(score, 100); signals.push('vpnapi:tor'); }
  if (data.security.relay) { score = Math.max(score, 85); signals.push('vpnapi:relay'); }

  return {
    source: 'vpnapi.io',
    score,
    signals,
    country: data.location?.country_code,
    asn: data.network?.autonomous_system_number,
    org: data.network?.autonomous_system_organization
  };
}

async function queryIpqs(ip, timeoutMs) {
  const key = process.env.IPQS_KEY;
  if (!key) return null;

  const { data } = await axios.get(
    `https://ipqualityscore.com/api/json/ip/${encodeURIComponent(key)}/${encodeURIComponent(ip)}`,
    { params: { strictness: 1, allow_public_access_points: true }, timeout: timeoutMs }
  );
  if (!data || data.success === false) return null;

  const signals = [];
  let score = 0;
  if (data.vpn) { score = Math.max(score, 100); signals.push('ipqs:vpn'); }
  if (data.proxy) { score = Math.max(score, 95); signals.push('ipqs:proxy'); }
  if (data.tor) { score = Math.max(score, 100); signals.push('ipqs:tor'); }
  if (data.active_vpn) { score = Math.max(score, 100); signals.push('ipqs:active_vpn'); }
  if (data.bot_status) { score = Math.max(score, 90); signals.push('ipqs:bot'); }
  if (data.recent_abuse) { score = Math.max(score, 80); signals.push('ipqs:recent_abuse'); }
  if (typeof data.fraud_score === 'number' && data.fraud_score >= 85) {
    score = Math.max(score, data.fraud_score);
    signals.push(`ipqs:fraud_${data.fraud_score}`);
  }

  return {
    source: 'ipqualityscore',
    score,
    signals,
    country: data.country_code,
    asn: data.ASN,
    org: data.ISP || data.organization
  };
}

async function queryProxyCheck(ip, timeoutMs) {
  const key = process.env.PROXYCHECK_KEY;
  if (!key) return null;

  const { data } = await axios.get(`https://proxycheck.io/v2/${encodeURIComponent(ip)}`, {
    params: { key, vpn: 3, asn: 1, risk: 1 },
    timeout: timeoutMs
  });
  const entry = data?.[ip];
  if (!entry) return null;

  const signals = [];
  let score = 0;
  if (entry.proxy === 'yes') {
    score = Math.max(score, entry.type === 'VPN' ? 100 : 90);
    signals.push(`proxycheck:${(entry.type || 'proxy').toLowerCase()}`);
  }
  if (typeof entry.risk === 'number' && entry.risk >= 66) {
    score = Math.max(score, entry.risk);
    signals.push(`proxycheck:risk_${entry.risk}`);
  }

  return {
    source: 'proxycheck.io',
    score,
    signals,
    country: entry.isocode,
    asn: entry.asn ? String(entry.asn).replace(/^AS/i, '') : undefined,
    org: entry.provider || entry.organisation
  };
}

async function queryIpApi(ip, timeoutMs) {
  const { data } = await axios.get(`http://ip-api.com/json/${encodeURIComponent(ip)}`, {
    params: { fields: 'status,message,countryCode,proxy,hosting,mobile,org,isp,as,asname' },
    timeout: timeoutMs
  });
  if (data?.status !== 'success') return null;

  const signals = [];
  let score = 0;
  if (data.proxy) { score = Math.max(score, 90); signals.push('ipapi:proxy'); }
  if (data.hosting) { score = Math.max(score, 75); signals.push('ipapi:hosting'); }
  if (data.mobile) { score = Math.min(score, 20); signals.push('ipapi:mobile'); }

  const asnMatch = /^AS(\d+)/i.exec(data.as || '');
  return {
    source: 'ip-api.com',
    score,
    signals,
    country: data.countryCode,
    asn: asnMatch ? asnMatch[1] : undefined,
    org: data.org || data.isp || data.asname,
    mobile: Boolean(data.mobile)
  };
}

function heuristicScore(org, isMobile) {
  const signals = [];
  let score = 0;

  const vpnHit = matchKeyword(org, VPN_KEYWORDS);
  if (vpnHit) {
    score = Math.max(score, 95);
    signals.push(`heuristic:vpn_org(${vpnHit})`);
  }

  const hostingHit = matchKeyword(org, HOSTING_KEYWORDS);
  if (hostingHit && !isMobile) {
    score = Math.max(score, 70);
    signals.push(`heuristic:hosting_org(${hostingHit})`);
  }

  return { score, signals };
}

async function runSources(ip, cfg) {
  const tasks = [
    queryVpnApi(ip, cfg.timeoutMs),
    queryIpqs(ip, cfg.timeoutMs),
    queryProxyCheck(ip, cfg.timeoutMs),
    queryIpApi(ip, cfg.timeoutMs)
  ];

  const settled = await Promise.allSettled(tasks);
  const results = [];
  const errors = [];

  for (const outcome of settled) {
    if (outcome.status === 'fulfilled') {
      if (outcome.value) results.push(outcome.value);
    } else {
      errors.push(outcome.reason?.message || String(outcome.reason));
    }
  }

  return { results, errors };
}

async function assessNetwork(ip) {
  const cfg = config();

  if (!ip) {
    return { verdict: 'block', score: 100, signals: ['no_ip'], reason: 'クライアントIPを特定できませんでした。' };
  }

  if (isPrivateIp(ip)) {
    return { verdict: 'allow', score: 0, signals: ['private_ip'], cached: false };
  }

  const cached = cache.get(ip);
  if (cached) return { ...cached, cached: true };

  if (inflight.has(ip)) return inflight.get(ip);

  const promise = (async () => {
    const { results, errors } = await runSources(ip, cfg);

    const country = results.find(r => r.country)?.country;
    const asn = results.find(r => r.asn)?.asn;
    const org = results.find(r => r.org)?.org;
    const isMobile = results.some(r => r.mobile);

    let score = 0;
    let signals = [];
    for (const result of results) {
      score = Math.max(score, result.score);
      signals = signals.concat(result.signals);
    }

    const heuristic = heuristicScore(org, isMobile);
    score = Math.max(score, heuristic.score);
    signals = signals.concat(heuristic.signals);

    if (cfg.allowHosting) {
      signals = signals.filter(s => !s.includes('hosting'));
      if (!signals.some(s => /vpn|proxy|tor|bot|abuse|fraud|risk/.test(s))) score = 0;
    }

    const decision = applyPolicies({ score, signals, country, asn, org, errors, results, cfg });
    cache.set(ip, decision, cfg.cacheTtlMs);
    return { ...decision, cached: false };
  })().finally(() => inflight.delete(ip));

  inflight.set(ip, promise);
  return promise;
}

function applyPolicies({ score, signals, country, asn, org, errors, results, cfg }) {
  const base = { score, signals, country, asn, org, sources: results.map(r => r.source), errors };

  if (results.length === 0) {
    const failClosed = cfg.failMode === 'closed' || (cfg.failMode === 'auto' && hasKeyedProvider());
    if (failClosed) {
      return {
        ...base,
        verdict: 'block',
        score: 100,
        reason: 'ネットワーク検査サービスに到達できなかったため、安全側に倒して接続を拒否しました。時間をおいて再度お試しください。'
      };
    }
    return { ...base, verdict: 'allow', score: 0, signals: [...signals, 'lookup_failed_open'] };
  }

  if (asn && cfg.allowedAsns.length > 0 && cfg.allowedAsns.includes(String(asn).toUpperCase())) {
    return { ...base, verdict: 'allow', score: 0, signals: [...signals, 'asn_allowlist'] };
  }

  if (asn && cfg.blockedAsns.includes(String(asn).toUpperCase())) {
    return { ...base, verdict: 'block', score: 100, reason: 'アクセス元のネットワーク事業者が拒否対象に指定されています。' };
  }

  if (country && cfg.blockedCountries.includes(country.toUpperCase())) {
    return { ...base, verdict: 'block', score: 100, reason: 'お住まいの地域からの接続は許可されていません。' };
  }

  if (cfg.allowedCountries.length > 0 && (!country || !cfg.allowedCountries.includes(country.toUpperCase()))) {
    return { ...base, verdict: 'block', score: 100, reason: '許可された地域以外からの接続は受け付けていません。' };
  }

  if (score >= cfg.blockScore) {
    return {
      ...base,
      verdict: 'block',
      reason: 'VPN、Tor、プロキシ、またはホスティング事業者（VPS/クラウド）のネットワークが検出されました。VPN・プロキシを完全に無効化し、携帯キャリア回線または家庭用回線から再度アクセスしてください。'
    };
  }

  return { ...base, verdict: 'allow' };
}

function stats() {
  return { cacheSize: cache.size, inflight: inflight.size, keyedProvider: hasKeyedProvider() };
}

module.exports = { assessNetwork, stats };
