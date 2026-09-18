process.env.SESSION_SECRET = 'integration-test-secret-value-long-enough-for-hmac';
process.env.TRUSTED_PROXY_CIDRS = 'private';
process.env.CLIENT_ID = '100000000000000000';
process.env.CLIENT_SECRET = 'test-client-secret';
process.env.GUILD_ID = '200000000000000000';
process.env.ROLE_ID = '300000000000000000';
process.env.REDIRECT_URI = 'http://127.0.0.1:0/api/auth/callback';
process.env.PORT = '0';
process.env.SECURE_COOKIES = 'false';
process.env.POW_DIFFICULTY_BITS = '12';

const assert = require('assert');
const http = require('http');

const { startWebServer } = require('../src/server');

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  ok  ${name}`);
  } catch (err) {
    failed++;
    console.error(`  FAIL ${name}\n       ${err.message}`);
  }
}

const botStub = {
  guilds: { fetch: async () => { throw new Error('not reached'); } },
  channels: { fetch: async () => { throw new Error('not reached'); } }
};

function request(port, pathname, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port, path: pathname, method, headers },
      res => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
      }
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

(async () => {
  const server = startWebServer(botStub);
  await new Promise(resolve => server.on('listening', resolve));
  const port = server.address().port;

  console.log('\n認証フロー — 入口の検証');

  let startResponse;
  await test('/api/auth/start が署名付き state を持つ Discord URL へ転送する', async () => {
    startResponse = await request(port, '/api/auth/start');
    assert.strictEqual(startResponse.status, 302);

    const location = startResponse.headers.location;
    assert.ok(location.startsWith('https://discord.com/oauth2/authorize'), `転送先が不正: ${location}`);

    const state = new URL(location).searchParams.get('state');
    assert.ok(state && state.includes('.'), 'state が付与されていない');
    assert.ok(state.length > 40, 'state が短すぎる');
  });

  await test('セッション Cookie が HttpOnly / SameSite 付きで発行される', async () => {
    const cookies = startResponse.headers['set-cookie'];
    assert.ok(cookies && cookies.length > 0, 'Cookie が発行されていない');
    const cookie = cookies[0];
    assert.ok(/HttpOnly/i.test(cookie), 'HttpOnly が無い');
    assert.ok(/SameSite=Lax/i.test(cookie), 'SameSite が無い');
  });

  await test('セキュリティヘッダが付与されている', async () => {
    const res = await request(port, '/healthz');
    const expected = {
      'content-security-policy': /default-src 'none'/,
      'x-content-type-options': /nosniff/,
      'x-frame-options': /DENY/,
      'referrer-policy': /no-referrer/,
      'cache-control': /no-store/
    };
    for (const [header, pattern] of Object.entries(expected)) {
      assert.ok(pattern.test(res.headers[header] || ''), `${header} が不正: ${res.headers[header]}`);
    }
    assert.strictEqual(res.headers['x-powered-by'], undefined, 'X-Powered-By が露出している');
  });

  await test('CSP の nonce がリクエストごとに変わる', async () => {
    const a = await request(port, '/healthz');
    const b = await request(port, '/healthz');
    const nonceOf = res => /'nonce-([^']+)'/.exec(res.headers['content-security-policy'] || '')?.[1];
    assert.ok(nonceOf(a) && nonceOf(b), 'nonce が付いていない');
    assert.notStrictEqual(nonceOf(a), nonceOf(b), 'nonce が使い回されている');
  });

  console.log('\nコールバック — state 検証');

  await test('state 無しのコールバックを拒否する', async () => {
    const res = await request(port, '/api/auth/callback?code=fakecode');
    assert.strictEqual(res.status, 302);
    assert.ok(res.headers.location.startsWith('/api/auth/result?t='), `想定外の転送: ${res.headers.location}`);
  });

  await test('偽造した state を拒否する', async () => {
    const res = await request(port, '/api/auth/callback?code=fakecode&state=forged.signature');
    assert.ok(res.headers.location.startsWith('/api/auth/result?t='));

    const token = new URL(res.headers.location, 'http://x').searchParams.get('t');
    const page = await request(port, `/api/auth/result?t=${encodeURIComponent(token)}`);
    assert.strictEqual(page.status, 403);
    assert.ok(page.body.includes('state_invalid'), '理由コードが記録されていない');
  });

  await test('正しい state でも Cookie が無ければ拒否する', async () => {
    const start = await request(port, '/api/auth/start');
    const state = new URL(start.headers.location).searchParams.get('state');

    const res = await request(port, `/api/auth/callback?code=fakecode&state=${encodeURIComponent(state)}`);
    const token = new URL(res.headers.location, 'http://x').searchParams.get('t');
    const page = await request(port, `/api/auth/result?t=${encodeURIComponent(token)}`);
    assert.ok(page.body.includes('cookie_mismatch'), `想定外の理由: ${page.body.slice(0, 400)}`);
  });

  await test('同じ state を2回使えない (リプレイ防止)', async () => {
    const start = await request(port, '/api/auth/start');
    const state = new URL(start.headers.location).searchParams.get('state');
    const cookie = start.headers['set-cookie'][0].split(';')[0];

    const first = await request(port, `/api/auth/callback?code=fakecode&state=${encodeURIComponent(state)}`, {
      headers: { cookie }
    });
    assert.strictEqual(first.status, 302);

    const second = await request(port, `/api/auth/callback?code=fakecode&state=${encodeURIComponent(state)}`, {
      headers: { cookie }
    });
    const token = new URL(second.headers.location, 'http://x').searchParams.get('t');
    const page = await request(port, `/api/auth/result?t=${encodeURIComponent(token)}`);
    assert.ok(page.body.includes('state_replayed'), `リプレイが検出されていない: ${page.body.slice(0, 400)}`);
  });

  console.log('\n検証エンドポイント');

  await test('セッション無しの verify を拒否する', async () => {
    const body = JSON.stringify({ sessionId: 'made-up-session', powNonce: '1', signals: {} });
    const res = await request(port, '/api/auth/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      body
    });
    assert.strictEqual(res.status, 400);
    const payload = JSON.parse(res.body);
    assert.strictEqual(payload.ok, false);
  });

  await test('旧エンドポイント /api/auth/verify-captcha が存在しない', async () => {
    const body = 'token=anything';
    const res = await request(port, '/api/auth/verify-captcha', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) },
      body
    });
    assert.strictEqual(res.status, 404, '旧来のバイパス経路が残っている');
  });

  await test('壊れた JSON に 400 を返す', async () => {
    const body = '{not json';
    const res = await request(port, '/api/auth/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      body
    });
    assert.strictEqual(res.status, 400);
  });

  await test('巨大な本文を拒否する', async () => {
    const body = JSON.stringify({ sessionId: 'x', signals: { pad: 'A'.repeat(64 * 1024) } });
    const res = await request(port, '/api/auth/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      body
    });
    assert.ok(res.status === 400 || res.status === 413, `受理されてしまった: ${res.status}`);
  });

  console.log('\n結果ページ');

  await test('期限切れトークンでも情報を漏らさない', async () => {
    const res = await request(port, '/api/auth/result?t=nonexistent');
    assert.strictEqual(res.status, 400);
    assert.ok(res.body.includes('やり直して'));
  });

  await test('存在しないパスは 404 を返す', async () => {
    const res = await request(port, '/etc/passwd');
    assert.strictEqual(res.status, 404);
  });

  console.log('\nIP 詐称');

  await test('プロキシヘッダを偽装しても接続元を差し替えられない', async () => {
    const res = await request(port, '/api/auth/start', {
      headers: { 'x-forwarded-for': 'not-an-ip, ../../etc/passwd', 'cf-connecting-ip': '<script>' }
    });
    assert.strictEqual(res.status, 302, `想定外の応答: ${res.status}`);
  });

  console.log('\n失敗の累積で締め出さないこと');

  await test('連続して失敗しても次の試行は普通に開始できる', async () => {
    for (let i = 0; i < 12; i++) {
      await request(port, `/api/auth/callback?code=x&state=bogus.${i}`);
    }

    const start = await request(port, '/api/auth/start');
    assert.strictEqual(start.status, 302, `開始が拒否された: ${start.status}`);
    assert.ok(
      start.headers.location.startsWith('https://discord.com/oauth2/authorize'),
      `締め出されている: ${start.headers.location}`
    );
  });

  server.close();
  console.log(`\n${'-'.repeat(50)}`);
  console.log(`${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
})();
