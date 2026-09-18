require('dotenv').config();

const { setupBot } = require('./bot');
const { startWebServer } = require('./server');
const { registerCommands } = require('../register');

const REQUIRED_ENV = ['DISCORD_TOKEN', 'CLIENT_ID', 'CLIENT_SECRET', 'GUILD_ID', 'ROLE_ID', 'REDIRECT_URI'];

function validateEnvironment() {
  const missing = REQUIRED_ENV.filter(key => !process.env[key]);
  if (missing.length > 0) {
    console.error(`[Error] 起動に失敗しました。以下の環境変数が設定されていません: ${missing.join(', ')}`);
    console.error('[Error] .env ファイルを作成して適切な値を設定してください。(.env.example を参考にしてください)');
    process.exit(1);
  }

  try {
    const redirect = new URL(process.env.REDIRECT_URI);
    if (!redirect.pathname.endsWith('/api/auth/callback')) {
      console.warn('[Warn] REDIRECT_URI のパスが /api/auth/callback で終わっていません。Discord 側の設定と一致しているか確認してください。');
    }
    if (redirect.protocol !== 'https:' && redirect.hostname !== 'localhost' && redirect.hostname !== '127.0.0.1') {
      console.warn('[Warn] REDIRECT_URI が HTTPS ではありません。本番環境では必ず HTTPS を使用してください。');
    }
  } catch {
    console.error('[Error] REDIRECT_URI が有効な URL ではありません。');
    process.exit(1);
  }

  if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
    console.warn('[Warn] SESSION_SECRET が未設定または短すぎます。32文字以上のランダム文字列を設定してください。');
    console.warn('[Warn] 生成例: node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'base64url\'))"');
  }

  if (!process.env.TRUSTED_PROXY_CIDRS) {
    console.warn('[Warn] TRUSTED_PROXY_CIDRS が未設定のため、プロキシヘッダを一切信用しません (最も安全な既定)。');
    console.warn('[Warn] 手前にリバースプロキシがある場合はこのままだと全利用者が同じIPに見え、全員ブロックされます。');
    console.warn('[Warn] 最初のアクセス時にログへ出る trust_config_diagnosis の socketIp を確認し、必要なら');
    console.warn('[Warn]   nginx等が手前 → TRUSTED_PROXY_CIDRS=private');
    console.warn('[Warn]   Cloudflare経由 → TRUSTED_PROXY_CIDRS=cloudflare');
    console.warn('[Warn] を .env に設定してください。');
  }
}

validateEnvironment();

console.log('[System] Initializing Discord Bot & Web Server...');

const botClient = setupBot();
const server = startWebServer(botClient);

botClient.login(process.env.DISCORD_TOKEN)
  .then(() => registerCommands(process.env.CLIENT_ID, process.env.DISCORD_TOKEN, process.env.GUILD_ID))
  .catch(err => {
    console.error('[Bot] Discordへのログインに失敗しました。DISCORD_TOKENが正しいか確認してください:', err.message);
    process.exit(1);
  });

function shutdown(signal) {
  console.log(`[System] ${signal} を受信しました。終了処理を行います...`);
  server.close(() => {
    botClient.destroy();
    process.exit(0);
  });
  setTimeout(() => process.exit(0), 10000).unref();
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

process.on('unhandledRejection', reason => {
  console.error('[System] 未処理の Promise 拒否:', reason);
});
process.on('uncaughtException', err => {
  console.error('[System] 未捕捉の例外:', err);
  process.exit(1);
});
