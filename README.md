# Rula Auth

## セットアップ

```bash
npm install
cp .env.example .env
npm run secret           # SESSION_SECRET 用のランダム鍵を生成
npm test                 # セキュリティテスト
npm start
```

## 認証の流れ

```
[Verify Account] ボタン
    → GET /api/auth/start (署名付き state 発行 + VPN 判定)
    → discord.com/oauth2/authorize
    → GET /api/auth/callback (state 検証 + PoW チャレンジ発行)
    → チャレンジ画面 (長押し + SHA-256 PoW)
    → POST /api/auth/verify (Cookie/セッション/PoW/シグナル突き合わせ → ロール付与)
    → GET /api/auth/result (結果表示)
```
