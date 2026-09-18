# Auth

## セットアップ

npm install
cp .env.example .env
npm run secret          
npm test                 
npm start


## 認証の流れ
    → GET /api/auth/start 
    → discord.com/oauth2/authorize
    → GET /api/auth/callback 
    → POST /api/auth/verify
    → GET /api/auth/result 

