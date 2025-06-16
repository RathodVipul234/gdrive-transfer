# Railway Deployment Guide

## 1. Setup Railway Account
1. Go to [Railway.app](https://railway.app) and sign up
2. Install Railway CLI: `npm install -g @railway/cli`
3. Login: `railway login`

## 2. Create Database (Supabase)
1. Go to [Supabase.com](https://supabase.com) and create account
2. Create new project
3. Go to Settings > Database
4. Copy connection string (replace [YOUR-PASSWORD])

## 3. Deploy to Railway
1. Navigate to your project directory
2. Run: `railway init`
3. Run: `railway up`

## 4. Set Environment Variables
In Railway dashboard, add these variables:
```
SECRET_KEY=your-generated-secret-key
DEBUG=False
DATABASE_URL=postgresql://postgres.xyz:[YOUR-PASSWORD]@aws-0-region.pooler.supabase.com:port/postgres
ALLOWED_HOSTS=your-app.railway.app
BASE_URL=https://your-app.railway.app
GOOGLE_OAUTH_PATH=new_cred.json
```

## 5. Update Google OAuth
1. Go to Google Cloud Console
2. Update OAuth redirect URIs:
   - https://your-app.railway.app/oauth2callback/source/
   - https://your-app.railway.app/oauth2callback/destination/

## 6. Deploy
Your app will auto-deploy on push. Railway provides:
- Always-on free tier
- No cold starts
- Automatic SSL
- Custom domain support

## Commands
- `railway up` - Deploy
- `railway logs` - View logs
- `railway variables` - Manage env vars
- `railway open` - Open deployed app