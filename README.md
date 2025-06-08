# GDrive Transfer - Google Drive File Migration Tool

A Django web application for transferring files between Google Drive accounts with real-time progress tracking.

## Features

- 🔐 Secure OAuth authentication with Google
- 📁 Transfer files and folders between Google Drive accounts
- 📊 Real-time progress tracking
- 🎨 Modern, responsive UI
- 📱 Mobile-friendly design
- 📈 Transfer history and logs

## Free Hosting Options

### 1. Render (Recommended)

1. **Create accounts:**
   - Sign up at [render.com](https://render.com)
   - Connect your GitHub account

2. **Push to GitHub:**
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git branch -M main
   git remote add origin https://github.com/yourusername/gdrive-transfer.git
   git push -u origin main
   ```

3. **Deploy on Render:**
   - Create new "Web Service" from GitHub repo
   - Render will auto-detect the `render.yaml` file
   - Set environment variables:
     - `SECRET_KEY`: Generate a secure key
     - `DEBUG`: False
     - `BASE_URL`: https://your-app-name.onrender.com
     - `ALLOWED_HOSTS`: your-app-name.onrender.com

4. **Update Google OAuth:**
   - Go to [Google Cloud Console](https://console.cloud.google.com)
   - Update redirect URIs to:
     - `https://your-app-name.onrender.com/oauth2callback/source/`
     - `https://your-app-name.onrender.com/oauth2callback/destination/`

### 2. Railway

1. **Install Railway CLI:**
   ```bash
   npm install -g @railway/cli
   railway login
   ```

2. **Deploy:**
   ```bash
   railway new
   railway add
   railway deploy
   ```

3. **Set environment variables in Railway dashboard**

### 3. PythonAnywhere

1. **Upload files** to PythonAnywhere
2. **Create virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
3. **Configure web app** in PythonAnywhere dashboard
4. **Set environment variables** in .env file

## Local Development

1. **Clone and setup:**
   ```bash
   git clone <repository-url>
   cd gdrive_transfer
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Environment setup:**
   ```bash
   cp .env.example .env
   # Edit .env with your values
   ```

3. **Database setup:**
   ```bash
   python manage.py migrate
   python manage.py createsuperuser
   ```

4. **Run development server:**
   ```bash
   python manage.py runserver
   ```

## Google OAuth Setup

1. **Create project** at [Google Cloud Console](https://console.cloud.google.com)
2. **Enable APIs:**
   - Google Drive API
   - Google+ API
3. **Create OAuth credentials:**
   - Application type: Web application
   - Authorized redirect URIs:
     - `http://localhost:8005/oauth2callback/source/` (development)
     - `http://localhost:8005/oauth2callback/destination/` (development)
     - Your production URLs
4. **Download credentials** as `new_cred.json`

## Environment Variables

- `SECRET_KEY`: Django secret key
- `DEBUG`: True/False
- `ALLOWED_HOSTS`: Comma-separated hostnames
- `DATABASE_URL`: Database connection string
- `BASE_URL`: Your app's base URL
- `GOOGLE_OAUTH_PATH`: Path to OAuth credentials file

## Free Database Options

- **Render**: Free PostgreSQL (90 days)
- **Supabase**: Free PostgreSQL (500MB)
- **Neon**: Free PostgreSQL (512MB)
- **Railway**: Free PostgreSQL (temporary)

## Production Checklist

- [ ] Set `DEBUG=False`
- [ ] Configure `ALLOWED_HOSTS`
- [ ] Set secure `SECRET_KEY`
- [ ] Setup PostgreSQL database
- [ ] Update Google OAuth redirect URIs
- [ ] Configure static files serving
- [ ] Set up SSL certificate
- [ ] Monitor application logs

## Support

For issues and questions, create an issue in the repository.

## License

MIT License