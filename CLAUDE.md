# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Django-based Google Drive transfer application that allows users to securely transfer files and folders between different Google Drive accounts. The application uses OAuth2 authentication to connect to both source and destination Google accounts and performs file transfers in background threads.

## Architecture

### Core Components

- **Django App**: `driveapp` - Main application handling Google Drive operations
- **Models**: 
  - `UserCredentials` - Stores OAuth tokens for Google accounts
  - `FileTransfer` - Tracks file transfer jobs and progress
- **Views**: Handle OAuth flow, file listing, transfer initiation, and status monitoring
- **Utils**: Core Google Drive API operations including file listing, folder creation, and file copying
- **Templates**: Bootstrap-based UI for the transfer wizard and status pages

### Key Files

- `driveapp/views.py` - Main application logic, OAuth handlers, transfer management
- `driveapp/utils.py` - Google Drive API utilities and file operations
- `driveapp/models.py` - Database models for credentials and transfers
- `gdrive_transfer/settings.py` - Django configuration with Google OAuth settings

### OAuth Flow

The application supports dual OAuth authentication:
- Source account authentication via `/login/source/` → `/oauth2callback/source/`
- Destination account authentication via `/login/destination/` → `/oauth2callback/destination/`

Credentials are stored in Django sessions, not the database for active transfers.

### Transfer Process

1. User authenticates both Google accounts
2. Application lists folders from both drives
3. User selects source and destination folders
4. Transfer job is created in database with unique UUID
5. Background thread performs recursive file/folder copying
6. Progress is tracked and can be monitored via API endpoints

## Development Commands

### Running the Application
```bash
# Activate virtual environment (if using venv)
venv/Scripts/activate  # Windows
# OR
source venv/bin/activate  # Linux/Mac

# Run development server
python manage.py runserver 8005

# Run with specific host/port
python manage.py runserver localhost:8005
```

### Database Operations
```bash
# Create and apply migrations
python manage.py makemigrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Django shell
python manage.py shell
```

### Development Setup

The application requires:
- Google OAuth2 credentials file (`new_cred.json` or `credentials.json`)
- Virtual environment with Google API libraries
- SQLite database (default)

## Important Configuration

### Google OAuth Setup
- Credentials file: `gdrive_transfer/credentials.json` or `new_cred.json`
- Redirect URIs configured in `settings.py`:
  - Source: `http://localhost:8005/oauth2callback/source/`
  - Destination: `http://localhost:8005/oauth2callback/destination/`

### Security Notes
- `DEBUG = True` in settings - should be False for production
- Secret key is hardcoded - should use environment variables in production
- OAuth credentials stored in session, not encrypted

### Logging
- Application logs to `driveapp/logs/app.log` and console
- File transfer logs include detailed progress information

## URL Structure

- `/` - Home page with transfer wizard
- `/login/source/` - Source account OAuth
- `/login/destination/` - Destination account OAuth  
- `/transfer/` - Initiate file transfer
- `/transfer-status/<uuid>/` - Transfer status page
- `/dashboard/` - View all transfers
- `/api/transfer-status/<uuid>/` - Transfer status API
- `/api/cancel-transfer/<uuid>/` - Cancel transfer API

## Common Development Tasks

### Adding New Google Drive Scopes
Update `SCOPES` list in `driveapp/views.py` and ensure OAuth consent screen includes new permissions.

### Modifying Transfer Logic
The main transfer logic is in `start_transfer()` function in `driveapp/views.py`. File operations are in `driveapp/utils.py`.

### Database Schema Changes
Create migrations after model changes:
```bash
python manage.py makemigrations driveapp
python manage.py migrate
```

## Known Issues to Address

1. **Hardcoded Admin User**: Line 202 in `views.py` uses hardcoded admin user - should use authenticated user
2. **Disabled Logging**: `LOGGING12` in settings is not used (should be `LOGGING`)
3. **Session Management**: OAuth tokens stored in sessions without encryption
4. **Error Handling**: Limited error handling for Google API failures
5. **File Copies**: Multiple view files (`views copy.py`, `views copy 2.py`) should be cleaned up
6. **Cancel Transfer Bug**: Line 335 in views.py uses `uuid` instead of `transfer_uuid` field