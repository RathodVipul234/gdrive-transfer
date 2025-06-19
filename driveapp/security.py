"""
Security utilities for GDrive Transfer application
Handles encryption, decryption, and security logging
"""
import os
import json
import logging
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import secrets
from django.conf import settings
from django.contrib.auth.models import User
from django.http import HttpRequest
import hashlib

logger = logging.getLogger(__name__)

class SecurityManager:
    """Centralized security management for the application"""
    
    def __init__(self):
        self.encryption_key = self._get_or_create_encryption_key()
        self.cipher_suite = Fernet(self.encryption_key)
    
    def _get_or_create_encryption_key(self):
        """Get or create encryption key for secure data storage"""
        key_file = os.path.join(settings.BASE_DIR, '.encryption_key')
        
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            # Generate new key
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            os.chmod(key_file, 0o600)  # Restrict file permissions
            return key
    
    def encrypt_credentials(self, credentials_dict):
        """Encrypt OAuth credentials for secure storage"""
        try:
            credentials_json = json.dumps(credentials_dict)
            encrypted_data = self.cipher_suite.encrypt(credentials_json.encode())
            return base64.b64encode(encrypted_data).decode()
        except Exception as e:
            logger.error(f"Failed to encrypt credentials: {str(e)}")
            raise
    
    def decrypt_credentials(self, encrypted_credentials):
        """Decrypt OAuth credentials for use"""
        try:
            encrypted_data = base64.b64decode(encrypted_credentials.encode())
            decrypted_data = self.cipher_suite.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except Exception as e:
            logger.error(f"Failed to decrypt credentials: {str(e)}")
            raise
    
    def generate_session_token(self):
        """Generate secure session token"""
        return secrets.token_urlsafe(32)
    
    def hash_sensitive_data(self, data):
        """Hash sensitive data for logging without exposing actual values"""
        return hashlib.sha256(str(data).encode()).hexdigest()[:16]

class SecurityAuditor:
    """Security audit logging and monitoring"""
    
    @staticmethod
    def log_security_event(event_type, user, details, request=None, severity='INFO'):
        """Log security-related events for audit purposes"""
        audit_entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'user': user.username if user and hasattr(user, 'username') else 'anonymous',
            'user_id': user.id if user and hasattr(user, 'id') else None,
            'severity': severity,
            'details': details,
            'ip_address': SecurityAuditor._get_client_ip(request) if request else None,
            'user_agent': request.META.get('HTTP_USER_AGENT', '') if request else None,
            'session_key': request.session.session_key if request and hasattr(request, 'session') else None
        }
        
        logger.info(f"SECURITY_AUDIT: {json.dumps(audit_entry)}")
        
        # Store in database for future reference
        from .models import SecurityLog
        try:
            SecurityLog.objects.create(
                event_type=event_type,
                user=user if user and hasattr(user, 'username') else None,
                severity=severity,
                details=json.dumps(details),
                ip_address=audit_entry['ip_address'],
                user_agent=audit_entry['user_agent'][:500] if audit_entry['user_agent'] else None
            )
        except Exception as e:
            logger.error(f"Failed to store security log: {str(e)}")
    
    @staticmethod
    def _get_client_ip(request):
        """Extract client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

class PrivacyManager:
    """Manage user privacy and data access transparency"""
    
    @staticmethod
    def get_data_access_summary(user):
        """Get summary of what data the application accesses"""
        return {
            'google_drive_scopes': [
                {
                    'scope': 'https://www.googleapis.com/auth/drive',
                    'description': 'Access to view and manage your Google Drive files',
                    'purpose': 'Required to list, read, and copy your files between accounts',
                    'data_accessed': ['File names', 'File contents', 'Folder structure', 'File metadata']
                },
                {
                    'scope': 'https://www.googleapis.com/auth/userinfo.email',
                    'description': 'Access to your email address',
                    'purpose': 'To identify your Google account and display it in the interface',
                    'data_accessed': ['Email address']
                },
                {
                    'scope': 'openid',
                    'description': 'OpenID Connect authentication',
                    'purpose': 'To securely authenticate your Google account',
                    'data_accessed': ['Basic profile information']
                }
            ],
            'local_data_storage': {
                'session_data': {
                    'description': 'Temporary authentication tokens and session information',
                    'retention': 'Cleared when you log out or session expires',
                    'encryption': 'Encrypted using AES-256'
                },
                'transfer_history': {
                    'description': 'Records of file transfers you have performed',
                    'retention': 'Stored permanently for your reference (can be deleted on request)',
                    'data_included': ['Transfer dates', 'Source/destination emails', 'File counts', 'Transfer status']
                }
            },
            'data_sharing': 'We never share your data with third parties. Files are transferred directly between your Google accounts.',
            'data_retention': 'OAuth tokens are discarded after use. Transfer logs are kept for your reference.',
            'user_rights': [
                'Request data deletion',
                'Export your data',
                'View all stored information',
                'Revoke access at any time'
            ]
        }
    
    @staticmethod
    def get_security_recommendations():
        """Get security recommendations for users"""
        return [
            {
                'title': 'Review OAuth Permissions',
                'description': 'Regularly review the apps connected to your Google account',
                'action': 'Visit Google Account Security settings',
                'priority': 'high'
            },
            {
                'title': 'Use Strong Passwords',
                'description': 'Ensure your Google account uses a strong, unique password',
                'action': 'Enable 2-factor authentication on your Google account',
                'priority': 'high'
            },
            {
                'title': 'Monitor Transfer Activity',
                'description': 'Keep track of your file transfers and report any suspicious activity',
                'action': 'Check your transfer history regularly',
                'priority': 'medium'
            },
            {
                'title': 'Secure Your Device',
                'description': 'Keep the device you use for transfers secure and up-to-date',
                'action': 'Use device lock screens and keep software updated',
                'priority': 'medium'
            }
        ]

# Global security manager instance
security_manager = SecurityManager()