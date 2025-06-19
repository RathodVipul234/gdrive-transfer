"""
Security middleware for GDrive Transfer application
"""
import time
import logging
import json
from collections import defaultdict
from django.conf import settings
from django.http import JsonResponse, HttpResponse
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver
from django.core.cache import cache
from .security import SecurityAuditor

# Custom HTTP 429 response for older Django versions
class HttpResponseTooManyRequests(HttpResponse):
    status_code = 429

logger = logging.getLogger(__name__)

class SecurityHeadersMiddleware(MiddlewareMixin):
    """Add comprehensive security headers to all responses"""
    
    def process_response(self, request, response):
        # Security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        
        # Content Security Policy
        if hasattr(settings, 'CSP_DEFAULT_SRC'):
            csp_parts = []
            csp_parts.append(f"default-src {' '.join(settings.CSP_DEFAULT_SRC)}")
            if hasattr(settings, 'CSP_SCRIPT_SRC'):
                csp_parts.append(f"script-src {' '.join(settings.CSP_SCRIPT_SRC)}")
            if hasattr(settings, 'CSP_STYLE_SRC'):
                csp_parts.append(f"style-src {' '.join(settings.CSP_STYLE_SRC)}")
            if hasattr(settings, 'CSP_FONT_SRC'):
                csp_parts.append(f"font-src {' '.join(settings.CSP_FONT_SRC)}")
            if hasattr(settings, 'CSP_IMG_SRC'):
                csp_parts.append(f"img-src {' '.join(settings.CSP_IMG_SRC)}")
            if hasattr(settings, 'CSP_CONNECT_SRC'):
                csp_parts.append(f"connect-src {' '.join(settings.CSP_CONNECT_SRC)}")
            
            response['Content-Security-Policy'] = '; '.join(csp_parts)
        
        # HSTS (only for HTTPS)
        if request.is_secure() and not settings.DEBUG:
            response['Strict-Transport-Security'] = f'max-age={settings.SECURE_HSTS_SECONDS}; includeSubDomains; preload'
        
        return response

class SecurityAuditMiddleware(MiddlewareMixin):
    """Audit security-related events"""
    
    def process_request(self, request):
        # Log suspicious activity
        if self._is_suspicious_request(request):
            SecurityAuditor.log_security_event(
                'suspicious_request',
                getattr(request, 'user', None),
                {
                    'path': request.path,
                    'method': request.method,
                    'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                    'reason': 'Suspicious request pattern detected'
                },
                request=request,
                severity='WARNING'
            )
        
        # Rate limiting
        if getattr(settings, 'RATE_LIMIT_ENABLE', False):
            if self._is_rate_limited(request):
                SecurityAuditor.log_security_event(
                    'rate_limit_exceeded',
                    getattr(request, 'user', None),
                    {
                        'path': request.path,
                        'method': request.method,
                        'ip': self._get_client_ip(request)
                    },
                    request=request,
                    severity='WARNING'
                )
                return JsonResponse({
                    'error': 'Rate limit exceeded. Please try again later.',
                    'retry_after': 60
                }, status=429)
        
        return None
    
    def _is_suspicious_request(self, request):
        """Detect suspicious request patterns"""
        suspicious_patterns = [
            'script>',
            'javascript:',
            'vbscript:',
            'onload=',
            'onerror=',
            'eval(',
            'document.cookie',
            'window.location',
            '../../../',
            '..\\..\\',
            'union select',
            'drop table',
            'insert into',
            'delete from',
        ]
        
        # Check query parameters
        for key, value in request.GET.items():
            if any(pattern.lower() in str(value).lower() for pattern in suspicious_patterns):
                return True
        
        # Check POST data
        if request.method == 'POST':
            try:
                post_data = request.body.decode('utf-8')
                if any(pattern.lower() in post_data.lower() for pattern in suspicious_patterns):
                    return True
            except:
                pass
        
        return False
    
    def _is_rate_limited(self, request):
        """Simple rate limiting implementation"""
        if not getattr(settings, 'RATE_LIMIT_ENABLE', False):
            return False
        
        # Skip rate limiting for static files
        if request.path.startswith('/static/'):
            return False
        
        client_ip = self._get_client_ip(request)
        cache_key = f'rate_limit_{client_ip}'
        
        # Get current request count
        request_count = cache.get(cache_key, 0)
        
        # Rate limit: 100 requests per minute
        if request_count >= 100:
            return True
        
        # Increment counter
        cache.set(cache_key, request_count + 1, 60)  # 1 minute expiry
        
        return False
    
    def _get_client_ip(self, request):
        """Extract client IP from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

# Signal handlers for security events
@receiver(user_logged_in)
def log_successful_login(sender, request, user, **kwargs):
    """Log successful login events"""
    if getattr(settings, 'SECURITY_LOG_OAUTH_EVENTS', True):
        SecurityAuditor.log_security_event(
            'user_login_success',
            user,
            {
                'login_method': 'django_auth',
                'session_key': request.session.session_key
            },
            request=request,
            severity='INFO'
        )

@receiver(user_logged_out)
def log_logout(sender, request, user, **kwargs):
    """Log logout events"""
    if getattr(settings, 'SECURITY_LOG_OAUTH_EVENTS', True):
        SecurityAuditor.log_security_event(
            'user_logout',
            user,
            {
                'logout_method': 'django_auth'
            },
            request=request,
            severity='INFO'
        )

@receiver(user_login_failed)
def log_failed_login(sender, credentials, request, **kwargs):
    """Log failed login attempts"""
    if getattr(settings, 'SECURITY_LOG_FAILED_LOGINS', True):
        SecurityAuditor.log_security_event(
            'user_login_failed',
            None,
            {
                'attempted_username': credentials.get('username', 'unknown'),
                'failure_reason': 'invalid_credentials'
            },
            request=request,
            severity='WARNING'
        )

class RateLimitMiddleware(MiddlewareMixin):
    """Advanced rate limiting middleware"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.request_counts = defaultdict(list)
        super().__init__(get_response)
    
    def process_request(self, request):
        if not getattr(settings, 'RATE_LIMIT_ENABLE', False):
            return None
        
        client_ip = self._get_client_ip(request)
        now = time.time()
        
        # Clean old requests
        self.request_counts[client_ip] = [
            req_time for req_time in self.request_counts[client_ip]
            if now - req_time < 60  # Keep requests from last minute
        ]
        
        # Check rate limit
        if len(self.request_counts[client_ip]) >= 100:  # 100 requests per minute
            return HttpResponseTooManyRequests(
                "Rate limit exceeded. Please try again later.",
                headers={'Retry-After': '60'}
            )
        
        # Add current request
        self.request_counts[client_ip].append(now)
        
        return None
    
    def _get_client_ip(self, request):
        """Extract client IP from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip