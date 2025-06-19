"""
Privacy and security dashboard views
"""
import json
import logging
from datetime import datetime, timedelta
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse
from django.contrib import messages
from django.conf import settings
from django.db.models import Count, Q
from django.utils import timezone
from django.core.paginator import Paginator

from .models import SecurityLog, UserPrivacyPreference, DataExportRequest, FileTransfer
from .security import PrivacyManager, SecurityAuditor
# from .forms import PrivacyPreferenceForm, DataExportForm  # Will implement inline for now

logger = logging.getLogger(__name__)

def privacy_dashboard(request):
    """Privacy dashboard showing data usage and security information - accessible to all users"""
    
    # Initialize context with public information
    context = {
        'privacy_policy_version': getattr(settings, 'PRIVACY_POLICY_VERSION', '1.0'),
        'terms_version': getattr(settings, 'TERMS_OF_SERVICE_VERSION', '1.0'),
        'data_summary': PrivacyManager.get_data_access_summary(None),  # Get general data summary
        'security_recommendations': PrivacyManager.get_security_recommendations(),
    }
    
    # Add user-specific data only if authenticated
    if request.user.is_authenticated:
        # Get or create privacy preferences
        privacy_prefs, created = UserPrivacyPreference.objects.get_or_create(
            user=request.user,
            defaults={
                'analytics_consent': False,
                'email_notifications': True,
                'data_retention_days': 90,
                'share_usage_stats': False
            }
        )
        
        # Get user-specific data access summary
        data_summary = PrivacyManager.get_data_access_summary(request.user)
        
        # Get recent security events for this user
        recent_security_events = SecurityLog.objects.filter(
            user=request.user
        ).order_by('-timestamp')[:10]
        
        # Get transfer statistics
        transfer_stats = {
            'total_transfers': FileTransfer.objects.filter(user=request.user).count(),
            'successful_transfers': FileTransfer.objects.filter(
                user=request.user, status='completed'
            ).count(),
            'data_transferred_files': FileTransfer.objects.filter(
                user=request.user, status='completed'
            ).aggregate(total=Count('transferred_files'))['total'] or 0,
            'last_transfer': FileTransfer.objects.filter(
                user=request.user
            ).order_by('-created_at').first()
        }
        
        # Get data export requests
        export_requests = DataExportRequest.objects.filter(
            user=request.user
        ).order_by('-requested_at')[:5]
        
        # Update context with user-specific data
        context.update({
            'privacy_prefs': privacy_prefs,
            'data_summary': data_summary,
            'recent_security_events': recent_security_events,
            'transfer_stats': transfer_stats,
            'export_requests': export_requests,
        })
    else:
        # For non-authenticated users, provide default/demo data
        context.update({
            'privacy_prefs': None,
            'recent_security_events': [],
            'transfer_stats': {
                'total_transfers': 0,
                'successful_transfers': 0,
                'data_transferred_files': 0,
                'last_transfer': None
            },
            'export_requests': [],
        })
    
    return render(request, 'driveapp/privacy_dashboard.html', context)

@login_required
def update_privacy_preferences(request):
    """Update user privacy preferences"""
    if request.method == 'POST':
        privacy_prefs, created = UserPrivacyPreference.objects.get_or_create(
            user=request.user
        )
        
        # Update privacy preferences directly
        analytics_consent = request.POST.get('analytics_consent') == 'on'
        email_notifications = request.POST.get('email_notifications') == 'on'
        data_retention_days = int(request.POST.get('data_retention_days', 90))
        share_usage_stats = request.POST.get('share_usage_stats') == 'on'
        
        privacy_prefs.analytics_consent = analytics_consent
        privacy_prefs.email_notifications = email_notifications
        privacy_prefs.data_retention_days = data_retention_days
        privacy_prefs.share_usage_stats = share_usage_stats
        privacy_prefs.save()
        
        # Log privacy preference change
        SecurityAuditor.log_security_event(
            'privacy_preferences_updated',
            request.user,
            {
                'analytics_consent': analytics_consent,
                'email_notifications': email_notifications,
                'data_retention_days': data_retention_days,
                'share_usage_stats': share_usage_stats
            },
            request=request
        )
        
        messages.success(request, 'Privacy preferences updated successfully!')
    
    return redirect('privacy_dashboard')

def security_log_view(request):
    """View detailed security logs - public view shows general info, authenticated users see their logs"""
    
    # Filter logs based on authentication status
    if request.user.is_authenticated:
        # Show user-specific logs and system logs for authenticated users
        logs = SecurityLog.objects.filter(
            Q(user=request.user) | Q(user__isnull=True, ip_address=request.META.get('REMOTE_ADDR'))
        ).order_by('-timestamp')
    else:
        # Show only public/system logs for non-authenticated users (demo data)
        logs = SecurityLog.objects.filter(
            user__isnull=True,
            event_type__in=['system_startup', 'security_scan', 'backup_completed', 'maintenance']
        ).order_by('-timestamp')[:10]  # Limit to recent system events only
    
    # Filter by severity if requested
    severity_filter = request.GET.get('severity')
    if severity_filter and severity_filter in ['INFO', 'WARNING', 'ERROR', 'CRITICAL']:
        logs = logs.filter(severity=severity_filter)
    
    # Filter by date range
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    
    if date_from:
        try:
            date_from = datetime.strptime(date_from, '%Y-%m-%d').date()
            logs = logs.filter(timestamp__date__gte=date_from)
        except ValueError:
            pass
    
    if date_to:
        try:
            date_to = datetime.strptime(date_to, '%Y-%m-%d').date()
            logs = logs.filter(timestamp__date__lte=date_to)
        except ValueError:
            pass
    
    # Pagination
    paginator = Paginator(logs, 25)  # Show 25 logs per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'severity_filter': severity_filter,
        'date_from': date_from,
        'date_to': date_to,
        'severity_choices': SecurityLog.SEVERITY_CHOICES
    }
    
    return render(request, 'driveapp/security_logs.html', context)

@login_required
def request_data_export(request):
    """Request export of user data"""
    if request.method == 'POST':
        request_type = request.POST.get('request_type', 'export')
        notes = request.POST.get('notes', '')
        
        export_request = DataExportRequest.objects.create(
            user=request.user,
            request_type=request_type,
            notes=notes
        )
        
        # Log data export request
        SecurityAuditor.log_security_event(
            'data_export_requested',
            request.user,
            {
                'request_type': request_type,
                'request_id': export_request.id
            },
            request=request
        )
        
        messages.success(
            request, 
            f'Data {request_type} request submitted successfully. '
            f'Request ID: {export_request.id}'
        )
        
        return redirect('privacy_dashboard')
    
    return redirect('privacy_dashboard')

@login_required
def revoke_oauth_access(request):
    """Revoke OAuth access for Google accounts"""
    if request.method == 'POST':
        account_type = request.POST.get('account_type')  # 'source' or 'destination'
        
        if account_type in ['source', 'destination']:
            # Clear session data
            session_key = f'credentials_{account_type}'
            email_key = f'{account_type}_email' if account_type == 'source' else 'dest_email'
            
            if session_key in request.session:
                del request.session[session_key]
            if email_key in request.session:
                del request.session[email_key]
            
            # Log OAuth revocation
            SecurityAuditor.log_security_event(
                'oauth_access_revoked',
                request.user,
                {
                    'account_type': account_type,
                    'revoked_by_user': True
                },
                request=request
            )
            
            messages.success(
                request, 
                f'{account_type.title()} account access has been revoked successfully.'
            )
        else:
            messages.error(request, 'Invalid account type.')
    
    return redirect('privacy_dashboard')

@login_required
def download_user_data(request):
    """Download user data as JSON"""
    try:
        # Compile user data
        user_data = {
            'account_info': {
                'username': request.user.username,
                'email': request.user.email,
                'date_joined': request.user.date_joined.isoformat(),
                'last_login': request.user.last_login.isoformat() if request.user.last_login else None
            },
            'transfers': [],
            'security_logs': [],
            'privacy_preferences': {}
        }
        
        # Add transfer data
        transfers = FileTransfer.objects.filter(user=request.user)
        for transfer in transfers:
            user_data['transfers'].append({
                'uuid': transfer.transfer_uuid,
                'source_email': transfer.source_email,
                'destination_email': transfer.destination_email,
                'status': transfer.status,
                'total_files': transfer.total_files,
                'transferred_files': transfer.transferred_files,
                'created_at': transfer.created_at.isoformat(),
                'updated_at': transfer.updated_at.isoformat()
            })
        
        # Add security logs (last 100)
        security_logs = SecurityLog.objects.filter(user=request.user).order_by('-timestamp')[:100]
        for log in security_logs:
            user_data['security_logs'].append({
                'timestamp': log.timestamp.isoformat(),
                'event_type': log.event_type,
                'severity': log.severity,
                'details': json.loads(log.details) if log.details else {}
            })
        
        # Add privacy preferences
        try:
            privacy_prefs = UserPrivacyPreference.objects.get(user=request.user)
            user_data['privacy_preferences'] = {
                'analytics_consent': privacy_prefs.analytics_consent,
                'email_notifications': privacy_prefs.email_notifications,
                'data_retention_days': privacy_prefs.data_retention_days,
                'share_usage_stats': privacy_prefs.share_usage_stats,
                'created_at': privacy_prefs.created_at.isoformat(),
                'updated_at': privacy_prefs.updated_at.isoformat()
            }
        except UserPrivacyPreference.DoesNotExist:
            pass
        
        # Log data export
        SecurityAuditor.log_security_event(
            'user_data_downloaded',
            request.user,
            {
                'transfers_count': len(user_data['transfers']),
                'logs_count': len(user_data['security_logs'])
            },
            request=request
        )
        
        # Return JSON response
        response = HttpResponse(
            json.dumps(user_data, indent=2),
            content_type='application/json'
        )
        response['Content-Disposition'] = f'attachment; filename="gdrive_transfer_data_{request.user.username}_{datetime.now().strftime("%Y%m%d")}.json"'
        
        return response
        
    except Exception as e:
        logger.error(f"Error generating user data export: {str(e)}")
        messages.error(request, 'Error generating data export. Please try again.')
        return redirect('privacy_dashboard')

@login_required
def security_dashboard_api(request):
    """API endpoint for security dashboard data"""
    try:
        # Get recent security events
        recent_events = SecurityLog.objects.filter(
            user=request.user
        ).order_by('-timestamp')[:10]
        
        events_data = []
        for event in recent_events:
            events_data.append({
                'timestamp': event.timestamp.isoformat(),
                'event_type': event.event_type,
                'severity': event.severity,
                'details': json.loads(event.details) if event.details else {}
            })
        
        # Get security stats
        stats = {
            'total_logins': SecurityLog.objects.filter(
                user=request.user,
                event_type__in=['user_login_success', 'oauth_login_success']
            ).count(),
            'failed_logins': SecurityLog.objects.filter(
                user=request.user,
                event_type='user_login_failed'
            ).count(),
            'transfers_completed': FileTransfer.objects.filter(
                user=request.user,
                status='completed'
            ).count(),
            'last_login': SecurityLog.objects.filter(
                user=request.user,
                event_type__in=['user_login_success', 'oauth_login_success']
            ).order_by('-timestamp').first()
        }
        
        if stats['last_login']:
            stats['last_login'] = stats['last_login'].timestamp.isoformat()
        
        return JsonResponse({
            'success': True,
            'recent_events': events_data,
            'stats': stats
        })
        
    except Exception as e:
        logger.error(f"Error in security dashboard API: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to load security data'
        }, status=500)