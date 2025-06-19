
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class UserCredentials(models.Model):
    """Secure storage for encrypted OAuth credentials"""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    user_email = models.EmailField()
    encrypted_credentials = models.TextField()  # Encrypted JSON of all OAuth data
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        unique_together = ['user', 'user_email']
        indexes = [
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['expires_at']),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.user_email}"
    
    def is_expired(self):
        """Check if credentials have expired"""
        return self.expires_at and timezone.now() > self.expires_at

class FileTransfer(models.Model):
    """Model to store file transfer details"""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    transfer_uuid = models.CharField(max_length=50, unique=True)

    source_email = models.EmailField(null=False, blank=False)
    destination_email = models.EmailField(null=False, blank=False)
    
    source_folder_id = models.CharField(max_length=100, blank=True, null=True)
    destination_folder_id = models.CharField(max_length=100, blank=True, null=True)
    
    status = models.CharField(max_length=20, default='pending')  # pending, in_progress, completed, failed
    total_files = models.IntegerField(default=0)
    transferred_files = models.IntegerField(default=0)
    current_file = models.CharField(max_length=255, blank=True, null=True)  # Current file being processed
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user} - {self.source_folder_id} to {self.destination_folder_id}"

class TransferLog(models.Model):
    """Model to store detailed logs for each file transfer"""
    transfer = models.ForeignKey(FileTransfer, on_delete=models.CASCADE, related_name='logs')
    timestamp = models.DateTimeField(auto_now_add=True)
    file_name = models.CharField(max_length=255)
    file_type = models.CharField(max_length=50)  # file or folder
    status = models.CharField(max_length=20)  # success, failed, skipped
    message = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.file_name} - {self.status}"

class SecurityLog(models.Model):
    """Model to store security audit logs"""
    SEVERITY_CHOICES = [
        ('INFO', 'Information'),
        ('WARNING', 'Warning'),
        ('ERROR', 'Error'),
        ('CRITICAL', 'Critical'),
    ]
    
    timestamp = models.DateTimeField(auto_now_add=True)
    event_type = models.CharField(max_length=100)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='INFO')
    details = models.TextField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=500, null=True, blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp', 'severity']),
            models.Index(fields=['event_type']),
            models.Index(fields=['user', 'timestamp']),
        ]
    
    def __str__(self):
        return f"{self.timestamp} - {self.event_type} - {self.severity}"
    
    @property
    def formatted_event_type(self):
        """Return formatted event type with spaces instead of underscores"""
        return self.event_type.replace('_', ' ').title()
    
    @property
    def severity_badge_class(self):
        """Return appropriate CSS class for severity badge"""
        severity_classes = {
            'INFO': 'info',
            'WARNING': 'warning', 
            'ERROR': 'error',
            'CRITICAL': 'critical'
        }
        return severity_classes.get(self.severity, 'info')

class UserPrivacyPreference(models.Model):
    """Model to store user privacy preferences"""
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    analytics_consent = models.BooleanField(default=False)
    email_notifications = models.BooleanField(default=True)
    data_retention_days = models.IntegerField(default=90)  # How long transfer logs are kept
    share_usage_stats = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Privacy preferences for {self.user.username}"

class DataExportRequest(models.Model):
    """Model to handle user data export requests"""
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('PROCESSING', 'Processing'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    request_type = models.CharField(max_length=50)  # 'export' or 'deletion'
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    requested_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)
    export_file_path = models.CharField(max_length=500, null=True, blank=True)
    notes = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-requested_at']
    
    def __str__(self):
        return f"{self.request_type.title()} request by {self.user.username} - {self.status}"
    
# class TransferJob(models.Model):
#     """Model to track transfer job details and progress"""
#     STATUS_CHOICES = (
#         ('pending', 'Pending'),
#         ('authenticating', 'Authenticating'),
#         ('listing', 'Listing Files'),
#         ('transferring', 'Transferring'),
#         ('completed', 'Completed'),
#         ('failed', 'Failed'),
#     )
    
#     user = models.ForeignKey(User, on_delete=models.CASCADE)
#     job_id = models.CharField(max_length=50, unique=True)
#     source_folder_id = models.CharField(max_length=100, blank=True, null=True)
#     dest_folder_id = models.CharField(max_length=100, blank=True, null=True)
#     status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
#     progress = models.IntegerField(default=0)  # 0-100%
#     total_files = models.IntegerField(default=0)
#     transferred_files = models.IntegerField(default=0)
#     error_message = models.TextField(blank=True, null=True)
#     created_at = models.DateTimeField(auto_now_add=True)
#     updated_at = models.DateTimeField(auto_now=True)
    
#     def __str__(self):
#         return f"Transfer Job {self.job_id} - {self.status}"

# class TransferLog(models.Model):
#     """Model to store detailed logs for each transfer job"""
#     transfer_job = models.ForeignKey(TransferJob, on_delete=models.CASCADE, related_name='logs')
#     timestamp = models.DateTimeField(auto_now_add=True)
#     level = models.CharField(max_length=10)  # INFO, WARNING, ERROR
#     message = models.TextField()
    
#     class Meta:
#         ordering = ['-timestamp']
    
#     def __str__(self):
#         return f"{self.timestamp} - {self.level}: {self.message[:50]}"