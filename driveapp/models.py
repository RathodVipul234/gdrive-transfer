
from django.db import models

from django.contrib.auth.models import User

class UserCredentials(models.Model):
    user_email = models.EmailField(unique=True)
    access_token = models.TextField()
    refresh_token = models.TextField(null=True, blank=True)
    token_uri = models.TextField()
    client_id = models.TextField()
    client_secret = models.TextField()
    scopes = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.user_email

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