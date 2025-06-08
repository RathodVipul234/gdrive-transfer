from django.contrib import admin
from .models import FileTransfer, UserCredentials


# class FileTransferAdmin(admin.ModelAdmin):
#     fields = ["transfer_uuid","source_folder_id","destination_folder_id","status","total_files","transferred_files","created_at","updated_at"]
#     # fieldsets = (
    #  How to print all filed names in the admin panel?

    #     (None, {
    #         'fields': ('file_id', 'file_name', 'file_size', 'transfer_status', 'transfer_time', 'user_email')
# Register your models here.

admin.site.register(FileTransfer)