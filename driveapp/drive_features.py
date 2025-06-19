"""
Advanced Google Drive features and utilities
"""
import logging
import mimetypes
from datetime import datetime, timedelta
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
from .security import SecurityAuditor

logger = logging.getLogger(__name__)

class DriveManager:
    """Advanced Google Drive operations manager"""
    
    def __init__(self, credentials_dict):
        """Initialize with OAuth credentials"""
        self.credentials = Credentials(**credentials_dict)
        self.service = build('drive', 'v3', credentials=self.credentials)
    
    def get_drive_info(self):
        """Get comprehensive Google Drive information"""
        try:
            # Get about info (storage quota, user info)
            about = self.service.about().get(fields='storageQuota,user').execute()
            
            # Get recent files
            recent_files = self.service.files().list(
                orderBy='modifiedTime desc',
                pageSize=10,
                fields="files(id,name,mimeType,size,modifiedTime,parents,webViewLink)"
            ).execute().get('files', [])
            
            # Get shared with me files
            shared_files = self.service.files().list(
                q="sharedWithMe=true",
                pageSize=10,
                fields="files(id,name,mimeType,size,modifiedTime,sharingUser,webViewLink)"
            ).execute().get('files', [])
            
            # Get folder statistics
            folder_stats = self._get_folder_statistics()
            
            return {
                'storage_quota': about.get('storageQuota', {}),
                'user_info': about.get('user', {}),
                'recent_files': recent_files,
                'shared_files': shared_files,
                'folder_stats': folder_stats,
                'drive_features': self._get_drive_features()
            }
            
        except HttpError as e:
            logger.error(f"Error getting drive info: {e}")
            return None
    
    def _get_folder_statistics(self):
        """Get folder and file type statistics"""
        try:
            # Count folders
            folders_result = self.service.files().list(
                q="mimeType='application/vnd.google-apps.folder'",
                fields="files(id)"
            ).execute()
            
            # Count different file types
            file_types = {
                'documents': "mimeType='application/vnd.google-apps.document'",
                'spreadsheets': "mimeType='application/vnd.google-apps.spreadsheet'",
                'presentations': "mimeType='application/vnd.google-apps.presentation'",
                'images': "mimeType contains 'image/'",
                'videos': "mimeType contains 'video/'",
                'pdfs': "mimeType='application/pdf'",
                'other_files': "mimeType != 'application/vnd.google-apps.folder'"
            }
            
            stats = {
                'total_folders': len(folders_result.get('files', [])),
                'file_types': {}
            }
            
            for file_type, query in file_types.items():
                try:
                    result = self.service.files().list(
                        q=query,
                        fields="files(id)"
                    ).execute()
                    stats['file_types'][file_type] = len(result.get('files', []))
                except:
                    stats['file_types'][file_type] = 0
            
            return stats
            
        except HttpError as e:
            logger.error(f"Error getting folder statistics: {e}")
            return {}
    
    def _get_drive_features(self):
        """Get available Google Drive features"""
        return {
            'can_create_folders': True,
            'can_share_files': True,
            'can_export_formats': [
                'application/pdf',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'text/html',
                'text/plain',
                'application/epub+zip'
            ],
            'supports_versions': True,
            'supports_comments': True,
            'max_file_size': '5TB',
            'api_version': 'v3'
        }
    
    def search_files(self, query, file_type=None, modified_after=None, page_size=20):
        """Advanced file search with filters"""
        try:
            # Build search query
            search_query = f"name contains '{query}'"
            
            if file_type:
                if file_type == 'folder':
                    search_query += " and mimeType='application/vnd.google-apps.folder'"
                elif file_type == 'document':
                    search_query += " and mimeType='application/vnd.google-apps.document'"
                elif file_type == 'image':
                    search_query += " and mimeType contains 'image/'"
                elif file_type == 'video':
                    search_query += " and mimeType contains 'video/'"
                elif file_type == 'pdf':
                    search_query += " and mimeType='application/pdf'"
            
            if modified_after:
                search_query += f" and modifiedTime > '{modified_after.isoformat()}'"
            
            # Exclude trashed files
            search_query += " and trashed=false"
            
            logger.info(f"Searching with query: {search_query}")
            
            results = self.service.files().list(
                q=search_query,
                pageSize=page_size,
                fields="files(id,name,mimeType,size,modifiedTime,parents,webViewLink,thumbnailLink)",
                orderBy="modifiedTime desc"
            ).execute()
            
            files = results.get('files', [])
            
            # Enhance file information
            for file in files:
                file['formatted_size'] = self._format_file_size(file.get('size', 0))
                file['file_category'] = self._get_file_category(file.get('mimeType', ''))
                file['modified_date'] = self._format_date(file.get('modifiedTime', ''))
            
            return files
            
        except HttpError as e:
            logger.error(f"Error searching files: {e}")
            return []
    
    def get_file_details(self, file_id):
        """Get detailed information about a specific file"""
        try:
            file_info = self.service.files().get(
                fileId=file_id,
                fields="id,name,mimeType,size,createdTime,modifiedTime,lastModifyingUser,parents,webViewLink,thumbnailLink,description,starred,shared,permissions"
            ).execute()
            
            # Get file permissions
            try:
                permissions = self.service.permissions().list(fileId=file_id).execute()
                file_info['detailed_permissions'] = permissions.get('permissions', [])
            except:
                file_info['detailed_permissions'] = []
            
            # Get file revisions if supported
            try:
                revisions = self.service.revisions().list(fileId=file_id).execute()
                file_info['revisions'] = revisions.get('revisions', [])
            except:
                file_info['revisions'] = []
            
            # Format additional information
            file_info['formatted_size'] = self._format_file_size(file_info.get('size', 0))
            file_info['file_category'] = self._get_file_category(file_info.get('mimeType', ''))
            file_info['created_date'] = self._format_date(file_info.get('createdTime', ''))
            file_info['modified_date'] = self._format_date(file_info.get('modifiedTime', ''))
            
            return file_info
            
        except HttpError as e:
            logger.error(f"Error getting file details for {file_id}: {e}")
            return None
    
    def create_folder_with_metadata(self, name, parent_id=None, description=None):
        """Create a folder with metadata"""
        try:
            folder_metadata = {
                'name': name,
                'mimeType': 'application/vnd.google-apps.folder',
            }
            
            if parent_id:
                folder_metadata['parents'] = [parent_id]
            
            if description:
                folder_metadata['description'] = description
            
            folder = self.service.files().create(
                body=folder_metadata,
                fields='id,name,webViewLink'
            ).execute()
            
            logger.info(f"Created folder: {name} with ID: {folder.get('id')}")
            return folder
            
        except HttpError as e:
            logger.error(f"Error creating folder '{name}': {e}")
            return None
    
    def get_folder_tree(self, folder_id='root', max_depth=3, current_depth=0):
        """Get folder tree structure with files"""
        if current_depth >= max_depth:
            return None
        
        try:
            folder_info = {
                'id': folder_id,
                'name': 'My Drive' if folder_id == 'root' else None,
                'children': [],
                'files': [],
                'depth': current_depth
            }
            
            # Get folder name if not root
            if folder_id != 'root':
                folder_details = self.service.files().get(
                    fileId=folder_id,
                    fields='name'
                ).execute()
                folder_info['name'] = folder_details.get('name')
            
            # Get children (folders and files)
            query = f"'{folder_id}' in parents and trashed=false"
            
            results = self.service.files().list(
                q=query,
                fields="files(id,name,mimeType,size,modifiedTime)",
                orderBy="name"
            ).execute()
            
            items = results.get('files', [])
            
            for item in items:
                if item['mimeType'] == 'application/vnd.google-apps.folder':
                    # Recursively get subfolder structure
                    subfolder = self.get_folder_tree(
                        item['id'], 
                        max_depth, 
                        current_depth + 1
                    )
                    if subfolder:
                        folder_info['children'].append(subfolder)
                else:
                    # Add file information
                    file_info = {
                        'id': item['id'],
                        'name': item['name'],
                        'mimeType': item['mimeType'],
                        'size': item.get('size', 0),
                        'formatted_size': self._format_file_size(item.get('size', 0)),
                        'file_category': self._get_file_category(item['mimeType']),
                        'modified_date': self._format_date(item.get('modifiedTime', ''))
                    }
                    folder_info['files'].append(file_info)
            
            return folder_info
            
        except HttpError as e:
            logger.error(f"Error getting folder tree for {folder_id}: {e}")
            return None
    
    def _format_file_size(self, size_bytes):
        """Format file size in human readable format"""
        if not size_bytes or size_bytes == '0':
            return '0 B'
        
        try:
            size_bytes = int(size_bytes)
        except (ValueError, TypeError):
            return 'Unknown'
        
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} PB"
    
    def _get_file_category(self, mime_type):
        """Categorize file by MIME type"""
        if not mime_type:
            return 'unknown'
        
        if 'image/' in mime_type:
            return 'image'
        elif 'video/' in mime_type:
            return 'video'
        elif 'audio/' in mime_type:
            return 'audio'
        elif mime_type == 'application/pdf':
            return 'pdf'
        elif 'document' in mime_type:
            return 'document'
        elif 'spreadsheet' in mime_type:
            return 'spreadsheet'
        elif 'presentation' in mime_type:
            return 'presentation'
        elif 'folder' in mime_type:
            return 'folder'
        elif 'text/' in mime_type:
            return 'text'
        elif 'application/zip' in mime_type or 'archive' in mime_type:
            return 'archive'
        else:
            return 'other'
    
    def _format_date(self, date_string):
        """Format ISO date string to readable format"""
        try:
            if not date_string:
                return 'Unknown'
            
            date_obj = datetime.fromisoformat(date_string.replace('Z', '+00:00'))
            now = datetime.now(date_obj.tzinfo)
            
            # Calculate time difference
            diff = now - date_obj
            
            if diff.days == 0:
                if diff.seconds < 3600:
                    minutes = diff.seconds // 60
                    return f"{minutes} minutes ago" if minutes > 1 else "Just now"
                else:
                    hours = diff.seconds // 3600
                    return f"{hours} hours ago" if hours > 1 else "1 hour ago"
            elif diff.days == 1:
                return "Yesterday"
            elif diff.days < 7:
                return f"{diff.days} days ago"
            elif diff.days < 30:
                weeks = diff.days // 7
                return f"{weeks} weeks ago" if weeks > 1 else "1 week ago"
            else:
                return date_obj.strftime("%B %d, %Y")
                
        except Exception as e:
            logger.error(f"Error formatting date {date_string}: {e}")
            return 'Unknown'

class TransferAnalytics:
    """Analytics and insights for file transfers"""
    
    @staticmethod
    def calculate_transfer_insights(transfer_history):
        """Calculate insights from transfer history"""
        if not transfer_history:
            return {}
        
        total_transfers = len(transfer_history)
        successful_transfers = len([t for t in transfer_history if t.status == 'completed'])
        failed_transfers = len([t for t in transfer_history if t.status == 'failed'])
        
        # Calculate file statistics
        total_files = sum(t.total_files for t in transfer_history)
        transferred_files = sum(t.transferred_files for t in transfer_history)
        
        # Calculate time statistics
        completion_times = []
        for transfer in transfer_history:
            if transfer.status == 'completed' and transfer.created_at and transfer.updated_at:
                duration = transfer.updated_at - transfer.created_at
                completion_times.append(duration.total_seconds())
        
        avg_completion_time = sum(completion_times) / len(completion_times) if completion_times else 0
        
        # Most active time periods
        transfer_hours = [t.created_at.hour for t in transfer_history if t.created_at]
        most_active_hour = max(set(transfer_hours), key=transfer_hours.count) if transfer_hours else None
        
        # Account usage
        source_accounts = [t.source_email for t in transfer_history if t.source_email]
        dest_accounts = [t.destination_email for t in transfer_history if t.destination_email]
        
        return {
            'total_transfers': total_transfers,
            'success_rate': (successful_transfers / total_transfers * 100) if total_transfers > 0 else 0,
            'failed_transfers': failed_transfers,
            'total_files_attempted': total_files,
            'total_files_transferred': transferred_files,
            'transfer_efficiency': (transferred_files / total_files * 100) if total_files > 0 else 0,
            'average_completion_time': avg_completion_time,
            'most_active_hour': most_active_hour,
            'unique_source_accounts': len(set(source_accounts)),
            'unique_destination_accounts': len(set(dest_accounts)),
            'recent_activity': transfer_history[:5] if transfer_history else []
        }
    
    @staticmethod
    def generate_transfer_recommendations(insights, drive_info):
        """Generate recommendations based on transfer patterns"""
        recommendations = []
        
        if insights.get('success_rate', 0) < 80:
            recommendations.append({
                'type': 'performance',
                'title': 'Improve Transfer Success Rate',
                'description': 'Your transfer success rate is below 80%. Consider checking network stability and file permissions.',
                'priority': 'high'
            })
        
        if insights.get('average_completion_time', 0) > 3600:  # More than 1 hour
            recommendations.append({
                'type': 'efficiency',
                'title': 'Optimize Transfer Speed',
                'description': 'Transfers are taking longer than expected. Consider transferring during off-peak hours.',
                'priority': 'medium'
            })
        
        if drive_info and drive_info.get('storage_quota'):
            storage = drive_info['storage_quota']
            if storage.get('usage') and storage.get('limit'):
                usage_percent = (int(storage['usage']) / int(storage['limit'])) * 100
                if usage_percent > 80:
                    recommendations.append({
                        'type': 'storage',
                        'title': 'Storage Space Running Low',
                        'description': f'Your Google Drive is {usage_percent:.1f}% full. Consider cleaning up old files.',
                        'priority': 'high'
                    })
        
        if insights.get('total_transfers', 0) > 10 and insights.get('unique_source_accounts', 0) == 1:
            recommendations.append({
                'type': 'security',
                'title': 'Consider Using Multiple Source Accounts',
                'description': 'You seem to be transferring from the same account frequently. Consider organizing your data.',
                'priority': 'low'
            })
        
        return recommendations