import os
import io
import logging
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
from googleapiclient.http import MediaIoBaseUpload

import logging
import os

def get_logger(name="app"):
    """
    Function to get a logger that is pre-configured for use in your app.
    :param name: The name of the logger, default is 'app'.
    :return: Logger instance
    """
    # Get logger instance
    logger = logging.getLogger(name)

    # Set up logging only once
    if not logger.hasHandlers():
        # Formatter for log messages
        formatter = logging.Formatter(
            '{levelname} {asctime} {module} {process:d} {thread:d} {message}', style='{'
        )

        # Console handler (prints logs to console)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(logging.INFO)
        logger.addHandler(console_handler)

        # Only add file handler in development
        try:
            log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
            if os.path.exists(log_dir) or (not os.environ.get('RENDER')):  # Not on Render
                if not os.path.exists(log_dir):
                    os.makedirs(log_dir)
                
                log_file = os.path.join(log_dir, 'app.log')
                file_handler = logging.FileHandler(log_file)
                file_handler.setFormatter(formatter)
                file_handler.setLevel(logging.INFO)
                logger.addHandler(file_handler)
        except (OSError, PermissionError):
            # If we can't create file handler, just use console
            pass

        # Set logger level
        logger.setLevel(logging.INFO)

    return logger


logger = get_logger()


def get_user_credentials(request):
    creds_data = request.session.get('credentials')
    if not creds_data:
        raise Exception("User credentials not found in session.")
    return Credentials(**creds_data)

def list_files_and_folders(service, folder_id, path="", parent=None):
    """List all files and folders recursively from the source drive"""
    items = []
    query = f"'{folder_id}' in parents and trashed = false"
    fields = "nextPageToken, files(id, name, mimeType)"

    page_token = None
    while True:
        response = service.files().list(
            q=query,
            spaces='drive',
            fields=fields,
            pageToken=page_token
        ).execute()

        for file in response.get('files', []):
            file_path = f"{path}/{file['name']}" if path else file['name']
            file['path'] = file_path
            file['parent'] = parent  # optional for hierarchy
            items.append(file)

            if file['mimeType'] == 'application/vnd.google-apps.folder':
                # Recursively list subfolder
                sub_items = list_files_and_folders(service, file['id'], file_path, file)
                items.extend(sub_items)

        page_token = response.get('nextPageToken', None)
        if page_token is None:
            break

    return items

def build_drive_service(creds_dict):
    """Build a Google Drive service from credentials dictionary."""
    if "source_email" in creds_dict:
        del creds_dict['source_email']
    if "dest_email" in creds_dict:
        del creds_dict['dest_email']
    
    creds = Credentials(**creds_dict)
    service = build('drive', 'v3', credentials=creds)
    return service

def create_folder(service, name, parent_id=None):
    """Create a folder in the destination drive"""
    metadata = {
        'name': name,
        'mimeType': 'application/vnd.google-apps.folder'
    }
    if parent_id:
        metadata['parents'] = [parent_id]

    folder = service.files().create(body=metadata, fields='id').execute()
    return folder.get('id')

def get_folder_name(service, folder_id):
    """Fetch folder name from folder ID"""
    try:
        folder = service.files().get(fileId=folder_id, fields="name").execute()
        return folder.get('name')
    except Exception as e:
        logger.error(f"Error fetching folder name for {folder_id}: {e}")
        return None

def copy_file_between_drives(service_source, service_destination, file_id, name, parent_id, parent_name):
    """Copy file between source and destination drive"""

    logger.info(f"Copying file '{name}' to folder '{parent_name}' (Folder ID: {parent_id})")

    try:
        # First, download the file from source
        file_data = service_source.files().get_media(fileId=file_id).execute()
        
        # Then, upload to destination
        file_metadata = {
            'name': name,
            'parents': [parent_id],
        }
        media = MediaIoBaseUpload(io.BytesIO(file_data), mimetype='application/octet-stream')
        service_destination.files().create(body=file_metadata, media_body=media, fields='id').execute()
    except Exception as e:
        logger.error(f"Error copying file {file_id}: {str(e)}")
    return True