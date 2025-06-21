import os
import logging
import uuid
import json
import tempfile
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.conf import settings
from django.contrib.auth import logout, login, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.contrib import messages
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from .models import FileTransfer, TransferLog
from .utils import get_user_credentials, list_files_and_folders, create_folder, build_drive_service, copy_file_between_drives,get_folder_name
from .photos_utils import build_photos_service, list_albums
import threading
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from functools import wraps

# Configure logger
logger = logging.getLogger(__name__)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

def require_auth(view_func):
    """Decorator to require both source and destination authentication"""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        creds_source = request.session.get('credentials_source')
        creds_destination = request.session.get('credentials_destination')
        
        if not creds_source or not creds_destination:
            if request.headers.get('Content-Type') == 'application/json':
                return JsonResponse({'error': 'Authentication required for both accounts'}, status=401)
            return redirect('home')
        
        return view_func(request, *args, **kwargs)
    return wrapper

# SCOPES for Google Drive and Google Photos
SCOPES = [
    "https://www.googleapis.com/auth/userinfo.email",
    "openid",
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/photoslibrary"
]

# Path to the credentials file
GOOGLE_OAUTH_PATH = "credentials.json"

def get_oauth_flow(redirect_uri):
    """Get OAuth flow using either environment variable JSON or file"""
    if hasattr(settings, 'GOOGLE_OAUTH_JSON') and settings.GOOGLE_OAUTH_JSON:
        # Use JSON from environment variable
        credentials_info = json.loads(settings.GOOGLE_OAUTH_JSON)
        return Flow.from_client_config(
            credentials_info,
            scopes=SCOPES,
            redirect_uri=redirect_uri
        )
    else:
        # Use file path (for local development)
        return Flow.from_client_secrets_file(
            settings.GOOGLE_OAUTH_PATH,
            scopes=SCOPES,
            redirect_uri=redirect_uri
        )

# Authentication Views
def user_login(request):
    """User login view"""
    if request.user.is_authenticated:
        return redirect('home')
    
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, 'Welcome back! You have successfully logged in.')
            next_url = request.GET.get('next', 'home')
            return redirect(next_url)
        else:
            messages.error(request, 'Invalid username or password.')
    
    return render(request, 'driveapp/login.html')

def user_register(request):
    """User registration view"""
    if request.user.is_authenticated:
        return redirect('home')
    
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            username = form.cleaned_data.get('username')
            messages.success(request, f'Account created for {username}! You can now log in.')
            return redirect('login')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f'{field.title()}: {error}')
    else:
        form = UserCreationForm()
    
    return render(request, 'driveapp/register.html', {'form': form})

def user_logout(request):
    """User logout view"""
    # Clear Google authentication sessions
    request.session.pop('credentials_source', None)
    request.session.pop('credentials_destination', None)
    request.session.pop('source_email', None)
    request.session.pop('dest_email', None)
    request.session.pop('transfer_id', None)
    
    logout(request)
    messages.success(request, 'You have been successfully logged out.')
    return redirect('login')

# Login to source Google account
@login_required
def login_source(request):
    flow = get_oauth_flow(settings.REDIRECT_URI_SOURCE)
    authorization_url, state = flow.authorization_url(access_type='offline', prompt='consent')
    request.session['state_source'] = state
    logger.info("Redirecting to source account authorization URL.")
    return redirect(authorization_url)

# Login to destination Google account
@login_required
def login_destination(request):
    flow = get_oauth_flow(settings.REDIRECT_URI_DESTINATION)
    authorization_url, state = flow.authorization_url(access_type='offline', prompt='consent')
    request.session['state_destination'] = state
    logger.info("Redirecting to destination account authorization URL.")
    return redirect(authorization_url)

# Handle OAuth2 callback for source account
@login_required
def oauth2callback_source(request):
    try:
        logger.info(f"OAuth callback received. Request params: {request.GET}")
        logger.info(f"Request URL: {request.build_absolute_uri()}")
        
        state = request.session.get('state_source')
        logger.info(f"Session state: {state}")
        
        if not state:
            logger.error("Session expired for source login.")
            messages.error(request, "Session expired. Please try again.")
            return redirect('home')
        
        flow = get_oauth_flow(settings.REDIRECT_URI_SOURCE)
        flow.state = state

        flow.fetch_token(authorization_response=request.build_absolute_uri())
        credentials = flow.credentials

        user_info_service = build('oauth2', 'v2', credentials=credentials)
        user_info = user_info_service.userinfo().get().execute()
        source_email = user_info.get('email')
        
        logger.info(f"OAuth granted scopes: {credentials.scopes}")
        
        # Save source email in session
        request.session['source_email'] = source_email
        request.session['credentials_source'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }

        logger.info(f"Source account {source_email} successfully authenticated.")
        messages.success(request, f"Successfully connected source account: {source_email}")
        return redirect('home')
        
    except Exception as e:
        logger.error(f"Error in OAuth callback for source: {str(e)}")
        logger.error(f"Exception type: {type(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        messages.error(request, f"Failed to authenticate with Google: {str(e)}")
        return redirect('home')

# Handle OAuth2 callback for destination account
@login_required
def oauth2callback_destination(request):
    try:
        state = request.session.get('state_destination')
        if not state:
            logger.error("Session expired for destination login.")
            messages.error(request, "Session expired. Please try again.")
            return redirect('home')
        
        flow = get_oauth_flow(settings.REDIRECT_URI_DESTINATION)
        flow.state = state

        flow.fetch_token(authorization_response=request.build_absolute_uri())
        credentials = flow.credentials

        user_info_service = build('oauth2', 'v2', credentials=credentials)
        user_info = user_info_service.userinfo().get().execute()
        dest_email = user_info.get('email')
        
        # Save destination email in session
        request.session['dest_email'] = dest_email
        request.session['credentials_destination'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }

        logger.info(f"Destination account {dest_email} successfully authenticated.")
        messages.success(request, f"Successfully connected destination account: {dest_email}")
        return redirect('home')
        
    except Exception as e:
        logger.error(f"Error in OAuth callback for destination: {str(e)}")
        messages.error(request, "Failed to authenticate with Google. Please try again.")
        return redirect('home')

def home(request):
    # Initialize context with default values for non-authenticated users
    context = {
        'source_logged_in': False,
        'dest_logged_in': False,
        'source_email': None,
        'dest_email': None,
        'transfer_id': None,
        'source_folders': [],
        'destination_folders': [],
    }
    
    # Only process Google Drive credentials if user is authenticated
    if request.user.is_authenticated:
        creds_source = request.session.get('credentials_source')
        creds_destination = request.session.get('credentials_destination')
        
        source_email = request.session.get('source_email')
        dest_email = request.session.get('dest_email')
        transfer_id = request.session.get('transfer_id', None)
        
        # Check if transfer is still active, if not remove from session
        active_transfer_id = None
        if transfer_id:
            try:
                transfer = FileTransfer.objects.get(transfer_uuid=transfer_id)
                if transfer.status == 'in_progress':
                    active_transfer_id = transfer_id
                else:
                    # Transfer is completed/failed/cancelled, remove from session
                    request.session.pop('transfer_id', None)
            except FileTransfer.DoesNotExist:
                # Transfer doesn't exist, remove from session
                request.session.pop('transfer_id', None)
        
        # Update context with authenticated user data
        context.update({
            'source_logged_in': bool(creds_source),
            'dest_logged_in': bool(creds_destination),
            'source_email': source_email,
            'dest_email': dest_email,
            'transfer_id': active_transfer_id,
        })

        # Fetch folders only if both Google accounts are connected
        if creds_source and creds_destination:
            try:
                service_source = build_drive_service(creds_source)
                service_destination = build_drive_service(creds_destination)

                # Fetch the folders from both source and destination drives
                source_folders = service_source.files().list(
                    q="'root' in parents",
                    fields="files(id, name, mimeType, parents)"
                ).execute().get('files', [])

                destination_folders = service_destination.files().list(
                    q="'root' in parents and mimeType='application/vnd.google-apps.folder'",
                    fields="files(id, name, parents)"
                ).execute().get('files', [])

                context['source_folders'] = source_folders
                context['destination_folders'] = destination_folders
                logger.info("Successfully fetched source and destination folders.")
            except Exception as e:
                logger.error(f"Error fetching folders: {str(e)}")
                messages.error(request, "Failed to fetch folders. Please try reconnecting your accounts.")
    
    return render(request, 'driveapp/home.html', context)

@login_required
def transfer_wizard(request):
    """Transfer wizard page with step-by-step interface"""
    # Initialize context with default values
    context = {
        'source_logged_in': False,
        'dest_logged_in': False,
        'source_email': None,
        'dest_email': None,
        'transfer_id': None,
        'source_folders': [],
        'destination_folders': [],
    }
    
    creds_source = request.session.get('credentials_source')
    creds_destination = request.session.get('credentials_destination')
    
    source_email = request.session.get('source_email')
    dest_email = request.session.get('dest_email')
    transfer_id = request.session.get('transfer_id', None)
    
    # Check if transfer is still active, if not remove from session
    active_transfer_id = None
    if transfer_id:
        try:
            transfer = FileTransfer.objects.get(transfer_uuid=transfer_id)
            if transfer.status == 'in_progress':
                active_transfer_id = transfer_id
            else:
                # Transfer is completed/failed/cancelled, remove from session
                request.session.pop('transfer_id', None)
        except FileTransfer.DoesNotExist:
            # Transfer doesn't exist, remove from session
            request.session.pop('transfer_id', None)
    
    # Update context with authenticated user data
    context.update({
        'source_logged_in': bool(creds_source),
        'dest_logged_in': bool(creds_destination),
        'source_email': source_email,
        'dest_email': dest_email,
        'transfer_id': active_transfer_id,
    })

    # Fetch folders only if both Google accounts are connected
    if creds_source and creds_destination:
        try:
            service_source = build_drive_service(creds_source)
            service_destination = build_drive_service(creds_destination)

            # Fetch the folders from both source and destination drives
            source_folders = service_source.files().list(
                q="'root' in parents",
                fields="files(id, name, mimeType, parents)"
            ).execute().get('files', [])

            destination_folders = service_destination.files().list(
                q="'root' in parents and mimeType='application/vnd.google-apps.folder'",
                fields="files(id, name, parents)"
            ).execute().get('files', [])

            context['source_folders'] = source_folders
            context['destination_folders'] = destination_folders
            logger.info("Successfully fetched source and destination folders for wizard.")
        except Exception as e:
            logger.error(f"Error fetching folders for wizard: {str(e)}")
            messages.error(request, "Failed to fetch folders. Please try reconnecting your accounts.")
    
    return render(request, 'driveapp/transfer_wizard.html', context)

def logout_view(request):
    logout(request)
    request.session.flush()
    logger.info("User logged out successfully.")
    return redirect('home')

def get_drive_service(credentials_dict):
    creds = Credentials(**credentials_dict)
    return build('drive', 'v3', credentials=creds)

# def perform_file_transfer(file_transfer_obj, creds_source,
#                            creds_destination, source_folder_id, 
#                            destination_folder_id):
#     try:
#         service_source = get_drive_service(creds_source)
#         service_destination = get_drive_service(creds_destination)

#         # List all files and folders
#         all_items = list_files_and_folders(service_source, source_folder_id, '', None)

#         file_transfer_obj.total_files = len([item for item in all_items if item['mimeType'] != 'application/vnd.google-apps.folder'])
#         file_transfer_obj.status = 'in_progress'
#         file_transfer_obj.save()

#         for idx,file in enumerate(all_items):
#             logger.info(f"Transferring file: {file['name']}")
#             body = {'name': file['name'], 'parents': [destination_folder_id]}
#             service_destination.files().copy(fileId=file['id'], body=body).execute()
#             file_transfer_obj.transferred_files = idx
#             file_transfer_obj.save()

#         file_transfer_obj.status = 'completed'
#         file_transfer_obj.save()
#         logger.info(f"File transfer completed for {file_transfer_obj.transfer_uuid}.")

#     except Exception as e:
#         file_transfer_obj.status = 'failed'
#         file_transfer_obj.error_message = str(e)
#         file_transfer_obj.save()
#         logger.error(f"Error during file transfer: {str(e)}")

@require_auth
def transfer_file(request):
    """Transfer files between Google Drive accounts with proper authentication"""
    if request.method == 'POST':
        # Check authentication for both accounts
        creds_source = request.session.get('credentials_source')
        creds_destination = request.session.get('credentials_destination')
        
        if not creds_source or not creds_destination:
            logger.error("Missing authentication credentials")
            return JsonResponse({'error': 'Both source and destination accounts must be authenticated'}, status=401)
        
        # Use the authenticated user for the transfer
        user = request.user
        
        # Get transfer type and source parameters
        transfer_type = request.POST.get('transfer_type', 'drive')
        destination_folder_id = request.POST.get('destination_folder_id')
        new_folder_name = request.POST.get('new_folder_name')
        new_folder_parent = request.POST.get('new_folder_parent')
        
        # Validate source based on transfer type
        if transfer_type == 'photos':
            source_album_id = request.POST.get('source_album_id')
            photos_date_filter = request.POST.get('photos_date_filter', 'all')
            
            if not source_album_id:
                logger.error("Missing source album ID for Photos transfer")
                return JsonResponse({'error': 'Source album must be selected for Photos transfer'}, status=400)
            
            # For photos transfers, source_folder_id will be None
            source_folder_id = None
        else:
            source_folder_id = request.POST.get('source_folder_id')
            source_album_id = None
            photos_date_filter = None
            
            if not source_folder_id:
                logger.error("Missing source folder ID for Drive transfer")
                return JsonResponse({'error': 'Source folder must be selected for Drive transfer'}, status=400)
        
        # Validate destination folder (required for both transfer types)
        if not destination_folder_id:
            logger.error("Missing destination folder ID")
            return JsonResponse({'error': 'Destination folder must be selected'}, status=400)
        
        # Handle new folder creation
        if destination_folder_id == 'create_new':
            if not new_folder_name or not new_folder_name.strip():
                logger.error("Missing new folder name")
                return JsonResponse({'error': 'New folder name is required'}, status=400)
            
            # Clean the folder name
            new_folder_name = new_folder_name.strip()
            parent_folder_id = new_folder_parent if new_folder_parent else 'root'
        
        try:
            # Build drive services first (needed for folder creation)
            try:
                service_source = build_drive_service(creds_source)
                service_destination = build_drive_service(creds_destination)
            except Exception as e:
                logger.error(f"Error building drive services: {str(e)}")
                return JsonResponse({'error': 'Error connecting to Google Drive'}, status=500)
            
            # Create new folder if requested
            if destination_folder_id == 'create_new':
                try:
                    logger.info(f"Creating new folder '{new_folder_name}' in parent '{parent_folder_id}'")
                    new_folder_id = create_folder(service_destination, new_folder_name, parent_folder_id)
                    destination_folder_id = new_folder_id
                    logger.info(f"Successfully created new folder with ID: {new_folder_id}")
                except Exception as e:
                    logger.error(f"Error creating new folder: {str(e)}")
                    return JsonResponse({'error': f'Error creating folder "{new_folder_name}": {str(e)}'}, status=500)
            
            obj = FileTransfer.objects.create(
                user=user,
                transfer_type=transfer_type,
                source_folder_id=source_folder_id,
                destination_folder_id=destination_folder_id,
                photos_album_id=source_album_id,
                photos_date_filter=photos_date_filter,
                status='pending',
                transfer_uuid=str(uuid.uuid4())
            )
            
            obj.source_email = request.session.get('source_email')
            obj.destination_email = request.session.get('dest_email')
            obj.save()

            # List items based on transfer type
            try:
                if transfer_type == 'photos':
                    # List photos from Google Photos
                    logger.info(f"Transfer {obj.transfer_uuid}: Listing photos from album ID: {source_album_id}")
                    photos_credentials = build_photos_service(creds_source)
                    
                    # Import photos utils
                    from .photos_utils import list_media_items
                    
                    # Get date filter if specified
                    date_filter = None
                    if photos_date_filter and photos_date_filter != 'all':
                        # You can implement date filtering logic here
                        pass
                    
                    # List media items
                    album_id = source_album_id if source_album_id != 'all' else None
                    all_items = list_media_items(photos_credentials, album_id, date_filter)
                    logger.info(f"Transfer {obj.transfer_uuid}: Photos listing completed. Items found: {len(all_items)}")
                else:
                    # List files from Google Drive
                    logger.info(f"Transfer {obj.transfer_uuid}: Listing files from folder ID: {obj.source_folder_id}")
                    all_items = list_files_and_folders(service_source, obj.source_folder_id)
                    logger.info(f"Transfer {obj.transfer_uuid}: Drive listing completed. Items found: {len(all_items)}")
                
                # Log first few items for debugging
                for i, item in enumerate(all_items[:5]):
                    logger.info(f"Item {i+1}: {item.get('filename' if transfer_type == 'photos' else 'name', 'Unknown')}")
                    
            except Exception as e:
                logger.error(f"Error listing items: {str(e)}")
                obj.status = 'failed'
                obj.save()
                return JsonResponse({'error': f'Error accessing source {transfer_type}'}, status=500)

            # Save file count and log details
            if transfer_type == 'photos':
                # For photos, all items are media files
                obj.total_files = len(all_items)
                folders_only = []
            else:
                # For drive, separate files and folders
                files_only = [item for item in all_items if item['mimeType'] != 'application/vnd.google-apps.folder']
                folders_only = [item for item in all_items if item['mimeType'] == 'application/vnd.google-apps.folder']
                obj.total_files = len(files_only)
            
            obj.save()
            
            logger.info(f"Transfer {obj.transfer_uuid}: Found {len(all_items)} total items ({obj.total_files} files, {len(folders_only) if transfer_type != 'photos' else 0} folders)")
            
            if len(all_items) == 0:
                obj.status = 'completed'
                obj.current_file = f'No items found in selected {transfer_type} source'
                obj.save()
                logger.warning(f"Transfer {obj.transfer_uuid} completed immediately - no items found")
                TransferLog.objects.create(
                    transfer=obj,
                    file_name='Transfer Completed',
                    file_type='system',
                    status='success',
                    message='Selected folder is empty or has no accessible items'
                )
            else:
                # Pass all_items to thread
                if transfer_type == 'photos':
                    photos_credentials = build_photos_service(creds_source)
                    thread = threading.Thread(target=start_transfer, args=(obj.id, all_items, service_source, service_destination, photos_credentials))
                else:
                    thread = threading.Thread(target=start_transfer, args=(obj.id, all_items, service_source, service_destination, None))
                thread.start()
                logger.info(f"{transfer_type.title()} transfer thread started for transfer UUID: {obj.transfer_uuid} with {len(all_items)} items")

            request.session['transfer_id'] = obj.transfer_uuid
            messages.success(request, f"Transfer started successfully! Monitoring progress...")
            return redirect('transfer_status_page', transfer_uuid=obj.transfer_uuid)
        
        except Exception as e:
            logger.error(f"Error creating transfer: {str(e)}")
            return JsonResponse({'error': 'Error creating file transfer'}, status=500)
    return redirect('home')

def start_transfer(obj_id, all_items, service_source, service_destination, photos_credentials=None):
    """Start the file transfer process with detailed logging and real-time updates"""
    try:
        obj = FileTransfer.objects.get(id=obj_id)
        obj.status = 'in_progress'
        obj.current_file = 'Initializing transfer...'
        obj.save()

        # Log transfer start
        TransferLog.objects.create(
            transfer=obj,
            file_name='Transfer Started',
            file_type='system',
            status='info',
            message=f'Starting {obj.get_transfer_type_display()} transfer of {len(all_items)} items'
        )

        # Handle different transfer types
        if obj.is_photos_transfer:
            transfer_photos_to_drive(obj, all_items, photos_credentials, service_destination)
        else:
            transfer_drive_to_drive(obj, all_items, service_source, service_destination)
        
    except Exception as e:
        logger.error(f"Error in transfer process: {str(e)}")
        try:
            obj = FileTransfer.objects.get(id=obj_id)
            obj.status = 'failed'
            obj.current_file = 'Transfer failed'
            obj.save()
            
            # Log transfer failure
            TransferLog.objects.create(
                transfer=obj,
                file_name='Transfer Failed',
                file_type='system',
                status='failed',
                message=f'Transfer failed with error: {str(e)}'
            )
        except:
            logger.error(f"Could not update transfer status to failed for ID: {obj_id}")

def transfer_photos_to_drive(obj, all_items, photos_credentials, service_destination):
    """Transfer Google Photos media items to Google Drive"""
    try:
        from .photos_utils import download_media_item
        
        destination_folder_id = obj.destination_folder_id
        file_count = 0
        
        obj.current_file = 'Starting Photos transfer...'
        obj.save()
        
        for idx, media_item in enumerate(all_items):
            try:
                # Update current file being processed
                filename = media_item.get('filename', f'Media Item {idx+1}')
                obj.current_file = f"Transferring: {filename}"
                obj.save()
                
                # Download from Photos and upload to Drive
                download_media_item(photos_credentials, media_item, destination_folder_id, service_destination)
                file_count += 1
                
                # Update transfer progress
                obj.transferred_files = file_count
                obj.save()
                
                # Log successful media transfer
                TransferLog.objects.create(
                    transfer=obj,
                    file_name=filename,
                    file_type='media',
                    status='success',
                    message=f'Media item transferred successfully'
                )
                
                logger.info(f"Transferred media: {filename}")
                
                # Check if transfer was cancelled
                obj.refresh_from_db()
                if obj.status == 'cancelled':
                    TransferLog.objects.create(
                        transfer=obj,
                        file_name='Transfer Cancelled',
                        file_type='system',
                        status='cancelled',
                        message='Transfer was cancelled by user'
                    )
                    logger.info(f"Transfer {obj.transfer_uuid} was cancelled")
                    return
                    
            except Exception as e:
                # Log media transfer failure
                TransferLog.objects.create(
                    transfer=obj,
                    file_name=filename,
                    file_type='media',
                    status='failed',
                    message=f'Error transferring media: {str(e)}'
                )
                logger.error(f"Error transferring media {filename}: {str(e)}")
                # Continue with other files even if one fails
                
        # Transfer completed
        obj.status = 'completed'
        obj.current_file = 'Photos transfer completed successfully!'
        obj.save()
        
        # Log transfer completion
        TransferLog.objects.create(
            transfer=obj,
            file_name='Transfer Completed',
            file_type='system',
            status='success',
            message=f'Successfully transferred {file_count} photos/videos'
        )
        
        logger.info(f"Photos transfer completed for UUID: {obj.transfer_uuid}. Media items: {file_count}")
        
    except Exception as e:
        logger.error(f"Error in Photos transfer: {str(e)}")
        obj.status = 'failed'
        obj.current_file = 'Photos transfer failed'
        obj.save()
        
        # Log transfer failure
        TransferLog.objects.create(
            transfer=obj,
            file_name='Transfer Failed',
            file_type='system',
            status='failed',
            message=f'Photos transfer failed: {str(e)}'
        )

def transfer_drive_to_drive(obj, all_items, service_source, service_destination):
    """Transfer Google Drive files and folders to another Drive account"""
    try:
        source_folder_id = obj.source_folder_id
        destination_folder_id = obj.destination_folder_id
        folder_mapping = {source_folder_id: destination_folder_id}

        # Create folders first
        obj.current_file = 'Creating folder structure...'
        obj.save()
        
        folder_count = 0
        for item in all_items:
            if item['mimeType'] == 'application/vnd.google-apps.folder':
                try:
                    obj.current_file = f"Creating folder: {item['name']}"
                    obj.save()
                    
                    if item['parent']:
                        parent_dest_id = folder_mapping.get(item['parent']['id'], destination_folder_id)
                    else:
                        parent_dest_id = destination_folder_id
                    
                    new_folder_id = create_folder(service_destination, item['name'], parent_dest_id)
                    folder_mapping[item['id']] = new_folder_id
                    folder_count += 1
                    
                    # Log successful folder creation
                    TransferLog.objects.create(
                        transfer=obj,
                        file_name=item['name'],
                        file_type='folder',
                        status='success',
                        message=f'Folder created successfully'
                    )
                    
                    logger.info(f"Created folder: {item['name']} in destination.")
                    
                except Exception as e:
                    # Log folder creation failure
                    TransferLog.objects.create(
                        transfer=obj,
                        file_name=item['name'],
                        file_type='folder',
                        status='failed',
                        message=f'Error creating folder: {str(e)}'
                    )
                    logger.error(f"Error creating folder {item['name']}: {str(e)}")

        # Log folder creation completion
        if folder_count > 0:
            TransferLog.objects.create(
                transfer=obj,
                file_name='Folder Structure',
                file_type='system',
                status='success',
                message=f'Created {folder_count} folders successfully'
            )

        # Then copy files
        pre_parenet_id = ""
        parent_name = "root"
        file_count = 0
        
        for idx, item in enumerate(all_items):
            if item['mimeType'] != 'application/vnd.google-apps.folder':
                try:
                    # Update current file being processed
                    obj.current_file = f"Transferring: {item['name']}"
                    obj.save()
                    
                    if item['parent']:
                        parent_dest_id = folder_mapping.get(item['parent']['id'], destination_folder_id)
                    else:
                        parent_dest_id = destination_folder_id
                    
                    # Get folder name if changed
                    if pre_parenet_id != parent_dest_id:
                        parent_name = get_folder_name(service_destination, parent_dest_id) if parent_dest_id else "Root"

                    # Copy the file
                    copy_file_between_drives(service_source, service_destination, item['id'], item['name'], parent_dest_id, parent_name)
                    pre_parenet_id = parent_dest_id
                    file_count += 1
                    
                    # Update transfer progress
                    obj.transferred_files = file_count
                    obj.save()
                    
                    # Log successful file transfer
                    TransferLog.objects.create(
                        transfer=obj,
                        file_name=item['name'],
                        file_type='file',
                        status='success',
                        message=f'File transferred successfully to {parent_name}'
                    )
                    
                    logger.info(f"Transferred file: {item['name']} to {parent_name}")
                    
                    # Check if transfer was cancelled
                    obj.refresh_from_db()
                    if obj.status == 'cancelled':
                        TransferLog.objects.create(
                            transfer=obj,
                            file_name='Transfer Cancelled',
                            file_type='system',
                            status='cancelled',
                            message='Transfer was cancelled by user'
                        )
                        logger.info(f"Transfer {obj.transfer_uuid} was cancelled")
                        return
                        
                except Exception as e:
                    # Log file transfer failure
                    TransferLog.objects.create(
                        transfer=obj,
                        file_name=item['name'],
                        file_type='file',
                        status='failed',
                        message=f'Error transferring file: {str(e)}'
                    )
                    logger.error(f"Error copying file {item['name']}: {str(e)}")
                    # Continue with other files even if one fails
                    
        # Transfer completed
        obj.status = 'completed'
        obj.current_file = 'Transfer completed successfully!'
        obj.save()
        
        # Log transfer completion
        TransferLog.objects.create(
            transfer=obj,
            file_name='Transfer Completed',
            file_type='system',
            status='success',
            message=f'Successfully transferred {file_count} files and {folder_count} folders'
        )
        
        logger.info(f"Drive transfer completed for UUID: {obj.transfer_uuid}. Files: {file_count}, Folders: {folder_count}")
        
    except Exception as e:
        logger.error(f"Error in Drive transfer: {str(e)}")
        obj.status = 'failed'
        obj.current_file = 'Drive transfer failed'
        obj.save()
        
        # Log transfer failure
        TransferLog.objects.create(
            transfer=obj,
            file_name='Transfer Failed',
            file_type='system',
            status='failed',
            message=f'Drive transfer failed: {str(e)}'
        )

@require_auth
def transfer_status_page(request, transfer_uuid):
    """
    Display a dedicated page showing the status of a specific transfer
    """
    try:
        # Get the transfer object (always get fresh data)
        transfer = FileTransfer.objects.get(transfer_uuid=transfer_uuid)
        
        # Update session if this transfer is completed but still in session
        session_transfer_id = request.session.get('transfer_id')
        if session_transfer_id == transfer_uuid and transfer.status != 'in_progress':
            request.session.pop('transfer_id', None)
        
        # Get source and destination account information
        source_email = request.session.get('source_email', transfer.source_email or 'Unknown')
        dest_email = request.session.get('dest_email', transfer.destination_email or 'Unknown')
        
        # Calculate progress percentage
        progress_percentage = 0
        if transfer.total_files > 0:
            progress_percentage = int((transfer.transferred_files / transfer.total_files) * 100)
        
        context = {
            'transfer': transfer,
            'source_email': source_email,
            'dest_email': dest_email,
            'progress_percentage': progress_percentage,
        }
        
        return render(request, 'driveapp/transfer_status.html', context)
    
    except FileTransfer.DoesNotExist:
        # messages.error(request, "Transfer not found. The UUID may be incorrect.")
        return redirect('home')

def get_transfer_status(request, transfer_uuid):
    """API endpoint to get the current status of a transfer with detailed progress"""
    try:
        transfer = FileTransfer.objects.get(transfer_uuid=transfer_uuid)
        
        # Calculate percentage
        percentage = 0
        if transfer.total_files > 0:
            percentage = int((transfer.transferred_files / transfer.total_files) * 100)
        
        # Get recent transfer logs (last 10 items)
        recent_logs = transfer.logs.all()[:10]
        logs_data = []
        for log in recent_logs:
            logs_data.append({
                'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'file_name': log.file_name,
                'file_type': log.file_type,
                'status': log.status,
                'message': log.message
            })
        
        return JsonResponse({
            'status': transfer.status,
            'total_files': transfer.total_files,
            'transferred_files': transfer.transferred_files,
            'percentage': percentage,
            'current_file': transfer.current_file,
            'is_complete': transfer.status == 'completed',
            'recent_logs': logs_data,
            'source_email': transfer.source_email,
            'destination_email': transfer.destination_email,
            'created_at': transfer.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': transfer.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    except FileTransfer.DoesNotExist:
        return JsonResponse({'error': 'Transfer not found'}, status=404)
@require_POST
def cancel_transfer(request, transfer_uuid):
    """API endpoint to cancel an in-progress transfer"""
    try:
        transfer = FileTransfer.objects.get(transfer_uuid=transfer_uuid)
        
        if transfer.status != 'in_progress':
            return JsonResponse({'success': False, 'error': 'Transfer is not in progress'})
        
        # Update transfer status
        transfer.status = 'cancelled'
        transfer.save()
        
        # You may need to signal any background process to stop the transfer
        # This depends on how you've implemented your transfer process
        
        return JsonResponse({'success': True})
    except FileTransfer.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Transfer not found'}, status=404)
    
@login_required
def dashboard(request):
    transfers = FileTransfer.objects.filter(user=request.user).order_by('-created_at')  # Latest first
    return render(request, 'driveapp/dashboard.html', {'transfers': transfers})

# Footer Pages Views
def help_center(request):
    """Help Center page with comprehensive guides and documentation"""
    return render(request, 'driveapp/help_center.html')

def faq(request):
    """Frequently Asked Questions page"""
    return render(request, 'driveapp/faq.html')

def tutorials(request):
    """Tutorials and how-to guides page"""
    return render(request, 'driveapp/tutorials.html')

def contact(request):
    """Contact Us page with support information"""
    return render(request, 'driveapp/contact.html')

def status(request):
    """System Status page showing service health"""
    return render(request, 'driveapp/status.html')

def about(request):
    """About Us page with company information"""
    return render(request, 'driveapp/about.html')

def blog(request):
    """Blog page with latest updates and articles"""
    return render(request, 'driveapp/blog.html')

def careers(request):
    """Careers page with job opportunities"""
    return render(request, 'driveapp/careers.html')

def press(request):
    """Press Kit page with media resources"""
    return render(request, 'driveapp/press.html')

def partners(request):
    """Partners page with partnership information"""
    return render(request, 'driveapp/partners.html')

def terms(request):
    """Terms of Service page"""
    return render(request, 'driveapp/terms.html')

def cookies(request):
    """Cookie Policy page"""
    return render(request, 'driveapp/cookies.html')

@require_auth
def get_photos_albums(request):
    """API endpoint to fetch Google Photos albums"""
    try:
        logger.info("Photos albums API called")
        creds_source = request.session.get('credentials_source')
        if not creds_source:
            logger.error("No source credentials found in session")
            return JsonResponse({'error': 'Source account not authenticated'}, status=401)
        
        logger.info("Building Photos service...")
        logger.info(f"Source credentials scopes: {creds_source.get('scopes', 'No scopes found')}")
        
        # Build Photos service (returns credentials)
        photos_credentials = build_photos_service(creds_source)
        
        logger.info("Fetching albums from Google Photos...")
        # Get albums
        albums = list_albums(photos_credentials)
        logger.info(f"Found {len(albums)} albums")
        
        # Format albums for frontend
        formatted_albums = []
        for album in albums:
            formatted_albums.append({
                'id': album.get('id'),
                'title': album.get('title', 'Untitled Album'),
                'mediaItemsCount': album.get('mediaItemsCount', 0)
            })
        
        logger.info(f"Returning {len(formatted_albums)} formatted albums")
        return JsonResponse({
            'success': True,
            'albums': formatted_albums
        })
        
    except Exception as e:
        error_str = str(e)
        logger.error(f"Error fetching Photos albums: {error_str}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        
        # Check if it's a scope/permission error (403 Forbidden)
        if '403' in error_str or 'forbidden' in error_str.lower() or 'insufficient' in error_str.lower() or 'scope' in error_str.lower() or 'permission' in error_str.lower():
            return JsonResponse({
                'error': 'Google Photos permission required. Please re-authenticate your source account to grant Photos access.',
                'needs_reauth': True
            }, status=403)
        
        return JsonResponse({'error': f'Failed to fetch albums: {error_str}'}, status=500)
