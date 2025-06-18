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

# SCOPES for Google Drive
SCOPES = [
    "https://www.googleapis.com/auth/userinfo.email",
    "openid",
    "https://www.googleapis.com/auth/drive"
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

@login_required
def home(request):
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
    
    context = {
        'source_logged_in': bool(creds_source),
        'dest_logged_in': bool(creds_destination),
        'source_email': source_email,
        'dest_email': dest_email,
        'transfer_id': active_transfer_id,
    }

    if creds_source and creds_destination:
        service_source = build_drive_service(creds_source)
        service_destination = build_drive_service(creds_destination)

        # Fetch the folders from both source and destination drives
        source_folders  = service_source.files().list(
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
        return render(request, 'driveapp/home.html', context)
    return render(request, 'driveapp/home.html', context)

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
        # Validate folder IDs
        source_folder_id = request.POST.get('source_folder_id')
        destination_folder_id = request.POST.get('destination_folder_id')
        
        if not source_folder_id or not destination_folder_id:
            logger.error("Missing source or destination folder ID")
            return JsonResponse({'error': 'Both source and destination folders must be selected'}, status=400)
        
        try:
            obj = FileTransfer.objects.create(
                user=user,
                source_folder_id=source_folder_id,
                destination_folder_id=destination_folder_id,
                status='pending',
                transfer_uuid=str(uuid.uuid4())
            )
            
            obj.source_email = request.session.get('source_email')
            obj.destination_email = request.session.get('dest_email')
            obj.save()
            
            # Build drive services with error handling
            try:
                service_source = build_drive_service(creds_source)
                service_destination = build_drive_service(creds_destination)
            except Exception as e:
                logger.error(f"Error building drive services: {str(e)}")
                obj.status = 'failed'
                obj.save()
                return JsonResponse({'error': 'Error connecting to Google Drive'}, status=500)

            # List files once with error handling
            try:
                logger.info(f"Transfer {obj.transfer_uuid}: Listing files from folder ID: {obj.source_folder_id}")
                all_items = list_files_and_folders(service_source, obj.source_folder_id)
                logger.info(f"Transfer {obj.transfer_uuid}: Raw file listing completed. Items found: {len(all_items)}")
                
                # Log first few items for debugging
                for i, item in enumerate(all_items[:5]):
                    logger.info(f"Item {i+1}: {item.get('name', 'Unknown')} (Type: {item.get('mimeType', 'Unknown')})")
                    
            except Exception as e:
                logger.error(f"Error listing files: {str(e)}")
                obj.status = 'failed'
                obj.save()
                return JsonResponse({'error': 'Error accessing source folder'}, status=500)

            # Save file count and log details
            files_only = [item for item in all_items if item['mimeType'] != 'application/vnd.google-apps.folder']
            folders_only = [item for item in all_items if item['mimeType'] == 'application/vnd.google-apps.folder']
            obj.total_files = len(files_only)
            obj.save()
            
            logger.info(f"Transfer {obj.transfer_uuid}: Found {len(all_items)} total items ({obj.total_files} files, {len(folders_only)} folders)")
            
            if len(all_items) == 0:
                obj.status = 'completed'
                obj.current_file = 'No items found in selected folder'
                obj.save()
                logger.warning(f"Transfer {obj.transfer_uuid} completed immediately - no items found in folder {obj.source_folder_id}")
                TransferLog.objects.create(
                    transfer=obj,
                    file_name='Transfer Completed',
                    file_type='system',
                    status='success',
                    message='Selected folder is empty or has no accessible items'
                )
            else:
                # Pass all_items to thread
                thread = threading.Thread(target=start_transfer, args=(obj.id, all_items, service_source, service_destination))
                thread.start()
                logger.info(f"File transfer thread started for transfer UUID: {obj.transfer_uuid} with {len(all_items)} items")

            request.session['transfer_id'] = obj.transfer_uuid
            messages.success(request, f"Transfer started successfully! Monitoring progress...")
            return redirect('transfer_status_page', transfer_uuid=obj.transfer_uuid)
        
        except Exception as e:
            logger.error(f"Error creating transfer: {str(e)}")
            return JsonResponse({'error': 'Error creating file transfer'}, status=500)
    return redirect('home')

def start_transfer(obj_id, all_items, service_source, service_destination):
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
            message=f'Starting transfer of {len(all_items)} items'
        )

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
        
        logger.info(f"Transfer completed for UUID: {obj.transfer_uuid}. Files: {file_count}, Folders: {folder_count}")
        
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
