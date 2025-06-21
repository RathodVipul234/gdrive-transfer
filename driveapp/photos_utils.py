"""
Google Photos API utilities for photo transfers
"""
import logging
import requests
from google.oauth2.credentials import Credentials

logger = logging.getLogger(__name__)

def build_photos_service(credentials_dict):
    """Build Google Photos Library API service using direct HTTP requests"""
    try:
        creds = Credentials(**credentials_dict)
        # Return credentials object that we'll use for direct API calls
        return creds
    except Exception as e:
        logger.error(f"Error building Photos service: {str(e)}")
        raise

def list_albums(credentials):
    """List all albums from Google Photos using direct HTTP requests"""
    try:
        albums = []
        page_token = None
        base_url = "https://photoslibrary.googleapis.com/v1/albums"
        
        # Get access token and ensure it's fresh
        if credentials.expired or not hasattr(credentials, 'token'):
            logger.info("Refreshing expired/missing credentials...")
            credentials.refresh(requests.Request())
        
        access_token = credentials.token
        
        logger.info(f"Using access token: {access_token[:20]}...")
        logger.info(f"Credentials scopes: {getattr(credentials, 'scopes', 'No scopes')}")
        logger.info(f"Token expires at: {getattr(credentials, 'expiry', 'No expiry info')}")
        
        headers = {
            'Authorization': f'Bearer {access_token}'
        }
        
        # Test what scopes the token actually has
        token_info_url = f"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={access_token}"
        token_info_response = requests.get(token_info_url)
        if token_info_response.status_code == 200:
            token_info = token_info_response.json()
            logger.info(f"Actual token scopes: {token_info.get('scope', 'No scope info')}")
            logger.info(f"Token audience: {token_info.get('audience', 'No audience info')}")
            logger.info(f"Token issued to: {token_info.get('issued_to', 'No issued_to info')}")
        else:
            logger.error(f"Could not verify token scopes: {token_info_response.text}")
        
        # Test API access with the simplest possible call
        test_url = "https://photoslibrary.googleapis.com/v1/mediaItems?pageSize=1"
        test_response = requests.get(test_url, headers=headers)
        logger.info(f"MediaItems test API call status: {test_response.status_code}")
        if test_response.status_code != 200:
            logger.error(f"MediaItems test API call failed: {test_response.text}")
        else:
            logger.info("MediaItems test API call successful!")
        
        while True:
            # Try the exact Google Photos API format
            if page_token:
                url = f"{base_url}?pageSize=50&pageToken={page_token}"
            else:
                url = f"{base_url}?pageSize=50"
            
            logger.info(f"Making request to: {url}")
            response = requests.get(url, headers=headers)
            logger.info(f"API Response Status: {response.status_code}")
            logger.info(f"API Response Headers: {dict(response.headers)}")
            if response.status_code != 200:
                logger.error(f"API Response Body: {response.text}")
            response.raise_for_status()
            
            data = response.json()
            
            if 'albums' in data:
                albums.extend(data['albums'])
            
            page_token = data.get('nextPageToken')
            if not page_token:
                break
                
        logger.info(f"Found {len(albums)} albums")
        return albums
        
    except Exception as e:
        logger.error(f"Error listing albums: {str(e)}")
        raise

def list_media_items(credentials, album_id=None, date_filter=None, page_size=100):
    """List media items from Google Photos using direct HTTP requests"""
    try:
        media_items = []
        page_token = None
        
        # Get access token
        if hasattr(credentials, 'token'):
            access_token = credentials.token
        else:
            credentials.refresh(requests.Request())
            access_token = credentials.token
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        
        while True:
            if album_id or date_filter:
                # Use search endpoint for filtered requests
                url = "https://photoslibrary.googleapis.com/v1/mediaItems:search"
                
                request_body = {
                    'pageSize': page_size
                }
                
                if album_id:
                    request_body['albumId'] = album_id
                
                if date_filter:
                    request_body['filters'] = {
                        'dateFilter': date_filter
                    }
                
                if page_token:
                    request_body['pageToken'] = page_token
                
                response = requests.post(url, headers=headers, json=request_body)
            else:
                # Use list endpoint for all media items
                url = "https://photoslibrary.googleapis.com/v1/mediaItems"
                params = {'pageSize': page_size}
                if page_token:
                    params['pageToken'] = page_token
                
                response = requests.get(url, headers=headers, params=params)
            
            response.raise_for_status()
            data = response.json()
            
            if 'mediaItems' in data:
                media_items.extend(data['mediaItems'])
            
            page_token = data.get('nextPageToken')
            if not page_token:
                break
                
        logger.info(f"Found {len(media_items)} media items")
        return media_items
        
    except Exception as e:
        logger.error(f"Error listing media items: {str(e)}")
        raise

def download_media_item(credentials, media_item, destination_folder_id, drive_service):
    """Download media item from Photos and upload to Drive"""
    try:
        # Get download URL with full resolution
        base_url = media_item['baseUrl']
        if media_item.get('mediaMetadata', {}).get('photo'):
            # For photos, request original quality
            download_url = f"{base_url}=d"
        else:
            # For videos, request original quality
            download_url = f"{base_url}=dv"
        
        # Download the media item
        response = requests.get(download_url)
        response.raise_for_status()
        
        # Upload to Google Drive
        file_metadata = {
            'name': media_item.get('filename', 'unknown'),
            'parents': [destination_folder_id]
        }
        
        from googleapiclient.http import MediaIoBaseUpload
        import io
        
        media = MediaIoBaseUpload(
            io.BytesIO(response.content),
            mimetype=media_item.get('mimeType', 'application/octet-stream'),
            resumable=True
        )
        
        file = drive_service.files().create(
            body=file_metadata,
            media_body=media,
            fields='id'
        ).execute()
        
        logger.info(f"Successfully transferred {media_item.get('filename')} to Drive")
        return file.get('id')
        
    except Exception as e:
        logger.error(f"Error transferring media item {media_item.get('filename', 'unknown')}: {str(e)}")
        raise

def get_album_name(credentials, album_id):
    """Get album name by ID using direct HTTP requests"""
    try:
        # Get access token
        if hasattr(credentials, 'token'):
            access_token = credentials.token
        else:
            credentials.refresh(requests.Request())
            access_token = credentials.token
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        
        url = f"https://photoslibrary.googleapis.com/v1/albums/{album_id}"
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        album = response.json()
        return album.get('title', 'Unknown Album')
    except Exception as e:
        logger.error(f"Error getting album name for {album_id}: {str(e)}")
        return 'Unknown Album'