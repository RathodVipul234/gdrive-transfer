from django.urls import path
from . import views
from . import privacy_views

# urlpatterns = [
#         path('', views.home, name='home'),
#         path('login/', views.login_view, name='login'),
#         path('logout/', views.logout_view, name='logout'),
#         path('dashboard/', views.dashboard, name='dashboard'),
#         # path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
#         # path('transfer/<str:user_email>/', views.transfer_to_user, name='transfer_to_user'),
#         path('transfer/<str:file_id>/', views.transfer_file, name='transfer_file'),

#         path('oauth2callback/', views.oauth2callback, name='oauth2callback'),
#     ]

urlpatterns = [
    # Authentication URLs
    path('login/', views.user_login, name='login'),
    path('register/', views.user_register, name='register'),
    path('logout/', views.user_logout, name='logout'),
    
    # Main app URLs
    path('', views.home, name='home'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('transfer-wizard/', views.transfer_wizard, name='transfer_wizard'),
    
    # Google OAuth URLs
    path('login/source/', views.login_source, name='login_source'),
    path('login/destination/', views.login_destination, name='login_destination'),
    path('oauth2callback/source/', views.oauth2callback_source, name='oauth2callback_source'),
    path('oauth2callback/destination/', views.oauth2callback_destination, name='oauth2callback_destination'),
    
    # Transfer URLs
    path('transfer/', views.transfer_file, name='transfer_file'),
    path('transfer-status/<str:transfer_uuid>/', views.transfer_status_page, name='transfer_status_page'),

    # API endpoints
    path('api/transfer-status/<str:transfer_uuid>/', views.get_transfer_status, name='get_transfer_status'),
    path('api/cancel-transfer/<str:transfer_uuid>/', views.cancel_transfer, name='cancel_transfer'),
    path('api/photos/albums/', views.get_photos_albums, name='get_photos_albums'),
    
    # Privacy and Security URLs
    path('privacy/', privacy_views.privacy_dashboard, name='privacy_dashboard'),
    path('privacy/update/', privacy_views.update_privacy_preferences, name='update_privacy_preferences'),
    path('privacy/security-logs/', privacy_views.security_log_view, name='security_logs'),
    path('privacy/export-request/', privacy_views.request_data_export, name='request_data_export'),
    path('privacy/revoke-access/', privacy_views.revoke_oauth_access, name='revoke_oauth_access'),
    path('privacy/download-data/', privacy_views.download_user_data, name='download_user_data'),
    path('api/security-dashboard/', privacy_views.security_dashboard_api, name='security_dashboard_api'),
    
    # Footer Pages URLs
    # Support Pages
    path('help/', views.help_center, name='help_center'),
    path('faq/', views.faq, name='faq'),
    path('tutorials/', views.tutorials, name='tutorials'),
    path('contact/', views.contact, name='contact'),
    path('status/', views.status, name='status'),
    
    # Company Pages
    path('about/', views.about, name='about'),
    path('blog/', views.blog, name='blog'),
    path('careers/', views.careers, name='careers'),
    path('press/', views.press, name='press'),
    path('partners/', views.partners, name='partners'),
    
    # Legal Pages
    path('terms/', views.terms, name='terms'),
    path('cookies/', views.cookies, name='cookies'),
]
