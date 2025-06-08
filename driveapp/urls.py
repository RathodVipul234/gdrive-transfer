from django.urls import path
from . import views

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
]
