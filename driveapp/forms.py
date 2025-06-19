"""
Forms for privacy and security features
"""
from django import forms
from .models import UserPrivacyPreference, DataExportRequest

class PrivacyPreferenceForm(forms.ModelForm):
    """Form for updating user privacy preferences"""
    
    class Meta:
        model = UserPrivacyPreference
        fields = [
            'analytics_consent',
            'email_notifications', 
            'data_retention_days',
            'share_usage_stats'
        ]
        widgets = {
            'analytics_consent': forms.CheckboxInput(attrs={
                'class': 'form-check-input',
                'id': 'analytics_consent'
            }),
            'email_notifications': forms.CheckboxInput(attrs={
                'class': 'form-check-input',
                'id': 'email_notifications'
            }),
            'data_retention_days': forms.Select(
                choices=[
                    (30, '30 days'),
                    (90, '90 days'),
                    (180, '180 days'),
                    (365, '1 year'),
                    (0, 'Keep forever')
                ],
                attrs={
                    'class': 'form-select',
                    'id': 'data_retention_days'
                }
            ),
            'share_usage_stats': forms.CheckboxInput(attrs={
                'class': 'form-check-input',
                'id': 'share_usage_stats'
            })
        }
        labels = {
            'analytics_consent': 'Allow analytics and usage tracking',
            'email_notifications': 'Receive email notifications about transfers',
            'data_retention_days': 'How long to keep your transfer data',
            'share_usage_stats': 'Share anonymous usage statistics to help improve the service'
        }
        help_texts = {
            'analytics_consent': 'Help us improve the service by sharing anonymous usage data',
            'email_notifications': 'Get notified when transfers complete or fail',
            'data_retention_days': 'Your transfer history will be automatically deleted after this period',
            'share_usage_stats': 'Only anonymous, aggregated statistics are shared - never your personal data'
        }

class DataExportForm(forms.ModelForm):
    """Form for requesting data export or deletion"""
    
    class Meta:
        model = DataExportRequest
        fields = ['request_type', 'notes']
        widgets = {
            'request_type': forms.Select(
                choices=[
                    ('export', 'Export my data'),
                    ('deletion', 'Delete my data')
                ],
                attrs={
                    'class': 'form-select',
                    'id': 'request_type'
                }
            ),
            'notes': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Optional: Add any specific requirements or notes about your request...',
                'id': 'export_notes'
            })
        }
        labels = {
            'request_type': 'Request type',
            'notes': 'Additional notes (optional)'
        }
        help_texts = {
            'request_type': 'Choose whether to export your data or request complete deletion',
            'notes': 'Provide any specific requirements for your data export or deletion request'
        }