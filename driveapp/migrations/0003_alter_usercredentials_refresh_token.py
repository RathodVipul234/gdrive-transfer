# Generated by Django 4.2.20 on 2025-04-16 16:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('driveapp', '0002_usercredentials_created_at_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='usercredentials',
            name='refresh_token',
            field=models.TextField(blank=True, null=True),
        ),
    ]
