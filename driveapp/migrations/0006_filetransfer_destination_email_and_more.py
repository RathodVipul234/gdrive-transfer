# Generated by Django 4.2.20 on 2025-04-27 17:38

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('driveapp', '0005_alter_filetransfer_user'),
    ]

    operations = [
        migrations.AddField(
            model_name='filetransfer',
            name='destination_email',
            field=models.EmailField(default=django.utils.timezone.now, max_length=254),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='filetransfer',
            name='source_email',
            field=models.EmailField(default=django.utils.timezone.now, max_length=254),
            preserve_default=False,
        ),
    ]
