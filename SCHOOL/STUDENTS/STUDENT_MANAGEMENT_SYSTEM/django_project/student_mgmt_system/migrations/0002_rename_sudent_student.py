# Generated by Django 4.2.2 on 2023-06-08 22:37

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('student_mgmt_system', '0001_initial'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='Sudent',
            new_name='Student',
        ),
    ]