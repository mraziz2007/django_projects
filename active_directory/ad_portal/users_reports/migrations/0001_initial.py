# Generated by Django 4.2.4 on 2023-08-31 05:50

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='RegistrationModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('first_name', models.CharField(max_length=50)),
                ('last_name', models.CharField(max_length=50)),
                ('email', models.EmailField(max_length=100)),
                ('username', models.CharField(max_length=50)),
                ('password', models.CharField(max_length=50)),
                ('security_question1', models.CharField(max_length=100)),
                ('security_question2', models.CharField(max_length=100)),
                ('security_question3', models.CharField(max_length=100)),
            ],
        ),
    ]