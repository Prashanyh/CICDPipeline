# Generated by Django 3.2.8 on 2022-02-11 09:31

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('UserAdministration', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='LoginHours',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user_id', models.CharField(blank=True, max_length=50, null=True)),
                ('user', models.CharField(blank=True, max_length=50, null=True)),
                ('login_date', models.CharField(blank=True, max_length=50, null=True)),
                ('diiffrences', models.CharField(blank=True, max_length=90, null=True)),
            ],
        ),
    ]