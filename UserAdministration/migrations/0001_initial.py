# Generated by Django 3.2.7 on 2021-12-13 08:58

import UserAdministration.models
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='Teams',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('teamname', models.CharField(max_length=100, unique=True)),
                ('team_description', models.CharField(max_length=1024)),
            ],
        ),
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('username', models.CharField(blank=True, max_length=200, null=True, unique=True)),
                ('fullname', models.CharField(blank=True, max_length=200, null=True, verbose_name='name')),
                ('mobile', models.CharField(blank=True, max_length=10, null=True, unique=True, verbose_name='mobile')),
                ('email', models.EmailField(blank=True, max_length=254, null=True, verbose_name='email address')),
                ('password', models.CharField(blank=True, max_length=25, null=True, verbose_name='password')),
                ('date_joined', models.DateTimeField(auto_now_add=True, verbose_name='date joined')),
                ('is_verified', models.BooleanField(default=True)),
                ('is_active', models.BooleanField(default=True, verbose_name='active')),
                ('is_admin', models.BooleanField(blank=True, default=False, null=True, verbose_name='is_Admin')),
                ('is_manager', models.BooleanField(blank=True, default=False, null=True, verbose_name='is_Manger')),
                ('is_tl', models.BooleanField(blank=True, default=False, null=True, verbose_name='is_Tl')),
                ('is_agent', models.BooleanField(blank=True, default=False, null=True, verbose_name='is_Agent')),
                ('orginization', models.CharField(default=False, max_length=200, null=True)),
                ('dob', models.DateField(default=False)),
                ('gender', models.CharField(choices=[('M', 'Male'), ('F', 'Female')], default=False, max_length=1)),
                ('role', models.CharField(choices=[('Manager', 'Manager'), ('TL', 'TL'), ('Admin', 'Admin'), ('Agent', 'Agent')], default=False, max_length=100, null=True)),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.Group', verbose_name='groups')),
                ('team_name', models.ForeignKey(default=False, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='person_team', to='UserAdministration.teams')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.Permission', verbose_name='user permissions')),
            ],
            options={
                'verbose_name': 'user',
                'verbose_name_plural': 'users',
            },
            managers=[
                ('objects', UserAdministration.models.UserManager()),
            ],
        ),
        migrations.CreateModel(
            name='Sci1stKey',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('xl_id', models.CharField(blank=True, max_length=5000, null=True)),
                ('projectId', models.CharField(max_length=200, null=True)),
                ('name', models.CharField(max_length=200, null=True)),
                ('reference', models.CharField(blank=True, default='', max_length=200, null=True)),
                ('jurisdiction_doctype', models.CharField(blank=True, default='', max_length=100, null=True)),
                ('propertystate', models.CharField(blank=True, default='', max_length=100, null=True)),
                ('dateaddded_to_kwf', models.CharField(blank=True, default='', max_length=100, null=True)),
                ('datereceived', models.CharField(blank=True, default='', max_length=100, null=True)),
                ('dateimaged', models.CharField(blank=True, default='', max_length=100, null=True)),
                ('default', models.CharField(blank=True, default='', max_length=50, null=True)),
                ('neverkeyed', models.CharField(blank=True, default='', max_length=100, null=True)),
                ('erecordable', models.CharField(blank=True, default='', max_length=100, null=True)),
                ('keying_duedate', models.CharField(blank=True, default='', max_length=100, null=True)),
                ('shipping_datedue', models.CharField(blank=True, default='', max_length=100, null=True)),
                ('isthis_a_rush', models.CharField(blank=True, default='', max_length=100, null=True)),
                ('workflow', models.CharField(blank=True, default='', max_length=100, null=True)),
                ('allocated_date', models.CharField(blank=True, default='', max_length=100, null=True)),
                ('organization', models.CharField(blank=True, default='', max_length=100, null=True)),
                ('agent', models.CharField(blank=True, default='', max_length=100, null=True)),
                ('tl_name', models.CharField(blank=True, default='', max_length=100, null=True)),
                ('team_name', models.CharField(blank=True, default='', max_length=100, null=True)),
                ('upload_date', models.DateField(auto_now_add=True)),
                ('status', models.CharField(default='newtickets', max_length=15, null=True)),
                ('process_status', models.CharField(default='emty', max_length=15)),
                ('completed_date', models.DateField(blank=True, null=True)),
                ('date_created', models.DateTimeField(auto_now_add=True, null=True)),
                ('stop_time_ticket', models.DateTimeField(null=True)),
                ('start_time_ticket', models.DateTimeField(null=True)),
                ('sci_user', models.ForeignKey(blank=True, default=1, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='sci', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
