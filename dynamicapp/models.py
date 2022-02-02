# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#   * Rearrange models' order
#   * Make sure each model has one field with primary_key=True
#   * Make sure each ForeignKey and OneToOneField has `on_delete` set to the desired behavior
#   * Remove `managed = False` lines if you wish to allow Django to create, modify, and delete the table
# Feel free to rename the models, but don't rename db_table values or field names.
from django.db import models


class UseradministrationAlllogin(models.Model):
    id = models.BigAutoField(primary_key=True)
    login_date = models.DateField(blank=True, null=True)
    login_time = models.TimeField()
    user = models.ForeignKey('UseradministrationUserprofile', models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'UserAdministration_alllogin'


class UseradministrationAlllogout(models.Model):
    id = models.BigAutoField(primary_key=True)
    logout_date = models.DateField(blank=True, null=True)
    logout_time = models.TimeField(blank=True, null=True)
    user = models.ForeignKey('UseradministrationUserprofile', models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'UserAdministration_alllogout'


class UseradministrationSci1Stkey(models.Model):
    id = models.BigAutoField(primary_key=True)
    projectid = models.CharField(db_column='projectId', max_length=200, blank=True, null=True)  # Field name made lowercase.
    name = models.CharField(max_length=200, blank=True, null=True)
    reference = models.CharField(max_length=200, blank=True, null=True)
    jurisdiction_doctype = models.CharField(max_length=100, blank=True, null=True)
    propertystate = models.CharField(max_length=100, blank=True, null=True)
    dateaddded_to_kwf = models.CharField(max_length=100, blank=True, null=True)
    datereceived = models.CharField(max_length=100, blank=True, null=True)
    dateimaged = models.CharField(max_length=100, blank=True, null=True)
    default = models.CharField(max_length=50, blank=True, null=True)
    neverkeyed = models.CharField(max_length=100, blank=True, null=True)
    erecordable = models.CharField(max_length=100, blank=True, null=True)
    keying_duedate = models.CharField(max_length=100, blank=True, null=True)
    shipping_datedue = models.CharField(max_length=100, blank=True, null=True)
    isthis_a_rush = models.CharField(max_length=100, blank=True, null=True)
    workflow = models.CharField(max_length=100, blank=True, null=True)
    allocated_date = models.CharField(max_length=100, blank=True, null=True)
    organization = models.CharField(max_length=100, blank=True, null=True)
    agent = models.CharField(max_length=100, blank=True, null=True)
    tl_name = models.CharField(max_length=100, blank=True, null=True)
    team_name = models.CharField(max_length=100, blank=True, null=True)
    upload_date = models.DateField()
    status = models.CharField(max_length=15, blank=True, null=True)
    process_status = models.CharField(max_length=15)
    completed_date = models.DateField(blank=True, null=True)
    date_created = models.DateTimeField(blank=True, null=True)
    stop_time_ticket = models.DateTimeField(blank=True, null=True)
    start_time_ticket = models.DateTimeField(blank=True, null=True)
    sci_user = models.ForeignKey('UseradministrationUserprofile', models.DO_NOTHING, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'UserAdministration_sci1stkey'


class UseradministrationTeams(models.Model):
    id = models.BigAutoField(primary_key=True)
    teamname = models.CharField(unique=True, max_length=100)
    team_description = models.CharField(max_length=1024)

    class Meta:
        managed = False
        db_table = 'UserAdministration_teams'


class UseradministrationUserprofile(models.Model):
    last_login = models.DateTimeField(blank=True, null=True)
    is_superuser = models.BooleanField()
    username = models.CharField(unique=True, max_length=200, blank=True, null=True)
    fullname = models.CharField(max_length=200, blank=True, null=True)
    mobile = models.CharField(unique=True, max_length=10, blank=True, null=True)
    email = models.CharField(max_length=254, blank=True, null=True)
    password = models.CharField(max_length=500, blank=True, null=True)
    date_joined = models.DateTimeField()
    is_verified = models.BooleanField(blank=True, null=True)
    is_active = models.BooleanField(blank=True, null=True)
    is_admin = models.BooleanField(blank=True, null=True)
    is_manager = models.BooleanField(blank=True, null=True)
    is_tl = models.BooleanField(blank=True, null=True)
    is_agent = models.BooleanField(blank=True, null=True)
    orginization = models.CharField(max_length=200, blank=True, null=True)
    dob = models.DateField(blank=True, null=True)
    gender = models.CharField(max_length=8)
    role = models.CharField(max_length=100, blank=True, null=True)
    team_name = models.ForeignKey(UseradministrationTeams, models.DO_NOTHING, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'UserAdministration_userprofile'


class UseradministrationUserprofileGroups(models.Model):
    id = models.BigAutoField(primary_key=True)
    userprofile = models.ForeignKey(UseradministrationUserprofile, models.DO_NOTHING)
    group = models.ForeignKey('AuthGroup', models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'UserAdministration_userprofile_groups'
        unique_together = (('userprofile', 'group'),)


class UseradministrationUserprofileUserPermissions(models.Model):
    id = models.BigAutoField(primary_key=True)
    userprofile = models.ForeignKey(UseradministrationUserprofile, models.DO_NOTHING)
    permission = models.ForeignKey('AuthPermission', models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'UserAdministration_userprofile_user_permissions'
        unique_together = (('userprofile', 'permission'),)


class AuthGroup(models.Model):
    name = models.CharField(unique=True, max_length=150)

    class Meta:
        managed = False
        db_table = 'auth_group'


class AuthGroupPermissions(models.Model):
    id = models.BigAutoField(primary_key=True)
    group = models.ForeignKey(AuthGroup, models.DO_NOTHING)
    permission = models.ForeignKey('AuthPermission', models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'auth_group_permissions'
        unique_together = (('group', 'permission'),)


class AuthPermission(models.Model):
    name = models.CharField(max_length=255)
    content_type = models.ForeignKey('DjangoContentType', models.DO_NOTHING)
    codename = models.CharField(max_length=100)

    class Meta:
        managed = False
        db_table = 'auth_permission'
        unique_together = (('content_type', 'codename'),)


class AuthtokenToken(models.Model):
    key = models.CharField(primary_key=True, max_length=40)
    created = models.DateTimeField()
    user = models.OneToOneField(UseradministrationUserprofile, models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'authtoken_token'


class DjangoAdminLog(models.Model):
    action_time = models.DateTimeField()
    object_id = models.TextField(blank=True, null=True)
    object_repr = models.CharField(max_length=200)
    action_flag = models.SmallIntegerField()
    change_message = models.TextField()
    content_type = models.ForeignKey('DjangoContentType', models.DO_NOTHING, blank=True, null=True)
    user = models.ForeignKey(UseradministrationUserprofile, models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'django_admin_log'


class DjangoContentType(models.Model):
    app_label = models.CharField(max_length=100)
    model = models.CharField(max_length=100)

    class Meta:
        managed = False
        db_table = 'django_content_type'
        unique_together = (('app_label', 'model'),)


class DjangoMigrations(models.Model):
    id = models.BigAutoField(primary_key=True)
    app = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    applied = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'django_migrations'


class DjangoSession(models.Model):
    session_key = models.CharField(primary_key=True, max_length=40)
    session_data = models.TextField()
    expire_date = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'django_session'


class Testing6(models.Model):
    user_id = models.AutoField(primary_key=True)
    username = models.CharField(unique=True, max_length=50)
    password = models.CharField(max_length=50)

    class Meta:
        managed = False
        db_table = 'testing6'


class Testing7(models.Model):
    user_id = models.AutoField(primary_key=True)
    username = models.CharField(unique=True, max_length=50)
    password = models.CharField(max_length=50)

    class Meta:
        managed = False
        db_table = 'testing7'


class Testing8(models.Model):
    user_id = models.AutoField(primary_key=True)
    username = models.CharField(unique=True, max_length=50)
    password = models.CharField(max_length=50)
    email = models.CharField(unique=True, max_length=255)
    created_on = models.DateTimeField()
    last_login = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'testing8'


class Testing9(models.Model):
    user_id = models.AutoField(primary_key=True)
    username = models.CharField(unique=True, max_length=50)
    password = models.CharField(max_length=50)

    class Meta:
        managed = False
        db_table = 'testing9'


class TokenBlacklistBlacklistedtoken(models.Model):
    id = models.BigAutoField(primary_key=True)
    blacklisted_at = models.DateTimeField()
    token = models.OneToOneField('TokenBlacklistOutstandingtoken', models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'token_blacklist_blacklistedtoken'


class TokenBlacklistOutstandingtoken(models.Model):
    id = models.BigAutoField(primary_key=True)
    token = models.TextField()
    created_at = models.DateTimeField(blank=True, null=True)
    expires_at = models.DateTimeField()
    user = models.ForeignKey(UseradministrationUserprofile, models.DO_NOTHING, blank=True, null=True)
    jti = models.CharField(unique=True, max_length=255)

    class Meta:
        managed = False
        db_table = 'token_blacklist_outstandingtoken'
