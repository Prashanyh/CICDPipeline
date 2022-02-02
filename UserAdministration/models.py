import django
from django.db import models

import django.utils.timezone
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import PermissionsMixin
from django.contrib.auth.base_user import AbstractBaseUser
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth.base_user import BaseUserManager

from rest_framework_simplejwt.tokens import RefreshToken
from django.core.validators import RegexValidator
import datetime,calendar
import uuid
class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        """
        Creates and saves a User with the given mobile and password.
        """
        if not email:
            raise ValueError('The given email must be set')
        # email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_staff', True)

        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(email, password, **extra_fields)

class Teams(models.Model):
    teamname = models.CharField(max_length=100,unique=True)
    team_description = models.CharField(max_length=1024)
    def __str__(self):
        return self.teamname


class UserProfile(AbstractBaseUser, PermissionsMixin):
    id=models.AutoField(primary_key=True)
    username = models.CharField(max_length=200, unique=True, null=True, blank=True)
    fullname = models.CharField(_('name'), max_length=200, blank=True, null=True)
    mobile = models.CharField(_('mobile'), unique=True, max_length=10, blank=True, null=True)
    email = models.EmailField(_('email address'), blank=True, null=True)
    password = models.CharField(_('password'),max_length=500,blank=True, null=True)
    date_joined = models.DateTimeField(verbose_name="date joined", auto_now_add=True)
    is_verified = models.BooleanField(default=True,null=True)
    is_active = models.BooleanField(_('active'), default=True,null=True)
    is_admin = models.BooleanField(_('is_Admin'), default=False, blank=True, null=True)
    is_manager = models.BooleanField(_('is_Manger'), default=False, blank=True, null=True)
    is_tl = models.BooleanField(_('is_Tl'), default=False, blank=True, null=True)
    is_agent = models.BooleanField(_('is_Agent'), default=False, blank=True, null=True)
    orginization = models.CharField(max_length=200, null=True, default=False)
    dob=models.DateField(default=False,null=True)
    GENDER_CHOICES = (
        ('Male', 'Male'),
        ('Female', 'Female'),
    )
    Roles = (
        ('Manager', 'Manager'),
        ('TL', 'TL'),
        ('Admin', 'Admin'),
        ('Agent', 'Agent'),
        ('SuperAdmin', 'SuperAdmin'),)

    gender = models.CharField(max_length=8, choices=GENDER_CHOICES, default=False)
    team_name = models.ForeignKey(Teams, on_delete=models.CASCADE, default=False, null=True, related_name='person_team')
    role = models.CharField(max_length=100, null=True, choices=Roles, default=False)
    objects =  UserManager()

    USERNAME_FIELD = 'username'  # User should be able to login with
    REQUIRED_FIELDS = []

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')

    def get_full_name(self):
        '''
        Returns the first_name plus the last_name, with a space in between.
        '''
        full_name = '%s %s' % (self.name)
        return full_name.strip()

    def get_short_name(self):
        '''
        Returns the short name for the user.
        '''
        return self.name

    def create_superuser(self, password, email):
        """
        Creates and saves a superuser with the given username and password.
        """
        user = self.create_user(
            email=email,
            password=password,
        )
        user.is_superuser = True
        user.is_staff = True
        user.save(using=self._db)
        return user

        # def create_superuser(self, email, date_of_birth, password):
        #     """
        #     Creates and saves a superuser with the given email, date of
        #     birth and password.
        #     """
        #     user = self.create_user(
        #         email=email,
        #         password=password,
        #     )
        #     user.is_superuser = True
        #     user.is_staff = True
        #     user.save(using=self._db)
        #     return user
        # user.is_admin = True
        # user.save(using=self._db)
        # return user

    def __str__(self):
        return self.email

        # def __str__(self):
        #     return str(self.mobile) + ' is sent ' + str(self.otp)

    def refresh(self):
        refresh = RefreshToken.for_user(self)
        return  str(refresh)

    def access(self):
        refresh = RefreshToken.for_user(self)
        return str(refresh.access_token)
        

class Sci1stKey(models.Model):
    sci_user = models.ForeignKey(UserProfile, related_name='sci', on_delete=models.CASCADE, default=1, blank=True,
                                 null=True)
    projectId = models.CharField(max_length=200, null=True,blank=True)
    name = models.CharField(max_length=200, null=True,blank=True)
    reference = models.CharField(max_length=200,  null=True, blank=True)
    jurisdiction_doctype = models.CharField(max_length=100, default="", null=True, blank=True)
    propertystate = models.CharField(max_length=100, default="", null=True, blank=True)
    dateaddded_to_kwf = models.CharField(max_length=100, default="", null=True, blank=True)
    datereceived = models.CharField(max_length=100, default="", null=True, blank=True)
    dateimaged = models.CharField(max_length=100, default="", null=True, blank=True)
    default = models.CharField(max_length=50, default="", null=True, blank=True)
    neverkeyed = models.CharField(max_length=100, default="", null=True, blank=True)
    erecordable = models.CharField(max_length=100, default="", null=True, blank=True)
    keying_duedate = models.CharField(max_length=100, default="", null=True, blank=True)
    shipping_datedue = models.CharField(max_length=100, default="", null=True, blank=True)
    isthis_a_rush = models.CharField(max_length=100, default="", null=True, blank=True)
    workflow = models.CharField(max_length=100, default="", null=True, blank=True)
    allocated_date = models.CharField(max_length=100, default="", null=True, blank=True)
    organization = models.CharField(max_length=100, default="", null=True, blank=True)
    agent = models.CharField(max_length=100, null=True, blank=True)
    tl_name = models.CharField(max_length=100, default="", null=True, blank=True)
    team_name = models.CharField(max_length=100,  null=True,blank=True)
    upload_date = models.DateField(auto_now_add=True)
    status = models.CharField(max_length=15, default='newtickets',null=True,blank=True)
    process_status = models.CharField(max_length=15, default='emty')
    completed_date = models.DateField(null=True, blank=True)
    date_created = models.DateTimeField(auto_now_add=True, null=True)
    stop_time_ticket = models.DateTimeField(null=True)
    start_time_ticket = models.DateTimeField(null=True)


    def __str__(self):
        return f"{self.agent},{self.status}"



class AllLogin(models.Model):
    user = models.ForeignKey(UserProfile,on_delete= models.CASCADE)
    login_date = models.DateField(null=True) # user login date store with custom date field
    login_time = models.TimeField(auto_now_add=True) # user login time stores this time will be generating automatically once login into the user page


    def __str__(self):
        return str(self.user) + ': ' + str(self.login_time)


class AllLogout(models.Model):
    user = models.ForeignKey(UserProfile,on_delete= models.CASCADE)
    logout_date = models.DateField(null=True) # user login date storing with cutom date field
    logout_time = models.TimeField(auto_now_add=True, null=True) # user logout time stores this time will be generating automatically once login into the user page

    def __str__(self):
        return str(self.user) + ': ' + str(self.logout_time)
