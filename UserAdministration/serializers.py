import csv

from django.contrib.auth.password_validation import validate_password
from django.http import request, HttpResponse, JsonResponse
from django.contrib.auth import login
from django.http import HttpResponse
from rest_framework import serializers
from .models import *
import re
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed

# def isValid(s):
#      if not re.compile("(0|91)?[7-9][0-9]{9}").match(s):
#         raise serializers.ValidationError({"Mobile": "Please Check Mobile Number"}
#         )
    # 1) Begins with 0 or 91
    # 2) Then contains 7 or 8 or 9.
    # 3) Then contains 9 digits

##prasanth
class UserSerializer(serializers.ModelSerializer):
    """
    user register serializer and required fields
    """
    # mobile = serializers.RegexField("[0-9]{10}",min_length=10,max_length=10)
    mobile = serializers.CharField()
    password = serializers.CharField(write_only=True)
    email=serializers.EmailField(max_length=155,min_length=3,required=True)
    fullname=serializers.CharField(max_length=55,min_length=3,required=True)

    class Meta:
        # get the model name
        model = UserProfile
        #required fields
        fields = ("id","username","fullname", "email", "password", "mobile","dob","gender","role","team_name","orginization","is_admin","is_manager","is_tl","is_agent")
        # fields="__all__"


    def create(self, validated_data):
        user = super(UserSerializer, self).create(validated_data)
        user.set_password(validated_data['password'])
        user.save()
        return user

##prasanth
class EmailVerificationSerializer(serializers.ModelSerializer):
    token=serializers.CharField(max_length=555)

    class Meta:
        model= UserProfile
        fields=['token']

##prasanth
class LoginSerializer(serializers.ModelSerializer):
    '''
    Login user serializer with required fields
    '''
    username=serializers.CharField()
    password=serializers.CharField(max_length=10,min_length=6,write_only=True)
    fullname=serializers.CharField(max_length=255,min_length=3,read_only=True)
    tokens=serializers.CharField(max_length=135,min_length=6,read_only=True)

    class Meta:
        # model name
        model= UserProfile
        # required fields
        fields=['username','password','fullname','tokens']


    def validate(self, attrs):
        username = attrs.get('username', '')
        password = attrs.get('password', '')
        user = auth.authenticate(username=username,password=password)

        if not user:
            raise AuthenticationFailed('Invalid credentials, try again')
        if not user.is_active:
            raise AuthenticationFailed('Account disabled , contact admin')
        if not user.is_verified:
            raise AuthenticationFailed('user is not verified')
        return {
            'username':user.username,
            'fullname':user.fullname,
            'role':user.role,
            'tokens':user.tokens
        }

##theja
from django.contrib.auth.hashers import make_password

class UserProfileSerializer(serializers.ModelSerializer):
    '''
    User Profile data serializer
    '''
    class Meta:
        # model name
        model = UserProfile
        # fields = ("name", "email", "mobile")
        # required fields
        fields = ("fullname", "email", "mobile", "dob", "gender", "role", "team_name")

###theja
class Teamserialsers(serializers.ModelSerializer):
    '''
    get all team serializer
    '''
    team_by_persons = UserSerializer(read_only=True,many=True)
    class Meta:
        # model name
        model = Teams
        # all fields
        fields = '__all__'

##prasanth
class FileSerializer(serializers.ModelSerializer):
  class Meta:
    model = Sci1stKey
    fields = ['file']


##prasanth
class ScikeylistSerializer(serializers.ModelSerializer):
    '''
    get the all ticket list serializer
    '''
    class Meta:
        # model name
        model = Sci1stKey
        # required fields
        fields = '__all__'
#     #     fields = ('projectId', 'name' ,'reference', 'jurisdiction_doctype', 'propertystate', 'dateaddded_to_kwf',
#     # 'datereceived', 'dateimaged', 'default', 'neverkeyed', 'erecordable',  'keying_duedate',  'shipping_datedue',
#     # 'isthis_a_rush', 'workflow', 'allocated_date', 'organization', 'agent', 'tl_name', 'team_name', 'upload_date',
#     # 'status')
class FileUploadSerializer(serializers.Serializer):
    '''
    sci key file upload serializer
    '''
    file = serializers.FileField()

##prasanth
class SaveFileSerializer(serializers.Serializer):
    '''sci key upload serializer'''
    class Meta:
        # model name
        model = Sci1stKey
        # required fields
        fields = "__all__"

##prasanth
class ScikeyAssignSerializer(serializers.ModelSerializer):
    '''
    sci key agent change the ticket status serializer
    '''
    status = serializers.CharField()
    class Meta:
        model = Sci1stKey
        fields = ('status')

##prasanth
class AgentOwnTicketsSerializer(serializers.ModelSerializer):
    '''
    sci all tickets serializer use this serializer all users
    '''
    class Meta:
        # model name
        model = Sci1stKey
        # required fields
        fields = '__all__'


##prasanth
class AgentRetriveSerializer(serializers.ModelSerializer):
    '''
    agent update status of scikey serializer
    '''
    class Meta:
        # model name
        model = Sci1stKey
        # required fields
        fields = ['id','process_status','status','stop_time_ticket']
        # fields = '__all__'
    # def update(self, instance, validated_data):
    #     qs = Sci1stKey.objects.filter(id=id)
    #     for x in qs:
    #         x.save()
    #         qs.update(process_status=tickets, status='closed')



##prasanth
class ScikeyTicketsListSerializer(serializers.ModelSerializer):
    '''
    sci all ticekt list serializer
    '''
    class Meta:
        # model name
        model = Sci1stKey
        # required fields
        fields = '__all__'


##prasanth
class ScikeyPendingTicketsListSerializer(serializers.ModelSerializer):
    '''
    This serializer using for all tickets in pending api view
    '''
    class Meta:
        model = Sci1stKey
        fields = '__all__'


##theja
class ChangePasswordSerializers(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    " importing the validate_password from from django.contrib.auth.password_validation import validate_password "
    confirm_password = serializers.CharField(write_only=True, required=True)
    old_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = UserProfile
        fields = ('old_password', 'password', 'confirm_password')

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})

        return attrs

    def validate_old_password(self, value):
        user = self.context['request'].user

        if not user.check_password(value):
            raise serializers.ValidationError({"old_password": "Old password is not correct"})
        return value

    def update(self, instance, validated_data):
        user = self.context['request'].user

        if user.pk != instance.pk:
            raise serializers.ValidationError({"authorize": "You dont have permission for this user."})

        instance.set_password(validated_data['password'])
        instance.save()

        return instance

##updating his own profile
##theja
class Update_his_profile_Serializer(serializers.ModelSerializer):
    '''
    Update user profile serializer with required fields
    '''
    email = serializers.EmailField(required=True)

    class Meta:
        # get model name
        model = UserProfile
        # required fields
        fields = ('username', 'fullname', 'email', 'mobile', 'role', 'team_name', 'gender', 'dob')

    def validate_email(self, value):
        user = self.context['request'].user
        if UserProfile.objects.exclude(pk=user.pk).filter(email=value).exists():
            'checking the update email with all emails in db'
            raise serializers.ValidationError({"email": "This email is already in use."})
        return value

    def validate_username(self, value):
        user = self.context['request'].user
        if UserProfile.objects.exclude(pk=user.pk).filter(username=value).exists():
            raise serializers.ValidationError({"username": "This username is already in use."})
        return value

    def update(self, instance, validated_data):
        user = self.context['request'].user

        if user.pk != instance.pk:
            raise serializers.ValidationError({"authorize": "You dont have permission for this user."})

        instance.username = validated_data['username']
        instance.fullname = validated_data['fullname']
        instance.email = validated_data['email']
        instance.mobile = validated_data['mobile']
        instance.role = validated_data['role']
        instance.team_name = validated_data['team_name']
        instance.gender = validated_data['gender']
        instance.dob = validated_data['dob']


        instance.save()

        return instance

class Assigntickets_listSerializer(serializers.ModelSerializer):
    # name = serializers.SlugRelatedField(many=False, slug_field='name', queryset=UserProfile.objects.all())

    class Meta:
        model = UserProfile
        # get model name
        fields = '__all__'





from rest_framework import serializers

class UserSerializer(serializers.ModelSerializer):
    # role = serializers.ChoicesField(choices=UserProfile.role)

    class Meta:
        model = UserProfile
        fields = ['role']