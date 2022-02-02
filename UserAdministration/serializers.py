import csv
import re

from django.contrib import auth
from django.contrib.auth import login
from django.contrib.auth.password_validation import validate_password
from django.http import HttpResponse, JsonResponse, request
from django.utils import timezone
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str,force_str,smart_bytes,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from UserAdministration.models import *
from django.contrib.auth import authenticate
from django.utils.text import gettext_lazy as _
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
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
    password = serializers.CharField(write_only=True,max_length=500)
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
import datetime
from django.http import HttpResponse

class LoginSerializer(serializers.ModelSerializer):
    '''
    Login user serializer with required fields
    '''
    Roles = (
        ('Manager', 'Manager'),
        ('TL', 'TL'),
        ('Admin', 'Admin'),
        ('Agent', 'Agent'),)

    username=serializers.CharField()
    password=serializers.CharField(max_length=10,min_length=6,write_only=True)
    fullname=serializers.CharField(max_length=255,min_length=3,read_only=True)
    refresh=serializers.CharField(max_length=135,min_length=6,read_only=True)
    access=serializers.CharField(max_length=135,min_length=6,read_only=True)
    role = models.CharField( choices=Roles)

    class Meta:
        # model name
        model= UserProfile
        # required fields
        fields=['username','password','fullname','access','refresh','role','id']


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
            'role':user.role,
            'refresh':user.refresh,
            'access':user.access,
            'id': user.id
        }
        


# prashanth
## password 
class ResetPasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)
    """
    This serializer is used for password reset api eg: end user will enter his mail id
    """

    class Meta:
        model = UserProfile
        fields = ['email']


## create new password
class SetNewPasswordSerializer(serializers.Serializer):
    # required fields 
    password = serializers.CharField(max_length=70,write_only=True)
    token = serializers.CharField(min_length=2,write_only=True)
    uidb64 = serializers.CharField(min_length=2,write_only=True)

    class Meta:
        # model
        model = UserProfile
        fields = ('password','token','uidb64')

    def validate(self,attrs):
        try:
            # validating attributes and verifying email
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64= attrs.get('uidb64')
            id =force_str(urlsafe_base64_decode(uidb64))
            user = UserProfile.objects.get(id=id)
            user.set_password(password)
            user.save()
            # saving new password

            return (user)
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid')
        return super().validate(attrs)
        


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


class PersonUploadSerializer(serializers.Serializer):
    file = serializers.FileField()


##prasanth
class SavePersonFileSerializer(serializers.Serializer):
    class Meta:
        model = UserProfile
        fields = "__all__"

##prasanth
class ScikeyAssignSerializer(serializers.ModelSerializer):
    '''
    sci key agent change the ticket status serializer
    '''
    status = serializers.CharField()
    class Meta:
        model = Sci1stKey
        fields = ['status']

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
class DateTimeFieldWihTZ(serializers.DateTimeField):
    '''Class to make output of a DateTime Field timezone aware
    '''
    def to_representation(self, value):
        value = timezone.localtime(value)
        return super(DateTimeFieldWihTZ, self).to_representation(value)

class AgentRetriveSerializer(serializers.ModelSerializer):
    # stop_time_ticket = serializers.DateTimeField(input_formats=datetime.datetime.now())
    '''
    agent update status of scikey serializer
    '''
    class Meta:
        # model name
        model = Sci1stKey
        # required fields
        fields = ['id','process_status','status','stop_time_ticket','completed_date']
    stop_time_ticket = DateTimeFieldWihTZ(format='%Y-%m-%d %H:%M')
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


from UserAdministration.models import UserProfile


#prashanth
class Assigntickets_listSerializer(serializers.ModelSerializer):
    # Roles = (
    #     ('Manager', 'Manager'),
    #     ('TL', 'TL'),
    #     ('Admin', 'Admin'),
    #     ('Agent', 'Agent'),)
    # # name = serializers.SlugRelatedField(many=False, slug_field='name', queryset=UserProfile.objects.all())
    # role = serializers.ChoiceField(choices=Roles)
    class Meta:
        model = UserProfile
        # get model name
        fields = '__all__'

# prashanth
class ReAssigntickets_listSerializer(serializers.ModelSerializer):
    # category_name = serializers.RelatedField(source='sci_user.agent', read_only=True)
    class Meta:
        model = Sci1stKey
        # get model name
        fields = "__all__"



from rest_framework import serializers


class DemoUserSerializer(serializers.ModelSerializer):
    # role = serializers.ChoicesField(choices=UserProfile.role)

    class Meta:
        model = UserProfile
        fields = ['id']


# prashanth
#admin teamwise status count
class AdminTeamwiseTicketListAPIViewSerializer(serializers.ModelSerializer):
    '''
    sci all tickets serializer use this serializer all users
    
    '''
    count = serializers.IntegerField()
    class Meta:
        # model name
        model = Sci1stKey
        # required fields
        fields = ['upload_date', 'team_name','count']
        # fields = '__all__'

# prashanth
# admin teamwise closed tickets serializer
class AdminTeamwiseClosedTicketListAPIViewSerializer(serializers.ModelSerializer):
    '''
    sci all tickets serializer use this serializer all users
    
    '''
    count = serializers.IntegerField()
    class Meta:
        # model name
        model = Sci1stKey
        # required fields
        fields = ['completed_date', 'team_name','status','count']
        # fields = '__all__'

## prashanth
#admin teamwise status count
class AdminAgentwiseTicketListAPIViewSerializer(serializers.ModelSerializer):
    '''
    sci all tickets serializer use this serializer all users
    
    '''
    count = serializers.IntegerField()
    class Meta:
        # model name
        model = Sci1stKey
        # required fields
        fields = ['upload_date', 'agent','count']
        # fields = '__all__'

## prashanth
# admin agentwise closed tickets serializer
class AdminAgentwiseClosedTicketListAPIViewSerializer(serializers.ModelSerializer):
    '''
    sci all tickets serializer use this serializer all users
    
    '''
    count = serializers.IntegerField()
    class Meta:
        # model name
        model = Sci1stKey
        # required fields
        fields = ['completed_date', 'agent','status','count']
        # fields = '__all__'

## prashanth
# admin agentwise assign tickets serializer
class AdminAgentwiseNewAssignTicketListAPIViewSerializer(serializers.ModelSerializer):
    '''
    sci all tickets serializer use this serializer all users
    
    '''
    count = serializers.IntegerField()
    class Meta:
        # model name
        model = Sci1stKey
        # required fields
        fields = ['upload_date','count']
        # fields = '__all__'

class AdminAgentwiseClosedTicketListCountAPIViewSerializer(serializers.ModelSerializer):
    '''
    sci all tickets serializer use this serializer all users
    
    '''
    count = serializers.IntegerField()
    class Meta:
        # model name
        model = Sci1stKey
        # required fields
        fields = ['completed_date','count']
        # fields = '__all__'

class AdminAgentwiseClosedTicketListCountSerializer(serializers.ModelSerializer):
    '''
    sci all tickets serializer use this serializer all users
    
    '''
    count = serializers.IntegerField()
    class Meta:
        # model name
        model = Sci1stKey
        # required fields
        fields = ['completed_date','count']
#
# class AdminAgentwiseClosedTicketListAPIViewSerializer(serializers.ModelSerializer):
#     '''
#     sci all tickets serializer use this serializer all users
#
#     '''
#     count = serializers.IntegerField()
#     class Meta:
#         # model name
#         model = Sci1stKey
#         # required fields
#         fields = ['upload_date','count']


 ###admin (agent team date wise count
 ##prashanth
class AdminProcessCountTicketListSerializer(serializers.ModelSerializer):
    process_status__count = serializers.IntegerField()
    '''
    sci all tickets serializer use this serializer all users
    '''
    class Meta:
        # model name
        model = Sci1stKey
        # required fields
        fields = ('agent','completed_date','process_status__count')



class TicketreassignAgentsCompleteSerializer(serializers.Serializer):
    agent = serializers.CharField(required=True)
    id = serializers.IntegerField()
    """
    This serializer is used for password reset api eg: end user will enter his mail id
    """

    class Meta:
        model = Sci1stKey
        fields = ['agent','id']


class TlReassignAgentsSerializer(serializers.ModelSerializer):
    '''
    sci all tickets serializer use this serializer all users
    '''
    class Meta:
        # model name
        model = UserProfile
        # required fields
        fields = ['fullname']


'''****************************************************************************************************'''

##theja
from django.contrib.auth.hashers import make_password


class UserProfileSerializer(serializers.ModelSerializer):
    team_name = serializers.SlugRelatedField(queryset=Teams.objects.all(),slug_field='teamname')

    '''
    User Profile data serializer
    '''
    class Meta:
        # model name
        model = UserProfile
        # fields = ("name", "email", "mobile")
        # required fields
        fields = ("id","fullname", "email", "mobile", "dob", "gender", "role", "team_name","is_admin","is_manager","is_tl","is_agent")



class TeamNameListSerializer(serializers.ModelSerializer):
    '''
    get all team serializer
    '''
    class Meta:
        # model name
        model = Teams
        # all fields
        fields = ['teamname']

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

class ChangePasswordSerializer(serializers.Serializer):
    model = UserProfile

    """
    Serializer for password change endpoint.
    """
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)


#######changing password
##theja
class ChangePasswordSerializers(serializers.Serializer):
    class Meta:
        model = UserProfile
        fields = ('old_password', 'password', 'confirm_password')

    """
    Serializer for password change endpoint.
    """
    old_password = serializers.CharField(required=True)
    password = serializers.CharField(required=True)
    confirm_password = serializers.CharField(required=True)

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"password": "newPassword  and confirm password didn't match."})
        return attrs

    # def validate_old_password(self, value):
    #     user = self.context['request'].user
    #     if not user.check_password(value):
    #         raise serializers.ValidationError({"old_password": "Old password is not correct"})
    #     return value



##updating his own profile
##theja
class Update_his_profile_Serializer(serializers.ModelSerializer):
    team_name = serializers.SlugRelatedField(queryset=Teams.objects.all(),slug_field='teamname')
    '''
    Update user profile serializer with required fields
    '''

    class Meta:
        # get model name
        model = UserProfile
        # required fields which we have to update
        fields = ('username', 'fullname', 'email', 'mobile', 'role', 'team_name', 'gender', 'dob')

##tl team wise all tickets
###theja
class TlwiseTeamAllTicketsSerializer(serializers.ModelSerializer):
    '''
    sci all tickets serializer use this serializer all users
    '''
    class Meta:
        # model name
        model = Sci1stKey
        # required fields
        fields = '__all__'



class AllTlReAssignTicketsListSerializer(serializers.ModelSerializer):
    '''
    sci all tickets serializer use this serializer all users
    '''
    class Meta:
        # model name
        model = Sci1stKey
        # required fields
        fields = '__all__'



 ###tl team date wise count
 ##theja
class TlwiseTeamdateTicketsSerializer(serializers.ModelSerializer):
    status__count = serializers.IntegerField()
    '''
    sci all tickets serializer use this serializer all users
    '''
    class Meta:
        # model name
        model = Sci1stKey
        # required fields
        fields = ('agent','upload_date','status__count','completed_date')


class RefreshTokenSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    '''field for entering the refresh token'''
    default_error_messages = {
        'bad_token': _('Token is invalid or expired')
    }
    '''if token is expired or invalid it will raise this exception message'''
    def validate(self, attrs):
        self.token = attrs['refresh']
        '''validateing the given token and returning'''
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
            '''getting the token and put in the blacklist'''
        except TokenError:
            self.fail('bad_token')



class RetriveTablesSerializer(serializers.Serializer):
    class Meta:
        fields = '__all__'