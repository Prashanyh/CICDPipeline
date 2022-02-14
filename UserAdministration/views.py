from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import render
from django.db.models.functions import Lower
from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import ValidationError
from rest_framework.generics import get_object_or_404
from rest_framework.parsers import JSONParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status, views, response
from rest_framework import generics, mixins
from rest_framework.views import APIView
from tablib import Dataset
from django.db.models import Count
from django.contrib.auth.hashers import make_password
from .serializers import *
import json
from datetime import timedelta, date
from django.utils import timezone
from rest_framework import permissions
from UserAdministration.manager_permissions import IsManagerPermission
from UserAdministration.admin_permissions import IsAdminPermission
from UserAdministration.tl_permissions import IsTlPermission
from UserAdministration.super_admin_permission import IsSuperAdminPermission
from UserAdministration.agent_permissions import IsAgentPermission
from django.utils.six import python_2_unicode_compatible
from .utils import Util
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from six import python_2_unicode_compatible
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
import jwt
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from rest_framework.response import Response
from rest_framework import viewsets
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken

import string
import random

from django.shortcuts import render
from django.db import connection
from django.apps import apps
from django.core.management import call_command
from django.core import management
from dynamicapp.models import *

from .agent_permissions import *

import datetime
# from django.db.models import Count
# from datetime import datetime, timedelta
from rest_framework import authentication, permissions
from UserAdministration.agent_permissions import *
from django.db.models import F, ExpressionWrapper, DecimalField
from django.db.models import F, Sum, FloatField, Avg
import datetime
from datetime import timedelta
import pandas as pd
from datetime import timedelta

from rest_framework.permissions import IsAuthenticated
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
import openpyxl
import pandas as pd
# initializing size of string
N = 7

# using random.choices()
# generating random strings
res = ''.join(random.choices(string.ascii_uppercase +
                             string.digits, k=N))

"**********************************************Prasanth**************************************************************************"


##prasanth
# user Registration
class RegisterApi(generics.GenericAPIView):
    # fetching serializer data
    serializer_class = UserSerializer
    # adding authentications & auth user with role
    authentication_classes = []

    # post method for user registration
    def post(self, request, *args, **kwargs):
        '''
        This function is used for post data into database of particuar model and
            method is POST this method is used for only post the data and this function
            contating serializer data fetching serializer data and register  user with details
        '''
        parameters = request.data.copy()
        serializer = self.get_serializer(data=parameters)
        # validating serializer
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"message": "User Created Successfully.  Now perform Login to get your token"},
                            status=status.HTTP_201_CREATED)
        else:
            return Response({'user name already exist'}, status=status.HTTP_406_NOT_ACCEPTABLE)


##prasanth
# user Login
class LoginAPIView(generics.GenericAPIView):
    # adding authentications & auth user with role
    # fetching serializer data
    serializer_class = LoginSerializer

    def post(self, request):
        '''
        getting serializer data and checking validating data sending data
        into the responce body with status code
        '''
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        # if serializer.is_valid():
        user = serializer.data
        userid = (user['id'])
        '''from the login serializer getting the user id'''
        m = datetime.date.today()
        '''getting the today date'''
        # getting_ids = AllLogin.objects.filter(user_id=userid, login_date=m)
        # '''filtering the userid and login date'''
        # for x in getting_ids:
        #     '''looping the userid and login date'''
        #     if x.login_date == datetime.date.today():
        #         '''checking the condition login date and today date is equal breaking the condition
        #         and return the response'''
        #         break
        # else:
        user = serializer.data
        userid = (user['id'])
        '''from the login serializer getting the user id'''
        getting_ids = AllLogin(user_id=userid, login_date=m)
        '''if the date is not today it will create the record'''
        getting_ids.save()
        '''returning the serializer data'''
        return Response(serializer.data, status=status.HTTP_200_OK)


## prashanth
# email send and verify mail
class RequestPasswordResetEmail(generics.GenericAPIView):
    # fetching serializer data
    serializer_class = ResetPasswordResetSerializer

    def post(self, request):
        try:
            """
            this class is get the data from end user (end user enter mail id)
            verifying the mail in db and mail is available in db generate the token 
            with uid (uid is same for each mail) every time token is changing
            once mail is availble in db one link will send to end user mail with token and uid with 
            current site url if end user click the link it will verify user credentials valid or not
            """
            serializer = self.serializer_class(data=request.data)
            # get the request data from end user
            email = request.data['email']
            if UserProfile.objects.filter(email=email):
                user = UserProfile.objects.get(email=email)
                uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
                token = PasswordResetTokenGenerator().make_token(user)
                current_site = get_current_site(request=request).domain
                relativeLink = reverse('password_reset_confirm', kwargs={'uidb64': uidb64, 'token': token})
                absurl = 'http://' + current_site + relativeLink
                email_body = 'Hey Use link below to verify your password  ' + absurl
                # 'Hey Use link below to verify your password' + absurl
                data = {'email_body': email_body, 'to_email': user.email, 'email_subject': 'verify your email'}
                Util.send_email(data)
            return Response({'we have sent you a link to reset your password'}, status=status.HTTP_200_OK)
        except Exception:
            "if any exception thant enter into exception block"
            return Response({'message': 'please enter valid email id'}, status=status.HTTP_404_NOT_FOUND)


## prashanth
## check the token of api(gmail)
class PasswordTokenCheckApiView(generics.GenericAPIView):
    """
    this class is contating end user received link verify mail he will clink the site link it
    will render to this page and validating credentials and sending current site link
    """

    def get(self, request, uidb64, token):
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = UserProfile.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is invalid please request a new token'},
                                status=status.HTTP_401_UNAUTHORIZED)
            return Response({'sucess': True, 'message': 'valid credentials', 'uidb64': uidb64, 'token': token},
                            status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError as identifier:
            if not PasswordResetTokenGenerator().check_token(user):
                return Response({'error': 'Token is not valid please request a new  one'})


## prashanth
## creating new password
class SetNewPasswordApiView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer
    """
    This class is used for once verifying the token he can create new password this 
    class is verifying token and uid in serializers with requested params
    """

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'status': True, 'message': 'password reset sucess'}, status=status.HTTP_200_OK)


##prasanth
class UploadFileView(APIView):
    permission_classes = [IsAuthenticated, IsSuperAdminPermission | IsAdminPermission]
    # fetching Serializer data (file upload serializer)
    serializer_class = FileUploadSerializer

    def post(self, request, *args, **kwargs):
        '''
        This function is used for post data into database of particuar model and
            method is POST this method is used for only post the data and this function
            contating serializer data fetching serializer data and
            validating data and loading into the data with the file format
        '''
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        dataset = Dataset()
        # fetching file
        file = serializer.validated_data['file']
        try:
            imported_data = dataset.load(file.read(), format='xlsx')
            '''
            uploading xl file with particular data what user mentioned in xl we are looping the xl data
                    and appending into the database with same fields
                    '''
            for data in imported_data:
                sci_data = Sci1stKey(projectId=data[0],
                                     name=data[1],
                                     reference=data[2],
                                     jurisdiction_doctype=data[3],
                                     propertystate=data[4],
                                     dateaddded_to_kwf=data[5],
                                     datereceived=data[6],
                                     dateimaged=data[7],
                                     default=data[8],
                                     neverkeyed=data[9],
                                     erecordable=data[10],
                                     keying_duedate=data[11],
                                     shipping_datedue=data[12],
                                     isthis_a_rush=data[13],
                                     workflow=data[14],
                                     allocated_date=data[15],
                                     organization=data[16],
                                     agent=data[17],
                                     tl_name=data[18],
                                     team_name=data[19],
                                     )
                sci_data.save()
                # return response
            return Response({'sucessfully uploaded your file'}, status=status.HTTP_200_OK)
        except:
            # return response
            return Response(
                {'please select proper file'}, status=status.HTTP_404_NOT_FOUND)

from UserAdministration.xl_validation import *
import pandas as pd
import numpy as np
from lxml import etree as et


class UploadPersonView(APIView):
    permission_classes = [IsAuthenticated, IsAdminPermission | IsSuperAdminPermission]
    serializer_class = PersonUploadSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        dataset = Dataset()
        file = serializer.validated_data['file']
        imported_data = dataset.load(file.read(), format='xlsx')
        '''uploading xl file with particular data what user mentioned in xl we are looping the xl data
                    and appending into the database with same fields'''
        
        for data in imported_data:
            d=data[0]
            d1=data[1]
            d2=data[2]
            d6=data[6]
            d12=data[12]
            d15=data[15]

            pop_data=[]
            if d==d:
                c='data already availble please check'
                pop_data.append(c)
            else:
                print('comming')    
            if isinstance(d, (str)):
                pop_data.append(d)
            
                
                if isinstance(d1, (str)):
                    pop_data.append(1)
                if isinstance(d2, (int)):
                    pop_data.append(d2)
                if eval(d6):
                    pop_data.append(d6)
                if isinstance(d12, (str)):
                    pop_data.append(d12)
                if isinstance(d15, (int)):
                    pop_data.append(d15)
            
            
                        

            # elif d == str:
            #     print(d,'str')
                person_data = UserProfile(username=d,
                                            fullname=d1,
                                            mobile=d2,
                                            email=data[3],
                                            password=make_password(data[4]),
                                            date_joined=data[5],
                                            is_verified=d6,
                                            is_active=data[7],
                                            is_admin=data[8],
                                            is_manager=data[9],
                                            is_tl=data[10],
                                            is_agent=data[11],
                                            orginization=d12,
                                            dob=data[13],
                                            gender=data[14],
                                            team_name_id=d15,
                                            role=data[16]
                                            )
                person_data.save()
            print(pop_data,'pop_data')
            return Response(pop_data, status=status.HTTP_200_OK)
            # except:
            #     return Response({'message': 'aaa'}, status=status.HTTP_404_NOT_FOUND)



##prasanth
class SciListViewView(APIView):
    permission_classes = [IsAuthenticated, IsSuperAdminPermission | IsAdminPermission | IsManagerPermission]
    """
    This function is used for get the list availble records in this function used get method
        get method is used for get the data in db or any local also this get method contains
        model data with query and assigned model data into serializer and get n number of records
        sending into responce body admin & manager
    """

    def get(self, request, format=None):
        # fetching model object
        scikeylist = Sci1stKey.objects.all()
        serializer = ScikeylistSerializer(scikeylist, many=True)
        # return response
        return Response(serializer.data)


##prasanth
class SciTicketDetail(APIView):
    permission_classes = [IsAuthenticated, IsSuperAdminPermission | IsAdminPermission | IsManagerPermission]
    """
    Retrieve, update or delete a scikey instance.
    """

    def get_object(self, pk):
        try:
            return Sci1stKey.objects.get(pk=pk)
        except Sci1stKey.DoesNotExist:
            raise Http404

    """  
    This method is used for get the particular data with id contains 
        and sending responce into the body admin
    """

    def get(self, request, pk, format=None):
        sci_key = self.get_object(pk)
        serializer = ScikeylistSerializer(sci_key)
        return Response(serializer.data)

    def delete(self, request, pk, format=None):
        sci_key = self.get_object(pk)
        sci_key.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


## prashanth
class SciKeyAdminBulkAssignTicketsAPIView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated,
                          IsSuperAdminPermission | IsSuperAdminPermission | IsAdminPermission | IsManagerPermission]
    # fetching serilizer
    serializer_class = ScikeyAssignSerializer

    def post(self, request, *args, **kwargs):
        """
        this method is used for update single record or multiple record
            and update the status of sci ticket
        """
        status_sci = request.data.get('status')
        # get the model with newtickets
        user = Sci1stKey.objects.filter(status="newtickets")
        serializer = ScikeyAssignSerializer(user, data=request.data)
        serializer.is_valid(raise_exception=True)
        if serializer is not None:
            for user_status in user:
                user_status.status = 'assign'
                user_status.assign_tickets_status = 'assign'
                user_status.assign_tickets_date = datetime.date.today()
                user_status.save()
                # update status
                user.update(status="assign", assign_tickets_status='assign', assign_tickets_date=datetime.date.today())

                # serializer.save()
                return Response({'sucessfully updated your status'}, status=status.HTTP_200_OK)
            else:
                return Response(
                    {'not available any newtickets in your database '}, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'Something went wrong, please contact a Admin member '})

    # def put(self, request, *args, **kwargs):
    #     # serializer = ScikeyAssignSerializer(data=request.data)
    #     # if serializer.is_valid():
    #     #     serializer.save()
    #     serializer = ScikeyAssignSerializer(data={'status':'assign'}, partial=True)
    #     if serializer.is_valid():
    #         serializer.save()
    #         return Response(serializer.data, status=status.HTTP_201_CREATED)
    #     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # def update(self, request, *args, **kwargs):
    #     # data = {'status': 'assign'}
    #     serializer = self.serializer_class(request.user,data=request.data, partial=True)
    #     serializer.is_valid(raise_exception=True)
    #     serializer.save()
    #     return Response(serializer.data, status=status.HTTP_200_OK)


# prashanth
class SciKeyAdminAllTicketsCountAPIView(APIView):
    permission_classes = [IsAuthenticated,
                          IsSuperAdminPermission | IsSuperAdminPermission | IsAdminPermission | IsManagerPermission]
    # fetching serializer data
    serializer_class = ScikeyAssignSerializer

    # get the token of user and checking user perimissions
    # permission_classes = (permissions.IsAuthenticated, IsManagerPermission)

    def get(self, request, *args, **kwargs):
        """
        get the all tickets count data with specific status of all ticket
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        new_tickets_count = Sci1stKey.objects.filter(status="newtickets").count()
        assign_tickets_count = Sci1stKey.objects.filter(status="assign").count()
        closed_tickets_count = Sci1stKey.objects.filter(status="closed").count()
        pending_tickets_count = Sci1stKey.objects.filter(status="pending").count()
        total_count = new_tickets_count + assign_tickets_count + closed_tickets_count + pending_tickets_count
        # context =[{"total_count":total_count},{"new": new_tickets_count},{'assign':assign_tickets_count},{'completed':completed_tickets_count},{'pending_tickets_count':pending_tickets_count}]
        response = {
            'status': 'success',
            'code': status.HTTP_200_OK,
            'data': [{"totalticketscount": total_count},
                     {"newticketscount": new_tickets_count},
                     {'assignticketscount': assign_tickets_count},
                     {'pendingticketscount': pending_tickets_count},
                     {'closedticketscount': closed_tickets_count}
                     ]
        }
        return Response(response)


# prashanth
class SciKeyAdminAssignTicketsListAPIView(generics.ListAPIView):
    permission_classes = [IsAuthenticated, IsSuperAdminPermission | IsAdminPermission | IsManagerPermission]
    """fetching the serializer and Scikey data"""
    serializer_class = ScikeyTicketsListSerializer
    queryset = Sci1stKey.objects.all()

    def get(self, request, *args, **kwargs):
        '''
        get the particular status of scikey and get the all data of assign ticket
        :param request:
        :param args:
        :param kwargs:
        :return:
        '''
        queryset = Sci1stKey.objects.filter(status='assign')
        try:
            user_serializer = AgentOwnTicketsSerializer(queryset, many=True)
            return Response(user_serializer.data)
        except:
            return Response(
                {'sorry dont have any assign ticktes'}, status=status.HTTP_404_NOT_FOUND)


# prashanth
class SciKeyAddminClosedTicketsListAPIView(generics.ListAPIView):
    permission_classes = [IsAuthenticated, IsSuperAdminPermission | IsAdminPermission | IsManagerPermission]
    """
    fetching the serializer and Scikey data
    """
    serializer_class = ScikeyTicketsListSerializer
    queryset = Sci1stKey.objects.all()

    def get(self, request, *args, **kwargs):
        '''
        get the particular status of scikey and get the all data of completed ticket
        :param request:
        :param args:
        :param kwargs:
        :return:
        '''
        queryset = Sci1stKey.objects.filter(process_status='completed')
        try:
            user_serializer = AgentOwnTicketsSerializer(queryset, many=True)
            # return responce data
            return Response(user_serializer.data)
        except:
            return Response(
                {'sorry dont have any completed ticktes'}, status=status.HTTP_404_NOT_FOUND)


# prashanth
class SciKeyAdminNewTicketsListAPIView(generics.ListAPIView):
    permission_classes = [IsAuthenticated, IsSuperAdminPermission | IsAdminPermission | IsManagerPermission]
    """
    fetching the serializer and Scikey data
    """
    serializer_class = ScikeyTicketsListSerializer
    queryset = Sci1stKey.objects.all()

    def get(self, request, *args, **kwargs):
        '''
        get the particular status of scikey and get the all data of completed ticket
        :param request:
        :param args:
        :param kwargs:
        :return:
        '''
        queryset = Sci1stKey.objects.filter(status='newtickets')
        try:
            user_serializer = AgentOwnTicketsSerializer(queryset, many=True)

            return Response(user_serializer.data)
        except:
            return Response(
                {'sorry dont have any newtickets ticktes'}, status=status.HTTP_404_NOT_FOUND)


## prashanth
# teamwise newtickets count
class AdminTeamwiseNewTicketListAPIView(APIView):
    permission_classes = [IsAuthenticated, IsSuperAdminPermission | IsAdminPermission | IsManagerPermission]
    serializer_class = AdminTeamwiseTicketListAPIViewSerializer
    queryset = Sci1stKey.objects.all()

    def get(self, request, *args, **kwargs):
        try:
            """ getting userid """
            queryset = Teams.objects.values('teamname')
            userslist = []
            for x in queryset:
                k = (x["teamname"])
                userslist.append(k)
            res = []
            for y in userslist:
                agentdata = Sci1stKey.objects.filter(team_name=k).filter(new_tickets_status="newtickets")
                res.append(agentdata)
            # tlteam_closed_tickets = (sum(res))
            agentdata = Sci1stKey.objects.filter(team_name=k).filter(new_tickets_status="newtickets").values(
                'upload_date', 'team_name', 'new_tickets_status').annotate(count=Count('status'))

            countArray = []
            for profile in agentdata:
                data = {'upload_date': str(profile['upload_date']), 'team_name': str(profile['team_name']),
                        'count': profile['count']}
                countArray.append(data)

            new_ticketsdata_serializer = AdminTeamwiseTicketListAPIViewSerializer(countArray, many=True)
            # return JsonResponse(serializer.data, safe=False)
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': new_ticketsdata_serializer.data
            }
            return Response(response)
            # return Response({'message':'assign tickets table data'}, status=status.HTTP_200_OK)
        except Exception:
            "if data does not exist enter into exception"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


## prashanth
# teamwise Assign count
class AdminTeamwiseAssignTicketListAPIView(APIView):
    permission_classes = [IsAuthenticated, IsSuperAdminPermission | IsAdminPermission | IsManagerPermission]
    serializer_class = AdminTeamwiseTicketListAPIViewSerializer
    queryset = Sci1stKey.objects.all()

    def get(self, request, *args, **kwargs):
        try:
            """ getting userid """
            queryset = Teams.objects.values('teamname')
            userslist = []
            for x in queryset:
                k = (x["teamname"])
                userslist.append(k)
            res = []
            for y in userslist:
                agentdata = Sci1stKey.objects.filter(team_name=k).filter(assign_tickets_status="assign")
                res.append(agentdata)
            # tlteam_closed_tickets = (sum(res))
            agentdata = Sci1stKey.objects.filter(team_name=k).filter(assign_tickets_status="assign").values(
                'assign_tickets_date', 'team_name', 'assign_tickets_status').annotate(count=Count('status'))
            countArray = []

            for profile in agentdata:
                data = {'assign_tickets_date': str(profile['assign_tickets_date']),
                        'team_name': str(profile['team_name']), 'count': profile['count']}
                countArray.append(data)

            assign_ticketsdata_serializer = AdminTeamwiseTicketListAPIViewSerializer(countArray, many=True)
            # return JsonResponse(serializer.data, safe=False)
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': assign_ticketsdata_serializer.data
            }
            return Response(response)
            # return Response(json.dumps(countArray))
            # return Response({'message':'assign tickets table data'}, status=status.HTTP_200_OK)
        except Exception:
            "if data does not exist enter into exception"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


## prashanth
# teamwise Pending count
class AdminTeamwisePendingTicketListAPIView(APIView):
    permission_classes = [IsAuthenticated, IsSuperAdminPermission | IsAdminPermission | IsManagerPermission]
    serializer_class = AdminTeamwiseTicketListAPIViewSerializer
    queryset = Sci1stKey.objects.all()

    def get(self, request, *args, **kwargs):
        try:
            """ getting userid """
            queryset = Teams.objects.values('teamname')
            userslist = []
            for x in queryset:
                k = (x["teamname"])
                userslist.append(k)
            res = []
            for y in userslist:
                agentdata = Sci1stKey.objects.filter(team_name=k).filter(pending_tickets_status="pending")
                res.append(agentdata)
            # tlteam_closed_tickets = (sum(res))
            agentdata = Sci1stKey.objects.filter(team_name=k).filter(pending_tickets_status="pending").values(
                'pending_tickets_date', 'team_name', 'pending_tickets_status').annotate(count=Count('status'))
            countArray = []

            for profile in agentdata:
                data = {'pending_tickets_date': str(profile['pending_tickets_date']),
                        'team_name': str(profile['team_name']), 'count': profile['count']}
                countArray.append(data)

            pending_ticketsdata_serializer = AdminTeamwiseTicketListAPIViewSerializer(countArray, many=True)
            # return JsonResponse(serializer.data, safe=False)
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': pending_ticketsdata_serializer.data
            }
            return Response(response)

            # return Response(json.dumps(countArray),{'message':'assign tickets table data'}, status=status.HTTP_200_OK)
        except Exception:
            "if data does not exist enter into exception"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


## prashanth
# teamwise closed count
class AdminTeamwiseClosedTicketListAPIView(APIView):
    permission_classes = [IsAuthenticated, IsSuperAdminPermission | IsAdminPermission | IsManagerPermission]
    serializer_class = AdminTeamwiseClosedTicketListAPIViewSerializer
    queryset = Sci1stKey.objects.all()

    def get(self, request, *args, **kwargs):
        try:
            """ getting userid """
            queryset = Teams.objects.values('teamname')
            userslist = []
            for x in queryset:
                k = (x["teamname"])
                userslist.append(k)
            res = []
            for y in userslist:
                agentdata = Sci1stKey.objects.filter(team_name=k).filter(status="closed")
                res.append(agentdata)
            # tlteam_closed_tickets = (sum(res))
            agentdata = Sci1stKey.objects.filter(team_name=k).filter(status="closed").values('completed_date',
                                                                                             'team_name',
                                                                                             'status').annotate(
                count=Count('status'))
            countArray = []

            for profile in agentdata:
                data = {'completed_date': str(profile['completed_date']), 'team_name': str(profile['team_name']),
                        'count': profile['count']}
                countArray.append(data)

            closed_ticketsdata_serializer = AdminTeamwiseClosedTicketListAPIViewSerializer(countArray, many=True)
            # return JsonResponse(serializer.data, safe=False)
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': closed_ticketsdata_serializer.data
            }
            return Response(response)

            # return Response(json.dumps(countArray))
            # return Response(json.dumps(countArray),{'message':'assign tickets table data'}, status=status.HTTP_200_OK)
        except Exception:
            "if data does not exist enter into exception"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


# agent assign tickets
class AdminAgentwiseNewTicketListAPIView(APIView):
    permission_classes = [IsAuthenticated, IsSuperAdminPermission | IsAdminPermission | IsManagerPermission]
    serializer_class = AdminAgentwiseTicketListAPIViewSerializer
    queryset = Sci1stKey.objects.all()

    def get(self, request):
        try:
            # queryset=Sci1stKey.objects.values('upload_date', 'Agent','team_name').order_by().annotate(Count('status')).filter(status="newtickets")
            queryset = Sci1stKey.objects.filter(new_tickets_status="newtickets").values('upload_date', 'agent',
                                                                                        'new_tickets_status').annotate(
                count=Count('status'))

            countArray = []
            for profile in queryset:
                data = {'upload_date': str(profile['upload_date']), 'agent': str(profile['agent']),
                        'new_tickets_status': profile['new_tickets_status'], 'count': int(profile['count'])}
                countArray.append(data)
            closed_ticketsdata_serializer = AdminAgentwiseTicketListAPIViewSerializer(countArray, many=True)
            # return JsonResponse(serializer.data, safe=False)
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': closed_ticketsdata_serializer.data
            }
            return Response(response)
        except Exception:
            "if data does not exist enter into exception"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


# agent assign tickets
class AdminAgentwiseAssignTicketListAPIView(APIView):
    permission_classes = [IsAuthenticated, IsSuperAdminPermission | IsAdminPermission | IsManagerPermission]
    serializer_class = AdminAgentwiseTicketListAPIViewSerializer
    queryset = Sci1stKey.objects.all()

    def get(self, request):
        try:
            # queryset=Sci1stKey.objects.values('upload_date', 'Agent','team_name').order_by().annotate(Count('status')).filter(status="newtickets")
            queryset = Sci1stKey.objects.filter(assign_tickets_status="assign").values('assign_tickets_date', 'agent',
                                                                                       'assign_tickets_status').annotate(
                count=Count('status'))

            countArray = []
            for profile in queryset:
                data = {'assign_tickets_date': str(profile['assign_tickets_date']), 'agent': str(profile['agent']),
                        'assign_tickets_status': profile['assign_tickets_status'], 'count': int(profile['count'])}
                countArray.append(data)
            closed_ticketsdata_serializer = AdminAgentwiseTicketListAPIViewSerializer(countArray, many=True)
            # return JsonResponse(serializer.data, safe=False)

            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': closed_ticketsdata_serializer.data
            }
            return Response(response)
        except Exception:
            "if data does not exist enter into exception"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


# agent pending tickets
class AdminAgentwisePendingTicketListAPIView(APIView):
    permission_classes = [IsAuthenticated, IsSuperAdminPermission | IsAdminPermission | IsManagerPermission]
    serializer_class = AdminAgentwiseTicketListAPIViewSerializer
    queryset = Sci1stKey.objects.all()

    def get(self, request):
        try:
            # queryset=Sci1stKey.objects.values('upload_date', 'Agent','team_name').order_by().annotate(Count('status')).filter(status="newtickets")
            queryset = Sci1stKey.objects.filter(pending_tickets_status="pending").values('pending_tickets_date',
                                                                                         'agent',
                                                                                         'pending_tickets_status').annotate(
                count=Count('status'))

            countArray = []
            for profile in queryset:
                data = {'pending_tickets_date': str(profile['pending_tickets_date']), 'agent': str(profile['agent']),
                        'pending_tickets_status': profile['pending_tickets_status'], 'count': int(profile['count'])}
                countArray.append(data)
            closed_ticketsdata_serializer = AdminAgentwiseTicketListAPIViewSerializer(countArray, many=True)
            # return JsonResponse(serializer.data, safe=False)
            # return Response(json.dumps(countArray))

            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': closed_ticketsdata_serializer.data
            }
            return Response(response)
        except Exception:
            "if data does not exist enter into exception"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)

        # agent pending tickets


class AdminAgentwiseClosedTicketListAPIView(APIView):
    permission_classes = [IsAuthenticated, IsSuperAdminPermission | IsAdminPermission | IsManagerPermission]
    serializer_class = AdminAgentwiseClosedTicketListAPIViewSerializer
    queryset = Sci1stKey.objects.all()

    def get(self, request):
        try:
            # queryset=Sci1stKey.objects.values('upload_date', 'Agent','team_name').order_by().annotate(Count('status')).filter(status="newtickets")
            queryset = Sci1stKey.objects.filter(status="closed").values('completed_date', 'agent', 'status').annotate(
                count=Count('status'))

            countArray = []
            for profile in queryset:
                data = {'completed_date': str(profile['completed_date']), 'agent': str(profile['agent']),
                        'status': profile['status'], 'count': int(profile['count'])}
                countArray.append(data)
            closed_ticketsdata_serializer = AdminAgentwiseClosedTicketListAPIViewSerializer(countArray, many=True)
            # return JsonResponse(serializer.data, safe=False)
            # return Response(json.dumps(countArray))

            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': closed_ticketsdata_serializer.data
            }
            return Response(response)
        except Exception:
            "if data does not exist enter into exception"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


class AdminDatewiseNewTicketListAPIView(APIView):
    permission_classes = [IsAuthenticated, IsSuperAdminPermission | IsAdminPermission | IsManagerPermission]
    """
        fetching the serializer and Scikey data
    """
    serializer_class = AdminAgentwiseNewAssignTicketListAPIViewSerializer
    queryset = Sci1stKey.objects.all()

    def get(self, request, *args, **kwargs):
        '''
        :param request:
        :param args:
        :param kwargs:
        :return:
        '''
        try:
            res = []
            agentdata = Sci1stKey.objects.filter(new_tickets_status="newtickets").values('upload_date',
                                                                                         'new_tickets_status').annotate(
                count=Count('status'))
            res.append(agentdata)

            data_list = [num for elem in res for num in elem]

            """looping lists [[][][]] inside list"""
            user_serializer = AdminAgentwiseNewAssignTicketListAPIViewSerializer(data_list, many=True)
            '''convserting the all tickets into json by serializer'''
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': user_serializer.data
            }
            return Response(response)
        except (Sci1stKey.DoesNotExist, ValidationError):
            "if data does not exist enter into exception"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


# prashanth
# admin agent datewise pending
class AdminDatewisePendingTicketListAPIView(APIView):
    permission_classes = [IsAuthenticated, IsSuperAdminPermission | IsAdminPermission | IsManagerPermission]
    """
        fetching the serializer and Scikey data
    """
    serializer_class = AdminAgentwiseClosedTicketListCountAPIViewSerializer
    queryset = Sci1stKey.objects.all()

    def get(self, request, *args, **kwargs):
        '''
        :param request:
        :param args:
        :param kwargs:
        :return:
        '''
        try:
            res = []
            agentdata = Sci1stKey.objects.filter(pending_tickets_status="pending").values('pending_tickets_date',
                                                                                          'pending_tickets_status').annotate(
                count=Count('status'))
            res.append(agentdata)
            data_list = [num for elem in res for num in elem]

            """looping lists [[][][]] inside list"""
            user_serializer = AdminAgentwiseClosedTicketListCountAPIViewSerializer(data_list, many=True)
            '''convserting the all tickets into json by serializer'''
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': user_serializer.data
            }
            return Response(response)
        except (Sci1stKey.DoesNotExist, ValidationError):
            "if data does not exist enter into exception"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


# prashanth
## agent datewise assign tickets
class AdminDatewiseAssignTicketListAPIView(APIView):
    permission_classes = [IsAuthenticated, IsSuperAdminPermission | IsAdminPermission | IsManagerPermission]
    """
        fetching the serializer and Scikey data
    """
    serializer_class = AdminAgentwiseNewAssignTicketListAPIViewSerializer
    queryset = Sci1stKey.objects.all()

    def get(self, request, *args, **kwargs):
        '''
        :param request:
        :param args:
        :param kwargs:
        :return:
        '''
        try:
            res = []
            agentdata = Sci1stKey.objects.filter(assign_tickets_status="assign").values('assign_tickets_date',
                                                                                        'assign_tickets_status').annotate(
                count=Count('status'))
            res.append(agentdata)
            data_list = [num for elem in res for num in elem]

            """looping lists [[][][]] inside list"""
            user_serializer = AdminAgentwiseNewAssignTicketListAPIViewSerializer(data_list, many=True)
            '''convserting the all tickets into json by serializer'''
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': user_serializer.data
            }
            return Response(response)
        except (Sci1stKey.DoesNotExist, ValidationError):
            "if data does not exist enter into exception"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


# prashanth
# admin agent datewise pending
class AdminDatewiseClosedTicketListAPIView(APIView):
    permission_classes = [IsAuthenticated, IsSuperAdminPermission | IsAdminPermission | IsManagerPermission]
    """
        fetching the serializer and Scikey data
    """
    serializer_class = AdminAgentwiseClosedTicketListCountSerializer
    queryset = Sci1stKey.objects.all()

    def get(self, request, *args, **kwargs):
        '''
        :param request:
        :param args:
        :param kwargs:
        :return:
        '''
        try:
            res = []
            agentdata = Sci1stKey.objects.filter(status="closed").values('completed_date', 'status').annotate(
                count=Count('status'))
            res.append(agentdata)
            data_list = [num for elem in res for num in elem]

            """looping lists [[][][]] inside list"""
            user_serializer = AdminAgentwiseClosedTicketListCountSerializer(data_list, many=True)
            '''convserting the all tickets into json by serializer'''
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': user_serializer.data
            }
            return Response(response)
        except (Sci1stKey.DoesNotExist, ValidationError):
            "if data does not exist enter into exception"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


# # prashanth
# class SciKeyNotFoundTicketsListAPIView(generics.ListAPIView):
#     """
#     fetching the serializer and Scikey data
#     """
#     serializer_class = ScikeyTicketsListSerializer
#     queryset = Sci1stKey.objects.all()
#
#     def list(self, request, *args, **kwargs):
#         '''
#             get the particular status of scikey and get the all data of notfound ticket
#             :param request:
#             :param args:
#             :param kwargs:
#             :return:
#         '''
#         queryset = Sci1stKey.objects.filter(process_status='notfound')
#         user_serializer = AgentOwnTicketsSerializer(queryset, many=True)
#         # return responce data
#         return Response(user_serializer.data)
#
# # prashanth
# class SciKeyExceptionTicketsListAPIView(generics.ListAPIView):
#     """
#     fetching the serializer and Scikey data
#     """
#     serializer_class = ScikeyTicketsListSerializer
#     queryset = Sci1stKey.objects.all()
#
#     def list(self, request, *args, **kwargs):
#         '''
#         get the particular status of scikey and get the all data of exception ticket
#         :param request:
#         :param args:
#         :param kwargs:
#         :return:
#         '''
#         queryset = Sci1stKey.objects.filter(process_status='exception')
#         user_serializer = AgentOwnTicketsSerializer(queryset, many=True)
#         # return responce data
#         return Response(user_serializer.data)
#


## prashanth
## agent wise process status count
class AdminAgentWiseCountTicketListAPIView(APIView):
    # fetching serializers
    serializer_class = AdminProcessCountTicketListSerializer

    def get(self, request):
        try:
            # get scikey model and filtering the data with exact fields, status and count of the status
            agentdata_notfound = Sci1stKey.objects.filter(process_status="notfound").values('agent', 'completed_date',
                                                                                            'process_status').order_by().annotate(
                Count('process_status'))
            notfound_ticketsdata_serializer = AdminProcessCountTicketListSerializer(agentdata_notfound, many=True)
            # converting db data into json(serializer) with n number of fields

            # get scikey model and filtering the data with exact fields, status and count of the status
            agentdata_exception = Sci1stKey.objects.filter(process_status="exception").values('agent', 'completed_date',
                                                                                              'process_status').order_by().annotate(
                Count('process_status'))
            exception_ticketsdata_serializer = AdminProcessCountTicketListSerializer(agentdata_exception, many=True)
            # converting db data into json(serializer) with n number of fields

            # get scikey model and filtering the data with exact fields, status and count of the status
            agentdata_completed = Sci1stKey.objects.filter(process_status="completed").values('agent', 'completed_date',
                                                                                              'process_status').order_by().annotate(
                Count('process_status'))
            completed_ticketsdata_serializer = AdminProcessCountTicketListSerializer(agentdata_completed, many=True)
            # converting db data into json(serializer) with n number of fields

            """
            send the data into the responce and here we 
            are fetching more than 3types of scikey data 
            here if data is not available in db also not getting any error it will show emty list(maens data is not available)
            """
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': {'notfound_ticketsdata_serializer': notfound_ticketsdata_serializer.data,
                         'exception_ticketsdata_serializer': exception_ticketsdata_serializer.data,
                         'completed_ticketsdata_serializer': completed_ticketsdata_serializer.data
                         }
            }
            return Response(response)
        except:
            return Response(
                {'you dont have valid process status tickets'}, status=status.HTTP_404_NOT_FOUND)


## prashanth
## agent wise process status count
class AdminProcessCountTicketListAPIView(APIView):
    # fetching serializers
    serializer_class = AdminProcessCountTicketListSerializer

    def get(self, request):
        try:
            # get scikey model and filtering the data with exact fields, status and count of the status
            agentdata_notfound = Sci1stKey.objects.filter(process_status="notfound").count()

            notfound_ticketsdata_serializer = AdminProcessCountTicketListSerializer(agentdata_notfound, many=True)
            # converting db data into json(serializer) with n number of fields

            # get scikey model and filtering the data with exact fields, status and count of the status
            agentdata_exception = Sci1stKey.objects.filter(process_status="exception").count()
            exception_ticketsdata_serializer = AdminProcessCountTicketListSerializer(agentdata_exception, many=True)
            # converting db data into json(serializer) with n number of fields

            # get scikey model and filtering the data with exact fields, status and count of the status
            agentdata_completed = Sci1stKey.objects.filter(process_status="completed").count()
            completed_ticketsdata_serializer = AdminProcessCountTicketListSerializer(agentdata_completed, many=True)
            # converting db data into json(serializer) with n number of fields

            """
            send the data into the responce and here we 
            are fetching more than 3types of scikey data 
            here if data is not available in db also not getting any error it will show emty list(maens data is not available)
            """
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': [
                    {"notfoundticketscount": agentdata_notfound},
                    {"exceptionticketscount": agentdata_exception},
                    {'completedticketscount': agentdata_completed}
                ]
            }
            return Response(response)
        except:
            return Response(
                {'you dont have valid process status tickets'}, status=status.HTTP_404_NOT_FOUND)


# prashanth


class AgentAssignTicketsListApiView(generics.ListAPIView):
    """
    fetching the serializer and Scikey data
    """
    queryset = Sci1stKey.objects.all()
    serializer_class = AgentOwnTicketsSerializer
    # authentication token and permissions of user we can change permissions
    permission_classes = (permissions.IsAuthenticated, IsSuperAdminPermission | IsAgentPermission)

    def get(self, request, *args, **kwargs):
        '''
        get the login user (agent)  particular all tickets
        :param request:
        :param args:
        :param kwargs:
        :return:
        '''
        user_id = request.user.username
        try:
            queryset = Sci1stKey.objects.filter(status="assign", agent=user_id)
            user_serializer = AgentOwnTicketsSerializer(queryset, many=True)
            return Response(user_serializer.data)
        except:
            return Response(
                {'your dont have any assign tickets'}, status=status.HTTP_404_NOT_FOUND)

    # def get_object(self):
    #     return self.request.user

    # def get_object(self):
    #     pk = self.kwargs.get('pk')
    #
    #     if pk == "current":
    #         return self.request.user
    # queryset = Sci1stKey.objects.all()
    # serializer_class = AgentOwnTicketsSerializer

    # def get(self, request):
    #     serializer = AgentOwnTicketsSerializer(request.user)
    #     return Response(serializer.data)

    # permission_classes = (permissions.IsAuthenticated,)
    # permission_classes = (IsAuthenticated,IsAgent)

    #
    # queryset = Sci1stKey.objects.all()
    # serializer_class = AgentOwnTicketsSerializer



# prashanth
class AgentAssignDetailTicketListApiView(generics.GenericAPIView, mixins.ListModelMixin, mixins.UpdateModelMixin,
                                         mixins.RetrieveModelMixin, mixins.DestroyModelMixin):
    """
    fetching the serializer and Scikey data
    """
    queryset = Sci1stKey.objects.all()
    serializer_class = AgentRetriveSerializer
    # authentication token and permissions of user we can change permissions
    permission_classes = (permissions.IsAuthenticated, IsSuperAdminPermission | IsAgentPermission)
    # filter the sciticket id and get the data
    lookup_field = 'id'

    def get_object(self, id):
        try:
            # return Sci1stKey.objects.get(id=id)
            qs = Sci1stKey.objects.filter(id=id)
            '''
            get the sci key id and get the ticket and 
                change the status of ticket
            '''
            for x in qs:
                x.start_time_ticket = timezone.now()
                x.save()
                qs.update(start_time_ticket=timezone.now())
                data = Sci1stKey.objects.get(id=id, status="assign", process_status="emty")
                return data
        except Sci1stKey.DoesNotExist:
            raise Http404

    def get(self, request, id=None, *args, **kwargs):
        if id:
            calobj = self.get_object(id)
            serializer = AgentRetriveSerializer(calobj)
            return Response(serializer.data)
        else:
            alldata = Sci1stKey.objects.all()
            serializer = AgentRetriveSerializer(alldata, many=True)
            return Response(serializer.data)

    def put(self, request, id=None, *args, **kwargs):
        '''
        update the agent scikey ticket status with paricular field here we are given two fields s(status)
        :param request:
        :param id:
        :param args:
        :param kwargs:
        :return:
        '''
        calobj = self.get_object(id)
        serializer = AgentRetriveSerializer(calobj, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            body_data = serializer.data
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# prashanth
class SciKeyAgentPendingTicketsListAPIView(generics.ListAPIView):
    """
    fetching the serializer and Scikey data
    """
    serializer_class = ScikeyPendingTicketsListSerializer
    queryset = Sci1stKey.objects.all()
    # authentication token and permissions of user we can change permissions
    permission_classes = (permissions.IsAuthenticated, IsAdminPermission | IsManagerPermission | IsAgentPermission)

    def get(self, request, *args, **kwargs):
        '''
        get the all agents & login agent data of scikey and get the all data of pending ticket
        :param request:
        :param args:
        :param kwargs:
        :return:
        '''
        user_id = request.user.username
        try:
            queryset = Sci1stKey.objects.filter(status='pending', agent=user_id, )
            user_serializer = AgentOwnTicketsSerializer(queryset, many=True)
            # return the reponce of data body
            return Response(user_serializer.data)
        except:
            return Response(
                {'your dont have any pending tickets'}, status=status.HTTP_404_NOT_FOUND)


# prashanth
class AgentPendingDetailTicketApiView(generics.GenericAPIView, mixins.UpdateModelMixin,
                                      mixins.RetrieveModelMixin, mixins.DestroyModelMixin):
    """
    fetching the serializer and Scikey data
    """

    queryset = Sci1stKey.objects.all()
    serializer_class = ScikeyPendingTicketsListSerializer
    # authentication token and permissions of user we can change permissions
    # permission_classes = (permissions.IsAuthenticated, IsAgentPermission)

    # get the particular agent id
    lookup_field = 'id'

    def get_object(self, id):
        try:
            '''
            get the sci key id and get the ticket and 
                            change the status of ticket
            '''
            data = Sci1stKey.objects.get(id=id, status="pending")
            return data
        except Sci1stKey.DoesNotExist:
            raise Http404

    def get(self, request, id=None, *args, **kwargs):
        if id:
            calobj = self.get_object(id)
            '''
            get the sci key id and get the ticket status 
            '''
            serializer = ScikeyPendingTicketsListSerializer(calobj)
            return Response(serializer.data)
        else:
            alldata = Sci1stKey.objects.all()
            serializer = ScikeyPendingTicketsListSerializer(alldata, many=True)
            return Response(serializer.data)

    def put(self, request, id=None, *args, **kwargs):
        """
        get the sci key id and get the ticket and
                            update the status of ticket
        :param request:
        :param id:
        :param args:
        :param kwargs:
        :return:
        """
        calobj = self.get_object(id)
        serializer = ScikeyPendingTicketsListSerializer(calobj, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            body_data = serializer.data
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


## prashanth
# admin side view all agents tickets
class AllReAssign_Tickets_ListApi_View(APIView):
    permission_classes = [IsAuthenticated, IsAdminPermission | IsManagerPermission]
    # fetching serializer class
    serializer_class = Assigntickets_listSerializer
    # model name and get all users
    queryset = UserProfile.objects.all()

    def get(self, request, *args, **kwargs):
        """
        this function is using for get the all agents and used get method
        and validating the data avilable or not checking
        """
        List_of_AgentNames = UserProfile.objects.filter(role='Agent').values('username')
        if not List_of_AgentNames:
            #  responce code
            return Response({"no agents in your database roles,, please add agent role"},
                            status=status.HTTP_404_NOT_FOUND)
        else:
            # stored agent names & ids
            reassign = []
            for agentname in List_of_AgentNames:
                reassign.append(agentname['username'])
            # storing agent ids here
            # userslist = []
            # for x in reassign:
            #     # selecting id
            #     k = (x["username"])
            #     userslist.append(k)
            # print(userslist)
            countArray = []
            for profile in reassign:
                countArray.append(profile)
            # print(countArray)
            # context = {'username':countArray}
            # return JsonResponse(serializer.data, safe=False)
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': {'username': countArray}
            }
            return Response(response)
            #  responce code
            # return Response({"received agent names"}, status=status.HTTP_200_OK)


## prashanth
## get the particular agent with his all tickets
class Ticketreassign_to_agentview(APIView):
    permission_classes = [IsAuthenticated, IsAdminPermission | IsManagerPermission]

    def get_object(self, agent):
        # queryset = Sci1stKey.objects.filter(agent=agent)
        try:
            queryset = Sci1stKey.objects.filter(agent=agent, status='assign')
            data = list(queryset)
            # user_serializer = AgentOwnTicketsSerializer(queryset, many=True)
            return data
        except Sci1stKey.DoesNotExist:
            raise Http404

    def get(self, request, agent=None, *args, **kwargs):
        if agent:
            calobj = self.get_object(agent)
            serializer = ReAssigntickets_listSerializer(calobj, many=True)
            return Response(serializer.data)
            return Response(serializer.data, {'sucessfully received agent details'})
        else:
            alldata = Sci1stKey.objects.all()
            serializer = ReAssigntickets_listSerializer(alldata, many=True)
            return Response(serializer.data)
            return Response({"no agent please check your agents"})


## prashanth
## reassign to another user class
class Ticketreassign_to_agentsCompleteview(APIView):
    permission_classes = [IsAuthenticated, IsAdminPermission | IsManagerPermission]
    ## fetching serializer data
    serializer_class = TicketreassignAgentsCompleteSerializer

    def put(self, request):
        """
        This function is used for get the agent name and agent tickets
        once get the tickets and assign agent name , this function is update the tickets
        to exact agent
        """
        serializer = self.serializer_class(data=request.data)
        try:
            agent_name = request.data['agent']
            id = request.data['id']
            values = id.split(',')
            user = Sci1stKey.objects.filter(id__in=values)
            for x in user:
                x.status = 'assign'
                x.save()
                user.update(agent=agent_name)
            return Response({"message": "sucessfully reassigned tickets"}, status=status.HTTP_200_OK)
        except Exception:
            "if any exception thant enter into exception block"
            return Response({'message': 'please select agent name and tickets'}, status=status.HTTP_404_NOT_FOUND)




import json
from django_pandas.io import read_frame



class LoginHours(generics.GenericAPIView):

    def get(self,request):
        try:
            queryset=AllLogin.objects.values('login_time','user_id','login_date')
            querySet3 = AllLogout.objects.values('logout_time','user_id','logout_date')

            df1 = pd.DataFrame(queryset)
            df2 = pd.DataFrame(querySet3)

            df2.rename(columns = {'user_id':'user'}, inplace = True)

            df1 = df1.sort_values(['user_id','login_time'])
            df2 = df2.sort_values([ 'user','logout_time'])

            df = pd.concat([df1.reset_index(drop=True),df2.reset_index(drop=True)], axis=1)
            df['logout_time'] = pd.to_timedelta(df['logout_time'].astype(str))

            df['login_time'] = pd.to_timedelta(df['login_time'].astype(str))


            df['diiffrences']=df['logout_time']-df['login_time']

            diff = df[['login_date','user_id','user','diiffrences']]

            group1 = diff.groupby(['user_id','user','login_date']).sum('')
            
            d=group1.reset_index()
            c = d[['diiffrences']]

            data_dict = d.to_dict('records')


            json_data =json.dumps(data_dict,default=str)
    
            python_obj = json.loads(json_data)
            for i in range(0,len(python_obj)):
                credit, created = ProductiveHours.objects.get_or_create(user_id=python_obj[i]['user_id'], user=python_obj[i]['user'], login_date=python_obj[i]['login_date'], diiffrences=python_obj[i]['diiffrences'])
                # ProductiveHours.objects.create(user_id=python_obj[i]['user_id'], user=python_obj[i]['user'], login_date=python_obj[i]['login_date'], diiffrences=python_obj[i]['diiffrences'])
            
            obj = ProductiveHours.objects.all()
            df = read_frame(obj)
                
            latest_prod = df.sort_values('diiffrences').groupby(['user_id','login_date']).tail(1)

            timer_dict = latest_prod.to_dict('records')

            timetr_json_data =json.dumps(timer_dict,default=str)
            timertr_json_data = json.loads(timetr_json_data)
                     
            return Response({"productive_hours":timertr_json_data},status=status.HTTP_404_NOT_FOUND )
        except:
            return Response('no time data in your database please check your database', status=status.HTTP_404_NOT_FOUND)





"****************************************Theja*********************************************************************************"


##theja
##theja
##changing password after user login his account
class ChangePasswordView(generics.UpdateAPIView):
    permission_classes = [IsAuthenticated]
    '''
    This class is used for get the user and change user password
    '''

    ## authentication token and permissions of user we can change permissions

    # get the model data
    model = UserProfile
    serializer_class = ChangePasswordSerializers

    def get_object(self, queryset=None):
        """ getting the user"""
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        """calling the above function """
        serializer = self.get_serializer(data=request.data)
        """getting the data from request"""

        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Old password is not correct"]}, status=status.HTTP_400_BAD_REQUEST)
            self.object.set_password(serializer.data.get("password"))
            '''getting the new password'''
            self.object.save()
            '''save the new password'''
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
                'data': serializer.data
            }
            '''sending the data in response'''
            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


##theja
###updating his profile after user login into the account
class Update_his_ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    '''
    This class is used for get the user and update his profile details
    '''
    ## authentication token and permissions of user we can change permissions
    serializer_class = Update_his_profile_Serializer

    # get the model data
    queryset = UserProfile.objects.all()

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def get(self, request, *args, **kwargs):
        calobj = self.get_object()

        '''
        getting his username
        '''
        serializer = Update_his_profile_Serializer(calobj)
        response = {
            'status': 'success',
            'code': status.HTTP_200_OK,
            'data': serializer.data
        }
        return Response(response)

    def put(self, request, *args, **kwargs):
        object = self.get_object()
        serializer = Update_his_profile_Serializer(object, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            body_data = serializer.data
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Profile updated successfully',
                'data': serializer.data
            }

            return Response(response)
            # return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class TeamNames(generics.ListAPIView):
    permission_classes = [IsAuthenticated, IsSuperAdminPermission | IsAdminPermission]
    """fetching the serializer and Scikey data"""
    serializer_class = TeamNameListSerializer
    queryset = Teams.objects.all()

    def get(self, request, *args, **kwargs):
        try:
            """ getting teamname """
            queryset = Teams.objects.values('teamname')
            userslist = []
            for x in queryset:
                k = (x["teamname"])
                userslist.append(k)
            return Response(json.dumps(userslist))
            # tutorial_serializer = TeamNameListSerializer(x)
            # return JsonResponse(tutorial_serializer.data)
            return Response({'message': 'team names in table data'}, status=status.HTTP_200_OK)
        except Exception:
            "if data does not exist enter into exception"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


##theja
# Adding Teams by Admin
class Addingteams(generics.GenericAPIView):
    ## authentication token and permissions of user we can change permissions
    permission_classes = [IsAuthenticated, IsSuperAdminPermission | IsAdminPermission]
    # fetch serializer data
    serializer_class = Teamserialsers

    def post(self, request, *args, **kwargs):
        '''
        This function is used for post the data of adding teams
        '''
        parameters = request.data.copy()
        serializer = self.get_serializer(data=parameters)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"message": "Teams Created Successfully."}, status=status.HTTP_201_CREATED)
        else:
            return Response({"message": 'Team name already exist'}, status=status.HTTP_406_NOT_ACCEPTABLE)


##theja
# View all_Team  by Admin
class Team_ListView(APIView):
    permission_classes = [IsAuthenticated, IsSuperAdminPermission | IsAdminPermission]

    ## authentication token and permissions of user we can change permissions
    def get(self, request):
        try:
            # get the model data
            tutorial = Teams.objects.all()
        except Teams.DoesNotExist:
            return JsonResponse({'message': 'Teams does not exist'}, status=status.HTTP_404_NOT_FOUND)

        tutorial_serializer = Teamserialsers(tutorial, many=True)
        return JsonResponse(tutorial_serializer.data, safe=False)



##theja
# view/update/delete Team  by Admin
@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated, IsSuperAdminPermission | IsAdminPermission])
def Team_detail(request, pk):
    '''
    This function is used for update team details of particular team and this
    function contain get, put, delete
    '''
    try:
        # get the model name with filtering team id
        tutorial = Teams.objects.get(pk=pk)
    except Teams.DoesNotExist:
        return JsonResponse({'message': 'The Team does not exist'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        # fetch serializer data and add model into serializer
        tutorial_serializer = Teamserialsers(tutorial)
        return JsonResponse(tutorial_serializer.data)

    elif request.method == 'PUT':
        '''this function is used for update team detail '''
        # tutorial_data = JSONParser().parse(request)
        tutorial_serializer = Teamserialsers(tutorial, data=request.data)
        if tutorial_serializer.is_valid():
            tutorial_serializer.save()
            return JsonResponse(tutorial_serializer.data, )
        return JsonResponse(tutorial_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        tutorial.delete()
        return JsonResponse({'message': 'Team was deleted successfully!'}, status=status.HTTP_204_NO_CONTENT)


##theja
# All Persons(user Profile) by Admin
class User_listApiview(APIView):
    ## authentication token and permissions of user we can add permissions
    permission_classes = [IsAuthenticated, IsSuperAdminPermission | IsAdminPermission | IsManagerPermission]

    def get(self, request):
        """
        this function is used for get the all user data
        :param request:
        :return:
        """
        try:
            tutorial = UserProfile.objects.all()
        except UserProfile.DoesNotExist:
            return JsonResponse({'message': 'The user does not exist'}, status=status.HTTP_404_NOT_FOUND)
        # fetching serializer data
        tutorial_serializer = UserProfileSerializer(tutorial, many=True)
        return JsonResponse(tutorial_serializer.data, safe=False)


##theja
# view/update/delete person(one)  by Admin
@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated, IsSuperAdminPermission | IsAdminPermission | IsManagerPermission])
def Person_detail(request, pk):
    '''
    this function is used for update his profie data single update or multiple update also
    :param request:
    :param pk:
    :return:
    '''
    try:
        # get the single user id and print the data
        tutorial = UserProfile.objects.get(pk=pk)
    except UserProfile.DoesNotExist:
        return JsonResponse({'message': 'The user does not exist'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        tutorial_serializer = UserProfileSerializer(tutorial)
        return JsonResponse(tutorial_serializer.data)

    elif request.method == 'PUT':
        '''
        this method is used for update single user data 
        \with particular field and update more fields
        '''
        tutorial_serializer = UserProfileSerializer(tutorial, data=request.data)
        if tutorial_serializer.is_valid():
            tutorial_serializer.save()
            return JsonResponse(tutorial_serializer.data)
        return JsonResponse(tutorial_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        '''
        this method is delete particular user record from db
        '''
        tutorial.delete()
        return JsonResponse({'message': 'person was deleted successfully!'}, status=status.HTTP_204_NO_CONTENT)


# theja
## In this class  we are showing tl his team wise agents all tickets
class Tl_Teamwise_AllticketsView(APIView):
    permission_classes = [IsAuthenticated, IsSuperAdminPermission | IsAdminPermission | IsTlPermission]
    """
        fetching the serializer and Scikey data
    """
    serializer_class = TlwiseTeamAllTicketsSerializer
    queryset = Sci1stKey.objects.all()

    def get(self, request, *args, **kwargs):
        '''
        get the login user (TL)  particular all tickets
        :param request:
        :param args:
        :param kwargs:
        :return:
        '''

        try:
            user_id = request.user.username
            """ getting userid """
            queryset = UserProfile.objects.get(username=user_id).team_name_id
            """ comparing the userid with userprofile(database) username and getting the teamnameid"""
            agentfilter = UserProfile.objects.filter(role='Agent')
            """ filter the agents with their roles from database"""
            agent_names = (UserProfile.objects.filter(team_name_id=queryset) & agentfilter).values(full_name=Lower('fullname'))
            """1)comparing teamnameid from database with your getting id
              2) filter the agents with their roles 
              3) satisfies both above two conditions and getting their fullnames"""
            res = []
            for fullname in agent_names:
                """ getting all agents names in list"""
                agentdata = Sci1stKey.objects.annotate(agent_name=Lower('agent')).filter(agent_name=fullname['full_name'])
                """ looping the list objects and comparing the sci1st key agent names with full names from 
                userprofile database and getting all tickets matches with fullnames"""
                res.append(agentdata)
            """ appending in new list"""
            data_list = [num for elem in res for num in elem]
            """looping lists [[][][]] inside list"""
            user_serializer = TlwiseTeamAllTicketsSerializer(data_list, many=True)
            '''convserting the all tickets into json by serializer'''
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': user_serializer.data
            }
            return Response(response)
        except (UserProfile.DoesNotExist, ValidationError):
            "if any exception thant enter into exception block"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


# theja
## In this class  we are showing tl his team wise agents assign tickets
class Tl_Teamwise_AssignticketsView(APIView):
    permission_classes = [IsAuthenticated,
                          IsSuperAdminPermission | IsAdminPermission | IsManagerPermission | IsTlPermission]
    """
        fetching the serializer and Scikey data
    """
    serializer_class = TlwiseTeamAllTicketsSerializer
    queryset = Sci1stKey.objects.all()

    def get(self, request, *args, **kwargs):
        '''
        get the login user (TL)  particular all tickets
        :param request:
        :param args:
        :param kwargs:
        :return:
        '''
        try:
            user_id = request.user.username
            """ getting userid """
            queryset = UserProfile.objects.get(username=user_id).team_name_id
            """ comparing the userid with userprofile(database) username and getting the teamnameid"""
            agentfilter = UserProfile.objects.filter(role='Agent')
            """ filter the agents with their roles from database"""
            agent_names = (UserProfile.objects.filter(team_name_id=queryset) & agentfilter).values(full_name=Lower('fullname'))
            """1)comparing teamnameid from database with your getting id
              2) filter the agents with their roles 
              3) satisfies both above two conditions and getting their fullnames"""
            res = []
            for fullname in agent_names:
                """ getting all agents names in list"""
                agentdata = Sci1stKey.objects.annotate(agent_name=Lower('agent')).filter(agent_name=fullname['full_name']).filter(status="assign")
                """ looping the list objects and comparing the sci1st key agent names with full names from 
                userprofile database and getting only assign tickets matches with fullnames"""
                res.append(agentdata)
                """ appending in new list"""
            data_list = [num for elem in res for num in elem]
            """looping lists [[][][]] inside list"""
            user_serializer = TlwiseTeamAllTicketsSerializer(data_list, many=True)
            '''convserting the all tickets into json by serializer'''
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': user_serializer.data
            }
            return Response(response)
        except (UserProfile.DoesNotExist, ValidationError):
            "if any exception thant enter into exception block"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


##theja
# showing newtickets/assign/closed tickets count for tl under his team
class Tl_Teamwise_ticket_StatuscountView(APIView):
    permission_classes = [IsAuthenticated,
                          IsSuperAdminPermission | IsAdminPermission | IsManagerPermission | IsTlPermission]
    """
            fetching the serializer and Scikey data
        """
    serializer_class = TlwiseTeamAllTicketsSerializer

    def get(self, request):
        '''get method for getting the list of data'''
        try:
            user_id = request.user.username
            """ getting userid """
            queryset = UserProfile.objects.get(username=user_id).team_name_id
            """ comparing the userid with userprofile(database) username and getting the teamnameid"""
            agentname = (UserProfile.objects.filter(role='Agent') & UserProfile.objects.filter(
                team_name_id=queryset)).values(full_name=Lower('fullname'))
            """1)comparing teamnameid from database with your getting id
            2) filter the agents with their roles 
            3) satisfies both above two conditions and getting their fullnames"""
            newtickets = []
            '''empty list'''
            for fullnames in agentname:
                """ getting all agents names in list"""
                agentdata = Sci1stKey.objects.annotate(agent_name=Lower('agent')).filter(agent_name=fullnames['full_name']).filter(status="newtickets").count()
                """ looping the list objects and comparing the sci1st key agent names with full names from 
                                userprofile database and getting only newtickets tickets matches with fullnames with count values"""
                newtickets.append(agentdata)
                """ appending in new list"""
            tlteam_new_tickets = (sum(newtickets))

            ''' adding the new tickets values in the list'''

            assigntickets = []
            ''' same process like new tickets'''
            for fullnames in agentname:
                agentdata = Sci1stKey.objects.annotate(agent_name=Lower('agent')).filter(agent_name=fullnames['full_name']).filter(status="assign").count()
                assigntickets.append(agentdata)
            tlteam_assign_tickets = (sum(assigntickets))
            ''' adding the assign tickets values in the list'''

            pendingtickets = []
            ''' same process like new tickets'''
            for fullnames in agentname:
                agentdata = Sci1stKey.objects.annotate(agent_name=Lower('agent')).filter(agent_name=fullnames['full_name']).filter(status="pending").count()
                pendingtickets.append(agentdata)
            tlteam_pending_tickets = (sum(pendingtickets))

            closedtickets = []
            ''' same process like new tickets'''
            for fullnames in agentname:
                agentdata = Sci1stKey.objects.annotate(agent_name=Lower('agent')).filter(agent_name=fullnames['full_name']).filter(status="closed").count()
                closedtickets.append(agentdata)
            tlteam_closed_tickets = (sum(closedtickets))
            totalticketscount = tlteam_new_tickets + tlteam_assign_tickets + tlteam_closed_tickets + tlteam_pending_tickets
            # context =[{"newticketscount": tlteam_new_tickets }, {'assignticketscount': tlteam_assign_tickets}, {'pendingticketscount':tlteam_pending_tickets},{'closedticketscount': tlteam_closed_tickets}]
            '''all count values added in the dict'''
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': [
                    {"totalticketscount": totalticketscount},
                    {"newticketscount": tlteam_new_tickets},
                    {'assignticketscount': tlteam_assign_tickets},
                    {'pendingticketscount': tlteam_pending_tickets},
                    {'closedticketscount': tlteam_closed_tickets}]
            }
            '''all count values added in the dict inside list'''
            return Response(response)

        except Exception:
            "if any exception thant enter into exception block"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


##theja
# showing exception/notfound/completd tickets count for tl under his team
class Tl_Teamwise_process_StatuscountView(APIView):
    permission_classes = [IsAuthenticated,
                          IsSuperAdminPermission | IsAdminPermission | IsManagerPermission | IsTlPermission]
    serializer_class = TlwiseTeamAllTicketsSerializer

    def get(self, request):
        '''get method for getting the list of data'''
        try:
            user_id = request.user.username
            """ getting userid """
            queryset = UserProfile.objects.get(username=user_id).team_name_id
            """ comparing the userid with userprofile(database) username and getting the teamnameid"""
            agentname = (UserProfile.objects.filter(role='Agent') & UserProfile.objects.filter(
                team_name_id=queryset)).values(full_name=Lower('fullname'))
            """1)comparing teamnameid from database with your getting id
                        2) filter the agents with their roles 
                        3) satisfies both above two conditions and getting their fullnames"""
            exceptiontickets = []
            '''empty list'''
            for fullnames in agentname:
                """ getting all agents names in list"""
                agentdata = Sci1stKey.objects.annotate(agent_name=Lower('agent')).filter(agent_name=fullnames['full_name']).filter(
                    process_status="exception").count()
                """ looping the list objects and comparing the sci1st key agent names with full names from 
                userprofile database and getting only exception tickets matches with fullnames with count values"""
                exceptiontickets.append(agentdata)
                """ appending in new list"""
            tlteam_exception_tickets = (sum(exceptiontickets))
            ''' adding the assign tickets values in the list'''

            notfoundtickets = []
            for fullnames in agentname:
                agentdata = Sci1stKey.objects.annotate(agent_name=Lower('agent')).filter(agent_name=fullnames['full_name']).filter(
                    process_status="notfound").count()
                notfoundtickets.append(agentdata)
            tlteam_notfound_tickets = (sum(notfoundtickets))

            completedtickets = []
            for fullnames in agentname:
                agentdata = Sci1stKey.objects.annotate(agent_name=Lower('agent')).filter(agent_name=fullnames['full_name']).filter(
                    process_status="completed").count()
                completedtickets.append(agentdata)
            tlteam_completd_tickets = (sum(completedtickets))

            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': [
                    {"notfoundticketscount": tlteam_notfound_tickets},
                    {"exceptionticketscount": tlteam_exception_tickets},
                    {'completedticketscount': tlteam_completd_tickets}
                ]
            }
            '''all count values added in the dict inside list'''
            return Response(response)

        except Exception:
            "if any exception thant enter into exception block"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


##theja
# showing new/asssign/closed tickets tl team his agentwise count for tl under his team
class Tl_Team_agentwise_ticketstatus_countView(APIView):
    permission_classes = [IsAuthenticated,
                          IsSuperAdminPermission | IsAdminPermission | IsManagerPermission | IsTlPermission]
    serializer_class = TlwiseTeamdateTicketsSerializer

    def get(self, request):
        try:
            user_id = request.user.username
            """ getting userid """
            queryset = UserProfile.objects.get(username=user_id).team_name_id
            """ comparing the userid with userprofile(database) username and getting the teamnameid"""
            agentname = (UserProfile.objects.filter(role='Agent') & UserProfile.objects.filter(
                team_name_id=queryset)).values('fullname')
            """1)comparing teamnameid from database with your getting id
                2) filter the agents with their roles 
                3) satisfies both above two conditions and getting their fullnames"""
            ###########New tickets
            newtickets = []
            '''empty list'''
            for fullnames in agentname:
                """ getting all agents names in list"""
                agentdata = (Sci1stKey.objects.filter(agent=fullnames['fullname']).filter(
                    new_tickets_status="newtickets")).values(
                    'agent', 'upload_date').order_by().annotate(Count('status'))
                """ looping the list objects and comparing the sci1st key agent names with full names from 
                                userprofile database and getting only new  tickets matches with fullnames with count values and agent names and date"""
                newtickets.append(agentdata)
                """ appending in new list"""
            new_ticketsdata = [num for elem in newtickets for num in elem]
            """looping lists [[][][]] inside list"""
            new_ticketsdata_serializer = TlwiseTeamdateTicketsSerializer(new_ticketsdata, many=True)
            '''convserting the all tickets into json by serializer'''

            ###########assign tickets
            '''same as new rickets'''
            assigntickets = []
            for fullnames in agentname:
                agentdata = (Sci1stKey.objects.filter(agent=fullnames['fullname']).filter(
                    assign_tickets_status="assign")).values(
                    'agent', 'assign_tickets_date').order_by().annotate(Count('status'))
                assigntickets.append(agentdata)
            assign_ticketsdata = [num for elem in assigntickets for num in elem]
            assign_ticketsdata_serializer = TlwiseTeamdateTicketsSerializer(assign_ticketsdata, many=True)

            ### pending tickets
            pendingtickets = []
            for fullnames in agentname:
                agentdata = (Sci1stKey.objects.filter(agent=fullnames['fullname']).filter(
                    pending_tickets_status="pending")).values(
                    'agent', 'pending_tickets_date').order_by().annotate(Count('status'))
                pendingtickets.append(agentdata)
            pending_ticketsdata = [num for elem in pendingtickets for num in elem]
            pending_ticketsdata_serializer = TlwiseTeamdateTicketsSerializer(pending_ticketsdata, many=True)

            ###########closed tickets
            closedtickets = []
            for fullnames in agentname:
                agentdata = (Sci1stKey.objects.filter(agent=fullnames['fullname']).filter(status="closed")).values(
                    'agent', 'completed_date').order_by().annotate(Count('status'))
                closedtickets.append(agentdata)
            closed_ticketsdata = [num for elem in closedtickets for num in elem]
            closed_ticketsdata_serializer = TlwiseTeamdateTicketsSerializer(closed_ticketsdata, many=True)

            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': {'newtickets': new_ticketsdata_serializer.data,
                         'assigntickets': assign_ticketsdata_serializer.data,
                         'pendingtickets': pending_ticketsdata_serializer.data,
                         'closed': closed_ticketsdata_serializer.data}
            }
            return Response(response)
        except Exception:
            "if any exception thant enter into exception block"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


##theja
# showing exception/notfound/completd tickets tl team his agentwise count for tl under his team
class Tl_Team_agentwise_processstatus_countView(APIView):
    permission_classes = [IsAuthenticated,
                          IsSuperAdminPermission | IsAdminPermission | IsManagerPermission | IsTlPermission]
    serializer_class = TlwiseTeamdateTicketsSerializer

    def get(self, request):
        try:
            user_id = request.user.username
            """ getting userid """
            queryset = UserProfile.objects.get(username=user_id).team_name_id
            """ comparing the userid with userprofile(database) username and getting the teamnameid"""
            agentname = (UserProfile.objects.filter(role='Agent') & UserProfile.objects.filter(
                team_name_id=queryset)).values('fullname')
            """1)comparing teamnameid from database with your getting id
                2) filter the agents with their roles 
                3) satisfies both above two conditions and getting their fullnames"""
            ##########notfound tickets
            notfoundtickets = []
            '''empty list'''
            for fullnames in agentname:
                """ getting all agents names in list"""
                agentdata = (
                    Sci1stKey.objects.filter(agent=fullnames['fullname']).filter(process_status="notfound")).values(
                    'agent', 'completed_date').order_by().annotate(Count('status'))
                """ 1)filtering the agent names and status
                2)getting values of agentnames and completd date
                3) count the no.of process status tickets
                """
                notfoundtickets.append(agentdata)
                """ appending in new list"""
            notfound_ticketsdata = [num for elem in notfoundtickets for num in elem]
            """looping lists [[][][]] inside list"""
            notfound_ticketsdata_serializer = TlwiseTeamdateTicketsSerializer(notfound_ticketsdata, many=True)
            '''convserting the all tickets into json by serializer'''

            ###########exception tickets
            '''same as new rickets'''
            exceptiontickets = []
            for fullnames in agentname:
                agentdata = (
                    Sci1stKey.objects.filter(agent=fullnames['fullname']).filter(process_status="exception")).values(
                    'agent', 'completed_date').order_by().annotate(Count('status'))
                exceptiontickets.append(agentdata)
            exception_ticketsdata = [num for elem in exceptiontickets for num in elem]
            exception_ticketsdata_serializer = TlwiseTeamdateTicketsSerializer(exception_ticketsdata, many=True)

            ### completed tickets
            completedtickets = []
            for fullnames in agentname:
                agentdata = (
                    Sci1stKey.objects.filter(agent=fullnames['fullname']).filter(process_status="completed")).values(
                    'agent', 'completed_date').order_by().annotate(Count('status'))
                completedtickets.append(agentdata)
            completed_ticketsdata = [num for elem in completedtickets for num in elem]
            completed_ticketsdata_serializer = TlwiseTeamdateTicketsSerializer(completed_ticketsdata, many=True)

            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': {'notfoundtickets': notfound_ticketsdata_serializer.data,
                         'exceptiontickets': exception_ticketsdata_serializer.data,
                         'completedtickets': completed_ticketsdata_serializer.data,
                         }
            }
            return Response(response)
        except Exception:
            "if any exception thant enter into exception block"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


##theja
# showing new/asssign/closed tickets tl team his datewise count for tl under his team
class Tl_Team_datewise_countView(APIView):
    permission_classes = [IsAuthenticated,
                          IsSuperAdminPermission | IsAdminPermission | IsManagerPermission | IsTlPermission]
    serializer_class = TlwiseTeamdateTicketsSerializer

    def get(self, request):
        try:
            user_id = request.user.username
            """ getting userid """
            queryset = UserProfile.objects.get(username=user_id).team_name_id
            """ comparing the userid with userprofile(database) username and getting the teamnameid"""
            agentname = (UserProfile.objects.filter(role='Agent') & UserProfile.objects.filter(
                team_name_id=queryset)).values(full_name=Lower('fullname'))
            """1)comparing teamnameid from database with your getting id
                2) filter the agents with their roles 
                3) satisfies both above two conditions and getting their fullnames"""
            ###########New tickets
            newtickets = []
            '''empty list'''
            for fullnames in agentname:
                """ getting all agents names in list"""
                agentdata = (Sci1stKey.objects.annotate(agent_name=Lower('agent')).filter(agent_name=fullnames['full_name']).filter(
                    new_tickets_status="newtickets")).values(
                     'upload_date').order_by().annotate(Count('status'))
                """ looping the list objects and comparing the sci1st key agent names with full names from 
                                userprofile database and getting only new  tickets matches with fullnames with count values and agent names and date"""
                newtickets.append(agentdata)
                """ appending in new list"""
            new_ticketsdata = [num for elem in newtickets for num in elem]
            """looping lists [[][][]] inside list"""
            new_ticketsdata_serializer = TlwiseTeamdateTicketsSerializer(new_ticketsdata, many=True)
            '''convserting the all tickets into json by serializer'''

            ###########assign tickets
            '''same as new rickets'''
            assigntickets = []
            for fullnames in agentname:
                agentdata = (Sci1stKey.objects.annotate(agent_name=Lower('agent')).filter(agent_name=fullnames['full_name']).filter(
                    assign_tickets_status="assign")).values(
                     'assign_tickets_date').order_by().annotate(Count('status'))
                assigntickets.append(agentdata)
            assign_ticketsdata = [num for elem in assigntickets for num in elem]
            assign_ticketsdata_serializer = TlwiseTeamdateTicketsSerializer(assign_ticketsdata, many=True)

            ### pending tickets
            pendingtickets = []
            for fullnames in agentname:
                agentdata = (Sci1stKey.objects.annotate(agent_name=Lower('agent')).filter(agent_name=fullnames['full_name']).filter(
                    pending_tickets_status="pending")).values(
                     'pending_tickets_date').order_by().annotate(Count('status'))
                pendingtickets.append(agentdata)
            pending_ticketsdata = [num for elem in pendingtickets for num in elem]
            pending_ticketsdata_serializer = TlwiseTeamdateTicketsSerializer(pending_ticketsdata, many=True)

            ###########closed tickets
            closedtickets = []
            for fullnames in agentname:
                agentdata = (Sci1stKey.objects.annotate(agent_name=Lower('agent')).filter(agent_name=fullnames['full_name']).filter(status="closed")).values(
                    'completed_date').order_by().annotate(Count('status'))
                closedtickets.append(agentdata)
            closed_ticketsdata = [num for elem in closedtickets for num in elem]
            closed_ticketsdata_serializer = TlwiseTeamdateTicketsSerializer(closed_ticketsdata, many=True)

            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': {'newtickets': new_ticketsdata_serializer.data,
                         'assigntickets': assign_ticketsdata_serializer.data,
                         'pendingtickets': pending_ticketsdata_serializer.data,
                         'closed': closed_ticketsdata_serializer.data}
            }
            return Response(response)
        except Exception:
            "if any exception thant enter into exception block"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


##theja
# showing new/closed tickets previous week count for tl under his team
class Tl_Teamwise_ticketstatus_privousweek_countView(APIView):
    permission_classes = [IsAuthenticated,
                          IsSuperAdminPermission | IsAdminPermission | IsManagerPermission | IsTlPermission]

    def get(self, request):
        try:
            user_id = request.user.username
            """ getting userid """
            queryset = UserProfile.objects.get(username=user_id).team_name_id
            """ comparing the userid with userprofile(database) username and getting the teamnameid"""
            agentname = (UserProfile.objects.filter(role='Agent') & UserProfile.objects.filter(
                team_name_id=queryset)).values(full_name=Lower('fullname'))
            """1)comparing teamnameid from database with your getting id
                2) filter the agents with their roles 
                3) satisfies both above two conditions and getting their fullnames"""
            ###########New tickets
            # date = datetime.date.today()
            # start_week = date - datetime.timedelta(date.weekday())
            # end_week = start_week + datetime.timedelta(7)
            # year, week, _ = now().isocalendar()
            some_day_last_week = timezone.now().date() - timedelta(days=7)
            monday_of_last_week = some_day_last_week - timedelta(days=(some_day_last_week.isocalendar()[2] - 1))
            monday_of_this_week = monday_of_last_week + timedelta(days=7)
            """Note that I added 7 days to get the monday of the this week instead of adding 6 days to get the sunday of last week and that 
            I used created_at__lt=monday_of_this_week (instead of __lte=). I did that because if your pub_date was a DateTimeField, it wouldn't 
            include the sunday objects since the time is 00:00:00 when using now().date().
            This could easily be adjusted to consider Sunday as the first day of the week instead,
             but isocalendar() considers it the last, so I went with that."""
            newtickets = []
            '''empty list'''
            for fullnames in agentname:
                """ getting all agents names in list"""
                agentdata = (
                    Sci1stKey.objects.annotate(agent_name=Lower('agent')).filter(agent_name=fullnames['full_name']).filter(upload_date__gte=monday_of_last_week,
                                                                                 upload_date__lt=monday_of_this_week,
                                                                                 new_tickets_status='newtickets')).count()
                """ looping the list objects and comparing the sci1st key agent names with full names from 
                userprofile database and getting only uploaded date greater than and less than date ,new tickets 
                matches with fullnames with count values and agent names and date"""
                newtickets.append(agentdata)

            new_tickets_count = sum(newtickets)

            ##assign tickets
            assigntickets = []
            '''empty list'''
            for fullnames in agentname:
                agentdata = (Sci1stKey.objects.annotate(agent_name=Lower('agent')).filter(agent_name=fullnames['full_name']).filter(
                    assign_tickets_date__gte=monday_of_last_week, assign_tickets_date__lt=monday_of_this_week,
                    assign_tickets_status='assign')).count()
                assigntickets.append(agentdata)
            assign_tickets_count = sum(assigntickets)

            ##pending tickets
            pendingtickets = []
            '''empty list'''
            for fullnames in agentname:
                agentdata = (
                    Sci1stKey.objects.annotate(agent_name=Lower('agent')).filter(agent_name=fullnames['full_name']).filter(
                        pending_tickets_date__gte=monday_of_last_week,
                        pending_tickets_date__lt=monday_of_this_week,
                        pending_tickets_status='pending')).count()

                pendingtickets.append(agentdata)
            pending_tickets_count = sum(pendingtickets)

            ###########closed tickets
            '''sames as new tickets'''
            closedtickets = []
            for fullnames in agentname:
                agentdata = (Sci1stKey.objects.annotate(agent_name=Lower('agent')).filter(agent_name=fullnames['full_name']).filter(
                    completed_date__gte=monday_of_last_week, completed_date__lt=monday_of_this_week,
                    status="closed")).count()
                closedtickets.append(agentdata)
            closed_tickets_count = sum(closedtickets)
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': {'previous_week_newtickets': new_tickets_count,
                         'previous_week_assigntickets': assign_tickets_count,
                         'previous_week_pendingtickets': pending_tickets_count,
                         'previous_week_closed': closed_tickets_count}
            }

            return Response(response)
        except Exception:
            "if any exception thant enter into exception block"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


##theja
# showing new/closed tickets current week count for tl under his team
class Tl_Teamwise_ticketstatus_currentweek_countView(APIView):
    permission_classes = [IsAuthenticated,
                          IsSuperAdminPermission | IsAdminPermission | IsManagerPermission | IsTlPermission]

    def get(self, request):
        try:
            user_id = request.user.username
            """ getting userid """
            queryset = UserProfile.objects.get(username=user_id).team_name_id
            """ comparing the userid with userprofile(database) username and getting the teamnameid"""
            agentname = (UserProfile.objects.filter(role='Agent') & UserProfile.objects.filter(
                team_name_id=queryset)).values(full_name=Lower('fullname'))
            """1)comparing teamnameid from database with your getting id
                2) filter the agents with their roles 
                3) satisfies both above two conditions and getting their fullnames"""
            ###########New tickets
            date = datetime.date.today()
            '''getting today date'''
            start_week = date - datetime.timedelta(date.weekday())
            '''getting week start date'''
            end_week = start_week + datetime.timedelta(7)
            '''getting last day by adding 6 days to start week'''

            newtickets = []
            '''empty list'''
            for fullnames in agentname:
                """ getting all agents names in list"""
                agentdata = (
                    Sci1stKey.objects.annotate(agent_name=Lower('agent')).filter(agent_name=fullnames['full_name']).filter(
                        upload_date__range=[start_week, end_week], new_tickets_status='newtickets')).count()
                newtickets.append(agentdata)

            new_tickets_count = sum(newtickets)

            ##assign tixkets
            assigntickets = []
            '''empty list'''
            for fullnames in agentname:
                agentdata = (
                    Sci1stKey.objects.annotate(agent_name=Lower('agent')).filter(agent_name=fullnames['full_name']).filter(
                        assign_tickets_date__range=[start_week, end_week], assign_tickets_status='assign')).count()
                assigntickets.append(agentdata)
            assign_tickets_count = sum(assigntickets)

            # pending tickets
            pendingtickets = []
            '''empty list'''
            for fullnames in agentname:
                agentdata = (
                    Sci1stKey.objects.annotate(agent_name=Lower('agent')).filter(agent_name=fullnames['full_name']).filter(
                        pending_tickets_date__range=[start_week, end_week], pending_tickets_status='pending')).count()
                pendingtickets.append(agentdata)
            pending_tickets_count = sum(pendingtickets)

            ###########closed tickets
            closedtickets = []
            for fullnames in agentname:
                agentdata = (Sci1stKey.objects.annotate(agent_name=Lower('agent')).filter(agent_name=fullnames['full_name']).filter(
                    completed_date__range=[start_week, end_week], status="closed")).count()
                closedtickets.append(agentdata)
            closed_tickets_count = sum(closedtickets)
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': {'current_week_newtickets': new_tickets_count,
                         'current_week_assigntickets': assign_tickets_count,
                         'current_week_pendingtickets': pending_tickets_count,
                         'current_week_closed': closed_tickets_count}
            }
            return Response(response)
        except Exception:
            "if any exception thant enter into exception block"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


##theja
# showing new/closed tickets currentmonth count for tl under his team
class Tl_Teamwise_ticketstatus_currentmonth_countView(APIView):
    permission_classes = [IsAuthenticated,
                          IsSuperAdminPermission | IsAdminPermission | IsManagerPermission | IsTlPermission]
    serializer_class = TlwiseTeamdateTicketsSerializer

    def get(self, request):
        try:
            user_id = request.user.username
            """ getting userid TL1"""
            queryset = UserProfile.objects.get(username=user_id).team_name_id
            """ (TL1=TL1,team_nameid=1)comparing the userid with userprofile(database) username and getting the teamnameid"""
            agentname = (UserProfile.objects.filter(role='Agent') & UserProfile.objects.filter(
                team_name_id=queryset)).values(full_name=Lower('fullname'))
            '''getting all agent names and filtering temaname id equal to queryset (all agents,1=1) '''
            # quary = Teams.objects.filter(id=queryset).values('teamname')
            # print(quary,'q66666666')
            """1)comparing teamnameid from database with your getting id
                2) filter the agents with their roles 
                3) satisfies both above two conditions and getting their fullnames"""
            ###########New tickets
            from datetime import datetime
            current_year = datetime.now().year

            '''getting current month and year from datetime.now method'''
            current_month = datetime.now().month

            newtickets = []
            '''empty list'''
            for fullnames in agentname:
                """ getting all agents names in list"""
                agentdata = (
                    Sci1stKey.objects.annotate(agent_name=Lower('agent')).filter(agent_name=fullnames['full_name']).filter(upload_date__year=current_year,
                                                                                 upload_date__month=current_month,
                                                                                 new_tickets_status='newtickets')).count()
                """ looping the list objects and comparing the sci1st key agent names with full names from 
                userprofile database and getting only uploaded date greater than and less than date ,new tickets 
                matches with fullnames with count values and agent names and date"""
                newtickets.append(agentdata)
            new_tickets_count = (sum(newtickets))


            ##asign tickets
            assigntickets = []
            '''empty list'''
            for fullnames in agentname:
                agentdata = (
                    Sci1stKey.objects.annotate(agent_name=Lower('agent')).filter(agent_name=fullnames['full_name']).filter(assign_tickets_date__year=current_year,
                                                                                 assign_tickets_date__month=current_month,
                                                                                 assign_tickets_status='assign')).count()
                assigntickets.append(agentdata)
            assign_tickets_count = (sum(assigntickets))

            ##pending tickets

            pendingtickets = []
            '''empty list'''
            for fullnames in agentname:
                agentdata = (
                    Sci1stKey.objects.annotate(agent_name=Lower('agent')).filter(agent_name=fullnames['full_name']).filter(
                        pending_tickets_date__year=current_year,
                        pending_tickets_date__month=current_month,
                        pending_tickets_status='pending')).count()
                pendingtickets.append(agentdata)
            pending_tickets_count = (sum(pendingtickets))


            ###########closed tickets
            '''sames as new tickets'''
            closedtickets = []
            for fullnames in agentname:
                agentdata = (Sci1stKey.objects.annotate(agent_name=Lower('agent')).filter(agent_name=fullnames['full_name']).filter(
                    completed_date__year=current_year, completed_date__month=current_month,
                    status="closed")).count()
                closedtickets.append(agentdata)
            closed_tickets_count = (sum(closedtickets))

            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': {'current_month_newtickets': new_tickets_count,
                         'current_month_assigntickets': assign_tickets_count,
                         'current_month_peningtickets': pending_tickets_count,
                         'current_month_closed': closed_tickets_count}
            }
            return Response(response)
        except Exception:
            "if any exception thant enter into exception block"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


##theja
# showing new/closed tickets previousmonth count for tl under his team
class Tl_Teamwise_ticketstatus_previousmonth_countView(APIView):
    permission_classes = [IsAuthenticated,
                          IsSuperAdminPermission | IsAdminPermission | IsManagerPermission | IsTlPermission]
    serializer_class = TlwiseTeamdateTicketsSerializer

    def get(self, request):
        try:
            user_id = request.user.username
            """ getting userid """
            queryset = UserProfile.objects.get(username=user_id).team_name_id

            """ comparing the userid with userprofile(database) username and getting the teamnameid"""
            agentname = (UserProfile.objects.filter(role='Agent') & UserProfile.objects.filter(
                team_name_id=queryset)).values(full_name=Lower('fullname'))
            """1)comparing teamnameid from database with your getting id
                2) filter the agents with their roles 
                3) satisfies both above two conditions and getting their fullnames"""
            ###########New tickets
            last_day_of_prev_month = date.today().replace(day=1) - timedelta(days=1)
            '''getting last date of previous month'''
            start_day_of_prev_month = date.today().replace(day=1) - timedelta(days=last_day_of_prev_month.day)
            '''getting 1st date of month'''
            newtickets = []
            '''empty list'''
            for fullnames in agentname:
                """ getting all agents names in list"""
                agentdata = (Sci1stKey.objects.annotate(agent_name=Lower('agent')).filter(agent_name=fullnames['full_name']).filter(
                    upload_date__lte=last_day_of_prev_month,
                    upload_date__gte=start_day_of_prev_month,
                    new_tickets_status='newtickets')).count()
                """ looping the list objects and comparing the sci1st key agent names with full names from 
                userprofile database and getting only uploaded date greater than and less than date ,new tickets 
                matches with fullnames with count values and agent names and date"""
                '''upload date will be less than are equal to last day of the month '''
                '''upload date will be greater than are equal to starting day of the month '''
                newtickets.append(agentdata)

            new_tickets_count = sum(newtickets)

            ##assign tickets
            assigntickets = []
            '''empty list'''
            for fullnames in agentname:
                agentdata = (Sci1stKey.objects.annotate(agent_name=Lower('agent')).filter(agent_name=fullnames['full_name']).filter(
                    assign_tickets_date__lte=last_day_of_prev_month,
                    assign_tickets_date__gte=start_day_of_prev_month,
                    assign_tickets_status='assign')).count()
                assigntickets.append(agentdata)

            assign_tickets_count = sum(assigntickets)

            ##pending
            pendingtickets = []
            '''empty list'''
            for fullnames in agentname:
                agentdata = (Sci1stKey.objects.annotate(agent_name=Lower('agent')).filter(agent_name=fullnames['full_name']).filter(
                    pending_tickets_date__lte=last_day_of_prev_month,
                    pending_tickets_date__gte=start_day_of_prev_month,
                    pending_tickets_status='pending')).count()
                pendingtickets.append(agentdata)
            pending_tickets_count = sum(pendingtickets)

            ###########closed tickets
            '''sames as new tickets'''
            closedtickets = []
            for fullnames in agentname:
                agentdata = (Sci1stKey.objects.annotate(agent_name=Lower('agent')).filter(agent_name=fullnames['full_name']).filter(
                    completed_date__lte=last_day_of_prev_month, completed_date__gte=start_day_of_prev_month,
                    status="closed")).count()

                closedtickets.append(agentdata)

            closed_tickets_count = sum(closedtickets)
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': {'previous_month_newtickets': new_tickets_count,
                         'previous_month_assigntickets': assign_tickets_count,
                         'previous_month_pendingtickets': pending_tickets_count,
                         'previous_month_closed': closed_tickets_count}
            }
            return Response(response)
        except Exception:
            "if any exception thant enter into exception block"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


##theja
###Agent can view only his new/assign/pending/closed tickets count
class Agent_ticket_status_count(APIView):
    permission_classes = [IsAuthenticated,
                          IsSuperAdminPermission | IsAdminPermission | IsManagerPermission | IsAgentPermission]
    serializer_class = TlwiseTeamdateTicketsSerializer

    def get(self, request):
        try:
            user_fullname = request.user.fullname
            """ getting fullname of user """
            agent_new_tickets = Sci1stKey.objects.filter(agent=user_fullname).filter(status='newtickets').count()
            '''using the username equalizing the agent name which is mention in the sci1stkey database then getting the newtickets/assign/pending etc count values'''
            agent_assign_tickets = Sci1stKey.objects.filter(agent=user_fullname).filter(status='assign').count()
            agent_pending_tickets = Sci1stKey.objects.filter(agent=user_fullname).filter(status='pending').count()
            agent_closed_tickets = Sci1stKey.objects.filter(agent=user_fullname).filter(status='closed').count()
            total_count = agent_new_tickets + agent_assign_tickets + agent_pending_tickets + agent_closed_tickets
            # context = {"agent_newtickets_count": agent_new_tickets, 'agent_assigntickets_count': agent_assign_tickets,
            #            'agent_pendingtickets_count': agent_pending_tickets,
            #            'agent_closedtickets_count': agent_closed_tickets}
            '''putting in the dic'''

            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': [{"totalticketscount": total_count},
                         {"newticketscount": agent_new_tickets},
                         {'assignticketscount': agent_assign_tickets},
                         {'pendingticketscount': agent_pending_tickets},
                         {'closedticketscount': agent_closed_tickets}
                         ]
            }
            '''putting in the dic'''
            return Response(response)
        except Exception:
            "if any exception thant enter into exception block"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


##theja
###Agent can view only his exception/notfound/completed tickets count
class Agent_process_status_count(APIView):
    permission_classes = [IsAuthenticated,
                          IsSuperAdminPermission | IsAdminPermission | IsManagerPermission | IsAgentPermission]

    serializer_class = TlwiseTeamdateTicketsSerializer

    def get(self, request):
        try:
            user_fullname = request.user.fullname
            """ getting fullname from user """
            agent_exception_tickets = Sci1stKey.objects.filter(agent=user_fullname).filter(status='closed',
                                                                                           process_status='exception').count()
            '''using the username equalizing the agent name which is mention in the sci1stkey database then getting the exception/notfound etc count values'''
            agent_notfound_tickets = Sci1stKey.objects.filter(agent=user_fullname).filter(status='closed',
                                                                                          process_status='notfound').count()
            agent_completd_tickets = Sci1stKey.objects.filter(agent=user_fullname).filter(status='closed',
                                                                                          process_status='completed').count()
            # context = {"agent_exceptiontickets_count": agent_exception_tickets, 'agent_notfoundtickets_count': agent_notfound_tickets,
            #            'agent_completedtickets_count': agent_completd_tickets}

            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': [{"notfoundticketscount": agent_notfound_tickets},
                         {"exceptionticketscount": agent_exception_tickets},
                         {'completedticketscount': agent_completd_tickets}]
            }
            return Response(response)
        except Exception:
            "if any exception thant enter into exception block"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


##theja
###Agent can view only his date wise count tickets
class Agent_datewise_ticketstatus_count(APIView):
    permission_classes = [IsAuthenticated,
                          IsSuperAdminPermission | IsAdminPermission | IsManagerPermission | IsAgentPermission]
    serializer_class = TlwiseTeamdateTicketsSerializer

    def get(self, request):
        try:
            user_fullname = request.user.fullname
            """ getting fullname """
            agent_new_tickets = (
                Sci1stKey.objects.filter(agent=user_fullname).filter(new_tickets_status="newtickets")).values(
                'upload_date').order_by().annotate(Count('status'))
            """1)filtering agents using  userfull name
                2) filter the agents with the newtickets 
              3) Group By agents and uploade_date
              4)Select the count of the grouping"""
            agent_new_ticketsdata_serializer = TlwiseTeamdateTicketsSerializer(agent_new_tickets, many=True)
            ''''serializering the data'''
            agent_assign_tickets = (
                Sci1stKey.objects.filter(agent=user_fullname).filter(assign_tickets_status="assign")).values(
                'assign_tickets_date').order_by().annotate(Count('status'))
            agent_assign_ticketsdata_serializer = TlwiseTeamdateTicketsSerializer(agent_assign_tickets, many=True)
            agent_pending_tickets = (
                Sci1stKey.objects.filter(agent=user_fullname).filter(pending_tickets_status="pending")).values(
                'pending_tickets_date').order_by().annotate(Count('status'))
            agent_pending_ticketsdata_serializer = TlwiseTeamdateTicketsSerializer(agent_pending_tickets, many=True)
            agent_closed_tickets = (Sci1stKey.objects.filter(agent=user_fullname).filter(status="closed")).values(
                'completed_date').order_by().annotate(Count('status'))
            agent_closed_ticketsdata_serializer = TlwiseTeamdateTicketsSerializer(agent_closed_tickets, many=True)

            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': {'agent_newtickets_count': agent_new_ticketsdata_serializer.data,
                         'agent_assigntickets_count': agent_assign_ticketsdata_serializer.data,
                         'agent_pendingtickets_count': agent_pending_ticketsdata_serializer.data,
                         'agent_closedtickets_count': agent_closed_ticketsdata_serializer.data}
            }
            '''returning the respnse'''
            return Response(response)
        except Exception:
            "if any exception thant enter into exception block"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


# theja
###showing Agent his new tickets list
class AgentNewticketsTicketsListApiView(generics.ListAPIView):
    """
    fetching the serializer and Scikey data
    """
    queryset = Sci1stKey.objects.all()
    serializer_class = AgentOwnTicketsSerializer
    # authentication token and permissions of user we can change permissions
    permission_classes = (permissions.IsAuthenticated, IsSuperAdminPermission | IsAgentPermission)

    def get(self, request, *args, **kwargs):
        '''
        get the login user (agent)  particular all tickets
        :param request:
        :param args:
        :param kwargs:
        :return:
        '''
        user_name = request.user.username
        '''gettin paricular username'''
        try:
            queryset = Sci1stKey.objects.filter(status="newtickets", agent=user_name)
            '''filtering the newtickets under his name'''
            user_serializer = AgentOwnTicketsSerializer(queryset, many=True)
            '''getting the serializing data'''
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': user_serializer.data
            }
            return Response(response)
        except:
            return Response(
                {'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


# theja
###showing Agent his closed tickets list
class AgentClosedticketsTicketsListApiView(generics.ListAPIView):
    """
    fetching the serializer and Scikey data
    """
    queryset = Sci1stKey.objects.all()
    serializer_class = AgentOwnTicketsSerializer
    # authentication token and permissions of user we can change permissions
    permission_classes = (permissions.IsAuthenticated, IsSuperAdminPermission | IsAgentPermission)

    def get(self, request, *args, **kwargs):
        '''
        get the login user (agent)  particular all tickets
        :param request:
        :param args:
        :param kwargs:
        :return:
        '''
        user_name = request.user.username
        '''getting paricular username'''
        try:
            queryset = Sci1stKey.objects.filter(status="closed", agent=user_name)
            '''filtering the closed tickets under his name'''
            user_serializer = AgentOwnTicketsSerializer(queryset, many=True)
            '''getting the serializing data'''
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': user_serializer.data
            }
            '''sending the json response'''
            return Response(response)
        except:
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


# creating class to show all tikets without authentication
# asked by rohit
class ALLTicketListViewView(APIView):
    def get(self, request, format=None):
        # fetching model object
        try:
            scikeylist = Sci1stKey.objects.all()
            '''getting all tickets'''
            serializer = ScikeylistSerializer(scikeylist, many=True)
            # return response
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': serializer.data
            }
            '''sending the json response'''
            return Response(response)

        except:
            return Response(status=status.HTTP_404_NOT_FOUND)


"*****Admin Current week/month and previous week/month reports"


class Admin_ticketstatus_privousmonth_countView(APIView):
    permission_classes = [IsAuthenticated,
                          IsSuperAdminPermission | IsAdminPermission | IsManagerPermission]

    def get(self, request):
        try:
            ##########New tickets
            last_day_of_prev_month = date.today().replace(day=1) - timedelta(days=1)
            '''getting last date of previous month'''
            start_day_of_prev_month = date.today().replace(day=1) - timedelta(days=last_day_of_prev_month.day)
            '''getting 1st date of month'''
            newtickets = []
            '''empty list'''

            """ getting all agents names in list"""
            agentdata = (Sci1stKey.objects.filter(upload_date__lte=last_day_of_prev_month,
                                                  upload_date__gte=start_day_of_prev_month,
                                                  new_tickets_status='newtickets')).count()
            newtickets.append(agentdata)
            """ appending in new list"""
            new_tickets_count = sum(newtickets)

            ##assign tickets
            assigntickets = []

            agentdata = (Sci1stKey.objects.filter(
                assign_tickets_date__lte=last_day_of_prev_month,
                assign_tickets_date__gte=start_day_of_prev_month,
                assign_tickets_status='assign')).count()
            assigntickets.append(agentdata)
            assign_tickets_count = sum(assigntickets)

            ##pending
            pendingtickets = []
            '''empty list'''
            agentdata = (Sci1stKey.objects.filter(
                pending_tickets_date__lte=last_day_of_prev_month,
                pending_tickets_date__gte=start_day_of_prev_month,
                pending_tickets_status='pending')).count()
            pendingtickets.append(agentdata)
            pending_tickets_count = sum(pendingtickets)

            ###########closed tickets
            '''sames as new tickets'''
            closedtickets = []
            agentdata = (Sci1stKey.objects.filter(
                completed_date__lte=last_day_of_prev_month, completed_date__gte=start_day_of_prev_month,
                status="closed")).count()
            closedtickets.append(agentdata)

            closed_tickets_count = sum(closedtickets)
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': {'previous_month_newtickets': new_tickets_count,
                         'previous_month_assigntickets': assign_tickets_count,
                         'previous_month_pendingtickets': pending_tickets_count,
                         'previous_month_closed': closed_tickets_count}
            }
            return Response(response)
        except Exception:
            "if any exception thant enter into exception block"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


class Admin_ticketstatus_currentmonth_countView(APIView):
    permission_classes = [IsAuthenticated,
                          IsSuperAdminPermission | IsAdminPermission | IsManagerPermission]

    def get(self, request):
        try:
            ###########New tickets
            from datetime import datetime
            current_year = datetime.now().year
            '''getting current month and year from datetime.now method'''
            current_month = datetime.now().month
            newtickets = []
            '''empty list'''
            agentdata = (
                Sci1stKey.objects.filter(upload_date__year=current_year, upload_date__month=current_month,
                                         new_tickets_status='newtickets')).count()

            newtickets.append(agentdata)
            new_tickets_count = sum(newtickets)

            ##asign tickets
            assigntickets = []

            agentdata = (
                Sci1stKey.objects.filter(assign_tickets_date__year=current_year,
                                         assign_tickets_date__month=current_month,
                                         assign_tickets_status='assign')).count()
            assigntickets.append(agentdata)
            assign_tickets_count = sum(assigntickets)

            ##pending tickets

            pendingtickets = []
            '''empty list'''
            agentdata = (
                Sci1stKey.objects.filter(pending_tickets_date__year=current_year,
                                         pending_tickets_date__month=current_month,
                                         pending_tickets_status='pending')).count()
            pendingtickets.append(agentdata)
            pending_tickets_count = sum(pendingtickets)

            ###########closed tickets
            '''sames as new tickets'''
            closedtickets = []

            agentdata = (Sci1stKey.objects.filter(
                completed_date__year=current_year, completed_date__month=current_month,
                status="closed")).count()
            closedtickets.append(agentdata)
            closed_tickets_count = sum(closedtickets)

            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': {'current_month_newtickets': new_tickets_count,
                         'current_month_assigntickets': assign_tickets_count,
                         'current_month_peningtickets': pending_tickets_count,
                         'current_month_closed': closed_tickets_count}
            }
            return Response(response)
        except Exception:
            "if any exception thant enter into exception block"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


class Admin_ticketstatus_privousweek_countView(APIView):
    permission_classes = [IsAuthenticated,
                          IsSuperAdminPermission | IsAdminPermission | IsManagerPermission | IsTlPermission]

    def get(self, request):
        try:
            ###########New tickets
            # date = datetime.date.today()
            # start_week = date - datetime.timedelta(date.weekday())
            # end_week = start_week + datetime.timedelta(7)
            # year, week, _ = now().isocalendar()
            some_day_last_week = timezone.now().date() - timedelta(days=7)
            monday_of_last_week = some_day_last_week - timedelta(days=(some_day_last_week.isocalendar()[2] - 1))
            monday_of_this_week = monday_of_last_week + timedelta(days=7)
            """Note that I added 7 days to get the monday of the this week instead of adding 6 days to get the sunday of last week and that 
            I used created_at__lt=monday_of_this_week (instead of __lte=). I did that because if your pub_date was a DateTimeField, it wouldn't 
            include the sunday objects since the time is 00:00:00 when using now().date().
            This could easily be adjusted to consider Sunday as the first day of the week instead,
             but isocalendar() considers it the last, so I went with that."""
            newtickets = []
            '''empty list'''

            agentdata = (
                Sci1stKey.objects.filter(upload_date__gte=monday_of_last_week,
                                         upload_date__lt=monday_of_this_week,
                                         new_tickets_status='newtickets')).count()
            """ looping the list objects and comparing the sci1st key agent names with full names from 
                userprofile database and getting only uploaded date greater than and less than date ,new tickets 
                matches with fullnames with count values and agent names and date"""
            newtickets.append(agentdata)

            new_tickets_count = sum(newtickets)

            ##assign tickets
            assigntickets = []
            '''empty list'''
            agentdata = (Sci1stKey.objects.filter(
                assign_tickets_date__gte=monday_of_last_week, assign_tickets_date__lt=monday_of_this_week,
                assign_tickets_status='assign')).count()
            assigntickets.append(agentdata)
            assign_tickets_count = sum(assigntickets)

            ##pending tickets
            pendingtickets = []
            '''empty list'''

            agentdata = (
                Sci1stKey.objects.filter(
                    pending_tickets_date__gte=monday_of_last_week,
                    pending_tickets_date__lt=monday_of_this_week,
                    pending_tickets_status='pending')).count()

            pendingtickets.append(agentdata)
            pending_tickets_count = sum(pendingtickets)

            ###########closed tickets
            '''sames as new tickets'''
            closedtickets = []
            agentdata = (Sci1stKey.objects.filter(
                completed_date__gte=monday_of_last_week, completed_date__lt=monday_of_this_week,
                status="closed")).count()
            closedtickets.append(agentdata)
            closed_tickets_count = sum(closedtickets)
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': {'previous_week_newtickets': new_tickets_count,
                         'previous_week_assigntickets': assign_tickets_count,
                         'previous_week_pendingtickets': pending_tickets_count,
                         'previous_week_closed': closed_tickets_count}
            }

            return Response(response)
        except Exception:
            "if any exception thant enter into exception block"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


class Admin_ticketstatus_currentweek_countView(APIView):
    permission_classes = [IsAuthenticated,
                          IsSuperAdminPermission | IsAdminPermission | IsManagerPermission | IsTlPermission]

    def get(self, request):
        try:

            ###########New tickets
            date = datetime.date.today()
            '''getting today date'''
            start_week = date - datetime.timedelta(date.weekday())
            '''getting week start date'''
            end_week = start_week + datetime.timedelta(7)
            '''getting last day by adding 6 days to start week'''

            newtickets = []
            '''empty list'''

            agentdata = (
                Sci1stKey.objects.filter(
                    upload_date__range=[start_week, end_week], new_tickets_status='newtickets')).count()
            newtickets.append(agentdata)

            new_tickets_count = sum(newtickets)

            ##assign tixkets
            assigntickets = []
            '''empty list'''

            agentdata = (
                Sci1stKey.objects.filter(
                    assign_tickets_date__range=[start_week, end_week], assign_tickets_status='assign')).count()
            assigntickets.append(agentdata)
            assign_tickets_count = sum(assigntickets)

            # pending tickets
            pendingtickets = []
            '''empty list'''

            agentdata = (
                Sci1stKey.objects.filter(
                    pending_tickets_date__range=[start_week, end_week], pending_tickets_status='pending')).count()
            pendingtickets.append(agentdata)
            pending_tickets_count = sum(pendingtickets)

            ###########closed tickets
            closedtickets = []

            agentdata = (Sci1stKey.objects.filter(
                completed_date__range=[start_week, end_week], status="closed")).count()
            closedtickets.append(agentdata)
            closed_tickets_count = sum(closedtickets)
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': {'current_week_newtickets': new_tickets_count,
                         'current_week_assigntickets': assign_tickets_count,
                         'current_week_pendingtickets': pending_tickets_count,
                         'current_week_closed': closed_tickets_count}
            }
            return Response(response)
        except Exception:
            "if any exception thant enter into exception block"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


"**********************************************Prasanth**************************************************************************"


class AllTlReAssign_Tickets_ListApi_View(APIView):
    permission_classes = [IsTlPermission, IsAdminPermission | IsManagerPermission | IsTlPermission]
    """
        fetching the serializer and Scikey data
    """
    serializer_class = TlReassignAgentsSerializer
    queryset = UserProfile.objects.all()

    def get(self, request, *args, **kwargs):
        '''
        get the login user (TL)  particular all tickets
        :param request:
        :param args:
        :param kwargs:
        :return:
        '''
        try:
            user_id = request.user.username
            """ getting userid """
            queryset = UserProfile.objects.get(username=user_id).team_name_id
            """ comparing the userid with userprofile(database) username and getting the teamnameid"""
            agentfilter = UserProfile.objects.filter(role='Agent')

            """ filter the agents with their roles from database"""
            agent_names = (UserProfile.objects.filter(team_name_id=queryset) & agentfilter).values('username')
            """1)comparing teamnameid from database with your getting id
              2) filter the agents with their roles 
              3) satisfies both above two conditions and getting their fullnames"""
            res = []
            for username in agent_names:
                #     # selecting id
                nameslist = (username["username"])
                #     userslist.append(k)
                """ getting all agents names in list"""
                # agentdata = Sci1stKey.objects.filter(agent=fullname['fullname']).all().filter(status="closed")
                """ looping the list objects and comparing the sci1st key agent names with full names from 
                userprofile database and getting only assign tickets matches with fullnames"""
                res.append(nameslist)
                """ appending in new list"""
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': {'username': res}
            }
            return Response(response)
        except (UserProfile.DoesNotExist, ValidationError):
            "if any exception thant enter into exception block"
            return Response({'message': 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)


## prashanth
## get the particular agent with his all tickets
class TLTicketreassignAgentDetailview(APIView):
    permission_classes = [IsAuthenticated,
                          IsSuperAdminPermission | IsAdminPermission | IsManagerPermission | IsTlPermission]

    def get_object(self, agent):
        # queryset = Sci1stKey.objects.filter(agent=agent)
        try:
            queryset = Sci1stKey.objects.filter(agent=agent).filter(status='assign')
            data = list(queryset)
            # user_serializer = AgentOwnTicketsSerializer(queryset, many=True)
            return queryset
        except Sci1stKey.DoesNotExist:
            raise Http404

    def get(self, request, agent=None, *args, **kwargs):
        if agent:
            calobj = self.get_object(agent)
            serializer = ReAssigntickets_listSerializer(calobj, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            alldata = Sci1stKey.objects.all()
            serializer = ReAssigntickets_listSerializer(alldata, many=True)
            return Response(serializer.data, status=status.HTTP_404_NOT_FOUND)


## prashanth
## reassign to another user class
class TLTicketreassign_to_agentsCompleteview(APIView):
    permission_classes = [IsAuthenticated,
                          IsSuperAdminPermission | IsAdminPermission | IsManagerPermission | IsTlPermission]
    ## fetching serializer data
    serializer_class = TicketreassignAgentsCompleteSerializer

    def put(self, request):
        """
        This function is used for get the agent name and agent tickets
        once get the tickets and assign agent name , this function is update the tickets
        to exact agent
        """
        serializer = self.serializer_class(data=request.data)
        try:
            agent_name = request.data['agent']
            id = request.data['id']
            values = id.split(',')
            user = Sci1stKey.objects.filter(id__in=values)
            for x in user:
                x.status = 'assign'
                x.save()
                user.update(agent=agent_name)
            return Response({"message": "sucessfully reassigned tickets"}, status=status.HTTP_200_OK)
        except Exception:
            "if any exception thant enter into exception block"
            return Response({'message': 'please select agent name and tickets'}, status=status.HTTP_404_NOT_FOUND)




##prasanth & theja
class Logout(GenericAPIView):
    serializer_class = RefreshTokenSerializer

    # permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args):
        sz = self.get_serializer(data=request.data)
        '''getting serializers data (only refresh token)'''
        sz.is_valid(raise_exception=True)
        '''if token is invalid raise the exception'''
        data = sz.data
        '''assign variable to the serializer data'''
        user = OutstandingToken.objects.get(token=data['refresh']).user_id
        '''getting the user_id based on the token stored in the Outstandingtoken table'''
        m = datetime.date.today()
        '''today data and time '''
        # name = AllLogout.objects.filter(user_id=user, logout_date=m)
        # '''filter the userid and logout data'''
        # for x in name:
        #     '''looping the userid and date '''
        #     '''storing the last logout time'''
        #     if x.logout_date == datetime.date.today():
        #         '''checking the condition if logout data equal to today date'''
        #         x.logout_date = datetime.date.today()
        #         x.save()
        #         '''saving the date as it is'''
        #         times = datetime.datetime.now()
        #         '''getting the time'''
        #         name.update(logout_time=times)
        #         '''updating the logout time'''
        #         break
        # else:
        user = OutstandingToken.objects.get(token=data['refresh']).user_id
        '''getting the user_id based on the token stored in the Outstandingtoken table'''
        m = datetime.date.today()
        '''getting the today date'''
        name = AllLogout.objects.create(user_id=user, logout_date=m)
        '''creating the new record if it is  new date '''
        name.save()
        sz.save()  ###saving the token in outstanding table
        return Response({'message': 'Succssfully Logout'}, status=status.HTTP_204_NO_CONTENT)



class DynamicQueries(APIView):
    permission_classes = [IsAuthenticated, IsSuperAdminPermission]

    def post(self, request, format=None):
        try:
            curser = connection.cursor()
            # connect the db server
            curser.execute(request.data['data'])
            # get the model name here(frontend)
            return Response('table is cretaed', status=status.HTTP_201_CREATED)
        except:
            return Response('please check your raw data query&table is already created with this name',
                            status=status.HTTP_404_NOT_FOUND)


class ShemaImports(APIView):
    permission_classes = [IsAuthenticated, IsSuperAdminPermission]

    def post(self, request, format=None):
        '''converting postgressql to django models
            eg :postgredata: varchar , tables name(table) ,,,
             converting django models
            eg:models(Table) CharField ,,, '''
        management.call_command('inspectdb')
        try:
            # after converting postgre data storing into django models
            with open('C:/Users/DELL/Downloads/arxt/Apis/XT01/dynamicapp/models.py', 'w') as f:
                call_command('inspectdb', stdout=f)
            return Response('schema imported into django models', status=status.HTTP_201_CREATED)
        except:
            return Response('your path is not defined properly ,please check your path',
                            status=status.HTTP_404_NOT_FOUND)



class AllModels(APIView):
    permission_classes = [IsAuthenticated, IsSuperAdminPermission]

    def get(self, request, format=None):
        try:
            # fetching all tables
            models = {
                model.__name__: model for model in apps.get_models()
            }
            # avalible models not required models
            data = ["LogEntry", "Permission", "Group", "ContentType", "Session", "Teams", "UserProfile", "Sci1stKey",
                    "AllLogin", "AllLogout", "UseradministrationAlllogin", "UseradministrationAlllogout",
                    "UseradministrationSci1Stkey",
                    "UseradministrationTeams", "UseradministrationUserprofile", "UseradministrationUserprofileGroups",
                    "UseradministrationUserprofileUserPermissions", "AuthGroup", "AuthGroupPermissions",
                    "AuthPermission",
                    "AuthtokenToken", "DjangoAdminLog", "DjangoContentType", "DjangoMigrations", "DjangoSession",
                    "TokenBlacklistBlacklistedtoken", "TokenBlacklistOutstandingtoken", "Token", "TokenProxy",
                    "OutstandingToken", "BlacklistedToken"]
            
            # get the table here        
            model_data = models
            # store all tables in dynamic data
            # data is not availble in dynamic models just storing and send the response
            dynamic_data = []
            for elem in model_data:
                if elem not in data:
                    dynamic_data.append(elem)
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': dynamic_data
            }
            return Response(response)
        except:
            return Response('no models in your database please check your database', status=status.HTTP_404_NOT_FOUND)



class SelectedTables(APIView):
    permission_classes = [IsAuthenticated, IsSuperAdminPermission]

    def post(self, request, format=None):
        try:
            # select table name here (front-end name)
            model = request.data['table']
            # converting table name to queryset
            model = apps.get_model('dynamicapp', model)
            # get the table name and send the response
            data = model.objects.all()
            # data = data.data
            fields = [f.name for f in model._meta.fields]
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'data': fields
            }
            return Response(response)
        except:
            return Response('please select any table / table data not found', status=status.HTTP_404_NOT_FOUND)





class Readingxldata(APIView):
    serializer_class = FileUploadSerializer

    def post(self, request, *args, **kwargs):

        '''
        This function is used for post data into database of particuar model and
            method is POST this method is used for only post the data and this function
            contating serializer data fetching serializer data and
            validating data and loading into the data with the file format
        '''
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        dataset = Dataset()
        # fetching file
        file = serializer.validated_data['file']

        try:
            imported_data = dataset.load(file.read(), format='xlsx')
            #  for fruit in fruit_serializer.data:
            #  for data in fruit
            #  ws.append([fruit[data] for h in headers])
            '''
            uploading xl file with particular data what user mentioned in xl we are looping the xl data
                    and appending into the database with same fields
                    '''
            for data in imported_data:
                print(data, 'gggggggggggggggggggggggggg')
                pass
            return Response("response")
        except:
            return Response('please select any table / table data not found', status=status.HTTP_404_NOT_FOUND)
