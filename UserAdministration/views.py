from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import render
from rest_framework.decorators import api_view, permission_classes
from rest_framework.generics import get_object_or_404
from rest_framework.parsers import JSONParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status, views, response
from rest_framework import generics,mixins
from rest_framework.views import APIView
from tablib import Dataset
from django.contrib.auth.hashers import make_password
from .serializers import *
import json
from rest_framework import permissions
from UserAdministration.manager_permissions import IsManagerPermission

##prasanth
#user Registration
class RegisterApi(generics.GenericAPIView):
    # fetching serializer data
    serializer_class = UserSerializer
    # adding authentications & auth user with role
    authentication_classes = []

    # post method for user registration
    def post(self, request, *args,  **kwargs):
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
            return Response({"message": "User Created Successfully.  Now perform Login to get your token"},status=status.HTTP_201_CREATED)
        else:
            return Response({'user name already exist'},status=status.HTTP_406_NOT_ACCEPTABLE)


##prasanth
#user Login
class LoginAPIView(generics.GenericAPIView):
    # adding authentications & auth user with role
    permission_classes = []
    # fetching serializer data
    serializer_class = LoginSerializer

    def post(self,request):
        '''
        getting serializer data and checking validating data sending data
        into the responce body with status code
        '''
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data,status=status.HTTP_200_OK)

##theja
##changing password
class ChangePasswordView(generics.UpdateAPIView):
    '''
    This class is used for get the user and change user password
    '''

    ## authentication token and permissions of user we can change permissions
    permission_classes = (IsAuthenticated,)
    # get the model data
    queryset = UserProfile.objects.all()
    serializer_class = ChangePasswordSerializers


class Update_his_ProfileView(generics.UpdateAPIView):
    '''
    This class is used for get the user and update his profile details
    '''
    ## authentication token and permissions of user we can change permissions
    permission_classes = (IsAuthenticated,)
    # get the model data
    queryset = UserProfile.objects.all()
    # fetch serializer
    serializer_class = Update_his_profile_Serializer

##theja
# Adding Teams by Admin
class Addingteams(generics.GenericAPIView):
    ## authentication token and permissions of user we can change permissions
    permission_classes = []
    # fetch serializer data
    serializer_class = Teamserialsers

    def post(self, request, *args,  **kwargs):
        '''
        This function is used for post the data of adding teams
        '''
        parameters = request.data.copy()
        serializer = self.get_serializer(data=parameters)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"message": "Teams Created Successfully."},status=status.HTTP_201_CREATED)
        else:
            return Response({'Team name already exist'},status=status.HTTP_406_NOT_ACCEPTABLE)

##theja
# View all_Team  by Admin
class Team_ListView(APIView):
    ## authentication token and permissions of user we can change permissions
    permission_classes = []
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
        tutorial_data = JSONParser().parse(request)
        tutorial_serializer = Teamserialsers(tutorial, data=tutorial_data)
        if tutorial_serializer.is_valid():
            tutorial_serializer.save()
            return JsonResponse(tutorial_serializer.data,)
        return JsonResponse(tutorial_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        tutorial.delete()
        return JsonResponse({'message': 'Team was deleted successfully!'}, status=status.HTTP_204_NO_CONTENT)


##theja
# All Persons(user Profile) by Admin
class User_listApiview(APIView):
    ## authentication token and permissions of user we can add permissions
    permission_classes = []

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
        tutorial_data = JSONParser().parse(request)
        tutorial_serializer = UserProfileSerializer(tutorial, data=tutorial_data)
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


##prasanth
class UploadFileView(APIView):
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
                sci_data=Sci1stKey(projectId=data[0],
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
            return Response({'sucessfully uploaded your file'},status=status.HTTP_200_OK)
        except:
            # return response
            return Response(
                {'please select proper file'}, status=status.HTTP_404_NOT_FOUND)


##prasanth
class SciListViewView(APIView):
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
class SciKeyAssignTicketsAPIView(generics.GenericAPIView):
    # fetching serilizer
    serializer_class = ScikeyAssignSerializer

    def post(self, request, *args, **kwargs):
        """
        this method is used for update single record or multiple record
            and update the status of sci ticket
        """
        # get the ticket status from
        status_sci = request.data.get('status')
        # get the model with newtickets
        user = Sci1stKey.objects.filter(status="newtickets")
        for user_status in user:
            user_status.status='assign'
            user_status.save()
            # update status
            user.update(status="assign")
            return Response({'sucessfully updated your status'}, status=status.HTTP_200_OK)
        else:
            return Response(
                {'your status is not valid please enter valid status'}, status=status.HTTP_406_NOT_ACCEPTABLE)



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
class SciKeyAllTicketsCountAPIView(APIView):
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
        completed_tickets_count = Sci1stKey.objects.filter(status="completed").count()
        context = {"new": new_tickets_count,'assign':assign_tickets_count,'completed':completed_tickets_count}
        return Response(json.dumps(context), status=status.HTTP_200_OK)


# prashanth
class SciKeyAssignTicketsListAPIView(generics.ListAPIView):
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
class SciKeyClosedTicketsListAPIView(generics.ListAPIView):
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
class SciKeyNewTicketsListAPIView(generics.ListAPIView):
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
            # return responce data
            return Response(user_serializer.data)
        except:
            return Response(
                {'sorry dont have any newtickets ticktes'}, status=status.HTTP_404_NOT_FOUND)

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


# prashanth
from .agent_permissions import *
class AgentOwnTicketsListApiView(generics.ListAPIView):

    """
    fetching the serializer and Scikey data
    """
    queryset = Sci1stKey.objects.all()
    serializer_class = AgentOwnTicketsSerializer
    # authentication token and permissions of user we can change permissions
    permission_classes = (permissions.IsAuthenticated, IsAgentPermission)

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
            queryset = Sci1stKey.objects.filter(status="assign",agent=user_id)
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


import datetime
# prashanth
class AgentDetailTicketsListApiView(generics.GenericAPIView,mixins.UpdateModelMixin,
                                 mixins.RetrieveModelMixin, mixins.DestroyModelMixin):
    """
    fetching the serializer and Scikey data
    """
    queryset = Sci1stKey.objects.all()
    serializer_class = AgentRetriveSerializer
    # authentication token and permissions of user we can change permissions
    permission_classes = (permissions.IsAuthenticated, IsAgentPermission)
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
                x.start_time_ticket = datetime.datetime.now()
                x.save()
                qs.update(start_time_ticket=datetime.datetime.now())
                return Sci1stKey.objects.get(id=id,status="assign", process_status="emty")
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
        # qs = Sci1stKey.objects.filter(id=id).values_list('agent')
        # for i in qs:
        #     a=list(i)
        #     agent_name=a[0]
        #     qs = Sci1stKey.objects.filter(agent=agent_name)
        #     for x in qs:
        #         print(x,'sssssssssssssssssssssssssssssss')
        #         x.stop_time_ticket = datetime.datetime.now()
        #         x.save()
        #         qs.update(start_time_ticket=datetime.datetime.now())
        serializer = AgentRetriveSerializer(calobj, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            body_data = serializer.data
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



# prashanth
class SciKeyPendingTicketsListAPIView(generics.ListAPIView):
    """
    fetching the serializer and Scikey data
    """
    serializer_class = ScikeyPendingTicketsListSerializer
    queryset = Sci1stKey.objects.all()
    # authentication token and permissions of user we can change permissions
    permission_classes = (permissions.IsAuthenticated, IsAgentPermission)

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
            queryset = Sci1stKey.objects.filter(status='pending',agent=user_id,)
            user_serializer = AgentOwnTicketsSerializer(queryset, many=True)
            # return the reponce of data body
            return Response(user_serializer.data)
        except:
            return Response(
                {'your dont have any pending tickets'}, status=status.HTTP_404_NOT_FOUND)



# prashanth
class AgentPendingDetailTicketApiView(generics.GenericAPIView,mixins.UpdateModelMixin,
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
            return Sci1stKey.objects.get(id=id)
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




class AllAssign_Tickets_ListApi_View(APIView):
    serializer_class = Assigntickets_listSerializer

    def get(self, request, agent):
        try:
            tutorial = Sci1stKey.objects.filter(agent=agent,status='assign')
            """
                get the sci 1st key all assigned tickets 
                :param request:
                :param id:
                :param args:
                :param kwargs:
                :return:
            """
        except (Sci1stKey.DoesNotExist):
            return JsonResponse({'message': 'No details'}, status=status.HTTP_404_NOT_FOUND)

        tutorial_serializer = Assigntickets_listSerializer(tutorial,many=True)
        data = {'list_of_data': tutorial_serializer.data}
        return Response(data)



class Ticketreassign_to_agentview(APIView):
    serializer_class = Assigntickets_listSerializer

    def get_object(self, obj_id):
        try:
            obj = Sci1stKey.objects.get(id=obj_id)
            return obj
        except (Sci1stKey.DoesNotExist, ValidationError):
            raise status.HTTP_400_BAD_REQUEST

    def validate_ids(self, ticket_ids):
        for id in ticket_ids:
            try:
                Sci1stKey.objects.get(id=id)
                print(Sci1stKey.objects.get(id=id))
            except (Sci1stKey.DoesNotExist, ValidationError):
                raise status.HTTP_400_BAD_REQUEST
        return True

    def put(self, request, *args, **kwargs):
        data = request.data
        str_data = json.dumps(data)#converting dict to str
        lis_data = json.loads(str_data)["data"]#convering str to list
        print(type(lis_data))
        ticket_ids = [i['id'] for i in lis_data]
        self.validate_ids(ticket_ids)
        instances = []
        for temp_dict in lis_data:
            id = temp_dict['id']
            agent = temp_dict['agent']
            obj = self.get_object(id)
            obj.agent = agent
            obj.save()
            instances.append(obj)
        serializer = Sci1stKey(instances)
        return Response(serializer.data)