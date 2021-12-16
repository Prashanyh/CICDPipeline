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
    serializer_class = UserSerializer
    authentication_classes = []

    def post(self, request, *args,  **kwargs):
        parameters = request.data.copy()
        serializer = self.get_serializer(data=parameters)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"message": "User Created Successfully.  Now perform Login to get your token"},status=status.HTTP_201_CREATED)
        else:
            return Response({'user name already exist'},status=status.HTTP_406_NOT_ACCEPTABLE)
##prasanth
#user Login
class LoginAPIView(generics.GenericAPIView):
    permission_classes = []
    serializer_class = LoginSerializer
    def post(self,request):
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data,status=status.HTTP_200_OK)

##theja
##changing password
class ChangePasswordView(generics.UpdateAPIView):
    queryset = UserProfile.objects.all()
    permission_classes = (IsAuthenticated,)
    serializer_class = ChangePasswordSerializers


class Update_his_ProfileView(generics.UpdateAPIView):
    queryset = UserProfile.objects.all()
    permission_classes = (IsAuthenticated,)
    serializer_class = Update_his_profile_Serializer

##theja
# Adding Teams by Admin
class Addingteams(generics.GenericAPIView):
    permission_classes = []
    serializer_class = Teamserialsers

    def post(self, request, *args,  **kwargs):
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
    permission_classes = []
    def get(self, request):
        try:
            tutorial = Teams.objects.all()
        except Teams.DoesNotExist:
            return JsonResponse({'message': 'Teams does not exist'}, status=status.HTTP_404_NOT_FOUND)

        tutorial_serializer = Teamserialsers(tutorial, many=True)
        return JsonResponse(tutorial_serializer.data, safe=False)


##theja
# view/update/delete Team  by Admin
@api_view(['GET', 'PUT', 'DELETE'])
def Team_detail(request, pk):

    try:
        tutorial = Teams.objects.get(pk=pk)
    except Teams.DoesNotExist:
        return JsonResponse({'message': 'The Team does not exist'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        tutorial_serializer = Teamserialsers(tutorial)
        return JsonResponse(tutorial_serializer.data)

    elif request.method == 'PUT':
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
    permission_classes = []

    def get(self, request):
        try:
            tutorial = UserProfile.objects.all()
        except UserProfile.DoesNotExist:
            return JsonResponse({'message': 'The user does not exist'}, status=status.HTTP_404_NOT_FOUND)

        tutorial_serializer = UserProfileSerializer(tutorial, many=True)
        return JsonResponse(tutorial_serializer.data, safe=False)


##theja
# view/update/delete person(one)  by Admin
@api_view(['GET', 'PUT', 'DELETE'])
def Person_detail(request, pk):
    try:
        tutorial = UserProfile.objects.get(pk=pk)
    except UserProfile.DoesNotExist:
        return JsonResponse({'message': 'The user does not exist'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        tutorial_serializer = UserProfileSerializer(tutorial)
        return JsonResponse(tutorial_serializer.data)

    elif request.method == 'PUT':
        tutorial_data = JSONParser().parse(request)
        tutorial_serializer = UserProfileSerializer(tutorial, data=tutorial_data)
        if tutorial_serializer.is_valid():
            tutorial_serializer.save()
            return JsonResponse(tutorial_serializer.data)
        return JsonResponse(tutorial_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        tutorial.delete()
        return JsonResponse({'message': 'person was deleted successfully!'}, status=status.HTTP_204_NO_CONTENT)


##prasanth
class UploadFileView(APIView):
    serializer_class = FileUploadSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        dataset = Dataset()
        file = serializer.validated_data['file']
        try:
            imported_data = dataset.load(file.read(), format='xlsx')
            '''uploading xl file with particular data what user mentioned in xl we are looping the xl data
                    and appending into the database with same fields'''
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
            return Response({'sucessfully uploaded your file'},status=status.HTTP_200_OK)
        except:
            return Response(
                {'please select proper file'}, status=status.HTTP_404_NOT_FOUND)

class UploadPersonView(APIView):
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
            person_data=UserProfile(username=data[0],
                      fullname=data[1],
                      mobile=data[2],
                      email=data[3],
                      password=data[4],
                      date_joined=data[5],
                      is_verified=data[6],
                      is_active=data[7],
                      is_admin=data[8],
                      is_manager=data[9],
                      is_tl=data[10],
                      is_agent=data[11],
                      orginization=data[12],
                      dob=data[13],
                      gender=data[14],
                      team_name=data[15],
                      role=data[16]
                      

                    
                      )
            person_data.save()
        return Response(status=status.HTTP_200_OK)


##prasanth
class SciListViewView(APIView):
    def get(self, request, format=None):
        scikeylist = Sci1stKey.objects.all()
        serializer = ScikeylistSerializer(scikeylist, many=True)
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

    def get(self, request, pk, format=None):
        sci_key = self.get_object(pk)
        serializer = ScikeylistSerializer(sci_key)
        return Response(serializer.data)

    def delete(self, request, pk, format=None):
        sci_key = self.get_object(pk)
        sci_key.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)




# prashanth
class SciKeyAssignTicketsAPIView(generics.GenericAPIView):
    serializer_class = ScikeyAssignSerializer

    def put(self, request, *args, **kwargs):
        status_sci = request.data.get('status')
        user = Sci1stKey.objects.filter(status="newtickets")
        for user_status in user:
            user_status.status='assign'
            user_status.save()
            user.update(status=status_sci)
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
    serializer_class = ScikeyAssignSerializer
    # permission_classes = (permissions.IsAuthenticated, IsManagerPermission)

    def get(self, request, *args, **kwargs):
        new_tickets_count = Sci1stKey.objects.filter(status="newtickets").count()
        assign_tickets_count = Sci1stKey.objects.filter(status="assign").count()
        completed_tickets_count = Sci1stKey.objects.filter(status="completed").count()
        context = {"new": new_tickets_count,'assign':assign_tickets_count,'completed':completed_tickets_count}
        return Response(json.dumps(context), status=status.HTTP_200_OK)


# prashanth
class SciKeyAssignTicketsListAPIView(generics.ListAPIView):
    serializer_class = ScikeyTicketsListSerializer
    queryset = Sci1stKey.objects.all()

    def list(self, request, *args, **kwargs):
        queryset = Sci1stKey.objects.filter(status='assign')
        user_serializer = AgentOwnTicketsSerializer(queryset, many=True)
        return Response(user_serializer.data)

# prashanth
class SciKeyClosedTicketsListAPIView(generics.ListAPIView):
    serializer_class = ScikeyTicketsListSerializer
    queryset = Sci1stKey.objects.all()

    def list(self, request, *args, **kwargs):
        queryset = Sci1stKey.objects.filter(process_status='completed')
        user_serializer = AgentOwnTicketsSerializer(queryset, many=True)
        return Response(user_serializer.data)

# prashanth
class SciKeyNewTicketsListAPIView(generics.ListAPIView):
    serializer_class = ScikeyTicketsListSerializer
    queryset = Sci1stKey.objects.all()

    def list(self, request, *args, **kwargs):
        queryset = Sci1stKey.objects.filter(status='newtickets')
        user_serializer = AgentOwnTicketsSerializer(queryset, many=True)
        return Response(user_serializer.data)

# prashanth
class SciKeyNotFoundTicketsListAPIView(generics.ListAPIView):
    serializer_class = ScikeyTicketsListSerializer
    queryset = Sci1stKey.objects.all()

    def list(self, request, *args, **kwargs):
        queryset = Sci1stKey.objects.filter(status='notfound')
        user_serializer = AgentOwnTicketsSerializer(queryset, many=True)
        return Response(user_serializer.data)

# prashanth
class SciKeyExceptionTicketsListAPIView(generics.ListAPIView):
    serializer_class = ScikeyTicketsListSerializer
    queryset = Sci1stKey.objects.all()

    def list(self, request, *args, **kwargs):
        queryset = Sci1stKey.objects.filter(status='exception')
        user_serializer = AgentOwnTicketsSerializer(queryset, many=True)
        return Response(user_serializer.data)




from .agent_permissions import *
class AgentOwnTicketsListApiView(generics.ListAPIView):
    queryset = Sci1stKey.objects.all()
    serializer_class = AgentOwnTicketsSerializer

    def list(self, request, *args, **kwargs):
        user_id = request.user.username
        queryset = Sci1stKey.objects.filter(agent=user_id)
        user_serializer = AgentOwnTicketsSerializer(queryset, many=True)
        return Response(user_serializer.data)




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

class AgentDetailTicketsListApiView(generics.GenericAPIView,mixins.UpdateModelMixin,
                                 mixins.RetrieveModelMixin, mixins.DestroyModelMixin):
    queryset = Sci1stKey.objects.all()
    serializer_class = AgentRetriveSerializer
    lookup_field = 'id'

    def get_object(self, id):
        try:
            # return Sci1stKey.objects.get(id=id)
            individual_ticket = Sci1stKey.objects.filter(id=id)
            for x in individual_ticket:
                x.status = 'inprogress'
                x.save()
                individual_ticket.update(status='inprogress')
                return Sci1stKey.objects.get(id=id)
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
        calobj = self.get_object(id)
        print(calobj, 'kkkkkkkkkkkkkkkk')
        # individual_ticket = Sci1stKey.objects.filter(id=id)
        # for x in individual_ticket:
        #     x.status = 'closed'
        #     x.save()
        #     individual_ticket.update(status='closed')
        serializer = AgentRetriveSerializer(calobj, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            body_data = serializer.data
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# prashanth
class SciKeyPendingTicketsListAPIView(generics.ListAPIView):
    serializer_class = ScikeyPendingTicketsListSerializer
    queryset = Sci1stKey.objects.all()
    permission_classes = (permissions.IsAuthenticated, IsAgentPermission)

    def list(self, request, *args, **kwargs):
        queryset = Sci1stKey.objects.filter(status='pending')
        user_serializer = AgentOwnTicketsSerializer(queryset, many=True)
        return Response(user_serializer.data)



class AgentPendingDetailTicketApiView(generics.GenericAPIView,mixins.UpdateModelMixin,
                                 mixins.RetrieveModelMixin, mixins.DestroyModelMixin):
    queryset = Sci1stKey.objects.all()
    serializer_class = ScikeyPendingTicketsListSerializer
    lookup_field = 'id'

    def get_object(self, id):
        try:
            return Sci1stKey.objects.get(id=id)
        except Sci1stKey.DoesNotExist:
            raise Http404

    def get(self, request, id=None, *args, **kwargs):
        if id:
            calobj = self.get_object(id)
            serializer = ScikeyPendingTicketsListSerializer(calobj)
            return Response(serializer.data)
        else:
            alldata = Sci1stKey.objects.all()
            serializer = ScikeyPendingTicketsListSerializer(alldata, many=True)
            return Response(serializer.data)


    def put(self, request, id=None, *args, **kwargs):
        calobj = self.get_object(id)
        serializer = ScikeyPendingTicketsListSerializer(calobj, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            body_data = serializer.data
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)