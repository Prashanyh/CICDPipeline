from django.contrib import admin
from django.urls import path
from UserAdministration import views

urlpatterns = [
    path('user_registration/', views.RegisterApi.as_view(), name='user_registration'),#user registration
    path('user_login/', views.LoginAPIView.as_view(), name='auth_login'),#Login Url

    path('user_change_password/<int:pk>',views.ChangePasswordView.as_view(),name='user_change_password'),## changing password
    path('user_edit_hisprofile/<int:pk>',views.Update_his_ProfileView.as_view(),name='user_edit_hisprofile'),

    path('team_adding/',views.Addingteams.as_view(),name='team_adding'),# Adding/Create Teams
    path('team_list/',views.Team_ListView.as_view(),name='team_list'),# Showing Teams
    path('team_update_delete/<int:pk>',views.Team_detail,name='team_update_delete'),#view/update/delete Team

    path('user_list/',views.User_listApiview.as_view(),name='user_list'),# Showing all persons
    path('person_update_delete/<int:pk>',views.Person_detail,name='persons_update_delete'),#view/update/delete persons(we have to change the nameing)

    path('upload-scikey/', views.UploadFileView.as_view(), name='upload-scikey'),#uploading sci1st key file
    path('view-scikey/', views.SciListViewView.as_view(), name='view-scikey'),##viewing all tickets
    path('detail-scikey/<int:pk>/', views.SciTicketDetail.as_view(), name='detail-scikey'),##viewing single ticket

    path('assign-newtickets/', views.SciKeyAssignTicketsAPIView.as_view(), name='assign-newtickets'),
    path('count-newtickets/', views.SciKeyAllTicketsCountAPIView.as_view(), name='count-newtickets'),

]