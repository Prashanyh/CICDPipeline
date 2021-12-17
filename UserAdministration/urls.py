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
    path('admin_all_tickets/', views.SciListViewView.as_view(), name='admin_all_tickets'),##viewing all tickets
    path('admin_ticket_get_delete/<int:pk>/', views.SciTicketDetail.as_view(), name='admin_ticket_get_delete'),##viewing single ticket

    path('admin_bulk_assign/', views.SciKeyAssignTicketsAPIView.as_view(), name='admin_bulk_assign'), # Assign tickets to agents
    path('admin_ticketstatus_count/', views.SciKeyAllTicketsCountAPIView.as_view(), name='admin_ticketstatus_count'), # Count All tickets

    # path('agent_own_tickets/',views.AgentOwnTicketsListApiView.as_view(),name="agent_own_tickets"),
    path('agent_assigntickets_list/',views.AgentOwnTicketsListApiView.as_view(),name="agent_assigntickets_list"), # agent own tickets api
    path('agent_assignticket_viewupdate/<int:id>/', views.AgentDetailTicketsListApiView.as_view(),name="agent_assignticket_viewupdate"), # agent own tickets update api

    path('show_assigntickets_viewlist/',views.AllAssign_Tickets_ListApi_View.as_view(),name='show_assigntickets_viewlist'),#showing all assign tickets to admin/manager
    path('tickets_reassign_agent/',views.Ticketreassign_to_agentview.as_view(),name='tickets_reassign_agent/'),#reassign tickets to agent


    path('admin_assigntickets_list/', views.SciKeyAssignTicketsListAPIView.as_view(),name="admin_assigntickets_list"), # agent assign tickets api
    path('admin_closetickets_list/', views.SciKeyClosedTicketsListAPIView.as_view(),name="admin_closetickets_list"), # agent closed tickets api
    path('admin_newtickets_list/', views.SciKeyNewTicketsListAPIView.as_view(),name="admin_newtickets_list"), # agent new tickets api

    # path('admin_notfoundtickets_list/', views.SciKeyNotFoundTicketsListAPIView.as_view(),name="agent_notfound_tickets"), # agent notfound tickets api
    # path('admin_exceptiondtickets_list/', views.SciKeyExceptionTicketsListAPIView.as_view(),name="agent_exception_tickets"), # agent exception tickets api

    path('agent_pending_tickets_list/', views.SciKeyPendingTicketsListAPIView.as_view(),name="agent_pending_tickets_list"),# agent own pending tickets
    path('agent_pending_ticket_viewupdate/<int:id>/', views.AgentPendingDetailTicketApiView.as_view(),name="agent_pending_ticket_viewupdate"), # agent update own ticktes

]