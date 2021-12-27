from django.contrib import admin
from django.urls import path
from UserAdministration import views


urlpatterns = [
    path('user_registration/', views.RegisterApi.as_view(), name='user_registration'),#user registration
    path('user_login/', views.LoginAPIView.as_view(), name='auth_login'),#Login Url
    

    path('user_change_password/', views.ChangePasswordView.as_view(), name='user_change_password'),## changing password
    path('user_edit_hisprofile/', views.Update_his_ProfileView.as_view(), name='user_edit_hisprofile'),##edit his profile




    ##admin/manger
    path('team_adding/',views.Addingteams.as_view(),name='team_adding'),# Adding/Create Teams
    path('team_list/',views.Team_ListView.as_view(),name='team_list'),# Showing Teams
    path('team_update_delete/<int:pk>',views.Team_detail,name='team_update_delete'),#view/update/delete Team

    path('user_list/',views.User_listApiview.as_view(),name='user_list'),# Showing all persons
    path('person_update_delete/<int:pk>',views.Person_detail,name='persons_update_delete'),#view/update/delete persons(we have to change the nameing)
    path('upload-person/', views.UploadPersonView.as_view(), name='upload-person'),#uploading sci1st key file

    path('upload-scikey/', views.UploadFileView.as_view(), name='upload-scikey'),#uploading sci1st key file
    
    path('admin_ticket_get_delete/<int:pk>/', views.SciTicketDetail.as_view(), name='admin_ticket_get_delete'),##viewing single ticket

    path('admin_bulk_assign/', views.SciKeyAdminBulkAssignTicketsAPIView.as_view(), name='admin_bulk_assign'), # Assign tickets to agents
    path('admin_ticketstatus_count/', views.SciKeyAdminAllTicketsCountAPIView.as_view(), name='admin_ticketstatus_count'), # Count All tickets

    path('admin_all_tickets/', views.SciListViewView.as_view(), name='admin_all_tickets'),##viewing all tickets

    # agent wise table count (dashboard )
    path('admin_assigntickets_list/', views.SciKeyAdminAssignTicketsListAPIView.as_view(),name="admin_assigntickets_list"), # agent assign tickets api
    path('admin_closetickets_list/', views.SciKeyAddminClosedTicketsListAPIView.as_view(),name="admin_closetickets_list"), # agent closed tickets api
    path('admin_newtickets_list/', views.SciKeyAdminNewTicketsListAPIView.as_view(),name="admin_newtickets_list"), # agent new tickets api

    # team wise with date count table data (tl sidebar)
    path('admin_teamwise_newticket_count/', views.AdminTeamwiseNewTicketListAPIView.as_view(),name="admin_teamwise_newticket_count"), # agent new tickets with date api
    path('admin_teamwise_assignticket_count/', views.AdminTeamwiseAssignTicketListAPIView.as_view(),name="admin_teamwise_assignticket_count"), # agent assign tickets with date api
    path('admin_teamwise_pendingticket_count/', views.AdminTeamwisePendingTicketListAPIView.as_view(),name="admin_teamwise_pendingticket_count"),# agent pending tickets with date api
    path('admin_teamwise_closedticket_count/', views.AdminTeamwiseClosedTicketListAPIView.as_view(),name="admin_teamwise_closedticket_count"), # agent closed tickets with date api

    # agent wise with date count table data (agent sidebar)
    path('admin_agentwise_newticket_count/', views.AdminAgentwiseNewTicketListAPIView.as_view(),name="admin_agentwise_newticket_count"), # agent new tickets with date api
    path('admin_agentwise_assignticket_count/', views.AdminAgentwiseAssignTicketListAPIView.as_view(),name="admin_agentwise_assignticket_count"), # agent assign tickets with date api
    path('admin_agentwise_pendingticket_count/', views.AdminAgentwisePendingTicketListAPIView.as_view(),name="admin_agentwise_pendingticket_count"), # agent new tickets with date api
    path('admin_agentwise_closedticket_count/', views.AdminAgentwiseClosedTicketListAPIView.as_view(),name="admin_agentwise_closedticket_count"), # agent closed tickets with date api

    #  date wise count table data (datewise sidebar)
    path('admin_datewise_newticket_count/', views.AdminDatewiseNewTicketListAPIView.as_view(),name="admin_datewise_newticket_count"), # agent new tickets with date api
    path('admin_datewise_pendingticket_count/', views.AdminDatewisePendingTicketListAPIView.as_view(),name="admin_datewise_pendingticket_count"), # agent pending tickets with date api
    path('admin_datewise_assignticket_count/', views.AdminDatewiseAssignTicketListAPIView.as_view(),name="admin_datewise_assignticket_count"),# agent pending tickets with date api
    path('admin_datewise_closedticket_count/', views.AdminDatewiseClosedTicketListAPIView.as_view(),name="admin_datewise_closedticket_count"), # agent closed tickets with date api

    # date wise count with agents
    path('admin_processtatus_count/', views.AdminProcessCountTicketListAPIView.as_view()), 
    path('admin_agentwise_processstatus_count/', views.AdminAgentWiseCountTicketListAPIView.as_view()),


    ####tl
    path('tl_alltickets_list/',views.Tl_Teamwise_AllticketsView.as_view(),name='tl_alltickets_list'),#showing all tickets his under his team
    path('tl_assigntickets_list/', views.Tl_Teamwise_AssignticketsView.as_view(), name='tl_assigntickets_list'),# showing assign tickets his under his team
    ##tl reports
    path('tl_ticketstatus_count/', views.Tl_Teamwise_ticket_StatuscountView.as_view(), name='tl_ticketstatus_count'),#showing all tickets status count under his team
    path('tl_processstatus_count/',views.Tl_Teamwise_process_StatuscountView.as_view(),name='tl_processstatus_count'),#showing all process status count under his team
    path('tl_agentwise_ticketstatus_count/',views.Tl_Team_agentwise_countView.as_view(),name='tl_agentwise_ticketstatus_count'),#showing all date wise with agent count under his team
    path('tl_datewise_ticketstatus_count/', views.Tl_Team_datewise_countView.as_view(),name='tl_datewise_ticketstatus_count'),  # showing all date wise count under his team
    path('tl_previousweek_tickets_list/', views.Tl_Teamwise_ticketstatus_privousweek_countView.as_view(),name='tl_previousweek_tickets_list'),#showing new/closed tickets previous week count for tl under his team
    path('tl_currentweek_tickets_list/',views.Tl_Teamwise_ticketstatus_currentweek_countView.as_view(),name='tl_currentweek_tickets_list'),#showing new/closed tickets current week count for tl under his team
    path('tl_currentmonth_tickets_list/', views.Tl_Teamwise_ticketstatus_currentmonth_countView.as_view(),name='tl_currentmonth_tickets_list'),  # showing new/closed tickets current month count for tl under his team
    path('tl_previousmonth_tickets_list/', views.Tl_Teamwise_ticketstatus_previousmonth_countView.as_view(),name='tl_previousmonth_tickets_list'),  # showing new/closed tickets prevoius month count for tl under his team



    ###agent
    # path('agent_own_tickets/',views.AgentOwnTicketsListApiView.as_view(),name="agent_own_tickets"),
    path('agent_assigntickets_list/',views.AgentAssignTicketsListApiView.as_view(),name="agent_assigntickets_list"), # agent own tickets api
    path('agent_assignticket_viewupdate/<int:id>/', views.AgentAssignDetailTicketListApiView.as_view(),name="agent_assignticket_viewupdate"), # agent own tickets update api

    # path('admin_notfoundtickets_list/', views.SciKeyNotFoundTicketsListAPIView.as_view(),name="agent_notfound_tickets"), # agent notfound tickets api
    # path('admin_exceptiondtickets_list/', views.SciKeyExceptionTicketsListAPIView.as_view(),name="agent_exception_tickets"), # agent exception tickets api

    path('agent_pending_tickets_list/', views.SciKeyAgentPendingTicketsListAPIView.as_view(),name="agent_pending_tickets_list"),# agent own pending tickets
    path('agent_pending_ticket_viewupdate/<int:id>/', views.AgentPendingDetailTicketApiView.as_view(),name="agent_pending_ticket_viewupdate"), # agent update own ticktes
    ##agent reports
    path('agent_ticketstatus_count/',views.Agent_ticket_status_count.as_view(),name='agent_ticketstatus_count'),#agent his ticketstatus counts
    path('agent_processstatus_count/', views.Agent_process_status_count.as_view(), name='agent_processstatus_count'),# agent his processstatus tickets counts
    path('agent_datewise_ticketstatus_count/',views.Agent_datewise_ticketstatus_count.as_view(),name='agent_datewise_ticketstatus_count'),#agent date wise ticket status count

    path('admin_bulk_reasign/', views.AllReAssign_Tickets_ListApi_View.as_view(),name='show_assigntickets_viewlist'),  # showing all assign tickets to admin/manager
    path('tickets_reassign_agent/<int:pk>/', views.Ticketreassign_to_agentview.as_view(), name='tickets_reassign_agent'),# reassign tickets to agent


    path('logout/', views.Logout.as_view()),

    
    path('demoapi/', views.ListUsers.as_view())

]

