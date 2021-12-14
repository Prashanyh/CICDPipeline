from rest_framework.permissions import  BasePermission

from rest_framework.permissions import BasePermission

class IsAgentPermission(BasePermission):
    """
    Check if user is a agent.
    """

    message = "The user is not a agent."

    def has_permission(self, request, view):
        return request.user.is_agent