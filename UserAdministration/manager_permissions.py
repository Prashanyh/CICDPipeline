from rest_framework.permissions import  BasePermission

from rest_framework.permissions import BasePermission

class IsManagerPermission(BasePermission):
    """
    Check if user is a manager.
    """

    message = "The user is not a manager."

    def has_permission(self, request, view):
        return request.user.is_manager