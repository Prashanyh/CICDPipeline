from rest_framework.permissions import  BasePermission

from rest_framework.permissions import BasePermission

class IsAdminPermission(BasePermission):
    """
    Check if user is a admin.
    """

    message = "The user is not a admin."

    def has_permission(self, request, view):
        return request.user.is_admin