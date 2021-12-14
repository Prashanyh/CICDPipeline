from rest_framework.permissions import BasePermission

class IsTlPermission(BasePermission):
    """
    Check if user is a tl.
    """

    message = "The user is not a tl."

    def has_permission(self, request, view):
        return request.user.is_tl