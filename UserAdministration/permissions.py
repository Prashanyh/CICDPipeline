# from rest_framework import permissions
#
#
# class AuthorAllStaffAllButEditOrReadOnly(permissions.BasePermission):
#
#     edit_methods = ("GET")
#
#     def has_permission(self, request, view):
#         if request.user.is_authenticated:
#             return True
#
#     def has_object_permission(self, request, view, obj):
#         if request.user.is_agent:
#             return True
#
#         if request.method in permissions.SAFE_METHODS:
#             return True
#
#         if obj.author == request.user:
#             return True
#
#         if request.user.is_staff and request.method not in self.edit_methods:
#             return True
#
#         return False

from rest_framework import permissions


class Agent(permissions.BasePermission):

    def has_object_permission(self, request, view, obj):
        return obj.agent == request.user