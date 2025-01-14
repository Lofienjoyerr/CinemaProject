from django.contrib.auth import get_user_model
from rest_framework import permissions
from rest_framework.request import Request
from rest_framework.generics import GenericAPIView

User = get_user_model()


class IsOwnerOrIsAdmin(permissions.BasePermission):

    def has_object_permission(self, request: Request, view: GenericAPIView, obj: User) -> bool:
        q_user = request.user
        return ((q_user.is_active and (q_user.is_staff or q_user.is_superuser))
                or q_user == obj)
