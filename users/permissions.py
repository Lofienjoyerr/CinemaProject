from django.contrib.auth import get_user_model
from rest_framework import permissions
from rest_framework.request import Request
from rest_framework.generics import GenericAPIView
from rest_framework.views import APIView

User = get_user_model()


class IsActive(permissions.BasePermission):
    def has_permission(self, request: Request, view: APIView) -> bool:
        q_user = request.user
        return q_user.is_active and q_user.email_address.verified


class IsOwnerOrIsAdmin(permissions.BasePermission):
    def has_object_permission(self, request: Request, view: GenericAPIView, obj: User) -> bool:
        q_user = request.user
        return q_user.is_staff or q_user.is_superuser or q_user == obj


class IsEmailOwnerOrIsAdmin(permissions.BasePermission):
    def has_permission(self, request: Request, view: APIView) -> bool:
        q_user = request.user
        return q_user.is_staff or q_user.is_superuser or q_user.email == request.data.get('email')
