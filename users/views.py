from django.contrib.auth import get_user_model
from rest_framework.generics import ListAPIView, RetrieveUpdateAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.request import Request
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.views import TokenObtainPairView

from .permissions import IsOwnerOrIsAdmin, IsEmailOwnerOrIsAdmin
from .serializers import (AdminUsersListSerializer, UsersListSerializer,
                          AdminUserDetailSerializer, UserDetailSerializer, PasswordChangeSerializer)

User = get_user_model()


class UsersView(ListAPIView):
    queryset = User.objects.all().order_by("date_joined")

    def get_serializer_class(self, *args, **kwargs) -> AdminUsersListSerializer | UsersListSerializer:
        if self.request.method == 'GET':
            if self.request.user.is_active and (self.request.user.is_staff or self.request.user.is_superuser):
                return AdminUsersListSerializer
            return UsersListSerializer


class UserDetailView(RetrieveUpdateAPIView):
    queryset = User.objects.all().order_by("date_joined")
    permission_classes = [IsOwnerOrIsAdmin]

    def get_serializer_class(self, *args, **kwargs) -> AdminUserDetailSerializer | UserDetailSerializer:
        q_user = self.request.user
        if q_user.is_active and (q_user.is_staff or q_user.is_superuser):
            return AdminUserDetailSerializer
        return UserDetailSerializer


class MyTokenObtainPairView(TokenObtainPairView):
    def post(self, request: Request, *args, **kwargs) -> Response:
        request.data._mutable = True
        request.data['email'] = request.data.get('login')
        request.data._mutable = False
        return super().post(request, *args, **kwargs)


class TokenVerifyView(APIView):
    def post(self, request: Request) -> Response:
        serializer = AdminUserDetailSerializer(request.user)
        return Response(serializer.data)


class PasswordChangeView(APIView):
    permission_classes = [IsAuthenticated, IsEmailOwnerOrIsAdmin]

    def get_user(self, request: Request) -> User:
        try:
            user = User.objects.get(email=request.data.get('email'))
            if user.check_password(request.data.get('old_password')):
                return user
            raise AuthenticationFailed
        except User.DoesNotExist:
            raise AuthenticationFailed

    def post(self, request: Request) -> Response:
        instance = self.get_user(request)
        serializer = PasswordChangeSerializer(instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        if getattr(instance, '_prefetched_objects_cache', None):
            instance._prefetched_objects_cache = {}

        return Response('Пароль успешно изменён!')


class RegisterView(APIView):
    def post(self, request: Request):
        pass