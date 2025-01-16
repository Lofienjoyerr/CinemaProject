from typing import Type

from django.contrib.auth import get_user_model

from rest_framework.generics import ListAPIView, RetrieveUpdateAPIView, CreateAPIView, UpdateAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.request import Request
from rest_framework.permissions import IsAuthenticated
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_201_CREATED
from rest_framework_simplejwt.views import TokenObtainPairView

from core.settings import EMAIL_CONFIRM_TIME
from .permissions import IsOwnerOrIsAdmin, IsEmailOwnerOrIsAdmin, IsActive
from .serializers import (AdminUsersListSerializer, UsersListSerializer,
                          AdminUserDetailSerializer, UserDetailSerializer, PasswordChangeSerializer, RegisterSerializer,
                          EmailChangeSerializer, PasswordResetSerializer, PasswordResetVerifySerializer)
from .services import create_email, get_user, verify_email, get_password_reset_token
from .utils import send_email_verify, send_password_reset

User = get_user_model()


class UsersView(ListAPIView):
    queryset = User.objects.all().order_by("date_joined")

    def get_serializer_class(self, *args, **kwargs) -> Type[AdminUsersListSerializer | UsersListSerializer]:
        if self.request.user.is_active and self.request.user.email_address.verified and (
                self.request.user.is_staff or self.request.user.is_superuser):
            return AdminUsersListSerializer
        return UsersListSerializer


class UserDetailView(RetrieveUpdateAPIView):
    queryset = User.objects.all().order_by("date_joined")
    permission_classes = [IsActive, IsOwnerOrIsAdmin]

    def get_serializer_class(self, *args, **kwargs) -> Type[AdminUserDetailSerializer | UserDetailSerializer]:
        if self.request.user.is_active and self.request.user.email_address.verified and (
                self.request.user.is_staff or self.request.user.is_superuser):
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
    permission_classes = [IsActive, IsAuthenticated, IsEmailOwnerOrIsAdmin]

    def post(self, request: Request) -> Response:
        instance = get_user(request.data.get('email'), request.data.get('old_password'))
        serializer = PasswordChangeSerializer(instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        if serializer.validated_data.get('new_password1') == serializer.validated_data.get('new_password2'):
            serializer.save()

            if getattr(instance, '_prefetched_objects_cache', None):
                instance._prefetched_objects_cache = {}

            return Response({'detail': 'Пароль успешно изменён!'})
        return Response({'detail': 'Пароли должны совпадать'}, status=HTTP_400_BAD_REQUEST)


class RegisterView(APIView):
    def post(self, request: Request) -> Response:
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if serializer.validated_data.get('password1') == serializer.validated_data.get('password2'):
            user = serializer.save()
            email = serializer.validated_data.get('email')

            token = create_email(email, user)
            send_email_verify(email, token)

            return Response({
                'detail': f'Письмо для подтверждения email отправлено. Перейдите по ссылке внутри письма в течение {EMAIL_CONFIRM_TIME} минут'},
                status=HTTP_201_CREATED)
        return Response({'detail': 'Пароли должны совпадать'}, status=HTTP_400_BAD_REQUEST)


class EmailVerifyView(APIView):
    def get(self, request: Request, token: str) -> Response:
        if verify_email(token):
            return Response({'detail': 'Электронная почта подтверждена'})
        return Response({'detail': 'Произошла ошибка подтверждения'}, status=HTTP_400_BAD_REQUEST)


class EmailChangeView(APIView):
    permission_classes = [IsActive, IsAuthenticated, IsEmailOwnerOrIsAdmin]

    def post(self, request: Request) -> Response:
        instance = get_user(request.data.get('email'), request.data.get('password'))
        serializer = EmailChangeSerializer(instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        if getattr(instance, '_prefetched_objects_cache', None):
            instance._prefetched_objects_cache = {}

        email = serializer.validated_data.get('new_email')
        token = create_email(email, instance)
        send_email_verify(email, token)

        return Response({
            'detail': f'Письмо для подтверждения email отправлено. Перейдите по ссылке внутри письма в течение {EMAIL_CONFIRM_TIME.seconds // 60} минут'})


class PasswordResetView(CreateAPIView):
    serializer_class = PasswordResetSerializer

    def create(self, request: Request, *args, **kwargs) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        prt = serializer.save()

        email = serializer.validated_data.get('email')
        send_password_reset(email, prt)

        return Response({
            'detail': f'Письмо для смены пароля отправлено. Перейдите по ссылке внутри письма в течение {EMAIL_CONFIRM_TIME.seconds // 60} минут'},
            status=HTTP_201_CREATED)


class PasswordResetVerifyView(CreateAPIView):
    def create(self, request: Request, *args, **kwargs) -> Response:
        token = get_password_reset_token(kwargs.get('token'))
        serializer = PasswordResetVerifySerializer(token.user, data=request.data)
        serializer.is_valid(raise_exception=True)
        if serializer.validated_data.get('password1') == serializer.validated_data.get('password2'):
            serializer.save()
            return Response({'detail': 'Пароль успешно изменён'})
        return Response({'detail': 'Пароли должны совпадать'}, status=HTTP_400_BAD_REQUEST)
