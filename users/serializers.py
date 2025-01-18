from typing import Dict, Any
from django.core.exceptions import ValidationError as djValidationError
from django.contrib.auth import get_user_model
from django.contrib.auth.models import update_last_login
from rest_framework import serializers, exceptions
from rest_framework.utils import model_meta
from rest_framework.serializers import raise_errors_on_nested_writes
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.tokens import Token
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.settings import api_settings

from users.authentication import JWTEmailOrPhoneBackend
from users.models import PasswordResetToken
from users.services import get_user_by_email
from users.utils import crop_avatar

User = get_user_model()


class AdminUserDetailSerializer(serializers.ModelSerializer):
    id = serializers.ReadOnlyField()
    email = serializers.ReadOnlyField()
    password = serializers.ReadOnlyField()
    date_joined = serializers.ReadOnlyField()
    last_login = serializers.ReadOnlyField()

    class Meta:
        model = User
        fields = ['id', 'email', 'phone', 'name', 'avatar', 'password',
                  'is_active', 'is_superuser', 'is_staff',
                  'date_joined', 'last_login']

    def update(self, instance, validated_data):
        raise_errors_on_nested_writes('update', self, validated_data)
        info = model_meta.get_field_info(instance)
        is_avatar_updated = validated_data.get("avatar", instance.avatar) != instance.avatar

        m2m_fields = []
        for attr, value in validated_data.items():
            if attr in info.relations and info.relations[attr].to_many:
                m2m_fields.append((attr, value))
            else:
                setattr(instance, attr, value)

        instance.save()

        for attr, value in m2m_fields:
            field = getattr(instance, attr)
            field.set(value)

        if is_avatar_updated:
            crop_avatar(str(instance.avatar))

        return instance


class UserDetailSerializer(serializers.ModelSerializer):
    id = serializers.ReadOnlyField()
    email = serializers.ReadOnlyField()
    password = serializers.ReadOnlyField()
    date_joined = serializers.ReadOnlyField()
    last_login = serializers.ReadOnlyField()

    class Meta:
        model = User
        fields = ['id', 'email', 'phone', 'name', 'avatar', 'password',
                  'date_joined', 'last_login']

    def update(self, instance, validated_data):
        raise_errors_on_nested_writes('update', self, validated_data)
        info = model_meta.get_field_info(instance)
        is_avatar_updated = validated_data.get("avatar", instance.avatar) != instance.avatar

        m2m_fields = []
        for attr, value in validated_data.items():
            if attr in info.relations and info.relations[attr].to_many:
                m2m_fields.append((attr, value))
            else:
                setattr(instance, attr, value)

        instance.save()

        for attr, value in m2m_fields:
            field = getattr(instance, attr)
            field.set(value)

        if is_avatar_updated:
            crop_avatar(str(instance.avatar))

        return instance


class AdminUsersListSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ['url', 'id', 'password', 'email', 'phone', 'name', 'avatar',
                  'is_active', 'is_superuser', 'is_staff',
                  'date_joined', 'last_login']


class UsersListSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ['url', 'id', 'email', 'phone', 'name', 'avatar',
                  'date_joined', 'last_login']


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user: User) -> Token:
        token = super().get_token(user)

        if user.email:
            token['email'] = user.email
        if user.phone:
            token['phone'] = user.phone
        return token

    def _validate(self, attrs: Dict[str, Any]) -> Dict[Any, Any]:
        authenticate_kwargs = {
            'login': attrs[self.username_field],
            "password": attrs["password"],
        }
        try:
            authenticate_kwargs["request"] = self.context["request"]
        except KeyError:
            pass

        self.user = JWTEmailOrPhoneBackend.authenticate(self, **authenticate_kwargs)

        if not api_settings.USER_AUTHENTICATION_RULE(self.user):
            raise exceptions.AuthenticationFailed(
                self.error_messages["no_active_account"],
                "no_active_account",
            )

        return {}

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, str]:
        data = self._validate(attrs)

        refresh = self.get_token(self.user)

        data["refresh"] = str(refresh)
        data["access"] = str(refresh.access_token)

        if api_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, self.user)

        return data


class PasswordChangeSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True, max_length=128)
    old_password = serializers.CharField(required=True, max_length=128)
    new_password1 = serializers.CharField(required=True, max_length=128)
    new_password2 = serializers.CharField(required=True, max_length=128)

    class Meta:
        model = User
        fields = ['email', 'old_password', 'new_password1', 'new_password2']

    def update(self, instance: User, validated_data: Dict[str, Any]) -> User:
        raise_errors_on_nested_writes('update', self, validated_data)
        instance.set_password(validated_data.get('new_password1'))
        instance.save()
        return instance


class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True, max_length=128)
    password1 = serializers.CharField(required=True, max_length=128)
    password2 = serializers.CharField(required=True, max_length=128)

    class Meta:
        model = User
        fields = ['email', 'password1', 'password2']

    def create(self, validated_data: Dict[str, Any]) -> User:
        raise_errors_on_nested_writes('create', self, validated_data)
        model_class = self.Meta.model
        validated_data['password'] = validated_data.pop('password1')
        validated_data.pop('password2')
        try:
            instance = model_class._default_manager.create(**validated_data)
        except djValidationError:
            raise ValidationError({'detail': 'Пользователь с таким email уже существует'})

        return instance


class EmailChangeSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True, max_length=128)
    password = serializers.CharField(required=True, max_length=128)
    new_email = serializers.EmailField(required=True, max_length=128)

    class Meta:
        model = User
        fields = ['email', 'password', 'new_email']

    def update(self, instance: User, validated_data: Dict[str, Any]) -> User:
        raise_errors_on_nested_writes('update', self, validated_data)
        setattr(instance, 'email', validated_data.get('new_email'))
        instance.save()

        instance.email_address.tokens.all().delete()
        instance.email_address.delete()

        return instance


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True, max_length=128)

    def create(self, validated_data: Dict[str, Any]) -> PasswordResetToken:
        user = get_user_by_email(validated_data.get('email'))
        instance = PasswordResetToken.objects.create(user)

        return instance


class PasswordResetVerifySerializer(serializers.Serializer):
    password1 = serializers.CharField(required=True, max_length=128)
    password2 = serializers.CharField(required=True, max_length=128)

    def update(self, instance: User, validated_data: Dict[str, Any]):
        instance.set_password(validated_data.get('password1'))
        instance.save()
        return instance


class EmailResendSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True, max_length=128)


class PasswordResendSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True, max_length=128)
