from django.db.models import Q
from django.core.exceptions import MultipleObjectsReturned
from django.contrib.auth import get_user_model
from rest_framework.request import Request
from rest_framework_simplejwt.settings import api_settings

from users.models import EmailAddress

User = get_user_model()


class JWTEmailOrPhoneBackend:
    def authenticate(self, request: Request, login: str = None, password: str = None) -> User | None:
        try:
            user = User.objects.get(Q(email=login) | Q(phone=login))
            if user.check_password(password):
                return user
        except (User.DoesNotExist, MultipleObjectsReturned):
            return None

    def get_user(self, user_id: int) -> User | None:
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None


def user_authentication_rule(user: User) -> bool:
    return user is not None and (
            not api_settings.CHECK_USER_IS_ACTIVE or user.is_active
    ) and user.email_address.verified
