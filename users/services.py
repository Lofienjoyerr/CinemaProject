from datetime import datetime

from django.contrib.auth import get_user_model
from rest_framework.exceptions import AuthenticationFailed, NotFound

from core.settings import EMAIL_CONFIRM_TIME
from users.models import EmailAddress, EmailVerifyToken, PasswordResetToken

User = get_user_model()


def create_email(email: str, user: User):
    email_address = EmailAddress.objects.create(email, user)
    return EmailVerifyToken.objects.create(email_address)


def create_password_token(user: User) -> str:
    return PasswordResetToken.objects.create(user)


def get_user(email: str, password: str) -> User:
    try:
        user = User.objects.get(email=email)
        if user.check_password(password):
            return user
        raise AuthenticationFailed
    except User.DoesNotExist:
        raise AuthenticationFailed


def get_user_by_email(email: str) -> User:
    try:
        user = User.objects.get(email=email)
        return user
    except User.DoesNotExist:
        raise AuthenticationFailed


def verify_email(token: str) -> bool:
    verify_tokens = EmailVerifyToken.objects.filter(token=token, created__gte=datetime.now() - EMAIL_CONFIRM_TIME)
    if verify_tokens:
        verify_token = verify_tokens.first()
        verify_token.email_address.verified = True
        verify_token.email_address.save()
        return True
    return False


def get_password_reset_token(token: str) -> PasswordResetToken:
    tokens = PasswordResetToken.objects.filter(token=token, created__gte=datetime.now() - EMAIL_CONFIRM_TIME)
    if tokens:
        return tokens.first()
    raise NotFound
