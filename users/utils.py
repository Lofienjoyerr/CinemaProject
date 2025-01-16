from django.core.mail import send_mail

from users.models import PasswordResetToken


def send_email_verify(email: str, token: str):
    send_mail("Подтверждение электронной почты", f"""От вашего адреса электронной почты была проведена попытка активации электронной почты.
Если это были Вы, то перейдите по следующему адресу, чтобы подтвердить почту
http://127.0.0.1:8000/api/v1/email/verify/{token}/
Если это были не Вы, проигнорируйте данное сообщение.""", from_email=None,
              recipient_list=[email])


def send_password_reset(email: str, token: PasswordResetToken):
    send_mail("Смена пароля", f"""От вашего адреса электронной почты была проведена попытка смены пароля.
Если это были Вы, то перейдите по следующему адресу, чтобы сменить пароль
http://127.0.0.1:8000/api/v1/password/reset/verify/{token.token}/
Если это были не Вы, проигнорируйте данное сообщение.""", from_email=None,
              recipient_list=[email])
