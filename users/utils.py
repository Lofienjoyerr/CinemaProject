from django.core.mail import send_mail


def send_email_verify(email: str, token: str):
    send_mail("Подтверждение электронной почты", f"""
    От вашего адреса электронной почты была проведена попытка регистрации.
    Если это были Вы, то перейдите по следующему адресу, чтобы подтвердить почту
    http://127.0.0.1:8000/api/v1/email/verify/{token}/
    Если это были не Вы, проигнорируйте данное сообщение.""", from_email=None,
              recipient_list=[email])
