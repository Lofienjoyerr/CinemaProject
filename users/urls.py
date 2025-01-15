from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView, TokenBlacklistView

from . import views

urlpatterns = [
    path('users/', views.UsersView.as_view(), name='users-list'),
    path('users/<int:pk>/', views.UserDetailView.as_view(), name='user-detail'),
    path('token/', views.MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', views.TokenVerifyView.as_view(), name='token_verify'),
    path('token/blacklist/', TokenBlacklistView.as_view(), name='token_blacklist'),
    path('password/change/', views.PasswordChangeView.as_view(), name='password_change'),
    path('register/', views.RegisterView.as_view(), name='register'),
    path('email/verify/<str:token>/', views.EmailVerifyView.as_view(), name='email_verify'),
    path('email/change/', views.EmailChangeView.as_view(), name='email_change'),
]
