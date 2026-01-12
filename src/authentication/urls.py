"""
URL configuration for authentication app
"""
from django.urls import path
from .views import (
    RegisterView,
    VerifyEmailView,
    LoginView,
    RefreshTokenView,
    LogoutView,
    LogoutAllView,
    CurrentUserView,
    ChangePasswordView,
    HealthCheckView,
)

app_name = 'authentication'

urlpatterns = [
    # Health Check
    path('health/', HealthCheckView.as_view(), name='health'),
    
    # Registration & Verification
    path('register/', RegisterView.as_view(), name='register'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify-email'),
    
    # Authentication
    path('login/', LoginView.as_view(), name='login'),
    path('refresh/', RefreshTokenView.as_view(), name='refresh'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('logout-all/', LogoutAllView.as_view(), name='logout-all'),
    
    # User
    path('me/', CurrentUserView.as_view(), name='current-user'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
]
