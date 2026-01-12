"""
Authentication views with rate limiting and security
"""
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth import authenticate
from django.utils import timezone
from django.conf import settings
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator
from django.core.mail import send_mail
import uuid
import logging

from .models import User, RefreshToken
from .serializers import (
    UserRegistrationSerializer,
    UserLoginSerializer,
    UserSerializer,
    PasswordChangeSerializer,
    EmailVerificationSerializer
)
from .jwt_utils import jwt_handler
from .utils import get_client_ip, get_user_agent, create_fingerprint

logger = logging.getLogger('authentication')


class RegisterView(APIView):
    """
    User registration endpoint
    Rate limited to prevent abuse
    """
    permission_classes = [AllowAny]
    
    @method_decorator(ratelimit(key='ip', rate=settings.RATE_LIMITS['REGISTER'], method='POST'))
    def post(self, request):
        """Register a new user"""
        serializer = UserRegistrationSerializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.save()
            
            # Generate email verification token
            verification_token = str(uuid.uuid4())
            user.email_verification_token = verification_token
            user.email_verification_sent_at = timezone.now()
            user.save()
            
            # Send verification email (in production, use celery for async)
            self._send_verification_email(user, verification_token)
            
            logger.info(f"New user registered: {user.email}")
            
            return Response({
                'message': 'Registration successful. Please check your email to verify your account.',
                'user': UserSerializer(user).data
            }, status=status.HTTP_201_CREATED)
        
        return Response({
            'error': True,
            'message': 'Registration failed',
            'details': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    def _send_verification_email(self, user, token):
        """Send email verification link"""
        verification_url = f"{settings.FRONTEND_URL}/verify-email?token={token}"
        
        subject = 'Verify your email address'
        message = f"""
        Hello {user.username},
        
        Please click the link below to verify your email address:
        {verification_url}
        
        This link will expire in 24 hours.
        
        If you didn't create an account, please ignore this email.
        """
        
        try:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            logger.info(f"Verification email sent to {user.email}")
        except Exception as e:
            logger.error(f"Failed to send verification email to {user.email}: {e}")


class VerifyEmailView(APIView):
    """Email verification endpoint"""
    permission_classes = [AllowAny]
    
    def post(self, request):
        """Verify email with token"""
        serializer = EmailVerificationSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                'error': True,
                'message': 'Invalid request',
                'details': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        token = serializer.validated_data['token']
        
        try:
            user = User.objects.get(email_verification_token=token)
            
            # Check if token is expired (24 hours)
            if user.email_verification_sent_at:
                expiry = user.email_verification_sent_at + timezone.timedelta(hours=24)
                if timezone.now() > expiry:
                    return Response({
                        'error': True,
                        'message': 'Verification token has expired'
                    }, status=status.HTTP_400_BAD_REQUEST)
            
            # Verify email
            user.email_verified = True
            user.email_verification_token = None
            user.save()
            
            logger.info(f"Email verified for user: {user.email}")
            
            return Response({
                'message': 'Email verified successfully'
            }, status=status.HTTP_200_OK)
        
        except User.DoesNotExist:
            return Response({
                'error': True,
                'message': 'Invalid verification token'
            }, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    """
    User login endpoint
    Returns access token and sets refresh token cookie
    """
    permission_classes = [AllowAny]
    
    @method_decorator(ratelimit(key='ip', rate=settings.RATE_LIMITS['LOGIN'], method='POST'))
    def post(self, request):
        """Authenticate user and return tokens"""
        serializer = UserLoginSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                'error': True,
                'message': 'Invalid credentials',
                'details': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        email = serializer.validated_data['email'].lower()
        password = serializer.validated_data['password']
        
        # Authenticate user
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            logger.warning(f"Login attempt for non-existent email: {email}")
            return Response({
                'error': True,
                'message': 'Invalid email or password'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        if not user.check_password(password):
            logger.warning(f"Failed login attempt for user: {email}")
            return Response({
                'error': True,
                'message': 'Invalid email or password'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        if not user.is_active:
            return Response({
                'error': True,
                'message': 'Account is disabled'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Optional: Require email verification
        # if not user.email_verified:
        #     return Response({
        #         'error': True,
        #         'message': 'Please verify your email before logging in'
        #     }, status=status.HTTP_403_FORBIDDEN)
        
        # Generate tokens
        access_token = jwt_handler.generate_access_token(user)
        refresh_token_raw = jwt_handler.generate_refresh_token()
        refresh_token_hash = jwt_handler.hash_token(refresh_token_raw)
        
        # Create refresh token record
        refresh_token = RefreshToken.objects.create(
            user=user,
            token_hash=refresh_token_hash,
            expires_at=timezone.now() + settings.JWT_SETTINGS['REFRESH_TOKEN_LIFETIME'],
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request),
            fingerprint=create_fingerprint(request)
        )
        
        # Update last login
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])
        
        # Create response with access token
        response = Response({
            'message': 'Login successful',
            'access_token': access_token,
            'user': UserSerializer(user).data
        }, status=status.HTTP_200_OK)
        
        # Set refresh token as HttpOnly cookie
        response.set_cookie(
            key=settings.REFRESH_TOKEN_COOKIE['NAME'],
            value=refresh_token_raw,
            max_age=settings.REFRESH_TOKEN_COOKIE['MAX_AGE'],
            httponly=settings.REFRESH_TOKEN_COOKIE['HTTPONLY'],
            secure=settings.REFRESH_TOKEN_COOKIE['SECURE'],
            samesite=settings.REFRESH_TOKEN_COOKIE['SAMESITE'],
            path=settings.REFRESH_TOKEN_COOKIE['PATH']
        )
        
        logger.info(f"User logged in: {user.email}")
        
        return response


class RefreshTokenView(APIView):
    """
    Token refresh endpoint with rotation
    Rotates refresh token: invalidates old, issues new
    """
    permission_classes = [AllowAny]
    
    @method_decorator(ratelimit(key='ip', rate=settings.RATE_LIMITS['REFRESH'], method='POST'))
    def post(self, request):
        """Refresh access token using refresh token from cookie"""
        
        # Get refresh token from cookie
        refresh_token_raw = request.COOKIES.get(settings.REFRESH_TOKEN_COOKIE['NAME'])
        
        if not refresh_token_raw:
            return Response({
                'error': True,
                'message': 'Refresh token not found'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        # Hash the token to find it in database
        refresh_token_hash = jwt_handler.hash_token(refresh_token_raw)
        
        try:
            # Find the refresh token
            refresh_token = RefreshToken.objects.select_related('user').get(
                token_hash=refresh_token_hash
            )
            
            # Validate token
            if not refresh_token.is_valid():
                if refresh_token.revoked:
                    logger.warning(f"Attempt to use revoked refresh token for user: {refresh_token.user.email}")
                    # Potential token theft - revoke all user tokens
                    RefreshToken.objects.filter(user=refresh_token.user, revoked=False).update(
                        revoked=True,
                        revoked_at=timezone.now()
                    )
                    return Response({
                        'error': True,
                        'message': 'Refresh token has been revoked'
                    }, status=status.HTTP_401_UNAUTHORIZED)
                else:
                    return Response({
                        'error': True,
                        'message': 'Refresh token has expired'
                    }, status=status.HTTP_401_UNAUTHORIZED)
            
            user = refresh_token.user
            
            if not user.is_active:
                return Response({
                    'error': True,
                    'message': 'Account is disabled'
                }, status=status.HTTP_403_FORBIDDEN)
            
            # Generate new tokens (rotation)
            new_access_token = jwt_handler.generate_access_token(user)
            new_refresh_token_raw = jwt_handler.generate_refresh_token()
            new_refresh_token_hash = jwt_handler.hash_token(new_refresh_token_raw)
            
            # Create new refresh token record
            new_refresh_token = RefreshToken.objects.create(
                user=user,
                token_hash=new_refresh_token_hash,
                expires_at=timezone.now() + settings.JWT_SETTINGS['REFRESH_TOKEN_LIFETIME'],
                ip_address=get_client_ip(request),
                user_agent=get_user_agent(request),
                fingerprint=create_fingerprint(request)
            )
            
            # Mark old token as replaced
            refresh_token.replaced_by = new_refresh_token
            refresh_token.revoked = True
            refresh_token.revoked_at = timezone.now()
            refresh_token.save()
            
            # Create response with new access token
            response = Response({
                'message': 'Token refreshed successfully',
                'access_token': new_access_token
            }, status=status.HTTP_200_OK)
            
            # Set new refresh token cookie
            response.set_cookie(
                key=settings.REFRESH_TOKEN_COOKIE['NAME'],
                value=new_refresh_token_raw,
                max_age=settings.REFRESH_TOKEN_COOKIE['MAX_AGE'],
                httponly=settings.REFRESH_TOKEN_COOKIE['HTTPONLY'],
                secure=settings.REFRESH_TOKEN_COOKIE['SECURE'],
                samesite=settings.REFRESH_TOKEN_COOKIE['SAMESITE'],
                path=settings.REFRESH_TOKEN_COOKIE['PATH']
            )
            
            logger.info(f"Token refreshed for user: {user.email}")
            
            return response
        
        except RefreshToken.DoesNotExist:
            logger.warning("Invalid refresh token attempt")
            return Response({
                'error': True,
                'message': 'Invalid refresh token'
            }, status=status.HTTP_401_UNAUTHORIZED)


class LogoutView(APIView):
    """
    Logout endpoint
    Revokes refresh token and clears cookie
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Logout user and revoke refresh token"""
        
        # Get refresh token from cookie
        refresh_token_raw = request.COOKIES.get(settings.REFRESH_TOKEN_COOKIE['NAME'])
        
        if refresh_token_raw:
            refresh_token_hash = jwt_handler.hash_token(refresh_token_raw)
            
            try:
                # Find and revoke the refresh token
                refresh_token = RefreshToken.objects.get(token_hash=refresh_token_hash)
                refresh_token.revoke()
                logger.info(f"User logged out: {request.user.email}")
            except RefreshToken.DoesNotExist:
                pass
        
        # Create response
        response = Response({
            'message': 'Logged out successfully'
        }, status=status.HTTP_200_OK)
        
        # Delete refresh token cookie
        response.delete_cookie(
            key=settings.REFRESH_TOKEN_COOKIE['NAME'],
            path=settings.REFRESH_TOKEN_COOKIE['PATH']
        )
        
        return response


class LogoutAllView(APIView):
    """
    Logout from all devices
    Revokes all refresh tokens for the user
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Revoke all refresh tokens for the user"""
        
        # Revoke all user's refresh tokens
        RefreshToken.objects.filter(
            user=request.user,
            revoked=False
        ).update(
            revoked=True,
            revoked_at=timezone.now()
        )
        
        logger.info(f"User logged out from all devices: {request.user.email}")
        
        # Create response
        response = Response({
            'message': 'Logged out from all devices successfully'
        }, status=status.HTTP_200_OK)
        
        # Delete refresh token cookie
        response.delete_cookie(
            key=settings.REFRESH_TOKEN_COOKIE['NAME'],
            path=settings.REFRESH_TOKEN_COOKIE['PATH']
        )
        
        return response


class CurrentUserView(APIView):
    """
    Get current user information
    Protected endpoint that requires valid access token
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Return current user data"""
        serializer = UserSerializer(request.user)
        return Response({
            'user': serializer.data
        }, status=status.HTTP_200_OK)


class ChangePasswordView(APIView):
    """Change user password"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Change user password"""
        serializer = PasswordChangeSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                'error': True,
                'message': 'Invalid data',
                'details': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        user = request.user
        
        # Verify old password
        if not user.check_password(serializer.validated_data['old_password']):
            return Response({
                'error': True,
                'message': 'Old password is incorrect'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Set new password
        user.set_password(serializer.validated_data['new_password'])
        user.save()
        
        # Revoke all refresh tokens for security
        RefreshToken.objects.filter(user=user, revoked=False).update(
            revoked=True,
            revoked_at=timezone.now()
        )
        
        logger.info(f"Password changed for user: {user.email}")
        
        return Response({
            'message': 'Password changed successfully. Please login again.'
        }, status=status.HTTP_200_OK)


class HealthCheckView(APIView):
    """
    Health check endpoint for Kubernetes liveness/readiness probes
    """
    permission_classes = [AllowAny]
    
    def get(self, request):
        """Return health status"""
        from django.db import connection
        
        try:
            # Check database connectivity
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            
            return Response({
                'status': 'healthy',
                'service': 'auth-service',
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return Response({
                'status': 'unhealthy',
                'service': 'auth-service',
                'error': str(e),
                'timestamp': timezone.now().isoformat()
            }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
