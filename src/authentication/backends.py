"""
Custom JWT Authentication Backend for Django REST Framework
"""
from rest_framework import authentication
from rest_framework import exceptions
from django.conf import settings
import jwt
import logging

from .models import User
from .jwt_utils import jwt_handler

logger = logging.getLogger('authentication')


class JWTAuthentication(authentication.BaseAuthentication):
    """
    Custom JWT authentication class for DRF
    Validates access tokens from Authorization header
    """
    
    authentication_header_prefix = 'Bearer'
    
    def authenticate(self, request):
        """
        Authenticate request using JWT access token
        Returns (user, token) tuple or None
        """
        # Get authorization header
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        
        if not auth_header:
            return None
        
        # Parse header
        auth_parts = auth_header.split()
        
        if len(auth_parts) != 2:
            return None
        
        prefix, token = auth_parts
        
        if prefix.lower() != self.authentication_header_prefix.lower():
            return None
        
        # Verify token
        return self._authenticate_credentials(request, token)
    
    def _authenticate_credentials(self, request, token):
        """
        Verify the JWT token and return the user
        """
        try:
            # Verify and decode token
            payload = jwt_handler.verify_access_token(token)
            
        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed('Access token has expired')
        
        except jwt.InvalidTokenError as e:
            raise exceptions.AuthenticationFailed(f'Invalid token: {str(e)}')
        
        # Get user from token payload
        user_id = payload.get('sub')
        
        if not user_id:
            raise exceptions.AuthenticationFailed('Token payload invalid')
        
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed('User not found')
        
        if not user.is_active:
            raise exceptions.AuthenticationFailed('User account is disabled')
        
        return (user, token)
    
    def authenticate_header(self, request):
        """
        Return the WWW-Authenticate header for 401 responses
        """
        return f'{self.authentication_header_prefix} realm="api"'
