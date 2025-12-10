"""
URL configuration for auth_service project.
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from authentication.jwt_utils import jwt_handler


@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    """Health check endpoint"""
    return Response({'status': 'ok', 'message': 'API is running'})


@api_view(['GET'])
@permission_classes([AllowAny])
def jwks_endpoint(request):
    """JWKS endpoint for RS256 public key distribution"""
    try:
        jwks = jwt_handler.get_jwks()
        return Response(jwks)
    except ValueError as e:
        return Response({'error': str(e)}, status=400)


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('authentication.urls')),
    path('api/health/', health_check, name='health-check'),
    path('.well-known/jwks.json', jwks_endpoint, name='jwks'),  # Standard JWKS endpoint
]
