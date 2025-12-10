"""
JWT Utility Module
Handles JWT token generation and verification using RS256 algorithm
"""
import jwt
import hashlib
import secrets
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
from pathlib import Path
import logging

logger = logging.getLogger('authentication')


class JWTHandler:
    """
    Handles JWT token generation and verification using RS256 (asymmetric RSA)
    """
    
    def __init__(self):
        self.algorithm = 'RS256'
        self.access_lifetime = settings.JWT_SETTINGS['ACCESS_TOKEN_LIFETIME']
        self.refresh_lifetime = settings.JWT_SETTINGS['REFRESH_TOKEN_LIFETIME']
        self.issuer = settings.JWT_SETTINGS['ISSUER']
        self.audience = settings.JWT_SETTINGS['AUDIENCE']
        
        # Load RSA keys
        self._load_rsa_keys()
    
    def _load_rsa_keys(self):
        """Load RSA private and public keys for RS256"""
        try:
            private_key_path = Path(settings.BASE_DIR) / settings.JWT_SETTINGS['PRIVATE_KEY_PATH']
            public_key_path = Path(settings.BASE_DIR) / settings.JWT_SETTINGS['PUBLIC_KEY_PATH']
            
            if not private_key_path.exists() or not public_key_path.exists():
                raise FileNotFoundError(
                    f"RSA keys not found. Generate them using:\n"
                    f"python manage.py generate_keys"
                )
            
            with open(private_key_path, 'r') as f:
                self.private_key = f.read()
            
            with open(public_key_path, 'r') as f:
                self.public_key = f.read()
            
            logger.info("RSA keys loaded successfully")
        except Exception as e:
            logger.error(f"Error loading RSA keys: {e}")
            raise
    
    def generate_access_token(self, user):
        """
        Generate a short-lived access token
        Contains minimal claims: sub, exp, iat, roles
        """
        now = timezone.now()
        exp = now + self.access_lifetime
        
        payload = {
            'sub': str(user.id),  # Subject (user ID)
            'email': user.email,
            'username': user.username,
            'role': user.role,
            'exp': int(exp.timestamp()),  # Expiration time
            'iat': int(now.timestamp()),  # Issued at
            'iss': self.issuer,  # Issuer
            'aud': self.audience,  # Audience
            'type': 'access'
        }
        
        token = jwt.encode(
            payload,
            self.private_key,
            algorithm=self.algorithm
        )
        
        logger.info(f"Access token generated for user {user.email}")
        return token
    
    def generate_refresh_token(self):
        """
        Generate a cryptographically secure refresh token
        This is the raw token that will be hashed before storage
        """
        # Generate 32 bytes (256 bits) of random data
        token = secrets.token_urlsafe(32)
        return token
    
    def hash_token(self, token):
        """
        Hash a token for secure storage
        Uses SHA-256 for hashing
        """
        return hashlib.sha256(token.encode()).hexdigest()
    
    def verify_access_token(self, token):
        """
        Verify and decode an access token
        Returns the payload if valid, raises exception if invalid
        """
        try:
            payload = jwt.decode(
                token,
                self.public_key,
                algorithms=[self.algorithm],
                audience=self.audience,
                issuer=self.issuer
            )
            
            # Verify token type
            if payload.get('type') != 'access':
                raise jwt.InvalidTokenError('Invalid token type')
            
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Access token expired")
            raise
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid access token: {e}")
            raise
        except Exception as e:
            logger.error(f"Error verifying access token: {e}")
            raise jwt.InvalidTokenError(str(e))
    
    def decode_token_without_verification(self, token):
        """
        Decode token without verification (for debugging only)
        DO NOT use for authentication
        """
        try:
            return jwt.decode(token, options={"verify_signature": False})
        except Exception as e:
            logger.error(f"Error decoding token: {e}")
            return None
    
    def get_token_expiry(self, token):
        """Get expiration datetime from token"""
        try:
            payload = self.decode_token_without_verification(token)
            if payload and 'exp' in payload:
                return datetime.fromtimestamp(payload['exp'], tz=timezone.utc)
        except Exception:
            pass
        return None
    
    def get_jwks(self):
        """
        Generate JWKS (JSON Web Key Set) for RS256
        Used by clients to verify tokens
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        import base64
        
        # Load public key
        public_key = serialization.load_pem_public_key(
            self.public_key.encode(),
            backend=default_backend()
        )
        
        # Extract modulus and exponent
        public_numbers = public_key.public_numbers()
        
        def int_to_base64(n):
            """Convert integer to base64url encoding"""
            byte_length = (n.bit_length() + 7) // 8
            bytes_val = n.to_bytes(byte_length, byteorder='big')
            return base64.urlsafe_b64encode(bytes_val).rstrip(b'=').decode('utf-8')
        
        jwk = {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "n": int_to_base64(public_numbers.n),
            "e": int_to_base64(public_numbers.e),
        }
        
        return {
            "keys": [jwk]
        }


# Global instance
jwt_handler = JWTHandler()
