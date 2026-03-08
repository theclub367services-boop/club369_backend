from rest_framework_simplejwt.authentication import JWTAuthentication
from django.conf import settings
from core.models import User

class CustomJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        header = self.get_header(request)
        
        if header is None:
            raw_token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE']) or None
        else:
            raw_token = self.get_raw_token(header)

        if raw_token is None:
            return None

        try:
            validated_token = self.get_validated_token(raw_token)
            
            # --- Stateless User Construction ---
            # Bypass DB lookup and rely entirely on JWT cryptographic signature
            user_id = validated_token.get(settings.SIMPLE_JWT.get('USER_ID_CLAIM', 'user_id'))
            email = validated_token.get('email', '')
            role = validated_token.get('role', 'USER')
            
            # Creating a memory-only Django User model
            user = User(id=user_id, email=email, role=role)
            # Ensure it passes basic isAuthenticated checks
            user.is_active = True
            
            # Map ADMIN role to Django's is_staff so DRF's IsAdminUser permission works
            if role == 'ADMIN':
                user.is_staff = True
                user.is_superuser = True
            
            return user, validated_token
        except Exception:
            return None
