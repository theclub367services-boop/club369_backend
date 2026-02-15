from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
import json

class JWTCookieMiddleware(MiddlewareMixin):
    """
    Middleware to handle JWT tokens in cookies using session bridging.
    """
    def process_request(self, request):
        """
        Injected access_token from cookies into the Authorization header for DRF.
        """
        access_token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE'])
        if access_token:
            request.META['HTTP_AUTHORIZATION'] = f"Bearer {access_token}"

    def process_response(self, request, response):
        """
        Intercepts response to set JWT cookies from session.
        """
        # Check if jwt_tokens were bridged via session
        jwt_tokens = request.session.get('jwt_tokens')
        
        if jwt_tokens:
            access_token = jwt_tokens.get('access')
            refresh_token = jwt_tokens.get('refresh')
            
            if access_token:
                response.set_cookie(
                    key=settings.SIMPLE_JWT['AUTH_COOKIE'],
                    value=access_token,
                    max_age=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds(),
                    httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                    secure=settings.SIMPLE_JWT.get('AUTH_COOKIE_SECURE', False),
                    samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE'],
                    path=settings.SIMPLE_JWT['AUTH_COOKIE_PATH']
                )

            if refresh_token:
                response.set_cookie(
                    key=settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],
                    value=refresh_token,
                    max_age=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'].total_seconds(),
                    httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                    secure=settings.SIMPLE_JWT.get('AUTH_COOKIE_SECURE', False),
                    samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE'],
                    path=settings.SIMPLE_JWT['AUTH_COOKIE_PATH']
                )

            # Cleanup session bridging key
            del request.session['jwt_tokens']

        return response
