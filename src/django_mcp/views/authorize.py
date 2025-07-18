from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.urls import reverse
from pydantic import AnyHttpUrl, ValidationError
import logging

from mcp.server.auth.provider import AuthorizationParams
from .auth_provider import auth_provider  # Your AuthProvider instance
from .models import OAuthClient  # Your Django model for OAuth clients

logger = logging.getLogger(__name__)


@method_decorator(csrf_exempt, name='dispatch')
class AuthorizeView(View):
    """
    OAuth 2.0 Authorization Endpoint
    
    Handles the initial authorization request from OAuth clients.
    This is the /oauth/authorize/ endpoint that clients redirect users to.
    """
    
    async def get(self, request: HttpRequest) -> HttpResponse:
        """
        Handle GET request to authorization endpoint.
        
        Expected parameters:
        - client_id: The OAuth client identifier
        - redirect_uri: Where to redirect after authorization
        - response_type: Must be 'code' for authorization code flow
        - state: CSRF protection token (optional but recommended)
        - code_challenge: PKCE code challenge (optional)
        - code_challenge_method: PKCE method, typically 'S256' (optional)
        - scope: Requested scopes (optional)
        - resource: RFC 8707 resource parameter (optional)
        """
        try:
            # Extract and validate required parameters
            client_id = request.GET.get('client_id')
            redirect_uri = request.GET.get('redirect_uri')
            response_type = request.GET.get('response_type')
            
            if not client_id:
                return self._error_response("Missing client_id parameter", status=400)
            
            if not redirect_uri:
                return self._error_response("Missing redirect_uri parameter", status=400)
            
            if response_type != 'code':
                return self._error_response(
                    "Invalid response_type. Only 'code' is supported", 
                    status=400
                )
            
            # Load client information
            client = await auth_provider.get_client(client_id)
            if not client:
                return self._error_response("Invalid client_id", status=400)
            
            # Validate redirect URI against registered URIs
            if not self._is_valid_redirect_uri(redirect_uri, client.redirect_uris):
                return self._error_response("Invalid redirect_uri", status=400)
            
            # Extract optional parameters
            state = request.GET.get('state')
            code_challenge = request.GET.get('code_challenge')
            code_challenge_method = request.GET.get('code_challenge_method', 'S256')
            scope = request.GET.get('scope', 'user')  # Default MCP scope
            resource = request.GET.get('resource')  # RFC 8707
            
            # Validate PKCE parameters if present
            if code_challenge and code_challenge_method not in ['S256', 'plain']:
                return self._error_response("Invalid code_challenge_method", status=400)
            
            # Build authorization parameters
            try:
                auth_params = AuthorizationParams(
                    redirect_uri=AnyHttpUrl(redirect_uri),
                    redirect_uri_provided_explicitly=True,
                    state=state,
                    code_challenge=code_challenge,
                    code_challenge_method=code_challenge_method,
                    scope=scope,
                    resource=resource
                )
            except ValidationError as e:
                logger.error(f"Invalid authorization parameters: {e}")
                return self._error_response("Invalid request parameters", status=400)
            
            # Call the provider's authorize method
            auth_url = await auth_provider.authorize(client, auth_params)
            
            # Redirect to the authorization URL (typically your login page)
            return redirect(auth_url)
            
        except Exception as e:
            logger.error(f"Authorization error: {e}")
            return self._error_response("Internal server error", status=500)
    
    def _is_valid_redirect_uri(self, redirect_uri: str, registered_uris: list[str]) -> bool:
        """
        Validate that the redirect URI matches one of the registered URIs.
        
        Args:
            redirect_uri: The redirect URI from the request
            registered_uris: List of registered redirect URIs for the client
            
        Returns:
            True if the redirect URI is valid, False otherwise
        """
        # Exact match check
        if redirect_uri in registered_uris:
            return True
        
        # For development, you might want to allow localhost with any port
        # This should be removed in production
        if redirect_uri.startswith('http://localhost:') or redirect_uri.startswith('http://127.0.0.1:'):
            for registered_uri in registered_uris:
                if registered_uri.startswith('http://localhost') or registered_uri.startswith('http://127.0.0.1'):
                    return True
        
        return False
    
    def _error_response(self, error_message: str, status: int = 400) -> HttpResponse:
        """
        Return an error response.
        
        Args:
            error_message: The error message to display
            status: HTTP status code
            
        Returns:
            HttpResponse with error message
        """
        return HttpResponse(
            f"OAuth Authorization Error: {error_message}",
            status=status,
            content_type='text/plain'
        )
