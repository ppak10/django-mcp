# views.py
from collections.abc import Sequence
from rest_framework.views import APIView
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, BasePermission, OperandHolder, SingleOperandHolder
from django.http import HttpResponse, HttpRequest
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views.decorators.http import require_http_methods
from pydantic import AnyHttpUrl

from mcp.server.auth.json_response import PydanticJSONResponse
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthMetadata, ProtectedResourceMetadata

PermissionClass = type[BasePermission] | OperandHolder | SingleOperandHolder

import json

# Constants
AUTHORIZATION_PATH = "/authorize"
TOKEN_PATH = "/token"
REGISTRATION_PATH = "/register"
REVOCATION_PATH = "/revoke"

class CORSMixin:
    """Mixin to handle CORS headers for OAuth endpoints"""
    
    def dispatch(self, request, *args, **kwargs):
        response = super().dispatch(request, *args, **kwargs)
        
        # Add CORS headers
        response['Access-Control-Allow-Origin'] = '*'
        response['Access-Control-Allow-Methods'] = ', '.join(self.get_allowed_methods())
        response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-MCP-Protocol-Version'
        
        return response
    
    def get_allowed_methods(self):
        """Override in subclasses to specify allowed methods"""
        return ['GET', 'POST', 'OPTIONS']
    
    def options(self, request, *args, **kwargs):
        """Handle preflight OPTIONS requests"""
        response = HttpResponse()
        response['Access-Control-Allow-Origin'] = '*'
        response['Access-Control-Allow-Methods'] = ', '.join(self.get_allowed_methods())
        response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-MCP-Protocol-Version'
        return response

# @dataclass
# class MetadataHandler:
#     metadata: OAuthMetadata
# 
#     async def handle(self, request: Request) -> Response:
#         return PydanticJSONResponse(
#             content=self.metadata,
#             headers={"Cache-Control": "public, max-age=3600"},  # Cache for 1 hour
#         )

class OAuthProtectedResource(APIView):
    """OAuth Protected Resource endpoint"""

    permission_classes: Sequence[PermissionClass] = [AllowAny]
    
    def get_allowed_methods(self):
        return ['GET', 'OPTIONS']
    
    def get(self, request: HttpRequest):
        print('called get')
        # Build metadata using your existing build_metadata function
        print(request.headers)
        metadata = ProtectedResourceMetadata(
            resource="",
            authorization_servers="",
        )
        print(metadata)
        return PydanticJSONResponse(
            content=metadata,
            headers={"Cache-Control": "public, max-age=3600"},  # Cache for 1 hour
        )

class OAuthAuthorizationServer(APIView):
    """OAuth Authorization Server Metadata endpoint"""
    permission_classes: Sequence[PermissionClass] = [AllowAny]
    
    def get_allowed_methods(self):
        return ['GET', 'OPTIONS']
    
    def get(self, request: Request):
        metadata = self.build_metadata()

        return Response(
            headers={"Cache-Control": "public, max-age=3600"},
            data=metadata.model_dump_json(exclude_none=True).encode("utf-8"),
        )
    
    def build_metadata(self):
        # TODO: Replace this issuer url with value obtained from django settings
        issuer_url: AnyHttpUrl = "http://127.0.0.1:8002/"
        authorization_url = AnyHttpUrl(str(issuer_url).rstrip("/") + AUTHORIZATION_PATH)
        token_url = AnyHttpUrl(str(issuer_url).rstrip("/") + TOKEN_PATH)
        service_documentation_url = None

        client_registration_options = ClientRegistrationOptions(
            enabled=True,
            client_secret_expiry_seconds=None,
            valid_scopes=['user'],
            default_scopes=['user'],
        )
        revocation_options = RevocationOptions()


        # Create metadata
        metadata = OAuthMetadata(
            issuer=issuer_url,
            authorization_endpoint=authorization_url,
            token_endpoint=token_url,
            scopes_supported=client_registration_options.valid_scopes,
            response_types_supported=["code"],
            response_modes_supported=None,
            grant_types_supported=["authorization_code", "refresh_token"],
            token_endpoint_auth_methods_supported=["client_secret_post"],
            token_endpoint_auth_signing_alg_values_supported=None,
            service_documentation=service_documentation_url,
            ui_locales_supported=None,
            op_policy_uri=None,
            op_tos_uri=None,
            introspection_endpoint=None,
            code_challenge_methods_supported=["S256"],
        )

        # Add registration endpoint if supported
        if client_registration_options.enabled:
            metadata.registration_endpoint = AnyHttpUrl(str(issuer_url).rstrip("/") + REGISTRATION_PATH)

        # Add revocation endpoint if supported
        if revocation_options.enabled:
            metadata.revocation_endpoint = AnyHttpUrl(str(issuer_url).rstrip("/") + REVOCATION_PATH)
            metadata.revocation_endpoint_auth_methods_supported = ["client_secret_post"]

        return metadata

class RegisterView(APIView):
    """OAuth Client Registration endpoint"""
    permission_classes: Sequence[PermissionClass] = [AllowAny]
    
    def get_allowed_methods(self):
        return ['POST', 'OPTIONS']
    
    def post(self, request: Request):
        print(f"register: {request.data}")
        # Handle client registration
        # Your existing RegistrationHandler.handle logic
        pass

class AuthorizationView(APIView):
    """OAuth Authorization endpoint - no CORS"""
    permission_classes = [AllowAny]
    
    def __init__(self, provider):
        super().__init__()
        self.provider = provider
    
    def get(self, request):
        # Handle authorization request
        # Your existing AuthorizationHandler.handle logic
        pass
    
    def post(self, request):
        # Handle authorization form submission
        # Your existing AuthorizationHandler.handle logic
        pass


class TokenView(CORSMixin, APIView):
    """OAuth Token endpoint"""
    permission_classes = [AllowAny]
    
    def __init__(self, provider, client_authenticator):
        super().__init__()
        self.provider = provider
        self.client_authenticator = client_authenticator
    
    def get_allowed_methods(self):
        return ['POST', 'OPTIONS']
    
    def post(self, request):
        # Handle token request
        # Your existing TokenHandler.handle logic
        pass



class RevocationView(CORSMixin, APIView):
    """OAuth Token Revocation endpoint"""
    permission_classes = [AllowAny]
    
    def __init__(self, provider, client_authenticator):
        super().__init__()
        self.provider = provider
        self.client_authenticator = client_authenticator
    
    def get_allowed_methods(self):
        return ['POST', 'OPTIONS']
    
    def post(self, request):
        # Handle token revocation
        # Your existing RevocationHandler.handle logic
        pass


# Factory function to create view instances
def create_oauth_views(
    provider,
    issuer_url,
    service_documentation_url=None,
    client_registration_options=None,
    revocation_options=None,
):
    """Factory function to create OAuth view instances"""
    
    client_registration_options = client_registration_options or ClientRegistrationOptions()
    revocation_options = revocation_options or RevocationOptions()
    
    views = {
        'metadata': MetadataView(
            provider, 
            issuer_url, 
            service_documentation_url,
            client_registration_options,
            revocation_options
        ),
        'authorization': AuthorizationView(provider),
        'token': TokenView(provider, ClientAuthenticator(provider)),
    }
    
    if client_registration_options.enabled:
        views['registration'] = RegistrationView(provider, client_registration_options)
    
    if revocation_options.enabled:
        views['revocation'] = RevocationView(provider, ClientAuthenticator(provider))
    
    return views
