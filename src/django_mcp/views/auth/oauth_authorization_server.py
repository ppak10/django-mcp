import json

from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthMetadata

from pydantic import AnyHttpUrl

from rest_framework.views import APIView
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.permissions import AllowAny

# Constants
AUTHORIZATION_PATH = "/authorize"
TOKEN_PATH = "/token"
REGISTRATION_PATH = "/register"
REVOCATION_PATH = "/revoke"

class OAuthAuthorizationServerView(APIView):
    """OAuth Authorization Server Metadata endpoint"""

    # TODO: Remove
    permission_classes = [AllowAny]
    
    def get_allowed_methods(self):
        return ['GET', 'OPTIONS']
    
    def get(self, request: Request):
        metadata = self.build_metadata()

        return Response(
            headers={"Cache-Control": "public, max-age=3600"},
            data=json.loads(metadata.model_dump_json(exclude_none=True).encode("utf-8")),
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

