import json
import secrets
import time

from asgiref.sync import async_to_sync

from django_mcp.auth.provider import auth_provider

from mcp.server.auth.errors import stringify_pydantic_error
from mcp.server.auth.settings import ClientRegistrationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata
from mcp.server.auth.provider import RegistrationError
from mcp.server.auth.handlers.register import RegistrationErrorResponse

from pydantic import ValidationError

from rest_framework.views import APIView
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework import status

from uuid import uuid4

class RegisterView(APIView):
    """OAuth Client Registration endpoint"""

    # TODO: Remove
    permission_classes = [AllowAny]
    
    def post(self, request: Request):
        provider = auth_provider
        options = ClientRegistrationOptions(
            enabled=True,
            client_secret_expiry_seconds=None,
            valid_scopes=['user'],
            default_scopes=['user'],
        )

        try:
            # Parse request body as JSON
            data = request.data
            client_metadata = OAuthClientMetadata.model_validate(data)

        except ValidationError as validation_error:
            return Response(
                data=json.loads(RegistrationErrorResponse(
                    error="invalid_client_metadata",
                    error_description=stringify_pydantic_error(validation_error),
                ).model_dump_json(exclude_none=True).encode("utf-8")),
                status=status.HTTP_400_BAD_REQUEST,
            )

        client_id = str(uuid4())
        client_secret = None
        if client_metadata.token_endpoint_auth_method != "none":
            # cryptographically secure random 32-byte hex string
            client_secret = secrets.token_hex(32)

        if client_metadata.scope is None and options.default_scopes is not None:
            client_metadata.scope = " ".join(options.default_scopes)
        elif client_metadata.scope is not None and options.valid_scopes is not None:
            requested_scopes = set(client_metadata.scope.split())
            valid_scopes = set(options.valid_scopes)
            if not requested_scopes.issubset(valid_scopes):
                return Response(
                    data=json.loads(RegistrationErrorResponse(
                        error="invalid_client_metadata",
                        error_description=f"Requested scopes are not valid: {', '.join(requested_scopes - valid_scopes)}",
                    ).model_dump_json(exclude_none=True).encode("utf-8")),
                    status=status.HTTP_400_BAD_REQUEST,
                )

        if set(client_metadata.grant_types) != {"authorization_code", "refresh_token"}:
            return Response(
                data=json.loads(RegistrationErrorResponse(
                    error="invalid_client_metadata",
                    error_description="grant_types must be authorization_code and refresh_token",
                ).model_dump_json(exclude_none=True).encode("utf-8")),
                status=status.HTTP_400_BAD_REQUEST,
            )

        client_id_issued_at = int(time.time())
        client_secret_expires_at = (
            client_id_issued_at + options.client_secret_expiry_seconds
            if options.client_secret_expiry_seconds is not None
            else None
        )

        client_info = OAuthClientInformationFull(
            client_id=client_id,
            client_id_issued_at=client_id_issued_at,
            client_secret=client_secret,
            client_secret_expires_at=client_secret_expires_at,
            # passthrough information from the client request
            redirect_uris=client_metadata.redirect_uris,
            token_endpoint_auth_method=client_metadata.token_endpoint_auth_method,
            grant_types=client_metadata.grant_types,
            response_types=client_metadata.response_types,
            client_name=client_metadata.client_name,
            client_uri=client_metadata.client_uri,
            logo_uri=client_metadata.logo_uri,
            scope=client_metadata.scope,
            contacts=client_metadata.contacts,
            tos_uri=client_metadata.tos_uri,
            policy_uri=client_metadata.policy_uri,
            jwks_uri=client_metadata.jwks_uri,
            jwks=client_metadata.jwks,
            software_id=client_metadata.software_id,
            software_version=client_metadata.software_version,
        )

        try:
            # Register client
            async_to_sync(provider.register_client)(client_info)

            # Return client information
            return Response(
                content_type="application/json",
                data=json.loads(client_info.model_dump_json(exclude_none=True).encode("utf-8")),
                status=status.HTTP_201_CREATED
            )
        except RegistrationError as e:
            # Handle registration errors as defined in RFC 7591 Section 3.2.2
            return Response(
                data=json.loads(RegistrationErrorResponse(
                    error=e.error,
                    error_description=e.error_description,
                ).model_dump_json(exclude_none=True).encode("utf-8")),
                status=status.HTTP_400_BAD_REQUEST,
            )
