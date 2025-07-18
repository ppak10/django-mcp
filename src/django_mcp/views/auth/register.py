import secrets
import time
import json

from django_mcp.auth.provider import AuthProvider

from mcp.server.auth.errors import stringify_pydantic_error
from mcp.server.auth.settings import ClientRegistrationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata
from mcp.server.auth.provider import RegistrationError, RegistrationErrorCode

from pydantic import BaseModel, ValidationError

from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from uuid import uuid4

class RegistrationErrorResponse(BaseModel):
    error: RegistrationErrorCode
    error_description: str | None

@csrf_exempt
@require_http_methods(["POST"])
async def register_view(request: HttpRequest):
    """OAuth Client Registration endpoint"""
    
    print('called')
    provider = AuthProvider()
    options = ClientRegistrationOptions(
        enabled=True,
        client_secret_expiry_seconds=None,
        valid_scopes=['user'],
        default_scopes=['user'],
    )

    try:
        # Parse request body as JSON
        data = json.loads(request.body.decode('utf-8'))
        client_metadata = OAuthClientMetadata.model_validate(data)

    except ValidationError as validation_error:
        return HttpResponseBadRequest(
            RegistrationErrorResponse(
                error="invalid_client_metadata",
                error_description=stringify_pydantic_error(validation_error),
            )
        )

    client_id = str(uuid4())
    print(client_id)
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
            return HttpResponseBadRequest(
                RegistrationErrorResponse(
                    error="invalid_client_metadata",
                    error_description= f"Requested scopes are not valid: {', '.join(requested_scopes - valid_scopes)}",
                )
            )
    if set(client_metadata.grant_types) != {"authorization_code", "refresh_token"}:
        return HttpResponseBadRequest(
            RegistrationErrorResponse(
                error="invalid_client_metadata",
                error_description="grant_types must be authorization_code and refresh_token",
            )
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

    print(client_info)
    try:
        # Register client - now this await will work
        await provider.register_client(client_info)

        # Return client information
        return HttpResponse(
            client_info.model_dump_json(exclude_none=True).encode("utf-8"),
        )
    except RegistrationError as e:
        # Handle registration errors as defined in RFC 7591 Section 3.2.2
        return HttpResponseBadRequest(
            RegistrationErrorResponse(
                error=e.error,
                error_description=e.error_description,
            )
        )
