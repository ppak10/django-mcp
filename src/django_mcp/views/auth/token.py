import base64
import hashlib
import json
import time

from asgiref.sync import async_to_sync

from django_mcp.auth.provider import auth_provider

from mcp.server.auth.errors import stringify_pydantic_error
from mcp.server.auth.middleware.client_auth import AuthenticationError, ClientAuthenticator
from mcp.server.auth.provider import TokenError
from mcp.server.auth.handlers.token import TokenRequest, TokenSuccessResponse, TokenErrorResponse, AuthorizationCodeRequest, RefreshTokenRequest
from mcp.shared.auth import OAuthToken

from pydantic import ValidationError

from rest_framework.views import APIView
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework import status

from uuid import uuid4

class TokenView(APIView):
    # TODO: Remove
    permission_classes = [AllowAny]
    
    def create_response(self, obj: TokenSuccessResponse | TokenErrorResponse):
        status_code = status.HTTP_200_OK 
        if isinstance(obj, TokenErrorResponse):
            status_code = status.HTTP_400_BAD_REQUEST
        return Response(
            data=json.loads(obj.model_dump_json(exclude_none=True).encode("utf-8")),
            status=status_code,
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
            },
        )

    def post(self, request: Request):
        provider = auth_provider
        client_authenticator = ClientAuthenticator(provider)

        try:
            form_data = request.data
            print(f"form_data: {form_data}")
            print(f"form_data dict: {dict(form_data)}")
            flat_form_data = {key: form_data.get(key) for key in dict(form_data)}
            token_request = TokenRequest.model_validate(flat_form_data).root
            print(f"token_request: {token_request}")
        except ValidationError as validation_error:
            print(f"validation_error: {validation_error}")
            return self.create_response(
                TokenErrorResponse(
                    error="invalid_request",
                    error_description=stringify_pydantic_error(validation_error),
                )
            )

        try:
            client_info = async_to_sync(client_authenticator.authenticate)(
                client_id=token_request.client_id,
                client_secret=token_request.client_secret,
            )
        except AuthenticationError as e:
            return self.create_response(
                TokenErrorResponse(
                    error="unauthorized_client",
                    error_description=e.message,
                )
            )

        if token_request.grant_type not in client_info.grant_types:
            return self.create_response(
                TokenErrorResponse(
                    error="unsupported_grant_type",
                    error_description=(f"Unsupported grant type (supported grant types are {client_info.grant_types})"),
                )
            )

        tokens: OAuthToken

        match token_request:
            case AuthorizationCodeRequest():
                auth_code = async_to_sync(provider.load_authorization_code)(client_info, token_request.code)
                if auth_code is None or auth_code.client_id != token_request.client_id:
                    # if code belongs to different client, pretend it doesn't exist
                    return self.create_response(
                        TokenErrorResponse(
                            error="invalid_grant",
                            error_description="authorization code does not exist",
                        )
                    )

                # make auth codes expire after a deadline
                # see https://datatracker.ietf.org/doc/html/rfc6749#section-10.5
                if auth_code.expires_at < time.time():
                    return self.create_response(
                        TokenErrorResponse(
                            error="invalid_grant",
                            error_description="authorization code has expired",
                        )
                    )

                # verify redirect_uri doesn't change between /authorize and /tokens
                # see https://datatracker.ietf.org/doc/html/rfc6749#section-10.6
                if auth_code.redirect_uri_provided_explicitly:
                    authorize_request_redirect_uri = auth_code.redirect_uri
                else:
                    authorize_request_redirect_uri = None

                # Convert both sides to strings for comparison to handle AnyUrl vs string issues
                token_redirect_str = str(token_request.redirect_uri) if token_request.redirect_uri is not None else None
                auth_redirect_str = (
                    str(authorize_request_redirect_uri) if authorize_request_redirect_uri is not None else None
                )

                if token_redirect_str != auth_redirect_str:
                    return self.create_response(
                        TokenErrorResponse(
                            error="invalid_request",
                            error_description=("redirect_uri did not match the one used when creating auth code"),
                        )
                    )

                # Verify PKCE code verifier
                sha256 = hashlib.sha256(token_request.code_verifier.encode()).digest()
                hashed_code_verifier = base64.urlsafe_b64encode(sha256).decode().rstrip("=")

                if hashed_code_verifier != auth_code.code_challenge:
                    # see https://datatracker.ietf.org/doc/html/rfc7636#section-4.6
                    return self.create_response(
                        TokenErrorResponse(
                            error="invalid_grant",
                            error_description="incorrect code_verifier",
                        )
                    )

                try:
                    # Exchange authorization code for tokens
                    tokens = async_to_sync(provider.exchange_authorization_code)(client_info, auth_code)
                except TokenError as e:
                    return self.create_response(
                        TokenErrorResponse(
                            error=e.error,
                            error_description=e.error_description,
                        )
                    )

            case RefreshTokenRequest():
                refresh_token = async_to_sync(provider.load_refresh_token)(client_info, token_request.refresh_token)
                if refresh_token is None or refresh_token.client_id != token_request.client_id:
                    # if token belongs to different client, pretend it doesn't exist
                    return self.create_response(
                        TokenErrorResponse(
                            error="invalid_grant",
                            error_description="refresh token does not exist",
                        )
                    )

                if refresh_token.expires_at and refresh_token.expires_at < time.time():
                    # if the refresh token has expired, pretend it doesn't exist
                    return self.create_response(
                        TokenErrorResponse(
                            error="invalid_grant",
                            error_description="refresh token has expired",
                        )
                    )

                # Parse scopes if provided
                scopes = token_request.scope.split(" ") if token_request.scope else refresh_token.scopes

                for scope in scopes:
                    if scope not in refresh_token.scopes:
                        return self.create_response(
                            TokenErrorResponse(
                                error="invalid_scope",
                                error_description=(f"cannot request scope `{scope}` not provided by refresh token"),
                            )
                        )

                try:
                    # Exchange refresh token for new tokens
                    tokens = async_to_sync(provider.exchange_refresh_token)(client_info, refresh_token, scopes)
                except TokenError as e:
                    return self.create_response(
                        TokenErrorResponse(
                            error=e.error,
                            error_description=e.error_description,
                        )
                    )

        return self.create_response(TokenSuccessResponse(root=tokens))
