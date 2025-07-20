import json

from asgiref.sync import async_to_sync

from django_mcp.auth_provider import auth_provider

from mcp.server.auth.errors import stringify_pydantic_error
from mcp.server.auth.provider import (
    AuthorizationErrorCode,
    AuthorizationParams,
    AuthorizeError,
    construct_redirect_uri,
)
 
from mcp.server.auth.handlers.authorize import AuthorizationRequest, AuthorizationErrorResponse, best_effort_extract_string, AnyUrlModel
from mcp.shared.auth import InvalidRedirectUriError, InvalidScopeError

from pydantic import ValidationError

from rest_framework.views import APIView
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework import status

from typing_extensions import override

from uuid import uuid4

class AuthorizeView(APIView):
    """OAuth Client Registration endpoint"""

    # TODO: Remove
    permission_classes = [AllowAny]
   
    def post(self, request: Request, *args, **kwargs) -> Response:
        return self.handle(request, *args, **kwargs)

    def get(self, request: Request, *args, **kwargs) -> Response:
        return self.handle(request, *args, **kwargs)

    def handle(self, request: Request, *args, **kwargs) -> Response:
        provider = auth_provider

        state = None
        redirect_uri = None
        client = None
        params = None

        def error_response(
            error: AuthorizationErrorCode,
            error_description: str | None,
            attempt_load_client: bool = True,
        ):
            # Error responses take two different formats:
            # 1. The request has a valid client ID & redirect_uri: we issue a redirect
            #    back to the redirect_uri with the error response fields as query
            #    parameters. This allows the client to be notified of the error.
            # 2. Otherwise, we return an error response directly to the end user;
            #     we choose to do so in JSON, but this is left undefined in the
            #     specification.
            # See https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
            #
            # This logic is a bit awkward to handle, because the error might be thrown
            # very early in request validation, before we've done the usual Pydantic
            # validation, loaded the client, etc. To handle this, error_response()
            # contains fallback logic which attempts to load the parameters directly
            # from the request.

            nonlocal client, redirect_uri, state
            if client is None and attempt_load_client:
                # make last-ditch attempt to load the client
                client_id = best_effort_extract_string("client_id", params)
                client = client_id and async_to_sync(provider.get_client)(client_id)
            if redirect_uri is None and client:
                # make last-ditch effort to load the redirect uri
                try:
                    if params is not None and "redirect_uri" not in params:
                        raw_redirect_uri = None
                    else:
                        raw_redirect_uri = AnyUrlModel.model_validate(
                            best_effort_extract_string("redirect_uri", params)
                        ).root
                    redirect_uri = client.validate_redirect_uri(raw_redirect_uri)
                except (ValidationError, InvalidRedirectUriError):
                    # if the redirect URI is invalid, ignore it & just return the
                    # initial error
                    pass

            # the error response MUST contain the state specified by the client, if any
            if state is None:
                # make last-ditch effort to load state
                state = best_effort_extract_string("state", params)

            error_resp = AuthorizationErrorResponse(
                error=error,
                error_description=error_description,
                state=state,
            )

            print(f"error_resp: {error_resp.model_dump_json(exclude_none=True).encode('utf-8')}")

            if redirect_uri and client:
                return Response(
                    headers={
                        "Cache-Control": "no-store",
                        "Location": construct_redirect_uri(str(redirect_uri), **error_resp.model_dump(exclude_none=True)),
                    },
                    status=status.HTTP_302_FOUND
                )
            else:
                return Response(
                    headers={"Cache-Control": "no-store"},
                    data=json.loads(error_resp.model_dump_json(exclude_none=True).encode("utf-8")),
                    status=status.HTTP_400_BAD_REQUEST,
                )

        try:
            if request.method == "GET":
                # Convert query_params to dict for pydantic validation
                params = request.query_params.dict()
                print(params)
            elif request.method == "POST":
                # Parse form data for POST requests
                params = request.data
            else:
                return Response({"error": "Method not allowed"}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
            # Save state if it exists, even before validation
            state = best_effort_extract_string("state", params)
            print(f"state: {state}")
            print(f"params: {params}")

            try:
                auth_request = AuthorizationRequest.model_validate(params)
                print(f"auth_request: {auth_request}")
                state = auth_request.state  # Update with validated state
            except ValidationError as validation_error:
                error: AuthorizationErrorCode = "invalid_request"
                for e in validation_error.errors():
                    if e["loc"] == ("response_type",) and e["type"] == "literal_error":
                        error = "unsupported_response_type"
                        break
                return error_response(error, stringify_pydantic_error(validation_error))

            # Get client information
            client = async_to_sync(provider.get_client)(auth_request.client_id)
            print(f"client: {client}")

            if not client:
                # For client_id validation errors, return direct error (no redirect)
                return error_response(
                    error="invalid_request",
                    error_description=f"Client ID '{auth_request.client_id}' not found",
                    attempt_load_client=False,
                )

            # Validate redirect_uri against client's registered URIs
            try:
                redirect_uri = client.validate_redirect_uri(auth_request.redirect_uri)
                print(f"redirect_uri: {redirect_uri}")
            except InvalidRedirectUriError as validation_error:
                # For redirect_uri validation errors, return direct error (no redirect)
                return error_response(
                    error="invalid_request",
                    error_description=validation_error.message,
                )

            # Validate scope - for scope errors, we can redirect
            try:
                scopes = client.validate_scope(auth_request.scope)
                print(f"scopes: {scopes}")
            except InvalidScopeError as validation_error:
                # For scope errors, redirect with error parameters
                return error_response(
                    error="invalid_scope",
                    error_description=validation_error.message,
                )

            # Setup authorization parameters
            auth_params = AuthorizationParams(
                state=state,
                scopes=scopes,
                code_challenge=auth_request.code_challenge,
                redirect_uri=redirect_uri,
                redirect_uri_provided_explicitly=auth_request.redirect_uri is not None,
                resource=auth_request.resource,  # RFC 8707
            )

            print(f"auth_params: {auth_params}")

            try:
                # Let the provider pick the next URI to redirect to
                return Response(
                    headers={
                        "Cache-Control": "no-store",
                        "Location": async_to_sync(provider.authorize)(client, auth_params)
                    },
                    status=status.HTTP_302_FOUND
                )
            except AuthorizeError as e:
                # Handle authorization errors as defined in RFC 6749 Section 4.1.2.1
                return error_response(error=e.error, error_description=e.error_description)

        except Exception as validation_error:
            # Catch-all for unexpected errors
            # logger.exception("Unexpected error in authorization_handler", exc_info=validation_error)
            return error_response(error="server_error", error_description="An unexpected error occurred")
