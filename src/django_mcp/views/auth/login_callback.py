import secrets
import time

from django_mcp.auth.provider import auth_provider

from mcp.server.auth.provider import (
    AuthorizationCode,
    construct_redirect_uri,
)

from pydantic import AnyHttpUrl

from rest_framework.views import APIView
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework import status

def handle_simple_callback(username: str, password: str, state: str) -> str:
    """Handle simple authentication callback and return redirect URI."""
    provider = auth_provider
    state_data = provider.state_mapping.get(state)
    if not state_data:
        print("Invalid state parameter")
        # raise HTTPException(400, "Invalid state parameter")

    redirect_uri = state_data["redirect_uri"]
    code_challenge = state_data["code_challenge"]
    redirect_uri_provided_explicitly = state_data["redirect_uri_provided_explicitly"] == "True"
    client_id = state_data["client_id"]
    resource = state_data.get("resource")  # RFC 8707

    # These are required values from our own state mapping
    assert redirect_uri is not None
    assert code_challenge is not None
    assert client_id is not None

    # Validate demo credentials
    if username != 'demo_user' or password != 'demo_password':
        print("Invalid credentials")

    # Create MCP authorization code
    new_code = f"mcp_{secrets.token_hex(16)}"
    auth_code = AuthorizationCode(
        code=new_code,
        client_id=client_id,
        redirect_uri=AnyHttpUrl(redirect_uri),
        redirect_uri_provided_explicitly=redirect_uri_provided_explicitly,
        expires_at=time.time() + 300,
        scopes=["user"],
        code_challenge=code_challenge,
        resource=resource,  # RFC 8707
    )
    provider.auth_codes[new_code] = auth_code

    # Store user data
    provider.user_data[username] = {
        "username": username,
        "user_id": f"user_{secrets.token_hex(8)}",
        "authenticated_at": time.time(),
    }

    del provider.state_mapping[state]
    return construct_redirect_uri(redirect_uri, code=new_code, state=state)

class LoginCallbackView(APIView):
    """OAuth Client Registration endpoint"""

    # TODO: Remove
    permission_classes = [AllowAny]
    
    def post(self, request: Request):
        """Handle login form submission callback."""
        form = request.data
        username = form.get("username")
        password = form.get("password")
        state = form.get("state")

        if not username or not password or not state:
            return Response(
                data="Missing username, password, or state parameter",
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Ensure we have strings, not UploadFile objects
        if not isinstance(username, str) or not isinstance(password, str) or not isinstance(state, str):
            return Response(
                data="Invalid parameter types",
                status=status.HTTP_400_BAD_REQUEST,
            )

        redirect_uri = handle_simple_callback(username, password, state)
        # return RedirectResponse(url=redirect_uri, status_code=302)
        return Response(
            headers={
                "Location": redirect_uri,
            },
            status=status.HTTP_302_FOUND
        )


