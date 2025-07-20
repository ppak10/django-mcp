import secrets
import time

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from typing_extensions import override

# First, fix the type arguments - specify the three generic types
class AuthProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):

    def __init__(self):
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.state_mapping: dict[str, dict[str, str | None]] = {}
        # self.auth_callback_url: str = "http://127.0.0.1:8002/login/callback"
        self.auth_callback_url: str = "http://127.0.0.1:8002/login"
        self.auth_codes: dict[str, AuthorizationCode] = {}
        self.tokens: dict[str, AccessToken] = {}
        # Store authenticated user information
        self.user_data: dict[str, dict[str, str | float]] = {}

    @override
    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """Get OAuth client information."""
        # TODO: Probably should export this to Redis
        return self.clients.get(client_id)

    
    @override
    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        """Register a new OAuth client."""
        self.clients[client_info.client_id] = client_info
    
    @override
    async def authorize(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams
    ) -> str:
        """Generate an authorization URL for simple login flow."""
        # This typically involves redirecting to a third-party OAuth provider
        # Example: return f"https://oauth-provider.com/authorize?client_id={client.client_id}&..."
        state = params.state or secrets.token_hex(16)
        self.state_mapping[state] = {
            "redirect_uri": str(params.redirect_uri),
            "code_challenge": params.code_challenge,
            "redirect_uri_provided_explicitly": str(params.redirect_uri_provided_explicitly),
            "client_id": client.client_id,
            "resource": params.resource,  # RFC 8707
        }

        # Build simple login URL that points to login page
        auth_url = f"{self.auth_callback_url}?state={state}&client_id={client.client_id}"

        return auth_url

    @override
    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        """Load an authorization code."""
        return self.auth_codes.get(authorization_code)
    
    @override
    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        """Exchange authorization code for tokens."""
        if authorization_code.code not in self.auth_codes:
            raise ValueError("Invalid authorization code")

        # Generate MCP access token
        mcp_token = f"mcp_{secrets.token_hex(32)}"

        # Store MCP token
        self.tokens[mcp_token] = AccessToken(
            token=mcp_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=int(time.time()) + 3600,
            resource=authorization_code.resource,  # RFC 8707
        )

        # Store user data mapping for this token
        self.user_data[mcp_token] = {
            "username": "demo_user",
            "user_id": f"user_{secrets.token_hex(8)}",
            "authenticated_at": time.time(),
        }

        del self.auth_codes[authorization_code.code]

        return OAuthToken(
            access_token=mcp_token,
            token_type="Bearer",
            expires_in=3600,
            scope=" ".join(authorization_code.scopes),
        )
   
    @override
    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        """
        Loads a RefreshToken by its token string.
        
        Args:
            client: The client that is requesting to load the refresh token.
            refresh_token: The refresh token string to load.
            
        Returns:
            The RefreshToken object if found, or None if not found.
        """
        # TODO: Implement your refresh token lookup logic here
        # Example: return await self.refresh_token_store.get(refresh_token)
        raise NotImplementedError("Implement refresh token lookup logic")
   
    @override
    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """
        Exchanges a refresh token for an access token and refresh token.
        
        Args:
            client: The client exchanging the refresh token.
            refresh_token: The refresh token to exchange.
            scopes: Optional scopes to request with the new access token.
            
        Returns:
            The OAuth token, containing access and refresh tokens.
            
        Raises:
            TokenError: If the request is invalid
        """
        # TODO: Implement your refresh token exchange logic here
        # Should rotate both access and refresh tokens
        raise NotImplementedError("Implement refresh token exchange logic")
   
    @override
    async def load_access_token(self, token: str) -> AccessToken | None:
        """
        Loads an access token by its token.
        
        Args:
            token: The access token to verify.
            
        Returns:
            The AccessToken, or None if the token is invalid.
        """
        # TODO: Implement your access token lookup logic here
        # Example: return await self.access_token_store.get(token)
        raise NotImplementedError("Implement access token lookup logic")

    @override 
    async def revoke_token(
        self,
        token: AccessToken | RefreshToken | str,
    ) -> None:
        """Revoke a token."""
        if token in self.tokens:
            if isinstance(token, str):
                del self.tokens[token]

auth_provider = AuthProvider()

