# urls.py
from django.urls import path
from . import views
from django_mcp.views.auth import OAuthAuthorizationServer, RegisterView 

# Base URL patterns
urlpatterns = [
    # path('.well-known/oauth-protected-resource/', OAuthProtectedResource.as_view(), name='oauth-protected-resource'),
    path(
        '.well-known/oauth-authorization-server/',
        OAuthAuthorizationServer.as_view(),
    ),
    path('register', RegisterView.as_view()),
]

def create_oauth_urlpatterns(
    provider,
    issuer_url,
    service_documentation_url=None,
    client_registration_options=None,
    revocation_options=None,
):
    """Create OAuth URL patterns"""
    
    # Create view instances
    oauth_views = views.create_oauth_views(
        provider,
        issuer_url,
        service_documentation_url,
        client_registration_options,
        revocation_options,
    )
    
    # Base URL patterns
    urlpatterns = [
        path('.well-known/oauth-authorization-server/', 
             oauth_views['metadata'].as_view(), 
             name='oauth-metadata'),
        path('authorize/', 
             oauth_views['authorization'].as_view(), 
             name='oauth-authorize'),
        path('token/', 
             oauth_views['token'].as_view(), 
             name='oauth-token'),
    ]
    
    # Add optional endpoints
    if 'registration' in oauth_views:
        urlpatterns.append(
            path('register/', 
                 oauth_views['registration'].as_view(), 
                 name='oauth-register')
        )
    
    if 'revocation' in oauth_views:
        urlpatterns.append(
            path('revoke/', 
                 oauth_views['revocation'].as_view(), 
                 name='oauth-revoke')
        )
    
    return urlpatterns


# Alternative approach: Class-based URL configuration
class OAuthURLConfig:
    """Class-based OAuth URL configuration"""
    
    def __init__(self, provider, issuer_url, service_documentation_url=None,
                 client_registration_options=None, revocation_options=None):
        self.provider = provider
        self.issuer_url = issuer_url
        self.service_documentation_url = service_documentation_url
        self.client_registration_options = client_registration_options or ClientRegistrationOptions()
        self.revocation_options = revocation_options or RevocationOptions()
        
    @property
    def urlpatterns(self):
        """Get URL patterns for this OAuth configuration"""
        return create_oauth_urlpatterns(
            self.provider,
            self.issuer_url,
            self.service_documentation_url,
            self.client_registration_options,
            self.revocation_options,
        )


# Example usage in your main urls.py:
"""
# In your main urls.py or app urls.py:

from django.urls import path, include
from .oauth_config import OAuthURLConfig
from your_app.oauth_provider import YourOAuthProvider

# Create your OAuth configuration
oauth_config = OAuthURLConfig(
    provider=YourOAuthProvider(),
    issuer_url="https://your-domain.com",
    service_documentation_url="https://your-domain.com/docs",
    client_registration_options=ClientRegistrationOptions(enabled=True),
    revocation_options=RevocationOptions(enabled=True),
)

# Include OAuth URLs
urlpatterns = [
    path('oauth/', include(oauth_config.urlpatterns)),
    # Your other URL patterns...
]
"""
