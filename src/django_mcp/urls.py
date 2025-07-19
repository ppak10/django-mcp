# urls.py
from django.urls import path

from django_mcp.views.auth.oauth_authorization_server import OAuthAuthorizationServerView
from django_mcp.views.auth.oauth_protected_resource import OAuthProtectedResourceView
from django_mcp.views.auth.register import RegisterView 
from django_mcp.views.auth.authorize import AuthorizeView 
from django_mcp.views.auth.login import login_page
from django_mcp.views.auth.login_callback import LoginCallbackView 
from django_mcp.views.auth.token import TokenView
# from django_mcp.views.auth.register_django import register_view

# Base URL patterns
urlpatterns = [
    # path('.well-known/oauth-protected-resource/', OAuthProtectedResource.as_view(), name='oauth-protected-resource'),
    path(
        '.well-known/oauth-authorization-server/',
        OAuthAuthorizationServerView.as_view(),
    ),
    path(
        '.well-known/oauth-protected-resource/',
        OAuthProtectedResourceView.as_view(),
    ),
    path('register', RegisterView.as_view()),
    # path('register', register_view),
    path('authorize', AuthorizeView.as_view()),
    path('login', login_page),
    path('login/callback', LoginCallbackView.as_view()),
    path('token', TokenView.as_view()),
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
        path('authorize/', 
             oauth_views['authorization'].as_view(), 
             name='oauth-authorize'),
        path('token/', 
             oauth_views['token'].as_view(), 
             name='oauth-token'),
    ]
    
    if 'revocation' in oauth_views:
        urlpatterns.append(
            path('revoke/', 
                 oauth_views['revocation'].as_view(), 
                 name='oauth-revoke')
        )
    
    return urlpatterns

