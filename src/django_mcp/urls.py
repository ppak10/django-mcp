from django.urls import path

from django_mcp.views.auth.oauth_authorization_server import OAuthAuthorizationServerView
from django_mcp.views.auth.oauth_protected_resource import OAuthProtectedResourceView
from django_mcp.views.auth.register import RegisterView 
from django_mcp.views.auth.authorize import AuthorizeView 
from django_mcp.views.auth.login import login_page
from django_mcp.views.auth.login_callback import LoginCallbackView 
from django_mcp.views.auth.token import TokenView
from django_mcp.views.proxy import ProxyView

# Base URL patterns
urlpatterns = [
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
    path('mcp', ProxyView.as_view()),
]

