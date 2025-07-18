# These routes are accessible via worker subdomain only.
# They proxy requests to the worker instance hosted on the subdomain.
from django.urls import path

from rest_framework.urlpatterns import format_suffix_patterns

from proxy.views import MCPView 

urlpatterns = [
    # General CRUD Views.
    path("mcp/", MCPView.as_view()),
]

urlpatterns = format_suffix_patterns(urlpatterns)

