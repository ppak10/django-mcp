from django.urls import path
from django.urls.resolvers import RoutePattern

from django_mcp.types import StreamableHTTPHandler
from .consumers import StreamableHTTPConsumer

def create_http_urlpatterns(handler: StreamableHTTPHandler) -> list[RoutePattern]:
    return [path("mcp", StreamableHTTPConsumer.as_asgi(handler=handler))]

