from django.urls import path
from .consumers import StreamableHTTPConsumer

http_urlpatterns = [
    path("mcp", StreamableHTTPConsumer.as_asgi()),
]

