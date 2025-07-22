from django.urls import path
from .consumers import StreamableHTTPConsumer

def create_http_urlpatterns(handle_streamable_http):
    http_urlpatterns = [
        path(
            "mcp",
            StreamableHTTPConsumer.as_asgi(
                handle_streamable_http=handle_streamable_http
            )
        ),
    ]
    return http_urlpatterns

