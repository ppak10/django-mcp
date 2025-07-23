import django
import os

from channels.routing import ProtocolTypeRouter, URLRouter
from django.urls import re_path
from django.core.asgi import get_asgi_application

from django_mcp.event_store import InMemoryEventStore
from django_mcp.middleware import LifespanMiddleware, create_session_manager_lifespan
from django_mcp.routes import create_http_urlpatterns 
from django_mcp.types import Receive, Send, Scope

from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

from .mcp_app import app

json_response = False

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_5.settings')
django.setup()

# Create event store for resumability
# The InMemoryEventStore enables resumability support for StreamableHTTP transport.
# It stores SSE events with unique IDs, allowing clients to:
#   1. Receive event IDs for each SSE message
#   2. Resume streams by sending Last-Event-ID in GET requests
#   3. Replay missed events after reconnection
# Note: This in-memory implementation is for demonstration ONLY.
# For production, use a persistent storage solution.
event_store = InMemoryEventStore()

# Create the session manager with our app and event store
session_manager = StreamableHTTPSessionManager(
    app=app,
    event_store=event_store,  # Enable resumability
    json_response=json_response,
)
# ASGI handler for streamable HTTP connections
async def handle_streamable_http(scope: Scope, receive: Receive, send: Send) -> None:
    await session_manager.handle_request(scope, receive, send)

http_urlpatterns = create_http_urlpatterns(handle_streamable_http)

on_startup, on_shutdown = create_session_manager_lifespan(session_manager)

django_asgi_app = get_asgi_application()

application = ProtocolTypeRouter({
    "http": URLRouter(
        http_urlpatterns + [
            # fallback: catch-all route to Django views ASGI app
            re_path(r".*", django_asgi_app),
        ]
    ),
})

application = LifespanMiddleware(application, on_startup, on_shutdown)

