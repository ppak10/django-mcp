import os
import django
from channels.routing import ProtocolTypeRouter, URLRouter
from django.urls import re_path
from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_5.settings')
django.setup()

from django_mcp.routes import http_urlpatterns 

django_asgi_app = get_asgi_application()

application = ProtocolTypeRouter({
    "http": URLRouter(
        http_urlpatterns + [
            # fallback: catch-all route to Django views ASGI app
            re_path(r".*", django_asgi_app),
        ]
    ),
})

