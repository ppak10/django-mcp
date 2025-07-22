import anyio
import functools
import typing

from asgiref.sync import async_to_sync
from anyio.abc import TaskGroup, TaskStatus
from channels.generic.http import AsyncHttpConsumer
from channels.layers import get_channel_layer
from collections.abc import Awaitable, MutableMapping

from django_mcp.event_store import InMemoryEventStore
from django_mcp.lowlevel.proxy import Proxy

from mcp.server.streamable_http import (
    EventStore,
    StreamableHTTPServerTransport,
)

from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

from mcp.server.transport_security import TransportSecuritySettings

from typing_extensions import override

from uuid import uuid4

Message = MutableMapping[str, typing.Any]
Scope = MutableMapping[str, typing.Any]

Receive = typing.Callable[[], Awaitable[Message]]
Send = typing.Callable[[Message], Awaitable[None]]

event_store = InMemoryEventStore()

class StreamableHTTPConsumer(AsyncHttpConsumer):
    """
    Adapted from mcp.server.streamable_http_manager
    
    Manages StreamableHTTP sessions with optional resumability via event store.
    """

    @override
    def __init__(self, *args, **kwargs):
        self.handle_streamable_http = kwargs["handle_streamable_http"]
        super().__init__(*args, **kwargs)

    @override
    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        await self.handle_streamable_http(scope, receive, send)


