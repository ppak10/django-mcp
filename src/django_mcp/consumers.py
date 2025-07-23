import typing

from channels.generic.http import AsyncHttpConsumer

from typing_extensions import override
from django_mcp.types import Receive, Scope, Send, StreamableHTTPHandler

class StreamableHTTPConsumer(AsyncHttpConsumer):
    """
    Adapted for mcp.server.streamable_http_manager
    """

    @override
    def __init__(self, *args: list[typing.Any], **kwargs: dict[str, typing.Any]):
        self.handler: StreamableHTTPHandler = kwargs["handler"]
        super().__init__(*args, **kwargs)

    @override
    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        await self.handler(scope, receive, send)

