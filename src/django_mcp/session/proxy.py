"""
Adapted from mcp/server/session.py from mcp python-sdk package.

Mainly intended for mocking session for mcp client when proxying requests to
user hosted MCP servers.
"""

import mcp.types as types
import httpx

from datetime import timedelta
from enum import Enum
from mcp.server.models import InitializationOptions
from mcp.shared.message import MessageMetadata, ServerMessageMetadata, SessionMessage
from mcp.shared.exceptions import McpError
from pydantic import BaseModel
from typing import Protocol, TypeVar

from .base_session import BaseSession

ReceiveResultT = TypeVar("ReceiveResultT", bound=BaseModel)

class InitializationState(Enum):
    NotInitialized = 1
    Initializing = 2
    Initialized = 3

class ServerSession(BaseSession):
    _initialized: InitializationState = InitializationState.NotInitialized
    _client_params: types.InitializeRequestParams | None = None

    def __init__(
        self,
        read_stream, # Read stream from worker client
        write_stream, # Write stream to worker client
        init_options: InitializationOptions,
        stateless: bool = False,
        # If none, reqding will never time out
        read_timeout_seconds: timedelta | None = None,
    ) -> None:
        super().__init__(read_stream, write_stream)
        self._initialization_state = (
            InitializationState.Initialized if stateless else InitializationState.NotInitialized
        )

        self._init_options = init_options

    async def send_ping(self) -> types.EmptyResult:
        """Send a ping request."""
        return await self.send_request(
            types.ServerRequest(
                types.PingRequest(
                    method="ping",
                )
            ),
            types.EmptyResult
        )

