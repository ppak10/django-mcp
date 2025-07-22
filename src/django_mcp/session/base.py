"""
Adapted from mcp/server/session.py from mcp python-sdk package.

Mainly intended for mocking session for mcp client when proxying requests to
user hosted MCP servers.
"""

import anyio
import mcp.types as types
import httpx

from collections.abc import Callable
from datetime import timedelta
from enum import Enum
from mcp.server.models import InitializationOptions
from mcp.shared.message import MessageMetadata, ServerMessageMetadata, SessionMessage
from mcp.shared.exceptions import McpError
from mcp.shared.session import RequestResponder 
from pydantic import BaseModel
from typing import Any, Protocol, TypeVar
from types import TracebackType

ReceiveResultT = TypeVar("ReceiveResultT", bound=BaseModel)

from mcp.types import (
    CONNECTION_CLOSED,
    INVALID_PARAMS,
    CancelledNotification,
    ClientNotification,
    ClientRequest,
    ClientResult,
    ErrorData,
    JSONRPCError,
    JSONRPCMessage,
    JSONRPCNotification,
    JSONRPCRequest,
    JSONRPCResponse,
    ProgressNotification,
    RequestParams,
    ServerNotification,
    ServerRequest,
    ServerResult,
)

SendRequestT = TypeVar("SendRequestT", ClientRequest, ServerRequest)
SendResultT = TypeVar("SendResultT", ClientResult, ServerResult)
SendNotificationT = TypeVar("SendNotificationT", ClientNotification, ServerNotification)
ReceiveRequestT = TypeVar("ReceiveRequestT", ClientRequest, ServerRequest)
ReceiveResultT = TypeVar("ReceiveResultT", bound=BaseModel)
ReceiveNotificationT = TypeVar("ReceiveNotificationT", ClientNotification, ServerNotification)

RequestId = str | int

class ProgressFnT(Protocol):
    """Protocol for progress notification callbacks."""

    async def __call__(self, progress: float, total: float | None, message: str | None) -> None: ...


class BaseSession():
    """
    Implements an MCP "session" on top of read/write streams, including features
    like request/response linking, notifications, and progress.

    This class is an async context manager that automatically starts processing
    messages when entered.
    """

    # _response_streams: dict[RequestId, MemoryObjectSendStream[JSONRPCResponse | JSONRPCError]]
    _response_streams: dict[RequestId, JSONRPCResponse | JSONRPCError]
    _request_id: int
    _in_flight: dict[RequestId, RequestResponder[ClientRequest, ServerResult]]
    _progress_callbacks: dict[RequestId, ProgressFnT]

    def __init__(
        self,
        read_stream, # Read stream from worker client
        write_stream, # Write stream to worker client
        # If none, reqding will never time out
        read_timeout_seconds: timedelta | None = None,
    ) -> None:
        self._read_stream = read_stream
        self._write_stream = write_stream
        self._response_streams = {}
        self._request_id = 0
        self._receive_request_type = types.ClientRequest 
        self._receive_notification_type = types.ClientNotification
        self._session_read_timeout_seconds = read_timeout_seconds
        self._in_flight = {}
        self._progress_callbacks = {}

    async def send_request(
        self,
        request: types.ServerRequest,
        result_type: type[ReceiveResultT],
        request_read_timeout_seconds: timedelta | None = None,
        metadata: MessageMetadata = None,
        progress_callback: ProgressFnT | None = None,
    ) -> ReceiveResultT:
        """
        Sends a request and wait for a response. Raises an McpError if the
        response contains an error. If a request read timeout is provided, it
        will take precedence over the session read timeout.

        Do not use this method to emit notifications! Use send_notification()
        instead.
        """
        request_id = self._request_id
        self._request_id = request_id + 1

        # response_stream, response_stream_reader = anyio.create_memory_object_stream[JSONRPCResponse | JSONRPCError](1)
        # self._response_streams[request_id] = response_stream

        # Set up progress token if progress callback is provided
        request_data = request.model_dump(by_alias=True, mode="json", exclude_none=True)
        if progress_callback is not None:
            # Use request_id as progress token
            if "params" not in request_data:
                request_data["params"] = {}
            if "_meta" not in request_data["params"]:
                request_data["params"]["_meta"] = {}
            request_data["params"]["_meta"]["progressToken"] = request_id
            # Store the callback for this request
            self._progress_callbacks[request_id] = progress_callback

        jsonrpc_request = types.JSONRPCRequest(
            jsonrpc="2.0",
            id=request_id,
            **request_data,
        )

        await self._write_stream.send(SessionMessage(message=types.JSONRPCMessage(jsonrpc_request), metadata=metadata))

        # request read timeout takes precedence over session read timeout
        timeout = None
        if request_read_timeout_seconds is not None:
            timeout = request_read_timeout_seconds.total_seconds()
        elif self._session_read_timeout_seconds is not None:
            timeout = self._session_read_timeout_seconds.total_seconds()

        try:
            with anyio.fail_after(timeout):
                response_or_error = await response_stream_reader.receive()
        except TimeoutError:
            raise McpError(
                types.ErrorData(
                    code=httpx.codes.REQUEST_TIMEOUT,
                    message=(
                        f"Timed out while waiting for response to "
                        f"{request.__class__.__name__}. Waited "
                        f"{timeout} seconds."
                    ),
                )
            )

        if isinstance(response_or_error, types.JSONRPCError):
            raise McpError(response_or_error.error)
        else:
            return result_type.model_validate(response_or_error.result)

        # finally:
        #     self._response_streams.pop(request_id, None)
        #     self._progress_callbacks.pop(request_id, None)
        #     await response_stream.aclose()
        #     await response_stream_reader.aclose()

