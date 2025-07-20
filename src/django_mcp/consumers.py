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

from mcp.server.transport_security import TransportSecuritySettings

from typing_extensions import override

from uuid import uuid4

Message = MutableMapping[str, typing.Any]
Scope = MutableMapping[str, typing.Any]

Receive = typing.Callable[[], Awaitable[Message]]
Send = typing.Callable[[Message], Awaitable[None]]

event_store = InMemoryEventStore()

app = Proxy("test_proxy")

class StreamableHTTPConsumer(AsyncHttpConsumer):
    """
    Adapted from mcp.server.streamable_http_manager
    
    Manages StreamableHTTP sessions with optional resumability via event store.
    """

    @override
    def __init__(self, *args, **kwargs):
        self.app: Proxy[typing.Any, typing.Any] = app
        self.event_store: EventStore | None = event_store
        self.json_response: bool = False 
        self.security_settings: TransportSecuritySettings | None = None 
        self.stateless: bool = False

        # Session tracking (only used if not stateless)
        self._session_creation_lock: anyio.Lock = anyio.Lock()
        self._server_instances: dict[str, StreamableHTTPServerTransport] = {}

        self._task_group: TaskGroup | None = None

        self.scope: Scope
        self.base_send: Send
        self.receive: Receive

        super().__init__(*args, **kwargs)

    @override
    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        self.scope = scope
        self.receive = receive
        self.base_send = send

        async with anyio.create_task_group() as tg:
            self._task_group = tg
            print("StreamableHTTP session manager started")

            if self.stateless:
                http_transport = StreamableHTTPServerTransport(
                    mcp_session_id=None,
                    is_json_response_enabled=self.json_response,
                    event_store=None,
                    security_settings=self.security_settings,
                )
            else:
                # Stateful transport setup (simplified here)
                http_transport = StreamableHTTPServerTransport(
                    mcp_session_id="some_session_id",
                    is_json_response_enabled=self.json_response,
                    event_store=self.event_store,
                    security_settings=self.security_settings,
                )
            
            # Start the app runner in a task
            async def run_transport(*, task_status=anyio.TASK_STATUS_IGNORED):
                async with http_transport.connect() as streams:
                    read_stream, write_stream = streams
                    task_status.started()
                    await self.app.run(
                        read_stream,
                        write_stream,
                        self.app.create_initialization_options(),
                        stateless=self.stateless,
                    )

            await tg.start(run_transport)

            # **Directly call your transport's handle_request which reads receive itself**
            await http_transport.handle_request(scope, receive, send)

            print("StreamableHTTP session manager shutting down")

        self._task_group = None

    # @override
    # async def __call__(
    #     self,
    #     scope: Scope,
    #     receive: Receive,
    #     send: Send,
    # ):
    #     self.receive = receive
    #
    #     async with anyio.create_task_group() as tg:
    #         # Store the task group for later use
    #         self._task_group = tg
    #         print("StreamableHTTP session manager started")
    #         try:
    #             # yield  # Let the application run
    #             await super().__call__(scope, receive, send)
    #
    #         finally:
    #             print("StreamableHTTP session manager shutting down")
    #             # Cancel task group to stop all spawned tasks
    #             tg.cancel_scope.cancel()
    #             self._task_group = None
    #             # Clear any remaining server instances
    #             self._server_instances.clear()
    #
    #     # await super().__call__(scope, receive, send)
    #
    # async def handle(self, body: bytes):
    #     print(f"body: {body}")
    #     print(f"self.base_send: {self.base_send}")
    #     print(f"self.receive: {self.receive}")
    #     print(f"self.scope: {self.scope}")
    #
    #     # Dispatch to the appropriate handler
    #     if self.stateless:
    #         await self._handle_stateless_request()
    #     else:
    #         await self._handle_stateful_request()

    async def _handle_stateless_request(self) -> None:
        """
        Process request in stateless mode - creating a new transport for each request.

        Args:
            scope: ASGI scope
            receive: ASGI receive function
            send: ASGI send function
        """
        # No session ID needed in stateless mode
        http_transport = StreamableHTTPServerTransport(
            mcp_session_id=None,  # No session tracking in stateless mode
            is_json_response_enabled=self.json_response,
            event_store=None,  # No event store in stateless mode
            security_settings=self.security_settings,
        )

        # Start server in a new task
        async def run_stateless_server(*, task_status: TaskStatus[None] = anyio.TASK_STATUS_IGNORED):
            async with http_transport.connect() as streams:
                read_stream, write_stream = streams
                task_status.started()
                try:
                    await self.app.run(
                        read_stream,
                        write_stream,
                        self.app.create_initialization_options(),
                        stateless=True,
                    )
                except Exception:
                    print("Stateless session crashed")

        # Assert task group is not None for type checking
        assert self._task_group is not None
        # Start the server task
        await self._task_group.start(run_stateless_server)

        # Handle the HTTP request and return the response
        await http_transport.handle_request(self.scope, self.receive, self.base_send)

    async def _handle_stateful_request(self) -> None:
        """
        Process request in stateful mode - maintaining session state between requests.

        Args:
            scope: ASGI scope
            receive: ASGI receive function
            send: ASGI send function
        """
        # request = Request(self.scope, self.receive)
        # request_mcp_session_id = request.headers.get(MCP_SESSION_ID_HEADER)
        request_mcp_session_id = None

        # Existing session case
        if request_mcp_session_id is not None and request_mcp_session_id in self._server_instances:
            transport = self._server_instances[request_mcp_session_id]
            print("Session already exists, handling request directly")
            await transport.handle_request(self.scope, self.receive, self.base_send)
            return

        if request_mcp_session_id is None:
            # New session case
            print("Creating new transport")
            async with self._session_creation_lock:
                new_session_id = uuid4().hex
                http_transport = StreamableHTTPServerTransport(
                    mcp_session_id=new_session_id,
                    is_json_response_enabled=self.json_response,
                    event_store=self.event_store,  # May be None (no resumability)
                    security_settings=self.security_settings,
                )

                assert http_transport.mcp_session_id is not None
                self._server_instances[http_transport.mcp_session_id] = http_transport
                print(f"Created new transport with session ID: {new_session_id}")

                # Define the server runner
                async def run_server(*, task_status: TaskStatus[None] = anyio.TASK_STATUS_IGNORED) -> None:
                    async with http_transport.connect() as streams:
                        read_stream, write_stream = streams
                        task_status.started()
                        try:
                            await self.app.run(
                                read_stream,
                                write_stream,
                                self.app.create_initialization_options(),
                                stateless=False,  # Stateful mode
                            )
                        except Exception as e:
                            print(
                                f"Session {http_transport.mcp_session_id} crashed: {e}",
                                # exc_info=True,
                            )
                        finally:
                            # Only remove from instances if not terminated
                            if (
                                http_transport.mcp_session_id
                                and http_transport.mcp_session_id in self._server_instances
                                and not http_transport.is_terminated
                            ):
                                print(
                                    f"Cleaning up crashed session {http_transport.mcp_session_id} from active instances."
                                )
                                del self._server_instances[http_transport.mcp_session_id]

                # Assert task group is not None for type checking
                assert self._task_group is not None
                # Start the server task
                await self._task_group.start(run_server)

                # Handle the HTTP request and return the response
                await http_transport.handle_request(self.scope, self.receive, self.base_send)
        else:
            # If session ID invalid, send 400 Bad Request response:
            await self.send_headers(
                status=400,
                headers=[
                    (b"content-type", b"text/plain"),
                ],
            )
            await self.send_body(b"Bad Request: No valid session ID provided", more_body=False)
            # response = Response(
            #     "Bad Request: No valid session ID provided",
            #     status_code=HTTPStatus.BAD_REQUEST,
            # )
            # await response(self.scope, self.receive, self.base_send)
