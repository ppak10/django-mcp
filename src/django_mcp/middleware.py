from contextlib import AsyncExitStack

from django_mcp.types import ASGIApp, LifespanHook, Receive, Scope, Send

from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

class LifespanMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        on_startup: LifespanHook,
        on_shutdown: LifespanHook
    ):
        self.app: ASGIApp = app
        self.on_startup: LifespanHook = on_startup
        self.on_shutdown: LifespanHook = on_shutdown

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await self.on_startup()
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await self.on_shutdown()
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        else:
            await self.app(scope, receive, send)

def create_session_manager_lifespan(session_manager: StreamableHTTPSessionManager):
    stack = AsyncExitStack()

    async def on_startup():
        print("Starting session manager...")
        await stack.enter_async_context(session_manager.run())

    async def on_shutdown():
        print("Shutting down session manager...")
        await stack.aclose()

    return on_startup, on_shutdown

