import typing
from collections.abc import Awaitable, MutableMapping

# Exactly the same as those in starlette.types but redefined here for clarity.
Message = MutableMapping[str, typing.Any]
Scope = MutableMapping[str, typing.Any]
Receive = typing.Callable[[], Awaitable[Message]]
Send = typing.Callable[[Message], Awaitable[None]]
ASGIApp = typing.Callable[[Scope, Receive, Send], Awaitable[None]]

# For passing streamable http to consumer.
StreamableHTTPHandler = typing.Callable[[Scope, Receive, Send], Awaitable[None]]

# Lifespan hook
LifespanHook = typing.Callable[[], Awaitable[None]]

