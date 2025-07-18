import asyncio
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client

async def main():
    # Connect to the MCP server via streamable HTTP
    async with streamablehttp_client("http://127.0.0.1:8002/mcp/") as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            # Initialize session
            result = await session.initialize()
            print(f"✅ Session initialized: {result.capabilities}")

            # List available tools
            tools = await session.list_tools()
            print("\n🛠️  Available Tools:")
            for tool in tools.tools:
                print(f"- {tool.name}: {tool.description}")

            # Call `echo` tool
            echo_result = await session.call_tool(
                "echo", arguments={"message": "Hello MCP!"}
            )
            print(f"\n📣 Echo result: {echo_result.content}")

            # Call `add` tool
            add_result = await session.call_tool(
                "add", arguments={"a": 2, "b": 3}
            )
            print(f"\n➕ Add result: {add_result.content}")

            # Read `info://server` resource
            content, mime_type = await session.read_resource("info://server")
            print(f"\nℹ️ Server Info [{mime_type}]: {content}")

if __name__ == "__main__":
    asyncio.run(main())

