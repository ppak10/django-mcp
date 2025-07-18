from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.prompts import base
from mcp.types import Completion, ResourceTemplateReference, PromptReference

# Create a stateless MCP server
mcp = FastMCP(name="SimpleServer", stateless_http=True)

# Completion
@mcp.completion()
async def handle_completion(ref, argument, context):
    if isinstance(ref, ResourceTemplateReference):
        return Completion(values=["user1", "user2"])
    if isinstance(ref, PromptReference):
        return Completion(values=["prompt1", "prompt2"])
    return None

# Prompts
@mcp.prompt()
def review_code(code: str) -> str:
    return f"Please review this code:\n\n{code}"

@mcp.prompt()
def debug_error(error: str) -> list[base.Message]:
    return [
        base.UserMessage("I'm seeing this error:"),
        base.UserMessage(error),
        base.AssistantMessage("I'll help debug that. What have you tried so far?"),
    ]

# Resources 
@mcp.resource("info://server")
def server_info() -> str:
    print("called Simple MCP Server v1.0")
    return "Simple MCP Server v1.0"

@mcp.resource("config://app")
def get_config() -> str:
    return "App configuration here"

# Resource Templates
@mcp.resource("users://{user_id}/profile")
def get_user_profile(user_id: str) -> str:
    return f"Profile data for user {user_id}"

# Tools
@mcp.tool(description="Echo a message back")
def echo(message: str) -> str:
    print(f"Echo: {message}")
    return f"Echo: {message}"

@mcp.tool(description="Add two numbers")
def add(a: int, b: int) -> int:
    print(a + b)
    return a + b

def create_app():
    """Used when importing as a module."""
    return mcp

def main():
    """Used when running as a script."""
    print("Starting MCP server...")
    mcp.run(transport="streamable-http")

if __name__ == "__main__":
    main()

