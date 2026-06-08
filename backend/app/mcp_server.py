"""Optional standalone MCP server (stdio) exposing SentinelOps tools to AI agents
such as Claude Desktop. Requires `pip install mcp`. The data is read via the
running REST API (set SIEM_API_URL, default http://localhost:8000).

Run:  python -m app.mcp_server
Claude Desktop config (claude_desktop_config.json):
  { "mcpServers": { "sentinelops": { "command": "python", "args": ["-m", "app.mcp_server"] } } }
"""
import os
import asyncio
import json
import httpx

API = os.getenv("SIEM_API_URL", "http://localhost:8000")


async def _main():
    try:
        from mcp.server import Server
        from mcp.server.stdio import stdio_server
        from mcp.types import Tool, TextContent
    except ImportError:
        raise SystemExit("Install the MCP SDK first:  pip install mcp")

    server = Server("sentinelops-siem")

    @server.list_tools()
    async def list_tools():
        async with httpx.AsyncClient() as c:
            tools = (await c.get(f"{API}/mcp/tools")).json()["tools"]
        return [Tool(name=t["name"], description=t["description"], inputSchema=t["inputSchema"]) for t in tools]

    @server.call_tool()
    async def call_tool(name, arguments):
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.post(f"{API}/mcp/call", json={"tool": name, "arguments": arguments})
            r.raise_for_status()
            return [TextContent(type="text", text=json.dumps(r.json(), indent=2))]

    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(_main())
