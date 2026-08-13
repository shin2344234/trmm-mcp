"""End-to-end MCP protocol check: launch run.sh and talk to it as a real client."""

import asyncio
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "readonly"
    params = StdioServerParameters(
        command=os.path.join(os.path.dirname(os.path.abspath(__file__)), "run.sh"), args=[mode], env=None
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            print(f"connected to: {init.server_info.name} v{init.server_info.version}")

            tools = await session.list_tools()
            names = sorted(t.name for t in tools.tools)
            print(f"tools ({len(names)}): {', '.join(names)}")

            result = await session.call_tool("trmm_fleet_overview", {})
            text = result.content[0].text if result.content else ""
            print(f"fleet_overview -> {text[:220]}")

            result = await session.call_tool(
                "trmm_list_agents", {"fields": ["hostname", "status", "plat"]}
            )
            print(f"list_agents -> {result.content[0].text[:220]}")

            if mode == "readonly":
                assert not any(n.startswith("trmm_run_") for n in names), \
                    "execution tool leaked into read-only mode"
                print("verified: no execution tools exposed over the wire")
            print("\nPROTOCOL OK")


asyncio.run(main())
