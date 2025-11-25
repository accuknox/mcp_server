#!/usr/bin/env python3
"""
Test script for deployed models functionality in MCP server
"""

import asyncio

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def test_deployed_models():
    server_params = StdioServerParameters(
        command="/home/satyam/AI_observability_ebpf/langchain_gemini_env/bin/python3",
        args=["/home/satyam/MCP_server_PoC/MCP_server.py"],
        env=None,
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            print("\n" + "=" * 70)
            print("Testing 'Show me deployed models'")
            print("=" * 70 + "\n")

            # Query for deployed models
            result = await session.call_tool(
                "search_assets",
                arguments={"deployed": True},
            )
            print(result.content[0].text)


if __name__ == "__main__":
    try:
        asyncio.run(test_deployed_models())
    except KeyboardInterrupt:
        print("\n\nInterrupted\n")
    except Exception as e:
        print(f"\nError: {e}\n")
