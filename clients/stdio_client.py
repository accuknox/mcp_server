#!/usr/bin/env python3
"""
stdio Test Client
Tests the stdio MCP server
"""

import asyncio

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def interactive():
    server_params = StdioServerParameters(
        command="python3",
        args=["MCP_server.py"],
        env=None,
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            print("\n" + "=" * 70)
            print("AccuKnox stdio Client")
            print("=" * 70)

            while True:
                print("\nOptions:")
                print("  1 - Count assets")
                print("  2 - List 5 assets")
                print("  3 - Search by category")
                print("  4 - Get vulnerabilities")
                print("  exit - Quit")

                choice = input("\nSelect: ").strip()

                if choice in ["exit", "quit", "q"]:
                    print("\n👋 Goodbye!\n")
                    break

                print()

                try:
                    if choice == "1":
                        result = await session.call_tool(
                            "search_assets",
                            arguments={"return_type": "count"},
                        )
                        print(result.content[0].text)

                    elif choice == "2":
                        result = await session.call_tool(
                            "search_assets",
                            arguments={"limit": 5},
                        )
                        print(result.content[0].text)

                    elif choice == "3":
                        category = input("Category: ").strip()
                        result = await session.call_tool(
                            "search_assets",
                            arguments={"type_category": category, "limit": 3},
                        )
                        print(result.content[0].text)

                    elif choice == "4":
                        result = await session.call_tool(
                            "get_model_vulnerabilities",
                            arguments={},
                        )
                        print(result.content[0].text)

                    else:
                        print("Invalid option")

                except Exception as e:
                    print(f"Error: {e}")

                input("\nPress Enter...")


if __name__ == "__main__":
    try:
        asyncio.run(interactive())
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!\n")
