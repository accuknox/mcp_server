#!/usr/bin/env python3
"""
HTTP Test Client
Tests the HTTP MCP server
"""

import asyncio
import httpx

SERVER_URL = "http://localhost:8000"


async def call_tool(tool_name: str, arguments: dict = None):
    if arguments is None:
        arguments = {}
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{SERVER_URL}/call_tool",
            json={"tool": tool_name, "arguments": arguments},
            timeout=30.0
        )
        response.raise_for_status()
        return response.json()


async def interactive():
    print("\n" + "=" * 70)
    print("AccuKnox HTTP Client")
    print("=" * 70)
    print(f"Server: {SERVER_URL}\n")
    
    while True:
        print("\nOptions:")
        print("  1 - Count assets")
        print("  2 - List 5 assets")
        print("  3 - Search by category")
        print("  4 - Get vulnerabilities")
        print("  exit - Quit")
        
        choice = input("\nSelect: ").strip()
        
        if choice in ['exit', 'quit', 'q']:
            print("\n Goodbye!\n")
            break
        
        print()
        
        try:
            if choice == '1':
                result = await call_tool("search_assets", {"return_type": "count"})
                print(result["result"])
            
            elif choice == '2':
                result = await call_tool("search_assets", {"limit": 5})
                print(result["result"])
            
            elif choice == '3':
                category = input("Category: ").strip()
                result = await call_tool("search_assets", {
                    "type_category": category,
                    "limit": 3
                })
                print(result["result"])
            
            elif choice == '4':
                result = await call_tool("get_model_vulnerabilities")
                print(result["result"])
            
            else:
                print("Invalid option")
        
        except Exception as e:
            print(f"Error: {e}")
        
        input("\nPress Enter...")


if __name__ == "__main__":
    try:
        asyncio.run(interactive())
    except KeyboardInterrupt:
        print("\n\n Goodbye!\n")
