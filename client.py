"""
Test Client for AccuKnox MCP Server
Run this AFTER starting the server
"""

import asyncio
import json

import httpx


async def test_server():
    base_url = "http://0.0.0.0:8000/mcp"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "x-accuknox-base-url": "https://cspm.demo.accuknox.com",
        "x-accuknox-api-token": "",  # REPLACE WITH REAL TOKEN
    }

    async with httpx.AsyncClient() as client:
        print("=" * 70)
        print("TEST 1: List Tools")
        print("=" * 70)

        request = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}

        response = await client.post(
            base_url,
            json=request,
            headers=headers,
            timeout=30.0,
        )
        print(f"Status: {response.status_code}")
        result = response.json()
        print(json.dumps(result, indent=2))

        print("\n" + "=" * 70)
        print("TEST 2: Count Models")
        print("=" * 70)

        request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "search_assets",
                "arguments": {"type_category": "Models", "return_type": "count"},
            },
        }

        response = await client.post(
            base_url,
            json=request,
            headers=headers,
            timeout=30.0,
        )
        print(f"Status: {response.status_code}")
        result = response.json()
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    asyncio.run(test_server())
