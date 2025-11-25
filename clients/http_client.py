#!/usr/bin/env python3
"""
HTTP Test Client - Enhanced with Request Logging
Tests the HTTP MCP server and shows detailed API requests
"""

import asyncio
import json
from datetime import datetime

import httpx

SERVER_URL = "http://localhost:8000"


def log_request(method: str, url: str, headers: dict = None, data: dict = None):
    """Log the outgoing API request"""
    print("\n" + "=" * 70)
    print("📤 API REQUEST")
    print("=" * 70)
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Method: {method}")
    print(f"URL: {url}")

    if headers:
        print("\nHeaders:")
        for key, value in headers.items():
            print(f"  {key}: {value}")

    if data:
        print("\nRequest Body:")
        print(json.dumps(data, indent=2))

    print("=" * 70 + "\n")


def log_response(status_code: int, response_data: dict, duration: float):
    """Log the API response"""
    print("\n" + "=" * 70)
    print("📥 API RESPONSE")
    print("=" * 70)
    print(f"Status Code: {status_code}")
    print(f"Duration: {duration:.2f}s")
    print("\nResponse Body:")
    print(json.dumps(response_data, indent=2))
    print("=" * 70 + "\n")


async def call_tool(tool_name: str, arguments: dict = None, verbose: bool = True):
    """Call a tool on the HTTP MCP server with logging"""
    if arguments is None:
        arguments = {}

    url = f"{SERVER_URL}/call_tool"
    headers = {"Content-Type": "application/json"}
    request_data = {"tool": tool_name, "arguments": arguments}

    # Log the request
    if verbose:
        log_request("POST", url, headers, request_data)

    start_time = asyncio.get_event_loop().time()

    async with httpx.AsyncClient() as client:
        response = await client.post(url, json=request_data, timeout=30.0)
        response.raise_for_status()
        response_data = response.json()

    duration = asyncio.get_event_loop().time() - start_time

    # Log the response
    if verbose:
        log_response(response.status_code, response_data, duration)

    return response_data


async def interactive():
    """Interactive client with request/response logging"""
    print("\n" + "=" * 70)
    print("AccuKnox HTTP Client - Enhanced with Request Logging")
    print("=" * 70)
    print(f"Server: {SERVER_URL}")
    print("All API requests and responses will be logged")
    print("=" * 70 + "\n")

    while True:
        print("\n" + "=" * 70)
        print("Available Options:")
        print("=" * 70)

        print("\n📊 Basic Queries:")
        print("  1  - Count all assets")
        print("  2  - List 5 assets (quick preview)")
        print("  3  - List 10 assets (detailed)")

        print("\n🏷️  Filter by Label:")
        print("  4  - Search by label name (e.g., Host, Environment)")
        print("  5  - Count assets with specific label")

        print("\n📁 Filter by Category:")
        print("  6  - Search by category (Models, Container, etc.)")
        print("  7  - Count assets in category")

        print("\n☁️  Filter by Cloud:")
        print("  8  - Search by cloud provider (aws, azure, gcp)")
        print("  9  - Search by region")
        print("  10 - Search by cloud + region")

        print("\n🔍 Advanced Search:")
        print("  11 - Multi-filter search (label + category + cloud)")
        print("  12 - Detailed asset view (with vulnerabilities)")

        print("\n🔐 Security:")
        print("  13 - Get model vulnerabilities")

        print("\n🛠️  Utilities:")
        print("  14 - Test server health")
        print("  15 - List available tools")

        print("\n  exit - Quit")
        print("=" * 70)

        choice = input("\nSelect option: ").strip()

        if choice in ["exit", "quit", "q"]:
            print("\n👋 Goodbye!\n")
            break

        print()

        try:
            # Basic Queries
            if choice == "1":
                print("🔢 Counting all assets...\n")
                result = await call_tool("search_assets", {"return_type": "count"})
                print(f"\n✅ Result: {result['result']}\n")

            elif choice == "2":
                print("📄 Listing first 5 assets...\n")
                result = await call_tool("search_assets", {"limit": 5})
                print(f"\n✅ Result:\n{result['result']}\n")

            elif choice == "3":
                print("📄 Listing first 10 assets...\n")
                result = await call_tool("search_assets", {"limit": 10})
                print(f"\n✅ Result:\n{result['result']}\n")

            # Filter by Label
            elif choice == "4":
                print("🏷️  Available label examples: Host, Environment, Team, Project")
                label_name = input("\nEnter label name: ").strip()
                limit_str = input("How many results? (default 10): ").strip() or "10"

                print(f"\n🔍 Searching assets with label '{label_name}'...\n")
                result = await call_tool(
                    "search_assets",
                    {"label_name": label_name, "limit": int(limit_str)},
                )
                print(f"\n✅ Result:\n{result['result']}\n")

            elif choice == "5":
                label_name = input("Enter label name to count: ").strip()

                print(f"\n🔢 Counting assets with label '{label_name}'...\n")
                result = await call_tool(
                    "search_assets",
                    {"label_name": label_name, "return_type": "count"},
                )
                print(f"\n✅ Result: {result['result']}\n")

            # Filter by Category
            elif choice == "6":
                print("📁 Available categories:")
                print("   - Configuration, User, Models")
                print("   - Block Storage, CI/CD, Datasets")
                print("   - Container, Audit logging")

                category = input("\nEnter category: ").strip()
                limit_str = input("How many results? (default 10): ").strip() or "10"

                print(f"\n🔍 Searching '{category}' assets...\n")
                result = await call_tool(
                    "search_assets",
                    {"type_category": category, "limit": int(limit_str)},
                )
                print(f"\n✅ Result:\n{result['result']}\n")

            elif choice == "7":
                category = input("Enter category to count: ").strip()

                print(f"\n🔢 Counting '{category}' assets...\n")
                result = await call_tool(
                    "search_assets",
                    {"type_category": category, "return_type": "count"},
                )
                print(f"\n✅ Result: {result['result']}\n")

            # Filter by Cloud
            elif choice == "8":
                print("☁️  Available providers: aws, azure, gcp")
                provider = input("\nEnter cloud provider: ").strip().lower()
                limit_str = input("How many results? (default 10): ").strip() or "10"

                print(f"\n🔍 Searching {provider.upper()} assets...\n")
                result = await call_tool(
                    "search_assets",
                    {"cloud_provider": provider, "limit": int(limit_str)},
                )
                print(f"\n✅ Result:\n{result['result']}\n")

            elif choice == "9":
                print("🌍 Example regions: us-east-1, eu-west-1, ap-south-1")
                region = input("\nEnter region: ").strip()
                limit_str = input("How many results? (default 10): ").strip() or "10"

                print(f"\n🔍 Searching assets in {region}...\n")
                result = await call_tool(
                    "search_assets",
                    {"region": region, "limit": int(limit_str)},
                )
                print(f"\n✅ Result:\n{result['result']}\n")

            elif choice == "10":
                provider = input("Cloud provider (aws/azure/gcp): ").strip().lower()
                region = input("Region: ").strip()
                limit_str = input("How many results? (default 10): ").strip() or "10"

                print(f"\n🔍 Searching {provider.upper()} assets in {region}...\n")
                result = await call_tool(
                    "search_assets",
                    {
                        "cloud_provider": provider,
                        "region": region,
                        "limit": int(limit_str),
                    },
                )
                print(f"\n✅ Result:\n{result['result']}\n")

            # Advanced Search
            elif choice == "11":
                print("🔍 Multi-filter Search")
                print("Leave blank to skip any filter\n")

                label_name = input("Label name: ").strip() or None
                category = input("Category: ").strip() or None
                provider = input("Cloud provider: ").strip() or None
                region = input("Region: ").strip() or None
                limit_str = input("Limit (default 10): ").strip() or "10"

                args = {"limit": int(limit_str)}

                if label_name:
                    args["label_name"] = label_name
                if category:
                    args["type_category"] = category
                if provider:
                    args["cloud_provider"] = provider
                if region:
                    args["region"] = region

                print("\n🔍 Searching with filters...\n")
                result = await call_tool("search_assets", args)
                print(f"\n✅ Result:\n{result['result']}\n")

            elif choice == "12":
                limit_str = input("How many assets? (default 5): ").strip() or "5"

                print("\n🔐 Getting detailed asset view...\n")
                result = await call_tool(
                    "search_assets",
                    {"limit": int(limit_str), "detailed": True},
                )
                print(f"\n✅ Result:\n{result['result']}\n")

            # Security
            elif choice == "13":
                print("🔐 Getting AI/ML model vulnerabilities...\n")
                result = await call_tool("get_model_vulnerabilities", {})
                print(f"\n✅ Result:\n{result['result']}\n")

            # Utilities
            elif choice == "14":
                print("🏥 Checking server health...\n")

                url = f"{SERVER_URL}/health"
                log_request("GET", url)

                start_time = asyncio.get_event_loop().time()
                async with httpx.AsyncClient() as client:
                    response = await client.get(url, timeout=10.0)
                    response.raise_for_status()
                    response_data = response.json()
                duration = asyncio.get_event_loop().time() - start_time

                log_response(response.status_code, response_data, duration)
                print(f"\n✅ Server is healthy: {response_data}\n")

            elif choice == "15":
                print("🛠️  Listing available tools...\n")

                url = f"{SERVER_URL}/tools"
                log_request("GET", url)

                start_time = asyncio.get_event_loop().time()
                async with httpx.AsyncClient() as client:
                    response = await client.get(url, timeout=10.0)
                    response.raise_for_status()
                    response_data = response.json()
                duration = asyncio.get_event_loop().time() - start_time

                log_response(response.status_code, response_data, duration)

                tools = response_data.get("tools", [])
                print("\n✅ Available Tools:")
                for tool in tools:
                    print(f"  • {tool['name']}: {tool['description']}")
                print()

            else:
                print("❌ Invalid option. Please try again.")

        except httpx.HTTPStatusError as e:
            print(f"\n❌ HTTP Error {e.response.status_code}")
            print(f"Response: {e.response.text}\n")
        except httpx.ConnectError:
            print(f"\n❌ Connection Error: Cannot connect to {SERVER_URL}")
            print("   Make sure the HTTP server is running.\n")
        except Exception as e:
            print(f"\n❌ Error: {e}\n")

        input("Press Enter to continue...")


if __name__ == "__main__":
    try:
        asyncio.run(interactive())
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!\n")
