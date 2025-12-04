from fastmcp_server import mcp
import asyncio

async def main():
    try:
        app = mcp.http_app()
        print(f"http_app returns: {type(app)}")
    except Exception as e:
        print(f"http_app error: {e}")

    try:
        app = mcp.sse_app()
        print(f"sse_app returns: {type(app)}")
    except Exception as e:
        print(f"sse_app error: {e}")

asyncio.run(main())
