#!/usr/bin/env python3
"""
AccuKnox MCP Server - HTTP transport
For web and remote clients
"""

import signal
import sys
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from shared import AccuKnoxClient, get_model_vulnerabilities_tool, search_assets_tool

# Global client instance
api_client = AccuKnoxClient()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan"""
    print("\n Server starting...", file=sys.stderr)
    yield
    print("\n Server shutting down...", file=sys.stderr)


app = FastAPI(title="AccuKnox MCP HTTP Server", lifespan=lifespan)


@app.get("/")
async def root():
    return {
        "name": "AccuKnox MCP HTTP Server",
        "version": "1.0.0",
        "tools": ["search_assets", "get_model_vulnerabilities"],
    }


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.get("/tools")
async def list_tools():
    return {
        "tools": [
            {"name": "search_assets", "description": "Search cloud assets"},
            {"name": "get_model_vulnerabilities", "description": "Get vulnerabilities"},
        ],
    }


@app.post("/call_tool")
async def call_tool(request: Request):
    body = await request.json()
    tool_name = body.get("tool")
    arguments = body.get("arguments", {})

    if tool_name == "search_assets":
        result = await search_assets_tool(api_client, **arguments)
    elif tool_name == "get_model_vulnerabilities":
        result = await get_model_vulnerabilities_tool(api_client)
    else:
        return JSONResponse(
            status_code=400,
            content={"error": f"Unknown tool: {tool_name}"},
        )

    return {"result": result}


if __name__ == "__main__":
    import uvicorn

    def signal_handler(sig, frame):
        print("\n\n Server stopped gracefully\n", file=sys.stderr)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print("=" * 70)
    print("AccuKnox MCP Server - HTTP")
    print("=" * 70)
    print("Server: http://localhost:8000")
    print("Tools: search_assets, get_model_vulnerabilities")
    print("Press Ctrl+C to shutdown")
    print("=" * 70)

    try:
        uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
    except KeyboardInterrupt:
        pass
