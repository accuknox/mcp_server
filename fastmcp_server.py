# server_http.py
import logging
import warnings
from typing import Literal, Optional

import httpx
from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse

from shared import AccuKnoxClient, get_model_vulnerabilities_tool, search_assets_tool

# Initialize FastMCP server for HTTP
mcp = FastMCP(
    "AccuKnox Assets Server",
    stateless_http=True,
    json_response=True,
)


@mcp.custom_route("/", methods=["GET"])
async def root_endpoint(request: Request) -> JSONResponse:
    return JSONResponse(
        {
            "name": "AccuKnox Assets MCP Server",
            "version": "1.0.0",
            "protocol": "mcp",
            "endpoints": {"mcp": "/mcp", "health": "/health", "info": "/info"},
        },
    )


@mcp.custom_route("/info", methods=["GET"])
async def server_info(request: Request) -> JSONResponse:
    return JSONResponse(
        {
            "server": "AccuKnox Assets Server",
            "version": "1.0.0",
            "endpoints": {"mcp": "/mcp", "health": "/health"},
        },
    )


@mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request) -> JSONResponse:
    return JSONResponse({"status": "healthy"})


@mcp.custom_route("/healthz", methods=["GET"])
async def health_check_simple(request: Request) -> PlainTextResponse:
    return PlainTextResponse("OK")


api_client = AccuKnoxClient()


@mcp.tool()
async def search_assets(
    asset_id: Optional[str] = None,
    type_name: Optional[str] = None,
    type_category: Optional[str] = None,
    label_name: Optional[str] = None,
    region: Optional[str] = None,
    cloud_provider: Optional[str] = None,
    return_type: str = "list",
    limit: int = 10,
    detailed: bool = False,
    deployed: bool = False,
    present_on_date_after: Optional[str] = None,
    present_on_date_before: Optional[str] = None,
) -> str:
    """
    READ-ONLY: Search and filter cloud infrastructure assets.

    Args:
        asset_id: Filter by specific asset ID
        type_name: Filter by asset type name
        type_category: Filter by category (sCommon categories: Configuration, User, Models, Block Storage, CI/CD,
    Datasets, Container, Audit logging, IaC_github-repository)
        label_name: Filter by label name
        region: Filter by cloud region
        cloud_provider: Filter by provider (aws, azure, gcp)
        return_type: "list" (default) or "count"
        limit: Maximum results to return (default: 10)
        detailed: Include vulnerabilities and compliance data
        deployed: Set to True to get AI model deployment statistics (e.g. "Show me deployed models")
        present_on_date_after: Filter assets present on or after this date. Format: YYYY-MM-DD. Defaults to two days ago if not provided.
        present_on_date_before: Filter assets present on or before this date. Format: YYYY-MM-DD. Defaults to now if not provided

    Returns:
        Formatted asset list, count, or model statistics

    Examples:
        - "How many Models do I have?" → type_category="Models", return_type="count"
        - "Show me deployed models" → deployed=True
        - "Show me Container assets" → type_category="Container"
        - "List AWS assets" → cloud_provider="aws"
        - "Show assets with security details" → detailed=True
    """
    return await search_assets_tool(
        api_client,
        asset_id,
        type_name,
        type_category,
        label_name,
        region,
        cloud_provider,
        return_type,
        limit,
        detailed,
        deployed,
        present_on_date_after,
        present_on_date_before,
    )


if __name__ == "__main__":
    print("=" * 70)
    print("🚀 AccuKnox MCP Server")
    print("=" * 70)
    print(f"📍 http://0.0.0.0:8000")
    print(f"🔌 http://0.0.0.0:8000/mcp")
    print(f"💚 http://0.0.0.0:8000/health")
    print("=" * 70)

    # THE KEY FIX: Use with_sse=False to disable Accept header checking
    mcp.run(
        transport="http",
        host="0.0.0.0",
        port=8000,
    )
