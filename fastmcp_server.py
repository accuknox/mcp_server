"""
AccuKnox Assets MCP Server - Production Ready
"""

import logging
import warnings
from typing import Literal, Optional

import httpx
from fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_headers
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse

# Suppress warnings
logging.getLogger("mcp.server.streamable_http").setLevel(logging.CRITICAL)
logging.getLogger("anyio").setLevel(logging.CRITICAL)
warnings.filterwarnings("ignore", category=RuntimeWarning)

# Initialize FastMCP server
mcp = FastMCP("AccuKnox Assets Server")


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


@mcp.custom_route("/tools", methods=["GET"])
async def list_tools_http(request: Request) -> JSONResponse:
    return JSONResponse(
        {"tools": [{"name": "search_assets", "description": "Search AccuKnox assets"}]},
    )


class AccuKnoxClient:
    def __init__(self, base_url: str, api_token: str):
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }

    async def fetch_assets(
        self,
        asset_id=None,
        type_name=None,
        type_category=None,
        label_name=None,
        region=None,
        cloud_provider=None,
        page=1,
        page_size=100,
    ) -> dict:
        endpoint = f"{self.base_url}/api/v1/assets"
        params = {"page": page, "page_size": page_size}

        if asset_id:
            params["id"] = asset_id
        if type_name:
            params["type_name"] = type_name
        if type_category:
            params["type_category"] = type_category
        if label_name:
            params["label_name"] = label_name
        if region:
            params["region"] = region
        if cloud_provider:
            params["cloud_provider"] = cloud_provider

        async with httpx.AsyncClient() as client:
            response = await client.get(
                endpoint,
                headers=self.headers,
                params=params,
                timeout=30.0,
            )
            response.raise_for_status()
            return response.json()


@mcp.tool
async def search_assets(
    asset_id: Optional[str] = None,
    type_name: Optional[str] = None,
    type_category: Optional[str] = None,
    label_name: Optional[str] = None,
    region: Optional[str] = None,
    cloud_provider: Optional[str] = None,
    return_type: Literal["list", "count"] = "list",
    limit: int = 10,
    detailed: bool = False,
) -> dict:
    """
    Search and filter cloud infrastructure assets.

    Args:
        asset_id: Filter by specific asset ID
        type_name: Filter by asset type name
        type_category: Filter by category (Configuration, User, Models, Block Storage,
                       CI/CD, Datasets, Container, Audit logging, IaC_github-repository)
        label_name: Filter by label name
        region: Filter by cloud region
        cloud_provider: Filter by provider (aws, azure, gcp)
        return_type: "list" or "count"
        limit: Maximum results (default: 10)
        detailed: Include vulnerabilities and compliance data

    Returns:
        Asset list or count
    """

    try:
        headers = get_http_headers(include_all=True)
    except Exception as e:
        return {"error": "Failed to read headers", "message": str(e)}

    accuknox_base_url = headers.get("x-accuknox-base-url", "")
    accuknox_api_token = headers.get("x-accuknox-api-token", "")

    if not accuknox_base_url:
        return {"error": "Missing x-accuknox-base-url header"}
    if not accuknox_api_token:
        return {"error": "Missing x-accuknox-api-token header"}

    client = AccuKnoxClient(accuknox_base_url, accuknox_api_token)

    try:
        response = await client.fetch_assets(
            asset_id=asset_id,
            type_name=type_name,
            type_category=type_category,
            label_name=label_name,
            region=region,
            cloud_provider=cloud_provider,
            page=1,
            page_size=limit if return_type == "list" else 1000,
        )

        assets = response.get("results", [])
        total_count = response.get("count", len(assets))

        if return_type == "count":
            return {"count": total_count}

        formatted_assets = []
        for asset in assets[:limit]:
            asset_data = {
                "id": asset.get("id"),
                "name": asset.get("name"),
                "type": asset.get("type_name"),
                "category": asset.get("type_category"),
                "cloud_provider": asset.get("cloud_provider"),
                "region": asset.get("region"),
                "labels": asset.get("labels", []),
            }
            if detailed:
                asset_data["vulnerabilities"] = asset.get("vulnerabilities", [])
                asset_data["compliance"] = asset.get("compliance", {})
            formatted_assets.append(asset_data)

        return {
            "total_count": total_count,
            "returned_count": len(formatted_assets),
            "assets": formatted_assets,
        }
    except httpx.HTTPStatusError as e:
        return {"error": f"HTTP {e.response.status_code}", "message": str(e)}
    except Exception as e:
        return {"error": "Request failed", "message": str(e)}


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
        with_sse=False,  # ← THIS IS THE FIX!
    )
