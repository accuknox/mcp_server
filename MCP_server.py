#!/usr/bin/env python3
"""
AccuKnox MCP Server - stdio transport
For use with Gemini CLI and other stdio-based clients
"""

import signal
import sys
from typing import Optional

from fastmcp import FastMCP

from shared import AccuKnoxClient, get_model_vulnerabilities_tool, search_assets_tool

# Global client instance
api_client = AccuKnoxClient()

# Initialize MCP server
mcp = FastMCP("AccuKnox Asset Manager")


def signal_handler(sig, frame):
    """Handle shutdown signals gracefully"""
    print("\n\n Shutting down gracefully...", file=sys.stderr)
    sys.exit(0)


# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


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
    deployed: Optional[bool] = None,
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
        deployed: Optional[bool]. Set to True for deployed models, False for undeployed models, or None (default) to ignore deployment status.
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


@mcp.tool()
async def get_model_vulnerabilities() -> str:
    """
    READ-ONLY: Get AI/ML model security vulnerabilities summary.

    Retrieves a comprehensive summary of security issues across:
    - ML Models (machine learning models)
    - LLM Models (large language models)
    - Datasets

    Shows breakdown by severity: Critical, High, Medium, Low

    Returns:
        Formatted vulnerability report with severity breakdown and recommendations

    Examples:
        - "Show me model vulnerabilities"
        - "What security issues do my AI models have?"
        - "List all model security problems
    """
    return await get_model_vulnerabilities_tool(api_client)


if __name__ == "__main__":
    print("=" * 70, file=sys.stderr)
    print("AccuKnox MCP Server - stdio", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    print("Transport: stdio (for Gemini CLI)", file=sys.stderr)
    print("Tools: search_assets, get_model_vulnerabilities", file=sys.stderr)
    print("Press Ctrl+C to shutdown", file=sys.stderr)
    print("=" * 70, file=sys.stderr)

    try:
        mcp.run()
    except KeyboardInterrupt:
        print("\n\nServer stopped gracefully\n", file=sys.stderr)
    except Exception as e:
        print(f"\n\n Server error: {e}\n", file=sys.stderr)
        sys.exit(1)
