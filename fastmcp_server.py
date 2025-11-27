# server_http.py
import logging
import warnings
from typing import Any, Dict, Literal, Optional

import httpx
from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse

from shared import AccuKnoxClient, get_model_vulnerabilities_tool, search_assets_tool
from shared.utils.finding import (
    _fetch_findings,
    _finding_filter,
    _get_finding_config,
    _normalize_dict,
)

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


@mcp.tool
async def data_type_selection() -> dict:
    """
    Provide a unified list of available data types for all finding-related tools.
    Select the data type to provide finding details for tools.
    """
    return {
        "tools": {
            "Cluster Findings": "For detecting Kubernetes cluster-level misconfigurations.",
            "STIG Findings": "For applying Risk Reduction and Security Technical Implementation Guides.",
            "CIS K8s Benchmark Findings": "For checking Kubernetes cluster against CIS benchmarks.",
            "Cloud Findings": "Cloud infrastructure / cloud resource auditing: scanning cloud accounts (AWS, Azure, GCP) for insecure or noncompliant settings (e.g. permissive IAM, open S3, etc.).",
            "API Security Findings": "Tool for scanning APIs (REST / GraphQL) to detect API-specific vulnerabilities (injection, authorization, parameter tampering, broken access control).",
            "RAT STIG": "For security hardening checks aligned with STIG standards.",
            "Container Image Findings": "A vulnerability scanner for containers/registry. Useful for scanning container images for known CVEs and misconfigurations.",
            "Software Composition Analysis": "A specialization of Trivy focusing on Software Composition Analysis (SCA) — i.e. scanning dependencies (open-source libraries) for known vulnerabilities, license issues, etc.",
            "Container Secret": "A variant or plugin of Trivy focused on secret detection (e.g. API keys, passwords, private keys) embedded in code, configurations, or other files.",  # pragma: allowlist secret
            "KIEM Findings": "For Kubernetes identity and entitlement misconfiguration detection- find identity misconfigurations, over-privileged accounts, broken RBAC setups, etc.",
            "Host-Endpoint Findings": "For broad vulnerability scanning across networks, hosts, and systems.",
            "CX SAST": "Static Application Security Testing from Checkmarx (CxSAST) — for analyzing source code to find logic, control-flow, data-flow vulnerabilities (SQL injection, XSS, etc.)",
            "CX CONTAINERS": "Checkmarx’s container-focused scanning (container images, Docker artifacts) to find vulnerabilities inside images and container-level misconfigurations.",
            "CX KICS": "Checkmarx integration with KICS (Keep It Cloud Secure) — for infrastructure-as-code (IaC) scanning (Terraform, CloudFormation, etc.)",
            "DAST Findings 1": "Zed Attack Proxy (OWASP ZAP) — a dynamic application security testing (DAST) tool, used to scan running web applications (APIs, web endpoints) for vulnerabilities (SQLi, XSS, etc.)",
            "ML Findings": "A tool or framework for validating machine-learning/AI pipelines — e.g. model validation, fairness checks, bias detection, security checks in ML workflows.",
            "LLM Findings": "An LLM / generative AI vulnerability scanner / red-teaming tool. It probes LLMs (chatbots, language models) for prompt injection, hallucination, data leakage, jailbreaks, etc.",
        },
    }


@mcp.tool
async def get_finding_config(data_type: str | None = None) -> dict:
    """
    MCP Tool: Retrieve finding configuration metadata for a given data type.

    Args:
        data_type (str | None):
            The human-readable name of the finding type.
            Examples:
              - "Cloud Findings"
              - "Container Image Findings"
              - "STIG Findings"
    Returns:
        dict:
            Configuration details for the requested data type, including:

            - display_fields:
                Valid fields that can be requested in `display_fields` when calling `get_finding`.

            - filter_fields:
                Valid fields usable in `extra_filters`.

            - group_by:
                Supported grouping fields (if any).

            - order_by:
                Default sorting field for findings.
    """
    return await _get_finding_config(data_type)


@mcp.tool
async def get_finding(
    data_type: str,
    ordering: Optional[str] = None,
    page: int = 1,
    page_size: int = 5,
    extra_filters: dict | str | None = None,
    display_fields: dict | str | None = None,
    group_by: Optional[str] = None,
    search: str = "",
) -> dict:
    """
    MCP Tool to fetch findings.

    Args:
        data_type: Human-readable data type name (e.g., 'Cloud Findings')
        ordering: Optional ordering (default: -last_seen)
        page: Page number
        page_size: Page size
        extra_filters: Optional filters - use ONLY fields from filter_fields and validate values
                    (pipe-separated values supported)
        display_fields: Optional dict of fields to display - use ONLY fields from
                        display_fields (if None → count only)
        group_by: Optional grouping field
        search: Optional search string

    Returns:
        dict: API response with cleaned results and count

    Notes:
        - For filtering: Use only fields available in filter_fields configuration
        - For display: Use only fields available in display_fields configuration
        - Call get_finding_config() first to see available filter_fields and display_fields
    """
    extra_filters = _normalize_dict(extra_filters)
    display_fields = _normalize_dict(display_fields)
    return await _fetch_findings(
        data_type=data_type,
        ordering=ordering,
        page=page,
        page_size=page_size,
        extra_filters=extra_filters,
        display_fields=display_fields,
        group_by=group_by,
        search=search,
    )


@mcp.tool
async def get_finding_filter(
    filter_field: str,
    data_type: str,
    filter_search: Optional[str] = "",
) -> dict:
    """
    Returns dropdown filter values for a given filter_field + data_type only for finding.
    Args:
        filter_field (str): The field to fetch filter values for.
        data_type (str): Human-readable finding type (e.g., "Cloud Findings").
        filter_search (str): Optional search string for narrowing values.

    Returns:
        dict: { filter_field, count, results }
    """
    return await _finding_filter(
        filter_field=filter_field,
        data_type=data_type,
        filter_search=filter_search or "",
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
