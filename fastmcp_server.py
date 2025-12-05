import os
from typing import Optional

import uvicorn
from fastmcp import Context, FastMCP
from fastmcp.exceptions import ClientError, InvalidSignature, ToolError
from fastmcp.server.middleware import Middleware, MiddlewareContext
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse

from logging_config import logger
from shared import AccuKnoxClient, get_model_vulnerabilities_tool, search_assets_tool
from shared.utils.auth_validator import CustomJWTVerifier, _get_auth_context
from shared.utils.finding import (
    _fetch_findings,
    _finding_filter,
    _get_finding_config,
    _normalize_dict,
)

mcp = FastMCP(
    "AccuKnox Assets Server",
    json_response=True,
)
verifier = CustomJWTVerifier()


class BearerTokenMiddleware(Middleware):
    async def on_message(self, context: MiddlewareContext, call_next):
        ctx = context.fastmcp_context
        base_url, token = _get_auth_context(ctx)
        if not base_url or not token:
            raise ToolError(
                "Missing required authentication parameters: base_url or token",
            )

        # try:
        # valid, reason = await verifier.verify(base_url, token)
        # except Exception as e:
        # raise ClientError(f"Token check failed unexpectedly: {str(e)}")
        #
        # if not valid:
        # if reason == "expired":
        # raise InvalidSignature("Token has expired.")
        # elif reason == "issuer_mismatch":
        # raise InvalidSignature("Token issuer does not match.")
        # elif reason == "invalid_signature":
        # raise InvalidSignature("Token signature is invalid.")
        # else:
        # raise ClientError(f"Token invalid: {reason}")

        ctx.set_state("base_url", base_url)
        ctx.set_state("token", token)

        return await call_next(context)


mcp.add_middleware(BearerTokenMiddleware())


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
    ctx: Context = None,
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
        ctx: FastMCP Context (injected automatically)

    Returns:
        Formatted asset list, count, or model statistics

    Examples:
        - "How many Models do I have?" → type_category="Models", return_type="count"
        - "Show me deployed models" → deployed=True
        - "Show me Container assets" → type_category="Container"
        - "List AWS assets" → cloud_provider="aws"
        - "Show assets with security details" → detailed=True
    """

    base_url = ctx.get_state("base_url")
    token = ctx.get_state("token")
    client = AccuKnoxClient(base_url=base_url, api_token=token)

    return await search_assets_tool(
        client,
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
            "Cloud Findings": "Cloud security posture management for AWS, Azure, and GCP: continuously audits cloud resources (IAM, storage, networking, logging, etc.) for insecure or non‑compliant configurations.",
            "Cluster Findings": "Kubernetes cluster configuration assessment: analyzes cluster-level settings (RBAC, namespaces, API server, admission controls, network policies) to detect misconfigurations and weak security controls.",
            "Container Image Findings": "Container image vulnerability and configuration scanner: inspects images and registries for known CVEs, insecure base images, exposed ports, and risky runtime configurations.",
            "Container Secret": "Secrets detection in container-related artifacts: scans container images, Kubernetes manifests, Helm charts, and config files for embedded secrets such as API keys, passwords, and private keys.",  # pragma: allowlist secret
            "CX CONTAINERS": "Checkmarx container security: focuses on vulnerabilities and misconfigurations inside container images and Docker artifacts as part of the Checkmarx platform.",
            "CX SAST": "Checkmarx Static Application Security Testing (CxSAST): analyzes application source code to find security flaws such as injection, insecure deserialization, XSS, and authorization issues before deployment.",
            "CX KICS": "Checkmarx KICS (Keep It Cloud Secure): scans infrastructure-as-code templates (Terraform, CloudFormation, Kubernetes, etc.) for misconfigurations and cloud security risks.",
            "CX SCA": "Checkmarx Software Composition Analysis: identifies vulnerable, outdated, or risky open‑source and third‑party dependencies, including license and compliance issues.",
            "CIS K8s Benchmark Findings": "CIS Kubernetes Benchmark compliance checks: evaluates Kubernetes components against CIS benchmark controls and reports gaps from recommended hardening guidelines.",
            "DAST Findings 1": "OWASP ZAP dynamic application security testing: actively probes running web applications and APIs for runtime vulnerabilities such as SQL injection, XSS, and authentication weaknesses.",
            "DAST Findings 2": "Burp Suite dynamic web application testing: performs interactive and automated security testing of web apps and APIs to uncover logic flaws, injection issues, and other exploitable defects.",
            "Host-Endpoint Findings": "Host and endpoint vulnerability management: scans servers, VMs, and endpoints for missing patches, insecure services, weak configurations, and known OS or middleware CVEs.",
            "IAC Findings": "Checkov infrastructure-as-code scanning: reviews Terraform, CloudFormation, ARM, and similar templates for misconfigurations, insecure defaults, and non‑compliant resource definitions.",
            "KIEM Findings": "Kubernetes identity and entitlement management: analyzes Kubernetes RBAC, service accounts, roles, and bindings to detect over‑privileged identities and risky access paths.",
            "LLM Findings": "Large language model (LLM) security assessment: tests LLM-powered applications for prompt injection, data leakage, jailbreaks, unsafe tool usage, and other generative AI risks.",
            "ML Findings": "Machine learning pipeline risk and quality assessment: evaluates ML workflows and models for security, governance, bias, data handling issues, and operational robustness.",
            "Opengrep Findings": "Semgrep source code and repository scanning: mines codebases using pattern and rule-based checks to find known vulnerability patterns, insecure usage, and policy violations.",
            "Prowler Cloud Findings": "AWS, Azure, and multi-cloud security best-practice scanner: uses Prowler to check cloud accounts against security benchmarks and hardening recommendations.",
            "Secret Scan Findings": "Dedicated secret detection across code, repositories, logs, and configuration files to prevent exposure of credentials, tokens, certificates, and other sensitive values.",
            "Software Composition Analysis": "Trivy-based software composition analysis: scans application dependencies and container layers for known CVEs, insecure packages, and license compliance issues.",
            "Static Code Analysis Findings": "Static analysis of application source code (SAST) independent of vendor: identifies coding-level security defects directly in code repositories before build and deployment.",
            "STIG Findings": "Security Technical Implementation Guide (STIG) compliance: checks systems and configurations against STIG and similar hardening baselines to reduce technical risk.",
            "API Security Findings": "API-focused security testing: analyzes REST and GraphQL APIs for issues such as broken access control, injection, insecure authentication, and improper input validation.",
        },
    }


@mcp.tool
async def get_finding_config(data_type: str | None = None, ctx: Context = None) -> dict:
    """
    MCP Tool: Retrieve finding configuration metadata for a given data type.

    Args:
        data_type (str | None):
            The human-readable name of the finding type.
            Default: "Cloud Findings"
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
    base_url = ctx.get_state("base_url")
    token = ctx.get_state("token")
    return await _get_finding_config(data_type, base_url=base_url, token=token)


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
    ctx: Context = None,
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
    extra_filters, valid = _normalize_dict(extra_filters, "extra_filters")
    if not valid:
        return extra_filters
    display_fields, valid = _normalize_dict(display_fields, "display_fields")
    if not valid:
        return display_fields

    base_url = ctx.get_state("base_url")
    token = ctx.get_state("token")
    return await _fetch_findings(
        data_type=data_type,
        ordering=ordering,
        page=page,
        page_size=page_size,
        extra_filters=extra_filters,
        display_fields=display_fields,
        group_by=group_by,
        search=search,
        base_url=base_url,
        token=token,
    )


@mcp.tool
async def get_finding_filter(
    filter_field: str,
    data_type: str,
    filter_search: Optional[str] = "",
    ctx: Context = None,
) -> dict:
    """
    Returns dropdown filter values for a given filter_field + data_type only for finding.
    Note:
        Shorter terms tend to match more items.
    Args:
        filter_field (str): The field to fetch filter values for.
        data_type (str): Human-readable finding type (e.g., "Cloud Findings").
        filter_search (str): Optional search string for narrowing values.

    Returns:
        dict: { filter_field, count, results }
    """
    base_url = ctx.get_state("base_url")
    token = ctx.get_state("token")
    return await _finding_filter(
        filter_field=filter_field,
        data_type=data_type,
        filter_search=filter_search or "",
        base_url=base_url,
        token=token,
    )


mode = os.environ.get("MCP_MODE", "http").lower()
if mode == "http":
    app = mcp.http_app()


def main():
    """Run the server directly (HTTP or STDIO mode)."""
    import sys

    if mode == "stdio":
        logger.info("📘 Running MCP server in STDIO mode")
        mcp.run()
    else:
        # Default: HTTP mode
        ssl_cert = os.environ.get("SSL_CERT_FILE")
        ssl_key = os.environ.get("SSL_KEY_FILE")

        host = os.environ.get("HOST", "0.0.0.0")
        port = int(os.environ.get("PORT", 8000))
        workers = int(os.environ.get("WORKERS", 1))

        kwargs = {
            "app": app,
            "host": host,
            "port": port,
            "workers": workers,
            "log_level": "info",
        }

        if ssl_cert and ssl_key:
            logger.info("SSL Enabled for HTTP server")
            kwargs["ssl_certfile"] = ssl_cert
            kwargs["ssl_keyfile"] = ssl_key
        else:
            logger.info("SSL Disabled — running over HTTP")

        logger.info(f"🌐 Starting HTTP server on {host}:{port}")
        uvicorn.run(**kwargs)


if __name__ == "__main__":
    main()
