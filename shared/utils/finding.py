import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from logging_config import logger
from shared.utils.api_utils import call_api

# Cache config maps for display/filter fields
config_maps: Dict[str, Dict[str, Any]] = {}

vul_data_map = {
    "Container Image Findings": "trivy",
    "Cloud Findings": "cloudsploit",
    "Cluster Findings": "cluster-misconfiguration",
    "Container Secret": "Trivy_Secret",  # pragma: allowlist secret
    "CX CONTAINERS": "cx_containers",
    "CX KICS": "cx_kics",
    "CX SAST": "cx_sast",
    "CX SCA": "cx_sca",
    "CIS K8s Benchmark Findings": "kubebench",
    "DAST Findings": "zap|burp",
    "DAST Findings 1": "zap",
    "DAST Findings 2": "burp",
    "Host-Endpoint Findings": "nessus",
    "Host-Endpoint Web Findings": "nessus_web",
    "IAC Findings": "IAC Scan",
    "IaC Findings": "IAC Scan",
    "KIEM Findings": "KIEM",
    "LLM Findings": "garak",
    "AI Red Teaming": "garak",
    "ML Findings": "MLChecks",
    "Model Audit": "model_audit",
    "Opengrep Findings": "sg",
    "SAST Findings": "sg",
    "Prowler Cloud Findings": "prowler",
    "SARIF Findings": "droopescan",
    "SBOM Findings": "sbom",
    "SBOM License Findings": "sbom_license",
    "Secret Scan Findings": "secret scanning",
    "Secret Scan Findings 1": "droopescan",
    "Secret Scan Findings 2": "secret scanning",
    "SecurityHub AWS Findings": "securityhub",
    "Software Composition Analysis": "trivy-sca",
    "Static Code Analysis Findings": "sonarqube",
    "Static Code Analysis Finding": "sonarqube",
    "STIG Findings": "RRA_STIG",
    "VM CIS Findings": "RRA_CIS",
    "VM Malware Findings": "clamscan",
    "WAF Findings": "RRA_WAF",
    "Linux VM Vulnerability Findings": "trivy-rootfs",
    "Windows VM Vulnerability Findings": "windowsvm",
    "API Security Findings": "APISCAN",
    "5G Security Findings": "5gscan",
    "All Findings": None,
}

# Operator suffixes allowed on a stage/filter key that won't appear verbatim in
# the config's filter_fields (e.g. `vulnerability__cvss_score__gte`).
FILTER_OPERATOR_SUFFIXES = ("__gte",)


def _strip_operator_suffix(field: str) -> str:
    """Strip a trailing lookup operator (e.g. `__gte`) so the base field can be
    validated against the config, while still allowing the operator form."""
    for suffix in FILTER_OPERATOR_SUFFIXES:
        if field.endswith(suffix):
            return field[: -len(suffix)]
    return field


async def _get_finding_config(
    data_type: str | None = None,
    base_url: str | None = None,
    token: str | None = None,
    include_endpoint: bool = False,
) -> dict:
    """
    Fetch and return the finding configuration for a given data_type.
    If data_type is None, returns the first config by default.
    """

    endpoint = "api/v1/vulnerability-configs/filters-data-config"
    response = await call_api(
        endpoint,
        method="GET",
        base_url=base_url,
        token=token,
        include_endpoint=include_endpoint,
    )

    # Handle wrapped response when include_endpoint=True
    endpoint_info = None
    if (
        isinstance(response, dict)
        and "data" in response
        and "endpoint_info" in response
    ):
        endpoint_info = response.get("endpoint_info")
        configs = response["data"]
    elif isinstance(response, dict) and "data" in response:
        configs = response["data"]
    else:
        configs = response

    data_types = []

    for cfg in configs:
        cfg_display_name = cfg.get("config_name")
        all_display_fields = cfg.get("all_display_fields", {})
        all_filter_fields = cfg.get("all_filter_fields", {})
        base_date_fields = ["present_on_date", "last_seen", "date_discovered"]
        for field in base_date_fields:
            if field in all_filter_fields:
                all_filter_fields.pop(field)
                all_filter_fields[
                    f"{field}_after"
                ] = f"{field.replace('_', ' ').title()} on or after this date. Format: YYYY-MM-DD"
                all_filter_fields[
                    f"{field}_before"
                ] = f"{field.replace('_', ' ').title()} on or before this date. Format: YYYY-MM-DD"
        group_by = cfg.get("group_by", {})
        group_by["group_by_order"] = "Default group by order is '-total' "
        config_maps[cfg_display_name] = {
            "data_type": cfg_display_name,
            "display_fields": all_display_fields,
            "filter_fields": all_filter_fields,
            "default_filter_field": cfg.get("filter_values_kv", {}),
            "group_by": cfg.get("group_by", {}),
            "order_by": cfg.get("order_by"),
        }
        data_types.append(cfg_display_name)

    if not data_type in config_maps:
        return {
            "data_type": f"No available {data_type} data type. Available: {data_types}",
        }

    result = config_maps.get(data_type).copy()
    if endpoint_info:
        result["endpoint_info"] = endpoint_info

    return result


def validate_fields(
    fields: Optional[Dict[str, Any]],
    default_fields: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Return only fields that exist in default_fields.
    """
    if not fields:
        return default_fields
    return {k: v for k, v in fields.items() if k in default_fields}


def create_api_params(filter_values_kv: Dict[str, Any]) -> Dict[str, str]:
    """
    Converts filter_values_kv to API query params.
    Joins multiple values with a pipe '|'.
    """
    api_params = {}
    for key, items in filter_values_kv.items():
        values = [item["value"] for item in items]
        api_params[key] = "|".join(values)
    return api_params


def _normalize_dict(value, name):
    """Accepts a dict or JSON string and returns (result, success)."""
    if value is None or value == "":
        return {}, True

    if isinstance(value, dict):
        return value, True

    if isinstance(value, str):
        try:
            return json.loads(value), True
        except json.JSONDecodeError:
            return (
                {name: f"'{value}' is not valid. Expected a dict or JSON string."},
                False,
            )

    return (
        {name: f"'{value}' is not valid. Expected a dict or JSON string."},
        False,
    )


async def validate_filters(
    extra_filters: dict,
    data_type: str,
    filter_fields: dict,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
):
    if not extra_filters:
        return {}, {}
    tasks = []
    valid_filters = {}
    invalid_filters = {}
    task_key = []

    date_keys = [
        "present_on_date_after",
        "present_on_date_before",
        "last_seen_after",
        "last_seen_before",
        "date_discovered_after",
        "date_discovered_before",
    ]
    for key, value in extra_filters.items():
        if key in date_keys:
            try:
                # Validate date format
                datetime.strptime(value, "%Y-%m-%d")
                valid_filters[key] = value
                if key.endswith("_after"):
                    before_key = key.replace("_after", "_before")
                    if before_key not in extra_filters:
                        valid_filters[before_key] = datetime.now().strftime("%Y-%m-%d")

            except ValueError:  # catch only date parsing errors
                invalid_filters[key] = {
                    "provided_value": value,
                    "message": f"'{value}' is not valid. Valid Format: YYYY-MM-DD.",
                }

        elif key in filter_fields:
            task_key.append(key)
            tasks.append(
                _finding_filter(
                    filter_field=key,
                    data_type=data_type,
                    filter_search=value,
                    base_url=base_url,
                    token=token,
                ),
            )

    results = await asyncio.gather(*tasks)

    for key, dropdown in zip(task_key, results):
        value = extra_filters.get(key)
        dropdown_values = set(dropdown.get("results", []))  # simplified

        if value not in dropdown_values:
            invalid_filters[key] = {
                "provided_value": value,
                "count": len(dropdown_values),
                "valid_values": dropdown_values,
                "message": (
                    "No matching values found."
                    if len(dropdown_values) == 0
                    else f"'{value}' is not valid. Choose from valid_values."
                ),
            }
        else:
            valid_filters[key] = value

    return valid_filters, invalid_filters


async def _fetch_findings(
    data_type: str,
    ordering: Optional[str] = None,
    page: int = 1,
    page_size: int = 5,
    extra_filters: Optional[Dict[str, Any]] = None,
    display_fields: Optional[Dict[str, Any]] = None,
    group_by: Optional[str] = None,
    search: str = "",
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    include_endpoint: bool = False,
) -> dict:
    """
    Internal flexible finding fetcher.

    Special behavior:
    - If display_fields=None → only return count
    - Supports group_by: if used → return grouped API results directly
    - Applies default filters: status=Active, ignored=False
    """
    if not config_maps:
        config = await _get_finding_config(
            data_type,
            base_url=base_url,
            token=token,
        )
    else:
        config = config_maps.get(data_type)
    if not config:
        return {"error": f"Data type '{data_type}' not found."}
    # Default filters

    default_filter_field = config.get("default_filter_field", {}) or config.get(
        "filter_values_kv",
        {},
    )
    default_filter = create_api_params(default_filter_field)
    # Apply only valid filters
    filter_fields = config.get("filter_fields", {})
    valid_filter, invalid_filter = await validate_filters(
        extra_filters or {},
        data_type,
        filter_fields,
        base_url=base_url,
        token=token,
    )
    if invalid_filter:
        return invalid_filter

    params = {
        "page": page,
        "search": search,
        "page_size": page_size,
        "depth": 3,
        "vulnerability__data_type": vul_data_map.get(data_type),
        "ordering": "-" + (ordering or config.get("order_by", "last_seen")).lstrip("-"),
    }
    params = {**params, **default_filter, **valid_filter}

    if group_by:
        params["group_by"] = group_by
        params["group_by_order"] = "-total"

    response = await call_api(
        "api/v1/finding-dashboard",
        method="GET",
        params=params,
        base_url=base_url,
        token=token,
        include_endpoint=include_endpoint,
    )

    endpoint_info = response.pop("endpoint_info", None) if include_endpoint else None

    if display_fields is None:
        result = {"count": response.get("count", 0)}
        if endpoint_info:
            result["endpoint_info"] = endpoint_info
        return result

    if group_by:
        result = {
            "group_by": group_by,
            "count": response.get("count"),
            "results": response.get("results", []),
        }
        if endpoint_info:
            result["endpoint_info"] = endpoint_info
        return result

    # Validate display fields
    default_display = config.get("display_fields", {})
    display_fields = validate_fields(display_fields, default_display)
    cleaned_results = [
        {v: item.get(k) for k, v in display_fields.items()}
        for item in response.get("results", {}).get("data", {})
    ]

    result = {
        "count": response.get("count", 0),
        "page": page,
        "results": cleaned_results,
    }
    if endpoint_info:
        result["endpoint_info"] = endpoint_info

    return result


async def _finding_filter(
    filter_field: str,
    data_type: str,
    filter_search: str = "",
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    include_endpoint: bool = False,
) -> dict:
    """
    Fetch filter dropdown values for a given filter_field + data_type.
    """
    api_data_type = vul_data_map.get(data_type)
    if not api_data_type:
        return {"error": f"Invalid data_type '{data_type}'"}

    params = {
        "filter_field": filter_field,
        "vulnerability__data_type": api_data_type,
        "filter_search": filter_search or "",
        "page": 1,
    }

    api_result = await call_api(
        "api/v1/finding-dashboard/filter-values",
        method="GET",
        params=params,
        base_url=base_url,
        token=token,
        include_endpoint=include_endpoint,
    )

    endpoint_info = api_result.pop("endpoint_info", None) if include_endpoint else None

    result = {
        "filter_field": filter_field,
        "count": api_result.get("count", 0),
        "results": api_result.get("results", []),
    }
    if endpoint_info:
        result["endpoint_info"] = endpoint_info

    return result


async def _fetch_finding_funnel(
    data_type: str,
    stages: Dict[str, Any],
    status: Optional[Any] = None,
    ignored: bool = False,
    present_on_date_after: Optional[str] = None,
    present_on_date_before: Optional[str] = None,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    include_endpoint: bool = False,
) -> dict:
    """
    Build a funnel across sequential filter stages for a given data_type.

    `stages` is an *ordered* mapping of {stage_field: value} (max 6). The keys
    become the `stage_order` (comma-separated) and each key/value is also sent as
    its own query param. Keys carrying a lookup operator
    (e.g. `vulnerability__cvss_score__gte`) are validated against their base field
    so they are supported even though the operator form is not present in the
    config verbatim. `status` is optional and only applied when provided.
    """
    if data_type not in vul_data_map:
        return {
            "error": f"Invalid data_type '{data_type}'.",
            "available_data_types": list(vul_data_map),
        }

    if not stages:
        return {"error": "At least one funnel stage is required."}
    if len(stages) > 6:
        return {
            "error": f"A maximum of 6 funnel stages is supported, got {len(stages)}.",
        }

    api_data_type = vul_data_map.get(data_type)

    # Load config so stage keys can be validated against the data type's fields.
    if not config_maps:
        await _get_finding_config(data_type, base_url=base_url, token=token)
    config = config_maps.get(data_type, {})
    filter_fields = config.get("filter_fields", {})

    # Validate stage keys leniently: allow either the field itself or its base
    # (after stripping a lookup operator) to be a known filter field.
    invalid_stages = {}
    for key in stages:
        base_key = _strip_operator_suffix(key)
        if filter_fields and key not in filter_fields and base_key not in filter_fields:
            invalid_stages[key] = (
                f"'{key}' is not a valid stage field for '{data_type}'."
            )
    if invalid_stages:
        return {
            "invalid_stages": invalid_stages,
            "valid_stage_fields": list(filter_fields),
        }

    # Validate optional date filters.
    for date_field, date_value in (
        ("present_on_date_after", present_on_date_after),
        ("present_on_date_before", present_on_date_before),
    ):
        if date_value:
            try:
                datetime.strptime(date_value, "%Y-%m-%d")
            except ValueError:
                return {
                    date_field: {
                        "provided_value": date_value,
                        "message": f"'{date_value}' is not valid. Valid Format: YYYY-MM-DD.",
                    },
                }

    params = {
        "ignored": "True" if ignored else "False",
        "stage_order": ",".join(stages.keys()),
    }

    # Status is optional: only apply when provided (list or pipe-separated string).
    if status:
        params["status"] = status if isinstance(status, str) else "|".join(status)

    if api_data_type:
        params["vulnerability__data_type"] = api_data_type
    if present_on_date_after:
        params["present_on_date_after"] = present_on_date_after
    if present_on_date_before:
        params["present_on_date_before"] = present_on_date_before

    # Each stage's own value (coerce booleans to the API's lowercase form).
    for key, value in stages.items():
        if isinstance(value, bool):
            params[key] = "true" if value else "false"
        else:
            params[key] = value

    response = await call_api(
        "api/v1/finding-dashboard-v2/funnel",
        method="GET",
        params=params,
        base_url=base_url,
        token=token,
        include_endpoint=include_endpoint,
    )

    endpoint_info = None
    if include_endpoint and isinstance(response, dict):
        endpoint_info = response.pop("endpoint_info", None)

    result = {
        "data_type": data_type,
        "stage_order": list(stages.keys()),
        "funnel": response,
    }
    if endpoint_info:
        result["endpoint_info"] = endpoint_info

    return result
