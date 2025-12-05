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
    "DAST Findings 1": "zap",
    "DAST Findings 2": "burp",
    "Host-Endpoint Findings": "nessus",
    "IAC Findings": "IAC Scan",
    "KIEM Findings": "KIEM",
    "LLM Findings": "garak",
    "ML Findings": "MLChecks",
    "Opengrep Findings": "sg",
    "Prowler Cloud Findings": "prowler",
    "Secret Scan Findings": "secret scanning",
    "SecurityHub AWS Findings": "securityhub",
    "Software Composition Analysis": "trivy-sca",
    "Static Code Analysis Findings": "sonarqube",
    "STIG Findings": "RRA_STIG",
    "VM Malware Findings": "clamscan",
    "Linux VM Vulnerability Findings": "trivy-rootfs",
    "Windows VM Vulnerability Findings": "windowsvm",
    "API Security Findings": "APISCAN",
    "5G Security Findings": "5gscan",
}


async def _get_finding_config(
    data_type: str | None = None,
    base_url: str | None = None,
    token: str | None = None,
) -> dict:
    """
    Fetch and return the finding configuration for a given data_type.
    If data_type is None, returns the first config by default.
    """

    endpoint = "api/v1/vulnerability-configs/filters-data-config"
    configs = await call_api(
        endpoint,
        method="GET",
        base_url=base_url,
        token=token,
    )
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
    return config_maps.get(data_type)


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
    )

    if display_fields is None:
        return {"count": response.get("count", 0)}

    if group_by:
        return {
            "group_by": group_by,
            "count": response.get("count"),
            "results": response.get("results", []),
        }

    # Validate display fields
    default_display = config.get("display_fields", {})
    display_fields = validate_fields(display_fields, default_display)
    cleaned_results = [
        {v: item.get(k) for k, v in display_fields.items()}
        for item in response.get("results", {}).get("data", {})
    ]

    return {
        "count": response.get("count", 0),
        "page": page,
        "results": cleaned_results,
    }


async def _finding_filter(
    filter_field: str,
    data_type: str,
    filter_search: str = "",
    base_url: Optional[str] = None,
    token: Optional[str] = None,
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

    result = await call_api(
        "api/v1/finding-dashboard/filter-values",
        method="GET",
        params=params,
        base_url=base_url,
        token=token,
    )

    return {
        "filter_field": filter_field,
        "count": result.get("count", 0),
        "results": result.get("results", []),
    }
