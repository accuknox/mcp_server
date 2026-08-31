"""
Policies module — tool implementations.

Covers CWPP policy management: paged policy listing, the four category counts,
and per-policy alert counts (with the cluster-scoped roll-up done server-side).
"""

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import httpx

from logging_config import logger
from shared.utils.scope import require_tenant, split_int_list, split_list, workspace_id
from shared.utils.timeutils import resolve_time_range, time_range_info

from .constants import (
    ALL_POLICY_FIELDS,
    DEFAULT_POLICY_FIELDS,
    POLICY_ALERT_TYPES,
    POLICY_ALERTS_DEFAULT_FROM,
    POLICY_CATEGORIES,
    POLICY_KINDS,
    POLICY_STATUSES,
    POLICY_WORKLOAD,
    resolve_enum_list,
)
from .utils import (
    build_alert_filter_entry,
    build_policy_filter,
    format_search_terms,
    normalize_policies,
    offset_range,
    policy_key,
    project_row,
    sum_alert_counts,
)

# One alert-count request covers a whole page of policies; keep the fan-in sane.
MAX_POLICIES_PER_ALERT_COUNT = 100


def _is_error(response: Any) -> bool:
    return isinstance(response, dict) and "error" in response


def _build_filter(
    cluster_ids: Any,
    namespace_ids: Any,
    workload_ids: Any,
    kinds: Any,
    statuses: Any,
    tags: Any,
    search: Any,
    tag_regex: Optional[str],
) -> Tuple[Optional[Dict[str, Any]], Optional[dict]]:
    """Validate and build the filter vocabulary shared by list-policy and policy-count."""

    cluster_id_list, bad = split_int_list(cluster_ids)
    if bad:
        return None, {"error": f"cluster_ids must be numeric IDs, got '{bad}'."}

    namespace_id_list, bad = split_int_list(namespace_ids)
    if bad:
        return None, {
            "error": f"namespace_ids must be numeric IDs, got '{bad}'.",
            "hint": "This API takes namespace IDs, not names — unlike the alerts tools. "
                    "Use list_namespaces to resolve a name to an ID.",
        }

    workload_id_list, bad = split_int_list(workload_ids)
    if bad:
        return None, {"error": f"workload_ids must be numeric IDs, got '{bad}'."}

    kind_list, error = resolve_enum_list(split_list(kinds), POLICY_KINDS, "kinds")
    if error:
        return None, error

    status_list, error = resolve_enum_list(split_list(statuses), POLICY_STATUSES, "statuses")
    if error:
        return None, error

    return (
        build_policy_filter(
            cluster_ids=cluster_id_list,
            namespace_ids=namespace_id_list,
            workload_ids=workload_id_list,
            kinds=kind_list,
            statuses=status_list,
            tags=split_list(tags),
            search_terms=format_search_terms(search),
            tag_regex=tag_regex,
        ),
        None,
    )


def _filter_info(policy_filter: Dict[str, Any]) -> Dict[str, Any]:
    """Echo back only the filters actually applied, for a readable response."""
    applied = {
        key: value
        for key, value in policy_filter.items()
        if value and key not in ("name", "tldr")
    }
    search_terms = (policy_filter.get("name") or {}).get("regex") or []
    if search_terms:
        applied["search_patterns"] = search_terms
    return applied


async def list_policies_tool(
    client,
    cwpp_base_url: str,
    tenant_id: Optional[str] = None,
    page: int = 1,
    page_size: int = 20,
    category: Optional[str] = None,
    cluster_ids: Any = None,
    namespace_ids: Any = None,
    workload_ids: Any = None,
    kinds: Any = None,
    statuses: Any = None,
    tags: Any = None,
    search: Optional[str] = None,
    tag_regex: Optional[str] = None,
    detailed: bool = False,
    display_fields: Any = None,
    include_endpoint: bool = False,
) -> dict:
    """List policies (POST /policymanagement/v2/list-policy)."""

    try:
        error = require_tenant(tenant_id)
        if error:
            return error

        policy_filter, error = _build_filter(
            cluster_ids,
            namespace_ids,
            workload_ids,
            kinds,
            statuses,
            tags,
            search,
            tag_regex,
        )
        if error:
            return error

        category_list, error = resolve_enum_list(
            split_list(category),
            POLICY_CATEGORIES,
            "category",
        )
        if error:
            return error

        page = max(1, int(page or 1))
        page_size = max(1, min(int(page_size or 20), 100))
        page_previous, page_next = offset_range(page, page_size)

        # list-policy nests the filter and adds three fields policy-count drops.
        nested_filter = dict(policy_filter)
        nested_filter["type"] = category_list
        nested_filter["node_id"] = []
        nested_filter["pod_id"] = []

        payload: Dict[str, Any] = {
            "workspace_id": workspace_id(tenant_id),
            "workload": POLICY_WORKLOAD,
            "page_previous": page_previous,
            "page_next": page_next,
            "filter": nested_filter,
        }

        response = await client.fetch_policies(
            cwpp_base_url=cwpp_base_url,
            payload=payload,
            tenant_id=tenant_id,
            include_endpoint=include_endpoint,
        )
        if _is_error(response):
            return response

        endpoint_info = response.pop("endpoint_info", None) if isinstance(response, dict) else None

        if isinstance(response, dict):
            rows = response.get("list_of_policies") or []
        elif isinstance(response, list):
            rows = response
        else:
            rows = []

        selected_fields = split_list(display_fields)
        if not detailed and not selected_fields:
            selected_fields = DEFAULT_POLICY_FIELDS
        shaped = [project_row(row, None if detailed else selected_fields) for row in rows]

        result: Dict[str, Any] = {
            "category": category_list or "All",
            "page": page,
            "page_size": page_size,
            "offset_range": {"page_previous": page_previous, "page_next": page_next},
            "returned": len(shaped),
            "filters": _filter_info(policy_filter),
            "results": shaped,
        }
        if not detailed and selected_fields:
            result["display_fields"] = selected_fields
            result["note"] = (
                "Truncated projection — pass detailed=True for every policy field. "
                "Use count_policies for the total across pages."
            )
        if endpoint_info:
            result["endpoint_info"] = endpoint_info
        return result

    except httpx.HTTPStatusError as e:
        return {"error": f"API Error: {e.response.status_code}"}
    except Exception as e:
        logger.exception("list_policies failed")
        return {"error": f"Error: {str(e)}"}


async def count_policies_tool(
    client,
    cwpp_base_url: str,
    tenant_id: Optional[str] = None,
    cluster_ids: Any = None,
    namespace_ids: Any = None,
    workload_ids: Any = None,
    kinds: Any = None,
    statuses: Any = None,
    tags: Any = None,
    search: Optional[str] = None,
    tag_regex: Optional[str] = None,
    include_endpoint: bool = False,
) -> dict:
    """Count policies per category (POST /policymanagement/v2/policy-count).

    Note the payload asymmetry: the same filter vocabulary is sent FLAT here,
    without workspace_id, paging, type, node_id or pod_id.
    """

    try:
        error = require_tenant(tenant_id)
        if error:
            return error

        policy_filter, error = _build_filter(
            cluster_ids,
            namespace_ids,
            workload_ids,
            kinds,
            statuses,
            tags,
            search,
            tag_regex,
        )
        if error:
            return error

        payload: Dict[str, Any] = {"workload": POLICY_WORKLOAD, **policy_filter}

        response = await client.fetch_policy_count(
            cwpp_base_url=cwpp_base_url,
            payload=payload,
            tenant_id=tenant_id,
            include_endpoint=include_endpoint,
        )
        if _is_error(response):
            return response

        endpoint_info = response.pop("endpoint_info", None) if isinstance(response, dict) else None
        counts = response if isinstance(response, dict) else {}

        result: Dict[str, Any] = {
            "total_count": counts.get("total_count", 0),
            "discovered_count": counts.get("discovered_count", 0),
            "hardening_count": counts.get("hardening_count", 0),
            "custom_count": counts.get("custom_count", 0),
            "filters": _filter_info(policy_filter),
        }
        if endpoint_info:
            result["endpoint_info"] = endpoint_info
        return result

    except httpx.HTTPStatusError as e:
        return {"error": f"API Error: {e.response.status_code}"}
    except Exception as e:
        logger.exception("count_policies failed")
        return {"error": f"Error: {str(e)}"}


async def get_policy_details_tool(
    client,
    cwpp_base_url: str,
    policy_id: Any,
    tenant_id: Optional[str] = None,
    include_endpoint: bool = False,
) -> dict:
    """Fetch one policy in full (GET /policymanagement/v2/policy/{policy_id})."""

    try:
        # Tenant is doubly important here: this endpoint carries no workspace_id,
        # so X-Tenant-Id is the only thing scoping the lookup.
        error = require_tenant(tenant_id)
        if error:
            return error

        identifier = str(policy_id).strip() if policy_id is not None else ""
        if not identifier:
            return {
                "error": "`policy_id` is required.",
                "hint": "Use the policy_id from a list_policies row.",
            }

        # The id lands directly in the path, so encode it rather than trusting it.
        response = await client.fetch_policy_details(
            cwpp_base_url=cwpp_base_url,
            policy_id=quote(identifier, safe=""),
            tenant_id=tenant_id,
            include_endpoint=include_endpoint,
        )
        if _is_error(response):
            return response

        endpoint_info = response.pop("endpoint_info", None) if isinstance(response, dict) else None

        result: Dict[str, Any] = {"policy_id": identifier, "policy": response}
        if endpoint_info:
            result["endpoint_info"] = endpoint_info
        return result

    except httpx.HTTPStatusError as e:
        return {"error": f"API Error: {e.response.status_code}"}
    except Exception as e:
        logger.exception("get_policy_details failed")
        return {"error": f"Error: {str(e)}"}


async def get_policy_alert_counts_tool(
    client,
    cwpp_base_url: str,
    policies: Any,
    tenant_id: Optional[str] = None,
    cluster_ids: Any = None,
    namespaces: Any = None,
    workload_types: Any = None,
    workload_names: Any = None,
    period: Optional[str] = None,
    from_time: Optional[Any] = None,
    to_time: Optional[Any] = None,
    log_type: str = "active",
    include_endpoint: bool = False,
) -> dict:
    """Per-policy alert counts (POST /datapipeline/v3/alerts/kubearmor/actions/count).

    One request covers every policy passed in. Cluster-scoped policies are rolled
    up across namespaces here, so the caller gets one flat count map per policy.
    """

    try:
        error = require_tenant(tenant_id)
        if error:
            return error

        policy_list, error = normalize_policies(policies)
        if error:
            return error
        if not policy_list:
            return {"error": "`policies` is empty — nothing to count."}
        if len(policy_list) > MAX_POLICIES_PER_ALERT_COUNT:
            return {
                "error": f"Too many policies ({len(policy_list)}); the maximum is "
                         f"{MAX_POLICIES_PER_ALERT_COUNT} per request.",
                "hint": "Call this once per page of list_policies.",
            }

        # Default to the UI's "all time" start rather than the usual 24h window.
        from_ts, to_ts, error = resolve_time_range(
            period=period,
            from_time=from_time,
            to_time=to_time,
            default_from=POLICY_ALERTS_DEFAULT_FROM,
        )
        if error:
            return error

        # Scope defaults to whatever the policies themselves reference.
        cluster_id_list = split_list(cluster_ids) or list(
            dict.fromkeys(p["cluster_id"] for p in policy_list if p["cluster_id"]),
        )
        namespace_list = split_list(namespaces) or list(
            dict.fromkeys(p["namespace"] for p in policy_list if p["namespace"]),
        )

        payload: Dict[str, Any] = {
            "ClusterID": cluster_id_list,
            "Namespace": namespace_list,
            "WorkloadType": list(dict.fromkeys(split_list(workload_types))),
            "WorkloadName": list(dict.fromkeys(split_list(workload_names))),
            "Filters": [build_alert_filter_entry(policy) for policy in policy_list],
            "FromTime": from_ts,
            "ToTime": to_ts,
            "LogType": log_type,
        }

        response = await client.fetch_policy_alert_counts(
            cwpp_base_url=cwpp_base_url,
            payload=payload,
            tenant_id=tenant_id,
            include_endpoint=include_endpoint,
        )
        if _is_error(response):
            return response

        endpoint_info = response.pop("endpoint_info", None) if isinstance(response, dict) else None

        rows = (((response or {}).get("response") or {}).get("PolicyCount") or []) \
            if isinstance(response, dict) else []

        # Kind drives the roll-up key, and only the request knows it.
        kind_by_policy = {
            (policy["cluster_id"], policy["name"]): policy.get("policy_kind", "")
            for policy in policy_list
        }

        counts_by_key: Dict[str, Dict[str, int]] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            name = row.get("policyName") or row.get("PolicyName") or ""
            cluster = str(row.get("cluster_id") or row.get("ClusterID") or "")
            namespace = row.get("namespace") or row.get("Namespace") or ""
            kind = kind_by_policy.get((cluster, name), "")

            bucket = counts_by_key.setdefault(policy_key(cluster, namespace, name, kind), {})
            for alert_type, count in sum_alert_counts(row.get("Alerts")).items():
                bucket[alert_type] = bucket.get(alert_type, 0) + count

        results: List[Dict[str, Any]] = []
        for policy in policy_list:
            key = policy_key(
                policy["cluster_id"],
                policy["namespace"],
                policy["name"],
                policy.get("policy_kind", ""),
            )
            counts = counts_by_key.get(key, {})
            entry: Dict[str, Any] = {
                "name": policy["name"],
                "cluster_id": policy["cluster_id"],
                "namespace": policy["namespace"],
                "policy_kind": policy.get("policy_kind") or None,
                "total_alerts": sum(counts.values()),
                "alerts": counts,
            }
            if policy.get("policy_id") is not None:
                entry["policy_id"] = policy["policy_id"]
            if policy.get("cluster_name"):
                entry["cluster_name"] = policy["cluster_name"]
            results.append(entry)

        results.sort(key=lambda item: item["total_alerts"], reverse=True)

        result: Dict[str, Any] = {
            "time_range": time_range_info(from_ts, to_ts),
            "log_type": log_type,
            "policies": len(results),
            "total_alerts": sum(item["total_alerts"] for item in results),
            "alert_types": list(POLICY_ALERT_TYPES),
            "results": results,
        }
        if endpoint_info:
            result["endpoint_info"] = endpoint_info
        return result

    except httpx.HTTPStatusError as e:
        return {"error": f"API Error: {e.response.status_code}"}
    except Exception as e:
        logger.exception("get_policy_alert_counts failed")
        return {"error": f"Error: {str(e)}"}


def list_policy_options_tool() -> dict:
    """Static catalogue of the policy enums and fields."""
    return {
        "kinds": list(POLICY_KINDS),
        "statuses": list(POLICY_STATUSES),
        "categories": list(POLICY_CATEGORIES),
        "category_note": "Omit `category` for All.",
        "alert_types": list(POLICY_ALERT_TYPES),
        "policy_fields": ALL_POLICY_FIELDS,
        "default_fields": DEFAULT_POLICY_FIELDS,
        "id_note": (
            "cluster_ids / namespace_ids / workload_ids are numeric IDs here, "
            "unlike the alerts tools which take namespace names."
        ),
    }
