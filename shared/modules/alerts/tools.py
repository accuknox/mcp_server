"""
Alerts module — tool implementations.

Covers CWPP alerts: filter-key discovery, filter-value discovery, paged queries,
counts, bulk export, plus two widget-oriented aggregations (breakdown & trend)
built on top of the count endpoint.
"""

import asyncio
import math
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx

from logging_config import logger
from shared.utils.scope import require_tenant, workspace_id

from .constants import (
    AGGREGATE_DISPLAY_FIELDS,
    ALERT_COMPONENTS,
    DEFAULT_COMPONENT,
    DEFAULT_DISPLAY_FIELDS,
    DEFAULT_LOG_TYPE,
    DEFAULT_VIEW,
    LOG_TYPES,
    SEVERITY_BUCKETS,
    SORT_ORDERS,
    SUGGESTED_GROUP_BY,
    VIEW_TYPES,
    fields_component,
    resolve_component,
    resolve_tool,
)
from .utils import (
    flatten_values,
    iso,
    normalize_filters,
    parse_duration,
    project_row,
    resolve_time_range,
    severity_bucket_filters,
    split_list,
    time_range_info,
)

# Cache of valid filter keys per (base_url, tenant, component, tool) so that
# filter validation does not cost an extra round-trip on every query.
_FIELD_KEYS_CACHE: Dict[Tuple[Any, ...], Tuple[float, List[str]]] = {}
_FIELD_KEYS_TTL_SECONDS = 300

# Bounds for the fan-out widget tools (each bucket costs one count request).
MAX_BREAKDOWN_BUCKETS = 15
MAX_TREND_BUCKETS = 24
_MAX_CONCURRENCY = 6


# ---------------------------------------------------------------------------
# Shared plumbing
# ---------------------------------------------------------------------------


def _is_error(response: Any) -> bool:
    return isinstance(response, dict) and "error" in response


# Tenant helpers live in shared.utils.scope — the CWPP APIs all need the tenant in
# both the header and the body.
_workspace_id = workspace_id
_require_tenant = require_tenant


class _Scope:
    """Validated, API-ready request scope shared by every alerts tool."""

    def __init__(
        self,
        component: str,
        tool: Optional[str],
        from_ts: int,
        to_ts: int,
        cluster_ids: List[str],
        namespaces: List[str],
        workload_types: List[str],
        workload_names: List[str],
        filters: List[Dict[str, Any]],
        search: str,
        tenant_id: Optional[str],
    ):
        self.component = component
        self.tool = tool
        self.from_ts = from_ts
        self.to_ts = to_ts
        self.cluster_ids = cluster_ids
        self.namespaces = namespaces
        self.workload_types = workload_types
        self.workload_names = workload_names
        self.filters = filters
        self.search = search
        self.tenant_id = tenant_id

    def base_payload(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "WorkspaceID": _workspace_id(self.tenant_id),
            "Type": self.component,
            "FromTime": self.from_ts,
            "ToTime": self.to_ts,
            "ClusterID": self.cluster_ids,
            "Namespace": self.namespaces,
            "WorkloadType": self.workload_types,
            "WorkloadName": self.workload_names,
            "Filters": self.filters,
            "Search": self.search,
        }
        if self.tool:
            payload["Tool"] = self.tool
        return payload

    def events_payload(
        self,
        view: str,
        log_type: str,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        filters: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        payload = self.base_payload()
        payload["View"] = view
        payload["LogType"] = log_type
        if filters is not None:
            payload["Filters"] = filters
        if page is not None:
            payload["PageId"] = page
        if page_size is not None:
            payload["PageSize"] = page_size
        return payload

    def info(self) -> Dict[str, Any]:
        details: Dict[str, Any] = {
            "component": self.component,
            "component_label": ALERT_COMPONENTS[self.component]["label"],
            "time_range": time_range_info(self.from_ts, self.to_ts),
        }
        if self.tool:
            details["tool"] = self.tool
        if self.cluster_ids:
            details["cluster_ids"] = self.cluster_ids
        if self.namespaces:
            details["namespaces"] = self.namespaces
        if self.filters:
            details["filters"] = self.filters
        if self.search:
            details["search"] = self.search
        return details


def _build_scope(
    component: Optional[str],
    tool: Optional[str],
    tenant_id: Optional[str],
    period: Optional[str] = None,
    from_time: Optional[Any] = None,
    to_time: Optional[Any] = None,
    cluster_ids: Any = None,
    namespaces: Any = None,
    workload_types: Any = None,
    workload_names: Any = None,
    filters: Any = None,
    search: Optional[str] = None,
) -> Tuple[Optional[_Scope], Optional[dict]]:
    """Validate every shared input once. Returns (scope, error_dict)."""

    error = _require_tenant(tenant_id)
    if error:
        return None, error

    canonical, error = resolve_component(component)
    if error:
        return None, error

    resolved_tool, error = resolve_tool(canonical, tool)
    if error:
        return None, error

    from_ts, to_ts, error = resolve_time_range(period, from_time, to_time)
    if error:
        return None, error

    wire_filters, error = normalize_filters(filters)
    if error:
        return None, error

    workload_type_list = split_list(workload_types)
    workload_name_list = split_list(workload_names)
    if workload_type_list and workload_name_list and len(workload_type_list) != len(workload_name_list):
        return None, {
            "error": "workload_types and workload_names are positionally paired and must have the same length.",
            "workload_types": workload_type_list,
            "workload_names": workload_name_list,
        }

    scope = _Scope(
        component=canonical,
        tool=resolved_tool,
        from_ts=from_ts,
        to_ts=to_ts,
        cluster_ids=split_list(cluster_ids),
        namespaces=split_list(namespaces),
        workload_types=workload_type_list,
        workload_names=workload_name_list,
        filters=wire_filters,
        search=(search or "").strip(),
        tenant_id=tenant_id,
    )
    return scope, None


def _validate_choice(
    value: Optional[str],
    allowed: Tuple[str, ...],
    name: str,
    default: str,
    lower: bool = False,
) -> Tuple[Optional[str], Optional[dict]]:
    if not value:
        return default, None
    candidate = str(value).strip()
    for option in allowed:
        if option.lower() == candidate.lower():
            return option.lower() if lower else option, None
    return None, {
        "error": f"'{value}' is not a valid {name}.",
        "valid_values": list(allowed),
    }


# ---------------------------------------------------------------------------
# Fields (discovery)
# ---------------------------------------------------------------------------


async def _fetch_field_keys(
    client,
    cwpp_base_url: str,
    scope: _Scope,
    include_endpoint: bool = False,
) -> Tuple[List[str], Optional[dict], Optional[dict]]:
    """Fetch the valid filter keys for a component. Returns (keys, endpoint_info, error)."""

    payload: Dict[str, Any] = {
        "WorkspaceID": _workspace_id(scope.tenant_id),
        "Component": fields_component(scope.component),
        "Type": "key",
        "ClusterID": scope.cluster_ids,
        "Namespace": scope.namespaces,
        "WorkloadType": scope.workload_types,
        "WorkloadName": scope.workload_names,
        "FromTime": scope.from_ts,
        "ToTime": scope.to_ts,
    }
    if scope.tool:
        payload["Tool"] = scope.tool

    response = await client.fetch_alert_fields(
        cwpp_base_url=cwpp_base_url,
        payload=payload,
        tenant_id=scope.tenant_id,
        include_endpoint=include_endpoint,
    )
    if _is_error(response):
        return [], None, response
    if not isinstance(response, dict):
        return [], None, {"error": f"Unexpected /alerts/fields response for '{scope.component}'."}

    endpoint_info = response.pop("endpoint_info", None)
    keys = (response.get("fields") or {}).get("keys") or []
    return [str(key) for key in keys], endpoint_info, None


async def _cached_field_keys(client, cwpp_base_url: str, scope: _Scope) -> List[str]:
    """Field keys with a short TTL cache; returns [] when discovery fails."""
    cache_key = (cwpp_base_url, scope.tenant_id, scope.component, scope.tool)
    cached = _FIELD_KEYS_CACHE.get(cache_key)
    if cached and cached[0] > time.time():
        return cached[1]

    keys, _, error = await _fetch_field_keys(client, cwpp_base_url, scope)
    if error or not keys:
        # Fail open: validation is a convenience, not a gate.
        logger.info(f"Alert field-key discovery unavailable for {scope.component}: {error}")
        return []

    _FIELD_KEYS_CACHE[cache_key] = (time.time() + _FIELD_KEYS_TTL_SECONDS, keys)
    return keys


async def _validate_filter_fields(
    client,
    cwpp_base_url: str,
    scope: _Scope,
) -> Optional[dict]:
    """Reject filters whose field is not a known key for this component."""
    if not scope.filters:
        return None

    keys = await _cached_field_keys(client, cwpp_base_url, scope)
    if not keys:
        return None

    lookup = {key.lower(): key for key in keys}
    unknown = []
    for entry in scope.filters:
        field = entry["field"]
        if field in keys:
            continue
        corrected = lookup.get(field.lower())
        if corrected:
            entry["field"] = corrected  # forgive casing differences
            continue
        unknown.append(field)

    if unknown:
        return {
            "error": f"Unknown filter field(s) for component '{scope.component}': {sorted(set(unknown))}.",
            "valid_fields": keys,
            "hint": "Call list_alert_fields() for this component to see valid filter fields.",
        }
    return None


async def list_alert_fields_tool(
    client,
    cwpp_base_url: str,
    tenant_id: Optional[str] = None,
    component: Optional[str] = None,
    tool: Optional[str] = None,
    period: Optional[str] = None,
    from_time: Optional[Any] = None,
    to_time: Optional[Any] = None,
    cluster_ids: Any = None,
    namespaces: Any = None,
    workload_types: Any = None,
    workload_names: Any = None,
    include_endpoint: bool = False,
) -> dict:
    """List the filter keys available for a component (POST /alerts/fields, Type=key)."""

    try:
        scope, error = _build_scope(
            component=component,
            tool=tool,
            tenant_id=tenant_id,
            period=period,
            from_time=from_time,
            to_time=to_time,
            cluster_ids=cluster_ids,
            namespaces=namespaces,
            workload_types=workload_types,
            workload_names=workload_names,
        )
        if error:
            return error

        keys, endpoint_info, error = await _fetch_field_keys(
            client,
            cwpp_base_url,
            scope,
            include_endpoint=include_endpoint,
        )
        if error:
            return error

        _FIELD_KEYS_CACHE[(cwpp_base_url, scope.tenant_id, scope.component, scope.tool)] = (
            time.time() + _FIELD_KEYS_TTL_SECONDS,
            keys,
        )

        result: Dict[str, Any] = {
            **scope.info(),
            "count": len(keys),
            "fields": keys,
            "suggested_group_by": SUGGESTED_GROUP_BY.get(scope.component, []),
        }
        if endpoint_info:
            result["endpoint_info"] = endpoint_info
        return result

    except httpx.HTTPStatusError as e:
        return {"error": f"API Error: {e.response.status_code}"}
    except Exception as e:
        logger.exception("list_alert_fields failed")
        return {"error": f"Error: {str(e)}"}


async def get_alert_field_values_tool(
    client,
    cwpp_base_url: str,
    field: str,
    tenant_id: Optional[str] = None,
    component: Optional[str] = None,
    tool: Optional[str] = None,
    period: Optional[str] = None,
    from_time: Optional[Any] = None,
    to_time: Optional[Any] = None,
    cluster_ids: Any = None,
    namespaces: Any = None,
    max_values: int = 25,
    page_size: int = 5,
    include_endpoint: bool = False,
) -> dict:
    """List observed values for one filter field (POST /alerts/fields, Type=value).

    The endpoint pages 5 values at a time by default; this walks pages until
    `max_values` is reached or a short page signals the end.
    """

    try:
        if not field:
            return {"error": "`field` is required.", "hint": "Call list_alert_fields() first."}

        scope, error = _build_scope(
            component=component,
            tool=tool,
            tenant_id=tenant_id,
            period=period,
            from_time=from_time,
            to_time=to_time,
            cluster_ids=cluster_ids,
            namespaces=namespaces,
        )
        if error:
            return error

        # Severity values are a fixed 1..10 scale — no round-trip needed.
        if field.lower() == "severity":
            return {
                **scope.info(),
                "field": "Severity",
                "count": 10,
                "values": [str(i) for i in range(1, 11)],
                "severity_buckets": SEVERITY_BUCKETS,
                "note": "Severity accepts op='match' only. Filter values may also be given as names (critical/high/medium/low/informational).",
            }

        keys = await _cached_field_keys(client, cwpp_base_url, scope)
        if keys and field not in keys:
            match = next((key for key in keys if key.lower() == field.lower()), None)
            if not match:
                return {
                    "error": f"'{field}' is not a valid filter field for component '{scope.component}'.",
                    "valid_fields": keys,
                }
            field = match

        page_size = max(1, min(int(page_size or 5), 50))
        max_values = max(1, min(int(max_values or 25), 200))

        values: List[Any] = []
        endpoint_info = None
        page = 1
        while len(values) < max_values and page <= 40:
            payload: Dict[str, Any] = {
                "WorkspaceID": _workspace_id(scope.tenant_id),
                "Component": fields_component(scope.component),
                "Type": "value",
                "ClusterID": scope.cluster_ids,
                "FromTime": scope.from_ts,
                "ToTime": scope.to_ts,
                "Query": [field],
                "PageId": page,
                "PageSize": page_size,
            }
            # The value path takes a single namespace string (FE quirk), unlike
            # every other endpoint which takes an array.
            if scope.namespaces:
                payload["Namespace"] = scope.namespaces[0]
            if scope.tool:
                payload["Tool"] = scope.tool

            response = await client.fetch_alert_fields(
                cwpp_base_url=cwpp_base_url,
                payload=payload,
                tenant_id=scope.tenant_id,
                include_endpoint=include_endpoint and page == 1,
            )
            if _is_error(response):
                return response
            if not isinstance(response, dict):
                return {"error": f"Unexpected /alerts/fields response for field '{field}'."}

            if endpoint_info is None:
                endpoint_info = response.pop("endpoint_info", None)

            raw = ((response.get("fields") or {}).get("values") or {}).get(field, [])
            page_values = flatten_values(raw)
            if not page_values:
                break

            values.extend(page_values)
            if len(page_values) < page_size:
                break
            page += 1

        # de-duplicate across pages, preserve order
        seen = set()
        unique: List[Any] = []
        for value in values:
            marker = (type(value).__name__, str(value))
            if marker not in seen:
                seen.add(marker)
                unique.append(value)
        unique = unique[:max_values]

        result: Dict[str, Any] = {
            **scope.info(),
            "field": field,
            "count": len(unique),
            "values": unique,
        }
        if endpoint_info:
            result["endpoint_info"] = endpoint_info
        return result

    except httpx.HTTPStatusError as e:
        return {"error": f"API Error: {e.response.status_code}"}
    except Exception as e:
        logger.exception("get_alert_field_values failed")
        return {"error": f"Error: {str(e)}"}


# ---------------------------------------------------------------------------
# Events + count
# ---------------------------------------------------------------------------


def _extract_rows(response: Any) -> List[Any]:
    if isinstance(response, dict):
        rows = response.get("response")
        if rows is None:
            rows = response.get("data")
        return rows or []
    if isinstance(response, list):
        return response
    return []


def _extract_count(response: Any) -> Optional[int]:
    if isinstance(response, dict):
        for key in ("count", "Count", "total"):
            if key in response and isinstance(response[key], (int, float)):
                return int(response[key])
    return None


async def query_alerts_tool(
    client,
    cwpp_base_url: str,
    tenant_id: Optional[str] = None,
    component: Optional[str] = None,
    view: Optional[str] = None,
    log_type: Optional[str] = None,
    tool: Optional[str] = None,
    period: Optional[str] = None,
    from_time: Optional[Any] = None,
    to_time: Optional[Any] = None,
    cluster_ids: Any = None,
    namespaces: Any = None,
    workload_types: Any = None,
    workload_names: Any = None,
    filters: Any = None,
    search: Optional[str] = None,
    page: int = 1,
    page_size: int = 20,
    order_by: Optional[str] = None,
    order_field: Optional[str] = None,
    detailed: bool = False,
    display_fields: Any = None,
    include_total: bool = False,
    include_endpoint: bool = False,
) -> dict:
    """Fetch a page of alerts (POST /monitors/v1/alerts/events)."""

    try:
        scope, error = _build_scope(
            component=component,
            tool=tool,
            tenant_id=tenant_id,
            period=period,
            from_time=from_time,
            to_time=to_time,
            cluster_ids=cluster_ids,
            namespaces=namespaces,
            workload_types=workload_types,
            workload_names=workload_names,
            filters=filters,
            search=search,
        )
        if error:
            return error

        view, error = _validate_choice(view, VIEW_TYPES, "view", DEFAULT_VIEW)
        if error:
            return error
        log_type, error = _validate_choice(log_type, LOG_TYPES, "log_type", DEFAULT_LOG_TYPE, lower=True)
        if error:
            return error
        if order_by:
            order_by, error = _validate_choice(order_by, SORT_ORDERS, "order_by", "desc", lower=True)
            if error:
                return error

        error = await _validate_filter_fields(client, cwpp_base_url, scope)
        if error:
            return error

        page = max(1, int(page or 1))
        page_size = max(1, min(int(page_size or 20), 100))

        payload = scope.events_payload(view=view, log_type=log_type, page=page, page_size=page_size)

        response = await client.fetch_alert_events(
            cwpp_base_url=cwpp_base_url,
            payload=payload,
            tenant_id=scope.tenant_id,
            order_by=order_by,
            order_field=order_field,
            include_endpoint=include_endpoint,
        )
        if _is_error(response):
            return response

        endpoint_info = response.pop("endpoint_info", None) if isinstance(response, dict) else None
        rows = _extract_rows(response)

        selected_fields = split_list(display_fields)
        if not detailed and not selected_fields:
            selected_fields = (
                AGGREGATE_DISPLAY_FIELDS
                if view == "Aggregate"
                else DEFAULT_DISPLAY_FIELDS.get(scope.component, [])
            )
        shaped = [project_row(row, None if detailed else selected_fields) for row in rows]

        result: Dict[str, Any] = {
            **scope.info(),
            "view": view,
            "log_type": log_type,
            "page": page,
            "page_size": page_size,
            "returned": len(shaped),
            "results": shaped,
        }
        if not detailed and selected_fields:
            result["display_fields"] = selected_fields
            result["note"] = "Truncated projection — pass detailed=True for every field on each alert."

        if include_total:
            count_payload = scope.events_payload(view=view, log_type=log_type)
            count_response = await client.fetch_alert_events_count(
                cwpp_base_url=cwpp_base_url,
                payload=count_payload,
                tenant_id=scope.tenant_id,
            )
            total = _extract_count(count_response)
            if total is not None:
                result["total"] = total
                result["total_pages"] = math.ceil(total / page_size) if page_size else None

        if endpoint_info:
            result["endpoint_info"] = endpoint_info
        return result

    except httpx.HTTPStatusError as e:
        return {"error": f"API Error: {e.response.status_code}"}
    except Exception as e:
        logger.exception("query_alerts failed")
        return {"error": f"Error: {str(e)}"}


async def count_alerts_tool(
    client,
    cwpp_base_url: str,
    tenant_id: Optional[str] = None,
    component: Optional[str] = None,
    view: Optional[str] = None,
    log_type: Optional[str] = None,
    tool: Optional[str] = None,
    period: Optional[str] = None,
    from_time: Optional[Any] = None,
    to_time: Optional[Any] = None,
    cluster_ids: Any = None,
    namespaces: Any = None,
    workload_types: Any = None,
    workload_names: Any = None,
    filters: Any = None,
    search: Optional[str] = None,
    tags_filter: Optional[dict] = None,
    include_endpoint: bool = False,
) -> dict:
    """Count matching alerts (POST /monitors/v1/alerts/events/count)."""

    try:
        scope, error = _build_scope(
            component=component,
            tool=tool,
            tenant_id=tenant_id,
            period=period,
            from_time=from_time,
            to_time=to_time,
            cluster_ids=cluster_ids,
            namespaces=namespaces,
            workload_types=workload_types,
            workload_names=workload_names,
            filters=filters,
            search=search,
        )
        if error:
            return error

        view, error = _validate_choice(view, VIEW_TYPES, "view", DEFAULT_VIEW)
        if error:
            return error
        log_type, error = _validate_choice(log_type, LOG_TYPES, "log_type", DEFAULT_LOG_TYPE, lower=True)
        if error:
            return error

        error = await _validate_filter_fields(client, cwpp_base_url, scope)
        if error:
            return error

        payload = scope.events_payload(view=view, log_type=log_type)
        if tags_filter:
            payload["TagsFilter"] = tags_filter

        response = await client.fetch_alert_events_count(
            cwpp_base_url=cwpp_base_url,
            payload=payload,
            tenant_id=scope.tenant_id,
            include_endpoint=include_endpoint,
        )
        if _is_error(response):
            return response

        endpoint_info = response.pop("endpoint_info", None) if isinstance(response, dict) else None

        result: Dict[str, Any] = {
            **scope.info(),
            "view": view,
            "log_type": log_type,
            "count": _extract_count(response) or 0,
        }
        if endpoint_info:
            result["endpoint_info"] = endpoint_info
        return result

    except httpx.HTTPStatusError as e:
        return {"error": f"API Error: {e.response.status_code}"}
    except Exception as e:
        logger.exception("count_alerts failed")
        return {"error": f"Error: {str(e)}"}


# ---------------------------------------------------------------------------
# Widgets (breakdown + trend), built on the count endpoint
# ---------------------------------------------------------------------------


async def _count_for(
    client,
    cwpp_base_url: str,
    scope: _Scope,
    view: str,
    log_type: str,
    filters: List[Dict[str, Any]],
    from_ts: Optional[int] = None,
    to_ts: Optional[int] = None,
    semaphore: Optional[asyncio.Semaphore] = None,
) -> Optional[int]:
    payload = scope.events_payload(view=view, log_type=log_type, filters=filters)
    if from_ts is not None:
        payload["FromTime"] = from_ts
    if to_ts is not None:
        payload["ToTime"] = to_ts

    async def _run() -> Optional[int]:
        response = await client.fetch_alert_events_count(
            cwpp_base_url=cwpp_base_url,
            payload=payload,
            tenant_id=scope.tenant_id,
        )
        if _is_error(response):
            logger.warning(f"count fan-out failed: {response.get('error')}")
            return None
        return _extract_count(response)

    if semaphore is None:
        return await _run()
    async with semaphore:
        return await _run()


async def get_alert_breakdown_tool(
    client,
    cwpp_base_url: str,
    group_by: str,
    tenant_id: Optional[str] = None,
    component: Optional[str] = None,
    tool: Optional[str] = None,
    log_type: Optional[str] = None,
    period: Optional[str] = None,
    from_time: Optional[Any] = None,
    to_time: Optional[Any] = None,
    cluster_ids: Any = None,
    namespaces: Any = None,
    workload_types: Any = None,
    workload_names: Any = None,
    filters: Any = None,
    search: Optional[str] = None,
    top_n: int = 8,
) -> dict:
    """Widget data: alert counts grouped by one field (pie / bar / stat tiles).

    The alerts API has no group-by, so this discovers the field's values and
    issues one count request per value (bounded fan-out), plus one for the total.
    """

    try:
        if not group_by:
            return {"error": "`group_by` is required.", "hint": "e.g. Severity, Operation, ClusterName, Action"}

        scope, error = _build_scope(
            component=component,
            tool=tool,
            tenant_id=tenant_id,
            period=period,
            from_time=from_time,
            to_time=to_time,
            cluster_ids=cluster_ids,
            namespaces=namespaces,
            workload_types=workload_types,
            workload_names=workload_names,
            filters=filters,
            search=search,
        )
        if error:
            return error

        log_type, error = _validate_choice(log_type, LOG_TYPES, "log_type", DEFAULT_LOG_TYPE, lower=True)
        if error:
            return error

        error = await _validate_filter_fields(client, cwpp_base_url, scope)
        if error:
            return error

        top_n = max(1, min(int(top_n or 8), MAX_BREAKDOWN_BUCKETS))

        # Build the buckets: severity gets its 5 named bands, everything else
        # uses the field's observed values.
        if group_by.lower() == "severity":
            buckets = [
                {"label": name, "values": values, "filters": severity_bucket_filters(name)}
                for name, values in SEVERITY_BUCKETS.items()
            ]
            group_by = "Severity"
        else:
            values_result = await get_alert_field_values_tool(
                client,
                cwpp_base_url=cwpp_base_url,
                field=group_by,
                tenant_id=tenant_id,
                component=scope.component,
                tool=scope.tool,
                from_time=scope.from_ts,
                to_time=scope.to_ts,
                cluster_ids=scope.cluster_ids,
                namespaces=scope.namespaces,
                max_values=top_n,
                page_size=min(top_n, 25),
            )
            if _is_error(values_result):
                return values_result

            group_by = values_result.get("field", group_by)
            buckets = [
                {
                    "label": str(value),
                    "values": [str(value)],
                    "filters": [{"field": group_by, "value": str(value), "op": "match"}],
                }
                for value in values_result.get("values", [])
            ][:top_n]

            if not buckets:
                return {
                    **scope.info(),
                    "widget": "breakdown",
                    "group_by": group_by,
                    "total": 0,
                    "buckets": [],
                    "note": f"No values observed for '{group_by}' in this time range.",
                }

        semaphore = asyncio.Semaphore(_MAX_CONCURRENCY)
        total_task = _count_for(
            client,
            cwpp_base_url,
            scope,
            DEFAULT_VIEW,
            log_type,
            scope.filters,
            semaphore=semaphore,
        )
        bucket_tasks = [
            _count_for(
                client,
                cwpp_base_url,
                scope,
                DEFAULT_VIEW,
                log_type,
                scope.filters + bucket["filters"],
                semaphore=semaphore,
            )
            for bucket in buckets
        ]
        counts = await asyncio.gather(total_task, *bucket_tasks)
        total = counts[0] or 0

        rows = []
        for bucket, count in zip(buckets, counts[1:]):
            count = count or 0
            rows.append(
                {
                    "label": bucket["label"],
                    "values": bucket["values"],
                    "count": count,
                    "percentage": round(count * 100 / total, 2) if total else 0,
                },
            )
        rows.sort(key=lambda row: row["count"], reverse=True)

        return {
            **scope.info(),
            "widget": "breakdown",
            "log_type": log_type,
            "group_by": group_by,
            "total": total,
            "buckets": rows,
        }

    except httpx.HTTPStatusError as e:
        return {"error": f"API Error: {e.response.status_code}"}
    except Exception as e:
        logger.exception("get_alert_breakdown failed")
        return {"error": f"Error: {str(e)}"}


async def get_alert_trend_tool(
    client,
    cwpp_base_url: str,
    tenant_id: Optional[str] = None,
    component: Optional[str] = None,
    tool: Optional[str] = None,
    log_type: Optional[str] = None,
    period: Optional[str] = None,
    from_time: Optional[Any] = None,
    to_time: Optional[Any] = None,
    interval: Optional[str] = None,
    buckets: int = 12,
    cluster_ids: Any = None,
    namespaces: Any = None,
    workload_types: Any = None,
    workload_names: Any = None,
    filters: Any = None,
    search: Optional[str] = None,
) -> dict:
    """Widget data: alert counts bucketed over time (line / area / bar chart)."""

    try:
        scope, error = _build_scope(
            component=component,
            tool=tool,
            tenant_id=tenant_id,
            period=period,
            from_time=from_time,
            to_time=to_time,
            cluster_ids=cluster_ids,
            namespaces=namespaces,
            workload_types=workload_types,
            workload_names=workload_names,
            filters=filters,
            search=search,
        )
        if error:
            return error

        log_type, error = _validate_choice(log_type, LOG_TYPES, "log_type", DEFAULT_LOG_TYPE, lower=True)
        if error:
            return error

        error = await _validate_filter_fields(client, cwpp_base_url, scope)
        if error:
            return error

        span = max(1, scope.to_ts - scope.from_ts)

        if interval:
            step = parse_duration(interval)
            if not step:
                return {
                    "error": f"Could not parse interval '{interval}'.",
                    "hint": "Examples: '1h', '30m', '1d'.",
                }
            bucket_count = min(max(1, math.ceil(span / step)), MAX_TREND_BUCKETS)
            step = math.ceil(span / bucket_count)
        else:
            bucket_count = max(1, min(int(buckets or 12), MAX_TREND_BUCKETS))
            step = math.ceil(span / bucket_count)

        windows = []
        cursor = scope.from_ts
        for _ in range(bucket_count):
            end = min(cursor + step, scope.to_ts)
            windows.append((cursor, end))
            cursor = end
            if cursor >= scope.to_ts:
                break

        semaphore = asyncio.Semaphore(_MAX_CONCURRENCY)
        counts = await asyncio.gather(
            *[
                _count_for(
                    client,
                    cwpp_base_url,
                    scope,
                    DEFAULT_VIEW,
                    log_type,
                    scope.filters,
                    from_ts=window[0],
                    to_ts=window[1],
                    semaphore=semaphore,
                )
                for window in windows
            ],
        )

        series = [
            {
                "from": window[0],
                "to": window[1],
                "from_iso": iso(window[0]),
                "to_iso": iso(window[1]),
                "count": count or 0,
            }
            for window, count in zip(windows, counts)
        ]

        return {
            **scope.info(),
            "widget": "trend",
            "log_type": log_type,
            "interval_seconds": step,
            "buckets": len(series),
            "total": sum(point["count"] for point in series),
            "series": series,
        }

    except httpx.HTTPStatusError as e:
        return {"error": f"API Error: {e.response.status_code}"}
    except Exception as e:
        logger.exception("get_alert_trend failed")
        return {"error": f"Error: {str(e)}"}


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


async def export_alerts_tool(
    client,
    cwpp_base_url: str,
    tenant_id: Optional[str] = None,
    tenant_name: Optional[str] = None,
    component: Optional[str] = None,
    view: Optional[str] = None,
    log_type: Optional[str] = None,
    tool: Optional[str] = None,
    period: Optional[str] = None,
    from_time: Optional[Any] = None,
    to_time: Optional[Any] = None,
    cluster_ids: Any = None,
    namespaces: Any = None,
    workload_types: Any = None,
    workload_names: Any = None,
    filters: Any = None,
    search: Optional[str] = None,
    limit: int = 100,
    detailed: bool = False,
    display_fields: Any = None,
    include_endpoint: bool = False,
) -> dict:
    """Bulk export alerts (POST /monitors/v2/alerts/events/export).

    Same payload as the events endpoint but with `Limit` + `TenantName` instead
    of `PageId`/`PageSize`.
    """

    try:
        scope, error = _build_scope(
            component=component,
            tool=tool,
            tenant_id=tenant_id,
            period=period,
            from_time=from_time,
            to_time=to_time,
            cluster_ids=cluster_ids,
            namespaces=namespaces,
            workload_types=workload_types,
            workload_names=workload_names,
            filters=filters,
            search=search,
        )
        if error:
            return error

        view, error = _validate_choice(view, VIEW_TYPES, "view", DEFAULT_VIEW)
        if error:
            return error
        log_type, error = _validate_choice(log_type, LOG_TYPES, "log_type", DEFAULT_LOG_TYPE, lower=True)
        if error:
            return error

        error = await _validate_filter_fields(client, cwpp_base_url, scope)
        if error:
            return error

        limit = max(1, min(int(limit or 100), 5000))

        payload = scope.events_payload(view=view, log_type=log_type)
        payload["Limit"] = limit
        payload["TenantName"] = tenant_name or ""

        response = await client.export_alert_events(
            cwpp_base_url=cwpp_base_url,
            payload=payload,
            tenant_id=scope.tenant_id,
            include_endpoint=include_endpoint,
        )
        if _is_error(response):
            return response

        endpoint_info = response.pop("endpoint_info", None) if isinstance(response, dict) else None
        rows = _extract_rows(response)

        selected_fields = split_list(display_fields)
        if not detailed and not selected_fields:
            selected_fields = (
                AGGREGATE_DISPLAY_FIELDS
                if view == "Aggregate"
                else DEFAULT_DISPLAY_FIELDS.get(scope.component, [])
            )
        shaped = [project_row(row, None if detailed else selected_fields) for row in rows]

        result: Dict[str, Any] = {
            **scope.info(),
            "view": view,
            "log_type": log_type,
            "limit": limit,
            "returned": len(shaped),
            "results": shaped,
        }
        if endpoint_info:
            result["endpoint_info"] = endpoint_info
        return result

    except httpx.HTTPStatusError as e:
        return {"error": f"API Error: {e.response.status_code}"}
    except Exception as e:
        logger.exception("export_alerts failed")
        return {"error": f"Error: {str(e)}"}


# ---------------------------------------------------------------------------
# Static discovery
# ---------------------------------------------------------------------------


def list_alert_components_tool() -> dict:
    """Static catalogue of alert components, their tools and filterable defaults."""
    return {
        "default_component": DEFAULT_COMPONENT,
        "components": {
            name: {
                "label": meta["label"],
                "description": meta["description"],
                "tools": meta["tools"],
                "tool_required": meta["tool_required"],
                "suggested_group_by": SUGGESTED_GROUP_BY.get(name, []),
            }
            for name, meta in ALERT_COMPONENTS.items()
        },
        "views": list(VIEW_TYPES),
        "log_types": list(LOG_TYPES),
        "filter_ops": {
            "match": "Equals",
            "ne": "Not Equals",
            "pattern": "Regex / glob (e.g. SPARTA*)",
        },
        "severity_buckets": SEVERITY_BUCKETS,
    }
