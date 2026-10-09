"""
CWPP Alerts MCP tools
Register with: alerts.register(mcp)

Recommended call order:
    1. list_alert_components()      – pick the component (and its tool, if needed)
    2. list_alert_fields()          – discover valid filter fields
    3. get_alert_field_values()     – discover valid values for a field
    4. query_alerts() / count_alerts() / get_alert_breakdown() / get_alert_trend()
"""

from typing import Any, Literal, Optional

from fastmcp import Context

from shared import (
    AccuKnoxClient,
    count_alerts_tool,
    export_alerts_tool,
    get_alert_breakdown_tool,
    get_alert_field_values_tool,
    get_alert_trend_tool,
    list_alert_components_tool,
    list_alert_fields_tool,
    query_alerts_tool,
)


def _client(ctx: Context) -> AccuKnoxClient:
    return AccuKnoxClient(base_url=ctx.get_state("base_url"), api_token=ctx.get_state("token"))


def register(mcp) -> None:
    """Register all CWPP alerts tools onto the given FastMCP instance."""

    @mcp.tool()
    async def list_alert_components() -> dict:
        """
        READ-ONLY: List every CWPP alert component, its `tool` values, supported
        views, log types, filter operators and severity bands.

        Call this first when the user asks about alerts and the source is unclear
        ("KubeArmor alerts", "SIEM logs", "audit trail", "LLM Defence", ...).

        Components: kubearmor (KubeArmor runtime), PSA (Pod Security Admission),
        cilium (network flows), knoxguard (Admission Controller), siem, cdr,
        accuknox_alert_service (Event Trail / platform audit), llm_defence_alerts,
        api-security, cloud-governance.

        Note: siem and cdr REQUIRE a `tool` — results without one are unreliable.

        Returns:
            dict: components (with tools + suggested_group_by), views, log_types,
                  filter_ops, severity_buckets
        """
        return list_alert_components_tool()

    @mcp.tool()
    async def list_alert_fields(
        component: str = "kubearmor",
        tool: Optional[str] = None,
        period: Optional[str] = None,
        from_time: Optional[str] = None,
        to_time: Optional[str] = None,
        cluster_ids: Optional[str] = None,
        namespaces: Optional[str] = None,
        workload_types: Optional[str] = None,
        workload_names: Optional[str] = None,
        ctx: Context = None,
    ) -> dict:
        """
        READ-ONLY: List the filter fields available for an alert component.

        Discovery tool — call this before building `filters` for query_alerts,
        count_alerts, get_alert_breakdown or get_alert_trend. Only fields returned
        here are accepted as filter fields.

        Args:
            component: Alert component (default "kubearmor"). See list_alert_components().
            tool: Sub-source; REQUIRED for "siem" and "cdr".
            period: Relative window — "last 24 hours", "7d", "30 minutes", "today",
                    "yesterday" (default: last 24 hours).
            from_time: Explicit start — ISO date/datetime, epoch seconds, or "now". Wins over period.
            to_time: Explicit end — same formats as from_time (default: now).
            cluster_ids: Comma-separated numeric cluster IDs (e.g. "1498,1502"); empty = all.
            namespaces: Comma-separated namespace names; empty = all.
            workload_types: Comma-separated workload types (e.g. "Deployment,StatefulSet").
            workload_names: Comma-separated workload names, positionally paired with workload_types.
            ctx: FastMCP Context (injected automatically)

        Returns:
            dict: { component, time_range, count, fields: [...], suggested_group_by: [...] }

        Examples:
            - "What can I filter KubeArmor alerts by?" → component="kubearmor"
            - "SIEM alert fields" → component="siem", tool="syslog"
        """
        return await list_alert_fields_tool(
            client=_client(ctx),
            cwpp_base_url=ctx.get_state("cwpp_base_url"),
            tenant_id=ctx.get_state("tenant_id"),
            component=component,
            tool=tool,
            period=period,
            from_time=from_time,
            to_time=to_time,
            cluster_ids=cluster_ids,
            namespaces=namespaces,
            workload_types=workload_types,
            workload_names=workload_names,
            include_endpoint=ctx.get_state("include_endpoint"),
        )

    @mcp.tool()
    async def get_alert_field_values(
        field: str,
        component: str = "kubearmor",
        tool: Optional[str] = None,
        period: Optional[str] = None,
        from_time: Optional[str] = None,
        to_time: Optional[str] = None,
        cluster_ids: Optional[str] = None,
        namespaces: Optional[str] = None,
        max_values: int = 25,
        ctx: Context = None,
    ) -> dict:
        """
        READ-ONLY: List the observed values of one alert filter field.

        Use this to build valid filters, and to answer "which clusters / namespaces
        / operations are producing alerts?". Pages are walked automatically until
        `max_values` is reached.

        Args:
            field: Field key from list_alert_fields() (e.g. "Operation", "ClusterName", "Action").
            component: Alert component (default "kubearmor").
            tool: Sub-source; REQUIRED for "siem" and "cdr".
            period: Relative window — "last 24 hours", "7d", "today" (default: last 24 hours).
            from_time: Explicit start — ISO date/datetime, epoch seconds, or "now".
            to_time: Explicit end (default: now).
            cluster_ids: Comma-separated numeric cluster IDs; empty = all.
            namespaces: Comma-separated namespace names; empty = all.
            max_values: Maximum values to return (default 25, max 200).
            ctx: FastMCP Context (injected automatically)

        Returns:
            dict: { component, field, count, values: [...] }

        Examples:
            - "What operations are alerting?" → field="Operation"
            - "Which clusters have KubeArmor alerts this week?" → field="ClusterName", period="7d"
        """
        return await get_alert_field_values_tool(
            client=_client(ctx),
            cwpp_base_url=ctx.get_state("cwpp_base_url"),
            field=field,
            tenant_id=ctx.get_state("tenant_id"),
            component=component,
            tool=tool,
            period=period,
            from_time=from_time,
            to_time=to_time,
            cluster_ids=cluster_ids,
            namespaces=namespaces,
            max_values=max_values,
            include_endpoint=ctx.get_state("include_endpoint"),
        )

    @mcp.tool()
    async def query_alerts(
        component: str = "kubearmor",
        view: Literal["List", "Aggregate"] = "List",
        log_type: Literal["active", "suppressed", "all"] = "active",
        tool: Optional[str] = None,
        period: Optional[str] = None,
        from_time: Optional[str] = None,
        to_time: Optional[str] = None,
        cluster_ids: Optional[str] = None,
        namespaces: Optional[str] = None,
        workload_types: Optional[str] = None,
        workload_names: Optional[str] = None,
        filters: Any = None,
        search: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
        order_by: Optional[Literal["asc", "desc"]] = None,
        order_field: Optional[str] = None,
        detailed: bool = False,
        display_fields: Optional[str] = None,
        include_total: bool = False,
        ctx: Context = None,
    ) -> dict:
        """
        READ-ONLY: Fetch a page of CWPP alerts for a component.

        Args:
            component: Alert component (default "kubearmor"). See list_alert_components().
            view: "List" for individual alerts, "Aggregate" for occurrence roll-ups
                  (PolicyName / ClusterName / Action / Operation + Count) — use
                  "Aggregate" for "most frequent" / "top policy" style questions.
            log_type: "active" (default), "suppressed" or "all".
            tool: Sub-source; REQUIRED for "siem" and "cdr".
            period: Relative window — "last 24 hours", "7d", "30 minutes", "today",
                    "yesterday" (default: last 24 hours).
            from_time: Explicit start — ISO date/datetime ("2026-08-10",
                       "2026-08-10T12:00:00Z"), epoch seconds, or "now". Wins over period.
            to_time: Explicit end — same formats (default: now).
            cluster_ids: Comma-separated numeric cluster IDs (e.g. "1498"); empty = all.
            namespaces: Comma-separated namespace names; empty = all.
            workload_types: Comma-separated workload types (e.g. "Deployment").
            workload_names: Comma-separated workload names, positionally paired with workload_types.
            filters: Field filters as [{"field": ..., "op": "match"|"ne"|"pattern", "values": [...]}]
                     (a JSON string, or a plain {field: value} object, is also accepted).
                     op: match = Equals, ne = Not Equals, pattern = regex/glob (e.g. "SPARTA*").
                     Multi-value entries are exploded to one API filter per value automatically.
                     Severity accepts op="match" only, with values 1..10 or names
                     ("critical", "high", "medium", "low", "informational").
                     Field names must come from list_alert_fields().
            search: Free-text search across the alert payload.
            page: 1-based page number.
            page_size: Rows per page (default 20, max 100).
            order_by: "asc" or "desc" — pair with order_field.
            order_field: Column to sort on (e.g. "Timestamp", "Severity", "ClusterName").
            detailed: True returns every field of each alert; default returns a
                      compact per-component projection.
            display_fields: Comma-separated fields to return instead of the default projection.
            include_total: Also fetch the total match count (one extra request) for pagination.
            ctx: FastMCP Context (injected automatically)

        Returns:
            dict: { component, time_range, view, page, returned, results: [...] }

        Examples:
            - "Show KubeArmor alerts from the last 24 hours" → defaults
            - "Critical KubeArmor alerts this week" →
                  period="7d", filters=[{"field": "Severity", "op": "match", "values": ["critical"]}]
            - "Process alerts in cluster 1498" →
                  cluster_ids="1498", filters=[{"field": "Operation", "op": "match", "values": ["Process"]}]
            - "Alerts tagged SPARTA" →
                  filters=[{"field": "ATags", "op": "pattern", "values": ["SPARTA*"]}]
            - "Most frequent policy violations" → view="Aggregate"
            - "Latest SIEM syslog events" → component="siem", tool="syslog"
        """
        return await query_alerts_tool(
            client=_client(ctx),
            cwpp_base_url=ctx.get_state("cwpp_base_url"),
            tenant_id=ctx.get_state("tenant_id"),
            component=component,
            view=view,
            log_type=log_type,
            tool=tool,
            period=period,
            from_time=from_time,
            to_time=to_time,
            cluster_ids=cluster_ids,
            namespaces=namespaces,
            workload_types=workload_types,
            workload_names=workload_names,
            filters=filters,
            search=search,
            page=page,
            page_size=page_size,
            order_by=order_by,
            order_field=order_field,
            detailed=detailed,
            display_fields=display_fields,
            include_total=include_total,
            include_endpoint=ctx.get_state("include_endpoint"),
        )

    @mcp.tool()
    async def count_alerts(
        component: str = "kubearmor",
        view: Literal["List", "Aggregate"] = "List",
        log_type: Literal["active", "suppressed", "all"] = "active",
        tool: Optional[str] = None,
        period: Optional[str] = None,
        from_time: Optional[str] = None,
        to_time: Optional[str] = None,
        cluster_ids: Optional[str] = None,
        namespaces: Optional[str] = None,
        workload_types: Optional[str] = None,
        workload_names: Optional[str] = None,
        filters: Any = None,
        search: Optional[str] = None,
        ctx: Context = None,
    ) -> dict:
        """
        READ-ONLY: Count CWPP alerts matching a scope — the "how many" tool.

        Same filtering as query_alerts, without paging or sorting.

        Args:
            component: Alert component (default "kubearmor").
            view: "List" (default) or "Aggregate".
            log_type: "active" (default), "suppressed" or "all".
            tool: Sub-source; REQUIRED for "siem" and "cdr".
            period: Relative window — "last 24 hours", "7d", "today" (default: last 24 hours).
            from_time: Explicit start — ISO date/datetime, epoch seconds, or "now".
            to_time: Explicit end (default: now).
            cluster_ids: Comma-separated numeric cluster IDs; empty = all.
            namespaces: Comma-separated namespace names; empty = all.
            workload_types / workload_names: Comma-separated, positionally paired.
            filters: Field filters as [{"field": ..., "op": "match"|"ne"|"pattern", "values": [...]}].
                     op: match = Equals, ne = Not Equals, pattern = regex/glob.
                     Severity accepts op="match" only, values 1..10 or names
                     ("critical", "high", "medium", "low", "informational").
                     Field names must come from list_alert_fields().
            search: Free-text search.
            ctx: FastMCP Context (injected automatically)

        Returns:
            dict: { component, time_range, count }

        Examples:
            - "How many alerts today?" → period="today"
            - "How many critical alerts in namespace prod?" →
                  namespaces="prod", filters=[{"field": "Severity", "op": "match", "values": ["critical"]}]
            - "Count of suppressed alerts" → log_type="suppressed"
        """
        return await count_alerts_tool(
            client=_client(ctx),
            cwpp_base_url=ctx.get_state("cwpp_base_url"),
            tenant_id=ctx.get_state("tenant_id"),
            component=component,
            view=view,
            log_type=log_type,
            tool=tool,
            period=period,
            from_time=from_time,
            to_time=to_time,
            cluster_ids=cluster_ids,
            namespaces=namespaces,
            workload_types=workload_types,
            workload_names=workload_names,
            filters=filters,
            search=search,
            include_endpoint=ctx.get_state("include_endpoint"),
        )

    @mcp.tool()
    async def get_alert_breakdown(
        group_by: str,
        component: str = "kubearmor",
        tool: Optional[str] = None,
        log_type: Literal["active", "suppressed", "all"] = "active",
        period: Optional[str] = None,
        from_time: Optional[str] = None,
        to_time: Optional[str] = None,
        cluster_ids: Optional[str] = None,
        namespaces: Optional[str] = None,
        workload_types: Optional[str] = None,
        workload_names: Optional[str] = None,
        filters: Any = None,
        search: Optional[str] = None,
        top_n: int = 8,
        ctx: Context = None,
    ) -> dict:
        """
        READ-ONLY: Alert counts grouped by one field — widget data for pie / bar
        charts and stat tiles ("alerts by severity", "top clusters by alerts").

        The alerts API has no group-by, so this discovers the field's values and
        counts each one (bounded fan-out, max 15 buckets). Grouping by "Severity"
        returns the five named bands (critical / high / medium / low /
        informational) instead of raw 1..10 values.

        Args:
            group_by: Field to group by (e.g. "Severity", "Operation", "Action",
                      "ClusterName", "NamespaceName", "PolicyName"). Must be a field
                      from list_alert_fields().
            component: Alert component (default "kubearmor").
            tool: Sub-source; REQUIRED for "siem" and "cdr".
            log_type: "active" (default), "suppressed" or "all".
            period: Relative window — "last 24 hours", "7d", "today" (default: last 24 hours).
            from_time: Explicit start — ISO date/datetime, epoch seconds, or "now".
            to_time: Explicit end (default: now).
            cluster_ids / namespaces / workload_types / workload_names: Comma-separated scope filters.
            filters: Extra filters applied to every bucket, same format as query_alerts.
            search: Free-text search.
            top_n: Maximum buckets to return (default 8, max 15).
            ctx: FastMCP Context (injected automatically)

        Returns:
            dict: { widget: "breakdown", group_by, total,
                    buckets: [{ label, values, count, percentage }] } sorted by count desc.

        Examples:
            - "Alert distribution by severity" → group_by="Severity"
            - "Which clusters have the most alerts?" → group_by="ClusterName", period="7d"
            - "Break down alerts by operation" → group_by="Operation"
        """
        return await get_alert_breakdown_tool(
            client=_client(ctx),
            cwpp_base_url=ctx.get_state("cwpp_base_url"),
            group_by=group_by,
            tenant_id=ctx.get_state("tenant_id"),
            component=component,
            tool=tool,
            log_type=log_type,
            period=period,
            from_time=from_time,
            to_time=to_time,
            cluster_ids=cluster_ids,
            namespaces=namespaces,
            workload_types=workload_types,
            workload_names=workload_names,
            filters=filters,
            search=search,
            top_n=top_n,
        )

    @mcp.tool()
    async def get_alert_trend(
        component: str = "kubearmor",
        tool: Optional[str] = None,
        log_type: Literal["active", "suppressed", "all"] = "active",
        period: Optional[str] = None,
        from_time: Optional[str] = None,
        to_time: Optional[str] = None,
        interval: Optional[str] = None,
        buckets: int = 12,
        cluster_ids: Optional[str] = None,
        namespaces: Optional[str] = None,
        workload_types: Optional[str] = None,
        workload_names: Optional[str] = None,
        filters: Any = None,
        search: Optional[str] = None,
        ctx: Context = None,
    ) -> dict:
        """
        READ-ONLY: Alert counts bucketed over time — widget data for line / area /
        bar charts ("alert trend over the last 7 days").

        Args:
            component: Alert component (default "kubearmor").
            tool: Sub-source; REQUIRED for "siem" and "cdr".
            log_type: "active" (default), "suppressed" or "all".
            period: Relative window — "last 24 hours", "7d", "today" (default: last 24 hours).
            from_time: Explicit start — ISO date/datetime, epoch seconds, or "now".
            to_time: Explicit end (default: now).
            interval: Bucket width ("1h", "30m", "1d"). Overrides `buckets`; the
                      bucket count is capped at 24.
            buckets: Number of equal buckets when no interval is given (default 12, max 24).
            cluster_ids / namespaces / workload_types / workload_names: Comma-separated scope filters.
            filters: Same format as query_alerts, applied to every bucket.
            search: Free-text search.
            ctx: FastMCP Context (injected automatically)

        Returns:
            dict: { widget: "trend", interval_seconds, total,
                    series: [{ from, to, from_iso, to_iso, count }] }

        Examples:
            - "Alert trend for the last 7 days" → period="7d", interval="1d"
            - "Hourly alerts today" → period="today", interval="1h"
            - "Critical alert trend" →
                  filters=[{"field": "Severity", "op": "match", "values": ["critical"]}]
        """
        return await get_alert_trend_tool(
            client=_client(ctx),
            cwpp_base_url=ctx.get_state("cwpp_base_url"),
            tenant_id=ctx.get_state("tenant_id"),
            component=component,
            tool=tool,
            log_type=log_type,
            period=period,
            from_time=from_time,
            to_time=to_time,
            interval=interval,
            buckets=buckets,
            cluster_ids=cluster_ids,
            namespaces=namespaces,
            workload_types=workload_types,
            workload_names=workload_names,
            filters=filters,
            search=search,
        )

    @mcp.tool()
    async def export_alerts(
        component: str = "kubearmor",
        view: Literal["List", "Aggregate"] = "List",
        log_type: Literal["active", "suppressed", "all"] = "active",
        tool: Optional[str] = None,
        period: Optional[str] = None,
        from_time: Optional[str] = None,
        to_time: Optional[str] = None,
        cluster_ids: Optional[str] = None,
        namespaces: Optional[str] = None,
        workload_types: Optional[str] = None,
        workload_names: Optional[str] = None,
        filters: Any = None,
        search: Optional[str] = None,
        limit: int = 100,
        detailed: bool = False,
        display_fields: Optional[str] = None,
        tenant_name: Optional[str] = None,
        ctx: Context = None,
    ) -> dict:
        """
        READ-ONLY: Bulk-export alerts in one call (no paging) for analysis or reports.

        Prefer query_alerts for browsing; use this when a large slice is needed at
        once. Keep `limit` modest — every row is returned in the response.

        Args:
            component: Alert component (default "kubearmor").
            view: "List" (default) or "Aggregate".
            log_type: "active" (default), "suppressed" or "all".
            tool: Sub-source; REQUIRED for "siem" and "cdr".
            period: Relative window — "last 24 hours", "7d", "today" (default: last 24 hours).
            from_time: Explicit start — ISO date/datetime, epoch seconds, or "now".
            to_time: Explicit end (default: now).
            cluster_ids / namespaces / workload_types / workload_names: Comma-separated scope filters.
            filters: Same format as query_alerts.
            search: Free-text search.
            limit: Maximum rows to export (default 100, max 5000).
            detailed: True returns every field of each alert.
            display_fields: Comma-separated fields to return instead of the default projection.
            tenant_name: Optional tenant name recorded on the export.
            ctx: FastMCP Context (injected automatically)

        Returns:
            dict: { component, time_range, limit, returned, results: [...] }

        Examples:
            - "Export last week's critical alerts" →
                  period="7d", limit=500,
                  filters=[{"field": "Severity", "op": "match", "values": ["critical"]}]
        """
        return await export_alerts_tool(
            client=_client(ctx),
            cwpp_base_url=ctx.get_state("cwpp_base_url"),
            tenant_id=ctx.get_state("tenant_id"),
            tenant_name=tenant_name,
            component=component,
            view=view,
            log_type=log_type,
            tool=tool,
            period=period,
            from_time=from_time,
            to_time=to_time,
            cluster_ids=cluster_ids,
            namespaces=namespaces,
            workload_types=workload_types,
            workload_names=workload_names,
            filters=filters,
            search=search,
            limit=limit,
            detailed=detailed,
            display_fields=display_fields,
            include_endpoint=ctx.get_state("include_endpoint"),
        )
