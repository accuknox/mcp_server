"""
CWPP Policy Management MCP tools
Register with: policies.register(mcp)

Typical flow:
    list_policy_options()      – enums, if unsure of kind/status/category spellings
    count_policies()           – totals per category (pagination + "how many")
    list_policies()            – a page of policies
    get_policy_alert_counts()  – alert counts for the policies on that page
"""

from typing import Any, Literal, Optional

from fastmcp import Context

from shared import (
    AccuKnoxClient,
    count_policies_tool,
    get_policy_alert_counts_tool,
    get_policy_details_tool,
    list_policies_tool,
    list_policy_options_tool,
)


def _client(ctx: Context) -> AccuKnoxClient:
    return AccuKnoxClient(base_url=ctx.get_state("base_url"), api_token=ctx.get_state("token"))


def register(mcp) -> None:
    """Register all CWPP policy tools onto the given FastMCP instance."""

    @mcp.tool()
    async def list_policy_options() -> dict:
        """
        READ-ONLY: List the valid policy kinds, statuses, categories, alert types
        and policy fields. No API call — a static catalogue.

        Use it when unsure of a spelling before filtering:
          kinds:      KubeArmorPolicy, KubeArmorHostPolicy, KubeArmorClusterPolicy,
                      KubeArmorNetworkPolicy, NetworkPolicy, AdmissionPolicy
          statuses:   Active, Inactive, Ignored, Changed, Stable
          categories: Discovered, Hardening, Custom (omit for All)
        """
        return list_policy_options_tool()

    @mcp.tool()
    async def list_policies(
        page: int = 1,
        page_size: int = 20,
        category: Optional[Literal["Discovered", "Hardening", "Custom"]] = None,
        cluster_ids: Optional[str] = None,
        namespace_ids: Optional[str] = None,
        workload_ids: Optional[str] = None,
        kinds: Optional[str] = None,
        statuses: Optional[str] = None,
        tags: Optional[str] = None,
        search: Optional[str] = None,
        tag_regex: Optional[str] = None,
        detailed: bool = False,
        display_fields: Optional[str] = None,
        ctx: Context = None,
    ) -> dict:
        """
        READ-ONLY: List Kubernetes security policies from CWPP.

        Args:
            page: 1-based page number (converted to the API's offset range internally).
            page_size: Policies per page (default 20, max 100).
            category: Policy category tab — "Discovered", "Hardening" or "Custom".
                      Omit for All.
            cluster_ids: Comma-separated numeric cluster IDs (e.g. "1498,1502").
            namespace_ids: Comma-separated numeric namespace **IDs** — not names.
                           Use list_namespaces to resolve a name to an ID.
            workload_ids: Comma-separated numeric workload IDs.
            kinds: Comma-separated policy kinds — KubeArmorPolicy, KubeArmorHostPolicy,
                   KubeArmorClusterPolicy, KubeArmorNetworkPolicy, NetworkPolicy,
                   AdmissionPolicy.
            statuses: Comma-separated statuses — Active, Inactive, Ignored, Changed, Stable.
            tags: Comma-separated exact tag values.
            search: Free-text search across policy name and description. Matched as a
                    SQL-LIKE pattern: "deny write" becomes "%deny%write%". Comma
                    separates independent terms; a string already containing "%" is
                    passed through unchanged.
            tag_regex: SQL-LIKE pattern matched against tags.
            detailed: True returns every policy field; default returns a compact projection.
            display_fields: Comma-separated fields to return instead of the default projection.
            ctx: FastMCP Context (injected automatically)

        Returns:
            dict: { category, page, page_size, returned, filters, results: [...] }

        Notes:
            - This endpoint returns no total. Use count_policies for totals/pagination.

        Examples:
            - "Show me all policies" → defaults
            - "List hardening policies in cluster 1498" → category="Hardening", cluster_ids="1498"
            - "Which admission policies are inactive?" → kinds="AdmissionPolicy", statuses="Inactive"
            - "Find policies about denying writes" → search="deny write"
        """
        return await list_policies_tool(
            client=_client(ctx),
            cwpp_base_url=ctx.get_state("cwpp_base_url"),
            tenant_id=ctx.get_state("tenant_id"),
            page=page,
            page_size=page_size,
            category=category,
            cluster_ids=cluster_ids,
            namespace_ids=namespace_ids,
            workload_ids=workload_ids,
            kinds=kinds,
            statuses=statuses,
            tags=tags,
            search=search,
            tag_regex=tag_regex,
            detailed=detailed,
            display_fields=display_fields,
            include_endpoint=ctx.get_state("include_endpoint"),
        )

    @mcp.tool()
    async def count_policies(
        cluster_ids: Optional[str] = None,
        namespace_ids: Optional[str] = None,
        workload_ids: Optional[str] = None,
        kinds: Optional[str] = None,
        statuses: Optional[str] = None,
        tags: Optional[str] = None,
        search: Optional[str] = None,
        tag_regex: Optional[str] = None,
        ctx: Context = None,
    ) -> dict:
        """
        READ-ONLY: Count policies, split by category — the "how many policies" tool.

        Returns all four totals in one call, so there is no `category` argument:
        total, discovered, hardening and custom. Also supplies the page total for
        paginating list_policies.

        Args:
            cluster_ids: Comma-separated numeric cluster IDs.
            namespace_ids: Comma-separated numeric namespace **IDs** — not names.
            workload_ids: Comma-separated numeric workload IDs.
            kinds: Comma-separated policy kinds (see list_policy_options).
            statuses: Comma-separated statuses — Active, Inactive, Ignored, Changed, Stable.
            tags: Comma-separated exact tag values.
            search: Free-text search, matched as a SQL-LIKE pattern (see list_policies).
            tag_regex: SQL-LIKE pattern matched against tags.
            ctx: FastMCP Context (injected automatically)

        Returns:
            dict: { total_count, discovered_count, hardening_count, custom_count, filters }

        Examples:
            - "How many policies do I have?" → no filters
            - "How many hardening policies exist?" → read hardening_count from the result
            - "How many active policies in cluster 1498?" → cluster_ids="1498", statuses="Active"
        """
        return await count_policies_tool(
            client=_client(ctx),
            cwpp_base_url=ctx.get_state("cwpp_base_url"),
            tenant_id=ctx.get_state("tenant_id"),
            cluster_ids=cluster_ids,
            namespace_ids=namespace_ids,
            workload_ids=workload_ids,
            kinds=kinds,
            statuses=statuses,
            tags=tags,
            search=search,
            tag_regex=tag_regex,
            include_endpoint=ctx.get_state("include_endpoint"),
        )

    @mcp.tool()
    async def get_policy_details(
        policy_id: str,
        ctx: Context = None,
    ) -> dict:
        """
        READ-ONLY: Get the full definition of a single policy by its ID.

        Use after list_policies, when the user asks what a specific policy actually
        does — its rules, spec, metadata and review state. list_policies returns a
        compact row per policy; this returns everything for one of them.

        Args:
            policy_id: The `policy_id` from a list_policies row.
            ctx: FastMCP Context (injected automatically)

        Returns:
            dict: { policy_id, policy: { ...full policy definition... } }

        Examples:
            - "What does policy 4821 do?" → policy_id="4821"
            - "Show me the details of that policy" → policy_id from the earlier list_policies result
        """
        return await get_policy_details_tool(
            client=_client(ctx),
            cwpp_base_url=ctx.get_state("cwpp_base_url"),
            policy_id=policy_id,
            tenant_id=ctx.get_state("tenant_id"),
            include_endpoint=ctx.get_state("include_endpoint"),
        )

    @mcp.tool()
    async def get_policy_alert_counts(
        policies: Any,
        cluster_ids: Optional[str] = None,
        namespaces: Optional[str] = None,
        workload_types: Optional[str] = None,
        workload_names: Optional[str] = None,
        period: Optional[str] = None,
        from_time: Optional[str] = None,
        to_time: Optional[str] = None,
        log_type: Literal["active", "suppressed", "all"] = "active",
        ctx: Context = None,
    ) -> dict:
        """
        READ-ONLY: Alert counts per policy — "which policies are actually firing?".

        One request covers every policy passed in, so call it once per page of
        list_policies rather than once per policy. Counts for cluster-scoped
        policies (KubeArmorClusterPolicy) are rolled up across namespaces here,
        so each policy comes back with one flat count map.

        Args:
            policies: The `results` array from list_policies, passed through
                      unchanged. A list of
                      {"name", "cluster_id", "namespace_name", "policy_kind"}
                      objects (or a JSON string of one) also works. Max 100.
            cluster_ids: Comma-separated cluster IDs to scope the query.
                         Defaults to the clusters referenced by `policies`.
            namespaces: Comma-separated namespace **names** here — not IDs, the
                        opposite of list_policies. Defaults to the namespaces
                        referenced by `policies`.
            workload_types: Comma-separated workload types (e.g. "Deployment").
            workload_names: Comma-separated workload names.
            period: Relative window — "7d", "last 24 hours", "today".
            from_time: Explicit start — ISO date/datetime, epoch seconds, or "now".
                       Defaults to May 2023, i.e. effectively all time.
            to_time: Explicit end (default: now).
            log_type: "active" (default), "suppressed" or "all".
            ctx: FastMCP Context (injected automatically)

        Returns:
            dict: { time_range, policies, total_alerts,
                    results: [{ name, cluster_id, namespace, policy_kind,
                                total_alerts, alerts: {Blocked, Audit, ...} }] }
                  sorted by total_alerts desc.

        Examples:
            - "Which policies are generating the most alerts?" →
                  list_policies() first, then pass its results here
            - "Alert counts for these policies over the last week" → period="7d"
        """
        return await get_policy_alert_counts_tool(
            client=_client(ctx),
            cwpp_base_url=ctx.get_state("cwpp_base_url"),
            policies=policies,
            tenant_id=ctx.get_state("tenant_id"),
            cluster_ids=cluster_ids,
            namespaces=namespaces,
            workload_types=workload_types,
            workload_names=workload_names,
            period=period,
            from_time=from_time,
            to_time=to_time,
            log_type=log_type,
            include_endpoint=ctx.get_state("include_endpoint"),
        )
