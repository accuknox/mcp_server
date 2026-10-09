"""
Cluster Management MCP tools
Register with: cluster_management.register(mcp)
"""

from datetime import datetime, timezone
from typing import Literal, Optional

from fastmcp import Context

from shared import (
    AccuKnoxClient,
    get_cluster_status_history_tool,
    list_clusters_tool,
    list_namespaces_tool,
    list_nodes_tool,
    list_workloads_tool,
)


def _parse_date_range(from_time: Optional[str], to_time: Optional[str]) -> tuple[int, int]:
    """Convert YYYY-MM-DD strings to unix timestamps (0 if not provided)."""
    from_ts = 0
    to_ts = 0
    if from_time:
        from_ts = int(
            datetime.strptime(from_time, "%Y-%m-%d")
            .replace(tzinfo=timezone.utc)
            .timestamp()
        )
    if to_time:
        to_ts = int(
            datetime.strptime(to_time, "%Y-%m-%d")
            .replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
            .timestamp()
        )
    return from_ts, to_ts


def _split_ids(value: Optional[str]) -> Optional[list[int]]:
    """Convert comma-separated ID string to list of ints."""
    if not value:
        return None
    return [int(v.strip()) for v in value.split(",")]


def _split_strings(value: Optional[str]) -> Optional[list[str]]:
    """Convert comma-separated string to list of strings."""
    if not value:
        return None
    return [v.strip() for v in value.split(",")]


def register(mcp) -> None:
    """Register all cluster management tools onto the given FastMCP instance."""

    @mcp.tool()
    async def list_clusters(
        cluster_type: Optional[str] = None,
        connection_status: Optional[str] = None,
        tag_name: Optional[str] = None,
        name_regex: Optional[str] = None,
        sort_by: Optional[Literal["cluster_name", "created_at", "last_updated_time", "alerts", "node_count", "workload_count", "namespace_count", "policy_count"]] = None,
        sort_order: Optional[Literal["ASC", "DESC"]] = None,
        from_time: Optional[str] = None,
        to_time: Optional[str] = None,
        page_next: int = 10,
        page_previous: int = 0,
        ctx: Context = None,
    ) -> dict:
        """
        READ-ONLY: List and filter Kubernetes clusters from CWPP.

        Args:
            cluster_type: Filter by cluster type
            connection_status: Filter by connection status
            tag_name: Filter by tag name (comma-separated for multiple)
            name_regex: Filter clusters by name pattern (regex)
            sort_by: Field to sort by:
                       "cluster_name"     – alphabetical by cluster name
                       "created_at"       – when the cluster was created
                       "last_updated_time"– when the cluster was last updated
                       "alerts"           – total alert count (use for highest/most/top alerts queries)
                       "node_count"       – number of nodes
                       "workload_count"   – number of workloads
                       "namespace_count"  – number of namespaces
                       "policy_count"     – number of policies
            sort_order: Sort direction ("ASC" for lowest first, "DESC" for highest first).
                        Always use "DESC" when user asks for highest/most/top.
            from_time: Start of time range (YYYY-MM-DD). Always pass when user specifies a start date.
            to_time: End of time range (YYYY-MM-DD). Always pass when user specifies an end date or says "today".
            page_next: Number of items to return (default: 10)
            page_previous: Offset to start from (default: 0)
            ctx: FastMCP Context (injected automatically)

        Returns:
            List of clusters matching the criteria

        Examples:
            - "List all clusters" → no filters
            - "Show connected clusters" → connection_status="connected"
            - "List clusters with tag prod" → tag_name="prod"
            - "Which cluster has the highest alerts from April 1 to today?" → sort_by="alerts", sort_order="DESC", from_time="2026-04-01", to_time="<today's date>"
            - "Top clusters by alert count this month" → sort_by="alerts", sort_order="DESC", from_time="<first day of month>", to_time="<today's date>"
            - "Which cluster has the most workloads?" → sort_by="workload_count", sort_order="DESC"
        """
        client = AccuKnoxClient(base_url=ctx.get_state("base_url"), api_token=ctx.get_state("token"))
        from_ts, to_ts = _parse_date_range(from_time, to_time)

        return await list_clusters_tool(
            client=client,
            cwpp_base_url=ctx.get_state("cwpp_base_url"),
            tenant_id=ctx.get_state("tenant_id"),
            cluster_type=cluster_type,
            connection_status=connection_status,
            tag_name=_split_strings(tag_name),
            name_regex=name_regex,
            sort_by=sort_by,
            sort_order=sort_order,
            from_time=from_ts,
            to_time=to_ts,
            page_next=page_next,
            page_previous=page_previous,
            include_endpoint=ctx.get_state("include_endpoint"),
        )

    @mcp.tool()
    async def list_namespaces(
        cluster_id: Optional[str] = None,
        tag_name: Optional[str] = None,
        name_regex: Optional[str] = None,
        sort_by: Optional[Literal["namespace", "cluster_name", "workload_count", "alerts", "protected_workload_count"]] = None,
        sort_order: Optional[Literal["ASC", "DESC"]] = None,
        pod_admission_level: Optional[str] = None,
        pod_admission_mode: Optional[str] = None,
        kubearmor_file_posture: Optional[str] = None,
        kubearmor_network_posture: Optional[str] = None,
        from_time: Optional[str] = None,
        to_time: Optional[str] = None,
        page_next: int = 10,
        page_previous: int = 0,
        ctx: Context = None,
    ) -> dict:
        """
        READ-ONLY: List and filter Kubernetes namespaces from CWPP.

        Args:
            cluster_id: Comma-separated cluster IDs to filter namespaces by (e.g. "1,2,3")
            tag_name: Filter by tag name (comma-separated for multiple)
            name_regex: Filter namespaces by name pattern (regex)
            sort_by: Field to sort by:
                       "namespace"                – alphabetical by namespace name
                       "cluster_name"             – alphabetical by cluster name
                       "workload_count"           – number of workloads in the namespace
                       "alerts"                   – total alert count (use for highest/most/top alerts queries)
                       "protected_workload_count" – number of protected workloads
            sort_order: Sort direction ("ASC" for lowest first, "DESC" for highest first).
                        Always use "DESC" when user asks for highest/most/top.
            pod_admission_level: Filter by pod admission config level
            pod_admission_mode: Filter by pod admission config mode
            kubearmor_file_posture: Filter by KubeArmor file posture (e.g. "audit", "block")
            kubearmor_network_posture: Filter by KubeArmor network posture (e.g. "audit", "block")
            from_time: Start of time range (YYYY-MM-DD). Always pass when user specifies a start date.
            to_time: End of time range (YYYY-MM-DD). Always pass when user specifies an end date or says "today".
            page_next: Number of items to return (default: 10)
            page_previous: Offset to start from (default: 0)
            ctx: FastMCP Context (injected automatically)

        Returns:
            List of namespaces matching the criteria

        Examples:
            - "List all namespaces" → no filters
            - "List namespaces in cluster 5" → cluster_id="5"
            - "Which namespace has the highest alerts from April 1 to today?" → sort_by="alerts", sort_order="DESC", from_time="2026-04-01", to_time="<today's date>"
            - "Namespaces with kubearmor block posture" → kubearmor_file_posture="block"
            - "Top namespaces by workload count" → sort_by="workload_count", sort_order="DESC"
        """
        client = AccuKnoxClient(base_url=ctx.get_state("base_url"), api_token=ctx.get_state("token"))
        from_ts, to_ts = _parse_date_range(from_time, to_time)

        return await list_namespaces_tool(
            client=client,
            cwpp_base_url=ctx.get_state("cwpp_base_url"),
            tenant_id=ctx.get_state("tenant_id"),
            cluster_id=_split_ids(cluster_id),
            tag_name=_split_strings(tag_name),
            name_regex=name_regex,
            sort_by=sort_by,
            sort_order=sort_order,
            pod_admission_level=pod_admission_level,
            pod_admission_mode=pod_admission_mode,
            kubearmor_file_posture=kubearmor_file_posture,
            kubearmor_network_posture=kubearmor_network_posture,
            from_time=from_ts,
            to_time=to_ts,
            page_next=page_next,
            page_previous=page_previous,
            include_endpoint=ctx.get_state("include_endpoint"),
        )

    @mcp.tool()
    async def list_workloads(
        cluster_id: Optional[str] = None,
        namespace_id: Optional[str] = None,
        workload_id: Optional[str] = None,
        tag_name: Optional[str] = None,
        name_regex: Optional[str] = None,
        sort: Optional[Literal["name", "cluster", "namespace", "policy_count", "alerts", "workload_type", "auto_ingress_policy_status", "created_at", "auto_egress_policy_status", "auto_system_policy_status"]] = None,
        order: Optional[Literal["ASC", "DESC"]] = None,
        workload_type: Optional[str] = None,
        type_filter: Optional[str] = None,
        active_since: Optional[str] = None,
        created_date: Optional[str] = None,
        egress_policy_status: Optional[str] = None,
        ingress_policy_status: Optional[str] = None,
        system_policy_status: Optional[str] = None,
        from_time: Optional[str] = None,
        to_time: Optional[str] = None,
        page_next: int = 10,
        page_previous: int = 0,
        ctx: Context = None,
    ) -> dict:
        """
        READ-ONLY: List and filter Kubernetes workloads from CWPP.

        Args:
            cluster_id: Comma-separated cluster IDs to filter by (e.g. "1,2,3")
            namespace_id: Comma-separated namespace IDs to filter by (e.g. "4,5")
            workload_id: Comma-separated workload IDs to filter by
            tag_name: Filter by tag name (comma-separated for multiple)
            name_regex: Filter workloads by name pattern (regex)
            sort: Field to sort by:
                       "name"                      – alphabetical by workload name
                       "cluster"                   – alphabetical by cluster name
                       "namespace"                 – alphabetical by namespace name
                       "policy_count"              – number of policies applied
                       "alerts"                    – total alert count (use for highest/most/top alerts queries)
                       "workload_type"             – grouped by workload type
                       "auto_ingress_policy_status"– ingress auto-discovered policy status
                       "created_at"                – when the workload was created
                       "auto_egress_policy_status" – egress auto-discovered policy status
                       "auto_system_policy_status" – system auto-discovered policy status
            order: Sort direction ("ASC" for lowest first, "DESC" for highest first).
                   Always use "DESC" when user asks for highest/most/top.
            workload_type: Filter by workload type (e.g. "Deployment", "DaemonSet", "StatefulSet")
            type_filter: Filter by workload category type
            active_since: Filter workloads active since this date (YYYY-MM-DD)
            created_date: Filter workloads created on this date (YYYY-MM-DD)
            egress_policy_status: Filter by egress discovered policy status
            ingress_policy_status: Filter by ingress discovered policy status
            system_policy_status: Filter by system discovered policy status
            from_time: Start of time range (YYYY-MM-DD). Always pass when user specifies a start date.
            to_time: End of time range (YYYY-MM-DD). Always pass when user specifies an end date or says "today".
            page_next: Number of items to return (default: 10)
            page_previous: Offset to start from (default: 0)
            ctx: FastMCP Context (injected automatically)

        Returns:
            List of workloads matching the criteria

        Examples:
            - "List all workloads" → no filters
            - "List workloads in cluster 5" → cluster_id="5"
            - "List workloads in namespace 3" → namespace_id="3"
            - "Which workload has the highest alerts from April 1 to today?" → sort="alerts", order="DESC", from_time="2026-04-01", to_time="<today's date>"
            - "Show all Deployments" → workload_type="Deployment"
            - "Top workloads by alert count this month" → sort="alerts", order="DESC", from_time="<first day of month>", to_time="<today's date>"
        """
        client = AccuKnoxClient(base_url=ctx.get_state("base_url"), api_token=ctx.get_state("token"))
        from_ts, to_ts = _parse_date_range(from_time, to_time)

        return await list_workloads_tool(
            client=client,
            cwpp_base_url=ctx.get_state("cwpp_base_url"),
            tenant_id=ctx.get_state("tenant_id"),
            cluster_id=_split_ids(cluster_id),
            namespace_id=_split_ids(namespace_id),
            workload_id=_split_ids(workload_id),
            tag_name=_split_strings(tag_name),
            name_regex=name_regex,
            sort=sort,
            order=order,
            workload_type=workload_type,
            type_filter=type_filter,
            active_since=active_since,
            created_date=created_date,
            egress_policy_status=egress_policy_status,
            ingress_policy_status=ingress_policy_status,
            system_policy_status=system_policy_status,
            from_time=from_ts,
            to_time=to_ts,
            page_next=page_next,
            page_previous=page_previous,
            include_endpoint=ctx.get_state("include_endpoint"),
        )

    @mcp.tool()
    async def list_nodes(
        cluster_id: Optional[str] = None,
        tag_name: Optional[str] = None,
        agent_versions: Optional[str] = None,
        name_regex: Optional[str] = None,
        sort: Optional[Literal["node_name", "alerts", "connection_status", "agent_version", "created_at", "last_updated_time"]] = None,
        order: Optional[Literal["ASC", "DESC"]] = None,
        connection_status: Optional[Literal["Active", "Inactive"]] = None,
        active_since: Optional[str] = None,
        created_date: Optional[str] = None,
        label_id: Optional[int] = None,
        from_time: Optional[str] = None,
        to_time: Optional[str] = None,
        page_next: int = 10,
        page_previous: int = 0,
        ctx: Context = None,
    ) -> dict:
        """
        READ-ONLY: List nodes within Kubernetes clusters from CWPP.

        Args:
            cluster_id: Comma-separated cluster IDs to filter nodes by (e.g. "1,2,3")
            tag_name: Filter by tag name (comma-separated for multiple)
            agent_versions: Filter by agent version (comma-separated for multiple, e.g. "v1.2,v1.3")
            name_regex: Filter nodes by name pattern (regex)
            sort: Field to sort by:
                       "node_name"         – alphabetical by node name
                       "alerts"            – total alert count (use for highest/most/top alerts queries)
                       "connection_status" – grouped by connection status
                       "agent_version"     – grouped by agent version
                       "created_at"        – when the node was registered
                       "last_updated_time" – when the node was last updated
            order: Sort direction ("ASC" for lowest first, "DESC" for highest first).
                   Always use "DESC" when user asks for highest/most/top.
            connection_status: Filter by node connection status ("Active" or "Inactive")
            active_since: Filter nodes active since this date (YYYY-MM-DD)
            created_date: Filter nodes created on this date (YYYY-MM-DD)
            label_id: Filter by label ID
            from_time: Start of time range (YYYY-MM-DD). Always pass when user specifies a start date.
            to_time: End of time range (YYYY-MM-DD). Always pass when user specifies an end date or says "today".
            page_next: Number of items to return (default: 10)
            page_previous: Offset to start from (default: 0)
            ctx: FastMCP Context (injected automatically)

        Returns:
            List of nodes matching the criteria

        Examples:
            - "List all nodes" → no filters
            - "List nodes in cluster 5" → cluster_id="5"
            - "Show active nodes" → connection_status="Active"
            - "Which node has the highest alerts from April 1 to today?" → sort="alerts", order="DESC", from_time="2026-04-01", to_time="<today's date>"
            - "Nodes running agent version v1.2" → agent_versions="v1.2"
        """
        client = AccuKnoxClient(base_url=ctx.get_state("base_url"), api_token=ctx.get_state("token"))

        return await list_nodes_tool(
            client=client,
            cwpp_base_url=ctx.get_state("cwpp_base_url"),
            tenant_id=ctx.get_state("tenant_id"),
            cluster_id=_split_ids(cluster_id),
            tag_name=_split_strings(tag_name),
            agent_versions=_split_strings(agent_versions),
            name_regex=name_regex,
            sort=sort,
            order=order,
            connection_status=connection_status,
            active_since=active_since,
            created_date=created_date,
            label_id=label_id,
            from_time=[from_time] if from_time else [],
            to_time=[to_time] if to_time else [],
            page_next=page_next,
            page_previous=page_previous,
            include_endpoint=ctx.get_state("include_endpoint"),
        )

    @mcp.tool()
    async def get_cluster_status_history(
        cluster_id: int,
        limit: int = 10,
        ctx: Context = None,
    ) -> dict:
        """
        READ-ONLY: Get connection status history for a specific Kubernetes cluster.

        Args:
            cluster_id: The ID of the cluster to fetch status history for (required)
            limit: Number of history records to return (default: 10)
            ctx: FastMCP Context (injected automatically)

        Returns:
            List of status history records for the cluster

        Examples:
            - "Show status history for cluster 4687" → cluster_id=4687
            - "Show last 5 status changes for cluster 4687" → cluster_id=4687, limit=5
            - "Has cluster 4687 been disconnecting recently?" → cluster_id=4687
        """
        client = AccuKnoxClient(base_url=ctx.get_state("base_url"), api_token=ctx.get_state("token"))

        return await get_cluster_status_history_tool(
            client=client,
            cwpp_base_url=ctx.get_state("cwpp_base_url"),
            cluster_id=cluster_id,
            limit=limit,
            tenant_id=ctx.get_state("tenant_id"),
            include_endpoint=ctx.get_state("include_endpoint"),
        )
