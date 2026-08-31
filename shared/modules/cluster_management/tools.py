"""
Cluster Management module — tool implementations
Covers: clusters, namespaces, workloads, nodes, cluster status history
"""

from typing import Optional

import httpx


async def list_clusters_tool(
    client,
    cwpp_base_url: str,
    tenant_id: Optional[str] = None,
    cluster_type: Optional[str] = None,
    connection_status: Optional[str] = None,
    tag_name: Optional[list] = None,
    name_regex: Optional[str] = None,
    sort_by: Optional[str] = None,
    sort_order: Optional[str] = None,
    from_time: int = 0,
    to_time: int = 0,
    page_next: int = 1,
    page_previous: int = 0,
    include_endpoint: bool = False,
) -> dict:
    """List Kubernetes clusters from CWPP API"""

    try:
        filters = {}
        if cluster_type:
            filters["cluster_type"] = cluster_type
        if connection_status:
            filters["connection_status"] = connection_status
        if tag_name:
            filters["tag_name"] = tag_name
        if sort_by:
            filters["sort_by"] = sort_by
        if sort_order:
            filters["sort_order"] = sort_order

        return await client.fetch_clusters(
            cwpp_base_url=cwpp_base_url,
            tenant_id=tenant_id,
            filters=filters,
            from_time=from_time,
            to_time=to_time,
            name_regex=name_regex,
            page_next=page_next,
            page_previous=page_previous,
            include_endpoint=include_endpoint,
        )

    except httpx.HTTPStatusError as e:
        return {"error": f"API Error: {e.response.status_code}"}
    except Exception as e:
        return {"error": f"Error: {str(e)}"}


async def list_namespaces_tool(
    client,
    cwpp_base_url: str,
    tenant_id: Optional[str] = None,
    cluster_id: Optional[list] = None,
    tag_name: Optional[list] = None,
    name_regex: Optional[str] = None,
    sort_by: Optional[str] = None,
    sort_order: Optional[str] = None,
    pod_admission_level: Optional[str] = None,
    pod_admission_mode: Optional[str] = None,
    kubearmor_file_posture: Optional[str] = None,
    kubearmor_network_posture: Optional[str] = None,
    from_time: int = 0,
    to_time: int = 0,
    page_next: int = 1,
    page_previous: int = 0,
    include_endpoint: bool = False,
) -> dict:
    """List namespaces from CWPP API"""

    try:
        filters = {}
        if sort_by:
            filters["sort_by"] = sort_by
        if sort_order:
            filters["sort_order"] = sort_order
        if tag_name:
            filters["tag_name"] = tag_name

        pod_admission = {}
        if pod_admission_level:
            pod_admission["level"] = pod_admission_level
        if pod_admission_mode:
            pod_admission["mode"] = pod_admission_mode
        if pod_admission:
            filters["pod_admission_configs"] = pod_admission

        security_posture = {}
        if kubearmor_file_posture:
            security_posture["kubearmor_file_posture"] = kubearmor_file_posture
        if kubearmor_network_posture:
            security_posture["kubearmor_network_posture"] = kubearmor_network_posture
        if security_posture:
            filters["security_posture"] = security_posture

        return await client.fetch_namespaces(
            cwpp_base_url=cwpp_base_url,
            tenant_id=tenant_id,
            cluster_id=cluster_id,
            filters=filters,
            from_time=from_time,
            to_time=to_time,
            name_regex=name_regex,
            page_next=page_next,
            page_previous=page_previous,
            include_endpoint=include_endpoint,
        )

    except httpx.HTTPStatusError as e:
        return {"error": f"API Error: {e.response.status_code}"}
    except Exception as e:
        return {"error": f"Error: {str(e)}"}


async def list_workloads_tool(
    client,
    cwpp_base_url: str,
    tenant_id: Optional[str] = None,
    cluster_id: Optional[list] = None,
    namespace_id: Optional[list] = None,
    workload_id: Optional[list] = None,
    tag_name: Optional[list] = None,
    name_regex: Optional[str] = None,
    sort: Optional[str] = None,
    order: Optional[str] = None,
    workload_type: Optional[str] = None,
    type_filter: Optional[str] = None,
    active_since: Optional[str] = None,
    created_date: Optional[str] = None,
    egress_policy_status: Optional[str] = None,
    ingress_policy_status: Optional[str] = None,
    system_policy_status: Optional[str] = None,
    from_time: int = 0,
    to_time: int = 0,
    page_next: int = 1,
    page_previous: int = 0,
    include_endpoint: bool = False,
) -> dict:
    """List workloads from CWPP API"""

    try:
        return await client.fetch_workloads(
            cwpp_base_url=cwpp_base_url,
            tenant_id=tenant_id,
            cluster_id=cluster_id,
            namespace_id=namespace_id,
            workload_id=workload_id,
            tag_name=tag_name,
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
            from_time=from_time,
            to_time=to_time,
            page_next=page_next,
            page_previous=page_previous,
            include_endpoint=include_endpoint,
        )

    except httpx.HTTPStatusError as e:
        return {"error": f"API Error: {e.response.status_code}"}
    except Exception as e:
        return {"error": f"Error: {str(e)}"}


async def list_nodes_tool(
    client,
    cwpp_base_url: str,
    tenant_id: Optional[str] = None,
    cluster_id: Optional[list] = None,
    tag_name: Optional[list] = None,
    agent_versions: Optional[list] = None,
    name_regex: Optional[str] = None,
    sort: Optional[str] = None,
    order: Optional[str] = None,
    connection_status: Optional[str] = None,
    active_since: Optional[str] = None,
    created_date: Optional[str] = None,
    label_id: Optional[int] = None,
    from_time: Optional[list] = None,
    to_time: Optional[list] = None,
    page_next: int = 1,
    page_previous: int = 0,
    include_endpoint: bool = False,
) -> dict:
    """List nodes in cluster from CWPP API"""

    try:
        return await client.fetch_nodes_in_cluster(
            cwpp_base_url=cwpp_base_url,
            tenant_id=tenant_id,
            cluster_id=cluster_id,
            tag_name=tag_name,
            agent_versions=agent_versions,
            name_regex=name_regex,
            sort=sort,
            order=order,
            connection_status=connection_status,
            active_since=active_since,
            created_date=created_date,
            label_id=label_id,
            from_time=from_time,
            to_time=to_time,
            page_next=page_next,
            page_previous=page_previous,
            include_endpoint=include_endpoint,
        )

    except httpx.HTTPStatusError as e:
        return {"error": f"API Error: {e.response.status_code}"}
    except Exception as e:
        return {"error": f"Error: {str(e)}"}


async def get_cluster_status_history_tool(
    client,
    cwpp_base_url: str,
    cluster_id: int,
    limit: int = 10,
    tenant_id: Optional[str] = None,
    include_endpoint: bool = False,
) -> dict:
    """Get cluster status history from CWPP API"""

    try:
        return await client.fetch_cluster_status_history(
            cwpp_base_url=cwpp_base_url,
            cluster_id=cluster_id,
            limit=limit,
            tenant_id=tenant_id,
            include_endpoint=include_endpoint,
        )

    except httpx.HTTPStatusError as e:
        return {"error": f"API Error: {e.response.status_code}"}
    except Exception as e:
        return {"error": f"Error: {str(e)}"}
