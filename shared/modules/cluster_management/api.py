"""
Cluster Management module — API mixin
Covers: clusters, namespaces, workloads, nodes, cluster status history
"""

from typing import Any, Dict, List, Optional

import httpx


class ClusterManagementMixin:
    """API methods for cluster management (uses self.headers from AccuKnoxClient)"""

    async def fetch_clusters(
        self,
        cwpp_base_url: str,
        tenant_id: Optional[str] = None,
        filters: Optional[dict] = None,
        from_time: int = 0,
        to_time: int = 0,
        name_regex: Optional[str] = None,
        page_next: int = 1,
        page_previous: int = 0,
        include_endpoint: bool = False,
    ) -> dict:
        """Fetch Kubernetes clusters from CWPP API"""

        endpoint = f"{cwpp_base_url}/cm/v3/clusters/list"

        payload: Dict[str, Any] = {
            "filters": filters or {},
            "from_time": from_time,
            "to_time": to_time,
            "page_next": page_next,
            "page_previous": page_previous,
        }

        if name_regex:
            payload["name"] = {"regex": [name_regex]}

        headers = {**self.headers}
        if tenant_id:
            headers["X-Tenant-Id"] = tenant_id

        async with httpx.AsyncClient(verify=False) as client:
            response = await client.post(endpoint, headers=headers, json=payload, timeout=30.0)
            response.raise_for_status()
            result = response.json()

            if include_endpoint:
                result["endpoint_info"] = {
                    "endpoint_url": str(response.url),
                    "method": "POST",
                    "request_body": payload,
                }

            return result

    async def fetch_namespaces(
        self,
        cwpp_base_url: str,
        tenant_id: Optional[str] = None,
        cluster_id: Optional[List[int]] = None,
        filters: Optional[dict] = None,
        from_time: int = 0,
        to_time: int = 0,
        name_regex: Optional[str] = None,
        page_next: int = 1,
        page_previous: int = 0,
        include_endpoint: bool = False,
    ) -> dict:
        """Fetch namespaces from CWPP API"""

        endpoint = f"{cwpp_base_url}/cm/v3/namespaces/list"

        payload: Dict[str, Any] = {
            "filters": filters or {},
            "from_time": from_time,
            "to_time": to_time,
            "page_next": page_next,
            "page_previous": page_previous,
        }

        if cluster_id:
            payload["cluster_id"] = cluster_id
        if name_regex:
            payload["name"] = {"regex": [name_regex]}

        headers = {**self.headers}
        if tenant_id:
            headers["X-Tenant-Id"] = tenant_id

        async with httpx.AsyncClient(verify=False) as client:
            response = await client.post(endpoint, headers=headers, json=payload, timeout=30.0)
            response.raise_for_status()
            result = response.json()

            if include_endpoint:
                result["endpoint_info"] = {
                    "endpoint_url": str(response.url),
                    "method": "POST",
                    "request_body": payload,
                }

            return result

    async def fetch_workloads(
        self,
        cwpp_base_url: str,
        tenant_id: Optional[str] = None,
        cluster_id: Optional[List[int]] = None,
        namespace_id: Optional[List[int]] = None,
        workload_id: Optional[List[int]] = None,
        tag_name: Optional[List[str]] = None,
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
        """Fetch workloads from CWPP API"""

        endpoint = f"{cwpp_base_url}/cm/v3/workloads/list"

        # All filters including from_time/to_time go inside the filters object
        filters: Dict[str, Any] = {
            "from_time": from_time,
            "to_time": to_time,
        }

        if cluster_id:
            filters["cluster_id"] = cluster_id
        if namespace_id:
            filters["namespace_id"] = namespace_id
        if workload_id:
            filters["workload_id"] = workload_id
        if tag_name:
            filters["tag_name"] = tag_name
        if name_regex:
            filters["name"] = {"regex": [name_regex]}
        if sort:
            filters["sort"] = sort
        if order:
            filters["order"] = order
        if workload_type:
            filters["workload_type"] = workload_type
        if type_filter:
            filters["type"] = type_filter
        if active_since:
            filters["active_since"] = active_since
        if created_date:
            filters["created_date"] = created_date

        policy_status: Dict[str, Any] = {}
        if egress_policy_status:
            policy_status["egress_policy_status"] = egress_policy_status
        if ingress_policy_status:
            policy_status["inress_policy_status"] = ingress_policy_status  # API typo preserved
        if system_policy_status:
            policy_status["system_policy_status"] = system_policy_status
        if policy_status:
            filters["discovered_policy_status"] = policy_status

        payload: Dict[str, Any] = {
            "filters": filters,
            "page_next": page_next,
            "page_previous": page_previous,
        }

        headers = {**self.headers}
        if tenant_id:
            headers["X-Tenant-Id"] = tenant_id

        async with httpx.AsyncClient(verify=False) as client:
            response = await client.post(endpoint, headers=headers, json=payload, timeout=30.0)
            response.raise_for_status()
            result = response.json()

            if include_endpoint:
                result["endpoint_info"] = {
                    "endpoint_url": str(response.url),
                    "method": "POST",
                    "request_body": payload,
                }

            return result

    async def fetch_nodes_in_cluster(
        self,
        cwpp_base_url: str,
        tenant_id: Optional[str] = None,
        cluster_id: Optional[List[int]] = None,
        tag_name: Optional[List[str]] = None,
        agent_versions: Optional[List[str]] = None,
        name_regex: Optional[str] = None,
        sort: Optional[str] = None,
        order: Optional[str] = None,
        connection_status: Optional[str] = None,
        active_since: Optional[str] = None,
        created_date: Optional[str] = None,
        label_id: Optional[int] = None,
        from_time: Optional[List[str]] = None,
        to_time: Optional[List[str]] = None,
        page_next: int = 1,
        page_previous: int = 0,
        include_endpoint: bool = False,
    ) -> dict:
        """Fetch nodes in cluster from CWPP API"""

        endpoint = f"{cwpp_base_url}/cm/api/v1/cluster-management/nodes-in-cluster"

        filter_obj: Dict[str, Any] = {}
        if sort:
            filter_obj["sort"] = sort
        if order:
            filter_obj["order"] = order
        if tag_name:
            filter_obj["tag_name"] = tag_name
        if agent_versions:
            filter_obj["agent_versions"] = agent_versions
        if connection_status:
            filter_obj["connection_status"] = connection_status
        if active_since:
            filter_obj["active_since"] = active_since
        if created_date:
            filter_obj["created_date"] = created_date
        if label_id is not None:
            filter_obj["label_id"] = label_id
        if name_regex:
            filter_obj["name"] = {"regex": [name_regex]}

        payload: Dict[str, Any] = {
            "filter": filter_obj,
            "from_time": from_time or [],
            "to_time": to_time or [],
            "page_next": page_next,
            "page_previous": page_previous,
        }

        if cluster_id:
            payload["cluster_id"] = cluster_id

        headers = {**self.headers}
        if tenant_id:
            headers["X-Tenant-Id"] = tenant_id
            payload["workspace_id"] = int(tenant_id)

        async with httpx.AsyncClient(verify=False) as client:
            response = await client.post(endpoint, headers=headers, json=payload, timeout=30.0)
            response.raise_for_status()
            result = response.json()

            if include_endpoint:
                result["endpoint_info"] = {
                    "endpoint_url": str(response.url),
                    "method": "POST",
                    "request_body": payload,
                }

            return result

    async def fetch_cluster_status_history(
        self,
        cwpp_base_url: str,
        cluster_id: int,
        limit: int = 10,
        tenant_id: Optional[str] = None,
        include_endpoint: bool = False,
    ) -> dict:
        """Fetch cluster status history from CWPP API"""

        endpoint = f"{cwpp_base_url}/cm/api/v1/cluster-management/get-cluster-status-history"

        payload: Dict[str, Any] = {
            "cluster_id": cluster_id,
            "limit": limit,
        }

        headers = {**self.headers}
        if tenant_id:
            headers["X-Tenant-Id"] = tenant_id

        async with httpx.AsyncClient(verify=False) as client:
            response = await client.post(endpoint, headers=headers, json=payload, timeout=30.0)
            response.raise_for_status()
            result = response.json()

            if include_endpoint:
                if isinstance(result, list):
                    result = {"data": result}
                result["endpoint_info"] = {
                    "endpoint_url": str(response.url),
                    "method": "POST",
                    "request_body": payload,
                }

            return result
