"""
Policies module — CWPP API calls.

All three endpoints are POST with no query params. The tenant travels in the
X-Tenant-Id header (added by call_api); only list-policy also carries it in the
body as `workspace_id`.
"""

from typing import Any, Dict, Optional

from shared.utils.api_utils import call_api

LIST_POLICY_ENDPOINT = "/policymanagement/v2/list-policy"
POLICY_COUNT_ENDPOINT = "/policymanagement/v2/policy-count"
POLICY_DETAIL_ENDPOINT = "/policymanagement/v2/policy"
POLICY_ALERT_COUNT_ENDPOINT = "/datapipeline/v3/alerts/kubearmor/actions/count"


class PoliciesMixin:
    """API methods for CWPP policy management."""

    async def _post_policies(
        self,
        endpoint: str,
        cwpp_base_url: str,
        payload: Dict[str, Any],
        tenant_id: Optional[str] = None,
        include_endpoint: bool = False,
        timeout: float = 60.0,
    ) -> Any:
        return await call_api(
            endpoint,
            base_url_type="cwpp",
            method="POST",
            data=payload,
            timeout=timeout,
            base_url=cwpp_base_url,
            token=self.api_token,
            include_endpoint=include_endpoint,
            tenant_id=tenant_id,
        )

    async def fetch_policies(
        self,
        cwpp_base_url: str,
        payload: Dict[str, Any],
        tenant_id: Optional[str] = None,
        include_endpoint: bool = False,
    ) -> Any:
        """POST /policymanagement/v2/list-policy — {"list_of_policies": [...]}."""
        return await self._post_policies(
            LIST_POLICY_ENDPOINT,
            cwpp_base_url=cwpp_base_url,
            payload=payload,
            tenant_id=tenant_id,
            include_endpoint=include_endpoint,
        )

    async def fetch_policy_count(
        self,
        cwpp_base_url: str,
        payload: Dict[str, Any],
        tenant_id: Optional[str] = None,
        include_endpoint: bool = False,
    ) -> Any:
        """POST /policymanagement/v2/policy-count — the four category totals."""
        return await self._post_policies(
            POLICY_COUNT_ENDPOINT,
            cwpp_base_url=cwpp_base_url,
            payload=payload,
            tenant_id=tenant_id,
            include_endpoint=include_endpoint,
        )

    async def fetch_policy_details(
        self,
        cwpp_base_url: str,
        policy_id: str,
        tenant_id: Optional[str] = None,
        include_endpoint: bool = False,
    ) -> Any:
        """GET /policymanagement/v2/policy/{policy_id} — a single policy.

        The only policy endpoint with no workspace_id in the request: the tenant
        is scoped by the X-Tenant-Id header alone, so it must be present.
        """
        return await call_api(
            f"{POLICY_DETAIL_ENDPOINT}/{policy_id}",
            base_url_type="cwpp",
            method="GET",
            base_url=cwpp_base_url,
            token=self.api_token,
            include_endpoint=include_endpoint,
            tenant_id=tenant_id,
        )

    async def fetch_policy_alert_counts(
        self,
        cwpp_base_url: str,
        payload: Dict[str, Any],
        tenant_id: Optional[str] = None,
        include_endpoint: bool = False,
    ) -> Any:
        """POST /datapipeline/v3/alerts/kubearmor/actions/count — per-policy alert counts."""
        return await self._post_policies(
            POLICY_ALERT_COUNT_ENDPOINT,
            cwpp_base_url=cwpp_base_url,
            payload=payload,
            tenant_id=tenant_id,
            include_endpoint=include_endpoint,
        )
