"""
Alerts module — CWPP API calls.

All four endpoints are POST, everything travels in the JSON body except the two
optional query params on /events. The tenant is sent twice — as the X-Tenant-Id
header (added by call_api) and as `WorkspaceID` in the body — and both must match.
"""

from typing import Any, Dict, Optional

from shared.utils.api_utils import call_api

ALERT_EVENTS_ENDPOINT = "/monitors/v1/alerts/events"
ALERT_EVENTS_COUNT_ENDPOINT = "/monitors/v1/alerts/events/count"
ALERT_FIELDS_ENDPOINT = "/monitors/v1/alerts/fields"
ALERT_EVENTS_EXPORT_ENDPOINT = "/monitors/v2/alerts/events/export"


class AlertsMixin:
    """API methods for CWPP alerts (events, counts, fields, export)."""

    async def _post_alerts(
        self,
        endpoint: str,
        cwpp_base_url: str,
        payload: Dict[str, Any],
        tenant_id: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        include_endpoint: bool = False,
        timeout: float = 60.0,
    ) -> Any:
        return await call_api(
            endpoint,
            base_url_type="cwpp",
            method="POST",
            params=params or None,
            data=payload,
            timeout=timeout,
            base_url=cwpp_base_url,
            token=self.api_token,
            include_endpoint=include_endpoint,
            tenant_id=tenant_id,
        )

    async def fetch_alert_events(
        self,
        cwpp_base_url: str,
        payload: Dict[str, Any],
        tenant_id: Optional[str] = None,
        order_by: Optional[str] = None,
        order_field: Optional[str] = None,
        include_endpoint: bool = False,
    ) -> Any:
        """POST /monitors/v1/alerts/events — a page of alerts."""
        params: Dict[str, Any] = {}
        if order_by:
            params["orderby"] = order_by
        if order_field:
            params["orderfield"] = order_field

        return await self._post_alerts(
            ALERT_EVENTS_ENDPOINT,
            cwpp_base_url=cwpp_base_url,
            payload=payload,
            tenant_id=tenant_id,
            params=params,
            include_endpoint=include_endpoint,
        )

    async def fetch_alert_events_count(
        self,
        cwpp_base_url: str,
        payload: Dict[str, Any],
        tenant_id: Optional[str] = None,
        include_endpoint: bool = False,
    ) -> Any:
        """POST /monitors/v1/alerts/events/count — {"count": n}."""
        return await self._post_alerts(
            ALERT_EVENTS_COUNT_ENDPOINT,
            cwpp_base_url=cwpp_base_url,
            payload=payload,
            tenant_id=tenant_id,
            include_endpoint=include_endpoint,
        )

    async def fetch_alert_fields(
        self,
        cwpp_base_url: str,
        payload: Dict[str, Any],
        tenant_id: Optional[str] = None,
        include_endpoint: bool = False,
    ) -> Any:
        """POST /monitors/v1/alerts/fields — filter keys (Type=key) or values (Type=value)."""
        return await self._post_alerts(
            ALERT_FIELDS_ENDPOINT,
            cwpp_base_url=cwpp_base_url,
            payload=payload,
            tenant_id=tenant_id,
            include_endpoint=include_endpoint,
        )

    async def export_alert_events(
        self,
        cwpp_base_url: str,
        payload: Dict[str, Any],
        tenant_id: Optional[str] = None,
        include_endpoint: bool = False,
    ) -> Any:
        """POST /monitors/v2/alerts/events/export — bulk JSON dump (Limit instead of paging)."""
        return await self._post_alerts(
            ALERT_EVENTS_EXPORT_ENDPOINT,
            cwpp_base_url=cwpp_base_url,
            payload=payload,
            tenant_id=tenant_id,
            include_endpoint=include_endpoint,
            timeout=120.0,
        )
