"""
Request-scoping helpers shared by the CWPP modules (alerts, policies, ...).

The CWPP APIs are multi-tenant: the tenant must travel in the X-Tenant-Id header
AND in the body (`WorkspaceID` / `workspace_id`). Sending null there issues an
unscoped request instead of failing, so callers validate up front.
"""

from typing import Any, List, Optional


def require_tenant(tenant_id: Optional[str]) -> Optional[dict]:
    """Fail fast when the tenant could not be derived from the auth token."""
    if tenant_id in (None, ""):
        return {
            "error": "Tenant ID unavailable — cannot scope this request.",
            "detail": (
                "The tenant must be sent both as the X-Tenant-Id header and in the "
                "request body, but it could not be read from the auth token."
            ),
            "hint": (
                "The tenant is taken from the `tenant-id` (or `tenant_id`/`tid`) claim "
                "of the bearer token. Check that a valid, non-expired AccuKnox JWT is "
                "being sent."
            ),
        }
    return None


def workspace_id(tenant_id: Optional[str]) -> Any:
    """Tenant id for the body field (numeric when it looks numeric).

    Only call this on a tenant already validated by `require_tenant`.
    """
    text = str(tenant_id)
    return int(text) if text.isdigit() else text


def split_list(value: Any) -> List[str]:
    """Accept a list, a comma-separated string, or None → list of strings."""
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [part.strip() for part in str(value).split(",") if part.strip()]


def split_int_list(value: Any) -> tuple[List[int], Optional[str]]:
    """Like `split_list` but for numeric IDs. Returns (ids, first_bad_value)."""
    ids: List[int] = []
    for item in split_list(value):
        try:
            ids.append(int(item))
        except ValueError:
            return [], item
    return ids, None
