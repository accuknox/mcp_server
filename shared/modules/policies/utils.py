"""
Policies module — input normalisation helpers.

The three things that are easy to get wrong here:

  * search  — the regex fields are SQL-LIKE patterns, not PCRE. A term is wrapped
              as %term% with spaces replaced by % ("deny write" -> "%deny%write%").
              Sending the raw string silently matches nothing.
  * paging  — page_previous/page_next are an OFFSET RANGE, not page numbers.
  * shape   — list-policy nests the filter under `filter`, policy-count sends the
              same vocabulary flat. Build once, wrap once.
"""

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from shared.utils.scope import split_list

from .constants import (
    ADMISSION_KIND,
    ADMISSION_REQ_TYPE,
    CLUSTER_SCOPED_KINDS,
)


def format_search_terms(search: Any) -> List[str]:
    """Turn a plain search string into the SQL-LIKE patterns the API expects.

    "deny write"      -> ["%deny%write%"]
    "deny, block"     -> ["%deny%", "%block%"]      (comma separates terms)
    "%already%custom" -> ["%already%custom"]        (passed through untouched)
    """
    terms: List[str] = []
    for raw in split_list(search):
        term = raw.strip()
        if not term:
            continue
        if "%" in term:
            # Caller supplied their own LIKE pattern — don't double-wrap it.
            terms.append(term)
            continue
        terms.append("%" + re.sub(r"\s+", "%", term) + "%")
    return terms


def offset_range(page: int, page_size: int) -> Tuple[int, int]:
    """1-based page number -> (page_previous, page_next) offset range."""
    page = max(1, int(page or 1))
    page_size = max(1, int(page_size or 20))
    previous = (page - 1) * page_size
    return previous, previous + page_size


def build_policy_filter(
    cluster_ids: List[int],
    namespace_ids: List[int],
    workload_ids: List[int],
    kinds: List[str],
    statuses: List[str],
    tags: List[str],
    search_terms: List[str],
    tag_regex: Optional[str] = None,
) -> Dict[str, Any]:
    """The filter vocabulary shared by list-policy and policy-count.

    `name.regex` and `tldr.regex` intentionally carry the same array — the API
    ORs the free-text search across both columns.
    """
    policy_filter: Dict[str, Any] = {
        "cluster_id": cluster_ids,
        "namespace_id": namespace_ids,
        "workload_id": workload_ids,
        "kind": kinds,
        "status": statuses,
        "tags": tags,
        "name": {"regex": search_terms},
        "tldr": {"regex": search_terms},
    }
    if tag_regex:
        policy_filter["tag_regex"] = str(tag_regex).strip()
    return policy_filter


def normalize_policies(policies: Any) -> Tuple[List[Dict[str, Any]], Optional[dict]]:
    """Normalise the `policies` argument of the alert-count tool.

    Accepts the `results` array of list_policies verbatim, a trimmed list of
    dicts, or a JSON string of either. Each entry needs a name and a cluster id;
    namespace and kind are optional but improve the roll-up.
    """
    if policies is None or policies == "":
        return [], {
            "error": "`policies` is required.",
            "hint": "Pass the `results` array from list_policies, or a list of "
                    '{"name": ..., "cluster_id": ..., "namespace_name": ..., "policy_kind": ...}.',
        }

    if isinstance(policies, str):
        try:
            policies = json.loads(policies)
        except json.JSONDecodeError:
            return [], {"error": f"`policies` is not valid JSON: {policies!r}"}

    if isinstance(policies, dict):
        # Tolerate the whole list_policies response being handed back.
        policies = policies.get("results") or policies.get("list_of_policies") or [policies]

    if not isinstance(policies, list):
        return [], {"error": "`policies` must be a list of policy objects."}

    normalized: List[Dict[str, Any]] = []
    invalid: List[Any] = []

    for item in policies:
        if not isinstance(item, dict):
            invalid.append(item)
            continue

        name = item.get("name") or item.get("policyName") or item.get("policy_name")
        cluster_id = item.get("cluster_id", item.get("clusterId", item.get("ClusterID")))
        if not name or cluster_id in (None, ""):
            invalid.append(item)
            continue

        namespace = (
            item.get("namespace_name")
            or item.get("namespace")
            or item.get("Namespace")
            or ""
        )
        normalized.append(
            {
                "name": str(name),
                "cluster_id": str(cluster_id),
                "namespace": str(namespace),
                "policy_kind": item.get("policy_kind") or item.get("kind") or "",
                "policy_id": item.get("policy_id"),
                "cluster_name": item.get("cluster_name"),
            },
        )

    if invalid:
        return [], {
            "error": "Every policy needs a `name` and a `cluster_id`.",
            "invalid_entries": invalid[:5],
            "hint": "Pass the `results` array from list_policies unchanged.",
        }

    return normalized, None


def policy_key(cluster_id: Any, namespace: Any, name: str, policy_kind: str) -> str:
    """Identity used to match alert-count rows back to policies.

    Cluster-scoped policies are keyed without the namespace so their counts
    accumulate across every namespace the backend reports them under.
    """
    cluster = str(cluster_id or "")
    if policy_kind in CLUSTER_SCOPED_KINDS:
        return f"{cluster}_{name}"
    return f"{cluster}_{namespace or ''}_{name}"


def build_alert_filter_entry(policy: Dict[str, Any]) -> Dict[str, Any]:
    """One Filters entry per policy, carrying its own scoping keys."""
    entry: Dict[str, Any] = {
        "field": "PolicyName",
        "value": policy["name"],
        "op": "match",
        "ClusterID": str(policy["cluster_id"]),
        "namespace": policy.get("namespace", ""),
    }
    if policy.get("policy_kind") == ADMISSION_KIND:
        entry["ReqType"] = ADMISSION_REQ_TYPE
    return entry


def sum_alert_counts(alerts: Any) -> Dict[str, int]:
    """Collapse a policy's `Alerts` array into one {alert_type: count} map.

    Tolerates both shapes seen in the wild: a list of {type: count} objects, and
    a list of {action/type, count} pairs.
    """
    totals: Dict[str, int] = {}
    if not isinstance(alerts, list):
        alerts = [alerts] if isinstance(alerts, dict) else []

    name_keys = ("Action", "action", "Type", "type", "Name", "name", "alert_type")
    count_keys = ("Count", "count", "total", "Total")

    for entry in alerts:
        if not isinstance(entry, dict):
            continue

        label = next((entry[k] for k in name_keys if k in entry), None)
        value = next((entry[k] for k in count_keys if k in entry), None)
        if label is not None and isinstance(value, (int, float)) and not isinstance(value, bool):
            totals[str(label)] = totals.get(str(label), 0) + int(value)
            continue

        for key, raw in entry.items():
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                continue
            totals[str(key)] = totals.get(str(key), 0) + int(raw)

    return totals


def project_row(row: Any, display_fields: Optional[List[str]]) -> Any:
    """Keep only `display_fields` from a row (absent fields are skipped)."""
    if not display_fields or not isinstance(row, dict):
        return row
    projected = {key: row[key] for key in display_fields if key in row}
    return projected or row
