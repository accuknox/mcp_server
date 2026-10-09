"""
Alerts module — input normalisation helpers.

Covers the two alerts-specific things that are easy to get wrong:

  * filters   — the DSL is a flat list with one object per value, not per field
  * severity  — only `match` is allowed and values are the strings "1".."10"

Time parsing and scope helpers are shared with the other CWPP modules; they are
re-exported here so this module stays the one import for alerts input handling.
"""

import json
from typing import Any, Dict, List, Optional, Tuple

from shared.utils.scope import split_list
from shared.utils.timeutils import (
    DEFAULT_RANGE_SECONDS,
    iso,
    parse_duration,
    parse_timestamp,
    resolve_time_range,
    time_range_info,
)

from .constants import (
    FILTER_OPS,
    SEVERITY_ALIASES,
    SEVERITY_BUCKETS,
    SEVERITY_VALUES,
)

__all__ = [
    "DEFAULT_RANGE_SECONDS",
    "iso",
    "parse_duration",
    "parse_timestamp",
    "resolve_time_range",
    "time_range_info",
    "split_list",
    "normalize_filters",
    "severity_bucket_filters",
    "flatten_values",
    "project_row",
]

# ---------------------------------------------------------------------------
# Filters DSL
# ---------------------------------------------------------------------------


def _expand_severity_values(values: List[Any]) -> Tuple[List[str], Optional[dict]]:
    """Map severity names to the numeric strings the API expects."""
    expanded: List[str] = []
    for raw in values:
        text = str(raw).strip().lower()
        bucket = SEVERITY_ALIASES.get(text)
        if bucket:
            expanded.extend(SEVERITY_BUCKETS[bucket])
            continue
        if text in SEVERITY_VALUES:
            expanded.append(text)
            continue
        return [], {
            "error": f"'{raw}' is not a valid Severity value.",
            "valid_values": SEVERITY_VALUES,
            "valid_names": list(SEVERITY_BUCKETS),
            "hint": "Severity is 1..10 (critical 1-2, high 3-4, medium 5-6, low 7-8, informational 9-10).",
        }

    # de-duplicate, keep order
    seen = set()
    result = []
    for value in expanded:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result, None


def normalize_filters(filters: Any) -> Tuple[List[Dict[str, Any]], Optional[dict]]:
    """Normalise caller filters into the flat DSL the API expects.

    Accepted inputs:
        [{"field": "Operation", "op": "match", "values": ["Process", "File"]}]
        [{"field": "Operation", "op": "match", "value": "Process"}]
        {"Operation": "Process", "Severity": ["critical", "high"]}
        '<any of the above as a JSON string>'

    Output (API wire format) — one object per value, field/op repeated:
        [{"field": "Operation", "value": "Process", "op": "match"},
         {"field": "Operation", "value": "File",    "op": "match"}]
    """
    if filters is None or filters == "":
        return [], None

    if isinstance(filters, str):
        try:
            filters = json.loads(filters)
        except json.JSONDecodeError:
            return [], {
                "error": f"filters '{filters}' is not valid JSON.",
                "hint": 'Example: [{"field": "Operation", "op": "match", "values": ["Process"]}]',
            }

    entries: List[Dict[str, Any]] = []

    if isinstance(filters, dict):
        entries = [{"field": key, "values": value} for key, value in filters.items()]
    elif isinstance(filters, list):
        for item in filters:
            if not isinstance(item, dict):
                return [], {
                    "error": f"Each filter must be an object, got '{item}'.",
                    "hint": 'Example: {"field": "Operation", "op": "match", "values": ["Process"]}',
                }
            entries.append(item)
    else:
        return [], {"error": "filters must be a list, an object, or a JSON string."}

    wire: List[Dict[str, Any]] = []

    for entry in entries:
        field = entry.get("field") or entry.get("key") or entry.get("name")
        if not field:
            return [], {"error": f"Filter {entry} is missing a 'field'."}
        field = str(field).strip()

        op = str(entry.get("op") or entry.get("operator") or "match").strip().lower()
        if op in ("equals", "eq", "="):
            op = "match"
        elif op in ("not equals", "not_equals", "neq", "!=", "not"):
            op = "ne"
        elif op in ("regex", "glob", "like"):
            op = "pattern"

        if op not in FILTER_OPS:
            return [], {
                "error": f"'{op}' is not a valid filter operator for field '{field}'.",
                "valid_ops": list(FILTER_OPS),
                "hint": "match = Equals, ne = Not Equals, pattern = regex/glob.",
            }

        raw_values = entry.get("values", entry.get("value"))
        if raw_values is None:
            # Field-exists style filter: value is omitted entirely.
            wire.append({"field": field, "op": op})
            continue

        values = raw_values if isinstance(raw_values, (list, tuple)) else [raw_values]
        values = [v for v in values if v is not None and str(v) != ""]
        if not values:
            wire.append({"field": field, "op": op})
            continue

        if field.lower() == "severity":
            if op != "match":
                return [], {
                    "error": "Severity only supports op 'match'.",
                    "hint": "Use op='match' with values 1..10 or names like 'critical'.",
                }
            values, error = _expand_severity_values(list(values))
            if error:
                return [], error

        for value in values:
            wire.append({"field": field, "value": str(value), "op": op})

    return wire, None


def severity_bucket_filters(bucket: str) -> List[Dict[str, Any]]:
    """Filter entries matching a named severity bucket (e.g. critical → 1, 2)."""
    return [
        {"field": "Severity", "value": value, "op": "match"}
        for value in SEVERITY_BUCKETS[bucket]
    ]


def flatten_values(values: Any) -> List[Any]:
    """Flatten nested field-value arrays and drop empty entries.

    Mirrors the FE behaviour: numbers and booleans are kept even when falsy,
    everything else must be truthy to survive.
    """
    flat: List[Any] = []

    def _walk(item: Any) -> None:
        if isinstance(item, (list, tuple)):
            for sub in item:
                _walk(sub)
            return
        if isinstance(item, bool) or isinstance(item, (int, float)):
            flat.append(item)
            return
        if item:
            flat.append(item)

    _walk(values)

    seen = set()
    unique: List[Any] = []
    for value in flat:
        key = (type(value).__name__, str(value))
        if key not in seen:
            seen.add(key)
            unique.append(value)
    return unique


def project_row(row: Any, display_fields: Optional[List[str]]) -> Any:
    """Keep only `display_fields` from a row (fields absent from the row are skipped)."""
    if not display_fields or not isinstance(row, dict):
        return row
    projected = {key: row[key] for key in display_fields if key in row}
    return projected or row
