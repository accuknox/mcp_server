"""
Alerts module — component catalogue, enums and display defaults.

The CWPP alerts APIs use two different spellings for the same component:

    POST /monitors/v1/alerts/events        -> body key `Type`      (e.g. "kubearmor")
    POST /monitors/v1/alerts/fields        -> body key `Component` (e.g. "KubeArmor")

Every tool in this module takes ONE canonical component name (the `Type` spelling)
and maps to the `Component` spelling internally, so callers can never mix them up.
"""

from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

VIEW_TYPES = ("List", "Aggregate")
LOG_TYPES = ("active", "suppressed", "all")
FILTER_OPS = ("match", "ne", "pattern")
SORT_ORDERS = ("asc", "desc")

DEFAULT_VIEW = "List"
DEFAULT_LOG_TYPE = "active"
DEFAULT_COMPONENT = "kubearmor"

# Severity is special-cased by the UI: only `match` is allowed and the values are
# the numeric strings "1".."10".
SEVERITY_BUCKETS: Dict[str, List[str]] = {
    "critical": ["1", "2"],
    "high": ["3", "4"],
    "medium": ["5", "6"],
    "low": ["7", "8"],
    "informational": ["9", "10"],
}

SEVERITY_ALIASES: Dict[str, str] = {
    "critical": "critical",
    "crit": "critical",
    "high": "high",
    "medium": "medium",
    "med": "medium",
    "moderate": "medium",
    "low": "low",
    "informational": "informational",
    "info": "informational",
    "information": "informational",
}

SEVERITY_VALUES = [str(i) for i in range(1, 11)]

# ---------------------------------------------------------------------------
# Components
# ---------------------------------------------------------------------------

ALERT_COMPONENTS: Dict[str, Dict[str, Any]] = {
    "kubearmor": {
        "label": "KubeArmor",
        "fields_component": "KubeArmor",
        "tools": [],
        "tool_required": False,
        "strict_tools": True,
        "description": "KubeArmor runtime alerts (File / Network / Process operations on Kubernetes workloads).",
    },
    "PSA": {
        "label": "Pod Security Admission",
        "fields_component": "PSA",
        "tools": [],
        "tool_required": False,
        "strict_tools": True,
        "description": "Kubernetes Pod Security Admission violations.",
    },
    "cilium": {
        "label": "Cilium",
        "fields_component": "Cilium",
        "tools": [],
        "tool_required": False,
        "strict_tools": True,
        "description": "Cilium network flow alerts.",
    },
    "knoxguard": {
        "label": "Admission Controller",
        "fields_component": "knoxguard",
        "tools": [],
        "tool_required": False,
        "strict_tools": True,
        "description": "KnoxGuard admission controller events.",
    },
    "siem": {
        "label": "SIEM",
        "fields_component": "siem",
        "tools": ["syslog", "kubearmor"],
        "tool_required": True,
        "strict_tools": True,
        "description": "SIEM log forwarding alerts. A `tool` is REQUIRED — results without it are unreliable.",
    },
    "cdr": {
        "label": "CDR",
        "fields_component": "cdr",
        "tools": ["awslogs", "gcplog", "azurelog"],
        "tool_required": True,
        "strict_tools": True,
        "description": "Cloud Detection & Response alerts from cloud provider logs. A `tool` is REQUIRED.",
    },
    "accuknox_alert_service": {
        "label": "Event Trail",
        "fields_component": "accuknox_alert_service",
        "tools": [
            "Certificates",
            "Channel Integration",
            "Cluster Management",
            "Cloud Account",
            "Collector",
            "Parser",
            "Policy Manager",
            "Registry Manager",
            "Report Management",
            "Rule Engine",
            "Scan",
            "Trigger Management",
            "User Management",
            "Vulnerability Management",
        ],
        "tool_required": False,
        # Lenient: the tool values here are the UI labels; unrecognised values are
        # passed through untouched instead of being rejected.
        "strict_tools": False,
        "description": "AccuKnox platform audit trail (who did what, on which platform component).",
    },
    "llm_defence_alerts": {
        "label": "LLM Defence",
        "fields_component": "llm_defence_alerts",
        "tools": [],
        "tool_required": False,
        "strict_tools": True,
        "description": "LLM Defence prompt/response guardrail alerts.",
    },
    "api-security": {
        "label": "API Security",
        "fields_component": "api-security",
        "tools": ["ratelimit"],
        "tool_required": False,
        "strict_tools": True,
        "description": "API security policy violations (e.g. rate-limit breaches).",
    },
    "cloud-governance": {
        "label": "Cloud Governance",
        "fields_component": "cloud-governance",
        "tools": ["aws-scp"],
        "tool_required": False,
        "strict_tools": True,
        "description": "Cloud governance / service control policy denials.",
    },
}

# Extra spellings accepted for `component` (all matched lower-cased).
_COMPONENT_ALIASES: Dict[str, str] = {
    "pod security admission": "PSA",
    "pod_security_admission": "PSA",
    "admission controller": "knoxguard",
    "admission_controller": "knoxguard",
    "knox guard": "knoxguard",
    "event trail": "accuknox_alert_service",
    "event_trail": "accuknox_alert_service",
    "eventtrail": "accuknox_alert_service",
    "audit": "accuknox_alert_service",
    "llm defence": "llm_defence_alerts",
    "llm defense": "llm_defence_alerts",
    "llm_defense_alerts": "llm_defence_alerts",
    "llm": "llm_defence_alerts",
    "api security": "api-security",
    "api_security": "api-security",
    "apisecurity": "api-security",
    "cloud governance": "cloud-governance",
    "cloud_governance": "cloud-governance",
    "cloudgovernance": "cloud-governance",
}


def _build_alias_index() -> Dict[str, str]:
    index: Dict[str, str] = {}
    for canonical, meta in ALERT_COMPONENTS.items():
        index[canonical.lower()] = canonical
        index[str(meta["label"]).lower()] = canonical
        index[str(meta["fields_component"]).lower()] = canonical
    index.update(_COMPONENT_ALIASES)
    return index


_COMPONENT_INDEX = _build_alias_index()


def resolve_component(component: Optional[str]) -> Tuple[Optional[str], Optional[dict]]:
    """Resolve any accepted spelling to the canonical `Type` value.

    Returns (canonical_component, error_dict). Exactly one is not None.
    """
    if not component:
        return DEFAULT_COMPONENT, None

    canonical = _COMPONENT_INDEX.get(str(component).strip().lower())
    if not canonical:
        return None, {
            "error": f"Unknown alert component '{component}'.",
            "available_components": list(ALERT_COMPONENTS),
            "hint": "Call list_alert_components() to see every component and its tools.",
        }
    return canonical, None


def resolve_tool(
    component: str,
    tool: Optional[str],
) -> Tuple[Optional[str], Optional[dict]]:
    """Validate/normalise the `Tool` value for a component.

    Returns (tool_or_None, error_dict).
    """
    meta = ALERT_COMPONENTS[component]
    allowed: List[str] = meta["tools"]

    if not tool:
        if meta["tool_required"]:
            return None, {
                "error": f"A `tool` is required for component '{component}'.",
                "available_tools": allowed,
            }
        return None, None

    if not allowed:
        return None, {
            "error": f"Component '{component}' does not support a `tool` filter.",
            "hint": "Omit `tool` for this component.",
        }

    for candidate in allowed:
        if candidate.lower() == str(tool).strip().lower():
            return candidate, None

    if meta["strict_tools"]:
        return None, {
            "error": f"'{tool}' is not a valid tool for component '{component}'.",
            "available_tools": allowed,
        }

    # Lenient component (Event Trail): pass the caller's value through as-is.
    return str(tool).strip(), None


def fields_component(component: str) -> str:
    """Map a canonical component to the `Component` value used by /alerts/fields."""
    return ALERT_COMPONENTS[component]["fields_component"]


# ---------------------------------------------------------------------------
# Row shaping
# ---------------------------------------------------------------------------

# Compact per-component projections used when `detailed=False` (the default), so
# a page of alerts stays readable instead of dumping ~35 raw columns per row.
DEFAULT_DISPLAY_FIELDS: Dict[str, List[str]] = {
    "kubearmor": [
        "Timestamp",
        "ClusterName",
        "NamespaceName",
        "PodName",
        "Operation",
        "Resource",
        "Action",
        "Result",
        "Severity",
        "PolicyName",
        "Message",
        "HostName",
    ],
    "PSA": ["Timestamp", "violation_event"],
    "cilium": ["Timestamp", "flow"],
    "knoxguard": ["Timestamp", "knoxguard_event"],
    "siem": ["timestamp", "tool", "topic", "cluster_id", "payload"],
    "cdr": ["timestamp", "tool", "topic", "cluster_id", "payload"],
    "accuknox_alert_service": [
        "Timestamp",
        "message",
        "component",
        "action",
        "result",
        "user",
    ],
    "llm_defence_alerts": [
        "input_timestamp",
        "application_name",
        "prompt",
        "response",
        "overall_action",
        "overall_severity",
        "user",
        "tag",
    ],
    "api-security": [
        "Timestamp",
        "LastViolation",
        "PolicyName",
        "Severity",
        "Action",
        "Endpoint",
        "ViolatingEntity",
        "ConfiguredLimit",
    ],
    "cloud-governance": [
        "Timestamp",
        "EventSource",
        "EventName",
        "ErrorCode",
        "AccountId",
        "OrganizationID",
        "Region",
        "count",
    ],
}

# Aggregate view returns the same roll-up shape for every component; the full
# alert is nested under `Event` and only included when detailed=True.
AGGREGATE_DISPLAY_FIELDS: List[str] = [
    "PolicyName",
    "ClusterName",
    "Action",
    "Operation",
    "Count",
    "WorkloadType",
    "WorkloadName",
]

# Fields that make sensible widget breakdowns per component (used as a hint).
SUGGESTED_GROUP_BY: Dict[str, List[str]] = {
    "kubearmor": ["Severity", "Operation", "Action", "ClusterName", "NamespaceName", "PolicyName"],
    "PSA": ["ClusterName", "NamespaceName"],
    "cilium": ["ClusterName", "NamespaceName"],
    "knoxguard": ["ClusterName", "NamespaceName"],
    "siem": ["topic", "cluster_id"],
    "cdr": ["topic", "cluster_id"],
    "accuknox_alert_service": ["component", "action", "result", "user"],
    "llm_defence_alerts": ["overall_action", "overall_severity", "application_name"],
    "api-security": ["Severity", "Action", "PolicyName", "Endpoint"],
    "cloud-governance": ["EventSource", "EventName", "ErrorCode", "AccountId", "Region"],
}
