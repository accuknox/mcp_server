"""
Policies module — enums and display defaults.

Three endpoints, three payload shapes:

    POST /policymanagement/v2/list-policy    -> filter vocabulary NESTED under `filter`
    POST /policymanagement/v2/policy-count   -> same vocabulary FLAT at the top level
    POST /datapipeline/v3/alerts/kubearmor/actions/count
                                             -> not policy-management at all; a
                                                KubeArmor alerts aggregation with
                                                its own capitalised field names
"""

from typing import List, Optional, Tuple

# `workload` is hardcoded by the UI on both policy-management endpoints.
POLICY_WORKLOAD = "k8s"

POLICY_KINDS: Tuple[str, ...] = (
    "KubeArmorPolicy",
    "KubeArmorHostPolicy",
    "KubeArmorClusterPolicy",
    "KubeArmorNetworkPolicy",
    "NetworkPolicy",
    "AdmissionPolicy",
)

POLICY_STATUSES: Tuple[str, ...] = (
    "Active",
    "Inactive",
    "Ignored",
    "Changed",
    "Stable",
)

# The `type` field is the UI's category tab. "All" is expressed as an empty list.
POLICY_CATEGORIES: Tuple[str, ...] = ("Discovered", "Hardening", "Custom")

# Policies whose alert counts roll up across namespaces (cluster-scoped).
CLUSTER_SCOPED_KINDS: Tuple[str, ...] = ("KubeArmorClusterPolicy",)

# Admission policies are served by a different backend path, flagged per-filter.
ADMISSION_KIND = "AdmissionPolicy"
ADMISSION_REQ_TYPE = "knoxguard"

# The UI hardcodes this FromTime (~17 May 2023) to mean "all time" on the
# per-policy alert-count endpoint. Exposed as a real parameter by the tool.
POLICY_ALERTS_DEFAULT_FROM = 1684343006

# Alert count keys returned per policy (constants.js -> alertTypes).
POLICY_ALERT_TYPES: Tuple[str, ...] = (
    "Blocked",
    "Audit",
    "Audit (Block)",
    "ResourceBlocked",
    "ResourceCleanedUp",
    "ResourceGenerated",
    "ResourceMutated",
    "ResourcePassed",
)

# Compact projection used when detailed=False, so a page of policies stays
# readable instead of dumping every field.
DEFAULT_POLICY_FIELDS: List[str] = [
    "policy_id",
    "name",
    "policy_kind",
    "category",
    "type",
    "status",
    "is_stable",
    "cluster_name",
    "namespace_name",
    "tags",
    "updated_at",
]

# Everything the FE consumes, for reference and for `display_fields` validation.
ALL_POLICY_FIELDS: List[str] = [
    "policy_id",
    "name",
    "tldr",
    "type",
    "label_type",
    "policy_kind",
    "category",
    "status",
    "is_stable",
    "version",
    "cluster_id",
    "cluster_name",
    "namespace_id",
    "namespace_name",
    "tags",
    "labels",
    "pending_available",
    "changes_available",
    "applied_at",
    "created_at",
    "updated_at",
    "updated_by",
    "owner_name",
    "review_msg",
]


def resolve_enum_list(
    values: List[str],
    allowed: Tuple[str, ...],
    name: str,
) -> Tuple[List[str], Optional[dict]]:
    """Case-insensitively map caller values onto their canonical spelling."""
    resolved: List[str] = []
    unknown: List[str] = []

    for value in values:
        candidate = str(value).strip()
        match = next((opt for opt in allowed if opt.lower() == candidate.lower()), None)
        if match:
            if match not in resolved:
                resolved.append(match)
        else:
            unknown.append(candidate)

    if unknown:
        return [], {
            "error": f"Invalid {name}: {unknown}.",
            "valid_values": list(allowed),
        }
    return resolved, None
