"""Deterministic config-only anomaly detectors (Volume 5).

Each detector is an independent pure function over a NormalizationResult:
    detect_xxx(result) -> list[Finding]

Detectors analyze the NORMALIZED model ONLY (never raw vendor data, never an LLM).
Set logic uses NormalizedRule.src_object_keys / dst_object_keys / service_keys,
which are canonical correlation keys. The ANY sentinels are:
    ANY_OBJECT_KEY  = canonical.object_key('any', '0.0.0.0/0')
    ANY_SERVICE_KEY = canonical.service_key('any', None, None)

Determinism: detectors never use randomness, wall-clock, or iteration over dicts in
nondeterministic order. Rules are processed in a stable order (rule_order, vendor_uuid)
and findings are emitted in that order.
"""
from __future__ import annotations

from itertools import combinations
from typing import Dict, Iterable, List, Set, Tuple

from services.normalization import canonical as C
from services.normalization.model import (
    NormalizationResult,
    NormalizedObjectRec,
    NormalizedRule,
)

from .model import Finding

# ── Canonical sentinels ──
ANY_OBJECT_KEY = C.object_key("any", "0.0.0.0/0")
ANY_SERVICE_KEY = C.service_key("any", None, None)

# Actions that block / terminate traffic (relevant for shadowing/conflict).
_BLOCKING_ACTIONS = {"deny", "drop", "reset"}
_ALLOW_ACTIONS = {"allow", "ipsec"}

# Wide port-range threshold (a single canonical service spanning > this many ports).
_WIDE_PORT_THRESHOLD = 1024

# Object-sprawl: number of distinct objects on ONE side of a single rule.
_SPRAWL_THRESHOLD = 50


# ─────────────────────────── helpers ───────────────────────────
def _sorted_rules(result: NormalizationResult) -> List[NormalizedRule]:
    """Stable, deterministic rule ordering."""
    return sorted(
        result.rules,
        key=lambda r: (r.device_id, r.rule_order, r.vendor_uuid or "", r.rule_name or ""),
    )


def _src_set(r: NormalizedRule) -> Set[str]:
    return set(r.src_object_keys)


def _dst_set(r: NormalizedRule) -> Set[str]:
    return set(r.dst_object_keys)


def _svc_set(r: NormalizedRule) -> Set[str]:
    return set(r.service_keys)


def _has_any_src(r: NormalizedRule) -> bool:
    return ANY_OBJECT_KEY in _src_set(r) or not r.src_object_keys


def _has_any_dst(r: NormalizedRule) -> bool:
    return ANY_OBJECT_KEY in _dst_set(r) or not r.dst_object_keys


def _has_any_svc(r: NormalizedRule) -> bool:
    return ANY_SERVICE_KEY in _svc_set(r) or not r.service_keys


def _covers(a_set: Set[str], b_set: Set[str], any_key: str) -> bool:
    """True if a_set (with ANY semantics) covers b_set.

    ANY in a_set covers everything. Empty a_set is treated as ANY (vendor default).
    """
    if any_key in a_set or not a_set:
        return True
    if any_key in b_set or not b_set:
        # b is ANY but a is not -> a does not cover all of b
        return False
    return b_set.issubset(a_set)


def _sensitivity_of(key: str, objs: Dict[str, NormalizedObjectRec]) -> str:
    rec = objs.get(key)
    return rec.sensitivity if rec else "unknown"


_SENSITIVE = {"admin", "database", "critical"}


def _is_allow(r: NormalizedRule) -> bool:
    return r.action in _ALLOW_ACTIONS


def _is_blocking(r: NormalizedRule) -> bool:
    return r.action in _BLOCKING_ACTIONS


def _rule_evidence(r: NormalizedRule) -> dict:
    return {
        "device_id": r.device_id,
        "vendor": r.vendor,
        "rule_name": r.rule_name,
        "rule_order": r.rule_order,
        "vendor_uuid": r.vendor_uuid,
        "action": r.action,
    }


# ─────────────────────────── single-rule detectors ───────────────────────────
def detect_unprotected_allow(result: NormalizationResult) -> List[Finding]:
    out: List[Finding] = []
    for r in _sorted_rules(result):
        if not r.enabled:
            continue
        if _is_allow(r) and r.security_inspection_enabled == "false":
            out.append(Finding(
                anomaly_type="unprotected_allow",
                device_id=r.device_id,
                rule_uuid=r.vendor_uuid,
                severity="high",
                confidence=0.95,
                description=(
                    f"Rule '{r.rule_name}' permits traffic (action={r.action}) with no "
                    f"security inspection (no AV/IPS/web/app profile)."
                ),
                recommendation="Attach a security profile group to inspect permitted traffic.",
                evidence={
                    **_rule_evidence(r),
                    "security_inspection_enabled": r.security_inspection_enabled,
                    "security_profile_group": r.security_profile_group,
                },
            ))
    return out


def detect_missing_logging(result: NormalizationResult) -> List[Finding]:
    out: List[Finding] = []
    for r in _sorted_rules(result):
        if not r.enabled:
            continue
        if r.logging_enabled == "false":
            out.append(Finding(
                anomaly_type="missing_logging",
                device_id=r.device_id,
                rule_uuid=r.vendor_uuid,
                severity="medium",
                confidence=0.9,
                description=f"Rule '{r.rule_name}' has logging disabled; matched traffic is invisible.",
                recommendation="Enable session/UTM logging on this rule.",
                evidence={**_rule_evidence(r), "logging_enabled": r.logging_enabled},
            ))
    return out


def detect_any_to_sensitive(result: NormalizationResult) -> List[Finding]:
    objs = result.normalized_objects
    out: List[Finding] = []
    for r in _sorted_rules(result):
        if not r.enabled or not _is_allow(r):
            continue
        if not _has_any_src(r):
            continue
        sensitive_dst = sorted(
            k for k in _dst_set(r) if _sensitivity_of(k, objs) in _SENSITIVE
        )
        if sensitive_dst:
            out.append(Finding(
                anomaly_type="any_to_sensitive",
                device_id=r.device_id,
                rule_uuid=r.vendor_uuid,
                severity="critical",
                confidence=0.9,
                description=(
                    f"Rule '{r.rule_name}' allows ANY source to reach sensitive "
                    f"destination(s): {', '.join(sensitive_dst)}."
                ),
                recommendation="Restrict source to known administrative/management networks.",
                evidence={
                    **_rule_evidence(r),
                    "src": "any",
                    "sensitive_destinations": sensitive_dst,
                },
            ))
    return out


def detect_overly_permissive(result: NormalizationResult) -> List[Finding]:
    out: List[Finding] = []
    for r in _sorted_rules(result):
        if not r.enabled or not _is_allow(r):
            continue
        if _has_any_src(r) and _has_any_dst(r) and _has_any_svc(r):
            out.append(Finding(
                anomaly_type="overly_permissive",
                device_id=r.device_id,
                rule_uuid=r.vendor_uuid,
                severity="critical",
                confidence=0.95,
                description=(
                    f"Rule '{r.rule_name}' allows ANY source to ANY destination on ANY "
                    f"service (any/any/any permit)."
                ),
                recommendation="Replace any/any/any with least-privilege source, destination, and service.",
                evidence={**_rule_evidence(r), "src": "any", "dst": "any", "service": "any"},
            ))
    return out


def detect_wide_port_range(result: NormalizationResult) -> List[Finding]:
    services = result.normalized_services
    out: List[Finding] = []
    for r in _sorted_rules(result):
        if not r.enabled or not _is_allow(r):
            continue
        wide: List[str] = []
        for k in sorted(_svc_set(r)):
            svc = services.get(k)
            if not svc:
                continue
            ps, pe = svc.port_start, svc.port_end
            if ps is not None and pe is not None and (pe - ps) > _WIDE_PORT_THRESHOLD:
                wide.append(f"{svc.protocol}:{ps}-{pe}")
        if wide:
            out.append(Finding(
                anomaly_type="wide_port_range",
                device_id=r.device_id,
                rule_uuid=r.vendor_uuid,
                severity="medium",
                confidence=0.8,
                description=(
                    f"Rule '{r.rule_name}' permits wide port range(s): {', '.join(wide)}."
                ),
                recommendation="Narrow the service to the specific ports required.",
                evidence={**_rule_evidence(r), "wide_services": wide,
                          "threshold": _WIDE_PORT_THRESHOLD},
            ))
    return out


def detect_missing_description(result: NormalizationResult) -> List[Finding]:
    out: List[Finding] = []
    for r in _sorted_rules(result):
        if (r.description or "").strip() == "":
            out.append(Finding(
                anomaly_type="missing_description",
                device_id=r.device_id,
                rule_uuid=r.vendor_uuid,
                severity="low",
                confidence=0.7,
                description=f"Rule '{r.rule_name}' has no description/comment documenting its intent.",
                recommendation="Add a description documenting the rule's business purpose and owner.",
                evidence={**_rule_evidence(r), "description": r.description},
            ))
    return out


def detect_disabled_rule_review(result: NormalizationResult) -> List[Finding]:
    out: List[Finding] = []
    for r in _sorted_rules(result):
        if not r.enabled:
            out.append(Finding(
                anomaly_type="disabled_rule_review",
                device_id=r.device_id,
                rule_uuid=r.vendor_uuid,
                severity="low",
                confidence=0.6,
                description=f"Rule '{r.rule_name}' is disabled; confirm it is intentional or remove it.",
                recommendation="Remove obsolete disabled rules to reduce policy clutter.",
                evidence={**_rule_evidence(r), "enabled": r.enabled},
            ))
    return out


def detect_object_sprawl(result: NormalizationResult) -> List[Finding]:
    out: List[Finding] = []
    for r in _sorted_rules(result):
        counts = {
            "source": len(_src_set(r)),
            "destination": len(_dst_set(r)),
            "service": len(_svc_set(r)),
        }
        offending = {side: n for side, n in counts.items() if n > _SPRAWL_THRESHOLD}
        if offending:
            out.append(Finding(
                anomaly_type="object_sprawl",
                device_id=r.device_id,
                rule_uuid=r.vendor_uuid,
                severity="low",
                confidence=0.6,
                description=(
                    f"Rule '{r.rule_name}' references an unusually large number of objects: "
                    f"{offending}."
                ),
                recommendation="Consolidate objects into address/service groups for maintainability.",
                evidence={**_rule_evidence(r), "counts": counts,
                          "threshold": _SPRAWL_THRESHOLD},
            ))
    return out


# ─────────────────────────── intra-device pair detectors ───────────────────────────
def _by_device(rules: Iterable[NormalizedRule]) -> Dict[int, List[NormalizedRule]]:
    grouped: Dict[int, List[NormalizedRule]] = {}
    for r in rules:
        grouped.setdefault(r.device_id, []).append(r)
    return grouped


def _same_access(a: NormalizedRule, b: NormalizedRule) -> bool:
    return (_src_set(a) == _src_set(b)
            and _dst_set(a) == _dst_set(b)
            and _svc_set(a) == _svc_set(b))


def detect_duplicate_rules(result: NormalizationResult) -> List[Finding]:
    """Same device: identical action + src set + dst set + service set."""
    out: List[Finding] = []
    for device_id, rules in _by_device(_sorted_rules(result)).items():
        for earlier, later in combinations(rules, 2):
            if earlier.action == later.action and _same_access(earlier, later):
                out.append(Finding(
                    anomaly_type="duplicate_rules",
                    device_id=later.device_id,
                    rule_uuid=later.vendor_uuid,
                    related_device_id=earlier.device_id,
                    related_rule_uuid=earlier.vendor_uuid,
                    severity="medium",
                    confidence=0.95,
                    description=(
                        f"Rule '{later.rule_name}' (order {later.rule_order}) duplicates "
                        f"rule '{earlier.rule_name}' (order {earlier.rule_order}): identical "
                        f"action and source/destination/service sets."
                    ),
                    recommendation="Remove the duplicate rule.",
                    evidence={
                        "rule": _rule_evidence(later),
                        "duplicate_of": _rule_evidence(earlier),
                    },
                ))
    return out


def detect_redundancy(result: NormalizationResult) -> List[Finding]:
    """Same device: a later rule whose sets are a SUBSET of an earlier rule with the
    same action (the earlier rule already covers it). Excludes exact duplicates."""
    out: List[Finding] = []
    for device_id, rules in _by_device(_sorted_rules(result)).items():
        for earlier, later in combinations(rules, 2):
            if earlier.action != later.action:
                continue
            if _same_access(earlier, later):
                continue  # handled by duplicate_rules
            covered = (
                _covers(_src_set(earlier), _src_set(later), ANY_OBJECT_KEY)
                and _covers(_dst_set(earlier), _dst_set(later), ANY_OBJECT_KEY)
                and _covers(_svc_set(earlier), _svc_set(later), ANY_SERVICE_KEY)
            )
            if covered:
                out.append(Finding(
                    anomaly_type="redundancy",
                    device_id=later.device_id,
                    rule_uuid=later.vendor_uuid,
                    related_device_id=earlier.device_id,
                    related_rule_uuid=earlier.vendor_uuid,
                    severity="medium",
                    confidence=0.85,
                    description=(
                        f"Rule '{later.rule_name}' (order {later.rule_order}) is redundant: "
                        f"its match set is already covered by earlier rule "
                        f"'{earlier.rule_name}' (order {earlier.rule_order}) with the same action."
                    ),
                    recommendation="Remove the redundant rule or merge it into the broader rule.",
                    evidence={
                        "rule": _rule_evidence(later),
                        "covered_by": _rule_evidence(earlier),
                    },
                ))
    return out


def detect_shadowing(result: NormalizationResult) -> List[Finding]:
    """Same device: an EARLIER rule (lower rule_order) with a blocking action whose
    src/dst/service sets are a SUPERSET of a later rule -> the later rule never matches."""
    out: List[Finding] = []
    for device_id, rules in _by_device(_sorted_rules(result)).items():
        for earlier, later in combinations(rules, 2):
            # combinations preserves sorted order: earlier.rule_order <= later.rule_order
            if not _is_blocking(earlier):
                continue
            if earlier.rule_order > later.rule_order:
                continue
            shadowed = (
                _covers(_src_set(earlier), _src_set(later), ANY_OBJECT_KEY)
                and _covers(_dst_set(earlier), _dst_set(later), ANY_OBJECT_KEY)
                and _covers(_svc_set(earlier), _svc_set(later), ANY_SERVICE_KEY)
            )
            if shadowed:
                out.append(Finding(
                    anomaly_type="shadowing",
                    device_id=later.device_id,
                    rule_uuid=later.vendor_uuid,
                    related_device_id=earlier.device_id,
                    related_rule_uuid=earlier.vendor_uuid,
                    severity="high",
                    confidence=0.9,
                    description=(
                        f"Rule '{later.rule_name}' (order {later.rule_order}) is shadowed by "
                        f"earlier blocking rule '{earlier.rule_name}' (order {earlier.rule_order}); "
                        f"it will never match traffic."
                    ),
                    recommendation="Reorder or remove the shadowed rule.",
                    evidence={
                        "rule": _rule_evidence(later),
                        "shadowed_by": _rule_evidence(earlier),
                    },
                ))
    return out


def _sets_overlap(a: Set[str], b: Set[str], any_key: str) -> bool:
    if any_key in a or any_key in b or not a or not b:
        return True
    return bool(a & b)


def detect_conflict(result: NormalizationResult) -> List[Finding]:
    """Same device: overlapping src/dst/service sets but DIFFERENT actions."""
    out: List[Finding] = []
    for device_id, rules in _by_device(_sorted_rules(result)).items():
        for earlier, later in combinations(rules, 2):
            if earlier.action == later.action:
                continue
            overlap = (
                _sets_overlap(_src_set(earlier), _src_set(later), ANY_OBJECT_KEY)
                and _sets_overlap(_dst_set(earlier), _dst_set(later), ANY_OBJECT_KEY)
                and _sets_overlap(_svc_set(earlier), _svc_set(later), ANY_SERVICE_KEY)
            )
            if overlap:
                out.append(Finding(
                    anomaly_type="conflict",
                    device_id=later.device_id,
                    rule_uuid=later.vendor_uuid,
                    related_device_id=earlier.device_id,
                    related_rule_uuid=earlier.vendor_uuid,
                    severity="high",
                    confidence=0.8,
                    description=(
                        f"Rule '{later.rule_name}' (order {later.rule_order}, action "
                        f"{later.action}) conflicts with rule '{earlier.rule_name}' "
                        f"(order {earlier.rule_order}, action {earlier.action}): overlapping "
                        f"match sets with different actions."
                    ),
                    recommendation="Resolve the action conflict; the earlier rule wins for overlapping traffic.",
                    evidence={
                        "rule": _rule_evidence(later),
                        "conflicts_with": _rule_evidence(earlier),
                    },
                ))
    return out


# ─────────────────────────── cross-device detectors ───────────────────────────
def _cross_device_pairs(result: NormalizationResult):
    rules = _sorted_rules(result)
    for a, b in combinations(rules, 2):
        if a.device_id == b.device_id:
            continue
        yield a, b


def detect_cross_device_inconsistency(result: NormalizationResult) -> List[Finding]:
    """Different devices: equal canonical src/dst/service sets but DIFFERENT action."""
    out: List[Finding] = []
    for a, b in _cross_device_pairs(result):
        if not _same_access(a, b):
            continue
        if a.action == b.action:
            continue
        out.append(Finding(
            anomaly_type="cross_device_inconsistency",
            device_id=b.device_id,
            rule_uuid=b.vendor_uuid,
            related_device_id=a.device_id,
            related_rule_uuid=a.vendor_uuid,
            severity="critical",  # conflicting access decision across devices (V6 Table 7; V7 §8)
            confidence=0.85,
            description=(
                f"Equivalent access (same source/destination/service) is handled "
                f"inconsistently across devices: device {a.device_id} rule "
                f"'{a.rule_name}' action={a.action} vs device {b.device_id} rule "
                f"'{b.rule_name}' action={b.action}."
            ),
            recommendation="Align the action for equivalent access across devices.",
            evidence={"rule": _rule_evidence(b), "peer": _rule_evidence(a)},
        ))
    return out


def detect_cross_device_security_posture_inconsistency(result: NormalizationResult) -> List[Finding]:
    """Different devices: equal sets + BOTH allow, but logging/inspection posture differs."""
    out: List[Finding] = []
    for a, b in _cross_device_pairs(result):
        if not _same_access(a, b):
            continue
        if not (_is_allow(a) and _is_allow(b)):
            continue
        if (a.logging_enabled == b.logging_enabled
                and a.security_inspection_enabled == b.security_inspection_enabled):
            continue
        out.append(Finding(
            anomaly_type="cross_device_security_posture_inconsistency",
            device_id=b.device_id,
            rule_uuid=b.vendor_uuid,
            related_device_id=a.device_id,
            related_rule_uuid=a.vendor_uuid,
            severity="medium",
            confidence=0.8,
            description=(
                f"Equivalent allow access has different security posture across devices: "
                f"device {a.device_id} rule '{a.rule_name}' "
                f"(logging={a.logging_enabled}, inspection={a.security_inspection_enabled}) "
                f"vs device {b.device_id} rule '{b.rule_name}' "
                f"(logging={b.logging_enabled}, inspection={b.security_inspection_enabled})."
            ),
            recommendation="Standardize logging and inspection for equivalent access across devices.",
            evidence={
                "rule": {**_rule_evidence(b), "logging_enabled": b.logging_enabled,
                         "security_inspection_enabled": b.security_inspection_enabled},
                "peer": {**_rule_evidence(a), "logging_enabled": a.logging_enabled,
                         "security_inspection_enabled": a.security_inspection_enabled},
            },
        ))
    return out


# ─────────────────────────── registry ───────────────────────────
ALL_DETECTORS = (
    detect_unprotected_allow,
    detect_missing_logging,
    detect_any_to_sensitive,
    detect_overly_permissive,
    detect_wide_port_range,
    detect_missing_description,
    detect_disabled_rule_review,
    detect_object_sprawl,
    detect_duplicate_rules,
    detect_redundancy,
    detect_shadowing,
    detect_conflict,
    detect_cross_device_inconsistency,
    detect_cross_device_security_posture_inconsistency,
)
