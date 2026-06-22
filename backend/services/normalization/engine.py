"""Deterministic normalization engine (Volume 4 §13).

`normalize_payloads` takes one or more ParsedDevicePayload (parser output) and
produces a NormalizationResult: canonical rules + cross-vendor object/service
correlation + warnings. Pure and idempotent — same input → same output. The
persist layer (persist.py) writes the result to PostgreSQL; the anomaly engine
consumes the normalized repository only.
"""
from __future__ import annotations

from typing import Dict, List, Tuple

from core.logging import get_logger
from services.parsing.models import ParsedDevicePayload

from . import canonical as C
from .model import (
    NormalizationResult,
    NormalizedObjectRec,
    NormalizedRule,
    NormalizedServiceRec,
    ObjectMappingRec,
    ServiceMappingRec,
)

logger = get_logger(__name__)


def _correlate_objects(payloads, result: NormalizationResult,
                       obj_index: Dict[Tuple[int, str], str],
                       grp_index: Dict[Tuple[int, str], List[str]]) -> None:
    # Group address records by canonical key to find cross-vendor equivalence.
    by_key: Dict[str, List[dict]] = {}
    name_values: Dict[Tuple[int, str], set] = {}
    for p in payloads:
        for o in p.address_objects:
            ctype, cvalue = C.canonical_object(o.name, o.type, o.value)
            key = C.object_key(ctype, cvalue)
            by_key.setdefault(key, []).append(
                {"device_id": p.device_id, "vendor": p.vendor, "name": o.name,
                 "ctype": ctype, "cvalue": cvalue}
            )
            obj_index[(p.device_id, o.name)] = key
            name_values.setdefault((p.device_id, o.name), set()).add(cvalue)
        for g in p.address_groups:
            gkey = C.object_key("group", g.name)
            by_key.setdefault(gkey, []).append(
                {"device_id": p.device_id, "vendor": p.vendor, "name": g.name,
                 "ctype": "group", "cvalue": g.name}
            )
            obj_index[(p.device_id, g.name)] = gkey
            grp_index[(p.device_id, g.name)] = list(g.members)

    for key, recs in by_key.items():
        names = [r["name"] for r in recs]
        canonical_name = max(set(names), key=names.count)
        rep = recs[0]
        result.normalized_objects[key] = NormalizedObjectRec(
            key=key, canonical_name=canonical_name, canonical_type=rep["ctype"],
            canonical_value=rep["cvalue"], sensitivity=C.infer_sensitivity(canonical_name, rep["cvalue"]),
        )
        for r in recs:
            if r["name"] == canonical_name:
                method, conf, reason = "exact_name_value", 1.00, "same canonical name + value"
            else:
                method, conf = "exact_value", 0.90
                reason = f"same value '{r['cvalue']}', different name (canonical '{canonical_name}')"
                result.warnings.append(
                    f"naming inconsistency: device {r['device_id']} '{r['name']}' == "
                    f"'{canonical_name}' (value {r['cvalue']})"
                )
            result.object_mappings.append(ObjectMappingRec(
                device_id=r["device_id"], vendor=r["vendor"], object_name=r["name"],
                normalized_key=key, match_method=method, confidence=conf, reason=reason,
            ))


def _correlate_services(payloads, result: NormalizationResult,
                        svc_index: Dict[Tuple[int, str], str],
                        svc_grp_index: Dict[Tuple[int, str], List[str]]) -> None:
    by_key: Dict[str, List[dict]] = {}
    for p in payloads:
        for s in p.service_objects:
            key = C.service_key(s.protocol, s.port_start, s.port_end, s.app_id)
            by_key.setdefault(key, []).append(
                {"device_id": p.device_id, "vendor": p.vendor, "name": s.name,
                 "proto": s.protocol, "ps": s.port_start, "pe": s.port_end, "app": s.app_id}
            )
            svc_index[(p.device_id, s.name)] = key
        for g in p.service_groups:
            svc_grp_index[(p.device_id, g.name)] = list(g.members)

    for key, recs in by_key.items():
        names = [r["name"] for r in recs]
        canonical_name = max(set(names), key=names.count)
        rep = recs[0]
        result.normalized_services[key] = NormalizedServiceRec(
            key=key, canonical_name=canonical_name, protocol=(rep["proto"] or "unknown"),
            port_start=rep["ps"], port_end=rep["pe"], app_id=rep["app"],
        )
        for r in recs:
            method, conf = ("exact_name_port", 1.00) if r["name"] == canonical_name else ("exact_port", 0.90)
            result.service_mappings.append(ServiceMappingRec(
                device_id=r["device_id"], vendor=r["vendor"], service_name=r["name"],
                normalized_key=key, match_method=method, confidence=conf,
                reason="same protocol/port",
            ))


def _ensure_predefined_service(name: str, result: NormalizationResult) -> str | None:
    """Resolve a predefined service name (e.g. PAN 'service-https') to a normalized key."""
    pre = C.PREDEFINED_SERVICES.get(name.lower())
    if not pre:
        return None
    proto, ps, pe = pre
    key = C.service_key(proto, ps, pe)
    if key not in result.normalized_services:
        result.normalized_services[key] = NormalizedServiceRec(
            key=key, canonical_name=name, protocol=proto, port_start=ps, port_end=pe, app_id=None,
        )
    return key


def _resolve_objects(device_id: int, names, obj_index, result) -> List[str]:
    keys = []
    for name in names:
        key = obj_index.get((device_id, name))
        if key is None:
            if C.is_any_object(name, ""):
                key = C.object_key("any", "0.0.0.0/0")
                result.normalized_objects.setdefault(key, NormalizedObjectRec(
                    key=key, canonical_name="any", canonical_type="any",
                    canonical_value="0.0.0.0/0", sensitivity="public"))
            else:
                key = C.object_key("unknown", name)
                result.warnings.append(f"device {device_id}: unresolved object reference '{name}'")
                result.normalized_objects.setdefault(key, NormalizedObjectRec(
                    key=key, canonical_name=name, canonical_type="unknown",
                    canonical_value=name, sensitivity="unknown"))
        keys.append(key)
    return keys


def _resolve_services(device_id: int, names, svc_index, result) -> List[str]:
    keys = []
    for name in names:
        key = svc_index.get((device_id, name)) or _ensure_predefined_service(name, result)
        if key is None:
            key = C.service_key("unknown", None, None)
            result.normalized_services.setdefault(key, NormalizedServiceRec(
                key=key, canonical_name=name, protocol="unknown", port_start=None,
                port_end=None, app_id=None))
            result.warnings.append(f"device {device_id}: unresolved service reference '{name}'")
        keys.append(key)
    return keys


def normalize_payloads(payloads: List[ParsedDevicePayload]) -> NormalizationResult:
    """Normalize one or more parsed device payloads into the canonical result."""
    result = NormalizationResult()
    obj_index: Dict[Tuple[int, str], str] = {}
    grp_index: Dict[Tuple[int, str], List[str]] = {}
    svc_index: Dict[Tuple[int, str], str] = {}
    svc_grp_index: Dict[Tuple[int, str], List[str]] = {}

    _correlate_objects(payloads, result, obj_index, grp_index)
    _correlate_services(payloads, result, svc_index, svc_grp_index)

    for p in payloads:
        for pr in p.rules:
            action = C.canonical_action(p.vendor, pr.action)
            logging_enabled = C.canonical_logging(p.vendor, pr)
            inspection = C.canonical_inspection(p.vendor, pr)
            strength = C.canonical_profile_strength(inspection, pr)
            vendor_uuid = pr.vendor_uuid or C.derive_vendor_uuid(
                p.device_id, pr.vdom_vsys, pr.vendor_rule_id, pr.rule_name, p.vendor)
            profile_group = (pr.security_profiles or {}).get("profile_group") or None

            src_keys = _resolve_objects(p.device_id, pr.src_addrs, obj_index, result)
            dst_keys = _resolve_objects(p.device_id, pr.dst_addrs, obj_index, result)
            svc_keys = _resolve_services(p.device_id, pr.services, svc_index, result)

            chash = C.content_hash(
                p.vendor, str(p.device_id), pr.vdom_vsys or "", action,
                ",".join(sorted(src_keys)), ",".join(sorted(dst_keys)),
                ",".join(sorted(svc_keys)), logging_enabled, inspection,
                "|".join(pr.src_zones), "|".join(pr.dst_zones),
            )

            result.rules.append(NormalizedRule(
                device_id=p.device_id, vendor=p.vendor, rule_name=pr.rule_name,
                rule_order=pr.rule_order, vendor_rule_id=pr.vendor_rule_id, vendor_uuid=vendor_uuid,
                vdom_vsys=pr.vdom_vsys, enabled=pr.enabled,
                src_zone=",".join(pr.src_zones) or "any", dst_zone=",".join(pr.dst_zones) or "any",
                action=action, logging_enabled=logging_enabled,
                security_inspection_enabled=inspection, security_profile_group=profile_group,
                security_profile_strength=strength, schedule=pr.schedule,
                schedule_scope=C.canonical_schedule_scope(pr.schedule), nat_enabled=pr.nat_enabled,
                description=pr.description, src_negate=pr.src_negate, dst_negate=pr.dst_negate,
                src_object_keys=src_keys, dst_object_keys=dst_keys, service_keys=svc_keys,
                src_object_names=list(pr.src_addrs), dst_object_names=list(pr.dst_addrs),
                service_names=list(pr.services), normalized_content_hash=chash,
            ))

    logger.info(
        "Normalized %d payload(s): %d rules, %d normalized objects, %d normalized services, %d warnings",
        len(payloads), len(result.rules), len(result.normalized_objects),
        len(result.normalized_services), len(result.warnings),
    )
    return result
