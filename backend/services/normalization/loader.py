"""Reconstruct a NormalizationResult from the persisted Schema v4 repository.

`load_normalized_result(db, device_ids=None)` reads the normalized rows written by
persist.py and rebuilds the pure NormalizationResult dataclasses so the anomaly
engine can analyze the NORMALIZED REPOSITORY (ADR-010) without ever touching raw
vendor data.

The canonical keys produced here MUST be byte-identical to those emitted by the
normalization engine (services/normalization/engine.py) so that detector set
logic (src_object_keys / dst_object_keys / service_keys) composes across a
persist→load round-trip:
  * object key  = object_key(canonical_type, canonical_value); groups use
                  object_key('group', canonical_name).
  * service key = service_key(protocol, port_start, port_end, app_id).
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from core.logging import get_logger
from models import models

from .canonical import object_key, service_key
from .model import (
    NormalizationResult,
    NormalizedObjectRec,
    NormalizedRule,
    NormalizedServiceRec,
    ObjectMappingRec,
    ServiceMappingRec,
)

logger = get_logger(__name__)


def _norm_object_key(no: models.NormalizedObject) -> str:
    if no.canonical_type == "group":
        return object_key("group", no.canonical_name)
    return object_key(no.canonical_type, no.canonical_value or "")


def _norm_service_key(ns: models.NormalizedService) -> str:
    return service_key(ns.protocol, ns.port_start, ns.port_end, ns.app_id)


def load_normalized_result(db, device_ids: Optional[List[int]] = None) -> NormalizationResult:
    """Rebuild the canonical NormalizationResult from persisted Schema v4 rows.

    If ``device_ids`` is None, all (non-deleted) rules across all devices are
    loaded — required for cross-device detectors.
    """
    result = NormalizationResult()

    # Resolve device -> vendor name (for *MappingRec.vendor and rule.vendor).
    dev_q = db.query(models.FirewallDevice.device_id, models.FirewallDevice.vendor_id)
    if device_ids is not None:
        dev_q = dev_q.filter(models.FirewallDevice.device_id.in_(device_ids))
    device_vendor_id: Dict[int, Optional[int]] = {d: v for d, v in dev_q.all()}

    vendor_name: Dict[int, str] = {}
    vendor_ids = {v for v in device_vendor_id.values() if v is not None}
    if vendor_ids:
        for vid, name in (
            db.query(models.Vendor.vendor_id, models.Vendor.name)
            .filter(models.Vendor.vendor_id.in_(vendor_ids))
            .all()
        ):
            vendor_name[vid] = (name or "").lower()

    def vendor_of(device_id: int) -> str:
        vid = device_vendor_id.get(device_id)
        return vendor_name.get(vid, "unknown")

    # ── 1) Canonical objects: normalized_object_id -> key, plus result records ──
    norm_obj_key: Dict[int, str] = {}
    for no in db.query(models.NormalizedObject).all():
        key = _norm_object_key(no)
        norm_obj_key[no.normalized_object_id] = key
        result.normalized_objects[key] = NormalizedObjectRec(
            key=key,
            canonical_name=no.canonical_name,
            canonical_type=no.canonical_type,
            canonical_value=no.canonical_value or "",
            sensitivity=no.sensitivity or "unknown",
        )

    # ── 2) Canonical services: normalized_service_id -> key, plus records ──
    norm_svc_key: Dict[int, str] = {}
    for ns in db.query(models.NormalizedService).all():
        key = _norm_service_key(ns)
        norm_svc_key[ns.normalized_service_id] = key
        result.normalized_services[key] = NormalizedServiceRec(
            key=key,
            canonical_name=ns.canonical_name,
            protocol=ns.protocol,
            port_start=ns.port_start,
            port_end=ns.port_end,
            app_id=ns.app_id,
        )

    # ── 3) Vendor objects scoped to devices: object_id -> (device_id, name, norm_key) ──
    netobj_q = db.query(models.NetworkObject)
    if device_ids is not None:
        netobj_q = netobj_q.filter(models.NetworkObject.device_id.in_(device_ids))
    netobj_info: Dict[int, Tuple[int, str]] = {}
    for no in netobj_q.all():
        if no.device_id is None:
            continue
        netobj_info[no.object_id] = (no.device_id, no.name)

    # object_id -> normalized key (via object_normalization_mapping)
    object_to_normkey: Dict[int, str] = {}
    onm_q = (
        db.query(models.ObjectNormalizationMapping)
        .filter(models.ObjectNormalizationMapping.object_id.in_(list(netobj_info.keys())))
        if netobj_info else None
    )
    if onm_q is not None:
        for m in onm_q.all():
            nkey = norm_obj_key.get(m.normalized_object_id)
            if nkey is None:
                continue
            object_to_normkey[m.object_id] = nkey
            dev_name = netobj_info.get(m.object_id)
            if dev_name is None:
                continue
            device_id, oname = dev_name
            result.object_mappings.append(ObjectMappingRec(
                device_id=device_id,
                vendor=vendor_of(device_id),
                object_name=oname,
                normalized_key=nkey,
                match_method=m.match_method,
                confidence=m.confidence if m.confidence is not None else 0.0,
                reason=m.mapping_reason or "",
            ))

    # ── 4) Vendor services scoped to devices: service_object_id -> (device_id, name) ──
    svcobj_q = db.query(models.ServiceObject)
    if device_ids is not None:
        svcobj_q = svcobj_q.filter(models.ServiceObject.device_id.in_(device_ids))
    svcobj_info: Dict[int, Tuple[int, str]] = {}
    for so in svcobj_q.all():
        if so.device_id is None:
            continue
        svcobj_info[so.service_object_id] = (so.device_id, so.name)

    service_to_normkey: Dict[int, str] = {}
    snm_q = (
        db.query(models.ServiceNormalizationMapping)
        .filter(models.ServiceNormalizationMapping.service_object_id.in_(list(svcobj_info.keys())))
        if svcobj_info else None
    )
    if snm_q is not None:
        for m in snm_q.all():
            nkey = norm_svc_key.get(m.normalized_service_id)
            if nkey is None:
                continue
            service_to_normkey[m.service_object_id] = nkey
            dev_name = svcobj_info.get(m.service_object_id)
            if dev_name is None:
                continue
            device_id, sname = dev_name
            result.service_mappings.append(ServiceMappingRec(
                device_id=device_id,
                vendor=vendor_of(device_id),
                service_name=sname,
                normalized_key=nkey,
                match_method=m.match_method,
                confidence=m.confidence if m.confidence is not None else 0.0,
                reason=m.mapping_reason or "",
            ))

    # ── 5) Rules ──
    rule_q = db.query(models.PolicyRule).filter(models.PolicyRule.deleted_at.is_(None))
    if device_ids is not None:
        rule_q = rule_q.filter(models.PolicyRule.device_id.in_(device_ids))
    rule_q = rule_q.order_by(models.PolicyRule.device_id, models.PolicyRule.rule_order)
    rules = rule_q.all()
    rule_ids = [r.rule_id for r in rules]

    # rule_id -> {source:[...], destination:[...]} of (object_id, name)
    rule_objs: Dict[int, Dict[str, List[Tuple[int, str]]]] = {}
    if rule_ids:
        for rom in (
            db.query(models.RuleObjectMapping)
            .filter(models.RuleObjectMapping.rule_id.in_(rule_ids))
            .all()
        ):
            info = netobj_info.get(rom.object_id)
            name = info[1] if info else ""
            rule_objs.setdefault(rom.rule_id, {}).setdefault(
                rom.mapping_type, []).append((rom.object_id, name))

    # rule_id -> list of (service_object_id|None, normalized_service_id|None)
    rule_svcs: Dict[int, List[models.RuleServiceMapping]] = {}
    if rule_ids:
        for rsm in (
            db.query(models.RuleServiceMapping)
            .filter(models.RuleServiceMapping.rule_id.in_(rule_ids))
            .all()
        ):
            rule_svcs.setdefault(rsm.rule_id, []).append(rsm)

    for r in rules:
        obj_map = rule_objs.get(r.rule_id, {})

        def _obj_side(side: str):
            keys: List[str] = []
            names: List[str] = []
            for oid, oname in obj_map.get(side, []):
                nkey = object_to_normkey.get(oid)
                if nkey is None:
                    # Vendor object with no normalization mapping — fall back to its
                    # own type/value so set logic still has a stable key.
                    nkey = object_key("unknown", oname)
                keys.append(nkey)
                names.append(oname)
            return keys, names

        src_keys, src_names = _obj_side("source")
        dst_keys, dst_names = _obj_side("destination")

        svc_keys: List[str] = []
        svc_names: List[str] = []
        for rsm in rule_svcs.get(r.rule_id, []):
            nkey = None
            if rsm.normalized_service_id is not None:
                nkey = norm_svc_key.get(rsm.normalized_service_id)
            if nkey is None and rsm.service_object_id is not None:
                nkey = service_to_normkey.get(rsm.service_object_id)
            if nkey is None:
                continue
            svc_keys.append(nkey)
            info = svcobj_info.get(rsm.service_object_id) if rsm.service_object_id else None
            if info is not None:
                svc_names.append(info[1])

        result.rules.append(NormalizedRule(
            device_id=r.device_id,
            vendor=vendor_of(r.device_id),
            rule_name=r.rule_name,
            rule_order=r.rule_order,
            vendor_rule_id=r.vendor_rule_id,
            vendor_uuid=r.vendor_uuid or "",
            vdom_vsys=r.vdom_vsys,
            enabled=bool(r.is_active),
            src_zone=r.src_zone_interface or "any",
            dst_zone=r.dst_zone_interface or "any",
            action=r.action,
            logging_enabled=r.logging_enabled or "unknown",
            security_inspection_enabled=r.security_inspection_enabled or "unknown",
            security_profile_group=r.security_profile_group,
            security_profile_strength=r.security_profile_strength or "unknown",
            schedule=r.schedule_name,
            schedule_scope=r.schedule_scope or "unknown",
            nat_enabled=r.nat_enabled,
            description=r.description,
            src_negate=bool(r.src_negate),
            dst_negate=bool(r.dst_negate),
            src_object_keys=src_keys,
            dst_object_keys=dst_keys,
            service_keys=svc_keys,
            src_object_names=src_names,
            dst_object_names=dst_names,
            service_names=svc_names,
            normalized_content_hash=r.normalized_content_hash or "",
        ))

    logger.info(
        "load_normalized_result: %d rules, %d objects, %d services (devices=%s)",
        len(result.rules), len(result.normalized_objects),
        len(result.normalized_services), device_ids,
    )
    return result
