"""Persist a NormalizationResult into the Schema v4 normalized repository.

`persist_result(db, result, payloads)` writes the pure normalization output
(canonical rules + object/service correlation) into PostgreSQL idempotently:
re-running with the same input MUST NOT duplicate rows. The anomaly engine later
reads the persisted repository back via loader.load_normalized_result.

Idempotency strategy (all by natural key, then update-in-place):
  * NormalizedObject   — by canonical_name when type == 'group', else by
                         (canonical_type, canonical_value).
  * NormalizedService  — by app_id when present, else by
                         (protocol, port_start, port_end).
  * NetworkObject      — by (device_id, name).
  * ServiceObject      — by (device_id, name).
  * ObjectNormalizationMapping / ServiceNormalizationMapping — by their unique
                         (object_id|service_object_id, normalized_*_id) pairs.
  * PolicyRule         — by (device_id, vdom_vsys, vendor_uuid).
  * RuleObjectMapping  — by (rule_id, object_id, mapping_type) PK.
  * RuleServiceMapping — by (rule_id, service_object_id|normalized_service_id, mapping_type).

NEVER stores secrets. Pure FK resolution: every normalized key in the result is
turned into a concrete PK before mappings are written.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from core.logging import get_logger
from models import models
from models.models import utcnow
from services.parsing.models import ParsedDevicePayload

from .canonical import object_key, service_key
from .model import NormalizationResult, NormalizedObjectRec, NormalizedServiceRec

logger = get_logger(__name__)

# Canonical key for the implicit ANY service (matches engine._resolve_services).
_ANY_SERVICE_KEY = service_key("any", None, None)


def _device_vendor_ids(db, device_ids) -> Dict[int, Optional[int]]:
    """Resolve device_id -> vendor_id for ownership stamping on vendor rows."""
    out: Dict[int, Optional[int]] = {}
    if not device_ids:
        return out
    rows = (
        db.query(models.FirewallDevice.device_id, models.FirewallDevice.vendor_id)
        .filter(models.FirewallDevice.device_id.in_(list(device_ids)))
        .all()
    )
    for did, vid in rows:
        out[did] = vid
    return out


def _upsert_normalized_object(db, rec: NormalizedObjectRec) -> models.NormalizedObject:
    """Upsert a canonical object by its natural key."""
    is_group = rec.canonical_type == "group"
    q = db.query(models.NormalizedObject)
    if is_group:
        q = q.filter(
            models.NormalizedObject.canonical_type == "group",
            models.NormalizedObject.canonical_name == rec.canonical_name,
        )
    else:
        q = q.filter(
            models.NormalizedObject.canonical_type == rec.canonical_type,
            models.NormalizedObject.canonical_value == rec.canonical_value,
        )
    row = q.first()
    if row is None:
        row = models.NormalizedObject(
            canonical_name=rec.canonical_name,
            canonical_type=rec.canonical_type,
            canonical_value=rec.canonical_value,
            sensitivity=rec.sensitivity,
        )
        db.add(row)
        db.flush()
    else:
        # Keep canonical attributes fresh (name/sensitivity may improve over polls).
        row.canonical_name = rec.canonical_name
        row.sensitivity = rec.sensitivity
        if not is_group:
            row.canonical_value = rec.canonical_value
    return row


def _upsert_normalized_service(db, rec: NormalizedServiceRec) -> models.NormalizedService:
    """Upsert a canonical service by app_id or (protocol, ports)."""
    q = db.query(models.NormalizedService)
    if rec.app_id:
        q = q.filter(models.NormalizedService.app_id == rec.app_id)
    else:
        q = q.filter(
            models.NormalizedService.protocol == rec.protocol,
            models.NormalizedService.port_start == rec.port_start,
            models.NormalizedService.port_end == rec.port_end,
            models.NormalizedService.app_id.is_(None),
        )
    row = q.first()
    if row is None:
        row = models.NormalizedService(
            canonical_name=rec.canonical_name,
            protocol=rec.protocol,
            port_start=rec.port_start,
            port_end=rec.port_end,
            app_id=rec.app_id,
        )
        db.add(row)
        db.flush()
    else:
        row.canonical_name = rec.canonical_name
    return row


def _upsert_network_object(db, device_id: int, vendor_id, name: str,
                           rec: Optional[NormalizedObjectRec]) -> models.NetworkObject:
    """Upsert a vendor network_object by (device_id, name)."""
    row = (
        db.query(models.NetworkObject)
        .filter(
            models.NetworkObject.device_id == device_id,
            models.NetworkObject.name == name,
        )
        .first()
    )
    ctype = rec.canonical_type if rec else "unknown"
    cvalue = rec.canonical_value if rec else name
    if row is None:
        row = models.NetworkObject(
            device_id=device_id,
            vendor_id=vendor_id,
            name=name,
            type=ctype,
            value=cvalue,
        )
        db.add(row)
        db.flush()
    else:
        row.type = ctype
        row.value = cvalue
        if vendor_id is not None:
            row.vendor_id = vendor_id
    return row


def _upsert_service_object(db, device_id: int, vendor_id, name: str,
                           rec: Optional[NormalizedServiceRec]) -> models.ServiceObject:
    """Upsert a vendor service_object by (device_id, name)."""
    row = (
        db.query(models.ServiceObject)
        .filter(
            models.ServiceObject.device_id == device_id,
            models.ServiceObject.name == name,
        )
        .first()
    )
    proto = rec.protocol if rec else "unknown"
    ps = rec.port_start if rec else None
    pe = rec.port_end if rec else None
    app_id = rec.app_id if rec else None
    if row is None:
        row = models.ServiceObject(
            device_id=device_id,
            vendor_id=vendor_id,
            name=name,
            protocol=proto,
            port_start=ps,
            port_end=pe,
            app_id=app_id,
        )
        db.add(row)
        db.flush()
    else:
        row.protocol = proto
        row.port_start = ps
        row.port_end = pe
        row.app_id = app_id
        if vendor_id is not None:
            row.vendor_id = vendor_id
    return row


def _upsert_object_norm_mapping(db, object_id: int, normalized_object_id: int,
                                method: str, confidence: float, reason: str) -> None:
    row = (
        db.query(models.ObjectNormalizationMapping)
        .filter(
            models.ObjectNormalizationMapping.object_id == object_id,
            models.ObjectNormalizationMapping.normalized_object_id == normalized_object_id,
        )
        .first()
    )
    if row is None:
        db.add(models.ObjectNormalizationMapping(
            object_id=object_id,
            normalized_object_id=normalized_object_id,
            match_method=method,
            confidence=confidence,
            mapping_reason=reason,
        ))
    else:
        row.match_method = method
        row.confidence = confidence
        row.mapping_reason = reason


def _upsert_service_norm_mapping(db, service_object_id: int, normalized_service_id: int,
                                 method: str, confidence: float, reason: str) -> None:
    row = (
        db.query(models.ServiceNormalizationMapping)
        .filter(
            models.ServiceNormalizationMapping.service_object_id == service_object_id,
            models.ServiceNormalizationMapping.normalized_service_id == normalized_service_id,
        )
        .first()
    )
    if row is None:
        db.add(models.ServiceNormalizationMapping(
            service_object_id=service_object_id,
            normalized_service_id=normalized_service_id,
            match_method=method,
            confidence=confidence,
            mapping_reason=reason,
        ))
    else:
        row.match_method = method
        row.confidence = confidence
        row.mapping_reason = reason


def _upsert_policy_rule(db, nr, vendor_type: str) -> models.PolicyRule:
    """Upsert a normalized rule by (device_id, vdom_vsys, vendor_uuid)."""
    row = (
        db.query(models.PolicyRule)
        .filter(
            models.PolicyRule.device_id == nr.device_id,
            models.PolicyRule.vendor_uuid == nr.vendor_uuid,
        )
    )
    if nr.vdom_vsys is None:
        row = row.filter(models.PolicyRule.vdom_vsys.is_(None))
    else:
        row = row.filter(models.PolicyRule.vdom_vsys == nr.vdom_vsys)
    rule = row.first()

    fields = dict(
        device_id=nr.device_id,
        vendor_rule_id=nr.vendor_rule_id,
        vendor_uuid=nr.vendor_uuid,
        vendor_type=vendor_type,
        vdom_vsys=nr.vdom_vsys,
        rule_name=nr.rule_name,
        rule_order=nr.rule_order,
        action=nr.action,
        is_active=nr.enabled,
        src_zone_interface=nr.src_zone,
        dst_zone_interface=nr.dst_zone,
        src_negate=nr.src_negate,
        dst_negate=nr.dst_negate,
        nat_enabled=nr.nat_enabled,
        security_profile_group=nr.security_profile_group,
        schedule_name=nr.schedule,
        description=nr.description,
        logging_enabled=nr.logging_enabled,
        security_inspection_enabled=nr.security_inspection_enabled,
        security_profile_strength=nr.security_profile_strength,
        schedule_scope=nr.schedule_scope,
        normalized_content_hash=nr.normalized_content_hash,
    )
    if rule is None:
        rule = models.PolicyRule(**fields)
        db.add(rule)
        db.flush()
    else:
        for k, v in fields.items():
            setattr(rule, k, v)
        rule.deleted_at = None
        rule.updated_at = utcnow()
    return rule


def _upsert_rule_object_mapping(db, rule_id: int, object_id: int,
                                mapping_type: str, direction: str) -> None:
    row = (
        db.query(models.RuleObjectMapping)
        .filter(
            models.RuleObjectMapping.rule_id == rule_id,
            models.RuleObjectMapping.object_id == object_id,
            models.RuleObjectMapping.mapping_type == mapping_type,
        )
        .first()
    )
    if row is None:
        db.add(models.RuleObjectMapping(
            rule_id=rule_id,
            object_id=object_id,
            mapping_type=mapping_type,
            direction=direction,
        ))
    else:
        row.direction = direction


def _upsert_rule_service_mapping(db, rule_id: int, service_object_id: Optional[int],
                                 normalized_service_id: Optional[int]) -> None:
    q = db.query(models.RuleServiceMapping).filter(
        models.RuleServiceMapping.rule_id == rule_id,
    )
    if service_object_id is not None:
        q = q.filter(models.RuleServiceMapping.service_object_id == service_object_id)
    else:
        q = q.filter(models.RuleServiceMapping.service_object_id.is_(None))
    if normalized_service_id is not None:
        q = q.filter(models.RuleServiceMapping.normalized_service_id == normalized_service_id)
    else:
        q = q.filter(models.RuleServiceMapping.normalized_service_id.is_(None))
    row = q.first()
    if row is None:
        db.add(models.RuleServiceMapping(
            rule_id=rule_id,
            service_object_id=service_object_id,
            normalized_service_id=normalized_service_id,
            mapping_type="service",
            direction="service",
        ))


def persist_result(db, result: NormalizationResult,
                   payloads: List[ParsedDevicePayload]) -> Dict[str, int]:
    """Idempotently persist a NormalizationResult into Schema v4.

    Returns a dict of insert/seen counts per table for logging/observability.
    """
    counts = {
        "normalized_objects": 0,
        "normalized_services": 0,
        "network_objects": 0,
        "service_objects": 0,
        "object_mappings": 0,
        "service_mappings": 0,
        "policy_rules": 0,
        "rule_object_mappings": 0,
        "rule_service_mappings": 0,
    }

    device_ids = {p.device_id for p in payloads}
    vendor_by_device = _device_vendor_ids(db, device_ids)
    vendor_type_by_device = {p.device_id: p.vendor for p in payloads}

    # ── 1) Canonical objects / services → key -> PK ──
    norm_obj_pk: Dict[str, int] = {}
    for key, rec in result.normalized_objects.items():
        row = _upsert_normalized_object(db, rec)
        norm_obj_pk[key] = row.normalized_object_id
        counts["normalized_objects"] += 1

    norm_svc_pk: Dict[str, int] = {}
    for key, rec in result.normalized_services.items():
        row = _upsert_normalized_service(db, rec)
        norm_svc_pk[key] = row.normalized_service_id
        counts["normalized_services"] += 1

    # ── 2) Vendor objects (network_object) per device, keyed by mapping rows ──
    # Build a quick lookup of normalized record by key for type/value stamping.
    # (device_id, name) -> network_object_id
    net_obj_pk: Dict[Tuple[int, str], int] = {}
    for m in result.object_mappings:
        vendor_id = vendor_by_device.get(m.device_id)
        rec = result.normalized_objects.get(m.normalized_key)
        no = _upsert_network_object(db, m.device_id, vendor_id, m.object_name, rec)
        net_obj_pk[(m.device_id, m.object_name)] = no.object_id
        counts["network_objects"] += 1
        nid = norm_obj_pk.get(m.normalized_key)
        if nid is not None:
            _upsert_object_norm_mapping(
                db, no.object_id, nid, m.match_method, m.confidence, m.reason)
            counts["object_mappings"] += 1

    # ── 3) Vendor services (service_object) per device ──
    # (device_id, name) -> service_object_id
    svc_obj_pk: Dict[Tuple[int, str], int] = {}
    for m in result.service_mappings:
        vendor_id = vendor_by_device.get(m.device_id)
        rec = result.normalized_services.get(m.normalized_key)
        so = _upsert_service_object(db, m.device_id, vendor_id, m.service_name, rec)
        svc_obj_pk[(m.device_id, m.service_name)] = so.service_object_id
        counts["service_objects"] += 1
        nsid = norm_svc_pk.get(m.normalized_key)
        if nsid is not None:
            _upsert_service_norm_mapping(
                db, so.service_object_id, nsid, m.match_method, m.confidence, m.reason)
            counts["service_mappings"] += 1

    db.flush()

    # ── 4) Rules + rule_object_mapping + rule_service_mapping ──
    for nr in result.rules:
        vendor_type = vendor_type_by_device.get(nr.device_id, nr.vendor)
        rule = _upsert_policy_rule(db, nr, vendor_type)
        counts["policy_rules"] += 1

        # Source / destination object mappings (via network_object).
        for names, keys, mtype in (
            (nr.src_object_names, nr.src_object_keys, "source"),
            (nr.dst_object_names, nr.dst_object_keys, "destination"),
        ):
            for idx, name in enumerate(names):
                oid = net_obj_pk.get((nr.device_id, name))
                if oid is None:
                    # Object never produced a vendor row (e.g. implicit ANY / unresolved):
                    # materialize a vendor network_object so the rule mapping is complete.
                    key = keys[idx] if idx < len(keys) else None
                    rec = result.normalized_objects.get(key) if key else None
                    vendor_id = vendor_by_device.get(nr.device_id)
                    no = _upsert_network_object(db, nr.device_id, vendor_id, name, rec)
                    oid = no.object_id
                    net_obj_pk[(nr.device_id, name)] = oid
                    counts["network_objects"] += 1
                    nid = norm_obj_pk.get(key) if key else None
                    if nid is not None:
                        _upsert_object_norm_mapping(
                            db, oid, nid, "derived", 1.0,
                            "materialized from rule reference")
                        counts["object_mappings"] += 1
                _upsert_rule_object_mapping(db, rule.rule_id, oid, mtype, mtype)
                counts["rule_object_mappings"] += 1

        # Service mappings (via service_object when available, else normalized only).
        for idx, name in enumerate(nr.service_names):
            key = nr.service_keys[idx] if idx < len(nr.service_keys) else None
            soid = svc_obj_pk.get((nr.device_id, name))
            nsid = norm_svc_pk.get(key) if key else None
            _upsert_rule_service_mapping(db, rule.rule_id, soid, nsid)
            counts["rule_service_mappings"] += 1

        # Rules with no explicit service reference imply ANY service.
        if not nr.service_names:
            nsid = norm_svc_pk.get(_ANY_SERVICE_KEY)
            _upsert_rule_service_mapping(db, rule.rule_id, None, nsid)
            counts["rule_service_mappings"] += 1

    db.commit()
    logger.info("persist_result: %s", counts)
    return counts
