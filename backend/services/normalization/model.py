"""Normalization result models — the pure, DB-independent output of the engine.

These mirror the persisted Schema v4 tables but carry correlation keys so the
persist layer can resolve foreign keys deterministically.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class NormalizedObjectRec:
    key: str                     # object_key(type, value)
    canonical_name: str
    canonical_type: str
    canonical_value: str
    sensitivity: str


@dataclass
class ObjectMappingRec:
    device_id: int
    vendor: str
    object_name: str             # vendor object name (network_object.name)
    normalized_key: str
    match_method: str            # exact_name_value | exact_value | name_similarity | derived
    confidence: float
    reason: str


@dataclass
class NormalizedServiceRec:
    key: str                     # service_key(...)
    canonical_name: str
    protocol: str
    port_start: Optional[int]
    port_end: Optional[int]
    app_id: Optional[str]


@dataclass
class ServiceMappingRec:
    device_id: int
    vendor: str
    service_name: str
    normalized_key: str
    match_method: str            # exact_port | exact_name_port | app_id | derived
    confidence: float
    reason: str


@dataclass
class NormalizedRule:
    device_id: int
    vendor: str
    rule_name: str
    rule_order: int
    vendor_rule_id: Optional[str]
    vendor_uuid: str             # real or derived (stable)
    vdom_vsys: Optional[str]
    enabled: bool
    src_zone: str
    dst_zone: str
    action: str                  # canonical
    logging_enabled: str         # true|false|unknown
    security_inspection_enabled: str
    security_profile_group: Optional[str]
    security_profile_strength: str
    schedule: Optional[str]
    schedule_scope: str
    nat_enabled: Optional[bool]
    description: Optional[str]
    src_negate: bool
    dst_negate: bool
    src_object_keys: List[str] = field(default_factory=list)
    dst_object_keys: List[str] = field(default_factory=list)
    service_keys: List[str] = field(default_factory=list)
    # vendor object/service names as referenced by the rule (for rule_object_mapping)
    src_object_names: List[str] = field(default_factory=list)
    dst_object_names: List[str] = field(default_factory=list)
    service_names: List[str] = field(default_factory=list)
    normalized_content_hash: str = ""


@dataclass
class NormalizationResult:
    normalized_objects: Dict[str, NormalizedObjectRec] = field(default_factory=dict)
    object_mappings: List[ObjectMappingRec] = field(default_factory=list)
    normalized_services: Dict[str, NormalizedServiceRec] = field(default_factory=dict)
    service_mappings: List[ServiceMappingRec] = field(default_factory=list)
    rules: List[NormalizedRule] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
