from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Boolean, Float, Text,
    DateTime, ForeignKey, UniqueConstraint, Index, text, create_engine
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from os import getenv

Base = declarative_base()


def utcnow() -> datetime:
    """Timezone-aware UTC now.

    Volume 5 §14 requires all timestamps stored consistently in UTC. ``datetime.utcnow``
    is deprecated (Python 3.12+) and returns a naive value; use this helper instead.
    """
    return datetime.now(timezone.utc)

_engine = None

def get_engine():
    global _engine
    if _engine is None:
        DATABASE_URL = getenv("DATABASE_URL")
        # Echo is set to False to avoid flooding production logs
        _engine = create_engine(DATABASE_URL, echo=False)
    return _engine

def get_db():
    engine = get_engine()
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Vendor(Base):
    __tablename__ = "vendor"

    vendor_id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    api_type = Column(String(50), nullable=False)
    support_contact = Column(String(200), nullable=True)

    devices = relationship("FirewallDevice", back_populates="vendor", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Vendor(vendor_id={self.vendor_id}, name='{self.name}')>"

class Administrator(Base):
    __tablename__ = "administrator"

    admin_id = Column(Integer, primary_key=True, autoincrement=True)
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)

    assignments = relationship("AdminDeviceAssignment", back_populates="administrator", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Administrator(admin_id={self.admin_id}, name='{self.first_name} {self.last_name}')>"

class FirewallDevice(Base):
    __tablename__ = "firewall_device"

    device_id = Column(Integer, primary_key=True, autoincrement=True)
    vendor_id = Column(Integer, ForeignKey("vendor.vendor_id"), nullable=False)
    # Semantic vendor for connector dispatch: 'fortinet' | 'paloalto' (V3 Table 8).
    # Nullable for legacy rows; resolved from the vendor when absent.
    vendor_type = Column(String(20), nullable=True)
    hostname = Column(String(255), nullable=False)
    firmware_version = Column(String(50), nullable=True)
    management_ip = Column(String(45), nullable=False)
    location = Column(String(255), nullable=True)
    uptime = Column(String(50), nullable=True)
    throughput = Column(String(50), nullable=True)
    last_poll_time = Column(DateTime, nullable=True)
    status = Column(String(20), default="unknown")

    vendor = relationship("Vendor", back_populates="devices")
    assignments = relationship("AdminDeviceAssignment", back_populates="device", cascade="all, delete-orphan")
    rules = relationship("PolicyRule", back_populates="device", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<FirewallDevice(device_id={self.device_id}, hostname='{self.hostname}')>"

class AdminDeviceAssignment(Base):
    __tablename__ = "admin_device_assignment"

    admin_id = Column(Integer, ForeignKey("administrator.admin_id"), primary_key=True)
    device_id = Column(Integer, ForeignKey("firewall_device.device_id"), primary_key=True)
    assigned_at = Column(DateTime, default=datetime.utcnow)
    role = Column(String(50), nullable=False)

    administrator = relationship("Administrator", back_populates="assignments")
    device = relationship("FirewallDevice", back_populates="assignments")

    def __repr__(self):
        return f"<AdminDeviceAssignment(admin_id={self.admin_id}, device_id={self.device_id}, role='{self.role}')>"

class NetworkObject(Base):
    __tablename__ = "network_object"

    object_id = Column(Integer, primary_key=True, autoincrement=True)
    # ── Schema v4 ownership fields (V4 §7.3, V5 Table 4) ──
    # Nullable for backward compatibility with pre-v4 rows; set by the normalization layer.
    device_id = Column(Integer, ForeignKey("firewall_device.device_id"), nullable=True)
    vendor_id = Column(Integer, ForeignKey("vendor.vendor_id"), nullable=True)
    vendor_object_id = Column(String(100), nullable=True)
    vendor_uuid = Column(String(100), nullable=True)
    name = Column(String(100), nullable=False)
    # type: ip_address | cidr | fqdn | group | any | application | url_category
    type = Column(String(50), nullable=False)
    value = Column(String(255), nullable=False)          # canonical value
    raw_value = Column(String(255), nullable=True)        # original extracted value
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    rule_mappings = relationship("RuleObjectMapping", back_populates="network_object", cascade="all, delete-orphan")
    normalization_mappings = relationship(
        "ObjectNormalizationMapping", back_populates="network_object", cascade="all, delete-orphan"
    )

    __table_args__ = (
        # V5 Table 12: object expansion/lookup index
        Index("idx_netobj_device_type_value", "device_id", "type", "value"),
        Index("idx_netobj_type", "type"),
    )

    def __repr__(self):
        return f"<NetworkObject(object_id={self.object_id}, name='{self.name}')>"

class PolicyRule(Base):
    __tablename__ = "policy_rule"

    rule_id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey("firewall_device.device_id"), nullable=False)
    vendor_rule_id = Column(String(50), nullable=True)
    vendor_uuid = Column(String(100), nullable=True)
    vendor_type = Column(String(20), nullable=False)
    vdom_vsys = Column(String(100), nullable=True)
    rule_name = Column(String(200), nullable=False)
    rule_order = Column(Integer, nullable=False)
    action = Column(String(20), nullable=False)
    is_active = Column(Boolean, default=True)
    src_zone_interface = Column(String(255), nullable=True)
    dst_zone_interface = Column(String(255), nullable=True)
    rule_type = Column(String(20), nullable=True)
    tags = Column(String(500), nullable=True)
    src_negate = Column(Boolean, default=False, nullable=False)
    dst_negate = Column(Boolean, default=False, nullable=False)
    nat_enabled = Column(Boolean, nullable=True)
    log_setting = Column(String(100), nullable=True)
    security_profile_group = Column(String(100), nullable=True)
    schedule_name = Column(String(100), nullable=True)
    description = Column(Text, nullable=True)
    # ── Schema v4 canonical posture fields (V4 §11, Table 16) ──
    # Tri-state strings: 'true' | 'false' | 'unknown'
    logging_enabled = Column(String(10), nullable=True)
    logging_mode = Column(String(20), nullable=True)      # all|security-event|profile|disabled|unknown
    security_inspection_enabled = Column(String(10), nullable=True)
    security_profile_strength = Column(String(10), nullable=True)  # strong|weak|missing|unknown
    schedule_scope = Column(String(20), nullable=True)    # always|limited|unknown
    # Change detection + soft delete (V4 §12, V5 §12)
    normalized_content_hash = Column(String(64), nullable=True)
    deleted_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    device = relationship("FirewallDevice", back_populates="rules")
    object_mappings = relationship("RuleObjectMapping", back_populates="rule", cascade="all, delete-orphan")
    # rule_anomaly has two FKs to policy_rule (rule_id, related_rule_id); disambiguate.
    anomalies = relationship(
        "RuleAnomaly", back_populates="rule",
        foreign_keys="RuleAnomaly.rule_id", cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("idx_rule_vendor_uuid", "device_id", "vdom_vsys", "vendor_uuid",
              unique=True,
              postgresql_where=text("vendor_uuid IS NOT NULL")),
        Index("idx_rule_device_order", "device_id", "vdom_vsys", "rule_order"),
        Index("idx_rule_vendor_type", "vendor_type"),
    )

    def __repr__(self):
        return f"<PolicyRule(rule_id={self.rule_id}, rule_name='{self.rule_name}')>"

class RuleObjectMapping(Base):
    __tablename__ = "rule_object_mapping"

    rule_id = Column(Integer, ForeignKey("policy_rule.rule_id"), primary_key=True)
    object_id = Column(Integer, ForeignKey("network_object.object_id"), primary_key=True)
    mapping_type = Column(String(50), primary_key=True)
    direction = Column(String(20), default="both")

    rule = relationship("PolicyRule", back_populates="object_mappings")
    network_object = relationship("NetworkObject", back_populates="rule_mappings")

    def __repr__(self):
        return f"<RuleObjectMapping(rule_id={self.rule_id}, object_id={self.object_id}, mapping_type='{self.mapping_type}')>"

class RuleServiceMapping(Base):
    """Maps a policy_rule to its (vendor and/or canonical) service objects.

    Mirrors RuleObjectMapping but for the service axis. Either service_object_id
    (vendor-owned) or normalized_service_id (canonical) may be set. No ORM
    relationships are declared to avoid ambiguous joins; mapping is by FK only.
    """
    __tablename__ = "rule_service_mapping"

    mapping_id = Column(Integer, primary_key=True, autoincrement=True)
    rule_id = Column(Integer, ForeignKey("policy_rule.rule_id"), nullable=False)
    service_object_id = Column(Integer, ForeignKey("service_object.service_object_id"), nullable=True)
    normalized_service_id = Column(Integer, ForeignKey("normalized_service.normalized_service_id"), nullable=True)
    mapping_type = Column(String(50), default="service", nullable=False)
    direction = Column(String(20), default="service", nullable=False)

    __table_args__ = (Index("idx_rulesvcmap_rule", "rule_id"),)

    def __repr__(self):
        return f"<RuleServiceMapping(mapping_id={self.mapping_id}, rule_id={self.rule_id})>"


class RuleAnomaly(Base):
    """Durable anomaly finding — full V6 output contract (V5 Table 9, V6 Table 3)."""
    __tablename__ = "rule_anomaly"

    anomaly_id = Column(Integer, primary_key=True, autoincrement=True)
    rule_id = Column(Integer, ForeignKey("policy_rule.rule_id"), nullable=False)
    # related rule for pairwise findings (conflict/shadowing/...) — now a real FK (was String)
    related_rule_id = Column(Integer, ForeignKey("policy_rule.rule_id"), nullable=True)
    anomaly_type = Column(String(100), nullable=False)     # taxonomy value
    severity_level = Column(String(20), nullable=False)    # critical|high|medium|low
    confidence = Column(Float, nullable=True)              # 0.00–1.00
    description = Column(Text, nullable=True)              # technical_reason
    evidence = Column(JSONB, nullable=True)                # rule fields/objects that caused the finding
    recommendation = Column(Text, nullable=True)
    detection_mode = Column(String(20), nullable=True)     # config_only|conditional|simulated|future_enhanced
    analysis_run_id = Column(Integer, ForeignKey("anomaly_execution_log.run_id"), nullable=True)
    status = Column(String(20), default="open", nullable=False)  # open|resolved|suppressed|accepted_risk|false_positive
    suppression_reason = Column(Text, nullable=True)
    suppressed_by = Column(Integer, ForeignKey("administrator.admin_id"), nullable=True)
    suppression_expires_at = Column(DateTime(timezone=True), nullable=True)
    detected_at = Column(DateTime(timezone=True), default=utcnow)

    rule = relationship("PolicyRule", back_populates="anomalies", foreign_keys=[rule_id])
    related_rule = relationship("PolicyRule", foreign_keys=[related_rule_id])
    execution_run = relationship("AnomalyExecutionLog", back_populates="findings")

    __table_args__ = (
        Index("idx_anomaly_rule", "rule_id"),
        Index("idx_anomaly_run", "analysis_run_id"),
    )

    def __repr__(self):
        return f"<RuleAnomaly(anomaly_id={self.anomaly_id}, anomaly_type='{self.anomaly_type}')>"


class ExternalNode(Base):
    __tablename__ = "external_node"
    node_id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    ip_address = Column(String(45), nullable=False)
    node_type = Column(String(50), nullable=False)  # 'threat_actor', 'partner', 'cloud_service', etc.
    description = Column(Text, nullable=True)
    
    def __repr__(self):
        return f"<ExternalNode(node_id={self.node_id}, name='{self.name}')>"

class ThreatFeed(Base):
    __tablename__ = "threat_feed"
    feed_id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    url = Column(String(255), nullable=False)
    status = Column(String(20), default="active")
    last_sync = Column(DateTime, nullable=True)
    
    def __repr__(self):
        return f"<ThreatFeed(feed_id={self.feed_id}, name='{self.name}')>"

class APIToken(Base):
    __tablename__ = "api_token"
    token_id = Column(Integer, primary_key=True, autoincrement=True)
    admin_id = Column(Integer, ForeignKey("administrator.admin_id"), nullable=False)
    name = Column(String(100), nullable=False)
    token_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    last_used = Column(DateTime, nullable=True)
    
    def __repr__(self):
        return f"<APIToken(token_id={self.token_id}, name='{self.name}')>"

class AuditLog(Base):
    __tablename__ = "audit_log"
    log_id = Column(Integer, primary_key=True, autoincrement=True)
    admin_id = Column(Integer, ForeignKey("administrator.admin_id"), nullable=True)
    action = Column(String(100), nullable=False)
    target_type = Column(String(50), nullable=False)
    target_id = Column(String(100), nullable=True)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<AuditLog(log_id={self.log_id}, action='{self.action}')>"

class SavedSearch(Base):
    __tablename__ = "saved_search"
    search_id = Column(Integer, primary_key=True, autoincrement=True)
    admin_id = Column(Integer, ForeignKey("administrator.admin_id"), nullable=False)
    name = Column(String(100), nullable=False)
    query_string = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<SavedSearch(search_id={self.search_id}, name='{self.name}')>"


# =====================================================================
# LUMINA SCHEMA v4 — NEW TABLES (Volume 5 + Volume 4)
# Frozen data contract. See docs/DATABASE_SCHEMA_V4.md.
# =====================================================================

# ── Normalization: object & service correlation model (V4 §7-8) ──

class NormalizedObject(Base):
    """Canonical object above vendor-owned network_object rows (V4 §7.4)."""
    __tablename__ = "normalized_object"

    normalized_object_id = Column(Integer, primary_key=True, autoincrement=True)
    canonical_name = Column(String(100), nullable=False)
    canonical_type = Column(String(30), nullable=False)   # ip_address|cidr|fqdn|group|any|unknown
    canonical_value = Column(String(255), nullable=True)
    sensitivity = Column(String(20), nullable=True)        # public|internal|dmz|database|admin|critical|unknown
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    mappings = relationship(
        "ObjectNormalizationMapping", back_populates="normalized_object", cascade="all, delete-orphan"
    )


class ObjectNormalizationMapping(Base):
    """Maps vendor network_object → canonical normalized_object (V4 §7.5)."""
    __tablename__ = "object_normalization_mapping"

    mapping_id = Column(Integer, primary_key=True, autoincrement=True)
    object_id = Column(Integer, ForeignKey("network_object.object_id"), nullable=False)
    normalized_object_id = Column(Integer, ForeignKey("normalized_object.normalized_object_id"), nullable=False)
    match_method = Column(String(30), nullable=False)      # exact_name_value|exact_value|name_similarity|manual|derived
    confidence = Column(Float, nullable=True)              # 0.00–1.00
    mapping_reason = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    network_object = relationship("NetworkObject", back_populates="normalization_mappings")
    normalized_object = relationship("NormalizedObject", back_populates="mappings")

    __table_args__ = (
        Index("idx_objnorm_normalized", "normalized_object_id"),
        UniqueConstraint("object_id", "normalized_object_id", name="uq_object_normalization"),
    )


class ServiceObject(Base):
    """Vendor-owned service object (protocol/port/app) — distinct from address objects."""
    __tablename__ = "service_object"

    service_object_id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey("firewall_device.device_id"), nullable=True)
    vendor_id = Column(Integer, ForeignKey("vendor.vendor_id"), nullable=True)
    vendor_service_id = Column(String(100), nullable=True)
    name = Column(String(100), nullable=False)
    protocol = Column(String(20), nullable=True)           # tcp|udp|icmp|application|any|unknown
    port_start = Column(Integer, nullable=True)
    port_end = Column(Integer, nullable=True)
    app_id = Column(String(100), nullable=True)            # PAN-OS App-ID
    raw_value = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    __table_args__ = (Index("idx_serviceobj_device", "device_id", "name"),)


class NormalizedService(Base):
    """Canonical service/protocol/port/application (V4 §8.1)."""
    __tablename__ = "normalized_service"

    normalized_service_id = Column(Integer, primary_key=True, autoincrement=True)
    canonical_name = Column(String(100), nullable=False)   # e.g. HTTPS, MYSQL
    protocol = Column(String(20), nullable=False)          # tcp|udp|icmp|application|any|unknown
    port_start = Column(Integer, nullable=True)
    port_end = Column(Integer, nullable=True)
    app_id = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    mappings = relationship(
        "ServiceNormalizationMapping", back_populates="normalized_service", cascade="all, delete-orphan"
    )


class ServiceNormalizationMapping(Base):
    """Maps vendor service_object → canonical normalized_service (V4 §8.1)."""
    __tablename__ = "service_normalization_mapping"

    mapping_id = Column(Integer, primary_key=True, autoincrement=True)
    service_object_id = Column(Integer, ForeignKey("service_object.service_object_id"), nullable=False)
    normalized_service_id = Column(Integer, ForeignKey("normalized_service.normalized_service_id"), nullable=False)
    match_method = Column(String(30), nullable=False)      # exact_port|exact_name_port|app_id|manual|derived
    confidence = Column(Float, nullable=True)
    mapping_reason = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    normalized_service = relationship("NormalizedService", back_populates="mappings")

    __table_args__ = (
        Index("idx_svcnorm_normalized", "normalized_service_id"),
        UniqueConstraint("service_object_id", "normalized_service_id", name="uq_service_normalization"),
    )


class NormalizationWarning(Base):
    """Unsupported/ambiguous/low-confidence transformation record (V4 §14.1)."""
    __tablename__ = "normalization_warning"

    warning_id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey("firewall_device.device_id"), nullable=True)
    rule_id = Column(Integer, ForeignKey("policy_rule.rule_id"), nullable=True)
    object_id = Column(Integer, ForeignKey("network_object.object_id"), nullable=True)
    warning_type = Column(String(40), nullable=False)      # unsupported_field|ambiguous_mapping|group_cycle|unknown_service|missing_uuid
    severity = Column(String(10), nullable=True)           # low|medium|high
    message = Column(Text, nullable=True)
    raw_reference = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class RuleSnapshot(Base):
    """Historical normalized rule version for drift/change-frequency/audit (V4 §14)."""
    __tablename__ = "rule_snapshot"

    snapshot_id = Column(Integer, primary_key=True, autoincrement=True)
    rule_id = Column(Integer, ForeignKey("policy_rule.rule_id"), nullable=False)
    device_id = Column(Integer, ForeignKey("firewall_device.device_id"), nullable=True)
    normalized_content_hash = Column(String(64), nullable=True)
    snapshot = Column(JSONB, nullable=True)                # full normalized rule at poll time
    job_id = Column(Integer, ForeignKey("acquisition_job.job_id"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (Index("idx_rulesnap_rule", "rule_id", "created_at"),)


# ── Analysis: execution log (V6 §11) ──

class AnomalyExecutionLog(Base):
    """One anomaly-engine run (V5 Table 4, V6 §11)."""
    __tablename__ = "anomaly_execution_log"

    run_id = Column(Integer, primary_key=True, autoincrement=True)
    scope_type = Column(String(20), nullable=False)        # device|all|benchmark
    scope_id = Column(Integer, nullable=True)
    started_at = Column(DateTime(timezone=True), default=utcnow)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(String(20), default="running", nullable=False)  # running|completed|failed|partial
    findings_count = Column(Integer, default=0)
    error_log = Column(JSONB, nullable=True)
    engine_version = Column(String(40), nullable=True)

    findings = relationship("RuleAnomaly", back_populates="execution_run")


# ── Risk (V8 §11) ──

class RiskAssessment(Base):
    """Rule/device/object risk score + factor breakdown (V8 §11)."""
    __tablename__ = "risk_assessment"

    risk_id = Column(Integer, primary_key=True, autoincrement=True)
    scope_type = Column(String(20), nullable=False)        # rule|device|object
    scope_id = Column(Integer, nullable=False)
    risk_score = Column(Integer, nullable=False)           # 0–100
    risk_tier = Column(String(20), nullable=False)         # critical|high|medium|low|informational
    factor_breakdown = Column(JSONB, nullable=True)
    calculated_at = Column(DateTime(timezone=True), default=utcnow)
    calculation_version = Column(String(20), nullable=True)
    analysis_run_id = Column(Integer, ForeignKey("anomaly_execution_log.run_id"), nullable=True)

    __table_args__ = (Index("idx_risk_scope", "scope_type", "scope_id", "calculated_at"),)


# ── CTI (V9 §7) ──

class CtiIndicator(Base):
    """Extracted threat indicator (V9 §7)."""
    __tablename__ = "cti_indicator"

    indicator_id = Column(Integer, primary_key=True, autoincrement=True)
    type = Column(String(30), nullable=False)              # ip_address|cidr|fqdn|url|cve|firmware_version|vendor_version_keyword
    value = Column(String(255), nullable=False)
    source_object_id = Column(Integer, ForeignKey("network_object.object_id"), nullable=True)
    source_device_id = Column(Integer, ForeignKey("firewall_device.device_id"), nullable=True)
    is_public = Column(Boolean, default=True)
    first_seen = Column(DateTime(timezone=True), default=utcnow)
    last_seen = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    observations = relationship("CtiObservation", back_populates="indicator", cascade="all, delete-orphan")

    __table_args__ = (Index("idx_cti_type_value", "type", "value"),)


class CtiObservation(Base):
    """Provider result for an indicator (V9 §7)."""
    __tablename__ = "cti_observation"

    observation_id = Column(Integer, primary_key=True, autoincrement=True)
    indicator_id = Column(Integer, ForeignKey("cti_indicator.indicator_id"), nullable=False)
    provider = Column(String(40), nullable=False)          # abuseipdb|otx|virustotal|nvd|vendor_advisory|...
    provider_reference = Column(String(255), nullable=True)
    severity = Column(String(20), nullable=True)
    confidence = Column(Float, nullable=True)
    threat_type = Column(String(40), nullable=True)        # malware|c2|scanner|exploit|botnet|vulnerability|...
    summary = Column(Text, nullable=True)
    raw_response_hash = Column(String(64), nullable=True)
    observed_at = Column(DateTime(timezone=True), default=utcnow)

    indicator = relationship("CtiIndicator", back_populates="observations")


# ── AI reporting (V10 §9) ──

class LlmReport(Base):
    """Evidence-grounded AI report (V10 §9)."""
    __tablename__ = "llm_report"

    report_id = Column(Integer, primary_key=True, autoincrement=True)
    scope_type = Column(String(20), nullable=False)        # rule|device|scan|executive
    scope_id = Column(Integer, nullable=True)
    provider = Column(String(20), nullable=False)          # gemini|openai|ollama
    model = Column(String(80), nullable=True)
    prompt_version = Column(String(40), nullable=True)
    evidence_refs = Column(JSONB, nullable=True)           # DB evidence IDs
    output = Column(Text, nullable=True)                   # legacy/back-compat: the AI prose
    # ── Structured report (V10 §8) — deterministic sections + downloadable render ──
    document = Column(JSONB, nullable=True)                # deterministic structured sections (tables)
    markdown = Column(Text, nullable=True)                 # full GFM render (summary + tables) for download
    executive_summary = Column(Text, nullable=True)        # AI-authored executive summary ONLY
    confidence_note = Column(Text, nullable=True)
    status = Column(String(20), default="complete")        # complete|partial|failed
    created_at = Column(DateTime(timezone=True), default=utcnow)


# ── Benchmark (V7) ──

class BenchmarkCase(Base):
    """Ground-truth expected anomaly (V5 Table 11, V7)."""
    __tablename__ = "benchmark_case"

    case_id = Column(Integer, primary_key=True, autoincrement=True)
    case_type = Column(String(20), nullable=False)         # atomic|compound
    anomaly_type = Column(String(100), nullable=False)
    device_a_id = Column(Integer, ForeignKey("firewall_device.device_id"), nullable=True)
    rule_a_id = Column(Integer, ForeignKey("policy_rule.rule_id"), nullable=True)
    device_b_id = Column(Integer, ForeignKey("firewall_device.device_id"), nullable=True)
    rule_b_id = Column(Integer, ForeignKey("policy_rule.rule_id"), nullable=True)
    expected_severity = Column(String(20), nullable=True)  # critical|high|medium|low
    expected_reason = Column(Text, nullable=True)
    detection_mode = Column(String(20), nullable=True)     # config_only|conditional|simulated|future_enhanced
    required_fields = Column(JSONB, nullable=True)

    results = relationship("BenchmarkResult", back_populates="case", cascade="all, delete-orphan")


class BenchmarkResult(Base):
    """Detected-vs-expected outcome (V7)."""
    __tablename__ = "benchmark_result"

    result_id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("benchmark_case.case_id"), nullable=False)
    analysis_run_id = Column(Integer, ForeignKey("anomaly_execution_log.run_id"), nullable=True)
    detected = Column(Boolean, default=False)
    detected_anomaly_id = Column(Integer, ForeignKey("rule_anomaly.anomaly_id"), nullable=True)
    match_quality = Column(String(20), nullable=True)      # exact|partial|none
    false_positive = Column(Boolean, default=False)
    false_negative = Column(Boolean, default=False)
    notes = Column(Text, nullable=True)

    case = relationship("BenchmarkCase", back_populates="results")


# ── Acquisition (V3 §6-8) ──

class AcquisitionJob(Base):
    """Async firewall extraction job + lifecycle (V3 §7)."""
    __tablename__ = "acquisition_job"

    job_id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey("firewall_device.device_id"), nullable=False)
    vendor_type = Column(String(20), nullable=True)
    requested_by = Column(String(80), nullable=True)       # admin id or 'scheduler'
    status = Column(String(30), default="queued", nullable=False)
    # queued|running|success|partial_success|failed|timeout|authentication_failed|
    # authorization_failed|connection_failed|rate_limited|parsing_queued|parsing_failed
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    duration_ms = Column(Integer, nullable=True)
    connector_version = Column(String(40), nullable=True)
    error_code = Column(String(40), nullable=True)
    error_message = Column(Text, nullable=True)            # safe summary — NO secrets
    created_at = Column(DateTime(timezone=True), default=utcnow)

    artifacts = relationship("RawArtifact", back_populates="job", cascade="all, delete-orphan")

    __table_args__ = (Index("idx_acqjob_device_status", "device_id", "status"),)


class RawArtifact(Base):
    """Stored raw API response for replay/audit (V3 §8)."""
    __tablename__ = "raw_artifact"

    artifact_id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(Integer, ForeignKey("acquisition_job.job_id"), nullable=False)
    device_id = Column(Integer, ForeignKey("firewall_device.device_id"), nullable=True)
    type = Column(String(40), nullable=False)              # policies|address_objects|...|device_metadata|manifest
    path = Column(String(500), nullable=True)
    sha256 = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    job = relationship("AcquisitionJob", back_populates="artifacts")


class DeviceCredential(Base):
    """Encrypted per-device firewall credential (V3 §6.2, V12 §6).

    secret_encrypted is ciphertext (Fernet/ENCRYPTION_KEY); decrypted only in
    backend/worker memory. NEVER returned to the frontend, NEVER logged.
    """
    __tablename__ = "device_credential"

    credential_id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey("firewall_device.device_id"), nullable=False)
    auth_type = Column(String(30), nullable=False)         # fortigate_api_token|panos_api_key|panos_userpass
    secret_encrypted = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    rotated_at = Column(DateTime(timezone=True), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (Index("idx_devcred_device", "device_id"),)
