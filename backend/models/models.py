from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Boolean, Float, Text,
    DateTime, ForeignKey, UniqueConstraint, Index, text,create_engine
)
from sqlalchemy.orm import declarative_base, relationship,sessionmaker
from os import getenv

Base = declarative_base()

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
    name = Column(String(100), nullable=False)
    type = Column(String(50), nullable=False)
    value = Column(String(255), nullable=False)

    rule_mappings = relationship("RuleObjectMapping", back_populates="network_object", cascade="all, delete-orphan")

    __table_args__ = (
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
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    device = relationship("FirewallDevice", back_populates="rules")
    object_mappings = relationship("RuleObjectMapping", back_populates="rule", cascade="all, delete-orphan")
    anomalies = relationship("RuleAnomaly", back_populates="rule", cascade="all, delete-orphan")

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

class RuleAnomaly(Base):
    __tablename__ = "rule_anomaly"

    anomaly_id = Column(Integer, primary_key=True, autoincrement=True)
    rule_id = Column(Integer, ForeignKey("policy_rule.rule_id"), nullable=False)
    anomaly_type = Column(String(100), nullable=False)
    severity_level = Column(String(20), nullable=False)
    related_rule_id = Column(String(100), nullable=True)  # e.g., 'POL-002' or vendor_rule_id of shadowed rule
    description = Column(Text, nullable=True)
    detected_at = Column(DateTime, default=datetime.utcnow)

    rule = relationship("PolicyRule", back_populates="anomalies")

    __table_args__ = (
        Index("idx_anomaly_rule", "rule_id"),
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
