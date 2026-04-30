from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


# =====================================================================
# VENDOR SCHEMAS
# =====================================================================

class VendorBase(BaseModel):
    name: str
    api_type: str
    support_contact: Optional[str] = None

class VendorCreate(VendorBase):
    pass

class VendorUpdate(BaseModel):
    name: Optional[str] = None
    api_type: Optional[str] = None
    support_contact: Optional[str] = None

class VendorResponse(VendorBase):
    model_config = ConfigDict(from_attributes=True)
    vendor_id: int


# =====================================================================
# ADMINISTRATOR SCHEMAS
# =====================================================================

class AdministratorBase(BaseModel):
    first_name: str
    last_name: str

class AdministratorCreate(AdministratorBase):
    pass

class AdministratorUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None

class AdministratorResponse(AdministratorBase):
    model_config = ConfigDict(from_attributes=True)
    admin_id: int


# =====================================================================
# FIREWALL DEVICE SCHEMAS
# =====================================================================

class DeviceBase(BaseModel):
    vendor_id: int
    hostname: str
    management_ip: str
    firmware_version: Optional[str] = None
    last_poll_time: Optional[datetime] = None
    status: Optional[str] = "unknown"

class DeviceCreate(DeviceBase):
    pass

class DeviceUpdate(BaseModel):
    vendor_id: Optional[int] = None
    hostname: Optional[str] = None
    management_ip: Optional[str] = None
    firmware_version: Optional[str] = None
    last_poll_time: Optional[datetime] = None
    status: Optional[str] = None

class DeviceResponse(DeviceBase):
    model_config = ConfigDict(from_attributes=True)
    device_id: int


# =====================================================================
# ADMIN-DEVICE ASSIGNMENT SCHEMAS
# =====================================================================

class AdminDeviceAssignmentBase(BaseModel):
    admin_id: int
    device_id: int
    role: str

class AdminDeviceAssignmentCreate(AdminDeviceAssignmentBase):
    pass

class AdminDeviceAssignmentResponse(AdminDeviceAssignmentBase):
    model_config = ConfigDict(from_attributes=True)
    assigned_at: Optional[datetime] = None


# =====================================================================
# NETWORK OBJECT SCHEMAS
# =====================================================================

class NetworkObjectBase(BaseModel):
    name: str
    type: str
    value: str

class NetworkObjectCreate(NetworkObjectBase):
    pass

class NetworkObjectUpdate(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = None
    value: Optional[str] = None

class NetworkObjectResponse(NetworkObjectBase):
    model_config = ConfigDict(from_attributes=True)
    object_id: int


# =====================================================================
# POLICY RULE SCHEMAS
# =====================================================================

class PolicyRuleBase(BaseModel):
    device_id: int
    vendor_type: str
    rule_name: str
    rule_order: int
    action: str
    vendor_rule_id: Optional[str] = None
    vendor_uuid: Optional[str] = None
    vdom_vsys: Optional[str] = None
    is_active: Optional[bool] = True
    src_zone_interface: Optional[str] = None
    dst_zone_interface: Optional[str] = None
    rule_type: Optional[str] = None
    tags: Optional[str] = None
    src_negate: Optional[bool] = False
    dst_negate: Optional[bool] = False
    nat_enabled: Optional[bool] = None
    log_setting: Optional[str] = None
    security_profile_group: Optional[str] = None
    schedule_name: Optional[str] = None
    description: Optional[str] = None

class PolicyRuleCreate(PolicyRuleBase):
    pass

class PolicyRuleUpdate(BaseModel):
    device_id: Optional[int] = None
    vendor_type: Optional[str] = None
    rule_name: Optional[str] = None
    rule_order: Optional[int] = None
    action: Optional[str] = None
    vendor_rule_id: Optional[str] = None
    vendor_uuid: Optional[str] = None
    vdom_vsys: Optional[str] = None
    is_active: Optional[bool] = None
    src_zone_interface: Optional[str] = None
    dst_zone_interface: Optional[str] = None
    rule_type: Optional[str] = None
    tags: Optional[str] = None
    src_negate: Optional[bool] = None
    dst_negate: Optional[bool] = None
    nat_enabled: Optional[bool] = None
    log_setting: Optional[str] = None
    security_profile_group: Optional[str] = None
    schedule_name: Optional[str] = None
    description: Optional[str] = None

class PolicyRuleResponse(PolicyRuleBase):
    model_config = ConfigDict(from_attributes=True)
    rule_id: int
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


# =====================================================================
# RULE-OBJECT MAPPING SCHEMAS
# =====================================================================

class RuleObjectMappingBase(BaseModel):
    rule_id: int
    object_id: int
    mapping_type: str
    direction: Optional[str] = "both"

class RuleObjectMappingCreate(RuleObjectMappingBase):
    pass

class RuleObjectMappingResponse(RuleObjectMappingBase):
    model_config = ConfigDict(from_attributes=True)


# =====================================================================
# RULE ANOMALY SCHEMAS
# =====================================================================

class RuleAnomalyBase(BaseModel):
    rule_id: int
    anomaly_type: str
    severity_level: str
    description: Optional[str] = None

class RuleAnomalyCreate(RuleAnomalyBase):
    pass

class RuleAnomalyUpdate(BaseModel):
    anomaly_type: Optional[str] = None
    severity_level: Optional[str] = None
    description: Optional[str] = None

class RuleAnomalyResponse(RuleAnomalyBase):
    model_config = ConfigDict(from_attributes=True)
    anomaly_id: int
    detected_at: Optional[datetime] = None


# =====================================================================
# THREAT INTELLIGENCE SCHEMAS
# =====================================================================

class ThreatIntelligenceBase(BaseModel):
    device_id: int
    target_version: Optional[str] = None
    intelligence_summary: Optional[str] = None
    risk_score: Optional[float] = None
    source_url: Optional[str] = None

class ThreatIntelligenceCreate(ThreatIntelligenceBase):
    pass

class ThreatIntelligenceUpdate(BaseModel):
    device_id: Optional[int] = None
    target_version: Optional[str] = None
    intelligence_summary: Optional[str] = None
    risk_score: Optional[float] = None
    source_url: Optional[str] = None

class ThreatIntelligenceResponse(ThreatIntelligenceBase):
    model_config = ConfigDict(from_attributes=True)
    threat_id: int


# =====================================================================
# THREAT CORRELATION SCHEMAS
# =====================================================================

class ThreatCorrelationBase(BaseModel):
    rule_id: int
    threat_id: int
    match_strength: Optional[float] = None
    confidence_level: Optional[float] = None

class ThreatCorrelationCreate(ThreatCorrelationBase):
    pass

class ThreatCorrelationResponse(ThreatCorrelationBase):
    model_config = ConfigDict(from_attributes=True)
    correlation_date: Optional[datetime] = None
