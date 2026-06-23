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
    vendor_type: Optional[str] = None   # 'fortinet' | 'paloalto' (derived from vendor if omitted)
    hostname: str
    management_ip: str
    location: Optional[str] = None
    uptime: Optional[str] = None
    throughput: Optional[str] = None
    firmware_version: Optional[str] = None
    last_poll_time: Optional[datetime] = None
    status: Optional[str] = "unknown"

class DeviceCreate(DeviceBase):
    pass

class DeviceUpdate(BaseModel):
    vendor_id: Optional[int] = None
    hostname: Optional[str] = None
    management_ip: Optional[str] = None
    location: Optional[str] = None
    uptime: Optional[str] = None
    throughput: Optional[str] = None
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
    related_rule_id: Optional[int] = None   # FK to policy_rule.rule_id (cross-device/shadowing pair)
    description: Optional[str] = None

class RuleAnomalyCreate(RuleAnomalyBase):
    pass

class RuleAnomalyUpdate(BaseModel):
    anomaly_type: Optional[str] = None
    severity_level: Optional[str] = None
    related_rule_id: Optional[int] = None
    description: Optional[str] = None

class RuleAnomalyResponse(RuleAnomalyBase):
    model_config = ConfigDict(from_attributes=True)
    anomaly_id: int
    detected_at: Optional[datetime] = None


# =====================================================================
# EXTERNAL NODE SCHEMAS
# =====================================================================

class ExternalNodeBase(BaseModel):
    name: str
    ip_address: str
    node_type: str
    description: Optional[str] = None

class ExternalNodeCreate(ExternalNodeBase):
    pass

class ExternalNodeUpdate(BaseModel):
    name: Optional[str] = None
    ip_address: Optional[str] = None
    node_type: Optional[str] = None
    description: Optional[str] = None

class ExternalNodeResponse(ExternalNodeBase):
    model_config = ConfigDict(from_attributes=True)
    node_id: int


# =====================================================================
# THREAT FEED SCHEMAS
# =====================================================================

class ThreatFeedBase(BaseModel):
    name: str
    url: str
    status: Optional[str] = "active"

class ThreatFeedCreate(ThreatFeedBase):
    pass

class ThreatFeedUpdate(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    status: Optional[str] = None

class ThreatFeedResponse(ThreatFeedBase):
    model_config = ConfigDict(from_attributes=True)
    feed_id: int
    last_sync: Optional[datetime] = None


# =====================================================================
# API TOKEN SCHEMAS
# =====================================================================

class APITokenBase(BaseModel):
    admin_id: int
    name: str

class APITokenCreate(APITokenBase):
    pass

class APITokenUpdate(BaseModel):
    name: Optional[str] = None

class APITokenResponse(APITokenBase):
    model_config = ConfigDict(from_attributes=True)
    token_id: int
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    last_used: Optional[datetime] = None


# =====================================================================
# AUDIT LOG SCHEMAS
# =====================================================================

class AuditLogBase(BaseModel):
    admin_id: Optional[int] = None
    action: str
    target_type: str
    target_id: Optional[str] = None
    details: Optional[str] = None

class AuditLogCreate(AuditLogBase):
    pass

class AuditLogResponse(AuditLogBase):
    model_config = ConfigDict(from_attributes=True)
    log_id: int
    timestamp: Optional[datetime] = None


# =====================================================================
# SAVED SEARCH SCHEMAS
# =====================================================================

class SavedSearchBase(BaseModel):
    admin_id: int
    name: str
    query_string: str

class SavedSearchCreate(SavedSearchBase):
    pass

class SavedSearchUpdate(BaseModel):
    name: Optional[str] = None
    query_string: Optional[str] = None

class SavedSearchResponse(SavedSearchBase):
    model_config = ConfigDict(from_attributes=True)
    search_id: int
    created_at: Optional[datetime] = None
