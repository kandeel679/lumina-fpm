from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import Dict, Any

from . import models

# =====================================================================
# DATABASE MANAGEMENT (Create/Drop Tables)
# =====================================================================

def create_database(engine):
    """
    Creates all database tables defined in models.py.
    Typically called on app startup with the sqlalchemy engine.
    """
    models.Base.metadata.create_all(bind=engine)


def drop_database(engine):
    """
    Drops all database tables. 
    WARNING: This will delete all data. Use carefully (e.g., tests only).
    """
    models.Base.metadata.drop_all(bind=engine)


# =====================================================================
# GENERIC CRUD OPERATIONS
# =====================================================================
# Since there are 10 models, generic CRUD functions save boilerplate 
# and can operate on any model simply by passing the model class.

def insert_data(db: Session, model_class, data: Dict[str, Any]):
    """
    Generic insert for any model.
    Usage: insert_data(db, models.Vendor, {"name": "Fortinet", "api_type": "api"})
    """
    db_obj = model_class(**data)
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    return db_obj


def update_data(db: Session, model_class, pk_name: str, pk_value: Any, data: Dict[str, Any]):
    """
    Generic update for any model by a single primary key.
    Usage: update_data(db, models.Vendor, "vendor_id", 1, {"name": "Updated"})
    """
    db_obj = db.query(model_class).filter(getattr(model_class, pk_name) == pk_value).first()
    if db_obj:
        for key, value in data.items():
            setattr(db_obj, key, value)
        db.commit()
        db.refresh(db_obj)
    return db_obj


def delete_data(db: Session, model_class, pk_name: str, pk_value: Any):
    """
    Generic delete for any model by a single primary key.
    Usage: delete_data(db, models.Vendor, "vendor_id", 1)
    """
    db_obj = db.query(model_class).filter(getattr(model_class, pk_name) == pk_value).first()
    if db_obj:
        db.delete(db_obj)
        db.commit()
        return True
    return False


def delete_data_composite(db: Session, model_class, key_mapping: Dict[str, Any]):
    """
    Generic delete for models with composite primary keys (e.g. Association objects).
    Usage: delete_data_composite(db, models.AdminDeviceAssignment, {"admin_id": 1, "device_id": 2})
    """
    query = db.query(model_class)
    for pk_name, pk_value in key_mapping.items():
        query = query.filter(getattr(model_class, pk_name) == pk_value)
    
    db_obj = query.first()
    if db_obj:
        db.delete(db_obj)
        db.commit()
        return True
    return False


# =====================================================================
# EXPLICIT MODEL HELPERS (Examples of direct implementations)
# =====================================================================
# Note: You can use these specifically if you don't want to use the generics.

# --- Vendor ---
def create_vendor(db: Session, vendor_data: dict):
    return insert_data(db, models.Vendor, vendor_data)

def delete_vendor(db: Session, vendor_id: int):
    return delete_data(db, models.Vendor, "vendor_id", vendor_id)

# --- Administrator ---
def create_administrator(db: Session, admin_data: dict):
    return insert_data(db, models.Administrator, admin_data)

def delete_administrator(db: Session, admin_id: int):
    return delete_data(db, models.Administrator, "admin_id", admin_id)

# --- FirewallDevice ---
def create_firewall_device(db: Session, device_data: dict):
    return insert_data(db, models.FirewallDevice, device_data)

def delete_firewall_device(db: Session, device_id: int):
    return delete_data(db, models.FirewallDevice, "device_id", device_id)

# --- AdminDeviceAssignment (Composite Key) ---
def assign_admin_to_device(db: Session, assignment_data: dict):
    return insert_data(db, models.AdminDeviceAssignment, assignment_data)

def remove_admin_from_device(db: Session, admin_id: int, device_id: int):
    return delete_data_composite(db, models.AdminDeviceAssignment, {"admin_id": admin_id, "device_id": device_id})

# --- NetworkObject ---
def create_network_object(db: Session, object_data: dict):
    return insert_data(db, models.NetworkObject, object_data)

def delete_network_object(db: Session, object_id: int):
    return delete_data(db, models.NetworkObject, "object_id", object_id)

# --- PolicyRule ---
def create_policy_rule(db: Session, rule_data: dict):
    return insert_data(db, models.PolicyRule, rule_data)

def delete_policy_rule(db: Session, rule_id: int):
    return delete_data(db, models.PolicyRule, "rule_id", rule_id)

# --- RuleObjectMapping (Composite Key) ---
def create_rule_object_mapping(db: Session, mapping_data: dict):
    return insert_data(db, models.RuleObjectMapping, mapping_data)

def remove_rule_object_mapping(db: Session, rule_id: int, object_id: int, mapping_type: str):
    return delete_data_composite(db, models.RuleObjectMapping, {
        "rule_id": rule_id, "object_id": object_id, "mapping_type": mapping_type
    })

# --- RuleAnomaly ---
def create_rule_anomaly(db: Session, anomaly_data: dict):
    return insert_data(db, models.RuleAnomaly, anomaly_data)

def delete_rule_anomaly(db: Session, anomaly_id: int):
    return delete_data(db, models.RuleAnomaly, "anomaly_id", anomaly_id)

# --- ThreatIntelligence ---
def create_threat_intelligence(db: Session, threat_data: dict):
    return insert_data(db, models.ThreatIntelligence, threat_data)

def delete_threat_intelligence(db: Session, threat_id: int):
    return delete_data(db, models.ThreatIntelligence, "threat_id", threat_id)

# --- ThreatCorrelation (Composite Key) ---
def create_threat_correlation(db: Session, correlation_data: dict):
    return insert_data(db, models.ThreatCorrelation, correlation_data)

def remove_threat_correlation(db: Session, rule_id: int, threat_id: int):
    return delete_data_composite(db, models.ThreatCorrelation, {
        "rule_id": rule_id, "threat_id": threat_id
    })
