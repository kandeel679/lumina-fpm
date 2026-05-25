from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from api.deps import get_db_session
from models import models, crud
from tasks.anomaly import run_anomaly_analysis_task
from schemas.pydantic_schemas import (
    PolicyRuleCreate, PolicyRuleUpdate, PolicyRuleResponse,
    RuleObjectMappingCreate, RuleObjectMappingResponse,
    RuleAnomalyCreate, RuleAnomalyUpdate, RuleAnomalyResponse,
)

router = APIRouter(prefix="/api/v1/rules", tags=["Policy Rules"])


# =====================================================================
# POLICY RULE ENDPOINTS
# =====================================================================

@router.get("/", response_model=List[PolicyRuleResponse])
def list_rules(skip: int = 0, limit: int = 100, db: Session = Depends(get_db_session)):
    return crud.get_all(db, models.PolicyRule, skip=skip, limit=limit)


@router.get("/{rule_id}", response_model=PolicyRuleResponse)
def get_rule(rule_id: int, db: Session = Depends(get_db_session)):
    rule = crud.get_by_id(db, models.PolicyRule, "rule_id", rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Policy rule not found")
    return rule


@router.post("/", response_model=PolicyRuleResponse, status_code=201)
def create_rule(rule: PolicyRuleCreate, db: Session = Depends(get_db_session)):
    return crud.insert_data(db, models.PolicyRule, rule.model_dump())


@router.patch("/{rule_id}", response_model=PolicyRuleResponse)
def update_rule(rule_id: int, rule: PolicyRuleUpdate, db: Session = Depends(get_db_session)):
    updated = crud.update_data(db, models.PolicyRule, "rule_id", rule_id, rule.model_dump(exclude_unset=True))
    if not updated:
        raise HTTPException(status_code=404, detail="Policy rule not found")
    return updated


@router.delete("/{rule_id}", status_code=204)
def delete_rule(rule_id: int, db: Session = Depends(get_db_session)):
    deleted = crud.delete_data(db, models.PolicyRule, "rule_id", rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Policy rule not found")
    return None


# =====================================================================
# RULE-OBJECT MAPPINGS (Nested under /rules/{rule_id}/objects)
# =====================================================================

@router.get("/{rule_id}/objects", response_model=List[RuleObjectMappingResponse], tags=["Rule-Object Mappings"])
def list_rule_objects(rule_id: int, db: Session = Depends(get_db_session)):
    rule = crud.get_by_id(db, models.PolicyRule, "rule_id", rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Policy rule not found")
    return db.query(models.RuleObjectMapping).filter(
        models.RuleObjectMapping.rule_id == rule_id
    ).all()


@router.post("/{rule_id}/objects", response_model=RuleObjectMappingResponse, status_code=201, tags=["Rule-Object Mappings"])
def create_rule_object_mapping(rule_id: int, mapping: RuleObjectMappingCreate, db: Session = Depends(get_db_session)):
    rule = crud.get_by_id(db, models.PolicyRule, "rule_id", rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Policy rule not found")
    data = mapping.model_dump()
    data["rule_id"] = rule_id
    return crud.insert_data(db, models.RuleObjectMapping, data)


@router.delete("/{rule_id}/objects/{object_id}/{mapping_type}", status_code=204, tags=["Rule-Object Mappings"])
def delete_rule_object_mapping(rule_id: int, object_id: int, mapping_type: str, db: Session = Depends(get_db_session)):
    deleted = crud.delete_data_composite(db, models.RuleObjectMapping, {
        "rule_id": rule_id, "object_id": object_id, "mapping_type": mapping_type
    })
    if not deleted:
        raise HTTPException(status_code=404, detail="Mapping not found")
    return None


# =====================================================================
# RULE ANOMALIES (Nested under /rules/{rule_id}/anomalies)
# =====================================================================

@router.get("/{rule_id}/anomalies", response_model=List[RuleAnomalyResponse], tags=["Rule Anomalies"])
def list_rule_anomalies(rule_id: int, db: Session = Depends(get_db_session)):
    rule = crud.get_by_id(db, models.PolicyRule, "rule_id", rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Policy rule not found")
    return db.query(models.RuleAnomaly).filter(
        models.RuleAnomaly.rule_id == rule_id
    ).all()


@router.post("/{rule_id}/anomalies", response_model=RuleAnomalyResponse, status_code=201, tags=["Rule Anomalies"])
def create_rule_anomaly(rule_id: int, anomaly: RuleAnomalyCreate, db: Session = Depends(get_db_session)):
    rule = crud.get_by_id(db, models.PolicyRule, "rule_id", rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Policy rule not found")
    data = anomaly.model_dump()
    data["rule_id"] = rule_id
    return crud.insert_data(db, models.RuleAnomaly, data)


@router.patch("/{rule_id}/anomalies/{anomaly_id}", response_model=RuleAnomalyResponse, tags=["Rule Anomalies"])
def update_rule_anomaly(rule_id: int, anomaly_id: int, anomaly: RuleAnomalyUpdate, db: Session = Depends(get_db_session)):
    existing = crud.get_by_id(db, models.RuleAnomaly, "anomaly_id", anomaly_id)
    if not existing or existing.rule_id != rule_id:
        raise HTTPException(status_code=404, detail="Anomaly not found for this rule")
    updated = crud.update_data(db, models.RuleAnomaly, "anomaly_id", anomaly_id, anomaly.model_dump(exclude_unset=True))
    return updated


@router.delete("/{rule_id}/anomalies/{anomaly_id}", status_code=204, tags=["Rule Anomalies"])
def delete_rule_anomaly(rule_id: int, anomaly_id: int, db: Session = Depends(get_db_session)):
    existing = crud.get_by_id(db, models.RuleAnomaly, "anomaly_id", anomaly_id)
    if not existing or existing.rule_id != rule_id:
        raise HTTPException(status_code=404, detail="Anomaly not found for this rule")
    crud.delete_data(db, models.RuleAnomaly, "anomaly_id", anomaly_id)
    return None


# =====================================================================
# DEVICE ANALYSIS (Trigger Background Task)
# =====================================================================

@router.post("/device/{device_id}/analyze", tags=["Rule Anomalies"])
def analyze_device_rules(device_id: int, db: Session = Depends(get_db_session)):
    device = crud.get_by_id(db, models.FirewallDevice, "device_id", device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
        
    task = run_anomaly_analysis_task.delay(device_id)
    return {"status": "accepted", "task_id": task.id, "message": "Anomaly analysis started in background"}
