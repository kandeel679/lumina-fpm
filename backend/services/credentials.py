"""Device credential service (V3 §6.2, V12 §6).

Stores per-device firewall secrets encrypted at rest and decrypts them only in
backend/worker memory. The plaintext secret is NEVER returned to the frontend,
NEVER logged. The frontend may create/rotate a credential and test it, but only
receives status.
"""
from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

from core.logging import get_logger
from core.security import decrypt_secret, encrypt_secret
from models import models

logger = get_logger(__name__)

VALID_AUTH_TYPES = {"fortigate_api_token", "panos_api_key", "panos_userpass"}


def set_credential(db: Session, device_id: int, auth_type: str, secret: str) -> models.DeviceCredential:
    """Create or replace the encrypted credential for a device."""
    if auth_type not in VALID_AUTH_TYPES:
        raise ValueError(f"Unsupported auth_type '{auth_type}'")
    existing = (
        db.query(models.DeviceCredential)
        .filter(models.DeviceCredential.device_id == device_id)
        .first()
    )
    ciphertext = encrypt_secret(secret)
    if existing:
        existing.auth_type = auth_type
        existing.secret_encrypted = ciphertext
        existing.rotated_at = models.utcnow()
        db.commit()
        db.refresh(existing)
        logger.info("Rotated credential for device %s (auth_type=%s)", device_id, auth_type)
        return existing
    cred = models.DeviceCredential(
        device_id=device_id, auth_type=auth_type, secret_encrypted=ciphertext
    )
    db.add(cred)
    db.commit()
    db.refresh(cred)
    logger.info("Stored credential for device %s (auth_type=%s)", device_id, auth_type)
    return cred


def get_decrypted_secret(db: Session, device_id: int) -> Optional["tuple[str, str]"]:
    """Return (auth_type, plaintext_secret) for a device, or None. Memory-only use."""
    cred = (
        db.query(models.DeviceCredential)
        .filter(models.DeviceCredential.device_id == device_id)
        .first()
    )
    if not cred:
        return None
    cred.last_used_at = models.utcnow()
    db.commit()
    return cred.auth_type, decrypt_secret(cred.secret_encrypted)


def has_credential(db: Session, device_id: int) -> bool:
    return (
        db.query(models.DeviceCredential.credential_id)
        .filter(models.DeviceCredential.device_id == device_id)
        .first()
        is not None
    )
