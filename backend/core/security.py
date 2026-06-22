"""Security primitives for LuminaFPM (Volume 12).

This module currently provides **credential encryption at rest** (V12 §6, V3 §6.2),
which the acquisition layer depends on to store per-device firewall secrets. Auth
(JWT/session) and the RBAC dependency are added in the security phase; their
helpers will live here too so security concerns stay in one place.

Secrets are encrypted with Fernet (AES-128-CBC + HMAC) using ``ENCRYPTION_KEY``.
Decryption happens only in backend/worker memory; ciphertext is what is persisted
in ``device_credential.secret_encrypted``. Plaintext is never logged or returned
to the frontend.
"""
from __future__ import annotations

import base64
import hashlib

from core.config import settings
from core.logging import get_logger

logger = get_logger(__name__)


class CredentialEncryptionError(RuntimeError):
    """Raised when a secret cannot be encrypted/decrypted."""


def _derive_fernet_key() -> bytes:
    """Return a valid 32-byte url-safe base64 Fernet key derived from ENCRYPTION_KEY.

    Accepts either a proper Fernet key (preferred) or any passphrase, which is
    hashed to 32 bytes so operators are not forced to pre-generate a Fernet key
    for lab use. In production a real generated key must be supplied.
    """
    raw = settings.encryption_key or ""
    if not raw:
        raise CredentialEncryptionError(
            "ENCRYPTION_KEY is not set; refusing to handle credentials. "
            "Generate one with: python -c \"from cryptography.fernet import "
            "Fernet;print(Fernet.generate_key().decode())\""
        )
    # If it already looks like a 32-byte urlsafe-b64 key, use as-is.
    try:
        decoded = base64.urlsafe_b64decode(raw.encode())
        if len(decoded) == 32:
            return raw.encode()
    except Exception:
        pass
    # Otherwise derive deterministically from the passphrase.
    digest = hashlib.sha256(raw.encode()).digest()
    return base64.urlsafe_b64encode(digest)


def _fernet():
    try:
        from cryptography.fernet import Fernet
    except Exception as exc:  # pragma: no cover
        raise CredentialEncryptionError("cryptography is not installed") from exc
    return Fernet(_derive_fernet_key())


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a secret → base64 ciphertext string for storage."""
    if plaintext is None:
        raise CredentialEncryptionError("Cannot encrypt None")
    token = _fernet().encrypt(plaintext.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_secret(ciphertext: str) -> str:
    """Decrypt stored ciphertext → plaintext (backend/worker memory only)."""
    try:
        return _fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except CredentialEncryptionError:
        raise
    except Exception as exc:
        # Never include the secret/ciphertext in the error.
        raise CredentialEncryptionError("Failed to decrypt credential") from exc


def mask_secret(value: str | None) -> str:
    """Return a safe display token for a secret (never the value)."""
    if not value:
        return "<none>"
    return f"<{len(value)} chars, ***>"
