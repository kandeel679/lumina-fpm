"""Raw acquisition artifact storage (V3 §8).

Persists each raw API response to disk so the parser can replay without re-polling
the device, and writes an acquisition manifest with per-artifact SHA-256 hashes.

Layout (V3 §8.2):
    {raw_dir}/{vendor_type}/{device_id}/{job_id}/
        <type>.json|.xml
        acquisition_manifest.json
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Dict, List

from core.config import settings
from core.logging import get_logger

from .models import ARTIFACT_MANIFEST, AcquisitionBundle, RawArtifact

logger = get_logger(__name__)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _ext_for(content_type: str) -> str:
    return "xml" if "xml" in (content_type or "") else "json"


def store_bundle(job_id: int, bundle: AcquisitionBundle) -> List[Dict[str, str]]:
    """Write raw artifacts + manifest to disk. Returns artifact metadata dicts.

    Each dict: {type, path, sha256}. The caller persists these as raw_artifact rows.
    """
    job_dir = os.path.join(
        settings.acquisition_raw_dir,
        bundle.vendor_type,
        str(bundle.device_id),
        str(job_id),
    )
    os.makedirs(job_dir, exist_ok=True)

    written: List[Dict[str, str]] = []
    manifest_artifacts = []
    for art in bundle.raw_artifacts:
        ext = _ext_for(art.content_type)
        filename = f"{art.type}.{ext}"
        path = os.path.join(job_dir, filename)
        digest = _sha256(art.content)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(art.content)
        art.sha256 = digest
        art.path = path
        written.append({"type": art.type, "path": path, "sha256": digest})
        manifest_artifacts.append({"type": art.type, "path": filename, "sha256": digest})

    manifest = {
        "job_id": job_id,
        "device_id": bundle.device_id,
        "vendor_type": bundle.vendor_type,
        "management_ip": bundle.management_ip,
        "connector_version": bundle.connector_version,
        "firmware_version": bundle.firmware_version,
        "status": bundle.status.value,
        "artifacts": manifest_artifacts,
        "warnings": [w.__dict__ for w in bundle.warnings],
    }
    manifest_path = os.path.join(job_dir, "acquisition_manifest.json")
    manifest_text = json.dumps(manifest, indent=2)
    with open(manifest_path, "w", encoding="utf-8") as fh:
        fh.write(manifest_text)
    written.append(
        {"type": ARTIFACT_MANIFEST, "path": manifest_path, "sha256": _sha256(manifest_text)}
    )
    logger.info(
        "Stored %d raw artifacts for job %s device %s (%s)",
        len(bundle.raw_artifacts), job_id, bundle.device_id, bundle.vendor_type,
    )
    return written


def load_artifact(path: str) -> str:
    """Read a stored raw artifact for parser replay (V3 §11.1)."""
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()
