"""
Canonical Provenance Event Factory
Constructs deterministic canonical decryption provenance event payloads.
"""

from datetime import datetime, timezone
import json
import uuid
from typing import Dict, Any, Optional
from backend.crypto.hashing import sha256_bytes


def create_canonical_event(
    session_id: str,
    document_id: str,
    recipient_id: str,
    document_hash: str,
    watermark_id: str,
    document_name: str = "Confidential Document",
    recipient_name: str = "Authorized Employee",
    recipient_username: str = "recipient",
    recipient_role: str = "Employee",
    fingerprint_hash: Optional[str] = None,
    action: str = "DECRYPT_AND_DOWNLOAD",
    event_id: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Construct canonical provenance event dictionary with strictly defined keys per SIH Section 4.
    """
    if not event_id:
        event_id = f"EVT-{uuid.uuid4().hex[:12].upper()}"

    if not timestamp:
        timestamp = datetime.now(timezone.utc).isoformat()

    if not fingerprint_hash and watermark_id:
        fingerprint_hash = sha256_bytes(watermark_id.encode("utf-8"))

    return {
        "event_id": event_id,
        "decryption_event_id": event_id,
        "session_id": session_id,
        "document_id": document_id,
        "document_name": document_name,
        "recipient_id": recipient_id,
        "recipient_user_id": recipient_id,
        "recipient_name": recipient_name,
        "recipient_username": recipient_username,
        "recipient_role": recipient_role,
        "watermark_id": watermark_id,
        "fingerprint_id": watermark_id,
        "fingerprint_hash": fingerprint_hash or "",
        "action": action,
        "document_hash": document_hash,
        "timestamp": timestamp,
    }


def serialize_canonical(event: Dict[str, Any]) -> str:
    """
    Serialize canonical event to deterministic JSON string.
    Ensures alphabetically sorted keys and strictly uniform separators.
    """
    canonical_keys = [
        "action",
        "decryption_event_id",
        "document_hash",
        "document_id",
        "document_name",
        "event_id",
        "fingerprint_hash",
        "fingerprint_id",
        "recipient_id",
        "recipient_name",
        "recipient_role",
        "recipient_user_id",
        "recipient_username",
        "session_id",
        "timestamp",
        "watermark_id",
    ]
    sub_dict = {k: event[k] for k in canonical_keys if k in event}
    if not sub_dict:
        sub_dict = event
    return json.dumps(sub_dict, sort_keys=True, separators=(",", ":"))
