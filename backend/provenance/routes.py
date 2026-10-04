"""
Cryptographic Provenance API Endpoints
"""

import json
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status

from backend.schemas import (
    ProvenanceEventOut,
    ProvenanceSignRequest,
    ProvenanceVerifyRequest,
    ProvenanceVerifyResponse,
)
from backend.auth.service import get_current_user, require_roles
from backend.database import get_db
from backend.crypto.pqc import pqc_provider
from backend.provenance.events import create_canonical_event
from backend.provenance.signing import sign_provenance_event
from backend.provenance.verification import verify_event_signature

router = APIRouter(prefix="/api/provenance", tags=["Cryptographic Provenance"])


@router.post("/sign", response_model=ProvenanceEventOut)
def sign_event_endpoint(
    req: ProvenanceSignRequest,
    current_user: dict = Depends(require_roles(["ADMIN", "RECIPIENT"])),
):
    """
    Digitally sign a canonical provenance event using NIST ML-DSA-44.
    """
    event = create_canonical_event(
        session_id=req.session_id,
        document_id=req.document_id,
        recipient_id=req.recipient_id,
        document_hash=req.document_hash,
        watermark_id=req.watermark_id,
    )
    canonical_str, signature, algorithm, pubkey = sign_provenance_event(event)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO provenance_events (
                event_id, session_id, document_id, recipient_id, document_hash,
                watermark_id, timestamp, canonical_payload, signature, algorithm, public_key_ref
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event["event_id"],
                event["session_id"],
                event["document_id"],
                event["recipient_id"],
                event["document_hash"],
                event["watermark_id"],
                event["timestamp"],
                canonical_str,
                signature,
                algorithm,
                pubkey,
            ),
        )

    return {
        "event_id": event["event_id"],
        "session_id": event["session_id"],
        "document_id": event["document_id"],
        "recipient_id": event["recipient_id"],
        "document_hash": event["document_hash"],
        "watermark_id": event["watermark_id"],
        "timestamp": event["timestamp"],
        "canonical_payload": canonical_str,
        "signature": signature,
        "algorithm": algorithm,
        "public_key_ref": pubkey,
    }


@router.post("/verify", response_model=ProvenanceVerifyResponse)
def verify_event_endpoint(
    req: ProvenanceVerifyRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    Verify the digital signature of a canonical provenance event against the authority public key.
    """
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM provenance_events WHERE event_id = ?", (req.event_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provenance event not found")
        evt = dict(row)

    canonical_payload = evt.get("canonical_payload")
    if canonical_payload:
        # Cross-check consistency between canonical_payload and database row columns
        # to ensure that if row columns were tampered, verification fails
        try:
            payload_data = json.loads(canonical_payload)
            if (payload_data.get("event_id") != evt["event_id"] or
                payload_data.get("document_hash") != evt["document_hash"] or
                payload_data.get("recipient_id") != evt["recipient_id"]):
                return {
                    "event_id": evt["event_id"],
                    "signature_valid": False,
                    "algorithm": evt["algorithm"],
                    "public_key_ref": evt["public_key_ref"][:32] + "...",
                    "signed_payload_hash": "",
                }
        except Exception:
            return {
                "event_id": evt["event_id"],
                "signature_valid": False,
                "algorithm": evt["algorithm"],
                "public_key_ref": evt["public_key_ref"][:32] + "...",
                "signed_payload_hash": "",
            }

        is_valid, payload_hash = verify_event_signature(
            canonical_payload,
            evt["signature"],
            evt["public_key_ref"],
        )
    else:
        event_dict = {
            "event_id": evt["event_id"],
            "session_id": evt["session_id"],
            "document_id": evt["document_id"],
            "recipient_id": evt["recipient_id"],
            "document_hash": evt["document_hash"],
            "watermark_id": evt["watermark_id"],
            "timestamp": evt["timestamp"],
        }
        is_valid, payload_hash = verify_event_signature(
            event_dict,
            evt["signature"],
            evt["public_key_ref"],
        )

    return {
        "event_id": evt["event_id"],
        "signature_valid": is_valid,
        "algorithm": evt["algorithm"],
        "public_key_ref": evt["public_key_ref"][:32] + "...",
        "signed_payload_hash": payload_hash,
    }


@router.get("/{event_id}", response_model=ProvenanceEventOut)
def get_provenance_event(
    event_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Retrieve full details of a specific provenance event."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM provenance_events WHERE event_id = ?", (event_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
        return dict(row)
