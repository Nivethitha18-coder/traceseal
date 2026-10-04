"""
Forensic Watermark API Endpoints
"""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status

from backend.schemas import (
    WatermarkCreateRequest,
    WatermarkCreateResponse,
    WatermarkExtractResponse,
)
from backend.auth.service import get_current_user, require_roles
from backend.database import get_db
from backend.watermark.generator import generate_watermark_id
from backend.watermark.extractor import WatermarkExtractor

router = APIRouter(prefix="/api/watermark", tags=["Forensic Watermarking"])


@router.post("/create", response_model=WatermarkCreateResponse)
def create_watermark(
    req: WatermarkCreateRequest,
    current_user: dict = Depends(require_roles(["ADMIN", "RECIPIENT"])),
):
    """
    Generate and register a unique cryptographically random watermark identifier
    mapped to a session and recipient (without encoding recipient identity in watermark text).
    """
    wm_id = generate_watermark_id()
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO watermarks (
                watermark_id, session_id, recipient_id, document_id,
                payload_signature, embedded_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (wm_id, req.session_id, req.recipient_id, req.document_id, "MANUAL_REGISTRATION", now),
        )

    return {
        "watermark_id": wm_id,
        "session_id": req.session_id,
        "recipient_id": req.recipient_id,
        "document_id": req.document_id,
        "embedded_at": now,
    }


@router.post("/extract", response_model=WatermarkExtractResponse)
async def extract_watermark(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user),
):
    """
    Forensically inspect an uploaded PDF to recover any embedded watermark identifier.
    Scans content stream, zero-width steganographic, and structural metadata layers.
    """
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be a PDF document.",
        )
    content = await file.read()
    res = WatermarkExtractor.extract_from_bytes(content)
    return res
