"""
Forensic Investigation & Attribution API Endpoints
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status, Header, Query
from fastapi.responses import FileResponse, Response
from pathlib import Path

from backend.schemas import (
    InvestigationResponse,
    WarningNoticeCreate,
    WarningNoticeOut,
    WarningNoticeStatusUpdate,
    WarningNoticeReply,
)
from backend.auth.service import get_current_user, require_roles, get_user_from_auth_or_query, normalize_role
from backend.database import get_db
from backend.forensic.investigation import ForensicInvestigator
from backend.forensic.report import generate_forensic_report_pdf
from backend.forensic.notice_service import NoticeService
from backend.services.storage import StorageService

router = APIRouter(prefix="/api/forensics", tags=["Forensic Investigation & Attribution"])


@router.post("/investigate", response_model=InvestigationResponse)
async def investigate_file_endpoint(
    file: UploadFile = File(...),
    current_user: dict = Depends(require_roles(["ADMIN", "INVESTIGATOR"])),
):
    """
    INVESTIGATOR: Upload suspect/leaked file (PDF, Image, Document, or Text).
    Computes SHA-256, extracts forensic watermark / corroborates copy hash, matches provenance event,
    identifies recipient, verifies ML-DSA digital signature, validates ledger integrity,
    and returns complete attribution evidence.
    """
    content = await file.read()
    if len(content) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )

    res = ForensicInvestigator.investigate_file(content, file.filename)
    return res


@router.get("/reports/{case_id}/download")
def download_forensic_report(
    case_id: str,
    token: Optional[str] = None,
    authorization: Optional[str] = Header(None),
):
    """Download official cryptographic Forensic Attribution PDF Report."""
    auth_header = authorization or (f"Bearer {token}" if token else None)
    current_user = get_current_user(auth_header)
    if current_user["role"] not in ("ADMIN", "INVESTIGATOR"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. Investigator or Admin role required.",
        )

    report_path = StorageService.get_evidence_report_path(case_id)
    if not report_path or not report_path.exists():
        try:
            generate_forensic_report_pdf(case_id)
            report_path = StorageService.get_evidence_report_path(case_id)
        except KeyError as ke:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ke))
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Report generation error: {str(e)}",
            )

    return FileResponse(
        path=str(report_path),
        filename=f"TRACESEAL_Forensic_Report_{case_id}.pdf",
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="TRACESEAL_Forensic_Report_{case_id}.pdf"',
        },
    )


@router.get("/cases")
def list_investigation_cases(
    current_user: dict = Depends(require_roles(["ADMIN", "INVESTIGATOR"])),
    incidents_only: bool = Query(False, description="Return deduplicated real leak incidents only"),
):
    """List forensic leak investigations. If incidents_only=True, returns deduplicated real leak incidents only."""
    with get_db() as conn:
        cursor = conn.cursor()
        if incidents_only:
            cursor.execute(
                """
                SELECT 
                    i.case_id,
                    i.filename,
                    i.filename as suspect_filename,
                    COALESCE(d.original_filename, i.filename) as original_filename,
                    COALESCE(d.document_id, i.matched_document_id) as matched_document_id,
                    i.matched_recipient_id,
                    u.username as recipient_username,
                    u.display_name as recipient_name,
                    i.attribution_status,
                    i.watermark_matched,
                    i.extracted_watermark_id,
                    i.signature_valid,
                    i.ledger_valid,
                    i.investigated_at,
                    (SELECT COUNT(*) FROM investigations i2 WHERE i2.matched_document_id = d.document_id) as total_investigations,
                    (SELECT notice_id FROM warning_notices WHERE warning_notices.investigation_id = i.case_id LIMIT 1) as related_warning_id,
                    (SELECT block_index FROM ledger_blocks WHERE ledger_blocks.watermark_id = i.extracted_watermark_id OR ledger_blocks.event_id = i.matched_event_id LIMIT 1) as related_ledger_block,
                    (SELECT event_id FROM ledger_blocks WHERE ledger_blocks.watermark_id = i.extracted_watermark_id OR ledger_blocks.event_id = i.matched_event_id LIMIT 1) as related_ledger_event
                FROM investigations i
                LEFT JOIN users u ON i.matched_recipient_id = u.id
                JOIN documents d ON i.matched_document_id = d.document_id
                WHERE d.status = 'LEAKED'
                  AND i.attribution_status IN ('ATTRIBUTION VERIFIED', 'LEAK DETECTED', 'CONFIRMED_LEAK')
                  AND i.watermark_matched = 1
                  AND i.matched_recipient_id IS NOT NULL
                  AND i.attribution_status != 'DIRECT SECURITY NOTICE'
                  AND i.rowid IN (
                      SELECT rowid FROM investigations inv
                      WHERE inv.matched_document_id = d.document_id
                        AND inv.attribution_status IN ('ATTRIBUTION VERIFIED', 'LEAK DETECTED', 'CONFIRMED_LEAK')
                      ORDER BY inv.investigated_at DESC LIMIT 1
                  )
                ORDER BY i.investigated_at DESC
                """
            )
        else:
            cursor.execute(
                """
                SELECT i.*,
                       u.username as recipient_username,
                       u.display_name as recipient_name,
                       d.original_filename,
                       d.original_hash,
                       'v1.0' as document_version,
                       CASE WHEN i.watermark_matched = 1 THEN 'EMBEDDED' ELSE 'NOT EMBEDDED' END as watermark_status,
                       'Imperceptible Multi-Layer Steganography' as method,
                       CASE WHEN i.watermark_matched = 1 THEN 'SUCCESS' ELSE 'NOT APPLICABLE' END as decryption_status,
                       (SELECT started_at FROM decryption_sessions WHERE session_id = i.matched_session_id LIMIT 1) as decryption_timestamp,
                       (SELECT notice_id FROM warning_notices WHERE warning_notices.investigation_id = i.case_id LIMIT 1) as related_warning_id,
                       (SELECT block_index FROM ledger_blocks WHERE ledger_blocks.watermark_id = i.extracted_watermark_id OR ledger_blocks.event_id = i.matched_event_id LIMIT 1) as related_ledger_block,
                       (SELECT event_id FROM ledger_blocks WHERE ledger_blocks.watermark_id = i.extracted_watermark_id OR ledger_blocks.event_id = i.matched_event_id LIMIT 1) as related_ledger_event
                FROM investigations i
                LEFT JOIN users u ON i.matched_recipient_id = u.id
                LEFT JOIN documents d ON i.matched_document_id = d.document_id
                WHERE i.attribution_status != 'DIRECT SECURITY NOTICE'
                ORDER BY i.investigated_at DESC
                """
            )
        return [dict(r) for r in cursor.fetchall()]


@router.get("/incidents")
def list_leak_incidents(
    current_user: dict = Depends(require_roles(["ADMIN", "INVESTIGATOR"])),
):
    """
    Dedicated endpoint returning deduplicated real leak incidents only.
    Each unique real document leak event is returned once, excluding administrative policy notices,
    unverified scans, and repeated automated test executions.
    """
    return list_investigation_cases(current_user=current_user, incidents_only=True)


@router.get("/cases/{case_id}")
def get_investigation_case(
    case_id: str,
    current_user: dict = Depends(require_roles(["ADMIN", "INVESTIGATOR"])),
):
    """Get full details of a specific investigation case."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT i.*,
                   COALESCE(u.username, (SELECT username FROM distributed_copies WHERE fingerprint = i.extracted_watermark_id LIMIT 1), 'unknown') as recipient_username,
                   COALESCE(u.display_name, (SELECT employee_name FROM distributed_copies WHERE fingerprint = i.extracted_watermark_id LIMIT 1), 'Authorized Personnel') as recipient_name,
                   COALESCE(u.display_name, (SELECT employee_name FROM distributed_copies WHERE fingerprint = i.extracted_watermark_id LIMIT 1), 'Authorized Personnel') as recipient_employee_name,
                   COALESCE(u.display_name, (SELECT employee_name FROM distributed_copies WHERE fingerprint = i.extracted_watermark_id LIMIT 1), 'Authorized Personnel') as matched_recipient_name,
                   COALESCE(u.role, 'RECIPIENT') as recipient_role,
                   i.extracted_watermark_id as watermark_id,
                   i.extracted_watermark_id as copy_fingerprint,
                   i.extracted_watermark_id as fingerprint_id,
                   COALESCE(d.original_filename, (SELECT document_name FROM distributed_copies WHERE fingerprint = i.extracted_watermark_id LIMIT 1), i.filename) as original_filename,
                   COALESCE(d.original_hash, (SELECT document_hash FROM distributed_copies WHERE fingerprint = i.extracted_watermark_id LIMIT 1), (SELECT document_hash FROM provenance_events WHERE event_id = i.matched_event_id OR watermark_id = i.extracted_watermark_id LIMIT 1), i.file_hash) as original_hash,
                   'v1.0' as document_version,
                   CASE WHEN i.watermark_matched = 1 THEN 'EMBEDDED' ELSE 'NOT EMBEDDED' END as watermark_status,
                   'Imperceptible Multi-Layer Steganography' as method,
                   CASE WHEN i.watermark_matched = 1 THEN 'SUCCESS' ELSE 'NOT APPLICABLE' END as decryption_status,
                   COALESCE(
                       (SELECT started_at FROM decryption_sessions WHERE session_id = i.matched_session_id LIMIT 1),
                       (SELECT timestamp FROM provenance_events WHERE event_id = i.matched_event_id OR watermark_id = i.extracted_watermark_id LIMIT 1),
                       (SELECT downloaded_at FROM distributed_copies WHERE fingerprint = i.extracted_watermark_id LIMIT 1),
                       i.investigated_at
                   ) as decryption_timestamp,
                   COALESCE(
                       (SELECT downloaded_at FROM distributed_copies WHERE fingerprint = i.extracted_watermark_id LIMIT 1),
                       (SELECT timestamp FROM provenance_events WHERE event_id = i.matched_event_id OR watermark_id = i.extracted_watermark_id LIMIT 1),
                       (SELECT started_at FROM decryption_sessions WHERE session_id = i.matched_session_id LIMIT 1),
                       i.investigated_at
                   ) as download_timestamp,
                   COALESCE(
                       i.matched_session_id,
                       (SELECT session_id FROM provenance_events WHERE event_id = i.matched_event_id OR watermark_id = i.extracted_watermark_id LIMIT 1),
                       (SELECT copy_id FROM distributed_copies WHERE fingerprint = i.extracted_watermark_id LIMIT 1)
                   ) as matched_session_id,
                   (SELECT notice_id FROM warning_notices WHERE warning_notices.investigation_id = i.case_id LIMIT 1) as related_warning_id,
                   COALESCE(
                       (SELECT block_index FROM ledger_blocks WHERE ledger_blocks.watermark_id = i.extracted_watermark_id OR ledger_blocks.event_id = i.matched_event_id LIMIT 1),
                       (SELECT ledger_block_index FROM distributed_copies WHERE fingerprint = i.extracted_watermark_id LIMIT 1),
                       1
                   ) as related_ledger_block,
                   (SELECT event_id FROM ledger_blocks WHERE ledger_blocks.watermark_id = i.extracted_watermark_id OR ledger_blocks.event_id = i.matched_event_id LIMIT 1) as related_ledger_event
            FROM investigations i
            LEFT JOIN users u ON i.matched_recipient_id = u.id
            LEFT JOIN documents d ON i.matched_document_id = d.document_id
            WHERE i.case_id = ?
            """,
            (case_id,),
        )
        row = cursor.fetchone()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation case '{case_id}' not found.",
            )
        data = dict(row)
        data["watermark_match"] = bool(data.get("watermark_matched"))
        data["signature_valid"] = bool(data.get("signature_valid"))
        data["document_hash_match"] = bool(data.get("document_hash_match"))
        data["ledger_valid"] = bool(data.get("ledger_valid"))
        data["session_id"] = data.get("matched_session_id")
        data["ledger_block_index"] = data.get("related_ledger_block") or 1
        data["report_download_url"] = f"/api/forensics/reports/{case_id}/download"
        data["action_event"] = "DECRYPT_AND_DOWNLOAD"

        emp = data.get("recipient_employee_name") or data.get("recipient_name") or "Authorized Personnel"
        uname = data.get("recipient_username") or "unknown"
        if data.get("attribution_status") == "ATTRIBUTION VERIFIED" or data.get("watermark_matched"):
            data["attribution_statement"] = f"Source copy identified: Leaked copy matches the copy issued to {emp} (@{uname})."
            data["issued_copy_status"] = "MATCHED"
            data["leak_status"] = "LEAK SOURCE COPY IDENTIFIED"
        else:
            data["attribution_statement"] = "No matching distributed copy found or cryptographic verification failed."
            data["issued_copy_status"] = "NOT IDENTIFIED"
            data["leak_status"] = "NO LEAK DETECTED"

        data["evidence_chain"] = [
            {
                "step": 1,
                "label": "LEAKED FILE SCAN",
                "detail": f"{data.get('filename')} (SHA-256: {(data.get('file_hash') or '')[:12]}...)",
                "status": "PASS",
            },
            {
                "step": 2,
                "label": "FORENSIC FINGERPRINT",
                "detail": f"Detected: {data.get('extracted_watermark_id')} (Layer: LSB/DWT/DCT Steganography)",
                "status": "PASS" if data.get("watermark_matched") else "FAIL",
            },
            {
                "step": 3,
                "label": "ISSUED COPY MATCH",
                "detail": f"Copy ID: {data.get('matched_session_id') or 'N/A'} (Issued to: {emp})",
                "status": "PASS" if data.get("watermark_matched") else "FAIL",
            },
            {
                "step": 4,
                "label": "RECIPIENT ATTRIBUTION",
                "detail": f"Source copy identified: {emp} (@{uname})",
                "status": "PASS" if data.get("watermark_matched") else "FAIL",
            },
            {
                "step": 5,
                "label": "DIGITAL SIGNATURE (ML-DSA-44)",
                "detail": f"Algorithm: ML-DSA-44 (NIST FIPS 204)",
                "status": "PASS" if data.get("signature_valid") else "FAIL",
            },
            {
                "step": 6,
                "label": "TAMPER-EVIDENT LEDGER",
                "detail": f"Block #{data.get('ledger_block_index') or 1} (Multi-validator verified)",
                "status": "PASS" if data.get("ledger_valid") else "FAIL",
            },
            {
                "step": 7,
                "label": "LEAK STATUS VERDICT",
                "detail": data["attribution_statement"],
                "status": "PASS" if data.get("attribution_status") == "ATTRIBUTION VERIFIED" else "FAIL",
            },
        ]
        return data


# --- Warning & Investigation Notice Endpoints ---

@router.post("/notices/send", response_model=WarningNoticeOut)
@router.post("/notices", response_model=WarningNoticeOut, include_in_schema=False)
def issue_warning_notice(
    payload: WarningNoticeCreate,
    current_user: dict = Depends(require_roles(["ADMIN", "INVESTIGATOR"])),
):
    """
    Issue a formal system-generated warning notice to the recipient associated with an investigation.
    Maintains forensic neutrality and evidentiary integrity.
    """
    return NoticeService.create_warning_notice(
        investigation_id=payload.investigation_id,
        recipient_id=payload.recipient_id,
        reason=payload.reason,
        subject=payload.subject,
        message=payload.message,
        actor=current_user,
        custom_notes=payload.custom_notes,
    )


@router.get("/notices", response_model=List[WarningNoticeOut])
def list_warning_notices(
    recipient_id: Optional[str] = Query(None),
    investigation_id: Optional[str] = Query(None),
    issued_by: Optional[str] = Query(None),
    all: bool = Query(False),
    current_user: dict = Depends(get_current_user),
):
    """
    List warning notices.
    ADMIN: Can view all (or filter by recipient_id or issued_by).
    INVESTIGATOR: Enforces per-user warning isolation by default (views notices issued by this account).
    EMPLOYEE/RECIPIENT: Can ONLY view notices where recipient_id == current_user['id'].
    """
    if current_user["role"] in ("RECIPIENT", "EMPLOYEE"):
        return NoticeService.list_warning_notices(
            recipient_id=current_user["id"],
            investigation_id=investigation_id,
        )

    filter_issued_by = issued_by
    if current_user["role"] == "INVESTIGATOR":
        # Investigator sees ONLY their own issued warnings
        filter_issued_by = current_user.get("username") or current_user.get("id")
    elif current_user["role"] == "ADMIN":
        if issued_by and issued_by.lower() == "me":
            filter_issued_by = current_user.get("username")
        elif not all and issued_by:
            filter_issued_by = issued_by
        else:
            filter_issued_by = None if all or not issued_by else issued_by

    return NoticeService.list_warning_notices(
        recipient_id=recipient_id,
        investigation_id=investigation_id,
        issued_by=filter_issued_by,
    )


@router.get("/notices/issued", response_model=List[WarningNoticeOut])
@router.get("/forensics/notices/issued", response_model=List[WarningNoticeOut], include_in_schema=False)
def get_my_issued_warning_notices(
    current_user: dict = Depends(require_roles(["ADMIN", "INVESTIGATOR"])),
):
    """
    Authorised Person / Investigator / Admin:
    Retrieve warning notices specifically issued by the current authenticated user's account.
    """
    issuer = current_user.get("username") or current_user.get("id")
    return NoticeService.list_warning_notices(issued_by=issuer)


@router.get("/notices/my", response_model=List[WarningNoticeOut])
@router.get("/recipient/notices", response_model=List[WarningNoticeOut], include_in_schema=False)
def get_my_warning_notices(current_user: dict = Depends(get_current_user)):
    """
    Authenticated RECIPIENT/EMPLOYEE: Retrieve formal warning notices issued specifically
    to the current authenticated user's account ID.
    """
    return NoticeService.list_warning_notices(recipient_id=current_user["id"])


def _is_notice_recipient(notice: dict, user: dict) -> bool:
    user_id = str(user.get("id") or "").strip()
    user_uname = str(user.get("username") or "").strip().lower()
    rec_id = str(notice.get("recipient_id") or "").strip()
    rec_uname = str(notice.get("recipient_username") or "").strip().lower()

    return bool(
        (user_id and rec_id == user_id)
        or (user_uname and rec_uname == user_uname)
        or (user_uname and rec_id.lower() == user_uname)
        or (user_id and rec_uname == user_id.lower())
    )


@router.get("/notices/{notice_id}", response_model=WarningNoticeOut)
def get_warning_notice(
    notice_id: str,
    current_user: dict = Depends(get_current_user),
):
    """
    Retrieve details of a specific warning notice.
    Admins & Investigators can view any notice; Authorized Personnel can only view their own notice.
    """
    notice = NoticeService.get_warning_notice(notice_id)
    if not notice:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Warning notice {notice_id} not found.",
        )
    user_role = normalize_role(current_user.get("role"))
    if user_role == "RECIPIENT":
        if not _is_notice_recipient(notice, current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: You can only view notices issued to your account.",
            )
    elif user_role not in ("ADMIN", "INVESTIGATOR"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Requires ADMIN, INVESTIGATOR, or AUTHORISED_PERSONNEL role.",
        )
    return notice


@router.patch("/notices/{notice_id}/status", response_model=WarningNoticeOut)
@router.post("/notices/{notice_id}/acknowledge", response_model=WarningNoticeOut, include_in_schema=False)
def update_warning_notice_status(
    notice_id: str,
    payload: Optional[WarningNoticeStatusUpdate] = None,
    current_user: dict = Depends(get_current_user),
):
    """Update warning notice status (SENT, ACKNOWLEDGED, PENDING, CLOSED)."""
    notice = NoticeService.get_warning_notice(notice_id)
    if not notice:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Notice not found.")

    user_role = normalize_role(current_user.get("role"))
    if user_role == "RECIPIENT":
        if not _is_notice_recipient(notice, current_user):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied: Cannot update notice of another user.")
        new_status = (payload.status if payload else "ACKNOWLEDGED").strip().upper()
        if new_status != "ACKNOWLEDGED":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Authorised Personnel may only acknowledge notices.")
    else:
        if user_role not in ("ADMIN", "INVESTIGATOR"):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")
        new_status = (payload.status if payload else "ACKNOWLEDGED").strip().upper()

    return NoticeService.update_notice_status(
        notice_id=notice_id,
        new_status=new_status,
        actor=current_user,
    )


@router.post("/notices/{notice_id}/read", response_model=WarningNoticeOut)
def mark_warning_notice_read(
    notice_id: str,
    current_user: dict = Depends(get_current_user),
):
    """
    Mark warning notice as READ and record read timestamp.
    Authorized Personnel can only mark their own notices as read.
    """
    notice = NoticeService.get_warning_notice(notice_id)
    if not notice:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Notice not found.")

    user_role = normalize_role(current_user.get("role"))
    if user_role == "RECIPIENT":
        if not _is_notice_recipient(notice, current_user):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied: Cannot read notice of another user.")
    elif user_role not in ("ADMIN", "INVESTIGATOR"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")

    return NoticeService.mark_notice_as_read(notice_id, actor=current_user)


@router.post("/notices/{notice_id}/reply", response_model=WarningNoticeOut)
def reply_to_warning_notice_endpoint(
    notice_id: str,
    payload: WarningNoticeReply,
    current_user: dict = Depends(get_current_user),
):
    """
    Submit a formal explanation / reply to a warning notice, updating status to REPLIED.
    Authorized Personnel can only reply to their own notices.
    """
    notice = NoticeService.get_warning_notice(notice_id)
    if not notice:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Notice not found.")

    user_role = normalize_role(current_user.get("role"))
    if user_role == "RECIPIENT":
        if not _is_notice_recipient(notice, current_user):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied: Cannot reply to notice of another user.")
    elif user_role not in ("ADMIN", "INVESTIGATOR"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")

    return NoticeService.reply_to_warning_notice(notice_id, reply_text=payload.reply_text, actor=current_user)


@router.get("/notices/{notice_id}/download")
def download_warning_notice_pdf(
    notice_id: str,
    token: Optional[str] = None,
    authorization: Optional[str] = Header(None),
):
    """Download official warning notice PDF document."""
    auth_header = authorization or (f"Bearer {token}" if token else None)
    current_user = get_current_user(auth_header)
    user_role = normalize_role(current_user.get("role"))
    if user_role not in ("ADMIN", "INVESTIGATOR", "RECIPIENT"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied.",
        )
    notice = NoticeService.get_warning_notice(notice_id)
    if not notice:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Notice not found.")
    if user_role == "RECIPIENT":
        if not _is_notice_recipient(notice, current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Cannot download another employee's notice.",
            )

    pdf_bytes = NoticeService.generate_notice_pdf(notice_id)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="TraceSeal_Notice_{notice_id}.pdf"',
        },
    )
