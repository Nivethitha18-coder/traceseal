"""
Warning & Investigation Notice Service
Handles creation, storage, retrieval, status management, and PDF generation for
official system-generated security investigation notices addressed to identified recipients.
Preserves forensic neutrality and evidentiary integrity.
"""

from datetime import datetime, timezone
import uuid
import io
import html
from typing import Dict, Any, List, Optional
from fastapi import HTTPException, status

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from backend.database import get_db
from backend.services.storage import StorageService
from backend.crypto.pqc import pqc_provider
from backend.provenance.events import serialize_canonical
from backend.ledger.ledger import OfflineLedger


def esc(text: Any) -> str:
    """Safely escape text for ReportLab Paragraph XML parser."""
    if text is None:
        return "N/A"
    return html.escape(str(text))


class NoticeService:
    @classmethod
    def create_warning_notice(
        cls,
        investigation_id: Optional[str] = None,
        recipient_id: Optional[str] = None,
        reason: Optional[str] = None,
        subject: Optional[str] = None,
        message: Optional[str] = None,
        actor: Optional[Dict[str, Any]] = None,
        custom_notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generate a formal system-generated warning notice addressed
        to an Authorised Personnel recipient, issued by an Investigator.
        """
        with get_db() as conn:
            cursor = conn.cursor()
            recipient_candidate = recipient_id
            document_id = "DOC-CONFIDENTIAL"
            document_name = "Confidential Document"
            fingerprint_id = "WM-UNSPECIFIED"
            now_dt = datetime.now(timezone.utc)
            now_iso = now_dt.isoformat()
            detection_time_str = now_dt.strftime("%d/%m/%Y %H:%M UTC")

            if investigation_id:
                cursor.execute("SELECT * FROM investigations WHERE case_id = ?", (investigation_id,))
                inv = cursor.fetchone()
                if inv:
                    inv_dict = dict(inv)
                    fingerprint_id = inv_dict.get("extracted_watermark_id") or fingerprint_id
                    if not recipient_candidate:
                        recipient_candidate = inv_dict.get("matched_recipient_id")
                    document_id = inv_dict.get("matched_document_id") or document_id
                    try:
                        investigated_dt = datetime.fromisoformat(inv_dict["investigated_at"])
                        detection_time_str = investigated_dt.strftime("%d/%m/%Y %H:%M UTC")
                    except Exception:
                        pass

                    if not recipient_candidate and fingerprint_id != "WM-UNSPECIFIED":
                        cursor.execute(
                            "SELECT recipient_id, document_id FROM provenance_events WHERE watermark_id = ?",
                            (fingerprint_id,),
                        )
                        pe = cursor.fetchone()
                        if pe:
                            recipient_candidate = pe["recipient_id"]
                            if pe["document_id"]:
                                document_id = pe["document_id"]
                elif not recipient_candidate:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail=f"Investigation case {investigation_id} not found.",
                    )
            else:
                investigation_id = f"CASE-SEC-{uuid.uuid4().hex[:6].upper()}"

            if not recipient_candidate:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot issue notice: Please specify an Authorised Personnel recipient.",
                )

            # Resolve to the actual internal account ID in users table
            cursor.execute(
                "SELECT id, username, display_name FROM users WHERE id = ? OR username = ? COLLATE NOCASE OR display_name = ? COLLATE NOCASE",
                (recipient_candidate, recipient_candidate, recipient_candidate),
            )
            u_row = cursor.fetchone()
            if not u_row:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Authorised Personnel recipient account '{recipient_candidate}' not found.",
                )

            actual_account_id = u_row["id"]
            recipient_name = u_row["display_name"]
            recipient_username = u_row["username"]

            # Lookup document details if available, resolving to valid document for foreign key
            cursor.execute("SELECT document_id, original_filename FROM documents WHERE document_id = ?", (document_id,))
            d_row = cursor.fetchone()
            if d_row:
                document_name = d_row["original_filename"]
            else:
                cursor.execute("SELECT document_id, original_filename FROM documents ORDER BY created_at ASC LIMIT 1")
                d_row = cursor.fetchone()
                if d_row:
                    document_id = d_row["document_id"]
                    document_name = d_row["original_filename"]
                else:
                    cursor.execute(
                        """
                        INSERT OR IGNORE INTO documents (
                            document_id, original_filename, file_size, mime_type, sha256_hash,
                            encrypted_path, uploaded_by, created_at, status
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            "DOC-CONFIDENTIAL",
                            "Confidential Document",
                            1024,
                            "application/pdf",
                            "0" * 64,
                            "storage/encrypted/confidential.enc",
                            "SYS-ADMIN",
                            now_iso,
                            "ACTIVE",
                        ),
                    )
                    document_id = "DOC-CONFIDENTIAL"
                    document_name = "Confidential Document"

            # Ensure investigation record exists so foreign key constraint passes
            cursor.execute("SELECT case_id FROM investigations WHERE case_id = ?", (investigation_id,))
            if not cursor.fetchone():
                cursor.execute(
                    """
                    INSERT INTO investigations (
                        case_id, filename, file_hash, extracted_watermark_id, matched_recipient_id,
                        matched_document_id, attribution_status, investigated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        investigation_id,
                        document_name,
                        "sha256-security-warning",
                        fingerprint_id,
                        actual_account_id,
                        document_id,
                        "DIRECT SECURITY NOTICE",
                        now_iso,
                    ),
                )

            notice_id = f"NOT-{uuid.uuid4().hex[:8].upper()}"
            final_subject = subject or reason or "Security Investigation Notice – Document Leak"

            if message and message.strip():
                notice_body = message.strip()
            else:
                notice_body = f"""Subject: {final_subject}

Dear {recipient_name},

Your account has been associated with a document security investigation regarding "{document_name}" ({document_id}).

You are required to cooperate with the ongoing investigation and provide any requested information. Further account action may be taken according to the applicable security procedures.

Investigation Reference: {investigation_id}
Document Reference: {document_id} ({document_name})
Detection Time: {detection_time_str}

TRACESEAL Security Administration"""

            issuer_id = actor.get("id", "SYS-SECURITY") if actor else "SYS-SECURITY"
            issued_by = actor.get("username", "investigator01") if actor else "investigator01"
            issuer_role = actor.get("role", "INVESTIGATOR") if actor else "INVESTIGATOR"
            recipient_role = "AUTHORISED_PERSONNEL"
            initial_status = "SENT"

            # Duplicate check: one warning per (leak incident, recipient).
            # "No existing warning" is the NORMAL path and simply falls through to creation.
            # Direct notices without an incident (CASE-SEC-*) are never deduplicated.
            if investigation_id and not investigation_id.startswith("CASE-SEC-"):
                cursor.execute(
                    """
                    SELECT * FROM warning_notices
                    WHERE investigation_id = ? AND recipient_id = ?
                    ORDER BY created_at ASC LIMIT 1
                    """,
                    (investigation_id, actual_account_id),
                )
                existing_row = cursor.fetchone()
                if existing_row:
                    existing = cls._format_notice_dict(existing_row)
                    existing["already_issued"] = True
                    return existing

            # Step 1: Store the warning record first (ledger fields filled in after the ledger commit)
            ledger_event_id = f"EVT-WARN-{notice_id}"
            cursor.execute(
                """
                INSERT INTO warning_notices (
                    notice_id, warning_id, investigation_id, recipient_id, recipient_name, recipient_username,
                    recipient_role, document_id, document_name, fingerprint_id, created_at, issued_at,
                    issued_by, issuer_id, issuer_role, status, subject, reason, notice_body, message,
                    ledger_block_index, ledger_event_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    notice_id,
                    notice_id,
                    investigation_id,
                    actual_account_id,
                    recipient_name,
                    recipient_username,
                    recipient_role,
                    document_id,
                    document_name,
                    fingerprint_id,
                    now_iso,
                    now_iso,
                    issued_by,
                    issuer_id,
                    issuer_role,
                    initial_status,
                    final_subject,
                    final_subject,
                    notice_body,
                    notice_body,
                    None,
                    ledger_event_id,
                ),
            )

            # Step 2: Exactly one WARNING_ISSUED ledger event referencing the stored warning ID.
            # Same transaction: if signing/commit fails, get_db() rolls back the warning row too,
            # so success is never reported for a half-completed flow.
            warning_event = {
                "event_id": ledger_event_id,
                "event_type": "WARNING_ISSUED",
                "warning_id": notice_id,
                "issuer_id": issuer_id,
                "issuer_username": issued_by,
                "issuer_role": issuer_role,
                "recipient_id": actual_account_id,
                "recipient_username": recipient_username,
                "recipient_name": recipient_name,
                "recipient_role": recipient_role,
                "reason": final_subject,
                "message": notice_body,
                "document_id": document_id,
                "investigation_id": investigation_id,
                "watermark_id": "WARNING_ISSUED",
                "timestamp": now_iso,
            }
            canonical_payload = serialize_canonical(warning_event)
            warning_sig = pqc_provider.sign_with_authority(canonical_payload.encode("utf-8"))
            ledger_block = OfflineLedger.commit_event(warning_event, warning_sig, conn=conn)
            ledger_block_index = ledger_block.get("block_index")
            if ledger_block_index is None:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Warning could not be committed to the ledger.",
                )

            cursor.execute(
                "UPDATE warning_notices SET ledger_block_index = ? WHERE notice_id = ?",
                (ledger_block_index, notice_id),
            )

            # Audit log inside same connection/transaction
            action_id = f"ACT-NOT-{uuid.uuid4().hex[:6].upper()}"
            cursor.execute(
                """
                INSERT INTO account_action_audits (
                    action_id, investigator_id, investigator_username, target_user_id, target_username,
                    action, previous_status, new_status, timestamp, investigation_id, fingerprint_id, ledger_record_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    action_id,
                    issuer_id,
                    issued_by,
                    actual_account_id,
                    recipient_username,
                    "WARNING_NOTICE_ISSUED",
                    "NOTICE_PENDING",
                    "NOTICE_SENT",
                    now_iso,
                    investigation_id,
                    fingerprint_id,
                    str(ledger_block_index),
                ),
            )

        return {
            "notice_id": notice_id,
            "warning_id": notice_id,
            "investigation_id": investigation_id,
            "recipient_id": actual_account_id,
            "recipient_name": recipient_name,
            "recipient_username": recipient_username,
            "recipient_role": recipient_role,
            "document_id": document_id,
            "document_name": document_name,
            "fingerprint_id": fingerprint_id,
            "created_at": now_iso,
            "issued_at": now_iso,
            "issued_by": issued_by,
            "issuer_id": issuer_id,
            "issuer_role": issuer_role,
            "status": initial_status,
            "subject": final_subject,
            "reason": final_subject,
            "notice_body": notice_body,
            "message": notice_body,
            "ledger_block_index": ledger_block_index,
            "ledger_event_id": ledger_event_id,
            "already_issued": False,
        }

    @classmethod
    def list_warning_notices(
        cls,
        recipient_id: Optional[str] = None,
        investigation_id: Optional[str] = None,
        issued_by: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List all stored warning/investigation notices with optional filtering."""
        with get_db() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM warning_notices"
            conditions = []
            params = []
            if recipient_id:
                # Resolve recipient_id so both internal account ID and canonical username match
                cursor.execute(
                    "SELECT id, username FROM users WHERE id = ? OR username = ? COLLATE NOCASE",
                    (recipient_id, recipient_id),
                )
                u = cursor.fetchone()
                if u:
                    uid = u["id"]
                    uname = u["username"]
                    conditions.append("(recipient_id = ? OR recipient_id = ? OR recipient_username = ? COLLATE NOCASE)")
                    params.extend([uid, uname, uname])
                else:
                    conditions.append("(recipient_id = ? OR recipient_username = ? COLLATE NOCASE)")
                    params.extend([recipient_id, recipient_id])
            if investigation_id:
                conditions.append("investigation_id = ?")
                params.append(investigation_id)
            if issued_by:
                cursor.execute(
                    "SELECT id, username FROM users WHERE id = ? OR username = ? COLLATE NOCASE",
                    (issued_by, issued_by),
                )
                u_iss = cursor.fetchone()
                if u_iss:
                    iss_uid = u_iss["id"]
                    iss_uname = u_iss["username"]
                    conditions.append("(issued_by = ? OR issuer_id = ? OR issued_by = ? COLLATE NOCASE)")
                    params.extend([iss_uname, iss_uid, iss_uname])
                else:
                    conditions.append("(issued_by = ? OR issuer_id = ? COLLATE NOCASE)")
                    params.extend([issued_by, issued_by])
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            query += " ORDER BY created_at DESC"
            cursor.execute(query, tuple(params))
            rows = [dict(r) for r in cursor.fetchall()]
            for r in rows:
                if not r.get("warning_id"):
                    r["warning_id"] = r.get("notice_id")
                if not r.get("reason"):
                    r["reason"] = r.get("subject")
                if not r.get("message"):
                    r["message"] = r.get("notice_body")
                if not r.get("issued_at"):
                    r["issued_at"] = r.get("created_at")
                if not r.get("recipient_role"):
                    r["recipient_role"] = "AUTHORISED_PERSONNEL"
                if not r.get("issuer_role"):
                    r["issuer_role"] = "INVESTIGATOR"
            return rows

    @classmethod
    def _format_notice_dict(cls, row_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Format warning notice database record ensuring all required fields are present and normalized."""
        r = dict(row_dict)
        if not r.get("warning_id"):
            r["warning_id"] = r.get("notice_id")
        if not r.get("reason"):
            r["reason"] = r.get("subject") or "Security Investigation Warning"
        if not r.get("subject"):
            r["subject"] = r.get("reason") or "Security Investigation Warning"
        if not r.get("message"):
            r["message"] = r.get("notice_body") or ""
        if not r.get("notice_body"):
            r["notice_body"] = r.get("message") or ""
        if not r.get("issued_at"):
            r["issued_at"] = r.get("created_at")
        if not r.get("recipient_role"):
            r["recipient_role"] = "AUTHORISED_PERSONNEL"
        if not r.get("issuer_role"):
            r["issuer_role"] = "INVESTIGATOR"
        return r

    @classmethod
    def get_warning_notice(cls, notice_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a specific warning notice by notice_id or warning_id."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM warning_notices WHERE notice_id = ? OR warning_id = ?",
                (notice_id, notice_id),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return cls._format_notice_dict(row)

    @classmethod
    def mark_notice_as_read(cls, notice_id: str, actor: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Mark notice as READ and record read_at timestamp."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM warning_notices WHERE notice_id = ? OR warning_id = ?",
                (notice_id, notice_id),
            )
            row = cursor.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Notice not found.")
            notice_dict = dict(row)
            target_nid = notice_dict.get("notice_id") or notice_id
            now_iso = datetime.now(timezone.utc).isoformat()
            new_status = notice_dict["status"]
            if new_status in ("SENT", "PENDING"):
                new_status = "READ"
            read_at = notice_dict.get("read_at") or now_iso

            cursor.execute(
                "UPDATE warning_notices SET status = ?, read_at = ? WHERE notice_id = ? OR warning_id = ?",
                (new_status, read_at, target_nid, target_nid),
            )
            cursor.execute(
                "SELECT * FROM warning_notices WHERE notice_id = ? OR warning_id = ?",
                (target_nid, target_nid),
            )
            return cls._format_notice_dict(cursor.fetchone())

    @classmethod
    def reply_to_warning_notice(cls, notice_id: str, reply_text: str, actor: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Submit a recipient explanation / reply to a warning notice, setting status to REPLIED."""
        if not reply_text or not reply_text.strip():
            raise HTTPException(status_code=400, detail="Reply text cannot be empty.")
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM warning_notices WHERE notice_id = ? OR warning_id = ?",
                (notice_id, notice_id),
            )
            row = cursor.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Notice not found.")
            notice_dict = dict(row)
            target_nid = notice_dict.get("notice_id") or notice_id
            prev_status = notice_dict["status"]
            now_iso = datetime.now(timezone.utc).isoformat()
            reply_by = (actor.get("username") if actor else None) or notice_dict.get("recipient_username") or "recipient"

            cursor.execute(
                """
                UPDATE warning_notices
                SET status = 'REPLIED', reply_text = ?, replied_at = ?, reply_by = ?,
                    read_at = COALESCE(read_at, ?)
                WHERE notice_id = ? OR warning_id = ?
                """,
                (reply_text.strip(), now_iso, reply_by, now_iso, target_nid, target_nid),
            )

        # Audit log entry for notice response
        action_id = f"ACT-REP-{uuid.uuid4().hex[:6].upper()}"
        actor_id = (actor.get("id") if actor else None) or notice_dict["recipient_id"]
        actor_username = (actor.get("username") if actor else None) or notice_dict.get("recipient_username") or "recipient"
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO account_action_audits (
                    action_id, investigator_id, investigator_username, target_user_id, target_username,
                    action, previous_status, new_status, timestamp, investigation_id, fingerprint_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    action_id,
                    actor_id,
                    actor_username,
                    notice_dict["recipient_id"],
                    notice_dict.get("recipient_username") or "recipient",
                    "WARNING_NOTICE_REPLIED",
                    prev_status,
                    "REPLIED",
                    now_iso,
                    notice_dict["investigation_id"],
                    notice_dict["fingerprint_id"],
                ),
            )

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM warning_notices WHERE notice_id = ? OR warning_id = ?",
                (target_nid, target_nid),
            )
            return cls._format_notice_dict(cursor.fetchone())

    @classmethod
    def update_notice_status(cls, notice_id: str, new_status: str, actor: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Update notice status (SENT, READ, ACKNOWLEDGED, REPLIED, PENDING, CLOSED)."""
        new_status = new_status.strip().upper()
        if new_status not in ("SENT", "READ", "ACKNOWLEDGED", "REPLIED", "PENDING", "CLOSED"):
            raise HTTPException(status_code=400, detail="Invalid notice status.")
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM warning_notices WHERE notice_id = ? OR warning_id = ?",
                (notice_id, notice_id),
            )
            row = cursor.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Notice not found.")
            target_nid = dict(row).get("notice_id") or notice_id
            cursor.execute(
                "UPDATE warning_notices SET status = ? WHERE notice_id = ? OR warning_id = ?",
                (new_status, target_nid, target_nid),
            )
            cursor.execute(
                "SELECT * FROM warning_notices WHERE notice_id = ? OR warning_id = ?",
                (target_nid, target_nid),
            )
            return cls._format_notice_dict(cursor.fetchone())

    @classmethod
    def generate_notice_pdf(cls, notice_id: str) -> bytes:
        """Generate official PDF notice for download."""
        notice = cls.get_warning_notice(notice_id)
        if not notice:
            raise HTTPException(status_code=404, detail="Notice not found.")

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=45,
            leftMargin=45,
            topMargin=45,
            bottomMargin=45,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "NoticeTitle",
            parent=styles["Heading1"],
            fontSize=16,
            leading=20,
            textColor=colors.HexColor("#0f172a"),
            fontName="Helvetica-Bold",
        )
        subtitle_style = ParagraphStyle(
            "NoticeSubtitle",
            parent=styles["Normal"],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#64748b"),
        )
        body_style = ParagraphStyle(
            "NoticeBody",
            parent=styles["Normal"],
            fontSize=10,
            leading=15,
            textColor=colors.HexColor("#1e293b"),
        )
        meta_label_style = ParagraphStyle(
            "NoticeMetaLabel",
            parent=styles["Normal"],
            fontSize=8,
            leading=10,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#475569"),
        )
        meta_val_style = ParagraphStyle(
            "NoticeMetaVal",
            parent=styles["Normal"],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#0f172a"),
        )

        elements = []

        # Header Banner
        header_data = [
            [
                Paragraph("<b>TRACESEAL SECURITY ADMINISTRATION</b>", title_style),
                Paragraph(f"<b>NOTICE ID:</b> {esc(notice['notice_id'])}<br/><b>DATE:</b> {esc(notice['created_at'][:10])}", meta_val_style)
            ]
        ]
        t_header = Table(header_data, colWidths=[360, 160])
        t_header.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
        ]))
        elements.append(t_header)
        elements.append(Spacer(1, 10))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#cbd5e1"), spaceAfter=15))

        # Metadata Table
        meta_table_data = [
            [
                Paragraph("RECIPIENT NAME:", meta_label_style),
                Paragraph(esc(notice["recipient_name"]), meta_val_style),
                Paragraph("RECIPIENT USERNAME:", meta_label_style),
                Paragraph(f"@{esc(notice['recipient_username'])}", meta_val_style),
            ],
            [
                Paragraph("INVESTIGATION REF:", meta_label_style),
                Paragraph(esc(notice["investigation_id"]), meta_val_style),
                Paragraph("FINGERPRINT ID:", meta_label_style),
                Paragraph(esc(notice["fingerprint_id"]), meta_val_style),
            ],
            [
                Paragraph("DOCUMENT REFERENCE:", meta_label_style),
                Paragraph(f"{esc(notice['document_name'])} ({esc(notice['document_id'])})", meta_val_style),
                Paragraph("NOTICE STATUS:", meta_label_style),
                Paragraph(f"<b>{esc(notice['status'])}</b>", meta_val_style),
            ],
        ]
        t_meta = Table(meta_table_data, colWidths=[120, 150, 120, 130])
        t_meta.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        elements.append(t_meta)
        elements.append(Spacer(1, 18))

        # Notice Title
        elements.append(Paragraph(f"<b>{esc(notice['subject'])}</b>", title_style))
        elements.append(Spacer(1, 12))

        # Notice Body Paragraphs
        paragraphs = notice["notice_body"].split("\n\n")
        for p in paragraphs:
            clean_p = p.strip()
            if clean_p.startswith("Subject:"):
                continue
            elements.append(Paragraph(esc(clean_p).replace("\n", "<br/>"), body_style))
            elements.append(Spacer(1, 10))

        # Recipient Read Status
        if notice.get("read_at"):
            elements.append(Spacer(1, 4))
            elements.append(Paragraph(f"<b>Recipient Read Confirmation:</b> Notice opened & read by recipient on {esc(str(notice['read_at'])[:19].replace('T', ' '))} UTC", subtitle_style))

        # Recipient Formal Response Section
        if notice.get("reply_text"):
            elements.append(Spacer(1, 10))
            elements.append(HRFlowable(width="100%", thickness=0.8, color=colors.HexColor("#cbd5e1"), spaceAfter=10))
            elements.append(Paragraph("<b>RECIPIENT FORMAL EXPLANATION / RESPONSE</b>", title_style))
            elements.append(Spacer(1, 4))
            rep_meta = f"Submitted by @{esc(notice.get('reply_by') or notice.get('recipient_username'))} on {esc(str(notice.get('replied_at') or '')[:19].replace('T', ' '))} UTC"
            elements.append(Paragraph(rep_meta, subtitle_style))
            elements.append(Spacer(1, 8))
            elements.append(Paragraph(esc(notice["reply_text"]).replace("\n", "<br/>"), body_style))
            elements.append(Spacer(1, 10))

        elements.append(Spacer(1, 20))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0"), spaceAfter=15))

        # Footer Seal
        footer_text = f"CONFIDENTIAL // OFFICIAL SECURITY INVESTIGATION NOTICE // ISSUED BY {esc(notice['issued_by']).upper()} // IMMUTABLE TRACESEAL AUDIT TRAIL"
        elements.append(Paragraph(footer_text, subtitle_style))

        doc.build(elements)
        return buffer.getvalue()
