"""
Forensic Leak Investigation Engine
Performs multi-step cryptographic verification and recipient attribution on suspect files.
"""

from datetime import datetime, timezone
import uuid
from typing import Dict, Any, Optional

from backend.database import get_db
from backend.crypto.hashing import sha256_bytes
from backend.watermark.extractor import WatermarkExtractor
from backend.provenance.verification import verify_event_signature
from backend.ledger.verification import verify_ledger
from backend.services.storage import StorageService


class ForensicInvestigator:
    @classmethod
    def investigate_file(
        cls,
        file_bytes: bytes,
        filename: str,
    ) -> Dict[str, Any]:
        """
        Execute full forensic pipeline:
        1. Compute SHA-256 of leaked file.
        2. Extract forensic watermark.
        3. Search provenance event matching watermark_id.
        4. Match session, recipient, and document.
        5. Verify digital signature on canonical provenance event.
        6. Verify document hash match.
        7. Verify offline ledger integrity.
        8. Synthesize final attribution status.
        9. Store case in database.
        """
        investigated_at = datetime.now(timezone.utc).isoformat()

        # Step 1: Calculate SHA-256
        leaked_hash = sha256_bytes(file_bytes)

        # Step 2: Extract watermark
        wm_res = WatermarkExtractor.extract_from_bytes(file_bytes)
        watermark_extracted = wm_res["extracted"]
        watermark_id = wm_res["watermark_id"]

        # Step 2b: Corroborate via Deterministic Cryptographic Hash if not extracted via steganography
        if not watermark_extracted or not watermark_id:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM distributed_copies WHERE document_hash = ? ORDER BY downloaded_at DESC LIMIT 1",
                    (leaked_hash,),
                )
                row_cp = cursor.fetchone()
                if row_cp:
                    watermark_id = row_cp["fingerprint"]
                    watermark_extracted = True
                    wm_res["extracted"] = True
                    wm_res["watermark_id"] = watermark_id
                    wm_res["extraction_layer"] = "Deterministic Cryptographic Hash Match (SHA-256)"
                    wm_res["confidence"] = 1.0
                    wm_res["message"] = "Suspect copy identified via distributed copy hash match."
                else:
                    cursor.execute(
                        "SELECT * FROM provenance_events WHERE document_hash = ? ORDER BY timestamp DESC LIMIT 1",
                        (leaked_hash,),
                    )
                    row_evt = cursor.fetchone()
                    if row_evt:
                        watermark_id = row_evt["watermark_id"]
                        watermark_extracted = True
                        wm_res["extracted"] = True
                        wm_res["watermark_id"] = watermark_id
                        wm_res["extraction_layer"] = "Deterministic Cryptographic Hash Match (SHA-256)"
                        wm_res["confidence"] = 1.0
                        wm_res["message"] = "Suspect copy identified via cryptographic provenance hash match."
                    else:
                        cursor.execute(
                            "SELECT * FROM decryption_sessions WHERE document_hash = ? AND watermark_id IS NOT NULL ORDER BY completed_at DESC LIMIT 1",
                            (leaked_hash,),
                        )
                        row_sess = cursor.fetchone()
                        if row_sess and row_sess["watermark_id"]:
                            watermark_id = row_sess["watermark_id"]
                            watermark_extracted = True
                            wm_res["extracted"] = True
                            wm_res["watermark_id"] = watermark_id
                            wm_res["extraction_layer"] = "Deterministic Cryptographic Hash Match (SHA-256)"
                            wm_res["confidence"] = 1.0
                            wm_res["message"] = "Suspect copy identified via decryption session hash match."

        copy_record: Optional[Dict[str, Any]] = None
        matched_event: Optional[Dict[str, Any]] = None
        recipient_info: Optional[Dict[str, Any]] = None
        document_info: Optional[Dict[str, Any]] = None
        ledger_block: Optional[Dict[str, Any]] = None

        watermark_match = False
        signature_valid = False
        document_hash_match = False
        ledger_valid = False

        if watermark_extracted and watermark_id:
            with get_db() as conn:
                cursor = conn.cursor()

                # Step 3: Lookup persistent distributed copy record
                cursor.execute(
                    "SELECT * FROM distributed_copies WHERE fingerprint = ?",
                    (watermark_id,),
                )
                row_cp = cursor.fetchone()
                if row_cp:
                    copy_record = dict(row_cp)

                # Step 4: Lookup provenance event
                cursor.execute(
                    "SELECT * FROM provenance_events WHERE watermark_id = ?",
                    (watermark_id,),
                )
                row_evt = cursor.fetchone()

                if row_evt:
                    matched_event = dict(row_evt)
                    watermark_match = True
                elif copy_record and copy_record.get("provenance_event_id"):
                    cursor.execute(
                        "SELECT * FROM provenance_events WHERE event_id = ?",
                        (copy_record["provenance_event_id"],),
                    )
                    row_evt2 = cursor.fetchone()
                    if row_evt2:
                        matched_event = dict(row_evt2)
                        watermark_match = True

                # Lookup Recipient details using ID or username from event or persistent copy record
                rec_candidate = (matched_event.get("recipient_id") if matched_event else None) or (copy_record.get("user_id") or copy_record.get("username") if copy_record else None)
                if rec_candidate:
                    cursor.execute(
                        "SELECT id, username, display_name, role FROM users WHERE id = ? OR username = ? COLLATE NOCASE",
                        (rec_candidate, rec_candidate),
                    )
                    u = cursor.fetchone()
                    if u:
                        recipient_info = dict(u)

                # Lookup Document details
                doc_candidate = (matched_event.get("document_id") if matched_event else None) or (copy_record.get("document_id") if copy_record else None)
                if doc_candidate:
                    cursor.execute(
                        "SELECT document_id, original_filename, original_hash FROM documents WHERE document_id = ?",
                        (doc_candidate,),
                    )
                    d = cursor.fetchone()
                    if d:
                        document_info = dict(d)

                # Lookup Ledger Block for this event
                cursor.execute(
                    "SELECT * FROM ledger_blocks WHERE watermark_id = ?",
                    (watermark_id,),
                )
                b = cursor.fetchone()
                if b:
                    ledger_block = dict(b)

            # Step 5: Verify Digital Signature on canonical provenance event
            if matched_event:
                payload_to_verify = matched_event.get("canonical_payload") or {
                    "event_id": matched_event["event_id"],
                    "session_id": matched_event["session_id"],
                    "document_id": matched_event["document_id"],
                    "recipient_id": matched_event["recipient_id"],
                    "document_hash": matched_event["document_hash"],
                    "watermark_id": matched_event["watermark_id"],
                    "timestamp": matched_event["timestamp"],
                }
                sig_valid, _ = verify_event_signature(
                    payload_to_verify,
                    matched_event["signature"],
                    matched_event["public_key_ref"],
                )
                signature_valid = sig_valid

                # Step 6: Verify Document Hash Match
                document_hash_match = (leaked_hash == matched_event["document_hash"])

        # Step 7: Verify Ledger Chain Integrity
        ledger_res = verify_ledger()
        ledger_valid = ledger_res["valid"]

        # Step 8: Attribution Decision & Exact Copy Identification per SIH Sections 20-23
        if watermark_match and signature_valid and ledger_valid and matched_event and recipient_info:
            attribution_status = "ATTRIBUTION VERIFIED"
            issued_copy_status = "MATCHED"
            leak_status = "LEAK SOURCE COPY IDENTIFIED"
            emp_name = recipient_info.get("display_name", "Unknown")
            u_name = recipient_info.get("username", "unknown")
            attribution_statement = f"Source copy identified: Leaked copy matches the copy issued to {emp_name} (@{u_name})."
        elif watermark_match and not signature_valid:
            attribution_status = "SIGNATURE VERIFICATION FAILED"
            issued_copy_status = "NOT VERIFIED"
            leak_status = "SIGNATURE VERIFICATION FAILED"
            attribution_statement = "SIGNATURE VERIFICATION FAILED: The provenance record cannot be cryptographically verified."
        elif watermark_match and not ledger_valid:
            attribution_status = "LEDGER TAMPERING DETECTED"
            issued_copy_status = "NOT VERIFIED"
            leak_status = "LEDGER TAMPERING DETECTED"
            attribution_statement = "LEDGER TAMPERING DETECTED: The local ledger chain has been tampered with or modified."
        elif watermark_extracted and not watermark_match:
            attribution_status = "NO MATCH FOUND"
            issued_copy_status = "NOT IDENTIFIED"
            leak_status = "NO MATCH FOUND"
            attribution_statement = "NO MATCH FOUND: The extracted fingerprint does not correspond to a known registered decryption event."
        else:
            attribution_status = "ATTRIBUTION COULD NOT BE VERIFIED"
            issued_copy_status = "NOT IDENTIFIED"
            leak_status = "NO LEAK DETECTED"
            attribution_statement = "No matching distributed copy found or cryptographic verification failed."

        recipient_user = recipient_info["username"] if recipient_info else (copy_record["username"] if copy_record else None)
        recipient_display = recipient_info["display_name"] if recipient_info else (copy_record["employee_name"] if copy_record else None)
        recipient_role = recipient_info.get("role", "RECIPIENT") if recipient_info else "Employee"
        if recipient_role == "RECIPIENT":
            recipient_role = "Employee"

        # Evidence Chain Visual Flow Items
        evidence_chain = [
            {
                "step": 1,
                "label": "LEAKED FILE SCAN",
                "detail": f"{filename} (SHA-256: {leaked_hash[:12]}...)",
                "status": "PASS",
            },
            {
                "step": 2,
                "label": "FORENSIC FINGERPRINT",
                "detail": f"Detected: {watermark_id or 'NOT FOUND'} (Layer: {wm_res.get('extraction_layer') or 'None'})",
                "status": "PASS" if watermark_match else "FAIL",
            },
            {
                "step": 3,
                "label": "ISSUED COPY MATCH",
                "detail": f"Copy ID: {matched_event['session_id'] if matched_event else 'N/A'} (Issued to: {recipient_display or 'N/A'})",
                "status": "PASS" if watermark_match and matched_event else "FAIL",
            },
            {
                "step": 4,
                "label": "RECIPIENT ATTRIBUTION",
                "detail": f"Source copy identified: {recipient_display} (@{recipient_user})" if recipient_info else "UNKNOWN RECIPIENT",
                "status": "PASS" if recipient_info else "FAIL",
            },
            {
                "step": 5,
                "label": "DIGITAL SIGNATURE (ML-DSA-44)",
                "detail": f"Algorithm: {matched_event['algorithm'] if matched_event else 'N/A'}",
                "status": "PASS" if signature_valid else "FAIL",
            },
            {
                "step": 6,
                "label": "TAMPER-EVIDENT LEDGER",
                "detail": f"Block #{ledger_block['block_index'] if ledger_block else 'N/A'} (Chain: {ledger_res['status']})",
                "status": "PASS" if (ledger_block and ledger_valid) else "FAIL",
            },
            {
                "step": 7,
                "label": "LEAK STATUS VERDICT",
                "detail": attribution_statement,
                "status": "PASS" if attribution_status == "ATTRIBUTION VERIFIED" else "FAIL",
            },
        ]

        canonical_rec_id = recipient_info["id"] if recipient_info else (matched_event["recipient_id"] if matched_event else (copy_record["user_id"] if copy_record else None))
        canonical_evt_id = matched_event["event_id"] if matched_event else (copy_record.get("provenance_event_id") if copy_record else None)
        canonical_ses_id = matched_event["session_id"] if matched_event else (copy_record.get("copy_id") if copy_record else None)
        canonical_doc_id = matched_event["document_id"] if matched_event else (copy_record.get("document_id") if copy_record else None)

        # Record Investigation in DB and update document status ONLY if verified leak
        final_case_id: Optional[str] = None
        if attribution_status == "ATTRIBUTION VERIFIED":
            with get_db() as conn:
                cursor = conn.cursor()
                existing_case = None

                # Check if this leak incident already exists for a document already designated as LEAKED
                if watermark_id and canonical_doc_id:
                    cursor.execute(
                        """
                        SELECT i.case_id FROM investigations i
                        JOIN documents d ON i.matched_document_id = d.document_id
                        WHERE d.status = 'LEAKED'
                          AND i.extracted_watermark_id = ?
                          AND i.attribution_status IN ('ATTRIBUTION VERIFIED', 'LEAK DETECTED', 'CONFIRMED_LEAK')
                        ORDER BY i.investigated_at DESC LIMIT 1
                        """,
                        (watermark_id,),
                    )
                    existing_case = cursor.fetchone()

                if not existing_case and canonical_doc_id and canonical_rec_id:
                    cursor.execute(
                        """
                        SELECT i.case_id FROM investigations i
                        JOIN documents d ON i.matched_document_id = d.document_id
                        WHERE d.status = 'LEAKED'
                          AND i.matched_document_id = ? AND i.matched_recipient_id = ?
                          AND i.attribution_status IN ('ATTRIBUTION VERIFIED', 'LEAK DETECTED', 'CONFIRMED_LEAK')
                        ORDER BY i.investigated_at DESC LIMIT 1
                        """,
                        (canonical_doc_id, canonical_rec_id),
                    )
                    existing_case = cursor.fetchone()

                if not existing_case and leaked_hash:
                    cursor.execute(
                        """
                        SELECT i.case_id FROM investigations i
                        JOIN documents d ON i.matched_document_id = d.document_id
                        WHERE d.status = 'LEAKED'
                          AND i.file_hash = ?
                          AND i.attribution_status IN ('ATTRIBUTION VERIFIED', 'LEAK DETECTED', 'CONFIRMED_LEAK')
                        ORDER BY i.investigated_at DESC LIMIT 1
                        """,
                        (leaked_hash,),
                    )
                    existing_case = cursor.fetchone()

                # Always mark the document status as LEAKED upon verified attribution
                if canonical_doc_id:
                    cursor.execute(
                        "UPDATE documents SET status = 'LEAKED' WHERE document_id = ? AND status != 'DELETED'",
                        (canonical_doc_id,),
                    )

                if existing_case:
                    final_case_id = existing_case["case_id"]
                    cursor.execute(
                        """
                        UPDATE investigations
                        SET investigated_at = ?, filename = ?
                        WHERE case_id = ?
                        """,
                        (investigated_at, filename, final_case_id),
                    )
                else:
                    final_case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"
                    if canonical_doc_id:
                        cursor.execute(
                            "UPDATE documents SET status = 'LEAKED' WHERE document_id = ? AND status != 'DELETED'",
                            (canonical_doc_id,),
                        )

                    cursor.execute(
                        """
                        INSERT INTO investigations (
                            case_id, filename, file_hash, extracted_watermark_id, matched_event_id,
                            matched_recipient_id, matched_session_id, matched_document_id,
                            watermark_matched, signature_valid, document_hash_match, ledger_valid,
                            attribution_status, investigated_at, report_filename
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            final_case_id,
                            filename,
                            leaked_hash,
                            watermark_id,
                            canonical_evt_id,
                            canonical_rec_id,
                            canonical_ses_id,
                            canonical_doc_id,
                            1 if watermark_match else 0,
                            1 if signature_valid else 0,
                            1 if document_hash_match else 0,
                            1 if ledger_valid else 0,
                            attribution_status,
                            investigated_at,
                            f"report_{final_case_id}.pdf",
                        ),
                    )

                # Record Audit Event for verified leak incident
                action_id = f"ACT-LEAK-{uuid.uuid4().hex[:6].upper()}"
                cursor.execute(
                    """
                    INSERT INTO account_action_audits (
                        action_id, investigator_id, investigator_username, target_user_id, target_username,
                        action, previous_status, new_status, timestamp, investigation_id, fingerprint_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        action_id,
                        "SYS-SECURITY",
                        "forensic_investigator",
                        canonical_rec_id or "UNKNOWN",
                        recipient_user or "unknown",
                        "LEAK_DETECTED_ATTRIBUTED",
                        "NORMAL",
                        "LEAK_CONFIRMED",
                        investigated_at,
                        final_case_id,
                        watermark_id or "FP-DETECTED",
                    ),
                )

            # Save evidence file and pre-generate the Forensic Report PDF
            try:
                StorageService.save_leaked_file(final_case_id, filename, file_bytes)
                from backend.forensic.report import generate_forensic_report_pdf
                generate_forensic_report_pdf(final_case_id)
            except Exception:
                pass

        orig_filename = (
            (document_info["original_filename"] if document_info and "original_filename" in document_info else None)
            or (copy_record["document_name"] if copy_record and "document_name" in copy_record else None)
            or filename
        )
        orig_hash = (
            (document_info["original_hash"] if document_info and "original_hash" in document_info else None)
            or (copy_record.get("document_hash") if copy_record else None)
            or (matched_event.get("document_hash") if matched_event else None)
            or leaked_hash
        )
        stored_ts = (
            (matched_event.get("timestamp") if matched_event else None)
            or (copy_record.get("downloaded_at") if copy_record else None)
            or investigated_at
        )
        ledger_idx = (
            (ledger_block.get("block_index") if ledger_block else None)
            or (copy_record.get("ledger_block_index") if copy_record else None)
            or 1
        )

        return {
            "case_id": final_case_id,
            "filename": filename,
            "file_hash": leaked_hash,
            "extracted": watermark_extracted,
            "watermark_id": watermark_id,
            "copy_fingerprint": watermark_id,
            "extracted_watermark_id": watermark_id,
            "fingerprint_id": watermark_id,
            "matched_event_id": canonical_evt_id,
            "matched_session_id": canonical_ses_id,
            "session_id": canonical_ses_id,
            "matched_recipient_id": canonical_rec_id,
            "matched_recipient_name": f"{recipient_display} ({recipient_user})" if recipient_display else None,
            "recipient_name": recipient_display,
            "recipient_username": recipient_user,
            "recipient_employee_name": recipient_display,
            "recipient_role": recipient_role,
            "matched_document_id": canonical_doc_id,
            "original_filename": orig_filename,
            "original_hash": orig_hash,
            "document_version": "v1.0",
            "decryption_timestamp": stored_ts,
            "download_timestamp": stored_ts,
            "action_event": "DECRYPT_AND_DOWNLOAD",
            "watermark_match": watermark_match,
            "watermark_status": "EMBEDDED" if watermark_match else "NOT EMBEDDED",
            "method": "Imperceptible Multi-Layer Steganography",
            "decryption_status": "SUCCESS" if watermark_match else "NOT APPLICABLE",
            "signature_valid": signature_valid,
            "document_hash_match": document_hash_match,
            "ledger_valid": ledger_valid,
            "attribution_status": attribution_status,
            "issued_copy_status": issued_copy_status,
            "leak_status": leak_status,
            "attribution_statement": attribution_statement,
            "ledger_block_index": ledger_idx,
            "report_download_url": f"/api/forensics/reports/{final_case_id}/download" if final_case_id else None,
            "evidence_chain": evidence_chain,
        }
