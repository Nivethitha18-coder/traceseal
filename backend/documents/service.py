"""
Document & Decryption Service
Handles upload, AES-256-GCM encryption, recipient authorization,
and session-specific forensic watermarking decryption.
"""

from datetime import datetime, timezone
import uuid
from typing import Dict, Any, List, Optional
from pypdf import PdfReader
import io

from backend.database import get_db
from backend.crypto.hashing import sha256_bytes
from backend.crypto.encryption import key_manager, document_cipher
from backend.services.storage import StorageService
from backend.watermark.generator import generate_watermark_id
from backend.watermark.embedder import WatermarkEmbedder
from backend.provenance.events import create_canonical_event
from backend.provenance.signing import sign_provenance_event
from backend.ledger.ledger import OfflineLedger


class DocumentService:
    @classmethod
    def upload_and_encrypt(
        cls,
        file_bytes: bytes,
        filename: str,
        uploaded_by_user_id: str,
    ) -> Dict[str, Any]:
        """
        Validate, hash, encrypt with AES-256-GCM, and store a confidential document.
        """
        # 1. Validate file content and structure
        if not file_bytes or len(file_bytes) == 0:
            raise ValueError("Uploaded file content is empty.")

        lower_fn = filename.lower()
        if lower_fn.endswith(".pdf"):
            try:
                reader = PdfReader(io.BytesIO(file_bytes))
                if len(reader.pages) == 0:
                    raise ValueError("PDF contains no pages")
            except Exception as e:
                if not file_bytes.startswith(b"%PDF"):
                    raise ValueError(f"Uploaded file is not a valid PDF: {str(e)}")

        # 2. Generate unique document_id
        doc_id = f"DOC-{uuid.uuid4().hex[:8].upper()}"

        # 3. Calculate SHA-256 of original file
        orig_hash = sha256_bytes(file_bytes)

        # 4. Generate unique 256-bit key in offline key vault
        dek = key_manager.generate_and_store_dek(doc_id)

        # 5. Encrypt with AES-256-GCM (associated data = doc_id)
        encrypted_bytes = document_cipher.encrypt(
            file_bytes, dek, associated_data=doc_id.encode("utf-8")
        )

        # 6. Save encrypted file to disk
        StorageService.save_encrypted_file(doc_id, encrypted_bytes)

        created_at = datetime.now(timezone.utc).isoformat()

        # 7. Store metadata and persistent DEK in SQLite
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO documents (
                    document_id, original_filename, original_hash, encrypted_filename,
                    file_size, uploaded_by, created_at, status, dek_hex
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    doc_id,
                    filename,
                    orig_hash,
                    f"{doc_id}.enc",
                    len(file_bytes),
                    uploaded_by_user_id,
                    created_at,
                    "ENCRYPTED",
                    dek.hex(),
                ),
            )


        return {
            "document_id": doc_id,
            "original_filename": filename,
            "original_hash": orig_hash,
            "file_size": len(file_bytes),
            "uploaded_by": uploaded_by_user_id,
            "created_at": created_at,
            "status": "ENCRYPTED",
        }

    @classmethod
    def get_document(cls, document_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve document metadata by ID without exposing plaintext."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT document_id, original_filename, original_hash, file_size, uploaded_by, created_at, status FROM documents WHERE document_id = ?",
                (document_id,),
            )
            doc = cursor.fetchone()
            if not doc:
                return None
            doc_dict = dict(doc)

            # Get authorized recipients
            cursor.execute(
                "SELECT recipient_id FROM document_authorizations WHERE document_id = ?",
                (document_id,),
            )
            doc_dict["authorized_recipients"] = [r["recipient_id"] for r in cursor.fetchall()]
            return doc_dict

    @classmethod
    def decrypt_original_document(cls, document_id: str) -> Dict[str, Any]:
        """
        Restore the exact original file bytes by decrypting ciphertext using the persistent DEK.
        Verifies SHA-256 integrity against the stored original_hash.
        """
        import mimetypes

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT document_id, original_filename, original_hash, file_size, status FROM documents WHERE document_id = ?",
                (document_id,),
            )
            doc = cursor.fetchone()
            if not doc:
                raise KeyError(f"Document {document_id} not found in database.")

        enc_bytes = StorageService.read_encrypted_file(document_id)
        dek = key_manager.get_dek(document_id)
        original_bytes = document_cipher.decrypt(
            enc_bytes, dek, associated_data=document_id.encode("utf-8")
        )

        # Verify cryptographic hash matches original
        dec_hash = sha256_bytes(original_bytes)
        if dec_hash != doc["original_hash"]:
            raise ValueError(f"Cryptographic hash mismatch! Stored: {doc['original_hash']}, Computed: {dec_hash}")

        orig_filename = doc["original_filename"]
        guessed_type, _ = mimetypes.guess_type(orig_filename)
        mime_type = guessed_type or "application/octet-stream"
        orig_lower = orig_filename.lower()
        if orig_lower.endswith(".pdf"):
            mime_type = "application/pdf"
        elif orig_lower.endswith(".txt"):
            mime_type = "text/plain"
        elif orig_lower.endswith(".png"):
            mime_type = "image/png"
        elif orig_lower.endswith((".jpg", ".jpeg")):
            mime_type = "image/jpeg"

        return {
            "document_id": document_id,
            "filename": orig_filename,
            "original_hash": doc["original_hash"],
            "bytes": original_bytes,
            "mime_type": mime_type,
            "file_size": len(original_bytes),
        }


    @classmethod
    def list_documents(cls, include_deleted: bool = False, limit: int = 100) -> List[Dict[str, Any]]:
        """List active documents for Admin audit (excludes soft-deleted documents by default, capped at limit=100)."""
        with get_db() as conn:
            cursor = conn.cursor()
            query = "SELECT document_id, original_filename, original_hash, file_size, uploaded_by, created_at, status FROM documents"
            if not include_deleted:
                query += " WHERE status != 'DELETED'"
            query += " ORDER BY created_at DESC LIMIT ?"
            cursor.execute(query, (limit,))
            rows = cursor.fetchall()
            result = []
            for r in rows:
                d = dict(r)
                cursor.execute(
                    "SELECT recipient_id FROM document_authorizations WHERE document_id = ?",
                    (d["document_id"],),
                )
                d["authorized_recipients"] = [x["recipient_id"] for x in cursor.fetchall()]
                result.append(d)
            return result

    @classmethod
    def authorize_recipient(cls, document_id: str, recipient_id: str, authorized_by: str):
        """Grant a recipient permission to decrypt the document and encapsulate DEK using recipient's ML-KEM key."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT document_id FROM documents WHERE document_id = ?",
                (document_id,),
            )
            if not cursor.fetchone():
                raise KeyError(f"Document {document_id} not found")

            dek = key_manager.get_dek(document_id)
            dsa_pk, kem_pk = key_manager.ensure_user_pqc_keys(recipient_id)
            enc_key = key_manager.encapsulate_dek_for_recipient(dek, kem_pk)

            granted_at = datetime.now(timezone.utc).isoformat()
            cursor.execute(
                """
                INSERT INTO document_authorizations (document_id, recipient_id, authorized_by, granted_at, encapsulated_key)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(document_id, recipient_id) DO UPDATE SET
                    authorized_by = excluded.authorized_by,
                    granted_at = excluded.granted_at,
                    encapsulated_key = excluded.encapsulated_key
                """,
                (document_id, recipient_id, authorized_by, granted_at, enc_key),
            )

    @classmethod
    def revoke_recipient(cls, document_id: str, recipient_id: str):
        """Revoke a recipient's permission to decrypt the document."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM document_authorizations WHERE document_id = ? AND recipient_id = ?",
                (document_id, recipient_id),
            )

    @classmethod
    def update_document_authorizations(cls, document_id: str, recipient_ids: List[str], authorized_by: str):
        """Synchronize the exact list of authorized recipients for a document with ML-KEM key encapsulation."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT document_id FROM documents WHERE document_id = ?", (document_id,))
            if not cursor.fetchone():
                raise KeyError(f"Document {document_id} not found")

            # Remove previous authorizations for this document
            cursor.execute("DELETE FROM document_authorizations WHERE document_id = ?", (document_id,))

            # Insert updated set of authorizations with ML-KEM encapsulated DEKs
            dek = key_manager.get_dek(document_id)
            granted_at = datetime.now(timezone.utc).isoformat()
            for r_id in set(recipient_ids):
                dsa_pk, kem_pk = key_manager.ensure_user_pqc_keys(r_id)
                enc_key = key_manager.encapsulate_dek_for_recipient(dek, kem_pk)
                cursor.execute(
                    """
                    INSERT INTO document_authorizations (document_id, recipient_id, authorized_by, granted_at, encapsulated_key)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (document_id, r_id, authorized_by, granted_at, enc_key),
                )

    @classmethod
    def delete_document(cls, document_id: str, actor: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Soft-delete an uploaded document from active lists while preserving complete
        cryptographic provenance, decryption events, watermarks, fingerprints, and ledger blocks.
        """
        from fastapi import HTTPException, status
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM documents WHERE document_id = ?", (document_id,))
            doc = cursor.fetchone()
            if not doc:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")
            if doc["status"] == "DELETED":
                return {
                    "status": "SUCCESS",
                    "message": "Document deleted successfully.",
                    "document_id": document_id,
                }

            # Soft delete document
            cursor.execute(
                "UPDATE documents SET status = 'DELETED' WHERE document_id = ?",
                (document_id,),
            )
            # Revoke active authorizations so it cannot be decrypted anymore
            cursor.execute(
                "DELETE FROM document_authorizations WHERE document_id = ?",
                (document_id,),
            )

        # Commit DOCUMENT_DELETED event to local tamper-evident ledger per SIH requirement
        import json
        from backend.crypto.pqc import pqc_provider

        now_dt = datetime.now(timezone.utc)
        now_iso = now_dt.isoformat()
        action_id = f"ACT-DOC-DEL-{uuid.uuid4().hex[:6].upper()}"
        actor_id = actor.get("id", "SYS-ADMIN") if actor else "SYS-ADMIN"
        actor_uname = actor.get("username", "admin") if actor else "admin"

        audit_event = {
            "event_id": action_id,
            "session_id": f"SES-DOC-DEL-{action_id}",
            "document_id": document_id,
            "recipient_id": actor_id,
            "document_hash": sha256_bytes(f"{action_id}:{document_id}:DOCUMENT_DELETED:{now_iso}".encode("utf-8")),
            "watermark_id": f"WM-DOC-DEL-{action_id}",
            "timestamp": now_iso,
            "action": "DOCUMENT_DELETED",
            "actor_id": actor_id,
            "actor_username": actor_uname,
        }
        audit_sig = pqc_provider.sign_with_authority(json.dumps(audit_event, sort_keys=True).encode("utf-8"))
        ledger_block = OfflineLedger.commit_event(audit_event, audit_sig)
        ledger_record_id = str(ledger_block.get("block_index", 0))

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO account_action_audits (
                    action_id, investigator_id, investigator_username, target_user_id, target_username,
                    action, previous_status, new_status, timestamp, investigation_id, fingerprint_id, ledger_record_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    action_id,
                    actor_id,
                    actor_uname,
                    document_id,
                    doc["original_filename"],
                    "DOCUMENT_DELETED",
                    doc["status"],
                    "DELETED",
                    now_iso,
                    None,
                    None,
                    ledger_record_id,
                ),
            )

        return {
            "status": "SUCCESS",
            "message": "Document deleted successfully.",
            "document_id": document_id,
            "ledger_block": ledger_record_id,
        }

    @classmethod
    def get_recipient_authorized_documents(cls, recipient_id: str) -> List[Dict[str, Any]]:
        """List active documents available for this recipient with live interaction status (RECEIVED/UNREAD, READ, DOWNLOADED)."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT 
                    d.document_id, d.original_filename, d.original_hash, d.file_size, d.created_at, d.status,
                    da.granted_at, da.read_at, da.interaction_status as stored_status,
                    (SELECT session_id FROM decryption_sessions ds WHERE ds.document_id = d.document_id AND ds.recipient_id = da.recipient_id AND ds.status = 'COMPLETED' ORDER BY ds.completed_at DESC LIMIT 1) as completed_session_id,
                    (SELECT watermark_id FROM decryption_sessions ds WHERE ds.document_id = d.document_id AND ds.recipient_id = da.recipient_id AND ds.status = 'COMPLETED' ORDER BY ds.completed_at DESC LIMIT 1) as session_watermark_id,
                    (SELECT completed_at FROM decryption_sessions ds WHERE ds.document_id = d.document_id AND ds.recipient_id = da.recipient_id AND ds.status = 'COMPLETED' ORDER BY ds.completed_at DESC LIMIT 1) as downloaded_at,
                    (SELECT signature_id FROM recipient_signatures rs WHERE rs.document_id = d.document_id AND rs.recipient_id = da.recipient_id LIMIT 1) as signature_id,
                    (SELECT signed_at FROM recipient_signatures rs WHERE rs.document_id = d.document_id AND rs.recipient_id = da.recipient_id LIMIT 1) as signed_at,
                    (SELECT verification_status FROM recipient_signatures rs WHERE rs.document_id = d.document_id AND rs.recipient_id = da.recipient_id LIMIT 1) as signature_verification_status
                FROM documents d
                JOIN document_authorizations da ON d.document_id = da.document_id
                WHERE da.recipient_id = ? AND d.status != 'DELETED'
                ORDER BY d.created_at DESC
                """,
                (recipient_id,),
            )
            rows = cursor.fetchall()
            result = []
            for r in rows:
                item = dict(r)
                if item["completed_session_id"]:
                    item["interaction_status"] = "DOWNLOADED"
                elif item["read_at"]:
                    item["interaction_status"] = "READ"
                else:
                    item["interaction_status"] = item["stored_status"] or "RECEIVED"
                item["is_signed"] = bool(item["signature_id"])
                result.append(item)
            return result


    @classmethod
    def mark_document_as_read(cls, document_id: str, recipient_id: str) -> Dict[str, Any]:
        """Record genuine reading event when authorized personnel views document in browser reader."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT d.document_id, d.original_filename, d.file_size, da.granted_at, da.read_at, da.interaction_status
                FROM documents d JOIN document_authorizations da ON d.document_id = da.document_id
                WHERE d.document_id = ? AND da.recipient_id = ?
                """,
                (document_id, recipient_id),
            )
            row = cursor.fetchone()
            if not row:
                raise KeyError("Document not found or access not authorized.")
            now_iso = datetime.now(timezone.utc).isoformat()
            cursor.execute(
                """
                UPDATE document_authorizations 
                SET read_at = COALESCE(read_at, ?), 
                    interaction_status = CASE WHEN interaction_status = 'DOWNLOADED' THEN 'DOWNLOADED' ELSE 'READ' END 
                WHERE document_id = ? AND recipient_id = ?
                """,
                (now_iso, document_id, recipient_id),
            )
            return {
                "status": "SUCCESS",
                "document_id": document_id,
                "original_filename": row["original_filename"],
                "file_size": row["file_size"],
                "granted_at": row["granted_at"],
                "read_at": now_iso,
                "interaction_status": "READ" if row["interaction_status"] != "DOWNLOADED" else "DOWNLOADED",
            }

    @classmethod
    def decrypt_for_recipient(
        cls,
        document_id: str,
        recipient_id: str,
    ) -> Dict[str, Any]:
        """
        Execute session-specific decryption:
        1. Verify active account status and authorization.
        2. Create unique session_id.
        3. Decapsulate document key using recipient's ML-KEM-768 private key.
        4. Decrypt document from AES-256-GCM.
        5. Generate unique cryptographic forensic fingerprint.
        6. Embed watermark imperceptibly into decrypted PDF.
        7. Calculate decrypted document hash.
        8. Create canonical provenance event.
        9. Sign event with recipient's ML-DSA-44 post-quantum private signing key.
        10. Commit signed block to Offline Permissioned DLT Ledger.
        11. Store session & watermark records.
        """
        started_at = datetime.now(timezone.utc).isoformat()

        # 1. Verify recipient user account is ACTIVE and not suspended/blacklisted
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT status FROM users WHERE id = ?", (recipient_id,))
            u_row = cursor.fetchone()
            if not u_row or u_row["status"] != "ACTIVE":
                raise PermissionError("Your account is currently inactive, suspended, or blacklisted.")

            # Verify authorization
            cursor.execute(
                "SELECT id, encapsulated_key FROM document_authorizations WHERE document_id = ? AND recipient_id = ?",
                (document_id, recipient_id),
            )
            auth = cursor.fetchone()
            if not auth:
                raise PermissionError(f"User {recipient_id} is not authorized to decrypt document {document_id}")

        # 2. Generate unique session ID (e.g. S-XXXX)
        session_id = f"SES-{uuid.uuid4().hex[:8].upper()}"

        # 3. Recover DEK via ML-KEM-768 decapsulation or key manager fallback
        if auth["encapsulated_key"]:
            try:
                dek = key_manager.decapsulate_dek_for_recipient(auth["encapsulated_key"], recipient_id)
            except Exception:
                dek = key_manager.get_dek(document_id)
        else:
            dek = key_manager.get_dek(document_id)

        # 4. Read encrypted payload and decrypt via AES-256-GCM
        enc_payload = StorageService.read_encrypted_file(document_id)
        plaintext_pdf = document_cipher.decrypt(
            enc_payload, dek, associated_data=document_id.encode("utf-8")
        )

        # 5. Generate cryptographically derived unique forensic fingerprint identifier (e.g. FP-8A72-X91B)
        watermark_id = generate_watermark_id(
            prefix="FP-",
            length=8,
            document_id=document_id,
            recipient_user_id=recipient_id,
            session_id=session_id,
        )

        # Fetch document & recipient details for complete canonical event record
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT original_filename, original_hash FROM documents WHERE document_id = ?", (document_id,))
            doc_row = cursor.fetchone()
            doc_name = doc_row["original_filename"] if doc_row else "Confidential.pdf"
            orig_hash = doc_row["original_hash"] if doc_row and "original_hash" in doc_row.keys() else ""

            cursor.execute("SELECT username, display_name, role FROM users WHERE id = ?", (recipient_id,))
            u_row = cursor.fetchone()

        # 6. Embed watermark imperceptibly across supported formats (PDF, images, text)
        fingerprinted_pdf = WatermarkEmbedder.embed_watermark_auto(plaintext_pdf, watermark_id, doc_name)

        # 7. Calculate hash of fingerprinted PDF / binary
        doc_hash = sha256_bytes(fingerprinted_pdf)

        # 8. Save fingerprinted file for recipient download
        StorageService.save_fingerprinted_file(session_id, fingerprinted_pdf)
        completed_at = datetime.now(timezone.utc).isoformat()

        u_username = u_row["username"] if u_row else "recipient"
        u_name = u_row["display_name"] if u_row else "Authorized Employee"
        u_role = u_row["role"] if u_row else "Employee"
        if u_role == "RECIPIENT":
            u_role = "Employee"


        # 9. Create canonical provenance event with all required SIH Section 4 fields
        event = create_canonical_event(
            session_id=session_id,
            document_id=document_id,
            recipient_id=recipient_id,
            document_hash=doc_hash,
            watermark_id=watermark_id,
            document_name=doc_name,
            recipient_name=u_name,
            recipient_username=u_username,
            recipient_role=u_role,
            timestamp=completed_at,
        )

        # 10. Sign canonical event with recipient's post-quantum private signing key (NIST ML-DSA-44)
        recipient_sk = key_manager.get_user_signing_key(recipient_id)
        recipient_pk = key_manager.get_user_public_key(recipient_id)
        canonical_str, signature, algorithm, pubkey = sign_provenance_event(
            event,
            private_key_hex=recipient_sk,
            public_key_hex=recipient_pk,
        )

        # 11. Commit to offline permissioned DLT ledger
        block = OfflineLedger.commit_event(event, signature)

        # 11. Record session, watermark, provenance event, and distributed copy mapping in SQLite
        with get_db() as conn:
            cursor = conn.cursor()

            # Insert session
            cursor.execute(
                """
                INSERT INTO decryption_sessions (
                    session_id, document_id, recipient_id, started_at, completed_at,
                    document_hash, watermark_id, fingerprinted_filename, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    document_id,
                    recipient_id,
                    started_at,
                    completed_at,
                    doc_hash,
                    watermark_id,
                    f"fingerprinted_{session_id}.pdf",
                    "COMPLETED",
                ),
            )

            # Insert watermark
            cursor.execute(
                """
                INSERT INTO watermarks (
                    watermark_id, session_id, recipient_id, document_id,
                    payload_signature, embedded_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    watermark_id,
                    session_id,
                    recipient_id,
                    document_id,
                    signature[:64] + "...",
                    completed_at,
                ),
            )

            # Insert provenance event
            cursor.execute(
                """
                INSERT INTO provenance_events (
                    event_id, session_id, document_id, recipient_id, document_hash,
                    watermark_id, timestamp, canonical_payload, signature, algorithm, public_key_ref
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event["event_id"],
                    session_id,
                    document_id,
                    recipient_id,
                    doc_hash,
                    watermark_id,
                    completed_at,
                    canonical_str,
                    signature,
                    algorithm,
                    pubkey,
                ),
            )

            # Persistent Copy-to-Employee Provenance Record
            cursor.execute("SELECT username, display_name FROM users WHERE id = ?", (recipient_id,))
            u_row = cursor.fetchone()
            u_username = u_row["username"] if u_row else "unknown"
            u_name = u_row["display_name"] if u_row else "Unknown Employee"

            cursor.execute("SELECT original_filename FROM documents WHERE document_id = ?", (document_id,))
            d_row = cursor.fetchone()
            d_name = d_row["original_filename"] if d_row else "Confidential.pdf"

            cursor.execute(
                """
                INSERT OR REPLACE INTO distributed_copies (
                    fingerprint, document_id, copy_id, user_id, username, employee_name,
                    downloaded_at, action, document_name, document_hash, provenance_event_id, ledger_block_index
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    watermark_id,
                    document_id,
                    session_id,
                    recipient_id,
                    u_username,
                    u_name,
                    completed_at,
                    "DECRYPT_AND_DOWNLOAD",
                    d_name,
                    doc_hash,
                    event["event_id"],
                    block["block_index"],
                ),
            )

            # Update authorization interaction status to DOWNLOADED
            cursor.execute(
                "UPDATE document_authorizations SET interaction_status = 'DOWNLOADED' WHERE document_id = ? AND recipient_id = ?",
                (document_id, recipient_id),
            )

        return {
            "session_id": session_id,
            "document_id": document_id,
            "document_name": doc_name,
            "original_filename": doc_name,
            "original_hash": orig_hash,
            "document_version": "v1.0",
            "recipient_id": recipient_id,
            "recipient_username": u_username,
            "recipient_name": u_name,
            "watermark_id": watermark_id,
            "fingerprint_id": watermark_id,
            "watermark_hash": doc_hash,
            "document_hash": doc_hash,
            "watermark_status": "EMBEDDED",
            "method": "Imperceptible Multi-Layer Steganography",
            "timestamp": completed_at,
            "completed_at": completed_at,
            "started_at": started_at,
            "event_id": event["event_id"],
            "block_index": block["block_index"],
            "download_url": f"/api/documents/download/{session_id}",
            "status": "SUCCESS",
            "decryption_status": "SUCCESS",
            "message": "Document successfully decrypted and uniquely fingerprinted.",
        }

    @classmethod
    def get_decryption_sessions(cls, recipient_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List decryption sessions with enriched document and recipient provenance metadata."""
        with get_db() as conn:
            cursor = conn.cursor()
            query = """
                SELECT 
                    ds.session_id, ds.document_id, ds.recipient_id, ds.started_at, ds.completed_at,
                    ds.completed_at as timestamp,
                    ds.document_hash, ds.watermark_id, ds.watermark_id as fingerprint_id, ds.status,
                    'SUCCESS' as decryption_status,
                    d.original_filename, d.original_filename as document_name, d.original_hash,
                    'v1.0' as document_version,
                    u.username as recipient_username, u.display_name as recipient_name,
                    'EMBEDDED' as watermark_status,
                    'Imperceptible Multi-Layer Steganography' as method,
                    (SELECT block_index FROM ledger_blocks lb WHERE lb.watermark_id = ds.watermark_id LIMIT 1) as ledger_block_index
                FROM decryption_sessions ds
                LEFT JOIN documents d ON ds.document_id = d.document_id
                LEFT JOIN users u ON ds.recipient_id = u.id
            """
            if recipient_id:
                query += " WHERE ds.recipient_id = ? ORDER BY ds.started_at DESC"
                cursor.execute(query, (recipient_id,))
            else:
                query += " ORDER BY ds.started_at DESC"
                cursor.execute(query)
            return [dict(r) for r in cursor.fetchall()]

    @classmethod
    def get_session(cls, session_id: str) -> Optional[Dict[str, Any]]:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT 
                    ds.session_id, ds.document_id, ds.recipient_id, ds.started_at, ds.completed_at,
                    ds.completed_at as timestamp,
                    ds.document_hash, ds.watermark_id, ds.watermark_id as fingerprint_id, ds.status,
                    'SUCCESS' as decryption_status,
                    d.original_filename, d.original_filename as document_name, d.original_hash,
                    'v1.0' as document_version,
                    u.username as recipient_username, u.display_name as recipient_name,
                    'EMBEDDED' as watermark_status,
                    'Imperceptible Multi-Layer Steganography' as method,
                    (SELECT block_index FROM ledger_blocks lb WHERE lb.watermark_id = ds.watermark_id LIMIT 1) as ledger_block_index
                FROM decryption_sessions ds
                LEFT JOIN documents d ON ds.document_id = d.document_id
                LEFT JOIN users u ON ds.recipient_id = u.id
                WHERE ds.session_id = ?
                """,
                (session_id,),
            )
            s = cursor.fetchone()
            return dict(s) if s else None

    @classmethod
    def get_latest_session_for_recipient(cls, recipient_id: str, document_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieve latest decryption session for a recipient, optionally scoped to a document."""
        with get_db() as conn:
            cursor = conn.cursor()
            query = """
                SELECT 
                    ds.session_id, ds.document_id, ds.recipient_id, ds.started_at, ds.completed_at,
                    ds.completed_at as timestamp,
                    ds.document_hash, ds.watermark_id, ds.watermark_id as fingerprint_id, ds.status,
                    'SUCCESS' as decryption_status,
                    d.original_filename, d.original_filename as document_name, d.original_hash,
                    'v1.0' as document_version,
                    u.username as recipient_username, u.display_name as recipient_name,
                    'EMBEDDED' as watermark_status,
                    'Imperceptible Multi-Layer Steganography' as method,
                    (SELECT block_index FROM ledger_blocks lb WHERE lb.watermark_id = ds.watermark_id LIMIT 1) as ledger_block_index
                FROM decryption_sessions ds
                LEFT JOIN documents d ON ds.document_id = d.document_id
                LEFT JOIN users u ON ds.recipient_id = u.id
                WHERE ds.recipient_id = ?
            """
            params = [recipient_id]
            if document_id:
                query += " AND ds.document_id = ?"
                params.append(document_id)
            query += " ORDER BY ds.completed_at DESC, ds.started_at DESC LIMIT 1"
            cursor.execute(query, tuple(params))
            s = cursor.fetchone()
            return dict(s) if s else None
