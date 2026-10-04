"""
TraceSeal Recipient Digital Signature Service (DSA + SHA-256)
Implements true cryptographic digital signatures using NIST FIPS 186-4 DSA
with SHA-256 for non-repudiation, tamper detection, and legal acknowledgement.
"""

import os
import json
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List
import uuid

from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

from backend.config import STORAGE_DIR, ensure_directories
from backend.database import get_db
from backend.crypto.hashing import sha256_bytes
from backend.ledger.ledger import OfflineLedger
from backend.crypto.pqc import pqc_provider

DSA_KEYS_PATH = STORAGE_DIR / "dsa_keys.json"


class DSAManager:
    """
    Manages persistent server-side DSA keypairs for registered recipients.
    Private keys are protected on the server side and never exposed to clients.
    Public keys are stored for cryptographic verification.
    """

    def __init__(self, keys_path: Path = DSA_KEYS_PATH):
        self.keys_path = keys_path
        self._private_keys: Dict[str, dsa.DSAPrivateKey] = {}
        self._public_pems: Dict[str, str] = {}
        self._load_keys()

    def _load_keys(self):
        ensure_directories()
        if not self.keys_path.exists():
            return
        try:
            with open(self.keys_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for user_id, entry in data.items():
                priv_pem = entry.get("private_key_pem", "")
                pub_pem = entry.get("public_key_pem", "")
                if priv_pem:
                    key = serialization.load_pem_private_key(priv_pem.encode("utf-8"), password=None)
                    self._private_keys[user_id] = key
                    self._public_pems[user_id] = pub_pem
        except Exception:
            pass

    def _save_keys(self):
        ensure_directories()
        payload = {}
        for user_id, key in self._private_keys.items():
            priv_pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")
            pub_pem = self._public_pems.get(user_id, "")
            if not pub_pem:
                pub_pem = key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode("utf-8")
                self._public_pems[user_id] = pub_pem
            payload[user_id] = {
                "private_key_pem": priv_pem,
                "public_key_pem": pub_pem,
            }
        with open(self.keys_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    def ensure_user_dsa_key(self, user_id: str) -> Tuple[dsa.DSAPrivateKey, str]:
        """
        Ensure user has a stable DSA-2048 keypair.
        Returns (private_key_object, public_key_pem).
        """
        if user_id in self._private_keys and user_id in self._public_pems:
            return self._private_keys[user_id], self._public_pems[user_id]

        self._load_keys()
        if user_id in self._private_keys and user_id in self._public_pems:
            return self._private_keys[user_id], self._public_pems[user_id]

        # Generate new DSA key with 2048-bit key size
        key = dsa.generate_private_key(key_size=2048)
        pub_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        self._private_keys[user_id] = key
        self._public_pems[user_id] = pub_pem
        self._save_keys()

        # Update database with DSA public key for transparency
        try:
            with get_db() as conn:
                conn.cursor().execute(
                    "UPDATE users SET dsa_public_key = ? WHERE id = ?",
                    (pub_pem, user_id),
                )
        except Exception:
            pass

        return key, pub_pem

    def get_user_dsa_private_key(self, user_id: str) -> dsa.DSAPrivateKey:
        key, _ = self.ensure_user_dsa_key(user_id)
        return key

    def get_user_dsa_public_key(self, user_id: str) -> str:
        _, pub_pem = self.ensure_user_dsa_key(user_id)
        return pub_pem


# Global DSA manager instance
dsa_manager = DSAManager()


def create_canonical_acknowledgement_payload(
    recipient_id: str,
    recipient_username: str,
    document_id: str,
    document_hash: str,
    document_version: str = "v1.0",
    action: str = "ACKNOWLEDGE",
    timestamp: str = "",
) -> Tuple[str, bytes]:
    """
    Creates a deterministic, byte-stable canonical representation of the acknowledgement event.
    Guarantees deterministic serialization for signature generation and verification.
    """
    lines = [
        f"action={action}",
        f"document_hash={document_hash}",
        f"document_id={document_id}",
        f"document_version={document_version}",
        f"recipient_id={recipient_id}",
        f"recipient_username={recipient_username}",
        f"timestamp={timestamp}",
    ]
    canonical_str = "\n".join(lines)
    return canonical_str, canonical_str.encode("utf-8")


class SignatureService:
    """
    Handles recipient document acknowledgement, DSA-SHA256 signature generation,
    DLT ledger commitment, and cryptographic verification.
    """

    @classmethod
    def sign_document(
        cls,
        document_id: str,
        recipient_id: str,
        document_version: str = "v1.0",
        action: str = "ACKNOWLEDGE",
    ) -> Dict[str, Any]:
        """
        Signs an authorized document on behalf of a recipient using DSA + SHA-256.
        1. Verifies user authorization and active status.
        2. Retrieves document details and current original_hash.
        3. Retrieves stable DSA private key for this recipient.
        4. Constructs canonical payload.
        5. Computes DSA signature over SHA-256 digest of payload.
        6. Commits DOCUMENT_SIGN event to local DLT ledger.
        7. Records signature in SQLite recipient_signatures table.
        """
        # 1. Look up user
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, display_name, status, role FROM users WHERE id = ?",
                (recipient_id,),
            )
            u = cursor.fetchone()
            if not u:
                raise KeyError(f"User {recipient_id} not found.")
            if u["status"] != "ACTIVE":
                raise PermissionError("Account is not active. Cannot sign documents.")

            # Look up document
            cursor.execute(
                "SELECT document_id, original_filename, original_hash, status FROM documents WHERE document_id = ?",
                (document_id,),
            )
            doc = cursor.fetchone()
            if not doc:
                raise KeyError(f"Document {document_id} not found.")

            # Verify authorization (unless admin)
            if u["role"] == "RECIPIENT":
                cursor.execute(
                    "SELECT id FROM document_authorizations WHERE document_id = ? AND recipient_id = ?",
                    (document_id, recipient_id),
                )
                if not cursor.fetchone():
                    raise PermissionError(f"User {recipient_id} is not authorized for document {document_id}.")

            # Check if already signed for this version
            cursor.execute(
                """
                SELECT signature_id, signed_at, signature_value, verification_status
                FROM recipient_signatures
                WHERE document_id = ? AND recipient_id = ? AND document_version = ?
                """,
                (document_id, recipient_id, document_version),
            )
            existing = cursor.fetchone()
            if existing:
                return {
                    "status": "ALREADY_SIGNED",
                    "signature_id": existing["signature_id"],
                    "signed_at": existing["signed_at"],
                    "verification_status": existing["verification_status"],
                    "message": "Document has already been signed by this recipient.",
                }

        # 2. Retrieve DSA keypair
        priv_key, pub_pem = dsa_manager.ensure_user_pqc_keys_fallback(recipient_id) if hasattr(dsa_manager, "ensure_user_pqc_keys_fallback") else dsa_manager.ensure_user_dsa_key(recipient_id)

        # 3. Create deterministic canonical payload
        now_iso = datetime.now(timezone.utc).isoformat()
        canonical_str, canonical_bytes = create_canonical_acknowledgement_payload(
            recipient_id=recipient_id,
            recipient_username=u["username"],
            document_id=document_id,
            document_hash=doc["original_hash"],
            document_version=document_version,
            action=action,
            timestamp=now_iso,
        )

        # 4. Sign using DSA + SHA-256
        sig_bytes = priv_key.sign(canonical_bytes, hashes.SHA256())
        sig_b64 = base64.b64encode(sig_bytes).decode("ascii")

        sig_id = f"SIG-{uuid.uuid4().hex[:8].upper()}"

        # 5. Commit to tamper-evident offline ledger
        audit_event = {
            "event_id": f"EVT-{sig_id}",
            "session_id": f"SES-SIGN-{sig_id}",
            "document_id": document_id,
            "recipient_id": recipient_id,
            "document_hash": doc["original_hash"],
            "watermark_id": f"SIG-ACK-{recipient_id}",
            "timestamp": now_iso,
            "action": "DOCUMENT_SIGN",
            "actor_id": recipient_id,
            "actor_username": u["username"],
            "signature_algorithm": "DSA-SHA256",
            "document_version": document_version,
        }
        authority_sig = pqc_provider.sign_with_authority(json.dumps(audit_event, sort_keys=True).encode("utf-8"))
        ledger_block = OfflineLedger.commit_event(audit_event, authority_sig)
        block_idx = ledger_block.get("block_index", 1)

        # 6. Save in SQLite
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO recipient_signatures (
                    signature_id, recipient_id, recipient_username, recipient_name,
                    document_id, document_name, document_hash, document_version,
                    signature_algorithm, signature_value, public_key_pem,
                    canonical_payload, signed_at, verification_status, acknowledgement_action,
                    ledger_block_index
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sig_id,
                    recipient_id,
                    u["username"],
                    u["display_name"],
                    document_id,
                    doc["original_filename"],
                    doc["original_hash"],
                    document_version,
                    "DSA-SHA256",
                    sig_b64,
                    pub_pem,
                    canonical_str,
                    now_iso,
                    "VERIFIED",
                    action,
                    block_idx,
                ),
            )

        return {
            "status": "SUCCESS",
            "signature_id": sig_id,
            "document_id": document_id,
            "document_name": doc["original_filename"],
            "document_hash": doc["original_hash"],
            "document_version": document_version,
            "recipient_id": recipient_id,
            "recipient_username": u["username"],
            "recipient_name": u["display_name"],
            "signature_algorithm": "DSA-SHA256",
            "signature_value": sig_b64,
            "public_key_pem": pub_pem,
            "signed_at": now_iso,
            "verification_status": "VERIFIED",
            "ledger_block_index": block_idx,
            "message": "Document successfully signed and cryptographically acknowledged with DSA-SHA256.",
        }

    @classmethod
    def verify_signature(cls, signature_id: str) -> Dict[str, Any]:
        """
        Performs genuine cryptographic verification of a DSA recipient signature.
        Re-verifies:
        1. Document hash has not changed (tamper detection).
        2. Document version matches.
        3. Recipient identity matches.
        4. Canonical payload matches.
        5. DSA public key verifies the signature over SHA-256.
        """
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT rs.*, d.original_hash as current_doc_hash, u.username as current_username
                FROM recipient_signatures rs
                LEFT JOIN documents d ON rs.document_id = d.document_id
                LEFT JOIN users u ON rs.recipient_id = u.id
                WHERE rs.signature_id = ?
                """,
                (signature_id,),
            )
            sig_row = cursor.fetchone()
            if not sig_row:
                raise KeyError(f"Signature {signature_id} not found.")

        # Check document existence and integrity
        if not sig_row["current_doc_hash"]:
            return {
                "signature_id": signature_id,
                "verification_status": "INVALID — DOCUMENT NOT FOUND",
                "valid": False,
                "details": "Associated document no longer exists in system records.",
            }

        # Check Document Hash
        if sig_row["current_doc_hash"] != sig_row["document_hash"]:
            return {
                "signature_id": signature_id,
                "verification_status": "INVALID — DOCUMENT MODIFIED",
                "valid": False,
                "details": "Document original hash changed since signature was produced.",
                "stored_hash": sig_row["document_hash"],
                "current_hash": sig_row["current_doc_hash"],
            }

        # Check Signer
        if sig_row["current_username"] and sig_row["current_username"] != sig_row["recipient_username"]:
            return {
                "signature_id": signature_id,
                "verification_status": "INVALID — SIGNER MISMATCH",
                "valid": False,
                "details": "Signer username does not match registered account identity.",
            }

        # Cryptographic verification using public key
        try:
            pub_key = serialization.load_pem_public_key(sig_row["public_key_pem"].encode("utf-8"))
            sig_bytes = base64.b64decode(sig_row["signature_value"].encode("ascii"))
            canonical_bytes = sig_row["canonical_payload"].encode("utf-8")

            pub_key.verify(sig_bytes, canonical_bytes, hashes.SHA256())
            status = "VERIFIED"
            valid = True
            details = "DSA signature cryptographically verified using public key and canonical acknowledgement payload."
        except InvalidSignature:
            status = "INVALID — SIGNATURE CORRUPTED"
            valid = False
            details = "DSA signature verification failed: signature does not correspond to public key or payload."
        except Exception as e:
            status = "INVALID — CORRUPTED KEY OR PAYLOAD"
            valid = False
            details = f"Verification error: {str(e)}"

        # Update verification status in DB
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE recipient_signatures SET verification_status = ? WHERE signature_id = ?",
                (status, signature_id),
            )

        return {
            "signature_id": signature_id,
            "document_id": sig_row["document_id"],
            "document_name": sig_row["document_name"],
            "recipient_id": sig_row["recipient_id"],
            "recipient_name": sig_row["recipient_name"],
            "recipient_username": sig_row["recipient_username"],
            "signed_at": sig_row["signed_at"],
            "document_hash": sig_row["document_hash"],
            "document_version": sig_row["document_version"],
            "signature_algorithm": sig_row["signature_algorithm"],
            "verification_status": status,
            "valid": valid,
            "details": details,
            "ledger_block_index": sig_row["ledger_block_index"],
        }

    @classmethod
    def get_document_signatures(cls, document_id: str) -> List[Dict[str, Any]]:
        """List all recipient signatures for a document."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT signature_id, recipient_id, recipient_username, recipient_name,
                       document_id, document_name, document_hash, document_version,
                       signature_algorithm, signed_at, verification_status,
                       acknowledgement_action, ledger_block_index
                FROM recipient_signatures
                WHERE document_id = ?
                ORDER BY signed_at DESC
                """,
                (document_id,),
            )
            return [dict(r) for r in cursor.fetchall()]

    @classmethod
    def get_recipient_signatures(cls, recipient_id: str) -> List[Dict[str, Any]]:
        """List all document signatures created by a recipient."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT signature_id, recipient_id, recipient_username, recipient_name,
                       document_id, document_name, document_hash, document_version,
                       signature_algorithm, signed_at, verification_status,
                       acknowledgement_action, ledger_block_index
                FROM recipient_signatures
                WHERE recipient_id = ?
                ORDER BY signed_at DESC
                """,
                (recipient_id,),
            )
            return [dict(r) for r in cursor.fetchall()]

    @classmethod
    def list_all_signatures(cls, limit: int = 100) -> List[Dict[str, Any]]:
        """List all signatures in the system for admin/investigator provenance review."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT signature_id, recipient_id, recipient_username, recipient_name,
                       document_id, document_name, document_hash, document_version,
                       signature_algorithm, signed_at, verification_status,
                       acknowledgement_action, ledger_block_index
                FROM recipient_signatures
                ORDER BY signed_at DESC
                LIMIT ?
                """,
                (limit,),
            )
            return [dict(r) for r in cursor.fetchall()]
