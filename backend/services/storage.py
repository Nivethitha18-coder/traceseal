"""
Local Storage Service
Handles encrypted, fingerprinted, leaked, and evidence files on disk.
Fully offline-first with zero external cloud dependencies.
"""

from pathlib import Path
from typing import Optional
from backend.config import (
    ENCRYPTED_DIR,
    DECRYPTED_DIR,
    LEAKED_DIR,
    EVIDENCE_DIR,
    ensure_directories,
)


class StorageService:
    @classmethod
    def save_encrypted_file(cls, document_id: str, data: bytes) -> Path:
        ensure_directories()
        filepath = ENCRYPTED_DIR / f"{document_id}.enc"
        with open(filepath, "wb") as f:
            f.write(data)
        return filepath

    @classmethod
    def get_encrypted_path(cls, document_id: str) -> Optional[Path]:
        filepath = ENCRYPTED_DIR / f"{document_id}.enc"
        return filepath if filepath.exists() else None

    @classmethod
    def read_encrypted_file(cls, document_id: str) -> bytes:
        filepath = ENCRYPTED_DIR / f"{document_id}.enc"
        if not filepath.exists():
            raise FileNotFoundError(f"Encrypted document {document_id} not found on disk.")
        with open(filepath, "rb") as f:
            return f.read()

    @classmethod
    def save_fingerprinted_file(cls, session_id: str, data: bytes) -> Path:
        ensure_directories()
        filepath = DECRYPTED_DIR / f"fingerprinted_{session_id}.pdf"
        with open(filepath, "wb") as f:
            f.write(data)
        return filepath

    @classmethod
    def get_fingerprinted_path(cls, session_id: str) -> Optional[Path]:
        filepath = DECRYPTED_DIR / f"fingerprinted_{session_id}.pdf"
        return filepath if filepath.exists() else None

    @classmethod
    def save_leaked_file(cls, case_id: str, filename: str, data: bytes) -> Path:
        ensure_directories()
        safe_name = filename.replace(" ", "_")
        filepath = LEAKED_DIR / f"{case_id}_{safe_name}"
        with open(filepath, "wb") as f:
            f.write(data)
        return filepath

    @classmethod
    def save_evidence_report(cls, case_id: str, data: bytes) -> Path:
        ensure_directories()
        filepath = EVIDENCE_DIR / f"report_{case_id}.pdf"
        with open(filepath, "wb") as f:
            f.write(data)
        return filepath

    @classmethod
    def get_evidence_report_path(cls, case_id: str) -> Optional[Path]:
        filepath = EVIDENCE_DIR / f"report_{case_id}.pdf"
        return filepath if filepath.exists() else None
