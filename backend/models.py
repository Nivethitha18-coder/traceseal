"""
Domain Data Models for TraceSeal
Represents core entities for users, documents, watermarks, provenance, ledger, and investigations.
"""

from dataclasses import dataclass
from typing import Optional, List


@dataclass
class User:
    id: str
    username: str
    display_name: str
    password_hash: str
    role: str  # 'ADMIN', 'RECIPIENT', 'INVESTIGATOR'
    created_at: str
    active: bool = True
    public_key: Optional[str] = None


@dataclass
class Document:
    document_id: str
    original_filename: str
    original_hash: str
    encrypted_filename: str
    file_size: int
    uploaded_by: str
    created_at: str
    status: str = "ENCRYPTED"
    authorized_recipients: Optional[List[str]] = None


@dataclass
class DecryptionSession:
    session_id: str
    document_id: str
    recipient_id: str
    started_at: str
    status: str
    completed_at: Optional[str] = None
    document_hash: Optional[str] = None
    watermark_id: Optional[str] = None
    fingerprinted_filename: Optional[str] = None


@dataclass
class Watermark:
    watermark_id: str
    session_id: str
    recipient_id: str
    document_id: str
    embedded_at: str
    payload_signature: Optional[str] = None


@dataclass
class ProvenanceEvent:
    event_id: str
    session_id: str
    document_id: str
    recipient_id: str
    document_hash: str
    watermark_id: str
    timestamp: str
    canonical_payload: str
    signature: str
    algorithm: str
    public_key_ref: str


@dataclass
class LedgerBlock:
    block_index: int
    timestamp: str
    previous_block_hash: str
    event_hash: str
    event_id: str
    watermark_id: str
    signature: str
    current_block_hash: str


@dataclass
class InvestigationCase:
    case_id: str
    filename: str
    file_hash: str
    attribution_status: str
    investigated_at: str
    extracted_watermark_id: Optional[str] = None
    matched_event_id: Optional[str] = None
    matched_recipient_id: Optional[str] = None
    matched_session_id: Optional[str] = None
    matched_document_id: Optional[str] = None
    watermark_matched: bool = False
    signature_valid: bool = False
    document_hash_match: bool = False
    ledger_valid: bool = False
    report_filename: Optional[str] = None
