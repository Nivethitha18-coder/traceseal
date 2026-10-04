"""
Pydantic Schemas for TraceSeal API
"""

from typing import List, Optional, Any
from pydantic import BaseModel, Field


# --- Auth Schemas ---
class UserCreate(BaseModel):
    username: str
    password: str
    display_name: str
    role: str = Field(..., pattern="^(ADMIN|RECIPIENT|INVESTIGATOR)$")


class UserLogin(BaseModel):
    username: str
    password: str
    required_role: Optional[str] = None
    user_id: Optional[str] = None


class UserOut(BaseModel):
    id: str
    username: str
    display_name: str
    role: str
    created_at: str
    active: bool
    status: str = "ACTIVE"
    public_key: Optional[str] = None


class UserDirectoryOut(BaseModel):
    id: str
    username: str
    display_name: str
    role: str
    status: str = "ACTIVE"


class UserStatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(ACTIVE|SUSPENDED|BLOCKED|BLACKLISTED|DEACTIVATED|REMOVED)$")
    investigation_id: Optional[str] = None
    fingerprint_id: Optional[str] = None


class AccountActionAuditOut(BaseModel):
    id: int
    action_id: Optional[str] = None
    investigator_id: str
    investigator_username: str
    target_user_id: str
    target_username: str
    action: str
    previous_status: str
    new_status: str
    timestamp: str
    investigation_id: Optional[str] = None
    fingerprint_id: Optional[str] = None
    ledger_record_id: Optional[str] = None


class EmployeeCreateRequest(BaseModel):
    name: str
    username: str
    password: str
    confirm_password: Optional[str] = None


class AccessAuditOut(BaseModel):
    session_id: str
    document_id: str
    document_name: str
    user_id: str
    user_name: str
    username: str
    user_status: str
    timestamp: str
    action: str
    watermark_id: Optional[str] = None
    provenance_id: Optional[str] = None
    status: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


# --- Document Schemas ---
class DocumentOut(BaseModel):
    document_id: str
    original_filename: str
    original_hash: str
    file_size: int
    uploaded_by: str
    created_at: str
    status: str
    authorized_recipients: Optional[List[str]] = None


class DocumentAuthorizeRequest(BaseModel):
    recipient_id: str


class DocumentUpdateAuthorizationsRequest(BaseModel):
    recipient_ids: List[str]


# --- Decryption & Session Schemas ---
class DecryptionResponse(BaseModel):
    session_id: str
    document_id: str
    recipient_id: str
    watermark_id: str
    document_hash: str
    event_id: str
    block_index: int
    download_url: str
    status: str
    message: str
    timestamp: Optional[str] = None
    completed_at: Optional[str] = None
    started_at: Optional[str] = None
    recipient_name: Optional[str] = None
    recipient_username: Optional[str] = None
    document_name: Optional[str] = None
    original_filename: Optional[str] = None
    original_hash: Optional[str] = None
    document_version: Optional[str] = "v1.0"
    fingerprint_id: Optional[str] = None
    watermark_status: Optional[str] = "EMBEDDED"
    method: Optional[str] = "Imperceptible Multi-Layer Steganography"
    decryption_status: Optional[str] = "SUCCESS"


class DecryptionSessionOut(BaseModel):
    session_id: str
    document_id: str
    recipient_id: str
    started_at: str
    completed_at: Optional[str] = None
    timestamp: Optional[str] = None
    document_hash: Optional[str] = None
    watermark_id: Optional[str] = None
    fingerprint_id: Optional[str] = None
    status: str
    decryption_status: Optional[str] = "SUCCESS"
    original_filename: Optional[str] = None
    document_name: Optional[str] = None
    original_hash: Optional[str] = None
    document_version: Optional[str] = "v1.0"
    recipient_name: Optional[str] = None
    recipient_username: Optional[str] = None
    watermark_status: Optional[str] = "EMBEDDED"
    method: Optional[str] = "Imperceptible Multi-Layer Steganography"
    ledger_block_index: Optional[int] = None


# --- Watermark Schemas ---
class WatermarkCreateRequest(BaseModel):
    session_id: str
    document_id: str
    recipient_id: str


class WatermarkCreateResponse(BaseModel):
    watermark_id: str
    session_id: str
    recipient_id: str
    document_id: str
    embedded_at: str


class WatermarkExtractResponse(BaseModel):
    extracted: bool
    watermark_id: Optional[str] = None
    extraction_layer: Optional[str] = None
    confidence: float
    message: str


# --- Provenance Schemas ---
class ProvenanceEventCanonical(BaseModel):
    event_id: str
    session_id: str
    document_id: str
    recipient_id: str
    document_hash: str
    watermark_id: str
    timestamp: str


class ProvenanceEventOut(BaseModel):
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


class ProvenanceSignRequest(BaseModel):
    session_id: str
    document_id: str
    recipient_id: str
    document_hash: str
    watermark_id: str


class ProvenanceVerifyRequest(BaseModel):
    event_id: str


class ProvenanceVerifyResponse(BaseModel):
    event_id: str
    signature_valid: bool
    algorithm: str
    public_key_ref: str
    signed_payload_hash: str


# --- Ledger Schemas ---
class LedgerBlockOut(BaseModel):
    block_index: int
    timestamp: str
    previous_block_hash: str
    event_hash: str
    event_id: str
    watermark_id: str
    signature: str
    current_block_hash: str
    merkle_root: Optional[str] = None
    transactions: Optional[str] = None
    validator_id: Optional[str] = None
    validator_signatures: Optional[str] = None


class LedgerVerifyResponse(BaseModel):
    valid: bool
    status: str
    total_blocks: int
    tampered_block_index: Optional[int] = None
    affected_entry_id: Optional[str] = None
    event_id: Optional[str] = None
    event_action: Optional[str] = None
    expected_hash: Optional[str] = None
    stored_hash: Optional[str] = None
    verification_timestamp: str
    details: str
    reason: Optional[str] = None
    validators_verified: Optional[List[str]] = None
    merkle_roots_verified: Optional[bool] = None
    replicas_consistent: Optional[bool] = None
    chain_status: Optional[str] = None


# --- Forensic Investigation Schemas ---
class InvestigationResponse(BaseModel):
    case_id: Optional[str] = None
    filename: str
    file_hash: str
    extracted: bool
    watermark_id: Optional[str] = None
    copy_fingerprint: Optional[str] = None
    matched_event_id: Optional[str] = None
    matched_session_id: Optional[str] = None
    matched_recipient_id: Optional[str] = None
    matched_recipient_name: Optional[str] = None
    recipient_username: Optional[str] = None
    recipient_employee_name: Optional[str] = None
    recipient_role: Optional[str] = "Employee"
    matched_document_id: Optional[str] = None
    original_filename: Optional[str] = None
    original_hash: Optional[str] = None
    document_version: Optional[str] = "v1.0"
    decryption_timestamp: Optional[str] = None
    download_timestamp: Optional[str] = None
    action_event: Optional[str] = "DECRYPT_AND_DOWNLOAD"
    watermark_match: bool
    watermark_status: Optional[str] = "EMBEDDED"
    method: Optional[str] = "Imperceptible Multi-Layer Steganography"
    decryption_status: Optional[str] = "SUCCESS"
    signature_valid: bool
    document_hash_match: bool
    ledger_valid: bool
    attribution_status: str  # "ATTRIBUTION VERIFIED" or "ATTRIBUTION COULD NOT BE VERIFIED"
    issued_copy_status: str = "NOT IDENTIFIED"  # "MATCHED" or "NOT IDENTIFIED"
    leak_status: str = "NO LEAK DETECTED"  # "LEAK SOURCE COPY IDENTIFIED" or "NO LEAK DETECTED"
    attribution_statement: str = "No matching distributed copy found."
    ledger_block_index: Optional[int] = None
    report_download_url: Optional[str] = None
    evidence_chain: List[dict]
    extracted_watermark_id: Optional[str] = None
    session_id: Optional[str] = None
    recipient_name: Optional[str] = None
    fingerprint_id: Optional[str] = None
    related_warning_id: Optional[str] = None
    related_ledger_block: Optional[int] = None
    related_ledger_event: Optional[str] = None


# --- Security Dashboard Schemas ---
class SecurityStatusResponse(BaseModel):
    offline_mode: str
    cloud_kms: str
    public_blockchain: str
    local_ledger: str
    document_encryption: str
    sha256_integrity: str
    pqc_status: str
    pqc_signature_algorithm: str
    pqc_kem_algorithm: str
    digital_signature_status: str
    notes: List[str]


# --- Warning Notice Schemas ---
class WarningNoticeCreate(BaseModel):
    investigation_id: Optional[str] = None
    recipient_id: Optional[str] = None
    reason: Optional[str] = None
    subject: Optional[str] = None
    message: Optional[str] = None
    custom_notes: Optional[str] = None


class WarningNoticeOut(BaseModel):
    notice_id: str
    warning_id: Optional[str] = None
    investigation_id: str
    recipient_id: str
    recipient_name: str
    recipient_username: Optional[str] = None
    recipient_role: Optional[str] = "AUTHORISED_PERSONNEL"
    document_id: str
    document_name: str
    fingerprint_id: str
    created_at: str
    issued_at: Optional[str] = None
    issued_by: str
    issuer_id: Optional[str] = None
    issuer_role: Optional[str] = None
    status: str
    subject: str
    reason: Optional[str] = None
    notice_body: str
    message: Optional[str] = None
    ledger_block_index: Optional[int] = None
    ledger_event_id: Optional[str] = None
    read_at: Optional[str] = None
    reply_text: Optional[str] = None
    replied_at: Optional[str] = None
    reply_by: Optional[str] = None
    already_issued: Optional[bool] = False


class WarningNoticeStatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(SENT|READ|ACKNOWLEDGED|REPLIED|PENDING|CLOSED)$")


class WarningNoticeReply(BaseModel):
    reply_text: str


class DocumentDeleteResponse(BaseModel):
    status: str
    message: str
    document_id: str
