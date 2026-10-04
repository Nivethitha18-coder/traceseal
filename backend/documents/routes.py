"""
Document Management & Recipient Decryption API Endpoints
"""

from typing import List, Optional
import re
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query, Header, status, Response
from fastapi.responses import FileResponse

from pathlib import Path

from backend.schemas import (
    DocumentOut,
    DocumentAuthorizeRequest,
    DocumentUpdateAuthorizationsRequest,
    DecryptionResponse,
    DecryptionSessionOut,
    DocumentDeleteResponse,
)
from backend.auth.service import get_current_user, require_roles, get_user_from_auth_or_query
from backend.documents.service import DocumentService
from backend.services.storage import StorageService

router = APIRouter(prefix="/api", tags=["Document Management & Decryption"])


@router.post("/documents/upload", response_model=DocumentOut, status_code=status.HTTP_201_CREATED)
async def upload_document(
    file: UploadFile = File(...),
    current_user: dict = Depends(require_roles(["ADMIN"])),
):
    """
    ADMIN only: Upload confidential PDF, compute SHA-256, encrypt with AES-256-GCM,
    and register metadata in SQLite.
    """
    allowed_exts = {".pdf", ".txt", ".png", ".jpg", ".jpeg"}
    file_ext = Path(file.filename).suffix.lower()
    if file_ext not in allowed_exts and not file.filename.lower().endswith(tuple(allowed_exts)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid document format. Supported formats: PDF, TXT, PNG, JPG.",
        )


    content = await file.read()
    if len(content) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File content is empty.",
        )

    try:
        doc = DocumentService.upload_and_encrypt(
            file_bytes=content,
            filename=file.filename,
            uploaded_by_user_id=current_user["id"],
        )
        return doc
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Upload processing failed: {str(e)}",
        )


@router.get("/documents", response_model=List[DocumentOut])
def list_documents(current_user: dict = Depends(require_roles(["ADMIN"]))):
    """ADMIN only: List all registered encrypted documents."""
    return DocumentService.list_documents()


@router.get("/documents/{document_id}", response_model=DocumentOut)
def get_document(
    document_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Retrieve document metadata by document_id (plaintext file is never exposed)."""
    doc = DocumentService.get_document(document_id)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")
    # Non-admins can only view if authorized
    if current_user["role"] == "RECIPIENT":
        if current_user["id"] not in doc.get("authorized_recipients", []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to view this document metadata.",
            )
    return doc


@router.delete("/documents/{document_id}", response_model=DocumentDeleteResponse, status_code=status.HTTP_200_OK)
@router.post("/documents/{document_id}/delete", response_model=DocumentDeleteResponse, status_code=status.HTTP_200_OK, include_in_schema=False)
def delete_document_endpoint(
    document_id: str,
    current_user: dict = Depends(require_roles(["ADMIN"])),
):
    """
    ADMIN only: Delete an uploaded document.
    Soft-deletes the document from active document lists while preserving all immutable
    ledger records, decryption sessions, watermarks, fingerprints, and forensic audit history.
    """
    res = DocumentService.delete_document(document_id=document_id, actor=current_user)
    return res


@router.post("/documents/{document_id}/authorize", status_code=status.HTTP_200_OK)
def authorize_recipient(
    document_id: str,
    req: DocumentAuthorizeRequest,
    current_user: dict = Depends(require_roles(["ADMIN"])),
):
    """ADMIN only: Authorize a recipient member to decrypt this document."""
    try:
        DocumentService.authorize_recipient(
            document_id=document_id,
            recipient_id=req.recipient_id,
            authorized_by=current_user["id"],
        )
        return {"status": "SUCCESS", "message": f"Recipient {req.recipient_id} authorized."}
    except KeyError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/documents/{document_id}/revoke", status_code=status.HTTP_200_OK)
def revoke_recipient_endpoint(
    document_id: str,
    req: DocumentAuthorizeRequest,
    current_user: dict = Depends(require_roles(["ADMIN"])),
):
    """ADMIN only: Revoke a recipient member's access to this document."""
    try:
        DocumentService.revoke_recipient(document_id=document_id, recipient_id=req.recipient_id)
        return {"status": "SUCCESS", "message": f"Recipient {req.recipient_id} access revoked."}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.put("/documents/{document_id}/authorizations", status_code=status.HTTP_200_OK)
def update_authorizations_endpoint(
    document_id: str,
    req: DocumentUpdateAuthorizationsRequest,
    current_user: dict = Depends(require_roles(["ADMIN"])),
):
    """ADMIN only: Synchronize authorized members for a document (bulk grant/revoke)."""
    try:
        DocumentService.update_document_authorizations(
            document_id=document_id,
            recipient_ids=req.recipient_ids,
            authorized_by=current_user["id"],
        )
        return {"status": "SUCCESS", "message": "Document authorizations updated successfully."}
    except KeyError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.get("/documents/{document_id}/download-encrypted")
def download_encrypted_document(
    document_id: str,
    current_user: dict = Depends(get_user_from_auth_or_query),
):
    """
    Download the encrypted document (AES-256-GCM ciphertext).
    Accepts Bearer token in Authorization header or ?token= query parameter.
    Streams valid binary response with Content-Type: application/pdf and attachment filename.
    """
    if current_user["role"] not in ["ADMIN", "INVESTIGATOR"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied. Requires Administrator privileges.")

    doc = DocumentService.get_document(document_id)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    enc_path = StorageService.get_encrypted_path(document_id)
    if not enc_path or not enc_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Encrypted file not found on disk")

    clean_orig = doc["original_filename"]
    stem = clean_orig[:-4] if clean_orig.lower().endswith(".pdf") else clean_orig
    download_filename = f"encrypted_{stem}.pdf"

    return FileResponse(
        path=str(enc_path),
        filename=download_filename,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{download_filename}"',
            "Content-Type": "application/pdf",
            "Access-Control-Expose-Headers": "Content-Disposition",
        },
    )


@router.get("/documents/{document_id}/download")
@router.get("/documents/{document_id}/download-decrypted", include_in_schema=False)
def download_decrypted_document(
    document_id: str,
    current_user: dict = Depends(get_user_from_auth_or_query),
):
    """
    Download and restore the exact original decrypted file bytes.
    1. Authenticates requester (Bearer token or ?token=).
    2. Verifies access authorization (ADMIN/INVESTIGATOR or authorized RECIPIENT).
    3. Reads AES-256-GCM encrypted ciphertext from storage.
    4. Retrieves persistent DEK from key vault / database.
    5. Decrypts ciphertext and verifies SHA-256 integrity against stored hash.
    6. Streams the exact original file bytes with appropriate MIME type.
    """
    doc = DocumentService.get_document(document_id)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    if current_user["role"] == "RECIPIENT":
        if current_user["id"] not in doc.get("authorized_recipients", []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to download this document.",
            )
        try:
            res = DocumentService.decrypt_for_recipient(
                document_id=document_id,
                recipient_id=current_user["id"],
            )
        except PermissionError as pe:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Decryption processing failed: {str(e)}",
            )

        session_id = res["session_id"]
        filepath = StorageService.get_fingerprinted_path(session_id)
        if not filepath or not filepath.exists():
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Decrypted document was not generated.")

        clean_orig = re.sub(r'[^\w\s\.-]', '_', doc["original_filename"]).strip()
        stem = clean_orig[:-4] if clean_orig.lower().endswith(".pdf") else clean_orig
        download_filename = f"{stem}_decrypted_{session_id}.pdf"
        file_bytes = filepath.read_bytes()

        return Response(
            content=file_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{download_filename}"',
                "Content-Type": "application/pdf",
                "X-Session-ID": session_id,
                "X-Watermark-ID": res["watermark_id"],
                "X-Fingerprint-ID": res["watermark_id"],
                "X-Fingerprint-Hash": res.get("document_hash", ""),
                "X-Event-ID": res["event_id"],
                "X-Block-Index": str(res.get("block_index", 1)),
                "X-Timestamp": res.get("completed_at") or res.get("timestamp") or "",
                "X-Recipient-ID": current_user["id"],
                "X-Recipient-Username": res.get("recipient_username") or current_user.get("username", ""),
                "X-Recipient-Name": res.get("recipient_name") or current_user.get("display_name", ""),
                "X-Document-ID": document_id,
                "X-Document-Name": clean_orig,
                "X-Document-Hash": doc.get("original_hash", ""),
                "X-Original-Hash": doc.get("original_hash", ""),
                "X-Document-Version": "v1.0",
                "X-Decryption-Status": "SUCCESS",
                "X-Watermark-Status": "EMBEDDED",
                "X-Method": "Imperceptible Multi-Layer Steganography",
                "Access-Control-Expose-Headers": (
                    "Content-Disposition, Content-Type, X-Session-ID, X-Watermark-ID, X-Fingerprint-ID, "
                    "X-Fingerprint-Hash, X-Event-ID, X-Block-Index, X-Timestamp, X-Recipient-ID, "
                    "X-Recipient-Username, X-Recipient-Name, X-Document-ID, X-Document-Name, "
                    "X-Document-Hash, X-Original-Hash, X-Document-Version, X-Decryption-Status, X-Watermark-Status, X-Method"
                ),
            },
        )

    try:
        result = DocumentService.decrypt_original_document(document_id)
    except KeyError as ke:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ke))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Decryption processing failed: {str(e)}",
        )

    safe_filename = re.sub(r'[^\w\s\.-]', '_', result["filename"]).strip() or f"document_{document_id}"
    return Response(
        content=result["bytes"],
        media_type=result["mime_type"],
        headers={
            "Content-Disposition": f'attachment; filename="{safe_filename}"',
            "Content-Type": result["mime_type"],
            "X-Original-Hash": result["original_hash"],
            "X-Document-ID": document_id,
            "X-Document-Name": safe_filename,
            "X-Document-Version": "v1.0",
            "X-Decryption-Status": "SUCCESS",
            "Access-Control-Expose-Headers": "Content-Disposition, Content-Type, X-Original-Hash, X-Document-ID, X-Document-Name, X-Document-Version, X-Decryption-Status",
        },
    )



@router.get("/recipient/documents")
def get_recipient_documents(current_user: dict = Depends(require_roles(["RECIPIENT"]))):
    """RECIPIENT / MEMBER only: List all documents authorized for decryption by the current member."""
    return DocumentService.get_recipient_authorized_documents(current_user["id"])


@router.post("/recipient/documents/{document_id}/read")
@router.post("/documents/{document_id}/read", include_in_schema=False)
def read_document_endpoint(
    document_id: str,
    current_user: dict = Depends(require_roles(["RECIPIENT"])),
):
    """Authorized Personnel: Open and read confidential document in secure viewer, updating interaction status to READ."""
    try:
        return DocumentService.mark_document_as_read(document_id, current_user["id"])
    except KeyError as ke:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ke))


@router.post("/documents/{document_id}/decrypt", response_model=DecryptionResponse)
def decrypt_document(
    document_id: str,
    current_user: dict = Depends(require_roles(["RECIPIENT"])),
):
    """
    RECIPIENT: Decrypt document.
    Creates a unique session ID, generates unique forensic watermark, embeds fingerprint,
    signs provenance event with ML-DSA, commits to local tamper-evident ledger,
    and returns fingerprinted PDF download link.
    """
    try:
        res = DocumentService.decrypt_for_recipient(
            document_id=document_id,
            recipient_id=current_user["id"],
        )
        return res
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Decryption failed: {str(e)}",
        )




@router.post("/documents/{document_id}/decrypt-and-download")
def decrypt_and_download_document(
    document_id: str,
    current_user: dict = Depends(require_roles(["RECIPIENT", "ADMIN"])),
):
    """
    Direct Decrypt & Download Pipeline:
    1. Authenticate user and verify ACTIVE account status.
    2. Verify user authorization for document_id.
    3. Decrypt document from AES-256-GCM.
    4. Generate unique forensic watermark/fingerprint for this recipient and session.
    5. Embed watermark imperceptibly into decrypted PDF.
    6. Sign canonical provenance event with NIST ML-DSA-44.
    7. Commit signed block to local offline ledger.
    8. Store audit/session record in database.
    9. Stream real decrypted PDF directly to client as application/pdf.
    """
    doc = DocumentService.get_document(document_id)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found.")

    try:
        res = DocumentService.decrypt_for_recipient(
            document_id=document_id,
            recipient_id=current_user["id"],
        )
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Decryption processing failed: {str(e)}",
        )

    session_id = res["session_id"]
    filepath = StorageService.get_fingerprinted_path(session_id)
    if not filepath or not filepath.exists():
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Decrypted PDF was not generated.")

    clean_orig = re.sub(r'[^\w\s\.-]', '_', doc["original_filename"]).strip()
    stem = clean_orig[:-4] if clean_orig.lower().endswith(".pdf") else clean_orig
    download_filename = f"{stem}_decrypted_{session_id}.pdf"

    return FileResponse(
        path=str(filepath),
        filename=download_filename,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{download_filename}"',
            "X-Session-ID": session_id,
            "X-Watermark-ID": res["watermark_id"],
            "X-Fingerprint-ID": res["watermark_id"],
            "X-Fingerprint-Hash": res.get("document_hash", ""),
            "X-Event-ID": res["event_id"],
            "X-Block-Index": str(res.get("block_index", 1)),
            "X-Timestamp": res.get("completed_at") or res.get("timestamp") or "",
            "X-Recipient-ID": current_user["id"],
            "X-Recipient-Username": res.get("recipient_username") or current_user.get("username", ""),
            "X-Recipient-Name": res.get("recipient_name") or current_user.get("display_name", ""),
            "X-Document-ID": document_id,
            "X-Document-Name": clean_orig,
            "X-Document-Hash": doc.get("original_hash", ""),
            "X-Original-Hash": doc.get("original_hash", ""),
            "X-Document-Version": "v1.0",
            "X-Decryption-Status": "SUCCESS",
            "X-Watermark-Status": "EMBEDDED",
            "X-Method": "Imperceptible Multi-Layer Steganography",
            "Access-Control-Expose-Headers": (
                "Content-Disposition, X-Session-ID, X-Watermark-ID, X-Fingerprint-ID, "
                "X-Fingerprint-Hash, X-Event-ID, X-Block-Index, X-Timestamp, X-Recipient-ID, "
                "X-Recipient-Username, X-Recipient-Name, X-Document-ID, X-Document-Name, "
                "X-Document-Hash, X-Original-Hash, X-Document-Version, X-Decryption-Status, X-Watermark-Status, X-Method"
            ),
        },
    )


@router.get("/decryption/sessions", response_model=List[DecryptionSessionOut])
def list_sessions(current_user: dict = Depends(get_current_user)):
    """
    List decryption sessions.
    ADMIN & INVESTIGATOR can view all sessions; RECIPIENT can only view their own.
    """
    if current_user["role"] == "RECIPIENT":
        return DocumentService.get_decryption_sessions(recipient_id=current_user["id"])
    return DocumentService.get_decryption_sessions()


@router.get("/decryption/sessions/{session_id}", response_model=DecryptionSessionOut)
def get_session(session_id: str, current_user: dict = Depends(get_current_user)):
    """Retrieve details for a specific decryption session."""
    session = DocumentService.get_session(session_id)
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    if current_user["role"] == "RECIPIENT" and session["recipient_id"] != current_user["id"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")
    return session


@router.get("/recipient/decryption/latest", response_model=Optional[DecryptionSessionOut])
def get_latest_recipient_decryption(
    document_id: Optional[str] = Query(None),
    current_user: dict = Depends(require_roles(["RECIPIENT", "ADMIN", "INVESTIGATOR"])),
):
    """Retrieve the recipient's most recent decryption session with complete provenance metadata."""
    return DocumentService.get_latest_session_for_recipient(current_user["id"], document_id)


@router.get("/documents/download/{session_id}")
def download_fingerprinted_document(
    session_id: str,
    current_user: dict = Depends(get_user_from_auth_or_query),
):
    """
    Download the unique fingerprinted PDF generated during the decryption session.
    Accepts Bearer token in Authorization header OR as a ?token= query parameter.
    """
    session = DocumentService.get_session(session_id)
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    if current_user["role"] == "RECIPIENT" and session["recipient_id"] != current_user["id"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")

    filepath = StorageService.get_fingerprinted_path(session_id)
    if not filepath or not filepath.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found on disk")

    download_filename = f"confidential_doc_{session_id}.pdf"
    return FileResponse(
        path=str(filepath),
        filename=download_filename,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{download_filename}"',
            "X-Session-ID": session_id,
            "X-Watermark-ID": session.get("watermark_id", ""),
            "Access-Control-Expose-Headers": "Content-Disposition, X-Session-ID, X-Watermark-ID",
        },
    )


# --- Recipient Digital Signatures (DSA + SHA-256) Endpoints ---

@router.post("/documents/{document_id}/sign")
def sign_document_endpoint(
    document_id: str,
    req: Optional[dict] = None,
    current_user: dict = Depends(require_roles(["RECIPIENT", "ADMIN"])),
):
    """
    Sign and acknowledge document using NIST FIPS 186-4 DSA + SHA-256.
    Generates genuine recipient digital signature over canonical payload.
    """
    from backend.crypto.dsa_signature import SignatureService
    version = (req or {}).get("version", "v1.0")
    action = (req or {}).get("action", "ACKNOWLEDGE")

    try:
        res = SignatureService.sign_document(
            document_id=document_id,
            recipient_id=current_user["id"],
            document_version=version,
            action=action,
        )
        return res
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except KeyError as ke:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ke))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Digital signature generation failed: {str(e)}")


@router.get("/documents/{document_id}/signatures")
def get_document_signatures_endpoint(
    document_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Get all DSA recipient signatures for a document."""
    from backend.crypto.dsa_signature import SignatureService
    return SignatureService.get_document_signatures(document_id)


@router.get("/signatures")
def list_all_signatures_endpoint(
    limit: int = 100,
    current_user: dict = Depends(require_roles(["ADMIN", "INVESTIGATOR"])),
):
    """Admin / Investigator: List all recipient digital signatures."""
    from backend.crypto.dsa_signature import SignatureService
    return SignatureService.list_all_signatures(limit=limit)


@router.get("/recipient/signatures")
def list_recipient_signatures_endpoint(
    current_user: dict = Depends(require_roles(["RECIPIENT"])),
):
    """Recipient: List own digital signatures and acknowledgement receipts."""
    from backend.crypto.dsa_signature import SignatureService
    return SignatureService.get_recipient_signatures(current_user["id"])


@router.post("/signatures/{signature_id}/verify")
def verify_signature_endpoint(
    signature_id: str,
    current_user: dict = Depends(get_current_user),
):
    """
    Perform genuine cryptographic verification of DSA digital signature.
    Validates document hash, document version, signer identity, and DSA public key signature.
    """
    from backend.crypto.dsa_signature import SignatureService
    try:
        return SignatureService.verify_signature(signature_id)
    except KeyError as ke:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ke))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Verification failed: {str(e)}")

