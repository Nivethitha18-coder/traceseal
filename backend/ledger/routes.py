"""
Offline Tamper-Evident Ledger API Endpoints
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from backend.schemas import LedgerBlockOut, LedgerVerifyResponse
from backend.auth.service import get_current_user, get_optional_current_user, require_roles
from backend.database import get_db
from backend.ledger.ledger import OfflineLedger
from backend.ledger.verification import verify_ledger

router = APIRouter(prefix="/api/ledger", tags=["Offline Tamper-Evident Ledger"])


class TamperRequest(BaseModel):
    block_index: int = 1


@router.get("", response_model=List[LedgerBlockOut])
@router.get("/blocks", response_model=List[LedgerBlockOut], include_in_schema=False)
def get_all_blocks(current_user: Optional[dict] = Depends(get_optional_current_user)):
    """Retrieve all blocks in the immutable hash-chained ledger."""
    return OfflineLedger.get_blocks()


@router.get("/verify", response_model=LedgerVerifyResponse)
def verify_ledger_endpoint(current_user: Optional[dict] = Depends(get_optional_current_user)):
    """
    Recalculate entire local ledger hash chain from Genesis to latest block.
    Returns status:
    - LEDGER INTEGRITY VERIFIED
    - LEDGER TAMPERING DETECTED
    - LEDGER VERIFICATION UNAVAILABLE
    - NO LEDGER RECORDS AVAILABLE
    """
    try:
        return verify_ledger()
    except Exception as e:
        from datetime import datetime, timezone
        return {
            "valid": False,
            "status": "LEDGER VERIFICATION UNAVAILABLE",
            "total_blocks": 0,
            "tampered_block_index": None,
            "affected_entry_id": None,
            "event_id": None,
            "event_action": None,
            "expected_hash": None,
            "stored_hash": None,
            "verification_timestamp": datetime.now(timezone.utc).isoformat(),
            "details": "Unable to access the local ledger.",
            "reason": f"Unable to access the local ledger: {str(e)}",
        }


@router.get("/{block_index}", response_model=LedgerBlockOut)
def get_block(block_index: int, current_user: Optional[dict] = Depends(get_optional_current_user)):
    """Retrieve details for a specific block index."""
    block = OfflineLedger.get_block_by_index(block_index)
    if not block:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Block not found")
    return block


@router.post("/commit/{event_id}", response_model=LedgerBlockOut)
def commit_event_endpoint(
    event_id: str,
    current_user: dict = Depends(require_roles(["ADMIN"])),
):
    """ADMIN: Manually commit an uncommitted provenance event to the ledger."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM provenance_events WHERE event_id = ?", (event_id,))
        evt = cursor.fetchone()
        if not evt:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provenance event not found")
        event_dict = {
            "event_id": evt["event_id"],
            "session_id": evt["session_id"],
            "document_id": evt["document_id"],
            "recipient_id": evt["recipient_id"],
            "document_hash": evt["document_hash"],
            "watermark_id": evt["watermark_id"],
            "timestamp": evt["timestamp"],
        }
        sig = evt["signature"]

    block = OfflineLedger.commit_event(event_dict, sig)
    return block


@router.post("/simulate-tampering")
def simulate_tampering_endpoint(
    req: TamperRequest,
    current_user: Optional[dict] = Depends(get_optional_current_user),
):
    """
    CONTROLLED DEMO FEATURE: Tamper with a target block in the ledger.
    Allows live presentation of the ledger detecting 'LEDGER TAMPERING DETECTED'.
    """
    res = OfflineLedger.simulate_tampering(req.block_index)
    return res


@router.post("/restore")
def restore_ledger_endpoint(
    current_user: Optional[dict] = Depends(get_optional_current_user),
):
    """Restore pristine cryptographic state after a demo tampering simulation."""
    res = OfflineLedger.restore_ledger()
    return res
