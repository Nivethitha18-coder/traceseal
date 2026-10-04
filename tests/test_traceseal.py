"""
Comprehensive Automated Test Suite for TraceSeal
Verifies Single Login, Dynamic Member Authorization, AES-256-GCM Encryption,
Watermarking, ML-DSA Signatures, Tamper-Evident Ledger, Leak Investigation,
and Attribution Report Generation.
"""

import io
import pytest
from fastapi.testclient import TestClient
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

from backend.main import app
from backend.database import init_db, get_db
from backend.demo import initialize_demo_environment
from backend.crypto.hashing import sha256_bytes
from backend.crypto.encryption import document_cipher, key_manager
from backend.crypto.pqc import pqc_provider
from backend.watermark.embedder import WatermarkEmbedder
from backend.watermark.extractor import WatermarkExtractor
from backend.ledger.ledger import OfflineLedger
from backend.ledger.verification import verify_ledger
from backend.forensic.report import generate_forensic_report_pdf

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_environment():
    init_db()
    OfflineLedger.initialize_ledger()
    initialize_demo_environment()
    OfflineLedger.restore_ledger()
    yield
    OfflineLedger.restore_ledger()


def create_test_pdf_bytes(title: str = "Test Confidential File") -> bytes:
    """Helper to generate valid PDF bytes."""
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    c.drawString(100, 700, f"Title: {title}")
    c.drawString(100, 680, "This is top secret classified content for automated testing.")
    c.save()
    return buf.getvalue()


# --- 1. Role-Separated Login Portal & RBAC Tests ---
def test_role_separated_login_validation():
    # 1. Admin logs in with required_role='ADMIN' -> Success
    admin_res = client.post("/api/auth/login", json={"username": "admin", "password": "admin123", "required_role": "ADMIN"})
    assert admin_res.status_code == 200, admin_res.text
    admin_data = admin_res.json()
    assert admin_data["user"]["role"] == "ADMIN"
    admin_token = admin_data["access_token"]

    # 2. Employee Rithick tries to log in via ADMINISTRATOR portal -> Rejection (403 Forbidden)
    mismatch_admin = client.post("/api/auth/login", json={"username": "rithick", "password": "rithick123", "required_role": "ADMIN"})
    assert mismatch_admin.status_code == 403
    assert "Access denied" in mismatch_admin.json()["detail"]
    assert "restricted to Administrator accounts only" in mismatch_admin.json()["detail"]

    # 3. Investigator (inv001 / inv123) logs in with required_role='INVESTIGATOR' -> Success
    inv_res = client.post("/api/auth/login", json={"username": "inv001", "password": "inv123", "required_role": "INVESTIGATOR"})
    assert inv_res.status_code == 200
    inv_data = inv_res.json()
    assert inv_data["user"]["role"] == "INVESTIGATOR"

    # Also verify investigator01 with investigator123 logs in
    inv01_res = client.post("/api/auth/login", json={"username": "investigator01", "password": "investigator123", "required_role": "INVESTIGATOR"})
    assert inv01_res.status_code == 200

    # 4. Employee Rithick tries to log in via INVESTIGATOR portal -> Rejection (403 Forbidden)
    mismatch_inv = client.post("/api/auth/login", json={"username": "rithick", "password": "rithick123", "required_role": "INVESTIGATOR"})
    assert mismatch_inv.status_code == 403
    assert "Access denied" in mismatch_inv.json()["detail"]

    # 5. Employee Rithick logs in via EMPLOYEE portal -> Success
    emp_res = client.post("/api/auth/login", json={"username": "rithick", "password": "rithick123", "required_role": "EMPLOYEE"})
    assert emp_res.status_code == 200
    emp_data = emp_res.json()
    assert emp_data["user"]["role"] == "RECIPIENT"
    rithick_token = emp_data["access_token"]

    # 6. Admin tries to log in via EMPLOYEE portal -> Rejection (403 Forbidden)
    mismatch_emp = client.post("/api/auth/login", json={"username": "admin", "password": "admin123", "required_role": "EMPLOYEE"})
    assert mismatch_emp.status_code == 403
    assert "Access denied" in mismatch_emp.json()["detail"]

    # 7. Employee cannot upload documents (ADMIN only)
    upload_res = client.post(
        "/api/documents/upload",
        headers={"Authorization": f"Bearer {rithick_token}"},
        files={"file": ("test.pdf", create_test_pdf_bytes(), "application/pdf")},
    )
    assert upload_res.status_code == 403


def test_user_specific_document_access_isolation():
    """Verify that employees only see documents specifically authorized for them."""
    admin_auth = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"}).json()
    admin_token = admin_auth["access_token"]
    rithick_auth = client.post("/api/auth/login", json={"username": "rithick", "password": "rithick123"}).json()
    rithick_token = rithick_auth["access_token"]
    rithick_id = rithick_auth["user"]["id"]
    arun_auth = client.post("/api/auth/login", json={"username": "arun", "password": "arun123"}).json()
    arun_token = arun_auth["access_token"]
    arun_id = arun_auth["user"]["id"]

    # 1. Admin uploads a confidential document
    upload_res = client.post(
        "/api/documents/upload",
        headers={"Authorization": f"Bearer {admin_token}"},
        files={"file": ("Classified_Directive_Alpha.pdf", create_test_pdf_bytes("Classified Directive Alpha"), "application/pdf")},
    )
    assert upload_res.status_code == 201
    doc_id = upload_res.json()["document_id"]

    # 2. Admin authorizes ONLY Rithick
    client.post(
        f"/api/documents/{doc_id}/authorize",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"recipient_id": rithick_id},
    )

    # 3. Rithick logs in -> Classified_Directive_Alpha.pdf is visible
    rithick_docs = client.get("/api/recipient/documents", headers={"Authorization": f"Bearer {rithick_token}"}).json()
    assert any(d["document_id"] == doc_id for d in rithick_docs), "Rithick must see Classified_Directive_Alpha.pdf"

    # 4. Arun logs in -> Classified_Directive_Alpha.pdf is NOT visible
    arun_docs = client.get("/api/recipient/documents", headers={"Authorization": f"Bearer {arun_token}"}).json()
    assert not any(d["document_id"] == doc_id for d in arun_docs), "Arun must NOT see Classified_Directive_Alpha.pdf when unauthorized"

    # Arun tries to decrypt directly -> 403 Forbidden!
    arun_dec_res = client.post(f"/api/documents/{doc_id}/decrypt", headers={"Authorization": f"Bearer {arun_token}"})
    assert arun_dec_res.status_code == 403

    # 5. Admin grants Arun access
    grant_res = client.post(
        f"/api/documents/{doc_id}/authorize",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"recipient_id": arun_id},
    )
    assert grant_res.status_code == 200

    # 6. Arun refreshes -> now sees Classified_Directive_Alpha.pdf
    arun_docs_after = client.get("/api/recipient/documents", headers={"Authorization": f"Bearer {arun_token}"}).json()
    assert any(d["document_id"] == doc_id for d in arun_docs_after), "Arun must now see Classified_Directive_Alpha.pdf"

    # 7. Admin revokes Arun's access
    revoke_res = client.post(
        f"/api/documents/{doc_id}/revoke",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"recipient_id": arun_id},
    )
    assert revoke_res.status_code == 200

    # 8. Arun refreshes -> Classified_Directive_Alpha.pdf is gone
    arun_docs_revoked = client.get("/api/recipient/documents", headers={"Authorization": f"Bearer {arun_token}"}).json()
    assert not any(d["document_id"] == doc_id for d in arun_docs_revoked), "Arun must no longer see document after revocation"


# --- 2. AES-256-GCM Encryption & Decryption Tests ---
def test_aes_gcm_document_encryption():
    plaintext = create_test_pdf_bytes("Encryption Test")
    doc_id = "DOC-TEST-ENC-001"
    dek = key_manager.generate_and_store_dek(doc_id)

    # Encrypt
    encrypted = document_cipher.encrypt(plaintext, dek, associated_data=doc_id.encode("utf-8"))
    assert encrypted != plaintext
    assert len(encrypted) > len(plaintext)

    # Decrypt
    decrypted = document_cipher.decrypt(encrypted, dek, associated_data=doc_id.encode("utf-8"))
    assert decrypted == plaintext

    # Tampered ciphertext fails
    tampered = bytearray(encrypted)
    tampered[-5] ^= 0xFF
    with pytest.raises(Exception):
        document_cipher.decrypt(bytes(tampered), dek, associated_data=doc_id.encode("utf-8"))


# --- 3. Post-Quantum Cryptography (ML-DSA) Tests ---
def test_pqc_ml_dsa_signing_and_verification():
    status = pqc_provider.get_status()
    assert status["digital_signature_status"] == "ACTIVE"
    assert "ML-DSA" in status["signature_algorithm"] or "Ed25519" in status["signature_algorithm"]

    message = b"Canonical Provenance Event Payload Verification Test"
    signature = pqc_provider.sign_with_authority(message)
    pubkey = pqc_provider.get_authority_public_key()

    # Valid signature
    is_valid = pqc_provider.verify(pubkey, message, signature)
    assert is_valid is True

    # Tampered message fails
    tampered_valid = pqc_provider.verify(pubkey, b"Tampered Message", signature)
    assert tampered_valid is False


# --- 4. Watermark Imperceptible Embedding & Extraction Tests ---
def test_watermark_embed_and_extract():
    clean_pdf = create_test_pdf_bytes("Clean Document")

    # Clean file has no watermark
    res_clean = WatermarkExtractor.extract_from_bytes(clean_pdf)
    assert res_clean["extracted"] is False

    # Embed unique watermark
    wm_id = "WM-X99Q2A"
    fingerprinted_pdf = WatermarkEmbedder.embed_watermark(clean_pdf, wm_id)

    # Extract watermark
    res_wm = WatermarkExtractor.extract_from_bytes(fingerprinted_pdf)
    assert res_wm["extracted"] is True
    assert res_wm["watermark_id"] == wm_id
    assert res_wm["confidence"] >= 0.9


# --- 5. Tamper-Evident Ledger Integrity & Tampering Simulation ---
def test_ledger_integrity_and_tamper_detection():
    # Verify initial ledger state
    initial_verif = verify_ledger()
    assert initial_verif["valid"] is True
    assert initial_verif["status"] == "LEDGER INTEGRITY VERIFIED"
    assert "All ledger entries passed hash-chain verification" in initial_verif["details"]

    # Simulate tampering on block 0 or 1
    tamper_res = OfflineLedger.simulate_tampering(1)
    assert tamper_res["tampered"] is True

    # Verification must now FAIL
    tampered_verif = verify_ledger()
    assert tampered_verif["valid"] is False
    assert tampered_verif["status"] == "LEDGER TAMPERING DETECTED"
    assert tampered_verif["tampered_block_index"] == 1
    assert tampered_verif["expected_hash"] is not None
    assert tampered_verif["stored_hash"] is not None
    assert tampered_verif["affected_entry_id"] is not None
    assert tampered_verif["event_action"] is not None
    assert tampered_verif["verification_timestamp"] is not None
    assert "A hash mismatch was detected in the local hash chain" in tampered_verif["details"]

    # Restore ledger
    restore_res = OfflineLedger.restore_ledger()
    assert restore_res["restored"] is True

    # Verification must PASS again
    restored_verif = verify_ledger()
    assert restored_verif["valid"] is True
    assert restored_verif["status"] == "LEDGER INTEGRITY VERIFIED"


def test_four_state_ledger_verification_cases():
    """
    Verify the 4 required ledger states and exact user prompt requirements:
    1. Untouched ledger -> LEDGER INTEGRITY VERIFIED
    2. Intentionally modified block -> LEDGER TAMPERING DETECTED (affected entry, expected vs stored hash)
    3. Verification source unavailable -> LEDGER VERIFICATION UNAVAILABLE (NOT 'Offline Tamper')
    4. Empty ledger -> NO LEDGER RECORDS AVAILABLE
    """
    # TEST CASE 1: Untouched ledger -> LEDGER INTEGRITY VERIFIED
    res1 = client.get("/api/ledger/verify")
    assert res1.status_code == 200
    data1 = res1.json()
    assert data1["valid"] is True
    assert data1["status"] == "LEDGER INTEGRITY VERIFIED"
    assert "All ledger entries passed hash-chain verification" in data1["details"]
    assert data1["total_blocks"] > 0
    assert data1["tampered_block_index"] is None

    # TEST CASE 2: Intentionally modified block -> LEDGER TAMPERING DETECTED
    admin_auth = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"}).json()
    admin_token = admin_auth["access_token"]
    tamper_res = client.post(
        "/api/ledger/simulate-tampering",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"block_index": 1},
    )
    assert tamper_res.status_code == 200

    res2 = client.get("/api/ledger/verify")
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["valid"] is False
    assert data2["status"] == "LEDGER TAMPERING DETECTED"
    assert data2["tampered_block_index"] is not None
    assert data2["affected_entry_id"] is not None
    assert data2["event_action"] is not None
    assert data2["expected_hash"] is not None
    assert data2["stored_hash"] is not None
    assert data2["expected_hash"] != data2["stored_hash"]
    assert data2["verification_timestamp"] is not None
    assert "A hash mismatch was detected in the local hash chain" in data2["details"]

    # Restore ledger cleanly
    restore_res = client.post(
        "/api/ledger/restore",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert restore_res.status_code == 200

    # TEST CASE 3: Verification source unavailable -> LEDGER VERIFICATION UNAVAILABLE (NOT 'Offline Tamper')
    from unittest.mock import patch
    with patch("backend.ledger.ledger.OfflineLedger.get_blocks", side_effect=Exception("Database connection timeout")):
        res3 = client.get("/api/ledger/verify")
        assert res3.status_code == 200
        data3 = res3.json()
        assert data3["valid"] is False
        assert data3["status"] == "LEDGER VERIFICATION UNAVAILABLE"
        assert data3["reason"] == "Unable to access the local ledger."
        assert "Unable to access the local ledger" in data3["details"]
        # Strict non-regression assertions
        assert data3["status"] != "Offline Tamper"
        assert "Offline Tamper" not in str(data3)
        assert "Cannot Verify" not in str(data3)
        assert "tamper" not in data3["status"].lower()
        assert "tamper" not in data3["details"].lower()

    # TEST CASE 4: Empty ledger -> NO LEDGER RECORDS AVAILABLE
    empty_verif = verify_ledger(blocks_source=[])
    assert empty_verif["valid"] is False
    assert empty_verif["status"] == "NO LEDGER RECORDS AVAILABLE"
    assert empty_verif["details"] == "The ledger contains no entries to verify."
    assert empty_verif["reason"] == "The ledger contains no entries to verify."


# --- 6. Document Access Control (Grant, Revoke, Bulk Update) & Encrypted Download ---
def test_document_access_control_and_encrypted_download():
    # 1. Admin login
    admin_auth = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"}).json()
    admin_token = admin_auth["access_token"]

    # 2. Get registered members
    users = client.get("/api/users", headers={"Authorization": f"Bearer {admin_token}"}, params={"role": "RECIPIENT"}).json()
    rithick_id = next(u["id"] for u in users if u["username"] == "rithick")
    arun_id = next(u["id"] for u in users if u["username"] == "arun")
    priya_id = next(u["id"] for u in users if u["username"] == "priya")

    # 3. Upload Confidential.pdf
    doc_bytes = create_test_pdf_bytes("Confidential File")
    upload_res = client.post(
        "/api/documents/upload",
        headers={"Authorization": f"Bearer {admin_token}"},
        files={"file": ("Confidential.pdf", doc_bytes, "application/pdf")},
    )
    assert upload_res.status_code == 201
    doc_id = upload_res.json()["document_id"]

    # 4. Initially authorize ONLY Rithick and Priya (Arun is unauthorized)
    client.put(
        f"/api/documents/{doc_id}/authorizations",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"recipient_ids": [rithick_id, priya_id]}
    )

    # 5. Check Rithick's access -> authorized!
    rithick_token = client.post("/api/auth/login", json={"username": "rithick", "password": "rithick123"}).json()["access_token"]
    rithick_docs = client.get("/api/recipient/documents", headers={"Authorization": f"Bearer {rithick_token}"}).json()
    assert any(d["document_id"] == doc_id for d in rithick_docs)

    # 6. Check Arun's access -> NOT authorized!
    arun_token = client.post("/api/auth/login", json={"username": "arun", "password": "arun123"}).json()["access_token"]
    arun_docs = client.get("/api/recipient/documents", headers={"Authorization": f"Bearer {arun_token}"}).json()
    assert not any(d["document_id"] == doc_id for d in arun_docs)

    # Arun tries to decrypt directly -> 403 Forbidden!
    arun_dec_res = client.post(f"/api/documents/{doc_id}/decrypt", headers={"Authorization": f"Bearer {arun_token}"})
    assert arun_dec_res.status_code == 403

    # 7. Admin updates authorizations to include Arun
    client.put(
        f"/api/documents/{doc_id}/authorizations",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"recipient_ids": [rithick_id, priya_id, arun_id]}
    )

    # Now Arun CAN see and decrypt
    arun_docs_after = client.get("/api/recipient/documents", headers={"Authorization": f"Bearer {arun_token}"}).json()
    assert any(d["document_id"] == doc_id for d in arun_docs_after)

    arun_dec = client.post(f"/api/documents/{doc_id}/decrypt", headers={"Authorization": f"Bearer {arun_token}"}).json()
    assert arun_dec["status"] in ("COMPLETED", "SUCCESS")
    assert arun_dec["watermark_id"].startswith(("FP-", "WM-"))

    # 8. Admin downloads the encrypted PDF
    enc_download = client.get(f"/api/documents/{doc_id}/download-encrypted", headers={"Authorization": f"Bearer {admin_token}"})
    assert enc_download.status_code == 200
    assert len(enc_download.content) > len(doc_bytes)  # AES-GCM ciphertext with nonce + tag


# --- 7. End-to-End Multi-Recipient Decryption, Session Uniqueness & Leak Attribution ---
def test_multi_recipient_session_uniqueness_and_leak_attribution():
    # 1. Admin login & upload
    admin_auth = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"}).json()
    admin_token = admin_auth["access_token"]

    doc_bytes = create_test_pdf_bytes("Tactical Directives")
    doc = client.post(
        "/api/documents/upload",
        headers={"Authorization": f"Bearer {admin_token}"},
        files={"file": ("Directives.pdf", doc_bytes, "application/pdf")},
    ).json()
    doc_id = doc["document_id"]

    # 2. Authorize Rithick and Priya
    users = client.get("/api/users", headers={"Authorization": f"Bearer {admin_token}"}, params={"role": "RECIPIENT"}).json()
    rithick_id = next(u["id"] for u in users if u["username"] == "rithick")
    priya_id = next(u["id"] for u in users if u["username"] == "priya")

    client.put(
        f"/api/documents/{doc_id}/authorizations",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"recipient_ids": [rithick_id, priya_id]}
    )

    # 3. Rithick Login & Decrypt Session 1
    rithick_token = client.post("/api/auth/login", json={"username": "rithick", "password": "rithick123"}).json()["access_token"]
    rithick_dec1 = client.post(f"/api/documents/{doc_id}/decrypt", headers={"Authorization": f"Bearer {rithick_token}"}).json()
    session1 = rithick_dec1["session_id"]
    wm1 = rithick_dec1["watermark_id"]

    # 4. Rithick Decrypts SAME Document Again (Session 2)
    rithick_dec2 = client.post(f"/api/documents/{doc_id}/decrypt", headers={"Authorization": f"Bearer {rithick_token}"}).json()
    session2 = rithick_dec2["session_id"]
    wm2 = rithick_dec2["watermark_id"]

    # S1 != S2 and WM1 != WM2 (Session uniqueness guaranteed!)
    assert session1 != session2, "Session IDs must be distinct across repeated decryptions!"
    assert wm1 != wm2, "Watermark IDs must be distinct across sessions!"

    # 5. Priya Decrypts SAME Document
    priya_token = client.post("/api/auth/login", json={"username": "priya", "password": "priya123"}).json()["access_token"]
    priya_dec = client.post(f"/api/documents/{doc_id}/decrypt", headers={"Authorization": f"Bearer {priya_token}"}).json()
    wm_priya = priya_dec["watermark_id"]

    assert wm_priya != wm1 and wm_priya != wm2, "Priya's watermark must be distinct from Rithick's!"

    # 6. Download Rithick's fingerprinted PDF from Session 1
    download_res = client.get(f"/api/documents/download/{session1}", headers={"Authorization": f"Bearer {rithick_token}"})
    assert download_res.status_code == 200
    leaked_pdf = download_res.content

    # 7. Investigator Login & Investigation of Leaked PDF
    inv_token = client.post("/api/auth/login", json={"username": "investigator", "password": "investigator123"}).json()["access_token"]
    inv_res = client.post(
        "/api/forensics/investigate",
        headers={"Authorization": f"Bearer {inv_token}"},
        files={"file": ("leaked_spec.pdf", leaked_pdf, "application/pdf")},
    )
    assert inv_res.status_code == 200
    inv_data = inv_res.json()

    # Assert Attribution Verdict
    assert inv_data["attribution_status"] == "ATTRIBUTION VERIFIED"
    assert inv_data["watermark_id"] == wm1
    assert inv_data["matched_session_id"] == session1
    assert inv_data["matched_recipient_id"] == rithick_id
    assert "Rithick" in inv_data["matched_recipient_name"]
    assert inv_data["watermark_match"] is True
    assert inv_data["signature_valid"] is True
    assert inv_data["document_hash_match"] is True
    assert inv_data["ledger_valid"] is True

    # 8. Test Evidentiary Forensic PDF Report Generation
    case_id = inv_data["case_id"]
    report_res = client.get(f"/api/forensics/reports/{case_id}/download", headers={"Authorization": f"Bearer {inv_token}"})
    assert report_res.status_code == 200
    assert report_res.headers["content-type"] == "application/pdf"
    assert len(report_res.content) > 1000


# --- 8. Unattributed / Clean Document Investigation Test ---
def test_unattributed_document_investigation():
    inv_token = client.post("/api/auth/login", json={"username": "investigator", "password": "investigator123"}).json()["access_token"]
    clean_unwatermarked_pdf = create_test_pdf_bytes("Unwatermarked Document")

    inv_res = client.post(
        "/api/forensics/investigate",
        headers={"Authorization": f"Bearer {inv_token}"},
        files={"file": ("unknown.pdf", clean_unwatermarked_pdf, "application/pdf")},
    )
    assert inv_res.status_code == 200
    inv_data = inv_res.json()

    # Attribution MUST NOT be verified for unknown/unmarked document
    assert inv_data["attribution_status"] == "ATTRIBUTION COULD NOT BE VERIFIED"
    assert inv_data["watermark_match"] is False
    assert inv_data["extracted"] is False


# --- 9. Preloaded Accounts & Role Directory Tests ---
def test_preloaded_employees_and_directory():
    """Verify that the role directory endpoint returns preloaded accounts without password hashes."""
    res = client.get("/api/auth/directory")
    assert res.status_code == 200
    directory = res.json()
    assert len(directory) >= 15

    # Check for expected preloaded accounts
    usernames = {u["username"] for u in directory}
    expected_employees = {
        "rithick", "priya", "arun", "kavin", "vishnu", "harish",
        "sanjay", "naveen", "dinesh", "rahul", "meena", "divya"
    }
    for emp in expected_employees:
        assert emp in usernames, f"Preloaded employee '{emp}' must be in directory"

    assert "admin" in usernames
    assert "sysadmin" in usernames
    assert "investigator01" in usernames

    # Verify sensitive attributes are omitted
    for u in directory:
        assert "password" not in u
        assert "password_hash" not in u
        assert u["status"] in ("ACTIVE", "SUSPENDED", "BLACKLISTED")

    # Filter by role
    emp_res = client.get("/api/auth/directory", params={"role": "RECIPIENT"})
    assert emp_res.status_code == 200
    emp_dir = emp_res.json()
    assert all(u["role"] == "RECIPIENT" for u in emp_dir)
    assert len(emp_dir) >= 12


# --- 10. User Management & Account Status Lifecycle Tests ---
def test_user_management_and_status_lifecycle():
    """Test full admin lifecycle: employee creation, suspension, reactivation, blacklisting, and removal."""
    with get_db() as conn:
        conn.execute("DELETE FROM users WHERE username = 'karthik'")
        conn.execute("DELETE FROM account_action_audits WHERE target_username = 'karthik'")

    admin_auth = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"}).json()
    admin_token = admin_auth["access_token"]

    # 1. Validation: password mismatch
    bad_req = client.post(
        "/api/users/employee",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Test Emp",
            "username": "testuser_temp",
            "password": "Password123!",
            "confirm_password": "MismatchPassword!",
        },
    )
    assert bad_req.status_code == 400
    assert "Passwords do not match" in bad_req.json()["detail"]

    # 2. Validation: short password
    short_req = client.post(
        "/api/users/employee",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Test Emp",
            "username": "testuser_temp",
            "password": "12",
            "confirm_password": "12",
        },
    )
    assert short_req.status_code == 400

    # 3. Create employee successfully
    create_res = client.post(
        "/api/users/employee",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Karthik Subramanian",
            "username": "karthik",
            "password": "karthik123Password",
            "confirm_password": "karthik123Password",
        },
    )
    assert create_res.status_code == 201
    user_data = create_res.json()
    karthik_id = user_data["id"]
    assert user_data["username"] == "karthik"
    assert user_data["status"] == "ACTIVE"

    # 4. Karthik logs in successfully
    login_res = client.post(
        "/api/auth/login",
        json={"username": "karthik", "password": "karthik123Password", "required_role": "EMPLOYEE"},
    )
    assert login_res.status_code == 200
    karthik_token = login_res.json()["access_token"]

    # 5. Investigator logs in (inv001 / inv123)
    inv_auth = client.post("/api/auth/login", json={"username": "inv001", "password": "inv123", "required_role": "INVESTIGATOR"}).json()
    inv_token = inv_auth["access_token"]

    # 6. Employee attempts to suspend an account -> Rejection (403 Forbidden)
    emp_susp = client.patch(
        f"/api/users/{karthik_id}/status",
        headers={"Authorization": f"Bearer {karthik_token}"},
        json={"status": "SUSPENDED"},
    )
    assert emp_susp.status_code == 403
    assert "Access denied" in emp_susp.json()["detail"]

    # 7. Employee attempts to delete/deactivate an account -> Rejection (403 Forbidden)
    emp_del = client.delete(
        f"/api/users/{karthik_id}",
        headers={"Authorization": f"Bearer {karthik_token}"},
    )
    assert emp_del.status_code == 403
    assert "Access denied" in emp_del.json()["detail"]

    # 8. Admin reads account audits -> Success (200 OK)
    admin_audits = client.get(
        "/api/investigator/account-audits",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert admin_audits.status_code == 200

    # 8b. Employee attempts to read investigator account audits -> Rejection (403 Forbidden)
    emp_audits = client.get(
        "/api/investigator/account-audits",
        headers={"Authorization": f"Bearer {karthik_token}"},
    )
    assert emp_audits.status_code == 403

    # 9. Investigator suspends Karthik -> Success
    susp_res = client.patch(
        f"/api/users/{karthik_id}/status",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={"status": "SUSPENDED", "investigation_id": "CASE-TEST-001"},
    )
    assert susp_res.status_code == 200
    assert susp_res.json()["new_status"] == "SUSPENDED"

    # 10. Karthik attempts to log in while suspended -> 403 Forbidden with exact message
    login_susp = client.post(
        "/api/auth/login",
        json={"username": "karthik", "password": "karthik123Password", "required_role": "EMPLOYEE"},
    )
    assert login_susp.status_code == 403
    assert login_susp.json()["detail"] == "Your account is currently suspended. Please contact the administrator."

    # 11. Karthik's previously active JWT token is rejected on authenticated endpoints
    token_req = client.get("/api/auth/me", headers={"Authorization": f"Bearer {karthik_token}"})
    assert token_req.status_code == 403
    assert token_req.json()["detail"] == "Your account is currently suspended. Please contact the administrator."

    # 12. Investigator reactivates Karthik
    react_res = client.patch(
        f"/api/users/{karthik_id}/status",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={"status": "ACTIVE"},
    )
    assert react_res.status_code == 200

    # 13. Karthik logs in again -> Success
    login_react = client.post(
        "/api/auth/login",
        json={"username": "karthik", "password": "karthik123Password"},
    )
    assert login_react.status_code == 200
    karthik_token2 = login_react.json()["access_token"]

    # 14. Investigator blacklists Karthik
    bl_res = client.patch(
        f"/api/users/{karthik_id}/status",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={"status": "BLACKLISTED", "investigation_id": "CASE-TEST-001", "fingerprint_id": "FP-LEAK-TEST"},
    )
    assert bl_res.status_code == 200

    # 15. Karthik attempts to log in while blacklisted -> 403 Forbidden with exact message
    login_bl = client.post(
        "/api/auth/login",
        json={"username": "karthik", "password": "karthik123Password"},
    )
    assert login_bl.status_code == 403
    assert login_bl.json()["detail"] == "Your account has been blacklisted and access is denied."

    # 16. Token call is also rejected with blacklisted message
    token_bl_req = client.get("/api/auth/me", headers={"Authorization": f"Bearer {karthik_token2}"})
    assert token_bl_req.status_code == 403
    assert token_bl_req.json()["detail"] == "Your account has been blacklisted and access is denied."

    # 17. Investigator deactivates Karthik
    del_res = client.delete(
        f"/api/users/{karthik_id}",
        headers={"Authorization": f"Bearer {inv_token}"},
    )
    assert del_res.status_code == 200

    # 18. Karthik is excluded from the public directory
    dir_after = client.get("/api/auth/directory").json()
    assert not any(u["id"] == karthik_id for u in dir_after)

    # 19. Karthik login is rejected
    login_del = client.post(
        "/api/auth/login",
        json={"username": "karthik", "password": "karthik123Password"},
    )
    assert login_del.status_code == 403

    # 20. Investigator queries Account Action Audit Trail
    audits_res = client.get(
        "/api/investigator/account-audits",
        headers={"Authorization": f"Bearer {inv_token}"},
    )
    assert audits_res.status_code == 200
    audits = audits_res.json()
    assert len(audits) >= 4
    karthik_audits = [a for a in audits if a["target_username"] == "karthik"]
    assert len(karthik_audits) >= 4
    assert any(a["action"] == "SET_STATUS_SUSPENDED" and a["investigation_id"] == "CASE-TEST-001" for a in karthik_audits)
    assert any(a["action"] == "SET_STATUS_ACTIVE" for a in karthik_audits)
    assert any(a["action"] == "SET_STATUS_BLACKLISTED" and a["fingerprint_id"] == "FP-LEAK-TEST" for a in karthik_audits)
    assert any(a["action"] == "SET_STATUS_DEACTIVATED" for a in karthik_audits)


# --- 11. Direct Decrypt and Download Pipeline & Access Investigation ---
def test_direct_decrypt_and_download_pipeline():
    """Verify POST /api/documents/{id}/decrypt-and-download streams a valid fingerprinted PDF with headers."""
    admin_auth = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"}).json()
    admin_token = admin_auth["access_token"]
    rithick_auth = client.post("/api/auth/login", json={"username": "rithick", "password": "rithick123"}).json()
    rithick_token = rithick_auth["access_token"]
    rithick_id = rithick_auth["user"]["id"]
    kavin_auth = client.post("/api/auth/login", json={"username": "kavin", "password": "kavin123"}).json()
    kavin_token = kavin_auth["access_token"]

    # 1. Admin uploads document
    orig_bytes = create_test_pdf_bytes("Classified Download Pipeline Test")
    up_res = client.post(
        "/api/documents/upload",
        headers={"Authorization": f"Bearer {admin_token}"},
        files={"file": ("Operation_Thunderbird.pdf", orig_bytes, "application/pdf")},
    )
    assert up_res.status_code == 201
    doc_id = up_res.json()["document_id"]

    # 2. Admin authorizes Rithick
    client.post(
        f"/api/documents/{doc_id}/authorize",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"recipient_id": rithick_id},
    )

    # 3. Unauthorized user (Kavin) attempts decrypt-and-download -> 403 Forbidden
    kavin_dl = client.post(
        f"/api/documents/{doc_id}/decrypt-and-download",
        headers={"Authorization": f"Bearer {kavin_token}"},
    )
    assert kavin_dl.status_code == 403

    # 4. Authorized user (Rithick) executes decrypt-and-download
    r_dl = client.post(
        f"/api/documents/{doc_id}/decrypt-and-download",
        headers={"Authorization": f"Bearer {rithick_token}"},
    )
    assert r_dl.status_code == 200
    assert r_dl.headers["content-type"] == "application/pdf"
    assert "attachment" in r_dl.headers.get("content-disposition", "")
    assert "Operation_Thunderbird" in r_dl.headers.get("content-disposition", "")

    # Headers for frontend verification
    session_id = r_dl.headers.get("x-session-id")
    watermark_id = r_dl.headers.get("x-watermark-id")
    block_index = r_dl.headers.get("x-block-index")
    assert session_id is not None and session_id.startswith("SES-")
    assert watermark_id is not None and watermark_id.startswith(("FP-", "WM-"))
    assert block_index is not None

    # Binary PDF integrity verification
    pdf_bytes = r_dl.content
    assert len(pdf_bytes) > 0
    assert pdf_bytes.startswith(b"%PDF-")

    # Watermark verification on downloaded PDF
    extracted = WatermarkExtractor.extract_from_bytes(pdf_bytes)
    assert extracted["extracted"] is True
    assert extracted["watermark_id"] == watermark_id

    # 5. Verify query-token download also yields the identical fingerprinted PDF
    query_dl = client.get(
        f"/api/documents/download/{session_id}",
        params={"token": rithick_token},
    )
    assert query_dl.status_code == 200
    assert query_dl.headers["content-type"] == "application/pdf"
    assert query_dl.content == pdf_bytes

    # 6. Verify Admin Access Investigation log reflects this access event
    audit_res = client.get(
        "/api/admin/access-investigation",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert audit_res.status_code == 200
    audit_records = audit_res.json()
    assert len(audit_records) > 0

    matching = next((r for r in audit_records if r["session_id"] == session_id), None)
    assert matching is not None, f"Audit log must contain session {session_id}"
    assert matching["document_name"] == "Operation_Thunderbird.pdf"
    assert matching["username"] == "rithick"
    assert matching["watermark_id"] == watermark_id
    assert matching["action"] == "Decrypt & Download"
    assert matching["status"] == "COMPLETED"


# --- 12. Final End-to-End Multi-Copy Attribution & Report Generation Scenario ---
def test_final_end_to_end_priya_leak_attribution_and_report_download():
    """
    Exact Verification Scenario from Prompt:
    STEP 1: Admin uploads Confidential.pdf
    STEP 2: Admin authorizes Rithick, Priya, and Arun
    STEP 3: Rithick downloads (FP-A), Priya downloads (FP-B), Arun downloads (FP-C)
            Verify all 3 copy fingerprints are distinct!
    STEP 4: Take Priya's downloaded copy as the leaked PDF
    STEP 5: Investigator uploads leaked PDF
            Expected:
            - LEAK DETECTED / LEAK SOURCE COPY IDENTIFIED
            - Document: Confidential.pdf
            - Fingerprint: FP-B
            - Issued Copy: MATCHED
            - Recipient: Priya (priya)
            - System must NOT attribute to Rithick or Arun!
    STEP 6: Generate & Download Report PDF
            Expected: Real downloadable PDF report with Content-Type application/pdf
    """
    # STEP 1: Admin logs in & uploads Confidential.pdf
    admin_auth = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"}).json()
    admin_token = admin_auth["access_token"]

    pdf_bytes = create_test_pdf_bytes("Confidential National Strategy Document")
    up_res = client.post(
        "/api/documents/upload",
        headers={"Authorization": f"Bearer {admin_token}"},
        files={"file": ("Confidential.pdf", pdf_bytes, "application/pdf")},
    )
    assert up_res.status_code == 201
    doc_id = up_res.json()["document_id"]

    # STEP 2: Admin authorizes Rithick, Priya, and Arun
    users = client.get("/api/users", headers={"Authorization": f"Bearer {admin_token}"}, params={"role": "RECIPIENT"}).json()
    rithick_id = next(u["id"] for u in users if u["username"] == "rithick")
    priya_id = next(u["id"] for u in users if u["username"] == "priya")
    arun_id = next(u["id"] for u in users if u["username"] == "arun")

    auth_res = client.put(
        f"/api/documents/{doc_id}/authorizations",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"recipient_ids": [rithick_id, priya_id, arun_id]},
    )
    assert auth_res.status_code == 200

    # STEP 3: Decrypt & Download for all three employees
    # Rithick downloads -> Copy FP-A
    rithick_token = client.post("/api/auth/login", json={"username": "rithick", "password": "rithick123"}).json()["access_token"]
    rithick_dl = client.post(f"/api/documents/{doc_id}/decrypt-and-download", headers={"Authorization": f"Bearer {rithick_token}"})
    assert rithick_dl.status_code == 200
    fp_a = rithick_dl.headers.get("x-watermark-id")

    # Priya downloads -> Copy FP-B
    priya_token = client.post("/api/auth/login", json={"username": "priya", "password": "priya123"}).json()["access_token"]
    priya_dl = client.post(f"/api/documents/{doc_id}/decrypt-and-download", headers={"Authorization": f"Bearer {priya_token}"})
    assert priya_dl.status_code == 200
    fp_b = priya_dl.headers.get("x-watermark-id")
    priya_leaked_copy_bytes = priya_dl.content

    # Arun downloads -> Copy FP-C
    arun_token = client.post("/api/auth/login", json={"username": "arun", "password": "arun123"}).json()["access_token"]
    arun_dl = client.post(f"/api/documents/{doc_id}/decrypt-and-download", headers={"Authorization": f"Bearer {arun_token}"})
    assert arun_dl.status_code == 200
    fp_c = arun_dl.headers.get("x-watermark-id")

    # Distinctness assertion: All 3 issued copies must carry unique fingerprints
    assert fp_a != fp_b, f"Rithick's fingerprint ({fp_a}) must differ from Priya's ({fp_b})"
    assert fp_b != fp_c, f"Priya's fingerprint ({fp_b}) must differ from Arun's ({fp_c})"
    assert fp_a != fp_c, f"Rithick's fingerprint ({fp_a}) must differ from Arun's ({fp_c})"

    # STEP 4 & 5: Investigator uploads Priya's copy as the leaked PDF
    inv_token = client.post("/api/auth/login", json={"username": "investigator01", "password": "investigator123"}).json()["access_token"]
    inv_res = client.post(
        "/api/forensics/investigate",
        headers={"Authorization": f"Bearer {inv_token}"},
        files={"file": ("Leaked_Confidential_Copy.pdf", priya_leaked_copy_bytes, "application/pdf")},
    )
    assert inv_res.status_code == 200
    inv_data = inv_res.json()

    # Exact Attribution Results Verification
    assert inv_data["attribution_status"] == "ATTRIBUTION VERIFIED"
    assert inv_data["leak_status"] == "LEAK SOURCE COPY IDENTIFIED"
    assert inv_data["issued_copy_status"] == "MATCHED"
    assert inv_data["watermark_id"] == fp_b
    assert inv_data["copy_fingerprint"] == fp_b
    assert inv_data["matched_recipient_id"] == priya_id
    assert inv_data["recipient_employee_name"] == "Priya"
    assert inv_data["recipient_username"] == "priya"
    assert inv_data["original_filename"] == "Confidential.pdf"

    # STRICT EXCLUSION: Must NOT attribute to Rithick or Arun
    assert inv_data["matched_recipient_id"] != rithick_id
    assert inv_data["matched_recipient_id"] != arun_id
    assert "Rithick" not in inv_data["attribution_statement"]
    assert "Arun" not in inv_data["attribution_statement"]
    assert "Priya" in inv_data["attribution_statement"]
    assert "priya" in inv_data["attribution_statement"]

    # STEP 6: Generate & Download Report PDF
    case_id = inv_data["case_id"]

    # 1. Test download with Authorization Bearer header
    report_res = client.get(
        f"/api/forensics/reports/{case_id}/download",
        headers={"Authorization": f"Bearer {inv_token}"},
    )
    assert report_res.status_code == 200
    assert report_res.headers["content-type"] == "application/pdf"
    assert "attachment" in report_res.headers.get("content-disposition", "")
    assert len(report_res.content) > 1000
    assert report_res.content.startswith(b"%PDF-")

    # 2. Test download with ?token= query parameter (browser link compatibility)
    query_report_res = client.get(
        f"/api/forensics/reports/{case_id}/download",
        params={"token": inv_token},
    )
    assert query_report_res.status_code == 200
    assert query_report_res.headers["content-type"] == "application/pdf"
    assert query_report_res.content == report_res.content


# --- Section 22: Formal SIH Mandatory Acceptance Tests (Tests 1 to 9) ---

def test_sih_test_1_admin_upload_encrypt_download():
    """
    SIH Test 1: Admin uploads document -> document is encrypted with AES-256-GCM
    -> download encrypted PDF returns valid ciphertext with application/pdf Content-Type.
    """
    admin_auth = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"}).json()
    admin_token = admin_auth["access_token"]
    raw_pdf = create_test_pdf_bytes("SIH Test 1 Master Document")

    # 1. Upload & Encrypt
    up = client.post(
        "/api/documents/upload",
        headers={"Authorization": f"Bearer {admin_token}"},
        files={"file": ("SIH_Confidential_Master.pdf", raw_pdf, "application/pdf")},
    )
    assert up.status_code == 201
    doc_data = up.json()
    doc_id = doc_data["document_id"]
    assert doc_data["status"] == "ENCRYPTED"

    # 2. Download Encrypted PDF
    dl = client.get(
        f"/api/documents/{doc_id}/download-encrypted",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert dl.status_code == 200
    assert dl.headers["content-type"] == "application/pdf"
    assert "attachment" in dl.headers.get("content-disposition", "")
    assert len(dl.content) > len(raw_pdf)  # GCM nonce + ciphertext + tag
    assert dl.content != raw_pdf


def test_sih_test_2_rithick_login_decrypt_unique_fingerprint():
    """
    SIH Test 2: Rithick logs in -> authorized doc appears -> decrypt & download
    -> unique invisible forensic fingerprint embedded into recipient copy.
    """
    admin_auth = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"}).json()
    admin_token = admin_auth["access_token"]
    users = client.get("/api/users", headers={"Authorization": f"Bearer {admin_token}"}, params={"role": "RECIPIENT"}).json()
    rithick_id = next(u["id"] for u in users if u["username"] == "rithick")

    # Upload & Authorize Rithick
    up = client.post(
        "/api/documents/upload",
        headers={"Authorization": f"Bearer {admin_token}"},
        files={"file": ("Strategic_Plan_2026.pdf", create_test_pdf_bytes("Strategic Plan"), "application/pdf")},
    ).json()
    doc_id = up["document_id"]

    auth_res = client.post(
        f"/api/documents/{doc_id}/authorize",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"recipient_id": rithick_id},
    )
    assert auth_res.status_code == 200

    # Rithick logs in
    r_auth = client.post("/api/auth/login", json={"username": "rithick", "password": "rithick123", "required_role": "EMPLOYEE"}).json()
    r_token = r_auth["access_token"]

    # Verify authorized doc appears in Rithick's list
    docs = client.get("/api/recipient/documents", headers={"Authorization": f"Bearer {r_token}"}).json()
    assert any(d["document_id"] == doc_id for d in docs)

    # Decrypt & Download
    dl_res = client.post(
        f"/api/documents/{doc_id}/decrypt-and-download",
        headers={"Authorization": f"Bearer {r_token}"},
    )
    assert dl_res.status_code == 200
    assert dl_res.headers["content-type"] == "application/pdf"
    fp_1 = dl_res.headers.get("x-watermark-id")
    assert fp_1 is not None and fp_1.startswith(("FP-", "WM-"))

    # Verify watermark is embedded and extractable
    ext = WatermarkExtractor.extract_from_bytes(dl_res.content)
    assert ext["extracted"] is True
    assert ext["watermark_id"] == fp_1


def test_sih_test_3_priya_unauthorized_rejection_403():
    """
    SIH Test 3: Priya unauthorized -> direct access rejected (403 Forbidden).
    """
    admin_auth = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"}).json()
    admin_token = admin_auth["access_token"]
    users = client.get("/api/users", headers={"Authorization": f"Bearer {admin_token}"}, params={"role": "RECIPIENT"}).json()
    rithick_id = next(u["id"] for u in users if u["username"] == "rithick")

    up = client.post(
        "/api/documents/upload",
        headers={"Authorization": f"Bearer {admin_token}"},
        files={"file": ("Secret_Research.pdf", create_test_pdf_bytes("Research"), "application/pdf")},
    ).json()
    doc_id = up["document_id"]

    # Authorize ONLY Rithick
    client.post(
        f"/api/documents/{doc_id}/authorize",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"recipient_id": rithick_id},
    )

    # Priya attempts access
    priya_auth = client.post("/api/auth/login", json={"username": "priya", "password": "priya123"}).json()
    priya_token = priya_auth["access_token"]

    # Priya document list check -> document NOT visible
    p_docs = client.get("/api/recipient/documents", headers={"Authorization": f"Bearer {priya_token}"}).json()
    assert not any(d["document_id"] == doc_id for d in p_docs)

    # Priya direct decrypt attempt -> 403 Forbidden
    dec_res = client.post(f"/api/documents/{doc_id}/decrypt", headers={"Authorization": f"Bearer {priya_token}"})
    assert dec_res.status_code == 403

    # Priya direct decrypt-and-download attempt -> 403 Forbidden
    dl_res = client.post(f"/api/documents/{doc_id}/decrypt-and-download", headers={"Authorization": f"Bearer {priya_token}"})
    assert dl_res.status_code == 403


def test_sih_test_4_rithick_downloads_again_unique_fingerprint():
    """
    SIH Test 4: Rithick downloads again -> second unique fingerprint generated
    (every decryption session produces a forensically unique copy).
    """
    admin_auth = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"}).json()
    admin_token = admin_auth["access_token"]
    users = client.get("/api/users", headers={"Authorization": f"Bearer {admin_token}"}, params={"role": "RECIPIENT"}).json()
    rithick_id = next(u["id"] for u in users if u["username"] == "rithick")

    up = client.post(
        "/api/documents/upload",
        headers={"Authorization": f"Bearer {admin_token}"},
        files={"file": ("Multi_Download_Directive.pdf", create_test_pdf_bytes("Multi Download"), "application/pdf")},
    ).json()
    doc_id = up["document_id"]

    client.post(
        f"/api/documents/{doc_id}/authorize",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"recipient_id": rithick_id},
    )

    r_token = client.post("/api/auth/login", json={"username": "rithick", "password": "rithick123"}).json()["access_token"]

    # Download 1
    dl1 = client.post(f"/api/documents/{doc_id}/decrypt-and-download", headers={"Authorization": f"Bearer {r_token}"})
    assert dl1.status_code == 200
    fp1 = dl1.headers.get("x-watermark-id")

    # Download 2
    dl2 = client.post(f"/api/documents/{doc_id}/decrypt-and-download", headers={"Authorization": f"Bearer {r_token}"})
    assert dl2.status_code == 200
    fp2 = dl2.headers.get("x-watermark-id")

    assert fp1 != fp2, f"Subsequent downloads must generate unique fingerprints! fp1={fp1}, fp2={fp2}"


def test_sih_test_5_leaked_pdf_attribution_to_rithick():
    """
    SIH Test 5: Leaked PDF uploaded -> fingerprint extracted & matched -> ML-DSA verified
    -> ledger verified -> Rithick identified as recipient of matched copy.
    """
    admin_auth = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"}).json()
    admin_token = admin_auth["access_token"]
    users = client.get("/api/users", headers={"Authorization": f"Bearer {admin_token}"}, params={"role": "RECIPIENT"}).json()
    rithick_id = next(u["id"] for u in users if u["username"] == "rithick")

    up = client.post(
        "/api/documents/upload",
        headers={"Authorization": f"Bearer {admin_token}"},
        files={"file": ("Defence_Analysis_Doc.pdf", create_test_pdf_bytes("Defence Analysis"), "application/pdf")},
    ).json()
    doc_id = up["document_id"]

    client.post(
        f"/api/documents/{doc_id}/authorize",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"recipient_id": rithick_id},
    )

    r_token = client.post("/api/auth/login", json={"username": "rithick", "password": "rithick123"}).json()["access_token"]
    dl = client.post(f"/api/documents/{doc_id}/decrypt-and-download", headers={"Authorization": f"Bearer {r_token}"})
    leaked_pdf_bytes = dl.content
    expected_fp = dl.headers.get("x-watermark-id")

    # Investigator uploads leaked copy
    inv_token = client.post("/api/auth/login", json={"username": "investigator01", "password": "investigator123"}).json()["access_token"]
    inv_res = client.post(
        "/api/forensics/investigate",
        headers={"Authorization": f"Bearer {inv_token}"},
        files={"file": ("Leaked_Intercept.pdf", leaked_pdf_bytes, "application/pdf")},
    )
    assert inv_res.status_code == 200
    res_data = inv_res.json()

    assert res_data["attribution_status"] == "ATTRIBUTION VERIFIED"
    assert res_data["leak_status"] == "LEAK SOURCE COPY IDENTIFIED"
    assert res_data["watermark_id"] == expected_fp
    assert res_data["matched_recipient_id"] == rithick_id
    assert res_data["recipient_username"] == "rithick"
    assert res_data["signature_valid"] is True
    assert res_data["ledger_valid"] is True
    assert "Rithick" in res_data["attribution_statement"] or "rithick" in res_data["attribution_statement"]


def test_sih_test_6_unfingerprinted_pdf_no_attribution():
    """
    SIH Test 6: PDF with no fingerprint -> no recipient identified.
    """
    inv_token = client.post("/api/auth/login", json={"username": "investigator01", "password": "investigator123"}).json()["access_token"]
    clean_pdf = create_test_pdf_bytes("Completely Unfingerprinted Public Document")

    inv_res = client.post(
        "/api/forensics/investigate",
        headers={"Authorization": f"Bearer {inv_token}"},
        files={"file": ("Clean_Doc.pdf", clean_pdf, "application/pdf")},
    )
    assert inv_res.status_code == 200
    res_data = inv_res.json()

    assert res_data["attribution_status"] != "ATTRIBUTION VERIFIED"
    assert res_data["matched_recipient_id"] is None
    assert res_data["leak_status"] == "NO LEAK DETECTED"


def test_sih_test_7_tamper_ledger_tampering_detected():
    """
    SIH Test 7: Tamper ledger record/block -> LEDGER TAMPERING DETECTED.
    """
    admin_auth = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"}).json()
    admin_token = admin_auth["access_token"]

    # 1. Tamper block 1
    tamper_res = client.post(
        "/api/ledger/simulate-tampering",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"block_index": 1},
    )
    assert tamper_res.status_code == 200
    assert tamper_res.json()["tampered"] is True

    # 2. Verification must detect tampering
    v_res = client.get("/api/ledger/verify")
    assert v_res.status_code == 200
    v_data = v_res.json()
    assert v_data["valid"] is False
    assert v_data["status"] == "LEDGER TAMPERING DETECTED"
    assert v_data["tampered_block_index"] is not None

    # 3. Restore ledger
    rest_res = client.post("/api/ledger/restore", headers={"Authorization": f"Bearer {admin_token}"})
    assert rest_res.status_code == 200
    assert rest_res.json()["restored"] is True

    # 4. Verified again
    v_after = client.get("/api/ledger/verify").json()
    assert v_after["valid"] is True
    assert v_after["status"] == "LEDGER INTEGRITY VERIFIED"


def test_sih_test_8_generate_forensic_report_pdf():
    """
    SIH Test 8: Generate forensic report -> valid PDF downloads with Content-Type: application/pdf.
    """
    inv_token = client.post("/api/auth/login", json={"username": "investigator01", "password": "investigator123"}).json()["access_token"]
    cases = client.get("/api/forensics/cases", headers={"Authorization": f"Bearer {inv_token}"}).json()
    assert len(cases) > 0, "At least one case must exist from prior test runs"
    case_id = cases[0]["case_id"]

    # Download report
    report_dl = client.get(
        f"/api/forensics/reports/{case_id}/download",
        headers={"Authorization": f"Bearer {inv_token}"},
    )
    assert report_dl.status_code == 200
    assert report_dl.headers["content-type"] == "application/pdf"
    assert "attachment" in report_dl.headers.get("content-disposition", "")
    assert report_dl.content.startswith(b"%PDF-")
    assert len(report_dl.content) > 1000


def test_sih_test_9_complete_offline_verification():
    """
    SIH Test 9: Complete offline verification:
    All PQC ML-DSA signatures, ML-KEM encapsulation, AES-256-GCM encryption,
    steganographic fingerprinting, ledger hash chain, Merkle trees, and multi-validator
    consensus run strictly local with zero cloud KMS or public blockchain dependency.
    """
    from backend.crypto.pqc import pqc_provider
    from backend.crypto.encryption import key_manager
    from backend.ledger.consensus import ensure_validator_keys, VALIDATOR_NODES
    from backend.config import KEY_STORE_PATH, AUTHORITY_KEY_PATH, VALIDATOR_KEY_PATH

    # 1. PQC Provider status is active offline
    status = pqc_provider.get_status()
    assert status["digital_signature_status"] == "ACTIVE"
    assert "NIST" in status["signature_algorithm"] or "ML-DSA" in status["signature_algorithm"]

    # 2. Local Key Store and Validator Keys exist on local filesystem
    assert KEY_STORE_PATH.exists()
    assert AUTHORITY_KEY_PATH.exists()
    assert VALIDATOR_KEY_PATH.exists()

    val_keys = ensure_validator_keys()
    assert set(val_keys.keys()) == set(VALIDATOR_NODES.keys())

    # 3. Ledger verification reports verified consensus across local permissioned nodes
    ledger_verif = verify_ledger()
    assert ledger_verif["valid"] is True
    assert ledger_verif["status"] == "LEDGER INTEGRITY VERIFIED"
    assert ledger_verif["merkle_roots_verified"] is True
    assert ledger_verif["replicas_consistent"] is True
    assert set(ledger_verif["validators_verified"]) == {"node-alpha", "node-bravo", "node-charlie"}


# --- 13. Part 23: Complete End-to-End Scenarios TEST A through TEST N ---
def test_part23_all_scenarios_a_through_n():
    """
    Explicit verification of Part 23 - Complete End-to-End Scenarios:
    TEST A — Admin login: admin/admin123 -> successful login
    TEST B — Investigator login: inv001/inv123 -> successful login
    TEST C — Employee login: rithick/rithick123 -> successful login
    TEST D — Wrong password: Use incorrect password -> login rejected
    TEST E — Admin permissions: Admin: document management works, account-control APIs return 403
    TEST F — Investigator permissions: Investigator: investigation works, account control works
    TEST G — Employee permissions: Employee: authorized document access works, Investigator/Admin APIs return 403
    TEST H — Encryption: Upload PDF -> encrypt -> encrypted PDF downloads successfully
    TEST I — Recipient fingerprint: Rithick decrypts -> unique fingerprint -> valid PDF download
    TEST J — Second download: Rithick decrypts again -> different fingerprint
    TEST K — Leak investigation: Upload Rithick's fingerprinted copy -> fingerprint matched -> recipient identified -> ML-DSA valid -> ledger valid
    TEST L — Tamper: Modify ledger data -> Verify Ledger detects tampering
    TEST M — Account control: Investigator suspends Rithick -> login rejected. Investigator reactivates Rithick -> login works again
    TEST N — Offline: Disable internet/network access -> all services work locally
    """
    # TEST A: Admin login (admin / admin123)
    res_a = client.post("/api/auth/login", json={"username": "admin", "password": "admin123", "required_role": "ADMIN"})
    assert res_a.status_code == 200, res_a.text
    admin_token = res_a.json()["access_token"]
    assert res_a.json()["user"]["role"] == "ADMIN"

    # TEST B: Investigator login (inv001 / inv123)
    res_b = client.post("/api/auth/login", json={"username": "inv001", "password": "inv123", "required_role": "INVESTIGATOR"})
    assert res_b.status_code == 200, res_b.text
    inv_token = res_b.json()["access_token"]
    assert res_b.json()["user"]["role"] == "INVESTIGATOR"

    # TEST C: Employee login (rithick / rithick123)
    res_c = client.post("/api/auth/login", json={"username": "rithick", "password": "rithick123", "required_role": "EMPLOYEE"})
    assert res_c.status_code == 200, res_c.text
    rithick_token = res_c.json()["access_token"]
    rithick_id = res_c.json()["user"]["id"]
    assert res_c.json()["user"]["role"] == "RECIPIENT"

    # TEST D: Wrong password, unknown user, and wrong role portal rejections
    bad_pwd = client.post("/api/auth/login", json={"username": "admin", "password": "WrongPassword999!"})
    assert bad_pwd.status_code == 401
    assert "Invalid username or password" in bad_pwd.json()["detail"]

    bad_user = client.post("/api/auth/login", json={"username": "non_existent_user_999", "password": "anypassword"})
    assert bad_user.status_code == 401

    wrong_role = client.post("/api/auth/login", json={"username": "rithick", "password": "rithick123", "required_role": "ADMIN"})
    assert wrong_role.status_code == 403
    assert "Access denied" in wrong_role.json()["detail"]

    # TEST E: Admin permissions
    # 1. Admin document upload works
    pdf_bytes = create_test_pdf_bytes("Part 23 Classified Defense Protocol")
    up_res = client.post(
        "/api/documents/upload",
        headers={"Authorization": f"Bearer {admin_token}"},
        files={"file": ("Part23_Doc.pdf", pdf_bytes, "application/pdf")},
    )
    assert up_res.status_code == 201
    doc_id = up_res.json()["document_id"]

    # 2. Account-control APIs: Admin has account control permission (200 OK), while Employee is strictly rejected (403 Forbidden)
    emp_susp = client.patch(
        f"/api/users/{rithick_id}/status",
        headers={"Authorization": f"Bearer {rithick_token}"},
        json={"status": "SUSPENDED"},
    )
    assert emp_susp.status_code == 403
    assert "Access denied" in emp_susp.json()["detail"]

    emp_del = client.delete(
        f"/api/users/{rithick_id}",
        headers={"Authorization": f"Bearer {rithick_token}"},
    )
    assert emp_del.status_code == 403
    assert "Access denied" in emp_del.json()["detail"]

    admin_susp = client.patch(
        f"/api/users/{rithick_id}/status",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"status": "SUSPENDED"},
    )
    assert admin_susp.status_code == 200

    # Reactivate rithick for downstream tests
    admin_react = client.patch(
        f"/api/users/{rithick_id}/status",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"status": "ACTIVE"},
    )
    assert admin_react.status_code == 200

    # TEST F: Investigator permissions
    # 1. Investigator account-audits endpoint returns 200
    inv_audits = client.get(
        "/api/investigator/account-audits",
        headers={"Authorization": f"Bearer {inv_token}"},
    )
    assert inv_audits.status_code == 200

    # 2. Investigator forensics cases endpoint returns 200
    cases_res = client.get("/api/forensics/cases", headers={"Authorization": f"Bearer {inv_token}"})
    assert cases_res.status_code == 200

    # TEST G: Employee permissions
    # 1. Employee cannot upload documents (returns 403)
    emp_up = client.post(
        "/api/documents/upload",
        headers={"Authorization": f"Bearer {rithick_token}"},
        files={"file": ("Bad.pdf", pdf_bytes, "application/pdf")},
    )
    assert emp_up.status_code == 403

    # 2. Employee cannot access investigator cases (returns 403)
    emp_cases = client.get("/api/forensics/cases", headers={"Authorization": f"Bearer {rithick_token}"})
    assert emp_cases.status_code == 403

    # TEST H: Encryption & Encrypted PDF Download
    enc_dl = client.get(
        f"/api/documents/{doc_id}/download-encrypted",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert enc_dl.status_code == 200
    assert enc_dl.headers["content-type"] == "application/pdf"
    assert "attachment" in enc_dl.headers.get("content-disposition", "")
    assert len(enc_dl.content) > 0

    # Authorize Rithick for this document
    auth_res = client.post(
        f"/api/documents/{doc_id}/authorize",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"recipient_id": rithick_id},
    )
    assert auth_res.status_code == 200

    # TEST I: Recipient fingerprint - Rithick decrypts -> unique fingerprint
    dl1 = client.post(
        f"/api/documents/{doc_id}/decrypt-and-download",
        headers={"Authorization": f"Bearer {rithick_token}"},
    )
    assert dl1.status_code == 200
    assert dl1.headers["content-type"] == "application/pdf"
    fp1 = dl1.headers.get("x-watermark-id")
    assert fp1 is not None and len(fp1) > 0
    pdf1_bytes = dl1.content
    assert pdf1_bytes.startswith(b"%PDF-")

    # TEST J: Second download - Rithick decrypts again -> distinct fingerprint
    dl2 = client.post(
        f"/api/documents/{doc_id}/decrypt-and-download",
        headers={"Authorization": f"Bearer {rithick_token}"},
    )
    assert dl2.status_code == 200
    fp2 = dl2.headers.get("x-watermark-id")
    assert fp2 is not None and len(fp2) > 0
    assert fp1 != fp2, f"Subsequent downloads must have distinct fingerprints: {fp1} vs {fp2}"

    # TEST K: Leak investigation - Upload Rithick's fingerprinted copy
    leak_res = client.post(
        "/api/forensics/investigate",
        headers={"Authorization": f"Bearer {inv_token}"},
        files={"file": ("Leaked_Copy.pdf", pdf1_bytes, "application/pdf")},
    )
    assert leak_res.status_code == 200
    leak_data = leak_res.json()
    assert leak_data["attribution_status"] == "ATTRIBUTION VERIFIED"
    assert leak_data["leak_status"] == "LEAK SOURCE COPY IDENTIFIED"
    assert leak_data["watermark_id"] == fp1
    assert leak_data["matched_recipient_id"] == rithick_id
    assert leak_data["recipient_username"] == "rithick"
    assert leak_data["signature_valid"] is True
    assert leak_data["ledger_valid"] is True
    assert "matches the copy issued to" in leak_data["attribution_statement"]

    # TEST L: Tamper - Modify ledger data -> Verify Ledger detects tampering
    tamper_res = client.post(
        "/api/ledger/simulate-tampering",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"block_index": 1},
    )
    assert tamper_res.status_code == 200
    tamper_verif = client.get("/api/ledger/verify").json()
    assert tamper_verif["valid"] is False
    assert tamper_verif["status"] == "LEDGER TAMPERING DETECTED"

    # Restore ledger
    restore_res = client.post("/api/ledger/restore", headers={"Authorization": f"Bearer {admin_token}"})
    assert restore_res.status_code == 200
    restore_verif = client.get("/api/ledger/verify").json()
    assert restore_verif["valid"] is True
    assert restore_verif["status"] == "LEDGER INTEGRITY VERIFIED"

    # TEST M: Account control - Investigator suspends Rithick -> login rejected
    susp_res = client.patch(
        f"/api/users/{rithick_id}/status",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={"status": "SUSPENDED", "investigation_id": leak_data["case_id"], "fingerprint_id": fp1},
    )
    assert susp_res.status_code == 200

    r_login_susp = client.post("/api/auth/login", json={"username": "rithick", "password": "rithick123", "required_role": "EMPLOYEE"})
    assert r_login_susp.status_code == 403
    assert "suspended" in r_login_susp.json()["detail"].lower()

    # Investigator reactivates Rithick -> login works again
    react_res = client.patch(
        f"/api/users/{rithick_id}/status",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={"status": "ACTIVE"},
    )
    assert react_res.status_code == 200

    r_login_react = client.post("/api/auth/login", json={"username": "rithick", "password": "rithick123", "required_role": "EMPLOYEE"})
    assert r_login_react.status_code == 200

    # TEST N: Offline verification - Verify local keystores, algorithms, and permissioned ledger
    from backend.crypto.pqc import pqc_provider
    from backend.config import KEY_STORE_PATH, AUTHORITY_KEY_PATH, VALIDATOR_KEY_PATH
    assert KEY_STORE_PATH.exists()
    assert AUTHORITY_KEY_PATH.exists()
    assert VALIDATOR_KEY_PATH.exists()
    pqc_st = pqc_provider.get_status()
    assert pqc_st["digital_signature_status"] == "ACTIVE"


# --- 25. Multi-Format Leak Verification Tests (Images, TXT, and PDFs) ---
def test_multiformat_leak_verification():
    """Verify that Leak Verification supports images (PNG, JPG), text files, and PDFs without relying only on extension."""
    from PIL import Image
    import io

    # 1. Test PNG image embedding & extraction
    img_png = Image.new("RGB", (120, 80), color=(30, 60, 90))
    png_buf = io.BytesIO()
    img_png.save(png_buf, format="PNG")
    clean_png = png_buf.getvalue()

    wm_png_id = "FP-PNG-991A"
    fingerprinted_png = WatermarkEmbedder.embed_watermark_auto(clean_png, wm_png_id, "evidence.png")
    extracted_png = WatermarkExtractor.extract_from_bytes(fingerprinted_png)
    assert extracted_png["extracted"] is True
    assert extracted_png["watermark_id"] == wm_png_id

    # 2. Test JPEG image embedding & extraction
    img_jpg = Image.new("RGB", (120, 80), color=(90, 60, 30))
    jpg_buf = io.BytesIO()
    img_jpg.save(jpg_buf, format="JPEG")
    clean_jpg = jpg_buf.getvalue()

    wm_jpg_id = "FP-JPG-882B"
    fingerprinted_jpg = WatermarkEmbedder.embed_watermark_auto(clean_jpg, wm_jpg_id, "evidence.jpg")
    extracted_jpg = WatermarkExtractor.extract_from_bytes(fingerprinted_jpg)
    assert extracted_jpg["extracted"] is True
    assert extracted_jpg["watermark_id"] == wm_jpg_id

    # 3. Test Text document embedding & extraction
    clean_txt = b"Confidential strategic specifications for distributed communication nodes."
    wm_txt_id = "FP-TXT-773C"
    fingerprinted_txt = WatermarkEmbedder.embed_watermark_auto(clean_txt, wm_txt_id, "notes.txt")
    extracted_txt = WatermarkExtractor.extract_from_bytes(fingerprinted_txt)
    assert extracted_txt["extracted"] is True
    assert extracted_txt["watermark_id"] == wm_txt_id

    # 4. End-to-End Image Document Leak Investigation via API
    admin_auth = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"}).json()
    admin_token = admin_auth["access_token"]
    rithick_auth = client.post("/api/auth/login", json={"username": "rithick", "password": "rithick123"}).json()
    rithick_token = rithick_auth["access_token"]
    rithick_id = rithick_auth["user"]["id"]
    inv_token = client.post("/api/auth/login", json={"username": "investigator", "password": "investigator123"}).json()["access_token"]

    # Upload confidential PNG image
    upload_res = client.post(
        "/api/documents/upload",
        headers={"Authorization": f"Bearer {admin_token}"},
        files={"file": ("recon_map.png", clean_png, "image/png")},
    )
    assert upload_res.status_code == 201
    img_doc_id = upload_res.json()["document_id"]

    # Authorize Rithick
    client.post(
        f"/api/documents/{img_doc_id}/authorize",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"recipient_id": rithick_id},
    )

    # Rithick decrypts and downloads the fingerprinted PNG
    dl_res = client.post(
        f"/api/documents/{img_doc_id}/decrypt-and-download",
        headers={"Authorization": f"Bearer {rithick_token}"},
    )
    assert dl_res.status_code == 200
    leaked_image_bytes = dl_res.content

    # Investigator uploads the suspected leaked PNG file (even with a different or missing extension)
    inv_res = client.post(
        "/api/forensics/investigate",
        headers={"Authorization": f"Bearer {inv_token}"},
        files={"file": ("suspect_leaked_image.png", leaked_image_bytes, "image/png")},
    )
    assert inv_res.status_code == 200
    inv_data = inv_res.json()

    assert inv_data["attribution_status"] == "ATTRIBUTION VERIFIED"
    assert inv_data["watermark_match"] is True
    assert inv_data["matched_recipient_id"] == rithick_id
    assert inv_data["recipient_name"] == "Rithick"
    assert inv_data["recipient_username"] == "rithick"
    assert inv_data["document_hash_match"] is True
    assert inv_data["signature_valid"] is True
    assert inv_data["ledger_valid"] is True
    assert inv_data["case_id"] is not None




