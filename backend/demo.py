"""
Demo Data & Seed Initialization
Pre-seeds realistic user profiles, role assignments, and sample confidential PDF document
for instantaneous SIH evaluation and testing.
"""

import io
from datetime import datetime, timezone
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

from backend.database import get_db
from backend.auth.service import AuthService
from backend.documents.service import DocumentService
from backend.ledger.ledger import OfflineLedger


def create_sample_confidential_pdf() -> bytes:
    """Generate a clean sample confidential PDF document."""
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica-Bold", 18)
    c.drawString(50, height - 70, "TOP SECRET // DEFENSE LOGISTICS DIRECTIVE")

    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, height - 100, "OPERATION ODYSSEY: SECURE SUPPLY CHAIN PROTOCOL")

    c.setFont("Helvetica", 10)
    lines = [
        "CLASSIFICATION: RESTRICTED DISTRIBUTION - AUTHORIZED RECIPIENTS ONLY",
        "ISSUED BY: DEFENSE PROCUREMENT & MATERIAL COMMAND (DPMC)",
        f"TIMESTAMP: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "1. OBJECTIVE",
        "This confidential directive establishes cryptographically bound distribution guidelines for tactical hardware.",
        "Unauthorized dissemination of this specification is strictly prohibited under National Security Act provisions.",
        "",
        "2. MULTI-RECIPIENT DISTRIBUTION POLICIES",
        "- All recipients receive cryptographically identical ciphertext during initial distribution.",
        "- Decryption is monitored via local tamper-evident provenance ledger.",
        "- Every authorized recipient session embeds a persistent imperceptible forensic fingerprint.",
        "- In the event of a document leak, TraceSeal automated attribution verifies exact session origin.",
        "",
        "3. TACTICAL PAYLOAD SPECIFICATIONS",
        "Asset Code: SIGMA-9942",
        "Hardware Manifest: Autonomous Secure Gateway v4.2",
        "Frequency Allocation: 4.82 GHz - 5.12 GHz L-Band",
        "Authorized Handlers: Rithick (Logistics), Priya (Field Operations)",
        "",
        "NOTICE: ANY DUPLICATE OR EXPORTED COPY CARRIES A CRYPTOGRAPHICALLY VERIFIABLE PROVENANCE EVENT."
    ]

    y = height - 130
    for line in lines:
        if line.startswith("1.") or line.startswith("2.") or line.startswith("3."):
            c.setFont("Helvetica-Bold", 10)
        elif line.startswith("TOP SECRET") or line.startswith("NOTICE:"):
            c.setFont("Helvetica-Bold", 9)
        else:
            c.setFont("Helvetica", 9)
        c.drawString(50, y, line)
        y -= 18

    # Border & Footer
    c.setLineWidth(1)
    c.rect(40, 40, width - 80, height - 80)
    c.setFont("Helvetica-Oblique", 8)
    c.drawString(50, 48, "CONFIDENTIAL // TRACESEAL PROTECTED DOCUMENT // DO NOT DUPLICATE WITHOUT AUTHORIZATION")

    c.save()
    return buffer.getvalue()


def initialize_demo_environment():
    """Seed demo accounts, document, and ledger."""
    OfflineLedger.initialize_ledger()

    # Clean up any malformed legacy usernames, ephemeral test accounts, and redundant investigators
    with get_db() as conn:
        conn.cursor().execute("DELETE FROM users WHERE username LIKE '@%'")
        conn.cursor().execute("DELETE FROM users WHERE username IN ('testemp_ctrl', 'testuser_temp', 'karthik')")
        conn.cursor().execute("DELETE FROM users WHERE role = 'INVESTIGATOR' AND username NOT IN ('investigator01', 'investigator02', 'investigator03')")

    demo_users = [
        # Administrators
        ("admin", "admin123", "Admin", "ADMIN"),
        ("sysadmin", "admin123", "System Administrator", "ADMIN"),
        # Investigators (Exactly 3 active accounts)
        ("investigator01", "investigator123", "Investigator 1", "INVESTIGATOR"),
        ("investigator02", "investigator123", "Investigator 2", "INVESTIGATOR"),
        ("investigator03", "investigator123", "Investigator 3", "INVESTIGATOR"),
        # Employees (12 realistic employees)
        ("rithick", "rithick123", "Rithick", "RECIPIENT"),
        ("priya", "priya123", "Priya", "RECIPIENT"),
        ("arun", "arun123", "Arun", "RECIPIENT"),
        ("kavin", "kavin123", "Kavin", "RECIPIENT"),
        ("vishnu", "vishnu123", "Vishnu", "RECIPIENT"),
        ("harish", "harish123", "Harish", "RECIPIENT"),
        ("sanjay", "sanjay123", "Sanjay", "RECIPIENT"),
        ("naveen", "naveen123", "Naveen", "RECIPIENT"),
        ("dinesh", "dinesh123", "Dinesh", "RECIPIENT"),
        ("rahul", "rahul123", "Rahul", "RECIPIENT"),
        ("meena", "meena123", "Meena", "RECIPIENT"),
        ("divya", "divya123", "Divya", "RECIPIENT"),
    ]

    created_users = {}
    for username, pwd, dname, role in demo_users:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, status, password_hash FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row:
                from backend.auth.service import verify_password, hash_password
                if not verify_password(row["password_hash"], pwd):
                    cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(pwd), row["id"]))
                cursor.execute("UPDATE users SET display_name = ? WHERE id = ?", (dname, row["id"]))
                if row["status"] != "ACTIVE":
                    cursor.execute("UPDATE users SET status = 'ACTIVE', active = 1 WHERE id = ?", (row["id"],))
                created_users[username] = row["id"]
            else:
                user = AuthService.register_user(username, pwd, dname, role)
                created_users[username] = user["id"]

    # Check if sample confidential document already uploaded
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT document_id FROM documents WHERE original_filename = 'Confidential.pdf'")
        doc_row = cursor.fetchone()

    if not doc_row:
        sample_pdf_bytes = create_sample_confidential_pdf()
        admin_id = created_users["admin"]
        doc = DocumentService.upload_and_encrypt(
            file_bytes=sample_pdf_bytes,
            filename="Confidential.pdf",
            uploaded_by_user_id=admin_id,
        )
        doc_id = doc["document_id"]

        # Authorize Rithick and Priya by default (Arun and Kavin are unauthorized)
        DocumentService.authorize_recipient(doc_id, created_users["rithick"], admin_id)
        DocumentService.authorize_recipient(doc_id, created_users["priya"], admin_id)

    # Ensure baseline initial leak incidents state: exactly 3 confirmed leaked documents, all others SAFE
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as cnt FROM documents WHERE status = 'LEAKED'")
        leaked_cnt = cursor.fetchone()["cnt"]
        if leaked_cnt == 0 or leaked_cnt > 10:
            cursor.execute("""
                SELECT DISTINCT matched_document_id FROM investigations 
                WHERE attribution_status IN ('ATTRIBUTION VERIFIED', 'LEAK DETECTED', 'CONFIRMED_LEAK')
                  AND watermark_matched = 1
                ORDER BY investigated_at DESC LIMIT 3
            """)
            top_3 = [r["matched_document_id"] for r in cursor.fetchall() if r["matched_document_id"]]
            if len(top_3) == 3:
                cursor.execute("UPDATE documents SET status = 'SAFE' WHERE status != 'DELETED'")
                cursor.execute(f"UPDATE documents SET status = 'LEAKED' WHERE document_id IN ({','.join(['?']*len(top_3))})", top_3)

    return {
        "status": "INITIALIZED",
        "demo_accounts": [
            {"username": u[0], "password": u[1], "role": u[3], "name": u[2]}
            for u in demo_users
        ],
        "sample_document": "Confidential.pdf",
    }
