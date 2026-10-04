"""
TraceSeal Database Management
Local SQLite database setup and migration schema.
"""

import sqlite3
from contextlib import contextmanager
from typing import Generator
from backend.config import DB_PATH, ensure_directories


def get_connection() -> sqlite3.Connection:
    """Create and return a configured SQLite connection."""
    ensure_directories()
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    """Context manager for safe database transactions."""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Initialize database tables for TraceSeal."""
    ensure_directories()
    with get_db() as conn:
        cursor = conn.cursor()

        # 1. Users
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            display_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('ADMIN', 'RECIPIENT', 'INVESTIGATOR')),
            public_key TEXT,
            created_at TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE', 'SUSPENDED', 'BLACKLISTED', 'REMOVED'))
        );
        """)

        # 2. Documents
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            document_id TEXT PRIMARY KEY,
            original_filename TEXT NOT NULL,
            original_hash TEXT NOT NULL,
            encrypted_filename TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            uploaded_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'ENCRYPTED',
            dek_hex TEXT,
            FOREIGN KEY (uploaded_by) REFERENCES users(id)
        );
        """)

        # Migration: ensure dek_hex column exists if table was previously created
        try:
            cursor.execute("ALTER TABLE documents ADD COLUMN dek_hex TEXT")
        except Exception:
            pass


        # 3. Document Authorizations
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS document_authorizations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id TEXT NOT NULL,
            recipient_id TEXT NOT NULL,
            authorized_by TEXT NOT NULL,
            granted_at TEXT NOT NULL,
            UNIQUE(document_id, recipient_id),
            FOREIGN KEY (document_id) REFERENCES documents(document_id),
            FOREIGN KEY (recipient_id) REFERENCES users(id),
            FOREIGN KEY (authorized_by) REFERENCES users(id)
        );
        """)

        # 4. Decryption Sessions
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS decryption_sessions (
            session_id TEXT PRIMARY KEY,
            document_id TEXT NOT NULL,
            recipient_id TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            document_hash TEXT,
            watermark_id TEXT,
            fingerprinted_filename TEXT,
            status TEXT NOT NULL CHECK(status IN ('STARTED', 'COMPLETED', 'FAILED')),
            FOREIGN KEY (document_id) REFERENCES documents(document_id),
            FOREIGN KEY (recipient_id) REFERENCES users(id)
        );
        """)

        # 5. Watermarks
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS watermarks (
            watermark_id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            recipient_id TEXT NOT NULL,
            document_id TEXT NOT NULL,
            payload_signature TEXT,
            embedded_at TEXT NOT NULL,
            FOREIGN KEY (session_id) REFERENCES decryption_sessions(session_id),
            FOREIGN KEY (recipient_id) REFERENCES users(id),
            FOREIGN KEY (document_id) REFERENCES documents(document_id)
        );
        """)

        # 6. Provenance Events
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS provenance_events (
            event_id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            document_id TEXT NOT NULL,
            recipient_id TEXT NOT NULL,
            document_hash TEXT NOT NULL,
            watermark_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            canonical_payload TEXT NOT NULL,
            signature TEXT NOT NULL,
            algorithm TEXT NOT NULL,
            public_key_ref TEXT NOT NULL,
            FOREIGN KEY (session_id) REFERENCES decryption_sessions(session_id),
            FOREIGN KEY (recipient_id) REFERENCES users(id),
            FOREIGN KEY (document_id) REFERENCES documents(document_id)
        );
        """)

        # 7. Ledger Blocks
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS ledger_blocks (
            block_index INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            previous_block_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL,
            event_id TEXT NOT NULL,
            watermark_id TEXT NOT NULL,
            signature TEXT NOT NULL,
            current_block_hash TEXT NOT NULL
        );
        """)

        # 8. Investigations
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS investigations (
            case_id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            extracted_watermark_id TEXT,
            matched_event_id TEXT,
            matched_recipient_id TEXT,
            matched_session_id TEXT,
            matched_document_id TEXT,
            watermark_matched INTEGER NOT NULL DEFAULT 0,
            signature_valid INTEGER NOT NULL DEFAULT 0,
            document_hash_match INTEGER NOT NULL DEFAULT 0,
            ledger_valid INTEGER NOT NULL DEFAULT 0,
            attribution_status TEXT NOT NULL,
            investigated_at TEXT NOT NULL,
            report_filename TEXT
        );
        """)

        # 9. Distributed Copies (Persistent Fingerprint -> Employee Provenance Mapping)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS distributed_copies (
            fingerprint TEXT PRIMARY KEY,
            document_id TEXT NOT NULL,
            copy_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            username TEXT NOT NULL,
            employee_name TEXT NOT NULL,
            downloaded_at TEXT NOT NULL,
            action TEXT NOT NULL DEFAULT 'DECRYPT_AND_DOWNLOAD',
            document_name TEXT NOT NULL,
            document_hash TEXT NOT NULL,
            provenance_event_id TEXT,
            ledger_block_index INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (document_id) REFERENCES documents(document_id)
        );
        """)

        # 10. Account Action Audits (Part 21 Investigator Action Log)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS account_action_audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigator_id TEXT NOT NULL,
            investigator_username TEXT NOT NULL,
            target_user_id TEXT NOT NULL,
            target_username TEXT NOT NULL,
            action TEXT NOT NULL,
            previous_status TEXT NOT NULL,
            new_status TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            investigation_id TEXT,
            fingerprint_id TEXT
        );
        """)

        # 11. Warning & Investigation Notices (Part 2 & 3)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS warning_notices (
            notice_id TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            recipient_id TEXT NOT NULL,
            recipient_name TEXT NOT NULL,
            recipient_username TEXT,
            document_id TEXT NOT NULL,
            document_name TEXT NOT NULL,
            fingerprint_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            issued_by TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'SENT' CHECK(status IN ('SENT', 'READ', 'ACKNOWLEDGED', 'REPLIED', 'PENDING', 'CLOSED')),
            subject TEXT NOT NULL,
            notice_body TEXT NOT NULL,
            read_at TEXT,
            reply_text TEXT,
            replied_at TEXT,
            reply_by TEXT,
            FOREIGN KEY (investigation_id) REFERENCES investigations(case_id),
            FOREIGN KEY (recipient_id) REFERENCES users(id),
            FOREIGN KEY (document_id) REFERENCES documents(document_id)
        );
        """)

        # Migration: ensure warning_notices table has read_at, reply_text, replied_at, reply_by and accepts READ/REPLIED status
        cursor.execute("PRAGMA table_info(warning_notices);")
        wn_cols = [row["name"] for row in cursor.fetchall()]
        cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='warning_notices';")
        wn_sql_row = cursor.fetchone()
        wn_sql = wn_sql_row["sql"] if wn_sql_row else ""
        if "read_at" not in wn_cols or "'READ'" not in wn_sql or "'REPLIED'" not in wn_sql:
            cursor.execute("PRAGMA foreign_keys = OFF;")
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS warning_notices_new (
                notice_id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                recipient_id TEXT NOT NULL,
                recipient_name TEXT NOT NULL,
                recipient_username TEXT,
                document_id TEXT NOT NULL,
                document_name TEXT NOT NULL,
                fingerprint_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                issued_by TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'SENT' CHECK(status IN ('SENT', 'READ', 'ACKNOWLEDGED', 'REPLIED', 'PENDING', 'CLOSED')),
                subject TEXT NOT NULL,
                notice_body TEXT NOT NULL,
                read_at TEXT,
                reply_text TEXT,
                replied_at TEXT,
                reply_by TEXT,
                FOREIGN KEY (investigation_id) REFERENCES investigations(case_id),
                FOREIGN KEY (recipient_id) REFERENCES users(id),
                FOREIGN KEY (document_id) REFERENCES documents(document_id)
            );
            """)
            has_read_at = "read_at" in wn_cols
            has_reply_text = "reply_text" in wn_cols
            read_at_expr = "read_at" if has_read_at else "NULL"
            reply_text_expr = "reply_text" if has_reply_text else "NULL"
            replied_at_expr = "replied_at" if "replied_at" in wn_cols else "NULL"
            reply_by_expr = "reply_by" if "reply_by" in wn_cols else "NULL"
            cursor.execute(f"""
            INSERT INTO warning_notices_new (
                notice_id, investigation_id, recipient_id, recipient_name, recipient_username,
                document_id, document_name, fingerprint_id, created_at, issued_by,
                status, subject, notice_body, read_at, reply_text, replied_at, reply_by
            )
            SELECT 
                notice_id, investigation_id, recipient_id, recipient_name, recipient_username,
                document_id, document_name, fingerprint_id, created_at, issued_by,
                status, subject, notice_body, {read_at_expr}, {reply_text_expr}, {replied_at_expr}, {reply_by_expr}
            FROM warning_notices;
            """)
            cursor.execute("DROP TABLE warning_notices;")
            cursor.execute("ALTER TABLE warning_notices_new RENAME TO warning_notices;")
            cursor.execute("PRAGMA foreign_keys = ON;")

        # Migration: ensure warning_id, issuer_id, issuer_role, recipient_role, reason, message, issued_at, ledger_block_index, ledger_event_id exist in warning_notices
        cursor.execute("PRAGMA table_info(warning_notices);")
        wn_info_cols = [row["name"] for row in cursor.fetchall()]
        wn_new_columns = [
            ("warning_id", "TEXT"),
            ("issuer_id", "TEXT"),
            ("issuer_role", "TEXT"),
            ("recipient_role", "TEXT DEFAULT 'AUTHORISED_PERSONNEL'"),
            ("reason", "TEXT"),
            ("message", "TEXT"),
            ("issued_at", "TEXT"),
            ("ledger_block_index", "INTEGER"),
            ("ledger_event_id", "TEXT"),
        ]
        for col_name, col_def in wn_new_columns:
            if col_name not in wn_info_cols:
                cursor.execute(f"ALTER TABLE warning_notices ADD COLUMN {col_name} {col_def};")

        # Backfill warning fields for existing records
        cursor.execute("""
        UPDATE warning_notices
        SET warning_id = COALESCE(warning_id, notice_id),
            reason = COALESCE(reason, subject),
            message = COALESCE(message, notice_body),
            issued_at = COALESCE(issued_at, created_at),
            recipient_role = COALESCE(recipient_role, 'AUTHORISED_PERSONNEL'),
            issuer_role = COALESCE(issuer_role, 'INVESTIGATOR')
        WHERE warning_id IS NULL OR reason IS NULL OR message IS NULL OR issued_at IS NULL;
        """)

        # Migration: ensure status and kem_public_key columns exist in users
        cursor.execute("PRAGMA table_info(users);")
        user_cols = [row["name"] for row in cursor.fetchall()]
        if "status" not in user_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'ACTIVE';")
        if "kem_public_key" not in user_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN kem_public_key TEXT;")

        # Migration: ensure encapsulated_key, read_at, interaction_status exist in document_authorizations
        cursor.execute("PRAGMA table_info(document_authorizations);")
        auth_cols = [row["name"] for row in cursor.fetchall()]
        if "encapsulated_key" not in auth_cols:
            cursor.execute("ALTER TABLE document_authorizations ADD COLUMN encapsulated_key TEXT;")
        if "read_at" not in auth_cols:
            cursor.execute("ALTER TABLE document_authorizations ADD COLUMN read_at TEXT;")
        if "interaction_status" not in auth_cols:
            cursor.execute("ALTER TABLE document_authorizations ADD COLUMN interaction_status TEXT DEFAULT 'RECEIVED';")

        # Migration: ensure DLT permissioned blockchain columns exist in ledger_blocks
        cursor.execute("PRAGMA table_info(ledger_blocks);")
        lb_cols = [row["name"] for row in cursor.fetchall()]
        if "merkle_root" not in lb_cols:
            cursor.execute("ALTER TABLE ledger_blocks ADD COLUMN merkle_root TEXT;")
        if "transactions" not in lb_cols:
            cursor.execute("ALTER TABLE ledger_blocks ADD COLUMN transactions TEXT;")
        if "validator_id" not in lb_cols:
            cursor.execute("ALTER TABLE ledger_blocks ADD COLUMN validator_id TEXT;")
        if "validator_signatures" not in lb_cols:
            cursor.execute("ALTER TABLE ledger_blocks ADD COLUMN validator_signatures TEXT;")

        # Migration: ensure role, fingerprint_hash, signature exist in distributed_copies
        cursor.execute("PRAGMA table_info(distributed_copies);")
        dc_cols = [row["name"] for row in cursor.fetchall()]
        if "role" not in dc_cols:
            cursor.execute("ALTER TABLE distributed_copies ADD COLUMN role TEXT DEFAULT 'Employee';")
        if "fingerprint_hash" not in dc_cols:
            cursor.execute("ALTER TABLE distributed_copies ADD COLUMN fingerprint_hash TEXT;")
        if "signature" not in dc_cols:
            cursor.execute("ALTER TABLE distributed_copies ADD COLUMN signature TEXT;")

        # Migration: ensure action_id and ledger_record_id exist in account_action_audits
        cursor.execute("PRAGMA table_info(account_action_audits);")
        audit_cols = [row["name"] for row in cursor.fetchall()]
        if "action_id" not in audit_cols:
            cursor.execute("ALTER TABLE account_action_audits ADD COLUMN action_id TEXT;")
        if "ledger_record_id" not in audit_cols:
            cursor.execute("ALTER TABLE account_action_audits ADD COLUMN ledger_record_id TEXT;")

        # Sync existing decryption sessions into distributed_copies
        cursor.execute("""
        INSERT OR IGNORE INTO distributed_copies (
            fingerprint, document_id, copy_id, user_id, username, employee_name,
            downloaded_at, action, document_name, document_hash, provenance_event_id, ledger_block_index
        )
        SELECT 
            ds.watermark_id,
            ds.document_id,
            ds.session_id,
            ds.recipient_id,
            COALESCE(u.username, 'unknown'),
            COALESCE(u.display_name, 'Unknown Employee'),
            COALESCE(ds.completed_at, ds.started_at),
            'DECRYPT_AND_DOWNLOAD',
            COALESCE(d.original_filename, 'Confidential Document'),
            COALESCE(ds.document_hash, ''),
            pe.event_id,
            lb.block_index
        FROM decryption_sessions ds
        LEFT JOIN users u ON ds.recipient_id = u.id
        LEFT JOIN documents d ON ds.document_id = d.document_id
        LEFT JOIN provenance_events pe ON ds.session_id = pe.session_id
        LEFT JOIN ledger_blocks lb ON ds.watermark_id = lb.watermark_id
        WHERE ds.watermark_id IS NOT NULL;
        """)

        # Normalize warning_notices.recipient_id to internal account ID
        cursor.execute("""
        UPDATE warning_notices
        SET recipient_id = (SELECT id FROM users WHERE users.username = warning_notices.recipient_id COLLATE NOCASE)
        WHERE recipient_id IN (SELECT username FROM users);
        """)

        # Normalize investigations.matched_recipient_id to internal account ID
        cursor.execute("""
        UPDATE investigations
        SET matched_recipient_id = (SELECT id FROM users WHERE users.username = investigations.matched_recipient_id COLLATE NOCASE)
        WHERE matched_recipient_id IN (SELECT username FROM users);
        """)

        # Ensure active/demo encrypted documents dataset remains <= 100
        cursor.execute("SELECT COUNT(*) as cnt FROM documents")
        doc_count_row = cursor.fetchone()
        if doc_count_row and doc_count_row["cnt"] > 100:
            cursor.execute("SELECT DISTINCT document_id FROM warning_notices WHERE document_id IS NOT NULL")
            wn_docs = {r["document_id"] for r in cursor.fetchall()}
            cursor.execute("SELECT DISTINCT matched_document_id FROM investigations WHERE matched_document_id IS NOT NULL")
            inv_docs = {r["matched_document_id"] for r in cursor.fetchall()}
            cursor.execute("SELECT document_id FROM documents ORDER BY created_at DESC LIMIT 60")
            recent_docs = {r["document_id"] for r in cursor.fetchall()}
            keep_doc_ids = wn_docs | inv_docs | recent_docs
            placeholders = ",".join(["?"] * len(keep_doc_ids))
            keep_list = list(keep_doc_ids)

            cursor.execute(f"DELETE FROM recipient_signatures WHERE document_id NOT IN ({placeholders})", keep_list)
            cursor.execute(f"DELETE FROM distributed_copies WHERE document_id NOT IN ({placeholders})", keep_list)
            cursor.execute(f"DELETE FROM provenance_events WHERE document_id NOT IN ({placeholders})", keep_list)
            cursor.execute(f"DELETE FROM watermarks WHERE document_id NOT IN ({placeholders})", keep_list)
            cursor.execute(f"DELETE FROM decryption_sessions WHERE document_id NOT IN ({placeholders})", keep_list)
            cursor.execute(f"DELETE FROM document_authorizations WHERE document_id NOT IN ({placeholders})", keep_list)
            cursor.execute(f"DELETE FROM documents WHERE document_id NOT IN ({placeholders})", keep_list)

        # 12. Recipient Digital Signatures (DSA + SHA-256)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS recipient_signatures (
            signature_id TEXT PRIMARY KEY,
            recipient_id TEXT NOT NULL,
            recipient_username TEXT,
            recipient_name TEXT,
            document_id TEXT NOT NULL,
            document_name TEXT,
            document_hash TEXT NOT NULL,
            document_version TEXT NOT NULL DEFAULT 'v1.0',
            signature_algorithm TEXT NOT NULL DEFAULT 'DSA-SHA256',
            signature_value TEXT NOT NULL,
            public_key_pem TEXT NOT NULL,
            canonical_payload TEXT NOT NULL,
            signed_at TEXT NOT NULL,
            verification_status TEXT NOT NULL DEFAULT 'VERIFIED',
            acknowledgement_action TEXT NOT NULL DEFAULT 'ACKNOWLEDGE',
            ledger_block_index INTEGER,
            FOREIGN KEY (document_id) REFERENCES documents(document_id),
            FOREIGN KEY (recipient_id) REFERENCES users(id)
        );
        """)

        # Migration: ensure users table has dsa_public_key
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN dsa_public_key TEXT")
        except Exception:
            pass


