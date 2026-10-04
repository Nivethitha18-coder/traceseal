# TRACESEAL

### Cryptographically Verifiable Document Leak Attribution
**Smart India Hackathon Problem Statement SIH26237**  
*Cryptographic Attribution and Immutable Decryption Provenance for Multi-Recipient Encrypted Document Distribution.*

---

## 1. Project Overview

**TraceSeal** is an offline-first document provenance and forensic leak attribution system. It addresses a fundamental vulnerability in enterprise document distribution: when a confidential document is encrypted and distributed to multiple authorized recipients, all recipients decrypt and obtain visually identical copies. If any copy is subsequently leaked, traditional access logs cannot distinguish which recipient generated that specific copy.

TraceSeal guarantees that:
> *"Every decrypted copy looks visually identical to the recipient, but every copy carries a distinct, cryptographically verifiable provenance."*

---

## 2. The Core Problem

When an organization distributes a confidential PDF to Alice, Bob, and Charlie:
1. Sender encrypts the master PDF and distributes it to all three parties.
2. Alice, Bob, and Charlie each decrypt the PDF.
3. All three receive visually identical documents.
4. If an unauthorized copy is discovered in public:
   - Server logs can only confirm that all three had access.
   - Traditional database logs can be manipulated by privileged insiders.
   - Static watermarks are identical across all recipients.
   - It is impossible to prove who leaked that specific copy.

---

## 3. The TraceSeal Solution

TraceSeal solves this through **session-level forensic attribution and immutable provenance**:
1. **Dynamic Session Attribution**: Every decryption request generates a distinct session ID (`S001`, `S002`, etc.) and a random cryptographic watermark identifier (`WM-A72X`, `WM-B42K`).
2. **Imperceptible Multi-Layer Watermarking**: The watermark is embedded into the decrypted PDF without modifying its visible appearance (using PDF rendering mode 3 invisible text, zero-width Unicode steganography, and structural document catalog metadata).
3. **NIST Post-Quantum Digital Signatures**: A canonical provenance event containing `{event_id, session_id, document_id, recipient_id, document_hash, watermark_id, timestamp}` is deterministically serialized and digitally signed using **NIST FIPS 204 (ML-DSA-44 via Dilithium2)**.
4. **Offline Tamper-Evident Ledger**: The signed provenance event is appended as a new block in a sequential SHA-256 hash-chained ledger.
5. **Verifiable Leak Attribution**: When a suspect file is uploaded to the investigator console, TraceSeal extracts the watermark, matches the provenance event, verifies the ML-DSA signature, verifies the document hash, audits the ledger integrity, and outputs **ATTRIBUTION VERIFIED** alongside an evidentiary PDF report.

---

## 4. Architecture & Evidence Chain

```
               [ SENDER / ADMIN ]
                       │
             Uploads confidential.pdf
                       │
          AES-256-GCM Document Encryption
                       │
       ┌───────────────┴───────────────┐
       ▼                               ▼
[ RECIPIENT: ALICE ]          [ RECIPIENT: BOB ]
       │                               │
  Decrypts PDF                    Decrypts PDF
  ├─ Session S001                 ├─ Session S002
  ├─ Watermark WM-A72X            ├─ Watermark WM-B42K
  ├─ ML-DSA Signature             ├─ ML-DSA Signature
  └─ Ledger Block #1              └─ Ledger Block #2
       │                               │
[ Visually Identical ]          [ Visually Identical ]
       │
   (Leaked Copy)
       │
       ▼
 [ INVESTIGATOR CONSOLE ]
       │
 1. Compute Leaked File SHA-256
 2. Extract Forensic Watermark (WM-A72X)
 3. Retrieve Provenance Event (S001 -> Alice)
 4. Verify ML-DSA Digital Signature (PASS)
 5. Verify Document Hash Match (PASS)
 6. Verify Ledger Hash-Chain Integrity (PASS)
       │
 ┌──────────────────────────────┐
 │     ATTRIBUTION VERIFIED     │
 └──────────────────────────────┘
       │
 Generate Official Forensic PDF Report
```

---

## 5. Technology Stack

- **Backend**: Python 3.11+, FastAPI, Uvicorn, SQLite, Pydantic v2
- **Document Processing**: `pypdf`, `reportlab`
- **Authenticated Encryption**: AES-256-GCM (NIST SP 800-38D) via `cryptography`
- **Document Hashing**: SHA-256 (NIST FIPS 180-4)
- **Post-Quantum Cryptography (PQC)**:
  - **ML-DSA-44** (NIST FIPS 204 / Dilithium2) for digital signatures
  - **ML-KEM-768** (NIST FIPS 203) for post-quantum key encapsulation
  - Clean modular fallback to Ed25519 with transparent algorithm reporting
- **Ledger**: Local permissioned hash-chained ledger (`ledger_blocks` SQLite table + append-only `ledger.jsonl`)
- **Frontend**: Clean, responsive cybersecurity dark dashboard (HTML5, CSS3, Vanilla JS)

---

## 6. Directory Structure

```
TraceSeal/
├── backend/
│   ├── main.py              # Application entrypoint & lifespan
│   ├── config.py            # Local storage paths & configurations
│   ├── database.py          # SQLite schema & transaction manager
│   ├── models.py            # Domain data models
│   ├── schemas.py           # Pydantic request/response schemas
│   ├── demo.py              # Pre-seeded test accounts & sample PDF
│   ├── auth/
│   │   ├── routes.py        # /api/auth/register, login, me, users
│   │   └── service.py       # PBKDF2 hashing, JWT & RBAC
│   ├── documents/
│   │   ├── routes.py        # /api/documents upload, authorize, decrypt
│   │   └── service.py       # AES-256-GCM encryption & decryption
│   ├── crypto/
│   │   ├── encryption.py    # AES-GCM cipher & offline KeyManager
│   │   ├── hashing.py       # SHA-256 & canonical JSON serialization
│   │   ├── pqc.py           # NIST ML-DSA-44 & ML-KEM-768 engine
│   │   └── routes.py        # /api/system/status, crypto metrics
│   ├── watermark/
│   │   ├── generator.py     # Random non-attributable WM ID generator
│   │   ├── embedder.py      # Mode 3 & zero-width imperceptible embedder
│   │   ├── extractor.py     # Multi-layer forensic watermark extractor
│   │   └── routes.py        # /api/watermark/create, extract
│   ├── provenance/
│   │   ├── events.py        # Canonical event factory & serializer
│   │   ├── signing.py       # ML-DSA provenance signer
│   │   ├── verification.py  # Provenance signature validator
│   │   └── routes.py        # /api/provenance/sign, verify
│   ├── ledger/
│   │   ├── ledger.py        # Genesis block & hash-chain manager
│   │   ├── verification.py  # Chain integrity recalculation & tamper check
│   │   └── routes.py        # /api/ledger, verify, simulate-tampering
│   ├── forensic/
│   │   ├── investigation.py # Multi-step investigation pipeline
│   │   ├── report.py        # Evidentiary PDF report generator
│   │   └── routes.py        # /api/forensics/investigate, reports
│   └── services/
│       └── storage.py       # Local air-gap filesystem manager
├── frontend/
│   ├── index.html           # Landing page with architecture & overview
│   ├── login.html           # Authentication with quick-role demo buttons
│   ├── admin.html           # Document encryption & audit dashboard
│   ├── recipient.html       # Document decryption & session feedback portal
│   ├── investigator.html    # Leak investigation & attribution console
│   ├── ledger.html          # Immutable ledger explorer & tamper simulator
│   ├── styles.css           # Cybersecurity dark theme stylesheet
│   └── app.js               # Frontend API client & pipeline logic
├── storage/
│   ├── encrypted/           # Encrypted AES-256-GCM ciphertext files
│   ├── decrypted/           # Fingerprinted session PDF copies
│   ├── leaked/              # Uploaded suspect investigation files
│   └── evidence/            # Generated forensic attribution PDF reports
├── ledger_data/             # Immutable JSONL append-only audit trail
├── tests/
│   └── test_traceseal.py    # Automated test suite (100% passing)
├── requirements.txt
├── .env.example
└── README.md
```

---

## 7. Installation & Setup

### Prerequisites
- Python 3.11+ (Tested on Python 3.13)
- Windows / Linux / macOS

### 1. Create Virtual Environment
```bash
python -m venv .venv
```

**Activate Environment:**
- **Windows (PowerShell):**
  ```powershell
  .venv\Scripts\activate
  ```
- **Linux / macOS:**
  ```bash
  source .venv/bin/activate
  ```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run Application
```bash
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

### 4. Access URLs
- **Web Interface**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive API Docs (Swagger)**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Alternative API Docs (ReDoc)**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

---

## 8. Registered Accounts (Pre-Seeded)

The system automatically initializes these demo accounts on startup:

| Username | Password | Role | Description |
| :--- | :--- | :--- | :--- |
| `admin` | `admin123` | **ADMIN** | Security Administrator (Uploads & Encrypts documents, manages employee access) |
| `investigator01` / `investigator` | `investigator123` | **INVESTIGATOR** | Forensic Examiner (Analyzes leaked documents, verifies PQC signatures & ledger) |
| `rithick` | `rithick123` | **EMPLOYEE (RECIPIENT)** | Authorized Employee (Pre-authorized for `Confidential.pdf`) |
| `priya` | `priya123` | **EMPLOYEE (RECIPIENT)** | Authorized Employee (Pre-authorized for `Confidential.pdf`) |
| `arun` | `arun123` | **EMPLOYEE (RECIPIENT)** | Employee (Initially Unauthorized for `Confidential.pdf`) |
| `kavin` | `kavin123` | **EMPLOYEE (RECIPIENT)** | Employee (Initially Unauthorized for `Confidential.pdf`) |

*Admins can also register new employee members dynamically via the Admin Dashboard.*

---

## 9. Live Demonstration Workflow

### Step 1: Account Type Selection & Role-Separated Login
1. Navigate to `/login`.
2. A clean role-selection interface is presented:
   ```
                   TRACESEAL
            Secure Document System

       Select your account type

       [ Administrator ]
       [ Investigator ]
       [ Employee ]
   ```
3. Selecting a role opens the dedicated login portal:
   - **Administrator Login**: Requires Administrator credentials (`admin` / `admin123`) $\rightarrow$ Redirects to **Administrator Dashboard** (`/admin`).
   - **Investigator Login**: Prompts for `Investigator ID / Username` (`investigator01` / `investigator123`) $\rightarrow$ Redirects to **Investigator Dashboard** (`/investigator`).
   - **Employee Login**: Prompts for employee credentials (`rithick`, `priya`, `arun`) $\rightarrow$ Redirects to **Employee Dashboard** (`/recipient`).
4. **Backend Role Validation Enforcement**:
   - If an employee tries to log in through the Administrator portal, the backend rejects the request with `HTTP 403 Forbidden` (`Access denied: This login portal is restricted to Administrator accounts only`).
   - Role separation is strictly verified by the server, not just in frontend views.

### Step 2: Administrator Manages Document Access
1. Sign in as `admin` via the Administrator portal.
2. A sample confidential document (`Confidential.pdf`) is pre-seeded and encrypted with AES-256-GCM.
3. Click **Manage Access** on `Confidential.pdf`.
4. A dynamic modal displays registered employees with checkboxes:
   ```
   [✓] Rithick
   [ ] Arun
   [✓] Priya
   [ ] Kavin
   ```
5. Only `Rithick` and `Priya` are authorized. `Arun` and `Kavin` are unauthorized.
6. The Administrator can download the raw AES-256-GCM encrypted ciphertext via **Encrypted PDF**.

### Step 3: Employee-Specific Document Isolation
1. Sign in as `rithick` via the Employee portal:
   - Header shows: `Welcome, Rithick`.
   - Under **Authorized Documents**, `Confidential.pdf` is visible with status **Authorized**.
   - Rithick clicks **🔓 Decrypt & Download**.
   - System decrypts with AES-256-GCM, generates a unique session ID (`SES-...`) and watermark (`WM-...`), signs the event with **NIST ML-DSA-44**, commits to the ledger, and embeds the watermark imperceptibly.
   - Rithick downloads his unique fingerprinted copy.
2. Sign in as `arun` via the Employee portal:
   - Header shows: `Welcome, Arun`.
   - Arun's dashboard displays: *"No documents currently authorized for your account."*
   - Arun cannot see or decrypt the confidential file.
3. Administrator logs in, opens **Manage Access** on `Confidential.pdf`, checks `[✓] Arun`, and saves:
   - Arun refreshes his dashboard $\rightarrow$ `Confidential.pdf` is now immediately visible and accessible!

### Step 4: Session Uniqueness Guarantee
1. Rithick clicks **Decrypt & Download** again on the same document:
   - The system produces a *new, distinct session ID* and a *new, distinct watermark*.
   - This proves that **session-level provenance** is strictly enforced even for repeated decryptions by the exact same employee.

### Step 5: Leak Investigation & Attribution
1. Sign in as `investigator01` via the Investigator portal.
2. Upload Rithick's downloaded fingerprinted PDF as the suspect file.
3. Click **🔍 Execute Forensic Investigation**.
4. The system executes the full cryptographic attribution pipeline:
   - Extracts the forensic watermark ID.
   - Matches the provenance record and deterministically attributes the leak to **Rithick**.
   - Verifies the **NIST ML-DSA-44 post-quantum digital signature**.
   - Verifies the **SHA-256 document hash**.
   - Audits the **tamper-evident local hash chain**.
   - Displays **ATTRIBUTION VERIFIED ✓**.
5. Click **Download Official Forensic Report (PDF)** to generate the signed evidentiary PDF report.

### Step 6: Tamper-Evident Ledger Integrity Audit
1. Navigate to `/ledger-view`.
2. Click **🛡️ Verify Ledger Integrity** $\rightarrow$ verifies sequential SHA-256 hash chains from Genesis block to latest block (**VALID ✓**).
3. Under *Controlled Presentation Demo*, click **Simulate Tampering** (modifies a recorded block hash/payload).
4. Click **Verify Ledger Integrity** $\rightarrow$ immediately alerts **FAILED ⚠** and pinpoints the corrupted block index.
5. Click **Restore Ledger** $\rightarrow$ re-establishes cryptographic chain integrity.

---

## 10. Cloud Deployment (Render)

TraceSeal is configured and production-ready for deployment on **Render**:
- **GitHub Repository**: `Nivethitha18-coder/traceseal`
- **Branch**: `main`
- **Production URL**: `https://traceseal-1.onrender.com`

TraceSeal operates as a single unified service that serves both the FastAPI REST API and the dark cybersecurity frontend.

### Option A: One-Click Render Blueprint (`render.yaml`)
1. In the Render Dashboard, select **New +** $\rightarrow$ **Blueprint**.
2. Select repository `Nivethitha18-coder/traceseal` on branch `main`.
3. Render automatically provisions the web service from [`render.yaml`](render.yaml):
   - **Runtime**: Python 3.13.0
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `python -m uvicorn backend.main:app --host 0.0.0.0 --port $PORT --workers 1`
   - **Health Check**: `/health` (or `/`)
   - Auto-generated cryptographically secure `TRACESEAL_SECRET` and `TRACESEAL_MASTER_KEY`.

### Option B: Docker Web Service on Render
1. In the Render Dashboard, select **New +** $\rightarrow$ **Web Service**.
2. Connect `Nivethitha18-coder/traceseal` (`main` branch).
3. Set **Runtime** to `Docker` (uses bundled [`Dockerfile`](Dockerfile) and [`start.sh`](start.sh)).
4. Set Environment Variables:
   - `TRACESEAL_SECRET`: *(Generate or paste 32-byte hex key)*
   - `TRACESEAL_MASTER_KEY`: *(Generate or paste 32-byte hex key)*
   - `PQC_ENABLED`: `true`
5. Click **Deploy Web Service**.

---

## 11. Automated Testing

TraceSeal includes an automated test suite verifying all cryptographic and functional requirements:

```bash
pytest -v tests
```

### Verified Test Cases:
1. `test_authentication_and_rbac`: User registration, PBKDF2 password verification, JWT generation, and role authorization.
2. `test_aes_gcm_document_encryption`: 256-bit DEK generation, AES-256-GCM authenticated encryption, decryption, and tamper detection.
3. `test_pqc_ml_dsa_signing_and_verification`: NIST FIPS 204 (ML-DSA-44) keygen, signing, and signature verification.
4. `test_watermark_embed_and_extract`: Imperceptible Mode 3 and zero-width watermark embedding and recovery.
5. `test_ledger_integrity_and_tamper_detection`: Sequential hash chaining, integrity recalculation, tamper detection, and restoration.
6. `test_multi_recipient_session_uniqueness_and_leak_attribution`: End-to-end multi-recipient test proving $S_1 \neq S_2$, $W_1 \neq W_2$, leak investigation attribution, and report generation.
7. `test_unattributed_document_investigation`: Clean/unknown files strictly return `ATTRIBUTION COULD NOT BE VERIFIED`.

---

## 11. Security & Cryptographic Design Principles

### Technical Honesty Guarantee:
- **No Fake PQC**: Real NIST FIPS 204 (ML-DSA-44 via Dilithium2) and NIST FIPS 203 (ML-KEM-768) are implemented. If dependencies are unavailable in an environment, the system falls back to Ed25519 and clearly reports: `Ed25519 (Classical Fallback - NIST ML-DSA unavailable)`.
- **Private Key Isolation**: Private keys are strictly stored server-side in secure local storage (`storage/authority_keys.json`, `storage/key_vault.json`) and are never exposed via APIs.
- **Offline Air-Gap Compliance**: Zero external cloud KMS, public blockchains, or internet telemetry during normal operations.
- **Strict Non-Repudiation**: A recipient is never attributed based on filename or user inputs; attribution strictly requires verified forensic watermark recovery, ML-DSA signature validity, and ledger hash-chain integrity.

---

## 12. Watermarking Design & Limitations

### Multi-Layer Forensic Strategy:
1. **Layer 1: Imperceptible Content Stream**: PDF Rendering Mode 3 (Neither fill nor stroke per PDF 1.7 Spec §9.3.5) injected into the vector content stream.
2. **Layer 2: Zero-Width Unicode Steganography**: Binary-encoded invisible Unicode characters (`\u200B`, `\u200C`) interleaved with stream text.
3. **Layer 3: Structural Document Metadata**: Custom `/TraceSealWatermark` and `/PieceInfo` entries in the PDF catalog dictionary.

### Tested Transformations:
- Copying and renaming the PDF file (100% Resilient)
- Normal PDF rendering across browser viewers, Adobe Acrobat, Foxit, and Preview (100% Resilient)
- Re-opening, annotating, and saving where vector objects are preserved (Resilient)

### Known Limitations:
- Low-DPI optical rasterization (printing to physical paper and re-scanning) strips digital vector streams.
- Adversarial PDF sanitization scripts specifically designed to strip Mode 3 invisible text objects.
- *Future Enhancement*: Dual-domain embedding combining spatial/DCT image frequency watermarking for rasterized documents.

---

## 13. License & Attribution

Developed for **Smart India Hackathon (SIH Problem Statement SIH26237)**.  
Built with technical rigor, offline-first reliability, and real NIST post-quantum cryptography.
