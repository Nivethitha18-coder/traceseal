"""
TraceSeal Main Application
Cryptographically Verifiable Document Leak Attribution
FastAPI Backend Server & Local Static Frontend Host.
"""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path

from backend.config import STATIC_DIR, ensure_directories, PQC_ENABLED
from backend.database import init_db
from backend.ledger.ledger import OfflineLedger
from backend.demo import initialize_demo_environment

from typing import List, Optional
from backend.auth.service import require_roles, get_current_user
from backend.schemas import (
    UserLogin,
    TokenResponse,
    DocumentDeleteResponse,
    WarningNoticeCreate,
    WarningNoticeOut,
    WarningNoticeStatusUpdate,
    WarningNoticeReply,
    AccountActionAuditOut,
)

from backend.auth.routes import (
    router as auth_router,
    login as auth_login_endpoint,
    get_user_activity_endpoint as activity_endpoint,
)
from backend.documents.routes import router as documents_router, delete_document_endpoint
from backend.watermark.routes import router as watermark_router
from backend.provenance.routes import router as provenance_router
from backend.ledger.routes import router as ledger_router
from backend.forensic.routes import (
    router as forensic_router,
    issue_warning_notice as notice_send_endpoint,
    list_warning_notices as notice_list_endpoint,
    get_warning_notice as notice_get_endpoint,
    update_warning_notice_status as notice_update_endpoint,
    mark_warning_notice_read as notice_read_endpoint,
    reply_to_warning_notice_endpoint as notice_reply_endpoint,
    download_warning_notice_pdf as notice_download_endpoint,
)
from backend.crypto.routes import router as crypto_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle startup and shutdown logic."""
    ensure_directories()
    init_db()
    OfflineLedger.initialize_ledger()
    initialize_demo_environment()
    yield


# Immediate initialization for offline CLI and test runners
ensure_directories()
init_db()
OfflineLedger.initialize_ledger()
initialize_demo_environment()


app = FastAPI(
    title="TraceSeal - Cryptographic Document Leak Attribution",
    description=(
        "Offline-First Document Provenance and Forensic Leak Attribution System. "
        "SIH Problem Statement SIH26237. Implements AES-256-GCM encryption, "
        "NIST FIPS 204 ML-DSA post-quantum signatures, imperceptible forensic watermarking, "
        "and an offline tamper-evident hash-chained provenance ledger."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Enable CORS for deployed frontend and local development
_allowed_origins_env = os.getenv("ALLOWED_ORIGINS", "")
if _allowed_origins_env and _allowed_origins_env.strip() != "*":
    cors_origins = [orig.strip() for orig in _allowed_origins_env.split(",") if orig.strip()]
else:
    cors_origins = [
        "https://traceseal-1.onrender.com",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins if _allowed_origins_env.strip() != "*" else ["*"],
    allow_origin_regex=r"^https://.*\.onrender\.com$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=[
        "Content-Disposition",
        "X-Session-ID",
        "X-Watermark-ID",
        "X-Fingerprint-ID",
        "X-Fingerprint-Hash",
        "X-Event-ID",
        "X-Block-Index",
        "X-Timestamp",
        "X-Recipient-ID",
        "X-Recipient-Username",
        "X-Recipient-Name",
        "X-Document-ID",
        "X-Document-Name",
        "X-Document-Hash",
        "X-Original-Hash",
        "X-Document-Version",
        "X-Decryption-Status",
        "X-Watermark-Status",
        "X-Method",
    ],
)

# Include All Modular API Routers
app.include_router(auth_router)
app.include_router(documents_router)
app.include_router(watermark_router)
app.include_router(provenance_router)
app.include_router(ledger_router)
app.include_router(forensic_router)
app.include_router(crypto_router)

# Mount Frontend Static Assets
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# Direct HTML page routes
@app.get("/", include_in_schema=False)
def serve_home():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/login", include_in_schema=False)
def serve_login():
    return FileResponse(STATIC_DIR / "login.html")


@app.get("/admin", include_in_schema=False)
def serve_admin():
    return FileResponse(STATIC_DIR / "admin.html")


@app.get("/recipient", include_in_schema=False)
def serve_recipient():
    return FileResponse(STATIC_DIR / "recipient.html")


@app.get("/investigator", include_in_schema=False)
def serve_investigator():
    return FileResponse(STATIC_DIR / "investigator.html")


@app.get("/ledger-view", include_in_schema=False)
def serve_ledger():
    return FileResponse(STATIC_DIR / "ledger.html")


# PWA Manifest & Service Worker Routes
@app.get("/manifest.json", include_in_schema=False)
@app.get("/manifest.webmanifest", include_in_schema=False)
def serve_manifest():
    return FileResponse(
        STATIC_DIR / "manifest.json",
        media_type="application/manifest+json",
        headers={"Cache-Control": "public, max-age=3600"}
    )


@app.get("/sw.js", include_in_schema=False)
def serve_sw():
    return FileResponse(
        STATIC_DIR / "sw.js",
        media_type="application/javascript",
        headers={
            "Service-Worker-Allowed": "/",
            "Cache-Control": "no-cache, no-store, must-revalidate"
        }
    )


@app.get("/favicon.ico", include_in_schema=False)
def serve_favicon():
    fav_file = STATIC_DIR / "favicon.ico"
    if fav_file.exists():
        return FileResponse(fav_file, media_type="image/x-icon")
    return FileResponse(STATIC_DIR / "icons" / "favicon.png", media_type="image/png")


# Direct Route Aliases ensuring consistent URL paths
@app.post("/auth/login", response_model=TokenResponse, tags=["Authentication & User Management"], include_in_schema=False)
@app.post("/login", response_model=TokenResponse, tags=["Authentication & User Management"], include_in_schema=False)
def direct_login_route(login_data: UserLogin):
    """Direct root login alias forwarding to canonical /api/auth/login."""
    return auth_login_endpoint(login_data)


@app.delete("/documents/{document_id}", response_model=DocumentDeleteResponse, tags=["Document Management & Decryption"], include_in_schema=False)
@app.post("/documents/{document_id}/delete", response_model=DocumentDeleteResponse, tags=["Document Management & Decryption"], include_in_schema=False)
def direct_delete_document_route(
    document_id: str,
    current_user: dict = Depends(require_roles(["ADMIN"])),
):
    """Direct root document delete alias forwarding to canonical /api/documents/{document_id}."""
    return delete_document_endpoint(document_id, current_user)


@app.post("/api/notices/send", response_model=WarningNoticeOut, tags=["Forensic Investigation & Attribution"], include_in_schema=False)
@app.post("/api/notices", response_model=WarningNoticeOut, tags=["Forensic Investigation & Attribution"], include_in_schema=False)
@app.post("/forensics/notices/send", response_model=WarningNoticeOut, tags=["Forensic Investigation & Attribution"], include_in_schema=False)
@app.post("/forensics/notices", response_model=WarningNoticeOut, tags=["Forensic Investigation & Attribution"], include_in_schema=False)
def direct_notice_send_route(
    payload: WarningNoticeCreate,
    current_user: dict = Depends(require_roles(["ADMIN", "INVESTIGATOR"])),
):
    """Direct root notice alias forwarding to canonical /api/forensics/notices/send."""
    return notice_send_endpoint(payload, current_user)


@app.get("/notices/my", response_model=List[WarningNoticeOut], tags=["Forensic Investigation & Attribution"], include_in_schema=False)
@app.get("/api/notices/my", response_model=List[WarningNoticeOut], tags=["Forensic Investigation & Attribution"], include_in_schema=False)
@app.get("/forensics/notices/my", response_model=List[WarningNoticeOut], tags=["Forensic Investigation & Attribution"], include_in_schema=False)
@app.get("/api/recipient/notices", response_model=List[WarningNoticeOut], tags=["Forensic Investigation & Attribution"], include_in_schema=False)
def direct_my_notices_route(current_user: dict = Depends(get_current_user)):
    """Direct alias to fetch recipient's own warning notices."""
    from backend.forensic.notice_service import NoticeService
    return NoticeService.list_warning_notices(recipient_id=current_user["id"])


@app.get("/notices/issued", response_model=List[WarningNoticeOut], tags=["Forensic Investigation & Attribution"], include_in_schema=False)
@app.get("/api/notices/issued", response_model=List[WarningNoticeOut], tags=["Forensic Investigation & Attribution"], include_in_schema=False)
@app.get("/forensics/notices/issued", response_model=List[WarningNoticeOut], tags=["Forensic Investigation & Attribution"], include_in_schema=False)
@app.get("/api/forensics/notices/issued", response_model=List[WarningNoticeOut], tags=["Forensic Investigation & Attribution"], include_in_schema=False)
def direct_issued_notices_route(current_user: dict = Depends(require_roles(["ADMIN", "INVESTIGATOR"]))):
    """Direct alias to fetch notices issued by current authenticated authorised person."""
    from backend.forensic.notice_service import NoticeService
    issuer = current_user.get("username") or current_user.get("id")
    return NoticeService.list_warning_notices(issued_by=issuer)


@app.get("/api/notices", response_model=List[WarningNoticeOut], tags=["Forensic Investigation & Attribution"], include_in_schema=False)
@app.get("/notices", response_model=List[WarningNoticeOut], tags=["Forensic Investigation & Attribution"], include_in_schema=False)
def direct_notices_list_route(
    recipient_id: Optional[str] = None,
    investigation_id: Optional[str] = None,
    issued_by: Optional[str] = None,
    all: bool = False,
    current_user: dict = Depends(get_current_user),
):
    """Direct alias for listing warning notices."""
    return notice_list_endpoint(
        recipient_id=recipient_id,
        investigation_id=investigation_id,
        issued_by=issued_by,
        all=all,
        current_user=current_user,
    )


@app.get("/api/notices/{notice_id}", response_model=WarningNoticeOut, tags=["Forensic Investigation & Attribution"], include_in_schema=False)
@app.get("/notices/{notice_id}", response_model=WarningNoticeOut, tags=["Forensic Investigation & Attribution"], include_in_schema=False)
@app.get("/forensics/notices/{notice_id}", response_model=WarningNoticeOut, tags=["Forensic Investigation & Attribution"], include_in_schema=False)
def direct_notice_get_route(
    notice_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Direct alias for getting single warning notice."""
    return notice_get_endpoint(notice_id=notice_id, current_user=current_user)


@app.patch("/api/notices/{notice_id}/status", response_model=WarningNoticeOut, tags=["Forensic Investigation & Attribution"], include_in_schema=False)
@app.patch("/forensics/notices/{notice_id}/status", response_model=WarningNoticeOut, tags=["Forensic Investigation & Attribution"], include_in_schema=False)
@app.post("/api/notices/{notice_id}/acknowledge", response_model=WarningNoticeOut, tags=["Forensic Investigation & Attribution"], include_in_schema=False)
@app.post("/forensics/notices/{notice_id}/acknowledge", response_model=WarningNoticeOut, tags=["Forensic Investigation & Attribution"], include_in_schema=False)
@app.post("/notices/{notice_id}/acknowledge", response_model=WarningNoticeOut, tags=["Forensic Investigation & Attribution"], include_in_schema=False)
def direct_notice_update_route(
    notice_id: str,
    payload: Optional[WarningNoticeStatusUpdate] = None,
    current_user: dict = Depends(get_current_user),
):
    """Direct alias for updating/acknowledging warning notice."""
    return notice_update_endpoint(notice_id=notice_id, payload=payload, current_user=current_user)


@app.get("/api/notices/{notice_id}/download", tags=["Forensic Investigation & Attribution"], include_in_schema=False)
@app.get("/forensics/notices/{notice_id}/download", tags=["Forensic Investigation & Attribution"], include_in_schema=False)
@app.get("/notices/{notice_id}/download", tags=["Forensic Investigation & Attribution"], include_in_schema=False)
def direct_notice_download_route(
    notice_id: str,
    token: Optional[str] = None,
    authorization: Optional[str] = Header(None),
):
    """Direct alias for downloading notice PDF."""
    return notice_download_endpoint(notice_id=notice_id, token=token, authorization=authorization)


@app.post("/api/notices/{notice_id}/read", response_model=WarningNoticeOut, tags=["Forensic Investigation & Attribution"], include_in_schema=False)
@app.post("/forensics/notices/{notice_id}/read", response_model=WarningNoticeOut, tags=["Forensic Investigation & Attribution"], include_in_schema=False)
@app.post("/notices/{notice_id}/read", response_model=WarningNoticeOut, tags=["Forensic Investigation & Attribution"], include_in_schema=False)
def direct_notice_read_route(
    notice_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Direct alias for marking notice as read."""
    return notice_read_endpoint(notice_id=notice_id, current_user=current_user)


@app.post("/api/notices/{notice_id}/reply", response_model=WarningNoticeOut, tags=["Forensic Investigation & Attribution"], include_in_schema=False)
@app.post("/forensics/notices/{notice_id}/reply", response_model=WarningNoticeOut, tags=["Forensic Investigation & Attribution"], include_in_schema=False)
@app.post("/notices/{notice_id}/reply", response_model=WarningNoticeOut, tags=["Forensic Investigation & Attribution"], include_in_schema=False)
def direct_notice_reply_route(
    notice_id: str,
    payload: WarningNoticeReply,
    current_user: dict = Depends(get_current_user),
):
    """Direct alias for replying to a notice."""
    return notice_reply_endpoint(notice_id=notice_id, payload=payload, current_user=current_user)


@app.get("/api/recipient/activity", response_model=List[AccountActionAuditOut], tags=["Authentication & User Management"], include_in_schema=False)
@app.get("/recipient/activity", response_model=List[AccountActionAuditOut], tags=["Authentication & User Management"], include_in_schema=False)
@app.get("/api/account-audits", response_model=List[AccountActionAuditOut], tags=["Authentication & User Management"], include_in_schema=False)
@app.get("/account-audits", response_model=List[AccountActionAuditOut], tags=["Authentication & User Management"], include_in_schema=False)
def direct_recipient_activity_route(
    limit: int = 100,
    current_user: dict = Depends(get_current_user),
):
    """Direct alias for retrieving user-isolated or admin activity audits."""
    return activity_endpoint(limit=limit, current_user=current_user)


# Health check endpoints for Render, Docker, and container orchestrators
@app.get("/health", tags=["System"], include_in_schema=False)
@app.get("/api/health", tags=["System"], include_in_schema=False)
def health_check():
    """Production health check endpoint."""
    return {
        "status": "healthy",
        "service": "TraceSeal",
        "version": "1.0.0",
        "pqc_enabled": PQC_ENABLED,
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    print(f"[TraceSeal] Starting production server on {host}:{port} ...")
    uvicorn.run("backend.main:app", host=host, port=port, reload=False, workers=1)




