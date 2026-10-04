"""
Authentication API Endpoints
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from backend.schemas import (
    UserCreate,
    UserLogin,
    UserOut,
    TokenResponse,
    UserDirectoryOut,
    UserStatusUpdate,
    EmployeeCreateRequest,
    AccessAuditOut,
    AccountActionAuditOut,
)
from backend.database import get_db
from backend.auth.service import (
    AuthService,
    create_access_token,
    get_current_user,
    require_roles,
)

router = APIRouter(prefix="/api", tags=["Authentication & User Management"])


@router.get("/auth/directory", response_model=List[UserDirectoryOut])
def get_auth_directory(role: Optional[str] = None):
    """
    Public directory of registered accounts for role-based account selection on the login page.
    Excludes removed accounts. No passwords or tokens exposed.
    """
    return AuthService.get_directory_users(role=role)


@router.post("/auth/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(user_data: UserCreate):
    """Register a new user (ADMIN, RECIPIENT, or INVESTIGATOR)."""
    user = AuthService.register_user(
        username=user_data.username,
        password=user_data.password,
        display_name=user_data.display_name,
        role=user_data.role,
    )
    return user


@router.post("/auth/login", response_model=TokenResponse)
@router.post("/login", response_model=TokenResponse, include_in_schema=False)
def login(login_data: UserLogin):
    """Authenticate and receive a JWT token for offline session access with strict role validation."""
    user = AuthService.authenticate_user(
        username=login_data.username,
        password=login_data.password,
        user_id=login_data.user_id,
    )

    # Enforce strict backend role validation when logging in via a role-specific portal
    if login_data.required_role:
        req = login_data.required_role.strip().upper()
        if req in ("EMPLOYEE", "MEMBER", "AUTHORISED_PERSONNEL", "AUTHORIZED_PERSONNEL", "AUTHORISED PERSONNEL", "AUTHORIZED PERSONNEL", "AUTHORISED_PERSON", "AUTHORIZED_PERSON"):
            req = "RECIPIENT"

        if user["role"] != req:
            role_labels = {
                "ADMIN": "Administrator",
                "INVESTIGATOR": "Investigator",
                "RECIPIENT": "Authorised Personnel",
            }
            portal_name = role_labels.get(req, req)
            actual_role_name = role_labels.get(user["role"], user["role"])
            print(f"[AUTH_AUDIT] Role Mismatch: Required={req}, Actual={user['role']} -> 403 Forbidden")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: This login portal is restricted to {portal_name} accounts only. Your account is registered as a {actual_role_name}."
            )

    token = create_access_token({"sub": user["id"], "role": user["role"], "username": user["username"]})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "display_name": user["display_name"],
            "role": user["role"],
            "created_at": user["created_at"],
            "active": bool(user["active"]),
            "status": user.get("status", "ACTIVE"),
            "public_key": user.get("public_key"),
        },
    }


@router.get("/auth/me", response_model=UserOut)
def get_me(current_user: dict = Depends(get_current_user)):
    """Get current authenticated user profile."""
    return current_user


@router.get("/users", response_model=List[UserOut])
def get_users(
    role: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    """List registered users (filtered by role optionally)."""
    users = AuthService.get_all_users(role=role)
    return users


@router.post("/users/employee", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_employee_endpoint(
    req: EmployeeCreateRequest,
    current_user: dict = Depends(require_roles(["ADMIN"])),
):
    """ADMIN only: Register a new employee with password confirmation."""
    if req.confirm_password and req.password != req.confirm_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Passwords do not match.")
    if len(req.password) < 4:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password must be at least 4 characters long.")

    user = AuthService.register_user(
        username=req.username.strip().lower(),
        password=req.password,
        display_name=req.name.strip(),
        role="RECIPIENT",
    )
    return user


@router.patch("/users/{user_id}/status")
def update_user_status_endpoint(
    user_id: str,
    req: UserStatusUpdate,
    current_user: dict = Depends(require_roles(["ADMIN", "INVESTIGATOR"])),
):
    """ADMIN OR INVESTIGATOR: Suspend, Block, Blacklist, Deactivate, Remove, or Reactivate an employee account."""
    res = AuthService.update_user_status(
        user_id=user_id,
        new_status=req.status,
        actor=current_user,
        investigation_id=req.investigation_id,
        fingerprint_id=req.fingerprint_id,
    )
    return res


@router.delete("/users/{user_id}")
def remove_or_deactivate_user_endpoint(
    user_id: str,
    action: Optional[str] = Query(None),
    current_user: dict = Depends(require_roles(["ADMIN", "INVESTIGATOR"])),
):
    """ADMIN OR INVESTIGATOR: Deactivate or Remove an employee (safely revokes document access and preserves evidence)."""
    if action and action.upper() == "REMOVE":
        return AuthService.remove_user(user_id=user_id, actor=current_user)
    return AuthService.deactivate_user(user_id=user_id, actor=current_user)


@router.get("/investigator/account-audits", response_model=List[AccountActionAuditOut])
@router.get("/admin/account-audits", response_model=List[AccountActionAuditOut])
def get_account_action_audits_endpoint(
    limit: int = 100,
    current_user: dict = Depends(require_roles(["ADMIN", "INVESTIGATOR"])),
):
    """ADMIN OR INVESTIGATOR: Audit log of employee account security actions taken by investigators or administrators."""
    return AuthService.get_account_action_audits(limit=limit)


@router.get("/recipient/activity", response_model=List[AccountActionAuditOut])
@router.get("/account-audits", response_model=List[AccountActionAuditOut])
def get_user_activity_endpoint(
    limit: int = 100,
    current_user: dict = Depends(get_current_user),
):
    """
    Activity and audit endpoint with strict ownership isolation:
    - Authorized Personnel (RECIPIENT/EMPLOYEE): retrieves ONLY own account actions.
    - ADMIN and INVESTIGATOR: retrieves full system audit history.
    """
    norm_role = current_user.get("role", "").upper()
    if norm_role in ("RECIPIENT", "EMPLOYEE", "AUTHORIZED_PERSONNEL", "MEMBER"):
        return AuthService.get_account_action_audits(limit=limit, target_user_id=current_user["id"])
    return AuthService.get_account_action_audits(limit=limit)


@router.get("/admin/access-investigation", response_model=List[AccessAuditOut])
def get_access_investigation_endpoint(
    current_user: dict = Depends(require_roles(["ADMIN"])),
):
    """ADMIN only: Document security and decryption access investigation events."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                ds.session_id,
                ds.document_id,
                d.original_filename AS document_name,
                ds.recipient_id AS user_id,
                u.display_name AS user_name,
                u.username,
                COALESCE(u.status, 'ACTIVE') AS user_status,
                COALESCE(ds.completed_at, ds.started_at) AS timestamp,
                'Decrypt & Download' AS action,
                ds.watermark_id,
                pe.event_id AS provenance_id,
                ds.status
            FROM decryption_sessions ds
            LEFT JOIN documents d ON ds.document_id = d.document_id
            LEFT JOIN users u ON ds.recipient_id = u.id
            LEFT JOIN provenance_events pe ON ds.session_id = pe.session_id
            ORDER BY ds.started_at DESC
        """)
        rows = cursor.fetchall()
        return [
            {
                "session_id": r["session_id"],
                "document_id": r["document_id"],
                "document_name": r["document_name"] or "Unknown Document",
                "user_id": r["user_id"],
                "user_name": r["user_name"] or "Unknown User",
                "username": r["username"] or "unknown",
                "user_status": r["user_status"],
                "timestamp": r["timestamp"],
                "action": r["action"],
                "watermark_id": r["watermark_id"],
                "provenance_id": r["provenance_id"],
                "status": r["status"]
            }
            for r in rows
        ]


@router.get("/users/{user_id}", response_model=UserOut)
def get_user(
    user_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Retrieve specific user profile."""
    user = AuthService.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user
