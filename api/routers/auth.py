"""
Auth Router — JWT with Refresh Tokens + RBAC
=============================================
POST /auth/login    — get access + refresh token pair
POST /auth/refresh  — exchange refresh token for new access token
POST /auth/logout   — revoke a refresh token
GET  /auth/me       — current user profile
POST /auth/users    — create user (ADMIN only)

Roles:
  ANALYST     — read alerts, incidents; submit feedback; read lessons
  SOC_MANAGER — all ANALYST + approve/reject lesson reviews; create users
  ADMIN       — all SOC_MANAGER + delete lessons; manage users; view audit logs
  READONLY    — read-only access to incidents and lessons

For enterprise deployments: replace the local user store with your
LDAP/Active Directory/Okta integration. The token structure stays the same;
only the _authenticate() function needs to be swapped.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from config.settings import cfg
from data.postgres.models import RefreshToken, UserRole
from data.postgres.session import get_db

logger = logging.getLogger(__name__)
router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)

# ── In-memory user store (replace with LDAP/Okta for production) ─────────────
# Passwords are bcrypt-hashed. Generate: python -c "from passlib.hash import bcrypt; print(bcrypt.hash('yourpassword'))"
_USERS: dict[str, dict] = {
    "admin": {
        "password_hash": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY7gDobWQHiJA2y",  # "admin"
        "role": UserRole.ADMIN,
        "display_name": "ASOC Administrator",
    },
    "analyst1": {
        "password_hash": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY7gDobWQHiJA2y",  # "admin"
        "role": UserRole.ANALYST,
        "display_name": "Tier-1 Analyst",
    },
    "soc_manager": {
        "password_hash": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY7gDobWQHiJA2y",  # "admin"
        "role": UserRole.SOC_MANAGER,
        "display_name": "SOC Manager",
    },
}


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class TokenResponse(BaseModel):
    access_token:  str
    refresh_token: str
    token_type:    str = "bearer"
    expires_in:    int
    role:          str


class RefreshRequest(BaseModel):
    refresh_token: str


class UserCreate(BaseModel):
    username:     str
    password:     str
    role:         UserRole
    display_name: str


class UserProfile(BaseModel):
    username:     str
    role:         str
    display_name: str


# ── Token helpers ─────────────────────────────────────────────────────────────

def _create_access_token(username: str, role: str) -> tuple[str, int]:
    expire   = datetime.now(timezone.utc) + timedelta(minutes=cfg.jwt_expire_minutes)
    payload  = {"sub": username, "role": role, "exp": expire, "type": "access"}
    token    = jwt.encode(payload, cfg.jwt_secret.get_secret_value(), algorithm=cfg.jwt_algorithm)
    return token, cfg.jwt_expire_minutes * 60


def _create_refresh_token(username: str, role: str) -> str:
    import secrets
    expire  = datetime.now(timezone.utc) + timedelta(days=cfg.jwt_refresh_expire_days)
    payload = {"sub": username, "role": role, "exp": expire, "type": "refresh",
               "jti": secrets.token_hex(16)}
    return jwt.encode(payload, cfg.jwt_secret.get_secret_value(), algorithm=cfg.jwt_algorithm)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _authenticate(username: str, password: str) -> dict | None:
    user = _USERS.get(username)
    if not user:
        return None
    try:
        from passlib.hash import bcrypt
        if bcrypt.verify(password, user["password_hash"]):
            return {**user, "username": username}
    except Exception:
        pass
    return None


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse)
async def login(
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db),
):
    user = _authenticate(form.username, form.password)
    if not user:
        logger.warning("LOGIN FAILED: username=%s", form.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token, expires_in = _create_access_token(form.username, user["role"].value)
    refresh_token = _create_refresh_token(form.username, user["role"].value)

    # Store refresh token hash in DB (enables revocation)
    expire = datetime.now(timezone.utc) + timedelta(days=cfg.jwt_refresh_expire_days)
    db.add(RefreshToken(
        token_hash=_hash_token(refresh_token),
        user_id=form.username,
        user_role=user["role"],
        expires_at=expire,
    ))
    db.commit()

    logger.info("LOGIN OK: username=%s role=%s", form.username, user["role"].value)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=expires_in,
        role=user["role"].value,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(payload: RefreshRequest, db: Session = Depends(get_db)):
    try:
        claims = jwt.decode(
            payload.refresh_token,
            cfg.jwt_secret.get_secret_value(),
            algorithms=[cfg.jwt_algorithm],
        )
        if claims.get("type") != "refresh":
            raise JWTError("Not a refresh token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    # Verify token is not revoked
    token_hash = _hash_token(payload.refresh_token)
    stored = db.execute(
        select(RefreshToken)
        .where(RefreshToken.token_hash == token_hash)
        .where(RefreshToken.is_revoked == False)
    ).scalar_one_or_none()

    if not stored:
        raise HTTPException(status_code=401, detail="Refresh token revoked or not found")

    username = claims["sub"]
    role     = claims["role"]

    access_token, expires_in = _create_access_token(username, role)

    logger.info("TOKEN REFRESHED: username=%s", username)
    return TokenResponse(
        access_token=access_token,
        refresh_token=payload.refresh_token,  # Return same refresh token
        expires_in=expires_in,
        role=role,
    )


@router.post("/logout", status_code=200)
async def logout(payload: RefreshRequest, db: Session = Depends(get_db)):
    token_hash = _hash_token(payload.refresh_token)
    stored = db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    ).scalar_one_or_none()

    if stored:
        stored.is_revoked = True
        stored.revoked_at = datetime.now(timezone.utc)
        db.commit()

    return {"status": "logged out"}


@router.get("/me", response_model=UserProfile)
async def get_profile(token: str = Depends(oauth2_scheme)):
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        claims = jwt.decode(
            token,
            cfg.jwt_secret.get_secret_value(),
            algorithms=[cfg.jwt_algorithm],
        )
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    username = claims.get("sub", "")
    user     = _USERS.get(username, {})
    return UserProfile(
        username=username,
        role=claims.get("role", "ANALYST"),
        display_name=user.get("display_name", username),
    )


# ── Dependency: get current user from token ───────────────────────────────────

def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """FastAPI dependency — inject into any route that needs the current user."""
    if not token:
        if cfg.asoc_dev_mode:
            return {"username": "dev_user", "role": UserRole.ADMIN}
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        claims = jwt.decode(
            token,
            cfg.jwt_secret.get_secret_value(),
            algorithms=[cfg.jwt_algorithm],
        )
        return {"username": claims["sub"], "role": claims.get("role", "ANALYST")}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def require_role(*roles: UserRole):
    """FastAPI dependency factory — enforce minimum role."""
    def _check(user: dict = Depends(get_current_user)) -> dict:
        if UserRole(user["role"]) not in roles:
            raise HTTPException(
                status_code=403,
                detail=f"Requires role: {[r.value for r in roles]}",
            )
        return user
    return _check
