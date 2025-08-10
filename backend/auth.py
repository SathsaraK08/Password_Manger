"""Authentication dependencies and helper functions.

This module encapsulates logic for registering users, verifying
credentials, issuing tokens and retrieving the current user from
incoming requests. It uses JWT bearer tokens and enforces role‑based
authorization.
"""

from datetime import datetime
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from .database import SessionLocal
from . import models, schemas
from .utils import verify_password, get_password_hash, create_access_token, decode_access_token


# OAuth2 bearer token extraction. Clients must send the JWT in an
# Authorization header: `Authorization: Bearer <token>`.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_db():
    """Provide a database session for dependency injection."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_user_by_username(db: Session, username: str) -> Optional[models.User]:
    return db.query(models.User).filter(models.User.username == username).first()


def create_user(db: Session, user: schemas.UserCreate) -> models.User:
    # Hash the user's password before storing
    hashed_password = get_password_hash(user.password)
    db_user = models.User(username=user.username, hashed_password=hashed_password, role=user.role)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def authenticate_user(db: Session, username: str, password: str) -> Optional[models.User]:
    user = get_user_by_username(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user


async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> models.User:
    """Retrieve the current user from the provided JWT bearer token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_access_token(token)
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None:
            raise credentials_exception
    except Exception:
        raise credentials_exception
    user = get_user_by_username(db, username)
    if user is None:
        raise credentials_exception
    return user


def admin_required(current_user: models.User = Depends(get_current_user)) -> models.User:
    """Verify that the current user has admin privileges."""
    if current_user.role != models.UserRole.ADMIN.value:
        raise HTTPException(status_code=403, detail="Insufficient privileges")
    return current_user