from typing import Optional, List, Literal
from datetime import datetime

from pydantic import BaseModel, Field, ConfigDict, EmailStr


# ------------------------
# Auth / Tokens
# ------------------------

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ------------------------
# Users
# ------------------------

class UserBase(BaseModel):
    username: str
    email: Optional[EmailStr] = None
    # Pydantic v2-friendly: restrict role to fixed values
    role: Literal["admin", "member"] = "member"

class UserCreate(UserBase):
    # Store plaintext only on create; server will hash with bcrypt
    password: str = Field(..., min_length=8)

class UserLogin(BaseModel):
    username: str
    password: str

class UserOut(BaseModel):
    id: int
    username: str
    email: Optional[EmailStr] = None
    role: Literal["admin", "member"]

    # Pydantic v2 replacement for orm_mode=True
    model_config = ConfigDict(from_attributes=True)


# ------------------------
# Credentials (Vault items)
# ------------------------

class CredentialCreate(BaseModel):
    # allow receiving "password" as an alias for "password_plain"
    model_config = ConfigDict(populate_by_name=True)

    site_name: str
    username: str
    password_plain: str = Field(..., validation_alias='password')
    notes: Optional[str] = None

class CredentialUpdate(BaseModel):
    site_name: Optional[str] = None
    username: Optional[str] = None
    password_plain: Optional[str] = None
    notes: Optional[str] = None

class CredentialOut(BaseModel):
    id: int
    site_name: str
    username: str
    # We return encrypted value to the UI (not plaintext)
    encrypted_password: str
    notes: Optional[str]
    owner_id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


# ------------------------
# Audit Log
# ------------------------

class AuditLogOut(BaseModel):
    id: int
    user_id: int
    action: str
    resource_type: str
    resource_id: Optional[int]
    timestamp: datetime
    details: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

# --- Backwards-compatible aliases for main.py ---
UserResponse = UserOut
CredentialResponse = CredentialOut
AuditLogResponse = AuditLogOut