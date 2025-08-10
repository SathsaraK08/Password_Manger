"""FastAPI application entry point.

This module defines the REST API for the password vault. It exposes
endpoints for user registration and login, credential management,
user administration and audit log retrieval. The API uses JWT bearer
authentication and enforces role-based access control.
"""

from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, status, Query, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from . import models, schemas, crud, auth, utils
from .database import Base, engine

# ------- DB init -------
Base.metadata.create_all(bind=engine)

# ------- App -------
app = FastAPI(
    title="Secure Password Vault",
    description="A simple internal password vault with AES-256 encryption and role-based access control.",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://[::1]:5500",   # <— add this for IPv6 localhost
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# ----------------------------
# Public /auth endpoints
# ----------------------------
auth_router = APIRouter(prefix="/auth")

@auth_router.post("/register", response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED)
def register(user: schemas.UserCreate, db: Session = Depends(auth.get_db)):
    """
    Public registration.
    - Anyone can self-register (default role 'member').
    - Blocking self-registration as 'admin'; promotion happens via admin endpoint later.
    """
    existing = auth.get_user_by_username(db, user.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already registered")

    if user.role == models.UserRole.ADMIN.value:
        # prevent creating admin via public register
        raise HTTPException(status_code=403, detail="Only admins can create admin users")

    db_user = auth.create_user(db, user)
    return db_user


@auth_router.post("/login", response_model=schemas.Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(auth.get_db)):
    """Authenticate a user and return a JWT access token."""
    user = auth.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = utils.create_access_token(data={"sub": user.username, "role": user.role})
    return schemas.Token(access_token=access_token, token_type="bearer")

app.include_router(auth_router)

# ----------------------------
# Users (admin only)
# ----------------------------
@app.get("/users", response_model=List[schemas.UserResponse])
def list_users(current_user: models.User = Depends(auth.admin_required), db: Session = Depends(auth.get_db)):
    return crud.list_users(db)

@app.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: int, current_user: models.User = Depends(auth.admin_required), db: Session = Depends(auth.get_db)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    crud.delete_user(db, user)
    return None

# ----------------------------
# Credentials
# ----------------------------
@app.get("/credentials", response_model=List[schemas.CredentialResponse])
def read_credentials(
    search: Optional[str] = Query(None, description="Search term to filter credentials"),
    owner_id: Optional[int] = Query(None, description="Filter credentials by owner ID (admin only)"),
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(auth.get_db),
):
    if owner_id is not None:
        if current_user.role != models.UserRole.ADMIN.value:
            raise HTTPException(status_code=403, detail="Only admin can filter by owner_id")
        target_user_id = owner_id
    else:
        target_user_id = current_user.id
    return crud.get_credentials(db, target_user_id, search)

@app.post("/credentials", response_model=schemas.CredentialResponse, status_code=status.HTTP_201_CREATED)
def create_credential(
    credential: schemas.CredentialCreate,
    owner_id: Optional[int] = Query(None, description="Owner ID for admin to create credential on behalf of user"),
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(auth.get_db),
):
    aes_key = utils.get_aes_key()
    if owner_id is not None:
        if current_user.role != models.UserRole.ADMIN.value:
            raise HTTPException(status_code=403, detail="Only admin can specify owner_id")
        owner = db.query(models.User).filter(models.User.id == owner_id).first()
        if not owner:
            raise HTTPException(status_code=404, detail="Owner user not found")
        target_user_id = owner.id
    else:
        target_user_id = current_user.id

    cred = crud.create_credential(db, target_user_id, credential, aes_key)
    crud.create_audit_log(db, current_user.id, "create", cred.id)
    return cred

@app.get("/credentials/{credential_id}", response_model=schemas.CredentialResponse)
def read_credential(
    credential_id: int,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(auth.get_db),
):
    cred = crud.get_credential(db, credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    if cred.owner_id != current_user.id and current_user.role != models.UserRole.ADMIN.value:
        raise HTTPException(status_code=403, detail="Not authorized to view this credential")
    crud.create_audit_log(db, current_user.id, "view", cred.id)
    return cred

@app.put("/credentials/{credential_id}", response_model=schemas.CredentialResponse)
def update_credential(
    credential_id: int,
    updates: schemas.CredentialUpdate,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(auth.get_db),
):
    if current_user.role != models.UserRole.ADMIN.value:
        raise HTTPException(status_code=403, detail="Only admin may update credentials")
    cred = crud.get_credential(db, credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    aes_key = utils.get_aes_key()
    updated = crud.update_credential(db, cred, updates, aes_key)
    crud.create_audit_log(db, current_user.id, "edit", cred.id)
    return updated

@app.delete("/credentials/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_credential(
    credential_id: int,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(auth.get_db),
):
    if current_user.role != models.UserRole.ADMIN.value:
        raise HTTPException(status_code=403, detail="Only admin may delete credentials")
    cred = crud.get_credential(db, credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    crud.delete_credential(db, cred)
    crud.create_audit_log(db, current_user.id, "delete", credential_id)
    return None

# ----------------------------
# Audit (admin)
# ----------------------------
@app.get("/auditlogs", response_model=List[schemas.AuditLogResponse])
def get_audit_logs(current_user: models.User = Depends(auth.admin_required), db: Session = Depends(auth.get_db)):
    return crud.list_audit_logs(db)

# (Optional) Friendly root/health
@app.get("/")
def root():
    return {"ok": True, "message": "Password Vault API running. See /docs"}

@app.get("/health")
def health():
    return {"status": "healthy"}
"""FastAPI application entry point.

Exposes REST API for:
  - Auth (/auth): register (public) & login
  - Users (admin)
  - Credentials (member/admin)
  - Audit logs (admin)

CORS is configured for localhost dev (including IPv6 [::1]).
"""

from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, status, Query, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from . import models, schemas, crud, auth, utils
from .database import Base, engine, get_db

# ------- DB init -------
Base.metadata.create_all(bind=engine)

# ------- App -------
app = FastAPI(
    title="Secure Password Vault",
    description="A simple internal password vault with AES-256 encryption and role-based access control.",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)
origins = [
    "http://localhost:8080",
    "http://127.0.0.1:8080",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://[::1]:5500",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------------
# Public /auth endpoints
# ----------------------------
auth_router = APIRouter(prefix="/auth", tags=["auth"])

@auth_router.post("/register", response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """
    Public registration.
    - Anyone can self-register (default role 'member').
    - Self-register as 'admin' is blocked; promotion happens via admin.
    """
    existing = auth.get_user_by_username(db, user.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already registered")

    if user.role == models.UserRole.ADMIN.value:
        # prevent creating admin via public register
        raise HTTPException(status_code=403, detail="Only admins can create admin users")

    db_user = auth.create_user(db, user)
    return db_user


@auth_router.post("/login", response_model=schemas.Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Authenticate a user and return a JWT access token."""
    user = auth.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = utils.create_access_token(data={"sub": user.username, "role": user.role})
    return schemas.Token(access_token=access_token, token_type="bearer")

app.include_router(auth_router)

# ----------------------------
# Users (admin only)
# ----------------------------
@app.get("/users", response_model=List[schemas.UserResponse], tags=["users"])
def list_users(current_user: models.User = Depends(auth.admin_required), db: Session = Depends(get_db)):
    return crud.list_users(db)

@app.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["users"])
def delete_user(user_id: int, current_user: models.User = Depends(auth.admin_required), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    crud.delete_user(db, user)
    return None

# ----------------------------
# Credentials
# ----------------------------
@app.get("/credentials", response_model=List[schemas.CredentialResponse], tags=["credentials"])
def read_credentials(
    search: Optional[str] = Query(None, description="Search term to filter credentials"),
    owner_id: Optional[int] = Query(None, description="Filter credentials by owner ID (admin only)"),
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    if owner_id is not None:
        if current_user.role != models.UserRole.ADMIN.value:
            raise HTTPException(status_code=403, detail="Only admin can filter by owner_id")
        target_user_id = owner_id
    else:
        target_user_id = current_user.id
    return crud.get_credentials(db, target_user_id, search)

@app.post("/credentials", response_model=schemas.CredentialResponse, status_code=status.HTTP_201_CREATED, tags=["credentials"])
def create_credential(
    credential: schemas.CredentialCreate,
    owner_id: Optional[int] = Query(None, description="Owner ID for admin to create credential on behalf of user"),
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    aes_key = utils.get_aes_key()
    if owner_id is not None:
        if current_user.role != models.UserRole.ADMIN.value:
            raise HTTPException(status_code=403, detail="Only admin can specify owner_id")
        owner = db.query(models.User).filter(models.User.id == owner_id).first()
        if not owner:
            raise HTTPException(status_code=404, detail="Owner user not found")
        target_user_id = owner.id
    else:
        target_user_id = current_user.id

    cred = crud.create_credential(db, target_user_id, credential, aes_key)
    crud.create_audit_log(db, current_user.id, "create", cred.id)
    return cred

@app.get("/credentials/{credential_id}", response_model=schemas.CredentialResponse, tags=["credentials"])
def read_credential(
    credential_id: int,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    cred = crud.get_credential(db, credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    if cred.owner_id != current_user.id and current_user.role != models.UserRole.ADMIN.value:
        raise HTTPException(status_code=403, detail="Not authorized to view this credential")
    crud.create_audit_log(db, current_user.id, "view", cred.id)
    return cred

@app.put("/credentials/{credential_id}", response_model=schemas.CredentialResponse, tags=["credentials"])
def update_credential(
    credential_id: int,
    updates: schemas.CredentialUpdate,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.role != models.UserRole.ADMIN.value:
        raise HTTPException(status_code=403, detail="Only admin may update credentials")
    cred = crud.get_credential(db, credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    aes_key = utils.get_aes_key()
    updated = crud.update_credential(db, cred, updates, aes_key)
    crud.create_audit_log(db, current_user.id, "edit", cred.id)
    return updated

@app.delete("/credentials/{credential_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["credentials"])
def delete_credential(
    credential_id: int,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.role != models.UserRole.ADMIN.value:
        raise HTTPException(status_code=403, detail="Only admin may delete credentials")
    cred = crud.get_credential(db, credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    crud.delete_credential(db, cred)
    crud.create_audit_log(db, current_user.id, "delete", credential_id)
    return None

# ----------------------------
# Audit (admin)
# ----------------------------
@app.get("/auditlogs", response_model=List[schemas.AuditLogResponse], tags=["audit"])
def get_audit_logs(current_user: models.User = Depends(auth.admin_required), db: Session = Depends(get_db)):
    return crud.list_audit_logs(db)

# (Optional) Friendly root/health
@app.get("/")
def root():
    return {"ok": True, "message": "Password Vault API running. See /docs"}

@app.get("/health")
def health():
    return {"status": "healthy"}