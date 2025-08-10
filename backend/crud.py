"""CRUD operations for database models.

Functions defined here encapsulate common patterns for creating,
retrieving, updating and deleting objects from the database. Using
dedicated functions helps isolate database access and makes the
application easier to maintain and test.
"""

from typing import List, Optional

from sqlalchemy.orm import Session
from sqlalchemy import or_, and_

from . import models, schemas, utils


def create_credential(db: Session, owner_id: int, credential: schemas.CredentialCreate, aes_key: bytes) -> models.Credential:
    """Create a new credential for a user.

    The password is encrypted using the provided AES key before
    persisting to the database.
    """
    encrypted_password = utils.encrypt_password(credential.password_plain, aes_key)
    db_cred = models.Credential(
        site_name=credential.site_name,
        username=credential.username,
        encrypted_password=encrypted_password,
        notes=credential.notes,
        owner_id=owner_id,
    )
    db.add(db_cred)
    db.commit()
    db.refresh(db_cred)
    return db_cred


def get_credentials(db: Session, owner_id: int, search: Optional[str] = None) -> List[models.Credential]:
    """Retrieve a list of credentials for a user optionally filtered by search."""
    query = db.query(models.Credential).filter(models.Credential.owner_id == owner_id)
    if search:
        like_term = f"%{search}%"
        query = query.filter(
            or_(
                models.Credential.site_name.ilike(like_term),
                models.Credential.username.ilike(like_term),
                models.Credential.notes.ilike(like_term),
            )
        )
    return query.order_by(models.Credential.created_at.desc()).all()


def get_credential(db: Session, credential_id: int) -> Optional[models.Credential]:
    return db.query(models.Credential).filter(models.Credential.id == credential_id).first()


def update_credential(db: Session, credential: models.Credential, updates: schemas.CredentialUpdate, aes_key: bytes) -> models.Credential:
    """Update credential fields. When a new password is provided it is encrypted."""
    if updates.site_name is not None:
        credential.site_name = updates.site_name
    if updates.username is not None:
        credential.username = updates.username
    if updates.password_plain is not None:
        credential.encrypted_password = utils.encrypt_password(updates.password_plain, aes_key)
    if updates.notes is not None:
        credential.notes = updates.notes
    from datetime import datetime
    credential.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(credential)
    return credential


def delete_credential(db: Session, credential: models.Credential) -> None:
    """Remove a credential from the database."""
    db.delete(credential)
    db.commit()


def list_users(db: Session) -> List[models.User]:
    return db.query(models.User).order_by(models.User.created_at).all()


def delete_user(db: Session, user: models.User) -> None:
    db.delete(user)
    db.commit()


def list_audit_logs(db: Session) -> List[models.AuditLog]:
    return db.query(models.AuditLog).order_by(models.AuditLog.timestamp.desc()).all()


def create_audit_log(db: Session, user_id: int, action: str, credential_id: Optional[int] = None) -> models.AuditLog:
    log = models.AuditLog(user_id=user_id, action=action, credential_id=credential_id)
    db.add(log)
    db.commit()
    db.refresh(log)
    return log