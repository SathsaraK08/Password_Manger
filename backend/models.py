"""SQLAlchemy ORM models for the password vault.

The models define users, credentials stored in the vault and audit log
entries. Relationships between models enable easy navigation between
users and their data.
"""

from datetime import datetime
from enum import Enum

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship

from .database import Base


class UserRole(str, Enum):
    """Enumeration of user roles.

    Admins can manage other users and credentials while members only have
    access to their own credentials. Using a Python `Enum` with string
    values improves type safety and ensures the values are stored as
    strings in the database.
    """

    ADMIN = "admin"
    MEMBER = "member"


class User(Base):
    """A registered user of the password vault.

    Attributes:
        id (int): Primary key identifier.
        username (str): Unique username used for login.
        hashed_password (str): The bcrypt hashed password.
        role (str): User role either 'admin' or 'member'.
        created_at (datetime): When the user was created.
    """

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), default=UserRole.MEMBER.value, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    credentials = relationship("Credential", back_populates="owner", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")


class Credential(Base):
    """A credential entry stored in the vault.

    Attributes:
        id (int): Primary key identifier.
        site_name (str): Descriptive name of the site or service.
        username (str): Username associated with the credential.
        encrypted_password (str): Encrypted password value (base64 encoded).
        notes (str): Optional notes for this credential.
        owner_id (int): Foreign key referencing the owning user.
        created_at (datetime): When the credential was created.
        updated_at (datetime): When the credential was last updated.
    """

    __tablename__ = "credentials"

    id = Column(Integer, primary_key=True, index=True)
    site_name = Column(String(255), nullable=False)
    username = Column(String(255), nullable=False)
    encrypted_password = Column(Text, nullable=False)
    notes = Column(Text, nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationship to user
    owner = relationship("User", back_populates="credentials")

    # Relationship to audit log entries
    audit_logs = relationship("AuditLog", back_populates="credential", cascade="all, delete-orphan")


class AuditLog(Base):
    """An audit log entry recording actions on credentials.

    Attributes:
        id (int): Primary key identifier.
        user_id (int): Foreign key referencing the acting user.
        action (str): Description of the action performed (e.g. 'view', 'edit', 'delete').
        credential_id (int): Foreign key referencing the credential on which the action occurred.
        timestamp (datetime): When the action occurred.
    """

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    action = Column(String(50), nullable=False)
    credential_id = Column(Integer, ForeignKey("credentials.id"), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    user = relationship("User", back_populates="audit_logs")
    credential = relationship("Credential", back_populates="audit_logs")