"""Utility functions for encryption, hashing and JWT handling.

This module centralizes cryptographic utilities used throughout the
application including AES‑256 encryption of passwords, password hashing
with bcrypt and JWT token creation/verification.

Notes:
  * The AES key must be a 32‑byte value supplied via the AES_KEY
    environment variable encoded in base64. A new random initialization
    vector (IV) is generated for each encryption and prepended to the
    ciphertext. The final encrypted payload is base64 encoded for
    storage in the database.

  * Passwords are hashed using passlib's bcrypt hasher which salts
    automatically and has a work factor suitable for modern hardware.
"""

import os
import base64
from datetime import datetime, timedelta
from typing import Optional

from pathlib import Path
from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env")
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from jose import jwt, JWTError
from passlib.context import CryptContext


# Password hashing context; bcrypt automatically includes a salt. Increasing
# the "rounds" parameter increases the work factor and security but may slow
# down login. The default of 12 rounds strikes a reasonable balance.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Retrieve the AES key from the environment and decode it from base64. If the
# key is missing or invalid a runtime error will be raised.
def get_aes_key() -> bytes:
    key_b64 = os.environ.get("AES_KEY")
    if not key_b64:
        raise RuntimeError("AES_KEY environment variable is not set")
    try:
        key = base64.b64decode(key_b64)
    except Exception as exc:
        raise RuntimeError("AES_KEY must be base64 encoded") from exc
    if len(key) != 32:
        raise RuntimeError("AES_KEY must decode to 32 bytes for AES‑256")
    return key


def encrypt_password(plain_password: str, key: bytes) -> str:
    """Encrypt a plaintext password using AES‑256 in CBC mode.

    Args:
        plain_password: The password in plain text.
        key: A 32‑byte AES key.

    Returns:
        Base64 encoded string containing IV + ciphertext.
    """
    # Generate a random 16‑byte IV for CBC mode.
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    # Pad the plaintext to a multiple of the block size.
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plain_password.encode("utf-8")) + padder.finalize()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ct).decode("utf-8")


def decrypt_password(token: str, key: bytes) -> str:
    """Decrypt an AES‑256 encrypted password.

    Args:
        token: The base64 encoded IV + ciphertext string from the database.
        key: The AES key used for decryption.

    Returns:
        Decrypted plain text password.
    """
    data = base64.b64decode(token)
    iv = data[:16]
    ct = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plain = decryptor.update(ct) + decryptor.finalize()
    # Remove PKCS7 padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plain = unpadder.update(padded_plain) + unpadder.finalize()
    return plain.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Check a plain password against its hashed version."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a plain password with bcrypt."""
    return pwd_context.hash(password)


# JWT token management. The SECRET_KEY and ALGORITHM are read from
# environment variables and used to sign and verify tokens.
SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-secret-key")
ALGORITHM = os.environ.get("ALGORITHM", "HS256")


def create_access_token(data: dict, expires_delta: Optional[int] = None) -> str:
    """Create a JWT access token.

    Args:
        data: A dictionary of claims to include in the token.
        expires_delta: Minutes until the token expires.

    Returns:
        Encoded JWT string.
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expires_delta or int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", 60)))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Decode a JWT token and return the payload.

    Raises JWTError if decoding or verification fails.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError as exc:
        # Re-raise with a clear message for callers to handle
        raise JWTError(str(exc))