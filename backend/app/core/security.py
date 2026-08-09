"""Password hashing and verification utilities for FinPilot.

All password hashing is delegated to bcrypt. Passwords are never stored or
logged in plaintext, and password hashes are never exposed through the API.
This module is intentionally independent of FastAPI routes, database models,
repositories, and services.
"""

from __future__ import annotations

import bcrypt

_BCRYPT_MAX_PASSWORD_BYTES = 72


def hash_password(password: str) -> str:
    """Return a bcrypt hash of the given plaintext password.

    Args:
        password: Plaintext password to hash. Must be a non-empty string of
            at most 72 UTF-8 bytes (bcrypt's supported input limit).

    Returns:
        The bcrypt hash as a string.

    Raises:
        ValueError: If the password is empty or exceeds 72 UTF-8 bytes.
    """
    _validate_password(password)
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    return hashed.decode("utf-8")


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Return whether the plaintext password matches the given bcrypt hash.

    Empty or malformed inputs never raise and simply produce False.

    Args:
        plain_password: Plaintext password to check.
        password_hash: Bcrypt hash produced by hash_password.

    Returns:
        True if the password matches the hash, False otherwise.
    """
    if not plain_password or not password_hash:
        return False
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            password_hash.encode("utf-8"),
        )
    except ValueError:
        return False


def _validate_password(password: str) -> None:
    """Validate that a password is acceptable for bcrypt hashing.

    Args:
        password: Plaintext password to validate.

    Raises:
        ValueError: If the password is empty or longer than bcrypt's 72-byte
            input limit.
    """
    if not password:
        raise ValueError("password must not be empty")
    if len(password.encode("utf-8")) > _BCRYPT_MAX_PASSWORD_BYTES:
        raise ValueError(f"password must not exceed {_BCRYPT_MAX_PASSWORD_BYTES} UTF-8 bytes")
