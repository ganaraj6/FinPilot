"""Secure generation and hashing of password-reset tokens for FinPilot.

Password-reset tokens are deliberately **not** JWTs. They are high-entropy
opaque random strings produced with Python's cryptographically secure ``secrets``
module, and they are unrelated to the access/refresh token architecture in
``app.core.tokens``. Only a deterministic SHA-256 digest of a token is ever
persisted, so a database disclosure does not yield usable reset links. The raw
token exists solely in the caller's memory on its way to the email-delivery
layer, which is implemented in a later step.

This module is intentionally framework independent, mirroring
``app.core.security``: it performs no I/O, touches no database, and knows
nothing about FastAPI routes, repositories, or services. Raw tokens and digests
are never logged.
"""

from __future__ import annotations

import hashlib
import secrets

_TOKEN_BYTES = 32
"""Number of random bytes drawn per token, giving 256 bits of entropy."""

TOKEN_HASH_LENGTH = 64
"""Length of the hex-encoded SHA-256 digest that is stored in the database."""


def generate_password_reset_token() -> str:
    """Return a new cryptographically secure URL-safe password-reset token.

    The token is drawn from ``secrets``, the operating system's CSPRNG, so it
    carries 256 bits of entropy and cannot be predicted, guessed, or derived
    from a user id, email address, or timestamp. The caller owns the raw value:
    it must be delivered to the user and must never be written to the database.

    Returns:
        A URL-safe random string of 43 characters.
    """
    return secrets.token_urlsafe(_TOKEN_BYTES)


def hash_password_reset_token(token: str) -> str:
    """Return the deterministic SHA-256 hex digest of a reset token.

    The digest is deterministic so a submitted token is located by one indexed
    equality lookup on ``token_hash``; no scan over stored tokens is required.
    A fast cryptographic hash is correct here and bcrypt is deliberately not
    reused: reset tokens are generated with high entropy rather than chosen by
    a human, so they are not brute-forceable and do not need bcrypt's
    intentionally expensive, salted work factor. Because the digest is a
    one-way function, the raw token cannot be recovered from the database.

    Args:
        token: The raw reset token exactly as it was delivered to the user.

    Returns:
        The lowercase hexadecimal SHA-256 digest, safe to persist.

    Raises:
        ValueError: If the token is empty, which can never match a stored
            digest and is therefore a caller error rather than a user error.
    """
    if not token:
        raise ValueError("token must not be empty")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
