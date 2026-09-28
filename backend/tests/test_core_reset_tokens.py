"""Unit tests for password-reset token generation and hashing.

The token utility is pure cryptography: no database, no network, and no
FastAPI. These tests pin the two properties the rest of the password-reset flow
depends on: generated tokens are unguessable and unique, and the stored digest
is a deterministic one-way SHA-256 hash of the raw token.
"""

# ruff: noqa: E402

import hashlib
import secrets
import string
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.reset_tokens import (
    TOKEN_HASH_LENGTH,
    generate_password_reset_token,
    hash_password_reset_token,
)

_URL_SAFE_ALPHABET = set(string.ascii_letters + string.digits + "-_")


class GeneratePasswordResetTokenTests(unittest.TestCase):
    """Generation of raw password-reset tokens."""

    def test_generated_token_is_non_empty(self) -> None:
        """A generated token is a non-empty string."""
        token = generate_password_reset_token()

        self.assertIsInstance(token, str)
        self.assertTrue(token)

    def test_generated_token_is_long_enough_to_be_unguessable(self) -> None:
        """A token carries 256 bits of entropy, i.e. at least 32 random bytes.

        ``secrets.token_urlsafe(32)`` produces 43 base64url characters. The
        bound is asserted rather than the exact length so a future increase in
        entropy does not break the test, but a reduction below 32 bytes would.
        """
        token = generate_password_reset_token()

        self.assertGreaterEqual(len(token), 43)

    def test_generated_token_is_url_safe(self) -> None:
        """A token contains only URL-safe base64 characters.

        The value can therefore be embedded in a reset link without escaping.
        """
        token = generate_password_reset_token()

        self.assertTrue(set(token) <= _URL_SAFE_ALPHABET)

    def test_two_generated_tokens_differ(self) -> None:
        """Two consecutive tokens are never equal."""
        tokens = {generate_password_reset_token() for _ in range(100)}

        self.assertEqual(len(tokens), 100)

    def test_generated_token_does_not_encode_predictable_inputs(self) -> None:
        """A token is not a UUID, email, or timestamp in another encoding.

        Guards against the token ever being derived from data an attacker
        already knows about the account.
        """
        token = generate_password_reset_token()

        self.assertNotEqual(len(token), 36)  # not a UUID string
        self.assertNotIn("@", token)  # not an email address
        self.assertNotIn(":", token)  # not a timestamp

    def test_generation_uses_the_secrets_module(self) -> None:
        """Tokens come from the OS CSPRNG exposed by ``secrets``.

        ``secrets.token_urlsafe`` is itself backed by ``secrets.SystemRandom``,
        so patching ``secrets.token_urlsafe`` proves the utility delegates to it
        rather than to the non-cryptographic ``random`` module.
        """
        original = secrets.token_urlsafe
        try:
            secrets.token_urlsafe = lambda n: "patched-token"  # type: ignore[assignment]
            self.assertEqual(generate_password_reset_token(), "patched-token")
        finally:
            secrets.token_urlsafe = original  # type: ignore[assignment]


class HashPasswordResetTokenTests(unittest.TestCase):
    """Deterministic hashing of raw password-reset tokens."""

    def test_hash_is_deterministic(self) -> None:
        """The same raw token always produces the same digest."""
        token = generate_password_reset_token()

        self.assertEqual(hash_password_reset_token(token), hash_password_reset_token(token))

    def test_hash_matches_sha256_of_the_raw_token(self) -> None:
        """The digest is exactly SHA-256 of the UTF-8 encoded token.

        Pinned to SHA-256 so an accidental change of algorithm, which would
        silently invalidate every outstanding reset link, fails the suite.
        """
        token = generate_password_reset_token()

        expected = hashlib.sha256(token.encode("utf-8")).hexdigest()

        self.assertEqual(hash_password_reset_token(token), expected)

    def test_hash_is_lowercase_hex_of_the_expected_length(self) -> None:
        """The stored digest is a 64-character lowercase hex string."""
        digest = hash_password_reset_token(generate_password_reset_token())

        self.assertEqual(len(digest), TOKEN_HASH_LENGTH)
        self.assertEqual(len(digest), 64)
        self.assertTrue(all(character in string.hexdigits for character in digest))
        self.assertEqual(digest, digest.lower())

    def test_hash_is_not_equal_to_the_raw_token(self) -> None:
        """The digest never equals the raw token, so the raw value is not stored."""
        token = generate_password_reset_token()

        self.assertNotEqual(hash_password_reset_token(token), token)

    def test_different_tokens_hash_differently(self) -> None:
        """Distinct tokens never collide under the digest."""
        digests = {hash_password_reset_token(generate_password_reset_token()) for _ in range(100)}

        self.assertEqual(len(digests), 100)

    def test_hash_is_one_way(self) -> None:
        """The raw token cannot be recovered from its digest."""
        token = generate_password_reset_token()

        self.assertNotIn(token, hash_password_reset_token(token))

    def test_unicode_token_is_hashed_consistently(self) -> None:
        """A non-ASCII token hashes deterministically over its UTF-8 bytes."""
        token = "tökén-with-ünicode-\u00e9\u00e8"

        self.assertEqual(hash_password_reset_token(token), hash_password_reset_token(token))
        self.assertEqual(
            hash_password_reset_token(token),
            hashlib.sha256(token.encode("utf-8")).hexdigest(),
        )

    def test_empty_token_is_rejected(self) -> None:
        """An empty token is a caller error and raises rather than hashing."""
        with self.assertRaises(ValueError):
            hash_password_reset_token("")


if __name__ == "__main__":
    unittest.main()
