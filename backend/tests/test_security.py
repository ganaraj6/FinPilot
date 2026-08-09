"""Unit tests for the password security utilities."""

import sys
import unittest
from pathlib import Path

try:
    from app.core.security import hash_password, verify_password
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from app.core.security import hash_password, verify_password


class TestHashPassword(unittest.TestCase):
    """Tests for hash_password."""

    def test_hash_differs_from_plaintext(self) -> None:
        """The produced hash must not equal the plaintext password."""
        hashed = hash_password("s3cr3t-passw0rd!")
        self.assertNotEqual(hashed, "s3cr3t-passw0rd!")
        self.assertNotIn("s3cr3t-passw0rd!", hashed)

    def test_hash_uses_bcrypt_format(self) -> None:
        """The produced hash must be a valid bcrypt hash."""
        hashed = hash_password("s3cr3t-passw0rd!")
        self.assertTrue(hashed.startswith("$2b$"))

    def test_same_password_yields_distinct_hashes(self) -> None:
        """Hashing the same password twice must yield distinct hashes."""
        first = hash_password("s3cr3t-passw0rd!")
        second = hash_password("s3cr3t-passw0rd!")
        self.assertNotEqual(first, second)


class TestVerifyPassword(unittest.TestCase):
    """Tests for verify_password."""

    def test_correct_password_verifies(self) -> None:
        """The matching password must verify successfully."""
        password = "s3cr3t-passw0rd!"
        hashed = hash_password(password)
        self.assertTrue(verify_password(password, hashed))

    def test_incorrect_password_fails_verification(self) -> None:
        """A wrong password must fail verification."""
        hashed = hash_password("correct-password")
        self.assertFalse(verify_password("wrong-password", hashed))


class TestInvalidInputs(unittest.TestCase):
    """Tests for empty and malformed inputs."""

    def test_hash_password_rejects_empty_password(self) -> None:
        """Hashing an empty password must raise ValueError."""
        with self.assertRaises(ValueError):
            hash_password("")

    def test_hash_password_rejects_overlong_password(self) -> None:
        """Hashing a password over 72 UTF-8 bytes must raise ValueError."""
        with self.assertRaises(ValueError):
            hash_password("a" * 73)

    def test_verify_password_rejects_empty_password(self) -> None:
        """Verifying an empty password must return False."""
        hashed = hash_password("s3cr3t-passw0rd!")
        self.assertFalse(verify_password("", hashed))

    def test_verify_password_rejects_empty_hash(self) -> None:
        """Verifying against an empty hash must return False."""
        self.assertFalse(verify_password("s3cr3t-passw0rd!", ""))

    def test_verify_password_rejects_malformed_hash(self) -> None:
        """A malformed hash must yield False without raising."""
        self.assertFalse(verify_password("s3cr3t-passw0rd!", "not-a-bcrypt-hash"))
        self.assertFalse(verify_password("s3cr3t-passw0rd!", "$2b$12$invalid"))


if __name__ == "__main__":
    unittest.main()
