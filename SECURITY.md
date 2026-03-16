"""
Basilisk Security Utilities
Argon2id password hashing and verification.
"""
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# OWASP-recommended default parameters
ph = PasswordHasher()


def hash_password(password: str) -> str:
    """Generate a secure Argon2id hash for the given password."""
    return ph.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """
    Verify a plaintext password against its Argon2id hash.

    Returns True on match, False on mismatch or malformed hash.
    Never raises.
    """
    try:
        return ph.verify(stored_hash, password)
    except VerifyMismatchError:
        return False
    except Exception:
        # Catches malformed hashes, encoding errors, etc.
        return False