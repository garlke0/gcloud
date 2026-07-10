"""Security primitives. All password handling lives here."""

from argon2 import PasswordHasher
from argon2.exceptions import (
    VerifyMismatchError,
    VerificationError,
    InvalidHashError,
)

# Argon2id parameters.
# Measured on Dell Latitude 5420 (i5-8350U, 16 GB): 201 ms per hash.
# OWASP floor is m=19456, t=2, p=1. Memory sits 10x above it.
# Worst case at 10 concurrent logins: 1.9 GB — fits alongside Docker + Postgres.
ph = PasswordHasher(
    time_cost=3,
    memory_cost=196608,
    parallelism=4,
    hash_len=32,
)


def hash_password(plaintext: str) -> str:
    """One-way. There is no inverse. Salt is generated internally
    and embedded in the returned string."""
    return ph.hash(plaintext)


def verify_password(stored_hash: str, plaintext: str) -> bool:
    """True on match, False otherwise.

    ph.verify() raises on failure instead of returning False,
    so we translate the exceptions into a boolean.
    """
    try:
        ph.verify(stored_hash, plaintext)
        return True
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False