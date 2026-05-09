"""Pure helpers for TOTP-based MFA and recovery codes.

This module holds *only* cryptographic / encoding primitives so it is
trivially unit-testable with no database, no network, no clock sources
other than a provided argument.

Design notes
------------
- TOTP algorithm: RFC 6238, SHA-1, 6 digits, 30-second window, ±1 step
  (±30 s) of skew tolerance. This matches Google Authenticator / Authy /
  1Password / Microsoft Authenticator defaults.
- Recovery codes: 10 codes per user. Each is 10 characters drawn from an
  unambiguous alphabet (no ``0/O/1/I/l``). Stored only as SHA-256 hashes;
  the plaintext is returned *once* at enrollment and never again.
- Secrets are base32-encoded (pyotp convention). Storage of the raw
  secret remains plaintext for now; Phase 6.3 wraps it with envelope
  encryption via the KMS abstraction in ``agcms.common.crypto``.
"""
from __future__ import annotations

import hashlib
import secrets
from base64 import b32encode
from dataclasses import dataclass
from io import BytesIO
from typing import Iterable

import pyotp

# Unambiguous alphabet: skip 0/O/1/I/L to reduce "did I write l or 1?" errors.
_RECOVERY_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
_RECOVERY_LENGTH = 10
_RECOVERY_COUNT = 10

# Issuer shown in authenticator apps alongside the user's email.
ISSUER = "AGCMS"


@dataclass(frozen=True)
class EnrollmentMaterial:
    """Return payload for `begin_enrollment`."""
    secret: str
    provisioning_uri: str
    recovery_codes: tuple[str, ...]  # plaintext — show to user ONCE
    recovery_hashes: tuple[str, ...]  # matching SHA-256 hex — persist these


# ---------------------------------------------------------------------------
# TOTP
# ---------------------------------------------------------------------------


def new_secret() -> str:
    """Return a fresh, 160-bit base32 TOTP secret."""
    # 20 random bytes → 32-char base32 string (no padding).
    return b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def provisioning_uri(secret: str, *, email: str, issuer: str = ISSUER) -> str:
    """Return an ``otpauth://`` URI suitable for QR rendering."""
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)


def verify_totp(secret: str, code: str, *, window: int = 1) -> bool:
    """Verify a 6-digit TOTP code with ±`window` steps of clock skew."""
    code = (code or "").strip()
    if not code.isdigit() or len(code) != 6:
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=window)


# ---------------------------------------------------------------------------
# Recovery codes
# ---------------------------------------------------------------------------


def _one_recovery_code() -> str:
    return "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(_RECOVERY_LENGTH))


def generate_recovery_codes(count: int = _RECOVERY_COUNT) -> tuple[str, ...]:
    """Return `count` fresh plaintext recovery codes (default 10)."""
    return tuple(_one_recovery_code() for _ in range(count))


def hash_recovery_code(code: str) -> str:
    """Hash a recovery code for storage. Normalizes case + whitespace."""
    normalized = (code or "").strip().upper().replace("-", "").replace(" ", "")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def hash_recovery_codes(codes: Iterable[str]) -> tuple[str, ...]:
    return tuple(hash_recovery_code(c) for c in codes)


def consume_recovery_code(
    provided: str, stored_hashes: Iterable[str]
) -> tuple[bool, tuple[str, ...]]:
    """Check `provided` against stored SHA-256 hashes.

    On match: returns ``(True, <remaining hashes with the match removed>)``.
    On miss:  returns ``(False, <stored hashes unchanged>)``.
    Recovery codes are single-use, so the caller must persist the new
    list atomically.
    """
    target = hash_recovery_code(provided)
    remaining = list(stored_hashes)
    try:
        remaining.remove(target)
    except ValueError:
        return False, tuple(stored_hashes)
    return True, tuple(remaining)


# ---------------------------------------------------------------------------
# Enrollment convenience
# ---------------------------------------------------------------------------


def begin_enrollment(email: str, *, issuer: str = ISSUER) -> EnrollmentMaterial:
    """Mint a fresh secret + recovery codes for a new enrollment."""
    secret = new_secret()
    codes = generate_recovery_codes()
    return EnrollmentMaterial(
        secret=secret,
        provisioning_uri=provisioning_uri(secret, email=email, issuer=issuer),
        recovery_codes=codes,
        recovery_hashes=hash_recovery_codes(codes),
    )


def qr_png_data_url(uri: str) -> str:
    """Render an otpauth:// URI as a base64-encoded PNG data URL.

    Kept in this module rather than inline in the endpoint because PIL /
    qrcode is heavyweight and we want to make it easy to stub out in tests.
    """
    import base64
    import qrcode  # local import — PIL-backed, slow to import

    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"
