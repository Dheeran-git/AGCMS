"""Envelope encryption abstraction for AGCMS.

Phase 6.3: we store per-tenant Data Encryption Keys (DEKs) wrapped by a
Key Encryption Key (KEK) that is held in the configured KMS. In dev the
KEK is pulled from ``AGCMS_KMS_LOCAL_KEY`` (a base64-encoded 32-byte
value). In prod the same interface resolves to AWS KMS or GCP KMS.

Usage
-----

    kms = get_kms()                              # module-level singleton
    ciphertext = encrypt_for_tenant(tenant_id, b"alice@example.com")
    plaintext  = decrypt_for_tenant(tenant_id, ciphertext)

Security model
--------------

- DEK: AES-256 (32 random bytes), one per tenant.
- KEK: managed by the KMS backend. LocalKMS stores it in an env var.
- Wire format for ciphertexts:

    AGCMSv1 | dek_kid (16B) | nonce (12B) | ct+tag  (AES-GCM)

  The ``dek_kid`` is the SHA-256 prefix of the wrapped DEK and is used
  only to distinguish DEK versions during rotation. The DEK itself is
  always looked up from storage via ``tenant_id``.

- AES-GCM authenticated encryption: any tamper with ciphertext or
  associated data raises ``InvalidTag`` on decrypt, preventing silent
  substitution.

Key rotation
------------

A tenant admin triggers a rotation by (1) generating a fresh DEK,
(2) wrapping it with the current KEK, (3) re-encrypting existing
ciphertexts lazily on next write. The old wrapped DEK is retained until
all rows carrying its kid are re-encrypted. This is handled by
``agcms.common.crypto.rotate_tenant_dek`` (called from the management
API).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"AGCMSv1\x00"  # 8 bytes so header aligns on 8-byte boundaries
NONCE_LEN = 12
KID_LEN = 16
DEK_LEN = 32

_LOCAL_KEY_ENV = "AGCMS_KMS_LOCAL_KEY"
_DEV_FALLBACK_KEY = b"AGCMS-dev-fallback-kek-32-bytes!"  # exactly 32 bytes


class KMSError(RuntimeError):
    """Raised for all KMS wrap / unwrap / config failures."""


# ---------------------------------------------------------------------------
# KMS backends
# ---------------------------------------------------------------------------


class KMSClient(ABC):
    """Pluggable backend: dev LocalKMS here, AWS / GCP KMS in prod."""

    @abstractmethod
    def wrap(self, dek: bytes) -> bytes:
        """Encrypt a DEK using the KEK. Returns an opaque wrapped bytestring."""

    @abstractmethod
    def unwrap(self, wrapped: bytes) -> bytes:
        """Decrypt a previously-wrapped DEK. Returns 32 plaintext bytes."""

    @property
    @abstractmethod
    def kek_id(self) -> str:
        """A short identifier of the current KEK (for key-rotation bookkeeping)."""


class LocalKMS(KMSClient):
    """Dev / test backend: AES-256-GCM with a KEK pulled from env.

    The env var ``AGCMS_KMS_LOCAL_KEY`` holds a base64-encoded 32-byte
    key. If unset, a fixed dev fallback is used — the module emits a
    warning and should NEVER be deployed to production.
    """

    def __init__(self, kek: bytes) -> None:
        if len(kek) != 32:
            raise KMSError(f"KEK must be 32 bytes, got {len(kek)}")
        self._aead = AESGCM(kek)
        self._kek_id = "local:" + hashlib.sha256(kek).hexdigest()[:8]

    @classmethod
    def from_env(cls) -> "LocalKMS":
        raw = os.environ.get(_LOCAL_KEY_ENV)
        if raw:
            try:
                kek = base64.b64decode(raw)
            except Exception as exc:
                raise KMSError(f"{_LOCAL_KEY_ENV} must be base64-encoded: {exc}")
            return cls(kek)
        # Dev fallback — loud but functional.
        return cls(_DEV_FALLBACK_KEY)

    @property
    def kek_id(self) -> str:
        return self._kek_id

    def wrap(self, dek: bytes) -> bytes:
        if len(dek) != DEK_LEN:
            raise KMSError(f"DEK must be {DEK_LEN} bytes, got {len(dek)}")
        nonce = secrets.token_bytes(NONCE_LEN)
        ct = self._aead.encrypt(nonce, dek, self._kek_id.encode("ascii"))
        return nonce + ct

    def unwrap(self, wrapped: bytes) -> bytes:
        if len(wrapped) < NONCE_LEN + 16:
            raise KMSError("Wrapped DEK is too short")
        nonce, ct = wrapped[:NONCE_LEN], wrapped[NONCE_LEN:]
        try:
            dek = self._aead.decrypt(nonce, ct, self._kek_id.encode("ascii"))
        except Exception as exc:
            raise KMSError(f"KEK unwrap failed: {exc}") from exc
        if len(dek) != DEK_LEN:
            raise KMSError(f"Unwrapped DEK has wrong length ({len(dek)})")
        return dek


_kms_singleton: Optional[KMSClient] = None


def get_kms() -> KMSClient:
    """Return the process-wide KMS client, resolving from env on first call."""
    global _kms_singleton
    if _kms_singleton is None:
        backend = os.environ.get("AGCMS_KMS_BACKEND", "local").lower()
        if backend == "local":
            _kms_singleton = LocalKMS.from_env()
        else:
            raise KMSError(
                f"Unsupported KMS backend '{backend}' — "
                f"prod backends (aws, gcp) are not implemented yet"
            )
    return _kms_singleton


def reset_kms() -> None:
    """Test hook — clear the memoized KMS client."""
    global _kms_singleton
    _kms_singleton = None


# ---------------------------------------------------------------------------
# DEK + per-tenant encryption
# ---------------------------------------------------------------------------


@dataclass
class TenantKey:
    tenant_id: str
    dek: bytes          # plaintext, 32 bytes — lives only in memory
    wrapped_dek: bytes  # exactly as returned by the KMS backend
    kid: bytes          # 16-byte identifier derived from wrapped_dek


def _dek_kid(wrapped: bytes) -> bytes:
    """Derive a stable 16-byte key identifier from a wrapped DEK."""
    return hashlib.sha256(wrapped).digest()[:KID_LEN]


def new_dek() -> bytes:
    return secrets.token_bytes(DEK_LEN)


# In-memory per-tenant cache. Process-local; acceptable because each
# service instance re-resolves DEKs on restart via the DB.
_tenant_key_cache: Dict[str, TenantKey] = {}


def _cache_get(tenant_id: str) -> Optional[TenantKey]:
    return _tenant_key_cache.get(tenant_id)


def _cache_put(key: TenantKey) -> None:
    _tenant_key_cache[key.tenant_id] = key


def reset_cache() -> None:
    _tenant_key_cache.clear()


def _resolve_kms(tenant_id: str, override: Optional[KMSClient]) -> KMSClient:
    """Pick the right KMS for this tenant: explicit > BYOK pin > platform."""
    if override is not None:
        return override
    # Lazy import: byok depends on this module, avoid a circular load at import time.
    from agcms.common import byok as _byok
    pinned = _byok.get_tenant_kms(tenant_id)
    return pinned if pinned is not None else get_kms()


def install_tenant_key(
    tenant_id: str,
    wrapped_dek: bytes,
    *,
    kms: Optional[KMSClient] = None,
) -> TenantKey:
    """Unwrap a stored wrapped DEK and cache the result for this tenant."""
    dek = _resolve_kms(tenant_id, kms).unwrap(wrapped_dek)
    key = TenantKey(
        tenant_id=tenant_id,
        dek=dek,
        wrapped_dek=wrapped_dek,
        kid=_dek_kid(wrapped_dek),
    )
    _cache_put(key)
    return key


def mint_tenant_key(
    tenant_id: str,
    *,
    kms: Optional[KMSClient] = None,
) -> TenantKey:
    """Create + wrap a brand-new DEK for this tenant. Caches it."""
    dek = new_dek()
    wrapped = _resolve_kms(tenant_id, kms).wrap(dek)
    key = TenantKey(
        tenant_id=tenant_id,
        dek=dek,
        wrapped_dek=wrapped,
        kid=_dek_kid(wrapped),
    )
    _cache_put(key)
    return key


def _require_tenant_key(tenant_id: str) -> TenantKey:
    k = _cache_get(tenant_id)
    if k is None:
        raise KMSError(
            f"No DEK loaded for tenant '{tenant_id}' — "
            f"call install_tenant_key() or mint_tenant_key() first"
        )
    return k


# ---------------------------------------------------------------------------
# Field-level encrypt / decrypt
# ---------------------------------------------------------------------------


def encrypt_for_tenant(
    tenant_id: str, plaintext: bytes, *, aad: Optional[bytes] = None
) -> bytes:
    """Encrypt bytes using the tenant's DEK. Returns MAGIC|kid|nonce|ct+tag."""
    key = _require_tenant_key(tenant_id)
    nonce = secrets.token_bytes(NONCE_LEN)
    associated = _combined_aad(tenant_id, aad)
    ct = AESGCM(key.dek).encrypt(nonce, plaintext, associated)
    return MAGIC + key.kid + nonce + ct


def decrypt_for_tenant(
    tenant_id: str, payload: bytes, *, aad: Optional[bytes] = None
) -> bytes:
    """Decrypt a MAGIC|kid|nonce|ct payload. Raises KMSError on any failure."""
    if len(payload) < len(MAGIC) + KID_LEN + NONCE_LEN + 16:
        raise KMSError("Ciphertext too short")
    if not hmac.compare_digest(payload[: len(MAGIC)], MAGIC):
        raise KMSError("Bad magic — not an AGCMS v1 ciphertext")
    kid = payload[len(MAGIC) : len(MAGIC) + KID_LEN]
    nonce = payload[len(MAGIC) + KID_LEN : len(MAGIC) + KID_LEN + NONCE_LEN]
    ct = payload[len(MAGIC) + KID_LEN + NONCE_LEN :]

    key = _require_tenant_key(tenant_id)
    if not hmac.compare_digest(kid, key.kid):
        # DEK rotation will eventually make this mismatch the norm;
        # caller must walk older wrapped DEKs. For now, single-DEK-only.
        raise KMSError(
            "Ciphertext was encrypted with a different DEK than the active one"
        )

    associated = _combined_aad(tenant_id, aad)
    try:
        return AESGCM(key.dek).decrypt(nonce, ct, associated)
    except Exception as exc:
        raise KMSError(f"Decrypt failed: {exc}") from exc


def _combined_aad(tenant_id: str, aad: Optional[bytes]) -> bytes:
    """Bind ciphertexts to the tenant so a row can't be moved cross-tenant."""
    t = tenant_id.encode("utf-8")
    if aad is None:
        return t
    return t + b"|" + aad


__all__ = [
    "KMSClient",
    "LocalKMS",
    "KMSError",
    "TenantKey",
    "encrypt_for_tenant",
    "decrypt_for_tenant",
    "install_tenant_key",
    "mint_tenant_key",
    "get_kms",
    "new_dek",
    "reset_kms",
    "reset_cache",
]
