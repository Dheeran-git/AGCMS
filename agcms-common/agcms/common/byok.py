"""Bring-Your-Own-Key (BYOK) routing for envelope encryption.

When ``tenants.kms_key_arn`` is set, the tenant's DEK is wrapped/unwrapped
via the customer's own KMS key instead of the AGCMS-platform KEK. This
module provides:

* :class:`AwsKmsClient` — a :class:`agcms.common.crypto.KMSClient`
  implementation backed by AWS KMS via ``boto3``. ``boto3`` is loaded
  lazily so it is not required for tenants that stay on the platform KEK.
* :func:`build_kms_for_tenant` — factory that returns the right
  ``KMSClient`` for a given tenant's BYOK config.
* A small process-local registry (``register_tenant_kms`` /
  ``get_tenant_kms``) that the audit/tenant services warm up on hydration
  so per-row encryption stays fast.

Wire format
-----------
For BYOK tenants, the wrapped-DEK payload stored in ``tenant_keys.wrapped_dek``
is the ``CiphertextBlob`` returned by ``kms.Encrypt``. We do not re-wrap or
re-frame it — auditors with the customer's KMS access can independently
unwrap the same bytes.

The ``kek_id`` column stores ``"aws-kms:<sha256(arn)[:8]>"`` for AWS BYOK,
which lets us track rotation evidence without leaking the full ARN to log
sinks that aggregate ``signing_keys.kek_id``.

Failure modes
-------------
* Missing/expired AWS credentials → :class:`KMSError`. The tenant service
  surfaces this so admins can see *why* their BYOK setup is broken; it
  never silently falls back to the platform KEK.
* ``KMSAccessDeniedException`` from KMS → :class:`KMSError` (often means
  the tenant revoked our IAM role's grant; surface, do not retry blindly).
"""
from __future__ import annotations

import hashlib
import os
import threading
from dataclasses import dataclass
from typing import Any, Dict, Optional

from agcms.common.crypto import KMSClient, KMSError


# ---------------------------------------------------------------------------
# AWS KMS implementation
# ---------------------------------------------------------------------------


class AwsKmsClient(KMSClient):
    """Wrap/unwrap DEKs through an AWS KMS customer-managed key.

    ``key_arn`` is the full ARN of the customer key. ``client`` is an
    optional pre-built boto3 ``kms`` client; injected by tests.
    """

    def __init__(self, key_arn: str, *, client: Optional[Any] = None) -> None:
        if not key_arn:
            raise KMSError("AwsKmsClient requires a key ARN")
        self._key_arn = key_arn
        self._client = client
        self._kek_id = "aws-kms:" + hashlib.sha256(key_arn.encode("utf-8")).hexdigest()[:8]

    @property
    def kek_id(self) -> str:
        return self._kek_id

    def _kms(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            import boto3  # type: ignore
        except ImportError as exc:
            raise KMSError(
                "boto3 is required for AWS BYOK — install it in the audit/"
                "tenant service images, or remove the tenant's kms_key_arn"
            ) from exc
        region = (
            os.environ.get("AWS_REGION")
            or os.environ.get("AWS_DEFAULT_REGION")
            or _region_from_arn(self._key_arn)
        )
        self._client = boto3.client("kms", region_name=region)
        return self._client

    def wrap(self, dek: bytes) -> bytes:
        try:
            resp = self._kms().encrypt(KeyId=self._key_arn, Plaintext=dek)
        except Exception as exc:
            raise KMSError(f"AWS KMS encrypt failed for {self._kek_id}: {exc}") from exc
        blob = resp.get("CiphertextBlob")
        if not blob:
            raise KMSError("AWS KMS returned an empty CiphertextBlob")
        return bytes(blob)

    def unwrap(self, wrapped: bytes) -> bytes:
        try:
            resp = self._kms().decrypt(
                CiphertextBlob=wrapped,
                KeyId=self._key_arn,
            )
        except Exception as exc:
            raise KMSError(f"AWS KMS decrypt failed for {self._kek_id}: {exc}") from exc
        plaintext = resp.get("Plaintext")
        if not plaintext or len(plaintext) != 32:
            raise KMSError("AWS KMS returned an unexpected DEK length")
        return bytes(plaintext)


def _region_from_arn(arn: str) -> Optional[str]:
    """Extract the region segment from ``arn:aws:kms:<region>:<acct>:key/<id>``."""
    parts = arn.split(":")
    if len(parts) >= 4 and parts[0] == "arn":
        return parts[3] or None
    return None


# ---------------------------------------------------------------------------
# Per-tenant KMS resolver
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ByokConfig:
    """Snapshot of a tenant's BYOK selection."""

    provider: str  # 'aws' | 'gcp' | 'azure'
    key_arn: str

    def is_aws(self) -> bool:
        return self.provider == "aws"


_lock = threading.Lock()
_per_tenant_kms: Dict[str, KMSClient] = {}


def register_tenant_kms(tenant_id: str, kms: Optional[KMSClient]) -> None:
    """Pin a tenant to a specific KMSClient.

    Pass ``None`` to clear the override (the tenant will fall back to the
    platform KMS on the next ``get_tenant_kms`` call).
    """
    with _lock:
        if kms is None:
            _per_tenant_kms.pop(tenant_id, None)
        else:
            _per_tenant_kms[tenant_id] = kms


def get_tenant_kms(tenant_id: str) -> Optional[KMSClient]:
    """Return the pinned KMSClient for a tenant, or ``None`` if unset."""
    with _lock:
        return _per_tenant_kms.get(tenant_id)


def reset_registry() -> None:
    """Test hook — clear the in-process tenant→KMS map."""
    with _lock:
        _per_tenant_kms.clear()


def build_kms_for_tenant(config: Optional[ByokConfig]) -> Optional[KMSClient]:
    """Construct a KMSClient from a BYOK config row, or ``None`` if no BYOK."""
    if config is None or not config.key_arn:
        return None
    if config.is_aws():
        return AwsKmsClient(config.key_arn)
    raise KMSError(
        f"BYOK provider '{config.provider}' is not implemented yet — "
        f"only 'aws' is supported in this build"
    )


__all__ = [
    "AwsKmsClient",
    "ByokConfig",
    "build_kms_for_tenant",
    "register_tenant_kms",
    "get_tenant_kms",
    "reset_registry",
]
