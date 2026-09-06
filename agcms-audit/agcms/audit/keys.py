"""Signing-key registry.

AGCMS signs every audit row with HMAC-SHA256 keyed by an identifier (`kid`).
Row writes use the active key; verification of a historical row uses the key
the row records, looked up by `kid`.

Environment inputs
------------------
AGCMS_SIGNING_KEY       Raw bytes of the active row-signing key. Required.
AGCMS_ACTIVE_ROW_KID    Kid to associate with AGCMS_SIGNING_KEY. Default 'v1'.
AGCMS_SIGNING_KEYS_JSON Optional JSON ``{"kid": "raw-bytes", ...}`` of
                        historical keys so old rows still verify.
"""
from __future__ import annotations

import json
import os
from typing import Dict


class KeyRegistry:
    """Immutable in-memory registry of row-signing keys keyed by kid."""

    def __init__(self, row_keys: Dict[str, bytes], active_row_kid: str) -> None:
        self._row_keys = row_keys
        self._active_row_kid = active_row_kid

    @classmethod
    def from_env(cls) -> "KeyRegistry":
        active_row_kid = os.environ.get("AGCMS_ACTIVE_ROW_KID", "v1")
        row_raw = os.environ.get("AGCMS_SIGNING_KEY")
        if row_raw is None:
            raise RuntimeError(
                "AGCMS_SIGNING_KEY environment variable is not set. "
                "The audit logger cannot start without a signing key."
            )
        if not row_raw:
            raise RuntimeError(
                "AGCMS_SIGNING_KEY environment variable is empty. "
                "Provide a non-empty signing key."
            )

        row_keys: Dict[str, bytes] = {active_row_kid: row_raw.encode("utf-8")}
        historical = os.environ.get("AGCMS_SIGNING_KEYS_JSON")
        if historical:
            for kid, material in json.loads(historical).items():
                if not material:
                    raise RuntimeError(f"Historical row key {kid!r} is empty.")
                row_keys[kid] = material.encode("utf-8")
        return cls(row_keys=row_keys, active_row_kid=active_row_kid)

    @property
    def active_row_kid(self) -> str:
        return self._active_row_kid

    def row_key(self, kid: str) -> bytes:
        try:
            return self._row_keys[kid]
        except KeyError as exc:
            raise KeyError(
                f"No row-signing key registered for kid {kid!r}. "
                "Configure AGCMS_SIGNING_KEYS_JSON with historical material."
            ) from exc

    def has_row_kid(self, kid: str) -> bool:
        return kid in self._row_keys


REGISTRY = KeyRegistry.from_env()
