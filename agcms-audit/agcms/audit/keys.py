"""Signing-key registry.

AGCMS signs every audit row with an HMAC-SHA256 keyed by an identifier
(`kid`). Row writes use the *active* row key; verification of a historical
row uses whatever key the row was signed with, looked up by `kid`. The
same pattern applies to the Merkle anchor key used by the nightly root
job (Phase 5.2).

Environment inputs
------------------
AGCMS_SIGNING_KEY       Raw bytes of the active row-signing key. Required.
AGCMS_ACTIVE_ROW_KID    Kid to associate with AGCMS_SIGNING_KEY. Default 'v1'.
AGCMS_SIGNING_KEYS_JSON Optional JSON ``{"kid": "raw-bytes", ...}`` of
                        historical row-signing keys so old rows still
                        verify after rotation.
AGCMS_ANCHOR_KEY        Raw bytes of the active anchor-signing key.
                        Optional here (required by the anchor service).
AGCMS_ACTIVE_ANCHOR_KID Kid for AGCMS_ANCHOR_KEY. Default 'a1'.
AGCMS_ANCHOR_KEYS_JSON  Optional JSON of historical anchor keys.
"""
from __future__ import annotations

import json
import os
from typing import Dict, Optional


class KeyRegistry:
    """Immutable in-memory registry of signing keys keyed by (purpose, kid)."""

    def __init__(
        self,
        row_keys: Dict[str, bytes],
        active_row_kid: str,
        anchor_keys: Dict[str, bytes],
        active_anchor_kid: Optional[str],
    ) -> None:
        self._row_keys = row_keys
        self._active_row_kid = active_row_kid
        self._anchor_keys = anchor_keys
        self._active_anchor_kid = active_anchor_kid

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------
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

        active_anchor_kid: Optional[str] = os.environ.get("AGCMS_ACTIVE_ANCHOR_KID", "a1")
        anchor_raw = os.environ.get("AGCMS_ANCHOR_KEY")
        anchor_keys: Dict[str, bytes] = {}
        if anchor_raw:
            anchor_keys[active_anchor_kid] = anchor_raw.encode("utf-8")
        else:
            # Anchor service not yet bootstrapped — leave registry empty.
            active_anchor_kid = None

        historical_anchor = os.environ.get("AGCMS_ANCHOR_KEYS_JSON")
        if historical_anchor:
            for kid, material in json.loads(historical_anchor).items():
                if not material:
                    raise RuntimeError(f"Historical anchor key {kid!r} is empty.")
                anchor_keys[kid] = material.encode("utf-8")

        return cls(
            row_keys=row_keys,
            active_row_kid=active_row_kid,
            anchor_keys=anchor_keys,
            active_anchor_kid=active_anchor_kid,
        )

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------
    @property
    def active_row_kid(self) -> str:
        return self._active_row_kid

    @property
    def active_anchor_kid(self) -> Optional[str]:
        return self._active_anchor_kid

    def row_key(self, kid: str) -> bytes:
        try:
            return self._row_keys[kid]
        except KeyError as exc:
            raise KeyError(
                f"No row-signing key registered for kid {kid!r}. "
                "Configure AGCMS_SIGNING_KEYS_JSON with historical material."
            ) from exc

    def anchor_key(self, kid: str) -> bytes:
        try:
            return self._anchor_keys[kid]
        except KeyError as exc:
            raise KeyError(
                f"No anchor-signing key registered for kid {kid!r}."
            ) from exc

    def has_row_kid(self, kid: str) -> bool:
        return kid in self._row_keys


REGISTRY = KeyRegistry.from_env()
