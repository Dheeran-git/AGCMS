"""Policy-pack loader.

Packs live in ``policies/packs/*.yaml``. Each pack has:

  * ``id``, ``name``, ``framework``, ``version`` — identity
  * ``overrides`` — merged on top of the tenant's base policy
  * ``rules`` — citation-annotated rules that the resolver can surface
  * ``metadata.framework_citations`` — every citation the pack references,
    so the UI can render hover-cards without hard-coding regulation text

This module exposes two public functions:

  * ``list_packs()`` — enumerate every installed pack
  * ``load_pack(pack_id)`` — load one pack and return the parsed dict
  * ``merge_packs(base, pack_ids)`` — shallow-merge base policy with
    selected packs' overrides (packs later in the list win)
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

# Pack root can be overridden for tests / non-standard layouts.
_PACKS_ROOT = Path(
    os.environ.get("AGCMS_POLICY_PACKS_DIR", "/app/policies/packs")
)


def _resolve_packs_root() -> Path:
    """Find the packs dir, falling back to the repo checkout if running
    from a developer machine where /app is not mounted."""
    if _PACKS_ROOT.exists():
        return _PACKS_ROOT
    # Dev fallback: repo-rooted ``policies/packs``.
    repo_candidate = Path(__file__).resolve().parents[3] / "policies" / "packs"
    if repo_candidate.exists():
        return repo_candidate
    return _PACKS_ROOT  # missing dir raises on list/load, with a clear error


def list_packs() -> list[dict[str, Any]]:
    """Return a summary entry per pack — id, name, framework, version, description."""
    root = _resolve_packs_root()
    if not root.exists():
        return []
    summaries: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.yaml")):
        with path.open("r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
        summaries.append(
            {
                "id": doc.get("id", path.stem),
                "name": doc.get("name", path.stem),
                "framework": doc.get("framework", "UNKNOWN"),
                "version": doc.get("version", "0.0.0"),
                "description": doc.get("description", "").strip(),
                "rule_count": len(doc.get("rules") or []),
                "citations": [
                    c.get("id")
                    for c in (doc.get("metadata", {}) or {}).get("framework_citations", [])
                ],
            }
        )
    return summaries


def load_pack(pack_id: str) -> dict[str, Any]:
    """Load one pack by id. Raises ``FileNotFoundError`` if missing."""
    root = _resolve_packs_root()
    path = root / f"{pack_id}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"Policy pack '{pack_id}' not found under {root}")
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def merge_packs(
    base_policy: dict[str, Any],
    pack_ids: list[str],
) -> dict[str, Any]:
    """Shallow-merge ``base_policy`` with each pack's ``overrides``.

    Conflict resolution: last pack wins. Lists are replaced wholesale
    rather than concatenated — this keeps the behavior predictable
    when a user removes a pack (their settings snap back to base).

    Also aggregates ``rules`` and ``citations`` across all selected
    packs so downstream consumers (resolver, UI) can see everything
    at once.
    """
    merged = _deep_copy_dict(base_policy)
    all_rules: list[dict[str, Any]] = []
    all_citations: list[dict[str, Any]] = []
    active_frameworks: list[str] = []

    for pid in pack_ids:
        pack = load_pack(pid)
        overrides = pack.get("overrides") or {}
        for top_key, sub in overrides.items():
            if isinstance(sub, dict) and isinstance(merged.get(top_key), dict):
                merged[top_key] = {**merged[top_key], **sub}
            else:
                merged[top_key] = sub
        all_rules.extend(pack.get("rules") or [])
        all_citations.extend(
            (pack.get("metadata", {}) or {}).get("framework_citations") or []
        )
        if pack.get("framework"):
            active_frameworks.append(pack["framework"])

    merged["rules"] = all_rules
    merged["citations"] = all_citations
    merged["active_frameworks"] = active_frameworks
    return merged


def _deep_copy_dict(d: dict[str, Any]) -> dict[str, Any]:
    """Enough copy for nested dicts of primitives + lists. Good enough for
    our single-level-nested policy shape, avoiding a copy.deepcopy import."""
    out: dict[str, Any] = {}
    for k, v in d.items():
        if isinstance(v, dict):
            out[k] = _deep_copy_dict(v)
        elif isinstance(v, list):
            out[k] = list(v)
        else:
            out[k] = v
    return out


__all__ = ["list_packs", "load_pack", "merge_packs"]
