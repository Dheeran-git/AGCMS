"""Public changelog API.

Reads ``CHANGELOG.md`` (Keep a Changelog format) from the repo root and
exposes it as JSON for the dashboard's Settings → About surface and the
public landing site. Falls back to an empty list if the file is missing
so deploys without the file don't 500.

Endpoints:
    GET /api/v1/changelog          — full parsed changelog
    GET /api/v1/changelog/latest   — only the most recent release entry

Format note: we do not require Markdown→HTML on the server; the dashboard
renders the raw bullet text.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import List

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/changelog", tags=["changelog"])

# Resolution rule: env override → repo root (4 levels up from this file).
_ENV_PATH = os.environ.get("AGCMS_CHANGELOG_PATH")
_DEFAULT_PATH = Path(__file__).resolve().parents[3] / "CHANGELOG.md"


class ChangelogSection(BaseModel):
    label: str  # e.g. "Added", "Fixed", "Removed"
    items: List[str]


class ChangelogEntry(BaseModel):
    version: str  # e.g. "1.1.0"
    date: str | None  # "2026-04-22" or "Unreleased"
    sections: List[ChangelogSection]


_HEADER_RE = re.compile(r"^##\s+\[(?P<version>[^\]]+)\](?:\s+[—-]\s+(?P<date>.+))?\s*$")
_SECTION_RE = re.compile(r"^###\s+(?P<label>.+?)\s*$")
_BULLET_RE = re.compile(r"^[-*]\s+(?P<item>.+?)\s*$")


def _changelog_path() -> Path:
    if _ENV_PATH:
        return Path(_ENV_PATH)
    return _DEFAULT_PATH


def _parse(text: str) -> List[ChangelogEntry]:
    """Convert Keep-a-Changelog markdown into structured entries."""
    entries: List[ChangelogEntry] = []
    current_entry: ChangelogEntry | None = None
    current_section: ChangelogSection | None = None
    pending_continuation: str | None = None

    def flush_continuation() -> None:
        nonlocal pending_continuation
        if pending_continuation and current_section and current_section.items:
            current_section.items[-1] = (
                current_section.items[-1] + " " + pending_continuation.strip()
            )
        pending_continuation = None

    for raw in text.splitlines():
        line = raw.rstrip()

        m = _HEADER_RE.match(line)
        if m:
            flush_continuation()
            current_entry = ChangelogEntry(
                version=m.group("version"),
                date=(m.group("date") or "").strip() or None,
                sections=[],
            )
            entries.append(current_entry)
            current_section = None
            continue

        m = _SECTION_RE.match(line)
        if m and current_entry is not None:
            flush_continuation()
            current_section = ChangelogSection(label=m.group("label"), items=[])
            current_entry.sections.append(current_section)
            continue

        m = _BULLET_RE.match(line)
        if m and current_section is not None:
            flush_continuation()
            current_section.items.append(m.group("item").strip())
            continue

        # Continuation of a wrapped bullet (indented two spaces in our format).
        if line.startswith("  ") and current_section and current_section.items:
            pending_continuation = (pending_continuation or "") + " " + line.strip()
            continue

        # Blank line ends a continuation but doesn't change state.
        if not line.strip():
            flush_continuation()

    flush_continuation()
    return entries


def _load() -> List[ChangelogEntry]:
    path = _changelog_path()
    if not path.is_file():
        return []
    try:
        return _parse(path.read_text(encoding="utf-8"))
    except OSError:
        return []


@router.get("", response_model=List[ChangelogEntry], summary="Full changelog")
async def get_changelog() -> List[ChangelogEntry]:
    return _load()


@router.get("/latest", response_model=ChangelogEntry | None, summary="Latest release")
async def get_latest() -> ChangelogEntry | None:
    entries = _load()
    return entries[0] if entries else None
