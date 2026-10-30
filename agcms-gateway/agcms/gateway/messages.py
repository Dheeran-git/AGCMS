"""Chat-message handling for the governed request path.

Every text segment the provider would receive is scanned: string content and
``text`` parts of list content, in every role. Scans run over the segments
joined with newlines; redaction maps the PII service's entity offsets back to
each segment, so each message is masked in place.
"""

import copy
from typing import NamedTuple, Optional


class Segment(NamedTuple):
    """One scannable text, located by message index and list-part index."""

    message: int
    part: Optional[int]
    start: int
    end: int


def validate_body(body) -> Optional[str]:
    """Return an error message if the chat body cannot be governed, else None."""
    if not isinstance(body, dict):
        return "Request body must be a JSON object"
    messages = body.get("messages")
    if not messages or not isinstance(messages, list):
        return "Request must include 'messages' array"
    for i, msg in enumerate(messages):
        if not isinstance(msg, dict) or not isinstance(msg.get("role"), str):
            return f"messages[{i}] must be an object with a string 'role'"
        content = msg.get("content")
        if content is None or isinstance(content, str):
            continue
        if not isinstance(content, list):
            return f"messages[{i}].content must be a string or a list of parts"
        for j, part in enumerate(content):
            if not (isinstance(part, dict) and part.get("type") == "text"
                    and isinstance(part.get("text"), str)):
                return f"messages[{i}].content[{j}] is not a text part; only text can be governed"
    for field in ("model", "provider"):
        if body.get(field) is not None and not isinstance(body[field], str):
            return f"'{field}' must be a string"
    return None


def segment_texts(messages: list) -> list[tuple[int, Optional[int], str]]:
    """List every text segment as (message index, part index, text)."""
    texts = []
    for i, msg in enumerate(messages):
        content = msg.get("content")
        if isinstance(content, str):
            texts.append((i, None, content))
        elif isinstance(content, list):
            texts.extend((i, j, part["text"]) for j, part in enumerate(content))
    return texts


def joined_prompt(messages: list) -> tuple[str, list[Segment]]:
    """Join all segments with newlines and record where each one sits."""
    pieces, segments, pos = [], [], 0
    for i, j, text in segment_texts(messages):
        segments.append(Segment(i, j, pos, pos + len(text)))
        pieces.append(text)
        pos += len(text) + 1
    return "\n".join(pieces), segments


def _mask(text: str, offset: int, entities: list) -> str:
    """Mask the parts of ``entities`` (offsets in the joined prompt) inside ``text``."""
    end = offset + len(text)
    for e in sorted(entities, key=lambda e: e["start"], reverse=True):
        start, stop = max(e["start"], offset), min(e["end"], end)
        if start < stop:
            text = text[:start - offset] + f"[{e['entity_type']}]" + text[stop - offset:]
    return text


def redact_messages(messages: list, segments: list[Segment], entities: list) -> list:
    """Return a copy of ``messages`` with every detected entity masked."""
    result = copy.deepcopy(messages)
    for seg in segments:
        msg = result[seg.message]
        if seg.part is None:
            msg["content"] = _mask(msg["content"], seg.start, entities)
        else:
            part = msg["content"][seg.part]
            part["text"] = _mask(part["text"], seg.start, entities)
    return result


def reply_text(llm_response: dict) -> str:
    """Text of the first choice of an OpenAI-format reply ('' when absent)."""
    choices = llm_response.get("choices") or []
    if not choices or not isinstance(choices[0], dict):
        return ""
    message = choices[0].get("message") or {}
    return "\n".join(t for _, _, t in segment_texts([message]))
