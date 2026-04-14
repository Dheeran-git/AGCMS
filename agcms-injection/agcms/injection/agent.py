"""Prompt Injection Detection Agent — heuristic rules + ML classifier.

Heuristic pipeline: 20+ patterns across 6 attack categories.
ML classifier: protectai/deberta-v3-base-prompt-injection-v2 via ONNX Runtime.
Score aggregation: max(heuristic_score, ml_score).
"""

import base64
import logging
import re
import unicodedata
from typing import List, Optional, Tuple

import numpy as np

from agcms.injection.model_loader import load_model
from agcms.injection.models import InjectionRule, InjectionScanResult

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Heuristic rule definitions
# Each rule: (name, category, compiled regex, weight)
# ------------------------------------------------------------------

_RULES: List[Tuple[str, str, re.Pattern, float]] = []


def _add(name: str, category: str, pattern: str, weight: float):
    _RULES.append((name, category, re.compile(pattern, re.IGNORECASE), weight))


# Category: DIRECT — explicit instruction override
_add("direct_ignore", "DIRECT",
     r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules|directives)",
     0.9)
_add("direct_disregard", "DIRECT",
     r"disregard\s+(all\s+)?(previous|prior|above|your)\s+(instructions|prompts|rules)",
     0.9)
_add("direct_forget", "DIRECT",
     r"forget\s+(all\s+)?(your|previous|prior)\s+(instructions|rules|guidelines|training)",
     0.85)
_add("direct_override", "DIRECT",
     r"(new\s+instructions?|override\s+(previous|your)|do\s+not\s+follow\s+(your|the)\s+rules)",
     0.85)
_add("direct_jailbreak", "DIRECT",
     r"(jailbreak|DAN\s+mode|developer\s+mode|god\s+mode)",
     0.95)

# Category: ROLEPLAY — identity manipulation
_add("roleplay_you_are", "ROLEPLAY",
     r"(you\s+are\s+now|from\s+now\s+on\s+you\s+are|act\s+as\s+if\s+you\s+are)\s+\w+",
     0.75)
_add("roleplay_pretend", "ROLEPLAY",
     r"pretend\s+(you\s+are|to\s+be|you're)\s+\w+",
     0.75)
_add("roleplay_simulate", "ROLEPLAY",
     r"simulate\s+(being|a)\s+\w+",
     0.65)
_add("roleplay_persona", "ROLEPLAY",
     r"(adopt|assume|take\s+on)\s+(the\s+)?(role|persona|identity)\s+of",
     0.75)

# Category: SYSTEM_PROMPT_LEAK — extraction attempts
_add("leak_repeat", "SYSTEM_PROMPT_LEAK",
     r"(repeat|recite|show|display|print|output|reveal)\s+(your|the)\s+(system\s+)?(instructions|prompt|rules|guidelines|configuration)",
     0.9)
_add("leak_what_are", "SYSTEM_PROMPT_LEAK",
     r"what\s+(are|is)\s+your\s+(system\s+)?(instructions|prompt|rules|initial\s+prompt)",
     0.85)
_add("leak_previous_text", "SYSTEM_PROMPT_LEAK",
     r"(text|content|message)\s+(above|before)\s+(this|the\s+user)",
     0.8)
_add("leak_verbatim", "SYSTEM_PROMPT_LEAK",
     r"(verbatim|word\s+for\s+word|exactly\s+as\s+written)",
     0.7)

# Category: DELIMITER — structural injection
_add("delimiter_system_tag", "DELIMITER",
     r"\[/?SYSTEM\]|\[/?INST\]|<\|system\|>|<\|im_start\|>system",
     0.95)
_add("delimiter_triple_backtick", "DELIMITER",
     r"```\s*system\b",
     0.85)
_add("delimiter_markdown_header", "DELIMITER",
     r"#{1,3}\s*(system\s*(prompt|message|instruction)|new\s*instructions?)",
     0.8)

# Category: CONTEXT_MANIPULATION — hypothetical framing
_add("context_hypothetical", "CONTEXT_MANIPULATION",
     r"(in\s+a\s+hypothetical\s+scenario|hypothetically\s+speaking|for\s+(educational|research|academic)\s+purposes)",
     0.6)
_add("context_fiction", "CONTEXT_MANIPULATION",
     r"(write\s+a\s+(story|fiction|novel)|in\s+this\s+fictional\s+scenario)\s+where\s+(you|the\s+AI)",
     0.55)

# Category: MULTI_TURN — conversation history manipulation
_add("multi_turn_previous", "MULTI_TURN",
     r"(previously\s+you\s+(said|agreed|confirmed)|as\s+you\s+mentioned\s+(earlier|before)|continue\s+from\s+where\s+you\s+left\s+off)",
     0.6)
_add("multi_turn_remember", "MULTI_TURN",
     r"(remember\s+when\s+you|you\s+already\s+(agreed|said)\s+(to|that))",
     0.55)


# ------------------------------------------------------------------
# Normalizers
# ------------------------------------------------------------------

# Common Unicode homoglyphs → ASCII
_HOMOGLYPHS = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    "\u0410": "A", "\u0415": "E", "\u041e": "O", "\u0420": "P",
    "\u0421": "C", "\u0423": "Y", "\u0425": "X",
    "\uff49": "i", "\uff47": "g", "\uff4e": "n", "\uff4f": "o",
    "\uff52": "r", "\uff45": "e",
    "\u200b": "",  # zero-width space
    "\u200c": "",  # zero-width non-joiner
    "\u200d": "",  # zero-width joiner
    "\ufeff": "",  # BOM
})

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_HEX_ESCAPE_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
_URL_ENCODED_RE = re.compile(r"(?:%[0-9a-fA-F]{2}){4,}")


def _normalize_unicode(text: str) -> str:
    """Replace Unicode homoglyphs and normalize to NFKC form."""
    text = text.translate(_HOMOGLYPHS)
    return unicodedata.normalize("NFKC", text)


def _decode_base64_segments(text: str) -> str:
    """Find and decode base64 segments, appending decoded text."""
    decoded_parts = []
    for match in _BASE64_RE.finditer(text):
        try:
            raw = base64.b64decode(match.group(), validate=True)
            decoded = raw.decode("utf-8", errors="ignore")
            if decoded.isprintable() and len(decoded) > 5:
                decoded_parts.append(decoded)
        except Exception:
            continue
    if decoded_parts:
        return text + " " + " ".join(decoded_parts)
    return text


def _decode_hex_escapes(text: str) -> str:
    """Decode \\xHH escape sequences."""
    def _replace(m: re.Match) -> str:
        try:
            return bytes.fromhex(
                m.group().replace("\\x", "")
            ).decode("utf-8", errors="ignore")
        except Exception:
            return m.group()
    return _HEX_ESCAPE_RE.sub(_replace, text)


def _decode_url_encoding(text: str) -> str:
    """Decode %HH URL-encoded sequences."""
    def _replace(m: re.Match) -> str:
        try:
            return bytes.fromhex(
                m.group().replace("%", "")
            ).decode("utf-8", errors="ignore")
        except Exception:
            return m.group()
    return _URL_ENCODED_RE.sub(_replace, text)


# ------------------------------------------------------------------
# Agent
# ------------------------------------------------------------------


class InjectionAgent:
    """Prompt injection detection using heuristic rules + ML classifier.

    Detection pipeline:
      1. Unicode normalization (homoglyph replacement, NFKC)
      2. Encoding decode (base64, hex escapes, URL encoding)
      3. Heuristic rule matching (20+ patterns across 6 categories)
      4. ML classification (DeBERTa v3 via ONNX Runtime)
      5. Score aggregation — max(heuristic, ml), capped at 1.0
    """

    def __init__(self) -> None:
        self._onnx_session, self._tokenizer = load_model()
        if self._onnx_session is not None:
            logger.info("InjectionAgent: ML classifier active")
        else:
            logger.info("InjectionAgent: heuristic-only mode")

    def scan(self, text: str) -> InjectionScanResult:
        """Run full injection detection pipeline on text."""
        if not text or not text.strip():
            return InjectionScanResult()

        # Step 1 & 2: Normalize
        normalized = _normalize_unicode(text)
        normalized = _decode_base64_segments(normalized)
        normalized = _decode_hex_escapes(normalized)
        normalized = _decode_url_encoding(normalized)

        # Step 3: Heuristic rules
        triggered: List[InjectionRule] = []
        for name, category, pattern, weight in _RULES:
            match = pattern.search(normalized)
            if match:
                triggered.append(InjectionRule(
                    name=name,
                    pattern=match.group(),
                    weight=weight,
                ))

        # Step 4: ML classification
        ml_score = self._ml_classify(normalized)

        # Step 5: Aggregate
        if not triggered and ml_score is None:
            return InjectionScanResult()

        heuristic_score = max(r.weight for r in triggered) if triggered else 0.0
        if ml_score is not None:
            final_score = max(heuristic_score, ml_score)
        else:
            final_score = heuristic_score

        # Determine primary attack type from highest-weight rule
        attack_type = None
        if triggered:
            best_rule = max(triggered, key=lambda r: r.weight)
            # Extract category from the rule name via lookup
            for name, category, _, _ in _RULES:
                if name == best_rule.name:
                    attack_type = category
                    break

        return InjectionScanResult(
            risk_score=min(final_score, 1.0),
            attack_type=attack_type,
            triggered_rules=triggered,
        )

    def _ml_classify(self, text: str) -> Optional[float]:
        """Run ML classifier and return injection probability [0, 1].

        Returns None when the model is unavailable (graceful fallback).
        Supports two backends:
          - ONNX Runtime InferenceSession (preferred, fast CPU inference)
          - HuggingFace model (fallback if ONNX export failed)
        """
        if self._onnx_session is None or self._tokenizer is None:
            return None

        try:
            inputs = self._tokenizer(
                text,
                return_tensors="np",
                truncation=True,
                max_length=512,
                padding="max_length",
            )

            # ONNX Runtime path
            import onnxruntime as ort

            if isinstance(self._onnx_session, ort.InferenceSession):
                ort_inputs = {
                    k: v for k, v in inputs.items()
                    if k in [i.name for i in self._onnx_session.get_inputs()]
                }
                logits = self._onnx_session.run(None, ort_inputs)[0]
                probs = _softmax(logits[0])
                # Label mapping: index 1 = INJECTION for this model
                return float(probs[1])

            # HuggingFace model fallback path
            import torch

            with torch.no_grad():
                pt_inputs = {
                    k: torch.tensor(v) for k, v in inputs.items()
                }
                output = self._onnx_session(**pt_inputs)
                probs = torch.softmax(output.logits, dim=-1)
                return float(probs[0][1])

        except Exception:
            logger.exception("ML classification failed — falling back to heuristic")
            return None


def _softmax(x: "np.ndarray") -> "np.ndarray":
    """Numerically stable softmax."""
    e_x = np.exp(x - np.max(x))
    return e_x / e_x.sum()
