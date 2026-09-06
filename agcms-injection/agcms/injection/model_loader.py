"""ONNX model loader for prompt injection classification.

Loads the fine-tuned AGCMS classifier (DistilBERT, see ``ml/train.py`` and
``ml/export_onnx.py``) from ``AGCMS_INJECTION_MODEL_DIR``. Any ONNX
sequence-classification export with label index 1 = injection works, so the
off-the-shelf ``protectai/deberta-v3-base-prompt-injection-v2`` can be dropped
in for comparison. If the directory is missing or fails to load, the agent
runs heuristic-only; nothing is downloaded at runtime.
"""

import logging
import os
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Environment toggle — set to "false" to skip ML entirely
_ML_ENABLED = os.environ.get("AGCMS_ML_ENABLED", "true").lower() == "true"

# Where the Dockerfile copies the exported ONNX model + tokenizer
_DEFAULT_MODEL_DIR = os.environ.get(
    "AGCMS_INJECTION_MODEL_DIR", "/app/model/onnx"
)


def load_model(
    model_dir: Optional[str] = None,
) -> Tuple[Optional[object], Optional[object]]:
    """Load ONNX session and tokenizer.

    Returns:
        (ort_session, tokenizer) on success.
        (None, None) on any failure — caller falls back to heuristics.
    """
    if not _ML_ENABLED:
        logger.info("ML injection classifier disabled via AGCMS_ML_ENABLED=false")
        return None, None

    model_dir = model_dir or _DEFAULT_MODEL_DIR
    onnx_path = os.path.join(model_dir, "model.onnx")
    if not os.path.isfile(onnx_path):
        logger.warning(
            "No ONNX model at %s — run ml/export_onnx.py; heuristic-only mode", onnx_path
        )
        return None, None

    try:
        import onnxruntime as ort
        from transformers import AutoTokenizer
    except ImportError as exc:
        logger.warning("%s not installed — ML classifier unavailable", exc.name)
        return None, None

    try:
        session_opts = ort.SessionOptions()
        session_opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        session = ort.InferenceSession(onnx_path, session_opts)
        tokenizer = AutoTokenizer.from_pretrained(model_dir)
        logger.info("ML injection classifier loaded from %s", model_dir)
        return session, tokenizer
    except Exception:
        logger.exception("Failed to load ONNX model from %s", model_dir)
        return None, None
