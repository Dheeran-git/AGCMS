"""ONNX model loader for prompt injection classification.

Loads the protectai/deberta-v3-base-prompt-injection-v2 model in ONNX
format for fast CPU inference.  Falls back gracefully if the model or
dependencies are unavailable — the agent continues with heuristic-only
detection.
"""

import logging
import os
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Environment toggle — set to "false" to skip ML entirely
_ML_ENABLED = os.environ.get("AGCMS_ML_ENABLED", "true").lower() == "true"

# Where the Dockerfile caches the converted ONNX model
_DEFAULT_MODEL_DIR = os.environ.get(
    "AGCMS_INJECTION_MODEL_DIR", "/app/model/onnx"
)

# HuggingFace model ID used when no local cache exists
_HF_MODEL_ID = "protectai/deberta-v3-base-prompt-injection-v2"


def load_model(
    model_dir: Optional[str] = None,
) -> Tuple[Optional[object], Optional[object]]:
    """Load ONNX session and tokenizer.

    Returns:
        (ort_session, tokenizer) on success.
        (None, None) on any failure — caller should fall back to heuristics.
    """
    if not _ML_ENABLED:
        logger.info("ML injection classifier disabled via AGCMS_ML_ENABLED=false")
        return None, None

    model_dir = model_dir or _DEFAULT_MODEL_DIR

    try:
        from transformers import AutoTokenizer  # noqa: F811
    except ImportError:
        logger.warning("transformers not installed — ML classifier unavailable")
        return None, None

    try:
        import onnxruntime as ort  # noqa: F811
    except ImportError:
        logger.warning("onnxruntime not installed — ML classifier unavailable")
        return None, None

    # Try local ONNX model first
    onnx_path = os.path.join(model_dir, "model.onnx")
    if os.path.isfile(onnx_path):
        return _load_from_dir(model_dir, ort)

    # Try downloading from HuggingFace and converting to ONNX
    return _download_and_load(model_dir, ort)


def _load_from_dir(
    model_dir: str, ort: object,
) -> Tuple[Optional[object], Optional[object]]:
    """Load tokenizer + ONNX session from a local directory."""
    try:
        from transformers import AutoTokenizer

        onnx_path = os.path.join(model_dir, "model.onnx")
        logger.info("Loading ONNX model from %s", onnx_path)

        session_opts = ort.SessionOptions()
        session_opts.graph_optimization_level = (
            ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        )
        session = ort.InferenceSession(onnx_path, session_opts)

        tokenizer = AutoTokenizer.from_pretrained(model_dir)
        logger.info("ML injection classifier loaded successfully (ONNX)")
        return session, tokenizer
    except Exception:
        logger.exception("Failed to load ONNX model from %s", model_dir)
        return None, None


def _download_and_load(
    model_dir: str, ort: object,
) -> Tuple[Optional[object], Optional[object]]:
    """Download model from HuggingFace, export to ONNX, and load."""
    try:
        from optimum.onnxruntime import ORTModelForSequenceClassification

        logger.info("Downloading and converting %s to ONNX …", _HF_MODEL_ID)
        ort_model = ORTModelForSequenceClassification.from_pretrained(
            _HF_MODEL_ID, export=True,
        )
        os.makedirs(model_dir, exist_ok=True)
        ort_model.save_pretrained(model_dir)
        logger.info("ONNX model saved to %s", model_dir)

        # Now load using the standard path
        return _load_from_dir(model_dir, ort)
    except ImportError:
        logger.warning(
            "optimum not installed — cannot convert HuggingFace model to ONNX. "
            "Falling back to direct HuggingFace pipeline."
        )
        return _load_hf_pipeline(ort)
    except Exception:
        logger.exception("Failed to download/convert model from HuggingFace")
        return _load_hf_pipeline(ort)


def _load_hf_pipeline(
    ort: object,
) -> Tuple[Optional[object], Optional[object]]:
    """Last-resort: load the HuggingFace pipeline directly (uses PyTorch)."""
    try:
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        logger.info("Loading %s via HuggingFace pipeline (non-ONNX) …", _HF_MODEL_ID)
        tokenizer = AutoTokenizer.from_pretrained(_HF_MODEL_ID)
        model = AutoModelForSequenceClassification.from_pretrained(_HF_MODEL_ID)
        # Return model as the "session" — agent._ml_classify handles both paths
        logger.info("ML injection classifier loaded (HuggingFace pipeline)")
        return model, tokenizer
    except Exception:
        logger.exception("All model loading paths failed — heuristic-only mode")
        return None, None
