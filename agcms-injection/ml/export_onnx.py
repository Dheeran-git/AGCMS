"""Export trained model to ONNX format for fast inference.

Usage: python export_onnx.py
Input:  ./model/best/ (PyTorch checkpoint)
Output: ./model/injection_classifier.onnx + tokenizer files
"""

import pathlib
import shutil
from optimum.onnxruntime import ORTModelForSequenceClassification
from transformers import AutoTokenizer

MODEL_DIR = pathlib.Path(__file__).parent / "model"
BEST_DIR = MODEL_DIR / "best"
ONNX_DIR = MODEL_DIR / "onnx"


def main():
    print(f"Loading model from {BEST_DIR}")
    ort_model = ORTModelForSequenceClassification.from_pretrained(
        BEST_DIR, export=True
    )
    tokenizer = AutoTokenizer.from_pretrained(BEST_DIR)

    # Save ONNX model + tokenizer together
    ONNX_DIR.mkdir(parents=True, exist_ok=True)
    ort_model.save_pretrained(ONNX_DIR)
    tokenizer.save_pretrained(ONNX_DIR)

    print(f"ONNX model saved to {ONNX_DIR}")

    # List output files
    for f in sorted(ONNX_DIR.iterdir()):
        size = f.stat().st_size
        print(f"  {f.name}: {size / 1024:.1f} KB")


if __name__ == "__main__":
    main()
