"""Export a fine-tuned checkpoint to ONNX for the injection service.

Usage:  python agcms-injection/ml/export_onnx.py [--src ml/model/best] [--dst ml/model/onnx]

The destination folder is what the injection Dockerfile copies into the
image (`/app/model/onnx`) and what `AGCMS_INJECTION_MODEL_DIR` points at.
"""

from __future__ import annotations

import argparse
import pathlib
import shutil

from optimum.onnxruntime import ORTModelForSequenceClassification
from transformers import AutoTokenizer

MODEL_DIR = pathlib.Path(__file__).resolve().parent / "model"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", type=pathlib.Path, default=MODEL_DIR / "best")
    ap.add_argument("--dst", type=pathlib.Path, default=MODEL_DIR / "onnx")
    args = ap.parse_args()

    ort_model = ORTModelForSequenceClassification.from_pretrained(str(args.src), export=True)
    tokenizer = AutoTokenizer.from_pretrained(str(args.src))
    args.dst.mkdir(parents=True, exist_ok=True)
    ort_model.save_pretrained(str(args.dst))
    tokenizer.save_pretrained(str(args.dst))
    metrics = args.src / "metrics.json"
    if metrics.exists():
        shutil.copy(metrics, args.dst / "metrics.json")
    for f in sorted(args.dst.iterdir()):
        print(f"  {f.name}: {f.stat().st_size / 1024:.1f} KB")


if __name__ == "__main__":
    main()
