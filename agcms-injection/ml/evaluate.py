"""Evaluate trained model on test set.

Usage: python evaluate.py
Reports F1, precision, recall, FPR, and confusion matrix.
"""

import json
import pathlib
import numpy as np
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from datasets import Dataset
from transformers import AutoModelForSequenceClassification, AutoTokenizer, pipeline

DATA_DIR = pathlib.Path(__file__).parent / "data"
MODEL_DIR = pathlib.Path(__file__).parent / "model" / "best"
SEED = 42


def load_test_split():
    """Load data and return test split (last 10%)."""
    samples = []
    for path in [DATA_DIR / "injection_samples.jsonl", DATA_DIR / "benign_samples.jsonl"]:
        with open(path, encoding="utf-8") as f:
            for line in f:
                samples.append(json.loads(line))

    np.random.seed(SEED)
    np.random.shuffle(samples)

    val_end = int(0.9 * len(samples))
    test_samples = samples[val_end:]
    return [s["text"] for s in test_samples], [s["label"] for s in test_samples]


def main():
    texts, labels = load_test_split()
    print(f"Test set: {len(texts)} samples ({sum(labels)} injection, {len(labels) - sum(labels)} benign)")

    print(f"Loading model from {MODEL_DIR}")
    clf = pipeline("text-classification", model=str(MODEL_DIR), tokenizer=str(MODEL_DIR))

    # Predict
    preds = []
    for result in clf(texts, batch_size=32, truncation=True, max_length=128):
        # LABEL_1 = injection, LABEL_0 = benign
        preds.append(1 if result["label"] == "LABEL_1" else 0)

    labels_arr = np.array(labels)
    preds_arr = np.array(preds)

    # Metrics
    f1 = f1_score(labels_arr, preds_arr, pos_label=1)
    prec = precision_score(labels_arr, preds_arr, pos_label=1)
    rec = recall_score(labels_arr, preds_arr, pos_label=1)

    # False positive rate
    tn, fp, fn, tp = confusion_matrix(labels_arr, preds_arr).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print(f"\n{'='*50}")
    print(f"F1:        {f1:.4f}  (target > 0.88)")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"FPR:       {fpr:.4f}  (target < 0.05)")
    print(f"{'='*50}")
    print(f"\nConfusion Matrix:")
    print(f"  TN={tn}  FP={fp}")
    print(f"  FN={fn}  TP={tp}")
    print(f"\n{classification_report(labels_arr, preds_arr, target_names=['BENIGN', 'INJECTION'])}")

    # Targets
    if f1 > 0.88:
        print("F1 target MET")
    else:
        print(f"F1 target NOT MET ({f1:.4f} < 0.88)")

    if fpr < 0.05:
        print("FPR target MET")
    else:
        print(f"FPR target NOT MET ({fpr:.4f} >= 0.05)")


if __name__ == "__main__":
    main()
