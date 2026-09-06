"""Fine-tune DistilBERT as an AGCMS prompt-injection classifier.

Trains on the ``train`` rows of tests/eval/data/injection.jsonl (deepset +
jackhhao publisher train splits + the AGCMS template set) and reports on the
publisher ``test`` rows only, so the numbers are held-out. AdvBench rows are
excluded from both (they are harmful requests, not injections).

Usage:  python agcms-injection/ml/train.py [--epochs 3] [--max-length 256]
                                          [--seed 42] [--out ml/model/best]
Output: <out>/                 PyTorch checkpoint + tokenizer
        <out>/metrics.json     held-out metrics, seed and row counts
"""

from __future__ import annotations

import argparse
import json
import pathlib

import numpy as np
from datasets import Dataset
from sklearn.metrics import f1_score, precision_score, recall_score
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    Trainer,
    TrainingArguments,
)

ROOT = pathlib.Path(__file__).resolve().parents[2]
DATA = ROOT / "tests" / "eval" / "data" / "injection.jsonl"
MODEL_DIR = pathlib.Path(__file__).resolve().parent / "model"
BASE_MODEL = "distilbert-base-uncased"
SEED = 42


def load_splits() -> tuple[Dataset, Dataset]:
    rows = [json.loads(l) for l in open(DATA, encoding="utf-8")]
    rows = [r for r in rows if r["source"] != "advbench"]
    train = [r for r in rows if r["split"] == "train"]
    test = [r for r in rows if r["split"] == "test"]
    to_ds = lambda rs: Dataset.from_dict({"text": [r["text"] for r in rs],
                                          "label": [r["label"] for r in rs]})
    return to_ds(train), to_ds(test)


def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    return {
        "f1": f1_score(labels, preds, pos_label=1),
        "precision": precision_score(labels, preds, pos_label=1),
        "recall": recall_score(labels, preds, pos_label=1),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--max-length", type=int, default=256)
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--out", type=pathlib.Path, default=MODEL_DIR / "best")
    args = ap.parse_args()

    train_ds, test_ds = load_splits()
    print(f"train={len(train_ds)} test={len(test_ds)}")

    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(BASE_MODEL, num_labels=2)

    def tokenize(batch):
        return tokenizer(batch["text"], truncation=True, max_length=args.max_length)

    train_tok = train_ds.map(tokenize, batched=True)
    test_tok = test_ds.map(tokenize, batched=True)

    targs = TrainingArguments(
        output_dir=str(args.out.parent / f"checkpoints-{args.seed}"),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=16,
        per_device_eval_batch_size=32,
        learning_rate=2e-5,
        warmup_ratio=0.06,
        weight_decay=0.01,
        eval_strategy="epoch",
        save_strategy="no",
        seed=args.seed,
        logging_steps=50,
        report_to="none",
        dataloader_num_workers=0,
        use_cpu=True,
    )
    trainer = Trainer(model=model, args=targs, train_dataset=train_tok, eval_dataset=test_tok,
                      compute_metrics=compute_metrics, processing_class=tokenizer)
    trainer.train()

    trainer.save_model(str(args.out))
    tokenizer.save_pretrained(str(args.out))

    results = trainer.evaluate(test_tok)
    results.update({"seed": args.seed, "epochs": args.epochs, "max_length": args.max_length,
                    "train_rows": len(train_ds), "test_rows": len(test_ds)})
    (args.out / "metrics.json").write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
