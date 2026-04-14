"""Train DistilBERT binary classifier for injection detection.

Usage: python train.py
Output: ./model/checkpoint-best/ (PyTorch) and metrics.
"""

import json
import pathlib
import numpy as np
from sklearn.metrics import f1_score, precision_score, recall_score
from datasets import Dataset
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    Trainer,
    TrainingArguments,
)

DATA_DIR = pathlib.Path(__file__).parent / "data"
MODEL_DIR = pathlib.Path(__file__).parent / "model"
BASE_MODEL = "distilbert-base-uncased"
SEED = 42


def load_data():
    """Load injection + benign JSONL files and split 80/10/10."""
    samples = []
    for path in [DATA_DIR / "injection_samples.jsonl", DATA_DIR / "benign_samples.jsonl"]:
        with open(path, encoding="utf-8") as f:
            for line in f:
                samples.append(json.loads(line))

    np.random.seed(SEED)
    np.random.shuffle(samples)

    texts = [s["text"] for s in samples]
    labels = [s["label"] for s in samples]

    n = len(texts)
    train_end = int(0.8 * n)
    val_end = int(0.9 * n)

    return {
        "train": Dataset.from_dict({"text": texts[:train_end], "label": labels[:train_end]}),
        "val": Dataset.from_dict({"text": texts[train_end:val_end], "label": labels[train_end:val_end]}),
        "test": Dataset.from_dict({"text": texts[val_end:], "label": labels[val_end:]}),
    }


def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    return {
        "f1": f1_score(labels, preds, pos_label=1),
        "precision": precision_score(labels, preds, pos_label=1),
        "recall": recall_score(labels, preds, pos_label=1),
    }


def main():
    print(f"Loading data from {DATA_DIR}")
    splits = load_data()
    print(f"Train: {len(splits['train'])}, Val: {len(splits['val'])}, Test: {len(splits['test'])}")

    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(
        BASE_MODEL, num_labels=2, low_cpu_mem_usage=True,
    )

    def tokenize(batch):
        return tokenizer(batch["text"], truncation=True, padding="max_length", max_length=128)

    train_ds = splits["train"].map(tokenize, batched=True)
    val_ds = splits["val"].map(tokenize, batched=True)

    output_dir = str(MODEL_DIR / "checkpoints")

    args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=5,
        per_device_train_batch_size=16,
        per_device_eval_batch_size=32,
        learning_rate=2e-5,
        warmup_steps=100,
        weight_decay=0.01,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        seed=SEED,
        logging_steps=50,
        report_to="none",
        dataloader_pin_memory=False,
        dataloader_num_workers=0,
        use_cpu=True,
    )

    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        compute_metrics=compute_metrics,
        processing_class=tokenizer,
    )

    print("Training...")
    trainer.train()

    # Save best model
    best_dir = str(MODEL_DIR / "best")
    trainer.save_model(best_dir)
    tokenizer.save_pretrained(best_dir)
    print(f"Best model saved to {best_dir}")

    # Evaluate on test set
    test_ds = splits["test"].map(tokenize, batched=True)
    results = trainer.evaluate(test_ds)
    print(f"\nTest results: {results}")

    # Save metrics
    metrics_path = MODEL_DIR / "metrics.json"
    with open(metrics_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Metrics saved to {metrics_path}")


if __name__ == "__main__":
    main()
