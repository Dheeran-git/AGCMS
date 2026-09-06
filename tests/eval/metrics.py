"""Small metric helpers shared by the evaluation runner."""

from __future__ import annotations

import statistics


def binary_metrics(gold: list[int], pred: list[int]) -> dict:
    """Precision, recall, F1, false-positive rate and accuracy for 0/1 labels."""
    tp = sum(1 for g, p in zip(gold, pred) if g == 1 and p == 1)
    fp = sum(1 for g, p in zip(gold, pred) if g == 0 and p == 1)
    fn = sum(1 for g, p in zip(gold, pred) if g == 1 and p == 0)
    tn = sum(1 for g, p in zip(gold, pred) if g == 0 and p == 0)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    acc = (tp + tn) / len(gold) if gold else 0.0
    return {"n": len(gold), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 4), "recall": round(recall, 4),
            "f1": round(f1, 4), "fpr": round(fpr, 4), "accuracy": round(acc, 4)}


def span_metrics(gold_spans: list[list[dict]], pred_spans: list[list[dict]]) -> dict:
    """Entity-level metrics: a prediction is correct if it overlaps a gold span
    of the same type. Each gold span can be matched at most once."""
    tp = fp = fn = 0
    per_type: dict[str, dict] = {}
    for gold, pred in zip(gold_spans, pred_spans):
        matched = set()
        for p in pred:
            hit = None
            for i, g in enumerate(gold):
                if i in matched or g["type"] != p["type"]:
                    continue
                if p["start"] < g["end"] and g["start"] < p["end"]:
                    hit = i
                    break
            bucket = per_type.setdefault(p["type"], {"tp": 0, "fp": 0, "fn": 0})
            if hit is None:
                fp += 1
                bucket["fp"] += 1
            else:
                matched.add(hit)
                tp += 1
                bucket["tp"] += 1
        for i, g in enumerate(gold):
            if i not in matched:
                fn += 1
                per_type.setdefault(g["type"], {"tp": 0, "fp": 0, "fn": 0})["fn"] += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    for t, b in per_type.items():
        p = b["tp"] / (b["tp"] + b["fp"]) if b["tp"] + b["fp"] else 0.0
        r = b["tp"] / (b["tp"] + b["fn"]) if b["tp"] + b["fn"] else 0.0
        b.update({"precision": round(p, 4), "recall": round(r, 4)})
    return {"tp": tp, "fp": fp, "fn": fn, "precision": round(precision, 4),
            "recall": round(recall, 4), "f1": round(f1, 4), "per_type": per_type}


def latency_summary(samples_ms: list[float]) -> dict:
    if not samples_ms:
        return {"n": 0}
    s = sorted(samples_ms)
    p95 = s[min(len(s) - 1, int(0.95 * len(s)))]
    return {"n": len(s), "median_ms": round(statistics.median(s), 2),
            "p95_ms": round(p95, 2), "mean_ms": round(statistics.mean(s), 2)}
