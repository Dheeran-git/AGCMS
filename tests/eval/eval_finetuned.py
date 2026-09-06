"""Compare the fine-tuned DistilBERT with the off-the-shelf DeBERTa classifier.

Both models are scored on the same held-out rows: the publisher ``test``
splits of deepset and jackhhao (AdvBench excluded). The DeBERTa model is
scored through the production ``InjectionAgent`` path; DistilBERT is loaded
from ``agcms-injection/ml/model/best`` produced by ``ml/train.py``.

Usage:  python tests/eval/eval_finetuned.py
"""

from __future__ import annotations

import json
import pathlib
import sys
import time

import numpy as np
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "agcms-injection"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from metrics import binary_metrics, latency_summary  # noqa: E402

from agcms.injection.agent import InjectionAgent  # noqa: E402

DATA = pathlib.Path(__file__).resolve().parent / "data" / "injection.jsonl"
BEST = ROOT / "agcms-injection" / "ml" / "model" / "best"
RESULTS = pathlib.Path(__file__).resolve().parent / "results"


def main() -> None:
    rows = [json.loads(l) for l in open(DATA, encoding="utf-8")]
    test = [r for r in rows if r["split"] == "test" and r["source"] != "advbench"]
    gold = [r["label"] for r in test]
    print(f"held-out test rows: {len(test)} ({sum(gold)} positive)")

    tok = AutoTokenizer.from_pretrained(str(BEST))
    model = AutoModelForSequenceClassification.from_pretrained(str(BEST)).eval()
    ft_pred, ft_lat = [], []
    for r in test:
        t0 = time.perf_counter()
        with torch.no_grad():
            enc = tok(r["text"], return_tensors="pt", truncation=True, max_length=256)
            prob = torch.softmax(model(**enc).logits, dim=-1)[0, 1].item()
        ft_lat.append((time.perf_counter() - t0) * 1000)
        ft_pred.append(int(prob >= 0.5))

    agent = InjectionAgent()
    assert agent._onnx_session is not None, "DeBERTa classifier did not load"
    ots_pred, ots_lat = [], []
    for r in test:
        t0 = time.perf_counter()
        score = agent._ml_classify(r["text"]) or 0.0
        ots_lat.append((time.perf_counter() - t0) * 1000)
        ots_pred.append(int(score >= 0.5))

    def by_source(pred):
        out = {}
        for src in sorted({r["source"] for r in test}):
            idx = [i for i, r in enumerate(test) if r["source"] == src]
            out[src] = binary_metrics([gold[i] for i in idx], [pred[i] for i in idx])
        return out

    report = {
        "test_rows": len(test),
        "distilbert_finetuned": {"overall": binary_metrics(gold, ft_pred), "by_source": by_source(ft_pred),
                                 "latency": latency_summary(ft_lat), "max_length": 256},
        "deberta_protectai": {"overall": binary_metrics(gold, ots_pred), "by_source": by_source(ots_pred),
                              "latency": latency_summary(ots_lat), "max_length": 512},
    }
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "finetuned_vs_offtheshelf.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("| Model | P | R | F1 | FPR | median ms | p95 ms |")
    print("|---|---|---|---|---|---|---|")
    for name in ("distilbert_finetuned", "deberta_protectai"):
        m, l = report[name]["overall"], report[name]["latency"]
        print(f"| {name} | {m['precision']} | {m['recall']} | {m['f1']} | {m['fpr']} | {l['median_ms']} | {l['p95_ms']} |")
    for name in ("distilbert_finetuned", "deberta_protectai"):
        print(name, {k: (v["recall"], v["fpr"]) for k, v in report[name]["by_source"].items()})


if __name__ == "__main__":
    main()
