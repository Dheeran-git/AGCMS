"""Compare fine-tuned DistilBERT checkpoints with the off-the-shelf DeBERTa.

All models are scored on the same held-out rows: the publisher ``test``
splits of deepset and jackhhao (AdvBench excluded). Each model is also scored
on the PII corpus, which contains no injections, to report the share of
PII-bearing enterprise prompts it would flag.

Usage:  python tests/eval/eval_finetuned.py [--models best seed1 seed2 seed3 seed1-hn ...]

``--models`` names sub-folders of ``agcms-injection/ml/model`` (default
``best``). The DeBERTa model is scored through the production
``InjectionAgent`` path when ``AGCMS_INJECTION_MODEL_DIR`` points at its
ONNX export. Groups of ``seedN`` and ``seedN-hn`` models get a mean and
standard deviation.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import statistics
import sys
import time

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "agcms-injection"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from metrics import binary_metrics, latency_summary  # noqa: E402

from agcms.injection.agent import InjectionAgent  # noqa: E402

DATA_DIR = pathlib.Path(__file__).resolve().parent / "data"
MODELS = ROOT / "agcms-injection" / "ml" / "model"
RESULTS = pathlib.Path(__file__).resolve().parent / "results"


def _torch_scorer(model_dir: pathlib.Path):
    tok = AutoTokenizer.from_pretrained(str(model_dir))
    model = AutoModelForSequenceClassification.from_pretrained(str(model_dir)).eval()

    def score(text: str) -> float:
        with torch.no_grad():
            enc = tok(text, return_tensors="pt", truncation=True, max_length=256)
            return torch.softmax(model(**enc).logits, dim=-1)[0, 1].item()
    return score


def _evaluate(name: str, score, test: list[dict], gold: list[int], pii_rows: list[dict]) -> dict:
    pred, lat = [], []
    for r in test:
        t0 = time.perf_counter()
        pred.append(int(score(r["text"]) >= 0.5))
        lat.append((time.perf_counter() - t0) * 1000)
    by_source = {}
    for src in sorted({r["source"] for r in test}):
        idx = [i for i, r in enumerate(test) if r["source"] == src]
        by_source[src] = binary_metrics([gold[i] for i in idx], [pred[i] for i in idx])
    pii_flags = {}
    for src in sorted({r["source"] for r in pii_rows}):
        sc = [score(r["text"]) for r in pii_rows if r["source"] == src]
        pii_flags[src] = {"n": len(sc),
                          "flagged_at_0_5": round(sum(x >= 0.5 for x in sc) / len(sc), 4),
                          "flagged_at_0_95": round(sum(x >= 0.95 for x in sc) / len(sc), 4)}
    print(f"  scored {name}")
    return {"overall": binary_metrics(gold, pred), "by_source": by_source,
            "latency": latency_summary(lat), "pii_prompts_flagged": pii_flags}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", default=["best"],
                    help="sub-folders of agcms-injection/ml/model")
    args = ap.parse_args()

    rows = [json.loads(l) for l in open(DATA_DIR / "injection.jsonl", encoding="utf-8")]
    test = [r for r in rows if r["split"] == "test" and r["source"] != "advbench"]
    gold = [r["label"] for r in test]
    pii_rows = [json.loads(l) for l in open(DATA_DIR / "pii.jsonl", encoding="utf-8")]
    print(f"held-out test rows: {len(test)} ({sum(gold)} positive); PII prompts: {len(pii_rows)}")

    report = {"test_rows": len(test), "models": {}}
    for name in args.models:
        entry = _evaluate(name, _torch_scorer(MODELS / name), test, gold, pii_rows)
        metrics_path = MODELS / name / "metrics.json"
        entry["training_metrics"] = json.loads(metrics_path.read_text()) if metrics_path.exists() else None
        report["models"][name] = entry

    agent = InjectionAgent()
    if agent._onnx_session is not None:
        report["models"]["deberta_protectai"] = _evaluate(
            "deberta_protectai", lambda t: agent._ml_classify(t) or 0.0, test, gold, pii_rows)

    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "classifier_comparison.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("\n| Model | P | R | F1 | FPR | PII prompts flagged >=0.95 (faker / ai4privacy) | median ms |")
    print("|---|---|---|---|---|---|---|")
    for name, m in report["models"].items():
        o, l, pf = m["overall"], m["latency"], m["pii_prompts_flagged"]
        fk = pf.get("faker-synthetic", {}).get("flagged_at_0_95")
        ai = pf.get("ai4privacy", {}).get("flagged_at_0_95")
        print(f"| {name} | {o['precision']} | {o['recall']} | {o['f1']} | {o['fpr']} | {fk} / {ai} | {l['median_ms']} |")

    groups: dict[str, list[float]] = {}
    for name, m in report["models"].items():
        if name.startswith("seed"):
            groups.setdefault("hard-negatives" if name.endswith("-hn") else "baseline", []).append(m["overall"]["f1"])
    for key, f1s in groups.items():
        if len(f1s) > 1:
            print(f"{key}: F1 mean {statistics.mean(f1s):.4f} sd {statistics.stdev(f1s):.4f} over {len(f1s)} seeds")


if __name__ == "__main__":
    main()
