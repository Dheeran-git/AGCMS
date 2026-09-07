"""AGCMS evaluation harness.

Drives the four detection modules in-process on the corpora produced by
``prepare_datasets.py`` and reports per-module precision / recall / F1 /
false-positive rate, per-module latency, an ablation over detection layers,
and two baselines (keyword-only, unguarded). Every number in the paper's
results section is produced by this script.

Usage:
    python tests/eval/run_eval.py                 # full run, writes results/
    python tests/eval/run_eval.py --limit 200     # quick smoke run

Environment: AGCMS_ML_ENABLED controls whether the DeBERTa classifier loads.
The ablation forces each configuration explicitly, so leave it at "true".
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import pathlib
import platform
import sys
import time
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[2]
for svc in ("common", "pii", "injection", "response", "policy"):
    sys.path.insert(0, str(ROOT / f"agcms-{svc}"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
os.environ.setdefault("AGCMS_DEFAULT_POLICY", str(ROOT / "policies" / "default.yaml"))

from metrics import binary_metrics, latency_summary, span_metrics  # noqa: E402

from agcms.injection.agent import InjectionAgent  # noqa: E402
from agcms.pii.agent import PIIAgent  # noqa: E402
from agcms.policy.resolver import PolicyResolver  # noqa: E402
from agcms.response.agent import ResponseComplianceAgent  # noqa: E402

DATA = pathlib.Path(__file__).resolve().parent / "data"
RESULTS = pathlib.Path(__file__).resolve().parent / "results"

# Keyword-only baseline: what a naive filter would do, no normalisation.
KEYWORDS = ["ignore previous", "ignore all previous", "disregard", "jailbreak", "dan mode",
            "developer mode", "system prompt", "pretend you are", "you are now",
            "forget your", "new instructions", "bypass", "no restrictions"]


GOLD_TYPES = {"EMAIL", "PHONE_US", "SSN", "CREDIT_CARD", "AADHAAR", "PAN", "IBAN", "DATE_OF_BIRTH",
              "IP_ADDRESS", "MRN", "PERSON_NAME", "IPV6_ADDRESS", "MAC_ADDRESS"}


def load(name: str, limit: int | None) -> list[dict]:
    rows = [json.loads(l) for l in open(DATA / name, encoding="utf-8")]
    return rows[:limit] if limit else rows


def timed(fn, *args):
    t0 = time.perf_counter()
    out = fn(*args)
    return out, (time.perf_counter() - t0) * 1000.0


# --------------------------------------------------------------------------
# PII
# --------------------------------------------------------------------------

def eval_pii(rows: list[dict], agent: PIIAgent, mode: str) -> dict:
    """mode: 'full' | 'regex' | 'ner'."""
    regex_scan, ner_scan = agent._regex_scan, agent._ner_scan
    if mode == "regex":
        agent._ner_scan = lambda text: []
    if mode == "ner":
        agent._regex_scan = lambda text, policy: []
    gold_flags, pred_flags, gold_spans, pred_spans, lat = [], [], [], [], []
    try:
        for r in rows:
            result, ms = timed(lambda t: asyncio.run(agent.scan(t, {})), r["text"])
            lat.append(ms)
            gold_flags.append(r["label"])
            pred_flags.append(int(result.has_pii))
            if r["label"] == 1:
                gold_spans.append(r["spans"])
                # Entity-level scoring only covers types the gold corpora
                # label; ORGANIZATION predictions are neither right nor wrong.
                pred_spans.append([{"start": e.start, "end": e.end, "type": e.entity_type}
                                   for e in result.entities if e.entity_type in GOLD_TYPES])
    finally:
        agent._regex_scan, agent._ner_scan = regex_scan, ner_scan
    by_source = {}
    for src in sorted({r["source"] for r in rows}):
        idx = [i for i, r in enumerate(rows) if r["source"] == src]
        by_source[src] = binary_metrics([gold_flags[i] for i in idx], [pred_flags[i] for i in idx])
    return {"prompt_level": binary_metrics(gold_flags, pred_flags),
            "entity_level": span_metrics(gold_spans, pred_spans),
            "by_source": by_source, "latency": latency_summary(lat)}


# --------------------------------------------------------------------------
# Injection
# --------------------------------------------------------------------------

def _keyword_baseline(text: str) -> int:
    low = text.lower()
    return int(any(k in low for k in KEYWORDS))


def eval_injection(rows: list[dict], agent: InjectionAgent, resolver: PolicyResolver) -> dict:
    """Score every prompt once and derive all configurations from that pass.

    Returns a dict keyed by config: unguarded, keyword, heuristic, ml, full.
    The ML model is the expensive part, so it runs exactly once per prompt;
    ``full`` = max(heuristic, ml) exactly as the agent computes it.
    """
    session = agent._onnx_session
    configs = ("unguarded", "keyword", "heuristic", "ml", "full")
    gold = []
    pred = {c: ([], []) for c in configs}        # (module flags, policy flags)
    lat = {c: [] for c in configs}
    try:
        for r in rows:
            text = r["text"]
            gold.append(r["label"])

            kw, ms_kw = timed(_keyword_baseline, text)
            agent._onnx_session = None
            heur, ms_h = timed(agent.scan, text)
            agent._onnx_session = session
            ml_score, ms_ml = timed(agent._ml_classify, text)
            ml_score = ml_score or 0.0

            heur_dict = heur.to_dict()
            ml_dict = {"risk_score": ml_score, "triggered_rules": [], "attack_type": None}
            full_dict = dict(heur_dict)
            full_dict["risk_score"] = round(max(heur.risk_score, ml_score), 3)

            def flags(module_flag: int, scan: dict | None) -> tuple[int, int]:
                if scan is None:
                    return module_flag, module_flag
                decision = resolver.resolve(None, scan)
                return module_flag, int(decision.action in ("BLOCK", "ESCALATE"))

            results = {
                "unguarded": (flags(0, None), 0.0),
                "keyword": (flags(kw, None), ms_kw),
                "heuristic": (flags(int(heur.is_injection), heur_dict), ms_h),
                "ml": (flags(int(ml_score >= 0.5), ml_dict), ms_ml),
                "full": (flags(int(full_dict["risk_score"] >= 0.5), full_dict), ms_h + ms_ml),
            }
            for c, ((m, p), ms) in results.items():
                pred[c][0].append(m)
                pred[c][1].append(p)
                lat[c].append(ms)
    finally:
        agent._onnx_session = session

    core_idx = [i for i, r in enumerate(rows) if r["source"] != "advbench"]
    # Publisher test splits only: the rows the fine-tuned classifier never saw.
    held_idx = [i for i in core_idx if rows[i].get("split") == "test"]
    out = {}
    for c in configs:
        module, policy = pred[c]
        by_source = {}
        for src in sorted({r["source"] for r in rows}):
            idx = [i for i, r in enumerate(rows) if r["source"] == src]
            by_source[src] = binary_metrics([gold[i] for i in idx], [module[i] for i in idx])
        out[c] = {"module_level": binary_metrics([gold[i] for i in core_idx], [module[i] for i in core_idx]),
                  "policy_level": binary_metrics([gold[i] for i in core_idx], [policy[i] for i in core_idx]),
                  "held_out": binary_metrics([gold[i] for i in held_idx], [module[i] for i in held_idx]),
                  "by_source": by_source, "latency": latency_summary(lat[c])}
    return out


def eval_ml_on_pii_prompts(pii_rows: list[dict], agent: InjectionAgent) -> dict:
    """Share of PII-bearing (non-injection) prompts the ML layer scores as an
    injection, at the module threshold (0.5) and the policy's ML-only block
    threshold (0.95). The injection corpus's benign rows carry almost no PII,
    so this is the hard-negative check the headline FPR misses."""
    out = {}
    for src in sorted({r["source"] for r in pii_rows}):
        scores = [agent._ml_classify(r["text"]) or 0.0 for r in pii_rows if r["source"] == src]
        out[src] = {"n": len(scores),
                    "flagged_at_0_5": round(sum(x >= 0.5 for x in scores) / len(scores), 4),
                    "flagged_at_0_95": round(sum(x >= 0.95 for x in scores) / len(scores), 4)}
    return out


# --------------------------------------------------------------------------
# Response compliance
# --------------------------------------------------------------------------

def eval_response(rows: list[dict], agent: ResponseComplianceAgent) -> dict:
    from response_synth import POLICY
    gold, pred, lat = [], [], []
    per_rule = {"PII_ECHO": ([], []), "SYSTEM_PROMPT_LEAK": ([], []), "RESTRICTED_TOPIC": ([], [])}
    for r in rows:
        result, ms = timed(agent.check, r["response"], r["prompt"], POLICY)
        lat.append(ms)
        gold.append(r["label"])
        pred.append(int(result.violated))
        found = {v.rule for v in result.violations}
        found = {"SYSTEM_PROMPT_LEAK" if f == "SYSTEM_PROMPT_KEYWORD" else f for f in found}
        for rule, (g, p) in per_rule.items():
            g.append(int(rule in r["gold"]))
            p.append(int(rule in found))
    return {"response_level": binary_metrics(gold, pred),
            "per_rule": {k: binary_metrics(g, p) for k, (g, p) in per_rule.items()},
            "latency": latency_summary(lat)}


# --------------------------------------------------------------------------
# Policy resolver
# --------------------------------------------------------------------------

def eval_policy(resolver: PolicyResolver) -> dict:
    """Latency of resolution and a truth table over representative inputs."""
    cases = [
        ("clean", None, None, "ALLOW"),
        ("pii-medium", {"has_pii": True, "risk_level": "MEDIUM"}, None, "REDACT"),
        ("pii-critical", {"has_pii": True, "risk_level": "CRITICAL"}, None, "BLOCK"),
        ("injection-rules", None, {"risk_score": 0.9, "triggered_rules": [{"name": "x"}]}, "BLOCK"),
        ("injection-ml-only-low", None, {"risk_score": 0.7, "triggered_rules": []}, "ALLOW"),
        ("injection-ml-only-high", None, {"risk_score": 0.97, "triggered_rules": []}, "BLOCK"),
    ]
    lat, table, correct = [], [], 0
    for name, pii, inj, expected in cases:
        for _ in range(200):
            decision, ms = timed(resolver.resolve, pii, inj)
            lat.append(ms)
        table.append({"case": name, "expected": expected, "got": decision.action})
        correct += int(decision.action == expected)
    return {"truth_table": table, "correct": correct, "total": len(cases),
            "latency": latency_summary(lat)}


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    pii_rows = load("pii.jsonl", args.limit)
    inj_rows = load("injection.jsonl", args.limit)
    resp_rows = load("response.jsonl", args.limit)

    pii_agent = PIIAgent()
    inj_agent = InjectionAgent()
    resp_agent = ResponseComplianceAgent()
    resolver = PolicyResolver()
    ml_loaded = inj_agent._onnx_session is not None
    print(f"PII rows={len(pii_rows)} injection rows={len(inj_rows)} response rows={len(resp_rows)} "
          f"ml_classifier={'loaded' if ml_loaded else 'MISSING'}")

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "machine": {"platform": platform.platform(), "python": platform.python_version(),
                    "cpu": platform.processor(), "ml_classifier_loaded": ml_loaded},
        "corpus_sizes": {"pii": len(pii_rows), "injection": len(inj_rows), "response": len(resp_rows)},
        "pii": {m: eval_pii(pii_rows, pii_agent, m) for m in ("regex", "ner", "full")},
        "injection": eval_injection(inj_rows, inj_agent, resolver),
        "ml_on_pii_prompts": eval_ml_on_pii_prompts(pii_rows, inj_agent) if ml_loaded else {},
        "response": eval_response(resp_rows, resp_agent),
        "policy": eval_policy(resolver),
    }

    RESULTS.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = RESULTS / f"eval_{stamp}.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    (RESULTS / "latest.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(render_markdown(report))
    print(f"\nwritten {out}")


def render_markdown(r: dict) -> str:
    lines = ["## PII detection", "",
             "| Config | Prompt P | Prompt R | Prompt FPR | Entity P | Entity R | Entity F1 | median ms |",
             "|---|---|---|---|---|---|---|---|"]
    for m in ("regex", "ner", "full"):
        p, e, l = r["pii"][m]["prompt_level"], r["pii"][m]["entity_level"], r["pii"][m]["latency"]
        lines.append(f"| {m} | {p['precision']} | {p['recall']} | {p['fpr']} | {e['precision']} | "
                     f"{e['recall']} | {e['f1']} | {l['median_ms']} |")
    lines += ["", "## Injection detection (advbench slice excluded)", "",
              "| Config | P | R | F1 | FPR | Policy-level F1 | median ms |", "|---|---|---|---|---|---|---|"]
    for m in ("unguarded", "keyword", "heuristic", "ml", "full"):
        a, b, l = r["injection"][m]["module_level"], r["injection"][m]["policy_level"], r["injection"][m]["latency"]
        lines.append(f"| {m} | {a['precision']} | {a['recall']} | {a['f1']} | {a['fpr']} | {b['f1']} | {l['median_ms']} |")
    lines += ["", "## Injection detection, held-out publisher test rows only (never used in training)", "",
              "| Config | n | P | R | F1 | FPR |", "|---|---|---|---|---|---|"]
    for m in ("keyword", "heuristic", "ml", "full"):
        h = r["injection"][m]["held_out"]
        lines.append(f"| {m} | {h['n']} | {h['precision']} | {h['recall']} | {h['f1']} | {h['fpr']} |")
    lines += ["", "## Injection recall by source (full config)", "", "| Source | n | recall | FPR |", "|---|---|---|---|"]
    for src, m in r["injection"]["full"]["by_source"].items():
        lines.append(f"| {src} | {m['n']} | {m['recall']} | {m['fpr']} |")
    if r.get("ml_on_pii_prompts"):
        lines += ["", "## ML classifier on PII-bearing prompts (no injections present)", "",
                  "| Source | n | flagged >=0.5 | flagged >=0.95 |", "|---|---|---|---|"]
        for src, m in r["ml_on_pii_prompts"].items():
            lines.append(f"| {src} | {m['n']} | {m['flagged_at_0_5']} | {m['flagged_at_0_95']} |")
    resp = r["response"]
    lines += ["", "## Response compliance", "", "| Rule | P | R | F1 |", "|---|---|---|---|"]
    for k, m in resp["per_rule"].items():
        lines.append(f"| {k} | {m['precision']} | {m['recall']} | {m['f1']} |")
    lines.append(f"| overall | {resp['response_level']['precision']} | {resp['response_level']['recall']} | "
                 f"{resp['response_level']['f1']} |")
    pol = r["policy"]
    lines += ["", f"## Policy resolver: {pol['correct']}/{pol['total']} truth-table cases correct, "
              f"median {pol['latency']['median_ms']} ms"]
    return "\n".join(lines)


if __name__ == "__main__":
    main()
