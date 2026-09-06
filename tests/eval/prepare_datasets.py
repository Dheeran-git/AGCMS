"""Build the evaluation corpora under tests/eval/data/.

Sources
-------
Injection (binary, 1 = injection/jailbreak). Each row keeps the publisher's
``split`` so a fine-tuned classifier can train on ``train`` rows and be
scored on held-out ``test`` rows only:
  deepset/prompt-injections           published, 662 rows (train+test)
  jackhhao/jailbreak-classification   published, DAN-style jailbreaks vs benign
  agcms-injection/ml/data             AGCMS template-generated set (kept as a
                                      separate source so its effect is visible)
  AdvBench harmful_behaviors.csv      from github.com/llm-attacks/llm-attacks;
                                      harmful *requests*, not injections; kept
                                      as its own slice for discussion only

PII (entity spans):
  faker-synthetic                     600 prompts from tests/eval/pii_synth.py
  ai4privacy/pii-masking-200k         400 English rows, labels mapped to AGCMS
                                      types; unmapped labels are dropped from
                                      gold so they never count as misses
  benign negatives                    prompts labelled 0 from the injection
                                      sources, used for the false-positive rate

Injection hard negatives (training only, never evaluated):
  pii-hard-negative                   600 PII-bearing benign prompts, Faker seed
                                      4242 with templates disjoint from the eval set

Response (LLM output compliance):
  synthetic                           240 prompt/response pairs

Usage:  python tests/eval/prepare_datasets.py
"""

from __future__ import annotations

import json
import pathlib
import random
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from datasets import load_dataset  # noqa: E402

import pii_synth  # noqa: E402
import response_synth  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
DATA = pathlib.Path(__file__).resolve().parent / "data"
SEED = 42

AI4P_MAP = {
    "EMAIL": "EMAIL", "PHONENUMBER": "PHONE_US", "PHONE_NUMBER": "PHONE_US",
    "SSN": "SSN", "CREDITCARDNUMBER": "CREDIT_CARD", "IBAN": "IBAN",
    "IPV4": "IP_ADDRESS", "IP": "IP_ADDRESS", "IPV6": "IPV6_ADDRESS",
    "MAC": "MAC_ADDRESS", "DOB": "DATE_OF_BIRTH", "DATE_OF_BIRTH": "DATE_OF_BIRTH",
    "FIRSTNAME": "PERSON_NAME", "LASTNAME": "PERSON_NAME", "MIDDLENAME": "PERSON_NAME",
    "FULLNAME": "PERSON_NAME", "NAME": "PERSON_NAME", "PREFIX": None,
}


def _write(name: str, rows: list[dict]) -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    with open(DATA / name, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"{name}: {len(rows)} rows")


def build_injection() -> list[dict]:
    rows: list[dict] = []
    ds = load_dataset("deepset/prompt-injections")
    for split in ds:
        for r in ds[split]:
            rows.append({"text": r["text"], "label": int(r["label"]), "source": "deepset",
                         "split": split})
    ds = load_dataset("jackhhao/jailbreak-classification")
    for split in ds:
        for r in ds[split]:
            rows.append({"text": r["prompt"], "label": int(r["type"] == "jailbreak"),
                         "source": "jackhhao", "split": split})
    for fname, label in (("injection_samples.jsonl", 1), ("benign_samples.jsonl", 0)):
        with open(ROOT / "agcms-injection" / "ml" / "data" / fname, encoding="utf-8") as f:
            for line in f:
                rows.append({"text": json.loads(line)["text"], "label": label,
                             "source": "agcms-synthetic", "split": "train"})
    for goal in _advbench_goals():
        rows.append({"text": goal, "label": 1, "source": "advbench", "split": "test"})
    return [r for r in rows if r["text"] and r["text"].strip()]


ADVBENCH_URL = ("https://raw.githubusercontent.com/llm-attacks/llm-attacks/main/"
                "data/advbench/harmful_behaviors.csv")


def _advbench_goals() -> list[str]:
    import csv
    import io
    import urllib.request

    with urllib.request.urlopen(ADVBENCH_URL, timeout=60) as resp:
        text = resp.read().decode("utf-8")
    return [row["goal"] for row in csv.DictReader(io.StringIO(text)) if row.get("goal")]


def _spans_from_mask(mask) -> list[dict]:
    if isinstance(mask, str):
        mask = json.loads(mask)
    spans = []
    for m in mask or []:
        label = str(m.get("label", "")).upper()
        mapped = AI4P_MAP.get(label)
        if mapped:
            spans.append({"start": int(m["start"]), "end": int(m["end"]), "type": mapped})
    return spans


def build_pii(benign_texts: list[str]) -> list[dict]:
    rows = pii_synth.generate(600, seed=SEED)
    ds = load_dataset("ai4privacy/pii-masking-200k", split="train", streaming=True)
    taken = 0
    for r in ds:
        if str(r.get("language", "en")).lower() not in ("en", "english"):
            continue
        spans = _spans_from_mask(r.get("privacy_mask"))
        if not spans:
            continue
        text = r["source_text"]
        if not all(text[s["start"]:s["end"]] for s in spans):
            continue
        rows.append({"text": text, "spans": spans, "label": 1, "source": "ai4privacy"})
        taken += 1
        if taken >= 400:
            break
    random.seed(SEED)
    for text in random.sample(benign_texts, k=min(600, len(benign_texts))):
        rows.append({"text": text, "spans": [], "label": 0, "source": "benign"})
    return rows


def build_hard_negatives() -> list[dict]:
    """PII-bearing benign prompts for injection-classifier training only.

    Different Faker seed and disjoint templates from the PII evaluation set,
    labelled 0 (not an injection). Never used for evaluation.
    """
    rows = pii_synth.generate(600, seed=4242, templates=pii_synth.TRAIN_TEMPLATES)
    return [{"text": r["text"], "label": 0, "source": "pii-hard-negative", "split": "train"}
            for r in rows]


def main() -> None:
    _write("injection_hard_negatives.jsonl", build_hard_negatives())
    injection = build_injection()
    _write("injection.jsonl", injection)
    benign = [r["text"] for r in injection if r["label"] == 0 and r["source"] != "agcms-synthetic"]
    _write("pii.jsonl", build_pii(benign))
    _write("response.jsonl", response_synth.generate(240, seed=SEED))


if __name__ == "__main__":
    main()
