# AGCMS Evaluation

All accuracy, latency, ablation and baseline figures for AGCMS come from the
harness in `tests/eval/`. Nothing in this document is typed by hand; the
tables are pasted from `tests/eval/results/latest.json` via the markdown
printed by `run_eval.py`.

## Reproduce

```bash
# one-off: build the corpora (downloads public datasets from Hugging Face)
python tests/eval/prepare_datasets.py

# full run (loads spaCy + DeBERTa ONNX, takes a few minutes on CPU)
python tests/eval/run_eval.py
```

Requirements beyond the service dependencies: `datasets`, `faker`,
`transformers`, `optimum[onnxruntime]`, `torch` (CPU build is fine).

## Corpora

| Corpus | Source | Size | Gold label |
|---|---|---|---|
| Injection | deepset/prompt-injections | see `data/injection.jsonl` | 1 = injection |
| Injection | jackhhao/jailbreak-classification | | 1 = jailbreak |
| Injection | AGCMS template set (`agcms-injection/ml/data`) | | 1 = injection |
| Harmful requests | walledai/AdvBench | | reported as a separate slice; excluded from the headline injection metric because these are harmful requests, not instruction-override attacks |
| PII | Faker-generated prompts with exact spans | 600 | entity spans, 11 types |
| PII | ai4privacy/pii-masking-200k (English rows, labels mapped to AGCMS types) | 400 | entity spans |
| PII negatives | benign prompts from the injection sources | 600 | no PII |
| Response | synthetic prompt/response pairs | 240 | PII_ECHO / SYSTEM_PROMPT_LEAK / RESTRICTED_TOPIC / clean |

## Metrics

- **Prompt-level** precision, recall, F1 and false-positive rate: does the
  module flag the prompt at all.
- **Entity-level** precision and recall for PII: a predicted span counts if
  it overlaps a gold span of the same type. Unmapped ai4privacy labels
  (usernames, job titles, URLs) are removed from gold and never count as
  misses.
- **Module-level vs policy-level** for injection: module-level uses the
  agent's own threshold (risk score 0.5). Policy-level uses the default
  tenant policy in `policies/default.yaml`, which blocks on rule-corroborated
  scores above 0.65 or ML-only scores above 0.95.
- **Latency** is per-module, in-process, on the evaluation machine. It
  excludes the HTTP hop between gateway and module; the Locust load test in
  `tests/load/` measures end-to-end.

## Ablation

| Config | Meaning |
|---|---|
| PII `regex` | regex patterns only, NER disabled |
| PII `ner` | spaCy NER only, regex disabled |
| PII `full` | shipped configuration |
| Injection `unguarded` | never flags (baseline: no governance layer) |
| Injection `keyword` | 13 literal jailbreak phrases, no normalisation (baseline) |
| Injection `heuristic` | 20 regex rules with unicode/base64/hex/URL normalisation |
| Injection `ml` | DeBERTa classifier alone (`protectai/deberta-v3-base-prompt-injection-v2`) |
| Injection `full` | max(heuristic, ml), the shipped configuration |

## Results

Results are appended below by the maintainer after each run, together with
the machine description printed in the JSON report.

_No run recorded yet._
