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

### Run 2026-09-06 (commit 781c565)

Machine: Windows-11-10.0.26200-SP0, Intel64 Family 6 Model 186 Stepping 2, GenuineIntel, Python 3.12.12, CPU only, DeBERTa ONNX classifier loaded. Corpus sizes: PII 1600, injection 3505, response 240.

#### PII detection

| Config | Prompt P | Prompt R | Prompt FPR | Entity P | Entity R | Entity F1 | median ms | p95 ms |
|---|---|---|---|---|---|---|---|---|
| regex | 0.996 | 0.804 | 0.005 | 0.956 | 0.672 | 0.789 | 1.29 | 2.5 |
| ner | 0.518 | 0.250 | 0.388 | 0.803 | 0.138 | 0.235 | 11.68 | 31.52 |
| full | 0.794 | 0.912 | 0.393 | 0.926 | 0.810 | 0.864 | 10.61 | 26.93 |

Entity-level precision / recall by type (full config):

| Type | P | R | Type | P | R |
|---|---|---|---|---|---|
| AADHAAR | 0.988 | 1.000 | CREDIT_CARD | 0.876 | 0.748 |
| DATE_OF_BIRTH | 0.869 | 0.819 | EMAIL | 1.000 | 1.000 |
| IBAN | 1.000 | 1.000 | IPV6_ADDRESS | 0.689 | 1.000 |
| IP_ADDRESS | 1.000 | 0.915 | MAC_ADDRESS | 1.000 | 0.950 |
| MRN | 1.000 | 1.000 | PAN | 1.000 | 1.000 |
| PERSON_NAME | 0.803 | 0.587 | PHONE_US | 1.000 | 0.478 |
| SSN | 0.956 | 0.916 |  |  |  |

Prompt-level recall / FPR by source (full config): ai4privacy R=0.780 FPR=0.000, benign R=0.000 FPR=0.393, faker-synthetic R=1.000 FPR=0.000

#### Injection detection (AdvBench slice excluded from the headline)

| Config | P | R | F1 | FPR | Policy-level F1 | median ms | p95 ms |
|---|---|---|---|---|---|---|---|
| unguarded | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.0 | 0.0 |
| keyword | 0.998 | 0.291 | 0.451 | 0.001 | 0.451 | 0.0 | 0.05 |
| heuristic | 0.935 | 0.328 | 0.485 | 0.026 | 0.452 | 0.06 | 2.06 |
| ml | 0.993 | 0.758 | 0.860 | 0.006 | 0.842 | 253.48 | 1799.56 |
| full | 0.966 | 0.795 | 0.873 | 0.032 | 0.857 | 269.44 | 3073.05 |

Recall / FPR by source:

| Source | n | heuristic R | ml R | full R | full FPR |
|---|---|---|---|---|---|
| advbench | 520 | 0.000 | 0.000 | 0.000 | 0.000 |
| agcms-synthetic | 1017 | 0.387 | 0.826 | 0.871 | 0.000 |
| deepset | 662 | 0.038 | 0.414 | 0.418 | 0.010 |
| jackhhao | 1306 | 0.383 | 0.827 | 0.869 | 0.062 |

#### Response compliance

| Rule | P | R | F1 |
|---|---|---|---|
| PII_ECHO | 1.000 | 1.000 | 1.000 |
| SYSTEM_PROMPT_LEAK | 1.000 | 1.000 | 1.000 |
| RESTRICTED_TOPIC | 1.000 | 1.000 | 1.000 |
| overall | 1.000 | 1.000 | 1.000 |

Median response-check latency 0.02 ms. Policy resolver: 6/6 truth-table cases correct, median 0.0 ms.

#### Reading the numbers

- **The ML classifier carries injection detection.** Heuristics alone reach
  F1 0.485 (recall 0.33); the DeBERTa classifier alone reaches 0.860; the
  shipped max(heuristic, ml) combination reaches 0.873 with 3.2% false
  positives. The 13-keyword baseline is barely below the heuristic layer,
  which shows how little regex rules add over naive matching on this data.
- **Heuristics cost precision on roleplay.** 35 of the 36 jackhhao benign
  false positives come from the ROLEPLAY rules (31 `roleplay_pretend`,
  3 `roleplay_persona`, 1 `roleplay_you_are`) on prompts like "Pretend to
  be Elle Woods"; one comes from `multi_turn_remember`. The ML-only
  configuration has a 0.6% FPR.
- **deepset is hard for both layers** (recall 0.42): about half of it is
  German, and many attacks are one short imperative sentence.
- **AdvBench recall is 0 by design.** These are harmful *requests*, not
  instruction-override attacks; an injection detector should not flag them
  and the paper should say so rather than count them.
- **PII regex is precise; NER is noisy.** Regex alone: prompt-level
  precision 0.996, FPR 0.5%. Adding spaCy PERSON detection lifts entity
  recall from 0.67 to 0.81 but raises prompt-level FPR to 39%. Most of those
  "false positives" are benign prompts that really do contain names
  ("Pretend to be Scout from Team Fortress 2"), so the FPR here is partly a
  labelling artefact of using jailbreak-corpus benign prompts as PII
  negatives. Organisation names are no longer treated as PII.
- **Weak PII types:** PHONE_US recall 0.48 and CREDIT_CARD 0.75 on the
  ai4privacy rows, whose phone and card formats are international.
  PERSON_NAME recall 0.59 (single first names in ai4privacy).
- **Latency:** regex+NER PII 10.6 ms median; DeBERTa 253 ms median but
  1.8 s p95 on 512-token jailbreak prompts (CPU, no batching). The old
  claim of a 155 ms injection layer was not measured on this hardware.
- **Response checks are saturated** on the synthetic set (F1 1.0). The
  corpus is easy by construction; the paper should present it as a
  functional check, not a benchmark.

### Fine-tuned DistilBERT vs off-the-shelf DeBERTa (run 2026-09-06)

`agcms-injection/ml/train.py`, `distilbert-base-uncased`, 3 epochs, max
length 256, batch 16, lr 2e-5, seed 42, CPU. Training rows: 2,607 (deepset
train + jackhhao train + AGCMS template set). Both models scored by
`tests/eval/eval_finetuned.py` on the same 378 held-out publisher test rows
(199 injections). AdvBench excluded.

| Model | P | R | F1 | FPR | median ms | p95 ms |
|---|---|---|---|---|---|---|
| DistilBERT fine-tuned (ours) | 0.994 | 0.899 | 0.945 | 0.006 | 58 | 182 |
| DeBERTa protectai v2 (off the shelf) | 0.986 | 0.699 | 0.818 | 0.011 | 126 | 959 |

Recall by source: DistilBERT deepset 0.733, jackhhao 0.971; DeBERTa deepset
0.367, jackhhao 0.842.

Held-out F1 per epoch during training: 0.917, 0.958, 0.945. The shipped
checkpoint is the final epoch (no per-epoch checkpointing), so epoch 2 would
have been marginally better; the difference is within run-to-run noise
(an earlier identical run scored 0.904 after epoch 1 vs 0.917 here).

Caveats for the paper:
- DistilBERT trained on the publisher *train* splits of the same two
  corpora it is tested on, so it is in-distribution; DeBERTa was not trained
  on them. The comparison shows the value of domain fine-tuning, not that
  DeBERTa is a weaker architecture.
- Single seed. Multi-seed mean and standard deviation are pending a
  decision on compute.
- Latency is PyTorch eager on CPU for DistilBERT and ONNX Runtime for
  DeBERTa; exporting DistilBERT to ONNX (`ml/export_onnx.py`) would lower
  its numbers further.

### Classifier false positives on PII-bearing enterprise prompts (2026-09-07)

The injection eval's benign rows come from jailbreak corpora and contain
almost no PII. Scoring the PII corpus (which contains no injections) through
both classifiers exposes a weakness the headline FPR hides. Share of prompts
scored at or above each threshold (0.95 is the default ML-only block point):

| Prompt set | n | DistilBERT >=0.5 | DistilBERT >=0.95 | DeBERTa >=0.5 | DeBERTa >=0.95 |
|---|---|---|---|---|---|
| Faker PII prompts | 600 | 0.057 | 0.023 | 0.157 | 0.112 |
| ai4privacy PII rows | 400 | 0.130 | 0.065 | 0.200 | 0.170 |
| benign (no PII) | 600 | 0.002 | 0.002 | 0.008 | 0.008 |

Typical false positives are imperative enterprise requests that carry PII,
such as "Extract the key facts: James Lewis / matthew64@example.com" (0.996)
or "confirm your SSN ... and DOB ... for the ICU record" (0.97). The
fine-tuned model is 3 to 5 times better than the off-the-shelf DeBERTa on
this set, but 2 to 6% of legitimate PII-bearing prompts would still be
blocked as injections under the default policy. The integration test
`test_ssn_blocked_critical` fails for exactly this reason: the prompt is
blocked, but as an injection (score 1.00) rather than as critical PII.

Root cause: none of the training sources contain PII-bearing benign prompts,
so the model has never seen "instruction + personal data" labelled benign.
Remedy under consideration: add generated PII-bearing benign prompts (a
separate Faker draw from the evaluation set) to the training rows as hard
negatives and retrain.
