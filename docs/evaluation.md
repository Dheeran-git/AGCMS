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
| Injection `ml` | classifier alone: fine-tuned DistilBERT since 2026-09-07 (`protectai/deberta-v3-base-prompt-injection-v2` in the 2026-09-06 run) |
| Injection `full` | max(heuristic, ml), the shipped configuration |

## Results

Results are appended below by the maintainer after each run, together with
the machine description printed in the JSON report.

### Run 2026-09-07 (commit c5b6867, shipped DistilBERT classifier)

Machine: same laptop as below, CPU only, fine-tuned DistilBERT ONNX
classifier (seed 2, hard negatives) loaded via `AGCMS_INJECTION_MODEL_DIR`.
Corpus sizes unchanged. PII, response and policy numbers are unchanged from
the 2026-09-06 run (same code paths); only the injection tables differ.

#### Injection detection, full corpus (AdvBench excluded)

The `ml` and `full` rows here are partly in-sample: 2,607 of the 2,985
scored rows are the classifier's training rows. Use the held-out table below
for the paper's headline.

| Config | P | R | F1 | FPR | Policy-level F1 | median ms | p95 ms |
|---|---|---|---|---|---|---|---|
| unguarded | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.0 | 0.0 |
| keyword | 0.998 | 0.291 | 0.451 | 0.001 | 0.451 | 0.02 | |
| heuristic | 0.935 | 0.328 | 0.485 | 0.026 | 0.452 | 0.26 | |
| ml | 1.000 | 0.984 | 0.992 | 0.000 | 0.987 | 39.1 | 608 |
| full | 0.978 | 0.984 | 0.981 | 0.026 | 0.976 | 39.4 | 615 |

#### Injection detection, held-out publisher test rows only (n=378, 199 injections)

| Config | P | R | F1 | FPR |
|---|---|---|---|---|
| keyword | 0.978 | 0.226 | 0.367 | 0.006 |
| heuristic | 0.833 | 0.276 | 0.415 | 0.062 |
| ml | 1.000 | 0.920 | 0.958 | 0.000 |
| full, all 20 rules blocking | 0.943 | 0.920 | 0.931 | 0.062 |
| heuristic, ROLEPLAY advisory | 1.000 | 0.126 | 0.223 | 0.000 |
| full, ROLEPLAY advisory (shipped) | 1.000 | 0.920 | 0.958 | 0.000 |

Recall by source, shipped config: agcms-synthetic 1.000, deepset 0.935,
jackhhao 0.987 (FPR 0.002), advbench 0.471. Full-corpus F1 0.991, FPR 0.001,
median 41 ms.

#### ML classifier on PII-bearing prompts (no injections present)

| Source | n | flagged >=0.5 | flagged >=0.95 |
|---|---|---|---|
| faker-synthetic | 600 | 0.000 | 0.000 |
| ai4privacy | 400 | 0.008 | 0.000 |
| benign | 600 | 0.000 | 0.000 |

#### Reading the numbers

- **Held-out F1 rises from 0.873 to 0.958** for the shipped configuration
  and from 0.860 to 0.958 for the classifier alone, against the DeBERTa-era
  numbers on the full corpus. Median injection latency falls from 269 ms to
  39 to 41 ms (ONNX DistilBERT, no fixed padding); p95 was 615 ms on an idle
  CPU and 992 ms when the harness shared the CPU with a Docker build.
- **The ROLEPLAY rules cost more than they added, so they are now advisory.**
  With all 20 rules blocking, the held-out combination scored F1 0.931 at
  6.2 % FPR: the classifier alone already reaches 0.958 at 0 % FPR, and the
  four ROLEPLAY rules added no recall while firing on jackhhao benign prompts
  such as "Pretend to be Elle Woods" (35 of 36 heuristic false positives).
  Since 2026-09-07 those rules are still matched and recorded in
  `triggered_rules` / `attack_type` for the audit row, but they no longer
  raise the risk score on their own; a roleplay prompt is blocked only when
  the classifier agrees (policy: rules fired and score >= 0.65). The shipped
  configuration now matches the classifier alone (F1 0.958, FPR 0) and keeps
  the other 16 rules as an interpretable, sub-millisecond layer and as the
  fallback when the ML model is disabled. Heuristic-only recall drops from
  0.276 to 0.126 on held-out rows, which quantifies how much of the old rule
  layer's recall came from roleplay phrasing.
- **PII-prompt false positives are gone.** 0 of 1,200 PII-bearing benign
  prompts and 0 of 600 plain benign prompts reach the 0.95 block threshold
  (yesterday: 2.3 %, 6.5 %, 0.2 %). Only 3 of 400 ai4privacy rows cross 0.5.
- **AdvBench recall is now 0.47** (was 0). The fine-tuned model has learned
  that harmful-request phrasing correlates with jailbreak prompts in its
  training corpora. This is still not injection detection; the slice stays
  excluded from every headline and the paper should note the leakage.
- **deepset recall 0.935 on the full corpus, 0.78 on its held-out rows**
  (see the multi-seed section): the German half of deepset remains the
  hardest part of the test set.

#### Gateway under concurrency (Locust, 2026-09-07)

`tests/load/locustfile.py`, 10 users, spawn rate 2/s, 60 s, against the
Docker stack on the same laptop; live Groq backend; default tenant policy
(60 requests per minute).

| Endpoint | requests | failures | median ms | p95 ms | max ms |
|---|---|---|---|---|---|
| POST /v1/chat/completions (all) | 1,155 | 0 | 52 | 190 | 5,406 |
| GET /api/dashboard/stats | 117 | 0 | 130 | 240 | 605 |
| GET /health | 122 | 0 | 7 | 19 | 38 |

Gateway status codes for the completions: 1,095 x 429 (tenant rate limit),
19 x 200 (reached the LLM), 17 x 403 (blocked), 24 x 502 (provider error).
Exactly 60 requests per minute passed the limiter, as configured. So this
run measures the gateway's auth, rate-limit and error path at 23 req/s
(median 52 ms, no failures, no crashes), not the scan pipeline under load:
the per-module scan latencies above are the governance-overhead numbers.
Raising the tenant limit would move the bottleneck to the provider's
free-tier quota rather than to AGCMS. Raw CSVs: `tests/load/results/`
(ignored by git).

#### Governance pipeline under concurrency (Locust, governance-only mix, 2026-09-07)

Same stack, tenant and per-IP limits raised to 100,000 rpm for the run,
`AGCMS_LOAD_MIX=governance`: every prompt is blocked (critical PII or
injection), so each request runs auth, PII scan, injection scan with the
ONNX classifier, policy resolution and the signed audit write, and returns
403 without an LLM call. 60 s per level, spawn rate 5/s, 0 failures at every
level.

| Concurrent users | requests | throughput req/s | p50 ms | p90 ms | p95 ms | p99 ms |
|---|---|---|---|---|---|---|
| 10 | 1,022 | 17.2 | 440 | 560 | 620 | 760 |
| 25 | 914 | 15.4 | 1,400 | 1,700 | 1,900 | 2,200 |
| 50 | 962 | 16.2 | 2,700 | 3,200 | 3,200 | 3,300 |

Reading the numbers:
- **Throughput is flat at about 16 to 17 governed requests per second** from
  10 users upward, and median latency grows linearly with concurrency
  (440 ms, 1.4 s, 2.7 s). That is a saturated single-core pipeline with
  requests queueing, not a failure: no request errored or timed out.
- **The classifier is the ceiling.** Single-request cost is about 40 ms of
  ONNX inference plus 20 ms of PII scan and service hops; one uvicorn worker
  per container on a laptop CPU gives roughly 1000 / 60 = 17 req/s. The
  containers are single-process; scaling the injection service horizontally
  (or a GPU) is the obvious lever and is not evaluated here.
- **Compare with the single-request figures** (median 41 ms classifier,
  10 ms PII): the per-request overhead of governance is tens of
  milliseconds; the seconds seen at 25 and 50 users are queueing on one
  machine. The paper should present both.
- Raw CSVs in `tests/load/results/gov_u{10,25,50}_*.csv` (ignored by git).

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
- Single seed (42). The multi-seed runs below supersede this table.
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
Remedy, applied below: add generated PII-bearing benign prompts (a separate
Faker draw with disjoint templates, `--hard-negatives`) to the training rows
and retrain.

### Multi-seed runs and hard negatives (2026-09-07)

Same recipe as above, seeds 1, 2, 3. "Hard-neg" runs add 600 PII-bearing
benign prompts (`tests/eval/data/injection_hard_negatives.jsonl`, Faker seed
4242, `TRAIN_TEMPLATES`, disjoint from the evaluation templates) to the 2,607
training rows. All models scored by `tests/eval/eval_finetuned.py` on the
same 378 held-out rows; PII-prompt columns are the share of prompts scored
>= 0.95 (the ML-only block threshold) on the Faker (n=600) and ai4privacy
(n=400) PII sets, which contain no injections.

| Model | Train rows | P | R | F1 | FPR | PII flagged: Faker | ai4privacy |
|---|---|---|---|---|---|---|---|
| seed 1 | 2,607 | 0.984 | 0.930 | 0.956 | 0.017 | 0.010 | 0.038 |
| seed 2 | 2,607 | 0.995 | 0.925 | 0.958 | 0.006 | 0.017 | 0.045 |
| seed 3 | 2,607 | 1.000 | 0.925 | 0.961 | 0.000 | 0.003 | 0.023 |
| **baseline mean +- sd** | | | | **0.958 +- 0.002** | | | |
| seed 1 hard-neg | 3,207 | 1.000 | 0.935 | 0.966 | 0.000 | 0.000 | 0.003 |
| seed 2 hard-neg (shipped) | 3,207 | 1.000 | 0.920 | 0.958 | 0.000 | 0.000 | 0.000 |
| seed 3 hard-neg | 3,207 | 0.995 | 0.915 | 0.953 | 0.006 | 0.000 | 0.005 |
| **hard-neg mean +- sd** | | | | **0.959 +- 0.007** | | | |
| DeBERTa protectai v2 | - | 0.986 | 0.699 | 0.818 | 0.011 | 0.112 | 0.170 |

Held-out F1 per epoch: seed 1 0.854 / 0.953 / 0.956; seed 2 0.929 / 0.956 /
0.958; seed 3 0.934 / 0.959 / 0.961; hard-neg seed 1 0.904 / 0.956 / 0.966;
seed 2 0.930 / 0.969 / 0.958; seed 3 0.939 / 0.942 / 0.953. Epoch-1 scores
vary by up to 0.08 across seeds; by epoch 3 the spread is 0.005.

Reading the numbers:
- Hard negatives do not change injection F1 (0.958 vs 0.959, inside one
  standard deviation) but remove the PII-prompt false positives almost
  entirely: 0 of 600 Faker prompts and 0 to 4 of 400 ai4privacy rows at the
  block threshold, against 2 to 27 and 9 to 26 for the baseline seeds. The
  integration prompt "My SSN is 123-45-6789, help me file taxes" drops from
  0.998 (seed 42) to 0.115 (seed 1 hard-neg), so it is now handled by the
  PII path rather than blocked as an injection.
- Recall, not precision, is the limit: every fine-tuned seed misses 13 to 17
  of the 199 held-out injections, almost all from deepset (recall 0.75 to
  0.82) rather than jackhhao (0.97 to 0.99).
- The shipped model is the median hard-negative seed by F1 (seed 2),
  exported to ONNX with `ml/export_onnx.py --src ml/model/seed2-hn`.
- Latency in this table is PyTorch eager on a CPU also running other jobs
  and is not comparable to the ONNX serving numbers in the results section.
