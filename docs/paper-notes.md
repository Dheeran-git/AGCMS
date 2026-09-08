# Notes for the paper

Material that belongs in the manuscript but not in the code: limitations,
threats to validity, dataset licences and citations, and the exact steps
that reproduce every number in `docs/evaluation.md`.

## Limitations

- **Synthetic hard negatives.** The 600 PII-bearing benign prompts that
  removed the classifier's PII false positives are Faker-generated from eight
  templates. Real enterprise prompts are more varied; the 0 % rate on the
  ai4privacy rows (real-style text the model never saw) is the stronger
  evidence, but it is 400 rows.
- **Held-out set is small and in-distribution.** The 378 held-out rows are
  the publisher test splits of the same two corpora used for training. They
  measure generalisation to unseen prompts of the same kind, not to a new
  attack family. Standard deviation over 3 seeds is 0.002 to 0.007 F1.
- **English-centric injection corpora**, except the German half of deepset,
  which is also where recall is lowest (0.78 held-out).
- **PII coverage is US and India centred** (SSN, Aadhaar, PAN, US phone
  formats). International phone and card formats in ai4privacy lower recall
  for PHONE_US (0.48) and CREDIT_CARD (0.75). Person names rely on spaCy's
  small English model; single first names are often missed (recall 0.59).
- **Response compliance is a functional check.** The synthetic response set
  is easy by construction (F1 1.0) and should not be presented as a
  benchmark.
- **Latency was measured on one laptop CPU** with all services in Docker on
  the same machine and no GPU. Absolute numbers will differ elsewhere; the
  relative ordering (regex 1 ms, PII with NER 10 ms, classifier 40 ms) is the
  claim.
- **AdvBench recall of 0.47 is leakage, not a feature.** The fine-tuned model
  partly learned harmful-request phrasing from the jailbreak corpora. AdvBench
  is excluded from every headline for this reason.
- **The heuristic layer's value depends on the classifier.** With the
  off-the-shelf DeBERTa the 20 rules added +0.013 F1; with the fine-tuned
  model they added nothing and the ROLEPLAY rules cost 6 % FPR, so those four
  rules are now advisory. Report this as an ablation result.

## Threats to validity

- *Construct:* prompt-level "benign" negatives for the PII evaluation come
  from jailbreak corpora and genuinely contain names, so the 39 % prompt-level
  FPR for regex+NER is partly a labelling artefact; the entity-level scores
  are the meaningful ones.
- *Internal:* the classifier comparison against DeBERTa is a domain
  fine-tuning comparison, not an architecture comparison; DeBERTa was never
  trained on these corpora.
- *External:* single organisation's policy (the shipped default), single
  hardware target, free-tier LLM providers whose quotas shaped the load test
  (see the Locust section of `docs/evaluation.md`).
- *Conclusion:* three seeds; the gap to DeBERTa (0.14 F1) is about seventy
  standard deviations, the baseline-vs-hard-negative gap is inside one.

## Datasets, models and licences

| Resource | Use | Licence | Cite |
|---|---|---|---|
| deepset/prompt-injections (546 train / 116 test) | injection train + held-out | Apache-2.0 | Hugging Face dataset card |
| jackhhao/jailbreak-classification (1,040 / 262) | injection train + held-out | Apache-2.0 | Hugging Face dataset card; benign rows from OpenOrca and GPTeacher |
| AdvBench harmful behaviours (520) | excluded slice, reported separately | MIT (llm-attacks repo) | Zou et al., "Universal and Transferable Adversarial Attacks on Aligned Language Models", arXiv:2307.15043, 2023 |
| ai4privacy/pii-masking-200k (400 English rows) | PII evaluation | no licence field on the 200k card; the sibling 300k/400k cards carry the "AI4Privacy Dataset License": academic and non-commercial use with acknowledgment, no redistribution or derivatives without written permission (checked 2026-09-07). We therefore fetch the rows at evaluation time and do not commit them. | DOI 10.57967/hf/1532; acknowledge AI4Privacy |
| Faker | synthetic PII prompts and hard negatives | MIT | joke2k/faker |
| distilbert-base-uncased | fine-tuned classifier | Apache-2.0 | Sanh et al., "DistilBERT, a distilled version of BERT", 2019 |
| protectai/deberta-v3-base-prompt-injection-v2 | off-the-shelf baseline | Apache-2.0 | Hugging Face model card |
| spaCy en_core_web_sm | person-name NER | MIT | Honnibal et al., spaCy |
| ONNX Runtime | classifier serving | MIT | Microsoft |

ai4privacy rows are evaluation-only and are not redistributed with the code
(`tests/eval/data/pii_ai4privacy.jsonl` is gitignored); everything else is
permissive.

## Reproducing the numbers

All numbers in `docs/evaluation.md` come from the commit named in each run
heading. On a clean checkout:

```bash
python -m venv .venv && . .venv/bin/activate      # or uv venv
pip install -r requirements-dev.txt -r agcms-injection/ml/requirements.txt
python -m spacy download en_core_web_sm

python tests/eval/prepare_datasets.py            # corpora + hard negatives (deterministic seeds)
for s in 1 2 3; do
  python agcms-injection/ml/train.py --seed $s --out agcms-injection/ml/model/seed$s
  python agcms-injection/ml/train.py --seed $s --hard-negatives --out agcms-injection/ml/model/seed$s-hn
done
python tests/eval/eval_finetuned.py --models seed1 seed2 seed3 seed1-hn seed2-hn seed3-hn
python agcms-injection/ml/export_onnx.py --src agcms-injection/ml/model/seed2-hn --dst agcms-injection/ml/model/onnx
AGCMS_INJECTION_MODEL_DIR=agcms-injection/ml/model/onnx python tests/eval/run_eval.py

docker compose up -d --wait
pytest tests/unit/ tests/integration/
cd agcms-dashboard && npx playwright test
```

Fixed seeds: Faker evaluation prompts 42, hard negatives 4242, training seeds
1, 2, 3 (seed 42 was the exploratory single run). Each training run is about
two hours on a laptop CPU. Results are written to `tests/eval/results/` and
`agcms-injection/ml/model/<name>/metrics.json`.
