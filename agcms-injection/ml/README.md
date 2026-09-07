# Injection classifier training

The injection service ships a DistilBERT classifier fine-tuned on the
publisher train splits of deepset/prompt-injections and
jackhhao/jailbreak-classification plus the AGCMS template set, with 600
PII-bearing benign prompts as hard negatives. It is exported to ONNX and
copied into the image from `ml/model/onnx` (weights are not committed).

```bash
python tests/eval/prepare_datasets.py                  # corpora + hard negatives
python agcms-injection/ml/train.py --seed 2 --hard-negatives --out agcms-injection/ml/model/seed2-hn
python agcms-injection/ml/export_onnx.py --src agcms-injection/ml/model/seed2-hn --dst agcms-injection/ml/model/onnx
```

Each run takes about two hours on a laptop CPU and writes `metrics.json`
(held-out precision, recall, F1) next to the weights. Multi-seed results and
the comparison with the off-the-shelf `protectai/deberta-v3-base-prompt-injection-v2`
are in `docs/evaluation.md`; `tests/eval/eval_finetuned.py --models ...`
regenerates them.

`generate_dataset.py` produces the AGCMS template set under `data/`; it is
one of the training sources, never the evaluation set.
