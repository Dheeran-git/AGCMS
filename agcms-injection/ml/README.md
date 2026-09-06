# Injection classifier training

The shipped service uses `protectai/deberta-v3-base-prompt-injection-v2`
(off the shelf, exported to ONNX at image build). This folder holds the
optional fine-tuning experiment described in the paper:

```bash
python tests/eval/prepare_datasets.py       # builds tests/eval/data/injection.jsonl
python agcms-injection/ml/train.py          # DistilBERT, held-out publisher test split
python agcms-injection/ml/export_onnx.py    # -> ml/model/onnx for serving
```

`generate_dataset.py` produces the AGCMS template set under `data/`; it is
one of the training sources, never the evaluation set.
