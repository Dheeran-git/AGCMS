FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc curl && rm -rf /var/lib/apt/lists/*

COPY agcms-injection/requirements.txt ./requirements.txt
COPY agcms-common/requirements.txt ./common-requirements.txt
RUN pip install --no-cache-dir -r requirements.txt -r common-requirements.txt

# Pre-download and convert the injection classifier to ONNX at build time.
# This makes container startup fast and deterministic (~400 MB model).
# Set AGCMS_ML_ENABLED=false at runtime to skip loading entirely.
#
# Model version is pinned to a specific HuggingFace commit SHA to prevent
# silent supply-chain updates. To upgrade: verify the new SHA against the
# HuggingFace model card, update AGCMS_INJECTION_MODEL_SHA, and rebuild.
ENV AGCMS_INJECTION_MODEL_DIR=/app/model/onnx
ENV AGCMS_INJECTION_MODEL_ID=protectai/deberta-v3-base-prompt-injection-v2
ENV AGCMS_INJECTION_MODEL_SHA=e6535ca4ce3ba852083e75ec585d7c8aeb4be4c5
RUN python -c "\
from optimum.onnxruntime import ORTModelForSequenceClassification; \
from transformers import AutoTokenizer; \
import os; \
model_id = os.environ['AGCMS_INJECTION_MODEL_ID']; \
revision = os.environ['AGCMS_INJECTION_MODEL_SHA']; \
m = ORTModelForSequenceClassification.from_pretrained(model_id, export=True, revision=revision); \
m.save_pretrained('/app/model/onnx'); \
t = AutoTokenizer.from_pretrained(model_id, revision=revision); \
t.save_pretrained('/app/model/onnx'); \
print('ONNX model exported successfully (SHA:', revision, ')')" \
    || echo "WARNING: ONNX export failed — will run in heuristic-only mode"

COPY agcms-common/agcms ./agcms
COPY agcms-injection/agcms ./agcms

RUN useradd -r -u 1001 agcms
USER agcms

EXPOSE 8002

CMD ["uvicorn", "agcms.injection.main:app", "--host", "0.0.0.0", "--port", "8002"]
