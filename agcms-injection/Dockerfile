FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc curl && rm -rf /var/lib/apt/lists/*

COPY agcms-injection/requirements.txt ./requirements.txt
COPY agcms-common/requirements.txt ./common-requirements.txt
RUN pip install --no-cache-dir -r requirements.txt -r common-requirements.txt

# Fine-tuned classifier exported by ml/export_onnx.py (gitignored weights;
# run `python agcms-injection/ml/train.py && python agcms-injection/ml/export_onnx.py`
# before building). Set AGCMS_ML_ENABLED=false at runtime to skip loading.
ENV AGCMS_INJECTION_MODEL_DIR=/app/model/onnx
COPY agcms-injection/ml/model/onnx /app/model/onnx

COPY agcms-common/agcms ./agcms
COPY agcms-injection/agcms ./agcms

RUN useradd -r -u 1001 agcms
USER agcms

EXPOSE 8002

CMD ["uvicorn", "agcms.injection.main:app", "--host", "0.0.0.0", "--port", "8002"]
