FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ curl && rm -rf /var/lib/apt/lists/*

COPY agcms-pii/requirements.txt ./requirements.txt
COPY agcms-common/requirements.txt ./common-requirements.txt
RUN pip install --no-cache-dir -r requirements.txt -r common-requirements.txt
RUN pip install --no-cache-dir https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.7.1/en_core_web_sm-3.7.1-py3-none-any.whl

COPY agcms-common/agcms ./agcms
COPY agcms-pii/agcms ./agcms

RUN useradd -r -u 1001 agcms
USER agcms

EXPOSE 8001

CMD ["uvicorn", "agcms.pii.main:app", "--host", "0.0.0.0", "--port", "8001"]
