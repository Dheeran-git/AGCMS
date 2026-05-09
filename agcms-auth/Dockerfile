FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc curl && rm -rf /var/lib/apt/lists/*

COPY agcms-auth/requirements.txt ./requirements.txt
COPY agcms-common/requirements.txt ./common-requirements.txt
RUN pip install --no-cache-dir -r requirements.txt -r common-requirements.txt

COPY agcms-common/agcms ./agcms
COPY agcms-auth/agcms ./agcms

RUN useradd -r -u 1001 agcms
USER agcms

EXPOSE 8006

CMD ["uvicorn", "agcms.auth.main:app", "--host", "0.0.0.0", "--port", "8006"]
