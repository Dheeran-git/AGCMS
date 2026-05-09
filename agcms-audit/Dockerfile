FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc curl && rm -rf /var/lib/apt/lists/*

COPY agcms-audit/requirements.txt ./requirements.txt
COPY agcms-common/requirements.txt ./common-requirements.txt
RUN pip install --no-cache-dir -r requirements.txt -r common-requirements.txt

COPY agcms-common/agcms ./agcms
COPY agcms-audit/agcms ./agcms

# Portable, stdlib-only verifier shipped inside every audit bundle.
# bundle.py looks for it at parents[3]/tools/verify.py — inside the
# container that resolves to /tools/verify.py.
COPY tools/verify.py /tools/verify.py

RUN useradd -r -u 1001 agcms
USER agcms

EXPOSE 8005

CMD ["uvicorn", "agcms.audit.main:app", "--host", "0.0.0.0", "--port", "8005"]
