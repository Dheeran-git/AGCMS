FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc curl && rm -rf /var/lib/apt/lists/*

# Install service + shared (agcms-common) requirements. Build context
# is the repo root so both trees are visible.
COPY agcms-tenant/requirements.txt ./requirements.txt
COPY agcms-common/requirements.txt ./common-requirements.txt
RUN pip install --no-cache-dir -r requirements.txt -r common-requirements.txt

# Shared crypto package — merges with agcms.tenant into the `agcms` namespace.
COPY agcms-common/agcms ./agcms
COPY agcms-tenant/agcms ./agcms

RUN useradd -r -u 1001 agcms
USER agcms

EXPOSE 8007

CMD ["uvicorn", "agcms.tenant.main:app", "--host", "0.0.0.0", "--port", "8007"]
