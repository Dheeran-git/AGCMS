FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -r -u 1001 agcms
USER agcms

EXPOSE 8006

CMD ["uvicorn", "agcms.auth.main:app", "--host", "0.0.0.0", "--port", "8006"]
