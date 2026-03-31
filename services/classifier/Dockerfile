# ===========================================================================
# Classifier Service — Dockerfile
# Lightweight Python container for AI classification proxy
# ===========================================================================
FROM python:3.11-slim

RUN useradd -m -u 1000 classifier

WORKDIR /service

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

USER classifier

EXPOSE 5001

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "5001", "--workers", "1"]
