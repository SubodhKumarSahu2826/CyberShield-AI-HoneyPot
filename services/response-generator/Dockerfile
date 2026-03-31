FROM python:3.11-slim

RUN groupadd -r responsegen && useradd -r -g responsegen responsegen

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# Switch to non-root user
USER responsegen

EXPOSE 3002

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "3002"]
