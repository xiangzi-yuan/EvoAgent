FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY evoagent ./evoagent
COPY web ./web
COPY skills ./skills
COPY scripts ./scripts
COPY pr_diff_100.jsonl pr_diff_100_v2.jsonl ./
COPY benchmarks ./benchmarks
EXPOSE 8080
CMD ["python", "-m", "evoagent"]
