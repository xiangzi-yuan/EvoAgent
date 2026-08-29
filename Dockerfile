FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY evoagent ./evoagent
COPY web ./web
COPY skills ./skills
COPY scripts ./scripts
COPY pr_diff_100.jsonl ./pr_diff_100.jsonl
EXPOSE 8080
CMD ["python", "-m", "evoagent"]
