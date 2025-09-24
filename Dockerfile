FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app
ENV PYTHONUNBUFFERED=1

CMD ["python", "src/analyzer.py", "--path", "examples/vulnerable_code", "--report", "reports/docker_report"]
