FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY thread_exporter.py .
COPY templates ./templates
EXPOSE 9108
CMD ["python", "thread_exporter.py"]
