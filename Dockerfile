FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Dependencies only first -> makes use of the Docker layer cache.
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

# WebSocket protocol (v2.2), admin web interface and firmware HTTP (OTA download).
EXPOSE 8443 8010 8080

CMD ["python", "run_server.py"]
