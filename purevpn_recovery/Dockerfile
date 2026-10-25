FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt && mkdir -p /data /config
COPY app.py purevpn_client.py ./
CMD ["python", "-u", "/app/app.py"]
