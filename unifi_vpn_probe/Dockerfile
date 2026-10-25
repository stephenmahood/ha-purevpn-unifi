FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN pip install --no-cache-dir "requests>=2.32,<3"
COPY probe.py /app/probe.py
CMD ["python", "-u", "/app/probe.py"]
