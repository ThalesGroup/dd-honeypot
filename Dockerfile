FROM python:3.12-alpine
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
WORKDIR /app/
COPY src/. .
ENV PYTHONPATH "/app"
ENTRYPOINT ["python", "-u", "honeypot_main.py"]
