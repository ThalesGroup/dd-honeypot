FROM python:3.12-alpine
COPY docker.requirements.txt .
RUN pip install --no-cache-dir -r docker.requirements.txt
RUN pip install flask
WORKDIR /app/
COPY src/. .
ENV PYTHONPATH "/app"
ENTRYPOINT ["python", "-u", "honeypot_main.py"]
