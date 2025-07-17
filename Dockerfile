FROM python:3.12-alpine
RUN python -m pip install --upgrade pip
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# verify that the license file is present for paramiko
RUN test -f /usr/local/lib/python3.12/site-packages/paramiko-*.dist-info/LICENSE
WORKDIR /app/
COPY src/. .
ENV PYTHONPATH "/app"
ENTRYPOINT ["python", "-u", "honeypot_main.py"]
