# Using python:3.9-slim instead of 3.6-slim
# Still has CVEs but builds MUCH faster
FROM python:3.9-slim

USER root

# Hardcoded secrets — Trivy will catch these
ENV AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
ENV DB_PASSWORD="admin123"

WORKDIR /app

COPY requirements.txt .

# Install packages
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000
EXPOSE 22

CMD python app.py
