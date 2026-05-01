# Old base image — full of CVEs
FROM python:3.6-slim

# Running as root — Trivy misconfig will catch this
USER root

# Hardcoded secrets in image — Trivy secret scan catches this
ENV AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
ENV DB_PASSWORD="admin123"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Exposing extra ports — misconfig
EXPOSE 5000
EXPOSE 22

# No HEALTHCHECK — misconfig
# Shell form CMD instead of exec form — misconfig
CMD python app.py
