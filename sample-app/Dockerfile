# PLANT outdated-base: Debian 10 (buster), past its end of life, with the
# Python packages from requirements.txt that have published CVEs.
FROM python:3.8-slim-buster@sha256:8799b0564103a9f36cfb8a8e1c562e11a9a6f2e3bb214e2adc23982b36a04511
WORKDIR /app
COPY requirements.txt app.py ./
RUN pip install --no-cache-dir -r requirements.txt
USER 1000
CMD ["python", "-m", "flask", "--app", "app", "run", "--host", "0.0.0.0"]
