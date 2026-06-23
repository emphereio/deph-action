# Minimal app with a KNOWN, REACHABLE vulnerable dependency, used by the e2e suite
# so deph has a real in-path finding to detect and the fail-on gate is exercised.
# pyyaml 5.3.1 carries CVE-2020-14343 (unsafe yaml.load), and app.py calls yaml.load.
FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir "pyyaml==5.3.1"
COPY app.py .
CMD ["python", "app.py"]
