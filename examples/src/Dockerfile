# Showcase app for the example report: a small Flask service that actually CALLS
# several pinned-vulnerable dependencies, so deph traces multiple CVEs as reachable
# (and the dependency graph is rich: framework + transitive deps + native libs).
FROM python:3.9-slim
WORKDIR /app
RUN pip install --no-cache-dir \
    flask==1.1.4 \
    jinja2==2.11.3 \
    pyyaml==5.3.1 \
    requests==2.25.1
COPY app.py .
CMD ["python", "app.py"]
