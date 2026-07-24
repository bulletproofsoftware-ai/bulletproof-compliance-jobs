FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app /app/app
COPY tests /app/tests
COPY migrations /app/migrations

# Run as an unprivileged user. Create the state dir up front and hand both the
# app tree and the state volume to `appuser` so the service never runs as root.
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /state \
    && chown -R appuser:appuser /app /state
USER appuser

EXPOSE 8087

ENV SQLITE_PATH=/state/compliance_jobs.sqlite

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8087/health').read()" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8087", "--workers", "1"]
