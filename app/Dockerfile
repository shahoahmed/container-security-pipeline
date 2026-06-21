# Base image is deliberately a few patch cycles behind so the pipeline has
# real findings to surface and map — that's the point of the exercise.
# In a real production pipeline this would track :latest-slim and get rebuilt
# on a schedule to stay current.
FROM python:3.12-slim-bookworm

WORKDIR /app

# Install dependencies first to leverage Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# --- Baseline hardening (NIST 800-171 3.4.2 - Security Configuration Settings) ---
# Run as a non-root user rather than the container default (root)
RUN useradd --no-create-home --shell /usr/sbin/nologin appuser
USER appuser

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1

CMD ["python", "app.py"]
