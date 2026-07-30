FROM python:3.13-slim-bookworm AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install --yes --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir --requirement requirements.txt


FROM base AS test

ENV SECURESCAN_DATABASE_PATH=/tmp/securescan-test.db

COPY backend ./backend
COPY database ./database
COPY reports ./reports
COPY scanner ./scanner
COPY static ./static
COPY templates ./templates
COPY vulnerability ./vulnerability
COPY tests ./tests
COPY Dockerfile docker-compose.yml .dockerignore .gitignore .env.example README.md ./

RUN python -m unittest discover -s tests -p "test_*.py"

CMD ["python", "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"]


FROM base AS runtime

ENV SECURESCAN_DATABASE_PATH=/app/data/securescan.db

RUN groupadd --system securescan \
    && useradd --system --gid securescan --home-dir /app --shell /usr/sbin/nologin securescan \
    && mkdir -p /app/data \
    && chown securescan:securescan /app/data

COPY --chown=securescan:securescan backend ./backend
COPY --chown=securescan:securescan database ./database
COPY --chown=securescan:securescan reports ./reports
COPY --chown=securescan:securescan scanner ./scanner
COPY --chown=securescan:securescan static ./static
COPY --chown=securescan:securescan templates ./templates
COPY --chown=securescan:securescan vulnerability ./vulnerability

USER securescan

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=3).read()"]

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--timeout", "90", "--access-logfile", "-", "--error-logfile", "-", "backend.app:app"]
