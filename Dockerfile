# App image for the triage service. Runs as a non-root user.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app \
    QDRANT_COLLECTION=otrf_recorded_events_v1

RUN useradd --create-home --uid 10001 triage
WORKDIR /app

COPY pyproject.toml ./
RUN python -c "import subprocess, tomllib; p = tomllib.load(open('pyproject.toml', 'rb'))['project']; subprocess.check_call(['python', '-m', 'pip', 'install', *p['dependencies'], *p['optional-dependencies']['anthropic'], *p['optional-dependencies']['openai']])"
COPY --chown=triage:triage soc_triage ./soc_triage
COPY --chown=triage:triage data/otrf/demo_alerts ./data/otrf/demo_alerts
COPY --chown=triage:triage data/synthetic_demo_alerts ./data/synthetic_demo_alerts

USER triage
EXPOSE 7860
CMD ["python", "-m", "soc_triage.ui"]
