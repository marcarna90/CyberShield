# =============================================================================
# CyberShield Enterprise Security Platform - single image, several roles:
#   api | dashboard | sensor | init-secrets | cli
# Multi-stage: dependencies are installed in a builder and copied into a
# slim, non-root runtime. No compilers or package caches in the final image.
# =============================================================================
ARG PYTHON_VERSION=3.12

# ------------------------------------------------------------------- builder
FROM python:${PYTHON_VERSION}-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN python -m venv /opt/venv
COPY requirements.txt /tmp/requirements.txt
RUN /opt/venv/bin/pip install --upgrade pip \
 && /opt/venv/bin/pip install -r /tmp/requirements.txt

# ------------------------------------------------------------------- runtime
FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="CyberShield Enterprise Security Platform" \
      org.opencontainers.image.description="Defensive security automation: audit, scan, monitor, comply, report" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="1.0.0"

# nmap: authorised discovery/version detection; libpcap: scapy capture (sensor);
# tini: proper PID 1 signal handling; ca-certificates: HTTPS threat feeds / SMTP TLS.
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap libpcap0.8 tini ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 cybershield \
 && useradd --system --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin cybershield \
 && mkdir -p /var/lib/cybershield/data /var/lib/cybershield/reports /var/lib/cybershield/logs \
             /run/cybershield-secrets /host \
 && chown -R cybershield:cybershield /var/lib/cybershield

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp \
    CYBERSHIELD_DATA_DIR=/var/lib/cybershield/data \
    CYBERSHIELD_REPORTS_DIR=/var/lib/cybershield/reports \
    CYBERSHIELD_LOGS_DIR=/var/lib/cybershield/logs

COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
COPY --chown=root:root app/ /app/app/
COPY --chown=root:root .streamlit/ /app/.streamlit/
COPY --chown=root:root pyproject.toml README.md LICENSE /app/
COPY --chown=root:root --chmod=0755 docker/entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN printf '#!/bin/sh\nexec python -m app.cli "$@"\n' > /usr/local/bin/cybershield \
 && chmod 0755 /usr/local/bin/cybershield \
 && python -m compileall -q /app/app

USER cybershield
EXPOSE 8000 8501
VOLUME ["/var/lib/cybershield"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=4).status == 200 else 1)"

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
CMD ["api"]
