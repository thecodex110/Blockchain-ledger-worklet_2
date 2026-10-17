# ==============================================================================
# Blockchain-Lite Ledger & Digital Wallet - container image (EDUCATIONAL DEMO)
#
# Zero third-party dependencies: the build needs no network beyond pulling the
# base image. The full test-suite runs during the build, so a broken tree never
# produces an image.
#
# SECURITY: the web dashboard is a demo. It holds the demo wallets' private keys
# server-side and signs with them; POST routes require a per-run API token printed
# at startup. Do not expose it to untrusted networks.
# ==============================================================================

FROM python:3.11-slim

# BLOCKCHAIN_LITE_HOST: dashboard bind address. Loopback by default, i.e. unreachable
# from outside the container. Opt in to publishing with BLOCKCHAIN_LITE_HOST=0.0.0.0
# (docker-compose.yml does this and maps the port to the HOST's loopback only).
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    BLOCKCHAIN_LITE_HOST=127.0.0.1

RUN useradd --create-home --shell /usr/sbin/nologin appuser

WORKDIR /app
COPY --chown=appuser:appuser . /app

USER appuser

# Verify the tree before shipping it (runs as the unprivileged user).
RUN python run_tests.py

# 8080: web dashboard. (The TCP RPC server has no standalone entry point; it is
# embedded via TCPSocketLedgerServer in the CLI demo and tests.)
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/chain', timeout=4)"]

ENTRYPOINT ["python"]
CMD ["-m", "blockchain_lite.network.web_dashboard", "--port", "8080"]
