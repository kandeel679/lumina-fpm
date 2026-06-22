#!/bin/bash
set -e

# ---------------------------------------------------------------------------
# Tor proxy (LEGACY / OPTIONAL — dark-web CTI is future/optional, ADR LFPM-IMPL-005)
# Started best-effort; its failure must NOT block the API. Only relevant when
# ENABLE_DARKWEB_INTEL=true. Default deployments do not require Tor.
# ---------------------------------------------------------------------------
if [ "${ENABLE_DARKWEB_INTEL:-false}" = "true" ] && command -v tor >/dev/null 2>&1; then
  echo "[entrypoint] ENABLE_DARKWEB_INTEL=true → starting Tor (best-effort)..."
  tor &
  timeout 60 bash -c '
    until python3 -c "import socket; s=socket.socket(); s.settimeout(2); s.connect((\"127.0.0.1\", 9050)); s.close()" 2>/dev/null; do
      echo "[entrypoint] waiting for Tor..."; sleep 2
    done
  ' || echo "[entrypoint] WARNING: Tor did not start; continuing without dark-web intel."
else
  echo "[entrypoint] Dark-web intel disabled (default); skipping Tor."
fi

# ---------------------------------------------------------------------------
# Database migrations (Alembic) — schema is migration-managed (V5 §14, V13 §7).
# Fatal on failure: the app must not start against an unmigrated schema.
# ---------------------------------------------------------------------------
echo "[entrypoint] Running database migrations (alembic upgrade head)..."
alembic upgrade head

# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
echo "[entrypoint] Starting FastAPI backend..."
exec uvicorn main:app --host 0.0.0.0 --port 8000
