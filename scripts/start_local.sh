#!/usr/bin/env bash
# Local Qdrant and UI launcher.
#
# Usage:
#   ./scripts/start_local.sh up        # start Qdrant and wait until it is ready
#   ./scripts/start_local.sh ingest    # index the OTRF captures into Qdrant
#   ./scripts/start_local.sh ui        # start the Gradio app container
#   ./scripts/start_local.sh status
#   ./scripts/start_local.sh down

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [[ -f .env ]]; then
  set -a; source .env; set +a
fi

QDRANT_HTTP="${QDRANT_HTTP:-http://localhost:6333}"

wait_for_qdrant() {
  echo "Waiting for Qdrant at ${QDRANT_HTTP} ..."
  for _ in $(seq 1 30); do
    if curl -fsS "${QDRANT_HTTP}/readyz" >/dev/null 2>&1; then
      echo "Qdrant is ready."
      return 0
    fi
    sleep 1
  done
  echo "Qdrant did not become ready in 30s. Check: docker compose logs qdrant" >&2
  return 1
}

case "${1:-}" in
  up)
    docker compose up -d qdrant
    wait_for_qdrant
    ;;
  ingest)
    docker compose up -d qdrant
    wait_for_qdrant
    shift
    python -m soc_triage.rag.ingest_otrf --url "$QDRANT_HTTP" "$@"
    ;;
  ui)
    docker compose up -d qdrant
    wait_for_qdrant
    docker compose up -d --build app
    echo "UI: http://localhost:7860"
    ;;
  status)
    docker compose ps
    ;;
  down)
    docker compose down
    ;;
  *)
    echo "Usage: $0 {up|ingest [--per-capture N]|ui|status|down}" >&2
    exit 1
    ;;
esac
