#!/usr/bin/env bash
# Stop the stack, optionally remove volumes
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

if [ "${1:-}" = "--clean" ]; then
    echo "==> Stopping stack and removing volumes"
    docker compose down -v
else
    echo "==> Stopping stack (volumes preserved)"
    docker compose down
    echo "    Use --clean to also remove volumes"
fi
