#!/usr/bin/env bash
# Run smoke tests against running stack
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

echo "==> Checking stack is running"
if ! curl -sf http://localhost:8000/healthz > /dev/null 2>&1; then
    echo "ERROR: MCP server not reachable at localhost:8000"
    echo "Run ./scripts/up.sh first"
    exit 1
fi

echo "==> Running smoke tests"
if [ -f .venv/bin/python ]; then
    .venv/bin/python tests/smoke_test.py "$@"
else
    python3 tests/smoke_test.py "$@"
fi
