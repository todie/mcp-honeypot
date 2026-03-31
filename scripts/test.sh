#!/usr/bin/env bash
# Run unit tests (no Docker required)
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

if [ -d tests ] && compgen -G "tests/test_*.py" > /dev/null 2>&1; then
    PYTHONPATH=server pytest tests/ -v --tb=short "$@"
else
    echo "No test files found — skipping"
fi
