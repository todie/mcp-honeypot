#!/usr/bin/env bash
# Create local dev environment from scratch
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

echo "==> Creating .env from .env.example"
if [ ! -f .env ]; then
    cp .env.example .env
    echo "    Created .env (review and adjust)"
else
    echo "    .env already exists, skipping"
fi

echo "==> Creating Python venv"
if [ ! -d .venv ]; then
    # Prefer python3.12, fall back to python3
    PY=$(command -v python3.12 || command -v python3)
    if [ -z "$PY" ]; then
        echo "ERROR: python3.12 or python3 not found"
        exit 1
    fi
    "$PY" -m venv .venv
    echo "    Created .venv (using $PY)"
else
    echo "    .venv already exists, skipping"
fi

echo "==> Installing dependencies"
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -r server/requirements.txt

echo "==> Done. Activate with: source .venv/bin/activate"
