#!/usr/bin/env bash
# Run linting and type-checking
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# Build target list — only include tests/ if it has .py files
targets=(server/)
if [ -d tests ] && compgen -G "tests/*.py" > /dev/null 2>&1; then
    targets+=(tests/)
fi

echo "==> Ruff (lint)"
ruff check "${targets[@]}" "$@"

echo "==> Ruff (format check)"
ruff format --check "${targets[@]}"

echo "==> Pyright (strict)"
pyright server/

echo "==> All checks passed"
