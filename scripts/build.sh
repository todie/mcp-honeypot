#!/usr/bin/env bash
# Build the honeypot server Docker image
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

echo "==> Building mcp-honeypot server image"
docker build -t mcp-honeypot:dev ./server "$@"
echo "==> Build complete: mcp-honeypot:dev"
