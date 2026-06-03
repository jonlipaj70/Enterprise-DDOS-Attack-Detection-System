#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

if [ ! -x ".venv/bin/python" ]; then
  echo ".venv was not found. Running setup first..."
  ./scripts/setup.sh
fi

if [ ! -f ".env" ] && [ -f ".env.example" ]; then
  cp .env.example .env
fi

export PYTHONPATH="$PROJECT_ROOT"
echo "Starting API and dashboard on http://localhost:8000/?ui=enterprise"
exec .venv/bin/python -m src.api.server
