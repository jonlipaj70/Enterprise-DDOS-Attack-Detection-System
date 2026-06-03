#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "== Enterprise DDoS setup =="
echo "Project: $PROJECT_ROOT"

if [ ! -x ".venv/bin/python" ]; then
  PYTHON_BIN="${PYTHON_BIN:-python3}"
  echo "Creating .venv..."
  "$PYTHON_BIN" -m venv .venv
fi

echo "Upgrading pip..."
.venv/bin/python -m pip install --upgrade pip

echo "Installing dependencies..."
.venv/bin/python -m pip install -r requirements.txt

if [ ! -f ".env" ]; then
  cp .env.example .env
  echo "Created .env from .env.example"
fi

mkdir -p models data/uploads/cicddos2019

echo "Initializing SQLite database..."
.venv/bin/python -c "from src.config.settings import get_settings; from src.storage.database import Database; db=Database(get_settings().database.database_url); db.initialize(); print(f'Initialized {db.path}')"

printf "Create the first Admin account now? [y/N] "
read -r create_admin
case "$create_admin" in
  y|Y|yes|YES)
    .venv/bin/python -m src.cli.create_admin
    ;;
esac

echo
echo "Setup complete."
echo "Run: ./scripts/run.sh"
echo "Dashboard: http://localhost:8000/?ui=enterprise"
