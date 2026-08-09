#!/bin/bash
# VoidRecon development environment setup.
# Installs the package (editable) with dev + full extras so tests and the linter
# run cleanly. Idempotent and non-interactive — safe to re-run.
set -euo pipefail

cd "$(dirname "$0")/.."

python -m pip install --upgrade pip >/dev/null 2>&1 || true
pip install -e ".[dev,full]"

echo "VoidRecon dev environment ready. Run 'make test' and 'make lint'."
