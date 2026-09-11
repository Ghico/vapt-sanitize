#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -x "$ROOT/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT/.venv/bin/python"
else
  PYTHON_BIN="${PYTHON_BIN:-python3}"
fi

cd "$ROOT"
echo "[1/4] Version"
"$PYTHON_BIN" -m vapt_sanitize --version
echo "[2/4] Python compile"
"$PYTHON_BIN" -m compileall -q vapt_sanitize tests
echo "[3/4] Unit/regression tests"
"$PYTHON_BIN" -m unittest discover -v
echo "[4/4] Auto-detection matrix"
"$ROOT/scripts/check-autodetect.sh"
echo "[+] Release checks passed."
