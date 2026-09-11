#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"

echo "[+] Creating virtual environment: $ROOT/.venv"
"$PYTHON_BIN" -m venv "$ROOT/.venv"

echo "[+] Installing VAPT Sanitizer v1.0.0 and frozen dependencies"
"$ROOT/.venv/bin/python" -m pip install --upgrade pip
"$ROOT/.venv/bin/python" -m pip install -e "$ROOT"

if command -v xclip >/dev/null 2>&1 || command -v xsel >/dev/null 2>&1 || command -v wl-copy >/dev/null 2>&1; then
    echo "[+] Clipboard backend detected."
else
    echo "[!] No Linux clipboard helper detected. On Kali/X11 install xclip if you need clipboard mode."
fi

echo "[+] Running regression suite"
cd "$ROOT"
"$ROOT/.venv/bin/python" -m unittest discover -v

echo "[+] Installation complete"
"$ROOT/.venv/bin/python" -m vapt_sanitize --version
