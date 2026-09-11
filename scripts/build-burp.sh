#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BURP_DIR="$ROOT/burp-extension"
cd "$BURP_DIR"

echo "[+] Building Burp extension with pinned Gradle bootstrap..."
./gradlew clean jar

echo "[+] Burp JAR(s):"
find "$BURP_DIR/build/libs" -maxdepth 1 -type f -name '*.jar' -print
