#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -x "$ROOT/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT/.venv/bin/python"
else
  PYTHON_BIN="${PYTHON_BIN:-python3}"
fi

declare -A EXPECTED=(
  [nmap.txt]=NMAP
  [burp.txt]=BURP
  [gobuster.txt]=GOBUSTER
  [nuclei.txt]=NUCLEI
  [windows.txt]=WINDOWS
  [linux.txt]=LINUX
  [aws.txt]=AWS
  [secrets.txt]=SECRETS
  [pii.txt]=PII
  [generic.txt]=GENERIC
)

order=(nmap.txt burp.txt gobuster.txt nuclei.txt windows.txt linux.txt aws.txt secrets.txt pii.txt generic.txt)
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
pass=0
fail=0

printf "%-16s %-12s %-12s %-32s %s\n" "FILE" "EXPECTED" "DETECTED" "SOURCE" "RESULT"

for file in "${order[@]}"; do
  expected="${EXPECTED[$file]}"
  fixture="$ROOT/tests/fixtures/$file"
  prompt="$tmp/$file.prompt"
  output="$(cd "$ROOT" && "$PYTHON_BIN" -m vapt_sanitize "$fixture" --ai-prompt -o "$prompt" 2>&1)"
  rc=$?
  detected="$(printf '%s\n' "$output" | sed -n 's/^\[+\] Profile: //p' | tail -1)"
  source="$(sed -n 's/^Source: //p' "$prompt" 2>/dev/null | head -1)"
  if [[ $rc -eq 0 && "$detected" == "$expected" ]]; then
    result=PASS; ((pass+=1))
  else
    result=FAIL; ((fail+=1))
  fi
  printf "%-16s %-12s %-12s %-32s %s\n" "$file" "$expected" "${detected:-UNKNOWN}" "${source:--}" "$result"
done

echo
echo "Auto-detection result: ${pass}/10 PASS"
[[ $fail -eq 0 ]]
