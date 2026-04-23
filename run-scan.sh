#!/usr/bin/env bash
set -u
cd "$(dirname "$0")"

echo ""
echo "== glasswing-mini: paste your Anthropic API key, then press Enter =="
echo "   (input is hidden — nothing will show as you paste)"
echo ""

# Read key silently, with a prompt
read -rs -p "key: " KEY
echo ""

len=${#KEY}
if [ "$len" -lt 80 ] || [ "$len" -gt 200 ]; then
  echo "ERROR: key length is $len — expected ~108. Looks wrong."
  echo "       Make sure you copied the whole sk-ant-api03-... string."
  exit 1
fi

export ANTHROPIC_API_KEY="$KEY"
unset KEY
echo "ok: key length=$len — running scan..."
echo ""

exec npx tsx src/cli.ts scan ./samples \
  --focus=rce,ssrf,sqli,path,auth \
  --i-own-this \
  --json 2>&1 | tee /tmp/glasswing-run.log
