#!/usr/bin/env bash
# scan-from-clipboard.sh — reads API key from macOS clipboard, runs scan.
set -u
cd "$(dirname "$0")"

KEY="$(pbpaste | tr -d '\n\r\t ')"
len=${#KEY}

if [ "$len" -lt 80 ] || [ "$len" -gt 200 ]; then
  echo ""
  echo "ERROR: clipboard doesn't look like an API key."
  echo "       got $len characters; expected ~108."
  echo ""
  echo "Fix: go to https://console.anthropic.com/settings/keys"
  echo "     Create Key → click the COPY icon next to it"
  echo "     then re-run this script."
  echo ""
  exit 1
fi

if [[ ! "$KEY" == sk-ant-* ]]; then
  echo ""
  echo "ERROR: clipboard has $len chars but doesn't start with 'sk-ant-'."
  echo "       Make sure you copied the API key, not something else."
  echo ""
  exit 1
fi

export ANTHROPIC_API_KEY="$KEY"
unset KEY
echo "ok: key from clipboard ($len chars). running scan..."
echo ""

exec npx tsx src/cli.ts scan ./samples \
  --focus=rce,ssrf,sqli,path,auth \
  --i-own-this \
  --json 2>&1 | tee /tmp/glasswing-run.log
