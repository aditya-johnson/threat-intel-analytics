#!/bin/bash
set -e
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

echo "=========================================================="
echo "🛡️  STARTING AEGIS THREAT INTELLIGENCE & ANALYTICS PIPELINE"
echo "=========================================================="
echo "Target Host: http://127.0.0.1:8055"
echo "API Docs:    http://127.0.0.1:8055/docs"
echo "=========================================================="

python3 -m uvicorn app:app --host 127.0.0.1 --port 8055 --reload
