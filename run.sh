#!/usr/bin/env bash
# Local dev runner (SQLite, no Docker needed)
set -e
cd "$(dirname "$0")/backend"
python -m pip install -q -r requirements.txt
echo "Starting SentinelOps SIEM on http://localhost:8000 ..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
