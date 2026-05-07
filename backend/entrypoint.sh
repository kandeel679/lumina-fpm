#!/bin/bash
echo "Starting Tor proxy..."
tor &

# Wait for Tor to open port 9050 locally
timeout 60 bash -c '
until python3 -c "import socket; s=socket.socket(); s.settimeout(2); s.connect((\"127.0.0.1\", 9050)); s.close()" 2>/dev/null; do
  echo "Waiting for Tor proxy to initialize..."
  sleep 2
done
'

if [ $? -ne 0 ]; then
  echo "ERROR: Tor failed to start."
  exit 1
fi

echo "Tor initialized. Starting FastAPI backend..."
exec uvicorn main:app --host 0.0.0.0 --port 8000
