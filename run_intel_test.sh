#!/bin/bash

echo "🚀 Launching Lumina Threat Intel Testing Ground..."
echo "This will execute the sandbox script inside the running API container."
echo "Press Ctrl+C to cancel if the container is not running."
echo ""

docker exec -it test-luminafpm-api-1 python services/lumina_threat_intel/test_ground.py "$@"
