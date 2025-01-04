#!/bin/sh
set -e

cleanup() {
    echo "Received signal - shutting down..."
    kill -TERM "$child" 2>/dev/null
}

trap cleanup SIGTERM SIGINT

/app/dltreceiver --config /app/config.yaml &
child=$!

wait "$child"
