#!/bin/sh
set -e

if [ -n "$SSL_CERT_DATA" ]; then
    echo "$SSL_CERT_DATA" > /tmp/cert.pem
    export SSL_CERT_FILE="/tmp/cert.pem"
fi

if [ -n "$SSL_KEY_DATA" ]; then
    echo "$SSL_KEY_DATA" > /tmp/key.pem
    export SSL_KEY_FILE="/tmp/key.pem"
fi

echo "🔧 ENTRYPOINT SETTINGS"
echo "HOST: ${HOST:-0.0.0.0}"
echo "PORT: ${PORT:-8000}"
echo "WORKERS: ${WORKERS:-1}"
[ -n "$SSL_CERT_FILE" ] && echo "SSL: enabled" || echo "SSL: disabled"

exec python fastmcp_server.py
