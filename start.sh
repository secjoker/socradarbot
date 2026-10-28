#!/usr/bin/env bash
# SocradarBot launcher (Linux / macOS)
set -e
cd "$(dirname "$0")"

[ -f config.yaml ] || cp config.example.yaml config.yaml

BIN=./socradarbot
[ -x "$BIN" ] || BIN=./socradarbot-linux-amd64
chmod +x "$BIN" 2>/dev/null || true

echo "SocradarBot starting at http://127.0.0.1:8100"
exec "$BIN" -addr 127.0.0.1:8100 -web web/dist
