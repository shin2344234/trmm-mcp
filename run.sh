#!/usr/bin/env bash
# Launcher for the TacticalRMM MCP server.
#
#   ./run.sh              # read-only (default)
#   ./run.sh command      # enable execution tools
#   ./run.sh readonly http   # read-only over HTTP instead of stdio
#
# Everything else comes from .env in this directory.
set -euo pipefail

cd "$(dirname "$0")"

if [ "${1:-}" = "command" ] || [ "${1:-}" = "readonly" ]; then
    export TRMM_MCP_MODE="$1"
fi
if [ "${2:-}" = "http" ]; then
    export TRMM_MCP_TRANSPORT="streamable-http"
fi

exec ./venv/bin/python -m trmm_mcp.server
