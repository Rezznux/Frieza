#!/usr/bin/env bash
# Bootstrap script for Codex and other cloud Linux runners.
# Run once per workspace to install all packages and verify the CLI is usable.
set -euo pipefail

pip install -e ".[dev]" -q

echo "apkit version: $(apkit --version)"
echo "Setup complete. Start the MCP server with: apkit mcp-server"
