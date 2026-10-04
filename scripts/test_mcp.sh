#!/usr/bin/env bash
# Run the MCP server tests in a throwaway env pinned like the image.
set -euo pipefail
cd "$(dirname "$0")/.."
exec uv run --no-project --python 3.12 \
  --with-requirements mcp_server/requirements.txt \
  --with-requirements mcp_server/constraints.txt \
  --with pytest \
  python -m pytest tests/mcp -q -p no:cacheprovider -o addopts="" "$@"
