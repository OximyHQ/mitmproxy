#!/bin/bash
# Dev run script: builds bundle and runs mitmproxy with local bundle

set -e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "🔨 Building bundle..."
python3 "$PROJECT_ROOT/registry/scripts/build-bundle.py"

echo "🗑️  Clearing bundle cache..."
rm -f ~/.oximy/bundle_cache.json

echo "🚀 Starting mitmproxy with local bundle..."
# Set DEV mode to use local bundle (env var is OXIMY_DEV, not OXIMY_DEV_MODE)
export OXIMY_DEV=true

# Pass through any arguments to mitmdump
exec uv run mitmdump "$@"
