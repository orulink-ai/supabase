#!/bin/sh
# macOS/Linux entry point; Python owns validation and deployment behavior.
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$script_dir/deploy.py" "$@"
