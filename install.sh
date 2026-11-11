#!/bin/sh
set -eu
package_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 -I "$package_dir/agentzab/rollout.py" "$@"
