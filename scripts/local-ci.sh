#!/bin/sh
# All CI runs locally. No hosted CI provider or production deployment.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 scripts/build.py
python3 scripts/check-release.py
if [ "${1:-}" = "--full" ]; then
    python3 tests/integration.py --platform
elif [ "${1:-}" = "--integration" ]; then
    python3 tests/integration.py
elif [ "$#" -ne 0 ]; then
    echo 'Usage: ./scripts/local-ci.sh [--integration|--full]' >&2
    exit 1
fi
