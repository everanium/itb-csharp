#!/usr/bin/env bash
#
# run_tests.sh -- one-step test runner for the C# / .NET binding.
# Verifies libitb.so is present, sets LD_LIBRARY_PATH, then invokes
# `dotnet test -c Release`. Forwards any positional arguments through
# to dotnet test (e.g. `--filter` to scope the run).
#
# Usage:
#   ./run_tests.sh                              # all tests
#   ./run_tests.sh --filter FullyQualifiedName~Blake3
#   ./run_tests.sh --logger 'console;verbosity=detailed'

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

if [[ ! -f "$DIST_DIR/libitb.so" ]]; then
    echo "error: libitb.so not found at $DIST_DIR" >&2
    echo "       run ./build.sh first" >&2
    exit 1
fi

export LD_LIBRARY_PATH="$DIST_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

exec dotnet test -c Release "$@"
