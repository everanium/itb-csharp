#!/usr/bin/env bash
#
# run_tests.sh -- one-step test runner for the C# / .NET binding.
# Builds libitb.so + the solution via build.sh, points
# ITB_LIBITB_PATH at the freshly-built shared library, then invokes
# `dotnet test -c Release`. Positional arguments are forwarded
# through to dotnet test (e.g. `--filter` to scope the run).
#
# Usage:
#   ./run_tests.sh                              # all tests
#   ./run_tests.sh --filter FullyQualifiedName~Smoke
#   ./run_tests.sh --logger 'console;verbosity=detailed'

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

./build.sh

export ITB_LIBITB_PATH="$DIST_DIR/libitb.so"

exec dotnet test Itb.sln -c Release --no-build "$@"
