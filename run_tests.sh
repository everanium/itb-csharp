#!/usr/bin/env bash
#
# run_tests.sh -- one-step test runner for the C# / .NET binding.
# Builds libitb3.so + the solution via build.sh, points
# ITB_LIBITB3_PATH at the freshly-built shared library, then invokes
# `dotnet test -c Release`. Positional arguments are forwarded
# through to dotnet test (e.g. `--filter` to scope the run).
#
# build.sh wipes the bin/ and obj/ tree of every project in the
# solution before it builds, so the assemblies exercised here -- the
# test assembly included -- are always the ones this invocation
# produced, which is what makes the --no-build below safe. Set
# ITB_SKIP_CLEAN=1 to keep the existing artefacts and build
# incrementally instead.
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

export ITB_LIBITB3_PATH="$DIST_DIR/libitb3.so"

exec dotnet test Everanium.LibItb3.sln -c Release --no-build "$@"
