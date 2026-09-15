#!/usr/bin/env bash
#
# build.sh -- one-step build for the C# / .NET binding: libitb3.so +
# dotnet build. Prerequisites (Go, dotnet-sdk) must be installed
# separately; see README.md "Prerequisites" section.
#
# The build starts from an empty tree: the bin/ and obj/ directories of
# every project in the solution, plus any test result output, are
# removed first, so no assembly can survive from an earlier invocation.
#
# Everanium.LibItb3/bin is shared: the F#, VB.NET and PowerShell
# bindings all resolve this assembly, and the PowerShell module does so
# through a `bin/<config>/net*/Everanium.LibItb3.dll` glob. A target
# framework directory left behind beside the current one is therefore
# ambiguous to that glob, which is why the wipe takes the whole bin
# tree rather than the current framework's subdirectory.
#
# Set ITB_SKIP_CLEAN=1 to keep the existing artefacts and let MSBuild
# build incrementally. With no environment set the wipe always runs.
#
# Usage:
#   ./build.sh             # default build (full asm stack)
#   ./build.sh --noitbasm  # opt out of ITB's SIMD asm kernels

set -eu
set -o pipefail

cd "$(dirname "$0")"
BINDING_DIR="$(pwd -P)"
REPO_ROOT="$(cd ../.. && pwd -P)"
START_EPOCH="$(date +%s)"
SKIP_CLEAN="${ITB_SKIP_CLEAN:-0}"

TAGS=()
case "${1:-}" in
    --noitbasm) TAGS=(-tags=noitbasm); shift;;
    -h|--help)  echo "usage: $0 [--noitbasm]"; exit 0;;
    "")         ;;
    *)          echo "unknown option: $1" >&2; exit 2;;
esac

# clean_under <root> <relative-path>...
#
# Removes each relative path under <root>. A target is removed only
# when it is a literal relative path (no leading slash, no ".."), it
# exists, and it still resolves inside <root> after symlinks are
# followed -- so a target can never escape the tree it belongs to.
# Every removal is logged before it happens, and a failing rm aborts
# the script rather than being swallowed.
clean_under() {
    local root="$1"; shift
    local rel abs
    root="$(realpath -e "$root")"
    for rel in "$@"; do
        case "$rel" in
            "" | /* | *..*)
                echo "clean: refusing suspicious target '$rel'" >&2
                exit 1
                ;;
        esac
        abs="$root/$rel"
        if [ ! -e "$abs" ] && [ ! -L "$abs" ]; then
            echo "[clean] (absent) $abs"
            continue
        fi
        abs="$(realpath -e "$abs")"
        case "$abs/" in
            "$root"/?*) ;;
            *)
                echo "clean: refusing to remove '$abs' -- outside $root" >&2
                exit 1
                ;;
        esac
        echo "[clean] rm -rf $abs"
        rm -rf "$abs"
    done
}

# require_built <path-glob>
#
# Asserts that a build artefact exists and, when the clean stage ran,
# that it was written by this invocation rather than inherited from an
# earlier one. The argument is a glob so the target framework
# directory does not have to be pinned here.
require_built() {
    local pattern="$1"
    local matches=()
    local f
    # shellcheck disable=SC2206  # deliberate glob expansion
    matches=( $pattern )
    # An unmatched glob stays unexpanded, so a lone entry that is not a
    # file means the build produced nothing at that path.
    if [ "${#matches[@]}" -eq 1 ] && [ ! -f "${matches[0]}" ]; then
        echo "build.sh: expected artefact was not produced: $pattern" >&2
        exit 1
    fi
    if [ "${#matches[@]}" -ne 1 ]; then
        echo "build.sh: $pattern matched ${#matches[@]} artefacts —" \
             "a target framework directory left behind beside the" \
             "current one is the usual cause" >&2
        exit 1
    fi
    f="${matches[0]}"
    if [ "$SKIP_CLEAN" != "1" ] && [ "$(stat -c %Y "$f")" -lt "$START_EPOCH" ]; then
        echo "build.sh: artefact predates this invocation: $f" >&2
        exit 1
    fi
}

if [ "$SKIP_CLEAN" = "1" ]; then
    echo "==> ITB_SKIP_CLEAN=1 — keeping existing artefacts"
else
    echo "==> cleaning C# binding artefacts"
    clean_under "$BINDING_DIR" \
        Everanium.LibItb3/bin           Everanium.LibItb3/obj \
        Everanium.LibItb3.Tests/bin     Everanium.LibItb3.Tests/obj \
        Everanium.LibItb3.Tests/TestResults \
        Everanium.LibItb3.Bench/bin     Everanium.LibItb3.Bench/obj \
        Everanium.LibItb3.Eitb/bin      Everanium.LibItb3.Eitb/obj \
        TestResults
fi

cd "$REPO_ROOT"
echo "==> building libitb3.so${TAGS:+ (with ${TAGS[*]})}"
go build -trimpath "${TAGS[@]}" -buildmode=c-shared \
    -o dist/linux-amd64/libitb3.so ./cmd/cshared

cd "$BINDING_DIR"
# The solution carries the library, the test, the bench and the eitb
# projects, so one build covers every artefact the sibling scripts run.
echo "==> building C# / .NET binding (dotnet build -c Release)"
dotnet build Everanium.LibItb3.sln -c Release

require_built "$BINDING_DIR/Everanium.LibItb3/bin/Release/net*/Everanium.LibItb3.dll"
require_built "$BINDING_DIR/Everanium.LibItb3.Eitb/bin/Release/net*/Everanium.LibItb3.Eitb.dll"
require_built "$BINDING_DIR/Everanium.LibItb3.Bench/bin/Release/net*/Everanium.LibItb3.Bench.dll"

echo "==> ready: ./run_tests.sh"
