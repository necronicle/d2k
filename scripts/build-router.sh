#!/bin/sh
# Complete C-only installable packages. Each architecture has isolated SSL objects.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
ARCHES=${ARCHES:-"arm64 arm mipsel mips mips64el amd64 x86 ppc64 riscv64"}
OUT=${OUT:-"$ROOT/builds"}
mkdir -p "$OUT"
OUT=$(CDPATH='' cd -- "$OUT" && pwd)
ZIG=${ZIG:-zig}
COMMIT=$(git -C "$ROOT" rev-parse HEAD)
BUILT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
DIRTY=0
[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ] || DIRTY=1
for ARCH in $ARCHES; do
    . "$ROOT/scripts/build-target.sh"
    echo "=== $ARCH ($TARGET $TARGET_FLAGS) ==="
    ARCH="$ARCH" ZIG="$BUILD_ZIG" OUT="$OUT" sh "$ROOT/scripts/build-openssl-tg.sh"
    for component in datapath core panel; do
        make -C "$ROOT/$component" release ARCH="$ARCH" TARGET="$TARGET" \
            TARGET_FLAGS="$TARGET_FLAGS" ZIG="$BUILD_ZIG" BUILDDIR="$OUT" \
            COMMIT="$COMMIT" BUILT="$BUILT" DIRTY="$DIRTY" RELEASE_ID="${RELEASE_ID:-dev}" VERSION="${VERSION:-0.1.0-mvp}"
    done
done
