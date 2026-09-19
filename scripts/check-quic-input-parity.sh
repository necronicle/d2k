#!/bin/sh
# Local-only donor oracle. No router, external server or traffic mutation.
# Requires the pinned donor checkout and Go 1.25.12 (tests only, not runtime).
# --export-profile explicitly regenerates core/profiles/quic_probe.h before
# rebuilding and checking. Without that flag no tracked file is changed.
set -eu
D2K_REPO=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2K_DONOR=${D2K_REF_ROOT:-"$D2K_REPO/../z2k"}
D2K_GO=${D2K_REF_GO:-go}
D2K_PIN=e9a391347671cbb07663d2bee5b3d92f016c789e
case "${1:-}" in
    '') D2K_EXPORT=0 ;;
    --export-profile) D2K_EXPORT=1 ;;
    *) echo 'usage: check-quic-input-parity.sh [--export-profile]' >&2; exit 2 ;;
esac
case "$("$D2K_GO" version)" in
    *' go1.25.12 '*) ;;
    *) echo 'Expected donor Go 1.25.12; set D2K_REF_GO to its executable.' >&2; exit 1 ;;
esac
git -C "$D2K_DONOR" diff --quiet "$D2K_PIN" -- \
    z2k-detect/internal/quicprobe/hello.go z2k-detect/internal/quicprobe/initial.go || {
    echo 'Donor input differs from pinned source; review before regenerating.' >&2; exit 1;
}
D2K_ORACLE_TMP=$(mktemp -d "${TMPDIR:-/tmp}/d2k-quic-oracle.XXXXXX")
trap 'rm -rf "$D2K_ORACLE_TMP"' EXIT HUP INT TERM
cp "$D2K_DONOR/z2k-detect/internal/quicprobe/hello.go" \
   "$D2K_DONOR/z2k-detect/internal/quicprobe/initial.go" \
   "$D2K_REPO/tests/quic-input/compare_test.go" "$D2K_ORACLE_TMP/"
cd "$D2K_ORACLE_TMP"
if [ "$D2K_EXPORT" = 1 ]; then
    GO111MODULE=off D2K_QUIC_PROFILE_OUT="$D2K_REPO/core/profiles/quic_probe.h" \
        "$D2K_GO" test -tags d2k_donor -run TestExportD2KProbeProfile -count=1 -v
fi
make -C "$D2K_REPO/core" test_quichello
GO111MODULE=off D2K_QUIC_INPUT_BIN="$D2K_REPO/core/test_quichello" \
    "$D2K_GO" test -tags d2k_donor -run TestD2KProbeHelloParity -count=1 -v
