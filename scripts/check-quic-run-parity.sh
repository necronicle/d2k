#!/bin/sh
# Real UDP loopback only; never touches the router, target sites or donor files.
set -eu
D2K_REPO=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2K_DONOR=${D2K_REF_ROOT:-"$D2K_REPO/../z2k"}
D2K_GO=${D2K_REF_GO:-go}
D2K_PIN=e9a391347671cbb07663d2bee5b3d92f016c789e
case "${1:-}" in
    '') D2K_LINUX=0 ;;
    --linux) D2K_LINUX=1 ;;
    *) echo 'usage: check-quic-run-parity.sh [--linux]' >&2; exit 2 ;;
esac
case "$("$D2K_GO" version)" in
    *' go1.25.12 '*) ;;
    *) echo 'Set D2K_REF_GO to donor Go 1.25.12.' >&2; exit 1 ;;
esac
git -C "$D2K_DONOR" diff --quiet "$D2K_PIN" -- z2k-detect/internal/quicprobe || {
    echo 'Review changes in donor quicprobe before updating the baseline.' >&2; exit 1;
}
D2K_TMP=$(mktemp -d "${TMPDIR:-/tmp}/d2k-quic-run.XXXXXX")
trap 'rm -rf "$D2K_TMP"' EXIT HUP INT TERM
cp "$D2K_DONOR/z2k-detect/go.mod" "$D2K_TMP/go.mod"
cp "$D2K_DONOR/z2k-detect/go.sum" "$D2K_TMP/go.sum"
cp -R "$D2K_DONOR/z2k-detect/internal/quicprobe" "$D2K_TMP/quicprobe"
cp "$D2K_REPO/tests/quic-run/compare_test.go" "$D2K_TMP/quicprobe/d2k_compare_test.go"
cd "$D2K_REPO/core"
make hello_profiles.inc
build_c() {
    "$@" -std=c99 -O2 -Wall -Wextra -Werror -Iinclude -I../datapath/include \
        -o "$D2K_TMP/d2k-run" ../tests/quic-run/main.c quicprobe.c net4.c \
        quichello.c hello.c tls13core.c x25519.c quic.c quicwire.c crypto.c meas.c -lpthread
}
if [ "$D2K_LINUX" = 1 ]; then
    [ "$(docker image inspect gcc:14 --format '{{.Architecture}} {{.Os}}')" = 'arm64 linux' ] || {
        echo 'Linux check requires the existing arm64 gcc:14 image; no image is pulled.' >&2; exit 1;
    }
    build_c "${D2K_ZIG:-zig}" cc -target aarch64-linux-musl
else
    build_c ${CC:-cc}
fi
cd "$D2K_TMP"
if [ "$D2K_LINUX" = 1 ]; then
    GOOS=linux GOARCH=arm64 CGO_ENABLED=0 "$D2K_GO" test -c -tags d2k_donor \
        -o "$D2K_TMP/oracle.test" ./quicprobe
    docker run --rm --pull never --network none --read-only --tmpfs /tmp \
        --cap-drop ALL --security-opt no-new-privileges \
        -v "$D2K_TMP:/w:ro" -e D2K_QUIC_RUN_BIN=/w/d2k-run \
        gcc:14 /w/oracle.test -test.run TestD2KRunTerminalParity -test.v
else
    D2K_QUIC_RUN_BIN="$D2K_TMP/d2k-run" "$D2K_GO" test -tags d2k_donor \
        ./quicprobe -run TestD2KRunTerminalParity -count=1 -v
fi
