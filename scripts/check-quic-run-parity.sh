#!/bin/sh
# Real UDP loopback only; never touches the router, target sites or donor files.
set -eu
D2K_REPO=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2K_DONOR=${D2K_REF_ROOT:-"$D2K_REPO/../z2k"}
D2K_GO=${D2K_REF_GO:-go}
D2K_PIN=e9a391347671cbb07663d2bee5b3d92f016c789e
D2K_QUIC_TESTS=${D2K_QUIC_TESTS:-'TestD2K(RunTerminal|Arms|Blob|Residual|Fragments)Parity'}
case "${1:-}" in
    '') D2K_LINUX=0 ;;
    --linux) D2K_LINUX=1 ;;
    --linux-raw) D2K_LINUX=2; D2K_QUIC_TESTS=TestD2KRawFragments ;;
    --linux-raw-conntrack) D2K_LINUX=3; D2K_QUIC_TESTS=TestD2KRawFragments ;;
    *) echo 'usage: check-quic-run-parity.sh [--linux|--linux-raw|--linux-raw-conntrack]' >&2; exit 2 ;;
esac
case "$("$D2K_GO" version)" in
    *' go1.25.12 '*) ;;
    *) echo 'Set D2K_REF_GO to donor Go 1.25.12.' >&2; exit 1 ;;
esac
git -C "$D2K_DONOR" diff --quiet "$D2K_PIN" -- z2k-detect/internal/quicprobe \
    files/fake/quic_5.bin files/fake/quic_initial_www_google_com.bin \
    files/fake/quic_initial_rutracker_org.bin || {
    echo 'Review changes in donor quicprobe before updating the baseline.' >&2; exit 1;
}
D2K_TMP=$(mktemp -d "${TMPDIR:-/tmp}/d2k-quic-run.XXXXXX")
trap 'rm -rf "$D2K_TMP"' EXIT HUP INT TERM
cp "$D2K_DONOR/z2k-detect/go.mod" "$D2K_TMP/go.mod"
cp "$D2K_DONOR/z2k-detect/go.sum" "$D2K_TMP/go.sum"
cp -R "$D2K_DONOR/z2k-detect/internal/quicprobe" "$D2K_TMP/quicprobe"
cp "$D2K_REPO/tests/quic-run/compare_test.go" "$D2K_TMP/quicprobe/d2k_compare_test.go"
cp "$D2K_REPO/tests/quic-run/arms_test.go" "$D2K_TMP/quicprobe/d2k_arms_test.go"
cp "$D2K_REPO/tests/quic-run/fragments_test.go" "$D2K_TMP/quicprobe/d2k_fragments_test.go"
cp "$D2K_REPO/tests/quic-run/fragments_linux_test.go" "$D2K_TMP/quicprobe/d2k_fragments_linux_test.go"
mkdir "$D2K_TMP/blobs"
for b in quic_5.bin quic_initial_www_google_com.bin quic_initial_rutracker_org.bin; do
    cp "$D2K_DONOR/files/fake/$b" "$D2K_TMP/blobs/$b"
done
cd "$D2K_REPO/core"
make hello_profiles.inc
build_c() {
    "$@" -std=c99 -O2 -Wall -Wextra -Werror -Iinclude -I../datapath/include \
        -Dsetsockopt=d2k_test_setsockopt -c quicprobe.c -o "$D2K_TMP/quicprobe.o"
    "$@" -std=c99 -O2 -Wall -Wextra -Werror -Iinclude -I../datapath/include \
        -o "$D2K_TMP/d2k-run" ../tests/quic-run/main.c "$D2K_TMP/quicprobe.o" quicarms.c ipfrag.c props.c net4.c \
        quichello.c hello.c tls13core.c x25519.c quic.c quicwire.c crypto.c meas.c -lpthread
}
if [ "$D2K_LINUX" != 0 ]; then
    [ "$(docker image inspect gcc:14 --format '{{.Architecture}} {{.Os}}')" = 'arm64 linux' ] || {
        echo 'Linux check requires the existing arm64 gcc:14 image; no image is pulled.' >&2; exit 1;
    }
    build_c "${D2K_ZIG:-zig}" cc -target aarch64-linux-musl
else
    build_c ${CC:-cc}
fi
cd "$D2K_TMP"
if [ "$D2K_LINUX" != 0 ]; then
    GOOS=linux GOARCH=arm64 CGO_ENABLED=0 "$D2K_GO" test -c -tags d2k_donor \
        -o "$D2K_TMP/oracle.test" ./quicprobe
    set -- --cap-drop ALL
    if [ "$D2K_LINUX" -ge 2 ]; then set -- "$@" --cap-add NET_RAW; fi
    if [ "$D2K_LINUX" = 3 ]; then
        # Built by tests/fragment-plan/Dockerfile. Only this disposable
        # container's loopback/OUTPUT conntrack changes; no outside network.
        docker run --rm --pull never --network none --read-only --tmpfs /tmp --tmpfs /run \
            "$@" --cap-add NET_ADMIN --security-opt no-new-privileges \
            -v "$D2K_TMP:/w:ro" -e D2K_QUIC_RUN_BIN=/w/d2k-run -e D2K_QUIC_BLOBS=/w/blobs \
            -e D2K_CONNTRACK=1 d2k-fragment-test sh -ec '
                iptables -A OUTPUT -m conntrack --ctstate INVALID -j ACCEPT
                exec /w/oracle.test -test.run TestD2KRawFragments -test.v
            '
        exit
    fi
    docker run --rm --pull never --network none --read-only --tmpfs /tmp \
        "$@" --security-opt no-new-privileges \
        -v "$D2K_TMP:/w:ro" -e D2K_QUIC_RUN_BIN=/w/d2k-run -e D2K_QUIC_BLOBS=/w/blobs \
        gcc:14 /w/oracle.test -test.run "$D2K_QUIC_TESTS" -test.v
else
    D2K_QUIC_RUN_BIN="$D2K_TMP/d2k-run" D2K_QUIC_BLOBS="$D2K_TMP/blobs" "$D2K_GO" test -tags d2k_donor \
        ./quicprobe -run "$D2K_QUIC_TESTS" -count=1 -v
fi
