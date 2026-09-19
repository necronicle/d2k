#!/bin/sh
# Isolated Linux veth/server namespace with real SNAT, never the router.
# Build the local test image separately (packages only, no project secrets):
# docker build -t d2k-fragment-test -f tests/fragment-plan/Dockerfile tests/fragment-plan
set -eu
D2K_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2K_TMP=$(mktemp -d "${TMPDIR:-/tmp}/d2k-fragment-plan.XXXXXX")
trap 'rm -rf "$D2K_TMP"' EXIT HUP INT TERM
cd "$D2K_ROOT"
make -C core hello_profiles.inc
# Test-only syscall fault injection, confined to the actual raw.c object.
"${D2K_ZIG:-zig}" cc -target aarch64-linux-musl -std=c99 -O2 -Wall -Wextra -Werror \
    -Idatapath/include -Dsetsockopt=d2k_test_setsockopt -c datapath/raw.c -o "$D2K_TMP/raw.o"
"${D2K_ZIG:-zig}" cc -target aarch64-linux-musl -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$D2K_ROOT/datapath/include" -I"$D2K_ROOT/core/include" \
    "$D2K_ROOT/tests/fragment-plan/raw.c" "$D2K_TMP/raw.o" \
    tests/fragment-plan/nfq.c tests/fragment-plan/compose.c core/compose.c core/plantlv.c core/hello.c core/meas.c core/link.c \
    core/quichello.c core/tls13core.c core/x25519.c core/quic.c core/quicwire.c core/crypto.c core/ipfrag.c \
    datapath/plan_parse.c datapath/plan_apply.c datapath/session.c datapath/hold.c datapath/capture.c \
    datapath/track.c datapath/tls.c datapath/wire.c datapath/wire_udp.c datapath/nat.c \
    datapath/journal.c datapath/plans.c -lpthread -o "$D2K_TMP/raw-test"
"${D2K_ZIG:-zig}" cc -target aarch64-linux-musl -std=c99 -O2 -Wall -Wextra -Werror \
    -Idatapath/include -Dsetsockopt=d2k_test_setsockopt -Dsendto=d2k_test_sendto \
    -c datapath/raw.c -o "$D2K_TMP/raw-daemon.o"
"${D2K_ZIG:-zig}" cc -target aarch64-linux-musl -std=c99 -O2 -Wall -Wextra -Werror \
    -Idatapath/include -Icore/include -o "$D2K_TMP/d2kd-test" \
    datapath/d2kd.c datapath/nfq.c "$D2K_TMP/raw-daemon.o" tests/fragment-plan/daemon_faults.c \
    datapath/plan_parse.c datapath/plan_apply.c datapath/tls.c datapath/capture.c \
    datapath/hold.c datapath/wire.c datapath/wire_udp.c datapath/track.c \
    datapath/session.c datapath/nat.c datapath/nl.c datapath/sched.c \
    datapath/journal.c datapath/plans.c datapath/ctl.c datapath/ctlsrv.c \
    core/quic.c core/quicwire.c core/crypto.c core/ipfrag.c
cp tests/fragment-plan/nfq.sh "$D2K_TMP/nfq.sh"
docker run --rm --pull never --network none --read-only --tmpfs /tmp --tmpfs /run \
    --cap-drop ALL --cap-add NET_RAW --cap-add NET_ADMIN --cap-add SYS_ADMIN \
    --security-opt no-new-privileges \
    -v "$D2K_TMP:/w:ro" \
    d2k-fragment-test sh -ec '
        iptables -A OUTPUT -m conntrack --ctstate INVALID -j ACCEPT
        ip netns add d2k-server
        ip link add d2k-out type veth peer name d2k-in
        ip link set d2k-in netns d2k-server
        ip addr add 10.77.0.1/24 dev d2k-out
        ip addr add 10.78.0.2/32 dev lo
        ip link set d2k-out up
        ip -n d2k-server addr add 10.77.0.2/24 dev d2k-in
        ip -n d2k-server link set d2k-in up
        ip -n d2k-server link set lo up
        iptables -t nat -A POSTROUTING -p udp -s 10.78.0.2 -d 10.77.0.2 \
            --sport 54000 --dport 54321 -j SNAT --to-source 10.77.0.1:55000
        ip netns exec d2k-server /w/raw-test server &
        sleep 0.1
        /w/raw-test
        sh /w/nfq.sh
    '
