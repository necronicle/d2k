#!/bin/sh
# Independent TLS 1.2/1.3 and HTTP/3 application proof over native IPv6.
# Docker only; never contacts the router or a public application endpoint.
set -eu
if [ "${1:-}" != --inside ]; then
    ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
    WORK=$(mktemp -d /tmp/d2k-native-protocols.XXXXXX)
    trap 'rm -rf "$WORK"' EXIT INT TERM
    cd "$ROOT"
    tar -cf - core/include datapath/include runtime/d2k_protocol.h core/profiles/psl_index.h core/profiles/rx_fake.h core/tcp1620_whitelist.inc core/doh_h2.inc core/dns_question_wire.inc core/verify.c core/dns_upstreams.c core/domain.c core/suite.c core/mlkem.c core/keccak.c core/tls13.c core/tls12.c core/p256.c \
        core/tls13core.c core/x25519.c core/crypto.c core/hello.c core/hello_profiles.inc \
        core/meas.c core/link.c core/compose.c core/measured.c core/quicconn.c core/quicwire.c core/h3.c \
        tests/native-protocol-probe.c tests/native-h3-server.py scripts/check-native-protocols.sh \
        | tar -C "$WORK" -xf -
    docker run --rm -v "$WORK:/w" -w /w gcc:14 sh scripts/check-native-protocols.sh --inside
    exit
fi

apt-get update -qq
apt-get install -y -qq openssl python3-aioquic >/dev/null
cc -std=c99 -O2 -DD2K_RELEASE_ID='"dev"' -Wall -Wextra -Werror -Icore/include -Idatapath/include \
    -o /tmp/native-probe tests/native-protocol-probe.c core/verify.c core/dns_upstreams.c core/domain.c core/suite.c core/mlkem.c core/keccak.c core/tls13.c \
    core/tls12.c core/p256.c core/tls13core.c core/x25519.c core/crypto.c core/hello.c core/meas.c \
    core/link.c core/compose.c core/measured.c core/quicconn.c core/quicwire.c core/h3.c
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout /tmp/native-key.pem -out /tmp/native-cert.pem -days 1 -nodes \
    -subj /CN=ipv6.example -addext subjectAltName=DNS:ipv6.example >/dev/null 2>&1
openssl s_server -accept '[::1]:4443' -cert /tmp/native-cert.pem \
    -key /tmp/native-key.pem -www -quiet >/tmp/native-tls.log 2>&1 &
tls_pid=$!
python3 tests/native-h3-server.py /tmp/native-cert.pem /tmp/native-key.pem >/tmp/native-h3.log 2>&1 &
h3_pid=$!
trap 'kill "$tls_pid" "$h3_pid" 2>/dev/null || true' EXIT INT TERM
i=0
while ! grep -q 'HTTP/3 ready' /tmp/native-h3.log; do
    kill -0 "$h3_pid" "$tls_pid" || { cat /tmp/native-h3.log /tmp/native-tls.log; exit 1; }
    i=$((i + 1))
    [ "$i" -lt 100 ] || { echo 'server startup timeout' >&2; exit 1; }
    sleep 0.05
done
/tmp/native-probe 12 ::1 4443 ipv6.example
/tmp/native-probe 13 ::1 4443 ipv6.example
/tmp/native-probe quic ::1 4444 ipv6.example
grep -q 'HTTP/3 request' /tmp/native-h3.log
cat /tmp/native-h3.log
echo 'native IPv6: TLS 1.2, TLS 1.3 and HTTP/3 application proof on reserved ports passed'
