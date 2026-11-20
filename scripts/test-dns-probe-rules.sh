#!/bin/sh
set -eu
task_tmp=$(mktemp -d)
trap 'rm -rf "$task_tmp"' EXIT HUP INT TERM
awk '/^dns_local_route_rule\(\)/,/^\)/' "${DNS_TEST_SERVICE:-files/S99d2k}" > "$task_tmp/functions"
awk '/^dns_excl_rule\(\)/,/^}/' "${DNS_TEST_SERVICE:-files/S99d2k}" >> "$task_tmp/functions"
. "$task_tmp/functions"
CHAIN_OUT=D2K_OUT CHAIN_IN=D2K_IN PROBE_MARK=0x2e QUEUE_NUM=2000 FW_V4ONLY="$task_tmp/ipv4-only"
DNS_TEST_LOG="$task_tmp/rules";export DNS_TEST_LOG
iptables() { printf 'v4 %s\n' "$*" >> "$DNS_TEST_LOG";case " $* " in *' -C '*) return 1;;esac; }
ip6tables() { printf 'v6 %s\n' "$*" >> "$DNS_TEST_LOG";case " $* " in *' -C '*) return 1;;esac; }
dns_excl_rule -A 192.0.2.53 8443
dns_excl_rule -A 2001:db8::53 8443
python3 - "$DNS_TEST_LOG" <<'PY'
import pathlib,sys
lines=pathlib.Path(sys.argv[1]).read_text().splitlines()
installed=[line.split() for line in lines if ' -I ' in line]
assert len(installed)==8
for args in installed:
    assert args[args.index('-p')+1] in ('tcp','udp')
    if 'D2K_OUT' in args:
        assert args[args.index('--dport')+1]=='8443'
        assert args[args.index('--mark')-1]=='!'
        assert args[args.index('--mark')+1]=='0x2e'
    else:
        assert 'D2K_IN' in args and args[args.index('--sport')+1]=='8443'
        assert '--mark' not in args
    assert args[-2:]==['-j','RETURN']
PY
printf '%s\n' 'DNS probe rules: own outbound verifier mark remains eligible; ordinary IPv4/IPv6 TCP/UDP and replies stay protected'

RUN="$task_tmp"
printf '%s\n' 'unlisted.example.test 192.0.2.53 8443 tcp' > "$RUN/dns-routes"
: > "$DNS_TEST_LOG"
dns_excl_rule -A 192.0.2.53 8443
python3 - "$DNS_TEST_LOG" <<'PYTEST'
import pathlib,sys
installed=[line.split() for line in pathlib.Path(sys.argv[1]).read_text().splitlines() if ' -I ' in line]
protected=[args for args in installed if args[-1]=='RETURN']
assert len(protected)==4, 'router DNS permission must keep forwarded TCP and UDP protected'
assert any('INPUT' in args and 'NFQUEUE' in args and args[args.index('-p')+1]=='tcp' for args in installed)
assert any('OUTPUT' in args and '--set-xmark' in args and args[args.index('--set-xmark')+1]=='0x2e/0xffffffff' and args[args.index('--mark')+1]=='0' for args in installed), 'router DNS must remain eligible when client policy is selected'
PYTEST
printf '%s\n' 'unlisted.example.test 192.0.2.53 853 tcp' > "$RUN/dns-routes"
: > "$DNS_TEST_LOG"
dns_excl_rule -A 192.0.2.53 853
python3 - "$DNS_TEST_LOG" <<'PYTEST'
import pathlib,sys
queued=[line.split() for line in pathlib.Path(sys.argv[1]).read_text().splitlines() if ' -I ' in line and 'NFQUEUE' in line]
assert len(queued)==1 and queued[0][queued[0].index('-I')+1]=='INPUT', 'early DNS replies must queue only for the router, never forwarded LAN devices'
PYTEST
printf '%s\n' 'resolver.example.test 192.0.2.53 53 udp' > "$RUN/dns-routes"
: > "$DNS_TEST_LOG"
dns_excl_rule -A 192.0.2.53 53
python3 - "$DNS_TEST_LOG" <<'PYTEST'
import pathlib,sys
installed=[line.split() for line in pathlib.Path(sys.argv[1]).read_text().splitlines() if ' -I ' in line]
owned=[a for a in installed if 'd2k-dns-route' in a]
assert {a[a.index('-I')+1] for a in owned}=={'OUTPUT','INPUT'}
assert all(a[a.index('-p')+1]=='udp' for a in owned), 'DNS/UDP permission must not admit TCP'
protected=[a for a in installed if a[-1]=='RETURN']
assert len(protected)==4, 'router DNS/UDP permission must keep forwarded DNS protected'
PYTEST
