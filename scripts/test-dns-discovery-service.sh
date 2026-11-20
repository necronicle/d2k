#!/bin/sh
set -eu
task_tmp=$(mktemp -d)
trap 'rm -rf "$task_tmp"' EXIT HUP INT TERM
mkdir "$task_tmp/bin" "$task_tmp/run"
cat > "$task_tmp/input" <<'EOF'
dns_server = 127.0.0.1 # https://unlisted.example.test:8443/private/dns-query?account=fixture
EOF
cat > "$task_tmp/bin/ndmc" <<'EOF'
#!/bin/sh
[ "$1" = -c ] && [ "$2" = 'show dns-proxy' ] || exit 2
cat "$DNS_TEST_INPUT"
[ "${DNS_TEST_FAILURE:-0}" = 0 ]
EOF
chmod +x "$task_tmp/bin/ndmc"
awk '/^dns_config_snapshot\(\)/,/^\)/' files/S99d2k > "$task_tmp/functions"
awk '/^dns_upstreams\(\)/,/^}/' files/S99d2k >> "$task_tmp/functions"
PATH="$task_tmp/bin:$PATH" RUN="$task_tmp/run" DNS_TEST_INPUT="$task_tmp/input"
export PATH RUN DNS_TEST_INPUT
. "$task_tmp/functions"
dns_config_snapshot >/dev/null
cmp "$task_tmp/input" "$RUN/dns-upstreams"
python3 -c 'import os,stat,sys; assert stat.S_IMODE(os.stat(sys.argv[1]).st_mode)==0o600' "$RUN/dns-upstreams"
[ "$(dns_upstreams)" = 'unlisted.example.test 8443' ]
cp "$RUN/dns-upstreams" "$task_tmp/previous"
printf '%s\n' 'partial failed configuration' > "$task_tmp/input"
DNS_TEST_FAILURE=1;export DNS_TEST_FAILURE
dns_config_snapshot >/dev/null
cmp "$task_tmp/previous" "$RUN/dns-upstreams"
awk '/^spawn_controller\(\)/,/^}/' files/S99d2k >> "$task_tmp/functions"
. "$task_tmp/functions"
spawn_daemon() { printf '%s\n' "$@" > "$RUN/controller-arguments"; }
wait_running() { return 0; }
pid_stamp() { return 0; }
CT_PID="$RUN/controller.pid" BIN=/fixture/d2kc SOCK="$RUN/control" DIR="$task_tmp"
LIVE="$RUN/live.json" LOG="$RUN" RUNTIME_DIR="$RUN" STATE_DIR="$task_tmp/state"
PROBE_MARK=46 MEASURE_MARK=47 D2K_PREFLIGHT=0 NEWCHAIN=0 SHADOW=0 EXP_CONTROL=0 SYNTHESIS_ONLY=0
spawn_controller
python3 - "$RUN" <<'PY'
import pathlib,sys
root=pathlib.Path(sys.argv[1]);args=(root/'controller-arguments').read_text().splitlines()
assert args[args.index('--dns-upstreams')+1]==str(root/'dns-upstreams')
assert args[args.index('--dns-addresses')+1]==str(root/'dns-excl')
assert '--synthesis-only' not in args
PY
printf '%s\n' 'DNS discovery service: private exact snapshot, existing endpoint protection parser, failed-refresh retention'
