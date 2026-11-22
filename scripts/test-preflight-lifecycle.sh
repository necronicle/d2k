#!/bin/sh
# shellcheck disable=SC1091,SC2034 # dynamic shell fixtures or runtime config
set -eu
task_tmp=$(mktemp -d)
trap 'rm -rf "$task_tmp"' EXIT HUP INT TERM
awk '/^engine_stop\(\)/,/^}/' "${DNS_TEST_SERVICE:-files/S99d2k}" > "$task_tmp/functions"
. "$task_tmp/functions"
RUN="$task_tmp/run";mkdir "$RUN"
SOCK="$RUN/no-socket" HL_PID=heal SH_PID=shadow CT_PID=controller DP_PID=datapath
stop_pidfile() { printf '%s\n' "stop:$1" >> "$RUN/order"; }
fw_down() { printf '%s\n' firewall >> "$RUN/order";return "$FAIL_FW"; }
legacy_http_stop() { :; }
fastnat_restore() { :; }
flowoffload_restore() { :; }
late_chains_down() { :; }
rst_rules_down() { :; }
say() { :; }
FAIL_FW=0
: > "$RUN/preflight-active"
engine_stop
python3 - "$RUN/order" <<'PYTEST'
import pathlib,sys
rows=pathlib.Path(sys.argv[1]).read_text().splitlines()
assert rows.index('stop:controller')<rows.index('firewall') and rows.index('stop:datapath')<rows.index('firewall'), 'active response owner must stop before its NF_REPEAT release rules disappear'
PYTEST
[ ! -f "$RUN/preflight-active" ]
: > "$RUN/preflight-active"
: > "$RUN/order"
FAIL_FW=1
if engine_stop; then echo 'failed firewall cleanup was reported as completed stop' >&2;exit 1;fi
grep -qx 'stop:datapath' "$RUN/order"
printf '%s\n' 'response lifecycle: owners stop before release rules; cleanup failure remains visible'

# The watchdog may have seen a partial ruleset while another service action
# was rebuilding it. By the time it acquires the lock both daemons are live.
awk '/^reapply\(\)/,/^}/' "${DNS_TEST_SERVICE:-files/S99d2k}" > "$task_tmp/reapply"
. "$task_tmp/reapply"
preflight_validate() { :; }
watch_validate() { :; }
running() { return 0; }
fw_installed() { return "$missing"; }
engine_stop() { echo stop >> "$RUN/calls"; }
start_engine() { echo start >> "$RUN/calls"; }
svc_log() { :; }
engine_evidence() { :; }
D2K_PREFLIGHT=1
missing=0
: > "$RUN/calls"
reapply auto
[ ! -s "$RUN/calls" ] || { echo 'watchdog restarted a healthy engine using a stale status'; exit 1; }
missing=1
FW_BACKEND=iptables
can_recover=1
fw_recover_mangle() { [ "$can_recover" = 1 ] && echo live-repair >> "$RUN/calls"; }
can_partial=0
fw_recover_partial() { [ "$can_partial" = 1 ] && echo partial-repair >> "$RUN/calls"; }
reapply auto
[ "$(cat "$RUN/calls")" = live-repair ] || { echo 'NDM mangle reset restarted live processes'; exit 1; }
: > "$RUN/calls"
can_recover=0
missing=1
can_partial=1
reapply auto
[ "$(cat "$RUN/calls")" = partial-repair ] || { echo 'partial preflight loss restarted live processes'; exit 1; }
: > "$RUN/calls"
can_partial=0
reapply auto
[ "$(cat "$RUN/calls")" = "$(printf 'stop\nstart')" ]
: > "$RUN/calls"
missing=0
reapply
[ "$(cat "$RUN/calls")" = "$(printf 'stop\nstart')" ]
