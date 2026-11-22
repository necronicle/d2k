#!/bin/sh
# shellcheck disable=SC1091,SC2034 # Runtime functions loaded from the init script.
set -eu
src=${DNS_TEST_SERVICE:-files/S99d2k}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
for fn in xt_wait svc_log engine_evidence stop_report; do
    sed -n "/^${fn}()/,/^}/p" "$src" >> "$tmp/functions"
done
. "$tmp/functions"
LOG=$tmp; SERVICE_LOG=$LOG/service.log; PROC_DIR=$tmp/proc
DP_PID=$tmp/dp; CT_PID=$tmp/ct
PF_CONN_BIT=0x08000000; ENGINE_ACTION=reapply; FW_DIAG=1
mkdir -p "$PROC_DIR" "$tmp/bin"
printf '42\n' > "$DP_PID"
printf '43\n' > "$CT_PID"
printf 'MemAvailable: 2048 kB\n' > "$PROC_DIR/meminfo"
say() { :; }
cat > "$tmp/bin/iptables" <<'SH'
#!/bin/sh
case "$*" in
    *" -S D2K_OUT") echo "-A D2K_OUT -p tcp -m connmark --mark 0x8000000/0x8000000 -j NFQUEUE --queue-num 2000"; exit 0 ;;
esac
exit 4
SH
chmod +x "$tmp/bin/iptables"
PATH=$tmp/bin:$PATH
if xt_wait iptables -t mangle -C D2K_OUT -j RETURN; then exit 1; else rc=$?; fi
[ "$rc" = 4 ]
grep -q 'iptables.*rc=4.*-C D2K_OUT' "$SERVICE_LOG"
if xt_wait iptables -t mangle -C D2K_OUT -m connmark --mark "$PF_CONN_BIT/$PF_CONN_BIT" -j NFQUEUE --queue-num 2000; then exit 1; fi
grep -q 'preflight-list D2K_OUT list_rc=0 marked_queue_rules=1' "$SERVICE_LOG"
dmesg() { printf '%s\n' 'Killed process 777 (unrelated)' 'Killed process 42 (d2kd)' ; }
engine_evidence missing
grep -q 'action=reapply.*dp_pid=42.*ct_pid=43' "$SERVICE_LOG"
grep -q 'Killed process 42 (d2kd)' "$SERVICE_LOG"
if grep -q unrelated "$SERVICE_LOG"; then exit 1; fi
grep -q 'MemAvailable: 2048 kB' "$SERVICE_LOG"
printf '%s\n' 'sensitive.example' 'd2kc: engine-exit time=123 pid=43 signal=15 sender_pid=17 link_lost=0 protocol_mismatch=0' > "$LOG/d2kc.log"
stop_report > "$tmp/report"
grep -q 'sender_pid=17' "$tmp/report"
grep -q 'engine-event=missing' "$tmp/report"
if grep -q 'sensitive.example' "$tmp/report"; then exit 1; fi
