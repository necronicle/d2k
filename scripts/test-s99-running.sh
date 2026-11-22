#!/bin/sh
# running() в S99d2k: зомби — мёртвый процесс. Демоны, запущенные обновлятором,
# усыновляет его супервизор; пока он не собрал завершившегося потомка, тот
# висит зомби. Считать его живым значило ждать, добивать KILL и объявлять
# остановку сорванной (лаборатория 05.10.2026: перезапуск Telegram сторожем
# во время передачи работы обновлятору оставлял туннель лежать).
# С этапа 29 running() подтверждает и экземпляр процесса движка (pid_is_ours:
# имя в ядре + время старта, без отметки — исполняемый файл и сокет): номер из
# pid-файла мог достаться чужому или другому экземпляру после падения.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

fail() { echo "FAIL: $*" >&2; exit 1; }

# Только эти функции, в том виде, в каком они в S99d2k.
for fn in running pid_is_ours pid_start stop_pidfile; do
    awk -v f="$fn" '$0 ~ "^" f "\\(\\) \\{" {p = 1} p {print} p && /^\}/ {exit}' "$ROOT/files/S99d2k" > "$TMP/$fn.sh"
    [ -s "$TMP/$fn.sh" ] || fail "$fn() not found in S99d2k"
    # shellcheck disable=SC1090
    . "$TMP/$fn.sh"
done
PROC_DIR=$TMP/proc
RUN=$TMP/run
# shellcheck disable=SC2034  # читают функции S99d2k (pid_is_ours)
{
    DP_PID=$RUN/d2kd.pid; CT_PID=$RUN/d2kc.pid; HL_PID=$RUN/heal.pid
    DPBIN=/opt/sbin/d2kd; BIN=/opt/sbin/d2kc; HEAL=/opt/sbin/d2k-fw-heal.sh
    SOCK=$RUN/d2kd.sock
}
mkdir -p "$RUN"

# Обычные pid-файлы (не движка): живой, зомби, зомби с «) » в имени, нет процесса, нет файла.
mkdir -p "$PROC_DIR/101" "$PROC_DIR/102" "$PROC_DIR/103"
echo '101 (d2ktg) S 1 101 101 0 -1' > "$PROC_DIR/101/stat"
echo '102 (d2ktg) Z 1 102 102 0 -1' > "$PROC_DIR/102/stat"
echo '103 (a) b) Z 1 103 103 0 -1' > "$PROC_DIR/103/stat"
for n in 101 102 103 104; do echo "$n" > "$TMP/$n.pid"; done

running "$TMP/101.pid" || fail "sleeping process must be running"
if running "$TMP/102.pid"; then fail "zombie must not count as running"; fi
if running "$TMP/103.pid"; then fail "zombie with ') ' in its name must not count as running"; fi
if running "$TMP/104.pid"; then fail "absent process must not count as running"; fi
if running "$TMP/none.pid"; then fail "missing pidfile must not count as running"; fi
echo "S99 running(): zombies and absent processes are not running: PASS"

# Процесс движка (d2kd): <pid> <comm> <состояние> <время старта> — поле 22 stat.
proc() {
    mkdir -p "$PROC_DIR/$1"
    printf '%s\n' "$2" > "$PROC_DIR/$1/comm"
    echo "$1 ($2) $3 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 $4 0 0" > "$PROC_DIR/$1/stat"
}
dp() { echo "$1" > "$DP_PID"; if [ -n "${2:-}" ]; then echo "$2" > "$DP_PID.start"; else rm -f "$DP_PID.start"; fi; }

proc 201 d2kd S 777
dp 201 777
running "$DP_PID" || fail "live d2kd with matching start stamp must be running"
proc 202 sshd S 777
dp 202 777
if running "$DP_PID"; then fail "foreign process (sshd) with the recorded number must not count as d2kd"; fi
proc 203 d2kd S 999
dp 203 777
if running "$DP_PID"; then fail "stale pidfile: another d2kd instance (start 999, stamp 777) must not count"; fi
proc 204 d2kd Z 777
dp 204 777
if running "$DP_PID"; then fail "zombie d2kd must not count as running"; fi
dp 205 777
if running "$DP_PID"; then fail "stale pidfile of a dead d2kd must not count"; fi
echo "S99 running(): engine pid — live, foreign, stale instance, zombie, dead: PASS"

# Без отметки старта (поднят прежней версией службы): экземпляр подтверждают
# настоящий исполняемый файл и точный управляющий сокет этой службы.
proc 206 d2kd S 555
ln -s "$DPBIN" "$PROC_DIR/206/exe"
printf 'd2kd\000--control\000%s\000' "$SOCK" > "$PROC_DIR/206/cmdline"
dp 206
running "$DP_PID" || fail "unstamped d2kd with our exe and --control socket must be running"
proc 207 d2kd S 555
ln -s "$DPBIN" "$PROC_DIR/207/exe"
printf 'd2kd\000--control\000%s\000' "$TMP/other.sock" > "$PROC_DIR/207/cmdline"
dp 207
if running "$DP_PID"; then fail "unstamped d2kd of another service (foreign socket) must not count"; fi
proc 208 d2kd S 555
ln -s /usr/bin/d2kd "$PROC_DIR/208/exe"
printf 'd2kd\000--control\000%s\000' "$SOCK" > "$PROC_DIR/208/cmdline"
dp 208
if running "$DP_PID"; then fail "unstamped process with a foreign executable must not count"; fi
proc 209 d2kd S 555
ln -s "$DPBIN (deleted)" "$PROC_DIR/209/exe"
printf 'd2kd\000--control\000%s\000' "$SOCK" > "$PROC_DIR/209/cmdline"
dp 209
running "$DP_PID" || fail "unstamped d2kd whose binary was replaced by an update must be running"
echo "S99 running(): unstamped engine pid — exe + control socket identity: PASS"

# Actual stop loop, with signals/time intercepted: no host PID is signalled.
svc_log() { printf '%s\n' "$*" >> "$TMP/events"; }
# shellcheck disable=SC2034 # consumed by stop_pidfile
ENGINE_ACTION=engine-stop
kill() { printf '%s\n' "$*" >> "$TMP/signals"; }
sleep() {
    [ "${stop_whole:-0}" != 1 ] || [ "$1" != 0.1 ] || return 1
    stop_ticks=$((stop_ticks+1))
    if [ "$stop_release" -gt 0 ] && [ "$stop_ticks" -eq "$stop_release" ]; then
        proc 201 d2kd "$stop_state" "$stop_start"
    fi
}
stop_fixture() {
    : > "$TMP/signals"
    stop_ticks=0; stop_release=$1; stop_state=${2:-Z}; stop_start=${3:-777}
    proc 201 d2kd S 777
    dp 201 777
}
stop_fixture 65
stop_pidfile "$DP_PID"
[ "$stop_ticks" -eq 65 ] || fail "datapath must get time for 2.5s drain + 2s filter cleanup + 2s worker stop"
[ "$(cat "$TMP/signals")" = 201 ] || fail "completed datapath cleanup must not receive SIGKILL"
grep -q 'engine-signal=TERM action=engine-stop .*target_pid=201' "$TMP/events" || fail "planned TERM missing from diagnostics"
stop_fixture 0
stop_pidfile "$DP_PID"
[ "$stop_ticks" -eq 100 ] || fail "stuck datapath stop must remain bounded at 10s"
grep -q '^-9 201$' "$TMP/signals" || fail "stuck datapath must receive SIGKILL after its grace"
stop_fixture 0
proc 202 d2kc S 777
echo 202 > "$CT_PID"; echo 777 > "$CT_PID.start"
stop_pidfile "$CT_PID"
[ "$stop_ticks" -eq 30 ] || fail "controller stop grace must remain 3s"
grep -q '^-9 202$' "$TMP/signals" || fail "stuck controller must receive SIGKILL"
stop_fixture 0
stop_whole=1
stop_pidfile "$DP_PID"
[ "$stop_ticks" -eq 10 ] || fail "integer-only sleep must not turn datapath grace into 100 seconds"
stop_whole=0
stop_fixture 5 S 999
stop_pidfile "$DP_PID"
[ "$stop_ticks" -eq 5 ] || fail "PID reuse must end waiting for old incarnation"
[ "$(cat "$TMP/signals")" = 201 ] || fail "replacement process must never receive SIGKILL"
echo "S99 stop(): datapath cleanup grace, bounded waits and PID reuse: PASS"

# Shadow uses the same instance checks, with its own queue argument.
SH_PID=$RUN/shadow.pid; SHADOWBIN=/opt/sbin/d2kshadow; SHADOW_QUEUE=$TMP/runtime/shadow.queue
proc 210 d2kshadow S 777
echo 210 > "$SH_PID"; echo 777 > "$SH_PID.start"
running "$SH_PID" || fail "shadow stamp must identify our live instance"
proc 210 d2kshadow S 888
if running "$SH_PID"; then fail "reused shadow PID must not count as ours"; fi
rm "$SH_PID.start"
ln -s "$SHADOWBIN" "$PROC_DIR/210/exe"
printf 'd2kshadow\000--queue\000%s\000' "$SHADOW_QUEUE" > "$PROC_DIR/210/cmdline"
running "$SH_PID" || fail "unstamped shadow requires executable and exact queue"
printf 'd2kshadow\000--queue\000%s\000' "$TMP/foreign.queue" > "$PROC_DIR/210/cmdline"
if running "$SH_PID"; then fail "shadow using foreign queue must not count as ours"; fi
echo "S99 running(): shadow instance and queue ownership: PASS"

proc 210 d2kshadow S 777
echo 210 > "$SH_PID"; echo 777 > "$SH_PID.start"
stop_release=0; stop_ticks=0; : > "$TMP/signals"
stop_pidfile "$SH_PID"
[ "$stop_ticks" -eq 300 ] || fail "shadow arm cleanup grace must remain bounded at 30s"
grep -q '^-9 210$' "$TMP/signals" || fail "stuck shadow must be killed after grace"
echo "S99 stop(): bounded shadow cleanup grace: PASS"
