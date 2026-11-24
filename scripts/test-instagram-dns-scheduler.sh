#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
SCHEDULER=$ROOT/files/d2k-instagram-dns-scheduler.sh
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

fail() { echo "FAIL: $*" >&2; exit 1; }

mkdir -p "$TMP/bin" "$TMP/d2k/state" "$TMP/d2k/log"
cat > "$TMP/bin/date" <<'EOF'
#!/bin/sh
case "$1" in
    +%Y-%m-%d) printf '%s\n' "${FAKE_DAY:-2026-09-29}" ;;
    +%H%M) printf '%s\n' "${FAKE_HHMM:-0359}" ;;
    +%s) printf '%s\n' "${FAKE_EPOCH:-1790654340}" ;;
    *) exit 2 ;;
esac
EOF
# The helper fails on its first call, then succeeds (HELPER_FAIL_ALL=1: always fails).
cat > "$TMP/helper" <<'EOF'
#!/bin/sh
count=$(cat "$HELPER_CALLS" 2>/dev/null || echo 0)
count=$((count + 1))
printf '%s\n' "$count" > "$HELPER_CALLS"
[ "${HELPER_FAIL_ALL:-0}" != 1 ] || exit 1
[ "$count" -gt 1 ]
EOF
chmod +x "$TMP/bin/date" "$TMP/helper"
run_tick() {
    env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$TMP/d2k" \
        D2K_INSTAGRAM_HELPER="$TMP/helper" \
        D2K_INSTAGRAM_SCHED_STATE="$TMP/d2k/state/success" \
        D2K_INSTAGRAM_SCHED_ATTEMPT="$TMP/attempt" \
        D2K_INSTAGRAM_SCHED_OFFSET="$TMP/d2k/state/offset" \
        D2K_INSTAGRAM_SCHED_LOG="$TMP/scheduler.log" HELPER_CALLS="$TMP/calls" \
        D2K_SCHEDULER_RETRY_AFTER=1800 "${TEST_SH:-sh}" "$SCHEDULER" tick
}
calls() { cat "$TMP/calls" 2>/dev/null || echo 0; }

# A previous day's success: wait for the install's slot (offset 60 → 02:00).
printf 'v2 60\n' > "$TMP/d2k/state/offset"
printf '2026-09-28\n1790560000\n' > "$TMP/d2k/state/success"
FAKE_HHMM=0159 run_tick
[ "$(calls)" = 0 ] || fail 'ran before the slot'
FAKE_HHMM=0200 run_tick
[ "$(calls)" = 1 ] || fail 'did not run at the slot'
FAKE_HHMM=0210 FAKE_EPOCH=1790654940 run_tick
[ "$(calls)" = 1 ] || fail 'retried before backoff expired'
FAKE_HHMM=0231 FAKE_EPOCH=1790656200 run_tick
[ "$(calls)" = 2 ] || fail 'did not retry after resolver failure'
[ "$(head -n 1 "$TMP/d2k/state/success")" = 2026-09-29 ] || fail 'successful date not persisted'
[ "$(sed -n 2p "$TMP/d2k/state/success")" = 1790656200 ] || fail 'success time not persisted'
[ "$(awk '{print $3}' "$TMP/attempt")" = 0 ] || fail 'success did not reset the failure count'
FAKE_HHMM=0500 FAKE_EPOCH=1790657940 run_tick
[ "$(calls)" = 2 ] || fail 'refreshed more than once after success'
# A success mark in the old one-line format is still read.
printf '2026-09-29\n' > "$TMP/d2k/state/success"
FAKE_HHMM=0600 FAKE_EPOCH=1790670000 run_tick
[ "$(calls)" = 2 ] || fail 'old one-line success mark not honoured'
echo 'PASS: daily slot, retry after backoff, one success per day'

# No recorded success (fresh install, or an old mark cleared by the installer):
# refresh in the background right away, whatever the hour.
rm -f "$TMP/d2k/state/success" "$TMP/attempt" "$TMP/calls"
FAKE_DAY=2026-09-30 FAKE_HHMM=0000 FAKE_EPOCH=1790730000 run_tick
[ "$(calls)" = 1 ] || fail 'first refresh waited for the slot'
FAKE_DAY=2026-09-30 FAKE_HHMM=0010 FAKE_EPOCH=1790730600 run_tick
[ "$(calls)" = 1 ] || fail 'first-refresh retry ignored the backoff'
FAKE_DAY=2026-09-30 FAKE_HHMM=0031 FAKE_EPOCH=1790731860 run_tick
[ "$(calls)" = 2 ] || fail 'failed first refresh was not retried'
[ "$(head -n 1 "$TMP/d2k/state/success")" = 2026-09-30 ] || fail 'first refresh success not persisted'
echo 'PASS: first refresh runs at once and backs off on failure'

# Routers spread over 01:00-04:59 by a stable per-install offset of 0-239
# minutes, so the fleet does not hit the shared /resolve limit together.
rm -f "$TMP/calls" "$TMP/attempt"; printf 'v2 157\n' > "$TMP/d2k/state/offset"
printf '2026-09-30\n1790731860\n' > "$TMP/d2k/state/success"
FAKE_DAY=2026-10-01 FAKE_HHMM=0336 FAKE_EPOCH=1790820000 run_tick
[ "$(calls)" = 0 ] || fail 'ran before 01:00 plus the install offset'
FAKE_DAY=2026-10-01 FAKE_HHMM=0337 FAKE_EPOCH=1790820060 run_tick
[ "$(calls)" = 1 ] || fail 'did not run at 01:00 plus the install offset (03:37)'
rm -f "$TMP/calls" "$TMP/attempt"; printf 'v2 239\n' > "$TMP/d2k/state/offset"
FAKE_DAY=2026-10-02 FAKE_HHMM=0458 FAKE_EPOCH=1790906000 run_tick
FAKE_DAY=2026-10-02 FAKE_HHMM=0459 FAKE_EPOCH=1790906060 run_tick
[ "$(calls)" = 1 ] || fail 'offset 239 is not 04:59'
# Without a stored offset one is drawn once (0-239) and kept.
rm -f "$TMP/d2k/state/offset" "$TMP/attempt"
FAKE_DAY=2026-10-02 FAKE_HHMM=0000 FAKE_EPOCH=1790900000 run_tick
first=$(cat "$TMP/d2k/state/offset" 2>/dev/null || true)
case "$first" in 'v2 '[0-9]*) ;; *) fail "no stored refresh offset ($first)";; esac
[ "${first#v2 }" -le 239 ] || fail "refresh offset out of range: $first"
FAKE_DAY=2026-10-02 FAKE_HHMM=0001 FAKE_EPOCH=1790900060 run_tick
[ "$(cat "$TMP/d2k/state/offset")" = "$first" ] || fail 'refresh offset is not stable'
printf 'junk\n' > "$TMP/d2k/state/offset"
FAKE_DAY=2026-10-02 FAKE_HHMM=0002 FAKE_EPOCH=1790900120 run_tick
case "$(cat "$TMP/d2k/state/offset")" in 'v2 '[0-9]*) ;; *) fail 'invalid offset was not replaced';; esac
# An offset from the old 02:00-02:59 window (0-59) migrates once into the new
# window, keeping the install's relative position: N → 4N..4N+3.
printf '37\n' > "$TMP/d2k/state/offset"
FAKE_DAY=2026-10-02 FAKE_HHMM=0003 FAKE_EPOCH=1790900180 run_tick
migrated=$(cat "$TMP/d2k/state/offset")
case "$migrated" in 'v2 148'|'v2 149'|'v2 150'|'v2 151') ;; *) fail "old offset 37 migrated to $migrated";; esac
FAKE_DAY=2026-10-02 FAKE_HHMM=0004 FAKE_EPOCH=1790900240 run_tick
[ "$(cat "$TMP/d2k/state/offset")" = "$migrated" ] || fail 'migrated offset is not stable'
printf '08\n' > "$TMP/d2k/state/offset"
FAKE_DAY=2026-10-02 FAKE_HHMM=0005 FAKE_EPOCH=1790900300 run_tick
case "$(cat "$TMP/d2k/state/offset")" in 'v2 32'|'v2 33'|'v2 34'|'v2 35') ;; *) fail 'old offset 08 was not read as 8 minutes';; esac
grep -q 'D2K_INSTAGRAM_REFRESH_AT' "$SCHEDULER" || fail 'explicit refresh time override is gone'
echo 'PASS: 01:00-04:59 spread, stable offset, old offsets migrate'

# A router whose refresh keeps failing backs off 30 min, 1 h, 2 h, … and at
# most until the next day's slot: a handful of calls on the first day, then
# one per day — not one every 30 minutes.
rm -f "$TMP/calls" "$TMP/attempt"; printf 'v2 0\n' > "$TMP/d2k/state/offset"
printf '2026-10-04\n1791060000\n' > "$TMP/d2k/state/success"
base=1791100800   # day 1, 00:00 in this fake clock
minute=0
day1=0
while [ "$minute" -lt 2880 ]; do
    d=$((minute / 1440)); m=$((minute % 1440))
    hhmm=$(printf '%02d%02d' $((m / 60)) $((m % 60)))
    HELPER_FAIL_ALL=1 FAKE_DAY="2026-10-0$((5 + d))" FAKE_HHMM="$hhmm" \
        FAKE_EPOCH=$((base + minute * 60)) run_tick
    [ "$minute" != 1430 ] || day1=$(calls)
    minute=$((minute + 10))
done
{ [ "$day1" -ge 2 ] && [ "$day1" -le 7 ]; } || fail "first failing day made $day1 calls (expected a few, backing off)"
day2=$(( $(calls) - day1 ))
[ "$day2" = 1 ] || fail "second failing day made $day2 calls (expected only the daily slot)"
grep -q 'следующая попытка через' "$TMP/scheduler.log" || fail 'backoff is not logged'
# One success clears the failure count.
HELPER_FAIL_ALL=0 FAKE_DAY=2026-10-07 FAKE_HHMM=0100 FAKE_EPOCH=$((base + 2880 * 60 + 3600)) run_tick
[ "$(awk '{print $3}' "$TMP/attempt")" = 0 ] || fail 'success after failures did not reset the backoff'
echo "PASS: persistent failure backs off ($day1 calls on day 1, $day2 on day 2)"

# Управляемая остановка даёт писателю состояния ограниченное время на TERM и
# считает принудительный SIGKILL отказом транзакции (files/S99d2k stop_pidfile).
# Планировщик, спящий между тиками, обязан выйти сразу, а не через RUN_EVERY:
# shell откладывает trap, пока ждёт foreground-команду.
rm -f "$TMP/calls" "$TMP/attempt"; printf 'v2 0\n' > "$TMP/d2k/state/offset"
printf '2026-10-07\n1791300000\n' > "$TMP/d2k/state/success"
env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$TMP/d2k" FAKE_DAY=2026-10-07 FAKE_HHMM=1200 \
    D2K_INSTAGRAM_HELPER="$TMP/helper" D2K_INSTAGRAM_SCHED_STATE="$TMP/d2k/state/success" \
    D2K_INSTAGRAM_SCHED_ATTEMPT="$TMP/attempt" D2K_INSTAGRAM_SCHED_OFFSET="$TMP/d2k/state/offset" \
    D2K_INSTAGRAM_SCHED_LOG="$TMP/scheduler.log" HELPER_CALLS="$TMP/calls" \
    D2K_SCHEDULER_INTERVAL=20 "${TEST_SH:-sh}" "$SCHEDULER" run &
sched=$!
sleep 1
kill -0 "$sched" 2>/dev/null || fail 'scheduler loop exited on its own'
kill -TERM "$sched"
i=0
while kill -0 "$sched" 2>/dev/null && [ "$i" -lt 20 ]; do i=$((i + 1)); sleep 0.1; done
if kill -0 "$sched" 2>/dev/null; then
    kill -KILL "$sched" 2>/dev/null || true
    fail 'sleeping scheduler ignored TERM for 2 s: a managed stop would have to SIGKILL it'
fi
wait "$sched" 2>/dev/null || fail 'scheduler did not exit cleanly on TERM'
[ "$(calls)" = 0 ] || fail 'idle scheduler ran the helper'
echo 'PASS: sleeping scheduler stops promptly on TERM'

# Entware's od applet rejects -A/-N/-t, whereas its hexdump reads random bytes.
cat > "$TMP/bin/od" <<'EOF'
#!/bin/sh
exit 1
EOF
cat > "$TMP/bin/hexdump" <<'EOF'
#!/bin/sh
printf '479'
EOF
cat > "$TMP/bin/awk" <<'EOF'
#!/bin/sh
printf '42\n'
EOF
chmod +x "$TMP/bin/od" "$TMP/bin/hexdump" "$TMP/bin/awk"
printf 'invalid\n' > "$TMP/d2k/state/offset"
FAKE_DAY=2026-10-07 FAKE_HHMM=0000 run_tick
[ "$(cat "$TMP/d2k/state/offset")" = 'v2 239' ] ||
    fail 'the scheduler fell back to the process ID on Entware'

echo 'Instagram DNS scheduler: all checks passed'
