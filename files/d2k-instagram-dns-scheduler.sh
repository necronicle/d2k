#!/bin/sh
# Local-time daily Instagram/WhatsApp DNS refresh in the 01:00-04:59 router-time
# window: 01:00 plus a stable per-install offset of 0-239 minutes.
# Without any recorded success (fresh install, or the installer cleared an old
# mark) the first refresh runs right away, in the background of the service,
# so installation does not wait for slow edges.
# A failing refresh backs off: 30 min, 1 h, 2 h, … and never past the next
# day's slot, so a router that cannot refresh asks the VPS about once a day.
# Cron is intentionally not used: Keenetic Entware cron does not reliably
# reload its crontab.
set -u
export PATH="${D2K_STUB_PATH:+$D2K_STUB_PATH:}/opt/sbin:/opt/bin:/sbin:/usr/sbin:/bin:/usr/bin"

DIR=${D2K_DIR:-/opt/d2k}
HELPER=${D2K_INSTAGRAM_HELPER:-${D2K_RELEASE_ROOT:-$DIR}/d2k-instagram-dns.sh}
# First line: local date of the last success; second: its epoch time.
STATE=${D2K_INSTAGRAM_SCHED_STATE:-$DIR/state/instagram-dns-last-success}
# "epoch date failures" of the last attempt (volatile: a reboot starts afresh).
ATTEMPT=${D2K_INSTAGRAM_SCHED_ATTEMPT:-/tmp/d2k-instagram-dns-last-attempt}
LOG=${D2K_INSTAGRAM_SCHED_LOG:-$DIR/log/instagram-dns-scheduler.log}
RUN_EVERY=${D2K_SCHEDULER_INTERVAL:-60}
RETRY_AFTER=${D2K_SCHEDULER_RETRY_AFTER:-1800}
MAX_BACKOFF=86400
OFFSET_FILE=${D2K_INSTAGRAM_SCHED_OFFSET:-$DIR/state/instagram-dns-offset}
# Explicit HHMM wins; otherwise 01:00 plus a per-install offset of 0-239
# minutes, drawn once and kept, so routers do not all call /resolve at once.
RUN_AT=${D2K_INSTAGRAM_REFRESH_AT:-}
child_pid=

stop_scheduler() {
    if [ -n "$child_pid" ]; then
        kill "$child_pid" 2>/dev/null || true
        wait "$child_pid" 2>/dev/null || true
    fi
    exit 0
}
trap stop_scheduler INT TERM HUP

log() {
    mkdir -p "$(dirname "$LOG")" 2>/dev/null || true
    printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >> "$LOG"
}

random16() {
    r=$(hexdump -v -n 2 -e '1/2 "%u"' /dev/urandom 2>/dev/null)
    case "$r" in ''|*[!0-9]*) r=$(awk -v s="$$" 'BEGIN{srand(s); print int(rand()*65536)}');; esac
    printf '%s\n' "$r"
}

store_offset() {
    mkdir -p "$(dirname "$OFFSET_FILE")" 2>/dev/null || true
    tmp="$OFFSET_FILE.new.$$"
    if printf 'v2 %s\n' "$1" > "$tmp" && mv -f "$tmp" "$OFFSET_FILE"; then :; else rm -f "$tmp"; fi
}

# "v2 N" (N 0-239). A bare 0-59 is an offset from the old 02:00-02:59 window:
# it moves once to 4N..4N+3, keeping the install's relative place.
refresh_offset() {
    stored=$(cat "$OFFSET_FILE" 2>/dev/null || true)
    case "$stored" in
        'v2 '[0-9]|'v2 '[1-9][0-9]|'v2 1'[0-9][0-9]|'v2 2'[0-3][0-9])
            printf '%s\n' "${stored#v2 }"; return 0 ;;
        [0-9]|[1-5][0-9]|0[0-9])
            old=${stored#0}
            offset=$((old * 4 + $(random16) % 4))
            store_offset "$offset"
            log "окно обновления DNS перенесено: прежняя минута $old → 01:00 + $offset мин"
            printf '%s\n' "$offset"; return 0 ;;
    esac
    offset=$(( $(random16) % 240 ))
    store_offset "$offset"
    printf '%s\n' "$offset"
}

run_at() {
    if [ -n "$RUN_AT" ]; then printf '%s\n' "$RUN_AT"; return 0; fi
    offset=$(refresh_offset)
    printf '%02d%02d\n' $((1 + offset / 60)) $((offset % 60))
}

# Seconds to wait after the given number of consecutive failures.
backoff_after() {
    wait_s=0
    if [ "$1" -gt 0 ]; then
        wait_s=$RETRY_AFTER
        n=1
        while [ "$n" -lt "$1" ] && [ "$wait_s" -lt "$MAX_BACKOFF" ]; do
            wait_s=$((wait_s * 2)); n=$((n + 1))
        done
        [ "$wait_s" -le "$MAX_BACKOFF" ] || wait_s=$MAX_BACKOFF
    fi
    printf '%s\n' "$wait_s"
}

write_attempt() {
    mkdir -p "$(dirname "$ATTEMPT")" 2>/dev/null || true
    printf '%s %s %s\n' "$1" "$2" "$3" > "$ATTEMPT" 2>/dev/null || true
}

tick() {
    today=$(date +%Y-%m-%d)
    hhmm=$(date +%H%M)
    at=$(run_at)
    now=$(date +%s)
    last=0; last_day=; fails=0
    if [ -r "$ATTEMPT" ]; then read -r last last_day fails < "$ATTEMPT" || true; fi
    case "$last" in ''|*[!0-9]*) last=0;; esac
    case "$fails" in ''|*[!0-9]*) fails=0;; esac
    case "$now" in ''|*[!0-9]*) return 0;; esac
    [ "$last" -le "$now" ] || last=0

    if [ -e "$STATE" ]; then
        [ "$hhmm" -ge "$at" ] || return 0
        [ "$(head -n 1 "$STATE" 2>/dev/null || true)" != "$today" ] || return 0
        # Today's slot is always tried once; later retries wait out the backoff.
        if [ "$last_day" = "$today" ]; then
            [ $((now - last)) -ge "$(backoff_after "$fails")" ] || return 0
        fi
    else
        [ $((now - last)) -ge "$(backoff_after "$fails")" ] || return 0
    fi

    mkdir -p "$(dirname "$STATE")" 2>/dev/null || true
    # Counted as failed until the helper says otherwise (a kill mid-run too).
    write_attempt "$now" "$today" $((fails + 1))
    log "обновление DNS Instagram/WhatsApp: старт"
    "$HELPER" refresh &
    child_pid=$!
    if wait "$child_pid"; then
        child_pid=
        write_attempt "$now" "$today" 0
        tmp="$STATE.new.$$"
        if printf '%s\n%s\n' "$today" "$now" > "$tmp" && mv -f "$tmp" "$STATE"; then
            log "DNS Instagram/WhatsApp обновлён; следующий запуск после $at завтра"
        else
            rm -f "$tmp"
            log 'обновление успешно, но не удалось сохранить дату; повтор подождёт обычной паузы'
        fi
    else
        rc=$?
        child_pid=
        next=$(backoff_after $((fails + 1)))
        log "VPS не ответил или не прошёл проверку (код $rc, неудач подряд: $((fails + 1))); следующая попытка через ${next} с, но не позже завтрашнего окна $at; текущие записи сохранены"
    fi
}

case "${1:-run}" in
    tick) tick ;;
    run)
        while :; do
            tick
            # Пауза — фоновым sleep и wait: trap на TERM срабатывает сразу, а
            # не после foreground-команды. Иначе остановка службы ждёт до
            # RUN_EVERY и добивает SIGKILL.
            sleep "$RUN_EVERY" &
            child_pid=$!
            wait "$child_pid" || true
            child_pid=
        done
        ;;
    *) echo "usage: $0 {run|tick}" >&2; exit 2 ;;
esac
