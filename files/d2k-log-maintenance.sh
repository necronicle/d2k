#!/bin/sh
# Bound only D2K-owned logs. Copy the retained tail back into the open inode.
# Defaults (2 MiB, keep 1 MiB per log) suit Entware on a router's internal
# flash; a developer raises LOGMAX/LOGKEEP in config.
# This process belongs to the whole service, independently of engine-stop.
DIR=${D2K_DIR:-/opt/d2k}
CONF=$DIR/config
# shellcheck disable=SC1090
[ ! -r "$CONF" ] || . "$CONF"
RUNTIME_DIR=${D2K_RUNTIME_DIR:-/tmp/d2k}
LOG=$DIR/log

valid_bytes() {
    case "$1" in ''|*[!0-9]*) return 1 ;; esac
    [ "${#1}" -le 8 ] && [ "$1" -ge 1024 ] && [ "$1" -le 67108864 ]
}

if ! valid_bytes "${LOGMAX:-2097152}" ||
   ! valid_bytes "${LOGKEEP:-1048576}" ||
   [ "${LOGKEEP:-1048576}" -ge "${LOGMAX:-2097152}" ]; then
    echo 'd2k: invalid LOGMAX/LOGKEEP; using 2 MiB / 1 MiB' >&2
    LOGMAX=2097152
    LOGKEEP=1048576
else
    LOGMAX=${LOGMAX:-2097152}
    LOGKEEP=${LOGKEEP:-1048576}
fi
# Avoid octal interpretation of configured numbers in shell arithmetic.
while [ "${LOGMAX#0}" != "$LOGMAX" ]; do LOGMAX=${LOGMAX#0}; done
while [ "${LOGKEEP#0}" != "$LOGKEEP" ]; do LOGKEEP=${LOGKEEP#0}; done
LOG_EVERY=${LOG_EVERY:-60}
case "$LOG_EVERY" in ''|*[!0-9]*) LOG_EVERY=60 ;; esac
if [ "${#LOG_EVERY}" -gt 4 ] || [ "$LOG_EVERY" -lt 1 ] || [ "$LOG_EVERY" -gt 3600 ]; then
    LOG_EVERY=60
fi

prepare_runtime() {
    [ ! -L "$RUNTIME_DIR" ] || return 1
    (umask 077; mkdir -p "$RUNTIME_DIR") && chmod 0700 "$RUNTIME_DIR"
}

file_size() {
    # BusyBox/GNU and BSD/macOS stat. The fallback reads at most LOGMAX+1
    # bytes from the tail, even on a device without a compatible stat.
    size=$(stat -c %s "$1" 2>/dev/null) || size=$(stat -f %z "$1" 2>/dev/null) || size=
    case "$size" in
        ''|*[!0-9]*)
            tail -c "$((LOGMAX + 1))" "$1" 2>/dev/null | wc -c
            ;;
        *) printf '%s\n' "$size" ;;
    esac
}

rotate_one() {
    [ -f "$1" ] && [ ! -L "$1" ] || return 0
    size=$(file_size "$1") || return 0
    [ "$size" -gt "$LOGMAX" ] 2>/dev/null || return 0
    stage=$(mktemp "$RUNTIME_DIR/log-tail.XXXXXX") || return 0
    if tail -c "$LOGKEEP" "$1" > "$stage" 2>/dev/null &&
       [ "$(file_size "$stage")" -eq "$LOGKEEP" ] 2>/dev/null; then
        # Renaming would strand writers that already hold the append fd.
        cat "$stage" > "$1"
    fi
    rm -f "$stage"
    stage=
}

tick() {
    prepare_runtime || return 1
    # Enumerate exact owned names: never rotate unrelated or custom logs.
    for name in service.log d2kd.log d2kc.log panel.log telegram.log d2khttp.log \
                instagram-dns.log instagram-dns-scheduler.log update.log shadow.log shadow-daemon.log; do
        rotate_one "$LOG/$name"
    done
}

stop_worker() {
    if [ -n "$sleep_pid" ]; then
        kill "$sleep_pid" 2>/dev/null || true
        wait "$sleep_pid" 2>/dev/null || true
    fi
    [ -z "$stage" ] || rm -f "$stage"
    exit 0
}

case "${1:-}" in
    tick) tick ;;
    run)
        stage=
        sleep_pid=
        trap stop_worker HUP INT TERM
        while :; do
            tick
            sleep "$LOG_EVERY" &
            sleep_pid=$!
            wait "$sleep_pid"
            sleep_pid=
        done
        ;;
    *) echo "usage: $0 {tick|run}" >&2; exit 2 ;;
esac
