#!/bin/sh
# Active transport probe for the TCP Telegram relay. HTTP error status is
# still a server response; only transport failures count toward restart.
set -u
PATH=/opt/sbin:/opt/bin:/opt/usr/sbin:/opt/usr/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

DIR=/opt/d2k
INIT=/opt/etc/init.d/S99d2k
STATE=$DIR/state/telegram-health.failures
PROBE_URL=https://core.telegram.org/
# Telegram's HTTPS endpoint, as in z2k. A native MTProto DC does not speak
# HTTPS and would trigger periodic restarts of a healthy tunnel.
PROBE_IP=149.154.167.99

log_health() {
    printf '%s d2k-tg-watchdog: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$DIR/log/telegram.log"
}

failures=0
unavailable_rc=
while :; do
    if [ -x "$DIR/d2k-tg-firewall.sh" ]; then "$DIR/d2k-tg-firewall.sh" heal >/dev/null 2>&1 || true; fi
    if code=$(curl --connect-timeout 8 --max-time 15 -s -o /dev/null -w '%{http_code}' \
        --resolve "core.telegram.org:443:$PROBE_IP" "$PROBE_URL" 2>/dev/null); then
        [ "$failures" -eq 0 ] || log_health "probe recovered: http=$code preceding_failures=$failures"
        failures=0
        unavailable_rc=
        rm -f "$STATE"
    else
        rc=$?
        case "$rc" in
            7|28|52|55|56)
                # Connection refused, timeout, empty reply or socket I/O failure.
                unavailable_rc=
                failures=$((failures + 1))
                log_health "probe failed: curl_rc=$rc http=$code consecutive=$failures"
                echo "$failures" > "$STATE"
                if [ "$failures" -ge 3 ]; then
                    log_health "restart requested: three consecutive transport failures"
                    if "$INIT" telegram-restart >/dev/null 2>&1; then
                        log_health "restart command completed"
                    else
                        log_health "restart command failed: rc=$?"
                    fi
                    failures=0
                    rm -f "$STATE"
                fi
                ;;
            *)
                # A local execution, configuration or certificate error cannot
                # establish that restarting the Telegram process will help.
                if [ "$unavailable_rc" != "$rc" ]; then
                    log_health "probe unavailable: curl_rc=$rc; tunnel left running"
                fi
                unavailable_rc=$rc
                failures=0
                rm -f "$STATE"
                ;;
        esac
    fi
    sleep 60
done
