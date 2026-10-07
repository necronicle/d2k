#!/bin/sh
# Удаление d2k с Keenetic.
#
# Убирает ТОЛЬКО своё: свои файлы, свою цепочку firewall, свои процессы.
# Чужого не трогает даже там, где похоже — правило соседа, снятое «на всякий
# случай», ломает соседа молча.
#
# Полное удаление, включая конфигурацию и каталог коробок, — поведение по
# умолчанию. Чтобы оставить изученное состояние, задайте D2K_KEEP_STATE=1.
set -eu

DIR=${D2K_DIR:-/opt/d2k}
PREFIX=${DIR%/*}
SBIN=$PREFIX/sbin
INIT=$PREFIX/etc/init.d/S99d2k
KEEP=${D2K_KEEP_STATE:-0}

say() { echo "d2k: $*"; }

# Cancel the host waiter before stopping any D2K process, so a late /opt mount
# cannot race uninstall. detach only cancels the waiter.
OPENWRT_INIT=/etc/init.d/d2k
if [ ! -L "$OPENWRT_INIT" ] && [ -f "$OPENWRT_INIT" ] &&
   grep -qx '# D2K-owned OpenWrt boot bridge v1' "$OPENWRT_INIT"; then
    sh /etc/rc.common "$OPENWRT_INIT" disable || exit 1
    sh /etc/rc.common "$OPENWRT_INIT" detach || exit 1
    rm -f "$OPENWRT_INIT"
fi

# Remove only exact DNS pairs recorded by this installation. If NDM cannot
# confirm cleanup, stop before deleting the helper/manifest so the owner can
# retry rather than leaving unexplained static routes behind.
# A background refresh (scheduled, or the first one after install) must not
# add pins while they are being removed: stop the owned scheduler first; its
# trap stops the running refresh. Pairs are claimed before they are added.
DNS_SCHED_PID=$DIR/run/d2k-instagram-dns-scheduler.pid
if [ -f "$DNS_SCHED_PID" ]; then
    start-stop-daemon -K -q -p "$DNS_SCHED_PID" 2>/dev/null || true
    n=0
    # Up to the resolver curl --max-time (15 s) plus one certificate check.
    while [ "$n" -lt 30 ] && pid=$(cat "$DNS_SCHED_PID" 2>/dev/null) &&
          [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; do
        sleep 1
        n=$((n + 1))
    done
fi
if [ -x "$DIR/d2k-instagram-dns.sh" ]; then
    say "снимаю свои DNS-записи Instagram/WhatsApp"
    "$DIR/d2k-instagram-dns.sh" remove || {
        say "не удалось снять D2K DNS-записи Instagram/WhatsApp; удаление остановлено, повторите позже"
        exit 1
    }
fi

if [ -x "$INIT" ]; then
    say "останавливаю"
    if [ "${D2K_MANAGED_INTERNAL:-}" = 1 ]; then "$INIT" --managed stop 0 || exit 1; else "$INIT" stop; fi || say "остановка вернула ошибку — продолжаю удаление"
fi

# Defense in depth when init has already been removed: stop only the owned
# Telegram PID and remove only the two D2K-owned redirect rule sets.
if [ -f "$DIR/run/d2ktg.pid" ]; then
    start-stop-daemon -K -q -p "$DIR/run/d2ktg.pid" 2>/dev/null || true
fi
if [ -f "$DIR/run/d2k-http.pid" ]; then
    start-stop-daemon -K -q -p "$DIR/run/d2k-http.pid" 2>/dev/null || true
fi
if [ -f "$DIR/run/d2k-log-maintenance.pid" ]; then
    start-stop-daemon -K -q -p "$DIR/run/d2k-log-maintenance.pid" 2>/dev/null || true
fi
if [ -f "$DIR/run/d2k-update.pid" ]; then
    start-stop-daemon -K -q -p "$DIR/run/d2k-update.pid" 2>/dev/null || true
fi
[ ! -x "$DIR/d2k-tg-firewall.sh" ] || "$DIR/d2k-tg-firewall.sh" stop >/dev/null 2>&1 || true

# Ускоритель NAT: init выключал его на время работы и запомнил прежнее
# значение в run/fastnat.saved. Без init вернуть его некому, кроме нас, и
# сделать это надо до удаления run/.
FASTNAT=/proc/sys/net/netfilter/nf_conntrack_fastnat
if [ -f "$DIR/run/fastnat.saved" ] && [ -w "$FASTNAT" ]; then
    saved=$(cat "$DIR/run/fastnat.saved" 2>/dev/null || true)
    case "$saved" in
        ''|*[!0-9]*) ;;
        *) echo "$saved" > "$FASTNAT" 2>/dev/null || say "не удалось вернуть прежний nf_conntrack_fastnat=$saved" ;;
    esac
fi

# Ускорение потоков fw4 (OpenWrt): init выключал его на время работы и
# запомнил в run/flow-offloading.saved. Без init вернуть его некому, кроме нас.
if [ -f "$DIR/run/flow-offloading.saved" ] && command -v uci >/dev/null 2>&1; then
    if [ "$(cat "$DIR/run/flow-offloading.saved" 2>/dev/null)" = 1 ] &&
       uci set firewall.@defaults[0].flow_offloading=1 && uci commit firewall; then
        fw4 reload >/dev/null 2>&1 || /etc/init.d/firewall reload >/dev/null 2>&1 ||
            say "flow offloading возвращён в настройку; перезапустите firewall"
    else
        say "не удалось вернуть flow offloading fw4 — включите его в настройках firewall"
    fi
fi

# Правила подавления RST (filter OUTPUT, «-m comment --comment d2k-rst:PID»)
# ставят d2kc и d2k-detect на время зонда; убитый процесс оставляет их висеть.
# Снимаются только правила этой точной формы с портом зонда и владельцем —
# мёртвым или процессом d2k; правило чужого процесса и чужие правила остаются.
for fw_tool in iptables ip6tables; do
    command -v "$fw_tool" >/dev/null 2>&1 || continue
    rst_rules=$("$fw_tool" -w -S OUTPUT 2>/dev/null || "$fw_tool" -S OUTPUT 2>/dev/null || true)
    printf '%s\n' "$rst_rules" | sed -n \
        's/^-A OUTPUT -p tcp \(-m tcp \)\{0,1\}--sport \([0-9][0-9]*\) --tcp-flags RST RST -m comment --comment "\{0,1\}d2k-rst:\([1-9][0-9]*\)"\{0,1\} -j DROP *$/\2 \3/p' |
    while read -r port owner; do
        { [ "$port" -ge 30000 ] && [ "$port" -le 54999 ]; } || continue
        if kill -0 "$owner" 2>/dev/null; then
            case "$(cat "/proc/$owner/comm" 2>/dev/null)" in d2k*) ;; *) continue ;; esac
        fi
        "$fw_tool" -w -D OUTPUT -p tcp --sport "$port" --tcp-flags RST RST \
            -m comment --comment "d2k-rst:$owner" -j DROP 2>/dev/null ||
        "$fw_tool" -D OUTPUT -p tcp --sport "$port" --tcp-flags RST RST \
            -m comment --comment "d2k-rst:$owner" -j DROP 2>/dev/null || true
    done
done

# Своё правило MASQUERADE для UDP-посылок датапата (init ставит его по метке
# MARK). Метка читается из конфигурации без исполнения её текста.
own_mark=0x2d
if [ -r "$DIR/config" ]; then
    cfg_mark=$(sed -n 's/^[[:space:]]*MARK=//p' "$DIR/config" | tail -n 1 | tr -d "\"'")
    case "$cfg_mark" in
        0x[0-9a-fA-F]*) case "${cfg_mark#0x}" in *[!0-9a-fA-F]*) ;; *) own_mark=$cfg_mark ;; esac ;;
        [1-9]*) case "$cfg_mark" in *[!0-9]*) ;; *) own_mark=$cfg_mark ;; esac ;;
    esac
fi
while iptables -t nat -D POSTROUTING -p udp -m mark --mark "$own_mark" -j MASQUERADE 2>/dev/null; do :; done
if command -v ipset >/dev/null 2>&1; then
    ipset destroy d2k_tg_dc 2>/dev/null || true
    ipset destroy d2k_tg_dc6 2>/dev/null || true
fi

# Разгрузка ускорителя (-j PPE с меткой d2k-ppe) живёт в общих цепочках
# mangle, а не в своей, и снимается по метке: чужие -j PPE (z2k, NDM)
# остаются. Даже без init-скрипта — init мог быть удалён руками.
if [ -r "$DIR/d2k-ppe-deoffload.sh" ]; then
    # shellcheck disable=SC1091
    . "$DIR/d2k-ppe-deoffload.sh"
    d2k_ppe_remove || true
fi

# Цепочка снимается даже если init-скрипта уже нет: он мог быть удалён руками,
# а правила остаться.
# Старое имя D2K тоже снимается: установка прошлой версии могла оставить его.
for fw_tool in iptables ip6tables; do
while "$fw_tool" -t nat -D PREROUTING -j D2K_HTTP 2>/dev/null; do :; done
if "$fw_tool" -t nat -n -L D2K_HTTP >/dev/null 2>&1; then
    "$fw_tool" -t nat -F D2K_HTTP 2>/dev/null || true
    "$fw_tool" -t nat -X D2K_HTTP 2>/dev/null || true
fi
while "$fw_tool" -t mangle -D OUTPUT -j D2K_HTTP_MARK 2>/dev/null; do :; done
if "$fw_tool" -t mangle -n -L D2K_HTTP_MARK >/dev/null 2>&1; then
    "$fw_tool" -t mangle -F D2K_HTTP_MARK 2>/dev/null || true
    "$fw_tool" -t mangle -X D2K_HTTP_MARK 2>/dev/null || true
fi
for hook in POSTROUTING FORWARD OUTPUT INPUT; do
    for ch in D2K_OUT D2K_IN D2K; do
        while "$fw_tool" -t mangle -D "$hook" -j "$ch" 2>/dev/null; do :; done
    done
done
for ch in D2K_OUT D2K_IN D2K; do
    if "$fw_tool" -t mangle -n -L "$ch" >/dev/null 2>&1; then
        "$fw_tool" -t mangle -F "$ch" 2>/dev/null || true
        "$fw_tool" -t mangle -X "$ch" 2>/dev/null || true
    fi
done
done
# OpenWrt на nftables: свои таблицы снимаются целиком — движок, подавление
# RST зондами, Telegram. Чужие (fw4) не трогаются.
if command -v nft >/dev/null 2>&1; then
    for t in d2k d2k_rst d2k_tg; do
        if nft list table inet "$t" >/dev/null 2>&1; then
            nft delete table inet "$t" || say "не снять таблицу nft inet $t"
        fi
    done
fi
say "правила сняты"

# Хук NDM снимается ПЕРВЫМ: оставленный, он будет звать сторожа, которого уже
# нет, на каждое изменение netfilter — мусор в журнале на ровном месте.
rm -f "$PREFIX/etc/ndm/netfilter.d/001-d2k.sh"
rm -f "$PREFIX/etc/init.d/S99d2k" "$PREFIX/etc/init.d/S98d2k-update" "$SBIN/d2k" "$SBIN/d2kpanel" "$SBIN/d2kc" "$SBIN/d2kd" "$SBIN/d2ktg" "$SBIN/d2khttp"
# Remove only d2kc snapshots explicitly named as D2K pre-install/work backups.
# These were created during router development and are not user configuration.
rm -f "$SBIN"/d2kc.before-d2k-* "$SBIN"/d2kc.pre-goal-* "$SBIN"/d2kc.pre-sched-*
rm -f "$DIR/d2k-ppe-deoffload.sh" "$DIR/d2k-fw-heal.sh"
rm -f "$DIR/d2k-tg-firewall.sh" "$DIR/d2k-tg-watchdog.sh" "$DIR/d2k-instagram-dns.sh" \
    "$DIR/d2k-instagram-dns-scheduler.sh" "$DIR/d2k-log-maintenance.sh" "$DIR/d2k-update.sh" \
    "$DIR/release-id" "$DIR/release-arch" \
    "$DIR/files/meta-ranges.txt" "$DIR/files/tg-roots.pem"
rm -rf "$DIR/run" "$DIR/log" "$DIR/panel" "$DIR/.update"
# Рабочий каталог обновления на OpenWrt без USB — в RAM (d2k-update.sh).
rm -rf /tmp/d2k-update
# Свои файлы в /tmp: отметки сторожа и планировщика, брошенные замки.
rm -f /tmp/d2k-fw-heal.last /tmp/d2k-instagram-dns-last-attempt
for lock in /tmp/d2k-fw-heal.lock /tmp/d2k-fw-operation.lock; do
    { [ -d "$lock" ] && [ ! -L "$lock" ]; } || continue
    rm -f "$lock/pid"
    rmdir "$lock" 2>/dev/null || true
done

cleanup_runtime() (
    runtime=$1
    # Only literal child paths in volatile runtime locations are eligible.
    # Never source configuration or evaluate shell substitutions for cleanup.
    case "$runtime" in
        /tmp/?*) base=/tmp; relative=${runtime#/tmp/} ;;
        /run/?*) base=/run; relative=${runtime#/run/} ;;
        /var/run/?*) base=/var/run; relative=${runtime#/var/run/} ;;
        *) return 0 ;;
    esac
    case "$runtime" in
        *[!A-Za-z0-9_./-]*|*//*|*/../*|*/./*|*/..|*/.|*/) return 0 ;;
    esac
    # Do not follow a user-created symlink in any component below the anchor.
    while [ -n "$relative" ]; do
        component=${relative%%/*}
        base=$base/$component
        [ ! -L "$base" ] || return 0
        case "$relative" in */*) relative=${relative#*/} ;; *) relative= ;; esac
    done
    [ -d "$runtime" ] || return 0
    rm -f "$runtime/live.json" "$runtime/d2kd.health" "$runtime/d2kc.health" \
        "$runtime/d2kpanel.health" "$runtime/d2ktg.health"
    # SIGKILL/power loss can leave an abandoned retained tail.
    for stage in "$runtime"/log-tail.??????; do
        [ -f "$stage" ] || [ -L "$stage" ] || continue
        rm -f "$stage"
    done
    rmdir "$runtime" 2>/dev/null || true
)

custom_runtime=${D2K_RUNTIME_DIR:-}
if [ -z "$custom_runtime" ] && [ -r "$DIR/config" ]; then
    custom_runtime=$(sed -n 's/^[[:space:]]*D2K_RUNTIME_DIR=//p' "$DIR/config" | tail -n 1)
    case "$custom_runtime" in
        \"*\") custom_runtime=${custom_runtime#\"}; custom_runtime=${custom_runtime%\"} ;;
        \'*\') custom_runtime=${custom_runtime#\'}; custom_runtime=${custom_runtime%\'} ;;
    esac
fi
cleanup_runtime /tmp/d2k
[ -z "$custom_runtime" ] || cleanup_runtime "$custom_runtime"

if [ "$KEEP" = "1" ]; then
    say "сохраняю конфигурацию и каталог изученных коробок в $DIR"
    say "чтобы удалить всё: D2K_KEEP_STATE=0 sh $0"
    rm -f "$DIR/config.new"
else
    rm -rf "$DIR"
    # OpenWrt без Entware: /opt создал D2K, пустые каталоги убираются.
    # Каталоги Entware (Keenetic, OpenWrt с Entware) не трогаются и пустыми.
    if [ -f /etc/openwrt_release ] && [ ! -e "$PREFIX/bin/opkg" ]; then
        for d in "$SBIN" "$PREFIX/etc/init.d" "$PREFIX/etc" "$PREFIX"; do
            rmdir "$d" 2>/dev/null || true
        done
    fi
    say "удалено всё, включая каталог коробок"
fi

left=$({ iptables -t mangle -S 2>/dev/null || true; ip6tables -t mangle -S 2>/dev/null || true; } | grep -c -- "-j D2K" || true)
say "готово. Ссылок на цепочки d2k осталось: $left"
