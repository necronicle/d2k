#!/bin/sh
# D2K-owned TCP-only Telegram redirect and IPv6 fast-fail rules.
set -eu

SET4=d2k_tg_dc
SET6=d2k_tg_dc6
PORT=1443
CIDRS4="149.154.160.0/20 91.108.4.0/22 91.108.8.0/22 91.108.12.0/22 91.108.16.0/22 91.108.20.0/22 91.108.56.0/22 91.105.192.0/23 95.161.64.0/20 185.76.151.0/24"
CIDRS6="2001:67c:4e8::/48 2001:b28:f23c::/47 2001:b28:f23f::/48 2a0a:f280:203::/48"

ipt() { iptables -w "$@" 2>/dev/null || iptables "$@" 2>/dev/null; }
ip6t() { ip6tables -w "$@" 2>/dev/null || ip6tables "$@" 2>/dev/null; }

# OpenWrt (25.12 без iptables вовсе): своя таблица nft, тот же выбор, что у
# S99d2k — он экспортирует D2K_FW; удаление зовёт без него, тогда по системе.
FW=${D2K_FW:-}
if [ -z "$FW" ]; then
    if [ -f "${D2K_OPENWRT_RELEASE:-/etc/openwrt_release}" ] && command -v nft >/dev/null 2>&1; then
        FW=nft
    else
        FW=iptables
    fi
fi
NFT_TABLE=d2k_tg

nft_list() { printf '%s' "$1" | sed 's/ /, /g'; }

# Перехват (LAN — prerouting, сам роутер — output) раньше dstnat fw4; IPv6 —
# быстрый отказ, как REJECT tcp-reset выше. Таблица целиком, одной транзакцией.
nft_ruleset() {
    cat <<EOF2
table inet $NFT_TABLE {
	set tg4 { type ipv4_addr; flags interval; elements = { $(nft_list "$CIDRS4") }; }
	set tg6 { type ipv6_addr; flags interval; elements = { $(nft_list "$CIDRS6") }; }
	chain pre {
		type nat hook prerouting priority dstnat - 1; policy accept;
		ip daddr @tg4 tcp dport 443 redirect to :$PORT
	}
	chain out {
		type nat hook output priority -101; policy accept;
		ip daddr @tg4 tcp dport 443 redirect to :$PORT
	}
	chain fwd6 {
		type filter hook forward priority filter - 1; policy accept;
		ip6 daddr @tg6 meta l4proto tcp reject with tcp reset
	}
	chain out6 {
		type filter hook output priority filter - 1; policy accept;
		ip6 daddr @tg6 meta l4proto tcp reject with tcp reset
	}
}
EOF2
}

nft_installed() {
    listed=$(nft list table inet "$NFT_TABLE" 2>/dev/null) || return 1
    [ "$(printf '%s\n' "$listed" | grep -c "redirect to :$PORT")" -eq 2 ] &&
        [ "$(printf '%s\n' "$listed" | grep -c 'reject with tcp reset')" -eq 2 ]
}

nft_up() {
    f=$(mktemp /tmp/d2k-tg-nft.XXXXXX) || return 1
    {
        ! nft list table inet "$NFT_TABLE" >/dev/null 2>&1 || echo "delete table inet $NFT_TABLE"
        nft_ruleset
    } > "$f" && nft -f "$f"
    rc=$?
    rm -f "$f"
    return "$rc"
}

ensure4() {
    command -v ipset >/dev/null 2>&1 || return 1
    ipset create "$SET4" hash:net -exist 2>/dev/null || return 1
    for c in $CIDRS4; do ipset add "$SET4" "$c" -exist 2>/dev/null || return 1; done
    for chain in PREROUTING OUTPUT; do
        ipt -t nat -C "$chain" -p tcp --dport 443 -m set --match-set "$SET4" dst -j REDIRECT --to-port "$PORT" ||
            ipt -t nat -I "$chain" 1 -p tcp --dport 443 -m set --match-set "$SET4" dst -j REDIRECT --to-port "$PORT" || return 1
        ipt -t nat -C "$chain" -p tcp --dport 443 -m set --match-set "$SET4" dst -j REDIRECT --to-port "$PORT" || return 1
    done
}

ensure6() {
    command -v ip6tables >/dev/null 2>&1 || return 0
    ipset create "$SET6" hash:net family inet6 -exist 2>/dev/null || return 0
    for c in $CIDRS6; do ipset add "$SET6" "$c" -exist 2>/dev/null || return 0; done
    for chain in FORWARD OUTPUT; do
        ip6t -C "$chain" -p tcp -m set --match-set "$SET6" dst -j REJECT --reject-with tcp-reset ||
            ip6t -I "$chain" 1 -p tcp -m set --match-set "$SET6" dst -j REJECT --reject-with tcp-reset || continue
    done
    return 0
}

start() {
    if [ "$FW" = nft ]; then
        ipt_stop
        nft_up || return 1
    else
        ensure4 || return 1
        ensure6
    fi
    if command -v conntrack >/dev/null 2>&1; then
        for c in $CIDRS4; do conntrack -D -d "$c" >/dev/null 2>&1 || true; done
    fi
}

heal() {
    if [ "$FW" = nft ]; then
        nft_installed || nft_up
    else
        ensure4 && ensure6
    fi
}

# Снятие iptables-правил — и на Keenetic, и на OpenWrt как остаток установки
# времён Entware. Без iptables здесь нечего делать.
ipt_stop() {
    command -v iptables >/dev/null 2>&1 || return 0
    for chain in PREROUTING OUTPUT; do
        while ipt -t nat -C "$chain" -p tcp --dport 443 -m set --match-set "$SET4" dst -j REDIRECT --to-port "$PORT"; do
            ipt -t nat -D "$chain" -p tcp --dport 443 -m set --match-set "$SET4" dst -j REDIRECT --to-port "$PORT" || break
        done
    done
    if command -v ip6tables >/dev/null 2>&1; then
        for chain in FORWARD OUTPUT; do
            while ip6t -C "$chain" -p tcp -m set --match-set "$SET6" dst -j REJECT --reject-with tcp-reset; do
                ip6t -D "$chain" -p tcp -m set --match-set "$SET6" dst -j REJECT --reject-with tcp-reset || break
            done
        done
    fi
}

stop() {
    if [ "$FW" = nft ] && nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
        nft delete table inet "$NFT_TABLE" || return 1
    fi
    ipt_stop
}

case "${1:-}" in
    start) start ;;
    heal) heal ;;
    stop) stop ;;
    *) echo "usage: $0 {start|heal|stop}" >&2; exit 2 ;;
esac
