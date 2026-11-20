#!/bin/sh
# d2k-ppe-deoffload.sh — окно рукопожатия мимо аппаратного ускорителя Keenetic.
#
# ЗАЧЕМ. На Keenetic (MediaTek PPE, fastnat) прошивка переводит транзитный
# поток в аппаратный путь мимо netfilter. d2k видит начало потока, но не
# ответы, повторы и сбросы: замер и подтверждение ломаются (полевое сообщение
# 02.10.2026). Выключить ускоритель целиком (`no ppe hardware`) надёжно, но
# меняет конфигурацию роутера и режет скорость всему трафику — это решает
# владелец, d2k только советует в статусе.
#
# ЧТО ДЕЛАЕТСЯ. Штатная цель прошивки `-j PPE` с `-m connskip --connskip N`
# держит на процессоре первые N пакетов КАЖДОГО подходящего соединения, дальше
# поток снова ускоряется. Так поступает сама NDM для своих правил, и так же
# z2k (files/z2k-ppe-deoffload.sh, проверено на KN-1811). Отличия от z2k:
#   * ПАРНЫЕ правила: исходящее по --dports в mangle PREROUTING и FORWARD,
#     ответное по --sports в mangle FORWARD. Правило только по --dports дало
#     видимость ответа 0,08 % (замер 05.09); в PREROUTING обратный NAT ещё не
#     отработал, поэтому ответ ловится в FORWARD;
#   * UDP — все порты: неизвестные приложения должны попадать в начальное
#     окно очереди так же, как QUIC и голос;
#   * каждое правило помечено комментарием d2k-ppe и снимается по метке:
#     чужие -j PPE (z2k, NDM) не трогаются, даже если порты совпали.
#
# ЧЕГО НЕ ОБЕЩАЕТ. `-j PPE`, вставленный на уже привязанный поток, его НЕ
# отвязывает (замер 02.10.2026): разгрузка работает только с первых пакетов.
# После N пакетов поток снова в ускорителе, и поздние RST/FIN (правила
# late_from в S99d2k) на таких роутерах не видны.
#
# Источник истины для правил — этот файл. S99d2k подключает его (`.`) и
# ставит разгрузку в fw_up, снимает в fw_down; сторож d2k-fw-heal.sh через
# `S99d2k ppe-ensure` возвращает снесённое; удаление (uninstall.sh) снимает
# по метке даже без S99d2k. Запуск напрямую: {ensure|remove|status [адрес]}.
#
# BusyBox ash. Подключение файла ничего не меняет — только объявляет функции.

# ---- постоянные ------------------------------------------------------------
# Окна d2k: CONNBYTES 0:8 в каждую сторону, голос 0:4. connskip считает
# пакеты соединения в обе стороны: 30 >= 2*8 плюс запас на повторы
# приветствия и ретрансмиссии (scripts/test-ppe-deoffload.sh сверяет это с
# S99d2k).
D2K_PPE_CONNSKIP=${D2K_PPE_CONNSKIP:-30}
D2K_PPE_TARGET=${D2K_PPE_TARGET:-PPE}
D2K_PPE_TAG=${D2K_PPE_TAG:-d2k-ppe}
# Порты — те же, что у очереди d2k (S99d2k задаёт PORTS/VOICE_PORTS до
# подключения этого файла).
D2K_PPE_TCP_PORTS=${D2K_PPE_TCP_PORTS:-${PORTS:-0:65535}}
D2K_PPE_UDP_PORTS=${D2K_PPE_UDP_PORTS:-0:65535}
# ОТКРЫТЫЙ HTTP, KEEP-ALIVE (поле 04.10.2026): коробка смотрит каждый запрос
# соединения, а следующие запросы браузера идут далеко за 30-м пакетом, когда
# поток уже в ускорителе и мимо netfilter. Поэтому для порта 80 — только
# направление клиента (--dports) и широкий connskip: запросы и подтверждения
# клиента идут процессором, ответ сервера (сама загрузка) остаётся в
# ускорителе. Замер 05.09.2026 (docs/field/2026-09-05-stage0-datapath.md,
# опыт 3): правило по --dports с connskip 1000000 — клиент→сервер виден на
# 100 %, сервер→клиент 0,08 %, 230–305 Мбит/с, процессор до 4,5 %.
D2K_PPE_HTTP_PORTS=${D2K_PPE_HTTP_PORTS:-80}
D2K_PPE_HTTP_CONNSKIP=${D2K_PPE_HTTP_CONNSKIP:-1000000}
D2K_PPE_PROC=${D2K_PPE_PROC:-/proc/net}
D2K_PPE_CONFIG=${D2K_PPE_CONFIG:-/opt/d2k/config}
D2K_PPE_BINDS=${D2K_PPE_BINDS:-/proc/driver/hw_nat/foe/binds}
D2K_PPE_DPLOG=${D2K_PPE_DPLOG:-/opt/d2k/log/d2kd.log}

# ---- обёртки, переживающие занятый xtables.lock -----------------------------
_d2k_ppe_ipt() {
    _d2k_ppe_tool=$1; shift
    "$_d2k_ppe_tool" -w "$@" 2>/dev/null || "$_d2k_ppe_tool" "$@" 2>/dev/null
}

# ---- шлюзы -----------------------------------------------------------------
# Выключил ли владелец (D2K_PPE_DEOFFLOAD=0). Переменная окружения (S99d2k
# уже прочёл конфигурацию) важнее файла; файл читается разбором, без `.`.
d2k_ppe_user_disabled() {
    _d2k_ppe_v=${D2K_PPE_DEOFFLOAD:-}
    if [ -z "$_d2k_ppe_v" ] && [ -r "$D2K_PPE_CONFIG" ]; then
        _d2k_ppe_v=$(awk -F= '/^[[:space:]]*D2K_PPE_DEOFFLOAD=/ { v = $2 } END {
            gsub(/["'"'"' ]/, "", v); print v }' "$D2K_PPE_CONFIG" 2>/dev/null)
    fi
    [ "$_d2k_ppe_v" = 0 ]
}

# Есть ли цель PPE для семейства (iptables | ip6tables).
d2k_ppe_available() {
    case "$1" in
        iptables)  _d2k_ppe_f=$D2K_PPE_PROC/ip_tables_targets ;;
        ip6tables) _d2k_ppe_f=$D2K_PPE_PROC/ip6_tables_targets ;;
        *) return 1 ;;
    esac
    command -v "$1" >/dev/null 2>&1 || return 1
    grep -qx "$D2K_PPE_TARGET" "$_d2k_ppe_f" 2>/dev/null
}

# ---- правила ---------------------------------------------------------------
# Строки «цепочка|аргументы» в порядке вставки. -I ставит в начало, поэтому
# итоговый порядок в цепочке обратный — для одинаковой цели он не важен.
_d2k_ppe_rules() {
    _d2k_ppe_tail="-m connskip --connskip $D2K_PPE_CONNSKIP -m comment --comment $D2K_PPE_TAG -j $D2K_PPE_TARGET"
    for _d2k_ppe_p in tcp udp; do
        if [ "$_d2k_ppe_p" = tcp ]; then _d2k_ppe_ports=$D2K_PPE_TCP_PORTS
        else _d2k_ppe_ports=$D2K_PPE_UDP_PORTS; fi
        printf 'PREROUTING|-p %s -m multiport --dports %s %s\n' "$_d2k_ppe_p" "$_d2k_ppe_ports" "$_d2k_ppe_tail"
        printf 'FORWARD|-p %s -m multiport --dports %s %s\n' "$_d2k_ppe_p" "$_d2k_ppe_ports" "$_d2k_ppe_tail"
        printf 'FORWARD|-p %s -m multiport --sports %s %s\n' "$_d2k_ppe_p" "$_d2k_ppe_ports" "$_d2k_ppe_tail"
    done
    _d2k_ppe_tail="-m connskip --connskip $D2K_PPE_HTTP_CONNSKIP -m comment --comment $D2K_PPE_TAG -j $D2K_PPE_TARGET"
    printf 'PREROUTING|-p tcp -m multiport --dports %s %s\n' "$D2K_PPE_HTTP_PORTS" "$_d2k_ppe_tail"
    printf 'FORWARD|-p tcp -m multiport --dports %s %s\n' "$D2K_PPE_HTTP_PORTS" "$_d2k_ppe_tail"
}

# Свои правила семейства по метке: строки «цепочка|аргументы» как их печатает
# iptables -S. По метке, а не по текущим портам: конфигурация могла смениться
# после установки, а снять надо то, что стоит.
_d2k_ppe_owned() {
    for _d2k_ppe_ch in PREROUTING FORWARD; do
        _d2k_ppe_ipt "$1" -t mangle -S "$_d2k_ppe_ch" |
            awk -v ch="$_d2k_ppe_ch" -v tag="$D2K_PPE_TAG" '
                $1 == "-A" && $2 == ch {
                    for (i = 3; i < NF; i++)
                        if ($i == "--comment" && ($(i + 1) == tag || $(i + 1) == "\"" tag "\"")) {
                            sub(/^-A [^ ]+ /, ""); print ch "|" $0; break
                        }
                }'
    done
}

_d2k_ppe_remove_family() {
    _d2k_ppe_owned "$1" | while IFS='|' read -r _d2k_ppe_ch _d2k_ppe_args; do
        # shellcheck disable=SC2086  # аргументы правила — слова, как у iptables -S
        _d2k_ppe_ipt "$1" -t mangle -D "$_d2k_ppe_ch" $_d2k_ppe_args
    done
}

_d2k_ppe_ensure_family() {
    _d2k_ppe_rc=0
    # Не через конвейер: цикл в подоболочке потерял бы код отказа.
    while IFS='|' read -r _d2k_ppe_ch _d2k_ppe_args; do
        [ -n "$_d2k_ppe_ch" ] || continue
        # shellcheck disable=SC2086
        _d2k_ppe_ipt "$1" -t mangle -C "$_d2k_ppe_ch" $_d2k_ppe_args && continue
        # shellcheck disable=SC2086
        _d2k_ppe_ipt "$1" -t mangle -I "$_d2k_ppe_ch" $_d2k_ppe_args || _d2k_ppe_rc=1
    done <<RULES
$(_d2k_ppe_rules)
RULES
    return "$_d2k_ppe_rc"
}

# Поставить недостающее. Коды: 0 — стоит; 1 — не встало; 2 — в прошивке нет
# цели PPE (ничего не ставится); 3 — выключено владельцем (своё снято).
d2k_ppe_ensure() {
    if d2k_ppe_user_disabled; then
        d2k_ppe_remove
        return 3
    fi
    d2k_ppe_available iptables || return 2
    _d2k_ppe_ensure_family iptables || return 1
    if d2k_ppe_available ip6tables; then
        _d2k_ppe_ensure_family ip6tables || return 1
    fi
    return 0
}

# Снять своё (оба семейства). Чужие -j PPE не трогаются.
d2k_ppe_remove() {
    for _d2k_ppe_tool in iptables ip6tables; do
        command -v "$_d2k_ppe_tool" >/dev/null 2>&1 || continue
        _d2k_ppe_remove_family "$_d2k_ppe_tool"
    done
    return 0
}

_d2k_ppe_count() { _d2k_ppe_owned "$1" | grep -c . ; }

# ---- состояние (только чтение) ---------------------------------------------
# $1 — необязательный адрес цели: виден ли он в привязках ускорителя.
d2k_ppe_status() {
    _d2k_ppe_want=$(_d2k_ppe_rules | grep -c .)
    if d2k_ppe_user_disabled; then
        echo "  разгрузка PPE: выключена владельцем (D2K_PPE_DEOFFLOAD=0)"
    elif ! d2k_ppe_available iptables; then
        echo "  разгрузка PPE: недоступна — в прошивке нет цели $D2K_PPE_TARGET"
    else
        _d2k_ppe_n4=$(_d2k_ppe_count iptables)
        _d2k_ppe_line="v4: $_d2k_ppe_n4 из $_d2k_ppe_want правил"
        if d2k_ppe_available ip6tables; then
            _d2k_ppe_line="$_d2k_ppe_line, v6: $(_d2k_ppe_count ip6tables) из $_d2k_ppe_want"
        fi
        # «Включена» — только если стоит целиком в каждом доступном семействе:
        # IPv6-поток без разгрузки так же слеп, как IPv4.
        _d2k_ppe_full=1
        [ "$_d2k_ppe_n4" -ge "$_d2k_ppe_want" ] || _d2k_ppe_full=0
        if d2k_ppe_available ip6tables &&
            [ "$(_d2k_ppe_count ip6tables)" -lt "$_d2k_ppe_want" ]; then
            _d2k_ppe_full=0
        fi
        if [ "$_d2k_ppe_full" = 1 ]; then
            echo "  разгрузка PPE: включена ($_d2k_ppe_line, первые $D2K_PPE_CONNSKIP пакетов)"
        else
            echo "  разгрузка PPE: не стоит ($_d2k_ppe_line)"
        fi
        echo "  ограничение: после $D2K_PPE_CONNSKIP пакетов поток снова в ускорителе — поздние RST/FIN такого потока d2k не видит"
        echo "  открытый HTTP (порт $D2K_PPE_HTTP_PORTS): сторона клиента мимо ускорителя все $D2K_PPE_HTTP_CONNSKIP пакетов — следующие запросы соединения видны"
    fi

    # Основной оракул на MediaTek: поток в binds ушёл мимо netfilter.
    if [ -r "$D2K_PPE_BINDS" ]; then
        # Заголовок вида «PPE0:» записью не является.
        _d2k_ppe_nb=$(grep -cv '^[[:space:]]*PPE[0-9]*:[[:space:]]*$' "$D2K_PPE_BINDS" 2>/dev/null)
        echo "  ускоритель binds: ${_d2k_ppe_nb:-0} записей в $D2K_PPE_BINDS"
        if [ -n "${1:-}" ]; then
            # Адрес — точно и с границами: 1.2.3.4 не находится в 11.2.3.4
            # и 1.2.3.45, точка — буквальная. Формат записи (KN-1811,
            # 02.10.2026): «IPv4_NAPT=802: 87.228.47.201:443 -> …».
            # shellcheck disable=SC2016  # $ здесь — буквальный символ класса
            _d2k_ppe_re=$(printf '%s' "$1" | sed 's/[].[\*^$()+?{}|]/\\&/g')
            if grep -Eq -- "(^|[^0-9.])$_d2k_ppe_re(:|[^0-9]|\$)" "$D2K_PPE_BINDS" 2>/dev/null; then
                echo "  $1: в ускорителе (поток привязан, мимо netfilter)"
            else
                echo "  $1: в binds нет"
            fi
        fi
    else
        echo "  ускоритель binds: нет ($D2K_PPE_BINDS не читается)"
    fi

    # Счётчик датапата: последняя сводка d2kd (datapath/d2kd.c).
    _d2k_ppe_last=$(tail -n 400 "$D2K_PPE_DPLOG" 2>/dev/null |
        grep '^ответ невидим очереди: ' | tail -n 1)
    if [ -n "$_d2k_ppe_last" ]; then
        # shellcheck disable=SC2046  # два числа, нарочно словами
        set -- $(printf '%s\n' "$_d2k_ppe_last" |
            sed -n 's/^ответ невидим очереди: \([0-9]*\) из \([0-9]*\) .*/\1 \2/p')
        _d2k_ppe_h=${1:-0}; _d2k_ppe_m=${2:-0}
        _d2k_ppe_pct=0
        [ "$_d2k_ppe_m" -gt 0 ] && _d2k_ppe_pct=$((_d2k_ppe_h * 100 / _d2k_ppe_m))
        echo "  ответ невидим очереди: $_d2k_ppe_h из $_d2k_ppe_m ($_d2k_ppe_pct%) TCP-потоков с приветствием"
        # Порог: не меньше 5 потоков и не меньше пятой части. Причина —
        # вероятная, не доказанная: ответы теряются и при переполнении очереди
        # или перезапуске датапата.
        if [ "$_d2k_ppe_h" -ge 5 ] && [ "$_d2k_ppe_pct" -ge 20 ]; then
            echo "  вероятно, ускоритель скрывает ответы (другие причины: переполнение очереди, перезапуск датапата); если подтвердится по binds — выключите аппаратное ускорение в CLI Keenetic (no ppe hardware), d2k этого сам не делает"
        fi
    fi
    return 0
}

# ---- запуск напрямую ---------------------------------------------------------
case "${0##*/}" in
    d2k-ppe-deoffload.sh)
        case "${1:-}" in
            ensure) d2k_ppe_ensure ;;
            remove) d2k_ppe_remove ;;
            status) d2k_ppe_status "${2:-}" ;;
            *) echo "использование: $0 {ensure|remove|status [адрес]}" >&2; exit 2 ;;
        esac
        ;;
esac
