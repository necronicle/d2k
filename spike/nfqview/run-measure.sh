#!/bin/sh
# d2k, этап 0 — один прогон замера датапата на роутере. НЕ продуктовый код.
#
# Ставит правила NFQUEUE, гоняет nfqview, снимает правила и кладёт рядом
# срезы conntrack до и после. Сравнение «что увидела очередь» против
# «сколько пакетов насчитал conntrack» и есть замер видимости.
#
# Правила ставятся с --queue-bypass: без слушателя пакеты идут дальше, а не
# теряются. Поэтому забытое правило не рвёт пользователю сеть, и дедлайн
# ниже — гигиена, а не страховка от катастрофы.
#
# Переменные:
#   Q       номер очереди (по умолчанию 200)
#   DUR     длительность (по умолчанию 60s)
#   SCOPE   IP клиента; пусто — весь транзит через WAN
#   WAN     имя WAN-интерфейса (по умолчанию ppp0)
#   OUT     префикс файлов результата
#   ARGS    дополнительные аргументы nfqview
#   DEOFF   ширина окна де-оффлоада в пакетах для SCOPE (пусто — не трогать).
#           Аппаратный PPE забирает поток себе через N пакетов, и после этого
#           очередь его не видит. Правило `-j PPE` с `-m connskip` держит поток
#           в софте ровно N пакетов — это и есть регулятор горизонта видимости.
set -u

Q=${Q:-200}
DUR=${DUR:-60s}
SCOPE=${SCOPE:-}
WAN=${WAN:-ppp0}
OUT=${OUT:-/tmp/nfqview}
ARGS=${ARGS:-}
BIN=${BIN:-/tmp/nfqview}
DEOFF=${DEOFF:-}

# BusyBox iptables на этой прошивке может не знать -w. Проверяем, а не
# предполагаем: молчаливый отказ здесь стоил бы правил, поставленных наполовину.
IPT="iptables -w"
$IPT -L INPUT -n >/dev/null 2>&1 || IPT="iptables"

if [ -n "$SCOPE" ]; then
    SPEC1="-s $SCOPE"
    SPEC2="-d $SCOPE"
    CT_FILTER="$SCOPE"
else
    SPEC1="-o $WAN"
    SPEC2="-i $WAN"
    CT_FILTER=""
fi

# SPEC1/SPEC2 обязаны разделиться на слова: это «-s IP» или «-o ppp0»,
# то есть два аргумента iptables. Кавычки здесь склеили бы их в один
# и правило не встало бы.
# shellcheck disable=SC2086
add_rules() {
    $IPT -I FORWARD 1 $SPEC1 -j NFQUEUE --queue-num "$Q" --queue-bypass || return 1
    $IPT -I FORWARD 2 $SPEC2 -j NFQUEUE --queue-num "$Q" --queue-bypass || return 1
    return 0
}

# SPEC1/SPEC2 обязаны разделиться на слова: это «-s IP» или «-o ppp0»,
# то есть два аргумента iptables. Кавычки здесь склеили бы их в один
# и правило не встало бы.
# shellcheck disable=SC2086
del_rules() {
    i=0
    while [ $i -lt 8 ]; do
        $IPT -D FORWARD $SPEC1 -j NFQUEUE --queue-num "$Q" --queue-bypass 2>/dev/null || break
        i=$((i + 1))
    done
    i=0
    while [ $i -lt 8 ]; do
        $IPT -D FORWARD $SPEC2 -j NFQUEUE --queue-num "$Q" --queue-bypass 2>/dev/null || break
        i=$((i + 1))
    done
}

# shellcheck disable=SC2086
deoff_add() {
    [ -n "$DEOFF" ] || return 0
    [ -n "$SCOPE" ] || { echo "DEOFF без SCOPE запрещён: это весь роутер" >&2; return 1; }
    $IPT -t mangle -I PREROUTING 1 -s "$SCOPE" -p tcp -m multiport --dports 80,443 \
        -m connskip --connskip "$DEOFF" -j PPE || return 1
    $IPT -t mangle -I FORWARD 1 -s "$SCOPE" -p tcp -m multiport --dports 80,443 \
        -m connskip --connskip "$DEOFF" -j PPE || return 1
    return 0
}

# shellcheck disable=SC2086
deoff_del() {
    [ -n "$DEOFF" ] || return 0
    i=0
    while [ $i -lt 4 ]; do
        $IPT -t mangle -D PREROUTING -s "$SCOPE" -p tcp -m multiport --dports 80,443 \
            -m connskip --connskip "$DEOFF" -j PPE 2>/dev/null || break
        i=$((i + 1))
    done
    i=0
    while [ $i -lt 4 ]; do
        $IPT -t mangle -D FORWARD -s "$SCOPE" -p tcp -m multiport --dports 80,443 \
            -m connskip --connskip "$DEOFF" -j PPE 2>/dev/null || break
        i=$((i + 1))
    done
}

ct_snapshot() {
    if [ -n "$CT_FILTER" ]; then
        grep -F "$CT_FILTER" /proc/net/nf_conntrack 2>/dev/null
    else
        cat /proc/net/nf_conntrack 2>/dev/null
    fi
}

trap 'deoff_del; del_rules; exit 130' INT TERM

echo "== снимок firewall до =="
$IPT -S FORWARD | head -6

if ! add_rules; then
    echo "ПРАВИЛА НЕ ПОСТАВЛЕНЫ — снимаю всё, что успело встать" >&2
    del_rules
    exit 1
fi
if ! deoff_add; then
    echo "ДЕ-ОФФЛОАД НЕ ПОСТАВЛЕН — откатываю всё" >&2
    deoff_del
    del_rules
    exit 1
fi
echo "== правила поставлены =="
$IPT -S FORWARD | head -4
[ -n "$DEOFF" ] && { echo "== окно де-оффлоада $DEOFF пакетов =="; $IPT -t mangle -S FORWARD | head -2; }

# Дедлайн на случай обрыва ssh: снимет правила даже если основной процесс
# не доживёт. trap "" HUP обязателен — на этой прошивке нет ни nohup, ни setsid.
case "$DUR" in
    *m) DSEC=$(( ${DUR%m} * 60 )) ;;
    *s) DSEC=${DUR%s} ;;
    *)  DSEC=$DUR ;;
esac
DEADLINE=${DEADLINE:-$(( DSEC + 120 ))}
# shellcheck disable=SC2086
( trap "" HUP; sleep "$DEADLINE"; [ -f /tmp/d2k-measure.done ] || {
      i=0; while [ $i -lt 8 ]; do
          $IPT -D FORWARD $SPEC1 -j NFQUEUE --queue-num "$Q" --queue-bypass 2>/dev/null || break; i=$((i+1)); done
      i=0; while [ $i -lt 8 ]; do
          $IPT -D FORWARD $SPEC2 -j NFQUEUE --queue-num "$Q" --queue-bypass 2>/dev/null || break; i=$((i+1)); done
  } ) </dev/null >/dev/null 2>&1 &

rm -f /tmp/d2k-measure.done
ct_snapshot > "$OUT.ct-before.txt"

echo "== замер $DUR =="
# shellcheck disable=SC2086
"$BIN" -q "$Q" -dur "$DUR" -out "$OUT" $ARGS
rc=$?

ct_snapshot > "$OUT.ct-after.txt"
touch /tmp/d2k-measure.done
deoff_del
del_rules

echo "== правила сняты =="
$IPT -S FORWARD | head -4
echo "== очередь ядра =="
cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null
exit $rc
