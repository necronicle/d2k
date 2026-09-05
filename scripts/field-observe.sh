#!/bin/sh
# Полевое наблюдение d2kd на роутере.
#
# Собирает службу, кладёт её в tmpfs роутера, ставит правила, ждёт, снимает
# правила и забирает вывод. В режиме observe ни один пакет не меняется.
#
# Устройство и доступ берутся из окружения — репозиторий публичный:
#   D2K_ROUTER   адрес роутера   (обязательно)
#   D2K_SSH_PORT порт ssh        (222)
#   D2K_SSH_PASS пароль root     (если нет ключа)
#   D2K_LOAD     команда нагрузки, выполняется локально
#
# Что здесь защищает от уже сделанных ошибок:
#   * У каждого запуска СВОЙ жетон, и он проставлен комментарием в КАЖДОМ
#     правиле. Снимаются правила по жетону: читаем `-S`, меняем -A на -D.
#     Раньше правило ставилось с комментарием, а снималось без него — и
#     оставалось висеть. Сторож прошлого прогона однажды снял правила живого
#     посреди замера, и результат выглядел как «железо забрало всё».
#   * Уборка стоит на trap и срабатывает на любом выходе, включая ошибку.
#   * Привязка очереди проверяется ДО подачи нагрузки: иначе меряется тишина.
#   * `ssh -n` везде, кроме одной команды, которой stdin отдаётся намеренно.
#     Без -n ssh съедает stdin цикла; с -n и `< файл` на роутер уезжает пустой
#     файл. Оба случая уже происходили, поэтому размер сверяется после
#     доставки.
#   * `--queue-bypass` в правиле и fail-open в очереди: смерть службы
#     пропускает трафик, а не останавливает его.
#   * Всё в /tmp роутера (tmpfs). На флеш не пишется ничего.
set -eu

ROUTER=${D2K_ROUTER:?не задан D2K_ROUTER}
SSH_PORT=${D2K_SSH_PORT:-222}
QUEUE=${D2K_QUEUE:-537}
DUR=${D2K_DUR:-60}
PORTS=${D2K_PORTS:-443}
MODE=${D2K_MODE:-observe}
CONNBYTES=${D2K_CONNBYTES:-0:8}

REPO=$(cd "$(dirname "$0")/.." && pwd)
TOKEN="d2k$$"
STAMP=$(date +%Y%m%d-%H%M%S)
LOCAL_LOG="$REPO/docs/field/raw/observe-$STAMP.log"

if [ -n "${D2K_SSH_PASS:-}" ]; then
    SSH="sshpass -p $D2K_SSH_PASS ssh -n -p $SSH_PORT -o StrictHostKeyChecking=no root@$ROUTER"
    SSH_IN="sshpass -p $D2K_SSH_PASS ssh -p $SSH_PORT -o StrictHostKeyChecking=no root@$ROUTER"
else
    SSH="ssh -n -p $SSH_PORT root@$ROUTER"
    SSH_IN="ssh -p $SSH_PORT root@$ROUTER"
fi

say() { printf '%s\n' "$*" >&2; }

# Снимает ВСЕ правила с нашим жетоном и гасит службу. Идемпотентно.
teardown() {
    $SSH "
        iptables -t mangle -S POSTROUTING 2>/dev/null | grep -- '--comment $TOKEN' |
        sed 's/^-A /-D /' | while IFS= read -r r; do eval \"iptables -t mangle \$r\"; done
        [ -f /tmp/d2kd.$TOKEN.pid ] && kill \$(cat /tmp/d2kd.$TOKEN.pid) 2>/dev/null
        echo \"остаток правил с жетоном: \$(iptables -t mangle -S POSTROUTING 2>/dev/null | grep -c -- '--comment $TOKEN')\"
    " >&2 || true
}
trap 'teardown' EXIT INT TERM

say "== сборка =="
make -C "$REPO/datapath" d2kd-aarch64 >/dev/null
BIN="$REPO/builds/d2kd-aarch64"
[ -s "$BIN" ] || { say "бинарник не собрался"; exit 1; }
LOCAL_SIZE=$(wc -c < "$BIN" | tr -d ' ')
say "  $LOCAL_SIZE байт"

say "== доставка =="
# Потоком через ssh, а не scp: у dropbear на Keenetic нет sftp-server.
# Здесь ssh БЕЗ -n — stdin отдаётся намеренно.
$SSH_IN "cat > /tmp/d2kd.$TOKEN" < "$BIN"
REMOTE_SIZE=$($SSH "wc -c < /tmp/d2kd.$TOKEN" | tr -d ' \r')
[ "$LOCAL_SIZE" = "$REMOTE_SIZE" ] || {
    say "доставка испорчена: у нас $LOCAL_SIZE, на роутере $REMOTE_SIZE"
    exit 1
}
say "  доставлено $REMOTE_SIZE байт, размер совпал"
$SSH "chmod +x /tmp/d2kd.$TOKEN && /tmp/d2kd.$TOKEN --help >/dev/null 2>&1 && echo '  служба запускается'"

say "== правила, жетон $TOKEN =="
# Порядок: сперва снять офлоад, потом отдать в очередь. Правило PPE матчит
# ОДНО направление — то, что в нём написано; обратное остаётся в железе.
$SSH "
set -e
iptables -t mangle -I POSTROUTING -p tcp --dport $PORTS -m connskip --connskip 1000000 -m comment --comment $TOKEN -j PPE
iptables -t mangle -I POSTROUTING -p tcp --dport $PORTS -m connbytes --connbytes $CONNBYTES --connbytes-dir original --connbytes-mode packets -m comment --comment $TOKEN -j NFQUEUE --queue-num $QUEUE --queue-bypass
iptables -t mangle -S POSTROUTING | grep -c -- '--comment $TOKEN'
" | sed 's/^/  правил поставлено: /' >&2

# Сторож на случай, если управляющая сторона умрёт: снимает ТОЛЬКО свои
# правила и только по своему жетону.
$SSH "
( sleep $((DUR + 60))
  iptables -t mangle -S POSTROUTING 2>/dev/null | grep -- '--comment $TOKEN' |
  sed 's/^-A /-D /' | while IFS= read -r r; do eval \"iptables -t mangle \$r\"; done
  [ -f /tmp/d2kd.$TOKEN.pid ] && kill \$(cat /tmp/d2kd.$TOKEN.pid) 2>/dev/null
  rm -f /tmp/d2kd.$TOKEN /tmp/d2kd.$TOKEN.pid
) >/dev/null 2>&1 &
echo '  сторож взведён'
" >&2

say "== запуск службы =="
# nohup на BusyBox нет; start-stop-daemon есть и умеет отвязывать процесс.
$SSH "
start-stop-daemon -S -b -m -p /tmp/d2kd.$TOKEN.pid -x /tmp/d2kd.$TOKEN -- \
    --queue $QUEUE --mode $MODE --stats 15 --duration $DUR \
    --log /tmp/d2kd.$TOKEN.out
sleep 1
echo \"  pid=\$(cat /tmp/d2kd.$TOKEN.pid 2>/dev/null)\"
" >&2

say "== проверка привязки очереди =="
# Замер, начатый до привязки, измеряет тишину и выглядит убедительно.
BOUND=$($SSH "awk -v q=$QUEUE '\$1==q{print \$2}' /proc/net/netfilter/nfnetlink_queue 2>/dev/null" | tr -d ' \r')
if [ -z "$BOUND" ] || [ "$BOUND" = "0" ]; then
    say "ОЧЕРЕДЬ $QUEUE НЕ ПРИВЯЗАНА — нагрузку не подаём"
    $SSH "cat /tmp/d2kd.$TOKEN.log 2>/dev/null; ls -l /tmp/d2kd.$TOKEN*" >&2 || true
    exit 1
fi
say "  очередь $QUEUE привязана к процессу $BOUND"

say "== нагрузка, $DUR с =="
if [ -n "${D2K_LOAD:-}" ]; then
    sh -c "$D2K_LOAD" >&2 || say "  нагрузка вернула $?"
else
    say "  своей нагрузки нет — пользуйтесь интернетом как обычно"
fi
sleep $((DUR + 3))

say "== сбор вывода =="
mkdir -p "$(dirname "$LOCAL_LOG")"
$SSH "cat /tmp/d2kd.$TOKEN.out 2>/dev/null" > "$LOCAL_LOG" || true
teardown
$SSH "rm -f /tmp/d2kd.$TOKEN /tmp/d2kd.$TOKEN.pid /tmp/d2kd.$TOKEN.out; ls /tmp/d2kd.* 2>/dev/null || echo '  на роутере чисто'" >&2
trap - EXIT

say "== вывод: $LOCAL_LOG =="
cat "$LOCAL_LOG"
