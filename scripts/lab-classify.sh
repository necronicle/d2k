#!/bin/sh
# lab-classify.sh — ПОКАЗАТЬ ТРАССУ ПОИСКА, а не гадать о ней.
#
# Зачем. Стенды проверяют утверждения («обход дошёл до клиента»), и когда поиск
# не сходится, они говорят только это: не сошёлся. Где он провёл минуты — в
# базе, в контроле, в вопросах о свойствах или в запасном переборе — из них не
# видно, и 17.09 это стоило двух прогонов вслепую: замер шёл третью минуту при
# окне стенда в две, и отличить «идёт» от «висит» было нечем.
#
# Здесь поднимается тот же игрушечный цензор, что в lab-transit.sh, и по нему
# гоняется САМ измеритель (detect/d2k-detect classify) — тот же код, что зовёт
# планировщик, но со своей трассой на выходе. Это не приёмка: ничего не
# доказывается, показывается ход поиска.
#
# Требует Docker. Ничего не трогает на хосте и на роутере.
set -eu

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$HERE/.." && pwd)

if ! docker info >/dev/null 2>&1; then
    echo "lab-classify.sh: нужен запущенный Docker (docker info не отвечает)" >&2
    exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
tar -C "$ROOT" -cf - --exclude='.git' --exclude='*.o' --exclude='state' . | tar -C "$WORK" -xf -

cat > "$WORK/classify.sh" <<'DRIVER'
#!/bin/sh
set -e
cd /w

NAME=${D2K_LAB_NAME:-www.google.com}
MODE=${D2K_LAB_CENSOR:-naive}
QUEUE=2107

echo "== подготовка =="
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq iptables curl >/dev/null 2>&1

IP=$(getent ahostsv4 "$NAME" | awk '{print $1; exit}')
[ -n "$IP" ] || { echo "имя $NAME не разрешается" >&2; exit 1; }
echo "цель: $NAME ($IP), цензор: $MODE"

echo "== сборка =="
cc -std=c99 -O2 -Wall -Wextra -Werror -Idatapath/include -Icore/include \
   -o /tmp/labdpi spike/labdpi.c datapath/nfq.c datapath/nl.c \
   core/quic.c core/quicwire.c core/crypto.c
make -s -C detect d2k-detect

echo "== цензор =="
# Очередь, а не -j DROP: вердикт очереди приходит ПОСЛЕ возврата sendto, а
# DROP локально рождённого пакета возвращает отправителю EPERM — и измеритель
# мерил бы собственную реакцию на локальный отказ вместо цензуры.
iptables -t mangle -N D2KQ 2>/dev/null || iptables -t mangle -F D2KQ
iptables -t mangle -A POSTROUTING -j D2KQ
iptables -t mangle -A D2KQ -p tcp --dport 443 -j NFQUEUE --queue-num "$QUEUE" --queue-bypass
if [ "$MODE" = "naive" ]; then
    /tmp/labdpi "$QUEUE" "$NAME" 62 --naive > /tmp/labdpi.log 2>&1 &
else
    /tmp/labdpi "$QUEUE" "$NAME" 62 > /tmp/labdpi.log 2>&1 &
fi
DPI=$!
sleep 1

# Цензор обязан РЕЗАТЬ, иначе показывать нечего: измеритель увидит чистую цель
# и честно остановится на первом же зонде.
CODE=$(curl -4 -s -o /dev/null -w "%{http_code}" --max-time 8 "https://$NAME/" || true)
[ "$CODE" = "000" ] || { echo "цензор не режет (код $CODE) — показывать нечего" >&2; exit 1; }
echo "цензор на месте: прямое обращение к $NAME не проходит"

echo "== поиск: полная трасса =="
START=$(date +%s)
# --progress: трасса печатается в конце, а поиск идёт десятки минут. Без него
# «идёт» не отличить от «висит» — ровно это и случилось 17.09 дважды.
./detect/d2k-detect classify "$IP:443" --sni "$NAME" --repeats 3 --progress 2>&1 || true
END=$(date +%s)
echo "поиск занял $((END-START)) с"

kill "$DPI" 2>/dev/null || true
wait "$DPI" 2>/dev/null || true
echo "--- цензор ---"
tail -3 /tmp/labdpi.log 2>/dev/null || true
DRIVER

docker run --rm --cap-add=NET_ADMIN --cap-add=NET_RAW \
    -e "D2K_LAB_NAME=${D2K_LAB_NAME:-www.google.com}" \
    -e "D2K_LAB_CENSOR=${D2K_LAB_CENSOR:-naive}" \
    -v "$WORK:/w" -w /w gcc:14 sh /w/classify.sh
