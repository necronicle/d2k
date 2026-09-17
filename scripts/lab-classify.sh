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

NAME=${D2K_LAB_NAME:-zamer.example}
MODE=${D2K_LAB_CENSOR:-naive}
TARGET=${D2K_LAB_TARGET:-local}
QUEUE=2107
PORT=443

echo "== подготовка =="
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq iptables iproute2 curl libssl-dev >/dev/null 2>&1

# ЦЕЛЬ ПО УМОЛЧАНИЮ — МЕСТНАЯ, И ЭТО НЕ УПРОЩЕНИЕ.
#
# Прогон к настоящему хосту уходит с машины и проходит через линию оператора.
# На роутере автора поднят z2k, и его правило ловит ВЕСЬ трафик на 443 по порту
# (zport_tcp — набор портов, а не адресов). Тогда измеряются три коробки сразу:
# игрушечный цензор, наш датапат и чужой десинк. Замер 17.09: на местной цели
# приём находится за 63 с, на внешней тот же поиск отдал 294 зонда за 16,8
# минуты и не нашёл ничего — включая disorder, который по построению обязан
# бить наивный цензор, потому что режет ПО ИМЕНИ (координаты имени в триггере
# проверены отдельно: sni_off=137, длина 14, середина имени 144 против
# середины пакета 768).
#
# Внешняя цель остаётся доступной ключом, но это другой опыт, и его результат
# читать надо с оговоркой про чужую линию.
if [ "$TARGET" = "local" ]; then
    IP=10.203.0.7
    ip addr add "$IP/32" dev lo
    ip link set lo mtu 1500 2>/dev/null || true
    echo "цель: $NAME ($IP, местная), цензор: $MODE"
else
    IP=$(getent ahostsv4 "$NAME" | awk '{print $1; exit}')
    [ -n "$IP" ] || { echo "имя $NAME не разрешается" >&2; exit 1; }
    echo "цель: $NAME ($IP, ВНЕШНЯЯ — в замере участвует чужая линия), цензор: $MODE"
fi

echo "== сборка =="
cc -std=c99 -O2 -Wall -Wextra -Werror -Idatapath/include -Icore/include \
   -o /tmp/labdpi spike/labdpi.c datapath/nfq.c datapath/nl.c \
   core/quic.c core/quicwire.c core/crypto.c
make -s -C detect d2k-detect

if [ "$TARGET" = "local" ]; then
    # Тот же форкающий сервер, что в lab-censor.sh, и по той же причине:
    # s_server обслуживает по очереди и виснет на зарезанном рукопожатии.
    cc -std=c99 -O2 -Wall -Wextra -o /tmp/labtls spike/labtls.c -lssl -lcrypto
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout /tmp/k.pem -out /tmp/c.pem -days 1 -nodes -subj "/CN=$NAME" \
        -addext "subjectAltName=DNS:$NAME" >/dev/null 2>&1
    /tmp/labtls "$PORT" /tmp/c.pem /tmp/k.pem >/tmp/server.log 2>&1 &
    SRV=$!
    i=0
    while ! (timeout 3 openssl s_client -connect "$IP:$PORT" </dev/null >/dev/null 2>&1) \
          && [ $i -lt 50 ]; do i=$((i+1)); sleep 0.2; done
    [ $i -lt 50 ] || { echo "сервер цели не поднялся" >&2; exit 1; }
    echo "местный сервер цели поднят"
fi

echo "== цензор =="
# Очередь, а не -j DROP: вердикт очереди приходит ПОСЛЕ возврата sendto, а
# DROP локально рождённого пакета возвращает отправителю EPERM — и измеритель
# мерил бы собственную реакцию на локальный отказ вместо цензуры.
iptables -t mangle -N D2KQ 2>/dev/null || iptables -t mangle -F D2KQ
iptables -t mangle -A POSTROUTING -j D2KQ
iptables -t mangle -A D2KQ -p tcp --dport "$PORT" -j NFQUEUE --queue-num "$QUEUE" --queue-bypass
if [ "$MODE" = "naive" ]; then
    /tmp/labdpi "$QUEUE" "$NAME" 62 --naive > /tmp/labdpi.log 2>&1 &
else
    /tmp/labdpi "$QUEUE" "$NAME" 62 > /tmp/labdpi.log 2>&1 &
fi
DPI=$!
sleep 1

# Цензор обязан РЕЗАТЬ, иначе показывать нечего: измеритель увидит чистую цель
# и честно остановится на первом же зонде.
CODE=$(curl -4 -sk -o /dev/null -w "%{http_code}" --max-time 8 \
    --resolve "$NAME:$PORT:$IP" "https://$NAME:$PORT/" || true)
[ "$CODE" = "000" ] || { echo "цензор не режет (код $CODE) — показывать нечего" >&2; exit 1; }
echo "цензор на месте: прямое обращение к $NAME не проходит"

echo "== поиск: полная трасса =="
START=$(date +%s)
# --progress: трасса печатается в конце, а поиск идёт десятки минут. Без него
# «идёт» не отличить от «висит» — ровно это и случилось 17.09 дважды.
./detect/d2k-detect classify "$IP:$PORT" --sni "$NAME" --repeats 3 --progress 2>&1 || true
END=$(date +%s)
echo "поиск занял $((END-START)) с"

kill "$DPI" 2>/dev/null || true
wait "$DPI" 2>/dev/null || true
[ -n "${SRV:-}" ] && { kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true; }
echo "--- цензор ---"
tail -3 /tmp/labdpi.log 2>/dev/null || true
DRIVER

docker run --rm --cap-add=NET_ADMIN --cap-add=NET_RAW \
    -e "D2K_LAB_NAME=${D2K_LAB_NAME:-zamer.example}" \
    -e "D2K_LAB_CENSOR=${D2K_LAB_CENSOR:-naive}" \
    -e "D2K_LAB_TARGET=${D2K_LAB_TARGET:-local}" \
    -v "$WORK:/w" -w /w gcc:14 sh /w/classify.sh
