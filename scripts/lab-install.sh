#!/bin/sh
# lab-install.sh — УСТАНОВКА ЦЕЛИКОМ, НА ЧИСТОЙ СИСТЕМЕ, В КОНТЕЙНЕРЕ.
#
# Этап G требует шесть проверок: чистая установка, переход версии, неудачное
# обновление, остановка, возврат в прежний режим и удаление. Ни одна из них
# не проверяется чтением скрипта: установщик правит /opt, ставит init-скрипт
# и правила экрана, и «на взгляд правильно» здесь стоит ровно столько же,
# сколько стоило в files/S99d2k до scripts/check_firewall.sh — то есть нисколько.
#
# Роутер не трогается ничем. Всё происходит в контейнере, чей /opt и чей
# сетевой namespace создаются заново на каждый запуск, и который после
# прогона исчезает.
#
# ПОЧЕМУ ЭТО НЕ «ПОЧТИ РОУТЕР» И ЧТО ОСТАЁТСЯ НЕПРОВЕРЕННЫМ. Контейнер даёт
# ту же арку (aarch64), тот же netfilter и тот же start-stop-daemon, но не
# даёт Entware, NDM и флеш-память роутера. Значит здесь НЕ проверяются:
# поведение при сбросе правил силами NDM, хук /opt/etc/ndm/netfilter.d,
# переживание перезагрузки и износ флешки. Это названо прямо, а не скрыто
# зелёным прогоном.
set -eu

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$HERE/.." && pwd)

if ! docker info >/dev/null 2>&1; then
    echo "lab-install.sh: нужен запущенный Docker (docker info не отвечает)" >&2
    exit 1
fi

WORK=$(mktemp -d)
# Контейнер ниже работает от root и пишет прямо в $WORK. На Linux такой
# каталог остаётся за root, и пользователь раннера удалить его не может —
# уборка падала с «Permission denied» уже ПОСЛЕ того, как все шесть проверок
# прошли, и красила зелёный прогон в красный. Тем же образом файлы сперва
# возвращаются вызвавшему пользователю. Docker Desktop на macOS сопоставляет
# владельца сам, поэтому локально этого не было видно.
cleanup() {
    if [ -d "$WORK" ] && command -v docker >/dev/null 2>&1; then
        docker run --rm -v "$WORK:/w" gcc:14 chown -R "$(id -u):$(id -g)" /w >/dev/null 2>&1 || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT
tar -C "$ROOT" -cf - --exclude='.git' --exclude='*.o' --exclude='state' \
    --exclude='./build' --exclude='./.impeccable' --exclude='./spike' . | tar -C "$WORK" -xf -

cat > "$WORK/install-lab.sh" <<'DRIVER'
#!/bin/sh
set -e
cd /w

INIT=/opt/etc/init.d/S99d2k
DIR=/opt/d2k
REL=/tmp/rel

fail() { echo "ПРОВАЛ: $*" >&2; dump; exit 1; }
dump() {
    echo "--- статус ---";  [ -x "$INIT" ] && "$INIT" status 2>&1 || true
    echo "--- API-панели ---"; curl -fsS http://127.0.0.1:8090/api/status 2>&1 || true; echo
    echo "--- повторная диагностика reapply ---"; sh -x "$INIT" reapply 2>&1 || true
    echo "--- правила ---"; iptables -t mangle -S 2>&1 | grep -i d2k || echo "(нет)"
    echo "--- журналы ---"; tail -n 15 "$DIR"/log/*.log 2>/dev/null || true
}
sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
# Действия панели асинхронны (POST отвечает «запущено», S99d2k идёт фоном):
# итог проверяем, дав ему до 30 с, а не в ту же миллисекунду.
await() { for _ in $(seq 1 30); do sh -c "$1" && return 0; sleep 1; done; sh -c "$1"; }
# POST действия панели. Пока предыдущее действие идёт, панель отвечает 409
# «Предыдущая команда ещё выполняется» — это не отказ, ждём и повторяем.
panel_post() {
    for _ in $(seq 1 60); do
        panel_curl -sS -X POST -H 'Origin: http://127.0.0.1:8090' "http://127.0.0.1:8090/api/control/$1" >/tmp/d2k-panel-post.json 2>/dev/null || true
        grep -q 'Предыдущая команда ещё выполняется' /tmp/d2k-panel-post.json || break
        sleep 1
    done
    cat /tmp/d2k-panel-post.json
    grep -q '"ok":true' /tmp/d2k-panel-post.json || return 1
    # Принятая команда идёт фоном: ждём её итога (control_state != running),
    # чтобы следующие проверки читали результат, а не полпути.
    for _ in $(seq 1 60); do
        panel_curl -fsS http://127.0.0.1:8090/api/status 2>/dev/null | grep -q '"control_state":"running"' || return 0
        sleep 1
    done
    return 0
}
rules() {
    iptables -t mangle -S 2>/dev/null | sort
    ip6tables -t mangle -S 2>/dev/null | sort
}
nfq6_direct() {
    # Explicit lab-only matches prove native queue delivery even when the
    # container's conntrack accounting is disabled. Never installed on a router.
    for proto in tcp udp; do
        ip6tables -t mangle -I OUTPUT -d ::1 -p "$proto" \
            -j NFQUEUE --queue-num 2000 --queue-bypass
    done
    /tmp/d2k-ipv6-direct || fail "IPv6 TCP/UDP не проходит очередь"
    ip6tables -t mangle -nvx -L OUTPUT | awk '
        $3 == "NFQUEUE" && $1 > 0 { seen++ } END { exit seen == 2 ? 0 : 1 }' \
        || fail "прямой IPv6 тест не прошёл оба NFQUEUE правила"
    for proto in tcp udp; do
        ip6tables -t mangle -D OUTPUT -d ::1 -p "$proto" \
            -j NFQUEUE --queue-num 2000 --queue-bypass
    done
}

echo "== подготовка контейнера =="
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq iptables ipset iproute2 openssl ca-certificates >/dev/null 2>&1
command -v start-stop-daemon >/dev/null || fail "нет start-stop-daemon — установщик на такой системе не работает"

case "$(uname -m)" in
    aarch64|arm64) ARCH=arm64 ;;
    *) fail "C runtime устанавливается только под ARM64, а лаборатория запущена на $(uname -m)" ;;
esac
echo "арка: $(uname -m) -> $ARCH"

echo "== сборка того, что будет установлено =="
# Сборка НАТИВНАЯ: контейнер той же арки, что и роутер Марка (aarch64).
# Кросс-сборка проверяется отдельно, гейтом; здесь проверяется установка.
make -s -C core d2kc d2kfetch d2kshadow
make -s -C datapath d2kd
cc -Wall -Wextra -Werror -o /tmp/d2k-ipv6-direct tests/ipv6-direct.c

mkdir -p "$REL/builds" "$REL/files/fake" "$REL/internal/web/assets" "$REL/scripts"
cp scripts/select-panel-ip.sh scripts/architecture.sh scripts/check-cpu.sh "$REL/scripts/"
cp core/d2kc     "$REL/builds/d2kc-linux-$ARCH"
cp core/d2kshadow "$REL/builds/d2kshadow-linux-$ARCH"
mkdir -p "$REL/core/profiles"
cp core/profiles/modern.hex "$REL/core/profiles/modern.hex"
cp core/profiles/legacy.hex "$REL/core/profiles/legacy.hex"
cp core/d2kfetch "$REL/builds/d2kfetch-linux-$ARCH"
cp datapath/d2kd "$REL/builds/d2kd-linux-$ARCH"
# d2ktg берётся готовым из builds/ — единственный бинарник, который там
# остался в git. Его собирают со статическим OpenSSL, это минуты на арку, а
# лаборатория проверяет установку, не сам туннель. Остальные четыре собираются
# выше нативно; на роутер все пять идут только подписанным выпуском.
cp builds/d2ktg-linux-arm64 "$REL/builds/d2ktg-linux-$ARCH"
make -s -C panel clean >/dev/null
make -s -C panel d2kpanel
cp panel/d2kpanel "$REL/builds/d2kpanel-linux-$ARCH"
cp internal/web/assets/index.html internal/web/assets/panel.css internal/web/assets/panel.js internal/web/assets/diagnostics.js internal/web/assets/gsap.js "$REL/internal/web/assets/"
cp internal/web/assets/favicon.svg "$REL/internal/web/assets/"
mkdir -p "$REL/internal/web/assets/fonts"
cp internal/web/assets/fonts/onest.woff2 internal/web/assets/fonts/OFL-onest.txt internal/web/assets/fonts/jbmono.woff2 internal/web/assets/fonts/OFL-jbmono.txt "$REL/internal/web/assets/fonts/"
cp files/S99d2k files/config files/d2k-fw-heal.sh files/001-d2k.sh "$REL/files/"
cp files/d2k-ppe-deoffload.sh files/d2k-log-maintenance.sh files/d2k-update.sh "$REL/files/"
cp files/d2k-openwrt-init "$REL/files/"
cp files/d2k-tg-firewall.sh files/d2k-tg-watchdog.sh files/d2k-instagram-dns.sh \
    files/d2k-instagram-dns-scheduler.sh files/meta-ranges.txt files/tg-roots.pem "$REL/files/"
cp files/fake/stun.bin files/fake/quic_initial_dbankcloud_ru.bin "$REL/files/fake/"
# The real package enables enrollment, but the isolated lab must never contact
# the production VPS or Telegram. Point its copied template to closed local ports.
sed -i 's|^TG_RELAY_URL=.*|TG_RELAY_URL=wss://127.0.0.1:11443/ws|; s/^TG_ENROLL_PORT=.*/TG_ENROLL_PORT=11444/' "$REL/files/config"
sed -i 's|^PROBE_URL=.*|PROBE_URL=https://127.0.0.1:11443/|; s/^PROBE_IP=.*/PROBE_IP=127.0.0.1/' "$REL/files/d2k-tg-watchdog.sh"
# Every path the installer will fetch must be staged: with D2K_LOCAL it dies
# on the first missing file, before installing anything (install.sh fetch).
for staged in $(sed -n 's/^fetch "\([^"]*\)".*/\1/p' scripts/install.sh | sed "s/\\\$ARCH/$ARCH/"); do
    [ -s "$REL/$staged" ] || fail "лабораторный пакет без $staged — установщик его потребует"
done

# Keenetic DNS lifecycle is exercised with a stateful ndmc double. curl is
# wrapped only for the external resolver and Instagram probes; the real curl
# still checks the local D2K panel below.
mkdir -p /tmp/d2k-test-bin
mkdir -p /tmp/d2k-install-bin
LAN_TEST_IP=$(hostname -I | awk '{print $1}')
[ -n "$LAN_TEST_IP" ] || fail "не определить IPv4 контейнера для проверки LAN-панели"
export LAN_TEST_IP
cat > /tmp/d2k-install-bin/ip <<'IP'
#!/bin/sh
case "$*" in
    "-4 -o addr show scope global")
        printf '9: ezcfg0 inet 198.51.100.11/32 scope global ezcfg0\n'
        printf '33: br1 inet 10.1.30.1/24 scope global br1\n'
        printf '34: br0 inet %s/24 scope global br0\n' "$LAN_TEST_IP"
        printf '37: ppp0 inet 88.87.93.11/32 scope global ppp0\n'
        ;;
    *) echo "unexpected ip invocation: $*" >&2; exit 2 ;;
esac
IP
chmod +x /tmp/d2k-install-bin/ip
export PATH="/tmp/d2k-install-bin:$PATH"
cat > /tmp/d2k-test-bin/ndmc <<'NDMC'
#!/bin/sh
case "$*" in
    *"show running-config"*) cat /tmp/d2k-ndmc-state ;;
    *"system configuration save"*) : ;;
    *"-c ip host "*)
        set -- $*
        printf 'ip host %s %s\n' "$4" "$5" >> /tmp/d2k-ndmc-state
        ;;
    *"-c no ip host "*)
        set -- $*
        host=$5; ip=$6
        awk -v h="$host" -v ip="$ip" '!( $1=="ip" && $2=="host" && $3==h && $4==ip )' /tmp/d2k-ndmc-state > /tmp/d2k-ndmc-state.new
        mv /tmp/d2k-ndmc-state.new /tmp/d2k-ndmc-state
        ;;
    *) echo "unexpected ndmc: $*" >&2; exit 2 ;;
esac
NDMC
cat > /tmp/d2k-test-bin/curl <<'CURL'
#!/bin/sh
case "$*" in
    *https://85.192.60.175.nip.io:9443/resolve*)
        printf '%s' '{"results":{"instagram.com":["157.240.9.174"],"www.instagram.com":["157.240.9.175"],"web.whatsapp.com":["157.240.9.52"]}}'
        exit 0
        ;;
    *https://instagram.com/*|*https://www.instagram.com/*)
        printf '200'
        exit 0
        ;;
esac
exec /usr/bin/curl "$@"
CURL
cat > /tmp/d2k-test-bin/d2ktg <<'TGPROBE'
#!/bin/sh
if [ "$1" = --check-instagram-ip ]; then
    [ "$#" = 4 ] || exit 2
    case "$2:$3" in
        instagram.com:157.240.9.174|www.instagram.com:157.240.9.175|web.whatsapp.com:157.240.9.52) exit 0 ;;
        *) exit 1 ;;
    esac
fi
exec /opt/sbin/d2ktg "$@"
TGPROBE
chmod +x /tmp/d2k-test-bin/ndmc /tmp/d2k-test-bin/curl /tmp/d2k-test-bin/d2ktg
printf 'ip host www.instagram.com 157.240.9.175\nip host instagram.com 203.0.113.10\nip host unrelated.example 192.0.2.7\n' > /tmp/d2k-ndmc-state
export D2K_STUB_PATH=/tmp/d2k-test-bin
panel_curl() {
    curl --connect-to "127.0.0.1:8090:$LAN_TEST_IP:8090" "$@"
}

# СНИМОК ЧИСТОЙ СИСТЕМЫ. По нему проверяются и остановка, и удаление: обе
# обязаны вернуть экран ровно в то состояние, в каком его застали.
CLEAN_RULES=$(rules)

echo "== 1. чистая установка =="
[ -e "$DIR" ] && fail "система не чистая: $DIR уже есть"
D2K_LOCAL="$REL" sh scripts/install.sh 2>&1 | tee /tmp/install1.log
[ "$(tail -1 /tmp/install1.log)" != "" ] || true
grep -q "готово" /tmp/install1.log || fail "установка с чистого состояния не прошла: $(tail -3 /tmp/install1.log)"
[ "$(stat -c '%a' "$DIR/config")" = 600 ] || fail "конфигурация с relay-секретом должна быть доступна только root"
[ "$(grep -c '^MODE=apply$' "$DIR/config")" = 1 ] || fail "чистая установка должна включать активный режим D2K"
[ "$(grep -c "^PANEL_LISTEN=$LAN_TEST_IP:8090$" "$DIR/config")" = 1 ] || fail "чистая установка не привязала панель к LAN-адресу"

"$INIT" status | grep -q "датапат: работает" || fail "после установки датапат не работает"
"$INIT" status | grep -q "правила: стоят"    || fail "после установки правил нет"
"$INIT" status | grep -q "очередь .*привязана" || fail "очередь не привязана"
ip6tables -t mangle -C POSTROUTING -j D2K_OUT || fail "установщик не включил IPv6"
nfq6_direct
[ -x /opt/sbin/d2kd ] || fail "d2kd не установлен"
[ -x /opt/sbin/d2kc ] || fail "d2kc не установлен"
[ -x /opt/sbin/d2ktg ] || fail "C-туннель Telegram не установлен"
[ -x "$DIR/d2k-tg-firewall.sh" ] || fail "не установлен firewall Telegram"
[ -x "$DIR/d2k-tg-watchdog.sh" ] || fail "не установлен сторож Telegram"
[ -x "$DIR/d2k-instagram-dns.sh" ] || fail "не установлен Instagram DNS manager"
[ -s "$DIR/files/meta-ranges.txt" ] || fail "не установлены диапазоны Meta для проверки VPS-ответа"
# The first DNS refresh runs in the background (service scheduler), not in the installer.
dns_wait=0
while [ "$dns_wait" -lt 30 ] && [ ! -s "$DIR/state/instagram-dns-last-success" ]; do
    sleep 1; dns_wait=$((dns_wait + 1))
done
[ "$(grep -c '^ip host instagram.com 157.240.9.174$' /tmp/d2k-ndmc-state)" = 1 ] || fail "фоновое обновление не применило VPS Instagram-резолв"
[ "$(grep -c '^ip host web.whatsapp.com 157.240.9.52$' /tmp/d2k-ndmc-state)" = 1 ] || fail "фоновое обновление не прописало WhatsApp Web"
[ "$(grep -c '^instagram.com 157.240.9.174$' "$DIR/state/instagram-ip-hosts.tsv")" = 1 ] || fail "установщик не сохранил владение Instagram-записью"
[ "$(grep -c '^www.instagram.com 157.240.9.175$' "$DIR/state/instagram-ip-hosts.tsv" || true)" = 0 ] || fail "установщик присвоил себе заранее существующую запись"
[ -s "$DIR/files/tg-roots.pem" ] || fail "не установлен CA bundle Telegram"
/opt/sbin/d2ktg --version | grep -q 'features=per-install-enrollment' || fail "нет автоматической регистрации C-туннеля"
[ "$(grep -c '^TG_ENABLED=1$' "$DIR/config")" = 1 ] || fail "Telegram должен быть включён по умолчанию"
[ "$(grep -Ec '^[[:space:]]*TG_RELAY_SECRET=' "$DIR/config" || true)" = 0 ] || fail "шаблон не должен задавать relay secret активным ключом"
[ -e "$DIR/run/d2ktg.pid" ] || fail "Telegram не запущен установщиком"
[ "$(stat -c '%a' "$DIR/state/tg.identity")" = 600 ] || fail "ключ установки доступен не только root"
[ -x /opt/sbin/d2kpanel ] || fail "C-панель не установлена"
[ ! -x /opt/sbin/d2k ] || fail "legacy Go-панель осталась установленной"
[ -s "$DIR/panel/index.html" ] && [ -s "$DIR/panel/panel.css" ] && [ -s "$DIR/panel/panel.js" ] && [ -s "$DIR/panel/gsap.js" ] && [ -s "$DIR/panel/fonts/onest.woff2" ] && [ -s "$DIR/panel/fonts/jbmono.woff2" ] || fail "не установлены статические ресурсы панели"
[ -x "$INIT" ]        || fail "init-скрипт не установлен"
[ -f "$DIR/run/d2k-panel.pid" ] || fail "C-панель не получила pid-файл"
PANEL_PID=$(cat "$DIR/run/d2k-panel.pid")
[ -d "/proc/$PANEL_PID" ] || fail "C-панель умерла после старта"
PANEL_OK=0
i=0
while [ "$i" -lt 30 ]; do
    if panel_curl -fsS http://127.0.0.1:8090/api/status -o /tmp/d2k-panel-status.json; then
        PANEL_OK=1
        break
    fi
    i=$((i + 1))
    sleep 0.1
done
[ "$PANEL_OK" = 1 ] || fail "C-панель не отдала /api/status"
grep -q '"snapshot"' /tmp/d2k-panel-status.json || fail "API не вернул status snapshot"
grep -q '"controls_enabled":true' /tmp/d2k-panel-status.json || fail "loopback-панель не включила управление сервисом"
grep -q '"telegram_enabled":true' /tmp/d2k-panel-status.json || fail "API считает включённый Telegram выключенным"
grep -q '"telegram_configured":true' /tmp/d2k-panel-status.json || fail "API не распознал регистрацию без общего секрета"
grep -q '"telegram_status":"connecting"' /tmp/d2k-panel-status.json || fail "закрытый локальный порт не должен давать статус connected"
if grep -q 'TG_RELAY_SECRET\|relay_secret\|telegram.*secret' /tmp/d2k-panel-status.json; then
    fail "API раскрыл поле или значение секрета ретранслятора"
fi
panel_curl -fsS http://127.0.0.1:8090/ | grep -q 'id="app"' || fail "C-панель не отдала главную страницу через LAN-привязку"
panel_curl -fsS http://127.0.0.1:8090/assets/gsap.js -o /tmp/d2k-gsap.js || fail "C-панель не отдала библиотеку анимаций"
panel_curl -fsS http://127.0.0.1:8090/assets/onest.woff2 -o /tmp/d2k-onest.woff2 || fail "C-панель не отдала шрифт"
panel_post stop | grep -q '"ok":true' || fail "локальная панель не остановила движок"
[ -d "/proc/$PANEL_PID" ] || fail "остановка движка погасила панель управления"
# Действие панели асинхронно: POST отвечает «запущено», S99d2k stop идёт фоном.
# Ждём его итога (до 30 с), а не опрашиваем статус в ту же миллисекунду.
for _ in $(seq 1 30); do
    panel_curl -fsS http://127.0.0.1:8090/api/status -o /tmp/d2k-panel-stopped.json || fail "панель недоступна после остановки движка"
    grep -q '"engine_running":false' /tmp/d2k-panel-stopped.json && break
    sleep 1
done
grep -q '"engine_running":false' /tmp/d2k-panel-stopped.json || fail "после остановки API продолжает считать движок работающим"
grep -q '"controller_running":false' /tmp/d2k-panel-stopped.json || fail "после остановки API продолжает считать контроллер работающим"
grep -Eq '"linked"[[:space:]]*:[[:space:]]*false' /tmp/d2k-panel-stopped.json || fail "API сохранил linked=true после остановки движка"
panel_post start | grep -q '"ok":true' || fail "локальная панель не запустила движок"
await "\"$INIT\" status | grep -q 'датапат: работает'" || fail "движок не восстановился из панели"
echo "== параллельное восстановление правил =="
REAPPLY_PIDS=
for i in 1 2 3 4; do
    sh "$INIT" reapply >"/tmp/d2k-reapply-$i.log" 2>&1 &
    REAPPLY_PIDS="$REAPPLY_PIDS $!"
done
REAPPLY_FAILED=0
for pid in $REAPPLY_PIDS; do wait "$pid" || REAPPLY_FAILED=1; done
[ "$REAPPLY_FAILED" = 0 ] || fail "параллельное восстановление завершилось ошибкой"
"$INIT" status | grep -q "правила: стоят" || fail "параллельное восстановление оставило firewall частичным"
panel_post telegram-disable | grep -q '"ok":true' || fail "панель не выключила Telegram"
sed -i '/^TG_RELAY_URL=/d; /^TG_ENROLL_PORT=/d' "$DIR/config"
if panel_post telegram-enable >/tmp/d2k-telegram-enable.json; then
    fail "панель включила Telegram без URL и relay secret"
fi
panel_curl -fsS http://127.0.0.1:8090/api/status -o /tmp/d2k-panel-telegram-unconfigured.json || fail "панель недоступна после отказа включить Telegram"
grep -q '"telegram_enabled":false' /tmp/d2k-panel-telegram-unconfigured.json || fail "не настроенный Telegram остался включён после отказа"
echo "== Telegram: локальный старт, redirect, отключение =="
# Указываем только loopback-релей без слушателя. C-клиент проверяется как
# процесс и firewall, но ни к VPS, ни к Telegram не подключается. Временный
# контейнерный watchdog выключен, чтобы лабораторная проверка не делала
# внешний health-probe.
printf '\nTG_RELAY_URL=wss://127.0.0.1:11443/ws\nTG_RELAY_SECRET=lab-only-not-a-real-secret\n' >> "$DIR/config"
chmod -x "$DIR/d2k-tg-watchdog.sh"
panel_post telegram-enable | grep -q '"ok":true' || fail "панель не включила настроенный Telegram-туннель"
await "[ -f \"$DIR/run/d2ktg.pid\" ]" || fail "d2ktg не создал pid-файл после включения"
TG_PID_NOW=$(cat "$DIR/run/d2ktg.pid")
[ -d "/proc/$TG_PID_NOW" ] || fail "d2ktg завершился после включения"
await "\"$INIT\" status | grep -q 'Telegram tunnel: работает'" || fail "служба не показывает активный Telegram-туннель"
ipset test d2k_tg_dc 149.154.167.51 >/dev/null 2>&1 || fail "ipset не содержит Telegram DC IPv4"
! ipset test d2k_tg_dc 203.0.113.1 >/dev/null 2>&1 || fail "ipset ошибочно включает посторонний IPv4"
iptables -t nat -C PREROUTING -p tcp --dport 443 -m set --match-set d2k_tg_dc dst -j REDIRECT --to-port 1443 || fail "нет Telegram PREROUTING redirect"
iptables -t nat -C OUTPUT -p tcp --dport 443 -m set --match-set d2k_tg_dc dst -j REDIRECT --to-port 1443 || fail "нет Telegram OUTPUT redirect"
if ipset test d2k_tg_dc6 2001:67c:4e8::1 >/dev/null 2>&1; then
    echo "IPv6 Telegram set and rules are available"
    ip6tables -C FORWARD -p tcp -m set --match-set d2k_tg_dc6 dst -j REJECT --reject-with tcp-reset || fail "нет IPv6 Telegram fast-reject в FORWARD"
    ip6tables -C OUTPUT -p tcp -m set --match-set d2k_tg_dc6 dst -j REJECT --reject-with tcp-reset || fail "нет IPv6 Telegram fast-reject в OUTPUT"
else
    echo "IPv6 Telegram rules unavailable in this container kernel (donor behavior is best-effort)"
fi
iptables -t nat -D PREROUTING -p tcp --dport 443 -m set --match-set d2k_tg_dc dst -j REDIRECT --to-port 1443
printf '#!/bin/sh\nexit 0\n' > /opt/sbin/curl
chmod +x /opt/sbin/curl
chmod +x "$DIR/d2k-tg-watchdog.sh"
if timeout 2 "$DIR/d2k-tg-watchdog.sh" >/tmp/d2k-tg-watchdog.log 2>&1; then
    fail "watchdog неожиданно завершился вместо продолжения цикла"
else
    WATCHDOG_RC=$?
    [ "$WATCHDOG_RC" = 124 ] || [ "$WATCHDOG_RC" = 143 ] || {
        cat /tmp/d2k-tg-watchdog.log >&2
        fail "локальный watchdog завершился с кодом $WATCHDOG_RC"
    }
fi
rm -f /opt/sbin/curl
iptables -t nat -C PREROUTING -p tcp --dport 443 -m set --match-set d2k_tg_dc dst -j REDIRECT --to-port 1443 || fail "watchdog не восстановил Telegram redirect"
panel_post telegram-disable | grep -q '"ok":true' || fail "панель не отключила Telegram-туннель"
[ ! -e "$DIR/run/d2ktg.pid" ] || fail "pid-файл d2ktg остался после отключения"
! iptables -t nat -C PREROUTING -p tcp --dport 443 -m set --match-set d2k_tg_dc dst -j REDIRECT --to-port 1443 2>/dev/null || fail "PREROUTING redirect остался после отключения"
! iptables -t nat -C OUTPUT -p tcp --dport 443 -m set --match-set d2k_tg_dc dst -j REDIRECT --to-port 1443 2>/dev/null || fail "OUTPUT redirect остался после отключения"
await "grep -q '^TG_ENABLED=0\$' \"$DIR/config\"" || fail "disable не сохранил TG_ENABLED=0"
panel_post reapply | grep -q '"ok":true' || fail "локальная панель не восстановила правила"
echo "установлено и работает"

echo "== 2. переход версии =="
# Метка человека в конфигурации: обновление обязано её сохранить.
echo "# метка человека" >> "$DIR/config"
PID_BEFORE=$(cat "$DIR/run/d2kd.pid")

# ДРУГИЕ БАЙТЫ, ТО ЖЕ ПОВЕДЕНИЕ: пересобираем с другой оптимизацией. Это
# настоящая смена версии с точки зрения установщика (файл другой), и при
# этом не требует выдумывать «версию 2» там, где её ещё нет.
make -s -C panel clean >/dev/null
make -s -C panel d2kpanel CFLAGS="-O1 -std=c11 -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L"
cp panel/d2kpanel "$REL/builds/d2kpanel-linux-$ARCH"
SHA_NEW=$(sha "$REL/builds/d2kpanel-linux-$ARCH")
[ "$SHA_NEW" != "$(sha /opt/sbin/d2kpanel)" ] || fail "новая сборка побайтно совпала со старой — переход версии не проверить"

D2K_LOCAL="$REL" sh scripts/install.sh 2>&1 | tee /tmp/install2.log
grep -q "готово" /tmp/install2.log || fail "переход версии не прошёл: $(tail -3 /tmp/install2.log)"
[ "$(sha /opt/sbin/d2kpanel)" = "$SHA_NEW" ] || fail "после обновления на месте осталась старая C-панель"
grep -q "^# метка человека" "$DIR/config" || fail "обновление затёрло конфигурацию человека"
PID_AFTER=$(cat "$DIR/run/d2kd.pid")
[ "$PID_AFTER" != "$PID_BEFORE" ] || fail "служба не перезапустилась — работает старый процесс"
"$INIT" status | grep -q "датапат: работает" || fail "после обновления датапат не работает"
echo "версия сменилась, конфигурация сохранена, служба перезапущена"

echo "== 3. неудачное обновление не трогает работающую =="
SHA_OK=$(sha /opt/sbin/d2kpanel)
PID_OK=$(cat "$DIR/run/d2kd.pid")
printf 'это не бинарник' > "$REL/builds/d2kpanel-linux-$ARCH"
if D2K_LOCAL="$REL" sh scripts/install.sh >/tmp/badinstall.log 2>&1; then
    fail "установщик принял испорченный бинарник"
fi
grep -q "не запускается" /tmp/badinstall.log || fail "отказ произошёл не там, где ждали: $(tail -1 /tmp/badinstall.log)"
[ "$(sha /opt/sbin/d2kpanel)" = "$SHA_OK" ] || fail "неудачное обновление подменило рабочую C-панель"
[ "$(cat "$DIR/run/d2kd.pid")" = "$PID_OK" ] || fail "неудачное обновление уронило работающую службу"
[ -d "/proc/$PID_OK" ] || fail "процесс службы умер после неудачного обновления"
"$INIT" status | grep -q "правила: стоят" || fail "неудачное обновление сняло правила"
echo "отказ до подмены: рабочая версия и правила не тронуты"

echo "== 4. остановка =="
"$INIT" stop >/dev/null
"$INIT" status | grep -q "датапат: не работает" || fail "после остановки датапат всё ещё работает"
[ -d "/proc/$PID_OK" ] && fail "процесс службы пережил остановку"
nfq6_direct

echo "== 5. возврат в прежний режим =="
# Экран обязан выглядеть ровно так, как до установки: не «похоже», а
# побайтно тот же список правил.
[ "$(rules)" = "$CLEAN_RULES" ] || {
    echo "--- было ---"; echo "$CLEAN_RULES"
    echo "--- стало ---"; rules
    fail "после остановки список правил не совпал с исходным"
}
# И обратно: служба поднимается снова тем же init-скриптом.
"$INIT" start >/dev/null
"$INIT" status | grep -q "датапат: работает" || fail "служба не поднялась после остановки"
echo "остановка и повторный запуск возвращают систему в оба состояния"

echo "== 6. удаление =="
# Simulate the explicitly D2K-owned rollback snapshots left by earlier router
# development installs. A full uninstall must remove these, not only runtime.
touch /opt/sbin/d2kc.before-d2k-lab /opt/sbin/d2kc.pre-goal-lab /opt/sbin/d2kc.pre-sched-lab
sh scripts/uninstall.sh >/dev/null
[ -e /opt/sbin/d2kd ] && fail "после удаления остался d2kd"
[ -e /opt/sbin/d2ktg ] && fail "после удаления остался C-туннель Telegram"
[ -e /opt/sbin/d2kc ] && fail "после удаления остался d2kc"
[ -e /opt/sbin/d2kpanel ] && fail "после удаления осталась C-панель"
[ -e "$DIR/panel" ] && fail "после удаления остались ресурсы панели"
[ -e "$DIR/d2k-tg-firewall.sh" ] && fail "после удаления остался firewall Telegram"
[ -e "$DIR/d2k-tg-watchdog.sh" ] && fail "после удаления остался сторож Telegram"
[ -e "$DIR/d2k-instagram-dns.sh" ] && fail "после удаления остался Instagram DNS manager"
[ -e "$DIR/files/meta-ranges.txt" ] && fail "после удаления остались диапазоны Meta"
[ "$(grep -c '^ip host instagram.com 157.240.9.174$' /tmp/d2k-ndmc-state || true)" = 0 ] || fail "деинсталлятор оставил D2K Instagram запись"
[ "$(grep -c '^ip host web.whatsapp.com 157.240.9.52$' /tmp/d2k-ndmc-state || true)" = 0 ] || fail "деинсталлятор оставил D2K WhatsApp запись"
[ "$(grep -c '^ip host www.instagram.com 157.240.9.175$' /tmp/d2k-ndmc-state)" = 1 ] || fail "деинсталлятор удалил существовавшую до D2K запись"
[ "$(grep -c '^ip host instagram.com 203.0.113.10$' /tmp/d2k-ndmc-state)" = 1 ] || fail "деинсталлятор удалил пользовательскую запись"
[ -e "$DIR/files/tg-roots.pem" ] && fail "после удаления остался CA bundle Telegram"
ipset list d2k_tg_dc >/dev/null 2>&1 && fail "после удаления остался IPv4 Telegram ipset"
ipset list d2k_tg_dc6 >/dev/null 2>&1 && fail "после удаления остался IPv6 Telegram ipset"
[ -e "$INIT" ]        && fail "после удаления остался init-скрипт"
[ -e /opt/sbin/d2kc.before-d2k-lab ] && fail "после удаления остался before-d2k backup"
[ -e /opt/sbin/d2kc.pre-goal-lab ] && fail "после удаления остался pre-goal backup"
[ -e /opt/sbin/d2kc.pre-sched-lab ] && fail "после удаления остался pre-sched backup"
[ "$(rules)" = "$CLEAN_RULES" ] || fail "после удаления список правил не совпал с исходным"
[ -e "$DIR" ] && fail "обычное удаление оставило каталог D2K"
echo "удалено без следов, включая каталог коробок"

echo
echo "УСТАНОВКА ПРОВЕРЕНА: шесть проверок этапа G пройдены на чистой системе"
DRIVER

docker run --rm --cap-add=NET_ADMIN --cap-add=NET_RAW \
    -v "$WORK:/w" -w /w gcc:14 sh /w/install-lab.sh
