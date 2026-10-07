#!/bin/sh
# Полная проверка перед коммитом. Один вход, чтобы её нельзя было прогнать
# наполовину.
#
# Существует потому, что я однажды прогнал make через grep, код возврата
# пришёл от grep, провал сборки одного теста не был замечен, и сломанное
# дерево уехало в коммит. Здесь ничего не фильтруется и каждый шаг проверяется
# по коду возврата.
set -eu

# Отказ ЛЮБОГО шага валит весь скрипт (set -e), и это единственное, на что
# можно опираться. Цепочка вида `sh check.sh; git commit && git push` этот
# отказ не заметит: точка с запятой пропускает код возврата дальше. Звать
# только через && либо проверять $? явно.


echo "== датапат: сборка и тесты =="
make -C datapath clean
make -C datapath check
make -C datapath planlab ctlprobe

echo "== ядро: сборка и тесты =="
make -C core clean
make -C core check

echo "== датапат: чужой компилятор =="
# Локально всё собирает clang, а CI — gcc. Они расходятся: gcc ловит
# sign-compare там, где clang молчит. Пока этого шага не было, гейт горел
# зелёным при КАЖДОМ красном прогоне CI.
make -C datapath gcc-warn

echo "== ядро: чужой компилятор =="
# Тот же смысл, что и для датапата, и здесь ещё буквальнее: SO_MARK есть
# только на Linux, mipsel-gcc собирает под Linux — только эта проверка (и
# cross ниже) вообще компилирует ветку с меткой. На маке она не строится
# никогда, потому что SO_MARK на маке не определён.
make -C core gcc-warn

echo "== датапат: санитайзеры =="
make -C datapath san

echo "== ядро: санитайзеры =="
make -C core san

echo "== датапат: переносимость =="
make -C datapath cross

echo "== ядро: переносимость =="
make -C core cross


echo "== скрипты =="
find scripts spike -name '*.sh' -print0 | xargs -0 shellcheck -s sh
sh scripts/test-instagram-dns.sh
sh scripts/test-ppe-deoffload.sh
sh scripts/test-instagram-dns-scheduler.sh
sh scripts/test-s99-firewall-stub.sh
sh scripts/test-s99-nft.sh
sh scripts/test-tg-firewall-nft.sh
sh scripts/test-s99-running.sh
sh scripts/test-install-manifest.sh
node scripts/test-runtime-files.cjs
node scripts/test-log-maintenance.cjs
node scripts/test-log-maintenance-process.cjs
node scripts/test-update.cjs
node scripts/test-runtime-install.cjs
node scripts/test-install-openwrt.cjs
node scripts/test-openwrt-init.cjs
sh scripts/test-readme-commands.sh
sh scripts/test-architecture.sh

# files/S99d2k — самый рискованный скрипт задачи (ставит правила firewall на
# живом роутере), а глоб *.sh его не ловит: init-скрипты Keenetic по
# соглашению SysV/OpenWrt называются без расширения (S99<имя>), не *.sh.
# Ревью задачи 4 (круг 2) нашло, что он был вне охвата этого гейта вовсе —
# указан явно, а не через более широкий глоб по files/, потому что там сейчас
# ровно один файл и обобщать шаблон под гипотетические будущие не по чему.
shellcheck -s sh files/S99d2k
shellcheck -s sh files/d2k-openwrt-init
shellcheck -s sh files/d2k-instagram-dns.sh
shellcheck -s sh files/d2k-instagram-dns-scheduler.sh
shellcheck -s sh files/d2k-log-maintenance.sh
shellcheck -s sh files/d2k-ppe-deoffload.sh
shellcheck -s sh files/d2k-update.sh
shellcheck -s sh files/d2k-tg-firewall.sh

# Синтаксис files/S99d2k проверен строкой выше; ПОВЕДЕНИЕ его правил firewall
# (что для UDP есть обе стороны, что на них --queue-bypass, что RETURN по
# метке без -p, что fw_down снимает всё, что поставил fw_up) — отдельным
# скриптом scripts/check_firewall.sh настоящим iptables в контейнере. Не
# вызывается отсюда безусловно: Docker — не зависимость остального гейта, а
# новая жёсткая зависимость всего check.sh явочным порядком не вводится.
# Запускать вручную при правке firewall-части S99d2k.

echo "ВСЁ ЗЕЛЕНО"
