# OpenWrt без Entware — лаборатория 07.10.2026

Дизайн: [docs/spec/2026-10-07-openwrt-native.md](../spec/2026-10-07-openwrt-native.md).
Ветка `feat/openwrt-native`. Полевой проверки на настоящем роутере OpenWrt нет.

## Повод

Пользователь: на OpenWrt D2K работает, но приходится ставить Entware.
Разбор: «нативная поддержка» из PR #10 и `a7a893f` — только мост автозапуска
procd и модули ядра; правила, `curl`, `openssl`, `ipset` и определение
архитектуры ждали Entware.

## Что измерено до правок

- Индексы downloads.openwrt.org: в 25.12.5 (текущая стабильная) нет пакетов
  `iptables-nft`, `iptables-zz-legacy`, `xtables-*` — ни для aarch64_generic, ни
  для mipsel_24kc, arm_cortex-a7_neon-vfpv4, x86_64. Модули `kmod-ipt-*`,
  `kmod-nft-queue`, `kmod-nf-conntrack-netlink` есть.
- Менеджер пакетов 25.12 — `apk` (`/usr/bin/apk`), 24.10 — `/bin/opkg`.
  Прежний установщик ставил модули только через `/bin/opkg`.
- `architecture.sh` отвергал `aarch64_generic`, `mipsel_24kc`,
  `arm_cortex-a7_neon-vfpv4`, `mips_24kc` (проходил только `x86_64`).
- Чистые образы armsr/armv8 24.10.8 и 25.12.5: есть `nft`, `wget`
  (uclient-fetch), BusyBox `ip` и `start-stop-daemon`, `ca-bundle`; нет `curl`,
  `openssl`, `iptables`, `ipset`; в BusyBox нет `od`, `stat`, `timeout` (у всех
  мест использования есть запасной путь). `DISTRIB_ARCH` есть в обеих
  версиях; `apk --print-arch` даёт лишь `aarch64`.
- `nft -f` на 25.12.5 принял все выражения правил D2K; ключевое слово `fwd`
  нельзя брать именем цепочки (поймано только настоящим nft). Таблица не fw4
  переживает `/etc/init.d/firewall restart` и `fw4 reload`. `ct original
  packets` сам включает `nf_conntrack_acct` (выставленный вручную 0 → 1 при
  загрузке таблицы), как `connbytes`; на чистом образе он и так 1. Поток без
  расширения учёта nft читает как 0 (`nft_ct.c`), поэтому окна начинаются с 1.
- Подавление RST через множество: `add element … timeout 300s` → `get` 0,
  `delete` 0, повторный `get` 1, повторный `delete` 1 — та же семантика, что у
  `iptables -I/-D/-C`.

## Лабораторный прогон

Стенды: QEMU `virt`, hvf, 2 CPU, 512 МБ, `~/d2k-openwrt-lab/native/vm.sh`
(25 → ssh 2225, 24 → 2224); прежний стенд с Entware — `~/d2k-openwrt-lab/vm`
(2222). Дерево раздавалось с Mac по HTTP (`10.0.2.2:8765`), бинарники ARM64
собраны из ветки (`d2kd`/`d2kc`/`d2kpanel`), `d2ktg` — из `builds/`.

Команда — как в README, с `D2K_BASE` стенда:
`(f=$(mktemp) && wget -q -T 60 -O "$f" http://10.0.2.2:8765/scripts/install.sh && D2K_BASE=http://10.0.2.2:8765 sh "$f"; …)`

| Проверка | 25.12.5 чистая | 24.10.8 чистая | 24.10.8 + Entware (миграция) |
|---|---|---|---|
| архитектура | `aarch64 / aarch64_generic -> arm64` | то же | то же |
| пакеты | apk: `kmod-nft-queue kmod-nfnetlink-queue kmod-nf-conntrack-netlink curl openssl-util` | opkg: то же | opkg: только `kmod-nft-queue` |
| служба, панель, Telegram | работают; регистрация на relay подтверждена | то же | работают |
| таблицы | `inet d2k`, `d2k_rst`, `d2k_tg` рядом с `fw4` | то же | то же; iptables-правил D2K 29 → 0 |
| `firewall restart`, `fw4 reload` | правила стоят | правила стоят | — |
| перезагрузка | мост procd поднял службу | то же | то же |
| повторная установка | пакеты не ставятся, конфигурация сохранена | — | ключ Telegram и состояние сохранены |
| удаление | таблиц, процессов, моста, `/opt` нет | то же | — |

Трафик (25.12.5): клиент LAN в netns за `br-lan` (лабораторные `ip-full`,
`kmod-veth`) — `curl --resolve www.google.com:443:…` → `200`, счётчик
`id_sequence` очереди 2000 вырос; запросы самого роутера тоже идут через
очередь. `d2kc` получил `D2K_FW=nft`, заметил поздние RST у
`downloads.openwrt.org`, сделал объёмный замер (HTTP 200, тело полностью) и
перебор не запускал.

Место (ext4, без сжатия): корень 18 544 → 33 008 КиБ занято после установки
на 25.12.5 (D2K ~6,8 МБ в `/opt`, пакеты ~6,7 МБ). На squashfs+overlay
(jffs2/ubifs сжимают) будет меньше; не мерилось.

`df -P /opt/d2k` в BusyBox OpenWrt даёт точку монтирования `/` — по ней
обновлятор держит рабочие файлы в `/tmp/d2k-update`.

## Ревью 07.10 и flow offloading

Независимое ревью ветки нашло четыре дефекта, все исправлены с тестами:
окна `ct packets` с 0 (поток без учёта шёл бы в очередь целиком); проверка
места до установки пакетов на ту же ФС; `heal` Telegram под `set -e` терял
временный файл; общий элемент RST по одному порту на все процессы (ключ теперь
`sport . цель . dport`, проверено nft на 25.12.5).

Flow offloading fw4 (25.12.5, клиент LAN, HTTPS, счётчик очереди):

| | в очередь за запрос |
|---|---|
| offloading выключен | 17, 18, 17 |
| offloading включён, D2K без учёта | 4, 5 — ClientHello мимо |
| offloading включён владельцем, D2K работает | 17 — D2K выключил его на время работы |
| после остановки D2K | настройка снова 1, `flow add` в fw4 на месте |

## Проверки кода

- `sh scripts/test-architecture.sh`, `sh scripts/test-s99-nft.sh`,
  `sh scripts/test-tg-firewall-nft.sh`, `node scripts/test-install-openwrt.cjs`,
  `node scripts/test-update.cjs`, `sh scripts/test-readme-commands.sh`;
  прежние `test-s99-firewall-stub.sh`, `test-runtime-install.cjs`,
  `test-openwrt-init.cjs` — зелёные.
- `make -C detect check` (новый `test_rule_through_nft`).

## Не проверено

- Настоящий роутер OpenWrt (MIPS, ARM32, squashfs+jffs2/ubifs, малый флеш).
- QUIC/UDP за роутером на nft (MASQUERADE своих посылок): правило стоит,
  трафиком не проверялось — в образе нет клиента HTTP/3.
- Сырые зонды с подавлением RST через nft под нагрузкой: проверены
  unit-тестом и командами `nft` через `sh -c`, не живым поиском.
- Ночное автообновление из подписанного выпуска на OpenWrt (логика RAM —
  unit-тестом).
- OpenWrt 22.03/23.05 (fw4, opkg) — логика та же, что у 24.10, не запускалось.
