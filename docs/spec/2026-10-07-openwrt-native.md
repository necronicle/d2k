# OpenWrt без Entware — дизайн (07.10.2026)

## Зачем

Пользователь: D2K на OpenWrt работает, но приходится ставить Entware. Владелец:
нативная поддержка OpenWrt принципиальна. Сейчас «поддержка OpenWrt» — только
мост автозапуска procd и установка модулей ядра; всё остальное ждёт Entware.

## Что измерено

Индексы пакетов downloads.openwrt.org и чистые образы armsr/armv8 в QEMU
(`~/d2k-openwrt-lab/native/vm.sh`), 07.10.2026:

| | 24.10.8 | 25.12.5 (текущая стабильная) |
|---|---|---|
| менеджер пакетов | `/bin/opkg` | `/usr/bin/apk` |
| `iptables`/`ip6tables` в репозитории | есть (`iptables-nft`, `-zz-legacy`) | **нет** (aarch64, arm, mipsel, x86_64) |
| `ipset` | пакет | пакет |
| в образе | `nft` (fw4), `wget`=uclient-fetch, `ca-bundle`, BusyBox `ip`, `start-stop-daemon` | то же |
| нет в образе | `curl`, `openssl`, `iptables`, `ipset` | то же |
| BusyBox без | `od`, `stat`, `timeout` | то же |

Следствия:

1. На 25.12 правила D2K на iptables поставить нечем, кроме Entware. Нативная
   поддержка — это правила на nftables.
2. Установщик ставит модули только `/bin/opkg`; на 25.12 (apk) молча не ставит.
3. `architecture.sh` не знает имён архитектур OpenWrt (`aarch64_generic`,
   `mipsel_24kc`, `arm_cortex-a7_neon-vfpv4`, `i386_pentium4`): без Entware
   установка падает до проверки зависимостей.
4. Все нужные выражения проверены `nft -f` на 25.12.5: `queue num N bypass`,
   `ct direction`, `ct original|reply packets A-B`, `fib daddr type broadcast`,
   множества портов/адресов, `tcp flags & rst == rst`, `icmp type
   time-exceeded icmp code 0`, `masquerade`, `redirect to :P`, `reject with tcp
   reset`, множество с `flags timeout` и `add/get/delete element`. Таблица,
   не принадлежащая fw4, переживает `/etc/init.d/firewall restart` и `fw4 reload`.

## Решения

### Правила — nftables на OpenWrt, iptables на Keenetic

`FW_BACKEND` в S99d2k: `auto` (умолчание) → `nft`, если есть `/etc/openwrt_release`
и `nft`; иначе `iptables`. Конфигурация может задать явно. Keenetic не меняется.

Существующие установки OpenWrt с Entware при обновлении тоже переходят на nft:
один путь проще проверять, а legacy-iptables рядом с fw4 — смесь двух подсистем.
`fw_down` снимает свои правила **обоих** видов (iptables-цепочки D2K, если есть
iptables; таблицы nft, если есть nft) — миграция без остатков.

Таблица `inet d2k` — всё, что сейчас ставит `fw_family_up` для обоих семейств:

- `out` — `hook postrouting priority mangle` (как mangle POSTROUTING);
- `fwd`/`inp` — `hook forward|input priority mangle`, оба `jump in_rules`
  (как D2K_IN из FORWARD и INPUT);
- `nat_post` — `hook postrouting priority srcnat - 1`: MASQUERADE своих UDP по `MARK`
  (только IPv4, как сейчас);
- правила по порядку и смыслу совпадают с iptables-версией; `multiport` →
  множество портов (`a:b` → `a-b`), `connbytes A:B` → `ct <dir> packets A-B`
  (открытая граница `A:` → `A-18446744073709551615`), `addrtype BROADCAST` →
  `fib daddr type broadcast`.

Ставится одной транзакцией `nft -f` (сначала `delete table`, если есть): либо
весь набор, либо ничего. `fw_installed` проверяет таблицу, все базовые цепочки и
число правил с `queue` против сгенерированного файла `$RUN/fw.nft`.

IPv6 в nft отдельно не отключается: таблица `inet`. Метка `fw-ipv4-only` в nft не
ставится.

### Подавление RST зондами — `inet d2k_rst`

Отдельная таблица, чтобы пересборка `inet d2k` (heal/reapply) не снимала
подавление у идущего зонда. Множества `rst4`/`rst6` (`inet_service`, `flags
timeout`), цепочка `hook output priority filter - 1`:
`meta nfproto ipv4 tcp sport @rst4 tcp flags & rst == rst drop` (и ipv6).
Создаётся в `fw_up`, только если её нет; снимается `stop`/удалением.

`detect/raw.c` при `D2K_FW=nft` (S99d2k экспортирует его для d2kc): вставка
`nft add element inet d2k_rst rst4 { P timeout 300s }`, снятие `delete element`,
проверка `get element`. Таймаут — страховка после `kill -9`: элемент исчезает
сам (зонд живёт секунды, `timeout_ms` на шаг). Уборка `-S OUTPUT` в nft не нужна.

### Telegram — множества nft вместо ipset

`d2k-tg-firewall.sh` на nft: таблица `inet d2k_tg` — множества `tg4`/`tg6`
(`flags interval`), `nat` prerouting/output `priority dstnat - 1`
`ip daddr @tg4 tcp dport 443 redirect to :TG_PORT`, filter forward/output
`ip6 daddr @tg6 meta l4proto tcp reject with tcp reset`. Отдельная таблица:
туннель включается и выключается независимо от движка.

### Установщик

- Определение OpenWrt — прежний `/etc/openwrt_release`. Менеджер пакетов:
  `/usr/bin/apk` (25.12+), иначе `/bin/opkg`. Entware-`opkg` для этого не
  используется никогда.
- Архитектура на OpenWrt — от системного менеджера (`apk --print-arch`,
  `opkg print-architecture`), не от Entware. `architecture.sh` понимает имена
  OpenWrt: `aarch64_*`, `arm_*`, `mipsel_*`, `mips_*`, `mips64el_*`,
  `x86_64`, `i386_*`, `riscv64_*`. На Keenetic — как было.
- Зависимости OpenWrt ставятся системным менеджером **до** проверки программ:
  `curl ca-bundle openssl-util kmod-nft-queue kmod-nfnetlink-queue
  kmod-nf-conntrack-netlink` — только недостающие (сверка по списку
  установленных). Отказ — с точной командой для человека. iptables, ipset и
  `kmod-ipt-*` на OpenWrt не нужны.
- Проверка программ на OpenWrt: `curl ip nft start-stop-daemon openssl`; проверки
  `/proc/net/ip_tables_*` (NFQUEUE, connbytes) — только для iptables.
- Свободное место: до установки пакетов проверяется место под `/opt` и в корне;
  при нехватке — отказ до остановки прежней версии.
- Раскладка прежняя: `/opt/d2k`, `/opt/sbin`, `/opt/etc/init.d/S99d2k`. Без
  Entware `/opt` — обычный каталог корневой ФС; мост `/etc/init.d/d2k` видит
  `S99d2k` сразу. С Entware на USB — как сейчас, ждёт монтирования.
- Команда в README для OpenWrt — через `wget` (uclient-fetch есть в образе);
  `curl` ставит сам установщик.

### Удаление

Снимает `inet d2k`, `inet d2k_rst`, `inet d2k_tg` (если есть `nft`) и, как
сейчас, iptables-остатки. Чужие таблицы не трогает.

## Не делается

- DNS Instagram/WhatsApp через NDM и разгрузка PPE — функции KeeneticOS, на
  OpenWrt по-прежнему пропускаются.
- Журналы остаются в `/opt/d2k/log` (на флеше, если нет USB). Объём ограничен
  ротацией 2 МиБ/файл; перенос в RAM — отдельное решение по полю.
- Замена `openssl` в обновляторе своим кодом — нет: пакет есть в обеих ветках.

## Проверка

- Unit: карта архитектур OpenWrt; выбор apk/opkg и докачка только недостающих
  пакетов; генерация ruleset nft (двойник `nft`); `fw_installed`/`fw_down` для nft
  и миграция с iptables; RST через nft в `detect/test_raw.c`; Telegram на nft;
  удаление снимает таблицы.
- Лаборатория (QEMU, armsr/armv8): чистые 25.12.5 и 24.10.8 без Entware —
  установка командой из README, очередь привязана, правила стоят, трафик клиента
  LAN идёт через NFQUEUE (счётчики `nft list table inet d2k`), `firewall restart`
  не сносит правила, перезагрузка поднимает службу, обновление `D2K_LOCAL`,
  удаление без остатков. Затем прежний стенд с Entware — миграция iptables→nft.
- Полевой проверки на настоящем роутере OpenWrt нет; README говорит об этом прямо.
