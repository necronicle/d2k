# Ядро d2k. Здесь живёт оракул: то, что отличает «прошло» от «убито», по
# РОВНО тем байтам, что шлёт настоящий клиент — см. шапку include/d2k_meas.h
# про то, чего стоила эта дисциплина 06.09.2026.
#
# -Werror и кросс-проверка — той же причины, что в датапате (см. его
# Makefile): непереносимость обязана ловиться в день, когда её внесли, а не
# на роутере. Для ядра это особенно буквально: SO_MARK есть только на Linux,
# и без цели cross ветка с меткой ни разу не компилируется на машине
# разработки (на маке SO_MARK не определён) — опечатка там доехала бы до
# узла незамеченной.

CC      ?= cc
# -I../datapath/include — задача 4: link.c — первый модуль ядра, которому
# нужен заголовок ИЗ ДАТАПАТА. Протокол управляющего сокета не переизобретён
# здесь: единственный источник истины — datapath/include/d2k_ctl.h (кадры,
# события, команды) и d2k_ctlsrv.h (D2K_KEY_WIRE_LEN — ширина ключа на
# проводе; зашитая числом она уже ломалась в этом проекте, см. её комментарий).
# Задача 5 (шаг 0) добавила второго читателя — compose.c: d2k_props_ask теперь
# сам говорит с датапатом (d2k_link.h) и собирает канонический TLV своих
# пяти зондов, для чего ему нужен ТОЛЬКО D2K_POISON_BADSUM из публичного
# datapath/include/d2k_plan.h (коды записей TLV — приватное зеркало этого
# контракта у compose.c, см. её шапку, а не отсюда).
CFLAGS  ?= -std=c99 -O2 -Wall -Wextra -Werror -Iinclude -I../datapath/include
LDFLAGS ?=
# Стенд в тестах поднимает петлю-мишень в отдельном потоке; самому оракулу
# потоки не нужны, поэтому pthread — только у тестовой линковки.
TEST_LDFLAGS = $(LDFLAGS) -lpthread

# Кросс-компиляторы для проверки переносимости. Пути переопределяются извне.
ZIG        ?= /opt/homebrew/bin/zig
MIPSEL_CC  ?= mipsel-unknown-linux-gnu-gcc

SRC     = meas.c verdict.c crypto.c quic.c quicprobe.c props.c hello.c catalog.c match.c compose.c link.c
HDR     = include/d2k_meas.h include/d2k_verdict.h include/d2k_crypto.h include/d2k_quic.h \
          include/d2k_quicprobe.h include/d2k_hello.h include/d2k_catalog.h include/d2k_compose.h \
          include/d2k_compose_internal.h include/d2k_link.h
# Общий стенд тестов (петля-мишень в потоке, режимы 0-4). Один на test_meas и
# test_verdict — второй, отдельный стенд не заводится нигде (см. его шапку).
# test_crypto и test_quic стенда не используют вовсе: криптография и разбор
# QUIC не трогают сеть, вход — байтовые вектора RFC, а не петля-мишень.
# test_quicprobe и test_quic_arms заводят СВОЙ стенд каждый (датаграммный, не
# потоковый — см. их шапки) и в TESTHDR не входят: они не общие ни с кем и
# друг с другом (задача 6 подменяет ДРУГИЕ крючки, чем задача 5). test_hello
# тоже без стенда: вход — снятые байты и встроенные профили, не сеть.
# test_catalog тоже без стенда: вход — файл на диске (testdata/catalog-real.json,
# снимок с роутера) и синтетические JSON-обрывки, которые тест пишет сам, не сеть.
# test_match тоже без стенда: сравнивает уже разобранные d2k_cat_fp (свои,
# сконструированные inline, и настоящие — из того же testdata/catalog-real.json),
# сети и файловой записи не касается вовсе.
# test_compose про d2k_compose (задача 3) без стенда и без сети: чистая
# сборка текста плана из вектора свойств. Про d2k_props_ask (задача 5, шаг 0)
# — уже С сетью и С TESTHDR-стендом (петля-мишень нужна как реальная точка
# "одного обращения к цели", d2k_meas_once внутри d2k_props_ask), и ДОПОЛНИТЕЛЬНО
# против настоящего ctlprobe (datapath/ctlprobe.c) тем же приёмом, что и
# test_link — стенд и сеть здесь не заменяют друг друга: петля-мишень нужна,
# чтобы connect+send в d2k_meas_once не упёрся в ECONNREFUSED/тайм-аут,
# ctlprobe — чтобы дать событие обмена, по которому судит сам d2k_props_ask.
# test_link тоже без TESTHDR-стенда: его "стенд" — настоящий ctlprobe
# (datapath/ctlprobe.c), отдельным процессом, а не петля-мишень в потоке.
TESTHDR = test_stand.h

# test_d2kask — ЧЁРНЫЙ ЯЩИК (см. её шапку): не общий стенд test_stand.h сам
# по себе, а настоящий бинарник d2kask, запущенный подпроцессом, плюс
# настоящий ctlprobe (как и test_compose/test_link) — но stand ей тоже нужен
# (петля-мишень test_stand.h, mode 0), поэтому TESTHDR всё равно указан.
TESTS   = test_meas test_verdict test_crypto test_quic test_quicprobe test_quic_arms test_hello test_catalog test_match test_compose test_link test_d2kask

.PHONY: all check san gcc-warn cross clean d2kask-aarch64 test-meas test-verdict test-crypto test-quic test-quicprobe test-quic-arms test-hello test-catalog test-match test-compose test-link test-d2kask FORCE

all: meas.o verdict.o crypto.o quic.o quicprobe.o props.o hello.o catalog.o match.o compose.o link.o d2kask


meas.o: meas.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

verdict.o: verdict.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

crypto.o: crypto.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Разбор QUIC зовёт примитивы crypto.c (HKDF, AES-ECB, AES-GCM) — см. шапку
# quic.c: снятие защиты заголовка и расшифровка Initial стоят целиком на них.
quic.o: quic.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Вопросник зовёт d2k_quic_is_initial (quic.c) для согласия в вопросе "это
# вообще Initial" и примитивы crypto.c для серверного направления расшифровки
# (см. шапку quicprobe.c про то, почему это направление не в quic.c).
quicprobe.o: quicprobe.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Задача 6: подбор плеча зовёт d2k_quic_build_pool/d2k_quic_verify_response
# (quicprobe.c, экспортированы задачей 6 — см. их doc-комментарии в
# d2k_quicprobe.h про то, почему не дублируются) и d2k_mark_hook (d2k_meas.h,
# как есть — та же метка, что и у остальных отправителей дерева).
props.o: props.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# core/hello_profiles.inc — приветствия холодного старта, встроенные в
# бинарник (см. шапку hello.c про то, почему не путь к файлу). Собирается
# ИЗ profiles/*.hex МЕХАНИЧЕСКИ: вырезаются комментарии (строки на '#') и все
# пробелы/переводы строк, остаётся чистая шестнадцатеричная строка — эта
# цель не решает, что внутри профиля, только переносит текст в компилируемый
# вид. Сам .inc в git не идёт (core/* в .gitignore, .hex — намеренное
# исключение из него, .inc — нет): это вывод сборки, источник — только .hex.
hello_profiles.inc: profiles/modern.hex profiles/legacy.hex
	@rm -f $@
	@echo "/* Сгенерировано из profiles/ (*.hex) core/Makefile'ом. Правь исходники, не этот файл. */" > $@
	@for name in modern legacy; do \
		hex=$$(grep -v '^#' profiles/$$name.hex | tr -cd '0-9a-fA-F'); \
		len=$${#hex}; \
		if [ $$((len % 2)) -ne 0 ]; then \
			echo "profiles/$$name.hex: нечётное число шестнадцатеричных цифр" >&2; \
			exit 1; \
		fi; \
		printf 'static const char d2k_profile_%s_hex[] = "%s";\n' "$$name" "$$hex" >> $@; \
	done

# hello.c #include'ит hello_profiles.inc напрямую (см. его шапку) — без
# этого правила предыдущей сборки объектник просто не найдёт файл.
hello.o: hello.c $(HDR) hello_profiles.inc
	$(CC) $(CFLAGS) -c -o $@ $<

# Каталог (задача 1): свой разбор JSON поверх файла, который читает и
# Go-панель (см. шапку d2k_catalog.h). Ни от одного другого модуля ядра не
# зависит и ни один не зависит от него — планировщик (задача 5) свяжет его
# с остальными.
catalog.o: catalog.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Узнавание коробки (задача 2): сравнение d2k_cat_fp с допуском поверх типов
# catalog.c (задача 1) — см. шапку match.c и d2k_fp_same/d2k_catalog_match в
# d2k_catalog.h. От catalog.c зависит только по заголовку (типы), не по
# символам, поэтому .o собирается отдельно; связывает их только тест ниже.
match.o: match.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Свойства коробки и вывод плана для TCP (задача 3, дополнено задачей 5
# шаг 0/0б): d2k_compose зовёт d2k_hello_from_profile (hello.c, задача 1) для
# decoy-приветствия вопросов 2/4/5, выбирая MODERN/LEGACY по виду снятого
# приветствия ЦЕЛИ (см. build_decoy_hello в compose.c) — отсюда hello.o в
# связывании тестов ниже. d2k_props_ask (задача 5, шаг 0) — теперь настоящий
# оракул: говорит с датапатом через link.o (d2k_link_set_name/_next,
# d2k_ev_has_appdata) и делает одно обращение к цели через meas.o
# (d2k_meas_once, без собственных разрезов — сегментацию делает уже
# поставленный план) — отсюда meas.o и link.o в связывании тестов ниже. От
# verdict.c не зависит по символам вовсе.
compose.o: compose.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Связь с датапатом и порог успеха (задача 4). Читает заголовок из
# datapath/include (см. -I в CFLAGS выше); задача 5 (шаг 0) добавила второго
# такого читателя — compose.c (см. её комментарий выше). Сам link.c не
# вызывает ни одной функции оттуда — только #define D2K_KEY_WIRE_LEN из
# d2k_ctlsrv.h, поэтому лишней линковки с датапатом не образуется.
link.o: link.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# ctlprobe — настоящий C-сервер управляющего сокета (datapath/ctlprobe.c),
# против которого проверяется link.c (см. шапку test_link.c): смысл
# протокола проверяется чужим клиентом/сервером, а не сравнением исходников
# на глаз. FORCE, а не файловый штамп: свежесть решает Makefile датапата, а
# не мы — иначе `make -C core check`, вызванный САМ ПО СЕБЕ (например, гейт
# в Docker на чужом дереве), рисковал бы найти бинарник чужой архитектуры
# или не собранный вовсе и молча его использовать.
../datapath/ctlprobe: FORCE
	$(MAKE) -C ../datapath ctlprobe

# planlab — лаборатория плана (datapath/planlab.c): тот же исполнитель
# (d2k_plan_load/d2k_plan_apply), что и прод, печатает точные байты и порядок
# посылок по плану и сценарию. test_compose.c гоняет через него TLV, что
# собирает d2k_props_ask (задача 5, шаг 0, ревью 11.09) — обмен на настоящем
# ctlprobe не зависит от СОДЕРЖИМОГО плана, только planlab его показывает.
# FORCE по той же причине, что и ctlprobe выше.
../datapath/planlab: FORCE
	$(MAKE) -C ../datapath planlab
FORCE:

test_meas: test_meas.c meas.o $(HDR) $(TESTHDR)
	$(CC) $(CFLAGS) -o $@ test_meas.c meas.o $(TEST_LDFLAGS)

test_verdict: test_verdict.c meas.o verdict.o $(HDR) $(TESTHDR)
	$(CC) $(CFLAGS) -o $@ test_verdict.c meas.o verdict.o $(TEST_LDFLAGS)

test_crypto: test_crypto.c crypto.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_crypto.c crypto.o $(TEST_LDFLAGS)

test_quic: test_quic.c quic.o crypto.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_quic.c quic.o crypto.o $(TEST_LDFLAGS)

test_quicprobe: test_quicprobe.c quicprobe.o quic.o crypto.o meas.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_quicprobe.c quicprobe.o quic.o crypto.o meas.o $(TEST_LDFLAGS)

test_quic_arms: test_quic_arms.c props.o quicprobe.o quic.o crypto.o meas.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_quic_arms.c props.o quicprobe.o quic.o crypto.o meas.o $(TEST_LDFLAGS)

test_hello: test_hello.c hello.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_hello.c hello.o $(TEST_LDFLAGS)

test_catalog: test_catalog.c catalog.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_catalog.c catalog.o $(TEST_LDFLAGS)

# Проверка каталога d2k_catalog_load настоящим testdata/catalog-real.json
# (задача 2, шаг "поиск по каталогу находит и не находит") — вот откуда
# catalog.o в этом связывании, а не только match.o.
test_match: test_match.c match.o catalog.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_match.c match.o catalog.o $(TEST_LDFLAGS)

test_compose: test_compose.c compose.o hello.o meas.o link.o $(HDR) $(TESTHDR)
	$(CC) $(CFLAGS) -o $@ test_compose.c compose.o hello.o meas.o link.o $(TEST_LDFLAGS)
test_link: test_link.c link.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_link.c link.o $(TEST_LDFLAGS)

# d2kask (задача 5в) — командная утилита: спросить настоящую коробку с
# командной строки. Собирается ПРЯМО в свой бинарник, тем же приёмом, что
# ctlprobe/planlab в datapath/Makefile (main() есть только там, файл с ним
# не превращается во второй объектник для линковки с чужим main()). Связка
# compose.o hello.o meas.o link.o — та же, что у test_compose выше: d2kask
# зовёт ровно то же ядро (d2k_props_ask/d2k_compose из compose.o,
# d2k_hello_shape/d2k_hello_sni из hello.o), никакой собственной логики
# замера. Без pthread — сам d2kask однопоточный (arm+wait — обычный
# последовательный цикл по d2k_link_next, тем же приёмом, что
# wait_for_event в compose.c).
d2kask: d2kask.c compose.o hello.o meas.o link.o $(HDR)
	$(CC) $(CFLAGS) -o $@ d2kask.c compose.o hello.o meas.o link.o $(LDFLAGS)

# test_d2kask зовёт настоящий d2kask подпроцессом (execv "./d2kask" — см. её
# шапку) — hello.o нужен ей САМОЙ (build_hello_hex_file собирает настоящее
# приветствие профилем d2k_hello_from_profile, тем же приёмом, что
# build_trigger в test_compose.c), link.o — чтобы вычистить очередь событий
# настоящего управляющего сокета между сценариями (drain_all_events) и
# разобрать D2K_EV_* константы. pthread — ведущий поток, что параллельно
# диктует ctlprobe "hello"/"reply", пока d2kask синхронно блокируется внутри
# d2k_props_ask (тот же приём, что driver_run в test_compose.c), И поток,
# что читает трубы d2kask, не блокируя основной поток теста.
test_d2kask: test_d2kask.c hello.o link.o $(HDR) $(TESTHDR)
	$(CC) $(CFLAGS) -o $@ test_d2kask.c hello.o link.o $(TEST_LDFLAGS)

test-meas: test_meas
	./test_meas

test-verdict: test_verdict
	./test_verdict

test-crypto: test_crypto
	./test_crypto

test-quic: test_quic
	./test_quic

test-quicprobe: test_quicprobe
	./test_quicprobe

test-quic-arms: test_quic_arms
	./test_quic_arms

test-hello: test_hello
	./test_hello

test-catalog: test_catalog
	./test_catalog

test-match: test_match
	./test_match

# ../datapath/ctlprobe и ../datapath/planlab как зависимости запуска (не
# только сборки test_compose): d2k_props_ask (задача 5, шаг 0) проверяется
# против настоящего ctlprobe (обмен) тем же приёмом, что test_link, И против
# planlab (содержимое плана — байты и порядок посылок, ревью 11.09, круг
# правок 1) — см. TESTHDR-блок выше.
test-compose: test_compose ../datapath/ctlprobe ../datapath/planlab
	./test_compose

# ../datapath/ctlprobe как зависимость запуска (не только сборки test_link):
# гарантирует свежий бинарник нужной архитектуры каждый раз, когда test_link
# на самом деле ЗАПУСКАЕТСЯ, а не просто собирается (gcc-warn/cross его не
# запускают — см. их комментарии, там этой зависимости нет и не нужно).
test-link: test_link ../datapath/ctlprobe
	./test_link

# d2kask как зависимость запуска (не только сборки test_d2kask): test_d2kask
# запускает "./d2kask" подпроцессом по относительному пути (см. её шапку) —
# без этой зависимости make мог бы прогнать тест со СТАРЫМ бинарником, если
# d2kask.c поменялся, а сам тест не тронут. ../datapath/ctlprobe — тот же
# смысл, что у test-compose/test-link выше.
test-d2kask: test_d2kask d2kask ../datapath/ctlprobe
	./test_d2kask

check: all test-meas test-verdict test-crypto test-quic test-quicprobe test-quic-arms test-hello test-catalog test-match test-compose test-link test-d2kask

# Тот же набор под санитайзерами. «Не упало» и «не читало за буфером» — разные
# утверждения, а оракул держит в руках чужой сокет и чужой ответ на нём.
# -I../datapath/include — по той же причине, что и в CFLAGS выше: test_link.c
# и link.c читают протокол оттуда.
SANFLAGS = -std=c99 -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
           -fno-omit-frame-pointer -Wall -Wextra -Werror -Iinclude -I../datapath/include
# ../datapath/ctlprobe и ../datapath/planlab — test_link и test_compose здесь
# не просто собираются, а сразу ЗАПУСКАЮТСЯ (см. цикл ниже), значит нужны
# свежие бинарники заранее, как и у test-link/test-compose выше. d2kask —
# по той же причине для test_d2kask: она запускает "./d2kask" подпроцессом
# (см. её шапку), и цикл ниже собирает test_d2kask.c под санитайзером, но
# сам d2kask здесь пока обычный — эту половину закрывает отдельный блок
# ниже (D2KASK_BIN), иначе санитайзер проверял бы только ТЕСТ, а не саму
# утилиту, которую он должен ловить прежде всего.
san: hello_profiles.inc ../datapath/ctlprobe ../datapath/planlab d2kask
	@set -e; for t in $(TESTS); do \
		echo "== $$t =="; \
		$(CC) $(SANFLAGS) -o /tmp/d2k-core-san-$$t $$t.c \
			$$(echo "$(SRC)" | tr ' ' '\n' | grep -v '^$$') -lpthread ; \
		/tmp/d2k-core-san-$$t; \
	done
	@echo "== d2kask (санитайзер самой утилиты, не только теста) =="
	@$(CC) $(SANFLAGS) -o /tmp/d2k-core-san-d2kask d2kask.c compose.c hello.c meas.c link.c
	@D2KASK_BIN=/tmp/d2k-core-san-d2kask /tmp/d2k-core-san-test_d2kask
	@echo "санитайзеры: все проверки прошли"

# Тот же набор ЧУЖИМ компилятором. Локально собирает clang, CI — gcc, и они
# расходятся в предупреждениях (см. датапат). Компиляция без запуска: тут
# важны предупреждения, а исполняются те же тесты обычной целью check.
GCC ?= mipsel-unknown-linux-gnu-gcc
gcc-warn: hello_profiles.inc
	@for f in $(SRC) d2kask.c $(TESTS:=.c); do \
		$(GCC) $(CFLAGS) -c -o /tmp/d2k-core-gccwarn.o $$f || exit 1; \
	done
	@echo "чужой компилятор: предупреждений нет"

# Переносимость проверяется компиляцией под целевые арки. Обе цели — Linux, и
# только там определён SO_MARK: без этой цели ветка с меткой не компилируется
# нигде на машине разработки. test_meas линкуется ЦЕЛИКОМ под обеими libc по
# той же причине, что d2kd в датапате: раздельная компиляция объектников не
# доказывает, что именно эта комбинация (включая pthread на musl и glibc)
# слинкуется.
cross: hello_profiles.inc
	@for f in $(SRC) d2kask.c; do \
		echo "== $$f =="; \
		$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -c -o /tmp/d2k-core-a64.o $$f || exit 1; \
		$(MIPSEL_CC) $(CFLAGS) -c -o /tmp/d2k-core-mipsel.o $$f || exit 1; \
	done
	@echo "== test_meas целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_meas-a64 \
		test_meas.c meas.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_meas-mipsel test_meas.c meas.c -lpthread || exit 1
	@echo "== test_verdict целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_verdict-a64 \
		test_verdict.c meas.c verdict.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_verdict-mipsel \
		test_verdict.c meas.c verdict.c -lpthread || exit 1
	@echo "== test_crypto целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_crypto-a64 \
		test_crypto.c crypto.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_crypto-mipsel \
		test_crypto.c crypto.c -lpthread || exit 1
	@echo "== test_quic целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_quic-a64 \
		test_quic.c quic.c crypto.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_quic-mipsel \
		test_quic.c quic.c crypto.c -lpthread || exit 1
	@echo "== test_quicprobe целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_quicprobe-a64 \
		test_quicprobe.c quicprobe.c quic.c crypto.c meas.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_quicprobe-mipsel \
		test_quicprobe.c quicprobe.c quic.c crypto.c meas.c -lpthread || exit 1
	@echo "== test_quic_arms целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_quic_arms-a64 \
		test_quic_arms.c props.c quicprobe.c quic.c crypto.c meas.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_quic_arms-mipsel \
		test_quic_arms.c props.c quicprobe.c quic.c crypto.c meas.c -lpthread || exit 1
	@echo "== test_hello целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_hello-a64 \
		test_hello.c hello.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_hello-mipsel \
		test_hello.c hello.c -lpthread || exit 1
	@echo "== test_catalog целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_catalog-a64 \
		test_catalog.c catalog.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_catalog-mipsel \
		test_catalog.c catalog.c -lpthread || exit 1
	@echo "== test_match целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_match-a64 \
		test_match.c match.c catalog.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_match-mipsel \
		test_match.c match.c catalog.c -lpthread || exit 1
	@echo "== test_compose целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_compose-a64 \
		test_compose.c compose.c hello.c meas.c link.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_compose-mipsel \
		test_compose.c compose.c hello.c meas.c link.c -lpthread || exit 1
	@echo "== test_link целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_link-a64 \
		test_link.c link.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_link-mipsel \
		test_link.c link.c -lpthread || exit 1
	@echo "== d2kask целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-d2kask-a64 \
		d2kask.c compose.c hello.c meas.c link.c || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-d2kask-mipsel \
		d2kask.c compose.c hello.c meas.c link.c || exit 1
	@echo "== test_d2kask целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_d2kask-a64 \
		test_d2kask.c hello.c link.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_d2kask-mipsel \
		test_d2kask.c hello.c link.c -lpthread || exit 1
	@echo "переносимость: aarch64 и mipsel собираются, тесты линкуются"

# Утилита для целевого устройства (задача 5в) — тот же приём, что
# d2kd-aarch64 в datapath/Makefile: статическая musl, потому что на роутере
# нет ни нужной libc, ни желания зависеть от той, что там есть. d2kask не
# нуждается ни в чём из datapath/ (LINUXSRC там свой, NFQUEUE/raw сокеты) —
# только в четырёх файлах ядра, тех же, что у d2kask/test_compose выше.
BUILDDIR ?= ../builds
d2kask-aarch64:
	@mkdir -p $(BUILDDIR)
	$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -static \
		-o $(BUILDDIR)/d2kask-aarch64 d2kask.c compose.c hello.c meas.c link.c
	@ls -l $(BUILDDIR)/d2kask-aarch64

clean:
	rm -f *.o $(TESTS) d2kask hello_profiles.inc
