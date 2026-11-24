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
.DEFAULT_GOAL := all
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
RELEASE_ID ?= dev
CFLAGS += -I../model/include
CFLAGS += -DD2K_RELEASE_ID='"$(RELEASE_ID)"'
LDFLAGS ?=
# Стенд в тестах поднимает петлю-мишень в отдельном потоке; самому оракулу
# потоки не нужны, поэтому pthread — только у тестовой линковки.
TEST_LDFLAGS = $(LDFLAGS) -lpthread

# Кросс-компиляторы для проверки переносимости. Пути переопределяются извне.
ZIG        ?= /opt/homebrew/bin/zig
MIPSEL_CC  ?= mipsel-unknown-linux-gnu-gcc
# Big-endian mips (ath79/ar71xx и прочие роутеры с 8/16 МиБ флеша) — своим gcc,
# если он в системе есть; на Ubuntu это пакет gcc-mips-linux-gnu. На машине
# разработки его обычно нет, поэтому он НЕОБЯЗАТЕЛЕН (цель сообщает и идёт
# дальше, как в detect/Makefile), а сам порядок байт ловится zig-целями ниже:
# они не зависят от установленных цепочек. Без хотя бы одной из них big-endian
# не компилировался нигде, кроме release.yml, и ловушки вроде «pipe() != 0»
# (a8a1f31, 12.10.2026) было видно только на выпуске.
MIPS_CC    ?= mips-unknown-linux-gnu-gcc
# Те же тройки, что у выпуска (см. scripts/build-target.sh): порядок байт и ABI
# проверяются ровно те, что уедут на роутер.
MIPS_BE_ZIG ?= -target mips-linux-musleabi -mcpu=mips32+soft_float
MIPS_LE_ZIG ?= -target mipsel-linux-musleabi -mcpu=mips32+soft_float

SRC     = ../synthesis/verification.c stun.c net4.c voice.c voice_discovery.c meas.c verdict.c crypto.c quicsnap.c quicsnap_reseal.c verify_quic_replay.c quicwire.c tls13core.c quicconn.c h3.c quic.c quicprobe.c quicarms.c ipfrag.c props.c hello.c catalog.c match.c compose.c measured.c link.c plantlv.c x25519.c tls13.c suite.c mlkem.c keccak.c tls12.c p256.c volume.c sched.c stunprobe.c stuntrial.c quichello.c verify.c
SRC += ../datapath/dns_family.c
dns_family.o: ../datapath/dns_family.c ../datapath/include/d2k_dns_family.h
	$(CC) $(CFLAGS) -c -o $@ $<
HDR     = include/d2k_meas.h include/d2k_verdict.h include/d2k_crypto.h include/d2k_quic.h \
          include/d2k_quicsnap.h include/d2k_quicprobe.h include/d2k_quic_arms.h include/d2k_ipfrag.h include/d2k_hello.h include/d2k_catalog.h include/d2k_compose.h \
          include/d2k_compose_internal.h include/d2k_link.h include/d2k_plantlv.h include/d2k_tls13.h include/d2k_volume.h include/d2k_sched.h \
          include/d2k_verify.h include/d2k_arm.h include/d2k_stun.h include/d2k_net4.h include/d2k_voice.h ../datapath/include/d2k_plan.h ../datapath/include/d2k_ctl.h ../datapath/include/d2k_ctlsrv.h
HDR += ../datapath/include/d2k_rawmeasure.h ../datapath/include/d2k_rawmeasure_wire.h
HDR += ../datapath/include/d2k_dns_family.h
HDR += ../datapath/include/d2k_http_response.h ../datapath/include/d2k_http_request_stream.h
HDR += ../synthesis/verification_status.h
HDR += include/d2k_boxprops.h include/d2k_shadow_queue.h include/d2k_doh_contract.h include/d2k_shadow_workers.h
HDR += include/d2k_stunprobe.h
HDR += include/d2k_stuntrial.h
HDR += ../runtime/d2k_runtime.h ../runtime/d2k_protocol.h include/d2k_p256.h include/d2k_udpruntime.h
# Заголовки датапата, которые объекты ядра включают через d2k_ctl.h/d2k_ctlsrv.h
# (список снят с `cc -MM` по всем SRC, не угадан): без них правка d2k_track.h
# или d2k_session.h оставляла link.o/sched.o со старой раскладкой структур.
HDR += ../datapath/include/d2k_addr.h ../datapath/include/d2k_ctq.h ../datapath/include/d2k_http80.h \
       ../datapath/include/d2k_journal.h ../datapath/include/d2k_plans.h ../datapath/include/d2k_raw.h \
       ../datapath/include/d2k_session.h ../datapath/include/d2k_track.h ../datapath/include/d2k_wire.h

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
HDR += include/d2k_ip6frag_send.h
HDR += profiles/rx_fake.h
HDR += include/d2k_tls12.h
HDR += include/d2k_resource.h
HDR += include/d2k_http_reply.h
HDR += include/d2k_domain.h include/d2k_groups.h
HDR += include/d2k_diagnostics.h ../runtime/d2k_diagnostics_files.h
diagnostics.o: diagnostics.c include/d2k_diagnostics.h
SRC += diagnostics.c domain.c groups.c udpplan.c udpruntime.c shadow_queue.c dns_upstreams.c
HDR += include/d2k_dns_upstreams.h sched_dns.inc
NEWCHAIN_SRC = ../model/fact.c ../model/box.c newchain.c ../model/store.c ../model/program.c ../model/context.c ../model/tls.c ../model/experiment.c ../model/codes.c
NEWCHAIN_OBJ = $(NEWCHAIN_SRC:.c=.o)
SRC += $(NEWCHAIN_SRC)
HDR += include/d2k_newchain.h ../model/include/d2km_store.h
# boxprops.c — И В ОБЩЕМ СПИСКЕ, И В ЯВНЫХ ПЕРЕЧИСЛЕНИЯХ НИЖЕ. Его зовёт sched.c,
# поэтому он нужен каждой цели, которая линкует планировщик. В SRC он затем, что
# test_catalog_sync линкует $(SRC:.c=.o) — без этого он не собирался, и нашлось
# это только линковкой в свежем дереве, где нет старых объектных файлов. В
# SCHED_TEST_OBJ, all и d2kc он тоже назван: это СВОИ списки, из SRC не
# производные, и попытка убрать его оттуда сломала линковку test_sched.
SRC += boxprops.c
domain.o: domain.c include/d2k_domain.h profiles/psl_index.h
groups.o: groups.c include/d2k_groups.h include/d2k_domain.h

.PHONY: test-domain test-groups
test-domain: test_domain
	./test_domain
test_domain: test_domain.c domain.c include/d2k_domain.h profiles/psl_index.h
	$(CC) $(CFLAGS) -o $@ test_domain.c domain.c $(LDFLAGS)
test-groups: test_groups
	./test_groups
test_groups: test_groups.c groups.c domain.c include/d2k_groups.h include/d2k_domain.h profiles/psl_index.h
	$(CC) $(CFLAGS) -o $@ test_groups.c groups.c domain.c $(LDFLAGS)
TESTHDR = test_stand.h

# test_d2kask — ЧЁРНЫЙ ЯЩИК (см. её шапку): не общий стенд test_stand.h сам
# по себе, а настоящий бинарник d2kask, запущенный подпроцессом, плюс
# настоящий ctlprobe (как и test_compose/test_link) — но stand ей тоже нужен
# (петля-мишень test_stand.h, mode 0), поэтому TESTHDR всё равно указан.
TESTS   = test_p256 test_stun test_voice test_meas test_verdict test_crypto test_h3 test_quicwire test_quic test_quichello test_quicprobe test_quic_fresh_repeats test_quic_arm_data test_quic_arms test_ipfrag test_quic_original_arms test_quic_run_order test_hello test_catalog test_match test_compose test_link test_d2kask test_plantlv test_sched test_verify test_measured
TESTS += test_boxprops
TESTS += test_stunprobe
TESTS += test_stuntrial
TESTS += test_ech test_sched_summary
TESTS += test_domain test_groups
TESTS += test_groups_catalog
TESTS += test_http_reply
HTTP_READ_SRC = verify.c dns_upstreams.c domain.c quicconn.c h3.c tls12.c p256.c compose.c measured.c hello.c meas.c link.c tls13.c suite.c mlkem.c keccak.c tls13core.c x25519.c
HTTP_READ_OBJ = dns_upstreams.o domain.o verify.o quicconn.o h3.o tls12.o p256.o compose.o measured.o hello.o meas.o link.o tls13.o suite.o mlkem.o keccak.o tls13core.o x25519.o
# Поиск обхода открытого HTTP (задача 51, шаг 4): исполнитель — настоящий
# датапатовский, планы кандидатов проверяются на нём.
TESTS += test_httpsearch
check: test-httpsearch
.PHONY: test-httpsearch
test_httpsearch: $(HTTP_READ_OBJ) test_httpsearch.c httpsearch.c httpup_logic.c plantlv.o quic.o quicwire.o crypto.o ../datapath/plan_parse.c ../datapath/plan_apply.c include/d2k_httpsearch.h
	$(CC) $(CFLAGS) -o $@ test_httpsearch.c httpsearch.c httpup_logic.c plantlv.o quic.o quicwire.o crypto.o ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c $(HTTP_READ_OBJ) $(TEST_LDFLAGS)
test-httpsearch: test_httpsearch
	./test_httpsearch

TESTS += test_http_compare_failure
check: test-http-compare-failure
.PHONY: test-http-compare-failure
httpsearch_compare_test.o: httpsearch.c include/d2k_httpsearch.h include/d2k_httpup.h $(HDR)
	$(CC) $(CFLAGS) -Dd2k_plan_text_to_tlv=d2k_test_compare_tlv -c httpsearch.c -o $@
test_http_compare_failure: $(HTTP_READ_OBJ) test_http_compare_failure.c test_httpsearch.c httpsearch_compare_test.o httpup_logic.c plantlv.o quic.o quicwire.o crypto.o ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c include/d2k_httpsearch.h include/d2k_httpup.h $(HDR)
	$(CC) $(CFLAGS) -o $@ test_http_compare_failure.c httpsearch_compare_test.o httpup_logic.c plantlv.o quic.o quicwire.o crypto.o ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c $(HTTP_READ_OBJ) $(TEST_LDFLAGS)
test-http-compare-failure: test_http_compare_failure
	./test_http_compare_failure

# Есть ли у имени HTTPS — для перевода вставки провайдера на https (задача 51).
TESTS += test_httpsprobe
check: test-httpsprobe
.PHONY: test-httpsprobe
test_httpsprobe: test_httpsprobe.c httpsprobe.c hello.o tls13.o suite.o mlkem.o keccak.o tls12.o p256.o tls13core.o x25519.o crypto.o include/d2k_httpsprobe.h
	$(CC) $(CFLAGS) -o $@ test_httpsprobe.c httpsprobe.c hello.o tls13.o suite.o mlkem.o keccak.o tls12.o p256.o tls13core.o x25519.o crypto.o $(TEST_LDFLAGS)
test-httpsprobe: test_httpsprobe
	./test_httpsprobe

# Ловушка MIPS: системный pipe там возвращает первый дескриптор (fd[0]) в v0, а
# не нуль, и обёртка musl отдаёт это значение как есть (см. шапку
# test_mips_pipe.c и d2k_sched_new в sched.c stunprobe.c). Проверка на ХОСТЕ: те же два
# конструктора с побудочной трубой компилируются с подменённой обёрткой — тот
# же приём, что у httpsearch_compare_test.o. Без этого ловушку видит только
# настоящий mips/mipsel-роутер, которого в проверках нет.
TESTS += test_mips_pipe
check: test-mips-pipe
.PHONY: test-mips-pipe
httpsearch_mips_pipe.o: httpsearch.c include/d2k_httpsearch.h include/d2k_httpup.h $(HDR)
	$(CC) $(CFLAGS) -Dpipe=d2k_test_mips_pipe -c httpsearch.c -o $@
httpsprobe_mips_pipe.o: httpsprobe.c include/d2k_httpsprobe.h $(HDR)
	$(CC) $(CFLAGS) -Dpipe=d2k_test_mips_pipe -c httpsprobe.c -o $@
test_mips_pipe: test_mips_pipe.c httpsearch_mips_pipe.o httpsprobe_mips_pipe.o httpup_logic.c plantlv.o quic.o quicwire.o crypto.o ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c $(HTTP_READ_OBJ) include/d2k_httpsearch.h include/d2k_httpsprobe.h
	$(CC) $(CFLAGS) -o $@ test_mips_pipe.c httpsearch_mips_pipe.o httpsprobe_mips_pipe.o httpup_logic.c plantlv.o quic.o quicwire.o crypto.o ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c $(HTTP_READ_OBJ) $(TEST_LDFLAGS)
test-mips-pipe: test_mips_pipe
	./test_mips_pipe

# Та же проверка под ОБА порядка байт mips — компиляцией и линковкой, без
# запуска: исполнять mips-бинарник на машине разработки нечем (qemu-user на
# macOS нет), а подменённая обёртка pipe живёт в тесте, не в коробке. Ловит то,
# что host-прогон поймать не может: непереносимость самого теста и двух его
# объектников, из-за которой проверка ловушки молча выпала бы из выпуска.
# Идёт и в check, и в cross — как check-release: порядок байт обязан
# проверяться обычной локальной проверкой, а не только на выпуске.
.PHONY: cross-mips-pipe
check cross: cross-mips-pipe
cross-mips-pipe: hello_profiles.inc
	@set -eu; pipe_dir=$$(mktemp -d "$${TMPDIR:-/tmp}/d2k-mips-pipe-cross.XXXXXX"); \
		trap 'rm -rf "$$pipe_dir"' EXIT HUP INT TERM; \
		for triple in "$(MIPS_BE_ZIG)" "$(MIPS_LE_ZIG)"; do \
			echo "== test_mips_pipe: zig $$triple =="; \
			$(ZIG) cc $$triple $(CFLAGS) -Dpipe=d2k_test_mips_pipe -c httpsearch.c -o "$$pipe_dir/httpsearch.o"; \
			$(ZIG) cc $$triple $(CFLAGS) -Dpipe=d2k_test_mips_pipe -c httpsprobe.c -o "$$pipe_dir/httpsprobe.o"; \
			$(ZIG) cc $$triple $(CFLAGS) -o "$$pipe_dir/test_mips_pipe" test_mips_pipe.c \
				"$$pipe_dir/httpsearch.o" "$$pipe_dir/httpsprobe.o" httpup_logic.c plantlv.c \
				quic.c quicwire.c crypto.c ../datapath/plan_parse.c ../datapath/plan_apply.c \
				../datapath/wire.c $(HTTP_READ_SRC) -lpthread; \
		done; \
		echo "test_mips_pipe: оба порядка байт mips линкуются"
TESTS += test_verify_http
check: test-verify-http
.PHONY: test-verify-http
test-verify-http: test_verify_http
	./test_verify_http
test_verify_http: test_verify_http.c verify.c quicconn.c tls12.o p256.o quicwire.o h3.o compose.o measured.o hello.o meas.o link.o tls13.o suite.o mlkem.o keccak.o tls13core.o x25519.o crypto.o dns_upstreams.o domain.o $(HDR)
	$(CC) $(CFLAGS) -o $@ $< tls12.o p256.o quicwire.o h3.o compose.o measured.o hello.o meas.o link.o tls13.o suite.o mlkem.o keccak.o tls13core.o x25519.o crypto.o dns_upstreams.o domain.o $(TEST_LDFLAGS)
check: test-http-reply
.PHONY: test-http-reply
test-http-reply: test_http_reply
	./test_http_reply
test_http_reply: test_http_reply.c include/d2k_http_reply.h
	$(CC) $(CFLAGS) -o $@ test_http_reply.c $(LDFLAGS)
check: test-domain test-groups
check: test-groups-catalog
.PHONY: test-groups-catalog
test-groups-catalog: test_groups_catalog
	./test_groups_catalog
test_groups_catalog: test_groups_catalog.c catalog.o groups.o domain.o $(HDR)
	$(CC) $(CFLAGS) -o $@ $< catalog.o groups.o domain.o $(LDFLAGS)

test_ech: test_ech.c verify.o tls12.o p256.o quicconn.o quicwire.o h3.o compose.o measured.o hello.o meas.o link.o tls13.o suite.o mlkem.o keccak.o tls13core.o x25519.o crypto.o dns_upstreams.o domain.o $(HDR)
	$(CC) $(CFLAGS) -o $@ $< verify.o tls12.o p256.o quicconn.o quicwire.o h3.o compose.o measured.o hello.o meas.o link.o tls13.o suite.o mlkem.o keccak.o tls13core.o x25519.o crypto.o dns_upstreams.o domain.o $(TEST_LDFLAGS)

.PHONY: test-ech
test-ech: test_ech
	./test_ech

check: test-ech d2kfetch

.PHONY: all check san gcc-warn cross clean d2kask-aarch64 d2kc-linux-arm64 d2kvoice-linux-arm64 test-meas test-verdict test-crypto test-quicwire test-h3 test-quic test-quichello test-quicprobe test-quic-fresh-repeats test-quic-arm-data test-quic-arms test-ipfrag test-quic-original-arms test-quic-run-order test-hello test-catalog test-match test-compose test-link test-d2kask test-plantlv test-sched test-rst-trigger test-voice-sched test-verify FORCE

all: boxprops.o meas.o verdict.o crypto.o quic.o quicprobe.o quicsnap.o quicsnap_reseal.o quicarms.o ipfrag.o net4.o props.o hello.o catalog.o groups.o domain.o match.o compose.o measured.o link.o plantlv.o x25519.o tls13.o suite.o mlkem.o keccak.o tls13core.o volume.o sched.o stunprobe.o stuntrial.o quichello.o verify.o tls12.o p256.o quicconn.o quicwire.o h3.o d2kask d2kc d2kvoice


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
quicarms.o: quicarms.c profiles/quic_arms.h $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

ipfrag.o: ipfrag.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

quicprobe.o: quicprobe.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Адресная арифметика IPv4 — общая вопроснику QUIC и голосовому пути
# (см. include/d2k_net4.h про то, почему список приватных диапазонов один).
net4.o: net4.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Голосовой путь (пункт 4): STUN-оракул, цель из живого разговора.
voice_discovery.o: voice_discovery.c include/d2k_voice_discovery.h $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

voice.o: voice.c include/d2k_voice_discovery.h $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

stun.o: stun.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Задача 6: подбор плеча зовёт d2k_quic_build_pool/d2k_quic_verify_response
# (quicprobe.c, экспортированы задачей 6 — см. их doc-комментарии в
# d2k_quicprobe.h про то, почему не дублируются) и d2k_mark_hook (d2k_meas.h,
# как есть — та же метка, что и у остальных отправителей дерева).
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

# core/tcp1620_whitelist.inc — 266 имён-кандидатов белого списка, встроенных
# в бинарник (compose.c #include'ит напрямую, как hello.c — hello_profiles.inc).
# Генерируется ИЗ profiles/tcp1620_whitelist.txt МЕХАНИЧЕСКИ: пустые строки и
# строки-комментарии на '#' выкидываются, CR срезается, остальное — по строке
# на имя. Эта цель не решает, что внутри списка, только переносит текст в
# компилируемый вид; источник правится только в .txt. Сам .inc в git не идёт
# (core/* в .gitignore, .txt — исключение, .inc — нет), это вывод сборки.
tcp1620_whitelist.inc: profiles/tcp1620_whitelist.txt
	@rm -f $@
	@echo "/* Сгенерировано из profiles/tcp1620_whitelist.txt core/Makefile'ом. Правь .txt, не этот файл. */" > $@
	@echo "static const char *const d2k_tcp1620_whitelist[] = {" >> $@
	@sed -e 's/\r$$//' -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$$/d' \
		-e 's/.*/    "&",/' profiles/tcp1620_whitelist.txt >> $@
	@echo "};" >> $@

compose.o: compose.c $(HDR) tcp1620_whitelist.inc

props.o: props.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# hello.c #include'ит hello_profiles.inc напрямую (см. его шапку) — без
# этого правила предыдущей сборки объектник просто не найдёт файл.
hello.o: hello.c $(HDR) hello_profiles.inc
	$(CC) $(CFLAGS) -c -o $@ $<

quichello.o: profiles/quic_probe.h

# Приветствие QUIC с другим именем, собранное из снятого: контроль для дерева
# вопросов по QUIC. Своего разбора не содержит — связывает quic.o (достать
# открытый ClientHello), hello.o (подставить имя) и quicwire.o (собрать
# пакет), см. d2k_quichello.h.
quichello.o: quichello.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Каталог (задача 1): свой разбор JSON поверх файла, который читает и
# Go-панель (см. шапку d2k_catalog.h). Ни от одного другого модуля ядра не
# зависит и ни один не зависит от него — планировщик (задача 5) свяжет его
# с остальными.
boxprops.o: boxprops.c $(HDR)

catalog.o: catalog.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Планировщик (задача 5): развилка по транспорту. Зовёт дерево вердиктов
# (verdict.o), вопросник QUIC (quicprobe.o, props.o), каталог с узнаванием
# (catalog.o groups.o domain.o, match.o), сборку планов и смысл вопросов о свойствах (compose.o)
# и связь с датапатом (link.o). Сетевые оракулы уезжают в рабочие потоки —
# отсюда pthread и в боевой линковке, не только в тестовой.
# Текст плана в байты провода (задача 5): d2k_compose выдаёт текст, датапат
# принимает TLV. Без этого моста планировщик не мог поставить ни одного
# собранного плана — d2k_link_set_name отвергала текст как «не hex».
# X25519 (RFC 7748): обмен ключами для настоящей TLS-сессии, внутри которой
# проба качает объём. См. шапку x25519.c.
x25519.o: x25519.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Минимальный клиент TLS 1.3: нужен пробе на блокировку по объёму, потому что
# объём приходится качать ВНУТРИ настоящей сессии. Что он намеренно не делает —
# в шапке d2k_tls13.h.
tls13.o: tls13.c tls12.c tls13core.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Шифры 0x1302/0x1303 и ML-KEM-768 для рукопожатия на форме клиента.
suite.o: suite.c include/d2k_suite.h $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<
mlkem.o: mlkem.c include/d2k_mlkem.h include/d2k_keccak.h
	$(CC) $(CFLAGS) -c -o $@ $<
keccak.o: keccak.c include/d2k_keccak.h
	$(CC) $(CFLAGS) -c -o $@ $<

tls12.o: tls12.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# ECDH secp256r1 для зонда TLS 1.2 (поле 07.10.2026), см. d2k_p256.h.
p256.o: p256.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

tls13core.o: tls13core.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

quicconn.o: quicconn.c quicwire.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

h3.o: h3.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Проба на блокировку по объёму (перенос internal/volume): качает объём внутри
# настоящей TLS-сессии, отсюда зависимость от tls13.o suite.o mlkem.o keccak.o tls13core.o.
volume.o: volume.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# d2kfetch — обращение к цели как у браузера (см. шапку d2kfetch.c): форма и
# длина приветствия браузерные, обращение непомеченное, поэтому датапат
# применяет к нему тот же план. Нужен полю вместо curl, чьё короткое
# приветствие под браузерный план не подходит.
D2KFETCH_OBJ = dns_upstreams.o domain.o verify.o verify_quic_replay.o quicconn.o quicwire.o h3.o \
	compose.o measured.o hello.o meas.o link.o tls13.o suite.o mlkem.o keccak.o tls13core.o tls12.o \
	p256.o x25519.o crypto.o quic.o quicsnap.o quicsnap_reseal.o quicprobe.o \
	quicarms.o quichello.o volume.o ipfrag.o net4.o props.o

d2kfetch: d2kfetch.c $(D2KFETCH_OBJ) $(HDR)
	$(CC) $(CFLAGS) -o $@ $< $(D2KFETCH_OBJ) $(TEST_LDFLAGS)

# Same sources as the host tool, linked (not merely compiled) for the router.
.PHONY: fetch-release
fetch-release: hello_profiles.inc tcp1620_whitelist.inc
	@mkdir -p $(BUILDDIR)
	$(ZIG) cc -target $(TARGET) $(TARGET_FLAGS) $(CFLAGS) -static -Wl,-S \
		-o $(BUILDDIR)/d2kfetch-linux-$(ARCH) d2kfetch.c \
		$(sort $(D2KFETCH_OBJ:.o=.c) $(UDP_ENGINE_SRC)) -lpthread

.PHONY: test-field-report
check: test-field-report
test-field-report: d2kfetch
	python3 ../scripts/field19/test-router-round.py
	python3 ../scripts/field19/test-d2kfetch-cli.py

plantlv.o: plantlv.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Уровни доказательства (проверка без ложного успеха): зонд ведёт СВОЁ
# рукопожатие TLS 1.3 (tls13.o suite.o mlkem.o keccak.o tls13core.o) своим ключом и доводит дело до настоящего
# ответа приложения, а обращается к цели тем же непомеченным сокетом с
# открытым наружу дескриптором, что и опрос свойств — d2k_props_contact из
# compose.o (её же оговорки про метку и про FIN, см. d2k_compose_internal.h).
# Повтор снятого чужого приветствия завершить рукопожатие не может: секретов
# того клиента у нас нет, и наружу виден только чужой второй полёт.
verify.o: verify.c quicconn.c quicwire.c h3.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

../synthesis/verification.o: ../synthesis/verification.c ../synthesis/verification.h $(HDR)
	$(CC) $(CFLAGS) -c $< -o $@

sched.o: sched.c sched_dns.inc dns_question_wire.inc ../synthesis/verification.h $(HDR)
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
# d2k_ev_outer_appdata) и делает одно обращение к цели через meas.o
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

# hello.o — дерево вердиктов спрашивает ВИД снятого приветствия
# (d2k_hello_shape): clear на форме TLS 1.2 обязан нести оговорку «обратное
# направление не проверено» (§6 спеки, шапка reverse_note в verdict.c), а на
# форме 1.3 такой оговорки нет и быть не должно. Тот же вопрос и тем же
# разбором уже задаёт compose.o (выбор формы приманки) — второго разбора
# приветствия ради одной оговорки не заводится.
test_verdict: test_verdict.c meas.o verdict.o hello.o $(HDR) $(TESTHDR)
	$(CC) $(CFLAGS) -o $@ test_verdict.c meas.o verdict.o hello.o $(TEST_LDFLAGS)

test_crypto: test_crypto.c crypto.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_crypto.c crypto.o $(TEST_LDFLAGS)

test_h3: test_h3.c h3.o quicwire.o crypto.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_h3.c h3.o quicwire.o crypto.o $(TEST_LDFLAGS)

test_quicwire: test_quicwire.c quicwire.o crypto.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_quicwire.c quicwire.o crypto.o $(TEST_LDFLAGS)

test_quic: test_quic.c quic.o quicwire.o crypto.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_quic.c quic.o quicwire.o crypto.o $(TEST_LDFLAGS)

# Задача 66: пачка Initial-датаграмм клиента — приветствие Chrome с ML-KEM не
# помещается в одну датаграмму, и снимком обязан стать весь полёт.
test_quicsnap: test_quicsnap.c quicsnap.o quicsnap_reseal.o quic.o quicwire.o crypto.o tls13core.o x25519.o $(HDR) test_quic_pq.h
	$(CC) $(CFLAGS) -o $@ test_quicsnap.c quicsnap.o quicsnap_reseal.o quic.o quicwire.o crypto.o tls13core.o x25519.o $(TEST_LDFLAGS)

TESTS += test_quicsnap
.PHONY: test-quicsnap
check: test-quicsnap
test-quicsnap: test_quicsnap
	./test_quicsnap

# Задача 40: разрез ClientHello на кадры CRYPTO — одна функция ядра для
# вопроса замера и исполнителя датапата.
test_quic_split: test_quic_split.c quic.o quicwire.o crypto.o $(HDR) test_quic_vector.h
	$(CC) $(CFLAGS) -o $@ test_quic_split.c quic.o quicwire.o crypto.o $(TEST_LDFLAGS)

.PHONY: test-quic-split
test-quic-split: test_quic_split
	./test_quic_split

check: test-quic-split
TESTS += test_quic_split

test_quicprobe: test_quicprobe.c props.o quicprobe.o quicsnap.o quicsnap_reseal.o quicarms.o ipfrag.o net4.o quichello.o hello.o tls13core.o x25519.o quic.o quicwire.o crypto.o meas.o quicconn.o h3.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_quicprobe.c props.o quicprobe.o quicsnap.o quicsnap_reseal.o quicarms.o ipfrag.o net4.o quichello.o hello.o tls13core.o x25519.o quic.o quicwire.o crypto.o meas.o quicconn.o h3.o $(TEST_LDFLAGS)

test_quic_arms: ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c test_quic_arms.c props.o quicprobe.o quicsnap.o quicsnap_reseal.o quicarms.o ipfrag.o net4.o quichello.o tls13core.o x25519.o quic.o quicwire.o crypto.o meas.o compose.o measured.o hello.o plantlv.o link.o quicconn.o h3.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_quic_arms.c ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c props.o quicprobe.o quicsnap.o quicsnap_reseal.o quicarms.o ipfrag.o net4.o quichello.o tls13core.o x25519.o quic.o quicwire.o crypto.o meas.o compose.o measured.o hello.o plantlv.o link.o quicconn.o h3.o $(TEST_LDFLAGS)

test_p256: test_p256.c p256.o tls13core.o crypto.o x25519.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_p256.c p256.o tls13core.o crypto.o x25519.o $(TEST_LDFLAGS)
# test_p256 состоял в TESTS (san-loop, clean), но check его не запускал.
.PHONY: test-p256
check: test-p256
test-p256: test_p256
	./test_p256

test_tls12: test_tls12.c tls12.o suite.o p256.o tls13core.o crypto.o x25519.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_tls12.c tls12.o suite.o p256.o tls13core.o crypto.o x25519.o $(TEST_LDFLAGS)

.PHONY: test-tls12
test-tls12: test_tls12
	./test_tls12

test_hello: test_hello.c hello.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_hello.c hello.o $(TEST_LDFLAGS)

test_stun: test_stun.c stun.o tls13core.o crypto.o x25519.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_stun.c stun.o tls13core.o crypto.o x25519.o $(TEST_LDFLAGS)

# Голосовой замер с командной строки. Линкуется тем же voice.o voice_discovery.o, что и тест:
# второй реализации замера в утилите нет (см. её шапку).
d2kvoice: d2kvoice.c voice.o voice_discovery.o stun.o net4.o tls13core.o crypto.o x25519.o meas.o $(HDR)
	$(CC) $(CFLAGS) -o $@ d2kvoice.c voice.o voice_discovery.o stun.o net4.o tls13core.o crypto.o x25519.o meas.o $(TEST_LDFLAGS)

test_voice: test_voice.c voice.o voice_discovery.o stun.o net4.o tls13core.o crypto.o x25519.o meas.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_voice.c voice.o voice_discovery.o stun.o net4.o tls13core.o crypto.o x25519.o meas.o $(TEST_LDFLAGS)

test_quichello: test_quichello.c quichello.o quicsnap.o quicsnap_reseal.o quic.o quicwire.o hello.o tls13core.o crypto.o x25519.o quicconn.o meas.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_quichello.c quichello.o quicsnap.o quicsnap_reseal.o quic.o quicwire.o hello.o tls13core.o crypto.o x25519.o quicconn.o meas.o $(TEST_LDFLAGS)

test_catalog: test_catalog.c catalog.o groups.o domain.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_catalog.c catalog.o groups.o domain.o $(TEST_LDFLAGS)

# Проверка каталога d2k_catalog_load настоящим testdata/catalog-real.json
# (задача 2, шаг "поиск по каталогу находит и не находит") — вот откуда
# catalog.o groups.o domain.o в этом связывании, а не только match.o.
test_boxprops: test_boxprops.c boxprops.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_boxprops.c boxprops.o $(TEST_LDFLAGS)

test_match: test_match.c match.o catalog.o groups.o domain.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_match.c match.o catalog.o groups.o domain.o $(TEST_LDFLAGS)

test_compose: test_compose.c compose.o measured.o hello.o meas.o link.o $(HDR) $(TESTHDR)
	$(CC) $(CFLAGS) -o $@ test_compose.c compose.o measured.o hello.o meas.o link.o $(TEST_LDFLAGS)
test_link: test_link.c link.o quicsnap.o quic.o quicwire.o crypto.o $(HDR) test_quic_pq.h
	$(CC) $(CFLAGS) -o $@ test_link.c link.o quicsnap.o quic.o quicwire.o crypto.o $(TEST_LDFLAGS)

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
d2kask: d2kask.c compose.o measured.o hello.o meas.o link.o $(HDR)
	$(CC) $(CFLAGS) -o $@ d2kask.c compose.o measured.o hello.o meas.o link.o $(LDFLAGS)

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

# Раньше эти три собирались (санитайзером и чужим компилятором), но в check не
# входили: у них просто не было цели запуска. Байтовый слой QUIC и HTTP/3
# проверялись только под санитайзером — то есть в самом дорогом шаге гейта и
# ни в одном дешёвом.
test-quicwire: test_quicwire
	./test_quicwire

test-h3: test_h3
	./test_h3

test-stun: test_stun
	./test_stun

test-voice: test_voice
	./test_voice

test-quichello: test_quichello
	./test_quichello

test-quicprobe: test_quicprobe
	./test_quicprobe

test_quic_fresh_repeats: test_quic_fresh_repeats.c props.o quicarms.o quicprobe.o quicsnap.o quicsnap_reseal.o ipfrag.o net4.o quichello.o hello.o tls13core.o x25519.o quic.o quicwire.o crypto.o meas.o quicconn.o h3.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_quic_fresh_repeats.c props.o quicarms.o quicprobe.o quicsnap.o quicsnap_reseal.o ipfrag.o net4.o quichello.o hello.o tls13core.o x25519.o quic.o quicwire.o crypto.o meas.o quicconn.o h3.o $(TEST_LDFLAGS)

test-quic-fresh-repeats: test_quic_fresh_repeats
	./test_quic_fresh_repeats

# Задача 39: честный замер плеча QUIC — ответ только на наш Initial, данные
# после рукопожатия, свежая четвёрка. Свой стенд на 127.0.0.1.
test_quic_arm_data: test_quic_arm_data.c props.o quicarms.o quicprobe.o quicsnap.o quicsnap_reseal.o ipfrag.o net4.o quichello.o hello.o tls13core.o x25519.o quic.o quicwire.o crypto.o meas.o quicconn.o h3.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_quic_arm_data.c props.o quicarms.o quicprobe.o quicsnap.o quicsnap_reseal.o ipfrag.o net4.o quichello.o hello.o tls13core.o x25519.o quic.o quicwire.o crypto.o meas.o quicconn.o h3.o $(TEST_LDFLAGS)

test-quic-arm-data: test_quic_arm_data
	./test_quic_arm_data

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

# d2kc обязан останавливаться на чужой версии провода (точное совпадение,
# задача 19: v8 — SET_NAME_PROBE с trial ID). Запускает "./d2kc" подпроцессом.
check: test-d2kc-proto
.PHONY: test-d2kc-proto
test-d2kc-proto: test_d2kc_proto d2kc
	./test_d2kc_proto
test_d2kc_proto: test_d2kc_proto.c $(HDR)
	$(CC) $(CFLAGS) -o $@ test_d2kc_proto.c $(TEST_LDFLAGS)

check: all test-stun test-voice test-tls12 test-meas test-verdict test-crypto test-quicwire test-h3 test-quic test-quichello test-quicprobe test-quic-fresh-repeats test-quic-arm-data test-quic-arms test-ipfrag test-quic-original-arms test-quic-run-order test-hello test-catalog test-match test-compose test-link test-d2kask test-plantlv test-sched test-sched-modes test-verify test-volume test-httpup-logic test-measured

test_measured: test_measured.c compose.o measured.o plantlv.o hello.o meas.o link.o quic.o quicwire.o crypto.o $(HDR) ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/plan_internal.h ../datapath/wire.c ../datapath/include/d2k_session.h
	$(CC) $(CFLAGS) -o $@ test_measured.c compose.o measured.o plantlv.o hello.o meas.o link.o quic.o quicwire.o crypto.o ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c $(TEST_LDFLAGS)

test-measured: test_measured
	./test_measured

.PHONY: test-measured

# Тот же набор под санитайзерами. «Не упало» и «не читало за буфером» — разные
# утверждения, а оракул держит в руках чужой сокет и чужой ответ на нём.
# -I../datapath/include — по той же причине, что и в CFLAGS выше: test_link.c
# и link.c читают протокол оттуда.
# -Wno-format-truncation: при -O1 GCC на Linux иначе предупреждает об
# обрезке в каждом snprintf подписей для человека; эта сборка ловит ошибки
# времени выполнения, а обрезка snprintf безопасна по определению.
# Выпуск — тот же, что в CFLAGS: link.c сверяет приветствие датапата по
# D2K_RELEASE_ID (задание 02, 28.10.2026), и санитайзерная сборка обязана его знать.
SANFLAGS = -std=c99 -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all -DD2K_RELEASE_ID='"$(RELEASE_ID)"' \
           -fno-omit-frame-pointer -Wall -Wextra -Werror -Wno-format-truncation -Iinclude -I../datapath/include -I../model/include
# ../datapath/ctlprobe и ../datapath/planlab — test_link и test_compose здесь
# не просто собираются, а сразу ЗАПУСКАЮТСЯ (см. цикл ниже), значит нужны
# свежие бинарники заранее, как и у test-link/test-compose выше. d2kask —
# по той же причине для test_d2kask: она запускает "./d2kask" подпроцессом
# (см. её шапку), и цикл ниже собирает test_d2kask.c под санитайзером, но
# сам d2kask здесь пока обычный — эту половину закрывает отдельный блок
# ниже (D2KASK_BIN), иначе санитайзер проверял бы только ТЕСТ, а не саму
# утилиту, которую он должен ловить прежде всего.
san-measured: hello_profiles.inc
	$(CC) $(SANFLAGS) -o /tmp/d2k-core-san-test_measured test_measured.c compose.c measured.c plantlv.c hello.c meas.c link.c quic.c quicwire.c crypto.c ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c -lpthread
	/tmp/d2k-core-san-test_measured

# test_httpsearch, как и test_measured, берёт исполнитель плана датапата:
# общий цикл ниже его не слинкует.
san-httpsearch:
	$(CC) $(SANFLAGS) -o /tmp/d2k-core-san-test_httpsearch test_httpsearch.c httpsearch.c httpup_logic.c plantlv.c quic.c quicwire.c crypto.c ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c $(HTTP_READ_SRC) -lpthread
	/tmp/d2k-core-san-test_httpsearch

# test_volume_context подставляет свои заглушки verify/tls12 вместо
# настоящих и сам включает volume.c: собирается одним файлом, как обычно.
san-volume-context:
	$(CC) $(SANFLAGS) -o /tmp/d2k-core-san-test_volume_context test_volume_context.c -lpthread
	/tmp/d2k-core-san-test_volume_context

.PHONY: san-measured san-httpsearch san-volume-context

# Исходники вне SRC, которые нужны тестам общего цикла (HTTPS-зонд и логика
# вставки провайдера); без них цикл не линковал test_httpsprobe и соседей.
SAN_EXTRA_SRC = httpsprobe.c httpup_logic.c
# test_quicconn_fc гонит 1 МБ по UDP-петле без повторов: под ASan клиент
# читает медленнее, на Linux приёмный буфер петли (208 КБ) переполняется,
# датаграммы теряются, и ответ «не доходит». Это свойство стенда, а не кода;
# сам тест идёт в обычном check.
SAN_SKIP = test_quicconn_fc
SAN_SKIP += test_http_compare_failure
# test_mips_pipe нужна подмена pipe() ровно в двух объектниках: общий цикл
# слинковал бы настоящие httpsearch.c/httpsprobe.c, и ловушка MIPS не
# проверялась бы вовсе. Свой блок ниже.
SAN_SKIP += test_mips_pipe

.PHONY: san-mips-pipe
san: san-mips-pipe
san-mips-pipe:
	@set -eu; mips_dir=$$(mktemp -d "$${TMPDIR:-/tmp}/d2k-mips-pipe-san.XXXXXX"); \
		trap 'rm -rf "$$mips_dir"' EXIT HUP INT TERM; \
		$(CC) $(SANFLAGS) -Dpipe=d2k_test_mips_pipe -c httpsearch.c -o "$$mips_dir/httpsearch.o"; \
		$(CC) $(SANFLAGS) -Dpipe=d2k_test_mips_pipe -c httpsprobe.c -o "$$mips_dir/httpsprobe.o"; \
		$(CC) $(SANFLAGS) -o "$$mips_dir/test" test_mips_pipe.c "$$mips_dir/httpsearch.o" \
			"$$mips_dir/httpsprobe.o" httpup_logic.c plantlv.c quic.c quicwire.c crypto.c \
			../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c $(HTTP_READ_SRC) -lpthread; \
		"$$mips_dir/test"

.PHONY: san-http-compare-failure
san: san-http-compare-failure
san-http-compare-failure:
	@set -eu; compare_dir=$$(mktemp -d "$${TMPDIR:-/tmp}/d2k-http-compare-san.XXXXXX"); \
		trap 'rm -rf "$$compare_dir"' EXIT HUP INT TERM; \
		$(CC) $(SANFLAGS) -Dd2k_plan_text_to_tlv=d2k_test_compare_tlv -c httpsearch.c -o "$$compare_dir/httpsearch.o"; \
		$(CC) $(SANFLAGS) -o "$$compare_dir/test" test_http_compare_failure.c "$$compare_dir/httpsearch.o" httpup_logic.c plantlv.c quic.c quicwire.c crypto.c ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c $(HTTP_READ_SRC) -lpthread; \
		"$$compare_dir/test"

# Цикл тестов под санитайзером — отдельной целью, чтобы CI мог делить его на
# шарды по измеренному весу (scripts/ci-core-san-shard.sh): одним заходом он
# шёл 21,5 минуты из 22,4. SAN_TESTS по умолчанию — все тесты, поэтому
# локальный `make san` проверяет ровно то же, что и прежде.
#
# Проверка самой утилиты d2kask стоит ВНУТРИ цикла, сразу после test_d2kask:
# ей нужен собранный в цикле /tmp/d2k-core-san-test_d2kask, и в шарде без
# этого теста она бы падала. Прежде она шла после всего цикла.
SAN_TESTS ?= $(TESTS)
SAN_LOOP = $(filter-out test_probe_plan test_measured test_httpsearch test_volume_context $(SAN_SKIP),$(SAN_TESTS))
.PHONY: san-loop san-list
san-list:
	@echo $(filter-out test_probe_plan test_measured test_httpsearch test_volume_context $(SAN_SKIP),$(TESTS))
san-loop: hello_profiles.inc tcp1620_whitelist.inc ../datapath/ctlprobe ../datapath/planlab d2kask d2kshadow
	@set -e; for t in $(SAN_LOOP); do \
		echo "== $$t =="; \
		srcs=$$(echo "$(SRC) $(SAN_EXTRA_SRC)" | tr ' ' '\n' | grep -v '^$$'); \
		for inc in $$(grep -o '#include "[A-Za-z0-9_]*\.c"' $$t.c | sed 's/#include "//; s/"//'); do \
			srcs=$$(echo "$$srcs" | grep -vx "$$inc" || true); \
		done; \
		if [ "$$t" = test_shadow ]; then srcs="shadow.c shadow_queue.c domain.c $(D2KEXP_COMMON_SRC) ../model/sim.c"; fi; \
		if [ "$$t" = test_shadow_parallel ]; then srcs="shadow.c shadow_queue.c domain.c $(D2KEXP_COMMON_SRC) ../model/sim.c"; fi; \
		if [ "$$t" = test_netarm ]; then srcs="$(NETARM_SRC) tls13core.c tls12.c p256.c x25519.c crypto.c"; fi; \
		if [ "$$t" = test_exp_local ]; then srcs="$(filter-out exp_task.c netarm.c,$(D2KEXP_COMMON_SRC))"; fi; \
		if [ "$$t" = test_doh_contract ]; then srcs=""; fi; \
		if [ "$$t" = test_appget ]; then srcs="../model/check.c"; fi; \
		if [ "$$t" = test_d2kapplication ]; then srcs="../synthesis/verification.c ../synthesis/application_search.c ../synthesis/application_policy.c ../synthesis/application_late.c ../synthesis/token_content.c ../synthesis/lower.c ../synthesis/application_history.c plantlv.c"; fi; \
		if [ "$$t" = test_application_provider ]; then srcs="$$(printf '%s\n' $(SYNTH_SRC) diagnostics.c $(SCHED_TEST_SRC) $(DETECT_OBJ:.o=.c) $(UDP_ENGINE_SRC) $(D2KC_CT_SRC) provider_ips.c | sort -u | tr '\n' ' ')"; fi; \
		if [ "$$t" = test_provider_ips ]; then srcs="provider_ips.c"; fi; \
		if [ "$$t" = test_dns_capture ]; then srcs="dns_capture.c"; fi; \
		if [ "$$t" = test_shadow_daemon ]; then srcs="shadow_queue.c"; fi; \
		$(CC) $(SANFLAGS) -I../model/include -I../detect/include -o /tmp/d2k-core-san-$$t $$t.c $$srcs -lpthread ; \
		/tmp/d2k-core-san-$$t; \
		if [ "$$t" = test_d2kask ]; then \
			echo "== d2kask (санитайзер самой утилиты, не только теста) =="; \
			$(CC) $(SANFLAGS) -o /tmp/d2k-core-san-d2kask d2kask.c compose.c measured.c hello.c meas.c link.c; \
			D2KASK_BIN=/tmp/d2k-core-san-d2kask /tmp/d2k-core-san-test_d2kask; \
		fi; \
	done

san: hello_profiles.inc ../datapath/ctlprobe ../datapath/planlab d2kask san-measured san-httpsearch san-volume-context san-probe-plan san-loop
	@echo "санитайзеры: все проверки прошли"

# Тот же набор ЧУЖИМ компилятором. Локально собирает clang, CI — gcc, и они
# расходятся в предупреждениях (см. датапат). Компиляция без запуска: тут
# важны предупреждения, а исполняются те же тесты обычной целью check.
GCC ?= mipsel-unknown-linux-gnu-gcc
# -I../detect/include — как у настоящего правила test_probe_plan ниже: один
# тест ядра включает d2k_detect.h, и без этого пути чужой компилятор падает
# на нём, не дойдя до самих предупреждений.
gcc-warn: hello_profiles.inc tcp1620_whitelist.inc
	@for f in $(SRC) d2kask.c $(TESTS:=.c); do \
		$(GCC) $(CFLAGS) -I../detect/include -I../model/include -c -o /tmp/d2k-core-gccwarn.o $$f || exit 1; \
	done
	@echo "чужой компилятор: предупреждений нет"

# Переносимость проверяется компиляцией под целевые арки. Обе цели — Linux, и
# только там определён SO_MARK: без этой цели ветка с меткой не компилируется
# нигде на машине разработки. test_meas линкуется ЦЕЛИКОМ под обеими libc по
# той же причине, что d2kd в датапате: раздельная компиляция объектников не
# доказывает, что именно эта комбинация (включая pthread на musl и glibc)
# слинкуется.
cross: hello_profiles.inc tcp1620_whitelist.inc
	@for f in $(SRC) d2kask.c d2kvoice.c d2kfetch.c; do \
		echo "== $$f =="; \
		$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -c -o /tmp/d2k-core-a64.o $$f || exit 1; \
		$(ZIG) cc $(MIPS_BE_ZIG) $(CFLAGS) -c -o /tmp/d2k-core-mips.o $$f || exit 1; \
		$(MIPSEL_CC) $(CFLAGS) -c -o /tmp/d2k-core-mipsel.o $$f || exit 1; \
	done
	@echo "== test_meas целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_meas-a64 \
		test_meas.c meas.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_meas-mipsel test_meas.c meas.c -lpthread || exit 1
	@echo "== test_verdict целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_verdict-a64 \
		test_verdict.c meas.c verdict.c hello.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_verdict-mipsel \
		test_verdict.c meas.c verdict.c hello.c -lpthread || exit 1
	@echo "== test_crypto целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_crypto-a64 \
		test_crypto.c crypto.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_crypto-mipsel \
		test_crypto.c crypto.c -lpthread || exit 1
	@echo "== test_quic целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_quic-a64 \
		test_quic.c quic.c quicwire.c crypto.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_quic-mipsel \
		test_quic.c quic.c quicwire.c crypto.c -lpthread || exit 1
	@echo "== test_stun целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_stun-a64 \
		test_stun.c stun.c tls13core.c crypto.c x25519.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_stun-mipsel \
		test_stun.c stun.c tls13core.c crypto.c x25519.c -lpthread || exit 1
	@echo "== test_voice целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_voice-a64 \
		test_voice.c voice.c voice_discovery.c stun.c net4.c tls13core.c crypto.c x25519.c meas.c $(filter-out test_voice.c voice.c voice_discovery.c stun.c net4.c tls13core.c crypto.c x25519.c meas.c,$(UDP_ENGINE_SRC)) -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_voice-mipsel \
		test_voice.c voice.c voice_discovery.c stun.c net4.c tls13core.c crypto.c x25519.c meas.c $(filter-out test_voice.c voice.c voice_discovery.c stun.c net4.c tls13core.c crypto.c x25519.c meas.c,$(UDP_ENGINE_SRC)) -lpthread || exit 1
	@echo "== d2kvoice целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-d2kvoice-a64 \
		d2kvoice.c voice.c voice_discovery.c stun.c net4.c tls13core.c crypto.c x25519.c meas.c $(filter-out d2kvoice.c voice.c voice_discovery.c stun.c net4.c tls13core.c crypto.c x25519.c meas.c,$(UDP_ENGINE_SRC)) -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-d2kvoice-mipsel \
		d2kvoice.c voice.c voice_discovery.c stun.c net4.c tls13core.c crypto.c x25519.c meas.c $(filter-out d2kvoice.c voice.c voice_discovery.c stun.c net4.c tls13core.c crypto.c x25519.c meas.c,$(UDP_ENGINE_SRC)) -lpthread || exit 1
	@echo "== test_quicprobe целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_quicprobe-a64 \
		test_quicprobe.c props.c quicprobe.c quicsnap_reseal.c quicarms.c ipfrag.c net4.c quichello.c hello.c tls13core.c x25519.c quic.c quicwire.c crypto.c meas.c quicconn.c h3.c $(filter-out test_quicprobe.c props.c quicprobe.c quicsnap_reseal.c quicarms.c ipfrag.c net4.c quichello.c hello.c tls13core.c x25519.c quic.c quicwire.c crypto.c meas.c quicconn.c h3.c,$(UDP_ENGINE_SRC)) -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_quicprobe-mipsel \
		test_quicprobe.c props.c quicprobe.c quicsnap_reseal.c quicarms.c ipfrag.c net4.c quichello.c hello.c tls13core.c x25519.c quic.c quicwire.c crypto.c meas.c quicconn.c h3.c $(filter-out test_quicprobe.c props.c quicprobe.c quicsnap_reseal.c quicarms.c ipfrag.c net4.c quichello.c hello.c tls13core.c x25519.c quic.c quicwire.c crypto.c meas.c quicconn.c h3.c,$(UDP_ENGINE_SRC)) -lpthread || exit 1
	@echo "== original QUIC arm regressions целиком =="
	@set -e; for t in test_ipfrag test_quic_original_arms test_quic_run_order test_quic_fresh_repeats test_quic_arm_data test_quic_strategy test_quic_split; do \
		$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-$$t-a64 $$t.c $(SRC) $(filter-out $$t.c $(SRC) $$t.c $(SRC),$(UDP_ENGINE_SRC)) -lpthread; \
		$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-$$t-mipsel $$t.c $(SRC) $(filter-out $$t.c $(SRC) $$t.c $(SRC),$(UDP_ENGINE_SRC)) -lpthread; \
	done
	@echo "== test_quic_arms целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_quic_arms-a64 \
		test_quic_arms.c ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c props.c quicprobe.c quicsnap_reseal.c quicarms.c ipfrag.c net4.c quichello.c tls13core.c x25519.c quic.c quicwire.c crypto.c meas.c compose.c measured.c hello.c plantlv.c link.c quicconn.c h3.c $(filter-out test_quic_arms.c ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c props.c quicprobe.c quicsnap_reseal.c quicarms.c ipfrag.c net4.c quichello.c tls13core.c x25519.c quic.c quicwire.c crypto.c meas.c compose.c measured.c hello.c plantlv.c link.c quicconn.c h3.c,$(UDP_ENGINE_SRC)) -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_quic_arms-mipsel \
		test_quic_arms.c ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c props.c quicprobe.c quicsnap_reseal.c quicarms.c ipfrag.c net4.c quichello.c tls13core.c x25519.c quic.c quicwire.c crypto.c meas.c compose.c measured.c hello.c plantlv.c link.c quicconn.c h3.c $(filter-out test_quic_arms.c ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c props.c quicprobe.c quicsnap_reseal.c quicarms.c ipfrag.c net4.c quichello.c tls13core.c x25519.c quic.c quicwire.c crypto.c meas.c compose.c measured.c hello.c plantlv.c link.c quicconn.c h3.c,$(UDP_ENGINE_SRC)) -lpthread || exit 1
	@echo "== test_hello целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_hello-a64 \
		test_hello.c hello.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_hello-mipsel \
		test_hello.c hello.c -lpthread || exit 1
	@echo "== test_quichello целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_quichello-a64 \
		test_quichello.c quichello.c quic.c quicsnap.c quicsnap_reseal.c quicwire.c hello.c tls13core.c crypto.c x25519.c quicconn.c meas.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_quichello-mipsel \
		test_quichello.c quichello.c quic.c quicsnap.c quicsnap_reseal.c quicwire.c hello.c tls13core.c crypto.c x25519.c quicconn.c meas.c -lpthread || exit 1
	@echo "== test_catalog целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_catalog-a64 \
		test_catalog.c catalog.c groups.c domain.c plantlv.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_catalog-mipsel \
		test_catalog.c catalog.c groups.c domain.c plantlv.c -lpthread || exit 1
	@echo "== test_match целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_match-a64 \
		test_match.c match.c catalog.c plantlv.c groups.c domain.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_match-mipsel \
		test_match.c match.c catalog.c plantlv.c groups.c domain.c -lpthread || exit 1
	@echo "== test_compose целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_compose-a64 \
		test_compose.c compose.c measured.c hello.c meas.c link.c udpplan.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_compose-mipsel \
		test_compose.c compose.c measured.c hello.c meas.c link.c udpplan.c -lpthread || exit 1
	@echo "== test_link целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_link-a64 \
		test_link.c link.c quicsnap.c quic.c quicwire.c crypto.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_link-mipsel \
		test_link.c link.c quicsnap.c quic.c quicwire.c crypto.c -lpthread || exit 1
	@echo "== test_plantlv целиком =="
# Исполнитель плана нужен здесь с 23.10.2026: тест оси autottl грузит TLV
# настоящим d2k_plan_load и применяет его d2k_plan_apply, то есть проверяет
# «измерено == исполнено» на кросс-целях тоже. В родном check эти символы
# приходят из libd2k_udp.a через LDFLAGS, а здесь линковка идёт исходниками —
# значит источники датапата перечисляются явно, как у test_measured ниже.
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_plantlv-a64 \
		test_plantlv.c plantlv.c compose.c measured.c hello.c meas.c link.c udpplan.c \
		quic.c quicwire.c crypto.c \
		../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_plantlv-mipsel \
		test_plantlv.c plantlv.c compose.c measured.c hello.c meas.c link.c udpplan.c \
		quic.c quicwire.c crypto.c \
		../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c -lpthread || exit 1
	@echo "== test_sched целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_sched-a64 \
		test_sched.c boxprops.c sched.c shadow_queue.c $(NEWCHAIN_SRC) ../synthesis/verification.c stunprobe.c stuntrial.c quichello.c plantlv.c verdict.c meas.c crypto.c quic.c quicsnap.c quicsnap_reseal.c quicwire.c quicprobe.c quicarms.c ipfrag.c net4.c \
		props.c voice.c voice_discovery.c stun.c hello.c catalog.c groups.c domain.c match.c compose.c measured.c link.c volume.c tls13.c suite.c mlkem.c keccak.c tls12.c p256.c tls13core.c x25519.c \
		verify.c dns_upstreams.c verify_quic_replay.c quicconn.c h3.c $(filter-out test_sched.c sched.c stunprobe.c stuntrial.c quichello.c plantlv.c verdict.c meas.c crypto.c quic.c quicsnap.c quicsnap_reseal.c quicwire.c quicprobe.c quicarms.c ipfrag.c net4.c props.c voice.c voice_discovery.c stun.c hello.c catalog.c groups.c domain.c match.c compose.c measured.c link.c volume.c tls13.c suite.c mlkem.c keccak.c tls12.c p256.c tls13core.c x25519.c verify.c verify_quic_replay.c quicconn.c h3.c,$(UDP_ENGINE_SRC)) -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_sched-mipsel \
		test_sched.c boxprops.c sched.c shadow_queue.c $(NEWCHAIN_SRC) ../synthesis/verification.c stunprobe.c stuntrial.c quichello.c plantlv.c verdict.c meas.c crypto.c quic.c quicsnap.c quicsnap_reseal.c quicwire.c quicprobe.c quicarms.c ipfrag.c net4.c \
		props.c voice.c voice_discovery.c stun.c hello.c catalog.c groups.c domain.c match.c compose.c measured.c link.c volume.c tls13.c suite.c mlkem.c keccak.c tls12.c p256.c tls13core.c x25519.c \
		verify.c dns_upstreams.c verify_quic_replay.c quicconn.c h3.c $(filter-out test_sched.c sched.c stunprobe.c stuntrial.c quichello.c plantlv.c verdict.c meas.c crypto.c quic.c quicsnap.c quicsnap_reseal.c quicwire.c quicprobe.c quicarms.c ipfrag.c net4.c props.c voice.c voice_discovery.c stun.c hello.c catalog.c groups.c domain.c match.c compose.c measured.c link.c volume.c tls13.c suite.c mlkem.c keccak.c tls12.c p256.c tls13core.c x25519.c verify.c verify_quic_replay.c quicconn.c h3.c,$(UDP_ENGINE_SRC)) -lpthread || exit 1
	@echo "== d2kask целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-d2kask-a64 \
		d2kask.c compose.c measured.c hello.c meas.c link.c || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-d2kask-mipsel \
		d2kask.c compose.c measured.c hello.c meas.c link.c || exit 1
	@echo "== test_verify целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_verify-a64 \
		test_verify.c verify.c dns_upstreams.c domain.c quicconn.c quicwire.c h3.c compose.c measured.c hello.c meas.c link.c tls13.c suite.c mlkem.c keccak.c tls12.c p256.c tls13core.c x25519.c crypto.c \
		udpplan.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_verify-mipsel \
		test_verify.c verify.c dns_upstreams.c domain.c quicconn.c quicwire.c h3.c compose.c measured.c hello.c meas.c link.c tls13.c suite.c mlkem.c keccak.c tls12.c p256.c tls13core.c x25519.c crypto.c \
		udpplan.c -lpthread || exit 1
	@echo "== d2kc целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -I../detect/include -o /tmp/d2k-core-d2kc-a64 \
		d2kc.c $(SYNTH_SRC) diagnostics.c httpsprobe.c httpsearch.c httpup_logic.c sched.c shadow_queue.c $(NEWCHAIN_SRC) boxprops.c ../synthesis/verification.c stunprobe.c stuntrial.c quichello.c plantlv.c verdict.c meas.c crypto.c quic.c quicsnap.c quicsnap_reseal.c quicwire.c quicprobe.c quicarms.c ipfrag.c net4.c \
		props.c voice.c voice_discovery.c stun.c hello.c catalog.c groups.c domain.c match.c compose.c measured.c link.c volume.c tls13.c suite.c mlkem.c keccak.c tls12.c p256.c tls13core.c x25519.c \
		verify.c dns_upstreams.c verify_quic_replay.c quicconn.c h3.c $(DETECT_SRC) ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c $(D2KC_CT_SRC) $(filter-out d2kc.c $(SYNTH_SRC) diagnostics.c httpsprobe.c httpsearch.c httpup_logic.c sched.c stunprobe.c stuntrial.c quichello.c plantlv.c verdict.c meas.c crypto.c quic.c quicsnap.c quicsnap_reseal.c quicwire.c quicprobe.c quicarms.c ipfrag.c net4.c props.c voice.c voice_discovery.c stun.c hello.c catalog.c groups.c domain.c match.c compose.c measured.c link.c volume.c tls13.c suite.c mlkem.c keccak.c tls12.c p256.c tls13core.c x25519.c verify.c verify_quic_replay.c quicconn.c h3.c ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c,$(UDP_ENGINE_SRC)) -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -I../detect/include -o /tmp/d2k-core-d2kc-mipsel \
		d2kc.c $(SYNTH_SRC) diagnostics.c httpsprobe.c httpsearch.c httpup_logic.c sched.c shadow_queue.c $(NEWCHAIN_SRC) boxprops.c ../synthesis/verification.c stunprobe.c stuntrial.c quichello.c plantlv.c verdict.c meas.c crypto.c quic.c quicsnap.c quicsnap_reseal.c quicwire.c quicprobe.c quicarms.c ipfrag.c net4.c \
		props.c voice.c voice_discovery.c stun.c hello.c catalog.c groups.c domain.c match.c compose.c measured.c link.c volume.c tls13.c suite.c mlkem.c keccak.c tls12.c p256.c tls13core.c x25519.c \
		verify.c dns_upstreams.c verify_quic_replay.c quicconn.c h3.c $(DETECT_SRC) ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c $(D2KC_CT_SRC) $(filter-out d2kc.c $(SYNTH_SRC) diagnostics.c httpsprobe.c httpsearch.c httpup_logic.c sched.c stunprobe.c stuntrial.c quichello.c plantlv.c verdict.c meas.c crypto.c quic.c quicsnap.c quicsnap_reseal.c quicwire.c quicprobe.c quicarms.c ipfrag.c net4.c props.c voice.c voice_discovery.c stun.c hello.c catalog.c groups.c domain.c match.c compose.c measured.c link.c volume.c tls13.c suite.c mlkem.c keccak.c tls12.c p256.c tls13core.c x25519.c verify.c verify_quic_replay.c quicconn.c h3.c ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c,$(UDP_ENGINE_SRC)) -lpthread || exit 1
	@echo "== test_measured целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_measured-a64 \
		test_measured.c compose.c measured.c plantlv.c hello.c meas.c link.c quic.c quicwire.c crypto.c ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c udpplan.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_measured-mipsel \
		test_measured.c compose.c measured.c plantlv.c hello.c meas.c link.c quic.c quicwire.c crypto.c ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c udpplan.c -lpthread || exit 1
	@echo "== test_d2kask целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-core-test_d2kask-a64 \
		test_d2kask.c hello.c link.c -lpthread || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-core-test_d2kask-mipsel \
		test_d2kask.c hello.c link.c -lpthread || exit 1
	@# Big-endian mips НАСТОЯЩИМ gcc — отдельным блоком, а не в цикле выше:
	@# на машине разработки этой цепочки обычно нет, и «не нашлась» не должна
	@# ронять переносимость целиком (тот же приём, что в detect/Makefile).
	@# Порядок байт при этом всё равно проверен: zig-проход в цикле выше и
	@# линковка выпуска в check-release идут без всяких установленных gcc.
	@if command -v $(MIPS_CC) >/dev/null 2>&1; then \
	  echo "== big-endian mips: $(MIPS_CC) =="; \
	  for f in $(SRC) d2kask.c d2kvoice.c; do \
	    $(MIPS_CC) $(CFLAGS) -c -o /tmp/d2k-core-mips-gcc.o $$f || exit 1; \
	  done; \
	  rm -f /tmp/d2k-core-mips-gcc.o; \
	else \
	  echo "cross: $(MIPS_CC) не найден — big-endian mips проверен zig-проходом и check-release"; \
	fi
	@echo "переносимость: aarch64, mipsel и big-endian mips собираются, тесты линкуются"

# Утилита для целевого устройства (задача 5в) — тот же приём, что
# d2kd-linux-arm64 в datapath/Makefile: статическая musl, потому что на роутере
# нет ни нужной libc, ни желания зависеть от той, что там есть. d2kask не
# нуждается ни в чём из datapath/ (LINUXSRC там свой, NFQUEUE/raw сокеты) —
# только в четырёх файлах ядра, тех же, что у d2kask/test_compose выше.
BUILDDIR ?= ../builds
# hello.c #include'ит hello_profiles.inc, props.c — (см.
# hello.o/props.o выше) — кросс-сборка
# компилирует hello.c напрямую, минуя hello.o, и без этой зависимости падала
# на чистом дереве: "fatal error: 'hello_profiles.inc' file not found".
# Тот же приём, что d2kask-aarch64: статический бинарник под роутер.
#
# ИМЯ ФАЙЛА — то же, что у сборок Go (builds/d2k-linux-arm64): его ищет
# scripts/install.sh, и расхождение здесь означало бы «скачанного файла нет»
# на живом роутере.
# Исходники перенесённого измерителя перечислены здесь по именам, а не
# подтянуты его Makefile: кросс-сборка идёт ОДНОЙ командой в статический
# бинарник, и промежуточные объектники host-сборки сюда не годятся.
SYNTH_SRC = ../synthesis/application_search.c ../synthesis/application_policy.c ../synthesis/application_archive.c ../synthesis/raw_tape.c ../synthesis/application_model.c ../synthesis/application_trial.c ../synthesis/application_owner.c ../synthesis/raw_tls.c ../synthesis/tracking.c ../synthesis/state_question.c ../synthesis/path_work.c ../synthesis/path_run.c ../synthesis/experiment.c \
            ../synthesis/stream.c ../synthesis/lower.c ../synthesis/tls_decode.c \
            ../synthesis/tls_observe.c ../synthesis/continuous.c ../synthesis/alternatives.c \
            ../synthesis/evidence.c ../synthesis/distinguish.c ../synthesis/joint.c ../synthesis/search.c
SYNTH_SRC += ../synthesis/application_refine.c ../synthesis/prefix_refine.c
SYNTH_SRC += ../synthesis/application_late.c
SYNTH_SRC += ../synthesis/token_content.c
SYNTH_SRC += ../synthesis/application_history.c
SYNTH_OBJ = $(SYNTH_SRC:.c=.o)
$(SYNTH_OBJ): ../synthesis/%.o: ../synthesis/%.c $(wildcard ../synthesis/*.h) $(HDR)
	$(CC) $(CFLAGS) -I../detect/include -c $< -o $@

DETECT_SRC = ../detect/bridge.c ../detect/classify.c ../detect/poison.c \
             ../detect/props.c ../detect/raw.c ../detect/trigger.c ../detect/response.c ../detect/preflight.c

# Голосовой замер под роутер. Статикой и на musl — по той же причине, что
# d2kc: на коробке нет ни glibc, ни наших библиотек.
d2kvoice-linux-arm64:
	@mkdir -p $(BUILDDIR)
	$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -static \
		-o $(BUILDDIR)/d2kvoice-linux-arm64 d2kvoice.c voice.c voice_discovery.c stun.c net4.c \
		tls13core.c crypto.c x25519.c meas.c -lpthread /tmp/libd2k-udp-a64.a
	@ls -l $(BUILDDIR)/d2kvoice-linux-arm64

TARGET ?= aarch64-linux-musl
TARGET_FLAGS ?=
ARCH ?= arm64
D2KC_MAIN ?= d2kc.c
OPENSSL_CFLAGS ?= $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS ?= $(shell pkg-config --libs openssl 2>/dev/null || printf '%s' '-lssl -lcrypto')
ROUTER_OPENSSL ?= ../build/telegram/openssl-$(ARCH)
ROUTER_SSL_LIBDIR = $(patsubst %/,%,$(dir $(firstword $(wildcard $(ROUTER_OPENSSL)/lib/libssl.a $(ROUTER_OPENSSL)/lib64/libssl.a))))
DOH_TLS_SRC = trusted_tls/trusted_tls.c trusted_tls/trusted_dot.c trusted_tls/trusted_dot_tls.c dns_message.c \
              dns_exchange.c flow_io.c dns_plain.c dns_capture.c provider_ips.c
DOH_TLS_HDR = include/d2k_trusted_tls.h include/d2k_trusted_dot.h include/d2k_dns_message.h dns_question_wire.inc \
              include/d2k_dns_exchange.h include/d2k_flow_io.h include/d2k_dns_capture.h include/d2k_dns_plain.h include/d2k_provider_ips.h
D2KC_OUTPUT ?= d2kc
.PHONY: application-probe-release
application-probe-release: D2KC_MAIN=d2kapplication.c
application-probe-release: D2KC_OUTPUT=d2kapplication
application-probe-release: release
.PHONY: test-application-probe
test-application-probe: test_d2kapplication
	./test_d2kapplication
test_d2kapplication: test_d2kapplication.c ../synthesis/verification.c ../synthesis/application_search.c ../synthesis/application_search.h ../synthesis/application_policy.c ../synthesis/application_policy.h d2kapplication.c $(HDR) ../synthesis/application_archive.h ../synthesis/application_trial.h ../synthesis/path_work.h
	$(CC) $(CFLAGS) -I../detect/include -o $@ test_d2kapplication.c ../synthesis/verification.c ../synthesis/application_search.c ../synthesis/application_policy.c ../synthesis/application_late.c ../synthesis/token_content.c ../synthesis/lower.c ../synthesis/application_history.c plantlv.c $(TEST_LDFLAGS)
test_d2kapplication: ../synthesis/application_late.c ../synthesis/application_late.h plantlv.c ../synthesis/token_content.c ../synthesis/token_content.h
test_d2kapplication: ../synthesis/lower.c ../synthesis/lower.h
test_d2kapplication: ../synthesis/application_history.c ../synthesis/application_history.h
TESTS += test_d2kapplication
check: test-application-probe
.PHONY: release check-release
d2kc-linux-arm64: release
.PHONY: router-openssl
router-openssl:
	@if ! test -f "$(ROUTER_SSL_LIBDIR)/libssl.a" || ! test -f "$(ROUTER_SSL_LIBDIR)/libcrypto.a"; then \
		ARCH="$(ARCH)" ZIG="$(ZIG)" LIBS_ONLY=1 OPENSSL_PREFIX="$(abspath $(ROUTER_OPENSSL))" \
			sh ../scripts/build-openssl-tg.sh; \
	fi
release: fetch-release shadow-release hello_profiles.inc tcp1620_whitelist.inc router-openssl
	@mkdir -p $(BUILDDIR)
	$(ZIG) cc -target $(TARGET) $(TARGET_FLAGS) $(CFLAGS) -I../detect/include -I"$(ROUTER_OPENSSL)/include" -DD2K_TRUSTED_DOH -static -Wl,-S,--gc-sections \
		-o $(BUILDDIR)/$(D2KC_OUTPUT)-linux-$(ARCH) $(D2KC_MAIN) $(DOH_TLS_SRC) ../datapath/dns_family.c dns_upstreams.c boxprops.c $(SYNTH_SRC) diagnostics.c httpsprobe.c httpsearch.c httpup_logic.c sched.c shadow_queue.c $(NEWCHAIN_SRC) ../synthesis/verification.c stunprobe.c stuntrial.c quichello.c plantlv.c verdict.c meas.c \
		crypto.c quic.c quicsnap.c quicsnap_reseal.c quicwire.c quicprobe.c quicarms.c ipfrag.c net4.c props.c voice.c voice_discovery.c stun.c hello.c catalog.c groups.c domain.c match.c compose.c measured.c link.c \
		volume.c tls13.c suite.c mlkem.c keccak.c tls12.c p256.c tls13core.c x25519.c verify.c verify_quic_replay.c quicconn.c h3.c $(DETECT_SRC) ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c $(D2KC_CT_SRC) ../datapath/wire_udp.c udpplan.c udpruntime.c -L"$(ROUTER_SSL_LIBDIR)" -lssl -lcrypto -ldl -lpthread
	@ls -l $(BUILDDIR)/$(D2KC_OUTPUT)-linux-$(ARCH)

# Check the deployment recipe itself, not a separately maintained test link.
# A private output directory preserves existing (possibly uncommitted) builds.
#
# Big-endian mips линкуется ЗДЕСЬ, а не только в release.yml: это единственное
# место, где весь контроллер (вместе с sched.c stunprobe.c, httpsearch.c и httpsprobe.c —
# тремя носителями ловушки pipe) компилируется с обратным порядком байт в
# обычном `make check`. До 12.10.2026 big-endian не собирался ни одной локальной
# проверкой и ни одним заданием CI.
check cross: check-release
check-release:
	@set -eu; \
		release_check_dir=$$(mktemp -d "$${TMPDIR:-/tmp}/d2k-release-check.XXXXXX"); \
		trap 'rm -rf "$$release_check_dir"' EXIT HUP INT TERM; \
		$(MAKE) release BUILDDIR="$$release_check_dir" TARGET=aarch64-linux-musl TARGET_FLAGS= ARCH=arm64; \
		$(MAKE) release BUILDDIR="$$release_check_dir" TARGET=mipsel-linux-musleabi TARGET_FLAGS=-mcpu=mips32+soft_float ARCH=mipsel; \
		$(MAKE) release BUILDDIR="$$release_check_dir" TARGET=mips-linux-musleabi TARGET_FLAGS=-mcpu=mips32+soft_float ARCH=mips; \
		echo "release: arm64, mipsel and big-endian mips deployment binaries linked"

d2kask-aarch64: hello_profiles.inc
	@mkdir -p $(BUILDDIR)
	$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -static \
		-o $(BUILDDIR)/d2kask-aarch64 d2kask.c compose.c measured.c hello.c meas.c link.c
	@ls -l $(BUILDDIR)/d2kask-aarch64

test-plantlv: test_plantlv
	./test_plantlv

# ../datapath/planlab — не украшение: тест прогоняет переведённый план через
# НАСТОЯЩИЙ исполнитель датапата. Без этой зависимости цель проходила бы на
# чистом дереве только потому, что planlab случайно собрал кто-то раньше.
test_plantlv: test_plantlv.c plantlv.o compose.o measured.o hello.o meas.o link.o $(HDR) ../datapath/planlab
	$(CC) $(CFLAGS) -o $@ $< plantlv.o compose.o measured.o hello.o meas.o link.o $(TEST_LDFLAGS)

# SHA-3 и ML-KEM-768 (FIPS 202/203) для гибридной группы TLS X25519MLKEM768.
test_mlkem: test_mlkem.c keccak.c mlkem.c include/d2k_keccak.h include/d2k_mlkem.h
	$(CC) $(CFLAGS) -o $@ test_mlkem.c keccak.c mlkem.c
TESTS += test_mlkem
check: test-mlkem
.PHONY: test-mlkem
test-mlkem: test_mlkem
	./test_mlkem

# Шифры TLS 1.3 0x1302 и 0x1303 (FIPS 180-4, SP 800-38D, RFC 8439).
test_suite: test_suite.c suite.c crypto.o include/d2k_suite.h
	$(CC) $(CFLAGS) -o $@ test_suite.c suite.c crypto.o
TESTS += test_suite
check: test-suite
.PHONY: test-suite
test-suite: test_suite
	./test_suite

# Прикладная проверка на сессии TLS: разбор :status HPACK (без сети).
test_appget: test_appget.c appget.c ../model/check.c include/d2k_appget.h
	$(CC) $(CFLAGS) -I../model/include -o $@ test_appget.c ../model/check.c
TESTS += test_appget
check: test-appget
.PHONY: test-appget
test-appget: test_appget
	./test_appget

# Исполнитель плеча опыта (d2km_net для роутера) на loopback-сокетах.
NETARM_SRC = netarm.c appget.c doh_contract.c ../model/check.c ../model/tls.c ../model/experiment.c ../model/context.c tls13.c suite.c mlkem.c keccak.c
test_netarm: test_netarm.c $(NETARM_SRC) tls13core.o tls12.o p256.o x25519.o crypto.o include/d2k_netarm.h
	$(CC) $(CFLAGS) -I../model/include -o $@ test_netarm.c $(NETARM_SRC) tls13core.o tls12.o p256.o x25519.o crypto.o -lpthread
TESTS += test_netarm
check: test-netarm
.PHONY: test-netarm
test-netarm: test_netarm
	./test_netarm

# d2kexp: новая цепочка для одной цели (ТЗ §4.1) — инструмент поля.
MODEL_LIB_SRC = $(filter-out ../model/test_% ../model/sim.c,$(wildcard ../model/*.c))
D2KEXP_COMMON_SRC = exp_task.c netarm.c appget.c doh_contract.c link.c hello.c plantlv.c tls13.c suite.c mlkem.c keccak.c tls13core.c tls12.c p256.c x25519.c crypto.c $(MODEL_LIB_SRC)
D2KEXP_SRC = d2kexp.c $(D2KEXP_COMMON_SRC)
D2KSHADOW_SRC = d2kshadow.c shadow.c shadow_queue.c domain.c $(D2KEXP_COMMON_SRC)
d2kexp: $(D2KEXP_SRC) $(HDR)
	$(CC) $(CFLAGS) -I../model/include -o $@ $(D2KEXP_SRC) -lpthread
d2kexp-linux-arm64: $(D2KEXP_SRC) $(HDR)
	$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -I../model/include -static -Wl,-S -o $@ $(D2KEXP_SRC) -lpthread

# Программа новой модели исполнима нынешним датапатом (model/ → plantlv → plan_load).
MODEL_SRC = ../model/context.c ../model/program.c ../model/tls.c
test_model_plan: test_model_plan.c plantlv.o $(MODEL_SRC) $(HDR) ../model/include/d2km_program.h ../model/include/d2km_tls.h
	$(CC) $(CFLAGS) -I../model/include -o $@ $< plantlv.o $(MODEL_SRC) $(TEST_LDFLAGS)
TESTS += test_model_plan
check: test-model-plan
.PHONY: test-model-plan
test-model-plan: test_model_plan
	./test_model_plan

test-sched: test_sched sched.o stunprobe.o stuntrial.o quichello.o plantlv.o verify.o tls12.o p256.o quicconn.o quicwire.o h3.o
	./test_sched

test-rst-trigger: test_sched sched.o stunprobe.o stuntrial.o quichello.o plantlv.o verify.o tls12.o p256.o quicconn.o quicwire.o h3.o
	./test_sched --rst-only

test-voice-sched: test_sched sched.o stunprobe.o stuntrial.o quichello.o plantlv.o verify.o tls12.o p256.o quicconn.o quicwire.o h3.o
	./test_sched --voice-only

# Все режимы test_sched входят в check (задача 44, раунд 1): режим --groups-only
# месяц стоял красным, потому что check его не запускал.
SCHED_MODES = --voice-only --rst-only --rx-volume-only --admission-only --question-only --shape-only --groups-only --retire-only --recheck-only --lifecycle-only --own-first-only --measured-only --ech-only --measure-only
.PHONY: test-sched-modes
test-sched-modes: test_sched sched.o stunprobe.o stuntrial.o quichello.o plantlv.o verify.o tls12.o p256.o quicconn.o quicwire.o h3.o
	@for m in $(SCHED_MODES); do echo "== test_sched $$m =="; ./test_sched $$m || exit 1; done

# verify.o tls12.o quicconn.o quicwire.o h3.o — с 12.09 планировщик испытывает кандидата САМ (d2k_sched_ver_hook,
# умолчание verify_default зовёт d2k_verify_probe). Тест зонд подменяет, но
# умолчание всё равно линкуется: крючок — точка подмены, а не условная сборка.
SCHED_TEST_OBJ = dns_family.o dns_upstreams.o shadow_queue.o $(NEWCHAIN_OBJ) boxprops.o ../synthesis/verification.o httpsprobe.o httpsearch.o httpup_logic.o sched.o stunprobe.o stuntrial.o verify_quic_replay.o quichello.o plantlv.o verdict.o meas.o crypto.o \
    quic.o quicwire.o quicprobe.o quicsnap.o quicsnap_reseal.o quicarms.o ipfrag.o net4.o props.o voice.o voice_discovery.o stun.o \
    hello.o catalog.o groups.o domain.o match.o compose.o measured.o link.o volume.o tls13.o suite.o mlkem.o keccak.o tls13core.o \
    x25519.o verify.o tls12.o p256.o quicconn.o h3.o
SCHED_TEST_SRC = $(filter-out dns_family.c,$(SCHED_TEST_OBJ:.o=.c)) ../datapath/dns_family.c
TESTS += test_sched_trial
TESTS += test_application_request
test_application_request: test_application_request.c sched.c test_task_slots.h $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(HDR)
	$(CC) $(CFLAGS) -o $@ $< $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(TEST_LDFLAGS)
check: test-application-request
.PHONY: test-application-request
test-application-request: test_application_request
	./test_application_request
TESTS += test_sched_raw_refine
check: test-sched-raw-refine
.PHONY: test-sched-raw-refine
test_sched_raw_refine: test_sched_raw_refine.c test_sched.c $(SCHED_TEST_OBJ) $(HDR)
	$(CC) $(CFLAGS) -o $@ $< $(SCHED_TEST_OBJ) $(TEST_LDFLAGS)
test-sched-raw-refine: test_sched_raw_refine
	./test_sched_raw_refine
check: test-sched-trial
.PHONY: test-sched-trial
test_sched_trial: test_sched_trial.c test_sched.c $(SCHED_TEST_OBJ) $(HDR)
	$(CC) $(CFLAGS) -o $@ $< $(SCHED_TEST_OBJ) $(TEST_LDFLAGS)
test-sched-trial: test_sched_trial
	./test_sched_trial

test_sched: test_sched.c $(SCHED_TEST_OBJ) $(HDR)
	$(CC) $(CFLAGS) -o $@ $< $(SCHED_TEST_OBJ) $(TEST_LDFLAGS)

test_sched_summary: test_sched_summary.c sched.c test_task_slots.h stunprobe.c $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(HDR)
	$(CC) $(CFLAGS) -o $@ $< $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(TEST_LDFLAGS)
.PHONY: test-sched-summary
test-sched-summary: test_sched_summary
	./test_sched_summary
check: test-sched-summary

# Стенд test_verify.c — СВОЙ (не общий test_stand.h): он единственный умеет
# довести рукопожатие TLS 1.3 до конца и умеет НЕ довести, а без этого уровни
# доказательства неразличимы (см. её шапку). Отсюда crypto.o и x25519.o в
# связывании — тем же расписанием ключей, что у клиента, стенд работает с
# другой стороны. compose.o тянет за собой hello.o/meas.o/link.o: зонд зовёт
# d2k_props_contact, а она живёт там же, где остальной опрос свойств.
test_verify: test_verify.c verify.o tls12.o p256.o quicconn.o quicwire.o h3.o compose.o measured.o hello.o meas.o link.o tls13.o suite.o mlkem.o keccak.o tls13core.o x25519.o crypto.o dns_upstreams.o domain.o $(HDR)
	$(CC) $(CFLAGS) -o $@ $< verify.o tls12.o p256.o quicconn.o quicwire.o h3.o compose.o measured.o hello.o meas.o link.o tls13.o suite.o mlkem.o keccak.o tls13core.o x25519.o crypto.o dns_upstreams.o domain.o $(TEST_LDFLAGS)

test-verify: test_verify
	./test_verify

test_quicconn6: test_quicconn6.c quicconn.o quicwire.o compose.o measured.o hello.o meas.o link.o tls13core.o x25519.o crypto.o $(HDR)
	$(CC) $(CFLAGS) -o $@ $< quicconn.o quicwire.o compose.o measured.o hello.o meas.o link.o tls13core.o x25519.o crypto.o $(TEST_LDFLAGS)

# Includes quicconn.c itself: the retransmit timer is connection state, and
# the test needs a ready 1-RTT connection without a live server.
test_quicconn_rtx: test_quicconn_rtx.c quicconn.c quicwire.o compose.o measured.o hello.o meas.o link.o tls13core.o x25519.o crypto.o $(HDR)
	$(CC) $(CFLAGS) -o $@ $< quicwire.o compose.o measured.o hello.o meas.o link.o tls13core.o x25519.o crypto.o $(TEST_LDFLAGS)

.PHONY: test-quicconn-rtx
check: test-quicconn-rtx
test-quicconn-rtx: test_quicconn_rtx
	./test_quicconn_rtx

test_quicconn_fc: test_quicconn_fc.c quicconn.c quicwire.o compose.o measured.o hello.o meas.o link.o tls13core.o x25519.o crypto.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_quicconn_fc.c quicwire.o compose.o measured.o hello.o meas.o link.o tls13core.o x25519.o crypto.o $(TEST_LDFLAGS)

.PHONY: test-quicconn-fc
test-quicconn-fc: test_quicconn_fc
	./test_quicconn_fc
check: test-quicconn-fc
TESTS += test_quicconn_fc

# Задача 29: предел потоков, объявленный СЕРВЕРОМ (транспортные параметры и
# MAX_STREAMS), обязан останавливать нас самих. Включает quicconn.c ради связи
# с ключами без живого сервера — как test_quicconn_fc.
test_quicconn_streams: test_quicconn_streams.c quicconn.c quicwire.o compose.o measured.o hello.o meas.o link.o tls13core.o x25519.o crypto.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_quicconn_streams.c quicwire.o compose.o measured.o hello.o meas.o link.o tls13core.o x25519.o crypto.o $(TEST_LDFLAGS)

.PHONY: test-quicconn-streams
test-quicconn-streams: test_quicconn_streams
	./test_quicconn_streams
check: test-quicconn-streams
TESTS += test_quicconn_streams

# Поле 04.10 (rua.gr): воспроизведение обрыва своим запросом мерится бюджетом
# коробки. Включает quicconn.c ради связи с ключами без живого сервера.
REPRO_OBJS = props.o quicarms.o quicprobe.o quicsnap.o quicsnap_reseal.o ipfrag.o net4.o quichello.o hello.o tls13core.o x25519.o quic.o quicwire.o crypto.o meas.o h3.o compose.o measured.o link.o
test_quic_repro_budget: test_quic_repro_budget.c quicconn.c $(REPRO_OBJS) $(HDR)
	$(CC) $(CFLAGS) -o $@ test_quic_repro_budget.c $(REPRO_OBJS) $(TEST_LDFLAGS)

.PHONY: test-quic-repro-budget
test-quic-repro-budget: test_quic_repro_budget
	./test_quic_repro_budget
check: test-quic-repro-budget
TESTS += test_quic_repro_budget

.PHONY: test-quicconn6
TESTS += test_quicconn_rtx
TESTS += test_quicconn6 test_volume test_volume_context test_httpup_logic
TESTS += test_catalog_sync

test_catalog_sync: test_catalog_sync.c $(SRC:.c=.o) $(HDR)
	$(CC) $(CFLAGS) -o $@ $< $(SRC:.c=.o) $(TEST_LDFLAGS)

.PHONY: test-catalog-sync
check: test-catalog-sync
test-catalog-sync: test_catalog_sync
	./test_catalog_sync

test_volume_context: test_volume_context.c volume.c $(HDR) include/d2k_tls12.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

check: test-volume-context

.PHONY: test-volume-context
test-volume-context: test_volume_context
	./test_volume_context

test_volume: test_volume.c volume.o verify.o tls13.o suite.o mlkem.o keccak.o tls13core.o tls12.o p256.o x25519.o crypto.o compose.o measured.o meas.o hello.o link.o quicconn.o quicwire.o h3.o dns_upstreams.o domain.o $(HDR)
	$(CC) $(CFLAGS) -o $@ $< volume.o verify.o tls13.o suite.o mlkem.o keccak.o tls13core.o tls12.o p256.o x25519.o crypto.o compose.o measured.o meas.o hello.o link.o quicconn.o quicwire.o h3.o dns_upstreams.o domain.o $(TEST_LDFLAGS)

test-volume: test_volume
	./test_volume

test_httpup_logic: test_httpup_logic.c httpup_logic.c include/d2k_httpup.h
	$(CC) $(CFLAGS) -o $@ test_httpup_logic.c httpup_logic.c $(TEST_LDFLAGS)

test-httpup-logic: test_httpup_logic
	./test_httpup_logic

# Прокси d2khttp убран (задача 51): разбор портала теперь вызывает датапат.
.PHONY: test-volume test-httpup-logic
check: test-quicconn6
test-quicconn6: test_quicconn6
	./test_quicconn6

# Requires an isolated Linux veth/marked-route fixture; not part of host check.
test_ip6frag_send_live: test_ip6frag_send_live.c ipfrag.c include/d2k_ip6frag_send.h include/d2k_ipfrag.h
	$(CC) $(CFLAGS) -o $@ test_ip6frag_send_live.c ipfrag.c $(TEST_LDFLAGS)

# d2kc — процесс контроллера на C: цикл событий поверх планировщика.
DETECT_OBJ = ../detect/bridge.o ../detect/classify.o ../detect/poison.o \
             ../detect/props.o ../detect/raw.o ../detect/trigger.o ../detect/response.o ../detect/preflight.o

# Перенесённый измеритель собирается своим Makefile: у него свои флаги и своя
# кросс-проверка, и второй рецепт сборки тех же файлов здесь означал бы два
# источника истины о том, как они собраны.
$(DETECT_OBJ): FORCE
	$(MAKE) -C ../detect $(notdir $@)

d2kc: d2kc.c $(DOH_TLS_SRC) $(DOH_TLS_HDR) dns_family.o dns_upstreams.o shadow_queue.o $(NEWCHAIN_OBJ) $(SYNTH_OBJ) boxprops.o ../synthesis/verification.o diagnostics.o httpsprobe.o httpsearch.o httpup_logic.o sched.o stunprobe.o stuntrial.o verify_quic_replay.o quichello.o plantlv.o verdict.o meas.o crypto.o quic.o quicwire.o quicprobe.o quicsnap.o quicsnap_reseal.o quicarms.o ipfrag.o net4.o props.o voice.o voice_discovery.o stun.o udpplan.o udpruntime.o \
      hello.o catalog.o groups.o domain.o match.o compose.o measured.o link.o volume.o tls13.o suite.o mlkem.o keccak.o tls13core.o x25519.o verify.o tls12.o p256.o quicconn.o h3.o \
      $(DETECT_OBJ) $(HDR) $(D2KC_CT_SRC) ../datapath/wire_udp.c
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -DD2K_TRUSTED_DOH -o $@ $< $(DOH_TLS_SRC) dns_family.o dns_upstreams.o shadow_queue.o $(NEWCHAIN_OBJ) $(SYNTH_OBJ) boxprops.o ../synthesis/verification.o diagnostics.o httpsprobe.o httpsearch.o httpup_logic.o sched.o stunprobe.o stuntrial.o verify_quic_replay.o quichello.o plantlv.o verdict.o meas.o crypto.o quic.o quicwire.o quicprobe.o quicsnap.o quicsnap_reseal.o quicarms.o ipfrag.o net4.o props.o \
		voice.o voice_discovery.o stun.o udpplan.o udpruntime.o hello.o catalog.o groups.o domain.o match.o compose.o measured.o link.o volume.o tls13.o suite.o mlkem.o keccak.o tls13core.o x25519.o verify.o tls12.o p256.o quicconn.o h3.o \
		$(DETECT_OBJ) ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c ../datapath/wire_udp.c \
		$(D2KC_CT_SRC) $(OPENSSL_LIBS) $(TEST_LDFLAGS)

clean:
	rm -f *.o $(TESTS) test_tls12 test_d2kc_proto d2kask d2kc d2kfetch hello_profiles.inc tcp1620_whitelist.inc libd2k_udp.a
	rm -rf .udp-engine

test_quic_original_arms: test_quic_original_arms.c quicarms.o $(HDR)
	$(CC) $(CFLAGS) -o $@ $< quicarms.o $(TEST_LDFLAGS)

# Задача 40: стратегия из ответов (остаточное разрешение, разрез CRYPTO)
# раньше перебора приманок — на подменённых ответах.
test_quic_strategy: test_quic_strategy.c quicarms.o $(HDR)
	$(CC) $(CFLAGS) -o $@ $< quicarms.o $(TEST_LDFLAGS)

.PHONY: test-quic-strategy
test-quic-strategy: test_quic_strategy
	./test_quic_strategy

check: test-quic-strategy
TESTS += test_quic_strategy

test_quic_run_order: test_quic_run_order.c $(SRC) $(HDR) hello_profiles.inc
	$(CC) $(CFLAGS) -o $@ $< $(SRC) $(TEST_LDFLAGS)

test_ipfrag: test_ipfrag.c ipfrag.o $(HDR)
	$(CC) $(CFLAGS) -o $@ $< ipfrag.o $(TEST_LDFLAGS)

test-ipfrag: test_ipfrag
	./test_ipfrag

test-quic-original-arms: test_quic_original_arms
	./test_quic_original_arms

test-quic-run-order: test_quic_run_order
	./test_quic_run_order


TESTS += test_voice_discovery
check: test-voice-discovery
.PHONY: test-voice-discovery
test_voice_discovery: test_voice_discovery.c voice.o net4.o voice_discovery.o stun.o meas.o crypto.o tls13core.o x25519.o include/d2k_voice_discovery.h
	$(CC) $(CFLAGS) -o $@ $< voice.o net4.o voice_discovery.o stun.o meas.o crypto.o tls13core.o x25519.o $(TEST_LDFLAGS)
test-voice-discovery: test_voice_discovery
	./test_voice_discovery

TESTS += test_catalog_durable
.PHONY: test-catalog-durable
check: test-catalog-durable
test-catalog-durable: test_catalog_durable
	./test_catalog_durable
test_catalog_durable: test_catalog_durable.c catalog.c groups.c domain.c $(HDR)
	$(CC) $(CFLAGS) -o $@ test_catalog_durable.c groups.c domain.c $(TEST_LDFLAGS)

# Property catalog is included by the test, not linked a second time.
TESTS += test_probe_plan
.PHONY: test-probe-plan
check: test-probe-plan
test-probe-plan: test_probe_plan
	./test_probe_plan
test_probe_plan: test_probe_plan.c ../detect/tests/legacy_sends.h $(DETECT_SRC) ../detect/include/d2k_detect.h compose.o measured.o plantlv.o hello.o meas.o link.o quic.o quicwire.o crypto.o $(HDR) ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/plan_internal.h
	$(CC) $(CFLAGS) -I../detect/include -o $@ test_probe_plan.c $(filter-out ../detect/props.c,$(DETECT_SRC)) compose.o measured.o plantlv.o hello.o meas.o link.o quic.o quicwire.o crypto.o ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c $(TEST_LDFLAGS)

.PHONY: san-probe-plan
san-probe-plan: hello_profiles.inc
	$(CC) $(SANFLAGS) -I../detect/include -o /tmp/d2k-core-san-test_probe_plan test_probe_plan.c $(filter-out ../detect/props.c,$(DETECT_SRC)) compose.c measured.c plantlv.c hello.c meas.c link.c quic.c quicwire.c crypto.c ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c -lpthread
	/tmp/d2k-core-san-test_probe_plan

measured.o: measured.c $(HDR) profiles/rx_fake.h
	$(CC) $(CFLAGS) -c -o $@ $<

# Shared UDP compiler/executor archive. Selective extraction avoids duplicate
# plan/wire objects in tests which already link those runtime sources directly.
# Наблюдение потоков по conntrack в d2kc (этап 37): разбор ctnetlink — те же
# файлы датапата, что и у его детекторов; одно место для всех сборок d2kc.
D2KC_CT_SRC = ../datapath/ctq.c ../datapath/nl.c
UDP_ENGINE_SRC = udpplan.c udpruntime.c plantlv.c ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c ../datapath/wire_udp.c ipfrag.c quic.c quicsnap.c quicwire.c crypto.c
UDP_ENGINE_OBJ = $(addprefix .udp-engine/,$(notdir $(UDP_ENGINE_SRC:.c=.o)))
UDP_ENGINE_HDR = $(HDR) $(wildcard ../datapath/include/*.h) ../datapath/plan_internal.h
udpplan.o: udpplan.c $(UDP_ENGINE_HDR)
udpruntime.o: udpruntime.c $(UDP_ENGINE_HDR)
libd2k_udp.a: $(UDP_ENGINE_SRC) $(UDP_ENGINE_HDR)
	@mkdir -p .udp-engine
	@for src in $(UDP_ENGINE_SRC); do $(CC) $(CFLAGS) -c $$src -o .udp-engine/$$(basename $$src .c).o || exit 1; done
	ar rcs $@ $(UDP_ENGINE_OBJ)
LDFLAGS += libd2k_udp.a

# session.c is also included by test_udp_runtime.c (and test_quic_sink.c).
# Keep its FSM dependency in the shared native/sanitizer/cross source group.
UDP_SESSION_SRC = ../datapath/preflight.c ../datapath/preflight_lease.c httpup_logic.c provider_ips.c ../datapath/http80.c ../datapath/hold.c ../datapath/capture.c ../datapath/nat.c ../datapath/ctq.c ../datapath/nl.c ../datapath/track.c ../datapath/tls.c ../datapath/journal.c ../datapath/plans.c ../core/stun.c
# Include-chain and header changes must also invalidate the runtime gates.
test_udp_runtime test_quic_sink test_http_runtime test_http_live: ../datapath/session.c ../datapath/include/d2k_preflight.h ../datapath/include/d2k_preflight_lease.h ../datapath/include/d2k_preflight_plan.h ../datapath/include/d2k_session.h ../datapath/plan_internal.h
TESTS += test_udp_runtime
check: test-udp-runtime
.PHONY: test-udp-runtime
test_udp_runtime: ../datapath/test_runtime_trace.h test_udp_runtime.c udpruntime.c ../datapath/session.c $(UDP_SESSION_SRC) libd2k_udp.a quicarms.o quichello.o hello.o tls13core.o x25519.o meas.o
	$(CC) $(CFLAGS) -o $@ test_udp_runtime.c $(UDP_SESSION_SRC) quicarms.o quichello.o hello.o tls13core.o x25519.o meas.o $(TEST_LDFLAGS)
test-udp-runtime: test_udp_runtime
	./test_udp_runtime
TESTS += test_udp_compose_exact
check: test-udp-compose-exact
.PHONY: test-udp-compose-exact
test_udp_compose_exact: test_udp_compose_exact.c libd2k_udp.a
	$(CC) $(CFLAGS) -o $@ test_udp_compose_exact.c $(TEST_LDFLAGS)
test-udp-compose-exact: test_udp_compose_exact
	./test_udp_compose_exact

TESTS += test_http_runtime
check: test-http-runtime
.PHONY: test-http-runtime
test_http_runtime: $(HTTP_READ_OBJ) ../datapath/test_runtime_trace.h test_http_runtime.c test_httpsearch.c httpsearch.c $(UDP_SESSION_SRC) ../datapath/session.c libd2k_udp.a tls13core.o x25519.o
	$(CC) $(CFLAGS) -o $@ test_http_runtime.c httpsearch.c $(UDP_SESSION_SRC) ../datapath/session.c $(HTTP_READ_OBJ) $(TEST_LDFLAGS)
test-http-runtime: test_http_runtime
	./test_http_runtime

TESTS += test_http_live
check: test-http-live
.PHONY: test-http-live
test_http_live: $(HTTP_READ_OBJ) test_http_live.c test_httpsearch.c ../datapath/test_runtime_trace.h d2kc httpsearch.c $(UDP_SESSION_SRC) ../datapath/session.c ../datapath/ctl.c ../datapath/ctlsrv.c libd2k_udp.a tls13core.o x25519.o link.o
	$(CC) $(CFLAGS) -o $@ test_http_live.c httpsearch.c $(UDP_SESSION_SRC) ../datapath/session.c ../datapath/ctl.c ../datapath/ctlsrv.c $(HTTP_READ_OBJ) $(TEST_LDFLAGS)
test-http-live: test_http_live
	./test_http_live

TESTS += test_quic_sink
check: test-quic-sink
.PHONY: test-quic-sink
test_quic_sink: test_quic_sink.c test_udp_runtime.c quicprobe.c udpruntime.c $(UDP_SESSION_SRC) libd2k_udp.a quicsnap.o quicsnap_reseal.o quicarms.o quichello.o hello.o tls13core.o x25519.o meas.o quicconn.o h3.o net4.o props.o
	$(CC) $(CFLAGS) -o $@ test_quic_sink.c $(UDP_SESSION_SRC) quicsnap.o quicsnap_reseal.o quicarms.o quichello.o hello.o tls13core.o x25519.o meas.o quicconn.o h3.o net4.o props.o $(TEST_LDFLAGS)
test-quic-sink: test_quic_sink
	./test_quic_sink

# The complete runtime gates include production translation units directly;
# give them dedicated sanitizer links rather than linking a second copy.
SAN_SKIP += test_udp_runtime test_quic_sink test_http_runtime test_http_live
SAN_EXTRA_SRC += $(filter-out $(SRC),$(UDP_ENGINE_SRC))
# Separate links from execution so socket-restricted builders can verify them.
.PHONY: san-udp-runtime san-http-live san-runtime-build
san: san-udp-runtime san-http-live
san-runtime-build: /tmp/d2k-san-udp-runtime /tmp/d2k-san-quic-sink /tmp/d2k-san-http-runtime /tmp/d2k-san-http-live
san-udp-runtime: /tmp/d2k-san-udp-runtime /tmp/d2k-san-quic-sink /tmp/d2k-san-http-runtime
	/tmp/d2k-san-udp-runtime
	/tmp/d2k-san-quic-sink
	/tmp/d2k-san-http-runtime
san-http-live: /tmp/d2k-san-http-live
	/tmp/d2k-san-http-live
.PHONY: /tmp/d2k-san-udp-runtime
/tmp/d2k-san-udp-runtime: hello_profiles.inc
	$(CC) $(SANFLAGS) -o /tmp/d2k-san-udp-runtime test_udp_runtime.c $(UDP_SESSION_SRC) $(filter-out udpruntime.c,$(UDP_ENGINE_SRC)) quicarms.c quichello.c hello.c tls13core.c x25519.c meas.c -lpthread
.PHONY: /tmp/d2k-san-quic-sink
/tmp/d2k-san-quic-sink: hello_profiles.inc
	$(CC) $(SANFLAGS) -o /tmp/d2k-san-quic-sink test_quic_sink.c $(UDP_SESSION_SRC) $(filter-out udpruntime.c,$(UDP_ENGINE_SRC)) quicarms.c quichello.c hello.c tls13core.c x25519.c meas.c quicconn.c h3.c net4.c props.c quicsnap_reseal.c -lpthread
.PHONY: /tmp/d2k-san-http-runtime
/tmp/d2k-san-http-runtime: hello_profiles.inc
	$(CC) $(SANFLAGS) -o /tmp/d2k-san-http-runtime test_http_runtime.c httpsearch.c $(UDP_SESSION_SRC) ../datapath/session.c $(filter-out udpruntime.c udpplan.c,$(UDP_ENGINE_SRC)) $(HTTP_READ_SRC) -lpthread
.PHONY: /tmp/d2k-san-http-live
/tmp/d2k-san-http-live: hello_profiles.inc d2kc
	$(CC) $(SANFLAGS) -o /tmp/d2k-san-http-live test_http_live.c httpsearch.c $(UDP_SESSION_SRC) ../datapath/session.c ../datapath/ctl.c ../datapath/ctlsrv.c $(filter-out udpruntime.c udpplan.c,$(UDP_ENGINE_SRC)) $(HTTP_READ_SRC) -lpthread

.PHONY: cross-runtime-gates
cross: cross-runtime-gates
cross-runtime-gates: hello_profiles.inc
	@for t in test_udp_runtime test_quic_sink; do \
		extra=""; if test "$$t" = test_quic_sink; then extra="quicconn.c h3.c net4.c props.c quicsnap_reseal.c"; fi; \
		$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-$$t-a64 $$t.c $(UDP_SESSION_SRC) quicarms.c quichello.c hello.c tls13core.c x25519.c meas.c $$extra $(filter-out udpruntime.c,$(UDP_ENGINE_SRC)) -lpthread || exit 1; \
		$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-$$t-mipsel $$t.c $(UDP_SESSION_SRC) quicarms.c quichello.c hello.c tls13core.c x25519.c meas.c $$extra $(filter-out udpruntime.c,$(UDP_ENGINE_SRC)) -lpthread || exit 1; \
	done
	$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-http-runtime-a64 test_http_runtime.c httpsearch.c $(UDP_SESSION_SRC) ../datapath/session.c $(filter-out test_http_runtime.c httpsearch.c $(UDP_SESSION_SRC) ../datapath/session.c udpruntime.c udpplan.c,$(UDP_ENGINE_SRC)) $(HTTP_READ_SRC) -lpthread
	$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-http-runtime-mipsel test_http_runtime.c httpsearch.c $(UDP_SESSION_SRC) ../datapath/session.c $(filter-out test_http_runtime.c httpsearch.c $(UDP_SESSION_SRC) ../datapath/session.c udpruntime.c udpplan.c,$(UDP_ENGINE_SRC)) $(HTTP_READ_SRC) -lpthread

# TLS record progress is observable independently of successful decryption.
TESTS += test_tls_rx12
# Живое рукопожатие TLS 1.2 без имени против openssl s_server на петле (этап 15).
TESTS += test_tls12_live
check: test-tls12-live
.PHONY: test-tls12-live
test-tls12-live: test_tls12_live
	./test_tls12_live
test_tls12_live: test_tls12_live.c verify.o quicconn.o h3.o tls12.o p256.o compose.o measured.o hello.o meas.o link.o tls13.o suite.o mlkem.o keccak.o tls13core.o x25519.o crypto.o quicwire.o dns_upstreams.o domain.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_tls12_live.c verify.o quicconn.o h3.o tls12.o p256.o compose.o measured.o hello.o meas.o link.o tls13.o suite.o mlkem.o keccak.o tls13core.o x25519.o crypto.o quicwire.o dns_upstreams.o domain.o $(TEST_LDFLAGS)
SAN_SKIP += test_tls12_live
check: test-tls-rx12
.PHONY: test-tls-rx12 san-tls-rx12 cross-tls-rx12
test_tls_rx12: test_tls_rx12.c tls12.c include/d2k_tls12.h suite.o p256.o tls13core.o crypto.o x25519.o libd2k_udp.a
	$(CC) $(CFLAGS) -o $@ $< suite.o p256.o tls13core.o crypto.o x25519.o $(TEST_LDFLAGS)
test-tls-rx12: test_tls_rx12
	./test_tls_rx12
SAN_SKIP += test_tls_rx12
san: san-tls-rx12
san-tls-rx12:
	$(CC) $(SANFLAGS) -o /tmp/d2k-san-tls-rx12 test_tls_rx12.c suite.c p256.c tls13core.c crypto.c x25519.c -lpthread
	/tmp/d2k-san-tls-rx12
cross: cross-tls-rx12
cross-tls-rx12:
	$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2k-tls-rx12-a64 test_tls_rx12.c suite.c p256.c tls13core.c crypto.c x25519.c -lpthread
	$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2k-tls-rx12-mipsel test_tls_rx12.c suite.c p256.c tls13core.c crypto.c x25519.c -lpthread

# A blocked QUIC question sequence must yield a measurement slot to TCP.
test_sched_quic_yield: test_sched_quic_yield.c sched.c test_task_slots.h stunprobe.c $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(HDR)
	$(CC) $(CFLAGS) -o $@ $< $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(TEST_LDFLAGS)
.PHONY: test-sched-quic-yield
test-sched-quic-yield: test_sched_quic_yield
	./test_sched_quic_yield
check: test-sched-quic-yield
TESTS += test_sched_quic_yield
.PHONY: san-sched-quic-yield
san: san-sched-quic-yield
san-sched-quic-yield: hello_profiles.inc tcp1620_whitelist.inc
	$(CC) $(SANFLAGS) -I../model/include -o /tmp/d2k-san-sched-quic-yield test_sched_quic_yield.c $(sort $(filter-out sched.c,$(SCHED_TEST_SRC)) $(UDP_ENGINE_SRC)) -lpthread
	/tmp/d2k-san-sched-quic-yield

# В САМОМ КОНЦЕ, И ЭТО ВАЖНО. LDFLAGS выше несёт libd2k_udp.a в каждую
# линковку с $(TEST_LDFLAGS), значит каждая такая цель обязана от неё
# зависеть. Прежде объявление стояло в середине файла: в позиции цели
# $(TESTS) раскрывается сразу, и тесты, добавленные ниже, зависимость не
# получали; а три цели вне TESTS (test_tls12, test_d2kc_proto,
# test_ip6frag_send_live) не получали её вовсе. Последовательная сборка этого
# не замечала — библиотека успевала собраться раньше. `make -j` падал за
# секунду: «no such file or directory: libd2k_udp.a».
# (объявление перенесено в конец файла — см. там же почему)

.PHONY: test-diagnostics
check: test-diagnostics
test-diagnostics: test_diagnostics
	python3 test_diagnostics_json.py
test_diagnostics: test_diagnostics.c diagnostics.c include/d2k_diagnostics.h
	$(CC) $(CFLAGS) -o $@ test_diagnostics.c diagnostics.c
clean: clean-diagnostics
.PHONY: clean-diagnostics
clean-diagnostics:
	$(RM) test_diagnostics

.PHONY: test-diagnostics-runtime
check: test-diagnostics-runtime
test-diagnostics-runtime: test_diagnostics_runtime
	./test_diagnostics_runtime
# d2kc.c читает conntrack (этап 37) — тот же список, что у сборок d2kc.
test_diagnostics_runtime: test_diagnostics_runtime.c $(SYNTH_OBJ) d2kc.c diagnostics.o $(SCHED_TEST_OBJ) $(DETECT_OBJ) libd2k_udp.a $(HDR) $(D2KC_CT_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(SYNTH_OBJ) diagnostics.o $(SCHED_TEST_OBJ) $(DETECT_OBJ) ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c $(D2KC_CT_SRC) $(TEST_LDFLAGS)
test_application_provider: test_application_provider.c $(SYNTH_OBJ) d2kc.c diagnostics.o $(SCHED_TEST_OBJ) $(DETECT_OBJ) libd2k_udp.a $(HDR) $(D2KC_CT_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(SYNTH_OBJ) diagnostics.o $(SCHED_TEST_OBJ) $(DETECT_OBJ) ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c $(D2KC_CT_SRC) $(TEST_LDFLAGS)
TESTS += test_application_provider
.PHONY: test-application-provider
check: test-application-provider
test-application-provider: test_application_provider
	./test_application_provider
clean-diagnostics-runtime:
	$(RM) test_diagnostics_runtime
clean: clean-diagnostics-runtime

# Address-only STUN transaction; no Discord or QUIC context is substituted.
.PHONY: test-stunprobe
check: test-stunprobe
test-stunprobe: test_stunprobe
	./test_stunprobe
test_stunprobe: test_stunprobe.c stunprobe.c stun.o meas.o tls13core.o crypto.o x25519.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_stunprobe.c stunprobe.c stun.o meas.o tls13core.o crypto.o x25519.o $(TEST_LDFLAGS)

stunprobe.o: stunprobe.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<
# Без явного правила stuntrial.o шёл встроенным правилом make — без единой
# зависимости от заголовков (d2k_stuntrial.h, d2k_link.h, d2k_ctl.h).
stuntrial.o: stuntrial.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: test-stuntrial
check: test-stuntrial
test-stuntrial: test_stuntrial
	./test_stuntrial

test_stuntrial: test_stuntrial.c stuntrial.c stunprobe.c link.o stun.o meas.o tls13core.o crypto.o x25519.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_stuntrial.c stuntrial.c stunprobe.c link.o stun.o meas.o tls13core.o crypto.o x25519.o $(TEST_LDFLAGS)

# Отказ calloc в d2k_stun_trial_open: stuntrial.c собирается с подменой
# calloc (приём san-mips-pipe), поэтому в общий san-loop тест не идёт —
# у него своя san-цель ниже.
TESTS += test_stuntrial_oom
SAN_SKIP += test_stuntrial_oom
check: test-stuntrial-oom
.PHONY: test-stuntrial-oom san-stuntrial-oom
test-stuntrial-oom: test_stuntrial_oom
	./test_stuntrial_oom
test_stuntrial_oom: test_stuntrial_oom.c stuntrial.c stunprobe.o link.o stun.o meas.o tls13core.o crypto.o x25519.o $(HDR)
	$(CC) $(CFLAGS) -Dcalloc=d2k_test_calloc -o $@ test_stuntrial_oom.c stuntrial.c stunprobe.o link.o stun.o meas.o tls13core.o crypto.o x25519.o $(TEST_LDFLAGS)
san: san-stuntrial-oom
san-stuntrial-oom:
	@set -eu; oom_dir=$$(mktemp -d "$${TMPDIR:-/tmp}/d2k-stuntrial-oom-san.XXXXXX"); \
		trap 'rm -rf "$$oom_dir"' EXIT HUP INT TERM; \
		$(CC) $(SANFLAGS) -Dcalloc=d2k_test_calloc -o "$$oom_dir/test" test_stuntrial_oom.c stuntrial.c stunprobe.c link.c stun.c meas.c tls13core.c crypto.c x25519.c -lpthread; \
		"$$oom_dir/test"

TESTS += test_stun_cleanup
check: test-stun-cleanup
.PHONY: test-stun-cleanup
test-stun-cleanup: test_stun_cleanup
	./test_stun_cleanup
test_stun_cleanup: test_stun_cleanup.c $(SCHED_TEST_OBJ) $(HDR)
	$(CC) $(CFLAGS) -o $@ $< $(SCHED_TEST_OBJ) $(TEST_LDFLAGS)

TESTS += test_stun_candidate
check: test-stun-candidate
.PHONY: test-stun-candidate
test-stun-candidate: test_stun_candidate
	./test_stun_candidate
test_stun_candidate: test_stun_candidate.c sched.c test_task_slots.h $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(HDR)
	$(CC) $(CFLAGS) -o $@ $< $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(TEST_LDFLAGS)

TESTS += test_service_confirmation
check: test-service-confirmation
.PHONY: test-service-confirmation
test-service-confirmation: test_service_confirmation
	./test_service_confirmation
test_service_confirmation: test_service_confirmation.c sched.c test_task_slots.h $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(HDR)
	$(CC) $(CFLAGS) -o $@ $< $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(TEST_LDFLAGS)

TESTS += test_voice_proof_context
check: test-voice-proof-context
.PHONY: test-voice-proof-context
test-voice-proof-context: test_voice_proof_context
	./test_voice_proof_context
test_voice_proof_context: test_voice_proof_context.c sched.c test_task_slots.h $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(HDR)
	$(CC) $(CFLAGS) -o $@ $< $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(TEST_LDFLAGS)

TESTS += test_raw_measure_sched

TESTS += test_sched_gate

.PHONY: test-raw-measure-sched
test_raw_measure_sched: test_raw_measure_sched.c sched.c test_task_slots.h $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(HDR) libd2k_udp.a
	$(CC) $(CFLAGS) -o $@ $< $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(TEST_LDFLAGS)
test-raw-measure-sched: test_raw_measure_sched
	./test_raw_measure_sched
check: test-raw-measure-sched

verify.o test_verify_http: doh_h2.inc dns_question_wire.inc
TESTS += test_verify_doh test_doh_h2
.PHONY: test-dns-journal
TESTS += test_dns_journal
check: test-dns-journal
test-dns-journal: test_dns_journal
	./test_dns_journal
test_dns_journal: test_dns_journal.c dns_journal.inc ../runtime/d2k_json_reader.h domain.c include/d2k_domain.h profiles/psl_index.h
	$(CC) $(CFLAGS) -o $@ test_dns_journal.c domain.c
d2kc: dns_journal.inc ../runtime/d2k_json_reader.h
release: dns_journal.inc ../runtime/d2k_json_reader.h
.PHONY: test-verify-doh test-doh-h2
check: test-verify-doh test-doh-h2
test-verify-doh: test_verify_doh
	./test_verify_doh
TESTS += test_verify_https_io
check: test-verify-https-io
.PHONY: test-verify-https-io
test-verify-https-io: test_verify_https_io
	./test_verify_https_io
test_verify_https_io: test_verify_https_io.c verify.c doh_h2.inc quicconn.c tls12.o p256.o quicwire.o h3.o compose.o measured.o hello.o meas.o link.o tls13.o suite.o mlkem.o keccak.o tls13core.o x25519.o crypto.o dns_upstreams.o domain.o $(HDR)
	$(CC) $(CFLAGS) -o $@ $< tls12.o p256.o quicwire.o h3.o compose.o measured.o hello.o meas.o link.o tls13.o suite.o mlkem.o keccak.o tls13core.o x25519.o crypto.o libd2k_udp.a dns_upstreams.o domain.o $(TEST_LDFLAGS)
test_verify_doh: test_verify_doh.c verify.c doh_h2.inc quicconn.c tls12.o p256.o quicwire.o h3.o compose.o measured.o hello.o meas.o link.o tls13.o suite.o mlkem.o keccak.o tls13core.o x25519.o crypto.o dns_upstreams.o domain.o $(HDR)
	$(CC) $(CFLAGS) -o $@ $< tls12.o p256.o quicwire.o h3.o compose.o measured.o hello.o meas.o link.o tls13.o suite.o mlkem.o keccak.o tls13core.o x25519.o crypto.o libd2k_udp.a dns_upstreams.o domain.o $(TEST_LDFLAGS)
test-doh-h2: test_doh_h2
	./test_doh_h2
test_doh_h2: test_doh_h2.c verify.c doh_h2.inc $(filter-out verify.o,$(D2KFETCH_OBJ)) $(HDR)
	$(CC) $(CFLAGS) -o $@ $< $(filter-out verify.o,$(D2KFETCH_OBJ)) $(TEST_LDFLAGS)

TESTS += test_tls_sh_records
check: test-tls-sh-records
.PHONY: test-tls-sh-records
test_tls_sh_records: test_tls_sh_records.c tls13.o suite.o mlkem.o keccak.o tls12.o p256.o tls13core.o crypto.o x25519.o libd2k_udp.a
	$(CC) $(CFLAGS) -o $@ $< tls13.o suite.o mlkem.o keccak.o tls12.o p256.o tls13core.o crypto.o x25519.o $(TEST_LDFLAGS)
test-tls-sh-records: test_tls_sh_records
	./test_tls_sh_records

plantlv.o compose.o: ../datapath/include/d2k_preflight_plan.h

libd2k_udp.a: ../datapath/include/d2k_preflight_plan.h ../datapath/plan_internal.h

# No listeners: preflight facts and strict malformed-frame rejection.
test_preflight_event: test_preflight_event.c link.o quicsnap.o quic.o quicwire.o crypto.o libd2k_udp.a $(HDR)
	$(CC) $(CFLAGS) -o $@ test_preflight_event.c link.o quicsnap.o quic.o quicwire.o crypto.o $(TEST_LDFLAGS)
test-preflight-event: test_preflight_event
	./test_preflight_event
check: test-preflight-event
.PHONY: test-preflight-event clean-preflight-event
clean: clean-preflight-event
clean-preflight-event:
	rm -f test_preflight_event

TESTS += test_preflight_verify
test_preflight_verify: test_preflight_verify.c verify.c doh_h2.inc $(filter-out verify.o,$(D2KFETCH_OBJ)) $(HDR)
	$(CC) $(CFLAGS) -o $@ $< $(filter-out verify.o,$(D2KFETCH_OBJ)) $(TEST_LDFLAGS)
test-preflight-verify: test_preflight_verify
	./test_preflight_verify
check: test-preflight-verify
.PHONY: test-preflight-verify

# Gate lifecycle, socketpair and existing verifier hooks; no listeners.
test_sched_gate: test_sched_gate.c sched.c test_task_slots.h $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(HDR)
	$(CC) $(CFLAGS) -o $@ $< $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(TEST_LDFLAGS)
test-sched-gate: test_sched_gate
	./test_sched_gate
check: test-sched-gate
.PHONY: test-sched-gate
.PHONY: san-sched-gate
san-sched-gate: hello_profiles.inc tcp1620_whitelist.inc
	$(CC) $(SANFLAGS) -o /tmp/d2k-san-sched-gate test_sched_gate.c $(sort $(filter-out sched.c,$(SCHED_TEST_SRC)) $(UDP_ENGINE_SRC)) -lpthread
	/tmp/d2k-san-sched-gate

# Offline memory ownership diagnostics: real lifecycle/storage, no network.
TESTS += test_memory_accounting test_httpsearch_memory
.PHONY: test-memory-accounting
check: test-memory-accounting
test_memory_accounting: test_memory_accounting.c sched.c test_task_slots.h $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(HDR)
	$(CC) $(CFLAGS) -o $@ $< $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(TEST_LDFLAGS)
test_httpsearch_memory: test_httpsearch_memory.c httpsearch.c $(HTTP_READ_OBJ) httpup_logic.c plantlv.o quic.o quicwire.o crypto.o $(HDR)
	$(CC) $(CFLAGS) -o $@ $< httpup_logic.c plantlv.o quic.o quicwire.o crypto.o ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c $(HTTP_READ_OBJ) $(TEST_LDFLAGS)
test-memory-accounting: test_memory_accounting test_httpsearch_memory
	./test_memory_accounting
	./test_httpsearch_memory

TESTS += test_sched_force
.PHONY: test-sched-force
test_sched_force: test_sched_force.c sched.c test_task_slots.h $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(HDR)
	$(CC) $(CFLAGS) -o $@ $< $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(TEST_LDFLAGS)
test-sched-force: test_sched_force
	./test_sched_force
check: test-sched-force

# TLS 1.2 PRF/AEAD wire format regression; memory transport, no sockets.
TESTS += test_tls12_suites
check: test-tls12-suites
.PHONY: test-tls12-suites
test_tls12_suites: test_tls12_suites.c test_tls12_vectors.h tls12.c tls13.o mlkem.o keccak.o suite.o p256.o tls13core.o crypto.o x25519.o $(HDR)
	$(CC) $(CFLAGS) -o $@ $< tls13.o mlkem.o keccak.o suite.o p256.o tls13core.o crypto.o x25519.o $(TEST_LDFLAGS)
test-tls12-suites: test_tls12_suites
	./test_tls12_suites
SAN_SKIP += test_tls12_suites
san: san-tls12-suites
.PHONY: san-tls12-suites
san-tls12-suites:
	$(CC) $(SANFLAGS) -o /tmp/d2k-san-tls12-suites test_tls12_suites.c tls13.c suite.c mlkem.c keccak.c p256.c tls13core.c crypto.c x25519.c -lpthread
	/tmp/d2k-san-tls12-suites

# Shadow observer and shared single-target task assembly.
EXP_HDR = include/d2k_exp_task.h include/d2k_netarm.h $(wildcard ../model/include/*.h)
SHADOW_HDR = include/d2k_shadow.h include/d2k_shadow_queue.h $(EXP_HDR)
d2kexp d2kexp-linux-arm64 d2kshadow d2kshadow-linux-arm64 test_shadow test_shadow_parallel test_netarm: doh_h2.inc $(EXP_HDR)
d2kshadow: $(D2KSHADOW_SRC) $(HDR) $(SHADOW_HDR)
	$(CC) $(CFLAGS) -I../model/include -o $@ $(D2KSHADOW_SRC) -lpthread
d2kshadow-linux-arm64: $(D2KSHADOW_SRC) $(HDR) $(SHADOW_HDR)
	$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -I../model/include -static -Wl,-S -o $@ $(D2KSHADOW_SRC) -lpthread
.PHONY: shadow-release
shadow-release: $(D2KSHADOW_SRC) $(HDR) $(SHADOW_HDR)
	@mkdir -p $(BUILDDIR)
	$(ZIG) cc -target $(TARGET) $(TARGET_FLAGS) $(CFLAGS) -I../model/include -static -Wl,-S -o $(BUILDDIR)/d2kshadow-linux-$(ARCH) $(D2KSHADOW_SRC) -lpthread

test_shadow_queue: test_shadow_queue.c shadow_queue.c include/d2k_shadow_queue.h
	$(CC) $(CFLAGS) -o $@ test_shadow_queue.c shadow_queue.c
test_shadow: test_shadow.c shadow.c shadow_queue.c domain.c $(D2KEXP_COMMON_SRC) ../model/sim.c $(SHADOW_HDR) $(HDR)
	$(CC) $(CFLAGS) -I../model/include -o $@ test_shadow.c shadow.c shadow_queue.c domain.c $(D2KEXP_COMMON_SRC) ../model/sim.c -lpthread
test_shadow_sched: test_shadow_sched.c sched.c test_task_slots.h $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(HDR) libd2k_udp.a
	$(CC) $(CFLAGS) -o $@ $< $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(TEST_LDFLAGS)
TESTS += test_shadow_queue test_shadow test_shadow_sched
.PHONY: test-shadow
check: test-shadow
test-shadow: test_shadow_queue test_shadow test_shadow_sched test_shadow_daemon
	./test_shadow_queue
	./test_shadow
	./test_shadow_sched
	./test_shadow_daemon

test_shadow_daemon: test_shadow_daemon.c shadow_queue.c include/d2k_shadow_queue.h d2kshadow
	$(CC) $(CFLAGS) -o $@ test_shadow_daemon.c shadow_queue.c
TESTS += test_shadow_daemon

# Real control framing over socketpair; no bind or network dependency.
test_newchain: test_newchain.c $(NEWCHAIN_SRC) link.c plantlv.c $(HDR)
	$(CC) $(CFLAGS) -o $@ test_newchain.c $(NEWCHAIN_SRC) link.c plantlv.c $(TEST_LDFLAGS)
TESTS += test_newchain
check: test-newchain
.PHONY: test-newchain
test-newchain: test_newchain test_newchain_sched
	./test_newchain
	./test_newchain_sched

test_newchain_sched: test_newchain_sched.c sched.c test_task_slots.h $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(HDR) libd2k_udp.a
	$(CC) $(CFLAGS) -o $@ $< $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(TEST_LDFLAGS)
TESTS += test_newchain_sched

test_doh_contract: test_doh_contract.c doh_contract.c doh_h2.inc include/d2k_doh_contract.h
	$(CC) $(CFLAGS) -o $@ test_doh_contract.c
check: test-doh-contract
.PHONY: test-doh-contract
test-doh-contract: test_doh_contract
	./test_doh_contract
TESTS += test_doh_contract

test_shadow_parallel: test_shadow_parallel.c shadow.c shadow_queue.c domain.c $(D2KEXP_COMMON_SRC) ../model/sim.c $(SHADOW_HDR) $(HDR)
	$(CC) $(CFLAGS) -I../model/include -o $@ test_shadow_parallel.c shadow.c shadow_queue.c domain.c $(D2KEXP_COMMON_SRC) ../model/sim.c -lpthread
check: test-shadow-parallel
.PHONY: test-shadow-parallel
test-shadow-parallel: test_shadow_parallel
	./test_shadow_parallel
TESTS += test_shadow_parallel

.PHONY: san-shadow-parallel san-doh-contract
san-shadow-parallel: $(SHADOW_HDR) $(HDR)
	$(CC) $(SANFLAGS) -I../model/include -o /tmp/d2k25-san-shadow-parallel test_shadow_parallel.c shadow.c shadow_queue.c domain.c $(D2KEXP_COMMON_SRC) ../model/sim.c -lpthread
	/tmp/d2k25-san-shadow-parallel
san-doh-contract:
	$(CC) $(SANFLAGS) -I../model/include -o /tmp/d2k25-san-doh-contract test_doh_contract.c
	/tmp/d2k25-san-doh-contract

# No network: mocked OS/control boundary with the real arm and task code.
test_exp_local: test_exp_local.c exp_task.c netarm.c $(D2KEXP_COMMON_SRC) $(EXP_HDR) $(HDR)
	$(CC) $(CFLAGS) -I../model/include -o $@ test_exp_local.c $(filter-out exp_task.c netarm.c,$(D2KEXP_COMMON_SRC)) -lpthread
TESTS += test_exp_local
.PHONY: test-exp-local san-exp-local
check: test-exp-local
test-exp-local: test_exp_local
	./test_exp_local
san-exp-local: test_exp_local.c exp_task.c netarm.c $(D2KEXP_COMMON_SRC) $(EXP_HDR) $(HDR)
	$(CC) $(SANFLAGS) -I../model/include -o /tmp/d2k26-san-exp-local test_exp_local.c $(filter-out exp_task.c netarm.c,$(D2KEXP_COMMON_SRC)) -lpthread
	/tmp/d2k26-san-exp-local

TESTS += test_dns_upstreams
.PHONY: test-dns-upstreams
test_dns_upstreams: test_dns_upstreams.c dns_upstreams.c domain.c include/d2k_dns_upstreams.h include/d2k_domain.h
	$(CC) $(CFLAGS) -o $@ test_dns_upstreams.c dns_upstreams.c domain.c $(filter-out libd2k_udp.a,$(LDFLAGS))
test-dns-upstreams: test_dns_upstreams
	./test_dns_upstreams
check: test-dns-upstreams

TESTS += test_sched_dns
.PHONY: test-sched-dns
test_sched_dns: test_sched_dns.c sched.c sched_dns.inc dns_question_wire.inc $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(HDR) libd2k_udp.a
	$(CC) $(CFLAGS) -o $@ $< $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(TEST_LDFLAGS)
test-sched-dns: test_sched_dns test-dns-upstreams
	./test_sched_dns
check: test-sched-dns

TESTS += test_doh_authority
.PHONY: test-doh-authority
check: test-doh-authority
test-doh-authority: test_doh_authority
	./test_doh_authority
test_doh_authority: test_doh_authority.c verify.c doh_h2.inc $(filter-out verify.o,$(D2KFETCH_OBJ)) $(HDR)
	$(CC) $(CFLAGS) -o $@ $< $(filter-out verify.o,$(D2KFETCH_OBJ)) $(TEST_LDFLAGS)

TESTS += test_dns_service
TESTS += test_dns_capture
TESTS += test_provider_ips
.PHONY: test-provider-ips
test-provider-ips: test_provider_ips
	./test_provider_ips
test_provider_ips: test_provider_ips.c provider_ips.c include/d2k_provider_ips.h
	$(CC) $(CFLAGS) -o $@ test_provider_ips.c provider_ips.c
check: test-provider-ips
.PHONY: test-dns-capture
test-dns-capture: test_dns_capture
	./test_dns_capture
test_dns_capture: test_dns_capture.c dns_capture.c include/d2k_dns_capture.h
	$(CC) $(CFLAGS) -o $@ test_dns_capture.c dns_capture.c
check: test-dns-capture
.PHONY: test-dns-service
check: test-dns-service
test-dns-service: test_dns_service
	./test_dns_service
test_dns_service: test_dns_service.c sched.c test_task_slots.h sched_dns.inc dns_question_wire.inc $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(HDR) libd2k_udp.a
	$(CC) $(CFLAGS) -o $@ $< $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(TEST_LDFLAGS)

TESTS += test_doh_health_route
.PHONY: test-doh-health-route
check: test-doh-health-route
test-doh-health-route: test_doh_health_route
	./test_doh_health_route
test_doh_health_route: test_doh_health_route.c sched.c test_task_slots.h $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(HDR) libd2k_udp.a
	$(CC) $(CFLAGS) -o $@ $< $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(TEST_LDFLAGS)

# Keep this after every TESTS +=: the target list expands immediately.
$(TESTS) d2kask d2kc d2kvoice d2kfetch test_tls12 test_d2kc_proto test_ip6frag_send_live: libd2k_udp.a
