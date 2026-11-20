# d2k/detect — перенос инструмента «Поиск по домену» из z2k на C.
#
# Эталон: z2k/z2k-detect, коммит e9a3913, пакет internal/classify.
# Приёмка переноса — не «собралось», а СОВПАЛО: см. tests/compare.sh.
#
# -Werror и кросс-проверка — той же причины, что в core/ и datapath/:
# непереносимость обязана ловиться в день, когда её внесли, а не на роутере.
# Для этого модуля это особенно буквально — сырой слой есть только на Linux,
# и на маке компилируется другая ветка файла.

CC      ?= cc
CFLAGS  ?= -std=c99 -O2 -Wall -Wextra -Werror -Iinclude -I../core/include -I../datapath/include
LDFLAGS ?=
LDLIBS  ?= -lpthread

ZIG        ?= /opt/homebrew/bin/zig
MIPSEL_CC  ?= mipsel-unknown-linux-gnu-gcc
# Big-endian mips — своим gcc (на Ubuntu это пакет gcc-mips-linux-gnu), если он
# есть; необязателен ровно как MIPSEL_CC. Порядок байт проверяется ещё и
# zig-проходом ниже, который установленных цепочек не требует.
MIPS_CC    ?= mips-unknown-linux-gnu-gcc
# Та же тройка, что у выпуска (см. scripts/build-target.sh).
MIPS_BE_ZIG ?= -target mips-linux-musleabi -mcpu=mips32+soft_float

.DEFAULT_GOAL := all

SHARED_SRC = ../core/measured.c ../core/hello.c ../core/plantlv.c ../core/quic.c ../core/quicwire.c ../core/crypto.c ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c
SHARED_OBJ = $(SHARED_SRC:.c=.o)
$(filter-out ../core/hello.o,$(SHARED_OBJ)): FORCE
	$(MAKE) -C $(dir $@) $(notdir $@)

SRC = classify.c poison.c props.c raw.c trigger.c response.c preflight.c
# bridge.c — только для сборки в составе d2kc: он тянет заголовки ядра.
BRIDGE = bridge.c
bridge.o: ../synthesis/provider.h ../synthesis/path_work.h ../synthesis/stream.h ../synthesis/experiment.h
OBJ = $(SRC:.c=.o)
HDR = include/d2k_preflight_probe.h ../synthesis/verification_status.h include/d2k_detect.h ../core/include/d2k_hello.h ../core/include/d2k_arm.h

HDR += ../core/include/d2k_boxprops.h

.PHONY: all check cross clean FORCE

all: d2k-detect

# hello.o берём из ядра, а не копируем сюда: профили приветствий — снятые с
# живого браузера байты, и второй экземпляр этого кода означал бы второй
# источник истины о том, чем мы меряем.
../core/hello.o: FORCE
	$(MAKE) -C ../core hello.o

%.o: %.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

main.o: main.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

d2k-detect: main.o $(OBJ) $(SHARED_OBJ)
	$(CC) $(CFLAGS) -o $@ main.o $(OBJ) $(SHARED_OBJ) $(LDFLAGS) $(LDLIBS)

test_port: test_port.c $(OBJ) $(SHARED_OBJ) $(HDR)
	$(CC) $(CFLAGS) -o $@ test_port.c $(OBJ) $(SHARED_OBJ) $(LDFLAGS) $(LDLIBS)

# Стенд поднимает поддельную коробку в отдельном потоке; самому измерителю
# потоки не нужны, поэтому pthread — только у этой линковки.
test_tree: test_tree.c classify.c $(OBJ) $(SHARED_OBJ) $(HDR)
	$(CC) $(CFLAGS) -o $@ test_tree.c $(filter-out classify.o,$(OBJ)) $(SHARED_OBJ) $(LDFLAGS) -lpthread

# Повторы и кэш самопроверки: классификатор и свойства включены в тест
# исходником (#include), сырой слой подменён сценарием ответов.
test_repeats: test_repeats.c classify.c props.c poison.o trigger.o response.o raw.o preflight.o $(SHARED_OBJ) $(HDR)
	$(CC) $(CFLAGS) -o $@ test_repeats.c poison.o trigger.o response.o raw.o preflight.o $(SHARED_OBJ) $(LDFLAGS) -lpthread

test_bridge: test_bridge.c bridge.o trigger.o poison.o $(SHARED_OBJ) $(HDR)
	$(CC) $(CFLAGS) -o $@ test_bridge.c bridge.o trigger.o poison.o $(SHARED_OBJ) $(LDFLAGS) -lpthread

test_response: test_response.c $(OBJ) $(SHARED_OBJ) $(HDR)
	$(CC) $(CFLAGS) -o $@ test_response.c $(OBJ) $(SHARED_OBJ) $(LDFLAGS) $(LDLIBS)

test_threads: test_threads.c poison.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_threads.c poison.o $(LDFLAGS) -lpthread

test_raw: ../synthesis/tls_observe.c ../synthesis/tls_observe.h ../synthesis/tls_decode.c ../synthesis/tls_decode.h
test_raw: ../synthesis/raw_tls.c ../synthesis/raw_tls.h
test_raw: ../synthesis/raw_tape.c ../synthesis/raw_tape.h
test_raw: ../synthesis/token_content.c ../synthesis/token_content.h
RAW_TEST_LIB_SRC += ../synthesis/token_content.c
test_raw: ../synthesis/application_owner.c ../synthesis/verification.c
test_raw: ../synthesis/evidence.c ../synthesis/evidence.h ../synthesis/distinguish.c ../synthesis/distinguish.h
test_raw: ../synthesis/learner.c ../synthesis/learner.h
test_raw: ../synthesis/path_work.c ../synthesis/path_work.h
test_raw: ../synthesis/tracking.c ../synthesis/state_question.c ../synthesis/alternatives.c ../synthesis/alternatives.h ../synthesis/path_run.c ../synthesis/path_run.h ../synthesis/continuous.c ../synthesis/continuous.h
test_raw: ../synthesis/lower.c ../synthesis/lower.h
test_raw: ../synthesis/stream.c ../synthesis/stream.h ../synthesis/stream_run.c
test_raw: ../synthesis/session.c ../synthesis/session.h ../synthesis/context.c ../synthesis/context.h ../synthesis/joint.c ../synthesis/joint.h ../synthesis/search.c ../synthesis/search.h

RAW_TEST_LIB_SRC += ../synthesis/application_owner.c ../synthesis/verification.c ../synthesis/tracking.c ../synthesis/state_question.c ../synthesis/continuous.c ../synthesis/alternatives.c ../synthesis/session.c ../synthesis/context.c ../synthesis/joint.c ../synthesis/search.c ../synthesis/stream.c ../synthesis/stream_run.c ../synthesis/lower.c ../synthesis/learner.c ../synthesis/evidence.c ../synthesis/distinguish.c
test_raw: test_raw.c ../synthesis/experiment.c ../synthesis/experiment.h ../synthesis/observation.c ../synthesis/observation.h ../datapath/test_runtime_trace.h tests/legacy_sends.h raw.c $(filter-out raw.o,$(OBJ)) $(SHARED_OBJ) $(HDR) ../datapath/plan_apply.c $(RAW_TEST_LIB_SRC)
	$(CC) $(CFLAGS) -o $@ test_raw.c $(RAW_TEST_LIB_SRC) $(filter-out raw.o,$(OBJ)) $(filter-out ../datapath/plan_apply.o,$(SHARED_OBJ)) $(LDFLAGS) $(LDLIBS)

# Memory peer + actual raw episode API; no socket listener or host rules.
PREFLIGHT_TEST_SRC = test_preflight.c $(filter-out raw.c preflight.c,$(SRC)) $(SHARED_SRC)
test_preflight: $(PREFLIGHT_TEST_SRC) raw.c preflight.c include/d2k_preflight_probe.h $(HDR)
	$(CC) $(CFLAGS) -o $@ $(PREFLIGHT_TEST_SRC) $(LDFLAGS) $(LDLIBS)

bridge.o: bridge.c $(HDR) ../core/include/d2k_arm.h ../core/include/d2k_verdict.h
	$(CC) $(CFLAGS) -c -o $@ $<

test_raw6_live: test_raw6_live.c $(OBJ) $(SHARED_OBJ) $(HDR)
	$(CC) $(CFLAGS) -o $@ $< $(OBJ) $(SHARED_OBJ) $(LDFLAGS) $(LDLIBS)

check: d2k-detect test_port test_tree test_repeats test_bridge test_threads test_raw test_response test_preflight
	@# Отправка в сокет — только через d2k_send_nosig: SIGPIPE на мёртвом пире
	@# воспроизводится гонкой, поэтому места вызова закреплены ещё и статически.
	@if grep -nE '(^|[^_[:alnum:]])send\(' classify.c response.c | grep -v 'return send(fd, buf, len, flags)'; then \
	    echo "classify.c/response.c: голый send() запрещён, используйте d2k_send_nosig"; exit 1; fi
	./test_preflight
	./test_port
	./test_tree
	./test_repeats
	./test_bridge
	./test_threads
	./test_raw
	./test_response

# Кросс-проверка: Linux-ветка сырого слоя на маке не компилируется вовсе,
# и без неё опечатка там доехала бы до роутера незамеченной.
#
# Вывод — во ВРЕМЕННЫЙ файл, а не в /dev/null: zig cc при «-c -o /dev/null»
# всё равно кладёт объектник рядом с исходником и затирает собранный хостом.
# Ловится это не ошибкой, а «unknown file type» на следующей же линковке —
# то есть выглядит как поломка совсем в другом месте.
cross:
	@if [ -x "$(ZIG)" ]; then \
	  echo "cross: linux-aarch64"; \
	  for f in $(SRC) $(BRIDGE) main.c; do \
	    $(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -c -o /tmp/d2k-detect-cross.o $$f || exit 1; \
	  done; \
	  rm -f /tmp/d2k-detect-cross.o; \
	  echo "cross: linux-mips (big-endian)"; \
	  for f in $(SRC) $(BRIDGE) main.c; do \
	    $(ZIG) cc $(MIPS_BE_ZIG) $(CFLAGS) -c -o /tmp/d2k-detect-mips.o $$f || exit 1; \
	  done; \
	  rm -f /tmp/d2k-detect-mips.o; \
	else \
	  echo "cross: zig не найден в $(ZIG) — aarch64 и big-endian mips пропущены"; \
	fi
	@# MIPS — ещё и настоящими кросс-компиляторами, как в core/: это другой
	@# компилятор с другими предупреждениями, и «собралось zig'ом» их не
	@# заменяет. Оба необязательны: не нашлись — сказали и пошли дальше.
	@if command -v $(MIPSEL_CC) >/dev/null 2>&1; then \
	  echo "cross: linux-mipsel"; \
	  for f in $(SRC) $(BRIDGE) main.c; do \
	    $(MIPSEL_CC) $(CFLAGS) -c -o /tmp/d2k-detect-mipsel.o $$f || exit 1; \
	  done; \
	  rm -f /tmp/d2k-detect-mipsel.o; \
	else \
	  echo "cross: $(MIPSEL_CC) не найден — mipsel пропущен"; \
	fi
	@if command -v $(MIPS_CC) >/dev/null 2>&1; then \
	  echo "cross: linux-mips gcc"; \
	  for f in $(SRC) $(BRIDGE) main.c; do \
	    $(MIPS_CC) $(CFLAGS) -c -o /tmp/d2k-detect-mips-gcc.o $$f || exit 1; \
	  done; \
	  rm -f /tmp/d2k-detect-mips-gcc.o; \
	else \
	  echo "cross: $(MIPS_CC) не найден — big-endian mips проверен zig-проходом выше"; \
	fi

clean:
	rm -f *.o d2k-detect test_port test_tree test_repeats test_bridge test_threads test_raw test_response test_preflight

FORCE:

# Сборка под роутер. Статически, как и остальные бинарники d2k: на Keenetic
# нет ни нужных .so, ни гарантии их версий.
BUILDDIR ?= ../builds

d2k-detect-linux-arm64:
	$(MAKE) -C ../core hello_profiles.inc
	@mkdir -p $(BUILDDIR)
	$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -I../core -static \
		-o $(BUILDDIR)/d2k-detect-linux-arm64 main.c $(SRC) $(SHARED_SRC) $(LDLIBS)
	@ls -l $(BUILDDIR)/d2k-detect-linux-arm64

.PHONY: test-sni-cli
check: test-sni-cli
test-sni-cli: d2k-detect
	python3 test_sni_cli.py

# Actual raw send loop + shared executor, with only OS boundaries mocked.
.PHONY: san-raw
san-raw:
	$(CC) $(CFLAGS) -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
		-o /tmp/d2k-detect-san-raw test_raw.c $(RAW_TEST_LIB_SRC) $(filter-out raw.c,$(SRC)) \
		$(filter-out ../datapath/plan_apply.c,$(SHARED_SRC)) $(LDLIBS)
	/tmp/d2k-detect-san-raw
	$(CC) $(CFLAGS) -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
		-o /tmp/d2k-detect-san-preflight $(PREFLIGHT_TEST_SRC) $(LDLIBS)
	/tmp/d2k-detect-san-preflight
