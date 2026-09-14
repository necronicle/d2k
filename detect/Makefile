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
CFLAGS  ?= -std=c99 -O2 -Wall -Wextra -Werror -Iinclude -I../core/include
LDFLAGS ?=

ZIG        ?= /opt/homebrew/bin/zig
MIPSEL_CC  ?= mipsel-unknown-linux-gnu-gcc

SRC = classify.c poison.c props.c raw.c trigger.c response.c
OBJ = $(SRC:.c=.o)
HDR = include/d2k_detect.h ../core/include/d2k_hello.h

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

d2k-detect: main.o $(OBJ) ../core/hello.o
	$(CC) $(CFLAGS) -o $@ main.o $(OBJ) ../core/hello.o $(LDFLAGS)

test_port: test_port.c $(OBJ) ../core/hello.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_port.c $(OBJ) ../core/hello.o $(LDFLAGS)

# Стенд поднимает поддельную коробку в отдельном потоке; самому измерителю
# потоки не нужны, поэтому pthread — только у этой линковки.
test_tree: test_tree.c $(OBJ) ../core/hello.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_tree.c $(OBJ) ../core/hello.o $(LDFLAGS) -lpthread

check: d2k-detect test_port test_tree
	./test_port
	./test_tree

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
	  for f in $(SRC) main.c; do \
	    $(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -c -o /tmp/d2k-detect-cross.o $$f || exit 1; \
	  done; \
	  rm -f /tmp/d2k-detect-cross.o; \
	else \
	  echo "cross: zig не найден в $(ZIG) — aarch64 пропущен"; \
	fi
	@# MIPS — настоящим кросс-компилятором, как и в core/: zig для mipsel-musl
	@# заголовков libc не даёт, а подменять проверку на «собралось где-то ещё»
	@# значит не проверить ничего.
	@if command -v $(MIPSEL_CC) >/dev/null 2>&1; then \
	  echo "cross: linux-mipsel"; \
	  for f in $(SRC) main.c; do \
	    $(MIPSEL_CC) $(CFLAGS) -c -o /tmp/d2k-detect-mipsel.o $$f || exit 1; \
	  done; \
	  rm -f /tmp/d2k-detect-mipsel.o; \
	else \
	  echo "cross: $(MIPSEL_CC) не найден — mipsel пропущен"; \
	fi

clean:
	rm -f *.o d2k-detect test_port test_tree

FORCE:

# Сборка под роутер. Статически, как и остальные бинарники d2k: на Keenetic
# нет ни нужных .so, ни гарантии их версий.
BUILDDIR ?= ../builds

d2k-detect-linux-arm64:
	$(MAKE) -C ../core hello_profiles.inc
	@mkdir -p $(BUILDDIR)
	$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -I../core -static \
		-o $(BUILDDIR)/d2k-detect-linux-arm64 main.c $(SRC) ../core/hello.c
	@ls -l $(BUILDDIR)/d2k-detect-linux-arm64
