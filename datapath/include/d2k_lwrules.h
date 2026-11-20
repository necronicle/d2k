#ifndef D2K_LWRULES_H
#define D2K_LWRULES_H

#include <stddef.h>
#include <stdint.h>
#include "d2k_ctq.h"

/* ЗАПАСНОЙ СПОСОБ ПОЗДНЕЙ ДОСТАВКИ БЕЗ CONNMARK (этап 53).
 *
 * Ядро без маски метки (vanilla 4.9) стёрло бы чужие биты записи; вместо
 * метки — пара правил в СВОИХ цепочках mangle по исходному кортежу conntrack:
 *   OUT: -m conntrack --ctdir ORIGINAL --ctproto P --ctorigsrc A --ctorigdst B
 *        --ctorigsrcport p --ctorigdstport q -j NFQUEUE --queue-num N --queue-bypass
 *   IN : то же с --ctdir REPLY.
 * Исходный кортеж записи не меняется при NAT — правило ловит поток до и после
 * трансляции, локальный и транзитный, IPv4 (iptables) и IPv6 (ip6tables).
 * Чужие метки и правила не трогаются: только свои цепочки; переход в них
 * ставит служба (S99d2k) после пользовательских RETURN и исключений.
 *
 * Исполнение — внешний iptables (системная зависимость, без оболочки), с
 * «-w» на блокировку xtables; вызывается только из потока исполнителя.
 *   установка: для каждой стороны -C, нет — -A; сбой второй — откат того,
 *              что поставила эта операция; откат не удался — FAIL (неясно);
 *   снятие:    для каждой стороны -C/-D, пока -C не скажет «нет»; сняли хоть
 *              одно — OK, нечего было — GONE, сбой — FAIL;
 *   уборка:    -N (есть — ладно) и -F своих цепочек обоих семейств. */

typedef struct {
    const char *chain_out, *chain_in;   /* свои цепочки mangle */
    unsigned queue;                     /* NFQUEUE d2kd */
    unsigned lock_wait_s;               /* срок ожидания блокировки xtables */
    /* Форма срока: 0 — не определена, 1 — «--wait=N» (iptables ≥ 1.6; раздельное
       «-w N» сроком не считается — ждал бы без конца), 2 — простое «-w» (старый
       iptables не знает --wait=N, код 2: ждёт без срока, только поток исполнителя). */
    int wait_form;
    /* Запуск argv (NULL-терминированного); код выхода, -1 — не запустился. */
    int (*run)(void *ctx, char *const argv[]);
    void *ctx;
} d2k_lwrules;

/* Итоги — как у d2k_lw_done.rc: 0 OK, 1 GONE, -1 FAIL. */
int d2k_lwrules_install(d2k_lwrules *r, const d2k_ct_tuple *t);
int d2k_lwrules_clear(d2k_lwrules *r, const d2k_ct_tuple *t);
int d2k_lwrules_sweep(d2k_lwrules *r);

/* Настоящий запуск (fork+exec на Linux, posix_spawn иначе). ctx — NULL или
 * указатель на unsigned: внешний срок потомка в секундах (0 — без срока). Срок
 * вышел — потомок убивается (SIGKILL), итог -1: старый iptables (простое -w)
 * иначе ждал бы блокировку без конца, срок держит сам исполнитель. */
int d2k_lwrules_spawn(void *ctx, char *const argv[]);

#endif
