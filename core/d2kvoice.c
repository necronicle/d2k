/* d2kvoice.c — командная утилита: померить голосовой поток на живой линии.
 *
 * ОТДЕЛЬНОЙ УТИЛИТОЙ, А НЕ РЕЖИМОМ d2kask, и причина не в удобстве. У d2kask
 * весь разбор аргументов построен вокруг ИМЕНИ цели (снимок приветствия,
 * контрольное имя, каталог), а у голоса имени нет вовсе — ни ввести, ни
 * подставить в контроль. Свести их значило бы завести у d2kask ветку, где
 * половина ключей запрещена, и первый же человек эту половину всё равно
 * передал бы. Оригинал развёл их по той же причине (cmd/z2k-detect/voice.go).
 *
 * СВОЕГО ЗАМЕРА ЗДЕСЬ НЕТ НИ СТРОКИ: всё считает d2k_voice_run (core/voice.c),
 * здесь только разбор argv и печать. Вторая реализация замера рядом с первой
 * рано или поздно разойдётся с ней — в этом проекте это уже случалось.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "d2k_net4.h"
#include "d2k_voice.h"

static void usage(void) {
    fprintf(stderr,
        "использование: d2kvoice [--addr IP:ПОРТ] [--control ХОСТ:ПОРТ] [--blobs КАТАЛОГ]\n"
        "                        [--conntrack ФАЙЛ] [--wait МС] [--mark 0x2d] [--list]\n"
        "  --addr       мерить этот адрес вместо поиска живого разговора\n"
        "  --control    публичный STUN для проверки, что UDP на канале ходит\n"
        "               (умолчание " D2K_VOICE_CONTROL_DEFAULT ")\n"
        "  --conntrack  таблица соединений (умолчание /proc/net/nf_conntrack)\n"
        "  --wait       сколько ждать ответа, мс (умолчание 3000)\n"
        "  --mark       метка SO_MARK для зондов; без неё замер про наш же обход\n"
        "  --list       только показать найденные разговоры и выйти\n"
        "\n"
        "У голоса нет имени: сервер выдаётся на сессию и в публичном DNS его нет.\n"
        "Поэтому адрес берётся из ИДУЩЕГО разговора — сначала позвоните.\n");
}

static int split_hostport(const char *s, char *host, size_t hcap, unsigned long *port) {
    const char *colon = strrchr(s, ':');
    if (!colon || colon == s) { return -1; }
    size_t hl = (size_t)(colon - s);
    if (hl >= hcap) { return -1; }
    memcpy(host, s, hl);
    host[hl] = '\0';
    *port = strtoul(colon + 1, NULL, 10);
    return (*port > 0 && *port <= 65535) ? 0 : -1;
}

static const char *verdict_word(d2k_voice_verdict v) {
    switch (v) {
    case D2K_VOICE_CLEAR:   return "резать нечего";
    case D2K_VOICE_BLOCKED: return "режут этот поток";
    case D2K_VOICE_NO_UDP:  return "UDP не ходит вовсе";
    case D2K_VOICE_NO_CALL: return "мерить нечего";
    case D2K_VOICE_FLAKY:   return "не воспроизводится";
    case D2K_VOICE_NO_ORACLE: return "мерить этим зондом нечем";
    case D2K_VOICE_UNMEASURED: return "измерение не закончено";
    }
    return "неизвестный вердикт";
}

int main(int argc, char **argv) {
    d2k_voice_opt o;
    memset(&o, 0, sizeof o);
    int list_only = 0;

    for (int i = 1; i < argc; i++) {
        const char *f = argv[i];
        if (strcmp(f, "--addr") == 0 && i + 1 < argc) {
            char host[64];
            unsigned long p = 0;
            if (split_hostport(argv[++i], host, sizeof host, &p) != 0 ||
                d2k_ip4_parse(host, &o.ip) != 0) {
                fprintf(stderr, "d2kvoice: --addr обязан быть IP:ПОРТ (имени у голоса нет)\n");
                return 2;
            }
            o.port = (uint16_t)p;
        } else if (strcmp(f, "--control") == 0 && i + 1 < argc) { o.control = argv[++i]; }
        else if (strcmp(f, "--conntrack") == 0 && i + 1 < argc) { o.ct_path = argv[++i]; }
        else if (strcmp(f, "--wait") == 0 && i + 1 < argc) {
            o.wait_ms = (uint32_t)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(f, "--mark") == 0 && i + 1 < argc) {
            o.mark = (uint32_t)strtoul(argv[++i], NULL, 0);
        } else if (strcmp(f, "--list") == 0) { list_only = 1; }
        else { usage(); return 2; }
    }

    if (list_only) {
        d2k_voice_target t[D2K_VOICE_MAX_TARGETS];
        size_t n = d2k_voice_targets(o.ct_path, t, D2K_VOICE_MAX_TARGETS);
        if (n == 0) {
            printf("Живых разговоров не видно. Начните звонок и повторите.\n");
            return 1;
        }
        printf("Живые разговоры (по убыванию нагрузки):\n");
        for (size_t i = 0; i < n; i++) {
            char a[24];
            d2k_ip4_text(t[i].ip, a, sizeof a);
            char c[24];
            d2k_ip4_text(t[i].src_ip, c, sizeof c);
            printf("  %s:%u  <- %s:%u  пакетов %d%s\n", a, t[i].port, c, t[i].sport,
                   t[i].packets, t[i].replied ? "" : "  (ответов нет)");
        }
        return 0;
    }

    d2k_voice_res r = d2k_voice_run(&o);

    if (r.ip) {
        char a[24];
        d2k_ip4_text(r.ip, a, sizeof a);
        printf("Разговор:  %s:%u\n", a, r.port);
    }
    printf("Вердикт:   %s — %s\n", verdict_word(r.verdict), r.reason);
    if (r.probes > 0) {
        printf("Зондов:    %d (по %d повтора)\n", r.probes, D2K_VOICE_REPEATS);
    }
    if (!r.marked) {
        printf("ВНИМАНИЕ:  сокет не помечен — замер прошёл через наш же обход и недостоверен\n");
    }
    if (r.strategy[0]) {
        printf("\nПриём:     %s\n", r.strategy);
        printf("           (вставлять на вкладке «Свои стратегии» в пул «Дискорд, голос»)\n");
    } else if (r.verdict == D2K_VOICE_BLOCKED) {
        printf("\nПриём:     не найдено ни одной фальшивки, которая пробивает\n");
    }
    return (r.verdict == D2K_VOICE_CLEAR) ? 0 : 1;
}
