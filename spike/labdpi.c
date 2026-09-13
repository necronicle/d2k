/* labdpi.c — ИГРУШЕЧНЫЙ, НО С ПАМЯТЬЮ: цензор, который собирает поток.
 *
 * Зачем нужен, если есть правило `iptables -m string`. Строковое правило
 * смотрит на ОДИН пакет, и его обходит любой разрез: имя разнесено между
 * сегментами — целой строки нет ни в одном пакете. Настоящий DPI так себя не
 * ведёт: он собирает поток по номерам последовательности и ищет имя в
 * СОБРАННОМ. Против такого разрез сам по себе не работает — работает семья
 * фальшивок, и ровно её лаборатория до сих пор не проверяла ВООБЩЕ.
 *
 * Что здесь смоделировано, и почему именно так:
 *
 *   СБОРКА ПО НОМЕРАМ. Байты кладутся по смещению seq − base_seq, а не в
 *   порядке прихода: иначе переупорядочивание сегментов «обходило» бы цензора
 *   по причине, не имеющей отношения к цензуре.
 *
 *   ПЕРВЫЙ ПИШУЩИЙ ВЫИГРЫВАЕТ. При перекрытии более поздняя копия байта
 *   отбрасывается. Это не произвол: именно на таком поведении держится вся
 *   семья фальшивок — подделка занимает смещения РАНЬШЕ настоящего
 *   приветствия, и собранный коробкой поток содержит подделку, а не правду.
 *   Коробка, берущая последнюю копию, этим приёмом не обходится, и её модель
 *   была бы ДРУГИМ опытом (ключ --last).
 *
 *   РАССТОЯНИЕ ДО КОРОБКИ. Коробка стоит не вплотную к серверу, и пакет с
 *   укороченным TTL до сервера не доходит, хотя коробка его видит. В петле
 *   хопов нет вовсе, поэтому расстояние эмулируется прямо здесь: пакет с
 *   TTL <= hops коробка ОСМАТРИВАЕТ (он отравляет её сборку) и роняет —
 *   ровно то, что делает настоящая сеть.
 *
 * Это НЕ часть продукта и не участвует в сборке d2k. Живёт в spike/ вместе с
 * остальными вспомогательными стендами.
 */
#define _DEFAULT_SOURCE 1
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "d2k_nfq.h"
#include "d2k_nl.h"
#include "d2k_quic.h"

#define NF_DROP   0u
#define NF_ACCEPT 1u

#define FLOWS   256
#define WINDOW  8192

typedef struct {
    int      used;
    uint8_t  a_ip[4], b_ip[4];
    uint16_t a_port, b_port;
    uint32_t base_seq;
    int      have_base;
    int      blocked;
    uint8_t  seen[WINDOW];   /* байт уже занят */
    uint8_t  data[WINDOW];
    size_t   high;           /* докуда дотянулась сборка */
} flow;

static flow flows[FLOWS];
static unsigned long long n_seen, n_dropped_name, n_dropped_ttl, n_pass;

static flow *flow_of(const uint8_t *ip, const uint8_t *tcp) {
    for (size_t i = 0; i < FLOWS; i++) {
        flow *f = &flows[i];
        if (!f->used) { continue; }
        if (memcmp(f->a_ip, ip + 12, 4) == 0 && memcmp(f->b_ip, ip + 16, 4) == 0 &&
            f->a_port == (uint16_t)((uint16_t)tcp[0] << 8 | tcp[1]) &&
            f->b_port == (uint16_t)((uint16_t)tcp[2] << 8 | tcp[3])) {
            return f;
        }
    }
    for (size_t i = 0; i < FLOWS; i++) {
        flow *f = &flows[i];
        if (f->used) { continue; }
        memset(f, 0, sizeof *f);
        f->used = 1;
        memcpy(f->a_ip, ip + 12, 4);
        memcpy(f->b_ip, ip + 16, 4);
        f->a_port = (uint16_t)((uint16_t)tcp[0] << 8 | tcp[1]);
        f->b_port = (uint16_t)((uint16_t)tcp[2] << 8 | tcp[3]);
        return f;
    }
    return NULL;   /* мест нет: цензор честно слепнет, а не выдумывает */
}

/* Сдвигает сборку назад: пришёл кусок РАНЬШЕ того, с которого начали.
 *
 * Без этого переупорядочивание сегментов «обходило» бы цензора даром: первый
 * пришедший кусок задавал бы начало, а всё, что до него, улетало бы за окно.
 * Настоящая коробка знает начало потока от SYN и такой ошибки не делает —
 * значит и модель не должна. */
static void rebase(flow *f, uint32_t new_base) {
    uint32_t shift = f->base_seq - new_base;
    if (shift == 0 || shift >= WINDOW) { return; }
    memmove(f->data + shift, f->data, WINDOW - shift);
    memmove(f->seen + shift, f->seen, WINDOW - shift);
    memset(f->data, 0, shift);
    memset(f->seen, 0, shift);
    f->base_seq = new_base;
    f->high += shift;
    if (f->high > WINDOW) { f->high = WINDOW; }
}

/* Кладёт кусок в сборку. Первый пишущий выигрывает — см. шапку. */
static void place(flow *f, uint32_t seq, const uint8_t *p, size_t len, int last_wins) {
    if (!f->have_base) { f->base_seq = seq; f->have_base = 1; }
    else if ((int32_t)(seq - f->base_seq) < 0) { rebase(f, seq); }
    uint32_t off = seq - f->base_seq;
    if (off >= WINDOW) { return; }         /* за окном — не наше дело */
    size_t n = len;
    if (off + n > WINDOW) { n = WINDOW - off; }
    for (size_t i = 0; i < n; i++) {
        if (!f->seen[off + i] || last_wins) {
            f->data[off + i] = p[i];
            f->seen[off + i] = 1;
        }
    }
    if (off + n > f->high) { f->high = off + n; }
}

static int found_name(const flow *f, const char *name) {
    size_t nl = strlen(name);
    if (f->high < nl) { return 0; }
    for (size_t i = 0; i + nl <= f->high; i++) {
        if (memcmp(f->data + i, name, nl) == 0) { return 1; }
    }
    return 0;
}

/* ---------------------------------------------------------------------
 * КОРОБКА, СМОТРЯЩАЯ ТОЛЬКО ПЕРВУЮ ДАТАГРАММУ ПОТОКА (--first).
 *
 * Это не поблажка нам, а ВТОРАЯ настоящая конструкция, и ради неё в каталоге
 * плеч вообще есть приманки: коробка, которая заводит состояние на пятёрку и
 * разбирает ПЕРВУЮ датаграмму, обманывается мусором, посланным перед
 * приветствием. Коробка без состояния (умолчание здесь) разбирает каждую
 * датаграмму и мусором не обманывается вовсе.
 *
 * Обе существуют в природе, и лаборатория обязана уметь показать обе: на
 * одной вертикаль ДОЛЖНА найти обход, на другой — честно сказать, что не
 * нашла. Один и тот же ответ на оба стенда означал бы, что стенд не
 * различает коробки.
 * --------------------------------------------------------------------- */
#define UFLOWS 256

typedef struct {
    int      used;
    uint32_t sip, dip;
    uint16_t sport, dport;
    int      decided;   /* первая датаграмма уже разобрана */
    int      blocked;   /* и разобрана как «наше имя» — поток закрыт целиком */
} uflow;

static uflow g_uflows[UFLOWS];

static uflow *uflow_of(uint32_t sip, uint16_t sport, uint32_t dip, uint16_t dport) {
    uflow *free_slot = NULL;
    for (size_t i = 0; i < UFLOWS; i++) {
        uflow *f = &g_uflows[i];
        if (!f->used) { if (!free_slot) { free_slot = f; } continue; }
        if (f->sip == sip && f->dip == dip && f->sport == sport && f->dport == dport) {
            return f;
        }
    }
    if (!free_slot) { return NULL; }   /* таблица полна — коробка просто смотрит всё */
    free_slot->used = 1;
    free_slot->sip = sip; free_slot->dip = dip;
    free_slot->sport = sport; free_slot->dport = dport;
    free_slot->decided = 0;
    free_slot->blocked = 0;
    return free_slot;
}

static uint32_t rd32be(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static uint16_t rd16be(const uint8_t *p) { return (uint16_t)((uint16_t)p[0] << 8 | p[1]); }

static volatile sig_atomic_t stop_now;
static void on_stop(int s) { (void)s; stop_now = 1; }

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "использование: labdpi <очередь> <имя> <хопов> [--last] [--quic] [--first]\n");
        return 2;
    }
    uint16_t queue = (uint16_t)atoi(argv[1]);
    const char *name = argv[2];
    int hops = atoi(argv[3]);
    int last_wins = 0, quic_mode = 0, first_only = 0;
    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "--last") == 0) { last_wins = 1; }
        if (strcmp(argv[i], "--quic") == 0) { quic_mode = 1; }
        if (strcmp(argv[i], "--first") == 0) { first_only = 1; }
    }

    signal(SIGINT, on_stop);
    signal(SIGTERM, on_stop);

    d2k_nfq_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.queue = queue;
    cfg.copy_range = 2000;
    cfg.maxlen = 1024;
    cfg.fail_open = 1;
    char err[200];
    d2k_nfq *q = d2k_nfq_open(&cfg, err, sizeof err);
    if (!q) { fprintf(stderr, "labdpi: очередь не открылась: %s\n", err); return 1; }
    printf("labdpi: очередь %u, имя \"%s\", коробка в %d хопах, перекрытие: %s\n",
           (unsigned)queue, name, hops, last_wins ? "последний" : "первый");
    fflush(stdout);

    static uint8_t buf[65536];
    while (!stop_now) {
        ssize_t n = d2k_nfq_recv(q, buf, sizeof buf, err, sizeof err);
        if (n == 0) { continue; }
        if (n < 0) { if (n == -2) { continue; } break; }
        d2k_nl_iter it;
        d2k_nl_iter_init(&it, buf, (size_t)n);
        d2k_nl_msg m;
        while (d2k_nl_next(&it, &m)) {
            d2k_nl_pkt p;
            if (d2k_nl_packet(&m, &p) != 0 || !p.have_hdr) { continue; }
            uint32_t verdict = NF_ACCEPT;
            /* QUIC: имя лежит в ЗАШИФРОВАННОМ Initial, и настоящая коробка
               достаёт его ровно так же, как мы — ключами, выведенными из
               идентификатора соединения, который лежит открытым текстом
               (RFC 9001 §5.2). Никакой сборки потока здесь не нужно: у
               датаграммы её нет, и весь смысл плеча QUIC в том, чтобы имя
               в собранном коробкой Initial оказалось не тем. */
            if (quic_mode && p.have_payload && !p.truncated && p.payload_len >= 28 &&
                (p.payload[0] >> 4) == 4 && p.payload[9] == 17) {
                const uint8_t *ip = p.payload;
                size_t ihl = (size_t)(ip[0] & 0x0F) * 4;
                if (ihl >= 20 && p.payload_len > ihl + 8) {
                    const uint8_t *udp = ip + ihl;
                    size_t plen = p.payload_len - ihl - 8;
                    n_seen++;
                    int look = 1;
                    uflow *f = NULL;
                    if (first_only) {
                        f = uflow_of(rd32be(ip + 12), rd16be(udp + 0),
                                     rd32be(ip + 16), rd16be(udp + 2));
                        if (f) { look = !f->decided; }
                    }
                    char sni[256];
                    int matched = look &&
                                  d2k_quic_is_initial(udp + 8, plen) &&
                                  d2k_quic_sni(udp + 8, plen, sni, sizeof sni) == 0 &&
                                  strcmp(sni, name) == 0;
                    if (f) {
                        /* ОСТАТОЧНАЯ БЛОКИРОВКА. Коробка, решившая «это наше
                           имя», закрывает ПОТОК, а не одну датаграмму: иначе
                           повтор Initial по таймеру PTO прошёл бы следом, и
                           блокировка не была бы блокировкой. Решение
                           «не наше» закрывает вопрос навсегда в другую
                           сторону — на это и рассчитана приманка. */
                        if (!f->decided) { f->decided = 1; f->blocked = matched; }
                        matched = f->blocked;
                    }
                    if (matched) {
                        verdict = NF_DROP;
                        n_dropped_name++;
                    } else if (ip[8] <= (uint8_t)hops) {
                        /* Смерть по TTL — это СЕТЬ, а не решение коробки, и
                           она случается независимо от того, смотрела коробка
                           эту датаграмму или уже приняла решение по потоку. */
                        verdict = NF_DROP;
                        n_dropped_ttl++;
                    } else {
                        n_pass++;
                    }
                }
                (void)d2k_nfq_verdict(q, p.id, verdict, err, sizeof err);
                continue;
            }
            if (p.have_payload && !p.truncated && p.payload_len >= 40 &&
                (p.payload[0] >> 4) == 4 && p.payload[9] == 6) {
                const uint8_t *ip = p.payload;
                size_t ihl = (size_t)(ip[0] & 0x0F) * 4;
                if (ihl >= 20 && p.payload_len > ihl + 20) {
                    const uint8_t *tcp = ip + ihl;
                    size_t doff = (size_t)(tcp[12] >> 4) * 4;
                    if (doff >= 20 && p.payload_len >= ihl + doff) {
                        n_seen++;
                        flow *f = flow_of(ip, tcp);
                        size_t plen = p.payload_len - ihl - doff;
                        uint32_t seq = (uint32_t)tcp[4] << 24 | (uint32_t)tcp[5] << 16 |
                                       (uint32_t)tcp[6] << 8 | tcp[7];
                        /* Начало потока берётся у SYN, как у настоящей коробки:
                           иначе началом станет первый ПРИШЕДШИЙ кусок, и
                           обратный порядок сегментов обошёл бы сборку даром. */
                        if (f && (tcp[13] & 0x02) && !(tcp[13] & 0x10)) {
                            f->base_seq = seq + 1;
                            f->have_base = 1;
                        }
                        if (f && plen > 0) {
                            place(f, seq, tcp + doff, plen, last_wins);
                            if (!f->blocked && found_name(f, name)) {
                                f->blocked = 1;
                            }
                        }
                        if (f && f->blocked) {
                            verdict = NF_DROP;
                            n_dropped_name++;
                        } else if (ip[8] <= (uint8_t)hops) {
                            /* Коробка это ВИДЕЛА (сборка уже отравлена), но до
                               сервера пакет не доживёт: расстояние. */
                            verdict = NF_DROP;
                            n_dropped_ttl++;
                        } else {
                            n_pass++;
                        }
                    }
                }
            }
            (void)d2k_nfq_verdict(q, p.id, verdict, err, sizeof err);
        }
    }
    printf("labdpi: пакетов %llu, снято по имени %llu, снято по расстоянию %llu, пропущено %llu\n",
           n_seen, n_dropped_name, n_dropped_ttl, n_pass);
    d2k_nfq_close(q);
    return 0;
}
