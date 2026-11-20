/* test_ctl.c — управляющий сокет, на настоящем сокете.
 *
 * AF_UNIX работает и на маке, поэтому здесь ничего не подделывается: тот же
 * код, что пойдёт на роутер, разговаривает с настоящим клиентом.
 *
 * Проверяется прежде всего то, что ломает поток: кадр, пришедший по кускам;
 * два кадра в одной записи; врущая длина; исчезнувший собеседник. Разбор
 * потока — место, где ошибка не видна до тех пор, пока не станет поздно.
 */
#define _POSIX_C_SOURCE 200809L

#include "test_nat_stub.h"
#include "d2k_nat.h"
#include "d2k_lateobs.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#include "d2k_ctl.h"
#include "d2k_crypto.h"
#include "../runtime/d2k_runtime.h"
#include "d2k_ctlsrv.h"
#include "d2k_rawmeasure_wire.h"
#include "d2k_http80.h"
#include "d2k_plan.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

static char SOCK[108];

static void check_execution(const uint8_t *p, const d2k_result *r) {
    uint64_t id = 0, generation = 0;
    for (unsigned b = 0; b < 8; b++) {
        id = id * 256 + p[b];
        generation = generation * 256 + p[8+b];
    }
    CHECK(id == r->execution_id && generation == r->binding.generation,
          "wire fate lost its original execution/generation");
    CHECK(p[16] == r->binding.kind && p[17] == r->binding.family &&
          p[18] == r->binding.shape && p[19] == r->binding.temporary,
          "wire fate lost binding context");
    CHECK(!memcmp(p+20, r->binding.epoch, sizeof r->binding.epoch),
          "late wire fate lost original table epoch");
}

static int dial(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    strcpy(sa.sun_path, SOCK);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Собранные обратным вызовом команды. */
static struct { uint16_t type; size_t len; uint8_t body[64]; } got[8];
static size_t n_got;

/* Ждёт, пока из потока соберётся заданное число ЦЕЛЫХ кадров.
 *
 * d2k_ctl_poll делает РОВНО ОДНО чтение за вызов и возвращает столько кадров,
 * сколько собралось из накопленного; датапат зовёт его в цикле. Кадр в
 * полторы тысячи байт ядро вправе отдать по кускам, и проверка «poll() == 1»
 * тогда проходит или падает в зависимости от нарезки потока, а не от
 * поведения кода. Поймано полным гейтом 13.09.2026: отдельным запуском тест
 * проходил сорок раз подряд, внутри гейта упал.
 *
 * Предел кругов нужен затем, чтобы сломанный разбор не превратился в вечный
 * цикл: сокет неблокирующий, и при пустом чтении poll возвращает ноль сразу.
 * Отрицательный ответ (разрыв) отдаётся как есть — он проверяется отдельно. */
static int poll_frames(d2k_ctl *c,
                       void (*cb)(void *ctx, uint16_t type, const uint8_t *body, size_t len),
                       void *ctx, int want) {
    int got_n = 0;
    for (int i = 0; i < 1000 && got_n < want; i++) {
        int n = d2k_ctl_poll(c, cb, ctx);
        if (n < 0) { return n; }
        got_n += n;
    }
    return got_n;
}

static void on_cmd(void *ctx, uint16_t type, const uint8_t *body, size_t len) {
    (void)ctx;
    if (n_got >= 8) {
        return;
    }
    got[n_got].type = type;
    got[n_got].len = len;
    if (len <= sizeof got[0].body) {
        memcpy(got[n_got].body, body, len);
    }
    n_got++;
}

static void frame(uint8_t *o, uint16_t type, const uint8_t *body, size_t len) {
    uint32_t plen = (uint32_t)(2 + len);
    o[0] = (uint8_t)(plen >> 24); o[1] = (uint8_t)(plen >> 16);
    o[2] = (uint8_t)(plen >> 8);  o[3] = (uint8_t)plen;
    o[4] = (uint8_t)(type >> 8);  o[5] = (uint8_t)type;
    if (len) {
        memcpy(o + 6, body, len);
    }
}

/* Читает один кадр D2K_EV_ACK целиком и разбирает тело: тип подтверждаемой
 * команды, признак успеха, код причины (см. d2k_ctl.h). Кадр ACK — фиксированной
 * длины (ключ нулевой, но место под него есть у всех событий одинаково), так
 * что read() одним вызовом на весь кадр — не подгонка под этот тест, а свойство
 * формата. Возвращает 1, если прочитан целый и это действительно ACK. */
static uint8_t last_ack_id[D2K_TRIAL_ID_LEN];
static int read_ack(int fd, uint16_t *cmd, int *ok, uint8_t *reason) {
    uint8_t hdr[6], body[128];
    size_t got = 0;
    while (got < sizeof hdr) {
        ssize_t n = read(fd, hdr + got, sizeof hdr - got);
        if (n > 0) { got += (size_t)n; continue; }
        return 0;
    }
    uint32_t frame_len = (uint32_t)hdr[0] << 24 | (uint32_t)hdr[1] << 16 |
                         (uint32_t)hdr[2] << 8 | hdr[3];
    if (frame_len < 2 || frame_len - 2 > sizeof body) { return 0; }
    size_t body_len = frame_len - 2;
    /* Тело одним recv(MSG_WAITALL): потоковый UNIX-сокет. Цикл read() по
       body + got glibc-фортификация GCC 13 (Ubuntu 24.04, x86-64) считала
       записью «до SSIZE_MAX байт» в body[128] и роняла сборку под -Werror. */
    if (body_len && recv(fd, body, body_len, MSG_WAITALL) != (ssize_t)body_len) {
        return 0;
    }
    uint16_t type = (uint16_t)((hdr[4] << 8) | hdr[5]);
    if (type != D2K_EV_ACK) {
        return 0;
    }
    if (body_len < D2K_KEY_WIRE_LEN + 4) { return 0; }
    *cmd = (uint16_t)((body[D2K_KEY_WIRE_LEN] << 8) | body[D2K_KEY_WIRE_LEN + 1]);
    *ok = body[D2K_KEY_WIRE_LEN + 2];
    *reason = body[D2K_KEY_WIRE_LEN + 3];
    memset(last_ack_id,0,sizeof last_ack_id);
    if(body_len>=D2K_KEY_WIRE_LEN+4+D2K_TRIAL_ID_LEN)
        memcpy(last_ack_id,body+D2K_KEY_WIRE_LEN+4,sizeof last_ack_id);
    return 1;
}

/* Тело команды SET_NAME: [длина имени u8][имя][план TLV]. */
/* Тело SET_NAME: [длина имени][имя][ФОРМА][план]. Форма байтом перед планом
   — длина плана в теле не объявлена, и поле после него было бы съедено как
   его часть (см. d2k_link.h). Дедушкино право здесь потому, что эти
   проверки про разбор команды, а не про ограничение по форме: оно проверяется
   отдельно, ниже. */
/* Этап 17: записывающие крючки точных проб. */
static int hook_addr_calls, hook_name_calls;
static struct { d2k_addr_probe_flow flow; uint64_t expires_ns; int installed; } hook_addr_last;
static struct { uint8_t name[64]; size_t len; uint8_t transport, family; uint16_t sport_be; int installed; } hook_name_last;
static void rec_addr_hook(void *ctx, const d2k_addr_probe_flow *flow, uint64_t expires_ns, int installed) {
    (void)ctx; hook_addr_calls++;
    hook_addr_last.flow = *flow; hook_addr_last.expires_ns = expires_ns; hook_addr_last.installed = installed;
}
static void rec_name_hook(void *ctx, const uint8_t *name, size_t len, uint8_t transport, uint8_t family,
                          uint16_t sport_be, uint64_t expires_ns, int installed) {
    (void)ctx; (void)expires_ns; hook_name_calls++;
    if (len > sizeof hook_name_last.name) len = sizeof hook_name_last.name;
    memcpy(hook_name_last.name, name, len); hook_name_last.len = len;
    hook_name_last.transport = transport; hook_name_last.family = family;
    hook_name_last.sport_be = sport_be; hook_name_last.installed = installed;
}

static size_t set_name_body_shaped(uint8_t *body, const char *name,
                                   const uint8_t *plan, size_t planlen,
                                   uint8_t shape) {
    size_t nl = strlen(name);
    body[0] = (uint8_t)nl;
    memcpy(body + 1, name, nl);
    body[1 + nl] = shape;
    body[2 + nl] = 4;
    memcpy(body + 3 + nl, plan, planlen);
    return 3 + nl + planlen;
}

static size_t set_name_body(uint8_t *body, const char *name,
                            const uint8_t *plan, size_t planlen) {
    return set_name_body_shaped(body, name, plan, planlen, D2K_PLAN_SHAPE_GRANDFATHER);
}

/* Минимальный годный план: только порядок. Общий для обоих блоков разбора
   команд ниже (заполнение таблицы и проверка давности) — раньше жил внутри
   первого, локальной static-переменной. */
static const uint8_t tiny[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 1,
    0x01, 0x03, 0x00, 0x01, 0x00
};

/* Тот же минимальный план плюс запись REC_ID (тип 0x0001, длина 16) — записей
   в заголовке поэтому две. Идентификатор нарочно НЕпечатный (0xA0..0xAF): он
   двоичный, и путь от разбора плана до провода не имеет права его чистить под
   печать — дорога через поле имени журнала заменила бы каждый такой байт
   точкой (journal.c), и проверка печатным идентификатором прошла бы мимо
   этого. */
static const uint8_t want_id[16] = {
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};
static const uint8_t plan_with_id[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 2,
    0x00, 0x01, 0x00, 0x10,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0x01, 0x03, 0x00, 0x01, 0x00
};

static void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

/* Приветствие TLS с заданным именем и несущий его пакет. Собираются здесь, а
   не берутся готовыми: разбирать их будет настоящий tls.c настоящим пакетным
   путём — план обязан примениться так же, как на роутере, иначе события
   применения взяться неоткуда. Те же сборщики, что в ctlprobe.c и
   test_session.c. */
static size_t build_hello(uint8_t *out, const char *sni) {
    uint8_t body[512];
    size_t b = 0;
    body[b++] = 0x03; body[b++] = 0x03;
    for (int i = 0; i < 32; i++) { body[b++] = (uint8_t)i; }
    body[b++] = 0;
    body[b++] = 0x00; body[b++] = 0x02; body[b++] = 0x13; body[b++] = 0x01;
    body[b++] = 0x01; body[b++] = 0x00;

    size_t nl = strlen(sni);
    uint8_t ext[320];
    size_t e = 0;
    ext[e++] = 0x00; ext[e++] = 0x00;
    ext[e++] = 0x00; ext[e++] = (uint8_t)(5 + nl);
    ext[e++] = 0x00; ext[e++] = (uint8_t)(3 + nl);
    ext[e++] = 0x00;
    ext[e++] = 0x00; ext[e++] = (uint8_t)nl;
    memcpy(ext + e, sni, nl); e += nl;
    body[b++] = 0x00; body[b++] = (uint8_t)e;
    memcpy(body + b, ext, e); b += e;

    size_t o = 0;
    out[o++] = 0x16; out[o++] = 0x03; out[o++] = 0x01;
    out[o++] = (uint8_t)((b + 4) >> 8); out[o++] = (uint8_t)(b + 4);
    out[o++] = 0x01; out[o++] = 0x00;
    out[o++] = (uint8_t)(b >> 8); out[o++] = (uint8_t)b;
    memcpy(out + o, body, b); o += b;
    return o;
}

static size_t build_pkt(uint8_t *o, uint16_t sport, const uint8_t *pay, size_t paylen) {
    size_t total = 20 + 20 + paylen;
    memset(o, 0, 40);
    o[0] = 0x45;
    wr16(o + 2, (uint16_t)total);
    o[8] = 64;
    o[9] = 6;
    uint8_t lan[4] = {192, 168, 1, 67}, wan[4] = {93, 184, 216, 34};
    memcpy(o + 12, lan, 4);
    memcpy(o + 16, wan, 4);
    wr16(o + 20, sport);
    wr16(o + 22, 443);
    wr32(o + 24, 1000);
    wr32(o + 28, 2000);
    o[32] = 0x50;
    o[33] = 0x18;
    wr16(o + 34, 64240);
    if (paylen) {
        memcpy(o + 40, pay, paylen);
    }
    return total;
}

static int read_exact(int fd, uint8_t *b, size_t n) {
    size_t have = 0;
    while (have < n) {
        ssize_t r = read(fd, b + have, n - have);
        if (r <= 0) {
            return -1;
        }
        have += (size_t)r;
    }
    return 0;
}

/* Читает ОДИН кадр события целиком: заголовок, потом ровно объявленное число
 * байт тела. Одним read() здесь не обойтись, в отличие от read_ack выше: pump
 * выкладывает подряд несколько событий, и «сколько отдал сокет» не равно
 * «сколько в кадре». Возвращает длину тела, -1 при обрыве или тайм-ауте
 * приёма (его ставит вызывающий через SO_RCVTIMEO — иначе непришедшее событие
 * означало бы вечное ожидание вместо провала). */
static ssize_t read_event(int fd, uint16_t *type, uint8_t *body, size_t cap) {
    uint8_t hdr[6];
    if (read_exact(fd, hdr, sizeof hdr) != 0) {
        return -1;
    }
    uint32_t plen = (uint32_t)hdr[0] << 24 | (uint32_t)hdr[1] << 16 |
                    (uint32_t)hdr[2] << 8 | hdr[3];
    if (plen < 2 || (size_t)(plen - 2) > cap) {
        return -1;
    }
    *type = (uint16_t)((hdr[4] << 8) | hdr[5]);
    size_t blen = (size_t)plen - 2;
    if (blen && read_exact(fd, body, blen) != 0) {
        return -1;
    }
    return (ssize_t)blen;
}

/* Версия провода приезжает ПЕРВЫМ событием после подключения.
 *
 * Провод менялся несовместимо дважды за один день (код APPLIED, формат тела
 * SET_NAME), и смешанная пара при этом не падает — она молча не даёт
 * подтверждений. Процедурной защиты мало: она бережёт от невнимательности, но
 * не от незнания. Здесь проверяется, что версия объявляется вообще и что
 * объявляется ИМЕННО она. */
/* Счётчики (D2K_EV_STATS) — тем же ключом, что и прочие события без потока.
 * Контроллер отвергает кадр с неизвестным семейством ключа (link.c), и до
 * 28.10.2026 d2kd слал STATS с нулевым первым байтом: каждый кадр отвергался,
 * dropped_seen у контроллера не менялся никогда, и потерянный датапатом
 * обмен выглядел как провал плана (ровно то, от чего STATS и заведён).
 * Найдено на Linux-стенде lab-pair после того, как d2kc стал называть
 * отвергнутые события (очередь 28.10, задания 02/09). */
static void check_stats_event(void) {
    unlink(SOCK);
    char err[160];
    d2k_ctl *c = d2k_ctl_open(SOCK, err, sizeof err);
    CHECK(c != NULL, "сокет для проверки счётчиков не создался");
    if (!c) { return; }
    int cli = dial();
    CHECK(cli >= 0, "клиент для проверки счётчиков не подключился");
    d2k_ctl_accept(c);
    d2k_ctlsrv_greet(c, 1500u);
    d2k_session *overflow = d2k_session_new(4, 1);
    CHECK(overflow != NULL, "journal overflow session");
    uint64_t seen = 0;
    if (overflow) {
        d2k_journal *journal = (d2k_journal *)d2k_session_journal(overflow);
        for (unsigned i=0;i<3;i++)
            d2k_journal_add(journal,i,NULL,255,0,0,NULL,NULL,0,NULL);
        d2k_ctlsrv_pump(c,overflow,&seen);
        CHECK(d2k_ctl_dropped(c)==2,"journal overwrite missing from delivery loss counter");
        d2k_ctlsrv_pump(c,overflow,&seen);
        CHECK(d2k_ctl_dropped(c)==2,"journal loss counted twice");
        d2k_journal_add(journal,4,NULL,255,0,0,NULL,NULL,0,NULL);
        d2k_ctlsrv_pump(c,overflow,&seen);
        CHECK(d2k_ctl_dropped(c)==2,"delivered journal history counted as lost");
        d2k_session_free(overflow);
    }
    d2k_ctlsrv_stats(c);
    d2k_ctl_flush(c);
    uint16_t type = 0;
    uint8_t ev[160];
    ssize_t n = read_event(cli, &type, ev, sizeof ev);
    CHECK(n > 0 && type == D2K_EV_PROTO, "перед счётчиками должна прийти версия");
    n = read_event(cli, &type, ev, sizeof ev);
    CHECK(n == (ssize_t)(D2K_KEY_WIRE_LEN + 8) && type == D2K_EV_STATS,
          "счётчики не приехали телом «ключ + 4 байта потерь + 4 байта отправленных»");
    if (n == (ssize_t)(D2K_KEY_WIRE_LEN + 8)) {
        CHECK(ev[0] == 4, "ключ события счётчиков без семейства — контроллер такой кадр отвергает");
        uint32_t dropped = (uint32_t)ev[D2K_KEY_WIRE_LEN] << 24 |
                           (uint32_t)ev[D2K_KEY_WIRE_LEN + 1] << 16 |
                           (uint32_t)ev[D2K_KEY_WIRE_LEN + 2] << 8 |
                           ev[D2K_KEY_WIRE_LEN + 3];
        CHECK(dropped == 2, "journal losses absent from STATS wire event");
        unsigned long sent = (unsigned long)ev[D2K_KEY_WIRE_LEN + 4] << 24 | (unsigned long)ev[D2K_KEY_WIRE_LEN + 5] << 16 |
                             (unsigned long)ev[D2K_KEY_WIRE_LEN + 6] << 8 | ev[D2K_KEY_WIRE_LEN + 7];
        CHECK(sent >= 1, "счётчик отправленных не учёл приветствие");
    }
    d2k_ctl_note_dropped(c, UINT64_MAX);
    CHECK(d2k_ctl_dropped(c) == UINT64_MAX, "loss counter did not saturate");
    d2k_ctl_event(c, D2K_EV_STATS, NULL, D2K_CTL_FRAME_MAX);
    CHECK(d2k_ctl_dropped(c) == UINT64_MAX, "socket loss wrapped saturated counter");
    close(cli);
    d2k_ctl_close(c);
    unlink(SOCK);
}

static void check_proto_greeting(void) {
    unlink(SOCK);
    char err[160];
    d2k_ctl *c = d2k_ctl_open(SOCK, err, sizeof err);
    CHECK(c != NULL, "сокет для проверки версии не создался");
    if (!c) { return; }
    int cli = dial();
    CHECK(cli >= 0, "клиент для проверки версии не подключился");
    d2k_ctl_accept(c);
    d2k_ctlsrv_greet(c, 1500u);
    d2k_ctl_flush(c);

    uint16_t type = 0;
    uint8_t ev[160];
    ssize_t n = read_event(cli, &type, ev, sizeof ev);
    CHECK(n > 0, "версия протокола не приехала вовсе");
    CHECK(type == D2K_EV_PROTO, "первым событием пришла не версия протокола");
    CHECK(n == (ssize_t)(D2K_KEY_WIRE_LEN + 7 + strlen(D2K_RELEASE_ID)),
          "тело версии не «ключ + два байта версии + четыре байта предела»");
    if (n >= (ssize_t)(D2K_KEY_WIRE_LEN + 7)) {
        CHECK(ev[D2K_KEY_WIRE_LEN + 6] == strlen(D2K_RELEASE_ID), "release length mismatch");
        CHECK(memcmp(ev + D2K_KEY_WIRE_LEN + 7, D2K_RELEASE_ID, strlen(D2K_RELEASE_ID)) == 0, "release ID mismatch");
        unsigned v = (unsigned)ev[D2K_KEY_WIRE_LEN] << 8 | ev[D2K_KEY_WIRE_LEN + 1];
        CHECK(v == (unsigned)D2K_CTL_PROTO_VERSION,
              "объявлена не та версия протокола, что собрана");
        /* v8: SET_NAME_PROBE несёт trial ID опыта, ACK возвращает его (задача 19). */
        CHECK(v >= 8u, "SET_NAME_PROBE с trial ID требует провода v8");
        /* Предел отправки едет ТЕМ ЖЕ событием: без него контроллер собирает
           планы, не зная, что унесёт канал (см. D2K_EV_PROTO в d2k_ctl.h). */
        unsigned long lim = (unsigned long)ev[D2K_KEY_WIRE_LEN + 2] << 24 |
                            (unsigned long)ev[D2K_KEY_WIRE_LEN + 3] << 16 |
                            (unsigned long)ev[D2K_KEY_WIRE_LEN + 4] << 8 |
                            ev[D2K_KEY_WIRE_LEN + 5];
        CHECK(lim == 1500ul, "предел отправки доехал не тем числом, каким объявлен");
    }
    close(cli);
    d2k_ctl_close(c);
    unlink(SOCK);
}

static void count_disconnect(void *ctx) { (*(unsigned *)ctx)++; }

static unsigned immediate_closes;
static void record_peer_close(void *ctx) { (void)ctx; immediate_closes++; }

static void test_probe_owner_disconnect(void) {
    char err[256];
    d2k_ctl *ctl = d2k_ctl_open(SOCK, err, sizeof err);
    d2k_session *sess = d2k_session_new(16, 0);
    CHECK(ctl && sess, "probe ownership fixture opens");
    if (!ctl || !sess) { d2k_ctl_close(ctl); d2k_session_free(sess); return; }
    d2k_ctlsrv cx = {.sess = sess, .ctl = ctl, .now_ns = 1000000};
    d2k_ctl_set_disconnect_hook(ctl, d2k_ctlsrv_peer_closed, &cx);
    immediate_closes = 0; cx.peer_closed_hook = record_peer_close;
    /* Этап 17: установка/снятие ТОЧНОЙ пробы сообщается крючками (d2kd ставит
       метку записи conntrack); адресная — с 5-tuple и сроком, именная порта —
       с именем/семейством/портом. */
    hook_addr_calls = hook_name_calls = 0;
    cx.addr_probe_hook = rec_addr_hook; cx.name_probe_hook = rec_name_hook; cx.probe_hook_ctx = &cx;
    int peer = dial();
    CHECK(peer >= 0, "probe owner connects");
    d2k_ctl_accept(ctl);
    d2k_plantab *tab = d2k_session_plans(sess);
    const char *name = "owner.example";
    size_t nl = strlen(name);
    uint8_t body[160], packet[180];
    uint16_t sport;
    const uint8_t port[2] = {0x9c, 0x40};
    memcpy(&sport, port, 2);
    d2k_addr_probe_flow flow = {.family = 6, .transport = 17};
    flow.src_ip6[0] = flow.dst_ip6[0] = 0xfd;
    flow.src_ip6[15] = 1; flow.dst_ip6[15] = 2;
    flow.src_port_be = sport;
    const uint8_t https[2] = {1, 0xbb};
    memcpy(&flow.dst_port_be, https, 2);
    for (unsigned kind = 0; kind < 3; kind++) {
        uint16_t type;
        size_t len;
        if (kind < 2) {
            len = set_name_body_shaped(body, name, tiny, sizeof tiny,
                                      D2K_PLAN_SHAPE_QUIC);
            body[2 + nl] = 6;
            type = kind ? D2K_CMD_SET_NAME_PROBE : D2K_CMD_SET_NAME;
            if (kind) {
                memmove(body + nl + 5, body + nl + 3, sizeof tiny);
                memcpy(body + nl + 3, port, 2);
                len += 2;
                memset(body + len, 0x31, D2K_TRIAL_ID_LEN); /* v8: trial ID */
                len += D2K_TRIAL_ID_LEN;
            }
        } else {
            memset(body, 0, 58);
            body[0] = 6;
            memcpy(body + 1, flow.src_ip6, 16);
            memcpy(body + 17, flow.dst_ip6, 16);
            memcpy(body + 33, port, 2);
            memcpy(body + 35, https, 2);
            body[37] = 17; body[38] = 1;
            body[56] = 0xea; body[57] = 0x60;
            memcpy(body + 58, tiny, sizeof tiny);
            len = 58 + sizeof tiny;
            type = D2K_CMD_SET_ADDR_PROBE;
        }
        frame(packet, type, body, len);
        CHECK(write(peer, packet, len + 6) == (ssize_t)(len + 6), "owner command written");
        CHECK(poll_frames(ctl, d2k_ctlsrv_command, &cx, 1) == 1, "owner command parsed");
        d2k_ctl_flush(ctl);
        uint16_t cmd; int ok; uint8_t reason;
        CHECK(read_ack(peer, &cmd, &ok, &reason) && ok, "owner command accepted");
    }
    CHECK(d2k_session_plan_count(sess) == 2, "permanent and named trial installed");
    CHECK(d2k_plantab_find_addr_probe(tab, &flow, cx.now_ns, NULL), "address trial installed");
    CHECK(hook_name_calls == 1 && hook_name_last.installed == 1 && hook_name_last.family == 6 &&
          hook_name_last.sport_be == sport && hook_name_last.transport == 6 &&
          hook_name_last.len == nl && !memcmp(hook_name_last.name, name, nl),
          "name probe hook not called once with name/family/port on SET_NAME_PROBE");
    CHECK(hook_addr_calls == 1 && hook_addr_last.installed == 1 &&
          hook_addr_last.expires_ns == 1000000ull + 60000ull * 1000000ull &&
          hook_addr_last.flow.transport == 17 && hook_addr_last.flow.family == 6 &&
          hook_addr_last.flow.src_port_be == sport && hook_addr_last.flow.dst_port_be == flow.dst_port_be,
          "addr probe hook not called once with exact flow and lease expiry on SET_ADDR_PROBE");
    {   /* Снятие — крючок с installed=0 на тот же кортеж. */
        memset(body, 0, 54);
        body[0] = 6;
        memcpy(body + 1, flow.src_ip6, 16);
        memcpy(body + 17, flow.dst_ip6, 16);
        memcpy(body + 33, port, 2);
        memcpy(body + 35, https, 2);
        body[37] = 17; body[38] = 1;
        frame(packet, D2K_CMD_DEL_ADDR_PROBE, body, 54);
        CHECK(write(peer, packet, 60) == 60, "del addr probe written");
        CHECK(poll_frames(ctl, d2k_ctlsrv_command, &cx, 1) == 1, "del addr probe parsed");
        d2k_ctl_flush(ctl);
        uint16_t cmd; int ok; uint8_t reason;
        CHECK(read_ack(peer, &cmd, &ok, &reason) && ok, "del addr probe acked");
        CHECK(hook_addr_calls == 2 && hook_addr_last.installed == 0 &&
              hook_addr_last.flow.src_port_be == sport, "addr probe hook not called with installed=0 on DEL_ADDR_PROBE");
    }
    const uint8_t question[] = {0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1};
    body[38] = 9;
    memset(body + 54, 0, D2K_DNS_PROBE_FIXED - 54);
    body[56] = 0xea; body[57] = 0x60;
    body[59] = sizeof question;
    d2k_sha256(question, sizeof question, body + 60);
    uint8_t *plan = body + D2K_DNS_PROBE_FIXED;
    const uint8_t udp_proto[] = {0, 2, 0, 2, 17, 2};
    memcpy(plan, tiny, sizeof tiny);
    plan[11] = 2;
    memcpy(plan + sizeof tiny, udp_proto, sizeof udp_proto);
    size_t len = D2K_DNS_PROBE_FIXED + sizeof tiny + sizeof udp_proto;
    frame(packet, D2K_CMD_SET_DNS_PROBE, body, len);
    CHECK(write(peer, packet, len + 6) == (ssize_t)(len + 6), "DNS owner command written");
    CHECK(poll_frames(ctl, d2k_ctlsrv_command, &cx, 1) == 1, "DNS owner command parsed");
    d2k_ctl_flush(ctl);
    uint16_t cmd; int ok; uint8_t reason;
    CHECK(read_ack(peer, &cmd, &ok, &reason) && ok && cmd == D2K_CMD_SET_DNS_PROBE &&
          !memcmp(last_ack_id, body + 38, sizeof last_ack_id), "DNS ACK identifies accepted trial");
    CHECK(d2k_plantab_find_dns_probe(tab, &flow, 1, question, sizeof question, cx.now_ns, NULL, NULL) &&
          !d2k_plantab_find_addr_probe(tab, &flow, cx.now_ns, NULL) && hook_addr_calls == 2,
          "DNS trial requires its own selector, without a conntrack lease");
    uint8_t direct[sizeof question];
    memcpy(direct,question,sizeof direct);direct[0]^=1;
    int reserved=0;
    CHECK(!d2k_plantab_find_dns_probe(tab,&flow,1,direct,sizeof direct,cx.now_ns,NULL,&reserved) && reserved,
          "a different query on the reserved UDP flow may pass without applying the candidate");
    body[38] = 1;
    frame(packet, D2K_CMD_DEL_ADDR_PROBE, body, D2K_ADDR_PROBE_FLOW_WIRE_LEN + D2K_TRIAL_ID_LEN);
    CHECK(write(peer, packet, 60) == 60, "stale DNS retirement written");
    CHECK(poll_frames(ctl, d2k_ctlsrv_command, &cx, 1) == 1, "stale DNS retirement parsed");
    d2k_ctl_flush(ctl);
    CHECK(read_ack(peer, &cmd, &ok, &reason) && ok &&
          d2k_plantab_find_dns_probe(tab, &flow, 1, question, sizeof question, cx.now_ns, NULL, NULL) &&
          hook_addr_calls == 2, "stale retirement leaves the DNS owner in place");
    uint8_t endpoint[80]={0};
    endpoint[0]=6;memcpy(endpoint+1,flow.dst_ip6,16);
    endpoint[17]=D2K_PLAN_SHAPE_DNS;memcpy(endpoint+18,&flow.dst_port_be,2);
    endpoint[21]=sizeof question;
    memcpy(endpoint+22,plan,sizeof tiny+sizeof udp_proto);
    size_t binding_len=22+sizeof tiny+sizeof udp_proto;
    uint8_t request[D2K_TRIAL_ID_LEN]={3};
    memcpy(endpoint+binding_len,request,sizeof request);
    binding_len+=sizeof request;
    frame(packet,D2K_CMD_SET_DNS_ENDPOINT,endpoint,binding_len);
    CHECK(write(peer,packet,binding_len+6)==(ssize_t)(binding_len+6),"DNS endpoint installation written");
    CHECK(poll_frames(ctl,d2k_ctlsrv_command,&cx,1)==1,"DNS endpoint installation parsed");
    d2k_ctl_flush(ctl);
    CHECK(read_ack(peer,&cmd,&ok,&reason) && ok && cmd==D2K_CMD_SET_DNS_ENDPOINT &&
          !memcmp(last_ack_id,request,sizeof request) &&
          d2k_plantab_find_dns_endpoint(tab,flow.dst_ip6,6,flow.dst_port_be,17,question,sizeof question,cx.now_ns),
          "DNS endpoint is authorized only for the carried wire length and DNS framing");
    endpoint[20]=6;
    frame(packet,D2K_CMD_DEL_ENDPOINT,endpoint,21);
    CHECK(write(peer,packet,27)==27 && poll_frames(ctl,d2k_ctlsrv_command,&cx,1)==1,
          "other DNS endpoint transport retirement parsed");
    d2k_ctl_flush(ctl);
    CHECK(read_ack(peer,&cmd,&ok,&reason) && ok &&
          d2k_plantab_find_dns_endpoint(tab,flow.dst_ip6,6,flow.dst_port_be,17,question,sizeof question,cx.now_ns),
          "transport-specific delete preserves another DNS binding");
    endpoint[20]=17;
    frame(packet,D2K_CMD_DEL_ENDPOINT,endpoint,21);
    CHECK(write(peer,packet,27)==27 && poll_frames(ctl,d2k_ctlsrv_command,&cx,1)==1,
          "exact DNS endpoint retirement parsed");
    d2k_ctl_flush(ctl);
    CHECK(read_ack(peer,&cmd,&ok,&reason) && ok &&
          !d2k_plantab_find_dns_endpoint(tab,flow.dst_ip6,6,flow.dst_port_be,17,question,sizeof question,cx.now_ns),
          "transport-specific delete retires exact endpoint");
    close(peer);
    CHECK(d2k_ctl_poll(ctl, d2k_ctlsrv_command, &cx) < 0, "owner EOF observed");
    CHECK(immediate_closes == 1, "late owner cancellation hook must run immediately on EOF before reconnect or tick");
    CHECK(d2k_session_plan_count(sess) == 1, "disconnect removes named trial only");
    CHECK(!d2k_plantab_find_addr_probe(tab, &flow, cx.now_ns, NULL), "disconnect removes address trial");
    CHECK(!d2k_plantab_find_dns_probe(tab, &flow, 1, question, sizeof question, cx.now_ns, NULL, NULL),
          "disconnect removes DNS trial");
    CHECK(d2k_plantab_find_family(tab, (const uint8_t *)name, nl, 0,
          cx.now_ns, D2K_PLAN_SHAPE_QUIC, 0, 6), "disconnect preserves confirmed strategy");
    peer = dial();
    d2k_ctl_accept(ctl);
    CHECK(peer >= 0 && d2k_ctl_peer_fd(ctl) >= 0, "replacement controller accepted");
    CHECK(d2k_session_plan_count(sess) == 1 &&
          !d2k_plantab_find_addr_probe(tab, &flow, cx.now_ns, NULL),
          "replacement controller cannot inherit stale trials");
    close(peer);
    d2k_ctl_poll(ctl, d2k_ctlsrv_command, &cx);
    d2k_ctl_close(ctl);
    d2k_session_free(sess);
}

/* SET_HTTPS (v10, задача 51): контроллер сообщает имя с подтверждённым
   HTTPS и срок; датапат держит его в таблице http80 и подтверждает. */
static void test_set_https(void) {
    unlink(SOCK);
    char err[160];
    d2k_ctl *c = d2k_ctl_open(SOCK, err, sizeof err);
    CHECK(c != NULL, "сокет для SET_HTTPS не создался");
    if (!c) { return; }
    int cli = dial();
    d2k_ctl_accept(c);
    d2k_session *sess = d2k_session_new(16, 16);
    d2k_http80 *h = d2k_http80_new();
    d2k_ctlsrv cx;
    memset(&cx, 0, sizeof cx);
    cx.sess = sess;
    cx.ctl = c;
    cx.http80 = h;
    cx.now_ns = 1000u * 1000000000ull;
    uint8_t body[64];
    uint16_t cmd = 0;
    int ok = 0;
    uint8_t reason = 0;
    const char *name = "RuTracker.org";
    size_t nl = strlen(name);
    body[0] = (uint8_t)nl;
    memcpy(body + 1, name, nl);
    wr32(body + 1 + nl, 3600);
    d2k_ctlsrv_command(&cx, D2K_CMD_SET_HTTPS, body, 1 + nl + 4);
    d2k_ctl_flush(c);
    CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && cmd == D2K_CMD_SET_HTTPS && ok,
          "SET_HTTPS не подтверждён");
    CHECK(d2k_http80_https(h, "rutracker.org", cx.now_ns + 3599ull * 1000000000ull) &&
          !d2k_http80_https(h, "rutracker.org", cx.now_ns + 3600ull * 1000000000ull),
          "SET_HTTPS поставил имя не на тот срок");
    wr32(body + 1 + nl, 0);
    d2k_ctlsrv_command(&cx, D2K_CMD_SET_HTTPS, body, 1 + nl + 4);
    d2k_ctl_flush(c);
    CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && ok &&
          !d2k_http80_https(h, "rutracker.org", cx.now_ns),
          "SET_HTTPS с нулевым сроком не снял имя");
    d2k_ctlsrv_command(&cx, D2K_CMD_SET_HTTPS, body, nl + 4);
    d2k_ctl_flush(c);
    CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && !ok && reason == D2K_ACK_BAD_ARGS,
          "обрезанный SET_HTTPS принят");
    body[1] = ' ';
    d2k_ctlsrv_command(&cx, D2K_CMD_SET_HTTPS, body, 1 + nl + 4);
    d2k_ctl_flush(c);
    CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && !ok, "негодное имя в SET_HTTPS принято");
    cx.http80 = NULL;
    body[1] = 'R';
    d2k_ctlsrv_command(&cx, D2K_CMD_SET_HTTPS, body, 1 + nl + 4);
    d2k_ctl_flush(c);
    CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && !ok,
          "SET_HTTPS без таблицы HTTP подтверждён как исполненный");
    /* SET_NAME формы HTTP (v11, шаг 4): только план протокола http. */
    {
        static const uint8_t http_plan[] = {
            'D', '2', 'K', 'P', 0, 1, 0, 11, 0, 0, 0, 2,
            0x00, 0x02, 0x00, 0x02, 6, 4,                  /* proto tcp http */
            0x01, 0x00, 0x00, 0x04, 0x00, 0x05, 0x00, 0x00 /* split sni_middle */
        };
        static const uint8_t tls_plan[] = {
            'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 2,
            0x00, 0x02, 0x00, 0x02, 6, 1,
            0x01, 0x00, 0x00, 0x04, 0x00, 0x05, 0x00, 0x00
        };
        const char *nm = "rutracker.org";
        size_t l = strlen(nm);
        uint8_t nb[128];
        nb[0] = (uint8_t)l; memcpy(nb + 1, nm, l); nb[1 + l] = 7; nb[2 + l] = 4;
        memcpy(nb + 3 + l, http_plan, sizeof http_plan);
        d2k_ctlsrv_command(&cx, D2K_CMD_SET_NAME, nb, 3 + l + sizeof http_plan);
        d2k_ctl_flush(c);
        CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && cmd == D2K_CMD_SET_NAME && ok,
              "SET_NAME формы HTTP с HTTP-планом не принят");
        CHECK(d2k_plantab_find_http(d2k_session_plans(sess), (const uint8_t *)nm, l, 4, 0, 1) != NULL,
              "HTTP-план имени не встал в таблицу");
        memcpy(nb + 3 + l, tls_plan, sizeof tls_plan);
        d2k_ctlsrv_command(&cx, D2K_CMD_SET_NAME, nb, 3 + l + sizeof tls_plan);
        d2k_ctl_flush(c);
        CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && !ok && reason == D2K_ACK_BAD_ARGS,
              "TLS-план под формой HTTP принят");
        nb[1 + l] = 1;   /* MODERN */
        memcpy(nb + 3 + l, http_plan, sizeof http_plan);
        d2k_ctlsrv_command(&cx, D2K_CMD_SET_NAME, nb, 3 + l + sizeof http_plan);
        d2k_ctl_flush(c);
        CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && !ok && reason == D2K_ACK_BAD_ARGS,
              "HTTP-план под формой TLS принят");
    }
    d2k_http80_free(h);
    d2k_session_free(sess);
    close(cli);
    d2k_ctl_close(c);
    unlink(SOCK);
}

/* ЗАДАЧА 56: бюджеты коробок едут командой (v12), подозрение «TCP встал на
   бюджете» везёт оценку пакетов с данными — байтами на проводе. */
static d2k_ct_info stall_ct;
static int stall_ct_query(void *ctx, const d2k_ct_tuple *t, d2k_ct_info *out) {
    (void)ctx;
    if (t->proto != 6) return -1;
    *out = stall_ct;
    return 0;
}
static size_t build_rev(uint8_t *o, uint16_t cport, uint8_t flags, uint32_t seq,
                        const uint8_t *pay, size_t paylen) {
    size_t total = build_pkt(o, cport, pay, paylen);
    uint8_t lan[4] = {192, 168, 1, 67}, wan[4] = {93, 184, 216, 34};
    memcpy(o + 12, wan, 4);
    memcpy(o + 16, lan, 4);
    wr16(o + 20, 443);
    wr16(o + 22, cport);
    wr32(o + 24, seq);
    o[33] = flags;
    return total;
}
static void test_tcp_stall_wire(void) {
    unlink(SOCK);
    char err[160];
    d2k_ctl *c = d2k_ctl_open(SOCK, err, sizeof err);
    CHECK(c != NULL, "сокет для SET_STALL_BUDGETS не создался");
    if (!c) { return; }
    int cli = dial();
    d2k_ctl_accept(c);
    struct timeval tv = { 2, 0 };
    (void)setsockopt(cli, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    d2k_session *sess = d2k_session_new(16, 16);
    d2k_ctlsrv cx;
    memset(&cx, 0, sizeof cx);
    cx.sess = sess;
    cx.ctl = c;
    uint16_t cmd = 0, got[D2K_STALL_BUDGETS_MAX];
    int ok = 0;
    uint8_t reason = 0;
    uint8_t body[32] = { 2, 0, 16, 0, 26 };
    d2k_ctlsrv_command(&cx, D2K_CMD_SET_STALL_BUDGETS, body, 5);
    d2k_ctl_flush(c);
    CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && cmd == D2K_CMD_SET_STALL_BUDGETS && ok,
          "SET_STALL_BUDGETS не подтверждён");
    CHECK(d2k_session_stall_budgets(sess, got, D2K_STALL_BUDGETS_MAX) == 2 &&
          got[0] == 16 && got[1] == 26, "бюджеты коробок не дошли до сессии");
    /* Негодное: длина не сходится, больше предела, нулевой бюджет — отказ,
       прежние бюджеты на месте. */
    d2k_ctlsrv_command(&cx, D2K_CMD_SET_STALL_BUDGETS, body, 4);
    d2k_ctl_flush(c);
    CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && !ok && reason == D2K_ACK_BAD_ARGS,
          "обрезанный SET_STALL_BUDGETS принят");
    uint8_t many[1 + 2 * (D2K_STALL_BUDGETS_MAX + 1)];
    memset(many, 0, sizeof many);
    many[0] = D2K_STALL_BUDGETS_MAX + 1;
    for (size_t i = 0; i <= D2K_STALL_BUDGETS_MAX; i++) many[2 + 2 * i] = 20;
    d2k_ctlsrv_command(&cx, D2K_CMD_SET_STALL_BUDGETS, many, sizeof many);
    d2k_ctl_flush(c);
    CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && !ok, "бюджетов сверх предела принято");
    uint8_t zero[3] = { 1, 0, 0 };
    d2k_ctlsrv_command(&cx, D2K_CMD_SET_STALL_BUDGETS, zero, 3);
    d2k_ctl_flush(c);
    CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && !ok, "нулевой бюджет принят");
    CHECK(d2k_session_stall_budgets(sess, got, D2K_STALL_BUDGETS_MAX) == 2 && got[1] == 26,
          "отвергнутая команда испортила бюджеты");
    uint8_t none[1] = { 0 };
    d2k_ctlsrv_command(&cx, D2K_CMD_SET_STALL_BUDGETS, none, 1);
    d2k_ctl_flush(c);
    CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && ok &&
          d2k_session_stall_budgets(sess, got, D2K_STALL_BUDGETS_MAX) == 1 &&
          got[0] == D2K_TCP_STALL_FIELD_BUDGET, "пустой список не вернул полевой бюджет");

    /* Поток: SYN, SYN-ACK, приветствие, одна запись app-data сервера; ядро:
       обратный 25 и стоит. Оценка 1 + 1 + (25 - 2) = 25. */
    d2k_session_set_ct_query(sess, stall_ct_query, NULL);
    const uint64_t S = 1000000000ull;
    uint8_t hello[512], pkt[1024], obuf[2048];
    size_t hl = build_hello(hello, "stall.example");
    d2k_result r;
    size_t n = build_pkt(pkt, 40300, NULL, 0);
    pkt[33] = 0x02; wr32(pkt + 24, 999);
    d2k_session_packet(sess, pkt, n, 1 * S, obuf, sizeof obuf, &r);
    n = build_rev(pkt, 40300, 0x12, 4999, NULL, 0);
    d2k_session_packet(sess, pkt, n, 1 * S + 50000000ull, obuf, sizeof obuf, &r);
    n = build_pkt(pkt, 40300, hello, hl);
    d2k_session_packet(sess, pkt, n, 1 * S + 50000001ull, obuf, sizeof obuf, &r);
    const uint8_t app[100] = { 0x17, 0x03, 0x03, 0x00, 0x5f };
    n = build_rev(pkt, 40300, 0x18, 5000, app, sizeof app);
    d2k_session_packet(sess, pkt, n, 1 * S + 100000000ull, obuf, sizeof obuf, &r);
    memset(&stall_ct, 0, sizeof stall_ct);
    stall_ct.orig_pkts = 14; stall_ct.reply_pkts = 25;
    stall_ct.tcp_state_known = 1; stall_ct.tcp_state = D2K_CT_TCP_ESTABLISHED;
    d2k_session_sweep(sess, 2 * S);
    stall_ct.orig_pkts = 17;   /* клиент говорит в тишину */
    d2k_session_sweep(sess, 4 * S + 100000000ull);
    uint64_t seen = 0;
    d2k_ctlsrv_pump(c, sess, &seen);
    d2k_ctl_flush(c);
    int found = 0;
    for (int i = 0; i < 8 && !found; i++) {
        uint16_t type = 0;
        uint8_t ev[256];
        ssize_t m = read_event(cli, &type, ev, sizeof ev);
        if (m < 0) break;
        if (type != D2K_EV_SUSPECT) continue;
        found = 1;
        CHECK(m == (ssize_t)(D2K_KEY_WIRE_LEN + 11), "SUSPECT missing packet estimate or observed endpoint");
        if (m >= (ssize_t)(D2K_KEY_WIRE_LEN + 11)) {
            CHECK(ev[D2K_KEY_WIRE_LEN + 10] == D2K_CLIENT_SIDE_HIGH,
                  "TCP stall lost observed client endpoint on wire");
        }
        CHECK(ev[D2K_KEY_WIRE_LEN] == D2K_SUSPECT_TCP_STALL, "код «TCP встал на бюджете» потерян");
        if (m >= (ssize_t)(D2K_KEY_WIRE_LEN + 10)) {
            CHECK((ev[D2K_KEY_WIRE_LEN + 8] << 8 | ev[D2K_KEY_WIRE_LEN + 9]) == 25,
                  "оценка пакетов с данными не доехала (ждали 25)");
        }
    }
    CHECK(found, "подозрение «TCP встал на бюджете» не вышло на провод");
    CHECK(strcmp(d2k_suspect_text(D2K_SUSPECT_TCP_STALL),
                 "TCP: сервер замолчал на бюджете коробки, соединение открыто; проверить объём ответа") == 0,
          "у кода 8 нет своего текста");
    close(cli);
    d2k_ctl_poll(c, d2k_ctlsrv_command, &cx);
    d2k_ctl_close(c);
    d2k_session_free(sess);
}

/* ПОЯВЛЕНИЕ ПОТОКА БЕЗ ПРОТОКОЛА НА ПРОВОДЕ (этап 42): D2K_EV_FLOW — ключ и
   байт наблюдённой стороны клиента; один на поток, повтор сегмента не даёт. */
static void test_flow_fact_wire(void) {
    unlink(SOCK);
    char err[160];
    d2k_ctl *c = d2k_ctl_open(SOCK, err, sizeof err);
    CHECK(c != NULL, "сокет для факта появления не создался");
    if (!c) { return; }
    int cli = dial();
    d2k_ctl_accept(c);
    struct timeval tv = { 1, 0 };
    (void)setsockopt(cli, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    d2k_session *sess = d2k_session_new(16, 16);
    static const uint8_t game[] = "\x7f\x01GAME-HELLO\x00\x00\x00\x10";
    uint8_t pkt[1024], obuf[2048];
    d2k_result r;
    size_t n = build_pkt(pkt, 40400, NULL, 0);
    pkt[33] = 0x02; wr32(pkt + 24, 999);
    d2k_session_packet(sess, pkt, n, 1000, obuf, sizeof obuf, &r);
    n = build_rev(pkt, 40400, 0x12, 4999, NULL, 0);
    d2k_session_packet(sess, pkt, n, 2000, obuf, sizeof obuf, &r);
    n = build_pkt(pkt, 40400, game, sizeof game - 1);
    d2k_session_packet(sess, pkt, n, 3000, obuf, sizeof obuf, &r);
    d2k_session_packet(sess, pkt, n, 4000, obuf, sizeof obuf, &r);
    uint64_t seen = 0;
    d2k_ctlsrv_pump(c, sess, &seen);
    d2k_ctl_flush(c);
    int found = 0;
    for (int i = 0; i < 8; i++) {
        uint16_t type = 0;
        uint8_t ev[256];
        ssize_t m = read_event(cli, &type, ev, sizeof ev);
        if (m < 0) break;
        if (type != D2K_EV_RAW_FLOW) continue;
        found++;
        CHECK(m == (ssize_t)(D2K_KEY_WIRE_LEN + 1 + 24) && ev[D2K_KEY_WIRE_LEN] == D2K_CLIENT_SIDE_HIGH &&
              ev[D2K_KEY_WIRE_LEN - 1] == 6,
              "факт появления: на проводе не ключ TCP и сторона клиента");
        CHECK(d2k_rm_nonzero(ev+D2K_KEY_WIRE_LEN+1,16)&&d2k_rm_nonzero(ev+D2K_KEY_WIRE_LEN+17,8),
              "факт появления без поколения соединения");
    }
    CHECK(found == 1, "факт появления потока без протокола не вышел на провод один раз");
    close(cli);
    d2k_ctl_close(c);
    d2k_session_free(sess);
}

/* ПОЗДНЕЕ НАБЛЮДЕНИЕ ТОЧНОГО ПОТОКА (этап 49): команда доходит до крючка с
   тем кортежем и сроком; неверное тело — отказ; без крючка (поздняя доставка
   выключена) — итог «недоступно» событием D2K_EV_LATE_OBS с ключом потока. */
static d2k_ct_tuple lo_seen;
static uint32_t lo_secs;
static int lo_calls;
static uint8_t lo_token[D2K_TRIAL_ID_LEN];
static void lo_hook(void *ctx, const d2k_ct_tuple *t, uint32_t seconds, const uint8_t token[D2K_TRIAL_ID_LEN]) {
    (void)ctx; lo_seen = *t; lo_secs = seconds; lo_calls++; memcpy(lo_token, token, D2K_TRIAL_ID_LEN);
}
/* ACK с хвостом-токеном (как у проб): 1 — прочитан. */
static int read_ack_token(int fd, uint16_t *cmd, int *ok, uint8_t tok[D2K_TRIAL_ID_LEN]) {
    for (int i = 0; i < 8; i++) {
        uint16_t type = 0;
        uint8_t ev[256];
        ssize_t m = read_event(fd, &type, ev, sizeof ev);
        if (m < 0) return 0;
        if (type != D2K_EV_ACK || m < (ssize_t)(D2K_KEY_WIRE_LEN + 4 + D2K_TRIAL_ID_LEN)) continue;
        *cmd = (uint16_t)(ev[D2K_KEY_WIRE_LEN] << 8 | ev[D2K_KEY_WIRE_LEN + 1]);
        *ok = ev[D2K_KEY_WIRE_LEN + 2];
        memcpy(tok, ev + D2K_KEY_WIRE_LEN + 4, D2K_TRIAL_ID_LEN);
        return 1;
    }
    return 0;
}
static void test_late_observe_wire(void) {
    unlink(SOCK);
    char err[160];
    d2k_ctl *c = d2k_ctl_open(SOCK, err, sizeof err);
    CHECK(c != NULL, "сокет для LATE_OBSERVE не создался");
    if (!c) { return; }
    int cli = dial();
    d2k_ctl_accept(c);
    struct timeval tv = { 1, 0 };
    (void)setsockopt(cli, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    d2k_session *sess = d2k_session_new(16, 16);
    d2k_ctlsrv cx;
    memset(&cx, 0, sizeof cx);
    cx.sess = sess; cx.ctl = c;
    uint8_t body[D2K_LATE_OBSERVE_LEN];
    memset(body, 0, sizeof body);
    body[0] = 4; body[1] = 6;
    body[2] = 192; body[3] = 168; body[4] = 1; body[5] = 67;     /* клиент */
    body[18] = 93; body[19] = 184; body[20] = 216; body[21] = 34; /* сервер */
    body[34] = 0xa0; body[35] = 0x01; body[37] = 0xbb; body[38] = 60;
    for (int i = 0; i < D2K_TRIAL_ID_LEN; i++) body[39 + i] = (uint8_t)(0xc0 + i);
    uint16_t cmd = 0; int ok = 0;
    uint8_t tok[D2K_TRIAL_ID_LEN];
    cx.late_observe_hook = lo_hook;
    d2k_ctlsrv_command(&cx, D2K_CMD_LATE_OBSERVE, body, sizeof body);
    d2k_ctl_flush(c);
    /* Этап 53: подтверждение — не сразу, а по готовности доставки (его шлёт
       модуль поздней доставки через d2k_ctlsrv_ack_late). */
    {
        struct timeval qt = { 0, 200000 };
        (void)setsockopt(cli, SOL_SOCKET, SO_RCVTIMEO, &qt, sizeof qt);
        CHECK(read_ack_token(cli, &cmd, &ok, tok) == 0, "LATE_OBSERVE подтверждён до готовности доставки");
        (void)setsockopt(cli, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    }
    d2k_ctlsrv_ack_late(&cx, 1, D2K_ACK_OK, lo_token);
    d2k_ctl_flush(c);
    CHECK(read_ack_token(cli, &cmd, &ok, tok) == 1 && cmd == D2K_CMD_LATE_OBSERVE && ok &&
          !memcmp(tok, body + 39, D2K_TRIAL_ID_LEN), "готовность LATE_OBSERVE не подтверждена своим токеном");
    CHECK(lo_calls == 1 && lo_secs == 60 && lo_seen.proto == 6 && lo_seen.family == 4 &&
          lo_seen.src[0] == 192 && lo_seen.dst[0] == 93 && lo_seen.sport_be[0] == 0xa0 && lo_seen.dport_be[1] == 0xbb &&
          !memcmp(lo_token, body + 39, D2K_TRIAL_ID_LEN),
          "LATE_OBSERVE дошёл до крючка не тем кортежем, сроком или токеном");
    uint8_t bad[D2K_LATE_OBSERVE_LEN];
    memcpy(bad, body, sizeof bad); bad[1] = 17;
    d2k_ctlsrv_command(&cx, D2K_CMD_LATE_OBSERVE, bad, sizeof bad);
    memcpy(bad, body, sizeof bad); bad[38] = 0;
    d2k_ctlsrv_command(&cx, D2K_CMD_LATE_OBSERVE, bad, sizeof bad);
    memcpy(bad, body, sizeof bad); bad[10] = 1;                   /* хвост IPv4 не нулевой */
    d2k_ctlsrv_command(&cx, D2K_CMD_LATE_OBSERVE, bad, sizeof bad);
    d2k_ctlsrv_command(&cx, D2K_CMD_LATE_OBSERVE, body, sizeof body - 1);
    memcpy(bad, body, sizeof bad); memset(bad + 39, 0, D2K_TRIAL_ID_LEN);   /* нулевой токен */
    d2k_ctlsrv_command(&cx, D2K_CMD_LATE_OBSERVE, bad, sizeof bad);
    d2k_ctl_flush(c);
    for (int i = 0; i < 5; i++) {
        CHECK(read_ack_token(cli, &cmd, &ok, tok) == 1 && !ok, "неверное LATE_OBSERVE принято");
        if (i < 3) CHECK(!memcmp(tok, body + 39, D2K_TRIAL_ID_LEN), "отказ LATE_OBSERVE без своего токена");
    }
    CHECK(lo_calls == 1, "неверное LATE_OBSERVE дошло до крючка");
    /* Нечем наблюдать (поздней доставки нет) — отказ сразу, со своим токеном. */
    cx.late_observe_hook = NULL;
    d2k_ctlsrv_command(&cx, D2K_CMD_LATE_OBSERVE, body, sizeof body);
    d2k_ctl_flush(c);
    CHECK(read_ack_token(cli, &cmd, &ok, tok) == 1 && !ok && !memcmp(tok, body + 39, D2K_TRIAL_ID_LEN),
          "без поздней доставки LATE_OBSERVE не отвергнут своим токеном");
    /* Итог наблюдения на проводе (его пишет модуль в журнал сессии). */
    {
        d2k_ct_tuple nt; memset(&nt, 0, sizeof nt);
        nt.family = 4; nt.proto = 6; memcpy(nt.src, body + 2, 4); memcpy(nt.dst, body + 18, 4);
        memcpy(nt.sport_be, body + 34, 2); memcpy(nt.dport_be, body + 36, 2);
        d2k_session_note_lateobs(sess, &nt, D2K_LATEOBS_UNAVAILABLE, 0, body + 39, 1);
    }
    uint64_t seen = 0;
    d2k_ctlsrv_pump(c, sess, &seen);
    d2k_ctl_flush(c);
    int found = 0;
    for (int i = 0; i < 8; i++) {
        uint16_t type = 0;
        uint8_t ev[256];
        ssize_t m = read_event(cli, &type, ev, sizeof ev);
        if (m < 0) break;
        if (type != D2K_EV_LATE_OBS) continue;
        found++;
        CHECK(m == (ssize_t)(D2K_KEY_WIRE_LEN + 4 + D2K_TRIAL_ID_LEN) && ev[D2K_KEY_WIRE_LEN] == D2K_LATEOBS_UNAVAILABLE &&
              ev[D2K_KEY_WIRE_LEN + 1] == D2K_CLIENT_SIDE_HIGH && ev[D2K_KEY_WIRE_LEN - 1] == 6 &&
              !memcmp(ev + D2K_KEY_WIRE_LEN + 4, body + 39, D2K_TRIAL_ID_LEN),
              "итог «недоступно» без ключа TCP, стороны клиента или токена");
    }
    CHECK(found == 1, "без крючка итог наблюдения не вышел на провод один раз");
    close(cli);
    d2k_ctl_close(c);
    d2k_session_free(sess);
}

static unsigned rm_calls;
static struct d2k_rawmeasure_request rm_request;
static void rm_hook(void *ctx,const struct d2k_rawmeasure_request *request) {
    (void)ctx;rm_calls++;rm_request=*request;
}
static void test_raw_measure_command(void) {
    unlink(SOCK);char err[160];d2k_ctl *c=d2k_ctl_open(SOCK,err,sizeof err);
    CHECK(c!=NULL,"RAW_MEASURE socket");if(!c)return;
    int cli=dial();d2k_ctl_accept(c);struct timeval tv={0,200000};
    (void)setsockopt(cli,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
    d2k_session *sess=d2k_session_new(16,16);d2k_ctlsrv cx;memset(&cx,0,sizeof cx);
    cx.sess=sess;cx.ctl=c;cx.raw_measure_hook=rm_hook;cx.addr_probe_hook=rec_addr_hook;
    struct d2k_rawmeasure_request request;memset(&request,0,sizeof request);
    request.tuple.family=4;request.tuple.proto=6;request.tuple.src[0]=1;request.tuple.dst[0]=2;
    request.tuple.sport_be[1]=9;request.tuple.dport_be[1]=8;request.epoch[0]=3;
    request.generation=7;request.token[0]=5;request.seconds=10;
    uint8_t body[D2K_RM_REQUEST_LEN],tok[16];uint16_t cmd=0;int ok=0;
    CHECK(!d2k_rawmeasure_request_write(body,sizeof body,&request),"RAW_MEASURE encode");
    d2k_ctlsrv_command(&cx,D2K_CMD_RAW_MEASURE,body,sizeof body);d2k_ctl_flush(c);
    CHECK(rm_calls==1 && rm_request.generation==7 && rm_request.epoch[0]==3,"RAW_MEASURE lost identity");
    CHECK(!read_ack_token(cli,&cmd,&ok,tok),"RAW_MEASURE ACK before actual readiness");
    d2k_ctlsrv_ack_raw_measure(&cx,1,D2K_ACK_OK,request.token);d2k_ctl_flush(c);
    CHECK(read_ack_token(cli,&cmd,&ok,tok)&&cmd==D2K_CMD_RAW_MEASURE&&ok&&!memcmp(tok,request.token,16),"RAW_MEASURE readiness ACK context");
    body[54]=0;memset(body+54,0,8);
    d2k_ctlsrv_command(&cx,D2K_CMD_RAW_MEASURE,body,sizeof body);d2k_ctl_flush(c);
    CHECK(read_ack_token(cli,&cmd,&ok,tok)&&!ok&&!memcmp(tok,request.token,16),"RAW_MEASURE zero generation accepted");
    CHECK(rm_calls==1,"RAW_MEASURE invalid request dispatched");
    CHECK(!d2k_rawmeasure_request_write(body,sizeof body,&request),"RAW_MEASURE encode repeat");
    cx.raw_measure_hook=NULL;d2k_ctlsrv_command(&cx,D2K_CMD_RAW_MEASURE,body,sizeof body);d2k_ctl_flush(c);
    CHECK(read_ack_token(cli,&cmd,&ok,tok)&&!ok&&!memcmp(tok,request.token,16),"RAW_MEASURE unavailable must refuse");

#ifndef D2K_RAWMEASURE_EMITTER
    CHECK(0,"measurement report emitter missing");
#else
    struct d2k_rawmeasure_report report={0},decoded;
    report.request=request;report.code=D2K_RM_SERVER_PRESENT;report.server_packets=1;
    report.flags=D2K_RM_TCP_ACK;report.tcp_ack=1;
    report.sample_len=report.smallest_data=report.largest_data=1;
    report.client_data=1;report.sample_digest[0]=1;

    CHECK(!d2k_ctlsrv_raw_measure(&cx,&report),"measurement emit failed");d2k_ctl_flush(c);
    uint8_t result[D2K_KEY_WIRE_LEN+D2K_RM_REPORT_LEN];uint16_t kind=0;
    CHECK(read_event(cli,&kind,result,sizeof result)==sizeof result && kind==D2K_EV_RAW_MEASURE,"measurement result missing");
    CHECK(result[0]==4&&result[1]==1&&result[17]==2&&result[34]==9&&result[36]==8&&result[37]==6,"measurement event tuple wrong");
    CHECK(!d2k_rawmeasure_report_read(&decoded,result+D2K_KEY_WIRE_LEN,D2K_RM_REPORT_LEN)&&
          decoded.request.generation==7&&decoded.request.token[0]==5&&decoded.server_packets==1,"measurement result lost context");
    report.request.tuple.src[0]=3; /* Client sorts after server: key builder returns 0, not failure. */
    CHECK(!d2k_ctlsrv_raw_measure(&cx,&report),"reverse-sorted client emit failed");d2k_ctl_flush(c);
    CHECK(read_event(cli,&kind,result,sizeof result)==sizeof result && result[1]==2 && result[17]==3 && result[34]==8 && result[36]==9,"reverse-sorted client key wrong");
    report.server_packets=0;CHECK(d2k_ctlsrv_raw_measure(&cx,&report)<0,"contradictory result emitted");
#endif
    {
        d2k_flow observed={0};d2k_addr a={0},b={0};a.family=b.family=4;a.bytes[0]=1;b.bytes[0]=2;
        d2k_key_make_addr(&observed.key,6,&a,&b,request.tuple.sport_be,request.tuple.dport_be);
        observed.incarnation=123;observed.flow_epoch[0]=9;
        d2k_jrn_detail detail={0};detail.client_shape=D2K_PLAN_SHAPE_RAW;detail.client_side=D2K_CLIENT_SIDE_LOW;
        detail.planned=D2K_PLANNED_NO;
        d2k_journal_add_suspect_bound((d2k_journal *)d2k_session_journal(sess),10,&observed.key,D2K_SUSPECT_SILENT,0,&detail,&observed);
        observed.incarnation=999;observed.flow_epoch[0]=7;uint64_t seen=0;
        d2k_ctlsrv_pump(c,sess,&seen);d2k_ctl_flush(c);
        uint8_t event[256];uint16_t type;ssize_t n=read_event(cli,&type,event,sizeof event);
        CHECK(n==D2K_KEY_WIRE_LEN+11+24&&type==D2K_EV_RAW_SUSPECT,"raw suspicion identity not serialized");
        if(n==D2K_KEY_WIRE_LEN+11+24)
            CHECK(event[D2K_KEY_WIRE_LEN+11]==9&&event[n-1]==123,"delayed raw suspicion got replacement identity");
    }

#ifndef D2K_CMD_SET_RAW_PROBE
    CHECK(0,"measured trial command missing");
#else
    {
        uint8_t packet[41]={0},scratch[4096];d2k_result outcome;
        packet[0]=0x45;packet[3]=40;packet[9]=6;packet[12]=1;packet[16]=2;
        packet[21]=9;packet[23]=8;packet[26]=3;packet[27]=0xe8;packet[32]=0x50;packet[33]=2;
        d2k_session_packet(sess,packet,40,1,scratch,sizeof scratch,&outcome);
        packet[3]=41;packet[33]=0x18;packet[40]='q';
        d2k_session_packet(sess,packet,41,2,scratch,sizeof scratch,&outcome);
        struct d2k_rawmeasure_report measured={0};measured.request=request;
        int prior=0;CHECK(!d2k_session_raw_identity(sess,&request.tuple,measured.request.epoch,&measured.request.generation,&prior),"trial command live identity fixture");
        measured.code=D2K_RM_REPEAT_SILENT;measured.sample_len=measured.smallest_data=measured.largest_data=1;
        measured.sample_seq=1000;measured.client_data=2;measured.exact_repeats=1;
        static const uint8_t digest[32]={0x8e,0x35,0xc2,0xcd,0x3b,0xf6,0x64,0x1b,0xdb,0x0e,0x20,0x50,0xb7,0x69,0x32,0xcb,0xb2,0xe6,0x03,0x4a,0x0d,0xda,0xcc,0x1d,0x9b,0xea,0x82,0xa6,0xba,0x57,0xf7,0xcf};
        memcpy(measured.sample_digest,digest,32);
        static const uint8_t program[]={'D','2','K','P',0,1,0,1,0,0,0,2,0,2,0,2,6,1,1,3,0,1,0};
        uint8_t command[D2K_RM_REPORT_LEN+20+sizeof program]={0};
        CHECK(!d2k_rawmeasure_report_write(command,D2K_RM_REPORT_LEN,&measured),"trial report encode");
        command[D2K_RM_REPORT_LEN]=0x55;command[D2K_RM_REPORT_LEN+18]=1;command[D2K_RM_REPORT_LEN+19]=0xf4;
        memcpy(command+D2K_RM_REPORT_LEN+20,program,sizeof program);
        command[61]^=1;d2k_ctlsrv_command(&cx,D2K_CMD_SET_RAW_PROBE,command,sizeof command);d2k_ctl_flush(c);
        CHECK(read_ack_token(cli,&cmd,&ok,tok)&&!ok&&tok[0]==0x55&&!d2k_plantab_probe_count(d2k_session_plans(sess)),"stale incarnation installed candidate");
        command[61]^=1;d2k_ctlsrv_command(&cx,D2K_CMD_SET_RAW_PROBE,command,sizeof command);d2k_ctl_flush(c);
        CHECK(read_ack_token(cli,&cmd,&ok,tok)&&ok&&cmd==D2K_CMD_SET_RAW_PROBE&&tok[0]==0x55,"measured trial not accepted with own token");
        CHECK(d2k_plantab_find_measured_probe(d2k_session_plans(sess),&request.tuple,measured.request.epoch,
              measured.request.generation,1000,(const uint8_t *)"q",1,3,tok)!=NULL,"accepted command did not install guarded plan");
        /* v27 lease renewal through the real command parser: identical
           report/trial/plan moves the expiry (and late delivery) only;
           changed evidence is refused and leaves the installed expiry. */
        const uint64_t ms=1000000ull;int hooks_before_renew=hook_addr_calls;
        cx.now_ns=200*ms;command[D2K_RM_REPORT_LEN+18]=0x03;command[D2K_RM_REPORT_LEN+19]=0xe8;
        d2k_ctlsrv_command(&cx,D2K_CMD_SET_RAW_PROBE,command,sizeof command);d2k_ctl_flush(c);
        CHECK(read_ack_token(cli,&cmd,&ok,tok)&&ok&&tok[0]==0x55&&d2k_plantab_probe_count(d2k_session_plans(sess))==1,
              "identical renewal refused or duplicated");
        CHECK(hook_addr_calls==hooks_before_renew+1&&hook_addr_last.installed&&hook_addr_last.expires_ns==1200*ms,
              "renewal did not extend late delivery to the new lease");
        CHECK(d2k_plantab_find_measured_probe(d2k_session_plans(sess),&request.tuple,measured.request.epoch,
              measured.request.generation,1000,(const uint8_t *)"q",1,700*ms,tok)!=NULL,"renewal did not outlive the first lease");
        struct d2k_rawmeasure_report altered=measured;altered.repeat_gap_ms=5;
        uint8_t changed[sizeof command];memcpy(changed,command,sizeof command);
        CHECK(!d2k_rawmeasure_report_write(changed,D2K_RM_REPORT_LEN,&altered),"altered report encode");
        changed[D2K_RM_REPORT_LEN+17]=0x10;cx.now_ns=300*ms;
        d2k_ctlsrv_command(&cx,D2K_CMD_SET_RAW_PROBE,changed,sizeof changed);d2k_ctl_flush(c);
        CHECK(read_ack_token(cli,&cmd,&ok,tok)&&!ok&&tok[0]==0x55,"renewal with altered evidence accepted");
        CHECK(hook_addr_calls==hooks_before_renew+1,"refused renewal touched late delivery");
        CHECK(d2k_plantab_find_measured_probe(d2k_session_plans(sess),&request.tuple,measured.request.epoch,
              measured.request.generation,1000,(const uint8_t *)"q",1,1100*ms,tok)!=NULL&&
              !d2k_plantab_find_measured_probe(d2k_session_plans(sess),&request.tuple,measured.request.epoch,
              measured.request.generation,1000,(const uint8_t *)"q",1,1200*ms,tok),"refused renewal moved the installed expiry");
        cx.now_ns=0;command[D2K_RM_REPORT_LEN+18]=1;command[D2K_RM_REPORT_LEN+19]=0xf4;
        d2k_ctlsrv_command(&cx,D2K_CMD_SET_RAW_PROBE,command,sizeof command);d2k_ctl_flush(c);
        CHECK(read_ack_token(cli,&cmd,&ok,tok)&&ok,"trial reinstall for cleanup checks");
        int hooks_before_delete=hook_addr_calls;
        uint8_t deletion[38+16]={0};deletion[0]=4;deletion[1]=1;deletion[17]=2;deletion[34]=9;deletion[36]=8;deletion[37]=6;deletion[38]=0x56;
        d2k_ctlsrv_command(&cx,D2K_CMD_DEL_ADDR_PROBE,deletion,sizeof deletion);d2k_ctl_flush(c);
        CHECK(read_ack_token(cli,&cmd,&ok,tok)&&ok&&d2k_plantab_probe_count(d2k_session_plans(sess))==1,"stale TCP cleanup removed another trial");
        CHECK(hook_addr_calls==hooks_before_delete,"stale TCP cleanup disabled active delivery");
        deletion[38]=0x55;d2k_ctlsrv_command(&cx,D2K_CMD_DEL_ADDR_PROBE,deletion,sizeof deletion);d2k_ctl_flush(c);
        CHECK(read_ack_token(cli,&cmd,&ok,tok)&&ok&&!d2k_plantab_probe_count(d2k_session_plans(sess)),"own TCP trial cleanup failed");
        CHECK(hook_addr_calls==hooks_before_delete+1 && !hook_addr_last.installed,"own TCP cleanup did not release delivery");

    }
#endif
    close(cli);d2k_ctl_close(c);d2k_session_free(sess);
}

int main(void) {
    snprintf(SOCK, sizeof SOCK, "/tmp/d2k-test-ctl-%ld.sock", (long)getpid());
    D2K_TEST_NAT_NO_TABLE();
    test_tcp_stall_wire();
    test_flow_fact_wire();
    test_late_observe_wire();
    test_raw_measure_command();
    test_probe_owner_disconnect();
    check_proto_greeting();
    check_stats_event();
    test_set_https();
    char err[160];
    d2k_ctl *c = d2k_ctl_open(SOCK, err, sizeof err);
    unsigned disconnects = 0;
    d2k_ctl_set_disconnect_hook(c, count_disconnect, &disconnects);
    CHECK(c != NULL, "сокет не создался");
    if (!c) {
        printf("  причина: %s\n", err);
        return 1;
    }

    /* --- событие без подключённого контроллера теряется -------------------- */
    {
        uint8_t body[4] = {1, 2, 3, 4};
        d2k_ctl_event(c, D2K_EV_HELLO, body, sizeof body);
        CHECK(d2k_ctl_dropped(c) == 1, "событие без собеседника не посчитано потерянным");
        CHECK(d2k_ctl_sent(c) == 0, "событие без собеседника сочтено отправленным");
    }

    int cli = dial();
    CHECK(cli >= 0, "клиент не подключился");
    d2k_ctl_accept(c);
    CHECK(d2k_ctl_peer_fd(c) >= 0, "подключение не принято");

    /* --- второй контроллер отвергается -------------------------------------
     * Двое поставили бы противоречащие планы, не зная друг о друге.          */
    {
        int cli2 = dial();
        d2k_ctl_accept(c);
        CHECK(d2k_ctl_peer_fd(c) >= 0, "первое подключение потеряно из-за второго");
        /* Второму закрыли — чтение вернёт ноль (конец файла). */
        if (cli2 >= 0) {
            uint8_t junk[4];
            ssize_t n = read(cli2, junk, sizeof junk);
            CHECK(n == 0, "второй контроллер не был отвергнут");
            close(cli2);
        }
    }

    /* --- событие доезжает байт в байт --------------------------------------- */
    {
        uint8_t body[5] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
        d2k_ctl_event(c, D2K_EV_SUSPECT, body, sizeof body);
        CHECK(d2k_ctl_sent(c) == 1, "событие не отправлено");

        uint8_t buf[64];
        ssize_t n = read(cli, buf, sizeof buf);
        CHECK(n == 11, "длина кадра события не та");
        uint8_t want[11];
        frame(want, D2K_EV_SUSPECT, body, sizeof body);
        CHECK(n == 11 && memcmp(buf, want, 11) == 0, "байты кадра события разошлись");
    }

    /* --- ВСПЛЕСК СОБЫТИЙ УЧТЁН ДО ЕДИНОГО И НЕ ПОРВАН ---------------------
     *
     * Здесь был буфер ровно на один недописанный кадр: пока хвост не ушёл,
     * каждое следующее событие терялось. На роутере владельца 13.09.2026 это
     * стоило 173 потерянных уведомлений за одно окно сводки и 269 раз
     * «зонд прошёл, а применения этого плана к его потоку не было» — то есть
     * двести шестьдесят девять НАЙДЕННЫХ обходов, выброшенных из-за канала.
     *
     * Проверяются два инварианта, и оба детерминированы, в отличие от
     * «ничего не теряется» (это зависит от размеров буферов сокета, которые
     * ядро вправе не уменьшать по просьбе — проверено, SO_RCVBUF на AF_UNIX
     * здесь не срабатывает):
     *
     *   1. СЧЁТ СХОДИТСЯ: принято + потеряно = отправлено. Ни одно событие не
     *      исчезает молча.
     *   2. КАДРЫ ЦЕЛЫЕ: в потоке нет половины кадра. Половина
     *      рассинхронизировала бы разбор у контроллера навсегда, и это хуже
     *      потери: контроллер после неё не понимает НИЧЕГО. */
    {
        uint8_t body[5] = {0x11, 0x22, 0x33, 0x44, 0x55};
        const int burst = 20000;              /* заведомо больше любого буфера */
        /* Читаем НЕБЛОКИРУЮЩЕ: иначе последний read повиснет навсегда, когда
           отдавать станет нечего. */
        (void)fcntl(cli, F_SETFL, O_NONBLOCK);
        uint64_t drop0 = d2k_ctl_dropped(c);
        uint64_t sent0 = d2k_ctl_sent(c);
        size_t got_bytes = 0;
        uint8_t buf[8192];

        for (int i = 0; i < burst; i++) {
            d2k_ctl_event(c, D2K_EV_SUSPECT, body, sizeof body);
            /* Собеседник читает лениво — раз в сто событий. */
            if ((i % 100) == 0) {
                ssize_t n = read(cli, buf, sizeof buf);
                if (n > 0) { got_bytes += (size_t)n; }
            }
        }
        for (int i = 0; i < 10000; i++) {
            d2k_ctl_flush(c);
            ssize_t n = read(cli, buf, sizeof buf);
            if (n <= 0) { break; }
            got_bytes += (size_t)n;
        }

        uint64_t accepted = d2k_ctl_sent(c) - sent0;
        uint64_t lost = d2k_ctl_dropped(c) - drop0;
        CHECK(accepted + lost == (uint64_t)burst,
              "счёт не сходится: часть событий исчезла, не попав ни в принятые, ни в потерянные");
        CHECK(got_bytes % 11u == 0,
              "в потоке половина кадра — разбор у контроллера сломан навсегда");
        CHECK(got_bytes / 11u == accepted,
              "дошло не столько кадров, сколько принято");
    }

    /* --- команда целиком ------------------------------------------------------ */
    {
        n_got = 0;
        uint8_t body[3] = {7, 8, 9};
        uint8_t f[16];
        frame(f, D2K_CMD_DEL_ADDR, body, sizeof body);
        CHECK(write(cli, f, 9) == 9, "команда не записалась");
        CHECK(d2k_ctl_poll(c, on_cmd, NULL) == 1, "команда не разобрана");
        CHECK(n_got == 1 && got[0].type == D2K_CMD_DEL_ADDR, "тип команды не тот");
        CHECK(n_got == 1 && got[0].len == 3 && got[0].body[2] == 9,
              "тело команды не то");
    }

    /* --- команда по кускам ------------------------------------------------------
     * Поток не обязан приходить кадрами. Разбор, который на это надеется,
     * ломается ровно тогда, когда команда большая — то есть когда в ней план. */
    {
        n_got = 0;
        uint8_t body[8] = {1, 2, 3, 4, 5, 6, 7, 8};
        uint8_t f[16];
        frame(f, D2K_CMD_SET_ADDR, body, sizeof body);
        CHECK(write(cli, f, 3) == 3, "первый кусок не записался");
        CHECK(d2k_ctl_poll(c, on_cmd, NULL) == 0, "полкадра разобрано как кадр");
        CHECK(n_got == 0, "обратный вызов случился на половине кадра");
        CHECK(write(cli, f + 3, 11) == 11, "второй кусок не записался");
        CHECK(d2k_ctl_poll(c, on_cmd, NULL) == 1, "кадр не собрался из кусков");
        CHECK(n_got == 1 && got[0].len == 8, "собранный кадр повреждён");
    }

    /* --- два кадра в одной записи ------------------------------------------- */
    {
        n_got = 0;
        uint8_t a[2] = {0x11, 0x22}, b[1] = {0x33};
        uint8_t f[16];
        frame(f, D2K_CMD_DEL_ADDR, a, sizeof a);
        frame(f + 8, D2K_CMD_CLEAR, b, sizeof b);
        CHECK(write(cli, f, 8 + 7) == 15, "пара кадров не записалась");
        CHECK(d2k_ctl_poll(c, on_cmd, NULL) == 2, "из двух кадров разобран не два");
        CHECK(n_got == 2 && got[1].type == D2K_CMD_CLEAR, "второй кадр не тот");
    }

    /* --- врущая длина рвёт соединение ---------------------------------------
     * Идти дальше по потоку нельзя: следующий заголовок пришлось бы искать по
     * выдуманному смещению.                                                   */
    {
        uint8_t f[8];
        f[0] = 0xFF; f[1] = 0xFF; f[2] = 0xFF; f[3] = 0xFF;
        f[4] = 0; f[5] = 1;
        CHECK(write(cli, f, 6) == 6, "кадр с врущей длиной не записался");
        CHECK(d2k_ctl_poll(c, on_cmd, NULL) == -1, "врущая длина не порвала соединение");
        CHECK(d2k_ctl_peer_fd(c) == -1, "собеседник остался после врущей длины");
        CHECK(disconnects == 1, "invalid frame must retire controller ownership");
        close(cli);
    }

    /* --- исчезнувший собеседник ---------------------------------------------- */
    {
        cli = dial();
        d2k_ctl_accept(c);
        CHECK(d2k_ctl_peer_fd(c) >= 0, "переподключение не принято");
        close(cli);
        CHECK(d2k_ctl_poll(c, on_cmd, NULL) == -1, "уход собеседника не замечен");
        CHECK(d2k_ctl_peer_fd(c) == -1, "собеседник числится живым после ухода");
        CHECK(disconnects == 2, "EOF must retire the next controller ownership");
    }

    /* --- слишком большое событие теряется, а не переполняет буфер ------------ */
    {
        cli = dial();
        d2k_ctl_accept(c);
        static uint8_t huge[D2K_CTL_FRAME_MAX];
        memset(huge, 0x5A, sizeof huge);
        uint64_t before = d2k_ctl_dropped(c);
        d2k_ctl_event(c, D2K_EV_STATS, huge, sizeof huge);
        CHECK(d2k_ctl_dropped(c) == before + 1, "великан не посчитан потерянным");
        close(cli);
    }

    /* --- текст причины выводится из кода, а не наоборот ---------------------- */
    {
        CHECK(strcmp(d2k_suspect_text(D2K_SUSPECT_RST),
                     "сброс в ответ на приветствие") == 0, "текст причины RST не тот");
        CHECK(strcmp(d2k_suspect_text(D2K_SUSPECT_RST_AFTER_APP),
                     "сброс клиента или сервера после TLS app-data; проверить объём ответа") == 0,
              "поздний TLS-сброс потерял отдельное диагностическое значение");
        CHECK(strcmp(d2k_suspect_text(D2K_SUSPECT_FIN_RETRY),
                     "FIN клиента повторён без ответа после ответа сервера; проверить объём ответа") == 0,
              "повтор FIN без ответа потерял отдельное диагностическое значение");
        CHECK(d2k_suspect_text(200) != NULL, "неизвестный код без текста");
    }

    /* --- SET_NAME/SET_ADDR настоящим разбором (d2k_ctlsrv_command) ------------
     *
     * До сих пор этот файл проверял только framing сокета (d2k_ctl.c) —
     * подделанным обратным вызовом on_cmd. Отказ «нет места» отличим от
     * отказа «план негоден» именно в РАЗБОРЕ команды (ctlsrv.c), и его
     * нельзя проверить подделкой: настоящая сессия, настоящая таблица
     * планов, настоящий ack.
     *
     * Вместимость таблицы планов — d2k_session_new(2, 0) — выводится из
     * вместимости таблицы потоков (2), а не из литерала: тот же вывод,
     * что делает session.c из --flows. Маленькая специально: переполнение
     * достижимо третьей же командой. */
    {
        d2k_session *sess = d2k_session_new(2, 0);
        CHECK(sess != NULL, "сессия для разбора команд не создалась");

        d2k_ctlsrv cx;
        memset(&cx, 0, sizeof cx);
        cx.sess = sess;
        cx.ctl = c;
        /* 0 — только наблюдение, d2k_plan_fits тогда пропускает любой план
           (см. её комментарий): у этого блока задача — различить причины
           ОТКАЗА разбора команды, а не причины непригодности плана коробке,
           это отдельно проверено в internal/control/bridge_test.go. */
        cx.send_limits = 0;

        /* Предыдущий блок закрыл своего cli, но ни разу не поллил c после
           этого — сервер узнаёт об уходе собеседника только через
           d2k_ctl_poll/d2k_ctl_flush (см. drop_peer в ctl.c), а не сам
           по себе. Без этого d2k_ctl_peer_fd(c) всё ещё показывает СТАРЫЙ
           fd занятым, и accept() ниже отверг бы наше новое подключение как
           «второго контроллера» (см. блок «второй контроллер отвергается»
           выше) — молча, а запись в уже закрытый cli падала бы SIGPIPE. */
        d2k_ctl_poll(c, on_cmd, NULL);
        CHECK(d2k_ctl_peer_fd(c) == -1, "старый собеседник не отвалился перед новым подключением");

        cli = dial();
        CHECK(cli >= 0, "клиент для разбора команд не подключился");
        d2k_ctl_accept(c);
        CHECK(d2k_ctl_peer_fd(c) >= 0, "подключение для разбора команд не принято");
        /* Exercise exact service commands through the real command decoder. */
        {
            d2k_session *services = d2k_session_new(8,0);
            CHECK(services != NULL,"endpoint command session");
            cx.sess = services;
            d2k_plantab *tab = d2k_session_plans(services);
            for (unsigned family=4; family<=6; family+=2) {
                uint8_t body[20+sizeof tiny];
                memset(body,0,sizeof body);
                body[0]=family; body[1]=0x20; body[2]=1; body[3]=0xd; body[4]=0xb8;
                if (family==6) body[16]=1;
                body[17]=D2K_PLAN_SHAPE_MODERN;
                memcpy(body+20,tiny,sizeof tiny);
                uint16_t cmd; int ok; uint8_t reason;
                for (unsigned port=443;port<=444;port++) {
                    body[18]=port>>8; body[19]=port;
                    d2k_ctlsrv_command(&cx,D2K_CMD_SET_ENDPOINT,body,sizeof body);
                    d2k_ctl_flush(c);
                    CHECK(read_ack(cli,&cmd,&ok,&reason)==1 && cmd==D2K_CMD_SET_ENDPOINT && ok,
                          "exact service SET acknowledgement");
                }
                CHECK(d2k_plantab_find_target_endpoint(tab,NULL,0,body+1,family,1,
                    D2K_PLAN_SHAPE_MODERN,0,htons(443)) != NULL,"decoded service port 443");
                CHECK(d2k_plantab_find_target_endpoint(tab,NULL,0,body+1,family,1,
                    D2K_PLAN_SHAPE_MODERN,0,htons(445)) == NULL,"decoder cannot broaden service");
                {
                    uint8_t bound[sizeof body+D2K_TRIAL_ID_LEN], response[256];
                    memcpy(bound,body,sizeof body);
                    memset(bound+sizeof body,0,D2K_TRIAL_ID_LEN);
                    bound[sizeof body]=0x71;
                    bound[18]=1;bound[19]=0xbf;
                    d2k_ctlsrv_command(&cx,D2K_CMD_SET_ENDPOINT_BOUND,bound,sizeof bound);
                    d2k_ctl_flush(c);
                    uint16_t kind=0;
                    ssize_t nr=read_event(cli,&kind,response,sizeof response);
                    size_t base=D2K_KEY_WIRE_LEN;
                    d2k_binding_context binding={0};
                    CHECK(kind==D2K_EV_ACK && nr==(ssize_t)(base+4+D2K_TRIAL_ID_LEN+D2K_CTL_BINDING_LEN) &&
                          response[base+1]==D2K_CMD_SET_ENDPOINT_BOUND && response[base+2]==1 &&
                          !memcmp(response+base+4,bound+sizeof body,D2K_TRIAL_ID_LEN) &&
                          !d2k_ctl_binding_read(&binding,response+base+4+D2K_TRIAL_ID_LEN,D2K_CTL_BINDING_LEN) &&
                          d2k_binding_known(&binding) && binding.kind==D2K_BIND_ADDR &&
                          binding.family==family && !binding.temporary,
                          "service installation ACK binds request token to installed generation");
                    bound[18]=bound[19]=0;
                    d2k_ctlsrv_command(&cx,D2K_CMD_SET_ENDPOINT_BOUND,bound,sizeof bound);
                    d2k_ctl_flush(c);
                    uint8_t returned[D2K_TRIAL_ID_LEN];
                    CHECK(read_ack_token(cli,&cmd,&ok,returned) && !ok &&
                          cmd==D2K_CMD_SET_ENDPOINT_BOUND &&
                          !memcmp(returned,bound+sizeof body,D2K_TRIAL_ID_LEN),
                          "rejected service installation echoes its own request token");
                }
                body[18]=1;body[19]=0xbb;
                d2k_ctlsrv_command(&cx,D2K_CMD_DEL_ENDPOINT,body,20);
                d2k_ctl_flush(c);
                CHECK(read_ack(cli,&cmd,&ok,&reason)==1 && cmd==D2K_CMD_DEL_ENDPOINT && ok,
                      "exact service DEL acknowledgement");
                CHECK(d2k_plantab_find_target_endpoint(tab,NULL,0,body+1,family,1,
                    D2K_PLAN_SHAPE_MODERN,0,htons(443)) == NULL,"decoded deletion removes exact service");
                CHECK(d2k_plantab_find_target_endpoint(tab,NULL,0,body+1,family,1,
                    D2K_PLAN_SHAPE_MODERN,0,htons(444)) != NULL,"decoded deletion preserves other port");
                body[18]=body[19]=0;
                d2k_ctlsrv_command(&cx,D2K_CMD_SET_ENDPOINT,body,sizeof body);
                d2k_ctl_flush(c);
                CHECK(read_ack(cli,&cmd,&ok,&reason)==1 && !ok && reason==D2K_ACK_BAD_ARGS,
                      "zero service port rejected");
                d2k_ctlsrv_command(&cx,D2K_CMD_DEL_ENDPOINT,body,19);
                d2k_ctl_flush(c);
                CHECK(read_ack(cli,&cmd,&ok,&reason)==1 && !ok && reason==D2K_ACK_BAD_ARGS,
                      "truncated service delete rejected");
            }
            for (unsigned family=4;family<=6;family+=2) {
                uint8_t rawplan[]={'D','2','K','P',0,1,0,1,0,0,0,2,0,2,0,2,6,1,1,3,0,1,0};
                uint8_t body[20+sizeof rawplan]; memset(body,0,sizeof body);
                body[0]=family; body[1]=192; body[4]=9; body[17]=D2K_PLAN_SHAPE_RAW;
                body[18]=1;body[19]=187;
                uint16_t cmd;int ok;uint8_t reason;
                for (unsigned tr=6;tr<=17;tr+=11) {
                    rawplan[16]=tr;rawplan[17]=tr==6?1:2;memcpy(body+20,rawplan,sizeof rawplan);
                    d2k_ctlsrv_command(&cx,D2K_CMD_SET_ENDPOINT,body,sizeof body);d2k_ctl_flush(c);
                    CHECK(read_ack(cli,&cmd,&ok,&reason)==1 && ok,"RAW service SET acknowledged");
                }
                CHECK(d2k_plantab_find_target_endpoint_tr(tab,NULL,0,body+1,family,1,D2K_PLAN_SHAPE_RAW,0,htons(443),6)!=NULL,
                      "RAW TCP installed through control");
                CHECK(d2k_plantab_find_target_endpoint_tr(tab,NULL,0,body+1,family,1,D2K_PLAN_SHAPE_RAW,0,htons(443),17)!=NULL,
                      "RAW UDP coexists through control");
                d2k_ctlsrv_command(&cx,D2K_CMD_DEL_ENDPOINT,body,20);d2k_ctl_flush(c);
                CHECK(read_ack(cli,&cmd,&ok,&reason)==1 && !ok,"ambiguous RAW wire deletion refused");
                body[20]=6;d2k_ctlsrv_command(&cx,D2K_CMD_DEL_ENDPOINT,body,21);d2k_ctl_flush(c);
                CHECK(read_ack(cli,&cmd,&ok,&reason)==1 && ok,"RAW TCP wire deletion acknowledged");
                CHECK(d2k_plantab_find_target_endpoint_tr(tab,NULL,0,body+1,family,1,D2K_PLAN_SHAPE_RAW,0,htons(443),6)==NULL,
                      "RAW TCP removed through control");
                CHECK(d2k_plantab_find_target_endpoint_tr(tab,NULL,0,body+1,family,1,D2K_PLAN_SHAPE_RAW,0,htons(443),17)!=NULL,
                      "RAW UDP survives TCP wire deletion");
                body[20]=17;d2k_ctlsrv_command(&cx,D2K_CMD_DEL_ENDPOINT,body,21);d2k_ctl_flush(c);
                CHECK(read_ack(cli,&cmd,&ok,&reason)==1 && ok,"RAW UDP wire deletion acknowledged");
            }
            cx.sess=sess;
            d2k_session_free(services);
        }


        {
            uint8_t body[64];
            size_t n = set_name_body_shaped(body, "googlevideo.com", tiny, sizeof tiny, 1);
            memset(body+n, 0x72, D2K_TRIAL_ID_LEN); n += D2K_TRIAL_ID_LEN;
            d2k_ctlsrv_command(&cx, D2K_CMD_SET_SUFFIX, body, n);
            CHECK(d2k_plantab_find(d2k_session_plans(sess),
                (const uint8_t *)"rr-new.googlevideo.com", 22, 0, 1, 1) != NULL,
                "ctl suffix installs first unseen child");
            d2k_ctl_flush(c);
            uint16_t cmd; int ok; uint8_t reason;
            CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && cmd == D2K_CMD_SET_SUFFIX && ok,
                "suffix ACK confirms installation");
            CHECK(last_ack_id[0]==0x72 && last_ack_id[15]==0x72,
                "suffix ACK echoes the complete command identity");
            const char *name = "rr-new.googlevideo.com";
            n = strlen(name); body[0] = (uint8_t)n; memcpy(body+1, name, n);
            body[n+1] = 6; body[n+2] = 1; body[n+3] = 4;
            memset(body+n+4, 0x73, D2K_TRIAL_ID_LEN);
            d2k_ctlsrv_command(&cx, D2K_CMD_SET_BYPASS, body, n+4+D2K_TRIAL_ID_LEN);
            CHECK(!d2k_plantab_find(d2k_session_plans(sess), (const uint8_t *)name, n, 0, 2, 1),
                "ctl bypass excludes child");
            d2k_ctl_flush(c);
            CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && ok, "bypass ACK");
            CHECK(last_ack_id[0]==0x73 && last_ack_id[15]==0x73,
                "bypass ACK echoes its separate command identity");
            d2k_ctlsrv_command(&cx, D2K_CMD_DEL_BYPASS, body, n+4+D2K_TRIAL_ID_LEN);
            d2k_ctl_flush(c);
            CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && ok, "remove bypass ACK");
            CHECK(d2k_plantab_find(d2k_session_plans(sess), (const uint8_t *)name, n, 0, 3, 1),
                "ctl remove bypass restores group");
        }
        /* Годная команда: ack ok=1, причина D2K_ACK_OK. */
        {
            uint8_t body[64], f[80];
            size_t blen = set_name_body(body, "ok.example", tiny, sizeof tiny);
            frame(f, D2K_CMD_SET_NAME, body, blen);
            CHECK(write(cli, f, 6 + blen) == (ssize_t)(6 + blen), "годная команда не отправилась");
            CHECK(poll_frames(c, d2k_ctlsrv_command, &cx, 1) == 1, "годная команда не разобралась");
            d2k_ctl_flush(c);
            uint16_t cmd = 0; int ok = 0; uint8_t reason = 0;
            ok = 0;
            CHECK(read_ack(cli, &cmd, &ok, &reason) == 1, "ack на годную команду не пришёл");
            CHECK(cmd == D2K_CMD_SET_NAME, "ack не на ту команду");
            CHECK(ok == 1, "годная команда отвергнута");
            CHECK(reason == D2K_ACK_OK, "у успеха причина не D2K_ACK_OK");
        }

        /* Точная очистка пробного имени не должна удалять подтверждённую
           запись той же цели. */
        {
            const char *nm = "ok.example";
            uint8_t body[96], f[112];
            size_t nl = strlen(nm), o = 0;
            body[o++] = (uint8_t)nl; memcpy(body + o, nm, nl); o += nl;
            body[o++] = D2K_PLAN_SHAPE_QUIC;
            body[o++] = 4;
            body[o++] = 0x9c; body[o++] = 0x40; /* port 40000 */
            memcpy(body + o, tiny, sizeof tiny); o += sizeof tiny;
            /* v8: хвост — trial ID опыта; ACK обязан вернуть его же. */
            memset(body + o, 0x5a, D2K_TRIAL_ID_LEN); o += D2K_TRIAL_ID_LEN;
            frame(f, D2K_CMD_SET_NAME_PROBE, body, o);
            CHECK(write(cli, f, 6 + o) == (ssize_t)(6 + o), "SET_NAME_PROBE для удаления не отправилась");
            CHECK(poll_frames(c, d2k_ctlsrv_command, &cx, 1) == 1, "SET_NAME_PROBE для удаления не разобралась");
            d2k_ctl_flush(c);
            uint16_t cmd = 0; int ok = 0; uint8_t reason = 0;
            CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && ok == 1,
                  "SET_NAME_PROBE для удаления не принялась");
            CHECK(cmd == D2K_CMD_SET_NAME_PROBE &&
                  last_ack_id[0] == 0x5a && last_ack_id[15] == 0x5a,
                  "ACK SET_NAME_PROBE не вернул trial ID опыта");
            o = 0; body[o++] = (uint8_t)nl; memcpy(body + o, nm, nl); o += nl;
            body[o++] = D2K_PLAN_SHAPE_QUIC; body[o++] = 4;
            body[o++] = 0x9c; body[o++] = 0x40;
            frame(f, D2K_CMD_DEL_NAME_PROBE, body, o);
            CHECK(write(cli, f, 6 + o) == (ssize_t)(6 + o), "DEL_NAME_PROBE не отправилась");
            CHECK(poll_frames(c, d2k_ctlsrv_command, &cx, 1) == 1, "DEL_NAME_PROBE не разобралась");
            d2k_ctl_flush(c);
            CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && ok == 1,
                  "DEL_NAME_PROBE не получила ACK");
            d2k_plantab *tab = d2k_session_plans(sess);
            CHECK(d2k_plantab_find(tab, (const uint8_t *)nm, nl, 0, cx.now_ns,
                                   D2K_PLAN_SHAPE_QUIC) != NULL,
                  "DEL_NAME_PROBE задела подтверждённый SET_NAME");
        }

        /* Same name in two families: commands cannot replace/delete the other. */
        {
            const char *nm = "dual.example";
            size_t nl = strlen(nm);
            uint8_t body[96], f[112];
            d2k_plantab *tab = d2k_session_plans(sess);
            for (uint8_t family = 4; family <= 6; family += 2) {
                size_t blen = set_name_body(body, nm, tiny, sizeof tiny);
                body[2 + nl] = family;
                frame(f, D2K_CMD_SET_NAME, body, blen);
                CHECK(write(cli, f, 6 + blen) == (ssize_t)(6 + blen), "dual SET write");
                CHECK(poll_frames(c, d2k_ctlsrv_command, &cx, 1) == 1, "dual SET parse");
                d2k_ctl_flush(c);
                uint16_t cmd; int ok; uint8_t reason;
                CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && ok, "dual SET ack");
            }
            CHECK(d2k_plantab_find_family(tab, (const uint8_t *)nm, nl, 0,
                    cx.now_ns, D2K_PLAN_SHAPE_QUIC, 0, 4) != NULL, "IPv4 plan retained");
            CHECK(d2k_plantab_find_family(tab, (const uint8_t *)nm, nl, 0,
                    cx.now_ns, D2K_PLAN_SHAPE_QUIC, 0, 6) != NULL, "IPv6 plan installed");
            uint16_t cmd; int ok; uint8_t reason;
            /* Прежнее тело v8 (без транспорта и формы) — отказ, а не «снять
               всё имя»: смешанная пара не превращает точное снятие в широкое. */
            body[0] = (uint8_t)nl; memcpy(body + 1, nm, nl); body[1 + nl] = 6;
            frame(f, D2K_CMD_DEL_NAME, body, nl + 2);
            CHECK(write(cli, f, nl + 8) == (ssize_t)(nl + 8), "old DEL write");
            CHECK(poll_frames(c, d2k_ctlsrv_command, &cx, 1) == 1, "old DEL parse");
            d2k_ctl_flush(c);
            CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && !ok &&
                  reason == D2K_ACK_BAD_ARGS, "v8 DEL_NAME body must be rejected");
            CHECK(d2k_plantab_find_family(tab, (const uint8_t *)nm, nl, 0,
                    cx.now_ns, D2K_PLAN_SHAPE_QUIC, 0, 6) != NULL, "rejected DEL removed a plan");
            /* v9: длина, имя, транспорт, форма, семейство. */
            body[1 + nl] = 6; body[2 + nl] = D2K_PLAN_SHAPE_GRANDFATHER; body[3 + nl] = 6;
            frame(f, D2K_CMD_DEL_NAME, body, nl + 4);
            CHECK(write(cli, f, nl + 10) == (ssize_t)(nl + 10), "dual DEL write");
            CHECK(poll_frames(c, d2k_ctlsrv_command, &cx, 1) == 1, "dual DEL parse");
            d2k_ctl_flush(c);
            CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && ok, "dual DEL ack");
            CHECK(d2k_plantab_find_family(tab, (const uint8_t *)nm, nl, 0,
                    cx.now_ns, D2K_PLAN_SHAPE_QUIC, 0, 4) != NULL, "IPv6 delete preserves IPv4");
            CHECK(d2k_plantab_find_family(tab, (const uint8_t *)nm, nl, 0,
                    cx.now_ns, D2K_PLAN_SHAPE_QUIC, 0, 6) == NULL, "IPv6 delete scoped");
            d2k_plantab_del_name(tab, (const uint8_t *)nm, nl);
        }

        /* Адресная проба передаёт полный 5-tuple и поколение отдельно от
           Plan ID. DELETE старого поколения не должен снимать активную. */
        for (uint8_t family = 4; family <= 6; family += 2) {
            uint8_t body[128], f[160], trial[D2K_TRIAL_ID_LEN];
            memset(trial, 0, sizeof trial);
            for (size_t i = 0; i < sizeof trial; i++) { trial[i] = (uint8_t)(i + 1); }
            uint8_t flow_wire[38] = {
                [0]=4, [1]=192, [3]=2, [4]=10,
                [17]=203, [19]=113, [20]=7,
                [33]=0x9c, [34]=0x40, [35]=0x01, [36]=0xbb, [37]=17
            };
            if (family == 6) {
                flow_wire[0] = 6;
                memset(flow_wire + 1, 0, 32);
                flow_wire[1] = flow_wire[17] = 0x20;
                flow_wire[2] = flow_wire[18] = 1;
                flow_wire[3] = flow_wire[19] = 0xdb;
                flow_wire[4] = flow_wire[20] = 8;
                flow_wire[16] = 1; flow_wire[32] = 2;
            }
            /* Invalid transport and zero generation must reject before the
               temporary table changes. The ACK echoes the address-trial ID. */
            memcpy(body, flow_wire, sizeof flow_wire);
            body[37] = 6;
            memcpy(body + 38, trial, sizeof trial);
            body[54] = 0; body[55] = 0; body[56] = 0xea; body[57] = 0x60;
            memcpy(body + 58, tiny, sizeof tiny);
            frame(f, 0x0089u, body, 58 + sizeof tiny);
            CHECK(write(cli, f, 6 + 58 + sizeof tiny) == (ssize_t)(6 + 58 + sizeof tiny),
                  "SET_ADDR_PROBE с неверным transport не отправилась");
            CHECK(poll_frames(c, d2k_ctlsrv_command, &cx, 1) == 1,
                  "SET_ADDR_PROBE с неверным transport не разобралась");
            d2k_ctl_flush(c);
            uint16_t cmd = 0; int ok = 1; uint8_t reason = 0;
            CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && cmd == 0x0089u &&
                  ok == 0 && reason == D2K_ACK_BAD_ARGS,
                  "неверный transport адресной пробы не получил BAD_ARGS");

            memcpy(body, flow_wire, sizeof flow_wire);
            memset(body + 38, 0, D2K_TRIAL_ID_LEN);
            body[54] = 0; body[55] = 0; body[56] = 0xea; body[57] = 0x60;
            memcpy(body + 58, tiny, sizeof tiny);
            frame(f, 0x0089u, body, 58 + sizeof tiny);
            CHECK(write(cli, f, 6 + 58 + sizeof tiny) == (ssize_t)(6 + 58 + sizeof tiny),
                  "SET_ADDR_PROBE с нулевым trial ID не отправилась");
            CHECK(poll_frames(c, d2k_ctlsrv_command, &cx, 1) == 1,
                  "SET_ADDR_PROBE с нулевым trial ID не разобралась");
            d2k_ctl_flush(c);
            CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && ok == 0 &&
                  reason == D2K_ACK_BAD_ARGS,
                  "нулевой trial ID адресной пробы не получил BAD_ARGS");

            memcpy(body, flow_wire, sizeof flow_wire);
            memcpy(body + 38, trial, sizeof trial);
            body[54] = 0; body[55] = 0; body[56] = 0xea; body[57] = 0x60;
            memcpy(body + 58, tiny, sizeof tiny);
            size_t blen = 58 + sizeof tiny;
            frame(f, 0x0089u, body, blen);
            CHECK(write(cli, f, 6 + blen) == (ssize_t)(6 + blen),
                  "адресная проба не отправилась");
            CHECK(poll_frames(c, d2k_ctlsrv_command, &cx, 1) == 1,
                  "SET_ADDR_PROBE не разобралась");
            d2k_ctl_flush(c);
            ok = 0;
            CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && cmd == 0x0089u && ok == 1,
                  "валидная SET_ADDR_PROBE не подтвердилась");
            d2k_addr_probe_flow flow = {
                .src_ip4 = {192, 0, 2, 10}, .src_port_be = 0x409c,
                .dst_ip4 = {203, 0, 113, 7}, .dst_port_be = 0xbb01,
                .transport = 17
            };
            flow.family = family;
            memcpy(&flow.src_port_be, flow_wire + 33, 2);
            memcpy(&flow.dst_port_be, flow_wire + 35, 2);
            if (family == 6) {
                memcpy(flow.src_ip6, flow_wire + 1, 16);
                memcpy(flow.dst_ip6, flow_wire + 17, 16);
            }
            uint8_t seen[D2K_TRIAL_ID_LEN] = {0};
            d2k_plantab *tab = d2k_session_plans(sess);
            CHECK(d2k_plantab_find_addr_probe(tab, &flow, cx.now_ns, seen) != NULL &&
                  memcmp(seen, trial, sizeof seen) == 0,
                  "разобранный SET_ADDR_PROBE потерял flow/generation");

            memcpy(body, flow_wire, sizeof flow_wire);
            memcpy(body + 38, trial, sizeof trial);
            body[38] ^= 0xff;
            frame(f, 0x008au, body, 54);
            CHECK(write(cli, f, 60) == 60, "stale DEL_ADDR_PROBE не отправилась");
            CHECK(poll_frames(c, d2k_ctlsrv_command, &cx, 1) == 1,
                  "stale DEL_ADDR_PROBE не разобралась");
            d2k_ctl_flush(c);
            CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && ok == 1,
                  "stale delete не получил идемпотентный ACK");
            CHECK(!memcmp(last_ack_id,body+38,D2K_TRIAL_ID_LEN),
                  "stale delete ACK must name the stale trial, never the active owner");
            CHECK(d2k_plantab_find_addr_probe(tab, &flow, cx.now_ns, NULL) != NULL,
                  "stale delete снял probe другого поколения");
            memcpy(body+38,trial,sizeof trial);body[37]=1;
            d2k_ctlsrv_command(&cx,D2K_CMD_DEL_ADDR_PROBE,body,54);
            d2k_ctl_flush(c);
            CHECK(read_ack(cli,&cmd,&ok,&reason)==1 && !ok && reason==D2K_ACK_BAD_ARGS &&
                  !memcmp(last_ack_id,trial,sizeof trial),"rejected delete ACK retains trial identity");
            CHECK(d2k_plantab_find_addr_probe(tab,&flow,cx.now_ns,NULL)!=NULL,
                  "rejected delete preserves active trial");

            memcpy(body, flow_wire, sizeof flow_wire);
            memcpy(body + 38, trial, sizeof trial);
            frame(f, 0x008au, body, 54);
            CHECK(write(cli, f, 60) == 60, "точный DEL_ADDR_PROBE не отправилась");
            CHECK(poll_frames(c, d2k_ctlsrv_command, &cx, 1) == 1,
                  "точный DEL_ADDR_PROBE не разобралась");
            d2k_ctl_flush(c);
            CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && ok == 1 &&
                  d2k_plantab_find_addr_probe(tab, &flow, cx.now_ns, NULL) == NULL,
                  "точный delete не удалил только свой probe");
            CHECK(!memcmp(last_ack_id,trial,sizeof trial),"successful delete ACK retains exact trial identity");
        }

        /* Байты плана не разбираются: ack ok=0, причина D2K_ACK_BAD_PLAN —
           «план негоден», а не «нет места». Раньше (ack(cx, type, rc == 0))
           это было той же самой единицей отказа, что и переполнение таблицы:
           контроллер не мог их различить (см. d2k_ctl.h). */
        {
            static const uint8_t garbage[8] = {0, 0, 0, 0, 0, 0, 0, 0};
            uint8_t body[64], f[80];
            size_t blen = set_name_body(body, "bad.example", garbage, sizeof garbage);
            frame(f, D2K_CMD_SET_NAME, body, blen);
            CHECK(write(cli, f, 6 + blen) == (ssize_t)(6 + blen), "негодный план не отправился");
            CHECK(poll_frames(c, d2k_ctlsrv_command, &cx, 1) == 1, "негодный план не разобрался");
            d2k_ctl_flush(c);
            uint16_t cmd = 0; int ok = 0; uint8_t reason = 0;
            CHECK(read_ack(cli, &cmd, &ok, &reason) == 1, "ack на негодный план не пришёл");
            CHECK(ok == 0, "негодный план подтверждён как принятый");
            CHECK(reason == D2K_ACK_BAD_PLAN, "негодный план не помечен D2K_ACK_BAD_PLAN");
        }

        /* Имя пустое: ack ok=0, причина D2K_ACK_BAD_ARGS. План тут годный —
           отказала САМА КОМАНДА, а не план; смешивать с BAD_PLAN нельзя. */
        {
            uint8_t body[32], f[48];
            body[0] = 0;
            body[1] = D2K_PLAN_SHAPE_GRANDFATHER;
            body[2] = 4;
            memcpy(body + 3, tiny, sizeof tiny);
            size_t blen = 3 + sizeof tiny;
            frame(f, D2K_CMD_SET_NAME, body, blen);
            CHECK(write(cli, f, 6 + blen) == (ssize_t)(6 + blen), "команда с пустым именем не отправилась");
            CHECK(poll_frames(c, d2k_ctlsrv_command, &cx, 1) == 1, "команда с пустым именем не разобралась");
            d2k_ctl_flush(c);
            uint16_t cmd = 0; int ok = 0; uint8_t reason = 0;
            CHECK(read_ack(cli, &cmd, &ok, &reason) == 1, "ack на пустое имя не пришёл");
            CHECK(ok == 0, "пустое имя принято как цель");
            CHECK(reason == D2K_ACK_BAD_ARGS, "пустое имя не помечено D2K_ACK_BAD_ARGS");
        }

        /* SET_ADDR/DEL_ADDR несут форму протокола (v7, задача 16): QUIC и
           голос одного IP — две записи; привязка без формы не принимается;
           снятие одной формы не трогает другую. Таблица возвращается к одной
           записи — блок ниже считает от неё. */
        {
            d2k_plantab *tab = d2k_session_plans(sess);
            const uint8_t voice[] = D2K_VOICE_CLASS;
            uint8_t ip[4] = {198, 51, 100, 23};
            uint32_t ip_be; memcpy(&ip_be, ip, 4);
            uint8_t body[64];
            uint16_t cmd; int ok; uint8_t reason;
            size_t before = d2k_session_plan_count(sess);
            const uint8_t shapes[4] = {D2K_PLAN_SHAPE_QUIC, D2K_PLAN_SHAPE_VOICE,
                                       D2K_PLAN_SHAPE_ANY, D2K_PLAN_SHAPE_GRANDFATHER};
            for (int i = 0; i < 4; i++) {
                memset(body, 0, sizeof body);
                body[0] = 4; memcpy(body + 1, ip, 4); body[17] = shapes[i];
                memcpy(body + 18, tiny, sizeof tiny);
                d2k_ctlsrv_command(&cx, D2K_CMD_SET_ADDR, body, 18 + sizeof tiny);
                d2k_ctl_flush(c);
                CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && cmd == D2K_CMD_SET_ADDR,
                      "SET_ADDR ack missing");
                CHECK(ok == (i < 2) && reason == (i < 2 ? D2K_ACK_OK : D2K_ACK_BAD_ARGS),
                      "SET_ADDR shape validation wrong (unshaped/grandfather must be refused)");
            }
            CHECK(d2k_session_plan_count(sess) == before + 2,
                  "QUIC and voice address bindings of one IP did not coexist");
            /* Этап 21 (аудит контракта RAW): форма RAW (8) по адресу принимается и
               снимается своей формой; неизвестная форма 9 отвергается BAD_ARGS и
               НИЧЕГО не ставит (нет ложного успеха). Другой адрес, чтобы блок
               ниже считал от прежней таблицы. */
            {
                uint8_t ip2[4] = {198, 51, 100, 24};
                size_t b0 = d2k_session_plan_count(sess);
                memset(body, 0, sizeof body);
                body[0] = 4; memcpy(body + 1, ip2, 4); body[17] = D2K_PLAN_SHAPE_RAW + 1;
                memcpy(body + 18, tiny, sizeof tiny);
                d2k_ctlsrv_command(&cx, D2K_CMD_SET_ADDR, body, 18 + sizeof tiny);
                d2k_ctl_flush(c);
                CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && cmd == D2K_CMD_SET_ADDR && !ok &&
                      reason == D2K_ACK_BAD_ARGS && d2k_session_plan_count(sess) == b0,
                      "SET_ADDR with unknown shape 9 accepted or installed something");
                body[17] = D2K_PLAN_SHAPE_RAW;
                d2k_ctlsrv_command(&cx, D2K_CMD_SET_ADDR, body, 18 + sizeof tiny);
                d2k_ctl_flush(c);
                CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && ok && d2k_session_plan_count(sess) == b0 + 1,
                      "SET_ADDR with shape RAW refused or not installed");
                memset(body, 0, 18);
                body[0] = 4; memcpy(body + 1, ip2, 4); body[17] = D2K_PLAN_SHAPE_RAW + 1;
                d2k_ctlsrv_command(&cx, D2K_CMD_DEL_ADDR, body, 18);
                d2k_ctl_flush(c);
                CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && !ok && d2k_session_plan_count(sess) == b0 + 1,
                      "DEL_ADDR with unknown shape 9 accepted");
                body[17] = D2K_PLAN_SHAPE_RAW;
                d2k_ctlsrv_command(&cx, D2K_CMD_DEL_ADDR, body, 18);
                d2k_ctl_flush(c);
                CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && ok && d2k_session_plan_count(sess) == b0,
                      "DEL_ADDR with shape RAW did not remove the RAW binding");
                /* Блок ниже переиспользует body с прежним адресом. */
                memset(body, 0, sizeof body);
                body[0] = 4; memcpy(body + 1, ip, 4);
            }
            const d2k_plan *q = d2k_plantab_find(tab, NULL, 0, ip_be, 1, D2K_PLAN_SHAPE_QUIC);
            const d2k_plan *v = d2k_plantab_find(tab, voice, sizeof voice - 1, ip_be, 1,
                                                 D2K_PLAN_SHAPE_VOICE);
            CHECK(q && v && q != v, "address bindings not separated by protocol shape");
            CHECK(!d2k_plantab_find(tab, NULL, 0, ip_be, 1, D2K_PLAN_SHAPE_MODERN),
                  "UDP address binding served to TCP hello");
            body[17] = D2K_PLAN_SHAPE_VOICE;
            d2k_ctlsrv_command(&cx, D2K_CMD_DEL_ADDR, body, 18);
            d2k_ctl_flush(c);
            CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && cmd == D2K_CMD_DEL_ADDR && ok,
                  "shaped DEL_ADDR not acknowledged");
            CHECK(d2k_plantab_find(tab, NULL, 0, ip_be, 1, D2K_PLAN_SHAPE_QUIC) == q &&
                  !d2k_plantab_find(tab, voice, sizeof voice - 1, ip_be, 1,
                                    D2K_PLAN_SHAPE_VOICE),
                  "DEL_ADDR(voice) touched the QUIC binding or kept the voice one");
            d2k_ctlsrv_command(&cx, D2K_CMD_DEL_ADDR, body, 17);
            d2k_ctl_flush(c);
            CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && !ok && reason == D2K_ACK_BAD_ARGS,
                  "DEL_ADDR without shape accepted");
            body[17] = D2K_PLAN_SHAPE_QUIC;
            d2k_ctlsrv_command(&cx, D2K_CMD_DEL_ADDR, body, 18);
            d2k_ctl_flush(c);
            CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && ok, "DEL_ADDR(QUIC) not acknowledged");
            CHECK(d2k_session_plan_count(sess) == before, "address bindings not cleaned up");
        }

        /* Главное: таблица полна — новая цель встаёт ВЫТЕСНЕНИЕМ, а не
           отказом. До вытеснения именно так на живом роутере отказывала
           КАЖДАЯ следующая цель после заполнения (см. d2k_plans.h).
         *
         * Вместимость таблицы планов выводится из d2k_track_capacity(flows)
         * (session.c), а не из d2k_session_new(2, ...) буквально: track.c
         * округляет capacity вверх до степени двойки С ПОЛОМ 16 (round_pow2
         * начинает с p=16 и удваивает, пока не догонит n) — при capacity=2
         * настоящая вместимость таблицы потоков и, значит, таблицы планов —
         * 16, а не 2. Число 16 здесь — не своя константа теста, а измеренное
         * значение этого пола; захардкодить «2» вместо него значило бы
         * повторить ту же ошибку, которую чинит эта задача, уже в тесте. */
        {
            CHECK(d2k_session_plan_count(sess) == 1,
                  "перед заполнением в таблице не одна принятая запись");
            size_t cap = d2k_session_plan_capacity(sess);
            CHECK(cap == 16,
                  "вместимость таблицы планов не выведена из числа потоков (16 с полом round_pow2)");

            /* Долить до вместимости: «ok.example» уже стоит, insert ok.example
               был первым и потому старше всех — он и обязан вытесниться. */
            for (size_t i = 1; i < cap; i++) {
                /* 64, не 32: gcc считает ширину %zu хуже некуда (до 20 цифр
                   на 64-битном size_t) и иначе ловит -Wformat-truncation,
                   даже зная, что здесь i < cap <= 16 и реально нужно байт
                   пять. См. задачу «зелёный на маке, красный на Linux». */
                char nm[64];
                snprintf(nm, sizeof nm, "filler%zu.example", i);
                uint8_t body[64], f[80];
                size_t blen = set_name_body(body, nm, tiny, sizeof tiny);
                frame(f, D2K_CMD_SET_NAME, body, blen);
                CHECK(write(cli, f, 6 + blen) == (ssize_t)(6 + blen), "цель-наполнитель не отправилась");
                CHECK(poll_frames(c, d2k_ctlsrv_command, &cx, 1) == 1, "цель-наполнитель не разобралась");
                d2k_ctl_flush(c);
                uint16_t cmd = 0; int ok = 0; uint8_t reason = 0;
                CHECK(read_ack(cli, &cmd, &ok, &reason) == 1, "ack на наполнитель не пришёл");
                CHECK(ok == 1, "наполнитель отвергнут при заполнении ровно до вместимости");
            }
            CHECK(d2k_session_plan_count(sess) == cap, "таблица не заполнилась ровно до вместимости");

            /* Таблица теперь полна. Следующая цель обязана встать
               вытеснением самой давно не использованной («ok.example» —
               она вставлена первой из всех и её ни разу не трогали
               повторно), а не получить отказ «мест нет». */
            uint8_t body[64], f[80];
            size_t blen = set_name_body(body, "overflow.example", tiny, sizeof tiny);
            frame(f, D2K_CMD_SET_NAME, body, blen);
            CHECK(write(cli, f, 6 + blen) == (ssize_t)(6 + blen), "цель после заполнения не отправилась");
            CHECK(poll_frames(c, d2k_ctlsrv_command, &cx, 1) == 1, "цель после заполнения не разобралась");
            d2k_ctl_flush(c);
            uint16_t cmd = 0; int ok = 0; uint8_t reason = 0;
            CHECK(read_ack(cli, &cmd, &ok, &reason) == 1, "ack на цель после заполнения не пришёл");
            CHECK(ok == 1, "заполненная таблица отказала вместо вытеснения");
            CHECK(reason == D2K_ACK_OK, "у вытеснения причина не D2K_ACK_OK");
            CHECK(d2k_session_plan_count(sess) == cap,
                  "вытеснение изменило число записей в таблице");
        }

        close(cli);
        d2k_session_free(sess);
    }

    /* --- давность приходит из cx.now_ns, а не подменяется константой --------
     *
     * Ревьюер поймал мутацией: замени cx->now_ns на литеральный 0 в местах,
     * где ctlsrv.c зовёт d2k_plantab_set_name/set_addr (:99, :103) — и весь
     * гейт остаётся зелёным. Причина в том, что ни один прогон до этого не
     * проводил давность через НАСТОЯЩИЙ разбор команды (d2k_ctlsrv_command)
     * с ДВУМЯ различающимися отметками: test_plans.c зовёт
     * d2k_plantab_set_addr напрямую, минуя ctlsrv.c целиком, а блок выше
     * заполняет таблицу через один и тот же cx, чьё now_ns ни разу не
     * менялся (в исходном виде — оставался нулём с memset) — обе стороны
     * подмены выглядят одинаково, когда времени всего одно значение.
     *
     * Расстановка ниже — НЕ по возрастанию вставки: "fresh.example" стоит
     * ПЕРВОЙ (то есть на наименьшем индексе — том самом, что побеждает при
     * разрыве ничьей по plans.c/oldest), но получает САМУЮ БОЛЬШУЮ отметку;
     * "filler1.example" вставлена ВТОРОЙ и получает САМУЮ МАЛЕНЬКУЮ. Если
     * давность не доходит до таблицы (то есть после подмены на 0), все
     * отметки равны, и вытесняется "fresh.example" — она с наименьшим
     * индексом; если доходит — "filler1.example", она старше по факту.
     * Настоящая давность и разрыв ничьей по индексу указывают на РАЗНЫЕ
     * записи — ровно то расхождение, которого не было в проверке выше. */
    {
        d2k_session *sess = d2k_session_new(2, 0);
        CHECK(sess != NULL, "сессия для проверки давности не создалась");

        d2k_ctlsrv cx;
        memset(&cx, 0, sizeof cx);
        cx.sess = sess;
        cx.ctl = c;
        cx.send_limits = 0;

        /* Старый собеседник блока выше закрыт, но сервер узнаёт об этом
           только через d2k_ctl_poll/d2k_ctl_flush — тот же приём, что и
           перед первым переподключением этого файла (см. комментарий там). */
        d2k_ctl_poll(c, on_cmd, NULL);
        cli = dial();
        CHECK(cli >= 0, "клиент для проверки давности не подключился");
        d2k_ctl_accept(c);

        size_t cap = d2k_session_plan_capacity(sess);
        CHECK(cap == 16, "вместимость таблицы давности не 16 (см. round_pow2 выше)");

        /* Первая цель — с индексом 0, но с давностью заведомо больше всех
           остальных: если бы разрыв ничьей по индексу решал дело (давность
           не дошла), вытеснилась бы именно она. */
        cx.now_ns = 1000000;
        {
            uint8_t body[64], f[80];
            size_t blen = set_name_body(body, "fresh.example", tiny, sizeof tiny);
            frame(f, D2K_CMD_SET_NAME, body, blen);
            CHECK(write(cli, f, 6 + blen) == (ssize_t)(6 + blen), "первая цель давности не отправилась");
            CHECK(poll_frames(c, d2k_ctlsrv_command, &cx, 1) == 1, "первая цель давности не разобралась");
            d2k_ctl_flush(c);
            uint16_t cmd = 0; int ok = 0; uint8_t reason = 0;
            CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && ok == 1,
                  "первая цель давности отвергнута");
        }

        /* Остальные до вместимости: filler1 получает давность 1 — самую
           маленькую из ВСЕХ, включая fresh.example; filler2..filler15 —
           давность 2..15, тоже меньше fresh.example, но больше filler1. */
        for (size_t i = 1; i < cap; i++) {
            char nm[64];
            snprintf(nm, sizeof nm, "filler%zu.example", i);
            cx.now_ns = (uint64_t)i;
            uint8_t body[64], f[80];
            size_t blen = set_name_body(body, nm, tiny, sizeof tiny);
            frame(f, D2K_CMD_SET_NAME, body, blen);
            CHECK(write(cli, f, 6 + blen) == (ssize_t)(6 + blen), "наполнитель давности не отправился");
            CHECK(poll_frames(c, d2k_ctlsrv_command, &cx, 1) == 1, "наполнитель давности не разобрался");
            d2k_ctl_flush(c);
            uint16_t cmd = 0; int ok = 0; uint8_t reason = 0;
            CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && ok == 1,
                  "наполнитель давности отвергнут");
        }
        CHECK(d2k_session_plan_count(sess) == cap,
              "таблица давности не заполнилась ровно до вместимости");

        /* Таблица полна. Новая цель обязана вытеснить "filler1.example" —
           самую старую ПО ФАКТУ, а не "fresh.example", которая старше
           только по индексу. */
        cx.now_ns = 2000000;
        {
            uint8_t body[64], f[80];
            size_t blen = set_name_body(body, "overflow2.example", tiny, sizeof tiny);
            frame(f, D2K_CMD_SET_NAME, body, blen);
            CHECK(write(cli, f, 6 + blen) == (ssize_t)(6 + blen), "цель поверх давности не отправилась");
            CHECK(poll_frames(c, d2k_ctlsrv_command, &cx, 1) == 1, "цель поверх давности не разобралась");
            d2k_ctl_flush(c);
            uint16_t cmd = 0; int ok = 0; uint8_t reason = 0;
            CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 && ok == 1,
                  "цель поверх давности отвергнута");
        }

        /* Проверяем ПОВЕДЕНИЕМ (что реально находится в таблице), как и
           тест выше и test_plans.c — внутреннее поле давности наружу не
           выставлено и не должно быть. */
        d2k_plantab *tab = d2k_session_plans(sess);
        CHECK(d2k_plantab_find(tab, (const uint8_t *)"fresh.example",
                               strlen("fresh.example"), 0, 9999999, D2K_PLAN_SHAPE_ANY) != NULL,
              "давность не дошла до таблицы: вытеснена свежая запись вместо старой "
              "(похоже на cx->now_ns, подменённый константой в ctlsrv.c)");
        CHECK(d2k_plantab_find(tab, (const uint8_t *)"filler1.example",
                               strlen("filler1.example"), 0, 9999999, D2K_PLAN_SHAPE_ANY) == NULL,
              "самая старая по факту запись пережила вытеснение вместо свежей");

        close(cli);
        d2k_session_free(sess);
    }

    /* --- событие применения несёт ИДЕНТИФИКАТОР плана ------------------------
     *
     * d2k_ctl.h объявляет D2K_EV_APPLIED как «ключ + id плана» с самого начала,
     * а на проводе ехал один ключ: «план применился» было неотличимо от
     * «применился КАКОЙ-ТО план», и при смене кандидата событие предыдущего
     * засчиталось бы новому.
     *
     * Проверяется БАЙТАМИ на проводе, а не разбором core/link.c: разбор —
     * вторая сторона того же контракта, и сверять их друг об друга значит не
     * проверять ни одну.
     *
     * Путь настоящий целиком: план приезжает командой, приветствие проходит
     * через d2k_session_packet, событие выкладывает d2k_ctlsrv_pump. Подделка
     * журнала здесь ничего бы не доказала — именно на этой дороге
     * идентификатор и терялся. */
    {
        d2k_session *sess = d2k_session_new(2, 16);
        CHECK(sess != NULL, "сессия для проверки идентификатора не создалась");

        d2k_ctlsrv cx;
        memset(&cx, 0, sizeof cx);
        cx.sess = sess;
        cx.ctl = c;
        cx.send_limits = 0;

        /* Прошлый блок закрыл своего cli, но сервер узнаёт об уходе
           собеседника только через poll/flush (см. drop_peer в ctl.c) — иначе
           accept() ниже отверг бы новое подключение как «второго
           контроллера». Тот же порядок, что и в блоках выше. */
        d2k_ctl_poll(c, on_cmd, NULL);
        cli = dial();
        CHECK(cli >= 0, "клиент для проверки идентификатора не подключился");
        d2k_ctl_accept(c);
        CHECK(d2k_ctl_peer_fd(c) >= 0, "подключение для проверки идентификатора не принято");

        /* Потолок ожидания на приёме: непришедшее событие обязано быть
           ПРОВАЛОМ, а не вечным чтением. Две секунды — с запасом на любую
           машину: всё, что читается, уже лежит в сокете к моменту чтения
           (pump и flush отработали строкой выше). */
        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        (void)setsockopt(cli, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

        {
            uint8_t body[128], f[160];
            size_t blen = set_name_body(body, "id.example", plan_with_id, sizeof plan_with_id);
            frame(f, D2K_CMD_SET_NAME, body, blen);
            CHECK(write(cli, f, 6 + blen) == (ssize_t)(6 + blen),
                  "команда с планом-носителем идентификатора не отправилась");
            CHECK(poll_frames(c, d2k_ctlsrv_command, &cx, 1) == 1,
                  "команда с планом-носителем идентификатора не разобралась");
            d2k_ctl_flush(c);
            uint16_t cmd = 0; int ok = 0; uint8_t reason = 0;
            CHECK(read_ack(cli, &cmd, &ok, &reason) == 1, "ack на план с идентификатором не пришёл");
            CHECK(ok == 1, "план с записью REC_ID отвергнут");
        }

        uint8_t hello[512], pkt[1024], obuf[2048];
        size_t hl = build_hello(hello, "id.example");
        size_t pl = build_pkt(pkt, 40100, hello, hl);
        d2k_result r;
        d2k_session_packet(sess, pkt, pl, 1000, obuf, sizeof obuf, &r);
        CHECK(d2k_session_applied(sess) == 1,
              "план не применился — проверять в событии нечего");
        uint64_t seen = 0;
        d2k_ctlsrv_pump(c, sess, &seen);
        d2k_ctl_flush(c);
        for (int i = 0; i < 4; i++) {
            uint16_t type = 0;
            uint8_t ev[256];
            if (read_event(cli, &type, ev, sizeof ev) < 0) { break; }
            CHECK(type != D2K_EV_APPLIED, "подготовка выдана за завершение отправки");
        }
        /* Explicitly complete the simulated sends and original verdict. */
        for (size_t i = 0; i <= r.n_out; i++) {
            d2k_session_sent(sess, 1001 + i, &r.key, r.execution_id);
        }

        /* Replace before journal serialization: the event belongs to r. */
        d2k_plan *replacement = NULL;
        char replace_err[128];
        CHECK(!d2k_plan_load(plan_with_id, sizeof plan_with_id, &replacement,
                            replace_err, sizeof replace_err), "replacement fixture");
        CHECK(!d2k_plantab_set_name(d2k_session_plans(sess),
            (const uint8_t *)"id.example", 10, 1010, replacement), "reinstall before pump");

        d2k_ctlsrv_pump(c, sess, &seen);
        d2k_ctl_flush(c);

        /* Pump выкладывает всё, что появилось в журнале: сперва приветствие,
           затем применение. Чужие виды пропускаем — их порядок не предмет
           этой проверки. */
        int found = 0;
        for (int i = 0; i < 4 && !found; i++) {
            uint16_t type = 0;
            uint8_t ev[256];
            ssize_t n = read_event(cli, &type, ev, sizeof ev);
            if (n < 0) {
                break;
            }
            if (type != D2K_EV_APPLIED) {
                continue;
            }
            found = 1;
            CHECK(n == (ssize_t)(D2K_KEY_WIRE_LEN + D2K_PLAN_ID_LEN + D2K_TRIAL_ID_LEN + D2K_CTL_EXECUTION_LEN),
                  "тело APPLIED не содержит Plan ID и trial ID фиксированной ширины");
            if (n == (ssize_t)(D2K_KEY_WIRE_LEN + D2K_PLAN_ID_LEN + D2K_TRIAL_ID_LEN + D2K_CTL_EXECUTION_LEN)) {
                check_execution(ev + D2K_KEY_WIRE_LEN + D2K_PLAN_ID_LEN + D2K_TRIAL_ID_LEN, &r);
                CHECK(memcmp(ev + D2K_KEY_WIRE_LEN, want_id, sizeof want_id) == 0,
                      "идентификатор на проводе не тот, что приехал записью REC_ID");
                CHECK(memcmp(ev + D2K_KEY_WIRE_LEN + D2K_PLAN_ID_LEN,
                             (uint8_t[D2K_TRIAL_ID_LEN]){0}, D2K_TRIAL_ID_LEN) == 0,
                      "обычный план неожиданно получил trial ID");
            }
        }
        CHECK(found, "события применения не пришло вовсе");

        /* Request-bound EXCHANGE must serialize the saved execution, even
           though the table entry was already replaced above. */
        {
            uint8_t trial[D2K_TRIAL_ID_LEN]; memset(trial,0x63,sizeof trial);
            d2k_journal_add_fate_bound((d2k_journal *)d2k_session_journal(sess),
                1011,&r.key,D2K_JRN_EXCHANGE,D2K_UDP_PROOF_STUN,
                r.plan_id,trial,r.execution_id,&r.binding);
            d2k_ctlsrv_pump(c,sess,&seen);d2k_ctl_flush(c);
            int got=0;
            for(int i=0;i<8 && !got;i++) {
                uint16_t kind;uint8_t ev[256];ssize_t n=read_event(cli,&kind,ev,sizeof ev);
                if(n<0)break;
                if(kind!=D2K_EV_EXCHANGE)continue;
                got=1;size_t off=D2K_KEY_WIRE_LEN+8;
                CHECK(n==(ssize_t)(off+32+D2K_CTL_EXECUTION_LEN),"bound EXCHANGE wire length");
                CHECK(!memcmp(ev+off,r.plan_id,16) && !memcmp(ev+off+16,trial,16),
                      "bound EXCHANGE plan/trial IDs");
                uint64_t execution=0;for(unsigned b=0;b<8;b++)execution=(execution<<8)|ev[off+32+b];
                d2k_binding_context saved={0};
                CHECK(execution==r.execution_id &&
                      !d2k_ctl_binding_read(&saved,ev+off+40,D2K_CTL_BINDING_LEN) &&
                      d2k_binding_equal(&saved,&r.binding),"EXCHANGE changed request snapshot during serialization");
            }
            CHECK(got,"bound EXCHANGE not emitted");
        }

        /* Request-bound SUSPECT must serialize the saved execution, even
           though the table entry was already replaced above. */
        {
            uint8_t trial[D2K_TRIAL_ID_LEN]; memset(trial,0x63,sizeof trial);
            d2k_flow observed={0};
            observed.execution_id=r.execution_id;observed.execution_binding=r.binding;
            memcpy(observed.execution_plan_id,r.plan_id,16);
            memcpy(observed.execution_trial_id,trial,16);
            d2k_jrn_detail detail={0};detail.planned=D2K_PLANNED_YES;
            detail.client_shape=D2K_PLAN_SHAPE_VOICE;
            d2k_journal_add_suspect_bound((d2k_journal *)d2k_session_journal(sess),
                1012,&r.key,D2K_SUSPECT_SILENT,37,&detail,&observed);
            memset(&observed,0,sizeof observed);
            d2k_ctlsrv_pump(c,sess,&seen);d2k_ctl_flush(c);
            int got=0;
            for(int i=0;i<8 && !got;i++) {
                uint16_t kind;uint8_t ev[256];ssize_t n=read_event(cli,&kind,ev,sizeof ev);
                if(n<0)break;
                if(kind!=D2K_EV_SUSPECT)continue;
                got=1;
                CHECK(ev[D2K_KEY_WIRE_LEN]==D2K_SUSPECT_SILENT &&
                      ev[D2K_KEY_WIRE_LEN+6]==D2K_PLANNED_YES &&
                      ev[D2K_KEY_WIRE_LEN+9]==37,"SUSPECT lost detail or count");
                size_t off=D2K_KEY_WIRE_LEN+11;
                CHECK(n==(ssize_t)(off+32+D2K_CTL_EXECUTION_LEN),"bound SUSPECT wire length");
                CHECK(!memcmp(ev+off,r.plan_id,16) && !memcmp(ev+off+16,trial,16),
                      "bound SUSPECT plan/trial IDs");
                uint64_t execution=0;for(unsigned b=0;b<8;b++)execution=(execution<<8)|ev[off+32+b];
                d2k_binding_context saved={0};
                CHECK(execution==r.execution_id &&
                      !d2k_ctl_binding_read(&saved,ev+off+40,D2K_CTL_BINDING_LEN) &&
                      d2k_binding_equal(&saved,&r.binding),"SUSPECT changed request snapshot during serialization");
            }
            CHECK(got,"bound SUSPECT not emitted");
        }

        /* --- НАБОР ОПЦИЙ TCP КЛИЕНТА ЕДЕТ ПЕРЕД СНИМКОМ (замысел 2026-10-23,
           п. 5.1). Снимок приветствия по запросу (ARM_SHAPE) контроллер уже
           получает; набор опций TCP того же пакета едет своим событием
           D2K_EV_CLIENT_TCP, ровно перед D2K_EV_SHAPE, с тем же ключом потока:
           так зонд здоровается набором клиента, а не литералом. Проверяется
           байтами на проводе, как и всё здесь. */
        {
            const uint8_t nm[] = "opts.example";
            CHECK(d2k_session_want_shape(sess, nm, sizeof nm - 1, 6) == 0,
                  "ловушка снимка не взвелась");
            uint8_t h2[512], p2[1024];
            size_t hl2 = build_hello(h2, "opts.example");
            size_t pl2 = build_pkt(p2, 40101, h2, hl2);
            /* Опции TCP: NOP NOP TS(10) — как у клиента с меткой времени. */
            static const uint8_t ts[12] = {1, 1, 8, 10, 0, 0, 0x23, 0x28, 0, 0, 0, 0};
            memmove(p2 + 40 + 12, p2 + 40, hl2);
            memcpy(p2 + 40, ts, 12);
            p2[32] = (uint8_t)(((20 + 12) / 4) << 4);
            pl2 += 12;
            wr16(p2 + 2, (uint16_t)pl2);
            d2k_result r2;
            d2k_session_packet(sess, p2, pl2, 2000, obuf, sizeof obuf, &r2);
            size_t sl = 0;
            CHECK(d2k_session_shape(sess, 6, &sl) != NULL, "снимок для проверки опций не снят");
            d2k_ctlsrv_pump(c, sess, &seen);
            d2k_ctl_flush(c);
            int got_opts = 0, got_shape = 0, shape_after_opts = 0;
            for (int i = 0; i < 8; i++) {
                uint16_t type = 0;
                uint8_t ev[D2K_KEY_WIRE_LEN + 4200];
                ssize_t n = read_event(cli, &type, ev, sizeof ev);
                if (n < 0) { break; }
                if (type == D2K_EV_CLIENT_TCP) {
                    got_opts = 1;
                    CHECK(n == (ssize_t)(D2K_KEY_WIRE_LEN + 12) && ev[D2K_KEY_WIRE_LEN + 2] == 8,
                          "тело CLIENT_TCP не несёт опции пакета-приветствия");
                    CHECK(ev[D2K_KEY_WIRE_LEN - 1] == 6 && ev[0] == 4,
                          "ключ CLIENT_TCP без транспорта/семейства");
                } else if (type == D2K_EV_SHAPE) {
                    got_shape = 1;
                    shape_after_opts = got_opts;
                    break;
                }
            }
            CHECK(got_opts, "события с набором опций TCP клиента не пришло");
            CHECK(got_shape && shape_after_opts, "снимок пришёл без набора опций перед ним");
        }

        close(cli);
        d2k_session_free(sess);
    }

    /* --- REFUSED несёт КОД ПРИЧИНЫ, а не только ключ -----------------------
     *
     * Разрыв «ложная отчётность об исполнении» (docs/decisions/0006): пока
     * событие отказа несло один ключ, контроллер не мог отличить «коробка не
     * поддалась» от «наша отправка не состоялась». Первое — свойство коробки,
     * второе — наша поломка, и записывать второе как первое запрещено.
     *
     * Проверяется БАЙТАМИ на проводе, как и идентификатор выше: разбор в
     * core/link.c — вторая сторона того же контракта.
     *
     * Обе стороны кода в одном блоке: обычный отказ ПРИМЕНИТЬ план («плана
     * для этой цели нет») обязан ехать с нулём — он случается на каждом
     * транзитном потоке и ничего не говорит о нашем зонде; отказ ОТПРАВКИ —
     * со своим кодом. */
    {
        d2k_session *sess = d2k_session_new(2, 16);
        CHECK(sess != NULL, "сессия для проверки кода отказа не создалась");

        d2k_ctlsrv cx;
        memset(&cx, 0, sizeof cx);
        cx.sess = sess;
        cx.ctl = c;
        cx.send_limits = 0;

        d2k_ctl_poll(c, on_cmd, NULL);
        cli = dial();
        CHECK(cli >= 0, "клиент для проверки кода отказа не подключился");
        d2k_ctl_accept(c);
        CHECK(d2k_ctl_peer_fd(c) >= 0, "подключение для проверки кода отказа не принято");

        struct timeval tv2;
        tv2.tv_sec = 2;
        tv2.tv_usec = 0;
        (void)setsockopt(cli, SOL_SOCKET, SO_RCVTIMEO, &tv2, sizeof tv2);

        {
            uint8_t body[128], f[160];
            size_t blen = set_name_body(body, "unsent.example", plan_with_id, sizeof plan_with_id);
            frame(f, D2K_CMD_SET_NAME, body, blen);
            CHECK(write(cli, f, 6 + blen) == (ssize_t)(6 + blen),
                  "команда с планом для проверки отказа не отправилась");
            CHECK(poll_frames(c, d2k_ctlsrv_command, &cx, 1) == 1,
                  "команда с планом для проверки отказа не разобралась");
            d2k_ctl_flush(c);
            uint16_t cmd = 0; int ok = 0; uint8_t reason = 0;
            CHECK(read_ack(cli, &cmd, &ok, &reason) == 1, "ack перед проверкой отказа не пришёл");
            CHECK(ok == 1, "план для проверки отказа отвергнут");
        }

        uint8_t hello[512], pkt[1024], obuf[2048];
        size_t hl = build_hello(hello, "unsent.example");
        size_t pl = build_pkt(pkt, 40200, hello, hl);
        d2k_result r;
        d2k_session_packet(sess, pkt, pl, 1000, obuf, sizeof obuf, &r);
        CHECK(r.applied == 1, "план не применился — недоисполнять нечего");

        /* Чужой поток без плана: обычный отказ ПРИМЕНИТЬ. */
        uint8_t other[512], opkt[1024];
        size_t ohl = build_hello(other, "noplan.example");
        size_t opl = build_pkt(opkt, 40201, other, ohl);
        d2k_result r2;
        d2k_session_packet(sess, opkt, opl, 1100, obuf, sizeof obuf, &r2);

        /* И отказ ОТПРАВКИ по нашему потоку. */
        d2k_session_unsent(sess, 1200, &r.key, r.plan_id, D2K_REFUSE_TOO_LONG, r.execution_id);

        /* ПОВРЕЖДЕНИЕ ПОТОКА — третий, отдельный факт. Раньше он доходил до
           контроллера неотличимо от «плана для цели нет» (код 0), потому что
           ехал обычным отказом ПРИМЕНИТЬ. Здесь проверяется вся цепочка
           целиком: session → journal → ctlsrv → провод. */
        uint8_t dmg_pkt[1024];
        /* ТО ЖЕ ИМЯ, другой клиентский порт: план стоит по имени, значит
           второе обращение к той же цели — второй поток с тем же планом. */
        size_t dpl = build_pkt(dmg_pkt, 40202, hello, hl);
        d2k_result rd;
        d2k_session_packet(sess, dmg_pkt, dpl, 1300, obuf, sizeof obuf, &rd);
        CHECK(rd.applied == 1, "второй поток той же цели не получил план");
        /* Нагрузка уже на проводе — чистого выхода нет. */
        CHECK(d2k_session_exec_failed(sess, 1400, &rd.key, rd.plan_id,
                                      D2K_REFUSE_SEND, rd.execution_id, 1, 0) == 0,
              "ушедшая нагрузка не объявила поток испорченным");

        uint64_t seen2 = 0;
        d2k_ctlsrv_pump(c, sess, &seen2);
        d2k_ctl_flush(c);

        int seen_plain = 0, seen_unsent = 0, seen_damaged = 0;
        for (int i = 0; i < 20; i++) {
            uint16_t type = 0;
            uint8_t ev[256];
            ssize_t n = read_event(cli, &type, ev, sizeof ev);
            if (n < 0) {
                break;
            }
            if (type != D2K_EV_REFUSED) {
                continue;
            }
            CHECK(n == (ssize_t)(D2K_KEY_WIRE_LEN + 2 + D2K_PLAN_ID_LEN + D2K_TRIAL_ID_LEN + D2K_CTL_EXECUTION_LEN),
                  "тело REFUSED не содержит код, Plan ID и trial ID");
            if (n < (ssize_t)(D2K_KEY_WIRE_LEN + 1)) {
                continue;
            }
            if (ev[D2K_KEY_WIRE_LEN] == D2K_REFUSE_NONE) {
                seen_plain = 1;
            } else if (ev[D2K_KEY_WIRE_LEN] == D2K_REFUSE_TOO_LONG) {
                seen_unsent = 1;
            } else if (ev[D2K_KEY_WIRE_LEN] == D2K_REFUSE_DAMAGED) {
                seen_damaged = 1;
                /* Идентичность обязана доехать: без неё повреждение нельзя
                   приписать ни попытке, ни плану. */
                CHECK(n == (ssize_t)(D2K_KEY_WIRE_LEN + 2 + D2K_PLAN_ID_LEN + D2K_TRIAL_ID_LEN + D2K_CTL_EXECUTION_LEN),
                      "повреждение приехало без Plan ID/trial ID");
                int nonzero = 0;
                for (int b = 0; b < 16; b++) {
                    if (ev[D2K_KEY_WIRE_LEN + 1 + b]) { nonzero = 1; }
                }
                CHECK(nonzero, "идентификатор плана у повреждения нулевой");
            }
            if (n == (ssize_t)(D2K_KEY_WIRE_LEN + 2 + D2K_PLAN_ID_LEN + D2K_TRIAL_ID_LEN + D2K_CTL_EXECUTION_LEN)) {
                const d2k_result empty = {0};
                const d2k_result *want = ev[D2K_KEY_WIRE_LEN] == D2K_REFUSE_NONE ? &empty :
                    ev[D2K_KEY_WIRE_LEN] == D2K_REFUSE_TOO_LONG ? &r : &rd;
                check_execution(ev + D2K_KEY_WIRE_LEN + 2 + D2K_PLAN_ID_LEN + D2K_TRIAL_ID_LEN, want);
            }
        }
        CHECK(seen_plain, "обычный отказ применить план приехал не с нулевым кодом");
        CHECK(seen_unsent, "отказ отправки не приехал кодом D2K_REFUSE_TOO_LONG");
        CHECK(seen_damaged,
              "повреждение потока не доехало до контроллера отдельным кодом — "
              "оно неотличимо от обычного «плана для цели нет»");

        close(cli);
        d2k_session_free(sess);
    }

    /* --- план отвергается по САМОЙ ДЛИННОЙ своей посылке --------------------
     *
     * На живой пробе 12.09.2026 отказ приходил от ядра — «sendto: Message too
     * large», — когда команда была уже подтверждена, план уже стоял, а событие
     * «план применён» уже ушло контроллеру. Отказ обязан случаться ДО всего
     * этого, в d2k_plan_fits, по величине, которую план объявляет сам.
     *
     * Числа в этом блоке — не подобранные: 1500 это Ethernet MTU (RFC 894),
     * а 1530 — вес приманки профиля MODERN, того самого, из-за которого отказ
     * и случился (замер записан в core/compose.c у D2K_COMPOSE_HELLO_MAX).
     * Посылка с такой приманкой весит 20 (IPv4) + 20 (TCP) + 1530 = 1570. */
    {
        static uint8_t longplan[2048];
        static uint8_t shortplan[2048];
        size_t lp = 0, sp = 0;

        /* Заголовок: D2KP, схема 1, исполнитель 1, флаги 0, записей 2. */
        for (size_t pass = 0; pass < 2; pass++) {
            uint8_t *b = pass ? shortplan : longplan;
            size_t plen = pass ? 8 : 1530;   /* 8 — заведомо влезает куда угодно */
            size_t o = 0;
            memcpy(b, "D2KP", 4); o = 4;
            b[o++] = 0; b[o++] = 1;
            b[o++] = 0; b[o++] = 1;
            b[o++] = 0; b[o++] = 0;
            b[o++] = 0; b[o++] = 2;
            /* REC_PAYLOAD: id=1, затем сами байты. */
            b[o++] = 0x00; b[o++] = 0x10;
            b[o++] = (uint8_t)((2 + plen) >> 8); b[o++] = (uint8_t)(2 + plen);
            b[o++] = 0x00; b[o++] = 0x01;
            memset(b + o, 0xAA, plen); o += plen;
            /* REC_FAKE: payload=1, poison=0, repeats=1, place=before, gap=0. */
            b[o++] = 0x01; b[o++] = 0x01;
            b[o++] = 0x00; b[o++] = 0x0A;
            b[o++] = 0x00; b[o++] = 0x01;
            b[o++] = 0x00; b[o++] = 0x00;
            b[o++] = 0x01; b[o++] = 0x00;
            b[o++] = 0; b[o++] = 0; b[o++] = 0; b[o++] = 0;
            if (pass) { sp = o; } else { lp = o; }
        }

        d2k_plan *big = NULL, *small = NULL;
        char why[200];
        CHECK(d2k_plan_load(longplan, lp, &big, why, sizeof why) == 0,
              "план с длинной приманкой не загрузился");
        CHECK(d2k_plan_load(shortplan, sp, &small, why, sizeof why) == 0,
              "план с короткой приманкой не загрузился");

        if (big && small) {
            /* Предел не объявлен (0) — не проверяем: стенд без сырого сокета
               отправлять не будет вовсе, и резать там нечего. */
            CHECK(d2k_plan_fits(big, D2K_RAW_CANT_IPID, 0, why, sizeof why) == 1,
                  "без объявленного предела длины план зачем-то отвергнут");
            CHECK(d2k_plan_fits(big, D2K_RAW_CANT_IPID, 1500, why, sizeof why) == 0,
                  "план с посылкой 1570 байт принят при пределе 1500");
            CHECK(d2k_plan_fits(small, D2K_RAW_CANT_IPID, 1500, why, sizeof why) == 1,
                  "план, который заведомо влезает, отвергнут по длине");
            /* Ровно на границе: 20+20+1460 = 1500 — это ВЛЕЗАЕТ. Проверка на
               «строго больше», а не «больше либо равно»: перепутав их, мы
               резали бы полный кадр, который прошёл бы. */
            CHECK(d2k_plan_fits(big, D2K_RAW_CANT_IPID, 1570, why, sizeof why) == 1,
                  "посылка ровно в предел объявлена невлезающей");
        }
        d2k_plan_free(big);
        d2k_plan_free(small);
    }

    /* Тот же отказ, но через НАСТОЯЩУЮ команду: контроллер обязан получить
       D2K_ACK_BAD_PLAN до того, как план встанет. */
    {
        d2k_session *sess = d2k_session_new(2, 16);
        CHECK(sess != NULL, "сессия для проверки предела длины не создалась");

        d2k_ctlsrv cx;
        memset(&cx, 0, sizeof cx);
        cx.sess = sess;
        cx.ctl = c;
        cx.send_limits = D2K_RAW_CANT_IPID | D2K_RAW_CANT_IPSUM;
        cx.send_maxlen = 1500;   /* Ethernet MTU, RFC 894 */

        d2k_ctl_poll(c, on_cmd, NULL);
        cli = dial();
        CHECK(cli >= 0, "клиент для проверки предела длины не подключился");
        d2k_ctl_accept(c);

        struct timeval tv3;
        tv3.tv_sec = 2;
        tv3.tv_usec = 0;
        (void)setsockopt(cli, SOL_SOCKET, SO_RCVTIMEO, &tv3, sizeof tv3);

        static uint8_t longplan[2048];
        size_t o = 0, plen = 1530;
        memcpy(longplan, "D2KP", 4); o = 4;
        longplan[o++] = 0; longplan[o++] = 1;
        longplan[o++] = 0; longplan[o++] = 1;
        longplan[o++] = 0; longplan[o++] = 0;
        longplan[o++] = 0; longplan[o++] = 2;
        longplan[o++] = 0x00; longplan[o++] = 0x10;
        longplan[o++] = (uint8_t)((2 + plen) >> 8); longplan[o++] = (uint8_t)(2 + plen);
        longplan[o++] = 0x00; longplan[o++] = 0x01;
        memset(longplan + o, 0xAA, plen); o += plen;
        longplan[o++] = 0x01; longplan[o++] = 0x01;
        longplan[o++] = 0x00; longplan[o++] = 0x0A;
        longplan[o++] = 0x00; longplan[o++] = 0x01;
        longplan[o++] = 0x00; longplan[o++] = 0x00;
        longplan[o++] = 0x01; longplan[o++] = 0x00;
        longplan[o++] = 0; longplan[o++] = 0; longplan[o++] = 0; longplan[o++] = 0;

        static uint8_t body[4096], f[4200];
        size_t blen = set_name_body(body, "toolong.example", longplan, o);
        frame(f, D2K_CMD_SET_NAME, body, blen);
        CHECK(write(cli, f, 6 + blen) == (ssize_t)(6 + blen),
              "команда с длинной посылкой не отправилась");
        CHECK(poll_frames(c, d2k_ctlsrv_command, &cx, 1) == 1,
              "команда с длинной посылкой не разобралась");
        d2k_ctl_flush(c);
        uint16_t cmd = 0; int ok = 1; uint8_t reason = 0;
        CHECK(read_ack(cli, &cmd, &ok, &reason) == 1, "ack на длинную посылку не пришёл");
        CHECK(ok == 0, "план, чья посылка не унесётся, подтверждён как принятый");
        CHECK(reason == D2K_ACK_BAD_PLAN, "отказ по длине назван не негодностью плана");
        CHECK(d2k_session_plan_count(sess) == 0,
              "отвергнутый по длине план всё-таки встал в таблицу");

        /* Тот же негодный план ПРОБНОЙ командой: отказ обязан нести trial ID
           опыта, иначе контроллер не отличит свой отказ от чужого и не
           сможет отделить местный отказ исполнителя от промаха кандидата
           (задача 19). */
        {
            size_t nl = strlen("toolong.example"), po = 0;
            body[po++] = (uint8_t)nl;
            memcpy(body + po, "toolong.example", nl); po += nl;
            body[po++] = D2K_PLAN_SHAPE_MODERN;
            body[po++] = 4;
            body[po++] = 0x9c; body[po++] = 0x41;
            memcpy(body + po, longplan, o); po += o;
            for (size_t i = 0; i < D2K_TRIAL_ID_LEN; i++) body[po++] = (uint8_t)(0xc0 + i);
            frame(f, D2K_CMD_SET_NAME_PROBE, body, po);
            CHECK(write(cli, f, 6 + po) == (ssize_t)(6 + po),
                  "пробная команда с длинной посылкой не отправилась");
            CHECK(poll_frames(c, d2k_ctlsrv_command, &cx, 1) == 1,
                  "пробная команда с длинной посылкой не разобралась");
            d2k_ctl_flush(c);
            ok = 1; cmd = 0; reason = 0;
            CHECK(read_ack(cli, &cmd, &ok, &reason) == 1 &&
                  cmd == D2K_CMD_SET_NAME_PROBE && ok == 0 &&
                  reason == D2K_ACK_BAD_PLAN,
                  "негодный пробный план не получил BAD_PLAN");
            CHECK(last_ack_id[0] == 0xc0 && last_ack_id[15] == 0xcf,
                  "отказ SET_NAME_PROBE не несёт trial ID опыта");
            CHECK(d2k_session_plan_count(sess) == 0,
                  "отвергнутый пробный план встал в таблицу");
        }

        close(cli);
        d2k_session_free(sess);
    }

    /* ГРАНИЦА ДЛИНЫ: предел−1, предел, предел+1 (приёмка U3).
     *
     * Сравнение в ctlsrv.c строгое: посылка РОВНО в предел проходит. Перепутай
     * его с «больше либо равно» — и отвергался бы полный кадр, который уедет;
     * перепутай в другую сторону — и план встал бы, чтобы упереться в ядро уже
     * на отправке, где чистого выхода нет. Обе ошибки различает только опыт на
     * самой границе, а не «сильно больше», который был здесь до сих пор.
     *
     * Само число берётся у d2k_plan_max_emit, а не считается в тесте заново:
     * вторая реализация правила разошлась бы с первой молча, и тест проверял
     * бы себя (§2.5). */
    {
        static uint8_t bp[512];
        size_t bo = 0, bpl = 200;
        memcpy(bp, "D2KP", 4); bo = 4;
        bp[bo++] = 0; bp[bo++] = 1;            /* версия */
        bp[bo++] = 0; bp[bo++] = 1;            /* записей */
        bp[bo++] = 0; bp[bo++] = 0;            /* REC_PAYLOAD... */
        bp[bo++] = 0; bp[bo++] = 2;
        bp[bo++] = 0x00; bp[bo++] = 0x10;
        bp[bo++] = (uint8_t)((2 + bpl) >> 8); bp[bo++] = (uint8_t)(2 + bpl);
        bp[bo++] = 0x00; bp[bo++] = 0x01;      /* id приманки */
        memset(bp + bo, 0xAA, bpl); bo += bpl;
        bp[bo++] = 0x01; bp[bo++] = 0x01;      /* REC_FAKE */
        bp[bo++] = 0x00; bp[bo++] = 0x0A;
        bp[bo++] = 0x00; bp[bo++] = 0x01;      /* payload id */
        bp[bo++] = 0x00; bp[bo++] = 0x00;      /* poison id */
        bp[bo++] = 0x01; bp[bo++] = 0x00;      /* repeats, placement */
        bp[bo++] = 0; bp[bo++] = 0; bp[bo++] = 0; bp[bo++] = 0;  /* gap_us */

        d2k_plan *probe = NULL;
        char perr[160];
        CHECK(d2k_plan_load(bp, bo, &probe, perr, sizeof perr) == 0,
              "пробный план для границы длины не разобрался");
        size_t need = probe ? d2k_plan_max_emit(probe) : 0;
        d2k_plan_free(probe);
        CHECK(need > 0, "самая длинная посылка плана нулевая — граница не определена");

        struct { size_t limit; int accept; const char *what; } cases[] = {
            { need - 1, 0, "предел−1" },
            { need,     1, "предел"   },
            { need + 1, 1, "предел+1" },
        };
        for (size_t ci = 0; ci < sizeof cases / sizeof cases[0]; ci++) {
            d2k_session *sess = d2k_session_new(2, 16);
            CHECK(sess != NULL, "сессия для границы длины не создалась");
            d2k_ctlsrv cb;
            memset(&cb, 0, sizeof cb);
            cb.sess = sess;
            cb.ctl = c;
            cb.send_limits = D2K_RAW_CANT_IPID | D2K_RAW_CANT_IPSUM;
            cb.send_maxlen = (uint32_t)cases[ci].limit;

            d2k_ctl_poll(c, on_cmd, NULL);
            cli = dial();
            CHECK(cli >= 0, "клиент для границы длины не подключился");
            d2k_ctl_accept(c);
            struct timeval tvb;
            tvb.tv_sec = 2; tvb.tv_usec = 0;
            (void)setsockopt(cli, SOL_SOCKET, SO_RCVTIMEO, &tvb, sizeof tvb);

            static uint8_t body[4096], f[4200];
            size_t blen = set_name_body(body, "granica.example", bp, bo);
            frame(f, D2K_CMD_SET_NAME, body, blen);
            CHECK(write(cli, f, 6 + blen) == (ssize_t)(6 + blen),
                  "команда границы длины не отправилась");
            CHECK(poll_frames(c, d2k_ctlsrv_command, &cb, 1) == 1,
                  "команда границы длины не разобралась");
            d2k_ctl_flush(c);
            uint16_t cmd = 0; int ok = 1; uint8_t reason = 0;
            CHECK(read_ack(cli, &cmd, &ok, &reason) == 1, "ack на границе длины не пришёл");
            if (cases[ci].accept) {
                CHECK(ok == 1, "план, ровно помещающийся в предел, отвергнут");
                CHECK(d2k_session_plan_count(sess) == 1,
                      "принятый на границе план не встал в таблицу");
            } else {
                CHECK(ok == 0, "план на байт длиннее предела принят");
                CHECK(reason == D2K_ACK_BAD_PLAN,
                      "отказ на границе назван не негодностью плана");
                CHECK(d2k_session_plan_count(sess) == 0,
                      "отвергнутый на границе план всё-таки встал в таблицу");
            }
            close(cli);
            d2k_session_free(sess);
        }
    }

    d2k_ctl_close(c);

    /* Файл сокета обязан исчезнуть: иначе следующий запуск наткнётся на него. */
    CHECK(access(SOCK, F_OK) != 0, "файл сокета остался после закрытия");

    if (fails) {
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }
    printf("управление: все проверки прошли\n");
    return 0;
}
