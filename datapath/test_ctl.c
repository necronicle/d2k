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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#include "d2k_ctl.h"
#include "d2k_ctlsrv.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

static const char *SOCK = "/tmp/d2k-test-ctl.sock";

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
static int read_ack(int fd, uint16_t *cmd, int *ok, uint8_t *reason) {
    uint8_t buf[6 + D2K_KEY_WIRE_LEN + 2 + 1 + 1];
    ssize_t n = read(fd, buf, sizeof buf);
    if (n != (ssize_t)sizeof buf) {
        return 0;
    }
    uint16_t type = (uint16_t)((buf[4] << 8) | buf[5]);
    if (type != D2K_EV_ACK) {
        return 0;
    }
    const uint8_t *body = buf + 6;
    *cmd = (uint16_t)((body[D2K_KEY_WIRE_LEN] << 8) | body[D2K_KEY_WIRE_LEN + 1]);
    *ok = body[D2K_KEY_WIRE_LEN + 2];
    *reason = body[D2K_KEY_WIRE_LEN + 3];
    return 1;
}

/* Тело команды SET_NAME: [длина имени u8][имя][план TLV]. */
/* Тело SET_NAME: [длина имени][имя][ФОРМА][план]. Форма байтом перед планом
   — длина плана в теле не объявлена, и поле после него было бы съедено как
   его часть (см. d2k_link.h). Дедушкино право здесь потому, что эти
   проверки про разбор команды, а не про ограничение по форме: оно проверяется
   отдельно, ниже. */
static size_t set_name_body_shaped(uint8_t *body, const char *name,
                                   const uint8_t *plan, size_t planlen,
                                   uint8_t shape) {
    size_t nl = strlen(name);
    body[0] = (uint8_t)nl;
    memcpy(body + 1, name, nl);
    body[1 + nl] = shape;
    memcpy(body + 2 + nl, plan, planlen);
    return 2 + nl + planlen;
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

int main(void) {
    char err[160];
    d2k_ctl *c = d2k_ctl_open(SOCK, err, sizeof err);
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

        /* Годная команда: ack ok=1, причина D2K_ACK_OK. */
        {
            uint8_t body[64], f[80];
            size_t blen = set_name_body(body, "ok.example", tiny, sizeof tiny);
            frame(f, D2K_CMD_SET_NAME, body, blen);
            CHECK(write(cli, f, 6 + blen) == (ssize_t)(6 + blen), "годная команда не отправилась");
            CHECK(d2k_ctl_poll(c, d2k_ctlsrv_command, &cx) == 1, "годная команда не разобралась");
            d2k_ctl_flush(c);
            uint16_t cmd = 0; int ok = 0; uint8_t reason = 0;
            CHECK(read_ack(cli, &cmd, &ok, &reason) == 1, "ack на годную команду не пришёл");
            CHECK(cmd == D2K_CMD_SET_NAME, "ack не на ту команду");
            CHECK(ok == 1, "годная команда отвергнута");
            CHECK(reason == D2K_ACK_OK, "у успеха причина не D2K_ACK_OK");
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
            CHECK(d2k_ctl_poll(c, d2k_ctlsrv_command, &cx) == 1, "негодный план не разобрался");
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
            memcpy(body + 2, tiny, sizeof tiny);
            size_t blen = 2 + sizeof tiny;
            frame(f, D2K_CMD_SET_NAME, body, blen);
            CHECK(write(cli, f, 6 + blen) == (ssize_t)(6 + blen), "команда с пустым именем не отправилась");
            CHECK(d2k_ctl_poll(c, d2k_ctlsrv_command, &cx) == 1, "команда с пустым именем не разобралась");
            d2k_ctl_flush(c);
            uint16_t cmd = 0; int ok = 0; uint8_t reason = 0;
            CHECK(read_ack(cli, &cmd, &ok, &reason) == 1, "ack на пустое имя не пришёл");
            CHECK(ok == 0, "пустое имя принято как цель");
            CHECK(reason == D2K_ACK_BAD_ARGS, "пустое имя не помечено D2K_ACK_BAD_ARGS");
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
                CHECK(d2k_ctl_poll(c, d2k_ctlsrv_command, &cx) == 1, "цель-наполнитель не разобралась");
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
            CHECK(d2k_ctl_poll(c, d2k_ctlsrv_command, &cx) == 1, "цель после заполнения не разобралась");
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
            CHECK(d2k_ctl_poll(c, d2k_ctlsrv_command, &cx) == 1, "первая цель давности не разобралась");
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
            CHECK(d2k_ctl_poll(c, d2k_ctlsrv_command, &cx) == 1, "наполнитель давности не разобрался");
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
            CHECK(d2k_ctl_poll(c, d2k_ctlsrv_command, &cx) == 1, "цель поверх давности не разобралась");
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
            CHECK(d2k_ctl_poll(c, d2k_ctlsrv_command, &cx) == 1,
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
            CHECK(n == (ssize_t)(D2K_KEY_WIRE_LEN + 16),
                  "тело APPLIED не «ключ + 16 байт идентификатора»");
            if (n == (ssize_t)(D2K_KEY_WIRE_LEN + 16)) {
                CHECK(memcmp(ev + D2K_KEY_WIRE_LEN, want_id, sizeof want_id) == 0,
                      "идентификатор на проводе не тот, что приехал записью REC_ID");
            }
        }
        CHECK(found, "события применения не пришло вовсе");

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
            CHECK(d2k_ctl_poll(c, d2k_ctlsrv_command, &cx) == 1,
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
            CHECK(n == (ssize_t)(D2K_KEY_WIRE_LEN + 1) || n == (ssize_t)(D2K_KEY_WIRE_LEN + 17),
                  "тело REFUSED не «ключ + код причины»");
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
                CHECK(n == (ssize_t)(D2K_KEY_WIRE_LEN + 17),
                      "повреждение приехало без идентификатора плана");
                int nonzero = 0;
                for (int b = 0; b < 16; b++) {
                    if (ev[D2K_KEY_WIRE_LEN + 1 + b]) { nonzero = 1; }
                }
                CHECK(nonzero, "идентификатор плана у повреждения нулевой");
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
        CHECK(d2k_ctl_poll(c, d2k_ctlsrv_command, &cx) == 1,
              "команда с длинной посылкой не разобралась");
        d2k_ctl_flush(c);
        uint16_t cmd = 0; int ok = 1; uint8_t reason = 0;
        CHECK(read_ack(cli, &cmd, &ok, &reason) == 1, "ack на длинную посылку не пришёл");
        CHECK(ok == 0, "план, чья посылка не унесётся, подтверждён как принятый");
        CHECK(reason == D2K_ACK_BAD_PLAN, "отказ по длине назван не негодностью плана");
        CHECK(d2k_session_plan_count(sess) == 0,
              "отвергнутый по длине план всё-таки встал в таблицу");

        close(cli);
        d2k_session_free(sess);
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
