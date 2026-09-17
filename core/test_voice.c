/* test_voice.c — голосовой путь: цель из живого разговора и три слоя.
 *
 * Сети здесь нет вовсе: оракул и разрешение имени подменяются крючками (см.
 * d2k_voice.h — почему они крючки), а таблица соединений подсовывается файлом.
 * Подменить файл честнее, чем подделывать ядро, и ровно так же устроен тест
 * NAT в датапате.
 */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#define _DEFAULT_SOURCE 1
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "d2k_stun.h"
#include "d2k_voice.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

static const char *write_ct(const char *body) {
    static char path[] = "/tmp/d2k-voice-ct-XXXXXX";
    static char made[sizeof path];
    strcpy(path, "/tmp/d2k-voice-ct-XXXXXX");
    int fd = mkstemp(path);
    if (fd < 0) { return NULL; }
    FILE *f = fdopen(fd, "w");
    fputs(body, f);
    fclose(f);
    strcpy(made, path);
    return made;
}

static uint32_t ip4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    uint8_t v[4] = { a, b, c, d };
    uint32_t out;
    memcpy(&out, v, 4);
    return out;
}

/* --- подменённый оракул ------------------------------------------------- */
static uint32_t g_answer_ip;      /* этот адрес отвечает всегда */
static uint32_t g_answer_with_pre; /* этот отвечает ТОЛЬКО когда впереди фальшивка */
static int      g_need_copies;     /* и только если копий не меньше этого */
static int      g_partial;         /* 1 — отвечать 1 из 3 (расхождение) */
static int      g_calls;
static uint32_t g_last_ip;
static int      g_last_copies;
static int      g_marked_ok = 1;

static d2k_tally stub_ask(uint32_t ip, uint16_t port, const uint8_t *pre, size_t pre_len,
                          int copies, uint32_t wait_ms, uint32_t mark, int repeats,
                          uint32_t *rtt_ms_out) {
    (void)port; (void)pre_len; (void)wait_ms;
    d2k_tally t;
    memset(&t, 0, sizeof t);
    t.marked = (mark == 0) || g_marked_ok;
    g_calls++;
    g_last_ip = ip;
    g_last_copies = copies;

    int ok = 0;
    if (ip == g_answer_ip) {
        ok = 1;
    } else if (g_answer_with_pre && ip == g_answer_with_pre && pre && copies >= g_need_copies) {
        ok = 1;
    }
    if (ok && g_partial) {
        t.pass = 1;
        t.fail = repeats - 1;
    } else if (ok) {
        t.pass = repeats;
    } else {
        t.fail = repeats;
    }
    if (rtt_ms_out) { *rtt_ms_out = t.pass ? 12u : 0u; }
    return t;
}

static int g_alive;
static int stub_alive(const char *ct_path, uint32_t ip, uint16_t port) {
    (void)ct_path; (void)ip; (void)port;
    return g_alive;
}

static uint32_t g_ctl_ip;
static int stub_resolve(const char *hostport, uint32_t *ip, uint16_t *port) {
    (void)hostport;
    if (!g_ctl_ip) { return -1; }
    *ip = g_ctl_ip;
    *port = 3478;
    return 0;
}

/* --- мишень STUN на петле ------------------------------------------------
 *
 * Отвечает на ОДИН запрос и завершается. honest=1 — ответ с нашим
 * идентификатором транзакции; honest=0 — с чужим: так выглядит посторонний
 * пакет, прилетевший на тот же порт. */
struct srv_arg { int fd; int honest; };

static void *stun_server(void *p) {
    struct srv_arg *a = (struct srv_arg *)p;
    uint8_t buf[1500];
    struct sockaddr_in from;
    socklen_t fl = sizeof from;
    for (int i = 0; i < D2K_VOICE_REPEATS; i++) {
        ssize_t n = recvfrom(a->fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
        if (n < D2K_STUN_HDR_LEN) { break; }
        uint8_t resp[32];
        memcpy(resp, buf, D2K_STUN_HDR_LEN);
        resp[0] = 0x01; resp[1] = 0x01;          /* Binding Response */
        resp[2] = 0x00; resp[3] = 0x0c;          /* один атрибут, 12 байт */
        if (!a->honest) { resp[8] ^= 0xff; }     /* чужой идентификатор */
        /* XOR-MAPPED-ADDRESS: 192.0.2.1:32853 — те же байты, что в RFC 5769. */
        static const uint8_t attr[12] = {
            0x00,0x20,0x00,0x08, 0x00,0x01,0xa1,0x47, 0xe1,0x12,0xa6,0x43
        };
        memcpy(resp + D2K_STUN_HDR_LEN, attr, sizeof attr);
        (void)sendto(a->fd, resp, D2K_STUN_HDR_LEN + sizeof attr, 0,
                     (struct sockaddr *)&from, fl);
    }
    close(a->fd);
    free(a);
    return NULL;
}

static int stun_server_start(pthread_t *th, uint16_t *port, int honest) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { return -1; }
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return -1; }
    socklen_t al = sizeof a;
    if (getsockname(fd, (struct sockaddr *)&a, &al) != 0) { close(fd); return -1; }
    *port = ntohs(a.sin_port);
    /* Мишень не должна висеть вечно, если зонд не пришёл: у сокета свой срок. */
    struct timeval tv = { 3, 0 };
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    struct srv_arg *arg = malloc(sizeof *arg);
    if (!arg) { close(fd); return -1; }
    arg->fd = fd;
    arg->honest = honest;
    if (pthread_create(th, NULL, stun_server, arg) != 0) { close(fd); free(arg); return -1; }
    return 0;
}

static void reset(void) {
    g_answer_ip = 0;
    g_answer_with_pre = 0;
    g_need_copies = 1;
    g_partial = 0;
    g_calls = 0;
    g_last_ip = 0;
    g_last_copies = 0;
    g_marked_ok = 1;
    g_ctl_ip = ip4(162, 159, 128, 233);
    g_alive = -1;   /* по умолчанию сказать нечего */
}

int main(void) {
    d2k_voice_ask_hook = stub_ask;
    d2k_voice_resolve_hook = stub_resolve;
    d2k_voice_alive_hook = stub_alive;

    /* --- ЦЕЛЬ ИЗ ЖИВОГО РАЗГОВОРА ---------------------------------------
     * Формат строки conntrack на разных ядрах отличается началом (есть или
     * нет колонка семейства), поэтому разбор идёт по парам «ключ=значение».
     * Здесь обе разновидности сразу — и с колонкой, и без. */
    {
        const char *body =
            /* голос, 812 пакетов — самый живой разговор */
            "ipv4     2 udp      17 29 src=192.168.1.117 dst=104.16.58.99 sport=54321 "
            "dport=50003 packets=812 bytes=90000 src=104.16.58.99 dst=88.87.93.11 "
            "sport=50003 dport=54321 packets=800 bytes=88000 mark=0 use=2\n"
            /* ДРУГОЙ порт источника — значит ДРУГОЙ поток, и складывать его
               с первым нельзя: ответ одному клиенту спрятал бы беду другого
               (ревью, P1-3). */
            "ipv4     2 udp      17 29 src=192.168.1.117 dst=104.16.58.99 sport=54999 "
            "dport=50003 packets=100 bytes=9000 src=104.16.58.99 dst=88.87.93.11 "
            "sport=50003 dport=54999 packets=90 bytes=8000 mark=0 use=2\n"
            /* голос, но менее нагруженный — обязан идти вторым */
            "udp      17 29 src=192.168.1.117 dst=104.16.58.100 sport=54322 "
            "dport=3478 packets=40 bytes=4000 src=104.16.58.100 dst=88.87.93.11 "
            "sport=3478 dport=54322 packets=38 bytes=3800 mark=0 use=2\n"
            /* не голосовой порт — не цель */
            "ipv4     2 udp      17 29 src=192.168.1.117 dst=8.8.8.8 sport=5000 "
            "dport=53 packets=9999 bytes=90000 src=8.8.8.8 dst=88.87.93.11 "
            "sport=53 dport=5000 packets=9999 bytes=90000 mark=0 use=2\n"
            /* TCP на голосовом порту — не голос */
            "ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.1.117 dst=104.16.58.7 "
            "sport=44444 dport=50004 packets=9999 bytes=90000 src=104.16.58.7 "
            "dst=88.87.93.11 sport=50004 dport=44444 packets=9999 bytes=9 mark=0 use=2\n"
            /* приватный адрес назначения — свой же NAT или редирект, не цель */
            "ipv4     2 udp      17 29 src=192.168.1.117 dst=10.171.171.171 sport=54444 "
            "dport=50005 packets=9999 bytes=90000 src=10.171.171.171 dst=192.168.1.117 "
            "sport=50005 dport=54444 packets=9999 bytes=9 mark=0 use=2\n";
        const char *path = write_ct(body);
        d2k_voice_target t[D2K_VOICE_MAX_TARGETS];
        size_t n = d2k_voice_targets(path, t, D2K_VOICE_MAX_TARGETS);

        CHECK(n == 3, "найдено не три голосовых потока — фильтр или разделение по потокам неверны");
        /* Пометки [UNREPLIED] в этих строках нет — значит точка отвечала. */
        if (n == 3) {
            CHECK(t[0].replied == 1 && t[1].replied == 1 && t[2].replied == 1,
                  "поток с обратным трафиком объявлен безответным");
        }
        if (n == 3) {
            CHECK(t[0].ip == ip4(104, 16, 58, 99) && t[0].port == 50003,
                  "первым идёт не самый нагруженный разговор");
            CHECK(t[0].packets == 812, "пакеты чужого потока приписаны этому");
            CHECK(t[0].sport == 54321, "поток не несёт порта своего клиента");
        }
        remove(path);

        CHECK(d2k_voice_targets("/nonexistent/d2k-voice", t, D2K_VOICE_MAX_TARGETS) == 0,
              "нечитаемая таблица выдала цели");
    }

    /* --- [UNREPLIED]: ТОЧКА НИКОМУ НЕ ОТВЕЧАЛА --------------------------
     * Признак берётся вместо счётчика пакетов: на роутере Марка голосовой
     * поток уходит в железо ([FASTNAT]), и счётчик замирает (замер 17.09:
     * 5593, 5593, 5593, 5594 за три секунды при непрерывном разговоре).
     * Флаг состояния железо не стирает. */
    {
        const char *path = write_ct(
            "ipv4     2 udp      17 3 src=88.87.93.11 dst=104.16.58.99 sport=57581 "
            "dport=50004 packets=10 bytes=13850 [UNREPLIED] src=104.16.58.99 "
            "dst=88.87.93.11 sport=50004 dport=57581 packets=0 bytes=0 [FASTNAT] use=2\n");
        d2k_voice_target t[D2K_VOICE_MAX_TARGETS];
        size_t n = d2k_voice_targets(path, t, D2K_VOICE_MAX_TARGETS);
        CHECK(n == 1, "поток без ответа обязан находиться — он цель не хуже прочих");
        if (n == 1) {
            CHECK(t[0].replied == 0,
                  "поток с пометкой [UNREPLIED] объявлен отвечающим — это выдача своих же "
                  "зондов за живой разговор");
        }
        remove(path);
    }

    /* --- РАЗГОВОРА НЕТ: мерить нечего, и это НЕ «всё хорошо» -------------- */
    {
        reset();
        const char *path = write_ct("ipv4 2 tcp 6 431999 ESTABLISHED src=1.2.3.4 dst=5.6.7.8 "
                                    "sport=1 dport=443 packets=1 bytes=1\n");
        d2k_voice_opt o;
        memset(&o, 0, sizeof o);
        o.ct_path = path;
        d2k_voice_res r = d2k_voice_run(&o);
        CHECK(r.verdict == D2K_VOICE_NO_CALL, "без разговора вердикт обязан быть «мерить нечего»");
        CHECK(r.probes == 0, "зонды ушли, хотя цели не было");
        CHECK(strstr(r.reason, "позвони") != NULL || strstr(r.reason, "разговор") != NULL,
              "причина обязана объяснить человеку, что делать");
        remove(path);
    }

    /* --- ОРАКУЛ ПО САМОМУ РАЗГОВОРУ, А НЕ ПО СВОЕМУ ЗОНДУ -----------------
     *
     * Поле 17.09 доказало, что зонд STUN оракулом быть не может: голосовая
     * точка молчит на что угодно с чужого сокета. Зато в таблице соединений
     * видно, отвечает ли она НАСТОЯЩЕМУ клиенту — по отсутствию пометки
     * [UNREPLIED]. Это и есть оракул: он про тот самый поток, который надо
     * пробить, а не про наш зонд.
     *
     * Отвечает — резать нечего, и никаких зондов слать не надо вовсе. */
    {
        reset();
        g_answer_ip = 0;   /* зонд молчал бы, и это больше не важно */
        g_alive = 1;
        d2k_voice_opt o;
        memset(&o, 0, sizeof o);
        o.ip = ip4(104, 16, 58, 99);
        o.port = 50003;
        d2k_voice_res r = d2k_voice_run(&o);
        CHECK(r.verdict == D2K_VOICE_CLEAR,
              "сервер отвечает настоящему клиенту, а вердикт не «резать нечего»");
        CHECK(g_calls == 0, "зонды ушли там, где ответ уже виден в таблице соединений");
        CHECK(r.probes == 0, "опыты посчитаны там, где их не было");
    }

    /* Поток есть, ответов НЕТ — вот это и есть блокировка потока. Контроль
       нужен, чтобы отделить «режут этот поток» от «UDP не ходит вовсе». */
    {
        reset();
        g_answer_ip = g_ctl_ip;   /* публичный STUN отвечает — UDP на канале жив */
        g_alive = 0;              /* а голосовой поток идёт без ответа */
        char dir[64];
        snprintf(dir, sizeof dir, "/tmp/d2k-voice-blobs-%d", (int)getpid());
        CHECK(mkdir(dir, 0700) == 0 || errno == EEXIST, "каталог блобов не создался");
        char file[256];
        snprintf(file, sizeof file, "%s/stun.bin", dir);
        FILE *f = fopen(file, "wb");
        for (int i = 0; i < 64; i++) { fputc(0x42, f); }
        fclose(f);
        g_answer_with_pre = ip4(104, 16, 58, 99);
        g_need_copies = 6;

        d2k_voice_opt o;
        memset(&o, 0, sizeof o);
        o.ip = ip4(104, 16, 58, 99);
        o.port = 50003;
        d2k_voice_res r = d2k_voice_run(&o);
        CHECK(r.verdict == D2K_VOICE_BLOCKED,
              "поток идёт без единого ответа, а контроль жив — это блокировка потока");
        /* ПРИЁМ НЕ ПОДТВЕРЖДАЕТСЯ ЗОНДОМ STUN, И ВЫВОДА ПРО НЕГО НЕТ.
           Базовый оракул заменён наблюдением разговора именно потому, что
           голосовая точка не отвечает посторонним. Испытывать приманки тем же
           отвергнутым способом и делать вывод «не пробивает» — повторять ту же
           ошибку на шаг позже (ревью, P1-4). */
        CHECK(r.arm[0] == '\0',
              "приём объявлен найденным по зонду, который оракулом быть не может");
        CHECK(strstr(r.reason, "не пробивает") == NULL,
              "сказано «ни одна фальшивка не пробивает» — вывод из непригодного зонда");
        CHECK(strstr(r.reason, "не подтвердить") != NULL ||
              strstr(r.reason, "не проверялись") != NULL,
              "не сказано, ПОЧЕМУ приёма нет");
        remove(file); rmdir(dir);
    }

    /* --- СЛОЙ 1: голосовой сервер отвечает — резать нечего ---------------- */
    {
        reset();
        g_answer_ip = ip4(104, 16, 58, 99);
        d2k_voice_opt o;
        memset(&o, 0, sizeof o);
        o.ip = g_answer_ip;
        o.port = 50003;
        d2k_voice_res r = d2k_voice_run(&o);
        CHECK(r.verdict == D2K_VOICE_CLEAR, "сервер отвечает, а вердикт не «резать нечего»");
        CHECK(g_calls == 1, "контроль спрошен зря: первый слой уже всё доказал");
        CHECK(r.probes == D2K_VOICE_REPEATS, "зонды посчитаны неверно");
    }

    /* --- РАСХОЖДЕНИЕ ПОВТОРОВ: вердикт выносить нельзя -------------------- */
    {
        reset();
        g_answer_ip = ip4(104, 16, 58, 99);
        g_partial = 1;
        d2k_voice_opt o;
        memset(&o, 0, sizeof o);
        o.ip = g_answer_ip;
        o.port = 50003;
        d2k_voice_res r = d2k_voice_run(&o);
        CHECK(r.verdict == D2K_VOICE_FLAKY,
              "1 из 3 — это «не воспроизводится», а не «резать нечего»");
    }

    /* --- СЛОЙ 2: молчат оба — UDP не ходит вовсе -------------------------- */
    {
        reset();
        g_answer_ip = 0; /* не отвечает никто */
        g_alive = 0;     /* поток к точке идёт, ответов по нему нет */
        d2k_voice_opt o;
        memset(&o, 0, sizeof o);
        o.ip = ip4(104, 16, 58, 99);
        o.port = 50003;
        d2k_voice_res r = d2k_voice_run(&o);
        CHECK(r.verdict == D2K_VOICE_NO_UDP,
              "молчит и контроль — значит режут UDP целиком, а не голос");
        CHECK(strstr(r.reason, "бессмысленно") != NULL,
              "причина обязана сказать, что обходить голос отдельно незачем");
        CHECK(g_calls == 1, "спрошен обязан быть только контроль: про сам поток ответ уже есть");
    }

    /* --- МОЛЧАНИЕ ЗОНДА ПРИ ЖИВОМ РАЗГОВОРЕ — НЕ БЛОКИРОВКА --------------
     *
     * Поле 17.09: голосовая точка Дискорда молчит на STUN, на нули и на мусор
     * одинаково, при живом разговоре через тот же адрес. Она обслуживает
     * только установленную сессию. Вердикт «режут именно этот поток» на
     * исправном голосе — прямая ложь, и опровергается она тем же источником,
     * откуда взята цель: счётчик пакетов потока растёт. */
    {
        reset();
        g_answer_ip = g_ctl_ip;   /* контроль отвечает — UDP на канале ходит */
        g_alive = 1;              /* а разговор к цели идёт прямо сейчас */
        d2k_voice_opt o;
        memset(&o, 0, sizeof o);
        o.ip = ip4(104, 16, 58, 99);
        o.port = 50003;
        d2k_voice_res r = d2k_voice_run(&o);

        CHECK(r.verdict == D2K_VOICE_CLEAR,
              "поток жив и сервер отвечает — резать нечего");
        CHECK(r.arm[0] == '\0',
              "приём подбирался там, где резать нечего");
    }

    /* Наблюдать нечего И зонд молчит — честное «мерить нечем», а НЕ
       «режут»: голосовая точка молчит и на исправной линии. */
    {
        reset();
        g_answer_ip = 0;
        g_alive = -1;   /* потока к этой точке ядро не видит */
        d2k_voice_opt o;
        memset(&o, 0, sizeof o);
        o.ip = ip4(104, 16, 58, 99);
        o.port = 50003;
        d2k_voice_res r = d2k_voice_run(&o);
        CHECK(r.verdict == D2K_VOICE_NO_ORACLE,
              "молчание зонда выдано за блокировку там, где наблюдать нечего");
        CHECK(r.arm[0] == '\0', "приём подбирался там, где мерить нечем");
    }

    /* --- КОНТРОЛЬ НЕ ИЗМЕРЕН — ЗНАЧИТ И ВЫВОДА НЕТ --------------------------
     *
     * Наблюдение «поток идёт, ответов нет» настоящее, но одного его мало:
     * отделить «режут именно этот поток» от «UDP не ходит вовсе» может только
     * контроль. Не разрешилось имя контроля — зондов ноль, измерение
     * незакончено, и объявлять блокировку нельзя. */
    {
        reset();
        g_ctl_ip = 0;    /* имя контроля не разрешается */
        g_alive = 0;     /* поток идёт, ответов по нему нет */
        d2k_voice_opt o;
        memset(&o, 0, sizeof o);
        o.ip = ip4(104, 16, 58, 99);
        o.port = 50003;
        d2k_voice_res r = d2k_voice_run(&o);
        CHECK(r.verdict != D2K_VOICE_BLOCKED,
              "блокировка объявлена без единого зонда контроля — это вывод из недостачи данных");
        CHECK(r.verdict == D2K_VOICE_UNMEASURED,
              "незаконченное измерение не названо незаконченным");
        CHECK(r.probes == 0, "зонды посчитаны там, где их не было");
        CHECK(r.arm[0] == '\0' && r.strategy[0] == '\0',
              "приём подобран там, где вывода нет");
    }

    /* --- ОТВЕТ ОДНОМУ КЛИЕНТУ НЕ ПРЯЧЕТ БЕДУ ДРУГОГО ----------------------
     *
     * На роутере к одной голосовой точке ходят разные устройства. Записи
     * складывались по адресу сервера, и признак «отвечает» брался ИЛИ по всем:
     * ответ одному клиенту объявлял живым поток другого. Поток — это пятёрка,
     * а не адрес сервера. */
    {
        const char *path = write_ct(
            /* первый клиент: ответы идут */
            "ipv4     2 udp      17 29 src=192.168.1.10 dst=104.16.58.99 sport=54321 "
            "dport=50003 packets=900 bytes=90000 src=104.16.58.99 dst=88.87.93.11 "
            "sport=50003 dport=54321 packets=800 bytes=88000 use=2\n"
            /* второй клиент: та же точка, ответов нет */
            "ipv4     2 udp      17 29 src=192.168.1.11 dst=104.16.58.99 sport=54999 "
            "dport=50003 packets=50 bytes=9000 [UNREPLIED] src=104.16.58.99 "
            "dst=88.87.93.11 sport=50003 dport=54999 packets=0 bytes=0 use=2\n");
        d2k_voice_target t[D2K_VOICE_MAX_TARGETS];
        size_t n = d2k_voice_targets(path, t, D2K_VOICE_MAX_TARGETS);
        CHECK(n == 2,
              "два разных потока к одной точке слиты в один — беда одного клиента спрятана "
              "ответом другому");
        if (n == 2) {
            int replied_seen = 0, unreplied_seen = 0;
            for (size_t i = 0; i < n; i++) {
                if (t[i].replied) { replied_seen = 1; } else { unreplied_seen = 1; }
            }
            CHECK(replied_seen && unreplied_seen,
                  "признак ответа взят общий по адресу, а не по потоку");
        }
        remove(path);
    }

    /* --- СЛОЙ 3: режут именно этот поток, фальшивка его пробивает --------- */
    {
        reset();
        g_answer_ip = g_ctl_ip;                    /* контроль отвечает — UDP ходит */
        g_alive = 0;                               /* поток идёт, ответов нет — режут */
        g_answer_with_pre = ip4(104, 16, 58, 99);  /* голос берётся фальшивкой */
        g_need_copies = 6;                         /* и только шестью копиями */

        char dir[64];
        snprintf(dir, sizeof dir, "/tmp/d2k-voice-blobs-%d", (int)getpid());
        CHECK(mkdir(dir, 0700) == 0 || errno == EEXIST, "каталог блобов не создался");
        char file[256];
        snprintf(file, sizeof file, "%s/stun.bin", dir);
        FILE *f = fopen(file, "wb");
        for (int i = 0; i < 64; i++) { fputc(0x42, f); }
        fclose(f);

        d2k_voice_opt o;
        memset(&o, 0, sizeof o);
        o.ip = ip4(104, 16, 58, 99);
        o.port = 50003;
        d2k_voice_res r = d2k_voice_run(&o);

        CHECK(r.verdict == D2K_VOICE_BLOCKED,
              "контроль жив, голос молчит — режут именно этот поток");
        remove(file);
        rmdir(dir);
    }


    /* --- НЕПОМЕЧЕННЫЙ ЗОНД: замер про наш же обход, а не про коробку ------ */
    {
        reset();
        g_answer_ip = ip4(104, 16, 58, 99);
        g_marked_ok = 0;
        d2k_voice_opt o;
        memset(&o, 0, sizeof o);
        o.ip = g_answer_ip;
        o.port = 50003;
        o.mark = 0x2d;
        d2k_voice_res r = d2k_voice_run(&o);
        CHECK(r.marked == 0, "метка не подтверждена, а прогон объявлен помеченным");
        CHECK(strstr(r.reason, "метк") != NULL || strstr(r.reason, "обход") != NULL,
              "непомеченный прогон обязан сказать о себе вслух");
    }

    /* ===== ЧАСТЬ 2: НАСТОЯЩИЕ СОКЕТЫ =====================================
     *
     * Всё выше меряет ДИСЦИПЛИНУ дерева при подменённом оракуле. Здесь
     * проверяется сам оракул: что он собирает запрос, узнаёт свой ответ и НЕ
     * засчитывает чужой — через настоящий сокет, а не через договорённость
     * мока с собой. Мишень своя, на петле: сеть наружу тест не трогает. */
    {
        d2k_voice_ask_hook = voice_ask_real();
        uint16_t port = 0;
        pthread_t th;
        int mode_ok = 1;

        /* --- ответчик отвечает ПРАВИЛЬНО: зонд обязан засчитать 3/3 ------- */
        CHECK(stun_server_start(&th, &port, 1) == 0, "мишень STUN не поднялась");
        if (port) {
            d2k_tally t = d2k_voice_ask_hook(ip4(127, 0, 0, 1), port, NULL, 0, 0,
                                             1500, 0, D2K_VOICE_REPEATS, NULL);
            CHECK(t.pass == D2K_VOICE_REPEATS,
                  "настоящий ответ STUN не засчитан — оракул не узнаёт собственный запрос");
            CHECK(t.err == 0, "зонд не отправился");
        }
        pthread_join(th, NULL);

        /* --- ответчик отвечает С ЧУЖИМ идентификатором ---------------------
         * Ровно то, ради чего сверка и существует: на порт прилетел
         * правдоподобный пакет, но он не про наш вопрос. */
        mode_ok = 0;
        (void)mode_ok;
        CHECK(stun_server_start(&th, &port, 0) == 0, "мишень STUN не поднялась (второй раз)");
        if (port) {
            d2k_tally t = d2k_voice_ask_hook(ip4(127, 0, 0, 1), port, NULL, 0, 0,
                                             400, 0, D2K_VOICE_REPEATS, NULL);
            CHECK(t.pass == 0,
                  "ответ с чужим идентификатором засчитан за наш — доказательство подделано");
        }
        pthread_join(th, NULL);
    }

    if (fails) {
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }
    printf("голосовой путь: все проверки прошли\n");
    return 0;
}
