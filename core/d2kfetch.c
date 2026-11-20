/* d2kfetch — обращение к цели КАК У БРАУЗЕРА, с роутера.
 *
 * ЗАЧЕМ. Полевую проверку до сих пор подпирали curl, и он врал. План D2K
 * привязан к ИМЕНИ И ФОРМЕ приветствия, а исполнитель считает смещения разреза
 * от разметки конкретного приветствия. Приветствие curl короче браузерного
 * (поле 15.10.2026: Edge — 1951 байт, curl — около 517) и устроено иначе:
 * план, выведенный по браузерным байтам, к потоку curl либо не подходит
 * формой, либо не исполняется — якоря разреза выходят за его длину. Оттого
 * flibusta.is у человека открывалась в браузере и не открывалась через curl,
 * и «ноль байт» в выводе curl ничего не говорил о том, работает ли обход.
 *
 * ЧТО ДЕЛАЕТ. Один запрос к цели СВОИМ клиентом, но приветствием той же формы
 * и той же длины, что у браузера, НЕПОМЕЧЕННЫЙ — то есть ровно так, как идёт
 * поток человека: датапат применит к нему тот же план. Печатает, что реально
 * пришло: версию TLS, код HTTP, сколько тела получено из скольких ожидаемых,
 * доведён ли ответ до конца или оборван.
 *
 * ДЛИНА ПРИВЕТСТВИЯ. --wire N задаёт её прямо. --snapshot берёт её у
 * ЖИВОГО браузера: взводит ловушку снимка в датапате и ждёт, пока человек
 * (или вкладка на этом же роутере) сам сходит на это имя. Это честнее
 * любого числа из головы: меряем тем, чем ходит клиент.
 *
 * ЧЕГО НЕ ДЕЛАЕТ. Не повторяет байты браузера один в один: без его ключей
 * сессию не продолжить, и за тем, что происходит ПОСЛЕ рукопожатия, пришлось
 * бы всё равно идти своим клиентом. Поэтому совпадают форма и длина — то, по
 * чему план выбирается и исполняется, — а не содержимое расширений.
 * Не ходит по редиректам и не меняет цель. */
#define _POSIX_C_SOURCE 200809L
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "d2k_hello.h"
#include "d2k_link.h"
#include "d2k_verify.h"
#include "d2k_volume.h"

static void json_string(const char *s) {
    if (!s) { printf("null"); return; }
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p < 32) printf("\\u%04x", *p);
        else if (*p < 128) putchar(*p);
        else {
            unsigned width = *p >= 0xc2 && *p <= 0xdf ? 2 :
                             *p >= 0xe0 && *p <= 0xef ? 3 :
                             *p >= 0xf0 && *p <= 0xf4 ? 4 : 0;
            int valid = width != 0;
            for (unsigned i = 1; valid && i < width; i++)
                if (!p[i] || (p[i] & 0xc0) != 0x80) valid = 0;
            if (valid && ((*p == 0xe0 && p[1] < 0xa0) || (*p == 0xed && p[1] >= 0xa0) ||
                          (*p == 0xf0 && p[1] < 0x90) || (*p == 0xf4 && p[1] >= 0x90))) valid = 0;
            if (valid) { for (unsigned i = 0; i < width; i++) putchar(p[i]); p += width - 1; }
            else printf("\\u%04x", *p);
        }
    }
    putchar('"');
}

static const char *vol_verdict_code(d2k_vol_verdict v) {
    switch (v) {
    case D2K_VOL_UNREACHABLE: return "unreachable";
    case D2K_VOL_CUT:         return "cut";
    case D2K_VOL_PASSED:      return "passed";
    case D2K_VOL_SHORT:       return "short";
    default:                  return "unknown";
    }
}

static void usage(void) {
    fprintf(stderr,
        "d2kfetch — обращение к цели как у браузера (через планы D2K)\n"
        "\n"
        "  d2kfetch --name ИМЯ [--ip АДРЕС] [--port N] [--path /путь]\n"
        "           [--wire N | --snapshot[=МС]] [--tls12] [--deadline МС]\n"
        "\n"
        "  --name      имя в SNI и в заголовке Host (обязательно)\n"
        "  --ip        адрес цели; без него имя разрешается системой\n"
        "  --port      порт, по умолчанию 443\n"
        "  --path      путь запроса, по умолчанию /\n"
        "  --wire N    длина приветствия на проводе, как у браузера\n"
        "  --snapshot  взять длину у живого приветствия браузера: взвести\n"
        "              ловушку датапата и ждать (по умолчанию 60000 мс)\n"
        "  --ladder    вместо запроса страницы прогнать ТУ ЖЕ исходящую\n"
        "              лестницу, которой меряет планировщик, и показать её\n"
        "              вердикт: так видно, совпадает ли её обрыв с тем, что\n"
        "              видит браузерное обращение\n"
        "  --mark 0xN  сокетная метка SO_MARK; обход очереди — только при\n"
        "              совпадении с MEASURE_MARK роутера (штатно 0x2f)\n"
        "  --quic      идти по QUIC/HTTP3 вместо TCP (как браузер по h3)\n"
        "  --tls12     старое приветствие TLS 1.2 вместо 1.3\n"
        "  --deadline  потолок на рукопожатие и на ответ, по умолчанию 15000 мс\n"
        "  --json      машиночитаемый вывод одной строкой JSON\n"
        "  --version   показать версию сборки и выйти\n"
        "\n"
        "По умолчанию обращение идёт НЕПОМЕЧЕННЫМ: датапат применяет к нему тот\n"
        "же план, что и к потоку браузера. Это и есть смысл инструмента.\n");
}

static int resolve_first(const char *name, char *out, size_t cap) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(name, NULL, &hints, &res) != 0 || !res) { return -1; }
    int rc = getnameinfo(res->ai_addr, res->ai_addrlen, out, (socklen_t)cap,
                         NULL, 0, NI_NUMERICHOST);
    freeaddrinfo(res);
    return rc == 0 ? 0 : -1;
}

/* Длина живого приветствия браузера: ловушка датапата и ожидание. */
static int snapshot_wire(const char *name, long wait_ms, size_t *out_wire) {
    char err[200];
    int fd = d2k_link_open(NULL, err, sizeof err);
    if (fd < 0) {
        fprintf(stderr, "нет связи с датапатом: %s\n", err);
        return -1;
    }
    if (d2k_link_arm_shape(fd, name, 6, err, sizeof err) != 0) {
        fprintf(stderr, "ловушка снимка не взвелась: %s\n", err);
        d2k_link_close(fd);
        return -1;
    }
    fprintf(stderr, "жду приветствие браузера к %s (до %ld мс): откройте сайт\n",
            name, wait_ms);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int rc = -1;
    for (;;) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long spent = (now.tv_sec - t0.tv_sec) * 1000L +
                     (now.tv_nsec - t0.tv_nsec) / 1000000L;
        if (spent >= wait_ms) {
            fprintf(stderr, "приветствия не дождались за %ld мс\n", wait_ms);
            break;
        }
        d2k_ev ev;
        int r = d2k_link_next(fd, &ev, (int)(wait_ms - spent), err, sizeof err);
        if (r < 0) { fprintf(stderr, "связь с датапатом: %s\n", err); break; }
        if (r == 1) { continue; }
        if (ev.kind != D2K_EV_SHAPE || ev.transport != 6) { continue; }
        *out_wire = ev.shape_len;
        fprintf(stderr, "снято приветствие браузера: %zu байт\n", ev.shape_len);
        rc = 0;
        break;
    }
    d2k_link_close(fd);
    return rc;
}

int main(int argc, char **argv) {
    const char *name = NULL, *ip = NULL, *path = "/";
    uint16_t port = 443;
    size_t wire = 0;
    int tls12 = 0, deadline = 15000, ladder = 0, quic = 0, json = 0;
    uint32_t mark = 0;
    long snap_ms = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        int last = i + 1 >= argc;
        if (!strcmp(a, "--name") && !last) { name = argv[++i]; }
        else if (!strcmp(a, "--ip") && !last) { ip = argv[++i]; }
        else if (!strcmp(a, "--path") && !last) { path = argv[++i]; }
        else if (!strcmp(a, "--port") && !last) { port = (uint16_t)atoi(argv[++i]); }
        else if (!strcmp(a, "--wire") && !last) { wire = (size_t)atol(argv[++i]); }
        else if (!strcmp(a, "--deadline") && !last) { deadline = atoi(argv[++i]); }
        else if (!strcmp(a, "--tls12")) { tls12 = 1; }
        else if (!strcmp(a, "--ladder")) { ladder = 1; }
        else if (!strcmp(a, "--quic")) { quic = 1; }
        else if (!strcmp(a, "--mark") && !last) { mark = (uint32_t)strtoul(argv[++i], NULL, 0); }
        else if (!strcmp(a, "--json")) { json = 1; }
        else if (!strcmp(a, "--snapshot")) { snap_ms = 60000; }
        else if (!strncmp(a, "--snapshot=", 11)) { snap_ms = atol(a + 11); }
        else if (!strcmp(a, "--version") || !strcmp(a, "-v")) {
            printf("d2kfetch %s\n", D2K_RELEASE_ID);
            return 0;
        }
        else { usage(); return 2; }
    }
    if (!name || !name[0]) { usage(); return 2; }

    if (snap_ms > 0 && snapshot_wire(name, snap_ms, &wire) != 0) {
        return 1;  /* без живой длины мерить браузерным приветствием нечем */
    }
    if (quic && wire == 0) {
        /* У QUIC приветствие живёт внутри Initial-датаграммы (около 1200
           байт вместе с заголовками), и длина от TCP-профиля в неё не
           влезает. Ноль — не добивать: пусть клиент возьмёт свою
           естественную длину. */
    } else if (wire == 0) {
        /* Длина не названа и снимка нет: берём длину приветствия того же
           профиля, которым D2K меряет холодный старт, — это всё ещё
           браузерная форма, но её длина, а не длина чужого браузера. */
        static uint8_t probe[4096];
        size_t n = 0;
        if (d2k_hello_from_profile(tls12 ? D2K_SHAPE_LEGACY : D2K_SHAPE_MODERN,
                                   name, probe, sizeof probe, &n) == 0) {
            wire = n;
        }
        fprintf(stderr, "длина приветствия не задана — беру профильную: %zu байт\n", wire);
    }

    char addr[128];
    if (!ip || !ip[0]) {
        if ((ip && !ip[0]) || resolve_first(name, addr, sizeof addr) != 0) {
            if (json) {
                printf("{\"schema\":2,\"shape\":\"dns_failed\",\"measured\":false,\"name\":");
                json_string(name); printf(",\"ip\":null,\"reason\":\"адрес не разрешился\"}\n");
            } else {
                fprintf(stderr, "имя %s не разрешилось\n", name);
            }
            return 2;
        }
        ip = addr;
    }

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (ladder) {
        /* Та же проба, которой меряет планировщик. Действие --mark зависит
           от правил установленного роутера; непомеченная идёт через планы. */
        d2k_vol_result v = d2k_volume_probe_path(ip, port, name, port == 80,
                                                 tls12, wire, mark,
                                                 (path && path[0] && strcmp(path, "/"))
                                                     ? path : NULL);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        long lms = (t1.tv_sec - t0.tv_sec) * 1000L + (t1.tv_nsec - t0.tv_nsec) / 1000000L;
        if (json) {
            printf("{\"schema\":2,\"shape\":\"ladder\",\"mode\":\"ladder\",\"name\":"); json_string(name);
            printf(",\"ip\":"); json_string(ip);
            printf(",\"port\":%u,\"verdict\":", port); json_string(vol_verdict_code(v.verdict));
            printf(",\"verdict_human\":"); json_string(d2k_vol_verdict_name(v.verdict));
            printf(",\"tx_passed\":%s,\"at_kb\":%d,\"rx_cut\":%s,\"rx_at_kb\":%d,"
                   "\"elapsed_ms\":%ld,\"reason\":",
                   v.verdict == D2K_VOL_PASSED ? "true" : "false",
                   v.at_kb,
                   v.rx_cut ? "true" : "false",
                   v.rx_at_kb,
                   lms);
            json_string(v.reason);
            printf(",\"rx_short\":%s,\"rx_unmeasured\":%s,\"rx_direct_complete\":%s,"
                   "\"rx_tls_unavailable\":%s,\"measured_path\":",
                   v.rx_short ? "true" : "false", v.rx_unmeasured ? "true" : "false",
                   v.rx_direct_complete ? "true" : "false", v.rx_tls_unavailable ? "true" : "false");
            json_string(v.measured_path);
            printf(",\"rx_reason\":"); json_string(v.rx_reason); puts("}");
            if (v.verdict == D2K_VOL_CUT || v.rx_cut) return 1;
            if (v.verdict == D2K_VOL_PASSED && !v.rx_cut) return 0;
            return 2;
        }
        printf("цель:        %s (%s:%u), путь %s\n", name, ip, (unsigned)port, path);
        if (mark) {
            printf("приветствие: %zu байт, %s, метка 0x%x\n", wire,
                   tls12 ? "TLS 1.2" : "TLS 1.3", (unsigned)mark);
        } else {
            printf("приветствие: %zu байт, %s, через планы (как браузер, без метки)\n", wire,
                   tls12 ? "TLS 1.2" : "TLS 1.3");
        }
        printf("лестница:    %s%s\n", d2k_vol_verdict_name(v.verdict),
               v.verdict == D2K_VOL_PASSED ? " (исходящая лестница пройдена)" : "");
        if (v.at_kb) { printf("оборвалась:  около %d КБ\n", v.at_kb); }
        if (v.rx_cut) { printf("вход:        обрыв ответа около %d КБ\n", v.rx_at_kb); }
        printf("время:       %ld мс\n", lms);
        if (v.reason[0]) { printf("причина:     %s\n", v.reason); }
        if (v.verdict == D2K_VOL_CUT || v.rx_cut) return 1;
        if (v.verdict == D2K_VOL_PASSED && !v.rx_cut) return 0;
        return 2;
    }
    /* Без --mark обращение идёт НЕПОМЕЧЕННЫМ, и датапат применяет к нему тот
       же план, что к потоку браузера, — ради этого инструмент и сделан.
       Для голой линии нужен --mark, совпадающий с MEASURE_MARK в правилах
       роутера (штатно 0x2f). Произвольная метка обхода очереди не гарантирует.
       Явный путь проверяется как HTTP request-target; он не становится
       автоматически найденной подсказкой для каталога. */
    const char *req = (path && path[0] && strcmp(path, "/")) ? path : NULL;
    /* Вопрос прибора — «страница целиком?»: тело HTTP/3 читается до FIN в
       рамках срока, а не до предела этапа данных плеча (поле 24.10.2026:
       139 КБ от www.cloudflare.com считались обрывом на 32 КиБ). */
    if (quic) { d2k_verify_quic_read_all_set(1); }
    d2k_ver_result r = quic
        ? d2k_verify_fetch_quic_on(-1, ip, port, name, deadline, wire, mark, req)
        : d2k_verify_fetch_tcp_on(-1, ip, port, name, deadline,
                                   wire, tls12, mark, req);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = (t1.tv_sec - t0.tv_sec) * 1000L + (t1.tv_nsec - t0.tv_nsec) / 1000000L;

    if (json) {
        printf("{\"schema\":2,\"client\":\"d2k-own-profile\",\"name\":");
        json_string(name); printf(",\"shape\":"); json_string(quic ? "quic" : "tcp");
        printf(",\"ip\":"); json_string(ip);
        printf(",\"port\":%u,\"path\":", port); json_string(path);
        printf(",\"protocol\":"); json_string(quic ? "quic" : tls12 ? "tls12" : "tls13");
        /* QUIC app_progress counts the request STREAM, including HTTP/3
           HEADERS and framing. Its verifier currently parses only :status. */
        if (quic) {
            printf(",\"body_bytes\":null,\"quic_stream_bytes\":%llu,"
                   "\"body_expected\":null,\"body_has_length\":null,"
                   "\"headers_inspected\":false,\"location\":null,\"cloudflare_challenge\":null",
                   (unsigned long long)r.body_bytes);
        } else {
            printf(",\"body_bytes\":%llu,\"body_expected\":%llu,\"body_has_length\":%s,"
                   "\"headers_inspected\":true,\"cloudflare_challenge\":%s,\"location\":",
                   (unsigned long long)r.body_bytes, (unsigned long long)r.body_expected,
                   r.body_has_length ? "true" : "false", r.cloudflare_challenge ? "true" : "false");
            json_string(r.location);
        }
        printf(",\"wire_requested\":%zu,\"mark\":%u,\"elapsed_ms\":%ld,\"local_port\":%u,"
               "\"negotiated_tls\":%u,\"http_status\":%d,"
               "\"response_complete\":%s,\"level\":%d,\"local_refusal\":%s,\"measured\":%s,"
               "\"name_ok\":%d",
               wire, mark, ms, (unsigned)r.local_port, (unsigned)r.negotiated_tls, r.status,
               r.body_complete ? "true" : "false", r.level,
               r.local_refusal ? "true" : "false", r.local_refusal ? "false" : "true", r.name_ok);
        printf(",\"reason\":");
        json_string(r.reason); puts("}");
    } else {
        printf("цель:        %s (%s:%u), путь %s\n", name, ip, (unsigned)port, path);
        if (mark) {
            printf("приветствие: %zu байт, %s, метка 0x%x\n", wire,
                   quic ? "QUIC (HTTP/3)" : tls12 ? "TLS 1.2" : "TLS 1.3",
                   (unsigned)mark);
        } else {
            printf("приветствие: %zu байт, %s, через планы (как браузер, без метки)\n", wire,
                   quic ? "QUIC (HTTP/3)" : tls12 ? "TLS 1.2" : "TLS 1.3");
        }
        printf("TLS:         %s\n",
               quic ? (r.level >= D2K_VER_HANDSHAKE ? "QUIC (TLS 1.3)" : "рукопожатия нет") :
               r.negotiated_tls == 0x0304 ? "1.3" :
               r.negotiated_tls == 0x0303 ? "1.2" : "рукопожатия нет");
        printf("HTTP:        %d\n", r.status);
        if (quic) {
            printf("поток H3:    %llu байт, включая заголовки и обрамление; тело отдельно не измерено\n",
                   (unsigned long long)r.body_bytes);
        } else if (r.body_has_length || r.body_chunked || r.body_bytes) {
            printf("тело:        %llu из %llu байт%s%s\n",
                   (unsigned long long)r.body_bytes,
                   (unsigned long long)r.body_expected,
                   r.body_chunked ? " (chunked)" : "",
                   r.body_encoding == 1 ? ", gzip" : "");
        }
        printf("итог:        %s\n",
               r.local_refusal ? "НЕ ИЗМЕРЕНО: локальный отказ"
               : r.body_complete ? "ОТВЕТ ПОЛУЧЕН ЦЕЛИКОМ"
               : r.status      ? "ОБРЫВ: ответ начался и не доехал"
                               : "ОБРЫВ: ответа нет");
        printf("время:       %ld мс, местный порт %u\n", ms, (unsigned)r.local_port);
        if (r.reason[0]) { printf("причина:     %s\n", r.reason); }
    }
    d2k_verify_close(&r);
    /* 0 — ответ целиком; 2 — локальный отказ (не измерено); 1 — оборвано */
    if (r.local_refusal) { return 2; }
    return r.body_complete ? 0 : 1;
}
