/* trigger.c — чем мерим. Перенос internal/classify/trigger.go эталона.
 *
 * ОДНО РАСХОЖДЕНИЕ С ЭТАЛОНОМ, И ОНО НАМЕРЕННОЕ. Там приветствие берётся у
 * crypto/tls: поднимают клиента над трубой и забирают первую запись. Здесь
 * взять его негде и незачем — у d2k уже есть профили, СНЯТЫЕ С ЖИВОГО
 * БРАУЗЕРА (core/profiles/ — файлы .hex, см. их шапки и d2k_hello.h). Форма
 * приветствия и есть измерительный инструмент: DPI решает по ней, и
 * самодельное приветствие мерило бы не ту коробку, что видит браузер.
 *
 * Поэтому сверять алгоритм с эталоном на СВОИХ приветствиях нельзя: байты
 * разные, и расхождение вердикта ничего не докажет. Сверка идёт на общем
 * триггере, заданном шестнадцатеричной строкой обоим инструментам
 * (-raw у эталона, --raw здесь) — см. tests/compare.sh.
 */
#include "d2k_detect.h"
#include "d2k_hello.h"

#include <stdio.h>
#include <string.h>

int d2k_trigger_tls(const char *sni, int legacy, d2k_trigger *out, char *err, size_t errcap)
{
    size_t n = 0, off = 0, slen = 0;

    memset(out, 0, sizeof(*out));
    if (!sni || sni[0] == '\0') {
        snprintf(err, errcap, "classify: пустой SNI");
        return -1;
    }
    if (d2k_hello_from_profile(legacy ? D2K_SHAPE_LEGACY : D2K_SHAPE_MODERN,
                               sni, out->payload, sizeof(out->payload), &n) != 0) {
        snprintf(err, errcap, "classify: приветствие для «%s» не собралось", sni);
        return -1;
    }
    if (n < 16) {
        snprintf(err, errcap, "classify: ClientHello вышел длиной %d байт", (int)n);
        return -1;
    }
    out->len = n;
    snprintf(out->name, sizeof(out->name), "tls:%s", sni);
    out->accept = D2K_ACCEPT_SERVERHELLO;
    /* Запоминаем, где в приветствии лежит имя: по нему режут, а не по
     * середине пакета. Координатами из разбора, а не поиском подстроки —
     * подстрока может случайно встретиться в шифре или в случайных полях. */
    if (d2k_hello_sni(out->payload, n, &off, &slen) == 0) {
        out->sni_off = (int)off;
        out->sni_len = (int)slen;
    }
    return 0;
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
    return -1;
}

/* RawTrigger — произвольные байты, заданные шестнадцатеричной строкой.
 *
 * Нужен для протоколов, у которых нет ни TLS, ни имени хоста в пакете: пролог
 * WhatsApp ("WA\x06\x03" плюс рукопожатие Noise) снимается из дампа и подаётся
 * сюда как есть. Доказательством прохода тогда считается любой непустой ответ:
 * разбирать чужой протокол ради вердикта незачем, важно лишь, ответил сервер
 * или промолчал. */
int d2k_trigger_raw_hex(const char *hex, d2k_trigger *out, char *err, size_t errcap)
{
    size_t n = 0;
    int hi = -1;

    memset(out, 0, sizeof(*out));
    for (; *hex; hex++) {
        int v;
        if (*hex == ' ' || *hex == '\t' || *hex == '\n' || *hex == '\r' ||
            *hex == ':' || *hex == '-') {
            continue;
        }
        v = hexval((unsigned char)*hex);
        if (v < 0) {
            snprintf(err, errcap, "classify: триггер не разобран как hex");
            return -1;
        }
        if (hi < 0) {
            hi = v;
        } else {
            if (n >= sizeof(out->payload)) {
                snprintf(err, errcap, "classify: триггер длиннее %d байт",
                         (int)sizeof(out->payload));
                return -1;
            }
            out->payload[n++] = (uint8_t)((hi << 4) | v);
            hi = -1;
        }
    }
    if (hi >= 0) {
        snprintf(err, errcap, "classify: триггер не разобран как hex");
        return -1;
    }
    if (n < 2) {
        snprintf(err, errcap, "classify: триггер короче двух байт");
        return -1;
    }
    out->len = n;
    snprintf(out->name, sizeof(out->name), "raw:%dB", (int)n);
    out->accept = D2K_ACCEPT_ANY;
    return 0;
}

/* ControlTrigger — заведомо безобидное приветствие на ту же цель.
 *
 * Имя намеренно случайное и явно не из блок-листов: нам не нужен успешный
 * сеанс, нужен ФАКТ, что наши байты дошли до TLS-сервера и он на них
 * отреагировал. Поэтому доказательством прохода тут считается ЛЮБАЯ запись
 * TLS, включая алерт: сервер, отвечающий отказом на незнакомое имя, — это всё
 * равно сервер, до которого дошли. А вот тишина означает, что до него не
 * дошло ничего, и тогда дело не в содержимом. */
int d2k_trigger_control(const char *tag, d2k_trigger *out, char *err, size_t errcap)
{
    char name[128];
    snprintf(name, sizeof(name), "probe-%s.invalid-control.example", tag);
    if (d2k_trigger_tls(name, 0, out, err, errcap) != 0) {
        return -1;
    }
    snprintf(out->name, sizeof(out->name), "control");
    out->accept = D2K_ACCEPT_TLSRECORD;
    return 0;
}

const d2k_trigger *d2k_opts_decoy(const d2k_opts *o)
{
    if (!o) {
        return NULL;
    }
    return o->decoy.len >= 2 ? &o->decoy : &o->control;
}

/* --- клиентский профиль TCP (замысел 2026-10-23, п. 5.1) ------------------ */
/* СПОСОБНОСТЬ ЛОКАЛЬНОГО СТЕКА ПРЕДЛАГАТЬ МЕТКУ ВРЕМЕНИ.
 *
 * Нужна там, где набор опций клиента не снят. Прежде в этом случае отвечали
 * «метка есть» — догадка, и поле 23.10.2026 показало её цену: на роутере с
 * выключенной меткой составной вопрос семейства C по `rutracker.org` прошёл
 * 2/2, план из него построился, и датапат отверг его причиной 6 — потому что
 * ИСПЫТАТЕЛЬНЫЙ ПОТОК ЗОНДА идёт обычным сокетом локального стека и метки не
 * несёт. Цель осталась без планов вовсе: «выведенные планы исчерпаны».
 *
 * Значит при неизвестном клиенте отвечать должен тот, кто и пойдёт на провод,
 * — локальный стек. На роутере с включённой меткой (обычный случай) ответ тот
 * же, что прежде, поэтому поведение поля не меняется.
 *
 * Читается один раз на процесс: значение sysctl за время поиска не меняется, а
 * чтение файла на каждый вопрос — лишняя работа в горячем пути. */
static int host_ts_override = -1;

void d2k_trigger_host_ts_override(int v) { host_ts_override = v; }

static int host_offers_ts(void)
{
    if (host_ts_override >= 0) {
        return host_ts_override ? 1 : 0;
    }
    static int cached = -1;
    if (cached >= 0) {
        return cached;
    }
    cached = 1; /* файла нет (не Linux) — прежнее поведение */
    FILE *f = fopen("/proc/sys/net/ipv4/tcp_timestamps", "r");
    if (f) {
        int v = 1;
        if (fscanf(f, "%d", &v) == 1) {
            /* 0 — выключена; 1 — включена; 2 — включена со случайным смещением */
            cached = v != 0;
        }
        fclose(f);
    }
    return cached;
}

int d2k_trigger_offers_ts(const d2k_trigger *t)
{
    if (!t || !t->client_tcp_known) {
        return host_offers_ts();
    }
    const uint8_t *o = t->client_tcp_options;
    size_t n = t->client_tcp_options_len;
    if (n > sizeof t->client_tcp_options) {
        return 0;
    }
    for (size_t off = 0; off < n;) {
        uint8_t kind = o[off];
        if (kind == 0) { break; }
        if (kind == 1) { off++; continue; }
        if (off + 2 > n || o[off + 1] < 2 || o[off + 1] > n - off) { return 0; }
        if (kind == 8 && o[off + 1] == 10) { return 1; }
        off += o[off + 1];
    }
    return 0;
}

int d2k_trigger_allows_poison(const d2k_trigger *t, const d2k_poison *p)
{
    if (!p) {
        return 0;
    }
    return !(p->tcp_ts || p->md5_ts) || d2k_trigger_offers_ts(t);
}
