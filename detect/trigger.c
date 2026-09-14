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
