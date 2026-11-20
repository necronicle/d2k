/* Разбор :status в HPACK для прикладной проверки HTTP/2 (без сети).
 * Блок rutracker.org снят с живого ответа: литерал без индексации с именем
 * из статической таблицы под индексом 14 и значением в коде Хаффмана. */
#include "appget.c"
#include <stdio.h>

/* Сессия TLS здесь не нужна: функции разбора её не трогают. */
long d2k_tls_read(d2k_tls *t, uint8_t *b, size_t c, int w, char *e, size_t ec) { (void)t; (void)b; (void)c; (void)w; (void)e; (void)ec; return -1; }
int d2k_tls_write(d2k_tls *t, const uint8_t *b, size_t n, char *e, size_t ec) { (void)t; (void)b; (void)n; (void)e; (void)ec; return -1; }
const char *d2k_tls_alpn(const d2k_tls *t) { (void)t; return ""; }

static int fails;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static int status_of(const uint8_t *b, size_t n)
{
    int s = 0;
    return hp_status(b, n, &s) == 0 ? s : -1;
}

int main(void)
{
    const uint8_t rutracker[] = {0x20, 0x0e, 0x82, 0x64, 0x01};
    CHECK(status_of(rutracker, sizeof rutracker) == 301);
    const uint8_t indexed200[] = {0x88};
    CHECK(status_of(indexed200, 1) == 200);
    const uint8_t indexed404[] = {0x8d};
    CHECK(status_of(indexed404, 1) == 404);
    const uint8_t literal302[] = {0x48, 0x03, '3', '0', '2'};   /* с индексацией, имя 8 */
    CHECK(status_of(literal302, sizeof literal302) == 302);
    const uint8_t named[] = {0x00, 0x07, ':', 's', 't', 'a', 't', 'u', 's', 0x03, '4', '5', '1'};
    CHECK(status_of(named, sizeof named) == 451);
    /* Прочие поля (в том числе ссылки на динамическую таблицу) статус не задают. */
    const uint8_t other[] = {0xbe, 0x0f, 0x10, 0x03, 'a', 'b', 'c'};
    CHECK(status_of(other, sizeof other) == 0);
    const uint8_t bad[] = {0x0e, 0x05, '2', '0'};
    CHECK(status_of(bad, sizeof bad) == -1);
    const uint8_t badnum[] = {0x08, 0x03, '9', '9', '9'};
    CHECK(status_of(badnum, sizeof badnum) == -1);
    /* Неполный ответ без сессии — локальный отказ, не «обход». */
    d2k_app_result r;
    d2k_app_get(NULL, "a.example", "/", 10, &r);
    CHECK(r.state == D2K_APP_LOCAL);
    if (fails) return 1;
    puts("HTTP/2 :status decoding PASS");
    return 0;
}
