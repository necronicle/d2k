#include "d2km_tls.h"
#include "test.h"
#include <string.h>

/* Приветствие собирается в тесте по грамматике: сервер и форма клиента
 * здесь — данные теста, в продукте форма берётся у клиента. */
static size_t w16(uint8_t *p, size_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; return 2; }

static size_t ext(uint8_t *p, uint16_t type, const uint8_t *d, size_t n)
{
    w16(p, type); w16(p + 2, n); memcpy(p + 4, d, n); return 4 + n;
}

static size_t client_hello(uint8_t *out, const char *sni, int with_psk)
{
    uint8_t e[1024]; size_t el = 0;
    uint8_t d[512]; size_t n = strlen(sni);
    w16(d, n + 3); d[2] = 0; w16(d + 3, n); memcpy(d + 5, sni, n);
    el += ext(e + el, 0, d, n + 5);                         /* server_name */
    uint8_t sv[] = {4, 0x03, 0x04, 0x03, 0x03};
    el += ext(e + el, 43, sv, sizeof(sv));                  /* supported_versions */
    uint8_t ks[2 + 4 + 32]; w16(ks, 36); w16(ks + 2, 0x001d); w16(ks + 4, 32);
    memset(ks + 6, 0xAB, 32);
    el += ext(e + el, 51, ks, sizeof(ks));                  /* key_share x25519 */
    if (with_psk) {
        uint8_t psk[] = {0, 6, 0, 1, 7, 0, 0, 0, 0, 0};
        el += ext(e + el, 41, psk, sizeof(psk));
    }
    uint8_t body[2048]; size_t b = 0;
    b += w16(body + b, 0x0303);
    memset(body + b, 0x11, 32); b += 32;
    body[b++] = 32; memset(body + b, 0x22, 32); b += 32;
    b += w16(body + b, 4); b += w16(body + b, 0x1301); b += w16(body + b, 0x1302);
    body[b++] = 1; body[b++] = 0;
    b += w16(body + b, el); memcpy(body + b, e, el); b += el;
    out[0] = 0x16; w16(out + 1, 0x0301); w16(out + 3, b + 4);
    out[5] = 1; out[6] = 0; w16(out + 7, b);
    memcpy(out + 9, body, b);
    return 9 + b;
}

int main(void)
{
    uint8_t in[2048], out[20000];
    size_t n = client_hello(in, "example.com", 0);
    static d2km_tls_hello h, h2;
    CHECK(d2km_tls_parse(in, n, &h) == D2KM_TLS_OK);
    CHECK(h.ext_count == 3 && h.session_id_length == 32 && h.ciphers_length == 4);
    char name[300];
    CHECK(d2km_tls_sni(&h, name, sizeof(name)) == D2KM_TLS_OK && strcmp(name, "example.com") == 0);

    /* Сборка без изменений — те же байты. */
    size_t m = d2km_tls_build(&h, out, sizeof(out));
    CHECK(m == n && memcmp(in, out, n) == 0);
    CHECK(d2km_tls_build(&h, out, n - 1) == 0);

    /* Неполные и чужие данные. */
    CHECK(d2km_tls_parse(in, 4, &h2) == D2KM_TLS_SHORT);
    CHECK(d2km_tls_parse(in, n - 1, &h2) == D2KM_TLS_SHORT);
    uint8_t bad[2048];
    memcpy(bad, in, n); bad[0] = 0x17;
    CHECK(d2km_tls_parse(bad, n, &h2) == D2KM_TLS_NOT_HELLO);
    memcpy(bad, in, n); bad[8] ^= 1;
    CHECK(d2km_tls_parse(bad, n, &h2) == D2KM_TLS_MALFORMED);
    memcpy(bad, in, n); bad[43] = 33;   /* session_id длиннее 32 */
    CHECK(d2km_tls_parse(bad, n, &h2) == D2KM_TLS_MALFORMED);
    /* Повтор расширения запрещён грамматикой. */
    h2 = h;
    uint8_t one[1] = {0};
    CHECK(d2km_tls_put_ext(&h2, 0xff01, one, 1) == D2KM_TLS_OK);
    m = d2km_tls_build(&h2, out, sizeof(out));
    size_t last = m - 5;   /* тип последнего расширения */
    out[last] = 0x00; out[last + 1] = 0x2b;
    CHECK(d2km_tls_parse(out, m, &h2) == D2KM_TLS_MALFORMED);

    /* Смена имени: длины пересчитаны, разбор обратно сходится. */
    h2 = h;
    CHECK(d2km_tls_set_sni(&h2, "a-much-longer-name.example.org") == D2KM_TLS_OK);
    m = d2km_tls_build(&h2, out, sizeof(out));
    CHECK(m == n + 19);
    static d2km_tls_hello back;
    CHECK(d2km_tls_parse(out, m, &back) == D2KM_TLS_OK);
    CHECK(d2km_tls_sni(&back, name, sizeof(name)) == D2KM_TLS_OK &&
          strcmp(name, "a-much-longer-name.example.org") == 0);
    CHECK(back.ext[0].type == 0 && back.ext_count == 3);   /* порядок сохранён */
    CHECK(d2km_tls_set_sni(&h2, "") == D2KM_TLS_MALFORMED);

    /* Удаление и добавление; добавленное — перед pre_shared_key. */
    h2 = h;
    CHECK(d2km_tls_drop_ext(&h2, 0) == D2KM_TLS_OK);
    CHECK(d2km_tls_sni(&h2, name, sizeof(name)) == D2KM_TLS_ABSENT);
    CHECK(d2km_tls_drop_ext(&h2, 0) == D2KM_TLS_ABSENT);
    CHECK(d2km_tls_set_sni(&h2, "x.com") == D2KM_TLS_ABSENT);
    size_t np = client_hello(in, "example.com", 1);
    CHECK(d2km_tls_parse(in, np, &h2) == D2KM_TLS_OK);
    uint8_t alpn[] = {0, 3, 2, 'h', '2'};
    CHECK(d2km_tls_put_ext(&h2, 16, alpn, sizeof(alpn)) == D2KM_TLS_OK);
    CHECK(h2.ext[h2.ext_count - 1].type == 41 && h2.ext[h2.ext_count - 2].type == 16);
    /* Замена существующего — на месте, без дубля, и для pre_shared_key тоже. */
    CHECK(d2km_tls_put_ext(&h2, 41, alpn, sizeof(alpn)) == D2KM_TLS_OK);
    size_t c41 = 0;
    for (size_t i = 0; i < h2.ext_count; i++) c41 += h2.ext[i].type == 41;
    CHECK(c41 == 1 && h2.ext[h2.ext_count - 1].type == 41);
    m = d2km_tls_build(&h2, out, sizeof(out));
    CHECK(d2km_tls_parse(out, m, &back) == D2KM_TLS_OK);

    /* padding до заданной длины всей записи. */
    h2 = h;
    CHECK(d2km_tls_pad_to(&h2, 517) == D2KM_TLS_OK);
    CHECK(d2km_tls_build(&h2, out, sizeof(out)) == 517);
    CHECK(d2km_tls_parse(out, 517, &back) == D2KM_TLS_OK);
    CHECK(d2km_tls_pad_to(&h2, 600) == D2KM_TLS_OK);   /* старый padding заменён */
    CHECK(d2km_tls_build(&h2, out, sizeof(out)) == 600);
    CHECK(d2km_tls_pad_to(&h2, n + 2) == D2KM_TLS_ABSENT);  /* меньше, чем стоит расширение */
    CHECK(d2km_tls_pad_to(&h2, 20000) == D2KM_TLS_TOO_BIG);

    /* Обновление полей нового соединения: воспроизводимо по зерну. */
    d2km_rng r1, r2;
    d2km_rng_seed(&r1, 42); d2km_rng_seed(&r2, 42);
    h2 = h; back = h;
    CHECK(d2km_tls_refresh(&h2, &r1) == D2KM_TLS_OK);
    CHECK(d2km_tls_refresh(&back, &r2) == D2KM_TLS_OK);
    CHECK(memcmp(h2.random, back.random, 32) == 0 && memcmp(h2.random, h.random, 32) != 0);
    CHECK(memcmp(h2.session_id, h.session_id, 32) != 0);
    CHECK(memcmp(h2.arena + h2.ext[2].offset + 6, h.arena + h.ext[2].offset + 6, 32) != 0);
    CHECK(h2.ext[2].length == h.ext[2].length);
    d2km_rng_seed(&r1, 43);
    back = h;
    d2km_tls_refresh(&back, &r1);
    CHECK(memcmp(h2.random, back.random, 32) != 0);
    /* Имя и форма при обновлении не меняются. */
    CHECK(d2km_tls_build(&h2, out, sizeof(out)) == n);
    CHECK(d2km_tls_sni(&h2, name, sizeof(name)) == D2KM_TLS_OK && strcmp(name, "example.com") == 0);

    /* Границы полей и место имени в собранной записи. */
    uint32_t so, sl, bounds[80];
    CHECK(d2km_tls_sni_span(&h, &so, &sl) == D2KM_TLS_OK && sl == 11);
    d2km_tls_build(&h, out, sizeof(out));
    CHECK(memcmp(out + so, "example.com", 11) == 0);
    size_t k = d2km_tls_bounds(&h, bounds, 80);
    CHECK(k == 7 + 3 + 2);
    CHECK(bounds[0] == 5 && bounds[2] == 11 && bounds[k - 2] == so && bounds[k - 1] == so + 11);
    DONE("test_tls");
}
