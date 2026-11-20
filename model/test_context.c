#include "d2km_context.h"
#include "test.h"
#include <string.h>

static void ctx(d2km_context *c, const char *name)
{
    memset(c, 0, sizeof(*c));
    CHECK(d2km_target_name(&c->target, name) == 0);
    c->transport = D2KM_TCP;
    c->protocol = D2KM_P_TLS13;
    c->family = D2KM_IPV4;
    static const uint8_t hello[10] = {0x16, 3, 1, 0, 5, 1, 2, 3, 4, 5};
    static const uint16_t seg[2] = {4, 6};
    static const uint8_t opts[3] = {2, 4, 8};
    CHECK(d2km_form_set(&c->form, hello, sizeof(hello), seg, 2, opts, 3, 0, 1) == 0);
    strcpy(c->path.ifname, "ppp0");
    c->path.mtu = 1500;
}

int main(void)
{
    d2km_target t;
    CHECK(d2km_target_name(&t, "WWW.Example.COM.") == 0);
    CHECK(t.has_name && strcmp(t.name, "www.example.com") == 0);
    CHECK(d2km_target_name(&t, "") == -1);
    CHECK(d2km_target_name(&t, ".") == -1);
    CHECK(d2km_target_name(&t, "a..b") == -1);
    CHECK(d2km_target_name(&t, "bad name") == -1);
    char lab[70];
    memset(lab, 'a', 64); lab[64] = 0;
    CHECK(d2km_target_name(&t, lab) == -1);
    lab[63] = 0;
    CHECK(d2km_target_name(&t, lab) == 0);

    uint8_t a4[4] = {1, 2, 3, 4};
    CHECK(d2km_target_address(&t, D2KM_IPV4, a4, 443) == 0);
    CHECK(!t.has_name && t.port == 443 && t.addr[3] == 4 && t.addr[4] == 0);
    CHECK(d2km_target_address(&t, D2KM_IPV4, a4, 0) == -1);

    /* Суффикс — только на границе метки (§4.5). */
    CHECK(d2km_name_suffix_match("x.cloudflare-gateway.com", "cloudflare-gateway.com"));
    CHECK(d2km_name_suffix_match("cloudflare-gateway.com", "cloudflare-gateway.com"));
    CHECK(!d2km_name_suffix_match("evilcloudflare-gateway.com", "cloudflare-gateway.com"));
    CHECK(!d2km_name_suffix_match("com", "cloudflare-gateway.com"));
    CHECK(!d2km_name_suffix_match("a.com", ""));

    /* Сегментация обязана покрывать байты приветствия. */
    d2km_form f;
    const uint8_t h[4] = {1, 2, 3, 4};
    const uint16_t bad[2] = {1, 2};
    CHECK(d2km_form_set(&f, h, 4, bad, 2, NULL, 0, 0, 0) == -1);
    const uint16_t zero[2] = {4, 0};
    CHECK(d2km_form_set(&f, h, 4, zero, 2, NULL, 0, 0, 0) == -1);

    d2km_context a, b;
    ctx(&a, "example.com");
    ctx(&b, "example.com");
    CHECK(d2km_context_valid(&a) == 0);
    CHECK(d2km_context_diff(&a, &b) == 0);
    CHECK(d2km_context_compatible(&a, &b, 0));

    /* Протокол и транспорт согласованы. */
    b.protocol = D2KM_P_QUIC1;
    CHECK(d2km_context_valid(&b) == -1);
    b.transport = D2KM_UDP;
    CHECK(d2km_context_valid(&b) == -1);   /* опции TCP у UDP */
    b.form.tcp_options_length = 0;
    CHECK(d2km_context_valid(&b) == 0);
    CHECK(d2km_context_diff(&a, &b) & D2KM_CTX_OTHER);
    CHECK(!d2km_context_compatible(&a, &b, D2KM_FORM_ALL));

    /* Совместимость: различие только в нечитаемых полях формы. */
    ctx(&b, "example.com");
    b.form.grease = 0;
    CHECK(d2km_context_diff(&a, &b) == D2KM_FORM_GREASE);
    CHECK(!d2km_context_compatible(&a, &b, 0));
    CHECK(d2km_context_compatible(&a, &b, D2KM_FORM_GREASE));
    CHECK(!d2km_context_compatible(&a, &b, D2KM_FORM_ECH));
    /* Маска не открывает поля вне формы. */
    ctx(&b, "other.com");
    CHECK(!d2km_context_compatible(&a, &b, 0xffffffffu));
    ctx(&b, "example.com");
    b.path.mtu = 1280;
    CHECK(!d2km_context_compatible(&a, &b, D2KM_FORM_ALL));

    /* Адресная цель: семейство цели совпадает с контекстом. */
    ctx(&b, "example.com");
    CHECK(d2km_target_address(&b.target, D2KM_IPV6, (const uint8_t *)"0123456789abcdef", 443) == 0);
    CHECK(d2km_context_valid(&b) == -1);
    b.family = D2KM_IPV6;
    CHECK(d2km_context_valid(&b) == 0);

    /* Каноническая запись: равные контексты — равные байты, мусор в
     * неиспользуемых полях не влияет; отсечка по cap не пишет лишнего. */
    ctx(&a, "example.com");
    ctx(&b, "example.com");
    b.form.segments[10] = 777;          /* за пределами segment_count */
    b.path.ifname[10] = 'x';            /* после завершающего нуля */
    uint8_t ea[256], eb[256];
    size_t na = d2km_context_encode(&a, ea, sizeof(ea));
    size_t nb = d2km_context_encode(&b, eb, sizeof(eb));
    CHECK(na == nb && na < sizeof(ea) && memcmp(ea, eb, na) == 0);
    uint8_t small[8];
    memset(small, 0xee, sizeof(small));
    CHECK(d2km_context_encode(&a, small, 4) == na);
    CHECK(small[4] == 0xee);
    CHECK(d2km_context_encode(&a, NULL, 0) == na);
    b.form.ech = 1;
    nb = d2km_context_encode(&b, eb, sizeof(eb));
    CHECK(nb == na && memcmp(ea, eb, na) != 0);
    DONE("test_context");
}
