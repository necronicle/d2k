#include "d2km_check.h"
#include "test.h"
#include <string.h>

#define S(x) (const uint8_t *)(x), strlen(x)

int main(void)
{
    d2km_http_response r, ref;
    /* Content-Length: полный, неполный, оборванный. */
    const char *ok = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX: y\r\n\r\nhello";
    CHECK(d2km_http1_response(S(ok), 0, &r) == D2KM_HTTP_COMPLETE);
    CHECK(r.status == 200 && r.body_bytes == 5 && r.message_bytes == strlen(ok));
    CHECK(d2km_http1_response((const uint8_t *)ok, strlen(ok) - 2, 0, &r) == D2KM_HTTP_INCOMPLETE);
    CHECK(d2km_http1_response((const uint8_t *)ok, strlen(ok) - 2, 1, &r) == D2KM_HTTP_CUT);
    CHECK(r.body_bytes == 3);
    CHECK(d2km_http1_response((const uint8_t *)ok, 20, 0, &r) == D2KM_HTTP_INCOMPLETE);
    CHECK(d2km_http1_response((const uint8_t *)ok, 20, 1, &r) == D2KM_HTTP_CUT);
    /* Лишние байты после тела (keep-alive) не мешают. */
    const char *two = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhiHTTP/1.1 ...";
    CHECK(d2km_http1_response(S(two), 0, &r) == D2KM_HTTP_COMPLETE && r.message_bytes == 40);

    /* chunked с расширением и трейлером; регистр имён заголовков. */
    const char *ch = "HTTP/1.1 200 OK\r\ntransfer-encoding: gzip, Chunked\r\n\r\n"
                     "4;x=1\r\nWiki\r\n5\r\npedia\r\n0\r\nT: v\r\n\r\n";
    CHECK(d2km_http1_response(S(ch), 0, &r) == D2KM_HTTP_COMPLETE);
    CHECK(r.chunked && r.body_bytes == 9 && r.message_bytes == strlen(ch));
    for (size_t cut = 60; cut < strlen(ch); cut++) {
        CHECK(d2km_http1_response((const uint8_t *)ch, cut, 0, &r) == D2KM_HTTP_INCOMPLETE);
        CHECK(d2km_http1_response((const uint8_t *)ch, cut, 1, &r) == D2KM_HTTP_CUT);
    }
    const char *badch = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n";
    CHECK(d2km_http1_response(S(badch), 0, &r) == D2KM_HTTP_MALFORMED);
    const char *badcrlf = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nabXY0\r\n\r\n";
    CHECK(d2km_http1_response(S(badcrlf), 0, &r) == D2KM_HTTP_MALFORMED);

    /* Тело до закрытия; 204/304 без тела; 1xx пропускается. */
    const char *eof = "HTTP/1.0 200 OK\r\n\r\nabc";
    CHECK(d2km_http1_response(S(eof), 0, &r) == D2KM_HTTP_INCOMPLETE);
    CHECK(d2km_http1_response(S(eof), 1, &r) == D2KM_HTTP_COMPLETE && r.body_bytes == 3);
    CHECK(d2km_http1_response(S("HTTP/1.1 204 No Content\r\n\r\n"), 0, &r) == D2KM_HTTP_COMPLETE);
    const char *cont = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx";
    CHECK(d2km_http1_response(S(cont), 0, &r) == D2KM_HTTP_COMPLETE && r.status == 200);

    /* Не HTTP и неоднозначные длины. */
    CHECK(d2km_http1_response(S("\x16\x03\x01\x00\x05hello"), 0, &r) == D2KM_HTTP_MALFORMED);
    CHECK(d2km_http1_response(S("HTTP/1.1 2x0 OK\r\n\r\n"), 0, &r) == D2KM_HTTP_MALFORMED);
    CHECK(d2km_http1_response(S("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxx"), 0, &r)
          == D2KM_HTTP_MALFORMED);
    CHECK(d2km_http1_response(S("HTTP/1.1 200 OK\r\nContent-Length: 1x\r\n\r\nx"), 0, &r) == D2KM_HTTP_MALFORMED);
    CHECK(d2km_http1_response(S("HTTP/1.1 200 OK\r\nbroken line\r\n\r\n"), 0, &r) == D2KM_HTTP_MALFORMED);
    CHECK(d2km_http1_response(S("HTT"), 0, &r) == D2KM_HTTP_INCOMPLETE);
    CHECK(d2km_http1_response(NULL, 0, 1, &r) == D2KM_HTTP_CUT);

    /* §9.2: подмена по статусу и хосту Location. */
    const char *real = "HTTP/1.1 302 Found\r\nLocation: https://Example.com:443/a?x=1\r\nContent-Length: 0\r\n\r\n";
    const char *same = "HTTP/1.1 302 Found\r\nLocation: https://example.com/b?x=2\r\nContent-Length: 0\r\n\r\n";
    const char *portal = "HTTP/1.1 302 Found\r\nLocation: http://warning.rt.ru/?id=1\r\nContent-Length: 0\r\n\r\n";
    d2km_http1_response(S(real), 0, &ref);
    d2km_http1_response(S(same), 0, &r);
    CHECK(!d2km_http_spoofed(&r, &ref));
    d2km_http1_response(S(portal), 0, &r);
    CHECK(d2km_http_spoofed(&r, &ref));
    d2km_http1_response(S(ok), 0, &r);
    CHECK(d2km_http_spoofed(&r, &ref));
    d2km_http_response ok2;
    d2km_http1_response(S(ok), 0, &ok2);
    CHECK(!d2km_http_spoofed(&r, &ok2));
    const char *rel1 = "HTTP/1.1 301 M\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n";
    const char *rel2 = "HTTP/1.1 301 M\r\nLocation: /other\r\nContent-Length: 0\r\n\r\n";
    const char *pr = "HTTP/1.1 301 M\r\nLocation: //evil.example/x\r\nContent-Length: 0\r\n\r\n";
    d2km_http1_response(S(rel1), 0, &r);
    d2km_http1_response(S(rel2), 0, &ref);
    CHECK(!d2km_http_spoofed(&r, &ref));
    d2km_http1_response(S(pr), 0, &r);
    CHECK(d2km_http_spoofed(&r, &ref));

    /* Объём: полный ответ больше порога. */
    d2km_http_state st = d2km_http1_response(S(ok), 0, &r);
    CHECK(d2km_volume_success(&r, st, 10));
    CHECK(!d2km_volume_success(&r, st, (uint64_t)strlen(ok)));
    CHECK(!d2km_volume_success(&r, D2KM_HTTP_CUT, 10));

    /* §9.5: DNS-ответ. */
    uint8_t q[] = {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
                   7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1};
    uint8_t a[sizeof(q) + 16];
    memcpy(a, q, sizeof(q));
    a[2] = 0x81; a[3] = 0x80; a[7] = 1;
    a[13] = 'E';   /* регистр имени не важен */
    memcpy(a + sizeof(q), "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04", 16);
    CHECK(d2km_dns_reply_valid(q, sizeof(q), a, sizeof(a)));
    a[3] = 0x83;   /* NXDOMAIN — правильный ответ */
    CHECK(d2km_dns_reply_valid(q, sizeof(q), a, sizeof(a)));
    a[3] = 0x82;   /* SERVFAIL — нет */
    CHECK(!d2km_dns_reply_valid(q, sizeof(q), a, sizeof(a)));
    a[3] = 0x80; a[1] = 0x35;
    CHECK(!d2km_dns_reply_valid(q, sizeof(q), a, sizeof(a)));
    a[1] = 0x34; a[2] = 0x01;   /* QR = 0 */
    CHECK(!d2km_dns_reply_valid(q, sizeof(q), a, sizeof(a)));
    a[2] = 0x81; a[sizeof(q) - 3] = 28;   /* другой тип */
    CHECK(!d2km_dns_reply_valid(q, sizeof(q), a, sizeof(a)));
    a[sizeof(q) - 3] = 1; a[14] = 'y';
    CHECK(!d2km_dns_reply_valid(q, sizeof(q), a, sizeof(a)));
    a[14] = 'x';
    CHECK(d2km_dns_reply_valid(q, sizeof(q), a, sizeof(a)));
    CHECK(!d2km_dns_reply_valid(q, sizeof(q), a, 20));   /* обрезан */

    /* DoH: долгая сессия. */
    d2km_dns_session s = {20, 1000, 31000, 0, 0};
    CHECK(d2km_dns_session_judge(&s) == D2KM_DNS_SESSION_SUCCESS);
    s.valid_replies = 19;
    CHECK(d2km_dns_session_judge(&s) == D2KM_DNS_SESSION_PARTIAL);
    s.valid_replies = 40; s.last_reply_ms = 30999;
    CHECK(d2km_dns_session_judge(&s) == D2KM_DNS_SESSION_PARTIAL);
    s.unanswered_while_open = 1;
    CHECK(d2km_dns_session_judge(&s) == D2KM_DNS_SESSION_CUT);
    s.unanswered_while_open = 0; s.closed_by_protocol = 1;
    CHECK(d2km_dns_session_judge(&s) == D2KM_DNS_SESSION_PARTIAL);   /* GOAWAY — не обрыв */

    /* §9.7: STUN. */
    uint8_t sq[20] = {0x00, 0x01, 0, 0, 0x21, 0x12, 0xA4, 0x42, 1,2,3,4,5,6,7,8,9,10,11,12};
    uint8_t sr[32] = {0x01, 0x01, 0, 12, 0x21, 0x12, 0xA4, 0x42, 1,2,3,4,5,6,7,8,9,10,11,12,
                      0x00, 0x20, 0, 8, 0, 1, 0x11, 0x22, 1, 2, 3, 4};
    CHECK(d2km_stun_binding_success(sq, 20, sr, 32));
    sr[19] = 99;
    CHECK(!d2km_stun_binding_success(sq, 20, sr, 32));
    sr[19] = 12; sr[3] = 16;
    CHECK(!d2km_stun_binding_success(sq, 20, sr, 32));
    sr[3] = 12; sr[21] = 0x22;   /* нет адреса */
    CHECK(!d2km_stun_binding_success(sq, 20, sr, 32));
    sr[21] = 0x01; sr[1] = 0x11;  /* Binding Error */
    CHECK(!d2km_stun_binding_success(sq, 20, sr, 32));
    sr[1] = 0x01; sr[23] = 200;   /* атрибут длиннее сообщения */
    CHECK(!d2km_stun_binding_success(sq, 20, sr, 32));

    /* §9.3: без рукопожатия и полного ответа — не успех. */
    CHECK(d2km_h3_level(0, 1) == D2KM_LEVEL_NONE);
    CHECK(d2km_h3_level(1, 0) == D2KM_LEVEL_HANDSHAKE);
    CHECK(d2km_h3_level(1, 1) == D2KM_LEVEL_APPLICATION);
    DONE("test_check");
}
