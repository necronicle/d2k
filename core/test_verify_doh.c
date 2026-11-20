/* DoH verification against binary in-memory HTTP fixtures; no network. */
#include "quicconn.c"
#include "verify.c"

static int fails;
#define CHECK(cond, msg) do { if (!(cond)) { \
    fprintf(stderr, "DoH:%d: %s\n", __LINE__, msg); fails++; \
} } while (0)

typedef struct {
    const uint8_t *response;
    size_t len, pos, fragment;
    char request[16384];
    size_t request_len;
} doh_fixture;

static long doh_read(void *ctx, uint8_t *buf, size_t cap, int wait,
                     char *err, size_t errcap) {
    doh_fixture *f = ctx;
    (void)wait; (void)err; (void)errcap;
    size_t n = f->len - f->pos;
    if (n > cap) n = cap;
    if (n > f->fragment) n = f->fragment;
    memcpy(buf, f->response + f->pos, n);
    f->pos += n;
    return (long)n;
}

static int doh_write(void *ctx, const uint8_t *buf, size_t n,
                     char *err, size_t errcap) {
    doh_fixture *f = ctx;
    (void)err; (void)errcap;
    if (n > sizeof f->request - f->request_len - 1) return -1;
    memcpy(f->request + f->request_len, buf, n);
    f->request_len += n;
    f->request[f->request_len] = 0;
    return 0;
}

static const uint8_t dns_a[] = {
    0x00,0x00,0x85,0x80,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00,
    0x07,'e','x','a','m','p','l','e',0x03,'c','o','m',0x00,0x00,0x01,0x00,0x01,
    0xc0,0x0c,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x3c,0x00,0x04,
    93,184,216,34
};

static size_t http_response(uint8_t *out, size_t cap, int status,
                            const uint8_t *body, size_t body_len, int chunked) {
    int n = snprintf((char *)out, cap,
        "HTTP/1.1 %d %s\r\nContent-Type: application/dns-message\r\n%s",
        status, status == 200 ? "OK" : "Error",
        chunked ? "Transfer-Encoding: chunked\r\n\r\n" : "");
    if (n < 0 || (size_t)n >= cap) return 0;
    size_t used = (size_t)n;
    if (chunked) {
        n = snprintf((char *)out + used, cap - used, "%zx\r\n", body_len);
        if (n < 0 || (size_t)n >= cap - used) return 0;
        used += (size_t)n;
    } else {
        n = snprintf((char *)out + used, cap - used, "Content-Length: %zu\r\n\r\n", body_len);
        if (n < 0 || (size_t)n >= cap - used) return 0;
        used += (size_t)n;
    }
    if (body_len > cap - used) return 0;
    memcpy(out + used, body, body_len); used += body_len;
    if (chunked) {
        static const char end[] = "\r\n0\r\n\r\n";
        if (used + sizeof end - 1 > cap) return 0;
        memcpy(out + used, end, sizeof end - 1); used += sizeof end - 1;
    }
    return used;
}

static d2k_ver_result run_doh(doh_fixture *f, int status, const uint8_t *body,
                              size_t body_len, int chunked, size_t fragment, int tls12) {
    static uint8_t response[70000];
    size_t len = http_response(response, sizeof response, status, body, body_len, chunked);
    CHECK(len > 0, "fixture construction");
    memset(f, 0, sizeof *f);
    f->response = response; f->len = len; f->fragment = fragment;
    d2k_ver_result r = {0};
    r.fd = -1; r.level = D2K_VER_HANDSHAKE; r.name_ok = -1;
    char err[200] = "";
    request_doh(doh_read, doh_write, f, "tenant.gateway.example.test",
                "/dns-query", 1000, tls12, &r, err, sizeof err);
    return r;
}

static void expect_reject(int status, const uint8_t *body, size_t len,
                          int chunked, const char *what) {
    doh_fixture f;
    d2k_ver_result r = run_doh(&f, status, body, len, chunked, 7, 0);
    if (r.level == D2K_VER_APPLICATION || !r.reason[0]) {
        fprintf(stderr, "DoH accepted %s: level=%d status=%d reason=%s\n",
                what, r.level, r.status, r.reason);
        fails++;
    }
}

int main(void) {
    static const char request_line[] =
        "GET /dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE HTTP/1.1\r\n";
    for (int tls12 = 0; tls12 < 2; tls12++) {
        for (size_t fragment = 1; fragment <= 64; fragment *= 8) {
            doh_fixture f;
            d2k_ver_result r = run_doh(&f, 200, dns_a, sizeof dns_a, 1, fragment, tls12);
            CHECK(r.level == (tls12 ? D2K_VER_HANDSHAKE : D2K_VER_APPLICATION) && r.status == 200,
                  "valid chunked DNS parsed, TLS12 cannot prove durable H2");
            CHECK(!tls12 || r.unsupported, "TLS12 HTTP/1 must report unsupported durable DoH");
            CHECK(r.body_complete && r.body_bytes == sizeof dns_a && r.body_expected == sizeof dns_a,
                  "short complete DNS body lost or misaccounted");
            CHECK(!strncmp(f.request, request_line, strlen(request_line)),
                  "DoH GET base64url query mismatch");
            CHECK(strstr(f.request, "Accept: application/dns-message\r\n") != NULL,
                  "DoH Accept header missing");
            CHECK(strstr(f.request, "Accept-Encoding: identity\r\n") != NULL,
                  "DoH response compression not disabled");
        }
    }

    uint8_t nodata[29];
    memcpy(nodata, dns_a, sizeof nodata);
    nodata[6] = nodata[7] = 0;
    doh_fixture short_fixture;
    d2k_ver_result short_result = run_doh(&short_fixture, 200, nodata, sizeof nodata, 0, 3, 0);
    CHECK(short_result.level == D2K_VER_APPLICATION && short_result.body_complete,
          "29-byte NODATA response mistaken for insufficient volume");

    uint8_t nxdomain[29];
    memcpy(nxdomain, nodata, sizeof nxdomain); nxdomain[3] = 0x83;
    doh_fixture nx_fixture;
    d2k_ver_result nx_result = run_doh(&nx_fixture, 200, nxdomain, sizeof nxdomain, 0, 64, 0);
    CHECK(nx_result.level == D2K_VER_APPLICATION, "valid NXDOMAIN rejected");

    uint8_t bad[sizeof dns_a];
    memcpy(bad, dns_a, sizeof bad); bad[0] = 1;
    expect_reject(200, bad, sizeof bad, 0, "mismatched DNS ID");
    memcpy(bad, dns_a, sizeof bad); bad[2] &= 0x7f;
    expect_reject(200, bad, sizeof bad, 0, "DNS query instead of response");
    memcpy(bad, dns_a, sizeof bad); bad[2] |= 0x08;
    expect_reject(200, bad, sizeof bad, 0, "wrong DNS opcode");
    memcpy(bad, dns_a, sizeof bad); bad[2] |= 0x02;
    expect_reject(200, bad, sizeof bad, 0, "truncated DNS response");
    memcpy(bad, dns_a, sizeof bad); bad[3] = 0x82;
    expect_reject(200, bad, sizeof bad, 0, "SERVFAIL");
    memcpy(bad, dns_a, sizeof bad); bad[3] = 0x85;
    expect_reject(200, bad, sizeof bad, 0, "REFUSED");
    memcpy(bad, dns_a, sizeof bad); bad[22] = 'o'; bad[23] = 'r'; bad[24] = 'g';
    expect_reject(200, bad, sizeof bad, 0, "wrong DNS question");
    memcpy(bad, dns_a, sizeof bad); bad[39] = 0xff;
    expect_reject(200, bad, sizeof bad, 0, "malformed RDATA length");
    expect_reject(200, dns_a, 20, 0, "short DNS header/question");
    expect_reject(200, (const uint8_t *)"<html>not dns</html>", 19, 0, "HTML body");
    expect_reject(500, dns_a, sizeof dns_a, 0, "HTTP 500");
    uint8_t trailing[sizeof dns_a + 1];
    memcpy(trailing, dns_a, sizeof dns_a); trailing[sizeof dns_a] = 0;
    expect_reject(200, trailing, sizeof trailing, 0, "trailing bytes after DNS message");

    uint8_t truncated[256];
    int header_len = snprintf((char *)truncated, sizeof truncated,
        "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: %zu\r\n\r\n",
        sizeof dns_a);
    CHECK(header_len > 0, "truncated fixture header");
    memcpy(truncated + header_len, dns_a, 20);
    doh_fixture truncated_fixture = {0};
    truncated_fixture.response = truncated;
    truncated_fixture.len = (size_t)header_len + 20;
    truncated_fixture.fragment = 7;
    d2k_ver_result truncated_result = {0};
    truncated_result.fd = -1; truncated_result.level = D2K_VER_HANDSHAKE;
    char truncated_err[100] = "";
    request_doh(doh_read, doh_write, &truncated_fixture, "example.com", "/dns-query",
                1000, 0, &truncated_result, truncated_err, sizeof truncated_err);
    CHECK(truncated_result.level != D2K_VER_APPLICATION && !truncated_result.body_complete,
          "truncated HTTP body accepted as DoH proof");

    d2k_ver_result no_target = d2k_verify_doh_on(-1, NULL, 443,
        "tenant.gateway.example.test", 10, 0, 0, 0, "/dns-query");
    CHECK(no_target.fd == -1 && no_target.level == D2K_VER_NOT_MEASURED,
          "public DoH API attempted contact without a target");
    d2k_ver_result legacy = d2k_verify_doh_on(-1, "192.0.2.1", 443,
        "dns.example", 10, 0, 1, 0, "/dns-query");
    CHECK(legacy.fd == -1 && legacy.unsupported && legacy.level != D2K_VER_APPLICATION &&
          legacy.budget != D2K_BUDGET_PASSED, "missing TLS backend must refuse before contact");
    doh_fixture untouched={0};d2k_tls_io transport={&untouched,doh_read,doh_write};
    d2k_ver_result no_counter=d2k_verify_doh_io(&transport,"dns.example","/dns-query",
        10,0,25,NULL,NULL);
    CHECK(no_counter.local_refusal && no_counter.level==D2K_VER_NOT_MEASURED &&
          !untouched.request_len,"missing packet counter must refuse before IO");
    d2k_ver_result bad_path=d2k_verify_doh_io(&transport,"dns.example","/bad\r\npath",
        10,0,0,NULL,NULL);
    CHECK(bad_path.local_refusal && !untouched.request_len,"invalid resource must refuse before IO");
    const uint8_t alert[]={21,3,3,0,2,2,40};
    untouched.response=alert;untouched.len=sizeof alert;untouched.fragment=2;
    d2k_ver_result refused=d2k_verify_doh_io(&transport,"dns.example","/dns-query",
        10,1200,0,NULL,NULL);
    CHECK(refused.level==D2K_VER_TRANSPORT && !refused.body_complete &&
          refused.budget!=D2K_BUDGET_PASSED && untouched.request_len>=1200 &&
          (unsigned char)untouched.request[0]==22,"TLS alert cannot become DoH success");

    if (fails) fprintf(stderr, "DoH: %d failures\n", fails);
    return fails ? 1 : 0;
}
