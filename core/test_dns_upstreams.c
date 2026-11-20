#include "d2k_dns_upstreams.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void endpoint_values(void) {
    d2k_dns_endpoint e;
    assert(d2k_dns_endpoint_parse("https://NEW.resolver.test:8443/dns-query?account=opaque",
                                  D2K_DNS_HTTPS, &e) == D2K_DNS_PARSE_OK);
    assert(e.transport == D2K_DNS_HTTPS && e.port == 8443);
    assert(!strcmp(e.host, "new.resolver.test"));
    assert(!strcmp(e.path, "/dns-query?account=opaque") && !e.address[0]);
    assert(d2k_dns_endpoint_parse("[2001:db8::53]:8853@tls.resolver.test",
                                  D2K_DNS_TLS, &e) == D2K_DNS_PARSE_OK);
    assert(e.transport == D2K_DNS_TLS && e.port == 8853);
    assert(!strcmp(e.host, "tls.resolver.test") && !strcmp(e.address, "2001:db8::53"));
    assert(d2k_dns_endpoint_parse("192.0.2.53:5353", D2K_DNS_PLAIN, &e) == D2K_DNS_PARSE_OK);
    assert(e.port == 5353 && !strcmp(e.address, "192.0.2.53"));
    assert(d2k_dns_endpoint_parse("https://[2001:db8::8]/", D2K_DNS_HTTPS, &e) == D2K_DNS_PARSE_OK);
    assert(!strcmp(e.host, "2001:db8::8") && !strcmp(e.path, "/"));
    assert(d2k_dns_endpoint_parse("tls://resolver.test", D2K_DNS_PLAIN, &e) == D2K_DNS_PARSE_OK);
    assert(e.transport == D2K_DNS_TLS && e.port == 853);
    d2k_dns_endpoint udp, tcp;
    assert(d2k_dns_endpoint_parse("udp://resolver.test", D2K_DNS_PLAIN, &udp) == D2K_DNS_PARSE_OK);
    assert(d2k_dns_endpoint_parse("tcp://resolver.test", D2K_DNS_PLAIN, &tcp) == D2K_DNS_PARSE_OK);
    assert(!d2k_dns_endpoint_equal(&udp, &tcp));
    const char *bad[] = {"http://resolver.test/dns-query", "https://u:p@resolver.test/dns-query",
        "https://resolver.test:0/dns-query", "https://resolver.test:65536/dns-query",
        "https://resolver.test/dns-query#fragment", "https://bad..test/", "not a host",
        "https://resolver.test:abc/", "[2001:db8::53", "192.0.2.53:853@bad..test"};
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        d2k_dns_endpoint original = e;
        assert(d2k_dns_endpoint_parse(bad[i], D2K_DNS_PLAIN, &e) == D2K_DNS_PARSE_INVALID);
        assert(!memcmp(&e, &original, sizeof e));
    }
}

static void discover_arbitrary_configured_names(void) {
    const char proxy[] =
        "proxy-status:\n proxy-name: System\n"
        "dns_server = 127.0.0.1:40508 . # https://BrandNew.resolver.test/dns-query@dnsm\n"
        "dns_server = 127.0.0.1:40500 . # 192.0.2.9:853@tls.other.test\n"
        "dns_server = 198.51.100.53:5353 .\n"
        "dns_server = [2001:db8::53]:53 .\n"
        "dns_server = 127.0.0.1:40501 .\n"
        "uri: https://brandnew.resolver.test/dns-query\n"
        "uri = https://second.unlisted.test/custom/path\n"
        "static_a = unrelated.test 203.0.113.7 1\n";
    d2k_dns_endpoint out[8];
    size_t count = 99;
    assert(d2k_dns_upstreams_parse(proxy, sizeof proxy - 1, out, 8, &count) == D2K_DNS_PARSE_OK);
    assert(count == 5);
    assert(!strcmp(out[0].host, "brandnew.resolver.test"));
    assert(out[1].transport == D2K_DNS_TLS && !strcmp(out[1].address, "192.0.2.9"));
    assert(out[2].transport == D2K_DNS_PLAIN && out[2].port == 5353);
    assert(!strcmp(out[3].address, "2001:db8::53"));
    assert(!strcmp(out[4].path, "/custom/path"));
    /* A local resolver/proxy without a declared remote is not an upstream. */
    assert(!strcmp(out[4].host, "second.unlisted.test"));
}

static void atomic_refresh_and_limits(void) {
    d2k_dns_endpoint out[2], saved[2];
    memset(out, 0x5a, sizeof out);
    memcpy(saved, out, sizeof out);
    size_t count = 7;
    const char broken[] = "uri = https://good.test/dns-query\nuri = https://bad.test:99999/\n";
    assert(d2k_dns_upstreams_parse(broken, sizeof broken - 1, out, 2, &count) == D2K_DNS_PARSE_INVALID);
    assert(count == 7 && !memcmp(out, saved, sizeof out));
    const char two[] = "uri = https://one.test/dns-query\nuri = https://two.test/dns-query\n";
    assert(d2k_dns_upstreams_parse(two, sizeof two - 1, out, 1, &count) == D2K_DNS_PARSE_LIMIT);
    assert(count == 7 && !memcmp(out, saved, sizeof out));
    const char nul[] = "uri = https://one.test/\0uri = https://two.test/";
    assert(d2k_dns_upstreams_parse(nul, sizeof nul - 1, out, 2, &count) == D2K_DNS_PARSE_INVALID);
    assert(count == 7 && !memcmp(out, saved, sizeof out));
    assert(d2k_dns_upstreams_parse("", 0, out, 2, &count) == D2K_DNS_PARSE_OK && count == 0);
}

static void keenetic_wrapped_uri(void) {
    const char config[] =
        "  uri: https://long.resolver-\n"
        "       gateway.test/dns-query?tenant=opaque\n"
        "  status: true\n"
        "  uri: https://second.test/\n"
        "       status: true\n";
    d2k_dns_endpoint out[3];
    size_t count = 0;
    assert(d2k_dns_upstreams_parse(config, sizeof config - 1, out, 3, &count) == D2K_DNS_PARSE_OK);
    assert(count == 2);
    assert(!strcmp(out[0].host, "long.resolver-gateway.test"));
    assert(!strcmp(out[0].path, "/dns-query?tenant=opaque"));
    assert(!strcmp(out[1].host, "second.test") && !strcmp(out[1].path, "/"));
}

static void owner_additions_keep_bootstrap_and_path(void) {
    const char rules[] = "# explicit additions, not an allowlist\n"
        "private.resolver.test 443 /tenant/dns-query?key=opaque 192.0.2.8\n"
        "v6.resolver.test 8443 /custom 2001:db8::8 # owner's IPv6 bootstrap\n";
    d2k_dns_endpoint out[4];
    size_t count = 0;
    assert(d2k_dns_owner_targets_parse(rules, sizeof rules - 1, out, 4, &count) == D2K_DNS_PARSE_OK);
    assert(count == 2 && !strcmp(out[0].host, "private.resolver.test"));
    assert(!strcmp(out[0].path, "/tenant/dns-query?key=opaque"));
    assert(!strcmp(out[0].address, "192.0.2.8"));
    assert(out[1].port == 8443 && !strcmp(out[1].address, "2001:db8::8"));
    d2k_dns_endpoint saved[4];
    memcpy(saved, out, sizeof out);
    const char bad[] = "resolver.test 443 /dns-query not-an-address\n";
    assert(d2k_dns_owner_targets_parse(bad, sizeof bad - 1, out, 4, &count) == D2K_DNS_PARSE_INVALID);
    assert(count == 2 && !memcmp(saved, out, sizeof out));
}

static void proxy_upstreams_and_bootstrap_are_separate(void) {
    const char config[] =
        "listen 127.0.0.1:5353\n"
        "upstream quic://unlisted.resolver.test\n"
        "upstream quic://[2001:db8::53]:8853 # encrypted upstream\n"
        "upstream https://another.resolver.test/tenant/dns-query\n"
        "bootstrap 192.0.2.53\n"
        "bootstrap [2001:db8::54]:5353\n"
        "bootstrap 192.0.2.53 # duplicate\n"
        "cache_size 100\n";
    d2k_dns_endpoint out[4];
    size_t count = 0;
    assert(d2k_dns_upstreams_parse(config, sizeof config - 1, out, 4, &count) == D2K_DNS_PARSE_OK);
    assert(count == 3 && out[0].transport == D2K_DNS_QUIC && out[0].port == 853);
    assert(!strcmp(out[0].host, "unlisted.resolver.test") && !out[0].address[0]);
    assert(out[1].transport == D2K_DNS_QUIC && out[1].port == 8853);
    assert(out[2].transport == D2K_DNS_HTTPS);
    assert(d2k_dns_bootstrap_parse(config, sizeof config - 1, out, 4, &count) == D2K_DNS_PARSE_OK);
    assert(count == 2 && out[0].transport == D2K_DNS_PLAIN && out[0].port == 53);
    assert(!strcmp(out[1].address, "2001:db8::54") && out[1].port == 5353);
    d2k_dns_endpoint saved[4];
    memcpy(saved, out, sizeof out);
    const char bad[] = "bootstrap recursive-name.test\n";
    assert(d2k_dns_bootstrap_parse(bad, sizeof bad - 1, out, 4, &count) == D2K_DNS_PARSE_INVALID);
    assert(count == 2 && !memcmp(saved, out, sizeof out));
    const char empty[] = "upstream # missing value\n";
    assert(d2k_dns_upstreams_parse(empty, sizeof empty - 1, out, 4, &count) == D2K_DNS_PARSE_INVALID);
    const char fragment[] = "upstream https://resolver.test/dns-query#fragment\n";
    assert(d2k_dns_upstreams_parse(fragment, sizeof fragment - 1, out, 4, &count) == D2K_DNS_PARSE_INVALID);
}

static void https_authority_preserves_endpoint(void) {
    const struct {const char *host;uint16_t port;const char *expected;} cases[]={
        {"resolver.example.test",443,"resolver.example.test"},
        {"resolver.example.test",8443,"resolver.example.test:8443"},
        {"192.0.2.53",8443,"192.0.2.53:8443"},
        {"2001:db8::53",443,"[2001:db8::53]"},
        {"2001:db8::53",8443,"[2001:db8::53]:8443"}
    };
    char out[262];
    for(size_t i=0;i<sizeof cases/sizeof *cases;i++) {
        assert(!d2k_dns_http_authority(cases[i].host,cases[i].port,out,sizeof out));
        assert(!strcmp(out,cases[i].expected));
        strcpy(out,"unchanged");
        assert(d2k_dns_http_authority(cases[i].host,cases[i].port,out,3)==D2K_DNS_PARSE_LIMIT);
        assert(!strcmp(out,"unchanged"));
    }
    strcpy(out,"unchanged");
    assert(d2k_dns_http_authority("resolver.example.test",0,out,sizeof out)==D2K_DNS_PARSE_INVALID);
    assert(d2k_dns_http_authority("bad\r\nhost",443,out,sizeof out)==D2K_DNS_PARSE_INVALID);
    assert(d2k_dns_http_authority("[2001:db8::53]",443,out,sizeof out)==D2K_DNS_PARSE_INVALID);
    assert(!strcmp(out,"unchanged"));
}
int main(void) {
    https_authority_preserves_endpoint();
    keenetic_wrapped_uri();
    endpoint_values();
    discover_arbitrary_configured_names();
    atomic_refresh_and_limits();
    owner_additions_keep_bootstrap_and_path();
    proxy_upstreams_and_bootstrap_are_separate();
    puts("DNS discovery: arbitrary configured endpoints, protocol identity, bootstrap, atomic rejection");
}
