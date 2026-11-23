#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "dns_journal.inc"

#define ENTRY(id, source, level, text) "\"" #id "\":{\"ident\":\"" source "\",\"message\":{\"label\":\"" level "\",\"message\":\"" text "\"}}"
#define SNAP(rows) "{\"log\":{" rows "}}"
int main(void) {
    const char *initial=SNAP(ENTRY(20,"https-dns-proxy","W","https://old.example.com error"));
    const char *fresh=SNAP(
        ENTRY(22,"tls-dns-proxy","E","tls://dns.example.net failed") ","
        ENTRY(21,"https-dns-proxy","W","A001: \\\"https://gw.cloudflare-gateway.com/dns-query\\\": curl error") ","
        ENTRY(23,"quic-dns-proxy","W","quic://dns.example.org timed out") ","
        ENTRY(24,"kernel","W","https://ignored.invalid error") ","
        ENTRY(25,"https-dns-proxy","I","https://ignored.invalid error") ","
        ENTRY(26,"https-dns-proxy","W","https://gw.cloudflare-gateway.com failed"));
    dns_journal_cursor cursor={0};
    dns_journal_hits hits={0};
    assert(!dns_journal_parse(initial,strlen(initial),&cursor,&hits) && !hits.count && cursor.last==20);
    assert(dns_journal_parse(fresh,strlen(fresh)-1,&cursor,&hits)<0 && cursor.last==20 && !hits.count);
    assert(!dns_journal_parse(fresh,strlen(fresh),&cursor,&hits) && cursor.last==26 && hits.count==3);
    assert(!strcmp(hits.names[0],"example.net") && !strcmp(hits.names[1],"cloudflare-gateway.com"));
    assert(!strcmp(hits.names[2],"example.org"));
    assert(!dns_journal_parse(fresh,strlen(fresh),&cursor,&hits) && !hits.count);
    assert(!dns_journal_parse(initial,strlen(initial),&cursor,&hits) && !hits.count && cursor.last==20);
    const char *wrapped=SNAP(ENTRY(21,"ndm","W","quic-dns-proxy: quic://wrap.example.org failed"));
    assert(dns_journal_parse("{}",2,&cursor,&hits)<0 && cursor.last==20);
    assert(!dns_journal_parse(wrapped,strlen(wrapped),&cursor,&hits));
    assert(hits.count==1 && !strcmp(hits.names[0],"example.org"));
    const char *empty=SNAP("");
    assert(!dns_journal_parse(empty,strlen(empty),&cursor,&hits) && cursor.ready && !hits.count);
    const char *first=SNAP(ENTRY(1,"https-dns-proxy[42]","E","https://dns.example.net failed"));
    assert(!dns_journal_parse(first,strlen(first),&cursor,&hits) && hits.count==1);
    const char *older="Mon Nov 23 09:00:00 2026 daemon.warn https-dns-proxy[42]: https://old.example.com failed\n";
    const char *newer="Mon Nov 23 09:00:01 2026 daemon.err tls-dns-proxy[41]: tls://new.example.net timed out\n";
    FILE *text=tmpfile();assert(text);
    fputs(older,text);rewind(text);
    cursor=(dns_journal_cursor){0};
    assert(!journal_scan_text(text,1,&cursor,&hits) && !hits.count);
    fseek(text,0,SEEK_END);fputs(newer,text);rewind(text);
    assert(!journal_scan_text(text,1,&cursor,&hits) && hits.count==1 && !strcmp(hits.names[0],"example.net"));
    rewind(text);assert(!journal_scan_text(text,1,&cursor,&hits) && !hits.count);
    fclose(text);
    char domain[256];
    assert(openwrt_event("Mon Nov 23 09:00:02 2026 daemon.info https-dns-proxy[42]: [W] https://dns.example.org failed",domain));
    assert(!openwrt_event("Mon Nov 23 09:00:02 2026 daemon.info https-dns-proxy[42]: [I] https://dns.example.org failed",domain));
    assert(!openwrt_event("Mon Nov 23 09:00:02 2026 daemon.err unrelated[42]: https://dns.example.org failed",domain));
    assert(journal_cli_domain("W [time] https-dns-proxy: https://dns.cloudflare-\tgateway.com/dns-query timed\tout",domain));
    assert(!strcmp(domain,"cloudflare-gateway.com"));
    const char *api="{\"log\":{\"1\":{\"timestamp\":\"Nov 23 09:00:00\",\"ident\":\"ndm\",\"message\":{\"label\":\"I\",\"message\":\"ready\"}}}}";
    cursor=(dns_journal_cursor){0};
    assert(!dns_journal_parse(api,strlen(api),&cursor,&hits));
    text=tmpfile();assert(text);
    fputs("I [Nov 23 09:00:00] ndm: ready\nW [Nov 23 09:00:01] tls-dns-proxy: tls://dns.example.net\n                    failed\n",text);
    rewind(text);assert(!journal_scan_text(text,0,&cursor,&hits) && hits.count==1);
    fclose(text);
    const char *back="{\"log\":{" ENTRY(3,"quic-dns-proxy","W","quic://dns.example.org timed out") ","
        "\"2\":{\"timestamp\":\"Nov 23 09:00:01\",\"ident\":\"tls-dns-proxy\",\"message\":{\"label\":\"W\",\"message\":\"tls://dns.example.net failed\"}}}}";
    assert(!dns_journal_parse(back,strlen(back),&cursor,&hits) && hits.count==1 && !strcmp(hits.names[0],"example.org"));
    return 0;
}
