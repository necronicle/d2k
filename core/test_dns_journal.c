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
    return 0;
}
