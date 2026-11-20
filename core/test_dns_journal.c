#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include "dns_journal.inc"

static void scan_text(const char *text,dns_journal_cursor *cursor,dns_journal_hits *hits) {
    FILE *f=tmpfile();assert(f);
    assert(fputs(text,f)>=0 && !fflush(f) && !fseek(f,0,SEEK_SET));
    assert(!dns_journal_scan(f,cursor,hits));
    assert(!fclose(f));
}
int main(void) {
    const char *old="I [Nov 19 21:00:00] ndm: ready\n"
        "W [Nov 19 21:00:01] https-dns-proxy: A001: \"https://old.example.com/dns-query\": curl error message: timeout\n";
    dns_journal_cursor cursor={0};dns_journal_hits hits={0};
    scan_text(old,&cursor,&hits);assert(cursor.ready && !hits.count);
    const char *fresh="I [Nov 19 21:00:00] ndm: ready\n"
        "W [Nov 19 21:00:01] https-dns-proxy: A001: \"https://old.example.com/dns-query\": curl error message: timeout\n"
        "W [Nov 19 21:00:02] https-dns-proxy: A002: \"https://gw.cloudflare-\n"
        "                    gateway.com/dns-query\": curl error message: Operation timed out\n"
        "W [Nov 19 21:00:03] unrelated: \"https://ignore.example.com\": error\n"
        "\033[K"
        "W [Nov 19 21:00:04] https-dns-proxy: A003: \"https://gw.cloudflare-gateway.com/dns-query\": curl error message: timeout\n";
    scan_text(fresh,&cursor,&hits);
    assert(hits.count==1 && !strcmp(hits.names[0],"cloudflare-gateway.com"));
    hits=(dns_journal_hits){0};scan_text(fresh,&cursor,&hits);assert(!hits.count);
    hits=(dns_journal_hits){0};
    scan_text("W [Nov 19 21:00:05] https-dns-proxy: A004: \"https://fresh.example.org/dns-query\": curl error message: timeout\n",
        &cursor,&hits);
    assert(!hits.count); /* Lost anchor after rotation: no old replay. */
    return 0;
}
