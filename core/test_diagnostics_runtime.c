#define _DARWIN_C_SOURCE
static char diagnostic_test_dir[]="/tmp/d2k-diag-runtime-XXXXXX";
#define D2K_DIAG_DIR diagnostic_test_dir
#define main d2kc_test_main
#include "d2kc.c"
#undef main
#include <assert.h>
/* Этап 45: соседи по conntrack. Счётчики — за всё время жизни записи; байты
   TCP включают заголовки, у которых нет нижней оценки содержимого: IPv4 — до
   60 + 60 байт, IPv6 — без верхней границы (заголовки расширения). Ответ
   данными засчитывается только доказанный; иначе «не доказан», не «нет». */
static d2k_ct_tuple peer_tuple(uint8_t fam, uint8_t proto, uint16_t sport, uint16_t dport) {
    d2k_ct_tuple t; memset(&t, 0, sizeof t);
    t.family = fam; t.proto = proto;
    t.src[0] = 10; t.src[3] = 1; t.dst[0] = 10; t.dst[3] = 2;
    t.sport_be[0] = (uint8_t)(sport >> 8); t.sport_be[1] = (uint8_t)sport;
    t.dport_be[0] = (uint8_t)(dport >> 8); t.dport_be[1] = (uint8_t)dport;
    return t;
}
static void peer_feed(peers_ctx *c, d2k_ct_tuple t, int known, uint64_t pkts, uint64_t bytes) {
    d2k_ct_info i; memset(&i, 0, sizeof i);
    i.counters_known = known; i.reply_pkts = pkts; i.reply_bytes = bytes; i.orig_pkts = pkts;
    (void)peers_cb(c, &t, &i);
}
static void test_peers_counters(void) {
    d2k_ct_tuple self = peer_tuple(4, 6, 40000, 443);
    peers_ctx c = { &self, 0, 0, 0 };
    peer_feed(&c, self, 1, 9, 9000);                                   /* сам поток — не сосед */
    peer_feed(&c, peer_tuple(4, 6, 40001, 443), 1, 5, 5 * 52);         /* ACK с отметками времени */
    peer_feed(&c, peer_tuple(4, 6, 40002, 443), 1, 10, 10 * 72);      /* ACK с SACK: 72 > 60, данных нет */
    peer_feed(&c, peer_tuple(4, 6, 40003, 443), 1, 3, 3 * 40 + 2800);  /* данные доказаны: > 3 × 120 */
    peer_feed(&c, peer_tuple(4, 6, 40004, 443), 0, 0, 0);             /* счётчиков нет */
    peer_feed(&c, peer_tuple(4, 6, 40005, 8443), 1, 3, 9000);          /* другой порт сервера */
    assert(c.flows == 4 && c.judged == 3);
    assert(c.answered == 1 && "ACK с опциями (72 байта) засчитан ответом данными");
    /* IPv6: заголовки расширения не ограничены — байты данных не доказывают. */
    d2k_ct_tuple s6 = peer_tuple(6, 6, 40000, 443);
    peers_ctx c6 = { &s6, 0, 0, 0 };
    peer_feed(&c6, peer_tuple(6, 6, 40001, 443), 1, 1, 1500);
    assert(c6.flows == 1 && c6.judged == 1 && c6.answered == 0);
    /* UDP: датаграмма сервера за время жизни записи — ответ; ни одной — нет. */
    d2k_ct_tuple su = peer_tuple(4, 17, 40000, 27015);
    peers_ctx cu = { &su, 0, 0, 0 };
    peer_feed(&cu, peer_tuple(4, 17, 40001, 27015), 1, 1, 28);
    peer_feed(&cu, peer_tuple(4, 17, 40002, 27015), 1, 0, 0);
    assert(cu.flows == 2 && cu.judged == 2 && cu.answered == 1);
    puts("ct peers: answer only when proven over the record lifetime PASS");
}
int main(void) {
    test_peers_counters();
    assert(mkdtemp(diagnostic_test_dir));
    d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,-1,0);assert(s);
    diagnostic_tick(s,1000);assert(!diagnostics);
    for(int i=0;i<10;i++) {
        int64_t now=2000+(int64_t)i*4000;
        assert(d2k_diag_toggle(D2K_DIAG_DIR,1)==0);
        diagnostic_tick(s,now);assert(diagnostics);
        char p[512];assert(!d2k_diag_path(p,sizeof p,D2K_DIAG_DIR,"report.json"));
        struct stat st;assert(!stat(p,&st));assert(st.st_size>0&&st.st_size<D2K_DIAG_REPORT_MAX);
        assert((st.st_mode&077)==0);
        assert(d2k_diag_sample_count(diagnostics)==1);
        diagnostic_tick(s,now+1000);assert(d2k_diag_sample_count(diagnostics)==1);
        diagnostic_tick(s,now+60000);assert(d2k_diag_sample_count(diagnostics)==2);
        FILE *saved=fopen(p,"r");assert(saved);
        char json[16384];size_t size=fread(json,1,sizeof json-1,saved);json[size]=0;fclose(saved);
        assert(strstr(json,"\"owners\":{") && strstr(json,"\"worker_args_live_bytes\":0"));
        assert(strstr(json,"\"catalog_boxes_bytes\":0"));
        assert(strstr(json,"\"sample_interval_ms\":60000"));
        assert(d2k_diag_toggle(D2K_DIAG_DIR,0)==0);
        assert(stat(p,&st)<0);
        /* Export can race the panel's disable; the next controller tick cleans it. */
        FILE *late=fopen(p,"w");assert(late);fputs("{}",late);assert(!fclose(late));
        diagnostic_tick(s,now+2000);assert(!diagnostics);
        assert(stat(p,&st)<0);
    }
    d2k_sched_free(s);d2k_catalog_free(&cat);assert(rmdir(D2K_DIAG_DIR)==0);
    puts("diagnostic runtime toggle/free/atomic export PASS");return 0;
}
