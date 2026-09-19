#include <stdio.h>
#include <string.h>
#include "d2k_hold.h"
static int fails;
#define CHECK(x) do { if (!(x)) { printf("hold:%d: %s\n", __LINE__, #x); fails++; } } while (0)
static uint32_t released[256];
static size_t nreleased;
static void release(void *ctx, uint32_t id, const uint8_t *p, size_t n) {
    (void)ctx;
    CHECK(n >= 40 && n <= D2K_HOLD_PACKET && p[0] == 0x45);
    CHECK(nreleased < 256);
    if (nreleased < 256) { released[nreleased++] = id; }
}
static void w16(uint8_t *p, size_t n) { p[0]=(uint8_t)(n>>8); p[1]=(uint8_t)n; }
static void w32(uint8_t *p, uint32_t n) { p[0]=(uint8_t)(n>>24); p[1]=(uint8_t)(n>>16); p[2]=(uint8_t)(n>>8); p[3]=(uint8_t)n; }
static size_t packet(uint8_t *p, unsigned port, uint32_t seq, const uint8_t *b, size_t n) {
    memset(p, 0, 40); p[0]=0x45; w16(p+2, n+40); p[8]=64; p[9]=6;
    p[12]=10; p[15]=1; p[16]=1; p[19]=2; w16(p+20, port); w16(p+22, 443);
    w32(p+24, seq); w32(p+28, 12345); p[32]=0x50; p[33]=0x18;
    if (n) { memcpy(p+40, b, n); }
    return n+40;
}
static uint32_t sent[8], verdicts[8]; static size_t nsent;
static int verdict(void *ctx, uint32_t id, uint32_t v) {
    (void)ctx; sent[nsent]=id; verdicts[nsent++]=v;
    return id == 2 ? -1 : 0;
}
int main(void) {
    uint8_t hello[1544], p[1600], old[1600];
    memset(hello, 0x42, sizeof hello);
    hello[0]=22; hello[1]=3; hello[2]=1; w16(hello+3, sizeof hello-5);
    hello[5]=1; hello[6]=0; w16(hello+7, sizeof hello-9);
    d2k_hold *h = d2k_hold_new(); CHECK(h != NULL); if (!h) { return 1; }
    d2k_hold_batch batch;
    size_t n = packet(p, 2000, 1000, hello, 1448); memcpy(old,p,n);
    CHECK(d2k_hold_feed(h, 1, p, n, 1, 1, 0, 0, 0, release, NULL, &batch)==0);
    CHECK(d2k_hold_feed(h, 1, p, n, 1, 1, 1, 0, 0, release, NULL, &batch)==1);
    CHECK(!memcmp(p,old,n) && nreleased==0);
    CHECK(d2k_hold_next(h)==1+D2K_HOLD_WAIT_NS);
    n = packet(p, 2000, 2448, hello+1448, sizeof hello-1448);
    CHECK(d2k_hold_feed(h, 2, p, n, 2, 1, 0, 0, 0, release, NULL, &batch)==2);
    CHECK(batch.count==2 && batch.ids[0]==1 && batch.ids[1]==2);
    CHECK(batch.len==40+sizeof hello && !memcmp(batch.packet+40,hello,sizeof hello));
    CHECK(!memcmp(batch.packet+24, old+24, 12)); /* seq/ACK/window from head */
    CHECK(d2k_hold_next(h)==0 && nreleased==0);
    /* Matching retransmit, reordering after head, wrap, tiny initial piece. */
    uint32_t seq = UINT32_MAX-40;
    n=packet(p,2001,seq,hello,1);
    CHECK(d2k_hold_feed(h,3,p,n,3,1,1, 0, 0,release,NULL,&batch)==1);
    CHECK(d2k_hold_feed(h,4,p,n,4,1,0, 0, 0,release,NULL,&batch)==1);
    n=packet(p,2001,seq+100,hello+100,sizeof hello-100);
    CHECK(d2k_hold_feed(h,5,p,n,5,1,0, 0, 0,release,NULL,&batch)==1);
    n=packet(p,2001,seq+1,hello+1,99);
    CHECK(d2k_hold_feed(h,6,p,n,6,1,0, 0, 0,release,NULL,&batch)==2);
    CHECK(batch.count==4 && !memcmp(batch.packet+40,hello,sizeof hello));
    /* Timeout releases exact originals, not reconstructed bytes. */
    n=packet(p,2002,1000,hello,100);
    CHECK(d2k_hold_feed(h,7,p,n,7,1,1, 0, 0,release,NULL,&batch)==1);
    d2k_hold_flush(h,7+D2K_HOLD_WAIT_NS,1,0,release,NULL);
    CHECK(nreleased==1 && released[0]==7);
    /* Revision invalidation, reset, conflict and incompatible ACK. */
    CHECK(d2k_hold_feed(h,8,p,n,8,1,1, 0, 0,release,NULL,&batch)==1);
    d2k_hold_flush(h,9,2,0,release,NULL);
    CHECK(nreleased==2 && released[1]==8);
    CHECK(d2k_hold_feed(h,9,p,n,10,2,1, 0, 0,release,NULL,&batch)==1);
    p[33]=0x14;
    CHECK(d2k_hold_feed(h,10,p,n,11,2,0, 0, 0,release,NULL,&batch)==0);
    CHECK(nreleased==3 && released[2]==9); /* caller owns RST */
    p[33]=0x18;
    CHECK(d2k_hold_feed(h,11,p,n,12,2,1, 0, 0,release,NULL,&batch)==1);
    p[60]^=1;
    CHECK(d2k_hold_feed(h,12,p,n,13,2,0, 0, 0,release,NULL,&batch)==1);
    CHECK(nreleased==5 && released[3]==11 && released[4]==12);
    p[60]^=1;
    CHECK(d2k_hold_feed(h,13,p,n,14,2,1, 0, 0,release,NULL,&batch)==1);
    p[31]^=1;
    CHECK(d2k_hold_feed(h,14,p,n,15,2,0, 0, 0,release,NULL,&batch)==1);
    CHECK(nreleased==7 && released[5]==13 && released[6]==14);
    /* Per-group capacity: ninth ID released along with eight originals. */
    n=packet(p,2003,1000,hello,100);
    for (uint32_t i=0; i<D2K_HOLD_IDS; i++) {
        CHECK(d2k_hold_feed(h,20+i,p,n,20+i,2,1, 0, 0,release,NULL,&batch)==1);
    }
    CHECK(d2k_hold_feed(h,28,p,n,29,2,0, 0, 0,release,NULL,&batch)==1);
    CHECK(nreleased==16 && released[15]==28);
    /* Slot pressure refuses only the new head; shutdown releases all slots. */
    for (unsigned i=0; i<D2K_HOLD_SLOTS; i++) {
        n=packet(p,3000+i,1000,hello,100);
        CHECK(d2k_hold_feed(h,40+i,p,n,40,2,1, 0, 0,release,NULL,&batch)==1);
    }
    n=packet(p,4000,1000,hello,100);
    CHECK(d2k_hold_feed(h,60,p,n,41,2,1, 0, 0,release,NULL,&batch)==0);
    d2k_hold_flush(h,42,2,1,release,NULL);
    CHECK(nreleased==32 && d2k_hold_next(h)==0);
    d2k_hold_stats stats; d2k_hold_get_stats(h,&stats);
    CHECK(stats.pending==0 && stats.ready==2 && stats.full==2 && stats.timed_out==1);
    /* ПРИЧИНА ОТПУСКАНИЯ НАЗЫВАЕТСЯ, А НЕ УГАДЫВАЕТСЯ. Общее «отпущено» не
       отличает истёкший срок от смены плана и от сброса очереди, а на живой
       линии это три разных диагноза: ждали и не дождались, план переставили
       под носом, ядро потеряло пакеты. */
    /* Куски, дошедшие до ОТКРЫТОГО слота, считаются отдельно от начатых. */
    CHECK(stats.joined==12);     /* все куски, попавшие к УЖЕ открытой группе */
    CHECK(stats.mismatched==2);  /* несовместимый ack и девятый сверх ёмкости */
    CHECK(stats.sided==0);       /* обратной стороны в этом наборе нет */
    CHECK(stats.plan_changed==1);   /* d2k_hold_flush(h,9,2,...) */
    CHECK(stats.dropped_all==D2K_HOLD_SLOTS); /* завершающий flush all=1 */
    /* One failed verdict cannot stop remaining releases or become success. */
    uint32_t ids[]={1,2,3};
    CHECK(d2k_hold_verdicts(ids,3,0,verdict,NULL)==1);
    CHECK(nsent==3 && sent[2]==3 && verdicts[0]==0 && verdicts[2]==0);
    d2k_hold_free(h);
    if (fails) { return 1; } puts("hold: ownership, bounds and release checks passed"); return 0;
}
