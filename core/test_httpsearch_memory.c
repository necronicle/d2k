/* Real HTTP storage and admission; keep a runner busy without opening sockets. */
#include "httpsearch.c"
#include <assert.h>
int main(void) {
    d2k_httpsearch *hs=d2k_httpsearch_new(NULL);assert(hs);
    d2k_diag_counts c={0};d2k_httpsearch_diagnostic_counts(hs,&c);
    assert(c.http_records==0 && c.memory.http_records_bytes==0);
    hs->cur.phase=PH_BASE;
    uint8_t addr[16]={192,0,2,1};
    for(int i=0;i<33;i++) {
        char host[64];snprintf(host,sizeof host,"target%d.example",i);
        assert(rec_get(hs,host,4));
        d2k_httpsearch_portal(hs,host,4,addr,1000);
    }
    d2k_httpsearch_diagnostic_counts(hs,&c);
    assert(c.http_records==33 && c.memory.http_records_capacity==64);
    assert(c.memory.http_records_bytes==64*sizeof(rec));
    assert(c.http_queued==33 && c.memory.http_queue_capacity==64);
    assert(c.memory.http_queue_bytes==64*sizeof(pend));
    d2k_binding_context binding={0};
    for(int i=0;i<2;i++) {
        rec *r=&hs->recs[i];strcpy(r->key,"split:1");
        for(int j=0;j<3;j++) {addr[3]=(uint8_t)(j+1);assert(!remember_live_failure(r,addr,&binding,1,1));}
        assert(!remember_live_failure(r,addr,&binding,1,1));
    }
    d2k_httpsearch_diagnostic_counts(hs,&c);
    assert(c.memory.http_failures==6 && c.memory.http_failures_bytes==6*sizeof(live_failure));
    hs->n_q=0; /* removing logical entries must not pretend realloc capacity was freed */
    d2k_httpsearch_diagnostic_counts(hs,&c);
    assert(c.http_queued==0 && c.memory.http_queue_bytes==64*sizeof(pend));
    assert(c.memory.http_records_bytes==64*sizeof(rec));
    hs->cur.phase=PH_IDLE;d2k_httpsearch_free(hs);

    /* ПРЕДЕЛЫ ПО ЖИЗНЕННОМУ ЦИКЛУ. Записи со знанием (подтверждённый ключ)
       не вытесняются; записей без знания и ожидающих целей не больше
       HS_PENDING_MAX; при переполнении — отказ, не рост. */
    hs=d2k_httpsearch_new(NULL);assert(hs);
    for(int i=0;i<10;i++) {
        char host[64];snprintf(host,sizeof host,"known%d.example",i);
        rec *r=rec_get(hs,host,4);assert(r);strcpy(r->key,"split:1");
    }
    hs->cur.phase=PH_BASE;strcpy(hs->cur.host,"busy.example");hs->cur.family=4;
    addr[3]=1;
    for(int i=0;i<500;i++) {
        char host[64];snprintf(host,sizeof host,"many%d.example",i);
        rec_get(hs,host,4);
        d2k_httpsearch_portal(hs,host,4,addr,1000);
    }
    size_t known=0,unknown=0;
    for(size_t i=0;i<hs->n_recs;i++) { if(hs->recs[i].key[0])known++; else unknown++; }
    assert(known==10);
    assert(unknown<=HS_PENDING_MAX);
    assert(hs->n_q<=HS_PENDING_MAX && hs->cap_q<=HS_PENDING_MAX);
    for(int i=0;i<10;i++) {
        char host[64];snprintf(host,sizeof host,"known%d.example",i);
        assert(rec_find(hs,host,4) && rec_find(hs,host,4)->key[0]);
    }
    /* Отказы одной записи ограничены: при переполнении — evidence_lost,
       а не молчаливое забывание. */
    rec *r=rec_find(hs,"known0.example",4);assert(r);
    for(int j=0;j<HS_FAILURES_MAX+5;j++) {
        uint8_t a2[16]={10,0,(uint8_t)(j>>8),(uint8_t)j};
        remember_live_failure(r,a2,&binding,1,1);
    }
    assert(r->n_failures==HS_FAILURES_MAX && r->evidence_lost==1);
    /* Опустевшая очередь отдаёт память. */
    hs->cur.phase=PH_IDLE;hs->n_q=0;
    queue_trim(hs);
    assert(hs->q==NULL && hs->cap_q==0);
    d2k_httpsearch_free(hs);
    puts("HTTP records/queue allocated capacities and failure bytes PASS");return 0;
}
