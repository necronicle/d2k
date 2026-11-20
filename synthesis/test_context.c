#include "context.h"
#include "evidence.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
static int equal(const d2k_learning_context *a,const d2k_learning_context *b) {
    return a->length==b->length && !memcmp(a->bytes,b->bytes,a->length);
}
int main(void) {
    d2k_trigger tr={0};tr.len=3;memcpy(tr.payload,"abc",3);
    size_t chunk=1;d2k_tls_stream s={&tr,&chunk,1,10,1};
    d2k_experiment e={.ip={192,0,2,1},.family=4,.port=443,.mark=45,.connect_ms=100,.reply_capacity=128};
    const char initial[]="controlled initial context";
    d2k_learning_context a,b;
    assert(!d2k_tls_stream_context(&s,&e,1,1,initial,sizeof initial,&a));
    d2k_evidence *evidence=d2k_evidence_new(a.bytes,a.length,s.chunks+1);assert(evidence);
    d2k_sample sample={0,0,D2K_SAMPLE_OBSERVED};
    assert(d2k_evidence_add(evidence,a.bytes,a.length,&sample,1)==D2K_EVIDENCE_OK);
    assert(!d2k_tls_stream_context(&s,&e,1,1,initial,sizeof initial,&b) && equal(&a,&b));
    d2k_learning_context_free(&b);
    for(int variation=0;variation<9;variation++) {
        d2k_experiment changed=e;d2k_tls_stream changed_s=s;uint64_t generation=1,schema=1;
        size_t alternate=2;
        if(variation==0)changed.port=444;
        if(variation==1)changed.mark++;
        if(variation==2)changed_s.read_timeout_ms++;
        if(variation==3)changed_s.chunk_bytes=&alternate;
        if(variation==4)generation++;
        if(variation==5)schema++;
        if(variation==6)tr.payload[0]='z';
        if(variation==7){tr.client_tcp_known=1;tr.client_tcp_options_len=1;tr.client_tcp_options[0]=1;}
        if(variation==8)changed.read_to_terminal=1;
        assert(!d2k_tls_stream_context(&changed_s,&changed,generation,schema,initial,sizeof initial,&b));
        assert(!equal(&a,&b));
        assert(d2k_evidence_add(evidence,b.bytes,b.length,&sample,1)==D2K_EVIDENCE_CONTEXT);
        d2k_learning_context_free(&b);tr.payload[0]='a';
        tr.client_tcp_known=0;tr.client_tcp_options_len=0;
    }
    assert(d2k_tls_stream_context(&s,&e,0,1,initial,sizeof initial,&b)==-1 && !b.bytes);
    assert(d2k_tls_stream_context(&s,&e,1,1,NULL,0,&b)==-1 && !b.bytes);
    d2k_evidence_free(evidence);d2k_learning_context_free(&a);
    puts("context: endpoint, bytes, operations, timing, transport options, generation and decoder separation PASS");
}
