#include "stream.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
static void ordered_actions(void) {
    d2k_trigger tr={0};tr.len=5;memcpy(tr.payload,"abcde",5);
    d2k_stream_action actions[]={{.bytes=2},{.bytes=2,.reverse=1},{.bytes=5}};
    d2k_ordered_stream s={&tr,actions,3,10,1};
    d2k_input_domain d=d2k_ordered_stream_domain(&s);assert(d.states && d.operations==7);
    size_t state,next;assert(d.step(d.ctx,d.initial,4,&state)==1 && state==0);
    d2k_payload_piece pieces[3];
    for(size_t i=0;i<3;i++) {
        d2k_experiment_operation op;
        assert(d2k_ordered_stream_operation(&s,state,2,&op,&next)==1);
        assert(op.payload_offset==(i==0?3:i==1?1:0));
        assert(op.payload_length==(i==2?1:2));
        assert(op.offset==op.payload_offset && op.next_offset==op.offset+op.payload_length);
        pieces[i]=(d2k_payload_piece){op.payload_offset,op.payload_length,0};
        size_t domain_next;assert(d.step(d.ctx,state,2,&domain_next)==1 && domain_next==next);
        state=next;
        assert(!d2k_ordered_stream_preserved(&s,state));
        assert(d.step(d.ctx,state,1,&next)==0);
    }
    assert(d.step(d.ctx,state,2,&next)==0);
    assert(d.step(d.ctx,state,6,&next)==1 && d2k_ordered_stream_preserved(&s,next));
    char *plan=NULL,err[160];assert(d2k_lower_partition(5,pieces,3,"tls",&plan,err,sizeof err)==D2K_LOWER_OK);
    assert(strstr(plan,"order reverse"));free(plan);
    d2k_stream_action extended[]={{.bytes=2},{.bytes=2,.reverse=1},{.bytes=5},{.bytes=3,.reverse=1}};
    d2k_ordered_stream more=s;more.actions=extended;more.count=4;
    assert(d2k_ordered_stream_prefix_equal(&s,4,&more,5)==1);
    for(size_t pos=0;pos<12;pos++)for(size_t input=0;input<4;input++) {
        d2k_experiment_operation a={0},b={0};size_t na=0,nb=0;
        int ra=d2k_ordered_stream_operation(&s,pos,input,&a,&na);
        int rb=d2k_ordered_stream_operation(&more,pos,input,&b,&nb);
        assert(ra==rb);if(ra==1)assert(na==nb && a.offset==b.offset && a.payload_length==b.payload_length);
    }
    extended[1].reverse=0;assert(!d2k_ordered_stream_prefix_equal(&s,4,&more,5));
}
static void prefix_actions(void) {
    uint8_t bytes[]={22,3,3,0,1,0};
    d2k_stream_program *prefix=d2k_stream_prefix_new(bytes,sizeof bytes,1400,0);
    assert(prefix);bytes[0]=0;
    const char *program=d2k_stream_program_text(prefix);
    assert(program && strstr(program,"160303000100") && !strstr(program,"000303000100"));
    d2k_trigger tr={0};tr.len=5;memcpy(tr.payload,"abcde",5);
    d2k_stream_action actions[]={{.bytes=2},{.bytes=5,.program=prefix}};
    d2k_ordered_stream s={&tr,actions,2,10,1};
    d2k_input_domain d=d2k_ordered_stream_domain(&s);assert(d.states);
    d2k_experiment_operation op;size_t next;
    assert(d2k_ordered_stream_operation(&s,0,2,&op,&next)==1 && next==5);
    assert(op.kind==D2K_EXPERIMENT_SEND && op.trigger==&tr && op.offset==0 && op.next_offset==5);
    assert(op.tls_program==prefix && !strcmp(op.program,program));
    for(size_t pos=1;pos<12;pos++)if(pos!=6)
        assert(d2k_ordered_stream_operation(&s,pos,2,&op,&next)==0);
    assert(!d2k_ordered_stream_preserved(&s,5));
    assert(d.step(d.ctx,5,5,&next)==1 && d2k_ordered_stream_preserved(&s,next));
    d2k_stream_action extended[]={{.bytes=2},{.bytes=5,.program=prefix},{.bytes=1,.reverse=1}};
    d2k_ordered_stream more=s;more.actions=extended;more.count=3;
    assert(d2k_ordered_stream_prefix_equal(&s,3,&more,4)==1);
    extended[1].program=NULL;assert(!d2k_ordered_stream_prefix_equal(&s,3,&more,4));
    actions[1].reverse=1;assert(!d2k_ordered_stream_domain(&s).states);
    d2k_stream_program_free(prefix);
    assert(!d2k_stream_prefix_new(bytes,0,1400,0));
    d2k_payload_piece pieces[]={{0,1,0},{1,4,0}};
    prefix=d2k_stream_prefix_partition_new(bytes,sizeof bytes,1400,0,5,pieces,2);
    assert(prefix && strstr(d2k_stream_program_text(prefix),"split payload_start +1\n"));
    actions[1]=(d2k_stream_action){.bytes=5,.program=prefix};
    assert(d2k_ordered_stream_operation(&s,0,2,&op,&next)==1 && next==5);
    assert(op.tls_program==prefix && op.trigger==&tr);
    tr.len=6;actions[1].bytes=6;
    assert(!d2k_ordered_stream_domain(&s).states);
    d2k_stream_program_free(prefix);
    assert(d2k_stream_partition_compile(5,pieces,2,NULL)==D2K_LOWER_ERROR);
}
int main(void) {
    prefix_actions();
    ordered_actions();
    d2k_trigger tr={0};tr.len=5;memcpy(tr.payload,"abcde",5);
    size_t chunks[]={2,5};d2k_tls_stream s={&tr,chunks,2,10,1};
    d2k_input_domain domain=d2k_tls_stream_domain(&s);size_t next;
    assert(domain.states==6 && domain.operations==3);
    assert(domain.step(domain.ctx,0,0,&next)==1 && next==2);
    assert(domain.step(domain.ctx,4,0,&next)==1 && next==5);
    assert(domain.step(domain.ctx,5,0,&next)==0);
    d2k_input_domain path=d2k_tls_stream_path_domain(&s);
    assert(path.states==7 && path.initial==6 && path.operations==5);
    assert(path.step(path.ctx,6,0,&next)==0);
    assert(path.step(path.ctx,6,3,&next)==1 && next==0);
    assert(path.step(path.ctx,0,0,&next)==1 && next==2);
    assert(path.step(path.ctx,2,3,&next)==0);
    assert(path.step(path.ctx,2,4,&next)==1 && next==6);
    assert(path.step(path.ctx,5,2,&next)==1 && next==5);
    assert(d2k_tls_stream_path_preserved(&s,5)==1);
    assert(d2k_tls_stream_path_preserved(&s,6)==0);
    assert(d2k_tls_stream_path_preserved(&s,2)==0);
    d2k_input_domain app=d2k_tls_stream_application_domain(&s);
    assert(app.states==8 && app.operations==6 && app.initial==6);
    assert(app.step(app.ctx,2,5,&next)==0);
    assert(app.step(app.ctx,5,5,&next)==1 && next==7);
    assert(!d2k_tls_stream_application_preserved(&s,5));
    assert(d2k_tls_stream_application_preserved(&s,7)==1);
    assert(!d2k_tls_stream_application_preserved(&s,6));
    assert(app.step(app.ctx,7,0,&next)==0 && app.step(app.ctx,7,2,&next)==0);
    assert(app.step(app.ctx,7,5,&next)==0 && app.step(app.ctx,7,4,&next)==0);
    assert(app.step(app.ctx,7,3,&next)==1 && next==0);
    size_t grown_chunks[]={2,5,3};d2k_tls_stream grown=s;
    grown.chunk_bytes=grown_chunks;grown.chunks=3;
    assert(d2k_tls_stream_prefix_equal(&s,3,&grown,4)==1);
    for(size_t position=0;position<=tr.len;position++)for(size_t input=0;input<3;input++) {
        d2k_experiment_operation a={0},b={0};size_t na=99,nb=99;
        int ra=d2k_tls_stream_stable_operation(&s,position,input,&a,&na);
        int rb=d2k_tls_stream_stable_operation(&grown,position,input,&b,&nb);
        assert(ra==rb);
        if(ra==1)assert(na==nb && a.kind==b.kind && a.offset==b.offset &&
            a.next_offset==b.next_offset && a.payload_offset==b.payload_offset &&
            a.payload_length==b.payload_length && a.timeout_ms==b.timeout_ms && a.minimum==b.minimum);
    }
    grown_chunks[0]=1;assert(!d2k_tls_stream_prefix_equal(&s,3,&grown,4));
    grown_chunks[0]=2;grown.read_timeout_ms++;
    assert(!d2k_tls_stream_prefix_equal(&s,3,&grown,4));
    grown.read_timeout_ms=s.read_timeout_ms;
    assert(d2k_tls_stream_prefix_equal(&s,2,&grown,4)==-1);
    d2k_input_domain stable=d2k_tls_stream_stable_application_domain(&grown);
    assert(stable.step(stable.ctx,0,0,&next)==1 && next==0);
    assert(stable.step(stable.ctx,0,1,&next)==1 && next==2);
    assert(stable.step(stable.ctx,0,3,&next)==1 && next==3);
    assert(stable.step(stable.ctx,5,6,&next)==1 && next==7);
    const size_t word[]={0,0,0,2};d2k_stream_word w;
    assert(d2k_tls_stream_resolve(&s,word,4,&w)==0 && w.complete && w.piece_count==3);
    assert(w.operations[0].payload_offset==0 && w.operations[0].payload_length==2);
    assert(w.operations[1].offset==2 && w.operations[1].next_offset==4);
    assert(w.operations[2].offset==4 && w.operations[2].payload_length==1);
    assert(w.operations[3].kind==D2K_EXPERIMENT_READ);
    assert(w.indices[0]==0 && w.indices[2]==2);
    d2k_stream_word_free(&w);
    char *plan=NULL,err[160];
    assert(d2k_tls_stream_lower(&s,word,4,&plan,err,sizeof err)==D2K_LOWER_OK);
    assert(strstr(plan,"split payload_start +2\n") && strstr(plan,"split payload_start +4\n"));free(plan);
    const size_t adaptive[]={0,2,0,0,2};
    assert(d2k_tls_stream_lower(&s,adaptive,5,&plan,err,sizeof err)==D2K_LOWER_UNSUPPORTED && !plan);
    assert(d2k_tls_stream_lower(&s,word,1,&plan,err,sizeof err)==D2K_LOWER_INVALID && !plan);
    const size_t extra[]={1,0};
    assert(d2k_tls_stream_resolve(&s,extra,2,&w)==-1 && !w.operations);
    assert(!memcmp(tr.payload,"abcde",5));
    puts("stream: stateful slices, full byte coverage, invalid continuation and adaptive-wait rejection PASS");
}
