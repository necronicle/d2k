#include "application_archive.h"
#include <assert.h>
#include "test_application_archive_v2.h"
#include <stdlib.h>
#include <string.h>
typedef struct {size_t calls,stop;} archive_cancel;
static int cancel_archive(void *ctx) {
    archive_cancel *c=ctx;return ++c->calls==c->stop;
}
static void append_series(FILE *f,d2k_synthesis_feedback id,d2k_application_observation o,
    unsigned count,int failed,int owned) {
    uint64_t experience=100+id.trial_id[0];
    d2k_application_model *m=d2k_application_model_new(&id,experience);assert(m);
    o.identity=&id;o.experience=experience;
    for(unsigned i=1;i<=count;i++) {
        o.raw_ordinal=3*i;o.query.ordinal=i;o.query.stream_id=2*i-1;
        o.query.started_ms=100*i;o.query.finished_ms=100*i+25;
        o.query.dns_valid=!(failed && i==count);o.query.timed_out=!o.query.dns_valid;
        o.query.response.budget_requests=i;o.query.response.doh_replies=i-o.query.timed_out;
        o.query.response.status=200;o.query.response.body_complete=o.query.dns_valid;
        o.query.response.level=D2K_VER_APPLICATION;
        assert(d2k_application_model_add(m,&o)>0);
    }
    d2k_application_end end={0};end.identity=&id;end.experience=experience;
    end.input=o.input;end.input_length=o.input_length;end.raw_ordinal=o.raw_ordinal+1;
    end.tuple=o.tuple;end.network_evidence=owned;end.timeout_ms=25;end.hello_wire=1200;
    end.first_tls_symbol=o.first_tls_symbol;end.result=o.query.response;
    assert(!d2k_application_model_finish(m,&end));
    assert(!d2k_application_archive_write(f,m));d2k_application_model_free(m);
}
int main(void) {
    FILE *legacy=tmpfile();assert(legacy);
    assert(fwrite(archive_v2,1,sizeof archive_v2,legacy)==sizeof archive_v2);rewind(legacy);
    d2k_application_model *old=NULL;assert(d2k_application_archive_read(legacy,&old)==1);
    assert(!d2k_application_model_end(old)->transport.available);
    size_t old_count=0;const d2k_application_observation *old_history=d2k_application_model_history(old,&old_count);
    assert(old_count==1 && !old_history[0].transport.available);
    d2k_application_model_free(old);fclose(legacy);
    d2k_synthesis_feedback id={0};id.generation=7;id.search_id=3;
    id.target="dns.example";id.ip="192.0.2.7";id.resource="/dns-query";
    id.program="measured plan\n";id.doh=1;id.family=4;id.transport=6;id.port=443;
    id.trial_id[0]=1;id.plan_id[0]=2;
    id.doh_replies=4;
    d2k_application_model *m=d2k_application_model_new(&id,19);assert(m);
    FILE *f=tmpfile();assert(f);
    assert(d2k_application_archive_write(f,m)==-1);
    uint8_t input[]={22,3,1,0,1,1};
    d2k_application_observation o={0};o.identity=&id;o.experience=19;
    o.input=input;o.input_length=sizeof input;o.raw_ordinal=3;
    o.tuple.family=4;o.tuple.local_port=50000;o.tuple.remote_port=443;
    o.tuple.remote[0]=192;o.tuple.remote[2]=2;o.tuple.remote[3]=7;
    o.first_tls_available=1;o.first_tls_symbol=42;
    o.query.ordinal=1;o.query.stream_id=1;o.query.query_schema=D2K_DOH_QUERY_SCHEMA_V1;
    o.query.timeout_ms=25;o.query.timed_out=1;o.query.response.budget_requests=1;
    o.query.started_ms=100;o.query.finished_ms=125;
    o.query.response.level=D2K_VER_HANDSHAKE;o.query.response.fd=72;
    o.query.response.name_ok=-1;o.query.response.body_bytes=UINT64_C(0x100000002);
    o.transport=(d2k_raw_transport){.available=1,.received_packets=19,.received_payload_bytes=UINT64_C(0x100000001),.ack_packets=8,.ack_advances=4,.sent_end=2105,.acked_end=2015,.peer_window_raw=16,.ack_seen=1,.window_seen=1};
    strcpy(o.query.response.reason,"incomplete DNS reply");
    assert(d2k_application_model_add(m,&o)>0);
    d2k_application_end end={0};end.identity=&id;end.experience=19;
    end.raw_ordinal=4;end.tuple=o.tuple;end.input=input;end.input_length=sizeof input;
    end.first_tls_symbol=42;end.network_evidence=1;end.timeout_ms=25;end.hello_wire=1200;
    end.transport=o.transport;end.transport.received_packets=20;
    end.result=o.query.response;end.result.n_resources=1;
    strcpy(end.result.resources[0].host,"assets.example");
    strcpy(end.result.resources[0].path,"/style.css");
    assert(d2k_application_model_finish(m,&end)==0);
    assert(d2k_application_archive_write(f,m)==0);
    long length=ftell(f);assert(length>0);rewind(f);
    d2k_application_model *restored=NULL;
    assert(d2k_application_archive_read(f,&restored)==1 && restored);
    d2k_application_model_free(m);m=NULL;
    const d2k_application_end *saved=d2k_application_model_end(restored);
    assert(saved && saved->experience==19 && saved->raw_ordinal==4);
    assert(saved->input_length==sizeof input && !memcmp(saved->input,input,sizeof input));
    assert(!strcmp(saved->identity->program,"measured plan\n") && saved->identity->trial_id[0]==1);
    assert(saved->identity->doh_replies==4);
    assert(saved->transport.available && saved->transport.received_packets==20);
    assert(saved->transport.sent_end==2105 && saved->transport.acked_end==2015);
    assert(saved->result.fd==-1 && saved->result.name_ok==-1);
    assert(saved->result.body_bytes==UINT64_C(0x100000002));
    assert(saved->result.n_resources==1 && !strcmp(saved->result.resources[0].path,"/style.css"));
    size_t count=0;const d2k_application_observation *history=d2k_application_model_history(restored,&count);
    assert(history[0].transport.available && history[0].transport.received_payload_bytes==UINT64_C(0x100000001));
    assert(count==1 && history[0].query.timed_out && history[0].query.finished_ms==125);
    assert(history[0].first_tls_symbol==42 && history[0].query.response.fd==-1);
    d2k_synthesis_feedback other=id;other.trial_id[0]=3;
    d2k_application_model *trial=d2k_application_model_new(&other,20);assert(trial);
    o.identity=&other;o.experience=20;
    assert(d2k_application_model_add(trial,&o)>0);
    assert(d2k_application_model_question(restored,trial).status==D2K_APP_REPRODUCED);
    d2k_application_model_free(trial);
    d2k_application_model *eof=NULL;assert(d2k_application_archive_read(f,&eof)==0 && !eof);
    rewind(f);unsigned char *bytes=malloc((size_t)length);assert(bytes);
    assert(fread(bytes,1,(size_t)length,f)==(size_t)length);
    for(long cut=1;cut<length;cut++) {
        FILE *broken=tmpfile();assert(broken);
        assert(fwrite(bytes,1,(size_t)cut,broken)==(size_t)cut);rewind(broken);
        assert(d2k_application_archive_read(broken,&eof)==-1 && !eof);
        fclose(broken);
    }
    for(int where=0;where<2;where++) {
        long position=where?length-1:length/2;bytes[position]^=1;
        FILE *broken=tmpfile();assert(broken);
        assert(fwrite(bytes,1,(size_t)length,broken)==(size_t)length);rewind(broken);
        assert(d2k_application_archive_read(broken,&eof)==-1 && !eof);
        fclose(broken);bytes[position]^=1;
    }
    assert(!fseek(f,0,SEEK_END));assert(!d2k_application_archive_write(f,restored));rewind(f);
    for(int i=0;i<2;i++) {
        assert(d2k_application_archive_read(f,&eof)==1 && eof);
        d2k_application_model_free(eof);eof=NULL;
    }
    assert(d2k_application_archive_read(f,&eof)==0 && !eof);
    trial=d2k_application_model_new(&other,20);assert(trial);
    d2k_application_witness_context context={trial,input,sizeof input,25,1200};
    d2k_synthesis_feedback later=id;later.trial_id[0]=4;
    append_series(f,later,o,3,1,1);
    later.trial_id[0]=5;append_series(f,later,o,4,0,1);
    later.trial_id[0]=6;append_series(f,later,o,5,1,0);
    later.trial_id[0]=7;later.resource="/other-query";append_series(f,later,o,6,1,1);
    later.trial_id[0]=8;later.resource=id.resource;
    d2k_application_observation wrong_timeout=o;wrong_timeout.query.timeout_ms=50;
    append_series(f,later,wrong_timeout,7,1,1);
    later.trial_id[0]=9;later.search_id++;append_series(f,later,o,8,0,1);later.search_id--;
    later.trial_id[0]=10;append_series(f,later,o,8,0,0);
    uint8_t foreign_input[]={22,3,1,0,1,9};
    d2k_application_observation foreign=o;foreign.input=foreign_input;
    later.trial_id[0]=11;append_series(f,later,foreign,8,0,1);
    later.trial_id[0]=12;append_series(f,later,wrong_timeout,8,0,1);
    later.trial_id[0]=13;later.resource="/foreign";append_series(f,later,o,8,0,1);later.resource=id.resource;
    later.trial_id[0]=14;later.generation++;append_series(f,later,o,8,0,1);later.generation--;
    later.trial_id[0]=15;append_series(f,later,o,2,0,1);
    long position=ftell(f);assert(position>0);
    d2k_application_model *witness=NULL;
    assert(d2k_application_archive_witness(f,&context,&witness)==1 && witness);
    assert(ftell(f)==position);
    const d2k_application_end *selected=d2k_application_model_end(witness);
    assert(selected->identity->trial_id[0]==4);
    d2k_application_model_history(witness,&count);assert(count==3);
    d2k_application_model *contrast=NULL;
    assert(d2k_application_archive_contrast(f,witness,4,&contrast)==1 && contrast);
    assert(ftell(f)==position);
    assert(d2k_application_model_end(contrast)->identity->trial_id[0]==5);
    d2k_application_model *invalid=NULL;
    assert(d2k_application_archive_contrast(f,contrast,4,&invalid)==-1 && !invalid);
    d2k_application_model_free(contrast);contrast=NULL;
    assert(d2k_application_archive_contrast(f,witness,5,&contrast)==0 && !contrast);
    assert(d2k_application_archive_contrast(f,witness,2,&contrast)==-1 && !contrast);
    assert(d2k_application_archive_contrast(f,trial,4,&contrast)==-1 && !contrast);
    d2k_application_model_free(witness);witness=NULL;
    d2k_synthesis_feedback current=id;
    current.generation=100;current.search_id=200;
    d2k_application_model *proposal=NULL;
    assert(d2k_application_archive_proposal(f,&current,25,1200,5,NULL,&proposal)==1);
    assert(proposal && ftell(f)==position);
    assert(d2k_application_model_end(proposal)->identity->trial_id[0]==14);
    assert(d2k_application_model_end(proposal)->identity->generation==8);
    assert(d2k_application_model_question(proposal,trial).status==D2K_APP_QUESTION_CONTEXT);
    d2k_application_model_free(proposal);proposal=NULL;
    archive_cancel cancelling={0};
    d2k_inference_control control={cancel_archive,&cancelling};
    assert(d2k_application_archive_proposal(f,&current,25,1200,5,&control,&proposal)==1);
    size_t checkpoints=cancelling.calls;assert(checkpoints>1);
    d2k_application_model_free(proposal);proposal=NULL;
    for(size_t at=1;at<=checkpoints;at++) {
        cancelling=(archive_cancel){.stop=at};
        assert(d2k_application_archive_proposal(f,&current,25,1200,5,&control,&proposal)==0);
        assert(!proposal && ftell(f)==position);
    }
    assert(d2k_application_archive_proposal(f,&current,25,1200,9,NULL,&proposal)==0 && !proposal);
    current.ip="192.0.2.8";
    assert(d2k_application_archive_proposal(f,&current,25,1200,1,NULL,&proposal)==0 && !proposal);
    current.ip=id.ip;current.transport=17;
    assert(d2k_application_archive_proposal(f,&current,25,1200,1,NULL,&proposal)==0 && !proposal);
    current.transport=6;current.resource="/unknown";
    assert(d2k_application_archive_proposal(f,&current,25,1200,1,NULL,&proposal)==0 && !proposal);
    current.resource=id.resource;
    assert(d2k_application_archive_proposal(f,&current,25,1300,1,NULL,&proposal)==0 && !proposal);
    assert(d2k_application_archive_transfer_proposal(f,&current,25,1556,5,NULL,&proposal)==1);
    assert(d2k_application_model_end(proposal)->hello_wire==1200);
    assert(d2k_application_model_end(proposal)->identity->generation==8);
    assert(d2k_application_model_question(proposal,trial).status==D2K_APP_QUESTION_CONTEXT);
    d2k_application_model_free(proposal);proposal=NULL;
    current.ip="192.0.2.8";
    assert(d2k_application_archive_transfer_proposal(f,&current,25,1556,5,NULL,&proposal)==0 && !proposal);
    current.ip=id.ip;
    assert(d2k_application_archive_transfer_proposal(f,&current,50,1556,5,NULL,&proposal)==0 && !proposal);
    assert(d2k_application_archive_transfer_proposal(f,&current,25,1556,9,NULL,&proposal)==0 && !proposal);
    assert(ftell(f)==position);
    context.timeout_ms=50;
    assert(d2k_application_archive_witness(f,&context,&witness)==0 && !witness);
    context.timeout_ms=25;context.hello_wire=1300;
    assert(d2k_application_archive_witness(f,&context,&witness)==0 && !witness);
    context.hello_wire=1200;uint8_t different[]={22,3,1,0,1,2};context.input=different;
    assert(d2k_application_archive_witness(f,&context,&witness)==0 && !witness);
    context.input=input;
    assert(fputc(0,f)!=EOF);
    assert(d2k_application_archive_witness(f,&context,&witness)==-1 && !witness);
    assert(d2k_application_archive_contrast(f,restored,4,&contrast)==-1 && !contrast);
    assert(d2k_application_archive_proposal(f,&current,25,1200,5,NULL,&proposal)==-1 && !proposal);
    assert(ftell(f)==position+1);
    d2k_application_model_free(trial);
    free(bytes);fclose(f);d2k_application_model_free(restored);
    return 0;
}
