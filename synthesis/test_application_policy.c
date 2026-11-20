#define main trial_fixture_main
#include "test_application_trial.c"
#undef main
#include "application_policy.h"
int d2k_t13_random(uint8_t *out,size_t n) {
    static unsigned serial=20;memset(out,++serial,n);return 0;
}
int main(void) {
    d2k_synthesis_feedback id={.generation=7,.search_id=3,.target="dns.example",
        .ip="192.0.2.7",.resource="/dns-query",.family=4,.transport=6,.port=443,
        .shape=D2K_SHAPE_MODERN,.program="baseline"};
    id.trial_id[0]=1;id.plan_id[0]=2;
    d2k_experiment net={.family=4,.port=443,.ip={192,0,2,7}};
    const d2k_tls_probe_seed *seed=(const d2k_tls_probe_seed *)&id;d2k_ver_result result;
    d2k_application_model *baseline=NULL;
    http_mode=1;mode=5;
    (void)d2k_application_https_learn(&id,19,&net,seed,25,1200,&baseline,&result);
    assert(baseline && !result.body_complete);
    const d2k_application_end *end=d2k_application_model_end(baseline);
    assert(end && end->network_evidence);
    d2k_application_policy policy;
    FILE *archive=tmpfile();assert(archive);
    assert(!d2k_application_archive_write(archive,baseline));
    id.trial_id[0]=3;
    id.doh=1;
    assert(d2k_application_policy_init(&policy,&id,baseline,seed,end->input,
        end->input_length,30,25,1200,archive)==-1);
    id.doh=0;id.resource="/other";
    assert(d2k_application_policy_init(&policy,&id,baseline,seed,end->input,
        end->input_length,30,25,1200,archive)==-1);
    id.resource="/dns-query";
    assert(!d2k_application_policy_init(&policy,&id,baseline,seed,end->input,
        end->input_length,30,25,1200,archive));
    assert(policy.witness);
    d2k_tls_application app=d2k_application_policy_callbacks(&policy);
    const char *program="d2k-plan 1 5\nid 00000000000000000000000000000000\nproto tcp tls\nwire detect-tcp-v1\norder forward\n";
    for(int scenario=0;scenario<6;scenario++) {
        mode=scenario==0?5:scenario==1?0:scenario==2?3:scenario==3?1:scenario==4?6:7;
        d2k_raw_tls_sink sink;assert(!d2k_application_policy_sink(&policy,&sink));
        char err[128];d2k_raw_tls *raw=d2k_raw_tls_open_observed(&net,program,&sink,err,sizeof err);
        assert(!d2k_raw_tls_prepare(raw,end->input,end->input_length,err,sizeof err));
        const uint8_t *prefix;size_t prefix_length;
        assert(!d2k_raw_tls_prefix(raw,25,&prefix,&prefix_length,err,sizeof err));
        assert(!app.prepare(app.context,program));
        d2k_tls_io io=d2k_raw_tls_io(raw);
        assert(!app.run(app.context,&io));d2k_raw_tls_close(raw);
        uint64_t symbol=0;int known=app.finish(app.context,&symbol);
        assert(known==(scenario!=3));
        assert(policy.qualified==(scenario==1));
        assert(app.accepted(app.context,symbol)==(scenario==1));
        assert(!(symbol&UINT64_C(0xffffffff)));
        assert(!!(symbol&(UINT64_C(1)<<62))==(scenario==5));
        if(scenario==5) {
            assert(policy.comparison.status==D2K_APP_CHANGED);
            assert(app.token_question(app.context,symbol|(UINT64_C(1)<<60))==2);
        }
        assert(d2k_application_model_kind(policy.model)==D2K_APPLICATION_HTTPS);
        assert(d2k_application_model_http_count(policy.model)==(scenario==3?2u:3u));
        if(scenario<2)assert(policy.comparison.status==
            (scenario?D2K_APP_CHANGED:D2K_APP_REPRODUCED));
    }
    d2k_application_policy_destroy(&policy);
    rewind(archive);d2k_application_model *restored=NULL;unsigned records=0;
    int read;
    while((read=d2k_application_archive_read(archive,&restored))==1) {
        assert(d2k_application_model_kind(restored)==D2K_APPLICATION_HTTPS);
        records++;d2k_application_model_free(restored);restored=NULL;
    }
    assert(read==0 && records==7);
    fclose(archive);d2k_application_model_free(baseline);
    puts("HTTP policy: owned full/truncated/503/challenge/local-refusal outcomes, context and archive pass");
    return 0;
}
