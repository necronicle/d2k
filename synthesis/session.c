#include "session.h"
#include "tls_decode.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
struct d2k_tls_learning {
    d2k_tls_stream stream;
    d2k_trigger trigger;
    size_t *chunks;
    uint64_t generation;
    d2k_learning_context context;
    d2k_learner *learner;
    d2k_tls_decoder decoder;
    size_t *reference_word,reference_len;
    d2k_sample *reference,*reference_check;
    d2k_learner_status halted;
};
void d2k_tls_learning_free(d2k_tls_learning *s) {
    if(!s)return;
    d2k_tls_decoder_free(&s->decoder);d2k_learner_free(s->learner);
    d2k_learning_context_free(&s->context);free(s->chunks);
    free(s->reference_word);free(s->reference);free(s->reference_check);free(s);
}
d2k_tls_learning *d2k_tls_learning_new(const d2k_tls_stream *stream,const d2k_experiment *base,
    uint64_t generation,const void *initial,size_t initial_len) {
    if(!stream || stream->chunks>SIZE_MAX/sizeof(size_t))return NULL;
    d2k_tls_learning *s=calloc(1,sizeof *s);if(!s)return NULL;
    if(d2k_tls_stream_context(stream,base,generation,2,initial,initial_len,&s->context))goto fail;
    s->chunks=malloc(stream->chunks*sizeof *s->chunks);if(!s->chunks)goto fail;
    memcpy(s->chunks,stream->chunk_bytes,stream->chunks*sizeof *s->chunks);
    s->trigger=*stream->trigger;s->stream=*stream;
    s->stream.trigger=&s->trigger;s->stream.chunk_bytes=s->chunks;s->generation=generation;
    d2k_input_domain domain=d2k_tls_stream_domain(&s->stream);
    s->learner=d2k_learner_new_in(s->context.bytes,s->context.length,domain.operations,&domain);
    if(!s->learner)goto fail;
    return s;
fail:
    d2k_tls_learning_free(s);return NULL;
}
int d2k_tls_learning_guard(d2k_tls_learning *s,const size_t *word,size_t n) {
    if(!s || s->halted || !word || !n || n>SIZE_MAX/sizeof(d2k_sample) ||
       n>SIZE_MAX/sizeof(size_t))return -1;
    int read=0;for(size_t i=0;i<n;i++)if(word[i]==s->stream.chunks)read=1;
    if(!read)return -1;
    d2k_sample *trace=malloc(n*sizeof *trace),*check=malloc(n*sizeof *check);
    size_t *owned=malloc(n*sizeof *owned);
    if(!trace || !check || !owned || d2k_learner_trace(s->learner,word,n,trace)!=1) {
        free(trace);free(check);free(owned);return -1;
    }
    memcpy(owned,word,n*sizeof *owned);
    free(s->reference_word);free(s->reference);free(s->reference_check);
    s->reference_word=owned;s->reference_len=n;s->reference=trace;s->reference_check=check;
    return 0;
}
static d2k_learner_status check_reference(d2k_tls_learning *s,const d2k_experiment *e,char *err,size_t cap) {
    if(!s->reference_len)return D2K_L_OBSERVED;
    size_t completed=0;d2k_raw_observation last;
    d2k_experiment_status run=d2k_tls_stream_run(&s->stream,e,s->reference_word,s->reference_len,
        s->reference_check,&completed,&last,err,cap);
    if((run!=D2K_EXPERIMENT_COMPLETE && run!=D2K_EXPERIMENT_TERMINAL) || completed!=s->reference_len) {
        snprintf(err,cap,"reference experiment incomplete; new evidence not admitted");
        return s->halted=D2K_L_INCONCLUSIVE;
    }
    for(size_t i=0;i<completed;i++) {
        const d2k_sample *a=&s->reference[i],*b=&s->reference_check[i];
        if(a->operation!=b->operation || a->observation!=b->observation || a->conclusive!=b->conclusive) {
            snprintf(err,cap,"reference response changed; new evidence not admitted");
            return s->halted=D2K_L_CONTEXT;
        }
    }
    return D2K_L_OBSERVED;
}
d2k_learner_status d2k_tls_learning_step(d2k_tls_learning *s,const d2k_tls_stream *stream,
    const d2k_experiment *base,const void *initial,size_t initial_len,
    d2k_learning_round *out,char *err,size_t cap) {
    if(out)memset(out,0,sizeof *out);if(err && cap)err[0]=0;
    if(!s || !base || !out || !err || !cap)return D2K_L_ERROR;
    if(s->halted){snprintf(err,cap,"reference guard stopped this learning context");return s->halted;}
    d2k_learning_context current={0};
    if(d2k_tls_stream_context(stream,base,s->generation,2,initial,initial_len,&current)) {
        snprintf(err,cap,"invalid current experiment context");return D2K_L_CONTEXT;
    }
    int same=current.length==s->context.length && !memcmp(current.bytes,s->context.bytes,current.length);
    d2k_learning_context_free(&current);
    if(!same){snprintf(err,cap,"experiment context changed");return D2K_L_CONTEXT;}
    d2k_learning_question q;d2k_learner_status status=d2k_learner_next(s->learner,&q);
    if(status!=D2K_L_QUESTION)return status;
    if(q.length>SIZE_MAX/sizeof(d2k_sample))return D2K_L_ERROR;
    d2k_sample *samples=calloc(q.length,sizeof *samples);
    if(!samples){snprintf(err,cap,"trace allocation failed");return D2K_L_ERROR;}
    out->question_generation=q.generation;out->requested=q.length;
    d2k_experiment e=*base;e.decoder_context=&s->decoder;
    e.begin_decode=d2k_tls_decoder_begin;e.decode=d2k_tls_decoder_read;e.decode_packet=NULL;
    e.read_to_terminal=1;
    status=check_reference(s,&e,err,cap);
    if(status!=D2K_L_OBSERVED){free(samples);return status;}
    out->execution=d2k_tls_stream_run(&s->stream,&e,q.operations,q.length,samples,
                                      &out->completed,&out->last,err,cap);
    if(s->reference_len) {
        if(out->execution!=D2K_EXPERIMENT_COMPLETE && out->execution!=D2K_EXPERIMENT_TERMINAL) {
            free(samples);return s->halted=D2K_L_INCONCLUSIVE;
        }
        status=check_reference(s,&e,err,cap);
        if(status!=D2K_L_OBSERVED){free(samples);return status;}
    }
    status=d2k_learner_submit(s->learner,q.generation,s->context.bytes,s->context.length,
                             samples,out->completed);
    free(samples);return status;
}
static int hello_response(void *ctx,uint64_t symbol) {
    (void)ctx;d2k_tls_response r;int timeout,reset;
    int decoded=d2k_tls_symbol_read(symbol,&r,&timeout,&reset);
    if(decoded<0)return -1;
    return decoded && !timeout && !reset && !d2k_tls_symbol_closed(symbol) && r.kind==D2K_TLS_OBS_HELLO && !r.retry;
}
d2k_learner_status d2k_tls_learning_request(d2k_tls_learning *s,const size_t *word,size_t n) {
    return s?(s->halted?s->halted:d2k_learner_request(s->learner,word,n)):D2K_L_ERROR;
}
d2k_syn_result d2k_tls_learning_propose(d2k_tls_learning *s,char **plan,char *err,size_t cap) {
    if(plan)*plan=NULL;if(err && cap)err[0]=0;
    d2k_syn_result error={.status=D2K_SYN_ERROR};
    if(!s || !plan || !err || !cap)return error;
    if(s->halted){snprintf(err,cap,"reference guard stopped this learning context");return error;}
    d2k_hypothesis *h=NULL;int ready=d2k_learner_snapshot(s->learner,&h);
    if(ready!=1){snprintf(err,cap,"learning model unavailable: %s",ready<0?"error":"pending or inconclusive");return error;}
    d2k_transducer model=d2k_hypothesis_model(h);
    d2k_synthesis_contract contract={d2k_tls_stream_domain(&s->stream),d2k_tls_stream_preserved,NULL,hello_response};
    d2k_syn_result result=d2k_joint_search(&model,&contract);
    if(result.status==D2K_SYN_CANDIDATE)
        (void)d2k_tls_stream_lower(&s->stream,result.operations,result.length,plan,err,cap);
    d2k_hypothesis_free(h);return result;
}
d2k_syn_status d2k_tls_learning_prepare(d2k_tls_learning *s,d2k_vres *out) {
    if(!out)return D2K_SYN_ERROR;
    memset(out,0,sizeof *out);out->verdict=D2K_V_INCONCLUSIVE;out->owns_search=1;
    char *plan=NULL,err[200];
    d2k_syn_result r=d2k_tls_learning_propose(s,&plan,err,sizeof err);
    d2k_syn_status status=D2K_SYN_ERROR;
    if(r.status==D2K_SYN_CANDIDATE || r.status==D2K_SYN_EXPERIMENT) {
        /* Submission alone observes only our own send path. Obtain a network
           response in this same episode instead of closing after SEND. */
        if(r.status==D2K_SYN_EXPERIMENT && r.length && r.operations[r.length-1]!=s->stream.chunks) {
            size_t *extended=r.length<SIZE_MAX/sizeof(size_t)?
                realloc(r.operations,(r.length+1)*sizeof(size_t)):NULL;
            if(!extended) {
                snprintf(out->reason,sizeof out->reason,"синтез: нет памяти для вопроса об ответе");
                free(plan);d2k_syn_result_free(&r);return D2K_SYN_ERROR;
            }
            r.operations=extended;r.operations[r.length++]=s->stream.chunks;
        }
        d2k_learner_status request=d2k_tls_learning_request(s,r.operations,r.length);
        if(request==D2K_L_QUESTION) {
            status=D2K_SYN_EXPERIMENT;
            snprintf(out->reason,sizeof out->reason,"синтез: требуется измерить предсказанный путь");
        } else if(request==D2K_L_CLOSED && r.status==D2K_SYN_CANDIDATE) {
            if(!plan || strlen(plan)>=sizeof out->program) {
                snprintf(out->reason,sizeof out->reason,"синтез: кандидат не выражен программой: %.160s",
                         plan?"текст превышает размер передачи":err);
            } else {
                out->synthesis_generation=s->generation;
                out->program_len=strlen(plan);
                memcpy(out->program,plan,out->program_len+1);
                status=D2K_SYN_CANDIDATE;
                snprintf(out->reason,sizeof out->reason,
                         "синтез: измерен первый TLS-ответ; программа требует проверки приложения");
            }
        } else snprintf(out->reason,sizeof out->reason,"синтез: опыт не назначен (%d)",request);
    } else if(r.status==D2K_SYN_CLOSED) {
        d2k_learning_question question;
        d2k_learner_status next=d2k_learner_next(s->learner,&question);
        if(next==D2K_L_QUESTION) {
            status=D2K_SYN_EXPERIMENT;
            snprintf(out->reason,sizeof out->reason,"синтез: проверка обобщения модели");
        } else if(next==D2K_L_CLOSED) {
            status=D2K_SYN_CLOSED;
            snprintf(out->reason,sizeof out->reason,"синтез: текущая модель и операции исчерпаны");
        } else snprintf(out->reason,sizeof out->reason,"синтез: обучение остановлено (%d)",next);
    } else snprintf(out->reason,sizeof out->reason,"синтез: %.180s",err);
    free(plan);d2k_syn_result_free(&r);return status;
}
d2k_syn_status d2k_tls_learning_work(const d2k_tls_stream *stream,const d2k_experiment *base,
    uint64_t generation,const void *initial,size_t initial_len,d2k_vres *out) {
    if(!out)return D2K_SYN_ERROR;
    memset(out,0,sizeof *out);out->verdict=D2K_V_INCONCLUSIVE;out->owns_search=1;
    if(!base) {
        snprintf(out->reason,sizeof out->reason,"синтез: отсутствуют параметры опыта");
        return D2K_SYN_ERROR;
    }
    if(d2k_detect_stopped(base->cancel)) {
        snprintf(out->reason,sizeof out->reason,"синтез: остановлен до первого опыта");
        return D2K_SYN_ERROR;
    }
    if(!d2k_tls_stream_domain(stream).states || stream->chunks>=SIZE_MAX/sizeof(size_t)) {
        snprintf(out->reason,sizeof out->reason,"синтез: некорректные операции потока");return D2K_SYN_ERROR;
    }
    d2k_tls_stream working=*stream;size_t whole=working.chunks;
    for(size_t i=0;i<working.chunks;i++)if(working.chunk_bytes[i]>=working.trigger->len){whole=i;break;}
    size_t *expanded=NULL;
    if(whole==working.chunks) {
        expanded=malloc((working.chunks+1)*sizeof *expanded);
        if(!expanded){snprintf(out->reason,sizeof out->reason,"синтез: нет памяти для прямого контроля");return D2K_SYN_ERROR;}
        memcpy(expanded,working.chunk_bytes,working.chunks*sizeof *expanded);
        expanded[working.chunks++]=working.trigger->len;working.chunk_bytes=expanded;
    }
    d2k_tls_learning *s=d2k_tls_learning_new(&working,base,generation,initial,initial_len);
    if(!s) {
        snprintf(out->reason,sizeof out->reason,"синтез: не удалось создать контекст обучения");
        free(expanded);return D2K_SYN_ERROR;
    }
    unsigned long started=d2k_raw_dial_count();d2k_syn_status result=D2K_SYN_ERROR;
    size_t reference[]={whole,working.chunks};d2k_sample baseline[2];
    d2k_learning_round initial_round;char initial_error[200];
    if(d2k_tls_learning_request(s,reference,2)!=D2K_L_QUESTION ||
       d2k_tls_learning_step(s,&working,base,initial,initial_len,&initial_round,initial_error,sizeof initial_error)!=D2K_L_OBSERVED ||
       d2k_learner_trace(s->learner,reference,2,baseline)!=1) {
        snprintf(out->reason,sizeof out->reason,"синтез: прямой контроль не завершён достоверно");goto done;
    }
    if(hello_response(NULL,baseline[1].observation)==1) {
        out->protocol_response=1;
        snprintf(out->reason,sizeof out->reason,"прямой TLS-ответ получен; синтез не запускаю, требуется проверка приложения");
        result=D2K_SYN_DIRECT_RESPONSE;goto done;
    }
    if(d2k_tls_learning_guard(s,reference,2)) {
        snprintf(out->reason,sizeof out->reason,"синтез: прямой контроль не сохранён");goto done;
    }
    for(;;) {
        if(d2k_detect_stopped(base->cancel)) {
            snprintf(out->reason,sizeof out->reason,"синтез: остановлен между опытами");
            break;
        }
        result=d2k_tls_learning_prepare(s,out);
        if(result!=D2K_SYN_EXPERIMENT)break;
        d2k_learning_round round;char err[200];
        d2k_learner_status learned=d2k_tls_learning_step(s,&working,base,initial,initial_len,
                                                       &round,err,sizeof err);
        if(learned!=D2K_L_OBSERVED) {
            snprintf(out->reason,sizeof out->reason,"синтез: опыт не допускает продолжение (%d): %.180s",learned,err);
            result=D2K_SYN_ERROR;break;
        }
    }
done:
    /* Cancellation may arrive while searching/lowering the last candidate. */
    if(d2k_detect_stopped(base->cancel)) {
        out->program_len=0;out->program[0]=0;
        snprintf(out->reason,sizeof out->reason,"синтез: остановлен; кандидат не передан");
        result=D2K_SYN_ERROR;
    }
    {
        unsigned long used=d2k_raw_dial_count()-started;
        out->probes=used>(unsigned long)INT_MAX?INT_MAX:(int)used;
    }
    d2k_tls_learning_free(s);free(expanded);return result;
}
