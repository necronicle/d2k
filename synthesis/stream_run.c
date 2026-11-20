#include "stream.h"
#include <stdio.h>
#include <string.h>
typedef struct {const d2k_experiment *base;const size_t *word;size_t length;} stream_decoder;
static int begin_stream(void *ctx) {
    stream_decoder *d=ctx;
    return d->base->begin_decode?d->base->begin_decode(d->base->decoder_context):0;
}
static int decode_stream(void *ctx,size_t index,const d2k_raw_observation *obs,
                         const uint8_t *bytes,size_t n,uint64_t *out) {
    stream_decoder *d=ctx;
    if(index>=d->length || !d->base->decode)return -1;
    return d->base->decode(d->base->decoder_context,d->word[index],obs,bytes,n,out);
}
d2k_experiment_status d2k_tls_stream_run(const d2k_tls_stream *s,const d2k_experiment *base,
    const size_t *word,size_t n,d2k_sample *samples,size_t *completed,
    d2k_raw_observation *last,char *err,size_t cap) {
    if(completed)*completed=0;if(last)memset(last,0,sizeof *last);if(err && cap)err[0]=0;
    if(!base || !completed || !last || !err || !cap || (n && (!samples || !word)) ||
       n>SIZE_MAX/sizeof *samples)return D2K_EXPERIMENT_ERROR;
    if(n)memset(samples,0,n*sizeof *samples);
    d2k_stream_word resolved;
    if(d2k_tls_stream_resolve(s,word,n,&resolved)) {
        snprintf(err,cap,"invalid stream experiment word");return D2K_EXPERIMENT_ERROR;
    }
    for(size_t i=0;i<n;i++)if(word[i]==s->chunks && !base->decode) {
        snprintf(err,cap,"stream experiment has no response decoder");
        d2k_stream_word_free(&resolved);return D2K_EXPERIMENT_ERROR;
    }
    stream_decoder decoder={base,word,n};d2k_experiment e=*base;
    e.operations=resolved.operations;e.operation_count=n;
    e.decoder_context=&decoder;e.begin_decode=begin_stream;e.decode=decode_stream;e.decode_packet=NULL;
    d2k_experiment_status status=d2k_experiment_run(&e,resolved.indices,n,samples,completed,last,err,cap);
    for(size_t i=0;i<n;i++)samples[i].operation=word[i];
    d2k_stream_word_free(&resolved);return status;
}
