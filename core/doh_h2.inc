/* Minimal sequential HTTP/2 DNS probe; SETTINGS disables dynamic HPACK. */
typedef struct {
    read_fn read; write_fn write; void *session;
    uint8_t buf[16384]; size_t pos, len;
    int wait_ms, timed_out, eof;
    int64_t end_ms;
} doh_h2_io;
static int dh2_read(doh_h2_io *io,uint8_t *out,size_t n,char *err,size_t cap) {
    while(n) {
        if(io->pos==io->len) {
            int64_t left=io->end_ms-verify_now_ms();
            if(left<=0) {io->timed_out=1;snprintf(err,cap,"HTTP/2 response timeout");return -1;}
            long z=io->read(io->session,io->buf,sizeof io->buf,(int)left,err,cap);
            if(z<=0) {io->eof=z==0;io->timed_out=z<0 && verify_now_ms()>=io->end_ms-10;return -1;}
            io->pos=0;io->len=(size_t)z;
        }
        size_t z=io->len-io->pos;if(z>n)z=n;
        memcpy(out,io->buf+io->pos,z);out+=z;n-=z;io->pos+=z;
    }
    return 0;
}
static int dh2_read_failed(char *err,size_t cap,const char *phase,size_t body_bytes) {
    char cause[80];snprintf(cause,sizeof cause,"%.79s",cap?err:"");
    snprintf(err,cap,"HTTP/2 %s after %zu DATA bytes: %s",phase,body_bytes,cause);
    return -1;
}
static int dh2_frame(doh_h2_io *io,uint8_t type,uint8_t flags,uint32_t stream,
    const uint8_t *p,size_t n,char *err,size_t cap) {
    uint8_t b[4096];if(n>sizeof b-9)return -1;
    b[0]=(uint8_t)(n>>16);b[1]=(uint8_t)(n>>8);b[2]=(uint8_t)n;
    b[3]=type;b[4]=flags;b[5]=(uint8_t)(stream>>24);b[6]=(uint8_t)(stream>>16);
    b[7]=(uint8_t)(stream>>8);b[8]=(uint8_t)stream;
    if(n)memcpy(b+9,p,n);
    return io->write(io->session,b,n+9,err,cap);
}
static int dh2_integer(const uint8_t *b,size_t n,size_t *p,unsigned prefix,uint32_t *out) {
    if(*p>=n)return -1;
    uint32_t mask=(1u<<prefix)-1, v=b[(*p)++]&mask;
    if(v<mask){*out=v;return 0;}
    for(unsigned shift=0;shift<=28;shift+=7) {
        if(*p>=n)return -1;
        unsigned c=b[(*p)++];
        if((uint64_t)v+((uint64_t)(c&127)<<shift)>UINT32_MAX)return -1;
        v+=(c&127)<<shift;
        if(!(c&128)){*out=v;return 0;}
    }
    return -1;
}
static int dh2_string(const uint8_t *b,size_t n,size_t *p,const uint8_t **v,size_t *len,int *huff) {
    if(*p>=n)return -1;
    *huff=(b[*p]&128)!=0;uint32_t z;
    if(dh2_integer(b,n,p,7,&z)||z>n-*p)return -1;
    *v=b+*p;*len=z;*p+=z;return 0;
}
static int dh2_huff_status(const uint8_t *v,size_t n) {
    if(n<2||n>3)return -1;
    uint32_t bits=0;for(size_t i=0;i<n;i++)bits=bits<<8|v[i];
    int total=(int)n*8,pos=0,status=0;
    for(int i=0;i<3;i++) {
        if(total-pos<5)return -1;
        unsigned c=(bits>>(total-pos-5))&31;
        if(c<=2){status=status*10+(int)c;pos+=5;continue;}
        if(total-pos<6)return -1;
        c=(bits>>(total-pos-6))&63;
        if(c<25||c>31)return -1;
        status=status*10+(int)c-22;pos+=6;
    }
    int rem=total-pos;
    if(rem>=8 || (bits&((1u<<rem)-1))!=((1u<<rem)-1))return -1;
    return status;
}
static int dh2_headers(const uint8_t *b,size_t n,int *status) {
    size_t p=0;int fields=0;
    while(p<n) {
        unsigned tag=b[p];uint32_t idx;
        if(tag&128) {
            if(dh2_integer(b,n,&p,7,&idx)||!idx||idx>61)return -1;
            if(idx>=8&&idx<=14) {
                static const int codes[]={200,204,206,304,400,404,500};
                if(*status)return -1;
                *status=codes[idx-8];
            }
            fields=1;continue;
        }
        if((tag&224)==32) {
            if(fields||dh2_integer(b,n,&p,5,&idx)||idx!=0)return -1;
            continue;
        }
        if(dh2_integer(b,n,&p,(tag&64)?6:4,&idx)||idx>61)return -1;
        int is_status=idx==8,huff;const uint8_t *v;size_t z;
        if(!idx) {
            if(dh2_string(b,n,&p,&v,&z,&huff))return -1;
            is_status=!huff&&z==7&&!memcmp(v,":status",7);
        }
        if(dh2_string(b,n,&p,&v,&z,&huff))return -1;
        if(is_status) {
            if(*status)return -1;
            int value=huff?dh2_huff_status(v,z):
                z==3&&v[0]>='1'&&v[0]<='5'&&v[1]>='0'&&v[1]<='9'&&v[2]>='0'&&v[2]<='9'
                ?(v[0]-'0')*100+(v[1]-'0')*10+v[2]-'0':-1;
            if(value<100||value>599)return -1;
            *status=value;
        }
        fields=1;
    }
    return 0;
}
static size_t dh2_encode_string(uint8_t *b,const char *s) {
    size_t n=strlen(s),p=0;
    if(n<127)b[p++]=(uint8_t)n;
    else {b[p++]=127;size_t left=n-127;while(left>=128){b[p++]=(uint8_t)(left|128);left>>=7;}b[p++]=(uint8_t)left;}
    memcpy(b+p,s,n);return p+n;
}
static int dh2_query(doh_h2_io *io,uint32_t stream,const char *host,const char *path,
    const uint8_t *question,size_t question_len,
    d2k_ver_result *r,char *err,size_t cap) {
    r->level=D2K_VER_HANDSHAKE;r->body_complete=0;r->status=0;r->body_bytes=0;
    r->body_expected=0;r->body_framing_valid=0;
    io->timed_out=io->eof=0;
    uint8_t block[2048];size_t n=0;char encoded[400],target[1024];
    if(question) {
        doh_base64url(question,question_len,encoded);
        int tn=snprintf(target,sizeof target,"%s%sdns=%s",path,strchr(path,'?')?"&":"?",encoded);
        if(tn<0||(size_t)tn>=sizeof target)return -1;
    } else {
        if(!path||!*path||strlen(path)>=sizeof target)return -1;
        snprintf(target,sizeof target,"%s",path);
    }
    /* Authority may include :65535 after a full DNS name (RFC 9113).
       The shared authority formatter bounds it to its 262-byte buffer. */
    if(strlen(host)>261)return -1;
    block[n++]=0x82;block[n++]=0x87;block[n++]=1;n+=dh2_encode_string(block+n,host);
    block[n++]=4;n+=dh2_encode_string(block+n,target);
    if(question) {block[n++]=15;block[n++]=4;n+=dh2_encode_string(block+n,"application/dns-message");}
    io->end_ms=verify_now_ms()+io->wait_ms;io->timed_out=io->eof=0;
    if(dh2_frame(io,1,5,stream,block,n,err,cap))return -1;
    uint8_t frame[16384],headers[16384],body[65535];size_t hn=0,bn=0;
    int status=0,open_headers=0,headers_seen=0,ended=0,header_end_stream=0;
    while(!ended) {
        uint8_t h[9];if(dh2_read(io,h,9,err,cap))return dh2_read_failed(err,cap,"frame header",bn);
        size_t z=(size_t)h[0]<<16|(size_t)h[1]<<8|h[2];
        unsigned type=h[3],flags=h[4];
        uint32_t id=(uint32_t)(h[5]&127)<<24|(uint32_t)h[6]<<16|(uint32_t)h[7]<<8|h[8];
        if(z>sizeof frame){r->local_limit=1;snprintf(err,cap,"HTTP/2 frame exceeds advertised limit");return -1;}
        if(dh2_read(io,frame,z,err,cap))return dh2_read_failed(err,cap,"frame payload",bn);
        if(open_headers&&(type!=9||id!=stream))return -1;
        if(type==4) {
            if(id||z%6||((flags&1)&&z))return -1;
            if(!(flags&1)&&dh2_frame(io,4,1,0,NULL,0,err,cap))return -1;
            continue;
        }
        if(type==6) {
            if(id||z!=8)return -1;
            if(!(flags&1)&&dh2_frame(io,6,1,0,frame,8,err,cap))return -1;
            continue;
        }
        if(type==7) {
            if(id || z<8) {
                snprintf(err,cap,"invalid HTTP/2 GOAWAY");
                return -1;
            }
            if(!(frame[4] || frame[5] || frame[6] || frame[7]))
                r->dns_session_ended=1;
            io->eof=1;
            snprintf(err,cap,"HTTP/2 GOAWAY");
            return -1;
        }
        if(type==8) {if(z!=4)return -1;continue;}
        if(type==2) {
            if(!id||z!=5)return -1;
            uint32_t dep=(uint32_t)(frame[0]&127)<<24|(uint32_t)frame[1]<<16|(uint32_t)frame[2]<<8|frame[3];
            if(dep==id)return -1;
            continue;
        }
        if(type>9)continue;
        if(id!=stream){snprintf(err,cap,"unexpected HTTP/2 stream");return -1;}

        if(type==3){io->eof=1;snprintf(err,cap,"HTTP/2 RST_STREAM");return -1;}
        size_t off=0,end=z;
        if((type==0||type==1)&&(flags&8)) {if(!z||frame[0]>=z)return -1;off=1;end-=frame[0];}
        if(type==1&&(flags&32)){if(end-off<5)return -1;off+=5;}
        if(type==1||type==9) {
            if(type==1)header_end_stream=(flags&1)!=0;
            else if(!open_headers)return -1;
            if(end-off>sizeof headers-hn){r->local_limit=1;return -1;}
            memcpy(headers+hn,frame+off,end-off);hn+=end-off;
            open_headers=!(flags&4);
            if(!open_headers) {
                int block_status=0;
                if(dh2_headers(headers,hn,&block_status)){r->local_limit=1;snprintf(err,cap,"unsupported or malformed HPACK");return -1;}
                hn=0;
                if(!headers_seen && block_status>=100 && block_status<200) {
                    if(header_end_stream)return -1;
                    continue;
                }
                if(!headers_seen) {
                    if(block_status<200)return -1;
                    status=block_status;headers_seen=1;r->status=status;
                } else if(block_status || !header_end_stream)return -1;
                if(header_end_stream)ended=1;
            }
        } else if(type==0) {
            if(!headers_seen||open_headers||(question&&end-off>sizeof body-bn))return -1;
            if(question)memcpy(body+bn,frame+off,end-off);
            bn+=end-off;r->body_bytes=bn;
            if(flags&1)ended=1;
        } else {r->unsupported=1;return -1;}
    }
    if(open_headers||!headers_seen)return -1;
    r->status=status;r->body_complete=1;r->body_bytes=bn;r->body_expected=bn;r->body_framing_valid=1;
    const char *why=NULL;
    if(question&&(status!=200||doh_dns_valid(question,question_len,body,bn,&why))) {
        r->dns_reply_rejected=1;
        snprintf(err,cap,"HTTP/2 DoH invalid response: HTTP %d %s",status,why?why:"");return -1;
    }
    return 0;
}
static int __attribute__((unused)) dh2_get(doh_h2_io *io,uint32_t stream,const char *host,const char *path,
    d2k_ver_result *r,char *err,size_t cap) {
    return dh2_query(io,stream,host,path,NULL,0,r,err,cap);
}
static void request_doh_h2_question(read_fn rd,write_fn wr,void *session,const char *host,
    const char *path,const uint8_t *question,size_t question_len,int timeout,const budget_io *bio,unsigned budget,
    d2k_ver_result *r,char *err,size_t cap,d2k_doh_observer observer,void *observer_ctx) {
    doh_h2_io io={0};io.read=rd;io.write=wr;io.session=session;io.wait_ms=timeout;
    static const uint8_t preface[]="PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    static const uint8_t settings[]={0,1,0,0,0,0,0,2,0,0,0,0};
    if(wr(session,preface,sizeof preface-1,err,cap)||dh2_frame(&io,4,0,0,settings,sizeof settings,err,cap))return;
    unsigned need=budget*2;r->budget_need=need;
    /* A short burst or a packet count cannot prove that this connection stays
       usable after the first reply (field: gateway DoH RX cut). */
    const unsigned min_replies=20;
    const int64_t min_span_ms=30000;
    const int64_t interval_ms=(min_span_ms+min_replies-2)/(min_replies-1);
    int64_t began=verify_now_ms();
    for(uint32_t stream=1;stream<0x7fffffff;stream+=2) {
        if(!observer && r->doh_replies) {
            int64_t next=began+(int64_t)r->doh_replies*interval_ms;
            int64_t left;
            while((left=next-verify_now_ms())>0) {
                struct timespec delay={left/1000,(left%1000)*1000000L};
                if(nanosleep(&delay,NULL)!=0 && errno!=EINTR) {
                    r->local_refusal=1;
                    snprintf(r->reason,sizeof r->reason,"DoH verification pacing failed");return;
                }
            }
        }
        r->budget_requests++;
        int64_t started=verify_now_ms();
        if(cap)err[0]=0;
        int query=dh2_query(&io,stream,host,path,question,question_len,r,err,cap);
        if(!query)r->doh_replies++;
        if(observer) {
            if(!query)r->level=D2K_VER_APPLICATION;
            budget_say(r,D2K_BUDGET_NOT_APPLICABLE,"DoH query observation, no volume verdict");
            snprintf(r->reason,sizeof r->reason,"DoH observed query %u: %s%.120s",
                r->budget_requests,query?"failed: ":"matching DNS reply",query?(err[0]?err:"HTTP/2 exchange incomplete"):"");
            d2k_doh_observation o={r->budget_requests,stream,started,verify_now_ms(),!query,io.timed_out,*r,
                D2K_DOH_QUERY_SCHEMA_V1,timeout};
            int decision=observer(observer_ctx,&o);
            if(decision!=0 && decision!=1) {
                r->local_refusal=1;
                snprintf(r->reason,sizeof r->reason,"DoH observation was not retained");return;
            }
            if(query || !decision) {
                return;
            }
            continue;
        }
        if(query) {
            long pk=bio->packets(bio->ctx);
            r->budget_packets=pk>=0?(unsigned)pk:0;
            if(pk<0)r->budget_uncountable=1;
            r->level=D2K_VER_HANDSHAKE;
            if(io.timed_out)budget_say(r,D2K_BUDGET_CUT,"DoH HTTP/2 timed out on query %u",r->budget_requests);
            else budget_say(r,D2K_BUDGET_NOT_APPLICABLE,"DoH HTTP/2 exchange incomplete: %s",err);
            snprintf(r->reason,sizeof r->reason,"DoH HTTP/2 query %u failed: %.120s",r->budget_requests,err);
            return;
        }
        /* Keep partial success separate from the durable application verdict. */
        r->level=D2K_VER_HANDSHAKE;
        long pk=bio->packets(bio->ctx);
        if(pk>=0)r->budget_packets=(unsigned)pk;
        else r->budget_uncountable=1;
        int64_t elapsed=verify_now_ms()-began;
        if(r->doh_replies>=min_replies && elapsed>=min_span_ms) {
            r->level=D2K_VER_APPLICATION;
            /* DNS continuity is the application criterion, not TCP counters. */
            r->budget_uncountable=0;
            budget_say(r,D2K_BUDGET_PASSED,"DoH HTTP/2: %u matching DNS replies over %lld ms, %ld data packets",
                r->doh_replies,(long long)elapsed,pk);
            snprintf(r->reason,sizeof r->reason,"DoH HTTP/2: %u matching DNS replies on one connection over %lld ms",
                r->doh_replies,(long long)elapsed);return;
        }
    }
    r->local_limit=1;
    budget_say(r,D2K_BUDGET_NOT_APPLICABLE,"HTTP/2 stream identifiers exhausted");
}
static void request_doh_h2_observed(read_fn rd,write_fn wr,void *session,const char *host,
    const char *path,int timeout,const budget_io *bio,unsigned budget,
    d2k_ver_result *r,char *err,size_t cap,d2k_doh_observer observer,void *observer_ctx) {
#ifndef DOH_DEFAULT_QUESTION
#define DOH_DEFAULT_QUESTION doh_query,sizeof doh_query
#endif
    request_doh_h2_question(rd,wr,session,host,path,DOH_DEFAULT_QUESTION,
        timeout,bio,budget,r,err,cap,observer,observer_ctx);
}
static void __attribute__((unused)) request_doh_h2(read_fn rd,write_fn wr,void *session,const char *host,
    const char *path,int timeout,const budget_io *bio,unsigned budget,
    d2k_ver_result *r,char *err,size_t cap) {
    request_doh_h2_observed(rd,wr,session,host,path,timeout,bio,budget,r,err,cap,NULL,NULL);
}
