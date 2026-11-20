/* TLS 1.2 suite selection and record tests need no sockets. */
#include "tls12.c"

static int fails;
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"TLS12 suites:%d: %s\n",__LINE__,#x); fails++; } } while (0)

typedef struct {
    uint8_t bytes[REC_MAX + 5];
    size_t len, off, writes;
} memory_stream;

static long memory_read(void *ctx,uint8_t *buf,size_t n,int wait,char *err,size_t cap) {
    memory_stream *m=ctx;
    (void)wait;(void)err;(void)cap;
    if(n>m->len-m->off)n=m->len-m->off;
    if(n>7)n=7; /* record and handshake fragmentation */
    memcpy(buf,m->bytes+m->off,n);m->off+=n;
    return (long)n;
}
static int discard_write(void *ctx,const uint8_t *buf,size_t n,char *err,size_t cap) {
    memory_stream *m=ctx;(void)buf;(void)n;(void)err;(void)cap;m->writes++;return 0;
}
static void test_selection(void) {
    const uint16_t ids[]={0xc02b,0xc02f,0xc02c,0xc030,0xcca9,0xcca8,0x009c};
    for(size_t i=0;i<sizeof ids/sizeof ids[0];i++) {
        /* ServerHello + SKE with a deliberately unsupported group. The six
         * suites must reach the group diagnostic, never the cipher diagnostic. */
        memory_stream m={.bytes={22,3,3,0,52, 2,0,0,40,3,3},.len=57};
        m.bytes[43]=0;put16(m.bytes+44,ids[i]);m.bytes[46]=0;
        m.bytes[47]=0;m.bytes[48]=0; /* empty ServerHello extensions */
        m.bytes[49]=12;m.bytes[50]=0;m.bytes[51]=0;m.bytes[52]=4;
        m.bytes[53]=3;put16(m.bytes+54,0x0018);m.bytes[56]=0;
        d2k_tls_io io={&m,memory_read,discard_write};
        d2k_tls12 *t=NULL;uint8_t random[32]={0};char err[256]={0};
        CHECK(d2k_tls12_connect_probe(&io,random,"",500,0,&t,err,sizeof err)<0);
        CHECK(t==NULL && m.writes==1);
        if(i<6) {
            if(!strstr(err,"группу 0x0018"))fprintf(stderr,"0x%04x: %s\n",ids[i],err);
            CHECK(strstr(err,"группу 0x0018")!=NULL);
        } else CHECK(strstr(err,"шифрнабор 0x009c")!=NULL);
    }
}
#include "test_tls12_vectors.h"

static size_t unhex(const char *hex,uint8_t *out) {
    size_t n=strlen(hex)/2;
    for(size_t i=0;i<n;i++){unsigned v=0;CHECK(sscanf(hex+2*i,"%2x",&v)==1);out[i]=(uint8_t)v;}
    return n;
}
static int hexeq(const uint8_t *got,size_t n,const char *hex) {
    uint8_t want[256];
    return strlen(hex)==2*n && unhex(hex,want)==n && !memcmp(got,want,n);
}
static void test_prf384(void) {
    /* TLS1-PRF from OpenSSL 3.6.5, using the historic SHA384 test inputs.
     * Command: openssl kdf -keylen 148 -kdfopt digest:SHA384
     * -kdfopt hexsecret:b80b733d6ceefcdc71566ea48e5567df
     * -kdfopt hexseed:74657374206c6162656ccd665cf6a8447dd6ff8b27555edb7465 TLS1-PRF
     * 7465...656c is ASCII "test label". No bytes from D2K's own output. */
    uint8_t secret[16],seed[16],got[148],part[149];d2k_suite suite;
    unhex("b80b733d6ceefcdc71566ea48e5567df",secret);
    unhex("cd665cf6a8447dd6ff8b27555edb7465",seed);
    CHECK(d2k_suite_of(0x1302,&suite)==0);
    prf(&suite,secret,16,"test label",seed,16,got,sizeof got);
    CHECK(hexeq(got,sizeof got,
        "7b0c18e9ced410ed1804f2cfa34a336a1c14dffb4900bb5fd7942107e81c83cd"
        "e9ca0faa60be9fe34f82b1233c9146a0e534cb400fed2700884f9dc236f80edd"
        "8bfa961144c9e8d792eca722a7b32fc3d416d473ebc2c5fd4abfdad05d918425"
        "9b5bf8cd4d90fa0d31e2dec479e4f1a26066f2eea9a69236a3e52655c9e9aee6"
        "91c8f3a26854308d5eaa3be85e0990703d73e56f"));
    const size_t lengths[]={0,1,12,47,48,49,72,96,147,148};
    for(size_t i=0;i<sizeof lengths/sizeof lengths[0];i++) {
        memset(part,0xa5,sizeof part);
        prf(&suite,secret,16,"test label",seed,16,part,lengths[i]);
        CHECK(!memcmp(part,got,lengths[i]));CHECK(part[lengths[i]]==0xa5);
    }
}
static void test_schedule(void) {
    d2k_tls12 *t=calloc(1,sizeof *t);CHECK(t!=NULL);if(!t)return;
    uint8_t shared[32],fin[16];
    for(size_t i=0;i<32;i++){shared[i]=(uint8_t)i;t->c_random[i]=(uint8_t)(32+i);t->s_random[i]=(uint8_t)(96+i);}
    for(size_t i=0;i<127;i++)t->transcript[i]=(uint8_t)i;
    t->tr_len=127;
    for(size_t i=0;i<sizeof schedules/sizeof schedules[0];i++) {
        CHECK(suite12_of(schedules[i].id,t)==0);t->extended_master_secret=schedules[i].ems;
        derive_keys(t,shared);size_t k=t->suite.key_len,iv=t->iv_len;
        CHECK(hexeq(t->master,48,schedules[i].master));
        uint8_t kb[88];memcpy(kb,t->c_key,k);memcpy(kb+k,t->s_key,k);
        memcpy(kb+2*k,t->c_salt,iv);memcpy(kb+2*k+iv,t->s_salt,iv);
        CHECK(hexeq(kb,2*k+2*iv,schedules[i].kb));
        client_finished(t,fin);CHECK(!memcmp(fin,"\x14\x00\x00\x0c",4));
        CHECK(hexeq(fin+4,12,schedules[i].finished));
    }
    free(t);
}
static int memory_write(void *ctx,const uint8_t *buf,size_t n,char *err,size_t cap) {
    memory_stream *m=ctx;(void)err;(void)cap;
    if(n>sizeof m->bytes)return -1;
    memcpy(m->bytes,buf,n);m->len=n;m->off=0;m->writes++;return 0;
}
static void test_records(void) {
    /* Independently sealed with OpenSSL 3.6.5 EVP_{aes_128_gcm,aes_256_gcm,
     * chacha20_poly1305}; source in results/19-evidence/openssl-record-reference.c.
     * key=00..1f, IV=a0..ab, seq=0102030405060708, AAD=seq||17||0303||0013. */
    const struct {uint16_t id;const char *wire;} vectors[]={
        {0xc02b,"170303002b01020304050607084871c8fb09e8eea1e5c885643872536cc958f1cd9e18192833cee9de465a770033aed7"},
        {0xc02f,"170303002b01020304050607084871c8fb09e8eea1e5c885643872536cc958f1cd9e18192833cee9de465a770033aed7"},
        {0xc02c,"170303002b0102030405060708a2b61195c69b087c25097a97f60330d90c479ae815eaca685a2536c86343e6444a05ef"},
        {0xc030,"170303002b0102030405060708a2b61195c69b087c25097a97f60330d90c479ae815eaca685a2536c86343e6444a05ef"},
        {0xcca9,"1703030023f2b31767e1ab4cf3d6939e3e73912105017ff96b70ca6d8ad8dc124ef8facece9deca2"},
        {0xcca8,"1703030023f2b31767e1ab4cf3d6939e3e73912105017ff96b70ca6d8ad8dc124ef8facece9deca2"}
    };
    d2k_tls12 *t=calloc(1,sizeof *t);CHECK(t!=NULL);if(!t)return;
    memory_stream m={0};t->have_io=1;t->io=(d2k_tls_io){&m,memory_read,memory_write};
    for(size_t i=0;i<32;i++)t->c_key[i]=t->s_key[i]=(uint8_t)i;
    for(size_t i=0;i<12;i++)t->c_salt[i]=t->s_salt[i]=(uint8_t)(0xa0+i);
    const uint8_t msg[]="TLS12 record vector";char err[160];uint8_t out[REC_MAX],type;size_t n;
    for(size_t v=0;v<sizeof vectors/sizeof vectors[0];v++) {
        CHECK(suite12_of(vectors[v].id,t)==0);t->c_seq=UINT64_C(0x0102030405060708);
        CHECK(send_sealed(t,REC_APPDATA,msg,sizeof msg-1,err,sizeof err)==0);
        CHECK(hexeq(m.bytes,m.len,vectors[v].wire));
        CHECK(t->c_seq==UINT64_C(0x0102030405060709));
        for(int damage=0;damage<5;damage++) {
            unhex(vectors[v].wire,m.bytes);m.off=0;t->s_seq=UINT64_C(0x0102030405060708);
            if(damage==1)m.bytes[m.len-1]^=1; /* tag */
            if(damage==2)m.bytes[5]^=1; /* explicit nonce for GCM, ciphertext for ChaCha */
            if(damage==3)m.bytes[0]=REC_HANDSHAKE; /* AAD type */
            if(damage==4)t->s_seq++; /* AAD sequence and implicit nonce */
            memset(out,0xa5,sizeof out);uint64_t before=t->s_seq;
            int rc=read_record(t,1,&type,out,sizeof out,&n,now_ms()+1000,err,sizeof err);
            if(damage) {CHECK(rc<0 && out[0]==0xa5);CHECK(t->s_seq==before);}
            else {CHECK(rc==0 && type==REC_APPDATA && n==sizeof msg-1 && !memcmp(out,msg,n));CHECK(t->s_seq==before+1);}
        }
        const size_t lens[]={0,1,19,16384};uint8_t plain[16384];memset(plain,0x5c,sizeof plain);
        for(size_t l=0;l<sizeof lens/sizeof lens[0];l++) {
            t->c_seq=t->s_seq=23+l;
            CHECK(send_sealed(t,REC_APPDATA,plain,lens[l],err,sizeof err)==0);
            CHECK(m.len==5+lens[l]+16+(v<4?8:0));
            CHECK(read_record(t,1,&type,out,sizeof out,&n,now_ms()+1000,err,sizeof err)==0);
            CHECK(n==lens[l] && !memcmp(out,plain,n));
        }
        m.len=5+15+(v<4?8:0);m.off=0;put16(m.bytes+3,(uint16_t)(m.len-5));
        CHECK(read_record(t,1,&type,out,sizeof out,&n,now_ms()+1000,err,sizeof err)<0);
        CHECK(send_sealed(t,REC_APPDATA,plain,SIZE_MAX,err,sizeof err)<0);
    }
    free(t);
}
/* Форма через транспорт исполнителя плеча: на ответ TLS 1.2 рукопожатие
   продолжается клиентом 1.2 (поле 11.11, flibusta.is), а не обрывается
   отказом «транспорт только для 1.3». В потоке тут лишь ServerHello —
   дальше чтение кончается, но ошибка уже не про версию. */
static void test_form_io_rejection(void) {
    uint8_t form[2048];d2k_tls_probe_seed *seed=d2k_tls_probe_seed_new();
    CHECK(seed!=NULL);if(!seed)return;
    size_t flen=d2k_tls_probe_hello(seed,"localhost",1200,NULL,0,form,sizeof form);
    CHECK(flen>0);
    const uint16_t ids[]={0xc02b,0xc02f,0xc02c,0xc030,0xcca9,0xcca8};
    for(size_t i=0;i<6;i++) {
        memory_stream m={.bytes={22,3,3,0,44,2,0,0,40,3,3},.len=49};
        put16(m.bytes+44,ids[i]);
        d2k_tls_io io={&m,memory_read,discard_write};char err[256]={0};d2k_tls *t=NULL;
        CHECK(d2k_tls_connect_form(-1,&io,"localhost",form,flen,500,&t,err,sizeof err)<0);
        CHECK(!t && !strstr(err,"requires TLS1.3"));
        CHECK(m.writes==1);
    }
    d2k_tls_probe_seed_free(seed);
}
int main(void) {
    test_selection();test_prf384();test_schedule();test_records();test_form_io_rejection();
    if(fails)return 1;
    puts("TLS 1.2 six suites: selection, PRF SHA384, schedules/EMS, Finished, record vectors/authentication OK");return 0;
}
