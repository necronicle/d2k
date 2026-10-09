#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "d2k_voice_discovery.h"
#include "d2k_stun.h"
#include "d2k_meas.h"

static int nibble(char c) {
    if(c>='0' && c<='9')return c-'0';
    if(c>='a' && c<='f')return c-'a'+10;
    if(c>='A' && c<='F')return c-'A'+10;
    return -1;
}
int d2k_voice_discovery_prefix(const char *text, uint8_t prefix[20]) {
    static const char head[]="d2k-plan 1 1\nid ";
    static const char mid[]="\nproto udp voice\npayload 1 ";
    static const char tail[]="\npoison 1\nfake payload=1 poison=1 repeats=1 gap_us=0 place=before\norder forward\npace 15000\n";
    if(!text || strlen(text)!=sizeof head-1+32+sizeof mid-1+40+sizeof tail-1 ||
       strncmp(text,head,sizeof head-1))return 0;
    const char *p=text+sizeof head-1;
    for(unsigned i=0;i<32;i++)if(nibble(p[i])<0)return 0;
    p+=32;
    if(strncmp(p,mid,sizeof mid-1))return 0;
    p+=sizeof mid-1;
    for(unsigned i=0;i<20;i++){
        int a=nibble(p[2*i]),b=nibble(p[2*i+1]);
        if(a<0 || b<0)return 0;
        prefix[i]=(uint8_t)(a*16+b);
    }
    return !strcmp(p+40,tail) && !memcmp(prefix,"\x00\x01\x00\x00\x21\x12\xa4\x42",8);
}

int d2k_discovery_response(const uint8_t *p, size_t n, const uint8_t ssrc[4]) {
    if (!p || n != 74 || p[0] || p[1] != 2 || p[2] || p[3] != 70 ||
        memcmp(p+4, ssrc, 4) || !(p[72] | p[73])) return 0;
    const uint8_t *end = memchr(p+8, 0, 64);
    if (!end || end == p+8) return 0;
    struct in_addr ip;
    return inet_pton(AF_INET, (const char *)p+8, &ip) == 1;
}
static int64_t milliseconds(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec*1000 + t.tv_nsec/1000000;
}
static d2k_discovery_result discovery_probe(uint32_t ip, uint16_t port,
    const uint8_t *prefix, size_t len, uint32_t wait, uint32_t mark) {
    d2k_discovery_result r = {0};
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { r.error = 1; return r; }
    if (mark && d2k_mark_hook(fd, mark) == 0) r.marked = 1;
    /* A failed mark must never turn a direct measurement into a test of
     * the currently installed bypass. Local unmarked CLI probes may run,
     * but cannot produce an installable candidate. */
    if (mark && !r.marked) { r.error = 1; close(fd); return r; }
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET; a.sin_port = htons(port); a.sin_addr.s_addr = ip;
    if (connect(fd, (struct sockaddr *)&a, sizeof a)) { r.error=1; goto done; }
    if (prefix && len) {
        if (send(fd,prefix,len,0) != (ssize_t)len) { r.error=1; goto done; }
        struct timespec pause = {0,15000000};
        while (nanosleep(&pause,&pause) && errno == EINTR) {}
    }
    unsigned misses = 0;
    uint32_t per_request = wait ? wait : 3000;
    int64_t series_end = milliseconds() + 15000;
    for (unsigned i = 0; r.received < D2K_DISCOVERY_EXCHANGES &&
         i < D2K_DISCOVERY_EXCHANGES + 6 && milliseconds() < series_end; i++) {
        uint8_t req[74] = {0,1,0,70}, seed[20], txid[12], reply[2048];
        if (!d2k_stun_request(seed,sizeof seed,txid)) { r.error=1; break; }
        /* Each request has a fresh SSRC, so delayed duplicates cannot
         * count as progress. These are our IDs, never the caller's SSRC. */
        memcpy(req+4,txid,4);
        if (send(fd,req,sizeof req,0) != sizeof req) { r.error=1; break; }
        r.sent++;
        int64_t end = milliseconds() + per_request;
        if (end > series_end) end = series_end;
        int answered = 0;
        while (milliseconds() < end) {
            struct pollfd p = {fd,POLLIN,0};
            int64_t left = end-milliseconds();
            if (left <= 0) break;
            int rc = poll(&p,1,(int)left);
            if (rc < 0 && errno == EINTR) continue;
            if (rc < 0) { r.error=1; break; }
            if (!rc) break;
            ssize_t n = recv(fd,reply,sizeof reply,0);
            if (n < 0) { if(errno==EINTR)continue; r.error=1; break; }
            if (d2k_discovery_response(reply,(size_t)n,req+4)) { answered=1; break; }
        }
        if (r.error) break;
        if (!answered) {
            if (++misses >= 3) break;
            continue;
        }
        misses = 0;
        r.received++;
    }
done:
    close(fd);
    return r;
}
d2k_discovery_probe_fn d2k_discovery_probe_hook = discovery_probe;

static int local_failure(d2k_voice_res *r, d2k_discovery_result q) {
    r->probes += (int)q.sent;
    if (!q.marked) r->marked = 0;
    if (!q.error && q.marked) return 0;
    r->verdict = D2K_VOICE_UNMEASURED;
    snprintf(r->reason,sizeof r->reason,"Discord IP Discovery: местная ошибка или неподтверждённая метка; кандидат не ставлю");
    return 1;
}
int d2k_voice_discovery_search(const d2k_voice_opt *o, d2k_voice_res *r) {
    if (o->known_discovery_prefix) {
        int failures = 0;
        for (int i = 0; i < D2K_VOICE_REPEATS; i++) {
            d2k_discovery_result q = d2k_discovery_probe_hook(r->ip, r->port,
                o->known_discovery_prefix, 20, o->wait_ms, o->mark);
            if (local_failure(r, q)) return 1;
            if (q.received != D2K_DISCOVERY_EXCHANGES) {
                failures++;
            }
        }
        if (failures > 0 && failures < D2K_VOICE_REPEATS) {
            r->verdict = D2K_VOICE_FLAKY;
            snprintf(r->reason, sizeof r->reason, "сохранённый STUN-префикс: серии разошлись; привязку не инвалидирую");
            return 1;
        }
        if (failures == D2K_VOICE_REPEATS) r->known_prefix_failed = 1;
        if (!failures) {
            r->verdict = D2K_VOICE_CLEAR;
            snprintf(r->reason, sizeof r->reason,
                "сохранённый STUN-префикс: 3/3 серии Discovery; BYPASS_PROBE_PASSED, звук не проверен");
            return 1;
        }
    }
    unsigned cutoff = 0;
    for (int i=0;i<D2K_VOICE_REPEATS;i++) {
        d2k_discovery_result q=d2k_discovery_probe_hook(r->ip,r->port,NULL,0,o->wait_ms,o->mark);
        if (local_failure(r,q)) return 1;
        if (!i && q.received == D2K_DISCOVERY_EXCHANGES) {
            r->verdict=D2K_VOICE_CLEAR;
            snprintf(r->reason,sizeof r->reason,"Discord IP Discovery напрямую: %u/%u ответов на одном потоке; поздний обрыв не воспроизведён (не проверка звука)",q.received,q.sent);
            return 1;
        }
        if (!i) cutoff=q.received;
        /* Finland field 09.10: zero or one initial answer, then silence.
         * This startup band is not normal packet loss: all three independent
         * direct flows stop here, and the remedy must sustain 75 replies. */
        int startup = cutoff <= 1 && q.received <= 1;
        if ((!startup && q.received != cutoff) || q.sent <= q.received) {
            r->verdict=D2K_VOICE_FLAKY;
            snprintf(r->reason,sizeof r->reason,"Discord IP Discovery: граница прекращения ответов не повторилась; кандидат не ставлю");
            return 1;
        }
    }
    uint8_t prefix[20], txid[12];
    /* Reuse the measured bytes, but never install on a new endpoint
     * merely because it belongs to Discord. The direct cut above is a gate. */
    if (o->candidate_discovery_prefix) memcpy(prefix, o->candidate_discovery_prefix, sizeof prefix);
    else if (!d2k_stun_request(prefix,sizeof prefix,txid)) {
        r->verdict=D2K_VOICE_UNMEASURED;
        snprintf(r->reason,sizeof r->reason,"не удалось сформировать STUN-префикс");
        return 1;
    }
    for (int i=0;i<D2K_VOICE_REPEATS;i++) {
        d2k_discovery_result q=d2k_discovery_probe_hook(r->ip,r->port,prefix,sizeof prefix,o->wait_ms,o->mark);
        if (local_failure(r,q)) return 1;
        if (q.received!=D2K_DISCOVERY_EXCHANGES) {
            if (!cutoff) return 0; /* no oracle or no measurable remedy; never infer from STUN silence */
            r->verdict=D2K_VOICE_UNMEASURED;
            snprintf(r->reason,sizeof r->reason,"Discord IP Discovery: прямой обрыв после %u ответов повторяется, STUN-префикс его устойчиво не снял",cutoff);
            return 1;
        }
    }
    r->verdict=D2K_VOICE_BLOCKED;
    r->discovery_verified=1;
    memcpy(r->arm_bytes,prefix,sizeof prefix); r->arm_len=sizeof prefix; r->arm_copies=1;
    snprintf(r->fake_arm,sizeof r->fake_arm,"stun-before-discovery");
    snprintf(r->reason,sizeof r->reason,"Discord IP Discovery: прямой поток 3/3 обрывается после %u ответов; STUN-префикс даёт 3/3 серии по %u ответов. Проверка медиасессии отдельно",cutoff,D2K_DISCOVERY_EXCHANGES);
    return 1;
}
