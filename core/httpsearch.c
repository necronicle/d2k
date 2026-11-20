/* httpsearch.c — поиск обхода открытого HTTP (задача 51, шаг 4), см.
 * d2k_httpsearch.h. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdarg.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "d2k_httpsearch.h"
#include "d2k_httpup.h"
#include "d2k_verify.h"
#include "d2k_plantlv.h"

uint16_t d2k_hs_probe_port = 80;
int d2k_hs_probe_ms = 6000;

/* Приманка — то же имя, что у TLS-поиска (SCHED_DECOY, core/sched.c):
   заведомо не связанное с целью и реально обслуживаемое. */
#define HS_DECOY "disk.rzd.ru"
/* Сколько ждать подтверждения датапата и события APPLIED после ответа. */
#define HS_ACK_MS     3000
#define HS_APPLIED_MS 500
/* Подтверждение — два опыта подряд; каждый проверяет два полных ответа
   на одной TCP-связи. Одиночный ответ не доказывает keep-alive. */
#define HS_CONFIRM    2

static int64_t mono_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

const char *d2k_hs_answer_name(d2k_hs_answer a) {
    switch (a) {
    case D2K_HS_REAL:         return "ответ сервера";
    case D2K_HS_INJECTED:     return "вставка провайдера";
    case D2K_HS_EARLY:        return "ответ раньше RTT/2 (не сервер)";
    case D2K_HS_GARBAGE:      return "не ответ HTTP";
    case D2K_HS_SILENT:       return "тишина";
    case D2K_HS_RESET:        return "сброс";
    case D2K_HS_CLOSED:       return "закрытие без ответа";
    case D2K_HS_CONNECT_FAIL: return "соединение не установилось";
    case D2K_HS_DECOY:        return "ответ на приманку, не на запрос цели";
    case D2K_HS_CUT:          return "обрыв тела ответа";
    default:                  return "нет";
    }
}

/* --- суждение ---------------------------------------------------------------- */

d2k_hs_answer d2k_hs_judge(const char *host, const char *head, size_t n,
                           int64_t rtt_us, int64_t reply_us) {
    /* Пропускаем ведущие промежуточные ответы 1xx (100 Continue, 103 Early
       Hints): они предшествуют ОКОНЧАТЕЛЬНОМУ ответу того же запроса, и судить
       надо его. Без этого «HTTP/1.1 100 …» перед финальным 421/400 читалось бы
       как код 100 и объявлялось ответом сервера. 101 — переключение протокола,
       не «продолжение», и финальным не считается. */
    size_t at = 0, end = 0;
    int code = 0;
    for (;;) {
        if (n - at < 12 || memcmp(head + at, "HTTP/1.", 7) != 0 ||
            (head[at + 7] != '0' && head[at + 7] != '1') || head[at + 8] != ' ' ||
            head[at + 9] < '1' || head[at + 9] > '5' ||
            head[at + 10] < '0' || head[at + 10] > '9' ||
            head[at + 11] < '0' || head[at + 11] > '9') {
            return D2K_HS_GARBAGE;
        }
        size_t e = 0;
        for (size_t i = at; i + 3 < n; i++) if (!memcmp(head + i, "\r\n\r\n", 4)) { e = i + 4; break; }
        if (!e) return D2K_HS_GARBAGE; /* status alone can precede a portal Location */
        code = (head[at + 9] - '0') * 100 + (head[at + 10] - '0') * 10 + (head[at + 11] - '0');
        if (code >= 100 && code < 200 && code != 101) {
            at = e;                       /* interim head; the final one follows */
            if (at + 12 > n) { return D2K_HS_GARBAGE; }
            continue;
        }
        end = e;
        break;
    }
    (void)end;
    char portal[256];
    /* Portal detection judges the FINAL response (head+at), so a legitimate
       interim 1xx prefix cannot hide an injected 30x to a provider portal. */
    if (host && d2k_httpup_portal_location(host, head + at, n - at, portal, sizeof portal)) {
        return D2K_HS_INJECTED;
    }
    /* ПРИМАНКА ДОШЛА ДО СЕРВЕРА (повторное ревью I-A): сервер принял её
       байты за начало запроса и ответил на склейку — 400/421 или ответ про
       имя приманки. Это не ответ цели, и подтверждать по нему план нельзя:
       такой план отдавал бы серверу приманку вместо каждого запроса. */
    if (code == 400 || code == 421) { return D2K_HS_DECOY; }
    {
        static const char decoy[] = HS_DECOY;
        const size_t dl = sizeof decoy - 1;
        for (size_t i = 0; i + dl <= n; i++) {
            if (!strncasecmp(head + i, decoy, dl)) { return D2K_HS_DECOY; }
        }
    }
    /* То же правило, что у датапата (http80.c): сервер не может ответить
       раньше, чем запрос дошёл до него и вернулся. */
    if (rtt_us > 0 && reply_us >= 0 && reply_us * 2 < rtt_us) {
        return D2K_HS_EARLY;
    }
    return D2K_HS_REAL;
}

/* --- зонд -------------------------------------------------------------------- */

static int hs_path_ok(const char *path) {
    if(!path||path[0]!='/'||path[1]=='/')return 0;
    size_t n=0;
    for(;path[n];n++) {
        unsigned char c=(unsigned char)path[n];
        if(n>=1023||c<=32||c>=127||c=='?'||c=='#'||c=='\\')return 0;
    }
    return n>0;
}

/* The capture is as large as the response reader's header limit: a real
   response with large headers must not look like garbage to the judge. */
typedef struct { int fd; int64_t first_us; struct timespec sent; char *head; size_t cap, used; } hs_reader;
static long hs_read(void *ctx, uint8_t *buf, size_t cap, int wait_ms, char *err, size_t errcap) {
    hs_reader *s=ctx; int64_t until=mono_ms()+wait_ms;
    for(;;) {
        int64_t left=until-mono_ms(); if(left<=0){snprintf(err,errcap,"HTTP read timeout");return -1;}
        struct pollfd p={s->fd,POLLIN,0};int rc=poll(&p,1,(int)left);
        if(rc<0&&errno==EINTR)continue;
        if(rc<=0){snprintf(err,errcap,"HTTP read timeout/error");return -1;}
        ssize_t n=recv(s->fd,buf,cap,0);
        if(n<0&&(errno==EINTR||errno==EAGAIN))continue;
        if(n<0){snprintf(err,errcap,"%s",strerror(errno));return -1;}
        if(n>0&&!s->used) {
            struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);
            s->first_us=(int64_t)(t.tv_sec-s->sent.tv_sec)*1000000+(t.tv_nsec-s->sent.tv_nsec)/1000;
        }
        if(n>0&&s->used<s->cap-1) {
            size_t take=(size_t)n;if(take>s->cap-1-s->used)take=s->cap-1-s->used;
            memcpy(s->head+s->used,buf,take);s->used+=take;s->head[s->used]=0;
        }
        return n;
    }
}

/* Bytes the judge scans: the whole header block, and no more body than the
   original 4 KiB capture did (the decoy name is searched there too). */
#define HS_JUDGE_SCAN 4095

static size_t hs_header_end(const char *h, size_t from, size_t n) {
    for (size_t i = from; i + 3 < n; i++)
        if (!memcmp(h + i, "\r\n\r\n", 4)) return i + 4;
    return 0;
}

/* Start and end offsets of the FINAL response header, skipping leading
 * interim 1xx (not 101) that precede it. 0 end if there is no complete final
 * header. The judge, the capture clamp and the reported status all key off the
 * final response, never the interim one. */
static size_t hs_final_header(const char *h, size_t n, size_t *start) {
    size_t at = 0;
    *start = 0;
    for (;;) {
        if (n - at < 12 || memcmp(h + at, "HTTP/1.", 7) != 0 ||
            (h[at + 7] != '0' && h[at + 7] != '1') || h[at + 8] != ' ' ||
            h[at + 9] < '1' || h[at + 9] > '5' ||
            h[at + 10] < '0' || h[at + 10] > '9' ||
            h[at + 11] < '0' || h[at + 11] > '9') { return 0; }
        size_t end = hs_header_end(h, at, n);
        if (!end) { return 0; }
        int code = (h[at + 9] - '0') * 100 + (h[at + 10] - '0') * 10 + (h[at + 11] - '0');
        if (code >= 100 && code < 200 && code != 101) { at = end; continue; }
        *start = at;
        return end;
    }
}

/* The server itself ended the connection after this complete response:
   explicit body framing (Content-Length, chunked, or 204/304) and an
   announced close (a "close" token, or HTTP/1.0 without "keep-alive"). A
   close-delimited body is never counted: an injected FIN looks the same. */
static int hs_announced_close(const char *h, size_t n) {
    size_t at = 0;
    for (;;) {
        size_t end = hs_header_end(h, at, n);
        if (!end || end - at < 16 || memcmp(h + at, "HTTP/1.", 7) || (h[at + 7] != '0' && h[at + 7] != '1') ||
            h[at + 8] != ' ' || h[at + 9] < '1' || h[at + 9] > '5' || h[at + 10] < '0' || h[at + 10] > '9' ||
            h[at + 11] < '0' || h[at + 11] > '9') return 0;
        int code = (h[at + 9] - '0') * 100 + (h[at + 10] - '0') * 10 + (h[at + 11] - '0');
        if (code < 200) { at = end; continue; }   /* interim head precedes the final one */
        int http10 = h[at + 7] == '0', tok_close = 0, tok_keep = 0, length = 0, chunked = 0;
        const char *line = memchr(h + at, '\n', end - at);
        while (line && (size_t)(line + 1 - h) < end - 2) {
            const char *p = line + 1, *e = memchr(p, '\r', (size_t)(h + end - p));
            if (!e) break;
            const char *colon = memchr(p, ':', (size_t)(e - p));
            if (colon) {
                size_t k = (size_t)(colon - p);
                const char *v = colon + 1;
                if (k == 10 && !strncasecmp(p, "Connection", 10)) {
                    while (v < e) {
                        while (v < e && (*v == ' ' || *v == '\t' || *v == ',')) v++;
                        const char *t = v;
                        while (v < e && *v != ',') v++;
                        const char *te = v;
                        while (te > t && (te[-1] == ' ' || te[-1] == '\t')) te--;
                        if (te - t == 5 && !strncasecmp(t, "close", 5)) tok_close = 1;
                        if (te - t == 10 && !strncasecmp(t, "keep-alive", 10)) tok_keep = 1;
                    }
                } else if (k == 14 && !strncasecmp(p, "Content-Length", 14)) {
                    length = 1;
                } else if (k == 17 && !strncasecmp(p, "Transfer-Encoding", 17)) {
                    while (v < e && (*v == ' ' || *v == '\t')) v++;
                    const char *te = e;
                    while (te > v && (te[-1] == ' ' || te[-1] == '\t')) te--;
                    chunked = te - v == 7 && !strncasecmp(v, "chunked", 7);
                }
            }
            line = memchr(e, '\n', (size_t)(h + end - e));
        }
        int framed = code == 204 || code == 304 || length || chunked;
        return framed && (tok_close || (http10 && !tok_keep));
    }
}

/* A successful exchange under the probe: two complete responses on one
   keep-alive connection, or one complete response after which the server
   itself announced the end of the connection (no second request possible). */
static int hs_exchange_ok(const d2k_hs_result *r) {
    return r->answer == D2K_HS_REAL &&
        (r->complete_responses >= 2 ||
         (r->server_closed && r->complete_responses == 1 && r->requests_sent == 1));
}

static void probe_run(const d2k_hs_job *job, d2k_hs_result *r, char *capture, size_t cap);
void d2k_hs_probe_run(const d2k_hs_job *job, d2k_hs_result *r) {
    size_t cap = D2K_VERIFY_HEADER_LIMIT + 1;
    char *capture = malloc(cap);
    if (!capture) {
        memset(r, 0, sizeof *r);
        r->answer = D2K_HS_NONE; r->fd = job ? job->fd : -1; r->seq = job ? job->seq : 0;
        snprintf(r->why, sizeof r->why, "local: no memory for the response capture");
        return;
    }
    probe_run(job, r, capture, cap);
    free(capture);
}

static void probe_run(const d2k_hs_job *job, d2k_hs_result *r, char *capture, size_t cap) {
    memset(r, 0, sizeof *r);
    r->answer = D2K_HS_CONNECT_FAIL;
    r->fd = job ? job->fd : -1;
    r->seq = job ? job->seq : 0;
    if (!job || job->fd < 0) { snprintf(r->why, sizeof r->why, "нет сокета"); return; }
    if(job->repeat_path[0]&&!hs_path_ok(job->repeat_path)) {
        r->answer=D2K_HS_GARBAGE;snprintf(r->why,sizeof r->why,"unsupported observed HTTP path");return;
    }
    int fd = job->fd;
#ifdef SO_NOSIGPIPE
    int no_sigpipe=1; (void)setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&no_sigpipe,sizeof no_sigpipe);
#endif
    struct sockaddr_storage ss;
    socklen_t sl;
    memset(&ss, 0, sizeof ss);
    if (job->family == 6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
        a->sin6_family = AF_INET6;
        a->sin6_port = htons(d2k_hs_probe_port);
        memcpy(&a->sin6_addr, job->addr, 16);
        sl = sizeof *a;
    } else {
        struct sockaddr_in *a = (struct sockaddr_in *)&ss;
        a->sin_family = AF_INET;
        a->sin_port = htons(d2k_hs_probe_port);
        memcpy(&a->sin_addr, job->addr, 4);
        sl = sizeof *a;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        snprintf(r->why, sizeof r->why, "fcntl: %s", strerror(errno));
        return;
    }
    int64_t t0 = mono_ms(), deadline = t0 + d2k_hs_probe_ms;
    struct timespec c0, c1;
    clock_gettime(CLOCK_MONOTONIC, &c0);
    int err = 0;
    if (connect(fd, (const struct sockaddr *)&ss, sl) != 0) {
        if (errno != EINPROGRESS) {
            err = errno;
        } else {
            struct pollfd p = {fd, POLLOUT, 0};
            int rc;
            do { rc = poll(&p, 1, (int)(deadline - mono_ms())); } while (rc < 0 && errno == EINTR);
            if (rc <= 0) {
                snprintf(r->why, sizeof r->why, "80 молчит %d мс", d2k_hs_probe_ms);
                return;
            }
            socklen_t el = sizeof err;
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0) { err = errno ? errno : EIO; }
        }
    }
    if (err) {
        snprintf(r->why, sizeof r->why, "80: %s", strerror(err));
        return;
    }
    clock_gettime(CLOCK_MONOTONIC, &c1);
    r->rtt_us = (int64_t)(c1.tv_sec - c0.tv_sec) * 1000000 + (c1.tv_nsec - c0.tv_nsec) / 1000;
    struct sockaddr_storage local; socklen_t local_len=sizeof local;
    if(getsockname(fd,(struct sockaddr *)&local,&local_len)) {
        snprintf(r->why,sizeof r->why,"local socket identity unavailable");return;
    }
    if(local.ss_family==AF_INET && job->family==4) {
        const struct sockaddr_in *a=(const struct sockaddr_in *)&local;
        memcpy(r->local_ip,&a->sin_addr,4);r->local_port=ntohs(a->sin_port);
    } else if(local.ss_family==AF_INET6 && job->family==6) {
        const struct sockaddr_in6 *a=(const struct sockaddr_in6 *)&local;
        memcpy(r->local_ip,&a->sin6_addr,16);r->local_port=ntohs(a->sin6_port);
    } else {snprintf(r->why,sizeof r->why,"unexpected local socket family");return;}

    char req[1536];
    for(unsigned request=0;request<2;request++) {
        const char *path=(request||job->cut)&&job->repeat_path[0]?job->repeat_path:"/";
        int rl=snprintf(req,sizeof req,"GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n",path,job->host);
        if(rl<=0||(size_t)rl>=sizeof req){r->answer=D2K_HS_GARBAGE;return;}
        hs_reader reader={0};reader.fd=fd;reader.head=capture;reader.cap=cap;capture[0]=0;
        clock_gettime(CLOCK_MONOTONIC,&reader.sent);
        int64_t until=mono_ms()+d2k_hs_probe_ms;size_t sent=0;
        while(sent<(size_t)rl) {
            ssize_t n=send(fd,req+sent,(size_t)rl-sent,
#ifdef MSG_NOSIGNAL
                MSG_NOSIGNAL
#else
                0
#endif
            );
            if(n>0){sent+=(size_t)n;continue;}
            if(n<0&&(errno==EAGAIN||errno==EINTR)) {
                int64_t left=until-mono_ms();if(left<=0)break;
                struct pollfd p={fd,POLLOUT,0};if(poll(&p,1,(int)left)>0)continue;
            }
            break;
        }
        if(sent!=(size_t)rl){r->answer=D2K_HS_CLOSED;snprintf(r->why,sizeof r->why,"HTTP request %u not sent",request+1);return;}
        r->requests_sent++;
        d2k_http_read_result response;
        d2k_http_read_response(hs_read,&reader,d2k_hs_probe_ms,&response,r->why,sizeof r->why);
        r->reply_us=reader.first_us;
        if(!reader.used){r->answer=strstr(r->why,"timeout")?D2K_HS_SILENT:D2K_HS_CLOSED;return;}
        if(response.local_limit) {
            /* Our reader's own limit: says nothing about the path. Never a cut. */
            char why[sizeof r->why];snprintf(why,sizeof why,"%s",r->why);
            snprintf(r->why,sizeof r->why,"local response limit: %.120s",why);
            r->answer=D2K_HS_NONE;return;
        }
        /* Judge the FINAL header in full (a large final Location must never be
           truncated by clamping to the interim 100's header), plus a bounded
           slice of body for the decoy-name scan. */
        size_t fstart=0, fend=hs_final_header(reader.head,reader.used,&fstart);
        size_t base=fend?fend:reader.used, judge_n=base;
        if(reader.used-base>HS_JUDGE_SCAN)judge_n=base+HS_JUDGE_SCAN; else judge_n=reader.used;
        r->answer=d2k_hs_judge(job->host,reader.head,judge_n,r->rtt_us,r->reply_us);
        if(response.reply.outcome==D2K_HTTP_BLOCKED)r->answer=D2K_HS_INJECTED;
        /* Status reflects the FINAL response, not an interim 100. */
        snprintf(r->status,sizeof r->status,"HTTP/1.1 %d",response.status);
        const char *line=reader.head+fstart,*eol=fend?memchr(line,'\r',reader.used-fstart):NULL;
        if(eol){size_t n=(size_t)(eol-line);if(n>=sizeof r->status)n=sizeof r->status-1;memcpy(r->status,line,n);r->status[n]=0;}
        if(r->answer!=D2K_HS_REAL)return;
        if(!response.complete) {
            /* Заголовки настоящего ответа пришли, тело — нет: обрыв, не мусор. */
            r->answer=D2K_HS_CUT;return;
        }
        r->complete_responses++;
        if(response.connection_close) {
            r->server_closed=hs_announced_close(reader.head,reader.used);
            snprintf(r->why,sizeof r->why,"%s",r->server_closed
                ? "server announced the end of the connection after a complete framed response"
                : "server closed connection: keep-alive not confirmed");
            return;
        }
    }
}

/* --- кандидаты --------------------------------------------------------------- */

static const char *const CANDS[] = {"split", "disorder", "fake-badsum", "fake-seqshift"};
#define N_CANDS (sizeof CANDS / sizeof CANDS[0])

size_t d2k_hs_candidate_count(void) { return N_CANDS; }
const char *d2k_hs_candidate_key(size_t i) { return i < N_CANDS ? CANDS[i] : NULL; }

/* Ключ измеренной порчи: «fake:» + признаки через «+» в порядке ttl,
   badsum, seqshift. Пишет строку признаков для плана в spec (через пробел). */
static int poison_key_spec(const char *key, char *spec, size_t cap) {
    if (strncmp(key, "fake:", 5) != 0 || !key[5] || strlen(key) > 39) { return -1; }
    char buf[48];
    snprintf(buf, sizeof buf, "%s", key + 5);
    size_t pos = 0;
    int have_ttl = 0, have_bad = 0, have_seq = 0, order = 0;
    spec[0] = '\0';
    for (char *tok = strtok(buf, "+"); tok; tok = strtok(NULL, "+")) {
        int rank;
        char *end = NULL;
        if (!strcmp(tok, "badsum")) { if (have_bad++) return -1; rank = 2; }
        else if (!strncmp(tok, "ttl=", 4)) {
            long v = strtol(tok + 4, &end, 10);
            if (have_ttl++ || !tok[4] || *end || v < 1 || v > 255) return -1;
            rank = 1;
        } else if (!strncmp(tok, "seqshift=", 9)) {
            long v = strtol(tok + 9, &end, 10);
            if (have_seq++ || !tok[9] || *end || v < -2147483647L || v > 2147483647L || v == 0) return -1;
            rank = 3;
        } else { return -1; }
        if (rank <= order) { return -1; }   /* канонический порядок */
        order = rank;
        int k = snprintf(spec + pos, cap - pos, "%s%s", pos ? " " : "", tok);
        if (k < 0 || (size_t)k >= cap - pos) { return -1; }
        pos += (size_t)k;
    }
    /* ttl одна приманку до сервера не останавливает наверняка. */
    if (have_ttl && !have_bad && !have_seq) { return -1; }
    return pos ? 0 : -1;
}

static int known_key(const char *k) {
    if (!strcmp(k,"fake-badsum-whole")) return 1;
    for (size_t i = 0; i < N_CANDS; i++) { if (!strcmp(CANDS[i], k)) return 1; }
    char spec[64];
    return poison_key_spec(k, spec, sizeof spec) == 0;
}

int d2k_hs_candidate_text(const char *key, const uint8_t id[16], char *buf, size_t cap) {
    if (!key || !buf || !known_key(key)) { return -1; }
    char idhex[33];
    for (int i = 0; i < 16; i++) { snprintf(idhex + 2 * i, 3, "%02x", id ? id[i] : 0); }
    int n = snprintf(buf, cap, "d2k-plan 1 11\nid %s\nproto tcp http\n", idhex);
    if (n < 0 || (size_t)n >= cap) { return -1; }
    size_t pos = (size_t)n;
#define ADD(...) do { int k_ = snprintf(buf + pos, cap - pos, __VA_ARGS__); \
                      if (k_ < 0 || (size_t)k_ >= cap - pos) { return -1; } \
                      pos += (size_t)k_; } while (0)
    if (!strncmp(key, "fake-", 5) || !strncmp(key, "fake:", 5)) {
        static const char fake[] = "GET / HTTP/1.1\r\nHost: " HS_DECOY "\r\n\r\n";
        char spec[64];
        if (!strcmp(key, "fake-badsum") || !strcmp(key,"fake-badsum-whole")) { snprintf(spec, sizeof spec, "badsum"); }
        else if (!strcmp(key, "fake-seqshift")) { snprintf(spec, sizeof spec, "seqshift=-66000"); }
        else if (poison_key_spec(key, spec, sizeof spec) != 0) { return -1; }
        ADD("payload 1 ");
        for (size_t i = 0; i < sizeof fake - 1; i++) { ADD("%02x", (unsigned char)fake[i]); }
        ADD("\n");
        ADD("poison 1 %s\n", spec);
        ADD("fake payload=1 poison=1 repeats=1 gap_us=0 place=before\n");
    }
    if(strcmp(key,"fake-badsum-whole")) ADD("split sni_middle +0\n");
    if (!strcmp(key, "disorder")) {
        /* Та же пауза между кусками, что у вопроса порядка в TLS-поиске
           (D2K_PACE_PIECE_US, compose.h). */
        ADD("order reverse\npace 12000\n");
    }
#undef ADD
    return 0;
}

/* Постоянный план кандидата — свой устойчивый идентификатор. */
static void stable_id(const char *key, uint8_t id[16]) {
    uint64_t h = 1469598103934665603ull;
    for (const char *p = "d2k-http:"; *p; p++) { h = (h ^ (uint8_t)*p) * 1099511628211ull; }
    for (const char *p = key; *p; p++) { h = (h ^ (uint8_t)*p) * 1099511628211ull; }
    for (int i = 0; i < 16; i++) { h = (h ^ (uint64_t)i) * 1099511628211ull; id[i] = (uint8_t)(h >> 56); }
}

static void fresh_id(uint8_t id[16]) {
    static uint64_t ctr;
    int fd = open("/dev/urandom", O_RDONLY);
    size_t got = 0;
    if (fd >= 0) {
        while (got < 16) {
            ssize_t r = read(fd, id + got, 16 - got);
            if (r > 0) { got += (size_t)r; continue; }
            if (r < 0 && errno == EINTR) { continue; }
            break;
        }
        close(fd);
    }
    if (got < 16) {
        uint64_t h = (uint64_t)mono_ms() ^ (++ctr * 0x9e3779b97f4a7c15ull);
        for (int i = 0; i < 16; i++) { h = h * 6364136223846793005ull + 1442695040888963407ull; id[i] = (uint8_t)(h >> 56); }
    }
    id[0] |= 1;   /* нулевой идентификатор — «нет идентичности» */
}

/* --- поиск ------------------------------------------------------------------- */

/* Program identity is the existing compiler's TLV with a neutral ID,
   not a fresh trial hash or an alternate spelling of its candidate key.
   A successful simplified probe cannot erase its owned live failure.
   Preserve the failing address, but publication is currently NAME-wide:
   success at another endpoint cannot authorize return to the failed one. */
typedef struct {
    char key[40];
    uint8_t addr[16];
    d2k_binding_context binding;
    uint64_t execution;
    int64_t request_ms;
} live_failure;

typedef struct {
    char host[256];
    uint8_t family;
    char key[40];          /* подтверждённый кандидат; "" — нет */
    char repeat_path[1024];
    int cut;               /* поиск идёт по обрыву ответа, не по порталу */
    int repro_gap, evidence_lost;
    live_failure *failures;
    size_t n_failures;
    int64_t installed_ms; /* diagnostic timestamp, never installation identity */
    uint8_t install_id[16], pending_plan_id[16], installed_plan_id[16];
    d2k_binding_context binding;
    int revoked;          /* old key is only a hypothesis, not saved success */
    uint64_t seq;          /* порядок подтверждения: свежие — первыми */
    int64_t no_before_ms;  /* раньше этого новый поиск/перепроверка не начинается */
    int64_t wall;          /* когда подтверждён (стенные часы, из файла) */
} rec;

typedef struct { char host[256]; uint8_t family, addr[16]; } pend;

/* ПРЕДЕЛЫ HTTP-СОСТОЯНИЯ — ПО ЖИЗНЕННОМУ ЦИКЛУ, А НЕ БЮДЖЕТ ПОИСКА.
   Поиск HTTP ведёт одну цель за раз, остальные ждут в очереди. Ждущих целей
   и записей без знания больше, чем задач у планировщика (SCHED_MAX_TASKS),
   держать незачем: столько целей система одновременно не ведёт, а цель,
   которой не хватило места, вернётся со следующим событием портала или
   обрыва. Переполнение — отказ «нет ресурсов» в журнале, не рост памяти.
   Записи со знанием (подтверждённый ключ, в том числе отозванный до
   перепроверки) не вытесняются никогда: это знание, а не ожидание. */
#define HS_PENDING_MAX 64
/* Провалы одной записи: (программа, адрес). Их держат, чтобы не вернуться к
   провалившейся паре. Больше 32 разных провалов у одного имени — запись уже
   не держит знание; дальше честнее признать свидетельство потерянным
   (evidence_lost → repro_gap, перепроверка с нуля), чем расти без конца. */
#define HS_FAILURES_MAX 32

enum { PH_IDLE = 0, PH_BASE, PH_ACK, PH_RUN, PH_APPLIED };
enum { HQ_OWN=0, HQ_SPLIT, HQ_CHECKSUM, HQ_PRODUCT, HQ_FALLBACK, HQ_END };

struct d2k_httpsearch {
    d2k_diag_observer diagnostic;
    void *diagnostic_ctx;
    uint64_t diagnostic_seq;
    d2k_hs_ops ops;
    rec *recs; size_t n_recs, cap_recs;
    char measured[8][40]; size_t n_measured;   /* ключи измеренной порчи */
    uint32_t job_seq;
    pend *q; size_t n_q, cap_q;
    uint64_t seq;
    struct {
        int phase;
        int64_t diagnostic_start;
        uint64_t diagnostic_id;
        char host[256];
        char repeat_path[1024];
        uint8_t family, addr[16];
        int recheck;
        int cut;
        char cands[N_CANDS * 4 + 8][40];
        size_t n_cands, idx;
        int ok;            /* настоящих ответов подряд у текущего кандидата */
        int cand_had_real;     /* текущий кандидат уже дал полноценный REAL */
        int cand_retried_cut;  /* текущий кандидат уже использовал повтор после CUT */
        size_t cand_idx_seen;  /* индекс кандидата для обнаружения смены idx */
        int any_had_real;      /* хотя бы один кандидат в поиске дал полноценный REAL */
        int question, next_question;
        int split_no, checksum_no;
        int split_conflict, checksum_conflict; /* not negative probe controls */
        int judged;        /* судимых испытаний: ответ сервера или вставка под планом */
        size_t conflicts;  /* passing probes contradicted by owned live failures */
        uint32_t job_seq;  /* номер текущего запуска зонда */
        int base_retries;  /* повторов базы после МЕСТНОГО отказа (поле 23.10.2026) */
        int fd;
        uint16_t sport;
        uint8_t trial[16], plan_id[16];
        int applied;
        uint16_t proof_sport;
        uint8_t proof_client[16];
        uint64_t executions[2];
        d2k_binding_context proof_binding;
        int64_t deadline;
        d2k_hs_result pending;
    } cur;
};

static void say(d2k_httpsearch *hs, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void say(d2k_httpsearch *hs, const char *fmt, ...) {
    if (!hs->ops.say) { return; }
    char line[600];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    hs->ops.say(hs->ops.ctx, line);
}

static int host_ok(const char *h) {
    size_t n = h ? strlen(h) : 0;
    if (n == 0 || n > 253) { return 0; }
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)h[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '.')) { return 0; }
    }
    /* Адрес IPv4 — не имя (ревью M-2). */
    const char *last = strrchr(h, '.');
    last = last ? last + 1 : h;
    if (!*last) { return 0; }
    for (; *last; last++) { if (*last < '0' || *last > '9') { return 1; } }
    return 0;
}

static rec *rec_find(const d2k_httpsearch *hs, const char *host, uint8_t family) {
    for (size_t i = 0; i < hs->n_recs; i++) {
        if (hs->recs[i].family == family && !strcasecmp(hs->recs[i].host, host)) {
            return &hs->recs[i];
        }
    }
    return NULL;
}

static int queued(const d2k_httpsearch *hs, const char *host, uint8_t family) {
    for (size_t i = 0; i < hs->n_q; i++)
        if (hs->q[i].family == family && !strcasecmp(hs->q[i].host, host)) return 1;
    return 0;
}

static int is_current(const d2k_httpsearch *hs, const rec *r) {
    return hs->cur.phase != PH_IDLE && hs->cur.family == r->family &&
           !strcasecmp(hs->cur.host, r->host);
}

/* Вытесняет одну запись без знания, которая не ведётся и не ждёт: ту, чей
   запрет повтора истёк раньше всех. 0 — освободила место, -1 — нечего. */
static int rec_evict(d2k_httpsearch *hs) {
    size_t victim = hs->n_recs;
    for (size_t i = 0; i < hs->n_recs; i++) {
        const rec *r = &hs->recs[i];
        if (r->key[0] || is_current(hs, r) || queued(hs, r->host, r->family)) continue;
        if (victim == hs->n_recs || r->no_before_ms < hs->recs[victim].no_before_ms) victim = i;
    }
    if (victim == hs->n_recs) return -1;
    free(hs->recs[victim].failures);
    memmove(&hs->recs[victim], &hs->recs[victim + 1],
            (hs->n_recs - victim - 1) * sizeof *hs->recs);
    hs->n_recs--;
    /* Ёмкость, которая больше не нужна, отдаётся. */
    if (hs->cap_recs > 16 && hs->n_recs * 4 <= hs->cap_recs) {
        rec *nv = realloc(hs->recs, hs->cap_recs / 2 * sizeof *nv);
        if (nv) { hs->recs = nv; hs->cap_recs /= 2; }
    }
    return 0;
}

static rec *rec_get(d2k_httpsearch *hs, const char *host, uint8_t family) {
    rec *r = rec_find(hs, host, family);
    if (r) { return r; }
    size_t unknown = 0;
    for (size_t i = 0; i < hs->n_recs; i++) unknown += !hs->recs[i].key[0];
    if (unknown >= HS_PENDING_MAX && rec_evict(hs) != 0) {
        say(hs, "HTTP %s: нет ресурсов — %d целей без знания уже ведутся или ждут", host, HS_PENDING_MAX);
        return NULL;
    }
    if (hs->n_recs == hs->cap_recs) {
        size_t nc = hs->cap_recs ? hs->cap_recs * 2 : 16;
        rec *nv = realloc(hs->recs, nc * sizeof *nv);
        if (!nv) { return NULL; }
        hs->recs = nv;
        hs->cap_recs = nc;
    }
    r = &hs->recs[hs->n_recs++];
    memset(r, 0, sizeof *r);
    snprintf(r->host, sizeof r->host, "%s", host);
    r->family = family;
    return r;
}

/* -1 means unknown, including compiler allocation failure. It must never
   be interpreted as evidence that a new program differs from a failed one. */
static int same_program(const char *a,const char *b) {
    if(!strcmp(a,b))return 1;
    char text[2048],err[160];uint8_t left[2048],right[2048];size_t ln=0,rn=0;
    if(d2k_hs_candidate_text(a,NULL,text,sizeof text) ||
       d2k_plan_text_to_tlv(text,left,sizeof left,&ln,err,sizeof err) ||
       d2k_hs_candidate_text(b,NULL,text,sizeof text) ||
       d2k_plan_text_to_tlv(text,right,sizeof right,&rn,err,sizeof err))return -1;
    return ln==rn && !memcmp(left,right,ln);
}

static const live_failure *failed_live(rec *r,const char *key,const uint8_t *addr) {
    if(r)for(size_t i=0;i<r->n_failures;i++) {
        const live_failure *f=&r->failures[i];
        if(addr && memcmp(f->addr,addr,r->family==6?16:4))continue;
        int same=same_program(f->key,key);
        if(same<0) { r->evidence_lost=1;r->repro_gap=1;return NULL; }
        if(same)return f;
    }
    return NULL;
}
static int remember_live_failure(rec *r,const uint8_t *addr,
    const d2k_binding_context *binding,uint64_t execution,int64_t request_ms) {
    if(failed_live(r,r->key,addr))return 0;
    if(r->evidence_lost)return -1;
    if(r->n_failures>=HS_FAILURES_MAX){r->evidence_lost=1;return -1;}
    live_failure *v=realloc(r->failures,(r->n_failures+1)*sizeof *v);
    if(!v)return -1;
    r->failures=v;
    live_failure *f=&v[r->n_failures++];memset(f,0,sizeof *f);
    snprintf(f->key,sizeof f->key,"%s",r->key);
    memcpy(f->addr,addr,r->family==6?16:4);f->binding=*binding;
    f->execution=execution;f->request_ms=request_ms;
    return 0;
}

int d2k_httpsearch_measured_poison(d2k_httpsearch *hs, const char *spec) {
    if (!hs || !spec) { return -1; }
    /* Строка признаков → канонический ключ. */
    char buf[64], key[48] = "fake:";
    char ttl[16] = "", seq[24] = "";
    int bad = 0;
    snprintf(buf, sizeof buf, "%s", spec);
    for (char *tok = strtok(buf, " \t"); tok; tok = strtok(NULL, " \t")) {
        if (!strcmp(tok, "badsum")) { bad = 1; }
        else if (!strncmp(tok, "ttl=", 4) && strlen(tok) < sizeof ttl) { snprintf(ttl, sizeof ttl, "%s", tok); }
        else if (!strncmp(tok, "seqshift=", 9) && strlen(tok) < sizeof seq) { snprintf(seq, sizeof seq, "%s", tok); }
        else { return -1; }
    }
    size_t n = 5;
    if (ttl[0]) { n += (size_t)snprintf(key + n, sizeof key - n, "%s", ttl); }
    if (bad) { n += (size_t)snprintf(key + n, sizeof key - n, "%sbadsum", n > 5 ? "+" : ""); }
    if (seq[0]) { n += (size_t)snprintf(key + n, sizeof key - n, "%s%s", n > 5 ? "+" : "", seq); }
    if (n == 5 || n >= sizeof key) { return -1; }
    /* Та же порча, что у заготовки, — ключ заготовки (одно имя на одно). */
    const char *use = key;
    if (!strcmp(key, "fake:badsum")) { use = "fake-badsum"; }
    else if (!strcmp(key, "fake:seqshift=-66000")) { use = "fake-seqshift"; }
    else if (!known_key(key)) { return -1; }
    for (size_t i = 0; i < hs->n_measured; i++) { if (!strcmp(hs->measured[i], use)) return 0; }
    if (hs->n_measured >= sizeof hs->measured / sizeof hs->measured[0]) { return -1; }
    snprintf(hs->measured[hs->n_measured++], sizeof hs->measured[0], "%s", use);
    return 0;
}

size_t d2k_hs_plan_poisons(const char *text, char out[][64], size_t cap) {
    size_t n = 0;
    if (!text || !strstr(text, "\nproto tcp tls\n")) { return 0; }
    for (const char *ln = text; ln && *ln && n < cap;) {
        unsigned id = 0;
        int used = 0;
        if (sscanf(ln, "poison %u %n", &id, &used) == 1 && used) {
            char ref[32];
            snprintf(ref, sizeof ref, " poison=%u ", id);
            const char *e = strchr(ln + used, '\n');
            size_t len = e ? (size_t)(e - (ln + used)) : strlen(ln + used);
            /* Порча именно приманки («fake … poison=N»), не перекрытия. */
            const char *f = strstr(text, "\nfake ");
            int is_fake = 0;
            while (f) {
                const char *fe = strchr(f + 1, '\n');
                size_t fl = fe ? (size_t)(fe - f) : strlen(f);
                char line[256];
                if (fl < sizeof line) {
                    memcpy(line, f, fl); line[fl] = ' '; line[fl + 1 < sizeof line ? fl + 1 : fl] = '\0';
                    if (strstr(line, ref)) { is_fake = 1; break; }
                }
                f = strstr(f + 1, "\nfake ");
            }
            if (is_fake && len > 0 && len < 64) {
                memcpy(out[n], ln + used, len);
                out[n][len] = '\0';
                n++;
            }
        }
        const char *nl = strchr(ln, '\n');
        ln = nl ? nl + 1 : NULL;
    }
    return n;
}

d2k_httpsearch *d2k_httpsearch_new(const d2k_hs_ops *ops) {
    d2k_httpsearch *hs = calloc(1, sizeof *hs);
    if (!hs) { return NULL; }
    if (ops) { hs->ops = *ops; }
    hs->cur.fd = -1;
    return hs;
}

static void drop_socket(d2k_httpsearch *hs) {
    if (hs->cur.fd >= 0) {
        if (hs->ops.close_port) { hs->ops.close_port(hs->ops.ctx, hs->cur.fd); }
        hs->cur.fd = -1;
    }
}

static void drop_probe(d2k_httpsearch *hs) {
    if (hs->cur.sport && hs->ops.del_probe) {
        hs->ops.del_probe(hs->ops.ctx, hs->cur.host, hs->cur.family, hs->cur.sport);
    }
    hs->cur.sport = 0;
}

void d2k_httpsearch_free(d2k_httpsearch *hs) {
    if (!hs) { return; }
    if (hs->cur.phase == PH_ACK || hs->cur.phase == PH_RUN) { drop_probe(hs); }
    drop_socket(hs);
    for(size_t i=0;i<hs->n_recs;i++)free(hs->recs[i].failures);
    free(hs->recs);
    free(hs->q);
    free(hs);
}

int d2k_httpsearch_busy(const d2k_httpsearch *hs) {
    return hs && hs->cur.phase != PH_IDLE;
}

const char *d2k_httpsearch_plan_of(const d2k_httpsearch *hs, const char *host, uint8_t family) {
    const rec *r = hs && host ? rec_find(hs, host, family) : NULL;
    return r && r->key[0] && !r->revoked ? r->key : NULL;
}

static void start_next(d2k_httpsearch *hs, int64_t now);

void d2k_httpsearch_diagnostic_counts(d2k_httpsearch *hs,d2k_diag_counts *c) {
    if(!c)return;
    c->http_records=hs?hs->n_recs:0;c->http_queued=hs?hs->n_q:0;
    c->memory.http_records_capacity=hs?hs->cap_recs:0;
    c->memory.http_records_bytes=hs?hs->cap_recs*sizeof *hs->recs:0;
    c->memory.http_queue_capacity=hs?hs->cap_q:0;
    c->memory.http_queue_bytes=hs?hs->cap_q*sizeof *hs->q:0;
    c->memory.http_failures=0;c->memory.http_failures_bytes=0;
    if(hs)for(size_t i=0;i<hs->n_recs;i++) {
        c->memory.http_failures+=hs->recs[i].n_failures;
        c->memory.http_failures_bytes+=hs->recs[i].n_failures*sizeof(live_failure);
    }
}
void d2k_httpsearch_diagnostics(d2k_httpsearch *hs,d2k_diag_observer fn,void *ctx) {
    if(hs){hs->diagnostic=fn;hs->diagnostic_ctx=ctx;}
}
static void diagnostic_end(d2k_httpsearch *hs,int64_t now,const char *outcome,const char *reason) {
    if(hs->diagnostic && hs->cur.diagnostic_id) {
        char ip[INET6_ADDRSTRLEN]="";
        (void)inet_ntop(hs->cur.family==6?AF_INET6:AF_INET,hs->cur.addr,ip,sizeof ip);
        d2k_diag_event e={.id=hs->cur.diagnostic_id,.target=hs->cur.host,.protocol="http",
            .family=hs->cur.family,.outcome=outcome,.reason=reason,
            .elapsed_ms=now-hs->cur.diagnostic_start,.queue_ms=-1,.probe_units=-1,
            .ip=ip,.path="httpsearch",.kind="name"};
        hs->diagnostic(hs->diagnostic_ctx,&e);
    }
    hs->cur.diagnostic_id=0;
}
static void finish(d2k_httpsearch *hs, int64_t now,const char *outcome,const char *reason) {
    diagnostic_end(hs,now,outcome,reason);
    drop_socket(hs);
    hs->cur.phase = PH_IDLE;
    hs->cur.sport = 0;
    start_next(hs, now);
}

static int open_job(d2k_httpsearch *hs, d2k_hs_job *job) {
    memset(job, 0, sizeof *job);
    int fd = -1;
    uint16_t sport = 0;
    if (!hs->ops.open_port || hs->ops.open_port(hs->ops.ctx, hs->cur.family, &fd, &sport) != 0 ||
        fd < 0 || !sport) {
        return -1;
    }
    hs->cur.fd = fd;
    hs->cur.sport = sport;
    hs->cur.proof_sport = ntohs(sport);
    job->fd = fd;
    job->family = hs->cur.family;
    memcpy(job->addr, hs->cur.addr, sizeof job->addr);
    snprintf(job->host, sizeof job->host, "%s", hs->cur.host);
    snprintf(job->repeat_path,sizeof job->repeat_path,"%s",hs->cur.repeat_path);
    job->cut=hs->cur.cut;
    return 0;
}

static void next_candidate(d2k_httpsearch *hs, int64_t now);

static void revoke_owned(d2k_httpsearch *hs,rec *r) {
    /* Keep the snapshot even after a failed write or a lost delete ACK.
       Repeating this conditional command cannot remove a replacement. */
    if(d2k_binding_known(&r->binding) && hs->ops.del_plan)
        (void)hs->ops.del_plan(hs->ops.ctx,r->host,r->family,&r->binding);
}

static void all_failed(d2k_httpsearch *hs, int64_t now) {
    rec *r = rec_get(hs, hs->cur.host, hs->cur.family);
    if (!hs->cur.judged) {
        /* Ни одного судимого испытания (ревью I-2): исполнение не
           подтвердилось, датапат отказал или не ответил. О коробке это
           ничего не говорит — план, если был, остаётся. */
        if (r) { r->no_before_ms = now + D2K_HS_INCONCLUSIVE_MS; }
        say(hs, "HTTP %s: поиск не измерен — ни один вопрос не дал исполненного опыта "
                "(нет APPLIED, отказ или молчание датапата)%s; повтор не раньше чем через "
                "%lld мин", hs->cur.host,
            r && r->key[0] && !r->revoked ? ", подтверждённый план оставлен" : "",
            (long long)(D2K_HS_INCONCLUSIVE_MS / 60000));
        finish(hs,now,"inconclusive","no-executed-trial");
        return;
    }
    if (r && r->key[0] && !r->revoked) {
        /* Перепроверка не подтвердила ни прежний план, ни другой: снимаем
           только свой постоянный план этого имени и формы HTTP. */
        r->revoked=1;
        revoke_owned(hs,r);
        r->key[0] = '\0';
        if (hs->ops.changed) { hs->ops.changed(hs->ops.ctx); }
    }
    if(hs->cur.conflicts) {
        if (r) { r->no_before_ms = now + D2K_HS_RETRY_MS; }
        say(hs,"HTTP %s: поиск завершён без принятого плана: %zu кандидатов прошли зонд, "
               "но имеют живой отказ в области привязки имени; воспроизведение не объясняет живой поток",
            hs->cur.host,hs->cur.conflicts);
        finish(hs,now,"inconclusive","live-conflict");return;
    }
    if (hs->cur.any_had_real) {
        if (r) { r->no_before_ms = now + D2K_HS_INCONCLUSIVE_MS; }
        say(hs, "HTTP %s: поиск завершён без подтверждения — ответ сервера был получен, "
                "но устойчивость не подтверждена; следующая попытка не раньше чем через %lld мин",
            hs->cur.host, (long long)(D2K_HS_INCONCLUSIVE_MS / 60000));
        finish(hs,now,"inconclusive","unstable-response");
        return;
    }
    if (r) { r->no_before_ms = now + D2K_HS_RETRY_MS; }
    say(hs, "HTTP %s: обход не найден — ни один вопрос не дал ответа сервера; "
            "следующая попытка не раньше чем через %lld мин", hs->cur.host,
        (long long)(D2K_HS_RETRY_MS / 60000));
    finish(hs,now,"failed","no-server-response");
}

static int install(d2k_httpsearch *hs,rec *r,const char *text,const uint8_t plan_id[16],int64_t now) {
    uint8_t token[16];fresh_id(token);
    if(!hs->ops.set_plan || hs->ops.set_plan(hs->ops.ctx,r->host,r->family,text,token))return -1;
    static const uint8_t none[16];
    if(memcmp(r->install_id,none,16)) {
        /* An unobserved SET may already have replaced the last known plan.
           A NACK of this newer command cannot restore that older identity. */
        memset(&r->binding,0,sizeof r->binding);
        memset(r->installed_plan_id,0,16);
    }
    memcpy(r->install_id,token,16);memcpy(r->pending_plan_id,plan_id,16);
    r->installed_ms=now;return 0;
}

void d2k_httpsearch_install_ack(d2k_httpsearch *hs,const uint8_t token[16],int ok,
    const d2k_binding_context *binding) {
    static const uint8_t zero[16];
    if(!hs || !token || !memcmp(token,zero,16))return;
    for(size_t i=0;i<hs->n_recs;i++) {
        rec *r=&hs->recs[i];
        if(memcmp(r->install_id,token,16))continue;
        memset(r->install_id,0,16);
        if(ok) {
            memset(&r->binding,0,sizeof r->binding);
            memset(r->installed_plan_id,0,16);
            if(d2k_binding_known(binding) && binding->kind==D2K_BIND_NAME &&
               !binding->temporary && binding->family==r->family && binding->shape==D2K_PLAN_SHAPE_HTTP) {
                r->binding=*binding;
                memcpy(r->installed_plan_id,r->pending_plan_id,16);
            }
        }
        memset(r->pending_plan_id,0,16);
        if(!ok || !d2k_binding_known(&r->binding))
            say(hs,"HTTP %s: новая установка не подтверждена известной привязкой — живая приёмка неизвестна",r->host);
        if(r->revoked)revoke_owned(hs,r);
        return;
    }
}

static void confirmed(d2k_httpsearch *hs, int64_t now) {
    const char *key = hs->cur.cands[hs->cur.idx];
    uint8_t id[16];
    char text[2048];
    stable_id(key, id);
    rec *r = rec_get(hs, hs->cur.host, hs->cur.family);
    const live_failure *failure=failed_live(r,key,NULL);
    if(r && r->evidence_lost) {
        say(hs,"HTTP %s: сравнение программ неизвестно или история живых отказов утрачена — "
               "зонд не разрешает публикацию, требуется воспроизведение живого контекста",hs->cur.host);
        finish(hs,now,"inconclusive","evidence-lost");return;
    }
    if(failure) {
        say(hs,"HTTP %s: «%s» — зонд прошёл, но живой отказ execution=%llu generation=%llu "
               "не снят; привязка действует на всё имя, план не возвращаю, продолжаю вопросы",
            hs->cur.host,key,(unsigned long long)failure->execution,
            (unsigned long long)failure->binding.generation);
        hs->cur.conflicts++;hs->cur.ok=0;hs->cur.idx++;
        if(!strcmp(key,"split"))hs->cur.split_conflict=1;
        if(!strcmp(key,"fake-badsum-whole"))hs->cur.checksum_conflict=1;
        if(hs->cur.question==HQ_SPLIT)hs->cur.next_question=HQ_CHECKSUM;
        else if(hs->cur.question==HQ_CHECKSUM)hs->cur.next_question=HQ_PRODUCT;
        next_candidate(hs,now);return;
    }
    if (d2k_hs_candidate_text(key, id, text, sizeof text) != 0 || !r ||
        install(hs,r,text,id,now) != 0) {
        say(hs, "HTTP %s: план «%s» подтверждён, но не поставлен датапату", hs->cur.host, key);
        finish(hs,now,"local-abort","plan-install-failed");
        return;
    }
    snprintf(r->key, sizeof r->key, "%s", key);
    r->installed_ms = now;
    r->revoked = 0;
    r->seq = ++hs->seq;
    r->wall = 0;
    r->no_before_ms = now + D2K_HS_RECHECK_MS;
    if (hs->ops.changed) { hs->ops.changed(hs->ops.ctx); }
    if(hs->cur.question>=HQ_SPLIT && hs->cur.question<=HQ_PRODUCT)
        say(hs,"HTTP %s: путь: свойство — %s; тот же запрос, APPLIED и два опыта с полными ответами без вставки",
            hs->cur.host,hs->cur.question==HQ_PRODUCT ?
            (hs->cur.split_no && hs->cur.checksum_no ? "разрез и checksum-приманка вместе после двух отрицательных контролей" :
             "разрез и checksum-приманка вместе после живого отказа одиночного приёма; парные контроли зонда не доказаны") :
            hs->cur.question==HQ_CHECKSUM ? "checksum-приманка перед целым запросом" : "разрез имени");
    say(hs, "HTTP %s: обход найден — «%s», %d опыта подряд с полными ответами (два по keep-alive либо один, "
            "после которого сервер сам объявил закрытие) под пробным "
            "планом; отправлен на установку (HTTP), живая приёмка ещё не подтверждена", hs->cur.host, key, HS_CONFIRM);
    finish(hs,now,"probe-confirmed","probe-confirmed-live-unknown");
}

static void add_cand(d2k_httpsearch *, const char *);
static void build_fallback(d2k_httpsearch *);

static int trial_executed(const d2k_httpsearch *hs,const d2k_hs_result *r) {
    return r->requests_sent>0 && r->requests_sent<=2 &&
        r->complete_responses<=r->requests_sent &&
        (unsigned)hs->cur.applied>=r->requests_sent &&
        r->local_port==hs->cur.proof_sport &&
        !memcmp(r->local_ip,hs->cur.proof_client,hs->cur.family==6?16:4);
}

static void judge_trial(d2k_httpsearch *hs, const d2k_hs_result *r, int64_t now) {
    const char *key = hs->cur.cands[hs->cur.idx];
    if (!trial_executed(hs,r)) {
        say(hs, "HTTP %s: «%s» — исполнение каждого запроса на потоке зонда не подтверждено "
            "(APPLIED %d, отправлено запросов %u), кандидат не судим",
            hs->cur.host, key,hs->cur.applied,r->requests_sent);
        hs->cur.ok = 0;
        hs->cur.idx++;
        next_candidate(hs, now);
        return;
    }
    if (hs_exchange_ok(r) || r->answer == D2K_HS_INJECTED ||
        r->answer == D2K_HS_CUT) { hs->cur.judged++; }
    if (hs_exchange_ok(r)) {
        hs->cur.cand_had_real = 1;
        hs->cur.any_had_real = 1;
        hs->cur.ok++;
        say(hs, "HTTP %s: «%s» — ответ сервера (%s), RTT %lld мкс, ответ через %lld мкс",
            hs->cur.host, key, r->status, (long long)r->rtt_us, (long long)r->reply_us);
        if (hs->cur.ok >= HS_CONFIRM) { confirmed(hs, now); return; }
        next_candidate(hs, now);     /* тот же кандидат ещё раз */
        return;
    }
    if (r->answer == D2K_HS_CUT && hs->cur.cand_had_real && !hs->cur.cand_retried_cut) {
        hs->cur.cand_retried_cut = 1;
        hs->cur.ok = 0;
        say(hs, "HTTP %s: «%s» — обрыв тела ответа после успешного ответа сервера "
                "(запросов %u, полных ответов %u), диагностический повтор: %s",
            hs->cur.host, key, r->requests_sent, r->complete_responses, r->why);
        next_candidate(hs, now);
        return;
    }
    if(r->answer==D2K_HS_REAL)
        say(hs,"HTTP %s: одиночный ответ без подтверждения keep-alive — кандидат не подтверждён",hs->cur.host);
    if(r->answer==D2K_HS_CUT) {
        say(hs, "HTTP %s: «%s» — %s (запросов %u, полных ответов %u)%s%s", hs->cur.host, key,
            d2k_hs_answer_name(r->answer), r->requests_sent, r->complete_responses,
            r->why[0] ? ": " : "", r->why);
    } else {
        say(hs, "HTTP %s: «%s» — %s%s%s", hs->cur.host, key, d2k_hs_answer_name(r->answer),
            r->why[0] ? ": " : "", r->why);
    }
    if(r->answer!=D2K_HS_REAL && r->answer!=D2K_HS_CONNECT_FAIL && r->answer!=D2K_HS_NONE) {
        if(!strcmp(key,"split")) hs->cur.split_no=1;
        if(!strcmp(key,"fake-badsum-whole")) hs->cur.checksum_no=1;
        if(hs->cur.question==HQ_SPLIT) hs->cur.next_question=HQ_CHECKSUM;
        else if(hs->cur.question==HQ_CHECKSUM) hs->cur.next_question=HQ_PRODUCT;
    }
    hs->cur.ok = 0;
    hs->cur.idx++;
    next_candidate(hs, now);
}

static void next_candidate(d2k_httpsearch *hs, int64_t now) {
    drop_socket(hs);
    hs->cur.sport = 0;
    while(hs->cur.idx>=hs->cur.n_cands) {
        if(hs->cur.next_question==HQ_SPLIT && (hs->cur.split_no || hs->cur.split_conflict)) hs->cur.next_question=HQ_CHECKSUM;
        if(hs->cur.next_question==HQ_CHECKSUM && (hs->cur.checksum_no || hs->cur.checksum_conflict)) hs->cur.next_question=HQ_PRODUCT;
        hs->cur.question=hs->cur.next_question;
        hs->cur.next_question=HQ_FALLBACK;
        switch(hs->cur.question) {
        case HQ_SPLIT: add_cand(hs,"split"); break;
        case HQ_CHECKSUM: add_cand(hs,"fake-badsum-whole"); break;
        case HQ_PRODUCT: add_cand(hs,"fake-badsum"); break;
        case HQ_FALLBACK: build_fallback(hs); hs->cur.next_question=HQ_END; break;
        default: break;
        }
        if(hs->cur.question==HQ_END) { all_failed(hs,now); return; }
    }
    if (hs->cur.idx != hs->cur.cand_idx_seen) {
        hs->cur.cand_had_real = 0;
        hs->cur.cand_retried_cut = 0;
        hs->cur.cand_idx_seen = hs->cur.idx;
    }
    const char *key = hs->cur.cands[hs->cur.idx];
    char text[2048];
    d2k_hs_job job;
    fresh_id(hs->cur.plan_id);
    fresh_id(hs->cur.trial);
    hs->cur.applied = 0;
    memset(hs->cur.executions,0,sizeof hs->cur.executions);
    memset(&hs->cur.proof_binding,0,sizeof hs->cur.proof_binding);
    memset(hs->cur.proof_client,0,sizeof hs->cur.proof_client);
    if (d2k_hs_candidate_text(key, hs->cur.plan_id, text, sizeof text) != 0 ||
        open_job(hs, &job) != 0) {
        say(hs, "HTTP %s: «%s» — сокет зонда не открылся, поиск остановлен", hs->cur.host, key);
        finish(hs,now,"local-abort","probe-build-or-socket");
        return;
    }
    if (!hs->ops.set_probe ||
        hs->ops.set_probe(hs->ops.ctx, hs->cur.host, hs->cur.family, hs->cur.sport,
                          text, hs->cur.trial) != 0) {
        say(hs, "HTTP %s: «%s» — пробный план не отправлен датапату, поиск остановлен",
            hs->cur.host, key);
        hs->cur.sport = 0;
        finish(hs,now,"local-abort","probe-install-failed");
        return;
    }
    hs->cur.phase = PH_ACK;
    hs->cur.deadline = now + HS_ACK_MS;
}

static void add_cand(d2k_httpsearch *hs, const char *key) {
    for (size_t i = 0; i < hs->cur.n_cands; i++) { if (!strcmp(hs->cur.cands[i], key)) return; }
    if (hs->cur.n_cands < sizeof hs->cur.cands / sizeof hs->cur.cands[0]) {
        snprintf(hs->cur.cands[hs->cur.n_cands++], sizeof hs->cur.cands[0], "%s", key);
    }
}

static void build_cands(d2k_httpsearch *hs) {
    hs->cur.n_cands = 0;
    hs->cur.idx = 0;
    hs->cur.ok = 0;
    hs->cur.cand_had_real = 0;
    hs->cur.cand_retried_cut = 0;
    hs->cur.cand_idx_seen = (size_t)-1;
    hs->cur.any_had_real = 0;
    /* Свой план этого имени (перепроверка), затем свои подтверждённые
       планы других имён — свежие первыми, затем вопросы по порядку. */
    rec *own = rec_find(hs, hs->cur.host, hs->cur.family);
    if (own && own->key[0]) { add_cand(hs, own->key); }
    for (;;) {
        const rec *best = NULL;
        for (size_t i = 0; i < hs->n_recs; i++) {
            const rec *r = &hs->recs[i];
            if (!r->key[0] || r->revoked) continue;
            int have = 0;
            for (size_t k = 0; k < hs->cur.n_cands; k++) { if (!strcmp(hs->cur.cands[k], r->key)) have = 1; }
            if (have) continue;
            if (!best || r->seq > best->seq) best = r;
        }
        if (!best) break;
        add_cand(hs, best->key);
    }
    hs->cur.question=HQ_OWN;
    hs->cur.next_question=HQ_SPLIT;
}

static void build_fallback(d2k_httpsearch *hs) {
    add_cand(hs, "split");
    add_cand(hs, "disorder");
    if (hs->n_measured) {
        /* Порча, измеренная на этой линии, — вместо заготовок. */
        for (size_t i = 0; i < hs->n_measured; i++) { add_cand(hs, hs->measured[i]); }
    } else {
        /* Измеренной нет — заготовки (гипотезы TLS-поиска). */
        add_cand(hs, "fake-badsum");
        add_cand(hs, "fake-seqshift");
    }
}

static void start(d2k_httpsearch *hs, const char *host, uint8_t family, const uint8_t *addr,
                  int recheck, int64_t now) {
    memset(&hs->cur, 0, sizeof hs->cur);
    hs->cur.cand_idx_seen = (size_t)-1;
    hs->cur.diagnostic_start=now;hs->cur.diagnostic_id=++hs->diagnostic_seq;
    hs->cur.fd = -1;
    snprintf(hs->cur.host, sizeof hs->cur.host, "%s", host);
    hs->cur.family = family;
    memcpy(hs->cur.addr, addr, family == 6 ? 16 : 4);
    hs->cur.recheck = recheck;
    rec *context=rec_find(hs,host,family);
    if(context&&context->repro_gap) {
        say(hs,"HTTP %s: контекст запроса утрачен или не поддержан — воспроизведение не начато",host);
        diagnostic_end(hs,now,"inconclusive","request-context-unavailable");return;
    }
    if(context)snprintf(hs->cur.repeat_path,sizeof hs->cur.repeat_path,"%s",context->repeat_path);
    if(context)hs->cur.cut=context->cut;
    d2k_hs_job job;
    hs->cur.job_seq = ++hs->job_seq;
    int opened = open_job(hs, &job) == 0;
    job.seq = hs->cur.job_seq;
    if (!opened || !hs->ops.start_probe || hs->ops.start_probe(hs->ops.ctx, &job) != 0) {
        say(hs, "HTTP %s: зонд не запустился — поиск не начат", host);
        diagnostic_end(hs,now,"local-abort","probe-start-failed");
        drop_socket(hs);
        hs->cur.phase = PH_IDLE;
        return;
    }
    /* База — без пробного плана: проба на этом порту не ставилась. */
    hs->cur.sport = 0;
    hs->cur.phase = PH_BASE;
    hs->cur.deadline = now + (int64_t)d2k_hs_probe_ms * 3;
    say(hs, "HTTP %s: %s — база: тот же запрос своим зондом без плана", host,
        hs->cur.cut ? (recheck ? "обрыв ответа при подтверждённом плане, перепроверка"
                               : "обрыв ответа без портала — поиск обхода HTTP")
        : recheck ? "вставка при подтверждённом плане, перепроверка"
                  : "вставка провайдера, HTTPS у имени нет — поиск обхода HTTP");
}

/* Опустевшая очередь отдаёт память: всплеск порталов не держит её навсегда. */
static void queue_trim(d2k_httpsearch *hs) {
    if (hs->n_q == 0 && hs->q) { free(hs->q); hs->q = NULL; hs->cap_q = 0; }
}

static void start_next(d2k_httpsearch *hs, int64_t now) {
    while (hs->cur.phase == PH_IDLE && hs->n_q) {
        pend p = hs->q[0];
        memmove(hs->q, hs->q + 1, (hs->n_q - 1) * sizeof *hs->q);
        hs->n_q--;
        rec *r = rec_find(hs, p.host, p.family);
        start(hs, p.host, p.family, p.addr, r && r->key[0], now);
    }
    queue_trim(hs);
}

static rec *live_owner(d2k_httpsearch *hs,const char *host,uint8_t family,
    const uint8_t plan_id[16],const d2k_binding_context *binding,uint64_t execution_id,int64_t request_ms) {
    static const uint8_t no_pending[16];
    if(!hs || !plan_id || !execution_id || request_ms<=0 || !host_ok(host) || (family!=4 && family!=6))return NULL;
    rec *r=rec_find(hs,host,family);
    if(!r || !r->key[0] || r->revoked || !d2k_binding_equal(&r->binding,binding) ||
       memcmp(r->install_id,no_pending,16) || memcmp(r->installed_plan_id,plan_id,16))return NULL;
    return r;
}

int d2k_httpsearch_bound_failure(d2k_httpsearch *hs, const char *host, uint8_t family,
                                const uint8_t *addr, const uint8_t plan_id[16], const d2k_binding_context *binding, uint64_t execution_id, int64_t request_ms, const char *path, int64_t now) {
    if(!addr)return 0;
    rec *r=live_owner(hs,host,family,plan_id,binding,execution_id,request_ms);
    if(!r)return 0;
    if(remember_live_failure(r,addr,binding,execution_id,request_ms))r->evidence_lost=1;
    r->revoked=1;r->no_before_ms=0;
    r->repro_gap=!hs_path_ok(path) || r->evidence_lost;
    r->repeat_path[0]=0;
    if(!r->repro_gap)snprintf(r->repeat_path,sizeof r->repeat_path,"%s",path);
    revoke_owned(hs,r);
    if(hs->ops.changed)hs->ops.changed(hs->ops.ctx);
    say(hs,"HTTP %s: связанная вставка под постоянным планом — успех отозван, нужна перепроверка",host);
    if(hs->cur.phase!=PH_IDLE&&hs->cur.family==family&&!strcasecmp(hs->cur.host,host)) {
        drop_probe(hs);finish(hs,now,"cancelled","context-changed");
    }
    d2k_httpsearch_portal(hs,host,family,addr,now);
    return 1;
}

int d2k_httpsearch_control(d2k_httpsearch *hs,const d2k_ev *ev,int64_t now) {
    if(!hs || !ev)return 0;
    if(ev->kind==D2K_EV_APPLIED)return d2k_httpsearch_applied(hs,ev);
    if(ev->kind==D2K_EV_ACK && ev->code==D2K_CMD_SET_NAME_BOUND)
        d2k_httpsearch_install_ack(hs,ev->trial_id,((ev->num>>8)&0xffu)==1u,&ev->execution_binding);
    if(ev->kind==D2K_EV_HTTP_RESPONSE && (ev->code==1 || ev->code==2) &&
       ev->transport==6 && ev->high_port==80 && ev->live_request_no) {
        static const uint8_t zero[16];
        rec *r=live_owner(hs,ev->name,ev->family,ev->plan_id,&ev->execution_binding,
                          ev->live_execution,ev->live_request_ms);
        if(!r || memcmp(ev->trial_id,zero,16))return 0;
        /* Per-request observation, never persistent target/application DONE. */
        say(hs,"HTTP live target=%s IPv%u request=%llu execution=%llu plan=%s generation=%llu outcome=%s status=%u body=%llu; scope=request, connection=pending",
            ev->name,(unsigned)ev->family,(unsigned long long)ev->live_request_no,
            (unsigned long long)ev->live_execution,r->key,(unsigned long long)ev->execution_binding.generation,
            ev->code==2?"unknown":"response-complete",(unsigned)ev->live_http_status,(unsigned long long)ev->live_body_bytes);
        return 1;
    }
    if(ev->kind==D2K_EV_HTTP_RESPONSE && ev->code==4 && ev->transport==6 && ev->high_port==80) {
        d2k_httpsearch_cut(hs,ev->name,ev->family,ev->high_ip,ev->live_http_path,ev->live_body_bytes,now);
        return 1;
    }
    if(((ev->kind==D2K_EV_HTTP_PORTAL && !ev->code) ||
        (ev->kind==D2K_EV_HTTP_RESPONSE && ev->code==3)) && ev->transport==6 && ev->high_port==80) {
        static const uint8_t zero[16];
        if(!memcmp(ev->trial_id,zero,16))
            return d2k_httpsearch_bound_failure(hs,ev->name,ev->family,ev->high_ip,ev->plan_id,
                &ev->execution_binding,ev->live_execution,ev->live_request_ms,ev->live_http_path,now);
    }
    return 0;
}

/* ОБРЫВ ОТВЕТА БЕЗ ПОРТАЛА (поле 15.10.2026, media5.cdnbase.com: стили
   fast-torrent рвались на 33120 из 106050 байт, ни портала, ни RST). Датапат
   сообщил ответ с заявленной длиной, вставший раньше конца (код 4). Поиск —
   тем же путём, что у портала, но база и кандидаты мерят ресурс клиента, и
   «не взят» значит обрыв тела, а успех — два полных тела подряд. */
void d2k_httpsearch_cut(d2k_httpsearch *hs, const char *host, uint8_t family,
                        const uint8_t *addr, const char *path, uint64_t got, int64_t now) {
    if (!hs || !addr || (family != 4 && family != 6) || !host_ok(host)) { return; }
    if (!hs_path_ok(path)) {
        say(hs, "HTTP %s: обрыв ответа на пути, который зонд не повторит, — поиск не начат", host);
        return;
    }
    rec *r = rec_get(hs, host, family);
    if (!r) { return; }
    if (hs->cur.phase != PH_IDLE && hs->cur.family == family && !strcasecmp(hs->cur.host, host)) { return; }
    if (!r->cut || !r->repeat_path[0]) {
        r->cut = 1;
        snprintf(r->repeat_path, sizeof r->repeat_path, "%s", path);
    }
    r->repro_gap = 0;
    say(hs, "HTTP %s: обрыв ответа на %s после %llu байт тела — до заявленной длины не дошло",
        host, path, (unsigned long long)got);
    d2k_httpsearch_portal(hs, host, family, addr, now);
}

void d2k_httpsearch_portal(d2k_httpsearch *hs, const char *host, uint8_t family,
                           const uint8_t *addr, int64_t now) {
    if (!hs || !addr || (family != 4 && family != 6) || !host_ok(host)) { return; }
    if (hs->cur.phase != PH_IDLE && hs->cur.family == family && !strcasecmp(hs->cur.host, host)) {
        return;
    }
    for (size_t i = 0; i < hs->n_q; i++) {
        if (hs->q[i].family == family && !strcasecmp(hs->q[i].host, host)) { return; }
    }
    rec *r = rec_find(hs, host, family);
    if(r&&r->repro_gap) {
        say(hs,"HTTP %s: контекст запроса утрачен или не поддержан — подтверждение по GET / запрещено",host);return;
    }
    if (r && (!r->key[0] || r->revoked) && now < r->no_before_ms) { return; }
    if (hs->cur.phase == PH_IDLE) {
        start(hs, host, family, addr, r && r->key[0], now);
        return;
    }
    if (hs->n_q >= HS_PENDING_MAX) {
        say(hs, "HTTP %s: нет ресурсов — очередь из %d целей полна, цель вернётся со следующим событием", host, HS_PENDING_MAX);
        return;
    }
    if (hs->n_q == hs->cap_q) {
        size_t nc = hs->cap_q ? hs->cap_q * 2 : 8;
        pend *nv = realloc(hs->q, nc * sizeof *nv);
        if (!nv) { return; }
        hs->q = nv;
        hs->cap_q = nc;
    }
    pend *p = &hs->q[hs->n_q++];
    memset(p, 0, sizeof *p);
    snprintf(p->host, sizeof p->host, "%s", host);
    p->family = family;
    memcpy(p->addr, addr, family == 6 ? 16 : 4);
}

void d2k_httpsearch_ack(d2k_httpsearch *hs, const uint8_t trial[16], int ok, int64_t now) {
    if (!hs || hs->cur.phase != PH_ACK || memcmp(trial, hs->cur.trial, 16) != 0) { return; }
    const char *key = hs->cur.cands[hs->cur.idx];
    if (!ok) {
        /* Местный отказ датапата — опыта не было, кандидат не судим. */
        say(hs, "HTTP %s: «%s» — датапат отверг пробный план, кандидат не судим",
            hs->cur.host, key);
        hs->cur.sport = 0;
        hs->cur.ok = 0;
        hs->cur.idx++;
        next_candidate(hs, now);
        return;
    }
    d2k_hs_job job;
    memset(&job, 0, sizeof job);
    hs->cur.job_seq = ++hs->job_seq;
    job.seq = hs->cur.job_seq;
    job.fd = hs->cur.fd;
    job.family = hs->cur.family;
    memcpy(job.addr, hs->cur.addr, sizeof job.addr);
    snprintf(job.host, sizeof job.host, "%s", hs->cur.host);
    snprintf(job.repeat_path,sizeof job.repeat_path,"%s",hs->cur.repeat_path);
    job.cut=hs->cur.cut;
    if (!hs->ops.start_probe || hs->ops.start_probe(hs->ops.ctx, &job) != 0) {
        say(hs, "HTTP %s: зонд не запустился — поиск остановлен", hs->cur.host);
        drop_probe(hs);
        finish(hs,now,"local-abort","probe-start-failed");
        return;
    }
    hs->cur.phase = PH_RUN;
    hs->cur.deadline = now + (int64_t)d2k_hs_probe_ms * 3;
}

int d2k_httpsearch_applied(d2k_httpsearch *hs, const d2k_ev *ev) {
    if (!hs || !ev || ev->kind!=D2K_EV_APPLIED ||
        (hs->cur.phase != PH_RUN && hs->cur.phase != PH_APPLIED) ||
        ev->transport!=6 || ev->family!=hs->cur.family || !ev->execution_id ||
        memcmp(ev->plan_id,hs->cur.plan_id,16) || memcmp(ev->trial_id,hs->cur.trial,16) ||
        !d2k_binding_known(&ev->execution_binding) ||
        ev->execution_binding.kind!=D2K_BIND_NAME || !ev->execution_binding.temporary ||
        ev->execution_binding.family!=hs->cur.family || ev->execution_binding.shape!=D2K_PLAN_SHAPE_HTTP) return 0;
    size_t n=hs->cur.family==6?16:4;
    const uint8_t *client=NULL;
    if(ev->high_port==80 && ev->low_port==hs->cur.proof_sport && !memcmp(ev->high_ip,hs->cur.addr,n))client=ev->low_ip;
    else if(ev->low_port==80 && ev->high_port==hs->cur.proof_sport && !memcmp(ev->low_ip,hs->cur.addr,n))client=ev->high_ip;
    if(!client)return 0;
    if(hs->cur.applied && (!d2k_binding_equal(&hs->cur.proof_binding,&ev->execution_binding) ||
                           memcmp(client,hs->cur.proof_client,n)))return 0;
    for(int i=0;i<hs->cur.applied;i++)if(hs->cur.executions[i]==ev->execution_id)return 0;
    if(hs->cur.applied>=2)return 0;
    hs->cur.proof_binding=ev->execution_binding;
    memcpy(hs->cur.proof_client,client,n);
    hs->cur.executions[hs->cur.applied++]=ev->execution_id;
    if (hs->cur.phase == PH_APPLIED && trial_executed(hs,&hs->cur.pending)) {
        d2k_hs_result r = hs->cur.pending;
        judge_trial(hs, &r, hs->cur.deadline - HS_APPLIED_MS);
    }
    return 1;
}

void d2k_httpsearch_result(d2k_httpsearch *hs, const d2k_hs_result *r, int64_t now) {
    if (!hs || !r) { return; }
    if ((hs->cur.phase != PH_BASE && hs->cur.phase != PH_RUN) || r->seq != hs->cur.job_seq) {
        /* Ответ не текущего запуска (ревью M-7): не судит опыт; его сокет
           остался у зонда после остановки по сроку — закрываем здесь. */
        if (r->fd >= 0 && r->fd != hs->cur.fd && hs->ops.close_port) {
            hs->ops.close_port(hs->ops.ctx, r->fd);
        }
        return;
    }
    if (hs->cur.phase == PH_BASE) {
        drop_socket(hs);
        /* Поле 16.10.2026, fast-torrent: клиент получил заглушку провайдера,
           а свой запрос роутера — тишину. Тишина на свой GET — та же
           блокировка в другой форме, а не «блока нет»: поиск начинается.
           Успех кандидата по-прежнему — только полный ответ под планом. */
        if (!hs->cur.cut && r->answer == D2K_HS_SILENT) {
            build_cands(hs);
            say(hs, "HTTP %s: база — тишина на свой запрос после заглушки у клиента: "
                    "блокировка в другой форме; своих планов %zu, затем вопросы разреза "
                    "и checksum-приманки", hs->cur.host, hs->cur.n_cands);
            next_candidate(hs, now);
            return;
        }
        if (r->answer == (hs->cur.cut ? D2K_HS_CUT : D2K_HS_INJECTED)) {
            build_cands(hs);
            say(hs, "HTTP %s: база — %s воспроизведён%s; своих планов %zu, затем вопросы разреза и checksum-приманки",
                hs->cur.host, hs->cur.cut ? "обрыв тела ответа" : "вставка провайдера",
                hs->cur.cut ? "" : "а", hs->cur.n_cands);
            next_candidate(hs, now);
            return;
        }
        /* МЕСТНЫЙ ОТКАЗ — НЕ ОТВЕТ О КОРОБКЕ (поле 23.10.2026, media5.cdnbase.com).
           Наш сокет не соединился: это «не измерено», а не «блока нет». Клиент
           при этом получал обрыв 33 120 Б из 106 050 трижды подряд, и приём,
           которым тот же билд в повторе отдал полный ответ, не был опробован —
           цель закрылась на 10 минут по НАШЕМУ сбою. Повторяем базу тем же
           поиском; если и повтор местный — короткий срок «не измерено». */
        /* ТИШИНА НА БАЗЕ ОБРЫВА — ТОЖЕ НЕ ОТВЕТ О КОРОБКЕ (поле 23.10.2026,
           media5.cdnbase.com, прогон final-e861d26-1). Клиент получал обрыв
           33 120 Б из 106 050 и до, и после базы, а на НАШ запрос ответа не
           было вовсе. Ветка портала читает тишину как «блокировку в другой
           форме» с 16.10.2026, но была закрыта условием `!cur.cut`, то есть
           для цели с обрывом не работала — и цель уходила на 10 минут с
           вердиктом «не воспроизводится», которого никто не измерял.
           Повторяем базу; повторная тишина — сигнал, и поиск начинается
           (ниже, тем же правилом, что у портала). */
        if (r->answer == D2K_HS_SILENT && hs->cur.cut &&
            hs->cur.base_retries >= D2K_HS_BASE_RETRIES) {
            build_cands(hs);
            say(hs, "HTTP %s: база — тишина на свой запрос ДВАЖДЫ при обрыве у "
                    "клиента: ответа нет вовсе, значит это отсутствие замера, а не "
                    "измеренное «блока нет»; своих планов %zu, затем вопросы разреза "
                    "и checksum-приманки", hs->cur.host, hs->cur.n_cands);
            next_candidate(hs, now);
            return;
        }
        if ((r->answer == D2K_HS_CONNECT_FAIL ||
             (r->answer == D2K_HS_SILENT && hs->cur.cut)) &&
            hs->cur.base_retries < D2K_HS_BASE_RETRIES) {
            hs->cur.base_retries++;
            d2k_hs_job job;
            hs->cur.job_seq = ++hs->job_seq;
            int opened = open_job(hs, &job) == 0;
            job.seq = hs->cur.job_seq;
            if (opened && hs->ops.start_probe && hs->ops.start_probe(hs->ops.ctx, &job) == 0) {
                hs->cur.sport = 0;
                hs->cur.phase = PH_BASE;
                hs->cur.deadline = now + (int64_t)d2k_hs_probe_ms * 3;
                say(hs, "HTTP %s: база — %s (попытка %d из %d): ответа о коробке "
                        "здесь нет — повторяю базу", hs->cur.host,
                    r->answer == D2K_HS_SILENT ? "тишина на свой запрос"
                                               : "соединение своего зонда не установилось",
                    hs->cur.base_retries + 1, D2K_HS_BASE_RETRIES + 1);
                return;
            }
            drop_socket(hs);
        }
        rec *rr = rec_get(hs, hs->cur.host, hs->cur.family);
        if (r->answer == D2K_HS_NONE) {
            /* Our own limit (headers beyond the reader, no memory): not measured. */
            if (rr) { rr->no_before_ms = now + D2K_HS_INCONCLUSIVE_MS; }
            say(hs, "HTTP %s: база не измерена — местный предел зонда (%s); о коробке это не "
                    "говорит ничего, повтор не раньше чем через %lld мин", hs->cur.host, r->why,
                (long long)(D2K_HS_INCONCLUSIVE_MS / 60000));
            finish(hs, now, "inconclusive", "baseline-local-limit");
            return;
        }
        int local = r->answer == D2K_HS_CONNECT_FAIL;
        if (rr) {
            rr->no_before_ms = now + (local ? D2K_HS_INCONCLUSIVE_MS : D2K_HS_RECHECK_MS);
        }
        if (local) {
            say(hs, "HTTP %s: база не измерена — соединение своего зонда не "
                    "установилось %d раза подряд; о коробке это не говорит ничего, "
                    "повтор не раньше чем через %lld мин", hs->cur.host,
                D2K_HS_BASE_RETRIES + 1, (long long)(D2K_HS_INCONCLUSIVE_MS / 60000));
            finish(hs, now, "inconclusive", "baseline-local-failure");
            return;
        }
        say(hs, "HTTP %s: база — %s%s%s: %s с роутера не воспроизводится, поиск HTTP "
                "не начат (подозрение не равно блокировке)", hs->cur.host,
            d2k_hs_answer_name(r->answer), r->status[0] ? ", " : "", r->status,
            hs->cur.cut ? "обрыв" : "вставка");
        finish(hs,now,hs_exchange_ok(r) ?
            "probe-direct":"inconclusive","baseline-not-reproduced");
        return;
    }
    if (hs->cur.phase != PH_RUN) { return; }
    drop_socket(hs);
    drop_probe(hs);
    if (trial_executed(hs,r)) { judge_trial(hs, r, now); return; }
    hs->cur.pending = *r;
    hs->cur.phase = PH_APPLIED;
    hs->cur.deadline = now + HS_APPLIED_MS;
}

void d2k_httpsearch_tick(d2k_httpsearch *hs, int64_t now) {
    if (!hs || hs->cur.phase == PH_IDLE || now < hs->cur.deadline) { return; }
    switch (hs->cur.phase) {
    case PH_ACK:
        say(hs, "HTTP %s: «%s» — датапат не подтвердил пробный план за %d мс, кандидат не судим",
            hs->cur.host, hs->cur.cands[hs->cur.idx], HS_ACK_MS);
        drop_probe(hs);
        hs->cur.ok = 0;
        hs->cur.idx++;
        next_candidate(hs, now);
        break;
    case PH_APPLIED: {
        d2k_hs_result r = hs->cur.pending;
        judge_trial(hs, &r, now);
        break;
    }
    case PH_BASE:
    case PH_RUN:
        /* Зонд не ответил втрое дольше своего срока — что-то сломалось у
           нас; поиск останавливается, сокет закрывается. */
        say(hs, "HTTP %s: зонд не вернулся — поиск остановлен", hs->cur.host);
        if (hs->cur.phase == PH_RUN) { drop_probe(hs); }
        /* Сокет у зонда: его закроет опоздавший ответ, не мы (ревью M-7). */
        hs->cur.fd = -1;
        hs->cur.job_seq = 0;
        finish(hs,now,"local-abort","worker-timeout");
        break;
    default:
        break;
    }
}

void d2k_httpsearch_push_all(d2k_httpsearch *hs) {
    if (!hs || !hs->ops.set_plan) { return; }
    for (size_t i = 0; i < hs->n_recs; i++) {
        rec *r = &hs->recs[i];
        if(r->revoked) {revoke_owned(hs,r);continue;}
        if (!r->key[0]) { continue; }
        uint8_t id[16];
        char text[2048];
        stable_id(r->key, id);
        if (d2k_hs_candidate_text(r->key, id, text, sizeof text) == 0) {
            (void)install(hs,r,text,id,mono_ms());
        }
    }
}

int d2k_httpsearch_save(d2k_httpsearch *hs, const char *path, int64_t wall_s,
                        char *err, size_t cap) {
    if (!hs || !path) { return -1; }
    char tmp[1100];
    if (snprintf(tmp, sizeof tmp, "%s.tmp", path) >= (int)sizeof tmp) {
        snprintf(err, cap, "путь длиннее %zu", sizeof tmp);
        return -1;
    }
    FILE *f = fopen(tmp, "w");
    if (!f) { snprintf(err, cap, "%s: %s", tmp, strerror(errno)); return -1; }
    fprintf(f, "d2k-http-plans 1\n");
    for (size_t i = 0; i < hs->n_recs; i++) {
        rec *r = &hs->recs[i];
        if (!r->key[0] || r->revoked) { continue; }
        /* Время подтверждения — первое сохранение после него (ревью M-4):
           сохранение идёт сразу за подтверждением. */
        if (!r->wall) { r->wall = wall_s; }
        fprintf(f, "%s %u %s %lld\n", r->host, (unsigned)r->family, r->key, (long long)r->wall);
    }
    int bad = fflush(f) != 0 || fsync(fileno(f)) != 0;
    bad |= fclose(f) != 0;
    if (bad || rename(tmp, path) != 0) {
        snprintf(err, cap, "%s: %s", path, strerror(errno));
        unlink(tmp);
        return -1;
    }
    return 0;
}

int d2k_httpsearch_load(d2k_httpsearch *hs, const char *path, size_t *n_loaded,
                        char *err, size_t cap) {
    if (n_loaded) { *n_loaded = 0; }
    if (!hs || !path) { return -1; }
    FILE *f = fopen(path, "r");
    if (!f) {
        if (errno == ENOENT) { return 0; }
        snprintf(err, cap, "%s: %s", path, strerror(errno));
        return -1;
    }
    char line[512];
    if (!fgets(line, sizeof line, f) || strcmp(line, "d2k-http-plans 1\n") != 0) {
        fclose(f);
        snprintf(err, cap, "%s: не планы HTTP d2k (нет заголовка «d2k-http-plans 1»)", path);
        return -1;
    }
    while (fgets(line, sizeof line, f)) {
        char host[300], key[48];
        unsigned family;
        long long wall;
        int used = 0;
        if (sscanf(line, "%299s %u %47s %lld %n", host, &family, key, &wall, &used) != 4 ||
            line[used] != '\0' || (family != 4 && family != 6) || !host_ok(host) ||
            !known_key(key)) { continue; }
        rec *r = rec_get(hs, host, (uint8_t)family);
        if (!r) { break; }
        snprintf(r->key, sizeof r->key, "%.39s", key);
        r->seq = ++hs->seq;
        r->wall = wall;
        uint8_t id[16];
        char text[2048];
        stable_id(key, id);
        if (d2k_hs_candidate_text(key, id, text, sizeof text) == 0 && hs->ops.set_plan) {
            (void)install(hs,r,text,id,mono_ms());
        }
        if (n_loaded) { (*n_loaded)++; }
    }
    fclose(f);
    return 0;
}

/* --- рабочий поток ------------------------------------------------------------ */

struct d2k_hs_runner {
    pthread_mutex_t mu;
    pthread_t th;
    int running, joinable, ready;
    d2k_hs_job job;
    d2k_hs_result res;
    int wake[2];
};

static void *runner_main(void *arg) {
    d2k_hs_runner *r = arg;
    d2k_hs_result res;
    d2k_hs_probe_run(&r->job, &res);
    pthread_mutex_lock(&r->mu);
    r->res = res;
    r->ready = 1;
    r->running = 0;
    pthread_mutex_unlock(&r->mu);
    ssize_t w = write(r->wake[1], "x", 1);
    (void)w;
    return NULL;
}

d2k_hs_runner *d2k_hs_runner_new(void) {
    d2k_hs_runner *r = calloc(1, sizeof *r);
    if (!r) { return NULL; }
    /* `< 0`, а не `!= 0`: системный pipe на MIPS возвращает первый дескриптор
       в v0 (второй в v1), и обёртка musl отдаёт это значение как есть — успех
       там положительный. Та же ловушка разобрана у d2k_sched_new (sched.c);
       проверка — test_mips_pipe. */
    if (pipe(r->wake) < 0) { free(r); return NULL; }
    for (int i = 0; i < 2; i++) {
        int fl = fcntl(r->wake[i], F_GETFL, 0);
        if (fl >= 0) { (void)fcntl(r->wake[i], F_SETFL, fl | O_NONBLOCK); }
    }
    pthread_mutex_init(&r->mu, NULL);
    return r;
}

void d2k_hs_runner_free(d2k_hs_runner *r) {
    if (!r) { return; }
    if (r->joinable) { pthread_join(r->th, NULL); }
    close(r->wake[0]);
    close(r->wake[1]);
    pthread_mutex_destroy(&r->mu);
    free(r);
}

int d2k_hs_runner_wake_fd(const d2k_hs_runner *r) { return r ? r->wake[0] : -1; }

int d2k_hs_runner_start(d2k_hs_runner *r, const d2k_hs_job *job) {
    if (!r || !job) { return -1; }
    pthread_mutex_lock(&r->mu);
    int busy = r->running;
    pthread_mutex_unlock(&r->mu);
    if (busy) { return -1; }
    if (r->joinable) { pthread_join(r->th, NULL); r->joinable = 0; }
    r->job = *job;
    r->ready = 0;
    r->running = 1;
    if (pthread_create(&r->th, NULL, runner_main, r) != 0) { r->running = 0; return -1; }
    r->joinable = 1;
    return 0;
}

int d2k_hs_runner_done(d2k_hs_runner *r, d2k_hs_result *out) {
    if (!r || !out) { return 0; }
    char drain[16];
    while (read(r->wake[0], drain, sizeof drain) > 0) { }
    pthread_mutex_lock(&r->mu);
    int ready = r->ready;
    if (ready) { *out = r->res; r->ready = 0; }
    pthread_mutex_unlock(&r->mu);
    if (ready && r->joinable) { pthread_join(r->th, NULL); r->joinable = 0; }
    return ready;
}
