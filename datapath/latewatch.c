/* Поздняя доставка: владение, готовность, снятие (этапы 17, 49, 51, 53),
   см. include/d2k_latewatch.h. Модуль не ждёт ядро и iptables — только
   сверяет «нужно» и «есть» и отдаёт заявки исполнителю. */
#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "d2k_latewatch.h"
#include "d2k_crypto.h"

#define NS_S 1000000000ull

static void say(d2k_lw *lw, const char *fmt, ...) {
    if (!lw->ops.say) return;
    char line[320];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    lw->ops.say(lw->ops.ctx, line);
}

static void text(const d2k_ct_tuple *t, char *o, size_t cap) {
    char a[INET6_ADDRSTRLEN], b[INET6_ADDRSTRLEN];
    int af = t->family == 6 ? AF_INET6 : AF_INET;
    if (!inet_ntop(af, t->src, a, sizeof a)) { snprintf(a, sizeof a, "?"); }
    if (!inet_ntop(af, t->dst, b, sizeof b)) { snprintf(b, sizeof b, "?"); }
    snprintf(o, cap, "%s %s:%u -> %s:%u", t->proto == 6 ? "tcp" : "udp", a,
             (unsigned)(t->sport_be[0] << 8 | t->sport_be[1]), b,
             (unsigned)(t->dport_be[0] << 8 | t->dport_be[1]));
}

static uint64_t backoff(uint64_t step) {
    return !step ? D2K_LW_RETRY_FIRST_NS : step * 2 > D2K_LW_RETRY_MAX_NS ? D2K_LW_RETRY_MAX_NS : step * 2;
}

void d2k_lw_init(d2k_lw *lw, const d2k_lw_ops *ops) {
    memset(lw, 0, sizeof *lw);
    if (ops) lw->ops = *ops;
    lw->enabled = 1;            /* до итога INIT заявки копятся у исполнителя */
}

static int submit(d2k_lw *lw, uint8_t op, int idx, int orphan, const d2k_ct_tuple *t, uint64_t *gen) {
    d2k_lw_req r;
    memset(&r, 0, sizeof r);
    r.op = op; r.slot = (uint16_t)(idx < 0 ? 0 : idx); r.orphan = (uint8_t)orphan;
    r.gen = ++lw->gen;
    if (t) r.t = *t;
    if (lw->ops.submit(lw->ops.ctx, &r) != 0) { lw->st.queue_full++; return -1; }
    if (gen) *gen = r.gen;
    return 0;
}

/* Проход уборки: заявка, повтор с откатом при полной очереди. */
static void sweep_submit(d2k_lw *lw, uint64_t now) {
    if (submit(lw, D2K_LWOP_SWEEP, -1, 0, NULL, &lw->sweep_gen) == 0) { lw->sweep_busy = 1; return; }
    lw->sweep_step_ns = backoff(lw->sweep_step_ns);
    lw->sweep_next_ns = now + lw->sweep_step_ns;
}

void d2k_lw_start(d2k_lw *lw, uint64_t now) {
    (void)submit(lw, D2K_LWOP_INIT, -1, 0, NULL, NULL);
    lw->sweep_pending = 1;
    sweep_submit(lw, now);
}

static d2k_lw_slot *find(d2k_lw *lw, const d2k_ct_tuple *t) {
    for (size_t i = 0; i < D2K_LW_SLOTS; i++)
        if (lw->slot[i].used && !memcmp(&lw->slot[i].t, t, sizeof *t)) return &lw->slot[i];
    return NULL;
}

static void flag(d2k_lw *lw, const d2k_ct_tuple *t, int on) {
    if (lw->ops.flow_flag) lw->ops.flow_flag(lw->ops.ctx, t, on);
}

static void ack(d2k_lw *lw, int ok, uint8_t reason, const uint8_t token[D2K_TRIAL_ID_LEN]) {
    if (lw->ops.ack) lw->ops.ack(lw->ops.ctx, ok, reason, token);
}

static int wanted(const d2k_lw_slot *w) { return w->trial || w->observe || w->obs_pending || w->raw_pending || w->raw_active; }

static void raw_ack(d2k_lw *lw,int ok,const uint8_t token[16]) {
    if (lw->raw_ops.ack) lw->raw_ops.ack(lw->raw_ops.ctx,ok,ok?D2K_ACK_OK:D2K_ACK_UNAVAILABLE,token);
}
static int raw_live(d2k_lw *lw,d2k_lw_slot *w,int *prior) {
    return w->raw_conn==lw->conn_gen && lw->raw_ops.identity &&
           lw->raw_ops.identity(lw->raw_ops.ctx,&w->raw_request,prior)==1;
}
static void raw_cancel(d2k_lw *lw,d2k_lw_slot *w,int notify) {
    if (notify && (w->raw_pending || w->raw_active) && w->raw_conn==lw->conn_gen)
        raw_ack(lw,0,w->raw_request.token);
    if (w->raw_active) lw->n_obs--;
    w->raw_pending=w->raw_active=0;
}
/* The lease bounds silence, not the sum of waiting for a sample and its
 * comparison. TCP gets one acquisition window and, after its first sample,
 * one comparison window. Heartbeats preserve evidence, never move the sample
 * or the acquisition deadline. Unsupported longer retry intervals remain
 * inconclusive; this is not a universal TCP RTO bound. */
static void raw_deadline(d2k_lw_slot *w) {
    uint64_t span=(uint64_t)w->raw_request.seconds*NS_S;
    uint64_t origin=w->raw_started_ns;
    uint64_t grace=0;
    if(w->t.proto==6 && w->raw.sampled) {
        origin=w->raw.sample_ns;grace=D2K_RM_GRACE_S*NS_S;
    }
    uint64_t limit=origin+span+grace,lease=w->raw_heartbeat_ns+span;
    w->raw_expires_ns=limit<lease?limit:lease;
}
static void raw_activate(d2k_lw *lw,d2k_lw_slot *w,uint64_t now) {
    if (!w->raw_pending) return;
    int prior=0;
    if (!raw_live(lw,w,&prior)) { raw_cancel(lw,w,1);return; }
    w->raw_pending=0;w->raw_active=1;lw->n_obs++;
    d2k_rawmeasure_init(&w->raw,&w->raw_request.tuple,w->raw_request.generation,prior);
    w->raw_started_ns=w->raw_heartbeat_ns=now;
    raw_deadline(w);
    raw_ack(lw,1,w->raw_request.token);
}

/* Доставка готова: ждущее наблюдение — подтверждение и срок от сейчас; только
   своему подключению контроллера. */
static void activate(d2k_lw *lw, d2k_lw_slot *w, uint64_t now) {
    raw_activate(lw,w,now);
    if (!w->obs_pending) return;
    if (w->obs_conn != lw->conn_gen) { w->obs_pending = 0; return; }
    w->obs_pending = 0;
    w->observe = 1;
    lw->n_obs++;
    d2k_lateobs_init(&w->obs, &w->t);
    w->obs_expires_ns = now + w->obs_secs * NS_S;
    ack(lw, 1, D2K_ACK_OK, w->obs_token);
}

/* Доставку поставить не удалось: ждущему наблюдению — отказ, опыт — без неё. */
static void owners_fail(d2k_lw *lw, d2k_lw_slot *w, const char *why) {
    char txt[160];
    text(&w->t, txt, sizeof txt);
    raw_cancel(lw,w,1);
    if (w->obs_pending) { w->obs_pending = 0; ack(lw, 0, D2K_ACK_UNAVAILABLE, w->obs_token); }
    if (w->trial) {
        w->trial = 0;
        say(lw, "d2kd: поздняя доставка %s: %s — опыт идёт без неё", txt, why);
    }
}

static void slot_free(d2k_lw *lw, d2k_lw_slot *w) {
    flag(lw, &w->t, 0);
    memset(w, 0, sizeof *w);
}

/* Барьер установки: способ известен, у «правил» стартовая очистка прошла. */
static int install_blocked(const d2k_lw *lw) {
    return !lw->backend_known || (lw->backend == D2K_LW_BACKEND_RULES && lw->sweep_pending);
}

/* Сверка «нужно» и «есть»: не больше одной операции в полёте. */
static void reconcile(d2k_lw *lw, d2k_lw_slot *w, uint64_t now) {
    while (w->used && !w->busy) {
        int idx = (int)(w - lw->slot);
        if (wanted(w)) {
            if (w->installed == D2K_LW_YES) { activate(lw, w, now); if (wanted(w)) return; continue; }
            if (lw->backend_known && !lw->enabled) { owners_fail(lw, w, "поздней доставки нет"); continue; }
            if (install_blocked(lw)) return;             /* ждёт барьер, не отказ */
            if (submit(lw, D2K_LWOP_INSTALL, idx, 0, &w->t, &w->gen) != 0) {
                owners_fail(lw, w, "очередь исполнителя полна");
                continue;
            }
            w->busy = 1; w->op = D2K_LWOP_INSTALL;
            return;
        }
        if (w->installed == D2K_LW_NO) { slot_free(lw, w); return; }
        if (now < w->retry_ns) return;
        if (submit(lw, D2K_LWOP_CLEAR, idx, 0, &w->t, &w->gen) != 0) {
            w->retry_step_ns = backoff(w->retry_step_ns);
            w->retry_ns = now + w->retry_step_ns;
            return;
        }
        w->busy = 1; w->op = D2K_LWOP_CLEAR;
        return;
    }
}

/* Слот кортежа: существующий или новый. NULL — мест нет. Сирота уборки на этом
   кортеже снимается с учёта: её снятие, если уже в очереди, исполнится раньше
   установки (очередь по порядку), а новое не начнётся. */
static d2k_lw_slot *acquire(d2k_lw *lw, const d2k_ct_tuple *t) {
    for (size_t i = 0; i < D2K_LW_SWEEP_LIST; i++)
        if (lw->orphan[i].used && !memcmp(&lw->orphan[i].t, t, sizeof *t)) memset(&lw->orphan[i], 0, sizeof lw->orphan[i]);
    d2k_lw_slot *w = find(lw, t);
    if (w) return w;
    for (size_t i = 0; i < D2K_LW_SLOTS && !w; i++) if (!lw->slot[i].used) w = &lw->slot[i];
    if (!w) {
        say(lw, "d2kd: поздняя доставка: мест нет (%d) — доставки не будет", D2K_LW_SLOTS);
        return NULL;
    }
    memset(w, 0, sizeof *w);
    w->used = 1;
    w->t = *t;
    w->delivered_at_set = lw->ops.delivered ? lw->ops.delivered(lw->ops.ctx) : 0;
    flag(lw, t, 1);
    return w;
}

void d2k_lw_raw_hooks(d2k_lw *lw,const d2k_lw_raw_ops *ops) {
    if (ops) lw->raw_ops=*ops; else memset(&lw->raw_ops,0,sizeof lw->raw_ops);
}
void d2k_lw_measure(d2k_lw *lw,const struct d2k_rawmeasure_request *r,uint64_t now) {
    int prior=0;
    if (!d2k_rawmeasure_request_valid(r)) return;
    if (!lw->enabled || !lw->raw_ops.identity ||
        lw->raw_ops.identity(lw->raw_ops.ctx,r,&prior)!=1) {raw_ack(lw,0,r->token);return;}
    d2k_lw_slot *w=r->renew?find(lw,&r->tuple):acquire(lw,&r->tuple);
    if (!w) {raw_ack(lw,0,r->token);return;}
    if ((w->raw_pending || w->raw_active) && w->raw_conn==lw->conn_gen &&
        !memcmp(w->raw_request.token,r->token,16) && !memcmp(w->raw_request.epoch,r->epoch,16) &&
        w->raw_request.generation==r->generation) {
        if(r->renew && !r->seconds) {
            raw_cancel(lw,w,0);raw_ack(lw,1,r->token);reconcile(lw,w,now);return;
        }
        if(r->seconds!=w->raw_request.seconds ||
           (w->raw_active && now>=w->raw_expires_ns)) {raw_ack(lw,0,r->token);return;}
        if (w->raw_active) {
            if(r->renew){w->raw_heartbeat_ns=now;raw_deadline(w);}
            raw_ack(lw,1,r->token);
        }
        return; /* Same owner, immutable evidence and phase deadlines. */
    }
    if(r->renew || ((w->raw_pending || w->raw_active) && raw_live(lw,w,&prior))) {
        raw_ack(lw,0,r->token);return; /* Never displace another live owner. */
    }
    raw_cancel(lw,w,1);
    w->raw_request=*r;w->raw_conn=lw->conn_gen;w->raw_pending=1;
    reconcile(lw,w,now);
}
static void raw_finish(d2k_lw *lw,d2k_lw_slot *w,uint8_t code,uint64_t now) {
    struct d2k_rawmeasure_report r;memset(&r,0,sizeof r);
    r.request=w->raw_request;r.code=code;
    r.flags=(w->raw.previous_reply?D2K_RM_PRIOR_REPLY:0)|(w->raw.changed?D2K_RM_CHANGED:0)|
            (w->raw.oversized?D2K_RM_OVERSIZED:0)|
            (w->raw.tcp_ack_seen?D2K_RM_TCP_ACK:0);
    r.sample_len=w->raw.sample_len;r.smallest_data=w->raw.smallest_data;r.largest_data=w->raw.largest_data;
    if(w->raw.sample_len)d2k_sha256(w->raw.sample,w->raw.sample_len,r.sample_digest);
    r.sample_seq=w->raw.sample_seq;r.client_data=w->raw.client_data;
    r.exact_repeats=w->raw.exact_repeats;r.server_packets=w->raw.server_packets;
    r.tcp_ack=w->raw.tcp_ack;
    if (w->raw.exact_repeats) {
        r.repeat_gap_ms=d2k_rm_ms(w->raw.last_copy_ns-w->raw.prev_copy_ns);
        r.repeat_age_ms=d2k_rm_ms(now>w->raw.last_copy_ns?now-w->raw.last_copy_ns:0);
    }
    if (w->raw_conn==lw->conn_gen && lw->raw_ops.note) lw->raw_ops.note(lw->raw_ops.ctx,&r);
    raw_cancel(lw,w,0);
    if (!wanted(w)) w->why="измерение окончено";
    reconcile(lw,w,now);
}

int d2k_lw_trial_add(d2k_lw *lw, const d2k_ct_tuple *t, uint64_t expires_ns, uint64_t now) {
    if (!lw->enabled) return -1;
    d2k_lw_slot *w = acquire(lw, t);
    if (!w) return -1;
    uint64_t cap = now + D2K_LW_MAX_NS;
    if (!expires_ns || expires_ns > cap) expires_ns = cap;
    if (expires_ns > w->expires_ns) w->expires_ns = expires_ns;
    w->trial = 1;
    reconcile(lw, w, now);
    return w->used && w->trial ? 0 : -1;
}

void d2k_lw_trial_del(d2k_lw *lw, const d2k_ct_tuple *t, uint64_t now) {
    d2k_lw_slot *w = find(lw, t);
    if (!w || !w->trial) return;
    w->trial = 0;
    if (!wanted(w)) w->why = "опыт снят";
    reconcile(lw, w, now);
}

void d2k_lw_observe(d2k_lw *lw, const d2k_ct_tuple *t, uint32_t seconds,
                    const uint8_t token[D2K_TRIAL_ID_LEN], uint64_t now) {
    if (!lw->enabled) { ack(lw, 0, D2K_ACK_UNAVAILABLE, token); return; }
    d2k_lw_slot *w = acquire(lw, t);
    if (!w) { ack(lw, 0, D2K_ACK_UNAVAILABLE, token); return; }
    char txt[160];
    text(t, txt, sizeof txt);
    if (w->obs_pending) ack(lw, 0, D2K_ACK_UNAVAILABLE, w->obs_token);     /* заменено новым */
    if (w->observe) {
        say(lw, "d2kd: позднее наблюдение %s: прежнее заменено новым запросом", txt);
        w->observe = 0;
        lw->n_obs--;
    }
    w->obs_pending = 1;
    w->obs_conn = lw->conn_gen;
    w->obs_secs = seconds;
    memcpy(w->obs_token, token, D2K_TRIAL_ID_LEN);
    reconcile(lw, w, now);
}

static void obs_finish(d2k_lw *lw, d2k_lw_slot *w, uint8_t code, uint64_t now) {
    char txt[160];
    text(&w->t, txt, sizeof txt);
    say(lw, "d2kd: позднее наблюдение %s: %s (данных клиента %u, повторов %u, пакетов сервера %u)",
        txt, d2k_lateobs_text(code), (unsigned)w->obs.client_data, (unsigned)w->obs.repeats,
        (unsigned)w->obs.server_pkts);
    if (lw->ops.note && w->obs_conn == lw->conn_gen)
        lw->ops.note(lw->ops.ctx, &w->t, code, w->obs.repeats, w->obs_token, now);
    w->observe = 0;
    lw->n_obs--;
    if (!wanted(w)) w->why = "наблюдение окончено";
    reconcile(lw, w, now);
}

int d2k_lw_packet(d2k_lw *lw, const uint8_t *pkt, size_t n, uint64_t now) {
    if (!lw->n_obs || !pkt) return 0;
    int matched=0;
    for (size_t i=0;i<D2K_LW_SLOTS;i++) {
        d2k_lw_slot *w=&lw->slot[i];
        if (!w->used) continue;
        if (w->raw_active) {
            int prior=0;
            if (!raw_live(lw,w,&prior)) {raw_cancel(lw,w,1);reconcile(lw,w,now);}
            else if (now>=w->raw_expires_ns) {
                raw_finish(lw,w,d2k_rawmeasure_result(&w->raw,1),now);
            } else if (d2k_rawmeasure_feed(&w->raw,w->raw_request.generation,pkt,n,now)) {
                raw_deadline(w);
                matched=1;
                uint8_t code=d2k_rawmeasure_result(&w->raw,0);
                if (code!=D2K_RM_PENDING) raw_finish(lw,w,code,now);
            }
        }
        if (!w->used || !w->observe || !d2k_lateobs_feed(&w->obs,pkt,n)) continue;
        matched=1;
        uint8_t code=d2k_lateobs_result(&w->obs,0);
        if (code!=D2K_LATEOBS_PENDING) obs_finish(lw,w,code,now);
    }
    return matched;
}

static void clear_done(d2k_lw *lw, d2k_lw_slot *w, int rc, uint64_t now, const char *txt) {
    if (rc == -1) {
        lw->st.clear_fail++;
        w->installed = D2K_LW_UNKNOWN;
        if (!w->fail_told) {
            w->fail_told = 1;
            say(lw, "d2kd: поздняя доставка %s: снятие не подтверждено — повторю; до подтверждения доставка "
                    "остаётся", txt);
        }
        w->retry_step_ns = backoff(w->retry_step_ns);
        w->retry_ns = now + w->retry_step_ns;
        return;
    }
    uint64_t seen = lw->ops.delivered ? lw->ops.delivered(lw->ops.ctx) - w->delivered_at_set : 0;
    const char *why = w->why ? w->why : "владельцев нет";
    if (rc == 1) {
        lw->st.gone++;
        say(lw, "d2kd: поздняя доставка %s: записи conntrack больше нет (%s) — снимать нечего", txt, why);
    } else {
        lw->st.cleared++;
        /* Формат строки — договор диагностики этапа 17 (лаборатории его читают);
           печатается только после подтверждения исполнителя. */
        if (seen) {
            say(lw, "d2kd: поздняя доставка %s снята (%s%s): пакетов за окном принято %llu", txt, why,
                w->fail_told ? ", после повтора" : "", (unsigned long long)seen);
        } else {
            lw->st.silent++;
            say(lw, "d2kd: поздняя доставка %s снята (%s%s): за время владения ни одного пакета потока за окном в "
                    "очереди сессии не было — ускоритель держит поток в железе или клиент замолчал",
                txt, why, w->fail_told ? ", после повтора" : "");
        }
    }
    w->installed = D2K_LW_NO;
    w->fail_told = 0;
    w->retry_step_ns = 0;
    w->retry_ns = 0;
}

static void slot_done(d2k_lw *lw, d2k_lw_slot *w, const d2k_lw_done *d, uint64_t now) {
    char txt[160];
    text(&w->t, txt, sizeof txt);
    w->busy = 0;
    if (d->op == D2K_LWOP_INSTALL) {
        if (d->rc == 0) {
            w->installed = D2K_LW_YES;
            lw->st.set++;
            say(lw, "d2kd: поздняя доставка: метка 0x%x поставлена на запись %s, срок %llu с", (unsigned)lw->ops.bit,
                txt, (unsigned long long)(w->trial && w->expires_ns > now ? (w->expires_ns - now) / NS_S : w->obs_secs));
        } else {
            w->installed = d->rc == 1 ? D2K_LW_NO : D2K_LW_UNKNOWN;
            if (d->rc != 1) { lw->st.install_fail++; w->why = "установка не подтверждена"; }
            owners_fail(lw, w, d->rc == 1 ? "записи conntrack нет" : "установка не подтверждена");
        }
    } else {
        clear_done(lw, w, d->rc, now, txt);
    }
    reconcile(lw, w, now);
}

static int owned(const d2k_lw *lw, const d2k_ct_tuple *t) {
    for (size_t i = 0; i < D2K_LW_SLOTS; i++)
        if (lw->slot[i].used && !memcmp(&lw->slot[i].t, t, sizeof *t)) return 1;
    return 0;
}

static void orphan_reconcile(d2k_lw *lw, uint64_t now) {
    for (size_t i = 0; i < D2K_LW_SWEEP_LIST; i++) {
        d2k_lw_orphan *o = &lw->orphan[i];
        if (!o->used || o->busy || now < o->retry_ns) continue;
        if (owned(lw, &o->t)) { memset(o, 0, sizeof *o); continue; }
        if (submit(lw, D2K_LWOP_CLEAR, (int)i, 1, &o->t, &o->gen) != 0) {
            o->retry_step_ns = backoff(o->retry_step_ns);
            o->retry_ns = now + o->retry_step_ns;
            continue;
        }
        o->busy = 1;
    }
}

static int orphans_left(const d2k_lw *lw) {
    for (size_t i = 0; i < D2K_LW_SWEEP_LIST; i++) if (lw->orphan[i].used) return 1;
    return 0;
}

/* Уборка закончена, когда последний проход полный, без переполнения и сирот
   нет; иначе — следующий проход (после отката при сбое). */
static void reconcile_all(d2k_lw *lw, uint64_t now) {
    for (size_t i = 0; i < D2K_LW_SLOTS; i++) reconcile(lw, &lw->slot[i], now);
}

static void sweep_check(d2k_lw *lw, uint64_t now) {
    if (!lw->sweep_pending || lw->sweep_busy || orphans_left(lw)) return;
    if (lw->sweep_clean) {
        lw->sweep_pending = 0;
        if (lw->st.swept)
            say(lw, "d2kd: поздняя доставка: уборка после перезапуска закончена — снято остатков %llu",
                (unsigned long long)lw->st.swept);
        reconcile_all(lw, now);                          /* барьер снят */
        return;
    }
    if (now >= lw->sweep_next_ns) sweep_submit(lw, now);
}

static void sweep_done(d2k_lw *lw, const d2k_lw_done *d, uint64_t now) {
    if (!lw->sweep_busy || d->gen != lw->sweep_gen) return;
    lw->sweep_busy = 0;
    int ok = d->rc == 0 && (lw->backend != D2K_LW_BACKEND_MARK || d->dump_ok);
    lw->sweep_clean = ok && !d->over;
    if (!ok) {
        lw->st.sweep_fail++;
        lw->sweep_step_ns = backoff(lw->sweep_step_ns);
        lw->sweep_next_ns = now + lw->sweep_step_ns;
        say(lw, "d2kd: поздняя доставка: уборка после перезапуска не прошла целиком — повтор через %llu с",
            (unsigned long long)(lw->sweep_step_ns / NS_S));
    } else {
        lw->sweep_next_ns = now;
    }
    for (size_t k = 0; k < d->n && k < D2K_LW_SWEEP_LIST; k++) {
        if (owned(lw, &d->list[k])) continue;          /* живой владелец нового экземпляра */
        int dup = 0;
        for (size_t i = 0; i < D2K_LW_SWEEP_LIST && !dup; i++)
            dup = lw->orphan[i].used && !memcmp(&lw->orphan[i].t, &d->list[k], sizeof d->list[k]);
        for (size_t i = 0; i < D2K_LW_SWEEP_LIST && !dup; i++) {
            if (lw->orphan[i].used) continue;
            memset(&lw->orphan[i], 0, sizeof lw->orphan[i]);
            lw->orphan[i].used = 1;
            lw->orphan[i].t = d->list[k];
            dup = 1;
        }
    }
    orphan_reconcile(lw, now);
    sweep_check(lw, now);
}

static void orphan_done(d2k_lw *lw, const d2k_lw_done *d, uint64_t now) {
    if (d->slot >= D2K_LW_SWEEP_LIST) return;
    d2k_lw_orphan *o = &lw->orphan[d->slot];
    if (!o->used || !o->busy || o->gen != d->gen) return;     /* снята с учёта: новый владелец */
    o->busy = 0;
    if (d->rc == -1) {
        o->retry_step_ns = backoff(o->retry_step_ns);
        o->retry_ns = now + o->retry_step_ns;
    } else {
        lw->st.swept++;
        memset(o, 0, sizeof *o);
    }
    sweep_check(lw, now);
}

static void init_done(d2k_lw *lw, const d2k_lw_done *d, uint64_t now) {
    lw->backend = d->backend;
    lw->enabled = d->backend != D2K_LW_BACKEND_NONE;
    lw->backend_known = 1;
    say(lw, "d2kd: поздняя доставка: способ — %s", d->backend == D2K_LW_BACKEND_MARK ? "метка conntrack (маска)"
        : d->backend == D2K_LW_BACKEND_RULES ? "правила точного кортежа (свои цепочки)" : "нет, выключена");
    if (lw->enabled) { reconcile_all(lw, now); return; }
    lw->sweep_pending = 0;
    for (size_t i = 0; i < D2K_LW_SLOTS; i++) {
        d2k_lw_slot *w = &lw->slot[i];
        if (!w->used || w->busy) continue;           /* в полёте — по его итогу */
        owners_fail(lw, w, "поздней доставки нет");
        reconcile(lw, w, now);
    }
}

void d2k_lw_complete(d2k_lw *lw, const d2k_lw_done *d, uint64_t now) {
    if (d->op == D2K_LWOP_INIT) { init_done(lw, d, now); return; }
    if (d->op == D2K_LWOP_SWEEP) { sweep_done(lw, d, now); return; }
    if (d->orphan) { orphan_done(lw, d, now); return; }
    if (d->slot >= D2K_LW_SLOTS) return;
    d2k_lw_slot *w = &lw->slot[d->slot];
    if (!w->used || !w->busy || w->gen != d->gen || memcmp(&w->t, &d->t, sizeof d->t)) return;
    slot_done(lw, w, d, now);
}

void d2k_lw_peer_closed(d2k_lw *lw, uint64_t now) {
    lw->conn_gen++;
    for (size_t i = 0; i < D2K_LW_SLOTS; i++) {
        d2k_lw_slot *w = &lw->slot[i];
        if (!w->used || !wanted(w)) continue;
        if (w->observe) { w->observe = 0; lw->n_obs--; }
        w->obs_pending = 0;
        raw_cancel(lw,w,0);
        w->trial = 0;                    /* пробы контроллера сняты вместе с ним */
        if (!wanted(w)) w->why = "контроллер отключился";
        reconcile(lw, w, now);
    }
}

void d2k_lw_ipv4_mangle_reset(d2k_lw *lw, uint64_t now) {
    for (size_t i = 0; i < D2K_LW_SLOTS; i++) {
        d2k_lw_slot *w = &lw->slot[i];
        if (!w->used || w->t.family != 4) continue;
        if (lw->backend == D2K_LW_BACKEND_RULES) {
            /* The serial executor finishes old jobs before their replacements.
               Ignore their receipts: they refer to the previous chains. */
            w->busy = 0;
            w->installed = D2K_LW_UNKNOWN;
            w->retry_ns = 0;
        }
        if (w->raw_active) raw_cancel(lw, w, 1);
        if (w->observe) obs_finish(lw, w, D2K_LATEOBS_UNAVAILABLE, now);
        else reconcile(lw, w, now);
    }
}

int d2k_lw_ipv4_repair_pending(const d2k_lw *lw) {
    if (lw->backend != D2K_LW_BACKEND_RULES) return 0;
    for (size_t i = 0; i < D2K_LW_SLOTS; i++) {
        const d2k_lw_slot *w = &lw->slot[i];
        if (w->used && w->t.family == 4 &&
            (w->busy || (wanted(w) && w->installed != D2K_LW_YES))) return 1;
    }
    return 0;
}

void d2k_lw_tick(d2k_lw *lw, uint64_t now, int controller_gone) {
    for (size_t i = 0; i < D2K_LW_SLOTS; i++) {
        d2k_lw_slot *w = &lw->slot[i];
        if (!w->used) continue;
        if (controller_gone && wanted(w)) {
            /* Спросить было некому — ни подтверждения, ни итога. */
            if (w->observe) { w->observe = 0; lw->n_obs--; }
            w->obs_pending = 0;
            raw_cancel(lw,w,0);
            w->trial = 0;
            w->why = "контроллер отключился";
        }
        if (w->raw_active || w->raw_pending) {
            int prior=0;
            if (!raw_live(lw,w,&prior)) raw_cancel(lw,w,1);
            else if (w->raw_active && w->raw_expires_ns<=now)
                raw_finish(lw,w,d2k_rawmeasure_result(&w->raw,1),now);
            if (!w->used) continue;
        }
        if (w->observe && w->obs_expires_ns <= now) { obs_finish(lw, w, d2k_lateobs_result(&w->obs, 1), now); continue; }
        if (w->trial && w->expires_ns <= now) {
            w->trial = 0;
            if (!wanted(w)) w->why = "срок";
        }
        reconcile(lw, w, now);
    }
    orphan_reconcile(lw, now);
    sweep_check(lw, now);
}

size_t d2k_lw_pending_clears(const d2k_lw *lw) {
    size_t n = 0;
    for (size_t i = 0; i < D2K_LW_SLOTS; i++)
        n += lw->slot[i].used && !wanted(&lw->slot[i]) && lw->slot[i].installed != D2K_LW_NO;
    return n;
}

int d2k_lw_sweep_pending(const d2k_lw *lw) { return lw->sweep_pending; }
