#include "d2km_sim.h"
#include "d2km_tls.h"

#include <string.h>

static int blocked(const d2km_sim *s, const char *name)
{
    return s->blocked_suffix != NULL && d2km_name_suffix_match(name, s->blocked_suffix);
}

/* Имя в приветствии; пустая строка — не разобрать. */
static void hello_name(const uint8_t *b, size_t n, char *out, size_t cap)
{
    /* Each simulated network arm may run on its own worker, just like the
       real transport. One parser arena cannot be shared across those arms. */
    static __thread d2km_tls_hello h;
    out[0] = '\0';
    if (b != NULL && d2km_tls_parse(b, n, &h) == D2KM_TLS_OK)
        d2km_tls_sni(&h, out, cap);
}

static d2km_result R(d2km_result_kind k)
{
    d2km_result r = {.kind = k};
    return r;
}

static int sim_run(void *ctx, const d2km_arm_spec *a, d2km_observation *obs,
                   d2km_result *res)
{
    d2km_sim *s = ctx;
    s->runs++;
    memset(obs, 0, sizeof(*obs));
    obs->sent_packets = 1;
    if (s->local_fail_every && s->runs % (unsigned)s->local_fail_every == 0) {
        obs->sent_packets = 0;
        *res = R(D2KM_R_LOCAL_FAIL);   /* своя сторона: посылка не ушла */
        return 0;
    }
    if (s->flaky_every && s->runs % (unsigned)s->flaky_every == 0) {
        obs->timeouts = 1;
        *res = R(D2KM_R_HELLO_SILENT);   /* потеря в сети */
        return 0;
    }
    if (a->reference) {
        if (s->reference_down) {
            obs->sent_packets = 0;
            *res = R(D2KM_R_NOT_MEASURED);
            return 0;
        }
        *res = R(s->server_down ? D2KM_R_SYN_SILENT : D2KM_R_APP_OK);
        return 0;
    }
    if (s->server_down) {
        *res = R(D2KM_R_SYN_SILENT);
        return 0;
    }
    if (s->addr_block) {
        *res = R(D2KM_R_SYN_SILENT);
        return 0;
    }
    char name[256];
    switch (a->kind) {
    case D2KM_ARM_PATH_SERVER:
        *res = R(a->ttl >= s->server_hop ? D2KM_R_APP_OK : D2KM_R_SYN_SILENT);
        return 0;
    case D2KM_ARM_PATH_BOX:
        hello_name(a->hello, a->hello_length, name, sizeof(name));
        if (a->ttl >= s->box_hop && s->reads_name && !s->late_cut && blocked(s, name))
            *res = R(s->silent_box ? D2KM_R_HELLO_SILENT : D2KM_R_RST);
        else if (a->ttl >= s->server_hop)
            *res = R(D2KM_R_REPLY);
        else
            *res = R(D2KM_R_HELLO_SILENT);
        return 0;
    case D2KM_ARM_EXCHANGE:
        break;
    default:
        return -1;
    }
    /* Коробка решает по первому приветствию, которое смогла прочитать. */
    const d2km_program *p = a->program;
    char seen[256] = "";
    int server_garbage = 0;
    if (p != NULL) {
        for (size_t i = 0; i < p->fake_count; i++) {
            const d2km_fake *f = &p->fakes[i];
            const d2km_payload *pl = &p->payloads[f->payload];
            int reaches_box = !f->poison.ttl || f->poison.ttl >= s->box_hop;
            int reaches_server = !f->poison.ttl || f->poison.ttl >= s->server_hop;
            unsigned spoil = (f->poison.tcpts ? 1u : 0u) | (f->poison.md5 ? 2u : 0u) |
                (f->poison.badsum ? 4u : 0u);
            int dropped_by_server = (spoil & ~s->server_accepts) != 0;
            if ((spoil & s->server_flaky) && (s->runs & 1u))
                dropped_by_server = 0;   /* через раз сервер фальшивку принимает */
            if (reaches_box && !(spoil & s->checks) &&
                !(s->ignores_low_ttl && f->poison.ttl) &&
                f->repeats >= (s->min_copies ? s->min_copies : 1) && !seen[0])
                hello_name(pl->bytes, pl->length, seen, sizeof(seen));
            if (reaches_server && !dropped_by_server)
                server_garbage = 1;
            obs->sent_packets += f->repeats;
            if (f->repeats > s->max_repeats_seen) s->max_repeats_seen = f->repeats;
        }
    }
    int name_hidden = 0;
    if (p != NULL)
        for (size_t i = 0; i < p->split_count; i++)
            if (p->splits[i].anchor == D2KM_AT_SNI_START && p->splits[i].offset > 0 &&
                !s->reassembles)
                name_hidden = 1;
    if (p != NULL && s->header_split_relief)
        for (size_t i = 0; i < p->split_count; i++)
            if (p->splits[i].anchor == D2KM_AT_PAYLOAD_START &&
                p->splits[i].offset >= 1 && p->splits[i].offset <= 4) name_hidden = 1;
    if (!seen[0] && !name_hidden)
        hello_name(a->hello, a->hello_length, seen, sizeof(seen));
    if (s->reads_name && seen[0] && blocked(s, seen) && s->late_cut) {
        obs->rsts = 1;
        *res = R(D2KM_R_CUT);   /* сервер ответил, обмен оборвался */
        return 0;
    }
    if (s->reads_name && seen[0] && blocked(s, seen)) {
        obs->rsts = s->silent_box ? 0 : 1;
        *res = R(s->silent_box ? D2KM_R_HELLO_SILENT : D2KM_R_RST);
        return 0;
    }
    if (server_garbage) {
        obs->rsts = 1;
        *res = R(D2KM_R_RST);   /* сервер получил фальшивку и сорвал обмен */
        return 0;
    }
    obs->received_packets = 4;
    if (s->cert_suffix != NULL) {
        char real[256];
        hello_name(a->hello, a->hello_length, real, sizeof(real));
        if (!d2km_name_suffix_match(real, s->cert_suffix)) {
            *res = R(D2KM_R_REPLY);   /* сервер ответил, сертификата на это имя нет */
            return 0;
        }
    }
    obs->application_bytes = 1000;
    *res = R(D2KM_R_APP_OK);
    return 0;
}

d2km_net d2km_sim_net(d2km_sim *s)
{
    d2km_net n = {.ctx = s, .run = sim_run};
    return n;
}
