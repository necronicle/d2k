/* ctlsrv.c — смысл команд и событий управляющего сокета.
 *
 * Переносимо: ни NFQUEUE, ни сырых сокетов. Смысл протокола обязан
 * проверяться настоящим клиентом на любой машине, а не только на роутере под
 * root — иначе расхождение двух реализаций найдётся в поле.
 */
#include <stdio.h>
#include <string.h>

#include "d2k_ctlsrv.h"

int d2k_plan_fits(const d2k_plan *p, uint32_t limits, char *why, size_t cap) {
    if (limits == 0) {
        return 1;   /* наблюдение: на провод ничего не пойдёт */
    }
    uint8_t used = d2k_plan_poison_used(p);
    if ((used & D2K_POISON_IPID_ZERO) && (limits & D2K_RAW_CANT_IPID)) {
        snprintf(why, cap,
            "план просит нулевой идентификатор IP, а сырой сокет им не "
            "распоряжается: ядро подставит свой");
        return 0;
    }
    return 1;
}

void d2k_ctlsrv_command(void *vctx, uint16_t type, const uint8_t *b, size_t len) {
    d2k_ctlsrv *cx = vctx;
    char why[200];
    d2k_plantab *tab = d2k_session_plans(cx->sess);

    switch (type) {
    case D2K_CMD_SET_NAME:
    case D2K_CMD_SET_ADDR: {
        size_t hdr = (type == D2K_CMD_SET_NAME) ? (len ? 1u + b[0] : 1u) : 4u;
        if (len < hdr) {
            cx->bad_cmds++;
            return;
        }
        d2k_plan *p = NULL;
        if (d2k_plan_load(b + hdr, len - hdr, &p, why, sizeof why) != 0) {
            fprintf(stderr, "d2kd: план от контроллера не принят: %s\n", why);
            cx->bad_cmds++;
            return;
        }
        if (!d2k_plan_fits(p, cx->send_limits, why, sizeof why)) {
            fprintf(stderr, "d2kd: план от контроллера не активирован: %s\n", why);
            d2k_plan_free(p);
            cx->bad_cmds++;
            return;
        }
        int rc;
        if (type == D2K_CMD_SET_NAME) {
            rc = d2k_plantab_set_name(tab, b + 1, b[0], p);
        } else {
            uint32_t addr;
            memcpy(&addr, b, 4);
            rc = d2k_plantab_set_addr(tab, addr, p);
        }
        /* Владение планом перешло таблице в любом случае, включая отказ. */
        if (rc == 0) { cx->ok_cmds++; } else { cx->bad_cmds++; }
        return;
    }
    case D2K_CMD_DEL_NAME:
        if (len < 1 || len < 1u + b[0]) {
            cx->bad_cmds++;
            return;
        }
        d2k_plantab_del_name(tab, b + 1, b[0]);
        cx->ok_cmds++;
        return;
    case D2K_CMD_DEL_ADDR: {
        if (len < 4) {
            cx->bad_cmds++;
            return;
        }
        uint32_t addr;
        memcpy(&addr, b, 4);
        d2k_plantab_del_addr(tab, addr);
        cx->ok_cmds++;
        return;
    }
    default:
        /* Незнакомая команда — не повод рвать соединение, но и не повод
           делать вид, что она исполнена. Считаем и продолжаем. */
        cx->bad_cmds++;
        return;
    }
}

void d2k_ctlsrv_pump(d2k_ctl *ctl, const d2k_session *s, uint64_t *seen) {
    const d2k_journal *j = d2k_session_journal(s);
    uint64_t added = d2k_journal_added(j);
    if (added <= *seen) {
        return;
    }
    size_t have = d2k_journal_count(j);
    uint64_t fresh = added - *seen;
    size_t from = (fresh >= have) ? 0 : (size_t)(have - fresh);
    *seen = added;

    for (size_t i = from; i < have; i++) {
        const d2k_jrn_entry *e = d2k_journal_at(j, i);
        if (!e) {
            continue;
        }
        uint8_t body[16 + D2K_JRN_NAME_MAX + 8];
        memcpy(body, &e->key, sizeof e->key);
        size_t n = sizeof e->key;
        uint16_t type = 0;
        switch (e->kind) {
        case D2K_JRN_HELLO_SNI:
        case D2K_JRN_HELLO_NONAME:
            type = D2K_EV_HELLO;
            body[n++] = e->name_len;
            if (e->name_len) {
                memcpy(body + n, e->name, e->name_len);
                n += e->name_len;
            }
            break;
        case D2K_JRN_SUSPECT:
            type = D2K_EV_SUSPECT;
            body[n++] = e->code;
            break;
        case D2K_JRN_PLAN_APPLIED:
            type = D2K_EV_APPLIED;
            break;
        case D2K_JRN_PLAN_REFUSED:
            type = D2K_EV_REFUSED;
            break;
        case D2K_JRN_EXCHANGE:
            type = D2K_EV_EXCHANGE;
            body[n++] = e->code;            /* тип первой TLS-записи */
            body[n++] = (uint8_t)(e->num >> 24);
            body[n++] = (uint8_t)(e->num >> 16);
            body[n++] = (uint8_t)(e->num >> 8);
            body[n++] = (uint8_t)e->num;
            break;
        default:
            continue;
        }
        d2k_ctl_event(ctl, type, body, n);
    }
}

