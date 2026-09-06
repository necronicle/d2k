/* ctlsrv.c — смысл команд и событий управляющего сокета.
 *
 * Переносимо: ни NFQUEUE, ни сырых сокетов. Смысл протокола обязан
 * проверяться настоящим клиентом на любой машине, а не только на роутере под
 * root — иначе расхождение двух реализаций найдётся в поле.
 */
#include <stdio.h>
#include <string.h>

#include "d2k_ctlsrv.h"

/* Кладёт ключ потока в тело события ПОЛЯМИ, а не наложением структуры на
 * буфер: memcpy(тело, &ключ, sizeof ключ) отправил бы на провод и три байта
 * дыры выравнивания (sizeof(d2k_key) == 16, значащих байт — D2K_KEY_WIRE_LEN
 * == 13), с непредсказуемым содержимым — см. большой комментарий у d2k_key
 * (d2k_track.h) про то, почему на эту дыру нельзя полагаться нигде, кроме
 * зануления внутри d2k_key_make. Тот же приём, каким остальной датапат
 * (wire.c, wire_udp.c) собирает заголовки: поле в поле, явным порядком.
 * Возвращает D2K_KEY_WIRE_LEN — сколько байт записано. */
static size_t put_key(uint8_t *out, const d2k_key *k) {
    memcpy(out + 0, &k->low_ip, 4);
    memcpy(out + 4, &k->high_ip, 4);
    memcpy(out + 8, &k->low_port, 2);
    memcpy(out + 10, &k->high_port, 2);
    out[12] = k->proto;
    return D2K_KEY_WIRE_LEN;
}

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

/* Подтверждает команду. Зовётся ровно один раз на команду — иначе
   контроллер, ждущий подтверждения, дождался бы чужого. */
static void ack(d2k_ctlsrv *cx, uint16_t type, int ok) {
    /* Место под ключ потока есть у всех событий одинаково: подтверждение не
       про поток, но общая раскладка проще и сборке, и разбору. Ключ нулевой. */
    uint8_t body[D2K_KEY_WIRE_LEN + 3];
    memset(body, 0, sizeof body);
    body[D2K_KEY_WIRE_LEN] = (uint8_t)(type >> 8);
    body[D2K_KEY_WIRE_LEN + 1] = (uint8_t)type;
    body[D2K_KEY_WIRE_LEN + 2] = ok ? 1 : 0;
    if (ok) {
        cx->ok_cmds++;
    } else {
        cx->bad_cmds++;
    }
    if (cx->ctl) {
        d2k_ctl_event(cx->ctl, D2K_EV_ACK, body, sizeof body);
    }
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
            ack(cx, type, 0);
            return;
        }
        d2k_plan *p = NULL;
        if (d2k_plan_load(b + hdr, len - hdr, &p, why, sizeof why) != 0) {
            fprintf(stderr, "d2kd: план от контроллера не принят: %s\n", why);
            ack(cx, type, 0);
            return;
        }
        if (!d2k_plan_fits(p, cx->send_limits, why, sizeof why)) {
            fprintf(stderr, "d2kd: план от контроллера не активирован: %s\n", why);
            d2k_plan_free(p);
            ack(cx, type, 0);
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
        ack(cx, type, rc == 0);
        return;
    }
    case D2K_CMD_ARM_SHAPE:
        if (len < 1 || len < 1u + b[0]) {
            ack(cx, type, 0);
            return;
        }
        if (d2k_session_want_shape(cx->sess, b + 1, b[0])) {
            /* Готово прямо сейчас — отдаём, не дожидаясь следующего
               приветствия. */
            size_t slen = 0;
            const uint8_t *sh = d2k_session_shape(cx->sess, &slen);
            if (sh && slen > 0 && cx->ctl) {
                uint8_t body[D2K_KEY_WIRE_LEN + 2048];
                memset(body, 0, D2K_KEY_WIRE_LEN);
                if (slen <= sizeof body - D2K_KEY_WIRE_LEN) {
                    memcpy(body + D2K_KEY_WIRE_LEN, sh, slen);
                    d2k_ctl_event(cx->ctl, D2K_EV_SHAPE, body, D2K_KEY_WIRE_LEN + slen);
                }
            }
        }
        ack(cx, type, 1);
        return;
    case D2K_CMD_DEL_NAME:
        if (len < 1 || len < 1u + b[0]) {
            ack(cx, type, 0);
            return;
        }
        d2k_plantab_del_name(tab, b + 1, b[0]);
        ack(cx, type, 1);
        return;
    case D2K_CMD_DEL_ADDR: {
        if (len < 4) {
            ack(cx, type, 0);
            return;
        }
        uint32_t addr;
        memcpy(&addr, b, 4);
        d2k_plantab_del_addr(tab, addr);
        ack(cx, type, 1);
        return;
    }
    default:
        /* Незнакомая команда — не повод рвать соединение, но и не повод
           делать вид, что она исполнена. Отвечаем отказом и продолжаем. */
        ack(cx, type, 0);
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
        /* Хватает и на приветствие целиком: форма приезжает сюда же. */
        uint8_t body[D2K_KEY_WIRE_LEN + 2048 + 8];
        size_t n = put_key(body, &e->key);
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
            /* Подробности — то, ЧЕМ подозрительный пакет отличался от
               остальных в этом же потоке. Из них складывается отпечаток
               коробки; без них в каталоге лежал бы факт «был сброс», по
               которому одну коробку от другой не отличить. */
            body[n++] = e->d_ttl;
            body[n++] = e->d_ref_ttl;
            body[n++] = e->d_tos;
            body[n++] = (uint8_t)(e->d_ipid >> 8);
            body[n++] = (uint8_t)e->d_ipid;
            break;
        case D2K_JRN_PLAN_APPLIED:
            type = D2K_EV_APPLIED;
            break;
        case D2K_JRN_PLAN_REFUSED:
            type = D2K_EV_REFUSED;
            break;
        case D2K_JRN_SHAPE: {
            /* Байты приветствия лежат не в журнале, а в ловушке сессии:
               запись журнала ограничена, а приветствие бывает в килобайт. */
            size_t slen = 0;
            const uint8_t *sh = d2k_session_shape(s, &slen);
            if (!sh || slen == 0 || n + slen > sizeof body) {
                continue;
            }
            type = D2K_EV_SHAPE;
            memcpy(body + n, sh, slen);
            n += slen;
            break;
        }
        case D2K_JRN_EXCHANGE:
            type = D2K_EV_EXCHANGE;
            body[n++] = e->code;            /* тип первой TLS-записи */
            body[n++] = e->d_tos;           /* набор встреченных типов */
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

