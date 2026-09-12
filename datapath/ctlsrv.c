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

int d2k_plan_fits(const d2k_plan *p, uint32_t limits, uint32_t maxlen,
                  char *why, size_t cap) {
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
    /* ДЛИНА ПОСЫЛКИ. Ноль означает «предел не объявлен» — так бывает у стенда
       без сырого сокета, и резать там нечего.

       Сравнение строгое: посылка РОВНО в предел проходит. Перепутав его с
       «больше либо равно», мы отвергали бы полный кадр, который уедет.

       Отказ здесь, а не на отправке, — весь смысл этой проверки: на живой
       пробе 12.09.2026 ядро отвечало «sendto: Message too large» уже после
       того, как команда подтверждена, план встал и событие «план применён»
       ушло контроллеру, — то есть наша собственная неудача записывалась
       коробке в свойства. */
    if (maxlen > 0) {
        size_t need = d2k_plan_max_emit(p);
        if (need > (size_t)maxlen) {
            snprintf(why, cap,
                "самая длинная посылка плана — %zu байт, а способ отправки "
                "унесёт %u", need, (unsigned)maxlen);
            return 0;
        }
    }
    return 1;
}

/* Подтверждает команду. Зовётся ровно один раз на команду — иначе
   контроллер, ждущий подтверждения, дождался бы чужого.
 *
 * reason значим только при ok == 0 (см. D2K_ACK_* в d2k_ctl.h) — успех
 * всегда несёт D2K_ACK_OK, чтобы контроллеру не приходилось смотреть на
 * причину, когда смотреть не на что. Раньше здесь был только признак
 * успеха: контроллер получал одну и ту же «нулевую единицу отказа» что на
 * негодный план, что на переполненную таблицу планов, и не мог отличить
 * своего негодного кандидата от чужой нехватки места (см. большой
 * комментарий у D2K_EV_ACK, d2k_ctl.h). */
static void ack(d2k_ctlsrv *cx, uint16_t type, int ok, uint8_t reason) {
    /* Место под ключ потока есть у всех событий одинаково: подтверждение не
       про поток, но общая раскладка проще и сборке, и разбору. Ключ нулевой. */
    uint8_t body[D2K_KEY_WIRE_LEN + 4];
    memset(body, 0, sizeof body);
    body[D2K_KEY_WIRE_LEN] = (uint8_t)(type >> 8);
    body[D2K_KEY_WIRE_LEN + 1] = (uint8_t)type;
    body[D2K_KEY_WIRE_LEN + 2] = ok ? 1 : 0;
    body[D2K_KEY_WIRE_LEN + 3] = ok ? D2K_ACK_OK : reason;
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
        /* SET_NAME: [длина имени][имя][ФОРМА][план]. Форма байтом перед
           планом, а не после: длина плана в теле не объявлена, план это «всё,
           что осталось», и поле после него было бы съедено как его часть.
           Формат сменился 12.09.2026 вместе с кодом APPLIED — d2kd и d2kc
           обновляются согласованно (d2k_ctl.h, d2k_link.h). */
        size_t hdr = (type == D2K_CMD_SET_NAME) ? (len ? 2u + b[0] : 2u) : 4u;
        if (len < hdr) {
            ack(cx, type, 0, D2K_ACK_BAD_ARGS);
            return;
        }
        d2k_plan *p = NULL;
        if (d2k_plan_load(b + hdr, len - hdr, &p, why, sizeof why) != 0) {
            fprintf(stderr, "d2kd: план от контроллера не принят: %s\n", why);
            ack(cx, type, 0, D2K_ACK_BAD_PLAN);
            return;
        }
        if (!d2k_plan_fits(p, cx->send_limits, cx->send_maxlen, why, sizeof why)) {
            fprintf(stderr, "d2kd: план от контроллера не активирован: %s\n", why);
            d2k_plan_free(p);
            ack(cx, type, 0, D2K_ACK_BAD_PLAN);
            return;
        }
        int rc;
        if (type == D2K_CMD_SET_NAME) {
            rc = d2k_plantab_set_name_shaped(tab, b + 1, b[0], cx->now_ns, p,
                                             b[1u + b[0]]);
        } else {
            uint32_t addr;
            memcpy(&addr, b, 4);
            rc = d2k_plantab_set_addr(tab, addr, cx->now_ns, p);
        }
        /* Владение планом перешло таблице в любом случае, включая отказ.
           rc различает ДВЕ разные по вине причины: -1 — таблице планов
           нечего вытеснить (не вина плана, см. d2k_plans.h; с вытеснением
           по давности недостижимо для таблицы ненулевой ёмкости, но
           различение оставлено на случай нарушения этого инварианта), -2 —
           аргументы самой команды негодны (например, пустое имя). Обе
           причины не «план негоден», и путать их с D2K_ACK_BAD_PLAN нельзя:
           контроллер решает по этому коду, жечь ли кандидата. */
        uint8_t reason = D2K_ACK_OK;
        if (rc == -1) {
            reason = D2K_ACK_NO_ROOM;
        } else if (rc != 0) {
            reason = D2K_ACK_BAD_ARGS;
        }
        ack(cx, type, rc == 0, reason);
        return;
    }
    case D2K_CMD_ARM_SHAPE:
        if (len < 1 || len < 1u + b[0]) {
            ack(cx, type, 0, D2K_ACK_BAD_ARGS);
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
        ack(cx, type, 1, D2K_ACK_OK);
        return;
    case D2K_CMD_DEL_NAME:
        if (len < 1 || len < 1u + b[0]) {
            ack(cx, type, 0, D2K_ACK_BAD_ARGS);
            return;
        }
        d2k_plantab_del_name(tab, b + 1, b[0]);
        ack(cx, type, 1, D2K_ACK_OK);
        return;
    case D2K_CMD_DEL_ADDR: {
        if (len < 4) {
            ack(cx, type, 0, D2K_ACK_BAD_ARGS);
            return;
        }
        uint32_t addr;
        memcpy(&addr, b, 4);
        d2k_plantab_del_addr(tab, addr);
        ack(cx, type, 1, D2K_ACK_OK);
        return;
    }
    default:
        /* Незнакомая команда — не повод рвать соединение, но и не повод
           делать вид, что она исполнена. Отвечаем отказом и продолжаем. */
        ack(cx, type, 0, D2K_ACK_BAD_ARGS);
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
            /* Prepared, not yet sent. Never expose this as positive proof. */
            continue;
        case D2K_JRN_PLAN_DONE:
            type = D2K_EV_APPLIED;
            /* Идентификатор применённого плана — тем же приёмом, что и всё
               остальное здесь: побайтно в тело, без наложения структуры.
               Едет ВСЕГДА, даже когда он нулевой: у плана без записи REC_ID
               нули и есть честный ответ «плану нечем представиться», и
               контроллер читает их так же, как отсутствие поля у старого
               датапата (см. d2k_plan_id, d2k_plan.h). Постоянная длина тела
               к тому же избавляет ту сторону от разбора «есть или нет». */
            memcpy(body + n, e->plan_id, D2K_PLAN_ID_LEN);
            n += D2K_PLAN_ID_LEN;
            break;
        case D2K_JRN_PLAN_REFUSED:
            type = D2K_EV_REFUSED;
            /* План НЕ ПРИМЕНЯЛСЯ. Код нулевой — «причина не кодирована»
               (D2K_REFUSE_NONE): такой отказ случается на каждом транзитном
               потоке, где плана для цели нет, и ничего не говорит ни о
               коробке, ни о нашей отправке. Байт едет ВСЕГДА, а не только
               когда он ненулевой: постоянная длина тела избавляет ту сторону
               от разбора «есть или нет» — тот же приём, что у plan_id в
               APPLIED выше. */
            body[n++] = D2K_REFUSE_NONE;
            break;
        case D2K_JRN_PLAN_DAMAGED:
            /* Поток испорчен недоисполнением. Тем же видом события, что отказ
               применить и недоисполнение: для контроллера все три означают
               «измерения не было». Различает их КОД, и у повреждения он свой
               (D2K_REFUSE_DAMAGED): испорченный поток не просто не измерен —
               к нему больше ничего применять нельзя, и путать это с обычным
               «плана для цели нет» (код 0, на каждом транзитном потоке)
               нельзя тем более. Идентификатор плана едет следом, как у
               недоисполнения. */
            type = D2K_EV_REFUSED;
            body[n++] = e->code;
            memcpy(body + n, e->plan_id, D2K_PLAN_ID_LEN);
            n += D2K_PLAN_ID_LEN;
            break;
        case D2K_JRN_PLAN_UNSENT:
            /* План применён, но НЕ ДОИСПОЛНЕН: хотя бы одна его посылка не
               покинула машину. Тем же видом события, что и отказ применить,
               и это осознанно: для контроллера оба означают «измерения не
               было». Различает их КОД, и именно ради него он здесь и
               появился — без кода локальная поломка выглядела у контроллера
               ровно как «коробка не поддалась» (docs/decisions/0006). */
            type = D2K_EV_REFUSED;
            body[n++] = e->code;
            memcpy(body + n, e->plan_id, D2K_PLAN_ID_LEN);
            n += D2K_PLAN_ID_LEN;
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
            /* ПРИЁМКА ВОПРОСА — седьмым байтом, добавлением в хвост.
               Старый контроллер читает шесть первых и седьмой не замечает;
               новый требует его для приёмки. Добавление в хвост выбрано
               вместо бита в маске типов намеренно: маска говорит «такой тип
               записи встречался», а это поле — «запись разобрана и это ответ
               сервера», и складывать их в одно значило бы однажды принять
               алерт за ответ (см. is_server_hello, d2k_tls.h). */
            body[n++] = e->d_server_hello;
            break;
        default:
            continue;
        }
        d2k_ctl_event(ctl, type, body, n);
    }
}
