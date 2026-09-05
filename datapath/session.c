/* session.c — склейка модулей датапата.
 *
 * Правило, которому подчинено всё: НЕ ПОНЯЛ — НЕ ТРОГАЙ. Любая неясность —
 * незнакомый протокол, обрезанный заголовок, полная таблица, невычислимый
 * якорь — приводит к тому, что пакет проходит как есть. Пропустить чужой
 * пакет безвредно; тронуть непонятый — значит испортить соединение человеку и
 * не узнать об этом.
 *
 * Времена в наносекундах целыми. Плавающей арифметики на пакетном пути нет.
 */
#include <stdlib.h>
#include <string.h>

#include "d2k_session.h"
#include "d2k_tls.h"

struct d2k_session {
    d2k_table *flows;
    d2k_plan  *plan;
    uint64_t   applied;
};

d2k_session *d2k_session_new(size_t capacity) {
    d2k_session *s = calloc(1, sizeof *s);
    if (!s) {
        return NULL;
    }
    s->flows = d2k_track_new(capacity);
    if (!s->flows) {
        free(s);
        return NULL;
    }
    return s;
}

void d2k_session_free(d2k_session *s) {
    if (!s) {
        return;
    }
    d2k_track_free(s->flows);
    d2k_plan_free(s->plan);
    free(s);
}

void d2k_session_set_plan(d2k_session *s, d2k_plan *p) {
    if (!s) {
        return;
    }
    d2k_plan_free(s->plan);
    s->plan = p;
}

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8 | (uint32_t)p[3];
}

int d2k_session_packet(d2k_session *s, const uint8_t *pkt, size_t len,
                       uint64_t now_ns, uint8_t *buf, size_t bufcap,
                       d2k_result *out) {
    if (!out) {
        return 0;
    }
    memset(out, 0, sizeof *out);
    out->verdict = D2K_VERDICT_ACCEPT;
    if (!s || !pkt) {
        out->skipped = "нет сессии или пакета";
        return 0;
    }

    /* --- заголовки, с явными границами на каждом шаге ------------------- */
    if (len < 20 || (pkt[0] >> 4) != 4) {
        out->skipped = "не IPv4";
        return 0;
    }
    size_t ihl = (size_t)(pkt[0] & 0x0f) * 4;
    if (ihl < 20 || len < ihl + 20) {
        out->skipped = "заголовок не помещается";
        return 0;
    }
    if (pkt[9] != 6) {
        out->skipped = "не TCP";
        return 0;
    }
    /* Фрагмент без нулевого смещения не несёт заголовка TCP. Собирать
       фрагменты датапат не умеет и не должен: §5.2 говорит про ОГРАНИЧЕННУЮ
       пересборку, и её ещё нет. */
    if ((rd16(pkt + 6) & 0x1fff) != 0) {
        out->skipped = "фрагмент";
        return 0;
    }
    size_t total = rd16(pkt + 2);
    if (total > len || total < ihl + 20) {
        out->skipped = "поле длины не сходится";
        return 0;
    }

    const uint8_t *t = pkt + ihl;
    size_t doff = (size_t)(t[12] >> 4) * 4;
    if (doff < 20 || ihl + doff > total) {
        out->skipped = "заголовок TCP не помещается";
        return 0;
    }

    d2k_key key;
    memset(&key, 0, sizeof key);
    memcpy(&key.src_ip, pkt + 12, 4);
    memcpy(&key.dst_ip, pkt + 16, 4);
    memcpy(&key.src_port, t + 0, 2);
    memcpy(&key.dst_port, t + 2, 2);

    uint8_t flags = t[13];
    const int fin = (flags & 0x01) != 0;
    const int syn = (flags & 0x02) != 0;
    const int rst = (flags & 0x04) != 0;
    const int ack = (flags & 0x10) != 0;

    d2k_flow *fl = d2k_track_get(s->flows, &key, now_ns);
    if (!fl) {
        /* Таблица полна. Пропускаем — и это правильный исход: обработать
           пакет без учёта потока значит применить план второй раз к тому же
           соединению. */
        out->skipped = "таблица потоков полна";
        return 0;
    }

    fl->out_pkts++;
    fl->out_bytes += total;
    if (syn && !ack) {
        fl->saw_syn = 1;
    }
    if (syn && ack) {
        fl->saw_synack = 1;
    }

    /* Закрытие — повод отпустить ячейку сразу, не дожидаясь молчания. */
    if (rst || fin) {
        d2k_track_remove(s->flows, &key);
        out->skipped = rst ? "соединение сброшено" : "соединение закрывается";
        return 0;
    }

    if (!s->plan) {
        out->skipped = "плана нет";
        return 0;
    }
    if (fl->plan_done) {
        /* План описывает обработку начала соединения. Применить его дважды
           значит послать фальшивку в середину потока, где она уже ничего не
           значит, а вреда наделает. */
        out->skipped = "план уже применён к этому потоку";
        return 0;
    }
    if (fl->damaged) {
        out->skipped = "поток испорчен предыдущей отменой";
        return 0;
    }

    size_t payload_off = ihl + doff;
    size_t payload_len = total - payload_off;
    if (payload_len == 0) {
        out->skipped = "нет полезной нагрузки";
        return 0;
    }

    /* --- протокол ------------------------------------------------------- */
    d2k_tls_info tls;
    d2k_tls_parse(pkt + payload_off, payload_len, &tls);
    if (!tls.is_client_hello) {
        /* Не приветствие — не наш случай. План первой версии описывает именно
           начало TLS-соединения. */
        out->skipped = "не ClientHello";
        return 0;
    }

    d2k_pkt in;
    memset(&in, 0, sizeof in);
    in.payload = pkt + payload_off;
    in.payload_len = payload_len;
    in.seq = rd32(t + 4);
    in.have_sni = tls.have_sni;
    in.sni_off = tls.sni_off;
    in.sni_len = tls.sni_len;

    d2k_actions acts;
    memset(&acts, 0, sizeof acts);
    if (d2k_plan_apply(s->plan, fl, &in, &acts) != 0) {
        /* Неприменим — пропускаем как есть. Отказ исполнителя это результат, а
           не сбой: якорь может быть невычислим для конкретного пакета. */
        out->skipped = "план неприменим к этому пакету";
        d2k_actions_free(&acts);
        return 0;
    }

    /* --- сборка на провод ----------------------------------------------- */
    d2k_conn c;
    memset(&c, 0, sizeof c);
    c.src_ip = key.src_ip;
    c.dst_ip = key.dst_ip;
    c.src_port = key.src_port;
    c.dst_port = key.dst_port;
    c.ack = rd32(t + 8);
    c.window = rd16(t + 14);
    c.ttl = pkt[8];
    c.ip_id = rd16(pkt + 4);

    size_t used = 0;
    size_t n = acts.n;
    if (n > sizeof out->out / sizeof out->out[0]) {
        n = sizeof out->out / sizeof out->out[0];
    }
    for (size_t i = 0; i < n; i++) {
        size_t made = d2k_wire_build(&c, &acts.v[i], buf + used, bufcap - used);
        if (made == 0) {
            /* Не поместилось. Отменяем то, что ещё не ушло, и спрашиваем
               исполнитель, что делать с оригиналом: половина выпущенного плана
               — это отмена, а у неё есть определённые правила. */
            d2k_cancel cancel;
            d2k_actions_cancel(&acts, i, &cancel);
            out->n_out = i;
            out->verdict = (cancel.fate == D2K_ORIG_DROP) ? D2K_VERDICT_DROP
                                                          : D2K_VERDICT_ACCEPT;
            if (cancel.stream_damaged) {
                fl->damaged = 1;
            }
            out->skipped = "буфер отправки кончился";
            d2k_actions_free(&acts);
            return 0;
        }
        out->out[i].delay_us = acts.v[i].delay_us;
        out->out[i].off = used;
        out->out[i].len = made;
        used += made;
    }
    out->n_out = n;
    out->verdict = (acts.fate == D2K_ORIG_DROP) ? D2K_VERDICT_DROP
                                                : D2K_VERDICT_ACCEPT;
    fl->plan_done = 1;
    s->applied++;

    d2k_actions_free(&acts);
    return 0;
}

size_t d2k_session_flows(const d2k_session *s) {
    return s ? d2k_track_count(s->flows) : 0;
}

uint64_t d2k_session_applied(const d2k_session *s) {
    return s ? s->applied : 0;
}

uint64_t d2k_session_refusals(const d2k_session *s) {
    return s ? d2k_track_refusals(s->flows) : 0;
}
