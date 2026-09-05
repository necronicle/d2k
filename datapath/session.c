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

#include "d2k_plans.h"
#include "d2k_session.h"
#include "d2k_tls.h"

/* Сколько первых пакетов потока имеет смысл разбирать в поисках приветствия.
 * ClientHello приходит первым или почти первым; после этого разбор — чистая
 * трата на каждом пакете загрузки. */
#define D2K_HELLO_WINDOW 8

struct d2k_session {
    d2k_table   *flows;
    d2k_plantab *plans;
    /* Запасной план — на все цели сразу. В продукте его быть не должно: §2.6
     * закрепляет план за контекстом, на котором он подтверждён, а один план
     * на весь трафик означает, что ошибка на одной цели переключит все
     * остальные без проверки. Он существует для опытов, где сужение задано
     * снаружи правилом firewall на одну пару адресов. */
    d2k_plan    *plan;
    d2k_journal *jrn;
    uint64_t     applied;
    uint64_t     hellos;
    uint64_t     with_sni;
    uint64_t     suspects;
    uint64_t     rst_dropped;
};

d2k_session *d2k_session_new(size_t capacity, size_t journal) {
    d2k_session *s = calloc(1, sizeof *s);
    if (!s) {
        return NULL;
    }
    s->flows = d2k_track_new(capacity);
    s->jrn = d2k_journal_new(journal);
    s->plans = d2k_plantab_new(256);
    if (!s->flows || !s->plans || (journal > 0 && !s->jrn)) {
        d2k_plantab_free(s->plans);
        d2k_journal_free(s->jrn);
        d2k_track_free(s->flows);
        free(s);
        return NULL;
    }
    return s;
}

void d2k_session_free(d2k_session *s) {
    if (!s) {
        return;
    }
    d2k_plantab_free(s->plans);
    d2k_journal_free(s->jrn);
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

/* Отказ по плану в журнал. Отдельной функцией, чтобы каждая точка отказа
   писала одинаково: журнал, в котором половина отказов не отмечена, хуже
   отсутствующего — он выглядит полным. */
static void refuse(d2k_session *s, uint64_t at_ns, const d2k_key *k,
                   const char *why) {
    d2k_journal_add(s->jrn, at_ns, k, D2K_JRN_PLAN_REFUSED, 0, NULL, 0, why);
}

/* Подозрение. Отмечается ОДИН раз на поток: три улики об одном соединении
   выглядели бы как три соединения, а это разные факты.
   Слово «подозрение» выбрано вместо «блокировки» намеренно: §2.4 запрещает
   превращать наблюдение в диагноз, а §2.3 — сохранять отрицательный результат
   вообще. Отсюда ничего не пишется на диск. */
static void suspect(d2k_session *s, uint64_t at_ns, const d2k_key *k,
                    d2k_flow *fl, uint8_t code) {
    if (fl->suspected) {
        return;
    }
    fl->suspected = 1;
    s->suspects++;
    d2k_journal_add(s->jrn, at_ns, k, D2K_JRN_SUSPECT, code, NULL, 0, NULL);
}

/* Зовётся при забвении потока по молчанию. Приветствие ушло, ответа с той
   стороны не было ни одного — и узнать это можно только здесь, в конце. */
static void on_flow_expire(void *ctx, const d2k_flow *f) {
    d2k_session *s = ctx;
    if (!f->saw_hello || f->rev_after_hello > 0 || f->suspected) {
        return;
    }
    s->suspects++;
    d2k_journal_add(s->jrn, f->last_ns, &f->key, D2K_JRN_SUSPECT,
                    D2K_SUSPECT_SILENT, NULL, 0, NULL);
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
    int src_is_low = d2k_key_make(&key, pkt + 12, pkt + 16, t + 0, t + 2);

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

    /* Направление. Сперва по флагам, и только потом по порядку прибытия.
       SYN без ACK шлёт тот, кто открывает соединение; SYN с ACK — тот, кто
       отвечает. Это свойство протокола, а не наблюдения, и потому надёжнее:
       два направления приходят из ДВУХ правил firewall, и порядок между ними
       не гарантирован ничем. Ранняя редакция определяла сторону по первому
       увиденному пакету, и поток, у которого SYN-ACK обогнал SYN, получал
       направления наоборот — приветствие клиента считалось ответом сервера и
       не разбиралось вовсе. */
    if (!fl->dir_known) {
        if (syn && !ack) {
            fl->init_low = src_is_low;
            fl->dir_known = 1;
        } else if (syn && ack) {
            fl->init_low = !src_is_low;
            fl->dir_known = 1;
        } else if (fl->fwd_pkts == 0 && fl->rev_pkts == 0) {
            /* Поток подхвачен посреди обмена: рукопожатия мы не видели.
               Берём порядок прибытия и НЕ считаем это знанием — придёт SYN,
               поправимся. */
            fl->init_low = src_is_low;
        }
    }
    const int fwd = (src_is_low == fl->init_low);

    /* Снимок ДО учёта этого пакета. Сам сброс — тоже пакет с обратной
       стороны, и, посчитав его первым, проверка «ответов не было» не сработала
       бы никогда: счётчик к моменту проверки уже единица. */
    const uint32_t rev_before = fl->rev_after_hello;

    if (fwd) {
        fl->fwd_pkts++;
        fl->fwd_bytes += total;
    } else {
        if (!fl->rev_profiled) {
            /* Первый пакет с той стороны задаёт ориентир. Обычно это SYN-ACK,
               то есть заведомо настоящий сервер: подделка приходит позже, в
               ответ на приветствие. */
            fl->rev_profiled = 1;
            fl->rev_ttl = pkt[8];
            fl->rev_tos = pkt[1];
        }
        fl->rev_pkts++;
        fl->rev_bytes += total;
        if (fl->saw_hello) {
            fl->rev_after_hello++;
        }
    }
    if (syn && !ack) {
        fl->saw_syn = 1;
    }
    if (syn && ack) {
        fl->saw_synack = 1;
    }

    /* Закрытие — повод отпустить ячейку сразу, не дожидаясь молчания.
       Но сперва посмотреть, не улика ли это. */
    if (rst && !fwd && (fl->guards & D2K_GUARD_RST_ALIEN) && fl->rev_profiled &&
        pkt[8] != fl->rev_ttl) {
        /* Сброс пришёл с другим TTL, чем всё, что до сих пор отвечало по этому
           соединению, — значит послан не оттуда. Снимаем.

           Поток НЕ удаляется: настоящий сервер про это соединение ничего не
           знает и продолжит отвечать, а нам ещё смотреть, чем кончится.
           Подозрение при этом отмечается: то, что мы сняли подделку, не
           означает, что её не было. §2.3 — на диск отсюда не идёт ничего. */
        fl->rst_dropped++;
        s->rst_dropped++;
        if (fl->saw_hello && rev_before == 0) {
            suspect(s, now_ns, &key, fl, D2K_SUSPECT_RST_CUT);
        }
        out->verdict = D2K_VERDICT_DROP;
        out->skipped = "чужой сброс снят защитой";
        return 0;
    }

    if (rst || fin) {
        if (rst && !fwd && fl->saw_hello && rev_before == 0) {
            /* Сброс пришёл с той стороны, куда ушло приветствие, и никаких
               других ответов оттуда не было. Это НАБЛЮДЕНИЕ, а не диагноз:
               §2.4 запрещает выводить из него устройство механизма. Сервер
               мог и правда закрыть соединение. */
            fl->saw_rev_rst = 1;
            suspect(s, now_ns, &key, fl, D2K_SUSPECT_RST);
        }
        d2k_track_remove(s->flows, &key);
        out->skipped = rst ? "соединение сброшено" : "соединение закрывается";
        return 0;
    }

    size_t payload_off = ihl + doff;
    size_t payload_len = total - payload_off;
    if (payload_len == 0) {
        out->skipped = "нет полезной нагрузки";
        return 0;
    }
    const uint32_t in_seq = rd32(t + 4);

    /* --- узнавание протокола -------------------------------------------
     * Стоит ДО всего, что связано с планом, и это не перестановка ради
     * красоты. Наблюдение обязано работать в режиме, где плана нет вовсе:
     * этап C документа — «видны реальные транзитные соединения», а не
     * «видны, если есть чем воздействовать». В первой версии проверка
     * «плана нет» стояла раньше разбора, и первый же полевой прогон дал
     * 145 пакетов с единственной причиной «плана нет» — о протоколе не
     * узналось ничего.
     *
     * Разбор ограничен началом соединения: дальше он всё равно ничего не
     * найдёт, а платить за него на каждом пакете загрузки незачем. Предел
     * здесь свой, а не унаследованный от правила firewall: датапат не
     * вправе считать, что снаружи стоит connbytes. */
    d2k_tls_info tls;
    memset(&tls, 0, sizeof tls);
    /* Повтор приветствия: тот же номер последовательности с той же стороны.
       Клиент повторяет, когда ответа нет, — самая дешёвая улика из доступных,
       и видна она в направлении, которое и так наблюдается. */
    if (fwd && fl->saw_hello && in_seq == fl->hello_seq) {
        fl->hello_repeats++;
        if (fl->hello_repeats >= 2) {
            suspect(s, now_ns, &key, fl, D2K_SUSPECT_REPEAT);
        }
    }

    if (!fl->saw_hello && fwd && fl->fwd_pkts <= D2K_HELLO_WINDOW) {
        d2k_tls_parse(pkt + payload_off, payload_len, &tls);
        if (tls.is_client_hello) {
            fl->saw_hello = 1;
            fl->had_sni = tls.have_sni ? 1 : 0;
            fl->hello_seq = in_seq;
            s->hellos++;
            if (tls.have_sni) {
                s->with_sni++;
                d2k_journal_add(s->jrn, now_ns, &key, D2K_JRN_HELLO_SNI, 0,
                                pkt + payload_off + tls.sni_off, tls.sni_len,
                                NULL);
            } else {
                /* Имени нет — и это нормальное состояние модели (§5.3), а не
                   ошибка разбора. */
                d2k_journal_add(s->jrn, now_ns, &key, D2K_JRN_HELLO_NONAME, 0,
                                NULL, 0, NULL);
            }
        }
    }

    /* Выбор плана по цели. Имя из приветствия точнее адреса и потому идёт
       первым; адрес — запасной ключ, за которым у CDN стоят сотни имён. */
    const d2k_plan *use = NULL;
    if (tls.is_client_hello) {
        uint32_t dst_be;
        memcpy(&dst_be, pkt + 16, 4);
        use = d2k_plantab_find(s->plans,
                               tls.have_sni ? pkt + payload_off + tls.sni_off : NULL,
                               tls.have_sni ? tls.sni_len : 0,
                               dst_be);
        if (!use) {
            use = s->plan;
        }
    }

    if (!use) {
        out->skipped = "плана для этой цели нет";
        return 0;
    }
    if (!tls.is_client_hello) {
        /* Не приветствие — не наш случай. План первой версии описывает именно
           начало TLS-соединения. */
        out->skipped = "не ClientHello";
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
        refuse(s, now_ns, &key, out->skipped);
        return 0;
    }

    d2k_pkt in;
    memset(&in, 0, sizeof in);
    in.payload = pkt + payload_off;
    in.payload_len = payload_len;
    in.seq = in_seq;
    in.have_sni = tls.have_sni;
    in.sni_off = tls.sni_off;
    in.sni_len = tls.sni_len;

    d2k_actions acts;
    memset(&acts, 0, sizeof acts);
    if (d2k_plan_apply(use, fl, &in, &acts) != 0) {
        /* Неприменим — пропускаем как есть. Отказ исполнителя это результат, а
           не сбой: якорь может быть невычислим для конкретного пакета. */
        out->skipped = "план неприменим к этому пакету";
        refuse(s, now_ns, &key, out->skipped);
        d2k_actions_free(&acts);
        return 0;
    }

    /* --- сборка на провод ----------------------------------------------- */
    d2k_conn c;
    memset(&c, 0, sizeof c);
    /* Из пакета, а не из ключа: ключ канонизирован, и «низкая» сторона может
       оказаться сервером. Собранный по нему пакет полетел бы задом наперёд. */
    memcpy(&c.src_ip, pkt + 12, 4);
    memcpy(&c.dst_ip, pkt + 16, 4);
    memcpy(&c.src_port, t + 0, 2);
    memcpy(&c.dst_port, t + 2, 2);
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
            refuse(s, now_ns, &key, out->skipped);
            d2k_actions_free(&acts);
            return 0;
        }
        out->out[i].delay_us = acts.v[i].delay_us;
        out->out[i].off = used;
        out->out[i].len = made;
        used += made;
    }
    if (acts.fate == D2K_ORIG_HOLD) {
        /* Удержание оригинала датапат не умеет: пакет в очереди нельзя держать
           без вердикта, а выпустить его позже самим — отдельная работа с
           отдельной проверкой. Исполнитель такой судьбы сейчас не порождает,
           и проверка стоит здесь именно поэтому: если он начнёт, отказ
           случится сразу, а не превратится тихо в «пропустить». §2.5. */
        out->n_out = 0;
        out->verdict = D2K_VERDICT_ACCEPT;
        out->skipped = "удержание оригинала не поддержано";
        refuse(s, now_ns, &key, out->skipped);
        d2k_actions_free(&acts);
        return 0;
    }
    out->n_out = n;
    out->verdict = (acts.fate == D2K_ORIG_DROP) ? D2K_VERDICT_DROP
                                                : D2K_VERDICT_ACCEPT;
    fl->plan_done = 1;
    fl->guards = d2k_plan_guards(use);
    s->applied++;
    d2k_journal_add(s->jrn, now_ns, &key, D2K_JRN_PLAN_APPLIED, 0, NULL, 0, NULL);

    d2k_actions_free(&acts);
    return 0;
}

d2k_plantab *d2k_session_plans(d2k_session *s) {
    return s ? s->plans : NULL;
}

size_t d2k_session_plan_count(const d2k_session *s) {
    return s ? d2k_plantab_count(s->plans) : 0;
}

size_t d2k_session_plan_capacity(const d2k_session *s) {
    return s ? d2k_plantab_capacity(s->plans) : 0;
}

size_t d2k_session_expire(d2k_session *s, uint64_t now_ns, uint64_t idle_ns) {
    return s ? d2k_track_expire(s->flows, now_ns, idle_ns,
                                on_flow_expire, s) : 0;
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

size_t d2k_session_capacity(const d2k_session *s) {
    return s ? d2k_track_capacity(s->flows) : 0;
}

uint64_t d2k_session_hellos(const d2k_session *s) {
    return s ? s->hellos : 0;
}

uint64_t d2k_session_with_sni(const d2k_session *s) {
    return s ? s->with_sni : 0;
}

uint64_t d2k_session_suspects(const d2k_session *s) {
    return s ? s->suspects : 0;
}

uint64_t d2k_session_rst_dropped(const d2k_session *s) {
    return s ? s->rst_dropped : 0;
}

const d2k_journal *d2k_session_journal(const d2k_session *s) {
    return s ? s->jrn : NULL;
}
