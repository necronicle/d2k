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
#include "d2k_time.h"
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
    uint64_t     exchanges;

    /* Разбор нагрузки: почему приветствие не узналось. */
    uint64_t     pay_reverse;      /* нагрузка с обратной стороны */
    uint64_t     pay_after_hello;  /* поток уже показал приветствие */
    uint64_t     pay_late;         /* прямая, но за окном поиска */
    uint64_t     pay_not_hello;    /* разобрали и это не приветствие */
    uint8_t      last_nonhello_first;
    uint64_t     sni_in_next_seg;

    /* Форма приветствия. Один буфер на всю сессию, и это объявленный предел:
     * хранить приветствие каждого потока значило бы килобайт на поток.
     *
     * last_* — последнее увиденное приветствие, копится всегда.
     * ready_* — то, что готово к выдаче по запросу. */
    uint8_t  last_hello[2048];
    size_t   last_hello_len;
    uint8_t  last_name[256];
    size_t   last_name_len;

    int      shape_armed;
    uint8_t  shape_name[256];
    size_t   shape_name_len;
    uint8_t  shape[2048];
    size_t   shape_len;
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

/* Сравнение имени цели без учёта регистра. Своя функция, а не strncasecmp:
   тот зависит от локали. */
static int name_same(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen) {
    if (alen != blen) {
        return 0;
    }
    for (size_t i = 0; i < alen; i++) {
        uint8_t x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') { x = (uint8_t)(x - 'A' + 'a'); }
        if (y >= 'A' && y <= 'Z') { y = (uint8_t)(y - 'A' + 'a'); }
        if (x != y) {
            return 0;
        }
    }
    return 1;
}

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

/* Отказ по плану в журнал. Отдельной функцией, чтобы каждая точка отказа
   писала одинаково: журнал, в котором половина отказов не отмечена, хуже
   отсутствующего — он выглядит полным. */
static void refuse(d2k_session *s, uint64_t at_ns, const d2k_key *k,
                   const char *why) {
    d2k_journal_add(s->jrn, at_ns, k, D2K_JRN_PLAN_REFUSED, 0, 0, NULL, NULL, 0, why);
}

/* Подозрение. Отмечается ОДИН раз на поток: три улики об одном соединении
   выглядели бы как три соединения, а это разные факты.
   Слово «подозрение» выбрано вместо «блокировки» намеренно: §2.4 запрещает
   превращать наблюдение в диагноз, а §2.3 — сохранять отрицательный результат
   вообще. Отсюда ничего не пишется на диск. */
static void suspect(d2k_session *s, uint64_t at_ns, const d2k_key *k,
                    d2k_flow *fl, uint8_t code, const d2k_jrn_detail *det) {
    if (fl->suspected) {
        return;
    }
    fl->suspected = 1;
    s->suspects++;
    d2k_journal_add(s->jrn, at_ns, k, D2K_JRN_SUSPECT, code, 0, det, NULL, 0, NULL);
}

/* Зовётся при забвении потока по молчанию. Приветствие ушло, ответа с той
   стороны не было ни одного — и узнать это можно только здесь, в конце. */
static void on_flow_expire(void *ctx, const d2k_flow *f) {
    d2k_session *s = ctx;
    if (!f->saw_hello || f->rev_after_hello > 0 || f->suspected) {
        return;
    }
    s->suspects++;
    d2k_journal_add(s->jrn, f->last_ns, &f->key, D2K_JRN_SUSPECT, D2K_SUSPECT_SILENT, 0, NULL, NULL, 0, NULL);
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
            size_t rpay_off = ihl + doff;
            if (total > rpay_off) {
                size_t rpay = total - rpay_off;
                uint8_t t0 = pkt[rpay_off];
                if (fl->rev_first_type == 0) {
                    /* Тип первой TLS-записи запоминается как есть. Толковать
                       его здесь нельзя: 0x16 рукопожатие и 0x15 предупреждение
                       — разные вещи, а §4.2 требует, чтобы уровни
                       доказательства различал принимающий решение. */
                    fl->rev_first_type = t0;
                }
                /* Начало пакета — не начало записи, поэтому набор говорит
                   «такой тип встречался», а не «записей столько-то».
                   Прикладные данные здесь важнее прочего: по §4.2 одного
                   ServerHello для подтверждения НЕ хватает. */
                if (t0 >= 20 && t0 <= 23) {
                    fl->rev_types |= (uint8_t)(1u << (t0 - 20));
                }
                fl->rev_payload_after_hello += (uint32_t)rpay;
            }
        }
    }
    /* Признак «время не записано» — отдельный флаг, а не нулевое время. Ноль
       это законная отметка часов, и опираться на неё значит терять первый же
       поток, начавшийся в начале отсчёта. */
    if (syn && !ack) {
        if (!fl->saw_syn) {
            fl->syn_ns = now_ns;
        }
        fl->saw_syn = 1;
    }
    if (syn && ack) {
        /* RTT берём с самого потока: от SYN до SYN-ACK. Ориентир из измерения,
           а не из константы — на медленной линии константа объявила бы
           молчанием обычную задержку. */
        if (fl->saw_syn && !fl->saw_synack && now_ns >= fl->syn_ns) {
            fl->rtt_ns = now_ns - fl->syn_ns;
        }
        fl->saw_synack = 1;
    }

    /* Сообщаем дважды: когда обмен вообще пошёл и когда в нём появились
       ПРИКЛАДНЫЕ данные. Это разные уровни доказательства (§4.2), и второй
       наступает позже первого — сообщить только о первом значит навсегда
       оставить контроллер на уровне 2. */
    const uint8_t appdata_bit = (uint8_t)(1u << (23 - 20));
    if (fl->saw_hello && fl->rev_payload_after_hello > 0 &&
        (!fl->exchange_told ||
         (!fl->appdata_told && (fl->rev_types & appdata_bit)))) {
        if (fl->rev_types & appdata_bit) {
            fl->appdata_told = 1;
        }
        fl->exchange_told = 1;
        s->exchanges++;
        d2k_jrn_detail det;
        memset(&det, 0, sizeof det);
        det.tos = fl->rev_types;   /* набор увиденных типов записей */
        d2k_journal_add(s->jrn, now_ns, &key, D2K_JRN_EXCHANGE,
                        fl->rev_first_type, fl->rev_payload_after_hello,
                        &det, NULL, 0, NULL);
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
            d2k_jrn_detail det;
            det.ttl = pkt[8];
            det.ref_ttl = fl->rev_ttl;
            det.tos = pkt[1];
            det.ipid = rd16(pkt + 4);
            suspect(s, now_ns, &key, fl, D2K_SUSPECT_RST_CUT, &det);
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
            d2k_jrn_detail det;
            det.ttl = pkt[8];
            det.ref_ttl = fl->rev_profiled ? fl->rev_ttl : 0;
            det.tos = pkt[1];
            det.ipid = rd16(pkt + 4);
            suspect(s, now_ns, &key, fl, D2K_SUSPECT_RST, &det);
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
            suspect(s, now_ns, &key, fl, D2K_SUSPECT_REPEAT, NULL);
        }
    }

    /* Почему разбор не состоялся — считается ОТДЕЛЬНО по каждой причине.
     *
     * Раньше все эти случаи сваливались в «плана для этой цели нет», и по
     * сводке нельзя было отличить ответный пакет от прямого, не оказавшегося
     * приветствием. Ровно на этом застряла диагностика 2026-09-05: ноль
     * узнанных приветствий при 59 пакетах с нагрузкой, и ни одной подсказки,
     * куда смотреть. Прибор, который не различает причины, не прибор. */
    if (!fwd) {
        s->pay_reverse++;
    } else if (fl->saw_hello) {
        s->pay_after_hello++;
    } else if (fl->fwd_pkts > D2K_HELLO_WINDOW) {
        s->pay_late++;
    }

    if (!fl->saw_hello && fwd && fl->fwd_pkts <= D2K_HELLO_WINDOW) {
        d2k_tls_parse(pkt + payload_off, payload_len, &tls);
        if (!tls.is_client_hello) {
            s->pay_not_hello++;
            /* Первый байт нагрузки — самая дешёвая улика о том, ЧТО это
               было: 0x16 значит рукопожатие и разбор споткнулся внутри,
               0x47 — обычный HTTP, прочее — не TLS вовсе. */
            s->last_nonhello_first = pkt[payload_off];
        }
        if (tls.is_client_hello) {
            /* Последнее приветствие копится всегда: подозрение возникнет на
               этом же соединении, и просить форму будет уже поздно. Один
               буфер, объявленный предел. */
            if (payload_len <= sizeof s->last_hello) {
                memcpy(s->last_hello, pkt + payload_off, payload_len);
                s->last_hello_len = payload_len;
                s->last_name_len = 0;
                if (tls.have_sni && tls.sni_len <= sizeof s->last_name) {
                    memcpy(s->last_name, pkt + payload_off + tls.sni_off, tls.sni_len);
                    s->last_name_len = tls.sni_len;
                }
            }
            /* Взведённая ловушка — на случай, когда в момент запроса
               подходящего приветствия ещё не было. */
            if (s->shape_armed && payload_len <= sizeof s->shape &&
                (s->shape_name_len == 0 ||
                 (tls.have_sni &&
                  name_same(pkt + payload_off + tls.sni_off, tls.sni_len,
                            s->shape_name, s->shape_name_len)))) {
                memcpy(s->shape, pkt + payload_off, payload_len);
                s->shape_len = payload_len;
                s->shape_armed = 0;
                d2k_journal_add(s->jrn, now_ns, &key, D2K_JRN_SHAPE, 0,
                                (uint32_t)payload_len, NULL, NULL, 0, NULL);
            }
            fl->hello_ns = now_ns;
            fl->saw_hello = 1;
            fl->had_sni = tls.have_sni ? 1 : 0;
            if (!tls.have_sni && !tls.have_record_end) {
                /* Приветствие узнали, а имени нет, и запись оборвана: имя
                   уехало во второй сегмент. Это ЦЕНА размена «читаем первый
                   сегмент вместо пересборки», и её надо измерять, а не
                   принимать на веру: донор оценил её как приемлемую на своей
                   линии, но своя линия у каждого. */
                s->sni_in_next_seg++;
            }
            fl->hello_seq = in_seq;
            s->hellos++;
            if (tls.have_sni) {
                s->with_sni++;
                d2k_journal_add(s->jrn, now_ns, &key, D2K_JRN_HELLO_SNI, 0, 0,
                                NULL, pkt + payload_off + tls.sni_off,
                                tls.sni_len, NULL);
            } else {
                /* Имени нет — и это нормальное состояние модели (§5.3), а не
                   ошибка разбора. */
                d2k_journal_add(s->jrn, now_ns, &key, D2K_JRN_HELLO_NONAME, 0, 0,
                                NULL, NULL, 0, NULL);
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
    d2k_journal_add(s->jrn, now_ns, &key, D2K_JRN_PLAN_APPLIED, 0, 0, NULL, NULL, 0, NULL);

    d2k_actions_free(&acts);
    return 0;
}

int d2k_session_want_shape(d2k_session *s, const uint8_t *name, size_t len) {
    if (!s) {
        return 0;
    }
    if (len > sizeof s->shape_name) {
        len = sizeof s->shape_name;
    }
    /* Сохранённое подходит — отдаём немедленно. Ждать следующего приветствия
       значило бы ждать повтора клиента, а подозрение возникло на том же
       соединении, чьё приветствие только что прошло. */
    if (s->last_hello_len > 0 &&
        (len == 0 || name_same(s->last_name, s->last_name_len, name, len))) {
        memcpy(s->shape, s->last_hello, s->last_hello_len);
        s->shape_len = s->last_hello_len;
        s->shape_armed = 0;
        return 1;
    }
    s->shape_armed = 1;
    s->shape_len = 0;
    s->shape_name_len = len;
    if (len) {
        memcpy(s->shape_name, name, len);
    }
    return 0;
}

const uint8_t *d2k_session_shape(const d2k_session *s, size_t *len) {
    if (!s || s->shape_len == 0) {
        return NULL;
    }
    if (len) {
        *len = s->shape_len;
    }
    return s->shape;
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

/* Срок, после которого молчание перестаёт быть задержкой.
 *
 * Здоровый ответ на приветствие приходит за один RTT. Первая повторная посылка
 * TCP уходит примерно через секунду; значит к исходу секунды не пришло ни
 * ответа, ни толку от повтора. Отсюда пол в одну секунду — он про терпение
 * человека перед пустой страницей, а не про сеть.
 *
 * Множитель на измеренный RTT нужен линиям, где секунда — это меньше двух
 * оборотов: там пол сработал бы на здоровом соединении. Потолок в пять секунд
 * — снова про человека: дольше он уже не ждёт, и поиск, начатый позже, ему
 * не нужен.
 *
 * RTT не измерен (поток подхватили посреди обмена) — берём две секунды: одна
 * на здоровый ответ, одна на неизвестность. */
static uint64_t silence_deadline(const d2k_flow *f) {
    const uint64_t floor_ns = NS_PER_S;
    const uint64_t ceil_ns  = 5 * NS_PER_S;
    if (!f->rtt_ns) {
        return 2 * NS_PER_S;
    }
    uint64_t d = f->rtt_ns * 8;
    if (d < floor_ns) { d = floor_ns; }
    if (d > ceil_ns)  { d = ceil_ns; }
    return d;
}

struct sweep_ctx {
    d2k_session *s;
    uint64_t     now_ns;
    size_t       told;
};

/* Молчание — это ОТСУТСТВИЕ нагрузки в ответ, а не отсутствие пакетов.
 * Сервер, подтвердивший приветствие пустым ACK и замолчавший, и есть картина
 * блокировки: TCP жив, ответа нет. */
static void sweep_one(void *ctx, d2k_flow *f) {
    struct sweep_ctx *c = ctx;
    if (!f->saw_hello || f->silence_told || f->suspected) {
        return;
    }
    if (f->rev_payload_after_hello > 0 || f->saw_rev_rst) {
        return;
    }
    /* Обратная сторона должна быть ВИДНА. Правило на обратное направление
       ставится не всегда, и без него в очередь не приходит ни один пакет
       сервера: каждый поток выглядел бы молчащим. Это была бы подмена «не
       смотрели» на «нет ответа» — ровно то, что §2.4 запрещает. Признаком
       видимости служит любой пакет оттуда, обычно SYN-ACK. */
    if (f->rev_pkts == 0) {
        return;
    }
    if (c->now_ns < f->hello_ns) {
        return;
    }
    if (c->now_ns - f->hello_ns < silence_deadline(f)) {
        return;
    }
    f->silence_told = 1;
    c->told++;
    suspect(c->s, c->now_ns, &f->key, f, D2K_SUSPECT_SILENT, NULL);
}

size_t d2k_session_sweep(d2k_session *s, uint64_t now_ns) {
    if (!s) {
        return 0;
    }
    struct sweep_ctx c = { s, now_ns, 0 };
    d2k_track_walk(s->flows, sweep_one, &c);
    return c.told;
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

uint64_t d2k_session_exchanges(const d2k_session *s) {
    return s ? s->exchanges : 0;
}

void d2k_session_payload_stats(const d2k_session *s, d2k_payload_stats *out) {
    if (!out) {
        return;
    }
    memset(out, 0, sizeof *out);
    if (!s) {
        return;
    }
    out->reverse = s->pay_reverse;
    out->after_hello = s->pay_after_hello;
    out->late = s->pay_late;
    out->not_hello = s->pay_not_hello;
    out->last_first_byte = s->last_nonhello_first;
    out->sni_next_seg = s->sni_in_next_seg;
}

const d2k_journal *d2k_session_journal(const d2k_session *s) {
    return s ? s->jrn : NULL;
}
