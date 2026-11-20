/* plan_apply.c — превращение плана в список посылок для одного пакета.
 *
 * Договорённость о выводе, из которой следует всё остальное: список содержит
 * ТОЛЬКО то, что порождаем мы. Судьба оригинала — отдельное поле, а не ещё
 * одна строка в списке. Иначе «пропустить оригинал» и «выпустить его копию»
 * стали бы неразличимы, и пакет ушёл бы дважды.
 *
 * Отсюда правило: если план выпускает нагрузку сам (есть разрезы или
 * перекрытие), оригинал снимается. Если план только добавляет фальшивку —
 * оригинал пропускается, а наши посылки идут перед ним.
 *
 * Плавающей арифметики здесь нет: MIPS-коробки без сопроцессора, и каждая
 * операция с double там становится вызовом libgcc.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "d2k_plan.h"
#include "d2k_arm.h"
#include "plan_internal.h"
#include "d2k_quic.h" /* d2k_quic_initial_split_crypto — задача 40 */

/* Разрешение якоря. Невычислимый якорь — ОТКАЗ, а не нулевое смещение:
 * молчаливый ноль исполнил бы не тот план, который измеряли. */
static int anchor_offset(const d2k_pkt *in, uint16_t anchor, size_t *out,
                         const char **why) {
    switch (anchor) {
    case ANCHOR_PAYLOAD_START:
        *out = 0;
        return 0;
    case ANCHOR_SNI_START:
        if (!in->have_sni) {
            *why = "якорь «начало имени»: имени в этом пакете нет";
            return -1;
        }
        *out = in->sni_off;
        return 0;
    case ANCHOR_SNI_END:
        if (!in->have_sni) {
            *why = "якорь «конец имени»: имени в этом пакете нет";
            return -1;
        }
        *out = in->sni_off + in->sni_len;
        return 0;
    case ANCHOR_HELLO_MIDDLE:
        *out = in->payload_len / 2;
        return 0;
    case ANCHOR_SNI_MIDDLE:
        /* Середина ИМЕНИ хоста, а не середина пакета. Коробка ищет имя
           целиком; ANCHOR_HELLO_MIDDLE чаще оставляет имя нетронутым в одном
           куске (осмысленное начало записи), и коробка спокойно ждёт
           остаток — разрез не срабатывает. Донор наступил на эту же ошибку
           и исправил её тем же замером: боевое плечо режет на midsld,
           середине домена второго уровня, а не на n/2
           (z2k-detect/internal/classify/raw_linux.go:667-690). */
        if (!in->have_sni) {
            *why = "якорь «середина имени»: имени в этом пакете нет";
            return -1;
        }
        /* Зажимы дословно донорские: без них короткое имя даёт вырожденный
           (меньше 2) или пустой/переполненный (>= длины нагрузки) кусок. */
        *out = in->sni_off + in->sni_len / 2;
        if (*out < 2) {
            *out = 2;
        }
        if (*out >= in->payload_len) {
            *out = in->payload_len - 1;
        }
        return 0;
    case ANCHOR_SLD_MIDDLE: {
        if (!in->have_sni || in->sni_off > in->payload_len ||
            in->sni_len > in->payload_len-in->sni_off) {
            *why = "якорь «середина домена»: полного имени нет";
            return -1;
        }
        const uint8_t *name=in->payload+in->sni_off;
        size_t last=in->sni_len, first=0;
        while(last && name[last-1]!='.')last--;
        if(!last || last==1 || last==in->sni_len) {
            *why = "якорь «середина домена»: второго уровня нет";
            return -1;
        }
        size_t end=last-1;
        for(size_t i=end;i>0;i--)if(name[i-1]=='.'){first=i;break;}
        if(first>=end) {
            *why = "якорь «середина домена»: пустая метка";
            return -1;
        }
        *out=in->sni_off+first+(end-first)/2;
        return 0;
    }
    case ANCHOR_RECORD_END:
        /* Границу записи TLS обязан передать протокольный модуль. Пока он не
           написан, честный ответ — отказ, а не догадка о длине. */
        *why = "якорь «конец записи TLS» не поддержан исполнителем";
        return -1;
    default:
        *why = "якорь плана не известен исполнителю";
        return -1;
    }
}

static int cmp_size(const void *a, const void *b) {
    size_t x = *(const size_t *)a, y = *(const size_t *)b;
    return x < y ? -1 : (x > y ? 1 : 0);
}

/* Позиции разрезов: якорь плюс смещение, отсортированы по возрастанию и
 * очищены от повторов и краёв. Порядок именно возрастающий, а не порядок
 * записей: иначе перестановка записей в плане меняла бы куски. */
static int split_points(const d2k_plan *p, const d2k_pkt *in,
                        size_t *pts, size_t *n_out, const char **why) {
    size_t n = 0;
    for (size_t i = 0; i < p->n_splits; i++) {
        size_t base;
        if (anchor_offset(in, p->splits[i].anchor, &base, why) != 0) {
            return -1;
        }
        long v = (long)base + p->splits[i].offset;
        if (v <= 0 || (size_t)v >= in->payload_len) {
            /* Разрез вне нагрузки не режет ничего. Это не отказ: якорь
               вычислился, просто пакет короче. */
            continue;
        }
        pts[n++] = (size_t)v;
    }
    if (n > 1) {
        qsort(pts, n, sizeof *pts, cmp_size);
        size_t w = 1;
        for (size_t i = 1; i < n; i++) {
            if (pts[i] != pts[w - 1]) {
                pts[w++] = pts[i];
            }
        }
        n = w;
    }
    *n_out = n;
    return 0;
}

static int tls_ch_layout(const uint8_t *b, size_t n, int allow_prefix, size_t *rnd_off,
                         size_t *sid_off, size_t *sid_len, const char **why) {
    if (!b || n < 44 || b[0] != 0x16 || b[1] != 3 || b[5] != 1) {
        *why = "правка приветствия: это не ClientHello или он короче 44 байт";
        return -1;
    }
    size_t rec_len = ((size_t)b[3] << 8) | b[4];
    size_t hs_len = ((size_t)b[6] << 16) | ((size_t)b[7] << 8) | b[8];
    /* Три РАЗНЫХ отказа, и различать их обязательно: первые два — негодная
       разметка, третий — «пришёл только НАЧАЛО приветствия», обычное дело при
       приветствии длиннее сегмента (1541 байт при MSS 1452 — поле
       13.10.2026). Один общий текст на все три не давал понять, почему план
       не применился. */
    if (rec_len + 5 != hs_len + 9) {
        *why = "правка приветствия: объявленные длины записи и рукопожатия не сходятся";
        return -1;
    }
    if (n > rec_len + 5) {
        *why = "правка приветствия: пришло больше, чем объявлено записью";
        return -1;
    }
    if (!allow_prefix && (hs_len > n - 9 || rec_len > n - 5)) {
        *why = "правка приветствия просит приветствие ЦЕЛИКОМ, а пришло только "
               "его начало (приветствие длиннее сегмента)";
        return -1;
    }
    size_t len_off = 43;
    size_t sl = b[len_off];
    if (sl > 32 || sl > n - (len_off + 1)) {
        *why = "правка приветствия: длина session id выходит за пришедшие байты";
        return -1;
    }
    *rnd_off = 11; *sid_off = len_off + 1; *sid_len = sl;
    return 0;
}

static int random_bytes(uint8_t *out, size_t n) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) { return -1; }
    size_t got = fread(out, 1, n, f);
    int bad = ferror(f);
    fclose(f);
    return got == n && !bad ? 0 : -1;
}

static void wr16(uint8_t *b, size_t off, size_t v) {
    b[off] = (uint8_t)(v >> 8); b[off + 1] = (uint8_t)v;
}
static void wr24(uint8_t *b, size_t off, size_t v) {
    b[off] = (uint8_t)(v >> 16); b[off + 1] = (uint8_t)(v >> 8);
    b[off + 2] = (uint8_t)v;
}

static int fake_tls_bytes(const d2k_plan *p, const struct d2k_fake *f,
                          const struct d2k_payload *pl, const d2k_pkt *in,
                          uint8_t **owned, const char **why) {
    size_t fake_rnd, fake_sid, fake_sid_len;
    size_t real_rnd, real_sid, real_sid_len;
    *owned = NULL;
    /* A saved tcp-template plan also needs to be tried on TLS 1.2. Random
       and session-ID fields have the same layout; unequal SID lengths are
       handled below without resizing the template. Keep the older native
       modifier profile's input contract unchanged. */
    if (!in->is_tls13 && p->wire_profile != D2K_WIRE_TCP_TEMPLATE) {
        *why = "правка приветствия просит TLS 1.3, а у этого пакета форма другая";
        return -1;
    }
    if (tls_ch_layout(in->payload, in->payload_len,
            p->wire_profile == D2K_WIRE_TCP_TEMPLATE,
            &real_rnd, &real_sid, &real_sid_len, why) != 0 ||
        tls_ch_layout(pl->bytes, pl->len, 0, &fake_rnd, &fake_sid,
                      &fake_sid_len, why) != 0) { return -1; }
    if (p->wire_profile == D2K_WIRE_TCP_TEMPLATE) {
        /* Original TLSMod: randomize fake random/SID, then duplicate SID only
         * when lengths match. It does not resize fake_default_tls. */
        uint8_t *b = malloc(pl->len);
        if (!b) { *why = "нет памяти на правку приветствия"; return -1; }
        memcpy(b, pl->bytes, pl->len);
        if ((f->tls_mod & D2K_TLS_MOD_RND) &&
            (random_bytes(b + fake_rnd, 32) != 0 ||
             random_bytes(b + fake_sid, fake_sid_len) != 0)) {
            *why = "случайные байты не прочитаны (/dev/urandom)";
            free(b); return -1;
        }
        if ((f->tls_mod & D2K_TLS_MOD_DUPSID) && fake_sid_len == real_sid_len)
            memcpy(b + fake_sid, in->payload + real_sid, real_sid_len);
        *owned = b;
        return 0;
    }
    size_t out_len = pl->len;
    if (f->tls_mod & D2K_TLS_MOD_DUPSID) {
        out_len = pl->len - fake_sid_len + real_sid_len;
        if (out_len > 65540 || out_len < 9 || out_len - 5 > 65535 || out_len - 9 > 0xffffff) {
            *why = "правка приветствия: копия session id не влезает в запись TLS";
            return -1;
        }
    }
    uint8_t *b = malloc(out_len);
    if (!b) { *why = "нет памяти на правку приветствия"; return -1; }
    if (f->tls_mod & D2K_TLS_MOD_DUPSID) {
        memcpy(b, pl->bytes, fake_sid);
        memcpy(b + fake_sid, in->payload + real_sid, real_sid_len);
        memcpy(b + fake_sid + real_sid_len, pl->bytes + fake_sid + fake_sid_len,
               pl->len - fake_sid - fake_sid_len);
        b[fake_sid - 1] = (uint8_t)real_sid_len;
        wr16(b, 3, out_len - 5);
        wr24(b, 6, out_len - 9);
    } else {
        memcpy(b, pl->bytes, pl->len);
    }
    if ((f->tls_mod & D2K_TLS_MOD_RND) && random_bytes(b + fake_rnd, 32) != 0) {
        *why = "случайные байты не прочитаны (/dev/urandom)";
        free(b); return -1;
    }
    (void)p;
    *owned = b;
    return 0;
}

static int emit_fake(d2k_emit *e, const d2k_plan *p, const struct d2k_fake *f,
                     const d2k_pkt *in, uint32_t seq, uint32_t delay,
                     const char **why) {
    const struct d2k_payload *pl = d2k_find_payload(p, f->payload_id);
    const struct d2k_poison *po = f->poison_id ? d2k_find_poison(p, f->poison_id) : NULL;
    if (!pl) { *why = "фальшивка плана ссылается на нагрузку, которой нет"; return -1; }
    memset(e, 0, sizeof *e);
    e->kind = D2K_EMIT_FAKE;
    e->delay_us = delay;
    e->seq = seq;
    e->bytes = pl->bytes;
    e->len = pl->len;
    if (f->tls_mod) {
        if (fake_tls_bytes(p, f, pl, in, &e->owned_bytes, why) != 0) { return -1; }
        e->bytes = e->owned_bytes;
    }
    if (po) {
        e->ttl = po->ttl;
        e->poison = po->flags;
        e->seq_shift = po->seq_shift;
        e->ack_shift = po->ack_shift;
        e->ts_up = po->ts_up;
        e->autottl = po->autottl;
        e->autottl_delta = po->autottl_delta;
        e->autottl_min = po->autottl_min;
        e->autottl_max = po->autottl_max;
    }
    return 0;
}

static void emit_vec_free(d2k_emit *v, size_t n) {
    if (!v) { return; }
    for (size_t i = 0; i < n; i++) { free(v[i].owned_bytes); }
    free(v);
}

/* Заголовки на проводе — те же числа, что у сборщиков (wire.c, wire_udp.c).
   Повторены здесь, а не вынесены в общий заголовок, по тому же правилу, по
   которому wire_udp.c держит собственные копии wr16/sum16: модули пакетного
   пути самодостаточны. Расхождение поймает test_ctl: он сверяет 20+20+длина
   приманки с тем, что реально собирает wire.c. */
#define EMIT_IP_HDR   20
#define EMIT_TCP_HDR  20
#define EMIT_UDP_HDR   8
/* Метка времени TCP: NOP, NOP, тип 8, длина 10 — см. TS_OPT_LEN в wire.c. */
#define EMIT_TS_OPT   12

static size_t emit_overhead(const d2k_plan *p, const struct d2k_poison *po) {
    /* Транспорт не объявлен — считаем по TCP: его заголовок шире, и ошибка в
       эту сторону отвергает лишнее, а не пропускает непроходимое. */
    size_t hdr = EMIT_IP_HDR + ((p->transport == 17) ? EMIT_UDP_HDR : EMIT_TCP_HDR);
    if (po && p->transport != 17) {
        /* MD5 replaces the timestamp option in detect/raw.c and wire.c.
           MD5+метка (D2K_POISON_MD5_TS) — MD5 первой плюс метка = 28 байт. */
        if (po->flags & D2K_POISON_MD5_TS) { hdr += 28; }
        else if (po->flags & D2K_POISON_MD5) { hdr += 20; }
        else if (po->flags & D2K_POISON_TCPTS_BACK) { hdr += EMIT_TS_OPT; }
    }
    return hdr;
}

size_t d2k_plan_max_emit(const d2k_plan *p) {
    if (!p) {
        return 0;
    }
    size_t max = 0;
    for (size_t i = 0; i < p->n_fakes; i++) {
        const struct d2k_payload *pl = d2k_find_payload(p, p->fakes[i].payload_id);
        if (!pl) {
            continue;   /* висячая ссылка отвергается разбором, сюда не доходит */
        }
        const struct d2k_poison *po = p->fakes[i].poison_id
            ? d2k_find_poison(p, p->fakes[i].poison_id) : NULL;
        size_t body = pl->len + ((p->fakes[i].tls_mod & D2K_TLS_MOD_DUPSID) ? 32u : 0u);
        if (p->segment_size && body > p->segment_size) { body = p->segment_size; }
        size_t n = emit_overhead(p, po) + body;
        if (n > max) { max = n; }
    }
    for (size_t i = 0; i < p->n_seqovls; i++) {
        const struct d2k_payload *pl = d2k_find_payload(p, p->seqovls[i].payload_id);
        if (!pl) {
            continue;
        }
        const struct d2k_poison *po = p->seqovls[i].poison_id
            ? d2k_find_poison(p, p->seqovls[i].poison_id) : NULL;
        /* Только приставка: кусок нагрузки, к которому она приклеивается,
           приходит из пакета — см. d2k_plan_max_emit в d2k_plan.h про то,
           почему он здесь не считается. */
        size_t body = pl->len;
        if (p->segment_size && body > p->segment_size) { body = p->segment_size; }
        size_t n = emit_overhead(p, po) + body;
        if (n > max) { max = n; }
    }
    if (p->udplen) {
        /* Удлинённая датаграмма — посылка, которую план объявляет сам: к
           любой пришедшей нагрузке он добавит udplen байт. Сама нагрузка
           зависит от пакета, но у QUIC её нижняя граница задана стандартом:
           клиентский Initial не короче 1200 байт (RFC 9000 §14.1). Без этого
           способ отправки, не уносящий 1328 байт, узнал бы о том только
           отказом ядра уже после APPLIED. */
        size_t body = (p->proto == 2 ? 1200u : 1u) + p->udplen;
        size_t n = emit_overhead(p, NULL) + body;
        if (n > max) { max = n; }
    }
    return max;
}

int d2k_plan_apply(const d2k_plan *p, const d2k_flow *f,
                   const d2k_pkt *in, d2k_actions *out) {
    (void)f;
    if (!p || !in || !out) {
        return -1;
    }
    memset(out, 0, sizeof *out);
    if (p->preflight && !p->pf_handover_apply) {
        out->refuse_why = "preflight requires the SYN FSM";
        return -1;
    }
    if(p->after_length) {
        uint32_t relative=in->stream_offset-p->after_offset;
        int replay=in->after_split_retry && relative<p->after_length &&
            in->payload_len && in->payload_len<=p->after_length-relative;
        if(!in->have_stream_offset ||
           (in->after_split_retry && !replay) ||
           (in->stream_offset!=0 && in->stream_offset!=p->after_offset && !replay)) {
            out->refuse_why="composed plan requires exact first or follow-up TCP input";return -1;
        }
        if(in->stream_offset==p->after_offset || replay) {
            uint32_t delta=replay?relative:0;
            size_t length=replay?in->payload_len:p->after_length;
            int interior=p->after_cut>delta && p->after_cut-delta<length;
            struct d2k_split cut={ANCHOR_PAYLOAD_START,interior?(int16_t)(p->after_cut-delta):0};
            d2k_plan late={0};
            late.schema=p->schema;late.minexec=p->minexec;memcpy(late.id,p->id,sizeof late.id);
            late.transport=p->transport;late.proto=p->proto;late.wire_profile=p->wire_profile;
            late.has_stream_offset=1;late.stream_offset=in->stream_offset;
            late.input_len=(uint32_t)length;late.splits=&cut;late.n_splits=interior?1:0;
            return d2k_plan_apply(&late,f,in,out);
        }
    }
    /* ПРИЧИНА ОТКАЗА НАЗЫВАЕТСЯ ВСЕГДА. Отказ исполнителя и вердикт коробки
       на проводе выглядят одинаково: зонд уходит голым и его срезают. Пока 36
       из 37 путей отказа молчали, обобщённое «план неприменим к этому пакету»
       в журнале датапата (10 раз за 15 минут, поле 13.10.2026,
       forum.ru-board.com) не давало отличить одно от другого, и контроллер
       записывал НАШ отказ в вину кандидату. */
    if (!in->payload || in->payload_len == 0) {
        out->refuse_why = "в пакете нет полезной нагрузки";
        return -1;
    }
    /* HTTP-план — только запросу HTTP, прочий план — только не ему (шаг 4
       задачи 51): якоря «sni_*» у них считаются от разного. */
    if ((p->proto == D2K_PLAN_PROTO_HTTP) != (in->is_http != 0)) {
        out->refuse_why = p->proto == D2K_PLAN_PROTO_HTTP
            ? "план открытого HTTP, а пакет — не запрос HTTP"
            : "пакет — запрос HTTP, а план объявлен не для него";
        return -1;
    }
    if(p->has_stream_offset && (!in->have_stream_offset || in->stream_offset!=p->stream_offset)) {
        out->refuse_why="TCP stream offset missing or different from measured input";
        return -1;
    }
    if (p->qdeny) {
        /* Не воздействие: оригинал снимается, посылок нет (сессия решает
           это раньше; здесь — чтобы исполнитель не выдумал иного). */
        out->fate = D2K_ORIG_DROP;
        return 0;
    }
    if (in->is_http && (p->input_tls || p->input_len || p->oob_enabled || p->ipfrag ||
                        p->udplen || p->qsplit)) {
        out->refuse_why = "приёмы этого плана к запросу HTTP не применяются";
        return -1;
    }
    if (p->input_tls) {
        /* SNI-relative actions are reusable, but a first TCP fragment is
         * not the full input on which raw.c performs its three-part send.
         * SNI metadata is provided by the normal session TLS parser. */
        const uint8_t *b = in->payload;
        size_t n = in->payload_len;
        if (n < 9 || n > D2K_ARM_TRIGGER_MAX || b[0] != 0x16 || b[1] != 3 || b[5] != 1 ||
            !in->have_sni || in->sni_len <= 1 || !in->sni_off ||
            in->sni_off > n || in->sni_len > n - in->sni_off) {
            out->refuse_why = !in->have_sni
                ? "план считает от имени, а имени в этом пакете нет"
                : "план считает от имени, а разметка имени негодна";
            return -1;
        }
        /* ЗАПИСЬ ЦЕЛИКОМ ИЛИ ЕЁ НАЧАЛО — ВХОД В ОБОИХ СЛУЧАЯХ.
         *
         * Приветствие длиннее сегмента — обычное дело: 1534 байта при MSS
         * 1388 (поле 18.09.2026, приветствие Discord). Прежде требовалось
         * совпадение объявленной длины с пришедшей, и такому потоку план не
         * применялся вовсе — «план неприменим к этому пакету». Дождаться
         * остатка и собрать целое нельзя: пока первый сегмент лежит в
         * очереди без вердикта, ядро остаток НЕ ВЫПУСКАЕТ (тот же замер, три
         * прогона: «начато=2, таймаутов=2, добавлено к голове=0» — второй
         * сегмент до сборщика не доходил ни разу, его не отвергали).
         *
         * Для действий плана целой записи и не нужно: имя в сегменте есть,
         * разрезы считаются от него, а остаток уйдёт на провод сам, следом за
         * нашими кусками — ровно как у донора с выключенной пересборкой.
         * Требование остаётся одно: объявленные длины сходятся между собой, и
         * пришло не больше объявленного. Байты, собранные под конкретный вход
         * (input_len ниже), по-прежнему требуют своего входа до байта. */
        size_t rec_total = 5u + ((size_t)b[3] << 8) + b[4];
        size_t hs_total = 9u + ((size_t)b[6] << 16) + ((size_t)b[7] << 8) + b[8];
        if (rec_total != hs_total || n > rec_total) {
            out->refuse_why = "приветствие негодно: длины записи и рукопожатия "
                              "не сходятся или пришло больше объявленного";
            return -1;
        }
    }
    if (p->input_len) {
        /* ИЗМЕРЕННЫЙ ВХОД: ПРИСТАВКА ТОГО ЖЕ ПРИВЕТСТВИЯ ГОДИТСЯ.
         *
         * Прежде требовалось равенство длин до байта, и для приветствия
         * длиннее сегмента это условие не выполнялось НИКОГДА: датапат видит
         * только первый сегмент, а пришпилена длина целого. Поле 13.10.2026,
         * forum.ru-board.com: приём найден замером (плотная серия с битой
         * суммой — три ServerHello на проводе), план из него пришпилен к 1541
         * байту, сегмент 1452, и журнал датапата назвал отказ дословно —
         * «байты плана собраны под другой вход». Зонд уходил голым, коробка
         * срезала его, а контроллер записывал это в вину кандидату. Тот же
         * класс был измерен 18.09.2026 на Discord (1534 байта при MSS 1388) и
         * тогда закрыт лишь для части плеч (см. «ВХОД ПРИШПИЛИВАЕТСЯ...» в
         * core/measured.c): плечи с приманкой и перестановкой остались
         * непроходимыми.
         *
         * ТО ЖЕ ПРИВЕТСТВИЕ ДОКАЗЫВАЕТСЯ ИЗ ПРИСТАВКИ, а не предполагается:
         * запись TLS объявляет свою полную длину в первых девяти байтах, и
         * она обязана совпасть с измеренной. Плюс имя на том же месте и той
         * же длины. Этого довольно: байты, которые план несёт сам (приманка,
         * приставка перекрытия), от хвоста не зависят, а хвост уйдёт на
         * провод сам, следом за нашими куска­ми — ровно как у input tls-sni.
         *
         * ПРОГРАММА ОБЯЗАНА БЫТЬ ТОЙ ЖЕ. Числовой разрез за пришедшими
         * байтами split_points молча пропускает («разрез вне нагрузки не
         * режет ничего»), и исполнилась бы ДРУГАЯ программа, чем мерили.
         * Такой вход — отказ, и он назван. */
        size_t declared = 0;
        const uint8_t *b = in->payload;
        if (in->payload_len >= 9 && b[0] == 0x16 && b[1] == 3 && b[5] == 1) {
            size_t rec_total = 5u + ((size_t)b[3] << 8) + b[4];
            size_t hs_total = 9u + ((size_t)b[6] << 16) + ((size_t)b[7] << 8) + b[8];
            if (rec_total == hs_total) { declared = rec_total; }
        }
        size_t have = in->payload_len == p->input_len ? p->input_len : declared;
        if (have != p->input_len || in->payload_len > p->input_len ||
            (in->have_sni ? in->sni_len : 0) != p->input_sni_len ||
            (p->input_sni_len && in->sni_off != p->input_sni_off)) {
            out->refuse_why = "байты плана собраны под другой вход: объявленная "
                              "длина приветствия, длина или место имени не те, "
                              "что мерили";
            return -1;
        }
        for (size_t i = 0; i < p->n_splits; i++) {
            if (p->splits[i].anchor != ANCHOR_PAYLOAD_START) { continue; }
            long v = p->splits[i].offset;
            if (v > 0 && (size_t)v >= in->payload_len) {
                out->refuse_why = "измеренный разрез лежит за пришедшими байтами: "
                                  "исполнилась бы другая программа, чем мерили";
                return -1;
            }
        }
    }

    d2k_emit *v = NULL;
    size_t n = 0;
    int owns_payload = 1;
    if (p->oob_enabled) {
        size_t mid = 0;
        if (anchor_offset(in, p->oob_anchor, &mid, &out->refuse_why) != 0) {
            return -1;
        }
        if (mid == 0 || mid >= in->payload_len) {
            out->refuse_why = "место срочного байта вне нагрузки этого пакета";
            return -1;
        }
        v = calloc(3, sizeof *v);
        if (!v) { out->refuse_why = "нет памяти на посылки плана"; return -1; }
        v[0].kind = D2K_EMIT_PAYLOAD;
        v[0].seq = in->seq;
        v[0].bytes = in->payload;
        v[0].len = mid;

        v[1].kind = D2K_EMIT_PAYLOAD;
        v[1].seq = in->seq + (uint32_t)mid;
        v[1].bytes = &p->oob_byte;
        v[1].len = 1;
        v[1].urgent = 1;
        v[1].urgent_ptr = 1;

        /* TCP sequence space includes urgent data even though the receiving
           application normally removes that byte from its in-band stream.
           Therefore replay the original suffix unchanged at seq+mid+1. */
        v[2].kind = D2K_EMIT_PAYLOAD;
        v[2].seq = in->seq + (uint32_t)mid + 1u;
        v[2].bytes = in->payload + mid;
        v[2].len = in->payload_len - mid;

        n = 3;
        goto finalize; /* same wire profile and segmentation as every Plan */
    }

    size_t *pts = NULL;
    size_t n_pts = 0;
    if (p->n_splits) {
        pts = calloc(p->n_splits, sizeof *pts);
        if (!pts) {
            out->refuse_why = "нет памяти на разрезы плана";
            return -1;
        }
        if (split_points(p, in, pts, &n_pts, &out->refuse_why) != 0) {
            free(pts);
            return -1; /* невычислимый якорь — причина уже названа */
        }
        /* НИ ОДИН РАЗРЕЗ НЕ ПОПАЛ В ПРИШЕДШИЕ БАЙТЫ — ЭТО ДРУГАЯ ПРОГРАММА.
         *
         * split_points пропускает разрез за нагрузкой молча («разрез вне
         * нагрузки не режет ничего»), и до 24.10.2026 план при этом
         * исполнялся без своего разреза и возвращался как ПРИМЕНЁННЫЙ. Для
         * плана с объявленным входом это уже было отказом (см. «ПРОГРАММА
         * ОБЯЗАНА БЫТЬ ТОЙ ЖЕ» выше); у плана без объявленного входа та же
         * подмена оставалась незамеченной.
         *
         * Так выглядит поток браузера: приветствие Chrome 1919–2015 байт при
         * MSS 1388 уезжает в два сегмента (issue 28), и числовой разрез,
         * измеренный на одном сегменте собственного зонда (1534 байта),
         * в голову клиента не попадает. Коробка режет по-прежнему, а
         * контроллер видит applied=1 и считает план рабочим.
         *
         * Отказ — только когда НЕ ПОПАЛ НИ ОДИН: часть разрезов плана может
         * законно не попасть (короткий запрос HTTP, несколько разрезов на
         * разных якорях), и такой план по-прежнему исполняется. */
        if (n_pts == 0) {
            free(pts);
            out->refuse_why = "ни один измеренный разрез не попал в пришедшие байты: "
                              "исполнилась бы другая программа, чем мерили";
            return -1;
        }
    }

    /* Разнос во времени тоже означает владение нагрузкой: выдержать паузу
       перед правдой можно только тогда, когда правду выпускаем мы сами.
       Оригинал, отпущенный ядром, уходит когда ему угодно. */
    owns_payload = in->emit_original || (n_pts > 0) || (p->n_seqovls > 0) || (p->pace_us > 0) ||
                       (p->settle_us > 0) || (p->delay_us > 0) || p->ipfrag ||
                       p->udplen || p->qsplit;
    /* Оригинал, отданный ядру после наших сырых фальшивок, может не уйти
       вовсе (см. own_after_fakes в d2k_plan.h). Тогда правда — последняя
       посылка плана, сразу за фальшивками, без собственной паузы. */
    /* Задача 47: не только фальшивки «перед». Любая сырая посылка плана
       выходит раньше вердикта оригинала (d2kd шлёт посылки до вердикта, а
       отложенные — до отложенного вердикта), и запись создаёт она. Поэтому
       при own_after_fakes оригинал — всегда посылка плана, если фальшивки
       есть вообще. Сегодня у датаграммы другого места для фальшивки нет
       («между» требует разрезов, а UDP их не допускает), так что это
       закрепление правила, а не новое поведение. */
    if (in->own_after_fakes && p->n_fakes > 0) {
        owns_payload = 1;
    }
    if (p->udplen && in->payload_len + (size_t)p->udplen > 65535u - 8u) {
        free(pts);
        out->refuse_why = "удлинённая нагрузка не помещается в одну UDP-датаграмму";
        return -1;
    }

    /* Верхняя оценка числа посылок: копии фальшивок плюс куски. Считаем
       заранее, чтобы выделить память один раз.
     *
     * ФАЛЬШИВКА «МЕЖДУ КУСКАМИ» ВЫПУСКАЕТСЯ В КАЖДЫЙ РАЗРЕЗ, а не один раз на
     * план: разрезов n_pts, и мест для неё столько же. Прежняя оценка считала
     * её однократной, и с ДВУМЯ разрезами исполнитель писал за границу
     * выделенного массива — на живом стенде 13.09.2026 это валило датапат
     * (`malloc(): corrupted top size`). С одним разрезом оценка совпадала со
     * счётом случайно, потому и прожило незамеченным: ни один тест не ставил
     * второго разреза рядом с такой фальшивкой.
     *
     * Фальшивки «между» учитываются ТОЛЬКО при owns_payload: без собственной
     * нагрузки кусков нет, разрезать нечего, и разбор их вовсе не принимает
     * (plan_parse.c: «между кусками» без разрезов — негодный план). */
    size_t max_emits = 0;
    size_t between_per_gap = 0;
    for (size_t i = 0; i < p->n_fakes; i++) {
        uint8_t r = p->fakes[i].repeats;
        size_t reps = (r == 0 ? 1 : (size_t)r);
        if (p->fakes[i].placement == PLACE_BETWEEN) {
            between_per_gap += reps;
        } else {
            max_emits += reps;
        }
    }
    if (owns_payload) {
        max_emits += n_pts + 1;
        max_emits += n_pts * between_per_gap;
    }
    if (max_emits == 0) {
        free(pts);
        out->fate = D2K_ORIG_PASS;
        return 0;
    }

    v = calloc(max_emits, sizeof *v);
    if (!v) {
        free(pts);
        out->refuse_why = "нет памяти на посылки плана";
        return -1;
    }
    n = 0;

    /* Фальшивки, стоящие перед всеми кусками. */
    for (size_t i = 0; i < p->n_fakes; i++) {
        if (p->fakes[i].placement != PLACE_BEFORE) {
            continue;
        }
        uint8_t reps = p->fakes[i].repeats ? p->fakes[i].repeats : 1;
        for (uint8_t r = 0; r < reps; r++) {
            if (emit_fake(&v[n], p, &p->fakes[i], in, in->seq,
                          r == 0 ? 0 : p->fakes[i].gap_us,
                          &out->refuse_why) != 0) {
                free(pts); emit_vec_free(v, n); return -1;
            }
            if (r && p->wire_profile == D2K_WIRE_TCP_TEMPLATE && v[n].owned_bytes) {
                /* repeats retransmits the same mutated fake, not eight
                 * independently randomized ClientHellos. */
                memcpy(v[n].owned_bytes, v[n - r].bytes, v[n].len);
            }
            n++;
        }
    }

    if (owns_payload) {
        /* ПЕРЕКРЫТИЕ. Первый кусок выходит с номером на длину приставки
           МЕНЬШЕ, чем начало нагрузки, и несёт эту приставку впереди.
           Сервер выбросит её как уже полученное и склеит нагрузку верно;
           коробка, складывающая поток по порядку прихода, положит приставку
           в поток и разберёт не то, что разберёт сервер.
           Это ответ на коробку, которая ПЕРЕСОБИРАЕТ: разрез её не берёт,
           потому что она склеивает куски, а вот отравить склейку можно. */
        const struct d2k_payload *ovl = NULL;
        const struct d2k_poison  *ovl_po = NULL;
        if (p->n_seqovls > 0) {
            ovl = d2k_find_payload(p, p->seqovls[0].payload_id);
            if (p->seqovls[0].poison_id) {
                ovl_po = d2k_find_poison(p, p->seqovls[0].poison_id);
            }
        }

        size_t start = 0;
        for (size_t i = 0; i <= n_pts; i++) {
            size_t end = (i < n_pts) ? pts[i] : in->payload_len;
            d2k_emit *e = &v[n++];
            memset(e, 0, sizeof *e);
            e->kind = D2K_EMIT_PAYLOAD;
            e->ipfrag = p->ipfrag;
            /* Разнос проставляется НЕ здесь, а после возможного переворота
               порядка: задержка — свойство МЕСТА в очереди отправки, а не
               куска. Уехав вместе с куском, она сделала бы паузу перед первой
               же посылкой и отменила бы её перед последней. */
            e->delay_us = 0;
            e->seq = in->seq + (uint32_t)start;
            e->bytes = in->payload + start;
            e->len = end - start;
            if (p->qsplit) {
                /* Тот же разрез, что задал вопрос замера (ядро), в копии:
                   вход принадлежит пакету. Разрезов при qsplit нет
                   (plan_parse.c), кусок один и он весь пакет. Не Initial,
                   чужой кадр, нет добивки — отказ целиком: пакет уйдёт
                   нетронутым, а не «почти так, как мерили». */
                uint8_t *re = malloc(e->len);
                size_t re_len = 0;
                int src = re ? d2k_quic_initial_split_crypto(e->bytes, e->len, re, e->len,
                                                             &re_len) : -1;
                if (src != 0 || re_len != e->len) {
                    /* Причина — вызывающему (журнал отказов): разрез, которого
                       не мерили, не выдаётся за применённый план. */
                    out->refuse_why = src == D2K_QUIC_SPLIT_NO_NAME
                        ? "разрез CRYPTO: имени нет в этой датаграмме "
                          "(ClientHello шире датаграммы) — такой разрез не мерили"
                        : "разрез CRYPTO неприменим: не Initial, чужой кадр или нет добивки";
                    free(re); free(pts); emit_vec_free(v, n); return -1;
                }
                e->owned_bytes = re;
                e->bytes = re;
            }
            if (p->udplen) {
                /* zapret udplen: payload .. pattern("\x00", 1, increment).
                   Копия, а не правка на месте: вход принадлежит пакету, и
                   отмена обязана отпустить его нетронутым. Разрезов при
                   udplen нет (plan_parse.c), кусок один и он весь пакет. */
                uint8_t *grown = malloc(e->len + p->udplen);
                if (!grown) {
                    out->refuse_why = "нет памяти на удлинение датаграммы";
                    free(pts); emit_vec_free(v, n); return -1;
                }
                memcpy(grown, e->bytes, e->len);
                memset(grown + e->len, 0, p->udplen);
                e->owned_bytes = grown;
                e->bytes = grown;
                e->len += p->udplen;
            }
            if (i == 0 && ovl && ovl->len > 0) {
                e->pre = ovl->bytes;
                e->pre_len = ovl->len;
                e->seq = in->seq - (uint32_t)ovl->len;
                if (ovl_po) {
                    e->ttl = ovl_po->ttl;
                    e->poison = ovl_po->flags;
                    e->seq_shift = ovl_po->seq_shift;
                    e->ack_shift = ovl_po->ack_shift;
                    e->ts_up = ovl_po->ts_up;
                    e->autottl = ovl_po->autottl;
                    e->autottl_delta = ovl_po->autottl_delta;
                    e->autottl_min = ovl_po->autottl_min;
                    e->autottl_max = ovl_po->autottl_max;
                }
            }
            start = end;

            /* Фальшивка между кусками — после каждого, кроме последнего. */
            if (i < n_pts) {
                for (size_t k = 0; k < p->n_fakes; k++) {
                    if (p->fakes[k].placement != PLACE_BETWEEN) {
                        continue;
                    }
                    uint8_t reps = p->fakes[k].repeats ? p->fakes[k].repeats : 1;
                    for (uint8_t r = 0; r < reps; r++) {
                        if (emit_fake(&v[n], p, &p->fakes[k], in,
                                      in->seq + (uint32_t)start,
                                      r == 0 ? 0 : p->fakes[k].gap_us,
                                      &out->refuse_why) != 0) {
                            free(pts); emit_vec_free(v, n); return -1;
                        }
                        n++;
                    }
                }
            }
        }

        if (p->order == ORDER_REVERSE) {
            /* Переворачиваем только куски нагрузки, не фальшивки: смысл
               обратного порядка в том, что хвост приветствия уходит раньше
               головы, а фальшивка обязана остаться там, куда её поставили.
               Фальшивка PLACE_BETWEEN стоит ВНУТРИ диапазона кусков — она
               выпущена между ними, а не по краям. Диапазонный переворот
               («найти границы и перевернуть весь кусок памяти») утащил бы её
               вместе с нагрузкой, хотя комментарий выше обещает обратное.
               Нужен обмен по конкретным посылкам нагрузки, а не по границам
               диапазона.

               Раньше кусок отыскивали сравнением v[i].bytes с in->payload:
               указатель фальшивки — из буфера плана, указатель нагрузки — из
               буфера пакета, а это разные выделения памяти. Сравнение таких
               указателей оператором `<` не определено языком и «работало»
               только при удачной случайной раскладке кучи. kind проставлен
               явно при формировании каждой посылки (emit_fake ставит
               D2K_EMIT_FAKE, кусок нагрузки — D2K_EMIT_PAYLOAD чуть выше),
               и сравнение через него определено всегда, а не по счастливой
               случайности.

               Схождение двух указателей навстречу друг другу без выделения
               памяти: i и j — size_t, i только растёт, j только убывает, и
               j - 1 ниже вычисляется исключительно когда цикл уже проверил
               i < j, то есть j >= 1. Переполнения размера нет ни на одном
               шаге, поэтому единственный кусок (или вовсе пустой диапазон)
               оставляет цикл без единой итерации, а не пишет за пределы v —
               раньше при hi == lo это же место разности `j - 1` при j == 0
               уходило в беззнаковое переполнение и писало за границу массива. */
            size_t i = 0, j = n;
            while (i < j) {
                if (v[i].kind != D2K_EMIT_PAYLOAD) {
                    i++;
                    continue;
                }
                if (v[j - 1].kind != D2K_EMIT_PAYLOAD) {
                    j--;
                    continue;
                }
                if (i + 1 >= j) {
                    /* Между указателями остался один кусок нагрузки или
                       ни одного — меняться больше нечему. */
                    break;
                }
                d2k_emit t = v[i];
                v[i] = v[j - 1];
                v[j - 1] = t;
                i++;
                j--;
            }
        }
    }

    /* РАЗНОС ВО ВРЕМЕНИ — позиционно, после всех перестановок.
     *
     * Пауза стоит перед каждой посылкой НАГРУЗКИ, кроме самой первой посылки
     * плана: перед ней ждать не перед чем. Фальшивки не трогаем — у них своя
     * пауза между копиями (gap_us), и приём «серия вплотную» с ней и
     * задуман; наложив сюда же общий разнос, мы превратили бы одно плечо в
     * другое.
     *
     * Обе формы донора закрываются этим одним правилом: три куска с паузой
     * между ними (фальшивок нет — первый уходит сразу) и выдержка между
     * последней фальшивкой и правдой (первой идёт фальшивка — нагрузка ждёт).
     */
    if (p->pace_us > 0) {
        for (size_t i = 0; i < n; i++) {
            if (v[i].kind != D2K_EMIT_PAYLOAD) { continue; }
            v[i].delay_us = (i == 0) ? 0 : p->pace_us;
        }
    }

    if (p->settle_us > 0) {
        for (size_t i = 0; i < n; i++) {
            if (v[i].kind != D2K_EMIT_PAYLOAD) { continue; }
            if (i > 0) { v[i].delay_us = p->settle_us; }
            break;
        }
    }

    /* ВЫДЕРЖКА ПЕРЕД ПЕРВОЙ НАГРУЗКОЙ — независимо от того, стоит ли что-то
       перед ней. Этим и отличается от settle, который молчит на посылке с
       нулевым номером (см. d2k_plan_internal.h про delay_us). */
    if (p->delay_us > 0) {
        for (size_t i = 0; i < n; i++) {
            if (v[i].kind != D2K_EMIT_PAYLOAD) { continue; }
            v[i].delay_us = p->delay_us;
            break;
        }
    }
    free(pts);
finalize:
    for (size_t i = 0; i < n; i++) { v[i].wire_profile = p->wire_profile; }
    if (p->segment_size || in->segment_cap) {
        /* Match raw_send: split the concatenated prefix+body, preserving
         * bytes, sequence space, fooling and only the first chunk's delay.
         * Route MTU also bounds ordinary TCP payloads: a paced or split
         * plan can own a reassembled ClientHello larger than one packet.
         * The route cap does not segment fake packets, UDP, or explicit
         * IP-fragment plans; an explicit segment_size keeps its semantics. */
        size_t count = 0;
        for (size_t i = 0; i < n; i++) {
            size_t bytes = v[i].pre_len + v[i].len;
            size_t limit = p->segment_size;
            if (in->segment_cap && (!p->transport || p->transport == 6) &&
                !p->ipfrag && v[i].kind == D2K_EMIT_PAYLOAD &&
                (!limit || in->segment_cap < limit)) {
                limit = in->segment_cap;
            }
            size_t chunks = limit && bytes ? (bytes - 1) / limit + 1 : 1;
            if (chunks > 65536 || count > 65536 - chunks) {
                out->refuse_why = "нарезка на сегменты даёт слишком много посылок";
                emit_vec_free(v, n); return -1;
            }
            count += chunks;
        }
        d2k_emit *split = calloc(count, sizeof *split);
        if (!split) {
            out->refuse_why = "нет памяти на нарезку посылок";
            emit_vec_free(v, n); return -1;
        }
        size_t k = 0;
        for (size_t i = 0; i < n; i++) {
            size_t limit = p->segment_size;
            if (in->segment_cap && (!p->transport || p->transport == 6) &&
                !p->ipfrag && v[i].kind == D2K_EMIT_PAYLOAD &&
                (!limit || in->segment_cap < limit)) {
                limit = in->segment_cap;
            }
            size_t total = v[i].pre_len + v[i].len, off = 0;
            do {
                d2k_emit *e = &split[k++];
                *e = v[i];
                size_t take = total - off;
                if (limit && take > limit) { take = limit; }
                e->seq += (uint32_t)off;
                if (off) { e->delay_us = 0; }
                e->pre_len = off < v[i].pre_len ? v[i].pre_len - off : 0;
                if (e->pre_len > take) { e->pre_len = take; }
                e->pre = e->pre_len ? v[i].pre + off : NULL;
                e->len = take - e->pre_len;
                e->bytes = e->len ? v[i].bytes + (off > v[i].pre_len ? off - v[i].pre_len : 0) : NULL;
                e->owned_bytes = off == 0 ? v[i].owned_bytes : NULL;
                off += take;
            } while (off < total);
            v[i].owned_bytes = NULL; /* ownership transferred to first chunk */
        }
        emit_vec_free(v, n); v = split; n = count;
    }
    out->v = v;
    out->n = n;
    out->fate = owns_payload ? D2K_ORIG_DROP : D2K_ORIG_PASS;
    return 0;
}

/* Отмена исполнения на середине.
 *
 * Три правила, и все три следуют из одного: коробка уже увидела часть того,
 * что мы собирались показать, и вернуть это назад нельзя.
 *
 * 1. Пока нагрузку не трогали — оригинал отпускается. Он цел, и потерять его
 *    значило бы оборвать соединение человеку из-за нашей внутренней причины.
 * 2. Как только ушёл хоть один кусок нагрузки — чистого выхода нет. Отпустить
 *    оригинал значит послать те же байты дважды, не отпустить — потерять
 *    остаток. Поток испорчен, и исполнитель сообщает об этом фактом, а не
 *    выбирает меньшее зло сам: что делать с испорченным потоком — политика
 *    контроллера.
 * 3. Любая незавершённая отправка делает исполнение неполным. По нему нельзя
 *    записывать ни успех, ни неудачу: коробка видела не тот набор пакетов,
 *    который описывает план, а §2.3 запрещает сохранять неподтверждённое.
 */
void d2k_actions_cancel(const d2k_actions *a, size_t emitted, d2k_cancel *out) {
    if (!out) {
        return;
    }
    memset(out, 0, sizeof *out);
    if (!a) {
        out->fate = D2K_ORIG_PASS;
        return;
    }
    if (emitted > a->n) {
        emitted = a->n;
    }

    int payload_out = 0;
    for (size_t i = 0; i < emitted; i++) {
        if (a->v[i].kind == D2K_EMIT_PAYLOAD) {
            payload_out = 1;
            break;
        }
    }

    out->partial = (emitted < a->n) ? 1 : 0;
    out->stream_damaged = (payload_out && emitted < a->n) ? 1 : 0;

    if (payload_out) {
        /* Байты нагрузки уже на проводе: повторять их нельзя. */
        out->fate = D2K_ORIG_DROP;
    } else {
        out->fate = D2K_ORIG_PASS;
    }
}

void d2k_actions_free(d2k_actions *a) {
    if (!a) {
        return;
    }
    for (size_t i = 0; i < a->n; i++) { free(a->v[i].owned_bytes); }
    free(a->v);
    a->v = NULL;
    a->n = 0;
}
