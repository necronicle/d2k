/* plan_parse.c — разбор канонической формы плана.
 *
 * Главное свойство: всё, что не понято ЦЕЛИКОМ, отвергается. Неизвестный тип
 * записи, завышенная схема, завышенная версия исполнителя, ненулевые флаги,
 * несовпадение числа записей, висячая ссылка — каждая из этих причин валит
 * загрузку. План, часть которого не разобрана, — это не «план попроще», а
 * план, отличный от измеренного.
 *
 * Границы считаются ЯВНО. Здесь намеренно нет ни одного вычитания выровненной
 * длины из остатка: измеритель этапа 0 на такой арифметике дал сегфолт на
 * первом же пакете, потому что у последнего атрибута хвоста выравнивания в
 * буфере не оказалось, а счётчик размера беззнаковый.
 */
#include "include/d2k_capture.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "d2k_plan.h"
#include "plan_internal.h"
#include "d2k_preflight_plan.h"

#define HEADER_LEN 12

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8 | (uint32_t)p[3];
}

static void fail(char *err, size_t errlen, const char *msg) {
    if (err && errlen) {
        snprintf(err, errlen, "%s", msg);
    }
}

/* Счётчик записей каждого вида — чтобы выделить память ровно один раз, а не
 * наращивать массивы по ходу. Проход дешёвый, а realloc в датапате — лишний
 * источник ошибок. */
struct counts {
    int explicit_order;
    size_t orders, payloads, poisons, splits, fakes, seqovls, oob, stream_offset,after_split,preflight,pf_resyn,pf_handover;
};

static int scan(const uint8_t *b, size_t len, struct counts *c,
                uint16_t *recs_seen, char *err, size_t errlen) {
    size_t off = HEADER_LEN;
    *recs_seen = 0;
    memset(c, 0, sizeof *c);

    while (off < len) {
        if (off + 4 > len) {
            fail(err, errlen, "обрезанный заголовок записи");
            return -1;
        }
        uint16_t typ = rd16(b + off);
        size_t ln = rd16(b + off + 2);
        off += 4;
        if (ln > len || off + ln > len) {
            fail(err, errlen, "запись выходит за буфер");
            return -1;
        }

        if ((typ == REC_INPUT || typ == REC_SETTLE || typ == REC_SEGMENT) &&
            rd16(b + 6) < 3) {
            fail(err, errlen, "измеренный план требует minexec=3"); return -1;
        }
        switch (typ) {
        case REC_HANDOVER_APPLY:
            if(rd16(b+6)<20 || ln!=1 || b[off]!=1 || ++c->pf_handover>1) {
                fail(err,errlen,"invalid handover apply or minexec");return -1;
            }
            break;
        case REC_PREFLIGHT_RESYN:
            if(rd16(b+6)<19 || ln!=7 || ++c->pf_resyn>1 || !rd16(b+off) ||
               rd16(b+off)>4999 || !b[off+2] || !rd32(b+off+3) ||
               rd32(b+off+3)>D2K_PF_EXEC_MAX_TIMEOUT_MS ||
               rd32(b+off+3)<(uint64_t)rd16(b+off)*b[off+2]) {
                fail(err,errlen,"invalid preflight resyn timing or minexec");return -1;
            }
            break;
        case REC_PREFLIGHT:
            if(rd16(b+6)<18 || ln<11 || ln>264 || ++c->preflight>1 ||
               !rd16(b+off) || b[off+2]>14 || !b[off+3] || b[off+4]>1 ||
               rd32(b+off+5)<1000 || rd32(b+off+5)>(rd16(b+6)<19 ? 5000u : D2K_PF_EXEC_MAX_TIMEOUT_MS) ||
               (!rd16(b+off+9)) || (b[off+4] ? ln!=11 : ln==11)) {
                fail(err,errlen,"invalid preflight parameters or minexec");return -1;
            }
            if(!b[off+4] && !d2k_pf_name_valid(b+off+11,ln-11)) {
                fail(err,errlen,"invalid preflight white name");return -1;
            }
            break;
        case REC_IPFRAG:
            if (rd16(b + 6) < 7 || ln != 1 || b[off] < 1 || b[off] > 4) {
                fail(err, errlen, "ipfrag требует minexec=7 и форму 1..4"); return -1;
            }
            break;
        case REC_UDPLEN:
            /* minexec=9: старый исполнитель удлинения не знает и выпустил бы
               датаграмму короче измеренной. Ноль — не действие. */
            if (rd16(b + 6) < 9 || ln != 2 || rd16(b + off) == 0) {
                fail(err, errlen, "udplen требует minexec=9 и ненулевого прироста"); return -1;
            }
            break;
        case REC_QSPLIT:
            /* minexec=10: старый исполнитель записи не знает и выпустил бы
               Initial целым — то есть не то, что мерили. Форма одна. */
            if (rd16(b + 6) < 10 || ln != 1 || b[off] != 1) {
                fail(err, errlen, "quicsplit требует minexec=10 и форму 1"); return -1;
            }
            break;
        case REC_QDENY:
            /* minexec=11: старый исполнитель записи не знает и пропустил бы
               QUIC — то есть не сделал бы того, ради чего план поставлен. */
            if (rd16(b + 6) < 11 || ln != 1 || b[off] != 1) {
                fail(err, errlen, "quicdeny требует minexec=11 и форму 1"); return -1;
            }
            break;
        case REC_OOB:
            if (rd16(b + 6) < 8 || ln != 3 || rd16(b + off) > ANCHOR_SLD_MIDDLE) {
                fail(err, errlen, "oob требует minexec=8, якорь и один байт"); return -1;
            }
            c->oob++;
            if (c->oob > 1) {
                fail(err, errlen, "повторная запись oob"); return -1;
            }
            break;
        case REC_ID:
            if (ln != D2K_PLAN_ID_LEN) { fail(err, errlen, "id не 16 байт"); return -1; }
            break;
        case REC_PROTO:
            if (ln != 2) { fail(err, errlen, "proto не 2 байта"); return -1; }
            if (b[off + 1] == D2K_PLAN_PROTO_HTTP &&
                (rd16(b + 6) < 11 || b[off] != 6)) {
                fail(err, errlen, "протокол http требует TCP и minexec=11"); return -1;
            }
            break;
        case REC_PAYLOAD:
            if (ln < 2) { fail(err, errlen, "приманка без номера"); return -1; }
            c->payloads++;
            break;
        case REC_POISON:
            if (ln != 8 && ln != 12) { fail(err, errlen, "poison must be 8 or 12 bytes"); return -1; }
            if (ln == 12 && rd16(b + 6) < 14) {
                fail(err, errlen, "ackshift requires minexec=14"); return -1;
            }
            if ((b[off + 3] & D2K_POISON_MD5) && rd16(b + 6) < 12) {
                fail(err, errlen, "md5 требует minexec=12"); return -1;
            }
            if ((b[off + 3] & D2K_POISON_MD5_TS) && rd16(b + 6) < 15) {
                fail(err, errlen, "md5ts требует minexec=15"); return -1;
            }
            c->poisons++;
            break;
        case REC_AUTOTTL:
            /* minexec 13: старый исполнитель записи не знает и поставил бы
               фальшивку с константным TTL — другое воздействие (§2.5). */
            if (rd16(b + 6) < 13 || ln != 5) {
                fail(err, errlen, "autottl требует minexec=13 и 5 байт"); return -1;
            }
            if (b[off + 3] > b[off + 4] && b[off + 4] != 0) {
                fail(err, errlen, "autottl: min больше max"); return -1;
            }
            break;
        case REC_SPLIT:
            if (ln != 4) { fail(err, errlen, "разрез не 4 байта"); return -1; }
            c->splits++;
            break;
        case REC_FAKE:
            if (ln != 10 && ln != 11) { fail(err, errlen, "фальшивка не 10/11 байт"); return -1; }
            if (ln == 11 && rd16(b + 6) < 8) {
                fail(err, errlen, "tlsmod требует minexec=8"); return -1;
            }
            if (ln == 11 && (b[off + 10] & ~(D2K_TLS_MOD_RND | D2K_TLS_MOD_DUPSID | D2K_TLS_MOD_FRESH))) {
                fail(err, errlen, "неизвестный tlsmod"); return -1;
            }
            if (ln == 11 && (b[off + 10] & D2K_TLS_MOD_FRESH) &&
                (rd16(b + 6) < D2K_EXEC_VERSION || !(b[off + 10] & D2K_TLS_MOD_RND))) {
                fail(err, errlen, "fresh требует minexec=21 и rnd"); return -1;
            }
            c->fakes++;
            break;
        case REC_SEQOVL:
            if (ln != 4) { fail(err, errlen, "перекрытие не 4 байта"); return -1; }
            c->seqovls++;
            break;
        case REC_ORDER:
            c->orders++;
            if (ln == 1 && b[off] <= ORDER_REVERSE) break;
            if (ln < 3 || b[off] != ORDER_EMISSIONS ||
                rd16(b + 6) < D2K_EXEC_EMISSION_ORDER ||
                !d2k_emission_order_valid(b + off + 1, ln - 1)) {
                fail(err, errlen, "неверная перестановка посылок или minexec"); return -1;
            }
            c->explicit_order = 1;
            break;
        case REC_PACE:
            if (ln != 4) { fail(err, errlen, "разнос во времени не 4 байта"); return -1; }
            break;
        case REC_DELAY:
            /* minexec=6: старый датапат выдержки перед единственной посылкой
               не знает, и молча выпустить её без паузы значит исполнить не
               тот план. Отказ громкий. */
            if (rd16(b + 6) < 6 || ln != 4 || rd32(b + off) == 0) {
                fail(err, errlen, "выдержка требует minexec=6 и ненулевого числа"); return -1;
            }
            break;
        case REC_INPUT:
            if (ln != 12 || rd32(b + off) == 0 ||
                rd32(b + off + 4) > rd32(b + off) ||
                rd32(b + off + 8) > rd32(b + off) - rd32(b + off + 4)) {
                fail(err, errlen, "недопустимый контекст измеренного входа"); return -1;
            }
            break;
        case REC_WIRE:
            if (rd16(b + 6) < 4 || ln != 1 ||
                (b[off] != D2K_WIRE_DETECT_TCP && b[off] != D2K_WIRE_TCP_TEMPLATE) ||
                (b[off] == D2K_WIRE_TCP_TEMPLATE && rd16(b + 6) < 8)) {
                fail(err, errlen, "неподдержанный TCP wire profile или minexec < 4"); return -1;
            }
            break;
        case REC_INPUT_TLS:
            if (rd16(b + 6) < 5 || ln != 0) {
                fail(err, errlen, "input tls-sni требует minexec=5 и пустую запись"); return -1;
            }
            break;
        case REC_STREAM_OFFSET:
            if(rd16(b+6)<16 || ln!=4 || rd32(b+off)>=UINT32_C(0x80000000) || c->stream_offset++) {
                fail(err,errlen,"invalid or duplicate stream-offset, requires minexec=16");return -1;
            }
            break;
        case REC_AFTER_SPLIT:
            if(rd16(b+6)<17 || ln!=12 || c->after_split++ || !rd32(b+off) ||
               rd32(b+off)>=UINT32_C(0x80000000) || rd32(b+off+4)<2 || rd32(b+off+4)>65535 ||
               rd32(b+off+4)>=UINT32_C(0x80000000)-rd32(b+off) ||
               !rd32(b+off+8) || rd32(b+off+8)>=rd32(b+off+4) || rd32(b+off+8)>32767) {
                fail(err,errlen,"invalid or duplicate after-split, requires minexec=17");return -1;
            }
            break;
        case REC_SETTLE:
            if (ln != 4 || rd32(b + off) == 0) {
                fail(err, errlen, "недопустимая пауза перед правдой"); return -1;
            }
            break;
        case REC_SEGMENT:
            if (ln != 4 || !rd32(b + off) || rd32(b + off) > 65535) {
                fail(err, errlen, "недопустимый размер сегмента"); return -1;
            }
            break;
        case REC_GUARD:
            if (ln != 1) { fail(err, errlen, "защита не 1 байт"); return -1; }
            if (b[off] == 0 || (b[off] & ~(unsigned)D2K_GUARD_RST_ALIEN) != 0) {
                /* Пустая или незнакомая защита — отказ, а не «ничего не
                   делаем»: план, часть которого исполнитель не понял, не
                   должен исполняться вовсе (§2.5). */
                fail(err, errlen, "неизвестные биты защиты");
                return -1;
            }
            break;
        default:
            /* Незнакомое не пропускается: см. заголовок файла. */
            fail(err, errlen, "неизвестный тип записи");
            return -1;
        }

        off += ln;
        if (*recs_seen == 0xffff) {
            fail(err, errlen, "слишком много записей");
            return -1;
        }
        (*recs_seen)++;
    }
    if (c->explicit_order) {
        if (c->orders != 1) {
            fail(err, errlen, "повторный порядок посылок"); return -1;
        }
        if (c->splits >= D2K_WIRE_BATCH_MAX || c->fakes >= D2K_WIRE_BATCH_MAX) {
            fail(err, errlen, "слишком много операций для перестановки посылок"); return -1;
        }
    }
    return 0;
}

/* Ссылки обязаны разрешаться. Ноль означает «ничего» и висячей ссылкой не
 * является: фальшивка без порчи законна. */
static int check_refs(d2k_plan *p, char *err, size_t errlen) {
    if(p->after_length && (p->transport!=6 || p->proto!=1 ||
       p->has_stream_offset || !p->input_len || p->input_len>p->after_offset ||
       (p->wire_profile!=D2K_WIRE_DETECT_TCP && p->wire_profile!=D2K_WIRE_TCP_TEMPLATE))) {
        fail(err,errlen,"after-split requires exact first TCP/TLS input and a TCP wire profile");return -1;
    }
    for (size_t i = 0; i < p->n_poisons; i++) {
        if (p->poisons[i].ack_shift && p->transport != 6) {
            fail(err, errlen, "ackshift requires TCP"); return -1;
        }
        if ((p->poisons[i].flags & D2K_POISON_MD5) &&
            (p->minexec < 12 || p->transport != 6 || p->wire_profile != D2K_WIRE_DETECT_TCP)) {
            fail(err, errlen, "md5 требует minexec=12 и wire detect-tcp-v1 TCP");
            return -1;
        }
        if ((p->poisons[i].flags & D2K_POISON_MD5_TS) &&
            (p->minexec < 15 || p->transport != 6 || p->wire_profile != D2K_WIRE_DETECT_TCP)) {
            fail(err, errlen, "md5ts требует minexec=15 и wire detect-tcp-v1 TCP");
            return -1;
        }
    }

    if (p->ipfrag && (p->transport != 17 || p->n_splits || p->n_seqovls ||
        p->order || p->input_len || p->input_tls || p->settle_us ||
        p->segment_size || p->wire_profile || p->guards)) {
        fail(err, errlen, "ipfrag требует UDP без TCP-операций/перестановки");
        return -1;
    }
    /* udplen с ipfrag не бывает и у донора: там udplen стоит после drop и на
       провод не попадает (DROP в zapret липкий). Исполнять удлинённые
       фрагменты значило бы исполнить то, чего никто не мерил. */
    if (p->udplen && (p->transport != 17 || p->ipfrag || p->n_splits || p->n_seqovls ||
        p->order || p->input_len || p->input_tls || p->settle_us ||
        p->segment_size || p->wire_profile || p->guards || p->oob_enabled)) {
        fail(err, errlen, "udplen требует UDP без фрагментации, разрезов и TCP-операций");
        return -1;
    }
    /* Разрез CRYPTO — отдельное измеренное действие: с фрагментами и
       удлинением его не мерили, а TCP-операций у датаграммы нет. */
    if (p->qsplit && (p->transport != 17 || p->ipfrag || p->udplen || p->n_splits ||
        p->n_seqovls || p->order || p->input_len || p->input_tls || p->settle_us ||
        p->segment_size || p->wire_profile || p->guards || p->oob_enabled)) {
        fail(err, errlen, "quicsplit требует UDP без фрагментации, удлинения и TCP-операций");
        return -1;
    }
    /* Снятие QUIC — единственное содержание своего плана: с воздействиями
       оно не смешивается, и у TCP его нет. */
    if (p->qdeny && (p->transport != 17 || p->ipfrag || p->udplen || p->qsplit ||
        p->n_splits || p->n_seqovls || p->n_fakes || p->n_payloads || p->n_poisons ||
        p->order || p->input_len || p->input_tls || p->settle_us || p->segment_size ||
        p->wire_profile || p->guards || p->oob_enabled || p->pace_us || p->delay_us)) {
        fail(err, errlen, "quicdeny требует UDP и план без воздействий");
        return -1;
    }
    if(p->pf_handover_apply && (!p->preflight || p->minexec<20)) {
        fail(err,errlen,"handover apply requires preflight and minexec=20");return -1;
    }
    if(p->preflight && (p->minexec<18 || p->transport!=6 || p->proto!=1)) {
        fail(err,errlen,"preflight requires TCP/TLS and minexec=18");return -1;
    }
    if(p->preflight && !p->pf_handover_apply && (
       p->n_payloads!=1 || p->n_poisons || p->n_splits || p->n_fakes || p->n_seqovls ||
       p->order || p->guards || p->pace_us || p->input_len || p->settle_us || p->segment_size ||
       p->wire_profile || p->input_tls || p->has_stream_offset || p->after_length ||
       p->delay_us || p->ipfrag || p->oob_enabled || p->udplen || p->qsplit || p->qdeny)) {
        fail(err,errlen,"preflight requires minexec=18 and a standalone TCP/TLS plan");return -1;
    }
    if(p->preflight) {
        const struct d2k_payload *hello=d2k_find_payload(p,p->pf_data);
        if(!hello || !hello->len || hello->len>D2K_CAPTURE_BYTES) {
            fail(err,errlen,"preflight needs its referenced hello payload, 1..4096 bytes");return -1;
        }
        p->pf_hello=hello->bytes;p->pf_hello_len=hello->len;
    }
    if (p->oob_enabled && (p->minexec < 8 || p->transport != 6 || p->proto != 1 ||
        !p->input_tls || !p->wire_profile || p->n_splits || p->n_seqovls || p->n_fakes ||
        p->ipfrag || p->pace_us || p->settle_us || p->delay_us)) {
        fail(err, errlen, "oob требует измеренный TCP/TLS-вход и отдельный план");
        return -1;
    }
    for (size_t i = 0; i < p->n_fakes; i++) {
        if ((p->fakes[i].tls_mod & D2K_TLS_MOD_FRESH) &&
            (p->wire_profile != D2K_WIRE_TCP_TEMPLATE || p->transport != 6 || p->proto != 1)) {
            fail(err,errlen,"fresh requires tcp-template-v1 TCP/TLS");return -1;
        }
        if (p->fakes[i].payload_id == 0 ||
            !d2k_find_payload(p, p->fakes[i].payload_id)) {
            fail(err, errlen, "фальшивка ссылается на несуществующую приманку");
            return -1;
        }
        if (p->fakes[i].poison_id != 0 &&
            !d2k_find_poison(p, p->fakes[i].poison_id)) {
            fail(err, errlen, "фальшивка ссылается на несуществующую порчу");
            return -1;
        }
    }
    for (size_t i = 0; i < p->n_seqovls; i++) {
        if (p->seqovls[i].payload_id == 0 ||
            !d2k_find_payload(p, p->seqovls[i].payload_id)) {
            fail(err, errlen, "перекрытие ссылается на несуществующую приманку");
            return -1;
        }
        if (p->seqovls[i].poison_id != 0 &&
            !d2k_find_poison(p, p->seqovls[i].poison_id)) {
            fail(err, errlen, "перекрытие ссылается на несуществующую порчу");
            return -1;
        }
    }

    if (p->pf_resyn_delay_ms && (!p->preflight || p->pf_resyn_timeout_ms>=p->pf_timeout_ms)) {
        fail(err,errlen,"resyn timing requires preflight and a delay below its timeout");return -1;
    }
    /* Фальшивке «между кусками» нужны куски. План, который просит положить её
       туда, где кусков нет, невыполним — и отвергается здесь, а не
       приближается размещением «перед всеми». Приблизить неподдерживаемую
       операцию другой запрещает §2.5. */
    for (size_t i = 0; i < p->n_fakes; i++) {
        if (p->fakes[i].placement == PLACE_BETWEEN && p->n_splits == 0) {
            fail(err, errlen, "фальшивка между кусками, а разрезов нет");
            return -1;
        }
        if (p->fakes[i].placement != PLACE_BEFORE &&
            p->fakes[i].placement != PLACE_BETWEEN) {
            fail(err, errlen, "неизвестное размещение фальшивки");
            return -1;
        }
    }

    if (p->order == ORDER_EMISSIONS) {
        if (p->transport != 6 || p->oob_enabled || p->after_length || p->preflight) {
            fail(err, errlen, "перестановка посылок требует обычного TCP-входа");
            return -1;
        }
        size_t count = p->n_splits + 1;
        for (size_t i = 0; i < p->n_fakes; i++) {
            size_t repeats = p->fakes[i].repeats ? p->fakes[i].repeats : 1;
            count += repeats * (p->fakes[i].placement == PLACE_BETWEEN ? p->n_splits : 1);
        }
        if (count != p->emission_count) {
            fail(err, errlen, "перестановка должна перечислять все логические посылки");
            return -1;
        }
    }

    /* Перекрытий больше одного не бывает: приставка у первого куска одна.
       Отказ, а не молчаливое взятие первого — план, часть которого не
       исполняется, это не тот план, который измеряли. */
    if (p->n_seqovls > 1) {
        fail(err, errlen, "перекрытие может быть только одно");
        return -1;
    }
    return 0;
}

const struct d2k_payload *d2k_find_payload(const d2k_plan *p, uint16_t id) {
    for (size_t i = 0; i < p->n_payloads; i++) {
        if (p->payloads[i].id == id) {
            return &p->payloads[i];
        }
    }
    return NULL;
}

const struct d2k_poison *d2k_find_poison(const d2k_plan *p, uint16_t id) {
    for (size_t i = 0; i < p->n_poisons; i++) {
        if (p->poisons[i].id == id) {
            return &p->poisons[i];
        }
    }
    return NULL;
}

int d2k_plan_load(const uint8_t *buf, size_t len,
                  d2k_plan **out, char *err, size_t errlen) {
    if (out) {
        *out = NULL;
    }
    if (!buf || len < HEADER_LEN) {
        fail(err, errlen, "короче заголовка");
        return -1;
    }
    if (memcmp(buf, "D2KP", 4) != 0) {
        fail(err, errlen, "не план d2k");
        return -1;
    }
    uint16_t schema = rd16(buf + 4);
    uint16_t minexec = rd16(buf + 6);
    if (schema > D2K_SCHEMA_MAX) {
        fail(err, errlen, "схема новее, чем понимает эта сборка");
        return -1;
    }
    if (minexec > D2K_EXEC_VERSION) {
        fail(err, errlen, "плану нужен более новый исполнитель");
        return -1;
    }
    if (rd16(buf + 8) != 0) {
        fail(err, errlen, "ненулевые флаги заголовка");
        return -1;
    }
    uint16_t declared = rd16(buf + 10);

    struct counts c;
    uint16_t seen = 0;
    if (scan(buf, len, &c, &seen, err, errlen) != 0) {
        return -1;
    }
    if (seen != declared) {
        fail(err, errlen, "число записей не совпадает с заявленным");
        return -1;
    }

    d2k_plan *p = calloc(1, sizeof *p);
    if (!p) {
        fail(err, errlen, "нет памяти");
        return -1;
    }
    p->schema = schema;
    p->minexec = minexec;

    if (c.payloads) { p->payloads = calloc(c.payloads, sizeof *p->payloads); }
    if (c.poisons)  { p->poisons  = calloc(c.poisons,  sizeof *p->poisons);  }
    if (c.splits)   { p->splits   = calloc(c.splits,   sizeof *p->splits);   }
    if (c.fakes)    { p->fakes    = calloc(c.fakes,    sizeof *p->fakes);    }
    if (c.seqovls)  { p->seqovls  = calloc(c.seqovls,  sizeof *p->seqovls);  }
    if ((c.payloads && !p->payloads) || (c.poisons && !p->poisons) ||
        (c.splits && !p->splits) || (c.fakes && !p->fakes) ||
        (c.seqovls && !p->seqovls)) {
        d2k_plan_free(p);
        fail(err, errlen, "нет памяти");
        return -1;
    }

    size_t off = HEADER_LEN;
    while (off < len) {
        uint16_t typ = rd16(buf + off);
        size_t ln = rd16(buf + off + 2);
        const uint8_t *v = buf + off + 4;
        off += 4 + ln;

        switch (typ) {
        case REC_PREFLIGHT_RESYN:
            p->pf_resyn_delay_ms=rd16(v);p->pf_resyn_sends=v[2];p->pf_resyn_timeout_ms=rd32(v+3);
            break;
        case REC_PREFLIGHT:
            p->preflight=1;p->pf_window=rd16(v);p->pf_wscale=v[2];p->pf_pieces=v[3];
            p->pf_hello_own=v[4];p->pf_timeout_ms=rd32(v+5);
            p->pf_data=rd16(v+9);
            memcpy(p->pf_name,v+11,ln-11);p->pf_name[ln-11]=0;
            break;
        case REC_HANDOVER_APPLY:
            p->pf_handover_apply=1;break;
        case REC_IPFRAG:
            if (p->ipfrag) {
                d2k_plan_free(p); fail(err, errlen, "повторная запись ipfrag"); return -1;
            }
            p->ipfrag = v[0];
            break;
        case REC_UDPLEN:
            if (p->udplen) {
                d2k_plan_free(p); fail(err, errlen, "повторная запись udplen"); return -1;
            }
            p->udplen = rd16(v);
            break;
        case REC_QSPLIT:
            if (p->qsplit) {
                d2k_plan_free(p); fail(err, errlen, "повторная запись quicsplit"); return -1;
            }
            p->qsplit = v[0];
            break;
        case REC_QDENY:
            if (p->qdeny) {
                d2k_plan_free(p); fail(err, errlen, "повторная запись quicdeny"); return -1;
            }
            p->qdeny = v[0];
            break;
        case REC_OOB:
            p->oob_enabled = 1;
            p->oob_anchor = rd16(v);
            p->oob_byte = v[2];
            break;
        case REC_ID:
            memcpy(p->id, v, D2K_PLAN_ID_LEN);
            break;
        case REC_PROTO:
            p->transport = v[0];
            p->proto = v[1];
            break;
        case REC_PAYLOAD: {
            struct d2k_payload *pl = &p->payloads[p->n_payloads++];
            pl->id = rd16(v);
            pl->len = ln - 2;
            if (pl->len) {
                pl->bytes = malloc(pl->len);
                if (!pl->bytes) {
                    d2k_plan_free(p);
                    fail(err, errlen, "нет памяти под приманку");
                    return -1;
                }
                memcpy(pl->bytes, v + 2, pl->len);
            }
            break;
        }
        case REC_POISON: {
            struct d2k_poison *po = &p->poisons[p->n_poisons++];
            po->id = rd16(v);
            po->ttl = v[2];
            po->flags = v[3];
            po->ts_up = (v[3] & D2K_POISON_TS_UP) ? 1 : 0;
            po->seq_shift = (int32_t)rd32(v + 4);
            po->ack_shift = ln == 12 ? (int32_t)rd32(v + 8) : 0;
            break;
        }
        case REC_AUTOTTL: {
            /* Ссылка на порчу по id: запись идёт ПОСЛЕ своей порчи, как и
               прочие ссылающиеся записи. Висячая ссылка — отказ. */
            uint16_t pid = rd16(v);
            struct d2k_poison *po = NULL;
            for (size_t k = 0; k < p->n_poisons; k++) {
                if (p->poisons[k].id == pid) { po = &p->poisons[k]; break; }
            }
            if (!po) {
                d2k_plan_free(p);
                fail(err, errlen, "autottl ссылается на неизвестную порчу");
                return -1;
            }
            po->autottl = 1;
            po->autottl_delta = (int8_t)v[2];
            po->autottl_min = v[3];
            po->autottl_max = v[4];
            break;
        }
        case REC_SPLIT: {
            struct d2k_split *s = &p->splits[p->n_splits++];
            s->anchor = rd16(v);
            s->offset = (int16_t)rd16(v + 2);
            break;
        }
        case REC_FAKE: {
            struct d2k_fake *f = &p->fakes[p->n_fakes++];
            f->payload_id = rd16(v);
            f->poison_id = rd16(v + 2);
            f->repeats = v[4];
            f->placement = v[5];
            f->gap_us = rd32(v + 6);
            f->tls_mod = ln == 11 ? v[10] : 0;
            break;
        }
        case REC_SEQOVL: {
            struct d2k_seqovl *s = &p->seqovls[p->n_seqovls++];
            s->payload_id = rd16(v);
            s->poison_id = rd16(v + 2);
            break;
        }
        case REC_ORDER:
            p->order = v[0];
            p->emission_count = (uint8_t)(ln - 1);
            memcpy(p->emission_order, v + 1, p->emission_count);
            break;
        case REC_PACE:
            /* Последняя запись побеждает — та же дисциплина, что у порядка и
               защиты выше: план с двумя разносами противоречив, но отвергать
               его нечем осмысленным, а молча складывать значения было бы
               выдумкой. */
            p->pace_us = rd32(v);
            break;
        case REC_DELAY:
            /* Последняя запись побеждает — та же дисциплина, что у разноса. */
            p->delay_us = rd32(v);
            break;
        case REC_INPUT:
            p->input_len = rd32(v);
            p->input_sni_off = rd32(v + 4);
            p->input_sni_len = rd32(v + 8);
            break;
        case REC_INPUT_TLS:
            p->input_tls = 1;
            break;
        case REC_STREAM_OFFSET:
            p->has_stream_offset=1;p->stream_offset=rd32(v);
            break;
        case REC_AFTER_SPLIT:
            p->after_offset=rd32(v);p->after_length=rd32(v+4);p->after_cut=rd32(v+8);
            break;
        case REC_WIRE:
            p->wire_profile = v[0];
            break;
        case REC_SETTLE:
            p->settle_us = rd32(v);
            break;
        case REC_SEGMENT:
            p->segment_size = rd32(v);
            break;
        case REC_GUARD:
            p->guards = v[0];
            break;
        default:
            /* Недостижимо: scan уже отверг бы такой план. Ветка оставлена,
               чтобы добавление кода записи без обновления scan не проходило
               молча. */
            d2k_plan_free(p);
            fail(err, errlen, "неизвестный тип записи");
            return -1;
        }
    }

    if (check_refs(p, err, errlen) != 0) {
        d2k_plan_free(p);
        return -1;
    }
    if (p->transport != 6 && (p->has_stream_offset || p->input_len || p->input_tls || p->settle_us || p->segment_size || p->wire_profile)) {
        d2k_plan_free(p);
        fail(err, errlen, "измеренные TCP-операции требуют явного транспорта TCP");
        return -1;
    }

    *out = p;
    return 0;
}

void d2k_plan_free(d2k_plan *p) {
    if (!p) {
        return;
    }
    for (size_t i = 0; i < p->n_payloads; i++) {
        free(p->payloads[i].bytes);
    }
    free(p->payloads);
    free(p->poisons);
    free(p->splits);
    free(p->fakes);
    free(p->seqovls);
    free(p);
}

uint8_t d2k_plan_poison_used(const d2k_plan *p) {
    if (!p) {
        return 0;
    }
    uint8_t used = 0;
    for (size_t i = 0; i < p->n_poisons; i++) {
        used |= p->poisons[i].flags;
    }
    return used;
}

uint8_t d2k_plan_flow_needs(const d2k_plan *p) {
    if (!p) { return 0; }
    uint8_t used = d2k_plan_poison_used(p);
    uint8_t need = 0;
    /* Профиль tcp-template-v1 со сдвигом метки исполним только на потоке,
       предлагающем метку. */
    if (p->wire_profile == D2K_WIRE_TCP_TEMPLATE && (used & D2K_POISON_TCPTS_BACK)) {
        need |= D2K_FLOW_NEED_TCPTS;
    }
    /* MD5+метка несёт РЕАЛЬНУЮ метку потока даже на измеренном профиле
       detect-tcp-v1: без метки у клиента подделать её нечем — поток требует
       метку, и контроллер перемеряет цель для такого клиента (как issue #7). */
    if (used & D2K_POISON_MD5_TS) {
        need |= D2K_FLOW_NEED_TCPTS;
    }
    return need;
}

int d2k_plan_stream_offset(const d2k_plan *p, uint32_t *offset) {
    if(!p || !p->has_stream_offset)return 0;
    if(offset)*offset=p->stream_offset;
    return 1;
}
int d2k_plan_after_split(const d2k_plan *p,uint32_t *offset,uint32_t *length,uint32_t *cut) {
    if(!p || !p->after_length)return 0;
    if(offset)*offset=p->after_offset;
    if(length)*length=p->after_length;
    if(cut)*cut=p->after_cut;
    return 1;
}

int d2k_plan_quic_deny(const d2k_plan *p) {
    return p && p->qdeny;
}

uint8_t d2k_plan_guards(const d2k_plan *p) {
    return p ? p->guards : 0;
}

uint8_t d2k_plan_transport(const d2k_plan *p) {
    return p ? p->transport : 0;
}

uint8_t d2k_plan_proto(const d2k_plan *p) {
    return p ? p->proto : 0;
}

int d2k_plan_stream_input(const d2k_plan *p) {
    return p && p->transport == 6 &&
           (p->wire_profile == D2K_WIRE_DETECT_TCP || p->wire_profile == D2K_WIRE_TCP_TEMPLATE) &&
           (p->input_tls || p->input_len);
}

const uint8_t *d2k_plan_id(const d2k_plan *p) {
    /* Указатель внутрь плана, а не копия: живёт он ровно столько же, сколько
       сам план, а на пакетном пути копировать шестнадцать байт ради возврата
       незачем. План без записи REC_ID отдаёт нули — calloc в d2k_plan_load
       обнулил поле, и «идентификатора нет» выглядит так же, как «его не
       прислали» на той стороне провода (см. d2k_plan.h). */
    return p ? p->id : NULL;
}
