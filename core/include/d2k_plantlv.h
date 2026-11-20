/* d2k_plantlv.h — человеческий текст плана в байты провода.
 *
 * d2k_compose выдаёт план ТЕКСТОМ (он же лежит в catalog.json и его же
 * показывает панель), а датапат принимает ТОЛЬКО байты TLV. Этот модуль —
 * единственный мост между ними на C-стороне; на Go-стороне ту же работу
 * делают internal/plan ParseText и MarshalTLV, и они здесь эталон.
 *
 * Текст — ЕДИНСТВЕННЫЙ источник: что записано в каталоге, то и едет на провод.
 * Второй сборщик TLV рядом с текстовым (соблазн научить d2k_compose выдавать
 * сразу обе формы) завёл бы две формы одного плана, и первое же расхождение
 * между ними означало бы, что записано одно, а исполняется другое — §2.5
 * запрещает ровно это.
 *
 * Неизвестная директива — ОТКАЗ с причиной, а не пропуск строки. */
#ifndef D2K_PLANTLV_H
#define D2K_PLANTLV_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

/* Потолок одного плана в байтах. Кадр управляющего сокета — 65536
 * (D2K_CTL_FRAME_MAX, datapath/include/d2k_ctl.h), и план в нём самое
 * большое, что ездит; под имя цели и заголовок команды оставлен запас. */
#define D2K_PLAN_TLV_MAX 65000

/* 0 — переведено, *out_len заполнено. -1 — отказ, причина в err (заполняется
 * ВСЕГДА и по-человечески: «не разобралось» без объяснения нечитаемо тому,
 * кто будет чинить). */
int d2k_plan_text_to_tlv(const char *text, uint8_t *out, size_t cap,
                         size_t *out_len, char *err, size_t errcap);
/* 1: IPv4 TCP endpoint-bound program, 0: ordinary plan, -1: invalid. */
int d2k_plan_text_requires_endpoint(const char *,char *,size_t);
/* Validated metadata from the same parser: 1 scoped, 0 unscoped, -1 invalid. */
int d2k_plan_text_stream_offset(const char *,uint32_t *,char *,size_t);
int d2k_plan_text_after_split(const char *,uint32_t *,uint32_t *,uint32_t *,char *,size_t);
/* Preserve first-input operations and append a measured later partition.
 * Allocates *out; never replaces an existing scoped/composed operation. */
int d2k_plan_text_compose_after_split(const char *,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,
    char **,char *,size_t);
/* Compose two explicitly selected programs. Allocates *out, remaps only
 * the preflight hello payload reference; conveys no application proof. */
int d2k_plan_text_compose_preflight(const char *,const char *,char **,char *,size_t);

/* То же, но сразу в hex — в том виде, в каком план принимает
 * d2k_link_set_name (d2k_link.h). out обязан быть не короче 2*N+1, где N —
 * длина TLV; для плана предельного размера это 2*D2K_PLAN_TLV_MAX+1. */
int d2k_plan_text_to_hex(const char *text, char *out, size_t cap,
                         char *err, size_t errcap);

#endif /* D2K_PLANTLV_H */
