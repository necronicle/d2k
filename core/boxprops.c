/* boxprops.c — слияние знания о коробке и его человеческий вид.
 *
 * ЗАЧЕМ ОТДЕЛЬНЫЙ МОДУЛЬ. Вектор живёт дольше одного прогона: его пишет
 * измеритель, хранит каталог, читает планировщик. Правило накопления знания
 * — одно на всех, и повторять его в каждом из трёх мест значило бы
 * разойтись при первой же правке.
 *
 * ГЛАВНОЕ ПРАВИЛО: ПРОТИВОРЕЧИЕ — НЕ ЗНАНИЕ. Два замера разошлись по полю —
 * поле становится неизмеренным (§2.4), а не берёт новое значение и не
 * оставляет прежнее. Оставить прежнее значило бы подбирать по свойству,
 * которого сеть сейчас не показывает (каталог переживает смену оператора и
 * маршрута, а приметы узнавания совпадают по допуску). Взять новое значило бы
 * поверить одному прогону против другого без причины предпочесть именно его.
 * Число противоречий возвращается наружу: это повод перемерить коробку, а не
 * тихая правка файла.
 *
 * ВЕЛИЧИНЫ НЕ УСРЕДНЯЮТСЯ. Расстояние до коробки и порог пересборки — числа,
 * и другое число означает другую коробку на пути либо сменившийся маршрут.
 * План по среднему не исполнится ни в одном из двух случаев: фальшивка с
 * усреднённым TTL либо не дойдёт до коробки, либо дойдёт до сервера.
 *
 * ФОРМА КЛИЕНТА — КЛЮЧ, А НЕ СВОЙСТВО. Слияние её не касается: векторы разных
 * форм клиента не сливаются вовсе, их держат отдельными записями каталога
 * (d2k_catalog.h, d2k_cat_props). */
#include "d2k_boxprops.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* Таблица вместо одиннадцати повторов: поля-признаки обрабатываются одним
 * правилом, и правило видно один раз. Ярлык — для журнала; он же называет
 * поле человеку, когда замер разошёлся с записанным. */
typedef struct { size_t off; const char *label; } tri_field;

static const tri_field g_tri[] = {
    { offsetof(d2k_box_props, reassembles),            "пересборка" },
    { offsetof(d2k_box_props, parses_l7),              "разбор TLS" },
    { offsetof(d2k_box_props, validates_checksum),     "сумма" },
    { offsetof(d2k_box_props, tolerates_reorder),      "порядок" },
    { offsetof(d2k_box_props, tolerates_left_overlap), "перекрытие слева" },
    { offsetof(d2k_box_props, counts_duplicates),      "дубликаты" },
    { offsetof(d2k_box_props, inspects_syn),           "данные в SYN" },
    { offsetof(d2k_box_props, validates_md5),          "MD5" },
    { offsetof(d2k_box_props, validates_seq_window),   "окно seq" },
    { offsetof(d2k_box_props, validates_timestamps),   "метка времени" },
    { offsetof(d2k_box_props, overlap_covers_sni),     "перекрытие до имени" },
    { offsetof(d2k_box_props, handles_urgent),         "срочный байт" },
    { offsetof(d2k_box_props, response_gate),          "блок ответа" },
    { offsetof(d2k_box_props, gate_carry),             "перенос через RST" },
    { offsetof(d2k_box_props, gate_hello_own),         "своё приветствие" },
};
#define TRI_N (sizeof g_tri / sizeof g_tri[0])

static int8_t *tri_at(d2k_box_props *p, size_t off) {
    return (int8_t *)((char *)p + off);
}
static int8_t tri_get(const d2k_box_props *p, size_t off) {
    return *(const int8_t *)((const char *)p + off);
}

/* Одно поле-величина: ноль в src молчит, равенство согласно, разное —
 * противоречие, после которого величины нет. */
static int merge_value(int32_t *dst, int32_t src) {
    if (src <= 0) { return 0; }
    if (*dst <= 0) { *dst = src; return 0; }
    if (*dst == src) { return 0; }
    *dst = 0;
    return 1;
}

static int merge_u32(uint32_t *dst, uint32_t src) {
    if (!src) { return 0; }
    if (!*dst) { *dst = src; return 0; }
    if (*dst == src) { return 0; }
    *dst = 0;
    return 1;
}

int d2k_box_props_merge(d2k_box_props *dst, const d2k_box_props *src) {
    size_t i;
    int conflicts = 0;
    if (!dst || !src) { return 0; }
    for (i = 0; i < TRI_N; i++) {
        int8_t *d = tri_at(dst, g_tri[i].off);
        int8_t s = tri_get(src, g_tri[i].off);
        if (s == D2K_PROP_UNKNOWN) { continue; }      /* прогон не спрашивал */
        if (*d == D2K_PROP_UNKNOWN) { *d = s; continue; } /* первое измерение */
        if (*d == s) { continue; }                     /* согласие */
        *d = D2K_PROP_UNKNOWN;
        conflicts++;
    }
    conflicts += merge_value(&dst->hops, src->hops);
    conflicts += merge_value(&dst->reasm_boundary, src->reasm_boundary);
    uint32_t window = dst->gate_window;
    conflicts += merge_u32(&window, src->gate_window);
    dst->gate_window = (uint16_t)window;
    conflicts += merge_u32(&dst->gate_pieces, src->gate_pieces);
    conflicts += merge_u32(&dst->gate_rtt_ms, src->gate_rtt_ms);
    return conflicts;
}

int d2k_box_props_any(const d2k_box_props *p) {
    size_t i;
    if (!p) { return 0; }
    for (i = 0; i < TRI_N; i++) {
        int8_t v = tri_get(p, g_tri[i].off);
        if (v == D2K_PROP_YES || v == D2K_PROP_NO) { return 1; }
    }
    return p->hops > 0 || p->reasm_boundary > 0 || p->gate_window || p->gate_pieces || p->gate_rtt_ms;
}

/* Дописывает строку, не переполняя буфер и не разрывая символ UTF-8
 * посередине: обрезка по байтам на кириллице — давняя ловушка этого проекта
 * (r-73.1), и журнал с битым символом читается как поломка кодировки. */
static size_t app(char *buf, size_t cap, size_t pos, const char *s) {
    while (*s && pos + 1 < cap) { buf[pos++] = *s++; }
    if (*s) {
        while (pos > 0 && ((unsigned char)buf[pos - 1] & 0xC0) == 0x80) { pos--; }
        if (pos > 0 && ((unsigned char)buf[pos - 1] & 0x80)) { pos--; }
    }
    buf[pos] = '\0';
    return pos;
}

size_t d2k_box_props_text(const d2k_box_props *p, char *buf, size_t cap) {
    size_t i, pos = 0;
    if (!buf || cap == 0) { return 0; }
    buf[0] = '\0';
    if (!p) { return 0; }
    for (i = 0; i < TRI_N; i++) {
        int8_t v = tri_get(p, g_tri[i].off);
        if (v != D2K_PROP_YES && v != D2K_PROP_NO) { continue; } /* не измерено — не называем */
        if (pos) { pos = app(buf, cap, pos, ", "); }
        pos = app(buf, cap, pos, g_tri[i].label);
        pos = app(buf, cap, pos, v == D2K_PROP_YES ? "=да" : "=нет");
    }
    if (p->hops > 0) {
        char n[32];
        snprintf(n, sizeof n, "хопов %d", p->hops);
        if (pos) { pos = app(buf, cap, pos, ", "); }
        pos = app(buf, cap, pos, n);
    }
    if (p->reasm_boundary > 0) {
        char n[32];
        snprintf(n, sizeof n, "порог %d", p->reasm_boundary);
        if (pos) { pos = app(buf, cap, pos, ", "); }
        pos = app(buf, cap, pos, n);
    }
    const uint32_t values[] = {p->gate_window, p->gate_pieces, p->gate_rtt_ms};
    const char *labels[] = {"окно", "кусков", "RTT мс"};
    for (i = 0; i < sizeof values / sizeof values[0]; i++) {
        if (!values[i]) { continue; }
        char n[48];
        snprintf(n, sizeof n, "%s %u", labels[i], (unsigned)values[i]);
        if (pos) { pos = app(buf, cap, pos, ", "); }
        pos = app(buf, cap, pos, n);
    }
    return pos;
}
