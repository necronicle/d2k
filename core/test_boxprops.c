/* test_boxprops.c — слияние знания о коробке, без сети.
 *
 * ЧТО ЗДЕСЬ ДОКАЗЫВАЕТСЯ. Вектор коробки живёт дольше одного прогона, и
 * каждый следующий замер его ДОПОЛНЯЕТ. Слияние — то место, где знание либо
 * накапливается, либо тихо врёт: неизмеренное не должно стирать измеренное,
 * а ПРОТИВОРЕЧИЕ не должно оставаться записанным как знание. Сеть сменилась,
 * приметы совпали по допуску — и вектор прежней коробки повёл бы подбор по
 * свойствам, которых у новой нет.
 */
#include "d2k_boxprops.h"

#include <stdio.h>
#include <string.h>

static int fails;
#define CHECK(cond, msg)                   \
    do {                                   \
        if (!(cond)) {                     \
            printf("ПРОВАЛ: %s\n", msg);   \
            fails++;                       \
        }                                  \
    } while (0)


static void test_gate_merge(void) {
    d2k_box_props dst = {0}, src = {0}, empty = {0}; char text[512];
    src.response_gate = D2K_PROP_YES; src.gate_carry = D2K_PROP_NO;
    src.gate_hello_own = D2K_PROP_NO; src.gate_window = 11; src.gate_pieces = 567;
    src.gate_rtt_ms = 89;
    CHECK(d2k_box_props_any(&src), "gate knowledge not recognized");
    CHECK(!d2k_box_props_merge(&dst, &src) && dst.gate_carry == D2K_PROP_NO &&
          dst.gate_window == 11 && dst.gate_pieces == 567 && dst.gate_rtt_ms == 89 &&
          dst.response_gate == D2K_PROP_YES && dst.gate_hello_own == D2K_PROP_NO, "gate merge lost knowledge");
    CHECK(!d2k_box_props_merge(&dst, &empty) && dst.gate_carry == D2K_PROP_NO, "unknown erased negative");
    src.gate_carry = D2K_PROP_YES; src.gate_window = 12; src.gate_pieces = 568; src.gate_rtt_ms = 90;
    CHECK(d2k_box_props_merge(&dst, &src) == 4 && !dst.gate_carry && !dst.gate_window &&
          !dst.gate_pieces && !dst.gate_rtt_ms, "gate contradictions retained");
    d2k_box_props_text(&src, text, sizeof text);
    CHECK(strstr(text, "568") && strstr(text, "90") && strstr(text, "12"), "gate numbers missing from journal");
    empty.gate_rtt_ms = 1; CHECK(d2k_box_props_any(&empty), "gate value not recognized");
    d2k_box_props_text(&empty, text, sizeof text);
    CHECK(strstr(text, "RTT") && !strstr(text, "окно") && !strstr(text, "кусков"),
          "unmeasured gate quantities printed as zero knowledge");
    puts("test_gate_merge: checked");
}

int main(void) {
    test_gate_merge();
    {
        /* Неизмеренное НЕ СТИРАЕТ измеренное: прогон, который вопроса не
           задавал, о свойстве ничего не сказал (§2.4). */
        d2k_box_props dst, src;
        memset(&dst, 0, sizeof dst);
        memset(&src, 0, sizeof src);
        dst.validates_checksum = D2K_PROP_NO;
        dst.hops = 58;
        dst.reasm_boundary = 517;
        CHECK(d2k_box_props_merge(&dst, &src) == 0, "молчание src названо противоречием");
        CHECK(dst.validates_checksum == D2K_PROP_NO, "молчание src стёрло признак");
        CHECK(dst.hops == 58 && dst.reasm_boundary == 517, "молчание src стёрло величины");
    }
    {
        /* Новое измеренное записывается. */
        d2k_box_props dst, src;
        memset(&dst, 0, sizeof dst);
        memset(&src, 0, sizeof src);
        src.parses_l7 = D2K_PROP_YES;
        src.hops = 12;
        src.reasm_boundary = 300;
        CHECK(d2k_box_props_merge(&dst, &src) == 0, "первое измерение названо противоречием");
        CHECK(dst.parses_l7 == D2K_PROP_YES, "новый признак не записан");
        CHECK(dst.hops == 12 && dst.reasm_boundary == 300, "новые величины не записаны");
    }
    {
        /* ПРОТИВОРЕЧИЕ СБРАСЫВАЕТ ПОЛЕ В «НЕ ИЗМЕРЕНО», а не оставляет
           прежнее и не берёт новое: два замера разошлись, и знания о поле
           больше нет. Оставить «да» значило бы подбирать по свойству,
           которого сеть сейчас не показывает; взять «нет» — поверить
           одному прогону против другого. */
        d2k_box_props dst, src;
        memset(&dst, 0, sizeof dst);
        memset(&src, 0, sizeof src);
        dst.tolerates_reorder = D2K_PROP_YES;
        src.tolerates_reorder = D2K_PROP_NO;
        CHECK(d2k_box_props_merge(&dst, &src) == 1, "противоречие не посчитано");
        CHECK(dst.tolerates_reorder == D2K_PROP_UNKNOWN,
              "противоречащее свойство осталось знанием");
    }
    {
        /* Согласие — не противоречие, и поле остаётся знанием. */
        d2k_box_props dst, src;
        memset(&dst, 0, sizeof dst);
        memset(&src, 0, sizeof src);
        dst.counts_duplicates = D2K_PROP_YES;
        src.counts_duplicates = D2K_PROP_YES;
        CHECK(d2k_box_props_merge(&dst, &src) == 0, "согласие названо противоречием");
        CHECK(dst.counts_duplicates == D2K_PROP_YES, "согласие стёрло знание");
    }
    {
        /* РАСХОЖДЕНИЕ ВЕЛИЧИН — ТОЖЕ ПРОТИВОРЕЧИЕ. Расстояние до коробки и
           порог пересборки измеряются числом, и другое число означает другую
           коробку на пути либо сменившийся маршрут. Среднее тут запрещено:
           план по среднему не исполнится ни в одном из двух случаев. */
        d2k_box_props dst, src;
        memset(&dst, 0, sizeof dst);
        memset(&src, 0, sizeof src);
        dst.hops = 58;
        src.hops = 12;
        CHECK(d2k_box_props_merge(&dst, &src) == 1, "расхождение величин не посчитано");
        CHECK(dst.hops == 0, "расхождение величин усреднено или оставлено");
    }
    {
        /* Форма клиента — КЛЮЧ записи, а не измеренное свойство: слияние её
           не трогает, и векторы разных форм не сливаются вовсе (их держат
           отдельными записями каталога). */
        d2k_box_props dst, src;
        memset(&dst, 0, sizeof dst);
        memset(&src, 0, sizeof src);
        dst.client_shape = 3;
        src.client_shape = 6;
        d2k_box_props_merge(&dst, &src);
        CHECK(dst.client_shape == 3, "слияние подменило форму клиента");
    }
    {
        /* Текст вектора читается человеком и называет ТОЛЬКО измеренное. */
        d2k_box_props p;
        char buf[256];
        memset(&p, 0, sizeof p);
        p.validates_checksum = D2K_PROP_NO;
        p.hops = 58;
        CHECK(d2k_box_props_text(&p, buf, sizeof buf) > 0, "текст вектора пуст");
        CHECK(strstr(buf, "сумма") != NULL, "измеренный признак не назван");
        CHECK(strstr(buf, "58") != NULL, "измеренная величина не названа");
        CHECK(strstr(buf, "порядок") == NULL, "неизмеренное названо знанием");
        memset(&p, 0, sizeof p);
        CHECK(d2k_box_props_text(&p, buf, sizeof buf) == 0 && buf[0] == '\0',
              "пустой вектор дал текст");
        /* Короткий буфер не переполняется и остаётся строкой. */
        memset(&p, 0, sizeof p);
        p.validates_checksum = D2K_PROP_NO;
        p.parses_l7 = D2K_PROP_YES;
        p.hops = 58;
        {
            char tiny[12];
            size_t n = d2k_box_props_text(&p, tiny, sizeof tiny);
            CHECK(n < sizeof tiny && tiny[n] == '\0', "короткий буфер переполнен");
        }
    }
    {
        /* «Измерено ли хоть что-нибудь»: пустая запись в каталоге означала бы
           «измеряли и не нашли», а это не «не измеряли». Форма клиента — ключ
           записи, а не знание, и сама по себе её не заводит. */
        d2k_box_props p;
        memset(&p, 0, sizeof p);
        CHECK(d2k_box_props_any(&p) == 0, "пустой вектор назван измеренным");
        p.client_shape = 3;
        CHECK(d2k_box_props_any(&p) == 0, "форма клиента посчитана знанием");
        p.reasm_boundary = 517;
        CHECK(d2k_box_props_any(&p) == 1, "измеренная величина не посчитана знанием");
        memset(&p, 0, sizeof p);
        p.inspects_syn = D2K_PROP_NO;
        CHECK(d2k_box_props_any(&p) == 1, "измеренный признак не посчитан знанием");
    }
    if (fails) { printf("ПРОВАЛОВ: %d\n", fails); return 1; }
    printf("вектор свойств: все проверки прошли\n");
    return 0;
}
