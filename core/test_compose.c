/* test_compose.c — проверки свойств коробки и вывода плана для TCP.
 *
 * Без стенда: d2k_compose — чистая сборка текста (вход — вектор свойств,
 * выход — строки), сети не касается вовсе; d2k_props_ask по устройству этой
 * реализации тоже сети не касается (см. большой комментарий в шапке
 * compose.c про то, почему) — соответствующий блок проверок это и
 * закрепляет, не поднимая ни одного сокета.
 *
 * РАСХОЖДЕНИЯ С БРИФОМ ЗАДАЧИ, НАЙДЕННЫЕ ПРИ ЧТЕНИИ properties.go.
 *
 * Бриф задачи (task-3-brief.md, шаг 1) ожидал 0 планов от вектора, в котором
 * ни одно свойство не встало в NO/YES ("да и только да, если требуется") —
 * ТРИ его примера построены ровно на этом: полностью нулевой вектор,
 * ToleratesLeftOverlap=YES при остальном неизмеренном, и
 * ValidatesChecksum=UNKNOWN на нулевом векторе. Но Go Compose
 * (properties.go:214-221) в точности для этого случая — «ни один вопрос
 * ничего не подтвердил» — добавляет everythingPlan: `if len(out) == 0 { add
 * (everythingPlan(decoy)) }`. Комментарий рядом называет его «единственным
 * честным кандидатом», а не отсутствием кандидата. Все три сценария ниже
 * проверяют ИСПРАВЛЕННОЕ ожидание — ровно 1 план (everythingPlan), а не 0 — и
 * это подтверждено и в отчёте задачи.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "d2k_compose.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

/* Подстрока, которая может встретиться ТОЛЬКО в checksum_plan_text: 64 байта
 * набивки 0x41 гарантируют длинный повтор "41", которого в decoy-приветствии
 * (LEGACY-профиль настоящего захвата) нет ни разу (проверено по исходнику
 * profiles/legacy.hex) — так отличаем "это план про сумму" от "это план про
 * разбор протокола/дубликаты", у которых тот же скелет (poison+fake), но
 * другая приманка. */
static const char CHECKSUM_FILLER_MARK[] = "4141414141414141";

int main(void) {
    const char *decoy = "disk.rzd.ru";
    char out[8][2048];

    /* --- пустой вектор: НЕ "плечей нет", а единственный честный кандидат --
     *
     * См. большой комментарий в шапке файла про расхождение с брифом. */
    {
        d2k_props pr = {0};
        size_t n = d2k_compose(&pr, decoy, out, 8);
        CHECK(n == 1, "полностью неизмеренный вектор обязан дать ровно один "
                       "запасной план (everythingPlan), а не ноль и не больше");
        CHECK(strstr(out[0], "seqovl") != NULL, "запасной план без перекрытия");
        CHECK(strstr(out[0], "split payload_start +1") != NULL,
              "запасной план без разреза payload_start+1");
        CHECK(strstr(out[0], "split sni_middle +0") != NULL,
              "запасной план без разреза по имени");
        CHECK(strstr(out[0], "order reverse") != NULL, "запасной план без обратного порядка");
        CHECK(strstr(out[0], "poison 1 badsum") != NULL, "запасной план без порчи суммы");
        CHECK(strstr(out[0], "fake payload=1 poison=1 repeats=2 gap_us=20000") != NULL,
              "запасной план без пары дублей с разрывом 20000мкс");
        CHECK(strstr(out[0], "payload 2 41") != NULL, "запасной план без приставки перекрытия");
    }

    /* --- перекрытие выводится только из своего свойства -------------------- */
    {
        d2k_props pr = {0};
        pr.tolerates_left_overlap = D2K_P_NO;
        size_t n = d2k_compose(&pr, decoy, out, 8);
        CHECK(n == 1, "ожидалось ровно одно плечо");
        CHECK(strstr(out[0], "seqovl") != NULL, "плечо перекрытия не собрано");
        CHECK(strstr(out[0], "payload 1 41") != NULL, "приставка перекрытия не та");

        /* Коробка ДЕРЖИТ перекрытие (YES) — из ЭТОГО конкретного свойства
           план больше не выводится, но вектор всё равно ПОЛНОСТЬЮ пуст по
           остальным четырём полям, и это снова случай everythingPlan (см.
           первый блок), а не "ничего". Расхождение с брифом — то же самое:
           его пример здесь ожидал 0. */
        pr.tolerates_left_overlap = D2K_P_YES;
        n = d2k_compose(&pr, decoy, out, 8);
        CHECK(n == 1, "коробка держит перекрытие: свой план не должен выводиться, "
                       "но вектор пуст и обязан дать everythingPlan, а не 0 и не 2");
        CHECK(strstr(out[0], "seqovl") != NULL && strstr(out[0], "order reverse") != NULL,
              "при YES-перекрытии на пустом остальном векторе вышел не запасной план");
    }

    /* --- порядок режет ПО ИМЕНИ, а не по середине приветствия -------------- */
    {
        d2k_props pr = {0};
        pr.tolerates_reorder = D2K_P_NO;
        size_t n = d2k_compose(&pr, decoy, out, 8);
        CHECK(n == 1, "ожидалось ровно одно плечо");
        CHECK(strstr(out[0], "sni_middle") != NULL,
              "рез не по имени: замер донора 07.09 показал, что середина приветствия не работает");
        CHECK(strstr(out[0], "hello_middle") == NULL,
              "вернулся рез по середине приветствия — забракованная замером форма");
        CHECK(strstr(out[0], "order reverse") != NULL, "куски не переставлены");
    }

    /* --- «не измерено» не равно «нет»: неизмеренная сумма ------------------
     *
     * Брифовый пример проверял это на ПОЛНОСТЬЮ нулевом векторе и ждал 0 —
     * тот же случай everythingPlan, что и выше. Здесь та же мысль проверена
     * там, где двусмысленности с запасным планом нет: вектор НЕ пуст
     * (overlap=NO уже даёт один план), поэтому если бы UNKNOWN-сумма ошибочно
     * трактовалась как NO, checksum-план добавился бы ВТОРЫМ и count стал бы
     * 2, а не 1. */
    {
        d2k_props pr = {0};
        pr.tolerates_left_overlap = D2K_P_NO;
        pr.validates_checksum = D2K_P_UNKNOWN; /* явно, хоть это и {0} по умолчанию */
        size_t n = d2k_compose(&pr, decoy, out, 8);
        CHECK(n == 1, "неизмеренная сумма всё равно породила своё плечо");
        CHECK(strstr(out[0], CHECKSUM_FILLER_MARK) == NULL,
              "неизмеренное свойство породило checksum-плечо");
    }

    /* --- счёт дубликатов: YES выводит пару с разрывом 20000мкс ------------- */
    {
        d2k_props pr = {0};
        pr.counts_duplicates = D2K_P_YES;
        size_t n = d2k_compose(&pr, decoy, out, 8);
        CHECK(n == 1, "ожидалось ровно одно плечо");
        CHECK(strstr(out[0], "fake payload=1 poison=1 repeats=2 gap_us=20000 place=before") != NULL,
              "план дубликатов: не та форма fake");
        CHECK(strstr(out[0], "poison 1 badsum") != NULL, "план дубликатов без порчи суммы");
        CHECK(strstr(out[0], CHECKSUM_FILLER_MARK) == NULL,
              "план дубликатов использует набивку вопроса о сумме, а не decoy-приветствие");
    }

    /* --- разбор протокола: YES выводит целое приветствие с decoy-именем ---- */
    {
        d2k_props pr = {0};
        pr.parses_l7 = D2K_P_YES;
        size_t n = d2k_compose(&pr, decoy, out, 8);
        CHECK(n == 1, "ожидалось ровно одно плечо");
        CHECK(strstr(out[0], "fake payload=1 poison=1 repeats=1 gap_us=0 place=before") != NULL,
              "план разбора протокола: не та форма fake (repeats/gap перепутаны с дубликатами)");
        CHECK(strstr(out[0], CHECKSUM_FILLER_MARK) == NULL,
              "план разбора протокола использует набивку вопроса о сумме, а не decoy-приветствие");
        /* LEGACY-профиль (210 «живых» байт), а не MODERN (1530 байт): вторая
           дала бы >3000 hex-символов и одна эта проверка стала бы
           бессмысленной, потому что план перестал бы влезать в 2048 байт
           вовсе (см. build_decoy_hello в compose.c). Порог generous: реальная
           длина ~600 байт. */
        CHECK(strlen(out[0]) < 1200,
              "план разбора протокола заметно длиннее LEGACY-приветствия — похоже, "
              "используется MODERN-профиль и он не влезает в буфер плана");
    }

    /* --- сумма выводится только из своего свойства -------------------------
     *
     * NO само по себе, без разбора протокола — план присутствует и это
     * НАБИВКА (64×0x41), а не decoy-приветствие: наличие длинного повтора
     * "41" — единственное, что отличает этот план от плана разбора
     * протокола на том же скелете poison+fake. */
    {
        d2k_props pr = {0};
        pr.validates_checksum = D2K_P_NO;
        size_t n = d2k_compose(&pr, decoy, out, 8);
        CHECK(n == 1, "ожидалось ровно одно плечо");
        CHECK(strstr(out[0], CHECKSUM_FILLER_MARK) != NULL,
              "план суммы не содержит набивку 0x41 — приманка не та");
        CHECK(strstr(out[0], "repeats=1 gap_us=0") != NULL,
              "план суммы: не та форма fake");
        CHECK(strstr(out[0], "split") == NULL, "план суммы не должен резать поток");
        CHECK(strstr(out[0], "seqovl") == NULL, "план суммы не должен перекрывать поток");
    }

    /* --- ловушка донора наоборот: сумма=NO вместе с разбором=YES не даёт
     * ДВУХ планов --------------------------------------------------------
     *
     * properties.go:185-207 — вопрос «разбор протокола» пишет ValidatesChecksum
     * =false ИЗ ТОГО ЖЕ прохода, что и ParsesL7=true (один и тот же факт, не
     * два разных измерения): если бы Compose добавлял оба плеча, второе
     * (checksumPlan, голая набивка) заведомо не проходило бы на коробке, что
     * РАЗБИРАЕТ TLS, — и было бы предложено впереди уже подтверждённого
     * плана. Правило: checksumPlan подавляется, когда ParsesL7=YES стоит
     * рядом. */
    {
        d2k_props pr = {0};
        pr.validates_checksum = D2K_P_NO;
        pr.parses_l7 = D2K_P_YES;
        size_t n = d2k_compose(&pr, decoy, out, 8);
        CHECK(n == 1, "сумма=NO вместе с разбором=YES дала не одно плечо — "
                       "ловушка донора наоборот не подавлена");
        CHECK(strstr(out[0], CHECKSUM_FILLER_MARK) == NULL,
              "вышел план про сумму, а не про разбор протокола — правило подавления не сработало");
    }

    /* --- несколько свойств сразу: порядок и отсутствие взаимного стирания -- */
    {
        d2k_props pr = {0};
        pr.tolerates_left_overlap = D2K_P_NO;
        pr.counts_duplicates = D2K_P_YES;
        size_t n = d2k_compose(&pr, decoy, out, 8);
        CHECK(n == 2, "два независимых свойства обязаны дать два плеча");
        CHECK(strstr(out[0], "seqovl") != NULL,
              "порядок плеч расходится с Go Compose: перекрытие обязано идти первым");
        CHECK(strstr(out[1], "fake payload=1 poison=1 repeats=2 gap_us=20000") != NULL,
              "порядок плеч расходится с Go Compose: дубликаты обязаны идти вторыми");
    }

    /* --- cap ограничивает запись и не переполняет буфер вызывающего -------- */
    {
        d2k_props pr = {0};
        pr.tolerates_left_overlap = D2K_P_NO;
        pr.counts_duplicates = D2K_P_YES; /* без cap дало бы 2 плеча */
        char out1[1][2048];
        size_t n = d2k_compose(&pr, decoy, out1, 1);
        CHECK(n == 1, "cap=1 не ограничил число записанных плеч");
        CHECK(strstr(out1[0], "seqovl") != NULL,
              "при cap=1 записано не первое по порядку плечо");
    }
    {
        d2k_props pr = {0};
        char out0[1][2048];
        size_t n = d2k_compose(&pr, decoy, out0, 0);
        CHECK(n == 0, "cap=0 обязан дать 0 независимо от вектора");
    }

    /* --- decoy не нужен свойствам, которые его не используют --------------- */
    {
        d2k_props pr = {0};
        pr.tolerates_left_overlap = D2K_P_NO;
        size_t n = d2k_compose(&pr, NULL, out, 8);
        CHECK(n == 1, "план перекрытия обязан собираться и без decoy");
    }
    {
        d2k_props pr = {0};
        pr.tolerates_reorder = D2K_P_NO;
        size_t n = d2k_compose(&pr, NULL, out, 8);
        CHECK(n == 1, "план порядка обязан собираться и без decoy — якорь вычисляется датапатом");
    }

    /* --- decoy нужен свойствам, которые его используют: без него плечо
     * пропускается, а не подставляется мусором или пустой строкой ----------- */
    {
        d2k_props pr = {0};
        pr.counts_duplicates = D2K_P_YES;
        size_t n = d2k_compose(&pr, NULL, out, 8);
        CHECK(n == 0, "без decoy план дубликатов обязан быть пропущен, а не выдуман; "
                       "запасной план тоже нуждается в decoy и падает по той же причине");
    }
    {
        d2k_props pr = {0};
        pr.counts_duplicates = D2K_P_YES;
        size_t n = d2k_compose(&pr, "", out, 8);
        CHECK(n == 0, "пустая строка decoy обязана трактоваться как «имени нет», а не как имя");
    }

    /* --- decoy длиннее буфера декой-приветствия: план пропускается, не режется
     * усечённым и не переполняет буфер (см. build_decoy_hello, compose.c) --- */
    {
        char long_decoy[701];
        memset(long_decoy, 'a', sizeof long_decoy - 1);
        long_decoy[sizeof long_decoy - 1] = '\0';
        d2k_props pr = {0};
        pr.parses_l7 = D2K_P_YES;
        size_t n = d2k_compose(&pr, long_decoy, out, 8);
        CHECK(n == 0, "слишком длинный decoy обязан дать пропуск плеча, а не переполнение/усечение");
    }

    /* --- d2k_props_ask: честно неизмеряющий оракул (см. шапку compose.c) --
     *
     * Пять Go-вопросов проверяются перекрытием/порчей суммы/переупорядоченной
     * отправкой — управлением TCP ниже уровня обычного сокета. Единственный
     * оракул этой задачи, d2k_meas, такого не умеет (честные разрезы по
     * возрастанию — meas.c: cuts_valid, send_all), а протокол связи с
     * датапатом (core/link.c) — параллельная задача 4, недоступная здесь.
     * Значит единственный НЕ подделывающий измерение ответ — вектор из
     * одних D2K_P_UNKNOWN, независимо от входа; проверка не поднимает ни
     * одного сокета и не должна начать это делать незаметно (см. также
     * отчёт задачи 3). */
    {
        uint8_t tb[] = { 0x16, 0x03, 0x01, 0x00, 0xAA, 0xBB };
        uint8_t cb[] = { 0x16, 0x03, 0x01, 0x00, 0xCC, 0xDD };
        d2k_hello trig = { tb, sizeof tb };
        d2k_hello ctl = { cb, sizeof cb };
        d2k_props pr = d2k_props_ask("192.0.2.1", 443, trig, ctl, 0x2d);
        CHECK(pr.tolerates_left_overlap == D2K_P_UNKNOWN, "overlap оказался измеренным без оракула");
        CHECK(pr.tolerates_reorder == D2K_P_UNKNOWN, "reorder оказался измеренным без оракула");
        CHECK(pr.validates_checksum == D2K_P_UNKNOWN, "checksum оказался измеренным без оракула");
        CHECK(pr.parses_l7 == D2K_P_UNKNOWN, "parses_l7 оказался измеренным без оракула");
        CHECK(pr.counts_duplicates == D2K_P_UNKNOWN, "counts_duplicates оказался измеренным без оракула");

        /* Тот же контракт и на пустом/нулевом входе — функция не имеет
           веток, зависящих от аргументов (см. compose.c), но это утверждение
           не должно перестать быть верным незаметно. */
        d2k_hello empty = { NULL, 0 };
        d2k_props pr2 = d2k_props_ask(NULL, 0, empty, empty, 0);
        CHECK(pr2.tolerates_left_overlap == D2K_P_UNKNOWN &&
              pr2.tolerates_reorder == D2K_P_UNKNOWN &&
              pr2.validates_checksum == D2K_P_UNKNOWN &&
              pr2.parses_l7 == D2K_P_UNKNOWN &&
              pr2.counts_duplicates == D2K_P_UNKNOWN,
              "вырожденный вход изменил вектор — ожидались одни D2K_P_UNKNOWN");
    }

    /* --- нулевые/негодные аргументы d2k_compose не падают и не пишут ------- */
    {
        CHECK(d2k_compose(NULL, decoy, out, 8) == 0, "pr==NULL обязан дать 0, а не падение");
    }
    {
        d2k_props pr = {0};
        pr.tolerates_left_overlap = D2K_P_NO; /* иначе было бы просто на пустом векторе */
        CHECK(d2k_compose(&pr, decoy, NULL, 8) == 0, "out==NULL обязан дать 0, а не падение");
    }

    if (fails) { printf("ПРОВАЛОВ: %d\n", fails); return 1; }
    printf("compose: все проверки прошли\n");
    return 0;
}
