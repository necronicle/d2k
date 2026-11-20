/* poison.c — гипотезы отравления и перевод находки в строку стратегии.
 *
 * Перенос internal/classify/classify.go эталона (poisons, strategyForPoison,
 * strategyFor, notePropsHit, notePropsMiss) — дословный, включая ПОРЯДОК.
 * Порядок здесь не косметика: неудачный зонд ждёт весь таймаут, удачный
 * отвечает мгновенно и обрывает перебор, поэтому первыми идут гипотезы,
 * которые уже брали живые коробки.
 */
#include "d2k_detect.h"
#include "d2k_arm.h"

#include <stdarg.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

int d2k_poison_supports_family(const d2k_poison *p, uint8_t family)
{
    /* IPv6 has no IPv4 Identification field. Do not measure an impossible
       wire hypothesis and record its local construction error as a block. */
    return p && (family == 4 || (family == 6 && !p->ip_id_zero));
}

int d2k_poison_has_fake(const d2k_poison *p)
{
    /* synData и oob фальшивки не несут вовсе, fakeBetween ставит её сам и в
     * другом месте — общий путь отправки для них не годится. */
    if (p->syn_data || p->oob || p->fake_between) {
        return 0;
    }
    /* Метка времени со сдвигом назад — тоже подделка: сервер отбросит её по
     * PAWS (§0.1, поле 07.10.2026 — вопрос «метка времени» без неё слал
     * обычное приветствие, и «проход» был ложным). */
    /* TTL по измеренному пути — такая же подделка, как заданный ttl: сервер
     * её не увидит, потому что пакет умрёт по дороге. Без этого плечо с одним
     * autottl не получало даже одной копии фальшивки, и план не собирался
     * (поймано test_probe_plan на 12 входах). */
    return p->badsum || p->md5 || p->md5_ts || p->ttl > 0 || p->autottl ||
           p->seq_shift != 0 || p->tcp_ts;
}

#define POISON_CAP 128
static d2k_poison g_poisons[POISON_CAP];
static int g_npoisons;
static pthread_once_t g_poisons_once = PTHREAD_ONCE_INIT;

static d2k_poison *add(const char *fmt, ...)
{
    va_list ap;
    d2k_poison *p;
    if (g_npoisons >= POISON_CAP) {
        return &g_poisons[POISON_CAP - 1];
    }
    p = &g_poisons[g_npoisons++];
    memset(p, 0, sizeof(*p));
    va_start(ap, fmt);
    vsnprintf(p->name, sizeof(p->name), fmt, ap);
    va_end(ap);
    return p;
}

int d2k_poison_same(const d2k_poison *x, const d2k_poison *y)
{
    d2k_poison a = *x, b = *y;
    memset(a.name, 0, sizeof a.name);
    memset(b.name, 0, sizeof b.name);
    if (a.repeats <= 1) { a.repeats = 1; }
    if (b.repeats <= 1) { b.repeats = 1; }
    return memcmp(&a, &b, sizeof a) == 0;
}

/* Та же гипотеза по всем параметрам, кроме имени, уже есть в списке. */
static int already_listed(const d2k_poison *p)
{
    int k;
    for (k = 0; k < g_npoisons; k++) {
        const d2k_poison *q = &g_poisons[k];
        if (q == p) { continue; }
        if (d2k_poison_same(q, p)) { return 1; }
    }
    return 0;
}

static void init_poisons(void)
{
    static const int rr[3] = {7, 4, 2};
    static const int ov3[3] = {1, 336, 681};
    static const int ovn[7] = {2, 4, 8, 16, 64, 336, 681};
    static const int gaps[4] = {0, 20, 80, 300};
    static const int reps[4] = {2, 3, 4, 7};
    d2k_poison *p;
    int i, j;

    /* ПОРЯДОК — ЭТО СТОИМОСТЬ. Перекрытие в один байт (facebook), разнесённые
     * дубликаты (YouTube, googlevideo) и плотная семёрка — первыми. */
    p = add("seqovl-1");           p->seqovl = 1;
    p = add("badsum-x2-g20");      p->badsum = 1; p->repeats = 2; p->gap_ms = 20;
    p = add("badsum-x2-g80");      p->badsum = 1; p->repeats = 2; p->gap_ms = 80;
    p = add("badsum-x7");          p->badsum = 1; p->repeats = 7;
    p = add("disorder");           p->disorder = 1;
    p = add("disorder-pos2");      p->disorder = 1; p->disorder_pos = 2;
    p = add("badsum");             p->badsum = 1;
    p = add("md5");                p->md5 = 1;
    p = add("seq-out-of-window");  p->seq_shift = -66000;

    /* ПРИМИТИВЫ, КОТОРЫХ НЕ БЫЛО: самостоятельные механизмы, а не варианты
     * уже покрытых. Флаги обязаны стоять — без них это пустые гипотезы с
     * говорящими именами. */
    p = add("syndata");            p->syn_data = 1;
    p = add("oob");                p->oob = 1;

    /* ОДИН вариант fakedsplit, а не четыре: отправитель в ветке fakeBetween
     * не читает ни seqovl, ни disorder, и варианты были побайтно теми же
     * пакетами. */
    p = add("fakedsplit");         p->fake_between = 1; p->badsum = 1;
    p = add("fakedsplit-x7");      p->fake_between = 1; p->badsum = 1; p->repeats = 7;

    /* ТОЧНАЯ КОПИЯ БОЕВОГО ПЛЕЧА 1: копии фальшивки отдельной посылкой, затем
     * перекрытие слева длиной в целое приветствие. Собрано по дампу. */
    for (i = 0; i < 3; i++) {
        p = add("fake-x%d+seqovl-hello", rr[i]);
        p->badsum = 1; p->repeats = rr[i]; p->seqovl_exact = 1; p->decoy_hello = 1;
        p = add("fake-x%d+seqovl-681", rr[i]);
        p->badsum = 1; p->repeats = rr[i]; p->seqovl = 681; p->decoy_hello = 1;
        p = add("fake-x%d+ttl62+seqovl-hello", rr[i]);
        p->badsum = 1; p->ttl = 62; p->repeats = rr[i]; p->seqovl_exact = 1; p->decoy_hello = 1;
    }

    p = add("seqovl-hello");                    p->seqovl_exact = 1; p->decoy_hello = 1;
    p = add("seqovl-hello+disorder");           p->seqovl_exact = 1; p->decoy_hello = 1; p->disorder = 1;
    p = add("seqovl-hello+disorder+badsum");    p->seqovl_exact = 1; p->decoy_hello = 1; p->disorder = 1; p->badsum = 1;

    /* ТРОЙНЫЕ СВЯЗКИ: фальшивка + перекрытие + сбитый порядок одновременно. */
    for (i = 0; i < 3; i++) {
        p = add("seqovl-%d+disorder", ov3[i]);        p->seqovl = ov3[i]; p->disorder = 1;
        p = add("seqovl-%d+disorder+hello", ov3[i]);  p->seqovl = ov3[i]; p->disorder = 1; p->decoy_hello = 1;
        p = add("seqovl-%d+disorder+badsum", ov3[i]); p->seqovl = ov3[i]; p->disorder = 1; p->badsum = 1;
    }

    for (i = 0; i < 7; i++) {
        p = add("seqovl-%d", ovn[i]);        p->seqovl = ovn[i];
        p = add("seqovl-%d+hello", ovn[i]);  p->seqovl = ovn[i]; p->decoy_hello = 1;
    }

    /* Дубликаты: число копий × пауза. Обе оси нужны — порог 7 оказался
     * артефактом нулевой паузы, при 20 мс хватает двух. */
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            p = add("badsum-x%d-g%d", reps[j], gaps[i]);
            p->badsum = 1; p->repeats = reps[j]; p->gap_ms = gaps[i];
            /* УЖЕ СПРОШЕНО ВЫШЕ (задача 49): badsum-x2-g20, badsum-x2-g80 и
             * badsum-x7 (= x7-g0) стоят в голове списка, где им и место по
             * цене. У донора они спрашивались второй раз — при единогласии
             * исход повтора тот же, это три лишних зонда. Решение владельца
             * 03.10: трассу донора здесь не повторяем. */
            if (already_listed(p)) { g_npoisons--; }
        }
    }

    /* ГИПОТЕЗ TTL ЗДЕСЬ БОЛЬШЕ НЕТ (23.10.2026). Их было девятнадцать:
     * ttl-62…ttl-8, badsum+ttl-62…badsum+ttl-8 и три disorder+badsum+ttl-N,
     * со значениями из чужого поля. Расстояние до коробки — её собственное
     * свойство, и теперь оно ИЗМЕРЯЕТСЯ делением отрезка прохода фальшивки
     * (d2k_hop_search, detect/props.c): опрос задаёт этот вопрос последним по
     * цене, находит само число и отдаёт готовую гипотезу с ним. Число ложится
     * в запись коробки, и следующей её цели зондов не стоит вовсе.
     *
     * ЧТО УШЛО ВМЕСТЕ С НИМИ: связки badsum+ttl и disorder+badsum+ttl. Их
     * смысл был в запасе на случай, когда TTL угадан неточно, — при
     * измеренном расстоянии запас не нужен, а нужную добавку (битую сумму,
     * сбитый порядок) теперь даёт вектор свойств через d2k_compose_from_props,
     * который видит и расстояние, и сверяет ли коробка сумму. */

    p = add("disorder+badsum");        p->disorder = 1; p->badsum = 1;
    p = add("disorder+badsum+hello");  p->disorder = 1; p->badsum = 1; p->decoy_hello = 1;

    p = add("badsum+ts");    p->badsum = 1; p->tcp_ts = 1;
    p = add("badsum+ipid");  p->badsum = 1; p->ip_id_zero = 1;
    p = add("badsum+hello"); p->badsum = 1; p->decoy_hello = 1;

    /* A distinct measured hypothesis after the existing questions fail.
       Its timestamp comes from the negotiated connection, not a fixed TS. */
    p = add("md5ts"); p->md5_ts = 1;

}

const d2k_poison *d2k_poisons(int *n)
{
    /* Publish only a complete immutable list. An in-progress count is not
     * an initialization flag when several scheduler workers enter here. */
    pthread_once(&g_poisons_once, init_poisons);
    *n = g_npoisons;
    return g_poisons;
}

/* notePropsHit/notePropsMiss переводят исход зонда в свойство коробки.
 * Именно здесь перебор перестаёт быть перебором: каждая попытка что-то
 * РАССКАЗЫВАЕТ о коробке, даже когда не срабатывает. */
void d2k_note_props_hit(d2k_dprops *pr, const d2k_poison *p)
{
    if (p->badsum) {
        pr->validates_checksum = D2K_TRI_FALSE; /* съела битую сумму */
    } else if (p->ttl > 0) {
        pr->hop_ttl = p->ttl;
    } else if (p->disorder) {
        pr->tolerates_reorder = D2K_TRI_FALSE;
    } else if (p->seqovl > 0) {
        pr->tolerates_left_overlap = D2K_TRI_FALSE;
    }
    if (p->decoy_hello) {
        pr->parses_l7 = D2K_TRI_TRUE; /* набивку не взяла, приветствие взяла */
    }
}

/* Промах доказывает немного. Сюда попадают только выводы, где он однозначен:
 * приём НЕ ломает коробку, значит она к нему терпима.
 *
 * ЧЕГО ЗДЕСЬ НЕТ: промах badsum-зонда НЕ пишет ValidatesChecksum = true. Это
 * вывод из тишины, запрещённый нормой пакета, и тот же исход в hit даёт
 * false — один прогон мог выдать оба вывода. */
void d2k_note_props_miss(d2k_dprops *pr, const d2k_poison *p)
{
    if (p->disorder) {
        pr->tolerates_reorder = D2K_TRI_TRUE;
    } else if (p->seqovl > 0 && !p->decoy_hello) {
        pr->tolerates_left_overlap = D2K_TRI_TRUE;
    }
}

/* strategyForPoison переводит найденную разницу в термины nfqws2. */
void d2k_strategy_for_poison(const d2k_poison *p, char *out, size_t cap)
{
    char head[512];
    char f[512];
    char ov[512];
    char st[768];

    out[0] = '\0';

    if (p->syn_data) {
        snprintf(out, cap, "--lua-desync=syndata:payload=tls_client_hello:dir=out");
        return;
    }
    if (p->oob) {
        snprintf(out, cap, "--lua-desync=multisplit:payload=tls_client_hello:dir=out:pos=1:oob");
        return;
    }
    if (p->fake_between) {
        snprintf(st, sizeof(st), "--lua-desync=fakedsplit:payload=tls_client_hello:dir=out:pos=1");
        if (p->badsum) {
            strncat(st, ":badsum", sizeof(st) - strlen(st) - 1);
        }
        if (p->repeats > 1) {
            char t[32];
            snprintf(t, sizeof(t), ":repeats=%d", p->repeats);
            strncat(st, t, sizeof(st) - strlen(st) - 1);
        }
        snprintf(out, cap, "%s", st);
        return;
    }
    if (d2k_poison_has_fake(p) && (p->seqovl > 0 || p->seqovl_exact)) {
        char t[64];
        snprintf(f, sizeof(f),
                 "--lua-desync=fake:payload=tls_client_hello:dir=out:blob=fake_default_tls"
                 ":tls_mod=rnd,dupsid,sni=www.google.com");
        if (p->badsum) {
            strncat(f, ":badsum", sizeof(f) - strlen(f) - 1);
        }
        if (p->ttl > 0) {
            snprintf(t, sizeof(t), ":ip_ttl=%d", p->ttl);
            strncat(f, t, sizeof(f) - strlen(f) - 1);
        }
        if (p->repeats > 1) {
            snprintf(t, sizeof(t), ":repeats=%d", p->repeats);
            strncat(f, t, sizeof(f) - strlen(f) - 1);
        }
        /* Длину перекрытия печатаем ИЗМЕРЕННУЮ, а не зашитую: seqovl-1 меряет
         * перекрытие в ОДИН байт, и печатать ей 681 значит выдать другой приём. */
        if (p->seqovl_exact) {
            snprintf(ov, sizeof(ov),
                     " --lua-desync=multisplit:payload=tls_client_hello:dir=out:pos=1:seqovl=681"
                     ":seqovl_pattern=tls_clienthello_www_google_com");
        } else {
            snprintf(ov, sizeof(ov),
                     " --lua-desync=multisplit:payload=tls_client_hello:dir=out:pos=1:seqovl=%d",
                     p->seqovl);
            if (p->decoy_hello) {
                strncat(ov, ":seqovl_pattern=tls_clienthello_www_google_com",
                        sizeof(ov) - strlen(ov) - 1);
            }
        }
        if (p->disorder) {
            strncat(ov, " --lua-desync=multidisorder:payload=tls_client_hello:dir=out:pos=1,midsld",
                    sizeof(ov) - strlen(ov) - 1);
        }
        snprintf(out, cap, "%s%s", f, ov);
        return;
    }
    if (p->seqovl_exact) {
        snprintf(st, sizeof(st),
                 "--lua-desync=multisplit:payload=tls_client_hello:dir=out:pos=1:seqovl=681"
                 ":seqovl_pattern=tls_clienthello_www_google_com");
        if (p->disorder) {
            strncat(st, " --lua-desync=multidisorder:payload=tls_client_hello:dir=out:pos=1,midsld",
                    sizeof(st) - strlen(st) - 1);
        }
        snprintf(out, cap, "%s", st);
        return;
    }
    if (p->seqovl > 0 && p->disorder) {
        snprintf(st, sizeof(st),
                 "--lua-desync=multisplit:payload=tls_client_hello:dir=out:pos=1:seqovl=%d",
                 p->seqovl);
        if (p->decoy_hello) {
            strncat(st, ":seqovl_pattern=tls_clienthello_www_google_com",
                    sizeof(st) - strlen(st) - 1);
        }
        strncat(st, " --lua-desync=multidisorder:payload=tls_client_hello:dir=out:pos=1,midsld",
                sizeof(st) - strlen(st) - 1);
        snprintf(out, cap, "%s", st);
        return;
    }
    if (p->disorder_pos > 0) {
        snprintf(out, cap,
                 "--lua-desync=multidisorder:payload=tls_client_hello:dir=out:pos=%d",
                 p->disorder_pos);
        return;
    }
    if (p->disorder) {
        snprintf(st, sizeof(st),
                 "--lua-desync=multidisorder:payload=tls_client_hello:dir=out:pos=1,midsld");
        if (d2k_poison_has_fake(p)) {
            char t[64];
            /* Связка: сперва фальшивка, следом настоящие сегменты вразнобой. */
            snprintf(f, sizeof(f),
                     "--lua-desync=fake:payload=tls_client_hello:dir=out:blob=fake_default_tls");
            if (p->decoy_hello) {
                strncat(f, ":tls_mod=rnd,dupsid,sni=www.google.com", sizeof(f) - strlen(f) - 1);
            }
            if (p->badsum) {
                strncat(f, ":badsum", sizeof(f) - strlen(f) - 1);
            }
            if (p->ttl > 0) {
                snprintf(t, sizeof(t), ":ip_ttl=%d", p->ttl);
                strncat(f, t, sizeof(f) - strlen(f) - 1);
            }
            if (p->repeats > 1) {
                snprintf(t, sizeof(t), ":repeats=%d", p->repeats);
                strncat(f, t, sizeof(f) - strlen(f) - 1);
            }
            snprintf(out, cap, "%s %s", f, st);
            return;
        }
        snprintf(out, cap, "%s", st);
        return;
    }
    if (p->seqovl > 0) {
        snprintf(st, sizeof(st),
                 "--lua-desync=multisplit:payload=tls_client_hello:dir=out:pos=1:seqovl=%d",
                 p->seqovl);
        if (p->decoy_hello) {
            strncat(st, ":seqovl_pattern=tls_clienthello_www_google_com",
                    sizeof(st) - strlen(st) - 1);
        }
        snprintf(out, cap, "%s", st);
        return;
    }

    snprintf(head, sizeof(head),
             "--lua-desync=fake:payload=tls_client_hello:dir=out:blob=fake_default_tls");
    /* Число копий печатается ЗДЕСЬ, до всех ранних возвратов ветки: без этого
     * семнадцать гипотез badsum-x{N}-g{G} выдавали ту же строку, что одиночная
     * badsum, и инструмент отдавал плечо с одной фальшивкой. */
    if (p->repeats > 1) {
        char t[32];
        snprintf(t, sizeof(t), ":repeats=%d", p->repeats);
        strncat(head, t, sizeof(head) - strlen(head) - 1);
    }
    if (p->tcp_ts) {
        strncat(head, ":tcp_ts=-1000", sizeof(head) - strlen(head) - 1);
    }
    if (p->ip_id_zero) {
        strncat(head, ":ip_id=zero", sizeof(head) - strlen(head) - 1);
    }
    if (p->badsum && p->ttl > 0) {
        snprintf(out, cap, "%s:badsum:ip_ttl=%d", head, p->ttl);
        return;
    }
    if (p->decoy_hello) {
        /* Приманкой служит приветствие с чужим именем — ровно то, что даёт
         * tls_mod=sni=... в боевых плечах. */
        strncat(head, ":tls_mod=rnd,dupsid,sni=www.google.com", sizeof(head) - strlen(head) - 1);
    }
    if (p->badsum) {
        snprintf(out, cap, "%s:badsum", head);
    } else if (p->md5_ts) {
        snprintf(out, cap, "%s:tcp_md5:tcp_ts:tcp_md5_first", head);
    } else if (p->md5) {
        snprintf(out, cap, "%s:tcp_md5", head);
    } else if (p->seq_shift != 0) {
        snprintf(out, cap, "%s:tcp_seq=%ld", head, (long)p->seq_shift);
    } else if (p->ttl > 0) {
        snprintf(out, cap, "%s:ip_ttl=%d", head, p->ttl);
    }
}

/* strategyFor — как записать найденное в термины nfqws2. */
void d2k_strategy_for(int pos, char *out, size_t cap)
{
    snprintf(out, cap, "--lua-desync=multisplit:payload=unknown:dir=out:pos=%d", pos);
}

/* Плечо измерителя в термины сборщика планов.
 *
 * Возврат 0 — выразимо, -1 — язык плана этого не знает. Отказ здесь — пробел
 * РЕАЛИЗАЦИИ, а не отрицательное свойство коробки (0007 п.3): воздействие
 * найдено и на замере сработало, просто поставить его мы сегодня не умеем.
 * Подставлять «похожее» нельзя — это был бы план, отличающийся от того, что
 * прошло проверку. */
int d2k_arm_from_poison(const d2k_poison *p, d2k_arm *a, char *why, size_t whycap)
{
    memset(a, 0, sizeof(*a));
    if (p->syn_data) {
        snprintf(why, whycap, "данные в SYN языком плана не выражаются");
        return -1;
    }
    a->oob = p->oob; /* срочный байт выражается планом «oob sni_middle 0f»
                        и исполняется датапатом (поле 10.10.2026, снят отказ);
                        место байта — середина имени, см. d2k_arm_plan_measured. */
    /* The result crosses worker threads by value. Keep its display name
     * in d2k_vres.arm_name, not as a pointer into res.hit/the bridge stack. */
    a->name         = NULL;
    if (p->seq_shift != 0 && p->seq_shift != -66000) {
        snprintf(why, whycap, "сдвиг TCP seq %d не выражается флагом seq_out",
                 (int)p->seq_shift);
        return -1;
    }
    a->badsum       = p->badsum;
    a->md5          = p->md5;
    a->md5_ts       = p->md5_ts;
    a->repeats      = p->repeats > 0 ? (unsigned)p->repeats : 0u;
    /* In the original, TTL/seq-shift alone also send a fake (one by
     * default). The Plan builder needs this explicitly to emit its body. */
    if (a->repeats == 0 && d2k_poison_has_fake(p)) { a->repeats = 1; }
    a->gap_ms       = p->gap_ms > 0 ? (unsigned)p->gap_ms : 0u;
    a->disorder     = p->disorder;
    a->disorder_pos = p->disorder_pos > 0 ? (unsigned)p->disorder_pos : 0u;
    a->between      = p->fake_between;
    a->ttl          = p->ttl > 0 ? (unsigned)p->ttl : 0u;
    a->autottl      = p->autottl;
    a->autottl_delta = p->autottl_delta;
    a->autottl_min  = p->autottl_min > 0 ? (unsigned)p->autottl_min : 0u;
    a->autottl_max  = p->autottl_max > 0 ? (unsigned)p->autottl_max : 0u;
    a->seq_out      = p->seq_shift != 0;
    a->decoy_hello  = p->decoy_hello;
    a->tcpts        = p->tcp_ts;
    /* ПОДЪЁМ МЕТКИ — ОТДЕЛЬНАЯ ОСЬ, А НЕ ДОБАВКА К tcpts.
     *
     * Документация zapret2 (tcp_ts_up) объясняет, зачем он нужен: «linux
     * стабильно отбрасывает пакеты с валидным seq и инвалидным ack ТОЛЬКО
     * ЕСЛИ опция идёт первой», а nfqws1 порядок не соблюдал и метка выходила
     * первой всегда. Соблазн включить его всем tcpts-планам есть, и он
     * отвергнут: это молча изменило бы КАЖДЫЙ существующий план и разошлось
     * бы с замороженным описанием отправителя замера (test_measured сверяет
     * флаги посылки плана с d2k_poison_sends — 12 расхождений). Инвариант
     * «мерили и ставим одно и то же» дороже догадки: ось включается только
     * там, где её ИЗМЕРИЛИ. */
    a->tcpts_up     = p->tcp_ts_up;
    a->ipidzero     = p->ip_id_zero;
    /* Прямой разрез настоящей нагрузки (семейство C: split payload_start +2).
       Отличен от disorder_pos (обратный порядок) — едет своим полем, его
       исполняет d2k_arm_plan_measured через «split … + order forward». */
    a->split_pos    = p->split_pos > 0 ? (unsigned)p->split_pos : 0u;
    if (p->seqovl_exact) {
        /* «Длиной в целое приветствие» — не число, а правило: сборщик кладёт
         * туда приманку целиком. Задать то же число вручную не то же самое —
         * см. комментарий к seqovlExact у донора. */
        a->seqovl_hello = 1;
    } else if (p->seqovl > 0) {
        a->seqovl = (unsigned)p->seqovl;
    }
    return 0;
}
