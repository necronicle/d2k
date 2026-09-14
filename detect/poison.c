/* poison.c — гипотезы отравления и перевод находки в строку стратегии.
 *
 * Перенос internal/classify/classify.go эталона (poisons, strategyForPoison,
 * strategyFor, notePropsHit, notePropsMiss) — дословный, включая ПОРЯДОК.
 * Порядок здесь не косметика: неудачный зонд ждёт весь таймаут, удачный
 * отвечает мгновенно и обрывает перебор, поэтому первыми идут гипотезы,
 * которые уже брали живые коробки.
 */
#include "d2k_detect.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

int d2k_poison_has_fake(const d2k_poison *p)
{
    /* synData и oob фальшивки не несут вовсе, fakeBetween ставит её сам и в
     * другом месте — общий путь отправки для них не годится. */
    if (p->syn_data || p->oob || p->fake_between) {
        return 0;
    }
    return p->badsum || p->md5 || p->ttl > 0 || p->seq_shift != 0;
}

#define POISON_CAP 128
static d2k_poison g_poisons[POISON_CAP];
static int g_npoisons;

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

const d2k_poison *d2k_poisons(int *n)
{
    static const int rr[3] = {7, 4, 2};
    static const int ov3[3] = {1, 336, 681};
    static const int ovn[7] = {2, 4, 8, 16, 64, 336, 681};
    static const int gaps[4] = {0, 20, 80, 300};
    static const int reps[4] = {2, 3, 4, 7};
    static const int ttls[8] = {62, 60, 58, 55, 50, 40, 20, 8};
    static const int dttls[3] = {62, 58, 50};
    d2k_poison *p;
    int i, j;

    if (g_npoisons > 0) {
        *n = g_npoisons;
        return g_poisons;
    }

    /* ПОРЯДОК — ЭТО СТОИМОСТЬ. Перекрытие в один байт (facebook), разнесённые
     * дубликаты (YouTube, googlevideo) и плотная семёрка — первыми. */
    p = add("seqovl-1");           p->seqovl = 1;
    p = add("badsum-x2-g20");      p->badsum = 1; p->repeats = 2; p->gap_ms = 20;
    p = add("badsum-x2-g80");      p->badsum = 1; p->repeats = 2; p->gap_ms = 80;
    p = add("badsum-x7");          p->badsum = 1; p->repeats = 7;
    p = add("disorder");           p->disorder = 1;
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
        }
    }

    /* TTL сверху вниз: фальшивка должна пройти почти весь путь и умереть
     * перед сервером, а не сдохнуть у первого маршрутизатора. */
    for (i = 0; i < 8; i++) {
        p = add("ttl-%d", ttls[i]);         p->ttl = ttls[i];
        p = add("badsum+ttl-%d", ttls[i]);  p->badsum = 1; p->ttl = ttls[i];
    }

    p = add("disorder+badsum");        p->disorder = 1; p->badsum = 1;
    p = add("disorder+badsum+hello");  p->disorder = 1; p->badsum = 1; p->decoy_hello = 1;
    for (i = 0; i < 3; i++) {
        p = add("disorder+badsum+ttl-%d", dttls[i]);
        p->disorder = 1; p->badsum = 1; p->ttl = dttls[i];
    }

    p = add("badsum+ts");    p->badsum = 1; p->tcp_ts = 1;
    p = add("badsum+ipid");  p->badsum = 1; p->ip_id_zero = 1;
    p = add("badsum+hello"); p->badsum = 1; p->decoy_hello = 1;

    *n = g_npoisons;
    return g_poisons;
}

/* notePropsHit/notePropsMiss переводят исход зонда в свойство коробки.
 * Именно здесь перебор перестаёт быть перебором: каждая попытка что-то
 * РАССКАЗЫВАЕТ о коробке, даже когда не срабатывает. */
void d2k_note_props_hit(d2k_props *pr, const d2k_poison *p)
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
void d2k_note_props_miss(d2k_props *pr, const d2k_poison *p)
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
