/* props.c — свойства сперва, стратегия — из них.
 *
 * Перенос internal/classify/compose.go эталона (propProbes, composeFromProps,
 * runProperties).
 *
 * ЧЕМ ЭТО ОТЛИЧАЕТСЯ ОТ ПЕРЕБОРА. Раньше свойства коробки записывались как
 * побочный продукт перебора: гоняли девяносто гипотез, а из исходов задним
 * числом узнавали, что коробка умеет. Порядок был обратный правильному, и
 * держался он на том, что список отсортирован по замеренной частоте попаданий
 * — то есть на подгонке под статистику, а не на выводе.
 *
 * Здесь сперва задаются ВОПРОСЫ, по одному на свойство, а стратегия
 * СОБИРАЕТСЯ из ответов. Перебор остаётся, но уже запасным путём.
 */
#include "d2k_detect.h"

#include <stdio.h>
#include <string.h>

/* Какое поле вектора заполняет исход вопроса. В эталоне это замыкание set;
 * здесь — перечисление, потому что каждый случай записан явным литералом и
 * читать их полезнее списком, чем через указатель на функцию. */
typedef enum {
    SET_LEFT_OVERLAP,   /* ТОЛЬКО по проходу; промах неоднозначен */
    SET_REORDER,        /* ТОЛЬКО по проходу; промах неоднозначен */
    SET_CHECKSUM,       /* ТОЛЬКО по проходу */
    SET_PARSES_L7,      /* ТОЛЬКО по проходу */
    SET_DUPLICATES,     /* ТОЛЬКО по проходу */
    SET_SYN,            /* ТОЛЬКО по проходу */
    SET_MD5,            /* ТОЛЬКО по проходу */
    SET_SEQ_WINDOW,     /* ТОЛЬКО по проходу */
    SET_TIMESTAMPS,     /* ТОЛЬКО по проходу */
    SET_OVERLAP_SNI,    /* ТОЛЬКО по проходу */
    SET_DUP_DENSE,      /* ТОЛЬКО по проходу, то же поле, что SET_DUPLICATES */
    SET_WHITE_TS,       /* проход → не сверяет метку И разбирает L7 (белое имя) */
    SET_URGENT          /* ТОЛЬКО по проходу: не учитывает срочный байт TCP */
} prop_set;

typedef struct {
    const char *label;
    d2k_poison  p;
    prop_set    set;
} prop_probe;

/* СКОЛЬКО ВОПРОСОВ О СВОЙСТВАХ. Одна константа на массив, его обнуление и
   вызов: прежде число 12 стояло в четырёх местах, и добавление вопроса писало
   за границу массива молча. */
#define PROP_QUESTIONS 13

static int prop_probes(prop_probe *out, int cap)
{
    int k = 0;
    if (cap < PROP_QUESTIONS) {
        return 0;
    }
    memset(out, 0, sizeof(*out) * PROP_QUESTIONS);

    out[k].label = "перекрытие слева";
    snprintf(out[k].p.name, sizeof(out[k].p.name), "seqovl-1");
    out[k].p.seqovl = 1;
    out[k].set = SET_LEFT_OVERLAP;
    k++;

    out[k].label = "порядок сегментов";
    snprintf(out[k].p.name, sizeof(out[k].p.name), "disorder");
    out[k].p.disorder = 1;
    out[k].set = SET_REORDER;
    k++;

    /* СРОЧНЫЙ БАЙТ — ТРЕТЬИМ, И ЭТО МЕСТО ВЫБРАНО ЗАМЕРОМ (23.10.2026).
     *
     * Гистограмма 2933 полевых журналов (scripts/field19/sweep-histogram.py):
     * этим приёмом взято 111 целей из 124 ВСЕХ попаданий запасного перебора,
     * медиана шесть зондов. Вопроса о нём в опросе не было вовсе — значит
     * перебор был не страховкой, а основным поставщиком решений для этого
     * класса коробок, и каждое его попадание было промахом классификатора
     * (§0.1 ТЗ: повод добавить вопрос о свойстве, которое его объясняет).
     *
     * Пишется ТОЛЬКО по проходу: взяла зонд со срочным байтом в середине имени
     * — значит прочла имя с лишним байтом и не узнала его, тогда как сервер
     * этот байт из потока уберёт. Промах объясняется чем угодно (§2.4). */
    out[k].label = "срочный байт";
    snprintf(out[k].p.name, sizeof(out[k].p.name), "oob");
    out[k].p.oob = 1;
    out[k].set = SET_URGENT;
    k++;

    /* Пишем ТОЛЬКО по проходу. Проход однозначен: коробка проглотила фальшивку
     * с битой суммой, значит сумму не сверяет. Промах объясняется и разбором
     * L7, и чем угодно ещё, поэтому поле остаётся неизмеренным. */
    out[k].label = "контрольная сумма";
    snprintf(out[k].p.name, sizeof(out[k].p.name), "badsum");
    out[k].p.badsum = 1;
    out[k].set = SET_CHECKSUM;
    k++;

    /* Сюда доходим только после промаха зонда выше: набивку коробка не взяла.
     * Если теперь взяла ПРИВЕТСТВИЕ — значит разбирает L7, а заодно доказано,
     * что сумму она не сверяет. Предусловия «ValidatesChecksum == true» здесь
     * нет: оно было тавтологией с перевёрнутым знаком и заставляло отчёт
     * печатать «разбирает протокол: да» рядом с ложным «сумму проверяет: да». */
    out[k].label = "разбор протокола";
    snprintf(out[k].p.name, sizeof(out[k].p.name), "badsum+hello");
    out[k].p.badsum = 1;
    out[k].p.decoy_hello = 1;
    out[k].set = SET_PARSES_L7;
    k++;

    out[k].label = "повтор как ретрансмит";
    snprintf(out[k].p.name, sizeof(out[k].p.name), "badsum-x2-g20");
    out[k].p.badsum = 1;
    out[k].p.repeats = 2;
    out[k].p.gap_ms = 20;
    out[k].set = SET_DUPLICATES;
    k++;

    /* ПОЛЯ, КОТОРЫЕ УЗНАВАЛ ТОЛЬКО ПЕРЕБОР (§0.1 ТЗ, 07.10.2026). По вопросу
     * на поле и БЕЗ битой суммы: с ней проход значил бы лишь «сумму не
     * сверяет» (вопрос выше), а не ответ о самом поле. IP ID отдельно не
     * спрашивается: пакет с нулевым IP ID сервер принимает — это не приём. */
    out[k].label = "сверка MD5";
    snprintf(out[k].p.name, sizeof(out[k].p.name), "md5");
    out[k].p.md5 = 1;
    out[k].set = SET_MD5;
    k++;

    out[k].label = "окно seq";
    snprintf(out[k].p.name, sizeof(out[k].p.name), "seq-out-of-window");
    out[k].p.seq_shift = -66000;
    out[k].set = SET_SEQ_WINDOW;
    k++;

    out[k].label = "метка времени";
    snprintf(out[k].p.name, sizeof(out[k].p.name), "ts");
    out[k].p.tcp_ts = 1;
    out[k].set = SET_TIMESTAMPS;
    k++;

    /* ОСИ `tcp_ts_up` И `ip_autottl` СПРАШИВАЛИСЬ ЗДЕСЬ И СНЯТЫ ПОЛЕМ.
     * Прогон 23.10.2026 `ttl-ae30825-1`: 12 провалов контроля из 56 против 10
     * у выпуска, и ни одного исполнения новых осей — все находки пути
     * «свойство» в раунде пришлись на ПЕРВЫЙ вопрос списка (`seqovl-1`), до
     * восьмого замер не дошёл ни на одной из 22 целей. Вопрос в конце списка
     * на этой линии стоит 2–4 зонда у глубоких целей и ответа не даёт.
     * Снят ВОПРОС, механизм остался: `ip_autottl` — запись языка плана
     * (REC_AUTOTTL, minexec 13), её выбирает RX-лестница для клиента без
     * метки времени (issue #7); `tcp_ts_up` — бит порчи. Вернуть вопрос,
     * когда поле покажет цель, доходящую до конца списка.
     * Регрессия: test_unreachable_axes_not_asked (detect/test_repeats.c). */

    /* Размер перекрытия не перебирается (прежде seqovl 2…681): длина —
     * до конца имени в приветствии, её задаёт run_properties по триггеру. */
    out[k].label = "перекрытие до конца имени";
    snprintf(out[k].p.name, sizeof(out[k].p.name), "seqovl-sni");
    out[k].set = SET_OVERLAP_SNI;
    k++;

    /* Порог дубликатов: вопрос выше — две копии с паузой 20 мс; здесь —
     * плотная семёрка без паузы, а не сетка 4×4 копий и пауз. */
    out[k].label = "плотная серия";
    snprintf(out[k].p.name, sizeof(out[k].p.name), "badsum-x7");
    out[k].p.badsum = 1;
    out[k].p.repeats = 7;
    out[k].set = SET_DUP_DENSE;
    k++;

    /* СОСТАВНОЙ ВОПРОС СЕМЕЙСТВА C: ECH-ПРИВЕТСТВИЕ ПОД МЕТКОЙ ВРЕМЕНИ, СЕРИЯ,
     * РАЗРЕЗ (поле 10.10.2026, разбор 2026-10-10-tcp-block-analysis.md, раздел
     * «Предложение»; уточнение владельца по ECH).
     *
     * КОРЕНЬ ДЫРЫ: коробка этих целей (rutracker.org и прочие за Cloudflare,
     * рукопожатие 0/3) поддаётся только ПРОИЗВЕДЕНИЮ множителей, а отдельные
     * вопросы «метка времени», «плотная серия», «разбор протокола» мерят каждый
     * ОТДЕЛЬНО и каждый промах. Этот вопрос мерит ВСЁ ВМЕСТЕ, одним приёмом:
     *   fake ECH-приветствие (opt->white — шаблон cloudflare-ech / fake_default_tls
     *     с ECH-расширением; коробка не читает в нём имя и не режет по нему)
     *   + poison tcpts (TS−1000, сервер отбросит по PAWS, коробка разберёт)
     *   + серия ×8 (одной копии мало — замерено полем)
     *   + split настоящего приветствия +2 (прямой порядок).
     * Это ровно рабочий plan-680fbe00 (ступень 0 RX-лестницы). Проход при
     * промахе «метки времени» значит: коробка принимает пакет со старой меткой
     * (метку не сверяет) И разбирает фальшивое ECH-приветствие (разбирает L7),
     * цепляясь за ECH-поток вместо имени. План из того же воздействия выразим
     * через мост (fake+tcpts, серия, split +2) — путь находки «свойство».
     *
     * Приманка — ECH-шаблон, а НЕ имя контроля: имя контроля коробка прочитает
     * и срежет. opt->white всегда несёт ECH-шаблон (планировщик строит его из
     * net.name либо из семени hcaptcha.com, см. core/sched.c, d2k_white_decoy_hello),
     * поэтому вопрос работает и с пустым каталогом. Задаётся ТОЛЬКО при наличии
     * ECH-приманки (opt->white). Это СЛОЙ РУКОПОЖАТИЯ; объёмный слой 16 КБ
     * (SNI-whitelist, «белое имя сети») снимает отдельный путь — RX-лестница,
     * здесь он не мерится и не предполагается снятым. Место — после «плотной
     * серии», перед «данными в SYN» (решение владельца 09.10: syndata последним). */
    out[k].label = "ECH-приветствие под меткой";
    snprintf(out[k].p.name, sizeof(out[k].p.name), "white-hello-ts");
    out[k].p.tcp_ts = 1;
    out[k].p.decoy_hello = 1;
    out[k].p.repeats = 8;    /* серия: одной копии мало (поле 10.10) */
    out[k].p.split_pos = 2;  /* разрез настоящего приветствия +2, прямой порядок */
    out[k].set = SET_WHITE_TS;
    k++;

    /* SYN precedes the observed name in a live flow. Ask all questions
     * whose successful send can become a datapath plan before syndata
     * (owner decision 09.10.2026, plan items 2–3). */
    out[k].label = "данные в SYN";
    snprintf(out[k].p.name, sizeof(out[k].p.name), "syndata");
    out[k].p.syn_data = 1;
    out[k].set = SET_SYN;
    k++;

    /* Если вопрос добавили, а константу забыли — ломаемся здесь, а не молча
       за границей массива. */
    return k <= PROP_QUESTIONS ? k : 0;
}

static void apply_set(d2k_dprops *pr, prop_set s, int ok, const d2k_poison *p)
{
    switch (s) {
    case SET_LEFT_OVERLAP:
        if (ok) { pr->tolerates_left_overlap = D2K_TRI_FALSE; }
        break;
    case SET_REORDER:
        if (ok) { pr->tolerates_reorder = D2K_TRI_FALSE; }
        break;
    case SET_CHECKSUM:
        if (ok) {
            pr->validates_checksum = D2K_TRI_FALSE;
        }
        break;
    case SET_PARSES_L7:
        if (ok) {
            pr->parses_l7 = D2K_TRI_TRUE;
            pr->validates_checksum = D2K_TRI_FALSE;
        }
        break;
    case SET_DUPLICATES:
        if (ok) {
            pr->counts_duplicates = D2K_TRI_TRUE;
        }
        break;
    case SET_SYN:
        if (ok) {
            pr->inspects_syn = D2K_TRI_FALSE;
        }
        break;
    case SET_MD5:
        if (ok) { pr->validates_md5 = D2K_TRI_FALSE; }
        break;
    case SET_SEQ_WINDOW:
        if (ok) { pr->validates_seq_window = D2K_TRI_FALSE; }
        break;
    case SET_TIMESTAMPS:
        if (ok) { pr->validates_timestamps = D2K_TRI_FALSE; }
        break;
    case SET_OVERLAP_SNI:
        if (ok) { pr->overlap_covers_sni = D2K_TRI_TRUE; }
        break;
    case SET_DUP_DENSE:
        if (ok) { pr->counts_duplicates = D2K_TRI_TRUE; }
        break;
    case SET_URGENT:
        if (ok) { pr->handles_urgent = D2K_TRI_FALSE; }
        break;
    case SET_WHITE_TS:
        /* Проход: коробка разобрала фальшивое ECH-приветствие (разбирает L7),
         * зацепившись за ECH-поток вместо имени. Про ПОРЧУ утверждаем только
         * то, что в этом вопросе действительно было: у клиента без метки
         * времени её в зонде нет, и «метку не сверяет» по такому проходу —
         * выдумка о коробке (§2.4, замысел 2026-10-23 п. 5.2). Все выводы —
         * только по проходу. */
        if (ok) {
            pr->parses_l7 = D2K_TRI_TRUE;
            if (p && p->tcp_ts) { pr->validates_timestamps = D2K_TRI_FALSE; }
            if (p && p->badsum) { pr->validates_checksum = D2K_TRI_FALSE; }
        }
        break;
    }
}

/* ЗНАНИЕ О КОРОБКЕ ВМЕСТО ПОВТОРНОГО ВОПРОСА (23.10.2026).
 *
 * Возвращает записанный ответ на вопрос s и кладёт в pass_v то значение
 * поля, которое означает ПРОХОД вопроса. D2K_PROP_UNKNOWN — знания нет.
 *
 * ПОЧЕМУ МИМО ПРОХОДИТ ТОЛЬКО ДВА ВОПРОСА. Промах пишется знанием лишь там,
 * где он однозначен: приём не ломает коробку — значит она к нему терпима
 * (d2k_note_props_miss). У остальных вопросов промах объясняется и разбором
 * L7, и чем угодно ещё, поэтому их поля ставятся ТОЛЬКО по проходу (§2.4), и
 * «известного промаха» у них не бывает по построению. Сокращать опрос
 * догадкой о тишине здесь нельзя — это ровно та ошибка, от которой защищает
 * тройственная логика. */
static int8_t known_of(const d2k_box_props *k, prop_set s, int8_t *pass_v)
{
    switch (s) {
    case SET_LEFT_OVERLAP: *pass_v = D2K_PROP_NO;  return k->tolerates_left_overlap;
    case SET_REORDER:      *pass_v = D2K_PROP_NO;  return k->tolerates_reorder;
    case SET_CHECKSUM:     *pass_v = D2K_PROP_NO;  return k->validates_checksum;
    case SET_SYN:          *pass_v = D2K_PROP_NO;  return k->inspects_syn;
    case SET_MD5:          *pass_v = D2K_PROP_NO;  return k->validates_md5;
    case SET_SEQ_WINDOW:   *pass_v = D2K_PROP_NO;  return k->validates_seq_window;
    case SET_TIMESTAMPS:   *pass_v = D2K_PROP_NO;  return k->validates_timestamps;
    case SET_DUPLICATES:
    case SET_DUP_DENSE:    *pass_v = D2K_PROP_YES; return k->counts_duplicates;
    case SET_OVERLAP_SNI:  *pass_v = D2K_PROP_YES; return k->overlap_covers_sni;
    case SET_URGENT:       *pass_v = D2K_PROP_NO;  return k->handles_urgent;
    /* Два вопроса пишут ДВА поля из ОДНОГО факта (разбор протокола — parses_l7
     * и сумму; ECH-приветствие под меткой — метку и parses_l7). По одному полю
     * исход такого вопроса не восстановим: parses_l7=да мог записать и сосед.
     * Поэтому знания о них здесь нет, и они задаются как раньше. */
    case SET_PARSES_L7:
    case SET_WHITE_TS:     break;
    }
    *pass_v = D2K_PROP_UNKNOWN;
    return D2K_PROP_UNKNOWN;
}

/* Кладёт записанный ответ в вектор ПРОГОНА: дальше план собирается из него
 * (d2k_compose_from_props), и потерять здесь знание значило бы снова
 * предлагать приём, про который уже известно, что он не проходит. */
static void known_into(d2k_dprops *pr, prop_set s, int8_t v)
{
    switch (s) {
    case SET_LEFT_OVERLAP: pr->tolerates_left_overlap = (d2k_tri)v; break;
    case SET_REORDER:      pr->tolerates_reorder = (d2k_tri)v; break;
    case SET_CHECKSUM:     pr->validates_checksum = (d2k_tri)v; break;
    case SET_SYN:          pr->inspects_syn = (d2k_tri)v; break;
    case SET_MD5:          pr->validates_md5 = (d2k_tri)v; break;
    case SET_SEQ_WINDOW:   pr->validates_seq_window = (d2k_tri)v; break;
    case SET_TIMESTAMPS:   pr->validates_timestamps = (d2k_tri)v; break;
    case SET_DUPLICATES:
    case SET_DUP_DENSE:    pr->counts_duplicates = (d2k_tri)v; break;
    case SET_OVERLAP_SNI:  pr->overlap_covers_sni = (d2k_tri)v; break;
    case SET_URGENT:       pr->handles_urgent = (d2k_tri)v; break;
    case SET_PARSES_L7:
    case SET_WHITE_TS:     break;
    }
}

/* РАССТОЯНИЕ ДО КОРОБКИ — ДВОИЧНЫМ ПОИСКОМ, А НЕ ЛЕСТНИЦЕЙ ИЗ СПИСКА
 * (23.10.2026).
 *
 * ЧТО НЕ ТАК БЫЛО. Расстояние до коробки — её собственное свойство: она стоит
 * на фиксированном числе хопов от нас, сколько бы целей за ней ни было. Но
 * измерялось оно случайно: hop_ttl писался лишь тогда, когда в запасном
 * переборе срабатывала одна из 19 гипотез с готовыми значениями TTL
 * (ttl-62, ttl-60, …, badsum+ttl-8, disorder+badsum+ttl-50). Числа взяты из
 * чужого поля, и на другой линии они мимо; а узнав рабочее значение, мы не
 * узнавали САМО РАССТОЯНИЕ и на следующей цели той же коробки перебирали
 * список заново.
 *
 * ЧТО ИЗМЕРЯЕМ. Фальшивка с TTL = T доходит до коробки, если T не меньше
 * расстояния до неё, и НЕ доходит до сервера, если T меньше расстояния до
 * сервера. Значит проход зонда — это отрезок [H, S−1], где H — расстояние до
 * коробки, S — до сервера. Нижняя граница отрезка и есть H.
 *
 * БИТАЯ СУММА ДЕЛАЕТ ПРОХОД МОНОТОННЫМ, И ЭТО ГЛАВНОЕ. Верхняя граница
 * отрезка существует только у ЧИСТОЙ фальшивки: доживи она до сервера, тот
 * примет её за данные соединения и поток сломается. Фальшивка с БИТОЙ СУММОЙ
 * безвредна и у сервера — он отбросит её сам, — поэтому проход у неё верен
 * для всех T не меньше расстояния до коробки. Монотонный предикат ищется
 * чистым делением: шесть зондов, ни одного числа из чужого поля.
 *
 * Битую сумму коробка должна глотать, и это известно из вектора: если она
 * сумму СВЕРЯЕТ, фальшивку с битой суммой она не возьмёт, и тогда остаётся
 * чистая — с отрезком вместо монотонности и с лестницей, которая этот отрезок
 * ищет. Лестница плотная сверху: там окно узкое (коробка близко к серверу), и
 * чисто геометрическая лестница окно [60, 61] пропускала целиком.
 *
 * ПОИСК — ОДНИМ ЗОНДОМ НА ШАГ, ИЗМЕРЕНИЕ — ЕДИНОГЛАСИЕМ. Шаги лестницы и
 * деления отвечают на вопрос «куда идти», и платить за каждый тремя зондами
 * значило бы втрое дороже за дорогу, а не за ответ: найденное число всё равно
 * проверяется повторами в конце, и невоспроизводимость там и видна. Разница
 * та же, что между поиском и замером во всём остальном коде.
 *
 * ЕДИНОГЛАСИЕ И НЕВОСПРОИЗВОДИМОСТЬ — ТЕМ ЖЕ ПРАВИЛОМ, ЧТО У ПОИСКА РАЗРЕЗА
 * (classify.c): шаг решён, только если прошли все повторы либо не прошёл ни
 * один. Разошлись — величина НЕ ИЗМЕРЕНА (возврат 0), а не усреднена:
 * фальшивка с усреднённым TTL либо не дойдёт до коробки, либо дойдёт до
 * сервера, и план по такому числу не исполнится ни в одном из двух случаев.
 * Локальный отказ зонда — тоже «не измерено» (§2.4). */
#define D2K_HOP_CEIL 62

/* Один шаг поиска: 1 — прошли все повторы, 0 — ни один, -1 — не решено
 * (повторы разошлись либо зонд не ушёл). */
static int hop_step(const uint8_t *ip4, uint8_t family, uint16_t port,
                    const d2k_trigger *tr, const d2k_opts *opt, d2k_result *res,
                    int ttl, int reps, int badsum)
{
    d2k_poison p;
    d2k_obs *obs;
    char err[160];
    char label[160];
    int j, pass = 0, done = 0;

    if (reps <= 0) { reps = 1; }
    memset(&p, 0, sizeof p);
    p.ttl = ttl;
    p.badsum = badsum ? 1 : 0;
    snprintf(p.name, sizeof p.name, badsum ? "badsum+ttl-%d" : "ttl-%d", ttl);
    snprintf(label, sizeof label, "свойство:расстояние до коробки, TTL %d%s", ttl,
             badsum ? ", битая сумма" : "");
    obs = d2k_trace_add(res, label);
    struct { int kind, ttl, repeats, badsum; } cache_key = {4, ttl, reps, !!badsum};
    d2k_run_entry *cached = d2k_run_cache_get(opt->run_cache,
        &cache_key, sizeof cache_key, NULL, 0);
    if (cached && !d2k_detect_stopped(&opt->cancel) &&
        ((cached->pass == reps && cached->fail == 0) ||
         (cached->pass == 0 && cached->fail > 0))) {
        obs->pass = cached->pass;
        obs->fail = cached->fail;
        obs->seeded = 1;
        if (opt->on_obs) { opt->on_obs(opt->on_obs_ctx, obs); }
        return cached->pass == reps ? 1 : 0;
    }
    for (j = 0; j < reps; j++) {
        int rc = d2k_raw_probe_poison_family(ip4, family, port, tr, &p, opt->timeout_ms,
                                             opt->mark, &opt->cancel, err, sizeof err);
        res->probes++;
        done++;
        d2k_raw_note_rc(res, family, rc);
        if (rc < 0) {
            if (obs->err[0] == '\0') { snprintf(obs->err, sizeof obs->err, "%s", err); }
            obs->fail = done - pass;
            if (opt->on_obs) { opt->on_obs(opt->on_obs_ctx, obs); }
            return -1;
        }
        if (rc > 0) { pass++; continue; }
        /* ПЕРВЫЙ ПРОВАЛ РЕШАЕТ: единогласие уже недостижимо, и остальные
           повторы его не вернут — тем же правилом, что в переборе отрав. */
        break;
    }
    obs->pass = pass;
    obs->fail = done - pass;
    if (!d2k_detect_stopped(&opt->cancel) && (pass == reps || pass == 0)) {
        d2k_run_cache_put(opt->run_cache, &cache_key, sizeof cache_key,
                          NULL, 0, obs->pass, obs->fail);
    }
    if (opt->on_obs) { opt->on_obs(opt->on_obs_ctx, obs); }
    if (pass == reps) { return 1; }
    if (pass == 0) { return 0; }
    return -1; /* повторы разошлись — шаг не решён */
}

int d2k_hop_search(const uint8_t *ip4, uint8_t family, uint16_t port,
                   const d2k_trigger *tr, const d2k_opts *opt, d2k_result *res)
{
    /* Сумму коробка сверяет — битую фальшивку не возьмёт; иначе берём её и
       получаем монотонный проход. «Не измерено» здесь читается как «можно
       пробовать»: промах на первом же зонде стоит один зонд и сразу уводит на
       чистую фальшивку. */
    int badsum = opt && opt->known.validates_checksum != D2K_PROP_YES;
    if (badsum) {
        int lo = 0, hi = D2K_HOP_CEIL;
        if (d2k_detect_stopped(&opt->cancel)) { return 0; }
        /* Потолок обязан проходить: иначе фальшивку с битой суммой не глотает
           ни коробка (и тогда лестница ниже бесполезна), ни путь. */
        if (hop_step(ip4, family, port, tr, opt, res, hi, 1, 1) == 1) {
            while (hi - lo > 1) {
                int mid = (lo + hi) / 2;
                int rc;
                if (d2k_detect_stopped(&opt->cancel)) { return 0; }
                rc = hop_step(ip4, family, port, tr, opt, res, mid, 1, 1);
                if (rc < 0) { return 0; }
                if (rc > 0) { hi = mid; } else { lo = mid; }
            }
            if (hop_step(ip4, family, port, tr, opt, res, hi, opt->repeats, 1) != 1) { return 0; }
            res->props.hop_ttl = hi;
            /* Сумму коробка не сверяет — это тот же факт, добытый этим же
               зондом, и терять его незачем (§2.4: пишем только по проходу). */
            res->props.validates_checksum = D2K_TRI_FALSE;
            return hi;
        }
        /* Битую сумму не взяла — дальше чистой фальшивкой, с отрезком. */
    }

    /* ЛЕСТНИЦА ПОИСКА ОТРЕЗКА — ПЛОТНАЯ СВЕРХУ, РЕДКАЯ СНИЗУ.
     *
     * Верхняя граница отрезка — расстояние до СЕРВЕРА минус один, и его мы
     * пока не измеряем (TTL входящих пакетов снимает только путь QUIC,
     * core/quicprobe.c). Коробка у самого сервера даёт узкое окно: с чисто
     * геометрической лестницей (62, 32, 16, …) окно [60, 61] не попадалось
     * ни одной ступенью, и расстояние объявлялось неизмеренным. Поэтому
     * сверху ступени частые — там окно узкое, — а снизу редкие: там оно
     * широкое, и попасть в него легко.
     *
     * Это ЕДИНСТВЕННОЕ место, где остались значения не из замера, и они
     * выбирают только ПОРЯДОК ПОИСКА, а не ответ: ответ даёт деление отрезка
     * ниже. Полный промах всей лестницы — доказательство отсутствия отрезка,
     * и стоит он четырнадцати зондов против девятнадцати гипотез, которые
     * платили за то же (см. init_poisons, detect/poison.c).
     *
     * ЛЕСТНИЦА — НАДМНОЖЕСТВО УДАЛЁННОГО СПИСКА (ревью 24.10.2026). У ушедших
     * гипотез были значения ttls[] = {62, 60, 58, 55, 50, 40, 20, 8}, и пока
     * они существовали, окно шириной в ОДИН хоп на любом из этих чисел
     * бралось: гипотеза пробовалась как есть. Ступеней 40 и 20 у лестницы не
     * было, и окно [20, 20] объявлялось неизмеренным — рабочий приём
     * становился недостижимым. Два зонда в случае полного промаха дешевле
     * потерянного приёма.
     *
     * ЧЕГО ЛЕСТНИЦА НЕ ДАЁТ. Окно шириной в один хоп на значении ВНЕ списка
     * ступеней не найдётся: промах ступени неоднозначен, и сузить отрезок по
     * нему нечем. Честно закрыть это можно только измеренным верхом отрезка —
     * расстоянием до сервера, — а его TCP-зонд пока не снимает: TTL входящих
     * пакетов читает только путь QUIC (core/quicprobe.c), и живым потокам его
     * знает датапат (fl->rev_ttl), не сообщая контроллеру. */
    static const int ladder[] = { D2K_HOP_CEIL, 60, 58, 55, 50, 44, 40, 38, 32,
                                  24, 20, 16, 8, 2 };
    size_t k;
    int lo = 0, hi = 0;

    if (!opt || opt->repeats <= 0) { return 0; }
    for (k = 0; k < sizeof ladder / sizeof ladder[0]; k++) {
        int rc;
        if (d2k_detect_stopped(&opt->cancel)) { return 0; }
        rc = hop_step(ip4, family, port, tr, opt, res, ladder[k], 1, 0);
        if (rc < 0) { return 0; }
        if (rc > 0) { hi = ladder[k]; break; }
        /* ПРОМАХ НА ЛЕСТНИЦЕ НИЧЕГО НЕ ГОВОРИТ О ГРАНИЦЕ. Он объясняется и
           «слишком высоко» (фальшивка дошла до сервера, тот её отбросил), и
           «слишком низко» (не дошла до коробки). Различить нечем, поэтому
           нижняя граница остаётся нулём — вывод из неоднозначного промаха был
           бы ровно той ошибкой, от которой защищает тройственная логика. */
    }
    if (hi == 0) { return 0; } /* отрезка прохода не нашли — расстояние не измерено */
    /* lo не проходит (ноль хопов не бывает), hi проходит: граница между ними. */
    while (hi - lo > 1) {
        int mid = (lo + hi) / 2;
        int rc;
        if (d2k_detect_stopped(&opt->cancel)) { return 0; }
        rc = hop_step(ip4, family, port, tr, opt, res, mid, 1, 0);
        if (rc < 0) { return 0; }
        if (rc > 0) { hi = mid; } else { lo = mid; }
    }
    /* НАЙДЕННОЕ ЧИСЛО ПРОВЕРЯЕТСЯ ПОВТОРАМИ: до этой строки был поиск, здесь
       — замер. Не прошло единогласно — расстояние НЕ ИЗМЕРЕНО (§2.4), и
       гипотезы из него не берутся. */
    if (hop_step(ip4, family, port, tr, opt, res, hi, opt->repeats, 0) != 1) { return 0; }
    res->props.hop_ttl = hi;
    return hi;
}

/* runProperties задаёт вопросы и заполняет вектор. Возвращает первую
 * гипотезу, которая сама по себе сработала, если такая была. */
int d2k_run_properties(const uint8_t ip4[4], uint16_t port,
    const d2k_trigger *tr, const d2k_opts *opt, d2k_result *res, d2k_poison *hit)
{
    return d2k_run_properties_family(ip4, 4, port, tr, opt, res, hit);
}

/* Ответ этого вопроса уже получен прежним прогоном того же входа (этап 25):
 * тот же ярлык, то же число повторов. NULL — спрашивать. */
static const d2k_known_prop *known_answer(const d2k_opts *opt, const char *label)
{
    int k;
    if (!opt || opt->nknown <= 0 || opt->known_repeats != opt->repeats) {
        return NULL;
    }
    for (k = 0; k < opt->nknown && k < D2K_KNOWN_MAX; k++) {
        if (strcmp(opt->known_answers[k].label, label) == 0) {
            return &opt->known_answers[k];
        }
    }
    return NULL;
}

int d2k_run_properties_family(const uint8_t *ip4, uint8_t family, uint16_t port,
                       const d2k_trigger *tr, const d2k_opts *opt,
                       d2k_result *res, d2k_poison *hit)
{
    prop_probe pp[PROP_QUESTIONS];
    int n = prop_probes(pp, PROP_QUESTIONS);
    int i, j;
    char err[160];

    for (i = 0; i < n; i++) {
        d2k_poison p = pp[i].p;
        d2k_obs *obs;
        char label[200];
        int pass = 0, done = 0, local_err = 0, got;
        int decoy_cloned = 0;

        if (d2k_detect_stopped(&opt->cancel)) {
            break;
        }
        if (d2k_opts_skipped(opt, p.name)) {
            continue;
        }
        {
            /* ОТВЕТ УЖЕ ЕСТЬ И ОН ОЗНАЧАЕТ ПРОМАХ — вопрос не задаём: его
               повторы ушли бы на уже известный промах. Знание кладём в вектор
               прогона, чтобы план собирался из него.
               ОТВЕТ «ПРОХОДИТ» — ВОПРОС ЗАДАЁМ ВСЁ РАВНО: прошедший вопрос и
               есть доказательство приёма на проводе (§0.1 ТЗ), а
               доказательство обязано быть свежим для ЭТОЙ сети; иначе «обход
               найден» означало бы «когда-то работало». */
            int8_t pass_v = D2K_PROP_UNKNOWN;
            int8_t was = known_of(&opt->known, pp[i].set, &pass_v);
            if (was != D2K_PROP_UNKNOWN && was != pass_v) {
                snprintf(label, sizeof(label), "свойство:%s", pp[i].label);
                obs = d2k_trace_add(res, label);
                obs->from_known = 1;
                known_into(&res->props, pp[i].set, was);
                if (opt->on_obs) { opt->on_obs(opt->on_obs_ctx, obs); }
                continue;
            }
        }
        /* ВОПРОС ЗАДАЁТСЯ КАК КЛИЕНТ (замысел 2026-10-23, п. 5.1 и 5.2).
         *
         * Порча «метка времени назад» исполнима только на потоке, который
         * метку предлагает: датапат копирует опции потока и сдвигает метку в
         * них (datapath/wire.c, профиль tcp-template-v1). Клиенту без метки
         * одиночный вопрос о метке не задаётся вовсе — его «нет» говорило бы
         * о нашем зонде, а не о коробке.
         *
         * СОСТАВНОЙ ВОПРОС СЕМЕЙСТВА C при этом НЕ ПРОПАДАЕТ, А СОБИРАЕТСЯ:
         * множители (приманка ECH, серия ×8, разрез +2) остаются, а порча
         * берётся из того, что уже измерено, — тем же правилом, которым
         * d2k_compose_from_props берёт битую сумму (пробуем, пока коробка не
         * доказала, что сумму сверяет): нечем сделать фальшивку отвергаемой
         * сервером — вопрос не задаётся, потому что приём, который примет и
         * сервер, обходом не является.
         *
         * Оговорка про «доказала» сегодня не срабатывает ни разу: TRI_TRUE в
         * validates_checksum не пишет никто — по §2.4 свойство ставится только
         * по ПРОХОДУ, а проход доказывает обратное (сумму НЕ сверяет). Условие
         * оставлено как страховка на случай, когда появится источник такого
         * доказательства; сегодня подстановка битой суммы безусловна, и это
         * безопасно: сервер такую фальшивку бракует по построению. */
        if (p.tcp_ts && !d2k_trigger_offers_ts(tr)) {
            if (pp[i].set != SET_WHITE_TS) {
                continue;
            }
            p.tcp_ts = 0;
            if (res->props.validates_checksum == D2K_TRI_TRUE) {
                continue;
            }
            p.badsum = 1;
        }
        if (pp[i].set == SET_OVERLAP_SNI) {
            /* До конца имени: без имени в приветствии вопрос не задаётся. */
            if (tr->sni_len <= 0 || tr->sni_off <= 0 ||
                (size_t)(tr->sni_off + tr->sni_len) >= tr->len) {
                continue;
            }
            p.seqovl = tr->sni_off + tr->sni_len;
        }
        if (pp[i].set == SET_WHITE_TS) {
            /* Приманка — ECH-ПРИВЕТСТВИЕ (opt->white), не имя контроля: имя
             * контроля коробка прочитает и срежет, а имя в ECH-приветствии она
             * не читает и цепляется за поток. Нет ECH-приманки — нет вопроса
             * (планировщик всегда её даёт, с пустым каталогом — семя hcaptcha.com;
             * уточнение владельца по ECH, поле 10.10.2026). */
            if (opt->white.len < 2) {
                continue;
            }
            p.decoy = opt->white.payload;
            p.decoy_len = opt->white.len;
        } else if (p.decoy_hello) {
            const d2k_trigger *d = d2k_opts_decoy(opt);
            p.decoy = d->payload;
            p.decoy_len = d->len;
            decoy_cloned = d == &opt->decoy;
        }
        /* Паузу и число копий кладём в наблюдение явно: без этого трасса
         * показывала «пауза=0мс» у зонда, который её честно выдерживает, и
         * читалась как поломка механизма. */
        /* ЯРЛЫК НАЗЫВАЕТ ТО, ЧТО УШЛО НА ПРОВОД (ревью ветки, находка 9).
         * Составной вопрос клиента без метки собран без неё: писать в трассу
         * «под меткой» значило бы назвать в журнале опыта воздействие,
         * которого не было. Имя гипотезы (p.name) при этом НЕ меняется — по
         * нему ведётся учёт заданных и пропущенных вопросов. */
        if (pp[i].set == SET_WHITE_TS && !p.tcp_ts) {
            snprintf(label, sizeof(label), "свойство:ECH-приветствие под битой суммой");
        } else if (decoy_cloned) {
            /* КАКОЙ ПРИМАНКОЙ ЗАДАН ВОПРОС — В ЗАПИСЬ ОПЫТА. Клон приветствия
             * клиента и встроенный шаблон (fallback) — разные стимулы для
             * коробки, разбирающей L7, и в журнале их обязано быть видно:
             * иначе два разных опыта выглядят одинаково (ТЗ §5). */
            snprintf(label, sizeof(label), "свойство:%s (приманка — клон клиента)",
                     pp[i].label);
        } else {
            snprintf(label, sizeof(label), "свойство:%s", pp[i].label);
        }
        obs = d2k_trace_add(res, label);
        obs->delay_ms = p.gap_ms;
        struct { int kind; d2k_poison poison; } cache_key;
        memset(&cache_key, 0, sizeof cache_key);
        cache_key.kind = 2; cache_key.poison = p; cache_key.poison.decoy = NULL;
        {
            d2k_run_entry *cached = d2k_run_cache_get(opt->run_cache,
                &cache_key, sizeof cache_key, p.decoy, p.decoy_len);
            d2k_known_prop saved;
            memset(&saved, 0, sizeof saved);
            if (cached) { saved.pass = cached->pass; saved.fail = cached->fail; }
            /* ОТВЕТ УЖЕ ЕСТЬ (этап 25): прогон тем же входом был прерван
             * (уступка, отмена) после этого вопроса — его исход берётся как
             * измеренный, зондов не тратится, в трассе пометка seeded. */
            const d2k_known_prop *kn = cached ? &saved :
                (opt->run_cache ? NULL : known_answer(opt, pp[i].label));
            if (kn) {
                pass = kn->pass;
                done = kn->pass + kn->fail;
                obs->pass = pass;
                obs->fail = kn->fail;
                obs->seeded = 1;
                if (res->nanswered < D2K_ANSWERED_MAX) {
                    res->answered[res->nanswered++] = p;
                }
                if (opt->on_obs) { opt->on_obs(opt->on_obs_ctx, obs); }
                got = d2k_prop_majority(pass, opt->repeats);
                apply_set(&res->props, pp[i].set, got, &p);
                if (got && d2k_opts_acceptable(opt, &p)) {
                    *hit = p;
                    return 1;
                }
                continue;
            }
        }
        /* ОТВЕТ — БОЛЬШИНСТВОМ ПОВТОРОВ (поле 14.10.2026, fost.club с роутера,
         * d2k-detect с меткой замера): «ECH-приветствие под меткой» к одному
         * адресу дало 3/3, 0/1, 2/3, 1/2 — приём срабатывает в ~2 попытках из
         * 3 при любой приманке, и тот же план (680fbe00) через датапат сайт
         * открывал весь день. Прежнее единогласие с выходом на первом провале
         * делало из такого приёма «нет» в ~7 случаях из 10. Вопросы о свойствах
         * задаются при режущейся базе (0/N), так что проход приёма — эффект
         * приёма, а не случайность сервера. Повторы кончаются, как только исход
         * решён: большинство набрано или уже недостижимо. */
        for (j = 0; j < opt->repeats; j++) {
            int rc = d2k_raw_probe_poison_family(ip4, family, port, tr, &p, opt->timeout_ms, opt->mark,
                                          &opt->cancel, err, sizeof(err));
            res->probes++;
            done++;
            d2k_raw_note_rc(res, family, rc);
            if (rc < 0) {
                local_err = 1;
                /* Локальная ошибка — в трассу: иначе «0/3» читается как
                 * ответ сети, а сети зонд не достиг (поле 10.10.2026). */
                if (obs->err[0] == '\0') {
                    snprintf(obs->err, sizeof(obs->err), "%s", err);
                }
                break;
            }
            if (rc > 0) { pass++; }
            if (d2k_prop_majority(pass, opt->repeats) ||
                !d2k_prop_majority(pass + (opt->repeats - done), opt->repeats)) {
                break;
            }
        }
        if (!local_err && res->nanswered < D2K_ANSWERED_MAX) {
            res->answered[res->nanswered++] = p;
        }
        obs->pass = pass;
        obs->fail = done - pass;
        if (!local_err && !d2k_detect_stopped(&opt->cancel) &&
            (d2k_prop_majority(pass, opt->repeats) ||
             !d2k_prop_majority(pass + opt->repeats - done, opt->repeats))) {
            d2k_run_cache_put(opt->run_cache, &cache_key, sizeof cache_key,
                              p.decoy, p.decoy_len, obs->pass, obs->fail);
        }
        if (opt->on_obs) { opt->on_obs(opt->on_obs_ctx, obs); }
        got = d2k_prop_majority(pass, opt->repeats);
        /* A local compile/apply/send refusal is not an answer from the box. */
        if (!local_err) apply_set(&res->props, pp[i].set, got, &p);
        /* Находку, которую план не выражает (фильтр дерева, d2k_opts.accept),
         * не берём и не останавливаемся: ответ уже в векторе, а следующие
         * вопросы могут найти выразимый приём — в переборе их может не быть. */
        if (got && d2k_opts_acceptable(opt, &p)) {
            *hit = p;
            return 1;
        }
    }
    /* РАССТОЯНИЕ ДО КОРОБКИ — ПОСЛЕДНИЙ ВОПРОС ОПРОСА (23.10.2026).
     *
     * Последний по цене: он стоит нескольких зондов, тогда как каждый вопрос
     * выше — одного-трёх, и спрашивать его раньше значило бы платить за него
     * на целях, которые берёт первый же дешёвый приём.
     *
     * ЗНАНИЕ ИЗ КАТАЛОГА ПОИСК ОТМЕНЯЕТ, НО НЕ ДОКАЗАТЕЛЬСТВО. Расстояние —
     * свойство коробки, и измеренное один раз, оно верно для всех её целей:
     * искать его заново — те же зонды впустую. Но «коробка в 12 хопах» не
     * значит «фальшивка с TTL 12 снимает блок ЗДЕСЬ И СЕЙЧАС»: приём обязан
     * пройти на проводе (§0.1), поэтому одна гипотеза с известным числом
     * задаётся. Три зонда вместо девятнадцати гипотез запасного перебора. */
    if (opt->known.hops > 0) {
        d2k_poison kp;
        int kb = opt->known.validates_checksum != D2K_PROP_YES;
        res->props.hop_ttl = opt->known.hops;
        memset(&kp, 0, sizeof kp);
        kp.ttl = opt->known.hops;
        kp.badsum = kb ? 1 : 0;
        snprintf(kp.name, sizeof kp.name, kb ? "badsum+ttl-%d" : "ttl-%d", opt->known.hops);
        /* ОПРОВЕРГНУТОЕ ИМЯ НЕ ПРОВЕРЯЕМ ВОВСЕ. Зонд здесь покупает ровно одно
           — доказательство на проводе для кандидата, и если этого кандидата
           опрос больше не предлагает (доспрос пришёл с его именем в skip),
           то зонд повторяет проваленный опыт. Расстояние при этом остаётся в
           векторе: оно знание из каталога, а не находка этого зонда. */
        if (!d2k_opts_skipped(opt, kp.name) && !d2k_detect_stopped(&opt->cancel) &&
            hop_step(ip4, family, port, tr, opt, res, opt->known.hops, opt->repeats,
                     kb) > 0) {
            if (d2k_opts_acceptable(opt, &kp)) { *hit = kp; return 1; }
        }
    } else if (!d2k_detect_stopped(&opt->cancel)) {
        int hops = d2k_hop_search(ip4, family, port, tr, opt, res);
        if (hops > 0) {
            /* Последний шаг поиска прошёл единогласно — это и есть
               доказательство на проводе, второй раз его не покупаем. */
            d2k_poison hp;
            int hb = res->props.validates_checksum == D2K_TRI_FALSE;
            memset(&hp, 0, sizeof hp);
            hp.ttl = hops;
            hp.badsum = hb ? 1 : 0;
            snprintf(hp.name, sizeof hp.name, hb ? "badsum+ttl-%d" : "ttl-%d", hops);
            /* Измерение остаётся в векторе и тогда, когда имя опровергнуто:
               деление отрезка — замер свойства коробки, а не этот кандидат. */
            if (!d2k_opts_skipped(opt, hp.name) && d2k_opts_acceptable(opt, &hp)) {
                *hit = hp;
                return 1;
            }
        }
    }
    return 0;
}

static int tri_no(d2k_tri t)  { return t == D2K_TRI_FALSE; }
static int tri_yes(d2k_tri t) { return t == D2K_TRI_TRUE; }

/* composeFromProps строит кандидатов ИЗ ВЕКТОРА, а не берёт из списка.
 *
 * Правила размещения взяты из дампов боевых плеч, а не из головы: фальшивка
 * идёт отдельной посылкой ПЕРЕД перекрытием, приманкой служит целое
 * приветствие, а не огрызок, и число копий имеет порог. */
int d2k_compose_from_props(const d2k_dprops *pr, const uint8_t *ctl, size_t ctl_len,
                           d2k_poison *out, int cap)
{
    d2k_poison base;
    int n = 0, i;

    memset(&base, 0, sizeof(base));
    /* Битую сумму пробуем и когда свойство НЕ ИЗМЕРЕНО: раньше здесь стояло
     * «нет», которое при «не измерено» давало ложь и выключало единственный
     * признак, работающий на коробках, не сверяющих сумму. */
    base.badsum = !tri_yes(pr->validates_checksum);
    /* ИЗМЕРЕННОЕ РАССТОЯНИЕ — В КАЖДУЮ СОБРАННУЮ ФАЛЬШИВКУ (23.10.2026).
     *
     * Фальшивка должна дойти до коробки и умереть перед сервером. Пока
     * расстояние не измерялось, собранные кандидаты шли БЕЗ TTL вовсе: они
     * держались только на том, что сервер отбросит их по битой сумме, а
     * коробка — нет. Теперь расстояние известно (d2k_hop_search либо запись
     * коробки), и фальшивка до сервера просто не доезжает — это и есть
     * механизм, который прежде изображали девятнадцать гипотез с готовыми
     * значениями TTL.
     *
     * Ноль — не измерено, и тогда поле остаётся нулём: выдумывать расстояние
     * нельзя, фальшивка с неверным TTL либо не дойдёт до коробки, либо
     * сломает поток у сервера. */
    if (pr->hop_ttl > 0) { base.ttl = pr->hop_ttl; }
    if (tri_yes(pr->parses_l7)) {
        base.decoy_hello = 1;
    }

    /* Дубликаты считаются как ретрансмиты — значит серия работает там, где
     * одиночная копия нет. Порог замерен: семь вплотную либо два с паузой. */
    if (tri_yes(pr->counts_duplicates) && n + 2 <= cap) {
        out[n] = base;
        snprintf(out[n].name, sizeof(out[n].name), "СОБРАНО: серия с паузой");
        out[n].repeats = 2;
        out[n].gap_ms = 20;
        n++;
        out[n] = base;
        snprintf(out[n].name, sizeof(out[n].name), "СОБРАНО: плотная серия");
        out[n].repeats = 7;
        n++;
    }

    /* Левое перекрытие не подрезается — добавляем его к фальшивке. Длину
     * берём равной приманке: в неё ложится целое приветствие. */
    if (tri_no(pr->tolerates_left_overlap) && n < cap) {
        out[n] = base;
        snprintf(out[n].name, sizeof(out[n].name), "СОБРАНО: фальшивка + перекрытие");
        out[n].seqovl_exact = 1;
        out[n].decoy_hello = 1;
        out[n].repeats = 7;
        n++;
    }

    /* Порядок не держит — добавляем сбитый порядок к тому же. */
    if (tri_no(pr->tolerates_reorder) && n < cap) {
        out[n] = base;
        snprintf(out[n].name, sizeof(out[n].name), "СОБРАНО: фальшивка + порядок");
        out[n].disorder = 1;
        out[n].repeats = 7;
        n++;
    }

    /* СРОЧНЫЙ БАЙТ КОРОБКА НЕ УЧИТЫВАЕТ — вставляем его в середину имени.
     * Фальшивки здесь нет и быть не может: приём не травит буфер, а ломает
     * РАЗБОР имени, и сервер тот же байт из потока уберёт сам. Поэтому
     * кандидат собирается не из base, а чистым. */
    if (tri_no(pr->handles_urgent) && n < cap) {
        memset(&out[n], 0, sizeof(out[n]));
        snprintf(out[n].name, sizeof(out[n].name), "СОБРАНО: срочный байт");
        out[n].oob = 1;
        n++;
    }

    /* Ничего одиночного не сработало — пробуем всё вместе. Это последний
     * собранный кандидат перед падением в перебор. */
    if (n == 0 && cap > 0) {
        memset(&out[0], 0, sizeof(out[0]));
        snprintf(out[0].name, sizeof(out[0].name), "СОБРАНО: всё сразу");
        out[0].badsum = 1;
        out[0].decoy_hello = 1;
        out[0].seqovl_exact = 1;
        out[0].disorder = 1;
        out[0].repeats = 7;
        /* И здесь измеренное расстояние, если оно есть: «всё сразу» — тоже
           фальшивка, и ей тоже незачем доезжать до сервера. */
        if (pr->hop_ttl > 0) { out[0].ttl = pr->hop_ttl; }
        n = 1;
    }

    for (i = 0; i < n; i++) {
        if (out[i].decoy_hello) {
            out[i].decoy = ctl;
            out[i].decoy_len = ctl_len;
            if (out[i].seqovl_exact) {
                out[i].seqovl = (int)ctl_len;
            }
        }
    }
    return n;
}

/* This question uses raw episodes, not a poison candidate: it cannot be
 * represented by prop_set. Both successful carry and measured NO are known.
 * The caller has selected the compatible box/client shape; this does not
 * prove application success on the new target. An alternate ClientHello
 * must be measured again because the box record does not contain its name. */
int d2k_preflight_known(const d2k_box_props *k, d2k_preflight_meas *m, int *verdict)
{
    if (k->response_gate != D2K_PROP_YES ||
        (k->gate_carry != D2K_PROP_NO && k->gate_carry != D2K_PROP_YES)) return 0;
    if (k->gate_carry == D2K_PROP_YES &&
        (!k->gate_window || !k->gate_pieces || !k->gate_rtt_ms ||
         k->gate_hello_own != D2K_PROP_YES)) return 0;
    memset(m, 0, sizeof *m);
    m->response_gate = 1;
    /* pieces_pass also witnesses the hello source at the bridge. A prior
     * conflict can erase that tri without erasing the measured window. */
    m->pieces_pass = k->gate_window != 0 &&
        (k->gate_hello_own == D2K_PROP_NO || k->gate_hello_own == D2K_PROP_YES);
    m->window = k->gate_window;
    m->pieces_needed = k->gate_pieces;
    m->carry_over_rst = k->gate_carry == D2K_PROP_YES;
    m->hello_own = k->gate_hello_own == D2K_PROP_YES;
    m->rtt_ms = k->gate_rtt_ms;
    *verdict = m->carry_over_rst;
    if (!*verdict) snprintf(m->reason, sizeof m->reason, "известный промах: перенос через RST не наступил");
    return 1;
}
