/* hello.c — вид приветствия, координаты имени, сборка холодного старта.
 *
 * ЭТАЛОН — datapath/tls.c, прочитан целиком перед этим файлом. Та же
 * дисциплина границ на КАЖДОМ поле: длина, объявленная где-то в потоке
 * («claimed» — конец записи по её собственному заголовку, обещание
 * отправителя) и длина того, что реально пришло («avail» — n аргумента).
 * Поле, не влезающее в claimed, — противоречие: разметка сама с собой
 * спорит, довериться ей нельзя. Поле, не влезающее в avail, — обрывок:
 * остальное не пришло, и это нормально. Спутать их нельзя — тот же довод,
 * что в tls.c: либо теряется каждый браузер (запись режется на два
 * сегмента), либо принимается любая подделка.
 *
 * Копипасты из tls.c здесь нет: core/ и datapath/ — разные цели сборки (свои
 * Makefile, свои бинарники — то же решение уже принято в core/quic.c).
 * Второй, параллельный разбор той же грамматики ClientHello поддерживается
 * здесь по одной причине: этому разбору, в отличие от tls.c, нужен ЕЩЁ вид
 * приветствия — и ради него он не останавливается на первом же найденном
 * расширении, как это законно делает find_sni в tls.c. supported_versions
 * может обнаружиться и до, и после server_name (test_hello.c: настоящее
 * приветствие openssl несёт его ПОСЛЕ), и цикл обязан долистать весь блок,
 * а не вернуться при первом совпадении.
 *
 * ПРОФИЛИ (core/profiles/, файлы *.hex) встраиваются В БИНАРНИК на сборке —
 * core/Makefile вырезает из текстового файла комментарии и пробелы и
 * оставляет чистую шестнадцатеричную строку в core/hello_profiles.inc (в
 * git не идёт, см. .gitignore: это вывод сборки, а не источник). Причина —
 * не эстетика: сигнатура d2k_hello_from_profile не принимает путь к файлу
 * (см. d2k_hello.h), а бинарники этого проекта — статические под musl без
 * гарантированной файловой системы конкретной раскладки (MIPS/ARM роутер).
 * Декодируются они лениво и один раз в статический буфер фиксированного
 * размера — тот же приём, что d2k_quic_arm_blob в props.c, и по той же
 * причине: это не пакетный путь датапата, а измерительный код, вызываемый
 * на первом контакте с целью, а не на каждом пакете.
 */
#include <string.h>

#include "d2k_hello.h"

#define REC_HDR         5
#define HS_HDR          4
#define TLS_HANDSHAKE   0x16
#define HS_CLIENT_HELLO 0x01
#define EXT_SERVER_NAME        0x0000
#define EXT_SUPPORTED_VERSIONS 0x002b
#define SNI_HOST_NAME   0x00
#define TLS13_VERSION   0x0304

/* Многобайтовые поля — побайтно и в сетевом порядке: MIPS и ARM не
 * гарантируют выравнивание, наложение структуры на буфер здесь запрещено
 * ровно так же, как в tls.c и quic.c. */
static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}
static uint32_t rd24(const uint8_t *p) {
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}
static void wr16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}
static void wr24(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 16);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)v;
}

/* Как в datapath/tls.c: 0 — поле с однобайтовым/двухбайтовым префиксом
 * длины целиком помещается в end, -1 — нет. */
static int skip_u8_vec(const uint8_t *b, size_t end, size_t *off) {
    if (*off + 1 > end) {
        return -1;
    }
    size_t n = b[*off];
    if (*off + 1 + n > end) {
        return -1;
    }
    *off += 1 + n;
    return 0;
}
static int skip_u16_vec(const uint8_t *b, size_t end, size_t *off) {
    if (*off + 2 > end) {
        return -1;
    }
    size_t n = rd16(b + *off);
    if (*off + 2 + n > end) {
        return -1;
    }
    *off += 2 + n;
    return 0;
}

/* Всё, что разбор способен утверждать про один блоб — только координаты,
 * байты не копируются и не пересобираются нигде на этом пути. */
typedef struct {
    int parsed;   /* дошли до конца обязательных полей ClientHello (по
                     client_version..compression_methods включительно).
                     Без этого ничего ниже не имеет смысла — см.
                     D2K_SHAPE_UNKNOWN в d2k_hello.h. */
    int complete; /* рукопожатие ПО ЕГО ЖЕ длине из заголовка целиком
                     поместилось в n. Нужно только сборке (splice_sni):
                     разбору вида и поиску имени, как в tls.c, достаточно
                     того, что реально пришло. */

    size_t rec_len_off; /* смещение 2-байтной длины TLS-записи */
    size_t hs_len_off;  /* смещение 3-байтной длины ClientHello */

    int    have_exts;
    size_t exts_len_off; /* смещение 2-байтной длины блока расширений */

    int have_tls13; /* нашли supported_versions (0x002b), и среди
                        перечисленных в нём версий есть 0x0304 */

    int    have_sni;
    size_t sni_ext_len_off;  /* длина расширения server_name (2 байта) */
    size_t sni_list_len_off; /* длина ServerNameList (2 байта) */
    size_t sni_name_len_off; /* длина самого имени (2 байта) */
    size_t sni_name_off;     /* первый байт имени */
    size_t sni_name_len;
} hello_layout;

static void parse_hello(const uint8_t *b, size_t n, hello_layout *L) {
    memset(L, 0, sizeof *L);
    if (!b || n < 3) {
        return;
    }
    /* Версия записи TLS проверяется грубо — 0x03xx, как в tls.c: этого
       достаточно, чтобы отличить запись от произвольного мусора. */
    if (b[1] != 0x03) {
        return;
    }
    if (n < REC_HDR) {
        return;
    }
    if (b[0] != TLS_HANDSHAKE) {
        return;
    }

    size_t rec_len = rd16(b + 3);
    L->rec_len_off = 3;
    const size_t claimed = REC_HDR + rec_len; /* обещание отправителя */
    const size_t avail = n;                   /* что реально пришло */
    size_t end = claimed < avail ? claimed : avail;

    size_t off = REC_HDR;
    if (off + HS_HDR > end) {
        return;
    }
    if (b[off] != HS_CLIENT_HELLO) {
        return;
    }
    size_t hs_len = rd24(b + off + 1);
    L->hs_len_off = off + 1;
    off += HS_HDR;
    if (off + hs_len > claimed) {
        return; /* рукопожатие не влезает даже в собственную запись */
    }
    size_t hs_end = off + hs_len;
    L->complete = (hs_end <= avail);
    if (!L->complete) {
        hs_end = avail; /* дальше только то, что реально пришло */
    }

    /* client_version(2) + random(32) */
    if (off + 2 + 32 > hs_end) {
        return;
    }
    off += 2 + 32;

    if (skip_u8_vec(b, hs_end, &off) != 0) {  /* legacy_session_id */
        return;
    }
    if (skip_u16_vec(b, hs_end, &off) != 0) { /* cipher_suites */
        return;
    }
    if (skip_u8_vec(b, hs_end, &off) != 0) {  /* compression_methods */
        return;
    }

    /* Обязательные поля кончились — дальше ClientHello подтверждён
       независимо от того, есть ли расширения вообще (см. LEGACY без
       supported_versions в d2k_hello.h). */
    L->parsed = 1;

    if (off + 2 > hs_end) {
        return; /* расширений нет вовсе — законный ClientHello без имени */
    }
    size_t exts_len = rd16(b + off);
    L->exts_len_off = off;
    L->have_exts = 1;
    off += 2;
    if (off + exts_len > claimed) {
        return; /* блок расширений спорит сам с собой */
    }
    size_t exts_end = off + exts_len;
    if (exts_end > hs_end) {
        exts_end = hs_end; /* влезает в запись, не в пришедшее */
    }

    /* Отличие от find_sni в tls.c: цикл не возвращается на первом же
       совпадении — нужны ОБА признака (SNI и вид), а порядок расширений у
       реальных клиентов не гарантирован. Первая же несостыковка всё равно
       останавливает разбор насовсем ("break", не "продолжить со
       следующего") — наполовину прочитанное расширение не даёт права на
       смещение, ровно как в tls.c. */
    size_t p = off;
    while (p + 4 <= exts_end) {
        uint16_t etype = rd16(b + p);
        size_t elen = rd16(b + p + 2);
        size_t edata = p + 4;
        if (edata + elen > exts_end) {
            break; /* расширение объявило себя больше блока */
        }

        if (etype == EXT_SERVER_NAME && !L->have_sni) {
            size_t q = edata;
            if (q + 2 <= edata + elen) {
                size_t list_len = rd16(b + q);
                size_t list_len_off = q;
                q += 2;
                size_t list_end = q + list_len;
                if (list_end <= edata + elen) {
                    while (q + 3 <= list_end) {
                        uint8_t nt = b[q];
                        size_t nlen = rd16(b + q + 1);
                        size_t name_len_off = q + 1;
                        size_t name_off = q + 3;
                        if (name_off + nlen > list_end) {
                            break; /* имя не помещается в список */
                        }
                        if (nt == SNI_HOST_NAME && nlen > 0) {
                            /* Пустое имя — не имя, как в tls.c. */
                            L->have_sni = 1;
                            L->sni_ext_len_off = p + 2;
                            L->sni_list_len_off = list_len_off;
                            L->sni_name_len_off = name_len_off;
                            L->sni_name_off = name_off;
                            L->sni_name_len = nlen;
                            break;
                        }
                        q = name_off + nlen;
                    }
                }
            }
        } else if (etype == EXT_SUPPORTED_VERSIONS) {
            /* RFC 8446 §4.2.1: список версий с ОДНОБАЙТНЫМ префиксом длины
               (максимум 254 укладывается в байт), каждая версия — 2 байта. */
            if (elen >= 1) {
                size_t list_len = b[edata];
                if (1 + list_len <= elen) {
                    size_t q = edata + 1;
                    size_t vend = q + list_len;
                    while (q + 2 <= vend) {
                        if (rd16(b + q) == TLS13_VERSION) {
                            L->have_tls13 = 1;
                        }
                        q += 2;
                    }
                }
            }
        }
        p = edata + elen;
    }
}

d2k_shape d2k_hello_shape(const uint8_t *b, size_t n) {
    hello_layout L;
    parse_hello(b, n, &L);
    if (!L.parsed) {
        return D2K_SHAPE_UNKNOWN;
    }
    return L.have_tls13 ? D2K_SHAPE_MODERN : D2K_SHAPE_LEGACY;
}

int d2k_hello_sni(const uint8_t *b, size_t n, size_t *off, size_t *len) {
    if (!off || !len) {
        return -1;
    }
    hello_layout L;
    parse_hello(b, n, &L);
    if (!L.parsed || !L.have_sni) {
        return -1;
    }
    *off = L.sni_name_off;
    *len = L.sni_name_len;
    return 0;
}

/* =========================================================================
 * Сборка приветствия холодного старта из профиля.
 * ========================================================================= */

/* Верхняя граница шаблона профиля. Приветствие браузера с постквантовым
 * key_share уходит за полтора килобайта (см. модель для profiles/modern.hex:
 * 1530 байт) — запас взят тем же порядком величины, что test_tls.c держит
 * для той же цели (uint8_t big[4096]). */
#define TEMPLATE_MAX 4096

/* Заменяет имя на sni ЛЮБОЙ длины (короче или длиннее старого — дельта может
 * быть и отрицательной) и пересчитывает ВСЕ объемлющие длины одной и той же
 * дельтой. Это ровно то место, о котором предупреждает бриф задачи: пропуск
 * любого звена цепочки не виден глазом — приветствие останется похожим на
 * валидное, но коробка (или наш же повторный разбор) увидит рассинхрон
 * между тем, что заявлено, и тем, что лежит по факту.
 *
 * tmpl обязан быть ЦЕЛЫМ (complete) приветствием: шаблон профиля — не
 * снятый на живую линию обрывок, а то, что мы сами собираемся послать
 * целиком, и посылать "досюда, а дальше не знаем" смысла не имеет. */
static int splice_sni(const uint8_t *tmpl, size_t tmpl_len,
                       const char *name, size_t name_len,
                       uint8_t *out, size_t cap, size_t *out_len) {
    hello_layout L;
    parse_hello(tmpl, tmpl_len, &L);
    if (!L.parsed || !L.complete || !L.have_sni) {
        return -1; /* шаблон профиля неисправен — вина не вызывающего */
    }

    /* sni_name_len всегда целиком внутри tmpl_len (это его же под-диапазон),
       поэтому вычитание не уходит в отрицательное. */
    size_t before = tmpl_len - L.sni_name_len;
    size_t new_total = before + name_len;
    if (new_total > cap) {
        return -1;
    }

    memmove(out, tmpl, L.sni_name_off);
    memmove(out + L.sni_name_off, name, name_len);
    memmove(out + L.sni_name_off + name_len,
            tmpl + L.sni_name_off + L.sni_name_len,
            tmpl_len - (L.sni_name_off + L.sni_name_len));

    /* Старое значение читается из tmpl (нетронутого оригинала), новое
       пишется в out — так корректность не зависит от порядка memmove выше. */
    long delta = (long)name_len - (long)L.sni_name_len;
    wr16(out + L.sni_name_len_off,
         (uint16_t)((long)rd16(tmpl + L.sni_name_len_off) + delta));
    wr16(out + L.sni_list_len_off,
         (uint16_t)((long)rd16(tmpl + L.sni_list_len_off) + delta));
    wr16(out + L.sni_ext_len_off,
         (uint16_t)((long)rd16(tmpl + L.sni_ext_len_off) + delta));
    if (L.have_exts) {
        wr16(out + L.exts_len_off,
             (uint16_t)((long)rd16(tmpl + L.exts_len_off) + delta));
    }
    wr24(out + L.hs_len_off,
         (uint32_t)((long)rd24(tmpl + L.hs_len_off) + delta));
    wr16(out + L.rec_len_off,
         (uint16_t)((long)rd16(tmpl + L.rec_len_off) + delta));

    *out_len = new_total;
    return 0;
}

/* core/hello_profiles.inc — сгенерирован из profiles/ (*.hex) Makefile'ом (см.
 * шапку файла и правило hello_profiles.inc в core/Makefile). Объявляет
 * d2k_profile_modern_hex[] / d2k_profile_legacy_hex[] — NUL-терминированные
 * строки из ЧИСТЫХ шестнадцатеричных цифр (комментарии и пробелы уже
 * вырезаны на сборке). Лежит в той же директории, что и этот файл, поэтому
 * находится через "" без дополнительного -I. */
#include "hello_profiles.inc"

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/* Декодирует строку из ЧИСТЫХ шестнадцатеричных цифр в байты. Генератор в
 * core/Makefile уже гарантирует чётную длину и валидные символы для ДВУХ
 * встроенных профилей — но эта функция не доверяет буферу до проверки НИ
 * для чьих данных, включая собственные встроенные: дисциплина проекта одна
 * на все входы, а не "для чужих полная, для своих на глаз". */
static int hex_decode(const char *hex, size_t hexlen, uint8_t *out, size_t cap, size_t *out_len) {
    if (hexlen % 2 != 0) {
        return -1;
    }
    size_t n = hexlen / 2;
    if (n > cap) {
        return -1;
    }
    for (size_t i = 0; i < n; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = n;
    return 0;
}

/* Профиль декодируется лениво и один раз в статический буфер — тот же
 * приём, что g_blob_shaped/g_blob_shaped_ready в props.c (d2k_quic_arm_blob),
 * и по той же причине: не пакетный путь, незачем повторять decode на
 * каждый вызов d2k_hello_from_profile. */
static uint8_t g_profile_modern[TEMPLATE_MAX];
static size_t  g_profile_modern_len;
static int     g_profile_modern_ready;

static uint8_t g_profile_legacy[TEMPLATE_MAX];
static size_t  g_profile_legacy_len;
static int     g_profile_legacy_ready;

int d2k_hello_from_profile(d2k_shape s, const char *sni, uint8_t *out, size_t cap, size_t *out_len) {
    if (!sni || !out || !out_len) {
        return -1;
    }
    size_t name_len = strlen(sni);
    if (name_len == 0) {
        return -1; /* пустое имя — не имя, как в tls.c */
    }

    const uint8_t *tmpl;
    size_t tmpl_len;
    if (s == D2K_SHAPE_MODERN) {
        if (!g_profile_modern_ready) {
            if (hex_decode(d2k_profile_modern_hex, sizeof(d2k_profile_modern_hex) - 1,
                            g_profile_modern, sizeof g_profile_modern, &g_profile_modern_len) != 0) {
                return -1;
            }
            g_profile_modern_ready = 1;
        }
        tmpl = g_profile_modern;
        tmpl_len = g_profile_modern_len;
    } else if (s == D2K_SHAPE_LEGACY) {
        if (!g_profile_legacy_ready) {
            if (hex_decode(d2k_profile_legacy_hex, sizeof(d2k_profile_legacy_hex) - 1,
                            g_profile_legacy, sizeof g_profile_legacy, &g_profile_legacy_len) != 0) {
                return -1;
            }
            g_profile_legacy_ready = 1;
        }
        tmpl = g_profile_legacy;
        tmpl_len = g_profile_legacy_len;
    } else {
        return -1; /* UNKNOWN — профиля для него не бывает */
    }
    if (tmpl_len == 0) {
        return -1; /* профиль этого вида не снят (см. предупреждение в .hex) */
    }

    return splice_sni(tmpl, tmpl_len, sni, name_len, out, cap, out_len);
}
