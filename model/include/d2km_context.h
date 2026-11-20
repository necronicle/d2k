/* Цель и контекст цели (D2K_SPEC.md §2.1).
 *
 * Контекст — цель, транспорт, протокол и версия, форма обмена, семейство,
 * путь. Совместимые контексты различаются только полями формы, которые
 * модель коробки признала нечитаемыми для коробки (установленный факт). */
#ifndef D2KM_CONTEXT_H
#define D2KM_CONTEXT_H

#include <stddef.h>
#include <stdint.h>

#define D2KM_NAME_MAX 253
#define D2KM_SEGMENTS_MAX 16
#define D2KM_TCP_OPTIONS_MAX 40
#define D2KM_IFNAME_MAX 16

typedef enum { D2KM_TCP = 6, D2KM_UDP = 17 } d2km_transport;
typedef enum { D2KM_IPV4 = 4, D2KM_IPV6 = 6 } d2km_family;

/* §2.1, список версий протокола контекста. DNS — по UDP или TCP; DoT и DoH
 * идут контекстом TLS, а их прикладной контракт задаёт §9.5–§9.6. */
typedef enum {
    D2KM_P_TLS12 = 1,
    D2KM_P_TLS13,
    D2KM_P_QUIC1,
    D2KM_P_QUIC2,
    D2KM_P_HTTP11,
    D2KM_P_HTTP2,
    D2KM_P_HTTP3,
    D2KM_P_STUN,
    D2KM_P_DNS,
    D2KM_PROTOCOL_END
} d2km_protocol;

/* Цель: имя ИЛИ адрес + порт + протокол. Имя для цели без имени не
 * придумывается: has_name == 0 означает адресную цель. */
typedef struct {
    int has_name;
    char name[D2KM_NAME_MAX + 1];   /* нижний регистр, без завершающей точки */
    d2km_family family;             /* для адресной цели */
    uint8_t addr[16];               /* IPv4 — первые 4 байта, остальное нули */
    uint16_t port;                  /* для адресной цели */
} d2km_target;

/* Поля формы обмена — биты маски «нечитаемо для коробки». */
enum {
    D2KM_FORM_HELLO = 1u << 0,        /* байты приветствия */
    D2KM_FORM_SEGMENTS = 1u << 1,     /* размеры и порядок сегментов/датаграмм */
    D2KM_FORM_TCP_OPTIONS = 1u << 2,  /* опции TCP */
    D2KM_FORM_ECH = 1u << 3,
    D2KM_FORM_GREASE = 1u << 4,
    D2KM_FORM_ALL = (1u << 5) - 1
};

/* Форма — наблюдение, не ярлык. Байты приветствия хранятся отпечатком
 * (длина + FNV-1a 64): форма сравнивается, а не воспроизводится из
 * контекста; сами байты хранит наблюдение. */
typedef struct {
    uint32_t hello_length;
    uint64_t hello_print;
    uint8_t segment_count;
    uint16_t segments[D2KM_SEGMENTS_MAX];
    uint8_t tcp_options_length;
    uint8_t tcp_options[D2KM_TCP_OPTIONS_MAX];   /* виды опций в порядке клиента */
    uint8_t ech;
    uint8_t grease;
} d2km_form;

typedef struct {
    char ifname[D2KM_IFNAME_MAX];
    uint16_t mtu;
} d2km_path;

typedef struct {
    d2km_target target;
    d2km_transport transport;
    d2km_protocol protocol;
    d2km_family family;
    d2km_form form;
    d2km_path path;
} d2km_context;

/* Нормализует имя: нижний регистр, без завершающей точки; буквы, цифры,
 * '-', '_' и точки; метки 1..63; длина 1..253. 0 — успех, -1 — ошибка. */
int d2km_target_name(d2km_target *, const char *name);
/* Адресная цель. 0 — успех, -1 — ошибка (семейство, порт 0). */
int d2km_target_address(d2km_target *, d2km_family, const uint8_t *addr,
                        uint16_t port);

/* Совпадение суффикса на границе метки: "a.example.com" ~ "example.com",
 * "badexample.com" !~ "example.com". Оба имени уже нормализованы. */
int d2km_name_suffix_match(const char *name, const char *suffix);

/* Заполняет форму из наблюдённого приветствия. segments/options — как у
 * клиента. 0 — успех, -1 — ошибка или превышение пределов. */
int d2km_form_set(d2km_form *, const uint8_t *hello, size_t hello_length,
                  const uint16_t *segments, size_t segment_count,
                  const uint8_t *tcp_options, size_t tcp_options_length,
                  int ech, int grease);

/* Проверяет согласованность контекста (цель, транспорт и протокол,
 * семейство адресной цели). 0 — годен, -1 — нет. */
int d2km_context_valid(const d2km_context *);

/* Поля, которые различают a и b: маска D2KM_FORM_* для формы и
 * D2KM_CTX_OTHER, если различаются поля вне формы. */
#define D2KM_CTX_OTHER (1u << 16)
unsigned d2km_context_diff(const d2km_context *a, const d2km_context *b);

/* Совместимы, если различаются только поля формы из unread (маска
 * D2KM_FORM_*, полученная из установленных фактов модели). */
int d2km_context_compatible(const d2km_context *a, const d2km_context *b,
                            unsigned unread);

/* Каноническая запись контекста: побайтно одинакова для равных контекстов,
 * не зависит от выравнивания структур. Возвращает нужную длину; при
 * cap < длины ничего не пишет за пределы cap. */
size_t d2km_context_encode(const d2km_context *, uint8_t *out, size_t cap);

uint64_t d2km_fnv1a64(const uint8_t *, size_t);
const char *d2km_protocol_name(d2km_protocol);

#endif
