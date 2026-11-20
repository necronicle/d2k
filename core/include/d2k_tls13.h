/* d2k_tls13.h — минимальный клиент TLS 1.3 (RFC 8446).
 *
 * ЗАЧЕМ ОН НУЖЕН И ЧЕГО НЕ ДЕЛАЕТ.
 *
 * Проба на блокировку по объёму (core/volume.c) обязана гнать объём ВНУТРИ
 * настоящей сессии: коробка считает байты установленного потока, а мусор на
 * 443-м порту сервер оборвёт сам — и мерить станет нечего. Отсюда клиент.
 *
 * Он НЕ проверяет сертификат и не будет: измеряется реакция КОРОБКИ на линии,
 * а не подлинность сервера, и мы сами подставляем имя, к которому сертификат
 * заведомо может не относиться. Через него не ходят ничьи данные, кроме
 * нашего же мусора для накачки объёма. Использовать его как транспорт для
 * чего-либо ещё нельзя — не потому что «недоделан», а потому что проверка
 * подлинности в его задачу не входит по построению.
 *
 * Поддерживается ровно одна связка: TLS 1.3, X25519, TLS_AES_128_GCM_SHA256.
 * Не «пока»: это то, что предлагает живой клиент на этой линии, а каждая
 * лишняя связка — это ещё одна ветка криптографии, которую придётся держать
 * верной без повода. Сервер, не согласившийся на неё, — законный отказ.
 */
#ifndef D2K_TLS13_H
#define D2K_TLS13_H

#include <stddef.h>
#include <stdint.h>
#include "d2k_tls13core.h"

typedef struct d2k_tls d2k_tls;
typedef struct d2k_tls_probe_seed d2k_tls_probe_seed;
/* Own random/key material for one controlled measurement episode. Reuse only
 * to keep ClientHello bytes fixed across its experiments, never for ordinary
 * user sessions. Does not reset the peer/network. Free wipes this storage. */
d2k_tls_probe_seed *d2k_tls_probe_seed_new(void);
void d2k_tls_probe_seed_free(d2k_tls_probe_seed *);
/* Copy public ClientHello random; private key material is never exposed. */
int d2k_tls_probe_seed_random(const d2k_tls_probe_seed *,uint8_t out[32]);
/* Exact first TLS record used by connect_probe for these inputs. No IO;
 * contains public handshake bytes only. Zero means invalid input/capacity. */
size_t d2k_tls_probe_hello(const d2k_tls_probe_seed *,const char *,size_t,
    const uint8_t *,size_t,uint8_t *,size_t);

/* Ordered byte stream supplied by a measurement transport. Descriptor is
 * copied; context stays borrowed until tls_free. read returns 1..cap bytes,
 * zero for EOF or -1 with reason; wait_ms is the remaining deadline.
 * write submits all bytes or returns -1. Neither callback owns TLS state.
 * No socket operations or implicit transport close occur on this path. */
typedef struct {
    void *context;
    long (*read)(void *,uint8_t *,size_t,int,char *,size_t);
    int (*write)(void *,const uint8_t *,size_t,char *,size_t);
} d2k_tls_io;
/* TLS1.3 only, explicit ALPN list (zero length means no ALPN). This is the
 * existing measurement client, with the same authentication limitations. */
int d2k_tls_connect_io(const d2k_tls_io *,const char *,int,size_t,
    const uint8_t *,size_t,d2k_tls **,char *,size_t);
/* РУКОПОЖАТИЕ НА ФОРМЕ КЛИЕНТА (ТЗ §4.3, §11.1). form — запись TLS с
 * ClientHello клиента; уходят его байты, где заменены только Random,
 * session_id и открытые ключи key_share (X25519, X25519MLKEM768, P-256 —
 * свои ключи; прочие группы — свои случайные байты). Шифр — 0x1301..0x1303 по выбору сервера. sni —
 * имя цели для сверки сертификата (имя в форме не меняется). fd или
 * io (io — транспорт опыта, тогда fd < 0). Отказ: форма не разбирается,
 * возобновление сессии, HelloRetryRequest, группа без нашего ключа. */
int d2k_tls_connect_form(int fd, const d2k_tls_io *io, const char *sni,
    const uint8_t *form, size_t form_len, int deadline_ms, d2k_tls **out,
    char *err, size_t errcap);
/* Группа key_share, выбранная сервером в режиме формы; 0 — неизвестно. */
int d2k_tls_group(const d2k_tls *);
/* Исход последнего чтения сокета в этом потоке: 0, ETIMEDOUT, -1 (FIN), errno. */
int d2k_tls_last_read_errno(void);
/* Протокол, выбранный сервером по ALPN (например "h2", "http/1.1"); "" — не согласован. */
const char *d2k_tls_alpn(const d2k_tls *);
int d2k_tls_connect_probe(const d2k_tls_io *,const d2k_tls_probe_seed *,const char *,int,size_t,
    const uint8_t *,size_t,d2k_tls **,char *,size_t);

/* Поднимает сессию поверх УЖЕ ПОДКЛЮЧЁННОГО сокета fd. sni — имя, которое
 * предъявляем (пустое — без расширения имени). deadline_ms — потолок на всё
 * рукопожатие.
 *
 * Владения сокетом НЕ берёт: закрывает его вызывающий, и после d2k_tls_free
 * сокет остаётся открытым. 0 — сессия установлена, -1 — отказ с причиной в
 * err (заполняется всегда и по-человечески). */
/* want_wire — ПРОВОДНАЯ длина, до которой добивается наше приветствие
 * (расширение padding, RFC 7685); 0 — не добивать. Нужна затем, что зонд
 * ходит своим приветствием, вчетверо короче браузерного, и план, чьи куски
 * помещаются в посылку на коротком приветствии, на длинном не помещается
 * вовсе — подтверждение достаётся зонду, а не человеку. */
int d2k_tls_connect(int fd, const char *sni, int deadline_ms, size_t want_wire,
                    d2k_tls **out, char *err, size_t errcap);
/* То же, но ALPN — список КЛИЕНТА как на проводе (protocol_name_list без
 * длины); alpn_len 0 — без расширения ALPN, как у клиента без него. */
int d2k_tls_connect_alpn(int fd, const char *sni, int deadline_ms, size_t want_wire,
                         const uint8_t *alpn_list, size_t alpn_len,
                         d2k_tls **out, char *err, size_t errcap);
/* ECH rejection is an error, never an ordinary TLS success for public_name. */
int d2k_tls_connect_ech(int fd, const char *origin, const d2k_ech_config *config,
    int deadline_ms, size_t want_wire, d2k_tls **out, char *err, size_t errcap);
int d2k_tls_ech_accepted(const d2k_tls *t);

/* Шлёт n байт прикладными данными. Возвращает 0 или -1 с причиной. */
int d2k_tls_write(d2k_tls *t, const uint8_t *buf, size_t n, char *err, size_t errcap);

/* Читает до cap байт прикладных данных. Возвращает число прочитанных (>0),
 * 0 — сессия закрыта той стороной, -1 — отказ (в том числе тайм-аут).
 * Записи не-прикладных типов (смена шифра, тревога) обрабатываются внутри и
 * наружу не выдаются; тревога close_notify даёт 0, а не отказ. */
long d2k_tls_read(d2k_tls *t, uint8_t *buf, size_t cap, int wait_ms,
                  char *err, size_t errcap);

/* Совпало ли имя, которым представился сервер, с тем, что мы спросили:
 * 1 — да, 0 — НЕТ, -1 — сказать нечего (сертификата не видели, SAN не нашли,
 * разбор не сошёлся, имя не спрашивали).
 *
 * Это НЕ проверка подлинности: цепочка не строится, доверенных корней нет,
 * самоподписанный сертификат с нужным именем ответ 1 получит. Уровень
 * доказательства от неё не растёт (§4.2). Её задача одна: не записать в
 * «подтверждено» разговор с коробкой, которая терминирует TLS и отдаёт
 * страницу блокировки — для зонда это выглядит РОВНО как рабочий обход. */
/* Consumed TLS record bytes (including headers); missing is declared body only. */
uint16_t d2k_tls_version(const d2k_tls *t);
uint64_t d2k_tls_rx_wire_bytes(const d2k_tls *t);
uint32_t d2k_tls_rx_record_missing(const d2k_tls *t);

int  d2k_tls_peer_name(const d2k_tls *t);

void d2k_tls_free(d2k_tls *t);

#endif /* D2K_TLS13_H */
