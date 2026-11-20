/* d2k_verify.h — подтверждение работоспособности без ложного успеха.
 *
 * ПОЧЕМУ ПРЕЖНЕГО ПОРОГА НЕ ХВАТАЛО. Успехом считался внешний тип записи TLS
 * 23 («прикладные данные») в событии обмена. В TLS 1.3 это не признак работы
 * приложения: наружу типом 23 едет ВЕСЬ второй полёт рукопожатия — смена
 * шифра, расширения, сертификат, подпись, Finished (RFC 8446 §5.2), а
 * настоящий тип записи лежит ВНУТРИ шифротекста и наблюдателю на проводе не
 * виден. «Сервер что-то ответил» читалось как «приложение работает», и
 * кандидат, который довёл дело только до ответа коробки, записывался в
 * каталог как рабочий.
 *
 * ПОЧЕМУ ПОВТОР СНЯТОГО ПРИВЕТСТВИЯ НЕ ГОДИТСЯ В ДОКАЗАТЕЛЬСТВА. Приветствие
 * чужой сессии (§4: измерительный прибор) отправить можно, а завершить по
 * нему рукопожатие нельзя никогда: закрытого ключа того клиента у нас нет, и
 * дальше чужого второго полёта дело не пойдёт по устройству, а не по
 * невезению. Поэтому доказательство ведёт СВОЁ рукопожатие своим ключом
 * (core/tls13.c) и доводит обмен до настоящего ответа приложения.
 *
 * ПЯТЬ РЕЗУЛЬТАТОВ, КОТОРЫЕ НЕЛЬЗЯ СЛИВАТЬ. Каждый следующий — строго больше
 * предыдущего, и ни один не подменяет соседа:
 *
 *   не измерено  — обращения не было вовсе, про линию не сказано НИЧЕГО
 *                  (§2.4: это не «нет», и ноль не превращается в диагноз);
 *   транспорт    — TCP встал, дальше не пошло. Сюда попадает и сервер,
 *                  ответивший «HTTP/1.1 200 OK» открытым текстом: ответ был,
 *                  доказательства нет;
 *   рукопожатие  — НАШЕ рукопожатие TLS 1.3 завершено нашим ключом, но
 *                  приложение молчит;
 *   приложение   — получен конечный HTTP-ответ вместе с полным телом; одноимённые
 *                  редиректы проверяются на той же TLS-сессии;
 *   challenge    — Cloudflare явно прислал cf-mitigated: challenge. Ответ
 *                  дошёл до HTTP, но это не доказательство полезного обхода.
 *
 * Уровень «приложение» доказывает завершённый HTTP-обмен внутри собственной
 * сессии. Подлинность сервера и доступность страницы после переходов на другое
 * имя НЕ проверены.
 * В частности, 403 остаётся HTTP-ответом, а не доказательством снятой блокировки.
 *
 * Сокет обращения остаётся ОТКРЫТЫМ до d2k_verify_close — не удобство, а
 * условие того, что измерение вообще что-то измеряет: датапат по FIN удаляет
 * ячейку потока (datapath/session.c), и событие применения плана становится
 * не с чем связать. Это уже стоило проекту дня отладки — см.
 * docs/field/2026-09-11-first-c-ask.md и doc-комментарий d2k_props_contact.
 */
#ifndef D2K_VERIFY_H
#define D2K_VERIFY_H

#include <stdint.h>
#include "d2k_quicsnap.h"
#include "d2k_resource.h"
#include "d2k_http_reply.h"
/* Shared HTTP framing reader; transport owns the connection and request. */
typedef long (*d2k_http_read_fn)(void *, uint8_t *, size_t, int, char *, size_t);
typedef struct {
    int status, complete, connection_close, local_limit;
    uint64_t body_bytes;
    char location[2048];
    d2k_http_reply_result reply;
} d2k_http_read_result;
void d2k_http_read_response(d2k_http_read_fn read, void *ctx, int wait_ms,
                            d2k_http_read_result *result, char *err, size_t cap);

#include "d2k_tls13core.h"
#include "d2k_tls13.h"

/* Предел заголовков ответа, байт. Поле 03.10.2026: край Meta отдаёт ~8,4 КБ,
   прежние 8 КБ браковали рабочие планы. Выше — ответ не принимается с
   названием предела; curl держит 100 КБ, этого с запасом хватает зонду. */
#define D2K_VERIFY_HEADER_LIMIT 65536

typedef enum {
    D2K_VER_NOT_MEASURED = 0, /* обращение не состоялось — про линию не сказано ничего */
    D2K_VER_TRANSPORT,        /* TCP встал, рукопожатие не дошло до конца */
    D2K_VER_HANDSHAKE,        /* рукопожатие завершено, прикладного ответа нет */
    D2K_VER_APPLICATION,      /* полный HTTP-ответ, включая HTTPS redirect другой цели */
    D2K_VER_CHALLENGE,        /* Cloudflare cf-mitigated: challenge; не успех обхода */
    D2K_VER_BLOCKPAGE,        /* явная сигнатура страницы блокировки */
    D2K_VER_DENIED            /* HTTP 451: юридический отказ, не диагноз DPI */
} d2k_ver_level;

typedef struct {
    d2k_ver_level level;
    int      status;        /* код состояния HTTP, 0 — не разобран */
    uint16_t negotiated_tls; /* 0x0303 TLS1.2, 0x0304 TLS1.3; zero without handshake */
    uint8_t  http_version;   /* 1 or 2, from authenticated ALPN */
    uint64_t rx_tls_wire_bytes; /* actual TLS recv bytes after handshake, incl. record headers */
    uint32_t rx_tls_record_missing; /* missing declared record body; not plaintext */
    uint64_t body_bytes;    /* прочитанное тело HTTP, без chunk framing */
    uint64_t body_expected; /* Content-Length либо измеренное число chunk-байт */
    int      body_complete; /* тело полностью прочитано по HTTP framing */
    int      body_has_length; /* получен однозначный Content-Length */
    int      body_chunked;   /* применён Transfer-Encoding: chunked */
    int      body_framing_valid; /* разбор framing однозначен, даже если тело оборвалось */
    int      body_encoding;  /* 0 identity/нет, 1 gzip, 2 другое/несколько */
    char     location[512];  /* Location ответа; другая цель не посещается этим зондом */
    int      cloudflare_challenge; /* получен cf-mitigated: challenge */
    d2k_http_outcome http_outcome;
    char     http_evidence[64];
    uint16_t local_port;    /* местный порт обращения — ключ потока для привязки события */
    uint8_t  local_ip4[4];
    uint8_t  family;
    uint8_t  local_addr[16];
    int      fd;            /* сокет держится ОТКРЫТЫМ до d2k_verify_close */
    char     reason[200];   /* человеческая причина достигнутого уровня, всегда заполнена */
    /* Совпало ли имя, которым представился сервер, с тем, что мы спросили:
       1 — да, 0 — НЕТ, -1 — сказать нечего. Значимо только начиная с уровня
       рукопожатия: до него сертификата не бывает.

       Это НЕ подлинность (цепочка не строится) и НЕ доказательство заглушки.
       Для обычного TLS несовпадение диагностическое; ECH требует отдельного
       строгого подтверждения имени origin и принятия ECH. */
    int      name_ok;
    int      peer_authenticated; /* certificate chain and endpoint identity verified */
    int      peer_auth_failed;    /* TLS reached the peer but authentication failed */
    int      dns_reply_rejected;  /* malformed or refused DNS response; no application proof */
    uint16_t dns_query_bytes;    /* exact submitted plain DNS bytes, including TCP length */
    int      dns_session_ended;   /* peer ended this DNS session without a path failure */
    uint8_t  doh_http_version;   /* 1 or 2, from authenticated ALPN */
    /* Зонд НЕ УМЕЕТ такой транспорт — и не научится сменой кандидата.
     *
     * Отличается от обычного «не измерено» (нет TCP, молчание) тем, что
     * повторять бессмысленно: следующий кандидат получит тот же ответ, и
     * весь бюджет зондов уйдёт на установку планов, которые никто не
     * проверит. Сегодня так отвечает QUIC: вопросник для него есть
     * (quicprobe умеет спрашивать Initial), а зонда, доводящего прикладной
     * обмен до конца, нет.
     *
     * Это утверждение о НАС, а не о коробке и не о кандидате: в каталог по
     * нему не идёт ничего, ни положительного, ни отрицательного (§10). */
    int      unsupported;
    /* Зонд не состоялся из-за локального отказа (например, не поставилась
       метка SO_MARK): наружу не ушло ни одного пакета, это не обрыв на проводе. */
    int      local_refusal;
    int      ech_accepted; /* own ECH acceptance, not extension presence/GREASE */
    /* Зонд говорил ALPN клиента, и этот протокол — НЕ HTTP (задача 37, F3).
       Тогда доказательство на проводе — завершённое рукопожатие TLS (level
       D2K_VER_HANDSHAKE: ServerHello и проверенный Finished сервера), а
       прикладной уровень НЕ ИЗМЕРЕН: HTTP-запрос на чужом языке ничего не
       доказал бы. Это не D2K_VER_APPLICATION и за него не выдаётся. */
    int      handshake_proof;
    /* ПОВТОР ECH-ПРИВЕТСТВИЯ КЛИЕНТА (d2k_verify_replay_on): снятые байты
       клиента ушли со своего сокета, и сервер ответил ServerHello (или
       HelloRetryRequest) — то есть ровно вход коробки прошёл её на проводе.
       Уровень — D2K_VER_HANDSHAKE в смысле «граница рукопожатия», НО
       рукопожатие не завершено: ключей клиента у нас нет, Finished сервера
       не проверен, прикладной уровень и бюджет потока не измеримы. Это не
       handshake_proof и не APPLICATION и за них не выдаётся. */
    int      replay_proof;
    /* Неуспех вызван НАШИМ пределом или нашей ошибкой чтения (заголовки длиннее
       D2K_VERIFY_HEADER_LIMIT, нет памяти), а не поведением линии. Такой
       неуспех не улика против плана и не записывается ему как провал. */
    int      local_limit;
    /* Сервер объявил конец keep-alive: Connection: close, HTTP/1.0 без
       keep-alive или тело до закрытия соединения. Повторить запрос на этом
       потоке нельзя (проверка бюджета ниже — «не применимо»). */
    int      conn_close;
    /* ПРОВЕРКА БЮДЖЕТА ПОТОКА (задача 55, D2K_BUDGET_*). После первого
       ответа приложения зонд продолжает ТОТ ЖЕ поток повторами того же
       запроса, пока поток не перенесёт budget_need пакетов с данными (обе
       стороны вместе) при ответе сервера на каждый запрос. */
    int      budget;
    unsigned budget_need;     /* 2 × бюджет коробки, пакетов с данными */
    unsigned budget_packets;  /* сколько пакетов с данными поток перенёс к итогу */
    unsigned budget_requests; /* запросов на потоке, включая первый */
    unsigned doh_replies;     /* fully validated DNS replies on this stream */
    /* Текст кириллический, то есть по два байта на символ, и к нему ещё
     * подклеивается до 60 байт причины от линии. При 160 байтах поле
     * «сервер замолчал посреди повторов: N-й запрос, поток перенёс N пакетов
     * с данными из нужных N: …» обрезалось посреди слова и теряло САМО
     * ЧИСЛО нужных пакетов: поле 12.10.2026, 30 с лишним строк отказа по
     * www.userscript.zone читались как «из нужны;». Журнал обязан печатать
     * порог, иначе отказ кандидата нечем проверить. */
    char     budget_note[320];
    int      budget_uncountable; /* «не применимо»: пакеты потока не считаются (старое ядро) */
    /* TCP: пакеты с данными обеих сторон на момент конца обращения
       (TCP_INFO data_segs_in + data_segs_out), 0 — не считается. Им объёмный
       замер записывает бюджет коробки там, где видит обрыв identity. */
    unsigned data_packets;
    d2k_resource resources[D2K_RESOURCE_COUNT];
    size_t n_resources; /* hints only, from a complete anonymous HTML response */
} d2k_ver_result;

/* БЮДЖЕТ ПОТОКА — ДЕЙСТВИЕ КОРОБКИ (a), поле 04.10.2026 (задача 55,
 * task-55-facts.md §1.2): на именах под её правилом поток переносит ~25
 * пакетов с данными (обе стороны вместе, TCP и QUIC), после чего сервер
 * для клиента замолкает; от времени и байтов (5,9–29,6 КБ) не зависит.
 * Ответ 403/404/401 или короткий 200 до этого порога не доходит, и план,
 * снимающий только распознавание имени при рукопожатии, «подтверждался» им.
 *
 * Итоги проверки (d2k_ver_result.budget):
 *   NOT_CHECKED — проверку не просили (бюджет потока 0) или уровень ниже
 *                 приложения;
 *   PASSED      — поток перенёс не меньше 2 × бюджет пакетов с данными, и
 *                 сервер ответил на каждый запрос;
 *   CUT         — сервер замолчал посреди повторов. Это ЗАМЕР ПОТОКА, а не
 *                 вердикт о кандидате: кому принадлежит остановка, решает
 *                 планировщик по остальным замерам ЦЕЛИ. Там, где у цели
 *                 измерен обрыв входящего объёма (d2k_vol_result.rx_cut),
 *                 остановка принадлежит ему — второму, отдельному блоку со
 *                 своими планами, — и кандидат записывается ЧАСТИЧНЫМ
 *                 результатом, а не отвергается (поле 12.10.2026,
 *                 www.userscript.zone: два независимых блока у одной цели);
 *   NOT_APPLICABLE — сервер закрыл keep-alive (Connection: close, конец
 *                 потока, сброс) раньше порога, или пакеты не считаются:
 *                 подтверждение прежнее, привязка «бюджет не проверен». */
#define D2K_BUDGET_NOT_CHECKED    0
#define D2K_BUDGET_PASSED         1
#define D2K_BUDGET_CUT            2
#define D2K_BUDGET_NOT_APPLICABLE 3
/* Бюджет до первого замера коробки: 25 пакетов с данными в 18 из 18
   оборванных потоков поля 04.10.2026 (task-55-facts.md §1.2). Не константа
   обхода: замер коробки (обрыв identity) заменяет его своим числом. */
#define D2K_BUDGET_FIELD_PACKETS 25

/* Бюджет для зондов ЭТОГО потока исполнения: 0 — без проверки (умолчание;
 * базовые и объёмные замеры её не делают). Зовёт рабочий поток испытания
 * кандидата перед зондом и снимает после. */
void d2k_verify_budget_set(unsigned budget_packets);
/* Форма приветствия клиента для зонда QUIC (задача 66): его собственный
   первый полёт пойдёт тем же числом датаграмм той же длины, что у клиента.
   NULL или нулевое n — как раньше. Поточная настройка: ставится перед одной
   проверкой и снимается сразу после. */
void d2k_verify_quic_form_set(const d2k_quic_form *form);
/* Прибор поля (d2kfetch): тело ответа HTTP/3 читается до FIN в рамках срока,
   а не до D2K_QUIC_ARM_DATA_BYTES. Вопрос прибора — «страница целиком?»;
   предел — мера этапа данных плеча (поле 24.10.2026: 139 КБ от
   www.cloudflare.com сочтены обрывом на 32 КиБ). Поточная настройка. */
void d2k_verify_quic_read_all_set(int on);
unsigned d2k_verify_budget_get(void);

/* Пакеты TCP с данными обеих сторон на сокете: TCP_INFO data_segs_in +
 * data_segs_out (Linux ≥ 4.6; роутеры — 4.9). Меньше нуля — не считается
 * (другая ОС, старое ядро). Подменяемо для тестов. */
typedef long (*d2k_verify_packets_fn)(int fd);
long d2k_verify_tcp_data_packets(int fd);
extern d2k_verify_packets_fn d2k_verify_packets_hook;

/* Same verifier and protocol, with a public stylesheet witness instead of /.
 * NULL preserves /. No arbitrary URI, credentials, query strings or redirects
 * to a different host are accepted. mark must be set before connect(). */
d2k_ver_result d2k_verify_probe_path_on(int use_fd, const char *ip, uint16_t port,
    const char *sni, int deadline_ms, size_t hello_wire, int tls12,
    int encoding, uint32_t mark, const char *path);

/* Одно обращение к цели со СВОИМ рукопожатием и настоящим запросом.
 *
 * ip/port — куда идти, sni — имя, которое предъявляем в приветствии и в
 * заголовке Host (пустое — берётся адрес). deadline_ms — потолок отдельно на
 * рукопожатие и отдельно на ожидание ответа: страховка от молчания, а не
 * общий бюджет.
 *
 * Обращение идёт НЕПОМЕЧЕННЫМ: помеченный пакет уходит мимо NFQUEUE первым
 * правилом цепочки (files/S99d2k), поставленный план к нему не применится, и
 * зонд мерил бы линию БЕЗ обхода, считая, что мерит с обходом.
 *
 * Блокирует вызывающий поток на время обмена — значит, зовётся только из
 * рабочего потока: цикл d2kc не блокируется никогда.
 *
 * hello_wire — длина приветствия, СНЯТОГО С КЛИЕНТА, до которой зонд добивает
 * своё (0 — не добивать). Без неё измерение идёт в другом контексте, чем
 * работа человека: см. d2k_tls_connect. */
d2k_ver_result d2k_verify_probe(const char *ip, uint16_t port, const char *sni,
                                int deadline_ms, size_t hello_wire);

/* То же, но на УЖЕ ЗАНЯТОМ сокете. Нужно испытанию кандидата: его план
 * ставится только для местного порта зонда, а порт обязан быть известен ДО
 * подключения (d2k_props_bind, d2k_link_set_name_probe). Меньше нуля —
 * создать свой сокет, тогда это в точности d2k_verify_probe. */
d2k_ver_result d2k_verify_probe_on(int use_fd, const char *ip, uint16_t port,
                                   const char *sni, int deadline_ms, size_t hello_wire);

/* Зонд TLS 1.3 с ALPN КЛИЕНТА (alpn_list — protocol_name_list как на проводе,
 * alpn_len 0 — без ALPN, как у клиента без него) для протокола, который не
 * HTTP. Ведёт рукопожатие до проверенного Finished сервера и останавливается:
 * HTTP-запроса нет. Успех — level D2K_VER_HANDSHAKE и handshake_proof = 1;
 * прикладной уровень не измерен (см. handshake_proof). Сокет — как у
 * d2k_verify_probe_on. */
/* ЗОНД РУКОПОЖАТИЯ TLS 1.2 (этап 15, 28.10.2026): для клиента TLS 1.2 без
 * имени (адресная цель). Тем же протоколом, что и клиент: ClientHello 1.2 без
 * server_name (sni пустое — расширения нет), ECDHE-RSA-AES128-GCM-SHA256,
 * рукопожатие до Finished сервера, расшифрованного ключами общего секрета.
 * HTTP-запроса нет. Успех — level D2K_VER_HANDSHAKE, handshake_proof = 1,
 * negotiated_tls = 0x0303; прикладной уровень не измерен. ГРАНИЦА ДОКАЗАТЕЛЬСТВА
 * (как у всего клиента 1.2 проекта, см. шапку tls12.c): подпись сертификата
 * сервера не проверяется, набор шифров один; сервер без него, только 1.3,
 * alert или обрыв — отказ с причиной, не «не измерено наполовину». */
d2k_ver_result d2k_verify_probe12_handshake_on(int use_fd, const char *ip, uint16_t port,
                                               const char *sni, int deadline_ms,
                                               size_t hello_wire);
d2k_ver_result d2k_verify_probe_alpn_on(int use_fd, const char *ip, uint16_t port,
                                        const char *sni, int deadline_ms, size_t hello_wire,
                                        const uint8_t *alpn_list, size_t alpn_len);

/* То же, но рукопожатием TLS 1.2 — для клиента СТАРОЙ формы.
 *
 * Подтверждать его обход современным рукопожатием значит записывать план под
 * форму, которой у этого клиента нет: по ключу формы такой план ему не
 * достанется вовсе (MVP_CHECKLIST, пункт 3). Приветствие берётся из профиля,
 * а не из живого снимка — почему, сказано у самой функции.
 *
 * hello_wire — та же надобность, что у зонда 1.3: план, чьи куски помещаются
 * в посылку на коротком приветствии, на длинном не помещается вовсе. */
d2k_ver_result d2k_verify_probe12_on(int use_fd, const char *ip, uint16_t port,
                                     const char *sni, int deadline_ms,
                                     size_t hello_wire);

/* RX-volume candidates must prove the previously truncated identity body,
 * not the compressed control that already worked without a candidate. */
d2k_ver_result d2k_verify_probe_identity_on(int use_fd, const char *ip, uint16_t port,
    const char *sni, int deadline_ms, size_t hello_wire, int tls12);
d2k_ver_result d2k_verify_probe_gzip_on(int use_fd, const char *ip, uint16_t port,
    const char *sni, int deadline_ms, size_t hello_wire, int tls12);

/* Базовое измерение полноты ответа на сокете, который обходит активные планы
 * через SO_MARK. encoding: 0 — identity, 1 — gzip; tls12 выбирает ровно ту же
 * форму клиента, что и живой поток. Используется парным измерителем объёма,
 * не кандидатом: проверочные зонды, наоборот, обязаны проходить через план. */
d2k_ver_result d2k_verify_probe_baseline(const char *ip, uint16_t port,
                                         const char *sni, int deadline_ms,
                                         size_t hello_wire, int tls12,
                                         int encoding, uint32_t mark);

/* ТО ЖЕ САМОЕ, НО ПО QUIC. Уровни и их смысл не меняются ни на йоту:
 * TRANSPORT — датаграммы уходят, ответа нет; HANDSHAKE — рукопожатие
 * завершено, приложение молчит; APPLICATION — пришёл код ответа HTTP/3.
 * Послаблений для QUIC нет и быть не может: доказательством считается
 * прикладной обмен, а не «сервер что-то прислал».
 *
 * hello_wire — длина приветствия, снятого с клиента, до которой зонд добивает
 * своё; смысл тот же, что у d2k_verify_probe. */
d2k_ver_result d2k_verify_probe_quic(const char *ip, uint16_t port, const char *sni,
                                     int deadline_ms, size_t hello_wire);

/* То же на УЖЕ ЗАНЯТОМ сокете UDP — испытанию кандидата по QUIC, чтобы его
 * план достался только потоку зонда (d2k_props_bind_udp). */
d2k_ver_result d2k_verify_probe_quic_on(int use_fd, const char *ip, uint16_t port,
                                        const char *sni, int deadline_ms,
                                        size_t hello_wire);
/* То же, но запрос HTTP/3 — по пути path (известный большой ресурс цели);
 * NULL или пусто — «/». Успех — тот же, что у этапа данных плеча: ответ
 * целиком без дыр или не меньше D2K_QUIC_ARM_DATA_BYTES. */
d2k_ver_result d2k_verify_probe_quic_path_on(int use_fd, const char *ip, uint16_t port,
                                             const char *sni, int deadline_ms,
                                             size_t hello_wire, const char *path);

/* То же, но с установкой метки сокета mark перед connect(). 0 — не метить (через планы). */
d2k_ver_result d2k_verify_probe_quic_path_mark_on(int use_fd, const char *ip, uint16_t port,
                                                 const char *sni, int deadline_ms,
                                                 size_t hello_wire, uint32_t mark,
                                                 const char *path);

/* Fetch one complete HTTP/3 response within the existing deadline. Unlike
 * the scheduler probe, reaching the data-stage threshold alone is not success.
 * body_bytes counts authenticated stream bytes, including HTTP/3 framing. */
/* Explicit diagnostic GET target (including query), not an automatic witness.
 * Origin-form ASCII only, at most 8192 bytes, no controls or fragment. */
d2k_ver_result d2k_verify_fetch_tcp_on(int use_fd, const char *ip, uint16_t port,
    const char *sni, int deadline_ms, size_t hello_wire, int tls12,
    uint32_t mark, const char *path);

d2k_ver_result d2k_verify_fetch_quic_on(int use_fd, const char *ip, uint16_t port,
                                      const char *sni, int deadline_ms,
                                      size_t hello_wire, uint32_t mark,
                                      const char *path);

/* Закрывает сокет обращения и обнуляет fd. Безопасна на любом результате, в
 * том числе на том, где обращения не было. */
void d2k_verify_close(d2k_ver_result *r);

/* ПОВТОР СНЯТОГО ECH-ПРИВЕТСТВИЯ КЛИЕНТА (поле 04.10.2026: Chrome → Cloudflare,
 * коробка глушит рукопожатие по расширению ECH, своего свидетеля-origin нет).
 * Шлёт hello байт в байт на новом соединении (use_fd — занятый под пробный
 * план порт, как у остальных зондов; <0 — свой сокет) и читает ответ до
 * первого сообщения рукопожатия сервера. Успех — ServerHello/HRR: level
 * D2K_VER_HANDSHAKE, replay_proof = 1, budget = D2K_BUDGET_NOT_APPLICABLE.
 * Тревога, молчание, обрыв — D2K_VER_TRANSPORT. Сокет — открыт до
 * d2k_verify_close. Чужую сессию не продолжает и за свою не выдаёт. */
d2k_ver_result d2k_verify_replay_on(int use_fd, const char *ip, uint16_t port,
    const uint8_t *hello, size_t hello_len, int deadline_ms);

/* ПОВТОР СНЯТОЙ ПАЧКИ QUIC КЛИЕНТА (поле 15.10.2026: Chrome ходит на сайты
 * Cloudflare по QUIC с ECH, внешнее имя cloudflare-ech.com; заготовка без ECH
 * коробку проходит, полёт Chrome — нет). Та же пачка со свежим DCID уходит
 * датаграммами с use_fd (порт пробного плана; <0 — свой сокет). Успех —
 * ответ сервера, привязанный к нашему соединению: level D2K_VER_HANDSHAKE,
 * replay_proof = 1, budget = D2K_BUDGET_NOT_APPLICABLE. Тишина, чужие
 * датаграммы — D2K_VER_TRANSPORT. Сокет открыт до d2k_verify_close. */
d2k_ver_result d2k_verify_quic_replay_on(int use_fd, const char *ip, uint16_t port,
    const uint8_t *pack, size_t pack_len, int deadline_ms);

/* Explicit origin witness: outer SNI is config.public_name, HTTP authority
 * and certificate-name observation are origin. Never follows another host. */
d2k_ver_result d2k_verify_probe_ech_on(int use_fd, const char *ip, uint16_t port,
    const char *origin, const d2k_ech_config *config, int deadline_ms,
    size_t hello_wire, uint32_t mark, const char *path);
/* Bounded HTTPS-RR lookup for a known origin; does not invent origin names
 * from a shared IP, install DNS overrides, or treat missing records as clear. */
int d2k_ech_resolve(const char *origin, uint32_t mark, d2k_ech_config *config);
/* Resolve a fresh config, but only for the caller's explicit known witness.
 * An unmatched public name cannot verify the target's candidate plan. */
d2k_ver_result d2k_verify_probe_ech_origin_on(int use_fd, const char *ip,
    uint16_t port, const char *outer_name, const char *origin, int deadline_ms,
    size_t hello_wire, uint32_t dns_mark, const char *path);

d2k_ver_result d2k_verify_doh_on(int, const char *, uint16_t, const char *, int, size_t, int, uint32_t, const char *);
/* Authenticated TLS1.2/1.3 + complete HTTP/1.1 or HTTP/2 GET for preflight. */
d2k_ver_result d2k_verify_preflight_on(int,const char *,uint16_t,const char *,int,size_t,int);
d2k_ver_result d2k_verify_doh_question_on(int,const char *,uint16_t,const char *,int,
    size_t,int,uint32_t,const char *,const char *,uint16_t);
/* Socket DoH must authenticate its peer. The process installs its TLS
 * implementation before starting workers. The socket remains borrowed. */
typedef enum {
    D2K_DOH_TLS_OK, D2K_DOH_TLS_NETWORK, D2K_DOH_TLS_AUTH, D2K_DOH_TLS_LOCAL,
    D2K_DOH_TLS_PROTOCOL
} d2k_doh_tls_status;
typedef struct {
    d2k_tls_io io;
    void (*release)(void *);
    uint8_t http_version; /* 1 or 2, from authenticated ALPN */
    uint16_t tls_version;
} d2k_doh_tls_session;
typedef d2k_doh_tls_status (*d2k_doh_tls_open_fn)(int, const char *, uint16_t,
    int, d2k_doh_tls_session *);
void d2k_verify_doh_set_tls(d2k_doh_tls_open_fn);
d2k_doh_tls_status d2k_doh_trusted_tls_open(int, const char *, uint16_t, int,
    d2k_doh_tls_session *);
/* DoT shares the verifier's exact TCP connection and flow receipt. */
typedef void (*d2k_dot_probe_fn)(int,const char *,uint16_t,int,const char *,uint16_t,d2k_ver_result *);
void d2k_verify_dot_set_probe(d2k_dot_probe_fn);
void d2k_dot_trusted_probe(int,const char *,uint16_t,int,const char *,uint16_t,d2k_ver_result *);
d2k_ver_result d2k_verify_dot_on(int, const char *, uint16_t, const char *, int, uint16_t, uint32_t);
d2k_ver_result d2k_verify_dot_question_on(int,const char *,uint16_t,const char *,
    int,uint16_t,uint32_t,const char *,uint16_t);
typedef d2k_ver_result (*d2k_plain_dns_probe_fn)(const char *, uint16_t, uint8_t,
    const char *, uint16_t, int, uint32_t);
void d2k_verify_plain_dns_set_probe(d2k_plain_dns_probe_fn);
d2k_ver_result d2k_verify_plain_dns_on(const char *, uint16_t, uint8_t,
    const char *, uint16_t, int, uint32_t);
d2k_ver_result d2k_plain_dns_probe(const char *, uint16_t, uint8_t,
    const char *, uint16_t, int, uint32_t);
/* DoH on an already owned measurement stream, using the same HTTP/2 and DNS
 * validation as socket probes. Never opens/closes sockets or invents a flow
 * identity. A nonzero packet budget requires a real cumulative data-packet
 * counter; zero checks one DNS response only. Transport stays caller-owned. */
d2k_ver_result d2k_verify_doh_io(const d2k_tls_io *,const char *host,const char *path,
    int timeout_ms,size_t hello_wire,unsigned budget,long (*packets)(void *),void *);
d2k_ver_result d2k_verify_doh_probe_io(const d2k_tls_io *,const d2k_tls_probe_seed *,
    const char *,const char *,int,size_t,unsigned,long (*)(void *),void *);
/* Owned TLS1.3 measurement stream, HTTP/1.1 and the existing complete-body
 * verifier. Caller retains transport/seed. No socket, DNS lookup, plan install
 * or volume certification. Certificate authentication limitations are the
 * same as the existing measurement TLS client. path NULL requests root. */
d2k_ver_result d2k_verify_https_probe_io(const d2k_tls_io *,const d2k_tls_probe_seed *,
    const char *host,const char *path,int timeout_ms,size_t hello_wire,int encoding);
typedef enum {D2K_HTTPS_REQUEST_BEGIN=1,D2K_HTTPS_REQUEST_SENT=2,
    D2K_HTTPS_EXCHANGE_END=3} d2k_https_phase;
typedef struct {
    d2k_https_phase phase;
    unsigned ordinal;
    const uint8_t *request;
    size_t request_length;
    const d2k_ver_result *response;
} d2k_https_observation;
/* Synchronous borrowed snapshots. BEGIN/SENT bracket TLS request writes;
 * redirects increment ordinal. END is the final exchange result, not proof
 * of completion of each redirect body. No callbacks occur before TLS succeeds.
 * Nonzero observer return aborts locally and cannot become network evidence. */
typedef int (*d2k_https_observer)(void *,const d2k_https_observation *);
d2k_ver_result d2k_verify_https_observe_io(const d2k_tls_io *,const d2k_tls_probe_seed *,
    const char *,const char *,int,size_t,int,d2k_https_observer,void *);
d2k_ver_result d2k_verify_https12_observe_io(const d2k_tls_io *,const uint8_t random[32],
    const char *,const char *,int,size_t,int,d2k_https_observer,void *);
typedef struct {
    unsigned ordinal;
    uint32_t stream_id;
    int64_t started_ms,finished_ms;
    int dns_valid,timed_out;
    d2k_ver_result response;
    unsigned query_schema;
    int timeout_ms;
} d2k_doh_observation;
enum { D2K_DOH_QUERY_SCHEMA_V1=1 };
/* Synchronous borrowed observation. Return 1 for another query, 0 to stop,
 * -1 if evidence could not be retained. A failed query always ends the stream.
 * Observation mode does not certify a volume budget or install a plan. */
typedef int (*d2k_doh_observer)(void *,const d2k_doh_observation *);
d2k_ver_result d2k_verify_doh_observe_io(const d2k_tls_io *,const d2k_tls_probe_seed *,
    const char *,const char *,int,size_t,d2k_doh_observer,void *);
#endif /* D2K_VERIFY_H */
