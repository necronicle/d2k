/* d2k_ctl.h — управляющий сокет.
 *
 * Датапат слушает, контроллер подключается. Ровно одно подключение: датапат
 * обслуживает одного хозяина, а не является сервером общего пользования.
 *
 * Кадр: [длина payload u32 BE][тип u16 BE][payload]. Подробности и причины —
 * в docs/decisions/0004-control-socket.md.
 *
 * Событие — сообщение, а не обязательство. Не поместилось в сокет — потеряно
 * и посчитано. Очереди событий нет: очередь это память без предела, а §5.2
 * требует предела на всё. Пакетный путь ради контроллера не останавливается
 * никогда.
 *
 * AF_UNIX работает и на маке, поэтому модуль переносим и проверяется настоящим
 * сокетом, а не подделкой.
 */
#ifndef D2K_CTL_H
#define D2K_CTL_H

#include <stddef.h>
#include <stdint.h>

#include "d2k_journal.h"

/* Предел кадра. План — самое большое, что здесь ездит. */
#define D2K_CTL_FRAME_MAX 65536

/* События: датапат → контроллер. */
/* ВЕРСИЯ УПРАВЛЯЮЩЕГО ПРОТОКОЛА.
 *
 * Растёт при КАЖДОМ несовместимом изменении провода. Уже было два таких за
 * один день: код APPLIED (0x0003 → 0x0009) и формат тела SET_NAME (появился
 * байт формы приветствия). Смешанная пара d2kd/d2kc при этом не падает и не
 * ругается — она молча не даёт подтверждений, и полдня измерений уходит в
 * никуда: ровно это и случилось 12.09, когда датапат был старше правки,
 * заводившей идентификатор плана.
 *
 * Процедурной защиты («собирать три бинарника одной серией») мало: она
 * защищает от невнимательности, но не от того, что человек НЕ ЗНАЕТ о
 * несовместимости. Датапат объявляет версию первым же событием после
 * подключения, контроллер сверяет и при расхождении отказывается работать
 * вслух, а не мерит пустоту.
 *
 * 1 — состояние на 12.09.2026 (APPLIED 0x0009, SET_NAME с формой, REFUSED с
 * кодом и ID, EXCHANGE с признаком ответа сервера). */
/* Версия 2 добавила транспорт в ARM_SHAPE. Версия 3 добавляет временную
 * адресную пробу с exact-flow key и поколением, а также trial ID в
 * APPLIED/REFUSED. Версия 4 добавляет полные адреса и семейство в ключи
 * событий и команды привязок. Смешанная пара останавливается на приветствии. */
/* v5: learned suffix areas and exact context bypass commands. */
/* v6: area command correlation IDs, safe retry after lost/late ACK. */
/* v7: SET_ADDR/DEL_ADDR несут форму протокола (D2K_PLAN_SHAPE_*): адресная
 * привязка — ключ (адрес, семейство, форма), QUIC и STUN/голос одного IP не
 * затирают друг друга. Без формы и с дедушкиным правом команда отвергается. */
/* v8: SET_NAME_PROBE несёт хвостом trial ID опыта (16 байт), ACK возвращает
 * его и на успех, и на отказ: подтверждение установки пробы привязано к своему
 * опыту, отказ исполнителя не принимается за промах кандидата (задача 19). */
/* v9: DEL_NAME несёт транспорт и форму и снимает ровно ПОСТОЯННУЮ запись
 * (имя, транспорт, форма, семейство). Пробы снимает только DEL_NAME_PROBE;
 * прямой проход TCP больше не уносит пробу параллельной QUIC-задачи и
 * подтверждённое знание других форм (задача 21). */
/* v10: открытый HTTP без прокси (задача 51) — событие D2K_EV_HTTP_PORTAL и
 * команда D2K_CMD_SET_HTTPS. */
/* v11: форма имени D2K_PLAN_SHAPE_HTTP (7) в SET_NAME/SET_NAME_PROBE/
 * DEL_NAME/DEL_NAME_PROBE и планы протокола http (задача 51, шаг 4). Старый
 * датапат принял бы такую запись как обычную. */
/* v21 (замысел 2026-10-23, п. 5.1): событие D2K_EV_CLIENT_TCP — набор опций
 * TCP клиента, ровно перед его SHAPE. Старый контроллер пропустил бы
 * незнакомый вид и мерил бы прежним набором, записав привязку как CLIENT. */
/* v12 (задача 56): подозрение D2K_SUSPECT_TCP_STALL (8) с оценкой пакетов
 * с данными u16 BE хвостом SUSPECT и команда D2K_CMD_SET_STALL_BUDGETS.
 * Старый контроллер принял бы код 8 за обычное подозрение и пустил бы полный
 * поиск вместо узкого RX-замера с повторяемостью. */
/* v13: mandatory release ID after send limit: u8 length + 1..64 bytes. */
/* v14: HTTP_PORTAL carries execution, plan/trial identity, monotonic request
 * start and the replayable GET path (no query); zero context is not proof. */
/* v15: APPLIED/REFUSED append the immutable process-local execution binding. */
/* v16: execution snapshots include a random plan-table lifetime epoch. */
#include "../../runtime/d2k_protocol.h"

/* Execution ID u64 BE, binding generation u64 BE, kind/family/shape/temporary.
 * Followed by the 16-byte table epoch. Unknown identity is not live proof. */
#define D2K_CTL_EXECUTION_LEN 36u
/* v17: identified permanent SET/conditional DEL and request binding snapshots. */
#define D2K_CTL_BINDING_LEN 28u
static inline void d2k_ctl_binding_write(uint8_t *p, const d2k_binding_context *b) {
    for(unsigned i=0;i<8;i++)p[i]=(uint8_t)(b->generation>>(56-8*i));
    p[8]=b->kind;p[9]=b->family;p[10]=b->shape;p[11]=b->temporary;
    for(unsigned i=0;i<16;i++)p[12+i]=b->epoch[i];
}
/* Accept every registered execution shape, including exact DNS endpoints. */
static inline int d2k_ctl_binding_read(d2k_binding_context *b,const uint8_t *p,size_t n) {
    if(n!=D2K_CTL_BINDING_LEN || p[8]>D2K_BIND_FLOW ||
       (p[9] && p[9]!=4 && p[9]!=6) || p[10]>D2K_PLAN_SHAPE_DNS || p[11]>1)return -1;
    b->generation=0;
    for(unsigned i=0;i<8;i++)b->generation=(b->generation<<8)|p[i];
    b->kind=p[8];b->family=p[9];b->shape=p[10];b->temporary=p[11];
    for(unsigned i=0;i<16;i++)b->epoch[i]=p[12+i];
    return 0;
}

#define D2K_EV_HELLO     0x0001  /* ключ + имя цели */
#define D2K_EV_SUSPECT   0x0002  /* ключ + код причины */
#define D2K_EV_PREPARED  0x0003  /* legacy: prepared only, never execution proof */
#define D2K_EV_APPLIED   0x0009
/* Версия протокола: ПЕРВОЕ событие после подключения контроллера. Тело —
 * ключ (нулевой, событие не про поток), два байта версии (старший первым) и
 * четыре байта ПРЕДЕЛА ОТПРАВКИ. Контроллер, не понявший версию, обязан
 * отказаться работать: смешанная пара не падает, а молча не даёт
 * подтверждений.
 *
 * ПРЕДЕЛ ОТПРАВКИ ЕДЕТ ЗДЕСЬ, и это не удобство. Контроллер СОБИРАЕТ планы, и
 * у собранного плана есть длина: тело фальшивки обязано и покрывать то, что
 * должно покрыть, и помещаться в канал. Второе число знает только датапат
 * (d2k_raw_maxlen), и пока оно не доезжало, длина набивки бралась с потолка —
 * 64 байта. Цена измерена лабораторией 13.09.2026: такая фальшивка
 * перекрывает остаток имени на приветствии зонда и не перекрывает на
 * приветствии браузера, и плечо оказывается переносимым СЛУЧАЙНО.
 *
 * Ноль означает «предел не объявлен» (стенд без сырого сокета) — в этом
 * случае контроллер обязан вести себя как раньше, а не считать, что можно
 * сколько угодно. */
#define D2K_EV_PROTO     0x000A  /* all sends + original verdict completed; key + plan ID */
/* Отказ по плану: ключ + КОД ПРИЧИНЫ (D2K_REFUSE_* из d2k_journal.h) одним
 * байтом сразу за ключом. При отказе отправки за кодом идут 16 байт ID плана;
 * при обычном отказе подготовки ID может отсутствовать.
 *
 * Так было объявлено здесь с самого начала, а на проводе до 12.09.2026 ехал
 * один ключ. Цена расхождения названа в docs/decisions/0006: локальный отказ
 * отправки выглядел у контроллера ровно как «коробка не поддалась», и он
 * записывал бы нашу поломку свойством чужого устройства. Ноль означает
 * «причина не кодирована» и приходит на обычный отказ ПРИМЕНИТЬ план — тот
 * случается на каждом транзитном потоке. */
#define D2K_EV_REFUSED   0x0004
#define D2K_EV_EXCHANGE  0x0005  /* ключ + сколько байт пришло в ответ */
#define D2K_EV_STATS     0x0006  /* счётчики */
/* Форма наблюдённого приветствия: ключ + байты ClientHello.
 *
 * Пассивно публикуется для полного TLS-приветствия клиента, с ключом его
 * потока, после HELLO (если он есть). Это вход DIRECT/OWN с формой клиента
 * (ТЗ §4.3, §11.2); собственные пробы контроллера исключены. Для QUIC —
 * по ARM_SHAPE либо при ECH. Снимок, вытесненный до публикации, пропускается:
 * байты другого потока к старому ключу не прикрепляются.
 *
 * ARM_SHAPE дополнительно возвращает уже пойманную форму: адреса/порты
 * ключа нулевые, транспорт и семейство сохранены. Для TCP непосредственно
 * перед каждым SHAPE идёт CLIENT_TCP с тем же ключом. За кэшированным SHAPE
 * непосредственно идёт ACK команды; хвост ACK содержит request ID, если он
 * был в команде. Уже поставленные в очередь пассивные события не являются
 * ответом команды. При отсутствии формы ACK приходит сразу, будущий снимок
 * публикуется с ключом наблюдённого потока.
 *
 * Нужна затем, что зонд обязан повторять форму пользовательского приветствия,
 * а не быть синтетическим: коробка может по-разному относиться к приветствию
 * браузера и к приветствию нашей библиотеки (§3.1, §5.5). */
#define D2K_EV_SHAPE     0x0007
/* НАБОР ОПЦИЙ TCP КЛИЕНТА, чьё приветствие едет следом событием SHAPE
 * (замысел 2026-10-23, п. 5.1): тот же ключ потока, затем 0..40 байт опций
 * заголовка TCP пакета-приветствия — ровно то, что профиль tcp-template-v1
 * копирует в фальшивки. Пустое тело за ключом — клиент без опций в данных,
 * и это честный профиль (ПК репортёра #7), а не «нет данных». Едет ТОЛЬКО
 * для TCP и ровно перед своим SHAPE, чтобы контроллер связал набор со
 * снимком по ключу до того, как задача возьмёт снимок в замер. Зонд
 * здоровается этим набором, а не литералом (detect/raw.c). v21. */
#define D2K_EV_CLIENT_TCP 0x000D
/* ПОЯВЛЕНИЕ ПОТОКА БЕЗ РАСПОЗНАННОГО ПРОТОКОЛА (этап 42): ключ потока, затем
 * u8 наблюдённой стороны клиента (D2K_CLIENT_SIDE_*, ноль — не известна).
 * Один раз на поток, объём ограничен датапатом. Факт существования для
 * наблюдения счётчиков — не подозрение и не повод к подбору. Необязательное
 * событие: контроллер, не знающий вида, пропускает его (link.c, default). */
#define D2K_EV_FLOW 0x000E
/* ИТОГ ПОЗДНЕГО НАБЛЮДЕНИЯ ТОЧНОГО ПОТОКА (этап 49): ключ потока, u8 итога
 * (D2K_LATEOBS_*), u8 стороны клиента, u16 BE повторов данных клиента, токен
 * наблюдения [16] из команды. Ответ на D2K_CMD_LATE_OBSERVE, один на
 * наблюдение; итог с чужим токеном контроллер не принимает. */
#define D2K_EV_LATE_OBS 0x000F
/* Exact connection observation facts; never application success. */
#define D2K_EV_RAW_MEASURE 0x0010
/* SUSPECT payload plus immutable flow epoch[16] and incarnation u64 BE. */
#define D2K_EV_RAW_SUSPECT 0x0011
/* FLOW payload with the same immutable identity suffix. */
#define D2K_EV_RAW_FLOW 0x0012
/* EXCHANGE with immutable flow epoch[16] and incarnation u64 BE suffix. */
#define D2K_EV_OWNED_EXCHANGE 0x0013
/* v31 preflight facts: canonical key, client side u8 (LOW/HIGH), K u32 BE,
 * elapsed since client SYN u64 BE, plan[16], trial[16], binding[28].
 * HANDOVER means original SYN released, never application success. */
#define D2K_EV_PREFLIGHT_START 0x0014
#define D2K_EV_PREFLIGHT_HANDOVER 0x0015
#define D2K_EV_PREFLIGHT_GAVE_UP 0x0016
#define D2K_CTL_PREFLIGHT_LEN (13u+D2K_PLAN_ID_LEN+D2K_TRIAL_ID_LEN+D2K_CTL_BINDING_LEN)
/* Вставка провайдера в открытый HTTP (задача 51): ключ потока (клиент и
 * сервер, порт 80), затем признак u8 (1 — клиенту ушёл 307 на https, 0 —
 * вставка пропущена как есть), длина имени u8 и Host запроса. Сообщение, а не
 * обязательство: по нему контроллер проверяет HTTPS имени.
 * v14 tail after Host: execution u64, plan[16], trial[16], request_ms u64,
 * path_len u16, GET path[path_len]. Integers are big endian. Only completed
 * live execution can carry nonzero execution. Empty path means that the
 * failed request cannot be reproduced safely by the HTTP probe. */
#define D2K_EV_HTTP_PORTAL 0x000B
/* Same identity envelope, code=1 complete framing/2 unknown/3 portal/
 * 4 cut (v19: a body with a length claim stopped short — sent without a plan,
 * execution may be zero; body bytes = what reached the client);
 * after binding: HTTP status u16, body bytes u64, request ordinal u64. */
#define D2K_EV_HTTP_RESPONSE 0x000C
/* Подтверждение команды: тип команды u16, признак успеха u8, код причины u8
 * (значим только при признаке успеха 0, см. D2K_ACK_*).
 *
 * Без него контроллер не знает, встал ли план, и зонд приходится пускать
 * «через паузу на всякий случай». Пауза наугад — это гонка, которую не видно,
 * пока она не проявится на медленной коробке.
 *
 * Код причины добавлен отдельно от признака успеха не для красоты: замер на
 * живом роутере (2026-09-06) поймал ровно то, к чему ведёт голый успех/отказ
 * без причины — таблица планов полна, SET_NAME отвечает отказом, и контроллер
 * читает его как «план плохой», сжигая кандидата, которому просто не хватило
 * места. Прибор, не различающий причины отказа, — не прибор (тот же принцип,
 * что и у счётчиков отказов в session.c). */
#define D2K_EV_ACK       0x0008

/* Коды причины отказа команды SET_NAME/SET_ADDR — тело события D2K_EV_ACK
 * целиком: код команды (u16), признак успеха (u8), затем этот код (u8).
 * Значим только когда признак успеха равен 0.
 *
 * D2K_ACK_NO_ROOM выделен из общего отказа НАРОЧНО: место в таблице планов
 * кончилось не по вине конкретного плана, и контроллер обязан не считать
 * кандидата негодным в этом случае (см. internal/controller/controller.go,
 * onAck). С вытеснением по давности (d2k_plans.h) таблица, за которую отвечает
 * этот код, вытесняет самую давно не использованную запись вместо отказа, и
 * d2k_plantab_set_name/set_addr с таблицей ненулевой ёмкости этот код больше
 * не возвращают — код сохранён в протоколе как страховка на случай нарушения
 * этого инварианта, а не как ожидаемый в бою исход. */
#define D2K_ACK_OK       0  /* принято */
#define D2K_ACK_BAD_PLAN 1  /* план не разобрался или не годится способу отправки */
#define D2K_ACK_NO_ROOM  2  /* таблице планов нечего вытеснить — не вина плана */
#define D2K_ACK_BAD_ARGS 3  /* аргументы команды негодны: обрезанный кадр, имя */
#define D2K_ACK_UNAVAILABLE 4  /* этап 53: позднюю доставку потоку поставить не удалось / нечем */

/* Команды: контроллер → датапат. */
#define D2K_CMD_SET_NAME 0x0081  /* длина имени u8, имя, форма u8, family u8, план TLV */
/* Как SET_NAME, но план — ПРОБНЫЙ и действует только на один поток:
 * длина имени u8, имя, форма u8, family u8, МЕСТНЫЙ ПОРТ u16 BE, план TLV,
 * trial ID (16 байт, v8; возвращается в D2K_EV_ACK).
 *
 * Отдельная команда, а не поле в SET_NAME: старое тело осталось прежним, и
 * контроллер, который про испытания не знает, продолжает ставить планы всем.
 * Испытание кандидата — это единственное место, где план не должен достаться
 * никому, кроме зонда (см. d2k_plans.h про цену обратного). */
#define D2K_CMD_SET_NAME_PROBE 0x0088
#define D2K_CMD_SET_ADDR_PROBE 0x0089 /* family+src/dst+ports+proto(38), trial-id(16), lease-ms(u32), Plan */
#define D2K_CMD_DEL_ADDR_PROBE 0x008A /* flow(38), trial-id(16); stale delete is no-op; v23 ACK echoes trial ID */
#define D2K_CMD_SET_ADDR 0x0082  /* family u8, address(16), форма u8, план TLV */
#define D2K_CMD_DEL_NAME 0x0083  /* длина имени u8, имя, transport u8, форма u8, family u8 (v9) */
#define D2K_CMD_DEL_ADDR 0x0084  /* family u8, address(16), форма u8 */
#define D2K_CMD_SET_ENDPOINT 0x0094 /* family u8, address(16), shape u8, server port u16 BE, Plan */
#define D2K_CMD_SET_ENDPOINT_BOUND 0x0099 /* SET_ENDPOINT body + request id(16); ACK includes binding */
#define D2K_CMD_COMMIT_ENDPOINT_TRIAL 0x009B /* endpoint key(20) + installation token(16); promote matching candidate */
#define D2K_CMD_DEL_ENDPOINT_TRIAL 0x009A /* endpoint key(20) + nonzero installation token(16); compare before delete */
#define D2K_CMD_DEL_ENDPOINT 0x0095 /* family u8, address(16), shape u8, server port u16 BE; RAW appends transport u8 (6/17), required */
#define D2K_CMD_CLEAR    0x0085  /* убрать все планы */
#define D2K_CMD_STATS    0x0086  /* прислать счётчики */
/* Получить кэшированную форму или взвести ловушку следующего приветствия:
 * длина имени u8, имя, transport u8, family u8, необязательный request ID[16].
 * Ловушка срабатывает один раз; пассивную публикацию TLS не отключает.
 * Порядок ответа и отличие от пассивной формы — у D2K_EV_SHAPE. */
#define D2K_CMD_ARM_SHAPE 0x0087
/* длина имени u8, имя, форма u8, family u8, порт u16 BE;
 * необязательный trial ID[16] требует ненулевые trial/форму и удаляет только
 * совпавшего владельца пробы. Чужой/устаревший токен — успешный no-op.
 * Старый обработчик отвергает расширенное тело по длине, без удаления. */
#define D2K_CMD_DEL_NAME_PROBE 0x008B
#define D2K_CMD_SET_SUFFIX 0x008C /* length/name/shape/family/TLV */
#define D2K_CMD_DEL_SUFFIX 0x008D /* length/name/transport/shape/family */
#define D2K_CMD_SET_BYPASS 0x008E /* length/name/transport/shape/family */
#define D2K_CMD_DEL_BYPASS 0x008F /* length/name/transport/shape/family */
/* У имени подтверждён HTTPS (v10, задача 51): длина имени u8, имя, срок в
 * секундах u32 BE. Ноль снимает имя. Вставку провайдера по такому имени
 * датапат заменяет на 307 → https. */
#define D2K_CMD_SET_HTTPS 0x0090
#define D2K_HTTPS_TTL_MAX_S (7u * 24u * 3600u)
/* Бюджеты потока коробок для детектора «TCP встал на бюджете» (v12, задача
 * 56): число u8 (0..D2K_STALL_BUDGETS_MAX), затем столько u16 BE, каждый не
 * ноль. Ноль значений возвращает полевой бюджет (d2k_journal.h). Контроллер
 * шлёт измеренные бюджеты коробок каталога и полевой — для целей, чья
 * коробка не измерена. */
#define D2K_CMD_SET_STALL_BUDGETS 0x0091
#define D2K_CMD_SET_NAME_BOUND 0x0092 /* SET_NAME body + command id(16); ACK includes binding */
#define D2K_CMD_DEL_NAME_BOUND 0x0093
/* Этап 49: понаблюдать ТОЧНЫЙ поток TCP, у которого счётчики показали позднюю
 * тишину: family u8, proto u8 (6), src[16], dst[16] (кортеж orig, хвост IPv4
 * нулевой), sport u16, dport u16, секунды u8 (1..120), токен наблюдения [16]
 * (ненулевой, как trial ID). d2kd ставит метку поздней доставки на запись,
 * классифицирует пакеты (d2k_lateobs.h), снимает метку и отвечает
 * D2K_EV_LATE_OBS с тем же токеном; ACK несёт токен хвостом, как у проб. Поток
 * не меняется. */
#define D2K_CMD_LATE_OBSERVE 0x0096
/* Exact connection identity and observation token; see d2k_rawmeasure_wire.h. */
#define D2K_CMD_RAW_MEASURE 0x0097
/* report, trial token[16], lease_ms u32 BE, plan TLV */
#define D2K_CMD_SET_RAW_PROBE 0x0098
/* One controller-owned DNS query: same exact flow and trial, lease u32,
 * DNS wire payload length u16, SHA256[32], plan TLV. */
#define D2K_CMD_SET_DNS_PROBE 0x009C
#define D2K_CMD_SET_PREFLIGHT_TRIAL 0x009E /* endpoint key, verifier source port, plan, request ID */
#define D2K_CMD_SET_PREFLIGHT_LEASE 0x00A1 /* scoped client/server/name/path/form + expiry + lease ID + Plan */
#define D2K_CMD_DEL_PREFLIGHT_LEASE 0x00A2 /* scope + lease ID; wrong/absent ID is a no-op */
#define D2K_PREFLIGHT_LEASE_SCOPE_WIRE_LEN 46u /* family/client/server/shape/path/port/lease-ms/name-len */
#define D2K_PREFLIGHT_LEASE_MAX_MS 86400000u /* local resource bound, not a network fact */
#define D2K_CMD_SET_DNS_ENDPOINT 0x009D /* endpoint key(20), measured length u16 BE, Plan, request ID(16) */
#define D2K_DNS_PROBE_FIXED (D2K_ADDR_PROBE_FLOW_WIRE_LEN + D2K_TRIAL_ID_LEN + 4 + 2 + 32)
#define D2K_LATE_OBSERVE_LEN (39 + D2K_TRIAL_ID_LEN) /* length/name/transport + expected binding(28); stale no-op */

/* Контроллер задаёт lease относительным временем, datapath сравнивает
 * абсолютный monotonic expires_ns. Ограничение не даёт аварийному disconnect
 * оставить временную адресную пробу бессрочно. */
#define D2K_ADDR_PROBE_LEASE_MAX_MS 120000u

/* Коды причин подозрения живут в d2k_journal.h: они про наблюдение, а сокет
 * их только везёт. */

typedef struct d2k_ctl d2k_ctl;

/* Создаёт слушающий сокет по пути path. Существующий файл сокета убирается:
 * после SIGKILL он остаётся и мешает следующему запуску, а §5.5 требует
 * описанного пути восстановления. */
d2k_ctl *d2k_ctl_open(const char *path, char *err, size_t errcap);
void     d2k_ctl_close(d2k_ctl *c);

int d2k_ctl_listen_fd(const d2k_ctl *c);
int d2k_ctl_peer_fd(const d2k_ctl *c);   /* -1 — контроллер не подключён */
void d2k_ctl_set_disconnect_hook(d2k_ctl *, void (*hook)(void *), void *ctx);

/* Принимает подключение, если оно ждёт. Второй контроллер отвергается. */
void d2k_ctl_accept(d2k_ctl *c);
/* A separate accepted stream for an experiment service. The caller bounds
 * the number of peers and owns close; the listener keeps no peer/buffers. */
d2k_ctl *d2k_ctl_accept_peer(d2k_ctl *listener);

/* Отправляет событие. Не блокирует. */
void d2k_ctl_event(d2k_ctl *c, uint16_t type, const uint8_t *body, size_t len);

/* Дописывает недоотправленный хвост, если он есть. */
void d2k_ctl_flush(d2k_ctl *c);

/* Читает и разбирает команды. cb зовётся на каждый целый кадр.
 * Возвращает число разобранных кадров; -1 — соединение закрылось. */
int d2k_ctl_poll(d2k_ctl *c,
                 void (*cb)(void *ctx, uint16_t type, const uint8_t *body, size_t len),
                 void *ctx);

uint64_t d2k_ctl_dropped(const d2k_ctl *c);
void d2k_ctl_note_dropped(d2k_ctl *c, uint64_t count);
uint64_t d2k_ctl_sent(const d2k_ctl *c);

#endif /* D2K_CTL_H */
