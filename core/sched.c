/* sched.c — планировщик поисков, один на оба транспорта. См. d2k_sched.h.
 *
 * УСТРОЙСТВО В ОДИН АБЗАЦ. Датапат шлёт события; цикл (d2kc.c) отдаёт их сюда
 * по одному. Приветствие (D2K_EV_HELLO) запоминает имя за ключом потока —
 * подозрение имени не несёт (на проводе это ключ и код причины, core/link.c),
 * и связать их иначе нечем. Подозрение (D2K_EV_SUSPECT) заводит задачу по паре
 * (имя, транспорт) и отправляет её сетевому оракулу в рабочий поток. Оракул
 * возвращается вердиктом; по вердикту собираются планы; план ставится
 * командой — и тут же ИСПЫТЫВАЕТСЯ СОБСТВЕННЫМ ЗОНДОМ.
 *
 * ПОЧЕМУ ИСПЫТЫВАЕМ САМИ. До 12.09 поставленный кандидат уходил ждать чужого
 * обмена: пока пользователь не откроет цель ещё раз, очередь не двигалась
 * вовсе. У телевизора живого потока нет — одно обращение, следующее через три
 * минуты (§4 спецификации, «почему не живой поток»), и рабочий вариант нужен
 * раньше; открывать цель несколько раз ради перебора спецификация прямо
 * отказывается. Теперь задача сама идёт к цели зондом (core/verify.c) и
 * получает ответ за секунды.
 *
 * ПОЧЕМУ ОДНОГО ЗОНДА МАЛО. Зонд доказывает, что ЛИНИЯ довела дело до
 * приложения, но не то, что она довела его С НАШИМ КАНДИДАТОМ: обход мог не
 * примениться к его пакетам вовсе, а цель — открыться сама (коробка сегодня
 * промахнулась). Вторая половина доказательства — событие применения
 * (D2K_EV_APPLIED) с идентификатором ЭТОГО плана по ключу ЭТОГО потока. Ни
 * одна половина в одиночку успехом не является.
 *
 * И ПОЧЕМУ НЕ ВНЕШНИЙ ТИП ЗАПИСИ 23. В TLS 1.3 им едет весь второй полёт
 * рукопожатия (RFC 8446 §5.2), то есть с провода «приложение ответило»
 * неотличимо от «коробка пропустила приветствие». Это наблюдение (§4.2,
 * уровень 2): ни завести запись, ни повысить достоверность уже записанного
 * успеха оно не может (d2k_ev_outer_appdata, d2k_link.h).
 *
 * ПАРА (ИМЯ, ТРАНСПОРТ), А НЕ ИМЯ. Go-сторона держит задачи по имени, и это её
 * известный дефект: комментарий в controller.go (обработка EvApplied) прямо
 * говорит, что «та же задача у TCP и QUIC к одному имени делят один *Task
 * (taskForKey резолвит по имени цели, не по ключу с протоколом)», и оттуда же
 * растёт оговорка про чужие применения. Здесь этого нет по построению: ключ
 * задачи — пара, и телевизор по QUIC не перезаписывает поиск браузера по TCP.
 *
 * ПОТОК ТОЛЬКО ПОД СЕТЕВОЙ ОРАКУЛ. d2k_classify и d2k_quic_classify —
 * блокирующие, секунды, со своими сокетами; управляющего сокета они не
 * касаются вовсе. Всё остальное делает цикл. Причина — в шапке d2k_sched.h
 * (единственное подключение к датапату) и в комментарии у Run на Go-стороне.
 */
/* Файл включают и как текст в составные тесты — после системных заголовков,
   где glibc (с 2026) уже задал _POSIX_C_SOURCE сам: голый #define там —
   переопределение под -Werror (CI 22.10.2026). Отдельной единицей трансляции
   значение задаётся как прежде. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#if defined(__linux__) || defined(D2K_TEST_PAGE_RELEASE)
#ifndef _DEFAULT_SOURCE   /* стенд может подключить libc раньше: не переопределять */
#define _DEFAULT_SOURCE   /* madvise: ячейка задачи отдаёт страницы (задача 60) */
#endif
#include <sys/mman.h>
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#ifdef __linux__
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/time.h>
#endif

#include "d2k_compose.h"
#include "d2k_compose_internal.h"
#include "d2k_hello.h"
#include "d2k_quic.h"
#include "d2k_quicsnap.h"
#include "d2k_quichello.h"
#include "d2k_quicconn.h"
#include "d2k_plantlv.h"
#include "d2k_plan.h"
#include "d2k_quicprobe.h"
#include "d2k_sched.h"
#include "d2k_shadow_queue.h"
#include "d2k_newchain.h"
#include <limits.h>
#include "../synthesis/verification.h"
#include "d2k_stuntrial.h"
#include "d2k_voice_discovery.h"
#include "d2k_verify.h"
#include "d2k_volume.h"
#include "d2k_domain.h"
#include "d2k_meas.h"

/* --------------------------------------------------------------------
 * Пределы. Перенесены с Go-стороны (internal/controller/controller.go, блок
 * «Пределы»), где они уже выведены; выдумывать здесь новые запрещено
 * проектным правилом «числа только из замера или наследования».
 * -------------------------------------------------------------------- */

/* Одновременных поисков. Больше — и рабочих потоков станет больше, чем у
   роутера есть смысла держать: каждый занят сетевым ожиданием, не счётом. */
#define SCHED_MAX_TASKS 64
/* ВХОД ЗАМЕРА — ДО ПАЧКИ ПРИВЕТСТВИЯ (задача 66). У QUIC это весь полёт
   клиента: приветствие Chrome с ML-KEM около 2,4 КБ в двух датаграммах, и
   прежних 2048 байт на него не хватало — снимок отсекался первой же
   проверкой длины. Контроль (ctrl) остаётся прежнего размера: пачку под
   другое имя не пересобрать, и контролем для неё служит собственный Initial
   донора (около 1200 байт). 64 задачи × (вход + снимок) — около 800 КБ,
   выделенных один раз, а не растущих. */
#define SCHED_TRIG_MAX D2K_SHAPE_MAX
#define SCHED_COOLDOWN_SLOTS 128
/* Одновременных сетевых замеров (задачи 29, 38). Замер почти не считает —
   он ждёт сеть, — но держит поток (стек 1 МиБ адресного пространства),
   запись conntrack на каждый зонд и пробный план в датапате. Поэтому предел
   не формула от ядер (задача 29 ставила min(2×ядра, 8) — оценку, не
   замер; поле 02.10.2026: KN-1811 свободен на 80–90 %, а замеров не больше
   4), а подстройка по измеренному запасу (AIMD, решение владельца: «не
   ограничивать искусственно, но с разумным буфером»):
   - рост на 1 после запуска, заполнившего предел (или при ждущей очереди
     и полном пределе), — не чаще раза за снимок ресурсов, и только если
     ВСЕ ресурсы с запасом: процессор свободен ≥ 40 %, MemAvailable ≥
     max(32 МБ, 20 % MemTotal), conntrack занят < 60 %;
   - снижение вдвое на снимке, где не хватает ЛЮБОГО: процессор свободен
     < 25 %, память ниже запаса, conntrack ≥ 60 %; не ниже 1 — один замер
     разрешён всегда; идущие не прерываются никогда;
   - между 25 и 40 % свободного процессора предел держится;
   - сверху — только реальные ёмкости (SCHED_MEASURE_SLOTS);
   - нет данных о процессоре или памяти (нет /proc, macOS) — прежний
     предел 2 (145e1da); нет conntrack — он не ограничивает.
   Пороги — решение владельца (запас под трафик, датапат и NDM), не замер. */
#define SCHED_DEFAULT_ACTIVE_MEASUREMENTS 2
#define SCHED_CPU_GROW_FREE_U   400000 /* 40 % в миллионных долях */
#define SCHED_CPU_SHRINK_FREE_U 250000 /* 25 % */
#define SCHED_MEM_RESERVE_MIN_KB (32u * 1024) /* 32 МБ */
#define SCHED_MEM_RESERVE_PCT   20
#define SCHED_CT_LIMIT_PCT      60
#define SCHED_CPU_SAMPLE_MS 1000
#define SCHED_CPU_EWMA_MS 10000
#define SCHED_LIMIT_LOG_STABLE_MS 10000
/* Ёмкость пробных планов датапата. Пробная запись имени живёт в общей
   таблице планов, адресный опыт — в своей таблице той же ёмкости; обе
   заводятся по числу потоков d2kd (--flows, по умолчанию 2048 — d2kd.c;
   установка его не меняет). Контроллер этой ёмкости у датапата не
   спрашивает (такого запроса в протоколе нет), поэтому здесь —
   задокументированная константа. Задача держит одну пробную запись за раз
   (SET_*_PROBE на том же порту/потоке заменяет прежнюю). */
#define SCHED_DP_TRIAL_SLOTS 2048
#define SCHED_MEASURE_SLOTS \
    (SCHED_MAX_TASKS < SCHED_DP_TRIAL_SLOTS ? SCHED_MAX_TASKS : SCHED_DP_TRIAL_SLOTS)
#define SCHED_MAX_QUEUED_MEASUREMENTS 16
/* Темп запуска (задача 38): не больше одного нового замера за 250 мс —
   и из очереди, и по свежему подозрению при уже идущем замере, — чтобы
   подъём предела не давал всплесков SYN/Initial. Прежняя секунда (задача
   29) нужна была, чтобы каждый выпуск судился по свежему снимку; теперь
   свежий снимок требуется для РОСТА предела (не чаще раза за снимок), а не
   для каждого старта в пределах уже измеренного. */
#define SCHED_START_GAP_MS 250

/* Жизнь задачи. Дольше — и задача занимает место, давно перестав быть про
   актуальное состояние линии. */
#define SCHED_TASK_LIFE_MS (10 * 60 * 1000)
/* ЗАСТРЯВШИЙ ЗАМЕР (этап 23, поле 28.10.2026 rr4---sn-4g5e6nss.googlevideo.com):
   срок задачи — не мера измерения. Классификация, которая ПРОДВИГАЕТСЯ
   (измеритель сообщает ход: вопрос и зонды, d2k_sched_progress_note), по сроку
   не бросается — иначе дерево свойств терялось целиком на 10-й минуте с итогом
   «failed», хотя отрицательного результата не было. Бросается только замер
   без хода дольше этого окна: одиночное сетевое ожидание измерителя ограничено
   SCHED_PROP_STEP_MS, и шестьдесят таких ожиданий без единого шага — это не
   измерение, а зависший поток. Явная отмена (stop), завершение службы и
   сроки отдельных ожиданий остаются как были. */
#define SCHED_ASK_STALL_MS (60 * SCHED_PROP_STEP_MS)

/* Отдых цели после неудачи: не долбить одну и ту же цель подряд. */
#define SCHED_REST_MS (2 * 60 * 1000)
/* Отрицательное наблюдение — оперативная защита от повторного сканирования,
   а НЕ знание каталога. Повторные CLEAR увеличивают паузу до одного часа. */
#define SCHED_CLEAR_BACKOFF_1_MS (10LL * 60 * 1000)
#define SCHED_CLEAR_BACKOFF_2_MS (30LL * 60 * 1000)
#define SCHED_CLEAR_BACKOFF_MAX_MS (60LL * 60 * 1000)
#define SCHED_INCOMPLETE_BACKOFF_MS (10LL * 60 * 1000)
#define SCHED_CHALLENGE_BACKOFF_MS (60LL * 60 * 1000)
/* Сколько держится доказательство здорового контекста под планом (этап 30):
   тот же горизонт, что первая пауза после прямого здорового прохода (CLEAR) —
   это тот же исход, только под планом. */
#define SCHED_HEALTHY_PROOF_MS SCHED_CLEAR_BACKOFF_1_MS
#define SCHED_PROOF_SLOTS 32
#define SCHED_UNKNOWN_SLOTS 32
#define SCHED_PLANOBS_SLOTS 32
/* Наблюдение потоков по conntrack (этап 37): сколько, как часто, как долго. */
#define SCHED_FLOWWATCH_SLOTS 64
#define SCHED_LATE_OBS_S 120
#define SCHED_FLOWWATCH_STEP_MS 5000
#define SCHED_FLOWWATCH_KEEP_MS (30LL * 60 * 1000)
#define SCHED_FLOWWATCH_STALL_STEPS 2
/* Явный порог планировщика, согласованный с владельцем: обычный TCP RST —
   низкоуверенное подозрение, второй должен прийти по независимому flow key,
   пока первое ещё отражает текущую линию. Это не порог дерева оригинала.
   Здесь он применяется к позднему RST после app-data (D2K_SUSPECT_RST_AFTER_APP):
   датапат шлёт его на любой TLS-поток с прикладными данными и RST, и на
   здоровом трафике одиночный такой RST устраивал шторм парных замеров. */
#define SCHED_LATE_RST_CONFIRM_MS (30 * 1000)
#define SCHED_LATE_RST_SLOTS 16
/* Одно и то же объяснение по одному имени (отдых, мёртвый адрес, одиночное
   позднее закрытие) звучит не чаще раза в SCHED_QUIET_MS. Поле 06.10: такие
   повторы шли сотнями строк в сутки и раздували журнал на флеше роутера. */
#define SCHED_QUIET_SLOTS 64
/* Отказ узла семейства живёт неделю; чистка — раз в час. */
#define SCHED_GROUP_FAIL_MAX_AGE_S (7 * 86400)
#define SCHED_GROUP_EXPIRE_EVERY_MS (60 * 60 * 1000)
#define SCHED_QUIET_MS (10 * 60 * 1000)
/* Сколько ждать решения по потоку разговора с применённым приёмом голоса.
   Приговор «молчит» датапат выносит через две секунды после приветствия
   (silence_deadline); пятнадцать — с запасом на медленную очередь событий, и
   не больше, чем человек готов слушать тишину в звонке. */
#define SCHED_VOICE_WATCH_MS (15 * 1000)
/* Продление голосового опыта: вдвое чаще потолка lease датапата. */
#define SCHED_VOICE_LEASE_RENEW_MS ((int64_t)D2K_ADDR_PROBE_LEASE_MAX_MS / 2)

/* Сколько выведенных планов держит задача. Это же потолок, который
   d2k_compose получает под свои плечи. */
#define SCHED_MAX_PLANS 8
/* Своих подтверждённых планов до полного замера пробуются ВСЕ подходящие
   (задача 49: потолок «три» из задачи 32 ничем не измерен, а свой план — одна
   проверка за секунды против ~100 зондов полного замера). В очередь задачи
   они идут порциями по SCHED_MAX_PLANS, свежие первыми; own_seen помнит, какие
   уже ставились в очередь, чтобы порции не повторялись. */
#define SCHED_OWN_SEEN_MAX 256
#define SCHED_TRIED_MAX 256
/* Memory of failed own plans retained across cooldowns (line A). */
#define SCHED_FAILED_PLANS 8
/* Опровергнутых приёмов — не больше, чем вопросов в опросе: каждый вопрос
   отвечает «да» один раз и опровергается один раз (detect/props.c, 13
   вопросов). Это граница цикла «опрос — испытание — опрос», а не бюджет
   зондов: зонды здесь тратят только НЕЗАДАННЫЕ вопросы. */
#define SCHED_ARM_REFUTED_MAX 13

/* Зондов на задачу. ЗАМЕРЕНО на живой линии 11.09 (accounts.youtube.com, та
   самая тяжёлая цель, из-за которой ревью 06.09 сказало «восьми мало»):

     19:28:26  вердикт «решает содержимое» — спрашиваю коробку о свойствах
     19:28:26  зонд вопроса 1 … 19:28:49 зонд вопроса 5   ← пять зондов
     19:28:57  поставил план 1 из 8
     19:29:40  план 1 … 19:30:12 план 2 … 19:30:42 план 3
     19:30:42  выведенные планы исчерпаны (зондов 8)      ← бюджет кончился

   Пять вопросов съели пять зондов, на планы осталось три из восьми — пять
   выведенных плечей не попробовали НИ РАЗУ, и «исчерпаны» означало «кончился
   бюджет», а не «кончились планы». Это и есть та подмена, из-за которой
   число пересматривалось.

   Новое значение не назначено с запасом, а ВЫВЕДЕНО из того, сколько зондов
   машина в принципе может потратить: пять вопросов (D2K_PROPS_QUESTIONS) плюс
   столько планов, сколько влезает в очередь (SCHED_MAX_PLANS). Больше она не
   израсходует по построению, меньше — обрежет саму себя. */
/* Reuse and new synthesis have independent bounded queues. Spending the
   reuse budget must not leave the subsequent research with no trials. */
/* БЮДЖЕТ ПОКРЫВАЕТ ЛЕСТНИЦУ ЦЕЛИКОМ, а не длину очереди планов.
 *
 * Прежнее значение выводилось из того, сколько планов влезает В ОЧЕРЕДЬ
 * (SCHED_MAX_PLANS), а не из того, сколько плеч вообще есть. Замерено на
 * роутере владельца 13.09.2026: по i.ytimg.com «выведенные планы исчерпаны
 * (зондов 22) — цель отдыхает» при СОРОКА СЕМИ выразимых плечах запасного
 * перебора. Тридцать одно не пробовалось ни разу — в том числе длинные
 * перекрытия (2, 4, 8, 16, 64, 336, 681 байт), а вердикт по этой цели гласит
 * «решает содержимое, поток пересобирается»: разрезом такую коробку не взять,
 * перекрытие — единственный ответ на неё. То есть поиск сдавался, не дойдя до
 * того приёма, ради которого и затевался.
 *
 * Слагаемые: пять вопросов дерева (D2K_PROPS_QUESTIONS), выведенные из
 * вердикта кандидаты (их не больше очереди, SCHED_MAX_PLANS), короткая
 * объёмная fake-SNI/split-лестница и запасной перебор ЦЕЛИКОМ
 * (d2k_fallback_arms — считается по самим таблицам, чтобы рост списка не
 * разошёлся с бюджетом молча).
 *
 * Цена названа прямо: поиск по одной цели может занять до сотни зондов. С тех
 * пор как пробный план виден ТОЛЬКО потоку зонда, эта цена платится нашим
 * трафиком, а не работой человека — раньше каждый зонд шёл за его счёт. */
#define SCHED_MAX_PROBES \
    ((int)(D2K_PROPS_QUESTIONS + SCHED_MAX_PLANS + \
           D2K_RX_VOLUME_PLAN_VARIANTS + d2k_fallback_arms()))

/* Сколько раз повторять испытание кандидата после ВРЕМЕННОГО отказа отправки.
 *
 * Два — не «разумное число», а следствие того, что различает повтор. Временный
 * отказ (очередь переполнилась, ядро не приняло посылку) проходит сам; если он
 * не прошёл и со второй попытки, дело не во всплеске, и дальнейшие повторы
 * тратят бюджет зондов на один и тот же исход. Детерминированный отказ —
 * «посылка длиннее того, что унесёт способ отправки» — не повторяется ВОВСЕ:
 * тот же план даст тот же результат, и десять одинаковых повторов съели бы
 * весь бюджет, после чего поиск объявил бы «рабочего обхода нет», не проверив
 * ни одного другого кандидата (0009, U2). */
#define SCHED_UNSENT_RETRIES 2
/* СКОЛЬКО РАЗ ПЕРЕИСПЫТАТЬ КАНДИДАТА, ЕСЛИ ПЛАНА НА ПОТОКЕ ЗОНДА НЕ БЫЛО.
 *
 * Два, и это не круглое число «на всякий случай». Причина отсутствия плана
 * одна и известна: план ставится записью в управляющий сокет, а испытание
 * стартует сразу, и на живой линии зонд иногда уходит раньше, чем датапат
 * прочитал команду. Такая гонка проигрывается один раз — ко второму зонду
 * команда давно прочитана. Второй повтор — запас на потерю события, третий
 * уже ничего не добавил бы, а стоил бы зонда из общего бюджета.
 *
 * Повтор дешевле ошибки несоизмеримо: зонд стоит одного опыта, а выброшенный
 * рабочий план — поиска целиком и цели без обхода (поле 17.09, discord.com). */
#define SCHED_BARE_RETRIES 1

/* ПОВТОР ПРОВЕРКИ КАНДИДАТА ИЗ ЗАМЕРА (поле 14.10.2026, fost.club с роутера).
 * Вечером провайдер ведёт часть соединений к одному адресу по маршруту, где
 * коробка снимает сегмент с именем (TTL SYN-ACK 53–54), остальные проходят
 * всегда; с VPS — 20/20, ночью — 84/84. Вопрос о свойствах отвечает
 * большинством (detect/props.c), а проверка своим зондом была одной попыткой
 * и выбрасывала выведенный из замера план, если зонд попал на тот маршрут.
 * Удача проверки — ответ приложения под нашим планом, ложного «да» повтор
 * дать не может; он стоит только зонда. Поэтому — до двух повторов и только
 * кандидату, которого вывел замер этого поиска. */
#define SCHED_ARM_VERIFY_RETRIES 2

/* СКОЛЬКО ЖДАТЬ, ПОКА ДАТАПАТ ПРИМЕТ ПРОБНЫЙ ПЛАН.
 *
 * План уходит записью в управляющий сокет, а датапат читает её своим циклом.
 * Зонд, запущенный сразу, обгонял её на живой линии: замер 18.09 на
 * discord.com — «удержание не начато: голова=1 нагрузка=1388 план=нет», и так
 * на каждой попытке. Зонд шёл голым, коробка резала его, и РАБОЧИЙ план
 * объявлялся негодным.
 *
 * ПРЕДЕЛ — ЗАПАСНОЙ ВЫХОД, А НЕ ЗАДЕРЖКА. Обычный путь — подтверждение
 * команды, и оно приходит за доли миллисекунды: датапат читает управляющий
 * сокет тем же циклом, что и пакеты. Предел нужен потому, что события у
 * датапата лосси по контракту (d2k_ctl.h) — подтверждение может не доехать, а
 * задача не имеет права зависнуть. Полсотни миллисекунд на порядки больше
 * наблюдаемого времени ответа и при этом не растягивают перебор кандидатов. */
#define SCHED_TRIAL_SETTLE_MS 50

/* Отказ, который повтором не лечится: результат зависит от плана и канала, а
 * не от момента. Разводить обязательно — иначе «наша поломка» и «всплеск»
 * лечатся одинаково и одинаково неправильно. */
static int refuse_is_permanent(uint8_t code) {
    /* NOT_APPLIED постоянен в том же смысле, что TOO_LONG: тот же план на том
       же приветствии будет отвергнут исполнителем снова. Повторять нечего,
       кандидат не виноват, свойство коробки не пишется. */
    /* FLOW_UNFIT — поток клиента не несёт того, что план требует (метка
       времени у tcp-template-v1): тот же план на том же потоке будет отвергнут
       снова. Для чужого потока это знак перемерить цель для этого клиента
       (on_refused_unfit), для зондового — опыт невозможен, кандидат не
       виноват. Замысел 2026-10-23, п. 5.3. */
    return code == D2K_REFUSE_TOO_LONG || code == D2K_REFUSE_NOT_APPLIED ||
           code == D2K_REFUSE_FLOW_UNFIT;
}

/* Поток испорчен недоисполнением: часть плана ушла, остаток нет. Отличается
 * от прочих локальных отказов тем, ЧТО случилось с клиентом, а не тем, что
 * делать дальше: испытывать кандидата снова можно — зонд откроет НОВЫЙ поток,
 * — но объяснение обязано называть повреждение, иначе в журнале поиска
 * останется «посылка не ушла», и человек не узнает, что чей-то поток порвался
 * (0009, U3-R2). */
static int refuse_is_damage(uint8_t code) {
    return code == D2K_REFUSE_DAMAGED;
}

/* Потолок ОДНОГО шага вопроса. Унаследован из D2K_PROPS_ASK_WAIT_MS (5000мс,
   compose.c) вместе с его оговоркой: это страховка от молчания, а не
   ожидаемая длительность, и для этого применения он НЕ измерен. */
#define SCHED_PROP_STEP_MS 5000

/* Потолок ОДНОГО шага испытания: столько же и по той же причине. Своего числа
   здесь взяться неоткуда — зонд идёт к той же цели по тому же транспорту, что
   и зонд вопроса, и его потолок это та же страховка от молчания. Выдумывать
   рядом второе число значило бы завести параметр, ничем не измеренный. */
#define SCHED_VERIFY_STEP_MS SCHED_PROP_STEP_MS

/* Сколько имён помним за ключами потоков. Приветствие приходит на КАЖДОЕ
   соединение, подозрение — на малую их часть; таблица нужна только чтобы
   пережить промежуток между ними. */
#define SCHED_SEEN 512

/* ECH-свидетели (поле 04.10, rutracker в Chrome). Кандидаты одного поиска —
   свои наблюдения и свой каталог; ответы HTTPS RR помнятся между поисками,
   поэтому имя без нужной конфигурации места в следующем списке не занимает
   и за несколько поисков проверяется каждое имя, а не 4 последних.
   Положительный ответ живёт дольше: конфигурация CDN меняется редко;
   отрицательный — короче: он же означает и тайм-аут DNS. */
#define SCHED_ECH_WITNESSES 32
#define SCHED_ECH_RR 256
#define SCHED_ECH_RR_YES_MS (6LL * 3600 * 1000)
#define SCHED_ECH_RR_NO_MS  (30LL * 60 * 1000)

/* Имя приманки по умолчанию. Не выдумано: то же значение, что у Go-стороны в
   internal/config/config.go (DecoySNI = "disk.rzd.ru"), и по той же причине —
   имя, заведомо не связанное с целью, но реально обслуживаемое. Измеренное
   проходящее имя точнее заготовки (Go: decoyFor), но измерять его умеет пока
   только путь объёма, которого здесь ещё нет; когда появится — брать его. */
#define SCHED_DECOY "disk.rzd.ru"

/* Форма приветствия СОБСТВЕННОГО зонда — то, в чём проверка состоялась, и то,
 * что уезжает в привязку (d2k_catalog.h про shape/verified_by).
 *
 * Не назначено, а ВЫТЕКАЕТ из того, чем зонд доказывает: D2K_VER_APPLICATION
 * достижим только через ЗАВЕРШЁННОЕ рукопожатие TLS 1.3 (core/tls13.c ведёт
 * его своим ключом), а такое рукопожатие по RFC 8446 §4.2.1 невозможно без
 * расширения supported_versions с 0x0304 — ровно того признака, по которому
 * d2k_hello_shape и отличает MODERN от LEGACY. Константа, а не запрос у
 * зонда на каждом успехе: форма его приветствия не меняется от цели к цели.
 * Связь с проводом проверяется замером, а не на слово — test_sched.c,
 * probe_hello_shape: приветствие снимается с сокета и разбирается той же
 * d2k_hello_shape.
 *
 * Когда появится второй зонд (скажем, старой формы или для QUIC), форме
 * придётся приехать из d2k_ver_result, а не отсюда: одна константа на два
 * разных обращения снова превратила бы контекст проверки в догадку. */
#define SCHED_PROBE_SHAPE D2K_SHAPE_MODERN

/* --------------------------------------------------------------------
 * Подменяемые оракулы (см. d2k_sched.h).
 * -------------------------------------------------------------------- */

/* Умолчание зонда подтверждения. Прослойка, а не сам d2k_verify_probe, из-за
 * ОДНОГО: зонд ведёт TCP и своё рукопожатие TLS 1.3, а доказательство
 * принадлежит транспорту. Подтвердить им план QUIC значило бы записать успех
 * ДРУГОГО транспорта — той самой подменой, из-за которой эта вертикаль и
 * затеяна. Своего зонда для QUIC сегодня нет (quicprobe умеет спрашивать
 * Initial, а не доводить обмен приложения до конца), и честный ответ про
 * QUIC — «не измерено» (§2.4): кандидат ставится, но в каталог не попадает.
 * Когда такой зонд появится, он встанет сюда же. */
static d2k_ver_result verify_default(int use_fd, const char *ip, uint16_t port,
                                     uint8_t transport, const char *sni,
                                     int deadline_ms, size_t hello_wire,
                                     uint8_t client_shape) {
    if (transport == 17) {
        /* Зонд QUIC появился: доводит рукопожатие до прикладных ключей и
           берёт код ответа HTTP/3. Порог доказательства тот же, что у TCP, —
           прикладной обмен, а не «сервер что-то прислал» (§4.2). */
        return d2k_verify_probe_quic_on(use_fd, ip, port, sni, deadline_ms, hello_wire);
    }
    if (transport != 6) {
        if (use_fd >= 0) { close(use_fd); }
        d2k_ver_result r;
        memset(&r, 0, sizeof r);
        r.fd = -1;
        r.unsupported = 1;
        snprintf(r.reason, sizeof r.reason,
                 "зонда подтверждения для этого транспорта нет — не измерено");
        return r;
    }
    if (client_shape == (uint8_t)D2K_SHAPE_LEGACY) {
        /* ТЕМ ЖЕ ПРОТОКОЛОМ, ЧТО И КЛИЕНТ. */
        return d2k_verify_probe12_on(use_fd, ip, port, sni, deadline_ms, hello_wire);
    }
    return d2k_verify_probe_on(use_fd, ip, port, sni, deadline_ms, hello_wire);
}

static d2k_ver_result preflight_verify_default(int use_fd,const char *ip,uint16_t port,
    uint8_t transport,const char *sni,int deadline_ms,size_t hello_wire,uint8_t client_shape) {
    if(transport!=6)return verify_default(use_fd,ip,port,transport,sni,deadline_ms,hello_wire,client_shape);
    return d2k_verify_preflight_on(use_fd,ip,port,sni,deadline_ms,hello_wire,
        client_shape==(uint8_t)D2K_SHAPE_LEGACY);
}

static int bind_default(uint8_t transport, uint8_t family, int *out_fd, uint16_t *sport_be) {
    return (transport == 17) ? d2k_props_bind_udp_family(family, out_fd, sport_be)
                             : d2k_props_bind_family(family, out_fd, sport_be);
}

static d2k_ver_result verify_rx_default(int use_fd, const char *ip, uint16_t port,
    uint8_t transport, const char *sni, int deadline_ms, size_t hello_wire,
    uint8_t client_shape) {
    if (transport != 6) return verify_default(use_fd, ip, port, transport, sni,
                                             deadline_ms, hello_wire, client_shape);
    return d2k_verify_probe_identity_on(use_fd, ip, port, sni, deadline_ms,
                                       hello_wire, client_shape == D2K_SHAPE_LEGACY);
}

static d2k_ver_result verify_rx_gzip_default(int use_fd, const char *ip, uint16_t port,
    uint8_t transport, const char *sni, int deadline_ms, size_t hello_wire,
    uint8_t client_shape) {
    if (transport != 6) return verify_default(use_fd, ip, port, transport, sni,
                                             deadline_ms, hello_wire, client_shape);
    return d2k_verify_probe_gzip_on(use_fd, ip, port, sni, deadline_ms,
                                   hello_wire, client_shape == D2K_SHAPE_LEGACY);
}

static int mark_default(int fd, uint32_t mark) {
    return d2k_mark_hook(fd, mark);
}

d2k_sched_bind_fn d2k_sched_bind_hook = bind_default;
d2k_sched_mark_fn d2k_sched_mark_hook = mark_default;
d2k_sched_vol_fn  d2k_sched_vol_hook  = d2k_volume_probe;
d2k_sched_vol_path_fn d2k_sched_vol_path_hook = d2k_volume_probe_path;
d2k_sched_path_ver_fn d2k_sched_path_ver_hook = d2k_verify_probe_path_on;
d2k_sched_quic_path_ver_fn d2k_sched_quic_path_ver_hook = d2k_verify_probe_quic_path_on;
/* Socket-write diagnostics (core/verdict.c) are not packet-runtime proof.
 * d2kc installs detect's shared executor explicitly. Library users must do
 * the same: no implicit second bypass engine when the hook is missing. */
static d2k_vres classify_unconfigured(const char *ip, uint16_t port,
                                   d2k_hello trigger, d2k_hello control,
                                   uint32_t mark, int repeats,
                                   uint32_t gap_us, uint32_t wait_ms,
                                   const volatile sig_atomic_t *stop,
                                   const d2k_sched_tcp_extra *extra) {
    (void)ip; (void)port; (void)trigger; (void)control; (void)mark;
    (void)repeats; (void)gap_us; (void)wait_ms; (void)stop; (void)extra;
    d2k_vres r = {0};
    r.verdict = D2K_V_FLAKY;
    r.owns_search = 1;
    snprintf(r.reason, sizeof r.reason, "общий исполнитель замера TCP не подключён");
    return r;
}

d2k_sched_tcp_fn d2k_sched_tcp_hook = classify_unconfigured;
d2k_sched_ech_resolve_fn d2k_sched_ech_resolve_hook = d2k_ech_resolve;
d2k_sched_replay_ver_fn d2k_sched_replay_ver_hook = d2k_verify_replay_on;
d2k_sched_replay_ver_fn d2k_sched_quic_replay_ver_hook = d2k_verify_quic_replay_on;
d2k_sched_tcp_fn  d2k_sched_tcp_base_hook = NULL;
d2k_sched_tcp_ack_fn d2k_sched_tcp_ack_hook = NULL;
d2k_sched_quic_base_fn  d2k_sched_quic_base_hook = NULL;
d2k_sched_quic_seeded_fn d2k_sched_quic_seeded_hook = NULL;
d2k_sched_quic_fn d2k_sched_quic_hook = d2k_quic_run;
d2k_sched_ver_fn  d2k_sched_ver_hook  = verify_default;
d2k_sched_ver_fn  d2k_sched_preflight_ver_hook = preflight_verify_default;
d2k_sched_ver_fn  d2k_sched_rx_ver_hook = verify_rx_default;
d2k_sched_ver_fn  d2k_sched_rx_gzip_ver_hook = verify_rx_gzip_default;
d2k_sched_alpn_ver_fn d2k_sched_alpn_ver_hook = d2k_verify_probe_alpn_on;
d2k_sched_ver12hs_fn d2k_sched_ver12hs_hook = d2k_verify_probe12_handshake_on;

static d2k_voice_res voice_default(const d2k_voice_opt *opt) {
    return d2k_voice_run(opt);
}
d2k_sched_voice_fn d2k_sched_voice_hook = voice_default;
d2k_sched_stun_fn d2k_sched_stun_hook = d2k_stun_probe;
d2k_sched_stun_run_fn d2k_sched_stun_run_hook = d2k_stun_probe_run;
d2k_sched_spawn_fn d2k_sched_spawn_hook = NULL;

int d2k_sched_cpu_parse(const char *line, uint64_t *busy, uint64_t *total) {
    if (!line || !busy || !total || strncmp(line, "cpu ", 4) != 0) return -1;
    const char *p = line + 4;
    uint64_t v[8] = {0};
    int n = 0;
    while (n < 8) {
        while (*p == ' ' || *p == '\t') p++;
        if (*p < '0' || *p > '9') break;
        char *end = NULL;
        errno = 0;
        unsigned long long x = strtoull(p, &end, 10);
        if (errno || end == p) return -1;
        v[n++] = (uint64_t)x;
        p = end;
    }
    if (n < 4) return -1;   /* user nice system idle — минимум ядра 2.4 */
    uint64_t sum = 0;
    for (int i = 0; i < n; i++) sum += v[i];
    uint64_t idle = v[3] + v[4]; /* idle + iowait: процессор не занят */
    if (sum < idle) return -1;
    *total = sum;
    *busy = sum - idle;
    return 0;
}

static int cpu_read_proc(uint64_t *busy, uint64_t *total, unsigned *cores) {
    FILE *f = fopen("/proc/stat", "r");
    if (!f) return -1;
    char line[512];
    int rc = fgets(line, sizeof line, f) ? d2k_sched_cpu_parse(line, busy, total) : -1;
    fclose(f);
    if (rc) return -1;
#ifdef _SC_NPROCESSORS_ONLN
    long n = sysconf(_SC_NPROCESSORS_ONLN);
#else
    long n = 1; /* без /proc/stat сюда не доходим; на всякий случай — одно ядро */
#endif
    *cores = n > 0 ? (unsigned)n : 1u;
    return 0;
}
d2k_sched_cpu_fn d2k_sched_cpu_hook = cpu_read_proc;

/* Значение строки «Ключ:   число kB» из текста /proc/meminfo. */
static int meminfo_field(const char *text, const char *key, uint64_t *kb) {
    size_t kl = strlen(key);
    for (const char *p = text; p && *p; ) {
        if (strncmp(p, key, kl) == 0 && p[kl] == ':') {
            const char *v = p + kl + 1;
            while (*v == ' ' || *v == '\t') v++;
            if (*v < '0' || *v > '9') return -1;
            char *end = NULL;
            errno = 0;
            unsigned long long x = strtoull(v, &end, 10);
            if (errno || end == v) return -1;
            *kb = (uint64_t)x;
            return 0;
        }
        p = strchr(p, '\n');
        if (p) p++;
    }
    return -1;
}

int d2k_sched_meminfo_parse(const char *text, uint64_t *avail_kb, uint64_t *total_kb) {
    if (!text || !avail_kb || !total_kb) return -1;
    uint64_t av = 0, tot = 0;
    if (meminfo_field(text, "MemTotal", &tot) || meminfo_field(text, "MemAvailable", &av) ||
        tot == 0)
        return -1;
    *avail_kb = av;
    *total_kb = tot;
    return 0;
}

static int mem_read_proc(uint64_t *avail_kb, uint64_t *total_kb) {
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return -1;
    char buf[4096];
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = '\0';
    return d2k_sched_meminfo_parse(buf, avail_kb, total_kb);
}
d2k_sched_mem_fn d2k_sched_mem_hook = mem_read_proc;

static int read_u64_file(const char *path, uint64_t *v) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    unsigned long long x = 0;
    int ok = fscanf(f, "%llu", &x) == 1;
    fclose(f);
    if (!ok) return -1;
    *v = (uint64_t)x;
    return 0;
}

static int ct_read_proc(uint64_t *count, uint64_t *max) {
    if (read_u64_file("/proc/sys/net/netfilter/nf_conntrack_count", count) ||
        read_u64_file("/proc/sys/net/netfilter/nf_conntrack_max", max) || *max == 0)
        return -1;
    return 0;
}
d2k_sched_ct_fn d2k_sched_ct_hook = ct_read_proc;

/* --------------------------------------------------------------------
 * Состояние задачи.
 * -------------------------------------------------------------------- */

typedef enum {
    T_FREE = 0,
    T_QUEUED,       /* подозрение сохранено, ждёт безопасного слота измерения */
    T_GATE_INSTALL, T_GATE_VERIFY, T_GATE_COMMIT, /* endpoint trial, then ordinary TLS application verifier */
    T_ASKING,        /* сетевой оракул работает в потоке */
    /* Снимок приветствия заказан, поиск ЖДЁТ его. Состояние заведено ради
       QUIC и существует только для него: у TLS есть профиль холодного старта
       (d2k_hello_from_profile), у QUIC профиля нет и быть не может —
       приветствие едет внутри зашифрованного Initial, и «профиль» пришлось
       бы хранить вместе с ключами чужой сессии. Мерить QUIC TLS-байтами
       нельзя: это не «хуже, чем снимок», это другой протокол.

       Ждать приходится потому, что снимок приезжает СОБЫТИЕМ: датапат
       отвечает на заказ немедленно, когда подходящее приветствие у него уже
       лежит, но кадр всё равно читается следующим кругом цикла. Раньше
       поиск стартовал тут же, а снимок дописывался в t->trig уже на ходу —
       рабочий поток читал байты, которые в это же время переписывались. */
    T_SHAPE_WAIT,
    T_PROPS_CONTACT, /* план-вопрос отправлен, обращение к цели работает в потоке */
    T_PROPS_WAIT,    /* обращение состоялось, ждём обмена по своему потоку */
    T_PLANNING,      /* вектор собран, ставим планы */
    T_TRIAL_SETTLE,  /* план записан в сокет; ждём, пока датапат его примет */
    T_VERIFY,        /* кандидат стоит, наш зонд идёт к цели в потоке */
    T_VERIFY_WAIT,   /* зонд вернулся успехом, ждём применения плана к ЕГО потоку */
    /* Подтверждено; смотрим на ЖИВОЙ трафик. Прежде это состояние означало
       «ждём, пока пользователь откроет цель» — того ожидания больше нет
       (см. шапку файла). Теперь оно означает другое: план подтверждён и
       стоит. Последующий TLS-ответ остаётся наблюдением, а не новым
       прикладным подтверждением. */
    T_WATCHING,
    T_DOH_HEALTH,
    T_DNS_PLAIN_TRIAL,
    T_RESTING,       /* неудача, цель отдыхает */
    T_RAW_MEASURE_ACK, T_RAW_MEASURE_OBSERVE, T_RAW_MEASURED,
    T_RAW_TRIAL,     /* опыт без протокола стоит на порту клиента, ждём его повтора (APPLIED) */
    T_RAW_WATCH,     /* план применён к повтору клиента, ждём ответа сервера (EXCHANGE) */
    T_STUN_MEASURE,  /* numeric endpoint Binding transaction */
    T_STUN_ACK, T_STUN_PROBE, T_STUN_PROOF, T_STUN_CLIENT, T_VOICE_INSTALL,
    T_VOICE_MEASURE, /* C voice/STUN instrument runs in a worker */
    /* ГОЛОС: временный arm измерен на конкретной conntrack-пятёрке и
       ограничен её локальным портом, ждём применения только к этому потоку. */
    T_VOICE_TRIAL,
    /* Приём применился к потоку разговора — ждём по нему ответа сервера или
       молчания. */
    T_VOICE_WATCH
} task_state;

/* Что делает рабочий поток задачи. Потоки заводятся только под сетевые
   оракулы; управляющего сокета они не касаются (см. шапку d2k_sched.h). */
typedef enum { JOB_NONE = 0, JOB_CLASSIFY, JOB_CONTACT, JOB_VERIFY, JOB_VOICE, JOB_STUN,
    JOB_STUN_TRIAL, JOB_DOH_HEALTH, JOB_DNS_PLAIN_PREPARE, JOB_DNS_PLAIN_RUN } task_job;

static int is_voice_class(const char *name, uint8_t transport);

typedef struct {
    task_state state;
    char       name[256];
    uint8_t    transport;
    uint8_t    family;
    char       ip[INET6_ADDRSTRLEN];
    uint16_t   port;

    int64_t    started_ms; /* active search/lifecycle budget begins on launch */
    int64_t    began_ms;   /* when this search began, for the card and verdict line only (task 49) */
    int64_t    queued_ms;  /* independent age of a queued suspicion */
    uint64_t   queued_event;
    uint8_t    queued_response_priority;
    /* «Горячая» цель (задача 29): по ждущей в очереди пришло новое
       подозрение — номер события последнего такого и их число. Очередь
       выпускает сначала горячие (по свежести), остальные — FIFO. */
    uint64_t   hot_event;
    unsigned   hot_count;
    int64_t    rest_until_ms;
    int        probes;
    uint64_t   report_id;
    int        report_closed;
    int64_t    report_admitted_ms; /* -1 until scheduler time is known */
    int64_t    report_queue_ms;

    /* ГОЛОС/АДРЕСНЫЙ UDP: поток, к которому применился приём, и наблюдения.
       Обратная датаграмма не доказывает протокольный или прикладной успех.
       Флаги ставят обработчики событий, сроки опыта проверяет тик. */
    /* ЦЕЛЬ — АДРЕС, А НЕ ИМЯ. Так бывает у QUIC, чьё приветствие разбросано
       по датаграммам: имя не читается ни нами, ни коробкой, а приём разноса
       от имени не зависит. Выдумывать имя запрещено (D2K_SPEC). */
    int         by_addr;
    int         stun_target;
    /* ПОТОК БЕЗ РАСПОЗНАННОГО ПРОТОКОЛА (этап 12): опыт — собственный план
       этого адреса на ПОВТОРЕ первого сегмента клиента (точная пробная запись
       порта клиента, форма RAW), доказательство — ответ сервера на то же
       продолжение (уровень пути; протокол и приложение не измеряются). */
    int         raw;
    int64_t     raw_until_ms;
    /* Измеренный опыт (v27): срок датапата — отдельные аренды не длиннее
       D2K_ADDR_PROBE_LEASE_MAX_MS, продлеваемые тем же опытом до конца окна. */
    int64_t     raw_lease_until_ms, raw_renew_sent_ms;
    uint32_t    raw_lease_ms, raw_renew_lease_ms;
    int64_t     raw_trial_window_ms;
    int         raw_renewing;
    int64_t raw_obs_sent_ms, raw_obs_lease_ms, raw_obs_renew_ms;
    int raw_obs_renewing;
    struct d2k_rawmeasure_request raw_measure_request;
    struct d2k_rawmeasure_report raw_measure_report;
    uint64_t raw_execution_id, raw_early_reply_execution;
    int raw_own_candidate, raw_skip_own;
    uint32_t raw_previous_seq;
    uint16_t raw_previous_len;
    uint8_t raw_previous_digest[D2K_RM_SAMPLE_DIGEST_LEN];
    char        raw_plan_id[40];
    char        raw_proto[16];
    uint8_t     addr_probe_src_ip[16];
    uint16_t    addr_probe_src_port_be;
    uint8_t     addr_probe_trial_id[D2K_TRIAL_ID_LEN];
    int         addr_probe_identity_valid;
    /* Точный сервер голосового опыта (задача 15): берётся из замера, а не из
       server_of — у голоса оба порта эфемерные, и догадка по портам может
       назвать сервером клиента. Ноль — адресат по-старому, t->ip/t->port. */
    uint8_t     addr_probe_dst_ip[16];
    uint16_t    addr_probe_dst_port_be;
    int64_t     voice_lease_ms;   /* когда опыт голоса последний раз (пере)ставлен */
    d2k_flowkey voice_flow;
    int         voice_flow_bound;
    int         voice_answered;
    int         voice_proven;
    uint64_t    voice_execution_id;
    d2k_binding_context voice_execution_binding;
    uint8_t     voice_execution_plan_id[D2K_PLAN_ID_LEN];
    uint8_t     voice_execution_trial_id[D2K_TRIAL_ID_LEN];
    int         voice_discovery_verified;
    uint8_t     voice_known_prefix[20];
    int         voice_known_prefix_valid;
    uint8_t     voice_proof_code;
    int         voice_silent;
    int64_t     voice_watch_ms;

    /* Приветствия. trigger — снятое датапатом, если уже поймано; иначе
       профиль холодного старта. control — приманка ДРУГИМ именем (§7). */
    uint8_t    trig[SCHED_TRIG_MAX];
    size_t     trig_len;
    uint8_t    ctrl[2048];
    size_t     ctrl_len;
    int        shape_armed;
    uint8_t    shape_request_id[16];
    int        shape_request_pending;
    int64_t    shape_request_until_ms;
    int        watch_shape_pending;
    char       watch_shape_ip[INET6_ADDRSTRLEN];
    uint16_t   watch_shape_port;
    /* Снимок в trig СНЯТ С ПРОВОДА, а не собран из профиля холодного старта.
       Различать обязательно: fill_hellos при пустом снимке подставляет
       профиль MODERN, и без этого признака «форма живого клиента» читалась бы
       по заготовке — то есть выдавалась бы за измерение то, что им не
       является (§2.4). Ноль означает «форма клиента не измерена». */
    int        trig_snapped;
    /* Набор опций TCP клиента снимка в trig (замысел 2026-10-23, п. 5.1):
       едет зонду вместе с байтами; known == 0 — снимок без набора, зонд
       здоровался прежним набором, и привязка помечается PROFILE. snap_* —
       то же для снимка, ждущего перезапуска в snap. */
    uint8_t    client_opts[40];
    size_t     client_opts_len;
    int        client_opts_known;
    uint8_t    snap_opts[40];
    size_t     snap_opts_len;
    int        snap_opts_known;
    /* ПРОГОН ОСТАНОВЛЕН РАДИ СНИМКА КЛИЕНТА (задача 31). Взводит on_shape,
       когда приветствие клиента приходит во время профильного замера; байты
       снимка лежат здесь, у задачи, а не только в общей ячейке tcp_shape:
       пока измеритель доходит до границы зонда, ячейку занимает приветствие
       соседнего имени, и перезапуск терял свою цель. Результат такого
       прогона — не замер и не вердикт: он выбрасывается, поиск повторяется
       этими байтами. Флаг stop для этого не годится — его взводит и
       join_worker. */
    int        snap_stop;
    /* ЗАДАЧА 54, I2. addr_recheck — адрес задачи держит вердикт address, и
       прогон начинается с нейтрального байта до любого триггера (ставит
       главный поток при старте поиска, снимает рабочий, задав вопрос).
       addr_ack — исход этого вопроса в текущем прогоне: 1 подтверждён,
       2 тишина (вердикт address подтверждён без триггеров), 0 не задавался. */
    int        addr_recheck;
    int        addr_ack;
    uint8_t    snap[SCHED_TRIG_MAX];
    size_t     snap_len;
    /* То же для QUIC: целый Initial клиента ЭТОЙ цели, пойманный во время
       поиска, хранится у задачи — общую ячейку quic_shape к перемеру может
       занять соседнее имя. snap_seq — номер снимка в quic_shape_seq, по нему
       видно, пришёл ли он после установки испытуемого плана. */
    uint64_t   snap_seq;

    /* Кандидаты, собранные d2k_compose по вердикту. */
    char       plans[SCHED_MAX_PLANS][4096];
    char       plan_boxes[SCHED_MAX_PLANS][40]; /* candidate source, not established identity */
    size_t     n_plans;
    size_t     next_plan;

    /* Испытание текущего кандидата собственным зондом (§4.2, core/verify.c).

       ver_plan_id — идентификатор, С КОТОРЫМ кандидат ушёл на провод: по нему
       событие применения отличается от применения предыдущего кандидата,
       чьё событие опоздало (install_next ниже).

       ver_early/ver_seen — ограниченный набор полных ключей применений,
       замеченных пока зонд ещё в сети. Сверка отложена до его возврата.

       ver_ok — применение сошлось с потоком зонда. Ноль здесь означает «не
       измерено», а не «плана не было» (§2.4): событие могло потеряться
       (d2k_ctl.h), и это проверяется отдельно по ver_dropped0. */
    d2k_ver_result ver;
    uint8_t    ver_plan_id[D2K_PLAN_ID_LEN];
    d2k_flowkey ver_flow;
    /* Bounded early-event cache: IP addresses are part of the proof, not
       just the local port. Concurrent clients may use the same port. */
    d2k_flowkey ver_early[8];
    /* РАННИЕ ОТКАЗЫ — тем же приёмом, что и ранние применения выше, и по той
       же причине: местный порт зонда назначает ядро, и до возврата зонда его
       не знает никто. Пока ключа нет, отказ нельзя приписать НАШЕМУ потоку.

       Один пробный план действует и на соседние подключения той же цели,
       поэтому отказ по цели и идентификатору плана совпадает с чужим
       обращением так же легко, как со своим. Сверять только их значило бы
       съесть чужую неудачу как свою и без нужды переиспытать кандидата
       (доказано стендом ревью: свой порт 40091, чужой 49999). */
    d2k_flowkey ver_unsent_early[8];
    uint8_t    ver_unsent_code_early[8];
    size_t     ver_unsent_seen;
    size_t     ver_seen;
    int        ver_ok;
    /* Последняя ПРИЧИНА, по которой посылка плана не ушла на провод
       (D2K_REFUSE_*), либо 0. Не «флаг неудачи»: это код, и он попадает в
       объяснение, чтобы отказ не читался как промах коробки. Сбрасывается при
       заведении задачи (task_reset) и перед повторным испытанием. */
    uint8_t    unsent_code;
    /* Сколько раз этого кандидата уже переиспытывали после ВРЕМЕННОГО отказа
       отправки. Сбрасывается вместе с кандидатом: счёт про одну гипотезу, а
       не про задачу. */
    uint8_t    unsent_tries;
    /* ПОСТОЯННЫЙ отказ, пришедший на ЧУЖОЙ поток — тот, что открыл настоящий
       клиент, а не наш зонд. Испытываемый план стоит на цели целиком, и
       браузер ходит по нему одновременно с зондом; приветствие браузера
       длиннее нашего втрое (лаборатория 13.09.2026, седьмая находка). Отсюда
       исход, который иначе не виден: куски приветствия ЗОНДА в посылку
       помещаются и план честно подтверждается, а куски КЛИЕНТСКОГО — нет, и
       у человека обхода не появляется.

       Хранится ИДЕНТИФИКАТОР, а не флаг: на цели за время поиска сменится
       несколько планов, и «не поместился» относится к одному из них.
       Сбрасывается вместе с кандидатом (install_next) — как и ранние
       отказы. */
    uint8_t    unfit_plan_id[8][D2K_PLAN_ID_LEN];
    size_t     unfit_seen;
    /* Идентификатор плана ЗАДАННОГО ВОПРОСА — с ним вопрос ушёл на провод.
       По нему сверяется «применён», как у кандидата по ver_plan_id: одного
       ключа потока мало, на нём мог примениться другой план. */
    uint8_t    prop_plan_id[D2K_PLAN_ID_LEN];
    /* Номер следующего плеча ЗАПАСНОГО ПЕРЕБОРА (третий источник кандидатов,
       после готовых планов и синтеза). */
    int        search_owned;
    /* Замер владеет поиском, блок доказан, а выразимого планом приёма нет:
       запасной список взят ЯВНО (решение координатора 04.10, поле
       rutracker.org/discord.com), а не через устаревший search_owned. */
    int        owned_fallback;
    size_t     fb_next;
    /* Хэши уже испытанных текстов планов — чтобы перебор не предлагал то, что
       синтез уже дал. Одинаковый текст это один и тот же план, сколько бы
       источников его ни назвало. */
    /* Испытанные тексты. Ёмкость с запасом на фазу своих планов (задача 49:
       испытываются все подходящие, до бюджета кандидатов); переполнение не
       молчит — tried_full и строка в журнале (tried_note). */
    uint32_t   tried[SCHED_TRIED_MAX];
    size_t     n_tried;
    /* ИСПЫТАННЫЕ СВОИ (КАТАЛОЖНЫЕ) ПЛАНЫ — ОТДЕЛЬНО ОТ ВСЕЙ ОЧЕРЕДИ.
       В tried лежит всё, что поиск ставил, включая кандидатов запасного
       перебора: за один провалившийся поиск их десятки, и восемь мест памяти
       остывания забивались ими целиком — хэшу своего плана места не
       оставалось. Проверке появившегося плана (plan_news_recheck) нужны ровно
       СВОИ планы: других она и не предлагает. */
    uint32_t   own_tried[SCHED_FAILED_PLANS];
    uint8_t    n_own_tried;
    int        tried_full;
    int64_t    ver_until_ms;
    uint32_t   ver_dropped0;    /* сколько событий было потеряно, когда план встал */

    /* Отпечаток коробки, накопленный по приметам подозрений ЭТОЙ цели. По
       нему каталог узнаёт уже изученную коробку (d2k_catalog_match) — без
       этого каждая цель заводила бы новую «коробку», и каталог перестал бы
       быть каталогом коробок. */
    d2k_cat_fp fp;
    /* ЗНАНИЕ О КОРОБКЕ, СНЯТОЕ ДЛЯ ЭТОГО ЗАМЕРА (23.10.2026). Снимок делает
       ГЛАВНЫЙ ПОТОК перед запуском рабочего (start_worker): каталог меняется
       главным потоком при подтверждении планов других целей, и читать его из
       рабочего значило бы гонку. known_valid — снимок есть. */
    d2k_box_props known_props;
    int        known_valid;
    /* id узнанной коробки, пусто — не узнана. */
    char       box_id[40];
    /* БЮДЖЕТ ПОТОКА испытания (задача 55): пакеты с данными, после которых
       коробка глушит поток, и откуда число взято. Считает главный поток при
       запуске испытания (task_budget) — рабочий каталога не читает. */
    unsigned   budget_pk;
    char       budget_src[96];
    /* План, под которым шёл поток подозрения (planned): испытывается первым
       (задача 55, §2.3); его подтверждение — «подозрение было ложным». */
    char       bound_plan_id[40];
    /* ЧАСТИЧНЫЙ ОБХОД (поле 04.10 12:24, updates.discord.com): кандидат с
       доказанным применением снял блок рукопожатия и ответил, но поток
       оборвался бюджетом посреди повторов. Не провал: поиск идёт дальше за
       проходящим бюджет, а если такого нет — подтверждается лучший частичный
       (больше пакетов до обрыва, затем успехи плана) с отметкой «оборван». */
    int        partial_valid, partial_finishing;
    char       partial_text[4096]; /* как plans[] */
    char       partial_box[40];
    unsigned   partial_pk;
    int        partial_succ;
    d2k_ver_result partial_ver;
    /* Сколько первых кандидатов пришло из готовых планов узнанной коробки, а
       не из синтеза по вердикту: различать их нужно на записи успеха (план
       узнанной коробки не заводит новую) и в логе. */
    size_t     n_known;
    int        researched;     /* whether this target has had a direct measurement */
    int        search_started; /* classifier/voice measurement started, even at zero probes */
    int        cached_measure_valid; /* preserve measured candidates after box-plan reuse */
    uint8_t    trigger_code;   /* signal that admitted this measurement; cooldown key */
    /* Задача 50, раунд 2: обрыв QUIC после рукопожатия воспроизведён своим
       запросом (прогон с arm.data_cut вернул OPAQUE). Неудача такой задачи
       снимает QUIC для имени (quic_deny_install). */
    uint8_t    stall_cut;
    /* Раунд 3: задача — перепроверка перед снятием запрета QUIC: прогон
       только прямыми запросами, без плеч (arm.data_cut = 2). */
    uint8_t    deny_recheck;
    uint8_t    trigger_planned;
    uint8_t    trigger_shape;
    char       trigger_executed_plan[40];
    d2k_binding_context trigger_binding;
    d2k_flowkey trigger_flow;
    /* Форма приветствия, КОТОРЫМ шёл замер, и было ли уже повторение из-за
       её расхождения со снимком. Нужны затем, что снимок настоящего клиента
       приходит уже ПОСЛЕ старта поиска: первый поиск идёт профилем холодного
       старта, и если клиент старой формы, замер сделан не тем приветствием. */
    uint8_t    asked_shape;
    int        reasked;
    int        trial_installed;
    int synthesis_resume_pending;
    char synthesis_context_resource[512];
    void *synthesis_context;
    void (*synthesis_release)(void *);
    d2k_synthesis_continuation_feedback synthesis_feedback;
    uint64_t synthesis_context_generation;
    d2k_verification_owner *synthesis_owner;

    d2k_verification_status synthesis_result;
    uint8_t synthesis_result_trial[D2K_TRIAL_ID_LEN];
    uint64_t   synthesis_generation;
    uint8_t    synthesis_ver_trial_id[D2K_TRIAL_ID_LEN];
    uint8_t    trial_shape;
    uint64_t   trial_shape_seq;
    /* Сколько раз ЭТОТ кандидат переиспытывался из-за того, что плана на
       потоке зонда не оказалось (см. ветку неудачи в T_VERIFY). */
    int        ver_bare_retries;
    /* Номер кандидата, которому принадлежит счётчик выше. Без него повтор
       сбрасывал бы сам себя: он идёт через переустановку плана, а она — тот
       же путь, что и установка следующего кандидата. */
    size_t     ver_retry_for;
    /* Повторы проверки кандидата из замера (SCHED_ARM_VERIFY_RETRIES); счёт —
       по тому же кандидату, что и ver_bare_retries. */
    int        ver_arm_retries;
    /* Пока датапат не принял пробный план, испытывать нечего: зонд уйдёт
       голым. trial_until_ms — предел ожидания, дальше идём как есть. */
    int64_t    trial_until_ms;
    int        trial_acked;
    /* trial ID пробной установки ИМЕНИ (v8, хвост SET_NAME_PROBE): ACK
       датапата возвращает его, и только он отпускает ожидание ЭТОЙ задачи
       (задача 19). Свежий на каждую установку кандидата. */
    uint8_t    trial_ack_id[D2K_TRIAL_ID_LEN];
    /* Кандидаты, отвергнутые исполнителем (ACK ok=0), и кандидаты, реально
       ушедшие сетевым зондом. Все отвергнуты и ни один не испытан — поиск
       закончился местным отказом, а не исчерпанием выведенных планов. */
    unsigned   exec_refused;
    unsigned   exec_probed;
    /* Отказ исполнителя, пришедший, когда зонд уже в сети (T_VERIFY):
       0x100|код; разбирается по возвращении потока раньше любого вердикта. */
    unsigned   exec_nak;
    /* СОКЕТ ЗОНДА, ЗАНЯТЫЙ ЗАРАНЕЕ. Пробный план ставится только для его
       местного порта, поэтому порт обязан быть известен ДО подключения:
       после connect ставить поздно. Минус один — порт занять не удалось, и
       тогда план ставится по-старому, всем (об этом говорится вслух). */
    int        probe_fd;
    uint16_t   probe_sport_be;

    /* Вопросы о свойствах коробки (§2.4, d2k_compose.h). Задаются ТОЛЬКО на
       вердикт «решает содержимое»: разрез такую коробку не берёт, берёт её
       отравление буфера пересборки, а чем именно — это и есть вопросы. */
    int        prop_q;          /* какой вопрос задаём, -1 — не спрашиваем */
    d2k_props  props;           /* накопленный вектор: не измерено / да / нет */
    int        props_asked;     /* хоть один вопрос задан — нужно снять план */
    d2k_flowkey prop_flow;      /* чей обмен ждём */
    int        prop_fd;         /* сокет обращения, держится до конца ожидания */
    /* СОКЕТ ДИАГНОСТИЧЕСКОГО ВОПРОСА, ЗАНЯТЫЙ ЗАРАНЕЕ, и его местный порт.
       Вопрос ставит план ровно так же, как испытание кандидата, и точно так
       же обязан действовать ТОЛЬКО на свой поток: до этого он вставал по
       имени и доставался всем, кто шёл к цели (0010, R1). Минус один — не
       занят; тогда вопрос не задаётся вовсе, а не задаётся «всем». */
    int        prop_bound_fd;
    uint16_t   prop_sport_be;
    /* План ВОПРОСА стоит в датапате (имя + форма вопроса + prop_sport_be).
       Отдельно от trial_installed (кандидат): после вопросов порт вопроса
       ещё помнится, и по одному общему флагу task_fail снимал давно снятый
       вопрос вместо стоящего кандидата (задача 20). */
    int        prop_installed;
    int        prop_applied;    /* план вопроса применён к пакетам НАШЕГО зонда */
    /* РАННИЕ ПРИМЕНЕНИЯ ВОПРОСА — тем же приёмом, что ver_early у кандидата
       (задача 24). Поток JOB_CONTACT возвращается сразу после посылки, а
       d2kc читает события связи раньше тика: APPLIED приходит, пока задача
       ещё в T_PROPS_CONTACT и ключ её потока не известен. Копятся полные
       ключи применений ЭТОГО плана вопроса; сверка — при переходе в
       T_PROPS_WAIT. Переполнение теряет улику, но не выдумывает её. */
    d2k_flowkey prop_early[8];
    size_t     prop_early_seen;
    /* РАННИЕ ОТВЕТЫ ВОПРОСА (EXCHANGE с ServerHello) — по той же причине:
       ответ сервера может прийти, пока задача ещё в T_PROPS_CONTACT. Прежде
       он терялся, и по сроку шага вопрос записывался ПРОМАХОМ — ложное
       «нет» о свойстве коробки из-за местного порядка событий (§7). Копятся
       только обмены по местному порту вопроса; полная сверка с prop_flow —
       при переходе в T_PROPS_WAIT, один раз. */
    d2k_ev     prop_early_x[4];
    size_t     prop_early_x_seen;
    int        prop_reply_seen;
    d2k_ev     prop_reply;
    int64_t    prop_until_ms;   /* потолок текущего шага */

    /* Рабочий поток оракула. */
    pthread_t  th;
    int        th_live;
    struct d2k_sched *worker_owner;
    /* request/waiting under owner->mu; parked and timestamp belong to loop. */
    int quic_yield_request, quic_yield_waiting, quic_parked;
    int64_t quic_parked_ms;
    int64_t quic_clock_ms, quic_wait_started_ms;
    uint64_t quic_tcp_turn;
    /* Просьба бросить замер, адресованная ЭТОЙ задаче. Взводит цикл (см.
       join_worker), читает измеритель. Обнуляется вместе со всей задачей в
       task_reset. */
    volatile sig_atomic_t stop;
    task_job   job;
    d2k_vres   res;
    d2k_voice_res voice_res;
    d2k_stun_probe_res stun_res;
    d2k_stun_trial *stun_trial;
    d2k_stun_socket *stun_socket; /* borrowed, worker never closes it */
    uint8_t stun_trial_id[D2K_TRIAL_ID_LEN], stun_plan_id[D2K_PLAN_ID_LEN];
    d2k_binding_context stun_binding;
    int stun_applied, stun_refused, stun_candidate_timeout;
    uint8_t stun_direct_request[20];
    int stun_direct_timeout,stun_own_attempted,stun_fragment_attempted;
    uint64_t stun_client_done_id, stun_client_reply_id;
    uint8_t voice_install_token[D2K_TRIAL_ID_LEN];
    int voice_install_acked, voice_install_refused;
    int64_t stun_until_ms;
    d2k_vol_result vol;
    unsigned   rx_phase; /* 0 identity candidate, 1 repeat, 2 gzip control */
    int        rx_bootstrap_only; /* measure an already confirmed target plan */
    int        family_reuse; /* 1 baseline pending, 2 isolated trial, 3 exhausted */
    int        group_block_proven;
    int        family_fast; /* 1 own-family verifier queue, 2 exhausted */
    int        skip_volume_once; /* resume classifier with existing baseline */
    /* СВОИ ПОДТВЕРЖДЁННЫЕ ПЛАНЫ ДО ПОЛНОГО ЗАМЕРА (задача 32, ТЗ §3.4).
       1 — задан только базовый вопрос донора (триггер целиком); 2 — он
       подтвердил блокировку на рукопожатии, и испытываются все свои планы
       той же формы, порциями очереди; 3 — шаг пройден (план
       не подтвердился, своих нет или база не показала блокировки), дальше
       полный прогон ровно как прежде. 0 — шага нет. */
    int        own_first;
    /* ПРОВЕРКА ПОЯВИВШЕГОСЯ ПЛАНА, А НЕ НОВЫЙ ПОИСК (24.10.2026). Такая
       задача заводится без запроса клиента: в каталоге появился
       подтверждённый план коробки, а цель уже отдыхала. Своих планов не
       хватило — задача кончается молча, полного замера не начинает: он по
       этой цели только что был. */
    int        plan_retry;
    uint32_t   own_seen[SCHED_OWN_SEEN_MAX]; /* fnv1a текстов, уже поставленных в очередь */
    size_t     n_own_seen;
    int        own_seen_full; /* своих подходящих больше, чем помнит own_seen */
    /* Испытан ли на проводе i-й свой план (бит i): только такие уходят в
       tried — отвергнутый исполнителем опыта не имел (задача 32, M1). */
    unsigned   own_probed;
    /* Ответ базового вопроса для полного прогона (задача 32): берётся вместо
       второго такого же опроса, только тем же входом (seed_input — хэш байт
       приветствия, адрес и порт) и один раз (seed_use взводит переход к
       полному прогону, снимает любой исход T_ASKING). */
    d2k_base_seed seed;
    uint64_t   seed_input;
    int        seed_use;
    /* Объёмный замер этой задачи уже выполнен (задача 30): повтор поиска
       снимком клиента не гоняет его заново, а берёт сохранённый исход —
       но ТОЛЬКО для того же входа замера. Замер зависит от версии TLS
       приветствия, его длины на проводе, пути ресурса и адреса: обрыв,
       снятый TLS 1.3-заготовкой, не улика для снимка TLS 1.2 (§4). */
    int        vol_done;
    d2k_vol_result vol_measured;
    int        vol_tls12;
    size_t     vol_wire;
    uint16_t   vol_port;
    char       vol_ip[INET6_ADDRSTRLEN];
    char       vol_path[512];
    char       doh_path[512];
    int        dns_dot;
    uint8_t    dns_plain;
    char       dns_question[256];
    uint16_t   dns_qtype;
    uint16_t   plain_first_timeout_bytes;
    uint16_t   plain_trial_bytes;
    d2k_plain_dns_request plain_request;
    uint8_t    dns_expected_http;
    int        doh_checked, doh_trial;
    unsigned   doh_failure_query;
    int        doh_synthesis_owned;
    char       measure_path[512]; /* selected before worker start, never guessed from ciphertext */
    /* ВТОРОЙ УЖЕ НАБЛЮДАВШИЙСЯ ПУБЛИЧНЫЙ ПУТЬ ЭТОГО ИМЕНИ (задача 26): на него
       уходит ОДИН повтор замера, когда по measure_path мерить было нечем
       (завершённый ответ меньше измеряемой полосы). Хост, отдающий 403/401 на
       любой путь, своих ресурсов не назовёт никогда — HTML-ссылки verify.c
       собирает только из завершённого 2xx text/html, — поэтому путь берётся из
       памяти планировщика, из уже виденного по этой цели. Пусто — другого
       НАБЛЮДАВШЕГОСЯ пути нет, и выдумывать его нечем. Выбирается до пуска
       потока, вместе с measure_path: память планировщика — не его дело. */
    char       measure_alt[512];
    int        ech_offer;
    int        ech_trial; /* failed baseline permits hypotheses, not a DPI verdict */
    int        ech_grease;     /* ECH offer оказался GREASE: обычный путь по имени */
    /* Настоящий ECH, своего свидетеля нет (поле 04.10.2026): меряем и
       проверяем кандидатов байтами клиента — его ECH-приветствием повтором
       на тот же адрес. Подтверждение — уровень рукопожатия (replay_proof). */
    int        ech_replay;
    /* QUIC с ECH (поле 15.10.2026): вход — пачка клиента с расширением ECH.
       Заготовка ECH не воспроизводит, и коробка её пропускает, а полёт
       клиента глушит. План подтверждается только повтором этой пачки под
       планом (уровень рукопожатия). Отдельно от ech_offer: тот означает
       форму TCP-ECH и выводит форму привязки ECH_TCP. */
    int        quic_ech;
    /* GREASE распознан рабочим потоком, а свои планы ещё не спрашивались
       (задача 49): поток вернулся без замера, решение own_first принимает
       главный поток (каталог не под s->mu) и запускает поиск заново. */
    int        ech_regrade;
    char       ech_origin[256]; /* known own-probe witness, not inferred hidden SNI */
    char       ech_witnesses[SCHED_ECH_WITNESSES][256];
    size_t     ech_witness_count;
    int        ech_reselect; /* свидетель ответил проверкой: следующий — рабочим потоком VERIFY */
    /* Отметки опыта: свидетель i ответил страницей проверки (не общий кеш —
       тот вытесняется, ревью Astra R3). */
    uint8_t    ech_bad[SCHED_ECH_WITNESSES];
    int        ech_exhausted; /* свидетелей для объёма нет: проверять нечем (R2) */
    int        ladder_unmeasurable; /* TX-обрыв: бюджет потока не измерить — ступени не ставить */
    int        yield_to_own_plan; /* прервать долгий замер: в каталоге появился подтверждённый план */
    d2k_ver_result rx_identity[2]; /* body evidence only; sockets closed normally */
    int64_t    rx_retry_after_ms;
    /* A late TLS RST is only permission for the paired receive-volume probe.
       Until that probe proves a repeatable identity cut with complete gzip,
       the ordinary classifier and candidate queue must remain untouched. */
    int        rx_volume_only;
    int        rx_volume_candidate_pending; /* special candidate after a measured RX-volume cut */
    /* Очередь долита из запасного перебора (refill_from_fallback), а не
       выведена из замера: панель и журнал называют её своим именем (задача 37). */
    int        fb_queue;
    size_t     fb_from;   /* с какого места очереди начинается запасной перебор:
                             ступени RX-лестницы перед ним — из замера */
    unsigned   rx_volume_next_variant;
    /* ПОДБОР БЕЛОГО ИМЕНИ СЕТИ (поле 10.10.2026). Когда у цели измерен
       RX-обрыв, а белое имя сети ещё не подобрано (catalog.net не искали),
       RX-лестница перебирает имена-кандидаты из встроенного списка как
       приманку: первое, что снимает обрыв (план подтверждён), и есть белое
       имя сети. net_probe_next — курсор по списку; net_probe_name[k] — имя
       приманки плана в слоте k очереди (пусто — не из подбора), чтобы при
       подтверждении записать его в каталог. */
    int        net_probing;
    size_t     net_probe_next;
    char       net_probe_name[SCHED_MAX_PLANS][32];
    char       net_probe_scratch[32];
    /* Путь находки для строки подтверждения (поле 10.10.2026): какой план
       очереди пришёл из приёма замера и какие — из RX-лестницы. По тексту,
       а не по месту: очередь перестраивается, а план остаётся тем же. */
    uint64_t   arm_hash;
    char       arm_path[32];
    /* ПРОДОЛЖЕНИЕ ОПРОСА ПОСЛЕ ОПРОВЕРГНУТОГО ПРИЁМА (24.10.2026).
     *
     * ЧТО БЫЛО. Опрос свойств кончается на первом прошедшем вопросе, и его
     * приём становится планом (detect/props.c). Если план не подтвердился на
     * применённом потоке, поиск уходил в запасной перебор донора — хотя
     * НЕЗАДАННЫХ вопросов оставалось большинство. Поле, 24.10.2026, три
     * круга выпуска 374a6df с чистого листа по одной и той же коробке:
     * clubtone.net в двух кругах взят вопросом 11 («ECH-приветствие под
     * меткой», план 680fbe00, 31 зонд, страница открылась), а в третьем
     * вопрос 4 («разбор протокола») ответил 2/2, опрос на нём кончился,
     * план 12f28799 получил RST на всех трёх испытаниях — и поиск, вместо
     * вопросов 5–11, ушёл в 8 планов перебора: 66 зондов и страница не
     * открылась. Один плавающий ответ решал исход всего круга.
     *
     * ЧТО ТЕПЕРЬ. Имя опровергнутого приёма едет в опрос списком «не
     * пробовать» (d2k_sched_tcp_extra.refuted), а вектор уже измеренного —
     * знанием о коробке: вопросы с известным промахом не задаются заново
     * (detect/props.c, known_of). Продолжение стоит только НЕЗАДАННЫХ
     * вопросов, а не полного опроса.
     *
     * ГРАНИЦА — ЧИСЛО ВОПРОСОВ, А НЕ БЮДЖЕТ ЗОНДОВ: каждый вопрос может быть
     * опровергнут не больше одного раза, поэтому продолжений не больше, чем
     * вопросов. Список по именам: место в очереди вопросов меняется. */
    char       arm_name[64];
    char       arm_refuted[SCHED_ARM_REFUTED_MAX][64];
    int        n_arm_refuted;
    /* Вектор, измеренный В ЭТОМ поиске: знание из каталога он дополняет, а не
       заменяет (противоречие гасится в D2K_PROP_UNKNOWN, core/boxprops.c). */
    d2k_box_props measured_props;
    uint64_t   rx_hashes[D2K_RX_VOLUME_PLAN_VARIANTS];
    size_t     n_rx_hashes;
    int gate_active, gate_installed, gate_reuse, gate_skip_reuse, gate_committed;
    int gate_combined;
    size_t gate_saved_plans,gate_saved_next,gate_saved_known;
    d2k_flowkey gate_outgoing_early[4];
    size_t gate_outgoing_seen;
    int gate_commit_sent,gate_lease_started,gate_lease_failed;
    unsigned gate_lease_pending,gate_lease_acked;
    int gate_catalog_saved, gate_catalog_had;
    char gate_catalog_box[40];
    d2k_cat_binding gate_catalog_previous;
    d2k_binding_context gate_binding;
    int        res_ready;   /* пишется потоком под мьютексом планировщика */
    /* Ход измерителя (задачи 48, 49): ask_probes — зонды, потраченные задачей
       ВНЕ счётчика кандидатов t->probes (бюджет SCHED_MAX_PROBES): прогоны
       измерителя и сброшенные счёты прежних испытаний. Пишет рабочий поток
       через d2k_sched_progress_note под s->mu; по возврату прогона —
       ask_base + r.probes (итог прогона, как «за N зондов замера» в журнале).
       Обнуляется только с задачей (task_reset): карточка не падает к нулю.
       ask_question — последний заданный вопрос идущего прогона. */
    d2k_run_cache run_cache; /* owned by task, accessed only by its joined worker */
    int        ask_probes;
    int        ask_base;
    char       ask_question[96];
    /* Ход замера по модельным часам (этап 23): когда последний раз менялся
       счёт зондов/вопрос; last_* — снимок для сравнения; long_told — сказано,
       что замер идёт дольше срока задачи и не прерывается. */
    int64_t    progress_ms;
    int        last_ask_probes;
    uint32_t   last_ask_qhash;
    int        long_told;
    /* Подобранное плечо QUIC и признак того, что подбор состоялся. Отдельно
       от вердикта: «плечо не найдено» и «вердикта нет» — разные утверждения,
       и складывать их в одно поле значило бы потерять различие. */
    d2k_quic_arm arm;
    int        arm_ready;

    /* Итог JOB_CONTACT. */
    uint8_t    c_ip[16];
    uint16_t   c_port;
    int        c_fd;
    int        c_ok;
} task;

/* АРГУМЕНТ РАБОЧЕГО ПОТОКА — ПОСТОЯННЫЙ СЛОТ ЗАДАЧИ, НЕ ВЫДЕЛЕНИЕ.
   Раньше главный поток выделял его malloc, а рабочий освобождал free: память
   по 8 КиБ на каждый замер переходила между потоками, и распределитель libc
   волен держать такие куски у себя (так d2o объяснял рост RSS статической
   musl-сборки). Слот выделен один раз вместе с планировщиком, по одному на
   задачу: выделений на замер нет, наибольший расход известен заранее
   (SCHED_MAX_TASKS * sizeof(worker_arg)), и расти ему некуда.
   Владение: главный поток пишет слот только в start_worker, и только когда
   прежний поток задачи присоединён; рабочий читает его в начале и больше не
   трогает. use_fd — сокет, занятый главным потоком до установки плана:
   владение переходит рабочему потоку вместе со слотом. */
typedef struct {
    d2k_sched *s; task *t; int use_fd;
    uint8_t trig[SCHED_TRIG_MAX], ctrl[2048];
    char response_probe_name[256];
    size_t trig_len, ctrl_len;
    uint8_t client_opts[40]; size_t client_opts_len; int client_opts_known;
    int trig_snapped; /* вход снят с провода: приманка строится клоном */
    int split_unfit; /* решено главным потоком (quic_split_unfit) */
    unsigned budget; /* бюджет потока испытания (JOB_VERIFY), 0 — без проверки */
} worker_arg;

/* ПРОТОКОЛ КЛИЕНТА — НЕ HTTP (задача 37, F3). Снимок TLS 1.3 целиком, и в
   его ALPN явно назван протокол не HTTP (MQTT, XMPP…), без http/1.1 и h2: тогда
   HTTP-зонд спрашивал бы сервер на чужом языке. 1 — зонд берёт ALPN клиента
   (list/len), 0 — прежний HTTP-зонд. Неполный снимок — «не измерено», 0. */
static int verdict_proves_block(d2k_verdict verdict);
static int client_alpn_nonhttp(const task *t, uint8_t *list, size_t cap, size_t *len) {
    *len = 0;
    if (t->transport != 6 || t->ech_offer || t->measure_path[0] ||
        d2k_hello_shape(t->trig, t->trig_len) != D2K_SHAPE_MODERN) return 0;
    /* ТОЛЬКО ПРИ ДОКАЗАННОМ БЛОКЕ САМОГО РУКОПОЖАТИЯ (раунд 2). Завершённое
       рукопожатие доказывает работу плана лишь там, где без плана оно не
       проходило: вердикт замера — блок на рукопожатии (или базовый вопрос
       донора это показал), и обрыва объёма нет. Блок, доказанный объёмом
       (TX- или RX-cut), рукопожатие пропускает и без плана, а его замер шёл
       по HTTP — сервер HTTP говорит; там доказательство — RX/HTTP-путь. */
    int handshake_blocked = verdict_proves_block(t->res.verdict) ||
                            (t->own_first == 2 && t->res.base_blocked);
    if (!handshake_blocked || t->vol.rx_cut || t->vol.verdict == D2K_VOL_CUT) return 0;
    /* Явный не-HTTP ALPN (mqtt…) — и КЛИЕНТ БЕЗ ALPN. Прежде здесь стояло
       «клиент без ALPN на HTTPS-порту — обычный HTTP-клиент»; поле
       07.10.2026 (KN-1811) опровергло это: приложение Facebook шлёт к
       edge-mqtt.facebook.com ClientHello без ALPN (запись с провода), а
       HTTP-зонд со своим http/1.1 получал тревогу 120 — 211 раз, ни одного
       подтверждения. Зонд повторяет клиента как есть: без ALPN (len 0). */
    int rc = d2k_hello_alpn(t->trig, t->trig_len, list, cap, len);
    if (rc == 0) { *len = 0; return 1; }
    if (rc != 1 || *len == 0) { *len = 0; return 0; }
    return !d2k_alpn_is_http(list, *len);
}

static int fresh_trial_id(uint8_t out[D2K_TRIAL_ID_LEN]) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) { return -1; }
    size_t n = 0;
    while (n < D2K_TRIAL_ID_LEN) {
        ssize_t r = read(fd, out + n, D2K_TRIAL_ID_LEN - n);
        if (r > 0) { n += (size_t)r; continue; }
        if (r < 0 && errno == EINTR) { continue; }
        close(fd); return -1;
    }
    close(fd);
    uint8_t any = 0;
    for (size_t i = 0; i < D2K_TRIAL_ID_LEN; i++) { any |= out[i]; }
    if (!any) { out[D2K_TRIAL_ID_LEN - 1] = 1; }
    return 0;
}

typedef struct {
    uint8_t  low_ip[16], high_ip[16];
    uint16_t low_port, high_port;
    uint8_t  transport;
    uint8_t  family;
    char     name[256];
    int      used;
    /* Приветствие TLS было, имени в нём нет (HELLO_NONAME датапата): поток
       известен как адресная TCP-цель, а не как «ничего не видели». */
    int      noname;
    int64_t observed_ms;
    uint8_t client_shape, named_client_side;
    int64_t named_ms;
} seen_name;
/* Independent current-connection state: legacy name retention cannot lend
 * an old name, direction or form to a new shadow observation. */
typedef struct {
    d2k_flowkey tuple;
    char name[254];
    uint8_t epoch[16], options[40], client_side, client_shape;
    uint64_t incarnation, snapshot, form_key;
    /* Bounded by the existing flow ring: passive observation must not take
       a durable slot from queued tasks. Bytes stay with their exact flow. */
    uint8_t hello[D2K_SHAPE_MAX], hello_options[40];
    size_t hello_len, hello_options_len, options_len;
    int used, awaiting_hello, options_known, signal, snapshot_queued;
} shadow_flow_state;


/* Negative observations never enter the strategy catalog. This bounded,
   process-local cache only debounces active measurements for an exact
   hostname+transport; normal CLEAR backoff may be bypassed by a different
   signal, while an explicit challenge or exhausted search remains quiet for
   the full backoff regardless of signal changes. */
typedef struct {
    char       name[256];
    uint8_t    transport;
    uint8_t    family;
    uint8_t    signal_code;
    uint8_t    negative_streak;
    int64_t    until_ms;
    int        challenge;
    int        denied;      /* сервис отказал по закону (451): остывание как у антибота */
    int        exhausted;
    int        ech_input;
    uint8_t    trigger_shape;
    int        ech_grease; /* resolved for the measured input, not a new ECH verdict */
    uint64_t   grease_input;
    int        late_rst_only; /* глушит только поздние RST/объёмные триггеры */
    /* АДРЕС ПОСЛЕДНЕГО ОПЫТА И ПОКОЛЕНИЕ ЗНАНИЯ (24.10.2026).
       Нужны проверке плана, появившегося в каталоге ПОСЛЕ того, как цель уже
       отдохнула: без адреса задачу не собрать, а без поколения одна и та же
       цель проверялась бы на каждом тике. Приветствие здесь не держим — его
       соберёт fill_hellos профильной заготовкой. */
    char       ip[46];
    uint16_t   port;
    uint32_t   plan_gen;     /* поколение каталога, на котором проверка уже была */
    /* ПЛАНЫ, КОТОРЫЕ НА ЭТОЙ ЦЕЛИ УЖЕ НЕ СРАБОТАЛИ (хэши текста). Проверка
       появившегося плана имеет смысл, только если каталог предлагает что-то,
       чего эта цель ещё не пробовала; иначе это повтор известного промаха.
       Поле 24.10.2026, круг fix-w1: 64 проверки на 34 цели, подтвердилось 10 —
       остальные перепробовали то же самое по второму и третьему разу. */
    uint32_t   failed_plans[SCHED_FAILED_PLANS];
    uint8_t    n_failed_plans;
    int        used;
} target_cooldown;

/* ДОКАЗАННЫЙ ЗДОРОВЫЙ КОНТЕКСТ (этап 30). Подозрение с потока под планом
   повело к замеру, и план, под которым шёл поток, переподтверждён своим
   зондом с пройденным бюджетом («подозрение было ложным»). Поле (старые
   сборки): flibusta.is, rutracker.org — через 36 с … 2 мин то же подозрение,
   тот же замер, тот же исход, по кругу. Тот же опыт на том же входе нового не
   скажет; запись держит ТОЧНЫЙ контекст доказательства, и только подозрение,
   совпавшее с ним целиком, не повторяет замер. Другой код, адрес, порт или
   форма, смена привязанного плана, истечение срока — замер как прежде.
   Каталог не правится; запись живёт в памяти процесса. */
typedef struct {
    char       name[256];
    uint8_t    transport;
    uint8_t    family;
    uint8_t    code;   /* код подозрения, которое опровергнуто */
    uint8_t    shape;  /* форма клиента потока подозрения */
    char       ip[INET6_ADDRSTRLEN];
    uint16_t   port;
    char       plan_id[40];
    d2k_binding_context binding;
    int64_t    proven_ms;
    unsigned   skipped;
    int        used;
} healthy_proof;

/* ЦЕЛЬ БЕЗ ВЫВОДА (этап 31). Трафик к цели замечен, но решения нет и данных
   для него не хватило: протокол не распознан и своих решений адреса нет,
   направление потока не наблюдалось, опыт не состоялся или исход неизвестен,
   замер не дал ответа. Прежде это жило только тихой строкой журнала, и по
   панели «цель молчит, кандидата нет» не отличалось от «цель не
   подозревалась». Таблица ограничена; повтор той же цели (адрес, порт,
   транспорт, семейство) обновляет запись и считает наблюдения, а не
   заводит новую — на каждый поток не размножается. Подтверждение цели
   снимает её запись. Это НЕ блок и НЕ решение: live.json отдаёт её отдельно. */
typedef struct {
    char       target[256];
    char       kind[8];     /* addr | name | flow (направление неизвестно) */
    uint8_t    transport;
    uint8_t    family;
    uint16_t   port;
    char       reason[24];
    char       why[768];   /* русский текст с фактами соседей (этап 45) */
    int64_t    first_s, last_s;
    unsigned   count;
    /* этап 38: соседи по адресу; -1 — не известно. judged — со счётчиками
       (этап 45): «не доказан» относится только к ним, не ко всем соседям. */
    int        peers, peers_judged, peers_answered;
    int64_t    peers_ms;
    int        used;
} unknown_target;

/* РЕЗУЛЬТАТ КЛИЕНТОВ ПОД ПЛАНОМ (этап 34). Подтверждение — доказательство
   зонда; реальные клиенты под планом датапат видит на уровне ОБМЕНА: поток,
   на котором сервер пошёл прикладными данными (TLS 23) или ответил по UDP, и
   поток, о котором пришло подозрение. Прежде наблюдатель отмечал первый такой
   обмен строкой и снимался — счёта не было нигде. По цели и плану на проводе,
   по одному на поток (датапат шлёт не больше одного события каждого рода на
   поток, потоки зонда не шлёт вовсе). Это НЕ доказательство работы
   приложения; каталог не правится, память процесса. */
typedef struct {
    char       name[256];   /* имя цели или адрес сервера (поток без имени) */
    uint16_t   port;        /* порт сервера для адресной цели; 0 — по имени */
    uint8_t    transport;
    uint8_t    family;
    char       plan_id[40]; /* ИСПОЛНЕННЫЙ план — из события, не из каталога */
    char       level[48];   /* уровень доказательства ответов */
    unsigned   answered;
    unsigned   suspected;
    int64_t    first_s, last_s;
    int        used;
} plan_obs;

/* МЕДЛЕННО, НО РАБОТАЕТ (этап 37). Окно очереди видит ≤8 пакетов потока,
   дальше поток идёт мимо (connbytes, ускоритель); счётчики записи conntrack
   ведут ВЕСЬ поток (учёт включает xt_connbytes). Поток из приветствия
   ставится под наблюдение; раз в шаг — байты и пакеты обеих сторон.
   Байты — длины IP-пакетов С ЗАГОЛОВКАМИ (этап 46): ACK, опции TCP и
   короткий ответ ими неразличимы, полезная нагрузка вычитанием не считается.
     идёт      — ответ доказан: UDP — датаграмма сервера; TCP IPv4 — байты
                 сверх наибольших заголовков (60 IP + 60 TCP) на пакет;
                 TCP IPv6 — байтами не доказывается (заголовки расширения);
     входящие  — от сервера больше голых заголовков, данные не доказаны
                 (ACK с опциями или короткий ответ) — не застой и не успех;
     застой    — клиент шлёт SCHED_FLOWWATCH_STALL_STEPS шагов, а от сервера
                 ничего сверх наименьших заголовков (ничего или голые ACK);
     простой   — клиент не шлёт, от сервера ничего сверх голых заголовков:
                 пауза приложения или поток ведёт ускоритель — НЕ застой;
     нет данных — счётчиков нет или запрос не удался.
   Скорость — входящие IP-байты шага (с заголовками), не данные приложения.
   Счётчики назад (запись заменена) и пропуск данных — новая точка отсчёта:
   ни скорости, ни шага застоя, ни объёма через разрыв.
   Причина не называется (сервер, канал, коробка — неразличимы этими
   счётчиками); поток не трогается; замер не запускается. Ретрансмиссии
   conntrack не видит. */
enum { FW_UNKNOWN = 0, FW_MOVING, FW_STALLED, FW_IDLE, FW_NODATA, FW_ACTIVE };
typedef struct {
    char       target[256];
    char       known_service[256]; /* address history when this connection appeared */
    uint16_t   port;        /* порт сервера для адресной цели; 0 — по имени */
    uint8_t    transport, family;
    d2k_ct_tuple tuple;
    int64_t    added_ms, sampled_ms, ct_seen_ms;
    uint64_t   orig_pkts, reply_pkts, orig_bytes, reply_bytes;
    uint64_t   in_bytes;    /* входящие IP-байты по годным шагам (без разрывов) */
    unsigned   samples, flat_steps;
    uint8_t    state;
    uint64_t   rate_Bps;    /* входящие IP-байты/с последнего шага */
    /* Поставлен только фактом появления (этап 42): без имени и без плана.
       Такая запись уступает место любой именной/плановой и сама её не
       вытесняет. */
    int        passive;
    /* ПОЗДНЯЯ ТИШИНА (этап 49). Ключ потока — как в событии датапата, чтобы
       подозрение было о ТОМ ЖЕ потоке; tls_noname — приветствие TLS без
       имени (адресная цель); исполнение — из APPLIED (иначе не сказано).
       had_reply — сервер слал больше голых заголовков; sil_* — подряд шагов
       без ЕДИНОГО пакета сервера и пакеты клиента на начало тишины. */
    uint8_t    low_ip[16], high_ip[16];
    uint16_t   low_port, high_port;
    uint8_t    client_side, tls_noname, planned;
    uint8_t    flow_epoch[16];
    uint64_t   flow_incarnation;
    uint64_t   execution_id;
    uint8_t    plan_id[D2K_PLAN_ID_LEN], trial_id[D2K_TRIAL_ID_LEN];
    d2k_binding_context binding;
    int        had_reply, escalated;   /* escalated — эпизод тишины уже разобран */
    unsigned   sil_steps;
    uint64_t   sil_orig;
    int64_t    sil_ms;
    int64_t    obs_asked_ms;  /* ждём итог позднего наблюдения датапата */
    uint8_t    obs_token[D2K_TRIAL_ID_LEN];   /* токен этого наблюдения */
    /* Отрицательный итог (данных нет, ничего, недоступно, отказ, срок) на
       ЭТОМ соединении: следующее наблюдение — не раньше rearm_ms (откат
       удваивается) и только при новой активности клиента после итога. */
    unsigned   obs_fails;
    int64_t    rearm_ms;
    uint64_t   rearm_orig;
    int        used;
} flow_watch;

/* МЁРТВЫЙ АДРЕС (задача 54). Замер доказал, что адрес после рукопожатия не
   принимает данных (вердикт address). Ключ — имя+транспорт+семейство+АДРЕС,
   отдельно от отсрочек имени: у имени бывают другие адреса, их исходы эту
   запись не трогают, и она не глушит их (fix round 1, I1). Запись живёт и
   после срока: её ступень растёт 10/30/60 мин, пока перепроверка (один
   нейтральный байт до любого триггера, I2) снова видит тишину. Снимается,
   только когда этот адрес данные принял. */
typedef struct {
    char       name[256];
    uint8_t    transport;
    uint8_t    family;
    char       addr[INET6_ADDRSTRLEN];
    uint8_t    streak;
    int64_t    until_ms;
    int        used;
} dead_address;

/* Первый поздний RST цели, ждущий второго по независимому flow key. */
typedef struct {
    char name[256];
    uint8_t transport, family, used;
    d2k_flowkey flow;
    int64_t seen_ms;
} late_rst_pending;

/* ЧИСТОЕ РУКОПОЖАТИЕ БЕЗ ПЛАНА (поле 15.10.2026, медиа VK). Имя, которое
   недавно завершило обмен с ответом сервера на потоке БЕЗ нашего плана,
   работает само; RST/молчание по нему на рукопожатии — не блок, а штатный
   сброс сервером лишних соединений. Гасит замер ТОЛЬКО на рукопожатии
   (RST/SILENT/REPEAT); обрыв объёма и позднее закрытие мерятся как прежде. */
typedef struct {
    char name[256];
    uint8_t transport, family, used;
    int64_t seen_ms;
} clean_hs_seen;
#define SCHED_CLEAN_HS_SLOTS 16
#define SCHED_CLEAN_HS_MS (60 * 1000)

/* QUIC ДЛЯ ИМЕНИ НЕ ПРОПУСКАЕТСЯ (задача 50, раунд 2, требование 5c).
   Обрыв QUIC после рукопожатия воспроизведён своим запросом, обхода по QUIC
   поиск не нашёл: на имя ставится план quicdeny, и браузер уходит на TCP.
   Это НЕ обход QUIC (§4) и НЕ знание: в каталог не пишется (§2.3 —
   отрицательное не хранится), живёт сроком отдыха цели и снимается, чтобы
   следующий обрыв был измерен заново. streak — сколько раз подряд имя
   снималось: срок растёт так же, как у повторного CLEAR (10/30/60 мин). */
#define SCHED_QUIC_DENY_SLOTS 16
typedef struct {
    char name[256];
    uint8_t family, used, active;
    /* Раунд 3: срок вышел, идёт своя перепроверка (только прямые запросы).
       Запрет стоит, пока она не скажет. */
    uint8_t rechecking;
    unsigned streak;
    int64_t until_ms;
    /* Для перепроверки: адрес, порт, Initial клиента (вход прогона). */
    char ip[64];
    uint16_t port;
    uint8_t trig[SCHED_TRIG_MAX];
    size_t trig_len;
} quic_deny_slot;

typedef struct {
    char name[256], plan_id[40];
    uint8_t kind, transport, shape, family;
    uint8_t confirmed;
    uint64_t confirmed_event;
} installed_area;

typedef struct {
    char host[256], path[512], ip[INET6_ADDRSTRLEN];
    uint16_t port;
    int64_t next_ms;
    unsigned health_ok;
    unsigned sources;
    unsigned recovery; /* Failed configured DNS context; not a DPI fact. */
    unsigned journal_pending;
    int dot;
    uint8_t plain;
    uint8_t plain_outcome;
    uint8_t http_version; /* last authenticated DoH health negotiation */
} doh_target;
typedef struct {
    char ip[INET6_ADDRSTRLEN],plan_id[40];
    uint16_t port,wire_length;
    uint8_t transport,family,active,routed;
    uint8_t request[D2K_TRIAL_ID_LEN];
    int64_t retry_at;
} plain_endpoint;
typedef struct {
    char name[256], ip[INET6_ADDRSTRLEN];
    uint16_t port;
    uint8_t family, transport, shape;
} force_target;
typedef struct {
    uint8_t address[16], family, client[16], client_family;
    uint32_t path;
    uint16_t observed_port;
    uint8_t observed_shape;
    char name[256];
    int64_t expires_ms;
} dns_address_name;
typedef struct {
    d2k_pf_scope scope;
    uint8_t id[D2K_TRIAL_ID_LEN];
    int64_t expires_ms;
    uint8_t pending,active;
    task *owner;
} sched_preflight_lease;

struct d2k_sched {
    dns_address_name dns_names[SCHED_SEEN];
    sched_preflight_lease preflight_leases[SCHED_SEEN];
    d2k_newchain newchain;
    int synthesis_only;
    d2k_shadow_writer shadow;
    d2k_shadow_recent shadow_recent;
    char force_suffixes[128][256];
    size_t n_force;
    force_target forced[SCHED_SEEN];
    size_t n_forced, force_next;
    d2k_diag_memory memory; /* argument counters protected by mu */
    doh_target doh[8];
    d2k_plain_prepare_fn plain_prepare;
    d2k_plain_run_fn plain_run;
    uint64_t plain_dns_revision;
    uint64_t plain_dns_saved;
    uint64_t encrypted_dns_revision;
    plain_endpoint plain_endpoints[8];
    size_t n_doh;
    char recent_dns_question[256];
    uint16_t recent_dns_qtype;
    int64_t recent_dns_at;
    doh_target recent_dns_service;

    d2k_diag_observer diagnostic;
    void *diagnostic_ctx;
    d2k_synthesis_observer synthesis_observer;
    void *synthesis_observer_ctx;
    d2k_catalog *cat;
    int          link_fd;
    uint32_t     mark;
    uint32_t     measure_mark;

    /* Часы последнего тика. Подтверждения приходят СОБЫТИЕМ, а не по часам, и
       спрашивать время у ОС в каждом обработчике незачем: тик идёт трижды в
       секунду, а сроки здесь считаются секундами. */
    int64_t      now_ms;
    uint64_t     event_sequence;
    int64_t      stun_cleanup_ms;
    int          stun_cleanup_seen;

    task         tasks[SCHED_MAX_TASKS];
    worker_arg   wargs[SCHED_MAX_TASKS]; /* слот аргумента рабочего потока задачи */
    shadow_flow_state shadow_flows[SCHED_SEEN];
    size_t shadow_next;
    seen_name    seen[SCHED_SEEN];
    size_t       seen_next;   /* кольцо: старое вытесняется, а не отказывает */
    /* Ответы HTTPS RR по именам-кандидатам в ECH-свидетели; под s->mu. */
    struct { char name[256]; char public_name[256]; int has; int used;
             int64_t until_ms; } ech_rr[SCHED_ECH_RR];
    size_t       ech_rr_next;
    /* Свидетели, ответившие через принятый ECH страницей проверки своего
       сервера: проход ECH они доказывают, объём ответа на них не измерить
       (поле 17.10.2026, romfea.gr); под s->mu. */
    struct { char name[256]; int64_t until_ms; } ech_chal[8];
    size_t       ech_chal_next;
    /* ПОКОЛЕНИЕ ПОДТВЕРЖДЁННЫХ ПЛАНОВ. Растёт на каждом подтверждении; по
       нему остывшие цели той же коробки получают по одной проверке на
       новое знание, а не по проверке на тик (24.10.2026). */
    uint32_t        plan_gen;
    int             plan_news;   /* заказ: проверить остывшие цели новым планом */
    target_cooldown cooldowns[SCHED_COOLDOWN_SLOTS];
    healthy_proof   proofs[SCHED_PROOF_SLOTS];
    unknown_target  unknowns[SCHED_UNKNOWN_SLOTS];
    plan_obs        planobs[SCHED_PLANOBS_SLOTS];
    flow_watch      flowwatch[SCHED_FLOWWATCH_SLOTS];
    d2k_sched_flow_ct_fn ct_query;
    d2k_sched_peers_fn ct_peers;
    int64_t         flowwatch_ms;
    /* Факты появления без свободного места: вытеснили давний пассивный поток
       или не встали (всё занято именными/плановыми) — предел наблюдения
       виден числом (этап 42). */
    uint64_t        flowwatch_full;
    dead_address    dead_addrs[SCHED_COOLDOWN_SLOTS];
    late_rst_pending late_rst[SCHED_LATE_RST_SLOTS];
    size_t       late_rst_next;
    clean_hs_seen clean_hs[SCHED_CLEAN_HS_SLOTS];
    size_t       clean_hs_next;
    d2k_application_control direct_control[2][2];
    int64_t      groups_expired_ms;   /* последняя чистка старых отказов семейств */
    /* Повторяемые объяснения, уже сказанные: ключ и срок молчания. */
    struct { char key[300]; int64_t until_ms; } quiet[SCHED_QUIET_SLOTS];
    size_t       quiet_next;
    quic_deny_slot quic_deny[SCHED_QUIC_DENY_SLOTS];
    /* proven — обрыв на этом пути ИЗМЕРЕН (d2k_vol_result.measured_path), а не
       только упомянут в чужом HTML: такой путь спрашивается первым и не
       вытесняется упоминанием (задача 26). */
    struct { d2k_resource ref; int64_t expires_ms; int proven; } resources[8];
    size_t resource_next;
    /* Ячейка — размером со вход задачи: датапат снимает TCP-приветствие до
       4096 байт, и с провода v20 длинное ECH-приветствие доходит целиком. */
    struct { char name[256]; uint8_t bytes[SCHED_TRIG_MAX]; size_t len;
             uint8_t family; int64_t observed_ms;
             uint8_t opts[40]; size_t opts_len; int opts_known; } ech_inputs[8];
    size_t ech_input_next;
    /* ПАЧКИ QUIC ПО ИМЕНИ (поле 15.10.2026). Общая ячейка quic_shape держит
       только последнюю пачку любого имени, и к поиску цели в ней почти
       всегда лежала чужая («пачка чужого имени — мерю собственным
       Initial»). Для имени, чей клиент шлёт ECH, это значило мерить
       заготовкой без ECH — она коробку проходит, и поиск кончался ложным
       «напрямую проходит». */
    struct { char name[256]; uint8_t bytes[SCHED_TRIG_MAX]; size_t len;
             uint8_t family; uint8_t ech; int64_t observed_ms; } quic_named[16];
    size_t quic_named_next;
    /* ИМЕНА, ЧЕЙ КЛИЕНТ ШЛЁТ QUIC ClientHello ШИРЕ ДАТАГРАММЫ (финальное
       ревью core, I1): снимок пришёл обрывком (on_shape). Разрез CRYPTO
       такому клиенту не исполнится — датапат режет только датаграмму с
       именем и отказывает «имени нет в этой датаграмме», — поэтому план
       разреза для имени не строится и не подтверждается. Кольцо: старое
       вытесняется. */
    struct { char name[256]; uint8_t family; } quic_multi[16];
    size_t quic_multi_next;
    int64_t      last_measure_start_ms;
    int          measure_start_seen;

    /* Ресурсы замеров (задачи 29, 38): последний снимок /proc/stat (или
       крючка), сглаженная доля свободного процессора в миллионных, память
       и conntrack последнего снимка; предел одновременных замеров (AIMD) и
       его журнал. */
    int          cpu_tried, cpu_have_prev, cpu_valid, cpu_logged_valid;
    int64_t      cpu_try_ms;
    uint64_t     cpu_prev_busy, cpu_prev_total;
    int64_t      cpu_free_u;
    unsigned     cpu_cores;
    int          mem_valid, ct_valid;
    uint64_t     mem_avail_kb, mem_total_kb;
    uint64_t     ct_count, ct_max;
    uint64_t     res_seq;           /* номер снимка ресурсов */
    uint64_t     limit_seq;         /* снимок, по которому предел менялся */
    int          grow_pending;      /* запуск заполнил предел — рост к снимку */
    unsigned     limiter;           /* во что упёрлись (MEAS_LIM_*) */
    int64_t      limit_since_ms;    /* когда (предел, причина) приняли значение */
    size_t       limit_logged;      /* последний названный в журнале предел */
    unsigned     limiter_logged;    /* и причина */
    size_t       meas_limit;
    uint64_t     report_sequence;

    /* Проход по каталогу, разложенный на порции (см. d2k_sched_sync_step):
       где остановились и просили ли начать заново. */
    size_t       sync_box, sync_bind;
    int          sync_active, sync_pending, sync_sent, sync_skipped;
    int          sync_weak;   /* привязки, чьё доказательство слабее обмена */
    int          sync_unshaped; /* адресные привязки без однозначной формы протокола */
    int          sync_recheck;  /* привязки «требует повторной проверки» (задача 21) */
    int          sync_refused;  /* отказы датапата (ACK ok=0) на планах каталога с прошлой сводки */
    int          sync_unfit;    /* планы, не влезающие в посылку датапата: не поставлены, привязки на повторную проверку */
    /* ЦЕЛИ, УЖЕ ПЕРЕМЕРЕННЫЕ ПО ОТКАЗУ «ПОТОК НЕ НЕСЁТ ТРЕБУЕМОГО» (ревью
       ветки, находка 3). Подтверждение снимает пометку повторной проверки
       (bind_confirmed), и следующее соединение того же клиента помечало цель
       заново — полный поиск на КАЖДОЕ соединение, ровно патология журналов
       #5/#7. Тот же план на том же клиенте отказывает детерминированно, и
       перемерять его второй раз нечем: помним пару «цель + план», для которой
       перемер уже заводили. ДРУГОЙ план той же цели (каталог сменился) заводит
       перемер снова — он ещё не проверялся. */
    struct { char name[256]; uint8_t family, transport;
             uint8_t plan_id[D2K_PLAN_ID_LEN]; } unfit_done[8];
    size_t       unfit_done_next;
    unsigned     sync_refused_code; /* причина последнего такого отказа (D2K_ACK_*) */
    installed_area *areas;
    size_t n_areas, areas_capacity;
    installed_area area_pending;
    uint16_t area_command;
    uint64_t area_sequence;
    uint8_t area_id[D2K_TRIAL_ID_LEN];
    int64_t area_deadline_ms;
    int area_sync_failed;

    /* Сколько событий датапат потерял к последнему отчёту. Нужно затем, что
       МОЛЧАНИЕ — не доказательство: пропавший обмен неотличим от «плана не
       сработало», и если связь в этот момент теряла события, считать молчание
       уликой нельзя (см. on_applied). */
    uint32_t     dropped_seen;

    /* Предел длины посылки, объявленный датапатом (D2K_EV_PROTO). Ноль — не
       объявлен: сборка планов тогда ведёт себя как раньше. */
    uint32_t     send_cap;

    /* ПОСЛЕДНИЙ СНЯТЫЙ INITIAL КЛИЕНТА — один на весь планировщик.
     *
     * Зачем он общий, а не при задаче. У QUIC нет профиля холодного старта:
     * приветствие едет зашифрованным, и заготовки взять неоткуда. Пока
     * снимок требовался ДЛЯ КАЖДОЙ ЦЕЛИ ОТДЕЛЬНО, первое обращение к новому
     * имени было потеряно всегда — датапат заказывал снимок и ждал ВТОРОГО
     * обращения к тому же имени.
     *
     * Это и ломало рилсы Instagram у владельца роутера 13.09.2026: ролики
     * едут с хостов `scontent-*.cdninstagram.com`, которые меняются от ролика
     * к ролику. Второго обращения к тому же имени не бывает, и задача
     * умирала с «формы приветствия так и не пришло» — измерено на живой
     * линии, три такие смерти за тридцать секунд листания.
     *
     * Почему чужой снимок здесь законен. Байты приветствия задаёт КЛИЕНТ, а
     * не цель: у одного и того же приложения приветствие к соседнему хосту
     * той же сети отличается именем, а не формой (замерено там же: все
     * снимки QUIC — 1252 байта). d2k_quic_hello_rename пересобирает снимок с
     * другим именем — ровно этим уже собирается контрольный зонд, и это
     * настоящее клиентское приветствие, а не выдумка.
     *
     * Чего он НЕ даёт: права назвать форму измеренной ДЛЯ ЭТОЙ ЦЕЛИ. Признак
     * trig_snapped остаётся нулевым, снимок этой цели заказывается как
     * прежде, и со следующего обращения мерится уже своим. */
    uint8_t      quic_shape[2][SCHED_TRIG_MAX];
    size_t       quic_shape_len[2];
    char         quic_shape_name[2][256];
    uint64_t     quic_shape_seq[2];
    /* ПОСЛЕДНЯЯ СНЯТАЯ ФОРМА TCP — С ИМЕНЕМ, ЧЬЯ ОНА.
     *
     * Снимок приходит РАНЬШЕ подозрения: датапат сперва видит приветствие, а
     * уж потом решает, что цель подозрительна. До сих пор форма клалась
     * только в УЖЕ существующие задачи, и при обычном порядке событий она
     * пропадала: задача заводилась без снимка и мерила профилем холодного
     * старта — современным, даже когда клиент говорит по TLS 1.2. Мерился
     * при этом не тот клиент, что ходит на самом деле, а план-вопрос уезжал
     * чужой формой и к отправленным байтам не применялся вовсе (0010, R2).
     *
     * Одна ячейка, а не таблица: подозрение по цели идёт следом за её же
     * приветствием, и между ними чужому снимку взяться почти неоткуда. Имя
     * сверяется, поэтому чужая форма не подставится молча — в худшем случае
     * снимка не окажется, и это прежнее поведение. */
    uint8_t      tcp_shape[2][2048];
    size_t       tcp_shape_len[2];
    char         tcp_shape_name[2][256];
    d2k_flowkey   tcp_shape_flow[2];
    /* НАБОР ОПЦИЙ TCP КЛИЕНТА рядом со снимком (замысел 2026-10-23, п. 5.1).
       Датапат шлёт его событием CLIENT_TCP ровно перед SHAPE того же потока:
       wait — набор пришёл и ждёт свой снимок; known — снимок связан с набором
       (ноль: снимок без набора — старый датапат, зонд пойдёт прежним набором,
       привязка PROFILE). Нулевая длина при known — клиент без опций. */
    uint8_t      tcp_shape_opts[2][40];
    size_t       tcp_shape_opts_len[2];
    int          tcp_shape_opts_known[2];
    uint8_t      tcp_opts_wait_bytes[2][40];
    size_t       tcp_opts_wait_len[2];
    int          tcp_opts_wait[2];
    d2k_flowkey  tcp_opts_wait_flow[2];

    /* Для вида панели: сколько подтверждено и сколько зондов потрачено за
       жизнь процесса, и отметка стенных часов, от которой считается «с
       какого времени идёт поиск» (внутри всё на монотонных). */
    int          confirms, probes_used;
    /* Разовая строка: пакеты потока на этой прошивке не считаются, проверка
       бюджета выключена (ядро без TCP_INFO data_segs, задача 55). */
    int          budget_uncountable_said;
    /* Бюджеты коробок, которые держит датапат для детектора «TCP встал на
       бюджете» (задача 56). Новый датапат держит полевой; d2kc живёт одно
       подключение (разрыв — выход), поэтому начальное значение — его. */
    uint16_t     stall_sent[D2K_STALL_BUDGETS_MAX];
    size_t       n_stall_sent;
    /* Сколько раз ПОСТОЯННЫЙ отказ пришёл на поток настоящего клиента при
       том, что план на цели стоит. Это не свойство коробки и не промах
       кандидата: это наша непереносимость — «подтверждено» в каталоге при
       отсутствии обхода у человека. Число растёт всегда; словами такое
       говорится по одному разу на имя (unfit_names), иначе строка
       повторялась бы на каждом соединении браузера. */
    uint32_t     unfit_client;
    char         unfit_names[8][256];
    size_t       unfit_next;
    int64_t      wall_base_s;
    /* Монотонные часы в тот же момент. Без них преобразование считает уптайм
       ДВАЖДЫ: CLOCK_MONOTONIC на Linux отсчитывается от ЗАГРУЗКИ, а не от
       старта процесса, и wall_base_s + now_ms давало дату на столько часов
       вперёд, сколько роутер к тому моменту работал. Поймано живой приёмкой
       12.09.2026: подтверждение записалось временем 05:16Z при настоящих
       00:43Z — ровно на 4,5 часа уптайма вперёд. */
    int64_t      mono_base_ms;
    int          clock_seen;   /* видели ли хоть один тик: до него привязки нет */
    /* Монотонные часы планировщика в СТЕННЫЕ секунды. Всё внутри считается
       монотонными миллисекундами (сроки, потолки, отдых) — и это верно: стенные
       часы на роутере прыгают при синхронизации времени, а сроки от этого
       прыгать не должны. Но каталог читает ЧЕЛОВЕК и панель, и там нужна дата.
       Без преобразования в файл уезжало «1970-01-01T04:14:39Z» — поймано на
       живой приёмке 12.09.2026, у всех новых подтверждений. */

    d2k_sched_say_fn say_fn;
    void            *say_ctx;

    int          wake[2];     /* самопайп: рабочий поток будит цикл */
    pthread_mutex_t mu;       /* охраняет res/res_ready/th_live задач */
    pthread_cond_t question_cv;
    uint64_t tcp_admission_sequence;
};

/* АДРЕСНАЯ ЦЕЛЬ — два разных механизма опыта (этап 11, 28.10.2026).
   by_addr говорит «цель — адрес, не имя» (каталог kind=addr, нет домена,
   нет объёма по имени). Но ТОЧНЫЙ опыт у транспортов разный: UDP (QUIC по
   адресу) ставит SET_ADDR_PROBE по своей пятёрке с UDP-сокета; TCP без SNI
   ставит пробную запись своего порта (SET_NAME_PROBE с ключом-адресом —
   датапат ищет пробную запись потока без имени только по порту, plans.c)
   и снимает её точно DEL_NAME_PROBE. Имя на провод не уходит: приветствие
   зонда без SNI, зонд подтверждения без SNI. */
void d2k_sched_set_plain_trial(d2k_sched *s,d2k_plain_prepare_fn prepare,d2k_plain_run_fn run) {
    if (s) {s->plain_prepare=prepare;s->plain_run=run;}
}

uint64_t d2k_sched_plain_dns_revision(const d2k_sched *s) {
    return s ? s->plain_dns_revision : 0;
}
int d2k_sched_dns_save_pending(const d2k_sched *s, uint64_t saved_catalog_revision) {
    return s && (s->plain_dns_revision > saved_catalog_revision ||
                 s->encrypted_dns_revision > saved_catalog_revision);
}
void d2k_sched_plain_dns_saved(d2k_sched *s,uint64_t revision) {
    if (s)s->plain_dns_saved=revision;
}

static int addr_udp(const task *t) { return t->by_addr && t->transport == 17; }

static int addr_probe_remove(d2k_sched *s, task *t, char *err, size_t errcap) {
    if (!t->addr_probe_identity_valid) { return 0; }
    uint8_t dst[16] = {0};
    uint16_t dst_port_be = t->addr_probe_dst_port_be;
    if (dst_port_be) {
        memcpy(dst, t->addr_probe_dst_ip, sizeof dst);
    } else {
        if (inet_pton(t->family == 6 ? AF_INET6 : AF_INET, t->ip, dst) != 1) { return -1; }
        dst_port_be = htons(t->port ? t->port : 443);
    }
    int rc = d2k_link_del_addr_probe_family(s->link_fd, t->addr_probe_src_ip,
                                     t->addr_probe_src_port_be, dst,
                                     dst_port_be, t->transport, t->family,
                                     t->addr_probe_trial_id, err, errcap);
    /* Принадлежность забывается только после того, как команда ушла. Не
       ушла — опыт по-прежнему наш и стоит до lease; следующая возможность
       (освобождение задачи, d2k_sched_free) обязана снять его снова. */
    if (rc == 0) { t->addr_probe_identity_valid = 0; }
    return rc;
}

static uint8_t question_shape(const task *t);
static void say(d2k_sched *s, const char *fmt, ...);

/* СНЯТИЕ ПРОБНЫХ ЗАПИСЕЙ ЗАДАЧИ — ТОЧНОЕ И НА КАЖДОМ ПЕРЕХОДЕ (задача 20).
 *
 * Пробная запись имени живёт по местному порту зонда. Не снятая, она стоит до
 * вытеснения LRU или переподключения контроллера: порт возвращается ядру и
 * достаётся постороннему сокету с той же меткой (measure_mark == mark), а сама
 * запись вытесняет из таблицы подтверждённое знание. Поэтому каждый переход —
 * следующий кандидат, следующий вопрос, отказ, подтверждение, task_fail —
 * снимает то, что задача поставила, и только это:
 *   - адресный опыт (QUIC по адресу, голос) — DEL_ADDR_PROBE по своему потоку
 *     и trial ID;
 *   - кандидат по имени — DEL_NAME_PROBE (имя, форма кандидата, семейство,
 *     порт зонда); порт занят задачей исключительно (SET_NAME_PROBE на том же
 *     порту передаёт владение), поэтому ключ точен;
 *   - вопрос — DEL_NAME_PROBE (имя, форма вопроса, семейство, порт вопроса).
 * Широкой DEL_NAME здесь нет: она снимает все записи имени, включая
 * подтверждённые (§7). */
static void question_retire(d2k_sched *s, task *t) {
    if (t->prop_installed && t->prop_sport_be != 0) {
        char err[160];
        if (d2k_link_del_name_probe_family(s->link_fd, t->name, t->transport,
                                           question_shape(t), t->prop_sport_be,
                                           t->family, err, sizeof err) != 0) {
            say(s, "по %s не удалось снять план вопроса: %s", t->name, err);
        }
    }
    t->prop_installed = 0;
    if (t->prop_bound_fd > 0) { close(t->prop_bound_fd); }
    t->prop_bound_fd = -1;
    t->prop_sport_be = 0;
}

static int force_name(const d2k_sched *s,const char *name);
static uint64_t fnv1a(const char *s);
static void tried_add(task *t,uint32_t h);
static d2k_verification_status synthesis_report(d2k_sched *s,task *t,int notify) {
        if(t->trial_installed && t->synthesis_generation &&
           t->next_plan>0 && t->next_plan<=t->n_plans) {
            d2k_synthesis_feedback e={0};
            e.generation=t->synthesis_generation;e.search_id=t->report_id;
            e.target=t->name;e.ip=t->ip;e.port=t->port;
            e.program=t->plans[t->next_plan-1];
            e.doh=t->doh_path[0]!=0;e.resource=e.doh?t->doh_path:
                t->measure_path[0]?t->measure_path:"/";
            e.by_addr=t->by_addr;e.family=t->family;e.transport=t->transport;
            e.shape=t->trial_shape;
            memcpy(e.trial_id,t->trial_ack_id,sizeof e.trial_id);
            memcpy(e.plan_id,t->ver_plan_id,sizeof e.plan_id);
            e.execution_refusal=t->exec_nak;
            e.events_lost=s->dropped_seen!=t->ver_dropped0;
            /* A running worker owns ver; never race it or read old results. */
            uint8_t present=0;
            for(size_t k=0;k<sizeof e.trial_id;k++)present|=e.trial_id[k];
            if(!t->th_live && present && t->ver.local_port &&
               !memcmp(t->synthesis_ver_trial_id,e.trial_id,sizeof e.trial_id)) {
                e.applied=t->ver_ok;
                e.flow.family=t->ver_flow.family;e.flow.transport=t->ver_flow.transport;
                e.flow.a_port=t->ver_flow.a_port;e.flow.b_port=t->ver_flow.b_port;
                memcpy(e.flow.a_ip,t->ver_flow.a_ip,sizeof e.flow.a_ip);
                memcpy(e.flow.b_ip,t->ver_flow.b_ip,sizeof e.flow.b_ip);
                e.verification_available=1;e.level=t->ver.level;
                e.status=t->ver.status;e.body_complete=t->ver.body_complete;
                e.body_bytes=t->ver.body_bytes;e.local_refusal=t->ver.local_refusal;
                e.local_limit=t->ver.local_limit;e.unsupported=t->ver.unsupported;
                e.challenge=t->ver.cloudflare_challenge;e.budget=t->ver.budget;
                e.budget_uncountable=t->ver.budget_uncountable;
                e.budget_need=t->ver.budget_need;e.budget_packets=t->ver.budget_packets;
                e.budget_requests=t->ver.budget_requests;
                e.doh_replies=t->ver.doh_replies;
            }
            d2k_verification_status result=t->synthesis_owner?
                d2k_verification_accept(t->synthesis_owner,&e):D2K_VF_UNKNOWN;
            /* An owned measured rejection is reusable as an exclusion, not
               as execution evidence for another generation. UNKNOWN/local
               refusal must remain eligible for a real experiment. */
            if(force_name(s,t->name) &&
               (result==D2K_VF_NOT_MET || result==D2K_VF_APP_NOT_MET))
                tried_add(t,(uint32_t)fnv1a(e.program));
            if(result!=D2K_VF_DUPLICATE) {
                t->synthesis_result=result;
                memcpy(t->synthesis_result_trial,e.trial_id,sizeof e.trial_id);
            } else if(memcmp(t->synthesis_result_trial,e.trial_id,sizeof e.trial_id)) {
                t->synthesis_result=D2K_VF_UNKNOWN;
            }
            if(notify && !t->th_live && t->synthesis_feedback &&
               t->synthesis_context_generation==e.generation) {
                int feedback=t->synthesis_feedback(t->synthesis_context,&e,t->synthesis_result);
                if(feedback)t->synthesis_resume_pending=feedback;
            }

            if(notify && s->synthesis_observer)
                s->synthesis_observer(s->synthesis_observer_ctx,&e);
            return t->synthesis_result;

        }
    return D2K_VF_UNKNOWN;
}

static int preflight_enabled(void) {
    const char *v=getenv("D2K_PREFLIGHT");
    return !v || !strcmp(v,"1");
}
static int preflight_family_enabled(uint8_t family) {
    const char *v6 = getenv("D2K_PREFLIGHT_V6");
    return preflight_enabled() && (family == 4 || (family == 6 && v6 && !strcmp(v6,"1")));
}
static int preflight_text(const char *text) {
    return text && strstr(text,"\npreflight ")!=NULL;
}
static void gate_retire(d2k_sched *s,task *t) {
    if(t->gate_installed) {
        uint8_t ip[16]={0};char err[160];
        if(inet_pton(t->family==6?AF_INET6:AF_INET,t->ip,ip)==1 &&
           !d2k_link_del_endpoint_trial(s->link_fd,ip,t->family,htons(t->port),
               t->trial_shape,t->trial_ack_id,err,sizeof err)) t->gate_installed=0;
    }
    if(t->gate_active && t->probe_fd>=0) {close(t->probe_fd);t->probe_fd=-1;}
}
static void candidate_retire(d2k_sched *s, task *t) {
    gate_retire(s,t);
    if (t->trial_installed) {
        (void)synthesis_report(s,t,1);
        char err[160];
        int rc = 0;
        if (addr_udp(t) || t->addr_probe_identity_valid) {
            rc = addr_probe_remove(s, t, err, sizeof err);
        } else if (t->probe_sport_be != 0 && t->trial_shape != 0) {
            rc = d2k_link_del_name_probe_family(s->link_fd, t->name, t->transport,
                                                t->trial_shape, t->probe_sport_be,
                                                t->family, err, sizeof err);
        }
        if (rc != 0) {
            say(s, "по %s не удалось снять пробный план: %s", t->name, err);
        }
    }
    if (t->probe_fd >= 0) { close(t->probe_fd); t->probe_fd = -1; }
    t->probe_sport_be = 0;
    t->trial_installed = 0;
}

static void trial_retire(d2k_sched *s, task *t) {
    question_retire(s, t);
    candidate_retire(s, t);
}

/* --------------------------------------------------------------------
 * Мелочи.
 * -------------------------------------------------------------------- */

/* Говорит наружу, если есть кому. Сборка строки — здесь, чтобы вызывающий не
   тащил printf-обвязку в каждый вызов. */
static void say(d2k_sched *s, const char *fmt, ...) {
    if (!s->say_fn) { return; }
    char line[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    s->say_fn(s->say_ctx, line);
}

/* say(), но повтор того же ключа в пределах SCHED_QUIET_MS молчит. Кольцо
   вытесняет старое: в худшем случае объяснение прозвучит лишний раз. */
static void say_quiet(d2k_sched *s, const char *key, const char *fmt, ...) {
    if (!s->say_fn) { return; }
    for (size_t i = 0; i < SCHED_QUIET_SLOTS; i++) {
        if (s->quiet[i].until_ms > s->now_ms && strcmp(s->quiet[i].key, key) == 0) {
            return;
        }
    }
    size_t slot = s->quiet_next;
    s->quiet_next = (s->quiet_next + 1) % SCHED_QUIET_SLOTS;
    snprintf(s->quiet[slot].key, sizeof s->quiet[slot].key, "%s", key);
    s->quiet[slot].until_ms = s->now_ms + SCHED_QUIET_MS;
    char line[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    s->say_fn(s->say_ctx, line);
}

static void newchain_log(void *ctx,const char *text) { say(ctx,"%s",text); }
static int newchain_task(d2k_sched *s,const task *t) {
    return s->synthesis_only || (!t->by_addr && d2k_newchain_protects(&s->newchain,t->name,t->transport,t->family,t->trigger_shape));
}
int d2k_sched_newchain_owned(const d2k_sched *s,const char *name,uint8_t tr,uint8_t family,uint8_t shape) {
    return s && d2k_newchain_protects(&s->newchain,name,tr,family,shape);
}
int d2k_sched_newchain_pending(const d2k_sched *s) {
    if(!s)return 0;
    for(size_t i=0;i<s->newchain.count;i++)if(s->newchain.entries[i].pending)return 1;
    return 0;
}
static int newchain_contract(void *arg,const d2km_knowledge *k) {
    d2k_sched *s=arg;
    for(size_t i=0;i<s->n_doh;i++)if(!strcasecmp(s->doh[i].host,k->context.target.name)) {
        char contract[600],proof[1200];snprintf(contract,sizeof contract,"doh-contract-v1 path=%s replies>=20 span>=30000ms",s->doh[i].path);
        if(!d2km_application_proof(proof,sizeof proof,&k->context,k->hash,contract))return 0;
        return strstr(k->why,proof)!=NULL;
    }
    return 1;
}
int d2k_sched_set_newchain(d2k_sched *s,const char *path) {
    if(!s || (path && !s->shadow.path[0]))return -1;
    if(d2k_newchain_set(&s->newchain,path))return -1;
    s->newchain.allow_knowledge=newchain_contract;s->newchain.allow_ctx=s;
    (void)d2k_newchain_poll(&s->newchain,s->link_fd,s->now_ms,newchain_log,s);return 0;
}
int d2k_sched_set_synthesis_only(d2k_sched *s,int enabled) {
    if(!s || (enabled && (!s->shadow.path[0] || !s->newchain.path[0])))return -1;
    /* §4.3 needs an observed form. Owner traffic is admitted by
       synthesis_owner after its SHAPE, never by a fabricated startup task. */
    s->synthesis_only=!!enabled;
    return 0;
}
static void shadow_forget(d2k_sched *,shadow_flow_state *);
int d2k_sched_set_shadow(d2k_sched *s,const char *path) {
    if(!s || (path && strlen(path)>=sizeof s->shadow.path))return -1;
    for(size_t i=0;i<SCHED_SEEN;i++)shadow_forget(s,&s->shadow_flows[i]);
    memset(&s->shadow_recent,0,sizeof s->shadow_recent);
    int rc=d2k_shadow_writer_set(&s->shadow,path);
    if(!rc && s->shadow.path[0])
        (void)d2k_shadow_recent_load(s->shadow.path,"recent",&s->shadow_recent,(uint64_t)time(NULL));
    return rc;
}
uint64_t d2k_sched_shadow_dropped(const d2k_sched *s) {
    return s?s->shadow.dropped:0;
}

void d2k_sched_set_send_cap(d2k_sched *s, uint32_t cap) {
    if (!s) { return; }
    s->send_cap = cap;
}

void d2k_sched_set_say(d2k_sched *s, d2k_sched_say_fn fn, void *ctx) {
    if (!s) { return; }
    s->say_fn = fn;
    s->say_ctx = ctx;
}

/* Вердикт словами. Своя таблица, а не в d2k_verdict.h: там перечисление —
   контракт измерения, а имена нужны ровно одному читателю, человеку у лога. */
static const char *verdict_name(d2k_verdict v) {
    switch (v) {
    case D2K_V_CLEAR:        return "проходит как есть";
    case D2K_V_PREFIX:       return "помогает разрез";
    case D2K_V_WHOLE:        return "нужен пакет целиком";
    case D2K_V_OPAQUE:       return "решает содержимое";
    case D2K_V_INCONCLUSIVE: return "вердикта нет";
    case D2K_V_FLAKY:        return "измерению верить нельзя";
    case D2K_V_UNREACHABLE:  return "до цели нет транспорта";
    case D2K_V_ADDRESS:      return "режут адрес, а не содержимое";
    case D2K_V_RESPONSE:     return "режут ответ сервера";
    case D2K_V_RESPONSE_GATE: return "режут ответ сервера с переносом через RST";
    case D2K_V_NO_QUIC:      return "хост не обслуживает HTTP/3";
    case D2K_V_LOCAL_ADDRESS: return "имя разрешается в приватный адрес";
    }
    return "неизвестный вердикт";
}

/* Примета из подозрения. Порт signalOf (controller.go) — перенос, не
   пересказ, включая обе его оговорки:
   - сброс и снятый-защитой сброс дают ОДИН вид "rst": различие между ними —
     наша РЕАКЦИЯ, а отпечаток описывает поведение КОРОБКИ; разведи их, и одна
     коробка попала бы в каталог дважды;
   - TTL, ToS и идентификатор берутся ТОЛЬКО у сброса: у молчания и повтора
     подделанного пакета нет вовсе, и подставлять туда нули значило бы
     сравнивать приметы по полям, которых не измеряли. */
static d2k_cat_signal signal_of(const d2k_ev *ev) {
    d2k_cat_signal s;
    memset(&s, 0, sizeof s);
    s.seen = 1;
    switch (ev->code) {
    case 1: case 4: snprintf(s.kind, sizeof s.kind, "rst"); break;
    case 2:         snprintf(s.kind, sizeof s.kind, "repeat"); break;
    case 3:         snprintf(s.kind, sizeof s.kind, "silent"); break;
    default:        snprintf(s.kind, sizeof s.kind, "код-%u", (unsigned)ev->code); break;
    }
    if (strcmp(s.kind, "rst") == 0) {
        /* TTL самой подделки — примета коробки: она стоит на фиксированном
           расстоянии от нас. Разность с TTL сервера сохраняется как
           наблюдение, но приметой не является: серверы стоят на разном
           расстоянии (замер: на четырёх целях одной линии разности были
           3, 38, 40 и 74 при одном и том же TTL подделки 127). */
        s.ttl = ev->ttl;
        s.ttl_delta = (int)ev->ttl - (int)ev->ref_ttl;
        s.tos = ev->tos;
        s.ipid = ev->ipid;
    }
    return s;
}

/* Добавляет примету к отпечатку, схлопывая совпавшие. Допуск по TTL тот же,
   что в каталоге (D2K_TTL_SLACK): иначе задача накопит приметы, которые
   каталог потом сочтёт одной. Порт addSignal (controller.go). */
static int is_rx_volume_kind(const char *kind) {
    return !strcmp(kind, "rx-volume") || !strcmp(kind, "rx-volume-wire");
}

static void fp_add(d2k_cat_fp *fp, const d2k_cat_signal *sig) {
    for (size_t i = 0; i < fp->n_sig; i++) {
        d2k_cat_signal *x = &fp->sig[i];
        if ((strcmp(x->kind, "volume") == 0 || is_rx_volume_kind(x->kind)) &&
            strcmp(x->kind, sig->kind) == 0) {
            int d = x->volume - sig->volume;
            if (d < 0) { d = -d; }
            if (d <= D2K_VOLUME_SLACK) {
                x->seen += sig->seen;
                /* Бюджет потока (задача 55) — последний посчитанный замер. */
                if (sig->packets > 0) x->packets = sig->packets;
                return;
            }
            continue;
        }
        int d = (int)x->ttl - (int)sig->ttl;
        if (d < 0) { d = -d; }
        if (strcmp(x->kind, sig->kind) == 0 && d <= D2K_TTL_SLACK &&
            x->ipid == sig->ipid && x->tos == sig->tos) {
            x->seen += sig->seen;
            return;
        }
    }
    if (fp->n_sig >= sizeof fp->sig / sizeof fp->sig[0]) {
        return; /* приметы кончились — восьми хватает с запасом (d2k_catalog.h) */
    }
    fp->sig[fp->n_sig++] = *sig;
}

/* КОРЗИНА ПОРОГА объёмного обрыва (задача 23). Направление уже различено
   родом приметы ("volume" — исходящая лестница, "rx-volume" — входящее
   тело); корзина — порядок величины порога: [2^k, 2^(k+1)) КБ -> k+1.
   Ноль — «порог не измерен» (запись без поля volume): такая примета ни с
   какой измеренной корзиной не совпадает.

   Степени двух, а не сырые килобайты: имя коробки обязано переживать
   дрожание прибора. TX-лестница даёт обрыв только на ступенях 15, 19, 23,
   27, 31, 35 КБ (4000 байт на ступень), полевой разброс одной коробки —
   19 и 23 КБ (D2K_VOLUME_SLACK) — лежит в одной корзине [16, 32). Соседние
   ступени через край корзины (15/19, 31/35) разводит имя, но не узнавание:
   узнавание идёт раньше хеша по допуску D2K_VOLUME_SLACK (d2k_fp_same), и
   цель с обрывом 19 КБ при коробке на 15 КБ получает имя этой коробки, а
   не новое. 16 и 128 КБ — корзины 5 и 8: разные коробки. */
static int volume_bucket(int kb) {
    if (kb <= 0) { return 0; }
    int b = 0;
    while (kb > 1) { kb >>= 1; b++; }
    return b + 1;
}

static int is_volume_kind(const char *kind) {
    return strcmp(kind, "volume") == 0 || is_rx_volume_kind(kind);
}

/* Совпадает ли у коробки корзина порога хоть по одной объёмной примете
   цели того же направления. Нужна очерёдности сохранённых планов: коробка
   той же корзины — ближайшая модель, её планы идут первыми. */
static int box_volume_bucket_agrees(const d2k_cat_fp *box, const d2k_cat_fp *fp) {
    for (size_t i = 0; i < fp->n_sig; i++) {
        const d2k_cat_signal *x = &fp->sig[i];
        if (!is_volume_kind(x->kind)) { continue; }
        int want = volume_bucket(x->volume);
        if (want == 0) { continue; }
        for (size_t j = 0; j < box->n_sig; j++) {
            if (strcmp(box->sig[j].kind, x->kind) == 0 &&
                volume_bucket(box->sig[j].volume) == want) { return 1; }
        }
    }
    return 0;
}


/* Начало эфемерного диапазона Linux (ip_local_port_range, умолчание
   32768-60999). Не «порт сервера» и не список сервисов — граница, из которой
   клиентские порты берутся ядром. */
#define EPHEMERAL_FROM 32768

/* Кто из пары ключа — сервер.
 *
 * Ключ на проводе (13 байт: два адреса, два порта, протокол —
 * D2K_KEY_WIRE_LEN, d2k_ctlsrv.h) УПОРЯДОЧЕН канонизацией, а не по ролям:
 * который конец клиент, а который сервер, сам ключ не сообщает. При
 * наличии client_side используем наблюдение датапата. Для старых событий
 * без направления пока остаётся прежняя эвристика портов.
 *
 * Правило совместимости: клиентский порт ядро берёт из эфемерного диапазона, серверный —
 * тот, который слушают. Если ровно один порт пары эфемерный, второй конец и
 * есть сервер. Если оба или ни одного (сервис на высоком порту и клиент,
 * попавший туда же; либо связь между двумя низкими портами) — берём меньший
 * порт: различать их больше нечем, и назвать правило честнее, чем взять
 * первый попавшийся молча.
 *
 * Go-сторона решает это же place'ом `if k.LowPort == 443` (controller.go,
 * serverOf) — то есть зашитым номером порта. Повторять это здесь нельзя:
 * охват d2k — весь IP-трафик, все порты всегда, а не 443. */
static void server_of(const d2k_ev *ev, char *ip, size_t ipcap, uint16_t *port) {
    int low_eph  = ev->low_port  >= EPHEMERAL_FROM;
    int high_eph = ev->high_port >= EPHEMERAL_FROM;
    int server_is_low;
    if (ev->client_side == D2K_CLIENT_SIDE_LOW || ev->client_side == D2K_CLIENT_SIDE_HIGH) {
        server_is_low = ev->client_side == D2K_CLIENT_SIDE_HIGH;
    } else if (low_eph != high_eph) {
        server_is_low = high_eph; /* эфемерный — клиент, значит сервер другой */
    } else {
        server_is_low = ev->low_port <= ev->high_port;
    }
    if (server_is_low) {
        (void)inet_ntop(ev->family == 6 ? AF_INET6 : AF_INET, ev->low_ip, ip, (socklen_t)ipcap);
        *port = ev->low_port;
    } else {
        (void)inet_ntop(ev->family == 6 ? AF_INET6 : AF_INET, ev->high_ip, ip, (socklen_t)ipcap);
        *port = ev->high_port;
    }
}

static int same_flow(const seen_name *s, const d2k_ev *ev) {
    return s->used && s->transport == ev->transport &&
           s->family == (ev->family ? ev->family : 4) &&
           s->low_port == ev->low_port && s->high_port == ev->high_port &&
           memcmp(s->low_ip, ev->low_ip, s->family == 6 ? 16 : 4) == 0 &&
           memcmp(s->high_ip, ev->high_ip, s->family == 6 ? 16 : 4) == 0;
}

static void server_of(const d2k_ev *, char *, size_t, uint16_t *);
static shadow_flow_state *shadow_tuple(d2k_sched *s,const d2k_ev *ev)
{
    for(size_t i=0;i<SCHED_SEEN;i++) {
        shadow_flow_state *w=&s->shadow_flows[i];
        if(w->used && ev_matches_flow(ev,&w->tuple))return w;
    }
    return NULL;
}
static shadow_flow_state *shadow_flow(d2k_sched *s,const d2k_ev *ev)
{
    shadow_flow_state *w=shadow_tuple(s,ev);
    if(w && (!w->incarnation || !ev->flow_incarnation ||
       (w->incarnation==ev->flow_incarnation && !memcmp(w->epoch,ev->flow_epoch,16))))return w;
    return NULL;
}
static void shadow_forget(d2k_sched *s,shadow_flow_state *w)
{
    if(w->snapshot) {
        d2k_shadow_record r={.snapshot=w->snapshot};
        d2k_shadow_snapshot_remove(s->shadow.path,&r);
    }
    memset(w,0,sizeof *w);
}
static void shadow_begin(d2k_sched *s,const d2k_ev *ev)
{
    if(!s->shadow.path[0] || ev->transport!=6)return;
    shadow_flow_state *w=shadow_tuple(s,ev);
    uint8_t side=0,epoch[16]={0};uint64_t incarnation=0;
    uint8_t options[40]={0};size_t options_len=0;int options_known=0;
    /* FLOW owns direction/generation before HELLO. A HELLO without this
       boundary cannot inherit the previous connection's metadata. */
    if(ev->kind==D2K_EV_HELLO && w && w->awaiting_hello) {
        side=w->client_side;memcpy(epoch,w->epoch,16);incarnation=w->incarnation;
        options_len=w->options_len;options_known=w->options_known;memcpy(options,w->options,sizeof options);
    }
    if(!w)w=&s->shadow_flows[s->shadow_next++%SCHED_SEEN];
    shadow_forget(s,w);w->used=1;
    memcpy(w->tuple.a_ip,ev->low_ip,16);memcpy(w->tuple.b_ip,ev->high_ip,16);
    w->tuple.a_port=ev->low_port;w->tuple.b_port=ev->high_port;
    w->tuple.transport=ev->transport;w->tuple.family=ev->family?ev->family:4;
    w->client_side=side;memcpy(w->epoch,epoch,16);w->incarnation=incarnation;
    w->options_len=options_len;w->options_known=options_known;memcpy(w->options,options,sizeof options);
    if(ev->client_side==D2K_CLIENT_SIDE_LOW || ev->client_side==D2K_CLIENT_SIDE_HIGH)
        w->client_side=ev->client_side;
    if(ev->flow_incarnation) {w->incarnation=ev->flow_incarnation;memcpy(w->epoch,ev->flow_epoch,16);}
    if(ev->kind==D2K_EV_HELLO)snprintf(w->name,sizeof w->name,"%.253s",ev->name);
    else w->awaiting_hello=1;
}
static int shadow_server(shadow_flow_state *w,const d2k_ev *ev,d2k_shadow_record *r)
{
    if(ev->client_side==D2K_CLIENT_SIDE_LOW || ev->client_side==D2K_CLIENT_SIDE_HIGH)
        w->client_side=ev->client_side;
    if(w->client_side!=D2K_CLIENT_SIDE_LOW && w->client_side!=D2K_CLIENT_SIDE_HIGH)return -1;
    const uint8_t *ip=w->client_side==D2K_CLIENT_SIDE_LOW?ev->high_ip:ev->low_ip;
    r->port=w->client_side==D2K_CLIENT_SIDE_LOW?ev->high_port:ev->low_port;
    return inet_ntop(r->family==6?AF_INET6:AF_INET,ip,r->ip,sizeof r->ip)?0:-1;
}
static void shadow_shape(d2k_sched *s,const d2k_ev *ev)
{
    if(!s->shadow.path[0] || ev->transport!=6)return;
    shadow_flow_state *w=shadow_flow(s,ev);if(!w || !w->name[0])return;
    if(w->snapshot) {
        d2k_shadow_record old={.snapshot=w->snapshot};
        d2k_shadow_snapshot_remove(s->shadow.path,&old);
    }
    w->snapshot=0;w->form_key=0;w->hello_len=0;w->snapshot_queued=0;
    w->client_shape=(uint8_t)d2k_hello_shape(ev->shape,ev->shape_len);
    /* Missing options are unknown; observed zero length is known-empty. */
    if(w->options_known && ev->shape_len && ev->shape_len<=sizeof w->hello) {
        memcpy(w->hello,ev->shape,ev->shape_len);w->hello_len=ev->shape_len;
        memcpy(w->hello_options,w->options,w->options_len);w->hello_options_len=w->options_len;
        w->form_key=d2k_shadow_form_key(w->hello,w->hello_len,w->hello_options,w->hello_options_len);
    }
    w->options_known=0;
}
/* Called only for an actual task. A failed write keeps the observed form
 * identity and records a local/resource cause, never a protocol failure. */
static void shadow_snapshot(d2k_sched *s,shadow_flow_state *w,d2k_shadow_record *r)
{
    r->form_key=w->form_key;
    if(w->snapshot) {r->snapshot=w->snapshot;return;}
    if(!w->hello_len)return;
    if(!d2k_shadow_snapshot_write(s->shadow.path,r,w->hello,w->hello_len,
                                  w->hello_options,w->hello_options_len,r->time))w->snapshot=r->snapshot;
    else say(s,"тень: snapshot-write host=%s form=%016llx outcome=%s errno=%d",
        w->name,(unsigned long long)r->form_key,
        r->snapshot_errno==ENOSPC || r->snapshot_errno==ENOMEM?"NO_RESOURCES":"LOCAL_FAIL",r->snapshot_errno);
}

static int shadow_submit(d2k_sched *s,shadow_flow_state *w,d2k_shadow_record *r)
{
    r->form_key=w->form_key;
    if(d2k_shadow_queue_pending(s->shadow.path,r)==1) {
        /* That pending task owns its own file. Only our unqueued file, if
           a previous append failed, may be removed here. */
        if(w->snapshot) {
            d2k_shadow_record own={.snapshot=w->snapshot};
            d2k_shadow_snapshot_remove(s->shadow.path,&own);w->snapshot=0;
        }
        return 1;
    }
    shadow_snapshot(s,w,r);
    return d2k_shadow_queue_append(&s->shadow,r);
}
static uint64_t shadow_source(const shadow_flow_state *w)
{
    /* A tuple without a generation is conservative on tuple reuse: its own
       later cut must never be hidden by its earlier encrypted flight. */
    uint64_t h=UINT64_C(14695981039346656037);
    const uint8_t *parts[]={(const uint8_t *)&w->tuple,w->epoch,(const uint8_t *)&w->incarnation};
    const size_t sizes[]={sizeof w->tuple,sizeof w->epoch,sizeof w->incarnation};
    for(unsigned p=0;p<3;p++)for(size_t i=0;i<sizes[p];i++)h=(h^parts[p][i])*UINT64_C(1099511628211);
    return h?h:1;
}
static void shadow_clean(d2k_sched *s,const d2k_ev *ev)
{
    if(!s->shadow.path[0] || ev->transport!=6 || ev->planned!=D2K_LINK_PLANNED_NO ||
       !ev->num || !d2k_ev_outer_appdata(ev))return;
    shadow_flow_state *w=shadow_flow(s,ev);
    /* A TCP HELLO is observed TLS; real HELLO frames carry no shape code. */
    if(!w || w->signal || !w->name[0])return;
    d2k_shadow_record r={.time=(uint64_t)time(NULL),.family=w->tuple.family};
    if(shadow_server(w,ev,&r))return;
    if(!w->incarnation && ev->flow_incarnation) {w->incarnation=ev->flow_incarnation;memcpy(w->epoch,ev->flow_epoch,16);}
    strcpy(r.host,w->name);
    r.form_key=w->form_key;r.protocol=w->client_shape==D2K_SHAPE_LEGACY?1:2;
    r.clean_source=shadow_source(w);
    d2k_shadow_recent_note(&s->shadow_recent,&r,r.time);
    (void)d2k_shadow_recent_save(s->shadow.path,"recent",&s->shadow_recent,r.time);
}

static int ech_rr_known(const d2k_sched *s, const char *name, const char *public_name);
static int ech_chal_has(const d2k_sched *s, const char *name);
static int ech_pick_witness(d2k_sched *s, task *t, int real, int allow_chal);
static int ladder_candidate_at(const task *t, size_t i);
static void ech_rr_store(d2k_sched *s, const char *name, int has, const char *public_name);
/* Имя ECH-приманки (net.name либо семя hcaptcha.com) — определено ниже, но
   нужно раньше, в выдаче измерителя (составной вопрос семейства C). */
static const char *rx_decoy_name(const d2k_sched *s);

static void server_of(const d2k_ev *ev, char *ip, size_t ipcap, uint16_t *port);

/* НОВОЕ СОЕДИНЕНИЕ НА ТОМ ЖЕ КОРТЕЖЕ (этап 49): всё, что знали о прежнем, —
   счётчики, «сервер отвечал», эпизод тишины, ожидание наблюдения, исполнение,
   имя и вид — новому не принадлежит. Остаются место, кортеж и время. */
static void flowwatch_conn_reset(flow_watch *w, int64_t now_ms) {
    flow_watch keep = *w;
    memset(w, 0, sizeof *w);
    w->used = 1;
    w->tuple = keep.tuple;
    w->transport = keep.transport;
    w->family = keep.family;
    w->added_ms = now_ms ? now_ms : 1;
    memcpy(w->low_ip, keep.low_ip, 16); memcpy(w->high_ip, keep.high_ip, 16);
    w->low_port = keep.low_port; w->high_port = keep.high_port;
    w->client_side = keep.client_side;
}

/* Цель наблюдения: имя, если оно есть, иначе адрес и порт сервера. */
static const char *known_service_name(const d2k_sched *,const uint8_t *,uint8_t,
                                      uint8_t,uint16_t,int64_t);
static void flowwatch_target(const d2k_sched *s,flow_watch *w, const char *name) {
    w->known_service[0]=0;
    if (name && name[0]) { snprintf(w->target, sizeof w->target, "%s", name); w->port = 0; return; }
    char srv[INET6_ADDRSTRLEN] = "";
    (void)inet_ntop(w->family == 6 ? AF_INET6 : AF_INET, w->tuple.dst, srv, sizeof srv);
    snprintf(w->target, sizeof w->target, "%s", srv);
    w->port = (uint16_t)(w->tuple.dport_be[0] << 8 | w->tuple.dport_be[1]);
    if (w->client_side==D2K_CLIENT_SIDE_LOW || w->client_side==D2K_CLIENT_SIDE_HIGH) {
        const char *service=known_service_name(s,w->tuple.dst,w->family,w->transport,w->port,s->now_ms);
        if (service) snprintf(w->known_service,sizeof w->known_service,"%s",service);
    }
}

/* Что событие говорит о потоке наблюдения (этап 49): TLS без имени — из
   приветствия; исполнение постоянного плана — из APPLIED. Остальное «не
   сказано» и не выдумывается. */
static void flowwatch_identity(flow_watch *w, const d2k_ev *ev) {
    if(ev->flow_incarnation && d2k_rm_nonzero(ev->flow_epoch,16)) {
        memcpy(w->flow_epoch,ev->flow_epoch,16);
        w->flow_incarnation=ev->flow_incarnation;
    }
    if (ev->kind == D2K_EV_HELLO && ev->transport == 6 && !ev->name[0]) w->tls_noname = 1;
    if (ev->kind == D2K_EV_APPLIED && ev->execution_id) {
        w->planned = D2K_LINK_PLANNED_YES;
        w->execution_id = ev->execution_id;
        memcpy(w->plan_id, ev->plan_id, sizeof w->plan_id);
        memcpy(w->trial_id, ev->trial_id, sizeof w->trial_id);
        w->binding = ev->execution_binding;
    }
}

/* Поток из приветствия — под наблюдение счётчиков (этап 37), если есть чем
   спрашивать conntrack. Кортеж orig — клиент → сервер (сервер — по
   наблюдённой стороне клиента, иначе конец с не эфемерным портом,
   server_of). Повтор потока не дублируется. passive — поток известен только
   фактом появления (этап 42): занимает свободное место или место другого
   пассивного, именную/плановую запись не вытесняет; приветствие или план того
   же потока делают его запись обычной. */
static void flowwatch_add(d2k_sched *s, const d2k_ev *ev, const char *name, int passive) {
    if (!name) name = "";
    if (!s->ct_query || (ev->transport != 6 && ev->transport != 17)) return;
    uint8_t family = ev->family ? ev->family : 4;
    char srv[INET6_ADDRSTRLEN];
    uint16_t sport = 0;
    server_of(ev, srv, sizeof srv, &sport);
    char low[INET6_ADDRSTRLEN] = "";
    (void)inet_ntop(family == 6 ? AF_INET6 : AF_INET, ev->low_ip, low, sizeof low);
    int server_low = ev->low_port == sport && !strcmp(low, srv);
    const uint8_t *cip = server_low ? ev->high_ip : ev->low_ip;
    const uint8_t *sip = server_low ? ev->low_ip : ev->high_ip;
    uint16_t cport = server_low ? ev->high_port : ev->low_port;
    d2k_ct_tuple t;
    memset(&t, 0, sizeof t);
    t.family = family;
    t.proto = ev->transport;
    memcpy(t.src, cip, family == 6 ? 16 : 4);
    memcpy(t.dst, sip, family == 6 ? 16 : 4);
    t.sport_be[0] = (uint8_t)(cport >> 8); t.sport_be[1] = (uint8_t)cport;
    t.dport_be[0] = (uint8_t)(sport >> 8); t.dport_be[1] = (uint8_t)sport;
    flow_watch *w = NULL;
    for (size_t i = 0; i < SCHED_FLOWWATCH_SLOTS; i++) {
        flow_watch *c = &s->flowwatch[i];
        if (c->used && !memcmp(&c->tuple, &t, sizeof t)) {
            if (ev->kind == D2K_EV_HELLO || ev->kind == D2K_EV_FLOW) {
                /* Приветствие и факт появления — начало соединения: прежнее
                   соединение этого кортежа кончилось (этап 49). */
                flowwatch_conn_reset(c, s->now_ms);
                c->passive = passive;
                memcpy(c->low_ip, ev->low_ip, 16); memcpy(c->high_ip, ev->high_ip, 16);
                c->low_port = ev->low_port; c->high_port = ev->high_port;
                c->client_side = ev->client_side;
                flowwatch_target(s, c, name);
            } else if (passive) {
                return;
            } else {
                c->passive = 0;
                if (name[0]) flowwatch_target(s, c, name);
            }
            flowwatch_identity(c, ev);
            return;
        }
        if (!c->used && !w) w = c;
    }
    if (!w) { /* все заняты — уступает давнее пассивное, затем давнее всех */
        for (size_t i = 0; i < SCHED_FLOWWATCH_SLOTS; i++) {
            flow_watch *c = &s->flowwatch[i];
            if (c->passive && (!w || c->added_ms < w->added_ms)) w = c;
        }
        /* Факт без свободного места — потеря наблюдения в любом случае:
           либо уступает давний пассивный, либо этот не встаёт. */
        if (passive) { s->flowwatch_full++; if (!w) return; }
    }
    if (!w) {
        w = &s->flowwatch[0];
        for (size_t i = 1; i < SCHED_FLOWWATCH_SLOTS; i++)
            if (s->flowwatch[i].added_ms < w->added_ms) w = &s->flowwatch[i];
    }
    memset(w, 0, sizeof *w);
    w->used = 1;
    w->passive = passive;
    w->tuple = t;
    w->transport = ev->transport;
    w->family = family;
    w->added_ms = s->now_ms;
    memcpy(w->low_ip, ev->low_ip, 16); memcpy(w->high_ip, ev->high_ip, 16);
    w->low_port = ev->low_port; w->high_port = ev->high_port;
    w->client_side = ev->client_side;
    flowwatch_target(s, w, name);
    flowwatch_identity(w, ev);
}

/* КАНДИДАТ ПОЗДНЕЙ ТИШИНЫ (этап 49): TCP, сервер уже отвечал,
   SCHED_FLOWWATCH_STALL_STEPS шагов подряд от него ни одного пакета, клиент за
   это время послал не меньше трёх, ядро говорит ESTABLISHED. Это только
   кандидат: чистые ACK и обновления окна ответа не требуют, и что за пакеты
   шлёт клиент, решает наблюдение самого потока, а не счётчики. Голые ACK
   сервера — сервер жив на уровне TCP, это не тишина. После отрицательного
   итога — только после отката и новой активности клиента. */
static int raw_late_eligible(const flow_watch *w) {
    return w->passive && w->port && !w->tls_noname && w->flow_incarnation &&
           d2k_rm_nonzero(w->flow_epoch,16);
}
static int late_silence_due(const flow_watch *w, const d2k_ct_info *ci, int64_t now_ms) {
    uint64_t from=w->obs_fails && w->rearm_orig>w->sil_orig?w->rearm_orig:w->sil_orig;
    int protocol=w->transport==6 ? ci->tcp_state_known && ci->tcp_state==D2K_CT_TCP_ESTABLISHED
                                : w->transport==17 && raw_late_eligible(w);
    return protocol && w->had_reply && !w->escalated && !w->obs_asked_ms &&
           w->sil_steps>=SCHED_FLOWWATCH_STALL_STEPS && (!w->obs_fails || now_ms>=w->rearm_ms) &&
           ci->orig_pkts>=from && ci->orig_pkts-from>=3;
}
static int raw_late_observe(d2k_sched *s,flow_watch *w);

/* Отрицательный итог наблюдения на этом соединении: эпизод снова открыт, но
   с откатом SCHED_LATE_OBS_S × 2^(неудач−1), не больше 2^6, — ни постоянной
   метки, ни петли наблюдений. */
static void late_obs_negative(d2k_sched *s, flow_watch *w) {
    w->obs_asked_ms = 0;
    w->escalated = 0;
    if (w->obs_fails < 7) w->obs_fails++;
    w->rearm_ms = s->now_ms + ((int64_t)SCHED_LATE_OBS_S * 1000 << (w->obs_fails - 1));
    w->rearm_orig = w->orig_pkts;
}

/* СЧЁТЧИКИ ТОЛЬКО ВЫДВИГАЮТ (этап 49): что шлёт клиент — чистые ACK, окно
   или повтор данных, — ими не различить. Свидетельство добывается на самом
   потоке: датапат ставит метку поздней доставки на его запись conntrack на
   SCHED_LATE_OBS_S, классифицирует пакеты и снимает метку (d2k_lateobs.h).
   Срок — предел метки (120 с): повторы TCP идут с удвоением RTO (~13, ~25,
   ~51, ~102 с от начала тишины), и к запросу (≥10–20 с тишины) два повтора
   укладываются только в него. Итог раньше срока — при повторе в тишине или
   ответе сервера. Токен связывает команду, ACK и итог с ЭТИМ наблюдением:
   поздний итог прежнего наблюдения того же кортежа не принимается. */
static void late_observe_ask(d2k_sched *s, flow_watch *w) {
    w->escalated = 1;
    if(raw_late_eligible(w)) {
        if(!raw_late_observe(s,w))late_obs_negative(s,w);
        return;
    }
    char err[160];
    if (fresh_trial_id(w->obs_token) != 0) {
        snprintf(err, sizeof err, "нет случайности для токена наблюдения");
    } else if (d2k_link_late_observe(s->link_fd, &w->tuple, SCHED_LATE_OBS_S, w->obs_token,
                                     err, sizeof err) == 0) {
        err[0] = '\0';
    }
    if (err[0]) {
        late_obs_negative(s, w);
        say_quiet(s, w->target, "по %s поздняя тишина по счётчикам, но наблюдение потока не попросить: %s — "
                  "замер не начинаю", w->target, err);
        return;
    }
    w->obs_asked_ms = s->now_ms ? s->now_ms : 1;
    say(s, "по %s поздняя тишина по счётчикам: сервер отвечал, затем ни одного его пакета, клиент шлёт — "
           "что именно (ACK или повтор данных), счётчики не говорят: наблюдаю сам поток до %d с",
        w->target, SCHED_LATE_OBS_S);
}
static void late_silence(d2k_sched *s, flow_watch *w, unsigned repeats);

/* Шаг наблюдения: по каждому потоку — счётчики и вывод состояния. */
static void flowwatch_tick(d2k_sched *s, int64_t now_ms) {
    if (!s->ct_query) return;
    if (s->flowwatch_ms && now_ms - s->flowwatch_ms < SCHED_FLOWWATCH_STEP_MS) return;
    s->flowwatch_ms = now_ms ? now_ms : 1;
    for (size_t i = 0; i < SCHED_FLOWWATCH_SLOTS; i++) {
        flow_watch *w = &s->flowwatch[i];
        if (!w->used) continue;
        /* Событие могло прийти до первого такта (часов ещё не было): срок —
           от первого такта, как у опытов RAW, иначе нулевое время постановки
           выглядело бы давним и поток снимался бы сразу. */
        if (!w->added_ms) w->added_ms = now_ms ? now_ms : 1;
        d2k_ct_info ci;
        memset(&ci, 0, sizeof ci);
        int rc = s->ct_query(&w->tuple, &ci);
        if (rc == 1) { memset(w, 0, sizeof *w); continue; }     /* записи нет — поток кончился */
        /* Presence in conntrack, including an idle connection, keeps this
           bounded watch slot useful. Age alone must not hide a later stall.
           Only prolonged inability to observe the record expires the watch. */
        if (rc == 0) w->ct_seen_ms = now_ms ? now_ms : 1;
        else if (now_ms - (w->ct_seen_ms ? w->ct_seen_ms : w->added_ms) > SCHED_FLOWWATCH_KEEP_MS) {
            memset(w, 0, sizeof *w); continue;
        }
        if (rc != 0 || !ci.counters_known) {
            /* Данных нет: ни прежней скорости, ни шагов застоя; следующий годный
               замер — новая точка отсчёта (дельты через разрыв нет). */
            w->state = FW_NODATA; w->rate_Bps = 0; w->flat_steps = 0; w->sil_steps = 0;
            w->samples++; w->sampled_ms = now_ms; continue;
        }
        int back = ci.reply_bytes < w->reply_bytes || ci.reply_pkts < w->reply_pkts ||
                   ci.orig_bytes < w->orig_bytes || ci.orig_pkts < w->orig_pkts;
        /* Наименьшие заголовки: TCP 20+20 / 40+20, UDP 20+8 / 40+8. Не
           больше их на пакет — данных от сервера нет наверняка. */
        uint64_t minhdr = w->transport == 6 ? (w->family == 6 ? 60u : 40u) : (w->family == 6 ? 48u : 28u);
        if (back && w->samples) {
            /* Счётчики назад без нового приветствия: запись заменена тем же
               кортежем — это другое соединение (этап 49). Имя, исполнение и
               эпизод прежнего ему не принадлежат: дальше — адрес по счётчикам. */
            flowwatch_conn_reset(w, now_ms);
            w->passive = 1;
            flowwatch_target(s, w, NULL);
        }
        if (w->samples == 0 || w->state == FW_NODATA || back) {
            /* Первый замер, после пропуска данных или новое соединение — только
               точка отсчёта. Ответ сервера за жизнь записи (больше голых
               заголовков) — «сервер отвечал», даже если всё пришло до первого
               замера. */
            w->state = FW_UNKNOWN; w->rate_Bps = 0; w->flat_steps = 0; w->sil_steps = 0;
            if (ci.reply_bytes > ci.reply_pkts * minhdr) w->had_reply = 1;
        } else {
            int64_t dt = now_ms - w->sampled_ms;
            uint64_t drb = ci.reply_bytes - w->reply_bytes;
            uint64_t drp = ci.reply_pkts - w->reply_pkts;
            uint64_t dop = ci.orig_pkts - w->orig_pkts;
            int proven = drp > 0 && (w->transport == 17 ||
                                     (w->family != 6 && drb > drp * 120u));
            if (proven || drb > drp * minhdr) w->had_reply = 1;
            if (drp == 0 && w->had_reply) {
                if (!w->sil_steps) { w->sil_orig = w->orig_pkts; w->sil_ms = w->sampled_ms; }
                w->sil_steps++;
            } else {
                w->sil_steps = 0;
                if (drp > 0) { w->escalated = 0; w->obs_fails = 0; }   /* сервер заговорил — эпизод кончился */
            }
            w->in_bytes += drb;
            w->rate_Bps = dt > 0 ? drb * 1000u / (uint64_t)dt : 0;
            if (proven) {
                w->state = FW_MOVING;
                w->flat_steps = 0;
            } else if (drb > drp * minhdr) {
                w->state = FW_ACTIVE;
                w->flat_steps = 0;
            } else if (dop > 0) {
                w->rate_Bps = 0;
                w->flat_steps++;
                w->state = w->flat_steps >= SCHED_FLOWWATCH_STALL_STEPS ? FW_STALLED : w->state;
            } else {
                w->rate_Bps = 0;
                w->flat_steps = 0;
                w->state = FW_IDLE;
            }
        }
        w->orig_pkts = ci.orig_pkts; w->reply_pkts = ci.reply_pkts;
        w->orig_bytes = ci.orig_bytes; w->reply_bytes = ci.reply_bytes;
        w->samples++;
        w->sampled_ms = now_ms;
        int raw_observing=0;
        if(w->obs_asked_ms)for(size_t ti=0;ti<SCHED_MAX_TASKS;ti++) {
            const task *rt=&s->tasks[ti];
            if((rt->state==T_RAW_MEASURE_ACK || rt->state==T_RAW_MEASURE_OBSERVE || rt->state==T_RAW_MEASURED) &&
               rt->raw_measure_request.generation==w->flow_incarnation &&
               !memcmp(rt->raw_measure_request.epoch,w->flow_epoch,16) &&
               !memcmp(rt->raw_measure_request.token,w->obs_token,16) &&
               !memcmp(&rt->raw_measure_request.tuple,&w->tuple,sizeof w->tuple)) {raw_observing=1;break;}
        }
        if (!raw_observing && w->obs_asked_ms && now_ms - w->obs_asked_ms > (SCHED_LATE_OBS_S + 15) * 1000) {
            late_obs_negative(s, w);
            say_quiet(s, w->target, "по %s поздняя тишина не подтверждена на самом потоке: итог наблюдения "
                      "не пришёл — замер не начинаю", w->target);
        }
        if (late_silence_due(w, &ci, now_ms)) late_observe_ask(s, w);
    }
}

void d2k_sched_set_ct_query(d2k_sched *s, d2k_sched_flow_ct_fn fn) {
    if (s) s->ct_query = fn;
}

void d2k_sched_set_ct_peers(d2k_sched *s, d2k_sched_peers_fn fn) {
    if (s) s->ct_peers = fn;
}

static void remember(d2k_sched *s, const d2k_ev *ev) {
    int noname = ev->name[0] == '\0';
    for (size_t i = 0; i < SCHED_SEEN; i++) {
        if (same_flow(&s->seen[i], ev)) {
            /* Пустое приветствие не стирает уже известное имя потока. */
            if (!noname) {
                snprintf(s->seen[i].name, sizeof s->seen[i].name, "%s", ev->name);
                s->seen[i].named_client_side=ev->client_side;
                s->seen[i].named_ms=s->now_ms;
            }
            else if (!s->seen[i].name[0]) { s->seen[i].noname = 1; }
            s->seen[i].observed_ms = s->now_ms;
            if(ev->client_shape)s->seen[i].client_shape=ev->client_shape;
            flowwatch_add(s, ev, ev->name, 0);   /* новое соединение на прежнем кортеже (этап 49) */
            return;
        }
    }
    seen_name *slot = &s->seen[s->seen_next];
    s->seen_next = (s->seen_next + 1) % SCHED_SEEN;
    memset(slot, 0, sizeof *slot);
    slot->family = ev->family ? ev->family : 4;
    memcpy(slot->low_ip, ev->low_ip, slot->family == 6 ? 16 : 4);
    memcpy(slot->high_ip, ev->high_ip, slot->family == 6 ? 16 : 4);
    slot->low_port = ev->low_port;
    slot->high_port = ev->high_port;
    slot->transport = ev->transport;
    snprintf(slot->name, sizeof slot->name, "%s", ev->name);
    slot->noname = noname;
    slot->used = 1;
    slot->observed_ms = s->now_ms;
    slot->client_shape=ev->client_shape;
    if (!noname) { slot->named_client_side=ev->client_side; slot->named_ms=s->now_ms; }
    flowwatch_add(s, ev, ev->name, 0);
}

static const char *recall(const d2k_sched *s, const d2k_ev *ev) {
    for (size_t i = 0; i < SCHED_SEEN; i++) {
        /* Имя или ничего: запись без имени для именных путей не существует. */
        if (same_flow(&s->seen[i], ev)) { return s->seen[i].name[0] ? s->seen[i].name : NULL; }
    }
    return NULL;
}

/* Было ли у потока приветствие TLS без имени (адресная TCP-цель). */
static int recall_noname(const d2k_sched *s, const d2k_ev *ev) {
    for (size_t i = 0; i < SCHED_SEEN; i++) {
        if (same_flow(&s->seen[i], ev)) { return s->seen[i].noname && !s->seen[i].name[0]; }
    }
    return 0;
}

static target_cooldown *cooldown_find(d2k_sched *s, const char *name,
                                     uint8_t transport, uint8_t family) {
    if (!s || !name || !name[0]) { return NULL; }
    for (size_t i = 0; i < SCHED_COOLDOWN_SLOTS; i++) {
        target_cooldown *c = &s->cooldowns[i];
        if (c->used && c->transport == transport &&
            c->family == (family ? family : 4) && strcmp(c->name, name) == 0) {
            return c;
        }
    }
    return NULL;
}

static dead_address *dead_find(d2k_sched *s, const char *name, uint8_t transport,
                               uint8_t family, const char *addr) {
    if (!s || !name || !name[0] || !addr || !addr[0]) { return NULL; }
    for (size_t i = 0; i < SCHED_COOLDOWN_SLOTS; i++) {
        dead_address *d = &s->dead_addrs[i];
        if (d->used && d->transport == transport && d->family == (family ? family : 4) &&
            strcmp(d->name, name) == 0 && strcmp(d->addr, addr) == 0) {
            return d;
        }
    }
    return NULL;
}

static int64_t clear_backoff_ms(unsigned streak);

/* Ступень лестницы мёртвого адреса; возвращает отсрочку. */
static int64_t dead_step(d2k_sched *s, const task *t) {
    dead_address *d = dead_find(s, t->name, t->transport, t->family, t->ip);
    if (!d) {
        /* Свободная запись, иначе та, чья отсрочка кончилась раньше всех. */
        for (size_t i = 0; i < SCHED_COOLDOWN_SLOTS; i++) {
            dead_address *c = &s->dead_addrs[i];
            if (!c->used) { d = c; break; }
            if (!d || c->until_ms < d->until_ms) { d = c; }
        }
        memset(d, 0, sizeof *d);
        snprintf(d->name, sizeof d->name, "%s", t->name);
        snprintf(d->addr, sizeof d->addr, "%s", t->ip);
        d->transport = t->transport;
        d->family = t->family ? t->family : 4;
        d->used = 1;
    }
    if (d->streak < UINT8_MAX) { d->streak++; }
    int64_t delay = clear_backoff_ms(d->streak);
    d->until_ms = s->now_ms + delay;
    return delay;
}

static void dead_clear(d2k_sched *s, const task *t) {
    dead_address *d = dead_find(s, t->name, t->transport, t->family, t->ip);
    if (d) { memset(d, 0, sizeof *d); }
}

static inline int is_late_volume_suspicion(uint8_t code) {
    return code == D2K_SUSPECT_RST_AFTER_APP ||
           code == D2K_SUSPECT_FIN_RETRY ||
           code == D2K_SUSPECT_TCP_STALL ||
           code == D2K_SUSPECT_LATE_SILENCE;
}

static doh_target *doh_find(d2k_sched *s, const char *host) {
    doh_target *found=NULL;
    for (size_t i=0; i<s->n_doh; i++)
        if (!s->doh[i].plain && !strcasecmp(s->doh[i].host,host)) {
            if(found && (found->port!=s->doh[i].port || found->dot!=s->doh[i].dot ||
                strcmp(found->path,s->doh[i].path)))return NULL;
            found=&s->doh[i];
        }
    return found;
}

/* Explicit operator policy only: no built-in domain or address list. */
static int force_name(const d2k_sched *s, const char *name) {
    if(!name)return 0;
    size_t n=strlen(name);if(n && name[n-1]=='.')n--;
    for(size_t i=0;i<s->n_force;i++) {
        size_t k=strlen(s->force_suffixes[i]);
        if(n>=k && (n==k || name[n-k-1]=='.') &&
           !strncasecmp(name+n-k,s->force_suffixes[i],k))return 1;
    }
    return 0;
}
int d2k_sched_force_load(d2k_sched *s,const char *path) {
    FILE *f=fopen(path,"r");if(!f)return errno==ENOENT?0:-1;
    char names[128][256],line[1024];size_t n=0;
    while(fgets(line,sizeof line,f)) {
        char *comment=strchr(line,'#');if(comment)*comment=0;
        char *a=line;while(isspace((unsigned char)*a))a++;
        size_t z=strlen(a);while(z && isspace((unsigned char)a[z-1]))a[--z]=0;
        if(!z)continue;
        if(z && a[z-1]=='.')a[--z]=0;
        if(!z || z>253 || n==128)goto bad;
        size_t label=0;
        for(size_t j=0;j<=z;j++) {
            unsigned char ch=(unsigned char)a[j];
            if(!ch || ch=='.') {
                if(!label || label>63 || a[j-1]=='-')goto bad;
                label=0;
            } else {
                if(!((ch>='A'&&ch<='Z') || (ch>='a'&&ch<='z') ||
                     (ch>='0'&&ch<='9') || (ch=='-' && label)))goto bad;
                label++;
            }
        }
        snprintf(names[n++],sizeof names[0],"%s",a);
    }
    if(ferror(f))goto bad;
    fclose(f);memcpy(s->force_suffixes,names,n*sizeof names[0]);s->n_force=n;
    return (int)n;
bad:
    fclose(f);return -1;
}

static int doh_path_ok(const char *path) {
    if(!path || path[0]!='/' || path[1]=='/')return 0;
    for(const unsigned char *p=(const unsigned char *)path;*p;p++)
        if(*p<=32 || *p>=127 || *p=='#' || *p=='\\')return 0;
    return 1;
}

int d2k_sched_doh_load(d2k_sched *s, const char *path) {
    FILE *f=fopen(path,"r");
    if (!f) return errno==ENOENT ? 0 : -1;
    doh_target targets[8]; size_t n=0; char line[1024],extra; unsigned port;
    while (fgets(line,sizeof line,f)) {
        if (line[0]=='#' || line[0]=='\n') continue;
        if (n==8) { fclose(f); return -1; }
        doh_target *d=&targets[n]; memset(d,0,sizeof *d);
        uint8_t addr[16];
        if (sscanf(line,"%255s %u %511s %45s %c",d->host,&port,d->path,d->ip,&extra)!=4 ||
            port==0 || port>65535 || !doh_path_ok(d->path) ||
            (inet_pton(AF_INET,d->ip,addr)!=1 && inet_pton(AF_INET6,d->ip,addr)!=1)) {
            fclose(f); return -1;
        }
        d->port=(uint16_t)port; d->sources=1; n++;
    }
    if (ferror(f)) { fclose(f); return -1; }
    fclose(f); memcpy(s->doh,targets,n*sizeof *targets); s->n_doh=n;
    return (int)n;
}

static int newer_target_binding(const d2k_catalog *cat, const d2k_cat_binding *bd);
static int stamp_plan_id(char *text,const uint8_t id[D2K_PLAN_ID_LEN]);
static void preflight_dns_reconcile(d2k_sched *,const uint8_t *,uint8_t,
    const uint8_t *,uint32_t,int64_t);
#include "sched_dns.inc"

static int cooldown_blocks(d2k_sched *s, const char *name, uint8_t transport,
                           uint8_t family, uint8_t signal_code, int64_t *remaining_ms) {
    if (force_name(s,name) || (transport==6 && doh_find(s,name))) return 0;
    target_cooldown *c = cooldown_find(s, name, transport, family);
    if (!c) { return 0; }
    if (s->now_ms >= c->until_ms) { return 0; }
    /* Неубедительная пара поздних RST (вид 3) говорит только о позднем
       обрыве ответа. Блокировка на рукопожатии (обычный RST, таймаут SNI) —
       другое наблюдение и мерится сразу (финальное ревью, п.4). */
    if (c->late_rst_only && !c->challenge &&
        !is_late_volume_suspicion(signal_code)) {
        return 0;
    }
    /* A changed symptom after a direct CLEAR is fresh evidence. Do not let a
       stale negative suppress it. A bot challenge is different: stay quiet
       for this exact origin even if the datapath reports another symptom. */
    if (!c->challenge && !c->exhausted && c->signal_code != signal_code) { return 0; }
    if (remaining_ms) { *remaining_ms = c->until_ms - s->now_ms; }
    return 1;
}

static void cooldown_clear(d2k_sched *s, const char *name, uint8_t transport, uint8_t family) {
    target_cooldown *c = cooldown_find(s, name, transport, family);
    if (c) { memset(c, 0, sizeof *c); }
}

static int64_t clear_backoff_ms(unsigned streak) {
    if (streak <= 1) { return SCHED_CLEAR_BACKOFF_1_MS; }
    if (streak == 2) { return SCHED_CLEAR_BACKOFF_2_MS; }
    return SCHED_CLEAR_BACKOFF_MAX_MS;
}

/* КОГО ВЫТЕСНИТЬ ИЗ КОЛЬЦА ОТСРОЧЕК (финальное ревью core, M6). Кольцо
   конечно, но писать его по кругу значило снимать действующую 60-минутную
   антибот-паузу раньше срока, когда в доме много неудачных целей. Порядок:
   свободная запись; истёкшая (дольше всех истёкшая); действующая не-антибот
   с ближайшим концом; и только если ВСЁ кольцо — действующие антибот-паузы,
   та из них, что кончится раньше. */
static target_cooldown *cooldown_victim(d2k_sched *s) {
    target_cooldown *best = NULL;
    int best_rank = 4;
    for (size_t i = 0; i < SCHED_COOLDOWN_SLOTS; i++) {
        target_cooldown *c = &s->cooldowns[i];
        int rank = !c->used ? 0
                 : s->now_ms >= c->until_ms ? 1
                 : !c->challenge ? 2 : 3;
        if (rank == 0) return c;
        if (rank < best_rank || (rank == best_rank && c->until_ms < best->until_ms)) {
            best = c;
            best_rank = rank;
        }
    }
    return best;
}

/* ИСПЫТАННОЕ ЭТИМ ПОИСКОМ — В ПАМЯТЬ ОСТЫВАНИЯ: по ней решается, есть ли
   смысл в проверке появившегося плана (plan_news_recheck). */
static void cooldown_merge_tried(target_cooldown *c, const task *t) {
    for (uint8_t i = 0; i < t->n_own_tried; i++) {
        uint32_t h = t->own_tried[i];
        int seen = 0;
        for (uint8_t k = 0; k < c->n_failed_plans; k++) {
            if (c->failed_plans[k] == h) { seen = 1; break; }
        }
        if (seen) { continue; }
        if (c->n_failed_plans < SCHED_FAILED_PLANS) {
            c->failed_plans[c->n_failed_plans++] = h;
            continue;
        }
        memmove(c->failed_plans, c->failed_plans + 1,
                (SCHED_FAILED_PLANS - 1) * sizeof c->failed_plans[0]);
        c->failed_plans[SCHED_FAILED_PLANS - 1] = h;
    }
}

/* ЗАПИСАТЬ ИСПЫТАННОЕ, НЕ ЗАВОДЯ НОВОГО СРОКА. Проверка появившегося плана
   остывания не заводит — его завёл провалившийся поиск, и сдвигать его срок
   проверке не за что. Ей нужно ровно одно: оставить след, что ЭТОТ план на
   ЭТОЙ цели уже не сработал. Нет записи остывания — нечего и помнить: цель
   не отдыхает, и следующий запрос начнёт обычный поиск. */
static void cooldown_note_tried(d2k_sched *s, const task *t) {
    target_cooldown *c;
    if (!s || !t || !t->name[0] || !t->n_own_tried) { return; }
    c = cooldown_find(s, t->name, t->transport, t->family);
    if (!c) { return; }
    cooldown_merge_tried(c, t);
}

/* kind: 0 = direct CLEAR, 1 = anti-bot challenge, 2 = exhausted/incomplete search,
   3 = inconclusive late-RST pair (suppresses only late-RST/volume triggers).
   A dead address (task 54) is not a name cooldown: see dead_address. */
/* A RAW failure belongs to one live incarnation, not every application at
 * its server address. Epoch+generation are assigned uniquely by the datapath. */
static void raw_cooldown_key(char *out,size_t cap,const uint8_t epoch[16],uint64_t generation) {
    char hex[33];
    for(unsigned i=0;i<16;i++)snprintf(hex+2*i,3,"%02x",epoch[i]);
    snprintf(out,cap,"raw:%s:%016llx",hex,(unsigned long long)generation);
}
static uint64_t seed_input_of(const uint8_t *, size_t, const char *, uint16_t);

static void cooldown_record(d2k_sched *s, const task *t, int kind) {
    if (!s || !t || !t->name[0]) { return; }
    char raw_key[64];const char *key=t->name;
    if(t->raw) {
        if(!t->raw_measure_request.generation || !d2k_rm_nonzero(t->raw_measure_request.epoch,16))return;
        raw_cooldown_key(raw_key,sizeof raw_key,t->raw_measure_request.epoch,t->raw_measure_request.generation);
        key=raw_key;
    }
    target_cooldown *c = cooldown_find(s, key, t->transport, t->family);
    if (!c) {
        c = cooldown_victim(s);
        memset(c, 0, sizeof *c);
        snprintf(c->name, sizeof c->name, "%s", key);
        c->transport = t->transport;
        c->family = t->family;
        c->used = 1;
    }
    /* Адрес — всегда последнего опыта: цель могла переехать. */
    snprintf(c->ip, sizeof c->ip, "%s", t->ip);
    c->port = t->port;
    c->trigger_shape = t->trigger_shape;
    c->ech_grease = t->ech_grease;
    c->grease_input = seed_input_of(t->trig,t->trig_len,NULL,0);
    cooldown_merge_tried(c, t);
    if (kind == 1 || kind == 4) {
        /* ВИД 4 — ЮРИДИЧЕСКИЙ ОТКАЗ СЕРВИСА (HTTP 451). Срок тот же, что у
           антибот-ответа, и признак `challenge` тот же, чтобы правила
           `cooldown_blocks` не раздваивались; отличается только слово в
           журнале, потому что это РАЗНЫЕ наблюдения и путать их нельзя.
           Поле 23.10.2026, x-minus.pro: без остывания тот же сервис
           перемерялся каждые пару минут (поиски 33 и 36 за 145 с, по 4 зонда
           и установке плана каждый) и каждый раз отвечал тем же 451. */
        c->challenge = 1;
        c->denied = kind == 4;
        c->exhausted = 0;
        c->late_rst_only = 0;
        c->until_ms = s->now_ms + SCHED_CHALLENGE_BACKOFF_MS;
        c->signal_code = t->trigger_code;
        return;
    }
    if (c->challenge && s->now_ms < c->until_ms) { return; }
    if (kind == 3) {
        /* Не ослаблять уже действующий общий запрет вида 2. */
        if (c->exhausted && !c->late_rst_only && s->now_ms < c->until_ms) { return; }
        kind = 2;
        c->late_rst_only = 1;
    } else {
        c->late_rst_only = 0;
    }
    if (kind == 2) {
        /* Incomplete/exhausted work is a different observation from a clean
           direct CLEAR. Cap retries at one fixed interval; do not inherit
           or advance the CLEAR 10/30/60-minute escalation. */
        c->negative_streak = 0;
        c->challenge = 0;
        c->denied = 0;
        c->exhausted = 1;
        c->ech_input = t->trig_snapped && t->transport == 6 &&
            d2k_hello_ech_offer(t->trig, t->trig_len, NULL) == 1;
        c->signal_code = t->trigger_code;
        c->until_ms = s->now_ms + SCHED_INCOMPLETE_BACKOFF_MS;
        return;
    }
    if (c->negative_streak < UINT8_MAX) { c->negative_streak++; }
    c->challenge = 0;
    c->denied = 0;   /* иначе позже причина читалась бы «юридический отказ» */
    c->exhausted = 0;
    c->signal_code = t->trigger_code;
    c->until_ms = s->now_ms + clear_backoff_ms(c->negative_streak);
}

/* Какое позднее закрытие пришло — для журнала; порог у них общий. */
static const char *late_close_what(uint8_t code) {
    return code == D2K_SUSPECT_FIN_RETRY ? "повтор FIN без ответа после ответа сервера"
         : code == D2K_SUSPECT_TCP_STALL ? "поток TCP встал на бюджете коробки, соединение открыто"
         : code == D2K_SUSPECT_LATE_SILENCE ? "поздняя тишина за окном очереди, соединение открыто"
                                         : "поздний RST после app-data";
}

/* Разброс бюджета один и тот же в датапате (полоса детектора) и в RX-примете
   объёма; полевой бюджет — тоже. Разойдутся — сборка остановится здесь. */
typedef char d2k_stall_slack_is_volume_slack
    [D2K_TCP_STALL_SLACK == D2K_VOLUME_PACKET_SLACK ? 1 : -1];
typedef char d2k_stall_field_is_verify_field
    [D2K_TCP_STALL_FIELD_BUDGET == D2K_BUDGET_FIELD_PACKETS ? 1 : -1];

/* Измеренный бюджет потока коробки (rx-volume, задача 55) — 0, если нет. */
static int box_stall_budget(const d2k_cat_box *b) {
    for (size_t i = 0; i < b->fp.n_sig; i++) {
        if (is_rx_volume_kind(b->fp.sig[i].kind) && b->fp.sig[i].packets > 0 &&
            b->fp.sig[i].packets <= 0xffff) {
            return b->fp.sig[i].packets;
        }
    }
    return 0;
}

static int budget_listed(const uint16_t *v, size_t n, int b) {
    for (size_t i = 0; i < n; i++) { if (v[i] == b) return 1; }
    return 0;
}

/* Бюджеты коробок, за которыми имя записано в каталоге (привязка по имени,
   TCP): коробка цели известна — полоса сверяется с её бюджетом. */
static size_t name_stall_budgets(const d2k_sched *s, const char *name, uint16_t *out,
                                 size_t cap) {
    size_t n = 0;
    for (size_t bi = 0; s->cat && bi < s->cat->n_boxes; bi++) {
        const d2k_cat_box *b = &s->cat->boxes[bi];
        int bud = box_stall_budget(b);
        if (!bud || budget_listed(out, n, bud)) continue;
        for (size_t i = 0; i < b->n_binds && n < cap; i++) {
            const d2k_cat_binding *bd = &b->binds[i];
            if (bd->enabled && !strcmp(bd->kind, "name") && !strcmp(bd->target, name) &&
                (bd->transport ? bd->transport : 6) == 6) {
                out[n++] = (uint16_t)bud;
                break;
            }
        }
    }
    return n;
}

/* «TCP встал на бюджете» (задача 56): датапат сверил оценку пакетов с
   бюджетами всех коробок; здесь — с бюджетом коробки ЭТОЙ цели, если он
   измерен. 1 — в полосе (или коробка цели не измерена). */
static int tcp_stall_in_name_band(d2k_sched *s, const char *name, const d2k_ev *ev) {
    uint16_t own[D2K_STALL_BUDGETS_MAX];
    size_t n = name_stall_budgets(s, name, own, D2K_STALL_BUDGETS_MAX);
    if (n == 0) return 1;
    for (size_t i = 0; i < n; i++) {
        if (ev->num + (uint32_t)D2K_TCP_STALL_SLACK >= own[i] &&
            ev->num <= (uint32_t)own[i] + (uint32_t)D2K_TCP_STALL_SLACK)
            return 1;
    }
    say(s, "по %s поток TCP встал на %u пакетах с данными — вне бюджета её коробки "
           "(%u ± %d): это не обрыв коробки, замер не запускаю",
        name, (unsigned)ev->num, (unsigned)own[0], D2K_TCP_STALL_SLACK);
    return 0;
}

/* Бюджеты для датапата: полевой (цели неизмеренных коробок) и измеренные
   бюджеты коробок каталога. Шлётся, только когда список изменился. */
static void stall_budgets_push(d2k_sched *s) {
    uint16_t v[D2K_STALL_BUDGETS_MAX];
    size_t n = 0;
    v[n++] = D2K_TCP_STALL_FIELD_BUDGET;
    for (size_t bi = 0; s->cat && bi < s->cat->n_boxes && n < D2K_STALL_BUDGETS_MAX; bi++) {
        int bud = box_stall_budget(&s->cat->boxes[bi]);
        if (bud && !budget_listed(v, n, bud)) v[n++] = (uint16_t)bud;
    }
    if (n == s->n_stall_sent && !memcmp(v, s->stall_sent, n * sizeof *v)) return;
    char err[160];
    if (d2k_link_set_stall_budgets(s->link_fd, v, n, err, sizeof err) != 0) {
        say(s, "бюджеты коробок датапату не отправились: %s", err);
        return;
    }
    memcpy(s->stall_sent, v, n * sizeof *v);
    s->n_stall_sent = n;
    char list[96] = "";
    for (size_t i = 0, o = 0; i < n && o < sizeof list; i++)
        o += (size_t)snprintf(list + o, sizeof list - o, "%s%u", i ? ", " : "", (unsigned)v[i]);
    say(s, "датапат: бюджеты потока для «TCP встал на бюджете» — %s пакетов (± %d)",
        list, D2K_TCP_STALL_SLACK);
}

static task *task_of(d2k_sched *s, const char *name, uint8_t transport, uint8_t family) {
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        if (s->tasks[i].state != T_FREE && s->tasks[i].transport == transport &&
            s->tasks[i].family == (family ? family : 4) &&
            strcmp(s->tasks[i].name, name) == 0) {
            return &s->tasks[i];
        }
    }
    return NULL;
}

static task *task_free_slot(d2k_sched *s) {
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        if (s->tasks[i].state == T_FREE) { return &s->tasks[i]; }
    }
    return NULL;
}

/* Задача, которая своё уже отдала: подтверждена и только смотрит на живой
   трафик (T_WATCHING). Её место уступается новому поиску, когда свободных не
   осталось: знание такой задачи ЛЕЖИТ В КАТАЛОГЕ, и потерять от её закрытия
   можно только последующее наблюдение — а отказ новому подозрению
   стоит целого поиска. До 12.09 этого выбора не было: подтверждённая задача
   освобождала место сразу. */
static task *task_watching_slot(d2k_sched *s) {
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        if (s->tasks[i].state == T_WATCHING) { return &s->tasks[i]; }
    }
    return NULL;
}

/* --------------------------------------------------------------------
 * Приветствия задачи: снятое, если есть; иначе профиль холодного старта.
 * -------------------------------------------------------------------- */

/* ФОРМА КЛИЕНТА ИЗ ПОДОЗРЕНИЯ — ИЗМЕРЕНИЕ, А НЕ ДОГАДКА.
 *
 * Датапат кладёт в подозрение форму приветствия ТОГО потока, из-за которого
 * оно возникло (trigger_shape). Снимок в общей ячейке — лишь последнее
 * приветствие этого ИМЕНИ, а у имени бывают клиенты разных форм: браузер
 * TLS 1.3 и программа обновления TLS 1.2. Поле 04.10.2026,
 * updates.discord.com: приложение говорило 179 байтами TLS 1.2 (форма 2 в
 * подозрении), а поиск шёл заготовкой TLS 1.3 — свой план формы 1.3, зонд
 * TLS 1.3, привязка формы 1 — и датапат отказывал потокам приложения по
 * форме. Байты, форма которых известна и расходится с формой клиента
 * подозрения, входом этого опыта не берутся; неизвестная форма с любой
 * стороны не противоречит. */
static uint8_t tcp_hello_kind(const uint8_t *b, size_t n) {
    return d2k_hello_ech_offer(b, n, NULL) == 1 ? (uint8_t)D2K_LINK_SHAPE_ECH_TCP
                                                : (uint8_t)d2k_hello_shape(b, n);
}

static int hello_fits_client(const task *t, const uint8_t *b, size_t n) {
    if (t->transport != 6) return 1;
    uint8_t want = t->trigger_shape;
    if (want != D2K_SHAPE_MODERN && want != D2K_SHAPE_LEGACY &&
        want != D2K_LINK_SHAPE_ECH_TCP) return 1;
    uint8_t got = tcp_hello_kind(b, n);
    return got == D2K_SHAPE_UNKNOWN || got == want;
}

/* ECH в приветствии пачки QUIC: собранный ClientHello оборачивается в
   заголовок записи TLS, чтобы его прочёл тот же разбор, что у TCP. */
static int quic_pack_ech(const uint8_t *b, size_t n) {
    d2k_qsnap pk;
    static __thread uint8_t rec[5 + SCHED_TRIG_MAX];
    size_t chl = 0;
    if (!d2k_qsnap_is(b, n) || d2k_qsnap_parse(b, n, &pk) != 0 ||
        d2k_qsnap_client_hello(&pk, rec + 5, sizeof rec - 5, &chl) != 0 ||
        chl == 0 || chl > 0xffff) return 0;
    rec[0] = 0x16; rec[1] = 0x03; rec[2] = 0x01;
    rec[3] = (uint8_t)(chl >> 8); rec[4] = (uint8_t)chl;
    return d2k_hello_ech_offer(rec, chl + 5, NULL) == 1;
}

static int quic_named_find(const d2k_sched *s, const char *name, uint8_t family) {
    for (size_t k = 0; k < sizeof s->quic_named / sizeof s->quic_named[0]; k++)
        if (s->quic_named[k].len && s->quic_named[k].family == family &&
            !strcmp(s->quic_named[k].name, name) &&
            s->quic_named[k].observed_ms + 600000 >= s->now_ms) return (int)k;
    return -1;
}

/* НЕСЁТ ЛИ ПОТОК КЛИЕНТА МЕТКУ ВРЕМЕНИ TCP (вид 8, длина 10).
 *
 * От этого зависит, исполним ли для него план с порчей «метка времени назад»:
 * датапат копирует опции потока и сдвигает метку в них, а если метки нет —
 * отказывается кодом FLOW_UNFIT (поле issue #7: ПК на Windows, 13 отказов из
 * 13 при работающих телефонах). Набор не снят — считаем, что метка есть: так
 * было всегда, и прежнее поведение сохраняется.
 *
 * Разбор побайтный, тот же, что у датапата и у зонда: NOP и EOL отдельно,
 * кривая длина — «нет». */
static int client_offers_ts(const task *t) {
    if (!t->client_opts_known) { return 1; }
    const uint8_t *o = t->client_opts;
    size_t n = t->client_opts_len;
    if (n > sizeof t->client_opts) { return 0; }
    for (size_t off = 0; off < n;) {
        uint8_t kind = o[off];
        if (kind == 0) { break; }
        if (kind == 1) { off++; continue; }
        if (off + 2 > n || o[off + 1] < 2 || o[off + 1] > n - off) { return 0; }
        if (kind == 8 && o[off + 1] == 10) { return 1; }
        off += o[off + 1];
    }
    return 0;
}

/* Набор опций клиента — задаче вместе со снимком (замысел 2026-10-23, п. 5.1). */
static void take_shape_opts(const d2k_sched *s, task *t) {
    int f = t->family == 6;
    t->client_opts_known = s->tcp_shape_opts_known[f];
    t->client_opts_len = t->client_opts_known ? s->tcp_shape_opts_len[f] : 0;
    if (t->client_opts_len) { memcpy(t->client_opts, s->tcp_shape_opts[f], t->client_opts_len); }
}
static void drop_client_opts(task *t) {
    t->client_opts_known = 0;
    t->client_opts_len = 0;
}

/* Приветствие профиля БЕЗ server_name: d2k_hello_from_profile не умеет пустое
   имя (и не должно — у именной цели оно обязательно), поэтому заготовка
   собирается с приманкой и расширение SNI вырезается d2k_hello_without_sni
   (та же единственная реализация, что у QUIC по адресу). Вход/выход —
   полная запись TLS, как у остальных приветствий задачи. */
static int hello_profile_without_sni(d2k_shape shape, uint8_t *out, size_t cap, size_t *out_len) {
    uint8_t rec[2048], body[2048];
    size_t rec_len = 0, body_len = 0;
    if (d2k_hello_from_profile(shape, SCHED_DECOY, rec, sizeof rec, &rec_len) != 0 ||
        rec_len <= 5 || rec[0] != 0x16 || cap < 5) {
        return -1;
    }
    if (d2k_hello_without_sni(rec + 5, rec_len - 5, body, sizeof body, &body_len) != 0 ||
        body_len == 0 || body_len > 0xFFFF || body_len + 5 > cap) {
        return -1;
    }
    out[0] = 0x16; out[1] = 0x03; out[2] = 0x01;
    out[3] = (uint8_t)(body_len >> 8); out[4] = (uint8_t)body_len;
    memcpy(out + 5, body, body_len);
    *out_len = body_len + 5;
    return 0;
}

static int fill_hellos(d2k_sched *s, task *t) {
    if (t->transport == 17) {
        /* Донор quicprobe.buildInitial начинает замер собственным QUIC
           Initial, не ожидая клиентского снимка. Голый TLS сюда не подходит;
           нужен законный зашифрованный Initial. Собственный вход остаётся
           PROFILE, а не CLIENT. Контроль пересобирается из того же входа
           с другим именем (core/quichello.c). */
        if (t->trig_len == 0) {
            if (t->by_addr) {
                /* Точный донорский режим для буквального IP: crypto/tls
                   создаёт новый ClientHello без SNI. Чужой снимок/его имя
                   сюда переносить нельзя, а IP нельзя кодировать как SNI. */
                if (d2k_quic_probe_initial(t->name, t->trig,
                                           sizeof t->trig, &t->trig_len) != 0) {
                    return -1;
                }
            } else {
            /* Снимка ЭТОЙ цели нет. Берём последний снятый у кого угодно и
               переписываем в нём имя: форма — свойство клиента, а не цели
               (см. quic_shape в структуре планировщика). Признак «форма
               измерена» НЕ ставится: измерена она не здесь. */
            int own = quic_named_find(s, t->name, t->family ? t->family : 4);
            if (own >= 0) {
                /* Пачка ЭТОГО имени за последние 10 минут — вход клиента. */
                memcpy(t->trig, s->quic_named[own].bytes, s->quic_named[own].len);
                t->trig_len = s->quic_named[own].len;
                t->trig_snapped = 1;
                say(s, "по %s мерю снятой пачкой этого имени (%zu байт%s)", t->name,
                    t->trig_len, s->quic_named[own].ech ? ", с ECH" : "");
            } else if (s->quic_shape_len[t->family == 6] > 0 &&
                strcmp(s->quic_shape_name[t->family == 6], t->name) == 0) {
                memcpy(t->trig, s->quic_shape[t->family == 6], s->quic_shape_len[t->family == 6]);
                t->trig_len = s->quic_shape_len[t->family == 6];
                t->trig_snapped = 1;
            } else if (s->quic_shape_len[t->family == 6] > 0 &&
                       d2k_qsnap_is(s->quic_shape[t->family == 6],
                                    s->quic_shape_len[t->family == 6])) {
                /* ЧУЖАЯ ПАЧКА ПОД ДРУГОЕ ИМЯ НЕ ПЕРЕСОБИРАЕТСЯ (задача 66).
                   Имя сидит внутри ClientHello, разложенного по нескольким
                   датаграммам: сменить его значит пересобрать весь полёт, и
                   это уже не форма клиента, а наша. Мерим собственным
                   Initial — честно и с пометкой PROFILE, пока не придёт
                   снимок этой цели. */
                if (d2k_quic_probe_initial(t->name, t->trig, sizeof t->trig,
                                           &t->trig_len) != 0) { return -1; }
                say(s, "по %s последний QUIC-снимок — пачка чужого имени, её не "
                       "переименовать; мерю собственным Initial (PROFILE)", t->name);
            } else if (s->quic_shape_len[t->family == 6] > 0) {
                int used_sample = 0;
                if (d2k_quic_prepare_target(s->quic_shape[t->family == 6], s->quic_shape_len[t->family == 6],
                                            t->name, t->trig, sizeof t->trig,
                                            &t->trig_len, &used_sample) != 0) {
                    return -1;
                }
                if (!used_sample) {
                    say(s, "по %s последний QUIC-снимок нельзя безопасно переименовать; использую измерительный PROFILE",
                        t->name);
                }
            } else {
                if (d2k_quic_probe_initial(t->name, t->trig, sizeof t->trig,
                                         &t->trig_len) != 0) { return -1; }
                say(s, "по %s начинаю замер собственным QUIC Initial (PROFILE, не снимок клиента)",
                    t->name);
            }
            }
        }
        if (t->ctrl_len == 0 && strcmp(t->name, SCHED_DECOY) != 0) {
            int control_rc = t->by_addr
                ? d2k_quic_probe_initial(SCHED_DECOY, t->ctrl,
                                         sizeof t->ctrl, &t->ctrl_len)
                : d2k_quic_hello_rename(t->trig, t->trig_len, SCHED_DECOY,
                                        t->ctrl, sizeof t->ctrl, &t->ctrl_len);
            if (control_rc != 0) {
                /* Вход цели не пересобирается под другое имя (обрывок
                   приветствия сюда уже не доходит — его отсекает on_shape).
                   Контроль тогда — собственный Initial донора с именем приманки, как
                   у ветки by_addr: донор контроль всегда строит сам
                   (quicprobe/probe.go:280-321). Пустой контроль превращал
                   опыт в INCONCLUSIVE «нет контрольного имени», и плечо не
                   подбиралось вовсе. Это PROFILE, а не снимок клиента, —
                   и так и названо в трассе. */
                t->ctrl_len = 0;
                if (d2k_quic_probe_initial(SCHED_DECOY, t->ctrl, sizeof t->ctrl,
                                           &t->ctrl_len) == 0) {
                    say(s, "по %s контроль — PROFILE: вход цели не пересобирается "
                           "под имя приманки", t->name);
                } else {
                    t->ctrl_len = 0;
                }
            }
        }
        return 0;
    }
    if (t->trig_len == 0) {
        for (size_t k = 0; k < 8; k++) {
            if (s->ech_inputs[k].len && s->ech_inputs[k].family == t->family &&
                s->ech_inputs[k].observed_ms + 600000 >= s->now_ms &&
                !strcmp(s->ech_inputs[k].name, t->name) &&
                hello_fits_client(t, s->ech_inputs[k].bytes, s->ech_inputs[k].len)) {
                memcpy(t->trig, s->ech_inputs[k].bytes, s->ech_inputs[k].len);
                t->trig_len = s->ech_inputs[k].len; t->trig_snapped = 1;
                t->client_opts_known = s->ech_inputs[k].opts_known;
                t->client_opts_len = t->client_opts_known ? s->ech_inputs[k].opts_len : 0;
                if (t->client_opts_len) memcpy(t->client_opts, s->ech_inputs[k].opts, t->client_opts_len);
                break;
            }
        }
    }
    if (t->trig_len == 0 && s->tcp_shape_len[t->family == 6] > 0 &&
        strcmp(s->tcp_shape_name[t->family == 6], t->name) == 0 &&
        s->tcp_shape_len[t->family == 6] <= sizeof t->trig &&
        hello_fits_client(t, s->tcp_shape[t->family == 6], s->tcp_shape_len[t->family == 6])) {
        /* Снимок ЭТОЙ цели пришёл раньше подозрения. Берём его: это настоящие
           байты клиента, а профиль холодного старта — заведомо не они. */
        memcpy(t->trig, s->tcp_shape[t->family == 6], s->tcp_shape_len[t->family == 6]);
        t->trig_len = s->tcp_shape_len[t->family == 6];
        t->trig_snapped = 1;
        take_shape_opts(s, t);
    }
    if (t->trig_len == 0) {
        drop_client_opts(t);
        /* Холодный старт: снимка ещё нет. Профиль — это заведомо НЕ те байты,
           что шлёт настоящий клиент (§4), и вердикт на нём слабее; но
           альтернатива — не измерять вовсе, пока цель не откроют второй раз.
           Снимок закажем параллельно (arm_shape ниже) и со следующего раза
           будем мерить уже им. Форма заготовки — форма клиента из
           подозрения (hello_fits_client): по ней выбираются свои планы,
           протокол зонда и форма привязки. Не сказана — MODERN: современный
           клиент — то, чем ходит браузер сегодня, и мерить им ближе к правде. */
        d2k_shape cold = t->transport == 6 && t->trigger_shape == D2K_SHAPE_LEGACY
                             ? D2K_SHAPE_LEGACY : D2K_SHAPE_MODERN;
        if (t->by_addr && t->transport == 6) {
            /* Адресная TCP-цель: имя не выдумывается — заготовка профиля
               собирается с приманкой и SNI из неё вырезается целиком
               (§4, §9.8). Форма клиента сохраняется. */
            if (hello_profile_without_sni(cold, t->trig, sizeof t->trig, &t->trig_len) != 0) {
                return -1;
            }
        } else if (d2k_hello_from_profile(cold, t->name,
                                   t->trig, sizeof t->trig, &t->trig_len) != 0) {
            return -1;
        }
    }
    if (t->ctrl_len == 0 && strcmp(t->name, SCHED_DECOY) != 0) {
        d2k_shape sh = d2k_hello_shape(t->trig, t->trig_len);
        if (d2k_hello_from_profile(sh, SCHED_DECOY,
                                   t->ctrl, sizeof t->ctrl, &t->ctrl_len) != 0) {
            t->ctrl_len = 0; /* контроль — законно пустой: дерево отвечает за это само */
        }
    }
    return 0;
}

/* --------------------------------------------------------------------
 * Рабочий поток: сетевой оракул.
 * -------------------------------------------------------------------- */

/* Аргумент рабочего потока — worker_arg, слот задачи в d2k_sched.wargs. */

d2k_vres d2k_sched_ech_baseline_result(const d2k_ver_result *baseline,
    d2k_vol_result *volume, const char *origin) {
    d2k_vres result = {0}; result.verdict = D2K_V_INCONCLUSIVE;
    if (volume) volume->rx_direct_complete = 0;
    if (!baseline) return result;
    if (baseline->fd < 0 || baseline->level == D2K_VER_CHALLENGE) {
        snprintf(result.reason, sizeof result.reason, "ECH: %.150s", baseline->reason);
    } else if (baseline->ech_accepted && baseline->name_ok == 1 &&
               baseline->level == D2K_VER_APPLICATION && baseline->body_complete) {
        result.verdict = D2K_V_CLEAR;
        if (volume) volume->rx_direct_complete = 1;
        snprintf(result.reason, sizeof result.reason,
            "прямой ECH witness %.80s завершён: HTTP %d, %llu байт",
            origin ? origin : "", baseline->status, (unsigned long long)baseline->body_bytes);
    } else {
        snprintf(result.reason, sizeof result.reason, "ECH witness не завершён: %.150s", baseline->reason);
    }
    return result;
}

/* Объёмный замер TCP-цели — один раз на задачу и вход (задача 30): повтор
   поиска с тем же приветствием (форма, длина), путём и адресом берёт исход
   уже выполненного замера; другой вход мерится заново. */
static void volume_account(d2k_sched *s, task *t, int probes) {
    if (probes <= 0) return;
    pthread_mutex_lock(&s->mu);
    t->ask_probes += probes;
    t->ask_base += probes;
    pthread_mutex_unlock(&s->mu);
}

static void worker_volume(d2k_sched *s, task *t, d2k_hello trig) {
    int tls12 = d2k_hello_shape(trig.bytes, trig.len) == D2K_SHAPE_LEGACY;
    int same_input = t->vol_done && t->vol_tls12 == tls12 && t->vol_wire == trig.len &&
                     t->vol_port == t->port && !strcmp(t->vol_ip, t->ip) &&
                     !strcmp(t->vol_path, t->measure_path);
    if (!same_input) {
        t->vol_measured = t->measure_path[0]
            ? d2k_sched_vol_path_hook(t->ip, t->port, t->name, t->port == 80,
                                     tls12, trig.len, s->measure_mark, t->measure_path)
            : d2k_sched_vol_hook(t->ip, t->port, t->name, t->port == 80,
                                tls12, trig.len, s->measure_mark);
        volume_account(s, t, t->vol_measured.probes);
        /* МЕРИТЬ БЫЛО НЕЧЕМ, А САМ ЭТОТ ХОСТ ПУТИ НЕ НАЗОВЁТ. Завершённый
           ответ меньше измеряемой полосы — не отрицание обрыва, а отсутствие
           измерения (rx_short). Подсказку из ответа зонд уже спросил; у хоста,
           который на любой путь отдаёт 403/401, её не будет никогда — ссылки
           собираются только из завершённого 2xx text/html. Остаётся то, что
           УЖЕ НАБЛЮДАЛОСЬ по этой цели (measure_alt, из памяти планировщика):
           один повтор по названной причине, не перебор. */
        if (!t->vol_measured.rx_cut && t->vol_measured.rx_short &&
            t->measure_alt[0] && strcmp(t->measure_alt, t->measure_path)) {
            say(s, "по %s по %s мерить было нечем (завершённый ответ %llu байт); "
                   "повторяю замер по уже наблюдавшемуся %s",
                t->name, t->measure_path[0] ? t->measure_path : "/",
                (unsigned long long)t->vol_measured.rx_short_bytes, t->measure_alt);
            d2k_vol_result alt = d2k_sched_vol_path_hook(t->ip, t->port, t->name,
                t->port == 80, tls12, trig.len, s->measure_mark, t->measure_alt);
            volume_account(s, t, alt.probes);
            /* Повтор принимается только ДОКАЗАННЫМ обрывом: второй путь, тоже
               ничего не измеривший, честного «бюджет не проверен» первого не
               отменяет — та же дисциплина, что у повтора внутри зонда. */
            if (alt.rx_cut) {
                t->vol_measured = alt;
                if (!t->vol_measured.measured_path[0]) {
                    snprintf(t->vol_measured.measured_path,
                             sizeof t->vol_measured.measured_path, "%s", t->measure_alt);
                }
            }
        }
        t->vol_done = 1;
        t->vol_tls12 = tls12;
        t->vol_wire = trig.len;
        t->vol_port = t->port;
        snprintf(t->vol_ip, sizeof t->vol_ip, "%s", t->ip);
        snprintf(t->vol_path, sizeof t->vol_path, "%s", t->measure_path);
        if (t->vol_measured.rx_reason[0]) {
            say(s, "по %s объёмный замер TLS %s, hello=%zu: TX %s; RX %s",
                t->name, tls12 ? "1.2" : "1.3", trig.len,
                t->vol_measured.reason, t->vol_measured.rx_reason);
        }
        /* ДАЛЬШЕ ВСЕ СПРАШИВАЮТ ПУТЬ, НА КОТОРОМ ОБРЫВ ДОКАЗАН. Зонд объёма
           мог доказать его ПОВТОРОМ по другому публичному пути имени (поле
           12.10.2026, style.sndcdn.com: на «/» завершённый 403 на 243 байта, а
           /css/soehne-*.css режется). Если кандидат и привязка останутся на
           «/», тот же короткий 403 придёт и под планом: доказанный обрыв не
           станет подтверждённым решением, а следующий эпизод начнёт заново с
           «/». Вход сохранённого замера переставляется туда же — результат
           снят ИМЕННО с этого пути, и считать его снятым с «/» значит мерить
           заново (vol_path, задача 30). */
        if (t->vol_measured.measured_path[0] &&
            strcmp(t->vol_measured.measured_path, t->measure_path)) {
            say(s, "по %s обрыв доказан по %s, а не по «/» — тем же путём идут "
                   "зонд кандидата и следующий замер",
                t->name, t->vol_measured.measured_path);
            snprintf(t->measure_path, sizeof t->measure_path, "%s",
                     t->vol_measured.measured_path);
            snprintf(t->vol_path, sizeof t->vol_path, "%s", t->measure_path);
        }
    }
    t->vol = t->vol_measured;
}

/* Обрыв объёма: 1 — результат задачи уже выложен, поток кончает работу. */
static int worker_volume_cut(d2k_sched *s, task *t) {
    if (t->vol.verdict != D2K_VOL_CUT && !t->vol.rx_cut) { return 0; }
    /* Объёмное измерение не даёт честного ответа на старые вопросы
       про имя/адрес: оборванный поток исказит их вердикт. Вместо этого
       записываем направленную улику и сразу идём к соответствующему
       кандидату; после его отказа общий перебор сохранится. */
    pthread_mutex_lock(&s->mu);
    memset(&t->res, 0, sizeof t->res);
    t->res.verdict = D2K_V_INCONCLUSIVE;
    if (t->vol.rx_cut && (!t->vol.rx_compressed_complete || t->vol.rx_wire_basis)) {
        /* Пакетный бюджет (поле 04.10, rua.gr): gzip оборван тоже, на том же
           числе пакетов — причину пишет сама проба. */
        snprintf(t->res.reason, sizeof t->res.reason, "%s", t->vol.reason);
    } else if (t->vol.rx_cut) {
        if (t->vol.rx_expected_kb > 0) {
            snprintf(t->res.reason, sizeof t->res.reason,
                     "identity-тело дважды оборвалось около %d/%d КБ, gzip завершился",
                     t->vol.rx_at_kb, t->vol.rx_expected_kb);
        } else {
            snprintf(t->res.reason, sizeof t->res.reason,
                     "chunked identity-тело дважды оборвалось около %d КБ, gzip завершился",
                     t->vol.rx_at_kb);
        }
    } else {
        snprintf(t->res.reason, sizeof t->res.reason,
                 "исходящая лестница оборвалась около %d КБ", t->vol.at_kb);
    }
    t->res_ready = 1;
    pthread_mutex_unlock(&s->mu);
    ssize_t ign = write(s->wake[1], "w", 1);
    (void)ign;
    return 1;
}

/* Хэш входа базового вопроса: байты приветствия, адрес и порт цели. */
static uint64_t seed_input_of(const uint8_t *bytes, size_t len, const char *ip, uint16_t port) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < len; i++) { h ^= bytes[i]; h *= 1099511628211ULL; }
    for (const char *c = ip; c && *c; c++) { h ^= (unsigned char)*c; h *= 1099511628211ULL; }
    h ^= port; h *= 1099511628211ULL;
    return h ^ len;
}

/* Приёмник хода — у потока, а не у задачи: сигнатуры пяти крючков измерителя
   не меняются, а ход идёт ровно из того потока, что ведёт задачу. */
typedef struct { d2k_sched *s; task *t; } progress_sink;
static __thread progress_sink g_progress_sink;
int d2k_sched_application_request(d2k_application_request *request) {
    if(!request)return -1;
    memset(request,0,sizeof *request);
    progress_sink *sink=&g_progress_sink;
    if(!sink->s || !sink->t)return 0;
    pthread_mutex_lock(&sink->s->mu);
    const task *t=sink->t;
    int available=!t->stop && t->report_id && t->port;
    if(available) {
        request->search_id=t->report_id;request->port=t->port;
        request->family=t->family;request->transport=t->transport;
        request->shape=t->asked_shape;request->by_addr=t->by_addr;
        request->ech=t->ech_offer;
        snprintf(request->ech_origin,sizeof request->ech_origin,"%s",t->ech_origin);
        snprintf(request->target,sizeof request->target,"%s",t->name);
        snprintf(request->ip,sizeof request->ip,"%s",t->ip);
        if(t->transport==6 && !t->by_addr) {
            request->doh=t->doh_path[0]!=0;
            request->doh_failure_query=request->doh?t->doh_failure_query:0;
            if(t->family==4 || t->family==6) {
                const d2k_application_control *controls=sink->s->direct_control[t->family==6];
                for(size_t i=0;i<2;i++) {
                    if(controls[i].family==t->family && strcmp(controls[i].name,t->name)) {
                        request->control=controls[i];break;
                    }
                }
            }
            snprintf(request->resource,sizeof request->resource,"%s",
                request->doh?t->doh_path:t->measure_path);
        }
    }
    pthread_mutex_unlock(&sink->s->mu);
    return available;
}
int d2k_sched_synthesis_retain(uint64_t generation,void *ctx,void (*release)(void *),
    d2k_synthesis_continuation_feedback feedback)
{
    progress_sink *k=&g_progress_sink;
    if(!k->s || !k->t || !generation || !ctx || !release)return 0;
    pthread_mutex_lock(&k->s->mu);
    int accepted=k->t->synthesis_context==NULL;
    if(accepted) {
        snprintf(k->t->synthesis_context_resource,sizeof k->t->synthesis_context_resource,
                 "%s",k->t->doh_path[0]?k->t->doh_path:k->t->measure_path);
        k->t->synthesis_context=ctx;k->t->synthesis_release=release;
        k->t->synthesis_feedback=feedback;k->t->synthesis_context_generation=generation;
    }
    pthread_mutex_unlock(&k->s->mu);
    return accepted;
}


void *d2k_sched_synthesis_take(void (*release)(void *),uint64_t *generation)
{
    progress_sink *k=&g_progress_sink;
    if(generation)*generation=0;
    if(!k->s || !k->t || !release || !generation)return NULL;
    void *ctx=NULL;int stale=0;
    pthread_mutex_lock(&k->s->mu);
    task *t=k->t;
    if(t->synthesis_context && t->synthesis_release==release) {
        ctx=t->synthesis_context;
        stale=strcmp(t->synthesis_context_resource,t->doh_path[0]?t->doh_path:t->measure_path)!=0;
        if(!stale)*generation=t->synthesis_context_generation;
        t->synthesis_context=NULL;t->synthesis_release=NULL;t->synthesis_feedback=NULL;
        t->synthesis_context_generation=0;t->synthesis_context_resource[0]=0;
    }
    pthread_mutex_unlock(&k->s->mu);
    if(stale){release(ctx);return NULL;}
    return ctx;
}

d2k_run_cache *d2k_sched_measure_cache(void) {
    return g_progress_sink.t ? &g_progress_sink.t->run_cache : NULL;
}
void d2k_sched_measure_trace(const char *line) {
    progress_sink *k = &g_progress_sink;
    if (!k->s || !k->t || !line) return;
    pthread_mutex_lock(&k->s->mu);
    say(k->s, "замер id=%llu %s %s:%u TCP: %s",
        (unsigned long long)k->t->report_id, k->t->name, k->t->ip,
        (unsigned)k->t->port, line);
    pthread_mutex_unlock(&k->s->mu);
}

void d2k_sched_progress_note(const char *question, int pass, int fail) {
    progress_sink *k = &g_progress_sink;
    if (!k->s || !k->t || !question) { return; }
    size_t n = strlen(question);
    if (n >= sizeof k->t->ask_question) {
        /* Обрезка по границе символа UTF-8: имена свойств — кириллица. */
        n = sizeof k->t->ask_question - 1;
        while (n > 0 && ((unsigned char)question[n] & 0xc0) == 0x80) { n--; }
    }
    pthread_mutex_lock(&k->s->mu);
    if (pass > 0) { k->t->ask_probes += pass; }
    if (fail > 0) { k->t->ask_probes += fail; }
    memcpy(k->t->ask_question, question, n);
    k->t->ask_question[n] = '\0';
    pthread_mutex_unlock(&k->s->mu);
}

/* Итог прогона измерителя — на счёт задачи (под s->mu). Ход мог недосчитать
   (ответное направление TCP хода не шлёт), но не пересчитать; max — страховка
   от падения карточки, если когда-нибудь пересчитает. */
static void ask_settle(task *t, int run_probes) {
    int fin = t->ask_base + (run_probes > 0 ? run_probes : 0);
    if (fin > t->ask_probes) t->ask_probes = fin;
}

/* Keep the exact search stack and answers while lending the slot to TCP.
 * The hook runs before a complete question, never between filter and data. */
static int sched_quic_yield(uint32_t *paused_ms) {
    progress_sink *k=&g_progress_sink;
    *paused_ms=0;
    if(!k->s || !k->t)return 0;
    d2k_sched *s=k->s;task *t=k->t;
    struct timespec begin,end;
    pthread_mutex_lock(&s->mu);
    if(t->stop){pthread_mutex_unlock(&s->mu);return -1;}
    if(!t->quic_yield_request){pthread_mutex_unlock(&s->mu);return 0;}
    clock_gettime(CLOCK_MONOTONIC,&begin);
    t->quic_yield_waiting=1;
    t->quic_wait_started_ms=t->quic_clock_ms;
    ssize_t ignored=write(s->wake[1],"w",1);(void)ignored;
    while(t->quic_yield_waiting && !t->stop)
        pthread_cond_wait(&s->question_cv,&s->mu);
    int stopped=t->stop;
    pthread_mutex_unlock(&s->mu);
    clock_gettime(CLOCK_MONOTONIC,&end);
    int64_t ns=(int64_t)(end.tv_sec-begin.tv_sec)*1000000000+end.tv_nsec-begin.tv_nsec;
    uint64_t ms=ns>0?((uint64_t)ns+999999)/1000000:0;
    *paused_ms=ms>UINT32_MAX?UINT32_MAX:(uint32_t)ms;
    return stopped?-1:0;
}

static void sched_quic_progress(const char *question, int probes) {
    d2k_sched_progress_note(question, probes, 0);
}

static int doh_measured_cut(const d2k_ver_result *r) {
    /* A partial valid DNS sequence is application evidence of a later cut,
       while its verifier level deliberately cannot claim durable success. */
    int query_cut=r->doh_replies>0 && r->doh_replies<r->budget_requests;
    return (r->level==D2K_VER_APPLICATION ||
            (r->level==D2K_VER_HANDSHAKE && query_cut)) &&
        (r->status==200 || (r->status==0 && query_cut)) && !r->body_complete &&
        r->budget==D2K_BUDGET_CUT && (r->budget_packets || query_cut) && !r->local_refusal &&
        !r->local_limit && !r->unsupported && (!r->budget_uncountable || query_cut) && !r->cloudflare_challenge;
}

d2k_application_synthesis_fn d2k_sched_application_synthesis_hook;
static d2k_ver_result verify_encrypted_dns(const task *,int,size_t,int,uint32_t,int);
static int worker_doh_synthesis(d2k_sched *s,task *t,d2k_hello trigger) {
    if(!d2k_sched_application_synthesis_hook || !t->doh_failure_query || !t->doh_path[0] ||
       t->stop || t->transport!=6 || t->by_addr || t->ech_offer ||
       d2k_hello_shape(trigger.bytes,trigger.len)!=D2K_SHAPE_MODERN)return 0;
    d2k_application_request request;
    if(d2k_sched_application_request(&request)!=1)return 0;
    request.shape=D2K_SHAPE_MODERN;
    d2k_vres result;
    int previous_probes=0;
next_application_question:
    memset(&result,0,sizeof result);result.verdict=D2K_V_INCONCLUSIVE;result.owns_search=1;
    int handled=d2k_sched_application_synthesis_hook(&request,trigger.len,SCHED_VERIFY_STEP_MS,
        s->measure_mark,&t->stop,&result);
    if(handled && result.protocol_response && !t->stop) {
        t->vol.rx_direct_complete=0;
        d2k_verify_budget_set(D2K_TCP_STALL_FIELD_BUDGET);
        d2k_ver_result direct=verify_encrypted_dns(t,-1,trigger.len,0,s->measure_mark,0);
        d2k_verify_budget_set(0);
        if(result.probes<INT_MAX)result.probes++;
        int ok=!t->stop && dns_application_proved(&direct) && direct.status==200 &&
            direct.doh_replies==direct.budget_requests && !dns_non_path_failure(&direct) &&
            !direct.cloudflare_challenge;
        result.verdict=ok?D2K_V_CLEAR:D2K_V_INCONCLUSIVE;
        result.protocol_response=0;
        if(ok) {
            t->doh_trial=0;t->vol.rx_cut=0;t->vol.rx_direct_complete=1;
            if(t->vol.verdict==D2K_VOL_CUT)t->vol.verdict=D2K_VOL_SHORT;
        }
        snprintf(result.reason,sizeof result.reason,"DoH direct confirmation: %.350s",direct.reason);
        unsigned deeper=!t->stop && direct.peer_authenticated && !dns_non_path_failure(&direct) &&
            doh_measured_cut(&direct) &&
            direct.budget_requests>request.doh_failure_query &&
            direct.doh_replies==direct.budget_requests-1 ? direct.budget_requests:0;
        d2k_verify_close(&direct);
        if(deeper) {
            /* This summary selects a longer owned question; it is not added
               to the model as an invented sequence of application events. */
            request.doh_failure_query=deeper;t->doh_failure_query=deeper;
            previous_probes=result.probes>INT_MAX-previous_probes?INT_MAX:previous_probes+result.probes;
            goto next_application_question;
        }
    }
    result.probes=result.probes>INT_MAX-previous_probes?INT_MAX:result.probes+previous_probes;
    pthread_mutex_lock(&s->mu);
    ask_settle(t,result.probes);
    if(!handled) {
        t->ask_base=t->ask_probes;
        pthread_mutex_unlock(&s->mu);return 0;
    }
    t->doh_synthesis_owned=1;t->res=result;t->res_ready=1;
    pthread_mutex_unlock(&s->mu);
    ssize_t ignored=write(s->wake[1],"w",1);(void)ignored;
    return 1;
}
static d2k_ver_result verify_encrypted_dns(const task *t,int fd,size_t wire,
    int tls12,uint32_t mark,int adaptive_tls) {
    if (t->dns_dot) {
        uint16_t version=adaptive_tls ? 0 : tls12 ? 0x0303 : 0x0304;
        if (t->dns_qtype)
            return d2k_verify_dot_question_on(fd,t->ip,t->port,t->name,SCHED_VERIFY_STEP_MS,
                version,mark,t->dns_question,t->dns_qtype);
        return d2k_verify_dot_on(fd,t->ip,t->port,t->name,SCHED_VERIFY_STEP_MS,version,mark);
    }
    if (t->dns_qtype)
        return d2k_verify_doh_question_on(fd,t->ip,t->port,t->name,SCHED_VERIFY_STEP_MS,
            wire,adaptive_tls ? -1 : tls12,mark,t->doh_path,t->dns_question,t->dns_qtype);
    return d2k_verify_doh_on(fd,t->ip,t->port,t->name,SCHED_VERIFY_STEP_MS,
        wire,adaptive_tls ? -1 : tls12,mark,t->doh_path);
}

static int worker_doh_repeat_cut(d2k_sched *s,task *t,d2k_hello trigger,d2k_ver_result *dns) {
    if(t->dns_dot || t->stop || !dns->peer_authenticated || !doh_measured_cut(dns))return 0;
    unsigned first=dns->budget_packets;
    unsigned first_query=dns->budget_requests;
    unsigned first_replies=dns->doh_replies;
    d2k_verify_close(dns);
    d2k_verify_budget_set(D2K_TCP_STALL_FIELD_BUDGET);
    *dns=verify_encrypted_dns(t,-1,trigger.len,
        d2k_hello_shape(trigger.bytes,trigger.len)==D2K_SHAPE_LEGACY,s->measure_mark,0);
    d2k_verify_budget_set(0);
    unsigned second=dns->budget_packets;
    if(t->stop || !dns->peer_authenticated || !doh_measured_cut(dns))return 0;
    int packet_repeat=first && second && !dns->budget_uncountable &&
        (first>second?first-second:second-first)<=3;
    int query_repeat=first_query>1 && first_replies==first_query-1 &&
        dns->budget_requests>1 && dns->doh_replies==dns->budget_requests-1;
    if(!packet_repeat && !query_repeat)return 0;
    t->vol.rx_cut=1;t->vol.rx_wire_basis=packet_repeat;
    t->doh_failure_query=first_query>dns->budget_requests?first_query:dns->budget_requests;
    t->vol.rx_cut_packets=packet_repeat?(int)(first<second?first:second):0;
    if(packet_repeat)snprintf(t->vol.reason,sizeof t->vol.reason,
        "DoH HTTP/2: два обрыва после %u/%u пакетов с данными",first,second);
    else snprintf(t->vol.reason,sizeof t->vol.reason,
        "DoH: отказы запросов %u/%u; порог пакетов неизвестен (%u/%u)",
        first_query,dns->budget_requests,first,second);
    snprintf(t->vol.rx_reason,sizeof t->vol.rx_reason,"%s",t->vol.reason);
    return 1;
}
static int worker_protocol_response(d2k_sched *s,task *t,d2k_hello trigger,d2k_vres *r) {
    r->verdict=D2K_V_INCONCLUSIVE;r->program_len=0;r->program[0]=0;r->have_arm=0;
    t->vol.rx_direct_complete=0;
    if(t->stop) {
        snprintf(r->reason,sizeof r->reason,"проверка приложения остановлена после прямого TLS-ответа");return 0;
    }
    if(t->transport!=6 || t->ech_offer || t->by_addr) {
        snprintf(r->reason,sizeof r->reason,
                 "прямой TLS-ответ получен; для этого контекста нужен отдельный прикладной проверяющий");return 0;
    }
    if(!encrypted_dns_task(t)) {
        d2k_shape shape=d2k_hello_shape(trigger.bytes,trigger.len);
        if(!t->measure_path[0] || (shape!=D2K_SHAPE_MODERN && shape!=D2K_SHAPE_LEGACY)) {
            snprintf(r->reason,sizeof r->reason,
                     "прямой TLS-ответ получен; HTTP-контекст или TLS-форма не установлены");return 0;
        }
        int need_volume=is_late_volume_suspicion(t->trigger_code) || t->vol.rx_cut ||
                        t->vol.verdict==D2K_VOL_CUT;
        d2k_verify_budget_set(need_volume?D2K_TCP_STALL_FIELD_BUDGET:0);
        d2k_ver_result http=d2k_sched_path_ver_hook(-1,t->ip,t->port,t->name,
            SCHED_VERIFY_STEP_MS,trigger.len,shape==D2K_SHAPE_LEGACY,0,
            s->measure_mark,t->measure_path);
        d2k_verify_budget_set(0);
        int local=http.local_refusal || http.local_limit || http.unsupported || http.budget_uncountable;
        int ok=!t->stop && !local && http.level==D2K_VER_APPLICATION && http.body_complete &&
               http.status>=200 && http.status<300 && http.budget!=D2K_BUDGET_CUT &&
               (!need_volume || http.budget==D2K_BUDGET_PASSED);
        t->vol.rx_direct_complete=ok;
        if(ok)r->verdict=D2K_V_CLEAR;
        snprintf(r->reason,sizeof r->reason,"прямая проверка HTTPS по известному пути: %.300s",http.reason);
        d2k_verify_close(&http);return 0;
    }
    d2k_verify_budget_set(D2K_TCP_STALL_FIELD_BUDGET);
    d2k_ver_result dns=verify_encrypted_dns(t,-1,trigger.len,
        d2k_hello_shape(trigger.bytes,trigger.len)==D2K_SHAPE_LEGACY,s->measure_mark,0);
    d2k_verify_budget_set(0);
    if(worker_doh_repeat_cut(s,t,trigger,&dns)) {
        t->doh_checked=1;t->doh_trial=1;
        d2k_verify_close(&dns);
        if(worker_doh_synthesis(s,t,trigger))return 1;
        return worker_volume_cut(s,t);
    }
    int local=dns_non_path_failure(&dns);
    int ok=!t->stop && !local && dns_application_proved(&dns);
    t->doh_checked=1;t->doh_trial=!ok && !local &&
        (dns.budget==D2K_BUDGET_CUT || dns.status==0 || (dns.status==200 && !dns.body_complete));
    t->vol.rx_direct_complete=ok;
    if(ok)r->verdict=D2K_V_CLEAR;
    snprintf(r->reason,sizeof r->reason,"прямая проверка DoH после TLS-ответа: %.300s",dns.reason);
    d2k_verify_close(&dns);
    return 0;
}

static int plain_trial_allowed(void *context) {
    task *t=context;
    d2k_sched *s=t->worker_owner;
    pthread_mutex_lock(&s->mu);
    int allowed=!t->stop;
    pthread_mutex_unlock(&s->mu);
    return allowed;
}

static void *worker_run(void *vp) {
    worker_arg *a = (worker_arg *)vp;
    d2k_sched *s = a->s;
    task *t = a->t;
    int a_use_fd = a->use_fd;
    int a_split_unfit = a->split_unfit;
    unsigned a_budget = a->budget;
    /* КОПИЯ ВХОДА — РАЗМЕРОМ С ВХОД. Вход QUIC — пачка датаграмм клиента до
       SCHED_TRIG_MAX байт (задача 66), и копия на 2048 переполняла стек
       потока на первой же пачке Chrome (2508 байт): поле 15.10.2026,
       контроллер умирал молча, ровно на «начинаю поиск». */
    uint8_t trigger_bytes[sizeof a->trig], control_bytes[sizeof a->ctrl];
    memcpy(trigger_bytes, a->trig, a->trig_len);
    memcpy(control_bytes, a->ctrl, a->ctrl_len);
    uint8_t opts_bytes[sizeof a->client_opts];
    memcpy(opts_bytes, a->client_opts, a->client_opts_len);
    d2k_hello trig = {trigger_bytes, a->trig_len, opts_bytes, a->client_opts_len,
                      a->client_opts_known, a->trig_snapped};
    d2k_hello ctl = {a->ctrl_len ? control_bytes : NULL, a->ctrl_len, NULL, 0, 0, 0};
    /* Слот прочитан: дальше поток его не трогает. */
    pthread_mutex_lock(&s->mu);
    s->memory.worker_args_freed++;
    pthread_mutex_unlock(&s->mu);
    /* Ход сообщает только прогон измерителя (JOB_CLASSIFY); поток живёт ровно
       одну задачу, поэтому снимать приёмник не нужно. */
    if (t->job == JOB_CLASSIFY) {
        t->doh_synthesis_owned=0;
        g_progress_sink.s = s;
        g_progress_sink.t = t;
    }

    if (t->job == JOB_STUN || t->job == JOB_STUN_TRIAL) {
        /* Same direct-probe wait as the existing STUN control. A single
           timeout remains inconclusive, never a blocking verdict. */
        d2k_stun_probe_opt opt = {t->ip, t->port, 3000, s->measure_mark};
        d2k_stun_probe_res r = t->job == JOB_STUN_TRIAL ?
            d2k_sched_stun_run_hook(t->stun_socket) : d2k_sched_stun_hook(&opt);
        pthread_mutex_lock(&s->mu);
        t->stun_res = r;
        t->res_ready = 1;
        pthread_mutex_unlock(&s->mu);
        ssize_t ignored = write(s->wake[1], "w", 1);
        (void)ignored;
        return NULL;
    }

    if (t->job == JOB_VOICE) {
        d2k_voice_opt opt;
        memset(&opt, 0, sizeof opt);
        opt.mark = s->measure_mark;
        opt.discovery = strcmp(t->name, "@discord-voice") == 0;
        opt.known_discovery_prefix = t->voice_known_prefix_valid ? t->voice_known_prefix : NULL;
        memcpy(&opt.flow_ip_a, t->voice_flow.a_ip, sizeof opt.flow_ip_a);
        opt.flow_port_a = t->voice_flow.a_port;
        memcpy(&opt.flow_ip_b, t->voice_flow.b_ip, sizeof opt.flow_ip_b);
        opt.flow_port_b = t->voice_flow.b_port;
        d2k_voice_res vr = d2k_sched_voice_hook(&opt);
        pthread_mutex_lock(&s->mu);
        t->voice_res = vr;
        t->res_ready = 1;
        pthread_mutex_unlock(&s->mu);
        ssize_t ign = write(s->wake[1], "w", 1);
        (void)ign;
        return NULL;
    }

    if(t->job==JOB_DNS_PLAIN_PREPARE || t->job==JOB_DNS_PLAIN_RUN) {
        d2k_ver_result dns=t->ver;
        if(t->job==JOB_DNS_PLAIN_PREPARE) {
            char fallback[256];
            const char *question=t->dns_question;
            uint16_t type=t->dns_qtype;
            if(!type) {
                type=d2k_dns_probe_question_name(t->name,fallback);
                question=fallback;
            }
            dns=s->plain_prepare(t->ip,t->port,t->dns_plain,question,type,
                SCHED_VERIFY_STEP_MS,s->mark,&t->plain_request);
        } else {
            s->plain_run(&t->plain_request,SCHED_VERIFY_STEP_MS,plain_trial_allowed,t,&dns);
        }
        pthread_mutex_lock(&s->mu);t->ver=dns;t->res_ready=1;pthread_mutex_unlock(&s->mu);
        ssize_t ignored=write(s->wake[1],"w",1);(void)ignored;
        return NULL;
    }
    if(t->job==JOB_DOH_HEALTH) {
        /* Match the real router DNS route. Candidate-verifier privilege
         * would mask a still-protected ordinary DNS flow. */
        d2k_ver_result dns;
        if (t->dns_plain) {
            char question[256];
            uint16_t type=t->dns_qtype;
            const char *name=t->dns_question;
            if (!type) {
                type=d2k_dns_probe_question_name(t->name,question);
                name=question;
            }
            dns=d2k_verify_plain_dns_on(t->ip,t->port,t->dns_plain,
                type ? name : NULL,type,SCHED_VERIFY_STEP_MS,0);
        } else {
            d2k_verify_budget_set(D2K_TCP_STALL_FIELD_BUDGET);
            dns=verify_encrypted_dns(t,-1,trig.len,0,0,1);
            d2k_verify_budget_set(0);
        }
        pthread_mutex_lock(&s->mu);t->ver=dns;t->res_ready=1;pthread_mutex_unlock(&s->mu);
        ssize_t ignored=write(s->wake[1],"w",1);(void)ignored;
        return NULL;
    }
    if (t->job == JOB_VERIFY) {
        uint8_t verification_trial_id[D2K_TRIAL_ID_LEN];
        memcpy(verification_trial_id,t->trial_ack_id,sizeof verification_trial_id);
        /* Испытание кандидата: своё рукопожатие TLS 1.3 своим ключом и
           настоящий запрос (d2k_verify.h). Блокирует НА СЕКУНДЫ — потому и
           живёт в рабочем потоке: цикл d2kc не блокируется никогда.
           Сокет остаётся ОТКРЫТЫМ: закроет его цикл, после решения (см.
           d2k_props_contact о том, что FIN удаляет ячейку потока раньше
           события применения). */
        /* Длина приветствия КЛИЕНТА — та, которой зонд добьёт своё. Это
           снимок с провода, когда он есть, и профиль холодного старта, когда
           снимка ещё нет; и то и другое — приветствие настоящего клиента, а
           не наше минимальное. Без этого испытание идёт в ДРУГОМ контексте,
           чем работа человека, и «подтверждено» достаётся зонду. */
        /* Сокет зонда занят заранее (install_next), и план поставлен именно
           под его порт: зонд обязан пойти С НЕГО, иначе испытание пройдёт
           мимо собственного плана. Владение отдаётся вниз — закроет тот, кто
           им распорядится. */
        int layered_rx = !encrypted_dns_task(t) &&
            (t->res.program_len || (t->vol.rx_tls_unavailable &&
             (t->res.verdict == D2K_V_OPAQUE || t->rx_bootstrap_only || t->own_first == 2))) &&
            d2k_hello_shape(t->trig, t->trig_len) == D2K_SHAPE_MODERN;
        d2k_sched_ver_fn verifier = t->rx_phase == 2 ? d2k_sched_rx_gzip_ver_hook :
                                   t->transport == 6 && (t->vol.rx_cut || layered_rx)
                                  ? d2k_sched_rx_ver_hook : d2k_sched_ver_hook;
        d2k_ver_result vr;
        uint8_t alpn[256];
        size_t alpn_len = 0;
        /* Проверка бюджета потока (задача 55) — поточная настройка зонда:
           подписи крючков зонда не меняются. Снимается сразу после. */
        d2k_verify_budget_set(a_budget);
        /* ФОРМА КЛИЕНТА ДЛЯ ЗОНДА QUIC (задача 66): когда вход замера — пачка
           снятых датаграмм, собственный полёт зонда идёт тем же числом
           датаграмм той же длины. Иначе план, снятый с двухдатаграммного
           приветствия, подтверждался бы одиночным — вопросом, которого
           клиент не задавал. */
        d2k_quic_form a_form;
        int a_form_ok = 0;
        if (t->transport == 17 && d2k_qsnap_is(trig.bytes, trig.len)) {
            d2k_qsnap a_pack;
            a_form_ok = d2k_qsnap_parse(trig.bytes, trig.len, &a_pack) == 0 &&
                        d2k_qsnap_form(&a_pack, &a_form) == 0;
        }
        d2k_verify_quic_form_set(a_form_ok ? &a_form : NULL);
        if (t->transport == 17 && t->quic_ech) {
            /* QUIC с ECH: свой клиент ECH не повторит — кандидат проверяется
               повтором пачки клиента под планом. */
            vr = d2k_sched_quic_replay_ver_hook(a_use_fd, t->ip, t->port, trig.bytes,
                                                trig.len, SCHED_VERIFY_STEP_MS);
        } else if (t->transport == 6 && t->ech_offer && t->ech_replay) {
            /* Свидетеля нет: кандидат проверяется теми же байтами клиента. */
            vr = d2k_sched_replay_ver_hook(a_use_fd, t->ip, t->port, trig.bytes, trig.len,
                                           SCHED_VERIFY_STEP_MS);
        } else if (t->transport == 6 && t->by_addr) {
            /* Адресная TCP-цель: зонд без SNI доводит TLS до завершённого
               рукопожатия с ALPN клиента, если тот его предлагал. Это
               доказательство TLS-этапа, не приложения (§4.2, §9.8): HTTP на
               адрес без имени — догадка о протоколе, её не делаем. */
            if (d2k_hello_shape(t->trig, t->trig_len) == D2K_SHAPE_LEGACY) {
                /* Клиент TLS 1.2 без имени: тем же протоколом (этап 15) —
                   рукопожатие 1.2 без server_name до Finished сервера; TLS 1.3
                   вместо 1.2 не подставляется (§4). Доказательство — TLS-этап. */
                vr = d2k_sched_ver12hs_hook(a_use_fd, t->ip, t->port, "",
                                            SCHED_VERIFY_STEP_MS, trig.len);
            } else {
                if (d2k_hello_alpn(t->trig, t->trig_len, alpn, sizeof alpn, &alpn_len) != 0) {
                    alpn_len = 0;
                }
                vr = d2k_sched_alpn_ver_hook(a_use_fd, t->ip, t->port, "",
                                             SCHED_VERIFY_STEP_MS, trig.len, alpn, alpn_len);
            }
        } else if (client_alpn_nonhttp(t, alpn, sizeof alpn, &alpn_len)) {
            vr = d2k_sched_alpn_ver_hook(a_use_fd, t->ip, t->port, t->name,
                                         SCHED_VERIFY_STEP_MS, trig.len, alpn, alpn_len);
        } else if (t->transport == 6 && t->ech_offer) {
            /* Прошлый свидетель ответил страницей проверки: следующего —
               здесь, в рабочем потоке (вопрос HTTPS RR не держит главный).
               Не нашёлся — объём не измерить: кандидат не подтверждается. */
            int picked = !t->ech_exhausted;
            if (picked && t->ech_reselect) {
                char was[sizeof t->ech_origin];
                snprintf(was, sizeof was, "%s", t->ech_origin);
                t->ech_reselect = 0;
                t->ech_origin[0] = 0;
                picked = ech_pick_witness(s, t, 1, 0);
                if (!picked) {
                    snprintf(t->ech_origin, sizeof t->ech_origin, "%s", was);
                    pthread_mutex_lock(&s->mu);
                    t->ech_exhausted = 1;
                    pthread_mutex_unlock(&s->mu);
                }
            }
            if (picked) {
                vr = d2k_verify_probe_ech_origin_on(a_use_fd, t->ip, t->port,
                    t->name, t->ech_origin, SCHED_VERIFY_STEP_MS, trig.len,
                    s->measure_mark, NULL);
            } else {
                if (a_use_fd >= 0) close(a_use_fd);
                memset(&vr, 0, sizeof vr);
                vr.fd = -1;
                vr.level = D2K_VER_HANDSHAKE;
                snprintf(vr.reason, sizeof vr.reason, "свидетеля ECH без страницы проверки "
                         "не осталось — объём ответа не измерить");
            }
        } else if (encrypted_dns_task(t)) {
            vr=verify_encrypted_dns(t,a_use_fd,trig.len,
                d2k_hello_shape(t->trig,t->trig_len)==D2K_SHAPE_LEGACY,0,0);
        } else if (t->transport == 6 && t->measure_path[0]) {

            int encoding = t->rx_phase == 2 ? 1 : 0;
            vr = d2k_sched_path_ver_hook(a_use_fd, t->ip, t->port, t->name,
                SCHED_VERIFY_STEP_MS, trig.len,
                d2k_hello_shape(t->trig, t->trig_len) == D2K_SHAPE_LEGACY,
                encoding, 0, t->measure_path);
        } else if (t->transport == 17 && t->measure_path[0]) {
            /* For QUIC `verifier` is always d2k_sched_ver_hook: rx_phase
               moves only in layered_rx_result, which requires a modern TLS
               hello shape -- a QUIC Initial never has one -- and the RX hook
               is chosen only for transport 6. No further condition needed. */
            vr = d2k_sched_quic_path_ver_hook(a_use_fd, t->ip, t->port, t->name,
                SCHED_VERIFY_STEP_MS, trig.len, t->measure_path);
        } else vr = (t->gate_active ? d2k_sched_preflight_ver_hook : verifier)(a_use_fd, t->ip, t->port, t->transport,
                                               t->name, SCHED_VERIFY_STEP_MS,
                                               trig.len,
                                               (uint8_t)(t->transport == 17
                                                         ? D2K_SHAPE_UNKNOWN
                                                         : d2k_hello_shape(t->trig, t->trig_len)));
        if(encrypted_dns_task(t) && vr.level==D2K_VER_APPLICATION &&
           vr.budget!=D2K_BUDGET_PASSED && vr.budget!=D2K_BUDGET_CUT) {
            vr.level=D2K_VER_HANDSHAKE;
            if(vr.budget_uncountable)vr.local_limit=1;
            snprintf(vr.reason,sizeof vr.reason,"DoH: постоянное соединение не проверено");
        }
        /* ПОДТВЕРЖДЕНИЕ ПЛАНА QUIC — ТЕМ ЖЕ ЧИСЛОМ ПОВТОРОВ, ЧТО У ПЛЕЧА (поле
           24.10.2026, h3-1024). Плечо засчитывается D2K_QUIC_REPEATS ответами
           из D2K_QUIC_REPEATS, а план подтверждался одним зондом: «quic5 ×11»
           прошёл один раз и лёг на rutracker.org, kinozal.me, nnmclub.to — у
           клиента 1 из 3 (pcap: сервер ответил на фальшивку, а не на настоящий
           Initial), у плеча nnmclub тот же приём — «1/3, неустойчиво». Повторы
           идут с того же сокета (план поставлен под его порт) новым
           соединением каждый, без бюджета — он измерен первым зондом. Повтор
           пачки клиента (ECH) — один по природе, его не трогаем. */
        if (t->transport == 17 && !t->quic_ech && vr.level >= D2K_VER_APPLICATION &&
            !vr.unsupported && !vr.local_refusal && vr.budget != D2K_BUDGET_CUT) {
            /* Повторяется только то, что первым зондом прошло целиком: план,
               отвергнутый бюджетом или не измеренный, повторять нечем. */
            d2k_verify_budget_set(0);
            for (int rep = 2; rep <= D2K_QUIC_REPEATS; rep++) {
                int fd = vr.fd;
                vr.fd = -1;
                d2k_ver_result again = t->measure_path[0]
                    ? d2k_sched_quic_path_ver_hook(fd, t->ip, t->port, t->name,
                                                   SCHED_VERIFY_STEP_MS, trig.len,
                                                   t->measure_path)
                    : verifier(fd, t->ip, t->port, 17, t->name, SCHED_VERIFY_STEP_MS,
                               trig.len, (uint8_t)D2K_SHAPE_UNKNOWN);
                if (again.level < D2K_VER_APPLICATION) {
                    char why[sizeof again.reason];
                    snprintf(why, sizeof why, "%s", again.reason);
                    /* Обрезка причины задумана: это текст диагностики. */
                    if (snprintf(again.reason, sizeof again.reason,
                                 "повтор %d из %d не прошёл: %.160s", rep, D2K_QUIC_REPEATS,
                                 why) < 0) { again.reason[0] = '\0'; }
                    vr = again;
                    break;
                }
                /* Бюджет и причина — первого зонда, сокет — последнего. */
                vr.fd = again.fd;
            }
            if (vr.level >= D2K_VER_APPLICATION) {
                size_t n = strlen(vr.reason);
                if (n < sizeof vr.reason)
                    snprintf(vr.reason + n, sizeof vr.reason - n,
                             "; воспроизведено %d/%d новыми соединениями",
                             D2K_QUIC_REPEATS, D2K_QUIC_REPEATS);
            }
        }
        d2k_verify_budget_set(0);
        d2k_verify_quic_form_set(NULL);

        pthread_mutex_lock(&s->mu);
        t->ver = vr;
        memcpy(t->synthesis_ver_trial_id,verification_trial_id,sizeof verification_trial_id);
        t->res_ready = 1;
        pthread_mutex_unlock(&s->mu);
        ssize_t ignv = write(s->wake[1], "w", 1);
        (void)ignv;
        return NULL;
    }

    if (t->job == JOB_CONTACT) {
        /* Keep the reserved, controller-marked socket open until the reply
           is judged. Its mark selects the probe queue, not the raw bypass. */
        uint8_t local_addr[16] = {0};
        uint16_t lport = 0;
        int fd = -1;
        int rc = d2k_props_contact_on_family(a_use_fd, t->ip, t->port, trig,
                                             t->family, local_addr, &lport, &fd);
        pthread_mutex_lock(&s->mu);
        memcpy(t->c_ip, local_addr, sizeof t->c_ip);
        t->c_port = lport;
        t->c_fd = fd;
        t->c_ok = (rc == 0);
        t->res_ready = 1;
        pthread_mutex_unlock(&s->mu);
        ssize_t ign = write(s->wake[1], "w", 1);
        (void)ign;
        return NULL;
    }

    /* ПОРЯДОК ДОНОРА (задача 30, D2K_SPEC §2). «Поиск по домену» z2k сразу
       задаёт вопросы классификатора; объём (TransferProbe) там — отдельный
       вопрос (-transfer, tcp16). Поэтому обычный TCP-поиск сначала
       классифицирует, и лишь вердикт CLEAR (рукопожатие и запись проходят)
       открывает два направленных измерения: лестницу исходящего запроса
       (TX-класс) и парные identity/gzip GET (обрыв ВХОДЯЩЕГО тела). До
       классификации объём идёт только там, где он и есть вопрос: поздний
       RST (rx_volume_only) и база собственного плана другого семейства
       (family_reuse == 1). Поле 02.10.2026: объём первым ждал 14–20 с
       таймаута «нет TLS» на целях, режущихся на рукопожатии. QUIC сюда не
       попадает. */
    if (t->transport == 6 && t->addr_recheck && d2k_sched_tcp_ack_hook && !t->stop) {
        /* ЗАДАЧА 54, I2. Перепроверка адреса с вердиктом address — ПЕРВЫМ
           вопросом, до любого зонда с триггером (база, свои планы, дерево):
           коробка, которая наказывает адрес за увиденный триггер, иначе
           выглядела бы мёртвым адресом. Один байт, без имени. */
        int probes = 0;
        int rc = d2k_sched_tcp_ack_hook(t->ip, t->port, s->measure_mark, &t->stop, &probes);
        pthread_mutex_lock(&s->mu);
        t->addr_recheck = 0;
        t->addr_ack = rc > 0 ? 1 : rc == 0 ? 2 : 0;
        if (rc == 0) {
            memset(&t->res, 0, sizeof t->res);
            t->res.verdict = D2K_V_ADDRESS;
            snprintf(t->res.reason, sizeof t->res.reason,
                     "перепроверка: сервер по-прежнему не подтверждает нейтральный байт "
                     "(0 из 3), триггеров в этот раз не было");
            ask_settle(t, probes);
            t->res_ready = 1;
            pthread_mutex_unlock(&s->mu);
            ssize_t ign_ack = write(s->wake[1], "w", 1); (void)ign_ack;
            return NULL;
        }
        pthread_mutex_unlock(&s->mu);
        if (rc > 0) {
            say(s, "по %s адрес %s принял нейтральный байт — вердикт address снят: прежнее "
                   "молчание вызывал триггер; иду обычным путём", t->name, t->ip);
        } else {
            say(s, "по %s нейтральный байт перепроверки адреса %s не измерен (локальная "
                   "ошибка или подтверждение TCP не наблюдается) — вердикт address не "
                   "подтверждён и не снят, перепроверка идёт обычным путём", t->name, t->ip);
        }
    }
    if (t->transport == 6 && t->ech_offer && !t->ech_replay) {
        /* НАСТОЯЩИЙ ECH ИЛИ GREASE (задача 41). По байтам они неотличимы
         * намеренно (RFC 9849 §6.2): Chromium/Electron без ECHConfig шлёт
         * расширение со случайными config_id, enc и payload. Отличает их
         * имя снаружи: у настоящего ECH это public_name конфигурации, у
         * GREASE — само имя цели. Доказательство «внешнее имя — public_name»
         * берётся только из своего знания: подтверждённая ECH-привязка этого
         * имени, HTTPS RR самого имени или известного свидетеля. Каждый
         * запрос HTTPS RR ограничен (d2k_ech_resolve: ≤1,5 с), ответы
         * помнятся между поисками (ech_rr), и отказ DNS не держит поиск: без
         * доказательства — GREASE и обычный путь по имени. Пока ECH не
         * доказан HTTPS RR самого имени, новых вопросов о свидетелях не
         * больше четырёх: GREASE шлёт почти каждый Chromium, и широкий
         * перебор задержал бы ему обычный поиск, ничего не сообщив;
         * доказанному настоящему ECH свидетель нужен — там весь список. */
        int real = t->ech_origin[0] != 0; /* своя подтверждённая ECH-привязка имени */
        if (t->ech_origin[0]) {
            d2k_ech_config cfg;
            if (d2k_sched_ech_resolve_hook(t->ech_origin, s->measure_mark, &cfg) ||
                strcmp(cfg.public_name, t->name)) t->ech_origin[0] = 0;
        }
        if (!real && !t->stop) {
            d2k_ech_config cfg;
            real = !d2k_sched_ech_resolve_hook(t->name, s->measure_mark, &cfg) &&
                   !strcmp(cfg.public_name, t->name);
        }
        /* Сначала свидетели, способные показать объём ответа; свидетель-
           проверка — только если других нет. */
        if (!t->ech_origin[0] && ech_pick_witness(s, t, real, 1)) real = 1;
        if (!real) {
            /* GREASE: обычный путь по имени тем же снимком клиента. Форма
             * вопроса — форма приветствия, а не ECH: иначе цикл, сравнив её
             * с ECH-формой того же снимка, выбросил бы готовый полный прогон
             * и повторил его теми же байтами (поле 02.10, discord.com). */
            pthread_mutex_lock(&s->mu);
            t->ech_offer = 0;
            t->ech_grease = 1;
            t->asked_shape = (uint8_t)d2k_hello_shape(trig.bytes, trig.len);
            pthread_mutex_unlock(&s->mu);
            say(s, "по %s ECH offer — GREASE: внешнее имя не является public_name "
                   "известной ECH-конфигурации; обычный поиск по имени", t->name);
            /* СВОИ ПЛАНЫ — КАК БЕЗ ECH (задача 49). При ECH offer главный
               поток своих планов не искал (own_first_plans: ECH-форма не
               та). Теперь форма известна, и решение о шаге своих планов —
               за главным потоком: он читает каталог. Замера не было. */
            if (t->own_first == 0 && !t->stop) {
                pthread_mutex_lock(&s->mu);
                memset(&t->res, 0, sizeof t->res);
                t->res.verdict = D2K_V_INCONCLUSIVE;
                t->ech_regrade = 1;
                t->res_ready = 1;
                pthread_mutex_unlock(&s->mu);
                ssize_t ign_rg = write(s->wake[1], "w", 1); (void)ign_rg;
                return NULL;
            }
        } else if (!t->ech_origin[0]) {
            /* НАСТОЯЩИЙ ECH, СВОЕГО СВИДЕТЕЛЯ НЕТ (поле 04.10.2026, Chrome →
             * Cloudflare, чистый каталог). Обычным приветствием внешнего
             * имени не меряем — это другой вопрос: коробка там глушила само
             * расширение ECH, а обычный cloudflare-ech.com проходил. Вход
             * коробки — байты клиента, и они у нас есть (снимок): их повтор
             * на новом соединении к тому же адресу и есть её вопрос. Дальше
             * обычный путь задачи 32 этими байтами — база донора, свои
             * планы, полный замер; кандидат проверяется тем же повтором под
             * планом (ServerHello — уровень рукопожатия: без ключей клиента
             * дальше не пройти). Решение о своих планах — за главным
             * потоком (каталог не под s->mu), как у GREASE. */
            pthread_mutex_lock(&s->mu);
            memset(&t->res, 0, sizeof t->res);
            t->res.verdict = D2K_V_INCONCLUSIVE;
            t->ech_replay = 1;
            t->ech_regrade = 1;
            t->res_ready = 1;
            pthread_mutex_unlock(&s->mu);
            ssize_t ign_ech0 = write(s->wake[1], "w", 1); (void)ign_ech0;
            return NULL;
        }
    }
    if (t->transport == 6 && t->ech_offer && !t->ech_replay) {
        d2k_ver_result baseline = d2k_verify_probe_ech_origin_on(-1, t->ip, t->port,
            t->name, t->ech_origin, SCHED_VERIFY_STEP_MS, trig.len, s->measure_mark, NULL);
        d2k_vres result = d2k_sched_ech_baseline_result(&baseline, &t->vol, t->ech_origin);
        if (result.verdict != D2K_V_CLEAR && baseline.fd >= 0 &&
            baseline.level != D2K_VER_CHALLENGE) {
            /* Permission for an isolated candidate experiment, not a proved
             * DPI verdict. Only own ECH+body+APPLIED can confirm a plan. */
            t->ech_trial = 1;
        }
        d2k_verify_close(&baseline);
        pthread_mutex_lock(&s->mu);
        t->res = result; t->res_ready = 1;
        pthread_mutex_unlock(&s->mu);
        ssize_t ign_ech = write(s->wake[1], "w", 1); (void)ign_ech;
        return NULL;
    }
    if (encrypted_dns_task(t) && !t->doh_checked) {
        d2k_verify_budget_set(D2K_TCP_STALL_FIELD_BUDGET);
        d2k_ver_result dns=verify_encrypted_dns(t,-1,trig.len,
            d2k_hello_shape(trig.bytes,trig.len)==D2K_SHAPE_LEGACY,s->measure_mark,0);
        d2k_verify_budget_set(0);
        int local=dns_non_path_failure(&dns);
        int ok=dns_application_proved(&dns) && !local;
        t->doh_checked=1;
        t->doh_trial=!ok && !local && (dns.budget==D2K_BUDGET_CUT || dns.status==0 || (dns.status==200 && !dns.body_complete));
        say(s,"по %s DoH-запрос: %s",t->name,dns.reason);
        if(worker_doh_repeat_cut(s,t,trig,&dns)) {
            d2k_verify_close(&dns);
            if(worker_doh_synthesis(s,t,trig))return NULL;
            (void)worker_volume_cut(s,t);
            return NULL;
        }
        local=dns_non_path_failure(&dns);
        ok=!t->stop && !local && dns_application_proved(&dns);
        t->doh_trial=!ok && !local && (dns.budget==D2K_BUDGET_CUT || dns.status==0 ||
                                     (dns.status==200 && !dns.body_complete));

        if (ok || local || !t->doh_trial) {
            pthread_mutex_lock(&s->mu);
            memset(&t->res,0,sizeof t->res);
            t->res.verdict=ok ? D2K_V_CLEAR : D2K_V_INCONCLUSIVE;
            snprintf(t->res.reason,sizeof t->res.reason,"%s",dns.reason);
            t->vol.rx_direct_complete=ok;
            t->res_ready=1;
            pthread_mutex_unlock(&s->mu);
            d2k_verify_close(&dns);
            ssize_t ignored=write(s->wake[1],"w",1); (void)ignored;
            return NULL;
        }
        d2k_verify_close(&dns);
    }
    if(worker_doh_synthesis(s,t,trig))return NULL;
    if (t->own_first == 1 &&
        (t->transport == 6 ? d2k_sched_tcp_base_hook != NULL : d2k_sched_quic_base_hook != NULL)) {
        /* Задача 32: только базовый вопрос. Полный прогон, если он
           понадобится, пойдёт отдельным потоком и возьмёт этот ответ. */
        d2k_vres base = t->transport == 6
            /* У базового вопроса дополнений не бывает: он задаёт один
               триггер целиком и ничего из каталога не берёт. */
            ? d2k_sched_tcp_base_hook(t->ip, t->port, trig, ctl, s->measure_mark, 0, 0, 0, &t->stop, NULL)
            : d2k_sched_quic_base_hook(t->ip, t->port, t->name, trig, ctl, s->measure_mark);
        pthread_mutex_lock(&s->mu);
        t->res = base;
        ask_settle(t, base.probes);
        t->res_ready = 1;
        pthread_mutex_unlock(&s->mu);
        ssize_t ign_base = write(s->wake[1], "w", 1);
        (void)ign_base;
        return NULL;
    }
    /* ECH здесь — только повтор байтов клиента без свидетеля: объём меряется
       обычным приветствием внешнего имени, а это другой вопрос (выше). */
    int volume_first = t->transport == 6 && !t->skip_volume_once && !t->ech_offer &&
                       (t->rx_volume_only || t->family_reuse == 1);
    int volume_after = t->transport == 6 && !t->skip_volume_once && !t->ech_offer &&
                       !volume_first;
    /* Обрыв ответа, доказанный прошлым прогоном этой задачи и не
       переспрашиваемый (повтор снимком, «отвеченное не переспрашивается»). */
    int volume_carried = t->transport == 6 && t->skip_volume_once &&
                         (t->vol.verdict == D2K_VOL_CUT || t->vol.rx_cut);
    if (volume_first) {
        worker_volume(s, t, trig);
        if (worker_volume_cut(s, t)) { return NULL; }
        if (t->rx_volume_only || (t->family_reuse == 1 && t->vol.rx_tls_unavailable)) {
            pthread_mutex_lock(&s->mu);
            memset(&t->res, 0, sizeof t->res);
            t->res.verdict = D2K_V_INCONCLUSIVE;
            snprintf(t->res.reason, sizeof t->res.reason,
                     "%s", t->rx_volume_only
                     ? "позднее закрытие не подтвердилось парной RX-volume-пробой"
                     : "прямая TLS-база не прошла; готовлю отдельную проверку собственного плана цели");
            t->res_ready = 1;
            pthread_mutex_unlock(&s->mu);
            ssize_t ign3 = write(s->wake[1], "w", 1);
            (void)ign3;
            return NULL;
        }
    }
    t->skip_volume_once = 0;

    d2k_vres r;
    /* Ответ базового вопроса (задача 32) — только тем же входом. */
    const d2k_base_seed *seed = t->seed_use && (t->seed.valid || t->seed.props_valid) &&
        t->seed_input == seed_input_of(trig.bytes, trig.len, t->ip, t->port) ? &t->seed : NULL;
    if (t->transport == 17) {
        /* Original Run owns both diagnosis and askArms, BEFORE properties,
           with one residual-aware address pool. Never restart search here. */
        /* Task 39 round 1: the arm data stage asks the known large resource. */
        snprintf(t->arm.probe_path, sizeof t->arm.probe_path, "%s", t->measure_path);
        t->arm.split_unfit = a_split_unfit;
        /* Задача 50, раунд 2: поиск начат обрывом ПОСЛЕ рукопожатия —
           прямой вопрос обязан проверить ответ своим запросом HTTP/3, а не
           только ответ на Initial (тот проходит и при обрыве). */
        /* Поле 04.10 13:37 (rua.gr, Safari): датапат назвал обрыв после
           рукопожатия «молчанием» (подозрение 3): сервер прислал 8 пакетов —
           все в окне очереди, — и счётчик conntrack не ушёл за них, так что
           детектор QUIC_STALL молчал, а молчание UDP сработало на повторах
           клиента после ответа. Без признака вопросник проверял только
           Initial (3/3) и закрывал поиск словами «проходит как есть», пока
           Safari стоял. Молчание QUIC при прошедшем Initial поэтому тоже
           проверяется своим запросом: этап данных задаётся, только если наш
           Initial ответ получил (иначе вопрос о рукопожатии и решается).

           ВТОРАЯ, НЕЗАВИСИМАЯ ПРИЧИНА ТОЙ ЖЕ ТИШИНЫ (разбор 12.10.2026,
           задача 31). При ОДНОСТОРОННЕМ блоке (оба измеренных цензора QUIC
           роняют только исходящее: FOCI 2026(2) §3, USENIX Sec 25) подозрение
           не ставится НИКОГДА, и это не вопрос порога. Сервер повторяет свой
           полёт по таймеру PTO, ct_flow обнуляет отметку прямого счётчика на
           каждом его сдвиге, а пакеты клиента идут В ФАЗЕ с этими полётами —
           подтверждений он не получает, поэтому его собственный pto_count
           растёт по тому же закону, а ACK он обязан слать на полёт сервера
           (RFC 9000 §13.2.1). Внутри промежутка трёх пакетов клиента не
           набирается ни при какой базе PTO: прогнано 32 случая (базы
           0,2/0,5/1/2 с × один-два пакета за срабатывание, RFC 9002 §6.2.4),
           подозрения нет ни в одном за все 120 с жизни записи.

           Признака в счётчиках conntrack для этого класса НЕТ, и это проверено
           числами, а не оставлено как недоделка: «лестница PTO в промежутках»
           даёт 10,3 % ложных подозрений на случайном кадансе при пороге три
           роста подряд (3000 прогонов на точку) — то есть подбор на рабочем
           трафике, запрет §0; порог пять безопасен (0,03 %), но срабатывает на
           106–257-й секунде, позже, чем живёт запись. Отношение прямого
           счётчика к обратному классы не делит: клиент подтверждает повторы, и
           orig ≈ reply/2 и при заглушении, и у здоровой загрузки. Размеры и
           каданс внутри полёта датапат не видит вовсе — после connbytes 0:8
           очередь этих пакетов не получает. Доказательство направления есть
           только у контроллера (d2k_qc_outbound, D2K_QSTALL_ONEWAY): он
           спрашивает подтверждение СВОЕГО номера пакета. Закреплено тестом
           datapath/test_quic_session.c (test_quic_oneway_block), который
           упадёт, когда дефект закроют. */
        /* Кода «QUIC без прикладного доказательства» в этом наборе больше
           нет: калитка снята по полевому замеру 12.10.2026v
           (docs/field/2026-10-12g) — она давала повод спросить по рабочим
           целям, 97 единиц зондов и ни одного плана. Датапат такого повода
           не присылает. */
        t->arm.data_cut = t->trigger_code != D2K_SUSPECT_QUIC_STALL &&
                          t->trigger_code != D2K_SUSPECT_SILENT ? 0 :
                          t->deny_recheck ? 2 : 1;
        /* Бюджет коробки (задача 55, task_budget): свой запрос повторяется
           на новых потоках до 2 × бюджет датаграмм или тишины сервера. */
        t->arm.budget_pk = a_budget;
        r = seed && d2k_sched_quic_seeded_hook
            ? d2k_sched_quic_seeded_hook(t->ip, t->port, t->name, trig, ctl, s->measure_mark, &t->arm, seed)
            : d2k_sched_quic_hook(t->ip, t->port, t->name, trig, ctl, s->measure_mark, &t->arm);
        t->arm_ready = t->arm.original;
    } else {
        /* repeats<=0 — то же умолчание (три), что у d2k_meas: второе число
           здесь развело бы два места по умолчанию (d2k_verdict.h). gap/wait
           нулями — та же передача умолчания вниз. */
        /* ECH-ПРИМАНКА для составного вопроса семейства C «ECH-приветствие под
           меткой времени» (поле 10.10.2026, уточнение владельца по ECH). Шаблон
           cloudflare-ech / fake_default_tls с ECH-расширением: коробка не читает
           в нём имя и не режет по нему. Даётся ВСЕГДА, НЕЗАВИСИМО ОТ seed: с
           пустым каталогом — семя hcaptcha.com, иначе имя из net.name
           (rx_decoy_name — тот же источник, что у RX-лестницы).

           ПОЧЕМУ НЕЗАВИСИМО ОТ seed (поле ac4edeb, 19 сайтов): у целей семейства
           C профильный замер ловит ClientHello клиента и идёт SEEDED (снятыми
           байтами). Пока приманка считалась только при !seed, у этих целей
           opt->white был пуст, вопрос пропускался — цель падала в старое
           поведение. Теперь приманка доходит и на seeded-путь (отдельный крючок,
           сигнатуру seeded менять нельзя). Объёмный слой (16 КБ) здесь не
           трогаем — его снимает отдельный путь. */
        uint8_t wbuf[2048]; /* ECH-приветствие-record ~700 байт, с запасом */
        size_t wlen = 0;
        d2k_hello white = {0};
        int want_white = d2k_white_decoy_hello(rx_decoy_name(s), wbuf, sizeof wbuf, &wlen) == 0;
        if (want_white) {
            white.bytes = wbuf;
            white.len = wlen;
        }
        /* ДОПОЛНЕНИЯ ЕДУТ ВМЕСТЕ И НЕЗАВИСИМО (23.10.2026). Прежде каждое
           имело свой крючок, и планировщик выбирал один из четырёх каскадом;
           пятое дополнение потребовало бы восьми. Теперь дополнение, которого
           нет, просто пусто. */
        d2k_sched_tcp_extra extra;
        memset(&extra, 0, sizeof extra);
        extra.white = white;
        extra.response_probe_name = a->response_probe_name;
        extra.seed = seed;
        extra.known = t->known_valid ? &t->known_props : NULL;
        extra.refuted = t->n_arm_refuted ? t->arm_refuted : NULL;
        extra.n_refuted = t->n_arm_refuted;
        r = d2k_sched_tcp_hook(t->ip, t->port, trig, ctl, s->measure_mark, 0, 0, 0, &t->stop, &extra);
    }

    if(r.protocol_response) {
        if(worker_protocol_response(s,t,trig,&r))return NULL;
        volume_after=0; /* Context-specific application check already selected. */
    }
    if(t->doh_trial && r.verdict==D2K_V_CLEAR) {
        r.verdict=D2K_V_INCONCLUSIVE;r.owns_search=0;
        snprintf(r.reason,sizeof r.reason,"TLS проходит, но DoH-обмен оборвался; проверяю гипотезы по ответу DNS");
    }
    if (volume_after) {

        int allow_vol = (r.verdict == D2K_V_CLEAR ||
                         (r.verdict == D2K_V_FLAKY &&
                          is_late_volume_suspicion(t->trigger_code) &&
                          !r.dial_deadline)) && !t->stop;
        if (allow_vol) {
            /* Рукопожатие и запись прошли (или для подозрения позднего
               обрыва дали FLAKY, не отменяющий замер объёма) — теперь
               блок по объёму. Обрыв ведёт той же веткой, что и прежде:
               направленная улика и кандидат, без вердикта CLEAR. */
            worker_volume(s, t, trig);
            if (worker_volume_cut(s, t)) { return NULL; }
        } else {
            /* Объём не измерялся: исход прошлого прогона этой задачи к
               другому вердикту не прикладывается. Флаг «TLS недоступен»
               здесь выводится из вердикта классификатора, а не из прямого
               RX-GET: OPAQUE (единственный вердикт, открывающий послойную
               RX-проверку под кандидатом) значит, что прямое рукопожатие
               не прошло. Под кандидатом без обрыва identity-тела такая
               проверка кончается обычным подтверждением. Путь
               rx_saved_bootstrap этим флагом не открывается: он идёт только
               после прямого объёмного замера (поздний RST, family_reuse 1). */
            memset(&t->vol, 0, sizeof t->vol);
            t->vol.rx_tls_unavailable = r.verdict == D2K_V_OPAQUE;
        }
    } else if (volume_carried && r.verdict == D2K_V_CLEAR && !t->stop) {
        /* ПРОШЕДШЕЕ РУКОПОЖАТИЕ НЕ ОТМЕНЯЕТ ДОКАЗАННЫЙ ОБРЫВ. Повтор байтами
           клиента спросил то, что от них зависит, — рукопожатие, — и оно
           прошло; ответ всё так же режется около тех же КБ. Голый CLEAR
           verdict_to_plans читает как «кандидатов нет» и до лестницы обрыва
           (белое имя, fake-SNI + split) не доходит: поле 14.10.2026,
           fast.com — «кандидатов 0», отдых на десять минут. Вердикт —
           тот же, что дал бы обрыв, измеренный этим прогоном. Если же
           рукопожатие байтами клиента НЕ прошло, остаётся его вердикт:
           блок на рукопожатии и есть ответ. */
        if (worker_volume_cut(s, t)) { return NULL; }
    }

    pthread_mutex_lock(&s->mu);
    t->res = r;
    ask_settle(t, r.probes);
    t->res_ready = 1;
    pthread_mutex_unlock(&s->mu);

    /* Разбудить цикл: без этого вердикт лежал бы до следующего события
       датапата или тика — секунды на ровном месте. Один байт, и отказ записи
       не беда: цикл всё равно проснётся по тику. */
    ssize_t ignored = write(s->wake[1], "w", 1);
    (void)ignored;
    return NULL;
}

static void contact_close(task *t);

/* --- разрез CRYPTO и клиент шире датаграммы (финальное ревью core, I1) --- */

static int quic_text_is_split(const char *text) {
    return text && strstr(text, "\nquicsplit ") != NULL;
}

static int quic_client_multi(const d2k_sched *s, const char *name, uint8_t family) {
    uint8_t f = family ? family : 4;
    for (size_t k = 0; k < sizeof s->quic_multi / sizeof s->quic_multi[0]; k++)
        if (s->quic_multi[k].name[0] && s->quic_multi[k].family == f &&
            !strcmp(s->quic_multi[k].name, name)) return 1;
    return 0;
}

/* Неприменим ли разрез CRYPTO клиенту этой цели. Снимок клиента был обрывком
   (ClientHello шире датаграммы) — неприменим. Целый снимок клиента —
   применим. Снимка нет вовсе — решает раскладка измеряемого Initial: разрез
   предлагается, только если вход, которым мерили, — ClientHello в одной
   датаграмме (так он и подтвердится зондом, и так его исполнит датапат). */
static int quic_split_unfit(const d2k_sched *s, const task *t) {
    if (t->transport != 17) return 0;
    if (!t->by_addr && quic_client_multi(s, t->name, t->family)) return 1;
    if (t->trig_snapped) return 0;
    return t->trig_len == 0 || d2k_quic_hello_incomplete(t->trig, t->trig_len);
}

/* БЮДЖЕТ ПОТОКА для испытания (задача 55): свойство коробки, а не константа
   обхода. Источники по силе: замер этой цели (пакеты на обрыве identity —
   примета rx-volume в её отпечатке или исход объёма), затем коробка задачи
   t->box_id (узнанная по отпечатку; у кандидата из каталога install_next
   кладёт туда коробку-владельца плана), затем поле 04.10 —
   25 пакетов в 18 из 18 оборванных потоков (task-55-facts.md §1.2). */
static unsigned task_budget(const d2k_sched *s, task *t) {
    for (size_t i = 0; i < t->fp.n_sig; i++) {
        if (is_rx_volume_kind(t->fp.sig[i].kind) && t->fp.sig[i].packets > 0) {
            snprintf(t->budget_src, sizeof t->budget_src, "замер этой цели (обрыв identity)");
            return t->budget_pk = (unsigned)t->fp.sig[i].packets;
        }
    }
    if (t->transport == 6 && t->vol.rx_cut_packets > 0) {
        snprintf(t->budget_src, sizeof t->budget_src, "замер этой цели (обрыв identity)");
        return t->budget_pk = (unsigned)t->vol.rx_cut_packets;
    }
    for (size_t bi = 0; t->box_id[0] && s->cat && bi < s->cat->n_boxes; bi++) {
        const d2k_cat_box *b = &s->cat->boxes[bi];
        if (strcmp(b->id, t->box_id)) continue;
        for (size_t i = 0; i < b->fp.n_sig; i++) {
            if (is_rx_volume_kind(b->fp.sig[i].kind) && b->fp.sig[i].packets > 0) {
                snprintf(t->budget_src, sizeof t->budget_src, "замер коробки %.40s", b->id);
                return t->budget_pk = (unsigned)b->fp.sig[i].packets;
            }
        }
    }
    snprintf(t->budget_src, sizeof t->budget_src, "поле 04.10, коробка не измерена");
    return t->budget_pk = D2K_BUDGET_FIELD_PACKETS;
}

/* ЗНАНИЕ УЗНАННОЙ КОРОБКИ ДЛЯ ЭТОЙ ЦЕЛИ (23.10.2026).
 *
 * Коробка узнаётся тем же сравнением примет, что и её сохранённые планы
 * (known_plans): d2k_fp_same. Запись выбирается по форме приветствия клиента —
 * вектор, снятый клиентом с меткой времени, для клиента без метки ложь
 * (issue #7). Запись с формой 0 из старого файла подходит любой форме.
 *
 * ЧЕМ ПЛОХО ОШИБИТЬСЯ. Если приметы совпали, а коробка на пути другая, знание
 * снимет вопрос, который на этой сети прошёл бы. Цена ограничена: пропускаются
 * только вопросы с ИЗВЕСТНЫМ ПРОМАХОМ (d2k_opts.known, detect/props.c), и
 * приём, который они бы нашли, остаётся в запасном переборе. Обратное — не
 * снимать вопрос никогда — стоит повторов на каждой цели коробки.
 *
 * Отпечаток ещё не набран (n_sig == 0) — узнавать нечем, знания нет. */
static void known_snapshot(d2k_sched *s, task *t) {
    t->known_valid = 0;
    memset(&t->known_props, 0, sizeof t->known_props);
    if (s->cat && t->fp.n_sig != 0 && t->transport == 6) {
        for (size_t bi = 0; bi < s->cat->n_boxes && !t->known_valid; bi++) {
            const d2k_cat_box *b = &s->cat->boxes[bi];
            if (!d2k_fp_same(&b->fp, &t->fp)) { continue; }
            for (size_t i = 0; i < b->n_props; i++) {
                const d2k_cat_props *r = &b->props[i];
                if (r->p.client_shape != 0 && r->p.client_shape != t->trigger_shape) { continue; }
                if (!d2k_box_props_any(&r->p)) { continue; }
                t->known_props = r->p;
                t->known_valid = 1;
                break;
            }
        }
    }
    /* ИЗМЕРЕННОЕ В ЭТОМ ПОИСКЕ — ТОЖЕ ЗНАНИЕ, И ОНО СВЕЖЕЕ КАТАЛОГА. Без
       него продолжение опроса после опровергнутого приёма задавало бы заново
       вопросы, на которые только что получило «нет» на этой же линии: в поле
       24.10.2026 это были первые три вопроса из четырёх. Противоречие с
       каталогом не выбирает сторону, а гасится в «не измерено»
       (d2k_box_props_merge): знание не вправе отменять вопрос, про который
       два замера сказали разное. */
    if (d2k_box_props_any(&t->measured_props)) {
        d2k_box_props_merge(&t->known_props, &t->measured_props);
        t->known_valid = d2k_box_props_any(&t->known_props);
    }
    if(t->gate_skip_reuse) {
        t->known_props.response_gate=t->known_props.gate_carry=t->known_props.gate_hello_own=0;
        t->known_props.gate_window=t->known_props.gate_pieces=t->known_props.gate_rtt_ms=0;
        t->known_valid=d2k_box_props_any(&t->known_props);
    }
}

static void join_worker(task *t);

static int start_worker(d2k_sched *s, task *t, task_job job) {
    if(newchain_task(s,t))return -1;

    /* Прежний поток задачи ещё не присоединён: присоединить его СЕЙЧАС.
       Иначе его pthread_t затирается, стек 1 МиБ не возвращается никогда, а
       слот аргумента переписывается под ним. */
    if (t->th_live) {
        pthread_mutex_lock(&s->mu);
        s->memory.worker_start_while_live++;
        pthread_mutex_unlock(&s->mu);
        join_worker(t);
    }
    worker_arg *a = &s->wargs[t - s->tasks];
    if (job==JOB_DOH_HEALTH && !t->plain_first_timeout_bytes)
        dns_pick_question(s,t,s->now_ms);
    pthread_mutex_lock(&s->mu);
    s->memory.worker_args_allocated++;
    pthread_mutex_unlock(&s->mu);
    a->s = s; a->t = t;
    a->response_probe_name[0] = '\0';
    if (job == JOB_CLASSIFY && t->transport == 6 && preflight_family_enabled(t->family)) {
        const clean_hs_seen *latest = NULL;
        for (size_t i = 0; i < SCHED_CLEAN_HS_SLOTS; i++) {
            const clean_hs_seen *c = &s->clean_hs[i];
            if (c->used && c->transport == 6 && c->family == t->family &&
                c->seen_ms <= s->now_ms && s->now_ms - c->seen_ms <= SCHED_CLEAN_HS_MS &&
                strcmp(c->name, t->name) && (!latest || c->seen_ms > latest->seen_ms))
                latest = c;
        }
        if (latest) {
            snprintf(a->response_probe_name, sizeof a->response_probe_name, "%s", latest->name);
            say(s, "по %s: имя для предварительной пробы из прямого обмена %s", t->name, latest->name);
        }
    }
    a->trig_len = t->trig_len; a->ctrl_len = t->ctrl_len;
    a->split_unfit = quic_split_unfit(s, t);
    a->budget = job == JOB_VERIFY || (job == JOB_CLASSIFY && t->transport == 17)
                ? task_budget(s, t) : 0;
    memcpy(a->trig, t->trig, t->trig_len);
    memcpy(a->ctrl, t->ctrl, t->ctrl_len);
    a->client_opts_known = t->client_opts_known;
    a->client_opts_len = t->client_opts_known ? t->client_opts_len : 0;
    memcpy(a->client_opts, t->client_opts, a->client_opts_len);
    a->trig_snapped = t->trig_snapped;
    /* Сокет вопроса забирается ЗДЕСЬ, в главном потоке, и поле задачи
       очищается сразу: два владельца одного дескриптора — двойное закрытие. */
    a->use_fd = job == JOB_CONTACT ? t->prop_bound_fd : job == JOB_VERIFY ? t->probe_fd : -1;
    if (job == JOB_CONTACT) { t->prop_bound_fd = -1; contact_close(t); }
    if (job == JOB_VERIFY) { t->probe_fd = -1; }
    /* ЗНАНИЕ О КОРОБКЕ СНИМАЕТСЯ ЗДЕСЬ, В ГЛАВНОМ ПОТОКЕ, по той же причине,
       что и сокет вопроса выше: рабочий поток каталога не читает. */
    if (job == JOB_CLASSIFY) { known_snapshot(s, t); }
    t->job = job;
    t->worker_owner=s;
    t->quic_yield_request=t->quic_yield_waiting=t->quic_parked=0;
    t->res_ready = 0;
    /* Новый поток — новый вопрос; зонды прежних прогонов (база задачи 32,
       повтор по снимку) остаются на счету задачи. Прежний поток присоединён. */
    t->ask_base = t->ask_probes;
    t->ask_question[0] = '\0';
    /* ФЛАГ «БРОСАЙ» — СВЕЖИЙ У КАЖДОГО ПОТОКА.
       Его взводит join_worker, дожидаясь предыдущего, и снимает только
       task_reset. Задача, которая начинает замер ЗАНОВО не через сброс
       (повтор из-за позднего снимка), унаследовала бы взведённый флаг — и
       новый замер бросался бы на нулевом зонде, отчитываясь «о цели не
       сказано ничего». Поймано стендом с цензором на клиенте TLS 1.2. */
    t->stop = 0;
    /* СТЕК ПОТОКА — ЯВНЫЙ, 1 МиБ. Замер идёт глубоко (дерево зондов, сырой
       слой, разбор TLS), а умолчание зависит от libc и ulimit -s на роутере
       (у musl — 128 КиБ); переполнение — тихая порча памяти, не ошибка. */
    pthread_attr_t attr;
    /* Атрибуты или размер не приняты — поток всё равно нужен: умолчание
       лучше, чем сорванный замер. */
    int have_attr = pthread_attr_init(&attr) == 0;
    int sized = have_attr && pthread_attr_setstacksize(&attr, (size_t)1u << 20) == 0;
    int created = (!d2k_sched_spawn_hook || d2k_sched_spawn_hook() == 0) &&
                  pthread_create(&t->th, sized ? &attr : NULL, worker_run, a) == 0;
    if (have_attr) { pthread_attr_destroy(&attr); }
    if (!created) {
        if (a->use_fd >= 0) { close(a->use_fd); }
        pthread_mutex_lock(&s->mu);
        s->memory.worker_args_freed++;
        pthread_mutex_unlock(&s->mu);
        return -1;
    }
    s->memory.workers_started++;
    t->th_live = 1;
    if (job == JOB_CLASSIFY || job == JOB_VOICE || job == JOB_STUN) { t->search_started = 1; }
    return 0;
}

/* Отмена будит рабочий поток перед ожиданием. Если поток уже опубликовал
 * результат, его можно присоединить, сохранив исходный статус отмены. */
static void finish_worker(task *t, int cancel) {
    if (t->th_live) {
        d2k_sched *s=t->worker_owner;
        if (cancel) {
            if(s)pthread_mutex_lock(&s->mu);
            t->stop = 1;
            t->quic_yield_waiting=0;
            if(s){pthread_cond_broadcast(&s->question_cv);pthread_mutex_unlock(&s->mu);}
        }
        int joined = pthread_join(t->th, NULL);
        if(s) {
            if(joined) s->memory.worker_join_errors++;
            else s->memory.workers_joined++;
        }
        t->th_live = 0;
        t->quic_parked=t->quic_yield_request=0;
        t->worker_owner=NULL;
    }
}
static void join_worker(task *t) { finish_worker(t, 1); }

/* --------------------------------------------------------------------
 * Каталог: записывается ТОЛЬКО по подтверждённому успеху.
 * -------------------------------------------------------------------- */

static d2k_cat_box *box_ensure(d2k_catalog *c, const char *id) {
    for (size_t i = 0; i < c->n_boxes; i++) {
        if (strcmp(c->boxes[i].id, id) == 0) { return &c->boxes[i]; }
    }
    d2k_cat_box *nb = realloc(c->boxes, (c->n_boxes + 1) * sizeof *nb);
    if (!nb) { return NULL; }
    c->boxes = nb;
    c->cap_boxes = c->n_boxes + 1;
    d2k_cat_box *b = &c->boxes[c->n_boxes];
    memset(b, 0, sizeof *b);
    snprintf(b->id, sizeof b->id, "%s", id);
    c->n_boxes++;
    return b;
}

/* Записывает подтверждённую привязку.
 *
 * КЛЮЧ — ТРОЙКА: цель, транспорт и форма приветствия (d2k_cat_shape_fits).
 * Форма в ключе затем, что успех добыт КОНКРЕТНЫМ приветствием, а коробка
 * вправе относиться к формам по-разному (§6): без неё успех собственного
 * зонда молча выдавался бы за успех любого клиента. Ноль в записи — «форма не
 * измерена» (старый файл): он совместим с любой формой, и такая привязка
 * ОБНОВЛЯЕТСЯ, а не дублируется — иначе каталог, копившийся неделями,
 * удвоился бы на первой же проверке.
 *
 * shape/verified_by кладутся только измеренными: ноль поверх записанного не
 * пишется никогда — «не измерено» не отменяет измеренного (§2.4). */
/* См. комментарий у wall_base_s. Отдельной функцией, а не выражением по месту:
   мест семь, и разойдись хоть одно — в каталоге окажутся записи из двух разных
   эпох, неотличимые на вид. */
static int64_t wall_s(const d2k_sched *s, int64_t now_ms) {
    return s->wall_base_s + (now_ms - s->mono_base_ms) / 1000;
}

/* ЗНАНИЕ О КОРОБКЕ — В ЕЁ ЗАПИСЬ, ПО ОСИ ФОРМЫ КЛИЕНТА (23.10.2026).
 *
 * До правки вектор свойств, измеренный дерево́м, кончался на мосту: каждая
 * новая цель узнанной коробки задавала ей те же вопросы заново. Теперь он
 * ложится в её запись, и следующая цель начинает со знания, а не с нуля.
 *
 * ОСЬ — ФОРМА ПРИВЕТСТВИЯ, И ЭТО НЕ ОСТОРОЖНОСТЬ, А ПОЛЕВОЙ ФАКТ. Клиент без
 * метки времени не исполняет план со сдвигом метки назад (issue #7): вектор,
 * снятый клиентом с меткой, для него ложь. Запись с формой 0 — из файла, где
 * формы не записывали; она поднимается до измеренной формы, а не дублируется,
 * иначе каталог удваивался бы на первой же проверке (тот же приём, что у
 * привязок выше).
 *
 * ПУСТОЕ ЗНАНИЕ ЗАПИСИ НЕ ЗАВОДИТ: «измеряли и ничего не нашли» — другое
 * утверждение, чем «не измеряли» (§2.4), и у QUIC-подтверждений вектор
 * TCP-вопросов пуст по определению.
 *
 * Возврат — число противоречий: замер разошёлся с записанным, поле стало
 * неизмеренным, и это повод перемерить коробку (§0), а не тихая правка файла. */
static int box_props_learn(d2k_catalog *c, d2k_cat_box *b, const d2k_box_props *src,
                           uint8_t shape, int64_t at_s) {
    d2k_cat_props *rec = NULL;
    size_t i;
    if (!d2k_box_props_any(src)) { return 0; }
    for (i = 0; i < b->n_props; i++) {
        if (b->props[i].p.client_shape == shape) { rec = &b->props[i]; break; }
    }
    for (i = 0; i < b->n_props && !rec; i++) {
        if (b->props[i].p.client_shape == 0) { rec = &b->props[i]; }
    }
    if (!rec) {
        /* Мест нет: вытеснять чужую форму нельзя — её знание добыто своим
           замером и этому замеру не противоречит. Молчать тоже нельзя. */
        if (b->n_props >= D2K_CAT_PROPS_MAX) { return -1; }
        rec = &b->props[b->n_props++];
        memset(rec, 0, sizeof *rec);
    }
    int conflicts = d2k_box_props_merge(&rec->p, src);
    rec->p.client_shape = shape;
    rec->measured_at = at_s;
    c->revision++;
    return conflicts;
}

static int bind_confirmed(d2k_catalog *c, const char *box_id, const char *plan_id,
                          const char *plan_text, const char *proto,
                          const char *target, const char *kind, uint8_t transport,
                          uint8_t family, uint8_t shape, uint16_t server_port,
                          uint8_t verified_by, uint8_t input,
                          int64_t at_s, const d2k_cat_fp *fp, const d2k_box_props *props,
                          int *props_conflicts) {
    int service = !strcmp(kind, "service");
    if (service != (server_port != 0)) return -1;
    d2k_cat_box *b = box_ensure(c, box_id);
    if (!b) { return -1; }
    if (b->created == 0) { b->created = at_s; }
    if (b->fp.n_sig == 0 && fp && fp->n_sig > 0) {
        /* Отпечаток записывается ОДИН раз, при заведении коробки: дальше он её
           удостоверение, и переписывать его приметами следующей цели значило
           бы менять то, по чему её узнают. */
        b->fp = *fp;
    } else if (fp) {
        /* Бюджет потока (задача 55) — измеренное свойство, не удостоверение:
           в узнавание и имя коробки не входит, поэтому последний посчитанный
           замер обрыва identity той же корзины обновляет его и у заведённой. */
        for (size_t i = 0; i < fp->n_sig; i++) {
            if (!is_rx_volume_kind(fp->sig[i].kind) || fp->sig[i].packets <= 0) continue;
            for (size_t k = 0; k < b->fp.n_sig; k++) {
                d2k_cat_signal *x = &b->fp.sig[k];
                int d = x->volume - fp->sig[i].volume;
                if (d < 0) d = -d;
                if (!strcmp(x->kind, fp->sig[i].kind) && d <= D2K_VOLUME_SLACK &&
                    x->packets != fp->sig[i].packets) {
                    x->packets = fp->sig[i].packets;
                    c->revision++;
                }
            }
        }
    }
    if (props) {
        int rc = box_props_learn(c, b, props, shape, at_s);
        if (props_conflicts) { *props_conflicts = rc; }
    }
    b->updated = at_s;

    int have_plan = 0;
    for (size_t i = 0; i < b->n_plans; i++) {
        if (strcmp(b->plans[i].id, plan_id) == 0) { b->plans[i].successes++; have_plan = 1; break; }
    }
    if (!have_plan) {
        d2k_cat_plan *np = realloc(b->plans, (b->n_plans + 1) * sizeof *np);
        if (!np) { return -1; }
        b->plans = np;
        b->cap_plans = b->n_plans + 1;
        d2k_cat_plan *p = &b->plans[b->n_plans];
        memset(p, 0, sizeof *p);
        snprintf(p->id, sizeof p->id, "%s", plan_id);
        snprintf(p->proto, sizeof p->proto, "%s", proto);
        p->text = strdup(plan_text ? plan_text : "");
        if (!p->text) { return -1; }
        p->added = at_s;
        p->successes = 1;
        p->enabled = 1;
        b->n_plans++;
    }

    for (size_t i = 0; i < b->n_binds; i++) {
        d2k_cat_binding *bd = &b->binds[i];
        if (bd->transport == transport && strcmp(bd->target, target) == 0 &&
            strcmp(bd->kind, kind) == 0 && bd->server_port == server_port &&
            (bd->family ? bd->family : 4) == family &&
            (service ? bd->shape == shape : d2k_cat_shape_fits(bd->shape, shape))) {
            bd->successes++;
            bd->confirmed = at_s;
            /* Повторное подтверждение снимает «требует повторной проверки»
               (задача 21): привязка возвращается на провод проходом каталога. */
            bd->recheck_since = 0;
            bd->recheck_mono_ms = 0;
            /* Отметка бюджета принадлежит ПЛАНУ привязки: смена плана её
               снимает, новую ставит verify_confirm (задача 55). */
            int replaced = strcmp(bd->plan_id, plan_id) != 0;
            if (replaced) {
                bd->budget = 0;
                bd->preflight_name[0] = 0;
                bd->dns_authenticated=0;bd->dns_dot=0;bd->dns_http_version=0;
                bd->dns_port=0;bd->dns_query_bytes=0;bd->dns_address[0]=0;bd->dns_name[0]=0;
                bd->input = input;
                bd->verified_by = verified_by;
            }
            snprintf(bd->plan_id, sizeof bd->plan_id, "%s", plan_id);
            if (shape) { bd->shape = shape; }
            if (verified_by) { bd->verified_by = verified_by; }
            /* Полнота входа пишется только СИЛЬНЕЕ прежней: замер байтами
               клиента отменяет прежнюю заготовку, обратное — нет. Иначе
               следующий холодный старт объявил бы слабым уже доказанное
               (§2.4). Ноль — «не измерено» — не пишется никогда. */
            if (input == D2K_INPUT_CLIENT || bd->input == 0) { bd->input = input; }
            c->revision++;
            return 0;
        }
    }
    d2k_cat_binding *nb = realloc(b->binds, (b->n_binds + 1) * sizeof *nb);
    if (!nb) { return -1; }
    b->binds = nb;
    b->cap_binds = b->n_binds + 1;
    d2k_cat_binding *bd = &b->binds[b->n_binds];
    memset(bd, 0, sizeof *bd);
    /* Вид цели — от вызывающего: у QUIC без читаемого имени цель адресная, и
       записать её именем значило бы выдумать имя (D2K_SPEC). */
    snprintf(bd->kind, sizeof bd->kind, "%s", kind);
    snprintf(bd->target, sizeof bd->target, "%s", target);
    snprintf(bd->plan_id, sizeof bd->plan_id, "%s", plan_id);
    bd->level = 3;
    bd->confirmed = at_s;
    bd->successes = 1;
    bd->enabled = 1;
    bd->transport = transport;
    bd->server_port = server_port;
    bd->family = family;
    bd->shape = shape;
    bd->verified_by = verified_by;
    bd->input = input;
    b->n_binds++;
    c->revision++;
    return 0;
}

/* Идентификатор коробки и плана — из содержимого, а не счётчиком: тот же
   план, найденный дважды, обязан получить то же имя, иначе каталог распухнет
   копиями одного и того же. FNV-1a: нужна устойчивая функция на 64 бита, а
   не криптостойкость. */
static uint64_t fnv1a(const char *s) {
    uint64_t h = 1469598103934665603ULL;
    for (; s && *s; s++) {
        h ^= (unsigned char)*s;
        h *= 1099511628211ULL;
    }
    return h;
}

/* Идентификатор кандидата в двух видах: строкой, под которой план ляжет в
 * каталог, и теми же байтами, с которыми он уйдёт на провод записью REC_ID.
 *
 * Вид на проводе — та же строка ASCII, добитая нулями до D2K_PLAN_ID_LEN, а
 * не отдельное число: два представления одного идентификатора разошлись бы
 * молча, а так журнал датапата и каталог показывают человеку буквально одно и
 * то же имя. Строка короче шестнадцати байт всегда: "plan-" плюс восемь
 * знаков. */
/* Испытанный текст — в tried; переполнение помечается (tried_full = 1) и
   называется в журнале на ближайшем шаге планирования, а не теряется молча. */
static void tried_add(task *t, uint32_t h) {
    if (t->n_tried < sizeof t->tried / sizeof t->tried[0]) t->tried[t->n_tried++] = h;
    else if (!t->tried_full) t->tried_full = 1;
}

/* ИСПЫТАННЫЙ СВОЙ ПЛАН — В ПАМЯТЬ ЗАДАЧИ, ОТТУДА В ПАМЯТЬ ОСТЫВАНИЯ.
   Память полна — вытесняем самый старый хэш, а не бросаем новый: забытый
   план проверяется зондами снова, и ровно этим кончалась прежняя запись. */
static void own_tried_add(task *t, uint32_t h) {
    for (uint8_t i = 0; i < t->n_own_tried; i++) {
        if (t->own_tried[i] == h) { return; }
    }
    if (t->n_own_tried < SCHED_FAILED_PLANS) {
        t->own_tried[t->n_own_tried++] = h;
        return;
    }
    memmove(t->own_tried, t->own_tried + 1,
            (SCHED_FAILED_PLANS - 1) * sizeof t->own_tried[0]);
    t->own_tried[SCHED_FAILED_PLANS - 1] = h;
}

static void plan_ident(const char *text, char *id, size_t cap,
                       uint8_t wire[D2K_PLAN_ID_LEN]) {
    snprintf(id, cap, "plan-%08x", (unsigned)(fnv1a(text) & 0xFFFFFFFFu));
    memset(wire, 0, D2K_PLAN_ID_LEN);
    size_t n = strlen(id);
    if (n > D2K_PLAN_ID_LEN) { n = D2K_PLAN_ID_LEN; }
    memcpy(wire, id, n);
}

static int is_hex_digit(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/* Подставляет идентификатор в строку "id <32 hex>" текста плана НА МЕСТЕ.
 * 0 — подставлено, -1 — такой строки в тексте нет.
 *
 * Длина не меняется: тридцать два шестнадцатеричных знака были и остались,
 * поэтому переписывание идёт прямо в буфере, а остальной текст не двигается и
 * не перестраивается. Второго сборщика текста плана здесь не заводится (§2.5):
 * правится ровно одно поле уже собранного. */
/* Форма приветствия, которым пойдёт наш зонд. Снимок в датапате — нагрузка
   одного пакета, и у браузерного приветствия форма по нему может не
   разобраться вовсе. Ограничивать нечем — объявляем дедушкино право: иначе
   план-кандидат не применится ни к чему, включая собственный зонд. План при
   этом временный и снимается по итогам испытания. */
/* ФОРМА ПЛАНА-ВОПРОСА — ИЗ ТЕХ БАЙТ, КОТОРЫЕ ВОПРОС И ПОШЛЁТ.
 *
 * Диагностический вопрос воспроизводит приветствие КЛИЕНТА: JOB_CONTACT шлёт
 * t->trig как есть. Объявить плану форму собственного зонда значит объявить
 * не ту: план не применится к отправленным байтам, и вопрос вернётся без
 * измеренного ответа — молча, как «коробка ничего не сделала» (0010, R2).
 * Ровно это я и сломал 13.09, сведя оба контекста к одной константе.
 *
 * Снимок неполный или форма не разобралась — дедушкино право: вопрос живёт
 * ровно один опыт и снимается сразу, а не применить его вовсе значит не
 * задать вопрос. Это НЕ «лечение общей совместимостью» подтверждённых
 * планов: там правило другое и строже (см. verify_confirm). */
static uint8_t question_shape(const task *t) {
    if (t->transport == 17) { return (uint8_t)D2K_LINK_SHAPE_QUIC; }
    d2k_shape sh = d2k_hello_shape(t->trig, t->trig_len);
    return (sh == D2K_SHAPE_UNKNOWN) ? (uint8_t)D2K_LINK_SHAPE_GRANDFATHER
                                     : (uint8_t)sh;
}

static uint8_t probe_shape(const task *t) {
    if (t->transport == 6 && t->ech_offer) return D2K_LINK_SHAPE_ECH_TCP;
    /* У QUIC форма своя и известна ЗАРАНЕЕ, из транспорта: перечисление
       d2k_shape знает только формы TLS, и вывести по нему тройку неоткуда.
       Пока этого не было, план QUIC-задачи уезжал формой MODERN, а таблица
       планов датапата на UDP отдаёт план только форме QUIC (или дедушкиному
       праву) — собственный кандидат был невидим для тех самых датаграмм,
       ради которых ставился. */
    if (t->transport == 17) { return (uint8_t)D2K_LINK_SHAPE_QUIC; }
    /* ФОРМА ЗОНДА, А НЕ КЛИЕНТА. Здесь стоял разбор снимка КЛИЕНТА, и это
       было прямой ошибкой: план ставится ради испытания, а испытывает его
       НАШ зонд. Когда у клиента форма другая, план вставал под клиентскую и
       к потоку зонда не применялся вовсе: «зонд прошёл, а применения этого
       плана к его потоку не было» — успех выброшен. На роутере владельца
       13.09.2026 таких выброшенных успехов набралось 269.

       НО ФОРМА ЗОНДА БОЛЬШЕ НЕ ОДНА. С 17.09 со старым клиентом зонд ведёт
       рукопожатие TLS 1.2 (d2k_verify_probe12_on), и его приветствие тогда
       СТАРОЙ формы. Константа здесь снова разошлась бы с проводом — только в
       другую сторону: план встал бы современным, а зонд пришёл бы старым, и
       к его же потоку план не применился бы. Поймано стендом с цензором на
       клиенте, говорящем только по 1.2: «нет TLS 1.2: не дождались 5 байт»
       на каждом кандидате подряд.

       Поэтому форма выводится из ТОГО ЖЕ правила, по которому выбирается
       протокол зонда (verify_default): старый клиент — старая форма. */
    if (d2k_hello_shape(t->trig, t->trig_len) == D2K_SHAPE_LEGACY) {
        return (uint8_t)D2K_SHAPE_LEGACY;
    }
    return (uint8_t)SCHED_PROBE_SHAPE;
}

static int stamp_plan_id(char *text, const uint8_t id[D2K_PLAN_ID_LEN]) {
    static const char digits[] = "0123456789abcdef";
    char *p = text;
    while (p) {
        if (strncmp(p, "id ", 3) == 0) {
            char *v = p + 3;
            while (*v == ' ') { v++; }
            size_t n = 0;
            while (n < 2 * D2K_PLAN_ID_LEN && is_hex_digit(v[n])) { n++; }
            if (n != 2 * D2K_PLAN_ID_LEN) { return -1; }
            for (size_t i = 0; i < D2K_PLAN_ID_LEN; i++) {
                v[2 * i]     = digits[id[i] >> 4];
                v[2 * i + 1] = digits[id[i] & 0x0Fu];
            }
            return 0;
        }
        p = strchr(p, '\n');
        if (p) { p++; }
    }
    return -1;
}

/* --------------------------------------------------------------------
 * Ход задачи.
 * -------------------------------------------------------------------- */

/* --------------------------------------------------------------------
 * Вопросы о свойствах коробки — конечный автомат, который двигает ЦИКЛ.
 *
 * Почему не d2k_props_ask: та блокирующая и читает управляющий сокет сама
 * (см. правку плана 11.09 и шапку d2k_sched.h). Смысл вопросов при этом
 * общий на обе стороны — d2k_props_question_plan/d2k_props_question_passed,
 * d2k_compose_internal.h: две копии этой развилки разошлись бы молча, и
 * вектор свойств стал бы зависеть от того, кто спрашивал.
 * -------------------------------------------------------------------- */

/* Обнулённая задача — это prop_fd == 0, а НЕ «нет сокета»: ноль это законный
   дескриптор (стандартный ввод), и закрывать его по такому признаку значит
   закрывать чужое. Первый прогон с вопросами так и падал: задача после
   memset закрывала дескриптор 0, дальше номер переиспользовался, и однажды на
   нём оказался читающий конец будилки планировщика — рабочий поток получал
   SIGPIPE и убивал весь процесс. Отсюда две вещи: task_reset ниже ставит -1
   явно, а эта функция не верит нулю. */
static void prop_close(task *t) {
    if (t->prop_fd > 0) {
        close(t->prop_fd);
    }
    t->prop_fd = -1;
}

/* Сокет обращения, который рабочий поток JOB_CONTACT вернул, а задача ещё
   не приняла в prop_fd (финальное ревью core, M2): срок жизни проверяется
   раньше разбора состояния, и задача, умершая в T_PROPS_CONTACT, теряла
   помеченный TCP-сокет. Звать только после join_worker. */
static void contact_close(task *t) {
    if (t->c_fd > 0) {
        close(t->c_fd);
    }
    t->c_fd = -1;
}

/* Закрывает сокет зонда подтверждения. Не зовёт d2k_verify_close на нуле по
   той же причине, по которой prop_close не верит нулю выше: обнулённая задача
   это fd == 0, а ноль — законный дескриптор, и «закрыть пустое» означало бы
   закрыть чужое. */
static void ver_close(task *t) {
    if (t->ver.fd > 0) {
        d2k_verify_close(&t->ver);
    }
    t->ver.fd = -1;
}

/* Единственное место, где задача обнуляется. Не memset на месте: у неё есть
   поле, чей «пусто» не ноль (см. prop_close выше), и разложить это по всем
   точкам сброса значило бы завести столько же мест, где про него забудут. */
static void search_report(d2k_sched *s, task *t, int64_t now_ms,
                          const char *outcome, const char *path, const char *why);

static void stun_retire(d2k_sched *s, task *t) {
    if (!t->stun_trial) return;
    join_worker(t);
    if (d2k_stun_trial_get_state(t->stun_trial) == D2K_STUN_TRIAL_RUNNING)
        (void)d2k_stun_trial_finished(t->stun_trial);
    (void)d2k_stun_trial_retire(t->stun_trial, s->link_fd, NULL, 0);
    (void)d2k_stun_trial_defer(&t->stun_trial);
    t->stun_socket = NULL;
}

static void task_reset(d2k_sched *s, task *t) {
    gate_retire(s,t);
    stun_retire(s, t);
    if ((t->state == T_STUN_CLIENT || t->state == T_VOICE_INSTALL) && t->addr_probe_identity_valid) {
        char err[160];
        (void)addr_probe_remove(s,t,err,sizeof err);
    }
    search_report(s, t, s->now_ms, "local-abort", NULL, "задача сброшена локально: поиск не кончался");
    if (t->prop_bound_fd > 0) { close(t->prop_bound_fd); }
    /* СТРОГО БОЛЬШЕ НУЛЯ. Задачи живут в занулённом массиве, и при самом
       первом сбросе здесь лежит ноль — не «сокет номер ноль», а «поля ещё не
       трогали». Закрыть его значит закрыть стандартный ввод процесса: тест
       ловил это немедленной смертью по SIGPIPE. */
    if (t->probe_fd > 0) { close(t->probe_fd); }
    if(t->synthesis_release)t->synthesis_release(t->synthesis_context);
    d2k_verification_free(t->synthesis_owner);
    d2k_run_cache_clear(&t->run_cache);
    memset(t, 0, sizeof *t);
#if (defined(__linux__) || defined(D2K_TEST_PAGE_RELEASE)) && defined(MADV_DONTNEED)
    /* ЯЧЕЙКА ОТДАЁТ ПАМЯТЬ (задача 60). memset выше касается всех ~114 КиБ
       ячейки, и каждая хоть раз занятая ячейка оставалась в RSS навсегда —
       до 7,3 МиБ на 64 ячейки: ровно «растёт до перезапуска» (жалоба
       14.10.2026, Netis N6: d2kc 10,6 → 29,1 МБ за 1 д 9 ч). Целые страницы
       внутри ячейки возвращаются ядру; частная анонимная память при следующем
       касании приходит нулями — то же, что записал memset. */
    {
        uintptr_t pg = (uintptr_t)sysconf(_SC_PAGESIZE);
        uintptr_t a = ((uintptr_t)t + pg - 1) & ~(pg - 1);
        uintptr_t b = ((uintptr_t)t + sizeof *t) & ~(pg - 1);
        if (pg && b > a) {
            size_t bytes = (size_t)(b - a);
            s->memory.task_madvise_calls++;
            s->memory.task_madvise_requested_bytes += bytes;
            int rc = madvise((void *)a, bytes, MADV_DONTNEED);
            s->memory.task_madvise_last_errno = rc == 0 ? 0 : (uint64_t)errno;
            if (rc == 0) s->memory.task_madvise_successes++;
        }
    }
#endif
    t->prop_fd = -1;
    t->prop_q = -1;
    t->probe_fd = -1;   /* та же ловушка нуля, что у prop_fd */
    t->ver.fd = -1; /* та же ловушка нуля, что у prop_fd, — см. prop_close */
    t->c_fd = -1;   /* и у сокета обращения (contact_close) */
}

/* КОРОБКА, КОТОРАЯ ВБРАСЫВАЕТ СБРОС, ЗАСЛУЖИВАЕТ ЗАЩИТЫ ОТ СБРОСА.
 *
 * Поле 13.10.2026, forum.ru-board.com, прогон 14:23: рукопожатие снято
 * найденным замером приёмом, план применился ко ВСЕМ 133 потокам браузера, и
 * сервер ответил всем. При этом коробка вбросила сброс в 132 потока из 133 —
 * с TTL 127, тогда как данные сервера шли с TTL 55–57, — и КАЖДЫЙ такой сброс
 * попал в окно приёма. Главный документ успевал прийти, а запросы картинок
 * умирали: ядро принимало подделку и закрывало соединение.
 *
 * Защита для этого уже есть и реализована в датапате (D2K_GUARD_RST_ALIEN,
 * d2k_plan.h): снять входящий RST, чей TTL не совпадает с TTL ответов ЭТОГО
 * ЖЕ потока. Ориентир берётся из самого потока, не из константы. Но строку
 * `guard rst_alien` не выдавал НИ ОДИН сборщик — возможность была мёртвой:
 * формат её разбирает, датапат исполняет, просить её было некому.
 *
 * Просится она по измеренному поводу, а не всем подряд: поиск начался со
 * сброса (подозрение RST, «чужой сброс снят» или RST после прикладных
 * данных). У цели, которую режут тишиной или объёмом, повода нет. */
/* Коробка, чей ОТПЕЧАТОК несёт примету «rst», — та самая, что вбрасывает
   сброс. Примета измеренная, из каталога (d2k_cat_signal.kind), а не
   догадка: её записал тот же замер, который нашёл обход. */
static int box_injects_rst(const d2k_cat_box *b) {
    if (!b) { return 0; }
    for (size_t i = 0; i < b->fp.n_sig; i++) {
        if (!strcmp(b->fp.sig[i].kind, "rst")) { return 1; }
    }
    return 0;
}

static int rst_guard_wanted(const task *t) {
    return t->transport == 6 &&
           (t->trigger_code == D2K_SUSPECT_RST ||
            t->trigger_code == D2K_SUSPECT_RST_CUT ||
            t->trigger_code == D2K_SUSPECT_RST_AFTER_APP);
}

/* Дописывает защиту в текст плана НА МЕСТЕ: 1 — дописана, 0 — уже есть либо
   не поместилась (тогда план идёт как был — защита не повод его потерять).
   Строка добавляется в конец: plantlv разбирает текст по словам, порядок
   строк для неё не значим, а запись в провод она укладывает сама. */
static int plan_arm_rst_guard(char *text, size_t cap) {
    static const char line[] = "guard rst_alien\n";
    size_t n = strlen(text);
    if (strstr(text, "guard ")) { return 0; }
    if (n + sizeof line > cap) { return 0; }
    memcpy(text + n, line, sizeof line);
    return 1;
}

/* Отправляет план следующего задаваемого вопроса. 0 — отправлен (ждём ack),
   -1 — вопросов больше нет. */
static int prop_send_next(d2k_sched *s, task *t, int64_t now_ms) {
    /* Тело фальшивки — двойная длина правды (build_fake_body в compose.c), а
       правда бывает размером с приветствие браузера. Потолок тот же, что у
       опросника из командной строки. */
    static uint8_t planbuf[2 * 1800 + 256];
    static char hex[2 * sizeof planbuf + 1];
    d2k_hello ctl = {0}; ctl.bytes = t->ctrl_len ? t->ctrl : NULL; ctl.len = t->ctrl_len;

    /* План ПРЕЖНЕГО вопроса снимается до следующего (задача 20): иначе на
       датапате копились пробные записи по уже свободным портам вопросов. */
    question_retire(s, t);
    while (++t->prop_q < D2K_PROPS_QUESTIONS) {
        size_t plan_len = 0;
        if (d2k_props_question_plan(t->prop_q, ctl, t->trig_len,
                                    planbuf, sizeof planbuf, &plan_len) != 0) {
            continue; /* этот вопрос сегодня не собрать — не измерено, а не «нет» */
        }
        /* Удостоверяем план вопроса — тем же способом, что и кандидата
           (plan_ident/stamp_plan_id выше) и что опросник из командной
           строки: у обоих опросников один контракт доказательства (0009, U1).
           Без идентификатора «применён» приписывается только по ключу
           потока, а на том же ключе мог примениться другой план. */
        if (plan_tlv_stamp_ident(planbuf, plan_len, t->prop_plan_id) != 0) {
            continue; /* раскладка не та — вопрос без идентичности не задаём */
        }
        if (fresh_trial_id(t->prop_plan_id) != 0) {
            continue;
        }
        /* stamp_ident above validated the first REC_ID at header12+record4. */
        memcpy(planbuf + 16, t->prop_plan_id, D2K_PLAN_ID_LEN);
        static const char digits[] = "0123456789abcdef";
        for (size_t i = 0; i < plan_len; i++) {
            hex[2 * i] = digits[planbuf[i] >> 4];
            hex[2 * i + 1] = digits[planbuf[i] & 0x0F];
        }
        hex[2 * plan_len] = '\0';
        char err[160];
        /* ПОРТ ВОПРОСА ЗАНИМАЕТСЯ ДО УСТАНОВКИ ПЛАНА, и без него вопрос не
           задаётся вовсе (0010, R1). Иначе план-вопрос встаёт по имени и
           достаётся всем клиентским соединениям к этой цели — испытание
           снова идёт за счёт человека, а «цель молчит» снова означает сразу
           «коробка режет» и «наш же вопрос сломал».

           Неудача bind — ЛОКАЛЬНЫЙ отказ: вопрос остаётся «не измерен», а не
           превращается в общий пробный план. */
        if (t->prop_bound_fd > 0) { close(t->prop_bound_fd); t->prop_bound_fd = -1; }
        t->prop_sport_be = 0;
        {
            int bfd = -1;
            uint16_t bsp = 0;
            int bound = d2k_sched_bind_hook(t->transport, t->family, &bfd, &bsp);
            if (bound != 0 || bsp == 0) {
                continue; /* порт не занят — вопрос не задаём */
            }
            t->prop_bound_fd = bfd;
            t->prop_sport_be = bsp;
        }
        if (s->mark && d2k_sched_mark_hook(t->prop_bound_fd, s->mark) != 0) {
            say(s, "по %s сокет вопроса не помечен — опыт не запускаю", t->name);
            close(t->prop_bound_fd);
            t->prop_bound_fd = -1;
            t->prop_sport_be = 0;
            continue;
        }
        /* Форма приветствия вопроса — та же, что у снятого триггера. */
        if (d2k_link_set_name_family(s->link_fd, t->name, t->transport, hex,
                                    question_shape(t), t->prop_sport_be,
                                    t->family, err, sizeof err) != 0) {
            close(t->prop_bound_fd);
            t->prop_bound_fd = -1;
            t->prop_sport_be = 0;
            continue; /* план-вопрос не ушёл — не наше наблюдение о коробке */
        }
        t->props_asked = 1;
        t->prop_installed = 1;
        t->probes++;
        s->probes_used++;
        t->prop_applied = 0;
        t->prop_early_seen = 0;
        t->prop_early_x_seen = 0;
        t->prop_reply_seen = 0;
        /* Подтверждения команды НЕ ждём, и это не спешка.
         *
         * Привязать подтверждение к своей команде можно было бы только по
         * порядку: D2K_EV_ACK несёт тип команды и код, но не имя цели. А
         * порядок здесь неприменим, потому что события у датапата ЛОССИ по
         * контракту (d2k_ctl.h, дословно): «Событие — сообщение, а не
         * обязательство. Не поместилось в сокет — потеряно и посчитано».
         * Живой прогон это и показал: после прохода по каталогу (371 команда
         * разом) очередь ожидаемых подтверждений разъехалась навсегда, и ВСЕ
         * пять вопросов молча упирались в тайм-аут, ни разу не дойдя до цели.
         *
         * Вместо подтверждения берём то, что нельзя потерять незаметно:
         * D2K_EV_APPLIED по КЛЮЧУ НАШЕГО ПОТОКА. Он говорит не «план принят на
         * хранение», а «план применён к этим самым пакетам» — то есть ровно
         * то, что вопросу и нужно знать. Не пришёл — ответ не засчитывается
         * (не измерено, а не «нет»): иначе зонд мерил бы линию БЕЗ обхода,
         * считая, что мерит с обходом (docs/field/2026-09-05-active-probe.md). */
        t->state = T_PROPS_CONTACT;
        t->prop_until_ms = now_ms + SCHED_PROP_STEP_MS;
        if (start_worker(s, t, JOB_CONTACT) != 0) {
            continue; /* поток не завёлся — вопрос не задан, берём следующий */
        }
        return 0;
    }
    return -1;
}

/* Вопросы кончились: снять план последнего (он не сработал) и идти собирать
   кандидатов по накопленному вектору. */
static void prop_finish(d2k_sched *s, task *t) {
    /* Иначе на боевом датапате остался бы стоять план, про который это же
       измерение только что сказало «не работает» (см. d2k_props_ask). Снятие
       точное, по порту вопроса: широкая DEL_NAME задела бы подтверждённое. */
    question_retire(s, t);
    prop_close(t);
    t->prop_q = -1;
    /* Проход каталога после вопросов (задача 21). Снятие вопроса точное и
       подтверждённое не трогает, но проход — единственный владелец установки
       постоянных планов (d2k_sched_sync_step), и после опыта знание цели
       обязано стоять на проводе, что бы ни случилось с таблицей датапата за
       время опроса (вытеснение LRU пробами вопросов). Кандидату, который
       встанет следом, проход не мешает: его запись пробная, по своему порту,
       и постоянная SET_NAME её не затирает (plans.c, find_name_shape_port). */
    s->sync_pending = 1;
}

static void quic_deny_install(d2k_sched *s, task *t, int64_t now_ms);

static void wake_loop(d2k_sched *s);
static void task_fail(d2k_sched *s, task *t, int64_t now_ms) {
    t->partial_valid = 0; /* поиск кончился — его частичный обход ему и принадлежал */
    join_worker(t);
    search_report(s, t, now_ms, "failed", NULL, "кандидаты кончились, ни один не подтверждён зондом");
    contact_close(t);
    if (t->transport == 17 && t->stall_cut) {
        t->stall_cut = 0;
        quic_deny_install(s, t, now_ms);
    }
    /* И вопрос, и кандидат — каждый своим ключом (задача 20). Прежде порт
       вопроса проверялся первым и, оставшись в памяти после вопросов, уводил
       снятие на давно снятый вопрос, а стоящий кандидат оставался. */
    trial_retire(s, t);
    prop_close(t);
    ver_close(t);
    /* ПРОХОД ПО КАТАЛОГУ ПОСЛЕ НЕУДАЧИ — не перестраховка.
       Второй поиск по УЖЕ ПОДТВЕРЖДЁННОЙ цели — обычное дело: новое
       подозрение закрывает наблюдение и заводит поиск заново. Пробный план
       такого поиска встаёт на то же имя ПОВЕРХ подтверждённого, а снятие
       уносит их вместе. В каталоге «подтверждено», в датапате пусто, у
       человека обхода нет.

       Поймано лабораторией с памятью 13.09.2026: на проверке настоящим
       клиентом датапат отвечал «плана для этой цели нет» — при непустом
       каталоге и записанной привязке.

       Восстанавливает знание не эта функция, а проход по каталогу: у
       установки планов один владелец (d2k_sched_sync_step), и вторая
       реализация разошлась бы с ним молча (§2.5). С пробными записями по
       порту зонда проход больше не перетирает следующего кандидата, поэтому
       его заказывает и prop_finish (задача 21). */
    s->sync_pending = 1;
    t->state = T_RESTING;
    t->rest_until_ms = now_ms + SCHED_REST_MS;
    if(force_name(s,t->name)) {
        t->rest_until_ms=now_ms;
        say(s,"принудительный поиск: %s — опыт не подтверждён (%s); отсрочка отключена",t->name,t->res.reason);
        wake_loop(s);
    }
    t->n_plans = 0;
    t->next_plan = 0;
    t->fb_queue = 0;
}

static quic_deny_slot *quic_deny_find(d2k_sched *s, const char *name, uint8_t family) {
    for (size_t i = 0; i < SCHED_QUIC_DENY_SLOTS; i++) {
        quic_deny_slot *q = &s->quic_deny[i];
        if (q->used && q->family == family && !strcmp(q->name, name)) return q;
    }
    return NULL;
}

static void quic_deny_install(d2k_sched *s, task *t, int64_t now_ms) {
    uint8_t family = t->family ? t->family : 4;
    quic_deny_slot *q = quic_deny_find(s, t->name, family);
    if (!q) {
        quic_deny_slot *victim = NULL;
        for (size_t i = 0; i < SCHED_QUIC_DENY_SLOTS; i++) {
            quic_deny_slot *c = &s->quic_deny[i];
            if (!c->used) { victim = c; break; }
            if (!c->active && (!victim || victim->active || c->until_ms < victim->until_ms))
                victim = c;
        }
        if (!victim) {
            say(s, "по %s (QUIC) обхода по QUIC нет, но мест для снятия QUIC нет — "
                   "оставляю как есть", t->name);
            return;
        }
        q = victim;
        memset(q, 0, sizeof *q);
        snprintf(q->name, sizeof q->name, "%s", t->name);
        q->family = family;
        q->used = 1;
    }
    char text[256], hex[2 * D2K_PLAN_TLV_MAX + 1], err[160], plan_id[40];
    uint8_t wire_id[D2K_PLAN_ID_LEN];
    snprintf(text, sizeof text, "d2k-plan 1 11\nid 00000000000000000000000000000000\n"
                                "proto udp quic\nquicdeny 1\norder forward\n");
    plan_ident(text, plan_id, sizeof plan_id, wire_id);
    err[0] = '\0';
    if (stamp_plan_id(text, wire_id) != 0 ||
        d2k_plan_text_to_hex(text, hex, sizeof hex, err, sizeof err) != 0 ||
        d2k_link_set_name_family(s->link_fd, t->name, 17, hex, D2K_LINK_SHAPE_QUIC, 0,
                                 family, err, sizeof err) != 0) {
        say(s, "по %s (QUIC) снять QUIC не удалось: %s", t->name, err[0] ? err : "ошибка записи");
        return;
    }
    if (q->streak < UINT8_MAX) q->streak++;
    int64_t dur = clear_backoff_ms(q->streak);
    q->until_ms = now_ms + dur;
    q->active = 1;
    q->rechecking = 0;
    snprintf(q->ip, sizeof q->ip, "%s", t->ip);
    q->port = t->port;
    if (t->trig_len && t->trig_len <= sizeof q->trig) {
        memcpy(q->trig, t->trig, t->trig_len);
        q->trig_len = t->trig_len;
    }
    /* I2 (раунд 3): подтверждённая QUIC-привязка этого имени под
       воспроизведённым обрывом не работает — повторная проверка (задача 21:
       каталог цел, с провода снята — запрет встал на её место, проход
       каталога её не вернёт). */
    if (s->cat) {
        size_t marked = 0;
        for (size_t bi = 0; bi < s->cat->n_boxes; bi++) {
            d2k_cat_box *b = &s->cat->boxes[bi];
            for (size_t j = 0; j < b->n_binds; j++) {
                d2k_cat_binding *bd = &b->binds[j];
                if (!bd->enabled || bd->recheck_since || strcmp(bd->kind, "name") ||
                    strcmp(bd->target, t->name) || (bd->transport ? bd->transport : 6) != 17 ||
                    (bd->family ? bd->family : 4) != family) continue;
                bd->recheck_since = wall_s(s, now_ms);
                bd->recheck_mono_ms = now_ms ? now_ms : 1;
                b->updated = bd->recheck_since;
                say(s, "по %s (QUIC) привязка %s не проходит обрыв после рукопожатия — "
                       "помечена на повторную проверку (каталог сохранён)", t->name, bd->plan_id);
                marked++;
            }
        }
        if (marked) s->cat->revision++;
    }
    say(s, "по %s (QUIC) обрыв после рукопожатия воспроизведён своим запросом, обхода по QUIC "
           "нет — QUIC для имени не пропускаю %lld мин: браузер уйдёт на TCP (это не обход QUIC, "
           "в каталог не пишется)", t->name, (long long)(dur / 60000));
}

static int quic_deny_active(const d2k_sched *s, const char *name, uint8_t family) {
    for (size_t i = 0; i < SCHED_QUIC_DENY_SLOTS; i++) {
        const quic_deny_slot *q = &s->quic_deny[i];
        if (q->used && q->active && q->family == family && !strcmp(q->name, name)) return 1;
    }
    return 0;
}

static int gate_start(d2k_sched *,task *,const d2k_box_props *,int);
static int launch_or_queue(d2k_sched *s, task *t);
static void task_done(d2k_sched *s, task *t);
static task *task_of(d2k_sched *s, const char *name, uint8_t transport, uint8_t family);
static task *task_free_slot(d2k_sched *s);

/* Перед снятием — своя перепроверка (раунд 3): задача по тем же адресу и
   Initial, только прямые запросы. 1 — запущена или уже идёт. */
static int quic_deny_recheck(d2k_sched *s, quic_deny_slot *q) {
    task *t = task_of(s, q->name, 17, q->family);
    if (t && t->state != T_RESTING) return 1;      /* поиск по имени уже идёт */
    if (t) { task_done(s, t); }
    if (!q->trig_len || !q->ip[0]) return 0;
    t = task_free_slot(s);
    if (!t) return 0;
    task_reset(s, t);
    snprintf(t->name, sizeof t->name, "%s", q->name);
    t->transport = 17;
    t->family = q->family;
    snprintf(t->ip, sizeof t->ip, "%.*s", (int)sizeof t->ip - 1, q->ip);
    t->port = q->port;
    memcpy(t->trig, q->trig, q->trig_len);
    t->trig_len = q->trig_len;
    t->trig_snapped = 1;
    t->trigger_code = D2K_SUSPECT_QUIC_STALL;
    t->trigger_planned = D2K_LINK_PLANNED_NO;
    t->deny_recheck = 1;
    t->fp.method = D2K_FP_METHOD;
    say(s, "по %s (QUIC) срок запрета QUIC вышел — сначала проверяю своим запросом HTTP/3, "
           "встаёт ли ответ по-прежнему", q->name);
    if (!launch_or_queue(s, t) && t->state == T_FREE) return 0;
    return 1;
}

static void quic_deny_tick(d2k_sched *s, int64_t now_ms) {
    for (size_t i = 0; i < SCHED_QUIC_DENY_SLOTS; i++) {
        quic_deny_slot *q = &s->quic_deny[i];
        if (!q->used || !q->active || now_ms < q->until_ms) continue;
        if (!q->rechecking) {
            if (quic_deny_recheck(s, q)) { q->rechecking = 1; continue; }
        } else {
            /* Перепроверка ещё идёт — запрет стоит. Встала снова — её
               task_fail уже продлил запрет (rechecking снят). */
            task *t = task_of(s, q->name, 17, q->family);
            if (t && t->deny_recheck && t->state != T_RESTING && t->state != T_FREE) continue;
        }
        char err[160];
        err[0] = '\0';
        q->active = 0;
        q->rechecking = 0;
        if (d2k_link_del_name_family(s->link_fd, q->name, 17, D2K_LINK_SHAPE_QUIC, q->family,
                                     err, sizeof err) != 0) {
            say(s, "по %s (QUIC) снятие запрета QUIC не ушло: %s", q->name, err);
        }
        /* Подтверждённая QUIC-привязка того же имени (если появилась) вернётся
           проходом каталога. */
        s->sync_pending = 1;
        say(s, "по %s (QUIC) своя перепроверка обрыв не воспроизвела (или не состоялась) — "
               "снимаю запрет QUIC; следующий обрыв измерю заново", q->name);
    }
}

static void task_done(d2k_sched *s, task *t) {
    join_worker(t);
    if(t->state==T_DNS_PLAIN_TRIAL)trial_retire(s,t);
    search_report(s, t, s->now_ms, "cancelled", NULL, "задача снята до исхода: цель больше не ищется");
    contact_close(t);
    prop_close(t);
    ver_close(t);
    task_reset(s, t);
    t->state = T_FREE;
}

/* ИМЯ ПРИМАНКИ RX-ЛЕСТНИЦЫ: подтверждённое белое имя сети, иначе семя
   (восстановленная ручная команда взяла hcaptcha.com, поле 10.10.2026). */
static const char *rx_decoy_name(const d2k_sched *s) {
    return s->cat && s->cat->net.name[0] ? s->cat->net.name : "hcaptcha.com";
}

/* Белое имя сети ещё не решено: не подобрано И не записано честное «не
   найдено». Только тогда уместен перебор кандидатов (иначе — семя/готовое). */
static int net_whitelist_undecided(const d2k_sched *s) {
    return s->cat && !s->cat->net.searched && !s->cat->net.name[0];
}

/* Нужен ли подбор ИМЕННО ЭТОЙ задаче (поле 23.10.2026). Кроме нерешённого
   имени подбор открывает ещё один случай: имя записано, но доказано только
   проходом ИСХОДЯЩЕЙ лестницы, а у этой задачи обрыв ВХОДЯЩИЙ — против него
   имя не проверялось. Семь целей парного прогона наследовали такое имя и
   рвали тело на 13–17 КБ при ответе 200. Цена названа: список имён, и потолок
   зондов на время подбора уже расширен (sched_probe_cap). */
static int net_whitelist_needs_probe(const d2k_sched *s, const task *t) {
    if (net_whitelist_undecided(s)) { return 1; }
    return t->vol.rx_cut && s->cat && s->cat->net.name[0] && s->cat->net.tx_only;
}

/* Потолок зондов задачи. Подбор белого имени сети перебирает до сотен
   кандидатов (цена названа прямо, §0 «искусственных бюджетов нет»): пока он
   идёт, потолок расширен на длину списка — только для этой задачи, обычный
   поиск остаётся на базовом бюджете. */
static int sched_probe_cap(const task *t) {
    return SCHED_MAX_PROBES + (t->net_probing ? (int)d2k_net_whitelist_count() : 0);
}

/* ОБРЫВ ОБЪЁМА ИЗМЕРЕН — В ЛЮБУЮ СТОРОНУ (поле 17.10.2026, spzh.eu): RX-проба
   получает 403 на 4540 Б, а исходящая лестница рвётся на ~19 КБ — это та же
   коробка, и вопрос к ней тот же: белое имя. Объём для журнала — измеренный. */
static int vol_cut_measured(const task *t) {
    return t->vol.rx_cut || t->vol.verdict == D2K_VOL_CUT;
}
static int vol_cut_kb(const task *t) {
    return t->vol.rx_cut ? t->vol.rx_at_kb : t->vol.at_kb;
}

/* Ещё есть что долить в RX-лестницу: в режиме подбора — непройденные имена
   списка, иначе — непройденные варианты разреза. */
static int rx_ladder_pending(const task *t) {
    return t->net_probing ? t->net_probe_next < d2k_net_whitelist_count()
                          : t->rx_volume_next_variant < D2K_RX_VOLUME_PLAN_VARIANTS;
}

/* ДОЛИВАЕТ ОЧЕРЕДЬ ИЗ ЗАПАСНОГО ПЕРЕБОРА — третий источник кандидатов после
   готовых планов коробки и синтеза по измеренному вектору (0007/0008).
   Это часть перенесённого поиска, не внешний пул заранее назначенных целей.
   Возвращает число долитых планов. */
static int next_rx_volume_plan(d2k_sched *s, task *t, d2k_shape sh,
                               char *text, size_t cap) {
    t->net_probe_scratch[0] = '\0';
    /* ПОДБОР БЕЛОГО ИМЕНИ СЕТИ: одно имя-кандидат за раз, приманкой перед
       настоящим ClientHello, разрез +2 (variant 0). Первое, что снимет
       RX-обрыв (план подтвердится), и есть белое имя — его запишет
       verify_confirm, прочитав net_probe_name слота. */
    if (t->net_probing) {
        while (t->net_probe_next < d2k_net_whitelist_count()) {
            const char *name = d2k_net_whitelist_name(t->net_probe_next++);
            if (!name || d2k_rx_volume_plan_client(0, sh, s->send_cap, name,
                                                  client_offers_ts(t), text, cap) != 0) {
                continue;
            }
            uint32_t h = fnv1a(text);
            int seen = 0;
            for (size_t i = 0; i < t->n_plans && !seen; i++) {
                if (strcmp(t->plans[i], text) == 0) { seen = 1; }
            }
            for (size_t i = 0; i < t->n_tried && !seen; i++) {
                if (t->tried[i] == h) { seen = 1; }
            }
            if (seen) { continue; }
            tried_add(t, h);
            snprintf(t->net_probe_scratch, sizeof t->net_probe_scratch, "%s", name);
            return 1;
        }
        return 0;
    }
    const char *decoy = rx_decoy_name(s);
    while (t->rx_volume_next_variant < D2K_RX_VOLUME_PLAN_VARIANTS) {
        unsigned variant = t->rx_volume_next_variant++;
        if (d2k_rx_volume_plan_client(variant, sh, s->send_cap, decoy,
                                      client_offers_ts(t), text, cap) != 0) { continue; }
        uint32_t h = fnv1a(text);
        int seen = 0;
        for (size_t i = 0; i < t->n_plans && !seen; i++) {
            if (strcmp(t->plans[i], text) == 0) { seen = 1; }
        }
        for (size_t i = 0; i < t->n_tried && !seen; i++) {
            if (t->tried[i] == h) { seen = 1; }
        }
        if (seen) { continue; }
        tried_add(t, h);
        t->rx_hashes[t->n_rx_hashes++ % D2K_RX_VOLUME_PLAN_VARIANTS] = fnv1a(text);
        return 1;
    }
    return 0;
}

/* ОПРОС ДОСПРАШИВАЕТСЯ ПОСЛЕ ОПРОВЕРГНУТОГО ПРИЁМА (24.10.2026).
 *
 * Опрос свойств кончается на ПЕРВОМ прошедшем вопросе (detect/props.c), и его
 * приём становится первым кандидатом. Если применённый поток этот приём
 * опроверг, «да» на вопросе не становится «нет»: спрашивать его заново — тот
 * же план, а идти в чужой список гипотез — бросать НЕЗАДАННЫЕ вопросы о той
 * же коробке. Поэтому имя приёма едет в список «не пробовать», измеренный
 * вектор — в знание, и задача возвращается к замеру.
 *
 * ЦЕНА. Продолжение стоит только незаданных вопросов: на заданные ответ уже
 * есть, и знание о коробке их снимает. В поле 24.10.2026 (clubtone.net,
 * выпуск 374a6df) опрос кончился на 4-м вопросе из 11, а вместо вопросов
 * 5–11 поиск взял 8 планов перебора: 51 зонд и страница не открылась. Тот же
 * вопрос 11 в двух других кругах давал план, под которым страница открывалась.
 *
 * 1 — опрос продолжится (researched сброшен, перебор не открывается);
 * 0 — продолжать нечем: приём не из опроса, имени нет, он уже опровергался
 * или опровергнуты все вопросы. */
static int arm_survey_resume(d2k_sched *s, task *t) {
    if (strcmp(t->arm_path, "свойство") != 0 || t->arm_name[0] == '\0') { return 0; }
    for (int i = 0; i < t->n_arm_refuted; i++) {
        if (!strcmp(t->arm_refuted[i], t->arm_name)) { return 0; }
    }
    if (t->n_arm_refuted >= SCHED_ARM_REFUTED_MAX) { return 0; }
    snprintf(t->arm_refuted[t->n_arm_refuted], sizeof t->arm_refuted[0], "%s", t->arm_name);
    t->n_arm_refuted++;
    /* Вектор ЭТОГО прогона — знание для следующего: вопрос с измеренным
       промахом второй раз не задаётся (detect/props.c, known_of). Без этого
       продолжение стоило бы полного опроса заново. */
    d2k_box_props_merge(&t->measured_props, &t->res.box_props);
    /* Возврат к замеру — существующей дорогой «готовые планы не помогли —
       начинаю новый замер»: она ждёт конца очереди кандидатов, поэтому
       уже выведенные из вектора планы испытываются первыми, как и раньше. */
    t->researched = 0;
    say(s, "по %s приём «%s» нашёл опрос, а применённый поток его опроверг — "
           "после оставшихся кандидатов доспрошу опрос со следующего вопроса "
           "(опровергнуто приёмов: %d), запасной перебор пока не открываю",
        t->name, t->arm_name, t->n_arm_refuted);
    return 1;
}

static size_t refill_from_fallback(d2k_sched *s, task *t) {
    /* Ownership of handshake synthesis does not cap an independently
       measured RX ladder at its first queue batch. Generic fallback stays
       closed; the RX branch below limits cap to the measured ladder. */
    if ((t->search_owned && !t->owned_fallback &&
         !(t->vol.rx_cut && t->rx_volume_candidate_pending)) || t->transport == 17) { return 0; }
    size_t cap = sizeof t->plans / sizeof t->plans[0];
    size_t added = 0;
    d2k_shape sh = d2k_hello_shape(t->trig, t->trig_len);
    while (t->rx_volume_candidate_pending && added < cap) {
        char text[sizeof t->plans[0]];
        if (!next_rx_volume_plan(s, t, sh, text, sizeof text)) {
            t->rx_volume_candidate_pending = 0;
            break;
        }
        snprintf(t->plans[added], sizeof t->plans[added], "%s", text);
        t->plan_boxes[added][0] = '\0';
        snprintf(t->net_probe_name[added], sizeof t->net_probe_name[added], "%s", t->net_probe_scratch);
        added++;
        if (t->net_probing) {
            say(s, "по %s подбор белого имени сети: кандидат %zu из %zu как приманка "
                   "снимает ли обрыв около %d КБ",
                t->name, t->net_probe_next, d2k_net_whitelist_count(), vol_cut_kb(t));
        } else {
            say(s, "по %s очередь кандидатов исчерпана — по замеренному обрыву входящего "
                "объёма около %d КБ проверяю fake-SNI + split-лестницу (%u/%u)",
                t->name, vol_cut_kb(t), t->rx_volume_next_variant,
                (unsigned)D2K_RX_VOLUME_PLAN_VARIANTS);
        }
    }
    /* ЛЕСТНИЦА — ТОЛЬКО ПО ЗАМЕРЕННОМУ ОБРЫВУ ОБЪЁМА, RX или TX (задача 37;
       TX — поле 17.10.2026, spzh). Прежде флаг
       взводился здесь безусловно, и любая цель на втором доливе получала
       все пять hcaptcha-планов: поле 02.10.2026, edge-mqtt-fallback, у
       коробки — только «rst», vol.rx_cut = 0. Условие лестницы — парный
       RX-volume-профиль (verdict_to_plans), а не исчерпание очереди. */
    t->rx_volume_candidate_pending = vol_cut_measured(t) && !t->ladder_unmeasurable &&
                                     rx_ladder_pending(t);
    size_t ladder = added;
    /* ЗАМЕРЕННЫЙ ОБРЫВ ОТВЕТА — ТОЛЬКО ЛЕСТНИЦА SNI. Обрыв меряется своим
       вопросом, и перебирать для него можно только имя (белое имя сети,
       fake-SNI + split); запасной список оригинала к обрыву отношения не
       имеет. Поле 14.10.2026, www.jetadmin.io: две ступени лестницы, затем
       четыре порции запасного перебора в той же задаче. */
    if (t->transport == 6 && t->vol.rx_cut) cap = added;
    if (added < cap && t->transport == 6 && !t->by_addr &&
        preflight_family_enabled(t->family) &&
        (d2k_domain_member(t->name,"googlevideo.com") ||
         d2k_domain_member(t->name,"c.youtube.com") ||
         d2k_domain_member(t->name,"gvt1.com"))) {
        char text[sizeof t->plans[0]];
        if (!d2k_compose_gv_reference(s->send_cap,text,sizeof text)) {
            uint32_t h=fnv1a(text);
            int seen=0;
            for(size_t i=0;i<t->n_tried;i++)if(t->tried[i]==h){seen=1;break;}
            if(!seen) {
                tried_add(t,h);
                snprintf(t->plans[added],sizeof t->plans[added],"%s",text);
                t->plan_boxes[added][0]='\0';
                t->net_probe_name[added][0]='\0';
                added++;
                say(s,"по %s: кандидат Z2K GV №1 после preflight; проверяю на этом адресе, без переноса успеха на другие",t->name);
            }
        }
    }
    while (added < cap) {
        char text[sizeof t->plans[0]];
        if (d2k_fallback_plan(t->fb_next, sh, SCHED_DECOY, s->send_cap,
                              text, sizeof text) != 0) {
            t->fb_next++;
            if (t->fb_next > D2K_FALLBACK_MAX) { break; }
            continue;
        }
        t->fb_next++;
        uint32_t h = fnv1a(text);
        int seen = 0;
        for (size_t i = 0; i < t->n_tried && !seen; i++) {
            if (t->tried[i] == h) { seen = 1; }
        }
        if (seen) { continue; }
        tried_add(t, h);
        snprintf(t->plans[added], sizeof t->plans[added], "%s", text);
        t->plan_boxes[added][0] = '\0';
        t->net_probe_name[added][0] = '\0'; /* не из подбора белого имени */
        added++;
    }
    if (added) {
        t->n_plans = added;
        t->next_plan = 0;
        t->n_known = 0;
        /* Ступени RX-лестницы выведены из замеренного RX-обрыва — запасным
           перебором они не называются; только то, что после них. */
        t->fb_queue = added > ladder;
        t->fb_from = ladder;
        if (added > ladder) {
            say(s, "по %s кандидаты замера исчерпаны — %zu планов из запасного перебора "
                   "донора (это не находка замера)", t->name, added - ladder);
        }
    }
    return added;
}

/* Ставит следующего кандидата. 0 — поставлен, -1 — кандидаты кончились. */
/* ЛОКАЛЬНЫЙ ОТКАЗ ОТПРАВКИ — единый разбор для ВСЕХ путей испытания.
 *
 * Раньше он жил только в T_VERIFY_WAIT, и путь «зонд не дошёл до приложения»
 * его не видел вовсе: кандидат выбрасывался из-за НАШЕЙ неудачи, потому что
 * рядом с ней коробка ещё и оборвала зонд. Сочетание обычное — посылка не
 * ушла, значит воздействия не было, значит цель ответила как без обхода.
 *
 * Возвращает:
 *   0 — отказа не было, решать по результату зонда;
 *   1 — временный отказ, кандидат переиспытывается (состояние уже выставлено);
 *   2 — постоянный отказ, опыт невозможен, нужен следующий кандидат.
 *
 * Свойство коробки не пишется ни в одном случае: воздействия не было (§2.4). */
/* Разбирает НАКОПЛЕННЫЕ ранние отказы теперь, когда ключ зонда известен.
 *
 * До возврата зонда местный порт назначает ядро, и отказ, совпавший по цели и
 * идентификатору плана, мог принадлежать как нашему обращению, так и
 * соседнему: один пробный план действует на все подключения к этой цели.
 * Съесть чужой отказ значит без нужды переиспытать кандидата, а при
 * постоянном коде — объявить опыт невозможным там, где он состоялся.
 *
 * Чужие отказы не выбрасываются молча в счётчик: их наличие само по себе
 * ничего про нашу попытку не говорит, и говорить не должно. */
static void claim_early_refusal(task *t) {
    d2k_ev probe;
    memset(&probe, 0, sizeof probe);
    probe.family = t->ver_flow.family;
    memcpy(probe.low_ip, t->ver_flow.a_ip, sizeof probe.low_ip);
    memcpy(probe.high_ip, t->ver_flow.b_ip, sizeof probe.high_ip);
    probe.low_port = t->ver_flow.a_port;
    probe.high_port = t->ver_flow.b_port;
    probe.transport = t->ver_flow.transport;
    for (size_t k = 0; k < t->ver_unsent_seen; k++) {
        if (ev_matches_flow(&probe, &t->ver_unsent_early[k])) {
            t->unsent_code = t->ver_unsent_code_early[k];
            break;
        }
    }
    t->ver_unsent_seen = 0;
}

static const char *ack_reason_text(unsigned code) {
    switch (code) {
    case D2K_ACK_BAD_PLAN: return "план не разобран или не годится способу отправки";
    case D2K_ACK_NO_ROOM:  return "в таблице планов нет места";
    case D2K_ACK_BAD_ARGS: return "аргументы команды негодны";
    default:               return "причина не известна";
    }
}

/* Пробная установка ЭТОГО кандидата: имя — по trial ID хвоста
   SET_NAME_PROBE, адрес (QUIC) — по trial ID SET_ADDR_PROBE. Голосовые
   опыты разбираются отдельно (их состояния другие). */
static int candidate_trial_matches(const task *t, uint16_t cmd,
                                   const uint8_t id[D2K_TRIAL_ID_LEN]) {
    if (cmd == D2K_CMD_SET_RAW_PROBE)
        return t->raw && t->raw_measure_request.generation && t->addr_probe_identity_valid &&
               !memcmp(id,t->addr_probe_trial_id,D2K_TRIAL_ID_LEN);
    if (cmd == D2K_CMD_SET_NAME_PROBE) {
        return !addr_udp(t) && !memcmp(id, t->trial_ack_id, D2K_TRIAL_ID_LEN);
    }
    return cmd == D2K_CMD_SET_ADDR_PROBE && addr_udp(t) &&
           !memcmp(id, t->addr_probe_trial_id, D2K_TRIAL_ID_LEN);
}

/* ИСПОЛНИТЕЛЬ ОТВЕРГ ПРОБНЫЙ ПЛАН (ACK ok=0, задача 19). План в таблицу не
   встал — снимать нечего; опыта не было, кандидат не судим. Бюджет зондов
   возвращается; поздний отказ (зонд уже сходил по сроку ожидания) не
   считается и испытанием. Дальше — следующий кандидат. */
static void exec_refusal(d2k_sched *s, task *t, unsigned code, int late) {
    if (late) {
        say(s, "по %s план отвергнут исполнителем: %s (код %u) — отказ пришёл, когда "
               "зонд уже ушёл без плана; местный отказ, кандидат не судим; беру следующего",
            t->name, ack_reason_text(code), code);
        ver_close(t);
        t->ver_seen = 0;
        t->ver_ok = 0;
        t->ver_unsent_seen = 0;
        t->unsent_code = 0;
        if (t->exec_probed > 0) { t->exec_probed--; }
        if (t->own_first == 2 && t->next_plan > 0 && t->next_plan <= 32)
            t->own_probed &= ~(1u << (t->next_plan - 1));
    } else {
        say(s, "по %s план отвергнут исполнителем: %s (код %u) — местный отказ, "
               "опыта не было, кандидат не судим; беру следующего без сетевого зонда",
            t->name, ack_reason_text(code), code);
    }
    if (t->probe_fd >= 0) { close(t->probe_fd); t->probe_fd = -1; }
    t->probe_sport_be = 0;
    t->trial_installed = 0;
    t->trial_acked = 0;
    t->exec_nak = 0;
    memset(t->trial_ack_id, 0, sizeof t->trial_ack_id);
    if (addr_udp(t)) { t->addr_probe_identity_valid = 0; }
    if (t->probes > 0) { t->probes--; }
    if (s->probes_used > 0) { s->probes_used--; }
    t->exec_refused++;
    t->state = T_PLANNING;
}

/* ПОЛЕ 17.10.2026 (router-round RR3-fix2-1): свидетель ECH romfea.gr стоит за
   Cloudflare challenge. Под планом рукопожатие с ПРИНЯТЫМ ECH прошло, сервер
   свидетеля ответил своей challenge-страницей, и cloudflare-ech.com получал
   60-минутную антибот-паузу. Свидетель доказывает только проход ECH через
   коробку: полный HTTP-ответ его сервера через принятый ECH с верным именем
   сертификата — доказательство прохода, а содержимое — дело сервера
   свидетеля, не антибот цели (так же релиз засчитывает 403 свидетеля). */
static int ech_witness_transport_proof(const task *t) {
    if (!t || t->transport != 6 || !t->ech_offer || t->ech_replay ||
        !t->ech_origin[0] || !strcmp(t->ech_origin, t->name)) return 0;
    if (!t->ver.ech_accepted || t->ver.name_ok != 1 || !t->ver.body_complete ||
        t->ver.status < 100 || t->ver.status > 599) return 0;
    return t->ver.level == D2K_VER_CHALLENGE || t->ver.cloudflare_challenge;
}

/* Тот же путь свидетеля (поле 17.10.2026, RR3-ech1-1): под планом рукопожатие
   с принятым ECH прошло, сервер свидетеля начал ответ, а тело оборвалось на
   десятках килобайт — это измеренный объёмный обрыв на этом адресе, а не
   «план не дошёл до приложения». */
static int ech_witness_rx_cut(const task *t) {
    if (!t || t->transport != 6 || !t->ech_offer || t->ech_replay ||
        !t->ech_origin[0] || !strcmp(t->ech_origin, t->name)) return 0;
    return t->ver.ech_accepted && t->ver.name_ok == 1 &&
           t->ver.status >= 200 && t->ver.status < 400 &&
           !t->ver.body_complete && t->ver.body_framing_valid &&
           t->ver.body_bytes >= 8192;
}

static int local_refusal_verdict(d2k_sched *s, task *t) {
    if (t->unsent_code == 0) { return 0; }
    if (refuse_is_permanent(t->unsent_code)) {
        /* Тот же план даст тот же результат: повторять нечего. Это причина,
           по которой опыт НЕВОЗМОЖЕН, а не промах кандидата. */
        say(s, "по %s %s (причина %u) — опыт невозможен, кандидат не виноват, "
               "беру следующего", t->name,
            t->unsent_code == D2K_REFUSE_NOT_APPLIED
                ? "исполнитель отверг план на приветствии зонда: зонд ушёл БЕЗ "
                  "плана, и ответ линии о плане ничего не говорит"
            : t->unsent_code == D2K_REFUSE_FLOW_UNFIT
                ? "поток зонда не несёт того, что план требует (метка времени "
                  "TCP у tcp-template-v1): зонд ушёл БЕЗ плана"
                : "план не помещается в посылку",
            (unsigned)t->unsent_code);
        t->unsent_code = 0;
        trial_retire(s, t);
        ver_close(t);
        t->state = T_PLANNING;
        return 2;
    }
    if (t->probes >= sched_probe_cap(t) || t->unsent_tries >= SCHED_UNSENT_RETRIES) {
        /* Временный отказ, но повторять больше не на что: бюджет исчерпан.
           Кандидат всё равно не виноват — просто испытать его нечем. */
        say(s, "по %s посылка плана не ушла на провод (причина %u), "
               "повторы исчерпаны — опыта не было, беру следующего кандидата",
            t->name, (unsigned)t->unsent_code);
        t->unsent_code = 0;
        trial_retire(s, t);
        ver_close(t);
        t->state = T_PLANNING;
        return 2;
    }
    t->unsent_tries++;
    say(s, "по %s %s (причина %u, попытка %u из %u) — "
           "опыта не было, испытываю кандидата ещё раз",
        t->name,
        refuse_is_damage(t->unsent_code)
            ? "поток испорчен недоисполнением плана"
            : "посылка плана не ушла на провод",
        (unsigned)t->unsent_code,
        (unsigned)t->unsent_tries, (unsigned)SCHED_UNSENT_RETRIES);
    t->unsent_code = 0;
    ver_close(t);
    t->ver_seen = 0;
    t->ver_unsent_seen = 0;
    t->ver_ok = 0;
    t->probes++;
    s->probes_used++;
    t->state = T_VERIFY;
    if (start_worker(s, t, JOB_VERIFY) != 0) { t->state = T_PLANNING; }
    return 1;
}

static int install_next(d2k_sched *s, task *t) {
    /* Счёт повторов после временного отказа — про ОДНУ гипотезу. Новый
       кандидат начинает с нуля: иначе неудачная очередь у первого забирала бы
       попытки у всех следующих. */
    t->unsent_tries = 0;
    t->unsent_code = 0;
    /* Накопленные ранние отказы принадлежали ПРЕЖНЕМУ кандидату: у нового
       свой идентификатор плана, и старые улики к нему не относятся. А вот
       набор НЕПЕРЕНОСИМЫХ планов не сбрасывается: он про ЦЕЛЬ, а не про
       кандидата — каждый его член назван своим идентификатором, и если тот же
       план вернётся из другого источника, отказ клиента про него остаётся
       правдой. */
    t->ver_unsent_seen = 0;
    t->exec_nak = 0;
    for (;;) {
    while (t->next_plan < t->n_plans) {
        if (t->probes >= sched_probe_cap(t)) { return -1; }
        const char *text = t->plans[t->next_plan++];
        /* Ступени лестницы по TX-обрыву, когда бюджет потока на этой цели
           не измерить: подтвердить их нечем — не ставим и не судим. */
        if (t->ladder_unmeasurable && ladder_candidate_at(t, t->next_plan - 1)) continue;
        if (t->transport == 17 && quic_text_is_split(text) && quic_split_unfit(s, t)) {
            /* Свой/готовый план разреза другой цели этому клиенту не
               исполнится (финальное ревью core, I1): не ставим и не судим. */
            say(s, "по %s (QUIC) план разреза CRYPTO пропускаю: ClientHello клиента "
                   "шире датаграммы — датапат его не исполнит", t->name);
            continue;
        }
        snprintf(t->box_id, sizeof t->box_id, "%s", t->plan_boxes[t->next_plan - 1]);
        t->probes++;
        s->probes_used++;
        /* План в каталог НЕ пишется здесь: кандидат — ещё не знание (§10).
           Пишется только подтверждённый зондом, в verify_confirm ниже. */
        char err[160];

        /* Stamp only the wire copy. The catalog retains the original plan
           text and its stable hash, independently of this trial's identity. */
        static char wire[sizeof t->plans[0]];
        /* Catalog identity describes the plan; wire identity describes THIS
           attempt. Reusing the hash lets a delayed APPLIED acknowledge a
           different attempt after the kernel reuses its source port. */
        if (fresh_trial_id(t->ver_plan_id) != 0) {
            say(s, "по %s не удалось создать идентификатор опыта", t->name);
            return -2;
        }
        if(preflight_text(text))continue;
        snprintf(wire, sizeof wire, "%s", text);
        /* ЗАЩИТА — ТОЛЬКО В ПРОВОДНУЮ КОПИЮ. В каталоге текст плана остаётся
           как измерен: его личность (plan_ident) считается ИЗ ТЕКСТА, и
           дописанная строка сделала бы из своего подтверждённого плана
           другой план — проверено тестом планировщика (26 падений:
           «подтверждён не тот свой план»). Защита же не часть программы
           воздействия, а решение о ЧУЖОМ входящем пакете. */
        if (rst_guard_wanted(t)) { (void)plan_arm_rst_guard(wire, sizeof wire); }
        if (stamp_plan_id(wire, t->ver_plan_id) != 0) {
            say(s, "по %s кандидат без идентичности опыта не устанавливаю", t->name);
            return -2;
        }

        /* d2k_compose выдаёт ТЕКСТ, датапат принимает hex от TLV — перевод
           обязателен, и без него сюда уезжал бы текст, который
           d2k_link_set_name законно отвергает как «не hex» (так и было
           обнаружено первым прогоном test_sched). */
        static char hex[2 * D2K_PLAN_TLV_MAX + 1];
        if (d2k_plan_text_to_hex(wire, hex, sizeof hex, err, sizeof err) != 0) {
            continue; /* кандидат не переводится — не наше наблюдение о коробке */
        }
        /* ПОРТ ЗОНДА ЗАНИМАЕТСЯ ЗДЕСЬ, в главном потоке, и до установки
           плана. Не в рабочем: управляющий сокет принадлежит главному циклу,
           и писать в него из потока зонда значило бы гонку на канале. */
        /* Прежний кандидат снимается ТОЧНО, пока его порт ещё наш (задача
           20): одно закрытие сокета оставляло пробную запись стоять по
           свободному порту. */
        trial_retire(s, t);
        {
            int pfd = -1;
            uint16_t psport = 0;
            /* TCP и UDP занимаются РАЗНЫМИ вызовами: тип сокета задаётся при
               создании, и «тот же bind, только датаграммный» — другой вызов,
               а не другой аргумент. */
            int bound = d2k_sched_bind_hook(t->transport, t->family, &pfd, &psport);
            if (bound == 0) {
                t->probe_fd = pfd;
                t->probe_sport_be = psport;
                /* Проверочный сокет должен пройти те же NFQUEUE-правила,
                   что и собственные измерения контроллера. Без SO_MARK
                   широкая привязка по LAN-клиенту исключает локальный
                   verifier: он подключается с адреса роутера и его Plan не
                   применяется к собственному потоку. Не ставим trial, если
                   метка не установилась — иначе verifier проверит обход
                   мимо datapath и даст ложный отказ кандидата. */
                if (s->mark != 0 && !is_voice_class(t->name, t->transport) &&
                    d2k_sched_mark_hook(pfd, s->mark) != 0) {
                    say(s, "по %s не удалось пометить сокет зонда меткой контроллера; "
                           "кандидат не ставлю", t->name);
                    close(t->probe_fd);
                    t->probe_fd = -1;
                    return -2;
                }
            } else {
                /* ПОРТ НЕ ЗАНЯЛСЯ — КАНДИДАТ НЕ СТАВИТСЯ ВОВСЕ (0010, R1).
                   Раньше здесь план уезжал с нулевым портом, то есть
                   доставался всем клиентским соединениям к цели: локальная
                   неудача превращалась в ущерб постороннему трафику и в
                   двусмысленное «цель молчит». Локальный отказ обязан
                   остаться локальным. */
                say(s, "по %s порт для зонда не занялся — кандидат не ставлю: "
                       "испытание без изоляции било бы по чужим соединениям", t->name);
                return -2;
            }
        }
        if (addr_udp(t)) {
            struct sockaddr_storage peer;
            memset(&peer, 0, sizeof peer);
            socklen_t peer_len;
            int parsed;
            if (t->family == 6) {
                struct sockaddr_in6 *p = (struct sockaddr_in6 *)&peer;
                p->sin6_family = AF_INET6;
                p->sin6_port = htons(t->port ? t->port : 443);
                peer_len = sizeof *p;
                parsed = inet_pton(AF_INET6, t->ip, &p->sin6_addr);
            } else {
                struct sockaddr_in *p = (struct sockaddr_in *)&peer;
                p->sin_family = AF_INET;
                p->sin_port = htons(t->port ? t->port : 443);
                peer_len = sizeof *p;
                parsed = inet_pton(AF_INET, t->ip, &p->sin_addr);
            }
            if (parsed != 1 ||
                connect(t->probe_fd, (struct sockaddr *)&peer, peer_len) != 0) {
                say(s, "по %s адресный QUIC-сокет не смог выбрать маршрут: %s",
                    t->name, strerror(errno));
                close(t->probe_fd); t->probe_fd = -1;
                return -2;
            }
            struct sockaddr_storage local;
            socklen_t local_len = sizeof local;
            memset(&local, 0, sizeof local);
            int local_ok = getsockname(t->probe_fd, (struct sockaddr *)&local, &local_len) == 0;
            uint16_t local_port = 0;
            memset(t->addr_probe_src_ip, 0, sizeof t->addr_probe_src_ip);
            if (local_ok && t->family == 6 && local.ss_family == AF_INET6) {
                const struct sockaddr_in6 *p = (const struct sockaddr_in6 *)&local;
                local_ok = !IN6_IS_ADDR_UNSPECIFIED(&p->sin6_addr);
                memcpy(t->addr_probe_src_ip, &p->sin6_addr, 16);
                local_port = p->sin6_port;
            } else if (local_ok && t->family == 4 && local.ss_family == AF_INET) {
                const struct sockaddr_in *p = (const struct sockaddr_in *)&local;
                local_ok = p->sin_addr.s_addr != 0;
                memcpy(t->addr_probe_src_ip, &p->sin_addr, 4);
                local_port = p->sin_port;
            } else {
                local_ok = 0;
            }
            if (!local_ok || !local_port || fresh_trial_id(t->addr_probe_trial_id) != 0) {
                say(s, "по %s не удалось закрепить адрес/порт/поколение QUIC-пробы",
                    t->name);
                close(t->probe_fd); t->probe_fd = -1;
                return -2;
            }
            t->addr_probe_src_port_be = local_port;
            t->probe_sport_be = local_port;
        }
        int set_rc;
        if (addr_udp(t)) {
            uint8_t dst[16] = {0};
            if (inet_pton(t->family == 6 ? AF_INET6 : AF_INET, t->ip, dst) != 1) {
                set_rc = -1;
                snprintf(err, sizeof err, "адрес цели не соответствует семейству опыта");
            } else {
                set_rc = d2k_link_set_addr_probe_family(s->link_fd,
                    t->addr_probe_src_ip, t->addr_probe_src_port_be,
                    dst, htons(t->port ? t->port : 443), 17, t->family,
                    t->addr_probe_trial_id, D2K_ADDR_PROBE_LEASE_MAX_MS,
                    hex, err, sizeof err);
            }
        } else if (fresh_trial_id(t->trial_ack_id) != 0) {
            set_rc = -1;
            snprintf(err, sizeof err, "не удалось создать trial ID установки");
        } else {
            set_rc = d2k_link_set_name_probe_trial(s->link_fd, t->name, t->transport, hex,
                                                   probe_shape(t), t->probe_sport_be,
                                                   t->family, t->trial_ack_id,
                                                   err, sizeof err);
        }
        if (set_rc == 0) {
            if(force_name(s,t->name))
                say(s,"принудительный поиск: %s — кандидат %s, отдельный поток зонда; ожидаю исполнение и прикладной результат",t->name,t->plans[t->next_plan?t->next_plan-1:0]);
            t->trial_installed = 1;
            t->trial_shape = (uint8_t)(addr_udp(t) ? 0 : probe_shape(t));
            t->trial_shape_seq = s->quic_shape_seq[t->family == 6];
            if (addr_udp(t)) { t->addr_probe_identity_valid = 1; }
            return 0;
        }
        if (t->probe_fd >= 0) { close(t->probe_fd); t->probe_fd = -1; }
    }
        /* Запасной перебор — последний этап оригинального инструмента. */
        if(t->family_fast==1 || t->own_first == 2) return -1;
        /* Свой план позднего закрытия (rx_saved_bootstrap) — не замер. Его
           неудача ведёт к полному замеру, а не к запасному списку: поле
           14.10.2026, www.bbc.com — «8 планов из запасного перебора донора»
           без единого вопроса замера. */
        if (t->rx_bootstrap_only) return -1;
        /* ЗАМЕР УЖЕ СДЕЛАН И ЕГО КАНДИДАТЫ ЕЩЁ НЕ ИСПЫТАНЫ (задача 37).
           Очередь узнанной коробки кончилась, а результат прямого замера
           лежит в t->res: следующими идут ЕГО кандидаты (ветка «проверяю
           кандидаты из уже выполненного прямого замера»), а не запасной
           список. Долив здесь обнулял n_known и делал ту ветку недостижимой:
           поле 02.10.2026, edge-mqtt-fallback — один план коробки, затем
           весь список донора и лестница, приём замера так и не испытан. */
        if (t->cached_measure_valid && t->n_known > 0) return -1;
        if (refill_from_fallback(s, t) == 0) { return -1; }
    }
}

/* Готовые планы УЗНАННОЙ коробки — первыми, синтез по вердикту — следом.
 *
 * Порядок не произволен: план, который уже работал на коробке с такой же
 * приметой, проверен на ней же, а синтез — только выведен. Порт buildQueue
 * (controller.go), включая порядок по числу подтверждённых успехов (§3.4).
 * Возвращает, сколько кандидатов взято из каталога. */
/* Привязка этой цели в каталоге — та, что подходит по транспорту. Нужна
   там, где решение зависит не от плана, а от того, ЧЕМ он был добыт. */
static const d2k_cat_binding *binding_for(const d2k_sched *s, const char *name,
                                          uint8_t transport, uint8_t family) {
    if (!s->cat) { return NULL; }
    for (size_t bi = 0; bi < s->cat->n_boxes; bi++) {
        const d2k_cat_box *b = &s->cat->boxes[bi];
        for (size_t i = 0; i < b->n_binds; i++) {
            const d2k_cat_binding *bd = &b->binds[i];
            if ((bd->transport ? bd->transport : 6) == transport &&
                (bd->family ? bd->family : 4) == family &&
                strcmp(bd->kind, "name") == 0 && strcmp(bd->target, name) == 0) {
                return bd;
            }
        }
    }
    return NULL;
}

/* ПОКРЫВАЕТ ЛИ ПОДТВЕРЖДЁННАЯ ПРИВЯЗКА ЭТУ ФОРМУ — ПО ПРАВИЛУ ДАТАПАТА
   (plans.c: shape_fits и порядок scan_name). Своя форма; запись TLS 1.3 годится
   потоку с ECH offer, пока у имени нет отдельной ECH-привязки — GREASE по
   байтам неотличим от ECH; ноль с любой стороны — «не измерено», не
   противоречит (так же d2k_cat_shape_fits). Берутся только привязки, которые
   стоят на проводе: включённые, подтверждённые, без пометки повторной
   проверки. Нужна там, где контроллер судит о потоке, к которому датапат план
   не применял: судить он обязан той же меркой, которой датапат выбирал план. */
static const d2k_cat_binding *binding_covering(const d2k_sched *s, const char *name,
                                               uint8_t transport, uint8_t family,
                                               uint8_t shape) {
    const d2k_cat_binding *exact = NULL, *modern = NULL, *unshaped = NULL;
    if (!s->cat || !name || !name[0]) { return NULL; }
    for (size_t bi = 0; bi < s->cat->n_boxes; bi++) {
        const d2k_cat_box *b = &s->cat->boxes[bi];
        for (size_t i = 0; i < b->n_binds; i++) {
            const d2k_cat_binding *bd = &b->binds[i];
            if (!bd->enabled || bd->level < 3 || bd->recheck_since ||
                strcmp(bd->kind, "name") != 0 || strcmp(bd->target, name) != 0 ||
                (bd->transport ? bd->transport : 6) != transport ||
                (bd->family ? bd->family : 4) != family) { continue; }
            if (shape == 0 || bd->shape == shape) { if (!exact) { exact = bd; } }
            else if (bd->shape == 0) { if (!unshaped) { unshaped = bd; } }
            else if (bd->shape == (uint8_t)D2K_SHAPE_MODERN &&
                     shape == D2K_LINK_SHAPE_ECH_TCP) { if (!modern) { modern = bd; } }
        }
    }
    return exact ? exact : modern ? modern : unshaped;
}

static size_t known_plans(d2k_sched *s, task *t) {
    t->fb_queue = 0;
    if (t->fp.n_sig == 0) { return 0; }
    /* Ambiguity yields candidates, not the identity of the first catalog
       entry. Order globally by positive evidence; retain each plan's owner. */
    size_t took = 0;
    size_t cap = sizeof t->plans / sizeof t->plans[0];
    /* proto у плана каталога — протокол УРОВНЯ ПРИЛОЖЕНИЯ ("tls"/"quic"), а
       не транспорт: живой каталог роутера Марка (11.09, 14 коробок, 353
       привязки) не содержит ни одного плана с proto "tcp" — у всех "tls".
       Сравнение с транспортом отбрасывало бы КАЖДЫЙ настоящий план узнанной
       коробки, и узнавание работало бы только в тесте, где план заводил сам
       планировщик. Имя поля общее с Go-стороной (Plan.Proto), и смысл берётся
       оттуда же, а не выдумывается здесь. */
    const char *want = (t->transport == 17) ? "quic" : "tls";
    while (took < cap) {
        const d2k_cat_plan *best = NULL;
        const d2k_cat_box *owner = NULL;
        int best_agree = 0;
        for (size_t bi = 0; bi < s->cat->n_boxes; bi++) {
            const d2k_cat_box *b = &s->cat->boxes[bi];
            if (!d2k_fp_same(&b->fp, &t->fp)) { continue; }
            for (size_t i = 0; i < b->n_plans; i++) {
                const d2k_cat_plan *p = &b->plans[i];
                if (!p->enabled || !p->text || strcmp(p->proto, want) != 0 ||
                    strlen(p->text) >= sizeof t->plans[0]) { continue; }
                int used = 0;
                for (size_t k = 0; k < took; k++) {
                    if (strcmp(t->plans[k], p->text) == 0) { used = 1; break; }
                }
                uint32_t h = fnv1a(p->text);
                for (size_t k = 0; k < t->n_tried && !used; k++) {
                    if (t->tried[k] == h) { used = 1; }
                }
                /* Коробка той же корзины порога — раньше: обрыв на 16 КБ
                   сначала проверяет планы 16-КБ-коробки, а не самой
                   успешной из совместимых по допуску (задача 23). */
                int agree = box_volume_bucket_agrees(&b->fp, &t->fp);
                if (!used && (!best || agree > best_agree ||
                              (agree == best_agree && p->successes > best->successes))) {
                    best = p;
                    owner = b;
                    best_agree = agree;
                }
            }
        }
        if (!best) { break; }
        memcpy(t->plans[took], best->text, strlen(best->text) + 1);
        snprintf(t->plan_boxes[took], sizeof t->plan_boxes[took], "%s", owner->id);
        uint32_t h = fnv1a(best->text);
        tried_add(t, h);
        took++;
    }
    return took;
}

/* СВОИ ПОДТВЕРЖДЁННЫЕ ПЛАНЫ ТОЙ ЖЕ ФОРМЫ — ДО ПОЛНОГО ЗАМЕРА (задача 32).

   ТЗ §3.4: для подходящей уже изученной коробки сначала проверить своё
   найденное решение в новом контексте; §5: совпадение отпечатка применимость
   не доказывает. Поэтому отбор здесь не по отпечатку, а по ПРОТОКОЛУ: план,
   подтверждённый собственным зондом для другой цели того же транспорта,
   семейства и формы приветствия (TLS 1.3 / TLS 1.2; ECH и QUIC — нет), из
   ЛЮБОЙ коробки. Применимость докажет только испытание зондом на этой цели.

   Не берутся: выключенный план, привязка ниже третьего уровня, выключенная
   или помеченная к повторной проверке (задача 21) — это не подтверждённое
   знание. При подозрении от потока, где план уже исполнялся (planned), план,
   который датапат держит для этого ключа (bound_plan_here), НЕ исключается
   вслепую (так было с 47c663c): он испытывается ПЕРВЫМ с проверкой бюджета
   потока (задача 55). Прошёл — подозрение было ложным (обрыв соединений при
   перезапуске, закрытие приложения), поиск окончен; оборвался — дальше свои
   планы обычным порядком. Уже испытанные в этой задаче тексты (tried) не
   повторяются.

   Порядок — по числу успехов плана, затем по свежести подтверждения. Не
   «свежее первым» (так было с задачи 49 до поля 04.10): свежий план с
   короткой историей «подтверждался» ответом почти без тела раньше плана,
   который снимает объёмную заморозку и подтверждён на десятках имён, — и
   картинки Discord с Cloudflare встали. Порция — не больше
   очереди задачи (SCHED_MAX_PLANS); уже поставленные в очередь (own_seen) не
   повторяются. fill — записать порцию в очередь задачи.
   В tried план попадает, только если реально испытан на проводе
   (own_first_continue): отвергнутый исполнителем опыта не имел. */
/* Which of two enabled bindings of one key the datapath gets (task 55, §2.2):
 * the one whose confirming flow passed the box's flow budget, then the newest;
 * one whose plan was later cut mid-repeats (applied, review I-3) goes last.
 * A short 403/404 confirmation is not evidence against the budget cut, so a
 * fresher unproven binding must not displace a proven one. */
static int budget_rank(uint8_t mark) {
    return mark == D2K_CAT_BUDGET_PASSED ? 2 : mark == D2K_CAT_BUDGET_CUT ? 0 : 1;
}
static int binding_beats(const d2k_cat_binding *a, const d2k_cat_binding *b) {
    int pa = budget_rank(a->budget), pb = budget_rank(b->budget);
    return pa != pb ? pa > pb : a->confirmed > b->confirmed;
}

static const d2k_cat_plan *plan_by_id(const d2k_cat_box *b, const char *id);

/* ПЛАН, ПОД КОТОРЫМ ШЁЛ ПОТОК ПОДОЗРЕНИЯ (задача 55, §2.3): привязка этого
   ключа (имя, транспорт, семейство, форма), которую ставит проход каталога —
   тот же выбор, что у d2k_sched_sync_step (binding_beats). Событие
   подозрения идентификатора плана не несёт; датапат держит именно эту. */
static int bound_plan_of(const d2k_sched *s, const char *name, uint8_t transport,
                         uint8_t family, uint8_t shape, char out_id[40]) {
    if (!s->cat) return 0;
    for (size_t bi = 0; bi < s->cat->n_boxes; bi++) {
        const d2k_cat_box *b = &s->cat->boxes[bi];
        for (size_t j = 0; j < b->n_binds; j++) {
            const d2k_cat_binding *bd = &b->binds[j];
            if (!bd->enabled || bd->recheck_since || (bd->level > 0 && bd->level < 3) ||
                strcmp(bd->kind, "name") || strcmp(bd->target, name) ||
                (bd->transport ? bd->transport : 6) != transport ||
                (bd->family ? bd->family : 4) != family || bd->shape != shape ||
                (bd->transport == 17 && bd->verified_by == D2K_VERBY_CLIENT) ||
                newer_target_binding(s->cat, bd)) continue;
            const d2k_cat_plan *p = plan_by_id(b, bd->plan_id);
            if (!p || !p->text) continue;
            snprintf(out_id, 40, "%s", bd->plan_id);
            return 1;
        }
    }
    return 0;
}

static int bound_plan_here(const d2k_sched *s, const task *t, uint8_t shape,
                           char out_id[40]) {
    if(encrypted_dns_task(t) && s->cat) {
        for(size_t bi=0;bi<s->cat->n_boxes;bi++) {
            const d2k_cat_box *box=s->cat->boxes+bi;
            for(size_t j=0;j<box->n_binds;j++) {
                const d2k_cat_binding *b=box->binds+j;
                if(!b->enabled || b->recheck_since || b->level<3 || b->shape!=shape ||
                   !dns_binding_matches_task(b,t) || newer_target_binding(s->cat,b))continue;
                const d2k_cat_plan *p=plan_by_id(box,b->plan_id);if(!p || !p->text)continue;
                snprintf(out_id,40,"%s",b->plan_id);return 1;
            }
        }
        return 0;
    }
    return bound_plan_of(s, t->name, t->transport, t->family, shape, out_id);
}

static healthy_proof *proof_find(d2k_sched *s, const char *name, uint8_t transport,
                                 uint8_t family) {
    for (size_t i = 0; i < SCHED_PROOF_SLOTS; i++) {
        healthy_proof *p = &s->proofs[i];
        if (p->used && p->transport == transport && p->family == family &&
            !strcmp(p->name, name)) return p;
    }
    return NULL;
}

/* Новый замер по ключу — доказательство прежнего контекста больше не итог. */
static void proof_drop(d2k_sched *s, const char *name, uint8_t transport, uint8_t family) {
    healthy_proof *p = proof_find(s, name, transport, family);
    if (p) memset(p, 0, sizeof *p);
}

static int ev_executed_plan(const d2k_ev *ev, char out[40]);

static void proof_record(d2k_sched *s, const task *t, const char *plan_id, int64_t now_ms) {
    if (!t->trigger_executed_plan[0] || strcmp(t->trigger_executed_plan, plan_id) ||
        !d2k_binding_known(&t->trigger_binding)) return;
    healthy_proof *p = proof_find(s, t->name, t->transport, t->family);
    for (size_t i = 0; !p && i < SCHED_PROOF_SLOTS; i++)
        if (!s->proofs[i].used) p = &s->proofs[i];
    if (!p) { /* все заняты — вытесняется самое старое доказательство */
        p = &s->proofs[0];
        for (size_t i = 1; i < SCHED_PROOF_SLOTS; i++)
            if (s->proofs[i].proven_ms < p->proven_ms) p = &s->proofs[i];
    }
    memset(p, 0, sizeof *p);
    p->used = 1;
    snprintf(p->name, sizeof p->name, "%s", t->name);
    p->transport = t->transport;
    p->family = t->family;
    p->code = t->trigger_code;
    p->shape = t->trigger_shape;
    snprintf(p->ip, sizeof p->ip, "%s", t->ip);
    p->port = t->port;
    snprintf(p->plan_id, sizeof p->plan_id, "%s", plan_id);
    p->binding = t->trigger_binding;
    p->proven_ms = now_ms;
}

/* Подозрение с потока под планом, совпавшее с доказанным контекстом целиком:
   тот же код, сервер и порт, та же форма клиента, тот же план на проводе
   (выбор установки — bound_plan_of) и срок доказательства не вышел. */
static healthy_proof *proof_covers(d2k_sched *s, const d2k_ev *ev, const char *name) {
    if (ev->planned != D2K_LINK_PLANNED_YES) return NULL;
    uint8_t family = ev->family ? ev->family : 4;
    healthy_proof *p = proof_find(s, name, ev->transport, family);
    if (!p || ev->code != p->code || ev->client_shape != p->shape) return NULL;
    char executed[40];
    if (!ev_executed_plan(ev, executed) || strcmp(executed, p->plan_id) ||
        !d2k_binding_equal(&ev->execution_binding, &p->binding)) return NULL;
    if (s->now_ms - p->proven_ms >= SCHED_HEALTHY_PROOF_MS) return NULL;
    char ip[INET6_ADDRSTRLEN];
    uint16_t port = 0;
    server_of(ev, ip, sizeof ip, &port);
    if (strcmp(ip, p->ip) || port != p->port) return NULL;
    char now_bound[40];
    uint8_t bound_shape = p->shape == D2K_LINK_SHAPE_ECH_TCP ? (uint8_t)D2K_LINK_SHAPE_ECH_TCP :
                          p->shape == (uint8_t)D2K_SHAPE_LEGACY ? (uint8_t)D2K_SHAPE_LEGACY :
                          (uint8_t)SCHED_PROBE_SHAPE;
    if (ev->transport == 17) bound_shape = (uint8_t)D2K_LINK_SHAPE_QUIC;
    if (!bound_plan_of(s, name, ev->transport, family, bound_shape, now_bound) ||
        strcmp(now_bound, p->plan_id)) return NULL;
    return p;
}

static void unknown_note(d2k_sched *s, const char *kind, const char *target, uint8_t transport,
                         uint8_t family, uint16_t port, const char *reason, const char *why) {
    if (!target || !target[0]) return;
    family = family ? family : 4;
    unknown_target *u = NULL;
    for (size_t i = 0; i < SCHED_UNKNOWN_SLOTS && !u; i++) {
        unknown_target *c = &s->unknowns[i];
        if (c->used && c->transport == transport && c->family == family && c->port == port &&
            !strcmp(c->target, target)) u = c;
    }
    int64_t now = wall_s(s, s->now_ms);
    if (!u) {
        for (size_t i = 0; i < SCHED_UNKNOWN_SLOTS && !u; i++)
            if (!s->unknowns[i].used) u = &s->unknowns[i];
        if (!u) { /* все заняты — уступает давнее всех виденная */
            u = &s->unknowns[0];
            for (size_t i = 1; i < SCHED_UNKNOWN_SLOTS; i++)
                if (s->unknowns[i].last_s < u->last_s) u = &s->unknowns[i];
        }
        memset(u, 0, sizeof *u);
        u->used = 1;
        snprintf(u->target, sizeof u->target, "%s", target);
        u->transport = transport;
        u->family = family;
        u->port = port;
        u->first_s = now;
        u->peers = u->peers_judged = u->peers_answered = -1;
    }
    snprintf(u->kind, sizeof u->kind, "%s", kind);
    snprintf(u->reason, sizeof u->reason, "%s", reason);
    snprintf(u->why, sizeof u->why, "%s", why ? why : "");
    u->last_s = now;
    u->count++;
}

/* Confirmation resolves only the measured service; other ports remain unknown. */
static void unknown_resolve(d2k_sched *s, const char *target, uint8_t transport, uint8_t family, uint16_t port) {
    family = family ? family : 4;
    for (size_t i = 0; i < SCHED_UNKNOWN_SLOTS; i++) {
        unknown_target *u = &s->unknowns[i];
        if (u->used && u->transport == transport && u->family == family && u->port == port && !strcmp(u->target, target))
            memset(u, 0, sizeof *u);
    }
}

/* ИСПОЛНЕННЫЙ план из события (этап 36): идентичность, которую датапат снял
   с потока в момент исполнения, — не текущая привязка каталога. Без неё
   (старый датапат, план без id) и у опыта (trial ID) — не приписывается
   постоянному плану. Проводной id плана каталога — ASCII «plan-…»
   (plan_ident); иной — шестнадцатеричной строкой. */
static int ev_executed_plan(const d2k_ev *ev, char out[40]) {
    if (!ev->execution_id) return 0;
    for (size_t i = 0; i < D2K_TRIAL_ID_LEN; i++) if (ev->trial_id[i]) return 0;
    size_t n = 0;
    while (n < D2K_PLAN_ID_LEN && ev->plan_id[n]) n++;
    if (!n) return 0;
    int printable = 1;
    for (size_t i = 0; i < n; i++) if (ev->plan_id[i] < 0x21 || ev->plan_id[i] > 0x7e) printable = 0;
    if (printable) { memcpy(out, ev->plan_id, n); out[n] = '\0'; return 1; }
    static const char hx[] = "0123456789abcdef";
    memcpy(out, "wire-", 5);
    for (size_t i = 0; i < D2K_PLAN_ID_LEN; i++) {
        out[5 + 2 * i] = hx[ev->plan_id[i] >> 4];
        out[6 + 2 * i] = hx[ev->plan_id[i] & 15];
    }
    out[5 + 2 * D2K_PLAN_ID_LEN] = '\0';
    return 1;
}

/* Уровень того, что показал ответ сервера: прикладные записи TLS — обмен;
   ответ STUN/Discovery на свой запрос — протокольный ответ; прочий UDP и
   поток без протокола — путь. Рукопожатие без данных — не считается. */
static const char *exchange_level(const d2k_ev *ev) {
    if (ev->transport == 6)
        return ev->client_shape == D2K_LINK_SHAPE_RAW ? "путь" :
               d2k_ev_outer_appdata(ev) ? "обмен TLS" : NULL;
    if (ev->code == D2K_UDP_PROOF_STUN) return "ответ STUN";
    if (ev->code == D2K_UDP_PROOF_VOICE_DISCOVERY) return "ответ Discovery";
    return "путь";
}

/* Поток клиента под ИСПОЛНЕННЫМ планом: ответ сервера (answered) или
   подозрение. Цель — имя, если поток узнан по имени, иначе адрес и порт
   сервера (адресные TCP/UDP/QUIC/STUN). */
static void plan_obs_note(d2k_sched *s, const d2k_ev *ev, const char *name, int answered) {
    if (ev->planned != D2K_LINK_PLANNED_YES) return;
    char plan[40];
    if (!ev_executed_plan(ev, plan)) return;
    const char *level = NULL;
    if (answered && !(level = exchange_level(ev))) return;
    uint8_t family = ev->family ? ev->family : 4;
    char target[256];
    uint16_t port = 0;
    if (name && name[0]) snprintf(target, sizeof target, "%s", name);
    else server_of(ev, target, sizeof target, &port);
    if (!target[0]) return;
    plan_obs *o = NULL;
    for (size_t i = 0; i < SCHED_PLANOBS_SLOTS && !o; i++) {
        plan_obs *c = &s->planobs[i];
        if (c->used && c->transport == ev->transport && c->family == family && c->port == port &&
            !strcmp(c->name, target) && !strcmp(c->plan_id, plan)) o = c;
    }
    int64_t now = wall_s(s, s->now_ms);
    if (!o) {
        for (size_t i = 0; i < SCHED_PLANOBS_SLOTS && !o; i++)
            if (!s->planobs[i].used) o = &s->planobs[i];
        if (!o) {
            o = &s->planobs[0];
            for (size_t i = 1; i < SCHED_PLANOBS_SLOTS; i++)
                if (s->planobs[i].last_s < o->last_s) o = &s->planobs[i];
        }
        memset(o, 0, sizeof *o);
        o->used = 1;
        snprintf(o->name, sizeof o->name, "%s", target);
        o->port = port;
        o->transport = ev->transport;
        o->family = family;
        snprintf(o->plan_id, sizeof o->plan_id, "%s", plan);
        o->first_s = now;
    }
    if (answered) {
        o->answered++;
        if (!o->level[0]) snprintf(o->level, sizeof o->level, "%s", level);
        else if (!strstr(o->level, level) && strlen(o->level) + strlen(level) + 3 < sizeof o->level) {
            strcat(o->level, ", ");
            strcat(o->level, level);
        }
    } else {
        o->suspected++;
    }
    o->last_s = now;
}

/* Оба конца потока, чья сторона клиента не наблюдалась: цель не угадывается. */
static void flow_ends(const d2k_ev *ev, char *out, size_t cap) {
    char a[INET6_ADDRSTRLEN] = "", b[INET6_ADDRSTRLEN] = "";
    int af = ev->family == 6 ? AF_INET6 : AF_INET;
    (void)inet_ntop(af, ev->low_ip, a, sizeof a);
    (void)inet_ntop(af, ev->high_ip, b, sizeof b);
    snprintf(out, cap, "%s:%u — %s:%u", a, (unsigned)ev->low_port, b, (unsigned)ev->high_port);
}

/* ПОРЯДОК СВОИХ ПЛАНОВ: план, под которым шёл поток подозрения; затем планы
   формы клиента; затем гипотезы другой формы TLS по TCP. Внутри группы —
   число успехов, затем свежесть подтверждения. */
static int own_rank_before(int lead_a, int tier_a, const d2k_cat_plan *a, int64_t fresh_a,
                           int lead_b, int tier_b, const d2k_cat_plan *b, int64_t fresh_b) {
    if (lead_a != lead_b) return lead_a > lead_b;
    if (tier_a != tier_b) return tier_a < tier_b;
    if (a->successes != b->successes) return a->successes > b->successes;
    return fresh_a > fresh_b;
}

static size_t own_first_plans(d2k_sched *s, task *t, int fill) {
    if (!s->cat || (t->transport != 6 && t->transport != 17) || t->by_addr ||
        (t->ech_offer && !t->ech_replay))
        return 0;
    int quic = t->transport == 17;
    /* Та же форма, что пойдёт в привязку (verify_confirm): QUIC — форма QUIC;
       старый TLS-клиент — старая форма, остальное — форма собственного зонда. */
    uint8_t want = quic ? (uint8_t)D2K_LINK_SHAPE_QUIC :
                   d2k_hello_shape(t->trig, t->trig_len) == D2K_SHAPE_LEGACY
                   ? (uint8_t)D2K_SHAPE_LEGACY : (uint8_t)SCHED_PROBE_SHAPE;
    /* НАСТОЯЩИЙ ECH БЕЗ СВИДЕТЕЛЯ (поле 04.10.2026). Привязка ляжет формой
       ECH, но планы коробки — те же TCP TLS 1.3 планы других целей (у ECH
       внешний ClientHello — тоже TLS 1.3), плюс ECH-привязки других внешних
       имён. Применимость докажет только повтор байтов клиента под планом. */
    int ech_replay = t->transport == 6 && t->ech_offer && t->ech_replay;
    uint8_t bound_shape = ech_replay ? (uint8_t)D2K_LINK_SHAPE_ECH_TCP : want;
    const d2k_cat_plan *pick[SCHED_MAX_PLANS];
    const d2k_cat_box *owner[SCHED_MAX_PLANS];
    int64_t fresh[SCHED_MAX_PLANS];
    int first[SCHED_MAX_PLANS];
    int tiers[SCHED_MAX_PLANS];
    size_t n = 0;
    /* ГИПОТЕЗЫ ДРУГОЙ ФОРМЫ TLS (поле 04.10.2026, апдейтер Discord TLS 1.2):
       фейк-первый план, рабочий на этой коробке для discord.com и rutracker,
       был привязан только формой 1.3, и клиенту 1.2 его не предлагали —
       поиск кончился «выведенные планы исчерпаны». Подтверждение другой
       формы — не доказательство для этой (U5), но гипотеза: испытывается
       ПОСЛЕ планов своей формы, зондом формы клиента (TLS 1.2 —
       d2k_verify_probe12_on) с проверкой бюджета, и привязка ложится формой
       клиента (record_shape). Только TLS 1.3 <-> TLS 1.2 по TCP: QUIC, ECH и
       HTTP не пересекаются. */
    uint8_t cross = quic ? 0 : want == D2K_SHAPE_LEGACY ? (uint8_t)D2K_SHAPE_MODERN :
                    want == D2K_SHAPE_MODERN ? (uint8_t)D2K_SHAPE_LEGACY : 0;
    /* Подозрение с потока ПОД планом: этот план не исключается вслепую, а
       испытывается ПЕРВЫМ с проверкой бюджета (задача 55, §2.3). Прошёл —
       подозрение было ложным; оборвался — дальше по порядку. */
    char bound[40] = "";
    if (t->trigger_planned == D2K_LINK_PLANNED_YES && bound_plan_here(s, t, bound_shape, bound))
        snprintf(t->bound_plan_id, sizeof t->bound_plan_id, "%s", bound);
    /* fill == 2: сколько ВСЕГО подходящих своих текстов ещё не ставилось в
       очередь (для честной строки, когда фаза обрывается не по их концу). */
    uint32_t *distinct = NULL;
    size_t n_distinct = 0;
    if (fill == 2) {
        size_t all = 0;
        for (size_t bi = 0; bi < s->cat->n_boxes; bi++) all += s->cat->boxes[bi].n_plans;
        distinct = all ? malloc(all * sizeof *distinct) : NULL;
        if (!distinct) return 0;
    }
    for (size_t bi = 0; bi < s->cat->n_boxes; bi++) {
        const d2k_cat_box *b = &s->cat->boxes[bi];
        for (size_t i = 0; i < b->n_plans; i++) {
            const d2k_cat_plan *p = &b->plans[i];
            if (!p->enabled || !p->text || preflight_text(p->text) || strcmp(p->proto, quic ? "quic" : "tls") ||
                strlen(p->text) >= sizeof t->plans[0]) continue;
            int found = 0, tier = 1;
            int64_t newest = 0;
            for (size_t j = 0; j < b->n_binds; j++) {
                const d2k_cat_binding *bd = &b->binds[j];
                if (strcmp(bd->plan_id, p->id) || !bd->enabled || bd->level < 3 ||
                    bd->recheck_since || (encrypted_dns_task(t) ? !dns_binding_matches_task(bd,t) : strcmp(bd->kind, "name")) ||
                    (encrypted_dns_task(t) && newer_target_binding(s->cat,bd)) ||
                    (bd->transport ? bd->transport : 6) != t->transport ||
                    (bd->family ? bd->family : 4) != t->family ||
                    (ech_replay ? !((bd->shape == want && !bd->ech_origin[0]) ||
                                    bd->shape == D2K_LINK_SHAPE_ECH_TCP)
                                : ((bd->shape != want && (!cross || bd->shape != cross)) ||
                                   bd->ech_origin[0])) ||
                    /* У QUIC подтверждение — только собственным зондом (H3):
                       «UDP + CLIENT» — любой обратный пакет, не доказательство. */
                    (quic && bd->verified_by != D2K_VERBY_PROBE)) continue;
                int bt = bd->shape == want ? 0 : 1;
                if (!found || bt < tier) { tier = bt; newest = bd->confirmed; }
                else if (bt == tier && bd->confirmed > newest) newest = bd->confirmed;
                found = 1;
            }
            if (!found) continue;
            int lead = bound[0] && !strcmp(p->id, bound);
            uint32_t h = fnv1a(p->text);
            int tried = 0;
            for (size_t k = 0; k < t->n_tried && !tried; k++) tried = t->tried[k] == h;
            for (size_t k = 0; k < t->n_own_seen && !tried; k++) tried = t->own_seen[k] == h;
            if (tried) continue;
            if (distinct) {
                int known = 0;
                for (size_t k = 0; k < n_distinct && !known; k++) known = distinct[k] == h;
                if (!known) distinct[n_distinct++] = h;
                continue;
            }
            /* Тот же текст в другой коробке — тот же план: остаётся лучший. */
            size_t dup = n;
            for (size_t k = 0; k < n; k++) if (!strcmp(pick[k]->text, p->text)) dup = k;
            int better_than_dup = dup < n &&
                own_rank_before(lead, tier, p, newest, first[dup], tiers[dup], pick[dup], fresh[dup]);
            if (dup < n && !better_than_dup) continue;
            if (dup < n) {
                for (size_t k = dup; k + 1 < n; k++) {
                    pick[k] = pick[k + 1]; owner[k] = owner[k + 1]; fresh[k] = fresh[k + 1];
                    first[k] = first[k + 1]; tiers[k] = tiers[k + 1];
                }
                n--;
            }
            size_t at = n;
            while (at > 0 && own_rank_before(lead, tier, p, newest, first[at - 1], tiers[at - 1],
                                             pick[at - 1], fresh[at - 1]))
                at--;
            if (at >= SCHED_MAX_PLANS) continue;
            if (n == SCHED_MAX_PLANS) n--;
            for (size_t k = n; k > at; k--) {
                pick[k] = pick[k - 1]; owner[k] = owner[k - 1]; fresh[k] = fresh[k - 1];
                first[k] = first[k - 1]; tiers[k] = tiers[k - 1];
            }
            pick[at] = p; owner[at] = b; fresh[at] = newest; first[at] = lead; tiers[at] = tier;
            n++;
        }
    }
    /* Порция не больше, чем помнит own_seen: незапомненный план вернулся бы
       следующей порцией снова (повторное ревью, Minor 2). Память кончилась —
       фаза своих планов кончилась; вызывающий скажет об этом. */
    if (distinct) { free(distinct); return n_distinct; }
    size_t room = SCHED_OWN_SEEN_MAX - t->n_own_seen;
    if (n > room) { n = room; t->own_seen_full = 1; }
    if (!fill) return n;
    t->fb_queue = 0;
    for (size_t k = 0; k < n; k++) {
        snprintf(t->plans[k], sizeof t->plans[k], "%s", pick[k]->text);
        snprintf(t->plan_boxes[k], sizeof t->plan_boxes[k], "%s", owner[k]->id);
        t->own_seen[t->n_own_seen++] = fnv1a(pick[k]->text);
    }
    t->own_probed = 0;
    return n;
}

/* A suspicion is only a trigger to measure. Reuse or synthesis is allowed
   only when the direct measurement positively identifies content blocking. */
static int verdict_proves_block(d2k_verdict verdict) {
    return verdict == D2K_V_PREFIX || verdict == D2K_V_WHOLE ||
           verdict == D2K_V_OPAQUE;
}

static const d2k_cat_plan *plan_by_id(const d2k_cat_box *b, const char *id);

/* ФОРМА, КОТОРУЮ ПРЯМОЙ ЗАМЕР ДЕЙСТВИТЕЛЬНО МЕРИЛ (задача 21).
 *
 * asked_shape — форма входа замера; ноль у неё — «не записана» (QUIC мерится
 * без неё, семейный путь берёт форму триггера, которой может не быть). Ноль
 * в d2k_cat_shape_fits совместим с ЛЮБОЙ формой, и прямой проход, измеренный
 * профилем TLS 1.3, снимал бы привязки TLS 1.2 и ECH, которых никто не
 * проверял (§4). Поэтому неизвестная форма заменяется формой профиля
 * измерения — той же, что легла бы в привязку при успехе (rec_shape в
 * verify_confirm): QUIC — QUIC, ECH-предложение — ECH, приветствие TLS 1.2 —
 * LEGACY, иначе профиль зонда (TLS 1.3). */
static uint8_t clear_measured_shape(const task *t) {
    if (t->asked_shape) { return t->asked_shape; }
    if (t->transport == 17) { return (uint8_t)D2K_LINK_SHAPE_QUIC; }
    if (t->ech_offer) { return (uint8_t)D2K_LINK_SHAPE_ECH_TCP; }
    return d2k_hello_shape(t->trig, t->trig_len) == D2K_SHAPE_LEGACY
               ? (uint8_t)D2K_SHAPE_LEGACY : (uint8_t)SCHED_PROBE_SHAPE;
}

static int clear_binding_matches(const d2k_cat_binding *bd, const task *t,
                                 uint8_t measured) {
    if(encrypted_dns_task(t))return dns_binding_matches_task(bd,t) && bd->shape==measured;
    uint8_t tr = bd->transport ? bd->transport : 6;
    return strcmp(bd->kind, "name") == 0 && strcmp(bd->target, t->name) == 0 &&
           tr == t->transport && (bd->family ? bd->family : 4) == t->family &&
           d2k_cat_shape_fits(bd->shape, measured);
}

static int clear_preflight_endpoint(const d2k_cat_box *box, const d2k_cat_binding *bd,
                                     const task *t, uint8_t measured) {
    if (!t->vol.rx_direct_complete || t->transport != 6 || !bd->enabled ||
        bd->transport != 6 || bd->family != t->family || bd->shape != measured ||
        !t->port || bd->server_port != t->port ||
        strcmp(bd->kind, "service") || strcmp(bd->target, t->ip) ||
        !bd->preflight_name[0] || strcasecmp(bd->preflight_name, t->name)) return 0;
    const d2k_cat_plan *plan = plan_by_id(box, bd->plan_id);
    return plan && preflight_text(plan->text);
}

/* ОДИН ПРЯМОЙ ПРОХОД НЕ СТИРАЕТ ПОДТВЕРЖДЁННОЕ (задача 21, D2K_SPEC §3.7,
 * §7, §9.7).
 *
 * Прежде первый же CLEAR удалял привязку из каталога и слал широкую DEL_NAME:
 * та уносила все записи имени в датапате — пробу параллельной QUIC-задачи,
 * подтверждённое TLS 1.2/ECH — и восстанавливала «выжившие» повтором. Один
 * transient (коробка на минуту замолчала) стирал знание, оплаченное поиском.
 *
 * Теперь:
 *   1. Первый CLEAR — привязка той формы, что мерилась (clear_measured_shape),
 *      помечается «требует повторной проверки» (recheck_since), снимается с
 *      провода ровно своим ключом (DEL_NAME v9: имя, транспорт, форма на
 *      проводе, семейство; пробы не трогаются) и проходом каталога больше не
 *      ставится. Цель идёт прямым путём — это и есть «блок исчез — прямой
 *      путь» до решения. Если блок вернётся, новое подозрение ведёт к замеру,
 *      и знакомая коробка сначала проверяет свои планы (known_plans,
 *      rx_saved_bootstrap) — подтверждение того же плана снимает пометку
 *      (bind_confirmed) и возвращает привязку на провод.
 *   2. Второй НЕЗАВИСИМЫЙ CLEAR — привязка удаляется из каталога.
 *
 * НЕЗАВИСИМОСТЬ — по тому же принципу, что у позднего RST (задача 18:
 * другой поток, а не повтор того же): второй CLEAR должен прийти из
 * ОТДЕЛЬНОГО прямого замера. Каждый прямой замер открывает свои соединения
 * (новые местные порты — другой 4-tuple), а на одну цель одновременно идёт
 * одна задача; отделённость замеров во времени закреплена порогом
 * SCHED_RECHECK_GAP_MS от пометки в этом процессе (прямые замеры цели и так
 * разнесены временным ограничителем CLEAR ≥ 10 мин). Пометка, пережившая
 * перезапуск (recheck_mono_ms == 0), заведомо поставлена другим замером.
 * Верхнего окна нет: до решения привязка уже снята с провода, и ждать второго
 * замера сколько угодно безвредно — ни обход, ни знание не теряются. */
#define SCHED_RECHECK_GAP_MS (60LL * 1000)

static void forget_clear_target_bindings(d2k_sched *s, task *t, int64_t now_ms) {
    if(s && t && newchain_task(s,t))return;

    if (!s || !s->cat || !t || t->by_addr) { return; }
    uint8_t measured = clear_measured_shape(t);
    size_t marked = 0, removed = 0, waiting = 0;
    char err[200];
    for (size_t bi = 0; bi < s->cat->n_boxes; bi++) {
        d2k_cat_box *b = &s->cat->boxes[bi];
        for (size_t j = 0; j < b->n_binds;) {
            d2k_cat_binding *bd = &b->binds[j];
            int preflight = clear_preflight_endpoint(b, bd, t, measured);
            if (!preflight && !clear_binding_matches(bd, t, measured)) { j++; continue; }
            if (bd->recheck_since &&
                (bd->recheck_mono_ms == 0 ||
                 now_ms - bd->recheck_mono_ms >= SCHED_RECHECK_GAP_MS)) {
                /* Второй независимый прямой проход: привязка не нужна. С
                   провода она снята ещё при пометке. */
                memmove(bd, bd + 1, (b->n_binds - j - 1) * sizeof *bd);
                b->n_binds--;
                b->updated = wall_s(s, now_ms);
                removed++;
                continue;
            }
            if (bd->recheck_since) { waiting++; j++; continue; }
            /* A saved SYN program uses an endpoint key. Leave a newer owner
               of the same key alone, including an ordinary payload plan. */
            if (preflight && !newer_target_binding(s->cat, bd)) {
                uint8_t address[16];
                if (inet_pton(t->family == 6 ? AF_INET6 : AF_INET, t->ip, address) != 1 ||
                    d2k_link_del_endpoint(s->link_fd, address, t->family, htons(t->port),
                                          bd->shape, err, sizeof err)) {
                    say(s, "по %s не удалось снять программу пробы %s", t->name, bd->plan_id);
                    j++;
                    continue;
                }
            }
            bd->recheck_since = wall_s(s, now_ms);
            bd->recheck_mono_ms = now_ms ? now_ms : 1;
            uint8_t tr = bd->transport ? bd->transport : 6;
            uint8_t wire_shape = bd->shape ? bd->shape : (uint8_t)D2K_LINK_SHAPE_GRANDFATHER;
            int rc;
            if (preflight) rc = 0;
            else if(encrypted_dns_task(t)) {
                uint8_t address[16];
                rc=inet_pton(t->family==6?AF_INET6:AF_INET,t->ip,address)!=1 ? -1 :
                    d2k_link_del_endpoint(s->link_fd,address,t->family,htons(t->port),wire_shape,err,sizeof err);
            } else rc=d2k_link_del_name_family(s->link_fd,t->name,tr,wire_shape,t->family,err,sizeof err);
            if (rc != 0) {
                say(s, "по %s привязку %s не удалось снять с провода: %s",
                    t->name, bd->plan_id, err);
            }
            marked++;
            j++;
        }
    }
    if (marked || removed) {
        s->cat->revision++;
        if (encrypted_dns_task(t)) s->encrypted_dns_revision = s->cat->revision;
    }
    if (marked) {
        say(s, "по %s напрямую проходит — привязок требуют повторной проверки: %zu "
               "(сняты с провода, в каталоге сохранены до второго независимого замера)",
            t->name, marked);
    }
    if (removed) {
        say(s, "по %s второй независимый прямой проход — удалено привязок: %zu; "
               "цель идёт прямым путём", t->name, removed);
    }
    if (waiting) {
        say(s, "по %s прямой проход не независим от пометки (тот же замер) — "
               "привязок ждут второго замера: %zu", t->name, waiting);
    }
}

/* Вектор свойств словами. Нужен наружу: иначе «кандидатов 3» ничего не
   говорит о том, ЧЕМ коробка себя выдала, а это и есть результат опроса.
   Тройственность сохраняется буквально — «не измерено» не превращается в
   «нет» (§2.4). */
static void props_text(const d2k_props *p, char *out, size_t cap) {
    static const char *v[] = { "не измерено", "да", "нет" };
    snprintf(out, cap,
             "перекрытие слева=%s, счёт дубликатов=%s, порядок сегментов=%s, "
             "контрольная сумма=%s, разбор протокола=%s",
             v[p->tolerates_left_overlap % 3], v[p->counts_duplicates % 3],
             v[p->tolerates_reorder % 3], v[p->validates_checksum % 3],
             v[p->parses_l7 % 3]);
}

/* «опыт», «опыта», «опытов» — по числу. Русский счёт не выводится из
   форматной строки, а «за 41 опытов» читается как машинный перевод: это
   текст, который читает человек в журнале контроллера. */
static const char *probes_word(int n) {
    int t = n % 100;
    if (t >= 11 && t <= 14) { return "опытов"; }
    switch (n % 10) {
    case 1:  return "опыт";
    case 2:
    case 3:
    case 4:  return "опыта";
    default: return "опытов";
    }
}

/* Кандидаты из вердикта.
 *
 * Принимает ВЕСЬ результат, а не один класс блокировки: измеритель, который
 * находит конкретное воздействие (перенесённый «Поиск по домену», detect/),
 * приносит его тут же, в d2k_vres.arm. Раньше здесь стоял только класс, и
 * найденное плечо было девать некуда. */
static void verdict_to_plans(d2k_sched *s, task *t, const d2k_vres *r) {
    d2k_verdict v = t->doh_trial && r->verdict==D2K_V_CLEAR ? D2K_V_INCONCLUSIVE : r->verdict;
    t->next_plan = 0;
    t->n_known = 0;
    t->n_plans = 0;
    t->fb_queue = 0;
    t->search_owned = r->owns_search;
    t->arm_hash = 0;
    t->arm_path[0] = '\0';
    /* Имя приёма — от ЭТОГО прогона; список опровергнутых — от поиска, и
       здесь не трогается: его смысл в том, чтобы пережить прогон. */
    t->arm_name[0] = '\0';
    d2k_verification_free(t->synthesis_owner);
    t->synthesis_owner = NULL;
    t->synthesis_result = D2K_VF_UNKNOWN;
    memset(t->synthesis_result_trial,0,sizeof t->synthesis_result_trial);
    t->synthesis_generation = 0;
    memset(t->plan_boxes, 0, sizeof t->plan_boxes);
    memset(t->net_probe_name, 0, sizeof t->net_probe_name);
    /* Failed reuse does not prove this is the same box. A newly synthesized
       plan must not silently enlarge the first vaguely matching model. */
    t->box_id[0] = '\0';

    if (v == D2K_V_CLEAR || v == D2K_V_UNREACHABLE ||
        v == D2K_V_ADDRESS || v == D2K_V_RESPONSE ||
        v == D2K_V_NO_QUIC || v == D2K_V_LOCAL_ADDRESS) {
        /* Кандидатов НЕТ, и это не бедность перебора. При блоке по адресу
           десинк не снимает ничего (ответ — туннель), а при блоке ответа
           резать запрос бессмысленно: он и так проходит. Не обслуживающему
           HTTP/3 хосту обход не нужен вовсе, а имя, разрешённое в приватный
           адрес, мы не мерили и мерить не можем. Предлагать сюда планы
           значило бы жечь бюджет зондов на заведомо ложной гипотезе. */
        return;
    }
    if (r->program_len) {
        /* Exact synthesis output is a candidate, never an installed proof.
           Reject malformed/oversized text rather than reconstruct an arm or
           silently substitute a legacy search after a transfer failure. */
        t->search_owned = 1;
        char why[200] = "некорректная длина программы";
        if (r->program_len < sizeof r->program &&
            r->program_len < sizeof t->plans[0] &&
            r->program[r->program_len] == '\0' &&
            !memchr(r->program, '\0', r->program_len)) {
            if(force_name(s,t->name)) {
                uint32_t h=(uint32_t)fnv1a(r->program);
                for(size_t i=0;i<t->n_tried;i++)if(t->tried[i]==h) {
                    say(s,"принудительный поиск: %s — измеренно отвергнутый кандидат %08x повторно не устанавливаю; требуется следующий вопрос",t->name,(unsigned)h);
                    return;
                }
            }
            uint8_t *tlv = malloc(D2K_PLAN_TLV_MAX);
            size_t len = 0;
            d2k_plan *plan = NULL;
            if (!tlv) snprintf(why, sizeof why, "нет памяти для проверки программы");
            else if (!d2k_plan_text_to_tlv(r->program, tlv, D2K_PLAN_TLV_MAX,
                                           &len, why, sizeof why) &&
                     !d2k_plan_load(tlv, len, &plan, why, sizeof why)) {
                uint8_t proto = d2k_plan_proto(plan);
                size_t emit = d2k_plan_max_emit(plan);
                if (d2k_plan_transport(plan) != t->transport ||
                    (t->transport == 6 && proto != 1) ||
                    (t->transport == 17 && proto != 2)) {
                    snprintf(why, sizeof why, "протокол программы не совпадает с опытом TLS/QUIC");
                } else if (s->send_cap && emit > s->send_cap) {
                    snprintf(why, sizeof why, "посылка программы превышает предел отправки");
                } else {
                    memcpy(t->plans[0], r->program, r->program_len + 1);
                    t->n_plans = 1;
                    t->synthesis_generation = r->synthesis_generation;
                    if(t->synthesis_generation) {
                        d2k_synthesis_feedback identity={0};
                        identity.generation=t->synthesis_generation;
                        identity.search_id=t->report_id;
                        identity.target=t->name;identity.ip=t->ip;identity.port=t->port;
                        identity.program=t->plans[0];identity.by_addr=t->by_addr;
                        identity.family=t->family;identity.transport=t->transport;
                        identity.shape=addr_udp(t)?0:probe_shape(t);
                        identity.doh=t->doh_path[0]!=0;
                        identity.resource=identity.doh?t->doh_path:
                            t->measure_path[0]?t->measure_path:"/";
                        int volume=is_late_volume_suspicion(t->trigger_code) ||
                            t->vol.rx_cut || t->vol.verdict==D2K_VOL_CUT;
                        t->synthesis_owner=d2k_verification_new(&identity,volume);
                    }

                    t->arm_hash = fnv1a(r->program);
                    snprintf(t->arm_path, sizeof t->arm_path, "synthesis");
                }
            }
            d2k_plan_free(plan); free(tlv);
        }
        if (!t->n_plans) say(s, "по %s синтезированная программа отклонена: %s", t->name, why);
        return;
    }
    if(t->doh_synthesis_owned)return;
    /* Inconclusive/flaky classification limits our diagnosis, not the
       permitted search space. Candidates remain hypotheses until verified. */
    /* Вектор — накопленный вопросами, а не пустой: в этом весь смысл опроса.
       Пустой вектор d2k_compose честно превращает в ОДИН запасной план, и до
       появления вопросов планировщик только его и получал. */
    size_t cap = sizeof t->plans / sizeof t->plans[0];

    if (t->ech_trial) {
        /* A known origin supplies tools, never the outer target's proof. */
        for (size_t bi = 0; s->cat && bi < s->cat->n_boxes && t->n_plans < cap; bi++) {
            const d2k_cat_box *b = &s->cat->boxes[bi];
            for (size_t j = 0; j < b->n_binds && t->n_plans < cap; j++) {
                const d2k_cat_binding *bd = &b->binds[j];
                if (!bd->enabled || bd->level < 3 || bd->transport != 6 ||
                    (bd->family ? bd->family : 4) != t->family ||
                    (strcmp(bd->target, t->ech_origin) && strcmp(bd->target, t->name))) continue;
                const d2k_cat_plan *p = plan_by_id(b, bd->plan_id);
                if (!p || !p->enabled || !p->text || strcmp(p->proto, "tls") ||
                    strlen(p->text) >= sizeof t->plans[0]) continue;
                int duplicate = 0;
                for (size_t k = 0; k < t->n_plans; k++)
                    if (!strcmp(t->plans[k], p->text)) duplicate = 1;
                if (!duplicate) snprintf(t->plans[t->n_plans++], sizeof t->plans[0], "%s", p->text);
            }
        }
        say(s, "по %s ECH-база неубедительна; %zu собственных планов witness проверяю как гипотезы, без опроса обычного TLS",
            t->name, t->n_plans);
    }

    if (t->transport == 17) {
        /* Снятие QUIC — только по обрыву, воспроизведённому своим запросом
           в этом прогоне, а не по любому OPAQUE при признаке на входе
           (молчание рукопожатия с признаком — вопрос о рукопожатии). */
        if (t->arm.data_cut_seen && r->verdict == D2K_V_OPAQUE) { t->stall_cut = 1; }
        /* У QUIC свой источник кандидатов — подобранное плечо. Разрезы и
           перекрытия, которые выводит d2k_compose, к датаграмме не
           применимы вовсе, и предлагать их значило бы тратить бюджет зондов
           на планы, которые датапат честно отвергнет. */
        if (!t->arm_ready) {
            say(s, "по %s (QUIC) плечо не подбиралось — воздействовать не на что",
                t->name);
            return;
        }
        for (size_t qi=0; qi<t->arm.n_trace && qi<D2K_QUIC_ARM_STEPS; qi++) {
            const d2k_quic_arm_step *step=&t->arm.trace[qi];
            const char *note=step->not_measured==1 ? "не задано: адреса" :
                step->not_measured==2 ? "не задано: бюджет" :
                step->not_measured==3 ? "не измерено: не собрано/локальный отказ" :
                /* Task 39: the filter alone is not an arm's pass. */
                step->data==D2K_QAD_NO_HANDSHAKE ? "ответ есть, рукопожатия нет: не прошло" :
                step->data==D2K_QAD_CUT ? "рукопожатие есть, поток встал без полного ответа ниже порога: не прошло" :
                step->answered==D2K_QUIC_REPEATS ? "прошло" :
                step->answered>0 ? "неустойчиво, не засчитано" : "не прошло";
            say(s, "по %s (QUIC) %s, адрес %s: %d/%d, %s%s%s", t->name,
                step->label, step->addr[0]?step->addr:"—", step->answered,step->sent,note,
                step->data?"; ":"", step->data?step->data_note:"");
        }
        /* ТРИ РАЗНЫХ ИСХОДА, И ИХ НЕЛЬЗЯ СЛИВАТЬ В ОДИН.
           «Не нашлось» — это про коробку и бюджет: перебор дошёл до конца и
           не нашёл, чем её взять. «Верить нельзя» — про измерение: повторы
           разошлись. «Не выразимо» — про НАС: воздействие найдено, а языка
           плана на него нет (0007 п.3). Прежде все три печатались как
           «не выразимо», и лаборатория 13.09 на коробке без состояния
           отчиталась пробелом реализации там, где на деле кончился бюджет
           развёртки TTL. */
        if (t->arm.kind == D2K_QA_FLAKY) {
            say(s, "по %s (QUIC) подбору плеча верить нельзя: %s",
                t->name, t->arm.reason);
            return;
        }
        /* compose ДОНОРА ЦЕЛИКОМ (questions.go:296-345): плечо askArms И
           подтверждённые свойства вопросника — один план. «Мусор перед
           Initial» и «длина» без плеча — тоже план, а не «плечо не нашлось»:
           ответ измерен, и выбрасывать его значило бы терять находку
           оригинала. The result owns the EXACT fake measured by original
           askArms; rebuilding a similar ClientHello would install another
           hypothesis. */
        const d2k_quic_props *qp = &r->qprops;
        if (t->arm.kind == D2K_QA_SPLIT && quic_split_unfit(s, t)) {
            say(s, "по %s (QUIC) разрез CRYPTO прошёл замер, но клиенту неприменим: его "
                   "ClientHello шире датаграммы (или вход замера не в одной датаграмме) — "
                   "план разреза не строю", t->name);
            return;
        }
        int arm_found = t->arm.kind != D2K_QA_NOT_FOUND;
        char text[sizeof t->plans[0]];
        if (t->arm.original && d2k_quic_compose_plan(&t->arm, qp, text, sizeof text) == 0) {
            if (t->n_plans < cap) {
                memcpy(t->plans[t->n_plans], text, strlen(text) + 1);
                t->n_plans++;
            }
            if (arm_found && (t->arm.strategy == D2K_QS_CLEARANCE ||
                              t->arm.strategy == D2K_QS_SPLIT ||
                              t->arm.strategy == D2K_QS_FRAG ||
                              t->arm.strategy == D2K_QS_LENGTH ||
                              t->arm.strategy == D2K_QS_TTL_LIFETIME ||
                              t->arm.strategy == D2K_QS_FAKE_SPLIT)) {
                /* Задача 40: план собран из ответа вопроса, приманки не
                   перебирались. */
                say(s, "по %s (QUIC) стратегия из замера за %d %s: %s",
                    t->name, t->arm.probes, probes_word(t->arm.probes), t->arm.reason);
                t->arm_hash=fnv1a(text);
                snprintf(t->arm_path,sizeof t->arm_path,"свойство");
            } else if (arm_found) {
                say(s, "по %s (QUIC) плечо подобрано за %d %s: %s",
                    t->name, t->arm.probes, probes_word(t->arm.probes), t->arm.reason);
                t->arm_hash=fnv1a(text);
                snprintf(t->arm_path,sizeof t->arm_path,"перебор");
            } else {
                say(s, "по %s (QUIC) плечо не подобрано (%s), план собран из свойств коробки",
                    t->name, t->arm.incomplete ? "поиск не завершён" : "перебор исчерпан");
            }
            int fake_from_arm = arm_found && t->arm.kind != D2K_QA_FRAG;
            if (qp->junk_ahead == D2K_PROP_YES && t->arm.strategy != D2K_QS_CLEARANCE) {
                say(s, fake_from_arm
                    ? "по %s (QUIC) «мусор перед Initial» взял, но у донора его вытесняет фальшивка плеча"
                    : "по %s (QUIC) в план: «мусор перед Initial» — 16 нулевых байт ×2 перед Initial",
                    t->name);
            }
            if (qp->longer == D2K_PROP_YES) {
                if (t->arm.strategy == D2K_QS_CLEARANCE || t->arm.strategy == D2K_QS_TTL_LIFETIME) {
                    say(s, "по %s (QUIC) «длина» взяла, но с выбранным воздействием её не мерили — "
                           "в план не входит", t->name);
                } else if (t->arm.kind == D2K_QA_SPLIT) {
                    say(s, "по %s (QUIC) «длина» взяла, но с разрезом CRYPTO её не мерили — "
                           "в план не входит", t->name);
                } else if (t->arm.frag_kind) {
                    say(s, "по %s (QUIC) «длина» взяла, но у донора udplen стоит после drop "
                           "фрагментации и на провод не попадает — в план не входит", t->name);
                } else {
                    say(s, "по %s (QUIC) в план: «длина» — к Initial дописывается 100 нулевых байт%s",
                        t->name, qp->longer_profile == 1
                        ? " (свойство измерено PROFILE: собственным Initial донора в 1300 байт, "
                          "не формой клиента)" : "");
                }
            }
        } else if (arm_found) {
            /* Сюда доходят только НАЙДЕННЫЕ, но неполные/невыразимые плечи:
               неизвестная форма фрагментации или потерянный блоб. Это пробел
               РЕАЛИЗАЦИИ, а не свойство коробки (0007 п.3), и подменять его
               похожим запрещено. */
            say(s, "по %s (QUIC) плечо не выразимо сегодняшним языком плана: %s",
                t->name, t->arm.reason);
        } else if (t->arm.incomplete) {
            say(s, "по %s (QUIC) поиск не завершён, кандидат не найден: %s",
                t->name,t->arm.reason);
        } else {
            say(s, "по %s (QUIC) плечо не нашлось за %d %s: %s",
                t->name, t->arm.probes, probes_word(t->arm.probes), t->arm.reason);
        }
        return;
    }

    d2k_shape sh = d2k_hello_shape(t->trig, t->trig_len);

    if (t->transport == 6 &&
        (t->vol.verdict == D2K_VOL_CUT || t->vol.rx_cut)) {
        if (t->vol.verdict == D2K_VOL_CUT) {
            d2k_cat_signal sig;
            memset(&sig, 0, sizeof sig);
            snprintf(sig.kind, sizeof sig.kind, "volume");
            sig.volume = t->vol.at_kb;
            sig.seen = 1;
            fp_add(&t->fp, &sig);
        }
        if (t->vol.rx_cut) {
            d2k_cat_signal sig;
            memset(&sig, 0, sizeof sig);
            snprintf(sig.kind, sizeof sig.kind, "%s",
                     t->vol.rx_wire_basis ? "rx-volume-wire" : "rx-volume");
            sig.volume = t->vol.rx_at_kb;
            sig.packets = t->vol.rx_cut_packets; /* бюджет потока коробки (задача 55) */
            sig.seen = 1;
            fp_add(&t->fp, &sig);
        }
        /* Повторно узнаём коробку уже по полной примете, включая измеренный
           объём. Первичный lookup был до сетевого измерения и не мог знать
           этого сигнала; новые домены иначе не переиспользовали бы подходящую
           коробку. known_plans пропускает уже испытанные тексты. */
        t->n_known = known_plans(s, t);
        t->n_plans = t->n_known;
        if (t->n_known) {
            snprintf(t->box_id, sizeof t->box_id, "%s", t->plan_boxes[0]);
            say(s, "по %s обрыв объёма %d КБ совпал с коробкой %s — "
                   "сначала проверяю её сохранённые планы",
                t->name, t->vol.at_kb, t->box_id);
        }
    }

    /* НАЙДЕННОЕ ЗАМЕРОМ — ПЕРВЫМ, и это не приоритет «на всякий случай».
       Плечо здесь не гипотеза: измеритель уже прогнал его по цели столько раз,
       сколько задано повторами, и засчитал только при единогласии. Ставить
       перед ним кандидатов, выведенных из вектора свойств, значило бы тратить
       бюджет зондов на догадки, имея на руках измеренный ответ. */
    if (r->have_arm && t->n_plans < cap) {
        char text[sizeof t->plans[0]];
        int rc = d2k_arm_plan_measured_cap(&r->arm, &r->arm_input, s->send_cap,
                                           text, sizeof text);
        /* Задача 37, I2: план без предела собирается, а с пределом — нет:
           посылка не помещается в канал датапата, опыт не состоялся бы
           (BAD_PLAN). Урезать измеренные байты нельзя — другое воздействие. */
        int unfit = rc != 0 && s->send_cap > 0 &&
            d2k_arm_plan_measured(&r->arm, &r->arm_input, text, sizeof text) == 0;
        if (rc == 0) {
            memcpy(t->plans[t->n_plans], text, strlen(text) + 1);
            t->n_plans++;
            t->arm_hash = fnv1a(text);
            snprintf(t->arm_path, sizeof t->arm_path, "%s", r->arm_path);
            snprintf(t->arm_name, sizeof t->arm_name, "%s", r->arm_name);
            /* Путь находки — в той же строке: доля «перебора» в поле меряет,
               чего классификатор ещё не знает (§0.1 ТЗ, 09.10.2026). */
            say(s, "по %s приём «%s» НАЙДЕН замером%s%s%s search=%llu protocol=%s family=%u "
                   "— ставлю его первым кандидатом",
                t->name, r->arm_name, r->arm_path[0] ? " (путь: " : "", r->arm_path,
                r->arm_path[0] ? ")" : "", (unsigned long long)t->report_id,
                t->transport == 17 ? "quic" : "tcp", (unsigned)t->family);
        } else if (unfit) {
            say(s, "по %s приём «%s» найден замером, но его посылка не помещается "
                   "в предел отправки %u байт — кандидатом не ставлю",
                t->name, r->arm_name, (unsigned)s->send_cap);
        } else {
            /* Пробел РЕАЛИЗАЦИИ, а не свойство коробки (0007 п.3): воздействие
               найдено и на замере сработало, задать его планом мы не умеем.
               Молчать нельзя — иначе «плана нет» читается как «не взяли». */
            say(s, "по %s приём «%s» сработал на замере, но сегодняшним языком плана "
                   "не задаётся", t->name, r->arm_name);
        }
    }

    /* После сохранённых коробок и уже найденного самим измерителем приёма,
       подтверждённый RX-volume профиль добавляет короткую fake-SNI/split-
       лестницу до общего синтеза. Это общий fingerprint-путь, без списка
       имён и без исключения для отдельного сайта. */
    if (t->transport == 6 && vol_cut_measured(t) && sh != D2K_SHAPE_MODERN) {
        say(s, "по %s обрыв объёма измерен, но TLS-форма %u не modern — "
               "fake-SNI/split-профиль не применим",
            t->name, (unsigned)sh);
    }
    if (t->transport == 6 && vol_cut_measured(t) && sh == D2K_SHAPE_MODERN) {
        char text[sizeof t->plans[0]];
        /* Белое имя сети не решено — RX-лестница сперва перебирает кандидаты
           как приманку (поле 10.10.2026); решено — берёт готовое/семя. */
        t->net_probing = net_whitelist_needs_probe(s, t);
        /* При одном TX-обрыве сразу — одна ступень: места в очереди остаются
           кандидатам, выведенным из замера, как в выпуске (их вытесняла
           лестница, тесты коробок задачи 23). Остальные ступени долива —
           после них и перед запасным перебором (refill_from_fallback). Это
           порядок, а не предел: число ступеней не урезается. */
        size_t room = t->vol.rx_cut ? cap : (t->n_plans + 1 < cap ? t->n_plans + 1 : cap);
        while (t->n_plans < room &&
               next_rx_volume_plan(s, t, sh, text, sizeof text)) {
            snprintf(t->plans[t->n_plans], sizeof t->plans[t->n_plans], "%s", text);
            t->plan_boxes[t->n_plans][0] = '\0';
            snprintf(t->net_probe_name[t->n_plans], sizeof t->net_probe_name[t->n_plans],
                     "%s", t->net_probe_scratch);
            t->n_plans++;
        }
        t->rx_volume_candidate_pending = rx_ladder_pending(t);
        /* КАКОЙ ПРОГРАММОЙ ПОШЛА ЛЕСТНИЦА — В ЖУРНАЛ (поле issue #7). У
           клиента без метки времени восстановленная программа поля неисполнима
           (датапат отказывает кодом FLOW_UNFIT), и лестница идёт с TTL по
           измеренному пути. Разные программы — разные опыты, и в журнале их
           обязано быть видно. */
        if (t->n_plans > 0 && !client_offers_ts(t)) {
            say(s, "по %s поток клиента не несёт метку времени — лестница идёт "
                   "с TTL по измеренному пути вместо метки (план с меткой "
                   "датапат этому клиенту не исполнит)", t->name);
        }
        if (t->net_probing) {
            say(s, "по %s белое имя сети не известно — подбираю его из %zu имён "
                   "списка приманкой под измеренный %s около %d КБ",
                t->name, d2k_net_whitelist_count(),
                t->vol.rx_cut ? "RX-обрыв" : "обрыв исходящей лестницы", vol_cut_kb(t));
        } else {
            if (t->rx_volume_candidate_pending) {
                say(s, "по %s сохранённые планы коробки занимают очередь; "
                    "объёмная fake-SNI/split-лестница ждёт их испытания",
                    t->name);
            }
            say(s, "по %s %s около %d КБ: проверю короткую fake-SNI + split-лестницу "
                   "(приманка «%s») после сохранённых планов",
                t->name, t->vol.rx_cut ? "повторяемый обрыв входящего identity-тела"
                                       : "обрыв исходящей лестницы", vol_cut_kb(t),
                rx_decoy_name(s));
        }
    }

    if (r->owns_search) {
        /* PREFIX/WHOLE are found solutions too: the source measured a
         * forward split at split_pos with write_gap_ms. No poison search. */
        if (!r->have_arm && (v == D2K_V_PREFIX || v == D2K_V_WHOLE) &&
            r->split_pos > 0 && (size_t)r->split_pos < t->trig_len) {
            if (d2k_tcp_split_plan(t->trig_len, (unsigned)r->split_pos, r->split_gap_us,
                                   s->send_cap, t->plans[0], sizeof t->plans[0]) == 0) {
                t->n_plans = 1;
            }
        }
        /* ЗАМЕР ВЛАДЕЕТ ПОИСКОМ, НО ПОСТАВИТЬ НЕЧЕГО. Поле 04.10, чистый
           каталог: rutracker.org и discord.com — «решает содержимое», взят
           только «oob» (URG языком плана не выражается), после него ни одна
           выразимая отрава не прошла; итог был «кандидатов 0» и отдых.
           Рабочий план этих целей (680fbe00) 02.10 вырос из запасного
           списка: его кандидат снял ранний TLS-блок, identity оборвался, и
           остаточная RX-лестница нашла fake-first план. Внутренние гипотезы
           оригинала — часть переносимого поведения (AGENTS.md), поэтому
           здесь запасной список берётся ЯВНО, по этому условию, а не через
           устаревший флаг владения (его закрыл 423507f, задача 37). */
        if (t->n_plans == 0 && t->transport == 6 && v == D2K_V_OPAQUE) {
            say(s, "по %s замер владеет поиском, блок доказан, а выразимого планом приёма нет — "
                   "беру внутренние гипотезы оригинала (запасной список)", t->name);
            t->owned_fallback = 1;
            (void)refill_from_fallback(s, t);
        }
        return;
    }
    if (t->n_plans < cap) {
        t->n_plans += d2k_compose(&t->props, sh, SCHED_DECOY, s->send_cap,
                                  t->plans + t->n_plans, cap - t->n_plans);
    }
}

/* --------------------------------------------------------------------
 * Открытое наружу.
 * -------------------------------------------------------------------- */

static size_t measurements_in_flight(const d2k_sched *s);
static size_t queued_measurements(const d2k_sched *s);
static int cpu_free_pct(const d2k_sched *s);
static uint64_t mem_reserve_kb(const d2k_sched *s);
static int ct_pct(const d2k_sched *s);
static void limiter_text(unsigned lm, char *buf, size_t n);

d2k_sched *d2k_sched_new(d2k_catalog *cat, int link_fd, uint32_t mark) {
    if (!cat) { errno = EINVAL; return NULL; }
    d2k_sched *s = calloc(1, sizeof *s);
    if (!s) { return NULL; }
    s->cat = cat;
    s->link_fd = link_fd;
    s->mark = mark;
    s->measure_mark = mark;
    s->stall_sent[0] = D2K_TCP_STALL_FIELD_BUDGET;
    s->n_stall_sent = 1;
    s->meas_limit = SCHED_DEFAULT_ACTIVE_MEASUREMENTS;
    s->limit_logged = SCHED_DEFAULT_ACTIVE_MEASUREMENTS;
    s->wake[0] = s->wake[1] = -1;
    s->wall_base_s = (int64_t)time(NULL);
    /* Ход QUIC-прогона — тем же приёмником, что TCP (задача 49). Приёмник
       поточный: вне рабочего потока задачи вызов ничего не делает. */
    d2k_quic_progress_hook = sched_quic_progress;
    d2k_quic_yield_hook = sched_quic_yield;
    /* The MIPS Linux pipe syscall returns the first descriptor in v0 (and
       the second in v1); Zig's musl wrapper exposes that positive value here
       instead of normalizing success to POSIX's zero. The descriptor pair is
       still written to wake[]. Accept every non-negative success value. */
    if (pipe(s->wake) < 0) {
        free(s);
        return NULL;
    }
    for (int i = 0; i < 2; i++) {
        int fl = fcntl(s->wake[i], F_GETFL, 0);
        if (fl >= 0) { (void)fcntl(s->wake[i], F_SETFL, fl | O_NONBLOCK); }
    }
    int mutex_error = pthread_mutex_init(&s->mu, NULL);
    if (mutex_error != 0) {
        close(s->wake[0]); close(s->wake[1]);
        free(s);
        errno = mutex_error;
        return NULL;
    }
    int cond_error=pthread_cond_init(&s->question_cv,NULL);
    if(cond_error){
        pthread_mutex_destroy(&s->mu);close(s->wake[0]);close(s->wake[1]);
        free(s);errno=cond_error;return NULL;
    }
    return s;
}

void d2k_sched_set_measure_mark(d2k_sched *s, uint32_t mark) {
    if (s) { s->measure_mark = mark; }
}

/* --------------------------------------------------------------------
 * Вид для панели. См. d2k_sched_write_live в d2k_sched.h.
 * -------------------------------------------------------------------- */

/* Экранирование строки в JSON. Тот же минимум, что и у писателя каталога:
   кавычка, обратная косая и управляющие. Имена целей приходят ИЗ СЕТИ, и
   пропустить их в файл как есть значило бы отдать панели то, что она разберёт
   не так, как мы записали. */
static void json_str(FILE *f, const char *s) {
    fputc('"', f);
    for (const unsigned char *p = (const unsigned char *)(s ? s : ""); *p; p++) {
        if (*p == '"' || *p == '\\') { fprintf(f, "\\%c", *p); }
        else if (*p < 0x20) { fprintf(f, "\\u%04x", *p); }
        else { fputc(*p, f); }
    }
    fputc('"', f);
}

static void json_time(FILE *f, int64_t unix_s) {
    if (unix_s <= 0) {
        fputs("\"0001-01-01T00:00:00Z\"", f); /* нулевое время Go — панель знает его */
        return;
    }
    time_t t = (time_t)unix_s;
    struct tm tmv;
    gmtime_r(&t, &tmv);
    char buf[32];
    strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tmv);
    json_str(f, buf);
}

/* Уровень доказательства словами — §4.2. Те же слова, что у status.LevelName
   на Go-стороне: подобраны так, чтобы уровень 2 нельзя было прочитать как
   уровень 4. Панель берёт готовую строку и не толкует число сама. */
static const char *level_name(int n) {
    switch (n) {
    case 1: return "транспорт установился";
    case 2: return "сервер ответил";
    case 3: return "обмен прошёл";
    case 4: return "прикладной обмен в проверенном объёме";
    case 5: return "подтверждён последующими соединениями";
    default: return "не измерено";
    }
}

/* Примета словами. Шаблон панели не должен знать, что 0x88 это ToS, а 54321 —
   идентификатор IP: собирается здесь, как и на Go-стороне. */
static void signal_human(const d2k_cat_signal *sig, char *out, size_t cap) {
    if (strcmp(sig->kind, "rst") == 0) {
        snprintf(out, cap, "подделанный сброс, TTL %u (на %d от сервера), ToS 0x%02x, ip id %u",
                 (unsigned)sig->ttl, sig->ttl_delta, (unsigned)sig->tos, (unsigned)sig->ipid);
    } else if (strcmp(sig->kind, "volume") == 0) {
        snprintf(out, cap, "обрыв по объёму около %d КБ", sig->volume);
    } else if (strcmp(sig->kind, "rx-volume") == 0) {
        snprintf(out, cap, "identity-ответ стабильно оборвался около %d КБ", sig->volume);
    } else if (strcmp(sig->kind, "rx-volume-wire") == 0) {
        snprintf(out, cap, "TLS-запись дважды оборвалась около %d КБ RX; меньший gzip дошёл", sig->volume);
    } else if (strcmp(sig->kind, "silent") == 0) {
        snprintf(out, cap, "ответа на приветствие не было");
    } else if (strcmp(sig->kind, "repeat") == 0) {
        snprintf(out, cap, "приветствие повторено");
    } else {
        snprintf(out, cap, "%s", sig->kind);
    }
}

/* Чем занята задача прямо сейчас — теми же словами, что показывала панель у
   Go-контроллера: §8 требует различать «распознаём», «проверяем готовое» и
   «ищем новое», и сливать их в одно нельзя. */
static const char *task_phase(const task *t) {
    switch (t->state) {
    case T_QUEUED:        return "ожидает безопасного слота замера";
    case T_SHAPE_WAIT:    return "ждём форму приветствия";
    case T_GATE_COMMIT: return "сохраняем подтверждённый endpoint preflight";
    case T_GATE_INSTALL: return "ждём установку endpoint preflight";
    case T_GATE_VERIFY: return "проверяем TLS и полный HTTP через preflight";
    case T_ASKING:        return "распознаём поведение";
    case T_PROPS_CONTACT:
    case T_PROPS_WAIT:    return "спрашиваем коробку о свойствах";
    case T_PLANNING:      return "выводим планы";
    case T_TRIAL_SETTLE:
    case T_VERIFY:
    case T_VERIFY_WAIT:   return t->next_plan <= t->n_known
                                     ? "проверяем готовое узнанной коробки"
                                     : "проверяем выведенный план";
    case T_DOH_HEALTH:    return "проверка работоспособности DoH";
    case T_DNS_PLAIN_TRIAL:return "изолированная проба обычного DNS";
    case T_WATCHING:      return "подтверждено, смотрим живой трафик";
    case T_RESTING:       return "цель отдыхает после неудачи";
    case T_RAW_MEASURE_ACK: return "ждём готовности наблюдения потока";
    case T_RAW_MEASURE_OBSERVE: return "измеряем продолжение потока";
    case T_RAW_MEASURED: return "разбираем измеренные повторы потока";
    case T_STUN_MEASURE: return "проверяем STUN к адресу и порту";
    case T_STUN_ACK: return "ждём установки точного STUN-опыта";
    case T_STUN_PROBE: return "испытываем свой STUN-кандидат";
    case T_STUN_PROOF: return "ждём доказательства исполнения STUN-кандидата";
    case T_STUN_CLIENT: return "проверяем STUN-кандидат на исходном потоке";
    case T_VOICE_INSTALL: return "ждём подтверждения постоянной UDP-привязки";
    case T_VOICE_MEASURE: return "измеряем живой голосовой поток";
    case T_VOICE_TRIAL:   return "приём голоса стоит, ждём разговора";
    case T_VOICE_WATCH:   return "приём применился к разговору, ждём ответа сервера";
    default:              return "заводим поиск";
    }
}

static void write_live_groups(FILE *f, const d2k_sched *s);

void d2k_sched_diagnostics(d2k_sched *s,d2k_diag_observer fn,void *ctx) {
    if(s){s->diagnostic=fn;s->diagnostic_ctx=ctx;}
}
void d2k_sched_synthesis_observer(d2k_sched *s,d2k_synthesis_observer fn,void *ctx) {
    if(s){s->synthesis_observer=fn;s->synthesis_observer_ctx=ctx;}
}
void d2k_sched_diagnostic_counts(d2k_sched *s,d2k_diag_counts *c) {
    if(!s||!c)return;
    memset(c,0,sizeof *c);c->boxes=s->cat->n_boxes;
    pthread_mutex_lock(&s->mu);
    c->memory=s->memory;
    pthread_mutex_unlock(&s->mu);
    c->memory.worker_args_live=c->memory.worker_args_allocated-c->memory.worker_args_freed;
    c->memory.worker_args_live_bytes=c->memory.worker_args_live*sizeof(worker_arg);
    c->memory.catalog_boxes_bytes=s->cat->cap_boxes*sizeof *s->cat->boxes;
    for(size_t i=0;i<s->cat->n_boxes;i++) {
        c->bindings+=s->cat->boxes[i].n_binds;c->plans+=s->cat->boxes[i].n_plans;
        c->memory.catalog_bindings_bytes+=s->cat->boxes[i].cap_binds*sizeof(d2k_cat_binding);
        c->memory.catalog_plans_bytes+=s->cat->boxes[i].cap_plans*sizeof(d2k_cat_plan);
    }
    if(s->cat->groups)c->observations=s->cat->groups->n_observations;
    c->active=measurements_in_flight(s);c->queued=queued_measurements(s);
    for(size_t i=0;i<SCHED_MAX_TASKS;i++) {
        const task *t=&s->tasks[i];
        if(t->state!=T_FREE){c->tasks++;if(t->trig_len||t->snap_len)c->snapshots++;}
    }
}

int d2k_sched_write_live(d2k_sched *s, const char *path, const char *catalog_path) {
    if (!s || !path) { return -1; }
    char tmp[512];
    int n = snprintf(tmp, sizeof tmp, "%s.new", path);
    if (n < 0 || (size_t)n >= sizeof tmp) { return -1; }
    FILE *f = fopen(tmp, "wb");
    if (!f) { return -1; }

    size_t targets = 0;
    for (size_t i = 0; i < s->cat->n_boxes; i++) { targets += s->cat->boxes[i].n_binds; }

    fputs("{\n", f);
    d2k_newchain_json(&s->newchain,f);fputs(",\n",f);
    fputs("  \"linked\": true,\n  \"link_note\": \"\",\n  \"catalog_at\": ", f);
    json_str(f, catalog_path ? catalog_path : "");
    fputs(",\n  \"boxes\": [", f);
    for (size_t i = 0; i < s->cat->n_boxes; i++) {
        const d2k_cat_box *b = &s->cat->boxes[i];
        fputs(i ? ",\n    {" : "\n    {", f);
        fputs("\"id\": ", f); json_str(f, b->id);
        fputs(", \"created\": ", f); json_time(f, b->created);
        fputs(", \"updated\": ", f); json_time(f, b->updated);

        fputs(", \"signals\": [", f);
        for (size_t j = 0; j < b->fp.n_sig; j++) {
            char human[200];
            signal_human(&b->fp.sig[j], human, sizeof human);
            fputs(j ? ", {" : "{", f);
            fputs("\"kind\": ", f); json_str(f, b->fp.sig[j].kind);
            fputs(", \"human\": ", f); json_str(f, human);
            fprintf(f, ", \"seen\": %d}", b->fp.sig[j].seen);
        }
        fputs("], \"plans\": [", f);
        for (size_t j = 0; j < b->n_plans; j++) {
            fputs(j ? ", {" : "{", f);
            fputs("\"id\": ", f); json_str(f, b->plans[j].id);
            fputs(", \"proto\": ", f); json_str(f, b->plans[j].proto);
            fprintf(f, ", \"successes\": %d, \"enabled\": %s",
                    b->plans[j].successes, b->plans[j].enabled ? "true" : "false");
            /* Human панель собирает сама из текста — здесь его и отдаём, а
               второго толкователя плана не заводим. */
            fputs(", \"human\": \"\", \"text\": ", f);
            json_str(f, b->plans[j].text ? b->plans[j].text : "");
            fputc('}', f);
        }
        fputs("], \"bindings\": [", f);
        for (size_t j = 0; j < b->n_binds; j++) {
            const d2k_cat_binding *bd = &b->binds[j];
            fputs(j ? ", {" : "{", f);
            fputs("\"target\": ", f); json_str(f, bd->target);
            fprintf(f, ", \"family\": %u, \"transport\": %u, \"shape\": %u",
                    (unsigned)(bd->family ? bd->family : 4),
                    (unsigned)(bd->transport ? bd->transport : 6), (unsigned)bd->shape);
            fputs(", \"kind\": ", f); json_str(f, bd->kind);
            fprintf(f, ", \"level\": %d, ", bd->level);
            fputs("\"level_name\": ", f); json_str(f, level_name(bd->level));
            fprintf(f, ", \"successes\": %d, ", bd->successes);
            fputs("\"confirmed\": ", f); json_time(f, bd->confirmed);
            fprintf(f, ", \"enabled\": %s, \"recheck\": %s}", bd->enabled ? "true" : "false",
                    bd->recheck_since ? "true" : "false");
        }
        fputs("]}", f);
    }
    fputs(s->cat->n_boxes ? "\n  ],\n" : "],\n", f);

    write_live_groups(f, s);
    fputs("  \"searches\": [", f);
    int first = 1;
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        const task *t = &s->tasks[i];
        if (t->state == T_FREE || t->state == T_WATCHING || t->state == T_RESTING) {
            continue; /* Passive monitoring/backoff is not an active search. */
        }
        fputs(first ? "\n    {" : ",\n    {", f);
        first = 0;
        fputs("\"target\": ", f); json_str(f, t->name);
        fprintf(f, ", \"family\": %u, \"transport\": %u",
                (unsigned)t->family, (unsigned)t->transport);
        fputs(", \"ip\": ", f); json_str(f, t->ip);
        fprintf(f, ", \"port\": %u", (unsigned)t->port);
        fputs(", \"phase\": ", f); json_str(f, task_phase(t));
        fputs(", \"since\": ", f);
        int64_t admitted_ms = t->state == T_QUEUED ? t->queued_ms
                            : (t->began_ms ? t->began_ms : t->started_ms);
        json_time(f, wall_s(s, admitted_ms ? admitted_ms : s->now_ms));
        /* Ход измерителя (задачи 48, 49): зонды задачи — кандидаты плюс
           прогоны измерителя (идущий — по ходу, законченный — его итог);
           вопрос — только пока прогон идёт. Копия под мьютексом: пишет
           рабочий поток. */
        int ask_probes;
        char question[sizeof t->ask_question];
        question[0] = '\0';
        pthread_mutex_lock(&s->mu);
        ask_probes = t->ask_probes;
        if (t->state == T_ASKING) memcpy(question, t->ask_question, sizeof question);
        pthread_mutex_unlock(&s->mu);
        question[sizeof question - 1] = '\0';
        fprintf(f, ", \"attempts\": %zu, \"probes\": %d, ", t->next_plan, t->probes + ask_probes);
        fputs("\"question\": ", f);
        json_str(f, question);
        fputs(", \"candidate\": ", f);
        json_str(f, t->next_plan > 0 ? "план поставлен" : "");
        /* Откуда план, КОТОРЫЙ ИСПЫТЫВАЕМ — только пока он испытывается. У
           задачи в очереди или в замере плана нет, и «выведен из замера» там
           читалось как «цель исключена». */
        int trying = t->state == T_TRIAL_SETTLE || t->state == T_VERIFY ||
                     t->state == T_VERIFY_WAIT;
        fputs(", \"source\": ", f);
        json_str(f, !trying ? ""
                        : t->n_known > 0 && t->next_plan <= t->n_known
                        ? "готовый план узнанной коробки"
                        : t->fb_queue && (t->next_plan ? t->next_plan - 1 : 0) >= t->fb_from
                        ? "запасной перебор" : "выведен из замера");
        fputc('}', f);
    }
    fputs(first ? "],\n" : "\n  ],\n", f);
    /* Непереносимость отдаётся наружу вместе с числом подтверждений, а не
       только в лог: человек смотрит панель, и «подтверждено N» без «а вот
       столько раз план не достался клиенту» читается как «обход работает»
       (седьмая находка лаборатории 13.09.2026). */
    /* Предел замеров (задачи 29, 38): сколько идёт, сколько можно, сколько
       ждёт и по какой нагрузке; null — данных нет (прежний предел). */
    fprintf(f, "  \"measurements\": {\"active\": %zu, \"limit\": %zu, \"queued\": %zu, ",
            measurements_in_flight(s), s->meas_limit, queued_measurements(s));
    if (s->cpu_valid)
        fprintf(f, "\"cores\": %u, \"free_pct\": %d, ", s->cpu_cores, cpu_free_pct(s));
    else
        fputs("\"cores\": null, \"free_pct\": null, ", f);
    /* Задача 38: память, conntrack и во что упёрся предел; null — данных
       нет (или упираться не во что). */
    if (s->mem_valid)
        fprintf(f, "\"mem_avail_mb\": %llu, \"mem_total_mb\": %llu, ",
                (unsigned long long)(s->mem_avail_kb / 1024),
                (unsigned long long)(s->mem_total_kb / 1024));
    else
        fputs("\"mem_avail_mb\": null, \"mem_total_mb\": null, ", f);
    if (s->ct_valid) fprintf(f, "\"conntrack_pct\": %d, ", ct_pct(s));
    else fputs("\"conntrack_pct\": null, ", f);
    if (s->limiter) {
        char why[96];
        limiter_text(s->limiter, why, sizeof why);
        fprintf(f, "\"limited_by\": \"%s\"},\n", why);
    } else {
        fputs("\"limited_by\": null},\n", f);
    }
    /* Цели без вывода (этап 31): отдельно от поисков и каталога — не блок
       и не решение. */
    fputs("  \"unknown\": [", f);
    int first_unknown = 1;
    for (size_t i = 0; i < SCHED_UNKNOWN_SLOTS; i++) {
        const unknown_target *u = &s->unknowns[i];
        if (!u->used) continue;
        fputs(first_unknown ? "\n    {" : ",\n    {", f);
        first_unknown = 0;
        fputs("\"target\": ", f); json_str(f, u->target);
        fputs(", \"kind\": ", f); json_str(f, u->kind);
        fprintf(f, ", \"transport\": %u, \"family\": %u, \"port\": %u, ",
                (unsigned)u->transport, (unsigned)u->family, (unsigned)u->port);
        fputs("\"reason\": ", f); json_str(f, u->reason);
        fputs(", \"why\": ", f); json_str(f, u->why);
        fputs(", \"first\": ", f); json_time(f, u->first_s);
        fputs(", \"last\": ", f); json_time(f, u->last_s);
        fprintf(f, ", \"count\": %u, \"peers\": %d, \"peers_judged\": %d, \"peers_answered\": %d}", u->count,
                u->peers, u->peers_judged, u->peers_answered);
    }
    fputs(first_unknown ? "],\n" : "\n  ],\n", f);
    /* Результат клиентов под планом (этап 34): уровень обмена, не приложение. */
    fputs("  \"plan_results\": [", f);
    int first_po = 1;
    for (size_t i = 0; i < SCHED_PLANOBS_SLOTS; i++) {
        const plan_obs *o = &s->planobs[i];
        if (!o->used) continue;
        fputs(first_po ? "\n    {" : ",\n    {", f);
        first_po = 0;
        fputs("\"target\": ", f); json_str(f, o->name);
        fprintf(f, ", \"port\": %u, \"transport\": %u, \"family\": %u, ", (unsigned)o->port,
                (unsigned)o->transport, (unsigned)o->family);
        fputs("\"plan_id\": ", f); json_str(f, o->plan_id);
        fprintf(f, ", \"answered\": %u, \"suspected\": %u, ", o->answered, o->suspected);
        fputs("\"level\": ", f); json_str(f, o->level[0] ? o->level : "нет ответов");
        fputs(", \"first\": ", f); json_time(f, o->first_s);
        fputs(", \"last\": ", f); json_time(f, o->last_s);
        fputs("}", f);
    }
    fputs(first_po ? "],\n" : "\n  ],\n", f);
    /* Наблюдение потоков по conntrack (этап 37/46): по цели — сколько потоков
       с доказанным ответом, с входящими без доказанных данных, в застое,
       простое, без данных; входящие IP-байты/с (с заголовками) и объём.
       Причины нет — только наблюдение. */
    fputs("  \"flow_health\": [", f);
    int first_fh = 1;
    for (size_t i = 0; i < SCHED_FLOWWATCH_SLOTS; i++) {
        const flow_watch *a = &s->flowwatch[i];
        if (!a->used || !a->samples) continue;
        int seen_before = 0;
        for (size_t j = 0; j < i && !seen_before; j++) {
            const flow_watch *b = &s->flowwatch[j];
            seen_before = b->used && b->samples && b->port == a->port && b->transport == a->transport &&
                          b->family == a->family && !strcmp(b->target, a->target) &&
                          !strcmp(b->known_service,a->known_service);
        }
        if (seen_before) continue;
        unsigned flows = 0, moving = 0, stalled = 0, idle = 0, nodata = 0, active = 0, passive = 0;
        uint64_t rate = 0, bytes_in = 0;
        for (size_t j = i; j < SCHED_FLOWWATCH_SLOTS; j++) {
            const flow_watch *b = &s->flowwatch[j];
            if (!b->used || !b->samples || b->port != a->port || b->transport != a->transport ||
                b->family != a->family || strcmp(b->target, a->target) || strcmp(b->known_service,a->known_service)) continue;
            flows++;
            if (b->passive) passive++;
            if (b->state == FW_MOVING) { moving++; rate += b->rate_Bps; }
            else if (b->state == FW_ACTIVE) { active++; rate += b->rate_Bps; }
            else if (b->state == FW_STALLED) stalled++;
            else if (b->state == FW_IDLE) idle++;
            else if (b->state == FW_NODATA) nodata++;
            bytes_in += b->in_bytes;
        }
        fputs(first_fh ? "\n    {" : ",\n    {", f);
        first_fh = 0;
        fputs("\"target\": ", f); json_str(f, a->target);
        if (a->known_service[0]) { fputs(", \"known_service\": ",f); json_str(f,a->known_service); }
        fprintf(f, ", \"port\": %u, \"transport\": %u, \"family\": %u, \"flows\": %u, \"moving\": %u, "
                   "\"stalled\": %u, \"idle\": %u, \"no_data\": %u, \"active\": %u, \"in_kBps\": %llu, "
                   "\"bytes_in\": %llu, \"passive\": %u}",
                (unsigned)a->port, (unsigned)a->transport, (unsigned)a->family, flows, moving, stalled, idle,
                nodata, active, (unsigned long long)(rate / 1000u), (unsigned long long)bytes_in, passive);
    }
    fputs(first_fh ? "],\n" : "\n  ],\n", f);
    /* Факты появления без свободного места под наблюдение (этап 42). */
    fprintf(f, "  \"flow_watch_full\": %llu,\n", (unsigned long long)s->flowwatch_full);
    fprintf(f, "  \"targets\": %zu,\n  \"confirms\": %d,\n  \"probes_used\": %d,\n"
               "  \"client_unfit\": %u\n}\n",
            targets, s->confirms, s->probes_used, (unsigned)s->unfit_client);

    if (fclose(f) != 0) { (void)remove(tmp); return -1; }
    if (rename(tmp, path) != 0) { (void)remove(tmp); return -1; }
    return 0;
}

void d2k_sched_free(d2k_sched *s) {
    if(s)d2k_newchain_set(&s->newchain,NULL);
    if (!s) { return; }
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        char err[160];
        if (s->tasks[i].state==T_DNS_PLAIN_TRIAL)join_worker(&s->tasks[i]);
        if (s->tasks[i].addr_probe_identity_valid) {
            (void)addr_probe_remove(s, &s->tasks[i], err, sizeof err);
        }
        join_worker(&s->tasks[i]);
        gate_retire(s,&s->tasks[i]);
        if(s->tasks[i].synthesis_release)s->tasks[i].synthesis_release(s->tasks[i].synthesis_context);
        d2k_verification_free(s->tasks[i].synthesis_owner);
        d2k_run_cache_clear(&s->tasks[i].run_cache);
        stun_retire(s, &s->tasks[i]);
        search_report(s, &s->tasks[i], s->now_ms, "shutdown", NULL, "служба останавливается, поиск не доведён");
        /* Сокеты обращений закрываем сами: поток к этому моменту уже вернулся,
           а дескриптор принадлежит задаче, а не ему. */
        contact_close(&s->tasks[i]);
        prop_close(&s->tasks[i]);
        ver_close(&s->tasks[i]);
    }
    pthread_cond_destroy(&s->question_cv);
    pthread_mutex_destroy(&s->mu);
    if (s->wake[0] >= 0) { close(s->wake[0]); }
    if (s->wake[1] >= 0) { close(s->wake[1]); }
    for(size_t i=0;i<SCHED_SEEN;i++)shadow_forget(s,&s->shadow_flows[i]);
    free(s->areas);
    free(s);
}

/* Будит цикл d2kc сразу. Тик — 3 с, а ожидания опыта меряются десятками
   миллисекунд: событие, которое отпускает ожидание (подтверждение установки
   плана, его применение на потоке зонда), не должно ждать следующего тика. */
static void wake_loop(d2k_sched *s) {
    ssize_t ign = write(s->wake[1], "w", 1);
    (void)ign;
}

int d2k_sched_wake_fd(const d2k_sched *s) { return s ? s->wake[0] : -1; }

size_t d2k_sched_active(const d2k_sched *s) {
    if (!s) { return 0; }
    size_t n = 0;
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        task_state st = s->tasks[i].state;
        if (st == T_GATE_INSTALL || st == T_GATE_VERIFY || st == T_GATE_COMMIT ||
            st == T_QUEUED || st == T_SHAPE_WAIT || st == T_ASKING || st == T_PLANNING ||
            st == T_VERIFY || st == T_VERIFY_WAIT || st == T_WATCHING ||
            st == T_STUN_MEASURE || st == T_STUN_ACK ||
            st == T_STUN_PROBE || st == T_STUN_PROOF || st == T_STUN_CLIENT ||
            st == T_VOICE_INSTALL) { n++; }
    }
    return n;
}

/* Находит план коробки по идентификатору. NULL — нет такого или выключен. */
static const d2k_cat_plan *plan_by_id(const d2k_cat_box *b, const char *id) {
    for (size_t i = 0; i < b->n_plans; i++) {
        if (strcmp(b->plans[i].id, id) == 0) {
            return b->plans[i].enabled ? &b->plans[i] : NULL;
        }
    }
    return NULL;
}

static int preflight_scope_same(const d2k_pf_scope *a,const d2k_pf_scope *b) {
    return a->family==b->family && a->shape==b->shape && a->server_port==b->server_port &&
        a->path==b->path && !memcmp(a->client,b->client,16) && !memcmp(a->server,b->server,16) &&
        !strcasecmp(a->name,b->name);
}
static int preflight_lease_tuple(const sched_preflight_lease *l,const uint8_t *client,
    uint8_t family,const uint8_t *server,uint32_t path) {
    size_t width=family==4?4:16;
    return (l->pending||l->active) && l->scope.family==family && l->scope.path==path &&
        !memcmp(l->scope.client,client,width) && !memcmp(l->scope.server,server,width);
}
static void preflight_lease_retire(d2k_sched *s,sched_preflight_lease *l) {
    if(!l->pending&&!l->active)return;
    char err[160];
    (void)d2k_link_del_preflight_lease(s->link_fd,&l->scope,l->id,err,sizeof err);
    memset(l,0,sizeof *l);
}
static sched_preflight_lease *preflight_lease_slot(d2k_sched *s,int64_t now) {
    sched_preflight_lease *old=&s->preflight_leases[0];
    for(size_t i=0;i<SCHED_SEEN;i++) {
        sched_preflight_lease *l=&s->preflight_leases[i];
        if(!l->pending&&!l->active)return l;
        if(l->expires_ms<=now){memset(l,0,sizeof *l);return l;}
        if(l->expires_ms<old->expires_ms)old=l;
    }
    preflight_lease_retire(s,old);return old;
}
static void preflight_dns_reconcile(d2k_sched *s,const uint8_t *client,uint8_t family,
    const uint8_t *server,uint32_t path,int64_t now) {
    if(!s||!client||!server||!path||(family!=4&&family!=6))return;
    size_t width=family==4?4:16;const char *name=NULL;int64_t expiry=INT64_MAX;int ambiguous=0;
    for(size_t i=0;i<SCHED_SEEN;i++) {
        dns_address_name *r=&s->dns_names[i];
        if(r->family!=family||r->client_family!=family||r->path!=path||r->expires_ms<=now||
           memcmp(r->client,client,width)||memcmp(r->address,server,width))continue;
        if(name&&strcasecmp(name,r->name)){ambiguous=1;break;}
        name=r->name;if(r->expires_ms<expiry)expiry=r->expires_ms;
    }
    for(size_t i=0;i<SCHED_SEEN;i++)if(preflight_lease_tuple(&s->preflight_leases[i],client,family,server,path))
        preflight_lease_retire(s,&s->preflight_leases[i]);
    if(ambiguous||!name||!s->cat||s->link_fd<0||expiry<=now)return;
    char address[INET6_ADDRSTRLEN];if(!inet_ntop(family==4?AF_INET:AF_INET6,server,address,sizeof address))return;
    for(size_t bi=0;bi<s->cat->n_boxes;bi++) {
        d2k_cat_box *box=&s->cat->boxes[bi];
        for(size_t j=0;j<box->n_binds;j++) {
            d2k_cat_binding *bd=&box->binds[j];
            if(!bd->enabled||bd->recheck_since||bd->level<3||strcmp(bd->kind,"service")||
               bd->transport!=6||bd->family!=family||bd->server_port==0||
               (bd->shape!=D2K_SHAPE_MODERN&&bd->shape!=D2K_SHAPE_LEGACY)||
               strcmp(bd->target,address)||strcasecmp(bd->preflight_name,name))continue;
            int competing=0;
            for(size_t x=0;x<s->cat->n_boxes&&!competing;x++)for(size_t y=0;y<s->cat->boxes[x].n_binds;y++) {
                d2k_cat_binding *other=&s->cat->boxes[x].binds[y];
                if(other==bd||!other->enabled||other->recheck_since||other->level<3||
                   strcmp(other->kind,"service")||other->transport!=6||other->family!=family||
                   other->server_port!=bd->server_port||strcmp(other->target,address)||
                   strcasecmp(other->preflight_name,name))continue;
                if(other->shape!=bd->shape||strcmp(other->plan_id,bd->plan_id))competing=1;
            }
            if(competing)continue;
            int incompatible=0;
            for(size_t k=0;k<SCHED_SEEN;k++) {
                const dns_address_name *r=&s->dns_names[k];
                if(r->expires_ms>now&&r->family==family&&r->client_family==family&&r->path==path&&
                   !memcmp(r->client,client,width)&&!memcmp(r->address,server,width)&&
                   !strcasecmp(r->name,name)&&r->observed_shape&&
                   (r->observed_shape!=bd->shape||r->observed_port!=bd->server_port))incompatible=1;
            }
            if(incompatible)continue;
            const d2k_cat_plan *plan=plan_by_id(box,bd->plan_id);if(!plan||!plan->text)continue;
            d2k_pf_scope scope={0};scope.family=family;scope.shape=bd->shape;scope.path=path;
            scope.server_port=htons(bd->server_port);memcpy(scope.client,client,width);memcpy(scope.server,server,width);
            snprintf(scope.name,sizeof scope.name,"%s",name);
            int duplicate=0;for(size_t k=0;k<SCHED_SEEN;k++)if((s->preflight_leases[k].pending||s->preflight_leases[k].active)&&
                preflight_scope_same(&s->preflight_leases[k].scope,&scope))duplicate=1;
            if(duplicate)continue;
            sched_preflight_lease *lease=preflight_lease_slot(s,now);char wire[4096],hex[2*D2K_PLAN_TLV_MAX+1],err[200];
            uint8_t wire_id[D2K_PLAN_ID_LEN];char id[40];plan_ident(plan->text,id,sizeof id,wire_id);
            if(strlen(plan->text)>=sizeof wire||fresh_trial_id(lease->id))continue;
            snprintf(wire,sizeof wire,"%s",plan->text);
            if(stamp_plan_id(wire,wire_id)||d2k_plan_text_to_hex(wire,hex,sizeof hex,err,sizeof err))continue;
            uint64_t remain=(uint64_t)(expiry-now);uint32_t lease_ms=remain>D2K_PREFLIGHT_LEASE_MAX_MS?
                D2K_PREFLIGHT_LEASE_MAX_MS:(uint32_t)remain;
            if(!lease_ms||d2k_link_set_preflight_lease(s->link_fd,&scope,lease_ms,hex,lease->id,err,sizeof err)) {
                memset(lease,0,sizeof *lease);continue;
            }
            lease->scope=scope;lease->expires_ms=now+lease_ms;lease->pending=1;lease->active=0;
            say(s,"по %s preflight: установка привязки клиента, IPv%u, путь %u, форма %u, срок %u мс; подтверждённый план %s",
                name,(unsigned)family,(unsigned)path,(unsigned)scope.shape,(unsigned)lease_ms,bd->plan_id);
        }
    }
}

static int preflight_lease_event(d2k_sched *s,const d2k_ev *ev) {
    if(ev->kind!=D2K_EV_ACK||ev->code!=D2K_CMD_SET_PREFLIGHT_LEASE)return 0;
    for(size_t i=0;i<SCHED_SEEN;i++) {
        sched_preflight_lease *l=&s->preflight_leases[i];
        if(!l->pending||memcmp(l->id,ev->trial_id,16))continue;
        task *owner=l->owner;
        if(owner&&owner->gate_lease_pending)owner->gate_lease_pending--;
        if(((ev->num>>8)&255)==1){
            l->pending=0;l->active=1;if(owner)owner->gate_lease_acked++;
            say(s,"по %s preflight: датапат подтвердил привязку клиента, IPv%u, путь %u, форма %u",
                l->scope.name,(unsigned)l->scope.family,(unsigned)l->scope.path,(unsigned)l->scope.shape);
        } else {
            say(s,"по %s preflight: датапат отказал привязке клиента, код %u",l->scope.name,(unsigned)(ev->num&255));
            if(owner)owner->gate_lease_failed=1;
            memset(l,0,sizeof *l);
        }
        return 1;
    }
    return 1;
}

/* Сколько команд за одну порцию. Восемь, а не одна: круг цикла стоит
   системного вызова, а датапат успевает отдать кадр за микросекунды — по
   одной команде за круг проход по большому каталогу растянулся бы на секунды
   без всякой пользы. И не сто: чем длиннее порция, тем длиннее окно, в котором
   датапату некуда сказать про живой трафик. */
#define SYNC_CHUNK 8

int d2k_sched_sync(d2k_sched *s) {
    if (!s || !s->cat) { return -1; }
    if(s->synthesis_only) {s->sync_active=s->sync_pending=0;return 0;}
    s->sync_box = 0;
    s->sync_bind = 0;
    s->sync_active = 1;
    s->sync_pending = 0;
    s->sync_sent = 0;
    s->sync_skipped = 0;
    s->sync_weak = 0;
    s->sync_unshaped = 0;
    s->sync_recheck = 0;
    s->sync_unfit = 0;
    s->area_sync_failed = 0;
    return 0;
}

int d2k_sched_sync_pending(const d2k_sched *s) {
    return (s && (s->sync_active || s->sync_pending)) ? 1 : 0;
}

/* Форма протокола адресной привязки на проводе (SET_ADDR v7), 0 — нет
 * однозначной.
 *
 * Адресная запись датапата — ключ (адрес, семейство, форма): QUIC и STUN/голос
 * одного IP не должны затирать друг друга и доставаться чужим пакетам
 * (D2K_SPEC §5). Записанная форма едет как есть, если согласна с транспортом.
 * Формы нет (файл до появления поля) — выводим ТОЛЬКО однозначное из того,
 * что записали сами пути подтверждения: UDP + STUN-доказательство пишет лишь
 * voice_confirm (форма голоса), UDP + собственный зонд по адресу — лишь
 * QUIC-поиск без SNI (форма QUIC). Остальное (TCP по адресу из старых
 * каталогов, UDP без доказательства) — неизвестный контекст: дедушкино право
 * сделало бы его рабочим для всех протоколов IP, а §7/§9.11 требуют проверки.
 * Каталог при этом не правится — запись просто не ставится, и это говорится. */
static uint8_t addr_binding_shape(const d2k_cat_binding *bd) {
    uint8_t tr = bd->transport;
    switch (bd->shape) {
    case D2K_LINK_SHAPE_QUIC:
    case D2K_LINK_SHAPE_VOICE:
        return tr == 17 ? bd->shape : 0;
    case D2K_SHAPE_MODERN:
    case D2K_SHAPE_LEGACY:
    case D2K_LINK_SHAPE_ECH_TCP:
        return tr == 6 || tr == 0 ? bd->shape : 0;
    case D2K_LINK_SHAPE_RAW:
        /* Форма RAW — доказанный путь без протокола; транспорт привязки —
           тот, на котором шёл опыт (TCP — этап 12, UDP — этап 16). */
        return tr == 6 || tr == 0 || tr == 17 ? bd->shape : 0;
    case 0:
        if (tr != 17) return 0;
        if (bd->verified_by == D2K_VERBY_STUN) return D2K_LINK_SHAPE_VOICE;
        if (bd->verified_by == D2K_VERBY_PROBE) return D2K_LINK_SHAPE_QUIC;
        return 0;
    default:
        return 0;
    }
}

/* Several measured boxes may retain the history of one target. SET_NAME
 * and SET_ENDPOINT replace exact context slots (including service port): catalog traversal
 * order must not let a weaker confirmation overwrite the chosen one
 * (binding_beats: budget passed first, then newest). */
static int newer_target_binding(const d2k_catalog *cat, const d2k_cat_binding *bd) {
    int service = !strcmp(bd->kind, "service");
    if (strcmp(bd->kind, "name") != 0 && !service) return 0;
    for (size_t bi = 0; bi < cat->n_boxes; bi++) {
        const d2k_cat_box *box = &cat->boxes[bi];
        for (size_t j = 0; j < box->n_binds; j++) {
            const d2k_cat_binding *other = &box->binds[j];
            if (other == bd || !other->enabled || other->recheck_since ||
                dns_proof_missing_authentication(other) ||
                (other->level > 0 && other->level < 3) ||
                !binding_beats(other, bd) ||
                strcmp(other->kind, bd->kind) != 0 ||
                other->server_port != bd->server_port ||
                (service && other->level < 3) ||
                strcmp(other->target, bd->target) != 0 ||
                (other->transport ? other->transport : 6) != (bd->transport ? bd->transport : 6) ||
                (other->family ? other->family : 4) != (bd->family ? bd->family : 4) ||
                other->shape != bd->shape ||
                (other->transport == 17 && other->verified_by == D2K_VERBY_CLIENT)) continue;
            const d2k_cat_plan *plan = plan_by_id(box, other->plan_id);
            if (plan && plan->text) return 1;
        }
    }
    return 0;
}

static int area_key_same(const installed_area *a, const installed_area *b) {
    return a->kind == b->kind && a->transport == b->transport &&
        a->shape == b->shape && a->family == b->family && !strcmp(a->name, b->name);
}

static const d2k_cat_plan *area_plan(const d2k_sched *s, const installed_area *a) {
    for (size_t i = 0; i < s->cat->n_boxes; i++) {
        const d2k_cat_plan *p = plan_by_id(&s->cat->boxes[i], a->plan_id);
        if (p && p->text && !strcmp(p->proto, a->transport == 17 ? "quic" : "tls")) return p;
    }
    return NULL;
}

/* Собственное подтверждённое точное решение цели в этом контексте (имя,
 * транспорт, семейство адресов, форма) — любым планом. Помеченная к
 * перепроверке привязка (задача 21) снята с провода и не считается. */
static int own_exact_confirmed(const d2k_catalog *cat, const char *name,
                               const d2k_group_key *key) {
    for (size_t bi = 0; bi < cat->n_boxes; bi++)
        for (size_t j = 0; j < cat->boxes[bi].n_binds; j++) {
            const d2k_cat_binding *bd = &cat->boxes[bi].binds[j];
            if (bd->enabled && bd->level >= 3 && !bd->recheck_since &&
                !strcmp(bd->kind, "name") && !strcmp(bd->target, name) &&
                (bd->transport ? bd->transport : 6) == key->transport &&
                (bd->family ? bd->family : 4) == key->family &&
                (bd->shape == key->shape ||
                 /* Старая подтверждённая привязка имени без формы (дедушкино
                    право) — своё точное решение участника для любой формы
                    TCP TLS; датапат так же ставит её выше BYPASS
                    (финальное ревью, п.6). */
                 (bd->shape == 0 && key->transport == 6 &&
                  (key->shape == D2K_SHAPE_MODERN || key->shape == D2K_SHAPE_LEGACY ||
                   key->shape == D2K_LINK_SHAPE_ECH_TCP)))) return 1;
        }
    return 0;
}

/* Diagnostic paths/origins are proof context, not visible packet fields.
 * Never pick an arbitrary plan when two proofs collide on a wire key. */
static int desired_area(const d2k_sched *s, size_t index, installed_area *a) {
    const d2k_group_state *g = s->cat->groups;
    if (!g || index >= d2k_group_slots(g)+g->n_observations) return 0;
    memset(a, 0, sizeof *a);
    if (index < d2k_group_slots(g)) {
        d2k_domain_group value;
        if (!d2k_group_at(g,index,&value)) return 0;
        const d2k_domain_group *v = &value;
        a->kind = 1; strcpy(a->name, v->suffix); strcpy(a->plan_id, v->plan_id);
        a->transport = v->key.transport; a->shape = v->key.shape; a->family = v->key.family;
        if (!area_plan(s, a)) return 0;
        for (size_t i = 0; i < d2k_group_slots(g); i++) {
            d2k_domain_group other_value;
            if (!d2k_group_at(g,i,&other_value)) continue;
            const d2k_domain_group *other = &other_value;
            if (i != index && other->key.transport == a->transport &&
                other->key.shape == a->shape && other->key.family == a->family &&
                !strcmp(other->suffix, a->name) && strcmp(other->plan_id, a->plan_id)) return 0;
        }
    } else {
        const d2k_group_observation *v = &d2k_group_rows(g)[index-d2k_group_slots(g)];
        if (!(v->evidence & (D2K_GROUP_DIRECT_CLEAR | D2K_GROUP_PLAN_FAILED))) return 0;
        if (!(v->evidence & D2K_GROUP_DIRECT_CLEAR)) {
            /* Исключение семейства снимает УНАСЛЕДОВАННЫЙ план. Собственное
               подтверждённое точное решение участника — любым планом, и тем
               же, что у семейства, — оно не гасит (задача 22, §7/§9.10):
               BYPASS в датапате отключил бы его для всех клиентов. */
            if (own_exact_confirmed(s->cat, v->name, &v->key)) return 0;
            int still_elected=0;
            for(size_t i=0;i<d2k_group_slots(g);i++) {
                d2k_domain_group elected;
                if(d2k_group_at(g,i,&elected) &&
                   d2k_group_key_same(&v->key,&elected.key) &&
                   d2k_domain_member(v->name,elected.suffix) &&
                   !strcmp(v->plan_id,elected.plan_id)) still_elected=1;
            }
            if(!still_elected) return 0;
        }
        a->kind = 2; strcpy(a->name, v->name);
        a->transport = v->key.transport; a->shape = v->key.shape; a->family = v->key.family;
    }
    return 1;
}

static int desired_has_key(const d2k_sched *s, const installed_area *a) {
    const d2k_group_state *g = s->cat->groups;
    if (!g) return 0;
    installed_area d;
    for (size_t i = 0; i < d2k_group_slots(g)+g->n_observations; i++)
        if (desired_area(s, i, &d) && area_key_same(a, &d)) return 1;
    return 0;
}

static void write_live_groups(FILE *f, const d2k_sched *s) {
    const d2k_group_state *state = s->cat->groups;
    fputs("  \"groups\": [", f);
    size_t count = d2k_group_slots(state); int emitted = 0;
    for (size_t i = 0; i < count; i++) {
        d2k_domain_group value;
        if (!d2k_group_at(state,i,&value)) continue;
        const d2k_domain_group *g = &value;
        fputs(emitted++ ? ",\n    {\"suffix\": " : "\n    {\"suffix\": ", f); json_str(f, g->suffix);
        fprintf(f, ", \"transport\": %u, \"family\": %u, \"shape\": %u, \"evidence_count\": %u",
            g->key.transport, g->key.family, g->key.shape, g->evidence_count);
        fputs(", \"plan_id\": ", f); json_str(f, g->plan_id);
        fputs(", \"probe_path\": ", f); json_str(f, g->key.probe_path);
        fputs(", \"ech_origin\": ", f); json_str(f, g->key.ech_origin);
        installed_area a; int active = 0;
        if (desired_area(s, i, &a)) {
            for (size_t j = 0; j < s->n_areas; j++)
                if (s->areas[j].confirmed && area_key_same(&a, &s->areas[j]) &&
                    !strcmp(a.plan_id, s->areas[j].plan_id)) active = 1;
        }
        fprintf(f, ", \"active\": %s, \"evidence\": [", active ? "true" : "false");
        int first = 1;
        for (size_t j = 0; j < state->n_observations; j++) {
            const d2k_group_observation *o = &d2k_group_rows(state)[j];
            if (!(o->evidence & D2K_GROUP_BLOCKED_CONFIRMED) ||
                !d2k_group_key_same(&g->key, &o->key) || strcmp(g->plan_id, o->plan_id) ||
                !d2k_domain_member(o->name, g->suffix)) continue;
            if (!first) fputs(", ", f);
            first = 0;
            json_str(f, o->name);
        }
        fputs("], \"exceptions\": [", f); first = 1;
        for (size_t j = 0; j < state->n_observations; j++) {
            const d2k_group_observation *o = &d2k_group_rows(state)[j];
            if (!(o->evidence & (D2K_GROUP_DIRECT_CLEAR | D2K_GROUP_PLAN_FAILED)) ||
                !d2k_group_key_same(&g->key, &o->key) || !d2k_domain_member(o->name, g->suffix)) continue;
            if (!first) fputs(", ", f);
            first = 0;
            fputs("{\"name\": ", f); json_str(f, o->name);
            fputs(", \"reason\": ", f); json_str(f, o->evidence & D2K_GROUP_DIRECT_CLEAR ?
                "Напрямую работает" : "Общий план не подошёл"); fputc('}', f);
        }
        fputs("]}", f);
    }
    fputs(count ? "\n  ],\n" : "],\n", f);
}

/* One outstanding identified area command. Remember installed state only
 * after its positive ACK; a stale ACK cannot acknowledge a later retry. */
static int sync_area_send(d2k_sched *s, const installed_area *a, int remove) {
    char err[200], hex[2*D2K_PLAN_TLV_MAX+1]; int rc;
    memset(s->area_id, 0, sizeof s->area_id);
    uint64_t seq = ++s->area_sequence;
    memcpy(s->area_id, &seq, sizeof seq);
    uint16_t cmd;
    if (a->kind == 1 && !remove) {
        const d2k_cat_plan *p = area_plan(s, a);
        char wire[sizeof s->tasks[0].plans[0]];
        uint8_t id[D2K_PLAN_ID_LEN] = {0};
        size_t n = strlen(a->plan_id); if (n > sizeof id) n = sizeof id;
        memcpy(id, a->plan_id, n);
        if (!p || strlen(p->text) >= sizeof wire) return -1;
        strcpy(wire, p->text);
        if (stamp_plan_id(wire, id) || d2k_plan_text_to_hex(wire, hex, sizeof hex, err, sizeof err)) {
            say(s, "область %s: план без проверяемого идентификатора", a->name); return -1;
        }
        cmd = D2K_CMD_SET_SUFFIX;
    } else if (a->kind == 1) {
        cmd = D2K_CMD_DEL_SUFFIX;
    } else if (remove) {
        cmd = D2K_CMD_DEL_BYPASS;
    } else {
        cmd = D2K_CMD_SET_BYPASS;
    }
    rc = d2k_link_area_identified(s->link_fd, cmd, a->name, a->transport,
        a->shape, a->family, cmd == D2K_CMD_SET_SUFFIX ? hex : NULL,
        s->area_id, err, sizeof err);
    if (rc) { say(s, "область %s не отправлена: %s", a->name, err); return -1; }
    s->area_pending = *a; s->area_command = cmd;
    s->area_deadline_ms = s->now_ms+5000;
    return 1;
}

static int area_reserve(d2k_sched *s,size_t need) {
    if(need<=s->areas_capacity)return 0;
    size_t cap=s->areas_capacity?s->areas_capacity:32;
    while(cap<need) {
        if(cap>SIZE_MAX/2/sizeof *s->areas)return -1;
        cap*=2;
    }
    installed_area *p=realloc(s->areas,cap*sizeof *s->areas);
    if(!p)return -1;
    memset(p+s->areas_capacity,0,(cap-s->areas_capacity)*sizeof *p);
    s->areas=p;s->areas_capacity=cap;return 0;
}

static int sync_areas(d2k_sched *s) {
    if (s->area_sync_failed) return 0;
    if (s->area_command) {
        if (s->now_ms < s->area_deadline_ms) return 1;
        say(s, "область %s: ACK не пришёл; применение не подтверждено", s->area_pending.name);
        /* A lost ACK does not prove the write was rejected. Retain uncertain
           installation so a later disable/change can explicitly remove it. */
        size_t i;
        for (i=0; i<s->n_areas; i++) if (area_key_same(&s->area_pending,&s->areas[i])) break;
        if (s->areas && i<s->areas_capacity) {
            s->areas[i]=s->area_pending; s->areas[i].confirmed=0;
            if (i==s->n_areas) s->n_areas++;
        }
        s->area_command = 0;
        /* Retry only unconfirmed area state; a late ACK keeps its old ID. */
        return 1;
    }
    for (size_t i = 0; i < s->n_areas; i++) {
        if (!desired_has_key(s, &s->areas[i])) {
            int rc = sync_area_send(s, &s->areas[i], 1);
            if (rc < 0) s->area_sync_failed = 1;
            return rc > 0;
        }
    }
    const d2k_group_state *g = s->cat->groups;
    if (!g) return 0;
    /* Exceptions before suffixes: a known clean/failed child must never
     * receive a broad plan during initial synchronized installation. */
    for (int kind = 2; kind >= 1; kind--) {
        for (size_t i = 0; i < d2k_group_slots(g)+g->n_observations; i++) {
            installed_area a;
            if (!desired_area(s, i, &a) || a.kind != kind) continue;
            size_t j;
            for (j = 0; j < s->n_areas; j++) if (area_key_same(&a, &s->areas[j])) break;
            if (j < s->n_areas && s->areas[j].confirmed && !strcmp(a.plan_id, s->areas[j].plan_id)) continue;
            if (j == s->n_areas && area_reserve(s,s->n_areas+1)) {
                say(s, "области: не хватает памяти для активных правил"); return 0;
            }
            int rc = sync_area_send(s, &a, 0);
            if (rc < 0) s->area_sync_failed = 1;
            return rc > 0;
        }
    }
    return 0;
}

/* Самая длинная посылка плана каталога — тем же шлюзом, что у датапата на
   активации (d2k_plan_max_emit, ctlsrv.c d2k_plan_fits). 0 — текст не
   собрался (такую запись ниже отвергнет d2k_plan_text_to_hex) либо у плана
   нет собственных посылок. */
static size_t plan_text_max_emit(const char *text) {
    static uint8_t tlv[D2K_PLAN_TLV_MAX];
    size_t n = 0;
    char err[200];
    d2k_plan *p = NULL;
    if (d2k_plan_text_to_tlv(text, tlv, sizeof tlv, &n, err, sizeof err) != 0 ||
        d2k_plan_load(tlv, n, &p, err, sizeof err) != 0) { return 0; }
    size_t m = d2k_plan_max_emit(p);
    d2k_plan_free(p);
    return m;
}

int d2k_sched_sync_step(d2k_sched *s) {
    if (!s) { return 0; }
    if(s->synthesis_only) {s->sync_active=s->sync_pending=0;return 0;}
    if (!s->cat || !s->sync_active) { return 0; }
    static char hex[2 * D2K_PLAN_TLV_MAX + 1];
    char err[200];
    int sent_now = 0;

    while (s->sync_box < s->cat->n_boxes && sent_now < SYNC_CHUNK) {
        const d2k_cat_box *b = &s->cat->boxes[s->sync_box];
        if (s->sync_bind >= b->n_binds) {
            s->sync_box++;
            s->sync_bind = 0;
            continue;
        }
        const d2k_cat_binding *bd = &b->binds[s->sync_bind++];
        if (s->synthesis_only || !bd->enabled || dns_proof_missing_authentication(bd)) { continue; }
        if(!strcmp(bd->kind,"name") && d2k_newchain_protects(&s->newchain,bd->target,
            bd->transport?bd->transport:6,bd->family?bd->family:4,bd->shape))continue;
        int service = !strcmp(bd->kind, "service");
        if ((service && (!bd->server_port || (bd->family != 4 && bd->family != 6) ||
                         (bd->transport != 6 && bd->transport != 17))) ||
            (!service && (bd->server_port || (strcmp(bd->kind, "name") && strcmp(bd->kind, "addr"))))) {
            s->sync_skipped++;
            say(s, "каталог: %s — некорректный тип или контекст привязки, не ставлю", bd->target);
            continue;
        }
        if (service && bd->level < 3) { s->sync_weak++; continue; }
        /* Old RAW continuation proofs did not persist the measured server
           port. They remain candidate material, never authority for all ports. */
        if (!service && bd->shape == D2K_LINK_SHAPE_RAW) {
            s->sync_weak++;
            say(s, "каталог: %s — RAW без измеренного порта; автоматически не ставлю, требуется проверка сервиса", bd->target);
            continue;
        }
        /* «Требует повторной проверки» (задача 21): прямой замер прошёл без
           обхода, привязка снята с провода и до повторного подтверждения или
           второго независимого прямого прохода на него не возвращается —
           ни этим проходом, ни после перезапуска. Каталог при этом цел. */
        if (bd->recheck_since) { s->sync_recheck++; continue; }
        if (newer_target_binding(s->cat, bd)) { continue; }
        /* I2 (раунд 3): пока QUIC имени не пропускается, его QUIC-привязка на
           провод не ставится — она перекрыла бы запрет. */
        if ((bd->transport ? bd->transport : 6) == 17 && !strcmp(bd->kind, "name") &&
            quic_deny_active(s, bd->target, bd->family ? bd->family : 4)) { continue; }
        /* Прежний voice_confirm присваивал UDP CLIENT уровень 3 на любую
           обратную датаграмму. У таких записей нет протокольного
           свидетельства, независимо от сохранённого level. Не стираем
           каталог, но не возвращаем ложное подтверждение на провод после
           перезапуска. Будущее пассивное подтверждение потребует отдельного
           проверяемого доказательства/версии, а не одного CLIENT. */
        /* Исключение — форма RAW (этап 16): это ОТДЕЛЬНЫЙ, проверяемый вид
           записи. Она не выдаёт себя за QUIC/STUN/голос: датапат кладёт
           план формы RAW только на датаграммы без распознанного протокола
           (не QUIC Initial, не STUN, не голос — session.c), а подтверждение —
           ответ сервера на продолжение ТОГО ЖЕ клиента под планом нашего
           поколения (trial), уровень «путь». Старые записи CLIENT формы
           QUIC/VOICE/0 под это исключение не подпадают. */
        if (bd->transport == 17 && bd->verified_by == D2K_VERBY_CLIENT &&
            bd->shape != D2K_LINK_SHAPE_RAW) {
            s->sync_weak++;
            say(s, "каталог: %s — UDP CLIENT без протокольного доказательства; "
                   "автоматически не ставлю, требуется повторная проверка", bd->target);
            continue;
        }
        /* ДОКАЗАТЕЛЬСТВО СЛАБЕЕ ОБМЕНА — НА ПРОВОД НЕ ЕДЕТ.
         *
         * §4.2: уровень 1 «транспорт установился» и уровень 2 «сервер
         * ответил» не говорят, что обход СРАБОТАЛ, — оба достижимы и там,
         * где коробка пропускает начало соединения и рвёт его дальше. Сам
         * планировщик ниже уровня 3 привязок не заводит (bd->level = 3), но
         * в файле у человека лежат записи прежних версий, у которых правило
         * было мягче.
         *
         * Что это стоило: 13.09.2026 при установке на роутер поднялось 398
         * привязок, среди них по адресу `8.47.69.0` — уровень 2, зондом не
         * подтверждённая. На том же адресе живёт `example.com`, и план,
         * выученный для чужого имени, сломал контрольную цель наглухо
         * (docs/field/2026-09-13-transit-vs-local.md).
         *
         * Запись НЕ правится и НЕ удаляется: каталог принадлежит человеку, а
         * «не ставлю» и «стёр» — разные действия. Она просто не ставится, и
         * об этом говорится вслух.
         *
         * НОЛЬ СЮДА НЕ ВХОДИТ. Ноль — «не записано», а не «слабое» (§2.4:
         * «не измерено» ≠ «нет»): так выглядит файл, снятый до появления
         * поля. Отвергнув и его, мы обнулили бы разом всё накопленное — ровно
         * та же ловушка, из-за которой форма приветствия получила дедушкино
         * право (d2k_cat_shape_fits). Отвергается только ИЗМЕРЕННОЕ слабым. */
        if (bd->level > 0 && bd->level < 3) {
            s->sync_weak++;
            continue;
        }
        const d2k_cat_plan *p = plan_by_id(b, bd->plan_id);
        if (!p || !p->text) {
            s->sync_skipped++;
            continue;
        }
        /* ЗАЩИТА ОТ ВБРОШЕННОГО СБРОСА — И КЛИЕНТСКИМ ПОТОКАМ, не только
           зонду. Поле 13.10.2026, forum.ru-board.com: рукопожатие снято,
           план применён ко всем 133 потокам браузера, сервер ответил всем, а
           коробка вбросила сброс в 132 из них — TTL 127 против 55–57 у
           сервера, и каждый В ОКНО приёма. Главный документ приходил,
           картинки умирали. Защита дописывается в ПРОВОДНУЮ копию: текст
           плана в каталоге не меняется, его личность (plan_ident) считается
           из текста. Повод — измеренная примета «rst» у этой коробки. */
        static char guarded[sizeof ((d2k_sched *)0)->tasks[0].plans[0]];
        const char *text = p->text;
        if(preflight_text(text) && !preflight_family_enabled(bd->family ? bd->family : 4))continue;
        if ((bd->transport ? bd->transport : 6) == 6 && box_injects_rst(b) &&
            strlen(p->text) < sizeof guarded) {
            memcpy(guarded, p->text, strlen(p->text) + 1);
            if (plan_arm_rst_guard(guarded, sizeof guarded)) { text = guarded; }
        }
        /* ИДЕНТИЧНОСТЬ ИСПОЛНЕНИЯ (этап 36). В каталоге текст хранится с
           «id 000…0», и план из прохода исполнялся БЕЗ идентификатора: события
           APPLIED/EXCHANGE/SUSPECT о потоке под ним не на что было опереть, и
           результат клиента приходилось приписывать текущей привязке каталога.
           В проводную копию ставится идентификатор плана каталога (как у
           областей, sync_area_send); текст в каталоге не меняется. Текст без
           строки id ставится как прежде — без идентичности. */
        static char stamped[sizeof ((d2k_sched *)0)->tasks[0].plans[0]];
        if (strlen(text) < sizeof stamped) {
            uint8_t wid[D2K_PLAN_ID_LEN] = {0};
            size_t idn = strlen(p->id);
            memcpy(wid, p->id, idn < sizeof wid ? idn : sizeof wid);
            memmove(stamped, text, strlen(text) + 1);
            if (stamp_plan_id(stamped, wid) == 0) text = stamped;
        }
        if (d2k_plan_text_to_hex(text, hex, sizeof hex, err, sizeof err) != 0) {
            /* Битую запись нашли бы при загрузке; сюда она дойти не должна.
               Если дошла — молчать нельзя (та же оговорка, что у Sync на
               Go-стороне). */
            say(s, "каталог: план %s коробки %s не собирается: %s", p->id, b->id, err);
            s->sync_skipped++;
            continue;
        }
        int rc;
        uint8_t family = bd->family ? bd->family : 4;
        if (family != 4 && family != 6) {
            s->sync_skipped++;
            continue;
        }
        /* ПЛАН, КОТОРЫЙ ДАТАПАТ НЕ УНЕСЁТ, НА ПРОВОД НЕ ЕДЕТ (поле 22.10.2026,
           issue #5/#7). Предел длины посылки датапат объявляет приветствием
           (send_cap); план, чья самая длинная посылка в него не укладывается,
           он отвергнет на активации (ctlsrv.c, d2k_plan_fits) — и так каждый
           проход: 3302 отказа за ночь у репортёра, а цель всё это время без
           обхода и без нового замера, потому что привязка «подтверждена».
           Считаем тем же шлюзом до отправки: такой план не ставим, привязку
           помечаем «требует повторной проверки» и снимаем с провода (там его,
           как правило, и нет) — тогда следующее подозрение по цели ведёт к
           новому замеру с сегментом под предел (d2k_arm_segment), а правило
           «план уже подтверждён — не улика» (binding_covering пропускает
           recheck_since) её не прикрывает. Каталог цел: запись и план
           остаются, подтверждение того же или нового плана снимает пометку. */
        if (s->send_cap > 0) {
            size_t need = plan_text_max_emit(text);
            if (need > s->send_cap) {
                d2k_cat_box *bx = &s->cat->boxes[s->sync_box];
                d2k_cat_binding *bdm = &bx->binds[s->sync_bind - 1];
                bdm->recheck_since = wall_s(s, s->now_ms);
                bdm->recheck_mono_ms = s->now_ms ? s->now_ms : 1;
                bx->updated = bdm->recheck_since;
                s->cat->revision++;
                s->sync_unfit++;
                if (strcmp(bd->kind, "name") == 0) {
                    uint8_t tr = bd->transport ? bd->transport : 6;
                    uint8_t wire_shape = bd->shape ? (uint8_t)bd->shape
                                                   : (uint8_t)D2K_LINK_SHAPE_GRANDFATHER;
                    if (d2k_link_del_name_family(s->link_fd, bd->target, tr, wire_shape,
                                                 family, err, sizeof err) != 0) {
                        say(s, "по %s привязку %s не удалось снять с провода: %s",
                            bd->target, bd->plan_id, err);
                    }
                }
                say(s, "каталог: план %s для %s не влезает в посылку датапата (%zu байт при "
                       "пределе %u) — не ставлю, привязка помечена на повторную проверку: "
                       "следующее подозрение перемерит цель сегментом под предел",
                    p->id, bd->target, need, (unsigned)s->send_cap);
                continue;
            }
        }
        if (strcmp(bd->kind, "addr") == 0 || service) {
            uint8_t addr_shape = addr_binding_shape(bd);
            if (!addr_shape) {
                s->sync_unshaped++;
                say(s, "каталог: %s — адресная привязка без однозначной формы протокола "
                       "(транспорт %u, форма %u); общей для всех протоколов адреса не ставлю, "
                       "требуется повторная проверка", bd->target,
                    (unsigned)bd->transport, (unsigned)bd->shape);
                continue;
            }
            uint8_t addr[16] = {0};
            if (strchr(bd->target, '%') ||
                inet_pton(family == 6 ? AF_INET6 : AF_INET, bd->target, addr) != 1) {
                say(s, "каталог: привязка по адресу \"%s\" не разбирается", bd->target);
                s->sync_skipped++;
                continue;
            }
            if(service && preflight_text(text)) {
                uint8_t token[16];
                rc=fresh_trial_id(token)?-1:d2k_link_set_endpoint_bound(s->link_fd,addr,family,
                    htons(bd->server_port),addr_shape,hex,token,err,sizeof err);
                if(!rc)rc=d2k_link_commit_endpoint_trial(s->link_fd,addr,family,
                    htons(bd->server_port),addr_shape,token,err,sizeof err);
            } else if (service)
                rc = d2k_link_set_endpoint(s->link_fd, addr, family, htons(bd->server_port),
                                           addr_shape, hex, err, sizeof err);
            else
                rc = d2k_link_set_addr_family(s->link_fd, addr, family, addr_shape,
                                              hex, err, sizeof err);
        } else {
            /* transport привязки проверяется, но на провод не едет: у SET_NAME
               сегодня нет места под него (d2k_link.h). Ноль — старый файл,
               снятый до появления поля; принимаем как TCP, потому что до
               задачи 5 иных привязок не заводилось.

               ФОРМА ПРИВЕТСТВИЯ С 12.09 ЕДЕТ, и датапат держит запись на
               ИМЯ + ФОРМУ (d2k_plantab_set_name_probe): план не отдаётся
               приветствию другой объявленной формы, а неизвестная форма не
               подходит ни к одной измеренной (shape_fits в plans.c).

               Две привязки одной цели, различающиеся формой, законны: зондов
               два (TLS 1.3 и TLS 1.2, d2k_verify_probe12_on), и браузер со
               старым клиентом одного имени получают каждый свою. Каждая
               уезжает под своей формой и ложится в датапате отдельной записью
               — проверено test_sched («две формы одной цели») и test_plans. */
            uint8_t tr = bd->transport ? bd->transport : 6;
            /* Форма — ИЗ ЗАПИСИ КАТАЛОГА, а не из текущего наблюдения: план
               подтверждён на той форме, и применять его к другой нельзя.

               Формы в записи нет — это весь каталог, заведённый до появления
               поля. Шлём явное дедушкино право, а не ноль: ноль означает
               «сказать нечего», совместимости не даёт, и такой план молча
               перестал бы применяться у человека (0009, U5-R3). */
            uint8_t wire_shape = bd->shape ? (uint8_t)bd->shape
                                           : (uint8_t)D2K_LINK_SHAPE_GRANDFATHER;
            rc = d2k_link_set_name_family(s->link_fd, bd->target, tr, hex,
                                          wire_shape, 0, family, err, sizeof err);
        }
        if (rc != 0) {
            say(s, "каталог: план для %s не отправился: %s", bd->target, err);
            s->sync_skipped++;
            continue;
        }
        s->sync_sent++;
        sent_now++;
    }

    if (s->sync_box >= s->cat->n_boxes) {
        if (sync_areas(s)) return 1;
        s->sync_active = 0;
        stall_budgets_push(s);
        if (s->sync_sent > 0 || s->sync_skipped > 0 || s->sync_weak > 0 ||
            s->sync_unshaped > 0 || s->sync_recheck > 0 || s->sync_unfit > 0) {
            say(s, "каталог: отправлено команд установки по подтверждённым привязкам: %d%s; применение требует ответа датапата",
                s->sync_sent, s->sync_skipped ? " (пропущено негодных: см. выше)" : "");
            if (s->sync_weak > 0) {
                say(s, "каталог: не поставлено привязок со слабым доказательством: "
                       "%d (уровень ниже «обмен прошёл» либо старый UDP CLIENT "
                       "без протокольного доказательства)",
                    s->sync_weak);
            }
            if (s->sync_unshaped > 0) {
                say(s, "каталог: не поставлено адресных привязок без формы протокола: %d "
                       "(требуется повторная проверка)", s->sync_unshaped);
            }
            if (s->sync_recheck > 0) {
                say(s, "каталог: не поставлено привязок, ждущих повторной проверки "
                       "после прямого прохода: %d", s->sync_recheck);
            }
            if (s->sync_unfit > 0) {
                say(s, "каталог: не поставлено планов, не влезающих в посылку датапата: %d "
                       "(привязки помечены на повторную проверку, каталог сохранён)",
                    s->sync_unfit);
            }
        }
        if (s->sync_refused > 0) {
            /* Отказы приходят ПОСЛЕ команд и без имени цели (см. on_event,
               D2K_EV_ACK), поэтому считаются между сводками и выдаются здесь.
               Поле 22.10.2026 (issue #5/#7): 3302 отказа «посылка 1440 байт
               при пределе 1280» лежали только в журнале датапата, а контроллер
               молча ставил каталог заново каждые полторы минуты. */
            say(s, "каталог: датапат отверг планов с прошлой сводки: %d (%s) — обход по "
                   "этим целям не исполняется, причина в журнале датапата",
                s->sync_refused, ack_reason_text(s->sync_refused_code));
            s->sync_refused = 0;
        }
        return 0;
    }
    return 1;
}

/* Заводит поиск на подготовленной задаче: прямой замер, затем готовые планы
   узнанной коробки и/или синтез. Отдельно от on_suspect потому, что тот же
   запуск нужен ПОЗЖЕ — когда задача ждала форму приветствия и дождалась
   (on_shape ниже). Возвращает 1, если задача занята делом. */
static int rx_saved_bootstrap(d2k_sched *s, task *t, int allow_other_family);
static int family_recovery_start(d2k_sched *s, task *t);
static int has_other_family_target_plan(const d2k_sched *s, const task *t) {
    if (t->transport != 6 || t->by_addr || t->port != 443 ||
        d2k_hello_shape(t->trig, t->trig_len) != D2K_SHAPE_MODERN) return 0;
    for (size_t bi = 0; bi < s->cat->n_boxes; bi++) {
        const d2k_cat_box *b = &s->cat->boxes[bi];
        for (size_t i = 0; i < b->n_binds; i++) {
            const d2k_cat_binding *bd = &b->binds[i];
            uint8_t family = bd->family ? bd->family : 4;
            if (!bd->enabled || strcmp(bd->kind, "name") || strcmp(bd->target, t->name) ||
                (bd->transport ? bd->transport : 6) != 6 ||
                (family != 4 && family != 6) || family == t->family ||
                bd->shape != D2K_SHAPE_MODERN || bd->level < 3) continue;
            for (size_t j = 0; j < b->n_plans; j++) {
                const d2k_cat_plan *p = &b->plans[j];
                if (p->enabled && p->text && !strcmp(p->id, bd->plan_id) &&
                    !strcmp(p->proto, "tls") && strlen(p->text) < sizeof t->plans[0]) return 1;
            }
        }
    }
    return 0;
}

/* HTML hints are not targets or proofs. No DNS lookup or request is caused by
 * a hint; they can refine an existing public TLS task only. */
static void remember_resources(d2k_sched *s, const d2k_resource *refs, size_t n) {
    if (n > D2K_RESOURCE_COUNT) return;
    for (size_t i = 0; i < n; i++) {
        if (!refs[i].host[0] || !d2k_resource_path_ok(refs[i].path)) continue;
        size_t slot = 8;
        for (size_t j = 0; j < 8; j++)
            if (!strcmp(s->resources[j].ref.host, refs[i].host)) { slot = j; break; }
        /* УПОМИНАНИЕ НЕ ВЫТЕСНЯЕТ ИЗМЕРЕННОЕ (задача 26). Слот у хоста один, и
           прежде любая более поздняя HTML-ссылка затирала путь, на котором
           обрыв уже ИЗМЕРЕН: следующий эпизод спрашивал упомянутый ресурс (у
           CDN-хоста — тот же завершённый 403), и доказательство погибало.
           Истёкшая отметка измерения своё место не держит. */
        if (slot < 8 && s->resources[slot].proven &&
            s->resources[slot].expires_ms > s->now_ms &&
            strcmp(s->resources[slot].ref.path, refs[i].path)) continue;
        if (slot == 8) slot = s->resource_next++ % 8;
        s->resources[slot].ref = refs[i];
        s->resources[slot].proven = 0;
        s->resources[slot].expires_ms = s->now_ms + 3600000;
    }
}

/* ПУТЬ ИЗМЕРЕННОГО ОБРЫВА ЖИВЁТ ДОЛЬШЕ ОДНОГО ЭПИЗОДА. В привязку путь
 * попадает только вместе с подтверждением плана; пока план не подтверждён (или
 * его ещё ищут), доказанный путь обязан дожить до следующего эпизода здесь,
 * иначе тот снова попросит «/» и получит у CDN-хоста завершённый 403 на
 * несколько сотен байт — то есть никакого измерения. Запоминается только
 * ДОКАЗАННЫЙ обрыв (rx_cut) по имени цели и только путь, проходящий тот же
 * строгий d2k_resource_path_ok. Адресная цель сюда не попадает: у неё нет
 * имени, у которого можно спросить публичный ресурс. */
static void remember_measured_path(d2k_sched *s, const task *t) {
    if (t->by_addr || !t->name[0] || !t->vol.rx_cut ||
        !d2k_resource_path_ok(t->vol.measured_path)) return;
    d2k_resource measured;
    memset(&measured, 0, sizeof measured);
    snprintf(measured.host, sizeof measured.host, "%s", t->name);
    snprintf(measured.path, sizeof measured.path, "%s", t->vol.measured_path);
    size_t slot = 8;
    for (size_t j = 0; j < 8; j++)
        if (!strcmp(s->resources[j].ref.host, measured.host)) { slot = j; break; }
    if (slot == 8) slot = s->resource_next++ % 8;
    s->resources[slot].ref = measured;
    s->resources[slot].proven = 1;
    s->resources[slot].expires_ms = s->now_ms + 3600000;
}

static int public_resource_peer(const task *t) {
    uint8_t ip[16];
    if (inet_pton(t->family == 6 ? AF_INET6 : AF_INET, t->ip, ip) != 1) return 0;
    if (t->family == 6) return (ip[0] & 0xe0) == 0x20; /* global unicast only */
    return ip[0] != 0 && ip[0] != 10 && ip[0] != 127 && ip[0] < 224 &&
        !(ip[0] == 169 && ip[1] == 254) && !(ip[0] == 192 && ip[1] == 168) &&
        !(ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) &&
        !(ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127);
}

static void select_resource_path(d2k_sched *s, task *t) {
    if ((t->transport != 6 && t->transport != 17) || t->port != 443 || t->by_addr ||
        !public_resource_peer(t)) return;
    /* Confirmed witness survives restart; never borrow proof across family
       or TLS shape. A live HTML hint contains no protocol proof at all. */
    const d2k_cat_binding *best = NULL;
    /* QUIC bindings are stored with D2K_LINK_SHAPE_QUIC (verify_confirm);
       a QUIC Initial never parses as a TLS hello shape. */
    uint8_t shape = t->transport == 17 ? (uint8_t)D2K_LINK_SHAPE_QUIC
                                       : (uint8_t)d2k_hello_shape(t->trig, t->trig_len);
    for (size_t bi = 0; bi < s->cat->n_boxes; bi++)
        for (size_t j = 0; j < s->cat->boxes[bi].n_binds; j++) {
            const d2k_cat_binding *bd = &s->cat->boxes[bi].binds[j];
            if (bd->enabled && bd->level >= 3 && !strcmp(bd->kind, "name") &&
                !strcmp(bd->target, t->name) && bd->transport == t->transport &&
                (bd->family ? bd->family : 4) == t->family && bd->shape == shape &&
                d2k_resource_path_ok(bd->probe_path) &&
                (!best || best->confirmed < bd->confirmed)) best = bd;
        }
    /* ИЗМЕРЕННЫЙ ПУТЬ ПЕРЕД УПОМЯНУТЫМ (задача 26). В памяти лежат ресурсы
       двух родов: путь, на котором обрыв ИЗМЕРЕН в прошлом эпизоде (proven), и
       HTML-упоминание — просто ссылка из чужого документа. Снова начинать с
       «/» или спрашивать упоминание, когда измеренный путь известен, значит
       выбросить измерение; свидетель подтверждённой привязки идёт впереди
       обоих — он привязан к плану, который на нём и подтверждали. */
    const d2k_resource *proven = NULL, *mention = NULL;
    for (size_t j = 0; j < 8; j++) {
        if (s->resources[j].expires_ms <= s->now_ms ||
            strcmp(s->resources[j].ref.host, t->name) ||
            !d2k_resource_path_ok(s->resources[j].ref.path)) continue;
        if (s->resources[j].proven) { if (!proven) proven = &s->resources[j].ref; }
        else if (!mention) mention = &s->resources[j].ref;
    }
    const char *first = best ? best->probe_path
                      : proven ? proven->path
                      : mention ? mention->path : NULL;
    if (!first) return;
    snprintf(t->measure_path, sizeof t->measure_path, "%s", first);
    /* Запас пересобирается вместе с основным путём: память могла с прошлого
       раза измениться, и старый запас говорил бы о ней неправду. */
    t->measure_alt[0] = '\0';
    /* ЗАПАСНОЙ УЖЕ НАБЛЮДАВШИЙСЯ ПУТЬ (задача 26, п.4): если по первому мерить
       будет нечем, повтор спросит его — и только его. Это не перебор: оба
       пути реально наблюдались у этой цели, второго источника нет. */
    if (proven && strcmp(proven->path, t->measure_path))
        snprintf(t->measure_alt, sizeof t->measure_alt, "%s", proven->path);
    else if (mention && strcmp(mention->path, t->measure_path))
        snprintf(t->measure_alt, sizeof t->measure_alt, "%s", mention->path);
    say(s, "по %s RX и кандидат проверяются по публичному stylesheet %s, не по короткому /",
        t->name, t->measure_path);
    if (t->measure_alt[0])
        say(s, "по %s в запасе уже наблюдавшийся %s: по нему пойдёт повтор, если по "
               "%s мерить будет нечем", t->name, t->measure_alt, t->measure_path);
}

/* Под s->mu. 1 — у имени ECH-конфигурация с этим public_name, 0 — свежий
   ответ «не та или нет», -1 — не спрашивали или ответ устарел. */
static int ech_rr_known(const d2k_sched *s, const char *name, const char *public_name) {
    for (size_t i = 0; i < SCHED_ECH_RR; i++) {
        const __typeof__(s->ech_rr[0]) *e = &s->ech_rr[i];
        if (!e->used || e->until_ms < s->now_ms || strcmp(e->name, name)) continue;
        return e->has && !strcmp(e->public_name, public_name);
    }
    return -1;
}

static void ech_rr_store(d2k_sched *s, const char *name, int has, const char *public_name) {
    size_t slot = s->ech_rr_next;
    for (size_t i = 0; i < SCHED_ECH_RR; i++)
        if (s->ech_rr[i].used && !strcmp(s->ech_rr[i].name, name)) { slot = i; break; }
    if (slot == s->ech_rr_next) s->ech_rr_next = (s->ech_rr_next + 1) % SCHED_ECH_RR;
    __typeof__(s->ech_rr[0]) *e = &s->ech_rr[slot];
    snprintf(e->name, sizeof e->name, "%s", name);
    snprintf(e->public_name, sizeof e->public_name, "%s", has ? public_name : "");
    e->has = has;
    e->used = 1;
    e->until_ms = s->now_ms + (has ? SCHED_ECH_RR_YES_MS : SCHED_ECH_RR_NO_MS);
}

/* Свидетель-проверка (ech_chal): s->mu держит вызывающий. */
static int ech_chal_has(const d2k_sched *s, const char *name) {
    for (size_t i = 0; i < sizeof s->ech_chal / sizeof s->ech_chal[0]; i++)
        if (s->ech_chal[i].name[0] && s->ech_chal[i].until_ms > s->now_ms &&
            !strcmp(s->ech_chal[i].name, name)) return 1;
    return 0;
}

static void ech_chal_add(d2k_sched *s, const char *name) {
    if (ech_chal_has(s, name)) return;
    size_t k = s->ech_chal_next++ % (sizeof s->ech_chal / sizeof s->ech_chal[0]);
    snprintf(s->ech_chal[k].name, sizeof s->ech_chal[k].name, "%s", name);
    s->ech_chal[k].until_ms = s->now_ms + 1800000;
}

/* Рабочий поток. Первый кандидат списка, чей HTTPS RR несёт эту ECH-
   конфигурацию; свидетель, уже ответивший страницей проверки, — только при
   allow_chal и только если других нет. Исключение — по результату (RR не та,
   проверка), не по счёту (ревью Astra 17.10). */
static int ech_pick_witness(d2k_sched *s, task *t, int real, int allow_chal) {
    for (int pass = 0; pass < (allow_chal ? 2 : 1); pass++) {
        for (size_t i = 0; i < t->ech_witness_count && !t->stop; i++) {
            pthread_mutex_lock(&s->mu);
            int known = ech_rr_known(s, t->ech_witnesses[i], t->name);
            int chal = ech_chal_has(s, t->ech_witnesses[i]);
            pthread_mutex_unlock(&s->mu);
            if (known == 0 || (pass == 0 && chal)) continue;
            if (!allow_chal && t->ech_bad[i]) continue;
            if (known < 0 && !real && i >= 4) continue;
            int match = known == 1;
            if (!match) {
                d2k_ech_config cfg;
                int has = !d2k_sched_ech_resolve_hook(t->ech_witnesses[i], s->measure_mark, &cfg);
                pthread_mutex_lock(&s->mu);
                ech_rr_store(s, t->ech_witnesses[i], has, has ? cfg.public_name : "");
                pthread_mutex_unlock(&s->mu);
                match = has && !strcmp(cfg.public_name, t->name);
            }
            if (match) {
                snprintf(t->ech_origin, sizeof t->ech_origin, "%s", t->ech_witnesses[i]);
                say(s, "по %s ECH-свидетель найден: %s — его HTTPS RR несёт ECH-конфигурацию "
                       "с public_name %s", t->name, t->ech_origin, t->name);
                return 1;
            }
        }
    }
    return 0;
}

/* Главный поток. Есть ли в списке свидетель, ещё не исключённый результатом:
   RR не опровергнута и страницей проверки не отвечал. */
static int ech_witness_untried(d2k_sched *s, const task *t) {
    for (size_t i = 0; i < t->ech_witness_count; i++) {
        if (t->ech_bad[i]) continue;
        pthread_mutex_lock(&s->mu);
        int ok = ech_rr_known(s, t->ech_witnesses[i], t->name) != 0 &&
                 !ech_chal_has(s, t->ech_witnesses[i]);
        pthread_mutex_unlock(&s->mu);
        if (ok) return 1;
    }
    return 0;
}

/* Главный поток. Свидетель-основа опыта ответил страницей проверки: отметка
   в опыте (переживает вытеснение общего кеша) и подсказка другим поискам. */
static void ech_witness_reject(d2k_sched *s, task *t) {
    for (size_t i = 0; i < t->ech_witness_count; i++)
        if (!strcmp(t->ech_witnesses[i], t->ech_origin)) t->ech_bad[i] = 1;
    pthread_mutex_lock(&s->mu);
    ech_chal_add(s, t->ech_origin);
    pthread_mutex_unlock(&s->mu);
}

/* Главный поток, s->mu не держит. Пропускает само внешнее имя, повторы и
   имена со свежим ответом «конфигурация не та». */
static void ech_witness_add(d2k_sched *s, task *t, const char *name) {
    if (!name || !name[0] || !strcmp(name, t->name) ||
        t->ech_witness_count >= SCHED_ECH_WITNESSES) return;
    for (size_t k = 0; k < t->ech_witness_count; k++)
        if (!strcmp(t->ech_witnesses[k], name)) return;
    pthread_mutex_lock(&s->mu);
    int known = ech_rr_known(s, name, t->name);
    pthread_mutex_unlock(&s->mu);
    if (known == 0) return;
    snprintf(t->ech_witnesses[t->ech_witness_count++], sizeof t->ech_witnesses[0], "%s", name);
}

static int start_search(d2k_sched *s, task *t) {
    if(newchain_task(s,t))return 0;

    if (fill_hellos(s, t) != 0) {
        if (t->transport == 17 && t->shape_armed) {
            /* Не применяем готовый план по одному подозрению. Если нельзя
               собрать собственный QUIC Initial, ждём запрошенный снимок. */
            t->state = T_SHAPE_WAIT;
            say(s, "по %s (QUIC) жду форму приветствия: собрать QUIC-вход не удалось, "
                   "мерить до снимка нечем", t->name);
            return 1;
        }
        task_reset(s, t);
        return 0;
    }
    select_resource_path(s, t);
    doh_target *doh = t->transport==6 ? doh_find(s,t->name) : NULL;
    if (doh && t->port==doh->port) {
        dns_configure_task(t,doh);
        t->rx_volume_only=0;
        t->skip_volume_once=1;
    }

    t->ech_offer = t->transport == 6 && t->trig_snapped && !t->ech_grease &&
                   d2k_hello_ech_offer(t->trig, t->trig_len, NULL) == 1;
    t->ech_origin[0] = 0;
    t->ech_reselect = 0;
    memset(t->ech_bad, 0, sizeof t->ech_bad);
    t->ech_exhausted = 0;
    t->ladder_unmeasurable = 0;
    t->ech_trial = 0;
    t->ech_replay = 0;
    t->ech_witness_count = 0;
    if (t->ech_offer) {
        t->asked_shape = D2K_LINK_SHAPE_ECH_TCP;
        /* ECH baseline owns its application result. A late-reset trigger
         * must not feed it into the ordinary identity/gzip RX gate. */
        t->rx_volume_only = 0;
        /* Preserve the explicit successful witness across restarts. The
         * witness is an origin name carrying this ECH config, not an address:
         * one proven over IPv6 serves IPv4 too (поле 04.10, rutracker в
         * Chrome по IPv4 при свидетеле, подтверждённом по IPv6). Its HTTPS RR
         * is re-checked by the worker; the same family's witness wins. */
        for (int pass = 0; pass < 2 && !t->ech_origin[0]; pass++)
        for (size_t bi = 0; s->cat && bi < s->cat->n_boxes; bi++) {
            const d2k_cat_box *b = &s->cat->boxes[bi];
            for (size_t j = 0; j < b->n_binds; j++) {
                const d2k_cat_binding *bd = &b->binds[j];
                if (bd->enabled && bd->level >= 3 && bd->transport == 6 &&
                    (pass || bd->family == t->family) &&
                    !strcmp(bd->target, t->name) && bd->ech_origin[0])
                    snprintf(t->ech_origin, sizeof t->ech_origin, "%s", bd->ech_origin);
            }
        }
        /* Свидетель-проверка объёма не покажет: выбор — заново, рабочим
           потоком (свидетель-проверка там последний). */
        pthread_mutex_lock(&s->mu);
        if (t->ech_origin[0] && ech_chal_has(s, t->ech_origin)) t->ech_origin[0] = 0;
        pthread_mutex_unlock(&s->mu);
        /* Кандидаты в свидетели — только своё знание, по убыванию силы:
         * (1) имена, чей ответ HTTPS RR уже назвал это внешнее имя;
         * (2) свидетели других своих ECH-привязок (любая семья);
         * (3) имена, недавно виденные открытым текстом на том же адресе;
         * (4) свои подтверждённые привязки имён (любой транспорт), новые
         *     раньше старых;
         * (5) имена, недавно виденные открытым текстом на любом адресе (CDN
         *     раздаёт один public_name на много адресов; свежая установка
         *     иначе свидетеля не найдёт никогда).
         * (4) раньше (5): поле 04.10.2026, чистый каталог — 32 места заняли
         * имена чужих адресов, и rua.gr (своя привязка, HTTPS RR с той же
         * конфигурацией cloudflare-ech.com) в очередь не попал.
         * Это не утверждение, что кандидат — скрытое имя потока: рабочий
         * поток берёт первого, у кого HTTPS RR даёт ту же конфигурацию.
         * Список собирается и при свидетеле из каталога: если тот ответит
         * страницей проверки, следующего берут из этого же списка (ревью
         * Astra 17.10). */
        {
            pthread_mutex_lock(&s->mu);
            char known[SCHED_ECH_WITNESSES][256];
            size_t n_known = 0;
            for (size_t i = 0; i < SCHED_ECH_RR && n_known < SCHED_ECH_WITNESSES; i++)
                if (ech_rr_known(s, s->ech_rr[i].name, t->name) == 1)
                    snprintf(known[n_known++], sizeof known[0], "%s", s->ech_rr[i].name);
            pthread_mutex_unlock(&s->mu);
            for (size_t i = 0; i < n_known; i++) ech_witness_add(s, t, known[i]);
            for (size_t bi = 0; s->cat && bi < s->cat->n_boxes; bi++)
                for (size_t j = 0; j < s->cat->boxes[bi].n_binds; j++) {
                    const d2k_cat_binding *bd = &s->cat->boxes[bi].binds[j];
                    if (bd->enabled && bd->level >= 3 && bd->ech_origin[0])
                        ech_witness_add(s, t, bd->ech_origin);
                }
            uint8_t addr[16] = {0};
            int have_addr = inet_pton(t->family == 6 ? AF_INET6 : AF_INET, t->ip, addr) == 1;
            for (int pass = 0; pass < 3; pass++) {
                if (pass == 1) {
                    /* (4) по убыванию времени подтверждения. Транспорт имени
                       не важен: свидетельствует HTTPS RR имени, а не план. */
                    int64_t below = INT64_MAX;
                    while (t->ech_witness_count < SCHED_ECH_WITNESSES) {
                        const char *pick = NULL;
                        int64_t best = INT64_MIN;
                        for (size_t bi = 0; s->cat && bi < s->cat->n_boxes; bi++)
                            for (size_t j = 0; j < s->cat->boxes[bi].n_binds; j++) {
                                const d2k_cat_binding *bd = &s->cat->boxes[bi].binds[j];
                                if (!bd->enabled || bd->level < 3 ||
                                    strcmp(bd->kind, "name") || !bd->target[0] || bd->ech_origin[0] ||
                                    bd->confirmed >= below || bd->confirmed <= best) continue;
                                best = bd->confirmed; pick = bd->target;
                            }
                        if (!pick) break;
                        /* Все привязки с этим временем — разом: равные метки
                           иначе потерялись бы при строгом «меньше». */
                        for (size_t bi = 0; s->cat && bi < s->cat->n_boxes; bi++)
                            for (size_t j = 0; j < s->cat->boxes[bi].n_binds; j++) {
                                const d2k_cat_binding *bd = &s->cat->boxes[bi].binds[j];
                                if (bd->enabled && bd->level >= 3 &&
                                    !strcmp(bd->kind, "name") && bd->target[0] && !bd->ech_origin[0] &&
                                    bd->confirmed == best)
                                    ech_witness_add(s, t, bd->target);
                            }
                        below = best;
                    }
                    continue;
                }
                int same = pass == 0; /* (3) тот же адрес, (5) любой */
                for (size_t i = 0; i < SCHED_SEEN; i++) {
                    const seen_name *w = &s->seen[i];
                    if (!w->used || w->transport != 6 || w->observed_ms + 600000 < s->now_ms) continue;
                    size_t bytes = w->family == 6 ? 16 : 4;
                    int at = have_addr && w->family == t->family &&
                             (!memcmp(addr, w->low_ip, bytes) || !memcmp(addr, w->high_ip, bytes));
                    if (at == same) ech_witness_add(s, t, w->name);
                }
            }
        }
        say(s, "по %s обнаружен ECH offer; по HTTPS RR отличаю настоящий ECH от GREASE; "
               "собственный witness: %s%s", t->name, t->ech_origin[0] ? t->ech_origin : "пока неизвестен",
            t->ech_origin[0] ? "" : (t->ech_witness_count ? ", кандидатов проверю" : ", кандидатов нет"));
    }
    if(!t->gate_skip_reuse && preflight_family_enabled(t->family) && t->transport==6 &&
       t->trigger_code==D2K_SUSPECT_SILENT && !t->ech_offer) {
        known_snapshot(s,t);
        if(t->known_valid && t->known_props.response_gate==D2K_PROP_YES &&
           t->known_props.gate_carry==D2K_PROP_YES && gate_start(s,t,&t->known_props,1)) return 1;
    }
    if (!encrypted_dns_task(t) && family_recovery_start(s,t)) return 1;
    if (!encrypted_dns_task(t) && !t->rx_volume_only && !t->family_reuse && has_other_family_target_plan(s, t))
        t->family_reuse = 1;
    if (t->rx_volume_only) {
        /* Do not try catalog plans on a generic late reset. First establish
           the measured response-volume fingerprint; only then can its box
           donate plans in the volume-aware result path. */
        t->n_known = 0;
        t->n_plans = 0;
        t->researched = 1;
        t->state = T_ASKING;
        t->asked_shape = t->ech_offer ? D2K_LINK_SHAPE_ECH_TCP :
            (uint8_t)d2k_hello_shape(t->trig, t->trig_len);
        if (start_worker(s, t, JOB_CLASSIFY) != 0) {
            task_reset(s, t);
            return 0;
        }
        say(s, "по %s %s: сначала проверяю только повторяемый обрыв входящего ответа",
            t->name, t->trigger_code == D2K_SUSPECT_TCP_STALL || t->trigger_code == D2K_SUSPECT_LATE_SILENCE
                ? late_close_what(t->trigger_code) : "позднее закрытие");
        return 1;
    }
    /* Задача 32: есть свои подтверждённые планы той же формы — сперва только
       базовый вопрос донора. Шаг один на задачу: пройденный (3) не
       повторяется перезапуском поиска; брошенный ради снимка (1) задаётся
       заново его байтами. Семейный путь и база другого семейства — свои. */
    t->quic_ech = t->transport == 17 && t->trig_snapped && quic_pack_ech(t->trig, t->trig_len);
    if (t->quic_ech)
        say(s, "по %s (QUIC) вход — пачка клиента с ECH: план подтверждается только "
               "повтором этой пачки (уровень рукопожатия)", t->name);
    if (encrypted_dns_task(t)) t->own_first=3;
    if (t->own_first <= 1)
        t->own_first = (t->transport == 17 ? d2k_sched_quic_base_hook != NULL
                                           : d2k_sched_tcp_base_hook != NULL) &&
                       !t->family_reuse && own_first_plans(s, t, 0) > 0 ? 1 : 0;
    t->researched = 1;
    t->state = T_ASKING;
    t->addr_ack = 0;
    t->addr_recheck = !encrypted_dns_task(t) && t->transport == 6 &&
                      dead_find(s, t->name, t->transport, t->family, t->ip) != NULL;
    t->asked_shape = t->ech_offer ? D2K_LINK_SHAPE_ECH_TCP :
        (uint8_t)(t->transport == 17 ? D2K_SHAPE_UNKNOWN : d2k_hello_shape(t->trig, t->trig_len));
    if (start_worker(s, t, JOB_CLASSIFY) != 0) {
        task_reset(s, t);
        return 0;
    }
    say(s, "по %s (%s) начинаю поиск: %s:%u, приветствие %zu байт%s",
        t->name, t->transport == 17 ? "QUIC" : "TCP", t->ip, (unsigned)t->port,
        t->trig_len, t->shape_armed ? ", снимок заказан" : "");
    if (t->own_first == 1)
        say(s, "по %s сначала базовый вопрос донора: если рукопожатие режется, "
               "проверю свои подтверждённые планы до полного замера", t->name);
    return 1;
}

/* ПРОВЕРКА ПЛАНА, ПОЯВИВШЕГОСЯ ПОСЛЕ ОТДЫХА ЦЕЛИ (24.10.2026).
 *
 * ЧТО БЫЛО. Подтверждённый план коробки догонял только те цели, чей поиск
 * ещё шёл (цикл в verify_confirm). Цель, чей поиск уже кончился неудачей,
 * ждала следующего запроса пользователя — и этот запрос был обречён: поиск
 * по нему заводится за секунды, а план встаёт на 5–7 с позже, когда
 * соединение клиента уже оборвано. Поле 24.10.2026, soundcloud.com: так было
 * во всех шести кругах подряд, и контрольный запрос всегда оказывался той
 * самой жертвой.
 *
 * ЧТО ТЕПЕРЬ. Новое подтверждение поднимает поколение знания, и остывшая цель
 * получает по одной проверке на поколение: базовый вопрос донора (режется ли
 * рукопожатие) и свои подтверждённые планы той же формы. Это не новый поиск —
 * полного замера такая задача не начинает, он по этой цели только что был.
 *
 * ПОЧЕМУ ЭТО НЕ НАРУШАЕТ «РАБОЧИЙ ТРАФИК НЕ ЗАПУСКАЕТ ПОДБОР». Проверка
 * заводится ТОЛЬКО по цели, чей поиск кончился исчерпанием при доказанной
 * блокировке, и ТОЛЬКО пока её остывание ещё идёт: то есть по цели, про
 * которую уже известно, что она не работает, и которая нужна была минуту
 * назад. Совпадение отпечатка применимость не доказывает — поэтому план
 * проверяется зондом, а не ставится молча (§0 «сначала проверять уже
 * найденное собственное решение»).
 *
 * Одна проверка за раз: цель у коробки не одна, и залп проверок был бы тем
 * самым перебором, только по целям.
 *
 * 1 — проверка заведена, 0 — по этой записи проверять нечего. */
static int plan_news_recheck(d2k_sched *s, target_cooldown *c, int64_t now_ms) {
    /* БЕЗ БАЗОВОГО ВОПРОСА ПРОВЕРКИ НЕ БЫВАЕТ. Он и есть здесь защита
       неподменяемого свойства «рабочий прямой трафик не запускает подбор»:
       план ставится только если рукопожатие к цели по-прежнему режется. Нет
       крючка базы — start_search повёл бы задачу в полный замер, то есть в
       подбор без спроса; тогда проверять нечем и лучше ничего не делать. */
    if (d2k_sched_tcp_base_hook == NULL) { return 0; }
    task *t = task_of(s, c->name, c->transport, c->family);
    if (t && t->state != T_FREE && t->state != T_RESTING) { return 0; }
    if (t) { task_done(s, t); }
    t = task_free_slot(s);
    if (!t) { return 0; }
    task_reset(s, t);
    snprintf(t->name, sizeof t->name, "%s", c->name);
    t->transport = c->transport;
    t->family = c->family;
    snprintf(t->ip, sizeof t->ip, "%s", c->ip);
    t->port = c->port;
    t->trigger_code = c->signal_code;
    t->trigger_shape = c->trigger_shape;
    t->ech_grease = c->ech_grease;
    t->trigger_planned = D2K_LINK_PLANNED_NO;
    t->fp.method = D2K_FP_METHOD;
    t->plan_retry = 1;
    t->started_ms = now_ms;
    t->began_ms = now_ms;
    if (fill_hellos(s, t) != 0) { task_reset(s, t); return 0; }
    /* A fresh offer needs its own RR decision; do not reuse GREASE from
       different bytes cached since the exhausted measurement. */
    if (t->ech_grease && d2k_hello_ech_offer(t->trig,t->trig_len,NULL)==1 &&
        c->grease_input!=seed_input_of(t->trig,t->trig_len,NULL,0))
        t->ech_grease=0;
    /* История относится к этой цели и действующему остыванию. Фильтруем
       её ДО отбора порции: иначе новый план возвращал в очередь старые,
       а восемь старых могли скрыть новый за первой порцией. */
    for (uint8_t i = 0; i < c->n_failed_plans; i++) {
        tried_add(t, c->failed_plans[i]);
    }
    /* Сухая примерка не заполняет own_seen: очередь наполнит поиск после
       базового вопроса. Нет нового плана — запускать проверку незачем. */
    if (own_first_plans(s, t, 0) == 0) { task_reset(s, t); return 0; }
    say(s, "по %s в каталоге появился план, которого эта цель ещё не пробовала, а она уже "
           "отдыхала — проверяю его своим зондом, не дожидаясь следующего запроса", c->name);
    if (!start_search(s, t)) {
        say(s, "по %s проверка появившегося плана не запустилась — цель ждёт запроса, "
               "как раньше", c->name);
        return 0;
    }
    return 1;
}

/* Один заказ — одна проверка за тик, и только пока есть что проверять. */
static void plan_news_tick(d2k_sched *s, int64_t now_ms) {
    if (!s->plan_news) { return; }
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        if (s->tasks[i].plan_retry && s->tasks[i].state != T_FREE &&
            s->tasks[i].state != T_RESTING && s->tasks[i].state != T_WATCHING) {
            return;                      /* проверка уже идёт — по одной */
        }
    }
    for (size_t i = 0; i < SCHED_COOLDOWN_SLOTS; i++) {
        target_cooldown *c = &s->cooldowns[i];
        if (!c->used || !c->exhausted || c->challenge || force_name(s,c->name)) { continue; }
        if (c->transport != 6 || !c->ip[0]) { continue; }
        if (c->plan_gen == s->plan_gen) { continue; }
        /* У цели УЖЕ есть подтверждённая привязка — датапат её прикрывает, и
           доказывать нечего. Проверка нужна той, у которой решения нет. */
        {
            const d2k_cat_binding *bd = binding_for(s, c->name, c->transport, c->family);
            if (bd && bd->enabled && bd->level >= 3 && !bd->recheck_since) {
                c->plan_gen = s->plan_gen;
                continue;
            }
        }
        /* Остывание кончилось — цель давно никому не нужна: следующий запрос
           сам заведёт поиск, и проверять её наперёд не за чем. */
        if (now_ms >= c->until_ms) { continue; }
        c->plan_gen = s->plan_gen;
        if (plan_news_recheck(s, c, now_ms)) { return; }
    }
    s->plan_news = 0;
}

/* ИМЯ КОРОБКИ, которой идёт подтверждённое зондом знание. Пассивное
   UDP-наблюдение сюда не попадает: оно не подтверждает обход. */
static void box_id_for(const d2k_sched *s, const task *t, const char *text,
                       char *box_id, size_t cap) {
    if (t->box_id[0]) {
        /* Коробка узнана по отпечатку — успех идёт ей, а не новой записи:
           иначе каталог наполнялся бы клонами одной и той же коробки. */
        snprintf(box_id, cap, "%s", t->box_id);
    } else if (t->fp.n_sig != 0 && s->cat) {
        /* A stale plan does not invalidate a measured box fingerprint. If the
           catalog has exactly one compatible model, let a newly measured and
           verified replacement enrich that box. With multiple compatible
           models, preserve ambiguity and do not guess an owner. */
        const d2k_cat_box *match = NULL;
        size_t matches = 0;
        for (size_t i = 0; i < s->cat->n_boxes; i++) {
            const d2k_cat_box *b = &s->cat->boxes[i];
            if (d2k_fp_same(&b->fp, &t->fp)) {
                match = b;
                matches++;
            }
        }
        if (matches == 1) {
            snprintf(box_id, cap, "%s", match->id);
        } else {
            goto new_box;
        }
    } else if (t->fp.n_sig == 0) {
        /* Примет нет вовсе — узнавать нечем. Знание пишется под отдельную
           запись, и это честнее, чем выдать её за узнанную коробку. */
        snprintf(box_id, cap, "box-без-приметы");
    } else {
new_box:
        ;
        /* Новая коробка, и её имя выводится ИЗ ОТПЕЧАТКА, а не из счётчика и
           не из транспорта: та же коробка, встреченная завтра на другой цели,
           обязана получить то же имя. */
        uint64_t h = 1469598103934665603ULL;
        for (size_t i = 0; i < t->fp.n_sig; i++) {
            char b[64];
            if (is_volume_kind(t->fp.sig[i].kind)) {
                /* У объёмной приметы TTL/TOS/IPID нулевые: без корзины порога
                   обрыв на 16 и на 128 КБ, взятые одним планом, получали бы
                   одно имя и сливались в одну коробку (задача 23).
                   Направление — в самом роде приметы. Остальные роды хешируются
                   как прежде: имена их коробок не меняются. */
                snprintf(b, sizeof b, "%s/%u/%u/%u/b%d", t->fp.sig[i].kind,
                         (unsigned)t->fp.sig[i].ttl, (unsigned)t->fp.sig[i].tos,
                         (unsigned)t->fp.sig[i].ipid,
                         volume_bucket(t->fp.sig[i].volume));
            } else {
                snprintf(b, sizeof b, "%s/%u/%u/%u", t->fp.sig[i].kind,
                         (unsigned)t->fp.sig[i].ttl, (unsigned)t->fp.sig[i].tos,
                         (unsigned)t->fp.sig[i].ipid);
            }
            h ^= fnv1a(b);
            h *= 1099511628211ULL;
        }
        /* Coarse passive evidence is not enough to merge a NEW solution
           into an old model whose ready plans failed. Keep it separate. */
        h ^= fnv1a(text);
        snprintf(box_id, cap, "box-%08x", (unsigned)(h & 0xFFFFFFFFu));
        /* Имя уже занято коробкой, чей отпечаток с этим ПРОТИВОРЕЧИТ (та же
           корзина, но порог за допуском; или старая запись с неизмеренным
           порогом)? Тогда это другая коробка: box_ensure молча вернул бы
           чужую, а её отпечаток не переписывается — новая примета пропала
           бы. Имя солится до свободного или совместимого; старая коробка
           остаётся нетронутой. */
        for (unsigned salt = 1; s->cat && salt < 64; salt++) {
            const d2k_cat_box *clash = NULL;
            for (size_t i = 0; i < s->cat->n_boxes; i++) {
                if (strcmp(s->cat->boxes[i].id, box_id) == 0) {
                    clash = &s->cat->boxes[i];
                    break;
                }
            }
            if (!clash || clash->fp.n_sig == 0 || d2k_fp_same(&clash->fp, &t->fp)) {
                break;
            }
            h = (h ^ salt) * 1099511628211ULL;
            snprintf(box_id, cap, "box-%08x", (unsigned)(h & 0xFFFFFFFFu));
        }
    }
}

/* --- ГОЛОС: замеряется перенесённым C voice/STUN-инструментом ------------
 * Измеритель использует цель из живого conntrack и исходный перебор
 * voiceprobe. Его результат запускается в worker: UDP-оракулы ждут сеть.
 * Только BLOCKED + найденные и помеченные байты превращаются во временный
 * voice Plan; проверка применением к самому разговору остаётся отдельной.
 * Обычный UDP EXCHANGE не подтверждает приложение и не создаёт каталог. */
/* Ставит или продлевает голосовой опыт: тот же поток-ключ (клиент, точка
   сервера, клиентский порт 0) и то же поколение — датапат продлевает lease
   и не заводит второй записи (d2k_plantab_set_addr_probe). */
static int voice_trial_send(d2k_sched *s, task *t, int64_t now_ms,
                            char *err, size_t errcap) {
    if (t->n_plans == 0) { snprintf(err, errcap, "нет плана"); return -1; }
    char wire[sizeof t->plans[0]];
    char hex[2 * D2K_PLAN_TLV_MAX + 1];
    snprintf(wire, sizeof wire, "%s", t->plans[0]);
    if (stamp_plan_id(wire, t->ver_plan_id) != 0) {
        snprintf(err, errcap, "Plan не идентифицируется");
        return -1;
    }
    if (d2k_plan_text_to_hex(wire, hex, sizeof hex, err, errcap) != 0 ||
        d2k_link_set_addr_probe_family(s->link_fd, t->addr_probe_src_ip, 0,
                                       t->addr_probe_dst_ip, t->addr_probe_dst_port_be,
                                       17, 4, t->addr_probe_trial_id,
                                       D2K_ADDR_PROBE_LEASE_MAX_MS, hex,
                                       err, errcap) != 0) {
        return -1;
    }
    t->voice_lease_ms = now_ms;
    return 0;
}

static const char *voice_ip_fmt(const uint32_t *ip, char *buf) {
    if (!inet_ntop(AF_INET, ip, buf, INET_ADDRSTRLEN)) { snprintf(buf, INET_ADDRSTRLEN, "?"); }
    return buf;
}
static const char *voice_ip_text(const uint32_t *ip) {
    static char b[INET_ADDRSTRLEN];
    return voice_ip_fmt(ip, b);
}
static const char *voice_ip_text2(const uint32_t *ip) {
    static char b[INET_ADDRSTRLEN];
    return voice_ip_fmt(ip, b);
}

/* Голосовой опыт этой задачи (не QUIC по адресу): клиент LAN + точка
   сервера, клиентский порт любой. */
static int voice_trial_owned(const task *t) {
    return !t->by_addr && t->addr_probe_identity_valid &&
           t->addr_probe_src_port_be == 0 && t->addr_probe_dst_port_be != 0;
}

/* Подозрение голоса относится к контексту ждущего опыта: та же точка
   сервера (IP:порт) и тот же клиент LAN. Клиентский порт не сравнивается —
   опыт ждёт любого следующего потока этого клиента (задача 15). */
static int voice_trial_same_context(const task *t, const d2k_ev *ev) {
    if ((ev->family ? ev->family : 4) != 4) { return 0; }
    uint16_t dport = ntohs(t->addr_probe_dst_port_be);
    if (memcmp(ev->low_ip, t->addr_probe_dst_ip, 4) == 0 && ev->low_port == dport) {
        return memcmp(ev->high_ip, t->addr_probe_src_ip, 4) == 0;
    }
    if (memcmp(ev->high_ip, t->addr_probe_dst_ip, 4) == 0 && ev->high_port == dport) {
        return memcmp(ev->low_ip, t->addr_probe_src_ip, 4) == 0;
    }
    return 0;
}

static void stun_start(d2k_sched *s, task *t) {
    t->state = T_STUN_MEASURE;
    if (start_worker(s, t, JOB_STUN) != 0) {
        say(s, "по %s STUN-замер не запустился: местная ошибка", t->name);
        task_reset(s, t);
        return;
    }
    say(s, "STUN к [%s]:%u: проверяю прямой Binding-обмен; исходный поток отдельно",
        t->ip, (unsigned)t->port);
}

/* A prior confirmation is a hypothesis, scoped to this service and protocol.
 * A fresh Binding reply is never promoted to proof of the original app. */
static int stun_plan_compatible(const char *text) {
    static uint8_t tlv[D2K_PLAN_TLV_MAX]; /* serialized control loop only */
    size_t n = 0; char err[160]; d2k_plan *p = NULL;
    if (d2k_plan_text_to_tlv(text, tlv, sizeof tlv, &n, err, sizeof err) ||
        d2k_plan_load(tlv, n, &p, err, sizeof err)) return 0;
    int ok = d2k_plan_transport(p) == 17 && d2k_plan_proto(p) == 3;
    d2k_plan_free(p);
    return ok;
}

static int stun_candidate_start(d2k_sched *s, task *t, int64_t now_ms) {
    uint8_t target[16] = {0};
    int af = t->family == 6 ? AF_INET6 : AF_INET;
    size_t addrlen = t->family == 6 ? 16 : 4;
    if (inet_pton(af, t->ip, target) != 1) return 0;
    const d2k_cat_binding *best = NULL;
    const d2k_cat_plan *chosen = NULL;
    for (size_t i = 0; !t->stun_own_attempted && s->cat && i < s->cat->n_boxes; i++) {
        const d2k_cat_box *box = &s->cat->boxes[i];
        for (size_t j = 0; j < box->n_binds; j++) {
            const d2k_cat_binding *b = &box->binds[j];
            uint8_t address[16] = {0};
            if (!b->enabled || !b->confirmed || b->recheck_since || b->level < 3 ||
                b->verified_by == D2K_VERBY_CLIENT || strcmp(b->kind, "service") ||
                b->family != t->family || inet_pton(af, b->target, address) != 1 ||
                memcmp(address, target, addrlen) ||
                b->server_port != t->port || b->transport != 17 ||
                b->shape != D2K_LINK_SHAPE_VOICE) continue;
            const d2k_cat_plan *p = plan_by_id(box, b->plan_id);
            if (!p || !p->text || (strcmp(p->proto, "voice") && strcmp(p->proto, "stun")) || !stun_plan_compatible(p->text)) continue;
            if (!best || binding_beats(b, best)) { best = b; chosen = p; }
        }
    }
    char generated[256];
    if(!chosen) {
        const uint8_t *q=t->stun_direct_request;
        if(!t->stun_direct_timeout || t->stun_fragment_attempted ||
           q[0]!=0 || q[1]!=1 || q[2]!=0 || q[3]!=0 ||
           q[4]!=0x21 || q[5]!=0x12 || q[6]!=0xa4 || q[7]!=0x42)return 0;
        /* The owned failed datagram is a complete Binding request. Split at
           its payload boundary (UDP header length 8), preserving all STUN
           bytes for endpoint reassembly. ipfrag 1 is that nonoverlapping,
           forward operation, not a candidate list or a censorship verdict. */
        snprintf(generated,sizeof generated,"d2k-plan 1 7\nid 00000000000000000000000000000000\nproto udp voice\nipfrag 1\norder forward\n");
    }
    const char *proposal=chosen?chosen->text:generated;
    char wire[sizeof t->plans[0]], hex[sizeof t->plans[0] * 2], err[160];
    if (strlen(proposal) >= sizeof wire || fresh_trial_id(t->stun_trial_id) ||
        fresh_trial_id(t->stun_plan_id)) return 0;
    strcpy(wire, proposal);
    if (stamp_plan_id(wire, t->stun_plan_id) ||
        d2k_plan_text_to_hex(wire, hex, sizeof hex, err, sizeof err)) return 0;
    d2k_stun_probe_opt opt = {t->ip, t->port, 3000, s->mark};
    t->stun_trial = d2k_stun_trial_open(s->link_fd, &opt, hex, t->stun_trial_id,
        D2K_ADDR_PROBE_LEASE_MAX_MS, err, sizeof err);
    if (!t->stun_trial) {
        say(s, "STUN к [%s]:%u: кандидат не запущен: %s", t->ip, t->port, err);
        return 0;
    }
    if(chosen)t->stun_own_attempted=1;
    else t->stun_fragment_attempted=1;
    snprintf(t->plans[0], sizeof t->plans[0], "%s", wire);
    t->n_plans = 1;
    t->stun_applied = t->stun_refused = t->stun_candidate_timeout = 0;
    memset(&t->stun_binding, 0, sizeof t->stun_binding);
    t->state = T_STUN_ACK;
    t->stun_until_ms = now_ms + SCHED_VERIFY_STEP_MS;
    if(chosen)say(s, "STUN к [%s]:%u: прямой таймаут не доказывает блокировку; проверяю своё решение %s для этой точки",
        t->ip, t->port, chosen->id);
    else say(s,"STUN к [%s]:%u: измеренный Binding не ответил; опыт разделяет UDP-заголовок и STUN без изменения запроса",t->ip,t->port);
    return 1;
}

static int stun_client_start(d2k_sched *s, task *t, int64_t now_ms) {
    const d2k_flowkey *f = &t->trigger_flow;
    uint8_t dst[16] = {0};
    size_t n = t->family == 6 ? 16 : 4;
    if (!t->n_plans || t->trigger_shape != D2K_LINK_SHAPE_VOICE ||
        f->family != t->family || f->transport != 17 || !t->port ||
        inet_pton(t->family == 6 ? AF_INET6 : AF_INET, t->ip, dst) != 1) return 0;
    int low = !memcmp(f->a_ip,dst,n) && f->a_port == t->port;
    int high = !memcmp(f->b_ip,dst,n) && f->b_port == t->port;
    if (low == high || !(low ? f->b_port : f->a_port)) return 0;
    stun_retire(s,t);
    if (t->stun_trial) return 0;
    char hex[2 * D2K_PLAN_TLV_MAX + 1], err[160];
    if (fresh_trial_id(t->addr_probe_trial_id) || fresh_trial_id(t->ver_plan_id) ||
        stamp_plan_id(t->plans[0],t->ver_plan_id) ||
        d2k_plan_text_to_hex(t->plans[0],hex,sizeof hex,err,sizeof err)) return 0;
    memcpy(t->addr_probe_dst_ip,dst,sizeof dst);
    memcpy(t->addr_probe_src_ip,low ? f->b_ip : f->a_ip,16);
    t->addr_probe_dst_port_be=htons(t->port);
    t->addr_probe_src_port_be=htons(low ? f->b_port : f->a_port);
    if (d2k_link_set_addr_probe_family(s->link_fd,t->addr_probe_src_ip,
            t->addr_probe_src_port_be,t->addr_probe_dst_ip,t->addr_probe_dst_port_be,
            17,t->family,t->addr_probe_trial_id,D2K_ADDR_PROBE_LEASE_MAX_MS,
            hex,err,sizeof err)) return 0;
    t->addr_probe_identity_valid=t->trial_installed=1;
    t->trial_acked=t->stun_refused=0;
    t->stun_client_done_id=t->stun_client_reply_id=0;
    memset(&t->stun_binding,0,sizeof t->stun_binding);
    memset(&t->voice_execution_binding,0,sizeof t->voice_execution_binding);
    t->state=T_STUN_CLIENT;
    t->stun_until_ms=now_ms+D2K_ADDR_PROBE_LEASE_MAX_MS;
    say(s,"STUN к [%s]:%u: диагностический ответ получен; жду повтор и ответ исходного клиента под точным временным опытом",t->ip,t->port);
    return 1;
}

static int stun_client_event(task *t,const d2k_ev *e) {
    if(t->state!=T_STUN_CLIENT ||
       memcmp(e->trial_id,t->addr_probe_trial_id,D2K_TRIAL_ID_LEN))return 0;
    if(e->kind==D2K_EV_ACK && e->code==D2K_CMD_SET_ADDR_PROBE) {
        if(((e->num>>8)&0xffu)==1u)t->trial_acked=1;
        else t->stun_refused=1;
        return 1;
    }
    if(!ev_matches_flow(e,&t->trigger_flow) ||
       memcmp(e->plan_id,t->ver_plan_id,D2K_PLAN_ID_LEN))return 0;
    if(e->kind==D2K_EV_REFUSED){t->stun_refused=1;return 1;}
    if(!e->execution_id || !d2k_binding_known(&e->execution_binding) ||
       e->execution_binding.kind!=D2K_BIND_FLOW || !e->execution_binding.temporary ||
       e->execution_binding.family!=t->family ||
       e->execution_binding.shape!=D2K_LINK_SHAPE_VOICE)return 0;
    if(e->kind==D2K_EV_APPLIED) {
        t->stun_client_done_id=e->execution_id;
        t->stun_binding=e->execution_binding;
        return 1;
    }
    if(e->kind==D2K_EV_EXCHANGE && e->planned==D2K_LINK_PLANNED_YES &&
       e->code==D2K_UDP_PROOF_STUN) {
        t->stun_client_reply_id=e->execution_id;
        t->voice_execution_binding=e->execution_binding;
        return 1;
    }
    return 0;
}

static void stun_candidate_done(d2k_sched *s, task *t, int64_t now_ms, int success,
                                const char *reason) {
    if(success && stun_client_start(s,t,now_ms))return;
    snprintf(t->res.reason, sizeof t->res.reason, "%s", reason);
    say(s, "STUN к [%s]:%u: %s; работа исходного приложения не подтверждена", t->ip, t->port, reason);
    search_report(s, t, now_ms, success ? "candidate-binding" : "inconclusive",
        t->stun_fragment_attempted?"measured-fragment":"own-service", reason);
    cooldown_record(s, t, 2);
    task_done(s, t); /* joins first, then retires only its exact trial */
}

static int stun_candidate_event(task *t, const d2k_ev *e) {
    if (!t->stun_trial) return 0;
    if (e->kind == D2K_EV_ACK) return d2k_stun_trial_event(t->stun_trial, e);
    if ((e->kind != D2K_EV_APPLIED && e->kind != D2K_EV_REFUSED) ||
        (t->state != T_STUN_PROBE && t->state != T_STUN_PROOF) ||
        memcmp(e->trial_id, t->stun_trial_id, D2K_TRIAL_ID_LEN) ||
        memcmp(e->plan_id, t->stun_plan_id, D2K_PLAN_ID_LEN)) return 0;
    const d2k_stun_flow *f = d2k_stun_trial_flow(t->stun_trial);
    if (e->family != f->family || e->transport != 17) return 0;
    size_t n = f->family == 6 ? 16 : 4;
    int forward = !memcmp(e->low_ip, f->source, n) && !memcmp(e->high_ip, f->destination, n) &&
        e->low_port == ntohs(f->source_port_be) && e->high_port == ntohs(f->destination_port_be);
    int reverse = !memcmp(e->high_ip, f->source, n) && !memcmp(e->low_ip, f->destination, n) &&
        e->high_port == ntohs(f->source_port_be) && e->low_port == ntohs(f->destination_port_be);
    if (!forward && !reverse) return 0;
    if (e->kind == D2K_EV_REFUSED) { t->stun_refused = 1; return 1; }
    const d2k_binding_context *b = &e->execution_binding;
    if (!e->execution_id || !d2k_binding_known(b) || b->kind != D2K_BIND_FLOW ||
        !b->temporary || b->family != f->family || b->shape != D2K_LINK_SHAPE_VOICE) return 0;
    if (t->stun_applied && !d2k_binding_equal(&t->stun_binding, b)) t->stun_refused = 1;
    t->stun_binding = *b;
    t->stun_applied = 1;
    return 1;
}

static void stun_candidate_tick(d2k_sched *s, task *t, int64_t now_ms) {
    if (t->state == T_STUN_ACK) {
        d2k_stun_trial_state state = d2k_stun_trial_get_state(t->stun_trial);
        if (state == D2K_STUN_TRIAL_READY) {
            t->stun_socket = d2k_stun_trial_start(t->stun_trial);
            if (!t->stun_socket || start_worker(s, t, JOB_STUN_TRIAL)) {
                stun_candidate_done(s, t, now_ms, 0, "местный отказ запуска кандидата");
                return;
            }
            t->state = T_STUN_PROBE;
        } else if (state == D2K_STUN_TRIAL_INSTALL_REFUSED || now_ms >= t->stun_until_ms) {
            stun_candidate_done(s, t, now_ms, 0, "установка опыта не подтверждена; зонд не отправлен");
        }
        return;
    }
    if (t->state == T_STUN_PROBE) {
        pthread_mutex_lock(&s->mu);
        int ready = t->res_ready;
        d2k_stun_probe_res r = t->stun_res;
        pthread_mutex_unlock(&s->mu);
        if (!ready) return;
        join_worker(t);
        (void)d2k_stun_trial_finished(t->stun_trial);
        t->probes += r.sent ? 1 : 0; s->probes_used += r.sent ? 1 : 0;
        t->stun_candidate_timeout = r.status == D2K_STUN_TIMEOUT &&
            r.sent && r.marked && t->stun_direct_timeout &&
            t->stun_own_attempted && !t->stun_fragment_attempted;
        if (!t->stun_candidate_timeout &&
            (r.status != D2K_STUN_BINDING_OK || !r.sent || !r.marked ||
             (r.mapped_family != 4 && r.mapped_family != 6))) {
            stun_candidate_done(s, t, now_ms, 0, "кандидат не дал подтверждённого Binding-обмена");
            return;
        }
        t->state = T_STUN_PROOF;
        t->stun_until_ms = now_ms + SCHED_VERIFY_STEP_MS;
    }
    if (t->stun_refused) {
        stun_candidate_done(s, t, now_ms, 0, "исполнитель отказал либо контекст опыта сменился");
    } else if (t->stun_applied) {
        if (t->stun_candidate_timeout) {
            stun_retire(s, t);
            if (!t->stun_trial && stun_candidate_start(s, t, now_ms)) return;
            stun_candidate_done(s, t, now_ms, 0, "своё решение исполнено без Binding-ответа; следующий опыт не запущен");
            return;
        }
        stun_candidate_done(s, t, now_ms, 1, "корректный Binding-ответ и исполнение на точном потоке подтверждены");
    } else if (now_ms >= t->stun_until_ms) {
        stun_candidate_done(s, t, now_ms, 0, t->stun_candidate_timeout ?
            "Binding-ответа нет, исполнение кандидата не доказано" :
            "Binding-ответ есть, исполнение кандидата не доказано");
    }
}

static void stun_finish(d2k_sched *s, task *t, int64_t now_ms) {
    pthread_mutex_lock(&s->mu);
    d2k_stun_probe_res r = t->stun_res;
    pthread_mutex_unlock(&s->mu);
    join_worker(t);
    t->probes += r.sent ? 1 : 0;
    s->probes_used += r.sent ? 1 : 0;
    int direct = r.status == D2K_STUN_BINDING_OK && r.sent && r.marked &&
                 (r.mapped_family == 4 || r.mapped_family == 6);
    t->stun_direct_timeout=r.status==D2K_STUN_TIMEOUT && r.sent && r.marked &&
        r.request_length==sizeof t->stun_direct_request;
    if(t->stun_direct_timeout)memcpy(t->stun_direct_request,r.request,sizeof t->stun_direct_request);
    if (!direct && r.status == D2K_STUN_TIMEOUT && r.sent && r.marked &&
        stun_candidate_start(s, t, now_ms)) return;
    const char *reason = direct ?
        "прямой Binding-зонд получил свой корректный ответ; работу исходного приложения это не подтверждает" :
        r.status == D2K_STUN_TIMEOUT ?
        "Binding-зонд не получил корректного ответа; блокировка не доказана, возможен запрос с авторизацией" :
        r.status == D2K_STUN_NETWORK_ERROR ?
        "сеть вернула ошибку; блокировка не доказана" :
        r.status == D2K_STUN_PROTOCOL_ERROR ?
        "получен STUN-ответ с ошибкой на свою транзакцию; это не таймаут и не подтверждение работы приложения" :
        "местный отказ либо неподтверждённая изоляция зонда; свойства сети не измерены";
    snprintf(t->res.reason, sizeof t->res.reason, "%s", reason);
    if(r.status==D2K_STUN_PROTOCOL_ERROR)
        snprintf(t->res.reason,sizeof t->res.reason,"STUN error %u: %s",r.protocol_error,reason);
    reason=t->res.reason;
    say(s, "STUN к [%s]:%u: %s (отправлено=%d, отвергнуто ответов=%u, ошибка=%d)",
        t->ip, (unsigned)t->port, reason, r.sent, r.rejected, r.error);
    search_report(s, t, now_ms, direct ? "probe-direct" : "inconclusive", direct ? "direct" : "none", reason);
    /* No catalog mutation: a direct fresh Binding transaction cannot
       confirm/revoke an application-specific plan for the observed flow. */
    cooldown_record(s, t, direct ? 0 : 2);
    task_done(s, t);
}

static void voice_start(d2k_sched *s, task *t) {
    t->voice_known_prefix_valid=0;
    for(size_t i=0;i<s->cat->n_boxes && !t->voice_known_prefix_valid;i++) {
        const d2k_cat_box *box=&s->cat->boxes[i];
        for(size_t j=0;j<box->n_binds && !t->voice_known_prefix_valid;j++) {
            const d2k_cat_binding *b=&box->binds[j];
            if(!b->enabled || !b->confirmed || b->recheck_since || b->level<3 || b->transport!=17 ||
               b->family!=4 || b->shape!=D2K_LINK_SHAPE_VOICE ||
               b->verified_by!=D2K_VERBY_VOICE_DISCOVERY ||
               (strcmp(b->kind,"addr") &&
                (strcmp(b->kind,"service") || b->server_port!=t->port)) ||
               strcmp(b->target,t->ip))continue;
            for(size_t k=0;k<box->n_plans;k++) {
                const d2k_cat_plan *p=&box->plans[k];
                if(p->enabled && !strcmp(p->id,b->plan_id) &&
                   d2k_voice_discovery_prefix(p->text,t->voice_known_prefix)){
                    t->voice_known_prefix_valid=1;break;
                }
            }
        }
    }
    t->n_plans = 0;
    t->next_plan = 0;
    t->state = T_VOICE_MEASURE;
    if (start_worker(s, t, JOB_VOICE) != 0) {
        say(s, "по %s голосовой C-замер не запустился", t->name);
        task_reset(s, t);
        return;
    }
    say(s, "по %s (голос) запускаю C-замер живого потока и перебор исходных приманок",
        t->name);
}

static void voice_finish_measure(d2k_sched *s, task *t, int64_t now_ms) {
    d2k_voice_res r;
    pthread_mutex_lock(&s->mu);
    r = t->voice_res;
    pthread_mutex_unlock(&s->mu);
    join_worker(t);
    t->voice_discovery_verified = r.discovery_verified;

    if (r.verdict != D2K_VOICE_BLOCKED) {
        /* CLEAR does not identify whether the known prefix or the subsequent
         * bare Discovery probe succeeded. Do not infer its source from cache. */
        search_report(s, t, now_ms,
            r.verdict == D2K_VOICE_CLEAR
                ? (t->voice_known_prefix_valid ? "probe-clear" : "probe-direct")
                : "inconclusive",
            r.verdict == D2K_VOICE_CLEAR
                ? (t->voice_known_prefix_valid ? "unknown" : "direct") : "none",
            r.verdict == D2K_VOICE_CLEAR
                ? "голосовой замер показал чистый путь"
                : "голосовой замер не подтвердил блокировку: временный план не ставлю");
        if (t->voice_known_prefix_valid && r.verdict == D2K_VOICE_CLEAR) {
            say(s, "по %s (голос) сохраняю подтверждённый приём: %s", t->name, r.reason);
        } else say(s, "по %s (голос) временный Plan не ставлю: измерение не подтвердило "
               "блокировку (%s)", t->name, r.reason[0] ? r.reason : "нет причины");
        task_fail(s, t, now_ms);
        return;
    }
    int flow_matches = t->voice_flow_bound &&
        ((memcmp(&r.ip, t->voice_flow.a_ip, sizeof r.ip) == 0 &&
          r.port == t->voice_flow.a_port &&
          memcmp(&r.client_ip, t->voice_flow.b_ip, sizeof r.client_ip) == 0 &&
          r.client_port == t->voice_flow.b_port) ||
         (memcmp(&r.ip, t->voice_flow.b_ip, sizeof r.ip) == 0 &&
          r.port == t->voice_flow.b_port &&
          memcmp(&r.client_ip, t->voice_flow.a_ip, sizeof r.client_ip) == 0 &&
          r.client_port == t->voice_flow.a_port));
    if (!flow_matches || !r.marked || r.arm_len == 0 ||
        r.arm_len > sizeof r.arm_bytes || r.arm_copies <= 0) {
        say(s, "по %s (голос) блокировка измерена, но найденный arm неполон или "
               "не помечен либо не относится к исходной пятёрке — Plan не ставлю", t->name);
        task_fail(s, t, now_ms);
        return;
    }
    if (d2k_voice_arm_plan(r.arm_bytes, r.arm_len, (unsigned)r.arm_copies,
                           t->plans[0], sizeof t->plans[0]) != 0) {
        say(s, "по %s (голос) найденный arm не выражается языком Plan", t->name);
        task_fail(s, t, now_ms);
        return;
    }

    t->n_plans = 1;
    t->next_plan = 1;
    t->n_known = 0;
    t->fb_queue = 0;
    char wire[sizeof t->plans[0]], cat_id[40], err[160];
    plan_ident(t->plans[0], cat_id, sizeof cat_id, t->ver_plan_id);
    snprintf(wire, sizeof wire, "%s", t->plans[0]);
    if (stamp_plan_id(wire, t->ver_plan_id) != 0) {
        say(s, "по %s (голос) не удалось идентифицировать измеренный Plan", t->name);
        task_fail(s, t, now_ms);
        return;
    }
    /* ОПЫТ — КЛИЕНТ LAN + ТОЧКА СЕРВЕРА + ЛЮБОЙ КЛИЕНТСКИЙ ПОРТ, С TRIAL ID
       (задача 15). Портовая запись имени (SET_NAME_PROBE) пользовательскому
       трафику не видна, а разговор, шедший во время замера, к этому моменту
       за окном экрана (S99d2k: в очередь идут первые 8 пакетов потока) —
       его поздние пакеты датапат не видит вовсе. Опыт ждёт СЛЕДУЮЩИЙ поток
       того же клиента к той же точке (повторный вход, новый звонок): его
       первый запрос голоса получает план, APPLIED несёт trial ID (on_applied).
       Другим клиентам и другим точкам опыт не достаётся. */
    (void)cat_id;
    if (t->family != 4 || fresh_trial_id(t->addr_probe_trial_id) != 0) {
        say(s, "по %s (голос) опыт не завести", t->name);
        task_fail(s, t, now_ms);
        return;
    }
    memset(t->addr_probe_src_ip, 0, sizeof t->addr_probe_src_ip);
    memcpy(t->addr_probe_src_ip, &r.client_ip, sizeof r.client_ip);
    t->addr_probe_src_port_be = 0;      /* любой клиентский порт */
    memset(t->addr_probe_dst_ip, 0, sizeof t->addr_probe_dst_ip);
    memcpy(t->addr_probe_dst_ip, &r.ip, sizeof r.ip);
    t->addr_probe_dst_port_be = htons(r.port);
    if (voice_trial_send(s, t, now_ms, err, sizeof err) != 0) {
        say(s, "по %s (голос) измеренный Plan не поставился: %s", t->name, err);
        task_fail(s, t, now_ms);
        return;
    }
    t->addr_probe_identity_valid = 1;
    t->trial_installed = 1;
    t->trial_shape = D2K_LINK_SHAPE_VOICE;
    t->probe_sport_be = 0;
    t->probes += r.probes;
    s->probes_used += r.probes;
    t->state = T_VOICE_TRIAL;
    say(s, "по %s (голос) найденный исходным перебором arm %s ×%d (%zu байт) "
           "поставлен на следующий разговор клиента %s к %s:%u (любой клиентский "
           "порт, lease). Это временный опыт",
        t->name, r.fake_arm[0] ? r.fake_arm : "voice", r.arm_copies, r.arm_len,
        voice_ip_text(&r.client_ip), voice_ip_text2(&r.ip), (unsigned)r.port);
}

/* QUIC-цель без доступного SNI. Не выдумываем имя: start_search проходит
 * общий путь каталога/коробки и donor Run, а адресный кандидат затем
 * устанавливается только на зарезервированный verifier flow. Само событие
 * UDP EXCHANGE по-прежнему лишь наблюдение; оно не подтверждает протокол и
 * не создаёт постоянную addr-привязку. */
static void quic_addr_start(d2k_sched *s, task *t) {
    /* Адресная цель — не повод подставить универсальный delay. Начинаем тот
       же переносимый QUIC Run, что и для имени: сначала знания коробки,
       затем контроль/VN, arm search и вопросы. */
    t->by_addr = 1;
    say(s, "по %s (QUIC) SNI не читается — запускаю донорский поиск по адресу, "
           "без выдуманного имени", t->name);
    (void)start_search(s, t);
}

static int meas_state(task_state st);

static size_t measurements_in_flight(const d2k_sched *s) {
    size_t n = 0;
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++)
        if (meas_state(s->tasks[i].state) && !s->tasks[i].quic_parked) n++;
    return n;
}

static size_t queued_measurements(const d2k_sched *s) {
    size_t n = 0;
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        if (s->tasks[i].state == T_QUEUED || s->tasks[i].quic_parked) { n++; }
    }
    return n;
}

/* Снимок ресурсов раз в SCHED_CPU_SAMPLE_MS модельных часов (задачи 29,
   38). Процессор — экспоненциальное сглаживание с постоянной
   ~SCHED_CPU_EWMA_MS; отказ источника или откат счётчиков — «данных нет».
   Память и conntrack — значения снимка как есть: они отзываются на
   прибавку замера сразу (поток, записи conntrack зондов), сглаживать их —
   опоздать с ответом на нехватку. 1 — снят новый снимок. */
static int res_sample(d2k_sched *s, int64_t now_ms) {
    if (s->cpu_tried && now_ms - s->cpu_try_ms < SCHED_CPU_SAMPLE_MS) return 0;
    int64_t dt = now_ms - s->cpu_try_ms;
    s->cpu_tried = 1;
    s->cpu_try_ms = now_ms;
    s->res_seq++;
    uint64_t av = 0, tot = 0;
    s->mem_valid = d2k_sched_mem_hook && d2k_sched_mem_hook(&av, &tot) == 0 && tot > 0;
    if (s->mem_valid) { s->mem_avail_kb = av; s->mem_total_kb = tot; }
    uint64_t cnt = 0, mx = 0;
    s->ct_valid = d2k_sched_ct_hook && d2k_sched_ct_hook(&cnt, &mx) == 0 && mx > 0;
    if (s->ct_valid) { s->ct_count = cnt; s->ct_max = mx; }
    uint64_t busy = 0, total = 0;
    unsigned cores = 0;
    if (!d2k_sched_cpu_hook || d2k_sched_cpu_hook(&busy, &total, &cores) != 0) {
        s->cpu_have_prev = s->cpu_valid = 0;
        return 1;
    }
    if (s->cpu_have_prev && total > s->cpu_prev_total && busy >= s->cpu_prev_busy &&
        busy - s->cpu_prev_busy <= total - s->cpu_prev_total) {
        uint64_t db = busy - s->cpu_prev_busy, dtot = total - s->cpu_prev_total;
        int64_t inst = 1000000 - (int64_t)(db * 1000000 / dtot);
        if (!s->cpu_valid) {
            s->cpu_free_u = inst;
            s->cpu_valid = 1;
        } else {
            if (dt < 1) dt = 1;
            s->cpu_free_u += (inst - s->cpu_free_u) * dt / (dt + SCHED_CPU_EWMA_MS);
        }
    } else if (s->cpu_have_prev) {
        s->cpu_valid = 0; /* счётчики откатились — прежнее сглаживание не о том */
    }
    s->cpu_prev_busy = busy;
    s->cpu_prev_total = total;
    s->cpu_have_prev = 1;
    s->cpu_cores = cores ? cores : 1;
    return 1;
}

enum { MEAS_LIM_CPU = 1u, MEAS_LIM_MEM = 2u, MEAS_LIM_CT = 4u, MEAS_LIM_SLOTS = 8u };

/* Подстройка возможна, только когда измерены процессор И память. */
static int res_valid(const d2k_sched *s) { return s->cpu_valid && s->mem_valid; }

static int cpu_free_pct(const d2k_sched *s) {
    return (int)((s->cpu_free_u + 5000) / 10000);
}

static uint64_t mem_reserve_kb(const d2k_sched *s) {
    uint64_t r = s->mem_total_kb * SCHED_MEM_RESERVE_PCT / 100;
    return r > SCHED_MEM_RESERVE_MIN_KB ? r : SCHED_MEM_RESERVE_MIN_KB;
}

static int mem_short(const d2k_sched *s) {
    return s->mem_valid && s->mem_avail_kb < mem_reserve_kb(s);
}

static int ct_short(const d2k_sched *s) {
    /* Счётчики conntrack — 32-битные в ядре: произведение в 64 битах
       не переполняется. */
    return s->ct_valid && s->ct_count * 100 >= s->ct_max * SCHED_CT_LIMIT_PCT;
}

static int ct_pct(const d2k_sched *s) {
    return (int)(s->ct_count >= s->ct_max ? 100 : s->ct_count * 100 / s->ct_max);
}

static int meas_state(task_state st) {
    switch (st) {
    case T_GATE_INSTALL:
    case T_GATE_VERIFY:
    case T_GATE_COMMIT:
    case T_ASKING:
    case T_PROPS_CONTACT:
    case T_PROPS_WAIT:
    case T_PLANNING:
    case T_TRIAL_SETTLE:
    case T_VERIFY:
    case T_VERIFY_WAIT:
    case T_VOICE_MEASURE:
    case T_STUN_MEASURE:
    case T_STUN_ACK:
    case T_STUN_PROBE:
    case T_STUN_PROOF:
        return 1;
    default:
        return 0;
    }
}

/* Реальная ёмкость (задача 38): сколько замеров вообще может идти сейчас —
   ячейки задач, свободные или уже занятые замером либо очередью (ячейку,
   где цель наблюдается или отдыхает, замер не займёт), и не больше
   пробных слотов датапата. */
static size_t measure_slots(const d2k_sched *s) {
    size_t n = 0;
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        task_state st = s->tasks[i].state;
        if (st == T_FREE || st == T_QUEUED || meas_state(st)) n++;
    }
    return n < SCHED_MEASURE_SLOTS ? n : SCHED_MEASURE_SLOTS;
}

static void limiter_text(unsigned lm, char *buf, size_t n) {
    static const struct { unsigned bit; const char *name; } names[] = {
        { MEAS_LIM_CPU, "процессор" }, { MEAS_LIM_MEM, "память" },
        { MEAS_LIM_CT, "conntrack" }, { MEAS_LIM_SLOTS, "слоты" },
    };
    size_t at = 0;
    buf[0] = '\0';
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        if (!(lm & names[i].bit)) continue;
        int w = snprintf(buf + at, n - at, "%s%s", at ? " / " : "", names[i].name);
        if (w < 0 || (size_t)w >= n - at) break;
        at += (size_t)w;
    }
}

/* Запуск, заполнивший предел, — спрос дошёл до предела: рост решит
   следующий снимок ресурсов, который уже видит этот замер. */
static void measure_started(d2k_sched *s) {
    if (measurements_in_flight(s) >= s->meas_limit) s->grow_pending = 1;
}

static void measure_limit_update(d2k_sched *s, int fresh) {
    size_t active = measurements_in_flight(s), lim = s->meas_limit;
    int valid = res_valid(s);
    int cpu_shrink = s->cpu_valid && s->cpu_free_u < SCHED_CPU_SHRINK_FREE_U;
    int cpu_hold = s->cpu_valid && !cpu_shrink && s->cpu_free_u < SCHED_CPU_GROW_FREE_U;
    if (!valid) {
        lim = SCHED_DEFAULT_ACTIVE_MEASUREMENTS;
        s->grow_pending = 0;
    } else if (fresh) {
        /* AIMD: нехватка любого ресурса — вдвое (не ниже 1, идущие не
           прерываются); запас всех и спрос на пределе — плюс один; между
           25 и 40 % свободного процессора — держится. Раз за снимок. */
        if (cpu_shrink || mem_short(s) || ct_short(s)) {
            lim = lim / 2;
            if (lim < 1) lim = 1;
        } else if (!cpu_hold &&
                   (s->grow_pending || (active >= lim && queued_measurements(s) > 0)) &&
                   lim < measure_slots(s)) {
            lim++;
        }
        s->grow_pending = 0;
    }
    unsigned lm = 0;
    if (valid) {
        if (cpu_shrink || cpu_hold) lm |= MEAS_LIM_CPU;
        if (mem_short(s)) lm |= MEAS_LIM_MEM;
        if (ct_short(s)) lm |= MEAS_LIM_CT;
        if (!lm && lim >= measure_slots(s)) lm |= MEAS_LIM_SLOTS;
    }
    if (lim != s->meas_limit || lm != s->limiter) {
        s->meas_limit = lim;
        s->limiter = lm;
        s->limit_since_ms = s->now_ms;
    }
    /* Журнал с мёртвой зоной (задача 29): смена наличия данных — сразу;
       смена предела или причины — только когда продержалась
       SCHED_LIMIT_LOG_STABLE_MS. Нагрузка около порога иначе писала бы
       строку на каждом пересечении. */
    if (valid == s->cpu_logged_valid &&
        ((lim == s->limit_logged && lm == s->limiter_logged) ||
         s->now_ms - s->limit_since_ms < SCHED_LIMIT_LOG_STABLE_MS))
        return;
    s->cpu_logged_valid = valid;
    s->limit_logged = lim;
    s->limiter_logged = lm;
    if (!valid) {
        say(s, "замеров %zu из %zu (данных о загрузке процессора и памяти нет — "
               "прежний предел)", active, lim);
        return;
    }
    char why[96], ct[32];
    limiter_text(lm, why, sizeof why);
    if (s->ct_valid) snprintf(ct, sizeof ct, "%d %%", ct_pct(s));
    else snprintf(ct, sizeof ct, "нет данных");
    say(s, "замеров %zu из %zu, %s%s (процессор свободен %d %%, память доступна "
           "%llu МБ из %llu, conntrack %s)",
        active, lim, lm ? "упёрлись в: " : "запас по всем ресурсам", why,
        cpu_free_pct(s), (unsigned long long)(s->mem_avail_kb / 1024),
        (unsigned long long)(s->mem_total_kb / 1024), ct);
}

/* An unplanned flow queued BEFORE a compatible area was installed cannot
   testify against that new area. Let its next flow inherit without an old
   backlog probe. Applied-plan failures and exact overrides remain diagnostic. */
static int installed_family_ready(const d2k_sched *s, const task *t, uint64_t after_event,
                                  int include_exact) {
    const d2k_group_state *state = s->cat->groups;
    if (!state || t->by_addr) return 0;
    uint8_t shape = t->trigger_shape;
    if (!shape) return 0;
    for (size_t bi=0; !include_exact && bi<s->cat->n_boxes; bi++) {
        const d2k_cat_box *b=&s->cat->boxes[bi];
        for (size_t j=0; j<b->n_binds; j++) {
            const d2k_cat_binding *bd=&b->binds[j];
            if (bd->enabled && bd->level>=3 && !strcmp(bd->kind,"name") &&
                !strcmp(bd->target,t->name) &&
                (bd->transport ? bd->transport : 6)==t->transport &&
                (bd->family ? bd->family : 4)==t->family &&
                d2k_cat_shape_fits(bd->shape,shape)) return 0;
        }
    }
    d2k_group_key key;
    const char *path=t->transport==17 || !t->measure_path[0] ? "/" : t->measure_path;
    if(d2k_group_key_make(&key,t->transport,t->family,shape,path,"")) return 0;
    d2k_domain_group group;
    if(!d2k_group_match(state,t->name,&key,&group)) return 0;
    installed_area desired;
    memset(&desired,0,sizeof desired);
    desired.kind=1;
    strcpy(desired.name,group.suffix); strcpy(desired.plan_id,group.plan_id);
    desired.transport=group.key.transport; desired.shape=group.key.shape;
    desired.family=group.key.family;
    int eligible=0;
    for(size_t i=0;i<d2k_group_slots(state);i++) {
        installed_area candidate;
        if(desired_area(s,i,&candidate) && area_key_same(&candidate,&desired) &&
           !strcmp(candidate.plan_id,desired.plan_id)) { eligible=1; break; }
    }
    if(!eligible) return 0;

    for(size_t j=0;j<s->n_areas;j++) {
        const installed_area *a=&s->areas[j];
        if(a->confirmed && a->confirmed_event>after_event &&
           area_key_same(a,&desired) && !strcmp(a->plan_id,desired.plan_id)) return 1;
    }
    return 0;
}

static int queued_family_ready(const d2k_sched *s, const task *t) {
    return t->queued_ms && t->trigger_planned == D2K_LINK_PLANNED_NO &&
        installed_family_ready(s, t, t->queued_event, 0);
}

static int family_recovery_eligible(const d2k_sched *s,const task *t) {
    return !t->rx_volume_only && t->trigger_planned==D2K_LINK_PLANNED_YES &&
        installed_family_ready(s,t,0,1);
}

/* Путь в ключе семейства (задача 39, раунд 2). У TCP он часть контекста
   замера (RX-проба по ресурсу). У QUIC путь — только подсказка, каким
   ресурсом спросить данные плеча и проверки, а не свойство коробки: ключ
   семейства QUIC всегда «/», как до задачи 39. */
static const char *group_path(uint8_t transport, const char *path) {
    return transport == 17 || !path || !path[0] ? "/" : path;
}

static int family_recovery_start(d2k_sched *s, task *t) {
    if(t->family_fast || t->trigger_planned!=D2K_LINK_PLANNED_YES ||
       t->rx_volume_only || t->ech_offer || !installed_family_ready(s,t,0,1)) return 0;
    /* Совместимость, а не равенство (задача 24): «не измерено» с любой
       стороны не противоречит форме ключа (d2k_cat_shape_fits). */
    if(t->transport==6 &&
       !d2k_cat_shape_fits((uint8_t)d2k_hello_shape(t->trig,t->trig_len),t->trigger_shape)) return 0;
    d2k_group_key key;
    if(d2k_group_key_make(&key,t->transport,t->family,t->trigger_shape,
                         group_path(t->transport,t->measure_path),"")) return 0;
    d2k_domain_group group;
    const d2k_domain_group *g=d2k_group_match(s->cat->groups,t->name,&key,&group);
    if(!g) return 0;
    t->n_plans=t->n_known=t->next_plan=0; t->fb_queue=0;
    /* Verify the inherited plan once, then distinct OWN confirmed siblings.
       No speculative candidate reaches user traffic; install_next reserves
       an exact trial port and normal verifier/APPLIED gates remain in force. */
    for(int pass=0;pass<2;pass++) {
        for(size_t i=0;i<s->cat->groups->n_observations;i++) {
            const d2k_group_observation *o=&d2k_group_rows(s->cat->groups)[i];
            if(!(o->evidence&D2K_GROUP_BLOCKED_CONFIRMED) ||
               (o->evidence&(D2K_GROUP_DIRECT_CLEAR|D2K_GROUP_PLAN_FAILED)) ||
               !d2k_group_key_same(&key,&o->key) || !d2k_domain_member(o->name,g->suffix) ||
               (pass==0)!=(!strcmp(o->plan_id,g->plan_id))) continue;
            for(size_t bi=0;bi<s->cat->n_boxes;bi++) {
                const d2k_cat_box *box=&s->cat->boxes[bi];
                const d2k_cat_plan *p=plan_by_id(box,o->plan_id);
                if(!p || !p->enabled || !p->text ||
                   strcmp(p->proto,t->transport==17?"quic":"tls") ||
                   strlen(p->text)>=sizeof t->plans[0]) continue;
                int confirmed=0;
                for(size_t j=0;j<box->n_binds;j++) {
                    const d2k_cat_binding *bd=&box->binds[j];
                    /* Наблюдение семейства хранит НОРМАЛИЗОВАННОЕ имя
                       (d2k_group_learn), привязка — имя из SNI как пришло:
                       сравнение сырых строк теряло брата, подтверждённого
                       под «B.Example.COM.» (задача 24). */
                    char bd_name[256];
                    /* Помеченная к перепроверке привязка (задача 21) снята с
                       провода и подтверждённым покрытием не считается — как в
                       own_exact_confirmed и sync (финальное ревью, п.2). Её
                       план остаётся кандидатом обычного поиска коробки. */
                    if(!bd->enabled || bd->level<3 || bd->recheck_since ||
                       strcmp(bd->kind,"name") ||
                       d2k_domain_normalize(bd->target,bd_name)) continue;
                    if(!strcmp(bd_name,o->name) && !strcmp(bd->plan_id,o->plan_id) &&
                       (bd->transport?bd->transport:6)==key.transport &&
                       (bd->family?bd->family:4)==key.family &&
                       d2k_cat_shape_fits(bd->shape,key.shape) &&
                       !strcmp(group_path(key.transport,bd->probe_path),key.probe_path) &&
                       !strcmp(bd->ech_origin,key.ech_origin)) confirmed=1;
                }
                if(!confirmed) continue;
                int duplicate=0;
                for(size_t j=0;j<t->n_plans;j++)
                    if(!strcmp(t->plans[j],p->text)) duplicate=1;
                if(duplicate || t->n_plans>=sizeof t->plans/sizeof t->plans[0]) break;
                snprintf(t->plans[t->n_plans],sizeof t->plans[0],"%s",p->text);
                snprintf(t->plan_boxes[t->n_plans],sizeof t->plan_boxes[0],"%s",box->id);
                t->n_plans++;
                break;
            }
        }
    }
    if(!t->n_plans) return 0;
    t->family_fast=1; t->n_known=t->n_plans; t->researched=1;
    t->asked_shape=t->trigger_shape; t->state=T_PLANNING;
    say(s,"по %s отказ семейного обхода: сначала проверяю %zu собственных планов семейства, без нового исследования",
        t->name,t->n_plans);
    return 1;
}

static int launch_task(d2k_sched *s, task *t) {
    if(newchain_task(s,t))return 0;

    if(t->transport==6)s->tcp_admission_sequence++;
    if (t->state == T_QUEUED && s->clock_seen && s->now_ms >= t->queued_ms)
        t->report_queue_ms += s->now_ms - t->queued_ms;
    t->started_ms = s->clock_seen ? s->now_ms : 0;
    /* Новый поиск (перемер по снимку и т.п.) считает время с себя. Переход
       «свои планы → полный замер» сюда не приходит (own_first_continue зовёт
       start_search и переносит began_ms сам), поэтому переносить отсюда
       нечего: прежний флаг переноса доживал до СЛЕДУЮЩЕГО запуска и отдавал
       перемеру начало прошлого поиска (финальное ревью core, M1). */
    t->began_ms = 0;
    t->queued_ms = 0;
    if (t->stun_target) {
        stun_start(s, t);
        return t->state == T_STUN_MEASURE;
    }
    if (addr_udp(t)) {
        quic_addr_start(s, t);
        return t->state != T_FREE && t->state != T_RESTING;
    }
    if (is_voice_class(t->name, t->transport)) {
        voice_start(s, t);
        return t->state == T_VOICE_MEASURE || t->state == T_VOICE_TRIAL;
    }
    if (!t->shape_armed) {
        char err[128];
        if (t->transport == 6 && t->rx_volume_only && !t->trig_snapped &&
            fresh_trial_id(t->shape_request_id) == 0 &&
            d2k_link_arm_shape_request(s->link_fd, t->name, t->transport,
                t->family, t->shape_request_id, err, sizeof err) == 0) {
            t->shape_armed = 1;
            t->shape_request_pending = 1;
            t->shape_request_until_ms = s->now_ms + 2000;
            t->state = T_SHAPE_WAIT;
            return 1;
        }
        if (d2k_link_arm_shape_family(s->link_fd, t->name, t->transport,
                                      t->family, err, sizeof err) == 0) {
            t->shape_armed = 1;
        }
    }
    return start_search(s, t);
}

static int queued_before(const task *a, const task *b);

static int can_measure_silent_tls(const task *t) {
    return t->transport==6 && !t->by_addr && t->port && t->ip[0] &&
           t->trigger_code==D2K_SUSPECT_SILENT &&
           (t->trigger_shape==D2K_SHAPE_MODERN || t->trigger_shape==D2K_SHAPE_LEGACY ||
            t->trigger_shape==D2K_LINK_SHAPE_ECH_TCP);
}

static int make_response_queue_room(d2k_sched *s, task *incoming) {
    /* The symptom admits a measurement. Only the measurement can authorize
       a response program. Preserve the resource cap and work already done. */
    if (!preflight_family_enabled(incoming->family) || !can_measure_silent_tls(incoming)) return 0;
    task *victim=NULL;
    for (size_t i=0;i<SCHED_MAX_TASKS;i++) {
        task *waiting=&s->tasks[i];
        if (waiting==incoming || waiting->state!=T_QUEUED ||
            waiting->search_started || waiting->probes || waiting->hot_event ||
            can_measure_silent_tls(waiting) || dns_task_registered(s,waiting) ||
            force_name(s,waiting->name) || family_recovery_eligible(s,waiting)) continue;
        /* Keep the oldest waiting evidence within this class. */
        if (!victim || queued_before(victim,waiting)) victim=waiting;
    }
    if (!victim) return 0;
    say(s,"по %s очередь уступила место проверке ответа на приветствие %s",
        victim->name,incoming->name);
    search_report(s,victim,s->now_ms,"queue-replaced","none",
                  "место отдано проверке молчания после TLS-приветствия; замер не начинался");
    task_reset(s,victim);
    return 1;
}

static int launch_or_queue(d2k_sched *s, task *t) {
    if(newchain_task(s,t))return 0;

    if (!t->report_id || t->report_closed) {
        t->report_id = ++s->report_sequence;
        t->report_closed = 0;
        t->report_admitted_ms = s->clock_seen ? s->now_ms : -1;
        t->report_queue_ms = 0;
    }
    size_t active = measurements_in_flight(s);
    /* Before the first scheduler tick, model time is intentionally unknown.
       Do not stamp a start at zero and later compare it with the first real
       monotonic tick (or a test's model clock); the concurrency cap still
       bounds the initial burst. Task 38: the start pace applies to a fresh
       suspicion even while another measurement runs — a raised limit must
       not turn a traffic burst into a burst of SYN/Initial. */
    int start_gap = s->clock_seen && s->measure_start_seen &&
                    s->now_ms - s->last_measure_start_ms < SCHED_START_GAP_MS && !force_name(s,t->name);
    if (active >= s->meas_limit || start_gap) {
        if (queued_measurements(s) >= SCHED_MAX_QUEUED_MEASUREMENTS &&
            !make_response_queue_room(s,t)) {
            say(s, "по %s измерение не поставлено: ограниченная очередь заполнена; "
                   "следующий поток снова сможет поднять подозрение", t->name);
            search_report(s, t, s->now_ms, "queue-full", "none", "ограниченная очередь измерений заполнена, зондов не было");
            task_reset(s, t);
            return 0;
        }
        t->state = T_QUEUED;
        t->queued_response_priority=preflight_family_enabled(t->family) && can_measure_silent_tls(t);
        t->started_ms = 0;
        t->queued_ms = s->clock_seen ? s->now_ms : 0;
        t->queued_event = s->event_sequence;
        say(s, "по %s подозрение сохранено в ограниченной очереди замеров "
               "(%zu из %d); новые измерения ограничены до %zu одновременно",
            t->name, queued_measurements(s), SCHED_MAX_QUEUED_MEASUREMENTS,
            s->meas_limit);
        return 0;
    }
    s->last_measure_start_ms = s->now_ms;
    s->measure_start_seen = 1;
    int rc = launch_task(s, t);
    measure_started(s);
    return rc;
}

static void voice_observe(d2k_sched *s, task *t) {
    /* handle_udp сообщает EXCHANGE на ЛЮБУЮ обратную датаграмму, включая
       пустую. APPLIED связывает её с исполненным планом, но не проверяет
       ответ протокола. В отличие от STUN/QUIC-оракулов оригинала здесь нет
       ни transaction ID, ни проверки серверного Initial, ни успеха
       приложения. Не создавать коробку/привязку и не увеличивать successes.

       Владение кандидатом и срок задачи сохраняются: неподтверждённый план
       обязан сняться по общему пределу, даже когда сервер что-то прислал. */
    say(s, "по %s (%s) UDP-ответ наблюдался по потоку с приёмом; "
           "протокольный и прикладной успех не проверены — "
           "в каталог не записываю, кандидат остаётся временным",
        t->name, t->by_addr ? "QUIC по адресу" : "голос");
    t->voice_answered = 0;
}

/* Настоящий Discord IP Discovery response — единственное UDP-доказательство
 * для голосового кандидата. В отличие от общего EXCHANGE это уже проверка
 * wire-протокола, поэтому кандидат можно перевести из временного опыта в
 * постоянную привязку и коробку. */
static void voice_confirm(d2k_sched *s, task *t, int64_t now_ms) {
    if (t->n_plans == 0) { task_fail(s, t, now_ms); return; }
    const char *text = t->plans[0];
    char plan_id[40], box_id[40], wire[sizeof t->plans[0]];
    uint8_t wire_id[D2K_PLAN_ID_LEN];
    char hex[2 * D2K_PLAN_TLV_MAX + 1], err[160];
    plan_ident(text, plan_id, sizeof plan_id, wire_id);
    box_id_for(s, t, text, box_id, sizeof box_id);
    snprintf(wire, sizeof wire, "%s", text);
    err[0] = '\0';
    int is_stun = t->voice_proof_code == D2K_UDP_PROOF_STUN;
    /* Both protocol replies prove only their measured server endpoint.
       A Discovery response cannot authorize a global @discord-voice policy. */
    if (!is_stun && t->voice_proof_code != D2K_UDP_PROOF_VOICE_DISCOVERY) {
        say(s, "по %s UDP-ответ не подтверждает протокол; привязку не создаю", t->name);
        task_done(s, t);
        return;
    }
    if(t->state!=T_VOICE_INSTALL) {
    int install_rc = -1;
    if (stamp_plan_id(wire, wire_id) == 0 &&
        d2k_plan_text_to_hex(wire, hex, sizeof hex, err, sizeof err) == 0) {
        {
            uint8_t address[16] = {0};
            if ((t->family == 4 || t->family == 6) && t->port &&
                inet_pton(t->family == 6 ? AF_INET6 : AF_INET, t->ip, address) == 1) {
                if(!fresh_trial_id(t->voice_install_token))
                    install_rc = d2k_link_set_endpoint_bound(s->link_fd, address, t->family,
                        htons(t->port), D2K_LINK_SHAPE_VOICE, hex,
                        t->voice_install_token,err,sizeof err);
            } else {
                snprintf(err, sizeof err, "неизвестны семейство, адрес либо порт UDP-цели");
            }
        }
    }
    if (install_rc != 0) {
        say(s, "по %s (%s) ответ протокола валиден, но постоянный Plan не поставился: %s",
            t->name, is_stun ? "STUN" : "голос",
            err[0] ? err : "ошибка записи");
        task_fail(s, t, now_ms);
        return;
    }
    t->voice_install_acked=t->voice_install_refused=0;
    t->stun_until_ms=now_ms+SCHED_VERIFY_STEP_MS;
    t->state=T_VOICE_INSTALL;
    return;
    }
    if(!t->voice_install_acked || t->voice_install_refused)return;
    int saved=bind_confirmed(s->cat, box_id, plan_id, text,
                         is_stun ? "stun" : "voice",
                         t->ip, "service", 17, t->family, D2K_LINK_SHAPE_VOICE,
                         t->port,
                         is_stun ? D2K_VERBY_STUN : D2K_VERBY_VOICE_DISCOVERY,
                         D2K_INPUT_PROFILE,
                         /* Голос/STUN TCP-вопросов не задаёт: знания о
                            коробке этот путь не приносит. */
                         wall_s(s, now_ms), &t->fp, NULL, NULL);
    if(saved!=0) {
        say(s,"по %s UDP-план установлен, но сохранение результата в каталог не удалось",t->name);
        search_report(s,t,now_ms,"local-error",NULL,"результат UDP-опыта не сохранён в каталог");
        task_done(s,t);
        return;
    }
    if (t->addr_probe_identity_valid) {
        (void)addr_probe_remove(s, t, err, sizeof err);
    }
    snprintf(t->box_id, sizeof t->box_id, "%s", box_id);
    t->trial_installed = 0;
    t->voice_answered = 0;
    t->voice_proven = 0;
    t->voice_proof_code = 0;
    t->state = T_WATCHING;
    s->confirms++;
    s->sync_pending = 1;
    unknown_resolve(s, t->name, t->transport, t->family, t->port);
    unknown_resolve(s, t->ip, t->transport, t->family, t->port);
    say(s, "по %s (%s) ПОДТВЕРЖДЕНО протокольным ответом: %s",
        t->name, is_stun ? "STUN" : "голос", plan_id);
    search_report(s, t, now_ms, is_stun ? "stun-confirmed" : "discovery-confirmed", NULL,
                  "протокольный ответ получен под пробным планом");
}

static void voice_fail(d2k_sched *s, task *t, int64_t now_ms) {
    say(s, "по %s (%s) приём не пробил: поток с применённым приёмом остался без "
           "ответа сервера. Перебирать дальше вслепую за счёт чужого трафика не "
           "буду — снимаю приём", t->name, t->by_addr ? "QUIC по адресу" : "голос");
    task_fail(s, t, now_ms);
}

static int is_voice_class(const char *name, uint8_t transport) {
    return transport == 17 && strcmp(name, D2K_LINK_VOICE_CLASS) == 0;
}

/* Telegram control/site traffic is routed through the separately managed VPS
   tunnel. It must not become a D2K measurement target. Match the DNS label
   boundary, so unrelated names such as nottelegram.org remain eligible. */
static int is_telegram_tunnel_domain(const char *name) {
    static const char domain[] = "telegram.org";
    size_t name_len = strlen(name);
    const size_t domain_len = sizeof domain - 1;
    if (name_len == domain_len) {
        return strcasecmp(name, domain) == 0;
    }
    if (name_len <= domain_len || name[name_len - domain_len - 1] != '.') {
        return 0;
    }
    return strcasecmp(name + name_len - domain_len, domain) == 0;
}

static int clean_handshake_recent(d2k_sched *s, const char *name, uint8_t transport,
                                  uint8_t family);
static int voice_execution_matches(const task *t, const d2k_ev *ev) {
    return t->voice_execution_id && ev->execution_id == t->voice_execution_id &&
        d2k_binding_equal(&ev->execution_binding,&t->voice_execution_binding) &&
        ev->execution_binding.shape == D2K_PLAN_SHAPE_VOICE &&
        !memcmp(ev->plan_id,t->voice_execution_plan_id,D2K_PLAN_ID_LEN) &&
        !memcmp(ev->trial_id,t->voice_execution_trial_id,D2K_TRIAL_ID_LEN);
}

/* Окна опыта без протокола (этап 12). Не бюджеты поиска, а сроки наблюдения:
   повтор первого сегмента клиент шлёт по своему таймеру (секунды, с удвоением)
   и в очередь попадают только первые пакеты потока; ответ сервера на
   продолжение под планом — в пределах срока молчания датапата. */
#define SCHED_RAW_TRIAL_MS 60000
#define SCHED_RAW_WATCH_MS 8000

/* Окно измеренного опыта — из фактов замера (v27), не новый бюджет. Следующая
   точная копия ждётся в пределах одного измеренного промежутка у UDP (таймер
   приложения, политика неизвестна) и двух у TCP (откат RTO не больше чем
   удваивается, RFC 6298 §5.5); прошедшее с последней копии вычитается.
   SCHED_RAW_TRIAL_MS остаётся запасом после этой точки. Промежуток не длиннее
   окна сравнения образца, которое его измерило (у TCP с прежним запасом
   завершения наблюдения). Более длинные таймеры остаются неизвестными;
   продления не превращают отсутствие повтора в доказательство блокировки. */
static int64_t raw_trial_window_ms(const struct d2k_rawmeasure_report *r) {
    uint64_t gap=r->repeat_gap_ms,cap=((uint64_t)r->request.seconds+(r->request.tuple.proto==6?D2K_RM_GRACE_S:0))*1000u;
    if(gap>cap)gap=cap;
    uint64_t due=r->request.tuple.proto==6?2*gap:gap;
    due=due>r->repeat_age_ms?due-r->repeat_age_ms:0;
    return SCHED_RAW_TRIAL_MS+(int64_t)due;
}
static uint32_t raw_trial_lease_ms(int64_t left_ms) {
    if(left_ms<1)left_ms=1;
    return left_ms>(int64_t)D2K_ADDR_PROBE_LEASE_MAX_MS?D2K_ADDR_PROBE_LEASE_MAX_MS:(uint32_t)left_ms;
}

/* Собственное решение этого адреса на ЭТОМ транспорте: подтверждённая
   адресная привязка каталога с тем же семейством; самая свежая. Чужих
   стратегий и перебора здесь нет: нет своего решения — честный unknown.
   TCP-решение для UDP-потока (и наоборот) кандидатом не является: план
   объявлен для другого транспорта, датапат его и не применил бы. */
static const d2k_cat_plan *raw_own_plan(const d2k_sched *s, const char *ip, uint8_t transport,
                                        uint8_t family, uint16_t port, const d2k_cat_box **owner) {
    const d2k_cat_plan *best = NULL;
    int64_t newest = 0;
    if (!s->cat) return NULL;
    for (size_t bi = 0; bi < s->cat->n_boxes; bi++) {
        const d2k_cat_box *b = &s->cat->boxes[bi];
        for (size_t j = 0; j < b->n_binds; j++) {
            const d2k_cat_binding *bd = &b->binds[j];
            if (!bd->enabled || bd->level < 3 || bd->recheck_since ||
                (strcmp(bd->kind, "addr") && strcmp(bd->kind, "service")) ||
                strcmp(bd->target, ip) || (bd->transport ? bd->transport : 6) != transport ||
                (bd->family ? bd->family : 4) != family) continue;
            if(!strcmp(bd->kind,"service") && bd->server_port!=port)continue;
            for (size_t i = 0; i < b->n_plans; i++) {
                const d2k_cat_plan *p = &b->plans[i];
                if (!p->enabled || !p->text || strcmp(p->id, bd->plan_id) ||
                    strlen(p->text) >= sizeof s->tasks[0].plans[0]) continue;
                if (!best || bd->confirmed > newest) { best = p; newest = bd->confirmed; *owner = b; }
            }
        }
    }
    return best;
}

/* RAW hypotheses operate on measured repetitions in the original flow.
 * Even a catalog candidate must pass this observation and exact-byte guard;
 * bare suspicion never installs a port-only temporary plan. */
#define D2K_SCHED_RAW_MEASUREMENT 1
static int raw_measure_state(const task *t) {
    return t->state==T_RAW_MEASURE_ACK || t->state==T_RAW_MEASURE_OBSERVE || t->state==T_RAW_MEASURED;
}
static int raw_measure_start(d2k_sched *s,const d2k_ev *ev,const char *ip,uint16_t port) {
    if (!ev->flow_incarnation || !d2k_rm_nonzero(ev->flow_epoch,16) ||
        (ev->client_side!=D2K_CLIENT_SIDE_LOW && ev->client_side!=D2K_CLIENT_SIDE_HIGH)) return 0;
    struct d2k_rawmeasure_request r;memset(&r,0,sizeof r);
    r.tuple.family=ev->family;r.tuple.proto=ev->transport;
    int low=ev->client_side==D2K_CLIENT_SIDE_LOW;
    memcpy(r.tuple.src,low?ev->low_ip:ev->high_ip,16);
    memcpy(r.tuple.dst,low?ev->high_ip:ev->low_ip,16);
    uint16_t cp=low?ev->low_port:ev->high_port,sp=low?ev->high_port:ev->low_port;
    r.tuple.sport_be[0]=(uint8_t)(cp>>8);r.tuple.sport_be[1]=(uint8_t)cp;
    r.tuple.dport_be[0]=(uint8_t)(sp>>8);r.tuple.dport_be[1]=(uint8_t)sp;
    r.generation=ev->flow_incarnation;memcpy(r.epoch,ev->flow_epoch,16);
    r.seconds=SCHED_LATE_OBS_S;
    for(size_t i=0;i<SCHED_MAX_TASKS;i++) {
        task *old=&s->tasks[i];
        int active=raw_measure_state(old) || (old->raw &&
                   (old->state==T_RAW_TRIAL || old->state==T_RAW_WATCH));
        if(!active && !(old->raw && old->state==T_WATCHING))continue;
        const struct d2k_rawmeasure_request *o=&old->raw_measure_request;
        if(memcmp(&o->tuple,&r.tuple,sizeof r.tuple))continue;
        if(active && o->generation==r.generation&&!memcmp(o->epoch,r.epoch,16))return 1;
        trial_retire(s,old);
        task_done(s,old); /* Retire only this tuple's old generation or watch. */
    }
    task *t=task_free_slot(s);
    if(!t) {
        t=task_watching_slot(s);
        if(t){trial_retire(s,t);task_done(s,t);}
    }
    if(!t || fresh_trial_id(r.token)) {
        unknown_note(s,"addr",ip,ev->transport,ev->family,port,"measurement-unavailable","нет свободного контекста или идентификатора наблюдения");return 1;
    }
    char err[160];
    if(d2k_link_raw_measure(s->link_fd,&r,err,sizeof err)) {
        unknown_note(s,"addr",ip,ev->transport,ev->family,port,"measurement-unavailable",err);return 1;
    }
    task_reset(s,t);t->state=T_RAW_MEASURE_ACK;t->raw=1;t->by_addr=1;
    snprintf(t->name,sizeof t->name,"%s",ip);snprintf(t->ip,sizeof t->ip,"%s",ip);
    t->transport=ev->transport;t->family=ev->family;t->port=port;
    t->raw_measure_request=r;t->raw_until_ms=s->now_ms?s->now_ms+60000:0;
    memcpy(t->trigger_flow.a_ip,ev->low_ip,16);memcpy(t->trigger_flow.b_ip,ev->high_ip,16);
    t->trigger_flow.a_port=ev->low_port;t->trigger_flow.b_port=ev->high_port;
    t->trigger_flow.family=ev->family;t->trigger_flow.transport=ev->transport;
    say(s,"по %s:%u: измеряю настоящий поток без имени; подтверждения доставки пока нет",ip,(unsigned)port);
    return 1;
}
static int raw_late_observe(d2k_sched *s,flow_watch *w) {
    d2k_ev ev={0};ev.kind=D2K_EV_SUSPECT;ev.code=D2K_SUSPECT_LATE_SILENCE;
    ev.transport=w->transport;ev.family=w->family;ev.client_side=w->client_side;
    memcpy(ev.low_ip,w->low_ip,16);memcpy(ev.high_ip,w->high_ip,16);
    ev.low_port=w->low_port;ev.high_port=w->high_port;
    memcpy(ev.flow_epoch,w->flow_epoch,16);ev.flow_incarnation=w->flow_incarnation;
    if(!raw_measure_start(s,&ev,w->target,w->port))return 0;
    for(size_t i=0;i<SCHED_MAX_TASKS;i++) {
        task *t=&s->tasks[i];const struct d2k_rawmeasure_request *r=&t->raw_measure_request;
        if(!raw_measure_state(t) || r->generation!=w->flow_incarnation ||
           memcmp(r->epoch,w->flow_epoch,16) || memcmp(&r->tuple,&w->tuple,sizeof w->tuple))continue;
        memcpy(w->obs_token,r->token,16);w->obs_asked_ms=s->now_ms?s->now_ms:1;return 1;
    }
    return 0;
}
/* Close only the watch owning this exact observation. A reply reopens the
 * episode; inconclusive/refused observations back off until fresh activity. */
static void raw_measure_watch_done(d2k_sched *s,const task *t,int result) {
    const struct d2k_rawmeasure_request *r=&t->raw_measure_request;
    for(size_t i=0;i<SCHED_FLOWWATCH_SLOTS;i++) {
        flow_watch *w=&s->flowwatch[i];
        if(!w->used || !r->generation || w->flow_incarnation!=r->generation ||
           memcmp(w->flow_epoch,r->epoch,16) || memcmp(w->obs_token,r->token,16) ||
           memcmp(&w->tuple,&r->tuple,sizeof w->tuple))continue;
        if(result<0 && !w->obs_asked_ms && !w->escalated)continue;
        if(result<0)late_obs_negative(s,w);
        else {w->obs_asked_ms=0;if(result>0){w->escalated=0;w->obs_fails=0;}}
    }
}
static void raw_measure_cancel(d2k_sched *s,const task *t) {
    struct d2k_rawmeasure_request cancel=t->raw_measure_request;
    cancel.renew=1;cancel.seconds=0;
    char err[160];(void)d2k_link_raw_measure(s->link_fd,&cancel,err,sizeof err);
    /* A broken link is bounded by daemon peer-close cleanup or its lease. */
}
static void raw_measure_ack(d2k_sched *s,const d2k_ev *ev) {
    for(size_t i=0;i<SCHED_MAX_TASKS;i++) {
        task *t=&s->tasks[i];if((t->state!=T_RAW_MEASURE_ACK && t->state!=T_RAW_MEASURE_OBSERVE)||memcmp(t->raw_measure_request.token,ev->trial_id,16))continue;
        if(((ev->num>>8)&255)!=1) {
            unknown_note(s,"addr",t->ip,t->transport,t->family,t->port,"measurement-unavailable","наблюдение недоступно или поколение соединения сменилось");
            raw_measure_watch_done(s,t,-1);task_done(s,t);return;
        }
        if(t->state==T_RAW_MEASURE_ACK) {
            t->state=T_RAW_MEASURE_OBSERVE;
            int64_t span=(int64_t)t->raw_measure_request.seconds*1000;
            t->raw_until_ms=s->now_ms?s->now_ms+(span+(int64_t)D2K_RM_GRACE_S*1000)*(t->transport==6?2:1):0;
            t->raw_obs_lease_ms=s->now_ms?s->now_ms+span:0;
            t->raw_obs_renew_ms=s->now_ms?s->now_ms+span/2:0;
        } else if(t->state==T_RAW_MEASURE_OBSERVE && t->raw_obs_renewing) {
            int64_t span=(int64_t)t->raw_measure_request.seconds*1000;
            t->raw_obs_lease_ms=t->raw_obs_sent_ms+span;
            t->raw_obs_renew_ms=t->raw_obs_sent_ms+span/2;
            t->raw_obs_renewing=0;
        }
        return;
    }
}
/* A silent repetition is a reason to test packetization, not a DPI verdict.
 * The executor matches the exact measured bytes and live incarnation before
 * transforming a client retransmission. No synthetic application request. */
#define D2K_SCHED_RAW_CANDIDATE 1
static int raw_program_same(const char *old,const char *next) {
    char a[sizeof ((task *)0)->plans[0]],b[sizeof a],err[160];
    uint8_t x[D2K_PLAN_TLV_MAX],y[D2K_PLAN_TLV_MAX],id[16]={0};
    size_t xn=0,yn=0;
    if(strlen(old)>=sizeof a || strlen(next)>=sizeof b)return 0;
    strcpy(a,old);strcpy(b,next);
    return !stamp_plan_id(a,id) && !stamp_plan_id(b,id) &&
        !d2k_plan_text_to_tlv(a,x,sizeof x,&xn,err,sizeof err) &&
        !d2k_plan_text_to_tlv(b,y,sizeof y,&yn,err,sizeof err) &&
        xn==yn && !memcmp(x,y,xn);
}
static void raw_measured_try(d2k_sched *s,task *t) {
    if(!t || t->state!=T_RAW_MEASURED)return;
    const struct d2k_rawmeasure_report *r=&t->raw_measure_report;
    char text[sizeof t->plans[0]],wire[sizeof t->plans[0]],err[160]={0};
    char hex[2*D2K_PLAN_TLV_MAX+1],box[sizeof t->plan_boxes[0]],id[sizeof t->raw_plan_id];
    const d2k_cat_box *owner=NULL;
    const d2k_cat_plan *own=t->raw_skip_own?NULL:
        raw_own_plan(s,t->ip,t->transport,t->family,t->port,&owner);
    if(own) {
        snprintf(text,sizeof text,"%s",own->text);
        snprintf(box,sizeof box,"%s",owner->id);snprintf(id,sizeof id,"%s",own->id);
    } else if(t->transport==6 && r->sample_len>=2) {
        unsigned cut=r->sample_len/2;
        snprintf(text,sizeof text,"d2k-plan 1 1\nid 00000000000000000000000000000000\nproto tcp tls\nsplit payload_start +%u\norder forward\n",cut);
        snprintf(box,sizeof box,"raw-packetization");snprintf(id,sizeof id,"raw-split-%u",cut);
    } else if(t->transport==17 && r->sample_len && (r->flags & D2K_RM_PRIOR_REPLY)) {
        snprintf(text,sizeof text,"d2k-plan 1 7\nid 00000000000000000000000000000000\nproto udp quic\nipfrag 1\n");
        snprintf(box,sizeof box,"raw-packetization");snprintf(id,sizeof id,"raw-udp-fragment");
    } else {
        unknown_note(s,"addr",t->ip,t->transport,t->family,t->port,"measurement-no-hypothesis",
                     "измеренная геометрия не позволяет этот опыт изменения разбиения; причина молчания неизвестна");
        raw_measure_watch_done(s,t,-1);task_done(s,t);return;
    }
    if(t->raw_skip_own && r->sample_seq==t->raw_previous_seq &&
       r->sample_len==t->raw_previous_len &&
       !memcmp(r->sample_digest,t->raw_previous_digest,sizeof t->raw_previous_digest) &&
       raw_program_same(t->plans[0],text)) {
        unknown_note(s,"addr",t->ip,t->transport,t->family,t->port,"measurement-no-new-hypothesis",
            "план из измеренной геометрии уже исполнен без ответа; новых различающих данных нет");
        raw_measure_watch_done(s,t,-1);task_done(s,t);return;
    }
    snprintf(wire,sizeof wire,"%s",text);
    const int64_t window=raw_trial_window_ms(r);const uint32_t lease=raw_trial_lease_ms(window);
    if(fresh_trial_id(t->ver_plan_id) || fresh_trial_id(t->addr_probe_trial_id) ||
       stamp_plan_id(wire,t->ver_plan_id) || d2k_plan_text_to_hex(wire,hex,sizeof hex,err,sizeof err) ||
       d2k_link_set_raw_probe(s->link_fd,r,t->addr_probe_trial_id,lease,hex,err,sizeof err)) {
        unknown_note(s,"addr",t->ip,t->transport,t->family,t->port,"candidate-unavailable",
                     err[0]?err:"не удалось собрать идентичность измеренного опыта");
        raw_measure_watch_done(s,t,-1);task_done(s,t);return;
    }
    memcpy(t->addr_probe_src_ip,r->request.tuple.src,16);memcpy(t->addr_probe_dst_ip,r->request.tuple.dst,16);
    memcpy(&t->addr_probe_src_port_be,r->request.tuple.sport_be,2);
    memcpy(&t->addr_probe_dst_port_be,r->request.tuple.dport_be,2);
    memcpy(t->trial_ack_id,t->addr_probe_trial_id,16);
    t->addr_probe_identity_valid=1;t->trial_installed=1;t->trial_shape=D2K_LINK_SHAPE_RAW;
    t->trial_acked=0;t->raw_execution_id=0;t->raw_early_reply_execution=0;
    t->raw_own_candidate=own!=NULL;
    t->probe_sport_be=t->addr_probe_src_port_be;t->probe_fd=-1;
    memcpy(t->plans[0],text,strlen(text)+1);memcpy(t->plan_boxes[0],box,strlen(box)+1);
    memcpy(t->raw_plan_id,id,strlen(id)+1);
    snprintf(t->raw_proto,sizeof t->raw_proto,"%s",t->transport==6?"tls":"quic");
    t->n_plans=1;t->next_plan=1;t->state=T_RAW_TRIAL;t->raw_until_ms=0;
    t->raw_trial_window_ms=window;t->raw_lease_ms=lease;t->raw_renewing=0;
    /* Окно и аренда — от одних часов: иначе окно на такт длиннее аренды. */
    t->raw_lease_until_ms=s->now_ms?s->now_ms+lease:0;t->raw_until_ms=s->now_ms?s->now_ms+window:0;
    say(s,"по %s:%u: проверяю %s на измеренном повторе того же соединения; установка не доказывает исполнение или успех приложения",
        t->ip,(unsigned)t->port,id);
    if(window>SCHED_RAW_TRIAL_MS)
        say(s,"по %s:%u: повтор измерен через %u мс — жду следующего до %lld с, датапату срок частями до %u с",
            t->ip,(unsigned)t->port,(unsigned)r->repeat_gap_ms,(long long)(window/1000),
            (unsigned)(D2K_ADDR_PROBE_LEASE_MAX_MS/1000));
}
/* Продление аренды того же измеренного опыта: тот же отчёт замера, тот же
   trial, тот же план (заново проштампованный тем же id). Датапат примет только
   совпадающее (d2k_plantab_set_measured_probe) и проверит, что поток и его
   поколение живы. */
static void raw_trial_end_unknown(d2k_sched *s,task *t,const char *reason,const char *why) {
    say(s,"по %s:%u (поток без протокола) опыт снят: %s — исход неизвестен",t->ip,(unsigned)t->port,why);
    unknown_note(s,"addr",t->ip,t->transport,t->family,t->port,reason,why);
    raw_measure_watch_done(s,t,-1);trial_retire(s,t);task_done(s,t);
}
static void raw_measure_again(d2k_sched *s,task *t) {
    struct d2k_rawmeasure_request next=t->raw_measure_request;
    char err[160]={0};
    t->raw_previous_seq=t->raw_measure_report.sample_seq;
    t->raw_previous_len=t->raw_measure_report.sample_len;
    memcpy(t->raw_previous_digest,t->raw_measure_report.sample_digest,sizeof t->raw_previous_digest);
    /* A partial ACK can shrink the client's next retransmission. Never
       carry the old byte range/digest into the next constructed candidate. */
    raw_measure_cancel(s,t);
    if(fresh_trial_id(next.token) || d2k_link_raw_measure(s->link_fd,&next,err,sizeof err)) {
        raw_trial_end_unknown(s,t,"measurement-unavailable",
            err[0]?err:"не удалось начать уточнение замера текущего потока");return;
    }
    for(size_t i=0;i<SCHED_FLOWWATCH_SLOTS;i++) {
        flow_watch *w=&s->flowwatch[i];
        if(w->used && w->flow_incarnation==next.generation &&
           !memcmp(w->flow_epoch,next.epoch,16) &&
           !memcmp(&w->tuple,&next.tuple,sizeof next.tuple) &&
           !memcmp(w->obs_token,t->raw_measure_request.token,16)) {
            memcpy(w->obs_token,next.token,16);w->obs_asked_ms=s->now_ms?s->now_ms:1;
        }
    }
    t->raw_measure_request=next;t->state=T_RAW_MEASURE_ACK;
    memset(&t->raw_measure_report,0,sizeof t->raw_measure_report);
    t->raw_obs_renewing=0;t->raw_obs_lease_ms=0;t->raw_obs_renew_ms=0;
    t->raw_until_ms=s->now_ms?s->now_ms+60000:0;
}
static void raw_trial_renew(d2k_sched *s,task *t,int64_t now_ms) {
    char wire[sizeof t->plans[0]],hex[2*D2K_PLAN_TLV_MAX+1],err[160]={0};
    const uint32_t lease=raw_trial_lease_ms(t->raw_until_ms-now_ms);
    snprintf(wire,sizeof wire,"%s",t->plans[0]);
    if(stamp_plan_id(wire,t->ver_plan_id) || d2k_plan_text_to_hex(wire,hex,sizeof hex,err,sizeof err) ||
       d2k_link_set_raw_probe(s->link_fd,&t->raw_measure_report,t->addr_probe_trial_id,lease,hex,err,sizeof err)) {
        raw_trial_end_unknown(s,t,"candidate-unavailable",err[0]?err:"продление измеренного опыта не отправилось");
        return;
    }
    t->raw_renewing=1;t->raw_renew_sent_ms=now_ms;t->raw_renew_lease_ms=lease;
}

static void raw_measure_result(d2k_sched *s,const d2k_ev *ev) {
    const struct d2k_rawmeasure_report *r=&ev->raw_measure;
    if(!d2k_rawmeasure_report_valid(r))return;
    for(size_t i=0;i<SCHED_MAX_TASKS;i++) {
        task *t=&s->tasks[i];if(t->state!=T_RAW_MEASURE_OBSERVE)continue;
        const struct d2k_rawmeasure_request *q=&t->raw_measure_request;
        if(memcmp(q->token,r->request.token,16)||memcmp(q->epoch,r->request.epoch,16)||
           q->generation!=r->request.generation||q->seconds!=r->request.seconds||
           memcmp(&q->tuple,&r->request.tuple,sizeof q->tuple))continue;
        t->raw_measure_report=*r;
        raw_measure_watch_done(s,t,r->code==D2K_RM_SERVER_PRESENT?1:r->code==D2K_RM_REPEAT_SILENT?0:-1);
        if(r->code==D2K_RM_REPEAT_SILENT) {t->state=T_RAW_MEASURED;t->raw_until_ms=0;return;}
        if(r->code==D2K_RM_UNINFORMATIVE && r->request.tuple.proto==17 &&
           r->exact_repeats && !(r->flags & D2K_RM_PRIOR_REPLY))
            unknown_note(s,"addr",t->ip,t->transport,t->family,t->port,"reply-unknown",
                         "повтор UDP-датаграммы наблюдался, но неизвестно, ожидает ли приложение ответ; блокировка не доказана, опыт не ставился");
        else if(r->code!=D2K_RM_SERVER_PRESENT)
            unknown_note(s,"addr",t->ip,t->transport,t->family,t->port,"measure-inconclusive","наблюдение не подтвердило повтор неизменных данных без ответа");
        task_done(s,t);return; /* Reply is presence, never application success. */
    }
}

static void raw_suspect(d2k_sched *s, const d2k_ev *ev) {
    const uint8_t tr = ev->transport == 17 ? 17 : 6;
    const char *trname = tr == 17 ? "UDP" : "TCP";
    char ip[INET6_ADDRSTRLEN] = "";
    uint16_t sport = 0;
    if (tr == 17 && ev->client_side != D2K_CLIENT_SIDE_LOW && ev->client_side != D2K_CLIENT_SIDE_HIGH) {
        /* У UDP нет SYN: кто клиент, знает только датапат по первой датаграмме.
           Без этого 5-tuple пробы не собрать — не угадываем. */
        say_quiet(s, "raw-udp-dir", "UDP без распознанного протокола молчит, но направление потока "
                  "не наблюдалось — точную пробу ставить не на что, остаётся неизвестным");
        char ends[2 * INET6_ADDRSTRLEN + 16];
        flow_ends(ev, ends, sizeof ends);
        unknown_note(s, "flow", ends, tr, ev->family, 0, "direction-unknown",
                     "UDP без распознанного протокола молчит; направление потока не наблюдалось");
        return;
    }
    server_of(ev, ip, sizeof ip, &sport);
    uint8_t family = ev->family ? ev->family : 4;
    if (ev->code == D2K_SUSPECT_RST) {
        /* СБРОС ПОТОКА БЕЗ ПРОТОКОЛА (этап 32) — диагностический факт, не
           замер. Опыт на продолжении клиента здесь невозможен: сброшенный
           поток не продолжится, а новый поток — уже другой опыт; зонда для
           неизвестного протокола нет. Закрытый порт сбрасывает так же, поэтому
           блоком это не называется; TTL сброса против TTL ответа сервера —
           лишь примета для человека. */
        char why[512];
        if (ev->ref_ttl && ev->ttl != ev->ref_ttl)
            snprintf(why, sizeof why, "соединение сброшено в ответ на первый сегмент; TTL сброса %u, "
                     "у ответа сервера %u — сброс пришёл не тем путём, что ответ (примета, не вывод)",
                     (unsigned)ev->ttl, (unsigned)ev->ref_ttl);
        else if (ev->ref_ttl)
            snprintf(why, sizeof why, "соединение сброшено в ответ на первый сегмент; TTL сброса %u "
                     "совпадает с ответом сервера — так закрывает и сам сервер (порт закрыт/отказ)",
                     (unsigned)ev->ttl);
        else
            snprintf(why, sizeof why, "соединение сброшено в ответ на первый сегмент; ответа сервера "
                     "до сброса не было — сравнить TTL не с чем (TTL сброса %u)", (unsigned)ev->ttl);
        char qk[300]; snprintf(qk, sizeof qk, "raw-rst %s:%u", ip, (unsigned)sport);
        say_quiet(s, qk, "%s без распознанного протокола к %s:%u: %s; замер не запускаю — "
                  "это факт для диагностики, не блок", trname, ip, (unsigned)sport, why);
        unknown_note(s, "addr", ip, tr, family, sport, "rst-no-protocol", why);
        return;
    }
    /* Опыт на продолжении клиента — только для молчания: клиент ждёт и
       повторит. Иных кодов датапат для потока без протокола не шлёт; пришёл бы
       — опыт не ставится вслепую. */
    if (ev->code != D2K_SUSPECT_SILENT) return;
    int64_t left = 0;char cooldown_key[64];
    raw_cooldown_key(cooldown_key,sizeof cooldown_key,ev->flow_epoch,ev->flow_incarnation);
    if (cooldown_blocks(s, cooldown_key, tr, family, ev->code, &left)) {
        char qk[300]; snprintf(qk, sizeof qk, "raw-rest %s/%u", ip, (unsigned)tr);
        say_quiet(s, qk, "по %s (поток без протокола, %s) опыт отложен ещё примерно %lld мин",
                  ip, trname, (long long)((left + 59999) / 60000));
        return;
    }
    if(raw_measure_start(s,ev,ip,sport))return;
    {
        char qk[300]; snprintf(qk, sizeof qk, "raw-unidentified %s:%u/%u", ip, (unsigned)sport, (unsigned)tr);
        say_quiet(s, qk, "%s без распознанного протокола к %s:%u молчит (клиент повторяет): "
                  "нет идентичности текущего соединения (транспорт %s) — "
                  "точный опыт поставить нельзя, остаётся неизвестным", trname, ip, (unsigned)sport, trname);
        /* ФАКТЫ ПУТИ В ИСХОДНОМ КОНТЕКСТЕ (этап 38) — без зонда, опыта и
           выдуманного протокола. Из самого подозрения: у TCP оно возможно лишь
           при видимом SYN-ACK — соединение установлено, на первый сегмент
           данных нет; у UDP от сервера не пришло ничего. Из conntrack (только
           чтение): виден ли ответ сервера ДРУГИМ потокам за время жизни их
           записей (не «сейчас»: счётчики накоплены, давности не показывают);
           соседи без счётчиков не судятся. Повтор той же цели в пределах
           минуты — прежний подсчёт. */
        int peers = -1, peers_judged = -1, peers_answered = -1;
        unknown_target *prev = NULL;
        for (size_t i = 0; i < SCHED_UNKNOWN_SLOTS && !prev; i++) {
            unknown_target *c = &s->unknowns[i];
            if (c->used && c->transport == tr && c->family == family && c->port == sport && !strcmp(c->target, ip))
                prev = c;
        }
        if (prev && prev->peers >= 0 && s->now_ms - prev->peers_ms < 60000) {
            peers = prev->peers; peers_judged = prev->peers_judged; peers_answered = prev->peers_answered;
        } else if (s->ct_peers) {
            char low[INET6_ADDRSTRLEN] = "";
            (void)inet_ntop(family == 6 ? AF_INET6 : AF_INET, ev->low_ip, low, sizeof low);
            int srv_low = ev->low_port == sport && !strcmp(low, ip);
            d2k_ct_tuple self;
            memset(&self, 0, sizeof self);
            self.family = family;
            self.proto = tr;
            memcpy(self.src, srv_low ? ev->high_ip : ev->low_ip, family == 6 ? 16 : 4);
            memcpy(self.dst, srv_low ? ev->low_ip : ev->high_ip, family == 6 ? 16 : 4);
            uint16_t cp = srv_low ? ev->high_port : ev->low_port;
            self.sport_be[0] = (uint8_t)(cp >> 8); self.sport_be[1] = (uint8_t)cp;
            self.dport_be[0] = (uint8_t)(sport >> 8); self.dport_be[1] = (uint8_t)sport;
            unsigned f = 0, j = 0, a = 0;
            if (s->ct_peers(&self, &f, &j, &a) == 0) {
                peers = (int)f;
                peers_judged = (int)j;
                /* Счётчиков нет ни у одного соседа (учёт выключен) — ответ не
                   виден, а не «ответа нет». */
                peers_answered = j ? (int)a : -1;
            }
        }
        char peer_txt[384] = "", nocnt[64] = "";
        if (peers > peers_judged && peers_judged > 0)
            snprintf(nocnt, sizeof nocnt, "; у %d счётчиков нет", peers - peers_judged);
        if (peers > 0 && peers_answered < 0)
            snprintf(peer_txt, sizeof peer_txt, "; других потоков к этому адресу %d, но ответы по ним не видны "
                     "(у записей conntrack нет счётчиков)", peers);
        else if (peers > 0 && peers_answered > 0)
            snprintf(peer_txt, sizeof peer_txt, "; у других потоков к этому адресу ответ сервера виден за время "
                     "жизни их записей conntrack (%d из %d со счётчиками) — давность ответа счётчики не "
                     "показывают%s", peers_answered, peers_judged, nocnt);
        else if (peers > 0)
            snprintf(peer_txt, sizeof peer_txt, "; у %d из %d других потоков к этому адресу ответ сервера за время "
                     "жизни их записей conntrack не доказан%s", peers_judged, peers, nocnt);
        else if (peers == 0)
            snprintf(peer_txt, sizeof peer_txt, "; других потоков к этому адресу сейчас нет — сравнить не с чем");
        char why[768];
        snprintf(why, sizeof why, "%s без распознанного протокола: %s, клиент повторяет%s; точного "
                 "опыта без идентичности соединения поставить нельзя", trname,
                 tr == 6 ? "соединение установлено, на первый сегмент данных нет" : "от сервера не пришло ничего",
                 peer_txt);
        unknown_note(s, "addr", ip, tr, family, sport, "flow-unidentified", why);
        for (size_t i = 0; i < SCHED_UNKNOWN_SLOTS; i++) {
            unknown_target *c = &s->unknowns[i];
            if (c->used && c->transport == tr && c->family == family && c->port == sport && !strcmp(c->target, ip)) {
                if (peers >= 0 && (!prev || prev->peers < 0 || s->now_ms - prev->peers_ms >= 60000)) c->peers_ms = s->now_ms;
                c->peers = peers; c->peers_judged = peers_judged; c->peers_answered = peers_answered;
                break;
            }
        }
        return;
    }
}

static void raw_confirm(d2k_sched *s, task *t, int64_t now_ms) {
    raw_measure_watch_done(s,t,1);
    trial_retire(s, t);
    (void)bind_confirmed(s->cat, t->plan_boxes[0], t->raw_plan_id, t->plans[0],
                         t->raw_proto[0] ? t->raw_proto : (t->transport == 17 ? "quic" : "tls"),
                         t->ip, "service", t->transport, t->family,
                         D2K_LINK_SHAPE_RAW, t->port, D2K_VERBY_CLIENT, D2K_INPUT_CLIENT,
                         wall_s(s, now_ms), NULL, NULL, NULL);
    {   /* обе строки лежат в одной задаче: gcc считает это перекрытием
           restrict-аргументов snprintf — копия через локальный буфер */
        char box[sizeof t->box_id];
        snprintf(box, sizeof box, "%s", t->plan_boxes[0]);
        memcpy(t->box_id, box, sizeof box);
    }
    t->state = T_WATCHING;
    s->confirms++;
    s->sync_pending = 1;
    unknown_resolve(s, t->ip, t->transport, t->family, t->port);
    say(s, "по %s:%u (поток без протокола) ПОДТВЕРЖДЕНО продолжением клиента: сервер ответил на повтор "
           "под планом %s — доказан путь; протокол и приложение не измерены (форма RAW, по адресу и порту, %s)",
        t->ip, (unsigned)t->port, t->raw_plan_id, t->transport == 17 ? "UDP" : "TCP");
    search_report(s, t, now_ms, "raw-path-confirmed", NULL,
                  "сервер ответил на повтор клиента под планом; приложение не измерено");
}

/* found/noname — имя потока и «TLS без имени»: у событий датапата из кольца
   приветствий (on_suspect), у поздней тишины — из записи наблюдения, которая
   живёт дольше кольца (этап 49). */
/* Client suspicion never starts configured DNS recovery. The router journal
   starts that work, including for a flow with no observable TLS name. */
static int force_doh_suspect(d2k_sched *s,const d2k_ev *ev,const char *name) {
    if(ev->transport!=6)return 0;
    char ip[INET6_ADDRSTRLEN];uint16_t port;server_of(ev,ip,sizeof ip,&port);
    for(size_t i=0;i<s->n_doh;i++) {
        const doh_target *d=&s->doh[i];
        if(d->port==port && (name && name[0] ? !strcasecmp(name,d->host) :
            d->ip[0] && !strcmp(ip,d->ip)))return 1;
    }
    if(!s->n_force)return 0;
    for(size_t i=0;i<SCHED_MAX_TASKS;i++) {
        task *t=&s->tasks[i];
        if(t->state==T_FREE || t->transport!=6 || !force_name(s,t->name) ||
           t->family!=(ev->family?ev->family:4) || t->port!=port || strcmp(t->ip,ip) ||
           (name && name[0] && strcasecmp(name,t->name)))continue;
        /* A queued/active endpoint already owns this work. Falling through
           would select a different address's watcher by name. */
        if(t->state!=T_WATCHING)return 1;
        if(!encrypted_dns_task(t))continue;
        /* Configured DNS recovery is initiated by the router journal only. */
        return 1;
    }
    return 0;
}

static int on_suspect_as(d2k_sched *s, const d2k_ev *ev, const char *found, int noname) {
    /* Имя копируется СРАЗУ, а не держится указателем в кольцо имён: и потому
       что кольцо переживает вытеснение (следующее приветствие может занять
       ту же ячейку), и потому что источник с приёмником лежат внутри одного
       и того же d2k_sched — gcc справедливо ловит это как перекрытие
       restrict-аргументов snprintf. */
    char name[256];
    name[0] = '\0';
    if (found) {
        size_t n = strlen(found);
        if (n >= sizeof name) { n = sizeof name - 1; }
        memcpy(name, found, n);
        name[n] = '\0';
    }
    /* Opt-in observation only; use the observed protocol, including the
       remembered greeting when a later suspicion has no shape field. */
    shadow_flow_state *shadow_client=shadow_flow(s,ev);
    if(shadow_client)shadow_client->signal=1;
    uint8_t shadow_shape=ev->client_shape;
    if(!shadow_shape && shadow_client)shadow_shape=shadow_client->client_shape;
    if(s->shadow.path[0] && shadow_client && !shadow_client->snapshot_queued && shadow_client->name[0] && ev->transport==6 && ev->code &&
       (shadow_shape==D2K_SHAPE_MODERN || shadow_shape==D2K_SHAPE_LEGACY || shadow_shape==D2K_LINK_SHAPE_ECH_TCP)) {
        d2k_shadow_record record={.time=(uint64_t)time(NULL),
            .family=ev->family?ev->family:4,.signal=ev->code,
            .protocol=shadow_shape==D2K_SHAPE_LEGACY?1:2};
        size_t length=strlen(shadow_client->name);
        if(length<sizeof record.host && !shadow_server(shadow_client,ev,&record)) {
            memcpy(record.host,shadow_client->name,length+1);
            record.form_key=shadow_client->form_key;
            doh_target *owner_doh=doh_find(s,record.host);
            record.priority=owner_doh || force_name(s,record.host)?2:record.degradation?1:0;
            if(owner_doh)snprintf(record.doh_path,sizeof record.doh_path,"%s",owner_doh->path);
            for(size_t i=0;i<s->shadow_recent.count;i++) {
                const d2k_shadow_record *h=&s->shadow_recent.entries[i];
                if(h->port==record.port && !strcmp(h->ip,record.ip) && h->time<=record.time &&
                   record.time-h->time<=D2K_SHADOW_HOUR && h->time>record.history_time) {
                    record.history_time=h->time;strcpy(record.history_name,h->host);
                }
            }
            int protected=d2k_newchain_protects(&s->newchain,record.host,6,record.family,shadow_shape);
            int exact=d2k_newchain_signal(&s->newchain,record.host,ev,&record);
            if(record.degradation && !record.priority)record.priority=1;
            record.clean_source=shadow_source(shadow_client);
            int clean=ev->planned==D2K_LINK_PLANNED_NO &&
                d2k_shadow_recent_clean(&s->shadow_recent,&record,record.time);
            if(clean)say(s,"тень: подозрение %s form=%016llx не создаёт задачу: независимый чистый обмен того же контекста (§4.2); не DIRECT_OK",
                record.host,(unsigned long long)record.form_key);
            int queued=0;
            if(!clean && (!protected || exact || ev->planned==D2K_LINK_PLANNED_NO)) {
                queued=shadow_submit(s,shadow_client,&record);
            }
            if(queued==1 && shadow_client) {
                shadow_client->snapshot_queued=1;
                shadow_client->snapshot=0; /* ownership to consumer */
            }
            if(queued<0 &&
               (s->shadow.dropped==1 || !(s->shadow.dropped&(s->shadow.dropped-1))))
                say(s,"тень: потеря подозрения в очереди, всего %llu",
                    (unsigned long long)s->shadow.dropped);
        }
    }
    if(s->synthesis_only)return 0;
    /* Подозрение о потоке под исполненным планом — к этому плану (этап 36),
       до любых ветвлений: и по имени, и по адресу. */
    plan_obs_note(s, ev, name[0] ? name : NULL, 0);
    if(d2k_newchain_protects(&s->newchain,name,ev->transport,ev->family?ev->family:4,shadow_shape))return 0;
    if(force_doh_suspect(s,ev,name))return 0;
    /* Имени нет: UDP (QUIC/голос) — всегда цель по адресу; TCP — только
       если датапат видел TLS-приветствие без SNI на этом потоке (этап 11):
       поток без приветствия вовсе остаётся неизвестным. */
    /* UDP без распознанного протокола (форма RAW, этап 16) — не QUIC по адресу:
       замер и опыт идут на настоящем продолжении клиента (raw_suspect). */
    if (name[0] == '\0' && ev->transport == 17 && ev->client_shape == D2K_LINK_SHAPE_RAW) {
        raw_suspect(s, ev);
        return 0;
    }
    int by_addr = name[0] == '\0' &&
                  (ev->transport == 17 || (ev->transport == 6 && noname));
    int stun_target = by_addr && ev->client_shape == D2K_LINK_SHAPE_VOICE;
    if (stun_target && ev->client_side != D2K_CLIENT_SIDE_LOW &&
        ev->client_side != D2K_CLIENT_SIDE_HIGH) {
        say(s, "STUN: направление потока не наблюдалось — адрес цели не угадываю, замер не запускаю");
        char ends[2 * INET6_ADDRSTRLEN + 16];
        flow_ends(ev, ends, sizeof ends);
        unknown_note(s, "flow", ends, ev->transport, ev->family, 0, "direction-unknown",
                     "STUN без ответа; направление потока не наблюдалось — адрес цели не угадывается");
        return 0;
    }
    if (by_addr) {
        /* ИМЕНИ НЕТ, НО ЕСТЬ АДРЕС. У QUIC приветствие настоящего клиента
           разбросано по датаграммам, и имя из него не читает никто — ни мы,
           ни коробка (поле 19.09.2026). Раньше такое подозрение выбрасывалось
           («искать не по чему»), и обход QUIC не заводился вовсе. */
        uint16_t sport = 0;
        server_of(ev, name, sizeof name, &sport);
        if (stun_target) {
            char endpoint[INET6_ADDRSTRLEN];
            snprintf(endpoint, sizeof endpoint, "%s", name);
            /* Internal task key only: never sent as a DNS name or SNI. */
            snprintf(name, sizeof name, "stun/[%s]:%u", endpoint, (unsigned)sport);
        }
        /* Дальше — общий жизненный цикл. Ранний return при найденной
           адресной задаче терял и молчание опыта, и деградацию WATCHING. */
    }
    if (name[0] == '\0') {
        /* Имени нет — искать не по чему. Это не отказ: датапат подозревает
           поток, а не имя, и поток без приветствия (или с приветствием, уже
           вытесненным из кольца) законно бывает. Поток без распознанного
           протокола (форма RAW, этап 12) получает опыт по адресу — только из
           собственных решений этого адреса и только на продолжении клиента. */
        if (ev->client_shape == D2K_LINK_SHAPE_RAW) { raw_suspect(s, ev); }
        return 0;
    }
    if (is_telegram_tunnel_domain(name)) {
        say(s, "по %s замер не запускаю: домен обслуживается Telegram VPS-туннелем",
            name);
        return 0;
    }

    if (!strcasecmp(name, SCHED_DECOY)) {
        /* СВОЯ ПРИМАНКА — НЕ ЦЕЛЬ. Её выбирают как имя, которое проходит;
           приветствие с ней — фальшивка или контроль D2K (наш или второго
           D2K за роутером, поле 14.10.2026), а не сайт человека. Поиск по
           ней искал обход своей же приманки по адресам чужих целей. */
        say_quiet(s, "decoy", "по %s замер не запускаю: это имя-приманка D2K, а не цель",
                  name);
        return 0;
    }
    /* ИМЯ ЗАВЕРШИЛО РУКОПОЖАТИЕ БЕЗ ПЛАНА — НЕ БЛОК НА РУКОПОЖАТИИ (поле
       15.10.2026, медиа VK: сервер сам сбрасывает лишние соединения, а
       рядом те же имена завершают обмен без нашего плана). Гасим только
       подозрения уровня рукопожатия (RST/повтор/молчание) и только если сам
       поток подозрения шёл без плана: деградация подтверждённой цели (план
       применён) и обрыв объёма/позднее закрытие сюда не попадают. */
    if (ev->transport == 6 && !doh_find(s,name) && !force_name(s,name) && ev->planned != D2K_LINK_PLANNED_YES &&
        (ev->code == D2K_SUSPECT_RST || ev->code == D2K_SUSPECT_REPEAT ||
         ev->code == D2K_SUSPECT_SILENT) &&
        clean_handshake_recent(s, name, 6, ev->family ? ev->family : 4)) {
        char quiet_key[300];
        snprintf(quiet_key, sizeof quiet_key, "clean-hs %s", name);
        say_quiet(s, quiet_key,
            "по %s замер не запускаю: имя только что завершило рукопожатие без обхода "
            "— сброс на другом соединении не блок", name);
        return 0;
    }
    int64_t cooldown_left_ms = 0;
    if (ev->transport == 6) {
        /* Мёртвый адрес мёртв для любого симптома; другие адреса имени — своё
           наблюдение (задача 54). */
        char srv[INET6_ADDRSTRLEN];
        uint16_t srv_port = 0;
        server_of(ev, srv, sizeof srv, &srv_port);
        dead_address *d = dead_find(s, name, ev->transport, ev->family, srv);
        if (d && !doh_find(s,name) && !force_name(s,name) && s->now_ms < d->until_ms) {
            char quiet_key[300];
            snprintf(quiet_key, sizeof quiet_key, "dead %s %s", name, srv);
            say_quiet(s, quiet_key, "по %s (TCP) замер отложен после блока адреса %s ещё примерно %lld мин",
                name, srv, (long long)((d->until_ms - s->now_ms + 59999) / 60000));
            return 0;
        }
    }
    if (cooldown_blocks(s, name, ev->transport, ev->family, ev->code, &cooldown_left_ms)) {
        target_cooldown *cool = cooldown_find(s, name, ev->transport, ev->family);
        const char *reason = cool && cool->denied ? "юридического отказа сервиса" :
                             cool && cool->challenge ? "антибот-ответа" :
                             cool && cool->exhausted ? "неподтверждённого прошлого замера" :
                             "повторного CLEAR";
        /* Транспорт — часть ключа отдыха и называется вслух: поле 03.10,
           Discord — отдых QUIC-повторов приложения читался как отложенный
           TCP-поиск того же имени, который на деле шёл своим ходом. */
        char quiet_key[300];
        snprintf(quiet_key, sizeof quiet_key, "rest %u %s %s", ev->transport, name, reason);
        say_quiet(s, quiet_key, "по %s (%s) замер отложен после %s ещё примерно %lld мин",
            name, stun_target ? "STUN" : ev->transport == 17 ? "QUIC" : "TCP", reason,
            (long long)((cooldown_left_ms + 59999) / 60000));
        return 0;
    }
    task *t = task_of(s, name, ev->transport, ev->family);
    if(force_name(s,name)) {
        char ip[INET6_ADDRSTRLEN];uint16_t port;server_of(ev,ip,sizeof ip,&port);
        t=NULL;
        for(size_t i=0;i<SCHED_MAX_TASKS;i++) {
            task *candidate=&s->tasks[i];
            if(candidate->state!=T_FREE && candidate->transport==ev->transport &&
               candidate->family==(ev->family?ev->family:4) && candidate->port==port &&
               !strcasecmp(candidate->name,name) && !strcmp(candidate->ip,ip)) {t=candidate;break;}
        }
    }
    int ordinary_tcp_rst = ev->transport == 6 && ev->code == D2K_SUSPECT_RST;
    const int late_app_rst = is_late_volume_suspicion(ev->code);
    if (t && t->state == T_VOICE_TRIAL && voice_trial_owned(t) &&
        is_voice_class(t->name, t->transport) && !voice_trial_same_context(t, ev)) {
        /* ОПЫТ ЖДЁТ РАЗГОВОРА К ДРУГОЙ ТОЧКЕ (финальное ревью, п.1). Задача
           голоса одна на класс, и раньше подозрение к новой точке сервера
           молча терялось на всё время ожидания (до 10 мин) — голос замирал.
           Ждущий опыт снимается точно (свой trial ID, кандидат не судим), и
           новая точка получает свой замер. Подозрение к той же точке и тому
           же клиенту ниже по-прежнему не дублирует замер. */
        char srv[INET6_ADDRSTRLEN];
        uint16_t sport = 0;
        server_of(ev, srv, sizeof srv, &sport);
        say(s, "по %s (голос) подозрение к другой точке %s:%u, пока опыт ждал "
               "разговора — снимаю ждущий опыт (не проверено, кандидат не судим) "
               "и меряю новую точку", t->name, srv, (unsigned)sport);
        trial_retire(s, t);
        task_done(s, t);
        t = NULL;
    }
    if (t && t->state == T_VOICE_WATCH && ev_matches_flow(ev, &t->voice_flow)) {
        /* Поток разговора, к которому применился приём, остался без ответа —
           решает тик (записи и снятию нужны часы). */
        if (voice_execution_matches(t,ev)) t->voice_silent = 1;
        return 0;
    }
    /* Повтор FIN без ответа на потоке БЕЗ плана (задача 50: глухой обрыв
       ответа без RST/FIN, поле 03.10) — такой же низкоуверенный сигнал
       позднего закрытия, как поздний RST, и с той же повторяемостью: второй
       по независимому потоку в окне. Повтор FIN под планом (05e24fa) по-
       прежнему меряется сразу: его датапат шлёт только о потоке, к которому
       применён собственный план. */
    /* «TCP встал на бюджете» (задача 56) порога второго потока НЕ ждёт — как
       QUIC-обрыв (задача 50): Safari держит одно соединение HTTP/2 на источник,
       и второй вставший поток имени в 30 с не появляется. Замер 04.10 на
       роутере (отчёт задачи 56): 4 подозрения за 9 минут живого браузинга,
       все — обрывы (mailsuite на AWS, Hetzner 178.104.16.59 дважды с
       разницей 41 с, Cloudflare), сервер ни разу не ответил даже на закрытие;
       порог по второму потоку не пропустил бы ни одного. Сигнал у него того
       же рода, что повтор FIN в тишину: клиент говорит, сервер глух (датапат
       требует трёх пакетов клиента без ответа), плюс полоса бюджета. Ворота —
       сама RX-пара identity/gzip: подбор только после воспроизведённого
       обрыва на бюджете, неподтверждённая пара — отдых позднего закрытия. */
    if (ev->code == D2K_SUSPECT_TCP_STALL && ev->transport == 6 &&
        !tcp_stall_in_name_band(s, name, ev)) {
        return 0;
    }
    /* ПОТОК БЕЗ ПЛАНА У ПОДТВЕРЖДЁННОЙ ЦЕЛИ — НЕ УЛИКА И БЕЗ НАБЛЮДАТЕЛЯ
       (issue #5 после 3f9a43e, журнал репортёра 21.10.2026). Наблюдатель
       снимается первым же последующим TLS-ответом (D2K_EV_EXCHANGE ниже), и
       подозрение о потоке, к которому датапат план НЕ применял, приходило уже
       к t==NULL: заводился полный поиск, 20 с и 4 зонда, тот же план
       подтверждался снова — 7 кругов за 15 минут; после рестарта так же
       (soundcloud). Правило то же, что у ветки T_WATCHING ниже: такой поток о
       плане не говорит ничего. Поиск нужен, только если форма потока привязкой
       не покрыта (TLS 1.2, QUIC) — это другой вход, и он меряется как прежде.
       Почему план не применён, отвечает журнал датапата, а не новый замер.
       Только TCP: у QUIC неприменённый разрез CRYPTO проверяется снимком
       пачки, и это делает ветка наблюдателя. */
    if (!t && !by_addr && ev->transport == 6 && !doh_find(s,name) && !force_name(s,name) && ev->planned == D2K_LINK_PLANNED_NO) {
        const d2k_cat_binding *bd = binding_covering(s, name, 6, ev->family ? ev->family : 4,
                                                     ev->client_shape);
        if (bd) {
            char quiet_key[300];
            snprintf(quiet_key, sizeof quiet_key, "unplanned %u %s", ev->transport, name);
            say_quiet(s, quiet_key, "по %s план %s уже подтверждён, а к этому потоку датапат "
                      "его не применял — не улика, поиск не начинаю (причина — в журнале "
                      "датапата)", name, bd->plan_id);
            return 0;
        }
    }
    /* ПОЗДНЕЕ ЗАКРЫТИЕ — ЗАМЕР С ПЕРВОГО СИГНАЛА (владелец, 15.10.2026).
       Прежде здесь ждали второго такого закрытия на независимом потоке за
       30 с. Клиент с одним соединением (старые телевизоры на webOS тянут
       YouTube одним запросом; Safari держит одно HTTP/2 на источник) второго
       сигнала не даёт никогда, и обрыв объёма у него не мерился вовсе. Ворота
       — сама RX-пара identity/gzip, как у «TCP встал на бюджете» выше: на
       здоровом сайте замер кончается первым же завершённым ответом
       (measure_response_volume), неподтверждённая пара даёт отдых позднего
       закрытия на 10 мин, и шторма замеров на одном имени не будет. */
    if (!t || t->state == T_WATCHING) {
        healthy_proof *hp = proof_covers(s, ev, name);
        if (hp) {
            hp->skipped++;
            char quiet_key[300];
            snprintf(quiet_key, sizeof quiet_key, "proven %u %s", ev->transport, name);
            say_quiet(s, quiet_key, "по %s тот же признак (подозрение %u под планом %s, сервер %s:%u, "
                      "форма %u) уже опровергнут: план доказано зондом прошёл бюджет %lld с назад — "
                      "повторный замер того же входа не начинаю (повторов: %u); другой признак, "
                      "сервер или план меряется сразу", name, (unsigned)hp->code, hp->plan_id,
                      hp->ip, (unsigned)hp->port, (unsigned)hp->shape,
                      (long long)((s->now_ms - hp->proven_ms) / 1000), hp->skipped);
            return 0;
        }
    }
    if ((ev->code == D2K_SUSPECT_RST_AFTER_APP ||
         (ev->code == D2K_SUSPECT_FIN_RETRY && ev->planned == D2K_LINK_PLANNED_NO)) &&
        (!t || (t->state == T_WATCHING && ev->planned != D2K_LINK_PLANNED_NO))) {
        char quiet_key[300];
        snprintf(quiet_key, sizeof quiet_key, "late %u %s", ev->transport, name);
        say_quiet(s, quiet_key, "по %s позднее закрытие (%s) — проверяю обрыв ответа сам, "
                  "не дожидаясь второго соединения", name, late_close_what(ev->code));
    }
    if (t) {
        if (t->state == T_QUEUED) {
            /* Задача 29: цель снова подозревается, пока ждёт — её очередь
               поднимается (queued_pick), место и возраст в очереди те же. */
            t->hot_event = s->event_sequence;
            t->hot_count++;
            char queued_plan[40];
            if (!ev_executed_plan(ev, queued_plan) ||
                strcmp(queued_plan, t->trigger_executed_plan) ||
                !d2k_binding_equal(&ev->execution_binding, &t->trigger_binding))
                t->trigger_executed_plan[0] = 0;
            /* An ACK must never erase a later failure of the inherited plan.
               A different TCP flow has unknown protocol provenance here. */
            if (ev->planned != D2K_LINK_PLANNED_NO ||
                (t->transport == 6 && !ev_matches_flow(ev, &t->trigger_flow)))
                t->trigger_planned = D2K_LINK_PLANNED_YES;
        }
        if (late_app_rst) {
            if (t->state != T_WATCHING) { return 0; }
            /* ПОЗДНЕЕ ЗАКРЫТИЕ НА ПОТОКЕ БЕЗ ПЛАНА У ПОДТВЕРЖДЁННОЙ ЦЕЛИ — НЕ
               УЛИКА (issue #5, station-drivers.com, 19.10.2026). Соединение
               браузера, открытое до того, как план доехал, режется на объёме
               как и прежде; датапат честно говорит «план не применялся».
               Прежде ветвь сносила наблюдателя и перемеряла: 18 с, 4 зонда,
               тот же план подтверждён снова — 10 кругов за вечер, и ни одного
               подозрения с применённым планом. О плане такой поток не говорит
               ничего — он идёт общей ветвью ниже: наблюдение продолжается,
               просится снимок. Поток ПОД планом меряется сразу, как и было. */
            if (ev->planned != D2K_LINK_PLANNED_NO) {
                /* Keep the confirmed catalog binding, but replace its passive
                   watcher with a targeted measurement task. */
                say(s, "по %s позднее закрытие после app-data — проверяю повторяемость обрыва ответа",
                    t->name);
                task_done(s, t);
                t = NULL;
            }
        }
    }
    if(t && t->state==T_RESTING && doh_find(s,name) && !force_name(s,name)){task_reset(s,t);t=NULL;}
    if (t) {
        /* Поиск уже идёт — но примета всё равно наша: отпечаток растёт по мере
           того, как коробка себя проявляет, и первое подозрение редко
           показывает её целиком. Позднее закрытие приметой коробки не
           является (как и у новой задачи ниже). */
        if (!late_app_rst) {
            d2k_cat_signal sig = signal_of(ev);
            fp_add(&t->fp, &sig);
        }
        if (t->state != T_WATCHING) { return 0; }
        /* A watcher has already confirmed a plan. A failure on a planned
           flow must start remeasurement from THIS event: datapath emits at
           most one suspicion per flow, so waiting for a second loses the
           trigger. Retain the catalog evidence until measurement judges it. */
        /* УЛИКОЙ ПРОТИВ ПЛАНА ЯВЛЯЕТСЯ НЕ ВСЯКОЕ ПОДОЗРЕНИЕ.
           Поток, к которому план НЕ применялся, шёл без обхода — обычно
           потому, что начался раньше, чем план доехал до датапата. Поле
           18.09.2026: такое подозрение приходило через две секунды после
           подтверждения, при том что клиент тут же получал 200 четыре раза
           подряд, и наблюдение снималось зря. Ноль в поле — «не сказано»
           (старая служба), и по нему поведение остаётся прежним. */
        if (ev->planned == D2K_LINK_PLANNED_NO && !doh_find(s,name) && !force_name(s,name)) {
            /* No application is not necessarily an old flow: a different
               TLS version deliberately does not match the confirmed plan.
               Ask for bytes, not another network measurement. */
            if (t->transport == 6 && !t->watch_shape_pending) {
                char err[128];
                if (d2k_link_arm_shape_family(s->link_fd, t->name, 6,
                                              t->family, err, sizeof err) == 0) {
                    t->watch_shape_pending = 1;
                    server_of(ev, t->watch_shape_ip, sizeof t->watch_shape_ip,
                              &t->watch_shape_port);
                }
            }
            /* QUIC: подтверждённый разрез CRYPTO не исполнился потоку клиента
               (финальное ревью core, I1). Причина, которую датапат так
               называет, — ClientHello шире датаграммы; проверяется снимком
               приветствия клиента, а не догадкой: обрывок снимет привязку
               к повторной проверке (quic_note_multi). */
            if (t->transport == 17 && !t->watch_shape_pending &&
                t->n_plans > 0 && t->next_plan > 0 && t->next_plan <= t->n_plans &&
                quic_text_is_split(t->plans[t->next_plan - 1])) {
                char err[128];
                if (d2k_link_arm_shape_family(s->link_fd, t->name, 17,
                                              t->family, err, sizeof err) == 0) {
                    t->watch_shape_pending = 1;
                }
            }
            say(s, "по %s подозрение о потоке, к которому план НЕ ПРИМЕНЯЛСЯ "
                   "— уликой против подтверждённого "
                   "плана не считаю, наблюдение продолжаю", t->name);
            return 0;
        }
        say(s, "по %s подозрение при подтверждённом плане — запускаю повторный замер",
            t->name);
        task_done(s, t);
        t = NULL;
    }
    t = task_free_slot(s);
    if (!t) {
        t = task_watching_slot(s);
        if (t) { task_done(s, t); }
    }
    if (!t) {
        return 0; /* мест нет — подозрение придёт снова, датапат не молчит */
    }
    task_reset(s, t);
    snprintf(t->name, sizeof t->name, "%s", name);
    t->transport = ev->transport;
    t->family = ev->family ? ev->family : 4;
    t->by_addr = by_addr;
    t->stun_target = stun_target;
    t->trigger_code = ev->code;
    t->trigger_planned = ev->planned;
    t->trigger_executed_plan[0] = 0;
    (void)ev_executed_plan(ev, t->trigger_executed_plan);
    t->trigger_binding = ev->execution_binding;
    memcpy(t->trigger_flow.a_ip, ev->low_ip, 16);
    memcpy(t->trigger_flow.b_ip, ev->high_ip, 16);
    t->trigger_flow.a_port = ev->low_port;
    t->trigger_flow.b_port = ev->high_port;
    t->trigger_flow.transport = ev->transport;
    t->trigger_flow.family = t->family;
    if (ev->client_shape) t->trigger_shape = ev->client_shape;
    else if (t->transport == 17) t->trigger_shape = D2K_LINK_SHAPE_QUIC;
    else if (!strcmp(s->tcp_shape_name[t->family == 6], name) &&
             ev_matches_flow(ev, &s->tcp_shape_flow[t->family == 6])) {
        const uint8_t *hello = s->tcp_shape[t->family == 6];
        size_t len = s->tcp_shape_len[t->family == 6];
        t->trigger_shape = d2k_hello_ech_offer(hello,len,NULL)==1 ?
                D2K_LINK_SHAPE_ECH_TCP : (uint8_t)d2k_hello_shape(hello,len);
        /* GREASE-клиент: ECH offer есть, а привязка имени — TLS 1.3 и отдельной
           ECH-привязки нет. Датапат применит к нему запись TLS 1.3 (plans.c), и
           форма задачи обязана совпадать с тем, что применится: иначе покрытие
           семейства и снимка расходятся с проводом (issue #7, 21.10.2026).
           Настоящий ECH доказывает только HTTPS RR — у цели с ECH-привязкой
           форма остаётся ECH. */
        if (t->trigger_shape == D2K_LINK_SHAPE_ECH_TCP) {
            const d2k_cat_binding *bd = binding_covering(s, name, 6, t->family,
                                                         D2K_LINK_SHAPE_ECH_TCP);
            if (bd && bd->shape == (uint8_t)D2K_SHAPE_MODERN) {
                t->trigger_shape = (uint8_t)D2K_SHAPE_MODERN;
            }
        }
    }
    if (!doh_find(s,t->name) && !force_name(s,t->name) && t->trigger_planned == D2K_LINK_PLANNED_NO &&
        installed_family_ready(s, t, 0, 0)) {
        say(s, "по %s отдельный поиск не запускаю: совместимое семейство уже установлено; "
               "новый поток наследует его план (форма %u, IPv%u)",
            t->name, (unsigned)t->trigger_shape, (unsigned)t->family);
        task_reset(s, t);
        return 0;
    }
    proof_drop(s, t->name, t->transport, t->family);
    server_of(ev, t->ip, sizeof t->ip, &t->port);
    unsigned client_port = t->port == ev->low_port ? ev->high_port : ev->low_port;
    say(s, "по %s источник нового замера: сервер %s, порт %u, %s, порт клиента %u, подозрение %u, исполнение плана %u, форма %u, IPv%u",
        t->name, t->ip, (unsigned)t->port, t->transport == 17 ? "UDP" : "TCP",
        client_port, (unsigned)t->trigger_code, (unsigned)t->trigger_planned,
        (unsigned)t->trigger_shape, (unsigned)t->family);
    t->fp.method = D2K_FP_METHOD;
    if (!late_app_rst) {
        d2k_cat_signal sig = signal_of(ev);
        fp_add(&t->fp, &sig);
    }
    t->rx_volume_only = late_app_rst;
    if (is_voice_class(t->name, t->transport)) {
        uint8_t target_ip[4];
        memcpy(t->voice_flow.a_ip, ev->low_ip, sizeof t->voice_flow.a_ip);
        memcpy(t->voice_flow.b_ip, ev->high_ip, sizeof t->voice_flow.b_ip);
        t->voice_flow.a_port = ev->low_port;
        t->voice_flow.b_port = ev->high_port;
        t->voice_flow.transport = ev->transport;
        if (inet_pton(AF_INET, t->ip, target_ip) == 1 &&
            memcmp(ev->low_ip, target_ip, sizeof target_ip) == 0 &&
            ev->low_port == t->port) {
            t->voice_flow_bound = 1;
        } else if (inet_pton(AF_INET, t->ip, target_ip) == 1 &&
                   memcmp(ev->high_ip, target_ip, sizeof target_ip) == 0 &&
                   ev->high_port == t->port) {
            t->voice_flow_bound = 1;
        }
    }
    t->started_ms = 0;
    /* Голос, QUIC по адресу и TLS идут через одну общую очередь: иначе
       ограничение только одного транспорта оставило бы остальные источником
       неограниченных параллельных сетевых измерений. */
    if (ordinary_tcp_rst) {
        say(s, "по %s одиночный обычный RST — запускаю прямую проверку; обход появится только при подтверждённой блокировке",
            t->name);
    }
    return launch_or_queue(s, t);
}

static int on_suspect(d2k_sched *s, const d2k_ev *ev) {
    return on_suspect_as(s, ev, recall(s, ev), recall_noname(s, ev));
}

/* ПОЗДНЯЯ ТИШИНА → УТОЧНЕНИЕ, НЕ ВЫВОД (этап 49). Только после свидетельства
   с самого потока: клиент повторил сегмент с данными, от сервера ни пакета.
   Поток TLS с именем или по адресу — подозрение того же потока (ключ и
   исполнение из наблюдения) в общий путь: узкий RX-замер объёма своим
   соединением, подбор только после воспроизведённого обрыва, отдых при
   чистом ответе. Поток без протокола — факт в неизвестных целях: зонда для
   неизвестного протокола нет (этап 38), опыта на продолжении клиента за окном
   очереди нет. Поток без наблюдённого исполнения у цели с подтверждённым
   планом о плане не говорит (issue #5) — повторного замера нет. */
static void late_silence(d2k_sched *s, flow_watch *w, unsigned repeats) {
    long long secs = (long long)((s->now_ms - w->sil_ms) / 1000);
    d2k_ev ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = D2K_EV_SUSPECT;
    ev.code = D2K_SUSPECT_LATE_SILENCE;
    ev.transport = 6;
    ev.family = w->family;
    memcpy(ev.low_ip, w->low_ip, 16); memcpy(ev.high_ip, w->high_ip, 16);
    ev.low_port = w->low_port; ev.high_port = w->high_port;
    ev.client_side = w->client_side;
    ev.planned = w->planned;
    ev.execution_id = w->execution_id;
    memcpy(ev.plan_id, w->plan_id, sizeof ev.plan_id);
    memcpy(ev.trial_id, w->trial_id, sizeof ev.trial_id);
    ev.execution_binding = w->binding;
    ev.num = repeats;
    int named = w->port == 0;
    if (!named && !w->tls_noname) {
        memcpy(ev.flow_epoch,w->flow_epoch,16);
        ev.flow_incarnation=w->flow_incarnation;
        if(raw_measure_start(s,&ev,w->target,w->port))return;
        char why[512];
        snprintf(why, sizeof why, "TCP без распознанного протокола: сервер отвечал, затем за окном очереди от "
                 "него ни одного пакета не меньше %lld с; на самом потоке клиент повторил сегмент с данными "
                 "(%u раз), от сервера ни пакета; зонда для неизвестного протокола нет, опыта нет", secs, repeats);
        unknown_note(s, "addr", w->target, 6, w->family, w->port, "late-silence", why);
        return;
    }
    task *t = task_of(s, w->target, 6, w->family);
    if (named && t && t->state == T_WATCHING && !w->execution_id) {
        say(s, "по %s поздняя тишина потока, исполнение плана на котором не наблюдалось, — "
               "о подтверждённом плане не говорит, повторный замер не начинаю", w->target);
        return;
    }
    say(s, "по %s поздняя тишина: сервер отвечал, затем от него ни одного пакета не меньше %lld с, на самом "
           "потоке клиент повторил сегмент с данными (%u раз) — это подозрение, не блок: проверяю ответ "
           "своим замером", w->target, secs, repeats);
    (void)on_suspect_as(s, &ev, named ? w->target : NULL, w->tls_noname);
}

/* Наблюдение того же потока под тем же токеном (этап 49). */
static int late_obs_owner(const flow_watch *w, const d2k_ev *ev) {
    return w->used && w->obs_asked_ms && w->transport == ev->transport &&
           w->family == (ev->family ? ev->family : 4) &&
           w->low_port == ev->low_port && w->high_port == ev->high_port &&
           !memcmp(w->low_ip, ev->low_ip, 16) && !memcmp(w->high_ip, ev->high_ip, 16) &&
           !memcmp(w->obs_token, ev->trial_id, D2K_TRIAL_ID_LEN);
}

/* Итог позднего наблюдения датапата (D2K_EV_LATE_OBS) — только своему
   наблюдению: тот же поток, семейство и токен. Чужой или устаревший итог
   (прежнее соединение кортежа, повторный запрос) не принимается. */
static void on_late_obs(d2k_sched *s, const d2k_ev *ev) {
    for (size_t i = 0; i < SCHED_FLOWWATCH_SLOTS; i++) {
        flow_watch *w = &s->flowwatch[i];
        if (!late_obs_owner(w, ev)) continue;
        if (ev->code == D2K_LATEOBS_REPEAT_SILENT && w->sil_steps) {
            w->obs_asked_ms = 0;
            late_silence(s, w, ev->num);
        } else {
            late_obs_negative(s, w);
            say(s, "по %s поздняя тишина не подтверждена на самом потоке: %s — замер не начинаю", w->target,
                ev->code == D2K_LATEOBS_REPEAT_SILENT ? "сервер снова отвечает по счётчикам"
                                                      : d2k_lateobs_text((uint8_t)ev->code));
        }
        return;
    }
}

/* Датапат отказал в наблюдении: итог — только наблюдению с этим токеном
   (ACK несёт токен). Отказ без токена (старый датапат) не относится ни к
   кому: ждущее наблюдение кончится сроком. */
static void late_obs_refused(d2k_sched *s, const d2k_ev *ev) {
    uint8_t any = 0;
    for (size_t k = 0; k < D2K_TRIAL_ID_LEN; k++) any |= ev->trial_id[k];
    if (!any) return;
    for (size_t i = 0; i < SCHED_FLOWWATCH_SLOTS; i++) {
        flow_watch *w = &s->flowwatch[i];
        if (!w->used || !w->obs_asked_ms || memcmp(w->obs_token, ev->trial_id, D2K_TRIAL_ID_LEN)) continue;
        late_obs_negative(s, w);
        say(s, "по %s поздняя тишина не подтверждена на самом потоке: датапат отказал в наблюдении (код %u) — "
               "замер не начинаю", w->target, (unsigned)(ev->num & 0xffu));
        return;
    }
}

/* ПЕРЕМЕР ПОДТВЕРЖДЁННОЙ ЦЕЛИ СНЯТЫМИ БАЙТАМИ.
 *
 * Привязка добыта заготовкой холодного старта, а снимок настоящего клиента
 * этой цели есть: поиск повторяется им. Подтверждённый план при этом стоит
 * как стоял — перемер может его только подтвердить заново (и тогда привязка
 * получает полноту «байты клиента») или найти другой. Состояние прошлого
 * поиска сбрасывается ПЕРЕД новым, иначе кандидаты прошлого вердикта доживают
 * до установки. Повтор один: после него trig_snapped взведён, и сюда задача
 * больше не попадает. */
/* ЦЕЛЫЙ INITIAL КЛИЕНТА ЭТОЙ ЦЕЛИ ДЛЯ ПЕРЕМЕРА (задача 31).
 * Сначала копия задачи (on_shape кладёт её, пока поиск идёт), затем общая
 * ячейка, если она всё ещё этого имени. Обрывки сюда не попадают: on_shape
 * отбрасывает их до сохранения (задача 12). */
static int quic_own_initial(const d2k_sched *s, const task *t,
                            const uint8_t **bytes, size_t *len, uint64_t *seq) {
    if (t->transport != 17) { return 0; }
    if (t->snap_len > 0 && t->snap_len <= sizeof t->trig) {
        *bytes = t->snap; *len = t->snap_len; *seq = t->snap_seq;
        return 1;
    }
    int f = t->family == 6;
    if (s->quic_shape_len[f] > 0 && s->quic_shape_len[f] <= sizeof t->trig &&
        strcmp(s->quic_shape_name[f], t->name) == 0) {
        *bytes = s->quic_shape[f]; *len = s->quic_shape_len[f]; *seq = s->quic_shape_seq[f];
        return 1;
    }
    return 0;
}

/* ФОРМА ПРИВЕТСТВИЯ ДЛЯ ПРОВЕРКИ ПОКРЫТИЯ — ТЕМ ЖЕ ПРАВИЛОМ, ЧТО У ПРИВЯЗКИ
   (record_shape). ECH offer по байтам неотличим от GREASE (RFC 9849 §6.2):
   настоящий ECH доказывает только HTTPS RR, и задача это уже выяснила
   (ech_grease). Привязка GREASE-клиента записана формой TLS 1.3; считать его
   же снимок формой ECH значило бы не найти у него покрытия и перемерять
   подтверждённую цель на каждое подозрение без плана (issue #7, журналы #5
   и #7, 21.10.2026: soundcloud.com — 18 поисков за 35 минут, gateway.instagram.com
   — 53). */
static d2k_shape watch_shape(const task *t, const uint8_t *b, size_t n) {
    if (!t->ech_grease && d2k_hello_ech_offer(b, n, NULL) == 1)
        return (d2k_shape)D2K_LINK_SHAPE_ECH_TCP;
    return d2k_hello_shape(b, n);
}

static void remeasure_snapped(d2k_sched *s, task *t, const uint8_t *bytes, size_t len) {
    if (len == 0 || len > sizeof t->trig) { return; }
    search_report(s, t, s->now_ms, "superseded", NULL, "пришёл снимок приветствия клиента: замер начинается заново его байтами");
    d2k_run_cache_clear(&t->run_cache);
    /* Байты могут лежать в самой задаче (t->snap): memmove, и копия
       гасится — перемер у задачи один. */
    memmove(t->trig, bytes, len);
    /* Набор опций — вместе с байтами: у TCP это набор последнего снимка
       семейства (SHAPE и его CLIENT_TCP уже связаны в on_shape), у QUIC
       набора нет. */
    if (t->transport == 6) { take_shape_opts(s, t); } else { drop_client_opts(t); }
    t->snap_len = 0;
    t->snap_stop = 0;
    t->trig_len = len;
    t->trig_snapped = 1;
    t->reasked = 1;
    /* Перемер идёт байтами ЭТОГО снимка: клиент опыта теперь он, и его форма
       — форма клиента (hello_fits_client), а не прежнего подозрения. */
    if (t->transport == 6 && tcp_hello_kind(t->trig, t->trig_len) != D2K_SHAPE_UNKNOWN)
        t->trigger_shape = tcp_hello_kind(t->trig, t->trig_len);
    t->ctrl_len = 0;   /* контроль соберётся из новых байт */
    t->researched = 0;
    t->family_fast = 0;
    t->own_first = 0;
    t->seed_use = 0;
    t->seed.valid = 0;
    t->seed.props_valid = 0; /* этап 25: ответы прежнего входа к новым байтам не относятся */
    t->seed.nprops = 0;
    t->n_plans = 0;
    t->next_plan = 0;
    /* ПЕРЕМЕР — НОВЫЙ ПОИСК, И БЮДЖЕТ У НЕГО СВОЙ (задача 24). Прежде задача
       несла сюда зонды и список испытанных текстов прошлого поиска: после
       долгого подбора перемер упирался в потолок зондов на первых шагах, а
       known_plans и запасной перебор пропускали уже испытанные хэши — в том
       числе только что подтверждённый план, который перемер и должен
       проверить первым. Курсоры источников кандидатов сбрасываются вместе с
       ними, иначе «свежий» перебор начинался бы с середины. Счёт на
       карточке — тоже новый: это новый поиск, а не продолжение прежнего. */
    t->ask_probes = 0;
    t->probes = 0;
    memset(t->tried, 0, sizeof t->tried);
    t->n_tried = 0;
    memset(t->own_tried, 0, sizeof t->own_tried);
    t->n_own_tried = 0;
    t->fb_next = 0;
    t->owned_fallback = 0;
    /* Опровергнутые приёмы и вектор — прошлого поиска: перемер байтами
       снимка спрашивает коробку заново (arm_survey_resume). */
    t->n_arm_refuted = 0;
    memset(t->arm_refuted, 0, sizeof t->arm_refuted);
    memset(&t->measured_props, 0, sizeof t->measured_props);
    t->rx_volume_next_variant = 0;
    t->net_probing = 0;
    t->net_probe_next = 0;
    t->exec_refused = t->exec_probed = 0;
    /* Состояние фазы своих планов, RX-начала и ECH — тоже прошлого поиска
       (финальное ревью core, M3): новый вход вправе снова проверить свои
       планы, начать обычным путём, а не «остаточным RX-блоком», и заново
       решить про ECH по новым байтам. */
    memset(t->own_seen, 0, sizeof t->own_seen);
    t->n_own_seen = 0;
    t->own_seen_full = 0;
    t->own_probed = 0;
    t->rx_bootstrap_only = 0;
    t->family_reuse = 0;
    t->ech_grease = 0;
    say(s, "по %s привязка добыта заготовкой, а снимок клиента есть — "
           "перемеряю снимком: %zu байт", t->name, len);
    (void)launch_or_queue(s, t);
}

/* Клиент имени шлёт ClientHello шире датаграммы — так сообщил датапат
   снимком-обрывком (финальное ревью core, I1). Запоминается для будущих
   поисков; подтверждённая привязка этого имени с планом разреза CRYPTO
   помечается к повторной проверке и снимается с провода: клиенту она не
   исполняется (датапат отказывает «имени нет в этой датаграмме»), и считать
   её подтверждённой нельзя. Удаления нет — только пометка, как у CLEAR. */
static void quic_note_multi(d2k_sched *s, const char *name, uint8_t family) {
    if (!quic_client_multi(s, name, family)) {
        size_t n = sizeof s->quic_multi / sizeof s->quic_multi[0];
        size_t slot = s->quic_multi_next++ % n;
        snprintf(s->quic_multi[slot].name, sizeof s->quic_multi[slot].name, "%s", name);
        s->quic_multi[slot].family = family;
    }
    if (!s->cat) return;
    size_t marked = 0;
    char err[200];
    for (size_t bi = 0; bi < s->cat->n_boxes; bi++) {
        d2k_cat_box *b = &s->cat->boxes[bi];
        for (size_t j = 0; j < b->n_binds; j++) {
            d2k_cat_binding *bd = &b->binds[j];
            if (!bd->enabled || bd->recheck_since || strcmp(bd->kind, "name") ||
                strcmp(bd->target, name) || (bd->transport ? bd->transport : 6) != 17 ||
                (bd->family ? bd->family : 4) != family) continue;
            const char *text = NULL;
            for (size_t k = 0; k < b->n_plans && !text; k++)
                if (!strcmp(b->plans[k].id, bd->plan_id)) text = b->plans[k].text;
            if (!quic_text_is_split(text)) continue;
            bd->recheck_since = wall_s(s, s->now_ms);
            bd->recheck_mono_ms = s->now_ms ? s->now_ms : 1;
            b->updated = bd->recheck_since;
            uint8_t wire_shape = bd->shape ? bd->shape : (uint8_t)D2K_LINK_SHAPE_GRANDFATHER;
            if (d2k_link_del_name_family(s->link_fd, name, 17, wire_shape, family,
                                         err, sizeof err) != 0) {
                say(s, "по %s привязку %s не удалось снять с провода: %s",
                    name, bd->plan_id, err);
            }
            marked++;
        }
    }
    if (marked) {
        s->cat->revision++;
        s->sync_pending = 1;
        say(s, "по %s (QUIC) клиент шлёт ClientHello шире датаграммы — подтверждённый "
               "разрез CRYPTO ему не исполняется: привязок к повторной проверке %zu "
               "(сняты с провода, в каталоге сохранены)", name, marked);
    }
}

static void on_shape(d2k_sched *s, const d2k_ev *ev) {
    if (ev->shape_len == 0 || ev->shape_len > sizeof s->tasks[0].trig) { return; }
    if (ev->transport == 6 && !d2k_hello_complete(ev->shape, ev->shape_len)) {
        say(s, "снимок TCP (%zu байт) не содержит целого ClientHello — "
               "не заменяю им вход измерителя", ev->shape_len);
        return;
    }
    /* ИМЯ ДОСТАЁТСЯ ТЕМ РАЗБОРОМ, КОТОРОМУ ПРИНАДЛЕЖАТ БАЙТЫ.
       Снимок приходит с транспортом в ключе (датапат кладёт его туда, см.
       ARM_SHAPE в ctlsrv.c), и приветствие QUIC — это Initial, а не запись
       TLS: разбор TLS на нём возвращает отказ, и снимок молча пропадал. */
    char name[256];
    if (ev->transport == 17) {
        /* ПАЧКА — ВЕСЬ ПОЛЁТ КЛИЕНТА (задача 66). Приветствие Chrome с
           постквантовым key_share едет двумя Initial, и датапат отдаёт их
           вместе. Имя берётся из СОБРАННОГО ClientHello: расширение
           server_name Chrome кладёт последним, и в первой датаграмме его нет
           вовсе. Пачка, которая не складывается в целое приветствие (Retry,
           вытесненная из кольца датаграмма), — тот же обрывок, что и
           одиночная половина ниже. */
        if (d2k_qsnap_is(ev->shape, ev->shape_len)) {
            d2k_qsnap pack;
            if (d2k_qsnap_parse(ev->shape, ev->shape_len, &pack) != 0) { return; }
            if (d2k_qsnap_sni(&pack, name, sizeof name) != 0) {
                say(s, "снимок QUIC (%zu датаграмм, %zu байт) не складывается в целое "
                       "приветствие — обрывок ClientHello; цель мерится собственным "
                       "Initial (PROFILE)", pack.n, ev->shape_len);
                return;
            }
            int ech = quic_pack_ech(ev->shape, ev->shape_len);
            uint8_t fam = ev->family ? ev->family : 4;
            size_t nslot = sizeof s->quic_named / sizeof s->quic_named[0];
            size_t slot = nslot;
            for (size_t k = 0; k < nslot; k++)
                if (s->quic_named[k].len && s->quic_named[k].family == fam &&
                    !strcmp(s->quic_named[k].name, name)) { slot = k; break; }
            int admitted = slot == nslot || !s->quic_named[slot].ech;
            /* ECH-пачки датапат шлёт без заказа, по одной на соединение: о
               каждой повторной пачке того же имени журнал молчит минуту. */
            if (slot == nslot || s->quic_named[slot].observed_ms + 60000 < s->now_ms ||
                (ech && admitted))
                say(s, "по %s снят снимок QUIC: %zu датаграмм, %zu байт%s — мерю снятыми "
                       "байтами клиента", name, pack.n, ev->shape_len, ech ? ", с ECH" : "");
            if (slot == nslot) slot = s->quic_named_next++ % nslot;
            if (ech && admitted) {
                /* Прежний «напрямую проходит» по этому имени мерился без ECH —
                   заготовкой. Он не говорит ничего о полёте клиента; отсрочку
                   снимаем один раз на допуск пачки, не на каждый повтор. */
                if (cooldown_find(s, name, 17, fam)) {
                    cooldown_clear(s, name, 17, fam);
                    say(s, "по %s клиент шлёт QUIC с ECH — прежний «напрямую проходит» "
                           "мерился без ECH; отсрочку снимаю, мерю пачкой клиента", name);
                }
            }
            snprintf(s->quic_named[slot].name, sizeof s->quic_named[slot].name, "%s", name);
            memcpy(s->quic_named[slot].bytes, ev->shape, ev->shape_len);
            s->quic_named[slot].len = ev->shape_len;
            s->quic_named[slot].family = fam;
            s->quic_named[slot].ech = (uint8_t)ech;
            s->quic_named[slot].observed_ms = s->now_ms;
        } else {
            /* ОДИНОЧНАЯ ДАТАГРАММА — прежний путь (датапат старой сборки,
               собственный зонд). Обрывок им не становится снимком: сервер
               такой Initial не дочитает и промолчит, контроль ответит — и
               молчание стало бы «доказанной» блокировкой от пакета, которого
               клиент не слал. Цель тогда мерится собственным Initial донора
               (PROFILE, trig_snapped=0, в привязке D2K_INPUT_PROFILE). */
            if (d2k_quic_sni(ev->shape, ev->shape_len, name, sizeof name) != 0) { return; }
            if (d2k_quic_hello_incomplete(ev->shape, ev->shape_len)) {
                say(s, "снимок QUIC по %s (%zu байт) — обрывок ClientHello, приветствие "
                       "не в одной датаграмме; не заменяю им вход измерителя, цель "
                       "мерится собственным Initial (PROFILE)", name, ev->shape_len);
                quic_note_multi(s, name, ev->family ? ev->family : 4);
                return;
            }
        }
    } else {
        size_t off = 0, len = 0;
        if (d2k_hello_sni(ev->shape, ev->shape_len, &off, &len) != 0 || len == 0) { return; }
        if (len >= sizeof name) { return; }
        memcpy(name, ev->shape + off, len);
        name[len] = '\0';
    }
    if (name[0] == '\0') { return; }
    if (ev->transport == 6) {
        /* НАБОР ОПЦИЙ СВЯЗЫВАЕТСЯ ТОЛЬКО С ТЕМ СНИМКОМ, КОТОРЫЙ СОХРАНЯЕТСЯ
           (ревью ветки, находка 1; замысел 2026-10-23, п. 5.1). Датапат шлёт
           CLIENT_TCP ровно перед своим SHAPE, и связывать их надо ПОСЛЕ всех
           ранних отказов: прежде это стояло в начале on_shape, и обрезанный
           снимок (целого ClientHello в нём нет) успевал привязать опции СВОЕГО
           приветствия к ранее сохранённому снимку ДРУГОГО — зонд здоровался бы
           набором одного клиента, повторяя байты другого, — а заодно гасил
           набор, ожидавший следующий годный снимок. Отвергнутый снимок теперь
           не трогает ожидание вовсе. Снимок без своего набора — known = 0:
           зонд идёт прежним набором. */
        int f = ev->family == 6;
        if (s->tcp_opts_wait[f] && ev_matches_flow(ev, &s->tcp_opts_wait_flow[f])) {
            s->tcp_shape_opts_known[f] = 1;
            s->tcp_shape_opts_len[f] = s->tcp_opts_wait_len[f];
            memcpy(s->tcp_shape_opts[f], s->tcp_opts_wait_bytes[f], s->tcp_opts_wait_len[f]);
        } else {
            s->tcp_shape_opts_known[f] = 0;
            s->tcp_shape_opts_len[f] = 0;
        }
        /* Ожидание гаснет на ПЕРВОМ сохранённом снимке, совпал ключ или нет:
           набор, чей снимок так и не доехал (кадр управления потерян), не
           должен позже достаться чужому снимку. Полностью это закрывает только
           неподдельный ключ: немедленный ответ на ARM_SHAPE кладёт в оба
           события нулевой ключ (datapath/ctlsrv.c), и при ПОТЕРЕ двух кадров
           подряд — снимка одной цели и набора следующей — нулевой ключ
           совпадёт с нулевым. Остаток названного риска в журнале работ. */
        s->tcp_opts_wait[f] = 0;
    }
    if (ev->transport == 6 && ev->shape_len <= sizeof s->ech_inputs[0].bytes &&
        d2k_hello_ech_offer(ev->shape, ev->shape_len, NULL) == 1) {
        size_t slot = 8;
        uint8_t family = ev->family ? ev->family : 4;
        for (size_t k = 0; k < 8; k++)
            if (s->ech_inputs[k].len && s->ech_inputs[k].family == family &&
                !strcmp(s->ech_inputs[k].name, name)) { slot = k; break; }
        if (slot == 8) {
            slot = s->ech_input_next++ % 8;
            /* New protocol evidence supersedes an inconclusive ordinary
             * profile measurement, once per cache admission, not per retry. */
            target_cooldown *cool = cooldown_find(s, name, 6, family);
            if (cool && cool->exhausted && !cool->challenge && !cool->ech_input)
                cooldown_clear(s, name, 6, family);
        }
        snprintf(s->ech_inputs[slot].name, 256, "%s", name);
        memcpy(s->ech_inputs[slot].bytes, ev->shape, ev->shape_len);
        s->ech_inputs[slot].len = ev->shape_len;
        s->ech_inputs[slot].family = family;
        s->ech_inputs[slot].observed_ms = s->now_ms;
        s->ech_inputs[slot].opts_known = s->tcp_shape_opts_known[family == 6];
        s->ech_inputs[slot].opts_len = s->ech_inputs[slot].opts_known ? s->tcp_shape_opts_len[family == 6] : 0;
        if (s->ech_inputs[slot].opts_len)
            memcpy(s->ech_inputs[slot].opts, s->tcp_shape_opts[family == 6], s->ech_inputs[slot].opts_len);
    }
    /* СНИМОК QUIC СОХРАНЯЕТСЯ ОБЩИМ, а не только задаче своего имени.
       Собственный Initial позволяет начать без него, но не является
       наблюдёнными байтами клиентского приветствия. Соседней
       цели он достанется с переписанным именем (см. quic_shape и
       fill_hellos). Сохраняем ДО поиска задач: снимок годится и тогда, когда
       задачи с этим именем уже нет. */
    if (ev->transport == 17 && ev->shape_len <= sizeof s->quic_shape[ev->family == 6]) {
        memcpy(s->quic_shape[ev->family == 6], ev->shape, ev->shape_len);
        s->quic_shape_len[ev->family == 6] = ev->shape_len;
        memcpy(s->quic_shape_name[ev->family == 6], name, strlen(name) + 1);
        s->quic_shape_seq[ev->family == 6]++;
    }
    /* Форма TCP сохраняется ВМЕСТЕ С ИМЕНЕМ и тоже ДО поиска задач: подозрение
       приходит следом, и без этой ячейки снимок терялся бы при обычном
       порядке событий (см. tcp_shape в структуре планировщика). */
    if (ev->transport == 6 && ev->shape_len <= sizeof s->tcp_shape[ev->family == 6] &&
        strlen(name) < sizeof s->tcp_shape_name[ev->family == 6]) {
        memcpy(s->tcp_shape[ev->family == 6], ev->shape, ev->shape_len);
        s->tcp_shape_len[ev->family == 6] = ev->shape_len;
        memcpy(s->tcp_shape_name[ev->family == 6], name, strlen(name) + 1);
        d2k_flowkey *flow=&s->tcp_shape_flow[ev->family == 6];
        memcpy(flow->a_ip,ev->low_ip,16); memcpy(flow->b_ip,ev->high_ip,16);
        flow->a_port=ev->low_port; flow->b_port=ev->high_port;
        flow->transport=6; flow->family=ev->family ? ev->family : 4;
        say(s, "по %s (TCP) сохранён целый снимок для следующего поиска: %zu байт",
            name, ev->shape_len);
    }
    /* Кладём ТОЛЬКО задачам своего транспорта: у TCP и QUIC приветствия
       разные, и снимок одного для другого — не «лучше, чем ничего», а чужие
       байты, которыми задача пойдёт мерить. */
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        task *t = &s->tasks[i];
        if (t->family != (ev->family ? ev->family : 4)) { continue; }
        if (ev->transport == 17 && t->transport == 17 && t->state != T_FREE &&
            t->state != T_WATCHING && t->state != T_SHAPE_WAIT &&
            !t->trig_snapped && !t->reasked && ev->shape_len <= sizeof t->snap &&
            strcmp(t->name, name) == 0) {
            /* Поиск идёт на собственном Initial; вход опыта неизменен, а
               Initial клиента ждёт у задачи её перемера. */
            memcpy(t->snap, ev->shape, ev->shape_len);
            t->snap_len = ev->shape_len;
            t->snap_seq = s->quic_shape_seq[ev->family == 6];
        }
        if ((t->state == T_QUEUED || t->state == T_ASKING) && t->transport == 6 && ev->transport == 6 &&
            ev_matches_flow(ev,&t->trigger_flow) && !t->trigger_shape) {
            t->trigger_shape=d2k_hello_ech_offer(ev->shape,ev->shape_len,NULL)==1 ?
                D2K_LINK_SHAPE_ECH_TCP : (uint8_t)d2k_hello_shape(ev->shape,ev->shape_len);
        }
        /* Только TCP-снимок: QUIC-пачка того же имени (cloudflare-ech.com —
           внешнее имя всех ECH-сайтов Cloudflare) — чужие байты, а
           hello_fits_client пропускает её как «форма неизвестна» (поле
           17.10.2026, LR-rx1-1). */
        if (t->state == T_ASKING && t->transport == 6 && ev->transport == 6 &&
            strcmp(t->name, name) == 0) {
            if (!t->trig_snapped && !t->reasked && ev->shape_len <= sizeof t->snap &&
                hello_fits_client(t, ev->shape, ev->shape_len)) {
                /* The worker owns an immutable cold-start profile copy. Ask
                   it to stop at its next bounded probe boundary; T_ASKING's
                   completion path restarts with the task-owned snapshot
                   (the shared tcp_shape slot may be taken by another name
                   by then). The latest client hello wins; the stop is
                   announced once per run. */
                memcpy(t->snap, ev->shape, ev->shape_len);
                t->snap_len = ev->shape_len;
                t->snap_opts_known = s->tcp_shape_opts_known[ev->family == 6];
                t->snap_opts_len = t->snap_opts_known ? s->tcp_shape_opts_len[ev->family == 6] : 0;
                if (t->snap_opts_len) memcpy(t->snap_opts, s->tcp_shape_opts[ev->family == 6], t->snap_opts_len);
                t->stop = 1;
                if (!t->snap_stop) {
                    t->snap_stop = 1;
                    say(s, "по %s во время профильного замера пойман ClientHello клиента — "
                           "останавливаю устаревший прогон и повторю его снятыми байтами",
                        t->name);
                }
            }
            continue;
        }
        /* The whole experiment, not just the worker, owns its input:
         * result conversion, Plan guards and verification must describe
         * the same bytes. New observations remain cached for NEXT search. */
        /* ПОДТВЕРЖДЁННОЕ ЗАГОТОВКОЙ ПЕРЕМЕРЯЕТСЯ СНЯТЫМИ БАЙТАМИ.
         *
         * Пока задача смотрит за подтверждённой целью, её привязка может быть
         * добыта заготовкой холодного старта: форма клиента угадана верно, а
         * байты — нет, и коробке никто не запрещал смотреть на содержимое
         * (§6). Такое доказательство слабее, и сказать об этом в отчёте мало:
         * снимок этой же цели пришёл — значит настоящие байты наконец есть, и
         * поиск повторяется ими. Повторяется ОДИН раз: перемер записывает
         * полноту входа «байты клиента», и следующий снимок сюда уже не
         * заходит. */
        if (t->state == T_WATCHING && t->transport == ev->transport &&
            strcmp(t->name, name) == 0) {
            if (t->watch_shape_pending && t->transport == 6) {
                t->watch_shape_pending = 0;
                d2k_shape shape = watch_shape(t, ev->shape, ev->shape_len);
                int covered = 0;
                for (size_t bi = 0; s->cat && bi < s->cat->n_boxes; bi++) {
                    const d2k_cat_box *b = &s->cat->boxes[bi];
                    for (size_t j = 0; j < b->n_binds; j++) {
                        const d2k_cat_binding *bd = &b->binds[j];
                        /* Помеченная «требует повторной проверки» снята с
                           провода (задача 21): клиентам этой формы плана нет,
                           и покрытием она не считается. */
                        if (bd->enabled && bd->level >= 3 && !bd->recheck_since &&
                            (bd->transport ? bd->transport : 6) == 6 &&
                            (bd->family ? bd->family : 4) == t->family &&
                            strcmp(bd->kind, "name") == 0 &&
                            strcmp(bd->target, name) == 0 && bd->shape == shape)
                            covered = 1;
                    }
                }
                if (!covered && shape != D2K_SHAPE_UNKNOWN &&
                    shape != watch_shape(t, t->trig, t->trig_len)) {
                    snprintf(t->ip, sizeof t->ip, "%s", t->watch_shape_ip);
                    t->port = t->watch_shape_port;
                    t->started_ms = s->now_ms;
                    remeasure_snapped(s, t, ev->shape, ev->shape_len);
                    continue;
                }
            }
            const d2k_cat_binding *bd = binding_for(s, t->name, t->transport, t->family);
            if (bd && bd->input == D2K_INPUT_PROFILE && !t->trig_snapped) {
                remeasure_snapped(s, t, ev->shape, ev->shape_len);
            }
            continue;
        }
        if (t->state == T_SHAPE_WAIT && t->transport == ev->transport &&
            strcmp(t->name, name) == 0) {
            t->shape_request_pending = 0;
            t->shape_request_until_ms = 0;
            memcpy(t->trig, ev->shape, ev->shape_len);
            t->trig_len = ev->shape_len;
            t->trig_snapped = 1;
            say(s, "по %s (%s) поймана форма приветствия: %zu байт",
                t->name, t->transport == 17 ? "QUIC" : "TCP", ev->shape_len);
            if (t->state == T_SHAPE_WAIT) {
                /* Ждали ровно этого. Контроль соберётся из этих же байт, и
                   поиск пойдёт дальше как обычно. */
                (void)launch_or_queue(s, t);
            }
        }
    }
}

/* Испытание сошлось: наш зонд довёл прикладной обмен до конца, и датапат
   сказал, что ИМЕННО ЭТОТ план применился к пакетам ИМЕННО ЭТОГО потока.
   Только теперь — каталог. */
static void group_record(d2k_sched *s, const task *t, unsigned evidence,
    const char *plan_id, uint8_t shape, int64_t now_ms) {
    char base[256];
    if (t->by_addr || encrypted_dns_task(t) || d2k_domain_base(t->name, base)) return;
    d2k_group_observation o = {0};
    snprintf(o.name, sizeof o.name, "%s", t->name);
    snprintf(o.plan_id, sizeof o.plan_id, "%s", plan_id ? plan_id : "");
    if (d2k_group_key_make(&o.key, t->transport, t->family, shape,
            group_path(t->transport, t->measure_path), t->ech_offer ? t->ech_origin : "")) {
        say(s, "по %s контекст слишком длинный для обучения области; точный обход сохранён", t->name);
        return;
    }
    o.evidence = evidence; o.at = wall_s(s, now_ms);
    if (!s->cat->groups) s->cat->groups = calloc(1, sizeof *s->cat->groups);
    if (!s->cat->groups) return;
    if (d2k_group_learn(s->cat->groups, &o) > 0) {
        s->cat->revision++; s->sync_pending = 1;
    }
}

/* Форма, под которую пишется привязка подтверждения. */
static uint8_t record_input(const task *t) {
    if(t->own_first==2)return D2K_INPUT_TRANSFER;
    return t->trig_snapped && !t->res.generated_input ? D2K_INPUT_CLIENT : D2K_INPUT_PROFILE;
}

static uint8_t record_shape(const task *t) {
    if (t->transport == 17) return (uint8_t)D2K_LINK_SHAPE_QUIC;
    if (t->ech_offer) return D2K_LINK_SHAPE_ECH_TCP;
    d2k_shape cs = d2k_hello_shape(t->trig, t->trig_len);
    return (uint8_t)(cs == D2K_SHAPE_LEGACY ? D2K_SHAPE_LEGACY : SCHED_PROBE_SHAPE);
}

/* Разовая строка о выключенной проверке бюджета (ревью M-5). */
static void budget_uncountable_note(d2k_sched *s, const task *t) {
    if (!t->ver.budget_uncountable || s->budget_uncountable_said) return;
    s->budget_uncountable_said = 1;
    say(s, "проверка бюджета потока на этой прошивке не работает: %s — подтверждения "
           "идут прежним критерием, привязки помечаются «бюджет не проверен»",
        t->transport == 17 ? "датаграммы связи не считаются"
                           : "ядро не отдаёт TCP_INFO data_segs (нужно Linux 4.6+)");
}

static int partial_finish(d2k_sched *s, task *t, int64_t now_ms);

/* ОБРЫВ ПОСРЕДИ ПОВТОРОВ ПРИ ДОКАЗАННОМ ПРИМЕНЕНИИ (задача 55; ревью I-1,
   I-3). Ответ приложения был, план исполнился на потоке зонда, а поток не
   перенёс 2 × бюджет коробки — действие (a) поля 04.10. Кандидат не
   подтверждён, как при RX-обрыве под кандидатом; у привязок этого ключа с
   этим планом «пройден» сменяется на «оборван» — новая улика, не удаление:
   установка больше не предпочитает план, только что измеренный режущимся.

   ИСКЛЮЧЕНИЕ — ВТОРОЙ, ОБЪЁМНЫЙ БЛОК ТОЙ ЖЕ ЦЕЛИ (поле 12.10.2026,
   www.userscript.zone). У цели ИЗМЕРЕН повторяемый обрыв входящего объёма
   (vol.rx_cut: /style.css 21289 байт с VPS против 15968 с линии), и это
   ОТДЕЛЬНЫЙ вопрос со своими планами и своим критерием. Кандидат доходил до
   HTTP 200 — рукопожатие он снимал, — а поток встал посреди повторов, не
   добрав 2 × 25 пакетов: 25 взято из ЧУЖОГО полевого замера (поле 04.10),
   к этой цели требование 50 никто не мерил. Отказ по нему отвергал кандидата
   за то, что проверялось НЕ ИМ: в поле так ушло 30 с лишним планов, 46
   зондов и 273 с, а плана не установлено вовсе. Смешивать два блока в один
   отказ нельзя — частичный результат записывается сразу (отметка «оборван»,
   повторная проверка после отдыха), объёмный блок остаётся открытым. */
static void budget_cut_reject(d2k_sched *s, task *t, int64_t now_ms) {
    char cut_id[40]; uint8_t cut_wire[D2K_PLAN_ID_LEN];
    plan_ident(t->plans[t->next_plan - 1], cut_id, sizeof cut_id, cut_wire);
    /* Объёмный обрыв этой цели измерен — остановка потока принадлежит ему. */
    int volume_block = t->transport == 6 && t->vol.rx_cut && !encrypted_dns_task(t);
    /* Строка о решении — короткая: числа бюджета печатает verify_confirm
       («частичный обход: … после ~N пакетов, нужно M, бюджет B»), и повтор
       их здесь обрезал бы её по 512 байт say (ровно это стоило полю 12.10
       самого порога в budget_note). */
    if (volume_block) {
        say(s, "по %s под кандидатом %s приложение ответило %d, а поток встал посреди "
               "повторов: у этой цели измерен обрыв входящего объёма около %d КБ — это он, "
               "отдельный вопрос со своими планами, а не провал плана рукопожатия",
            t->name, cut_id, t->ver.status, t->vol.rx_at_kb);
    } else {
    say(s, "по %s под кандидатом %s (план %zu) поток оборван посреди повторов: "
           "HTTP %d, %s; бюджет %u пакетов (%s) — не подтверждаю, беру следующего",
        t->name, cut_id, t->next_plan, t->ver.status, t->ver.budget_note,
        t->budget_pk, t->budget_src);
    }
    uint8_t shape = record_shape(t);
    for (size_t bi = 0; s->cat && bi < s->cat->n_boxes; bi++) {
        d2k_cat_box *b = &s->cat->boxes[bi];
        for (size_t j = 0; j < b->n_binds; j++) {
            d2k_cat_binding *bd = &b->binds[j];
            if (strcmp(bd->plan_id, cut_id) || strcmp(bd->target, t->name) ||
                strcmp(bd->kind, t->by_addr ? "addr" : "name") ||
                (bd->transport ? bd->transport : 6) != t->transport ||
                (bd->family ? bd->family : 4) != t->family || bd->shape != shape ||
                bd->budget == D2K_CAT_BUDGET_CUT) continue;
            say(s, "по %s привязка плана %s коробки %s: отметка бюджета «%s» → «оборван»",
                t->name, cut_id, b->id, bd->budget == D2K_CAT_BUDGET_PASSED ? "пройден" :
                bd->budget == D2K_CAT_BUDGET_UNCHECKED ? "не проверен" : "нет");
            bd->budget = D2K_CAT_BUDGET_CUT;
            s->cat->revision++;
            s->sync_pending = 1;
        }
    }
    /* ЧАСТИЧНЫЙ ОБХОД — лучший запоминается (больше пакетов до обрыва, затем
       успехи плана в каталоге): если проходящего бюджет не найдётся, он и
       будет подтверждён в конце поиска (partial_finish). */
    int succ = 0;
    for (size_t bi = 0; s->cat && bi < s->cat->n_boxes; bi++) {
        const d2k_cat_plan *p = plan_by_id(&s->cat->boxes[bi], cut_id);
        if (p && p->successes > succ) succ = p->successes;
    }
    if (!encrypted_dns_task(t) && (!t->partial_valid || t->ver.budget_packets > t->partial_pk ||
        (t->ver.budget_packets == t->partial_pk && succ > t->partial_succ))) {
        t->partial_valid = 1;
        t->partial_pk = t->ver.budget_packets;
        t->partial_succ = succ;
        snprintf(t->partial_text, sizeof t->partial_text, "%s", t->plans[t->next_plan - 1]);
        snprintf(t->partial_box, sizeof t->partial_box, "%s", t->box_id);
        t->partial_ver = t->ver;
        t->partial_ver.fd = -1;
    }
    /* Объёмный блок измерен: перебирать планы дальше по ЭТОМУ отказу нечем —
       каждый следующий кандидат получит тот же обрыв от того же блока, и
       судить его будет то же неизмеренное число. Поиск кончается частичным
       результатом; объёмный вопрос мерит свой замер, а не этот бюджет. */
    if (volume_block) {
        say(s, "по %s следующий кандидат получит тот же обрыв от того же блока, а "
               "требование %u пакетов к этой цели не измерено (%s) — перебор по нему не "
               "продолжаю, записываю частичный результат", t->name,
            t->ver.budget_need, t->budget_src);
        if (partial_finish(s, t, now_ms)) return;
    }
    /* Оборванный бюджетом приём ЗАМЕРА не кончает поиск (решение 04.10):
       замер владеет поиском и продолжить свой перебор с этого места не
       умеет, поэтому дальше — внутренние гипотезы оригинала (запасной
       список), как у невыразимого приёма (78a70fd). */
    if (t->transport == 6 && t->search_owned && !t->owned_fallback && t->own_first != 2) {
        t->owned_fallback = 1;
        say(s, "по %s приём замера снял рукопожатие, но поток режется бюджетом — это "
               "частичный обход; ищу проходящий бюджет дальше, в запасном списке", t->name);
    }
    trial_retire(s, t);
    ver_close(t);
    t->state = T_PLANNING;
}

/* ТРАССА ВОПРОСНИКА — по строке на заданный вопрос. Свойство говорит «помог
   ли приём», трасса — «что при этом видели»: без неё «приём не сработал»
   неотличимо от «зонд не долетел по другой причине» (см. d2k_quic_step). С
   10.10.2026 сюда же идут TCP-вопросы о свойствах (detect/bridge.c), и
   печатать трассу обязана каждая ветка, принявшая вердикт: ветка готовых
   планов узнанной коробки её прежде пропускала. */
static void say_question_trace(d2k_sched *s, const task *t, const d2k_vres *r) {
    for (size_t qi = 0; qi < D2K_QTRACE_MAX; qi++) {
        const d2k_quic_step *st = &r->qtrace[qi];
        if (!st->label[0]) { continue; }
        say(s, "по %s вопрос «%s»: %u/%u%s", t->name, st->label,
            (unsigned)st->answered, (unsigned)st->sent,
            st->outcome == D2K_PROP_UNKNOWN ? " — не измерено" :
            (st->outcome == D2K_PROP_YES ? " — взял" : ""));
    }
}

/* ТРАССА ПРЕРВАННОГО ПРОГОНА — В СЕМЯ ПЕРЕЗАПУСКА (этап 25, поле 28.10.2026).
   Прогон, прерванный уступкой или отменой, успел ответить на часть вопросов о
   свойствах; это измерено и верно. Ответы печатаются и кладутся в семя задачи
   под ключом входа (цель, порт, байты триггера — тот же, что у базы): полный
   замер, перезапущенный ТЕМ ЖЕ входом, берёт их, а не спрашивает заново.
   Снимок клиента меняет вход — семя не подходит (remeasure_snapped гасит).
   «Не измерено» в семени остаётся для журнала; измеритель такие вопросы задаёт
   заново (detect/bridge.c). */
static void keep_props_seed(d2k_sched *s, task *t, const d2k_vres *r) {
    say_question_trace(s, t, r);
    t->seed.nprops = 0;
    t->seed.props_valid = 0;
    for (size_t qi = 0; qi < D2K_QTRACE_MAX; qi++) {
        const d2k_quic_step *st = &r->qtrace[qi];
        if (!st->label[0]) { continue; }
        t->seed.props[t->seed.nprops++] = *st;
    }
    if (t->seed.nprops > 0 && r->repeats > 0) {
        t->seed.props_valid = 1;
        t->seed.props_repeats = r->repeats;
        t->seed_input = seed_input_of(t->trig, t->trig_len, t->ip, t->port);
        say(s, "по %s ответов вопросов о свойствах сохранено: %d — при перезапуске замера тем же "
               "входом они не переспрашиваются", t->name, t->seed.nprops);
    }
}

/* Испытываемый кандидат — ступень лестницы белого имени: имя из подбора или
   вариант разреза с приманкой сети. */
static int ladder_candidate_at(const task *t, size_t i) {
    if (i >= t->n_plans) return 0;
    if (t->net_probe_name[i][0]) return 1;
    uint64_t h = fnv1a(t->plans[i]);
    size_t n = t->n_rx_hashes < D2K_RX_VOLUME_PLAN_VARIANTS
        ? t->n_rx_hashes : D2K_RX_VOLUME_PLAN_VARIANTS;
    for (size_t k = 0; k < n; k++)
        if (t->rx_hashes[k] == h) return 1;
    return 0;
}
static int ladder_candidate(const task *t) {
    return t->next_plan ? ladder_candidate_at(t, t->next_plan - 1) : 0;
}

/* ПУТЬ НАХОДКИ ПОДТВЕРЖДАЕМОГО КАНДИДАТА (поле 10.10.2026, §0.1 ТЗ). Доля
   «перебора» считается по журналу; успех запасного перебора и RX-лестницы
   прежде писался без пути, и счёт видел только находки замера. Порядок —
   как у источника на панели: свой план коробки, затем приём замера с путём
   дерева, затем ступень RX-лестницы, затем запасной перебор. */
static const char *candidate_path(const task *t) {
    size_t i = t->next_plan ? t->next_plan - 1 : 0;
    if (t->n_known > 0 && t->next_plan <= t->n_known) return "свой план";
    uint64_t h = fnv1a(t->plans[i]);
    if (t->arm_hash && h == t->arm_hash) return t->arm_path[0] ? t->arm_path : "приём замера";
    size_t n = t->n_rx_hashes < D2K_RX_VOLUME_PLAN_VARIANTS
        ? t->n_rx_hashes : D2K_RX_VOLUME_PLAN_VARIANTS;
    for (size_t k = 0; k < n; k++)
        if (t->rx_hashes[k] == h) return "RX-лестница";
    if (t->fb_queue && i >= t->fb_from) return "перебор";
    return "вывод из замера";
}

/* One terminal row per admitted search, including failures. These are the
   existing scheduler accounting units, not a count of wire packets. They
   include measurement progress and candidate/question trials; a single
   verifier can perform more than one connection. Never label this as live
   application proof. Cross-search/run aggregation is a separate layer. */
static void search_report(d2k_sched *s, task *t, int64_t now_ms,
                          const char *outcome, const char *path, const char *why) {
    if (!t->report_id || t->report_closed) return;
    t->report_closed = 1;
    if (!strcmp(outcome, "unknown") || !strcmp(outcome, "inconclusive") ||
        !strcmp(outcome, "interrupted")) {
        char why[D2K_REASON_MAX];
        pthread_mutex_lock(&s->mu);
        snprintf(why, sizeof why, "%s", t->res.reason);
        pthread_mutex_unlock(&s->mu);
        unknown_note(s, t->by_addr ? "addr" : "name", t->by_addr ? t->ip : t->name, t->transport,
                     t->family, t->by_addr ? t->port : 0, outcome, why);
    }
    if (!s->say_fn && !s->diagnostic) return;
    if (!path) {
        path = "none";
        if (t->next_plan && t->next_plan <= t->n_plans) {
            const char *p = candidate_path(t);
            /* RX-лестница — перебор ИМЕНИ по замеренному обрыву ответа, а не
               запасной список оригинала (владелец, 14.10.2026: «белое имя к
               перебору не имеет отношения»). Своя подпись: иначе доля
               перебора в поле считала и её. */
            path = !strcmp(p, "свой план") || t->own_first == 2 ? "own-plan" :
                   !strcmp(p, "RX-лестница") ? "ladder" :
                   !strcmp(p, "перебор") ? "fallback" : "property";
        }
    }
    pthread_mutex_lock(&s->mu);
    int measured = t->ask_probes;
    pthread_mutex_unlock(&s->mu);
    int64_t elapsed = t->report_admitted_ms >= 0 && now_ms >= t->report_admitted_ms
        ? now_ms - t->report_admitted_ms : -1;
    int64_t queued = t->report_queue_ms;
    if (t->state == T_QUEUED && s->clock_seen && now_ms >= t->queued_ms)
        queued += now_ms - t->queued_ms;
    char line[1024];
    const char *proto = t->stun_target ? "stun" : t->transport == 6 ? "tcp" :
        !strcmp(outcome, "stun-confirmed") ? "stun" :
        !strcmp(outcome, "discovery-confirmed") ? "discovery" :
        is_voice_class(t->name, t->transport) || t->trigger_shape == D2K_LINK_SHAPE_VOICE
            ? "udp" : "quic";
    if (s->diagnostic) {
        /* Result fields are published by workers under the same mutex. */
        char reason[D2K_REASON_MAX];
        pthread_mutex_lock(&s->mu);
        snprintf(reason,sizeof reason,"%s",t->res.reason);
        pthread_mutex_unlock(&s->mu);
        d2k_diag_event e={.id=t->report_id,.target=t->name,.protocol=proto,
            .family=t->family,.trigger=t->trigger_code,.outcome=outcome,.reason=reason,
            .elapsed_ms=elapsed,.queue_ms=queued,.probe_units=(int64_t)t->probes+measured,
            .ip=t->ip,.path=path,.kind=t->by_addr?"addr":"name",.shape=t->trigger_shape,
            /* Причина ИТОГА — из точки его объявления, а не последняя фраза
               классификатора: в диагностике 23.10 они противоречили друг другу
               в 18 событиях из 61. Фраза классификатора остаётся рядом
               контекстом (.reason выше). */
            .outcome_reason=why?why:"",
            /* Идентичность решения: без неё «own-plan подтверждён» по
               одиннадцати именам не сверить с каталогом. */
            .plan_id=t->bound_plan_id,.box_id=t->box_id};
        s->diagnostic(s->diagnostic_ctx,&e);
    }
    if (!s->say_fn) return;
    snprintf(line, sizeof line,
        "итог поиска: search=%llu target=%s protocol=%s family=%u "
        "outcome=%s path=%s probe_units=%lld accounting=scheduler "
        "elapsed_ms=%lld queue_ms=%lld live=unknown box=%s plan=%s why=%s",
        (unsigned long long)t->report_id, t->name, proto,
        (unsigned)t->family, outcome, path, (long long)t->probes + measured,
        (long long)elapsed, (long long)queued,
        t->box_id[0] ? t->box_id : "-", t->bound_plan_id[0] ? t->bound_plan_id : "-",
        why ? why : "-");
    s->say_fn(s->say_ctx, line);
}

static void verify_confirm(d2k_sched *s, task *t, int64_t now_ms) {
    if(newchain_task(s,t)) {t->stop=1;task_done(s,t);return;}

    /* DNS promotion requires the candidate's exact APPLIED receipt and the
       complete durable DNS contract, never an HTTP or handshake success. */
    if(encrypted_dns_task(t) && (!t->ver_ok || !dns_application_proved(&t->ver) ||
       dns_non_path_failure(&t->ver) ||
       (!t->dns_dot && (!t->ver.doh_http_version ||
        (t->dns_expected_http && t->dns_expected_http!=t->ver.doh_http_version))))) {
        say(s,"по %s DNS-сервис не подтверждён применением и полным DNS-контрактом с проверкой TLS",t->name);
        trial_retire(s,t);ver_close(t);t->state=T_PLANNING;return;
    }

    if(t->synthesis_generation && synthesis_report(s,t,0)!=D2K_VF_OBSERVED) {
        say(s,"по %s синтезированный кандидат не подтверждён своим испытанием приложения "
              "(проверка %d, владелец %d, HTTP %d, полный ответ %d, применение %d): %s",
            t->name,(int)t->synthesis_result,t->synthesis_owner!=NULL,t->ver.status,
            t->ver.body_complete,t->ver_ok,t->ver.reason);
        trial_retire(s,t);ver_close(t);t->state=T_PLANNING;
        return;
    }

    const char *text = t->plans[t->next_plan - 1];
    char plan_id[40], box_id[40];
    int props_conflicts = 0;
    uint8_t wire_id[D2K_PLAN_ID_LEN];
    plan_ident(text, plan_id, sizeof plan_id, wire_id);
    /* Этап 23: сколько своих кандидатов у каждой идущей классификации БЫЛО до
       этого подтверждения. Уступить замер ей стоит, только если подтверждение
       добавило ей нового кандидата (тот же транспорт/семейство/форма, текст не
       испытан) — чужое по транспорту подтверждение (QUIC при TCP-замере, поле
       28.10.2026) лишь перепроверяло бы старых кандидатов и теряло дерево. */
    size_t own_before[SCHED_MAX_TASKS];
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        task *ot = &s->tasks[i];
        own_before[i] = (ot != t && ot->state == T_ASKING && ot->th_live && !ot->yield_to_own_plan)
                        ? own_first_plans(s, ot, 0) : (size_t)-1;
    }
    budget_uncountable_note(s, t);
    if (!t->partial_finishing &&
        t->own_first == 2 && t->bound_plan_id[0] && !strcmp(t->bound_plan_id, plan_id) &&
        t->ver.budget != D2K_BUDGET_PASSED) {
        /* ПЛАН, ПОД КОТОРЫМ ШЁЛ ПОТОК ПОДОЗРЕНИЯ, снимает подозрение ТОЛЬКО
           пройденным бюджетом (ревью I-2). «Не применимо» — не измерение:
           переподтверждать нечем, поиск не кончается. Дальше свои планы без
           него, как до задачи 55; отметка привязки не трогается. */
        say(s, "по %s план %s, под которым шёл поток подозрения, ответил, но бюджет не проверен "
               "(%s) — подозрение не снято, план не переподтверждаю, продолжаю свои планы без него",
            t->name, plan_id, t->ver.budget_note[0] ? t->ver.budget_note : "проверки не было");
        trial_retire(s, t); ver_close(t); t->state = T_PLANNING;
        return;
    }
    /* ЛЕСТНИЦА БЕЛОГО ИМЕНИ ПО ОДНОМУ ОБРЫВУ ИСХОДЯЩЕЙ ЛЕСТНИЦЫ (ревью Astra
       R1). Короткий полный ответ (spzh: 403 на 4540 Б) и «бюджет не применим»
       не говорят, снят ли этот обрыв; доказательство — пройденный бюджет
       потока. Без него ступень не подтверждается и белое имя сети не
       записывается. Прочие кандидаты TX-обрыва — как в выпуске. */
    if (!t->partial_finishing && t->transport == 6 &&
        t->vol.verdict == D2K_VOL_CUT && !t->vol.rx_cut && ladder_candidate(t) &&
        (t->ver.budget == D2K_BUDGET_NOT_APPLICABLE || t->ver.budget == D2K_BUDGET_CUT ||
         (t->ver.budget != D2K_BUDGET_PASSED && t->ver.conn_close))) {
        say(s, "по %s план %s: приложение ответило %d, но измерен обрыв исходящей лестницы "
               "около %d КБ, а бюджет потока не пройден (%s) — снятие обрыва не доказано, "
               "кандидата не подтверждаю", t->name, plan_id, t->ver.status, t->vol.at_kb,
            t->ver.budget_note[0] ? t->ver.budget_note : "проверки не было");
        if (t->ver.budget != D2K_BUDGET_CUT) {
            /* Бюджет на этой цели не измерить (ответ закрыл соединение, счёт
               недоступен): остальные ступени подтвердить так же нечем — не
               гонять их все, дальше обычные кандидаты (как в выпуске). */
            t->ladder_unmeasurable = 1;
            t->rx_volume_candidate_pending = 0;
            t->net_probing = 0;
            say(s, "по %s бюджет потока на этой цели не измерить — лестницу белого имени "
                   "по исходящему обрыву прекращаю, дальше обычные кандидаты", t->name);
        }
        trial_retire(s, t); ver_close(t); t->state = T_PLANNING;
        return;
    }
    if (t->transport == 17 && t->quic_ech &&
        (!t->ver.replay_proof || t->ver.level != D2K_VER_HANDSHAKE)) {
        say(s, "по %s QUIC-план для ECH не подтверждён: нет ответа на повтор пачки клиента",
            t->name);
        trial_retire(s, t); ver_close(t); t->state = T_PLANNING; return;
    }
    if (t->ech_offer && t->ech_replay) {
        /* Свидетеля нет: доказательство — только ServerHello на повтор байт
           клиента под планом. Принятый ECH и ответ origin здесь не
           измеримы (нет ключей клиента) и не подразумеваются. */
        if (!t->ver.replay_proof || t->ver.level != D2K_VER_HANDSHAKE) {
            say(s, "по %s ECH-план не подтверждён: нет ServerHello на повтор приветствия клиента",
                t->name);
            trial_retire(s, t); ver_close(t); t->state = T_PLANNING; return;
        }
    } else if (t->ech_offer && (!t->ver.ech_accepted || t->ver.name_ok != 1 ||
        t->ver.level != D2K_VER_APPLICATION || !t->ver.body_complete)) {
        say(s, "по %s ECH-план не подтверждён принятым ECH и полным ответом origin", t->name);
        trial_retire(s, t); ver_close(t); t->state = T_PLANNING; return;
    }
    /* НЕПЕРЕНОСИМОСТЬ ПЕРЕВЕШИВАЕТ УСПЕХ ЗОНДА.
       Пока шло испытание, тот же план применялся и к потокам настоящих
       клиентов — план стоит на цели целиком. Если хотя бы одному из них он
       не исполнился ПОСТОЯННОЙ причиной, записывать его подтверждённым
       нельзя: опыт зонда состоялся, а человеку этот план не достанется
       (лаборатория 13.09.2026, седьмая находка). Кандидат при этом не
       виноват и в каталог не идёт ничего — ни положительного, ни
       отрицательного (§10). Берём следующего: он может подойти обоим. */
    /* Shared frontends may legitimately return a default certificate.
       Explicit HTTP denial is rejected before confirmation; SAN mismatch
       alone cannot distinguish that denial from a usable response. */
    if (t->ver.name_ok == 0) {
        say(s, "по %s план %s: сертификат не совпал с запрошенным именем; "
               "это диагностический признак, не доказательство заглушки",
            t->name, plan_id);
    }
    if (t->transport == 17 && quic_text_is_split(text) && quic_split_unfit(s, t)) {
        /* Зонд шлёт ClientHello одной датаграммой, и разрез ему исполнился;
           клиенту этой цели — нет (финальное ревью core, I1). */
        say(s, "по %s план %s (разрез CRYPTO) зонду исполнился, а клиенту — нет: "
               "его ClientHello шире датаграммы. Подтверждать не буду, беру "
               "следующего кандидата", t->name, plan_id);
        trial_retire(s, t);
        ver_close(t);
        t->state = T_PLANNING;
        return;
    }
    int unfit_here = 0;
    for (size_t k = 0; k < t->unfit_seen; k++) {
        if (memcmp(t->unfit_plan_id[k], wire_id, D2K_PLAN_ID_LEN) == 0 ||
            memcmp(t->unfit_plan_id[k], t->ver_plan_id, D2K_PLAN_ID_LEN) == 0) {
            unfit_here = 1;
            break;
        }
    }
    if (unfit_here) {
        say(s, "по %s план %s зонду исполнился, а потоку клиента — нет "
               "(не помещается в посылку либо поток не несёт того, что план "
               "требует). Подтверждать не буду: обход, "
               "который не достаётся человеку, обходом не является. "
               "Беру следующего кандидата",
            t->name, plan_id);
        trial_retire(s, t);
        ver_close(t);
        t->state = T_PLANNING;
        return;
    }
    box_id_for(s, t, text, box_id, sizeof box_id);
    /* Контекст: проверку вёл СОБСТВЕННЫЙ зонд и СВОЕЙ формой приветствия
       (SCHED_PROBE_SHAPE). Записывается вместе с успехом, а не выводится
       потом: через день по файлу будет не восстановить, чем именно он
       добыт. */
    /* ФОРМА — ТА, КОТОРОЙ ГОВОРИЛ ЗОНД, а она теперь равна форме КЛИЕНТА:
       со старым клиентом зонд ведёт рукопожатие TLS 1.2 (d2k_verify_probe12_on).
       Неразобранное приветствие означает, что зонд пошёл современным, — и
       записывается современная форма, а не «не знаю». */
    uint8_t rec_shape = record_shape(t);
    /* ЧЕМ ГОВОРИЛ ЗАМЕР, ИЗ КОТОРОГО ЭТОТ ПЛАН ВЫВЕДЕН. Не то же, что форма:
       форма у заготовки и у снимка может совпадать, а байты — нет, и коробке
       никто не запрещал смотреть на содержимое (§6). */
    /* Свой план другой цели, проверенный здесь зондом до полного замера
       (задача 32), выведен НЕ замером этой цели: его вход — перенос. */
    int transferred = t->own_first == 2;
    uint8_t rec_input = record_input(t);
    /* QUIC С ECH — ПРИВЯЗКА К АДРЕСУ, А НЕ К ВНЕШНЕМУ ИМЕНИ (поле 15.10.2026).
       При ECH все цели Cloudflare приходят к датапату под одним именем
       cloudflare-ech.com, и привязка этого имени раздавала ОДИН план,
       измеренный на одном адресе, всем сразу: rutracker, lostfilm и enimerosi
       он открывал (28-79 КБ по QUIC на проводе), а katzauction, spzh и
       nnmclub — нет, у них адреса другие. Имя тут не различает цели, адрес
       различает: привязываем к нему, и каждый адрес получает СВОЙ измеренный
       план. Поиск по-прежнему идёт по имени — меняется только то, чем
       помечено доказательство. */
    int quic_ech_bind = t->transport == 17 && t->quic_ech && !t->by_addr && t->ip[0];
    if (quic_ech_bind) {
        /* Старая привязка этого имени ушла бы вперёд адресной (имя ищется
           первым, plans.c) и закрыла бы её собой. */
        for (size_t bi = 0; bi < s->cat->n_boxes; bi++) {
            d2k_cat_box *b = &s->cat->boxes[bi];
            for (size_t j = 0; j < b->n_binds;) {
                d2k_cat_binding *bd = &b->binds[j];
                if (!strcmp(bd->kind, "name") && bd->transport == 17 &&
                    bd->family == t->family && !strcmp(bd->target, t->name)) {
                    memmove(bd, bd + 1, (b->n_binds - j - 1) * sizeof *bd);
                    b->n_binds--;
                    b->updated = wall_s(s, now_ms);
                    continue;
                }
                j++;
            }
        }
        say(s, "по %s (QUIC, ECH) доказательство привязываю к адресу %s: под внешним "
               "именем ECH приходят разные цели, и один план на имя раздавался всем",
            t->name, t->ip);
    }
    int dns_service = encrypted_dns_task(t);
    const char *rec_target = dns_service || quic_ech_bind ? t->ip : t->name;
    const char *rec_kind = dns_service ? "service" :
        (quic_ech_bind || t->by_addr) ? "addr" : "name";
    uint16_t rec_port = dns_service ? t->port : 0;
    if(dns_service) {
        /* Name lookup precedes exact endpoint lookup in the datapath. Retire
           the old broad authority on wire and retain its catalog knowledge. */
        for(size_t bi=0;bi<s->cat->n_boxes;bi++)for(size_t j=0;j<s->cat->boxes[bi].n_binds;j++) {
            d2k_cat_binding *bd=s->cat->boxes[bi].binds+j;
            if(!bd->enabled || strcmp(bd->kind,"name") || strcasecmp(bd->target,t->name) ||
               (bd->transport?bd->transport:6)!=6 || (bd->family?bd->family:4)!=t->family ||
               !d2k_cat_shape_fits(bd->shape,rec_shape))continue;
            char error[160];uint8_t shape=bd->shape?bd->shape:D2K_LINK_SHAPE_GRANDFATHER;
            if(d2k_link_del_name_family(s->link_fd,bd->target,6,shape,t->family,error,sizeof error)) {
                say(s,"по %s прежнюю привязку имени не удалось снять: %s",t->name,error);
                trial_retire(s,t);ver_close(t);t->state=T_PLANNING;return;
            }
            bd->enabled=0;bd->recheck_since=wall_s(s,now_ms);
            bd->recheck_mono_ms=now_ms?now_ms:1;s->cat->revision++;
        }
    }
    int binding_rc=bind_confirmed(s->cat, box_id, plan_id, text,
                         t->transport == 17 ? "quic" : "tls",
                         rec_target, rec_kind,
                         t->transport, t->family, rec_shape, rec_port,
                         t->ver.replay_proof ? D2K_VERBY_REPLAY_HANDSHAKE :
                         t->ver.handshake_proof ? D2K_VERBY_PROBE_HANDSHAKE
                                                : D2K_VERBY_PROBE, rec_input,
                         /* Перенос не меняет отпечаток коробки плана: цель
                            этой коробкой не измерялась (задача 32, I1). По той
                            же причине перенос не приписывает ей и вектор
                            свойств: его измерили на этой цели, а личность
                            коробки взята с чужой записи. */
                         wall_s(s, now_ms), transferred ? NULL : &t->fp,
                         transferred ? NULL : &t->res.box_props, &props_conflicts);
    if(dns_service && binding_rc) {
        say(s,"по %s подтверждённый DNS-сервис не удалось сохранить",t->name);
        trial_retire(s,t);ver_close(t);t->state=T_PLANNING;return;
    }

    /* ЗНАНИЕ О КОРОБКЕ НАЗЫВАЕТСЯ ВСЛУХ. Иначе рост вектора не отличить от
       его отсутствия ни по журналу, ни по прибору, и экономия зондов на
       следующей цели выглядела бы случайной. */
    if (!transferred && d2k_box_props_any(&t->res.box_props)) {
        char pv[256];
        if (d2k_box_props_text(&t->res.box_props, pv, sizeof pv) > 0) {
            say(s, "по %s знание о коробке %s (форма %u): %s",
                t->name, box_id, (unsigned)rec_shape, pv);
        }
        if (props_conflicts > 0) {
            /* Замер разошёлся с записанным: поля стали неизмеренными, и это
               повод перемерить коробку, а не тихая правка файла (§0). */
            say(s, "по %s замер разошёлся с записанным знанием коробки %s в %d поле(ях) — "
                   "они снова не измерены, коробку надо перемерить",
                t->name, box_id, props_conflicts);
        } else if (props_conflicts < 0) {
            say(s, "по %s знание о коробке %s не записано: все %d места форм клиента заняты",
                t->name, box_id, D2K_CAT_PROPS_MAX);
        }
    }
    /* Блок доказан полным замером ИЛИ базовым вопросом донора перед своими
       планами (0/3 — рукопожатие режется): оба — опыт для семейства. Без
       второго семейства не учились бы на основном пути (поле 03.10). */
    if (t->group_block_proven || (t->own_first == 2 && t->res.base_blocked))
        group_record(s, t, D2K_GROUP_BLOCKED_CONFIRMED, plan_id, rec_shape, now_ms);
    /* Подтверждение повтором (свидетеля нет) не стирает известного раньше
       свидетеля привязки: его HTTPS RR перепроверяется при каждом поиске. */
    if (t->ech_offer && t->ech_origin[0]) {
        for (size_t bi = 0; bi < s->cat->n_boxes; bi++) {
            d2k_cat_box *b = &s->cat->boxes[bi];
            if (strcmp(b->id, box_id)) continue;
            for (size_t j = 0; j < b->n_binds; j++) {
                d2k_cat_binding *bd = &b->binds[j];
                if (!strcmp(bd->target, t->name) && !strcmp(bd->plan_id, plan_id) &&
                    bd->family == t->family && bd->shape == rec_shape && bd->transport == 6) {
                    snprintf(bd->ech_origin, sizeof bd->ech_origin, "%s", t->ech_origin);
                    s->cat->revision++;
                }
            }
        }
    }
    /* ОТМЕТКА БЮДЖЕТА ПОТОКА (задача 55). Пройдено — сильнее всего и пишется
       всегда; «не применимо» ложится только на пустую отметку: оно не
       отменяет ни пройденного, ни оборванного (не измерено ≠ нет, §2.4); без
       проверки (рукопожатие ALPN) — ничего. */
    {
        uint8_t mark = t->ver.budget == D2K_BUDGET_PASSED ? D2K_CAT_BUDGET_PASSED :
                       t->ver.budget == D2K_BUDGET_NOT_APPLICABLE ? D2K_CAT_BUDGET_UNCHECKED :
                       t->ver.budget == D2K_BUDGET_CUT ? D2K_CAT_BUDGET_CUT : 0;
        for (size_t bi = 0; mark && bi < s->cat->n_boxes; bi++) {
            d2k_cat_box *b = &s->cat->boxes[bi];
            if (strcmp(b->id, box_id)) continue;
            for (size_t j = 0; j < b->n_binds; j++) {
                d2k_cat_binding *bd = &b->binds[j];
                if (!strcmp(bd->target, dns_service?rec_target:t->name) && !strcmp(bd->plan_id, plan_id) &&
                    !strcmp(bd->kind, dns_service?rec_kind:(t->by_addr?"addr":"name")) &&
                    (!dns_service || bd->server_port==rec_port) &&
                    (bd->family ? bd->family : 4) == t->family && bd->shape == rec_shape &&
                    bd->transport == t->transport &&
                    (mark == D2K_CAT_BUDGET_PASSED || bd->budget == 0 ||
                     (mark == D2K_CAT_BUDGET_CUT && bd->budget != D2K_CAT_BUDGET_PASSED)) &&
                    bd->budget != mark) {
                    bd->budget = mark;
                    s->cat->revision++;
                }
            }
        }
    }
    if (dns_service || t->measure_path[0]) {
        for (size_t bi = 0; bi < s->cat->n_boxes; bi++) {
            d2k_cat_box *b = &s->cat->boxes[bi];
            if (strcmp(b->id, box_id)) continue;
            for (size_t j = 0; j < b->n_binds; j++) {
                d2k_cat_binding *bd = &b->binds[j];
                if (!strcmp(bd->target, dns_service?rec_target:t->name) && !strcmp(bd->plan_id, plan_id) &&
                    (dns_service ? (!strcmp(bd->kind,rec_kind) && bd->server_port==rec_port) : !bd->dns_name[0]) &&
                    bd->family == t->family && bd->shape == rec_shape && bd->transport == t->transport) {
                    snprintf(bd->probe_path, sizeof bd->probe_path, "%s", dns_service?t->doh_path:t->measure_path);
                    if (dns_service) {
                        bd->dns_authenticated=1;
                        bd->dns_dot=t->dns_dot;
                        bd->dns_http_version=t->ver.doh_http_version;
                        snprintf(bd->dns_name,sizeof bd->dns_name,"%s",t->name);
                        bd->dns_port=t->port;
                        snprintf(bd->dns_address,sizeof bd->dns_address,"%s",t->ip);
                    } else {
                        bd->dns_authenticated=0;bd->dns_dot=0;bd->dns_http_version=0;
                        bd->dns_port=0;bd->dns_address[0]=0;bd->dns_name[0]=0;
                    }
                    s->cat->revision++;
                    if (dns_service) s->encrypted_dns_revision = s->cat->revision;
                }
            }
        }
    }
    if (t->by_addr) {
        uint8_t addr[16] = {0};
        char err[160], permanent_wire[sizeof t->plans[0]];
        char permanent_hex[2 * D2K_PLAN_TLV_MAX + 1];
        err[0] = '\0';
        snprintf(permanent_wire, sizeof permanent_wire, "%s", text);
        if (stamp_plan_id(permanent_wire, wire_id) != 0 ||
            d2k_plan_text_to_hex(permanent_wire, permanent_hex,
                                 sizeof permanent_hex, err, sizeof err) != 0 ||
            inet_pton(t->family == 6 ? AF_INET6 : AF_INET, t->ip, addr) != 1 ||
            d2k_link_set_addr_family(s->link_fd, addr, t->family, rec_shape,
                                     permanent_hex, err, sizeof err) != 0) {
            if (!err[0]) { snprintf(err, sizeof err, "неверный адрес цели или отсутствует REC_ID"); }
            say(s, "по %s адресный план подтверждён, но не удалось продвинуть его в постоянную таблицу: %s",
                t->name, err);
        }
    }
    /* Запоминаем владельца подтверждённого плана. */
    snprintf(t->box_id, sizeof t->box_id, "%s", box_id);
    s->confirms++;
    unknown_resolve(s, t->by_addr ? t->ip : t->name, t->transport, t->family, t->port);
    /* ПОДБОР БЕЛОГО ИМЕНИ СЕТИ ЗАВЕРШЁН НАХОДКОЙ (поле 10.10.2026). Если
       подтверждённый план пришёл из перебора имён-кандидатов, его приманка и
       есть белое имя сети: записываем в каталог как свойство сети, с меткой
       времени для повторной проверки при деградации. Больше не перебираем. */
    if (t->net_probing && t->next_plan > 0 && t->net_probe_name[t->next_plan - 1][0] &&
        (t->vol.rx_cut || t->ver.budget == D2K_BUDGET_PASSED)) {
        d2k_net_whitelist *nw = &s->cat->net;
        snprintf(nw->name, sizeof nw->name, "%s", t->net_probe_name[t->next_plan - 1]);
        /* ДОКАЗАТЕЛЬСТВО СВЯЗЫВАЕТСЯ С ТИПОМ ОБРЫВА (поле 23.10.2026). Подбор
           закрывает только проход ВХОДЯЩЕГО обрыва: поле определено как имя,
           под которым коробка пропускает поток за RX-обрыв. Проход исходящей
           лестницы имя запоминает — он настоящая находка для этой цели, — но
           подбор держит открытым: иначе цели с входящим обрывом наследуют
           имя, против их обрыва не проверенное (семь целей, тела 13–17 КБ при
           ответе 200). */
        nw->tx_only = t->vol.rx_cut ? 0 : 1;
        nw->searched = t->vol.rx_cut ? 1 : 0;
        nw->confirmed_at = wall_s(s, now_ms);
        s->cat->revision++;
        s->sync_pending = 1;
        t->net_probing = 0;
        say(s, "по %s белое имя сети подобрано: «%s» снимает %s — сохраняю как "
               "свойство сети, %s", t->name, nw->name,
            t->vol.rx_cut ? "RX-обрыв" : "обрыв исходящей лестницы (бюджет потока пройден)",
            t->vol.rx_cut ? "подбор больше не повторяю"
                          : "но подбор остаётся открытым: входящий обрыв этим именем "
                            "не проверялся");
    }
    if (t->ver.replay_proof && t->transport == 17)
        say(s, "по %s (QUIC, ECH) ПОДТВЕРЖДЕНО повтором пачки клиента на уровне "
               "рукопожатия: %s (путь: %s) — сервер ответил нашему соединению под планом "
               "(план применён к потоку зонда); без ключей клиента прикладной уровень не измерен",
            t->name, plan_id, candidate_path(t));
    else if (t->ver.replay_proof)
        say(s, "по %s (TCP, ECH) ПОДТВЕРЖДЕНО повтором приветствия клиента на уровне "
               "рукопожатия: %s (путь: %s) — ServerHello под планом (план применён к потоку "
               "зонда); без ключей клиента прикладной уровень не измерен",
            t->name, plan_id, candidate_path(t));
    else if (t->ver.handshake_proof)
        say(s, "по %s (TCP) ПОДТВЕРЖДЕНО собственным зондом на уровне рукопожатия: %s "
               "(путь: %s) — TLS с ALPN клиента завершён (план применён к потоку зонда); "
               "протокол клиента не HTTP, прикладной уровень не измерен",
            t->name, plan_id, candidate_path(t));
    else
    say(s, "по %s (%s) ПОДТВЕРЖДЕНО собственным зондом: %s (путь: %s), приложение "
           "ответило %d (план применён к потоку зонда)",
        t->name, t->transport == 17 ? "QUIC" : "TCP", plan_id, candidate_path(t),
        t->ver.status);
    /* Одна строка на подтверждение: пакеты и исход проверки бюджета. */
    if (t->ver.replay_proof)
        say(s, "по %s бюджет потока не применим (задача 55): %s — привязка помечена "
               "«бюджет не проверен»", t->name, t->ver.budget_note);
    else if (t->ver.budget == D2K_BUDGET_PASSED || t->ver.budget == D2K_BUDGET_NOT_APPLICABLE)
        say(s, "по %s бюджет потока %s: %u пакетов с данными из нужных %u за %u запросов "
               "(бюджет %u — %s): %s", t->name,
            t->ver.budget == D2K_BUDGET_PASSED ? "пройден" : "не проверен",
            t->ver.budget_packets, t->ver.budget_need, t->ver.budget_requests,
            t->budget_pk, t->budget_src, t->ver.budget_note);
    else if (t->ver.budget == D2K_BUDGET_CUT)
        say(s, "по %s частичный обход: рукопожатие снято, поток режется после ~%u пакетов "
               "(нужно %u, бюджет %u — %s); привязка помечена «оборван», лучший план её заменит",
            t->name, t->ver.budget_packets, t->ver.budget_need, t->budget_pk, t->budget_src);
    else
        say(s, "по %s бюджет потока не проверялся (%s)", t->name,
            t->ver.handshake_proof ? "протокол клиента не HTTP" : "проверку не просили");
    if (!t->partial_finishing) t->partial_valid = 0; /* поиск кончился полным обходом */
    if (transferred && t->bound_plan_id[0] && !strcmp(t->bound_plan_id, plan_id) &&
        t->ver.budget == D2K_BUDGET_PASSED) {
        if (t->trigger_executed_plan[0] && !strcmp(t->trigger_executed_plan, plan_id)) {
            say(s, "по %s план %s из потока подозрения переподтверждён зондом "
                   "с проверкой бюджета; сбой клиента этим не воспроизведён", t->name, plan_id);
            if (t->trigger_planned == D2K_LINK_PLANNED_YES) proof_record(s, t, plan_id, now_ms);
        } else {
            say(s, "по %s план %s прошёл проверку бюджета зондом; его исполнение "
                   "в исходном потоке не подтверждено — причину сбоя клиента не устанавливаю",
                   t->name, plan_id);
        }
    }
    /* ЧЕЙ КЛИЕНТ ЗАВЁЛ ПОИСК — ТОТ ПРОТОКОЛ И ПОДТВЕРДИЛ.
     *
     * Раньше здесь стояла оговорка: замер идёт приветствием клиента, а
     * подтверждает зонд TLS 1.3, и для старого клиента план записывался под
     * чужую форму — по ключу формы он такого плана не получал вовсе.
     * Оговорка называла разрыв, но не закрывала его. Теперь со старым
     * клиентом зонд ведёт рукопожатие TLS 1.2 (d2k_verify_probe12_on), и
     * привязка пишется под ЕГО форму. Говорим об этом вслух — не как об
     * оговорке, а как о факте, который потом придётся сопоставлять с
     * каталогом. */
    /* ГРАНИЦА ЭТОГО ДОКАЗАТЕЛЬСТВА НАЗЫВАЕТСЯ ВСЛУХ, а не подразумевается.
       Подтверждение всегда ведёт СОБСТВЕННОЕ рукопожатие зонда — чужой
       ClientHello ему не воспроизвести (core/verify.c). Значит байтами
       настоящего клиента приём может быть добыт только на ЗАМЕРЕ, и если
       замер шёл заготовкой холодного старта, то байты клиента не проверял
       никто. Это записано в привязке (input) и сказано здесь. */
    if (transferred) {
        say(s, "по %s свой план %s коробки %s перенесён и подтверждён собственным зондом "
               "до полного замера — классификацию не продолжаю", t->name, plan_id, box_id);
        t->own_first = 3;
    } else if (t->res.generated_input && t->trig_snapped) {
        say(s, "по %s прикладной замер использовал собственный ClientHello длиной снимка клиента; "
               "исходные байты клиента не проверены этим замером", t->name);
    } else if (!t->trig_snapped) {
        say(s, "по %s замер шёл ЗАГОТОВКОЙ холодного старта, а не снятыми байтами "
               "клиента: форма та же, содержимое — нет. Приём подтверждён, но "
               "байтами клиента его не проверял никто — повторю поиск, как "
               "только датапат снимет приветствие этой цели", t->name);
    }
    if (t->transport == 6 && d2k_hello_shape(t->trig, t->trig_len) == D2K_SHAPE_LEGACY) {
        say(s, "по %s подтверждение вёл зонд СТАРОЙ формы (TLS 1.2) — тем же протоколом, "
               "что и клиент, и привязка записана под неё", t->name);
    }
    /* Решение принято — только теперь сокет зонда можно закрыть: до этого FIN
       удалил бы ячейку потока в датапате раньше события применения
       (см. d2k_props_contact). */
    /* Подтверждённое встаёт ПОСТОЯННОЙ записью (адрес — выше, имя — проходом
       каталога ниже). Пробная запись порта зонда своё отслужила и снимается
       точно (задача 20): прежде trial_installed просто обнулялся, и запись
       по уже свободному порту стояла до LRU, вытесняя подтверждённое. */
    search_report(s, t, now_ms,
                  t->partial_finishing || t->ver.budget == D2K_BUDGET_CUT
                      ? "probe-partial" : "probe-confirmed", transferred ? "own-plan" : NULL,
                  t->ver.budget == D2K_BUDGET_CUT
                      ? "кандидат подтверждён зондом, но бюджет потока оборвал ответ"
                      : t->partial_finishing
                      ? "кандидат подтверждён зондом частично: обход неполный"
                      : transferred
                      ? "перенесённый план коробки подтверждён собственным зондом"
                      : "кандидат подтверждён собственным зондом на проводе");
    trial_retire(s, t);
    ver_close(t);
    t->state = T_WATCHING;
    /* Кооперативный выход из долгой классификации: если соседняя задача в T_ASKING
       всё ещё крутит классификатор, а подтверждённый план совместим с её формой,
       просим её уступить место проверке готового решения (§3.4, §5). */
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        task *ot = &s->tasks[i];
        if (ot == t || ot->state != T_ASKING || !ot->th_live || ot->yield_to_own_plan)
            continue;
        pthread_mutex_lock(&s->mu);
        int ot_ready = ot->res_ready;
        pthread_mutex_unlock(&s->mu);
        if (ot_ready) continue;
        if (own_before[i] == (size_t)-1) continue;
        if (ot->own_first != 1 && own_first_plans(s, ot, 0) > own_before[i]) {
            ot->yield_to_own_plan = 1;
            ot->stop = 1;
            say(s, "по %s замер прерывается: в каталоге появился подтверждённый план — "
                   "перехожу к его проверке", ot->name);
        }
    }
    /* ТОТ ЖЕ ПОВОД — И ДЛЯ ЦЕЛЕЙ, КОТОРЫЕ УЖЕ ОТДОХНУЛИ (24.10.2026).
     *
     * Цикл выше трогает только задачи в T_ASKING с живым потоком. Поле
     * 24.10.2026, soundcloud.com: во ВСЕХ шести кругах его поиск кончался
     * неудачей за минуту, а через полторы минуты clubtone подтверждал
     * plan-680fbe00 для ТОЙ ЖЕ коробки. Отдохнувшую цель это знание не
     * догоняло, и рабочий план она получала только от следующего запроса
     * пользователя — который сам и погибал: подтверждение приходило через
     * 5–7 с после его смерти. Четыре провала страницы из шести кругов — ровно
     * этот разрыв.
     *
     * Поэтому новое подтверждение поднимает поколение знания, а остывшие цели
     * получают по ОДНОЙ проверке на поколение (plan_news_tick). */
    s->plan_gen++;
    s->plan_news = 1;
    /* Подтверждение — это новое знание, и датапат обязан узнать о нём сразу,
       а не после следующего запуска (та же причина, по которой Sync на
       Go-стороне зовётся «при запуске И после каждого подтверждения»). Но
       ЗАКАЗЫВАЕМ проход, а не делаем его здесь: залп команд из разбора
       события создал бы то самое окно слепоты, ради устранения которого
       проход и разложен на порции. */
    s->sync_pending = 1;
    /* СНИМОК ПРИШЁЛ, ПОКА ШЛО ИСПЫТАНИЕ. Повтор после замера к этому времени
       уже прошёл, а крючок наблюдения (on_shape) ловит только снимки,
       пришедшие ПОСЛЕ подтверждения. Без этой проверки привязка легла бы
       заготовкой при настоящих байтах на руках. */
    if (!transferred && !t->trig_snapped && t->transport == 6 &&
        s->tcp_shape_len[t->family == 6] > 0 &&
        strcmp(s->tcp_shape_name[t->family == 6], t->name) == 0) {
        remeasure_snapped(s, t, s->tcp_shape[t->family == 6], s->tcp_shape_len[t->family == 6]);
    }
}

/* Тот ли это идентификатор, с которым кандидат ушёл на провод.
 *
 * Нули в событии означают «плану нечем представиться» (d2k_link.h): либо
 * датапат старый, либо в тексте плана не нашлось строки id. Сверяем с тем,
 * что записали в план САМИ (install_next). Отсутствующий идентификатор
 * доказательством применения кандидата быть не может. */
/* КОНЕЦ ПОИСКА БЕЗ ПРОХОДЯЩЕГО БЮДЖЕТ ПЛАНА (решение 04.10): лучший
   частичный обход подтверждается — человек получает снятый блок
   рукопожатия (малые обмены, как у программы обновления Discord, умещаются
   в бюджет), привязка помечена «оборван» (установка ставит её после любой
   прошедшей и непроверенной), а повторный поиск — не раньше отдыха задачи:
   следующее подозрение под этим планом проверит его первым, и проходящий
   бюджет план его заменит. 1 — подтверждено, задача уже в T_WATCHING. */
static int partial_finish(d2k_sched *s, task *t, int64_t now_ms) {
    if (encrypted_dns_task(t) || !t->partial_valid) return 0;
    trial_retire(s, t);
    ver_close(t);
    snprintf(t->plans[0], sizeof t->plans[0], "%s", t->partial_text);
    snprintf(t->plan_boxes[0], sizeof t->plan_boxes[0], "%s", t->partial_box);
    snprintf(t->box_id, sizeof t->box_id, "%s", t->partial_box);
    t->n_plans = 1;
    t->next_plan = 1;
    t->ver = t->partial_ver;
    t->ver.fd = -1;
    say(s, "по %s проходящего бюджет плана не нашлось — беру лучший частичный обход "
           "(~%u пакетов до обрыва)", t->name, t->partial_pk);
    t->partial_finishing = 1;
    verify_confirm(s, t, now_ms);
    t->partial_finishing = 0;
    t->partial_valid = 0;
    cooldown_record(s, t, 2);
    say(s, "по %s повторная проверка частичного обхода — не раньше чем через %lld мин",
        t->name, (long long)(SCHED_INCOMPLETE_BACKOFF_MS / 60000));
    return 1;
}

static int plan_id_is_ours(const task *t, const d2k_ev *ev) {
    uint8_t present = 0;
    for (size_t i = 0; i < D2K_PLAN_ID_LEN; i++) { present |= ev->plan_id[i]; }
    if (!present) { return 0; } /* an absent identity never proves application */
    return memcmp(ev->plan_id, t->ver_plan_id, D2K_PLAN_ID_LEN) == 0;
}

/* An exact flow and plan can recur. Only the current installation's trial
 * binds a completion to this experiment, before or after verifier return. */
static int applied_trial_is_ours(const task *t,const d2k_ev *ev) {
    uint8_t present=0;
    for(size_t i=0;i<D2K_TRIAL_ID_LEN;i++)present|=ev->trial_id[i];
    return present && candidate_trial_matches(t,t->raw_measure_request.generation?D2K_CMD_SET_RAW_PROBE:
                                                addr_udp(t)?D2K_CMD_SET_ADDR_PROBE:
                                                D2K_CMD_SET_NAME_PROBE,ev->trial_id);
}

/* Применение НАШЕГО кандидата к НАШЕЙ цели? Полный ключ сверим после зонда. */
static int applied_of_candidate(const task *t, const d2k_ev *ev) {
    if ((ev->family ? ev->family : 4) != t->family) { return 0; }
    if (ev->transport != t->transport || !plan_id_is_ours(t, ev)) { return 0; }
    if (addr_udp(t) && memcmp(ev->trial_id, t->addr_probe_trial_id,
                             D2K_TRIAL_ID_LEN) != 0) { return 0; }
    char ip[INET6_ADDRSTRLEN];
    (void)inet_ntop(t->family == 6 ? AF_INET6 : AF_INET, ev->low_ip, ip, sizeof ip);
    if (ev->low_port == t->port && strcmp(ip, t->ip) == 0) {
        return 1;
    }
    (void)inet_ntop(t->family == 6 ? AF_INET6 : AF_INET, ev->high_ip, ip, sizeof ip);
    if (ev->high_port == t->port && strcmp(ip, t->ip) == 0) {
        return 1;
    }
    return 0;
}

/* Кандидат доехал до какого-то соединения — ПОЛОВИНА доказательства: план
   тронул ЭТИ пакеты. Вторая половина у зонда (дошло ли по ним до приложения),
   и по отдельности ни одна успехом не является — см. шапку файла.

   Транспорт здесь больше НЕ фильтруется. Фильтр «только TCP» стоял, пока
   молчание считалось уликой против кандидата: событие обмена у QUIC-потока
   прийти не может структурно (datapath/session.c, handle_udp возвращается
   раньше хвоста со счётом обменов), и QUIC-кандидат выбрасывался бы по
   молчанию, которого не могло не быть. Счёт молчаливых применений снят —
   кандидата судит зонд, — а применение датапат журналирует для обоих
   транспортов (обе ветки session.c), и ключ потока с транспортом сверяет
   ev_matches_flow. */
static void on_exchange(d2k_sched *s, const d2k_ev *ev);

static void on_applied(d2k_sched *s, const d2k_ev *ev) {
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        task *t = &s->tasks[i];
        if (t->state == T_RAW_TRIAL) {
            /* Опыт применился к повтору ИМЕННО этого клиентского потока и
               ИМЕННО нашим планом — дальше ждём ответа сервера на него. */
            if (!ev->execution_id || ev->transport != t->transport || !plan_id_is_ours(t, ev) ||
                !ev_matches_flow(ev, &t->trigger_flow) ||
                (addr_udp(t) && memcmp(ev->trial_id, t->addr_probe_trial_id, D2K_TRIAL_ID_LEN) != 0) ||
                (!addr_udp(t) && !applied_trial_is_ours(t, ev))) {
                continue; /* ИМЕННО это поколение пробы (trial): UDP — адресной, TCP — именной (этап 21) */
            }
            t->raw_execution_id = ev->execution_id;
            if(t->raw_early_reply_execution==ev->execution_id) {
                raw_confirm(s,t,s->now_ms);return;
            }
            t->state = T_RAW_WATCH;
            t->raw_until_ms = 0; /* срок ответа взводит первый тик после применения */
            say(s, "по %s:%u (поток без протокола) план применён к повтору клиента — жду ответа сервера",
                t->ip, (unsigned)t->port);
            return;
        }
        if (t->state == T_VOICE_TRIAL) {
            /* Приём голоса применяется только к исходной conntrack-пятёрке;
               общий class/name сам по себе недостаточен для доказательства. */
            if (ev->transport != 17 || !plan_id_is_ours(t, ev)) { continue; }
            /* У адресных QUIC-целей один и тот же план имеет один ID.
               Чужой адрес/порт не может выбрать эту задачу для WATCH:
               последующий EXCHANGE иначе подтвердит не ту цель.
               Голосовой Plan тоже ограничен точной conntrack-пятёркой. */
            if (addr_udp(t) && !applied_of_candidate(t, ev)) { continue; }
            /* Голос: та же пятёрка разговора И trial ID этого опыта. Новый
               пакет живого разговора приходит за окном приветствия, и
               признать его можно только по поколению опыта — один Plan ID
               опыта не называет (задача 15). */
            if (!addr_udp(t)) {
                /* Голос: trial ID этого опыта И клиент LAN + точка сервера
                   опыта; клиентский порт любой — это следующий поток того же
                   клиента (задача 15). Пятёрка этого потока становится
                   потоком наблюдения: доказательство ждётся на нём. */
                if (!voice_trial_owned(t) ||
                    memcmp(ev->trial_id, t->addr_probe_trial_id, D2K_TRIAL_ID_LEN) != 0 ||
                    (ev->family ? ev->family : 4) != 4) {
                    continue;
                }
                uint16_t dport = ntohs(t->addr_probe_dst_port_be);
                int server_low = memcmp(ev->low_ip, t->addr_probe_dst_ip, 4) == 0 &&
                                 ev->low_port == dport &&
                                 memcmp(ev->high_ip, t->addr_probe_src_ip, 4) == 0;
                int server_high = memcmp(ev->high_ip, t->addr_probe_dst_ip, 4) == 0 &&
                                  ev->high_port == dport &&
                                  memcmp(ev->low_ip, t->addr_probe_src_ip, 4) == 0;
                if (!server_low && !server_high) { continue; }
            }
            {
                memcpy(t->voice_flow.a_ip, ev->low_ip, 4);
                memcpy(t->voice_flow.b_ip, ev->high_ip, 4);
                t->voice_flow.a_port = ev->low_port;
                t->voice_flow.b_port = ev->high_port;
                t->voice_flow.transport = ev->transport;
            }
            t->voice_answered = 0;
            t->voice_proven = 0;
            t->voice_proof_code = 0;
            t->voice_execution_id = ev->execution_id;
            t->voice_execution_binding = ev->execution_binding;
            memcpy(t->voice_execution_plan_id,ev->plan_id,D2K_PLAN_ID_LEN);
            memcpy(t->voice_execution_trial_id,ev->trial_id,D2K_TRIAL_ID_LEN);
            t->voice_silent = 0;
            t->voice_watch_ms = 0;
            t->state = T_VOICE_WATCH;
            return;
        }
        if (t->state == T_PROPS_CONTACT) {
            /* Ключа потока вопроса ещё нет — копим применение ЭТОГО плана
               целиком; разберём при переходе в T_PROPS_WAIT. */
            if (memcmp(ev->plan_id, t->prop_plan_id, D2K_PLAN_ID_LEN) != 0) { continue; }
            int duplicate = 0;
            for (size_t k = 0; k < t->prop_early_seen; k++) {
                if (ev_matches_flow(ev, &t->prop_early[k])) { duplicate = 1; break; }
            }
            if (duplicate) { return; }
            if (t->prop_early_seen == sizeof t->prop_early / sizeof t->prop_early[0]) { continue; }
            d2k_flowkey *k = &t->prop_early[t->prop_early_seen++];
            memset(k, 0, sizeof *k);
            k->family = t->family;
            memcpy(k->a_ip, ev->low_ip, t->family == 6 ? 16 : 4);
            memcpy(k->b_ip, ev->high_ip, t->family == 6 ? 16 : 4);
            k->a_port = ev->low_port;
            k->b_port = ev->high_port;
            k->transport = ev->transport;
            return;
        }
        if (t->state == T_PROPS_WAIT) {
            /* Зонд вопроса: «применён» по КЛЮЧУ НАШЕГО потока И ПО ID НАШЕГО
               плана есть то доказательство, которого вопрос ждёт вместо
               подтверждения команды (см. prop_send_next). Одного ключа мало:
               на том же потоке мог примениться другой план — соседней задачи
               или прежней попытки. */
            if (t->prop_applied || !ev_matches_flow(ev, &t->prop_flow)) { continue; }
            if (memcmp(ev->plan_id, t->prop_plan_id, D2K_PLAN_ID_LEN) != 0) { continue; }
            t->prop_applied = 1;
            if (t->prop_reply_seen) {
                d2k_ev reply = t->prop_reply;
                t->prop_reply_seen = 0;
                on_exchange(s, &reply);
            }
            return;
        }
        if (t->state == T_VERIFY || t->state == T_TRIAL_SETTLE) {
            /* T_TRIAL_SETTLE — то же испытание, только зонд ещё не побежал:
               план уже стоит, и события о НЁМ приходят с этой же секунды.
               Пропустить их значило бы потерять улику ровно там, где она
               появляется раньше всего.
               Пока зонд работает, сохраняем полные ключи нескольких событий:
               чужое соединение может прийти первым и иметь тот же порт на
               другом клиенте. Переполнение теряет улику, но не создаёт успех. */
            if (!applied_trial_is_ours(t,ev) || !applied_of_candidate(t, ev)) { continue; }
            int duplicate = 0;
            for (size_t k = 0; k < t->ver_seen; k++) {
                if (ev_matches_flow(ev, &t->ver_early[k])) { duplicate = 1; break; }
            }
            if (duplicate || t->ver_seen == sizeof t->ver_early / sizeof t->ver_early[0]) {
                continue; /* saturation may lose evidence, never invent it */
            }
            d2k_flowkey *k = &t->ver_early[t->ver_seen++];
            k->family = t->family;
            memcpy(k->a_ip, ev->low_ip, t->family == 6 ? 16 : 4);
            memcpy(k->b_ip, ev->high_ip, t->family == 6 ? 16 : 4);
            k->a_port = ev->low_port;
            k->b_port = ev->high_port;
            k->transport = ev->transport;
            return;
        }
        if (t->state == T_VERIFY_WAIT) {
            /* Зонд вернулся, ключ его потока известен — сверяем точно. */
            if (!applied_trial_is_ours(t,ev) || !ev_matches_flow(ev, &t->ver_flow) ||
                !plan_id_is_ours(t, ev)) { continue; }
            t->ver_ok = 1;
            wake_loop(s);
            return;
        }
    }
}

/* ОТКАЗ С ПРИЧИНОЙ — не ответ коробки, а наша неудача.
 *
 * Нулевой код означает «причина не кодирована»: такой отказ приходит на
 * каждый транзитный поток, для цели которого плана нет, и к задачам поиска
 * отношения не имеет. Ненулевой (D2K_REFUSE_*) означает, что план применён,
 * но хотя бы одна операция не завершена: воздействие могло уйти ЧАСТИЧНО.
 *
 * Что с этим делает планировщик: отмечает, что ИСПЫТАНИЕ НЕ СОСТОЯЛОСЬ, и
 * оставляет разбор общему пути T_VERIFY_WAIT. Своё решение здесь принимать
 * нельзя — событие приходит вне тика, а смена состояния задачи живёт в
 * d2k_sched_tick; ровно поэтому и on_applied только помечает.
 *
 * Почему это не «кандидат не сработал»: выбросив его, поиск потерял бы
 * рабочий план из-за собственной поломки (MTU, очередь отправки), и записал
 * бы её свойством чужого устройства — тот самый разрыв из
 * docs/decisions/0006-proof-boundaries.md. */
/* ОТКАЗ НА ЧУЖОМ ПОТОКЕ — непереносимость, а не поломка коробки.
 *
 * Седьмая находка лаборатории 13.09.2026: подтверждение на зонде не равно
 * работе у клиента. Пробный или уже подтверждённый план стоит на ЦЕЛИ, и
 * действует он на все подключения к ней. Приветствие нашего зонда втрое
 * короче браузерного, поэтому при узком пределе отправки бывает так: куски
 * приветствия зонда помещаются — план исполняется и честно подтверждается
 * уровнем 3; куски приветствия браузера не помещаются — план ему не
 * исполняется. В каталоге «подтверждено», у человека обхода нет.
 *
 * Здесь разбирается только ПОСТОЯННЫЙ отказ (D2K_REFUSE_TOO_LONG): он
 * детерминирован — тот же план на приветствии той же длины даст тот же
 * исход, и говорить о переносимости по нему можно. Временный отказ (очередь,
 * ядро) ничего о переносимости не говорит и молча проходит мимо.
 *
 * Что делается: (1) факт считается; (2) он называется словами — по одному
 * разу на имя, иначе строка повторялась бы на каждом соединении браузера;
 * (3) если по этой цели ИДЁТ поиск, идентификатор непоместившегося плана
 * запоминается задачей, и verify_confirm откажется записывать его как
 * подтверждённый.
 *
 * Чего НЕ делается: запись в каталоге не трогается. Отрицательное не
 * хранится и положительного не переписывает (§10, §13), а «у клиента не
 * поместилось» — утверждение о НАС, не о коробке. Снимать подтверждение
 * по нему значило бы стирать состоявшийся опыт чужой длиной приветствия. */
static void on_refused_foreign(d2k_sched *s, const d2k_ev *ev) {
    if (!refuse_is_permanent((uint8_t)ev->code)) { return; }
    const char *found = recall(s, ev);
    if (!found || found[0] == '\0') { return; }
    char name[256];
    snprintf(name, sizeof name, "%s", found);
    s->unfit_client++;

    uint8_t present = 0;
    for (size_t i = 0; i < D2K_PLAN_ID_LEN; i++) { present |= ev->plan_id[i]; }
    task *t = task_of(s, name, ev->transport, ev->family);
    if (t && present) {
        /* По этой цели идёт поиск. Запоминаем ИМЕННО ТОТ план, который не
           поместился: к моменту решения кандидат может смениться. Отказ без
           идентификатора (d2k_link.h: «плану нечем представиться») в задачу
           не пишется — приписать его кандидату нечем, а приписать наугад
           значило бы отменить чужой годный опыт. В счёт он при этом уже
           попал: непереносимость случилась, просто неизвестно чья. */
        size_t cap = sizeof t->unfit_plan_id / sizeof t->unfit_plan_id[0];
        size_t k = 0;
        for (; k < t->unfit_seen; k++) {
            if (memcmp(t->unfit_plan_id[k], ev->plan_id, D2K_PLAN_ID_LEN) == 0) { break; }
        }
        if (k == t->unfit_seen && t->unfit_seen < cap) {
            memcpy(t->unfit_plan_id[t->unfit_seen], ev->plan_id, D2K_PLAN_ID_LEN);
            t->unfit_seen++;
        }
    }

    for (size_t i = 0; i < sizeof s->unfit_names / sizeof s->unfit_names[0]; i++) {
        if (strcmp(s->unfit_names[i], name) == 0) { return; }
    }
    size_t slot = s->unfit_next % (sizeof s->unfit_names / sizeof s->unfit_names[0]);
    snprintf(s->unfit_names[slot], sizeof s->unfit_names[slot], "%s", name);
    s->unfit_next++;
    say(s, "по %s план НЕ ИСПОЛНЯЕТСЯ потоку клиента: не помещается в посылку "
           "(причина %u). Приветствие браузера длиннее зондового — подтверждение "
           "зонда на этот поток не переносится",
        name, (unsigned)ev->code);
}

/* ПОТОК КЛИЕНТА НЕ НЕСЁТ ТОГО, ЧТО ПЛАН ТРЕБУЕТ (D2K_REFUSE_FLOW_UNFIT) —
 * перемерить цель для этого клиента, а не докладывать «подтверждено».
 *
 * Поле issue #7, 22.10.2026: план tcp-template-v1 со сдвигом метки времени
 * подтверждён зондом (зонд метку предлагает всегда — detect/raw.c), телефоны
 * его исполняют, ПК без метки времени — 13 из 13 «план не применён». Привязка
 * при этом числилась подтверждённой, и правило «план уже подтверждён — не
 * улика» (on_suspect, binding_covering) закрывало цель от нового замера.
 *
 * Что делается: привязка этого плана на эту цель помечается «требует
 * повторной проверки» (задача 21: каталог цел, план не стёрт, подтверждение
 * того же или нового плана снимает пометку) и по цели заводится подозрение —
 * оно и ведёт к замеру. С провода план НЕ снимается: клиентам с меткой он
 * исполняется, и отнять у них обход до нового замера — вред без пользы.
 * Повторный такой отказ (следующее соединение того же ПК) пометку не
 * обновляет и второй строки не пишет.
 *
 * Чего НЕ делается: свойство коробки не пишется и план не бракуется — отказ
 * говорит о клиенте, не о коробке (§2.4). Замысел 2026-10-23, п. 5.3. */
static void on_refused_unfit(d2k_sched *s, const d2k_ev *ev) {
    const char *found = recall(s, ev);
    if (!found || found[0] == '\0' || !s->cat) { return; }
    char name[256];
    snprintf(name, sizeof name, "%s", found);
    uint8_t transport = ev->transport ? ev->transport : 6;
    uint8_t family = ev->family ? ev->family : 4;
    uint8_t present = 0;
    for (size_t i = 0; i < D2K_PLAN_ID_LEN; i++) { present |= ev->plan_id[i]; }
    /* ЭТУ ПАРУ «ЦЕЛЬ + ПЛАН» УЖЕ ПЕРЕМЕРЯЛИ — второй раз нечем (находка 3). */
    size_t n_done = sizeof s->unfit_done / sizeof s->unfit_done[0];
    for (size_t i = 0; i < n_done; i++) {
        if (!s->unfit_done[i].name[0] || s->unfit_done[i].transport != transport ||
            s->unfit_done[i].family != family ||
            strcmp(s->unfit_done[i].name, name) != 0) { continue; }
        if (memcmp(s->unfit_done[i].plan_id, ev->plan_id, D2K_PLAN_ID_LEN) == 0) {
            char quiet_key[300];
            snprintf(quiet_key, sizeof quiet_key, "unfit-done %u %s", transport, name);
            say_quiet(s, quiet_key, "по %s поток этого клиента не несёт того, что план "
                      "требует, и цель по этому плану уже перемеряна — второй раз "
                      "перемерять нечем, отказ детерминирован (причина %u)",
                      name, (unsigned)ev->code);
            return;
        }
    }
    size_t marked = 0, waiting = 0;
    for (size_t bi = 0; bi < s->cat->n_boxes; bi++) {
        d2k_cat_box *b = &s->cat->boxes[bi];
        for (size_t j = 0; j < b->n_binds; j++) {
            d2k_cat_binding *bd = &b->binds[j];
            if (!bd->enabled || strcmp(bd->kind, "name") || strcmp(bd->target, name) ||
                (bd->transport ? bd->transport : 6) != transport ||
                (bd->family ? bd->family : 4) != family) { continue; }
            if (present) {
                uint8_t id[D2K_PLAN_ID_LEN] = {0};
                size_t n = strlen(bd->plan_id); if (n > sizeof id) { n = sizeof id; }
                memcpy(id, bd->plan_id, n);
                if (memcmp(id, ev->plan_id, sizeof id) != 0) { continue; }
            }
            if (bd->recheck_since) { waiting++; continue; }
            bd->recheck_since = wall_s(s, s->now_ms);
            bd->recheck_mono_ms = s->now_ms ? s->now_ms : 1;
            b->updated = bd->recheck_since;
            marked++;
            /* НЕ «для этого клиента» (ревью, находка 4): событие отказа не
               несёт набор опций отказавшего потока, и замер пойдёт тем
               снимком и набором, который попадёт в ячейку первым — может
               оказаться другой клиент той же цели. Говорим ровно то, что
               делаем: цель перемеряется заново. */
            say(s, "по %s привязка %s помечена на повторную проверку: поток клиента не "
                   "несёт того, что план требует (причина %u; у tcp-template-v1 это "
                   "метка времени TCP) — перемеряю цель заново тем клиентом, чьё "
                   "приветствие снимется первым, план с провода не снимаю "
                   "(каталог сохранён)",
                name, bd->plan_id, (unsigned)ev->code);
        }
    }
    if (marked) { s->cat->revision++; }
    if (waiting || task_of(s, name, transport, family)) { return; }
    /* Запоминаем пару до завода замера: он один на эту пару (находка 3). */
    size_t slot = s->unfit_done_next++ % n_done;
    snprintf(s->unfit_done[slot].name, sizeof s->unfit_done[slot].name, "%s", name);
    s->unfit_done[slot].transport = transport;
    s->unfit_done[slot].family = family;
    memcpy(s->unfit_done[slot].plan_id, ev->plan_id, D2K_PLAN_ID_LEN);
    d2k_ev suspicion = *ev;
    suspicion.kind = D2K_EV_SUSPECT;
    suspicion.code = D2K_SUSPECT_REPEAT;
    suspicion.planned = D2K_LINK_PLANNED_NO;
    (void)on_suspect(s, &suspicion);
}

static void on_refused(d2k_sched *s, const d2k_ev *ev) {
    if (ev->code == 0) { return; }
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        task *t = &s->tasks[i];
        if((t->state==T_RAW_TRIAL || t->state==T_RAW_WATCH) &&
           ev_matches_flow(ev,&t->trigger_flow) && plan_id_is_ours(t,ev) && applied_trial_is_ours(t,ev)) {
            if(t->state==T_RAW_WATCH && (!ev->execution_id || ev->execution_id!=t->raw_execution_id))continue;
            unknown_note(s,"addr",t->ip,t->transport,t->family,t->port,"local-exec-refused",
                         "исполнение опыта не состоялось на нашей стороне; исход пути не измерен");
            raw_measure_watch_done(s,t,-1);trial_retire(s,t);task_done(s,t);return;
        }
        if (t->state == T_PROPS_WAIT) {
            if (!ev_matches_flow(ev, &t->prop_flow)) { continue; }
            /* И по идентификатору тоже: на том же потоке мог отказать другой
               план — прежней попытки или соседней задачи. Старый отказ,
               приписанный новому вопросу, отменил бы годный опыт. */
            if (memcmp(ev->plan_id, t->prop_plan_id, D2K_PLAN_ID_LEN) != 0) { continue; }
            t->unsent_code = (uint8_t)ev->code;
            return;
        }
        if (t->state == T_VERIFY || t->state == T_TRIAL_SETTLE) {
            /* Ключа зонда ещё нет — копим отказ целиком, как раннее
               применение. Разберём, когда зонд вернётся и назовёт свой
               местный порт. */
            if (!applied_of_candidate(t, ev)) { continue; }
            size_t cap = sizeof t->ver_unsent_early / sizeof t->ver_unsent_early[0];
            for (size_t k = 0; k < t->ver_unsent_seen; k++) {
                if (ev_matches_flow(ev, &t->ver_unsent_early[k])) { return; }
            }
            if (t->ver_unsent_seen == cap) {
                return; /* переполнение теряет улику, но не выдумывает её */
            }
            d2k_flowkey *k = &t->ver_unsent_early[t->ver_unsent_seen];
            k->family = t->family;
            memcpy(k->a_ip, ev->low_ip, t->family == 6 ? 16 : 4);
            memcpy(k->b_ip, ev->high_ip, t->family == 6 ? 16 : 4);
            k->a_port = ev->low_port;
            k->b_port = ev->high_port;
            k->transport = ev->transport;
            t->ver_unsent_code_early[t->ver_unsent_seen] = (uint8_t)ev->code;
            t->ver_unsent_seen++;
            return;
        }
        if (t->state == T_VERIFY_WAIT) {
            if (!ev_matches_flow(ev, &t->ver_flow)) { continue; }
            if (!plan_id_is_ours(t, ev)) { continue; }
            t->unsent_code = (uint8_t)ev->code;
            return;
        }
    }
    /* Ни одна задача этот отказ своим не признала: поток не наш, его открыл
       кто-то в доме. План при этом применялся — значит он стоит на цели, а
       браузер под него не подошёл. */
    if (ev->code == D2K_REFUSE_FLOW_UNFIT) {
        /* ТОЛЬКО on_refused_unfit. on_refused_foreign здесь ЗАПРЕЩЁН (ревью
           ветки, находка 2): он пишет план в t->unfit_plan_id[], и
           verify_confirm по этому идентификатору отказывается подтверждать
           («обход, который не достаётся человеку, обходом не является»). Это
           верно для НЕПОМЕСТИВШЕЙСЯ посылки — там план не исполнится никому с
           таким приветствием. Здесь же план исполняется каждому, кто несёт
           метку времени, и один ПК без метки накладывал бы вето на
           подтверждение tcpts-плана по любой цели: телефоны теряли бы рабочий
           обход. Это прямо против решения 5.3 — с провода план не снимаем
           именно потому, что он работает у остальных. */
        on_refused_unfit(s, ev);
        return;
    }
    if (refuse_is_permanent((uint8_t)ev->code) && s->cat->groups) {
        const char *name = recall(s, ev);
        if (name) {
            for (size_t i = 0; i < d2k_group_slots(s->cat->groups); i++) {
                d2k_domain_group value;
                if (!d2k_group_at(s->cat->groups,i,&value)) continue;
                const d2k_domain_group *g = &value;
                uint8_t id[D2K_PLAN_ID_LEN] = {0};
                size_t n = strlen(g->plan_id); if (n > sizeof id) n = sizeof id;
                memcpy(id, g->plan_id, n);
                if (g->key.transport != ev->transport || g->key.family != (ev->family ? ev->family : 4) ||
                    g->key.shape != ev->client_shape ||
                    !d2k_domain_member(name, g->suffix) || memcmp(id, ev->plan_id, sizeof id)) continue;
                /* У участника своё подтверждённое точное решение: отказ
                   исполнения у одного клиента — свойство его потока, а не
                   улика против плана для семейства (§7). Не записываем
                   провал группы: он сделал бы голос участника устаревшим. */
                int own = own_exact_confirmed(s->cat, name, &g->key);
                d2k_ev suspicion = *ev;
                suspicion.kind = D2K_EV_SUSPECT;
                suspicion.code = D2K_SUSPECT_REPEAT;
                suspicion.planned = D2K_LINK_PLANNED_NO;
                /* The exact wire plan refused execution on this client.
                   Retain that fact even when subsequent diagnosis cannot
                   establish a DPI verdict. It never invalidates siblings. */
                d2k_group_observation failed = {0};
                snprintf(failed.name, sizeof failed.name, "%s", name);
                snprintf(failed.plan_id, sizeof failed.plan_id, "%s", g->plan_id);
                failed.key = g->key; failed.evidence = D2K_GROUP_PLAN_FAILED;
                failed.at = wall_s(s, s->now_ms);
                if (!own && d2k_group_learn(s->cat->groups, &failed) > 0) {
                    s->cat->revision++; s->sync_pending = 1;
                }
                if (!task_of(s, name, ev->transport, ev->family)) (void)on_suspect(s, &suspicion);
                break; /* refusal is execution evidence, not a DPI verdict */
            }
        }
    }
    on_refused_foreign(s, ev);
}

/* Обмен по живому трафику. Порога успеха здесь БОЛЬШЕ НЕТ: внешний тип
   записи 23 — наблюдение (§4.2, уровень 2), потому что в TLS 1.3 им едет и
   второй полёт рукопожатия (RFC 8446 §5.2, см. d2k_ev_outer_appdata). Два
   читателя у этого наблюдения: ответ на заданный вопрос о свойствах коробки
   и ПОСЛЕДУЮЩЕЕ живое соединение к уже подтверждённой цели. Ответ на вопрос
   может прийти до завершения отложенных посылок: сохраняем его до APPLIED,
   но без доказательства исполнения свойство не меняем.

   ПРИЁМКА ВОПРОСА — не это наблюдение, а РАЗБОР ОТВЕТА СЕРВЕРА
   (ev->server_hello). Внешний тип 23 появляется и там, где сервер только
   поздоровался, и там, где обмен дошёл до приложения, — им нельзя отвечать
   на вопрос «пропустила ли коробка наш ClientHello до сервера». Донор
   принимает зонд по разбору ожидаемого ответа (Trigger.Accept,
   internal/classify/trigger.go), и теперь так же принимают оба наших
   опросника (0009, U1). Для ПОСЛЕДУЮЩЕГО живого соединения наблюдение
   остаётся прежним: там вопрос другой. */
/* Запоминаем имя, завершившее обмен с ответом сервера БЕЗ нашего плана. */
/* ЖИВОГО БЕЛОГО ИМЕНИ ЗДЕСЬ БОЛЬШЕ НЕТ (ревью 24.10.2026, замечания 4 и 5).
 *
 * Правило было такое: поток БЕЗ плана, с разобранным ответом сервера, прошедший
 * больше измеренной полосы обрыва, — доказательство, что коробка это имя
 * пропускает, и подбор из 266 имён не нужен. Правило верное, а исполнение
 * опиралось на две неправды.
 *
 * ОБЪЁМ НЕ ДОХОДИЛ. Объём брался из EXCHANGE, а датапат сообщает его ДВАЖДЫ за
 * поток: когда обмен пошёл и когда в нём появились прикладные данные, то есть
 * сразу за рукопожатием. Прогон 70 КБ через настоящие функции session дал два
 * события, последнее с 1149 байтами. Накопленный объём потока (fl->rev_bytes)
 * датапат знает и никому не сообщает, так что порога в 16 КБ число из
 * EXCHANGE не достигало никогда — в поле это правило не сработало ни разу.
 *
 * ПОРОГ БРАЛСЯ НЕ ТОТ. Из измеренных коробками полос брался САМЫЙ ТЕСНЫЙ, и
 * комментарий уверял, что прошедший его прошёл и остальные. Это неверно: при
 * полосах 16 и 64 КБ поток на 32 КБ доказывает проход только первой, а
 * searched=1 закрывал подбор для ВСЕЙ сети, то есть и для второго класса целей.
 *
 * Чтобы вернуть правило, нужен объём ПОТОКА от датапата (отчёт о накопленном
 * rev_bytes) и порог, достаточный для всех измеренных коробок, — обе части
 * честно проверяются полем, а не синтетическим событием в тесте. Пока их нет,
 * механизма нет: мёртвый механизм хуже отсутствующего, потому что обещает
 * экономию перебора, которой не будет. Наблюдение чистого рукопожатия
 * (note_clean_handshake) — другое дело: оно работает и остаётся. */
static void note_clean_handshake(d2k_sched *s, const char *name, uint8_t transport,
                                 uint8_t family) {
    if (!name || !name[0]) return;
    clean_hs_seen *slot = NULL;
    for (size_t i = 0; i < SCHED_CLEAN_HS_SLOTS; i++) {
        clean_hs_seen *c = &s->clean_hs[i];
        if (c->used && c->transport == transport && c->family == family &&
            strcmp(c->name, name) == 0) { slot = c; break; }
    }
    if (!slot) {
        slot = &s->clean_hs[s->clean_hs_next];
        s->clean_hs_next = (s->clean_hs_next + 1) % SCHED_CLEAN_HS_SLOTS;
        memset(slot, 0, sizeof *slot);
        snprintf(slot->name, sizeof slot->name, "%s", name);
        slot->transport = transport;
        slot->family = family;
        slot->used = 1;
    }
    slot->seen_ms = s->now_ms;
}

/* Было ли у имени недавно чистое рукопожатие без плана. */
static int clean_handshake_recent(d2k_sched *s, const char *name, uint8_t transport,
                                  uint8_t family) {
    for (size_t i = 0; i < SCHED_CLEAN_HS_SLOTS; i++) {
        const clean_hs_seen *c = &s->clean_hs[i];
        if (c->used && c->transport == transport && c->family == family &&
            strcmp(c->name, name) == 0) {
            return s->now_ms - c->seen_ms <= SCHED_CLEAN_HS_MS;
        }
    }
    return 0;
}

static void flowwatch_direct_exchange(d2k_sched *s, const d2k_ev *ev) {
    if (ev->transport != 6 || !d2k_ev_outer_appdata(ev)) return;
    for (size_t i = 0; i < SCHED_FLOWWATCH_SLOTS; i++) {
        flow_watch *w = &s->flowwatch[i];
        if (!w->used || w->transport != ev->transport ||
            w->family != (ev->family ? ev->family : 4) ||
            w->low_port != ev->low_port || w->high_port != ev->high_port ||
            memcmp(w->low_ip, ev->low_ip, 16) || memcmp(w->high_ip, ev->high_ip, 16)) continue;
        w->had_reply = 1;
        w->sil_steps = 0;
        w->escalated = 0;
        w->obs_fails = 0;
        return;
    }
}

static void note_direct_control(d2k_sched *s,const d2k_ev *ev,const char *name) {
    unsigned epoch=0;
    for(size_t i=0;i<sizeof ev->flow_epoch;i++)epoch|=ev->flow_epoch[i];
    if(!name || !name[0] || strlen(name)>=sizeof s->direct_control[0][0].name ||
       ev->transport!=6 || (ev->family!=4 && ev->family!=6) ||
       !ev->server_hello || ev->planned!=D2K_LINK_PLANNED_NO || !ev->num ||
       !epoch || !ev->flow_incarnation || !ev->low_port || !ev->high_port)return;
    d2k_application_control c={0};
    memcpy(c.name,name,strlen(name)+1);
    memcpy(c.epoch,ev->flow_epoch,sizeof c.epoch);
    memcpy(c.low_ip,ev->low_ip,sizeof c.low_ip);memcpy(c.high_ip,ev->high_ip,sizeof c.high_ip);
    c.family=ev->family;c.transport=ev->transport;c.low_port=ev->low_port;c.high_port=ev->high_port;
    c.incarnation=ev->flow_incarnation;c.bytes=ev->num;
    /* Keep a distinct-name contrast when the target itself completes TLS.
       Repeated records of that target must not erase the other observation. */
    d2k_application_control *controls=s->direct_control[ev->family==6];
    if(strcmp(controls[0].name,name))controls[1]=controls[0];
    controls[0]=c;
}

static void on_exchange(d2k_sched *s, const d2k_ev *ev) {
    flowwatch_direct_exchange(s, ev);
    int raw_path_proven = ev->code == D2K_RAW_PROOF_ECHO ||
                          ev->code == D2K_RAW_PROOF_PROGRESS;
    if (ev->planned == D2K_LINK_PLANNED_YES) plan_obs_note(s, ev, recall(s, ev), 1);
    /* Обмен с ответом сервера на потоке без плана — имя работает само.
       Запоминаем по имени (recall по ключу потока): по нему гасится замер
       на рукопожатии (поле 15.10.2026, медиа VK). Только TCP и только с
       разобранным ServerHello: это доказательство рукопожатия (§4.2). */
    if (ev->transport == 6 && ev->server_hello &&
        ev->planned == D2K_LINK_PLANNED_NO) {
        const char *nm = recall(s, ev);
        if (nm) {
            note_direct_control(s,ev,nm);
            note_clean_handshake(s, nm, 6, ev->family ? ev->family : 4);
        }
    }
    /* Ответ сервера на продолжение клиента под опытом без протокола (этап 12):
       только тот поток, только план применён (planned), только уровень пути. */
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        task *t = &s->tasks[i];
        if(raw_path_proven && t->state==T_RAW_TRIAL && ev->transport==t->transport && ev->execution_id &&
           ev->planned==D2K_LINK_PLANNED_YES && ev_matches_flow(ev,&t->trigger_flow) &&
           plan_id_is_ours(t,ev) && applied_trial_is_ours(t,ev)) {
            /* Store presence only. APPLIED on the control wire means DONE;
               until that exact execution finishes, no confirmation is made. */
            t->raw_early_reply_execution=ev->execution_id;return;
        }
        if (raw_path_proven && t->state == T_RAW_WATCH && ev->transport == t->transport &&
            ev->planned == D2K_LINK_PLANNED_YES && ev_matches_flow(ev, &t->trigger_flow) &&
            t->raw_execution_id && ev->execution_id == t->raw_execution_id &&
            plan_id_is_ours(t,ev) && applied_trial_is_ours(t,ev)) {
            raw_confirm(s, t, s->now_ms);
            return;
        }
    }
    /* Наблюдение UDP-ответа по потоку с применённым приёмом. Раньше
       всех прочих разборов: у UDP нет типов записей TLS, и проверка на
       прикладные данные ниже отбросила бы его. */
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        task *t = &s->tasks[i];
        if (t->state == T_VOICE_WATCH && ev_matches_flow(ev, &t->voice_flow)) {
            if (ev->code == D2K_UDP_PROOF_VOICE_DISCOVERY ||
                ev->code == D2K_UDP_PROOF_STUN) {
                /* A response belongs to its outbound request, not whichever
                   candidate happens to occupy this tuple when it arrives. */
                if (!voice_execution_matches(t,ev)) return;
                t->voice_proven = 1;
                t->voice_proof_code = ev->code;
            }
            t->voice_answered = 1;
            return;
        }
    }
    /* Сперва — не ответ ли это на заданный вопрос. Своё это обращение или
       чужое, решает КЛЮЧ ПОТОКА: событие обмена не адресовано команде, и без
       фильтра чужой обмен засчитался бы за наш зонд (ревью 11.09, находка 1
       в compose.c — воспроизводилось 5/5 на стенде). */
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        task *t = &s->tasks[i];
        if (t->state == T_PROPS_CONTACT && ev->server_hello && ev->transport == 6 &&
            t->prop_sport_be != 0 &&
            (ev->family ? ev->family : 4) == (t->family ? t->family : 4) &&
            (ev->low_port == ntohs(t->prop_sport_be) ||
             ev->high_port == ntohs(t->prop_sport_be))) {
            /* Ключа потока вопроса ещё нет, но местный порт вопроса занят
               заранее и известен. Копим; полная сверка — при переходе. */
            if (t->prop_early_x_seen < sizeof t->prop_early_x / sizeof t->prop_early_x[0]) {
                t->prop_early_x[t->prop_early_x_seen++] = *ev;
            }
            return;
        }
        if (t->state != T_PROPS_WAIT) { continue; }
        if (!ev_matches_flow(ev, &t->prop_flow)) { continue; }
        if (!ev->server_hello) {
            /* Обмен пошёл, но ОТВЕТА СЕРВЕРА в нём нет. Вопрос спрашивает,
               пропустила ли коробка наш отравленный ClientHello до сервера,
               и прямой ответ на это — ServerHello, а не тип записи. Алерт,
               мусор и оборванная запись сюда не попадают: датапат ставит
               признак только по разобранному ServerHello, чья длина
               укладывается в обещание записи (d2k_tls.h).

               Довести рукопожатие до конца вопрос и не собирается — повтором
               снятых байт это невозможно (d2k_verify.h), и валидный ответ на
               вопрос не выдаётся за работу пользовательского приложения. */
            return;
        }
        if (!t->prop_applied) {
            /* Ответ может опередить завершение последней отложенной посылки.
               Нужны ОБА факта; отсутствие второго сейчас — не отказ. */
            t->prop_reply = *ev;
            t->prop_reply_seen = 1;
            say(s, "по %s вопрос %d: ответ замечен — жду подтверждения полного исполнения",
                t->name, t->prop_q + 1);
            return;
        }
        d2k_props_question_passed(t->prop_q, &t->props);
        {
            char pv[400];
            props_text(&t->props, pv, sizeof pv);
            say(s, "по %s вопрос %d прошёл, вектор: %s", t->name, t->prop_q + 1, pv);
        }
        /* Вопрос прошёл — это уже стратегия (двойное назначение плана, см.
           шапку compose.c), и второй вопрос той же цели не задаётся. План
           вопроса снимается до первого кандидата (задача 20). */
        question_retire(s, t);
        prop_close(t);
        t->prop_q = -1;
        verdict_to_plans(s, t, &t->res);
        t->state = T_PLANNING;
        return;
    }

    if (!d2k_ev_outer_appdata(ev)) {
        return; /* даже наблюдения нет: внешнего типа 23 в обмене не было */
    }
    const char *name = recall(s, ev);
    if (!name) { return; }
    task *t = task_of(s, name, ev->transport, ev->family);
    /* Только ПОДТВЕРЖДЁННАЯ задача. Завести привязку это наблюдение не может
       (задача 4): на нём кандидат, доведший дело лишь до ответа коробки,
       записывался бы в каталог рабочим — так и набрались 4796 «успехов» по
       instagram при мёртвом плане (§1 спецификации). */
    if (!t || t->state != T_WATCHING) { return; }
    if (ev_matches_flow(ev, &t->ver_flow)) {
        /* Это поток нашего же зонда: он уже был доказательством, и считать его
           вдобавок «последующим соединением» значит подтвердить себя собой. */
        return;
    }
    /* Даже известная форма приветствия не раскрывает зашифрованный ответ. */
    say(s, "по %s замечен последующий TLS-ответ (%u байт); это не доказательство "
           "работы приложения клиента — уровень и источник подтверждения не меняются",
        t->name, (unsigned)ev->num);
    /* Освобождаем задачу наблюдения. Подтверждённый план остаётся стоять. */
    task_done(s, t);
}

static void gate_restore_queue(task *t) {
    if(!t->gate_combined)return;
    t->n_plans=t->gate_saved_plans;t->next_plan=t->gate_saved_next;t->n_known=t->gate_saved_known;
    t->gate_combined=0;
}
/* Standalone measured gates and explicitly composed fallback trials share
 * ownership/verification, while their evidence and origin remain distinct. */
static int gate_start_program(d2k_sched *s,task *t,const d2k_box_props *p,int reuse,const char *outgoing) {
    if(!preflight_family_enabled(t->family) || t->transport!=6 || t->ech_offer) return 0;
    uint8_t white[4096];const uint8_t *hello=t->trig;size_t len=t->trig_len;
    char err[200]={0};
    const char *probe_name=NULL;
    if(!outgoing && p->gate_hello_own==D2K_PROP_NO) {
        if(reuse)return 0;
        if(!t->res.gate_probe_name[0]) {
            say(s,"по %s preflight: не сохранено имя измеренного пробного приветствия",t->name);
            return 0;
        }
        probe_name=t->res.gate_probe_name;
        if(d2k_white_decoy_hello(probe_name,white,sizeof white,&len))return 0;
        hello=white;
    }
    if(outgoing) {
        char pf[sizeof t->plans[0]],*joined=NULL;
        const char *origin="# origin=fallback-combined; direct carry unconfirmed; application trial required\n";
        if(d2k_compose_preflight_candidate(&t->res.gate_candidate,t->family,t->transport,
            pf,sizeof pf,err,sizeof err)!=1 ||
           d2k_plan_text_compose_preflight(pf,outgoing,&joined,err,sizeof err) ||
           strlen(joined)+strlen(origin)>=sizeof t->plans[0]) {
            free(joined);say(s,"по %s составной кандидат не собран: %s",t->name,err);return 0;
        }
        trial_retire(s,t);ver_close(t);
        t->gate_saved_plans=t->n_plans;t->gate_saved_next=t->next_plan;t->gate_saved_known=t->n_known;
        t->gate_combined=1;
        snprintf(t->plans[0],sizeof t->plans[0],"%s%s",origin,joined);free(joined);
    } else {
        int rc=d2k_compose_preflight_from_props(p,probe_name,reuse?0:t->res.gate_probe_wscale,
            t->family,t->transport,hello,len,t->plans[0],sizeof t->plans[0],err,sizeof err);
        if(rc!=1) {say(s,"по %s preflight: %s",t->name,err);return 0;}
        t->res.box_props=*p;t->res.verdict=D2K_V_RESPONSE_GATE;t->gate_combined=0;
    }
    t->gate_active=1;t->gate_reuse=reuse;t->n_plans=1;t->next_plan=1;
    t->trial_shape=d2k_hello_shape(t->trig,t->trig_len)==D2K_SHAPE_LEGACY?
        D2K_SHAPE_LEGACY:D2K_SHAPE_MODERN;
    char id[40],wire[sizeof t->plans[0]],hex[2*D2K_PLAN_TLV_MAX+1];
    uint8_t ip[16]={0};plan_ident(t->plans[0],id,sizeof id,t->ver_plan_id);
    snprintf(wire,sizeof wire,"%s",t->plans[0]);
    if(stamp_plan_id(wire,t->ver_plan_id) ||
       d2k_plan_text_to_hex(wire,hex,sizeof hex,err,sizeof err) ||
       fresh_trial_id(t->trial_ack_id) || inet_pton(t->family==6?AF_INET6:AF_INET,t->ip,ip)!=1 ||
       d2k_sched_bind_hook(6,t->family,&t->probe_fd,&t->probe_sport_be) ||
       (s->mark && d2k_sched_mark_hook(t->probe_fd,s->mark)) ||
       d2k_link_set_preflight_trial(s->link_fd,ip,t->family,htons(t->port),t->probe_sport_be,t->trial_shape,
           hex,t->trial_ack_id,err,sizeof err)) {
        say(s,"по %s preflight: установка опыта не состоялась: %s",t->name,err);
        if(t->probe_fd>=0){close(t->probe_fd);t->probe_fd=-1;}
        t->gate_active=0;t->n_plans=0;gate_restore_queue(t);return 0;
    }
    t->gate_installed=1;t->gate_committed=0;t->gate_commit_sent=0;t->gate_catalog_saved=0;
    t->gate_lease_started=0;t->gate_lease_failed=0;t->gate_lease_pending=t->gate_lease_acked=0;
    t->trial_acked=0;t->exec_nak=0;t->ver_seen=0;t->gate_outgoing_seen=0;
    memset(&t->gate_binding,0,sizeof t->gate_binding);
    t->ver_unsent_seen=0;
    t->ver_dropped0=s->dropped_seen;t->trial_until_ms=s->now_ms+SCHED_VERIFY_STEP_MS;
    t->state=T_GATE_INSTALL;
    if(outgoing){t->probes++;s->probes_used++;}
    say(s,"по %s preflight %s: %s:%u, план %s; установка не означает успех",
        t->name,outgoing?"составной fallback; прямой перенос не подтверждён":
        reuse?"свойства совместимой коробки первыми":"окно/K/carry из замера; таймер передачи fallback",t->ip,t->port,id);
    return 1;
}
static int gate_start(d2k_sched *s,task *t,const d2k_box_props *p,int reuse) {
    return gate_start_program(s,t,p,reuse,NULL);
}
static int gate_try_composed(d2k_sched *s,task *t,int touched) {
    if(!t->res.gate_candidate.present || !touched || t->ver.level<D2K_VER_TRANSPORT ||
       t->ver.local_limit || t->ver.local_refusal || t->ver.unsupported || t->ver.peer_auth_failed ||
       s->dropped_seen!=t->ver_dropped0 || !t->next_plan || t->next_plan>t->n_plans ||
       t->probes>=sched_probe_cap(t))return 0;
    return gate_start_program(s,t,NULL,0,t->plans[t->next_plan-1]);
}
static d2k_cat_binding *gate_catalog_binding(d2k_sched *s,task *t) {
    if(!s->cat)return NULL;
    for(size_t i=0;i<s->cat->n_boxes;i++) {
        d2k_cat_box *b=&s->cat->boxes[i];
        if(strcmp(b->id,t->gate_catalog_box))continue;
        for(size_t j=0;j<b->n_binds;j++) {
            d2k_cat_binding *bd=&b->binds[j];
            if(!strcmp(bd->kind,"service") && bd->transport==6 && bd->family==t->family &&
               bd->shape==t->trial_shape && bd->server_port==t->port && !strcmp(bd->target,t->ip))return bd;
        }
    }
    return NULL;
}
static int gate_catalog_save(d2k_sched *s,task *t,int64_t now_ms) {
    if(!s->cat)return -1;
    char id[40];uint8_t wid[16];plan_ident(t->plans[0],id,sizeof id,wid);
    box_id_for(s,t,t->plans[0],t->gate_catalog_box,sizeof t->gate_catalog_box);
    t->gate_catalog_saved=0;t->gate_catalog_had=0;memset(&t->gate_catalog_previous,0,sizeof t->gate_catalog_previous);
    d2k_cat_binding *old=gate_catalog_binding(s,t);
    if(old) {t->gate_catalog_had=1;t->gate_catalog_previous=*old;}
    if(bind_confirmed(s->cat,t->gate_catalog_box,id,t->plans[0],"tls",t->ip,"service",6,t->family,t->trial_shape,t->port,
        D2K_VERBY_PROBE,record_input(t),wall_s(s,now_ms),&t->fp,&t->res.box_props,NULL))return -1;
    t->gate_catalog_saved=1;
    d2k_cat_binding *bd=gate_catalog_binding(s,t);
    if(bd)snprintf(bd->preflight_name,sizeof bd->preflight_name,"%s",t->name);
    return 0;
}
static void gate_catalog_rollback(d2k_sched *s,task *t) {
    if(!t->gate_catalog_saved)return;
    d2k_cat_binding *bd=gate_catalog_binding(s,t);
    if(bd) {
        if(t->gate_catalog_had)*bd=t->gate_catalog_previous;
        else {
            d2k_cat_box *b=&s->cat->boxes[0];size_t i=0;
            for(;i<s->cat->n_boxes;i++)if(!strcmp(s->cat->boxes[i].id,t->gate_catalog_box)){b=&s->cat->boxes[i];break;}
            size_t pos=(size_t)(bd-b->binds);b->binds[pos]=b->binds[b->n_binds-1];b->n_binds--;
        }
        s->cat->revision++;
    }
    t->gate_catalog_saved=0;
}
static void gate_failed(d2k_sched *s,task *t,const char *reason) {
    for(size_t i=0;i<SCHED_SEEN;i++)if(s->preflight_leases[i].owner==t)
        preflight_lease_retire(s,&s->preflight_leases[i]);
    gate_catalog_rollback(s,t);
    join_worker(t);trial_retire(s,t);ver_close(t);
    say(s,"по %s preflight: опыт не подтверждён: %s",t->name,reason);
    t->gate_active=0;
    if(t->gate_combined) {
        gate_restore_queue(t);t->res_ready=0;t->exec_nak=0;t->ver_seen=0;t->gate_outgoing_seen=0;
        t->started_ms=s->now_ms;t->state=T_PLANNING;
        say(s,"по %s составной опыт не подтверждён — продолжаю оставшиеся исходящие кандидаты",t->name);
        return;
    }
    if(t->gate_reuse && preflight_family_enabled(t->family)) {
        t->gate_reuse=0;t->gate_skip_reuse=1;t->own_first=3;
        t->n_plans=t->next_plan=t->n_known=0;t->started_ms=s->now_ms;
        memset(&t->res,0,sizeof t->res);t->state=T_ASKING;
        say(s,"по %s preflight: своё решение не подошло — повторный замер, без перебора",t->name);
        if(start_worker(s,t,JOB_CLASSIFY))task_done(s,t);
    } else task_done(s,t);
}
static int gate_event(d2k_sched *s,task *t,const d2k_ev *ev) {
    (void)s;
    if(!t->gate_active)return 0;
    if(ev->kind==D2K_EV_ACK && ev->code==D2K_CMD_SET_PREFLIGHT_TRIAL &&
       !memcmp(ev->trial_id,t->trial_ack_id,16)) {
        if(((ev->num>>8)&255)!=1) t->exec_nak=0x100|(ev->num&255);
        else if(d2k_binding_known(&ev->execution_binding) &&
            ev->execution_binding.kind==D2K_BIND_ADDR && ev->execution_binding.family==t->family &&
            ev->execution_binding.shape==t->trial_shape && ev->execution_binding.temporary) {
            t->gate_binding=ev->execution_binding;t->trial_acked=1;
        }
        return 1;
    }
    if(ev->kind==D2K_EV_ACK && ev->code==D2K_CMD_COMMIT_ENDPOINT_TRIAL &&
       t->state==T_GATE_COMMIT && t->gate_commit_sent &&
       !memcmp(ev->trial_id,t->trial_ack_id,16)) {
        if(((ev->num>>8)&255)==1)t->gate_committed=1;
        else t->exec_nak=0x100|(ev->num&255);
        return 1;
    }
    if(ev->kind!=D2K_EV_PREFLIGHT_HANDOVER && ev->kind!=D2K_EV_PREFLIGHT_GAVE_UP &&
       ev->kind!=D2K_EV_REFUSED && !(t->gate_combined && ev->kind==D2K_EV_APPLIED))return 0;
    if(ev->family!=t->family || ev->transport!=6 || !plan_id_is_ours(t,ev) ||
       memcmp(ev->trial_id,t->trial_ack_id,16) ||
       !d2k_binding_equal(&ev->execution_binding,&t->gate_binding) ||
       !applied_of_candidate(t,ev))return 0;
    /* A neighbouring client using the endpoint is not this verifier trial. */
    if(ev->low_port!=ntohs(t->probe_sport_be) && ev->high_port!=ntohs(t->probe_sport_be))return 0;
    if(ev->kind==D2K_EV_APPLIED) {
        if(!ev->execution_id)return 0;
        if(t->gate_outgoing_seen<sizeof t->gate_outgoing_early/sizeof t->gate_outgoing_early[0]) {
            d2k_flowkey *k=&t->gate_outgoing_early[t->gate_outgoing_seen++];
            memset(k,0,sizeof *k);k->family=t->family;k->transport=6;
            memcpy(k->a_ip,ev->low_ip,16);memcpy(k->b_ip,ev->high_ip,16);
            k->a_port=ev->low_port;k->b_port=ev->high_port;
        }
        return 1;
    }
    if(ev->kind!=D2K_EV_PREFLIGHT_HANDOVER) {
        if(t->ver_unsent_seen<sizeof t->ver_unsent_early/sizeof t->ver_unsent_early[0]) {
            size_t i=t->ver_unsent_seen++;
            d2k_flowkey *k=&t->ver_unsent_early[i];
            k->family=t->family;k->transport=6;memcpy(k->a_ip,ev->low_ip,16);memcpy(k->b_ip,ev->high_ip,16);
            k->a_port=ev->low_port;k->b_port=ev->high_port;
            t->ver_unsent_code_early[i]=(uint8_t)(ev->num?ev->num:1);
        }
        return 1;
    }
    if(t->ver_seen<sizeof t->ver_early/sizeof t->ver_early[0]) {
        d2k_flowkey *k=&t->ver_early[t->ver_seen++];
        k->family=t->family;k->transport=6;memcpy(k->a_ip,ev->low_ip,16);memcpy(k->b_ip,ev->high_ip,16);
        k->a_port=ev->low_port;k->b_port=ev->high_port;
    }
    return 1;
}
static unsigned gate_dns_leases(d2k_sched *s,task *t,int64_t now_ms) {
    uint8_t server[16]={0};size_t width=t->family==6?16:4;
    if(inet_pton(t->family==6?AF_INET6:AF_INET,t->ip,server)!=1)return 0;
    /* Chromium's GREASE offer is initially reported as ECH. Only the
     * completed classification may lend its ordinary TLS shape to that
     * same observed endpoint; real ECH never enters this path. */
    if(t->ech_grease&&!t->ech_offer)for(size_t i=0;i<SCHED_SEEN;i++) {
        const seen_name *r=&s->seen[i];
        if(!r->used||r->family!=t->family||r->transport!=6||
           r->client_shape!=D2K_LINK_SHAPE_ECH_TCP||strcasecmp(r->name,t->name)||
           now_ms-r->named_ms>600000||now_ms<r->named_ms)continue;
        if(r->named_client_side!=D2K_CLIENT_SIDE_LOW&&r->named_client_side!=D2K_CLIENT_SIDE_HIGH)continue;
        int low=r->named_client_side==D2K_CLIENT_SIDE_LOW;
        if((low?r->high_port:r->low_port)!=t->port||memcmp(low?r->high_ip:r->low_ip,server,width))continue;
        d2k_ev e={.family=r->family,.transport=6,.client_side=r->named_client_side,
            .client_shape=t->trial_shape,.low_port=r->low_port,.high_port=r->high_port};
        memcpy(e.low_ip,r->low_ip,16);memcpy(e.high_ip,r->high_ip,16);
        snprintf(e.name,sizeof e.name,"%s",r->name);
        preflight_observe_named_path(s,&e,0);
    }
    for(size_t i=0;i<SCHED_SEEN;i++) {
        dns_address_name *r=&s->dns_names[i];
        if(r->family!=t->family||r->client_family!=t->family||r->expires_ms<=now_ms||
           !r->path||strcasecmp(r->name,t->name)||memcmp(r->address,server,width))continue;
        preflight_dns_reconcile(s,r->client,t->family,server,r->path,now_ms);
    }
    unsigned pending=0;
    for(size_t i=0;i<SCHED_SEEN;i++) {
        sched_preflight_lease *l=&s->preflight_leases[i];
        if(!l->pending||l->scope.family!=t->family||l->scope.shape!=t->trial_shape||
           ntohs(l->scope.server_port)!=t->port||strcasecmp(l->scope.name,t->name)||
           memcmp(l->scope.server,server,width))continue;
        l->owner=t;pending++;
    }
    t->gate_lease_pending=pending;return pending;
}
static void gate_tick(d2k_sched *s,task *t,int64_t now_ms) {
    if(!preflight_family_enabled(t->family) || t->exec_nak) {gate_failed(s,t,t->exec_nak?"GAVE_UP/отказ исполнителя":"D2K_PREFLIGHT=0");return;}
    if(t->state==T_GATE_INSTALL) {
        if(!t->trial_acked) {
            if(now_ms>=t->trial_until_ms)gate_failed(s,t,"нет ACK установки");
            return;
        }
        t->state=T_GATE_VERIFY;
        t->trial_until_ms=now_ms+SCHED_TASK_LIFE_MS;
        if(start_worker(s,t,JOB_VERIFY))gate_failed(s,t,"verifier не запущен");
        return;
    }
    int ready;pthread_mutex_lock(&s->mu);ready=t->res_ready;pthread_mutex_unlock(&s->mu);
    if(!ready) {if(now_ms>=t->trial_until_ms)gate_failed(s,t,"истёк срок verifier");return;}
    join_worker(t);
    d2k_ev flow={0};flow.family=t->family;flow.transport=6;flow.low_port=t->ver.local_port;
    flow.high_port=t->port;
    memcpy(flow.low_ip,t->family==6?t->ver.local_addr:t->ver.local_ip4,t->family==6?16:4);
    if(t->ver.family!=t->family ||
       inet_pton(t->family==6?AF_INET6:AF_INET,t->ip,flow.high_ip)!=1) {
        gate_failed(s,t,"семейство потока verifier не совпадает с опытом");return;
    }
    for(size_t i=0;i<t->ver_unsent_seen;i++)if(ev_matches_flow(&flow,&t->ver_unsent_early[i])) {
        gate_failed(s,t,"GAVE_UP/отказ исполнителя на потоке verifier");return;
    }
    int applied=0;
    for(size_t i=0;i<t->ver_seen;i++)if(ev_matches_flow(&flow,&t->ver_early[i]))applied=1;
    int outgoing=!t->gate_combined;
    for(size_t i=0;i<t->gate_outgoing_seen;i++)if(ev_matches_flow(&flow,&t->gate_outgoing_early[i]))outgoing=1;
    if(t->ver.level!=D2K_VER_APPLICATION || !t->ver.body_complete ||
       !t->ver.peer_authenticated || t->ver.peer_auth_failed ||
       (t->ver.http_version!=1 && t->ver.http_version!=2) ||
       t->ver.local_refusal || t->ver.local_limit || t->ver.unsupported ||
       t->ver.local_port!=ntohs(t->probe_sport_be)) {gate_failed(s,t,"нет полного HTTP-ответа на настоящем TLS-соединении");return;}
    if(!applied || !outgoing) {
        if(now_ms>=t->trial_until_ms)gate_failed(s,t,"нет handover/исходящего исполнения своего поколения на потоке verifier");
        return;
    }
    if(s->dropped_seen!=t->ver_dropped0) {gate_failed(s,t,"потеря событий опыта");return;}
    if(t->state!=T_GATE_COMMIT) {
        if(gate_catalog_save(s,t,now_ms)) {gate_failed(s,t,"каталог не сохранил подтверждение");return;}
        t->state=T_GATE_COMMIT;t->gate_lease_started=1;
        if(gate_dns_leases(s,t,now_ms)) {t->trial_until_ms=now_ms+SCHED_VERIFY_STEP_MS;return;}
    }
    if(t->gate_lease_failed){gate_failed(s,t,"датапат отказал установке DNS-аренды");return;}
    if(t->gate_lease_pending) {
        if(now_ms>=t->trial_until_ms)gate_failed(s,t,"нет ACK установки DNS-аренды");
        return;
    }
    if(!t->gate_commit_sent) {
        char err[160];
        if(d2k_link_commit_endpoint_trial(s->link_fd,flow.high_ip,t->family,htons(t->port),t->trial_shape,
            t->trial_ack_id,err,sizeof err)) {gate_failed(s,t,"не отправилось продвижение кандидата");return;}
        t->gate_commit_sent=1;t->trial_until_ms=now_ms+SCHED_VERIFY_STEP_MS;return;
    }
    if(!t->gate_committed) {
        if(now_ms>=t->trial_until_ms)gate_failed(s,t,"нет ACK продвижения кандидата");
        return;
    }
    t->gate_installed=0; /* This generation is now confirmed; cleanup must retain it. */
    for(size_t i=0;i<SCHED_SEEN;i++)if(s->preflight_leases[i].owner==t)s->preflight_leases[i].owner=NULL;
    t->gate_active=0;s->confirms++;s->plan_gen++;
    say(s,"по %s preflight: ПОДТВЕРЖДЕНО — исполнение своего поколения, TLS и полный HTTP",t->name);
    search_report(s,t,now_ms,"probe-confirmed",t->gate_combined?"fallback-combined":t->gate_reuse?"own-plan":"property",
                  "проба начального ответа подтверждена исполнением и полным HTTP-ответом");
    task_done(s,t);
}

/* Save only observed/configured service associations. They are not SNI
   attributed to an unnamed client, nor evidence that a plan succeeded. */
static void force_remember(d2k_sched *s,const char *name,const char *ip,
                           uint16_t port,uint8_t transport,uint8_t family,uint8_t shape) {
    if(!force_name(s,name) || !port || !ip[0])return;
    for(size_t i=0;i<s->n_forced;i++) {
        force_target *f=&s->forced[i];
        if(f->transport==transport && f->family==family && f->port==port &&
           !strcasecmp(f->name,name) && !strcmp(f->ip,ip)) {if(shape)f->shape=shape;return;}
    }
    size_t k=s->n_forced<SCHED_SEEN?s->n_forced++:s->force_next++%SCHED_SEEN;
    force_target *f=&s->forced[k];memset(f,0,sizeof *f);
    snprintf(f->name,sizeof f->name,"%s",name);
    snprintf(f->ip,sizeof f->ip,"%s",ip);
    f->port=port;f->transport=transport;f->family=family;f->shape=shape;
}
static void force_retry(d2k_sched *s,task *t) {
    /* A new owned experiment keeps negative hypotheses/measurements, never
       a candidate's ACK, wire execution or application success. */
    task *old=malloc(sizeof *old);if(!old)return;
    memcpy(old,t,sizeof *old);
    memset(&t->run_cache,0,sizeof t->run_cache); /* transfer, do not free */
    task_reset(s,t);
#define KEEP(x) memcpy(&t->x,&old->x,sizeof t->x)
    KEEP(name);KEEP(ip);KEEP(port);KEEP(transport);KEEP(family);KEEP(by_addr);
    KEEP(trigger_shape);KEEP(trigger_code);KEEP(trig);KEEP(trig_len);KEEP(trig_snapped);
    KEEP(ctrl);KEEP(ctrl_len);KEEP(tried);KEEP(n_tried);KEEP(tried_full);KEEP(own_tried);KEEP(n_own_tried);
    KEEP(arm_refuted);KEEP(n_arm_refuted);KEEP(measured_props);KEEP(fp);
    KEEP(seed);KEEP(seed_input);KEEP(vol);KEEP(doh_failure_query);KEEP(doh_path);KEEP(dns_dot);KEEP(dns_expected_http);
    KEEP(dns_question);KEEP(dns_qtype);
    KEEP(run_cache);KEEP(client_opts);KEEP(client_opts_len);KEEP(client_opts_known);
    KEEP(trigger_flow);KEEP(trigger_planned);
#undef KEEP
    t->seed_use=1;t->own_first=3;
    free(old);
    say(s,"принудительный поиск: %s — предыдущий опыт не подтвердил обход; следующий полный замер, испытанные кандидаты и измерения сохранены",t->name);
    (void)launch_or_queue(s,t);
}
static task *force_task_of(d2k_sched *s,const force_target *f) {
    for(size_t i=0;i<SCHED_MAX_TASKS;i++) {
        task *t=&s->tasks[i];
        if(t->state!=T_FREE && t->transport==f->transport && t->family==f->family &&
           t->port==f->port && !strcasecmp(t->name,f->name) && !strcmp(t->ip,f->ip))return t;
    }
    return NULL;
}
/* Configured encrypted resolvers are handled by the journal event path. */
static void force_tick(d2k_sched *s) {
    for(size_t i=0;i<s->n_forced;i++) {
        force_target f=s->forced[i];
        if(!force_name(s,f.name) || d2k_newchain_protects(&s->newchain,f.name,f.transport,f.family,f.shape))continue;
        task *t=force_task_of(s,&f);
        if(f.transport==6 && doh_find(s,f.name))continue;
        if(t && t->state==T_RESTING){force_retry(s,t);continue;}
        if(t)continue;
        t=task_free_slot(s);if(!t)return;
        task_reset(s,t);snprintf(t->name,sizeof t->name,"%s",f.name);
        snprintf(t->ip,sizeof t->ip,"%s",f.ip);
        t->transport=f.transport;t->family=f.family;t->port=f.port;t->trigger_shape=f.shape;
        t->fp.method=D2K_FP_METHOD;
        say(s,"принудительный поиск: %s (%s:%u) — первый поток/повтор без подтверждённого обхода, подозрение не требуется",f.name,f.ip,(unsigned)f.port);
        (void)launch_or_queue(s,t);
    }
}
static void force_event(d2k_sched *s,const d2k_ev *ev) {
    if(!s->n_force)return;
    char ip[INET6_ADDRSTRLEN];uint16_t port;server_of(ev,ip,sizeof ip,&port);
    uint8_t family=ev->family?ev->family:4;
    if(ev->name[0]) {
        force_remember(s,ev->name,ip,port,ev->transport,family,ev->client_shape);
    } else {
        /* Configured DoH addresses also work before an SNI has been seen. */
        for(size_t i=0;i<s->n_doh;i++) {
            const doh_target *d=&s->doh[i];
            if(!d->plain && ev->transport==6 && port==d->port && !strcmp(ip,d->ip))
                force_remember(s,d->host,ip,port,6,family,0);
        }
    }
    force_tick(s);
}

static void synthesis_owner(d2k_sched *s,const d2k_ev *ev) {
    shadow_flow_state *w=shadow_flow(s,ev);
    if(ev->transport!=6 || !w || !w->name[0])return;
    if(!w->hello_len || w->snapshot_queued)return; /* wait for this flow's bytes/options */
    if(d2k_newchain_protects(&s->newchain,w->name,6,w->tuple.family,w->client_shape))return;
    doh_target *d=doh_find(s,w->name);
    if(!d && !force_name(s,w->name))return;
    d2k_shadow_record r={.time=(uint64_t)time(NULL),.family=w->tuple.family,.priority=2};
    if(shadow_server(w,ev,&r))return;
    if(d && (d->port!=r.port || strcmp(d->ip,r.ip)))return;
    strcpy(r.host,w->name);r.protocol=w->client_shape==D2K_SHAPE_LEGACY?1:2;
    if(d)snprintf(r.doh_path,sizeof r.doh_path,"%s",d->path);
    if(shadow_submit(s,w,&r)==1) {w->snapshot=0;w->snapshot_queued=1;}
}

static int plain_trial_event(task *t,const d2k_ev *event) {
    if (t->state!=T_DNS_PLAIN_TRIAL || !t->trial_installed ||
        memcmp(event->trial_id,t->addr_probe_trial_id,D2K_TRIAL_ID_LEN))return 0;
    if (event->kind==D2K_EV_ACK && event->code==D2K_CMD_SET_DNS_PROBE) {
        if (((event->num>>8)&0xffu)==1)t->trial_acked=1;
        else t->exec_nak=1;
        return 1;
    }
    if (t->job!=JOB_DNS_PLAIN_RUN || !t->trial_acked ||
        !ev_matches_flow(event,&t->ver_flow) ||
        memcmp(event->plan_id,t->ver_plan_id,D2K_PLAN_ID_LEN))return 0;
    if (event->kind==D2K_EV_REFUSED) {t->exec_nak=1;return 1;}
    const d2k_binding_context *b=&event->execution_binding;
    if (event->kind!=D2K_EV_APPLIED || !event->execution_id || !d2k_binding_known(b) ||
        !b->temporary || b->kind!=D2K_BIND_FLOW || b->shape!=D2K_LINK_SHAPE_RAW ||
        b->family!=t->family)return 0;
    t->ver_ok=1;
    return 1;
}

int d2k_sched_event(d2k_sched *s, const d2k_ev *ev) {
    if (!s || !ev) { return -1; }
    if(preflight_lease_event(s,ev)){wake_loop(s);return 0;}
    if(plain_dns_ack(s,ev)){wake_loop(s);return 0;}
    if(d2k_newchain_event(&s->newchain,ev,newchain_log,s)) {
        /* Legacy reconciliation is disabled in this mode. Keeping it pending
           makes the controller's poll timeout zero after the first ACK. */
        s->sync_pending=!s->synthesis_only;
        (void)d2k_newchain_poll(&s->newchain,s->link_fd,s->now_ms,newchain_log,s);
        return 0;
    }
    if(s->synthesis_only) {
        switch(ev->kind) {
        case D2K_EV_HELLO: shadow_begin(s,ev);synthesis_owner(s,ev);break;
        case D2K_EV_FLOW: shadow_begin(s,ev);break;
        case D2K_EV_CLIENT_TCP: {
            shadow_flow_state *w=shadow_flow(s,ev);
            if(w && ev->tcp_options_len<=sizeof w->options) {
                memcpy(w->options,ev->tcp_options,ev->tcp_options_len);
                w->options_len=ev->tcp_options_len;w->options_known=1;
            }
            break;
        }
        case D2K_EV_SHAPE: shadow_shape(s,ev);synthesis_owner(s,ev);break;
        case D2K_EV_EXCHANGE: shadow_clean(s,ev);break;
        case D2K_EV_SUSPECT: return on_suspect_as(s,ev,shadow_flow(s,ev)?shadow_flow(s,ev)->name:NULL,0);
        default: break;
        }
        return 0;
    }
    s->event_sequence++;
    (void)d2k_stun_trial_reap(ev);
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        task *t=&s->tasks[i];
        if(plain_trial_event(t,ev)){wake_loop(s);return 0;}
        if(gate_event(s,t,ev)){wake_loop(s);return 0;}
        if(t->state==T_VOICE_INSTALL && ev->kind==D2K_EV_ACK &&
           ev->code==D2K_CMD_SET_ENDPOINT_BOUND &&
           !memcmp(ev->trial_id,t->voice_install_token,D2K_TRIAL_ID_LEN)) {
            const d2k_binding_context *b=&ev->execution_binding;
            if(((ev->num>>8)&0xffu)==1u && d2k_binding_known(b) &&
               b->kind==D2K_BIND_ADDR && !b->temporary &&
               b->family==t->family && b->shape==D2K_LINK_SHAPE_VOICE)
                t->voice_install_acked=1;
            else t->voice_install_refused=1;
            wake_loop(s);return 0;
        }
        if (stun_client_event(&s->tasks[i], ev)) { wake_loop(s); return 0; }
        if (stun_candidate_event(&s->tasks[i], ev)) { wake_loop(s); return 0; }
    }
    switch (ev->kind) {
    case D2K_EV_HELLO:
        preflight_observe_named_path(s,ev,0);
        dns_observe_hello(s,ev);
        shadow_begin(s,ev);
        remember(s, ev);
        force_event(s,ev);
        return 0;
    case D2K_EV_RAW_MEASURE:
        raw_measure_result(s,ev);return 0;
    case D2K_EV_ACK:
        if (ev->code == D2K_CMD_ARM_SHAPE) {
            for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
                task *t = &s->tasks[i];
                if (t->state == T_SHAPE_WAIT && t->shape_request_pending &&
                    !memcmp(t->shape_request_id, ev->trial_id, 16))
                    t->shape_request_pending = 0;
            }
            return 0;
        }
        if(ev->code==D2K_CMD_RAW_MEASURE){raw_measure_ack(s,ev);return 0;}
        if(ev->code==D2K_CMD_SET_RAW_PROBE) {
            for(size_t i=0;i<SCHED_MAX_TASKS;i++) {
                task *t=&s->tasks[i];
                if((t->state!=T_RAW_TRIAL && t->state!=T_RAW_WATCH) ||
                   !candidate_trial_matches(t,ev->code,ev->trial_id))continue;
                if(((ev->num>>8)&255)!=1) {
                    if(t->raw_renewing && t->state==T_RAW_WATCH) {
                        t->raw_renewing=0; /* Already executed: its own verdict stands. */
                    } else if(t->raw_renewing) {
                        raw_trial_end_unknown(s,t,"candidate-lost",
                            "датапат не продлил измеренный опыт (поток закрыт, сменилось поколение или нет места); сетевой исход не установлен");
                    } else {
                        unknown_note(s,"addr",t->ip,t->transport,t->family,t->port,"candidate-refused",
                                     "датапат отверг измеренный опыт; сетевой исход не установлен");
                        raw_measure_watch_done(s,t,-1);trial_retire(s,t);task_done(s,t);
                    }
                } else if(t->raw_renewing) {
                    t->raw_renewing=0;t->raw_lease_ms=t->raw_renew_lease_ms;
                    t->raw_lease_until_ms=t->raw_renew_sent_ms+t->raw_renew_lease_ms;
                } else t->trial_acked=1;
                break;
            }
            return 0;
        }
        if (ev->code == D2K_CMD_LATE_OBSERVE) {
            if (((ev->num >> 8) & 0xffu) != 1u) late_obs_refused(s, ev);
            return 0;
        }
        if (s->area_command && ev->code == s->area_command &&
            !memcmp(ev->trial_id, s->area_id, sizeof s->area_id)) {
            if (((ev->num >> 8) & 255) != 1) {
                say(s, "область %s отвергнута датапатом (код %u)", s->area_pending.name, (unsigned)(ev->num & 255));
                s->area_sync_failed = 1;
            } else {
                size_t i;
                for (i = 0; i < s->n_areas; i++) if (area_key_same(&s->area_pending, &s->areas[i])) break;
                if (ev->code == D2K_CMD_DEL_SUFFIX || ev->code == D2K_CMD_DEL_BYPASS) {
                    if (i < s->n_areas) s->areas[i] = s->areas[--s->n_areas];
                } else if (s->areas && i < s->areas_capacity) {
                    s->areas[i] = s->area_pending;
                    s->areas[i].confirmed = 1;
                    s->areas[i].confirmed_event = s->event_sequence;
                    if (i == s->n_areas) s->n_areas++;
                }
            }
            s->area_command = 0;
            return 0;
        }
        if ((ev->code == D2K_CMD_SET_NAME || ev->code == D2K_CMD_SET_NAME_BOUND ||
             ev->code == D2K_CMD_SET_SUFFIX || ev->code == D2K_CMD_SET_ADDR ||
             ev->code == D2K_CMD_SET_ENDPOINT || ev->code == D2K_CMD_SET_ENDPOINT_BOUND) &&
            ((ev->num >> 8) & 0xffu) != 1u) {
            /* ДАТАПАТ ОТВЕРГ ПЛАН КАТАЛОГА. Имени в подтверждении нет (ниже),
               поэтому только счёт — строкой в сводке следующего прохода
               (d2k_sched_sync_step). Это не местный отказ опыта: такой план
               уже подтверждён, и цель остаётся без обхода, пока датапат его не
               берёт. */
            s->sync_refused++;
            s->sync_refused_code = ev->num & 0xffu;
            /* A rejected installation must be visible now, even if no further
               catalog pass occurs. Keep the aggregate for repeated refusals. */
            char quiet_key[64];
            snprintf(quiet_key, sizeof quiet_key, "catalog-refusal %u %u",
                     (unsigned)ev->code, s->sync_refused_code);
            say_quiet(s, quiet_key,
                "каталог: датапат отверг команду установки (тип %u): %s; "
                "отправка команды не означает, что план установлен",
                (unsigned)ev->code, ack_reason_text(s->sync_refused_code));
        }
        /* ТИП КОМАНДЫ В ПОДТВЕРЖДЕНИИ ЕСТЬ, И ОН ОБЯЗАТЕЛЕН.
           Имени цели подтверждение не несёт, но тип команды несёт (d2k_link.h:
           code — тип, num — (ok<<8)|причина). Засчитывать ЛЮБОЙ ack значило бы
           отпускать ожидание по чужому, в том числе по старому, лежавшему в
           сокете: на живой линии 18.09 ожидание так и отпускалось мгновенно, и
           зонд снова обгонял план.
           Датапат шлёт ack ПОСЛЕ установки плана в таблицу (ctlsrv.c), значит
           этот ack и есть «план на месте». */
        if (ev->code == D2K_CMD_SET_NAME_PROBE || ev->code == D2K_CMD_SET_ADDR_PROBE) {
            /* v8: ack пробной установки несёт trial ID опыта (задача 19).
               Нулевой — чужой (диагностический вопрос, d2kask): ожидание
               кандидата им не отпускается. Отказ (ok=0) — местный отказ
               исполнителя: кандидат не судим, сетевого зонда нет, берём
               следующего. Поздний отказ (зонд уже ушёл по сроку ожидания)
               — то же: зонд шёл без плана, его исход не про кандидата. */
            uint8_t any = 0;
            for (size_t k = 0; k < D2K_TRIAL_ID_LEN; k++) { any |= ev->trial_id[k]; }
            if (!any) { return 0; }
            int ok = ((ev->num >> 8) & 0xffu) == 1u;
            unsigned code = ev->num & 0xffu;
            for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
                task *t = &s->tasks[i];
                if (!candidate_trial_matches(t, ev->code, ev->trial_id)) { continue; }
                if (t->state == T_TRIAL_SETTLE) {
                    if (ok) { t->trial_acked = 1; wake_loop(s); }
                    else { exec_refusal(s, t, code, 0); }
                } else if (!ok && t->state == T_VERIFY) {
                    /* Рабочий поток зонда ещё в сети: разбор — когда вернётся. */
                    t->exec_nak = 0x100u | code;
                } else if (!ok && t->state == T_VERIFY_WAIT) {
                    exec_refusal(s, t, code, 1);
                }
            }
        }
        if (ev->code == D2K_CMD_SET_ADDR_PROBE &&
                   ((ev->num >> 8) & 0xffu) != 1u) {
            /* ДАТАПАТ ОТВЕРГ ГОЛОСОВОЙ ОПЫТ (нет места, план не принят) —
               это местный отказ: опыта не было, кандидат не судим. */
            for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
                task *t = &s->tasks[i];
                if ((t->state == T_VOICE_TRIAL || t->state == T_VOICE_WATCH) &&
                    voice_trial_owned(t) &&
                    memcmp(ev->trial_id, t->addr_probe_trial_id, D2K_TRIAL_ID_LEN) == 0) {
                    say(s, "по %s (голос) датапат отверг опыт (причина %u) — "
                           "местный отказ, опыта не было, кандидат не судим",
                        t->name, (unsigned)(ev->num & 0xffu));
                    trial_retire(s, t);
                    task_done(s, t);
                }
            }
        }
        return 0;
    case D2K_EV_SUSPECT:
        return on_suspect(s, ev);
    case D2K_EV_STATS:
        s->dropped_seen = ev->dropped;
        return 0;
    case D2K_EV_SHAPE:
        shadow_shape(s,ev);
        on_shape(s, ev);
        return 0;
    case D2K_EV_CLIENT_TCP: {
        /* Набор опций TCP клиента — ждёт свой SHAPE (тот же поток), см. on_shape. */
        int f = ev->family == 6;
        shadow_flow_state *shadow_client=shadow_flow(s,ev);
        if(shadow_client && ev->tcp_options_len<=sizeof shadow_client->options) {
            memcpy(shadow_client->options,ev->tcp_options,ev->tcp_options_len);
            shadow_client->options_len=ev->tcp_options_len;shadow_client->options_known=1;
        }
        if (ev->tcp_options_len > sizeof s->tcp_opts_wait_bytes[f]) { return 0; }
        memcpy(s->tcp_opts_wait_bytes[f], ev->tcp_options, ev->tcp_options_len);
        s->tcp_opts_wait_len[f] = ev->tcp_options_len;
        d2k_flowkey *flow = &s->tcp_opts_wait_flow[f];
        memcpy(flow->a_ip, ev->low_ip, 16); memcpy(flow->b_ip, ev->high_ip, 16);
        flow->a_port = ev->low_port; flow->b_port = ev->high_port;
        flow->transport = 6; flow->family = ev->family ? ev->family : 4;
        s->tcp_opts_wait[f] = 1;
        return 0;
    }
    case D2K_EV_APPLIED: {
        /* Поток под ПОСТОЯННЫМ планом (этап 41) — под наблюдение счётчиков, и
           без приветствия (игра, UDP/TCP по адресу): по имени, если поток
           узнан, иначе по адресу и порту сервера. Исполнение опыта (trial ID)
           — не постоянный план; его судит свой опыт. */
        int trial = 0;
        for (size_t k = 0; k < D2K_TRIAL_ID_LEN; k++) trial |= ev->trial_id[k];
        if (ev->execution_id && !trial) flowwatch_add(s, ev, recall(s, ev), 0);
        on_applied(s, ev);
        return 0;
    }
    case D2K_EV_REFUSED:
        on_refused(s, ev);
        return 0;
    case D2K_EV_EXCHANGE:
        shadow_clean(s,ev);
        on_exchange(s, ev);
        return 0;
    case D2K_EV_LATE_OBS:
        on_late_obs(s, ev);
        return 0;
    case D2K_EV_FLOW:
        shadow_begin(s,ev);
        /* Explicit operator targets are the sole admission exception below. */
        force_event(s,ev);
        /* ПОЯВЛЕНИЕ ПОТОКА БЕЗ ПРОТОКОЛА (этап 42) — только наблюдение
           счётчиков, пассивно. Факт существования не подозрение: ни поиска,
           ни записи неизвестной цели, ни команд датапату. Имени у такого
           потока нет: имя в памяти приветствий того же кортежа — от прежнего
           соединения и новому не приписывается (этап 49). */
        flowwatch_add(s, ev, "", 1);
        return 0;
    default:
        return 0;
    }
}

/* ШАГ СВОИХ ПЛАНОВ ПРОЙДЕН — ПОЛНЫЙ ЗАМЕР КАК ПРЕЖДЕ (задача 32).
   Испытание своих планов не оставляет следов в поиске: пробная запись снята
   точно, очередь и бюджет зондов — с нуля, коробка не назначена, объём и
   ответ базы забыты (база в вердикт не идёт: полный прогон задаст её заново).
   Снимок клиента, пришедший во время испытания, берётся сразу — иначе
   прогон пошёл бы заготовкой и перезапустился бы после конца. */
static void own_first_continue(d2k_sched *s, task *t) {
    /* ПРОВЕРКА ПОЯВИВШЕГОСЯ ПЛАНА ПОЛНОГО ЗАМЕРА НЕ НАЧИНАЕТ (24.10.2026).
       Такая задача заведена без запроса клиента и ровно для одного дела:
       испытать план, который появился в каталоге после отдыха цели
       (plan_news_recheck). Не подтвердился — замер по этой цели только что
       был, и повторять его по своему же поводу значит гонять зонды без
       спроса. Цель остаётся отдыхать, как и была. */
    if (t->plan_retry && !force_name(s,t->name)) {
        /* ИСПЫТАННОЕ — В ПАМЯТЬ ОСТЫВАНИЯ (ревью 24.10.2026, замечание 3).
           Без этого провалившийся план не считался пробованным: поколение
           знания растёт на подтверждении ЛЮБОЙ другой цели, сверка
           «предлагает ли каталог непробованное» снова отвечала «да», и тот же
           план проверялся зондами заново на каждом чужом подтверждении.
           Обычному поиску эти хэши кладёт ЗАПИСЬ остывания (cooldown_record),
           а проверка плана остывания не записывает — его завёл провалившийся
           поиск. Поэтому след кладём сами, не трогая срок. */
        for (size_t k = 0; k < t->n_plans && k < 32; k++) {
            if (!(t->own_probed & (1u << k))) continue;
            tried_add(t, (uint32_t)fnv1a(t->plans[k]));
            own_tried_add(t, (uint32_t)fnv1a(t->plans[k]));
        }
        cooldown_note_tried(s, t);
        say(s, "по %s появившийся план коробки не подтвердился — полного замера не "
               "начинаю: он по этой цели только что был", t->name);
        task_fail(s, t, s->now_ms);
        return;
    }
    /* Фазу может оборвать и срок жизни посреди испытания: рабочий поток
       зонда сперва присоединяется, потом снимается его опыт. */
    join_worker(t);
    trial_retire(s, t);
    ver_close(t);
    /* Испытанные на проводе свои планы полный прогон второй раз не берёт. */
    for (size_t k = 0; k < t->n_plans && k < 32; k++) {
        if (!(t->own_probed & (1u << k))) continue;
        tried_add(t, (uint32_t)fnv1a(t->plans[k]));
        own_tried_add(t, (uint32_t)fnv1a(t->plans[k]));
    }
    t->own_probed = 0;
    t->seed_use = 1;
    t->own_first = 3;
    /* СРОК ЖИЗНИ — ЗАНОВО (задача 49, повторное ревью A). Фаза своих планов
       конечна сама (каждый текст в очереди один раз), а полному замеру нужен
       свой целый SCHED_TASK_LIFE_MS: иначе десятки своих планов съедали бы
       его срок, и цель, которую замер нашёл бы, уходила в отдых. Страховка
       от зацикливания остаётся у каждой фазы. */
    int64_t began = t->began_ms ? t->began_ms : t->started_ms;
    t->started_ms = s->now_ms;
    t->n_plans = t->n_known = t->next_plan = 0;
    t->exec_refused = t->exec_probed = 0;
    t->cached_measure_valid = 0;
    t->box_id[0] = '\0';
    t->rx_phase = 0;
    t->ask_probes += t->probes; /* на карточке зонды не пропадают (задача 49) */
    t->probes = 0;
    /* ЗАБЫТЬ ОБЪЁМ МОЖНО, ТОЛЬКО ЕСЛИ ПОЛНЫЙ ПРОГОН СПРОСИТ ЕГО ЗАНОВО.
       Повтор снимком с доказанным обрывом ответа ставит skip_volume_once
       («отвеченное не переспрашивается»), и тогда t->vol — единственная
       запись доказательства этого эпизода. Поле 14.10.2026, fast.com: обрыв
       около 15 КБ доказан парой при полном gzip (эталон с VPS 26326 байт,
       с роутера 16384), повтор байтами клиента начался с базового вопроса,
       база прошла 3 из 3 — и стёртый здесь объём превратил доказанный блок
       в «триггер проходит как есть — обходить нечего»; лестница белого
       имени, которую открывает t->vol.rx_cut, не началась. */
    if (t->transport == 6 && !(t->skip_volume_once && t->vol.rx_cut))
        memset(&t->vol, 0, sizeof t->vol);
    memset(&t->res, 0, sizeof t->res);
    int f = t->family == 6;
    if (t->transport == 6 && !t->trig_snapped && !t->reasked && s->tcp_shape_len[f] > 0 &&
        s->tcp_shape_len[f] <= sizeof t->trig && !strcmp(s->tcp_shape_name[f], t->name)) {
        memcpy(t->trig, s->tcp_shape[f], s->tcp_shape_len[f]);
        t->trig_len = s->tcp_shape_len[f];
        t->trig_snapped = 1;
        take_shape_opts(s, t);
        t->reasked = 1;
        t->ctrl_len = 0;
        say(s, "по %s снимок клиента пришёл во время проверки своих планов — "
               "полный замер иду его байтами: %zu", t->name, t->trig_len);
    }
    char name[sizeof t->name];
    snprintf(name, sizeof name, "%s", t->name);
    t->began_ms = began; /* перезапуск окна не «омолаживает» поиск на карточке */
    if (!start_search(s, t))
        say(s, "по %s полный замер не запустился — задача снята, следующее "
               "подозрение начнёт поиск заново", name);
}

/* A working TLS bootstrap is not necessarily a complete bypass: identity
 * may still be truncated while gzip succeeds. Each follow-up reserves a new
 * socket and reinstalls only this candidate on that socket's source port. */
static int rx_saved_bootstrap(d2k_sched *s, task *t, int allow_other_family) {
    if (t->transport != 6 || t->by_addr ||
        d2k_hello_shape(t->trig, t->trig_len) != D2K_SHAPE_MODERN) return 0;
    const d2k_cat_binding *best = NULL;
    const d2k_cat_plan *plan = NULL;
    const d2k_cat_box *owner = NULL;
    for (size_t bi = 0; bi < s->cat->n_boxes; bi++) {
        const d2k_cat_box *b = &s->cat->boxes[bi];
        for (size_t i = 0; i < b->n_binds; i++) {
            const d2k_cat_binding *bd = &b->binds[i];
            if (!bd->enabled || strcmp(bd->kind, "name") || strcmp(bd->target, t->name) ||
                (bd->transport ? bd->transport : 6) != 6 ||
                (!allow_other_family && (bd->family ? bd->family : 4) != t->family) ||
                ((bd->family ? bd->family : 4) != 4 && bd->family != 6) ||
                bd->shape != D2K_SHAPE_MODERN || (bd->level && bd->level < 3)) continue;
            if ((bd->family ? bd->family : 4) != t->family && bd->level < 3) continue;
            for (size_t j = 0; j < b->n_plans; j++) {
                const d2k_cat_plan *p = &b->plans[j];
                if (!p->enabled || !p->text || strcmp(p->id, bd->plan_id) ||
                    strcmp(p->proto, "tls") || strlen(p->text) >= sizeof t->plans[0]) continue;
                int exact = (bd->family ? bd->family : 4) == t->family;
                int best_exact = best && (best->family ? best->family : 4) == t->family;
                /* Тот же выбор, что у установки (задача 55): прошедшая бюджет,
                   затем новейшая — меряем под планом, который стоит на проводе. */
                if (!best || (exact && !best_exact) ||
                    (exact == best_exact && binding_beats(bd, best))) {
                    best = bd; plan = p; owner = b;
                }
            }
        }
    }
    if (!plan) return 0;
    snprintf(t->plans[0], sizeof t->plans[0], "%s", plan->text);
    int same_family = (best->family ? best->family : 4) == t->family;
    snprintf(t->plan_boxes[0], sizeof t->plan_boxes[0], "%s", same_family ? owner->id : "");
    t->next_plan = 0; t->n_plans = 1; t->n_known = same_family ? 1 : 0; t->fb_queue = 0;
    t->researched = 1; t->rx_bootstrap_only = 1;
    t->state = T_PLANNING;
    say(s, "по %s прямой RX-зонд не дошёл до TLS; измеряю identity под уже "
           "подтверждённым планом этой цели, без нового общего перебора", t->name);
    if (!same_family) say(s, "по %s собственный план IPv%u проверяю отдельно по IPv%u; "
                            "подтверждение и отпечаток между семьями не переношу",
                           t->name, (unsigned)(best->family ? best->family : 4), (unsigned)t->family);
    return 1;
}

static int layered_rx_result(d2k_sched *s, task *t, int64_t now_ms) {
    int eligible = t->transport == 6 && !t->vol.rx_cut && !encrypted_dns_task(t) &&
        (t->res.program_len || (t->vol.rx_tls_unavailable &&
         (t->res.verdict == D2K_V_OPAQUE || t->rx_bootstrap_only || t->own_first == 2))) &&
        d2k_hello_shape(t->trig, t->trig_len) == D2K_SHAPE_MODERN;
    if (!eligible || !t->next_plan) return 0;
    d2k_ev own = {0};
    own.family = t->ver_flow.family;
    memcpy(own.low_ip, t->ver_flow.a_ip, sizeof own.low_ip);
    memcpy(own.high_ip, t->ver_flow.b_ip, sizeof own.high_ip);
    own.low_port = t->ver_flow.a_port; own.high_port = t->ver_flow.b_port;
    own.transport = t->ver_flow.transport;
    int applied = 0;
    for (size_t k = 0; k < t->ver_seen; k++)
        if (ev_matches_flow(&own, &t->ver_early[k])) { applied = 1; break; }
    int partial = applied && !t->unsent_code &&
        t->ver.http_outcome != D2K_HTTP_BLOCKED && t->ver.http_outcome != D2K_HTTP_LEGAL_DENIAL &&
        d2k_volume_rx_partial(&t->ver);
    if (!t->rx_phase && !partial) return 0;

    if (t->rx_phase == 2) {
        int proven = applied && !t->unsent_code &&
            t->ver.http_outcome != D2K_HTTP_BLOCKED && t->ver.http_outcome != D2K_HTTP_LEGAL_DENIAL &&
            d2k_volume_rx_evidence(&t->rx_identity[0], &t->rx_identity[1], &t->ver, &t->vol);
        ver_close(t); trial_retire(s, t); t->rx_phase = 0;
        if (proven) {
            /* A transferred plan exposed a new measured RX block too.
               A plan-news retry may ask that residual question; it must
               not drop the evidence as an unsuccessful transfer. */
            t->own_first = 3;
            t->plan_retry = 0;
            t->rx_bootstrap_only = 0;
            say(s, "по %s кандидат снял ранний TLS-блок, но identity дважды "
                   "оборвался около %d КБ при полном gzip; ищу остаточный RX-обход",
                t->name, t->vol.rx_at_kb);
            t->cached_measure_valid = 0;
            t->researched = 1;
            t->rx_volume_next_variant = 0;
            t->net_probe_next = 0; /* ладдер строится заново — подбор с начала списка */
            /* The application measured a separate residual volume block.
               Do not requeue the handshake program or resume its failed
               application trial in place of the measured RX question. */
            d2k_vres residual = t->res;
            residual.program_len = 0; residual.program[0] = 0;
            residual.synthesis_generation = 0;
            t->synthesis_resume_pending = 0;
            t->res = residual;
            verdict_to_plans(s, t, &residual);
        } else {
            say(s, "по %s RX-обрыв под кандидатом не подтверждён полным gzip-контролем; "
                   "не сохраняю gzip как окончательный обход", t->name);
        }
        t->state = T_PLANNING;
        t->rx_retry_after_ms = now_ms + 500;
        return 1;
    }

    if (t->rx_phase == 1 && partial) {
        const d2k_ver_result *a = &t->rx_identity[0], *b = &t->ver;
        uint64_t delta = a->body_bytes > b->body_bytes
            ? a->body_bytes - b->body_bytes : b->body_bytes - a->body_bytes;
        partial = a->body_has_length == b->body_has_length &&
            a->body_chunked == b->body_chunked &&
            delta <= (uint64_t)D2K_VOLUME_SLACK * 1024;
    }
    if (!partial || t->probes >= sched_probe_cap(t)) {
        say(s, "по %s повторный identity-обрыв под кандидатом не подтвердился; "
               "RX-профиль не создаю", t->name);
        ver_close(t); trial_retire(s, t); t->rx_phase = 0;
        t->state = T_PLANNING;
        return 1;
    }
    t->rx_identity[t->rx_phase] = t->ver;
    t->rx_identity[t->rx_phase].fd = -1;
    say(s, "по %s под кандидатом identity-%u оборвался на %llu байтах; "
           "%s на новом изолированном порту", t->name, t->rx_phase + 1,
        (unsigned long long)t->ver.body_bytes,
        t->rx_phase ? "проверяю gzip-контроль" : "повторяю identity");
    ver_close(t); trial_retire(s, t);
    t->rx_phase++;
    t->next_plan--; /* same candidate, newly reserved socket and trial */
    t->rx_retry_after_ms = now_ms + 500;
    t->state = T_PLANNING;
    return 1;
}

/* Порядок выпуска очереди (задача 29). Сохранённое восстановление семейства
   по-прежнему впереди всех (задача 24); среди равных — сначала «горячие»
   (новое подозрение пришло, пока цель ждала; свежее — раньше), затем FIFO по
   порядку постановки. Истёкшие к этому моменту уже сняты проходом тика. */
static int queued_before(const task *a, const task *b) {
    if (a->queued_response_priority != b->queued_response_priority)
        return a->queued_response_priority > b->queued_response_priority;
    if (a->hot_event != b->hot_event) return a->hot_event > b->hot_event;
    if (a->queued_event != b->queued_event) return a->queued_event < b->queued_event;
    return a->queued_ms < b->queued_ms;
}

/* Only the loop lends/releases a slot. Worker flags are read under mu;
 * no task state, trial or classification result changes on a pause. */
static void quic_yield_tick(d2k_sched *s,int64_t now_ms) {
    int tcp_waiting=0;
    for(size_t i=0;i<SCHED_MAX_TASKS;i++)
        if(s->tasks[i].state==T_QUEUED && s->tasks[i].transport==6)tcp_waiting=1;
    int need_slot=tcp_waiting && measurements_in_flight(s)>=s->meas_limit;
    task *resume=NULL;
    int parked_log[SCHED_MAX_TASKS]={0};
    pthread_mutex_lock(&s->mu);
    for(size_t i=0;i<SCHED_MAX_TASKS;i++) {
        task *t=&s->tasks[i];
        if(t->state!=T_ASKING || t->transport!=17 || t->job!=JOB_CLASSIFY)continue;
        t->quic_clock_ms=now_ms;
        t->quic_yield_request=need_slot;
        if(t->quic_yield_waiting && !t->quic_parked){
            t->quic_parked=1;t->quic_parked_ms=t->quic_wait_started_ms;
            t->quic_tcp_turn=s->tcp_admission_sequence;parked_log[i]=1;
        }
        if(t->quic_parked && (!tcp_waiting || t->quic_tcp_turn!=s->tcp_admission_sequence) &&
           (!resume || t->quic_parked_ms<resume->quic_parked_ms))resume=t;
    }
    int64_t resumed_wait=-1;
    if(resume && measurements_in_flight(s)<s->meas_limit &&
       (!s->measure_start_seen || now_ms-s->last_measure_start_ms>=SCHED_START_GAP_MS)) {
        int64_t wait=now_ms-resume->quic_parked_ms;
        if(wait>0){resume->report_queue_ms+=wait;resume->started_ms+=wait;}
        resumed_wait=wait;
        resume->quic_parked=resume->quic_yield_waiting=resume->quic_yield_request=0;
        s->last_measure_start_ms=now_ms;s->measure_start_seen=1;
        pthread_cond_broadcast(&s->question_cv);
    }
    pthread_mutex_unlock(&s->mu);
    for(size_t i=0;i<SCHED_MAX_TASKS;i++)if(parked_log[i])
        say(s,"по %s (QUIC) вопрос завершён: уступаю слот ожидающему TCP, ответы сохранены",s->tasks[i].name);
    if(resumed_wait>=0)
        say(s,"по %s (QUIC) продолжаю со следующего вопроса после очереди (%lld мс)",resume->name,(long long)resumed_wait);
}

static task *queued_pick(d2k_sched *s) {
    task *forced=NULL;
    for(size_t i=0;i<SCHED_MAX_TASKS;i++) {
        task *t=&s->tasks[i];
        if(t->state==T_QUEUED && force_name(s,t->name) &&
           (!forced || queued_before(t,forced)))forced=t;
    }
    if(forced)return forced;
    int tcp_first=0;
    for(size_t i=0;i<SCHED_MAX_TASKS;i++)if(s->tasks[i].quic_parked)tcp_first=1;
    if(tcp_first){
        task *best=NULL;
        for(size_t i=0;i<SCHED_MAX_TASKS;i++){
            task *t=&s->tasks[i];
            if(t->state==T_QUEUED && t->transport==6 && (!best || queued_before(t,best)))best=t;
        }
        if(best)return best;
    }
    int recovery = 0;
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++)
        if (s->tasks[i].state == T_QUEUED && family_recovery_eligible(s, &s->tasks[i]))
            recovery = 1;
    task *best = NULL;
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        task *t = &s->tasks[i];
        if (t->state != T_QUEUED) continue;
        if (recovery && !family_recovery_eligible(s, t)) continue;
        if (!best || queued_before(t, best)) best = t;
    }
    return best;
}

static int queued_release(d2k_sched *s, int64_t now_ms) {
    if (!queued_measurements(s)) return 0;
    size_t active = measurements_in_flight(s);
    /* Once work has actually waited in the queue, pace its release even if
       a long-running measurement still occupies a slot. A fresh event may
       immediately fill a genuinely free slot (launch_or_queue), but queued
       backlog must not drain in a burst as workers finish: see
       SCHED_START_GAP_MS. */
    int start_gap = s->measure_start_seen &&
                    now_ms - s->last_measure_start_ms < SCHED_START_GAP_MS;
    if (active >= s->meas_limit) return 0;
    task *t = queued_pick(s);
    if (!t || (start_gap && !force_name(s,t->name))) return 0;
    s->last_measure_start_ms = now_ms;
    s->measure_start_seen = 1;
    long long waited_s = (long long)((now_ms - t->queued_ms + 500) / 1000);
    if (t->hot_count) {
        say(s, "по %s ожидание в очереди замеров: %lld с; цель снова подозревалась "
               "(%u раз) — запускаю поиск раньше тихих", t->name, waited_s, t->hot_count);
    } else {
        say(s, "по %s ожидание в очереди замеров: %lld с; запускаю поиск",
            t->name, waited_s);
    }
    (void)launch_task(s, t);
    measure_started(s);
    return 1;
}

static void plain_trial_finish(d2k_sched *s,task *t,doh_target *d,const char *reason) {
    join_worker(t);
    trial_retire(s,t);
    ver_close(t);
    t->res_ready=0;
    t->state=T_WATCHING;
    d->recovery=0;
    d->next_ms=s->now_ms+5000;
    say(s,"по %s проба DNS/%s: %s",t->name,t->dns_plain==17?"UDP":"TCP",reason);
}

static int plain_trial_install(d2k_sched *s,task *t) {
    uint8_t ip[16]={0};
    size_t address_size=t->family==6 ? 16 : 4;
    size_t wire_size=t->plain_request.length+(t->dns_plain==6 ? 2 : 0);
    if (t->ver.fd<0 || !t->ver.local_port || t->ver.family!=t->family ||
        t->ver.level!=D2K_VER_TRANSPORT || t->ver.dns_query_bytes ||
        t->plain_request.transport!=t->dns_plain || wire_size!=t->plain_trial_bytes ||
        wire_size>D2K_DNS_PROBE_WIRE_MAX || wire_size<17 ||
        memcmp(t->ver.local_addr,t->addr_probe_src_ip,address_size) ||
        inet_pton(t->family==6 ? AF_INET6 : AF_INET,t->ip,ip)!=1)return -1;
    char plan[192],hex[512],err[160];
    if (t->dns_plain==6)
        snprintf(plan,sizeof plan,"d2k-plan 1 1\nid 00000000000000000000000000000000\nproto tcp tls\nsplit payload_start +%zu\norder forward\n",wire_size/2);
    else
        snprintf(plan,sizeof plan,"d2k-plan 1 7\nid 00000000000000000000000000000000\nproto udp quic\nipfrag 1\n");
    snprintf(t->plans[0],sizeof t->plans[0],"%s",plan);
    if (fresh_trial_id(t->ver_plan_id) || fresh_trial_id(t->addr_probe_trial_id) ||
        stamp_plan_id(plan,t->ver_plan_id) || d2k_plan_text_to_hex(plan,hex,sizeof hex,err,sizeof err) ||
        d2k_link_set_dns_probe(s->link_fd,t->ver.local_addr,htons(t->ver.local_port),ip,htons(t->port),
            t->dns_plain,t->family,t->addr_probe_trial_id,2*SCHED_VERIFY_STEP_MS,hex,
            (uint16_t)wire_size,t->plain_request.wire_digest,err,sizeof err))return -1;
    memcpy(t->addr_probe_dst_ip,ip,sizeof ip);
    t->addr_probe_src_port_be=htons(t->ver.local_port);
    t->addr_probe_dst_port_be=htons(t->port);
    t->ver_flow=(d2k_flowkey){.family=t->family,.transport=t->dns_plain,
        .a_port=t->ver.local_port,.b_port=t->port};
    memcpy(t->ver_flow.a_ip,t->ver.local_addr,address_size);
    memcpy(t->ver_flow.b_ip,ip,address_size);
    t->addr_probe_identity_valid=t->trial_installed=1;
    t->trial_until_ms=s->now_ms+SCHED_VERIFY_STEP_MS;
    t->ver_dropped0=s->dropped_seen;
    if (t->dns_plain==6)
        say(s,"по %s: проба DNS/TCP делит запрос из %zu байт на границе %zu после двух таймаутов",
            t->name,wire_size,wire_size/2);
    else
        say(s,"по %s: проба DNS/UDP меняет разбиение датаграммы из %zu байт после двух таймаутов",
            t->name,wire_size);
    return 0;
}

static int plain_trial_record(d2k_sched *s,const task *t) {
    if (!s->cat)return -1;
    const char *box_id="plain-dns";
    char plan_id[40];uint8_t wire_id[D2K_PLAN_ID_LEN];
    plan_ident(t->plans[0],plan_id,sizeof plan_id,wire_id);
    if (bind_confirmed(s->cat,box_id,plan_id,t->plans[0],"dns",t->ip,"service",
        t->dns_plain,t->family,D2K_CAT_SHAPE_DNS,t->port,D2K_VERBY_PROBE,D2K_INPUT_PROFILE,
        wall_s(s,s->now_ms),NULL,NULL,NULL))return -1;
    d2k_cat_box *box=box_ensure(s->cat,box_id);
    for (size_t i=0;i<box->n_binds;i++) {
        d2k_cat_binding *b=&box->binds[i];
        if (b->shape!=D2K_CAT_SHAPE_DNS || b->family!=t->family || b->transport!=t->dns_plain ||
            b->server_port!=t->port || strcmp(b->target,t->ip))continue;
        b->budget=D2K_CAT_BUDGET_PASSED;
        b->dns_port=t->port;
        b->dns_query_bytes=t->plain_trial_bytes;
        snprintf(b->dns_name,sizeof b->dns_name,"%s",t->name);
        snprintf(b->dns_address,sizeof b->dns_address,"%s",t->ip);
        s->plain_dns_revision=s->cat->revision;
        return 0;
    }
    return -1;
}

static void plain_trial_tick(d2k_sched *s,task *t) {
    doh_target *d=dns_target_of(s,t);
    if (!d || t->stop) {task_done(s,t);return;}
    if (s->now_ms>=t->trial_until_ms || t->exec_nak ||
        (t->trial_installed && s->dropped_seen!=t->ver_dropped0)) {
        plain_trial_finish(s,t,d,"срок истёк, датапат отказал или квитанция потеряна");
        return;
    }
    if (t->trial_installed && t->job==JOB_DNS_PLAIN_PREPARE) {
        if (!t->trial_acked)return;
        if (start_worker(s,t,JOB_DNS_PLAIN_RUN))
            plain_trial_finish(s,t,d,"не удалось запустить обмен");
        else t->trial_until_ms=s->now_ms+SCHED_VERIFY_STEP_MS;
        return;
    }
    pthread_mutex_lock(&s->mu);int ready=t->res_ready;pthread_mutex_unlock(&s->mu);
    if (!ready)return;
    finish_worker(t,0);
    if (t->job==JOB_DNS_PLAIN_PREPARE) {
        if (plain_trial_install(s,t))plain_trial_finish(s,t,d,"подготовить изолированный поток не удалось");
        return;
    }
    if (t->dns_plain==17 && t->ver.budget_requests!=2) {
        plain_trial_finish(s,t,d,"контрольный обмен завершился без испытания кандидата");
        return;
    }
    if (t->ver.level!=D2K_VER_APPLICATION || !t->ver.body_complete || t->ver.doh_replies!=1 ||
        t->ver.budget!=D2K_BUDGET_PASSED || t->ver.dns_query_bytes!=t->plain_trial_bytes) {
        plain_trial_finish(s,t,d,"прикладной ответ не подтверждён");
        return;
    }
    if (t->ver_ok) {
        const char *reason=plain_trial_record(s,t) ? "исполнение и ответ получены, запись результата не удалась" :
            "исполнение и точный DNS-ответ получены на одном потоке";
        plain_trial_finish(s,t,d,reason);
    }
}

static int doh_health_complete(d2k_sched *s,task *t) {
    pthread_mutex_lock(&s->mu);int ready=t->res_ready;pthread_mutex_unlock(&s->mu);
    if(!ready)return 0;
    finish_worker(t, 0);
    if(t->stop || !dns_task_registered(s,t)) {
        ver_close(t);t->res_ready=0;task_done(s,t);return 1;
    }
    if (t->dns_plain) {
        enum { PLAIN_OK = 1, PLAIN_REJECTED, PLAIN_LOCAL, PLAIN_UNOBSERVED,
               PLAIN_TIMEOUT, PLAIN_REPEAT_TIMEOUT };
        doh_target *d=dns_target_of(s,t);
        int ok=t->ver.level==D2K_VER_APPLICATION && t->ver.body_complete &&
            t->ver.doh_replies==1 && t->ver.budget==D2K_BUDGET_PASSED;
        int local=t->ver.local_refusal || t->ver.local_limit || t->ver.unsupported;
        int rejected=t->ver.dns_reply_rejected;
        int submitted_timeout=!local && !rejected && t->ver.dns_query_bytes &&
            t->ver.budget==D2K_BUDGET_CUT;
        unsigned outcome=ok ? PLAIN_OK : rejected ? PLAIN_REJECTED : local ? PLAIN_LOCAL :
            submitted_timeout ? PLAIN_TIMEOUT : PLAIN_UNOBSERVED;
        if (d) {
            uint16_t previous=t->plain_first_timeout_bytes;
            int recheck=outcome==PLAIN_TIMEOUT && !previous &&
                d->plain_outcome!=PLAIN_REPEAT_TIMEOUT;
            int repeated=outcome==PLAIN_TIMEOUT && previous==t->ver.dns_query_bytes &&
                !memcmp(t->addr_probe_src_ip,t->ver.local_addr,sizeof t->addr_probe_src_ip);
            if (recheck)memcpy(t->addr_probe_src_ip,t->ver.local_addr,sizeof t->addr_probe_src_ip);
            t->plain_first_timeout_bytes=recheck ? t->ver.dns_query_bytes : 0;
            if (repeated || (outcome==PLAIN_TIMEOUT && d->plain_outcome==PLAIN_REPEAT_TIMEOUT))
                outcome=PLAIN_REPEAT_TIMEOUT;
            if (d->plain_outcome!=outcome) {
                if (repeated)
                    say(s,"по %s: таймаут повторился после отправки того же DNS-вопроса (%u байт, %s)",
                        t->name,(unsigned)t->ver.dns_query_bytes,t->dns_plain==17?"UDP":"TCP");
                else if (submitted_timeout)
                    say(s,"по %s: таймаут после отправки DNS-запроса (%u байт, %s)",
                        t->name,(unsigned)t->ver.dns_query_bytes,t->dns_plain==17?"UDP":"TCP");
                else
                    say(s,"по %s проверка DNS по фактическому пути роутера: %s",t->name,t->ver.reason);
            }
            d->plain_outcome=(uint8_t)outcome;
            d->next_ms=recheck ? s->now_ms : s->now_ms+5000;
            plain_endpoint *installed=plain_dns_slot(s,d);
            if (repeated && installed && installed->active && !installed->routed)repeated=0;
            if (repeated && installed && installed->active &&
                t->ver.dns_query_bytes==installed->wire_length) {
                d2k_cat_binding *bd=plain_dns_binding(s,d,NULL);
                if (plain_dns_same_plan(installed,bd)) {
                    int64_t at=wall_s(s,s->now_ms);
                    bd->recheck_since=at>0?at:1;
                    bd->recheck_mono_ms=s->now_ms;
                    s->cat->revision++;
                    s->plain_dns_revision=s->cat->revision;
                    d->plain_outcome=0;
                    d->next_ms=s->now_ms;
                    plain_dns_reconcile(s);
                    say(s,"по %s подтверждённая стратегия DNS снята после повторного таймаута",t->name);
                    ver_close(t);t->res_ready=0;t->state=T_WATCHING;
                    return 1;
                }
            }
            if (repeated && t->ver.family==t->family && s->plain_prepare && s->plain_run && s->mark &&
                !dns_recovery_active(s) && !t->addr_probe_identity_valid) {
                t->plain_trial_bytes=t->ver.dns_query_bytes;
                ver_close(t);
                t->trial_acked=t->ver_ok=t->exec_nak=0;
                t->trial_until_ms=s->now_ms+SCHED_VERIFY_STEP_MS;
                t->state=T_DNS_PLAIN_TRIAL;
                if (!start_worker(s,t,JOB_DNS_PLAIN_PREPARE)) {
                    d->recovery=1;
                    return 1;
                }
            }
        }
        ver_close(t);t->res_ready=0;t->state=T_WATCHING;
        return 1;
    }
    const char *protocol=t->dns_dot ? "DoT" : "DoH";
    int local=dns_non_path_failure(&t->ver);
    int ok=!local && dns_application_proved(&t->ver);
    char why[200];snprintf(why,sizeof why,"%s",t->ver.reason);
    ver_close(t);t->res_ready=0;
    doh_target *d=dns_target_of(s,t);if(d)d->next_ms=s->now_ms+5000;
    if(d && !d->dot && t->ver.peer_authenticated && t->ver.doh_http_version)
        t->dns_expected_http=d->http_version=t->ver.doh_http_version;
    int path_failure=!local && (t->ver.budget==D2K_BUDGET_CUT || t->ver.status==0 ||
        (t->ver.status==200 && !t->ver.body_complete));
    if(ok||local||!path_failure){
        if(t->ver.peer_auth_failed)
            say(s,"по %s периодическая проверка %s: %s",t->name,protocol,why);
        if(d && (ok || t->ver.peer_auth_failed || (!local && !path_failure)))d->recovery=0;
        if(ok && d && !d->health_ok) {
            d->health_ok=1;
            say(s,"по %s периодическая проверка %s по фактическому пути роутера прошла; интервал 5 с: %s",t->name,protocol,why);
        }
        t->state=T_WATCHING;return 1;
    }

    if(d) {
        d->health_ok=0;
        d->recovery=1;
    }
    /* The authenticated health handshake answers which DNS TLS form was
       actually in use, even if the application exchange later timed out. */
    if(t->ver.peer_authenticated && t->ver.negotiated_tls)
        t->trigger_shape=t->ver.negotiated_tls==0x0303 ? D2K_SHAPE_LEGACY : D2K_SHAPE_MODERN;
    uint8_t shape=t->trigger_shape;
    uint8_t http=t->dns_expected_http;uint16_t qtype=t->dns_qtype;
    char question[256];snprintf(question,sizeof question,"%s",t->dns_question);
    char name[256],ip[INET6_ADDRSTRLEN],doh_resource[sizeof t->doh_path];uint16_t port=t->port;uint8_t family=t->family;int dot=t->dns_dot;
    snprintf(doh_resource,sizeof doh_resource,"%s",t->doh_path);
    snprintf(name,sizeof name,"%s",t->name);snprintf(ip,sizeof ip,"%s",t->ip);
    say(s,"по %s проверка %s по фактическому пути роутера не прошла (%s) — сразу повторяю замер",name,protocol,why);
    if(force_name(s,t->name)) { force_retry(s,t);return 1; }
    task_reset(s,t);snprintf(t->name,sizeof t->name,"%s",name);snprintf(t->ip,sizeof t->ip,"%s",ip);
    t->transport=6;t->port=port;t->family=family;t->dns_dot=dot;
    t->trigger_shape=shape;t->dns_expected_http=http;t->fp.method=D2K_FP_METHOD;
    t->dns_qtype=qtype;snprintf(t->dns_question,sizeof t->dns_question,"%s",question);
    snprintf(t->doh_path,sizeof t->doh_path,"%s",doh_resource);
    snprintf(t->measure_path,sizeof t->measure_path,"%s",doh_resource);
    (void)launch_or_queue(s,t);return 1;
}

static int doh_health_target(d2k_sched *s,doh_target *d) {
        if(s->sync_active || s->sync_pending || !d->ip[0])return 0;
        uint8_t family=strchr(d->ip,':') ? 6 : 4;
        uint8_t transport=d->plain ? d->plain : 6;
        if(d2k_newchain_protects(&s->newchain,d->host,transport,family,0))return 1;
        if (s->now_ms<d->next_ms) return 0;
        task *t=dns_task_of(s,d);
        if(t && t->state==T_WATCHING) {
            if(!t->th_live) {
                t->state=T_DOH_HEALTH;
                d->next_ms=s->now_ms+5000;
                if(start_worker(s,t,JOB_DOH_HEALTH)){t->state=T_WATCHING;return 0;}
            }
            return 1;
        }
        if(t && t->state!=T_RESTING)return 1;

        if(!t)t=task_free_slot(s);

        if (!t) return 0;
        task_reset(s,t);
        snprintf(t->name,sizeof t->name,"%s",d->host);
        snprintf(t->ip,sizeof t->ip,"%s",d->ip);
        t->transport=transport; t->family=family; t->port=d->port;
        t->fp.method=D2K_FP_METHOD;
        d->next_ms=s->now_ms+5000;
        dns_configure_task(t,d);
        t->state=T_WATCHING;
        t->state=T_DOH_HEALTH;
        if(start_worker(s,t,JOB_DOH_HEALTH)){t->state=T_WATCHING;return 0;}
        return 1;
}
static void __attribute__((unused)) doh_health_tick(d2k_sched *s) {
    for (size_t i=0; i<s->n_doh; i++) (void)doh_health_target(s,&s->doh[i]);
}
static int dns_journal_solved(d2k_sched *s,const char *base) {
    if(!s->cat)return 0;
    for(size_t i=0;i<s->cat->n_boxes;i++)
        for(size_t j=0;j<s->cat->boxes[i].n_binds;j++) {
            const d2k_cat_binding *b=&s->cat->boxes[i].binds[j];char own[256];
            if(strcmp(b->kind,"service") || b->level<3 || !b->confirmed ||
               b->budget!=D2K_CAT_BUDGET_PASSED ||
               (!b->dns_authenticated && b->shape!=D2K_CAT_SHAPE_DNS) ||
               d2k_domain_base(b->dns_name,own) || strcmp(own,base))continue;
            return 1; /* Durable catalog proof; even a later disabled binding stays solved. */
        }
    return 0;
}
int d2k_sched_dns_journal_error(d2k_sched *s,const char *domain) {
    char base[256];
    if(!s || d2k_domain_base(domain,base) || dns_journal_solved(s,base))return 0;
    int matched=0;
    for(size_t i=0;i<s->n_doh;i++) {
        doh_target *d=&s->doh[i];char own[256];
        if(d2k_domain_base(d->host,own) || strcmp(own,base))continue;
        d->journal_pending=1;d->next_ms=0;matched++;
    }
    return matched;
}
static void dns_journal_pending_tick(d2k_sched *s) {
    for(size_t i=0;i<s->n_doh;i++) {
        doh_target *d=&s->doh[i];char base[256];
        if(!d->journal_pending)continue;
        if(!d2k_domain_base(d->host,base) && dns_journal_solved(s,base)) {
            d->journal_pending=0;continue;
        }
        if(doh_health_target(s,d))d->journal_pending=0;
    }
}

static int synthesis_resume(d2k_sched *s,task *t)
{
    if(!t->synthesis_resume_pending || t->th_live || !t->synthesis_context)return 0;
    if(t->synthesis_resume_pending<0) {
        say(s,"по %s результат приложения не удалось сохранить для синтеза",t->name);
        /* Keep failed work in the same plan-news queue as other exhausted
           searches. T_RESTING alone is not visited by plan_news_tick. */
        cooldown_record(s,t,2);
        task_fail(s,t,s->now_ms);return 1;
    }
    trial_retire(s,t);ver_close(t);
    t->synthesis_resume_pending=0;
    t->n_plans=t->n_known=t->next_plan=0;
    t->skip_volume_once=1;t->seed_use=0;t->state=T_ASKING;
    if(start_worker(s,t,JOB_CLASSIFY)!=0) {
        t->state=T_PLANNING;t->synthesis_resume_pending=1;
    }
    return 1;
}

int d2k_sched_tick(d2k_sched *s, int64_t now_ms) {
    if (!s) { return 0; }
    /* Привязка монотонных часов к стенным делается ПО ПЕРВОМУ ТИКУ, а не при
       заведении планировщика, и не своим вызовом clock_gettime. Причина: часы
       сюда приносит ВЫЗЫВАЮЩИЙ, и какие они — его дело. d2kc даёт
       CLOCK_MONOTONIC (на Linux отсчитывается от ЗАГРУЗКИ), тест — модельные
       от нуля. Сними отсчёт сам — и в тесте разность окажется отрицательной на
       весь уптайм машины, а в проде уптайм посчитался бы дважды. Привязываемся
       к тому, что реально приходит. */
    if (!s->clock_seen) {
        s->clock_seen = 1;
        s->mono_base_ms = now_ms;
        s->wall_base_s = (int64_t)time(NULL);
        for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
            task *t = &s->tasks[i];
            if (t->report_id && !t->report_closed && t->report_admitted_ms < 0)
                t->report_admitted_ms = now_ms;
        }
        /* Events may beat the first timer tick. Their local zero timestamp
           is provisional; rebase admission pacing when the clock becomes
           meaningful so uptime/model-clock differences cannot release the
           initial queue immediately. */
        if (s->measure_start_seen) { s->last_measure_start_ms = now_ms; }
    }
    s->now_ms = now_ms;
    (void)d2k_newchain_poll(&s->newchain,s->link_fd,now_ms,newchain_log,s);
    /* Retire already running old workers before consuming their results.
       Their cleanup owns only temporary trials, never the imported binding. */
    for(size_t i=0;i<SCHED_MAX_TASKS;i++)if(s->tasks[i].state!=T_FREE && newchain_task(s,&s->tasks[i])) {
        s->tasks[i].stop=1;task_done(s,&s->tasks[i]);
    }
    if(s->synthesis_only)return 0;
    /* Retry exact cleanup separately from measurement tasks. A lost ACK or
       scheduler replacement must not release a still-targeted source port.
       One-second pacing limits control retries, not network measurement. */
    if (d2k_stun_trial_pending() && (!s->stun_cleanup_seen ||
        now_ms < s->stun_cleanup_ms || now_ms - s->stun_cleanup_ms >= 1000)) {
        (void)d2k_stun_trial_retry_pending(s->link_fd);
        s->stun_cleanup_seen = 1;
        s->stun_cleanup_ms = now_ms;
    }
    measure_limit_update(s, res_sample(s, now_ms));
    force_tick(s);
    plain_dns_reconcile(s);
    dns_journal_pending_tick(s);

    /* Осушить самопайп: он только будит, содержимое значения не имеет. */
    uint8_t drain[64];
    while (read(s->wake[0], drain, sizeof drain) > 0) { }

    /* A worker may already be waiting when this tick crosses its lifetime.
       Acknowledge that pause before applying any network/task deadline. */
    quic_yield_tick(s,now_ms);
    quic_deny_tick(s, now_ms);
    flowwatch_tick(s, now_ms);
    plan_news_tick(s, now_ms);
    /* Отказы узлов семейства стареют: узел, который неделю никто не встречал,
       ничего не говорит о плане (поле 06.10, googlevideo). Раз в час и сразу
       после запуска; при несинхронных часах d2k_group_expire не трогает ничего. */
    if (s->cat && s->cat->groups &&
        (!s->groups_expired_ms || now_ms - s->groups_expired_ms >= SCHED_GROUP_EXPIRE_EVERY_MS)) {
        s->groups_expired_ms = now_ms ? now_ms : 1;
        int dropped = d2k_group_expire(s->cat->groups, wall_s(s, now_ms), SCHED_GROUP_FAIL_MAX_AGE_S);
        if (dropped > 0) {
            s->cat->revision++; s->sync_pending = 1;
            say(s, "семейства: убраны отказы узлов старше 7 суток (%d)", dropped);
        }
    }
    if (s->sync_pending && !s->sync_active) {
        (void)d2k_sched_sync(s);
    }

    int moved = 0;
    for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
        task *t = &s->tasks[i];
        if (t->state == T_FREE) { continue; }

        if(t->state==T_GATE_INSTALL || t->state==T_GATE_VERIFY || t->state==T_GATE_COMMIT) {
            gate_tick(s,t,now_ms);moved++;continue;
        }
        if (t->state == T_SHAPE_WAIT && t->shape_request_until_ms &&
            (!t->shape_request_pending || now_ms >= t->shape_request_until_ms)) {
            say(s, "по %s снимок до замера не получен (%s) — использую профильный вход",
                t->name, t->shape_request_pending ? "нет подтверждения запроса" : "запрос обработан");
            t->shape_request_pending = 0;
            t->shape_request_until_ms = 0;
            (void)launch_or_queue(s, t);
            moved++;
            continue;
        }

        if (t->state == T_QUEUED) {
            if (t->queued_ms == 0) { t->queued_ms = now_ms; }
            if (!encrypted_dns_task(t) && queued_family_ready(s,t)) {
                say(s,"по %s прежнюю очередь снимаю: новое семейство уже установлено; "
                      "следующий поток наследует обход без отдельного замера",t->name);
                task_done(s, t); moved++; continue;
            }
            /* Срок — ДО приоритета восстановления семейства (задача 24):
               приоритет решает, кому достанется слот, а не продлевает жизнь
               чужому подозрению. Прежде устаревшее ждало, пока восстановление
               получит слот, и висело в очереди сверх SCHED_TASK_LIFE_MS. */
            if (now_ms - t->queued_ms > SCHED_TASK_LIFE_MS) {
                say(s, "по %s подозрение устарело в очереди — сетевой замер не запускал",
                    t->name);
                task_done(s, t);
                moved++;
                continue;
            }
            /* Выпуск — после прохода (queued_release): кому достанется
               слот, решает порядок очереди, а не номер ячейки. */
            continue;
        }

        if(t->state==T_DOH_HEALTH){moved+=doh_health_complete(s,t);continue;}
        if(t->state==T_DNS_PLAIN_TRIAL){plain_trial_tick(s,t);continue;}
        if (t->state == T_RESTING) {
            if (!force_name(s,t->name) && now_ms >= t->rest_until_ms) { task_done(s, t); moved++; }
            continue;
        }
        if (t->started_ms == 0) { t->started_ms = now_ms; }
        /* Ход классификации (этап 23): отметка по модельным часам, когда счёт
           зондов или вопрос измерителя менялись в последний раз. */
        int progressing = 0;
        int measurement_ready = 0;
        if (t->state == T_ASKING && t->th_live) {
            pthread_mutex_lock(&s->mu);
            int ap = t->ask_probes;
            uint32_t qh = (uint32_t)fnv1a(t->ask_question);
            measurement_ready = t->res_ready;
            pthread_mutex_unlock(&s->mu);
            if (t->progress_ms == 0) { t->progress_ms = t->started_ms; }
            if (ap != t->last_ask_probes || qh != t->last_ask_qhash) {
                t->last_ask_probes = ap; t->last_ask_qhash = qh; t->progress_ms = now_ms;
            }
            progressing = now_ms - t->progress_ms <= SCHED_ASK_STALL_MS;
        }
        if (!t->quic_parked && now_ms - t->started_ms > SCHED_TASK_LIFE_MS && progressing &&
            !t->long_told) {
            pthread_mutex_lock(&s->mu);
            char q[96]; snprintf(q, sizeof q, "%s", t->ask_question);
            int ap = t->ask_probes;
            pthread_mutex_unlock(&s->mu);
            t->long_told = 1;
            say(s, "по %s замер идёт дольше %d мин, но продолжается (вопрос «%s», зондов %d) — "
                   "не прерываю: срок задачи не мера измерения, бросается только замер без хода",
                t->name, SCHED_TASK_LIFE_MS / 60000, q, ap);
        }
        if (!t->quic_parked && now_ms - t->started_ms > SCHED_TASK_LIFE_MS &&
            !progressing && !measurement_ready) {
            if (t->state == T_SHAPE_WAIT) {
                /* Формы так и не дождались: человек ушёл со страницы, и
                   повторять приветствие некому. Это НЕ неудача плана —
                   планов не было вовсе; освобождаем место молча по сути, но
                   вслух по журналу. */
                say(s, "по %s (QUIC) формы приветствия так и не пришло — мерить нечем",
                    t->name);
                task_done(s, t);
            } else if (t->state == T_WATCHING) {
                /* Наблюдение за живым трафиком кончилось ничем — и это НЕ
                   неудача: план уже подтверждён зондом и записан, снимать его
                   (task_fail) не за что. Просто освобождаем место. */
                task_done(s, t);
            } else if (t->own_first == 2) {
                /* СРОК ФАЗЫ СВОИХ ПЛАНОВ (финальное ревью core, I2). Фаза
                   своих планов идёт на сроке запуска; упёршись в него, она
                   кончается так же, как по бюджету: дальше полный замер
                   донора со своим целым сроком (own_first_continue). Провал
                   в отдых здесь означал бы, что следующая задача начнёт с
                   пустым own_seen и проиграет те же свои планы снова, а
                   полный замер не начнётся никогда. */
                join_worker(t);
                for (size_t k = 0; k < t->n_plans && k < 32; k++) {
                    if (!(t->own_probed & (1u << k))) continue;
                    tried_add(t, (uint32_t)fnv1a(t->plans[k]));
                    own_tried_add(t, (uint32_t)fnv1a(t->plans[k]));
                }
                t->own_probed = 0;
                size_t left = (t->next_plan < t->n_plans ? t->n_plans - t->next_plan : 0) +
                              own_first_plans(s, t, 2);
                say(s, "по %s срок фазы своих планов (%d мин) истёк: свои подтверждённые "
                       "планы испытаны не все, НЕ испытано %zu — продолжаю полный замер донора",
                    t->name, SCHED_TASK_LIFE_MS / 60000, left);
                own_first_continue(s, t);
            } else if ((t->state == T_VOICE_TRIAL || t->state == T_VOICE_WATCH) &&
                       voice_trial_owned(t)) {
                /* Следующего разговора с доказательством за срок не было —
                   опыт НЕ ПРОВЕРЕН, а не провален: кандидата никто не судил.
                   Снимаем только свой опыт (поток + trial ID). */
                say(s, "по %s (голос) не проверено: за %d мин опыт не дождался "
                       "разговора с протокольным ответом — снимаю опыт, "
                       "кандидат не судим", t->name, SCHED_TASK_LIFE_MS / 60000);
                /* Общий запрет поиска (cooldown вида 2) здесь не ставится:
                   он глушил бы любое подозрение голоса на 10 мин, хотя
                   кандидата никто не судил (финальное ревью, п.1). Новый
                   замер возможен только по новому подозрению из датапата. */
                trial_retire(s, t);
                task_done(s, t);
            } else {
                /* СРОК ЗАДАЧИ ИСТЁК — И ЕСЛИ ЗАМЕР ЕЩЁ ШЁЛ, ЭТО НАДО СКАЗАТЬ.
                   Иначе в журнале остаётся «поисков идёт 1» и тишина, а
                   выглядит это как зависание службы, а не как упёршийся в
                   потолок поиск. Сам замер бросается просьбой (join_worker),
                   и его вердикт никуда не идёт: дерево пройдено не до конца. */
                if (t->state == T_ASKING) {
                    /* Этап 23: не «не уложился», а «нет хода»: состояние —
                       незавершённое (interrupted), с последним вопросом и
                       числом зондов; отрицательным результатом это не является. */
                    char q[96]; int ap;
                    pthread_mutex_lock(&s->mu);
                    snprintf(q, sizeof q, "%s", t->ask_question);
                    ap = t->ask_probes;
                    snprintf(t->res.reason, sizeof t->res.reason,
                             "прерван: нет хода %lld с после вопроса «%s», зондов %d",
                             (long long)((now_ms - t->progress_ms) / 1000), q, ap);
                    pthread_mutex_unlock(&s->mu);
                    say(s, "по %s замер прерван: хода нет %lld с (последний вопрос «%s», зондов %d) — "
                           "результат НЕ измерен, в каталог не идёт ничего",
                        t->name, (long long)((now_ms - t->progress_ms) / 1000), q, ap);
                    search_report(s, t, now_ms, "interrupted", NULL, t->res.reason);
                    /* Этап 25: что успели измерить до прерывания — в журнал. */
                    join_worker(t);
                    {
                        d2k_vres rr; int rd;
                        pthread_mutex_lock(&s->mu);
                        rd = t->res_ready; rr = t->res;
                        pthread_mutex_unlock(&s->mu);
                        if (rd) { say_question_trace(s, t, &rr); }
                    }
                } else if (t->state == T_VOICE_MEASURE) {
                    say(s, "по %s голосовой замер не уложился в %d мин — "
                           "результат не применяется",
                        t->name, SCHED_TASK_LIFE_MS / 60000);
                }
                if (t->search_started || t->probes > 0) {
                    cooldown_record(s, t, 2);
                    say(s, "по %s после незавершённой попытки новый поиск временно отложен на 10 мин",
                        t->name);
                }
                task_fail(s, t, now_ms);
            }
            moved++;
            continue;
        }

        if (t->state == T_VOICE_INSTALL) {
            if(t->voice_install_refused || (!t->voice_install_acked && now_ms>=t->stun_until_ms)) {
                search_report(s,t,now_ms,"local-error",NULL,"установка постоянного UDP-плана не подтверждена");
                task_done(s,t);
            } else if(t->voice_install_acked)voice_confirm(s,t,now_ms);
            moved++;
            continue;
        }
        if (t->state == T_STUN_CLIENT) {
            if(t->stun_refused) {
                stun_candidate_done(s,t,now_ms,0,"исходный STUN-опыт отвергнут; решение не подтверждено");
            } else if(t->trial_acked && t->stun_client_done_id &&
                      t->stun_client_done_id==t->stun_client_reply_id &&
                      d2k_binding_equal(&t->stun_binding,&t->voice_execution_binding)) {
                t->voice_proof_code=D2K_UDP_PROOF_STUN;
                voice_confirm(s,t,now_ms);
            } else if(now_ms>=t->stun_until_ms) {
                stun_candidate_done(s,t,now_ms,0,"исходный STUN-обмен не подтверждён за срок временного опыта");
            }
            moved++;
            continue;
        }
        if (t->state == T_STUN_ACK || t->state == T_STUN_PROBE || t->state == T_STUN_PROOF) {
            stun_candidate_tick(s, t, now_ms);
            moved++;
            continue;
        }

        if (t->state == T_STUN_MEASURE) {
            pthread_mutex_lock(&s->mu);
            int ready = t->res_ready;
            pthread_mutex_unlock(&s->mu);
            if (!ready) { continue; }
            stun_finish(s, t, now_ms);
            moved++;
            continue;
        }

        if (t->state == T_VOICE_MEASURE) {
            int ready;
            pthread_mutex_lock(&s->mu);
            ready = t->res_ready;
            pthread_mutex_unlock(&s->mu);
            if (!ready) { continue; }
            voice_finish_measure(s, t, now_ms);
            moved++;
            continue;
        }

        if(raw_measure_state(t)) {
            if(t->state==T_RAW_MEASURED){raw_measured_try(s,t);moved++;continue;}
            int64_t span=(int64_t)t->raw_measure_request.seconds*1000;
            if(!t->raw_until_ms)t->raw_until_ms=now_ms+(t->state==T_RAW_MEASURE_ACK?60000:(span+(int64_t)D2K_RM_GRACE_S*1000)*(t->transport==6?2:1));
            if(t->state==T_RAW_MEASURE_OBSERVE && t->transport==6) {
                if(!t->raw_obs_lease_ms) {
                    t->raw_obs_lease_ms=now_ms+span;t->raw_obs_renew_ms=now_ms+span/2;
                }
                if(now_ms>=t->raw_obs_lease_ms) {
                    unknown_note(s,"addr",t->ip,t->transport,t->family,t->port,"measurement-unavailable","срок подтверждённой доставки истёк; продолжение замера неизвестно");
                    raw_measure_cancel(s,t);raw_measure_watch_done(s,t,-1);task_done(s,t);moved++;continue;
                }
                if(!t->raw_obs_renewing && now_ms>=t->raw_obs_renew_ms) {
                    char err[160];
                    struct d2k_rawmeasure_request renew=t->raw_measure_request;renew.renew=1;
                    if(d2k_link_raw_measure(s->link_fd,&renew,err,sizeof err)) {
                        unknown_note(s,"addr",t->ip,t->transport,t->family,t->port,"measurement-unavailable",err);
                        raw_measure_cancel(s,t);raw_measure_watch_done(s,t,-1);task_done(s,t);moved++;continue;
                    }
                    t->raw_obs_sent_ms=now_ms;t->raw_obs_renewing=1;
                }
            }
            if(now_ms>=t->raw_until_ms) {
                unknown_note(s,"addr",t->ip,t->transport,t->family,t->port,"measurement-timeout","подтверждение или результат наблюдения не получен; причина молчания неизвестна");
                raw_measure_cancel(s,t);raw_measure_watch_done(s,t,-1);task_done(s,t);moved++;
            }
            continue;
        }

        if (t->state == T_RAW_TRIAL || t->state == T_RAW_WATCH) {
            /* Сроки — от часов тика, не от момента события: у свежей задачи
               модельных часов ещё нет (clock_seen), и срок от нуля истёк бы
               первым же тиком. */
            if (t->raw_until_ms == 0) {
                int64_t window = t->raw_trial_window_ms ? t->raw_trial_window_ms : SCHED_RAW_TRIAL_MS;
                t->raw_until_ms = now_ms + (t->state == T_RAW_TRIAL ? window : SCHED_RAW_WATCH_MS);
                if (t->state == T_RAW_TRIAL && !t->raw_lease_until_ms) t->raw_lease_until_ms = now_ms + t->raw_lease_ms;
                continue;
            }
            /* Окно длиннее аренды датапата: продлить тот же опыт до конца
               окна; без подтверждённой аренды повтор клиента прошёл бы без
               плана, и «клиент не повторил» было бы неправдой. */
            if (t->state == T_RAW_TRIAL && t->raw_measure_request.generation && t->raw_lease_until_ms) {
                /* Expired coverage cannot be recreated after a scheduler pause.
                 * At the normal end of an acknowledged final lease, no-retry
                 * is valid; without its ACK even an equal window is unknown. */
                if (now_ms >= t->raw_lease_until_ms &&
                    (t->raw_renewing || !t->trial_acked || t->raw_until_ms > t->raw_lease_until_ms)) {
                    raw_trial_end_unknown(s, t, "candidate-lost",
                        t->raw_renewing ? "продление измеренного опыта не подтверждено датапатом до конца прежнего срока"
                                        : "установка измеренного опыта не подтверждена датапатом до конца срока");
                    moved++;
                    continue;
                }
                if (t->raw_until_ms > t->raw_lease_until_ms && t->trial_acked && !t->raw_renewing &&
                    t->raw_lease_until_ms - now_ms <= (int64_t)t->raw_lease_ms / 2) {
                    raw_trial_renew(s, t, now_ms);
                    if (t->state != T_RAW_TRIAL) { moved++; continue; }
                }
            }
            if (now_ms < t->raw_until_ms) { continue; }
            if(t->state==T_RAW_WATCH &&
               t->raw_measure_report.code==D2K_RM_REPEAT_SILENT) {
                /* The stored solution failed in this measured flow. Retire
                   only its exact trial, then construct from the already
                   measured packet geometry. An unapplied or locally refused
                   candidate is not evidence for this transition. */
                say(s,"по %s:%u %s %s не дало подтверждения; уточняю замер оставшихся данных перед построением",
                    t->ip,(unsigned)t->port,t->raw_own_candidate?"сохранённое решение":"измеренное решение",t->raw_plan_id);
                trial_retire(s,t);t->raw_skip_own=1;t->raw_own_candidate=0;
                raw_measure_again(s,t);moved++;continue;
            }
            raw_measure_watch_done(s,t,-1);
            if (t->state == T_RAW_TRIAL) {
                say(s, "по %s:%u (поток без протокола) опыта не было: клиент не повторил %s в окне — "
                       "снимаю пробную запись, исход неизвестен", t->ip, (unsigned)t->port,
                    t->transport == 17 ? "датаграмму" : "сегмент");
                trial_retire(s, t);
                search_report(s, t, now_ms, "raw-no-retry", NULL, "клиент не повторил запрос в окне опыта");
                unknown_note(s, "addr", t->ip, t->transport, t->family, t->port, "no-retry",
                             "опыт со своим решением адреса поставлен, но клиент не повторил запрос в окне");
                task_done(s, t);
            } else {
                say(s, "по %s:%u (поток без протокола) сервер не ответил на повтор клиента под планом %s — "
                       "план не помог; исход неизвестен, без перебора", t->ip, (unsigned)t->port, t->raw_plan_id);
                trial_retire(s, t);
                cooldown_record(s, t, 2);
                search_report(s, t, now_ms, "raw-silent", NULL, "ответ на повтор клиента под планом не получен");
                unknown_note(s, "addr", t->ip, t->transport, t->family, t->port, "plan-silent",
                             "сервер не ответил на повтор клиента под собственным решением адреса");
                task_done(s, t);
            }
            moved++;
            continue;
        }
        if (t->state == T_VOICE_WATCH) {
            if (t->voice_answered) {
                if (t->voice_proven) { voice_confirm(s, t, now_ms); }
                else { voice_observe(s, t); }
                moved++;
                continue;
            }
            if (t->voice_silent) {
                voice_fail(s, t, now_ms);
                moved++;
                continue;
            }
            /* Ни ответа, ни приговора датапата: поток кончился, не решив
               ничего (закрыли звонок раньше срока молчания). Ждём следующего
               разговора, а не выдумываем исход. */
            if (t->voice_watch_ms == 0) { t->voice_watch_ms = now_ms; }
            if (now_ms - t->voice_watch_ms > SCHED_VOICE_WATCH_MS) {
                say(s, "по %s (%s) поток с приёмом не решил ничего — жду следующего",
                    t->name, t->by_addr ? "QUIC по адресу" : "голос");
                t->state = T_VOICE_TRIAL;
            }
            continue;
        }
        if (t->state == T_VOICE_TRIAL) {
            /* Опыт ждёт следующего разговора дольше lease датапата —
               продлеваем тем же поколением, пока задача жива. */
            if (voice_trial_owned(t) &&
                now_ms - t->voice_lease_ms >= SCHED_VOICE_LEASE_RENEW_MS) {
                char err[160];
                if (voice_trial_send(s, t, now_ms, err, sizeof err) != 0) {
                    say(s, "по %s (голос) опыт не продлился: %s", t->name, err);
                    t->voice_lease_ms = now_ms;
                }
            }
            continue;
        }

        if (t->state == T_ASKING) {
            int ready;
            d2k_vres r;
            pthread_mutex_lock(&s->mu);
            ready = t->res_ready;
            r = t->res;
            pthread_mutex_unlock(&s->mu);
            if (!ready) { continue; }
            join_worker(t);
            /* A progressing measurement may legitimately exceed the task
               lifetime. Its completed result starts the next phase, whose
               verification must not inherit an already expired deadline.
               Keep the original start for elapsed-time reporting. */
            if (!t->began_ms) t->began_ms = t->started_ms;
            t->started_ms = now_ms;
            if(r.verdict==D2K_V_INCONCLUSIVE && r.gate_candidate.present &&
               preflight_family_enabled(t->family) && t->transport==6 && !t->ech_offer) {
                char candidate[sizeof t->plans[0]],err[160];
                if(d2k_compose_preflight_candidate(&r.gate_candidate,t->family,6,
                    candidate,sizeof candidate,err,sizeof err)==1) {
                    t->res=r;t->researched=1;t->own_first=0;t->owned_fallback=1;
                    t->n_plans=t->n_known=t->next_plan=0;
                    if(refill_from_fallback(s,t)) {
                        t->state=T_PLANNING;
                        say(s,"по %s повторён ответ в малом окне, прямой перенос не подтверждён: "
                            "явный резервный подбор; для известного адреса preflight действует и при проверке плана",t->name);
                        moved++;continue;
                    }
                }
            }
            if(r.verdict==D2K_V_RESPONSE_GATE || r.box_props.response_gate==D2K_PROP_YES) {
                t->res=r;
                char box[40];box_id_for(s,t,"response-gate",box,sizeof box);
                d2k_cat_box *b=s->cat?box_ensure(s->cat,box):NULL;
                if(b) {
                    if(!b->fp.n_sig)b->fp=t->fp;
                    (void)box_props_learn(s->cat,b,&r.box_props,t->trigger_shape,wall_s(s,now_ms));
                }
                if(r.verdict==D2K_V_RESPONSE_GATE && gate_start(s,t,&r.box_props,0)) {moved++;continue;}
                say(s,"по %s preflight: %s — без плана, перебора и штрафа цели",t->name,
                    !preflight_family_enabled(t->family)?"семейство preflight отключено":
                    r.box_props.gate_carry==D2K_PROP_NO?"не этот класс (gate_carry=NO)":"план не выводится");
                task_done(s,t);moved++;continue;
            }
            int vol_cut = t->transport == 6 &&
                (t->vol.rx_cut || t->vol.verdict == D2K_VOL_CUT);
            int direct_clear = (r.verdict == D2K_V_CLEAR && !vol_cut && !t->ech_trial && !t->doh_trial &&
                                !t->vol.rx_partial_bytes && !t->vol.rx_partial_wire_bytes);
            if (t->yield_to_own_plan) {
                t->yield_to_own_plan = 0;
                t->stop = 0;
                if (!direct_clear) {
                    size_t own = own_first_plans(s, t, 1);
                    if (own > 0) {
                        t->own_first = 2;
                        t->res = r;
                        keep_props_seed(s, t, &r); /* этап 25: измеренное не теряется */
                        if (t->transport == 6 && !t->vol.rx_cut) {
                            memset(&t->vol, 0, sizeof t->vol);
                        }
                        t->n_plans = t->n_known = own;
                        t->next_plan = 0;
                        t->cached_measure_valid = 0;
                        t->exec_refused = t->exec_probed = 0;
                        t->rx_phase = 0;
                        t->state = T_PLANNING;
                        say(s, "по %s замер уступил место собственным планам из каталога: %zu",
                            t->name, own);
                        moved++;
                        continue;
                    }
                }
            }
            if (t->addr_ack == 2) {
                /* Перепроверка мёртвого адреса: тишина без единого триггера —
                   вердикт подтверждён, ступень лестницы растёт. */
                t->addr_ack = 0;
                int64_t delay_ms = dead_step(s, t);
                say(s, "по %s адрес %s не принимает данных (%s) — средствами d2k это не "
                       "обходится; повторная проверка этого адреса через %lld мин",
                    t->name, t->ip, r.reason, (long long)((delay_ms + 59999) / 60000));
                task_fail(s, t, now_ms);
                moved++;
                continue;
            }
            if (t->addr_ack == 1 && t->transport == 6) { dead_clear(s, t); }
            if (t->ech_regrade) {
                /* GREASE (задача 49): тот же вход, теперь как обычное
                   приветствие — сперва свои подтверждённые планы той же
                   формы, если они есть; иначе полный поиск сразу. */
                t->ech_regrade = 0;
                /* Повтор байтов клиента — не семейный путь: тот меряет объём
                   обычным приветствием имени, а это другой вопрос. */
                if (t->ech_replay) t->family_reuse = 0;
                t->own_first = (d2k_sched_tcp_base_hook != NULL) && !t->family_reuse &&
                               own_first_plans(s, t, 0) > 0 ? 1 : 0;
                if (t->ech_replay)
                    say(s, "по %s настоящий ECH (внешнее имя — public_name конфигурации), своего "
                           "ECH-свидетеля нет — меряю байтами клиента: его ECH-приветствие (%zu байт) "
                           "повтором на %s; кандидата подтвердит ServerHello на тот же повтор "
                           "под планом", t->name, t->trig_len, t->ip);
                if (start_worker(s, t, JOB_CLASSIFY) != 0) { task_fail(s, t, now_ms); moved++; continue; }
                if (t->own_first == 1)
                    say(s, "по %s сначала базовый вопрос донора: если рукопожатие режется, "
                           "проверю свои подтверждённые планы до полного замера", t->name);
                moved++;
                continue;
            }
            /* Ответ базы годится одному полному прогону (задача 32). */
            int base_answer = t->own_first == 1;
            if (!base_answer) { t->seed_use = 0; t->seed.valid = 0; }
            if (t->trigger_planned == D2K_LINK_PLANNED_NO && installed_family_ready(s, t, 0, 0)) {
                say(s, "по %s снимок подтвердил совместимое установленное семейство; "
                       "отдельный поиск прекращаю без перебора", t->name);
                task_done(s, t); moved++; continue;
            }
            remember_resources(s, t->vol.resources, t->vol.n_resources);
            remember_measured_path(s, t);
            if (t->transport == 6 && !t->by_addr && t->vol.rx_direct_complete)
                note_clean_handshake(s, t->name, 6, t->family);
            /* ПРОГОН, ОСТАНОВЛЕННЫЙ РАДИ СНИМКА, — НЕ ВЕРДИКТ (задача 31).
               Поле 02.10.2026, i.ytimg.com: брошенный на первом зонде
               классификатор («о цели не сказано ничего») ушёл в разбор
               вердикта — «прямой замер не подтвердил блокировку» и покой на
               десять минут, — потому что общую ячейку снимка к его возврату
               заняло соседнее имя. Ни вердикта, ни покоя: повтор байтами,
               сохранёнными у задачи. */
            int snap_restart = t->transport == 6 && t->snap_stop && !t->reasked &&
                               t->snap_len > 0 && t->snap_len <= sizeof t->trig;
            /* Этап 25: прогон, остановленный ради снимка, успел измерить часть
               свойств — трасса печатается; в семя не идёт (вход меняется). */
            if (snap_restart) { say_question_trace(s, t, &r); }
            /* ДОКАЗАННЫЙ ОБРЫВ ОТВЕТА — ОТВЕТ, А НЕ ЧЕРНОВИК ПРОГОНА.
               Поле 12.10.2026, www.tampermonkey.net: парный замер сошёлся
               полностью («identity 15627/15627, gzip завершился»), и
               следующей же строкой прогон был аннулирован ради повтора
               байтами клиента (1543 против 1578). Повтор дал НЕпарный
               результат — одно измерение оборвалось, второе дошло целиком, —
               и вопрос закрылся ложным отрицанием с покоем на десять минут;
               так погибли три эпизода подряд, при эталоне с VPS 30182 байта
               против 15963 с роутера (8 раз из 8).
               Байтовый бюджет ОТВЕТА считается ПОСЛЕ успешного рукопожатия и
               от формы приветствия не зависит (см. «не семейный путь» выше):
               полученный обрыв забирается ДО повтора. Снимку остаётся то, что
               от байт клиента действительно зависит, — коробка и её планы. */
            if (t->rx_volume_only && (!snap_restart || t->vol.rx_cut)) {
                t->rx_volume_only = 0;
                /* Доказанный обрыв исходящей лестницы пустой или короткой
                   RX-пробой не отменяется (поле 17.10.2026, LR-rx8-1, rua.gr):
                   он сам открывает лестницу белого имени (vol_cut_measured). */
                if (!t->vol.rx_cut && t->vol.verdict == D2K_VOL_CUT) {
                    say(s, "по %s исходящая лестница оборвалась около %d КБ; "
                           "входящий замер ничего не измерил и этот обрыв не отменяет — "
                           "продолжаю поиск", t->name, t->vol.at_kb);
                } else if (!t->vol.rx_cut) {
                    if (t->vol.rx_tls_unavailable && rx_saved_bootstrap(s, t, 0)) {
                        moved++;
                        continue;
                    }
                    /* Neither late RST nor repeated FIN proves a block.
                       A complete short body leaves volume unmeasured; it
                       cannot authorize handshake synthesis or a plan queue. */
                    if (t->vol.rx_short)
                        say(s, "по %s короткий завершённый ответ не проверяет бюджет объёма; "
                               "подозрения позднего закрытия недостаточно для полного поиска", t->name);
                    else
                        say(s, "по %s позднее закрытие не подтвердилось парными измерениями ответа; "
                           "перебор не запускаю", t->name);
                    search_report(s, t, now_ms, "inconclusive", "none",
                                  "позднее закрытие не подтвердилось парными измерениями ответа");
                    /* Не блок: неубедительный замер, как у прямого вердикта
                       без доказательства. Без cooldown здоровый трафик с
                       поздними RST повторял пару каждые две минуты. */
                    cooldown_record(s, t, 3);
                    say(s, "по %s повторный замер позднего обрыва отложен на %lld мин",
                        t->name, (long long)(SCHED_INCOMPLETE_BACKOFF_MS / 60000));
                    task_fail(s, t, now_ms);
                    moved++;
                    continue;
                }
                if (t->vol.rx_cut && t->vol.rx_compressed_complete) {
                    say(s, "по %s подтверждён повторяемый обрыв входящего ответа около %d КБ "
                           "при полном gzip-контроле — теперь ищу коробку и её планы",
                        t->name, t->vol.rx_at_kb);
                } else if (t->vol.rx_cut) {
                    say(s, "по %s подтверждён пакетный бюджет потока: identity и gzip "
                           "оборвались около %d пакетов с данными — теперь ищу коробку и её планы",
                        t->name, t->vol.rx_cut_packets);
                }
            }
            /* QUIC snapshots can arrive while the original Run is in flight.
               Keep that Run's copied input immutable, then discard its result
               and repeat once with the exact target-owned client Initial. */
            const uint8_t *qb; size_t ql; uint64_t qseq;
            if (!t->reasked && !t->trig_snapped && quic_own_initial(s, t, &qb, &ql, &qseq)) {
                remeasure_snapped(s, t, qb, ql);
                moved++;
                continue;
            }
            /* СНИМОК ПРИШЁЛ ПОСЛЕ СТАРТА — ЗАМЕР СДЕЛАН НЕ ТЕМ ПРИВЕТСТВИЕМ.
               Первый поиск по цели идёт профилем холодного старта, а форму
               настоящего клиента датапат присылает отдельным событием, и
               приходит она на секунду позже. Если клиент старой формы, мерили
               мы современным приветствием — то есть другую реакцию коробки, —
               и подтверждение легло бы под форму, которой у клиента нет.
               Стенд с цензором на клиенте TLS 1.2: профиль 1544 байта против
               снимка в 235, привязка modern, у человека обхода нет.

               Повторяем ОДИН раз: снимок уже на руках, второго расхождения
               взяться неоткуда, а бесконечный перезапуск был бы хуже любого
               неверного вердикта. */
            /* ТА ЖЕ ФОРМА — ЕЩЁ НЕ ТЕ БАЙТЫ.
               Повтор заводился только при расхождении ФОРМЫ. Поле 18.09.2026,
               discord.com: замер заготовкой в 1534 байта (два сегмента), а
               снимок клиента — 321 байт одним сегментом; оба современные, и
               повтора не было — привязка легла заготовкой при снимке на
               руках. Коробка вправе смотреть на содержимое и длину, а не
               только на версию (§6), поэтому повод для повтора один: мерили
               НЕ байтами клиента, а они уже есть. */
            /* Снимок ДРУГОГО клиента этого имени (форма расходится с формой
               клиента подозрения) повтором не берётся: мерили бы снова не
               того клиента (hello_fits_client). */
            if (snap_restart ||
                (t->transport == 6 && !t->reasked && s->tcp_shape_len[t->family == 6] > 0 &&
                strcmp(s->tcp_shape_name[t->family == 6], t->name) == 0 &&
                s->tcp_shape_len[t->family == 6] <= sizeof t->trig &&
                hello_fits_client(t, s->tcp_shape[t->family == 6], s->tcp_shape_len[t->family == 6]) &&
                (!t->trig_snapped ||
                 (!t->ech_grease &&
                  d2k_hello_ech_offer(s->tcp_shape[t->family == 6], s->tcp_shape_len[t->family == 6], NULL) == 1
                    ? D2K_LINK_SHAPE_ECH_TCP :
                    (uint8_t)d2k_hello_shape(s->tcp_shape[t->family == 6], s->tcp_shape_len[t->family == 6]))
                     != t->asked_shape))) {
                const uint8_t *snap = snap_restart ? t->snap : s->tcp_shape[t->family == 6];
                size_t snap_len = snap_restart ? t->snap_len : s->tcp_shape_len[t->family == 6];
                int other_form = d2k_hello_shape(snap, snap_len) != (d2k_shape)t->asked_shape;
                /* Снимок берём ТОЛЬКО ТЕПЕРЬ, когда замер закончен: вход
                   опыта неизменен, пока опыт идёт (см. on_shape — снимок
                   кладётся лишь задачам, которые его ЖДУТ). */
                t->reasked = 1;
                t->snap_stop = 0;
                d2k_run_cache_clear(&t->run_cache);
                size_t was_len = t->trig_len;
                memcpy(t->trig, snap, snap_len);
                t->trig_len = snap_len;
                t->trig_snapped = 1;
                if (snap_restart) {
                    t->client_opts_known = t->snap_opts_known;
                    t->client_opts_len = t->snap_opts_known ? t->snap_opts_len : 0;
                    if (t->client_opts_len) memcpy(t->client_opts, t->snap_opts, t->client_opts_len);
                } else {
                    take_shape_opts(s, t);
                }
                t->ctrl_len = 0;   /* контроль соберётся из новых байт */
                if (other_form) {
                    say(s, "по %s замер шёл приветствием другой формы, чем у клиента "
                           "(снимок пришёл позже старта) — повторяю поиск его байтами: %zu",
                        t->name, t->trig_len);
                } else {
                    say(s, "по %s замер шёл заготовкой (%zu байт), а снимок клиента "
                           "пришёл позже старта (%zu байт) — повторяю поиск его байтами",
                        t->name, was_len, t->trig_len);
                }
                t->researched = 0;
                t->n_plans = 0;
                t->next_plan = 0;
                /* ОТВЕЧЕННОЕ НЕ ПЕРЕСПРАШИВАЕТСЯ. Обрыв ответа этим прогоном
                   уже доказан парой измерений и забран выше; второй, непарный
                   замер объёма — ровно то, чем поле 12.10 стирало полученное
                   доказательство. Повтор идёт за коробкой и планами. */
                if (snap_restart && t->vol.rx_cut) { t->skip_volume_once = 1; }
                char restart_name[sizeof t->name];
                snprintf(restart_name, sizeof restart_name, "%s", t->name);
                if (start_search(s, t)) {
                    moved++;
                    continue;
                }
                /* ПРОВАЛ ПЕРЕЗАПУСКА — КОНЕЦ ЗАДАЧИ (задача 24). start_search
                   уже сбросил её (task_reset): разбирать дальше вердикт
                   устаревшего прогона занулённой задачей значило завести
                   T_PLANNING без имени, цели и формы. Результат прогона
                   заготовкой выброшен выше сознательно — он не тех байт. */
                say(s, "по %s повтор поиска снимком не запустился — задача снята, "
                       "следующее подозрение начнёт поиск заново", restart_name);
                moved++;
                continue;
            }
            /* БАЗОВЫЙ ВОПРОС ДОНОРА ОТВЕТИЛ (задача 32). Блокировка на
               рукопожатии подтверждена — сначала свои подтверждённые планы
               той же формы, на изолированных портах собственным зондом с
               полным ответом. Иначе — полный прогон как прежде; ответ базы в
               его вердикт не идёт. */
            if (t->own_first == 1) {
                t->own_first = 3;
                t->seed = r.base;
                t->seed_input = seed_input_of(t->trig, t->trig_len, t->ip, t->port);
                size_t own = r.base_blocked ? own_first_plans(s, t, 1) : 0;
                if (own > 0) {
                    t->own_first = 2;
                    t->res = r;
                    /* Прямое рукопожатие не прошло: под кандидатом тело
                       проверяется identity-путём, как после OPAQUE. */
                    if (t->transport == 6) {
                        memset(&t->vol, 0, sizeof t->vol);
                        t->vol.rx_tls_unavailable = 1;
                    }
                    t->n_plans = t->n_known = own;
                    t->next_plan = 0;
                    t->cached_measure_valid = 0;
                    t->exec_refused = t->exec_probed = 0;
                    t->rx_phase = 0;
                    t->state = T_PLANNING;
                    say(s, "по %s базовый вопрос донора: рукопожатие не проходит (%s) — "
                           "пробую свои подтверждённые планы до полного замера: %zu",
                        t->name, r.reason, own);
                    moved++;
                    continue;
                }
                if (r.base_blocked) {
                    say(s, "по %s базовый вопрос донора: рукопожатие не проходит (%s), "
                           "своих подтверждённых планов этой формы нет — продолжаю полный замер",
                        t->name, r.reason);
                } else {
                    say(s, "по %s базовый вопрос донора не подтвердил блокировку рукопожатия "
                           "(%s) — свои планы не пробую, продолжаю полный замер",
                        t->name, r.reason);
                }
                own_first_continue(s, t);
                moved++;
                continue;
            }
            int volume_proven = t->transport == 6 &&
                (t->vol.verdict == D2K_VOL_CUT || t->vol.rx_cut);
            if (t->family_reuse == 1 && t->vol.rx_tls_unavailable && !volume_proven) {
                t->family_reuse = 2;
                if (rx_saved_bootstrap(s, t, 1)) { moved++; continue; }
                t->family_reuse = 3; t->skip_volume_once = 1;
                t->exec_refused = t->exec_probed = 0;
                t->state = T_ASKING;
                if (start_worker(s, t, JOB_CLASSIFY) != 0) task_fail(s, t, now_ms);
                moved++; continue;
            }
            if (r.verdict == D2K_V_ADDRESS && t->transport == 6 && !volume_proven &&
                !t->ech_trial && t->addr_ack == 1) {
                /* ЗАДАЧА 54, I2. Этот же прогон начался с подтверждённого
                   нейтрального байта, а после триггеров адрес замолчал: это
                   штраф коробки за триггер, а не блок адреса. Address здесь
                   был бы ложью; честно — неубедительно. */
                t->addr_ack = 0;
                say(s, "по %s адрес %s принимает данные до триггера и глохнет только после "
                       "триггера — это штраф коробки, а не блок адреса; результат неубедителен, "
                       "повторный замер отложен на %lld мин",
                    t->name, t->ip, (long long)(SCHED_INCOMPLETE_BACKOFF_MS / 60000));
                cooldown_record(s, t, 2);
                task_fail(s, t, now_ms);
                moved++;
                continue;
            }
            if (r.verdict == D2K_V_ADDRESS && t->transport == 6 && !volume_proven &&
                !t->ech_trial) {
                /* ЗАДАЧА 54. Адрес после рукопожатия не принимает данных —
                   доказанный исход, а не «неубедительно»: план тут не поможет
                   никакой (десинк меняет вид байт, а не доставку). Отсрочка —
                   этому адресу, лестницей; каталог не трогаем. Сюда же идёт
                   address дерева после полного перебора при поручительстве за
                   контроль (control_vouched; планировщик его не ставит). */
                int64_t delay_ms = dead_step(s, t);
                say(s, "по %s адрес %s не принимает данных (%s) — средствами d2k это не "
                       "обходится; повторная проверка этого адреса через %lld мин (сначала "
                       "одним нейтральным байтом, без триггера), другие адреса имени мерятся "
                       "как обычно",
                    t->name, t->ip, r.reason, (long long)((delay_ms + 59999) / 60000));
                task_fail(s, t, now_ms);
                moved++;
                continue;
            }
            if (t->transport == 6) { dead_clear(s, t); }
            t->addr_ack = 0;
            /* A passing ClientHello says nothing about the framed response
             * that was already cut in this same measurement. An unavailable
             * repeat is not a paired volume verdict, nor a direct success. */
            if (r.verdict == D2K_V_CLEAR &&
                (t->vol.rx_partial_bytes || t->vol.rx_partial_wire_bytes) && !volume_proven) {
                r.verdict = D2K_V_INCONCLUSIVE;
                snprintf(r.reason, sizeof r.reason,
                    "RX %s оборвался после %llu байт; повторный объёмный замер не завершён",
                    t->vol.rx_partial_wire_bytes ? "TLS wire" : "HTTP body",
                    (unsigned long long)(t->vol.rx_partial_wire_bytes
                        ? t->vol.rx_partial_wire_bytes : t->vol.rx_partial_bytes));
            }
            if (r.verdict == D2K_V_CLEAR && is_late_volume_suspicion(t->trigger_code) &&
                t->transport == 6 && !volume_proven && !t->vol.rx_direct_complete) {
                r.verdict = D2K_V_INCONCLUSIVE;
                if (t->vol.rx_unmeasured) {
                    snprintf(r.reason, sizeof r.reason,
                             "объём ответа измерить не удалось; прямой замер не подтверждён");
                } else if (t->vol.verdict == D2K_VOL_SHORT) {
                    snprintf(r.reason, sizeof r.reason,
                             "объём ответа меньше полосы; прямой замер не подтверждён");
                } else {
                    snprintf(r.reason, sizeof r.reason,
                             "прямой ответ не подтвердил прикладной успех; прямой замер не подтверждён");
                }
            }
            /* A measured synthesis candidate requests an isolated application
               trial; it does not assert a blocking class. CLEAR and other
               direct/unreachable verdicts still forbid candidate execution. */
            int synthesis_trial = r.verdict == D2K_V_INCONCLUSIVE && r.program_len != 0;
            if (!verdict_proves_block(r.verdict) && !synthesis_trial && !volume_proven && !t->ech_trial && !t->doh_trial) {
                say(s, "по %s прямой замер не подтвердил блокировку (%s: %s) — "
                       "подбор и применение обхода не запускаю",
                    t->name, verdict_name(r.verdict), r.reason);
                if (r.verdict == D2K_V_CLEAR) {
                    search_report(s, t, now_ms, "probe-direct", "direct",
                                  "прямой замер показал чистый путь: обходить нечего");
                    if (t->vol.rx_direct_complete) {
                        uint8_t shape = t->transport == 17 ? D2K_LINK_SHAPE_QUIC :
                            t->ech_offer ? D2K_LINK_SHAPE_ECH_TCP :
                            d2k_hello_shape(t->trig, t->trig_len) == D2K_SHAPE_LEGACY ?
                            D2K_SHAPE_LEGACY : SCHED_PROBE_SHAPE;
                        group_record(s, t, D2K_GROUP_DIRECT_CLEAR, NULL, shape, now_ms);
                    }
                    if(encrypted_dns_task(t) && t->vol.rx_direct_complete) {
                        doh_target *d=dns_target_of(s,t);if(d)d->recovery=0;
                    }
                    forget_clear_target_bindings(s, t, now_ms);
                    cooldown_record(s, t, 0);
                    target_cooldown *cool = cooldown_find(s, t->name, t->transport, t->family);
                    int64_t delay_ms = cool
                                           ? clear_backoff_ms(cool->negative_streak)
                                           : SCHED_CLEAR_BACKOFF_1_MS;
                    say(s, "по %s напрямую проходит — повторный поиск отложен на %lld мин; "
                           "это временный ограничитель, а не запись в каталоге",
                        t->name, (long long)((delay_ms + 59999) / 60000));
                } else if (r.verdict == D2K_V_FLAKY && t->transport == 6 &&
                           r.dial_deadline) {
                    /* АДРЕС НЕ ПРИНИМАЛ СОЕДИНЕНИЙ ПОСРЕДИ ЗАМЕРА (поле 17.10.2026,
                       flibusta.is): после серии приветствий с триггером коробка
                       глушит SYN к адресу — с роутера после 40 таких запросов
                       половина подключений не прошла, остальные шли 1–3 с, через
                       10 с — снова. Это не неубедительный замер, а его отсутствие,
                       вызванное нашими же зондами: отсрочка на 10 минут оставляла
                       цель без плана на весь сеанс. Следующее подозрение начнёт
                       поиск заново — своими планами первыми, они триггера не
                       показывают. */
                    search_report(s, t, now_ms, "unknown", "none",
                                  "адрес не принимал соединений во время замера: замера не было");
                    say(s, "по %s замер не состоялся: адрес не принимал соединений во время "
                           "замера — это не отказ и не неубедительный замер; повторю при "
                           "следующем подозрении, своими планами первыми", t->name);
                } else {
                    search_report(s, t, now_ms, "inconclusive", "none",
                                  "замер не подтвердил блокировку: подбор не открыт");
                    cooldown_record(s, t, 2);
                    say(s, "по %s результат неубедителен — повторный замер отложен на %lld мин",
                        t->name, (long long)(SCHED_INCOMPLETE_BACKOFF_MS / 60000));
                }
                task_fail(s, t, now_ms);
                moved++;
                continue;
            }
            cooldown_clear(s, t->name, t->transport, t->family);
            t->group_block_proven = verdict_proves_block(r.verdict) || volume_proven;
            {
                /* Volume fingerprint is installed by make_plans before its
                   catalog lookup; do not match the earlier generic reset. */
                size_t known = volume_proven || t->ech_trial || r.program_len ? 0 : known_plans(s, t);
                if (known > 0) {
                    t->res = r;
                    /* Поиск принадлежит замеру и в этой ветке (задача 37):
                       verdict_to_plans здесь не зовётся, а владение ставит
                       только он. Без этого провал плана коробки уводил в
                       запасной список, которого донор после вердикта не
                       перебирает. */
                    t->search_owned = r.owns_search || r.program_len != 0;
                    t->owned_fallback = 0;
                    t->cached_measure_valid = 1;
                    t->n_known = known;
                    t->n_plans = known;
                    t->next_plan = 0;
                    t->state = T_PLANNING;
                    say(s, "по %s прямой замер подтвердил блокировку (%s: %s) за %d зондов "
                           "замера — сначала проверяю %zu готовых планов узнанной коробки",
                        t->name, verdict_name(r.verdict), r.reason, r.probes, known);
                    say_question_trace(s, t, &r);
                    moved++;
                    continue;
                }
            }
            /* Вопросы о свойствах нужны ТОЛЬКО там, где чем брать — неизвестно.
               Измеритель, вернувший плечо, на этот вопрос уже ответил своими
               зондами; спрашивать то же самое ещё раз через датапат значит
               потратить минуты на повторение готового ответа. */
            if (r.verdict == D2K_V_OPAQUE && t->transport == 6 && !r.have_arm && !r.program_len && !r.owns_search) {
                /* «Решает содержимое» — единственный вердикт, на который
                   вопросы о свойствах вообще осмысленны: разрез такую коробку
                   не берёт, берёт её отравление буфера пересборки, а чем
                   именно — это и есть вопросы (d2k_compose.h). На остальных
                   вердиктах спрашивать нечего: там ответ уже дан разрезом или
                   его отсутствием. Только TCP: все пять вопросов —
                   про TCP-сегменты, которых у QUIC нет. */
                say(s, "по %s вердикт: %s (%s) — спрашиваю коробку о свойствах",
                    t->name, verdict_name(r.verdict), r.reason);
                memset(&t->props, 0, sizeof t->props);
                t->prop_q = -1;
                t->props_asked = 0;
                t->res = r;
                if (prop_send_next(s, t, now_ms) == 0) {
                    moved++;
                    continue;
                }
                prop_finish(s, t);
            }
            verdict_to_plans(s, t, &r);
            /* ДЛИТЕЛЬНОСТЬ И ЦЕНА — В ТОЙ ЖЕ СТРОКЕ, ЧТО И ВЕРДИКТ.
               Без них «поиск идёт» в журнале ничем не отличается от «поиск
               завис», и разобраться можно только с секундомером у чужого
               стенда: ровно этим кончился прогон транзита 17.09, где замер
               шёл третью минуту при окне стенда в две. Числа берём
               измеренные — часы задачи и её же счётчик зондов. */
            long long took_s = (long long)((now_ms - (t->began_ms ? t->began_ms : t->started_ms) + 500) / 1000);
            /* Зонды берём У ЗАМЕРА (r.probes), а не у задачи (t->probes):
               задачный счётчик считает поставленные кандидаты, а не опыты
               измерителя, и печатал «0 зондов» там, где их было восемнадцать. */
            if (t->n_known > 0) {
                say(s, "по %s вердикт: %s (%s) за %lld с и %d зондов замера, кандидатов %zu — "
                       "из них %zu готовых планов узнанной коробки %s",
                    t->name, verdict_name(r.verdict), r.reason, took_s, r.probes,
                    t->n_plans, t->n_known, t->box_id);
            } else {
                say(s, "по %s вердикт: %s (%s) за %lld с и %d зондов замера, кандидатов %zu",
                    t->name, verdict_name(r.verdict), r.reason, took_s, r.probes,
                    t->n_plans);
            }
            /* НАХОДКИ — ОТДЕЛЬНЫМИ СТРОКАМИ И ПОСЛЕ ВЕРДИКТА.
               Приём, который коробку ломает, а движку исполнить нечем, — это
               не кандидат и в план не пойдёт; но и молчать о нём нельзя:
               ровно эти строки говорят, куда движку расти, и ровно они
               теряются первыми, если складывать их в текст причины (384
               байта на весь вердикт). См. d2k_quic_props_findings. */
            say_question_trace(s, t, &r);
            {
                char found[1024];
                if (d2k_quic_props_findings(&r.qprops, found, sizeof found) > 0) {
                    char *line = found;
                    while (line && *line) {
                        char *nl = strchr(line, '\n');
                        if (nl) { *nl = '\0'; }
                        say(s, "по %s приём взял, а движку нечем: %s", t->name, line);
                        line = nl ? nl + 1 : NULL;
                    }
                }
            }
            if (t->n_plans == 0) {
                /* Блок доказан, а кандидатов нет — тот же исход, что
                   исчерпание: повтор через десять минут, не через два. */
                cooldown_record(s, t, 2);
                say(s, "по %s кандидатов нет — новый поиск отложен на %lld мин",
                    t->name, (long long)(SCHED_INCOMPLETE_BACKOFF_MS / 60000));
                task_fail(s, t, now_ms);
                moved++;
                continue;
            }
            t->state = T_PLANNING;
            moved++;
        }

        if (t->state == T_PROPS_CONTACT) {
            int ready;
            pthread_mutex_lock(&s->mu);
            ready = t->res_ready;
            pthread_mutex_unlock(&s->mu);
            if (!ready) {
                if (now_ms < t->prop_until_ms) { continue; }
                /* Обращение не вернулось в срок — поток ещё в сети; бросать
                   его нельзя, ждём столько же ещё раз, а не режем задачу. */
                t->prop_until_ms = now_ms + SCHED_PROP_STEP_MS;
                continue;
            }
            join_worker(t);
            if (!t->c_ok) {
                contact_close(t);
                /* Обращение не состоялось (транспорт) — вопрос не измерен. */
                if (prop_send_next(s, t, now_ms) != 0) {
                    prop_finish(s, t);
                    verdict_to_plans(s, t, &t->res);
                    t->state = T_PLANNING;
                }
                moved++;
                if (t->state != T_PLANNING) { continue; }
            } else {
                t->prop_fd = t->c_fd;
                t->c_fd = -1; /* владелец теперь prop_fd */
                t->prop_flow.family = t->family;
                memcpy(t->prop_flow.a_ip, t->c_ip, sizeof t->prop_flow.a_ip);
                t->prop_flow.a_port = t->c_port;
                inet_pton(t->family == 6 ? AF_INET6 : AF_INET, t->ip, t->prop_flow.b_ip);
                t->prop_flow.b_port = t->port;
                t->prop_flow.transport = 6;
                t->state = T_PROPS_WAIT;
                {
                    /* Применение, пришедшее ещё в T_PROPS_CONTACT. */
                    d2k_ev own;
                    memset(&own, 0, sizeof own);
                    own.family = t->prop_flow.family;
                    memcpy(own.low_ip, t->prop_flow.a_ip, sizeof own.low_ip);
                    memcpy(own.high_ip, t->prop_flow.b_ip, sizeof own.high_ip);
                    own.low_port = t->prop_flow.a_port;
                    own.high_port = t->prop_flow.b_port;
                    own.transport = t->prop_flow.transport;
                    for (size_t k = 0; k < t->prop_early_seen && !t->prop_applied; k++) {
                        if (ev_matches_flow(&own, &t->prop_early[k])) { t->prop_applied = 1; }
                    }
                    t->prop_early_seen = 0;
                }
                {
                    /* Ответ сервера, пришедший ещё в T_PROPS_CONTACT: первый,
                       чей ПОЛНЫЙ ключ — поток вопроса; чужие отбрасываются. */
                    d2k_ev early;
                    int have_early = 0;
                    for (size_t k = 0; k < t->prop_early_x_seen && !have_early; k++) {
                        if (ev_matches_flow(&t->prop_early_x[k], &t->prop_flow)) {
                            early = t->prop_early_x[k];
                            have_early = 1;
                        }
                    }
                    t->prop_early_x_seen = 0;
                    if (have_early) {
                        say(s, "по %s зонд вопроса %d ушёл с местного порта %u — ответ "
                               "пришёл раньше перехода к ожиданию",
                            t->name, t->prop_q + 1, (unsigned)t->c_port);
                        on_exchange(s, &early);
                        moved++;
                        continue;
                    }
                }
                t->prop_until_ms = now_ms + SCHED_PROP_STEP_MS;
                say(s, "по %s зонд вопроса %d ушёл с местного порта %u — жду обмена",
                    t->name, t->prop_q + 1, (unsigned)t->c_port);
                moved++;
                continue;
            }
        }

        if (t->state == T_PROPS_WAIT) {
            if (now_ms < t->prop_until_ms) { continue; }
            /* Обмена с прикладными данными не дождались — промах вопроса. Он
               НЕ пишет ничего (§2.4, каждый Set в Go начинается с
               `if !passed { return }`).

               Отдельно называем случай, когда воздействия НЕ БЫЛО ВОВСЕ:
               датапат сообщил, что посылка плана не покинула машину. Свойство
               не пишется и здесь, но это другой факт, и в объяснении он
               обязан звучать по-другому — иначе своя поломка читается как
               «коробка не поддалась» и уводит поиск. Следующий вопрос
               задаётся в обоих случаях: бюджет вопросов общий. */
            if (t->unsent_code != 0) {
                say(s, "по %s вопрос %d не состоялся: посылка плана не ушла на провод "
                       "(причина %u) — это наша неудача, не свойство коробки",
                    t->name, t->prop_q, (unsigned)t->unsent_code);
                t->unsent_code = 0;
            }
            question_retire(s, t);
            prop_close(t);
            if (prop_send_next(s, t, now_ms) != 0) {
                prop_finish(s, t);
                verdict_to_plans(s, t, &t->res);
                t->state = T_PLANNING;
            }
            moved++;
            if (t->state != T_PLANNING) { continue; }
        }

        if (t->state == T_VERIFY) {
            int ready;
            pthread_mutex_lock(&s->mu);
            ready = t->res_ready;
            pthread_mutex_unlock(&s->mu);
            if (!ready) { continue; } /* зонд в сети; срок задачи считается выше */
            join_worker(t);
            if (encrypted_dns_task(t) && (dns_non_path_failure(&t->ver) ||
                (t->dns_expected_http && t->ver.doh_http_version &&
                 t->dns_expected_http!=t->ver.doh_http_version))) {
                say(s, "по %s проверка DNS остановлена: %s", t->name, t->ver.reason);
                doh_target *target=dns_target_of(s,t);
                if (target) target->recovery=0;
                trial_retire(s,t);
                task_done(s,t);
                moved++;
                continue;
            }
            if (t->exec_nak) {
                exec_refusal(s, t, t->exec_nak & 0xffu, 1);
                moved++;
                continue;
            }
            if (t->transport == 6 && t->ver.body_complete &&
                t->ver.status >= 200 && t->ver.status < 300 &&
                t->ver.http_outcome != D2K_HTTP_BLOCKED && t->ver.http_outcome != D2K_HTTP_LEGAL_DENIAL)
                remember_resources(s, t->ver.resources, t->ver.n_resources);
            /* Если настоящий QUIC snapshot пришёл уже после установки этого
               trial, его результат относится к профилю, а не к байтам клиента.
               Кандидат обязан быть снят exact-командой ДО повторного поиска;
               иначе успешный VERIFY запишет ложное знание под чужой формой. */
            const uint8_t *qb; size_t ql; uint64_t qseq;
            if (!t->reasked && !t->trig_snapped && t->trial_installed &&
                quic_own_initial(s, t, &qb, &ql, &qseq) && qseq > t->trial_shape_seq) {
                ver_close(t);
                trial_retire(s, t);
                remeasure_snapped(s, t, qb, ql);
                moved++;
                continue;
            }
            /* КЛЮЧ ЗОНДА ИЗВЕСТЕН ТОЛЬКО ТЕПЕРЬ: местный порт назначает ядро
               при обращении. Собираем его сразу, до любых решений, потому что
               по нему разбираются НАКОПЛЕННЫЕ ранние отказы: до возврата
               зонда отличить отказ своего обращения от отказа соседнего
               клиента той же цели было нечем. */
            t->ver_flow.family = t->family;
            memcpy(t->ver_flow.a_ip, t->family == 6 ? t->ver.local_addr : t->ver.local_ip4,
                   t->family == 6 ? 16 : 4);
            t->ver_flow.a_port = t->ver.local_port;
            inet_pton(t->family == 6 ? AF_INET6 : AF_INET, t->ip, t->ver_flow.b_ip);
            t->ver_flow.b_port = t->port;
            t->ver_flow.transport = t->transport;
            claim_early_refusal(t);
            /* СВИДЕТЕЛЬ-ПРОВЕРКА ОБЪЁМА НЕ ПОКАЖЕТ (поле 17.10.2026, LR-rx4-1).
               romfea.gr отвечает через принятый ECH страницей проверки
               Cloudflare (403, 3,6 КБ): проход ECH она доказывает, а обрыв
               на ~16 КБ на ней не случится. Прежде (joint-02) такой ответ
               подтверждал план перебора, снимающий только рукопожатие, и
               Chrome резался на 16 КБ у шести сайтов. Это и не антибот цели
               (паузы нет), и не подтверждение: есть запасной свидетель — тот
               же кандидат через него (отчёт и курсоры кандидатов те же); нет —
               кандидат не измерен, следующий. Нехватка свидетелей
               доказательство не усиливает (ревью Astra, 17.10). */
            if (ech_witness_transport_proof(t)) {
                ech_witness_reject(s, t);
                if (ech_witness_untried(s, t)) {
                    say(s, "по %s свидетель %s ответил страницей проверки своего сервера "
                           "(HTTP %d): проход ECH она доказывает, объём ответа на ней не "
                           "измерить — тот же кандидат проверяю через другого свидетеля",
                        t->name, t->ech_origin, t->ver.status);
                    t->ech_reselect = 1;
                    trial_retire(s, t);
                    ver_close(t);
                    t->ver_seen = 0;
                    t->ver_ok = 0;
                    if (t->next_plan > 0) { t->next_plan--; }
                    t->state = T_PLANNING;
                    moved++;
                    continue;
                }
                t->ech_exhausted = 1;
            }
            /* ПРОВЕРЯТЬ ОБЪЁМ НЕЧЕМ (ревью Astra R2): ни один свидетель этой
               ECH-конфигурации не отвечает без страницы проверки. Следующий
               план не делает отвергнутого свидетеля пригодным: кандидаты не
               оцениваются, поиск закрывается неубедительным — это не
               доказательство против планов и не антибот цели. */
            if (t->transport == 6 && t->ech_offer && !t->ech_replay && t->ech_exhausted) {
                say(s, "по %s свидетели ECH отвечают только страницей проверки (последний — "
                       "%s): проход ECH доказан, объём ответа измерить нечем — кандидатов не "
                       "оцениваю, поиск закрываю неубедительным", t->name, t->ech_origin);
                trial_retire(s, t);
                ver_close(t);
                search_report(s, t, now_ms, "inconclusive", "none",
                              "проход ECH доказан, объём ответа измерить нечем: кандидатов нет");
                cooldown_record(s, t, 3);
                task_fail(s, t, now_ms);
                moved++;
                continue;
            }
            if (t->ver.level == D2K_VER_CHALLENGE) {
                /* Anti-bot challenge means the HTTP edge answered, but the
                   requested content was not established. It is neither a
                   successful bypass nor evidence against this candidate:
                   stop this search instead of burning every arm against the
                   same challenge, and remove only the temporary trial. */
                say(s, "по %s зонд получил %s — это не подтверждение обхода и не диагноз блокировки; "
                       "перебор остановлен",
                    t->name, t->ver.reason);
                cooldown_record(s, t, 1);
                say(s, "по %s антибот-ответ: активный замер этой цели поставлен на паузу на %lld мин",
                    t->name, (long long)(SCHED_CHALLENGE_BACKOFF_MS / 60000));
                ver_close(t);
                task_fail(s, t, now_ms);
                moved++;
                continue;
            }
            if (t->ver.level == D2K_VER_DENIED) {
                /* Имя собеседника подтверждено сертификатом — иначе уровень
                   DENIED не ставится вовсе (core/verify.c, 24.10.2026).
                   Говорим это прямо: прежняя строка утверждала отказ сервиса
                   по одному коду, и по x-minus.pro час тишины уходил на
                   ответ, который сервис не присылал. */
                say(s, "по %s HTTP 451 от владельца имени (сертификат сверен): юридический отказ "
                       "сервиса, не блокировка провайдера; перебор остановлен",
                    t->name);
                /* ОТКАЗАЛ СЕРВИС, А НЕ КОРОБКА — значит перемерять эту цель
                   сейчас же бессмысленно: следующий замер получит тот же 451.
                   Остывание такое же, как у антибот-ответа рядом; без него
                   поле 23.10.2026 показало два полных поиска одной цели за
                   145 секунд с одинаковым исходом. Что опыт при этом
                   выбрасывается целиком (план снял блок рукопожатия, а
                   пользователь получает разорванное соединение вместо
                   страницы отказа) — отдельный вопрос, см. замысел
                   2026-10-23 «HTTP 451: приём снял блок рукопожатия». */
                cooldown_record(s, t, 4);
                say(s, "по %s юридический отказ сервиса: активный замер этой цели "
                       "поставлен на паузу на %lld мин", t->name,
                    (long long)(SCHED_CHALLENGE_BACKOFF_MS / 60000));
                ver_close(t);
                task_fail(s, t, now_ms);
                moved++;
                continue;
            }
            if (t->ver.unsupported) {
                /* НЕ ПРО КАНДИДАТА, А ПРО ТРАНСПОРТ. Следующий кандидат
                   получит тот же ответ, и перебор потратил бы весь бюджет
                   зондов на установку планов, которых никто не проверит, —
                   а на живом роутере таких целей десятки (браузер ходит по
                   QUIC ко всему подряд). Закрываем задачу и говорим прямо:
                   мерить умеем, подтверждать нечем. В каталог не идёт
                   ничего (§10). */
                say(s, "по %s (%s) подтверждать нечем: %s. Кандидатов не перебираю — "
                       "ответ будет тот же, а знание в каталог не попадёт",
                    t->name, t->transport == 17 ? "QUIC" : "TCP", t->ver.reason);
                ver_close(t);
                task_fail(s, t, now_ms);
                moved++;
                continue;
            }
            if (t->ver.cloudflare_challenge) {
                /* Cloudflare challenge is an HTTP response, but not the
                   requested application content. Treating it as success
                   would persist a useless plan; cycling through more plans
                   would repeat bot-like probes while the challenge remains.
                   The exact header is parsed by verify.c, not guessed from a
                   generic 403 which some APIs legitimately return. */
                say(s, "по %s получен Cloudflare challenge (cf-mitigated: challenge) — "
                       "это не обход; останавливаю поиск и даю цели отдохнуть",
                    t->name);
                /* Как у соседней ветки D2K_VER_CHALLENGE: антибот-пауза цели,
                   а не только 2-минутный отдых задачи (финальное ревью, п.5). */
                cooldown_record(s, t, 1);
                say(s, "по %s антибот-ответ: активный замер этой цели поставлен на паузу на %lld мин",
                    t->name, (long long)(SCHED_CHALLENGE_BACKOFF_MS / 60000));
                task_fail(s, t, now_ms);
                moved++;
                continue;
            }
            if (!t->ver.handshake_proof && !t->ver.replay_proof &&
                layered_rx_result(s, t, now_ms)) { moved++; continue; }
            if (t->ver.level == D2K_VER_APPLICATION && t->ver.budget == D2K_BUDGET_CUT) {
                /* ОБРЫВ ПОСРЕДИ ПОВТОРОВ — улика, только если план исполнился на
                   потоке зонда (ревью I-1): тот же порядок, что у подтверждения.
                   Посылка не ушла — наша неудача (local_refusal_verdict);
                   применение не пришло — ждём его, держа сокет; не придёт —
                   «не засчитано», как у подтверждения без применения. */
                budget_uncountable_note(s, t);
                if (local_refusal_verdict(s, t) != 0) { moved++; continue; }
                d2k_ev own;
                memset(&own, 0, sizeof own);
                memcpy(own.low_ip, t->ver_flow.a_ip, sizeof own.low_ip);
                memcpy(own.high_ip, t->ver_flow.b_ip, sizeof own.high_ip);
                own.family = t->ver_flow.family;
                own.low_port = t->ver_flow.a_port;
                own.high_port = t->ver_flow.b_port;
                own.transport = t->ver_flow.transport;
                for (size_t k = 0; k < t->ver_seen; k++)
                    if (ev_matches_flow(&own, &t->ver_early[k])) { t->ver_ok = 1; break; }
                if (t->ver_ok) {
                    budget_cut_reject(s, t, now_ms);
                } else {
                    t->state = T_VERIFY_WAIT;
                    t->ver_until_ms = now_ms + SCHED_VERIFY_STEP_MS;
                    say(s, "по %s поток зонда оборвался посреди повторов (порт %u) — жду "
                           "применения плана к нему, без него обрыв не улика",
                        t->name, (unsigned)t->ver.local_port);
                }
                moved++;
                continue;
            }
            /* Доказательство на проводе: полный HTTP-ответ — либо, для
               не-HTTP протокола клиента, завершённое рукопожатие с его ALPN
               (задача 37, F3). Второе — уровень рукопожатия, не приложения. */
            /* Повтор ECH-приветствия клиента без свидетеля (поле 04.10) —
               ServerHello на те же байты под планом: тоже граница
               рукопожатия, и слабее предыдущей (своё рукопожатие не
               завершено); verify_confirm так его и записывает. */
            int wire_proof = t->ver.level == D2K_VER_APPLICATION ||
                ((t->ver.handshake_proof || t->ver.replay_proof) &&
                 t->ver.level == D2K_VER_HANDSHAKE);
            if (!wire_proof) {
                /* СПЕРВА — НАША ЛИ ЭТО НЕУДАЧА. Зонд мог не дойти до
                   приложения просто потому, что воздействия не было: посылка
                   плана не покинула машину, и цель ответила ровно как без
                   обхода. Объявить это промахом кандидата значит выбросить,
                   возможно, рабочий план из-за своей поломки (0009, U2).

                   Разбор стоит ВНУТРИ отрицательной ветки, а не перед ней, и
                   это не мелочь: полное доказательство сильнее отказа. При
                   уровне «приложение» и уже совпавшем раннем применении
                   находка подтверждается, а не уходит в повтор — иначе
                   поведение зависело бы от того, успело ли событие применения
                   прийти раньше возврата зонда. Порядок фактов в обеих ветках
                   один: доказательство → потеря событий → локальный отказ →
                   «не измерено». */
                if (local_refusal_verdict(s, t) == 0) {
                    /* НЕУДАЧА ЗОНДА, К ПОТОКУ КОТОРОГО ПЛАН НЕ ПРИМЕНЯЛСЯ, —
                       НЕ УЛИКА ПРОТИВ ПЛАНА, А ОТСУТСТВИЕ ОПЫТА.
                       Соседняя ветка (зонд ПРОШЁЛ) эту дисциплину уже держит:
                       нет доказательства применения — не засчитано. Здесь она
                       была обратной, и асимметрия выбрасывала рабочие планы.
                       Поле 17.09.2026, discord.com: замер нашёл приём, приём
                       рабочий (проверено планом отдельно, 3/3 по 200), а
                       подтверждение дало «зонд не дошёл» и выбросило его. План
                       ставится записью в управляющий сокет, а испытание
                       стартует сразу: на живой линии зонд успевает уйти
                       раньше, чем датапат прочитал команду, и идёт голым. */
                    int touched = 0;
                    {
                        d2k_ev own;
                        memset(&own, 0, sizeof own);
                        memcpy(own.low_ip, t->ver_flow.a_ip, sizeof own.low_ip);
                        memcpy(own.high_ip, t->ver_flow.b_ip, sizeof own.high_ip);
                        own.family = t->ver_flow.family;
                        own.low_port = t->ver_flow.a_port;
                        own.high_port = t->ver_flow.b_port;
                        own.transport = t->ver_flow.transport;
                        for (size_t k = 0; k < t->ver_seen; k++) {
                            if (ev_matches_flow(&own, &t->ver_early[k])) { touched = 1; break; }
                        }
                    }
                    /* ТОЛЬКО ПРИ D2K_VER_TRANSPORT, а не при любой неудаче.
                       Это подпись голого зонда: соединение встало, а приложение
                       молчит — ровно так выглядит зонд, которого коробка
                       срезала по приветствию. D2K_VER_NOT_MEASURED значит
                       другое («обращение не состоялось»), и там повторять
                       нечего: измеритель сам сказал, что опыта не было. */
                    if (t->ver.level == D2K_VER_TRANSPORT && !touched &&
                        t->ver_bare_retries < SCHED_BARE_RETRIES &&
                        t->probes < sched_probe_cap(t)) {
                        t->ver_bare_retries++;
                        say(s, "по %s план %zu: зонд не дошёл (%s), но и плана на его потоке "
                               "не было — опыта не было, ставлю того же кандидата заново",
                            t->name, t->next_plan, t->ver.reason);
                        trial_retire(s, t);
                        ver_close(t);
                        t->ver_seen = 0;
                        t->ver_ok = 0;
                        /* ЗАНОВО СТАВИМ ПЛАН, А НЕ ПРОСТО ПОВТОРЯЕМ ЗОНД.
                           Рабочий поток ЗАБИРАЕТ занятый сокет (see start_worker:
                           t->probe_fd = -1), и следующий зонд возьмёт ДРУГОЙ
                           местный порт. Пробный план привязан к порту — значит
                           к новому потоку он не применится никогда, и повтор
                           был бы обречён ещё до отправки. Возвращаем счётчик
                           кандидатов на шаг назад: install_next займёт новый
                           порт и поставит ТОТ ЖЕ план под него. */
                        if (t->next_plan > 0) { t->next_plan--; }
                        t->state = T_PLANNING;
                    } else if (t->transport == 6 && touched && !t->ver.local_limit &&
                               t->next_plan > 0 && t->next_plan > t->n_known &&
                               t->arm_hash && t->arm_hash == fnv1a(t->plans[t->next_plan - 1]) &&
                               s->dropped_seen == t->ver_dropped0 &&
                               t->ver.level >= D2K_VER_TRANSPORT &&
                               t->ver_arm_retries < SCHED_ARM_VERIFY_RETRIES &&
                               t->probes < sched_probe_cap(t)) {
                        t->ver_arm_retries++;
                        say(s, "по %s план %zu из замера: зонд не дошёл до приложения (%s) — "
                               "проверяю его ещё раз (%d из %d): маршрут к адресу бывает разный",
                            t->name, t->next_plan, t->ver.reason, t->ver_arm_retries,
                            SCHED_ARM_VERIFY_RETRIES);
                        trial_retire(s, t);
                        ver_close(t);
                        t->ver_seen = 0;
                        t->ver_ok = 0;
                        if (t->next_plan > 0) { t->next_plan--; }
                        t->state = T_PLANNING;
                    } else {
                        /* Транспорт, рукопожатие и даже «сервер что-то ответил» —
                           не доказательство (§4.2 и шапка d2k_verify.h). Кандидат
                           не виноват и не оправдан: он просто не показал
                           прикладного обмена, и в каталог не идёт ничего (§10). */
                        if(gate_try_composed(s,t,touched)) {moved++;continue;}
                        say(s, "по %s план %zu: зонд не дошёл до приложения (%s) — беру следующего кандидата",
                            t->name, t->next_plan, t->ver.reason);
                        if (!t->vol.rx_cut && ech_witness_rx_cut(t)) {
                            t->vol.rx_cut = 1;
                            t->vol.rx_at_kb = (int)(t->ver.body_bytes / 1024);
                            t->net_probing = net_whitelist_needs_probe(s, t);
                            t->rx_volume_candidate_pending = rx_ladder_pending(t);
                            say(s, "по %s под планом через принятый ECH ответ свидетеля %s "
                                   "оборвался около %d КБ — это объёмный обрыв; добавляю "
                                   "лестницу белого имени (fake-SNI + split)",
                                t->name, t->ech_origin, t->vol.rx_at_kb);
                        }
                        /* A measured arm is still a candidate in this context.
                           Only a completed, attributable experiment may unlock
                           fallback: missing execution/local failure is not a
                           failed network hypothesis. Keep cached plans first. */
                        if (t->transport == 6 && t->search_owned && !t->owned_fallback &&
                            t->own_first != 2 && t->next_plan > t->n_known &&
                            t->arm_hash && t->arm_hash == fnv1a(t->plans[t->next_plan-1]) &&
                            touched && !t->ver.local_limit &&
                            s->dropped_seen == t->ver_dropped0 &&
                            t->ver.level >= D2K_VER_TRANSPORT) {
                            /* ОПРОС, ОБОРВАННЫЙ НА ЭТОМ ПРИЁМЕ, ДОСПРАШИВАЕТСЯ —
                               И ТОЛЬКО ПОТОМ ПЕРЕБОР (поле 24.10.2026, см.
                               task.arm_refuted). Опрос кончается на первом
                               прошедшем вопросе, и «да» на нём остаётся «да»:
                               продолжать надо со СЛЕДУЮЩЕГО вопроса, а не с
                               чужого списка гипотез. */
                            if (arm_survey_resume(s, t)) {
                                /* researched сброшен: кандидаты кончатся —
                                   задача пойдёт новым замером, не перебором. */
                            } else {
                                t->owned_fallback = 1;
                                say(s, "по %s измеренный кандидат не подтвердился на применённом потоке — "
                                       "после оставшихся кандидатов продолжу запасной перебор", t->name);
                            }
                        }
                        /* Неуспех по НАШЕМУ пределу или нашей ошибке чтения (заголовки
                           длиннее предела, нет памяти) — не поведение линии и не
                           улика против плана семьи (задача 44, поле 03.10.2026:
                           web.whatsapp.com). */
                        if(t->family_fast==1 && touched && !t->ver.local_limit &&
                           s->dropped_seen==t->ver_dropped0 &&
                           t->ver.level>=D2K_VER_TRANSPORT) {
                            char failed_id[40]; uint8_t wire_id[D2K_PLAN_ID_LEN];
                            plan_ident(t->plans[t->next_plan-1],failed_id,sizeof failed_id,wire_id);
                            group_record(s,t,D2K_GROUP_PLAN_FAILED,failed_id,t->asked_shape,now_ms);
                        }
                        trial_retire(s, t);
                        ver_close(t);
                        t->state = T_PLANNING;
                    }
                }
            } else {
                d2k_ev own;
                memset(&own, 0, sizeof own);
                memcpy(own.low_ip, t->ver_flow.a_ip, sizeof own.low_ip);
                memcpy(own.high_ip, t->ver_flow.b_ip, sizeof own.high_ip);
                own.family = t->ver_flow.family;
                own.low_port = t->ver_flow.a_port;
                own.high_port = t->ver_flow.b_port;
                own.transport = t->ver_flow.transport;
                for (size_t k = 0; k < t->ver_seen; k++) {
                    if (ev_matches_flow(&own, &t->ver_early[k])) { t->ver_ok = 1; break; }
                }
                if (t->ver_ok) {
                    verify_confirm(s, t, now_ms);
                } else {
                    /* Применение могло ещё не доехать: событие — сообщение, а
                       не обязательство (d2k_ctl.h). Ждём его, держа сокет
                       зонда открытым. */
                    t->state = T_VERIFY_WAIT;
                    t->ver_until_ms = now_ms + SCHED_VERIFY_STEP_MS;
                    if (t->ver.replay_proof)
                        say(s, "по %s на повтор ECH-приветствия клиента пришёл ServerHello с "
                               "местного порта %u — жду применения плана к его потоку",
                            t->name, (unsigned)t->ver.local_port);
                    else if (t->ver.handshake_proof)
                        say(s, "по %s рукопожатие с ALPN клиента завершено с местного порта %u "
                               "— жду применения плана к его потоку",
                            t->name, (unsigned)t->ver.local_port);
                    else
                    say(s, "по %s зонд дошёл до приложения (%d) с местного порта %u "
                           "— жду применения плана к его потоку",
                        t->name, t->ver.status, (unsigned)t->ver.local_port);
                }
            }
            moved++;
        }

        if (t->state == T_VERIFY_WAIT) {
            if (t->ver_ok) {
                int cut = t->ver.level == D2K_VER_APPLICATION && t->ver.budget == D2K_BUDGET_CUT;
                if (cut && local_refusal_verdict(s, t) != 0) { /* наша неудача — не улика */ }
                else if (cut) budget_cut_reject(s, t, now_ms);
                else verify_confirm(s, t, now_ms);
                moved++;
            } else if (now_ms >= t->ver_until_ms) {
                if (s->dropped_seen != t->ver_dropped0 && t->probes < sched_probe_cap(t)) {
                    /* Связь теряла события с тех пор, как план встал. Значит
                       «применения не было» может означать «было, но событие о
                       нём не доехало», — а это разные вещи, и вторая не улика
                       против кандидата. Испытываем ЕГО ЖЕ ещё раз, а не
                       выбрасываем: повтор стоит одного зонда и ограничен общим
                       бюджетом зондов, а выброшенный рабочий план стоит
                       поиска целиком (ровно эта ошибка ловилась счётом потерь
                       и раньше). */
                    say(s, "по %s связь потеряла события (%u) — молчание не в счёт, "
                           "испытываю кандидата ещё раз",
                        t->name, (unsigned)(s->dropped_seen - t->ver_dropped0));
                    t->ver_dropped0 = s->dropped_seen;
                    trial_retire(s, t);
                    ver_close(t);
                    t->ver_seen = 0;
                    t->ver_ok = 0;
                    /* Та же причина, что и у соседней ветки: сокет с занятым
                       портом уже забран рабочим потоком, и новый зонд пришёл
                       бы с другого порта — мимо пробного плана. Ставим
                       кандидата заново, а не повторяем зонд вслепую. */
                    if (t->next_plan > 0) { t->next_plan--; }
                    t->state = T_PLANNING;
                } else if (local_refusal_verdict(s, t) != 0) {
                    /* Наша неудача — разбор общий с T_VERIFY, чтобы обе ветки
                       вели себя одинаково (0009, U2). */
                } else {
                    /* Зонд прошёл, а доказательства, что план тронул ЕГО
                       пакеты, нет. Засчитать это значило бы записать план по
                       обращению, которое, возможно, шло голым, — цель просто
                       открылась сама. Не измерено (§2.4), берём следующего. */
                    say(s, "по %s зонд прошёл, а применения этого плана к его потоку не было "
                           "— не засчитано, беру следующего кандидата",
                        t->name);
                    trial_retire(s, t);
                    ver_close(t);
                    t->state = T_PLANNING;
                }
                moved++;
            }
        }

        if (t->state == T_TRIAL_SETTLE) {
            if (t->trial_acked || now_ms >= t->trial_until_ms) {
                t->trial_acked = 0;
                t->exec_probed++;
                t->state = T_VERIFY;
                if (start_worker(s, t, JOB_VERIFY) != 0) {
                    /* Потока нет — испытать нечем. Это «не измерено»:
                       следующий круг тика возьмёт следующего кандидата. */
                    say(s, "по %s поток испытания не завёлся", t->name);
                    trial_retire(s, t);
                    t->state = T_PLANNING;
                } else if (t->own_first == 2 && t->next_plan > 0 && t->next_plan <= 32) {
                    /* Не запустившийся зонд не оставляет отрицательную
                       историю в остывании: опыта с этим планом ещё нет. */
                    t->own_probed |= 1u << (t->next_plan - 1);
                }
                moved++;
            }
            continue;
        }

        if (t->state == T_PLANNING) {
            if(synthesis_resume(s,t)){moved++;continue;}
            if (t->tried_full == 1) {
                t->tried_full = 2;
                say(s, "по %s список испытанных планов полон (%d) — дальше уже испытанный "
                       "план может быть предложен повторно", t->name, SCHED_TRIED_MAX);
            }
            if (now_ms < t->rx_retry_after_ms) continue;
            int inst = install_next(s, t);
            if (inst == -2) {
                /* ЛОКАЛЬНЫЙ ОТКАЗ, А НЕ «ПЛАНЫ КОНЧИЛИСЬ» (0010, R1). Порт для
                   изоляции не занялся — это про нашу машину, а не про коробку.
                   Ни исследование заводить, ни цель хоронить нельзя: очередь
                   кандидатов цела, пробуем её на следующем круге. */
                moved++;
                continue;
            }
            if (inst != 0) {
                if (t->own_first == 2) {
                    /* Порция кончилась: следующие свои планы по свежести,
                       пока они есть (задача 49). Испытанные на проводе — в
                       tried, как в own_first_continue. */
                    for (size_t k = 0; k < t->n_plans && k < 32; k++) {
                        if (!(t->own_probed & (1u << k))) continue;
                        tried_add(t, (uint32_t)fnv1a(t->plans[k]));
                        own_tried_add(t, (uint32_t)fnv1a(t->plans[k]));
                    }
                    t->own_probed = 0;
                    trial_retire(s, t);
                    ver_close(t);
                    /* Фаза оборвана не концом своих планов (повторное ревью,
                       Minor 1–2): кончился бюджет кандидатов или память
                       own_seen. Сказать прямо, сколько НЕ испытано, и не
                       называть их «не подтвердившимися». */
                    if (t->probes >= sched_probe_cap(t) || t->own_seen_full) {
                        size_t left = (t->next_plan < t->n_plans ? t->n_plans - t->next_plan : 0) +
                                      own_first_plans(s, t, 2);
                        say(s, "по %s свои подтверждённые планы испытаны не все: %s; "
                               "НЕ испытано %zu — продолжаю полный замер донора",
                            t->name, t->own_seen_full
                                ? "их больше, чем помнит фаза своих планов"
                                : "кончился бюджет кандидатов задачи", left);
                        own_first_continue(s, t);
                        moved++;
                        continue;
                    }
                    size_t more = own_first_plans(s, t, 1);
                    if (more > 0) {
                        t->n_plans = t->n_known = more;
                        t->next_plan = 0;
                        t->exec_refused = t->exec_probed = 0;
                        t->rx_phase = 0;
                        say(s, "по %s следующие свои подтверждённые планы до полного замера: %zu",
                            t->name, more);
                        moved++;
                        continue;
                    }
                    /* Свои планы кончились (или все отвергнуты исполнителем —
                       это местный отказ, не повод хоронить поиск). */
                    say(s, "по %s свои подтверждённые планы не подтвердились — "
                           "продолжаю полный замер донора", t->name);
                    own_first_continue(s, t);
                    moved++;
                    continue;
                }
                if (t->exec_refused > 0 && t->exec_probed == 0) {
                    /* Задача 19: ни один кандидат не дошёл до провода —
                       все отвергнуты исполнителем. Это не блокировка и не
                       «невозможно»: опыта не было. Отдых — как у неполного
                       поиска (cooldown kind 2). */
                    say(s, "по %s все кандидаты отвергнуты исполнителем (%u) — местный "
                           "отказ: опыта не было, это не блокировка; новый поиск отложен "
                           "на %lld мин",
                        t->name, t->exec_refused,
                        (long long)(SCHED_INCOMPLETE_BACKOFF_MS / 60000));
                    trial_retire(s, t);
                    cooldown_record(s, t, 2);
                    task_fail(s, t, now_ms);
                    moved++;
                    continue;
                }
                if(t->family_fast==1) {
                    trial_retire(s, t);
                    /* Этап 23: семейные планы испытаны и провалились — в tried,
                       иначе фаза своих планов (own_first_plans) и уступка
                       замера предложат те же тексты снова без новой причины
                       (поле: 680fbe00/0df173dd/99ddace7 по второму разу). */
                    for (size_t k = 0; k < t->n_plans; k++) tried_add(t, (uint32_t)fnv1a(t->plans[k]));
                    t->family_fast=2; t->n_plans=t->n_known=t->next_plan=0;
                    t->exec_refused=t->exec_probed=0;
                    t->box_id[0]=0; t->state=T_ASKING;
                    say(s,"по %s собственные планы семейства не подтвердились; теперь выполняю прямую диагностику",t->name);
                    if(start_worker(s,t,JOB_CLASSIFY)!=0) task_fail(s,t,now_ms);
                    moved++; continue;
                }
                if (t->rx_bootstrap_only && !t->vol.rx_cut) {
                    /* Прямой зонд не дошёл до TLS, свой план цели тоже — про
                       коробку ещё не сказано ничего. Дальше полный замер
                       донора, а не отказ и не запасной список (поле
                       14.10.2026, www.bbc.com). */
                    int other_family = t->family_reuse == 2;
                    trial_retire(s, t);
                    if (other_family) t->family_reuse = 3;
                    t->rx_bootstrap_only = 0;
                    t->exec_refused = t->exec_probed = 0;
                    t->skip_volume_once = 1;
                    t->n_plans = t->n_known = t->next_plan = 0;
                    t->box_id[0] = '\0';
                    t->state = T_ASKING;
                    if (other_family)
                        say(s, "по %s план другого семейства не подтвердился; "
                               "продолжаю исходный поиск без повторения объёмной базы", t->name);
                    else
                        say(s, "по %s свой план не подтвердился, а прямой зонд не дошёл до TLS; "
                               "перебор не запускаю — продолжаю полным замером", t->name);
                    if (start_worker(s, t, JOB_CLASSIFY) != 0) task_fail(s, t, now_ms);
                    moved++; continue;
                }
                if (t->n_known > 0 && t->cached_measure_valid) {
                    d2k_vres measured = t->res;
                    t->cached_measure_valid = 0;
                    trial_retire(s, t);
                    /* ВОПРОСЫ О СВОЙСТВАХ — И ПОСЛЕ ГОТОВЫХ ПЛАНОВ (задача 37, I1).
                       Ветка узнанной коробки входила в испытание, минуя
                       вопросы; не помогли её планы — «выведенным из замера»
                       оказывался синтез по ПУСТОМУ вектору (everythingPlan).
                       Измеритель без владения поиском (nft-роутер без сырого
                       сокета) ответа «чем брать» не принёс — его дают
                       вопросы, как на пути без узнанной коробки. Кандидаты
                       выводятся из ответов, когда опрос кончится. */
                    if (measured.verdict == D2K_V_OPAQUE && t->transport == 6 &&
                        !measured.have_arm && !measured.program_len && !measured.owns_search) {
                        say(s, "по %s готовые планы не помогли; вердикт: %s — "
                               "спрашиваю коробку о свойствах", t->name,
                            verdict_name(measured.verdict));
                        memset(&t->props, 0, sizeof t->props);
                        t->prop_q = -1;
                        t->props_asked = 0;
                        t->n_known = 0;
                        if (prop_send_next(s, t, now_ms) == 0) {
                            moved++;
                            continue;
                        }
                        prop_finish(s, t);
                    }
                    verdict_to_plans(s, t, &measured);
                    if (t->n_plans == 0) {
                        if (partial_finish(s, t, now_ms)) { moved++; continue; }
                        say(s, "по %s готовые планы не помогли; прямое измерение "
                               "не дало новых кандидатов", t->name);
                        cooldown_record(s, t, 2);
                        say(s, "по %s после исчерпания кандидатов новый поиск отложен на %lld мин",
                            t->name, (long long)(SCHED_INCOMPLETE_BACKOFF_MS / 60000));
                        task_fail(s, t, now_ms);
                        moved++;
                        continue;
                    }
                    t->state = T_PLANNING;
                    say(s, "по %s готовые планы не помогли — проверяю кандидаты "
                           "из уже выполненного прямого замера", t->name);
                    moved++;
                    continue;
                }
                if (!t->researched) {
                    /* Exhausted known plans: remove the trial before any
                       baseline measurement. Research happens at most once. */
                    /* Точно, своим ключом: широкая DEL_NAME сняла бы и
                       подтверждённые записи имени (задача 20). */
                    trial_retire(s, t);
                    t->researched = 1;
                    t->box_id[0] = '\0';
                    t->state = T_ASKING;
                    const uint8_t *qb; size_t ql; uint64_t qseq;
                    if (!t->reasked && !t->trig_snapped &&
                        quic_own_initial(s, t, &qb, &ql, &qseq)) {
                        remeasure_snapped(s, t, qb, ql);
                        moved++;
                        continue;
                    }
                    /* ПРИВЕТСТВИЯ ПОДБИРАЮТСЯ ЗАНОВО, А НЕ БЕРУТСЯ КАКИЕ ЕСТЬ.
                     *
                     * Сюда задача приходит двумя дорогами. Прежняя — через
                     * успешный fill_hellos, и тогда оба приветствия на месте.
                     * Новая (QUIC, коробка узнана, снимка ещё не было) входит
                     * в T_PLANNING БЕЗ приветствий вовсе: испытать готовый
                     * план ими не нужно, зонд QUIC ведёт рукопожатие сам.
                     * Но ЗАМЕР без них невозможен, и на живой линии 13.09.2026
                     * это вышло ровно так: по scontent-arn2-1.cdninstagram.com
                     * снимок приехал через секунду после входа в T_PLANNING, а
                     * замер стартовал со старым пустым контролем и закончился
                     * «вердикта нет (нет контрольного имени — базовая живость
                     * не проверена)» — то есть вопрос коробке не задавался
                     * вовсе, а восемь кандидатов ушли в никуда.
                     *
                     * Повторный вызов дешёв и идемпотентен: заполняются только
                     * пустые поля (см. fill_hellos). Отказ означает, что
                     * мерить по-прежнему нечем, и честнее сказать это, чем
                     * задать вопрос пустотой. */
                    if (fill_hellos(s, t) != 0) {
                        say(s, "по %s готовые планы не помогли, а мерить нечем: "
                               "приветствия для этой цели так и нет", t->name);
                        task_fail(s, t, now_ms);
                        moved++;
                        continue;
                    }
                    if (start_worker(s, t, JOB_CLASSIFY) == 0) {
                        /* Одна дорога, два повода: готовых планов не хватило —
                           или опрос оборвался на опровергнутом приёме. Второй
                           повод называется прямо: иначе в журнале «готовые
                           планы не помогли» стоит там, где готовых планов не
                           было вовсе (поле 24.10.2026). */
                        if (t->n_arm_refuted > 0)
                            say(s, "по %s доспрашиваю опрос: опровергнуто приёмов %d, "
                                   "уже отвеченные вопросы снимает знание о коробке",
                                t->name, t->n_arm_refuted);
                        else
                            say(s, "по %s готовые планы не помогли — начинаю новый замер", t->name);
                        moved++;
                        continue;
                    }
                }
                if (t->probes >= sched_probe_cap(t) && t->next_plan < t->n_plans) {
                    /* Кончился БЮДЖЕТ, а не кандидаты (задача 24, D2K_SPEC §3):
                       поиск не завершён, и это не «обхода нет». Только пока
                       кандидаты ЕСТЬ: если они кончились на том же зонде,
                       что и бюджет, правдивее «планы исчерпаны». */
                    if (partial_finish(s, t, now_ms)) { moved++; continue; }
                    say(s, "по %s бюджет зондов исчерпан (зондов %d из %d) — поиск не "
                           "завершён, это не «обхода нет»; цель отдыхает",
                        t->name, t->probes, sched_probe_cap(t));
                    cooldown_record(s, t, 2);
                    say(s, "по %s после исчерпания бюджета зондов новый поиск отложен на %lld мин",
                        t->name, (long long)(SCHED_INCOMPLETE_BACKOFF_MS / 60000));
                    task_fail(s, t, now_ms);
                    moved++;
                    continue;
                }
                if (partial_finish(s, t, now_ms)) { moved++; continue; }
                /* ПОДБОР БЕЛОГО ИМЕНИ СЕТИ ДОВЕДЁН ДО КОНЦА, НАХОДКИ НЕТ (поле
                   10.10.2026). Все имена списка опробованы приманкой, ни одно
                   не сняло RX-обрыв — честный исход «не найдено», с меткой
                   времени: не перебираем список заново на каждой цели, пока
                   сеть не сменится. Бюджет обрыва (не полный проход списка)
                   сюда не попадает — там net_probe_next < длины списка. */
                if (t->net_probing && t->net_probe_next >= d2k_net_whitelist_count() &&
                    s->cat && !s->cat->net.searched) {
                    s->cat->net.searched = 1;
                    s->cat->net.name[0] = '\0';
                    s->cat->net.confirmed_at = wall_s(s, now_ms);
                    s->cat->revision++;
                    s->sync_pending = 1;
                    t->net_probing = 0;
                    say(s, "по %s белое имя сети не найдено: ни одно из %zu имён списка "
                           "не сняло RX-обрыв — запоминаю исход, подбор не повторяю",
                        t->name, d2k_net_whitelist_count());
                }
                if (t->fb_queue) {
                    say(s, "по %s выведенные из замера и запасные планы исчерпаны "
                           "(зондов %d) — цель отдыхает", t->name, t->probes);
                } else {
                    say(s, "по %s выведенные планы исчерпаны (зондов %d) — цель отдыхает. "
                           "Это не «перебор кончился»: планы выводятся из замера, и если "
                           "измерить было нечем, их и нет",
                        t->name, t->probes);
                }
                cooldown_record(s, t, 2);
                say(s, "по %s после исчерпания кандидатов новый поиск отложен на 10 мин",
                    t->name);
                /* Поле 06.10, googlevideo: узел, на котором не помог ни план
                   семейства, ни собственный поиск, недоступен — это не голос
                   против плана. Его отказы выкидываются из семейства. */
                if (!t->by_addr && s->cat->groups &&
                    d2k_group_forget(s->cat->groups, t->name, t->transport, t->family) > 0) {
                    s->cat->revision++; s->sync_pending = 1;
                    say(s, "по %s не помог ни общий план семейства, ни свой — узел недоступен, "
                           "его отказы из семейства убраны", t->name);
                }
                task_fail(s, t, now_ms);
                moved++;
                continue;
            }
            /* Кандидат стоит — испытываем его САМИ, не дожидаясь, пока цель
               откроет человек (см. шапку файла). */
            t->ver_seen = 0;
            t->ver_ok = 0;
            ver_close(t);
            memset(&t->ver, 0, sizeof t->ver);
            t->ver.fd = -1;
            t->ver_dropped0 = s->dropped_seen;
            /* Счёт повторов — ПО КАНДИДАТУ, а не по установке: повтор сам
               идёт через установку, и сброс здесь обнулял бы его же. */
            if (t->ver_retry_for != t->next_plan) {
                t->ver_retry_for = t->next_plan;
                t->ver_bare_retries = 0;
                t->ver_arm_retries = 0;
            }
            /* СНАЧАЛА ПЛАН ДОЛЖЕН ДОЙТИ, ПОТОМ ЗОНД — см. SCHED_TRIAL_SETTLE_MS. */
            t->trial_acked = 0;
            t->trial_until_ms = now_ms + SCHED_TRIAL_SETTLE_MS;
            t->state = T_TRIAL_SETTLE;
            /* Порт зонда — в строке НАРОЧНО: пробный план ставится только для
               него, и расхождение «поставили под порт P, зонд ушёл с Q»
               иначе не видно ничем, а стоит оно выброшенным успехом. */
            /* Id плана — тот же, что назовёт подтверждение (plan_ident):
               иначе «план 1 из 8» по журналу не опознать (поле 10.10.2026). */
            char trial_id[40];
            uint8_t trial_wire[D2K_PLAN_ID_LEN];
            plan_ident(t->plans[t->next_plan - 1], trial_id, sizeof trial_id, trial_wire);
            say(s, "по %s поставил план %zu из %zu (%s, порт зонда %u) — испытываю его собственным зондом",
                t->name, t->next_plan, t->n_plans, trial_id,
                (unsigned)ntohs(t->probe_sport_be));
            moved++;
        }
    }
    quic_yield_tick(s,now_ms);
    moved += queued_release(s, now_ms);
    return moved;
}
