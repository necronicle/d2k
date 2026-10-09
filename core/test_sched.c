/* test_sched.c — развилка по транспорту и то, что вокруг неё.
 *
 * ГЛАВНАЯ ПРОВЕРКА ЗАДАЧИ 5: подозрение по TCP уходит в дерево вердиктов,
 * подозрение по UDP — в вопросник QUIC, и никогда наоборот. Ради этого шва
 * переписан план, и он же — единственное место, где две половины движка
 * встречаются.
 *
 * СЕТИ ЗДЕСЬ НЕТ. Сетевые оракулы подменены через d2k_sched_tcp_hook,
 * d2k_sched_quic_hook, d2k_sched_vol_hook и d2k_sched_ver_hook — тот же приём,
 * что d2k_mark_hook (d2k_meas.h), и по той же причине: тест обязан утверждать
 * развилку одинаково и на машине разработки, и на роутере, а не зависеть от
 * того, что сегодня отвечает настоящий instagram.com. Датапат подменён обычным
 * socketpair: планировщик пишет в него команды, тест их читает.
 *
 * ЧТО СЧИТАЕТСЯ ПОДТВЕРЖДЕНИЕМ. Две вещи вместе, и ни одна по отдельности:
 * СОБСТВЕННЫЙ зонд планировщика дошёл до ответа приложения (D2K_VER_APPLICATION
 * от подменённого d2k_sched_ver_hook) И датапат сказал, что ИМЕННО ЭТОТ план
 * применился к ключу ИМЕННО ЕГО потока (D2K_EV_APPLIED с идентификатором
 * плана). Событие обмена с внешним типом записи 23 подтверждением больше не
 * является вовсе: в TLS 1.3 им едет и второй полёт рукопожатия (RFC 8446
 * §5.2). Идентификатор плана тест не выдумывает, а ЧИТАЕТ С ПРОВОДА — из той
 * самой команды, которую планировщик только что отправил (см. last_plan_id
 * ниже): иначе он проверял бы своё представление о связи, а не связь.
 *
 * ПОДОЗРЕНИЕ НЕ НЕСЁТ ИМЕНИ. На проводе D2K_EV_SUSPECT — это ключ потока и код
 * причины, и только (core/link.c, разбор события; datapath/include/d2k_ctl.h).
 * Имя цели приходит РАНЬШЕ, отдельным D2K_EV_HELLO, и планировщик обязан их
 * связать по ключу. Go-сторона делает ровно это (controller.go, Handle:
 * `c.remember(ev.Key, ev.Name)` на EvHello). Поэтому каждый случай ниже сперва
 * шлёт приветствие и лишь затем подозрение: тест, который клал бы имя прямо в
 * подозрение, проверял бы путь, которого на проводе не существует. */
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700 /* strptime under -std=c99 on glibc/musl */
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>

#include "d2k_compose_internal.h"
#include "d2k_plantlv.h"
#include "d2k_quichello.h"
#include "d2k_sched.h"
#include "d2k_quic.h"
#include "test_quic_vector.h"
#include "d2k_tls13.h"
#include "d2k_meas.h"

/* Что планировщик говорил о себе. Нужен не для красоты: узнавание коробки
   снаружи иначе НЕ отличить от совпадения имени — имя коробки выводится из
   отпечатка, поэтому вторая цель с тем же отпечатком попадёт в ту же запись
   каталога и БЕЗ узнавания. Отличает их ровно одно: пришли ли готовые планы
   узнанной коробки в кандидаты. Про это планировщик говорит, и только по
   этому проверка честна (первая редакция этой проверки смотрела на число
   коробок и проходила даже при выключенном d2k_catalog_match). */
static char saidbuf[1 << 18];
static void collect_say(void *ctx, const char *line) {
    (void)ctx;
    size_t n = strlen(saidbuf);
    snprintf(saidbuf + n, sizeof saidbuf - n, "%s\n", line);
}
static int said(const char *needle) { return strstr(saidbuf, needle) != NULL; }

static int fails;
#define CHECK(cond, msg) do { if (!(cond)) { printf("ПРОВАЛ: %s\n", (msg)); fails++; } } while (0)

/* --- подменённые оракулы ------------------------------------------------- */

static int tcp_calls, quic_calls;
static int voice_calls;
static int voice_discovery_fixture;
static int voice_seen_known;
static int voice_known_fails;
static uint32_t voice_target_ip;
static uint16_t voice_target_port;
static uint32_t voice_target_wait;
static int voice_candidate_seen;
static d2k_verdict tcp_answer = D2K_V_OPAQUE;
static int tcp_owns_search;
static int tcp_found_arm;
static size_t tcp_last_wire;
static d2k_verdict quic_answer = D2K_V_OPAQUE;
/* Вход плеча «разрез CRYPTO клиенту неприменим», с которым позвали вопросник
   (финальное ревью core, I1); -1 — не звали. */
static int quic_last_split_unfit = -1;
static char tcp_last_ip[64], quic_last_sni[256], quic_last_ip[64];
static uint8_t quic_seen_triggers[2][2048];
static size_t quic_seen_trigger_lens[2];
static char quic_seen_ips[2][64], quic_seen_snis[2][256];
static char quic_seen_targets[2][256], quic_seen_controls[2][256];
static pthread_mutex_t snapshot_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t snapshot_cv = PTHREAD_COND_INITIALIZER;
static int snapshot_enabled, snapshot_entered, snapshot_release, snapshot_ok;
/* Задача 48: подменённый измеритель сообщает ход (два вопроса по 500 зондов —
   число заведомо больше бюджета кандидатов, чтобы утечку нельзя было спутать
   со счётом проверки),
   как настоящий через on_obs, и только потом ждёт отпуска на snapshot_cv. */
static int tcp_progress_notes;
static int quic_progress_notes; /* задача 49: то же для QUIC */
static int ver_snapshot_enabled, ver_snapshot_entered, ver_snapshot_release;

static d2k_voice_res stub_voice(const d2k_voice_opt *opt) {
    d2k_voice_res r;
    memset(&r, 0, sizeof r);
    voice_calls++;
    if(opt){voice_target_ip=opt->ip;voice_target_port=opt->port;voice_target_wait=opt->wait_ms;voice_candidate_seen=opt->candidate_discovery_prefix!=NULL;}
    if (opt && opt->known_discovery_prefix) {
        voice_seen_known=1;
        if (voice_known_fails) { r.verdict=voice_known_fails==2?D2K_VOICE_CLEAR:D2K_VOICE_UNMEASURED; r.known_prefix_failed=1; }
        return r;
    }
    if (!opt || opt->mark != 0x2d || !opt->flow_port_a || !opt->flow_port_b ||
        (voice_discovery_fixture && !opt->discovery)) { return r; }
    r.verdict = D2K_VOICE_BLOCKED;
    r.ip = opt->flow_ip_a;
    r.port = opt->flow_port_a;
    r.client_ip = opt->flow_ip_b;
    r.client_port = opt->flow_port_b;
    r.marked = 1;
    snprintf(r.fake_arm, sizeof r.fake_arm, "active_discord_udp");
    memcpy(r.arm_bytes, "\xa1\xb2\xc3\xd4", 4);
    r.arm_len = 4;
    r.arm_copies = 6;
    r.discovery_verified = voice_discovery_fixture;
    if (voice_discovery_fixture) {
        memset(r.arm_bytes,0,20);
        memcpy(r.arm_bytes,"\x00\x01\x00\x00\x21\x12\xa4\x42",8);
        r.arm_len=20; r.arm_copies=1;
    }
    return r;
}

/* Сколько измеритель ждёт просьбы бросить, прежде чем сдаться сам. Пять
   секунд — не «достаточно», а «заведомо больше», чем позволено ждать циклу:
   если отмена не дойдёт, тест не повиснет навсегда, а честно покажет, во
   сколько обошлось ожидание. */
#define STUB_BLOCK_MS 5000
static int tcp_block_until_stop;
static int tcp_wait_until_stop;
static int tcp_release_waiters;
static int tcp_saw_stop;
static int tcp_stop_count;
static uint8_t tcp_last_trig[2048];

static d2k_vres stub_tcp(const char *ip, uint16_t port, d2k_hello trigger,
                         d2k_hello control, uint32_t mark, int repeats,
                         uint32_t gap_us, uint32_t wait_ms,
                         const volatile sig_atomic_t *stop) {
    (void)port; (void)trigger; (void)control; (void)mark;
    (void)repeats; (void)gap_us; (void)wait_ms;
    tcp_calls++;
    tcp_last_wire = trigger.len;
    if (trigger.bytes && trigger.len <= sizeof tcp_last_trig)
        memcpy(tcp_last_trig, trigger.bytes, trigger.len);
    if (tcp_wait_until_stop) {
        while (!(stop && *stop) && !tcp_release_waiters) { usleep(1000); }
        if (stop && *stop) {
            tcp_saw_stop = 1;
            tcp_stop_count++;
        }
    }
    if (tcp_block_until_stop) {
        /* Так ведёт себя настоящий сетевой оракул: он в сети, и бросить его
           может только просьба. Без неё цикл ждал бы его до конца. */
        for (int i = 0; i < STUB_BLOCK_MS; i++) {
            if (stop && *stop) { tcp_saw_stop = 1; break; }
            usleep(1000);
        }
    }
    snprintf(tcp_last_ip, sizeof tcp_last_ip, "%s", ip ? ip : "");
    d2k_vres r;
    memset(&r, 0, sizeof r);
    r.verdict = tcp_answer;
    r.owns_search = tcp_owns_search;
    r.split_pos = tcp_owns_search ? 1 : 0;
    r.split_gap_us = 60000;
    if (tcp_found_arm) {
        r.have_arm = 1; r.arm.badsum = 1;
        r.arm_input.trigger_len = trigger.len;
        (void)d2k_hello_sni(trigger.bytes, trigger.len, &r.arm_input.sni_off, &r.arm_input.sni_len);
    }
    if (tcp_progress_notes) {
        d2k_sched_progress_note("split", 0, 500);
        d2k_sched_progress_note("poison:seqovl-1", 0, 500);
        r.probes = 1006; /* итог прогона больше хода: ответное направление хода не шлёт */
    }
    if (snapshot_enabled) {
        uint8_t before[2048];
        memcpy(before, trigger.bytes, trigger.len);
        pthread_mutex_lock(&snapshot_mu);
        snapshot_entered = 1;
        pthread_cond_broadcast(&snapshot_cv);
        while (!snapshot_release) { pthread_cond_wait(&snapshot_cv, &snapshot_mu); }
        snapshot_ok = memcmp(before, trigger.bytes, trigger.len) == 0;
        pthread_mutex_unlock(&snapshot_mu);
    }
    snprintf(r.reason, sizeof r.reason, "подменённое дерево вердиктов");
    return r;
}

/* Проба на объём подменена: иначе планировщик гонял бы настоящую лестницу
   HTTP-запросов к стенду, который TLS не умеет, и тест мерил бы это. */
static int vol_calls;
static volatile int vol_hold, vol_entered;
static size_t vol_last_wire;
static d2k_vol_verdict vol_answer = D2K_VOL_PASSED;
static int vol_rx_cut;
static int vol_at_kb = 20;
static int vol_rx_at_kb = 24;
static int vol_rx_tls_unavailable;
static int vol_direct_complete;
static int resource_fixture;
static int resource_volume_calls, resource_verify_calls;

static int vol_rx_packets; /* задача 55: пакеты на обрыве identity */
static int vol_rx_packet_only; /* gzip оборван на том же бюджете пакетов */
static d2k_vol_result stub_vol(const char *ip, uint16_t port, const char *sni,
                               int plain, int tls12, size_t hello_wire,
                               uint32_t mark) {
    (void)ip; (void)port; (void)sni; (void)plain; (void)tls12;
    (void)mark;
    vol_calls++;
    vol_last_wire = hello_wire;
    /* Задача 31: проба объёма «в сети», пока тест не отпустит, — чтобы
       снимок клиента пришёл именно во время объёмного шага. */
    vol_entered = 1;
    while (vol_hold) { usleep(1000); }
    d2k_vol_result r;
    memset(&r, 0, sizeof r);
    r.verdict = vol_answer;
    r.at_kb = vol_at_kb;
    r.rx_cut = vol_rx_cut;
    r.rx_tls_unavailable = vol_rx_tls_unavailable;
    r.rx_direct_complete = vol_direct_complete;
    r.rx_at_kb = vol_rx_at_kb;
    r.rx_cut_packets = vol_rx_cut ? vol_rx_packets : 0;
    r.rx_expected_kb = 96;
    r.rx_compressed_complete = vol_rx_cut && !vol_rx_packet_only;
    if (resource_fixture) {
        r.n_resources = 1;
        strcpy(r.resources[0].host, "assets.example");
        strcpy(r.resources[0].path, "/public/app.min.css");
    }
    snprintf(r.reason, sizeof r.reason, "подменённая проба объёма");
    return r;
}

/* Подменённый зонд подтверждения. Уровень задаёт тест; местный порт — тоже,
   потому что планировщик сверяет событие применения со СВОИМ потоком, а
   местный порт настоящего зонда назначает ядро. ver_fail_first позволяет
   «провалить» первые обращения: так проверяется, что очередь кандидатов
   движется сама, без пользователя. */
static int ver_calls;
static int ver_fail_first;
static int ver_local_limit; /* неуспех зонда из-за нашего предела чтения (задача 44) */
static int ver_app_after_tcp_search;
static uint8_t ver_last_transport;
static d2k_ver_level ver_answer = D2K_VER_APPLICATION;
static uint16_t ver_answer_port;
static uint8_t ver_local_ip4[4] = {192, 168, 1, 67};
static int mark_calls;
static uint32_t last_mark;

static int stub_mark(int fd, uint32_t mark) {
    (void)fd;
    mark_calls++;
    last_mark = mark;
    return 0;
}

/* Подменённый подбор плеча QUIC: настоящий ходит в сеть десятками опытов, а
   тест обязан утверждать поведение планировщика, не выходя наружу. */
static d2k_quic_arm_kind arm_kind = D2K_QA_BLOB;
/* Свойства коробки, которые подменённый вопросник «измерил» (d2k_vres.qprops). */
static d2k_quic_props quic_props_answer;
static int arm_calls;
static int arm_fragment_shape;

/* Занятие порта всегда неудачно — инъекция отказа для 0010 R1. */
static int stub_bind_fail(uint8_t transport, uint8_t family, int *out_fd, uint16_t *sport_be) {
    (void)transport;
    (void)family;
    if (out_fd) { *out_fd = -1; }
    if (sport_be) { *sport_be = 0; }
    return -1;
}

static d2k_quic_arm stub_arm(const char *ip, uint16_t port, const char *sni,
                             const char *decoy_sni, d2k_hello trigger, uint32_t mark) {
    (void)ip; (void)port; (void)sni; (void)decoy_sni; (void)trigger; (void)mark;
    arm_calls++;
    d2k_quic_arm a;
    memset(&a, 0, sizeof a);
    a.kind = arm_kind;
    a.original = 1;
    a.len = 4;
    memcpy(a.bytes, "\x41\x42\x43\x44", a.len);
    a.copies = 6;
    a.ttl = 3;
    a.probes = 4;
    if (arm_kind == D2K_QA_SPLIT) {
        /* Ответ вопроса стратегии «разрез CRYPTO»: план без блоба. */
        a.len = 0; a.copies = 0; a.ttl = 0;
        a.strategy = D2K_QS_SPLIT;
    }
    if(arm_fragment_shape) {
        a.frag_kind=arm_fragment_shape;a.frag_survives=D2K_PROP_YES;
        if(arm_kind==D2K_QA_FRAG){a.len=0;a.copies=0;a.ttl=0;}
    }
    snprintf(a.reason, sizeof a.reason, "подменённый подбор");
    return a;
}

static size_t ver_last_wire;

/* Что подменённый зонд говорит про имя сервера: -1 «сказать нечего» (так
   ведёт себя стенд без сертификата), 0 — измеренное несовпадение, 1 —
   совпадение. */
static int ver_name_ok = -1;

/* Умеет ли подменённый зонд такой транспорт. Ноль — умеет (так он вёл себя
   всегда), единица — «не про кандидата, а про транспорт». */
static int ver_unsupported;
static int ver_cloudflare_challenge;

/* Сокет зонда приходит УЖЕ ЗАНЯТЫМ (под его порт поставлен пробный план).
   Подменённый зонд в сеть не ходит, но владение обязан взять: иначе каждый
   опыт течёт дескриптором, и тест упрётся в их предел. */
static int ver_last_fd = -2;
static int ver_socket_family;
static uint8_t ver_last_shape;

/* ЗАДАЧА 55: исход проверки бюджета потока по номеру обращения (1..n) и
   бюджет, с которым зонд позван (поточная настройка d2k_verify). Пусто —
   проверка «не просилась» (0), как у прежних тестов. */
static int ver_budget_seq[8];
static int ver_budget_n;
static unsigned ver_budget_seen[8];
static int ver_budget_status = 200;
static int ver_fail_after; /* обращения после этого номера — без приложения (0 — нет) */

static d2k_ver_result stub_ver(int use_fd, const char *ip, uint16_t port, uint8_t transport,
                               const char *sni, int deadline_ms, size_t hello_wire,
                               uint8_t client_shape) {
    ver_last_fd = use_fd;
    uint8_t routed_local6[16] = {0};
    ver_socket_family = 0;
    if (use_fd >= 0) {
        struct sockaddr_storage local;
        socklen_t n = sizeof local;
        if (getsockname(use_fd, (struct sockaddr *)&local, &n) == 0) {
            ver_socket_family = local.ss_family;
            if (local.ss_family == AF_INET6) {
                const struct sockaddr_in6 *p = (const struct sockaddr_in6 *)&local;
                memcpy(routed_local6, &p->sin6_addr, 16);
            }
        }
    }
    if (use_fd >= 0) { close(use_fd); }
    (void)ip; (void)port; (void)sni; (void)deadline_ms;
    ver_last_shape = client_shape;
    ver_last_wire = hello_wire;
    ver_calls++;
    ver_last_transport = transport;
    d2k_ver_result r;
    memset(&r, 0, sizeof r);
    /* «Сказать нечего», а не «чужое имя»: ноль здесь значил бы ИЗМЕРЕННОЕ
       несовпадение, и обнуление структуры молча отменяло бы все
       подтверждения теста. */
    r.name_ok = ver_name_ok;
    r.unsupported = ver_unsupported;
    r.cloudflare_challenge = ver_cloudflare_challenge;
    /* Сокета нет вовсе: ver_close планировщика на отрицательном дескрипторе
       ничего не закрывает, и чужой дескриптор тест не теряет. */
    r.fd = -1;
    r.level = (ver_calls <= ver_fail_first ||
               (ver_fail_after && ver_calls > ver_fail_after) ||
               (ver_app_after_tcp_search && tcp_calls == 0))
                  ? D2K_VER_HANDSHAKE : ver_answer;
    r.status = (r.level == D2K_VER_APPLICATION) ? 200 : 0;
    r.local_limit = r.level == D2K_VER_APPLICATION ? 0 : ver_local_limit;
    if (ver_calls >= 1 && ver_calls <= 8) ver_budget_seen[ver_calls - 1] = d2k_verify_budget_get();
    if (r.level == D2K_VER_APPLICATION && ver_calls >= 1 && ver_calls <= ver_budget_n) {
        unsigned b = d2k_verify_budget_get();
        r.status = ver_budget_status;
        r.budget = ver_budget_seq[ver_calls - 1];
        r.budget_need = 2 * b;
        r.budget_packets = r.budget == D2K_BUDGET_PASSED ? 2 * b : r.budget == D2K_BUDGET_CUT ? b : 9;
        r.budget_requests = r.budget == D2K_BUDGET_NOT_APPLICABLE ? 1 : 6;
        snprintf(r.budget_note, sizeof r.budget_note, "подменённый бюджет %d", r.budget);
    }
    /* Тот же местный конец, что в ключах событий этого теста (ev_hello). */
    memcpy(r.local_ip4, ver_local_ip4, sizeof r.local_ip4);
    r.family = ver_socket_family == AF_INET6 ? 6 : 4;
    if (r.family == 6) {
        CHECK(inet_pton(AF_INET6, "2001:db8::2", r.local_addr) == 1, "verifier native local fixture");
        uint8_t nonzero = 0;
        for (size_t i = 0; i < 16; i++) nonzero |= routed_local6[i];
        if (nonzero) memcpy(r.local_addr, routed_local6, 16);
    } else {
        memcpy(r.local_addr, ver_local_ip4, 4);
    }
    r.local_port = ver_answer_port;
    snprintf(r.reason, sizeof r.reason, "%s",
             r.level == D2K_VER_CHALLENGE ? "Cloudflare challenge, HTTP 403" : "подменённый зонд");
    if (ver_snapshot_enabled) {
        pthread_mutex_lock(&snapshot_mu);
        ver_snapshot_entered = 1;
        pthread_cond_broadcast(&snapshot_cv);
        while (!ver_snapshot_release) { pthread_cond_wait(&snapshot_cv, &snapshot_mu); }
        pthread_mutex_unlock(&snapshot_mu);
    }
    return r;
}

/* Зонд с ALPN клиента (задача 37, F3): что ему предложили и сколько раз
   звали. Отвечает завершённым рукопожатием без прикладного уровня. */
static int alpn_ver_calls;
static uint8_t alpn_ver_seen[256];
static size_t alpn_ver_seen_len;
static d2k_ver_result stub_alpn_ver(int use_fd, const char *ip, uint16_t port,
                                    const char *sni, int deadline_ms, size_t hello_wire,
                                    const uint8_t *alpn, size_t alpn_len) {
    (void)ip; (void)port; (void)sni; (void)deadline_ms; (void)hello_wire;
    if (use_fd >= 0) close(use_fd);
    alpn_ver_calls++;
    alpn_ver_seen_len = alpn_len < sizeof alpn_ver_seen ? alpn_len : sizeof alpn_ver_seen;
    if (alpn_ver_seen_len) memcpy(alpn_ver_seen, alpn, alpn_ver_seen_len);
    d2k_ver_result r;
    memset(&r, 0, sizeof r);
    r.fd = -1; r.name_ok = -1; r.family = 4;
    r.level = D2K_VER_HANDSHAKE;
    r.handshake_proof = 1;
    memcpy(r.local_ip4, ver_local_ip4, 4);
    memcpy(r.local_addr, ver_local_ip4, 4);
    r.local_port = ver_answer_port;
    snprintf(r.reason, sizeof r.reason, "подменённое рукопожатие с ALPN клиента");
    return r;
}

static d2k_vol_result stub_resource_volume(const char *ip, uint16_t port,
    const char *name, int plain, int tls12, size_t wire, uint32_t mark, const char *path) {
    resource_volume_calls++;
    CHECK(!strcmp(path, "/public/app.min.css") && !strcmp(name, "assets.example"),
          "volume worker changed resource context");
    d2k_vol_result r = stub_vol(ip, port, name, plain, tls12, wire, mark);
    r.rx_cut = r.rx_compressed_complete = 1;
    return r;
}

static d2k_ver_result stub_resource_verify(int fd, const char *ip, uint16_t port,
    const char *name, int deadline, size_t wire, int tls12, int encoding,
    uint32_t mark, const char *path) {
    resource_verify_calls++;
    CHECK(!strcmp(path, "/public/app.min.css") && encoding == 0 && mark == 0,
          "candidate did not prove the same identity resource");
    d2k_ver_result r = stub_ver(fd, ip, port, 6, name, deadline, wire,
                              tls12 ? D2K_SHAPE_LEGACY : D2K_SHAPE_MODERN);
    r.body_complete = r.body_framing_valid = r.body_has_length = 1;
    r.body_bytes = r.body_expected = 40000;
    return r;
}

/* Layered failure fixture: TLS works under the candidate, identity is cut,
 * but the compressed control may finish. No network access is involved. */
static int layered_identity_calls, layered_gzip_calls, layered_bad_control;
/* Полное identity-тело под кандидатом: TLS доходит, обрыва нет (задача 30). */
static d2k_ver_result stub_rx_counting(int fd, const char *ip, uint16_t port,
        uint8_t transport, const char *name, int deadline, size_t wire, uint8_t shape) {
    layered_identity_calls++;
    return stub_ver(fd, ip, port, transport, name, deadline, wire, shape);
}

static d2k_ver_result stub_layered_identity(int fd, const char *ip, uint16_t port,
        uint8_t transport, const char *name, int deadline, size_t wire, uint8_t shape) {
    d2k_ver_result r = stub_ver(fd, ip, port, transport, name, deadline, wire, shape);
    layered_identity_calls++;
    r.level = D2K_VER_HANDSHAKE; r.status = 200;
    r.body_bytes = 19806; r.body_expected = 96460;
    r.body_has_length = 1; r.body_framing_valid = 1;
    if (layered_bad_control == 3 && layered_identity_calls == 2)
        r.body_bytes += 10000;
    return r;
}
static d2k_ver_result stub_layered_gzip(int fd, const char *ip, uint16_t port,
        uint8_t transport, const char *name, int deadline, size_t wire, uint8_t shape) {
    d2k_ver_result r = stub_ver(fd, ip, port, transport, name, deadline, wire, shape);
    layered_gzip_calls++;
    r.level = D2K_VER_APPLICATION; r.status = 200;
    r.body_bytes = r.body_expected = 14384;
    r.body_has_length = r.body_framing_valid = r.body_complete = 1;
    r.body_encoding = (layered_bad_control == 1 || layered_bad_control == 5) ? 0 : 1;
    return r;
}

static d2k_ver_result stub_family_identity(int fd, const char *ip, uint16_t port,
        uint8_t transport, const char *name, int deadline, size_t wire, uint8_t shape) {
    d2k_ver_result r = stub_ver(fd, ip, port, transport, name, deadline, wire, shape);
    r.body_has_length = r.body_framing_valid = 1;
    r.body_bytes = r.body_expected = 96460;
    r.body_complete = r.level == D2K_VER_APPLICATION;
    return r;
}

static char quic_last_trig[256];
static char quic_last_ctl[256];
static uint32_t quic_last_mark;

/* Задача 39: QUIC-проверка плана по известному ресурсу. Делегирует общему
   stub_ver (транспорт 17) и запоминает путь — настоящий хук пошёл бы в сеть. */
static int quic_path_ver_calls;
static char quic_path_ver_last[512];
static d2k_ver_result stub_quic_path_ver(int use_fd, const char *ip, uint16_t port,
                                         const char *sni, int deadline_ms,
                                         size_t hello_wire, const char *path) {
    quic_path_ver_calls++;
    snprintf(quic_path_ver_last, sizeof quic_path_ver_last, "%s", path ? path : "");
    return stub_ver(use_fd, ip, port, 17, sni, deadline_ms, hello_wire, D2K_SHAPE_UNKNOWN);
}

/* Задача 39: путь, которым этап данных плеча спрашивает цель (вход в arm). */
static char quic_last_path[512];
static int quic_last_data_cut = -1;
static unsigned quic_last_budget;
static int quic_arm_none = 0; /* OPAQUE без найденного плеча */
/* OPAQUE от рукопожатия, а не от своего запроса: data_cut_seen не ставится. */
static int quic_opaque_handshake = 0;
static d2k_vres stub_quic(const char *ip, uint16_t port, const char *sni,
                          d2k_hello trigger, d2k_hello control, uint32_t mark,
                          d2k_quic_arm *arm) {
    (void)port;
    quic_last_mark = mark;
    snprintf(quic_last_path, sizeof quic_last_path, "%s", arm ? arm->probe_path : "");
    int call_index = quic_calls++;
    if (call_index < 2 && trigger.bytes && trigger.len <= sizeof quic_seen_triggers[0]) {
        memcpy(quic_seen_triggers[call_index], trigger.bytes, trigger.len);
        quic_seen_trigger_lens[call_index] = trigger.len;
    }
    snprintf(quic_last_sni, sizeof quic_last_sni, "%s", sni ? sni : "");
    snprintf(quic_last_ip, sizeof quic_last_ip, "%s", ip ? ip : "");
    /* Чем именно позвали мерить — разбираем ТЕМ ЖЕ разбором, что и коробка.
       Без этого «вопросник вызван» ничего не значит: ему могли подсунуть
       TLS-приветствие, и стенд не заметил бы. */
    quic_last_trig[0] = '\0';
    quic_last_ctl[0] = '\0';
    if (trigger.bytes && trigger.len &&
        d2k_quic_sni(trigger.bytes, trigger.len, quic_last_trig, sizeof quic_last_trig) != 0) {
        uint8_t ch[2048]; size_t ch_len = 0;
        snprintf(quic_last_trig, sizeof quic_last_trig, "%s",
                 d2k_quic_client_hello(trigger.bytes, trigger.len, ch, sizeof ch, &ch_len) == 0
                    ? "<без SNI>" : "<не QUIC>");
    }
    if (control.bytes && control.len &&
        d2k_quic_sni(control.bytes, control.len, quic_last_ctl, sizeof quic_last_ctl) != 0) {
        uint8_t ch[2048]; size_t ch_len = 0;
        snprintf(quic_last_ctl, sizeof quic_last_ctl, "%s",
                 d2k_quic_client_hello(control.bytes, control.len, ch, sizeof ch, &ch_len) == 0
                    ? "<без SNI>" : "<не QUIC>");
    }
    if (call_index < 2) {
        snprintf(quic_seen_ips[call_index], sizeof quic_seen_ips[call_index], "%s", ip ? ip : "");
        snprintf(quic_seen_snis[call_index], sizeof quic_seen_snis[call_index], "%s", sni ? sni : "");
        snprintf(quic_seen_targets[call_index], sizeof quic_seen_targets[call_index], "%s", quic_last_trig);
        snprintf(quic_seen_controls[call_index], sizeof quic_seen_controls[call_index], "%s", quic_last_ctl);
    }
    if (quic_progress_notes && d2k_quic_progress_hook) {
        d2k_quic_progress_hook("контроль живости", 3);
        d2k_quic_progress_hook("прямой зонд", 3);
    }
    if (snapshot_enabled) {
        uint8_t before[2048];
        size_t before_len = trigger.len <= sizeof before ? trigger.len : sizeof before;
        if (trigger.bytes && before_len) { memcpy(before, trigger.bytes, before_len); }
        pthread_mutex_lock(&snapshot_mu);
        snapshot_entered = 1;
        pthread_cond_broadcast(&snapshot_cv);
        while (!snapshot_release) { pthread_cond_wait(&snapshot_cv, &snapshot_mu); }
        snapshot_ok = trigger.bytes && trigger.len == before_len &&
                      memcmp(before, trigger.bytes, before_len) == 0;
        pthread_mutex_unlock(&snapshot_mu);
    }
    d2k_vres r;
    memset(&r, 0, sizeof r);
    r.verdict = quic_answer;
    quic_last_split_unfit = arm ? arm->split_unfit : -1;
    quic_last_data_cut = arm ? arm->data_cut : -1;
    quic_last_budget = arm ? arm->budget_pk : 0;
    int keep_data_cut = arm ? arm->data_cut : 0;
    memset(arm, 0, sizeof *arm);
    arm->kind = D2K_QA_NOT_FOUND;
    if (!quic_arm_none &&
        (r.verdict == D2K_V_OPAQUE || r.verdict == D2K_V_PREFIX || r.verdict == D2K_V_WHOLE))
        *arm = stub_arm(ip, port, sni, NULL, trigger, mark);
    if (quic_arm_none) { arm->original = 1; }
    arm->data_cut = keep_data_cut;
    /* Как настоящий прогон: обрыв своим запросом воспроизведён — выход. */
    arm->data_cut_seen = keep_data_cut && r.verdict == D2K_V_OPAQUE && !quic_opaque_handshake;
    r.qprops = quic_props_answer;
    snprintf(r.reason, sizeof r.reason, "подменённый вопросник QUIC");
    return r;
}

/* --- события ------------------------------------------------------------- */

/* Адрес «сервера» в ключах событий. 127.0.0.1 и НЕ 443 — потому что
   планировщик, задавая вопросы о свойствах, действительно идёт к этому адресу
   настоящим сокетом (d2k_props_contact). Поставь сюда чужой адрес — и модульный
   тест начал бы ходить в интернет, а его вердикт зависел бы от того, что
   сегодня отвечает чужой сервер. Порт подставляет стенд, когда он нужен. */
static uint16_t g_server_port = 1; /* 1 — заведомо никто не слушает */

static d2k_ev ev_hello(uint8_t transport, uint16_t cport, const char *name) {
    d2k_ev e;
    memset(&e, 0, sizeof e);
    e.kind = D2K_EV_HELLO;
    e.transport = transport;
    /* Сервер — тот конец, чей порт НЕ эфемерный (server_of в sched.c);
       клиентские порты здесь всегда 4xxxx, серверный — маленький. */
    e.low_ip[0] = 127; e.low_ip[1] = 0; e.low_ip[2] = 0; e.low_ip[3] = 1;
    e.low_port = g_server_port;
    e.high_ip[0] = 192; e.high_ip[1] = 168; e.high_ip[2] = 1; e.high_ip[3] = 67;
    e.high_port = cport;
    snprintf(e.name, sizeof e.name, "%s", name);
    return e;
}

static d2k_ev ev_suspect(uint8_t transport, uint16_t cport) {
    d2k_ev e = ev_hello(transport, cport, "");
    e.kind = D2K_EV_SUSPECT;
    e.name[0] = '\0';
    e.code = D2K_SUSPECT_RST_CUT; /* снятый защитой аномальный сброс */
    e.ttl = 127;     /* примета коробки: она на фиксированном расстоянии */
    e.ref_ttl = 53;  /* сервер — на своём, разность приметой не является */
    e.tos = 0x88;
    e.ipid = 54321;
    return e;
}

static int tls_shape_event(d2k_ev *e, const char *name, d2k_shape shape) {
    if (!e) { return -1; }
    memset(e, 0, sizeof *e);
    e->kind = D2K_EV_SHAPE;
    e->transport = 6;
    return d2k_hello_from_profile(shape, name, e->shape, sizeof e->shape,
                                  &e->shape_len);
}

/* СНИМОК ПРИВЕТСТВИЯ QUIC для имени. У TLS ту же роль в этом файле играет
   d2k_hello_from_profile; для QUIC профиля нет и быть не может (см.
   d2k_quichello.h), поэтому снимок делается ровно тем же способом, каким его
   делает продукт: из настоящего снятого Initial с подставленным именем.

   Нужен он теперь КАЖДОМУ поиску по QUIC: без снимка планировщик больше не
   меряет вовсе (T_SHAPE_WAIT) — прежде он подставлял TLS-приветствие, то есть
   байты другого протокола, и «цель молчит» говорило про нашу ошибку. */
static int quic_shape(d2k_ev *sh, const char *name) {
    memset(sh, 0, sizeof *sh);
    sh->kind = D2K_EV_SHAPE;
    sh->transport = 17;
    return d2k_quic_hello_rename(d2k_test_v1_initial, sizeof d2k_test_v1_initial,
                                 name, sh->shape, sizeof sh->shape, &sh->shape_len);
}

/* ПЕРВАЯ ИЗ ДВУХ ДАТАГРАММ ПРИВЕТСТВИЯ: CRYPTO с нуля, имя в нём целиком,
   но ClientHello обрезан сразу за server_name — ровно то, что датапат отдаёт
   снимком, когда браузер с постквантовым key_share шлёт приветствие двумя
   Initial. d2k_quic_sni его принимает, d2k_quic_client_hello — нет. */
static int quic_shape_first_of_two(d2k_ev *sh, const char *name) {
    d2k_ev whole;
    if (quic_shape(&whole, name) != 0) { return -1; }
    uint8_t ch[2048];
    size_t ch_len = 0;
    if (d2k_quic_client_hello(whole.shape, whole.shape_len, ch, sizeof ch, &ch_len) != 0) {
        return -1;
    }
    size_t nl = strlen(name), at = 0;
    while (at + nl <= ch_len && memcmp(ch + at, name, nl) != 0) { at++; }
    size_t cut = at + nl + 4;
    if (at + nl > ch_len || cut >= ch_len) { return -1; }
    uint8_t body[D2K_QW_MAX_DGRAM];
    size_t b = 0;
    body[b++] = 0x06;                                   /* CRYPTO */
    b += d2k_qw_varint_write(body + b, sizeof body - b, 0);
    b += d2k_qw_varint_write(body + b, sizeof body - b, cut);
    memcpy(body + b, ch, cut);
    b += cut;
    uint8_t dcid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t sec[32];
    d2k_qw_keys k;
    if (d2k_qw_initial_secret(D2K_QW_V1, dcid, sizeof dcid, D2K_QW_CLIENT, sec) != 0 ||
        d2k_qw_keys_from_secret(D2K_QW_V1, sec, &k) != 0) { return -1; }
    size_t pn_len = 1, hlen = 0;
    uint8_t pkt[D2K_QW_MAX_DGRAM];
    for (int i = 0; i < 4; i++) {
        hlen = d2k_qw_long_hdr(pkt, sizeof pkt, D2K_QW_V1, D2K_QW_LT_INITIAL,
                               dcid, sizeof dcid, NULL, 0, pn_len, b);
        if (hlen == 0) { return -1; }
        size_t total = hlen + pn_len + b + 16;
        if (total >= 1250) { break; }
        memset(body + b, 0, 1250 - total);
        b += 1250 - total;
    }
    hlen = d2k_qw_long_hdr(pkt, sizeof pkt, D2K_QW_V1, D2K_QW_LT_INITIAL,
                           dcid, sizeof dcid, NULL, 0, pn_len, b);
    memset(sh, 0, sizeof *sh);
    sh->kind = D2K_EV_SHAPE;
    sh->transport = 17;
    sh->shape_len = d2k_qw_seal(&k, 1, pkt, hlen, 0, pn_len, body, b,
                                sh->shape, sizeof sh->shape);
    return sh->shape_len ? 0 : -1;
}

/* Обмен с ВНЕШНИМ типом записи 23 в маске встреченных типов
   (d2k_ev_outer_appdata). Порогом успеха это БОЛЬШЕ НЕ является: в TLS 1.3 тем
   же типом едет второй полёт рукопожатия (RFC 8446 §5.2). Наблюдение не
   повышает достоверность уже подтверждённой записи. */
static d2k_ev ev_exchange(uint8_t transport, uint16_t cport, int appdata) {
    d2k_ev e = ev_hello(transport, cport, "");
    e.kind = D2K_EV_EXCHANGE;
    e.name[0] = '\0';
    e.code = 22;
    e.num = 1380;
    e.seen_types = (uint8_t)(appdata ? 0x0C : 0x04);
    /* ПРИЁМКА вопроса — ответ сервера, а не тип записи (донор,
       acceptServerHello, trigger.go:67-70). Тот же признак, что несёт
       датапат седьмым байтом события. */
    e.server_hello = (uint8_t)(appdata ? 1 : 0);
    if (transport == 17) {
        /* Реальный UDP EXCHANGE не несёт TLS-типов или ServerHello. */
        e.code = 0;
        e.seen_types = 0;
        e.server_hello = 0;
    }
    return e;
}

/* Осушает сторону датапата: планировщик пишет туда команды SET_NAME, и
   приветствие-приманка внутри плана весит полтора килобайта. Без чтения
   буфер socketpair переполняется, и d2k_link_set_name встаёт в write
   навсегда — первый прогон этого теста так и повис. На живом датапате
   команды читает d2kd своим циклом; здесь читать обязан тест.

   Прочитанное НЕ выбрасывается: из него тест берёт идентификатор плана (см.
   last_plan_id). */
static int drain_fd = -1;
static uint8_t sentbuf[1 << 21];
static size_t sent_len;

static void drain(void) {
    uint8_t buf[4096];
    /* Неблокирующее чтение через O_NONBLOCK на самом дескрипторе, а не через
       MSG_DONTWAIT: флага recv нет в чистом POSIX, и -std=c99 его не даёт. */
    for (;;) {
        ssize_t n = read(drain_fd, buf, sizeof buf);
        if (n <= 0) { break; }
        size_t take = (size_t)n;
        if (take > sizeof sentbuf) { take = sizeof sentbuf; }
        if (sent_len + take > sizeof sentbuf) {
            /* Нужен ПОСЛЕДНИЙ отправленный план, а не вся история: начинаем
               буфер заново, а не отказываемся читать (иначе тест повиснет на
               write планировщика — см. выше). */
            sent_len = 0;
        }
        memcpy(sentbuf + sent_len, buf, take);
        sent_len += take;
    }
}

static void forget_sent(void) { sent_len = 0; }

static void area_ack_id(d2k_ev *ack) {
    for (size_t off=0; off+6<=sent_len;) {
        const uint8_t *p=sentbuf+off;
        uint32_t n=(uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3];
        if(n<2 || n>sent_len-off-4) break;
        uint16_t cmd=(uint16_t)((uint16_t)p[4]<<8|p[5]);
        if(cmd==ack->code && n>=2+D2K_TRIAL_ID_LEN)
            memcpy(ack->trial_id,p+4+n-D2K_TRIAL_ID_LEN,D2K_TRIAL_ID_LEN);
        off+=4+n;
    }
}

/* Trial ID последней пробной установки ИМЕНИ name (v8: хвост
   SET_NAME_PROBE). Нулевой хвост — диагностический вопрос, не опыт
   кандидата: такие пропускаются. 1 — найден. */
static int name_probe_trial(const char *name, uint8_t out[D2K_TRIAL_ID_LEN]) {
    int found = 0;
    size_t nl = strlen(name);
    for (size_t off = 0; off + 6 <= sent_len;) {
        const uint8_t *p = sentbuf + off;
        uint32_t n = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
                     (uint32_t)p[2] << 8 | p[3];
        if (n < 2 || n > sent_len - off - 4) break;
        uint16_t cmd = (uint16_t)((uint16_t)p[4] << 8 | p[5]);
        const uint8_t *body = p + 6;
        if (cmd == D2K_CMD_SET_NAME_PROBE && n >= 2 + 1 + nl + D2K_TRIAL_ID_LEN &&
            body[0] == nl && !memcmp(body + 1, name, nl)) {
            const uint8_t *id = p + 4 + n - D2K_TRIAL_ID_LEN;
            uint8_t any = 0;
            for (size_t i = 0; i < D2K_TRIAL_ID_LEN; i++) any |= id[i];
            if (any) { memcpy(out, id, D2K_TRIAL_ID_LEN); found = 1; }
        }
        off += 4 + n;
    }
    return found;
}

static d2k_ev name_probe_ack(const uint8_t id[D2K_TRIAL_ID_LEN], int ok, uint8_t reason) {
    d2k_ev e;
    memset(&e, 0, sizeof e);
    e.kind = D2K_EV_ACK;
    e.code = D2K_CMD_SET_NAME_PROBE;
    e.num = (uint32_t)(ok ? 1u : 0u) << 8 | reason;
    memcpy(e.trial_id, id, D2K_TRIAL_ID_LEN);
    return e;
}

/* trial ID последней SET_ADDR_PROBE (адресный QUIC-опыт). 1 — найден. */
static int last_addr_probe_trial(uint8_t out[D2K_TRIAL_ID_LEN]) {
    int found = 0;
    for (size_t off = 0; off + 6 <= sent_len;) {
        const uint8_t *p = sentbuf + off;
        uint32_t n = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
                     (uint32_t)p[2] << 8 | p[3];
        if (n < 2 || n > sent_len - off - 4) break;
        uint16_t cmd = (uint16_t)((uint16_t)p[4] << 8 | p[5]);
        if (cmd == D2K_CMD_SET_ADDR_PROBE && n >= 2 + 38 + D2K_TRIAL_ID_LEN) {
            memcpy(out, p + 6 + 38, D2K_TRIAL_ID_LEN);
            found = 1;
        }
        off += 4 + n;
    }
    return found;
}

static d2k_ev addr_probe_ack(const uint8_t id[D2K_TRIAL_ID_LEN], int ok, uint8_t reason) {
    d2k_ev e;
    memset(&e, 0, sizeof e);
    e.kind = D2K_EV_ACK;
    e.code = D2K_CMD_SET_ADDR_PROBE;
    e.num = (uint32_t)(ok ? 1u : 0u) << 8 | reason;
    memcpy(e.trial_id, id, D2K_TRIAL_ID_LEN);
    return e;
}

/* Бюджет зондов планировщика — из его живого файла (probes_used). */
static int live_probes_used(d2k_sched *s) {
    char path[] = "/tmp/d2k-probes-live-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return -1;
    close(fd);
    int v = -1;
    if (d2k_sched_write_live(s, path, "catalog.json") == 0) {
        FILE *f = fopen(path, "r");
        char body[65536] = {0};
        if (f) { size_t got = fread(body, 1, sizeof body - 1, f); body[got] = 0; fclose(f); }
        const char *at = strstr(body, "\"probes_used\":");
        if (at) v = atoi(at + strlen("\"probes_used\":"));
    }
    unlink(path);
    return v;
}

/* Запись ОДНОЙ активной задачи из живого файла (до закрывающей скобки).
   Пустая строка — задачи нет среди активных или файл не прочитан. */
static const char *live_task_entry(d2k_sched *s, const char *target) {
    static char entry[4096];
    char path[] = "/tmp/d2k-task-entry-XXXXXX";
    entry[0] = 0;
    int fd = mkstemp(path);
    if (fd < 0) return entry;
    close(fd);
    if (d2k_sched_write_live(s, path, "catalog.json") == 0) {
        FILE *f = fopen(path, "r");
        static char body[65536];
        body[0] = 0;
        if (f) { size_t got = fread(body, 1, sizeof body - 1, f); body[got] = 0; fclose(f); }
        char needle[300];
        snprintf(needle, sizeof needle, "\"target\": \"%s\"", target);
        const char *at = strstr(body, needle);
        const char *end = at ? strchr(at, '}') : NULL;
        if (at && end && (size_t)(end - at) < sizeof entry) {
            memcpy(entry, at, (size_t)(end - at)); entry[end - at] = 0;
        }
    }
    unlink(path);
    return entry;
}

/* "since" активного поиска цели — из блока "searches", а не первой
   встречной записи с этим именем (у подтверждённой цели раньше идёт её
   привязка в каталоге). Пусто — поиска нет. */
static void search_since(d2k_sched *s, const char *target, char *out, size_t cap) {
    char path[] = "/tmp/d2k-task-since-XXXXXX";
    out[0] = 0;
    int fd = mkstemp(path);
    if (fd < 0) return;
    close(fd);
    if (d2k_sched_write_live(s, path, "catalog.json") == 0) {
        FILE *f = fopen(path, "r");
        static char body[65536];
        body[0] = 0;
        if (f) { size_t got = fread(body, 1, sizeof body - 1, f); body[got] = 0; fclose(f); }
        const char *sr = strstr(body, "\"searches\"");
        char needle[300];
        snprintf(needle, sizeof needle, "\"target\": \"%s\"", target);
        const char *at = sr ? strstr(sr, needle) : NULL;
        const char *e = at ? strstr(at, "\"since\": ") : NULL;
        const char *end = at ? strchr(at, '}') : NULL;
        if (e && end && e < end) snprintf(out, cap, "%.40s", e);
    }
    unlink(path);
}

/* Зонды ОДНОЙ активной задачи из живого файла ("probes" её записи). -1 —
   задачи нет среди активных или файл не прочитан. */
static int live_task_probes(d2k_sched *s, const char *target) {
    char path[] = "/tmp/d2k-task-probes-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return -1;
    close(fd);
    int v = -1;
    if (d2k_sched_write_live(s, path, "catalog.json") == 0) {
        FILE *f = fopen(path, "r");
        static char body[65536];
        body[0] = 0;
        if (f) { size_t got = fread(body, 1, sizeof body - 1, f); body[got] = 0; fclose(f); }
        char needle[300];
        snprintf(needle, sizeof needle, "\"target\": \"%s\"", target);
        const char *at = strstr(body, needle);
        if (at) at = strstr(at, "\"probes\": ");
        if (at) v = atoi(at + strlen("\"probes\": "));
    }
    unlink(path);
    return v;
}

/* Отказ запуска рабочего потока (задача 24): spawn_fail взводит тест,
   spawn_refused считает изображённые отказы. */
static int spawn_fail, spawn_refused;
/* Источник занятости процессора (задача 29). По умолчанию «данных нет» —
   прежний предел 2, и остальные проверки не зависят от того, есть ли у
   машины /proc/stat. Включённый, он отдаёт ровную долю свободного времени:
   каждый вызов добавляет 1000 тиков, из них занято 1000 - cpu_free_pm. */
static int cpu_ok;
static unsigned cpu_cores_v = 4;
static int cpu_free_pm = 900;
static uint64_t cpu_busy_acc, cpu_total_acc;
static int stub_cpu(uint64_t *busy, uint64_t *total, unsigned *cores) {
    if (!cpu_ok) return -1;
    cpu_total_acc += 1000;
    cpu_busy_acc += (uint64_t)(1000 - cpu_free_pm);
    *busy = cpu_busy_acc; *total = cpu_total_acc; *cores = cpu_cores_v;
    return 0;
}

/* Память и conntrack (задача 38) — так же подменены. По умолчанию «данных
   нет», как и процессор; res_ok() включает все три источника сразу с
   просторными значениями: 90 % свободного процессора, 400 МБ доступно из
   512 МБ, conntrack занят на 10 %. */
static int mem_ok;
static uint64_t mem_avail_kb_v = 400u * 1024, mem_total_kb_v = 512u * 1024;
static int stub_mem(uint64_t *avail_kb, uint64_t *total_kb) {
    if (!mem_ok) return -1;
    *avail_kb = mem_avail_kb_v; *total_kb = mem_total_kb_v;
    return 0;
}
static int ct_ok;
static uint64_t ct_count_v = 100, ct_max_v = 1000;
static int stub_ct(uint64_t *count, uint64_t *max) {
    if (!ct_ok) return -1;
    *count = ct_count_v; *max = ct_max_v;
    return 0;
}
static void res_ok(int on) {
    cpu_ok = mem_ok = ct_ok = on;
    cpu_cores_v = 4; cpu_free_pm = 900;
    mem_avail_kb_v = 400u * 1024; mem_total_kb_v = 512u * 1024;
    ct_count_v = 100; ct_max_v = 1000;
}

static int stub_spawn(void) {
    if (spawn_fail) { spawn_refused++; return -1; }
    return 0;
}

/* Безымянный QUIC по IPv6: задача by_addr, опыт — SET_ADDR_PROBE. */
static d2k_ev addr_quic_suspect(uint16_t port) {
    d2k_ev su = ev_suspect(17, port);
    su.family = 6;
    CHECK(inet_pton(AF_INET6, "::1", su.low_ip) == 1, "address trial destination");
    CHECK(inet_pton(AF_INET6, "2001:db8::2", su.high_ip) == 1, "address trial client");
    return su;
}

static uint16_t last_area_command(void) {
    uint16_t found=0;
    for(size_t off=0;off+6<=sent_len;) {
        const uint8_t *p=sentbuf+off;
        uint32_t n=(uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3];
        if(n<2 || n>sent_len-off-4) break;
        uint16_t cmd=(uint16_t)((uint16_t)p[4]<<8|p[5]);
        if(cmd==D2K_CMD_SET_SUFFIX || cmd==D2K_CMD_SET_BYPASS ||
           cmd==D2K_CMD_DEL_SUFFIX || cmd==D2K_CMD_DEL_BYPASS) found=cmd;
        off+=4+n;
    }
    return found;
}

/* Count complete commands from the real scheduler socket, not a byte pattern
   inside a plan. Used to distinguish removal of name and address keys. */
static size_t sent_command_count(uint16_t kind, const uint8_t *body, size_t len) {
    size_t count = 0;
    for (size_t off = 0; off + 6 <= sent_len;) {
        const uint8_t *p = sentbuf + off;
        uint32_t n = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                     ((uint32_t)p[2] << 8) | p[3];
        if (n < 2 || n > sent_len - off - 4) { break; }
        uint16_t type = (uint16_t)(((uint16_t)p[4] << 8) | p[5]);
        if (type == kind && (!body || (n == len + 2 && memcmp(p + 6, body, len) == 0))) {
            count++;
        }
        off += 4 + n;
    }
    return count;
}

/* Пробные записи ИМЕНИ name по проводу (задача 20). Каждая SET_NAME_PROBE
   (имя, форма, семейство, местный порт) обязана быть снята ровно своей
   DEL_NAME_PROBE с тем же ключом; широкая DEL_NAME подтверждённое знание
   задела бы. pending — сколько осталось стоять, max_pending — сколько
   стояло одновременно (каждый переход снимает прежнюю запись ДО следующей),
   stray — снятия без своей установки. */
typedef struct {
    size_t sets, dels, stray, pending, max_pending, broad;
} probe_tally;

static probe_tally name_probe_tally(const char *name) {
    probe_tally r;
    memset(&r, 0, sizeof r);
    struct { uint8_t shape, family; uint16_t port; } open_set[256];
    size_t n_open = 0, nl = strlen(name);
    for (size_t off = 0; off + 6 <= sent_len;) {
        const uint8_t *p = sentbuf + off;
        uint32_t n = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
                     (uint32_t)p[2] << 8 | p[3];
        if (n < 2 || n > sent_len - off - 4) break;
        uint16_t cmd = (uint16_t)((uint16_t)p[4] << 8 | p[5]);
        const uint8_t *body = p + 6;
        size_t blen = n - 2;
        int ours = blen >= 1 + nl && body[0] == nl && !memcmp(body + 1, name, nl);
        if (ours && cmd == D2K_CMD_DEL_NAME) { r.broad++; }
        if (ours && (cmd == D2K_CMD_SET_NAME_PROBE || cmd == D2K_CMD_DEL_NAME_PROBE) &&
            blen >= 1 + nl + 4) {
            uint8_t shape = body[1 + nl], family = body[2 + nl];
            uint16_t port;
            memcpy(&port, body + 3 + nl, 2);
            size_t k = 0;
            while (k < n_open && !(open_set[k].shape == shape &&
                                   open_set[k].family == family &&
                                   open_set[k].port == port)) { k++; }
            if (cmd == D2K_CMD_SET_NAME_PROBE) {
                r.sets++;
                if (k == n_open && n_open < sizeof open_set / sizeof open_set[0]) {
                    open_set[n_open].shape = shape;
                    open_set[n_open].family = family;
                    open_set[n_open].port = port;
                    n_open++;
                }
                if (n_open > r.max_pending) { r.max_pending = n_open; }
            } else {
                r.dels++;
                if (k == n_open) { r.stray++; }
                else { open_set[k] = open_set[--n_open]; }
            }
        }
        off += 4 + n;
    }
    r.pending = n_open;
    return r;
}

/* SET_ADDR v7: [family][address 16][форма][план]. Сколько ушло на этот
   адрес с этой формой протокола (задача 16). */
static size_t sent_set_addr_shape(uint8_t family, const uint8_t *ip, uint8_t shape) {
    size_t count = 0;
    for (size_t off = 0; off + 6 <= sent_len;) {
        const uint8_t *p = sentbuf + off;
        uint32_t n = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                     ((uint32_t)p[2] << 8) | p[3];
        if (n < 2 || n > sent_len - off - 4) { break; }
        uint16_t type = (uint16_t)(((uint16_t)p[4] << 8) | p[5]);
        const uint8_t *body = p + 6;
        if (type == D2K_CMD_SET_ADDR && n >= 2 + 18 && body[0] == family &&
            !memcmp(body + 1, ip, family == 6 ? 16 : 4) && body[17] == shape) {
            count++;
        }
        off += 4 + n;
    }
    return count;
}

static int last_addr_probe_endpoint(uint8_t src[4], uint16_t *sport_be,
                                    uint8_t trial[D2K_TRIAL_ID_LEN]) {
    for (size_t off = 0; off + 6 <= sent_len;) {
        const uint8_t *p = sentbuf + off;
        uint32_t n = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                     ((uint32_t)p[2] << 8) | p[3];
        if (n < 2 || n > sent_len - off - 4) { break; }
        uint16_t type = (uint16_t)(((uint16_t)p[4] << 8) | p[5]);
        if (type == D2K_CMD_SET_ADDR_PROBE && n >= 2 + 38 + D2K_TRIAL_ID_LEN + 4) {
            memcpy(src, p + 7, 4);
            memcpy(sport_be, p + 39, 2);
            memcpy(trial, p + 6 + 38, D2K_TRIAL_ID_LEN);
            return 1;
        }
        off += 4 + n;
    }
    return 0;
}

/* Снимок всех адресных проб, ушедших по управляющему сокету. Нужен для
 * lifecycle-регрессий: один и тот же Plan ID не различает параллельные
 * задачи, а trial ID и точный destination должны различать их. */
static size_t collect_addr_probes(uint8_t dst[][4], uint8_t trial[][D2K_TRIAL_ID_LEN],
                                  uint16_t *src_port_be, size_t cap) {
    size_t found = 0;
    for (size_t off = 0; off + 6 <= sent_len;) {
        const uint8_t *p = sentbuf + off;
        uint32_t n = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                     ((uint32_t)p[2] << 8) | p[3];
        if (n < 2 || n > sent_len - off - 4) { break; }
        uint16_t type = (uint16_t)(((uint16_t)p[4] << 8) | p[5]);
        if (type == D2K_CMD_SET_ADDR_PROBE && n >= 2 + 38 + D2K_TRIAL_ID_LEN + 4 &&
            found < cap) {
            const uint8_t *body = p + 6;
            memcpy(dst[found], body + 17, 4);
            if (src_port_be) { memcpy(&src_port_be[found], body + 33, 2); }
            memcpy(trial[found], body + 38, D2K_TRIAL_ID_LEN);
            found++;
        }
        off += 4 + n;
    }
    return found;
}

/* Read the last REC_ID from complete command frames. Trial IDs are binary,
   not a printable catalog hash; never derive the expectation from the plan. */
static int last_plan_id(uint8_t out[16]) {
    int found = 0;
    for (size_t off = 0; off + 6 <= sent_len;) {
        const uint8_t *p = sentbuf + off;
        uint32_t n = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                     ((uint32_t)p[2] << 8) | p[3];
        if (n < 2 || n > sent_len - off - 4) break;
        uint16_t type = (uint16_t)(((uint16_t)p[4] << 8) | p[5]);
        const uint8_t *body = p + 6;
        size_t len = n - 2, start = len;
        if (type == D2K_CMD_SET_NAME_PROBE && len >= D2K_TRIAL_ID_LEN) {
            len -= D2K_TRIAL_ID_LEN; /* v8: хвост — trial ID, не план */
        }
        if ((type == D2K_CMD_SET_NAME || type == D2K_CMD_SET_NAME_PROBE) && len) {
            start = 3u + body[0] + (type == D2K_CMD_SET_NAME_PROBE ? 2u : 0u);
        } else if (type == D2K_CMD_SET_ADDR) {
            start = 18; /* v7: family, address(16), форма */
        } else if (type == D2K_CMD_SET_ADDR_PROBE) {
            start = 58;
        }
        if (start <= len && len - start >= 12 && !memcmp(body + start, "D2KP", 4)) {
            for (size_t at = start + 12; at + 4 <= len;) {
                unsigned record = ((unsigned)body[at] << 8) | body[at + 1];
                size_t size = ((size_t)body[at + 2] << 8) | body[at + 3];
                at += 4;
                if (size > len - at) break;
                if (record == 1 && size == 16) {
                    memcpy(out, body + at, 16);
                    found = 1;
                }
                at += size;
            }
        }
        off += 4 + n;
    }
    return found;
}

/* SET_NAME(_PROBE) несёт шестнадцатеричный текстовый план. Ищем в отправленной
   команде фрагмент его внутреннего payload, закодированный дважды: сначала
   сам ClientHello в hex, затем весь текст плана в hex. Это позволяет тесту
   проверить порядок кандидатов по фактически ушедшей команде, не дублируя
   разбор TLV и не подглядывая в task планировщика. */
static int sent_contains_plan_ascii(const char *fragment) {
    char inner[256], outer[512];
    size_t n = strlen(fragment);
    if (n * 2 + 1 > sizeof inner) { return 0; }
    for (size_t i = 0; i < n; i++) {
        (void)snprintf(inner + i * 2, sizeof inner - i * 2, "%02x",
                       (unsigned char)fragment[i]);
    }
    inner[n * 2] = '\0';
    n = strlen(inner);
    if (n * 2 + 1 > sizeof outer) { return 0; }
    for (size_t i = 0; i < n; i++) {
        (void)snprintf(outer + i * 2, sizeof outer - i * 2, "%02x",
                       (unsigned char)inner[i]);
    }
    outer[n * 2] = '\0';
    size_t m = strlen(outer);
    for (size_t i = 0; i + m <= sent_len; i++) {
        if (memcmp(sentbuf + i, outer, m) == 0) { return 1; }
    }
    return 0;
}

/* Binary payload bytes (for example the literal SNI in a generated ClientHello)
   are encoded once by d2k_plan_text_to_hex as the complete TLV frame. */
static int sent_contains_plan_payload(const char *fragment) {
    char current[1024], hex[2048];
    size_t n = strlen(fragment);
    if (n >= sizeof current) { return 0; }
    for (size_t i = 0; i + n <= sent_len; i++) {
        if (memcmp(sentbuf + i, fragment, n) == 0) { return 1; }
    }
    memcpy(current, fragment, n + 1);
    for (unsigned depth = 0; depth < 3; depth++) {
        n = strlen(current);
        if (n * 2 + 1 > sizeof hex) { return 0; }
        for (size_t i = 0; i < n; i++) {
            (void)snprintf(hex + i * 2, sizeof hex - i * 2, "%02x",
                           (unsigned char)current[i]);
        }
        hex[n * 2] = '\0';
        for (size_t i = 0; i + n * 2 <= sent_len; i++) {
            if (memcmp(sentbuf + i, hex, n * 2) == 0) { return 1; }
        }
        memcpy(current, hex, n * 2 + 1);
    }
    return 0;
}

static int region_has_encoded(const uint8_t *bytes, size_t bytes_len,
                              const char *fragment, unsigned target_depth) {
    char current[1024], next[2048];
    size_t n = strlen(fragment);
    if (n >= sizeof current) { return 0; }
    for (size_t i = 0; i + n <= bytes_len; i++) {
        if (memcmp(bytes + i, fragment, n) == 0) { return 1; }
    }
    memcpy(current, fragment, n + 1);
    for (unsigned depth = 1; depth <= target_depth; depth++) {
        n = strlen(current);
        if (n * 2 + 1 > sizeof next) { return 0; }
        for (size_t i = 0; i < n; i++) {
            (void)snprintf(next + i * 2, sizeof next - i * 2, "%02x",
                           (unsigned char)current[i]);
        }
        next[n * 2] = '\0';
        if (depth == target_depth) {
            for (size_t i = 0; i + n * 2 <= bytes_len; i++) {
                if (memcmp(bytes + i, next, n * 2) == 0) { return 1; }
            }
        }
        memcpy(current, next, n * 2 + 1);
    }
    return 0;
}

static int sent_first_split_index(unsigned wanted_offset) {
    size_t plan_index = 0;
    for (size_t off = 0; off + 6 <= sent_len;) {
        const uint8_t *frame = sentbuf + off;
        uint32_t n = ((uint32_t)frame[0] << 24) | ((uint32_t)frame[1] << 16) |
                     ((uint32_t)frame[2] << 8) | frame[3];
        if (n < 2 || n > sent_len - off - 4) { break; }
        uint16_t type = (uint16_t)(((uint16_t)frame[4] << 8) | frame[5]);
        if (type == D2K_CMD_SET_NAME || type == D2K_CMD_SET_NAME_PROBE) {
            const uint8_t *body = frame + 6;
            size_t body_len = n - 2;
            if (type == D2K_CMD_SET_NAME_PROBE && body_len >= D2K_TRIAL_ID_LEN) {
                body_len -= D2K_TRIAL_ID_LEN; /* v8: хвост — trial ID */
            }
            size_t nl = body_len ? body[0] : body_len;
            size_t prefix = 1 + nl + 2 + (type == D2K_CMD_SET_NAME_PROBE ? 2 : 0);
            int found = 0;
            if (prefix <= body_len && body_len - prefix >= 12) {
                const uint8_t *plan = body + prefix;
                size_t plan_len = body_len - prefix;
                size_t pos = 12; /* D2KP header */
                while (pos + 4 <= plan_len) {
                    uint16_t rec = (uint16_t)(((uint16_t)plan[pos] << 8) | plan[pos + 1]);
                    size_t len = ((size_t)plan[pos + 2] << 8) | plan[pos + 3];
                    pos += 4;
                    if (len > plan_len - pos) { break; }
                    if (rec == 0x0100 && len == 4) {
                        unsigned split = ((unsigned)plan[pos + 2] << 8) | plan[pos + 3];
                        if (split == wanted_offset) { found = 1; break; }
                    }
                    pos += len;
                }
            }
            if (found) { return (int)plan_index; }
            plan_index++;
        }
        off += 4 + n;
    }
    return -1;
}

static int sent_plan_index(const char *fragment, unsigned first_depth,
                           unsigned last_depth) {
    size_t plan_index = 0;
    for (size_t off = 0; off + 6 <= sent_len;) {
        const uint8_t *frame = sentbuf + off;
        uint32_t n = ((uint32_t)frame[0] << 24) | ((uint32_t)frame[1] << 16) |
                     ((uint32_t)frame[2] << 8) | frame[3];
        if (n < 2 || n > sent_len - off - 4) { break; }
        uint16_t type = (uint16_t)(((uint16_t)frame[4] << 8) | frame[5]);
        if (type == D2K_CMD_SET_NAME || type == D2K_CMD_SET_NAME_PROBE) {
            int found = 0;
            for (unsigned depth = first_depth; depth <= last_depth; depth++) {
                if (region_has_encoded(frame + 6, n - 2, fragment, depth)) {
                    found = 1;
                    break;
                }
            }
            if (found) { return (int)plan_index; }
            plan_index++;
        }
        off += 4 + n;
    }
    return -1;
}

/* Событие применения ПО КЛЮЧУ ПОТОКА ЗОНДА и с идентификатором того плана,
   который планировщик только что отправил. Вместе с уровнем «приложение» от
   подменённого зонда это и есть полное доказательство. */
static d2k_ev ev_applied(uint8_t transport, uint16_t cport) {
    d2k_ev e = ev_hello(transport, cport, "");
    e.kind = D2K_EV_APPLIED;
    e.name[0] = '\0';
    (void)last_plan_id(e.plan_id);
    return e;
}

/* Отказ отправки ПО КЛЮЧУ ПОТОКА ЗОНДА. code — D2K_REFUSE_*: ненулевой
   означает «посылка плана не покинула машину», то есть опыта не было. Это НЕ
   ответ коробки, и свойство от него меняться не имеет права.
   own_id == 0 подставляет ЧУЖОЙ идентификатор: такой отказ относится к
   другому плану и не должен влиять на нашего кандидата (0009, U2). */
static d2k_ev ev_refused(uint8_t transport, uint16_t cport, uint8_t code, int own_id) {
    d2k_ev e = ev_hello(transport, cport, "");
    e.kind = D2K_EV_REFUSED;
    e.name[0] = '\0';
    e.code = code;
    (void)last_plan_id(e.plan_id);
    if (!own_id) { e.plan_id[0] = (uint8_t)~e.plan_id[0]; }
    return e;
}

/* Модельные часы теста. ТОЛЬКО ВПЕРЁД и общие на весь файл: у планировщика
   есть сроки, измеряемые секундами (потолок шага испытания — пять секунд), и
   тик, поданный «назад», отменял бы их молча. Раньше каждый цикл ожидания
   считал время от нуля своим i*5, и пересечь пятисекундный срок было нечем. */
static int64_t g_now_ms;

/* Один круг: ждём на будилке планировщика, двигаем часы, тикаем, читаем
   команды. Ждём, а не крутим тики вплотную: рабочий поток сетевого оракула ещё
   даже не начинался, когда четыреста пустых тиков уже кончились — первая
   редакция этой функции так и плавала, проходя или падая в зависимости от
   того, успел ли поток встать. Миллисекунда на круг — это и ожидание, и
   уступка планировщику ОС, и ровно тот же приём, каким d2kc ждёт событий. */
static void tick_once(d2k_sched *s) {
    struct pollfd pfd;
    pfd.fd = d2k_sched_wake_fd(s); pfd.events = POLLIN; pfd.revents = 0;
    (void)poll(&pfd, 1, 1);
    g_now_ms += 5;
    d2k_sched_tick(s, g_now_ms);
    drain();
}

/* Круг БЕЗ хода часов: срок ожидания приёма плана (SCHED_TRIAL_SETTLE_MS)
   не истекает, и отпустить ожидание может только подтверждение. */
static void tick_frozen(d2k_sched *s) {
    struct pollfd pfd;
    pfd.fd = d2k_sched_wake_fd(s); pfd.events = POLLIN; pfd.revents = 0;
    (void)poll(&pfd, 1, 1);
    d2k_sched_tick(s, g_now_ms);
    drain();
}

static void spin(d2k_sched *s, int rounds) {
    for (int i = 0; i < rounds; i++) { tick_once(s); }
}

/* Крутит планировщик четыреста кругов — две секунды модельного времени.
   Потолок щедрый: на машине разработки подменённый оракул возвращается
   мгновенно, а на медленной сборке — за несколько миллисекунд. */
/* Шагов, а не секунд: один шаг — 5 мс модельных часов. Запас взят с учётом
   того, что каждый кандидат теперь ждёт приёма плана датапатом
   (SCHED_TRIAL_SETTLE_MS) — это ход планировщика, а не задержка теста. */
static void settle(d2k_sched *s) { spin(s, 800); }

/* Крутит до УСТАНОВКИ ПЕРВОГО кандидата и останавливается. Нужно тем
   проверкам, которым надо вмешаться, пока задача ещё испытывает именно его:
   settle() к тому времени прогонит всю очередь.

   Ждём именно УСТАНОВКУ, а не первое обращение зонда. Зонд работает в
   отдельном потоке, и его счётчик виден главному потоку асинхронно: пока
   счётчик доходит, очередной тик успевает забрать результат и объявить
   промах — впрыск опаздывал, и отказ доставался уже СЛЕДУЮЩЕМУ кандидату
   (поймано санитайзерами, где всё медленнее). Установка происходит в самом
   тике, и после неё главный поток гарантированно успевает вмешаться до
   разбора результата.

   drain() обязателен: идентификатор кандидата тест берёт из последней ушедшей
   команды SET_NAME (last_plan_id по sentbuf), а туда она попадает только
   через drain(). Без него отказ строился со старым идентификатором, не
   совпадал с кандидатом и молча пропадал. */
static void spin_until_installed(d2k_sched *s) {
    for (int i = 0; i < 400 && !said("поставил план"); i++) { tick_once(s); }
    drain();
}

/* Перешагивает срок планировщика: сроки считаются секундами, а settle()
   проходит меньше двух секунд модельного времени и потолок не пересекает
   никогда. Живое время при этом не тратится — у планировщика часы приходят
   аргументом, а не из ОС. */
/* Первый поздний RST той же цели на соседнем потоке: одиночный поздний RST
   замер не запускает (задача 18), второй по независимому flow key — да. */
static void prime_late_rst(d2k_sched *s, const char *name, uint16_t cport) {
    d2k_ev h = ev_hello(6, cport, name);
    d2k_sched_event(s, &h);
    d2k_ev r = ev_suspect(6, cport);
    r.code = D2K_SUSPECT_RST_AFTER_APP;
    d2k_sched_event(s, &r);
}

static void skip_ahead(d2k_sched *s, int64_t ms) {
    g_now_ms += ms;
    d2k_sched_tick(s, g_now_ms);
    drain();
}

/* Задача 38: блок "measurements" живого JSON целиком (в buf) и предел из
   него; -1 — блока нет. */
static int live_meas(d2k_sched *s, char *buf, size_t n) {
    char path[] = "/tmp/d2k-t38-live-XXXXXX";
    int fd = mkstemp(path);
    if (n) buf[0] = '\0';
    if (fd < 0) return -1;
    close(fd);
    static char body[65536];
    body[0] = '\0';
    if (d2k_sched_write_live(s, path, "catalog.json") == 0) {
        FILE *f = fopen(path, "r");
        if (f) { size_t got = fread(body, 1, sizeof body - 1, f); body[got] = '\0'; fclose(f); }
    }
    unlink(path);
    const char *m = strstr(body, "\"measurements\": {");
    if (!m) return -1;
    const char *e = strchr(m, '}');
    if (buf && n && e) {
        size_t len = (size_t)(e - m + 1);
        if (len >= n) len = n - 1;
        memcpy(buf, m, len); buf[len] = '\0';
    }
    const char *l = strstr(m, "\"limit\": ");
    return l ? atoi(l + strlen("\"limit\": ")) : -1;
}
static int live_limit(d2k_sched *s) { return live_meas(s, NULL, 0); }

/* Задача 38: n новых целей по одной в секунду модельных часов (каждая
   успевает выйти из очереди за паузу запуска); возвращает наибольший
   увиденный предел. */
static int meas_ramp(d2k_sched *s, const char *prefix, uint16_t port0, int n) {
    int top = 0;
    for (int i = 0; i < n; i++) {
        char name[64];
        snprintf(name, sizeof name, "%s-%d.example", prefix, i);
        d2k_ev h = ev_hello(6, (uint16_t)(port0 + i), name); d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, (uint16_t)(port0 + i)); d2k_sched_event(s, &su);
        spin(s, 60);
        skip_ahead(s, 1000);
        int l = live_limit(s);
        if (l > top) top = l;
    }
    return top;
}

/* Доводит поиск до конца очереди кандидатов. Каждый неподтверждённый кандидат
   уходит по потолку ожидания применения, а тот считается секундами модельного
   времени — значит нужны прыжки часов, а не долгое кручение. Сорока кругов
   между прыжками хватает с запасом: рабочий поток будит цикл сам, а tick_once
   этого пробуждения и ждёт. */
/* Докручивает проход по каталогу до конца и ЧИТАЕТ провод после каждой
   порции, включая последнюю: последняя возвращает ноль («больше нечего»), уже
   отправив свои команды, и цикл вида while(step) { drain(); } их теряет. */
/* Есть ли байты подстроки в том, что УЖЕ уехало датапату. Нужна там, где
   идентификатор плана не годится: план из каталога несёт идентичность своего
   текста, а не подставленную установкой. */
/* Постоянные SET_NAME (0x0081) по имени и форме на проводе — тело: длина
   имени, имя, форма, семейство, план. Задача 21: проход каталога не ставит
   привязку, ждущую повторной проверки. */
static size_t sent_set_name_shape(const char *name, uint8_t shape) {
    size_t count = 0, nl = strlen(name);
    for (size_t off = 0; off + 6 <= sent_len;) {
        const uint8_t *p = sentbuf + off;
        uint32_t n = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
                     (uint32_t)p[2] << 8 | p[3];
        if (n < 2 || n > sent_len - off - 4) break;
        uint16_t cmd = (uint16_t)((uint16_t)p[4] << 8 | p[5]);
        const uint8_t *body = p + 6;
        if (cmd == D2K_CMD_SET_NAME && n - 2 >= 3 + nl && body[0] == nl &&
            !memcmp(body + 1, name, nl) && body[1 + nl] == shape) { count++; }
        off += 4 + n;
    }
    return count;
}

/* SET_NAME с планом quicdeny (запись 0x0110) для имени — задача 50, раунд 2. */
static size_t sent_quic_deny(const char *name) {
    static const uint8_t rec[] = {0x01, 0x10, 0x00, 0x01, 0x01};
    size_t count = 0, nl = strlen(name);
    for (size_t off = 0; off + 6 <= sent_len;) {
        const uint8_t *p = sentbuf + off;
        uint32_t n = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
                     (uint32_t)p[2] << 8 | p[3];
        if (n < 2 || n > sent_len - off - 4) break;
        uint16_t cmd = (uint16_t)((uint16_t)p[4] << 8 | p[5]);
        const uint8_t *body = p + 6;
        size_t len = n - 2;
        if (cmd == D2K_CMD_SET_NAME && len >= 3 + nl && body[0] == nl &&
            !memcmp(body + 1, name, nl)) {
            for (size_t i = 1 + nl; i + sizeof rec <= len; i++)
                if (!memcmp(body + i, rec, sizeof rec)) { count++; break; }
        }
        off += 4 + n;
    }
    return count;
}

/* DEL_NAME v9 ровно этого ключа: длина имени, имя, транспорт, форма, семейство. */
static size_t sent_del_name_key(const char *name, uint8_t transport, uint8_t shape,
                                uint8_t family) {
    uint8_t body[300];
    size_t nl = strlen(name);
    body[0] = (uint8_t)nl;
    memcpy(body + 1, name, nl);
    body[1 + nl] = transport; body[2 + nl] = shape; body[3 + nl] = family;
    return sent_command_count(D2K_CMD_DEL_NAME, body, nl + 4);
}

/* Добавляет к коробке копию привязки с другой формой/транспортом — фикстура
   «то же имя, другие протоколы». */
static void add_binding_like(d2k_cat_box *b, const d2k_cat_binding *proto,
                             uint8_t transport, uint8_t shape) {
    d2k_cat_binding copy = *proto;
    d2k_cat_binding *nb = realloc(b->binds, (b->n_binds + 1) * sizeof *nb);
    CHECK(nb != NULL, "fixture binding realloc");
    if (!nb) return;
    b->binds = nb;
    copy.transport = transport;
    copy.shape = shape;
    copy.recheck_since = 0;
    copy.recheck_mono_ms = 0;
    b->binds[b->n_binds++] = copy;
}

static d2k_cat_binding *binding_shape(d2k_catalog *c, const char *target,
                                      uint8_t transport, uint8_t shape) {
    for (size_t i = 0; i < c->n_boxes; i++)
        for (size_t j = 0; j < c->boxes[i].n_binds; j++) {
            d2k_cat_binding *b = &c->boxes[i].binds[j];
            if (!strcmp(b->target, target) && b->transport == transport && b->shape == shape)
                return b;
        }
    return NULL;
}

static int sent_has(const char *needle) {
    size_t n = strlen(needle);
    if (n == 0 || sent_len < n) { return 0; }
    for (size_t i = 0; i + n <= sent_len; i++) {
        if (memcmp(sentbuf + i, needle, n) == 0) { return 1; }
    }
    return 0;
}

static int sent_has_bytes(const uint8_t *needle, size_t n) {
    if (!needle || n == 0 || sent_len < n) { return 0; }
    for (size_t i = 0; i + n <= sent_len; i++) {
        if (memcmp(sentbuf + i, needle, n) == 0) { return 1; }
    }
    return 0;
}

static void sync_out(d2k_sched *s) {
    for (int i = 0; i < 1000; i++) {
        int more = d2k_sched_sync_step(s);
        drain();
        if (!more) { break; }
    }
}

static void run_out(d2k_sched *s) {
    for (int i = 0; i < 60 && d2k_sched_active(s); i++) {
        skip_ahead(s, 6000);
        spin(s, 40);
    }
}

static size_t total_bindings(const d2k_catalog *c) {
    size_t n = 0;
    for (size_t i = 0; i < c->n_boxes; i++) { n += c->boxes[i].n_binds; }
    return n;
}

/* Форма приветствия СОБСТВЕННОГО зонда — ИЗМЕРЕННАЯ, а не назначенная.
 *
 * Планировщик записывает её в привязку константой (SCHED_PROBE_SHAPE,
 * sched.c): спрашивать зонд о форме его же приветствия на каждом успехе
 * незачем, она не меняется. Но константа, назначенная из головы, — это тот
 * самый параметр без замера, который здесь запрещён. Поэтому тест ДОБЫВАЕТ
 * её: поднимает клиента TLS 1.3 (core/tls13.c — тот самый, которым ходит
 * зонд) поверх socketpair, снимает с провода его приветствие и отдаёт на
 * разбор d2k_hello_shape — ровно тем же способом, которым планировщик
 * определяет форму снятого приветствия цели.
 *
 * Рукопожатие при этом не состоится (на том конце socketpair никто не
 * отвечает), и это неважно: приветствие уходит ПЕРВЫМ, до любого чтения. */
static d2k_shape probe_hello_shape(void) {
    int p[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, p) != 0) { return D2K_SHAPE_UNKNOWN; }
    d2k_tls *t = NULL;
    char e[200];
    /* Потолок маленький: ждать здесь нечего, а тест платит за это временем. */
    (void)d2k_tls_connect(p[0], "пример.цель", 50, 0, &t, e, sizeof e);
    d2k_tls_free(t);
    uint8_t buf[2048];
    ssize_t n = read(p[1], buf, sizeof buf);
    close(p[0]);
    close(p[1]);
    if (n <= 0) { return D2K_SHAPE_UNKNOWN; }
    return d2k_hello_shape(buf, (size_t)n);
}

static const d2k_cat_binding *binding_of(const d2k_catalog *c, const char *target,
                                          uint8_t transport) {
    for (size_t i = 0; i < c->n_boxes; i++) {
        for (size_t j = 0; j < c->boxes[i].n_binds; j++) {
            const d2k_cat_binding *b = &c->boxes[i].binds[j];
            if (strcmp(b->target, target) == 0 && b->transport == transport) { return b; }
        }
    }
    return NULL;
}

/* Сколько привязок у одной цели по одному транспорту. До задачи 5 ответ был
   «не больше одной» по построению; теперь ключ — тройка с формой приветствия,
   и число записей стало наблюдаемым различием между «обновили» и «завели
   рядом». */
static size_t bindings_of(const d2k_catalog *c, const char *target, uint8_t transport) {
    size_t n = 0;
    for (size_t i = 0; i < c->n_boxes; i++) {
        for (size_t j = 0; j < c->boxes[i].n_binds; j++) {
            const d2k_cat_binding *b = &c->boxes[i].binds[j];
            if (strcmp(b->target, target) == 0 && b->transport == transport) { n++; }
        }
    }
    return n;
}

/* Тот же поиск, но для правки: тест изображает файл, снятый ДО появления
   полей (shape = 0), и файл, где записана ДРУГАЯ форма. Настоящих путей
   завести такую запись у планировщика сегодня нет — зонд один, и форма у
   него одна, — а проверить ключ надо сейчас, а не когда появится второй. */
static d2k_cat_binding *binding_mut(d2k_catalog *c, const char *target, uint8_t transport) {
    for (size_t i = 0; i < c->n_boxes; i++) {
        for (size_t j = 0; j < c->boxes[i].n_binds; j++) {
            d2k_cat_binding *b = &c->boxes[i].binds[j];
            if (strcmp(b->target, target) == 0 && b->transport == transport) { return b; }
        }
    }
    return NULL;
}

/* Один полный проход поиска до подтверждения: подозрение, испытание зондом,
   событие применения по ключу потока зонда. Результат остаётся в каталоге —
   его вызывающий и смотрит; планировщик после прохода закрывается, потому что
   проверяется именно НАКОПЛЕННОЕ в файле, а не живое состояние задачи. Порт
   клиента задаёт вызывающий: по нему сходятся зонд и событие. */
static void confirm_transport(d2k_catalog *cat, int link_fd, const char *target,
                              uint16_t cport, uint8_t transport) {
    d2k_sched *s = d2k_sched_new(cat, link_fd, 0x2d);
    if (!s) { CHECK(0, "планировщик не завёлся"); return; }
    d2k_sched_set_say(s, collect_say, NULL);
    ver_answer_port = cport;
    ver_calls = 0;
    forget_sent();
    d2k_ev h = ev_hello(transport, cport, target);
    d2k_sched_event(s, &h);
    d2k_ev su = ev_suspect(transport, cport);
    d2k_sched_event(s, &su);
    settle(s);
    d2k_ev ap = ev_applied(transport, cport);
    d2k_sched_event(s, &ap);
    spin(s, 40);
    char live_path[] = "/tmp/d2k-confirmed-live-XXXXXX";
    int live_fd = mkstemp(live_path);
    CHECK(live_fd >= 0, "confirmed live fixture");
    if (live_fd >= 0) {
        close(live_fd);
        CHECK(!d2k_sched_write_live(s, live_path, "catalog.json"), "confirmed live write");
        FILE *live = fopen(live_path, "r"); char body[32768] = {0};
        if (live) { (void)!fread(body, 1, sizeof body - 1, live); fclose(live); }
        CHECK(!strstr(body, "подтверждено, смотрим живой трафик"),
              "confirmed passive watcher must not be exported as an ongoing search");
        unlink(live_path);
    }
    d2k_sched_free(s);
}

static void confirm_once(d2k_catalog *cat, int link_fd, const char *target,
                         uint16_t cport) {
    confirm_transport(cat, link_fd, target, cport, 6);
}

/* Задача 54: нейтральный байт перепроверки мёртвого адреса. */
static int ack_calls;
static int ack_answer;
static char ack_last_ip[64];
static int stub_ack(const char *ip, uint16_t port, uint32_t mark,
                    const volatile sig_atomic_t *stop, int *probes) {
    (void)port; (void)mark; (void)stop;
    ack_calls++;
    snprintf(ack_last_ip, sizeof ack_last_ip, "%s", ip ? ip : "");
    if (probes) *probes = ack_answer > 0 ? 1 : 3;
    return ack_answer;
}

/* ЗАДАЧА 32: базовый вопрос донора отдельно от полного прогона. base_blocked —
   «триггер целиком не прошёл ни разу», это и есть подтверждённая блокировка на
   рукопожатии, после которой планировщик сначала пробует свои планы. */
static int base_calls;
static int base_blocked_answer = 1;
static int base_wait_until_stop;
static d2k_vres stub_base(const char *ip, uint16_t port, d2k_hello trigger,
                          d2k_hello control, uint32_t mark, int repeats,
                          uint32_t gap_us, uint32_t wait_ms,
                          const volatile sig_atomic_t *stop) {
    (void)ip; (void)port; (void)control; (void)mark; (void)repeats;
    (void)gap_us; (void)wait_ms;
    base_calls++;
    tcp_last_wire = trigger.len;
    d2k_vres r;
    memset(&r, 0, sizeof r);
    if (base_wait_until_stop && base_calls == 1) {
        /* Как настоящий: в сети, бросить может только просьба. */
        while (!(stop && *stop)) usleep(1000);
        r.verdict = D2K_V_INCONCLUSIVE;
        snprintf(r.reason, sizeof r.reason, "базовый вопрос брошен");
        return r;
    }
    r.owns_search = 1;
    r.probes = 3;
    r.base_blocked = base_blocked_answer;
    r.base.valid = 1; r.base.repeats = 3;
    r.base.pass = base_blocked_answer ? 0 : 3;
    r.base.fail = 3 - r.base.pass;
    r.verdict = base_blocked_answer ? D2K_V_INCONCLUSIVE : D2K_V_CLEAR;
    snprintf(r.reason, sizeof r.reason, "%s", base_blocked_answer
             ? "подменённая база: 0 из 3" : "подменённая база: 3 из 3");
    return r;
}

/* Полный прогон с ответом базы: сколько раз позван и с каким ответом. */
static int seeded_calls, seeded_pass, seeded_fail;
static d2k_vres stub_tcp_seeded(const char *ip, uint16_t port, d2k_hello trigger,
                                d2k_hello control, uint32_t mark, int repeats,
                                uint32_t gap_us, uint32_t wait_ms,
                                const volatile sig_atomic_t *stop, const d2k_base_seed *seed) {
    seeded_calls++;
    seeded_pass = seed ? seed->pass : -1;
    seeded_fail = seed ? seed->fail : -1;
    return stub_tcp(ip, port, trigger, control, mark, repeats, gap_us, wait_ms, stop);
}
/* QUIC: базовый вопрос и полный прогон с его ответом. */
static int quic_base_calls, quic_seeded_calls, quic_seeded_ctl;
static d2k_vres stub_quic_base(const char *ip, uint16_t port, const char *sni,
                               d2k_hello trigger, d2k_hello control, uint32_t mark) {
    (void)ip; (void)port; (void)sni; (void)trigger; (void)control; (void)mark;
    quic_base_calls++;
    d2k_vres r;
    memset(&r, 0, sizeof r);
    r.verdict = D2K_V_INCONCLUSIVE;
    r.base_blocked = base_blocked_answer;
    r.base.valid = 1; r.base.repeats = 3; r.base.ctl_pass = 3; r.base.ctl_marked = 1;
    r.base.direct_asked = 1; r.base.pass = base_blocked_answer ? 0 : 3;
    r.base.fail = 3 - r.base.pass; r.base.direct_marked = 1;
    snprintf(r.reason, sizeof r.reason, "подменённая QUIC-база");
    return r;
}
static d2k_vres stub_quic_seeded(const char *ip, uint16_t port, const char *sni,
                                 d2k_hello trigger, d2k_hello control, uint32_t mark,
                                 d2k_quic_arm *arm, const d2k_base_seed *seed) {
    quic_seeded_calls++;
    quic_seeded_ctl = seed ? seed->ctl_pass : -1;
    return stub_quic(ip, port, sni, trigger, control, mark, arm);
}

/* Коробка с одним планом и одной подтверждённой привязкой — фикстура своего
   найденного решения другой цели. split различает тексты планов. */
static void own_box(d2k_catalog *c, const char *box, char plan_id[40], unsigned split,
                    int successes, const char *target, uint8_t transport, uint8_t shape,
                    uint8_t family, int64_t confirmed, int64_t recheck) {
    char plan[256];
    if (transport == 17)
        snprintf(plan, sizeof plan,
                 "d2k-plan 1 1\nid 00000000000000000000000000000000\n"
                 "proto udp quic\npayload 1 aa%02x\n"
                 "fake payload=1 poison=0 repeats=1 gap_us=0 place=before\n"
                 "order forward\n", split & 0xff);
    else
        snprintf(plan, sizeof plan,
                 "d2k-plan 1 1\nid 00000000000000000000000000000000\n"
                 "proto tcp tls\nsplit payload_start +%u\norder forward\n", split);
    /* Идентификатор — из текста, тем же FNV-1a, что plan_ident планировщика:
       каталог роутера иначе не бывает. */
    uint64_t h = 1469598103934665603ULL;
    for (const char *q = plan; *q; q++) { h ^= (unsigned char)*q; h *= 1099511628211ULL; }
    snprintf(plan_id, 40, "plan-%08x", (unsigned)(h & 0xFFFFFFFFu));
    d2k_cat_box *nb = realloc(c->boxes, (c->n_boxes + 1) * sizeof *nb);
    CHECK(nb != NULL, "own_box: realloc");
    if (!nb) return;
    c->boxes = nb;
    d2k_cat_box *b = &c->boxes[c->n_boxes++];
    memset(b, 0, sizeof *b);
    snprintf(b->id, sizeof b->id, "%s", box);
    b->fp.method = D2K_FP_METHOD;
    b->fp.n_sig = 1;
    snprintf(b->fp.sig[0].kind, sizeof b->fp.sig[0].kind, "rst");
    b->fp.sig[0].ttl = (uint8_t)(60 + c->n_boxes);
    b->fp.sig[0].seen = 1;
    b->plans = calloc(1, sizeof *b->plans);
    b->binds = calloc(1, sizeof *b->binds);
    CHECK(b->plans && b->binds, "own_box: calloc");
    if (!b->plans || !b->binds) return;
    b->n_plans = 1;
    b->plans[0].enabled = 1;
    b->plans[0].successes = successes;
    snprintf(b->plans[0].id, sizeof b->plans[0].id, "%s", plan_id);
    snprintf(b->plans[0].proto, sizeof b->plans[0].proto, "%s", transport == 17 ? "quic" : "tls");
    b->plans[0].text = strdup(plan);
    b->n_binds = 1;
    d2k_cat_binding *bd = &b->binds[0];
    snprintf(bd->kind, sizeof bd->kind, "name");
    snprintf(bd->target, sizeof bd->target, "%s", target);
    snprintf(bd->plan_id, sizeof bd->plan_id, "%s", plan_id);
    bd->level = 3; bd->enabled = 1; bd->successes = successes;
    bd->confirmed = confirmed; bd->transport = transport; bd->family = family;
    bd->shape = shape; bd->verified_by = D2K_VERBY_PROBE; bd->input = D2K_INPUT_CLIENT;
    bd->recheck_since = recheck;
}

/* Сколько раз подстрока встречается в сказанном. */
static int said_count(const char *needle) {
    int n = 0;
    for (const char *p = saidbuf; (p = strstr(p, needle)) != NULL; p += strlen(needle)) n++;
    return n;
}

/* ECH OFFER В ПРИВЕТСТВИИ (задача 41). Расширение encrypted_client_hello
   типа outer со случайными config_id, enc и payload — ровно так выглядит и
   GREASE Chromium (RFC 9849 §6.2), и настоящее предложение: по байтам они
   неотличимы намеренно. Отличает их только то, чьё имя снаружи. */
static int ech_offer_hello(const char *name, uint8_t *out, size_t cap, size_t *len) {
    size_t n = 0;
    if (d2k_hello_from_profile(D2K_SHAPE_MODERN, name, out, cap, &n) != 0) return -1;
    size_t p = 9 + 2 + 32;
    p += 1 + out[p];
    p += 2 + ((size_t)out[p] << 8 | out[p + 1]);
    p += 1 + out[p];
    size_t ext_len_off = p;
    const size_t enc = 32, payload = 144, elen = 10 + enc + payload;
    if (n + 4 + elen > cap) return -1;
    uint8_t *e = out + n;
    e[0] = 0xfe; e[1] = 0x0d; e[2] = (uint8_t)(elen >> 8); e[3] = (uint8_t)elen;
    e[4] = 0; e[5] = 0; e[6] = 1; e[7] = 0; e[8] = 1; e[9] = 0x5a;
    e[10] = 0; e[11] = (uint8_t)enc;
    for (size_t i = 0; i < enc; i++) e[12 + i] = (uint8_t)(i * 7 + 3);
    e[12 + enc] = (uint8_t)(payload >> 8); e[13 + enc] = (uint8_t)payload;
    for (size_t i = 0; i < payload; i++) e[14 + enc + i] = (uint8_t)(i * 13 + 1);
    n += 4 + elen;
    size_t ext = ((size_t)out[ext_len_off] << 8 | out[ext_len_off + 1]) + 4 + elen;
    out[ext_len_off] = (uint8_t)(ext >> 8); out[ext_len_off + 1] = (uint8_t)ext;
    size_t hs = n - 9, rec = n - 5;
    out[6] = (uint8_t)(hs >> 16); out[7] = (uint8_t)(hs >> 8); out[8] = (uint8_t)hs;
    out[3] = (uint8_t)(rec >> 8); out[4] = (uint8_t)rec;
    *len = n;
    return 0;
}

/* HTTPS RR без сети: ECH есть у origin.ech.example (public_name
   ech-public.example) и у самого ech-public.example; у прочих — нет. */
static int ech_resolve_calls;
static int stub_ech_resolve(const char *origin, uint32_t mark, d2k_ech_config *cfg) {
    (void)mark;
    __atomic_add_fetch(&ech_resolve_calls, 1, __ATOMIC_SEQ_CST);
    if (!origin || !cfg) return -1;
    if (strcmp(origin, "origin.ech.example") && strcmp(origin, "ech-public.example")) return -1;
    memset(cfg, 0, sizeof *cfg);
    cfg->config_id = 0x5a;
    snprintf(cfg->public_name, sizeof cfg->public_name, "%s", "ech-public.example");
    return 0;
}

/* Повтор ECH-приветствия клиента (поле 04.10): что ему дали и что он ответил.
   replay_answer_ok — ServerHello на повтор (коробка пропустила), иначе
   тишина. Местный конец — тот же, что у stub_ver: событие применения
   теста ищет поток зонда по ver_answer_port. */
static int replay_calls;
static size_t replay_last_len;
static int replay_answer_ok = 1;
static d2k_ver_result stub_replay(int use_fd, const char *ip, uint16_t port,
                                  const uint8_t *hello, size_t len, int deadline_ms) {
    (void)ip; (void)port; (void)hello; (void)deadline_ms;
    if (use_fd >= 0) close(use_fd);
    __atomic_add_fetch(&replay_calls, 1, __ATOMIC_SEQ_CST);
    replay_last_len = len;
    d2k_ver_result r;
    memset(&r, 0, sizeof r);
    r.fd = -1; r.name_ok = -1; r.family = 4;
    memcpy(r.local_ip4, ver_local_ip4, 4);
    memcpy(r.local_addr, ver_local_ip4, 4);
    r.local_port = ver_answer_port;
    r.level = replay_answer_ok ? D2K_VER_HANDSHAKE : D2K_VER_TRANSPORT;
    r.replay_proof = replay_answer_ok;
    r.budget = D2K_BUDGET_NOT_APPLICABLE;
    snprintf(r.budget_note, sizeof r.budget_note, "подменённый повтор: пакеты не считаются");
    snprintf(r.reason, sizeof r.reason, "%s", replay_answer_ok
             ? "подменённый повтор: ServerHello" : "подменённый повтор: тишина");
    return r;
}

int main(int argc, char **argv) {
    d2k_sched_mark_fn saved_mark = d2k_sched_mark_hook;
    int voice_only = argc == 2 && strcmp(argv[1], "--voice-only") == 0;
    int rx_only = argc == 2 && strcmp(argv[1], "--rx-volume-only") == 0;
    int rst_only = argc == 2 && strcmp(argv[1], "--rst-only") == 0;
    int admission_only = argc == 2 && strcmp(argv[1], "--admission-only") == 0;
    int question_only = argc == 2 && strcmp(argv[1], "--question-only") == 0;
    int shape_only = argc == 2 && strcmp(argv[1], "--shape-only") == 0;
    int groups_only = argc == 2 && strcmp(argv[1], "--groups-only") == 0;
    int retire_only = argc == 2 && strcmp(argv[1], "--retire-only") == 0;
    int recheck_only = argc == 2 && strcmp(argv[1], "--recheck-only") == 0;
    int lifecycle_only = argc == 2 && strcmp(argv[1], "--lifecycle-only") == 0;
    int own_first_only = argc == 2 && strcmp(argv[1], "--own-first-only") == 0;
    int measured_only = argc == 2 && strcmp(argv[1], "--measured-only") == 0;
    int ech_only = argc == 2 && strcmp(argv[1], "--ech-only") == 0;
    if (argc > 1 && !voice_only && !rx_only && !rst_only && !admission_only && !question_only && !shape_only && !groups_only && !retire_only && !recheck_only && !lifecycle_only && !own_first_only && !measured_only && !ech_only) {
        fprintf(stderr, "usage: test_sched [--voice-only|--rst-only|--admission-only|--question-only|--retire-only|--recheck-only|--lifecycle-only|--own-first-only|--measured-only|--ech-only]\n");
        return 2;
    }
    /* Real default verifier, before replacing hooks: the Plan is scoped to
     * the reserved socket's port. Opening another socket defeats that scope. */
    {
        int lfd = socket(AF_INET, SOCK_STREAM, 0), fd = -1;
        struct sockaddr_in a;
        memset(&a, 0, sizeof a); a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        CHECK(lfd >= 0 && bind(lfd, (struct sockaddr *)&a, sizeof a) == 0 &&
              listen(lfd, 1) == 0, "default-verifier listener failed");
        socklen_t alen = sizeof a;
        CHECK(getsockname(lfd, (struct sockaddr *)&a, &alen) == 0, "listener address failed");
        uint16_t sport = 0;
        CHECK(d2k_props_bind(&fd, &sport) == 0, "reserve verifier socket failed");
        if (fd >= 0 && lfd >= 0) {
            d2k_ver_result r = d2k_sched_ver_hook(fd, "127.0.0.1", ntohs(a.sin_port),
                                                  6, "probe.example", 50, 0,
                                                  (uint8_t)D2K_SHAPE_MODERN);
            CHECK(r.fd == fd && r.local_port == ntohs(sport), "verifier replaced reserved socket");
            if (r.fd != fd) { close(fd); }
            d2k_verify_close(&r);
        }
        if (lfd >= 0) { close(lfd); }
    }
    d2k_sched_vol_hook = stub_vol;
    d2k_sched_tcp_hook = stub_tcp;
    d2k_sched_quic_hook = stub_quic;
    /* Зонд подтверждения тоже подменён: настоящий пошёл бы к 127.0.0.1 своим
       рукопожатием TLS 1.3, а стенд этого теста TLS не умеет — тест мерил бы
       стенд. */
    d2k_sched_ver_hook = stub_ver;
    d2k_sched_rx_ver_hook = stub_ver;
    d2k_sched_rx_gzip_ver_hook = stub_ver;
    d2k_sched_quic_path_ver_hook = stub_quic_path_ver;
    d2k_sched_mark_hook = stub_mark;
    d2k_sched_spawn_hook = stub_spawn;
    d2k_sched_cpu_hook = stub_cpu;
    d2k_sched_mem_hook = stub_mem;
    d2k_sched_ct_hook = stub_ct;

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        printf("ПРОВАЛ: socketpair не создался\n");
        return 1;
    }

    drain_fd = sv[1];
    {
        int fl = fcntl(drain_fd, F_GETFL, 0);
    if (fl >= 0) { (void)fcntl(drain_fd, F_SETFL, fl | O_NONBLOCK); }
    }

    d2k_catalog cat;
    memset(&cat, 0, sizeof cat);
    if (groups_only) {
        d2k_ver_result ech_direct = {0}; d2k_vol_result ech_volume = {0};
        ech_direct.fd = 7; ech_direct.ech_accepted=1; ech_direct.name_ok=1;
        ech_direct.level=D2K_VER_APPLICATION; ech_direct.body_complete=1;
        ech_direct.status=200;
        d2k_vres ech_result=d2k_sched_ech_baseline_result(&ech_direct,&ech_volume,"origin.example.com");
        CHECK(ech_result.verdict==D2K_V_CLEAR && ech_volume.rx_direct_complete,
              "authenticated complete direct ECH supplies the clear learner gate");
        ech_direct.ech_accepted=0;
        ech_result=d2k_sched_ech_baseline_result(&ech_direct,&ech_volume,"origin.example.com");
        CHECK(ech_result.verdict!=D2K_V_CLEAR && !ech_volume.rx_direct_complete,
              "rejected ECH cannot become a clean bypass observation");
        tcp_answer = D2K_V_PREFIX; ver_answer = D2K_VER_APPLICATION; ver_fail_first = 0;
        d2k_catalog c = {0};
        confirm_once(&c, sv[0], "rr-a.googlevideo.com", 40301);
        confirm_once(&c, sv[0], "rr-b.googlevideo.com", 40302);
        confirm_once(&c, sv[0], "rr-c.googlevideo.com", 40303);
        d2k_group_key key = {0}; key.transport = 6; key.family = 4; key.shape = 1;
        strcpy(key.probe_path, "/");
        const d2k_domain_group *g = d2k_group_match(c.groups, "rr-new.googlevideo.com", &key);
        CHECK(g && !strcmp(g->suffix, "googlevideo.com"), "three own blocking outcomes teach shared area");
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        tcp_calls = vol_calls = ver_calls = 0;
        d2k_ev h = ev_hello(6, 40304, "rr-new.googlevideo.com");
        d2k_sched_event(s, &h); spin(s, 5);
        CHECK(!d2k_sched_active(s) && !tcp_calls && !vol_calls && !ver_calls,
              "new member hello launches no measure or verification");
        CHECK(!binding_of(&c, "rr-new.googlevideo.com", 6), "new member creates no individual binding");
        drain(); forget_sent(); d2k_sched_sync(s); sync_out(s);
        CHECK(sent_command_count(D2K_CMD_SET_SUFFIX, NULL, 0) == 1, "restart sync installs learned suffix");
        CHECK(g && sent_has(g->plan_id), "suffix carries its own nonzero Plan ID");
        CHECK(d2k_sched_sync_pending(s), "suffix write waits for ACK");
        d2k_ev stale = {0}; stale.kind=D2K_EV_ACK; stale.code=D2K_CMD_SET_SUFFIX;
        stale.num=1u<<8; area_ack_id(&stale);
        skip_ahead(s, 6000); sync_out(s);
        CHECK(!d2k_sched_sync_pending(s), "lost area ACK ends bounded wait");
        c.groups->disabled=1; CHECK(!d2k_group_restore(c.groups), "disable learned areas");
        d2k_sched_sync(s); sync_out(s);
        CHECK(sent_command_count(D2K_CMD_DEL_SUFFIX,NULL,0)==1,
              "possibly installed rule is removed even when its install ACK was lost");
        d2k_ev removed={0}; removed.kind=D2K_EV_ACK; removed.code=D2K_CMD_DEL_SUFFIX;
        removed.num=1u<<8; area_ack_id(&removed);
        d2k_sched_event(s,&removed); sync_out(s);
        c.groups->disabled=0; CHECK(!d2k_group_restore(c.groups), "restore eligible family");
        g=d2k_group_match(c.groups,"rr-new.googlevideo.com",&key);
        d2k_sched_sync(s); sync_out(s);
        CHECK(sent_command_count(D2K_CMD_SET_SUFFIX, NULL, 0) == 2,
              "lost ACK can retry safely on next synchronization");
        d2k_sched_event(s,&stale); sync_out(s);
        CHECK(d2k_sched_sync_pending(s), "late ACK cannot confirm a newer area command");
        d2k_ev ack = {0}; ack.kind = D2K_EV_ACK; ack.code = D2K_CMD_SET_SUFFIX; ack.num = 1u << 8;
        area_ack_id(&ack);
        d2k_sched_event(s, &ack); sync_out(s);
        CHECK(!d2k_sched_sync_pending(s), "positive suffix ACK completes sync");
        h = ev_hello(6, 40308, "rr-fresh.googlevideo.com");
        d2k_sched_event(s, &h);
        d2k_ev fresh = ev_suspect(6, 40308);
        fresh.planned = D2K_LINK_PLANNED_NO;
        fresh.client_shape = D2K_SHAPE_MODERN;
        tcp_calls = vol_calls = ver_calls = 0;
        d2k_sched_event(s, &fresh); spin(s, 2);
        CHECK(!d2k_sched_active(s) && !tcp_calls && !vol_calls && !ver_calls,
              "fresh unplanned TLS13 family member inherits without starting a search");
        fresh.planned = D2K_LINK_PLANNED_YES;
        fresh.code = D2K_SUSPECT_SILENT;
        d2k_sched_event(s, &fresh);
        settle(s);
        CHECK(ver_calls > 0 && tcp_calls == 0 && vol_calls == 0,
              "inherited plan recovery verifies own family knowledge before full classification");
        char live_path[] = "/tmp/d2k-family-live-XXXXXX";
        int live_fd = mkstemp(live_path); CHECK(live_fd >= 0, "family live fixture");
        if (live_fd >= 0) {
            close(live_fd);
            CHECK(!d2k_sched_write_live(s, live_path, "catalog.json"), "family live write");
            FILE *live = fopen(live_path, "r"); char body[32768] = {0};
            if (live) { (void)!fread(body, 1, sizeof body-1, live); fclose(live); }
            CHECK(strstr(body, "\"groups\"") && strstr(body, "\"suffix\": \"googlevideo.com\"") &&
                  strstr(body, "\"active\": true"), "live exposes actual ACKed area, not individual inheritance proofs");
            unlink(live_path);
        }
        drain(); forget_sent(); d2k_sched_sync(s); sync_out(s);
        CHECK(!sent_command_count(D2K_CMD_SET_SUFFIX, NULL, 0) &&
              !sent_command_count(D2K_CMD_DEL_SUFFIX, NULL, 0), "unchanged group never withdrawn or resent");
        d2k_group_observation failed = {0};
        strcpy(failed.name, "rr-new.googlevideo.com"); strcpy(failed.plan_id, g->plan_id);
        failed.key = key; failed.evidence = D2K_GROUP_PLAN_FAILED; failed.at = g->at+1;
        CHECK(d2k_group_learn(c.groups, &failed) > 0, "targeted member failure recorded");
        drain(); forget_sent(); d2k_sched_sync(s); sync_out(s);
        CHECK(sent_command_count(D2K_CMD_SET_BYPASS, NULL, 0) == 1 &&
              !sent_command_count(D2K_CMD_DEL_SUFFIX, NULL, 0), "one exception does not withdraw family");
        ack.code = D2K_CMD_SET_BYPASS; ack.num = D2K_ACK_NO_ROOM;
        area_ack_id(&ack);
        d2k_sched_event(s, &ack); sync_out(s);
        CHECK(!d2k_sched_sync_pending(s), "negative area ACK ends sync explicitly");
        drain(); forget_sent(); d2k_sched_sync(s); sync_out(s);
        CHECK(sent_command_count(D2K_CMD_SET_BYPASS, NULL, 0) == 1, "negative ACK was not remembered as installed");
        ack.num = 1u << 8; area_ack_id(&ack); d2k_sched_event(s, &ack); sync_out(s);
        CHECK(d2k_group_match(c.groups, "rr-other.googlevideo.com", &key), "other members retain learned plan");
        tcp_answer = D2K_V_CLEAR; vol_direct_complete = 1;
        h = ev_hello(6, 40305, "clean.googlevideo.com"); d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40305); d2k_sched_event(s, &su); settle(s);
        CHECK(d2k_group_match(c.groups, "rr-other.googlevideo.com", &key), "direct clean exception preserves family");
        CHECK(!d2k_group_match(c.groups, "clean.googlevideo.com", &key), "complete direct application records bypass exception");
        vol_direct_complete = 0;
        h = ev_hello(6, 40306, "unfit.googlevideo.com"); d2k_sched_event(s, &h);
        d2k_ev refusal = h; refusal.kind = D2K_EV_REFUSED; refusal.code = D2K_REFUSE_TOO_LONG;
        refusal.client_shape = 1;
        memset(refusal.plan_id, 0, sizeof refusal.plan_id);
        memcpy(refusal.plan_id, failed.plan_id, strlen(failed.plan_id));
        refusal.client_shape=2; d2k_sched_event(s,&refusal);
        CHECK(d2k_group_match(c.groups,"unfit.googlevideo.com",&key),
              "refusal in TLS12 cannot exclude the same host from TLS13 family");
        refusal.client_shape=1;
        d2k_sched_event(s, &refusal);
        CHECK(d2k_sched_active(s) > 0, "real inherited plan refusal starts targeted diagnosis");
        CHECK(!d2k_group_match(c.groups, "unfit.googlevideo.com", &key),
              "permanent inherited execution refusal persists exact exception");
        CHECK(d2k_group_restore(c.groups)==0 &&
              !d2k_group_match(c.groups, "unfit.googlevideo.com", &key) &&
              d2k_group_match(c.groups, "rr-other.googlevideo.com", &key),
              "runtime failure exception survives restore without losing siblings");
        /* Task 22: a family exception never overrides a member's own exact
           confirmed plan. Settle pending areas first, then fail the group
           plan for rr-b, which holds its own confirmed exact binding. */
        drain(); forget_sent(); d2k_sched_sync(s); sync_out(s);
        for(unsigned i=0;i<8;i++) {
            ack.code=last_area_command(); if(!ack.code) break;
            ack.num=1u<<8; area_ack_id(&ack); d2k_sched_event(s,&ack);
            forget_sent(); sync_out(s);
        }
        {
            const d2k_cat_binding *own = binding_of(&c, "rr-b.googlevideo.com", 6);
            CHECK(own && own->level >= 3 && !own->recheck_since && own->shape == key.shape &&
                  !strcmp(own->plan_id, g->plan_id),
                  "fixture: member holds own exact confirmed binding with the group plan");
            d2k_group_observation own_fail = {0};
            strcpy(own_fail.name, "rr-b.googlevideo.com"); strcpy(own_fail.plan_id, g->plan_id);
            own_fail.key = key; own_fail.evidence = D2K_GROUP_PLAN_FAILED; own_fail.at = g->at+2;
            CHECK(d2k_group_learn(c.groups, &own_fail) > 0, "member failure of group plan recorded");
            drain(); forget_sent(); d2k_sched_sync(s); sync_out(s);
            CHECK(!sent_command_count(D2K_CMD_SET_BYPASS, NULL, 0),
                  "family bypass is never installed over a member's own exact confirmed plan");
            /* A foreign client's permanent execution refusal of the group
               plan on a member with its own confirmed exact plan is about
               that client's flow, not evidence against the plan (§7): it must
               not stale the member's vote nor exclude it from the family. */
            h = ev_hello(6, 40309, "rr-a.googlevideo.com"); d2k_sched_event(s, &h);
            d2k_ev foreign = h; foreign.kind = D2K_EV_REFUSED; foreign.code = D2K_REFUSE_TOO_LONG;
            foreign.client_shape = 1;
            memset(foreign.plan_id, 0, sizeof foreign.plan_id);
            memcpy(foreign.plan_id, g->plan_id, strlen(g->plan_id));
            d2k_sched_event(s, &foreign);
            int stale_vote = 0;
            for (size_t i = 0; i < c.groups->n_observations; i++)
                if (!strcmp(c.groups->observations[i].name, "rr-a.googlevideo.com") &&
                    (c.groups->observations[i].evidence & D2K_GROUP_PLAN_FAILED)) stale_vote = 1;
            CHECK(d2k_group_match(c.groups, "rr-a.googlevideo.com", &key) && !stale_vote,
                  "foreign refusal on a member with own exact plan records no family failure");
            drain(); forget_sent(); d2k_sched_sync(s); sync_out(s);
            CHECK(!sent_command_count(D2K_CMD_SET_BYPASS, NULL, 0),
                  "foreign refusal installs no bypass over own exact plan");
        }
        d2k_sched_free(s);
        {
            /* Final review #6: a legacy grandfathered (shape 0) confirmed
               name binding is the member's own exact plan for any TCP TLS
               shape; a family exception must not be installed over it. */
            d2k_catalog cg = {0};
            static const char *gm[4] = {"a.gf.net", "b.gf.net", "c.gf.net", "d.gf.net"};
            tcp_answer = D2K_V_PREFIX; ver_answer = D2K_VER_APPLICATION; ver_fail_first = 0;
            int gf_sendbuf = 256 * 1024;
            (void)setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &gf_sendbuf, sizeof gf_sendbuf);
            for (int i = 0; i < 4; i++) confirm_once(&cg, sv[0], gm[i], (uint16_t)(40391 + i));
            const d2k_domain_group *gg = d2k_group_match(cg.groups, "new.gf.net", &key);
            d2k_cat_binding *legacy = binding_mut(&cg, "d.gf.net", 6);
            CHECK(gg && legacy && legacy->level >= 3 && !strcmp(legacy->plan_id, gg->plan_id),
                  "fixture: gf family learned and member d holds own confirmed binding");
            if (gg && legacy) {
                legacy->shape = 0;
                d2k_sched *sg = d2k_sched_new(&cg, sv[0], 0x2d);
                drain(); forget_sent(); d2k_sched_sync(sg); sync_out(sg);
                d2k_ev gack = {0}; gack.kind = D2K_EV_ACK;
                for (unsigned i = 0; i < 8; i++) {
                    gack.code = last_area_command(); if (!gack.code) break;
                    gack.num = 1u << 8; area_ack_id(&gack); d2k_sched_event(sg, &gack);
                    forget_sent(); sync_out(sg);
                }
                d2k_group_observation gf_fail = {0};
                strcpy(gf_fail.name, "d.gf.net"); strcpy(gf_fail.plan_id, gg->plan_id);
                gf_fail.key = key; gf_fail.evidence = D2K_GROUP_PLAN_FAILED; gf_fail.at = gg->at + 1;
                CHECK(d2k_group_learn(cg.groups, &gf_fail) > 0, "legacy member failure recorded");
                CHECK(d2k_group_match(cg.groups, "new.gf.net", &key) != NULL,
                      "fixture: one member failure keeps the family");
                drain(); forget_sent(); d2k_sched_sync(sg); sync_out(sg);
                CHECK(!sent_command_count(D2K_CMD_SET_BYPASS, NULL, 0),
                      "family bypass installed over a grandfathered own exact name binding");
                d2k_sched_free(sg);
            }
            d2k_catalog_free(&cg);
        }
        s=d2k_sched_new(&c,sv[0],0x2d); spin(s,1);
        tcp_block_until_stop=1;
        for (uint16_t port=40311; port<40313; port++) {
            h=ev_hello(6,port,port==40311?"busy-a.example":"busy-b.example");
            d2k_sched_event(s,&h); su=ev_suspect(6,port); d2k_sched_event(s,&su);
        }
        for (uint16_t port=40314; port<40317; port++) {
            const char *name=port==40314?"tls12.googlevideo.com":
                port==40315?"tls13.googlevideo.com":"unknown.googlevideo.com";
            h=ev_hello(6,port,name); d2k_sched_event(s,&h);
            if (port!=40316) {
                d2k_ev shape;
                CHECK(tls_shape_event(&shape,name,port==40314?D2K_SHAPE_LEGACY:D2K_SHAPE_MODERN)==0,
                      "queued TLS shape fixture");
                memcpy(shape.low_ip,h.low_ip,16); memcpy(shape.high_ip,h.high_ip,16);
                shape.low_port=h.low_port; shape.high_port=h.high_port;
                d2k_sched_event(s,&shape);
            }
            su=ev_suspect(6,port); su.planned=D2K_LINK_PLANNED_NO; d2k_sched_event(s,&su);
        }
        h=ev_hello(6,40317,"tls12.googlevideo.com"); d2k_sched_event(s,&h);
        d2k_ev later_shape;
        CHECK(tls_shape_event(&later_shape,h.name,D2K_SHAPE_MODERN)==0,"later TLS13 fixture");
        memcpy(later_shape.low_ip,h.low_ip,16); memcpy(later_shape.high_ip,h.high_ip,16);
        later_shape.low_port=h.low_port; later_shape.high_port=h.high_port;
        d2k_sched_event(s,&later_shape);
        drain(); forget_sent(); d2k_sched_sync(s); sync_out(s);
        for(unsigned i=0;i<8;i++) {
            ack.code=last_area_command(); if(!ack.code) break;
            ack.num=1u<<8; area_ack_id(&ack); d2k_sched_event(s,&ack);
            forget_sent(); sync_out(s);
        }
        spin(s,2);
        CHECK(d2k_sched_active(s)==4,
              "retire only flow-proven TLS13 queue; preserve TLS12 and unknown after later same-name snapshot");
        tcp_block_until_stop=0;
        d2k_sched_free(s); d2k_catalog_free(&c);
        /* Two historically working family plans. An applied first candidate
           fails its own verifier; the second succeeds without classification. */
        d2k_catalog recovery={0};
        int recovery_sendbuf=256*1024;
        CHECK(!setsockopt(sv[0],SOL_SOCKET,SO_SNDBUF,&recovery_sendbuf,sizeof recovery_sendbuf),
              "family recovery socket must hold one bounded sync batch before test receiver drains it");
        tcp_answer=D2K_V_PREFIX; tcp_found_arm=0; ver_fail_first=0;
        confirm_once(&recovery,sv[0],"a.recovery.net",40501);
        confirm_once(&recovery,sv[0],"b.recovery.net",40502);
        confirm_once(&recovery,sv[0],"c.recovery.net",40503);
        confirm_once(&recovery,sv[0],"d.recovery.net",40504);
        char primary[40];
        snprintf(primary,sizeof primary,"%s",binding_of(&recovery,"a.recovery.net",6)->plan_id);
        d2k_catalog alternate_catalog={0};
        tcp_found_arm=1; tcp_owns_search=1;
        confirm_once(&alternate_catalog,sv[0],"e.recovery.net",40505);
        confirm_once(&alternate_catalog,sv[0],"f.recovery.net",40506);
        confirm_once(&alternate_catalog,sv[0],"g.recovery.net",40507);
        char alternate[40];
        snprintf(alternate,sizeof alternate,"%s",binding_of(&alternate_catalog,"g.recovery.net",6)->plan_id);
        CHECK(strcmp(primary,alternate),"recovery fixture needs different own confirmed plans");
        d2k_cat_box *merged=realloc(recovery.boxes,
            (recovery.n_boxes+alternate_catalog.n_boxes)*sizeof *merged);
        CHECK(merged!=NULL,"merge independently measured family alternatives");
        if(!merged) return 1;
        recovery.boxes=merged;
        memcpy(recovery.boxes+recovery.n_boxes,alternate_catalog.boxes,
               alternate_catalog.n_boxes*sizeof *merged);
        recovery.n_boxes+=alternate_catalog.n_boxes;
        for(size_t i=0;i<alternate_catalog.groups->n_observations;i++)
            CHECK(d2k_group_learn(recovery.groups,&alternate_catalog.groups->observations[i])>0,
                  "merge own independently confirmed sibling observations");
        free(alternate_catalog.boxes); alternate_catalog.boxes=NULL; alternate_catalog.n_boxes=0;
        d2k_catalog_free(&alternate_catalog);
        tcp_found_arm=0; tcp_owns_search=0;
        s=d2k_sched_new(&recovery,sv[0],0x2d);
        drain(); forget_sent(); d2k_sched_sync(s); sync_out(s);
        ack.code=D2K_CMD_SET_SUFFIX; ack.num=1u<<8; area_ack_id(&ack);
        d2k_sched_event(s,&ack); sync_out(s);
        tcp_calls=vol_calls=ver_calls=0; ver_fail_first=1; ver_answer_port=40508;
        h=ev_hello(6,40508,"new.recovery.net"); d2k_sched_event(s,&h);
        su=ev_suspect(6,40508); su.planned=D2K_LINK_PLANNED_YES;
        su.code=D2K_SUSPECT_SILENT; su.client_shape=D2K_SHAPE_MODERN;
        d2k_sched_event(s,&su);
        for(int i=0;i<800;i++) {
            tick_once(s);
            d2k_ev applied=ev_applied(6,40508); d2k_sched_event(s,&applied);
        }
        const d2k_cat_binding *recovered=binding_of(&recovery,"new.recovery.net",6);
        CHECK(recovered && !strcmp(recovered->plan_id,alternate),
              "failed inherited plan must recover under distinct confirmed sibling alternative");
        CHECK(ver_calls==2 && !tcp_calls && !vol_calls,
              "family recovery must not classify or synthesize before two saved alternatives");
        g=d2k_group_match(recovery.groups,"next.recovery.net",&key);
        CHECK(g && !strcmp(g->plan_id,alternate),
              "actual applied verifier failure must change family election for future members");
        CHECK(binding_of(&recovery,"a.recovery.net",6) &&
              !strcmp(binding_of(&recovery,"a.recovery.net",6)->plan_id,primary),
              "failure on new family member must preserve old individual successes");
        d2k_sched_free(s); ver_fail_first=0;
        s=d2k_sched_new(&recovery,sv[0],0x2d);
        drain(); forget_sent(); d2k_sched_sync(s); sync_out(s);
        ack.code=D2K_CMD_SET_SUFFIX; ack.num=1u<<8; area_ack_id(&ack);
        d2k_sched_event(s,&ack); sync_out(s);
        tcp_calls=vol_calls=ver_calls=0; ver_answer_port=40509;
        h=ev_hello(6,40509,"new.recovery.net"); d2k_sched_event(s,&h);
        su=ev_suspect(6,40509); su.planned=D2K_LINK_PLANNED_YES;
        su.code=D2K_SUSPECT_SILENT; su.client_shape=D2K_SHAPE_MODERN;
        d2k_sched_event(s,&su); settle(s);
        CHECK(ver_calls>0 && !tcp_calls && !vol_calls,
              "existing individual family members must also recover from saved family plans first");
        d2k_sched_free(s);
        s=d2k_sched_new(&recovery,sv[0],0x2d);
        d2k_sched_set_say(s,collect_say,NULL);
        drain(); forget_sent(); d2k_sched_sync(s); sync_out(s);
        ack.code=D2K_CMD_SET_SUFFIX; ack.num=1u<<8; area_ack_id(&ack);
        d2k_sched_event(s,&ack); sync_out(s);
        tcp_answer=D2K_V_CLEAR; tcp_wait_until_stop=1; tcp_release_waiters=0;
        for(uint16_t port=40511;port<40513;port++) {
            h=ev_hello(6,port,port==40511?"busy-one.example":"busy-two.example");
            d2k_sched_event(s,&h); su=ev_suspect(6,port); d2k_sched_event(s,&su);
        }
        h=ev_hello(6,40513,"fresh-research.example"); d2k_sched_event(s,&h);
        su=ev_suspect(6,40513); d2k_sched_event(s,&su);
        h=ev_hello(6,40514,"priority.recovery.net"); d2k_sched_event(s,&h);
        su=ev_suspect(6,40514); su.planned=D2K_LINK_PLANNED_YES;
        su.client_shape=D2K_SHAPE_MODERN; d2k_sched_event(s,&su);
        tcp_release_waiters=1; spin(s,40); tcp_wait_until_stop=0;
        saidbuf[0]=0;
        skip_ahead(s,15000); spin(s,100);
        /* Порядок, а не окно времени: сколько задач успеет стартовать за 100
           тиков, зависит от SCHED_START_GAP_MS (1000→250 мс сломало прежнее
           «fresh ещё не выпущен»). Свойство — семейное восстановление
           выпускается РАНЬШЕ старой несвязанной классификации. */
        const char *prio_line = strstr(saidbuf, "по priority.recovery.net ожидание в очереди");
        const char *fresh_line = strstr(saidbuf, "по fresh-research.example ожидание в очереди");
        CHECK(prio_line && (!fresh_line || prio_line < fresh_line),
              "saved family recovery must precede older unrelated queued classification");
        d2k_sched_free(s); tcp_answer=D2K_V_PREFIX;
        /* Задача 44: неуспех зонда из-за НАШЕГО предела чтения при применённом
           плане не засчитывается плану семьи как провал на проводе; тот же
           неуспех без признака предела — засчитывается (контроль). */
        for (int limit = 1; limit >= 0; limit--) {
            const char *nm = limit ? "lim.recovery.net" : "ctl.recovery.net";
            uint16_t pt = limit ? 40519 : 40520;
            s=d2k_sched_new(&recovery,sv[0],0x2d);
            drain(); forget_sent(); d2k_sched_sync(s); sync_out(s);
            ack.code=D2K_CMD_SET_SUFFIX; ack.num=1u<<8; area_ack_id(&ack);
            d2k_sched_event(s,&ack); sync_out(s);
            tcp_calls=vol_calls=ver_calls=0; ver_fail_first=1; ver_local_limit=limit;
            ver_answer_port=pt;
            h=ev_hello(6,pt,nm); d2k_sched_event(s,&h);
            su=ev_suspect(6,pt); su.planned=D2K_LINK_PLANNED_YES;
            su.code=D2K_SUSPECT_SILENT; su.client_shape=D2K_SHAPE_MODERN;
            d2k_sched_event(s,&su);
            for(int i=0;i<800;i++) {
                tick_once(s);
                d2k_ev applied=ev_applied(6,pt); d2k_sched_event(s,&applied);
            }
            int failed_votes=0;
            for(size_t i=0;i<recovery.groups->n_observations;i++)
                if(!strcmp(recovery.groups->observations[i].name,nm) &&
                   (recovery.groups->observations[i].evidence&D2K_GROUP_PLAN_FAILED)) failed_votes++;
            if(limit) CHECK(ver_calls>=1 && failed_votes==0,
                  "verifier failure from our own reader limit is not recorded as a plan failure");
            else CHECK(ver_calls>=1 && failed_votes>=1,
                  "control: the same verifier failure from the wire is recorded as a plan failure");
            d2k_sched_free(s); ver_fail_first=0; ver_local_limit=0;
        }
        d2k_catalog_free(&recovery);
        d2k_catalog qc = {0};
        quic_answer = D2K_V_OPAQUE;
        confirm_transport(&qc, sv[0], "q-a.googlevideo.com", 40401, 17);
        confirm_transport(&qc, sv[0], "q-b.googlevideo.com", 40402, 17);
        confirm_transport(&qc, sv[0], "q-c.googlevideo.com", 40403, 17);
        d2k_group_key qkey = {0}; qkey.transport=17; qkey.family=4; qkey.shape=3;
        strcpy(qkey.probe_path,"/");
        CHECK(d2k_group_match(qc.groups,"q-new.googlevideo.com",&qkey),
              "three own QUIC outcomes teach their own family, not TCP's");
        s=d2k_sched_new(&qc,sv[0],0x2d); spin(s,1);
        tcp_block_until_stop=1; tcp_calls=quic_calls=0;
        for (uint16_t port=40411; port<40413; port++) {
            d2k_ev busy=ev_hello(6,port,port==40411?"busy-a.example":"busy-b.example");
            d2k_sched_event(s,&busy);
            d2k_ev suspect=ev_suspect(6,port); d2k_sched_event(s,&suspect);
        }
        h=ev_hello(17,40414,"q-new.googlevideo.com"); d2k_sched_event(s,&h);
        su=ev_suspect(17,40414); su.planned=D2K_LINK_PLANNED_NO;
        d2k_sched_event(s,&su);
        h=ev_hello(17,40415,"q-failed.googlevideo.com"); d2k_sched_event(s,&h);
        su=ev_suspect(17,40415); su.planned=D2K_LINK_PLANNED_NO;
        d2k_sched_event(s,&su);
        CHECK(d2k_sched_active(s)==4,"uncovered QUIC suspicions are queued before area ACK");
        drain(); forget_sent(); d2k_sched_sync(s); sync_out(s);
        ack.code=D2K_CMD_SET_SUFFIX; ack.num=1u<<8; area_ack_id(&ack);
        d2k_sched_event(s,&ack);
        su.planned=D2K_LINK_PLANNED_YES; d2k_sched_event(s,&su);
        spin(s,2);
        CHECK(d2k_sched_active(s)==3 && quic_calls==0,
              "same-tick family ACK retires old unplanned queue but preserves later inherited-plan failure");
        char queued_live[]="/tmp/d2k-family-queues-XXXXXX";
        int queued_fd=mkstemp(queued_live);
        CHECK(queued_fd>=0,"queue retirement fixture");
        if (queued_fd>=0) {
            close(queued_fd); d2k_sched_write_live(s,queued_live,"catalog.json");
            FILE *live=fopen(queued_live,"r"); char body[32768]={0};
            if(live){(void)!fread(body,1,sizeof body-1,live);fclose(live);}
            CHECK(!strstr(body,"q-new.googlevideo.com") && strstr(body,"q-failed.googlevideo.com"),
                  "retirement must remove the unplanned name, not the later failed inherited flow");
            unlink(queued_live);
        }
        CHECK(!binding_of(&qc,"q-new.googlevideo.com",17),"queue adoption creates no exact enrollment");
        tcp_block_until_stop=0;
        d2k_sched_free(s); d2k_catalog_free(&qc); close(sv[0]); close(sv[1]);
        return fails ? 1 : 0;
    }
    uint8_t question_prev_id[D2K_PLAN_ID_LEN] = {0};
    if (rx_only) { goto rx_volume_tests; }
    if (question_only) { goto question_test; }
    if (retire_only) { goto retire_test; }
    if (recheck_only) { goto recheck_test; }
    if (lifecycle_only) { goto lifecycle_test; }
    if (own_first_only) { goto own_first_test; }
    if (measured_only) { goto measured_test; }
    if (shape_only) { goto shape_test; }
    {
        d2k_catalog empty = {0};
        d2k_sched *s = d2k_sched_new(&empty, sv[0], 0x2d);
        /* Each family starts its own direct classifier; an address/name
           mismatch is still discarded rather than attached to either task. */
        d2k_ev h4 = ev_hello(6, 41001, "dual.example");
        h4.family = 4;
        d2k_sched_event(s, &h4);
        d2k_ev h6 = h4;
        h6.family = 6;
        CHECK(inet_pton(AF_INET6, "2001:db8::1", h6.low_ip) == 1, "IPv6 low fixture");
        CHECK(inet_pton(AF_INET6, "2001:db8::2", h6.high_ip) == 1, "IPv6 high fixture");
        d2k_sched_event(s, &h6);
        d2k_ev r4 = h4, r6 = h6;
        r4.kind = r6.kind = D2K_EV_SUSPECT;
        r4.code = r6.code = D2K_SUSPECT_RST;
        r4.name[0] = r6.name[0] = 0;
        d2k_sched_event(s, &r4);
        d2k_sched_event(s, &r6);
        CHECK(d2k_sched_active(s) == 2, "IPv4/IPv6 direct checks were incorrectly merged");
        /* Same IPv6 /32 but distinct endpoints: must not recall dual.example. */
        d2k_ev other = r6;
        other.low_ip[15] = 3;
        d2k_sched_event(s, &other);
        CHECK(d2k_sched_active(s) == 2, "IPv6 name recall compares all 128 bits");
        h6.high_port++;
        d2k_sched_event(s, &h6);
        r6.high_port++;
        d2k_sched_event(s, &r6);
        CHECK(d2k_sched_active(s) == 2, "repeat RST created a duplicate IPv6 classifier");
        d2k_sched_free(s);
        d2k_catalog_free(&empty);
    }
    if (voice_only) { goto voice_only_run; }
    if (admission_only) { goto admission_only_run; }

    /* ECH OFFER: GREASE ОТДЕЛЬНО ОТ НАСТОЯЩЕГО (задача 41).
     *
     * Поле 02.10.2026, Discord (Electron/Chromium): приветствие discord.com
     * несло расширение encrypted_client_hello — это GREASE (RFC 9849 §6.2):
     * внешнее имя и есть настоящее имя, конфигурации ECH у клиента нет.
     * Поиск «с ECH offer» после этого молчал 5+ минут. Прежний рабочий поток
     * гасил ech_offer и мерил приветствием, а цикл, сравнив форму снимка
     * (ECH) с формой вопроса (TLS 1.3), выбрасывал ГОТОВЫЙ полный прогон и
     * запускал его заново теми же байтами — минуты полного «Поиска по
     * домену» вдвое и ни строки в журнале. Настоящий ECH (внешнее имя —
     * public_name конфигурации), напротив, мерился обычным приветствием
     * внешнего имени: cloudflare-ech.com «чисто» — не тот вопрос. */
    {
        uint8_t ech_bytes[2048]; size_t ech_len = 0;
        for (int mode = 0; mode < 3; mode++) {
            const char *nm = mode == 0 ? "grease.ech.example" :
                             mode == 1 ? "ech-public.example" : "grease2.ech.example";
            d2k_catalog empty = {0};
            d2k_sched *s = d2k_sched_new(&empty, sv[0], 0x2d);
            d2k_sched_set_say(s, collect_say, NULL);
            saidbuf[0] = '\0'; sent_len = 0;
            tcp_calls = 0; tcp_last_wire = 0; ech_resolve_calls = 0;
            tcp_answer = D2K_V_CLEAR;
            d2k_sched_ech_resolve_hook = stub_ech_resolve;
            CHECK(ech_offer_hello(nm, ech_bytes, sizeof ech_bytes, &ech_len) == 0 &&
                  d2k_hello_ech_offer(ech_bytes, ech_len, NULL) == 1,
                  "ECH: приветствие с ECH offer не собралось");
            if (mode == 2) {
                /* Свидетель на том же адресе есть, но его public_name — не
                   внешнее имя этого приветствия: это не доказательство ECH. */
                d2k_ev w = ev_hello(6, 41199, "origin.ech.example");
                d2k_sched_event(s, &w);
            }
            d2k_ev h = ev_hello(6, (uint16_t)(41100 + mode), nm);
            d2k_sched_event(s, &h);
            d2k_ev sh; memset(&sh, 0, sizeof sh);
            sh.kind = D2K_EV_SHAPE; sh.transport = 6;
            memcpy(sh.shape, ech_bytes, ech_len); sh.shape_len = ech_len;
            d2k_sched_event(s, &sh);
            d2k_ev su = ev_suspect(6, (uint16_t)(41100 + mode));
            d2k_sched_event(s, &su);
            settle(s);
            if (mode != 1) {
                CHECK(tcp_calls == 1,
                      "ECH: GREASE-приветствие — полный поиск выброшен и повторён теми же байтами");
                CHECK(tcp_last_wire == ech_len, "ECH: GREASE мерился не байтами клиента");
                CHECK(!said("повторяю поиск"), "ECH: GREASE перезапустил готовый поиск");
                CHECK(said("GREASE"), "ECH: GREASE не назван в журнале");
                CHECK(said("напрямую проходит"), "ECH: GREASE-поиск не дошёл до итога");
            } else {
                /* ПОЛЕ 04.10.2026, Chrome → Cloudflare: свидетеля нет — мерим
                   байтами самого клиента (его ECH-приветствие повтором на
                   тот же адрес), а не обычным приветствием внешнего имени.
                   Повтор проходит — обходить нечего, плана нет. */
                CHECK(tcp_calls == 1 && tcp_last_wire == ech_len,
                      "ECH replay: без свидетеля база не мерилась байтами клиента");
                CHECK(said("байтами клиента"), "ECH replay: замер повтором не назван в журнале");
                CHECK(said("напрямую проходит"), "ECH replay: проходящий повтор не дал «обходить нечего»");
                CHECK(!said("ПОДТВЕРЖДЕНО") && total_bindings(&empty) == 0,
                      "ECH replay: проходящий повтор завёл план");
                /* Повтор подозрения в окне не заводит тот же опыт. */
                saidbuf[0] = '\0';
                d2k_ev h2 = ev_hello(6, 41150, nm);
                d2k_sched_event(s, &h2);
                d2k_ev su2 = ev_suspect(6, 41150);
                d2k_sched_event(s, &su2);
                settle(s);
                CHECK(tcp_calls == 1 && !said("начинаю поиск"),
                      "ECH replay: «напрямую проходит» не отложило повтор");
            }
            if (mode == 2)
                CHECK(ech_resolve_calls >= 2, "ECH: свидетель на том же адресе не проверен по HTTPS RR");
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&empty);
        }
        d2k_sched_ech_resolve_hook = d2k_ech_resolve;
        tcp_answer = D2K_V_OPAQUE;
    }

    /* ПОЛЕ 04.10.2026, rutracker в Chrome: ECH-привязка внешнего имени
     * cloudflare-ech.com со свидетелем static.rutracker.cc подтверждена по
     * IPv6, а Chrome пошёл тем же ECH по IPv4 — «своего свидетеля нет — не
     * проверено», и сайт не открывался. Свидетель — имя origin с этой
     * ECH-конфигурацией; к IP-семье он не привязан (HTTPS RR перепроверяется
     * при каждом поиске), семья — только у самой привязки. */
    {
        const char *nm = "ech-public.example";
        d2k_catalog c = {0};
        char pid[40];
        own_box(&c, "box-ech-v6", pid, 2, 2, nm, 6, D2K_LINK_SHAPE_ECH_TCP, 6, 1790000000, 0);
        if (c.n_boxes && c.boxes[0].n_binds)
            snprintf(c.boxes[0].binds[0].ech_origin, sizeof c.boxes[0].binds[0].ech_origin,
                     "%s", "origin.ech.example");
        d2k_sched_ech_resolve_hook = stub_ech_resolve;
        d2k_sched_replay_ver_hook = stub_replay; replay_calls = 0;
        tcp_answer = D2K_V_CLEAR; tcp_calls = 0;
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        uint8_t eb[2048]; size_t el = 0;
        CHECK(ech_offer_hello(nm, eb, sizeof eb, &el) == 0 &&
              d2k_hello_ech_offer(eb, el, NULL) == 1, "ECH cross-family: fixture");
        d2k_ev h = ev_hello(6, 41180, nm); d2k_sched_event(s, &h);   /* IPv4 */
        d2k_ev sh; memset(&sh, 0, sizeof sh);
        sh.kind = D2K_EV_SHAPE; sh.transport = 6;
        memcpy(sh.shape, eb, el); sh.shape_len = el;
        d2k_sched_event(s, &sh);
        d2k_ev su = ev_suspect(6, 41180); d2k_sched_event(s, &su);
        settle(s);
        CHECK(said("собственный witness: origin.ech.example"),
              "ECH cross-family: свидетель ECH-привязки IPv6 не подхвачен для IPv4");
        CHECK(replay_calls == 0 && tcp_calls == 0 && !said("байтами клиента"),
              "ECH cross-family: при известном свидетеле пошёл повтор приветствия клиента");
        CHECK(!said("своего свидетеля нет") && !said("своего ECH-свидетеля нет"),
              "ECH cross-family: IPv4 объявлен «не проверено» при известном свидетеле");
        if (fails) fprintf(stderr, "%s\n", saidbuf);
        d2k_sched_free(s); d2k_catalog_free(&c);
        d2k_sched_ech_resolve_hook = d2k_ech_resolve;
        tcp_answer = D2K_V_OPAQUE;
    }

    /* ПОЛЕ 04.10.2026: свидетель находился случайно — кандидатами были
     * только 4 последние подтверждённые TCP-привязки, и static.rutracker.cc
     * выпадал из них по мере роста каталога (00:11 «не проверено», 00:22
     * найден, когда его переподтвердили). (r) Свидетель в каталоге старше
     * шести других привязок — всё равно найден. (f) Свежая установка:
     * каталог пуст, но имя с той же ECH-конфигурацией недавно видено
     * открытым текстом на ДРУГОМ адресе — оно и свидетель (своё
     * наблюдение, не список). (c) Имя без ECH-конфигурации второй раз по
     * HTTPS RR не спрашивается. */
    /* (q) ПОЛЕ 04.10.2026, чистый каталог: свидетель rua.gr (HTTPS RR даёт
     * ту же конфигурацию cloudflare-ech.com) был в каталоге, но 32 места
     * кандидатов заняли имена, виденные открытым текстом на ДРУГИХ адресах,
     * — до своих привязок очередь не дошла, и d2kc сказал «своего
     * ECH-свидетеля нет». Своё подтверждённое знание (любой транспорт)
     * идёт раньше случайных имён чужих адресов. */
    for (int mode = 0; mode < 3; mode++) {
        const char *nm = "ech-public.example";
        d2k_catalog c = {0};
        char pid[40];
        if (mode == 2)
            own_box(&c, "box-wit-quic", pid, 2, 2, "origin.ech.example", 17, D2K_LINK_SHAPE_QUIC, 4,
                    1780000000, 0);
        if (mode == 0) {
            own_box(&c, "box-wit-old", pid, 2, 2, "origin.ech.example", 6, D2K_SHAPE_MODERN, 4,
                    1780000000, 0);
            for (int k = 0; k < 6; k++) {
                char bn[32], nn[64];
                snprintf(bn, sizeof bn, "box-new-%d", k);
                snprintf(nn, sizeof nn, "newer%d.example", k);
                own_box(&c, bn, pid, (unsigned)(3 + k), 2, nn, 6, D2K_SHAPE_MODERN, 4,
                        1790000000 + k, 0);
            }
        }
        d2k_sched_ech_resolve_hook = stub_ech_resolve;
        tcp_answer = D2K_V_CLEAR; tcp_calls = 0; ech_resolve_calls = 0;
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        if (mode == 1) {
            d2k_ev w = ev_hello(6, 41190, "origin.ech.example");
            w.low_ip[3] = 9;                 /* другой адрес того же Cloudflare */
            d2k_sched_event(s, &w);
            d2k_ev o = ev_hello(6, 41191, "plain-other.example");
            o.low_ip[3] = 10;
            d2k_sched_event(s, &o);
        }
        if (mode == 2) {
            for (int k = 0; k < 40; k++) {
                char other[64];
                snprintf(other, sizeof other, "flood%d.example", k);
                d2k_ev o = ev_hello(6, (uint16_t)(43000 + k), other);
                o.low_ip[2] = 7; o.low_ip[3] = (uint8_t)(10 + k);
                d2k_sched_event(s, &o);
            }
        }
        d2k_sched_replay_ver_hook = stub_replay; replay_calls = 0;
        uint8_t eb[2048]; size_t el = 0;
        CHECK(ech_offer_hello(nm, eb, sizeof eb, &el) == 0, "ECH witness: fixture");
        d2k_ev h = ev_hello(6, (uint16_t)(41192 + mode), nm); d2k_sched_event(s, &h);
        d2k_ev sh; memset(&sh, 0, sizeof sh);
        sh.kind = D2K_EV_SHAPE; sh.transport = 6;
        memcpy(sh.shape, eb, el); sh.shape_len = el;
        d2k_sched_event(s, &sh);
        d2k_ev su = ev_suspect(6, (uint16_t)(41192 + mode)); d2k_sched_event(s, &su);
        settle(s);
        CHECK(said("ECH-свидетель найден: origin.ech.example") && replay_calls == 0,
              mode == 0 ? "ECH witness (r): свидетель старше 4 последних привязок не найден"
              : mode == 1 ? "ECH witness (f): имя, видённое на другом адресе, не стало свидетелем"
                          : "ECH witness (q): своя привязка вытеснена именами чужих адресов");
        if (mode == 1) {
            /* (c) Повторный поиск: plain-other.example (без ECH) не
               переспрашивается — ответ HTTPS RR запомнен. */
            int before = ech_resolve_calls;
            skip_ahead(s, 11 * 60 * 1000);
            saidbuf[0] = '\0';
            d2k_ev h2 = ev_hello(6, 41196, nm); d2k_sched_event(s, &h2);
            d2k_ev sh2 = sh; d2k_sched_event(s, &sh2);
            d2k_ev su2 = ev_suspect(6, 41196); d2k_sched_event(s, &su2);
            settle(s);
            CHECK(ech_resolve_calls - before <= 2,
                  "ECH witness (c): ответы HTTPS RR не запоминаются между поисками");
        }
        if (fails) fprintf(stderr, "%s\n", saidbuf);
        d2k_sched_free(s); d2k_catalog_free(&c);
        d2k_sched_ech_resolve_hook = d2k_ech_resolve;
        tcp_answer = D2K_V_OPAQUE;
    }

    /* ПОЛЕ 04.10.2026, чистый каталог, Chrome → Cloudflare с настоящим ECH
     * (внешнее имя cloudflare-ech.com): коробка глушит рукопожатие по самому
     * расширению ECH, свидетеля нет — «не проверено», и nnmclub/kinozal/rua
     * в Chrome не открывались. Теперь мерим байтами клиента: (o) повтор
     * его ECH-приветствия без плана не проходит (база донора 0/3), свой
     * план коробки (другая цель, TLS 1.3) подтверждается повтором тех же
     * байт под планом — ServerHello, уровень рукопожатия — и ложится на
     * внешнее имя формой ECH, без свидетеля и с бюджетом «не проверен».
     * (n) Своих планов нет — обычный путь кандидатов замера, проверка тем же
     * повтором. */
    for (int mode = 0; mode < 2; mode++) {
        const char *nm = "ech-public.example";
        d2k_catalog c = {0};
        char pid[40] = "";
        if (mode == 0)
            own_box(&c, "box-ech-own", pid, 2, 3, "rua.own", 6, D2K_SHAPE_MODERN, 4,
                    1790000000, 0);
        d2k_sched_tcp_fn saved_base = d2k_sched_tcp_base_hook;
        d2k_sched_tcp_base_hook = mode == 0 ? stub_base : NULL;
        base_blocked_answer = 1;
        d2k_sched_replay_ver_hook = stub_replay;
        d2k_sched_ech_resolve_hook = stub_ech_resolve;
        replay_answer_ok = 1; replay_calls = 0; replay_last_len = 0;
        tcp_answer = mode == 0 ? D2K_V_OPAQUE : D2K_V_PREFIX;
        tcp_owns_search = 0; tcp_found_arm = 0;
        ver_answer = D2K_VER_APPLICATION; ver_fail_first = 0; ver_app_after_tcp_search = 0;
        base_calls = tcp_calls = ver_calls = vol_calls = 0; tcp_last_wire = 0;
        uint16_t port = (uint16_t)(41230 + mode);
        ver_answer_port = port;
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        uint8_t eb[2048]; size_t el = 0;
        CHECK(ech_offer_hello(nm, eb, sizeof eb, &el) == 0, "ECH replay: fixture");
        d2k_ev h = ev_hello(6, port, nm); d2k_sched_event(s, &h);
        d2k_ev sh; memset(&sh, 0, sizeof sh);
        sh.kind = D2K_EV_SHAPE; sh.transport = 6;
        memcpy(sh.shape, eb, el); sh.shape_len = el;
        d2k_sched_event(s, &sh);
        d2k_ev su = ev_suspect(6, port); d2k_sched_event(s, &su);
        for (int i = 0; i < 40 && !said("ПОДТВЕРЖДЕНО"); i++) {
            spin(s, 200);
            d2k_ev ap = ev_applied(6, port); d2k_sched_event(s, &ap);
        }
        spin(s, 40);
        if (mode == 0) {
            CHECK(base_calls == 1 && tcp_last_wire == el,
                  "ECH replay (o): база не задана байтами клиента");
            CHECK(tcp_calls == 0, "ECH replay (o): полный замер раньше своих планов");
        } else {
            CHECK(tcp_calls == 1 && tcp_last_wire == el,
                  "ECH replay (n): замер шёл не байтами клиента");
        }
        CHECK(replay_calls >= 1 && replay_last_len == el,
              "ECH replay: кандидат проверен не повтором приветствия клиента");
        CHECK(ver_calls == 0, "ECH replay: кандидат проверен обычным зондом внешнего имени");
        const d2k_cat_binding *bd = binding_of(&c, nm, 6);
        CHECK(bd && bd->shape == D2K_LINK_SHAPE_ECH_TCP && bd->level >= 3 && bd->enabled &&
              bd->verified_by == D2K_VERBY_REPLAY_HANDSHAKE && !bd->ech_origin[0] &&
              bd->budget == D2K_CAT_BUDGET_UNCHECKED && bd->family == 4,
              "ECH replay: привязка внешнего имени не ECH-формы с уровнем рукопожатия");
        if (mode == 0)
            CHECK(bd && !strcmp(bd->plan_id, pid), "ECH replay (o): подтверждён не свой план коробки");
        CHECK(said("уровне рукопожатия") && said("прикладной уровень не измерен"),
              "ECH replay: граница доказательства не названа");
        if (fails) fprintf(stderr, "%s\n", saidbuf);
        d2k_sched_free(s); d2k_catalog_free(&c);
        d2k_sched_tcp_base_hook = saved_base;
        d2k_sched_ech_resolve_hook = d2k_ech_resolve;
        tcp_answer = D2K_V_OPAQUE;
    }

    /* ПОЛЕ 03.10.2026, Discord: QUIC-поиск discord.com кончился «кандидатов
     * нет» (отдых 10 мин — для QUIC), приложение ушло на TCP с GREASE ECH.
     * TCP-поиск того же имени шёл до конца (18:50:33 → 18:52:14, план
     * подтверждён в 18:52:28), но журнал между ними показывал только
     * «замер отложен после неподтверждённого прошлого замера» — без
     * транспорта, и это читалось как подавление TCP отдыхом QUIC. Свойства:
     * отдых QUIC не откладывает TCP того же имени; решение «GREASE» не
     * снимает свой идущий поиск; отложенное подозрение называет свой
     * транспорт. */
    {
        const char *nm = "discord-fallback.test";
        d2k_catalog cd = {0};
        d2k_sched *s = d2k_sched_new(&cd, sv[0], 0x2d);
        CHECK(s != NULL, "QUIC→TCP: планировщик не завёлся");
        if (s) {
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            quic_answer = D2K_V_PREFIX;
            arm_kind = D2K_QA_FLAKY;
            quic_calls = 0;
            d2k_ev qh = ev_hello(17, 41070, nm); d2k_sched_event(s, &qh);
            d2k_ev qs = ev_suspect(17, 41070); d2k_sched_event(s, &qs);
            settle(s);
            CHECK(quic_calls == 1 && said("кандидатов нет"),
                  "QUIC→TCP: пустой QUIC-поиск не воспроизведён");
            uint8_t eb[2048]; size_t el = 0;
            CHECK(ech_offer_hello(nm, eb, sizeof eb, &el) == 0 &&
                  d2k_hello_ech_offer(eb, el, NULL) == 1, "QUIC→TCP: fixture GREASE");
            d2k_sched_ech_resolve_hook = stub_ech_resolve;
            tcp_calls = 0; tcp_answer = D2K_V_CLEAR;
            tcp_wait_until_stop = 1; tcp_release_waiters = 0;
            saidbuf[0] = '\0';
            d2k_ev th = ev_hello(6, 41071, nm); d2k_sched_event(s, &th);
            d2k_ev sh; memset(&sh, 0, sizeof sh);
            sh.kind = D2K_EV_SHAPE; sh.transport = 6;
            memcpy(sh.shape, eb, el); sh.shape_len = el;
            d2k_sched_event(s, &sh);
            d2k_ev ts = ev_suspect(6, 41071); ts.code = D2K_SUSPECT_REPEAT;
            d2k_sched_event(s, &ts);
            for (int i = 0; i < 200 && tcp_calls == 0; i++) spin(s, 5);
            CHECK(said("(TCP) начинаю поиск") && said("GREASE") && tcp_calls == 1,
                  "QUIC→TCP: отдых QUIC отложил TCP-поиск того же имени");
            /* Пока TCP-поиск идёт: новый TCP-поток того же имени и повтор
               QUIC приложением (поле: каждые ~30 с). */
            d2k_ev th2 = ev_hello(6, 41072, nm); d2k_sched_event(s, &th2);
            d2k_ev ts2 = ev_suspect(6, 41072); ts2.code = D2K_SUSPECT_REPEAT;
            d2k_sched_event(s, &ts2);
            d2k_ev qh2 = ev_hello(17, 41073, nm); d2k_sched_event(s, &qh2);
            d2k_ev qs2 = ev_suspect(17, 41073); d2k_sched_event(s, &qs2);
            spin(s, 20);
            CHECK(!said("(TCP) замер отложен"),
                  "QUIC→TCP: TCP-подозрение отложено отдыхом QUIC");
            CHECK(said("(QUIC) замер отложен после неподтверждённого прошлого замера"),
                  "QUIC→TCP: отложенное подозрение не называет свой транспорт");
            CHECK(quic_calls == 1, "QUIC→TCP: повтор QUIC в отдыхе запустил замер");
            tcp_release_waiters = 1;
            settle(s);
            CHECK(tcp_calls == 1 && said("напрямую проходит"),
                  "QUIC→TCP: TCP-поиск после GREASE не дошёл до своего итога");
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s);
        }
        d2k_catalog_free(&cd);
        d2k_sched_ech_resolve_hook = d2k_ech_resolve;
        tcp_answer = D2K_V_OPAQUE;
        tcp_wait_until_stop = 0; tcp_release_waiters = 0;
        quic_answer = D2K_V_OPAQUE;
        arm_kind = D2K_QA_BLOB;
    }
    if (ech_only) { goto voice_only_done; }

    /* A completed domain-search provider is not a bare classifier. Its
     * failure must not launch another property questionnaire or fallback. */
    for (int mode = 0; mode < 5; mode++) {
        d2k_catalog empty = {0};
        d2k_sched *s = d2k_sched_new(&empty, sv[0], 0x2d);
        tcp_owns_search = 1;
        mark_calls = 0;
        tcp_answer = mode == 4 ? D2K_V_FLAKY :
            mode == 0 || mode == 3 ? D2K_V_OPAQUE : mode == 1 ? D2K_V_PREFIX : D2K_V_WHOLE;
        tcp_found_arm = mode == 3;
        ver_answer = D2K_VER_NOT_MEASURED; ver_calls = 0; tcp_calls = 0;
        saidbuf[0] = '\0'; sent_len = 0;
        d2k_sched_set_say(s, collect_say, NULL);
        d2k_ev h = ev_hello(6, (uint16_t)(39990 + mode), "search-owned.example");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, (uint16_t)(39990 + mode));
        d2k_sched_event(s, &su);
        settle(s); spin(s, 100);
        CHECK(tcp_calls == 1, "domain search repeated");
        CHECK(!said("спрашиваю коробку о свойствах"), "second property search after original");
        if (mode == 0) {
            /* ПОЛЕ 04.10, rutracker.org на чистом каталоге: замер владеет
               поиском, блок доказан («решает содержимое»), а выразимого
               планом приёма нет (взят только «oob»). Решение координатора:
               внутренние гипотезы оригинала — запасной список — идут явно,
               и первый его кандидат испытывается. */
            CHECK(said("выразимого планом приёма нет"),
                  "owned OPAQUE without a plan: fallback not named");
            CHECK(said("запасного перебора"), "owned OPAQUE without a plan: fallback list not used");
            CHECK(said("поставил план 1 из") && ver_calls >= 1,
                  "owned OPAQUE without a plan: first fallback candidate not tried");
        } else {
            CHECK(!said("запасного перебора"), "second fallback search after original");
            CHECK(mode == 4 ? ver_calls == 0 : ver_calls == 1,
                  "original split solution lost or extra candidates tested");
        }
        if (mode == 1) {
            CHECK(mark_calls > 0 && last_mark == 0x2d,
                  "сокет verifier-зонда не получил метку контроллера");
        }
        d2k_sched_free(s); d2k_catalog_free(&empty);
    }
    tcp_owns_search = tcp_found_arm = 0; tcp_answer = D2K_V_OPAQUE; ver_answer = D2K_VER_APPLICATION;

    /* СТАРЫЙ КЛИЕНТ НЕ ПОЛУЧАЕТ ПОКРЫТИЯ МОЛЧА.
     *
     * Замер идёт приветствием КЛИЕНТА, а подтверждает найденное НАШ зонд —
     * он ведёт рукопожатие TLS 1.3, и привязка пишется под его форму. Когда
     * клиент старый, формы расходятся: план подтверждён для современных
     * приветствий, а тому клиенту по ключу формы не достанется вовсе.
     * Ложного в каталоге при этом нет, но молчание читается как покрытие,
     * которого нет. Проверяем, что расхождение названо вслух. */
    {
        d2k_catalog empty = {0};
        d2k_sched *s = d2k_sched_new(&empty, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_calls = 0; ver_answer_port = 40507;
        d2k_ev h = ev_hello(6, 40507, "staryi.klient.example");
        d2k_sched_event(s, &h);
        {
            d2k_ev sh;
            memset(&sh, 0, sizeof sh);
            sh.kind = D2K_EV_SHAPE;
            sh.transport = 6;
            CHECK(d2k_hello_from_profile(D2K_SHAPE_LEGACY, "staryi.klient.example",
                                         sh.shape, sizeof sh.shape, &sh.shape_len) == 0,
                  "приветствие старой формы не собралось — проверять нечем");
            d2k_sched_event(s, &sh);
        }
        d2k_ev su = ev_suspect(6, 40507);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(ver_calls >= 1, "планировщик не испытал кандидата сам");
        /* Датапат говорит, что план применился к пакетам ЭТОГО потока —
           без этого подтверждения не бывает, и проверять было бы нечего. */
        d2k_ev ap = ev_applied(6, 40507);
        d2k_sched_event(s, &ap);
        spin(s, 60);
        CHECK(said("ПОДТВЕРЖДЕНО"), "подтверждения не случилось — оговорку проверять не на чем");
        /* ПРОТОКОЛ ПОДТВЕРЖДЕНИЯ ВЫБИРАЕТСЯ ПО ФОРМЕ КЛИЕНТА. Зонд подменён,
           поэтому проверяем не сам обмен, а то, ЧТО ему сказали: с чужой
           формой он пошёл бы современным рукопожатием к старому клиенту. */
        CHECK(ver_last_shape == (uint8_t)D2K_SHAPE_LEGACY,
              "зонду не сказали, что клиент старой формы — он подтвердит не тем протоколом");
        {
            const d2k_cat_binding *bd = binding_of(&empty, "staryi.klient.example", 6);
            CHECK(bd != NULL && bd->shape == (uint8_t)D2K_SHAPE_LEGACY,
                  "привязка записана НЕ под форму клиента — по ключу формы он её не получит");
        }
        CHECK(said("зонд СТАРОЙ формы"), "подтверждение старой формой не названо в журнале");
        d2k_sched_free(s); d2k_catalog_free(&empty);
        ver_answer = D2K_VER_APPLICATION; tcp_answer = D2K_V_OPAQUE;
    }

    /* ЦИКЛ НЕ ЖДЁТ СЕТЕВОГО ОРАКУЛА.
     *
     * task_fail и task_done зовут pthread_join безусловно. Пока у измерителя
     * не было просьбы бросить, истёкший срок задачи или остановка службы
     * блокировали ГЛАВНЫЙ поток на всё время замера: один зонд до шести
     * секунд, полный перебор — десятки минут. Контроллер в это время не читал
     * событий датапата и не выходил по сигналу — стенд транзита 17.09 повис
     * ровно так, и это выглядело как «служба не реагирует».
     *
     * Проверяем ДВА факта: просьба дошла до измерителя и ожидание уложилось в
     * малую долю того, сколько он был готов ждать. */
    {
        d2k_catalog empty = {0};
        d2k_sched *s = d2k_sched_new(&empty, sv[0], 0x2d);
        tcp_block_until_stop = 1; tcp_saw_stop = 0; tcp_calls = 0;
        tcp_answer = D2K_V_INCONCLUSIVE;
        d2k_sched_set_say(s, collect_say, NULL);
        d2k_ev h = ev_hello(6, 39977, "slow-oracle.example");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 39977);
        d2k_sched_event(s, &su);
        /* Крутим ровно столько, чтобы замер успел начаться, и не столько,
           чтобы он успел кончиться сам. */
        spin(s, 60);
        CHECK(tcp_calls == 1, "замер не начался — проверять было бы нечего");
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        d2k_sched_free(s);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
        CHECK(tcp_saw_stop, "измеритель не получил просьбы бросить");
        CHECK(ms < STUB_BLOCK_MS / 5,
              "остановка ждала сетевого оракула");
        d2k_catalog_free(&empty);
        tcp_block_until_stop = 0;
        tcp_answer = D2K_V_OPAQUE;
    }

    /* Time spent in the bounded admission queue must not consume the active
       search lifetime. Two deliberately held workers fill the measurement
       slots; the third target waits nine minutes, then receives its own full
       ten-minute active budget after those workers time out. */
    {
        d2k_catalog c = {0};
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        tcp_wait_until_stop = 1;
        tcp_saw_stop = tcp_stop_count = tcp_calls = 0;
        tcp_answer = D2K_V_INCONCLUSIVE;
        CHECK(s != NULL, "планировщик проверки очереди не завёлся");
        if (s) {
            for (uint16_t port = 40601; port <= 40603; port++) {
                char name[64];
                snprintf(name, sizeof name, "queue-life-%u.example", port);
                d2k_ev h = ev_hello(6, port, name);
                d2k_sched_event(s, &h);
                d2k_ev su = ev_suspect(6, port);
                d2k_sched_event(s, &su);
            }
            spin(s, 60);
            CHECK(tcp_calls == 2, "очередь не ограничила одновременные замеры двумя");
            skip_ahead(s, 9 * 60 * 1000);
            tcp_release_waiters = 1;
            spin(s, 60);
            CHECK(tcp_calls == 3, "ожидавшая цель не стартовала после освобождения слота");
            tcp_release_waiters = 0;
            skip_ahead(s, 60 * 1000 + 1);
            CHECK(tcp_stop_count == 0,
                  "время ожидания в очереди сократило активный лимит поиска");
            d2k_sched_free(s);
        }
        tcp_release_waiters = 0;
        tcp_wait_until_stop = 0;
        tcp_answer = D2K_V_OPAQUE;
    }

    /* A direct classifier timeout with zero candidate probes is still an
       incomplete search and must receive the bounded, target-local cooldown. */
    {
        d2k_catalog c = {0};
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        tcp_wait_until_stop = 1;
        tcp_saw_stop = tcp_stop_count = tcp_calls = 0;
        tcp_answer = D2K_V_INCONCLUSIVE;
        CHECK(s != NULL, "планировщик cooldown незавершённого замера не завёлся");
        if (s) {
            d2k_ev h = ev_hello(6, 40620, "incomplete-cooldown.example");
            d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 40620);
            d2k_sched_event(s, &su);
            spin(s, 60);
            CHECK(tcp_calls == 1, "незавершённый прямой замер не стартовал");
            skip_ahead(s, 10 * 60 * 1000 + 1);
            CHECK(tcp_stop_count == 1, "десятиминутный таймаут не остановил замер");
            skip_ahead(s, 2 * 60 * 1000 + 1);
            d2k_ev h2 = ev_hello(6, 40621, "incomplete-cooldown.example");
            d2k_sched_event(s, &h2);
            d2k_ev su2 = ev_suspect(6, 40621);
            d2k_sched_event(s, &su2);
            spin(s, 60);
            CHECK(tcp_calls == 1,
                  "замер с нулём кандидатов не получил cooldown и сразу повторился");
            skip_ahead(s, 8 * 60 * 1000 + 1);
            d2k_ev h3 = ev_hello(6, 40622, "incomplete-cooldown.example");
            d2k_sched_event(s, &h3);
            d2k_ev su3 = ev_suspect(6, 40622);
            d2k_sched_event(s, &su3);
            spin(s, 60);
            CHECK(tcp_calls == 2,
                  "ограниченный cooldown незавершённого поиска не истёк через 10 минут");
            d2k_sched_free(s);
        }
        tcp_wait_until_stop = 0;
        tcp_answer = D2K_V_OPAQUE;
    }

    /* SHAPE arrives while the oracle holds its trigger. Main-thread writes
     * must not alter the bytes of an already-running measurement. */
    {
        d2k_catalog empty = {0};
        d2k_sched *s = d2k_sched_new(&empty, sv[0], 0x2d);
        snapshot_enabled = 1; snapshot_entered = snapshot_release = snapshot_ok = 0;
        tcp_answer = D2K_V_CLEAR;
        d2k_ev h = ev_hello(6, 39989, "snapshot.example");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 39989);
        d2k_sched_event(s, &su);
        pthread_mutex_lock(&snapshot_mu);
        while (!snapshot_entered) { pthread_cond_wait(&snapshot_cv, &snapshot_mu); }
        pthread_mutex_unlock(&snapshot_mu);
        d2k_ev sh = {0}; sh.kind = D2K_EV_SHAPE; sh.transport = 6;
        CHECK(d2k_hello_from_profile(D2K_SHAPE_LEGACY, "snapshot.example",
              sh.shape, sizeof sh.shape, &sh.shape_len) == 0, "snapshot fixture failed");
        d2k_sched_event(s, &sh);
        pthread_mutex_lock(&snapshot_mu);
        snapshot_release = 1; pthread_cond_broadcast(&snapshot_cv);
        pthread_mutex_unlock(&snapshot_mu);
        settle(s);
        CHECK(snapshot_ok, "SHAPE overwrote a running measurement's trigger");
        d2k_sched_free(s); d2k_catalog_free(&empty);
        snapshot_enabled = 0; tcp_answer = D2K_V_OPAQUE;
    }

    /* Задача 48: ход классификатора виден, пока он работает. Полный прогон
     * дерева на трудной цели идёт минутами (meduza.io IPv6 03.10: 102 зонда,
     * 4 мин 20 с), и «probes: 0» без вопроса не отличить от зависания. Поле
     * source («откуда план») у задачи без плана — ложь: только при проверке. */
    {
        d2k_catalog empty = {0};
        d2k_sched *s = d2k_sched_new(&empty, sv[0], 0x2d);
        /* Задача 49: QUIC-прогон отдаёт ход тем же приёмником. */
        CHECK(d2k_quic_progress_hook != NULL, "QUIC progress is not wired into the scheduler");
        snapshot_enabled = 1; snapshot_entered = snapshot_release = snapshot_ok = 0;
        tcp_progress_notes = 1;
        tcp_answer = D2K_V_OPAQUE;
        d2k_ev h = ev_hello(6, 39977, "progress.example");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 39977);
        d2k_sched_event(s, &su);
        pthread_mutex_lock(&snapshot_mu);
        while (!snapshot_entered) { pthread_cond_wait(&snapshot_cv, &snapshot_mu); }
        pthread_mutex_unlock(&snapshot_mu);
        const char *e = live_task_entry(s, "progress.example");
        CHECK(strstr(e, "\"phase\": \"распознаём поведение\"") != NULL,
              "progress fixture is not in the classifier phase");
        CHECK(strstr(e, "\"probes\": 1000,") != NULL,
              "running classifier probes are not visible in live.json");
        CHECK(strstr(e, "\"question\": \"poison:seqovl-1\"") != NULL,
              "running classifier question is not visible in live.json");
        CHECK(strstr(e, "\"source\": \"\"") != NULL && !strstr(e, "выведен из замера"),
              "a task without a plan under trial claims a plan source");
        pthread_mutex_lock(&snapshot_mu);
        snapshot_release = 1; pthread_cond_broadcast(&snapshot_cv);
        pthread_mutex_unlock(&snapshot_mu);
        settle(s);
        /* Вернувшийся измеритель больше не «спрашивает», но его зонды с
           карточки не исчезают (задача 49: счётчик монотонный): после
           возврата — итог прогона r.probes (1006, а не ход 1000 и не сумма
           2006) плюс зонды проверки плана. */
        e = live_task_entry(s, "progress.example");
        CHECK(!strstr(e, "\"question\": \"poison:seqovl-1\""),
              "a finished classifier keeps reporting its last question");
        int p = live_task_probes(s, "progress.example");
        CHECK(p >= 1006 && p < 2006,
              "live probes dropped after the classifier returned or counted it twice");
        d2k_sched_free(s); d2k_catalog_free(&empty);
        snapshot_enabled = 0; tcp_progress_notes = 0; tcp_answer = D2K_V_OPAQUE;
    }
    /* Задача 49: QUIC-поиск отдаёт ход тем же путём (через настоящий
       рабочий поток и d2k_quic_progress_hook). */
    {
        d2k_catalog empty = {0};
        d2k_sched *s = d2k_sched_new(&empty, sv[0], 0x2d);
        snapshot_enabled = 1; snapshot_entered = snapshot_release = snapshot_ok = 0;
        quic_progress_notes = 1;
        d2k_ev h = ev_hello(17, 39975, "quic-progress.example");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(17, 39975);
        d2k_sched_event(s, &su);
        pthread_mutex_lock(&snapshot_mu);
        while (!snapshot_entered) { pthread_cond_wait(&snapshot_cv, &snapshot_mu); }
        pthread_mutex_unlock(&snapshot_mu);
        const char *e = live_task_entry(s, "quic-progress.example");
        CHECK(strstr(e, "\"probes\": 6,") != NULL &&
              strstr(e, "\"question\": \"прямой зонд\"") != NULL,
              "running QUIC classifier progress is not visible in live.json");
        pthread_mutex_lock(&snapshot_mu);
        snapshot_release = 1; pthread_cond_broadcast(&snapshot_cv);
        pthread_mutex_unlock(&snapshot_mu);
        settle(s);
        d2k_sched_free(s); d2k_catalog_free(&empty);
        snapshot_enabled = 0; quic_progress_notes = 0;
    }

    /* Complete cached input is used; an observable SNI prefix is not.
       Neither case needs a second visit to obtain the cached observation. */
    for (int partial = 0; partial < 2; partial++) {
        d2k_catalog empty = {0};
        d2k_sched *s = d2k_sched_new(&empty, sv[0], 0x2d);
        d2k_ev sh = {0}; sh.kind = D2K_EV_SHAPE; sh.transport = 6;
        CHECK(d2k_hello_from_profile(D2K_SHAPE_LEGACY, "complete.example",
              sh.shape, sizeof sh.shape, &sh.shape_len) == 0, "complete fixture failed");
        size_t complete_len = sh.shape_len;
        if (partial) { sh.shape_len--; }
        size_t off, len;
        CHECK(d2k_hello_sni(sh.shape, sh.shape_len, &off, &len) == 0,
              "fragment fixture must still expose SNI");
        d2k_sched_event(s, &sh);
        tcp_answer = D2K_V_CLEAR; tcp_last_wire = 0;
        d2k_ev h = ev_hello(6, 39988, "complete.example");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 39988);
        d2k_sched_event(s, &su); settle(s);
        CHECK(partial ? tcp_last_wire > complete_len : tcp_last_wire == complete_len,
              "complete cache ignored or fragment used as a complete input");
        d2k_sched_free(s); d2k_catalog_free(&empty);
    }

    tcp_answer = D2K_V_OPAQUE;

    /* ЗАДАЧА 54. Поле 04.10, cdn.cookielaw.org: адрес 104.18.86.42 после
       рукопожатия не принимает никаких данных, замер это доказывает (вердикт
       address). Это не «результат неубедителен» с десятиминутным кругом:
       отсрочка нарастает 10/30/60 мин и ключ у неё — имя+адрес+семейство
       (fix round 1, I1); перепроверка такого адреса начинается с ОДНОГО
       нейтрального байта до любого зонда с триггером (I2): тишина — вердикт
       подтверждён без триггеров, подтверждение — молчание вызывал триггер,
       вердикт снят, обычный путь. */
    {
        d2k_catalog c_addr = {0};
        d2k_sched *s = d2k_sched_new(&c_addr, sv[0], 0x2d);
        CHECK(s != NULL, "task54: планировщик не завёлся");
        if (s) {
            const char *name = "dead.address.example";
            d2k_sched_tcp_ack_hook = stub_ack;
            tcp_calls = quic_calls = 0;
            ack_calls = 0; ack_answer = 0;
            tcp_answer = D2K_V_ADDRESS;
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            /* A — 127.0.0.1 (мёртвый), B — 127.0.0.2 (DNS чередует). */
            #define T54_EV(port, last, code_) do { \
                d2k_ev h_ = ev_hello(6, (port), name); h_.low_ip[3] = (last); \
                d2k_sched_event(s, &h_); \
                d2k_ev r_ = ev_suspect(6, (port)); r_.low_ip[3] = (last); \
                if (code_) r_.code = (code_); \
                t54_rc = d2k_sched_event(s, &r_); settle(s); } while (0)
            int t54_rc;
            T54_EV(41301, 1, 0);
            CHECK(t54_rc == 1 && tcp_calls == 1 && strcmp(tcp_last_ip, "127.0.0.1") == 0,
                  "task54: замер адреса не прошёл");
            CHECK(ack_calls == 0, "task54: первый замер спросил нейтральный байт вне дерева");
            CHECK(!said("результат неубедителен"),
                  "task54: доказанный блок адреса назван неубедительным");
            CHECK(said("по dead.address.example адрес 127.0.0.1 не принимает данных"),
                  "task54: блок адреса не назван в журнале");
            CHECK(said("через 10 мин"), "task54: первая ступень не 10 мин");
            CHECK(bindings_of(&c_addr, name, 6) == 0 && c_addr.n_boxes == 0,
                  "task54: блок адреса записал обход");

            /* Другой адрес имени мерится сразу и исходом (inconclusive,
               отсрочка имени вида 2) лестницу A не сбрасывает (I1). */
            tcp_answer = D2K_V_INCONCLUSIVE;
            skip_ahead(s, 3 * 60 * 1000); /* задача имени отдыхает 2 мин после исхода */
            T54_EV(41302, 2, 0);
            CHECK(t54_rc == 1 && tcp_calls == 2 && strcmp(tcp_last_ip, "127.0.0.2") == 0,
                  "task54: отсрочка мёртвого адреса заглушила другой адрес имени");

            /* +11 мин: перепроверка A — нейтральный байт ПЕРВЫМ, без
               триггера; тишина — вердикт подтверждён, ступень 30 мин. */
            skip_ahead(s, 11 * 60 * 1000);
            saidbuf[0] = '\0';
            T54_EV(41303, 1, D2K_SUSPECT_RST);
            CHECK(t54_rc == 1 && ack_calls == 1 && strcmp(ack_last_ip, "127.0.0.1") == 0,
                  "task54: перепроверка мёртвого адреса не начала с нейтрального байта");
            CHECK(tcp_calls == 2, "task54: перепроверка мёртвого адреса слала триггер");
            CHECK(said("через 30 мин"), "task54: вторая ступень не 30 мин");
            /* B в это время — снова неубедительно (DNS чередует). */
            tcp_answer = D2K_V_INCONCLUSIVE;
            skip_ahead(s, 11 * 60 * 1000);
            T54_EV(41304, 2, 0);
            CHECK(tcp_calls == 3, "task54: другой адрес не измерен после своей отсрочки");
            /* A ещё в 30-минутной отсрочке, любой симптом. */
            skip_ahead(s, 3 * 60 * 1000);
            T54_EV(41305, 1, D2K_SUSPECT_RST);
            CHECK(t54_rc == 0 && ack_calls == 1 && tcp_calls == 3,
                  "task54: исход другого адреса снял отсрочку мёртвого");
            CHECK(said("замер отложен после блока адреса 127.0.0.1"),
                  "task54: причина отсрочки не названа");
            /* +31 мин от перепроверки: третья ступень 60 мин. */
            skip_ahead(s, 20 * 60 * 1000);
            saidbuf[0] = '\0';
            T54_EV(41306, 1, 0);
            CHECK(ack_calls == 2 && tcp_calls == 3 && said("через 60 мин"),
                  "task54: третья ступень не 60 мин");
            /* Потолок: следующая ступень тоже 60 мин. */
            skip_ahead(s, 59 * 60 * 1000);
            T54_EV(41307, 1, 0);
            CHECK(t54_rc == 0 && ack_calls == 2, "task54: потолок 60 мин не держится");
            skip_ahead(s, 2 * 60 * 1000);
            saidbuf[0] = '\0';
            T54_EV(41308, 1, 0);
            CHECK(ack_calls == 3 && said("через 60 мин"), "task54: после потолка ступень не 60 мин");

            /* I2, вторая ветка: байт подтверждён — молчание вызывал триггер;
               вердикт адреса снят, дальше обычный путь с триггером. */
            skip_ahead(s, 61 * 60 * 1000);
            saidbuf[0] = '\0';
            ack_answer = 1;
            tcp_answer = D2K_V_INCONCLUSIVE;
            T54_EV(41309, 1, 0);
            CHECK(ack_calls == 4 && tcp_calls == 4 && strcmp(tcp_last_ip, "127.0.0.1") == 0,
                  "task54: подтверждённый байт не открыл обычный путь");
            CHECK(said("вердикт address снят"), "task54: снятие вердикта не названо");
            /* Снят по-настоящему: следующая перепроверка без байта. */
            skip_ahead(s, 11 * 60 * 1000);
            T54_EV(41310, 1, 0);
            CHECK(ack_calls == 4 && tcp_calls == 5, "task54: снятый вердикт адреса снова спрашивал байт");

            /* Байт подтверждён, а дерево снова сказало address: адрес глохнет
               только после триггера — это штраф, а не блок адреса. */
            tcp_answer = D2K_V_ADDRESS; ack_answer = 0;
            skip_ahead(s, 11 * 60 * 1000);
            T54_EV(41311, 1, 0);              /* address, ступень 1 */
            skip_ahead(s, 11 * 60 * 1000);
            ack_answer = 1; saidbuf[0] = '\0';
            T54_EV(41312, 1, 0);              /* перепроверка: ACK, дерево: address */
            CHECK(said("глохнет только после триггера"),
                  "task54: штраф после триггера выдан за блок адреса");
            CHECK(!said("не принимает данных"), "task54: штраф записан как блок адреса");
            #undef T54_EV
            d2k_sched_free(s);
        }
        d2k_catalog_free(&c_addr);

        /* IPv6: тот же ключ с семейством. */
        d2k_catalog c6 = {0};
        s = d2k_sched_new(&c6, sv[0], 0x2d);
        if (s) {
            tcp_calls = 0; ack_calls = 0; ack_answer = 0;
            tcp_answer = D2K_V_ADDRESS;
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            d2k_ev h = ev_hello(6, 41320, "dead6.example");
            h.family = 6; memset(h.low_ip, 0, 16); h.low_ip[15] = 1;
            memset(h.high_ip, 0, 16); h.high_ip[0] = 0xfd; h.high_ip[15] = 2;
            d2k_sched_event(s, &h);
            d2k_ev r = ev_suspect(6, 41320);
            r.family = 6; memcpy(r.low_ip, h.low_ip, 16); memcpy(r.high_ip, h.high_ip, 16);
            d2k_sched_event(s, &r);
            settle(s);
            CHECK(tcp_calls == 1 && said("адрес ::1 не принимает данных"),
                  "task54/v6: блок адреса IPv6 не установлен");
            skip_ahead(s, 3 * 60 * 1000);
            d2k_ev h2 = h; h2.high_port = 41321; d2k_sched_event(s, &h2);
            d2k_ev r2 = r; r2.high_port = 41321;
            CHECK(d2k_sched_event(s, &r2) == 0 && tcp_calls == 1,
                  "task54/v6: отсрочка адреса IPv6 не держится");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&c6);

        /* Найденные раньше привязки имени вердикт address не трогает. */
        d2k_catalog cb = {0};
        tcp_answer = D2K_V_PREFIX; tcp_owns_search = 0; tcp_found_arm = 0;
        ver_answer = D2K_VER_APPLICATION; ver_fail_first = 0;
        confirm_once(&cb, sv[0], "bound.dead.example", 41330);
        size_t before = bindings_of(&cb, "bound.dead.example", 6);
        CHECK(before >= 1, "task54: фикстура привязки не подтверждена");
        s = d2k_sched_new(&cb, sv[0], 0x2d);
        if (s) {
            tcp_calls = 0;
            tcp_answer = D2K_V_ADDRESS;
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            d2k_ev h = ev_hello(6, 41331, "bound.dead.example");
            h.low_ip[3] = 9; /* другой адрес того же имени */
            d2k_sched_event(s, &h);
            d2k_ev r = ev_suspect(6, 41331); r.low_ip[3] = 9;
            d2k_sched_event(s, &r);
            settle(s);
            CHECK(said("адрес 127.0.0.9 не принимает данных"),
                  "task54: фикстура с привязками не дошла до вердикта address");
            CHECK(bindings_of(&cb, "bound.dead.example", 6) == before,
                  "task54: вердикт address тронул найденные привязки имени");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&cb);
        d2k_sched_tcp_ack_hook = NULL;
        tcp_answer = D2K_V_OPAQUE;
    }

    /* Обычный входящий RST запускает ТОЛЬКО прямую классификацию. Пока она
       не докажет блокировку, ни готовые планы, ни синтез не запускаются.
       Неопределённый результат охлаждает цель, чтобы повторные RST не
       превращались в непрерывный перебор. */
    {
        d2k_catalog c_rst = {0};
        d2k_sched *s = d2k_sched_new(&c_rst, sv[0], 0x2d);
        tcp_calls = quic_calls = 0;
        tcp_answer = D2K_V_INCONCLUSIVE;
        ver_answer = D2K_VER_NOT_MEASURED;
        saidbuf[0] = '\0';
        CHECK(s != NULL, "планировщик для порога RST не завёлся");
        if (s) {
            d2k_sched_set_say(s, collect_say, NULL);
            d2k_ev h1 = ev_hello(6, 41001, "single-reset.example");
            d2k_sched_event(s, &h1);
            d2k_ev r1 = ev_suspect(6, 41001);
            r1.code = D2K_SUSPECT_RST;
            CHECK(d2k_sched_event(s, &r1) == 1,
                  "одиночный обычный RST не запустил прямую классификацию");
            settle(s);
            CHECK(tcp_calls == 1 && quic_calls == 0,
                  "одиночный RST не прошёл ровно одну прямую TCP-проверку");
            CHECK(bindings_of(&c_rst, "single-reset.example", 6) == 0,
                  "неопределённый прямой замер записал обход");
            CHECK(said("прямой замер не подтвердил блокировку"),
                  "неопределённый прямой вердикт не отражён в журнале");

            /* После обязательного двухминутного отдыха задача освобождается,
               но десятиминутный cooldown неопределённого замера всё ещё
               не позволяет повторно запускать измеритель. */
            skip_ahead(s, 121000);
            d2k_ev h2 = ev_hello(6, 41002, "single-reset.example");
            d2k_sched_event(s, &h2);
            d2k_ev r2 = ev_suspect(6, 41002);
            r2.code = D2K_SUSPECT_RST;
            CHECK(d2k_sched_event(s, &r2) == 0,
                  "неопределённый RST обошёл десятиминутный cooldown");
            settle(s);
            CHECK(tcp_calls == 1,
                  "повторный RST запустил измерение до истечения cooldown");
            CHECK(said("замер отложен после неподтверждённого прошлого замера"),
                  "причина cooldown не отражена в журнале");
            /* Поле 06.10: один и тот же отказ по одному имени повторялся
               сотнями строк и раздувал журнал на флеше. Причина уже названа —
               повтор в пределах десяти минут молчит, после — звучит снова. */
            d2k_ev h3 = ev_hello(6, 41003, "single-reset.example");
            d2k_sched_event(s, &h3);
            d2k_ev r3 = ev_suspect(6, 41003);
            r3.code = D2K_SUSPECT_RST;
            (void)d2k_sched_event(s, &r3);
            settle(s);
            CHECK(said_count("single-reset.example (TCP) замер отложен") == 1,
                  "повтор той же причины отдыха записан в журнал снова");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&c_rst);
        tcp_answer = D2K_V_OPAQUE;
        ver_answer = D2K_VER_APPLICATION;
    }

    /* Таймер второго RST больше не является условием допуска к прямой
       классификации: каждый новый flow того же имени уже покрыт её cooldown. */
    {
        d2k_catalog c_rst = {0};
        d2k_sched *s = d2k_sched_new(&c_rst, sv[0], 0x2d);
        tcp_calls = 0; tcp_answer = D2K_V_INCONCLUSIVE;
        CHECK(s != NULL, "планировщик для границ RST не завёлся");
        if (s) {
            d2k_ev h = ev_hello(6, 41003, "reset-window.example");
            d2k_sched_event(s, &h);
            d2k_ev r = ev_suspect(6, 41003);
            r.code = D2K_SUSPECT_RST;
            CHECK(d2k_sched_event(s, &r) == 1, "прямой замер по первому RST не начат");
            settle(s);
            CHECK(tcp_calls == 1, "первый RST не запустил прямой замер ровно один раз");
            skip_ahead(s, 30001);
            d2k_ev h2 = ev_hello(6, 41004, "reset-window.example");
            d2k_sched_event(s, &h2);
            d2k_ev r2 = ev_suspect(6, 41004);
            r2.code = D2K_SUSPECT_RST;
            CHECK(d2k_sched_event(s, &r2) == 0,
                  "повторное соединение обошло cooldown прямого замера");
            settle(s);
            CHECK(tcp_calls == 1, "повторное соединение запустило второй прямой замер");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&c_rst);
        tcp_answer = D2K_V_OPAQUE;
    }

    /* Более сильные сигналы не должны ждать второго потока: повтор ClientHello,
       молчание и снятый защитой аномальный RST запускают поиск сразу. */
    {
        static const uint16_t strong_codes[] = {
            D2K_SUSPECT_REPEAT, D2K_SUSPECT_SILENT, D2K_SUSPECT_RST_CUT
        };
        for (size_t i = 0; i < sizeof strong_codes / sizeof strong_codes[0]; i++) {
            d2k_catalog c_strong = {0};
            d2k_sched *s = d2k_sched_new(&c_strong, sv[0], 0x2d);
            tcp_calls = quic_calls = 0;
            CHECK(s != NULL, "планировщик сильного подозрения не завёлся");
            if (s) {
                uint16_t port = (uint16_t)(41010 + i);
                d2k_ev h = ev_hello(6, port, "strong-signal.example");
                d2k_sched_event(s, &h);
                d2k_ev su = ev_suspect(6, port);
                su.code = strong_codes[i];
                CHECK(d2k_sched_event(s, &su) == 1,
                      "сильный сигнал ошибочно ждал второго потока");
                settle(s);
                CHECK(tcp_calls == 1,
                      "сильный сигнал не вызвал ровно один TCP-поиск");
                d2k_sched_free(s);
            }
            d2k_catalog_free(&c_strong);
        }
    }

    /* Сильный сигнал на соседнем потоке не создаёт второй прямой замер,
       пока первый классификатор уже проверяет цель. */
    {
        d2k_catalog c_promote = {0};
        d2k_sched *s = d2k_sched_new(&c_promote, sv[0], 0x2d);
        tcp_calls = 0;
        CHECK(s != NULL, "планировщик для усиления RST не завёлся");
        if (s) {
            d2k_ev h1 = ev_hello(6, 41020, "promote-reset.example");
            d2k_sched_event(s, &h1);
            d2k_ev r1 = ev_suspect(6, 41020);
            r1.code = D2K_SUSPECT_RST;
            CHECK(d2k_sched_event(s, &r1) == 1,
                  "первый обычный RST не запустил прямую классификацию");
            d2k_ev h2 = ev_hello(6, 41021, "promote-reset.example");
            d2k_sched_event(s, &h2);
            d2k_ev repeat = ev_suspect(6, 41021);
            repeat.code = D2K_SUSPECT_REPEAT;
            CHECK(d2k_sched_event(s, &repeat) == 0,
                  "дополнительный сигнал создал параллельный поиск той же цели");
            settle(s);
            CHECK(tcp_calls == 1,
                  "усиленное подозрение не запустило ровно один поиск");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&c_promote);
    }

    /* ЗАДАЧА 18. Поздний RST на здоровой цели не устраивает шторм замеров.
       Датапат шлёт D2K_SUSPECT_RST_AFTER_APP на любой TLS-поток с app-data и
       RST. Это низкоуверенное подозрение: замер начинается только после
       второго такого RST по независимому flow key, а неподтверждённая
       RX-volume-пара откладывает повтор обычным cooldown, а не двухминутным
       отдыхом. */
    {
        d2k_catalog c18 = {0};
        d2k_sched *s = d2k_sched_new(&c18, sv[0], 0x2d);
        CHECK(s != NULL, "планировщик для порога позднего RST не завёлся");
        if (s) {
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            vol_calls = tcp_calls = 0;
            vol_answer = D2K_VOL_PASSED;
            vol_rx_cut = 0;
            const char *name = "late-threshold.test";
            d2k_ev h = ev_hello(6, 41040, name);
            d2k_sched_event(s, &h);
            d2k_ev r = ev_suspect(6, 41040);
            r.code = D2K_SUSPECT_RST_AFTER_APP;
            CHECK(d2k_sched_event(s, &r) == 0,
                  "одиночный поздний RST сразу запустил замер");
            settle(s);
            CHECK(vol_calls == 0 && tcp_calls == 0,
                  "одиночный поздний RST дошёл до сетевого измерения");
            CHECK(said("жду второй независимый поток"),
                  "ожидание второго позднего RST не отражено в журнале");
            /* Тот же поток повторно — не независимый ключ. */
            CHECK(d2k_sched_event(s, &r) == 0,
                  "повтор позднего RST того же потока засчитан как независимый");
            settle(s);
            CHECK(vol_calls == 0, "повтор того же потока запустил замер");
            /* Второй RST вне окна подтверждения не подтверждает первый. */
            skip_ahead(s, 31000);
            d2k_ev h2 = ev_hello(6, 41041, name);
            d2k_sched_event(s, &h2);
            d2k_ev r2 = ev_suspect(6, 41041);
            r2.code = D2K_SUSPECT_RST_AFTER_APP;
            CHECK(d2k_sched_event(s, &r2) == 0,
                  "устаревший первый поздний RST подтвердил второй");
            settle(s);
            CHECK(vol_calls == 0, "поздний RST вне окна запустил замер");
            /* Независимый поток в окне — подтверждение, замер начинается. */
            d2k_ev h3 = ev_hello(6, 41042, name);
            d2k_sched_event(s, &h3);
            d2k_ev r3 = ev_suspect(6, 41042);
            r3.code = D2K_SUSPECT_RST_AFTER_APP;
            CHECK(d2k_sched_event(s, &r3) == 1,
                  "второй поздний RST по независимому потоку не запустил замер");
            settle(s);
            CHECK(vol_calls == 1 && tcp_calls == 0,
                  "подтверждённый поздний RST не прошёл ровно одну RX-volume-пару");
            CHECK(said("позднее закрытие не подтвердилось"),
                  "неподтверждённый поздний RST не отражён в журнале");

            /* Двухминутный отдых прошёл, здоровый трафик продолжает рвать
               соединения поздним RST — повторного замера быть не должно. */
            skip_ahead(s, 3 * 60 * 1000);
            for (uint16_t port = 41043; port <= 41044; port++) {
                d2k_ev hh = ev_hello(6, port, name);
                d2k_sched_event(s, &hh);
                d2k_ev rr = ev_suspect(6, port);
                rr.code = D2K_SUSPECT_RST_AFTER_APP;
                d2k_sched_event(s, &rr);
                settle(s);
            }
            CHECK(vol_calls == 1,
                  "неподтверждённый поздний RST повторил замер через два минуты");
            CHECK(said("замер отложен после неподтверждённого прошлого замера"),
                  "cooldown неподтверждённого позднего RST не отражён в журнале");
            CHECK(bindings_of(&c18, name, 6) == 0,
                  "неподтверждённый поздний RST записал обход");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&c18);
    }

    /* ПОЛЕ 04.10, rua.gr: два поздних закрытия подтвердили подозрение,
       RX-пара: identity 22229/22280 и gzip 20817 оборваны на одном бюджете
       пакетов (~25). Это примета коробки — дальше обычный поиск планов
       (RX-лестница fake-first), а не «не подтвердилось» и отдых. */
    {
        d2k_catalog cr = {0};
        d2k_sched *s = d2k_sched_new(&cr, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        vol_calls = tcp_calls = ver_calls = 0;
        vol_answer = D2K_VOL_PASSED;
        vol_rx_cut = 1; vol_rx_packet_only = 1; vol_rx_packets = 25; vol_rx_at_kb = 21;
        const char *name = "rua.packet.example";
        for (uint16_t port = 41060; port <= 41061; port++) {
            d2k_ev hh = ev_hello(6, port, name);
            d2k_sched_event(s, &hh);
            d2k_ev rr = ev_suspect(6, port);
            rr.code = D2K_SUSPECT_RST_AFTER_APP;
            d2k_sched_event(s, &rr);
        }
        settle(s); spin(s, 200);
        CHECK(vol_calls >= 1, "rua.gr: RX-пара позднего закрытия не началась");
        CHECK(!said("позднее закрытие не подтвердилось"),
              "rua.gr: пакетный бюджет identity+gzip прочитан как «не подтвердилось»");
        CHECK(said("подтверждён пакетный бюджет потока"),
              "rua.gr: пакетная примета коробки не названа");
        CHECK(said("fake-SNI") && said("поставил план 1 из"),
              "rua.gr: после пакетной приметы не начат поиск fake-first кандидатов");
        if (fails) fprintf(stderr, "%s\n", saidbuf);
        d2k_sched_free(s); d2k_catalog_free(&cr);
        vol_rx_cut = 0; vol_rx_packet_only = 0; vol_rx_packets = 0; vol_rx_at_kb = 24;
    }

    /* ЗАДАЧА 50. Повтор FIN без ответа на потоке БЕЗ плана (глухой обрыв
       ответа Cloudflare, rua.gr 03.10) — тот же низкоуверенный сигнал
       позднего закрытия, что поздний RST: одиночный не меряется, второй по
       независимому потоку в окне запускает ровно одну RX-volume-пару, а не
       полный поиск. Поздний RST и повтор FIN подтверждают друг друга: оба —
       оборванный ответ той же цели. */
    {
        d2k_catalog c50 = {0};
        d2k_sched *s = d2k_sched_new(&c50, sv[0], 0x2d);
        CHECK(s != NULL, "планировщик для повтора FIN не завёлся");
        if (s) {
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            vol_calls = tcp_calls = 0;
            vol_answer = D2K_VOL_PASSED;
            vol_rx_cut = 0;
            settle(s);
            const char *name = "silent-cut.test";
            d2k_ev h = ev_hello(6, 41060, name);
            d2k_sched_event(s, &h);
            d2k_ev f = ev_suspect(6, 41060);
            f.code = D2K_SUSPECT_FIN_RETRY;
            f.planned = D2K_LINK_PLANNED_NO;
            CHECK(d2k_sched_event(s, &f) == 0,
                  "одиночный повтор FIN без плана сразу запустил замер");
            settle(s);
            CHECK(vol_calls == 0 && tcp_calls == 0,
                  "одиночный повтор FIN без плана дошёл до сетевого измерения");
            CHECK(said("жду второй независимый поток"),
                  "ожидание второго позднего закрытия не отражено в журнале");
            CHECK(d2k_sched_event(s, &f) == 0,
                  "повтор FIN того же потока засчитан как независимый");
            settle(s);
            CHECK(vol_calls == 0, "повтор того же потока запустил замер");
            d2k_ev h2 = ev_hello(6, 41061, name);
            d2k_sched_event(s, &h2);
            d2k_ev f2 = ev_suspect(6, 41061);
            f2.code = D2K_SUSPECT_FIN_RETRY;
            f2.planned = D2K_LINK_PLANNED_NO;
            CHECK(d2k_sched_event(s, &f2) == 1,
                  "второй повтор FIN по независимому потоку не запустил замер");
            settle(s);
            CHECK(vol_calls == 1 && tcp_calls == 0,
                  "подтверждённый повтор FIN не прошёл ровно одну RX-volume-пару");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&c50);

        /* Смешанная пара: поздний RST, затем повтор FIN на другом потоке. */
        c50 = (d2k_catalog){0};
        s = d2k_sched_new(&c50, sv[0], 0x2d);
        CHECK(s != NULL, "планировщик смешанной пары не завёлся");
        if (s) {
            d2k_sched_set_say(s, collect_say, NULL);
            vol_calls = tcp_calls = 0;
            vol_answer = D2K_VOL_PASSED;
            vol_rx_cut = 0;
            /* Часы планировщика ставит первый тик; без него первое
               подозрение помечено нулём и окно истекло бы на settle(). */
            settle(s);
            const char *name = "silent-cut-mixed.test";
            d2k_ev h = ev_hello(6, 41062, name);
            d2k_sched_event(s, &h);
            d2k_ev r = ev_suspect(6, 41062);
            r.code = D2K_SUSPECT_RST_AFTER_APP;
            d2k_sched_event(s, &r);
            settle(s);
            d2k_ev h2 = ev_hello(6, 41063, name);
            d2k_sched_event(s, &h2);
            d2k_ev f2 = ev_suspect(6, 41063);
            f2.code = D2K_SUSPECT_FIN_RETRY;
            f2.planned = D2K_LINK_PLANNED_NO;
            CHECK(d2k_sched_event(s, &f2) == 1,
                  "поздний RST и повтор FIN на независимых потоках не подтвердили друг друга");
            settle(s);
            CHECK(vol_calls == 1 && tcp_calls == 0,
                  "смешанная пара позднего закрытия не прошла ровно одну RX-volume-пару");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&c50);
    }

    /* ЗАДАЧА 56. «TCP встал на бюджете коробки» (Safari на mailsuite.com и
       www.romfea.gr, 04.10): соединение открыто, сервер глух, клиент говорит в
       тишину, пакетов с данными к тишине — в полосе бюджета. Второго потока
       не ждём (Safari держит одно соединение на источник): одиночное
       подозрение — ровно одна RX-volume-пара, не поиск; второе того же имени,
       пока пара идёт, второй пары не даёт. Под планом — так же (наблюдение
       заменяется узким замером). Если коробка цели измерена, полоса
       сверяется с ЕЁ бюджетом. Повтор FIN без плана по-прежнему ждёт второго
       потока. */
    {
        d2k_catalog c56 = {0};
        d2k_sched *s = d2k_sched_new(&c56, sv[0], 0x2d);
        CHECK(s != NULL, "планировщик для TCP-обрыва на бюджете не завёлся");
        if (s) {
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            vol_calls = tcp_calls = 0;
            vol_answer = D2K_VOL_PASSED;
            vol_rx_cut = 0;
            settle(s);
            const char *name = "stall.mailsuite.test";
            d2k_ev h = ev_hello(6, 41070, name);
            d2k_sched_event(s, &h);
            d2k_ev f = ev_suspect(6, 41070);
            f.code = D2K_SUSPECT_TCP_STALL; f.planned = D2K_LINK_PLANNED_NO; f.num = 24;
            CHECK(d2k_sched_event(s, &f) == 1,
                  "одиночный TCP-обрыв на бюджете не запустил RX-замер");
            d2k_ev h2 = ev_hello(6, 41071, name);
            d2k_sched_event(s, &h2);
            d2k_ev f2 = ev_suspect(6, 41071);
            f2.code = D2K_SUSPECT_TCP_STALL; f2.planned = D2K_LINK_PLANNED_NO; f2.num = 25;
            d2k_sched_event(s, &f2);
            settle(s);
            CHECK(vol_calls == 1 && tcp_calls == 0,
                  "TCP-обрыв на бюджете не прошёл ровно одну RX-volume-пару (без поиска)");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&c56);

        /* Под планом — тоже сразу один узкий замер. */
        c56 = (d2k_catalog){0};
        s = d2k_sched_new(&c56, sv[0], 0x2d);
        if (s) {
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            vol_calls = tcp_calls = 0;
            settle(s);
            const char *name = "stall-planned.test";
            d2k_ev h = ev_hello(6, 41072, name);
            d2k_sched_event(s, &h);
            d2k_ev f = ev_suspect(6, 41072);
            f.code = D2K_SUSPECT_TCP_STALL; f.planned = D2K_LINK_PLANNED_YES; f.num = 25;
            CHECK(d2k_sched_event(s, &f) == 1, "TCP-обрыв под планом не запустил RX-замер");
            settle(s);
            CHECK(vol_calls == 1 && tcp_calls == 0,
                  "TCP-обрыв под планом не прошёл ровно одну RX-volume-пару");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&c56);

        /* Коробка цели измерена: бюджет 16 (адресные диапазоны хостинга).
           Поток на 25 — вне её полосы, замера нет; на 17 — есть. */
        c56 = (d2k_catalog){0};
        char pid[40];
        own_box(&c56, "box-16", pid, 64, 3, "stall.hz.test", 6, D2K_SHAPE_MODERN, 4,
                1790000000, 0);
        d2k_cat_signal *rv = &c56.boxes[0].fp.sig[c56.boxes[0].fp.n_sig++];
        memset(rv, 0, sizeof *rv);
        snprintf(rv->kind, sizeof rv->kind, "rx-volume");
        rv->volume = 16; rv->seen = 1; rv->packets = 16;
        s = d2k_sched_new(&c56, sv[0], 0x2d);
        if (s) {
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            vol_calls = tcp_calls = 0;
            settle(s);
            d2k_ev h = ev_hello(6, 41074, "stall.hz.test");
            d2k_sched_event(s, &h);
            d2k_ev f = ev_suspect(6, 41074);
            f.code = D2K_SUSPECT_TCP_STALL; f.planned = D2K_LINK_PLANNED_YES; f.num = 25;
            d2k_sched_event(s, &f);
            settle(s);
            CHECK(vol_calls == 0, "TCP-обрыв вне бюджета коробки цели запустил замер");
            CHECK(said("вне бюджета её коробки"), "отказ по бюджету коробки цели не назван");
            d2k_ev h2 = ev_hello(6, 41076, "stall.hz.test");
            d2k_sched_event(s, &h2);
            d2k_ev f2 = ev_suspect(6, 41076);
            f2.code = D2K_SUSPECT_TCP_STALL; f2.planned = D2K_LINK_PLANNED_YES; f2.num = 17;
            d2k_sched_event(s, &f2);
            settle(s);
            CHECK(vol_calls == 1, "TCP-обрыв на бюджете коробки цели (16) не запустил замер");
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s);
        }
        d2k_catalog_free(&c56);
    }

    /* ЗАДАЧА 56. Бюджеты коробок уходят датапату командой после прохода по
       каталогу: полевой 25 и измеренные. Каталог без измерений — команды нет
       (датапат и так держит полевой). */
    {
        d2k_catalog cb = {0};
        char pid[40];
        own_box(&cb, "box-26", pid, 64, 3, "budget.push.test", 6, D2K_SHAPE_MODERN, 4,
                1790000000, 0);
        d2k_sched *s = d2k_sched_new(&cb, sv[0], 0x2d);
        if (s) {
            drain(); forget_sent(); d2k_sched_sync(s); sync_out(s);
            int frames = 0;
            for (size_t off = 0; off + 6 <= sent_len;) {
                const uint8_t *p = sentbuf + off;
                uint32_t n = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
                if (n < 2 || n > sent_len - off - 4) break;
                if (((uint16_t)p[4] << 8 | p[5]) == D2K_CMD_SET_STALL_BUDGETS) frames++;
                off += 4 + n;
            }
            CHECK(frames == 0, "каталог без измеренных бюджетов прислал команду бюджетов");
            d2k_sched_free(s);
        }
        d2k_cat_signal *rv = &cb.boxes[0].fp.sig[cb.boxes[0].fp.n_sig++];
        memset(rv, 0, sizeof *rv);
        snprintf(rv->kind, sizeof rv->kind, "rx-volume");
        rv->volume = 20; rv->seen = 1; rv->packets = 26;
        s = d2k_sched_new(&cb, sv[0], 0x2d);
        if (s) {
            drain(); forget_sent(); d2k_sched_sync(s); sync_out(s);
            int frames = 0, ok = 0;
            for (size_t off = 0; off + 6 <= sent_len;) {
                const uint8_t *p = sentbuf + off;
                uint32_t n = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
                if (n < 2 || n > sent_len - off - 4) break;
                if (((uint16_t)p[4] << 8 | p[5]) == D2K_CMD_SET_STALL_BUDGETS) {
                    frames++;
                    ok = n == 2 + 5 && p[6] == 2 && (p[7] << 8 | p[8]) == 25 &&
                         (p[9] << 8 | p[10]) == 26;
                }
                off += 4 + n;
            }
            CHECK(frames == 1 && ok, "бюджеты коробок (25 и 26) не ушли датапату одной командой");
            forget_sent(); d2k_sched_sync(s); sync_out(s);
            frames = 0;
            for (size_t off = 0; off + 6 <= sent_len;) {
                const uint8_t *p = sentbuf + off;
                uint32_t n = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
                if (n < 2 || n > sent_len - off - 4) break;
                if (((uint16_t)p[4] << 8 | p[5]) == D2K_CMD_SET_STALL_BUDGETS) frames++;
                off += 4 + n;
            }
            CHECK(frames == 0, "неизменные бюджеты отправлены повторно");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&cb);
    }

    /* ЗАДАЧА 50, РАУНД 2. «QUIC замолчал после рукопожатия» (Safari на
       rua.gr) — QUIC-поиск своего протокола, и вопросник обязан мерить
       ответ своим запросом (arm.data_cut), а не только ответ на Initial.
       Обычное подозрение QUIC (молчание рукопожатия) — без этого признака. */
    {
        d2k_catalog cq = {0};
        d2k_sched *s = d2k_sched_new(&cq, sv[0], 0x2d);
        CHECK(s != NULL, "планировщик для обрыва QUIC не завёлся");
        if (s) {
            settle(s);
            quic_calls = 0; quic_last_data_cut = -1;
            quic_answer = D2K_V_CLEAR;
            d2k_ev h = ev_hello(17, 41090, "quic-stall.test");
            d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(17, 41090);
            su.code = D2K_SUSPECT_QUIC_STALL;
            su.planned = D2K_LINK_PLANNED_NO;
            d2k_sched_event(s, &su);
            settle(s);
            CHECK(quic_calls == 1 && quic_last_data_cut == 1,
                  "обрыв QUIC после рукопожатия не дошёл до замера ответа своим запросом");
            CHECK(quic_last_budget == D2K_BUDGET_FIELD_PACKETS,
                  "свой запрос не получил бюджет коробки (по умолчанию поле 04.10, 25)");
            /* Поле 04.10 13:37, rua.gr в Safari: обрыв после рукопожатия
               пришёл подозрением 3 (молчание) — сервер уложился в окно
               очереди. Прежде вопросник проверял только Initial и говорил
               «проходит как есть». Теперь молчание QUIC тоже доходит до
               своего запроса — он задаётся, лишь если Initial прошёл. */
            d2k_ev h2 = ev_hello(17, 41091, "quic-silent.test");
            d2k_sched_event(s, &h2);
            d2k_ev su2 = ev_suspect(17, 41091);
            su2.code = D2K_SUSPECT_SILENT;
            d2k_sched_event(s, &su2);
            settle(s);
            CHECK(quic_calls == 2 && quic_last_data_cut == 1,
                  "молчание QUIC при прошедшем Initial не проверено своим запросом");
            CHECK(sent_quic_deny("quic-stall.test") == 0,
                  "QUIC снят по невоспроизведённому обрыву");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&cq);
        quic_answer = D2K_V_OPAQUE;
    }

    /* Молчание QUIC с признаком на входе, а OPAQUE — от рукопожатия (свой
       запрос не задавался): это не воспроизведённый обрыв после
       рукопожатия, и QUIC для имени не снимается. */
    {
        d2k_catalog cq = {0};
        d2k_sched *s = d2k_sched_new(&cq, sv[0], 0x2d);
        CHECK(s != NULL, "планировщик для молчания рукопожатия QUIC не завёлся");
        if (s) {
            settle(s);
            forget_sent();
            quic_calls = 0; quic_answer = D2K_V_OPAQUE; quic_arm_none = 1;
            quic_opaque_handshake = 1;
            d2k_ev h = ev_hello(17, 41097, "quic-hs.test");
            d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(17, 41097);
            su.code = D2K_SUSPECT_SILENT;
            su.planned = D2K_LINK_PLANNED_NO;
            d2k_sched_event(s, &su);
            for (int i = 0; i < 20; i++) settle(s);
            CHECK(quic_calls == 1 && sent_quic_deny("quic-hs.test") == 0,
                  "блок рукопожатия QUIC снял QUIC как обрыв после рукопожатия");
            quic_opaque_handshake = 0; quic_arm_none = 0;
            d2k_sched_free(s);
        }
        d2k_catalog_free(&cq);
    }

    /* ЗАДАЧА 50, РАУНД 2, требование 5c. Обрыв воспроизведён своим
       запросом, обхода по QUIC нет — QUIC для имени не пропускается (план
       quicdeny на провод, в каталог — нет: это не обход и не знание), чтобы
       браузер ушёл на TCP. По сроку отдыха снимается — следующий обрыв
       меряется заново. */
    {
        d2k_catalog cq = {0};
        d2k_sched *s = d2k_sched_new(&cq, sv[0], 0x2d);
        CHECK(s != NULL, "планировщик для снятия QUIC не завёлся");
        if (s) {
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            settle(s);
            forget_sent();
            quic_calls = 0; quic_answer = D2K_V_OPAQUE; quic_arm_none = 1;
            d2k_ev h = ev_hello(17, 41095, "quic-deny.test");
            d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(17, 41095);
            su.code = D2K_SUSPECT_QUIC_STALL;
            su.planned = D2K_LINK_PLANNED_NO;
            d2k_sched_event(s, &su);
            for (int i = 0; i < 40 && !sent_quic_deny("quic-deny.test"); i++) settle(s);
            CHECK(quic_calls == 1 && sent_quic_deny("quic-deny.test") == 1,
                  "обхода по QUIC нет, а QUIC для имени по-прежнему пропускается");
            CHECK(said("QUIC для имени не пропускаю"), "снятие QUIC не названо в журнале");
            CHECK(bindings_of(&cq, "quic-deny.test", 17) == 0,
                  "снятие QUIC записано в каталог как обход");
            /* Раунд 3: по сроку — сначала своя перепроверка (только прямые
               запросы, без плеч). Обрыв воспроизводится — снятие продлено, не
               снято. */
            quic_last_data_cut = -1;
            skip_ahead(s, 11 * 60 * 1000);
            for (int i = 0; i < 40 && sent_quic_deny("quic-deny.test") < 2; i++) settle(s);
            CHECK(quic_calls == 2 && quic_last_data_cut == 2,
                  "перед снятием запрета QUIC нет своей перепроверки только прямым запросом");
            CHECK(sent_quic_deny("quic-deny.test") == 2 &&
                  sent_del_name_key("quic-deny.test", 17, D2K_LINK_SHAPE_QUIC, 4) == 0,
                  "обрыв воспроизведён перепроверкой, а запрет QUIC снят или не продлён");
            /* Второй срок длиннее (30 мин). Ответ своим запросом пришёл — снять. */
            quic_answer = D2K_V_CLEAR;
            skip_ahead(s, 11 * 60 * 1000);
            settle(s);
            CHECK(quic_calls == 2, "продлённый запрет перепроверен раньше своего срока");
            skip_ahead(s, 20 * 60 * 1000);
            for (int i = 0; i < 40 &&
                 !sent_del_name_key("quic-deny.test", 17, D2K_LINK_SHAPE_QUIC, 4); i++) settle(s);
            CHECK(quic_calls == 3 &&
                  sent_del_name_key("quic-deny.test", 17, D2K_LINK_SHAPE_QUIC, 4) >= 1,
                  "ответ своим запросом пришёл целиком, а запрет QUIC не снят");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&cq);
        quic_arm_none = 0;
        quic_answer = D2K_V_OPAQUE;
    }

    /* Раунд 3, I2: у имени подтверждённая QUIC-привязка, а обрыв после
       рукопожатия воспроизведён своим запросом и обхода нет — привязка под
       этим обрывом не работает: помечается на повторную проверку (каталог
       цел), запрет QUIC действует, проход каталога её обратно не ставит. */
    {
        d2k_catalog cq = {0};
        char pq[40];
        own_box(&cq, "box-quic-deny", pq, 31, 5, "quic-bound.test", 17,
                D2K_LINK_SHAPE_QUIC, 4, 1790000000, 0);
        d2k_sched *s = d2k_sched_new(&cq, sv[0], 0x2d);
        CHECK(s != NULL, "планировщик для привязки под обрывом не завёлся");
        if (s) {
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            settle(s);
            drain(); forget_sent(); d2k_sched_sync(s); sync_out(s);
            size_t set_before = sent_set_name_shape("quic-bound.test", D2K_LINK_SHAPE_QUIC);
            CHECK(set_before >= 1, "фикстура: подтверждённая QUIC-привязка не встала");
            forget_sent();
            quic_calls = 0; quic_answer = D2K_V_OPAQUE; quic_arm_none = 1;
            d2k_ev h = ev_hello(17, 41097, "quic-bound.test");
            d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(17, 41097);
            su.code = D2K_SUSPECT_QUIC_STALL;
            su.planned = D2K_LINK_PLANNED_YES;
            d2k_sched_event(s, &su);
            for (int i = 0; i < 40 && !sent_quic_deny("quic-bound.test"); i++) settle(s);
            CHECK(sent_quic_deny("quic-bound.test") == 1, "обрыв под привязкой не снял QUIC");
            CHECK(cq.n_boxes == 1 && cq.boxes[0].n_binds == 1 &&
                  cq.boxes[0].binds[0].recheck_since != 0,
                  "QUIC-привязка под воспроизведённым обрывом не помечена на перепроверку");
            CHECK(said("помечена на повторную проверку"), "пометка привязки не названа в журнале");
            /* Проходы каталога после этого привязку не возвращают. */
            for (int i = 0; i < 10; i++) settle(s);
            d2k_sched_sync(s); sync_out(s);
            CHECK(sent_set_name_shape("quic-bound.test", D2K_LINK_SHAPE_QUIC) ==
                  sent_quic_deny("quic-bound.test"),
                  "проход каталога вернул QUIC-привязку поверх запрета QUIC");
            /* И даже привязка без пометки (например, подтверждённая заново
               где-то ещё) поверх действующего запрета не ставится. */
            cq.boxes[0].binds[0].recheck_since = 0;
            d2k_sched_sync(s); sync_out(s);
            CHECK(sent_set_name_shape("quic-bound.test", D2K_LINK_SHAPE_QUIC) ==
                  sent_quic_deny("quic-bound.test"),
                  "проход каталога поставил QUIC-привязку при действующем запрете QUIC");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&cq);
        quic_arm_none = 0;
        quic_answer = D2K_V_OPAQUE;
    }

    /* Найденное плечо — обычный кандидат, QUIC не снимается. */
    {
        d2k_catalog cq = {0};
        d2k_sched *s = d2k_sched_new(&cq, sv[0], 0x2d);
        if (s) {
            settle(s);
            forget_sent();
            quic_calls = 0; quic_answer = D2K_V_OPAQUE;
            d2k_ev h = ev_hello(17, 41096, "quic-arm.test");
            d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(17, 41096);
            su.code = D2K_SUSPECT_QUIC_STALL;
            su.planned = D2K_LINK_PLANNED_NO;
            d2k_sched_event(s, &su);
            settle(s);
            CHECK(quic_calls == 1 && sent_quic_deny("quic-arm.test") == 0,
                  "QUIC снят при найденном плече");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&cq);
    }

    /* «Блок доказан, кандидатов 0»: пустой поиск откладывается на cooldown,
       а не повторяется после двухминутного отдыха. */
    {
        d2k_catalog c18 = {0};
        d2k_sched *s = d2k_sched_new(&c18, sv[0], 0x2d);
        CHECK(s != NULL, "планировщик для пустого поиска не завёлся");
        if (s) {
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            quic_answer = D2K_V_PREFIX;
            arm_kind = D2K_QA_FLAKY;
            quic_calls = 0;
            d2k_ev h = ev_hello(17, 41050, "empty-search.test");
            d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(17, 41050);
            d2k_sched_event(s, &su);
            settle(s);
            CHECK(quic_calls == 1 && said("верить нельзя"),
                  "блок без кандидатов не прошёл ровно один QUIC-замер");
            skip_ahead(s, 3 * 60 * 1000);
            d2k_ev h2 = ev_hello(17, 41051, "empty-search.test");
            d2k_sched_event(s, &h2);
            d2k_ev su2 = ev_suspect(17, 41051);
            d2k_sched_event(s, &su2);
            settle(s);
            CHECK(quic_calls == 1,
                  "пустой поиск при доказанном блоке повторён через две минуты");
            skip_ahead(s, 8 * 60 * 1000);
            d2k_ev h3 = ev_hello(17, 41052, "empty-search.test");
            d2k_sched_event(s, &h3);
            d2k_ev su3 = ev_suspect(17, 41052);
            d2k_sched_event(s, &su3);
            settle(s);
            CHECK(quic_calls == 2, "после cooldown пустой поиск не возобновился");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&c18);
        quic_answer = D2K_V_OPAQUE;
        arm_kind = D2K_QA_BLOB;
    }

    /* «Готовые планы не помогли, новых кандидатов нет» — тоже cooldown. */
    {
        d2k_catalog cR;
        memset(&cR, 0, sizeof cR);
        cR.boxes = calloc(1, sizeof *cR.boxes);
        CHECK(cR.boxes != NULL, "не удалось создать коробку для пустого повтора");
        if (cR.boxes) {
            cR.n_boxes = 1;
            d2k_cat_box *b = &cR.boxes[0];
            snprintf(b->id, sizeof b->id, "box-empty-after-known");
            b->fp.method = D2K_FP_METHOD;
            b->fp.n_sig = 1;
            snprintf(b->fp.sig[0].kind, sizeof b->fp.sig[0].kind, "rst");
            b->fp.sig[0].ttl = 127;
            b->fp.sig[0].tos = 0x88;
            b->fp.sig[0].ipid = 54321;
            b->plans = calloc(1, sizeof *b->plans);
            CHECK(b->plans != NULL, "не удалось создать готовый план");
            if (b->plans) {
                b->n_plans = 1;
                b->plans[0].enabled = 1;
                b->plans[0].successes = 3;
                snprintf(b->plans[0].proto, sizeof b->plans[0].proto, "quic");
                b->plans[0].text = strdup(
                    "d2k-plan 1 1\nid 00000000000000000000000000000000\n"
                    "proto udp quic\npayload 1 aabb\n"
                    "fake payload=1 poison=0 repeats=1 gap_us=0 place=before\n"
                    "order forward\n");
            }
            if (b->plans && b->plans[0].text) {
                d2k_sched *s = d2k_sched_new(&cR, sv[0], 0x2d);
                saidbuf[0] = '\0';
                d2k_sched_set_say(s, collect_say, NULL);
                quic_answer = D2K_V_PREFIX;
                arm_kind = D2K_QA_FLAKY;
                ver_answer = D2K_VER_TRANSPORT;
                ver_fail_first = 0;
                quic_calls = ver_calls = 0;
                ver_answer_port = 41060;
                d2k_ev h = ev_hello(17, 41060, "known-then-empty.test");
                d2k_sched_event(s, &h);
                d2k_ev su = ev_suspect(17, 41060);
                d2k_sched_event(s, &su);
                spin_until_installed(s);
                for (int i = 0; i < 20 && !said("не дало новых кандидатов"); i++) {
                    d2k_ev ap = ev_applied(17, 41060);
                    d2k_sched_event(s, &ap);
                    spin(s, 80);
                }
                CHECK(said("готовых планов узнанной коробки") &&
                      said("не дало новых кандидатов"),
                      "сценарий «готовые планы не помогли, новых нет» не воспроизведён");
                int measured = quic_calls;
                skip_ahead(s, 3 * 60 * 1000);
                d2k_ev h2 = ev_hello(17, 41061, "known-then-empty.test");
                d2k_sched_event(s, &h2);
                d2k_ev su2 = ev_suspect(17, 41061);
                d2k_sched_event(s, &su2);
                settle(s);
                CHECK(quic_calls == measured && said("замер отложен"),
                      "пустой повтор после готовых планов не отложен cooldown");
                d2k_sched_free(s);
            }
        }
        d2k_catalog_free(&cR);
        quic_answer = D2K_V_OPAQUE;
        arm_kind = D2K_QA_BLOB;
        ver_answer = D2K_VER_APPLICATION;
        ver_answer_port = 0;
    }

    if (rst_only) {
        if (fails) { printf("ПРОВАЛОВ: %d\n", fails); return 1; }
        printf("RST trigger criterion: all checks passed\n");
        return 0;
    }

admission_only_run:
    {
        int lfd = socket(AF_INET6, SOCK_STREAM, 0);
        struct sockaddr_in6 local = {0};
        local.sin6_family = AF_INET6; local.sin6_addr = in6addr_loopback;
        int bound = 0;
        for (uint16_t port = 19500; port < 19600 && !bound; port++) {
            local.sin6_port = htons(port);
            bound = bind(lfd, (struct sockaddr *)&local, sizeof local) == 0;
        }
        CHECK(bound && listen(lfd, 4) == 0, "native property listener");
        uint16_t saved_port = g_server_port;
        g_server_port = ntohs(local.sin6_port);
        d2k_catalog c = {0};
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        saidbuf[0] = 0; d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_OPAQUE; ver_answer = D2K_VER_NOT_MEASURED;
        d2k_ev h = ev_hello(6, 41015, "native-properties.example");
        h.family = 6;
        CHECK(inet_pton(AF_INET6, "::1", h.low_ip) == 1, "property destination");
        CHECK(inet_pton(AF_INET6, "2001:db8::2", h.high_ip) == 1, "property client");
        d2k_sched_event(s, &h);
        d2k_ev su = h; su.kind = D2K_EV_SUSPECT; su.code = D2K_SUSPECT_RST_CUT;
        d2k_sched_event(s, &su);
        int peer = -1; struct sockaddr_in6 remote = {0};
        for (int i = 0; i < 500 && peer < 0; i++) {
            tick_once(s);
            struct pollfd p = {lfd, POLLIN, 0};
            if (poll(&p, 1, 0) > 0) {
                socklen_t len = sizeof remote;
                peer = accept(lfd, (struct sockaddr *)&remote, &len);
            }
        }
        CHECK(peer >= 0, "property question connects over native IPv6");
        if (peer >= 0) {
            for (int i = 0; i < 500 && !said("жду обмена"); i++) tick_once(s);
            d2k_ev x = {0}; x.family = 6; x.transport = 6;
            memcpy(x.low_ip, &local.sin6_addr, 16); memcpy(x.high_ip, &remote.sin6_addr, 16);
            x.low_port = g_server_port; x.high_port = ntohs(remote.sin6_port);
            x.kind = D2K_EV_EXCHANGE; x.code = 22; x.num = 1380;
            x.seen_types = 0x0c; x.server_hello = 1;
            d2k_sched_event(s, &x);
            CHECK(said("жду подтверждения полного исполнения"), "native reply matches property flow");
            x.kind = D2K_EV_APPLIED; (void)last_plan_id(x.plan_id);
            d2k_sched_event(s, &x); spin(s, 20);
            CHECK(said("перекрытие слева=нет"), "native property proof updates measured vector");
            close(peer);
        }
        d2k_sched_free(s); d2k_catalog_free(&c); close(lfd);
        g_server_port = saved_port; ver_answer = D2K_VER_APPLICATION;
    }
    for (int proof = 0; proof < 4; proof++) {
        d2k_catalog c = {0};
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        quic_answer = D2K_V_PREFIX;
        ver_answer = proof == 1 ? D2K_VER_APPLICATION : D2K_VER_NOT_MEASURED;
        ver_fail_first = 0;
        saidbuf[0] = 0; d2k_sched_set_say(s, collect_say, NULL);
        quic_calls = 0;
        drain(); forget_sent();
        d2k_ev su = ev_suspect(17, 41016);
        su.family = 6;
        CHECK(inet_pton(AF_INET6, "::1", su.low_ip) == 1, "address trial destination");
        CHECK(inet_pton(AF_INET6, "2001:db8::2", su.high_ip) == 1, "address trial client");
        d2k_sched_event(s, &su); spin_until_installed(s); drain();
        CHECK(quic_calls == 1 && !strcmp(quic_last_ip, "::1"), "unnamed native QUIC measured as IP");
        CHECK(sent_command_count(D2K_CMD_SET_NAME_PROBE, NULL, 0) == 0,
              "unnamed native QUIC never installs a name probe");
        unsigned found = 0;
        uint8_t trial[D2K_TRIAL_ID_LEN] = {0}, endpoint[38] = {0};
        for (size_t off = 0; off + 6 <= sent_len;) {
            const uint8_t *p = sentbuf + off;
            uint32_t n = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                         ((uint32_t)p[2] << 8) | p[3];
            if (n < 2 || n > sent_len - off - 4) break;
            unsigned kind = ((unsigned)p[4] << 8) | p[5];
            if (kind == D2K_CMD_SET_ADDR_PROBE && n >= 2 + 38 + sizeof trial) {
                const uint8_t *body = p + 6;
                uint8_t loopback[16] = {0}; loopback[15] = 1;
                CHECK(body[0] == 6 && !memcmp(body + 1, loopback, 16) &&
                      !memcmp(body + 17, loopback, 16) && body[37] == 17,
                      "address trial uses native routed source and full destination");
                CHECK(body[33] || body[34], "address trial has reserved source port");
                CHECK((((unsigned)body[35] << 8) | body[36]) == su.low_port,
                      "address trial preserves target port");
                memcpy(endpoint, body, sizeof endpoint);
                memcpy(trial, body + 38, sizeof trial); found++;
            }
            off += 4 + n;
        }
        CHECK(found == 1, "native address trial installed exactly once");
        if (proof && found) {
            ver_answer_port = (uint16_t)(((unsigned)endpoint[33] << 8) | endpoint[34]);
            d2k_ev ap = ev_applied(17, ver_answer_port);
            ap.family = 6;
            memcpy(ap.low_ip, endpoint + 17, 16); memcpy(ap.high_ip, endpoint + 1, 16);
            ap.low_port = su.low_port;
            memcpy(ap.trial_id, trial, sizeof trial);
            if (proof >= 2) {
                ap.kind = D2K_EV_REFUSED; ap.code = D2K_REFUSE_TOO_LONG;
                if (proof == 2) ap.high_ip[15] = 2; /* same /32, foreign full source */
            }
            d2k_sched_event(s, &ap);
            d2k_ev ack = {0}; ack.kind = D2K_EV_ACK; ack.code = D2K_CMD_SET_ADDR_PROBE;
            ack.num = 0x100u; memcpy(ack.trial_id, trial, sizeof trial);
            d2k_sched_event(s, &ack); settle(s);
            const d2k_cat_binding *bd = binding_of(&c, "::1", 17);
            if (proof >= 2) {
                CHECK(!bd && said("опыт невозможен") == (proof == 3),
                      "early IPv6 refusal matches full source, not just first32 bits");
            } else {
            if (!bd) fprintf(stderr, "native address proof trace:\n%s", saidbuf);
            CHECK(bd && bd->family == 6 && !strcmp(bd->kind, "addr"),
                  "native address proof saved as IPv6 address binding");
            CHECK(sent_command_count(D2K_CMD_SET_ADDR, NULL, 0) >= 1,
                  "native address proof promotes persistent datapath plan");
            CHECK(sent_set_addr_shape(6, endpoint + 17, D2K_LINK_SHAPE_QUIC) >= 1 &&
                  sent_command_count(D2K_CMD_SET_ADDR, NULL, 0) ==
                      sent_set_addr_shape(6, endpoint + 17, D2K_LINK_SHAPE_QUIC),
                  "QUIC address promotion not keyed by the QUIC protocol shape");
            }
        }
        settle(s); d2k_sched_free(s); drain();
        uint8_t removal[38 + D2K_TRIAL_ID_LEN];
        memcpy(removal, endpoint, 38); memcpy(removal + 38, trial, sizeof trial);
        CHECK(sent_command_count(D2K_CMD_DEL_ADDR_PROBE, removal, sizeof removal) >= 1,
              "native address trial cleanup preserves full endpoint and generation");
        d2k_catalog_free(&c); quic_answer = D2K_V_OPAQUE;
        ver_answer = D2K_VER_APPLICATION;
    }
    for (int proof = 0; proof < 2; proof++) {
        d2k_catalog c = {0};
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        tcp_answer = D2K_V_PREFIX; tcp_owns_search = tcp_found_arm = 1;
        ver_answer = proof ? D2K_VER_APPLICATION : D2K_VER_NOT_MEASURED;
        ver_answer_port = 41017; ver_fail_first = 0;
        ver_socket_family = ver_calls = 0;
        drain(); forget_sent();
        d2k_ev h = ev_hello(6, 41017, "native-probe.example");
        h.family = 6;
        CHECK(inet_pton(AF_INET6, "::1", h.low_ip) == 1, "native probe destination");
        CHECK(inet_pton(AF_INET6, "2001:db8::2", h.high_ip) == 1, "native probe client");
        d2k_sched_event(s, &h);
        d2k_ev su = h; su.kind = D2K_EV_SUSPECT; su.code = D2K_SUSPECT_RST_CUT;
        d2k_sched_event(s, &su); settle(s);
        CHECK(ver_calls > 0, "native candidate reaches verifier");
        CHECK(ver_socket_family == AF_INET6, "IPv6 verifier receives a reserved IPv6 socket");
        CHECK(strcmp(tcp_last_ip, "::1") == 0, "native measurement receives full target address");
        if (proof) {
        d2k_ev ap = ev_applied(6, 41017);
        memcpy(ap.low_ip, h.low_ip, 16); memcpy(ap.high_ip, h.high_ip, 16);
        ap.family = 4;
        d2k_sched_event(s, &ap); spin(s, 10);
        CHECK(c.n_boxes == 0, "IPv4 APPLIED cannot prove an IPv6 trial");
        ap.family = 6;
        d2k_sched_event(s, &ap); spin(s, 40);
        const d2k_cat_binding *native = binding_of(&c, "native-probe.example", 6);
        CHECK(native && native->family == 6, "verified IPv6 trial creates IPv6 binding");
        CHECK(d2k_sched_write_live(s, "/tmp/d2k-native-live.json", "") == 0,
              "write native live API snapshot");
        d2k_catalog live = {0}; char live_err[160];
        CHECK(d2k_catalog_load("/tmp/d2k-native-live.json", &live, live_err, sizeof live_err) == 0,
              "parse native bindings from live API");
        const d2k_cat_binding *live_native = binding_of(&live, "native-probe.example", 6);
        CHECK(live_native && live_native->family == 6, "live API retains transport and family of binding");
        d2k_catalog_free(&live);
        if (c.n_boxes == 1 && c.boxes[0].n_binds == 1) {
            d2k_cat_box *b = &c.boxes[0];
            d2k_cat_binding *both = realloc(b->binds, 2 * sizeof *both);
            CHECK(both != NULL, "allocate mixed-family measured bindings");
            if (both) {
                b->binds = both; b->n_binds = 2;
                both[1] = both[0];
                both[0].family = 4; both[0].input = D2K_INPUT_PROFILE;
                both[1].input = D2K_INPUT_CLIENT;
                d2k_ev sh = {0}; sh.kind = D2K_EV_SHAPE; sh.transport = 6; sh.family = 6;
                CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, "native-probe.example",
                      sh.shape, sizeof sh.shape, &sh.shape_len) == 0, "native repeat snapshot");
                int before_calls = tcp_calls;
                d2k_sched_event(s, &sh); settle(s);
                CHECK(tcp_calls == before_calls, "IPv4 profile binding cannot force IPv6 remeasurement");
            }
        }
        }
        d2k_sched_free(s); drain(); d2k_catalog_free(&c);
        unsigned installed = 0, removed = 0;
        for (size_t off = 0; off + 6 <= sent_len;) {
            const uint8_t *p = sentbuf + off;
            uint32_t n = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                         ((uint32_t)p[2] << 8) | p[3];
            if (n < 2 || n > sent_len - off - 4) break;
            unsigned kind = ((unsigned)p[4] << 8) | p[5];
            const uint8_t *body = p + 6;
            if (kind == D2K_CMD_SET_NAME_PROBE || kind == D2K_CMD_DEL_NAME_PROBE) {
                CHECK(n > 4 && (size_t)body[0] + 5 <= n - 2,
                      "native probe frame is complete");
                if (n > 4 && (size_t)body[0] + 5 <= n - 2) {
                    CHECK(body[body[0] + 2] == 6, "probe install/removal uses IPv6 family");
                    installed += kind == D2K_CMD_SET_NAME_PROBE;
                    removed += kind == D2K_CMD_DEL_NAME_PROBE;
                }
            }
            off += 4 + n;
        }
        CHECK(installed && (proof || removed), "unconfirmed native trial is installed and cleaned up");
        tcp_owns_search = tcp_found_arm = 0;
        tcp_answer = D2K_V_OPAQUE; ver_answer = D2K_VER_APPLICATION;
    }
    for (int proto_case = 0; proto_case < 2; proto_case++) {
        uint8_t transport = proto_case ? 17 : 6;
        d2k_catalog c = {0};
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        d2k_ev sh4 = {0}, sh6 = {0};
        sh4.kind = sh6.kind = D2K_EV_SHAPE;
        sh4.transport = sh6.transport = transport;
        sh4.family = 4; sh6.family = 6;
        if (!proto_case) {
        CHECK(d2k_hello_from_profile(D2K_SHAPE_LEGACY, "shape-family.example",
              sh4.shape, sizeof sh4.shape, &sh4.shape_len) == 0, "IPv4 legacy snapshot");
        CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, "shape-family.example",
              sh6.shape, sizeof sh6.shape, &sh6.shape_len) == 0, "IPv6 modern snapshot");
        CHECK(sh4.shape_len != sh6.shape_len, "snapshot fixtures differ");
        } else {
            CHECK(quic_shape(&sh4, "shape-family.example") == 0, "IPv4 QUIC snapshot");
            sh4.family = 4;
            CHECK(d2k_quic_probe_initial("shape-family.example", sh6.shape,
                  sizeof sh6.shape, &sh6.shape_len) == 0, "IPv6 QUIC snapshot");
            CHECK(sh4.shape_len != sh6.shape_len ||
                  memcmp(sh4.shape, sh6.shape, sh4.shape_len) != 0, "QUIC fixtures differ");
        }
        d2k_sched_event(s, &sh4); d2k_sched_event(s, &sh6);
        tcp_answer = quic_answer = D2K_V_CLEAR;
        quic_calls = 0;
        memset(quic_seen_trigger_lens, 0, sizeof quic_seen_trigger_lens);
        drain(); forget_sent();
        for (int family = 4; family <= 6; family += 2) {
            d2k_ev h = ev_hello(transport, 41018, "shape-family.example");
            d2k_ev su = ev_suspect(transport, 41018);
            h.family = su.family = (uint8_t)family;
            if (family == 6) {
                CHECK(inet_pton(AF_INET6, "2001:db8::1", h.low_ip) == 1, "snapshot low IPv6");
                CHECK(inet_pton(AF_INET6, "2001:db8::2", h.high_ip) == 1, "snapshot high IPv6");
                memcpy(su.low_ip, h.low_ip, 16); memcpy(su.high_ip, h.high_ip, 16);
            }
            tcp_last_wire = 0;
            d2k_sched_event(s, &h); d2k_sched_event(s, &su); settle(s);
            const d2k_ev *want = family == 4 ? &sh4 : &sh6;
            if (!proto_case) {
                CHECK(tcp_last_wire == want->shape_len, "search uses snapshot from its own family");
            } else {
                size_t idx = family == 6;
                CHECK(quic_seen_trigger_lens[idx] == want->shape_len &&
                      !memcmp(quic_seen_triggers[idx], want->shape, want->shape_len),
                      "QUIC search retains exact snapshot of its family");
            }
            uint8_t request[64];
            size_t nl = strlen("shape-family.example");
            request[0] = (uint8_t)nl;
            memcpy(request + 1, "shape-family.example", nl);
            request[nl + 1] = transport; request[nl + 2] = (uint8_t)family;
            drain();
            CHECK(sent_command_count(D2K_CMD_ARM_SHAPE, request, nl + 3) == 1,
                  "snapshot request carries the search family");
            skip_ahead(s, 1000);
        }
        d2k_sched_free(s); d2k_catalog_free(&c);
        tcp_answer = quic_answer = D2K_V_OPAQUE;
    }
    {
        d2k_catalog c = {0};
        tcp_answer = D2K_V_PREFIX; ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        confirm_once(&c, sv[0], "family-sync.example", 40170);
        CHECK(c.n_boxes == 1 && c.boxes[0].n_binds == 1, "sync family fixture confirmed");
        if (c.n_boxes == 1 && c.boxes[0].n_binds == 1) {
            d2k_cat_box *b = &c.boxes[0];
            d2k_cat_binding *grown = realloc(b->binds, 3 * sizeof *grown);
            CHECK(grown != NULL, "allocate native family bindings");
            if (grown) {
                b->binds = grown; b->n_binds = 3;
                b->binds[1] = b->binds[2] = b->binds[0];
                b->binds[0].family = 4;
                b->binds[1].family = b->binds[2].family = 6;
                snprintf(b->binds[2].kind, sizeof b->binds[2].kind, "addr");
                snprintf(b->binds[2].target, sizeof b->binds[2].target, "2001:db8::abcd");
                d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
                drain(); forget_sent();
                (void)d2k_sched_sync(s); sync_out(s);
                unsigned name4 = 0, name6 = 0, addr6 = 0;
                uint8_t want_addr[16];
                CHECK(inet_pton(AF_INET6, "2001:db8::abcd", want_addr) == 1, "sync address fixture");
                for (size_t off = 0; off + 6 <= sent_len;) {
                    const uint8_t *p = sentbuf + off;
                    uint32_t n = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                                 ((uint32_t)p[2] << 8) | p[3];
                    if (n < 2 || n > sent_len - off - 4) break;
                    unsigned kind = ((unsigned)p[4] << 8) | p[5];
                    const uint8_t *body = p + 6;
                    if (kind == D2K_CMD_SET_NAME && n > 2 + 1 + strlen("family-sync.example") + 2 &&
                        body[0] == strlen("family-sync.example") &&
                        !memcmp(body + 1, "family-sync.example", body[0])) {
                        name4 += body[2 + body[0]] == 4;
                        name6 += body[2 + body[0]] == 6;
                    }
                    if (kind == D2K_CMD_SET_ADDR && n > 19 && body[0] == 6 &&
                        !memcmp(body + 1, want_addr, 16)) addr6++;
                    off += 4 + n;
                }
                CHECK(name4 == 1 && name6 == 1, "sync restores each name family exactly once");
                CHECK(addr6 == 1, "sync restores full native IPv6 address binding");
                tcp_answer = D2K_V_CLEAR;
                d2k_ev h = ev_hello(6, 41019, "family-sync.example");
                d2k_sched_event(s, &h);
                d2k_ev su = ev_suspect(6, 41019);
                d2k_sched_event(s, &su);
                settle(s);
                /* Задача 21: один прямой проход помечает, а не удаляет. */
                CHECK(b->n_binds == 3 && b->binds[0].family == 4 &&
                      b->binds[0].recheck_since != 0,
                      "IPv4 CLEAR marks only the IPv4 binding for recheck");
                if (b->n_binds == 3) {
                    CHECK(b->binds[1].family == 6 && !b->binds[1].recheck_since &&
                          b->binds[2].family == 6 && !b->binds[2].recheck_since,
                          "IPv4 CLEAR retains IPv6 knowledge");
                }
                d2k_sched_free(s);
            }
        }
        d2k_catalog_free(&c);
        tcp_answer = D2K_V_OPAQUE;
    }
    {
        d2k_catalog c = {0};
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        tcp_calls = 0; tcp_answer = D2K_V_CLEAR;
        d2k_ev h = ev_hello(6, 41020, "family-clear.example");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 41020);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(tcp_calls == 1, "IPv4 CLEAR fixture measured once");
        skip_ahead(s, 3 * 60 * 1000);
        d2k_sched_event(s, &su);
        CHECK(d2k_sched_active(s) == 0, "IPv4 CLEAR suppresses IPv4 repeat");
        h.family = su.family = 6;
        CHECK(inet_pton(AF_INET6, "2001:db8::1", h.low_ip) == 1, "CLEAR low fixture");
        CHECK(inet_pton(AF_INET6, "2001:db8::2", h.high_ip) == 1, "CLEAR high fixture");
        memcpy(su.low_ip, h.low_ip, 16); memcpy(su.high_ip, h.high_ip, 16);
        d2k_sched_event(s, &h);
        d2k_sched_event(s, &su);
        CHECK(d2k_sched_active(s) == 1, "IPv4 CLEAR must not suppress IPv6 search");
        d2k_sched_free(s); d2k_catalog_free(&c);
        tcp_answer = D2K_V_OPAQUE;
    }
    /* Bound network work during a burst of distinct targets. Two measurements
       may run at once; the third stays queued, and starts only after the
       minimum spacing. The stub blocks until cancellation, so this verifies
       the bound without touching any external host. */
    {
        d2k_catalog c = {0};
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        tcp_calls = 0;
        tcp_block_until_stop = 1;
        tcp_saw_stop = 0;
        CHECK(s != NULL, "планировщик ограничения нагрузки не завёлся");
        if (s) {
            spin(s, 1); /* Establish the monotonic/wall clock before admission. */
            for (uint16_t i = 0; i < 3; i++) {
                char name[48];
                uint16_t port = (uint16_t)(41030 + i);
                snprintf(name, sizeof name, "burst-%u.example", (unsigned)i);
                d2k_ev h = ev_hello(6, port, name);
                d2k_sched_event(s, &h);
                d2k_ev su = ev_suspect(6, port);
                d2k_sched_event(s, &su);
            }
            settle(s);
            CHECK(tcp_calls == 2,
                  "всплеск запустил больше двух сетевых замеров одновременно");
            CHECK(d2k_sched_active(s) == 3,
                  "третий сигнал потерян, а не сохранён в ограниченной очереди");
            char live_path[] = "/tmp/d2k-queue-time-XXXXXX";
            int live_fd = mkstemp(live_path);
            CHECK(live_fd >= 0, "queue time fixture");
            if (live_fd >= 0) {
                close(live_fd);
                CHECK(!d2k_sched_write_live(s, live_path, "catalog.json"), "queue live write");
                char body[16384] = {0}; FILE *live = fopen(live_path, "r");
                if (live) { (void)!fread(body, 1, sizeof body - 1, live); fclose(live); }
                const char *row = strstr(body, "burst-2.example");
                const char *since = row ? strstr(row, "\"since\": \"") : NULL;
                struct tm tm = {0}; time_t queued_at = 0;
                if (since && strptime(since + strlen("\"since\": \""),
                                      "%Y-%m-%dT%H:%M:%SZ", &tm)) queued_at = timegm(&tm);
                CHECK(queued_at >= time(NULL) - 30 && queued_at <= time(NULL) + 30,
                      "queued task reports its admission time, not router boot time");
                /* Задача 48: в очереди плана нет — и источника плана нет. */
                const char *row_end = row ? strchr(row, '}') : NULL;
                const char *src = row ? strstr(row, "\"source\": ") : NULL;
                CHECK(src && row_end && src < row_end &&
                      !strncmp(src, "\"source\": \"\"", strlen("\"source\": \"\"")),
                      "queued task claims a plan source");
                CHECK(strstr(body, "\"measurements\": {\"active\": 2, \"limit\": 2, "
                                   "\"queued\": 1, \"cores\": null, \"free_pct\": null, "
                                   "\"mem_avail_mb\": null, \"mem_total_mb\": null, "
                                   "\"conntrack_pct\": null, \"limited_by\": null}") != NULL,
                      "без данных о процессоре live JSON не показывает прежний предел 2");
                unlink(live_path);
            }
            tcp_block_until_stop = 0;
            d2k_sched_free(s);
        }
        tcp_block_until_stop = 0;
        d2k_catalog_free(&c);
    }
    {
        /* Задача 38: темп запуска — не больше одного нового замера за
           250 мс (было 1 с). События пришли до первого тика: время ещё
           неизвестно, оба первых стартуют; третий ждёт паузу от первого
           тика и выходит из очереди после 250 мс, а не через секунду. */
        d2k_catalog c = {0};
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        tcp_calls = 0;
        tcp_block_until_stop = 0;
        tcp_answer = D2K_V_CLEAR;
        if (s) {
            for (uint16_t i = 0; i < 3; i++) {
                char name[48];
                uint16_t port = (uint16_t)(41040 + i);
                snprintf(name, sizeof name, "paced-%u.example", (unsigned)i);
                d2k_ev h = ev_hello(6, port, name);
                d2k_sched_event(s, &h);
                d2k_ev su = ev_suspect(6, port);
                d2k_sched_event(s, &su);
            }
            spin(s, 40); /* 200 мс: оба первых уже кончились, пауза ещё идёт */
            CHECK(tcp_calls == 2,
                  "третье измерение обошло межстартовую паузу 250 мс");
            spin(s, 30); /* 350 мс */
            CHECK(tcp_calls == 3,
                  "очередь не продолжилась через 250 мс (осталась прежняя секунда)");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&c);
        tcp_answer = D2K_V_OPAQUE;
    }
    {
        /* Задача 38: темп касается и свежего подозрения при уже идущем
           замере — всплеск живого трафика не даёт пачки SYN. Предел 2 (нет
           данных), часы уже идут: второй стартует не раньше 250 мс. */
        d2k_catalog c = {0};
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        tcp_calls = 0; tcp_stop_count = 0;
        tcp_wait_until_stop = 1; tcp_release_waiters = 0;
        tcp_answer = D2K_V_INCONCLUSIVE;
        if (s) {
            spin(s, 1);
            for (uint16_t i = 0; i < 2; i++) {
                char name[48];
                uint16_t port = (uint16_t)(41050 + i);
                snprintf(name, sizeof name, "pace-live-%u.example", (unsigned)i);
                d2k_ev h = ev_hello(6, port, name); d2k_sched_event(s, &h);
                d2k_ev su = ev_suspect(6, port); d2k_sched_event(s, &su);
            }
            spin(s, 40); /* 200 мс */
            CHECK(tcp_calls == 1, "pace: второй замер стартовал раньше 250 мс после первого");
            spin(s, 20); /* 300 мс */
            CHECK(tcp_calls == 2, "pace: второй замер не стартовал после паузы 250 мс");
            tcp_release_waiters = 1; spin(s, 60); tcp_release_waiters = 0;
            d2k_sched_free(s);
        }
        tcp_wait_until_stop = 0;
        tcp_answer = D2K_V_OPAQUE;
        d2k_catalog_free(&c);
    }
    /* ЗАДАЧА 29 → 38: параллельность замеров по измеренным ресурсам с
       запасом. Задача 29 мерила только процессор и ставила потолок
       min(2×ядра, 8) — оценку, не замер; её проверки «4 ядра → 8»,
       «8 ядер → 8», «2 ядра → 4» и полоса 15–30 % заменены: теперь предел
       растёт на 1 (AIMD) при запасе процессора (свободно ≥ 40 %), памяти
       (MemAvailable ≥ max(32 МБ, 20 % MemTotal)) и conntrack (< 60 %) до
       реальной ёмкости слотов, вдвое падает при нехватке любого (процессор
       < 25 %), не ниже 1; без данных — прежние 2. Источники подменены. */
    {
        /* Разбор строки /proc/stat: занятость без idle и iowait. */
        uint64_t b = 0, tt = 0;
        CHECK(d2k_sched_cpu_parse("cpu  100 5 50 800 40 3 2 0 0 0\n", &b, &tt) == 0 &&
              b == 160 && tt == 1000, "cpu parse: busy/total из строки cpu");
        CHECK(d2k_sched_cpu_parse("cpu0 1 2 3 4\n", &b, &tt) != 0,
              "cpu parse: строка отдельного ядра принята за общую");
        CHECK(d2k_sched_cpu_parse("intr 1 2 3\n", &b, &tt) != 0,
              "cpu parse: чужая строка принята");
    }
    {
        /* Разбор /proc/meminfo: MemTotal и MemAvailable в кБ; без
           MemAvailable (ядро старше 3.14) данных о памяти нет. */
        uint64_t av = 0, tot = 0;
        CHECK(d2k_sched_meminfo_parse("MemTotal:         254000 kB\nMemFree:  10000 kB\n"
                                      "MemAvailable:     120000 kB\nBuffers: 1 kB\n",
                                      &av, &tot) == 0 && av == 120000 && tot == 254000,
              "meminfo parse: MemTotal/MemAvailable");
        CHECK(d2k_sched_meminfo_parse("MemTotal: 254000 kB\nMemFree: 10000 kB\n", &av, &tot) != 0,
              "meminfo parse: без MemAvailable принята оценка");
        CHECK(d2k_sched_meminfo_parse("garbage\n", &av, &tot) != 0,
              "meminfo parse: чужой текст принят");
    }
    {
        /* Рост до ёмкости слотов задач при запасе всех ресурсов; затем
           нехватка памяти (20 % от 512 МБ = 102 МБ > 32 МБ) — предел вдвое
           на каждом снимке до 1; идущие не прерываются; один замер
           разрешён всегда. */
        d2k_catalog c = {0};
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        res_ok(1);
        tcp_calls = 0; tcp_saw_stop = 0; tcp_stop_count = 0;
        tcp_wait_until_stop = 1; tcp_release_waiters = 0;
        tcp_answer = D2K_V_INCONCLUSIVE;
        CHECK(s != NULL, "aimd: планировщик не завёлся");
        if (s) {
            d2k_sched_set_say(s, collect_say, NULL);
            saidbuf[0] = '\0';
            for (int i = 0; i < 4; i++) skip_ahead(s, 1000);
            CHECK(said("замеров 0 из 2, запас по всем ресурсам"),
                  "aimd: появление данных не названо с прежним пределом 2");
            CHECK(live_limit(s) == 2, "aimd: без спроса предел вырос сам");
            int top = meas_ramp(s, "grow", 42000, 70);
            CHECK(tcp_calls == 64,
                  "aimd: при запасе всех ресурсов замеры не дошли до ёмкости слотов (64)");
            CHECK(top == 64 && live_limit(s) == 64,
                  "aimd: предел не дорос до ёмкости слотов или перерос её");
            for (int i = 0; i < 12; i++) skip_ahead(s, 1000);
            CHECK(said("замеров 64 из 64, упёрлись в: слоты"),
                  "aimd: журнал не назвал слоты причиной потолка");
            char m[512];
            (void)live_meas(s, m, sizeof m);
            CHECK(strstr(m, "\"active\": 64, \"limit\": 64, \"queued\": 0, \"cores\": 4, "
                            "\"free_pct\": 90, \"mem_avail_mb\": 400, \"mem_total_mb\": 512, "
                            "\"conntrack_pct\": 10, \"limited_by\": \"слоты\"}") != NULL,
                  "aimd: live JSON не показывает ресурсы и причину предела");
            /* Память: 100 МБ доступно из 512 — меньше 20 % (102 МБ). */
            mem_avail_kb_v = 100u * 1024;
            int seq[8], k = 0;
            for (int i = 0; i < 8; i++) { skip_ahead(s, 1000); seq[k++] = live_limit(s); }
            CHECK(seq[0] == 32 && seq[1] == 16 && seq[2] == 8 && seq[3] == 4 &&
                  seq[4] == 2 && seq[5] == 1 && seq[6] == 1 && seq[7] == 1,
                  "aimd: нехватка памяти не уменьшает предел вдвое за снимок до 1");
            CHECK(tcp_stop_count == 0 && tcp_calls == 64,
                  "aimd: снижение предела прервало идущие замеры");
            for (int i = 0; i < 12; i++) skip_ahead(s, 1000);
            CHECK(said("замеров 64 из 1, упёрлись в: память"),
                  "aimd: журнал не назвал память причиной снижения");
            tcp_release_waiters = 1; spin(s, 60); tcp_release_waiters = 0;
            d2k_sched_free(s);
        }
        tcp_wait_until_stop = 0; tcp_release_waiters = 0;
        tcp_answer = D2K_V_OPAQUE;
        res_ok(0);
        d2k_catalog_free(&c);
    }
    {
        /* Минимум 1: нехватка памяти с самого начала — 2 → 1 и не ниже;
           один замер при этом идёт всегда, второй ждёт в очереди. */
        d2k_catalog c = {0};
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        res_ok(1);
        mem_avail_kb_v = 20u * 1024;
        tcp_calls = 0; tcp_stop_count = 0;
        tcp_wait_until_stop = 1; tcp_release_waiters = 0;
        tcp_answer = D2K_V_INCONCLUSIVE;
        if (s) {
            for (int i = 0; i < 10; i++) skip_ahead(s, 1000);
            CHECK(live_limit(s) == 1, "min: нехватка памяти не опустила предел до 1 или опустила ниже");
            for (uint16_t i = 0; i < 2; i++) {
                char name[48];
                uint16_t port = (uint16_t)(42150 + i);
                snprintf(name, sizeof name, "aimd-one-%u.example", (unsigned)i);
                d2k_ev h = ev_hello(6, port, name); d2k_sched_event(s, &h);
                d2k_ev su = ev_suspect(6, port); d2k_sched_event(s, &su);
            }
            spin(s, 100);
            for (int i = 0; i < 3; i++) skip_ahead(s, 1000);
            spin(s, 20);
            CHECK(tcp_calls == 1 && d2k_sched_active(s) == 2,
                  "min: при пределе 1 идёт не ровно один замер (второй не в очереди)");
            tcp_release_waiters = 1; spin(s, 60); tcp_release_waiters = 0;
            d2k_sched_free(s);
        }
        tcp_wait_until_stop = 0; tcp_release_waiters = 0;
        tcp_answer = D2K_V_OPAQUE;
        res_ok(0);
        d2k_catalog_free(&c);
    }
    {
        /* Процессор: свободно 30 % (между 25 и 40) — предел держится: ни
           роста при спросе, ни снижения; ниже 25 % — вдвое за снимок. */
        d2k_catalog c = {0};
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        res_ok(1);
        tcp_calls = 0; tcp_stop_count = 0;
        tcp_wait_until_stop = 1; tcp_release_waiters = 0;
        tcp_answer = D2K_V_INCONCLUSIVE;
        if (s) {
            d2k_sched_set_say(s, collect_say, NULL);
            saidbuf[0] = '\0';
            for (int i = 0; i < 4; i++) skip_ahead(s, 1000);
            (void)meas_ramp(s, "cpu-up", 42200, 8);
            /* Восемь целей по одной: каждый запуск заполняет предел, и
               снимок после него прибавляет 1 — окно на шаг впереди спроса. */
            CHECK(tcp_calls == 8 && live_limit(s) == 9, "cpu: рост до 9 при свободном процессоре");
            cpu_free_pm = 300;
            for (int i = 0; i < 60; i++) skip_ahead(s, 1000);
            CHECK(live_limit(s) == 9, "cpu: при 30 % свободных предел снизился");
            (void)meas_ramp(s, "cpu-hold", 42220, 3);
            CHECK(tcp_calls == 9 && live_limit(s) == 9,
                  "cpu: при 30 % свободных (меньше 40 %) предел вырос");
            for (int i = 0; i < 12; i++) skip_ahead(s, 1000);
            CHECK(said(" из 9, упёрлись в: процессор"),
                  "cpu: журнал не назвал процессор при удержании");
            cpu_free_pm = 100;
            int seen[64], n = 0;
            for (int i = 0; i < 40 && n < 64; i++) { skip_ahead(s, 1000); seen[n++] = live_limit(s); }
            int halving = 1;
            for (int i = 0; i < n; i++)
                if (seen[i] != 9 && seen[i] != 4 && seen[i] != 2 && seen[i] != 1) halving = 0;
            for (int i = 1; i < n; i++)
                if (seen[i] != seen[i - 1] && seen[i] != seen[i - 1] / 2) halving = 0;
            CHECK(halving && seen[n - 1] == 1, "cpu: при свободных < 25 % предел не падает вдвое до 1");
            CHECK(tcp_stop_count == 0, "cpu: снижение прервало идущие замеры");
            CHECK(said("упёрлись в: процессор"), "cpu: журнал не назвал процессор");
            tcp_release_waiters = 1; spin(s, 60); tcp_release_waiters = 0;
            d2k_sched_free(s);
        }
        tcp_wait_until_stop = 0; tcp_release_waiters = 0;
        tcp_answer = D2K_V_OPAQUE;
        res_ok(0);
        d2k_catalog_free(&c);
    }
    {
        /* conntrack: 59 % — запас, 60 % — вдвое. Память: при MemTotal
           128 МБ запас — 32 МБ (20 % меньше), 33 МБ хватает. */
        d2k_catalog c = {0};
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        res_ok(1);
        tcp_calls = 0; tcp_stop_count = 0;
        tcp_wait_until_stop = 1; tcp_release_waiters = 0;
        tcp_answer = D2K_V_INCONCLUSIVE;
        if (s) {
            d2k_sched_set_say(s, collect_say, NULL);
            saidbuf[0] = '\0';
            for (int i = 0; i < 4; i++) skip_ahead(s, 1000);
            mem_total_kb_v = 128u * 1024; mem_avail_kb_v = 33u * 1024;
            ct_count_v = 590;
            (void)meas_ramp(s, "ct-up", 42300, 8);
            CHECK(tcp_calls == 8 && live_limit(s) == 9,
                  "ct: при 59 % conntrack и 33 МБ из 128 МБ предел не рос");
            ct_count_v = 600;
            skip_ahead(s, 1000);
            CHECK(live_limit(s) == 4, "ct: при 60 % conntrack предел не уменьшился вдвое");
            for (int i = 0; i < 12; i++) skip_ahead(s, 1000);
            CHECK(said("замеров 8 из 1, упёрлись в: conntrack"),
                  "ct: журнал не назвал conntrack");
            ct_count_v = 100;
            mem_avail_kb_v = 31u * 1024;
            (void)meas_ramp(s, "ct-mem", 42320, 1);
            for (int i = 0; i < 12; i++) skip_ahead(s, 1000);
            CHECK(live_limit(s) == 1 && said("упёрлись в: память"),
                  "mem: 31 МБ при запасе 32 МБ не названы нехваткой памяти");
            tcp_release_waiters = 1; spin(s, 60); tcp_release_waiters = 0;
            d2k_sched_free(s);
        }
        tcp_wait_until_stop = 0; tcp_release_waiters = 0;
        tcp_answer = D2K_V_OPAQUE;
        res_ok(0);
        d2k_catalog_free(&c);
    }
    {
        /* Мёртвая зона журнала (задача 29) сохранена: conntrack, скачущий
           через 60 % каждый снимок, не пишет строку на каждом
           пересечении; устоявшееся состояние называется один раз. */
        d2k_catalog c = {0};
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        res_ok(1);
        if (s) {
            d2k_sched_set_say(s, collect_say, NULL);
            saidbuf[0] = '\0';
            for (int i = 0; i < 4; i++) skip_ahead(s, 1000);
            CHECK(said("замеров 0 из 2, запас по всем ресурсам"), "log: первый предел не назван");
            saidbuf[0] = '\0';
            for (int i = 0; i < 30; i++) {
                ct_count_v = (i & 1) ? 100 : 700;
                skip_ahead(s, 1000);
            }
            CHECK(!said("замеров"), "log: колебание около 60 % conntrack пишет строку на каждом пересечении");
            ct_count_v = 100;
            for (int i = 0; i < 12; i++) skip_ahead(s, 1000);
            CHECK(said("замеров 0 из 1, запас по всем ресурсам"),
                  "log: устоявшийся предел не назван");
            d2k_sched_free(s);
        }
        res_ok(0);
        d2k_catalog_free(&c);
    }
    {
        /* Горячая цель: по ждущей в очереди пришло новое подозрение — она
           стартует раньше тех, что встали до неё; остальные — FIFO. Без
           данных о ресурсах: предел 2, темп 250 мс (задача 38: свежее
           подозрение при идущем замере тоже ждёт паузу, поэтому run1 встаёт
           в очередь первым и выходит через 250 мс). */
        d2k_catalog c = {0};
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        tcp_calls = 0; tcp_block_until_stop = 0; tcp_answer = D2K_V_CLEAR;
        if (s) {
            d2k_sched_set_say(s, collect_say, NULL);
            spin(s, 1);
            const char *names[5] = { "hot-run0.example", "hot-run1.example",
                                     "hot-a.example", "hot-b.example", "hot-c.example" };
            for (uint16_t i = 0; i < 5; i++) {
                uint16_t port = (uint16_t)(41140 + i);
                d2k_ev h = ev_hello(6, port, names[i]); d2k_sched_event(s, &h);
                d2k_ev su = ev_suspect(6, port); d2k_sched_event(s, &su);
            }
            spin(s, 55); /* 275 мс: run0 сразу, run1 — через паузу */
            CHECK(tcp_calls == 2, "hot: run0 и run1 не стартовали за первую паузу");
            saidbuf[0] = '\0';
            d2k_ev again = ev_suspect(6, 41144); d2k_sched_event(s, &again);
            skip_ahead(s, 250);
            CHECK(said("по hot-c.example ожидание в очереди") &&
                  !said("по hot-a.example ожидание в очереди"),
                  "hot: цель с новым подозрением не обогнала тихую очередь");
            spin(s, 10);
            skip_ahead(s, 250);
            CHECK(said("по hot-a.example ожидание в очереди") &&
                  !said("по hot-b.example ожидание в очереди"),
                  "hot: тихая очередь нарушила FIFO");
            d2k_sched_free(s);
        }
        tcp_answer = D2K_V_OPAQUE;
        d2k_catalog_free(&c);
    }
    if (admission_only) {
        close(sv[0]); close(sv[1]);
        if (fails) { printf("ПРОВАЛОВ: %d\n", fails); return 1; }
        printf("measurement admission: all checks passed\n");
        return 0;
    }

    /* --- подозрение по TCP идёт в дерево вердиктов --------------------- */
    {
        static const struct {
            const char *name;
            int excluded;
        } cases[] = {
            { "telegram.org", 1 },
            { "core.telegram.org", 1 },
            { "WEB.TELEGRAM.ORG", 1 },
            { "nottelegram.org", 0 },
        };
        for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
            d2k_catalog empty = {0};
            d2k_sched *s = d2k_sched_new(&empty, sv[0], 0x2d);
            uint16_t port = (uint16_t)(40600 + i);
            tcp_calls = quic_calls = 0;
            d2k_ev h = ev_hello(6, port, cases[i].name);
            d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, port);
            int rc = d2k_sched_event(s, &su);
            if (cases[i].excluded) {
                CHECK(rc == 0, "telegram.org попал в очередь замеров");
                settle(s);
                CHECK(tcp_calls == 0 && quic_calls == 0,
                      "telegram.org запустил сетевое измерение");
            } else {
                CHECK(rc == 1, "похожий, но посторонний домен исключён ошибочно");
                settle(s);
                CHECK(tcp_calls == 1, "посторонний домен перестал измеряться");
            }
            d2k_sched_free(s);
            d2k_catalog_free(&empty);
        }
    }

    /* --- подозрение по TCP идёт в дерево вердиктов --------------------- */
    {
        tcp_calls = quic_calls = 0;
        d2k_sched *s = d2k_sched_new(&cat, sv[0], 0x2d);
        CHECK(s != NULL, "планировщик не завёлся");
        d2k_ev h = ev_hello(6, 40001, "instagram.com");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40001);
        CHECK(d2k_sched_event(s, &su) == 1, "поиск по TCP не начат");
        settle(s);
        CHECK(tcp_calls == 1, "дерево вердиктов TCP не вызвано");
        CHECK(quic_calls == 0, "по TCP-подозрению позван вопросник QUIC");
        CHECK(strcmp(tcp_last_ip, "127.0.0.1") == 0,
              "дереву вердиктов достался не адрес сервера из ключа потока");
        d2k_sched_free(s);
    }

    /* --- подозрение по UDP идёт в вопросник QUIC ----------------------- */
    {
        tcp_calls = quic_calls = 0;
        d2k_sched *s = d2k_sched_new(&cat, sv[0], 0x2d);
        d2k_sched_set_measure_mark(s, 0x2f);
        d2k_ev h = ev_hello(17, 40002, "instagram.com");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(17, 40002);
        CHECK(d2k_sched_event(s, &su) == 1, "поиск по QUIC не начат");
        {
            d2k_ev sh;
            CHECK(quic_shape(&sh, "instagram.com") == 0, "снимок QUIC не собрался");
            d2k_sched_event(s, &sh);
        }
        settle(s);
        CHECK(quic_calls >= 1, "вопросник QUIC не вызван");
        CHECK(quic_last_mark == 0x2f,
              "QUIC-измерение не получило отдельную обходную метку");
        CHECK(tcp_calls == 0, "по UDP-подозрению позвано дерево вердиктов TCP");
        CHECK(strcmp(quic_last_sni, "instagram.com") == 0,
              "вопроснику QUIC досталось не имя цели");
        d2k_sched_free(s);
    }

    /* --- QUIC НАЧИНАЕТСЯ СВОИМ INITIAL, КАК buildInitial ДОНОРА --------
     * Отсутствие снимка не разрешает слать TLS-запись в UDP, но и не
     * запрещает исходный корректный QUIC-зонд. stub_quic разбирает AEAD/SNI
     * настоящим парсером; обе стороны должны быть QUIC, а не просто байты. */
    {
        tcp_calls = quic_calls = 0;
        d2k_catalog cW;
        memset(&cW, 0, sizeof cW);
        d2k_sched *s = d2k_sched_new(&cW, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        d2k_ev h = ev_hello(17, 40004, "ждём.форму");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(17, 40004);
        CHECK(d2k_sched_event(s, &su) == 1, "подозрение по QUIC не завело задачу");
        settle(s);
        CHECK(quic_calls == 1, "оригинальный QUIC-поиск не запущен без снимка");
        CHECK(tcp_calls == 0 && strcmp(quic_last_trig, "ждём.форму") == 0 &&
              strcmp(quic_last_ctl, "disk.rzd.ru") == 0,
              "холодный QUIC-зонд/контроль не являются Initial со своими именами");
        CHECK(said("собственным QUIC Initial") && !said("жду форму приветствия"),
              "собственный QUIC-вход не назван либо поиск всё ещё ждёт снимок");
        CHECK(binding_of(&cW, "ждём.форму", 17) == NULL,
              "один холодный замер записан подтверждённым обходом");

        /* Поздний снимок не подменяет вход уже идущего опыта. */
        {
            d2k_ev sh;
            CHECK(quic_shape(&sh, "ждём.форму") == 0, "снимок QUIC не собрался");
            d2k_sched_event(s, &sh);
        }
        settle(s);
        CHECK(quic_calls == 1, "снимок подменил вход текущего QUIC-опыта");
        CHECK(strcmp(quic_last_trig, "ждём.форму") == 0,
              "имя цели потерялось в собственном Initial");
        /* КОНТРОЛЬ — тоже QUIC, и с именем приманки: он собирается из того же
           входа (core/quichello.c). Прежде сюда уезжало TLS-приветствие, и
           базовая живость не подтверждалась никогда. */
        CHECK(strcmp(quic_last_ctl, "disk.rzd.ru") == 0,
              "контроль по QUIC не собран из входа с именем приманки");
        d2k_sched_free(s);
        d2k_catalog_free(&cW);
    }

    /* SHAPE, пришедший ПОКА ИДЁТ QUIC Run, относится к тому же имени и
       обязан запустить ровно один повтор после завершения текущего вопроса.
       Нельзя менять вход активного опыта; повтор обязан получить реальные
       байты события, а не пересобранный профиль с тем же SNI. */
    {
        d2k_catalog empty = {0};
        d2k_sched *s = d2k_sched_new(&empty, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_calls = quic_calls = 0;
        memset(quic_seen_trigger_lens, 0, sizeof quic_seen_trigger_lens);
        snapshot_enabled = 1;
        snapshot_entered = snapshot_release = snapshot_ok = 0;
        quic_answer = D2K_V_CLEAR;
        d2k_ev h = ev_hello(17, 40005, "late.quic.example");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(17, 40005);
        d2k_sched_event(s, &su);
        pthread_mutex_lock(&snapshot_mu);
        struct timespec snapshot_deadline;
        clock_gettime(CLOCK_REALTIME, &snapshot_deadline);
        snapshot_deadline.tv_sec += 2;
        int snapshot_wait_rc = 0;
        while (!snapshot_entered && snapshot_wait_rc == 0) {
            snapshot_wait_rc = pthread_cond_timedwait(&snapshot_cv, &snapshot_mu,
                                                       &snapshot_deadline);
        }
        int quic_entered = snapshot_entered;
        pthread_mutex_unlock(&snapshot_mu);
        CHECK(quic_entered, "QUIC worker не достиг контрольного барьера");
        d2k_ev sh;
        CHECK(quic_shape(&sh, "late.quic.example") == 0,
              "поздний QUIC снимок не собрался");
        d2k_sched_event(s, &sh);
        pthread_mutex_lock(&snapshot_mu);
        snapshot_release = 1;
        pthread_cond_broadcast(&snapshot_cv);
        pthread_mutex_unlock(&snapshot_mu);
        settle(s);
        CHECK(snapshot_ok, "поздний SHAPE изменил байты уже идущего QUIC-опыта");
        CHECK(quic_calls == 2,
              "снимок QUIC во время ASKING не вызвал ровно один повтор измерения");
        CHECK(quic_seen_trigger_lens[1] == sh.shape_len &&
              memcmp(quic_seen_triggers[1], sh.shape, sh.shape_len) == 0,
              "повтор QUIC-измерения не получил точные байты позднего снимка");
        d2k_sched_free(s);
        d2k_catalog_free(&empty);
        snapshot_enabled = 0;
        quic_answer = D2K_V_OPAQUE;
    }

    /* Свежий QUIC snapshot во время VERIFY отменяет только поставленный
       кандидат. Без этого барьера scheduler успевал записать профильный
       trial как будто это байты клиента. */
    {
        d2k_catalog cV;
        memset(&cV, 0, sizeof cV);
        d2k_sched *s = d2k_sched_new(&cV, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        quic_calls = ver_calls = 0;
        memset(quic_seen_trigger_lens, 0, sizeof quic_seen_trigger_lens);
        quic_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_answer_port = 40006;
        ver_snapshot_enabled = 1;
        ver_snapshot_entered = ver_snapshot_release = 0;
        d2k_ev h = ev_hello(17, 40006, "verify.snapshot.example");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(17, 40006);
        d2k_sched_event(s, &su);
        spin(s, 20);
        pthread_mutex_lock(&snapshot_mu);
        struct timespec verify_deadline;
        clock_gettime(CLOCK_REALTIME, &verify_deadline);
        verify_deadline.tv_sec += 2;
        int verify_wait_rc = 0;
        while (!ver_snapshot_entered && verify_wait_rc == 0) {
            verify_wait_rc = pthread_cond_timedwait(&snapshot_cv, &snapshot_mu,
                                                     &verify_deadline);
        }
        pthread_mutex_unlock(&snapshot_mu);
        CHECK(ver_snapshot_entered, "QUIC VERIFY не достиг контрольного барьера");
        d2k_ev sh;
        CHECK(quic_shape(&sh, "verify.snapshot.example") == 0,
              "VERIFY snapshot не собрался");
        d2k_sched_event(s, &sh);
        pthread_mutex_lock(&snapshot_mu);
        ver_snapshot_release = 1;
        pthread_cond_broadcast(&snapshot_cv);
        pthread_mutex_unlock(&snapshot_mu);
        settle(s);
        CHECK(quic_calls == 2,
              "snapshot во время VERIFY не вызвал ровно один повтор QUIC-поиска");
        CHECK(quic_seen_trigger_lens[1] == sh.shape_len &&
              memcmp(quic_seen_triggers[1], sh.shape, sh.shape_len) == 0,
              "повтор после VERIFY не получил точные байты snapshot клиента");
        ver_snapshot_enabled = 0;
        d2k_sched_free(s);
        d2k_catalog_free(&cV);
        quic_answer = D2K_V_OPAQUE;
    }

    /* --- СНИМОК СОСЕДА ЗАКРЫВАЕТ ХОЛОДНЫЙ СТАРТ QUIC ---------------------
     *
     * Рилсы Instagram у владельца роутера 13.09.2026 не грузились вовсе:
     * ролики едут с хостов `scontent-*.cdninstagram.com`, которые меняются от
     * ролика к ролику, второго обращения к тому же имени не бывает, и задача
     * умирала с «формы приветствия так и не пришло» — три смерти за тридцать
     * секунд листания на живой линии.
     *
     * Байты приветствия задаёт КЛИЕНТ: снимок, снятый с одной цели, годится
     * соседней с переписанным именем (d2k_quic_hello_rename — им уже
     * собирается контроль). Проверяем, что вторая цель мерится СРАЗУ и своим
     * именем, а не ждёт собственного снимка. */
    {
        tcp_calls = quic_calls = 0;
        d2k_catalog cQ;
        memset(&cQ, 0, sizeof cQ);
        d2k_sched *s = d2k_sched_new(&cQ, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);

        d2k_ev h1 = ev_hello(17, 40201, "первая.цель");
        d2k_sched_event(s, &h1);
        d2k_ev su1 = ev_suspect(17, 40201);
        d2k_sched_event(s, &su1);
        settle(s);
        CHECK(quic_calls == 1, "первая цель QUIC не начала собственный замер без снимка");
        {
            d2k_ev sh;
            CHECK(quic_shape(&sh, "первая.цель") == 0, "снимок QUIC не собрался");
            d2k_sched_event(s, &sh);
        }
        settle(s);
        CHECK(quic_calls == 1, "после прихода формы поиск первой цели не начался");

        /* Вторая цель — своего снимка у неё нет и не будет. */
        d2k_ev h2 = ev_hello(17, 40202, "вторая.цель");
        d2k_sched_event(s, &h2);
        d2k_ev su2 = ev_suspect(17, 40202);
        d2k_sched_event(s, &su2);
        settle(s);
        CHECK(quic_calls == 2,
              "вторая цель QUIC ушла ждать собственный снимок — рилсы так и теряются");
        CHECK(strcmp(quic_last_trig, "вторая.цель") == 0,
              "мерить пошли чужим именем: снимок соседа не переименован");
        CHECK(strcmp(quic_last_ctl, "disk.rzd.ru") == 0,
              "контроль из переписанного снимка не собрался");
        d2k_sched_free(s);
        d2k_catalog_free(&cQ);
    }

    /* --- КОРОБКА НЕ ОБХОДИТ ПРЯМОЙ ЗАМЕР -------------------------------
     * Даже если коробка известна, стратегия не испытывается до подтверждения
     * блокировки именно у этой цели. */
    {
        tcp_calls = quic_calls = 0;
        d2k_catalog cK;
        memset(&cK, 0, sizeof cK);
        cK.boxes = calloc(1, sizeof *cK.boxes);
        CHECK(cK.boxes != NULL, "не удалось создать модель коробки");
        if (cK.boxes) {
            cK.n_boxes = 1;
            d2k_cat_box *b = &cK.boxes[0];
            snprintf(b->id, sizeof b->id, "box-quic-known");
            b->fp.method = D2K_FP_METHOD;
            b->fp.n_sig = 1;
            snprintf(b->fp.sig[0].kind, sizeof b->fp.sig[0].kind, "rst");
            b->fp.sig[0].ttl = 127;
            b->fp.sig[0].tos = 0x88;
            b->fp.sig[0].ipid = 54321;
            b->plans = calloc(2, sizeof *b->plans);
            CHECK(b->plans != NULL, "не удалось создать план модели");
            if (b->plans) {
                b->n_plans = 2;
                b->plans[0].enabled = 1;
                b->plans[0].successes = 4;
                snprintf(b->plans[0].proto, sizeof b->plans[0].proto, "quic");
                b->plans[0].text = strdup(
                    "d2k-plan 1 1\nid 00000000000000000000000000000000\n"
                    "proto udp quic\npayload 1 aabb\n"
                    "fake payload=1 poison=0 repeats=1 gap_us=0 place=before\n"
                    "order forward\n");
                CHECK(b->plans[0].text != NULL, "текст плана не создался");
                snprintf(b->plans[1].id, sizeof b->plans[1].id,
                         "plan-tls-still-valid");
                b->plans[1].enabled = 1;
                b->plans[1].successes = 2;
                snprintf(b->plans[1].proto, sizeof b->plans[1].proto, "tls");
                b->plans[1].text = strdup(
                    "d2k-plan 1 1\nid 00000000000000000000000000000000\n"
                    "proto tcp tls\nsplit payload_start +1\norder forward\n");
                CHECK(b->plans[1].text != NULL, "TLS-план коробки не создался");
            }
            b->binds = calloc(2, sizeof *b->binds);
            CHECK(b->binds != NULL, "не удалось создать старые привязки коробки");
            if (b->binds) {
                b->n_binds = 2;
                snprintf(b->binds[0].kind, sizeof b->binds[0].kind, "name");
                snprintf(b->binds[0].target, sizeof b->binds[0].target,
                         "новый.хост.цдн");
                snprintf(b->binds[0].plan_id, sizeof b->binds[0].plan_id,
                         "plan-quic-stale");
                b->binds[0].enabled = 1;
                b->binds[0].level = 3;
                b->binds[0].transport = 17;
                b->binds[0].shape = D2K_LINK_SHAPE_QUIC;
                snprintf(b->binds[1].kind, sizeof b->binds[1].kind, "name");
                snprintf(b->binds[1].target, sizeof b->binds[1].target,
                         "новый.хост.цдн");
                snprintf(b->binds[1].plan_id, sizeof b->binds[1].plan_id,
                         "plan-tls-still-valid");
                b->binds[1].enabled = 1;
                b->binds[1].level = 3;
                b->binds[1].transport = 6;
                b->binds[1].shape = D2K_SHAPE_MODERN;
            }
            if (b->plans && b->plans[0].text) {
                /* An existing box plan is not evidence that this target is
                   blocked. A clear direct QUIC measurement must stop before
                   installing the catalog plan. */
                {
                    d2k_sched *s = d2k_sched_new(&cK, sv[0], 0x2d);
                    saidbuf[0] = '\0';
                    d2k_sched_set_say(s, collect_say, NULL);
                    quic_answer = D2K_V_CLEAR;
                    quic_calls = ver_calls = 0;
                    d2k_ev h = ev_hello(17, 40202, "новый.хост.цдн");
                    d2k_sched_event(s, &h);
                    d2k_ev su = ev_suspect(17, 40202);
                    d2k_sched_event(s, &su);
                    settle(s);
                    CHECK(quic_calls == 1,
                          "известная коробка обошла прямое QUIC-измерение");
                    CHECK(ver_calls == 0,
                          "при прямом QUIC-проходе проверялся готовый обход");
                    CHECK(!said("готовых планов узнанной коробки"),
                          "готовый обход запускался без подтверждения блокировки");
                    /* Задача 21: один прямой проход не удаляет, а помечает
                       «требует повторной проверки» и снимает с провода. */
                    CHECK(b->n_binds == 2 && b->binds[0].transport == 17 &&
                          b->binds[0].recheck_since != 0 &&
                          b->binds[1].transport == 6 && !b->binds[1].recheck_since,
                          "прямой проход не пометил старую QUIC-привязку или задел TLS");
                    CHECK(cK.revision > 0,
                          "снятие устаревшей привязки не отметило каталог для сохранения");
                    d2k_sched_free(s);
                }

                /* A flaky 2/3 direct measurement is uncertainty, not a
                   license to probe Ozon-like targets with a known bypass. */
                {
                    d2k_sched *s = d2k_sched_new(&cK, sv[0], 0x2d);
                    saidbuf[0] = '\0';
                    d2k_sched_set_say(s, collect_say, NULL);
                    quic_answer = D2K_V_FLAKY;
                    quic_calls = ver_calls = 0;
                    d2k_ev h = ev_hello(17, 40206, "сомнительная.цель");
                    d2k_sched_event(s, &h);
                    d2k_ev su = ev_suspect(17, 40206);
                    d2k_sched_event(s, &su);
                    settle(s);
                    CHECK(quic_calls == 1,
                          "неоднозначная коробка не прошла прямой QUIC-замер");
                    CHECK(ver_calls == 0,
                          "при неоднозначном QUIC-замере применялся обход");
                    CHECK(!said("готовых планов узнанной коробки"),
                          "готовый обход применён без подтверждения блокировки");
                    d2k_sched_free(s);
                    quic_answer = D2K_V_OPAQUE;
                }

                /* With a positive direct-block verdict, reuse stays first:
                   measure first, then try the box plan before synthesis. */
                d2k_sched *s = d2k_sched_new(&cK, sv[0], 0x2d);
                saidbuf[0] = '\0';
                d2k_sched_set_say(s, collect_say, NULL);
                quic_answer = D2K_V_OPAQUE;
                ver_answer = D2K_VER_APPLICATION;
                ver_fail_first = 0;
                ver_calls = 0;
                quic_calls = 0;
                ver_answer_port = 40203;
                d2k_ev h = ev_hello(17, 40203, "новый.хост.цдн");
                d2k_sched_event(s, &h);
                d2k_ev su = ev_suspect(17, 40203);
                d2k_sched_event(s, &su);
                spin_until_installed(s);
                {
                    d2k_ev ap = ev_applied(17, 40203);
                    d2k_sched_event(s, &ap);
                    spin(s, 80);
                }
                CHECK(said("готовых планов узнанной коробки"),
                      "после прямого подтверждения блокировки не проверен план коробки");
                CHECK(quic_calls == 1,
                      "прямой QUIC-замер не выполнен до готового плана");
                CHECK(ver_calls >= 1, "готовый план не дошёл до зонда");
                d2k_sched_free(s);
            }
        }
        d2k_catalog_free(&cK);
    }

    /* --- ЗАМЕР ПОСЛЕ ПРОВАЛА ГОТОВЫХ ПЛАНОВ ИДЁТ С КОНТРОЛЕМ ------------
     *
     * Задача QUIC входит в испытание готовых планов БЕЗ приветствий вовсе
     * (коробка узнана, снимка ещё нет — испытать готовый план ими не нужно).
     * Если готовые планы не помогли, начинается замер — и вот ему приветствия
     * нужны оба. На живой линии 13.09.2026 замер стартовал со старым пустым
     * контролем и закончился «вердикта нет (нет контрольного имени)»: вопрос
     * коробке не задавался вовсе, а восемь кандидатов ушли в никуда.
     *
     * Снимок здесь приезжает ПОСЛЕ входа в испытание — ровно как на линии. */
    {
        tcp_calls = quic_calls = 0;
        d2k_catalog cR;
        memset(&cR, 0, sizeof cR);
        cR.boxes = calloc(1, sizeof *cR.boxes);
        CHECK(cR.boxes != NULL, "не удалось создать модель коробки");
        if (cR.boxes) {
            cR.n_boxes = 1;
            d2k_cat_box *b = &cR.boxes[0];
            snprintf(b->id, sizeof b->id, "box-quic-remeasure");
            b->fp.method = D2K_FP_METHOD;
            b->fp.n_sig = 1;
            snprintf(b->fp.sig[0].kind, sizeof b->fp.sig[0].kind, "rst");
            b->fp.sig[0].ttl = 127;
            b->fp.sig[0].tos = 0x88;
            b->fp.sig[0].ipid = 54321;
            b->plans = calloc(1, sizeof *b->plans);
            CHECK(b->plans != NULL, "не удалось создать план модели");
            if (b->plans) {
                b->n_plans = 1;
                b->plans[0].enabled = 1;
                b->plans[0].successes = 3;
                snprintf(b->plans[0].proto, sizeof b->plans[0].proto, "quic");
                b->plans[0].text = strdup(
                    "d2k-plan 1 1\nid 00000000000000000000000000000000\n"
                    "proto udp quic\npayload 1 aabb\n"
                    "fake payload=1 poison=0 repeats=1 gap_us=0 place=before\n"
                    "order forward\n");
                CHECK(b->plans[0].text != NULL, "текст плана не создался");
            }
            if (b->plans && b->plans[0].text) {
                d2k_sched *s = d2k_sched_new(&cR, sv[0], 0x2d);
                saidbuf[0] = '\0';
                d2k_sched_set_say(s, collect_say, NULL);
                quic_calls = 0;
                memset(quic_seen_trigger_lens, 0, sizeof quic_seen_trigger_lens);
                /* Положительный прямой вердикт допускает повторное применение. */
                ver_answer = D2K_VER_HANDSHAKE;
                ver_fail_first = 0;
                ver_calls = 0;
                ver_answer_port = 40205;
                d2k_ev h = ev_hello(17, 40205, "остыл.снимок.позже");
                d2k_sched_event(s, &h);
                d2k_ev sh;
                CHECK(quic_shape(&sh, "остыл.снимок.позже") == 0,
                      "снимок QUIC не собрался");
                d2k_sched_event(s, &sh);
                d2k_ev su = ev_suspect(17, 40205);
                d2k_sched_event(s, &su);
                spin_until_installed(s);
                CHECK(said("готовых планов узнанной коробки"),
                      "готовый план не был проверен после прямого подтверждения блокировки");
                CHECK(quic_calls == 1,
                      "перед планом узнанной коробки не выполнен ровно один прямой QUIC-замер");
                CHECK(quic_seen_trigger_lens[0] == sh.shape_len &&
                      memcmp(quic_seen_triggers[0], sh.shape, sh.shape_len) == 0,
                      "прямое QUIC-измерение не использовало снимок клиента");
                CHECK(strcmp(quic_last_ctl, "disk.rzd.ru") == 0,
                      "замер пошёл БЕЗ контрольного имени — вопрос коробке не задан, "
                      "а кандидаты будут потрачены впустую");
                CHECK(strcmp(quic_last_trig, "остыл.снимок.позже") == 0,
                      "мерить пошли не приветствием цели");
                d2k_sched_free(s);
            }
        }
        d2k_catalog_free(&cR);
    }

    /* --- ПРОБНЫЙ ПЛАН СТАВИТСЯ ПОД ПОРТ ЗОНДА, А НЕ ВСЕМ ------------------
     *
     * Испытывает кандидата зонд, а платил за испытание пользователь: план
     * вставал по имени и доставался всем, кто шёл к этой цели. На роутере
     * владельца 13.09.2026 поиск по i.ytimg.com шёл двадцать одну минуту, и
     * всё это время цель работала через раз.
     *
     * Проверяем, что зонду достаётся УЖЕ ЗАНЯТЫЙ сокет: значит порт известен
     * заранее и план поставлен именно под него. */
    {
        d2k_catalog cP;
        memset(&cP, 0, sizeof cP);
        d2k_sched *s = d2k_sched_new(&cP, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_calls = 0;
        ver_last_fd = -2;
        ver_answer_port = 40301;
        d2k_ev h = ev_hello(6, 40301, "испытание.под.портом");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40301);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(ver_calls >= 1, "зонд не пошёл вовсе");
        CHECK(ver_last_fd >= 0,
              "зонду достался пустой сокет — порт не занят заранее, значит пробный "
              "план встал ВСЕМ, а не одному потоку");
        d2k_sched_free(s);
        d2k_catalog_free(&cP);
    }

    /* То же для QUIC: у него свой сокет внутри рукопожатия, и порт для него
       занимается ДРУГИМ вызовом (датаграммным). Пока этого не было, в журнале
       стояло «порт зонда 0» и испытание по QUIC действовало на всех. */
    {
        d2k_catalog cQ2;
        memset(&cQ2, 0, sizeof cQ2);
        d2k_sched *s = d2k_sched_new(&cQ2, sv[0], 0x2d);
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_calls = 0;
        ver_last_fd = -2;
        ver_answer_port = 40302;
        d2k_ev h = ev_hello(17, 40302, "квик.под.портом");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(17, 40302);
        d2k_sched_event(s, &su);
        {
            d2k_ev sh;
            CHECK(quic_shape(&sh, "квик.под.портом") == 0, "снимок QUIC не собрался");
            d2k_sched_event(s, &sh);
        }
        settle(s);
        CHECK(ver_calls >= 1, "зонд QUIC не пошёл вовсе");
        CHECK(ver_last_fd >= 0,
              "зонду QUIC достался пустой сокет — испытание по QUIC действует на всех");
        d2k_sched_free(s);
        d2k_catalog_free(&cQ2);
    }

    /* --- ПОДТВЕРЖДЕНИЕ УСТАНОВКИ ПРОБЫ ПРИВЯЗАНО К СВОЕМУ ОПЫТУ ---------
     *
     * Задача 19. ACK SET_NAME_PROBE раньше отпускал ВСЕ задачи в ожидании
     * приёма плана, не глядя ни на опыт, ни на признак успеха. Теперь ack
     * несёт trial ID: чужое подтверждение никого не отпускает, своё —
     * только свою задачу. */
    {
        d2k_catalog cT;
        memset(&cT, 0, sizeof cT);
        d2k_sched *s = d2k_sched_new(&cT, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_calls = 0;
        ver_answer_port = 40611;
        forget_sent();
        d2k_ev h1 = ev_hello(6, 40611, "первая.проба");
        d2k_sched_event(s, &h1);
        d2k_ev su1 = ev_suspect(6, 40611);
        d2k_sched_event(s, &su1);
        d2k_ev h2 = ev_hello(6, 40612, "вторая.проба");
        d2k_sched_event(s, &h2);
        d2k_ev su2 = ev_suspect(6, 40612);
        d2k_sched_event(s, &su2);
        for (int i = 0; i < 4000 && !(said("по первая.проба поставил план") &&
                                      said("по вторая.проба поставил план")); i++) {
            tick_frozen(s);
        }
        CHECK(said("по первая.проба поставил план") && said("по вторая.проба поставил план"),
              "обе задачи не дошли до ожидания приёма пробного плана");
        uint8_t id1[D2K_TRIAL_ID_LEN], id2[D2K_TRIAL_ID_LEN];
        CHECK(name_probe_trial("первая.проба", id1) && name_probe_trial("вторая.проба", id2),
              "SET_NAME_PROBE опыта ушла без trial ID");
        CHECK(memcmp(id1, id2, D2K_TRIAL_ID_LEN) != 0, "у двух опытов один trial ID");
        int base = ver_calls;
        uint8_t foreign[D2K_TRIAL_ID_LEN];
        memset(foreign, 0x77, sizeof foreign);
        d2k_ev a = name_probe_ack(foreign, 1, D2K_ACK_OK);
        d2k_sched_event(s, &a);
        uint8_t zero[D2K_TRIAL_ID_LEN] = {0};
        a = name_probe_ack(zero, 1, D2K_ACK_OK);
        d2k_sched_event(s, &a);
        for (int i = 0; i < 40; i++) { tick_frozen(s); }
        CHECK(ver_calls == base, "чужое подтверждение установки отпустило ожидание опыта");
        a = name_probe_ack(id1, 1, D2K_ACK_OK);
        d2k_sched_event(s, &a);
        for (int i = 0; i < 400 && ver_calls == base; i++) { tick_frozen(s); }
        for (int i = 0; i < 40; i++) { tick_frozen(s); }
        CHECK(ver_calls == base + 1,
              "подтверждение первой задачи отпустило не ровно её одну");
        a = name_probe_ack(id2, 1, D2K_ACK_OK);
        d2k_sched_event(s, &a);
        for (int i = 0; i < 400 && ver_calls == base + 1; i++) { tick_frozen(s); }
        CHECK(ver_calls == base + 2, "своё подтверждение второй задачи её не отпустило");
        d2k_sched_free(s);
        d2k_catalog_free(&cT);
    }

    /* --- ОТКАЗ ИСПОЛНИТЕЛЯ — НЕ ПРОМАХ КАНДИДАТА -------------------------
     *
     * Задача 19. Датапат ответил ok=0/BAD_PLAN (план не годится способу
     * отправки). Раньше ack засчитывался как «план на месте», зонд шёл
     * голым, и местный отказ записывался кандидату промахом. Теперь:
     * «план отвергнут исполнителем», следующий кандидат без сетевого зонда,
     * а когда отвергнуты все — местный отказ, не «выведенные планы
     * исчерпаны». */
    {
        d2k_catalog cR;
        memset(&cR, 0, sizeof cR);
        d2k_sched *s = d2k_sched_new(&cR, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_calls = 0;
        ver_answer_port = 40621;
        forget_sent();
        d2k_ev h = ev_hello(6, 40621, "отказ.исполнителя");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40621);
        d2k_sched_event(s, &su);
        spin_until_installed(s);
        CHECK(said("поставил план 1 из"), "первый кандидат не поставлен");
        int base = ver_calls;
        int budget0 = live_probes_used(s);
        CHECK(budget0 > 0, "бюджет зондов не прочитан из живого файла");
        int seen_refused = 0, seen_second = 0, seen_miss = 0, seen_final = 0;
        int seen_exhausted = 0, naks = 0;
        uint8_t last[D2K_TRIAL_ID_LEN] = {0};
        for (int round = 0; round < 400 && !seen_final; round++) {
            uint8_t id[D2K_TRIAL_ID_LEN];
            if (name_probe_trial("отказ.исполнителя", id) &&
                memcmp(id, last, sizeof id) != 0) {
                memcpy(last, id, sizeof last);
                d2k_ev nak = name_probe_ack(id, 0, D2K_ACK_BAD_PLAN);
                d2k_sched_event(s, &nak);
                naks++;
            }
            tick_frozen(s);
            seen_refused |= said("план отвергнут исполнителем");
            seen_second |= said("поставил план 2 из");
            seen_miss |= said("зонд не дошёл до приложения");
            seen_exhausted |= said("выведенные планы исчерпаны");
            seen_final |= said("все кандидаты отвергнуты исполнителем");
            saidbuf[0] = '\0';
        }
        CHECK(seen_refused, "отказ исполнителя не назван «план отвергнут исполнителем»");
        CHECK(seen_second && naks >= 2,
              "после отказа исполнителя не взят следующий кандидат");
        CHECK(ver_calls == base, "отвергнутый исполнителем кандидат испытан сетевым зондом");
        CHECK(!seen_miss, "отказ исполнителя записан кандидату промахом");
        CHECK(seen_final, "все отказы исполнителя не завершились местным отказом");
        CHECK(!seen_exhausted, "местный отказ выдан за исчерпание выведенных планов");
        CHECK(live_probes_used(s) == budget0 - 1,
              "отвергнутые исполнителем кандидаты съели бюджет зондов");
        /* Отдых — как у неполного поиска (cooldown kind 2), не CLEAR. */
        saidbuf[0] = '\0';
        d2k_ev su2 = ev_suspect(6, 40622);
        d2k_ev h2 = ev_hello(6, 40622, "отказ.исполнителя");
        d2k_sched_event(s, &h2);
        d2k_sched_event(s, &su2);
        CHECK(said("замер отложен после неподтверждённого прошлого замера"),
              "местный отказ не дал отдыха неполного поиска (kind 2)");
        d2k_sched_free(s);
        d2k_catalog_free(&cR);
    }

    /* --- ОТКАЗ ИСПОЛНИТЕЛЯ ДЛЯ АДРЕСНОГО QUIC-ОПЫТА ------------------------
     *
     * Задача 19, раунд 1. NAK SET_ADDR_PROBE раньше разбирался только для
     * голоса: QUIC by_addr ждал срок, шёл зондом без плана и выбрасывал
     * кандидата «зонд не дошёл до приложения». */
    {
        d2k_catalog cA;
        memset(&cA, 0, sizeof cA);
        d2k_sched *s = d2k_sched_new(&cA, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        quic_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_TRANSPORT;
        ver_fail_first = 0;
        ver_calls = 0;
        drain(); forget_sent();
        d2k_ev su = addr_quic_suspect(41031);
        d2k_sched_event(s, &su);
        spin_until_installed(s);
        CHECK(said("поставил план 1 из"), "адресный кандидат не поставлен");
        int base = ver_calls;
        int budget0 = live_probes_used(s);
        int seen_refused = 0, seen_miss = 0, seen_final = 0, seen_exhausted = 0, naks = 0;
        uint8_t last[D2K_TRIAL_ID_LEN] = {0};
        for (int round = 0; round < 400 && !seen_final; round++) {
            uint8_t id[D2K_TRIAL_ID_LEN];
            if (last_addr_probe_trial(id) && memcmp(id, last, sizeof id) != 0) {
                memcpy(last, id, sizeof last);
                d2k_ev nak = addr_probe_ack(id, 0, D2K_ACK_BAD_PLAN);
                d2k_sched_event(s, &nak);
                naks++;
            }
            tick_frozen(s);
            seen_refused |= said("план отвергнут исполнителем");
            seen_miss |= said("зонд не дошёл");
            seen_exhausted |= said("выведенные планы исчерпаны");
            seen_final |= said("все кандидаты отвергнуты исполнителем");
            saidbuf[0] = '\0';
        }
        CHECK(seen_refused && naks >= 1, "NAK адресного опыта не назван отказом исполнителя");
        CHECK(ver_calls == base, "отвергнутый адресный кандидат испытан сетевым зондом");
        CHECK(!seen_miss, "NAK адресного опыта записан кандидату промахом");
        CHECK(seen_final && !seen_exhausted,
              "все отказы адресного опыта не завершились местным отказом");
        CHECK(live_probes_used(s) == budget0 - 1,
              "отвергнутые адресные кандидаты съели бюджет зондов");
        saidbuf[0] = '\0';
        d2k_ev again = addr_quic_suspect(41031);
        d2k_sched_event(s, &again);
        CHECK(said("замер отложен после неподтверждённого прошлого замера"),
              "местный отказ адресного опыта не дал отдыха неполного поиска (kind 2)");
        d2k_sched_free(s);
        d2k_catalog_free(&cA);
        quic_answer = D2K_V_OPAQUE;
        ver_answer = D2K_VER_APPLICATION;
    }

    /* --- ПОЗДНИЙ ОТКАЗ: ЗОНД УЖЕ УШЁЛ ПО СРОКУ ОЖИДАНИЯ -------------------
     *
     * ACK ok=0 пришёл, когда ожидание приёма плана истекло и зонд уже в
     * сети. Зонд шёл без плана — его исход не про кандидата: ни промаха,
     * ни повтора «того же кандидата заново». */
    {
        d2k_catalog cL;
        memset(&cL, 0, sizeof cL);
        d2k_sched *s = d2k_sched_new(&cL, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        quic_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_TRANSPORT;
        ver_fail_first = 0;
        ver_calls = 0;
        drain(); forget_sent();
        d2k_ev su = addr_quic_suspect(41032);
        d2k_sched_event(s, &su);
        spin_until_installed(s);
        uint8_t id[D2K_TRIAL_ID_LEN];
        CHECK(last_addr_probe_trial(id), "адресный опыт без trial ID");
        int budget0 = live_probes_used(s);
        ver_snapshot_enabled = 1;
        ver_snapshot_entered = ver_snapshot_release = 0;
        skip_ahead(s, 60); /* срок SCHED_TRIAL_SETTLE_MS истёк — зонд пошёл */
        pthread_mutex_lock(&snapshot_mu);
        struct timespec dl;
        clock_gettime(CLOCK_REALTIME, &dl);
        dl.tv_sec += 2;
        int rc = 0;
        while (!ver_snapshot_entered && rc == 0) {
            rc = pthread_cond_timedwait(&snapshot_cv, &snapshot_mu, &dl);
        }
        pthread_mutex_unlock(&snapshot_mu);
        CHECK(ver_snapshot_entered, "адресный зонд не дошёл до барьера");
        d2k_ev nak = addr_probe_ack(id, 0, D2K_ACK_BAD_PLAN);
        d2k_sched_event(s, &nak);
        pthread_mutex_lock(&snapshot_mu);
        ver_snapshot_release = 1;
        pthread_cond_broadcast(&snapshot_cv);
        pthread_mutex_unlock(&snapshot_mu);
        int seen_late = 0, seen_miss = 0, seen_retry = 0;
        for (int i = 0; i < 400 && !seen_late; i++) {
            tick_frozen(s);
            seen_late |= said("зонд уже ушёл без плана");
            seen_miss |= said("зонд не дошёл");
            seen_retry |= said("ставлю того же кандидата заново");
        }
        ver_snapshot_enabled = 0;
        CHECK(seen_late, "поздний отказ исполнителя не разобран как местный отказ");
        CHECK(!seen_miss && !seen_retry, "поздний отказ исполнителя засужен кандидату");
        CHECK(live_probes_used(s) <= budget0,
              "поздний отказ исполнителя не вернул бюджет зонда");
        d2k_sched_free(s);
        d2k_catalog_free(&cL);
        quic_answer = D2K_V_OPAQUE;
        ver_answer = D2K_VER_APPLICATION;
    }

    /* --- ПРОБНЫЙ ПЛАН СТАВИТСЯ ПОД ФОРМУ ЗОНДА, А НЕ КЛИЕНТА -------------
     *
     * План ставится РАДИ ИСПЫТАНИЯ, а испытывает его наш зонд: он ведёт своё
     * рукопожатие TLS 1.3, и его приветствие всегда современной формы. Когда
     * форму брали у клиента и она оказывалась другой, план к потоку зонда не
     * применялся вовсе — «зонд прошёл, а применения этого плана к его потоку
     * не было», успех выброшен. На роутере владельца 13.09.2026 таких
     * выброшенных успехов набралось 269. */
    {
        d2k_catalog cS;
        memset(&cS, 0, sizeof cS);
        d2k_sched *s = d2k_sched_new(&cS, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_calls = 0;
        ver_answer_port = 40311;
        forget_sent();
        d2k_ev h = ev_hello(6, 40311, "форма.зонда");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40311);
        d2k_sched_event(s, &su);
        spin_until_installed(s);
        CHECK(said("поставил план"), "кандидат не поставлен вовсе");
        /* Форма стоит байтом сразу ПОСЛЕ имени в теле команды (d2k_ctl.h:
           длина имени, имя, ФОРМА, план). Ищем имя прямо в отправленных
           байтах — вторая реализация разбора разошлась бы с первой молча. */
        {
            drain();
            const char *nm = "форма.зонда";
            size_t nl = strlen(nm);
            int seen = 0, shaped_ok = 0;
            for (size_t i = 0; i + nl + 1 < sent_len; i++) {
                if (memcmp(sentbuf + i, nm, nl) != 0) { continue; }
                seen = 1;
                /* Команд с этим именем в потоке несколько (ARM_SHAPE, DEL_NAME,
                   установка кандидата), и форма есть только у установки.
                   Достаточно, чтобы хоть одна несла форму зонда. */
                if (sentbuf[i + nl] == (uint8_t)D2K_SHAPE_MODERN) { shaped_ok = 1; }
            }
            CHECK(seen, "имя цели не найдено в отправленном вовсе");
            CHECK(shaped_ok,
                  "пробный план ушёл не формой зонда — к его потоку он не применится");
        }
        d2k_sched_free(s);
        d2k_catalog_free(&cS);
    }

    /* --- ОТКАЗ bind НЕ РАСШИРЯЕТ ПРОБНЫЙ ПЛАН НА ЧУЖИЕ ПОТОКИ ------------
     *
     * 0010, R1. Локальная неудача (порт для изоляции не занялся) раньше
     * превращалась в ущерб постороннему трафику: план уезжал с нулевым
     * портом и доставался ВСЕМ соединениям к цели. Локальный отказ обязан
     * остаться локальным.
     *
     * Проверяем оба пути сразу — и диагностический вопрос, и кандидата: у
     * них общий крючок занятия порта. */
    {
        d2k_sched_bind_fn saved_bind = d2k_sched_bind_hook;
        d2k_sched_bind_hook = stub_bind_fail;
        d2k_catalog cB;
        memset(&cB, 0, sizeof cB);
        d2k_sched *s = d2k_sched_new(&cB, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_calls = 0;
        ver_answer_port = 40401;
        forget_sent();
        d2k_ev h = ev_hello(6, 40401, "отказ.порта");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40401);
        d2k_sched_event(s, &su);
        settle(s);

        /* Ни один план не поставлен: ни вопрос, ни кандидат. */
        CHECK(!said("поставил план"),
              "кандидат поставлен при неудаче bind — испытание идёт по чужим потокам");
        /* И причина названа вслух, а не спрятана под «планы исчерпаны». */
        CHECK(said("порт для зонда не занялся") || !said("выведенные планы исчерпаны"),
              "локальный отказ выдан за исчерпание планов");
        /* На проводе нет ни одной команды с планом по этому имени: длина
           тела команды с планом заведомо больше длины имени с заголовком. */
        {
            drain();
            const char *nm = "отказ.порта";
            size_t nl = strlen(nm);
            int plan_cmd = 0;
            for (size_t i = 0; i + nl + 2 < sent_len; i++) {
                if (memcmp(sentbuf + i, nm, nl) != 0) { continue; }
                /* За именем у ARM_SHAPE/DEL_NAME тела нет; у установки плана
                   идёт форма и сам план. Больше двух байт хвоста — план. */
                if (sent_len - (i + nl) > 3) { plan_cmd = 1; }
            }
            CHECK(!plan_cmd, "команда с планом ушла на провод при неудаче bind");
        }
        d2k_sched_free(s);
        d2k_catalog_free(&cB);
        d2k_sched_bind_hook = saved_bind;
    }

    /* --- ПЛАН-ВОПРОС ОБЪЯВЛЯЕТ ФОРМУ ТЕХ БАЙТ, КОТОРЫЕ САМ И ШЛЁТ --------
     *
     * 0010, R2. Диагностический вопрос воспроизводит приветствие КЛИЕНТА:
     * JOB_CONTACT шлёт снятый триггер как есть. Если плану объявить форму
     * собственного зонда (всегда современную), он не применится к
     * отправленным байтам старой формы — и вопрос вернётся без измеренного
     * ответа, молча, как «коробка ничего не сделала». Ровно это я и сломал
     * 13.09, сведя оба контекста к одной константе.
     *
     * Форму читаем ПРЯМО С ПРОВОДА: вторая реализация разбора разошлась бы с
     * первой молча. */
    {
        d2k_catalog cQS;
        memset(&cQS, 0, sizeof cQS);
        d2k_sched *s = d2k_sched_new(&cQS, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        /* ИМЕННО OPAQUE, и это не деталь настройки. Вопросы о свойствах
           задаются ТОЛЬКО на этом вердикте: на остальных ответ уже дан
           разрезом или его отсутствием (см. ветку в цикле планировщика).
           С prefix проверка смотрела бы на пробный план — а он по замыслу
           уезжает формой НАШЕГО зонда, и утверждение про форму клиента к нему
           не относится вовсе. */
        tcp_answer = D2K_V_OPAQUE;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_calls = 0;
        ver_answer_port = 40501;

        d2k_ev h = ev_hello(6, 40501, "вопрос.старой.формы");
        d2k_sched_event(s, &h);
        /* Снимок живого клиента — СТАРОЙ формы, из того же профиля, что и
           холодный старт, а не собранный тут руками. */
        {
            d2k_ev sh;
            memset(&sh, 0, sizeof sh);
            sh.kind = D2K_EV_SHAPE;
            sh.transport = 6;
            CHECK(d2k_hello_from_profile(D2K_SHAPE_LEGACY, "вопрос.старой.формы",
                                         sh.shape, sizeof sh.shape, &sh.shape_len) == 0,
                  "приветствие старой формы не собралось — проверять нечем");
            d2k_sched_event(s, &sh);
        }
        forget_sent();
        d2k_ev su = ev_suspect(6, 40501);
        d2k_sched_event(s, &su);
        settle(s);
        drain();

        {
            const char *nm = "вопрос.старой.формы";
            size_t nl = strlen(nm);
            int seen = 0, legacy_ok = 0, modern_seen = 0;
            for (size_t i = 0; i + nl + 1 < sent_len; i++) {
                if (memcmp(sentbuf + i, nm, nl) != 0) { continue; }
                seen = 1;
                if (sentbuf[i + nl] == (uint8_t)D2K_SHAPE_LEGACY) { legacy_ok = 1; }
                if (sentbuf[i + nl] == (uint8_t)D2K_SHAPE_MODERN) { modern_seen = 1; }
            }
            CHECK(seen, "имя цели не найдено в отправленном вовсе");
            CHECK(legacy_ok,
                  "план-вопрос ушёл НЕ формой своего триггера — к отправленным "
                  "байтам он не применится, и вопрос вернётся без ответа");
            CHECK(!modern_seen || legacy_ok,
                  "вопрос объявил форму собственного зонда вместо формы триггера");
        }
        d2k_sched_free(s);
        d2k_catalog_free(&cQS);
    }

    /* --- подозрение без предшествующего приветствия: имени нет, искать
     * нечего, и это НЕ отказ ------------------------------------------- */
    {
        tcp_calls = quic_calls = 0;
        d2k_sched *s = d2k_sched_new(&cat, sv[0], 0x2d);
        d2k_ev su = ev_suspect(6, 40003);
        CHECK(d2k_sched_event(s, &su) == 0,
              "подозрение по неизвестному потоку начало поиск без имени цели");
        settle(s);
        CHECK(tcp_calls == 0, "поиск без имени всё же позвал дерево вердиктов");
        d2k_sched_free(s);
    }

    /* --- планы двух транспортов не перетирают друг друга --------------- */
    {
        d2k_catalog c2;
        memset(&c2, 0, sizeof c2);
        d2k_sched *s = d2k_sched_new(&c2, sv[0], 0x2d);
        tcp_answer = D2K_V_PREFIX;
        quic_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;

        /* Зонд «занимает» тот же местный порт, что стоит в ключе событий этой
           цели: планировщик сверяет применение со СВОИМ потоком, и чужой порт
           здесь означал бы чужой поток. */
        ver_answer_port = 40010;
        forget_sent();
        d2k_ev h1 = ev_hello(6, 40010, "instagram.com");
        d2k_sched_event(s, &h1);
        d2k_ev s1 = ev_suspect(6, 40010);
        d2k_sched_event(s, &s1);
        settle(s);
        d2k_ev a1 = ev_applied(6, 40010);
        d2k_sched_event(s, &a1);
        spin(s, 40);

        ver_answer_port = 40011;
        forget_sent();
        d2k_ev h2 = ev_hello(17, 40011, "instagram.com");
        d2k_sched_event(s, &h2);
        d2k_ev s2 = ev_suspect(17, 40011);
        d2k_sched_event(s, &s2);
        {
            d2k_ev sh;
            CHECK(quic_shape(&sh, "instagram.com") == 0, "снимок QUIC не собрался");
            d2k_sched_event(s, &sh);
        }
        settle(s);
        CHECK(ver_last_transport == 17,
              "зонду не сказали транспорт — умолчание не смогло бы отказать QUIC");
        d2k_ev a2 = ev_applied(17, 40011);
        d2k_sched_event(s, &a2);
        spin(s, 40);

        const d2k_cat_binding *btcp = binding_of(&c2, "instagram.com", 6);
        const d2k_cat_binding *budp = binding_of(&c2, "instagram.com", 17);
        CHECK(btcp != NULL, "привязка по TCP не записана");
        CHECK(budp != NULL, "привязка по QUIC не записана — план одного транспорта затёр другой");
        d2k_sched_free(s);
        d2k_catalog_free(&c2);
    }

shape_test:
    /* СНИМОК — ОДНА ИЗ ДВУХ ДАТАГРАММ ПРИВЕТСТВИЯ (браузер с постквантовым
       key_share). Датапат отдаёт датаграмму, на которой сборка дала имя, и
       целого ClientHello в ней нет: d2k_quic_hello_rename отказывает. Контроль
       обязан всё равно быть — собственный Initial донора с именем приманки
       (probe.go:280-321 всегда строит свой), а не пустота с «нет контрольного
       имени» вместо опыта. */
    {
        d2k_catalog empty = {0};
        d2k_sched *s = d2k_sched_new(&empty, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_calls = quic_calls = 0;
        quic_last_ctl[0] = '\0';
        memset(quic_seen_trigger_lens, 0, sizeof quic_seen_trigger_lens);
        d2k_ev sh;
        char got[256];
        CHECK(quic_shape_first_of_two(&sh, "две.датаграммы.example") == 0 &&
              d2k_quic_sni(sh.shape, sh.shape_len, got, sizeof got) == 0 &&
              strcmp(got, "две.датаграммы.example") == 0,
              "первая датаграмма приветствия не собралась или не даёт имя");
        uint8_t probe[2048];
        size_t probe_len = 0;
        CHECK(d2k_quic_hello_rename(sh.shape, sh.shape_len, "disk.rzd.ru",
                                    probe, sizeof probe, &probe_len) != 0,
              "половина приветствия переименовалась — стенд не воспроизводит разрыв");
        d2k_sched_event(s, &sh);
        d2k_ev h = ev_hello(17, 40071, "две.датаграммы.example");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(17, 40071);
        CHECK(d2k_sched_event(s, &su) == 1, "подозрение по QUIC не завело задачу");
        settle(s);
        CHECK(quic_calls == 1, "QUIC-поиск по снимку из двух датаграмм не запущен");
        CHECK(strcmp(quic_last_ctl, "disk.rzd.ru") == 0,
              "контроль пуст/не QUIC, когда снимок не в одной датаграмме");
        /* ЦЕЛЬ — ТОЖЕ PROFILE, а не обрывок. Обрывок CRYPTO сервер не
           дочитает и промолчит; контроль ответит — и молчание цели станет
           D2K_V_OPAQUE, «доказанной» блокировкой от пакета, который клиент
           никогда не слал. Проверяется то, что ушло в зонд: целый Initial с
           именем цели, не байты снимка. */
        {
            uint8_t ch[2048];
            size_t ch_len = 0;
            CHECK(quic_seen_trigger_lens[0] > 0 &&
                  d2k_quic_client_hello(quic_seen_triggers[0], quic_seen_trigger_lens[0],
                                        ch, sizeof ch, &ch_len) == 0 &&
                  strcmp(quic_seen_targets[0], "две.датаграммы.example") == 0,
                  "зонд цели получил не целый Initial с именем цели");
            CHECK(!(quic_seen_trigger_lens[0] == sh.shape_len &&
                    memcmp(quic_seen_triggers[0], sh.shape, sh.shape_len) == 0),
                  "зонд цели ушёл обрывком приветствия из снимка");
        }
        CHECK(said("не в одной датаграмме") && said("PROFILE"),
              "обрывок приветствия не назван, PROFILE-вход не помечен в трассе");
        CHECK(!said("контроль — PROFILE, снимок не в одной датаграмме"),
              "контроль приписан снимку, которым цель не мерили");
        {
            d2k_ev whole;
            CHECK(d2k_quic_hello_incomplete(sh.shape, sh.shape_len) == 1 &&
                  quic_shape(&whole, "две.датаграммы.example") == 0 &&
                  d2k_quic_hello_incomplete(whole.shape, whole.shape_len) == 0,
                  "признак обрывка приветствия перепутан с целым Initial");
        }
        /* Поздний обрывок не заводит «перемер снимком клиента». */
        d2k_sched_event(s, &sh);
        settle(s);
        CHECK(quic_calls == 1, "обрывок приветствия запустил перемер как снимок клиента");
        d2k_sched_free(s);
    }

    /* ФИНАЛЬНОЕ РЕВЬЮ CORE, I1: разрез CRYPTO (quicsplit) и клиент, чей
       ClientHello шире датаграммы (Chrome с ML-KEM). Датапат режет только
       датаграмму с именем и такому клиенту отказывает; зонд шлёт ClientHello
       одной датаграммой и разрез подтверждает. Без защиты цель «подтверждена»
       и пересматривается каждые 10 минут. */
    {
        d2k_catalog c = {0};
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        quic_answer = D2K_V_OPAQUE; arm_kind = D2K_QA_SPLIT;
        ver_answer = D2K_VER_APPLICATION; ver_fail_first = 0;

        /* (a) Снимок клиента — обрывок: разрез не спрашивается и не строится. */
        quic_calls = 0; quic_last_split_unfit = -1; ver_calls = 0;
        d2k_ev sh;
        CHECK(quic_shape_first_of_two(&sh, "pq.split.example") == 0, "I1: обрывок не собран");
        d2k_sched_event(s, &sh);
        ver_answer_port = 40081;
        d2k_ev h = ev_hello(17, 40081, "pq.split.example"); d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(17, 40081); d2k_sched_event(s, &su);
        settle(s);
        d2k_ev ap = ev_applied(17, 40081); d2k_sched_event(s, &ap);
        spin(s, 40);
        CHECK(quic_calls == 1 && quic_last_split_unfit == 1,
              "I1: вопроснику не сказано, что разрез клиенту неприменим");
        CHECK(said("план разреза не строю") && !binding_of(&c, "pq.split.example", 17),
              "I1: разрез CRYPTO построен/подтверждён клиенту шире датаграммы");

        /* (b) Снимка нет, вход замера (PROFILE) — одна датаграмма: разрез
           предлагается и подтверждается. */
        quic_calls = 0; quic_last_split_unfit = -1;
        ver_answer_port = 40082;
        forget_sent();
        d2k_ev h2 = ev_hello(17, 40082, "single.split.example"); d2k_sched_event(s, &h2);
        d2k_ev su2 = ev_suspect(17, 40082); d2k_sched_event(s, &su2);
        settle(s);
        d2k_ev ap2 = ev_applied(17, 40082); d2k_sched_event(s, &ap2);
        spin(s, 40);
        CHECK(quic_calls == 1 && quic_last_split_unfit == 0,
              "I1: однодатаграммному входу разрез запрещён");
        d2k_cat_binding *bd = binding_mut(&c, "single.split.example", 17);
        CHECK(bd && !bd->recheck_since, "I1: разрез CRYPTO для однодатаграммного входа не подтверждён");
        int succ0 = bd ? bd->successes : -1;

        /* (c) Подтверждённый разрез не исполнился потоку клиента
           (planned=NO): снимок заказан; обрывок — привязка к повторной
           проверке, снята с провода. */
        forget_sent();
        d2k_ev h3 = ev_hello(17, 40083, "single.split.example"); d2k_sched_event(s, &h3);
        d2k_ev su3 = ev_suspect(17, 40083); su3.planned = D2K_LINK_PLANNED_NO;
        d2k_sched_event(s, &su3);
        spin(s, 5);
        CHECK(sent_command_count(D2K_CMD_ARM_SHAPE, NULL, 0) == 1,
              "I1: неисполненный разрез не заказал снимок клиента");
        d2k_ev sh3;
        CHECK(quic_shape_first_of_two(&sh3, "single.split.example") == 0, "I1: обрывок (c) не собран");
        d2k_sched_event(s, &sh3);
        spin(s, 5);
        bd = binding_mut(&c, "single.split.example", 17);
        CHECK(bd && bd->recheck_since != 0,
              "I1: разрез, не исполняющийся клиенту, остался подтверждённым");
        CHECK(said("привязок к повторной проверке"), "I1: снятие разреза не сказано");

        /* (d) Следующий поиск той же цели разрез не переподтверждает. */
        d2k_ev h4 = ev_hello(17, 40084, "single.split.example"); d2k_sched_event(s, &h4);
        d2k_ev su4 = ev_suspect(17, 40084); d2k_sched_event(s, &su4); /* наблюдение кончено */
        spin(s, 5);
        quic_calls = 0; quic_last_split_unfit = -1;
        ver_answer_port = 40085;
        d2k_ev h5 = ev_hello(17, 40085, "single.split.example"); d2k_sched_event(s, &h5);
        d2k_ev su5 = ev_suspect(17, 40085); d2k_sched_event(s, &su5);
        for (int i = 0; i < 30 && quic_calls == 0; i++) { skip_ahead(s, 6000); spin(s, 40); }
        settle(s);
        d2k_ev ap5 = ev_applied(17, 40085); d2k_sched_event(s, &ap5);
        spin(s, 40);
        bd = binding_mut(&c, "single.split.example", 17);
        CHECK(quic_last_split_unfit == 1 && bd && bd->recheck_since != 0 && bd->successes == succ0,
              "I1: разрез CRYPTO переподтверждён клиенту шире датаграммы");
        if (fails) fprintf(stderr, "%s\n", saidbuf);
        d2k_sched_free(s); d2k_catalog_free(&c);
        arm_kind = D2K_QA_BLOB;
    }

    /* A late TCP snapshot must stop a search based on the synthetic profile,
       then start exactly one search with the captured ClientHello. */
    {
        d2k_catalog empty = {0};
        d2k_sched *s = d2k_sched_new(&empty, sv[0], 0x2d);
        tcp_wait_until_stop = 1; tcp_release_waiters = 0;
        tcp_saw_stop = tcp_stop_count = tcp_calls = 0;
        tcp_last_wire = 0;
        tcp_answer = D2K_V_INCONCLUSIVE;
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        d2k_ev h = ev_hello(6, 39988, "late.tcp.snapshot.example");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 39988);
        d2k_sched_event(s, &su);
        spin(s, 30);
        CHECK(tcp_calls == 1, "TCP cold-start classifier did not start");
        d2k_ev sh = {0}; sh.kind = D2K_EV_SHAPE; sh.transport = 6;
        CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, "late.tcp.snapshot.example",
              sh.shape, sizeof sh.shape, &sh.shape_len) == 0,
              "TCP late-snapshot fixture failed");
        d2k_sched_event(s, &sh);
        /* On the old implementation this release prevents the test itself
           from waiting forever; only a real stop request satisfies the
           assertion below. */
        tcp_release_waiters = 1;
        spin(s, 50);
        CHECK(tcp_saw_stop,
              "late TCP snapshot did not cancel the stale profile measurement");
        tcp_wait_until_stop = 0;
        spin(s, 80);
        CHECK(tcp_calls == 2,
              "late TCP snapshot did not cause exactly one measurement restart");
        CHECK(tcp_last_wire == sh.shape_len,
              "restarted TCP measurement did not use the captured ClientHello");
        CHECK(said("повторяю поиск его байтами"),
              "late TCP snapshot restart was not reported");
        d2k_sched_free(s); d2k_catalog_free(&empty);
        tcp_wait_until_stop = 0; tcp_release_waiters = 0;
        tcp_answer = D2K_V_OPAQUE;
    }

    /* ЗАДАЧА 31. Поле 02.10.2026, i.ytimg.com: классификатор (первый шаг
       после задачи 30) брошен ради снимка клиента, а пока он доходил до
       границы зонда, общую ячейку TCP-снимка заняло приветствие соседнего
       имени. Повтор снимком не узнал своей цели, брошенный прогон («о цели
       не сказано ничего») ушёл в разбор вердикта — «прямой замер не
       подтвердил блокировку» и десять минут покоя. Остановленный ради
       снимка прогон — не замер: он перезапускается байтами клиента. */
    for (int during_volume = 0; during_volume <= 1; during_volume++) {
        d2k_catalog empty = {0};
        d2k_sched *s = d2k_sched_new(&empty, sv[0], 0x2d);
        tcp_wait_until_stop = !during_volume; tcp_release_waiters = 0;
        tcp_saw_stop = tcp_stop_count = tcp_calls = 0;
        tcp_last_wire = 0; vol_calls = 0; vol_entered = 0;
        vol_hold = during_volume;
        tcp_answer = during_volume ? D2K_V_CLEAR : D2K_V_INCONCLUSIVE;
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        d2k_ev h = ev_hello(6, 39989, "snap.stop.example");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 39989);
        d2k_sched_event(s, &su);
        spin(s, 30);
        CHECK(tcp_calls == 1, "task31: профильный классификатор не начался");
        if (during_volume) {
            for (int i = 0; i < 2000 && !vol_entered; i++) usleep(1000);
            CHECK(vol_entered, "task31: объёмный шаг не начался после CLEAR");
        }
        d2k_ev sh = {0}; sh.kind = D2K_EV_SHAPE; sh.transport = 6;
        CHECK(d2k_hello_from_profile(D2K_SHAPE_LEGACY, "snap.stop.example",
              sh.shape, sizeof sh.shape, &sh.shape_len) == 0, "task31: снимок");
        /* Клиент повторяет приветствие — несколько снимков одной цели. */
        for (int k = 0; k < 4; k++) d2k_sched_event(s, &sh);
        /* Соседнее имя занимает общую ячейку снимка. */
        d2k_ev other = {0}; other.kind = D2K_EV_SHAPE; other.transport = 6;
        CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, "neighbour.other.example",
              other.shape, sizeof other.shape, &other.shape_len) == 0, "task31: соседний снимок");
        d2k_sched_event(s, &other);
        tcp_answer = D2K_V_INCONCLUSIVE;
        vol_hold = 0;
        spin(s, 50);
        tcp_wait_until_stop = 0;
        spin(s, 120);
        const char *msg = "останавливаю устаревший прогон";
        int stops = 0;
        for (const char *p = saidbuf; (p = strstr(p, msg)) != NULL; p += strlen(msg)) stops++;
        CHECK(stops == 1, "task31: просьба остановки объявлена не один раз за прогон");
        CHECK(tcp_calls == 2, "task31: брошенный ради снимка прогон не перезапущен");
        CHECK(tcp_last_wire == sh.shape_len &&
              memcmp(tcp_last_trig, sh.shape, sh.shape_len) == 0,
              "task31: перезапуск шёл не снятыми байтами клиента");
        /* Вердикт и покой допустимы только у ПЕРЕЗАПУЩЕННОГО прогона —
           его неубедительность честна; до перезапуска их быть не должно. */
        const char *restart = strstr(saidbuf, "повторяю поиск его байтами");
        CHECK(restart != NULL, "task31: перезапуск снимком не объявлен");
        const char *verdict = strstr(saidbuf, "прямой замер не подтвердил блокировку");
        const char *rest = strstr(saidbuf, "результат неубедителен");
        const char *clear = strstr(saidbuf, "напрямую проходит");
        CHECK(!verdict || (restart && verdict > restart),
              "task31: брошенный прогон разобран как вердикт");
        CHECK(!rest || (restart && rest > restart),
              "task31: брошенный прогон отправил цель на покой");
        CHECK(!clear, "task31: брошенный объёмный прогон отправил цель на покой как CLEAR");
        d2k_sched_free(s); d2k_catalog_free(&empty);
        tcp_wait_until_stop = 0; tcp_release_waiters = 0; vol_hold = 0;
        tcp_answer = D2K_V_OPAQUE;
    }

    /* ЗАДАЧА 31, поздний обрыв: снимок клиента пришёл во время RX-пары
       позднего закрытия. Брошенная пара — не «позднее закрытие не
       подтвердилось» и не покой: повтор снятыми байтами, и это снова
       RX-пара (rx_volume_only сохраняется). */
    {
        d2k_catalog empty = {0};
        d2k_sched *s = d2k_sched_new(&empty, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        vol_calls = tcp_calls = 0; vol_entered = 0; vol_last_wire = 0;
        vol_answer = D2K_VOL_PASSED; vol_rx_cut = 0;
        vol_hold = 1;
        const char *name = "late.rst.snap.example";
        d2k_ev h1 = ev_hello(6, 41150, name);
        d2k_sched_event(s, &h1);
        d2k_ev r1 = ev_suspect(6, 41150); r1.code = D2K_SUSPECT_RST_AFTER_APP;
        d2k_sched_event(s, &r1);
        d2k_ev h2 = ev_hello(6, 41151, name);
        d2k_sched_event(s, &h2);
        d2k_ev r2 = ev_suspect(6, 41151); r2.code = D2K_SUSPECT_RST_AFTER_APP;
        d2k_sched_event(s, &r2);
        spin(s, 30);
        for (int i = 0; i < 2000 && !vol_entered; i++) usleep(1000);
        CHECK(vol_entered && tcp_calls == 0, "task31/rx: RX-пара позднего закрытия не началась");
        d2k_ev sh = {0}; sh.kind = D2K_EV_SHAPE; sh.transport = 6;
        CHECK(d2k_hello_from_profile(D2K_SHAPE_LEGACY, name,
              sh.shape, sizeof sh.shape, &sh.shape_len) == 0, "task31/rx: снимок");
        d2k_sched_event(s, &sh);
        d2k_ev other = {0}; other.kind = D2K_EV_SHAPE; other.transport = 6;
        CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, "neighbour.rx.example",
              other.shape, sizeof other.shape, &other.shape_len) == 0, "task31/rx: соседний снимок");
        d2k_sched_event(s, &other);
        vol_hold = 0;
        spin(s, 120);
        const char *restart = strstr(saidbuf, "повторяю поиск его байтами");
        CHECK(restart != NULL, "task31/rx: брошенная RX-пара не перезапущена снимком");
        CHECK(vol_calls == 2 && tcp_calls == 0,
              "task31/rx: перезапуск не остался RX-парой позднего закрытия");
        CHECK(vol_last_wire == sh.shape_len, "task31/rx: перезапуск шёл не байтами клиента");
        const char *rest = strstr(saidbuf, "позднее закрытие не подтвердилось");
        CHECK(!rest || (restart && rest > restart),
              "task31/rx: брошенная RX-пара разобрана как неподтверждённое позднее закрытие");
        d2k_sched_free(s); d2k_catalog_free(&empty);
        vol_hold = 0;
    }

    /* ЗАДАЧА 31, QUIC: Initial клиента этой цели пришёл во время прогона,
       затем общую ячейку quic_shape заняло соседнее имя. Перемер обязан
       идти Initial клиента цели (он хранится у задачи), без покоя до
       перемера. Обрывок приветствия (задача 12) копией не становится. */
    for (int fragment = 0; fragment <= 1; fragment++) {
        d2k_catalog empty = {0};
        d2k_sched *s = d2k_sched_new(&empty, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_calls = quic_calls = 0;
        memset(quic_seen_trigger_lens, 0, sizeof quic_seen_trigger_lens);
        snapshot_enabled = 1;
        snapshot_entered = snapshot_release = snapshot_ok = 0;
        quic_answer = D2K_V_INCONCLUSIVE;
        const char *name = "quic.own.initial.example";
        d2k_ev h = ev_hello(17, 40115, name);
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(17, 40115);
        d2k_sched_event(s, &su);
        pthread_mutex_lock(&snapshot_mu);
        struct timespec dl;
        clock_gettime(CLOCK_REALTIME, &dl);
        dl.tv_sec += 2;
        int rc = 0;
        while (!snapshot_entered && rc == 0)
            rc = pthread_cond_timedwait(&snapshot_cv, &snapshot_mu, &dl);
        int entered = snapshot_entered;
        pthread_mutex_unlock(&snapshot_mu);
        CHECK(entered, "task31/quic: QUIC-прогон не начался");
        d2k_ev sh;
        CHECK((fragment ? quic_shape_first_of_two(&sh, name) : quic_shape(&sh, name)) == 0,
              "task31/quic: снимок цели");
        d2k_sched_event(s, &sh);
        d2k_ev other;
        CHECK(quic_shape(&other, "neighbour.quic.example") == 0, "task31/quic: соседний снимок");
        d2k_sched_event(s, &other);
        pthread_mutex_lock(&snapshot_mu);
        snapshot_release = 1;
        pthread_cond_broadcast(&snapshot_cv);
        pthread_mutex_unlock(&snapshot_mu);
        snapshot_enabled = 0;
        settle(s);
        if (fragment) {
            CHECK(quic_calls == 1, "task31/quic: обрывок приветствия запустил перемер");
        } else {
            CHECK(quic_calls == 2, "task31/quic: перемер Initial клиента потерян");
            CHECK(quic_seen_trigger_lens[1] == sh.shape_len &&
                  memcmp(quic_seen_triggers[1], sh.shape, sh.shape_len) == 0,
                  "task31/quic: перемер шёл не Initial клиента цели");
            const char *remeasure = strstr(saidbuf, "перемеряю снимком");
            const char *rest = strstr(saidbuf, "результат неубедителен");
            CHECK(remeasure && (!rest || rest > remeasure),
                  "task31/quic: цель ушла на покой до перемера Initial клиента");
        }
        d2k_sched_free(s); d2k_catalog_free(&empty);
        quic_answer = D2K_V_OPAQUE;
    }

    /* A confirmed TLS1.3 task must not hide blocked TLS1.2 of the same name. */
    for (int family = 4; family <= 6; family += 2) {
        d2k_catalog c = {0};
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        tcp_answer = D2K_V_PREFIX; tcp_owns_search = tcp_found_arm = 1;
        ver_answer = D2K_VER_APPLICATION; ver_fail_first = 0;
        ver_answer_port = 41017;
        drain(); forget_sent();
        d2k_ev sh = {0}; sh.kind = D2K_EV_SHAPE;
        sh.transport = 6; sh.family = (uint8_t)family;
        CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, "versions.example",
              sh.shape, sizeof sh.shape, &sh.shape_len) == 0, "modern snapshot");
        d2k_sched_event(s, &sh);
        d2k_ev h = ev_hello(6, 41017, "versions.example");
        h.family = (uint8_t)family;
        if (family == 6) {
            (void)inet_pton(AF_INET6, "::1", h.low_ip);
            (void)inet_pton(AF_INET6, "2001:db8::2", h.high_ip);
        }
        d2k_sched_event(s, &h);
        d2k_ev su = h; su.kind = D2K_EV_SUSPECT; su.code = D2K_SUSPECT_RST_CUT;
        d2k_sched_event(s, &su); settle(s);
        d2k_ev ap = ev_applied(6, 41017);
        ap.family = h.family;
        memcpy(ap.low_ip, h.low_ip, 16); memcpy(ap.high_ip, h.high_ip, 16);
        d2k_sched_event(s, &ap); spin(s, 40);
        CHECK(binding_of(&c, "versions.example", 6) != NULL, "modern binding exists");
        int before = tcp_calls;
        forget_sent();
        h.high_port++; su.high_port++;
        d2k_sched_event(s, &h);
        su.planned = D2K_LINK_PLANNED_NO;
        d2k_sched_event(s, &su); drain();
        CHECK(sent_command_count(D2K_CMD_ARM_SHAPE, NULL, 0) == 1,
              "unplanned suspicious flow must request snapshot without discarding binding");
        d2k_sched_event(s, &sh); spin(s, 10);
        CHECK(tcp_calls == before, "same TLS shape must not trigger a new measurement");
        d2k_sched_event(s, &su);
        CHECK(d2k_hello_from_profile(D2K_SHAPE_LEGACY, "versions.example",
              sh.shape, sizeof sh.shape, &sh.shape_len) == 0, "legacy snapshot");
        sh.family = family == 4 ? 6 : 4;
        d2k_sched_event(s, &sh); spin(s, 10);
        CHECK(tcp_calls == before, "other address family cannot resolve pending TLS snapshot");
        sh.family = (uint8_t)family;
        d2k_sched_event(s, &sh); settle(s);
        CHECK(tcp_calls > before && ver_last_shape == D2K_SHAPE_LEGACY,
              "blocked TLS1.2 must be measured and verified as TLS1.2 after TLS1.3");
        ap = ev_applied(6, 41017); ap.family = h.family;
        memcpy(ap.low_ip, h.low_ip, 16); memcpy(ap.high_ip, h.high_ip, 16);
        d2k_sched_event(s, &ap); spin(s, 40);
        unsigned modern = 0, legacy = 0;
        for (size_t b = 0; b < c.n_boxes; b++) {
            for (size_t j = 0; j < c.boxes[b].n_binds; j++) {
                const d2k_cat_binding *bd = &c.boxes[b].binds[j];
                modern += bd->shape == D2K_SHAPE_MODERN;
                legacy += bd->shape == D2K_SHAPE_LEGACY;
            }
        }
        CHECK(modern == 1 && legacy == 1, "both TLS bindings must survive confirmation");
        before = tcp_calls;
        d2k_sched_event(s, &su);
        CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, "versions.example",
              sh.shape, sizeof sh.shape, &sh.shape_len) == 0, "returning modern snapshot");
        d2k_sched_event(s, &sh); spin(s, 10);
        CHECK(tcp_calls == before, "already covered TLS1.3 must not be measured again after TLS1.2");
        d2k_sched_free(s); d2k_catalog_free(&c);
    }
    tcp_owns_search = tcp_found_arm = 0;
    if (shape_only) { goto voice_only_done; }

question_test:
    /* --- вопросы о свойствах: задаются, проходят, и ответ меняет план --- */
    for (int question_run = 0; question_run < 2; question_run++) {
        /* Что здесь проверяется. На вердикт «решает содержимое» разрез коробку
           не берёт — и до появления вопросов планировщик получал от
           d2k_compose РОВНО ОДИН запасной план (пустой вектор), ставил его и
           на этом сдавался. Вопрос — это план-кандидат, который проходит
           только если коробку можно отравить ИМЕННО ТАК; его проход пишет
           свойство, и уже по вектору d2k_compose собирает прицельные плечи.
           Проверяем всю цепочку: вопрос задан → подтверждён → зонд сходил к
           цели → обмен с прикладными данными по ЕГО потоку → свойство
           записано → кандидатов стало больше одного.

           Цель — настоящий слушающий сокет на локалхосте: планировщик идёт к
           ней НАСТОЯЩИМ соединением (d2k_props_contact), и местный порт
           назначает ядро. Узнать его вовремя может только тот, кто принял
           соединение, — отсюда стенд, а не догадка. */
        int lfd = socket(AF_INET, SOCK_STREAM, 0);
        CHECK(lfd >= 0, "стенд-цель не открылась");
        struct sockaddr_in a;
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(0x7f000001);
        /* Порт НЕ эфемерный: сервером планировщик считает тот конец, чей порт
           вне диапазона, из которого ядро раздаёт клиентские (server_of в
           sched.c). Возьми bind(0) — стенд получил бы порт из того же
           диапазона, что и клиент в ключе события, и планировщик пошёл бы
           измерять клиента. Ищем свободный низкий, а не назначаем один: на
           машине разработки он может быть занят. */
        int bound = 0;
        for (uint16_t port = 19400; port < 19500 && !bound; port++) {
            a.sin_port = htons(port);
            bound = (bind(lfd, (struct sockaddr *)&a, sizeof a) == 0);
        }
        CHECK(bound, "стенд-цель не привязалась ни к одному свободному низкому порту");
        socklen_t al = sizeof a;
        CHECK(getsockname(lfd, (struct sockaddr *)&a, &al) == 0, "порт стенда не узнать");
        CHECK(listen(lfd, 4) == 0, "стенд-цель не слушает");
        g_server_port = ntohs(a.sin_port);

        d2k_catalog c8;
        memset(&c8, 0, sizeof c8);
        d2k_sched *s = d2k_sched_new(&c8, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_OPAQUE;

        d2k_ev h = ev_hello(6, 40060, "непрозрачная.цель");
        mark_calls = 0;
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40060);
        d2k_sched_event(s, &su);

        /* Крутим до вопроса: он задаётся, когда вернулся вердикт. */
        for (int i = 0; i < 200 && !said("спрашиваю коробку о свойствах"); i++) {
            tick_once(s);
        }
        CHECK(said("спрашиваю коробку о свойствах"),
              "на вердикт «решает содержимое» вопросы о свойствах не начались");
        CHECK(mark_calls > 0 && last_mark == 0x2d,
              "property question socket must carry the controller probe mark");
        uint8_t question_id[D2K_PLAN_ID_LEN] = {0};
        CHECK(last_plan_id(question_id), "question identity captured from wire");
        if (question_run) {
            CHECK(memcmp(question_prev_id, question_id, sizeof question_id) != 0,
                  "same property question in a new task must have a new trial identity");
        }
        memcpy(question_prev_id, question_id, sizeof question_id);

        /* Подтверждения команды планировщик не ждёт и ждать не может: события
           у датапата лосси по контракту, и привязать ack к своей команде по
           порядку нельзя (см. prop_send_next в sched.c). Зонд уходит к цели
           сразу. */
        int peer = -1;
        for (int i = 0; i < 200 && peer < 0; i++) {
            struct pollfd p2; p2.fd = lfd; p2.events = POLLIN; p2.revents = 0;
            if (poll(&p2, 1, 5) > 0) {
                struct sockaddr_in pa;
                socklen_t pl = sizeof pa;
                peer = accept(lfd, (struct sockaddr *)&pa, &pl);
                if (peer >= 0) { a = pa; }
            }
            g_now_ms += 5;
            d2k_sched_tick(s, g_now_ms);
            drain();
        }
        CHECK(peer >= 0, "зонд не пришёл к цели после подтверждения плана-вопроса");

        /* Принять соединение — ещё не значит, что планировщик уже ЖДЁТ обмена:
           рабочий поток зонда возвращается позже, чем цель его приняла, и
           событие обмена, посланное раньше, просто некому было бы отнести
           (в T_PROPS_WAIT ни одной задачи). Ждём, пока планировщик сам
           скажет, что ждёт. */
        for (int i = 0; i < 400 && !said("жду обмена"); i++) {
            tick_once(s);
        }
        CHECK(said("жду обмена"), "планировщик не дошёл до ожидания обмена по вопросу");

        if (peer >= 0) {
            /* Обмен по ЕГО потоку: ключ — настоящий местный порт зонда,
               который знает только принявшая сторона. */
            uint16_t pport = ntohs(a.sin_port);
            d2k_ev x;
            memset(&x, 0, sizeof x);
            x.transport = 6;
            x.low_ip[0] = 127; x.low_ip[3] = 1;
            x.low_port = g_server_port;
            x.high_ip[0] = 127; x.high_ip[3] = 1;
            x.high_port = pport;

            /* СПЕРВА обмен БЕЗ доказательства применения: план мог не встать,
               и тогда зонд шёл к цели голым. Засчитать такой обмен за ответ
               значит записать свойство коробки по измерению не того. */
            x.kind = D2K_EV_EXCHANGE;
            x.code = 22;
            x.num = 1380;
            x.seen_types = 0x0C; /* рукопожатие + прикладные данные */
            x.server_hello = 1;  /* сервер ответил — приёмка вопроса */
            d2k_sched_event(s, &x);
            CHECK(said("жду подтверждения полного исполнения"),
                  "обмен без доказательства применения засчитан за ответ коробки");
            CHECK(!said("перекрытие слева=нет"),
                  "свойство записано по зонду, который мог идти без плана");

            /* Последняя посылка завершилась позже ответа: не нужен новый
               вопрос или повторное EXCHANGE для того же полного потока. */
            x.kind = D2K_EV_APPLIED;
            /* С идентификатором ИМЕННО ТОГО плана, который планировщик
               только что отправил: по одному ключу потока «применён» больше
               не засчитывается (0009, U1). */
            (void)last_plan_id(x.plan_id);
            d2k_sched_event(s, &x);
            spin(s, 40);

            CHECK(said("вопрос 1 прошёл"),
                  "проход вопроса не записан — свойство коробки потеряно");
            /* Проход обязан попасть В ВЕКТОР, а не просто в строку лога:
               проверка на «сказал, что прошёл» пропустила бы планировщик,
               который говорит и не записывает. */
            CHECK(said("перекрытие слева=нет"),
                  "вопрос прошёл, а вектор остался пустым — свойство не записано");
            CHECK(said("поставил план 1 из"),
                  "после ответа коробки кандидаты не собрались");

            /* Ответ обязан МЕНЯТЬ план, иначе спрашивать незачем. Число
               кандидатов для этого не годится: на «не держит перекрытие
               слева» d2k_compose даёт ровно одно прицельное плечо, и пустой
               вектор тоже даёт один план — запасной. Различаются они
               СОДЕРЖИМЫМ, и сверять надо его. */
            char empty_plan[8][4096], answered_plan[8][4096];
            d2k_props none, answered;
            memset(&none, 0, sizeof none);
            memset(&answered, 0, sizeof answered);
            d2k_props_question_passed(2, &answered);
            size_t n_empty = d2k_compose(&none, D2K_SHAPE_MODERN, "disk.rzd.ru", 0, empty_plan, 8);
            size_t n_answ = d2k_compose(&answered, D2K_SHAPE_MODERN, "disk.rzd.ru", 0, answered_plan, 8);
            CHECK(n_empty >= 1 && n_answ >= 1, "d2k_compose не собрал план ни там, ни там");
            CHECK(n_empty >= 1 && n_answ >= 1 && strcmp(empty_plan[0], answered_plan[0]) != 0,
                  "план по отвеченному вектору совпал с запасным — ответ коробки ничего не изменил");
            close(peer);
        }
        d2k_sched_free(s);
        d2k_catalog_free(&c8);
        close(lfd);
        g_server_port = 1;
        tcp_answer = D2K_V_OPAQUE;
    }

    if (question_only) { goto voice_only_done; }
retire_test:
    /* --- ЗАДАЧА 20: каждый пробный план снимается на каждом переходе ---
       Пробная запись имени живёт по местному порту зонда. Не снятая точно,
       она стоит до вытеснения LRU или переподключения контроллера: порт
       вернётся ядру и достанется постороннему сокету с той же меткой, а сама
       запись вытеснит подтверждённое знание. Считаем по проводу: каждая
       SET_NAME_PROBE задачи снята своей DEL_NAME_PROBE (тот же порт, форма и
       семейство), прежняя — ДО установки следующей, широкой DEL_NAME нет. */
    {
        /* 1. Провал кандидата → следующий → исчерпание (task_fail). */
        d2k_catalog cr = {0};
        d2k_sched *s = d2k_sched_new(&cr, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX; tcp_owns_search = 0; tcp_found_arm = 0;
        ver_answer = D2K_VER_HANDSHAKE; ver_fail_first = 0;
        ver_answer_port = 40201; ver_calls = 0;
        forget_sent();
        d2k_ev h = ev_hello(6, 40201, "снятие.провал");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40201);
        d2k_sched_event(s, &su);
        settle(s);
        run_out(s);
        probe_tally pt = name_probe_tally("снятие.провал");
        printf("retire/fail: sets=%zu dels=%zu pending=%zu max=%zu stray=%zu broad=%zu\n",
               pt.sets, pt.dels, pt.pending, pt.max_pending, pt.stray, pt.broad);
        CHECK(pt.sets >= 2, "retire: провал кандидатов не дошёл до второго кандидата");
        CHECK(pt.max_pending == 1,
              "retire: следующий кандидат встал, а план провалившегося не снят");
        CHECK(pt.pending == 0, "retire: после task_fail пробные записи кандидатов остались стоять");
        CHECK(pt.stray == 0 && pt.broad == 0,
              "retire: снятие задело запись, которую задача не ставила");
        d2k_sched_free(s);
        d2k_catalog_free(&cr);
        ver_answer = D2K_VER_APPLICATION;
    }
    {
        /* 2. Непереносимость: зонду план исполнился, клиенту — нет. Кандидат
           отвергнут в verify_confirm, его запись обязана уйти. */
        d2k_catalog cr = {0};
        d2k_sched *s = d2k_sched_new(&cr, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION; ver_fail_first = 0;
        ver_answer_port = 40210; ver_calls = 0;
        forget_sent();
        d2k_ev h = ev_hello(6, 40210, "снятие.непереносимо");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40210);
        d2k_sched_event(s, &su);
        settle(s);
        spin_until_installed(s);
        d2k_ev hc = ev_hello(6, 40211, "снятие.непереносимо");
        d2k_sched_event(s, &hc);
        d2k_ev big = ev_refused(6, 40211, D2K_REFUSE_TOO_LONG, 1);
        d2k_sched_event(s, &big);
        d2k_ev ap = ev_applied(6, 40210);
        d2k_sched_event(s, &ap);
        spin(s, 60);
        CHECK(said("потоку клиента"), "retire: непереносимость не сработала — проверять нечего");
        probe_tally mid = name_probe_tally("снятие.непереносимо");
        CHECK(mid.sets >= 1 && mid.pending <= 1 && mid.max_pending == 1,
              "retire: непереносимый кандидат остался стоять рядом со следующим");
        run_out(s);
        probe_tally pt = name_probe_tally("снятие.непереносимо");
        printf("retire/unfit: sets=%zu dels=%zu pending=%zu max=%zu stray=%zu broad=%zu\n",
               pt.sets, pt.dels, pt.pending, pt.max_pending, pt.stray, pt.broad);
        CHECK(pt.pending == 0 && pt.stray == 0 && pt.broad == 0,
              "retire: непереносимый кандидат не снят точно");
        d2k_sched_free(s);
        d2k_catalog_free(&cr);
    }
    {
        /* 3. verify_confirm: подтверждённое ставится постоянной записью
           (проход каталога), пробная запись порта зонда снимается точно, и
           ни одной широкой DEL_NAME — подтверждённое не задето. */
        d2k_catalog cr = {0};
        d2k_sched *s = d2k_sched_new(&cr, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION; ver_fail_first = 0;
        ver_answer_port = 40220; ver_calls = 0;
        forget_sent();
        d2k_ev h = ev_hello(6, 40220, "снятие.подтверждено");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40220);
        d2k_sched_event(s, &su);
        settle(s);
        d2k_ev ap = ev_applied(6, 40220);
        d2k_sched_event(s, &ap);
        spin(s, 60);
        CHECK(said("ПОДТВЕРЖДЕНО"), "retire: подтверждения не случилось — проверять нечего");
        CHECK(binding_of(&cr, "снятие.подтверждено", 6) != NULL,
              "retire: подтверждённое не записано");
        sync_out(s);
        probe_tally pt = name_probe_tally("снятие.подтверждено");
        printf("retire/confirm: sets=%zu dels=%zu pending=%zu max=%zu stray=%zu broad=%zu\n",
               pt.sets, pt.dels, pt.pending, pt.max_pending, pt.stray, pt.broad);
        CHECK(pt.sets >= 1 && pt.pending == 0,
              "retire: после подтверждения пробная запись порта зонда осталась стоять");
        CHECK(pt.stray == 0 && pt.broad == 0,
              "retire: подтверждение сняло больше, чем свою пробную запись");
        CHECK(sent_command_count(D2K_CMD_SET_NAME, NULL, 0) >= 1,
              "retire: подтверждённый план не поставлен постоянной записью");
        d2k_sched_free(s);
        d2k_catalog_free(&cr);
    }
    /* 4–5. Вопросы о свойствах: каждый следующий вопрос снимает прежний,
       прошедший вопрос снимается до первого кандидата, а task_fail после
       кандидата снимает и кандидата (не только давно снятый вопрос). */
    for (int qmode = 0; qmode < 2; qmode++) {
        int lfd = socket(AF_INET, SOCK_STREAM, 0);
        CHECK(lfd >= 0, "retire: стенд-цель не открылась");
        struct sockaddr_in a;
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(0x7f000001);
        int bound = 0;
        for (uint16_t port = 19500; port < 19600 && !bound; port++) {
            a.sin_port = htons(port);
            bound = (bind(lfd, (struct sockaddr *)&a, sizeof a) == 0);
        }
        CHECK(bound && listen(lfd, 8) == 0, "retire: стенд-цель не слушает");
        g_server_port = ntohs(a.sin_port);
        const char *qname = qmode ? "снятие.вопрос-прошёл" : "снятие.вопросы";

        d2k_catalog cq = {0};
        d2k_sched *s = d2k_sched_new(&cq, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_OPAQUE; tcp_owns_search = 0; tcp_found_arm = 0;
        ver_answer = D2K_VER_HANDSHAKE; ver_fail_first = 0;
        ver_answer_port = 40230; ver_calls = 0;
        forget_sent();
        d2k_ev h = ev_hello(6, 40230, qname);
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40230);
        d2k_sched_event(s, &su);
        for (int i = 0; i < 200 && !said("спрашиваю коробку о свойствах"); i++) {
            tick_once(s);
        }
        CHECK(said("спрашиваю коробку о свойствах"), "retire: вопросы не начались");
        int peers[16], n_peers = 0;
        if (!qmode) {
            /* Ни один вопрос не отвечен: каждый ждёт своего срока. */
            for (int round = 0; round < 40 && !said("поставил план 1 из"); round++) {
                for (int i = 0; i < 20; i++) {
                    struct pollfd p2; p2.fd = lfd; p2.events = POLLIN; p2.revents = 0;
                    if (poll(&p2, 1, 1) > 0 && n_peers < 16) {
                        int pf = accept(lfd, NULL, NULL);
                        if (pf >= 0) { peers[n_peers++] = pf; }
                    }
                    tick_once(s);
                }
                if (!said("поставил план 1 из")) { skip_ahead(s, 6000); }
            }
        } else {
            int peer = -1;
            struct sockaddr_in pa;
            for (int i = 0; i < 400 && peer < 0; i++) {
                struct pollfd p2; p2.fd = lfd; p2.events = POLLIN; p2.revents = 0;
                if (poll(&p2, 1, 5) > 0) {
                    socklen_t pl = sizeof pa;
                    peer = accept(lfd, (struct sockaddr *)&pa, &pl);
                }
                tick_once(s);
            }
            CHECK(peer >= 0, "retire: зонд вопроса не пришёл");
            if (peer >= 0) { peers[n_peers++] = peer; }
            for (int i = 0; i < 400 && !said("жду обмена"); i++) { tick_once(s); }
            if (peer >= 0) {
                d2k_ev x;
                memset(&x, 0, sizeof x);
                x.transport = 6;
                x.low_ip[0] = 127; x.low_ip[3] = 1;
                x.low_port = g_server_port;
                x.high_ip[0] = 127; x.high_ip[3] = 1;
                x.high_port = ntohs(pa.sin_port);
                x.kind = D2K_EV_APPLIED;
                (void)last_plan_id(x.plan_id);
                d2k_sched_event(s, &x);
                x.kind = D2K_EV_EXCHANGE;
                x.code = 22; x.num = 1380; x.seen_types = 0x0C; x.server_hello = 1;
                memset(x.plan_id, 0, sizeof x.plan_id);
                d2k_sched_event(s, &x);
            }
            for (int i = 0; i < 400 && !said("поставил план 1 из"); i++) { tick_once(s); }
            CHECK(said("вопрос 1 прошёл"), "retire: вопрос не прошёл — проверять нечего");
        }
        CHECK(said("поставил план 1 из"), "retire: после вопросов кандидат не встал");
        probe_tally mid = name_probe_tally(qname);
        printf("retire/questions%d at candidate: sets=%zu dels=%zu pending=%zu max=%zu stray=%zu\n",
               qmode, mid.sets, mid.dels, mid.pending, mid.max_pending, mid.stray);
        CHECK(mid.sets >= 2, "retire: вопрос и кандидат не поставлены");
        CHECK(mid.pending == 1 && mid.max_pending == 1,
              qmode ? "retire: прошедший вопрос остался стоять рядом с кандидатом"
                    : "retire: план прежнего вопроса не снят при переходе к следующему");
        /* run_out останавливается, когда задача ждёт приёма плана
           (T_TRIAL_SETTLE не «активна»): крутим до отдыха цели. */
        for (int i = 0; i < 150 && !said("новый поиск отложен"); i++) {
            skip_ahead(s, 6000);
            spin(s, 40);
        }
        CHECK(said("новый поиск отложен"), "retire: поиск не дошёл до исчерпания");
        probe_tally pt = name_probe_tally(qname);
        printf("retire/questions%d end: sets=%zu dels=%zu pending=%zu max=%zu stray=%zu broad=%zu\n",
               qmode, pt.sets, pt.dels, pt.pending, pt.max_pending, pt.stray, pt.broad);
        CHECK(pt.pending == 0,
              "retire: task_fail после кандидата оставил пробную запись (вопроса или кандидата)");
        CHECK(pt.stray == 0 && pt.broad == 0,
              "retire: снятие задело запись, которую задача не ставила");
        d2k_sched_free(s);
        d2k_catalog_free(&cq);
        for (int i = 0; i < n_peers; i++) { close(peers[i]); }
        close(lfd);
        g_server_port = 1;
        tcp_answer = D2K_V_OPAQUE;
        ver_answer = D2K_VER_APPLICATION;
    }
    if (retire_only) { goto voice_only_done; }
recheck_test:
    /* --- ЗАДАЧА 21: прямой проход снимает с провода ровно свою форму и
       помечает привязку «требует повторной проверки»; удаляет только второй
       независимый проход; повторное подтверждение снимает пометку. ------- */
    {
        const char *nm = "recheck.example";
        d2k_catalog c = {0};
        tcp_answer = D2K_V_PREFIX; tcp_owns_search = 0; tcp_found_arm = 0;
        ver_answer = D2K_VER_APPLICATION; ver_fail_first = 0;
        vol_answer = D2K_VOL_PASSED; vol_rx_cut = 0; vol_direct_complete = 0;
        confirm_once(&c, sv[0], nm, 40601);
        d2k_cat_binding *modern = binding_of(&c, nm, 6) ?
            binding_mut(&c, nm, 6) : NULL;
        CHECK(modern && modern->shape == D2K_SHAPE_MODERN && !modern->recheck_since,
              "recheck: fixture TLS1.3 binding not confirmed");
        if (modern) {
            d2k_cat_box *box = NULL;
            for (size_t i = 0; i < c.n_boxes; i++)
                if (modern >= c.boxes[i].binds &&
                    modern < c.boxes[i].binds + c.boxes[i].n_binds) box = &c.boxes[i];
            d2k_cat_binding proto = *modern;
            add_binding_like(box, &proto, 6, D2K_SHAPE_LEGACY);
            add_binding_like(box, &proto, 6, D2K_LINK_SHAPE_ECH_TCP);
            add_binding_like(box, &proto, 17, D2K_LINK_SHAPE_QUIC);
        }
        CHECK(total_bindings(&c) == 4, "recheck: four-shape fixture");

        /* 1. Первый прямой проход TCP (профиль TLS 1.3). */
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        drain(); d2k_sched_sync(s); sync_out(s);
        forget_sent();
        tcp_answer = D2K_V_CLEAR; tcp_calls = 0;
        d2k_ev h = ev_hello(6, 40602, nm);
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40602);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(tcp_calls == 1, "recheck: direct measurement did not run");
        CHECK(total_bindings(&c) == 4,
              "recheck: a single direct CLEAR deleted a confirmed binding (§9.7)");
        modern = binding_shape(&c, nm, 6, D2K_SHAPE_MODERN);
        d2k_cat_binding *legacy = binding_shape(&c, nm, 6, D2K_SHAPE_LEGACY);
        d2k_cat_binding *ech = binding_shape(&c, nm, 6, D2K_LINK_SHAPE_ECH_TCP);
        d2k_cat_binding *quic = binding_shape(&c, nm, 17, D2K_LINK_SHAPE_QUIC);
        CHECK(modern && modern->recheck_since != 0,
              "recheck: measured TLS1.3 binding not marked «требует повторной проверки»");
        CHECK(legacy && !legacy->recheck_since && ech && !ech->recheck_since,
              "recheck: TLS1.3 CLEAR touched TLS1.2/ECH bindings it did not measure");
        CHECK(quic && !quic->recheck_since, "recheck: TCP CLEAR touched the QUIC binding");
        CHECK(sent_command_count(D2K_CMD_DEL_NAME, NULL, 0) == 1 &&
              sent_del_name_key(nm, 6, D2K_SHAPE_MODERN, 4) == 1,
              "recheck: CLEAR must take off the wire exactly (name, TCP, TLS1.3, IPv4)");
        CHECK(sent_command_count(D2K_CMD_DEL_NAME_PROBE, NULL, 0) == 0,
              "recheck: CLEAR removed a trial entry it does not own");
        CHECK(c.revision > 0, "recheck: mark not flagged for persistence");
        CHECK(said("требуют повторной проверки"), "recheck: mark not reported");
        drain(); forget_sent(); d2k_sched_sync(s); sync_out(s);
        CHECK(sent_set_name_shape(nm, D2K_SHAPE_MODERN) == 0,
              "recheck: catalog sync put the marked binding back on the wire");
        CHECK(sent_set_name_shape(nm, D2K_SHAPE_LEGACY) == 1 &&
              sent_set_name_shape(nm, D2K_LINK_SHAPE_ECH_TCP) == 1 &&
              sent_set_name_shape(nm, D2K_LINK_SHAPE_QUIC) == 1,
              "recheck: sync lost the other confirmed shapes/transports");
        {
            char live_path[] = "/tmp/d2k-recheck-live-XXXXXX";
            int live_fd = mkstemp(live_path);
            if (live_fd >= 0) {
                close(live_fd);
                CHECK(!d2k_sched_write_live(s, live_path, "catalog.json"), "recheck live write");
                FILE *live = fopen(live_path, "r"); char body[32768] = {0};
                if (live) { (void)!fread(body, 1, sizeof body - 1, live); fclose(live); }
                CHECK(strstr(body, "\"recheck\": true") != NULL,
                      "recheck: live status hides the recheck mark");
                unlink(live_path);
            }
        }

        /* 2. Перезапуск: пометка переживает его, и проход не ставит привязку. */
        {
            char path[] = "/tmp/d2k-recheck-cat-XXXXXX";
            int fd = mkstemp(path);
            char err[200];
            if (fd >= 0) {
                close(fd);
                CHECK(d2k_catalog_save(&c, path, err, sizeof err) == 0, "recheck: save");
                d2k_catalog c2;
                CHECK(d2k_catalog_load(path, &c2, err, sizeof err) == 0, "recheck: load");
                d2k_cat_binding *m2 = binding_shape(&c2, nm, 6, D2K_SHAPE_MODERN);
                CHECK(m2 && m2->recheck_since == modern->recheck_since,
                      "recheck: mark lost across restart");
                d2k_sched *s2 = d2k_sched_new(&c2, sv[0], 0x2d);
                drain(); forget_sent(); d2k_sched_sync(s2); sync_out(s2);
                CHECK(sent_set_name_shape(nm, D2K_SHAPE_MODERN) == 0 &&
                      sent_set_name_shape(nm, D2K_SHAPE_LEGACY) == 1,
                      "recheck: after restart the marked binding went back on the wire");
                d2k_sched_free(s2);
                d2k_catalog_free(&c2);
                unlink(path);
            }
        }

        /* 3. Второй независимый прямой проход (отдельный замер после
           ограничителя) — привязка удаляется; остальное цело. */
        skip_ahead(s, 61LL * 60 * 1000);
        saidbuf[0] = '\0';
        forget_sent();
        tcp_calls = 0;
        h = ev_hello(6, 40603, nm);
        d2k_sched_event(s, &h);
        su = ev_suspect(6, 40603);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(tcp_calls == 1, "recheck: second direct measurement did not run");
        CHECK(binding_shape(&c, nm, 6, D2K_SHAPE_MODERN) == NULL,
              "recheck: second independent CLEAR did not delete the binding");
        legacy = binding_shape(&c, nm, 6, D2K_SHAPE_LEGACY);
        ech = binding_shape(&c, nm, 6, D2K_LINK_SHAPE_ECH_TCP);
        quic = binding_shape(&c, nm, 17, D2K_LINK_SHAPE_QUIC);
        CHECK(total_bindings(&c) == 3 && legacy && !legacy->recheck_since &&
              ech && !ech->recheck_since && quic && !quic->recheck_since,
              "recheck: second CLEAR touched other shapes/transports");
        CHECK(sent_command_count(D2K_CMD_DEL_NAME, NULL, 0) <= 1 &&
              sent_del_name_key(nm, 6, D2K_SHAPE_LEGACY, 4) == 0 &&
              sent_del_name_key(nm, 6, D2K_LINK_SHAPE_ECH_TCP, 4) == 0 &&
              sent_del_name_key(nm, 17, D2K_LINK_SHAPE_QUIC, 4) == 0,
              "recheck: second CLEAR sent a delete outside its measured shape");
        CHECK(said("второй независимый"), "recheck: deletion not reported");
        d2k_sched_free(s);
        d2k_catalog_free(&c);
    }
    {
        /* 4. Повторное подтверждение после пометки снимает её и возвращает
           привязку на провод (§3.7: перепроверить сохранённое решение). */
        const char *nm = "recheck-again.example";
        d2k_catalog c = {0};
        tcp_answer = D2K_V_PREFIX; ver_answer = D2K_VER_APPLICATION; ver_fail_first = 0;
        confirm_once(&c, sv[0], nm, 40611);
        CHECK(bindings_of(&c, nm, 6) == 1, "recheck/again: fixture not confirmed");
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_CLEAR;
        d2k_ev h = ev_hello(6, 40612, nm);
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40612);
        d2k_sched_event(s, &su);
        settle(s);
        d2k_sched_free(s);
        const d2k_cat_binding *b = binding_of(&c, nm, 6);
        CHECK(b && b->recheck_since, "recheck/again: CLEAR did not mark");
        tcp_answer = D2K_V_PREFIX;
        confirm_once(&c, sv[0], nm, 40613);
        b = binding_of(&c, nm, 6);
        CHECK(bindings_of(&c, nm, 6) == 1 && b && !b->recheck_since,
              "recheck/again: reconfirmation did not clear the recheck mark");
        s = d2k_sched_new(&c, sv[0], 0x2d);
        drain(); forget_sent(); d2k_sched_sync(s); sync_out(s);
        CHECK(sent_set_name_shape(nm, b ? (b->shape ? b->shape : D2K_LINK_SHAPE_GRANDFATHER) : 1) == 1,
              "recheck/again: reconfirmed binding not back on the wire");
        d2k_sched_free(s);
        d2k_catalog_free(&c);
    }
    {
        /* 5. QUIC мерится без записанной формы (asked_shape = 0): прямой
           проход касается только формы замера — QUIC, — не TLS той же цели. */
        const char *nm = "recheck-quic.example";
        d2k_catalog c = {0};
        tcp_answer = D2K_V_PREFIX; ver_answer = D2K_VER_APPLICATION; ver_fail_first = 0;
        confirm_once(&c, sv[0], nm, 40621);
        d2k_cat_binding *modern = binding_mut(&c, nm, 6);
        CHECK(modern != NULL, "recheck/quic: fixture not confirmed");
        if (modern) {
            d2k_cat_binding proto = *modern;
            add_binding_like(&c.boxes[0], &proto, 6, D2K_SHAPE_LEGACY);
            add_binding_like(&c.boxes[0], &proto, 6, D2K_LINK_SHAPE_ECH_TCP);
            add_binding_like(&c.boxes[0], &proto, 17, D2K_LINK_SHAPE_QUIC);
        }
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        drain(); forget_sent();
        quic_answer = D2K_V_CLEAR; quic_calls = 0;
        d2k_ev h = ev_hello(17, 40622, nm);
        d2k_sched_event(s, &h);
        d2k_ev sh;
        CHECK(quic_shape(&sh, nm) == 0, "recheck/quic: snapshot fixture");
        d2k_sched_event(s, &sh);
        d2k_ev su = ev_suspect(17, 40622);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(quic_calls == 1, "recheck/quic: direct QUIC measurement did not run");
        d2k_cat_binding *q = binding_shape(&c, nm, 17, D2K_LINK_SHAPE_QUIC);
        CHECK(q && q->recheck_since, "recheck/quic: QUIC binding not marked");
        CHECK(!binding_shape(&c, nm, 6, D2K_SHAPE_MODERN)->recheck_since &&
              !binding_shape(&c, nm, 6, D2K_SHAPE_LEGACY)->recheck_since &&
              !binding_shape(&c, nm, 6, D2K_LINK_SHAPE_ECH_TCP)->recheck_since,
              "recheck/quic: unknown-shape CLEAR touched TLS bindings it did not measure");
        CHECK(sent_command_count(D2K_CMD_DEL_NAME, NULL, 0) == 1 &&
              sent_del_name_key(nm, 17, D2K_LINK_SHAPE_QUIC, 4) == 1,
              "recheck/quic: QUIC CLEAR must delete exactly (name, UDP, QUIC)");
        d2k_sched_free(s);
        d2k_catalog_free(&c);
        quic_answer = D2K_V_OPAQUE;
    }
    {
        /* 6. Вопросы о свойствах: после prop_finish заказан проход каталога,
           и ни одна ветка (в т.ч. prop_sport_be == 0 при props_asked) не
           шлёт DEL_NAME. */
        d2k_catalog c = {0};
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        drain(); d2k_sched_sync(s); sync_out(s);
        CHECK(!d2k_sched_sync_pending(s), "recheck/props: initial sync did not finish");
        forget_sent();
        tcp_answer = D2K_V_OPAQUE; tcp_owns_search = 0; tcp_found_arm = 0;
        ver_answer = D2K_VER_HANDSHAKE;
        d2k_ev h = ev_hello(6, 40631, "recheck-props.example");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40631);
        d2k_sched_event(s, &su);
        for (int i = 0; i < 300 && !said("поставил план 1 из"); i++) {
            skip_ahead(s, 3000);
            spin(s, 20);
        }
        CHECK(said("спрашиваю коробку о свойствах"), "recheck/props: questions not asked");
        CHECK(said("поставил план 1 из"), "recheck/props: no candidate after questions");
        CHECK(d2k_sched_sync_pending(s), "recheck/props: prop_finish did not order catalog sync");
        run_out(s);
        CHECK(sent_command_count(D2K_CMD_DEL_NAME, NULL, 0) == 0,
              "recheck/props: question/candidate cleanup sent a name-wide/permanent DEL_NAME");
        d2k_sched_free(s);
        d2k_catalog_free(&c);
        ver_answer = D2K_VER_APPLICATION;
    }
    {
        /* 7. Ревью задачи 21: помеченная к перепроверке привязка TLS 1.3
           снята с провода и «покрытием» формы не считается. Блок вернулся,
           TLS 1.2 подтверждён, задача наблюдает; клиент TLS 1.3 без плана
           приходит неприменённым — его снимок обязан завести перемер. */
        const char *nm = "recheck-watch.example";
        d2k_catalog c = {0};
        tcp_answer = D2K_V_PREFIX; tcp_owns_search = 0; tcp_found_arm = 0;
        ver_answer = D2K_VER_APPLICATION; ver_fail_first = 0;
        confirm_once(&c, sv[0], nm, 40641);
        d2k_cat_binding *m = binding_shape(&c, nm, 6, D2K_SHAPE_MODERN);
        CHECK(m != NULL, "recheck/watch: TLS1.3 fixture not confirmed");
        /* Вход «байты клиента»: иначе перемер заводит другая ветка (привязка
           добыта заготовкой), и проверка покрытия не различалась бы. */
        if (m) { m->recheck_since = 1790000000; m->recheck_mono_ms = 0;
                 m->input = D2K_INPUT_CLIENT; }
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        d2k_ev sh = {0}; sh.kind = D2K_EV_SHAPE; sh.transport = 6; sh.family = 4;
        CHECK(d2k_hello_from_profile(D2K_SHAPE_LEGACY, nm, sh.shape, sizeof sh.shape,
                                     &sh.shape_len) == 0, "recheck/watch: legacy snapshot");
        d2k_sched_event(s, &sh);
        ver_answer_port = 40642;
        d2k_ev h = ev_hello(6, 40642, nm);
        d2k_sched_event(s, &h);
        d2k_ev su = h; su.kind = D2K_EV_SUSPECT; su.code = D2K_SUSPECT_RST_CUT;
        d2k_sched_event(s, &su); settle(s);
        d2k_ev ap = ev_applied(6, 40642);
        d2k_sched_event(s, &ap); spin(s, 40);
        CHECK(binding_shape(&c, nm, 6, D2K_SHAPE_LEGACY) != NULL,
              "recheck/watch: TLS1.2 not confirmed — nothing to watch");
        d2k_cat_binding *lg = binding_shape(&c, nm, 6, D2K_SHAPE_LEGACY);
        if (lg) lg->input = D2K_INPUT_CLIENT;
        int before = tcp_calls;
        saidbuf[0] = '\0';
        forget_sent();
        h.high_port++; su.high_port++;
        d2k_sched_event(s, &h);
        su.planned = D2K_LINK_PLANNED_NO;
        d2k_sched_event(s, &su); drain();
        CHECK(sent_command_count(D2K_CMD_ARM_SHAPE, NULL, 0) == 1,
              "recheck/watch: unplanned flow did not request a snapshot");
        CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, nm, sh.shape, sizeof sh.shape,
                                     &sh.shape_len) == 0, "recheck/watch: modern snapshot");
        d2k_sched_event(s, &sh); settle(s);
        CHECK(tcp_calls > before,
              "recheck/watch: off-wire recheck binding counted as covering TLS1.3 — no remeasure");
        d2k_sched_free(s);
        d2k_catalog_free(&c);
    }
    if (recheck_only) { goto voice_only_done; }
lifecycle_test:
    /* --- ЗАДАЧА 24: жизненный цикл задачи --------------------------------
       (1) провал запуска замера при перезапуске снимком не оставляет зомби;
       (2) перемер снимком получает свежий бюджет и сначала проверяет уже
           подтверждённый план; (3) просроченное T_QUEUED снимается, пока
           восстановление семейства ждёт слота; (4) APPLIED вопроса, пришедший
           до T_PROPS_WAIT, засчитан; (5) восстановление семейства находит
           планы братьев при другом регистре имени и совместимой форме;
           (6) исчерпание бюджета зондов не называется «планы исчерпаны». */
    {
        /* (1) Поздний TCP-снимок перезапускает поиск, а рабочий поток не
           заводится. start_search уже сбросил задачу — продолжать разбор
           старого вердикта занулённой задачей нельзя. */
        d2k_catalog c1 = {0};
        d2k_sched *s = d2k_sched_new(&c1, sv[0], 0x2d);
        tcp_wait_until_stop = 1; tcp_release_waiters = 0;
        tcp_saw_stop = tcp_stop_count = tcp_calls = 0;
        tcp_answer = D2K_V_PREFIX; tcp_owns_search = tcp_found_arm = 0;
        ver_answer = D2K_VER_APPLICATION; ver_fail_first = 0;
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        d2k_ev h = ev_hello(6, 41301, "restart.fail.example");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 41301);
        d2k_sched_event(s, &su);
        spin(s, 30);
        CHECK(tcp_calls == 1, "lifecycle/restart: первый замер не начался");
        d2k_ev sh = {0}; sh.kind = D2K_EV_SHAPE; sh.transport = 6;
        CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, "restart.fail.example",
              sh.shape, sizeof sh.shape, &sh.shape_len) == 0, "lifecycle/restart: снимок");
        d2k_sched_event(s, &sh);
        spawn_fail = 1;
        tcp_release_waiters = 1;
        drain(); forget_sent();
        spin(s, 80);
        tcp_wait_until_stop = 0; tcp_release_waiters = 0;
        CHECK(said("повторяю поиск его байтами"), "lifecycle/restart: перезапуск снимком не начат");
        CHECK(spawn_refused > 0, "lifecycle/restart: отказ запуска потока не случился");
        CHECK(d2k_sched_active(s) == 0,
              "lifecycle/restart: после провала запуска осталась задача-зомби");
        spawn_fail = 0;
        settle(s);
        /* Пустое имя в трассе («по  ...») — та самая задача-зомби: сброшенная
           задача продолжала разбор старого вердикта. */
        CHECK(!said("по  "), "lifecycle/restart: задача без имени продолжила поиск");
        CHECK(said("по restart.fail.example повтор поиска снимком не запустился"),
              "lifecycle/restart: провал перезапуска не назван");
        CHECK(sent_command_count(D2K_CMD_SET_NAME_PROBE, NULL, 0) == 0,
              "lifecycle/restart: задача без имени поставила пробный план");
        d2k_sched_free(s); d2k_catalog_free(&c1);
        tcp_answer = D2K_V_OPAQUE;
    }
    {
        /* (2) Подтверждённое заготовкой после многих промахов (бюджет почти
           потрачен), затем снимок клиента. Перемер — новый поиск: свежий
           бюджет и ранее подтверждённый план — первым кандидатом. */
        d2k_catalog c2 = {0};
        d2k_sched *s = d2k_sched_new(&c2, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX; tcp_owns_search = tcp_found_arm = 0;
        ver_answer = D2K_VER_APPLICATION;
        ver_calls = 0; ver_fail_first = 12;
        ver_answer_port = 41311;
        forget_sent();
        d2k_ev h = ev_hello(6, 41311, "remeasure.budget.example");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 41311);
        d2k_sched_event(s, &su);
        for (int i = 0; i < 60 && ver_calls <= ver_fail_first; i++) { skip_ahead(s, 6000); spin(s, 40); }
        settle(s);
        d2k_ev ap = ev_applied(6, 41311);
        d2k_sched_event(s, &ap);
        spin(s, 40);
        const d2k_cat_binding *bd = binding_of(&c2, "remeasure.budget.example", 6);
        CHECK(bd != NULL && bd->input == D2K_INPUT_PROFILE,
              "lifecycle/remeasure: подтверждение заготовкой не записано");
        char confirmed_plan[40] = {0};
        if (bd) snprintf(confirmed_plan, sizeof confirmed_plan, "%s", bd->plan_id);
        ver_fail_first = 0;
        ver_answer_port = 41312;
        saidbuf[0] = '\0';
        d2k_ev sh = {0}; sh.kind = D2K_EV_SHAPE; sh.transport = 6;
        CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, "remeasure.budget.example",
              sh.shape, sizeof sh.shape, &sh.shape_len) == 0, "lifecycle/remeasure: снимок");
        d2k_sched_event(s, &sh);
        CHECK(said("перемеряю снимком"), "lifecycle/remeasure: перемер не начат");
        int probes_after = live_task_probes(s, "remeasure.budget.example");
        printf("lifecycle/remeasure: probes after remeasure start = %d\n", probes_after);
        CHECK(probes_after == 0,
              "lifecycle/remeasure: перемер унаследовал бюджет зондов прошлого поиска");
        settle(s);
        CHECK(said("готовых планов узнанной коробки"),
              "lifecycle/remeasure: ранее подтверждённый план не проверен первым");
        d2k_ev ap2 = ev_applied(6, 41312);
        d2k_sched_event(s, &ap2);
        spin(s, 40);
        bd = binding_of(&c2, "remeasure.budget.example", 6);
        CHECK(bd != NULL && bd->input == D2K_INPUT_CLIENT && !strcmp(bd->plan_id, confirmed_plan),
              "lifecycle/remeasure: перемер не подтвердил прежний план байтами клиента");
        d2k_sched_free(s); d2k_catalog_free(&c2);
    }
    {
        /* (6) Бюджет зондов кончается раньше кандидатов: каждый кандидат
           переиспытывается после временных отказов отправки. Это неполный
           поиск, а не «планы исчерпаны» (D2K_SPEC §3). */
        d2k_catalog c6 = {0};
        d2k_sched *s = d2k_sched_new(&c6, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX; tcp_owns_search = tcp_found_arm = 0;
        ver_answer = D2K_VER_APPLICATION; ver_fail_first = 0;
        ver_answer_port = 41361; ver_calls = 0;
        d2k_ev h = ev_hello(6, 41361, "budget.out.example");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 41361);
        d2k_sched_event(s, &su);
        settle(s);
        int done = 0;
        for (int i = 0; i < 400 && !done; i++) {
            d2k_ev tmp = ev_refused(6, 41361, D2K_REFUSE_QUEUE, 1);
            d2k_sched_event(s, &tmp);
            skip_ahead(s, 6000);
            spin(s, 30);
            done = said("цель отдыхает") || said("бюджет зондов исчерпан") ||
                   said("новый поиск отложен");
        }
        CHECK(done, "lifecycle/budget: поиск не завершился");
        CHECK(said("бюджет зондов исчерпан"),
              "lifecycle/budget: исчерпание бюджета зондов не названо");
        CHECK(!said("выведенные планы исчерпаны"),
              "lifecycle/budget: исчерпание бюджета выдано за исчерпание планов");
        CHECK(total_bindings(&c6) == 0, "lifecycle/budget: отказ отправки записан успехом");
        d2k_sched_free(s); d2k_catalog_free(&c6);
    }
    for (int qmode = 0; qmode < 3; qmode++) {
        /* (4) APPLIED вопроса приходит, пока задача ещё в T_PROPS_CONTACT:
           рабочий поток вернулся сразу после посылки, а d2kc читает события
           связи раньше тика. Применение засчитывается после перехода.
           qmode 1: и ответ сервера (EXCHANGE с ServerHello) пришёл до тика —
           это улика, а не промах. qmode 2: ранний обмен ЧУЖОГО потока с тем
           же местным портом не засчитан; настоящий ответ — засчитан. */
        uint16_t saved_port = g_server_port;
        int lfd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a;
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(0x7f000001);
        int bound = 0;
        for (uint16_t port = 19500; port < 19600 && !bound; port++) {
            a.sin_port = htons(port);
            bound = (bind(lfd, (struct sockaddr *)&a, sizeof a) == 0);
        }
        CHECK(lfd >= 0 && bound, "lifecycle/question: стенд-цель не привязалась");
        socklen_t al = sizeof a;
        CHECK(getsockname(lfd, (struct sockaddr *)&a, &al) == 0 && listen(lfd, 4) == 0,
              "lifecycle/question: стенд-цель не слушает");
        g_server_port = ntohs(a.sin_port);
        d2k_catalog c4 = {0};
        d2k_sched *s = d2k_sched_new(&c4, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_OPAQUE; tcp_owns_search = tcp_found_arm = 0;
        uint16_t cport = (uint16_t)(41341 + qmode);
        d2k_ev h = ev_hello(6, cport, "early.question.example");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, cport);
        d2k_sched_event(s, &su);
        for (int i = 0; i < 200 && !said("спрашиваю коробку о свойствах"); i++) tick_once(s);
        CHECK(said("спрашиваю коробку о свойствах"), "lifecycle/question: вопрос не задан");
        uint8_t qid[D2K_PLAN_ID_LEN] = {0};
        CHECK(last_plan_id(qid), "lifecycle/question: id вопроса не прочитан");
        int peer = -1;
        for (int i = 0; i < 400 && peer < 0; i++) {
            struct pollfd p2; p2.fd = lfd; p2.events = POLLIN; p2.revents = 0;
            if (poll(&p2, 1, 5) > 0) {
                struct sockaddr_in pa;
                socklen_t pl = sizeof pa;
                peer = accept(lfd, (struct sockaddr *)&pa, &pl);
                if (peer >= 0) { a = pa; break; }
            }
            tick_once(s);
        }
        CHECK(peer >= 0, "lifecycle/question: зонд вопроса не пришёл к цели");
        CHECK(!said("ушёл с местного порта"), "lifecycle/question: стенд не воспроизводит T_PROPS_CONTACT");
        d2k_ev x;
        memset(&x, 0, sizeof x);
        x.transport = 6;
        x.low_ip[0] = 127; x.low_ip[3] = 1; x.low_port = g_server_port;
        x.high_ip[0] = 127; x.high_ip[3] = 1; x.high_port = ntohs(a.sin_port);
        x.kind = D2K_EV_APPLIED;
        memcpy(x.plan_id, qid, sizeof qid);
        d2k_sched_event(s, &x);
        d2k_ev ex = x;
        ex.kind = D2K_EV_EXCHANGE;
        memset(ex.plan_id, 0, sizeof ex.plan_id);
        ex.code = 22; ex.num = 1380; ex.seen_types = 0x0C; ex.server_hello = 1;
        if (qmode == 1) d2k_sched_event(s, &ex);
        if (qmode == 2) {
            d2k_ev foreign = ex;
            foreign.low_port = (uint16_t)(g_server_port + 1);   /* другой сервер */
            d2k_sched_event(s, &foreign);
        }
        for (int i = 0; i < 400 && !said("ушёл с местного порта"); i++) tick_once(s);
        CHECK(said("ушёл с местного порта"), "lifecycle/question: переход к ожиданию не случился");
        if (qmode == 2) {
            CHECK(!said("вопрос 1 прошёл") && !said("ответ замечен"),
                  "lifecycle/question: ранний обмен чужого потока засчитан за ответ вопроса");
        }
        if (qmode != 1) d2k_sched_event(s, &ex);
        CHECK(said("вопрос 1 прошёл"),
              qmode == 1 ? "lifecycle/question: ранний ответ сервера потерян — вопрос станет промахом"
                         : "lifecycle/question: ранний APPLIED вопроса потерян в T_PROPS_CONTACT");
        CHECK(!said("жду подтверждения полного исполнения"),
              "lifecycle/question: ответ ждёт применения, которое уже пришло");
        d2k_sched_free(s); d2k_catalog_free(&c4);
        if (peer >= 0) close(peer);
        close(lfd);
        g_server_port = saved_port;
    }
    {
        /* Финальное ревью core, M2: срок жизни истёк, пока вопрос о свойствах
           стоял в T_PROPS_CONTACT (поток обращения вернулся, задача его ещё
           не приняла). Сокет обращения закрывается вместе с задачей, а не
           остаётся висеть в d2kc, живущем сутками. */
        uint16_t saved_port = g_server_port;
        int lfd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a;
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(0x7f000001);
        int bound = 0;
        for (uint16_t port = 19600; port < 19700 && !bound; port++) {
            a.sin_port = htons(port);
            bound = (bind(lfd, (struct sockaddr *)&a, sizeof a) == 0);
        }
        socklen_t al = sizeof a;
        CHECK(lfd >= 0 && bound && getsockname(lfd, (struct sockaddr *)&a, &al) == 0 &&
              listen(lfd, 4) == 0, "lifecycle/contact-life: стенд-цель не слушает");
        g_server_port = ntohs(a.sin_port);
        d2k_catalog c4 = {0};
        d2k_sched *s = d2k_sched_new(&c4, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_OPAQUE; tcp_owns_search = tcp_found_arm = 0;
        d2k_ev h = ev_hello(6, 41349, "contact-life.example");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 41349);
        d2k_sched_event(s, &su);
        for (int i = 0; i < 200 && !said("спрашиваю коробку о свойствах"); i++) tick_once(s);
        int peer = -1;
        for (int i = 0; i < 400 && peer < 0; i++) {
            struct pollfd p2; p2.fd = lfd; p2.events = POLLIN; p2.revents = 0;
            if (poll(&p2, 1, 5) > 0) { peer = accept(lfd, NULL, NULL); if (peer >= 0) break; }
            tick_once(s);
        }
        CHECK(peer >= 0 && !said("ушёл с местного порта"),
              "lifecycle/contact-life: стенд не воспроизводит T_PROPS_CONTACT");
        skip_ahead(s, 11 * 60 * 1000);
        int closed = 0;
        for (int i = 0; i < 200 && peer >= 0 && !closed; i++) {
            struct pollfd p3; p3.fd = peer; p3.events = POLLIN; p3.revents = 0;
            if (poll(&p3, 1, 10) > 0) {
                char b[4096];
                ssize_t n = recv(peer, b, sizeof b, 0);
                if (n == 0 || (n < 0 && errno != EAGAIN && errno != EINTR)) closed = 1;
            }
        }
        CHECK(closed, "lifecycle/contact-life: сокет обращения пережил задачу (утечка дескриптора)");
        d2k_sched_free(s); d2k_catalog_free(&c4);
        if (peer >= 0) close(peer);
        close(lfd);
        g_server_port = saved_port;
    }
    {
        /* (5) Братья семейства подтверждены под именами в другом регистре
           (SNI клиента не нормализован), новый член пишется
           WWW.Mixed.NET. — восстановление обязано найти их планы. Второй
           каталог: формы привязок братьев не измерены (0), что совместимо
           с формой ключа семейства. */
        /* Вариант 2 (финальное ревью, п.2): все братья помечены к
           перепроверке (recheck_since). Такая привязка — не подтверждённое
           покрытие: быстрый путь «собственных планов семейства» на ней не
           строится (как own_exact_confirmed и sync), план остаётся лишь
           кандидатом обычного поиска. */
        for (int variant = 0; variant < 3; variant++) {
            static const char *mixed[4] = {"A.Mixed.NET", "b.MIXED.net.", "C.mixed.Net", "d.Mixed.net"};
            static const char *plain[4] = {"a.shape.net", "b.shape.net", "c.shape.net", "d.shape.net"};
            static const char *rechk[4] = {"a.rechk.net", "b.rechk.net", "c.rechk.net", "d.rechk.net"};
            const char **names = variant == 0 ? mixed : variant == 1 ? plain : rechk;
            const char *member = variant == 0 ? "WWW.Mixed.NET." :
                                 variant == 1 ? "www.shape.net" : "www.rechk.net";
            int saved_buf = 256 * 1024;
            (void)setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &saved_buf, sizeof saved_buf);
            tcp_answer = D2K_V_PREFIX; tcp_found_arm = 0; tcp_owns_search = 0; ver_fail_first = 0;
            d2k_catalog c5 = {0};
            for (int i = 0; i < 4; i++) confirm_once(&c5, sv[0], names[i], (uint16_t)(41350 + variant * 10 + i));
            if (variant == 1) {
                for (int i = 0; i < 4; i++) {
                    d2k_cat_binding *m = binding_mut(&c5, names[i], 6);
                    CHECK(m != NULL, "lifecycle/family: привязка брата не найдена");
                    if (m) m->shape = 0;
                }
            }
            if (variant == 2) {
                for (int i = 0; i < 4; i++) {
                    d2k_cat_binding *m = binding_mut(&c5, names[i], 6);
                    CHECK(m != NULL, "lifecycle/family: привязка брата не найдена");
                    if (m) { m->recheck_since = 1790000000; m->recheck_mono_ms = 0; }
                }
            }
            d2k_group_key key = {0}; key.transport = 6; key.family = 4; key.shape = 1;
            strcpy(key.probe_path, "/");
            CHECK(d2k_group_match(c5.groups, member, &key) != NULL,
                  "lifecycle/family: семейство братьев не выучено");
            d2k_sched *s = d2k_sched_new(&c5, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            drain(); forget_sent(); d2k_sched_sync(s); sync_out(s);
            d2k_ev ack = {0}; ack.kind = D2K_EV_ACK; ack.code = D2K_CMD_SET_SUFFIX; ack.num = 1u << 8;
            area_ack_id(&ack);
            d2k_sched_event(s, &ack); sync_out(s);
            tcp_calls = vol_calls = ver_calls = 0;
            uint16_t port = (uint16_t)(41358 + variant * 10);
            ver_answer_port = port;
            d2k_ev h = ev_hello(6, port, member); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, port); su.planned = D2K_LINK_PLANNED_YES;
            su.code = D2K_SUSPECT_SILENT; su.client_shape = D2K_SHAPE_MODERN;
            d2k_sched_event(s, &su);
            settle(s);
            if (variant == 2) {
                CHECK(!said("собственных планов семейства"),
                      "lifecycle/family: помеченный к перепроверке брат засчитан подтверждённым покрытием");
                d2k_sched_free(s); d2k_catalog_free(&c5);
                continue;
            }
            CHECK(said("собственных планов семейства"),
                  variant == 0 ? "lifecycle/family: регистр имени брата скрыл его план"
                               : "lifecycle/family: совместимая форма привязки брата отвергнута");
            CHECK(ver_calls > 0 && tcp_calls == 0 && vol_calls == 0,
                  "lifecycle/family: восстановление семейства ушло в полный замер");
            d2k_sched_free(s); d2k_catalog_free(&c5);
        }
    }
    {
        /* (3) Два слота заняты, в очереди — обычное подозрение O, позже —
           восстановление семейства R. Срок жизни O истекает: O снимается
           в том же круге, а не ждёт, пока R получит слот. */
        d2k_catalog c3 = {0};
        tcp_answer = D2K_V_PREFIX; tcp_found_arm = 0; tcp_owns_search = 0; ver_fail_first = 0;
        for (int i = 0; i < 4; i++) {
            char nm[64];
            snprintf(nm, sizeof nm, "%c.queue.net", 'a' + i);
            confirm_once(&c3, sv[0], nm, (uint16_t)(41370 + i));
        }
        d2k_sched *s = d2k_sched_new(&c3, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        drain(); forget_sent(); d2k_sched_sync(s); sync_out(s);
        d2k_ev ack = {0}; ack.kind = D2K_EV_ACK; ack.code = D2K_CMD_SET_SUFFIX; ack.num = 1u << 8;
        area_ack_id(&ack);
        d2k_sched_event(s, &ack); sync_out(s);
        tick_once(s);
        tcp_wait_until_stop = 1; tcp_release_waiters = 0; tcp_calls = 0;
        for (uint16_t port = 41381; port < 41383; port++) {
            d2k_ev h = ev_hello(6, port, port == 41381 ? "busy-q1.example" : "busy-q2.example");
            d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, port); d2k_sched_event(s, &su);
        }
        spin(s, 5);
        d2k_ev h = ev_hello(6, 41383, "old-queued.example"); d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 41383); d2k_sched_event(s, &su);
        CHECK(said("по old-queued.example подозрение сохранено в ограниченной очереди"),
              "lifecycle/queue: обычное подозрение не встало в очередь");
        int64_t queued_at = g_now_ms;
        skip_ahead(s, 9 * 60 * 1000);
        h = ev_hello(6, 41384, "new.queue.net"); d2k_sched_event(s, &h);
        su = ev_suspect(6, 41384); su.planned = D2K_LINK_PLANNED_YES;
        su.code = D2K_SUSPECT_SILENT; su.client_shape = D2K_SHAPE_MODERN;
        d2k_sched_event(s, &su);
        CHECK(said("по new.queue.net подозрение сохранено в ограниченной очереди"),
              "lifecycle/queue: восстановление семейства не ждёт слота");
        saidbuf[0] = '\0';
        skip_ahead(s, queued_at + 10 * 60 * 1000 + 1000 - g_now_ms);
        CHECK(said("по old-queued.example подозрение устарело в очереди"),
              "lifecycle/queue: просроченное подозрение ждёт слота восстановления семейства");
        tcp_wait_until_stop = 0; tcp_release_waiters = 1;
        d2k_sched_free(s); d2k_catalog_free(&c3);
        tcp_release_waiters = 0;
    }
    if (lifecycle_only) { goto voice_only_done; }
    /* --- узнанная коробка отдаёт свои планы, и успех идёт ЕЙ ----------- */
    {
        d2k_catalog c6;
        memset(&c6, 0, sizeof c6);
        d2k_sched *s = d2k_sched_new(&c6, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;

        /* Первая цель: коробка ещё не известна — заводится новая, по
           отпечатку. */
        ver_answer_port = 40050;
        forget_sent();
        d2k_ev h = ev_hello(6, 40050, "первая.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40050);
        d2k_sched_event(s, &su);
        settle(s);
        d2k_ev x = ev_applied(6, 40050);
        d2k_sched_event(s, &x);
        spin(s, 40);
        CHECK(c6.n_boxes == 1, "первый успех не завёл коробку");
        CHECK(c6.n_boxes == 1 && c6.boxes[0].fp.n_sig == 1,
              "у заведённой коробки не записан отпечаток — узнать её потом будет нечем");
        CHECK(c6.n_boxes == 1 && strcmp(c6.boxes[0].id, "box-без-приметы") != 0,
              "коробка заведена без имени по отпечатку");

        /* Вторая цель с ТЕМ ЖЕ отпечатком: коробка обязана узнаться, её план —
           уйти в кандидаты первым, а успех — лечь в ту же коробку, а не в
           клон. */
        size_t boxes_before = c6.n_boxes;
        tcp_calls = vol_calls = 0;
        ver_answer_port = 40051;
        forget_sent();
        d2k_ev h2 = ev_hello(6, 40051, "вторая.цель");
        d2k_sched_event(s, &h2);
        d2k_ev su2 = ev_suspect(6, 40051);
        d2k_sched_event(s, &su2);
        settle(s);
        /* Блок на рукопожатии (PREFIX): объём после него не мерится (задача 30). */
        CHECK(tcp_calls == 1 && vol_calls == 0,
              "узнанная коробка не была проверена прямым замером до готового плана");
        d2k_ev x2 = ev_applied(6, 40051);
        d2k_sched_event(s, &x2);
        spin(s, 40);
        CHECK(c6.n_boxes == boxes_before,
              "вторая цель с тем же отпечатком завела КЛОН коробки вместо узнавания");
        CHECK(binding_of(&c6, "вторая.цель", 6) != NULL, "вторая привязка не записана");
        CHECK(said("готовых планов узнанной коробки"),
              "коробка не узнана: её проверенные планы не попали в кандидаты второй цели");
        CHECK(c6.n_boxes == 1 && c6.boxes[0].n_plans >= 1 &&
              strcmp(c6.boxes[0].plans[0].proto, "tls") == 0,
              "proto записанного плана не \"tls\" — в живом каталоге у всех планов именно он, "
              "и сравнение с транспортом отбрасывало бы каждый настоящий план");

        /* A miss on a new target falls back to research ONCE, without
           discarding the established bindings of the other targets. */
        tcp_calls = vol_calls = 0;
        /* Готовый план узнанной коробки третьей цели НЕ помогает: зонд доходит
           до рукопожатия и молчит. Промах виден планировщику сам, без единого
           события от пользователя. */
        ver_answer = D2K_VER_HANDSHAKE;
        forget_sent();
        d2k_ev h3 = ev_hello(6, 40052, "третья.цель");
        d2k_sched_event(s, &h3);
        d2k_ev su3 = ev_suspect(6, 40052);
        d2k_sched_event(s, &su3);
        settle(s);
        CHECK(tcp_calls == 1 && vol_calls == 0,
              "после промаха готового плана повторно запущено прямое измерение");
        CHECK(binding_of(&c6, "вторая.цель", 6) != NULL,
              "промах третьей цели повредил подтверждённую вторую");
        CHECK(binding_of(&c6, "третья.цель", 6) == NULL,
              "промах готового плана записан как новая привязка");
        d2k_sched_free(s);
        d2k_catalog_free(&c6);
    }

    /* A recognized box whose old plan has gone stale may learn a replacement,
       but the new plan belongs to that same measured box.  The passive
       fingerprint is unchanged; plan identity must not be mixed into box
       identity after a successful re-search. */
    {
        d2k_catalog cD;
        memset(&cD, 0, sizeof cD);
        cD.boxes = calloc(1, sizeof *cD.boxes);
        CHECK(cD.boxes != NULL, "не удалось создать коробку для деградации");
        if (cD.boxes) {
            cD.n_boxes = 1;
            d2k_cat_box *b = &cD.boxes[0];
            snprintf(b->id, sizeof b->id, "box-stable-fingerprint");
            b->fp.method = D2K_FP_METHOD;
            b->fp.n_sig = 1;
            snprintf(b->fp.sig[0].kind, sizeof b->fp.sig[0].kind, "rst");
            b->fp.sig[0].ttl = 127;
            b->fp.sig[0].tos = 0x88;
            b->fp.sig[0].ipid = 54321;
            b->plans = calloc(1, sizeof *b->plans);
            CHECK(b->plans != NULL, "не удалось создать устаревший план");
            if (b->plans) {
                b->n_plans = 1;
                snprintf(b->plans[0].id, sizeof b->plans[0].id, "plan-stale");
                snprintf(b->plans[0].proto, sizeof b->plans[0].proto, "tls");
                b->plans[0].enabled = 1;
                b->plans[0].successes = 3;
                b->plans[0].text = strdup(
                    "d2k-plan 1 1\nid 00000000000000000000000000000000\n"
                    "proto tcp tls\nsplit payload_start +1\norder forward\n");
            }
            d2k_sched *s = d2k_sched_new(&cD, sv[0], 0x2d);
            CHECK(s != NULL, "планировщик деградации не создан");
            if (s) {
                saidbuf[0] = '\0';
                d2k_sched_set_say(s, collect_say, NULL);
                tcp_answer = D2K_V_PREFIX;
                tcp_calls = vol_calls = 0;
                ver_answer = D2K_VER_APPLICATION;
                /* The first (catalog) plan fails; the already-measured
                   replacement candidate is independently verifiable. */
                ver_fail_first = 1;
                ver_app_after_tcp_search = 1;
                ver_calls = 0;
                ver_answer_port = 40053;
                forget_sent();
                d2k_ev h = ev_hello(6, 40053, "деградировавшая.цель");
                d2k_sched_event(s, &h);
                d2k_ev su = ev_suspect(6, 40053);
                d2k_sched_event(s, &su);
                /* As with the existing known-box path, wait until the first
                   (catalog) plan is installed and acknowledge its application
                   before expecting the verifier's miss to advance the task. */
                spin_until_installed(s);
                d2k_ev old_ap = ev_applied(6, 40053);
                d2k_sched_event(s, &old_ap);
                settle(s);

                CHECK(said("готовых планов узнанной коробки"),
                      "устаревший план не был проверен первым");
                CHECK(tcp_calls == 1, "после отказа готового плана прямое измерение повторилось");
                CHECK(ver_calls >= 1, "готовый план не был проверен");

                /* The measured replacement has its own apply proof. */
                d2k_ev ap = ev_applied(6, 40053);
                d2k_sched_event(s, &ap);
                settle(s);
                CHECK(ver_calls >= 2,
                      "новый измеренный кандидат не проверен после отказа старого плана");
                CHECK(total_bindings(&cD) == 1,
                      "успех нового плана не создал ровно одну привязку");
                CHECK(cD.n_boxes == 1,
                      "новый Plan с тем же совместимым измеренным отпечатком размножил коробку");
                CHECK(cD.n_boxes == 1 && cD.boxes[0].n_plans >= 2,
                      "новый подтверждённый Plan не добавлен к модели уже узнанной коробки");
                CHECK(cD.revision > 0,
                      "изменение каталога не подняло revision для надёжного сохранения");
                CHECK(binding_of(&cD, "деградировавшая.цель", 6) != NULL,
                      "после деградации не сохранена новая подтверждённая привязка");
                ver_app_after_tcp_search = 0;
                d2k_sched_free(s);
            }
            d2k_catalog_free(&cD);
        }
    }

    /* --- каталог едет датапату при запуске, а не лежит мёртвым грузом --- */
    {
        /* Каталог с одной коробкой, одним планом и двумя привязками: по имени
           и по адресу. d2k_sched_sync обязан поставить обе — датапат состояния
           между запусками не хранит, и без этого прохода уже изученная цель
           начинала бы поиск заново. */
        d2k_catalog c7;
        memset(&c7, 0, sizeof c7);
        c7.boxes = calloc(1, sizeof *c7.boxes);
        CHECK(c7.boxes != NULL, "каталог не завёлся");
        if (c7.boxes) {
            c7.n_boxes = 1;
            snprintf(c7.boxes[0].id, sizeof c7.boxes[0].id, "box-эталон");
            c7.boxes[0].plans = calloc(1, sizeof *c7.boxes[0].plans);
            c7.boxes[0].n_plans = 1;
            snprintf(c7.boxes[0].plans[0].id, sizeof c7.boxes[0].plans[0].id, "plan-эталон");
            /* "tls", а не "tcp": proto плана — протокол уровня приложения,
               как в живом каталоге (см. known_plans в sched.c). */
            snprintf(c7.boxes[0].plans[0].proto, sizeof c7.boxes[0].plans[0].proto, "tls");
            c7.boxes[0].plans[0].enabled = 1;
            c7.boxes[0].plans[0].text = strdup(
                "d2k-plan 1 1\nid 00000000000000000000000000000000\nproto tcp tls\n"
                "split payload_start +1\norder reverse\n");
            c7.boxes[0].binds = calloc(4, sizeof *c7.boxes[0].binds);
            c7.boxes[0].n_binds = 4;
            for (int i = 0; i < 4; i++) {
                snprintf(c7.boxes[0].binds[i].plan_id, sizeof c7.boxes[0].binds[i].plan_id,
                         "plan-эталон");
                c7.boxes[0].binds[i].transport = 6;
            }
            snprintf(c7.boxes[0].binds[0].kind, sizeof c7.boxes[0].binds[0].kind, "name");
            snprintf(c7.boxes[0].binds[0].target, sizeof c7.boxes[0].binds[0].target, "по.имени");
            c7.boxes[0].binds[0].enabled = 1;
            snprintf(c7.boxes[0].binds[1].kind, sizeof c7.boxes[0].binds[1].kind, "addr");
            snprintf(c7.boxes[0].binds[1].target, sizeof c7.boxes[0].binds[1].target, "1.2.3.4");
            c7.boxes[0].binds[1].enabled = 1;
            /* Третья выключена — ставиться не должна. */
            snprintf(c7.boxes[0].binds[2].kind, sizeof c7.boxes[0].binds[2].kind, "name");
            snprintf(c7.boxes[0].binds[2].target, sizeof c7.boxes[0].binds[2].target, "выключена");
            c7.boxes[0].binds[2].enabled = 0;
            /* Четвёртая — по АДРЕСУ и с уровнем 2 «сервер ответил»: ровно та
               запись, что 13.09.2026 сломала контрольную цель на роутере.
               Доказательство слабее обмена — на провод не едет.

               У первых трёх уровень нулевой, и это НЕ упущение фикстуры: ноль
               означает «не записано» (старый файл), и он обязан ставиться
               по-прежнему — иначе правило обнулило бы человеку весь каталог
               разом. Обе половины правила проверяются одним прогоном. */
            snprintf(c7.boxes[0].binds[3].kind, sizeof c7.boxes[0].binds[3].kind, "addr");
            snprintf(c7.boxes[0].binds[3].target, sizeof c7.boxes[0].binds[3].target, "8.47.69.0");
            c7.boxes[0].binds[3].enabled = 1;
            c7.boxes[0].binds[3].level = 2;

            d2k_sched *s = d2k_sched_new(&c7, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            /* Проход идёт ПОРЦИЯМИ: залпом он создавал бы окно, в котором
               датапату некуда сказать про живой трафик (см. d2k_sched_sync_step).
               Крутим его так же, как это делает цикл d2kc — до конца. */
            (void)d2k_sched_sync(s);
            int rounds = 0;
            while (d2k_sched_sync_step(s) && rounds++ < 1000) { drain(); }
            drain();
            CHECK(rounds < 1000, "проход по каталогу не закончился");
            CHECK(!d2k_sched_sync_pending(s), "проход по каталогу остался незакрытым");
            /* Задача 16: адресная привязка 1.2.3.4 без формы протокола (TCP,
               старый файл) — неизвестный контекст (§7): общей совместимости
               ей не выдаём, на провод не едет, требуется повторная проверка.
               Имя без формы по-прежнему ставится дедушкиным правом. */
            CHECK(said("поставлено планов по подтверждённым привязкам: 1"),
                  "проход по каталогу не сказал, сколько поставил");
            CHECK(said("адресных привязок без формы протокола: 1"),
                  "адресная привязка без формы поставлена как общая либо пропала молча");
            CHECK(sent_command_count(D2K_CMD_SET_ADDR, NULL, 0) == 0,
                  "адресная привязка без формы ушла на провод");
            CHECK(said("не поставлено привязок со слабым доказательством: 1"),
                  "привязка уровня «сервер ответил» ушла на провод наравне с "
                  "подтверждённой либо пропала молча");
            d2k_sched_free(s);
            d2k_catalog_free(&c7);
        }
    }

    /* Старый каталог записывал любой UDP EXCHANGE как CLIENT/level=3.
       Более высокий level сам по себе не добавляет доказательства. Эти записи
       не восстанавливаются автоматически даже при level=5. Подтверждения
       собственным протокольным зондом это ограничение не затрагивает. */
    for (int by_addr = 0; by_addr < 2; by_addr++) {
        for (int proof = 0; proof < 3; proof++) {
            d2k_catalog c = {0};
            c.boxes = calloc(1, sizeof *c.boxes);
            CHECK(c.boxes != NULL, "каталог UDP-доказательств не создан");
            if (!c.boxes) { continue; }
            c.n_boxes = 1;
            d2k_cat_box *box = &c.boxes[0];
            snprintf(box->id, sizeof box->id, "udp-box");
            box->plans = calloc(1, sizeof *box->plans);
            box->binds = calloc(1, sizeof *box->binds);
            CHECK(box->plans && box->binds, "записи UDP-каталога не созданы");
            if (box->plans && box->binds) {
                box->n_plans = box->n_binds = 1;
                d2k_cat_plan *p = &box->plans[0];
                snprintf(p->id, sizeof p->id, "udp-plan");
                snprintf(p->proto, sizeof p->proto, "quic");
                p->enabled = 1;
                p->successes = 1;
                p->text = strdup("d2k-plan 1 6\nid 00000000000000000000000000000000\n"
                                 "proto udp quic\ndelay 15000\n");
                d2k_cat_binding *bd = &box->binds[0];
                snprintf(bd->kind, sizeof bd->kind, "%s", by_addr ? "addr" : "name");
                snprintf(bd->target, sizeof bd->target, "%s", by_addr ? "192.0.2.7" : "udp.test");
                snprintf(bd->plan_id, sizeof bd->plan_id, "%s", p->id);
                bd->enabled = 1;
                bd->transport = 17;
                bd->level = proof == 1 ? 5 : 3;
                bd->verified_by = proof == 2 ? D2K_VERBY_PROBE : D2K_VERBY_CLIENT;
                bd->confirmed = 42;
                bd->successes = 1;
                d2k_cat_binding before = *bd;
                saidbuf[0] = '\0';
                forget_sent();
                d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
                CHECK(s != NULL, "планировщик UDP-каталога не создан");
                if (s) {
                    d2k_sched_set_say(s, collect_say, NULL);
                    (void)d2k_sched_sync(s);
                    int rounds = 0;
                    while (d2k_sched_sync_step(s) && rounds++ < 1000) { drain(); }
                    drain();
                    CHECK(rounds < 1000, "проход UDP-каталога не закончился");
                    size_t sent = sent_command_count(D2K_CMD_SET_ADDR, NULL, 0) +
                                  sent_command_count(D2K_CMD_SET_NAME, NULL, 0);
                    CHECK(sent == (size_t)(proof == 2),
                          "старый UDP CLIENT восстановлен без доказательства либо потерян PROBE");
                    if (by_addr && proof == 2) {
                        uint8_t ip7[4] = {192, 0, 2, 7};
                        CHECK(sent_set_addr_shape(4, ip7, D2K_LINK_SHAPE_QUIC) == 1,
                              "старая адресная UDP-привязка зонда без формы не восстановлена "
                              "однозначной формой QUIC");
                    }
                    CHECK(proof == 2 || said("UDP CLIENT"),
                          "пропуск старого UDP-подтверждения не объяснён");
                    CHECK(memcmp(bd, &before, sizeof before) == 0 && p->successes == 1,
                          "защита восстановления переписала пользовательский каталог");
                    d2k_sched_free(s);
                }
            }
            d2k_catalog_free(&c);
        }
    }

    /* --- очередь кандидатов движется БЕЗ пользователя (задача 3) -------- */
    {
        /* Раньше поставленный кандидат ждал чужого обмена: пока цель не
           откроют ещё раз, очередь стояла, а у телевизора «ещё раз» — через
           три минуты. Теперь кандидата испытывает сам планировщик, и промах
           виден через секунды, без единого события от пользователя. */
        d2k_catalog c5;
        memset(&c5, 0, sizeof c5);
        d2k_sched *s = d2k_sched_new(&c5, sv[0], 0x2d);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_HANDSHAKE;  /* рукопожатие есть, приложение молчит */
        ver_fail_first = 0;
        ver_calls = 0;
        d2k_ev h = ev_hello(6, 40040, "instagram.com");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40040);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(ver_calls >= 1, "планировщик не испытал кандидата сам");
        CHECK(total_bindings(&c5) == 0,
              "рукопожатие без ответа приложения записано как успех");
        CHECK(d2k_sched_active(s) == 0,
              "очередь кандидатов не продвинулась сама — поиск ждёт пользователя");
        d2k_sched_free(s);
        d2k_catalog_free(&c5);
    }

    /* --- потерянное применение НЕ улика против кандидата ---------------- */
    {
        /* Датапат держит ровно один исходящий кадр и теряет всё, что не
           поместилось (d2k_ctl.h). Пропавшее применение снаружи неотличимо от
           «план к зонду не применялся» — и без этой проверки планировщик
           выбрасывал бы РАБОЧИЙ кандидат просто потому, что о его применении
           не смогли сказать. */
        d2k_catalog c9;
        memset(&c9, 0, sizeof c9);
        d2k_sched *s = d2k_sched_new(&c9, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = 40070;
        ver_calls = 0;
        d2k_ev h = ev_hello(6, 40070, "молчащая.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40070);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(ver_calls == 1, "кандидат не испытан");
        CHECK(said("жду применения плана"),
              "зонд дошёл до приложения, а применения плана никто не ждёт");
        uint8_t first_attempt_id[D2K_PLAN_ID_LEN], second_attempt_id[D2K_PLAN_ID_LEN];
        CHECK(last_plan_id(first_attempt_id), "first trial identity captured from wire");

        /* Связь сообщает о потерях, и события применения так и нет: считать
           это уликой против кандидата нельзя — испытываем его ЕЩЁ РАЗ. */
        d2k_ev st;
        memset(&st, 0, sizeof st);
        st.kind = D2K_EV_STATS;
        st.dropped = 3;
        d2k_sched_event(s, &st);
        skip_ahead(s, 6000); /* перешагнуть потолок ожидания применения */
        settle(s);
        CHECK(said("молчание не в счёт"),
              "потери событий не учтены — молчание засчитано как улика против кандидата");
        CHECK(ver_calls == 2, "кандидат не испытан повторно, хотя связь теряла события");
        CHECK(last_plan_id(second_attempt_id), "second trial identity captured from wire");
        CHECK(memcmp(first_attempt_id, second_attempt_id, sizeof first_attempt_id) != 0,
              "retry of the same plan must not inherit the previous trial identity");
        CHECK(total_bindings(&c9) == 0, "потеря событий записана как успех");
        d2k_ev delayed = ev_applied(6, 40070);
        memcpy(delayed.plan_id, first_attempt_id, sizeof delayed.plan_id);
        d2k_sched_event(s, &delayed);
        spin(s, 20);
        CHECK(total_bindings(&c9) == 0,
              "late APPLIED from previous trial cannot confirm reused tuple and plan");

        /* А когда потерь больше нет — кандидат честно сменяется, и поиск
           доходит до конца очереди сам. */
        run_out(s);
        CHECK(total_bindings(&c9) == 0,
              "зонд прошёл, а применения не было — записано как успех");
        CHECK(d2k_sched_active(s) == 0,
              "без потерь связи кандидат так и не сменился — поиск встал");
        d2k_sched_free(s);
        d2k_catalog_free(&c9);
    }

    /* --- отказ отправки: временный лечится повтором, постоянный — нет ---
     *
     * 0009, U2. Четыре утверждения в одном сценарии, потому что все четыре про
     * одно: НАША неудача не имеет права стать свойством чужого устройства и не
     * имеет права съесть поиск.
     *
     *   чужой отказ (не наш идентификатор плана) не трогает кандидата;
     *   временный отказ даёт ПОВТОР того же кандидата, а не выброс;
     *   повторов ограниченное число, а не «пока не кончится бюджет»;
     *   постоянный отказ (посылка длиннее канала) не повторяется вовсе,
     *     кандидат сменяется, и «рабочего обхода нет» никто не объявляет. */
    {
        d2k_catalog cu;
        memset(&cu, 0, sizeof cu);
        d2k_sched *s = d2k_sched_new(&cu, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = 40077;
        ver_calls = 0;
        d2k_ev h = ev_hello(6, 40077, "отказная.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40077);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(ver_calls == 1, "кандидат не испытан");

        /* ЧУЖОЙ отказ: ключ наш, идентификатор плана — нет. */
        d2k_ev alien = ev_refused(6, 40077, D2K_REFUSE_SEND, 0);
        d2k_sched_event(s, &alien);
        skip_ahead(s, 6000);
        settle(s);
        CHECK(!said("посылка плана не ушла на провод"),
              "чужой отказ приписан нашему кандидату");

        CHECK(total_bindings(&cu) == 0, "чужой отказ записан как успех");
        d2k_sched_free(s);
        d2k_catalog_free(&cu);
    }

    {
        /* СВОЙ временный отказ — повтор ТОГО ЖЕ кандидата. Отдельный
           планировщик: проверка выше уже израсходовала своё окно ожидания,
           и слать сюда второй отказ было бы некому. */
        d2k_catalog ct;
        memset(&ct, 0, sizeof ct);
        d2k_sched *s = d2k_sched_new(&ct, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = 40079;
        ver_calls = 0;
        d2k_ev h = ev_hello(6, 40079, "временная.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40079);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(ver_calls == 1, "кандидат не испытан");

        int before = ver_calls;
        d2k_ev tmp = ev_refused(6, 40079, D2K_REFUSE_QUEUE, 1);
        d2k_sched_event(s, &tmp);
        skip_ahead(s, 6000);
        settle(s);
        CHECK(said("посылка плана не ушла на провод"),
              "временный отказ отправки не назван — он неотличим от промаха коробки");
        CHECK(ver_calls > before, "после временного отказа кандидат не переиспытан");
        CHECK(total_bindings(&ct) == 0, "отказ отправки записан как успех");
        d2k_sched_free(s);
        d2k_catalog_free(&ct);
    }

    {
        /* Постоянный отказ: повторять нечего, тот же план даст то же. */
        d2k_catalog cp;
        memset(&cp, 0, sizeof cp);
        d2k_sched *s = d2k_sched_new(&cp, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = 40078;
        ver_calls = 0;
        d2k_ev h = ev_hello(6, 40078, "длинная.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40078);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(ver_calls == 1, "кандидат не испытан");

        int before = ver_calls;
        d2k_ev big = ev_refused(6, 40078, D2K_REFUSE_TOO_LONG, 1);
        d2k_sched_event(s, &big);
        skip_ahead(s, 6000);
        settle(s);
        CHECK(said("опыт невозможен"),
              "постоянный отказ не назван причиной невозможности опыта");
        CHECK(!said("испытываю кандидата ещё раз"),
              "постоянный отказ лечится повтором — тот же план даст тот же результат");
        CHECK(ver_calls == before || ver_calls == before + 1,
              "постоянный отказ породил череду одинаковых повторов");
        CHECK(total_bindings(&cp) == 0, "отказ по длине записан как успех");
        d2k_sched_free(s);
        d2k_catalog_free(&cp);
    }

    /* --- запасной перебор: синтез не помог — поиск продолжается ---------
     *
     * 0007 п.3, 0008 п.7. Раньше очередь синтеза кончалась — и задача уходила
     * в отдых, хотя у донора после синтеза начинается перебор poisons(). При
     * пустом векторе синтез даёт РОВНО ОДИН план («всё сразу»), поэтому без
     * перебора испытание было бы ровно одно.
     *
     * Проверяем две вещи: испытаний стало больше одного (перебор подхватил) и
     * поиск всё равно КОНЧАЕТСЯ — общий бюджет зондов принадлежит
     * планировщику, а не длине списка. */
    {
        d2k_catalog cf;
        memset(&cf, 0, sizeof cf);
        d2k_sched *s = d2k_sched_new(&cf, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_TRANSPORT;   /* зонд не доходит до приложения: промах */
        ver_fail_first = 0;
        ver_answer_port = 40081;
        ver_calls = 0;
        d2k_ev h = ev_hello(6, 40081, "перебор.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40081);
        d2k_sched_event(s, &su);
        run_out(s);

        CHECK(ver_calls > 1,
              "после синтеза поиск встал — запасной перебор не подхватил");
        CHECK(d2k_sched_active(s) == 0,
              "запасной перебор не кончился — бюджет зондов не ограничил поиск");
        CHECK(total_bindings(&cf) == 0,
              "перебор записал привязку, хотя ни один зонд не дошёл до приложения");
        d2k_sched_free(s);
        d2k_catalog_free(&cf);
    }

    /* --- отказ отправки + ОБОРВАННЫЙ ЗОНД: кандидат не виноват -----------
     *
     * 0009, U2, пропущенный путь. Сочетание обычное: посылка плана не ушла,
     * значит воздействия не было, значит цель ответила ровно как без обхода —
     * зонд не доходит до приложения. Раньше этот путь шёл мимо разбора
     * unsent_code: код видел «зонд не дошёл» и выбрасывал кандидата из-за
     * НАШЕЙ неудачи. Проверки успешного TLS этого не ловили — там до ветки
     * с провалом зонда дело не доходит вовсе.
     *
     * Временный отказ обязан дать повтор ТОГО ЖЕ кандидата. */
    {
        d2k_catalog cw;
        memset(&cw, 0, sizeof cw);
        d2k_sched *s = d2k_sched_new(&cw, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_TRANSPORT;   /* зонд оборван: до приложения не дошёл */
        ver_fail_first = 0;
        ver_answer_port = 40091;
        ver_calls = 0;
        d2k_ev h = ev_hello(6, 40091, "оборванная.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40091);
        d2k_sched_event(s, &su);
        /* Кандидат обязан уже стоять: отказ относится к ЕГО посылке, и до
           установки приписывать его нечему. */
        spin_until_installed(s);
        /* Отказ приходит, пока задача ещё испытывает кандидата. */
        d2k_ev tmp = ev_refused(6, 40091, D2K_REFUSE_QUEUE, 1);
        d2k_sched_event(s, &tmp);
        settle(s);

        CHECK(said("посылка плана не ушла на провод"),
              "зонд оборван и посылка не ушла — отказ не разобран, наша неудача "
              "записана промахом кандидата");
        CHECK(ver_calls > 1, "кандидат не переиспытан после временного отказа");
        CHECK(total_bindings(&cw) == 0, "отказ отправки записан как успех");
        d2k_sched_free(s);
        d2k_catalog_free(&cw);
    }

    {
        /* Тот же путь, но отказ ПОСТОЯННЫЙ: повторять нечего, опыт невозможен,
           и кандидат всё равно не объявляется промахнувшимся. */
        d2k_catalog cx2;
        memset(&cx2, 0, sizeof cx2);
        d2k_sched *s = d2k_sched_new(&cx2, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_TRANSPORT;
        ver_fail_first = 0;
        ver_answer_port = 40092;
        ver_calls = 0;
        d2k_ev h = ev_hello(6, 40092, "длинная-оборванная.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40092);
        d2k_sched_event(s, &su);
        /* Кандидат обязан уже стоять: отказ относится к ЕГО посылке, и до
           установки приписывать его нечему. */
        spin_until_installed(s);
        d2k_ev big = ev_refused(6, 40092, D2K_REFUSE_TOO_LONG, 1);
        d2k_sched_event(s, &big);
        settle(s);

        CHECK(said("опыт невозможен"),
              "постоянный отказ на оборванном зонде не назван причиной невозможности опыта");
        /* Порядком, а не отсутствием: следующие кандидаты промахиваются
           законно — у них своего отказа не было, и «зонд не дошёл» про них
           правда. Проверяем, что ПЕРВЫЙ кандидат не обвинён: объяснение про
           невозможность опыта обязано прозвучать РАНЬШЕ первого промаха. */
        {
            const char *imp = strstr(saidbuf, "опыт невозможен");
            const char *miss = strstr(saidbuf, "зонд не дошёл до приложения");
            CHECK(imp && (!miss || imp < miss),
                  "наша неудача объявлена промахом зонда — кандидат обвинён не за что");
        }
        CHECK(total_bindings(&cx2) == 0, "отказ по длине записан как успех");
        d2k_sched_free(s);
        d2k_catalog_free(&cx2);
    }

    {
        /* ЗОНД НЕ ДОШЁЛ, А ПЛАНА НА ЕГО ПОТОКЕ НЕ БЫЛО — ЭТО НЕ УЛИКА.
         *
         * Поле 17.09.2026, живая линия, discord.com. Замер нашёл приём,
         * приём РАБОЧИЙ (проверено отдельно планом: 3/3 по 200), но
         * подтверждение дало «зонд не дошёл до приложения», кандидат был
         * выброшен, и цель осталась без обхода. Причина: испытание стартует
         * сразу после записи плана в управляющий сокет, и на живой линии
         * зонд успевает уйти РАНЬШЕ, чем датапат прочитал команду. План к его
         * потоку не применяется, зонд идёт голым и его режут.
         *
         * У соседней ветки дисциплина уже верная: зонд ПРОШЁЛ, а применения
         * не видно — «не засчитано». Здесь она была обратной: неудача без
         * применения засчитывалась против кандидата. Асимметрия и выбрасывала
         * рабочие планы. */
        d2k_catalog cz;
        memset(&cz, 0, sizeof cz);
        d2k_sched *s = d2k_sched_new(&cz, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_TRANSPORT;   /* зонд не дошёл до приложения */
        ver_fail_first = 0;
        ver_answer_port = 40097;
        ver_calls = 0;
        d2k_ev h = ev_hello(6, 40097, "голый-зонд.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40097);
        d2k_sched_event(s, &su);
        spin_until_installed(s);
        settle(s);

        CHECK(said("плана на его потоке не было"),
              "неудача зонда БЕЗ применения плана к его потоку засчитана уликой против "
              "плана: кандидат обвинён за опыт, которого не было");
        {
            /* И объяснение обязано прозвучать РАНЬШЕ смены кандидата: иначе
               «не измерено» появилось бы задним числом, после того как
               рабочий план уже выброшен. */
            const char *notmeas = strstr(saidbuf, "плана на его потоке не было");
            const char *next = strstr(saidbuf, "беру следующего кандидата");
            CHECK(notmeas && (!next || notmeas < next),
                  "кандидат сменён раньше, чем сказано, что опыта не было");
        }
        d2k_sched_free(s);
        d2k_catalog_free(&cz);
    }

    {
        /* ЧУЖОЙ ранний отказ на том же потоке не должен трогать кандидата:
           зонд оборван по своей причине, и объяснение обязано остаться про
           зонд, а не про нашу отправку. */
        d2k_catalog cy;
        memset(&cy, 0, sizeof cy);
        d2k_sched *s = d2k_sched_new(&cy, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_TRANSPORT;
        ver_fail_first = 0;
        ver_answer_port = 40093;
        ver_calls = 0;
        d2k_ev h = ev_hello(6, 40093, "чужой-отказ.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40093);
        d2k_sched_event(s, &su);
        /* Кандидат обязан уже стоять: отказ относится к ЕГО посылке, и до
           установки приписывать его нечему. */
        spin_until_installed(s);
        d2k_ev alien = ev_refused(6, 40093, D2K_REFUSE_SEND, 0);
        d2k_sched_event(s, &alien);
        settle(s);

        CHECK(!said("посылка плана не ушла на провод"),
              "чужой отказ приписан нашему кандидату");
        CHECK(said("зонд не дошёл до приложения"),
              "объяснение промаха подменено чужим отказом");
        CHECK(total_bindings(&cy) == 0, "чужой отказ записан как успех");
        d2k_sched_free(s);
        d2k_catalog_free(&cy);
    }

    /* --- ЧУЖОЙ ОТКАЗ С НАШИМ ПЛАНОМ (0009, U2-R1) ----------------------
     *
     * Доказано стендом ревью, не предположение. Один пробный план действует на
     * ВСЕ подключения к этой цели, поэтому отказ соседнего клиента совпадает
     * с нашим по цели, транспорту и идентификатору плана — а отказом НАШЕГО
     * зонда при этом не является. Местный порт зонда до его возврата не знает
     * никто: ядро назначает его при обращении.
     *
     * Раньше такой отказ съедался как свой и без нужды переиспытывал
     * кандидата; при постоянном коде объявил бы опыт невозможным там, где он
     * состоялся. */
    {
        d2k_catalog cr;
        memset(&cr, 0, sizeof cr);
        d2k_sched *s = d2k_sched_new(&cr, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_TRANSPORT;
        ver_fail_first = 0;
        ver_answer_port = 40091;   /* местный порт НАШЕГО зонда */
        ver_calls = 0;
        d2k_ev h = ev_hello(6, 40091, "чужой-порт.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40091);
        d2k_sched_event(s, &su);
        spin_until_installed(s);

        /* Цель и идентификатор плана НАШИ, клиентский порт ДРУГОЙ. */
        d2k_ev alien = ev_refused(6, 49999, D2K_REFUSE_QUEUE, 1);
        d2k_sched_event(s, &alien);
        settle(s);

        CHECK(!said("посылка плана не ушла на провод"),
              "отказ ЧУЖОГО соединения с тем же планом съеден как свой — "
              "кандидат переиспытан без причины");
        CHECK(said("зонд не дошёл до приложения"),
              "объяснение промаха подменено чужим отказом");
        CHECK(total_bindings(&cr) == 0, "чужой отказ записан как успех");
        d2k_sched_free(s);
        d2k_catalog_free(&cr);
    }

    /* --- дата подтверждения — стенная, а не монотонная ------------------ */
    {
        /* Внутри планировщик считает МОНОТОННЫМИ миллисекундами, и это верно:
           стенные часы на роутере прыгают при синхронизации времени, а сроки
           от этого прыгать не должны. Но каталог читает человек и панель.
           Живая приёмка 12.09.2026 показала, чем это кончается: у всех новых
           подтверждений в файле стояло «1970-01-01T04:14:39Z» — монотонные
           миллисекунды, записанные как секунды эпохи. */
        d2k_catalog cC;
        memset(&cC, 0, sizeof cC);
        ver_answer = D2K_VER_APPLICATION;
        tcp_answer = D2K_V_PREFIX;
        confirm_once(&cC, sv[0], "часы.цель", 40120);

        const d2k_cat_binding *bd = binding_of(&cC, "часы.цель", 6);
        CHECK(bd != NULL, "часы: привязка не записана");
        /* Живая приёмка 12.09.2026 поймала ВТОРУЮ половину той же ошибки:
           CLOCK_MONOTONIC на Linux отсчитывается от ЗАГРУЗКИ, и привязка,
           снятая своим вызовом часов при заведении планировщика, считала
           уптайм дважды — запись легла временем 05:16Z при настоящих 00:43Z,
           ровно на 4,5 часа работы роутера вперёд. Здесь роутер «уже работает»
           четыре часа: часы приходят аргументом, как в проде. */
        g_now_ms += 4 * 60 * 60 * 1000;
        d2k_catalog cD;
        memset(&cD, 0, sizeof cD);
        confirm_once(&cD, sv[0], "часы.уптайм", 40121);
        const d2k_cat_binding *bu = binding_of(&cD, "часы.уптайм", 6);
        CHECK(bu != NULL, "часы: привязка при ненулевом уптайме не записана");
        if (bu) {
            int64_t now = (int64_t)time(NULL);
            int64_t off = bu->confirmed - now;
            if (off < 0) { off = -off; }
            CHECK(off < 120,
                  "дата подтверждения разошлась с настоящей больше чем на две "
                  "минуты — уптайм посчитан дважды");
        }
        d2k_catalog_free(&cD);
        if (bd) {
            /* 2026-01-01 в секундах эпохи. Всё, что меньше, — это не дата, а
               время с загрузки, попавшее в файл как дата. */
            CHECK(bd->confirmed > 1767225600,
                  "дата подтверждения меньше 2026 года — в каталог уехали "
                  "монотонные часы вместо стенных");
        }
        d2k_catalog_free(&cC);
    }

    /* --- сначала донорская классификация, объём — только после CLEAR (задача 30) */
    {
        /* Поле 02.10.2026: обычный TCP-поиск начинался с объёмного замера и
           для цели, режущейся на рукопожатии, ждал таймаута «нет TLS». Донор
           (z2k «Поиск по домену») сразу задаёт вопросы классификатора; объём
           — отдельный вопрос, осмысленный лишь когда рукопожатие и запись
           проходят. */
        d2k_catalog cH = {0};
        d2k_sched *s = d2k_sched_new(&cH, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        vol_calls = tcp_calls = 0;
        vol_answer = D2K_VOL_UNREACHABLE; vol_rx_tls_unavailable = 1; vol_rx_cut = 0;
        tcp_answer = D2K_V_OPAQUE;
        ver_answer = D2K_VER_NOT_MEASURED;
        forget_sent();
        d2k_ev h = ev_hello(6, 40090, "рукопожатие.режут");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40090);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(tcp_calls == 1, "заблокированная на рукопожатии цель не прошла классификацию");
        CHECK(vol_calls == 0,
              "объёмный замер запущен при вердикте классификатора, не равном CLEAR");
        CHECK(!said("подбор и применение обхода не запускаю"),
              "блок на рукопожатии не повёл к подбору");
        d2k_sched_free(s); d2k_catalog_free(&cH);
        vol_answer = D2K_VOL_PASSED; vol_rx_tls_unavailable = 0;
    }
    {
        /* CLEAR без обрыва объёма — прямой путь, подбор не запускается. */
        d2k_catalog cP = {0};
        d2k_sched *s = d2k_sched_new(&cP, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        vol_calls = tcp_calls = 0;
        vol_answer = D2K_VOL_PASSED; vol_rx_cut = 0;
        tcp_answer = D2K_V_CLEAR;
        forget_sent();
        d2k_ev h = ev_hello(6, 40091, "напрямую.проходит");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40091);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(tcp_calls == 1 && vol_calls == 1,
              "CLEAR классификатора не дополнен объёмным замером");
        CHECK(said("напрямую проходит") && total_bindings(&cP) == 0,
              "CLEAR без обрыва объёма не остался прямым путём");
        d2k_sched_free(s); d2k_catalog_free(&cP);
        tcp_answer = D2K_V_OPAQUE;
    }
    {
        const int other_shape = 0;
        /* Снимок клиента пришёл, пока шла классификация: повтор поиска его
           байтами (та же форма и длина, что у заготовки) не гоняет объём
           второй раз. Другая форма здесь объёма не застаёт: устаревший
           прогон останавливается до объёмного замера — разная форма
           проверяется ниже, после подтверждения. */
        d2k_catalog cR = {0};
        d2k_sched *s = d2k_sched_new(&cR, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        vol_calls = tcp_calls = 0;
        vol_answer = D2K_VOL_CUT; vol_rx_cut = 0;
        tcp_answer = D2K_V_CLEAR;
        ver_answer = D2K_VER_NOT_MEASURED;
        tcp_last_wire = 0;
        forget_sent();
        snapshot_enabled = 1; snapshot_entered = snapshot_release = snapshot_ok = 0;
        d2k_ev h = ev_hello(6, (uint16_t)(40092 + other_shape),
                            other_shape ? "объём.другая.форма" : "объём.без.повтора");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, (uint16_t)(40092 + other_shape));
        d2k_sched_event(s, &su);
        int entered = 0;
        for (int i = 0; i < 3000 && !entered; i++) {
            tick_once(s);
            pthread_mutex_lock(&snapshot_mu);
            entered = snapshot_entered;
            pthread_mutex_unlock(&snapshot_mu);
        }
        CHECK(entered, "классификатор не позван первым — объём шёл до вопросов донора");
        size_t template_wire = tcp_last_wire;
        d2k_ev sh;
        CHECK(tls_shape_event(&sh, h.name, other_shape ? D2K_SHAPE_LEGACY : D2K_SHAPE_MODERN) == 0,
              "snapshot fixture failed");
        CHECK(other_shape || sh.shape_len == template_wire,
              "предпосылка: снимок TLS 1.3 должен совпасть с заготовкой по длине");
        d2k_sched_event(s, &sh);
        pthread_mutex_lock(&snapshot_mu);
        snapshot_release = 1; pthread_cond_broadcast(&snapshot_cv);
        pthread_mutex_unlock(&snapshot_mu);
        settle(s);
        CHECK(tcp_calls == 2, "снимок клиента не повторил классификацию его байтами");
        CHECK(other_shape || vol_calls == 1,
              "повтор снимком того же входа заново прогнал объёмный замер");
        CHECK(said("исходящая лестница оборвалась"),
              "повтор снимком потерял обрыв объёмного замера");
        if (tcp_calls != 2 || vol_calls != 1) fprintf(stderr, "%s\n", saidbuf);
        d2k_sched_free(s); d2k_catalog_free(&cR);
        snapshot_enabled = 0;
        vol_answer = D2K_VOL_PASSED; tcp_answer = D2K_V_OPAQUE;
    }
    for (int other_shape = 0; other_shape < 2; other_shape++) {
        /* Подтверждено заготовкой TLS 1.3 после обрыва объёма; затем пришёл
           снимок клиента, и поиск повторяется его байтами. Тот же вход
           (TLS 1.3, та же длина) берёт выполненный замер; снимок TLS 1.2 —
           другая версия, обрыв заготовки ему не улика: объём мерится заново
           (после CLEAR классификатора). */
        d2k_catalog cW = {0};
        d2k_sched *s = d2k_sched_new(&cW, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        vol_calls = tcp_calls = ver_calls = 0;
        vol_answer = D2K_VOL_CUT; vol_rx_cut = 0;
        tcp_answer = D2K_V_CLEAR; tcp_last_wire = 0;
        ver_answer = D2K_VER_APPLICATION; ver_fail_first = 0;
        uint16_t port = (uint16_t)(40095 + other_shape);
        ver_answer_port = port;
        forget_sent();
        d2k_ev h = ev_hello(6, port, other_shape ? "объём.tls12.снимок" : "объём.tls13.снимок");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, port);
        d2k_sched_event(s, &su);
        int installed = 0;
        for (int i = 0; i < 2000 && !total_bindings(&cW); i++) {
            tick_once(s);
            int n = (int)sent_command_count(D2K_CMD_SET_NAME_PROBE, NULL, 0);
            if (n > installed) {
                installed = n;
                d2k_ev ap = ev_applied(6, port);
                d2k_sched_event(s, &ap);
            }
        }
        spin(s, 40);
        CHECK(total_bindings(&cW) == 1 && vol_calls == 1 && tcp_calls == 1,
              "предпосылка: объёмный обрыв заготовкой не подтвердился");
        size_t template_wire = tcp_last_wire;
        d2k_ev sh;
        CHECK(tls_shape_event(&sh, h.name, other_shape ? D2K_SHAPE_LEGACY : D2K_SHAPE_MODERN) == 0,
              "snapshot fixture failed");
        CHECK(other_shape || sh.shape_len == template_wire,
              "предпосылка: снимок TLS 1.3 должен совпасть с заготовкой по длине");
        d2k_sched_event(s, &sh);
        installed = (int)sent_command_count(D2K_CMD_SET_NAME_PROBE, NULL, 0);
        for (int i = 0; i < 2000 && tcp_calls < 2; i++) tick_once(s);
        settle(s);
        CHECK(tcp_calls == 2, "снимок после подтверждения не повторил классификацию");
        CHECK(other_shape || vol_calls == 1,
              "повтор снимком того же входа заново прогнал объёмный замер");
        CHECK(!other_shape || vol_calls == 2,
              "обрыв, измеренный приветствием другой версии TLS, приложен к снимку");
        if (tcp_calls != 2 || vol_calls != 1 + other_shape)
            fprintf(stderr, "shape=%d tcp=%d vol=%d\n%s\n", other_shape, tcp_calls, vol_calls, saidbuf);
        d2k_sched_free(s); d2k_catalog_free(&cW);
        vol_answer = D2K_VOL_PASSED; tcp_answer = D2K_V_OPAQUE;
    }
    {
        /* OPAQUE: прямое рукопожатие не прошло, объём не мерился, флаг
           «TLS недоступен» выведен из вердикта и открывает послойную
           RX-проверку под кандидатом. Если под кандидатом TLS доходит и
           identity-тело приходит целиком, это обычное подтверждение —
           без RX-лестницы и без RX-улики. */
        d2k_catalog cO2 = {0};
        d2k_sched *s = d2k_sched_new(&cO2, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        vol_calls = tcp_calls = ver_calls = 0;
        tcp_answer = D2K_V_OPAQUE; vol_rx_cut = 0;
        ver_answer = D2K_VER_APPLICATION; ver_answer_port = 40094; ver_fail_first = 0;
        layered_identity_calls = layered_gzip_calls = 0;
        d2k_sched_rx_ver_hook = stub_rx_counting;
        forget_sent();
        d2k_ev h = ev_hello(6, 40094, "opaque.tls.reachable"), sh;
        d2k_sched_event(s, &h);
        CHECK(tls_shape_event(&sh, h.name, D2K_SHAPE_MODERN) == 0, "OPAQUE shape fixture");
        d2k_sched_event(s, &sh);
        d2k_ev su = ev_suspect(6, 40094);
        d2k_sched_event(s, &su);
        int installed = 0;
        for (int i = 0; i < 2000 && !total_bindings(&cO2); i++) {
            tick_once(s);
            int n = (int)sent_command_count(D2K_CMD_SET_NAME_PROBE, NULL, 0);
            if (n > installed) {
                installed = n;
                d2k_ev ap = ev_applied(6, 40094);
                d2k_sched_event(s, &ap);
            }
        }
        CHECK(vol_calls == 0 && tcp_calls == 1, "OPAQUE: объём мерился после блока рукопожатия");
        CHECK(layered_identity_calls >= 1, "OPAQUE: послойная RX-проверка под кандидатом не открыта");
        CHECK(total_bindings(&cO2) == 1 && layered_gzip_calls == 0 &&
              !sent_contains_plan_payload("hcaptcha.com"),
              "OPAQUE с доступным TLS под кандидатом не подтвердился обычным путём");
        if (total_bindings(&cO2) != 1) fprintf(stderr, "%s\n", saidbuf);
        d2k_sched_free(s); d2k_catalog_free(&cO2);
        d2k_sched_rx_ver_hook = stub_ver;
    }

    /* --- TX-volume не открывает RX-volume-лестницу ---------------------- */
    {
        /* Один только обрыв исходящей лестницы не эквивалентен подтверждённому
           срезу входящего ответа. Специальная fake-SNI/split-лестница не
           должна попадать в очередь по этому другому профилю. */
        d2k_catalog cA;
        memset(&cA, 0, sizeof cA);
        d2k_sched *s = d2k_sched_new(&cA, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        vol_calls = tcp_calls = 0;
        vol_answer = D2K_VOL_CUT;
        /* Объём мерится после CLEAR донорского классификатора (задача 30). */
        tcp_answer = D2K_V_CLEAR;
        ver_answer = D2K_VER_NOT_MEASURED;
        ver_calls = 0;
        forget_sent();

        d2k_ev h = ev_hello(6, 40080, "режут.по.объёму");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40080);
        d2k_sched_event(s, &su);
        settle(s);

        CHECK(vol_calls == 1, "проба на объём не вызвана");
        CHECK(tcp_calls == 1,
              "объём измерен без предшествующей донорской классификации");
        CHECK(!sent_contains_plan_ascii("68636170746368612e636f6d"),
              "TX-volume ошибочно запустил профильную RX fake-SNI-лестницу");
        CHECK(total_bindings(&cA) == 0, "обрыв по объёму записан в каталог");
        CHECK(said("исходящая лестница оборвалась"), "TX-volume не назван в отчёте");
        vol_answer = D2K_VOL_PASSED;
        tcp_answer = D2K_V_OPAQUE;
        vol_rx_cut = 0;
        d2k_sched_free(s);
        d2k_catalog_free(&cA);
    }

    /* --- объёмные коробки не сливаются по одному плану (задача 23) ------ */
    {
        /* Две цели режутся по объёму на РАЗНЫХ порогах (16 и 128 КБ), и обе
           берёт один и тот же план. Это две разные измеренные коробки (§5:
           не сливать разные случаи из-за одного плана): у каждой свой
           отпечаток в каталоге. Третья цель с обрывом около 16 КБ узнаёт
           коробку A и сначала проверяет её сохранённый план. */
        d2k_catalog cV;
        memset(&cV, 0, sizeof cV);
        vol_answer = D2K_VOL_CUT;
        tcp_answer = D2K_V_CLEAR; /* рукопожатие проходит — объём мерится (задача 30) */
        ver_answer = D2K_VER_APPLICATION;
        vol_at_kb = 16;
        confirm_once(&cV, sv[0], "a.vol-16.test", 40610);
        vol_at_kb = 128;
        confirm_once(&cV, sv[0], "b.vol-128.test", 40611);

        const d2k_cat_box *ba = NULL, *bb = NULL;
        for (size_t i = 0; i < cV.n_boxes; i++) {
            for (size_t j = 0; j < cV.boxes[i].n_binds; j++) {
                if (!strcmp(cV.boxes[i].binds[j].target, "a.vol-16.test")) ba = &cV.boxes[i];
                if (!strcmp(cV.boxes[i].binds[j].target, "b.vol-128.test")) bb = &cV.boxes[i];
            }
        }
        CHECK(ba && bb, "объёмные цели не записаны в каталог");
        CHECK(ba && bb && ba != bb,
              "коробки с обрывом 16 и 128 КБ слиты в одну по общему плану");
        CHECK(ba && bb && ba->n_plans == 1 && bb->n_plans == 1 &&
              ba->plans[0].text && bb->plans[0].text &&
              !strcmp(ba->plans[0].text, bb->plans[0].text),
              "предпосылка теста: обе коробки должны взять один и тот же план");
        int va = -1, vb = -1;
        for (size_t i = 0; ba && i < ba->fp.n_sig; i++)
            if (!strcmp(ba->fp.sig[i].kind, "volume")) va = ba->fp.sig[i].volume;
        for (size_t i = 0; bb && i < bb->fp.n_sig; i++)
            if (!strcmp(bb->fp.sig[i].kind, "volume")) vb = bb->fp.sig[i].volume;
        CHECK(va == 16, "у коробки A не сохранён отпечаток обрыва 16 КБ");
        CHECK(vb == 128, "у коробки B не сохранён свой отпечаток обрыва 128 КБ");

        char ida[sizeof ba->id] = {0};
        if (ba) snprintf(ida, sizeof ida, "%s", ba->id);
        saidbuf[0] = '\0';
        vol_at_kb = 17;
        confirm_once(&cV, sv[0], "c.vol-17.test", 40612);
        char want[160];
        snprintf(want, sizeof want, "совпал с коробкой %s", ida);
        CHECK(ida[0] && said(want),
              "цель с обрывом ~16 КБ не начала с планов коробки A");
        const d2k_cat_box *bc = NULL;
        for (size_t i = 0; i < cV.n_boxes; i++)
            for (size_t j = 0; j < cV.boxes[i].n_binds; j++)
                if (!strcmp(cV.boxes[i].binds[j].target, "c.vol-17.test")) bc = &cV.boxes[i];
        CHECK(bc && !strcmp(bc->id, ida), "цель ~16 КБ записана не в коробку A");
        if (!(ba && bb && ba != bb) || !said(want)) fprintf(stderr, "%s\n", saidbuf);

        /* Та же корзина [16, 32), но порог за допуском (30 КБ против 16):
           имя по хешу совпало бы с коробкой A, однако её отпечаток с этим
           противоречит — заводится отдельная коробка, A не трогается. */
        vol_at_kb = 30;
        confirm_once(&cV, sv[0], "d.vol-30.test", 40613);
        const d2k_cat_box *bd30 = NULL, *ba2 = NULL;
        for (size_t i = 0; i < cV.n_boxes; i++) {
            if (!strcmp(cV.boxes[i].id, ida)) ba2 = &cV.boxes[i];
            for (size_t j = 0; j < cV.boxes[i].n_binds; j++)
                if (!strcmp(cV.boxes[i].binds[j].target, "d.vol-30.test")) bd30 = &cV.boxes[i];
        }
        CHECK(bd30 && strcmp(bd30->id, ida) != 0,
              "обрыв 30 КБ слит с коробкой 16 КБ из-за общей корзины и плана");
        int vd = -1, va2 = -1;
        for (size_t i = 0; bd30 && i < bd30->fp.n_sig; i++)
            if (!strcmp(bd30->fp.sig[i].kind, "volume")) vd = bd30->fp.sig[i].volume;
        for (size_t i = 0; ba2 && i < ba2->fp.n_sig; i++)
            if (!strcmp(ba2->fp.sig[i].kind, "volume")) va2 = ba2->fp.sig[i].volume;
        CHECK(vd == 30, "у коробки 30 КБ не сохранён свой отпечаток");
        CHECK(va2 == 16, "отпечаток коробки A переписан чужой приметой");

        vol_at_kb = 20;
        vol_answer = D2K_VOL_PASSED;
        d2k_catalog_free(&cV);
    }

    /* --- очерёдность сохранённых планов идёт по корзине порога ---------- */
    {
        /* Обрыв 19 КБ совместим по допуску с обеими коробками: X (15 КБ,
           корзина [8,16)) и Y (21 КБ, корзина [16,32)). У X больше успехов,
           но ближайшая модель — Y той же корзины: её план проверяется первым. */
        d2k_catalog cO;
        memset(&cO, 0, sizeof cO);
        cO.boxes = calloc(2, sizeof *cO.boxes);
        CHECK(cO.boxes != NULL, "не удалось создать коробки очерёдности");
        int ready = cO.boxes != NULL;
        for (unsigned bi = 0; ready && bi < 2; bi++) {
            d2k_cat_box *b = &cO.boxes[bi];
            cO.n_boxes++;
            snprintf(b->id, sizeof b->id, bi == 0 ? "box-vol-x15" : "box-vol-y21");
            b->fp.method = D2K_FP_METHOD;
            b->fp.n_sig = 1;
            snprintf(b->fp.sig[0].kind, sizeof b->fp.sig[0].kind, "volume");
            b->fp.sig[0].volume = bi == 0 ? 15 : 21;
            b->fp.sig[0].seen = 1;
            b->plans = calloc(1, sizeof *b->plans);
            if (!b->plans) { ready = 0; break; }
            b->n_plans = 1;
            b->plans[0].enabled = 1;
            b->plans[0].successes = bi == 0 ? 9 : 1;
            snprintf(b->plans[0].proto, sizeof b->plans[0].proto, "tls");
            char plan[256];
            snprintf(plan, sizeof plan,
                     "d2k-plan 1 1\nid 00000000000000000000000000000000\n"
                     "proto tcp tls\nsplit payload_start +%u\norder forward\n", 31 + bi);
            b->plans[0].text = strdup(plan);
            if (!b->plans[0].text) { ready = 0; }
        }
        CHECK(ready, "не удалось подготовить планы очерёдности");
        if (ready) {
            saidbuf[0] = '\0';
            vol_answer = D2K_VOL_CUT;
            tcp_answer = D2K_V_CLEAR;
            ver_answer = D2K_VER_APPLICATION;
            vol_at_kb = 19;
            confirm_once(&cO, sv[0], "e.vol-19.test", 40614);
            CHECK(said("совпал с коробкой box-vol-y21"),
                  "обрыв 19 КБ начал не с коробки своей корзины порога");
            if (!said("совпал с коробкой box-vol-y21")) fprintf(stderr, "%s\n", saidbuf);
        }
        vol_at_kb = 20;
        vol_answer = D2K_VOL_PASSED;
        tcp_answer = D2K_V_PREFIX; /* прежнее состояние для следующих проверок */
        d2k_catalog_free(&cO);
    }

rx_volume_tests:
    /* A hint never launches its target. A subsequent live public TLS target
       measures and verifies the same resource, then persists its witness. */
    {
        d2k_catalog c = {0};
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        saidbuf[0] = 0; forget_sent(); d2k_sched_set_say(s, collect_say, NULL);
        resource_fixture = 1; vol_rx_cut = 0; vol_answer = D2K_VOL_PASSED;
        tcp_answer = D2K_V_CLEAR; tcp_calls = 0;
        d2k_ev parent = ev_hello(6, 40381, "parent.example");
        d2k_sched_event(s, &parent);
        d2k_ev su = ev_suspect(6, 40381); d2k_sched_event(s, &su);
        settle(s);
        CHECK(tcp_calls == 1 && total_bindings(&c) == 0,
              "CSS hint invented a target or confirmed an unrelated bypass");
        resource_fixture = 0;
        uint16_t saved = g_server_port; g_server_port = 443;
        d2k_sched_vol_path_hook = stub_resource_volume;
        d2k_sched_path_ver_hook = stub_resource_verify;
        resource_volume_calls = resource_verify_calls = 0;
        ver_calls = 0; ver_fail_first = 0;
        ver_answer = D2K_VER_APPLICATION; ver_answer_port = 40382;
        d2k_ev h = ev_hello(6, 40382, "assets.example"), sh;
        inet_pton(AF_INET, "8.8.8.8", h.low_ip);
        d2k_sched_event(s, &h);
        CHECK(tls_shape_event(&sh, h.name, D2K_SHAPE_MODERN) == 0, "CSS task TLS fixture");
        d2k_sched_event(s, &sh);
        su = h; su.kind = D2K_EV_SUSPECT; su.code = D2K_SUSPECT_FIN_RETRY;
        d2k_sched_event(s, &su);
        size_t installed = 0;
        for (int i = 0; i < 2000 && !total_bindings(&c); i++) {
            tick_once(s);
            size_t n = sent_command_count(D2K_CMD_SET_NAME_PROBE, NULL, 0);
            if (n > installed) {
                installed = n;
                d2k_ev ap = ev_applied(6, 40382);
                memcpy(ap.low_ip, h.low_ip, 4);
                d2k_sched_event(s, &ap);
            }
        }
        CHECK(resource_volume_calls == 1 && resource_verify_calls >= 1,
              "public resource measured/verifier silently reverted to /");
        CHECK(total_bindings(&c) == 1 &&
              !strcmp(c.boxes[0].binds[0].probe_path, "/public/app.min.css"),
              "confirmed resource witness lost on binding");
        d2k_sched_free(s); d2k_catalog_free(&c); g_server_port = saved;
        d2k_sched_vol_path_hook = d2k_volume_probe_path;
        d2k_sched_path_ver_hook = d2k_verify_probe_path_on;
        vol_rx_cut = 0;
    }
    /* Задача 39, раунд 2: сохранённый путь подтверждённой QUIC-привязки
       читается обратно, когда HTML-подсказки TCP уже нет (новый
       планировщик — как после перезапуска). Ключ формы у QUIC-привязки —
       D2K_LINK_SHAPE_QUIC, не форма TLS-приветствия. Путь идёт и в этап
       данных плеча, и в проверку плана; в ключ семейства QUIC он не входит. */
    {
        d2k_catalog c = {0};
        uint16_t saved = g_server_port; g_server_port = 443;
        static const char *names[3] = {"a1.cdn-qres.com", "b1.cdn-qres.com", "c1.cdn-qres.com"};
        quic_answer = D2K_V_OPAQUE; arm_kind = D2K_QA_BLOB;
        ver_answer = D2K_VER_APPLICATION; ver_fail_first = 0;
        /* 1. Подтверждаем QUIC-привязки на публичном адресе (подсказки нет — «/»). */
        for (int n = 0; n < 3; n++) {
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            d2k_sched_set_say(s, collect_say, NULL);
            uint16_t cport = (uint16_t)(41700 + n);
            ver_answer_port = cport; forget_sent();
            d2k_ev h = ev_hello(17, cport, names[n]);
            inet_pton(AF_INET, "8.8.8.8", h.low_ip);
            d2k_sched_event(s, &h);
            d2k_ev sh; CHECK(quic_shape(&sh, names[n]) == 0, "QUIC shape fixture");
            d2k_sched_event(s, &sh);
            d2k_ev su = ev_suspect(17, cport); memcpy(su.low_ip, h.low_ip, 4);
            d2k_sched_event(s, &su);
            settle(s);
            d2k_ev ap = ev_applied(17, cport); memcpy(ap.low_ip, h.low_ip, 4);
            d2k_sched_event(s, &ap);
            spin(s, 40);
            d2k_sched_free(s);
        }
        const d2k_cat_binding *qb = binding_of(&c, names[0], 17);
        CHECK(qb && qb->shape == D2K_LINK_SHAPE_QUIC, "QUIC binding fixture confirmed");
        /* 2. Сохранённый свидетель-ресурс на привязках, подсказок нет. */
        for (size_t i = 0; i < c.n_boxes; i++)
            for (size_t j = 0; j < c.boxes[i].n_binds; j++)
                if (c.boxes[i].binds[j].transport == 17)
                    snprintf(c.boxes[i].binds[j].probe_path,
                             sizeof c.boxes[i].binds[j].probe_path, "/static/app.css");
        for (int n = 0; n < 3; n++) {
            quic_last_path[0] = 0; quic_path_ver_calls = 0; quic_path_ver_last[0] = 0;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = 0; d2k_sched_set_say(s, collect_say, NULL);
            uint16_t cport = (uint16_t)(41710 + n);
            ver_answer_port = cport; forget_sent();
            d2k_ev h = ev_hello(17, cport, names[n]);
            inet_pton(AF_INET, "8.8.8.8", h.low_ip);
            d2k_sched_event(s, &h);
            d2k_ev sh; CHECK(quic_shape(&sh, names[n]) == 0, "QUIC shape fixture");
            d2k_sched_event(s, &sh);
            d2k_ev su = ev_suspect(17, cport); memcpy(su.low_ip, h.low_ip, 4);
            su.planned = D2K_LINK_PLANNED_NO;
            d2k_sched_event(s, &su);
            settle(s);
            d2k_ev ap = ev_applied(17, cport); memcpy(ap.low_ip, h.low_ip, 4);
            d2k_sched_event(s, &ap);
            spin(s, 40);
            char want[160];
            snprintf(want, sizeof want, "по %s RX и кандидат проверяются по публичному stylesheet /static/app.css", names[n]);
            CHECK(said(want),
                  "confirmed QUIC binding path not read back after the hint is gone");
            CHECK(!strcmp(quic_last_path, "/static/app.css"),
                  "QUIC arm data stage did not receive the saved resource path");
            CHECK(quic_path_ver_calls > 0 && !strcmp(quic_path_ver_last, "/static/app.css"),
                  "QUIC plan verification did not go by the saved resource path");
            if (!said("публичному stylesheet /static/app.css")) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s);
        }
        /* 3. Ключ семейства QUIC — «/», путь-подсказка в него не входит. */
        d2k_group_key gk = {0}; gk.transport = 17; gk.family = 4; gk.shape = D2K_LINK_SHAPE_QUIC;
        strcpy(gk.probe_path, "/static/app.css");
        CHECK(c.groups && !d2k_group_match(c.groups, "d1.cdn-qres.com", &gk),
              "QUIC family key must not carry the resource path");
        strcpy(gk.probe_path, "/");
        CHECK(c.groups && d2k_group_match(c.groups, "d1.cdn-qres.com", &gk),
              "QUIC family learned with \"/\" despite the resource path (previous matching)");
        printf("QUIC resource path: binding read back, measure=%s, verify calls %d (%s)\n",
               quic_last_path, quic_path_ver_calls, quic_path_ver_last);
        d2k_catalog_free(&c); g_server_port = saved;
    }
    /* IPv4 success is only a candidate for IPv6. A failed native baseline
       checks it on an isolated native socket; own APPLIED and complete
       identity are required. Failure resumes the original classifier once. */
    for (int outcome = 0; outcome < 4; outcome++) {
        d2k_catalog c = {0};
        c.boxes = calloc(1, sizeof *c.boxes);
        CHECK(c.boxes != NULL, "family reuse fixture allocation");
        if (!c.boxes) continue;
        c.n_boxes = 1;
        d2k_cat_box *b = c.boxes;
        snprintf(b->id, sizeof b->id, "box-v4-only");
        b->plans = calloc(1, sizeof *b->plans);
        b->binds = calloc(1, sizeof *b->binds);
        CHECK(b->plans && b->binds, "family reuse plan fixture allocation");
        if (!b->plans || !b->binds) { d2k_catalog_free(&c); continue; }
        b->n_plans = b->n_binds = 1;
        snprintf(b->plans[0].id, sizeof b->plans[0].id, "own-v4-plan");
        snprintf(b->plans[0].proto, sizeof b->plans[0].proto, "tls");
        b->plans[0].enabled = 1;
        b->plans[0].text = strdup("d2k-plan 1 1\nid 00000000000000000000000000000000\n"
                                 "proto tcp tls\nsplit payload_start +2\norder forward\n");
        d2k_cat_binding *bd = b->binds;
        snprintf(bd->kind, sizeof bd->kind, "name");
        snprintf(bd->target, sizeof bd->target, "family-reuse.test");
        snprintf(bd->plan_id, sizeof bd->plan_id, "own-v4-plan");
        bd->enabled = 1; bd->level = 3; bd->transport = 6;
        bd->shape = D2K_SHAPE_MODERN; bd->family = 4;
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        saidbuf[0] = 0; forget_sent(); d2k_sched_set_say(s, collect_say, NULL);
        vol_calls = tcp_calls = ver_calls = 0;
        vol_answer = outcome == 3 ? D2K_VOL_PASSED : D2K_VOL_UNREACHABLE;
        vol_rx_tls_unavailable = outcome != 3; vol_rx_cut = 0;
        tcp_answer = outcome == 3 ? D2K_V_CLEAR : D2K_V_INCONCLUSIVE;
        ver_answer = outcome == 1 ? D2K_VER_HANDSHAKE : D2K_VER_APPLICATION;
        ver_answer_port = 40311; ver_fail_first = 0;
        d2k_sched_rx_ver_hook = stub_family_identity;
        d2k_ev h = ev_hello(6, 40311, "family-reuse.test"), sh;
        h.family = 6; h.low_port = 443;
        CHECK(inet_pton(AF_INET6, "::1", h.low_ip) == 1, "reuse destination fixture");
        CHECK(inet_pton(AF_INET6, "2001:db8::2", h.high_ip) == 1, "reuse client fixture");
        d2k_sched_event(s, &h);
        CHECK(tls_shape_event(&sh, h.name, D2K_SHAPE_MODERN) == 0, "reuse shape fixture");
        sh.family = 6; d2k_sched_event(s, &sh);
        d2k_ev su = h; su.kind = D2K_EV_SUSPECT; su.code = D2K_SUSPECT_REPEAT;
        d2k_sched_event(s, &su);
        size_t installed = 0;
        for (int i = 0; i < 2000; i++) {
            tick_once(s);
            size_t n = sent_command_count(D2K_CMD_SET_NAME_PROBE, NULL, 0);
            if (n > installed) {
                installed = n;
                d2k_ev ap = ev_applied(6, 40311); ap.family = 6;
                ap.low_port = h.low_port;
                memcpy(ap.low_ip, h.low_ip, 16); memcpy(ap.high_ip, h.high_ip, 16);
                if (outcome == 2) ap.plan_id[0] ^= 1;
                d2k_sched_event(s, &ap);
            }
            if ((outcome == 0 && total_bindings(&c) == 2) ||
                ((outcome == 1 || outcome == 3) && tcp_calls) ||
                (outcome == 2 && ver_calls >= 3)) break;
        }
        CHECK(vol_calls == 1, "family retry repeats baseline unnecessarily");
        if (total_bindings(&c) != (outcome == 0 ? 2u : 1u) ||
            tcp_calls != (outcome == 1 || outcome == 3 ? 1 : 0))
            fprintf(stderr, "family outcome=%d tcp=%d ver=%d\n%s\n", outcome, tcp_calls, ver_calls, saidbuf);
        CHECK(total_bindings(&c) == (outcome == 0 ? 2u : 1u),
              "family success borrowed without own native proof");
        CHECK(tcp_calls == (outcome == 1 || outcome == 3 ? 1 : 0),
              "family trial does not resume original search or bypasses healthy baseline");
        if (outcome == 0) {
            int native = 0;
            for (size_t bi = 0; bi < c.n_boxes; bi++)
                for (size_t i = 0; i < c.boxes[bi].n_binds; i++)
                    native += c.boxes[bi].binds[i].family == 6 && c.boxes[bi].binds[i].level >= 3;
            CHECK(native == 1 && ver_socket_family == AF_INET6, "reuse did not prove a separate IPv6 binding");
            CHECK(!strcmp(c.boxes[0].id, "box-v4-only") && c.boxes[0].n_binds == 1,
                  "unmeasured IPv6 fingerprint merged into IPv4 box");
        }
        d2k_sched_free(s); d2k_catalog_free(&c);
        d2k_sched_rx_ver_hook = stub_ver;
        vol_rx_tls_unavailable = 0; vol_answer = D2K_VOL_PASSED;
    }
    /* A bootstrap must not be saved merely because gzip completed. Only
       two own applied identity cuts plus actual gzip admit the RX ladder. */
    for (int bad = 0; bad < 6; bad++) {
        d2k_catalog c = {0};
        if (bad >= 4) {
            c.boxes = calloc(1, sizeof *c.boxes);
            CHECK(c.boxes != NULL, "late bootstrap box allocation failed");
            if (!c.boxes) continue;
            c.n_boxes = 1;
            d2k_cat_box *b = c.boxes;
            snprintf(b->id, sizeof b->id, "box-layered-bootstrap");
            b->plans = calloc(1, sizeof *b->plans);
            b->binds = calloc(1, sizeof *b->binds);
            CHECK(b->plans && b->binds, "late bootstrap fixture allocation failed");
            if (!b->plans || !b->binds) { d2k_catalog_free(&c); continue; }
            b->n_plans = b->n_binds = 1;
            snprintf(b->plans[0].id, sizeof b->plans[0].id, "plan-bootstrap");
            snprintf(b->plans[0].proto, sizeof b->plans[0].proto, "tls");
            b->plans[0].enabled = 1;
            b->plans[0].text = strdup("d2k-plan 1 1\nid 00000000000000000000000000000000\n"
                "proto tcp tls\nsplit payload_start +2\norder forward\n");
            d2k_cat_binding *bd = b->binds;
            snprintf(bd->kind, sizeof bd->kind, "name");
            snprintf(bd->target, sizeof bd->target, "layered-rx.test");
            snprintf(bd->plan_id, sizeof bd->plan_id, "plan-bootstrap");
            bd->enabled = 1; bd->level = 3; bd->transport = 6;
            bd->shape = D2K_SHAPE_MODERN; bd->family = 4;
        }
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        saidbuf[0] = '\0'; forget_sent();
        d2k_sched_set_say(s, collect_say, NULL);
        vol_answer = D2K_VOL_UNREACHABLE; vol_rx_cut = 0;
        vol_rx_tls_unavailable = 1; tcp_answer = D2K_V_OPAQUE;
        ver_answer_port = 40241; ver_fail_first = 0;
        ver_answer = D2K_VER_HANDSHAKE;
        layered_identity_calls = layered_gzip_calls = 0;
        layered_bad_control = bad;
        d2k_sched_rx_ver_hook = stub_layered_identity;
        d2k_sched_rx_gzip_ver_hook = stub_layered_gzip;
        d2k_ev h = ev_hello(6, 40241, "layered-rx.test"), sh;
        d2k_sched_event(s, &h);
        CHECK(tls_shape_event(&sh, h.name, D2K_SHAPE_MODERN) == 0,
              "layered RX shape fixture failed");
        d2k_sched_event(s, &sh);
        d2k_ev su = ev_suspect(6, 40241);
        if (bad >= 4) su.code = D2K_SUSPECT_FIN_RETRY;
        d2k_sched_event(s, &su);
        int installed = 0;
        for (int i = 0; i < 4000; i++) {
            tick_once(s);
            int n = sent_command_count(D2K_CMD_SET_NAME_PROBE, NULL, 0);
            if (n > installed) {
                installed = n;
                d2k_ev ap = ev_applied(6, 40241);
                if (bad == 2) ap.plan_id[0] ^= 1;
                d2k_sched_event(s, &ap);
            }
            if (layered_gzip_calls && ((bad == 1 || bad == 5) ? said("не подтверждён полным gzip") :
                    sent_contains_plan_payload("hcaptcha.com"))) break;
            if (bad == 2 && layered_identity_calls >= 3) break;
            if (bad == 3 && said("повторный identity-обрыв под кандидатом не подтвердился")) break;
        }
        CHECK(layered_identity_calls >= 2 && layered_gzip_calls == (bad == 2 || bad == 3 ? 0 : 1),
              "layered RX did not run two identity checks followed by gzip");
        CHECK(total_bindings(&c) == (bad >= 4 ? 1u : 0u), "gzip bootstrap incorrectly saved as complete bypass");
        CHECK(sent_contains_plan_payload("hcaptcha.com") == (bad == 0 || bad == 4),
              "RX ladder admission ignored paired identity/gzip evidence");
        if (bad < 2 && !layered_gzip_calls) fprintf(stderr, "%s\n", saidbuf);
        d2k_sched_free(s); d2k_catalog_free(&c);
        d2k_sched_rx_ver_hook = stub_ver;
        d2k_sched_rx_gzip_ver_hook = stub_ver;
        vol_rx_tls_unavailable = 0; vol_answer = D2K_VOL_PASSED;
    }
    /* Парный RX-замер тоже поднимает поиск без доменного списка и сохраняет
       направление/объём как отдельную примету; gzip completion — часть
       критерия, не просто статус заголовков. */
    {
        d2k_catalog cRx = {0};
        d2k_sched *s = d2k_sched_new(&cRx, sv[0], 0x2d);
        saidbuf[0] = '\0';
        forget_sent();
        d2k_sched_set_say(s, collect_say, NULL);
        vol_answer = D2K_VOL_PASSED;
        vol_rx_cut = 1;
        vol_rx_packets = 26; /* задача 55: бюджет коробки из её замера */
        tcp_calls = 0; ver_calls = 0;
        memset(ver_budget_seen, 0, sizeof ver_budget_seen);
        d2k_verdict rx_tcp_was = tcp_answer;
        tcp_answer = D2K_V_CLEAR; /* объём — после CLEAR классификатора (задача 30) */
        d2k_ev h = ev_hello(6, 40081, "непрофильная.цель");
        d2k_sched_event(s, &h);
        d2k_ev sh;
        CHECK(tls_shape_event(&sh, h.name, D2K_SHAPE_MODERN) == 0,
              "не удалось собрать TLS 1.3 shape для RX-volume-теста");
        d2k_sched_event(s, &sh);
        d2k_ev su = ev_suspect(6, 40081);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(tcp_calls == 1, "RX-обрыв измерен без предшествующей донорской классификации");
        CHECK(said("identity-тело дважды оборвалось") && said("gzip завершился"),
              "причина RX-volume не раскрыла парный результат");
        CHECK(sent_contains_plan_payload("hcaptcha.com"),
              "RX-volume не приоритизировал fake-SNI/multisplit-кандидат");
        if (!sent_contains_plan_payload("hcaptcha.com")) { fprintf(stderr, "%s\n", saidbuf); }
        CHECK(ver_calls >= 1 && ver_budget_seen[0] == 26,
              "задача 55: кандидат испытан не с бюджетом из замера коробки (пакеты на обрыве identity)");
        vol_rx_cut = 0; vol_rx_packets = 0;
        tcp_answer = rx_tcp_was;
        d2k_sched_free(s);
        d2k_catalog_free(&cRx);
    }

    /* Поздний RST после TLS app-data не считается блокировкой сам по себе:
       он допускает только RX-volume-пару, а общий классификатор и кандидаты
       запускаются лишь после воспроизводимого identity-cut + полного gzip. */
    {
        d2k_catalog cLate = {0};
        d2k_sched *s = d2k_sched_new(&cLate, sv[0], 0x2d);
        saidbuf[0] = '\0';
        forget_sent();
        d2k_sched_set_say(s, collect_say, NULL);
        vol_calls = tcp_calls = 0;
        vol_answer = D2K_VOL_PASSED;
        vol_rx_cut = 0;
        d2k_ev h = ev_hello(6, 40082, "late-reset-volume.test");
        d2k_sched_event(s, &h);
        d2k_ev sh;
        CHECK(tls_shape_event(&sh, h.name, D2K_SHAPE_MODERN) == 0,
              "не удалось собрать TLS 1.3 shape для позднего RST");
        d2k_sched_event(s, &sh);
        prime_late_rst(s, h.name, 40182);
        d2k_ev su = ev_suspect(6, 40082);
        su.code = D2K_SUSPECT_RST_AFTER_APP;
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(vol_calls == 1, "поздний RST не запустил узкую RX-volume-пару");
        CHECK(tcp_calls == 0, "поздний RST без RX-cut запустил общий перебор");
        CHECK(!sent_contains_plan_payload("hcaptcha.com"),
              "кандидат отправлен без подтверждения RX-volume");
        /* Финальное ревью, п.4: неубедительная пара поздних RST глушит
           только повторные поздние RST/объёмные триггеры этой цели, а не
           блокировку на рукопожатии (обычный RST/таймаут SNI). */
        vol_calls = tcp_calls = 0;
        skip_ahead(s, 3 * 60 * 1000);           /* отдых задачи (2 мин) прошёл */
        spin(s, 5);
        saidbuf[0] = '\0';
        prime_late_rst(s, h.name, 40184);
        su = ev_suspect(6, 40085);
        su.code = D2K_SUSPECT_RST_AFTER_APP;
        d2k_ev h3 = ev_hello(6, 40085, h.name);
        d2k_sched_event(s, &h3);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(vol_calls == 0 && tcp_calls == 0 && said("замер отложен"),
              "повторная пара поздних RST не отложена после неубедительного замера");
        saidbuf[0] = '\0';
        d2k_ev h4 = ev_hello(6, 40086, h.name);
        d2k_sched_event(s, &h4);
        d2k_ev su4 = ev_suspect(6, 40086);       /* обычный сброс на рукопожатии */
        d2k_sched_event(s, &su4);
        settle(s);
        CHECK(!said("замер отложен") && said("источник нового замера"),
              "неубедительный поздний RST заглушил блокировку на рукопожатии на 10 мин");
        vol_calls = tcp_calls = 0;
        d2k_sched_free(s);
        d2k_catalog_free(&cLate);

        d2k_catalog cLateConfirmed = {0};
        s = d2k_sched_new(&cLateConfirmed, sv[0], 0x2d);
        saidbuf[0] = '\0';
        forget_sent();
        d2k_sched_set_say(s, collect_say, NULL);
        vol_answer = D2K_VOL_PASSED;
        vol_rx_cut = 1;
        d2k_ev h2 = ev_hello(6, 40083, "late-reset-volume-confirmed.test");
        d2k_sched_event(s, &h2);
        CHECK(tls_shape_event(&sh, h2.name, D2K_SHAPE_MODERN) == 0,
              "не удалось собрать TLS 1.3 shape для подтверждённого позднего RST");
        d2k_sched_event(s, &sh);
        prime_late_rst(s, h2.name, 40183);
        d2k_ev su2 = ev_suspect(6, 40083);
        su2.code = D2K_SUSPECT_RST_AFTER_APP;
        d2k_sched_event(s, &su2);
        settle(s);
        CHECK(vol_calls == 1, "подтверждённый поздний RST замерен не один раз");
        CHECK(tcp_calls == 0,
              "после подтверждённого RX-volume запущено постороннее дерево классификации");
        CHECK(sent_contains_plan_payload("hcaptcha.com"),
              "подтверждённый RX-volume не открыл очередь volume-кандидатов");
        vol_rx_cut = 0;
        d2k_sched_free(s);
        d2k_catalog_free(&cLateConfirmed);
    }

    /* Полная очередь сохранённых планов коробки не должна вытеснять новый
       RX-volume-кандидат навсегда. Все восемь сохранённых испытываются
       первыми; после восьми отказов в проводной очереди появляется профильная
       fake-SNI/split-лестница. */
    {
        d2k_catalog cFull;
        memset(&cFull, 0, sizeof cFull);
        cFull.boxes = calloc(1, sizeof *cFull.boxes);
        CHECK(cFull.boxes != NULL, "не удалось создать коробку для полной очереди");
        if (cFull.boxes) {
            cFull.n_boxes = 1;
            d2k_cat_box *b = &cFull.boxes[0];
            snprintf(b->id, sizeof b->id, "box-rx-volume-full");
            b->fp.method = D2K_FP_METHOD;
            b->fp.n_sig = 1;
            snprintf(b->fp.sig[0].kind, sizeof b->fp.sig[0].kind, "rx-volume");
            b->fp.sig[0].volume = 24;
            b->fp.sig[0].seen = 1;
            b->plans = calloc(8, sizeof *b->plans);
            CHECK(b->plans != NULL, "не удалось создать восемь сохранённых планов");
            if (b->plans) {
                b->n_plans = 8;
                int ready = 1;
                for (unsigned i = 0; i < 8; i++) {
                    d2k_cat_plan *p = &b->plans[i];
                    p->enabled = 1;
                    p->successes = (int)(8 - i);
                    snprintf(p->proto, sizeof p->proto, "tls");
                    char plan[256];
                    snprintf(plan, sizeof plan,
                             "d2k-plan 1 1\nid 00000000000000000000000000000000\n"
                             "proto tcp tls\nsplit payload_start +%u\norder forward\n",
                             i + 11);
                    p->text = strdup(plan);
                    if (!p->text) { ready = 0; break; }
                }
                CHECK(ready, "не удалось подготовить планы полной очереди");
                if (ready) {
                    d2k_sched *s = d2k_sched_new(&cFull, sv[0], 0x2d);
                    saidbuf[0] = '\0';
                    forget_sent();
                    d2k_sched_set_say(s, collect_say, NULL);
                    vol_calls = tcp_calls = 0;
                    vol_answer = D2K_VOL_PASSED;
                    vol_rx_cut = 1;
                    ver_answer = D2K_VER_HANDSHAKE;
                    ver_fail_first = 0;
                    ver_calls = 0;
                    ver_answer_port = 40240;
                    d2k_ev h = ev_hello(6, 40240, "full-rx-box.test");
                    d2k_sched_event(s, &h);
                    d2k_ev sh;
                    CHECK(tls_shape_event(&sh, h.name, D2K_SHAPE_MODERN) == 0,
                          "не удалось собрать TLS 1.3 shape для полной коробки");
                    d2k_sched_event(s, &sh);
                    prime_late_rst(s, h.name, 40340);
                    d2k_ev su = ev_suspect(6, 40240);
                    su.code = D2K_SUSPECT_RST_AFTER_APP;
                    d2k_sched_event(s, &su);
                    settle(s);
                    CHECK(vol_calls == 1 && tcp_calls == 0,
                          "поздний RST не остался в парном RX-измерении");
                    CHECK(sent_first_split_index(11) == 0 &&
                          sent_plan_index("hcaptcha.com", 0, 3) >= 8,
                          "RX-volume-кандидат поставлен раньше восьми сохранённых планов коробки");
                    for (unsigned i = 0; i < 8; i++) {
                        d2k_ev ap = ev_applied(6, 40240);
                        d2k_sched_event(s, &ap);
                        spin(s, 40);
                    }
                    CHECK(sent_contains_plan_payload("hcaptcha.com"),
                          "после всех сохранённых планов не долита RX-volume-лестница");
                    ver_fail_first = 0;
                    vol_rx_cut = 0;
                    d2k_sched_free(s);
                }
            }
        }
        d2k_catalog_free(&cFull);
    }

    if (rx_only) { goto voice_only_done; }
    /* --- внешний тип 23 сам по себе не подтверждает ничего (задача 4) --- */
    {
        /* В TLS 1.3 внешним типом записи 23 наружу едет ВЕСЬ второй полёт
           рукопожатия (RFC 8446 §5.2): с провода «приложение ответило» и
           «коробка пропустила приветствие» неотличимы. Ровно на этом пороге
           в каталоге накопились 4796 «успехов» по instagram при мёртвом
           плане (§1 спецификации). Событие обмена по потоку задачи обязано
           остаться НАБЛЮДЕНИЕМ и привязку не заводить. */
        d2k_catalog c4;
        memset(&c4, 0, sizeof c4);
        d2k_sched *s = d2k_sched_new(&c4, sv[0], 0x2d);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_HANDSHAKE; /* зонд до приложения НЕ дошёл */
        ver_fail_first = 0;
        d2k_ev h = ev_hello(6, 40030, "instagram.com");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40030);
        d2k_sched_event(s, &su);
        settle(s);
        d2k_ev x = ev_exchange(6, 40030, 1); /* внешний тип 23 по потоку цели */
        d2k_sched_event(s, &x);
        spin(s, 40);
        CHECK(total_bindings(&c4) == 0,
              "внешний тип 23 записан как подтверждение — это только наблюдение (RFC 8446 §5.2)");
        d2k_ev x0 = ev_exchange(6, 40030, 0); /* и рукопожатие тем более */
        d2k_sched_event(s, &x0);
        spin(s, 40);
        CHECK(total_bindings(&c4) == 0, "обмен без внешнего типа 23 засчитан за успех");
        d2k_sched_free(s);
        d2k_catalog_free(&c4);
    }

    /* --- отрицательный результат не сохраняется (§10) ------------------ */
    {
        d2k_catalog c3;
        memset(&c3, 0, sizeof c3);
        d2k_sched *s = d2k_sched_new(&c3, sv[0], 0x2d);
        tcp_answer = D2K_V_INCONCLUSIVE;
        d2k_ev h = ev_hello(6, 40020, "безнадёжная.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40020);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(total_bindings(&c3) == 0,
              "неудачный поиск оставил след в каталоге — §10 это запрещает");
        CHECK(c3.n_boxes == 0, "неудачный поиск завёл коробку");
        d2k_sched_free(s);
        d2k_catalog_free(&c3);
        tcp_answer = D2K_V_OPAQUE;
    }

    /* A direct CLEAR is not a catalog fact, but it is a short-lived scheduler
       backoff: the same target must not be actively remeasured on every fresh
       suspicion while it is already known to pass. It becomes eligible again
       after the backoff expires. */
    {
        d2k_catalog c;
        memset(&c, 0, sizeof c);
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        tcp_answer = D2K_V_CLEAR;
        tcp_calls = 0;
        CHECK(s != NULL, "планировщик CLEAR-backoff не завёлся");
        if (s) {
            d2k_ev h = ev_hello(6, 40201, "clear-backoff.example");
            d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 40201);
            d2k_sched_event(s, &su);
            settle(s);
            CHECK(tcp_calls == 1, "первый CLEAR не выполнил прямой замер");

            /* First clean result must suppress the same repeated signal for
               longer than the old two-minute task rest. */
            skip_ahead(s, 3 * 60 * 1000);
            d2k_ev h2 = ev_hello(6, 40202, "clear-backoff.example");
            d2k_sched_event(s, &h2);
            d2k_ev su2 = ev_suspect(6, 40202);
            d2k_sched_event(s, &su2);
            settle(s);
            CHECK(tcp_calls == 1,
                  "повторный CLEAR по той же цели начал замер внутри cooldown");

            /* The cooldown expires; a new observation can measure again. */
            skip_ahead(s, 8 * 60 * 1000);
            d2k_ev h3 = ev_hello(6, 40203, "clear-backoff.example");
            d2k_sched_event(s, &h3);
            d2k_ev su3 = ev_suspect(6, 40203);
            d2k_sched_event(s, &su3);
            settle(s);
            CHECK(tcp_calls == 2, "первый CLEAR-backoff не истёк через 10 минут");

            skip_ahead(s, 3 * 60 * 1000);
            d2k_ev h4 = ev_hello(6, 40204, "clear-backoff.example");
            d2k_sched_event(s, &h4);
            d2k_ev su4 = ev_suspect(6, 40204);
            d2k_sched_event(s, &su4);
            settle(s);
            CHECK(tcp_calls == 2,
                  "повторный CLEAR не увеличил cooldown: частота не снижается");

            skip_ahead(s, 28 * 60 * 1000);
            d2k_ev h5 = ev_hello(6, 40205, "clear-backoff.example");
            d2k_sched_event(s, &h5);
            d2k_ev su5 = ev_suspect(6, 40205);
            d2k_sched_event(s, &su5);
            settle(s);
            CHECK(tcp_calls == 3,
                  "увеличенный CLEAR-backoff не истёк после 30 минут");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&c);
        tcp_answer = D2K_V_OPAQUE;
    }

    /* A genuinely different datapath signal may bypass a prior CLEAR; the
       cooldown is target-local and must not suppress unrelated sites. */
    {
        d2k_catalog c = {0};
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        tcp_answer = D2K_V_CLEAR;
        tcp_calls = 0;
        CHECK(s != NULL, "планировщик проверки усиленного сигнала не завёлся");
        if (s) {
            d2k_ev h = ev_hello(6, 40231, "changed-signal.example");
            d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 40231);
            d2k_sched_event(s, &su);
            settle(s);
            CHECK(tcp_calls == 1, "первый direct CLEAR не измерен");

            skip_ahead(s, 3 * 60 * 1000);
            d2k_ev h2 = ev_hello(6, 40232, "changed-signal.example");
            d2k_sched_event(s, &h2);
            d2k_ev stronger = ev_suspect(6, 40232);
            stronger.code = D2K_SUSPECT_SILENT;
            d2k_sched_event(s, &stronger);
            settle(s);
            CHECK(tcp_calls == 2,
                  "новый тип сигнала был подавлен старым CLEAR-backoff");

            d2k_ev h3 = ev_hello(6, 40233, "unrelated-site.example");
            d2k_sched_event(s, &h3);
            d2k_ev su3 = ev_suspect(6, 40233);
            d2k_sched_event(s, &su3);
            settle(s);
            CHECK(tcp_calls == 3,
                  "cooldown одной цели остановил измерение другого сайта");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&c);
        tcp_answer = D2K_V_OPAQUE;
    }

    /* An anti-bot challenge gets a longer target-local cooldown than an
       ordinary CLEAR, and must not be treated as a failed strategy to retry. */
    {
        d2k_catalog c;
        memset(&c, 0, sizeof c);
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_CHALLENGE;
        ver_fail_first = 0;
        ver_answer_port = 40210;
        ver_calls = 0;
        forget_sent();
        CHECK(s != NULL, "планировщик challenge-backoff не завёлся");
        if (s) {
            d2k_ev h = ev_hello(6, 40210, "challenge-backoff.example");
            d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 40210);
            d2k_sched_event(s, &su);
            settle(s);
            CHECK(ver_calls == 1, "первый challenge не был получен");

            skip_ahead(s, 3 * 60 * 1000);
            d2k_ev h2 = ev_hello(6, 40211, "challenge-backoff.example");
            d2k_sched_event(s, &h2);
            d2k_ev su2 = ev_suspect(6, 40211);
            su2.code = D2K_SUSPECT_SILENT;
            d2k_sched_event(s, &su2);
            settle(s);
            CHECK(ver_calls == 1,
                  "антибот-челлендж вызвал повторный активный зонд внутри cooldown");

            skip_ahead(s, 58 * 60 * 1000);
            d2k_ev h3 = ev_hello(6, 40212, "challenge-backoff.example");
            d2k_sched_event(s, &h3);
            d2k_ev su3 = ev_suspect(6, 40212);
            d2k_sched_event(s, &su3);
            settle(s);
            CHECK(ver_calls == 2,
                  "challenge-backoff не истёк: цель навсегда исключена из перепроверки");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&c);
        tcp_answer = D2K_V_OPAQUE;
        ver_answer = D2K_VER_APPLICATION;
    }

    /* Финальное ревью core, M6: кольцо отсрочек конечно (128), но
       действующая антибот-пауза (60 мин) не вытесняется, пока есть чем
       её заменить: сначала свободные и истёкшие записи, затем действующие
       не-антибот. Прежде кольцо писалось по кругу, и 128 прямых CLEAR
       снимали паузу раньше срока. */
    {
        d2k_catalog c = {0};
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_CHALLENGE;
        ver_fail_first = 0;
        ver_answer_port = 40250;
        ver_calls = tcp_calls = 0;
        forget_sent();
        CHECK(s != NULL, "планировщик кольца отсрочек не завёлся");
        if (s) {
            d2k_ev h = ev_hello(6, 40250, "challenge-ring.example");
            d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 40250);
            d2k_sched_event(s, &su);
            settle(s);
            CHECK(ver_calls == 1, "кольцо: антибот-челлендж не получен");
            tcp_answer = D2K_V_CLEAR;
            /* Половина CLEAR истекает (10 мин), затем ещё 128 — кольцо
               переполняется и истёкшими, и действующими записями. */
            for (int round = 0; round < 2; round++) {
                for (int k = 0; k < 128; k++) {
                    char nm[64];
                    snprintf(nm, sizeof nm, "clear-ring-%d-%d.example", round, k);
                    uint16_t port = (uint16_t)(43000 + round * 200 + k);
                    int before = tcp_calls;
                    skip_ahead(s, 300);
                    d2k_ev hk = ev_hello(6, port, nm);
                    d2k_sched_event(s, &hk);
                    d2k_ev sk = ev_suspect(6, port);
                    d2k_sched_event(s, &sk);
                    for (int i = 0; i < 400 && tcp_calls == before; i++) tick_once(s);
                    spin(s, 4);
                }
                if (round == 0) skip_ahead(s, 11 * 60 * 1000);
            }
            int t0 = tcp_calls, v0 = ver_calls;
            tcp_answer = D2K_V_PREFIX;
            d2k_ev h2 = ev_hello(6, 40251, "challenge-ring.example");
            d2k_sched_event(s, &h2);
            d2k_ev su2 = ev_suspect(6, 40251);
            d2k_sched_event(s, &su2);
            settle(s);
            CHECK(tcp_calls == t0 && ver_calls == v0,
                  "кольцо отсрочек вытеснило действующую антибот-паузу");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&c);
        tcp_answer = D2K_V_OPAQUE;
        ver_answer = D2K_VER_APPLICATION;
    }

    /* Two compatible models are alternatives, not "first match wins". */
    {
        d2k_catalog c;
        memset(&c, 0, sizeof c);
        c.boxes = calloc(2, sizeof *c.boxes);
        CHECK(c.boxes != NULL, "не удалось создать две модели");
        if (c.boxes) {
            c.n_boxes = 2;
            int ready = 1;
            for (size_t i = 0; i < 2; i++) {
                d2k_cat_box *b = &c.boxes[i];
                snprintf(b->id, sizeof b->id, "box-alternative-%u", (unsigned)i);
                b->fp.method = D2K_FP_METHOD;
                b->fp.n_sig = 1;
                snprintf(b->fp.sig[0].kind, sizeof b->fp.sig[0].kind, "rst");
                b->fp.sig[0].ttl = 127;
                b->fp.sig[0].tos = 0x88;
                b->fp.sig[0].ipid = 54321;
                b->plans = calloc(1, sizeof *b->plans);
                if (!b->plans) { ready = 0; break; }
                b->n_plans = 1;
                b->plans[0].enabled = 1;
                b->plans[0].successes = (int)(2 - i);
                snprintf(b->plans[0].proto, sizeof b->plans[0].proto, "tls");
                char plan[256];
                snprintf(plan, sizeof plan,
                         "d2k-plan 1 1\nid 00000000000000000000000000000000\n"
                         "proto tcp tls\nsplit payload_start +%u\norder reverse\n",
                         (unsigned)(i + 1));
                b->plans[0].text = strdup(plan);
                if (!b->plans[0].text) { ready = 0; break; }
            }
            CHECK(ready, "не удалось создать планы альтернативных моделей");
            if (ready) {
                d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
                tcp_calls = vol_calls = 0;
                /* Первый кандидат (план модели с бо́льшим числом успехов) не
                   помогает: зонд доходит только до рукопожатия. Второй —
                   помогает. Обе развилки видит сам планировщик. */
                ver_answer = D2K_VER_APPLICATION;
                ver_fail_first = 1;
                ver_calls = 0;
                ver_answer_port = 40101;
                forget_sent();
                d2k_ev h = ev_hello(6, 40101, "неоднозначная.цель");
                d2k_sched_event(s, &h);
                d2k_ev su = ev_suspect(6, 40101);
                d2k_sched_event(s, &su);
                settle(s);
                CHECK(tcp_calls == 1 && vol_calls == 0,
                      "модели не проверялись после прямого подтверждения блокировки");
                d2k_ev ap = ev_applied(6, 40101);
                d2k_sched_event(s, &ap);
                spin(s, 40);
                CHECK(c.boxes[0].n_binds == 0 && c.boxes[1].n_binds == 1,
                      "результат второго плана записан не в его модель");
                ver_fail_first = 0;
                d2k_sched_free(s);
            }
            d2k_catalog_free(&c);
        }
    }

    /* An inconclusive direct measurement is not evidence to apply a bypass. */
    {
        d2k_catalog c;
        memset(&c, 0, sizeof c);
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_INCONCLUSIVE;
        ver_answer = D2K_VER_HANDSHAKE;
        d2k_ev h = ev_hello(6, 40100, "без.контроля");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40100);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(!said("поставил план 1 из"),
              "без положительного диагноза план ошибочно применён");
        CHECK(said("не подтвердил блокировку"),
              "неопределённый замер не остановил подбор");
        CHECK(c.n_boxes == 0, "непроверенная гипотеза попала в каталог");
        d2k_sched_free(s);
        d2k_catalog_free(&c);
        tcp_answer = D2K_V_OPAQUE;
    }

    /* Явный ответ Cloudflare challenge — не успех и не повод перебрать
       остальные кандидаты: все они упрётся в ту же проверку ботов. */
    {
        d2k_catalog c;
        memset(&c, 0, sizeof c);
        d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_CHALLENGE;
        ver_fail_first = 0;
        ver_answer_port = 40105;
        ver_calls = 0;
        forget_sent();

        d2k_ev h = ev_hello(6, 40105, "challenge.example");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40105);
        d2k_sched_event(s, &su);
        settle(s);

        CHECK(ver_calls == 1, "challenge привёл к перебору следующих кандидатов");
        CHECK(said("Cloudflare challenge"), "challenge не объяснён в журнале");
        CHECK(said("перебор остановлен"), "поиск не остановлен на challenge");
        CHECK(binding_of(&c, "challenge.example", 6) == NULL,
              "challenge записан в каталог как подтверждённый обход");
        d2k_sched_free(s);
        d2k_catalog_free(&c);
        tcp_answer = D2K_V_OPAQUE;
        ver_answer = D2K_VER_APPLICATION;
    }

    /* --- редкую цель планировщик испытывает САМ (задача 3) -------------- */
    {
        /* Главная проверка этой вертикали. Событий от пользователя после
           подозрения НЕТ ВОВСЕ — только то, что говорит датапат о НАШЕМ
           зонде. Спецификация (§4) прямо отказывается от того, чтобы цель
           открывали несколько раз ради перебора: у телевизора одно обращение,
           следующее через три минуты. */
        d2k_catalog cB;
        memset(&cB, 0, sizeof cB);
        d2k_sched *s = d2k_sched_new(&cB, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = 40090;
        ver_calls = 0;
        forget_sent();

        d2k_ev h = ev_hello(6, 40090, "редкая.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40090);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(ver_calls >= 1, "планировщик не испытал кандидата сам");

        /* Датапат говорит, что план применился к пакетам ЭТОГО потока. */
        d2k_ev ap = ev_applied(6, 40090);
        CHECK(memcmp(ap.plan_id, (const uint8_t[16]){0}, 16) != 0,
              "кандидат ушёл на провод без идентификатора — сверять применение нечем");
        d2k_sched_event(s, &ap);
        spin(s, 40);
        CHECK(total_bindings(&cB) == 1,
              "успех собственного испытания не записан — перебор снова ждёт пользователя");
        CHECK(said("ПОДТВЕРЖДЕНО собственным зондом"),
              "подтверждение не названо тем, чем оно является");
        const d2k_cat_binding *bd = binding_of(&cB, "редкая.цель", 6);
        CHECK(bd != NULL && bd->level == 3,
              "уровень записи не третий («обмен прошёл») — именно это и доказано зондом");

        /* Чужое применение того же плана к той же цели — НЕ наше испытание:
           ключ потока другой. Проверяется отдельной целью, чтобы поймать
           сверку по порту, а не «по чему-нибудь». */
        ver_answer_port = 40091;
        ver_calls = 0;
        forget_sent();
        d2k_ev h2 = ev_hello(6, 40091, "чужой.поток");
        d2k_sched_event(s, &h2);
        d2k_ev su2 = ev_suspect(6, 40091);
        d2k_sched_event(s, &su2);
        settle(s);
        d2k_ev ap2 = ev_applied(6, 40091);
        ap2.high_port = 40099; /* тот же план и та же цель, но ЧУЖОЙ поток */
        d2k_sched_event(s, &ap2);
        run_out(s);
        CHECK(binding_of(&cB, "чужой.поток", 6) == NULL,
              "применение по ЧУЖОМУ потоку засчитано за испытание нашего зонда");

        /* Применение ЧУЖОГО плана по НАШЕМУ потоку — тоже не испытание: так
           выглядит опоздавшее событие предыдущего кандидата (ради этого
           различия идентификатор и завели, d2k_link.h). */
        ver_answer_port = 40092;
        ver_calls = 0;
        forget_sent();
        d2k_ev h3 = ev_hello(6, 40092, "старый.план");
        d2k_sched_event(s, &h3);
        d2k_ev su3 = ev_suspect(6, 40092);
        d2k_sched_event(s, &su3);
        settle(s);
        d2k_ev ap3 = ev_applied(6, 40092);
        memcpy(ap3.plan_id, "plan-deadbeef\0\0", 16); /* идентификатор другого плана */
        d2k_sched_event(s, &ap3);
        run_out(s);
        CHECK(binding_of(&cB, "старый.план", 6) == NULL,
              "применение ЧУЖОГО плана засчитано за испытание нашего кандидата");
        d2k_sched_free(s);
        d2k_catalog_free(&cB);
    }

    /* СЕДЬМАЯ НАХОДКА ЛАБОРАТОРИИ: подтверждение на зонде ≠ работа у клиента.
       Кандидат стоит на ЦЕЛИ, и по нему одновременно с зондом ходит браузер.
       Приветствие браузера длиннее зондового, и бывает так: зонду план
       исполняется и доходит до приложения, а потоку клиента — нет, отказом по
       длине. Записать такое подтверждённым значит выдать человеку каталог с
       «подтверждено» и отсутствием обхода. */
    {
        d2k_catalog cuf;
        memset(&cuf, 0, sizeof cuf);
        d2k_sched *s = d2k_sched_new(&cuf, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;   /* зонду план исполнился до конца */
        ver_fail_first = 0;
        ver_answer_port = 40160;
        ver_calls = 0;
        forget_sent();

        d2k_ev h = ev_hello(6, 40160, "непереносимая.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40160);
        d2k_sched_event(s, &su);
        settle(s);
        spin_until_installed(s);

        /* Второй поток к ТОЙ ЖЕ цели — его открыл клиент, а не зонд. Имя за
           ним планировщик знает из приветствия, как и на живой линии. */
        d2k_ev hc = ev_hello(6, 40161, "непереносимая.цель");
        d2k_sched_event(s, &hc);
        d2k_ev big = ev_refused(6, 40161, D2K_REFUSE_TOO_LONG, 1);
        CHECK(memcmp(big.plan_id, (const uint8_t[16]){0}, 16) != 0,
              "кандидат ушёл на провод без идентификатора — приписать отказ нечему");
        d2k_sched_event(s, &big);

        /* А зонду тот же план исполнился: полное доказательство на руках. */
        d2k_ev ap = ev_applied(6, 40160);
        d2k_sched_event(s, &ap);
        run_out(s);

        CHECK(said("потоку клиента"),
              "план не исполнился клиенту, а планировщик об этом промолчал");
        CHECK(binding_of(&cuf, "непереносимая.цель", 6) == NULL,
              "план, не исполнимый потоку клиента, записан подтверждённым — "
              "в каталоге «подтверждено», у человека обхода нет");
        d2k_sched_free(s);
        d2k_catalog_free(&cuf);
    }

    /* Тот же ход, но отказ у клиента ВРЕМЕННЫЙ: очередь переполнилась, к
       переносимости это отношения не имеет, и подтверждение обязано пройти. */
    {
        d2k_catalog ctq;
        memset(&ctq, 0, sizeof ctq);
        d2k_sched *s = d2k_sched_new(&ctq, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = 40162;
        ver_calls = 0;
        forget_sent();

        d2k_ev h = ev_hello(6, 40162, "временная.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40162);
        d2k_sched_event(s, &su);
        settle(s);
        spin_until_installed(s);

        d2k_ev hc = ev_hello(6, 40163, "временная.цель");
        d2k_sched_event(s, &hc);
        d2k_ev tmp = ev_refused(6, 40163, D2K_REFUSE_QUEUE, 1);
        d2k_sched_event(s, &tmp);

        d2k_ev ap = ev_applied(6, 40162);
        d2k_sched_event(s, &ap);
        run_out(s);

        CHECK(binding_of(&ctq, "временная.цель", 6) != NULL,
              "временный отказ у клиента отменил состоявшееся подтверждение — "
              "всплеск очереди объявлен непереносимостью");
        d2k_sched_free(s);
        d2k_catalog_free(&ctq);
    }

    /* Ранние APPLIED: два клиента вправе иметь одинаковый местный порт.
       События подаются до следующего tick: результат worker ещё не принят. */
    for (int with_own = 0; with_own < 2; with_own++) {
        d2k_catalog early;
        memset(&early, 0, sizeof early);
        d2k_sched *s = d2k_sched_new(&early, sv[0], 0x2d);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = 40109;
        forget_sent();
        d2k_ev h = ev_hello(6, 40109, "early.example");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40109);
        d2k_sched_event(s, &su);
        uint8_t id[16];
        int installed = 0;
        for (int i = 0; i < 400 && !installed; i++) {
            tick_once(s);
            installed = last_plan_id(id);
        }
        CHECK(installed, "кандидат для ранних событий не установлен");
        d2k_ev ap = ev_applied(6, 40109);
        ap.high_ip[3] = 68;
        d2k_sched_event(s, &ap); /* правильные цель/план/порт, но чужой IP */
        ap.high_ip[3] = 67;
        memset(ap.plan_id, 0, sizeof ap.plan_id);
        d2k_sched_event(s, &ap); /* свой поток без идентификатора не доказательство */
        if (with_own) {
            ap = ev_applied(6, 40109);
            d2k_sched_event(s, &ap);
        }
        settle(s);
        CHECK((binding_of(&early, "early.example", 6) != NULL) == with_own,
              "раннее применение перепутало клиентов или потеряло своё за чужим");
        d2k_sched_free(s);
        d2k_catalog_free(&early);
    }

    /* --- живой TLS-ответ ПОСЛЕ подтверждения остаётся наблюдением ------- */
    {
        /* T_WATCHING теперь означает другое: не «ждём, пока пользователь
           откроет цель», а «план подтверждён и стоит, смотрим на живой
           трафик». Наблюдение внешнего типа 23 привязку не заводит (проверено
           выше), но уже подтверждённой поднять уровень может — это и есть
           пятый уровень, «подтверждён последующими соединениями». */
        d2k_catalog cC;
        memset(&cC, 0, sizeof cC);
        d2k_sched *s = d2k_sched_new(&cC, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = 40110;
        forget_sent();

        d2k_ev h = ev_hello(6, 40110, "подтверждённая.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40110);
        d2k_sched_event(s, &su);
        settle(s);
        d2k_ev ap = ev_applied(6, 40110);
        d2k_sched_event(s, &ap);
        spin(s, 40);
        const d2k_cat_binding *bd = binding_of(&cC, "подтверждённая.цель", 6);
        CHECK(bd != NULL && bd->level == 3, "подтверждение зондом не записано третьим уровнем");

        /* Обмен по потоку САМОГО зонда уровень не поднимает: это он и был
           доказательством, и считать его ещё и «последующим соединением»
           значит подтвердить себя собой. */
        d2k_ev own = ev_exchange(6, 40110, 1);
        d2k_sched_event(s, &own);
        bd = binding_of(&cC, "подтверждённая.цель", 6);
        CHECK(bd != NULL && bd->level == 3,
              "обмен по потоку самого зонда поднял уровень — запись подтвердила себя собой");

        /* Другое соединение тоже могло оборваться на рукопожатии. */
        d2k_ev h2 = ev_hello(6, 40111, "подтверждённая.цель");
        d2k_sched_event(s, &h2);
        d2k_ev live = ev_exchange(6, 40111, 1);
        d2k_sched_event(s, &live);
        bd = binding_of(&cC, "подтверждённая.цель", 6);
        CHECK(bd != NULL && bd->level == 3,
              "пассивный TLS-ответ ошибочно повысил уровень доказательства");
        CHECK(said("это не доказательство"), "граница наблюдения не названа в отчёте");
        CHECK(bd != NULL && bd->verified_by == D2K_VERBY_PROBE,
              "пассивный TLS-ответ затёр источник прикладного подтверждения");
        /* А форма осталась той, что ИЗМЕРЕНА зондом: приветствие живого
           клиента датапат не присылал, и «не измерено» не отменяет
           измеренного (§2.4). */
        CHECK(bd != NULL && bd->shape == (uint8_t)D2K_SHAPE_MODERN,
              "измеренная форма затёрта нулём от клиента, чьё приветствие не снято");

        d2k_sched_free(s);
        d2k_catalog_free(&cC);
    }

    /* --- ПОДОЗРЕНИЕ БЕЗ ПРИМЕНЁННОГО ПЛАНА — НЕ ДЕГРАДАЦИЯ ---------------
     *
     * Поле 18.09.2026: через две секунды после «ПОДТВЕРЖДЕНО» приходило
     * «подозрение при подтверждённом плане — наблюдение прекращаю», хотя
     * клиент тут же получал 200 четыре раза подряд. Тот поток был начат ДО
     * того, как план доехал до датапата: он шёл без обхода и про план не
     * говорит ничего. Различить их может только датапат — он один знает,
     * применялся ли план к ЭТОМУ потоку (ev->planned). */
    {
        d2k_catalog cG;
        memset(&cG, 0, sizeof cG);
        saidbuf[0] = '\0';
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        d2k_sched *s = d2k_sched_new(&cG, sv[0], 0x2d);
        CHECK(s != NULL, "планировщик для проверки деградации не завёлся");
        if (s) {
            d2k_sched_set_say(s, collect_say, NULL);
            ver_answer_port = 40310;
            ver_calls = 0;
            forget_sent();
            d2k_ev h = ev_hello(6, 40310, "деградация.цель");
            d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 40310);
            d2k_sched_event(s, &su);
            settle(s);
            d2k_ev ap = ev_applied(6, 40310);
            d2k_sched_event(s, &ap);
            spin(s, 40);
            CHECK(binding_of(&cG, "деградация.цель", 6) != NULL,
                  "цель не подтверждена — проверять деградацию не на чем");

            /* Второй поток той же цели: приветствие по нему датапат прислал,
               значит имя известно и подозрение дойдёт до задачи. */
            d2k_ev h2 = ev_hello(6, 40311, "деградация.цель");
            d2k_sched_event(s, &h2);
            saidbuf[0] = '\0';

            d2k_ev sn = ev_suspect(6, 40311);
            sn.planned = D2K_LINK_PLANNED_NO;
            d2k_sched_event(s, &sn);
            CHECK(!said("наблюдение прекращаю"),
                  "поток, шедший БЕЗ плана, объявлен деградацией подтверждённой цели");
            CHECK(said("план НЕ ПРИМЕНЯЛСЯ"),
                  "не сказано, почему подозрение уликой не считается");

            d2k_ev sy = ev_suspect(6, 40311);
            sy.planned = D2K_LINK_PLANNED_YES;
            d2k_sched_event(s, &sy);
            CHECK(said("наблюдение прекращаю"),
                  "подозрение о потоке С применённым планом не признано деградацией");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&cG);
    }

    /* --- контекст проверки записан в привязке (задача 5) ---------------- */
    {
        /* У зонда СВОЯ форма приветствия — не та, которой ходит браузер, и
           коробка вправе относиться к ним по-разному (§6). Значит успех,
           добытый зондом, нельзя молча переносить на произвольную форму: в
           привязке обязан стоять контекст, в котором проверка ДЕЙСТВИТЕЛЬНО
           состоялась. */
        d2k_shape probe_shape = probe_hello_shape();
        CHECK(probe_shape == D2K_SHAPE_MODERN,
              "приветствие собственного зонда оказалось не современной формы — "
              "константа планировщика разошлась с тем, что уходит на провод");

        d2k_catalog cD;
        memset(&cD, 0, sizeof cD);
        saidbuf[0] = '\0';
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;

        confirm_once(&cD, sv[0], "контекст.цель", 40130);
        CHECK(bindings_of(&cD, "контекст.цель", 6) == 1, "подтверждение не записано");
        const d2k_cat_binding *bd = binding_of(&cD, "контекст.цель", 6);
        CHECK(bd != NULL && bd->shape == (uint8_t)probe_shape,
              "в привязке не та форма приветствия, которой зонд ходил на самом деле");
        CHECK(bd != NULL && bd->verified_by == D2K_VERBY_PROBE,
              "в привязке не записано, что проверял собственный зонд");

        /* Файл, снятый ДО появления полей: форма не записана. Такая привязка
           совместима с любой формой, и повторное подтверждение обязано её
           ОБНОВИТЬ, а не завести рядом вторую. Иначе каталог роутера (376
           подтверждённых целей, копившихся неделями) удвоился бы на первой же
           проверке. */
        d2k_cat_binding *m = binding_mut(&cD, "контекст.цель", 6);
        CHECK(m != NULL, "нечего помечать под старый файл");
        if (m) { m->shape = 0; m->verified_by = 0; }
        confirm_once(&cD, sv[0], "контекст.цель", 40131);
        CHECK(bindings_of(&cD, "контекст.цель", 6) == 1,
              "запись без формы (старый файл) не обновлена, а продублирована");
        bd = binding_of(&cD, "контекст.цель", 6);
        CHECK(bd != NULL && bd->successes == 2,
              "повторное подтверждение не досталось прежней записи");
        CHECK(bd != NULL && bd->shape == (uint8_t)probe_shape,
              "измеренная форма не записана поверх «не измерено»");

        /* А ДРУГАЯ форма — уже другая запись: ключ привязки стал тройкой
           (цель, транспорт, форма приветствия). Успех современной формы не
           имеет права лечь в запись, добытую старой. */
        m = binding_mut(&cD, "контекст.цель", 6);
        if (m) { m->shape = (uint8_t)D2K_SHAPE_LEGACY; }
        confirm_once(&cD, sv[0], "контекст.цель", 40132);
        CHECK(bindings_of(&cD, "контекст.цель", 6) == 2,
              "успех одной формы приветствия лёг в запись, добытую другой");
        {
            int legacy_kept = 0, modern_new = 0;
            for (size_t i = 0; i < cD.n_boxes; i++) {
                for (size_t j = 0; j < cD.boxes[i].n_binds; j++) {
                    const d2k_cat_binding *x = &cD.boxes[i].binds[j];
                    if (strcmp(x->target, "контекст.цель") != 0) { continue; }
                    if (x->shape == (uint8_t)D2K_SHAPE_LEGACY && x->successes == 2) { legacy_kept++; }
                    if (x->shape == (uint8_t)probe_shape && x->successes == 1) { modern_new++; }
                }
            }
            CHECK(legacy_kept == 1, "чужая по форме запись изменена, а не оставлена в покое");
            CHECK(modern_new == 1, "новая форма не завела своей записи");
        }
        d2k_catalog_free(&cD);
    }

    /* --- живой клиент ДРУГОЙ формы уровень не поднимает ------------------ */
    {
        /* Зеркало предыдущего блока со стороны наблюдения. Запись добыта
           современной формой; живой клиент, чьё приветствие снято датапатом и
           оказалось СТАРОЙ формы, — это другой контекст, и его обмен ничего
           не говорит о записанном. Уровень остаётся третьим.
           Пара к проверке выше по файлу, где форма живого клиента не снята
           вовсе («не измерено») и уровень поднимается. */
        d2k_catalog cE;
        memset(&cE, 0, sizeof cE);
        d2k_sched *s = d2k_sched_new(&cE, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = 40140;
        ver_calls = 0;
        forget_sent();

        d2k_ev h = ev_hello(6, 40140, "форма.важна");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40140);
        d2k_sched_event(s, &su);
        settle(s);
        d2k_ev ap = ev_applied(6, 40140);
        d2k_sched_event(s, &ap);
        spin(s, 40);
        const d2k_cat_binding *bd = binding_of(&cE, "форма.важна", 6);
        CHECK(bd != NULL && bd->level == 3, "подтверждение зондом не записано третьим уровнем");

        /* Датапат снял приветствие живого клиента — и оно СТАРОЙ формы.
           Профиль берётся тот же, что у холодного старта (core/profiles), а
           не собирается в тесте руками. */
        {
            d2k_ev sh;
            memset(&sh, 0, sizeof sh);
            sh.kind = D2K_EV_SHAPE;
            sh.transport = 6;
            CHECK(d2k_hello_from_profile(D2K_SHAPE_LEGACY, "форма.важна",
                                         sh.shape, sizeof sh.shape, &sh.shape_len) == 0,
                  "приветствие старой формы не собралось — проверять нечем");
            CHECK(d2k_hello_shape(sh.shape, sh.shape_len) == D2K_SHAPE_LEGACY,
                  "собранное приветствие оказалось не старой формы");
            d2k_sched_event(s, &sh);
            CHECK(said("сохранён целый снимок для следующего поиска"),
                  "снимок приветствия не сохранён для следующего поиска");
        }

        d2k_ev h2 = ev_hello(6, 40141, "форма.важна");
        d2k_sched_event(s, &h2);
        d2k_ev live = ev_exchange(6, 40141, 1);
        d2k_sched_event(s, &live);
        bd = binding_of(&cE, "форма.важна", 6);
        CHECK(bd != NULL && bd->level == 3,
              "обмен клиента ДРУГОЙ формы поднял уровень записи, добытой не им");
        CHECK(bd != NULL && bd->verified_by == D2K_VERBY_PROBE,
              "контекст проверки переписан обменом клиента другой формы");
        CHECK(bindings_of(&cE, "форма.важна", 6) == 1,
              "наблюдение завело привязку — заводить её может только подтверждение");
        d2k_sched_free(s);
        d2k_catalog_free(&cE);
    }

    /* --- ЧЕМ МЕРИЛИ, ТО И ЗАПИСАНО (полнота входа, пункт 3) ------------ */
    {
        /* План выводится из ЗАМЕРА, а замер идёт какими-то байтами. Со
           снимком это настоящее приветствие клиента; без снимка — заготовка
           холодного старта: форма та же, байты не те. Коробка вправе смотреть
           на содержимое, а не только на длину (§6), поэтому доказательства
           разной силы, и привязка обязана помнить, какое у неё. */
        d2k_catalog cI;
        memset(&cI, 0, sizeof cI);
        saidbuf[0] = '\0';
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        confirm_once(&cI, sv[0], "холодная.цель", 40150);
        const d2k_cat_binding *bd = binding_of(&cI, "холодная.цель", 6);
        CHECK(bd != NULL && bd->input == D2K_INPUT_PROFILE,
              "замер заготовкой записан как замер байтами клиента");
        CHECK(said("ЗАГОТОВКОЙ холодного старта"),
              "слабость входа не названа вслух — из отчёта её не узнать");
        d2k_catalog_free(&cI);

        d2k_catalog cJ;
        memset(&cJ, 0, sizeof cJ);
        saidbuf[0] = '\0';
        d2k_sched *s = d2k_sched_new(&cJ, sv[0], 0x2d);
        CHECK(s != NULL, "планировщик для замера снимком не завёлся");
        if (s) {
            d2k_sched_set_say(s, collect_say, NULL);
            ver_answer_port = 40151;
            ver_calls = 0;
            forget_sent();
            d2k_ev sh;
            memset(&sh, 0, sizeof sh);
            sh.kind = D2K_EV_SHAPE;
            sh.transport = 6;
            CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, "снятая.цель",
                                         sh.shape, sizeof sh.shape, &sh.shape_len) == 0,
                  "снимок для замера не собрался");
            d2k_sched_event(s, &sh);
            d2k_ev h = ev_hello(6, 40151, "снятая.цель");
            d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 40151);
            d2k_sched_event(s, &su);
            settle(s);
            d2k_ev ap = ev_applied(6, 40151);
            d2k_sched_event(s, &ap);
            spin(s, 40);
            const d2k_cat_binding *b2 = binding_of(&cJ, "снятая.цель", 6);
            CHECK(b2 != NULL && b2->input == D2K_INPUT_CLIENT,
                  "замер снятыми байтами клиента записан как замер заготовкой");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&cJ);
    }

    /* --- СЛАБЫЙ ВХОД ПЕРЕМЕРЯЕТСЯ, КОГДА ПРИХОДИТ СНИМОК --------------- */
    {
        /* Обещание «перемеряю снимком» обязано быть механизмом, а не
           оговоркой в отчёте: пока привязка добыта заготовкой, байты
           настоящего клиента не проверял никто. */
        d2k_catalog cK;
        memset(&cK, 0, sizeof cK);
        saidbuf[0] = '\0';
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        d2k_sched *s = d2k_sched_new(&cK, sv[0], 0x2d);
        CHECK(s != NULL, "планировщик для перемера не завёлся");
        if (s) {
            d2k_sched_set_say(s, collect_say, NULL);
            ver_answer_port = 40160;
            ver_calls = 0;
            forget_sent();
            d2k_ev h = ev_hello(6, 40160, "перемерю.цель");
            d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 40160);
            d2k_sched_event(s, &su);
            settle(s);
            d2k_ev ap = ev_applied(6, 40160);
            d2k_sched_event(s, &ap);
            spin(s, 40);
            const d2k_cat_binding *bd = binding_of(&cK, "перемерю.цель", 6);
            CHECK(bd != NULL && bd->input == D2K_INPUT_PROFILE,
                  "холодный старт не записан заготовкой — перемерять нечего");

            /* Датапат снял приветствие этой цели. */
            ver_answer_port = 40161;
            d2k_ev sh;
            memset(&sh, 0, sizeof sh);
            sh.kind = D2K_EV_SHAPE;
            sh.transport = 6;
            CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, "перемерю.цель",
                                         sh.shape, sizeof sh.shape, &sh.shape_len) == 0,
                  "снимок для перемера не собрался");
            d2k_sched_event(s, &sh);
            CHECK(said("перемеряю снимком"),
                  "снимок пришёл, а обещанного перемера не случилось");
            settle(s);
            d2k_ev ap2 = ev_applied(6, 40161);
            d2k_sched_event(s, &ap2);
            spin(s, 40);
            bd = binding_of(&cK, "перемерю.цель", 6);
            CHECK(bd != NULL && bd->input == D2K_INPUT_CLIENT,
                  "перемер снимком не поднял полноту входа привязки");
            CHECK(bindings_of(&cK, "перемерю.цель", 6) == 1,
                  "перемер завёл вторую привязку вместо обновления прежней");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&cK);
    }

    /* --- QUIC БЕЗ ЧИТАЕМОГО ИМЕНИ: ЦЕЛЬ ПО АДРЕСУ --------------------------
     *
     * Поле 19.09.2026: настоящий клиент разбрасывает ClientHello так, что имя
     * из него не читается ни датапатом, ни коробкой. Подозрение о таком потоке
     * приходит БЕЗ имени. Цель — адрес сервера; донорский Run должен получить
     * буквальный IP и собрать собственный ClientHello без SNI. Непроверенный
     * delay не должен устанавливаться вместо измерения. */
    {
        uint16_t saved_port = g_server_port;
        g_server_port = 443;
        d2k_catalog cQ;
        memset(&cQ, 0, sizeof cQ);
        saidbuf[0] = '\0';
        d2k_sched *s = d2k_sched_new(&cQ, sv[0], 0x2d);
        CHECK(s != NULL, "планировщик для адресной цели не завёлся");
        if (s) {
            d2k_sched_set_say(s, collect_say, NULL);
            tcp_calls = quic_calls = vol_calls = 0;
            ver_calls = 0;
            quic_calls = 0;
            quic_answer = D2K_V_CLEAR;
            forget_sent();
            /* Приветствия по этому потоку НЕ было: имя не прочиталось. */
            d2k_ev su = ev_suspect(17, 40400);
            d2k_sched_event(s, &su);
            spin(s, 20);
            drain();
            CHECK(quic_calls == 1 && strcmp(quic_last_ip, "127.0.0.1") == 0 &&
                  strcmp(quic_last_sni, "127.0.0.1") == 0,
                  "безымянная QUIC-цель не прошла через полный измеритель как буквальный IP");
            CHECK(strcmp(quic_last_trig, "<без SNI>") == 0 &&
                  strcmp(quic_last_ctl, "<без SNI>") != 0,
                  "адресный Run не сохранил SNI-less trigger и отдельный контроль");
            CHECK(sent_command_count(D2K_CMD_SET_ADDR, NULL, 0) == 0,
                  "неизмеренный delay установлен вместо donor Run");
            CHECK(ver_calls == 0,
                  "чистый donor verdict неожиданно запустил кандидатную верификацию");

            d2k_ev ap = ev_applied(17, 40401);
            d2k_sched_event(s, &ap);
            d2k_ev ex = ev_exchange(17, 40401, 0);
            ex.num = 0; /* даже пустая обратная датаграмма порождает событие */
            d2k_sched_event(s, &ex);
            spin(s, 20);
            const d2k_cat_binding *bd = binding_of(&cQ, "127.0.0.1", 17);
            CHECK(bd == NULL && cQ.n_boxes == 0,
                  "произвольный UDP-ответ создал подтверждение/коробку адресной цели");
            CHECK(!said("ПОДТВЕРЖДЕНО"),
                  "произвольный UDP-ответ назван подтверждением QUIC-успеха");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&cQ);
        g_server_port = saved_port;
    }

    /* Два безымянных QUIC-адреса остаются двумя задачами, каждая идёт через
       donor Run со своим literal IP и без SNI. Никакой delay не выставляется
       только из факта подозрения. */
    {
        uint16_t saved_port = g_server_port;
        g_server_port = 443;
        d2k_catalog cQ = {0};
        d2k_sched *s = d2k_sched_new(&cQ, sv[0], 0x2d);
        CHECK(s != NULL, "планировщик нескольких адресных целей не завёлся");
        if (s) {
            d2k_sched_set_say(s, collect_say, NULL);
            quic_answer = D2K_V_CLEAR;
            quic_calls = 0;
            forget_sent();
            d2k_ev a = ev_suspect(17, 40410);
            d2k_sched_event(s, &a);
            d2k_ev b = ev_suspect(17, 40411);
            b.low_ip[3] = 2;
            d2k_sched_event(s, &b);
            spin(s, 20);
            CHECK(quic_calls == 2, "два адреса не получили два независимых QUIC Run");
            CHECK(strcmp(quic_seen_ips[0], "127.0.0.1") == 0 &&
                  strcmp(quic_seen_snis[0], "127.0.0.1") == 0 &&
                  strcmp(quic_seen_targets[0], "<без SNI>") == 0,
                  "первый адресный Run подменил цель или его SNI");
            CHECK(strcmp(quic_seen_ips[1], "127.0.0.2") == 0 &&
                  strcmp(quic_seen_snis[1], "127.0.0.2") == 0 &&
                  strcmp(quic_seen_targets[1], "<без SNI>") == 0,
                  "второй адресный Run потерял собственный target context");
            CHECK(sent_command_count(D2K_CMD_SET_ADDR, NULL, 0) == 0 &&
                  cQ.n_boxes == 0,
                  "подозрение или UDP EXCHANGE создали неизмеренный address Plan/успех");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&cQ);
        g_server_port = saved_port;
    }

    /* Адресный кандидат не может идти через SET_NAME_PROBE (у цели нет SNI)
       и не может временно ставиться общим SET_ADDR (это затронет чужие
       потоки к тому же IP). Для него нужен отдельный exact-flow probe overlay. */
    {
        uint16_t saved_port = g_server_port;
        d2k_sched_ver_fn saved_ver = d2k_sched_ver_hook;
        uint8_t saved_local_ip4[4];
        memcpy(saved_local_ip4, ver_local_ip4, sizeof saved_local_ip4);
        g_server_port = 443;
        d2k_catalog cQ = {0};
        d2k_sched *s = d2k_sched_new(&cQ, sv[0], 0x2d);
        CHECK(s != NULL, "планировщик адресного кандидата не завёлся");
        if (s) {
            d2k_sched_set_say(s, collect_say, NULL);
            quic_answer = D2K_V_PREFIX;
            ver_answer = D2K_VER_APPLICATION;
            ver_answer_port = 40450;
            quic_calls = 0;
            ver_calls = 0;
            forget_sent();
            d2k_ev su = ev_suspect(17, 40450);
            su.low_ip[3] = 9;
            d2k_sched_event(s, &su);
            spin_until_installed(s);
            CHECK(quic_calls == 1,
                  "безымянная QUIC-цель не прошла через donor Run");
            uint8_t src_ip4[4], trial_id[D2K_TRIAL_ID_LEN];
            uint16_t src_port_be = 0;
            CHECK(last_addr_probe_endpoint(src_ip4, &src_port_be, trial_id),
                  "SET_ADDR_PROBE не несёт зарезервированный endpoint и trial ID");
            CHECK(sent_command_count(D2K_CMD_SET_ADDR_PROBE, NULL, 0) >= 1,
                  "адресный кандидат не установлен отдельной SET_ADDR_PROBE-командой");
            CHECK(sent_command_count(D2K_CMD_SET_NAME_PROBE, NULL, 0) == 0,
                  "адресный кандидат ошибочно установлен как проба по имени");
            CHECK(sent_command_count(D2K_CMD_SET_ADDR, NULL, 0) == 0,
                  "временный адресный кандидат утёк в постоянную таблицу адресов");
            if (src_port_be != 0) {
                memcpy(ver_local_ip4, src_ip4, 4);
                ver_answer_port = ntohs(src_port_be);
                d2k_ev applied = ev_applied(17, ver_answer_port);
                applied.low_ip[0] = 127; applied.low_ip[1] = 0;
                applied.low_ip[2] = 0; applied.low_ip[3] = 9;
                applied.low_port = 443;
                memcpy(applied.high_ip, src_ip4, 4);
                applied.high_port = ntohs(src_port_be);
                memcpy(applied.trial_id, trial_id, sizeof trial_id);
                d2k_ev stale = applied;
                stale.trial_id[0] ^= 0x80u;
                d2k_sched_event(s, &stale);
                spin(s, 20);
                CHECK(binding_of(&cQ, "127.0.0.9", 17) == NULL &&
                      sent_command_count(D2K_CMD_SET_ADDR, NULL, 0) == 0,
                      "stale APPLIED с тем же Plan/flow, но чужим trial ID не должен promote-ить адрес");
                d2k_sched_event(s, &applied);
                d2k_ev ack;
                memset(&ack, 0, sizeof ack);
                ack.kind = D2K_EV_ACK;
                ack.code = D2K_CMD_SET_ADDR_PROBE;
                ack.num = 0x100u;
                memcpy(ack.trial_id, trial_id, sizeof trial_id);
                d2k_sched_event(s, &ack);
                spin(s, 20);
                const d2k_cat_binding *bd = binding_of(&cQ, "127.0.0.9", 17);
                CHECK(bd && strcmp(bd->kind, "addr") == 0 &&
                      strcmp(bd->target, "127.0.0.9") == 0,
                      "QUIC application proof + exact Plan/trial evidence не создали addr binding");
                CHECK(sent_command_count(D2K_CMD_SET_ADDR, NULL, 0) == 1,
                      "подтверждённый адресный план не продвинут в постоянную таблицу");
                drain();
                CHECK(sent_command_count(D2K_CMD_DEL_ADDR_PROBE, NULL, 0) >= 1,
                      "успешный адресный trial не удалил только свою временную пробу");
            }
            d2k_sched_free(s);
        }
        memcpy(ver_local_ip4, saved_local_ip4, sizeof saved_local_ip4);
        d2k_catalog_free(&cQ);
        d2k_sched_ver_hook = saved_ver;
        g_server_port = saved_port;
    }

    /* Адресный lifecycle: параллельные задачи не смешивают destination и
       поколения даже когда у них один и тот же измеренный Plan. */
    {
        uint16_t saved_port = g_server_port;
        g_server_port = 443;
        d2k_catalog cQ = {0};
        d2k_sched *s = d2k_sched_new(&cQ, sv[0], 0x2d);
        CHECK(s != NULL, "планировщик параллельных адресных опытов не завёлся");
        if (s) {
            d2k_sched_set_say(s, collect_say, NULL);
            quic_answer = D2K_V_PREFIX;
            ver_answer = D2K_VER_APPLICATION;
            ver_fail_first = 1; /* first candidate fails, next one is usable */
            quic_calls = ver_calls = 0;
            forget_sent();
            d2k_ev a = ev_suspect(17, 40460);
            d2k_ev b = ev_suspect(17, 40461);
            b.low_ip[3] = 2;
            d2k_sched_event(s, &a);
            d2k_sched_event(s, &b);
            for (int i = 0; i < 400 &&
                 sent_command_count(D2K_CMD_SET_ADDR_PROBE, NULL, 0) < 2; i++) {
                tick_once(s);
            }
            uint8_t ips[4][4], ids[4][D2K_TRIAL_ID_LEN];
            uint16_t sports[4] = {0};
            size_t n = collect_addr_probes(ips, ids, sports, 4);
            CHECK(n >= 2, "две адресные задачи не получили независимые SET_ADDR_PROBE");
            if (n >= 2) {
                CHECK((ips[0][3] == 1 && ips[1][3] == 2) ||
                      (ips[0][3] == 2 && ips[1][3] == 1),
                      "параллельные адресные пробы потеряли destination");
                CHECK(memcmp(ids[0], ids[1], D2K_TRIAL_ID_LEN) != 0,
                      "параллельные адресные пробы разделяют trial generation");
                CHECK(sports[0] != 0 && sports[1] != 0 && sports[0] != sports[1],
                      "параллельные адресные пробы разделяют локальный verifier port");
            }
            d2k_sched_free(s);
        }
        d2k_catalog_free(&cQ);
        g_server_port = saved_port;
    }

    /* Отказ/неуспех кандидата обязан снять только старое поколение и
       поставить следующий опыт с новым UDP-портом и trial ID. */
    {
        uint16_t saved_port = g_server_port;
        g_server_port = 443;
        d2k_catalog cQ = {0};
        d2k_sched *s = d2k_sched_new(&cQ, sv[0], 0x2d);
        CHECK(s != NULL, "планировщик retry адресной пробы не завёлся");
        if (s) {
            d2k_sched_set_say(s, collect_say, NULL);
            quic_answer = D2K_V_PREFIX;
            ver_answer = D2K_VER_HANDSHAKE;
            ver_fail_first = 0;
            quic_calls = ver_calls = 0;
            forget_sent();
            d2k_ev su = ev_suspect(17, 40470);
            su.low_ip[3] = 7;
            d2k_sched_event(s, &su);
            for (int i = 0; i < 400 &&
                 sent_command_count(D2K_CMD_SET_ADDR_PROBE, NULL, 0) < 1; i++) {
                tick_once(s);
            }
            drain();
            uint8_t first_ip[4], first_id[D2K_TRIAL_ID_LEN];
            uint16_t first_port = 0;
            CHECK(last_addr_probe_endpoint(first_ip, &first_port, first_id),
                  "первое поколение адресной пробы не зафиксировано");
            size_t before_del = sent_command_count(D2K_CMD_DEL_ADDR_PROBE, NULL, 0);
            for (int i = 0; i < 500 &&
                 sent_command_count(D2K_CMD_SET_ADDR_PROBE, NULL, 0) < 2; i++) {
                tick_once(s);
            }
            uint8_t ips[4][4], ids[4][D2K_TRIAL_ID_LEN];
            uint16_t sports[4] = {0};
            size_t n = collect_addr_probes(ips, ids, sports, 4);
            CHECK(n == 1, "после исчерпания единственного измеренного arm появился чужой retry");
            if (n == 1) {
                CHECK(memcmp(ids[0], first_id, D2K_TRIAL_ID_LEN) == 0,
                      "единственный address trial изменился сам по себе");
                CHECK(sports[0] == first_port,
                      "единственный address trial получил неожиданный порт");
            }
            CHECK(sent_command_count(D2K_CMD_DEL_ADDR_PROBE, NULL, 0) > before_del,
                  "старое поколение адресной пробы не снято перед retry");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&cQ);
        g_server_port = saved_port;
    }

    /* Таймаут задачи — это не успех и не вечная lease: временный address
       probe должен быть снят exact-командой, постоянный SET_ADDR не появляется. */
    {
        uint16_t saved_port = g_server_port;
        g_server_port = 443;
        d2k_catalog cQ = {0};
        d2k_sched *s = d2k_sched_new(&cQ, sv[0], 0x2d);
        CHECK(s != NULL, "планировщик timeout адресной пробы не завёлся");
        if (s) {
            d2k_sched_set_say(s, collect_say, NULL);
            quic_answer = D2K_V_PREFIX;
            ver_answer = D2K_VER_APPLICATION;
            /* Keep the verifier unsuccessful while the task itself reaches
               its ten-minute lifetime; the first probe must still remain
               observable before that timeout. */
            ver_fail_first = 100000;
            quic_calls = ver_calls = 0;
            forget_sent();
            d2k_ev su = ev_suspect(17, 40480);
            su.low_ip[3] = 8;
            d2k_sched_event(s, &su);
            for (int i = 0; i < 400 &&
                 sent_command_count(D2K_CMD_SET_ADDR_PROBE, NULL, 0) < 1; i++) {
                tick_once(s);
            }
            drain();
            CHECK(sent_command_count(D2K_CMD_SET_ADDR_PROBE, NULL, 0) == 1,
                  "timeout-тест не дошёл до единственной адресной пробы");
            size_t del_before = sent_command_count(D2K_CMD_DEL_ADDR_PROBE, NULL, 0);
            skip_ahead(s, 10 * 60 * 1000 + 1);
            CHECK(sent_command_count(D2K_CMD_DEL_ADDR_PROBE, NULL, 0) > del_before,
                  "истёкшая адресная задача не сняла exact address probe");
            CHECK(sent_command_count(D2K_CMD_SET_ADDR, NULL, 0) == 0 &&
                  cQ.n_boxes == 0,
                  "таймаут адресной пробы создал постоянное знание");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&cQ);
        g_server_port = saved_port;
    }

    /* --- ГОЛОС: C-ЗАМЕР И ВРЕМЕННЫЙ PLAN ----------------------------------
       Сам голосовой сервер молчит на посторонние пробы (поле 17.09), поэтому
       подтверждать обход ими нельзя. Измеритель берёт цель из живого потока,
       спрашивает публичный STUN-контроль и подбирает arm по исходному списку.
       Plan ставится на voice-класс, а последующий ответ самого разговора
       остаётся только наблюдением: каталог от него не пополняется. */
voice_only_run:
    {
        uint16_t saved_port = g_server_port;
        d2k_sched_voice_fn saved_voice_hook = d2k_sched_voice_hook;
        d2k_sched_voice_hook = stub_voice;
        g_server_port = 50004;
        d2k_catalog cV;
        memset(&cV, 0, sizeof cV);
        saidbuf[0] = '\0';
        d2k_sched *s = d2k_sched_new(&cV, sv[0], 0x2d);
        CHECK(s != NULL, "планировщик для голоса не завёлся");
        if (s) {
            d2k_sched_set_say(s, collect_say, NULL);
            const uint8_t expected_arm[] = {0xa1, 0xb2, 0xc3, 0xd4};
            const uint8_t expected_fake[] = {
                0x01, 0x01, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x01,
                0x06, 0x00, 0x00, 0x00, 0x00, 0x00
            };
            tcp_calls = quic_calls = vol_calls = 0;
            ver_calls = voice_calls = 0;
            forget_sent();
            d2k_ev h = ev_hello(17, 40200, D2K_LINK_VOICE_CLASS);
            d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(17, 40200);
            d2k_sched_event(s, &su);
            spin(s, 20);
            drain();
            CHECK(voice_calls == 1, "scheduler не вызвал C voice-измеритель");
            CHECK(sent_has_bytes(expected_arm, sizeof expected_arm) &&
                  sent_has_bytes(expected_fake, sizeof expected_fake) &&
                  said("arm active_discord_udp ×6"),
                  "voice Plan не сохранил точные байты найденного arm и его число повторов");
            CHECK(said("найденный исходным перебором arm"),
                  "результат C voice-измерителя не отражён в журнале");
            /* Кандидат голоса ставится не на класс, а на точную пятёрку (ниже):
               класс получает только подтверждённый план (voice_confirm). */
            /* Задача 15: опыт — клиент LAN + точка сервера + ЛЮБОЙ клиентский
               порт, с trial ID. Портовая запись имени пользовательскому
               трафику не видна, а разговор во время замера уже за окном
               экрана (первые 8 пакетов) — опыт ждёт следующего потока. */
            uint8_t vsrc[4], vtrial[D2K_TRIAL_ID_LEN];
            uint16_t vsport = 0;
            CHECK(sent_command_count(D2K_CMD_SET_ADDR_PROBE, NULL, 0) == 1 &&
                  sent_command_count(D2K_CMD_SET_NAME_PROBE, NULL, 0) == 0 &&
                  last_addr_probe_endpoint(vsrc, &vsport, vtrial) &&
                  memcmp(vsrc, "\xc0\xa8\x01\x43", 4) == 0 &&
                  vsport == 0,
                  "voice Plan не ограничен клиентом LAN и точкой сервера");
            /* Опыт ждёт дольше lease датапата — продление тем же поколением. */
            forget_sent();
            skip_ahead(s, 61 * 1000);
            uint8_t rsrc[4], rtrial[D2K_TRIAL_ID_LEN];
            uint16_t rsport = 1;
            CHECK(sent_command_count(D2K_CMD_SET_ADDR_PROBE, NULL, 0) == 1 &&
                  last_addr_probe_endpoint(rsrc, &rsport, rtrial) && rsport == 0 &&
                  memcmp(rtrial, vtrial, sizeof vtrial) == 0,
                  "голосовой опыт не продлён тем же trial ID");
            CHECK(tcp_calls == 0 && quic_calls == 0 && ver_calls == 0,
                  "по голосу пошёл замер или зонд, которые мерить его не могут");
            CHECK(!said("жду форму приветствия"),
                  "голос принят за QUIC и ждёт снимка Initial");
            /* Посторонний голосовой поток не должен забрать план, найденный
               измерением конкретной conntrack-пятёрки. */
            d2k_ev ap = ev_applied(17, 40201);
            memcpy(ap.trial_id, vtrial, sizeof vtrial);
            ap.high_ip[3] = 68;                 /* другой клиент LAN */
            d2k_sched_event(s, &ap);
            ap = ev_applied(17, 40201);
            memcpy(ap.trial_id, vtrial, sizeof vtrial);
            ap.low_port = 50005;                /* другая точка сервера */
            d2k_sched_event(s, &ap);
            d2k_ev ex = ev_exchange(17, 40201, 0);
            d2k_sched_event(s, &ex);
            spin(s, 20);
            CHECK(!said("UDP-ответ наблюдался"),
                  "посторонний голосовой поток выбран для измеренного arm");
            /* Следующий поток того же клиента, тот же Plan ID, но без trial ID
               опыта — это не наш опыт: один plan hash опыта не называет. */
            ap = ev_applied(17, 40201);
            d2k_sched_event(s, &ap);
            ex = ev_exchange(17, 40201, 0);
            d2k_sched_event(s, &ex);
            spin(s, 20);
            CHECK(!said("UDP-ответ наблюдался"),
                  "APPLIED без trial ID опыта признан применением голосового опыта");
            /* Следующий разговор того же клиента к той же точке (новый
               клиентский порт) с trial ID опыта становится WATCH. */
            ap = ev_applied(17, 40201);
            memcpy(ap.trial_id, vtrial, sizeof vtrial);
            d2k_sched_event(s, &ap);
            ex = ev_exchange(17, 40201, 0);
            d2k_sched_event(s, &ex);
            spin(s, 20);
            const d2k_cat_binding *bd = binding_of(&cV, D2K_LINK_VOICE_CLASS, 17);
            CHECK(bd == NULL && cV.n_boxes == 0,
                  "произвольный UDP-ответ записал голос подтверждённым");
            CHECK(said("UDP-ответ наблюдался") && !said("ПОДТВЕРЖДЕНО"),
                  "UDP-наблюдение голоса потеряно либо названо подтверждением");
            ex.code = D2K_UDP_PROOF_VOICE_DISCOVERY;
            d2k_sched_event(s, &ex); spin(s,20);
            CHECK(cV.n_boxes == 0 && !said("ПОДТВЕРЖДЕНО"),
                  "one Discovery answer without sustained bypass probes creates global voice policy");
            forget_sent();
            skip_ahead(s, 10 * 60 * 1000 + 1);
            CHECK(sent_command_count(D2K_CMD_DEL_ADDR_PROBE, NULL, 0) == 1 &&
                  sent_command_count(D2K_CMD_DEL_NAME, NULL, 0) == 0 &&
                  sent_command_count(D2K_CMD_DEL_NAME_PROBE, NULL, 0) == 0,
                  "UDP-ответ оставил неподтверждённый голосовой кандидат навсегда");
            CHECK(said("не проверено") && !said("не пробил"),
                  "истёкший голосовой опыт не назван «не проверено» либо назван провалом");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&cV);

        d2k_catalog cS;
        memset(&cS, 0, sizeof cS);
        saidbuf[0] = '\0';
        s = d2k_sched_new(&cS, sv[0], 0x2d);
        if (s) {
            d2k_sched_set_say(s, collect_say, NULL);
            forget_sent();
            /* Оба порта выше эфемерной границы: server_of выбирает меньший,
               то есть адрес сервера 127.0.0.1, а не клиента 192.168.1.67. */
            d2k_ev h = ev_hello(17, 52005, D2K_LINK_VOICE_CLASS);
            d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(17, 52005);
            d2k_sched_event(s, &su);
            spin(s, 20);
            drain();
            uint8_t ssrc_ip[4], strial[D2K_TRIAL_ID_LEN];
            uint16_t ssport = 0;
            CHECK(last_addr_probe_endpoint(ssrc_ip, &ssport, strial),
                  "STUN-опыт не поставлен на точную пятёрку");
            d2k_ev ap = ev_applied(17, 52005);
            memcpy(ap.trial_id, strial, sizeof strial);
            d2k_sched_event(s, &ap);
            d2k_ev ex = ev_exchange(17, 52005, 0);
            ex.code = D2K_UDP_PROOF_STUN;
            d2k_sched_event(s, &ex);
            spin(s, 20);
            const d2k_cat_binding *bd = binding_of(&cS, "127.0.0.1", 17);
            CHECK(bd != NULL && strcmp(bd->kind, "addr") == 0 &&
                  strcmp(bd->target, "127.0.0.1") == 0 &&
                  bd->verified_by == D2K_VERBY_STUN,
                  "валидный STUN proof не создал адресную STUN-привязку");
            CHECK(sent_command_count(D2K_CMD_SET_ADDR, NULL, 0) == 1 &&
                  sent_command_count(D2K_CMD_SET_NAME, NULL, 0) == 0,
                  "STUN proof записал общий voice class вместо IP цели");
            CHECK(sent_command_count(D2K_CMD_DEL_ADDR_PROBE, NULL, 0) == 1,
                  "подтверждённый STUN оставил временный опыт пятёрки");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&cS);

        /* A sustained Discovery remedy is scoped to the measured address,
           not the global @discord-voice classifier label. */
        memset(&cS, 0, sizeof cS);
        voice_discovery_fixture = 1;
        s = d2k_sched_new(&cS, sv[0], 0x2d);
        if (s) {
            forget_sent();
            d2k_ev h = ev_hello(17, 52005, D2K_LINK_VOICE_CLASS);
            d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(17, 52005);
            d2k_sched_event(s, &su);
            spin(s, 20); drain();
            uint8_t src[4], trial[D2K_TRIAL_ID_LEN]; uint16_t sport = 0;
            CHECK(last_addr_probe_endpoint(src, &sport, trial), "Discovery trial missing");
            d2k_ev ap = ev_applied(17, 52005);
            memcpy(ap.trial_id, trial, sizeof trial);
            d2k_sched_event(s, &ap);
            d2k_ev ex = ev_exchange(17, 52005, 0);
            ex.code = D2K_UDP_PROOF_VOICE_DISCOVERY;
            d2k_sched_event(s, &ex); spin(s, 20); drain();
            const d2k_cat_binding *bd = binding_of(&cS, "127.0.0.1", 17);
            CHECK(bd && !strcmp(bd->kind, "addr") && bd->verified_by == D2K_VERBY_VOICE_DISCOVERY,
                  "sustained Discovery did not retain address scope");
            CHECK(sent_command_count(D2K_CMD_SET_NAME, NULL, 0) == 0,
                  "one Discovery endpoint became a global voice policy");
            char live_path[128];snprintf(live_path,sizeof live_path,"/tmp/d2k-voice-live-%ld.json",(long)getpid());
            CHECK(d2k_sched_write_live(s,live_path,NULL)==0,"voice live diagnostic write");
            FILE *vf=fopen(live_path,"rb");char vb[32768]={0};
            if(vf){(void)!fread(vb,1,sizeof vb-1,vf);fclose(vf);}
            CHECK(strstr(vb,"BYPASS_PROBE_PASSED") && strstr(vb,"audio_verified") &&
                  strstr(vb,"192.168.1.67"),"voice diagnostics lose probe scope or client identity");
            unlink(live_path);

            d2k_sched_free(s);
        }
        s = d2k_sched_new(&cS, sv[0], 0x2d);
        if (s) {
            forget_sent(); (void)d2k_sched_sync(s);
            int rounds = 0;
            while (d2k_sched_sync_step(s) && rounds++ < 1000) drain();
            drain(); const uint8_t target[4] = {127,0,0,1};
            CHECK(sent_set_addr_shape(4, target, D2K_LINK_SHAPE_VOICE) == 1,
                  "saved Discovery remedy did not restore as address/voice");
            CHECK(sent_command_count(D2K_CMD_SET_NAME, NULL, 0) == 0,
                  "restored Discovery remedy became a global voice policy");
            forget_sent(); voice_seen_known=0;
            d2k_ev h=ev_hello(17,52005,D2K_LINK_VOICE_CLASS);
            d2k_sched_event(s,&h);
            d2k_ev su=ev_suspect(17,52005);
            d2k_sched_event(s,&su);spin(s,20);drain();
            CHECK(voice_seen_known && sent_command_count(D2K_CMD_SET_ADDR_PROBE,NULL,0)==0,
                  "working saved Discovery remedy restarted candidate search");
            d2k_sched_free(s);
        }
        s = d2k_sched_new(&cS, sv[0], 0x2d);
        if (s) {
            forget_sent();voice_candidate_seen=0;
            d2k_ev h=ev_hello(17,52005,D2K_LINK_VOICE_CLASS);
            memcpy(h.low_ip,"\x23\xd9\x38\xc3",4);d2k_sched_event(s,&h);
            d2k_ev su=ev_suspect(17,52005);memcpy(su.low_ip,h.low_ip,4);
            d2k_sched_event(s,&su);spin(s,20);drain();
            CHECK(voice_candidate_seen && voice_target_wait>0 && voice_target_wait<=500 &&
                  sent_command_count(D2K_CMD_SET_ADDR_PROBE,NULL,0)==1,
                  "saved remedy on a new endpoint waits through full cold-start timeout");
            d2k_sched_free(s);
        }
        s = d2k_sched_new(&cS, sv[0], 0x2d);
        if (s) {
            forget_sent(); voice_known_fails=2;saidbuf[0]=0;
            d2k_sched_set_say(s,collect_say,NULL);
            d2k_ev h=ev_hello(17,52005,D2K_LINK_VOICE_CLASS);
            d2k_sched_event(s,&h);
            d2k_ev su=ev_suspect(17,52005);
            d2k_sched_event(s,&su);spin(s,20);drain();
            const d2k_cat_binding *b=binding_of(&cS,"127.0.0.1",17);
            CHECK(b && b->recheck_since && b->confirmed && b->enabled,
                  "failed known prefix does not mark only its address binding for recheck");
            CHECK(sent_command_count(D2K_CMD_DEL_ADDR,NULL,0)==1 &&
                  sent_command_count(D2K_CMD_DEL_NAME,NULL,0)==0,
                  "failed known voice binding does not retire only address/voice scope");
            CHECK(!said("сохраняю подтверждённый приём"),
                  "direct CLEAR after a failed prefix is falsely reported as a passing bypass");
            char vp[128];snprintf(vp,sizeof vp,"/tmp/d2k-direct-clear-%ld.json",(long)getpid());
            CHECK(!d2k_sched_write_live(s,vp,NULL),"direct CLEAR diagnostic write");
            FILE *vf=fopen(vp,"rb");char vb[32768]={0};
            if(vf){(void)!fread(vb,1,sizeof vb-1,vf);fclose(vf);}unlink(vp);
            CHECK(!strstr(vb,"BYPASS_PROBE_PASSED"),
                  "direct CLEAR falsely labels a rejected prefix as BYPASS_PROBE_PASSED");

            voice_known_fails=0;d2k_sched_free(s);
        }
        d2k_catalog_free(&cS);
        voice_discovery_fixture = 0;

        /* Задача 16: подтверждённый STUN/голос того же IP не затирает
           подтверждённую QUIC-привязку по адресу. Каждая едет со своей формой
           протокола, DEL_ADDR не посылается, обе переживают перезапуск. */
        d2k_catalog cQ;
        memset(&cQ, 0, sizeof cQ);
        cQ.boxes = calloc(1, sizeof *cQ.boxes);
        CHECK(cQ.boxes != NULL, "каталог QUIC-по-адресу не создан");
        if (cQ.boxes) {
            cQ.n_boxes = 1;
            d2k_cat_box *qb = &cQ.boxes[0];
            snprintf(qb->id, sizeof qb->id, "quic-addr-box");
            qb->plans = calloc(1, sizeof *qb->plans);
            qb->binds = calloc(1, sizeof *qb->binds);
            if (qb->plans && qb->binds) {
                qb->n_plans = qb->n_binds = 1;
                snprintf(qb->plans[0].id, sizeof qb->plans[0].id, "quic-addr-plan");
                snprintf(qb->plans[0].proto, sizeof qb->plans[0].proto, "quic");
                qb->plans[0].enabled = 1;
                qb->plans[0].successes = 1;
                qb->plans[0].text = strdup("d2k-plan 1 6\nid 00000000000000000000000000000000\n"
                                           "proto udp quic\ndelay 15000\n");
                d2k_cat_binding *qbd = &qb->binds[0];
                snprintf(qbd->kind, sizeof qbd->kind, "addr");
                snprintf(qbd->target, sizeof qbd->target, "127.0.0.1");
                snprintf(qbd->plan_id, sizeof qbd->plan_id, "quic-addr-plan");
                qbd->enabled = 1; qbd->level = 3; qbd->confirmed = 42; qbd->successes = 1;
                qbd->transport = 17; qbd->family = 4;
                qbd->shape = D2K_LINK_SHAPE_QUIC; qbd->verified_by = D2K_VERBY_PROBE;
            }
            const uint8_t lo[4] = {127, 0, 0, 1};
            d2k_cat_binding quic_before = qb->binds ? qb->binds[0] : (d2k_cat_binding){0};
            saidbuf[0] = '\0';
            s = d2k_sched_new(&cQ, sv[0], 0x2d);
            if (s) {
                d2k_sched_set_say(s, collect_say, NULL);
                forget_sent();
                (void)d2k_sched_sync(s);
                int rounds = 0;
                while (d2k_sched_sync_step(s) && rounds++ < 1000) { drain(); }
                drain();
                CHECK(sent_set_addr_shape(4, lo, D2K_LINK_SHAPE_QUIC) == 1,
                      "QUIC-привязка по адресу не восстановлена со своей формой");
                forget_sent();
                d2k_ev h = ev_hello(17, 52005, D2K_LINK_VOICE_CLASS);
                d2k_sched_event(s, &h);
                d2k_ev su = ev_suspect(17, 52005);
                d2k_sched_event(s, &su);
                spin(s, 20);
                drain();
                uint8_t ssrc_ip[4], strial[D2K_TRIAL_ID_LEN];
                uint16_t ssport = 0;
                CHECK(last_addr_probe_endpoint(ssrc_ip, &ssport, strial),
                      "STUN-опыт рядом с QUIC-привязкой не поставлен");
                d2k_ev ap = ev_applied(17, 52005);
                memcpy(ap.trial_id, strial, sizeof strial);
                d2k_sched_event(s, &ap);
                d2k_ev ex = ev_exchange(17, 52005, 0);
                ex.code = D2K_UDP_PROOF_STUN;
                d2k_sched_event(s, &ex);
                spin(s, 20);
                drain();
                CHECK(sent_set_addr_shape(4, lo, D2K_LINK_SHAPE_VOICE) == 1 &&
                      sent_command_count(D2K_CMD_SET_ADDR, NULL, 0) == 1,
                      "подтверждённый STUN ушёл не формой голоса");
                CHECK(sent_command_count(D2K_CMD_DEL_ADDR, NULL, 0) == 0,
                      "подтверждение STUN сняло адресную привязку");
                CHECK(bindings_of(&cQ, "127.0.0.1", 17) == 2,
                      "STUN-привязка слилась с QUIC-привязкой того же IP");
                /* box_ensure мог переложить массив коробок — берём заново. */
                const d2k_cat_binding *qnow = cQ.boxes[0].binds;
                CHECK(qnow && !strcmp(qnow->plan_id, quic_before.plan_id) &&
                      qnow->shape == D2K_LINK_SHAPE_QUIC &&
                      qnow->verified_by == D2K_VERBY_PROBE &&
                      qnow->successes == quic_before.successes,
                      "подтверждение STUN переписало QUIC-привязку");
                forget_sent();
                (void)d2k_sched_sync(s);
                rounds = 0;
                while (d2k_sched_sync_step(s) && rounds++ < 1000) { drain(); }
                drain();
                CHECK(sent_set_addr_shape(4, lo, D2K_LINK_SHAPE_QUIC) == 1 &&
                      sent_set_addr_shape(4, lo, D2K_LINK_SHAPE_VOICE) == 1,
                      "после перезапуска QUIC и STUN одного IP не восстановлены раздельно");
                d2k_sched_free(s);
            }
        }
        d2k_catalog_free(&cQ);

        /* Старые адресные привязки без формы: форма выводится только там, где
           она однозначна (STUN-подтверждение — голос, UDP-зонд по адресу —
           QUIC, см. выше); прочие не получают «подходит всем» (§7, §9.11). */
        for (int legacy = 0; legacy < 2; legacy++) {
            d2k_catalog cL;
            memset(&cL, 0, sizeof cL);
            cL.boxes = calloc(1, sizeof *cL.boxes);
            if (!cL.boxes) { continue; }
            cL.n_boxes = 1;
            d2k_cat_box *lb = &cL.boxes[0];
            snprintf(lb->id, sizeof lb->id, "legacy-addr-box");
            lb->plans = calloc(1, sizeof *lb->plans);
            lb->binds = calloc(1, sizeof *lb->binds);
            if (lb->plans && lb->binds) {
                lb->n_plans = lb->n_binds = 1;
                snprintf(lb->plans[0].id, sizeof lb->plans[0].id, "legacy-plan");
                snprintf(lb->plans[0].proto, sizeof lb->plans[0].proto, "stun");
                lb->plans[0].enabled = 1;
                lb->plans[0].text = strdup("d2k-plan 1 6\nid 00000000000000000000000000000000\n"
                                           "proto udp quic\ndelay 15000\n");
                d2k_cat_binding *lbd = &lb->binds[0];
                snprintf(lbd->kind, sizeof lbd->kind, "addr");
                snprintf(lbd->target, sizeof lbd->target, "203.0.113.5");
                snprintf(lbd->plan_id, sizeof lbd->plan_id, "legacy-plan");
                lbd->enabled = 1; lbd->level = 3; lbd->transport = 17;
                lbd->verified_by = legacy == 0 ? D2K_VERBY_STUN : 0;
            }
            saidbuf[0] = '\0';
            s = d2k_sched_new(&cL, sv[0], 0x2d);
            if (s) {
                d2k_sched_set_say(s, collect_say, NULL);
                forget_sent();
                (void)d2k_sched_sync(s);
                int rounds = 0;
                while (d2k_sched_sync_step(s) && rounds++ < 1000) { drain(); }
                drain();
                const uint8_t ip5[4] = {203, 0, 113, 5};
                if (legacy == 0) {
                    CHECK(sent_set_addr_shape(4, ip5, D2K_LINK_SHAPE_VOICE) == 1 &&
                          sent_command_count(D2K_CMD_SET_ADDR, NULL, 0) == 1,
                          "старая STUN-привязка без формы не восстановлена формой голоса");
                } else {
                    CHECK(sent_command_count(D2K_CMD_SET_ADDR, NULL, 0) == 0 &&
                          said("адресных привязок без формы протокола: 1"),
                          "неоднозначная адресная привязка без формы поставлена как общая");
                }
                d2k_sched_free(s);
            }
            d2k_catalog_free(&cL);
        }

        /* Задача 15, сквозной путь Дискорда: опыт на пятёрке разговора →
           APPLIED с trial ID → настоящий IP Discovery response → постоянная
           привязка класса; временный опыт снят точно, своим trial ID. */
        voice_discovery_fixture = 1;
        d2k_catalog cD;
        memset(&cD, 0, sizeof cD);
        saidbuf[0] = '\0';
        s = d2k_sched_new(&cD, sv[0], 0x2d);
        if (s) {
            d2k_sched_set_say(s, collect_say, NULL);
            forget_sent();
            d2k_ev h = ev_hello(17, 52006, D2K_LINK_VOICE_CLASS);
            d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(17, 52006);
            d2k_sched_event(s, &su);
            spin(s, 20);
            drain();
            uint8_t dsrc[4], dtrial[D2K_TRIAL_ID_LEN];
            uint16_t dsport = 0;
            CHECK(last_addr_probe_endpoint(dsrc, &dsport, dtrial) && dsport == 0,
                  "голосовой опыт Дискорда не поставлен на клиента и точку сервера");
            /* Следующий разговор: новый клиентский порт, первый IP Discovery. */
            d2k_ev ap = ev_applied(17, 52016);
            memcpy(ap.trial_id, dtrial, sizeof dtrial);
            d2k_sched_event(s, &ap);
            d2k_ev ex = ev_exchange(17, 52016, 0);
            ex.code = D2K_UDP_PROOF_VOICE_DISCOVERY;
            d2k_sched_event(s, &ex);
            spin(s, 20);
            const d2k_cat_binding *bd = binding_of(&cD, "127.0.0.1", 17);
            CHECK(bd != NULL && strcmp(bd->kind, "addr") == 0 && said("ПОДТВЕРЖДЕНО"),
                  "IP Discovery response после APPLIED опыта не подтвердил голос");
            CHECK(sent_command_count(D2K_CMD_DEL_ADDR_PROBE, NULL, 0) == 1 &&
                  sent_command_count(D2K_CMD_DEL_NAME, NULL, 0) == 0,
                  "подтверждённый голос оставил временный опыт или задел имя");
            /* Задача 17, п.1: доказательство IP Discovery записано своим
               видом, а не «UDP CLIENT», и переживает перезапуск. */
            CHECK(bd != NULL && bd->verified_by == D2K_VERBY_VOICE_DISCOVERY,
                  "подтверждение IP Discovery записано не видом VOICE_DISCOVERY");
            d2k_sched_free(s);
            saidbuf[0] = '\0';
            s = d2k_sched_new(&cD, sv[0], 0x2d);
            if (s) {
                d2k_sched_set_say(s, collect_say, NULL);
                drain();
                forget_sent();
                (void)d2k_sched_sync(s);
                int rounds = 0;
                while (d2k_sched_sync_step(s) && rounds++ < 1000) { drain(); }
                drain();
                CHECK(sent_command_count(D2K_CMD_SET_ADDR, NULL, 0) == 1 &&
                      !said("UDP CLIENT без протокольного"),
                      "после перезапуска подтверждённый IP Discovery голос не поставлен на провод");
                d2k_sched_free(s);
            }
        }
        d2k_catalog_free(&cD);
        voice_discovery_fixture = 0;

        /* Финальное ревью, п.1: пока единственная задача @discord-voice ждёт
           следующего разговора (T_VOICE_TRIAL) к точке A, подозрение голоса
           к ДРУГОЙ точке B не теряется: опыт A снимается точно (свой trial
           ID), и B получает свой замер в том же окне тиков. Истечение опыта
           «не проверено» не ставит общий 10-минутный запрет: новое
           подозрение после него снова мерится. */
        d2k_catalog cR;
        memset(&cR, 0, sizeof cR);
        saidbuf[0] = '\0';
        s = d2k_sched_new(&cR, sv[0], 0x2d);
        if (s) {
            d2k_sched_set_say(s, collect_say, NULL);
            forget_sent();
            voice_calls = 0;
            g_server_port = 50004;
            d2k_ev h = ev_hello(17, 52040, D2K_LINK_VOICE_CLASS);
            d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(17, 52040);
            d2k_sched_event(s, &su);
            spin(s, 20);
            drain();
            uint8_t adst[2][4], atrial[2][D2K_TRIAL_ID_LEN];
            CHECK(voice_calls == 1 &&
                  collect_addr_probes(adst, atrial, NULL, 2) == 1,
                  "голосовой опыт к точке A не поставлен");
            forget_sent();
            g_server_port = 50008;              /* другая точка сервера B */
            h = ev_hello(17, 52041, D2K_LINK_VOICE_CLASS);
            d2k_sched_event(s, &h);
            su = ev_suspect(17, 52041);
            d2k_sched_event(s, &su);
            /* Общий интервал запуска замеров (250 мс) может поставить B в
               очередь — это и есть начало работы, не потеря. */
            spin(s, 400);
            drain();
            uint8_t bdst[2][4], btrial[2][D2K_TRIAL_ID_LEN];
            uint16_t bsport[2] = {1, 1};
            size_t nb = collect_addr_probes(bdst, btrial, bsport, 2);
            CHECK(voice_calls == 2,
                  "подозрение голоса к другой точке сервера потеряно, пока опыт ждал разговора");
            CHECK(sent_command_count(D2K_CMD_DEL_ADDR_PROBE, NULL, 0) == 0,
                  "independent endpoint B must not retire endpoint A trial");
            CHECK(nb == 1 && bsport[0] == 0 &&
                  memcmp(btrial[0], atrial[0], D2K_TRIAL_ID_LEN) != 0,
                  "точка B не получила собственного опыта с новым trial ID");
            /* Та же точка B, пока её опыт ждёт: подозрение не дублирует замер. */
            h = ev_hello(17, 52042, D2K_LINK_VOICE_CLASS);
            d2k_sched_event(s, &h);
            su = ev_suspect(17, 52042);
            d2k_sched_event(s, &su);
            spin(s, 20);
            CHECK(voice_calls == 2,
                  "подозрение к той же точке сбросило ждущий опыт");
            /* Опыт истёк «не проверено» — общий запрет не ставится. */
            skip_ahead(s, 10 * 60 * 1000 + 1);
            CHECK(said("не проверено"), "истечение голосового опыта не названо");
            forget_sent();
            h = ev_hello(17, 52043, D2K_LINK_VOICE_CLASS);
            d2k_sched_event(s, &h);
            su = ev_suspect(17, 52043);
            d2k_sched_event(s, &su);
            spin(s, 20);
            drain();
            CHECK(voice_calls == 3 && !said("замер отложен"),
                  "истёкший «не проверено» голосовой опыт заморозил голос на 10 мин");
            d2k_sched_free(s);
            g_server_port = 50004;
        }
        d2k_catalog_free(&cR);

        /* A WATCH must neither absorb nor block another client's endpoint. */
        memset(&cR, 0, sizeof cR);
        s = d2k_sched_new(&cR, sv[0], 0x2d);
        if (s) {
            forget_sent(); voice_calls = 0;
            g_server_port = 50004;
            d2k_ev h = ev_hello(17, 52100, D2K_LINK_VOICE_CLASS);
            d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(17, 52100);
            d2k_sched_event(s, &su); spin(s, 20); drain();
            uint8_t src[4], trial[D2K_TRIAL_ID_LEN]; uint16_t port;
            CHECK(last_addr_probe_endpoint(src, &port, trial), "client A trial");
            d2k_ev ap = ev_applied(17, 52100);
            memcpy(ap.trial_id, trial, sizeof trial);
            d2k_sched_event(s, &ap);
            h = ev_hello(17, 52102, D2K_LINK_VOICE_CLASS);
            d2k_sched_event(s, &h);
            su = ev_suspect(17, 52102);
            d2k_sched_event(s, &su); spin(s, 400); drain();
            CHECK(voice_calls == 1, "same endpoint reconnect creates competing wildcard trials");
            forget_sent();
            g_server_port = 50008;
            h = ev_hello(17, 52101, D2K_LINK_VOICE_CLASS);
            h.high_ip[3] = 68;
            d2k_sched_event(s, &h);
            su = ev_suspect(17, 52101); su.high_ip[3] = 68;
            d2k_sched_event(s, &su); spin(s, 400); drain();
            CHECK(voice_calls == 2, "client B is blocked by client A WATCH");
            CHECK(sent_command_count(D2K_CMD_DEL_ADDR_PROBE, NULL, 0) == 0,
                  "client B removes active client A trial");
            d2k_sched_free(s); g_server_port = 50004;
        }
        d2k_catalog_free(&cR);

        memset(&cR,0,sizeof cR);
        s=d2k_sched_new(&cR,sv[0],0x2d);
        if(s) {
            forget_sent();g_server_port=50008;
            d2k_ev h=ev_hello(17,40005,D2K_LINK_VOICE_CLASS);
            memcpy(h.low_ip,"\x23\xd9\x3f\x89",4);d2k_sched_event(s,&h);
            d2k_ev su=ev_suspect(17,40005);memcpy(su.low_ip,h.low_ip,4);
            su.client_shape=D2K_LINK_SHAPE_VOICE;d2k_sched_event(s,&su);spin(s,20);drain();
            uint32_t expected;memcpy(&expected,h.low_ip,4);
            CHECK(voice_target_ip==expected && voice_target_port==50008,
                  "lower ephemeral client port is misidentified as voice server");
            d2k_sched_free(s);g_server_port=50004;
        }
        d2k_catalog_free(&cR);

        /* Датапат отверг опыт (NAK) — местный отказ, а не провал кандидата. */
        d2k_catalog cN;
        memset(&cN, 0, sizeof cN);
        saidbuf[0] = '\0';
        s = d2k_sched_new(&cN, sv[0], 0x2d);
        if (s) {
            d2k_sched_set_say(s, collect_say, NULL);
            forget_sent();
            d2k_ev h = ev_hello(17, 52007, D2K_LINK_VOICE_CLASS);
            d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(17, 52007);
            d2k_sched_event(s, &su);
            spin(s, 20);
            drain();
            uint8_t nsrc[4], ntrial[D2K_TRIAL_ID_LEN];
            uint16_t nsport = 1;
            CHECK(last_addr_probe_endpoint(nsrc, &nsport, ntrial),
                  "голосовой опыт для NAK-проверки не ушёл");
            forget_sent();
            d2k_ev nak;
            memset(&nak, 0, sizeof nak);
            nak.kind = D2K_EV_ACK;
            nak.code = D2K_CMD_SET_ADDR_PROBE;
            nak.num = D2K_ACK_NO_ROOM;          /* ok = 0 в старшем байте */
            memcpy(nak.trial_id, ntrial, sizeof ntrial);
            d2k_sched_event(s, &nak);
            spin(s, 5);
            CHECK(said("местный отказ") && !said("не пробил") &&
                  binding_of(&cN, D2K_LINK_VOICE_CLASS, 17) == NULL,
                  "NAK голосового опыта не назван местным отказом");
            /* Задача освобождена: APPLIED с этим trial ID ничего не двигает. */
            d2k_ev ap = ev_applied(17, 52017);
            memcpy(ap.trial_id, ntrial, sizeof ntrial);
            d2k_sched_event(s, &ap);
            d2k_ev ex = ev_exchange(17, 52017, 0);
            ex.code = D2K_UDP_PROOF_VOICE_DISCOVERY;
            d2k_sched_event(s, &ex);
            spin(s, 5);
            CHECK(!said("ПОДТВЕРЖДЕНО"), "отвергнутый опыт подтвердился");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&cN);

        /* Тот же путь, но поток разговора с приёмом МОЛЧИТ. */
        d2k_catalog cW;
        memset(&cW, 0, sizeof cW);
        saidbuf[0] = '\0';
        s = d2k_sched_new(&cW, sv[0], 0x2d);
        if (s) {
            d2k_sched_set_say(s, collect_say, NULL);
            forget_sent();
            d2k_ev h = ev_hello(17, 40210, D2K_LINK_VOICE_CLASS);
            d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(17, 40210);
            d2k_sched_event(s, &su);
            spin(s, 20);
            drain();
            d2k_ev h2 = ev_hello(17, 40210, D2K_LINK_VOICE_CLASS);
            d2k_sched_event(s, &h2);
            uint8_t wsrc[4], wtrial[D2K_TRIAL_ID_LEN];
            uint16_t wsport = 0;
            (void)last_addr_probe_endpoint(wsrc, &wsport, wtrial);
            d2k_ev ap = ev_applied(17, 40210);
            memcpy(ap.trial_id, wtrial, sizeof wtrial);
            d2k_sched_event(s, &ap);
            /* Задача 17, п.8: снятие опыта не дошло до датапата (связь
               оборвана) — опыт остаётся своим и снимается при следующей
               возможности, а не забывается. */
            drain();
            int saved_link = dup(sv[0]);
            int broken[2];
            CHECK(saved_link >= 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, broken) == 0,
                  "не удалось подготовить оборванную связь");
            close(broken[1]);
            dup2(broken[0], sv[0]);
            close(broken[0]);
            d2k_ev su2 = ev_suspect(17, 40210);
            d2k_sched_event(s, &su2);
            spin(s, 20);
            dup2(saved_link, sv[0]);
            close(saved_link);
            CHECK(binding_of(&cW, D2K_LINK_VOICE_CLASS, 17) == NULL,
                  "молчание разговора с приёмом записано подтверждением");
            CHECK(said("не пробил"), "провал приёма голоса не назван");
            forget_sent();
            d2k_sched_free(s);
            drain();
            CHECK(sent_command_count(D2K_CMD_DEL_ADDR_PROBE, NULL, 0) == 1,
                  "неудачное снятие адресной пробы сбросило её принадлежность — "
                  "повторного снятия нет");
        }
        d2k_catalog_free(&cW);

        /* Задача 17, п.7: STUN вне голоса Дискорда приходит безымянным с
           формой голоса/STUN. Это не @discord-voice и не QUIC: поиск не
           запускается, пробел оригинала назван вслух. */
        d2k_catalog cG;
        memset(&cG, 0, sizeof cG);
        saidbuf[0] = '\0';
        s = d2k_sched_new(&cG, sv[0], 0x2d);
        if (s) {
            d2k_sched_set_say(s, collect_say, NULL);
            forget_sent();
            tcp_calls = quic_calls = vol_calls = 0;
            ver_calls = voice_calls = 0;
            d2k_ev su = ev_suspect(17, 52031);
            su.code = D2K_SUSPECT_SILENT;
            su.client_shape = D2K_LINK_SHAPE_VOICE;
            d2k_sched_event(s, &su);
            spin(s, 20);
            drain();
            CHECK(voice_calls == 0 && quic_calls == 0 &&
                  sent_command_count(D2K_CMD_SET_ADDR_PROBE, NULL, 0) == 0 &&
                  binding_of(&cG, D2K_LINK_VOICE_CLASS, 17) == NULL,
                  "безымянный STUN завёл голосовую или QUIC-задачу");
            CHECK(said("не поддержано"),
                  "пробел оригинала для произвольного STUN не назван");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&cG);
        d2k_sched_voice_hook = saved_voice_hook;
        g_server_port = saved_port;
    }
    if (voice_only) { goto voice_only_done; }

    /* --- СНИМОК, ПРИШЕДШИЙ ВО ВРЕМЯ ЗАМЕРА, НЕ ПРОПАДАЕТ ---------------
       Поле 18.09.2026, discord.com: замер начат заготовкой в 1534 байта, а
       снимок настоящего клиента (321 байт, одним сегментом) пришёл в ту же
       секунду — ПОСЛЕ старта. Форма у обоих современная, поэтому повтор по
       расхождению формы не сработал, а крючок на наблюдение ещё не
       существовал: привязка легла заготовкой при снимке на руках. Приём тот
       же, но доказан он не на том, что шлёт клиент. */
    {
        d2k_catalog cL;
        memset(&cL, 0, sizeof cL);
        saidbuf[0] = '\0';
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        d2k_sched *s = d2k_sched_new(&cL, sv[0], 0x2d);
        CHECK(s != NULL, "планировщик для позднего снимка не завёлся");
        if (s) {
            d2k_sched_set_say(s, collect_say, NULL);
            ver_answer_port = 40180;
            ver_calls = 0;
            forget_sent();
            d2k_ev h = ev_hello(6, 40180, "поздний.снимок");
            d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 40180);
            d2k_sched_event(s, &su);
            /* Замер уже идёт заготовкой — и тут снимок. */
            d2k_ev sh;
            memset(&sh, 0, sizeof sh);
            sh.kind = D2K_EV_SHAPE;
            sh.transport = 6;
            CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, "поздний.снимок",
                                         sh.shape, sizeof sh.shape, &sh.shape_len) == 0,
                  "поздний снимок не собрался");
            d2k_sched_event(s, &sh);
            for (int round = 0; round < 3; round++) {
                settle(s);
                d2k_ev ap = ev_applied(6, 40180);
                d2k_sched_event(s, &ap);
                spin(s, 40);
            }
            const d2k_cat_binding *bd = binding_of(&cL, "поздний.снимок", 6);
            CHECK(bd != NULL, "поздний снимок: подтверждения нет вовсе");
            CHECK(bd != NULL && bd->input == D2K_INPUT_CLIENT,
                  "снимок пришёл во время замера, а привязка легла заготовкой");
            CHECK(bindings_of(&cL, "поздний.снимок", 6) == 1,
                  "повтор завёл вторую привязку вместо обновления прежней");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&cL);
    }

    /* --- СНИМОК, ПРИШЕДШИЙ ВО ВРЕМЯ ИСПЫТАНИЯ, ТОЖЕ НЕ ПРОПАДАЕТ ---------
       Третий порядок событий: замер кончился, кандидат испытывается — и тут
       снимок. Повтор после замера уже прошёл, крючок наблюдения ещё не
       взведён; без отдельной проверки у подтверждения привязка легла бы
       заготовкой при снимке на руках. */
    {
        d2k_catalog cM;
        memset(&cM, 0, sizeof cM);
        saidbuf[0] = '\0';
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        d2k_sched *s = d2k_sched_new(&cM, sv[0], 0x2d);
        CHECK(s != NULL, "планировщик для снимка во время испытания не завёлся");
        if (s) {
            d2k_sched_set_say(s, collect_say, NULL);
            ver_answer_port = 40190;
            ver_calls = 0;
            forget_sent();
            d2k_ev h = ev_hello(6, 40190, "снимок.при.испытании");
            d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 40190);
            d2k_sched_event(s, &su);
            settle(s);   /* замер кончился, кандидат на испытании */
            d2k_ev sh;
            memset(&sh, 0, sizeof sh);
            sh.kind = D2K_EV_SHAPE;
            sh.transport = 6;
            CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, "снимок.при.испытании",
                                         sh.shape, sizeof sh.shape, &sh.shape_len) == 0,
                  "снимок при испытании не собрался");
            d2k_sched_event(s, &sh);
            for (int round = 0; round < 3; round++) {
                d2k_ev ap = ev_applied(6, 40190);
                d2k_sched_event(s, &ap);
                spin(s, 40);
                settle(s);
            }
            const d2k_cat_binding *bd = binding_of(&cM, "снимок.при.испытании", 6);
            CHECK(bd != NULL, "снимок при испытании: подтверждения нет вовсе");
            CHECK(bd != NULL && bd->input == D2K_INPUT_CLIENT,
                  "снимок пришёл во время испытания, а привязка осталась заготовкой");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&cM);
    }

    /* --- ДВЕ ФОРМЫ ОДНОЙ ЦЕЛИ ЕДУТ ДАТАПАТУ КАЖДАЯ СО СВОЕЙ ------------
       Область применимости (пункт 3): успех, добытый одной формой, не
       переносится на другую. С двумя зондами (TLS 1.3 и TLS 1.2) у одной цели
       законно бывают две привязки — браузер и старый клиент, — и каждая
       обязана уехать под СВОЕЙ формой. Датапат держит запись на имя+форму
       (test_plans.c), здесь проверяется, что контроллер ему это и шлёт. */
    {
        d2k_catalog cF;
        memset(&cF, 0, sizeof cF);
        saidbuf[0] = '\0';
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        confirm_once(&cF, sv[0], "две.формы", 40170);
        d2k_cat_binding *m = binding_mut(&cF, "две.формы", 6);
        CHECK(m != NULL && m->shape == (uint8_t)D2K_SHAPE_MODERN,
              "первая привязка не современной формы — проверять нечего");
        if (m && cF.n_boxes == 1) {
            d2k_cat_box *b = &cF.boxes[0];
            d2k_cat_binding *grown = realloc(b->binds, (b->n_binds + 1) * sizeof *grown);
            CHECK(grown != NULL, "не хватило памяти на вторую форму");
            if (grown) {
                b->binds = grown;
                b->binds[b->n_binds] = b->binds[0];
                b->binds[b->n_binds].shape = (uint8_t)D2K_SHAPE_LEGACY;
                b->n_binds++;
            }
        }
        d2k_sched *s = d2k_sched_new(&cF, sv[0], 0x2d);
        CHECK(s != NULL, "планировщик для двух форм не завёлся");
        if (s) {
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            forget_sent();
            (void)d2k_sched_sync(s);
            sync_out(s);
            CHECK(said("поставлено планов по подтверждённым привязкам: 2"),
                  "из двух форм одной цели поставлена не каждая");
            /* На проводе SET_NAME: длина имени, имя, байт формы, план. */
            char want_modern[64], want_legacy[64];
            size_t nl = strlen("две.формы");
            snprintf(want_modern, sizeof want_modern, "%c%s%c",
                     (char)nl, "две.формы", (char)D2K_SHAPE_MODERN);
            snprintf(want_legacy, sizeof want_legacy, "%c%s%c",
                     (char)nl, "две.формы", (char)D2K_SHAPE_LEGACY);
            CHECK(sent_has(want_modern), "современная форма цели не уехала датапату");
            CHECK(sent_has(want_legacy),
                  "старая форма цели не уехала датапату — её клиент останется без обхода");
            d2k_sched_free(s);
        }
        d2k_catalog_free(&cF);
    }

    /* --- снимок приветствия не уходит на ЧУЖОЙ транспорт --------------- */
    {
        /* Приветствие TLS поверх TCP и Initial поверх UDP — разные байты
           разной формы. Пока снимок раздавался всем задачам имени, QUIC-задача
           уходила мерить TLS-приветствием, и первый же разбор его отвергал. */
        d2k_catalog cS;
        memset(&cS, 0, sizeof cS);
        d2k_sched *s = d2k_sched_new(&cS, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        quic_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_HANDSHAKE;
        ver_fail_first = 0;
        ver_answer_port = 40210;
        forget_sent();

        /* Две задачи одного имени: по TCP и по QUIC. */
        d2k_ev h1 = ev_hello(6, 40210, "оба.транспорта");
        d2k_sched_event(s, &h1);
        d2k_ev s1 = ev_suspect(6, 40210);
        d2k_sched_event(s, &s1);
        d2k_ev h2 = ev_hello(17, 40211, "оба.транспорта");
        d2k_sched_event(s, &h2);
        d2k_ev s2 = ev_suspect(17, 40211);
        d2k_sched_event(s, &s2);
        settle(s);

        /* Снимок приходит с транспортом TCP. */
        d2k_ev sh;
        memset(&sh, 0, sizeof sh);
        sh.kind = D2K_EV_SHAPE;
        sh.transport = 6;
        CHECK(d2k_hello_from_profile(D2K_SHAPE_LEGACY, "оба.транспорта",
                                     sh.shape, sizeof sh.shape, &sh.shape_len) == 0,
              "приветствие для снимка не собралось");
        saidbuf[0] = '\0';
        d2k_sched_event(s, &sh);

        CHECK(said("(TCP) сохранён целый снимок"),
              "снимок своего транспорта не сохранён");
        CHECK(!said("(QUIC) поймана форма приветствия"),
              "снимок TCP положили QUIC-задаче — она пойдёт мерить чужими байтами");
        d2k_sched_free(s);
        d2k_catalog_free(&cS);
    }

    /* --- неудачный ВТОРОЙ поиск не уносит подтверждённый план ---------- */
    {
        /* Второй поиск по уже подтверждённой цели — обычное дело: новое
           подозрение закрывает наблюдение и заводит поиск заново. Пробный
           план такого поиска встаёт на то же имя ПОВЕРХ подтверждённого, а
           снятие уносит их вместе: в каталоге «подтверждено», в датапате
           пусто, у человека обхода нет. Поймано лабораторией с памятью. */
        d2k_catalog cR;
        memset(&cR, 0, sizeof cR);
        d2k_sched *s = d2k_sched_new(&cR, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = 40200;
        ver_calls = 0;
        forget_sent();

        d2k_ev h = ev_hello(6, 40200, "второй.поиск");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40200);
        d2k_sched_event(s, &su);
        settle(s);
        d2k_ev ap = ev_applied(6, 40200);
        d2k_sched_event(s, &ap);
        spin(s, 40);
        CHECK(binding_of(&cR, "второй.поиск", 6) != NULL, "первый поиск не подтвердился");
        /* Проход по каталогу, заказанный подтверждением, надо ДОКРУТИТЬ: его
           порции крутит цикл d2kc, а не тик, и недокрученный проход не даст
           начаться следующему. */
        sync_out(s);

        /* Коробка вмешалась снова: наблюдение прекращается. */
        d2k_ev su2 = ev_suspect(6, 40200);
        d2k_sched_event(s, &su2);
        spin(s, 5);

        /* И ещё раз — заводится ВТОРОЙ поиск, который ничем не кончится. */
        ver_answer = D2K_VER_HANDSHAKE;   /* зонд до приложения не доходит */
        ver_answer_port = 40201;
        d2k_ev h3 = ev_hello(6, 40201, "второй.поиск");
        d2k_sched_event(s, &h3);
        d2k_ev su3 = ev_suspect(6, 40201);
        d2k_sched_event(s, &su3);
        /* Дольше, чем run_out: задача сдаётся либо по бюджету зондов, либо по
           сроку жизни (десять минут модельных часов), и до этого места надо
           дожить. */
        for (int i = 0; i < 300 && d2k_sched_active(s); i++) {
            skip_ahead(s, 6000);
            spin(s, 20);
        }

        /* Задача сдалась. Знание каталога обязано вернуться на провод. */
        forget_sent();
        spin(s, 5);
        /* Проход по каталогу разложен на порции, и крутит их цикл d2kc
           (d2k_sched_sync_step) — здесь за него это делает тест, ровно как в
           проверке синхронизации выше. */
        sync_out(s);
        /* Ищем на проводе САМ ПЛАН (заголовок "D2KP"), а не идентификатор:
           план каталога несёт ту идентичность, что записана в его тексте, и у
           подтверждённого она нулевая — «plan-…» подставляется только пробному
           при установке (install_next). Присутствие тела плана отличает
           SET_NAME от DEL_NAME, а имя цели проверяется рядом. */
        CHECK(sent_has("D2KP"),
              "после неудачного второго поиска цель осталась БЕЗ плана — "
              "в каталоге «подтверждено», в датапате пусто");
        CHECK(sent_has("второй.поиск"),
              "на провод вернулся план не той цели");
        d2k_sched_free(s);
        d2k_catalog_free(&cR);
    }

    /* --- ПЕТЛЯ ПО QUIC ЗАМКНУТА: плечо → план → подтверждение ---------- */
    {
        /* До этой правки задача транспорта 17 шла в d2k_compose, который про
           QUIC не знает, и получала разрезы — а датаграмму резать нельзя.
           Подбор плеча был написан и не звался ниоткуда, кроме тестов. */
        d2k_catalog cQ;
        memset(&cQ, 0, sizeof cQ);
        d2k_sched *s = d2k_sched_new(&cQ, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        quic_answer = D2K_V_OPAQUE;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = 40220;
        ver_calls = 0;
        arm_calls = 0;
        arm_kind = D2K_QA_COPIES;
        forget_sent();

        d2k_ev h = ev_hello(17, 40220, "квик.обход");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(17, 40220);
        d2k_sched_event(s, &su);
        {
            d2k_ev sh;
            CHECK(quic_shape(&sh, "квик.обход") == 0, "снимок QUIC не собрался");
            d2k_sched_event(s, &sh);
        }
        settle(s);
        CHECK(arm_calls >= 1, "плечо QUIC не подбиралось вовсе");
        CHECK(said("плечо подобрано"), "подбор плеча не назван вслух");

        d2k_ev ap = ev_applied(17, 40220);
        d2k_sched_event(s, &ap);
        spin(s, 40);
        const d2k_cat_binding *bd = binding_of(&cQ, "квик.обход", 17);
        CHECK(bd != NULL, "подтверждённый обход по QUIC не записан в каталог");
        CHECK(bd != NULL && bd->level == 3, "уровень записи по QUIC не третий");
        /* Текст записанного плана — из плеча, а не из разрезов: датаграмму
           резать нельзя, и план обязан объявлять udp/quic. На проводе он едет
           байтами TLV, поэтому сверяем то, что легло в каталог. */
        {
            int quic_text = 0;
            for (size_t bi = 0; bi < cQ.n_boxes; bi++) {
                for (size_t pj = 0; pj < cQ.boxes[bi].n_plans; pj++) {
                    const char *txt = cQ.boxes[bi].plans[pj].text;
                    if (txt && strstr(txt, "proto udp quic")) {
                        quic_text = 1;
                        CHECK(strstr(txt, "payload 1 41424344\n") != NULL,
                              "scheduler replaced measured original fake bytes");
                        CHECK(strstr(txt, "repeats=6") != NULL,
                              "scheduler lost original copies");
                    }
                }
            }
            CHECK(quic_text,
                  "записанный план не объявляет udp/quic — он собран не из плеча");
        }
        d2k_sched_free(s);
        d2k_catalog_free(&cQ);
    }

    for(int fake=0;fake<2;fake++) {
        d2k_catalog c={0};d2k_sched *s=d2k_sched_new(&c,sv[0],0x2d);
        quic_answer=D2K_V_OPAQUE;ver_answer=D2K_VER_APPLICATION;
        ver_fail_first=0;ver_answer_port=(uint16_t)(40225+fake);
        arm_kind=fake?D2K_QA_COPIES:D2K_QA_FRAG;arm_fragment_shape=4;
        forget_sent();
        d2k_ev h=ev_hello(17,ver_answer_port,"original.fragment");d2k_sched_event(s,&h);
        d2k_ev su=ev_suspect(17,ver_answer_port);d2k_sched_event(s,&su);
        d2k_ev sh;CHECK(quic_shape(&sh,"original.fragment")==0,"fragment shape fixture");
        d2k_sched_event(s,&sh);settle(s);
        d2k_ev ap=ev_applied(17,ver_answer_port);d2k_sched_event(s,&ap);spin(s,40);
        CHECK(binding_of(&c,"original.fragment",17)!=NULL,"scheduler discarded fragment-only/combo result");
        int found=0;
        for(size_t i=0;i<c.n_boxes;i++)for(size_t j=0;j<c.boxes[i].n_plans;j++) {
            const char *text=c.boxes[i].plans[j].text;
            if(text && strstr(text,"ipfrag 4\n")) {
                found=1;
                CHECK((strstr(text,"fake ")!=NULL)==fake,"scheduler invented/lost fake in fragment plan");
            }
        }
        CHECK(found,"learned catalog lost original fragment shape");
        d2k_sched_free(s);d2k_catalog_free(&c);arm_fragment_shape=0;
    }

    /* --- невыразимое плечо QUIC не подменяется похожим ------------------ */
    {
        d2k_catalog cF2;
        memset(&cF2, 0, sizeof cF2);
        d2k_sched *s = d2k_sched_new(&cF2, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        quic_answer = D2K_V_OPAQUE;
        ver_answer = D2K_VER_APPLICATION;
        ver_answer_port = 40221;
        arm_kind = D2K_QA_FRAG;     /* нет измеренной формы/выживания */
        forget_sent();

        d2k_ev h = ev_hello(17, 40221, "фрагмент.квик");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(17, 40221);
        d2k_sched_event(s, &su);
        {
            d2k_ev sh;
            CHECK(quic_shape(&sh, "фрагмент.квик") == 0, "снимок QUIC не собрался");
            d2k_sched_event(s, &sh);
        }
        run_out(s);

        CHECK(said("не выразимо"),
              "невыразимое плечо не названо пробелом реализации");
        CHECK(!said("не нашлось"),
              "невыразимое плечо выдано за ненайденное — это разные факты");
        CHECK(binding_of(&cF2, "фрагмент.квик", 17) == NULL,
              "по невыразимому плечу появилась привязка");
        arm_kind = D2K_QA_BLOB;
        quic_answer = D2K_V_CLEAR;
        d2k_sched_free(s);
        d2k_catalog_free(&cF2);
    }

    /* --- «не нашлось» и «не выразимо» — РАЗНЫЕ ответы --------------------
     *
     * Первое про коробку и бюджет: перебор кончился, воздействия нет.
     * Второе про нас: воздействие есть, языка плана на него нет. Лаборатория
     * 13.09 на коробке без состояния получила «не выразимо» там, где на деле
     * кончился бюджет развёртки TTL, — то есть отчиталась нашим пробелом
     * вместо свойства сети. */
    {
        d2k_catalog cNF;
        memset(&cNF, 0, sizeof cNF);
        d2k_sched *s = d2k_sched_new(&cNF, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        quic_answer = D2K_V_OPAQUE;
        ver_answer_port = 40222;
        arm_kind = D2K_QA_NOT_FOUND;
        forget_sent();

        d2k_ev h = ev_hello(17, 40222, "нечем.квик");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(17, 40222);
        d2k_sched_event(s, &su);
        {
            d2k_ev sh;
            CHECK(quic_shape(&sh, "нечем.квик") == 0, "снимок QUIC не собрался");
            d2k_sched_event(s, &sh);
        }
        run_out(s);

        CHECK(said("плечо не нашлось"),
              "исчерпанный перебор не назван своим именем");
        CHECK(!said("не выразимо"),
              "ненайденное плечо выдано за пробел реализации");
        CHECK(binding_of(&cNF, "нечем.квик", 17) == NULL,
              "по ненайденному плечу появилась привязка");
        CHECK(sent_command_count(D2K_CMD_SET_NAME_PROBE, NULL, 0) == 0,
              "QUIC без найденного плеча получил резервный TCP/TLS-план");
        arm_kind = D2K_QA_BLOB;
        quic_answer = D2K_V_CLEAR;
        d2k_sched_free(s);
        d2k_catalog_free(&cNF);
    }

    /* --- ПЛЕЧА НЕТ, А «МУСОР»/«ДЛИНА» ПОДТВЕРЖДЕНЫ — ЭТО ПЛАН ------------
     * Донор compose (questions.go:317-334) превращает JunkAheadHelps в fake
     * 16 нулей ×2, UDPLen — в udplen increment=100, без всякого плеча
     * askArms. Прежде планировщик строил QUIC-план только из плеча и
     * отчитывался «плечо не нашлось» при измеренном ответе. */
    /* which 1 и 2 — одна и та же «длина», измеренная PROFILE и снимком:
       провенанс обязан остаться в журнале и НЕ менять текст/имя плана. */
    char len_text[2][4096] = {{0}}, len_id[2][40] = {{0}};
    for (int which = 0; which < 3; which++) {
        d2k_catalog cJ;
        memset(&cJ, 0, sizeof cJ);
        d2k_sched *s = d2k_sched_new(&cJ, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        quic_answer = D2K_V_OPAQUE;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = (uint16_t)(40223 + which);
        arm_kind = D2K_QA_NOT_FOUND;
        memset(&quic_props_answer, 0, sizeof quic_props_answer);
        if (which == 0) { quic_props_answer.junk_ahead = D2K_PROP_YES; }
        else {
            quic_props_answer.longer = D2K_PROP_YES;
            quic_props_answer.longer_profile = which == 1;
        }
        forget_sent();
        const char *nm = which == 0 ? "мусор.квик" : which == 1 ? "длина.квик" : "длина2.квик";
        d2k_ev h = ev_hello(17, ver_answer_port, nm);
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(17, ver_answer_port);
        d2k_sched_event(s, &su);
        {
            d2k_ev sh;
            CHECK(quic_shape(&sh, nm) == 0, "снимок QUIC не собрался");
            d2k_sched_event(s, &sh);
        }
        settle(s);
        CHECK(!said("плечо не нашлось за"),
              "подтверждённое свойство коробки выдано за «плечо не нашлось»");
        d2k_ev ap = ev_applied(17, ver_answer_port);
        d2k_sched_event(s, &ap);
        spin(s, 40);
        CHECK(binding_of(&cJ, nm, 17) != NULL,
              "план из свойств «мусор»/«длина» не дошёл до подтверждённой привязки");
        int found = 0;
        for (size_t bi = 0; bi < cJ.n_boxes; bi++) {
            for (size_t pj = 0; pj < cJ.boxes[bi].n_plans; pj++) {
                const char *txt = cJ.boxes[bi].plans[pj].text;
                if (!txt || !strstr(txt, "proto udp quic")) { continue; }
                found = 1;
                if (which == 0) {
                    CHECK(strstr(txt, "payload 1 00000000000000000000000000000000\n") &&
                          strstr(txt, "repeats=2 gap_us=0 place=before"),
                          "мусор: не 16 нулей донора ×2 перед Initial");
                } else {
                    CHECK(strstr(txt, "udplen 100\n") && !strstr(txt, "PROFILE"),
                          "длина: нет udplen 100 либо провенанс попал в текст плана");
                    snprintf(len_text[which - 1], sizeof len_text[0], "%s", txt);
                    snprintf(len_id[which - 1], sizeof len_id[0], "%s", cJ.boxes[bi].plans[pj].id);
                }
            }
        }
        CHECK(found, "в каталоге нет QUIC-плана из свойств");
        if (which == 1) {
            CHECK(said("измерено PROFILE"), "журнал не назвал, что «длина» измерена PROFILE");
        }
        if (which == 2) {
            CHECK(!said("измерено PROFILE"), "журнал назвал PROFILE у «длины», измеренной снимком");
            CHECK(len_text[0][0] && !strcmp(len_text[0], len_text[1]),
                  "одна и та же «длина» с PROFILE и без дала разный текст плана");
            CHECK(len_id[0][0] && !strcmp(len_id[0], len_id[1]),
                  "одна и та же «длина» с PROFILE и без дала разное имя плана");
        }
        memset(&quic_props_answer, 0, sizeof quic_props_answer);
        arm_kind = D2K_QA_BLOB;
        quic_answer = D2K_V_CLEAR;
        d2k_sched_free(s);
        d2k_catalog_free(&cJ);
    }
    /* План из свойств — такая же гипотеза, как любой другой: ответ UDP и
       даже завершённое рукопожатие без прикладного ответа его не
       подтверждают. */
    {
        d2k_catalog cH;
        memset(&cH, 0, sizeof cH);
        d2k_sched *s = d2k_sched_new(&cH, sv[0], 0x2d);
        quic_answer = D2K_V_OPAQUE;
        ver_answer = D2K_VER_HANDSHAKE;
        ver_fail_first = 0;
        ver_answer_port = 40227;
        arm_kind = D2K_QA_NOT_FOUND;
        memset(&quic_props_answer, 0, sizeof quic_props_answer);
        quic_props_answer.junk_ahead = D2K_PROP_YES;
        forget_sent();
        d2k_ev h = ev_hello(17, 40227, "рукопожатие.квик");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(17, 40227);
        d2k_sched_event(s, &su);
        {
            d2k_ev sh;
            CHECK(quic_shape(&sh, "рукопожатие.квик") == 0, "снимок QUIC не собрался");
            d2k_sched_event(s, &sh);
        }
        settle(s);
        d2k_ev ap = ev_applied(17, 40227);
        d2k_sched_event(s, &ap);
        spin(s, 40);
        CHECK(binding_of(&cH, "рукопожатие.квик", 17) == NULL,
              "план из свойств подтверждён без прикладного ответа QUIC");
        memset(&quic_props_answer, 0, sizeof quic_props_answer);
        ver_answer = D2K_VER_APPLICATION;
        arm_kind = D2K_QA_BLOB;
        quic_answer = D2K_V_CLEAR;
        d2k_sched_free(s);
        d2k_catalog_free(&cH);
    }

    /* Терминальные исходы QUIC не превращаются обратно в подбор обвязкой.
       Само получение этих исходов сверялось с Go донора (обвязка удалена 06.10.2026). */
    {
        const d2k_verdict terminal[] = { D2K_V_CLEAR, D2K_V_ADDRESS, D2K_V_NO_QUIC };
        for (size_t i = 0; i < sizeof terminal / sizeof terminal[0]; i++) {
            d2k_catalog empty = {0};
            d2k_sched *s = d2k_sched_new(&empty, sv[0], 0x2d);
            CHECK(s != NULL, "планировщик терминального QUIC-исхода не создался");
            if (!s) { continue; }
            quic_answer = terminal[i];
            quic_calls = arm_calls = ver_calls = 0;
            forget_sent();
            d2k_ev h = ev_hello(17, 40230, "terminal.example");
            d2k_ev su = ev_suspect(17, 40230);
            d2k_sched_event(s, &h);
            d2k_sched_event(s, &su);
            settle(s);
            CHECK(quic_calls == 1, "терминальный QUIC-исход не получен либо запускается повторно");
            CHECK(arm_calls == 0 && ver_calls == 0,
                  "обвязка начала подбор/подтверждение после CLEAR, ADDRESS или NO_QUIC");
            CHECK(empty.n_boxes == 0 && binding_of(&empty, "terminal.example", 17) == NULL,
                  "терминальный QUIC-исход записан найденным обходом");
            d2k_sched_free(s);
            d2k_catalog_free(&empty);
        }
        quic_answer = D2K_V_CLEAR;
    }

    /* --- подтверждать нечем: перебор кандидатов не начинается ---------- */
    {
        /* У QUIC вопросник есть, а зонда подтверждения нет. Перебор в такой
           задаче потратил бы весь бюджет зондов на установку планов, которых
           никто не проверит, — а на живом роутере таких целей десятки. */
        d2k_catalog cU;
        memset(&cU, 0, sizeof cU);
        d2k_sched *s = d2k_sched_new(&cU, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        quic_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;   /* не важно: до ответа не дойдёт */
        ver_fail_first = 0;
        ver_answer_port = 40190;
        ver_calls = 0;
        ver_unsupported = 1;
        forget_sent();

        d2k_ev h = ev_hello(17, 40190, "квик.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(17, 40190);
        d2k_sched_event(s, &su);
        {
            d2k_ev sh;
            CHECK(quic_shape(&sh, "квик.цель") == 0, "снимок QUIC не собрался");
            d2k_sched_event(s, &sh);
        }
        run_out(s);

        CHECK(said("подтверждать нечем"),
              "транспорт без зонда подтверждения не назван своим именем");
        CHECK(ver_calls == 1,
              "перебор кандидатов пошёл дальше, хотя ответ будет тот же — "
              "бюджет зондов тратится впустую");
        CHECK(binding_of(&cU, "квик.цель", 17) == NULL,
              "непроверяемый транспорт дал запись в каталоге");
        ver_unsupported = 0;
        quic_answer = D2K_V_CLEAR;
        d2k_sched_free(s);
        d2k_catalog_free(&cU);
    }

    /* --- Cloudflare challenge не подтверждает обход и останавливает поиск --- */
    {
        d2k_catalog cC;
        memset(&cC, 0, sizeof cC);
        d2k_sched *s = d2k_sched_new(&cC, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = 40175;
        ver_calls = 0;
        ver_cloudflare_challenge = 1;
        forget_sent();

        d2k_ev h = ev_hello(6, 40175, "challenge.example");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40175);
        d2k_sched_event(s, &su);
        settle(s);
        d2k_ev ap = ev_applied(6, 40175);
        d2k_sched_event(s, &ap);
        spin(s, 40);

        CHECK(said("Cloudflare challenge"),
              "ответ cf-mitigated: challenge не назван challenge и поиск не остановлен");
        CHECK(binding_of(&cC, "challenge.example", 6) == NULL,
              "страница Cloudflare challenge записана как подтверждённый обход");
        CHECK(ver_calls == 1,
              "после challenge был испытан ещё один кандидат и послан лишний запрос");
        /* Финальное ревью, п.5: как у соседней ветки D2K_VER_CHALLENGE,
           цель получает антибот-паузу, а не только 2-минутный отдых. */
        skip_ahead(s, 3 * 60 * 1000);
        spin(s, 5);
        saidbuf[0] = '\0';
        h = ev_hello(6, 40176, "challenge.example");
        d2k_sched_event(s, &h);
        su = ev_suspect(6, 40176);
        d2k_sched_event(s, &su);
        spin(s, 5);
        CHECK(said("замер отложен после антибот-ответа"),
              "Cloudflare challenge не поставил антибот-паузу цели");

        ver_cloudflare_challenge = 0;
        d2k_sched_free(s);
        d2k_catalog_free(&cC);
    }

    /* Explicit HTTP denial cannot promote a plan, even with APPLIED. */
    for (int denied = 0; denied < 2; denied++) {
        d2k_catalog cB = {0};
        d2k_sched *s = d2k_sched_new(&cB, sv[0], 0x2d);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = denied ? D2K_VER_DENIED : D2K_VER_BLOCKPAGE;
        ver_fail_first = 0; ver_calls = 0;
        ver_answer_port = (uint16_t)(40178 + denied);
        ver_name_ok = 1;
        forget_sent(); saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        d2k_ev h = ev_hello(6, ver_answer_port, "blocked.example");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, ver_answer_port);
        d2k_sched_event(s, &su);
        settle(s);
        d2k_ev ap = ev_applied(6, ver_answer_port);
        d2k_sched_event(s, &ap);
        run_out(s);
        CHECK(binding_of(&cB, "blocked.example", 6) == NULL,
              "явная заглушка/451 сохранены как подтверждённый обход");
        if (denied) CHECK(ver_calls == 1 && said("юридический отказ"),
              "HTTP 451 не остановил перебор после первого ответа");
        d2k_sched_free(s); d2k_catalog_free(&cB);
    }
    ver_answer = D2K_VER_APPLICATION; ver_name_ok = -1;

    /* --- mismatch alone is diagnostic, not evidence of a block page ---- */
    {
        /* Complete ordinary response from a shared/default TLS frontend. */
        d2k_catalog cN;
        memset(&cN, 0, sizeof cN);
        d2k_sched *s = d2k_sched_new(&cN, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = 40180;
        ver_calls = 0;
        ver_name_ok = 0;                 /* ИЗМЕРЕННОЕ несовпадение */
        forget_sent();

        d2k_ev h = ev_hello(6, 40180, "подмена.цель");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40180);
        d2k_sched_event(s, &su);
        settle(s);
        d2k_ev ap = ev_applied(6, 40180);
        d2k_sched_event(s, &ap);
        run_out(s);

        CHECK(said("сертификат не совпал"),
              "несовпадение сертификата потеряло диагностическое предупреждение");
        CHECK(binding_of(&cN, "подмена.цель", 6) != NULL,
              "полный ответ и исполненный план отвергнуты только из-за имени сертификата");
        ver_name_ok = -1;
        d2k_sched_free(s);
        d2k_catalog_free(&cN);
    }

    /* --- зонд ходит ДЛИНОЙ КЛИЕНТА, а не своей ------------------------- */
    {
        /* Приветствие зонда вчетверо короче браузерного (замерено: curl шлёт
           1581 байт), и на этой разнице ломается переносимость: план, чьи
           куски помещаются в посылку на коротком приветствии, на длинном не
           помещается вовсе. Поэтому длина снятого с клиента приветствия
           обязана доехать до зонда — проверяем, что доезжает именно она, а не
           ноль и не своя. */
        d2k_catalog cW;
        memset(&cW, 0, sizeof cW);
        d2k_sched *s = d2k_sched_new(&cW, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = 40170;
        ver_calls = 0;
        ver_last_wire = 0;
        forget_sent();

        d2k_ev h = ev_hello(6, 40170, "длина.клиента");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40170);
        d2k_sched_event(s, &su);
        settle(s);
        CHECK(ver_calls >= 1, "зонд не позван — длину проверять не на чем");
        CHECK(ver_last_wire > 0,
              "зонду досталась нулевая длина — он пойдёт СВОИМ коротким приветствием, "
              "и подтверждение достанется ему, а не человеку");

        /* A late observation belongs to the NEXT search, not to another
           candidate of the experiment already measured on different bytes. */
        size_t measured_wire = ver_last_wire;
        d2k_ev sh;
        memset(&sh, 0, sizeof sh);
        sh.kind = D2K_EV_SHAPE;
        sh.transport = 6;
        CHECK(d2k_hello_from_profile(D2K_SHAPE_LEGACY, "длина.клиента",
                                     sh.shape, sizeof sh.shape, &sh.shape_len) == 0,
              "приветствие клиента не собралось — проверять нечем");
        d2k_sched_event(s, &sh);
        CHECK(said("сохранён целый снимок"), "снимок не сохранён");

        CHECK(sh.shape_len != measured_wire, "fixture must change the input length");
        ver_last_wire = 0;
        ver_answer_port = 40171;
        run_out(s);
        CHECK(ver_last_wire == measured_wire,
              "late SHAPE changed the input length inside the measured experiment");
        d2k_sched_free(s);
        d2k_catalog_free(&cW);
    }

    /* --- живой обмен не ВЫДУМЫВАЕТ форму клиента ------------------------ */
    {
        /* Обратная сторона предыдущей проверки. Приветствия живого клиента
           датапат не присылал — значит его форма НЕ ИЗМЕРЕНА, и взять её из
           заготовки холодного старта (fill_hellos подставляет туда MODERN)
           нельзя: заготовка — это то, чем планировщик ходит сам, а не то, чем
           ходит клиент. Запись изображает старый файл (формы в ней нет), и
           после наблюдения формы в ней по-прежнему быть не должно. */
        d2k_catalog cF;
        memset(&cF, 0, sizeof cF);
        d2k_sched *s = d2k_sched_new(&cF, sv[0], 0x2d);
        saidbuf[0] = '\0';
        d2k_sched_set_say(s, collect_say, NULL);
        tcp_answer = D2K_V_PREFIX;
        ver_answer = D2K_VER_APPLICATION;
        ver_fail_first = 0;
        ver_answer_port = 40150;
        ver_calls = 0;
        forget_sent();

        d2k_ev h = ev_hello(6, 40150, "снимка.нет");
        d2k_sched_event(s, &h);
        d2k_ev su = ev_suspect(6, 40150);
        d2k_sched_event(s, &su);
        settle(s);
        d2k_ev ap = ev_applied(6, 40150);
        d2k_sched_event(s, &ap);
        spin(s, 40);

        d2k_cat_binding *m = binding_mut(&cF, "снимка.нет", 6);
        CHECK(m != NULL, "подтверждение не записано");
        if (m) { m->shape = 0; }   /* запись из файла, снятого до появления поля */

        d2k_ev h2 = ev_hello(6, 40151, "снимка.нет");
        d2k_sched_event(s, &h2);
        d2k_ev live = ev_exchange(6, 40151, 1);
        d2k_sched_event(s, &live);
        const d2k_cat_binding *bd = binding_of(&cF, "снимка.нет", 6);
        CHECK(bd != NULL && bd->level == 3,
              "TLS-ответ повысил уровень записи без записанной формы");
        CHECK(bd != NULL && bd->shape == 0,
              "форма клиента не измерена, а в записи появилась — заготовка выдана за замер");
        CHECK(bd != NULL && bd->verified_by == D2K_VERBY_PROBE,
              "наблюдение подменило источник проверки");
        d2k_sched_free(s);
        d2k_catalog_free(&cF);
    }

measured_test:
    /* --- ЗАДАЧА 37: после сохранённого плана — стратегия замера ------------
       Поле 02.10.2026, edge-mqtt-fallback.facebook.com: «решает содержимое»,
       узнанная коробка с одним сохранённым планом. План не подошёл — и вместо
       приёма, найденного замером, планировщик прогнал запасной список донора
       и fake-SNI-лестницу: 45 опытов. Донор после вердикта списка не
       перебирает: находка — ОДНА стратегия, промах — ни одной. */
    {
        tcp_wait_until_stop = 0; tcp_block_until_stop = 0;
        ver_fail_first = 0; ver_unsupported = 0; ver_cloudflare_challenge = 0;
        ver_app_after_tcp_search = 0;
        vol_answer = D2K_VOL_PASSED; vol_rx_cut = 0; vol_rx_tls_unavailable = 0;
        snapshot_enabled = 0;
        for (int mode = 0; mode < 5; mode++) {
            /* 0 — замер нашёл приём (disorder у донора; здесь плечо badsum);
               1 — замер владеет поиском и приёма не нашёл;
               2 — прежний провайдер без владения поиском: запасной список
                   законен, но RX-лестница без RX-обрыва — нет;
               3 — замер нашёл приём, но его посылка не помещается в предел
                   отправки датапата (I2): кандидатом он не ставится, BAD_PLAN
                   и «местный отказ» не случаются;
               4 — «решает содержимое» без владения поиском (nft-роутер без
                   сырого сокета, I1): после плана коробки — вопросы о
                   свойствах, и только потом выведенные кандидаты. */
            d2k_catalog c = {0};
            c.boxes = calloc(1, sizeof *c.boxes);
            CHECK(c.boxes != NULL, "t37: коробка не создалась");
            if (!c.boxes) break;
            c.n_boxes = 1;
            d2k_cat_box *b = &c.boxes[0];
            snprintf(b->id, sizeof b->id, "box-mqtt-%d", mode);
            b->fp.method = D2K_FP_METHOD;
            b->fp.n_sig = 1;
            snprintf(b->fp.sig[0].kind, sizeof b->fp.sig[0].kind, "rst");
            b->fp.sig[0].ttl = 127;
            b->fp.sig[0].tos = 0x88;
            b->fp.sig[0].ipid = 54321;
            b->plans = calloc(1, sizeof *b->plans);
            CHECK(b->plans != NULL, "t37: план коробки не создался");
            if (!b->plans) { d2k_catalog_free(&c); break; }
            b->n_plans = 1;
            snprintf(b->plans[0].id, sizeof b->plans[0].id, "plan-mqtt-saved");
            snprintf(b->plans[0].proto, sizeof b->plans[0].proto, "tls");
            b->plans[0].enabled = 1;
            b->plans[0].successes = 2;
            b->plans[0].text = strdup(
                "d2k-plan 1 1\nid 00000000000000000000000000000000\n"
                "proto tcp tls\nsplit payload_start +7\norder forward\n");
            tcp_answer = mode == 2 ? D2K_V_PREFIX : D2K_V_OPAQUE;
            tcp_owns_search = mode != 2 && mode != 4;
            tcp_found_arm = mode == 0 || mode == 3;
            ver_answer = D2K_VER_HANDSHAKE;   /* ни один кандидат не помогает */
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            if (mode == 3) d2k_sched_set_send_cap(s, 1400);
            tcp_calls = ver_calls = vol_calls = 0;
            uint16_t cport = (uint16_t)(42401 + mode);
            ver_answer_port = cport;
            drain(); forget_sent();
            const char *name = mode == 0 ? "edge-mqtt-fallback.facebook.example" :
                               mode == 1 ? "edge-mqtt-miss.facebook.example" :
                               mode == 2 ? "edge-legacy.facebook.example" :
                               mode == 3 ? "edge-mqtt-narrow.facebook.example" :
                                           "edge-nft.facebook.example";
            d2k_ev h = ev_hello(6, cport, name); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, cport); d2k_sched_event(s, &su);
            int used = 0;
            for (int i = 0; i < 1500 && !said("отложен"); i++) {
                spin(s, 120);
                drain();
                d2k_ev ap = ev_applied(6, cport); d2k_sched_event(s, &ap);
                spin(s, 5);
                int u = live_probes_used(s);
                if (u > used) used = u;
            }
            drain();
            {
                int u = live_probes_used(s);
                if (u > used) used = u;
            }
            printf("t37 mode %d: опытов планировщика %d, вызовов зонда %d\n", mode, used, ver_calls);
            CHECK(tcp_calls == 1, "t37: прямой замер выполнен не ровно один раз");
            CHECK(said("готовых планов узнанной коробки"),
                  "t37: сохранённый план узнанной коробки не испытан первым");
            CHECK(!sent_contains_plan_payload("hcaptcha.com") && !said("fake-SNI"),
                  "t37: RX fake-SNI-лестница пошла без замеренного RX-обрыва");
            if (mode == 0) {
                CHECK(said("НАЙДЕН замером"),
                      "t37: после неудачи сохранённого плана не испытан приём, найденный замером");
                CHECK(said("проверяю кандидаты из уже выполненного прямого замера"),
                      "t37: возврат к результату замера не назван");
                CHECK(used == 2,
                      "t37: найденный замером приём — второй и последний опыт; запасной список не перебирается");
            } else if (mode == 1) {
                /* Владеющий поиском замер ничего выразимого не нашёл: после
                   плана коробки — явный запасной список (решение
                   координатора 04.10), а не отдых. */
                const char *box_at = strstr(saidbuf, "готовых планов узнанной коробки");
                const char *fallback_at = strstr(saidbuf, "запасного перебора");
                CHECK(said("выразимого планом приёма нет"),
                      "t37: переход владеющего поиском замера к запасному списку не назван");
                CHECK(box_at && fallback_at && box_at < fallback_at && used > 1,
                      "t37: после плана коробки запасной список не испытан");
            } else if (mode == 2) {
                const char *measured_at = strstr(saidbuf,
                    "проверяю кандидаты из уже выполненного прямого замера");
                const char *fallback_at = strstr(saidbuf, "запасного перебора");
                CHECK(measured_at && fallback_at && measured_at < fallback_at,
                      "t37: прежний провайдер — кандидаты замера не испытаны раньше запасного списка");
                /* Между ними — хотя бы один опыт кандидата замера. */
                const char *trial_between = measured_at ? strstr(measured_at, "поставил план") : NULL;
                CHECK(trial_between && fallback_at && trial_between < fallback_at,
                      "t37: кандидат замера не испытан до запасного перебора");
            } else if (mode == 3) {
                CHECK(said("не помещается в предел отправки 1400"),
                      "t37: неподходящий пределу отправки приём замера не назван");
                CHECK(!said("НАЙДЕН замером"),
                      "t37: приём, не помещающийся в предел отправки, поставлен кандидатом");
                CHECK(!said("отвергнуты исполнителем"),
                      "t37: неподходящий приём дошёл до исполнителя и кончился местным отказом");
                /* Плана из приёма не вышло — дальше явный запасной список. */
                CHECK(said("запасного перебора") && used > 1,
                      "t37: без выразимого плана запасной список не испытан");
            } else {
                const char *box_at = strstr(saidbuf, "готовых планов узнанной коробки");
                const char *ask_at = strstr(saidbuf, "готовые планы не помогли; вердикт: решает содержимое — "
                                                     "спрашиваю коробку о свойствах");
                const char *fallback_at = strstr(saidbuf, "запасного перебора");
                CHECK(box_at && ask_at && box_at < ask_at,
                      "t37: без владения поиском после плана коробки вопросы о свойствах не заданы");
                CHECK(ask_at && (!fallback_at || ask_at < fallback_at),
                      "t37: запасной перебор начался раньше вопросов о свойствах");
            }
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
        }
        tcp_answer = D2K_V_OPAQUE; tcp_owns_search = tcp_found_arm = 0;
        ver_answer = D2K_VER_APPLICATION;

        /* F3: клиент — MQTT поверх TLS 1.3 (ALPN «mqtt», «mqttv5»). Зонд
           подтверждения предлагает ЕГО ALPN, а не http/1.1, и засчитывает
           завершённое рукопожатие как доказательство уровня рукопожатия:
           привязка — D2K_VERBY_PROBE_HANDSHAKE, не PROBE (приложение не
           измерено). HTTP-зонд не зовётся. */
        {
            d2k_sched_alpn_ver_fn saved_alpn = d2k_sched_alpn_ver_hook;
            d2k_sched_alpn_ver_hook = stub_alpn_ver;
            d2k_catalog c = {0};
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            tcp_answer = D2K_V_PREFIX; tcp_owns_search = tcp_found_arm = 0;
            ver_answer = D2K_VER_APPLICATION; ver_fail_first = 0;
            tcp_calls = ver_calls = alpn_ver_calls = 0; alpn_ver_seen_len = 0;
            const char *nm = "edge-mqtt-alpn.facebook.example";
            uint16_t cport = 42431;
            ver_answer_port = cport;
            d2k_ev sh; memset(&sh, 0, sizeof sh);
            sh.kind = D2K_EV_SHAPE; sh.transport = 6;
            CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, nm, sh.shape, sizeof sh.shape,
                                         &sh.shape_len) == 0, "t37/F3: снимок не собрался");
            uint8_t list[256]; size_t ll = 0;
            CHECK(d2k_hello_alpn(sh.shape, sh.shape_len, list, sizeof list, &ll) == 1 &&
                  ll == 12, "t37/F3: в профиле нет ожидаемого ALPN h2,http/1.1");
            static const uint8_t mqtt[12] = { 4,'m','q','t','t', 6,'m','q','t','t','v','5' };
            for (size_t i = 0; ll == 12 && i + 12 <= sh.shape_len; i++) {
                if (!memcmp(sh.shape + i, list, 12)) { memcpy(sh.shape + i, mqtt, 12); break; }
            }
            CHECK(d2k_hello_alpn(sh.shape, sh.shape_len, list, sizeof list, &ll) == 1 &&
                  ll == 12 && !memcmp(list, mqtt, 12) && !d2k_alpn_is_http(list, ll),
                  "t37/F3: ALPN снимка не переписан на mqtt");
            drain(); forget_sent();
            d2k_ev h = ev_hello(6, cport, nm); d2k_sched_event(s, &h);
            d2k_sched_event(s, &sh);
            d2k_ev su = ev_suspect(6, cport); d2k_sched_event(s, &su);
            for (int i = 0; i < 60 && !said("ПОДТВЕРЖДЕНО"); i++) {
                spin(s, 100);
                d2k_ev ap = ev_applied(6, cport); d2k_sched_event(s, &ap);
                spin(s, 5);
            }
            CHECK(alpn_ver_calls >= 1 && alpn_ver_seen_len == 12 &&
                  !memcmp(alpn_ver_seen, mqtt, 12),
                  "t37/F3: зонд подтверждения не предложил ALPN клиента");
            CHECK(ver_calls == 0, "t37/F3: для не-HTTP клиента позван HTTP-зонд");
            CHECK(said("ПОДТВЕРЖДЕНО собственным зондом на уровне рукопожатия"),
                  "t37/F3: рукопожатие с ALPN клиента не подтвердило план");
            const d2k_cat_binding *bd = binding_of(&c, nm, 6);
            CHECK(bd && bd->verified_by == D2K_VERBY_PROBE_HANDSHAKE,
                  "t37/F3: привязка не помечена уровнем рукопожатия (выдана за приложение)");
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
            d2k_sched_alpn_ver_hook = saved_alpn;
            tcp_answer = D2K_V_OPAQUE;
        }
        /* F3, раунд 2: рукопожатие НЕ было заблокировано (CLEAR), блок
           доказан обрывом объёма (RX-cut, мерился по HTTP — сервер говорит
           HTTP). Рукопожатие тут проходит и без плана, и «доказательство
           рукопожатием» было бы ложным подтверждением. Ни клиент без ALPN,
           ни даже явный не-HTTP ALPN не уводят такое испытание с RX-пути. */
        for (int variant = 0; variant < 2; variant++) {
            d2k_sched_alpn_ver_fn saved_alpn = d2k_sched_alpn_ver_hook;
            d2k_sched_alpn_ver_hook = stub_alpn_ver;
            d2k_catalog c = {0};
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            tcp_answer = D2K_V_CLEAR; tcp_owns_search = tcp_found_arm = 0;
            vol_answer = D2K_VOL_PASSED; vol_rx_cut = 1;
            ver_answer = D2K_VER_HANDSHAKE; ver_fail_first = 0;
            tcp_calls = ver_calls = alpn_ver_calls = 0;
            const char *nm = variant ? "rxcut-mqtt.example" : "rxcut-noalpn.example";
            uint16_t cport = (uint16_t)(42441 + variant);
            ver_answer_port = cport;
            d2k_ev sh;
            CHECK(tls_shape_event(&sh, nm, D2K_SHAPE_MODERN) == 0, "t37/F3r2: снимок");
            uint8_t list[256]; size_t ll = 0;
            CHECK(d2k_hello_alpn(sh.shape, sh.shape_len, list, sizeof list, &ll) == 1 && ll == 12,
                  "t37/F3r2: ALPN профиля");
            for (size_t i = 0; ll == 12 && i + 18 <= sh.shape_len; i++) {
                /* тип 0x0010, длина 14, список 12 */
                if (sh.shape[i] == 0x00 && sh.shape[i + 1] == 0x10 && sh.shape[i + 2] == 0 &&
                    sh.shape[i + 3] == 14 && !memcmp(sh.shape + i + 6, list, 12)) {
                    static const uint8_t mqtt[12] = { 4,'m','q','t','t', 6,'m','q','t','t','v','5' };
                    if (variant) memcpy(sh.shape + i + 6, mqtt, 12);
                    else { sh.shape[i] = 0x0a; sh.shape[i + 1] = 0x0a; } /* GREASE: ALPN нет */
                    break;
                }
            }
            int arc = d2k_hello_alpn(sh.shape, sh.shape_len, list, sizeof list, &ll);
            CHECK(variant ? (arc == 1 && !d2k_alpn_is_http(list, ll)) : arc == 0,
                  "t37/F3r2: снимок не переписан");
            drain(); forget_sent();
            d2k_ev h = ev_hello(6, cport, nm); d2k_sched_event(s, &h);
            d2k_sched_event(s, &sh);
            d2k_ev su = ev_suspect(6, cport); d2k_sched_event(s, &su);
            for (int i = 0; i < 20; i++) {
                spin(s, 100);
                d2k_ev ap = ev_applied(6, cport); d2k_sched_event(s, &ap);
                spin(s, 5);
            }
            CHECK(tcp_calls == 1 && ver_calls >= 1,
                  "t37/F3r2: RX-cut после CLEAR не дошёл до испытаний обычным путём");
            CHECK(alpn_ver_calls == 0,
                  "t37/F3r2: при незаблокированном рукопожатии позван зонд «рукопожатием»");
            CHECK(!said("на уровне рукопожатия"),
                  "t37/F3r2: план подтверждён рукопожатием, которое проходит и без него");
            for (size_t bi = 0; bi < c.n_boxes; bi++)
                for (size_t j = 0; j < c.boxes[bi].n_binds; j++)
                    CHECK(c.boxes[bi].binds[j].verified_by != D2K_VERBY_PROBE_HANDSHAKE,
                          "t37/F3r2: привязка записана уровнем рукопожатия");
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
            d2k_sched_alpn_ver_hook = saved_alpn;
            vol_rx_cut = 0; tcp_answer = D2K_V_OPAQUE; ver_answer = D2K_VER_APPLICATION;
        }
        if (measured_only) { goto voice_only_done; }
    }

own_first_test:
    /* --- ЗАДАЧА 32: свои подтверждённые планы — до полного замера ----------
       Поле 02.10.2026: static.rutracker.cc классифицировался 338 с, хотя
       plan-680fbe00 той же коробки был подтверждён для rutracker.org за 28 с
       до начала и подтвердился для static.rutracker.cc через 30 с после
       классификации. ТЗ §3.4/§5: для подходящей коробки сначала проверить
       своё найденное решение; применимость доказывает собственный зонд.
       Базовый вопрос донора (триггер целиком) подтвердил блокировку на
       рукопожатии — и до продолжения классификации пробуются не больше трёх
       своих подтверждённых планов той же формы. */
    {
        d2k_sched_tcp_fn saved_base = d2k_sched_tcp_base_hook;
        d2k_sched_ver_fn saved_rx = d2k_sched_rx_ver_hook;
        d2k_sched_ver_fn saved_gzip = d2k_sched_rx_gzip_ver_hook;
        d2k_sched_tcp_base_hook = stub_base;
        tcp_found_arm = 0; tcp_owns_search = 0;
        tcp_wait_until_stop = 0; tcp_block_until_stop = 0;
        ver_fail_first = 0; ver_unsupported = 0; ver_cloudflare_challenge = 0;
        vol_answer = D2K_VOL_PASSED; vol_rx_cut = 0; vol_rx_tls_unavailable = 0;
        snapshot_enabled = 0;

        /* (a) Свой план другой цели подтверждается собственным зондом раньше
           полного замера: классификатор не зовётся, привязка ложится под
           коробку плана с происхождением «перенесено, проверено зондом». */
        {
            d2k_catalog c = {0};
            char pid[40];
            own_box(&c, "box-cf-own", pid, 2, 3, "rutracker.own", 6, D2K_SHAPE_MODERN, 4,
                    1790000000, 0);
            tcp_answer = D2K_V_OPAQUE; ver_answer = D2K_VER_APPLICATION;
            ver_app_after_tcp_search = 0; base_blocked_answer = 1;
            d2k_sched_rx_ver_hook = stub_rx_counting;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            base_calls = tcp_calls = ver_calls = vol_calls = layered_identity_calls = 0;
            ver_answer_port = 42101;
            d2k_ev h = ev_hello(6, 42101, "static.rutracker.own"); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 42101); d2k_sched_event(s, &su);
            settle(s);
            d2k_ev ap = ev_applied(6, 42101); d2k_sched_event(s, &ap);
            spin(s, 40);
            CHECK(base_calls == 1, "own-first: базовый вопрос донора не задан один раз");
            CHECK(said("пробую свои подтверждённые планы до полного замера: 1"),
                  "own-first: шаг своих планов не виден в журнале");
            CHECK(tcp_calls == 0 && vol_calls == 0,
                  "own-first: подтверждённый свой план не остановил полный замер");
            CHECK(layered_identity_calls >= 1,
                  "own-first: свой план испытан не RX-путём (identity) при закрытом рукопожатии");
            const d2k_cat_binding *bd = binding_of(&c, "static.rutracker.own", 6);
            CHECK(bd != NULL && !strcmp(bd->plan_id, pid),
                  "own-first: цель не привязана к своему подтверждённому плану");
            const char *owner = NULL;
            for (size_t i = 0; i < c.n_boxes; i++)
                for (size_t j = 0; j < c.boxes[i].n_binds; j++)
                    if (!strcmp(c.boxes[i].binds[j].target, "static.rutracker.own"))
                        owner = c.boxes[i].id;
            CHECK(owner && !strcmp(owner, "box-cf-own"),
                  "own-first: привязка легла не под коробку плана");
            CHECK(bd && bd->verified_by == D2K_VERBY_PROBE && bd->input == D2K_INPUT_TRANSFER &&
                  bd->level >= 3 && bd->shape == D2K_SHAPE_MODERN && bd->family == 4,
                  "own-first: происхождение не «перенесено, проверено зондом»");
            CHECK(said("ПОДТВЕРЖДЕНО собственным зондом"),
                  "own-first: подтверждение не сказано");
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
            d2k_sched_rx_ver_hook = saved_rx;
        }

        /* (a-fam) Блок доказан базовым вопросом (0/3), свой план подтверждён
           своим зондом: это такой же опыт для семейства, как после полного
           замера. Иначе семейства перестают учиться — свои планы стали
           основным путём (поле 03.10: googlevideo QUIC rr16/r1/rr12 на одном
           плане, записан только rr16). Имя в настоящей зоне: у выдуманной нет
           базового домена, и семейства там не бывает вовсе. */
        {
            d2k_catalog c = {0};
            char pid[40];
            own_box(&c, "box-fam-own", pid, 2, 3, "a.famtest.org", 6, D2K_SHAPE_MODERN, 4,
                    1790000000, 0);
            tcp_answer = D2K_V_OPAQUE; ver_answer = D2K_VER_APPLICATION;
            ver_app_after_tcp_search = 0; base_blocked_answer = 1;
            d2k_sched_rx_ver_hook = stub_rx_counting;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            base_calls = tcp_calls = ver_calls = vol_calls = layered_identity_calls = 0;
            ver_answer_port = 42109;
            d2k_ev h = ev_hello(6, 42109, "b.famtest.org"); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 42109); d2k_sched_event(s, &su);
            settle(s);
            d2k_ev ap = ev_applied(6, 42109); d2k_sched_event(s, &ap);
            spin(s, 40);
            CHECK(said("ПОДТВЕРЖДЕНО собственным зондом") && tcp_calls == 0,
                  "own-first fam: свой план не подтвердился до полного замера");
            int own_vote = 0;
            for (size_t i = 0; c.groups && i < c.groups->n_observations; i++)
                if (!strcmp(c.groups->observations[i].name, "b.famtest.org") &&
                    !strcmp(c.groups->observations[i].plan_id, pid) &&
                    (c.groups->observations[i].evidence & D2K_GROUP_BLOCKED_CONFIRMED)) own_vote = 1;
            CHECK(own_vote, "own-first fam: подтверждение своим планом не записано опытом семейства");
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
            d2k_sched_rx_ver_hook = saved_rx;
        }

        /* (a2) ЗАДАЧА 49: GREASE ECH (любой Chromium) — те же свои планы до
           полного замера. Поле 03.10: meduza.io IPv6 со снимком ECH offer
           шёл 4:37 полным деревом (104 зонда), хотя plan-680fbe00 той же
           формы и семейства был в каталоге: own_first_plans отказывал при
           ech_offer, а GREASE распознаётся позже, в рабочем потоке, после
           чего поток сразу шёл в полный классификатор. */
        {
            d2k_catalog c = {0};
            char pid[40];
            own_box(&c, "box-cf-grease", pid, 2, 3, "rutracker.grease", 6, D2K_SHAPE_MODERN, 4,
                    1790000000, 0);
            tcp_answer = D2K_V_OPAQUE; ver_answer = D2K_VER_APPLICATION;
            ver_app_after_tcp_search = 0; base_blocked_answer = 1;
            d2k_sched_rx_ver_hook = stub_rx_counting;
            d2k_sched_ech_resolve_hook = stub_ech_resolve;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            base_calls = tcp_calls = ver_calls = vol_calls = 0;
            ver_answer_port = 42105;
            uint8_t eb[2048]; size_t el = 0;
            CHECK(ech_offer_hello("grease-own.example", eb, sizeof eb, &el) == 0 &&
                  d2k_hello_ech_offer(eb, el, NULL) == 1, "own-first GREASE: fixture");
            d2k_ev h = ev_hello(6, 42105, "grease-own.example"); d2k_sched_event(s, &h);
            d2k_ev sh; memset(&sh, 0, sizeof sh);
            sh.kind = D2K_EV_SHAPE; sh.transport = 6;
            memcpy(sh.shape, eb, el); sh.shape_len = el;
            d2k_sched_event(s, &sh);
            d2k_ev su = ev_suspect(6, 42105); d2k_sched_event(s, &su);
            settle(s);
            d2k_ev ap = ev_applied(6, 42105); d2k_sched_event(s, &ap);
            spin(s, 40);
            CHECK(said("GREASE"), "own-first GREASE: GREASE не распознан");
            CHECK(base_calls == 1, "own-first GREASE: базовый вопрос донора не задан");
            CHECK(said("пробую свои подтверждённые планы до полного замера: 1"),
                  "own-first GREASE: свои планы не пробовались до полного замера");
            CHECK(tcp_calls == 0, "own-first GREASE: полный классификатор пошёл раньше своих планов");
            const d2k_cat_binding *bd = binding_of(&c, "grease-own.example", 6);
            CHECK(bd != NULL && !strcmp(bd->plan_id, pid),
                  "own-first GREASE: цель не подтверждена своим планом");
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
            d2k_sched_rx_ver_hook = saved_rx;
            d2k_sched_ech_resolve_hook = d2k_ech_resolve;
        }

        /* (a3) GREASE, свой план не помог: ровно один полный прогон с ответом
           базы, HTTPS RR второй раз не спрашивается. */
        {
            d2k_catalog c = {0};
            char pid[40];
            own_box(&c, "box-cf-grease-miss", pid, 2, 3, "rutracker.grease-miss", 6,
                    D2K_SHAPE_MODERN, 4, 1790000000, 0);
            tcp_answer = D2K_V_INCONCLUSIVE; ver_answer = D2K_VER_HANDSHAKE;
            ver_app_after_tcp_search = 0; base_blocked_answer = 1;
            d2k_sched_tcp_seeded_hook = stub_tcp_seeded;
            seeded_calls = 0;
            d2k_sched_ech_resolve_hook = stub_ech_resolve;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            base_calls = tcp_calls = ver_calls = vol_calls = 0;
            uint8_t eb[2048]; size_t el = 0;
            CHECK(ech_offer_hello("grease-miss.example", eb, sizeof eb, &el) == 0,
                  "own-first GREASE miss: fixture");
            d2k_ev h = ev_hello(6, 42106, "grease-miss.example"); d2k_sched_event(s, &h);
            d2k_ev sh; memset(&sh, 0, sizeof sh);
            sh.kind = D2K_EV_SHAPE; sh.transport = 6;
            memcpy(sh.shape, eb, el); sh.shape_len = el;
            d2k_sched_event(s, &sh);
            ech_resolve_calls = 0;
            d2k_ev su = ev_suspect(6, 42106); d2k_sched_event(s, &su);
            for (int i = 0; i < 30 && tcp_calls == 0; i++) { skip_ahead(s, 6000); spin(s, 40); }
            settle(s);
            int resolves = ech_resolve_calls;
            CHECK(base_calls == 1 && tcp_calls == 1 && seeded_calls == 1,
                  "own-first GREASE miss: не ровно одна база и один полный прогон с её ответом");
            /* Одно решение «GREASE» (имя + свидетели адреса) — и только одно:
               перезапуск после regrade ECH-ветку не повторяет. */
            CHECK(resolves >= 1 && said_count("ECH offer — GREASE") == 1,
                  "own-first GREASE miss: HTTPS RR спрошен повторно после regrade");
            CHECK(said("свои подтверждённые планы не подтвердились"),
                  "own-first GREASE miss: неудача своих планов не видна");
            d2k_sched_tcp_seeded_hook = NULL;
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
            d2k_sched_ech_resolve_hook = d2k_ech_resolve;
        }

        /* (b) Свой план не подтвердился: классификация продолжается как
           прежде, её вердикт и её кандидаты — те же, что без этого шага. */
        {
            d2k_catalog c = {0};
            char pid[40];
            own_box(&c, "box-cf-miss", pid, 2, 3, "miss-first.own", 6, D2K_SHAPE_MODERN, 4,
                    1790000000, 0);
            tcp_answer = D2K_V_PREFIX; ver_answer = D2K_VER_APPLICATION;
            ver_app_after_tcp_search = 1; base_blocked_answer = 1;
            d2k_sched_tcp_seeded_hook = stub_tcp_seeded;
            seeded_calls = 0; seeded_pass = seeded_fail = -2;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            base_calls = tcp_calls = ver_calls = vol_calls = 0;
            ver_answer_port = 42111;
            d2k_ev h = ev_hello(6, 42111, "miss-second.own"); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 42111); d2k_sched_event(s, &su);
            for (int i = 0; i < 40 && !said("ПОДТВЕРЖДЕНО"); i++) {
                spin(s, 200);
                d2k_ev ap = ev_applied(6, 42111); d2k_sched_event(s, &ap);
                spin(s, 5);
            }
            CHECK(base_calls == 1 && tcp_calls == 1,
                  "own-first: после неудачи своих планов полный замер не выполнен ровно раз");
            CHECK(said("пробую свои подтверждённые планы до полного замера: 1") &&
                  said("свои подтверждённые планы не подтвердились"),
                  "own-first: неудача своих планов не видна в журнале");
            const char *own_at = strstr(saidbuf, "пробую свои подтверждённые планы");
            const char *verdict_at = strstr(saidbuf, "вердикт: помогает разрез");
            CHECK(own_at && verdict_at && own_at < verdict_at,
                  "own-first: вердикт донора не тот или пришёл раньше своих планов");
            const d2k_cat_binding *bd = binding_of(&c, "miss-second.own", 6);
            CHECK(bd != NULL && bd->input != D2K_INPUT_TRANSFER,
                  "own-first: после полного замера подтверждение записано как перенос");
            CHECK(seeded_calls == 1 && seeded_pass == 0 && seeded_fail == 3,
                  "own-first: полный замер не получил ответ базового вопроса (I2)");
            d2k_sched_tcp_seeded_hook = NULL;
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
            ver_app_after_tcp_search = 0;
        }

        /* (c) ЗАДАЧА 49: БЕЗ ПОТОЛКА «ТРИ». Свой план — одна проверка за
           секунды, полный замер — ~100 зондов и минуты (meduza.io IPv6 03.10),
           поэтому пробуются ВСЕ подходящие свои планы; классификатор —
           только когда не подтвердился ни один.
           ПОРЯДОК — ПО ЧИСЛУ УСПЕХОВ, ЗАТЕМ ПО СВЕЖЕСТИ (поле 04.10, откат
           порядка задачи 49): «свежее первым» поставило media.discordapp.net
           и cdn.discordapp.com на свежий plan-8830b1a2 без приманки, он
           «подтвердился» ответом 401/403 почти без тела, а plan-680fbe00 —
           обход 16-КБ заморозки Cloudflare, подтверждённый на десятках
           имён, — до очереди не дошёл; картинки Discord встали. */
        {
            d2k_catalog c = {0};
            char p1[40], p5[40], p3[40], p4a[40], p4b[40];
            own_box(&c, "box-s1", p1, 11, 1, "s1.limit.own", 6, D2K_SHAPE_MODERN, 4, 1790000300, 0);
            own_box(&c, "box-s5", p5, 15, 5, "s5.limit.own", 6, D2K_SHAPE_MODERN, 4, 1790000000, 0);
            own_box(&c, "box-s3", p3, 13, 3, "s3.limit.own", 6, D2K_SHAPE_MODERN, 4, 1790000400, 0);
            own_box(&c, "box-s4a", p4a, 14, 4, "s4a.limit.own", 6, D2K_SHAPE_MODERN, 4, 1790000100, 0);
            own_box(&c, "box-s4b", p4b, 16, 4, "s4b.limit.own", 6, D2K_SHAPE_MODERN, 4, 1790000200, 0);
            tcp_answer = D2K_V_INCONCLUSIVE; ver_answer = D2K_VER_HANDSHAKE;
            ver_app_after_tcp_search = 0; base_blocked_answer = 1;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            spin(s, 5);
            forget_sent();
            base_calls = tcp_calls = ver_calls = vol_calls = 0;
            ver_answer_port = 42121;
            d2k_ev h = ev_hello(6, 42121, "new.limit-target.own"); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 42121); d2k_sched_event(s, &su);
            for (int i = 0; i < 30 && tcp_calls == 0; i++) { skip_ahead(s, 6000); spin(s, 40); }
            settle(s);
            CHECK(said("пробую свои подтверждённые планы до полного замера: 5"),
                  "own-first: свои планы взяты не все");
            CHECK(said_count("поставил план") == 5 && ver_calls == 5,
                  "own-first: испытаны не все свои планы ровно по разу");
            CHECK(sent_first_split_index(15) == 0 && sent_first_split_index(16) == 1 &&
                  sent_first_split_index(14) == 2 && sent_first_split_index(13) == 3 &&
                  sent_first_split_index(11) == 4,
                  "own-first: порядок не «больше успехов, затем свежее»");
            CHECK(tcp_calls == 1, "own-first: полный замер не продолжился после неудачи всех своих");
            CHECK(!binding_of(&c, "new.limit-target.own", 6),
                  "own-first: неподтверждённый план привязан");
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
        }

        /* (c2) Нужный — четвёртый по свежести (прежний потолок «три» его не
           брал): подтверждён без классификатора. (c3) Своих планов больше
           очереди задачи (SCHED_MAX_PLANS): очередь пополняется следующими
           по свежести, нужный девятый тоже подтверждается без классификатора. */
        for (int variant = 0; variant < 2; variant++) {
            int n_own = variant == 0 ? 4 : 10;
            d2k_catalog c = {0};
            char ids[10][40];
            for (int k = 0; k < n_own; k++) {
                char box[32], tgt[48];
                snprintf(box, sizeof box, "box-many-%d", k);
                snprintf(tgt, sizeof tgt, "m%d.many.own", k);
                own_box(&c, box, ids[k], (unsigned)(30 + k), 1, tgt, 6, D2K_SHAPE_MODERN, 4,
                        1790001000 - k * 10, 0); /* k = место по свежести */
            }
            tcp_answer = D2K_V_OPAQUE; ver_answer = D2K_VER_APPLICATION;
            ver_fail_first = n_own - 1; ver_app_after_tcp_search = 0; base_blocked_answer = 1;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            spin(s, 5);
            forget_sent();
            base_calls = tcp_calls = ver_calls = vol_calls = 0;
            uint16_t port = (uint16_t)(42141 + variant);
            ver_answer_port = port;
            char tgt[48];
            snprintf(tgt, sizeof tgt, "many%d.target.own", variant);
            d2k_ev h = ev_hello(6, port, tgt); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, port); d2k_sched_event(s, &su);
            for (int i = 0; i < 60 && !said("ПОДТВЕРЖДЕНО") && tcp_calls == 0; i++) {
                skip_ahead(s, 6000); spin(s, 40);
                d2k_ev ap = ev_applied(6, port); d2k_sched_event(s, &ap);
                spin(s, 5);
            }
            settle(s);
            const d2k_cat_binding *bd = binding_of(&c, tgt, 6);
            CHECK(tcp_calls == 0, "own-first: классификатор пошёл, хотя подходящий свой план был");
            CHECK(bd != NULL && !strcmp(bd->plan_id, ids[n_own - 1]),
                  "own-first: подтверждён не тот свой план (не последний по свежести)");
            CHECK(bd && bd->shape == D2K_SHAPE_MODERN && bd->family == 4 &&
                  (bd->transport ? bd->transport : 6) == 6,
                  "own-first: привязка не той формы/семейства/транспорта");
            CHECK(ver_calls == n_own, "own-first: свои планы испытаны не ровно по разу до подтверждения");
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
            ver_fail_first = 0;
        }

        /* (c4) ЗАДАЧА 49, повторное ревью A: фаза своих планов не съедает
           срок полного замера. Свои планы шли 9 мин, полный замер — ещё 3:
           от начала поиска 12 мин, больше SCHED_TASK_LIFE_MS. Замер обязан
           дойти до вердикта, а не быть брошенным «не уложился». */
        {
            d2k_catalog c = {0};
            char pa[40], pb[40];
            own_box(&c, "box-life-a", pa, 41, 1, "a.life.own", 6, D2K_SHAPE_MODERN, 4, 1790000100, 0);
            own_box(&c, "box-life-b", pb, 42, 1, "b.life.own", 6, D2K_SHAPE_MODERN, 4, 1790000000, 0);
            tcp_answer = D2K_V_INCONCLUSIVE; ver_answer = D2K_VER_HANDSHAKE;
            ver_app_after_tcp_search = 0; base_blocked_answer = 1;
            tcp_wait_until_stop = 1; tcp_release_waiters = 0; tcp_saw_stop = 0;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            spin(s, 5);
            base_calls = tcp_calls = ver_calls = vol_calls = 0;
            ver_answer_port = 42151;
            d2k_ev h = ev_hello(6, 42151, "life.target.own"); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 42151); d2k_sched_event(s, &su);
            for (int i = 0; i < 40 && !said("пробую свои подтверждённые планы"); i++) spin(s, 20);
            char since0[64] = "", since1[64] = "";
            {
                const char *e = strstr(live_task_entry(s, "life.target.own"), "\"since\": ");
                if (e) snprintf(since0, sizeof since0, "%.40s", e);
            }
            skip_ahead(s, 9 * 60 * 1000);
            for (int i = 0; i < 60 && tcp_calls == 0; i++) { skip_ahead(s, 6000); spin(s, 20); }
            CHECK(tcp_calls == 1, "own-first life: полный замер не начался после своих планов");
            {
                const char *e = strstr(live_task_entry(s, "life.target.own"), "\"since\": ");
                if (e) snprintf(since1, sizeof since1, "%.40s", e);
            }
            /* Срок окна перезапущен, но время поиска на карточке — от его
               начала: карточка не «молодеет» на фазу своих планов. */
            CHECK(since0[0] && !strcmp(since0, since1),
                  "own-first life: карточка показывает время от перезапуска окна, а не от начала поиска");
            skip_ahead(s, 3 * 60 * 1000);
            spin(s, 40);
            tcp_release_waiters = 1;
            settle(s);
            CHECK(!tcp_saw_stop && !said("не уложился"),
                  "own-first life: фаза своих планов съела срок полного замера");
            CHECK(said("прямой замер не подтвердил блокировку") || said("вердикт:"),
                  "own-first life: полный замер не дошёл до итога");
            tcp_wait_until_stop = 0; tcp_release_waiters = 0;
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
        }

        /* (c5) Повторное ревью, Minor 1: своих планов больше бюджета
           кандидатов задачи. Кончился бюджет — так и сказано, с числом НЕ
           испытанных; «не подтвердились» про неиспытанные не говорится; дальше
           полный замер. Порции после бюджета не прокручиваются. */
        {
            int budget = (int)(D2K_PROPS_QUESTIONS + 8 + D2K_RX_VOLUME_PLAN_VARIANTS +
                               d2k_fallback_arms());
            int n_own = budget + 3;
            d2k_catalog c = {0};
            for (int k = 0; k < n_own; k++) {
                char box[32], tgt[48], id[40];
                snprintf(box, sizeof box, "box-budget-%d", k);
                snprintf(tgt, sizeof tgt, "b%d.budget.own", k);
                own_box(&c, box, id, (unsigned)(100 + k), 1, tgt, 6, D2K_SHAPE_MODERN, 4,
                        1790002000 - k, 0);
            }
            tcp_answer = D2K_V_INCONCLUSIVE; ver_answer = D2K_VER_HANDSHAKE;
            ver_app_after_tcp_search = 0; base_blocked_answer = 1;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            spin(s, 5);
            base_calls = tcp_calls = ver_calls = vol_calls = 0;
            ver_answer_port = 42161;
            d2k_ev h = ev_hello(6, 42161, "budget.target.own"); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 42161); d2k_sched_event(s, &su);
            for (int i = 0; i < 4000 && tcp_calls == 0; i++) { skip_ahead(s, 1000); spin(s, 3); }
            settle(s);
            CHECK(tcp_calls == 1, "own-first budget: полный замер не пошёл после бюджета своих планов");
            CHECK(said("НЕ испытано"), "own-first budget: не сказано, сколько своих планов не испытано");
            CHECK(!said("свои подтверждённые планы не подтвердились"),
                  "own-first budget: неиспытанные планы названы неподтвердившимися");
            CHECK(ver_calls < n_own, "own-first budget: испытано больше, чем позволяет бюджет");
            d2k_sched_free(s); d2k_catalog_free(&c);
        }

        /* (d) Формы, транспорты и семейства не смешиваются; помеченная к
           перепроверке и выключенная привязка — не подтверждённое знание. */
        {
            d2k_catalog c = {0};
            char pl[40], pq[40], pr[40], p6[40], pd[40];
            own_box(&c, "box-legacy", pl, 21, 9, "legacy.mix.own", 6, D2K_SHAPE_LEGACY, 4, 1790000000, 0);
            own_box(&c, "box-quic", pq, 22, 9, "quic.mix.own", 17, D2K_LINK_SHAPE_QUIC, 4, 1790000000, 0);
            own_box(&c, "box-recheck", pr, 23, 9, "recheck.mix.own", 6, D2K_SHAPE_MODERN, 4,
                    1790000000, 1790000500);
            own_box(&c, "box-v6", p6, 24, 9, "v6.mix.own", 6, D2K_SHAPE_MODERN, 6, 1790000000, 0);
            own_box(&c, "box-disabled", pd, 25, 9, "disabled.mix.own", 6, D2K_SHAPE_MODERN, 4,
                    1790000000, 0);
            c.boxes[c.n_boxes - 1].binds[0].enabled = 0;
            tcp_answer = D2K_V_INCONCLUSIVE; ver_answer = D2K_VER_HANDSHAKE;
            ver_app_after_tcp_search = 0; base_blocked_answer = 1;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            base_calls = tcp_calls = ver_calls = 0;
            drain(); forget_sent();
            d2k_ev h = ev_hello(6, 42131, "modern.mix-target.own"); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 42131); d2k_sched_event(s, &su);
            settle(s);
            /* План формы 1.2 — гипотеза для клиента 1.3 (поле 04.10, решение
               координатора): предлагается, но один — QUIC, другое семейство,
               помеченный к перепроверке и выключенный не предлагаются. */
            CHECK(base_calls == 1 && tcp_calls == 1 &&
                  said("пробую свои подтверждённые планы до полного замера: 1") &&
                  sent_first_split_index(21) == 0 && sent_first_split_index(23) < 0 &&
                  sent_first_split_index(24) < 0 && sent_first_split_index(25) < 0,
                  "own-first: TLS 1.3-цели предложены планы другого транспорта/семейства "
                  "или помеченные к перепроверке");
            /* Тот же каталог, клиент TLS 1.2: берётся только план формы 1.2. */
            saidbuf[0] = '\0';
            spin(s, 5);
            forget_sent();
            base_calls = tcp_calls = ver_calls = 0;
            ver_answer_port = 42132;
            d2k_ev sh;
            CHECK(tls_shape_event(&sh, "legacy.mix-target.own", D2K_SHAPE_LEGACY) == 0,
                  "own-first: снимок TLS 1.2 не собран");
            d2k_sched_event(s, &sh);
            d2k_ev h2 = ev_hello(6, 42132, "legacy.mix-target.own"); d2k_sched_event(s, &h2);
            d2k_ev su2 = ev_suspect(6, 42132); d2k_sched_event(s, &su2);
            for (int i = 0; i < 30 && tcp_calls == 0; i++) { skip_ahead(s, 6000); spin(s, 40); }
            CHECK(base_calls == 1 && said("пробую свои подтверждённые планы до полного замера: 1"),
                  "own-first: TLS 1.2-клиенту не предложен свой план формы 1.2");
            CHECK(sent_first_split_index(21) == 0 && said_count("поставил план") == 1,
                  "own-first: TLS 1.2-клиенту испытан план другой формы");
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
            /* QUIC: этот шаг только для TCP (QUIC — своим путём оригинала). */
            d2k_catalog cq = {0};
            own_box(&cq, "box-quic-only", pq, 26, 9, "quic.only.own", 17, D2K_LINK_SHAPE_QUIC, 4,
                    1790000000, 0);
            s = d2k_sched_new(&cq, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            base_calls = 0;
            d2k_ev hq = ev_hello(17, 42133, "quic.target.own"); d2k_sched_event(s, &hq);
            d2k_ev sq = ev_suspect(17, 42133); d2k_sched_event(s, &sq);
            settle(s);
            CHECK(base_calls == 0 && !said("пробую свои подтверждённые"),
                  "own-first: без QUIC-крючка базы QUIC-цели задан TCP-базовый вопрос");
            d2k_sched_free(s); d2k_catalog_free(&cq);
        }

        /* (f) ПОЛЕ 04.10.2026, updates.discord.com: приложение Discord ходит
           коротким приветствием TLS 1.2 (179 байт, форма 2 в подозрении), а
           снимка к началу поиска ещё нет. Задача мерила ЗАГОТОВКОЙ TLS 1.3,
           own_first_plans брал свой план формы 1, зонд вёл TLS 1.3, и
           привязка легла формой 1 — датапат отказывал потокам приложения
           («отказов по форме приветствия»), обновление не проходило.
           Форма клиента известна из подозрения: заготовка, свои планы,
           зонд и привязка — той же формы, что у клиента. */
        {
            /* (f1) Своих планов формы 1.2 нет — план формы 1.3 клиенту 1.2 не
               переносится; замер идёт приветствием старой формы. */
            d2k_catalog c = {0};
            char pm[40];
            own_box(&c, "box-modern-only", pm, 41, 3, "modern.app.own", 6, D2K_SHAPE_MODERN, 4,
                    1790000000, 0);
            tcp_answer = D2K_V_INCONCLUSIVE; ver_answer = D2K_VER_APPLICATION;
            ver_app_after_tcp_search = 0; base_blocked_answer = 1;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            base_calls = tcp_calls = ver_calls = 0;
            memset(tcp_last_trig, 0, sizeof tcp_last_trig); tcp_last_wire = 0;
            ver_answer_port = 42171;
            d2k_ev h = ev_hello(6, 42171, "updates.app.own"); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 42171); su.client_shape = D2K_SHAPE_LEGACY;
            d2k_sched_event(s, &su);
            settle(s);
            d2k_ev ap = ev_applied(6, 42171); d2k_sched_event(s, &ap);
            spin(s, 40);
            /* С 04.10 (решение координатора) план формы 1.3 предлагается
               клиенту 1.2 гипотезой — но испытывается зондом TLS 1.2 и
               привязывается формой 1.2 (см. g1). */
            CHECK(ver_calls >= 1 && ver_last_shape == (uint8_t)D2K_SHAPE_LEGACY,
                  "shape f1: клиенту TLS 1.2 план испытан зондом другой формы");
            CHECK(binding_shape(&c, "updates.app.own", 6, D2K_SHAPE_MODERN) == NULL,
                  "shape f1: клиенту TLS 1.2 записана привязка формы TLS 1.3");
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
        }
        {
            /* (f2) Свой план формы 1.2 есть: он и переносится, зонд TLS 1.2,
               привязка формы 1.2. Снимок клиента (та же форма) приходит
               ПОСЛЕ ответа базы — посреди испытания своих планов. */
            d2k_catalog c = {0};
            char pm[40], pl[40];
            own_box(&c, "box-modern-app", pm, 42, 5, "modern.app2.own", 6, D2K_SHAPE_MODERN, 4,
                    1790000000, 0);
            own_box(&c, "box-legacy-app", pl, 43, 3, "legacy.app2.own", 6, D2K_SHAPE_LEGACY, 4,
                    1790000000, 0);
            tcp_answer = D2K_V_INCONCLUSIVE; ver_answer = D2K_VER_APPLICATION;
            ver_app_after_tcp_search = 0; base_blocked_answer = 1;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            base_calls = tcp_calls = ver_calls = 0; ver_last_shape = 0;
            drain(); forget_sent();
            ver_answer_port = 42172;
            d2k_ev h = ev_hello(6, 42172, "updates.app2.own"); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 42172); su.client_shape = D2K_SHAPE_LEGACY;
            d2k_sched_event(s, &su);
            for (int i = 0; i < 400 && !said("пробую свои подтверждённые"); i++) tick_once(s);
            d2k_ev sh;
            CHECK(tls_shape_event(&sh, "updates.app2.own", D2K_SHAPE_LEGACY) == 0,
                  "shape f2: снимок TLS 1.2 не собран");
            d2k_sched_event(s, &sh);
            settle(s);
            d2k_ev ap = ev_applied(6, 42172); d2k_sched_event(s, &ap);
            spin(s, 40);
            CHECK(base_calls == 1 && said("пробую свои подтверждённые планы до полного замера: 2") &&
                  sent_first_split_index(43) == 0,
                  "shape f2: клиенту TLS 1.2 свой план формы TLS 1.2 предложен не первым");
            CHECK(ver_calls >= 1 && ver_last_shape == (uint8_t)D2K_SHAPE_LEGACY,
                  "shape f2: свой план испытан не зондом TLS 1.2");
            const d2k_cat_binding *lg = binding_shape(&c, "updates.app2.own", 6, D2K_SHAPE_LEGACY);
            CHECK(lg != NULL && !strcmp(lg->plan_id, pl) && lg->level >= 3,
                  "shape f2: привязка клиента TLS 1.2 легла не формой TLS 1.2");
            CHECK(binding_shape(&c, "updates.app2.own", 6, D2K_SHAPE_MODERN) == NULL,
                  "shape f2: клиенту TLS 1.2 записана привязка формы TLS 1.3");
            drain(); forget_sent(); d2k_sched_sync(s); sync_out(s);
            CHECK(sent_set_name_shape("updates.app2.own", D2K_SHAPE_LEGACY) == 1 &&
                  sent_set_name_shape("updates.app2.own", D2K_SHAPE_MODERN) == 0,
                  "shape f2: датапату не ушла постоянная привязка формы TLS 1.2");
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
        }
        {
            /* (f3) Обратное направление и две формы на одном имени: у имени
               уже есть привязка формы 1.2 (приложение), в ячейке снимка —
               приветствие 1.2 этого имени, а подозрение пришло от браузера
               формы 1.3. Мерить и подтверждать надо формой 1.3, не байтами
               чужого клиента; привязка 1.2 остаётся. */
            d2k_catalog c = {0};
            char pm[40], pl[40];
            own_box(&c, "box-modern-br", pm, 44, 3, "modern.app3.own", 6, D2K_SHAPE_MODERN, 4,
                    1790000000, 0);
            own_box(&c, "box-legacy-br", pl, 45, 3, "updates.app3.own", 6, D2K_SHAPE_LEGACY, 4,
                    1790000000, 0);
            tcp_answer = D2K_V_OPAQUE; ver_answer = D2K_VER_APPLICATION;
            ver_app_after_tcp_search = 0; base_blocked_answer = 1;
            d2k_sched_rx_ver_hook = stub_rx_counting;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            base_calls = tcp_calls = ver_calls = 0; ver_last_shape = 0;
            ver_answer_port = 42173;
            d2k_ev sh;
            CHECK(tls_shape_event(&sh, "updates.app3.own", D2K_SHAPE_LEGACY) == 0,
                  "shape f3: снимок TLS 1.2 не собран");
            sh.low_ip[0] = 127; sh.low_ip[3] = 1; sh.low_port = g_server_port;
            sh.high_ip[0] = 192; sh.high_ip[1] = 168; sh.high_ip[2] = 1; sh.high_ip[3] = 67;
            sh.high_port = 42170; /* другой поток: приложение, не браузер */
            d2k_sched_event(s, &sh);
            d2k_ev h = ev_hello(6, 42173, "updates.app3.own"); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 42173); su.client_shape = D2K_SHAPE_MODERN;
            d2k_sched_event(s, &su);
            settle(s);
            d2k_ev ap = ev_applied(6, 42173); d2k_sched_event(s, &ap);
            spin(s, 40);
            CHECK(!said("повторяю поиск его байтами"),
                  "shape f3: поиск браузера перезапущен байтами другого клиента");
            CHECK(ver_calls >= 1 && ver_last_shape == (uint8_t)D2K_SHAPE_MODERN,
                  "shape f3: клиенту TLS 1.3 план испытан зондом другой формы");
            const d2k_cat_binding *md = binding_shape(&c, "updates.app3.own", 6, D2K_SHAPE_MODERN);
            CHECK(md != NULL && !strcmp(md->plan_id, pm) && md->level >= 3,
                  "shape f3: клиенту TLS 1.3 привязка не легла формой TLS 1.3");
            const d2k_cat_binding *lg = binding_shape(&c, "updates.app3.own", 6, D2K_SHAPE_LEGACY);
            CHECK(lg != NULL && !strcmp(lg->plan_id, pl) && lg->enabled && lg->level >= 3,
                  "shape f3: привязка формы TLS 1.2 того же имени задета");
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
            d2k_sched_rx_ver_hook = saved_rx;
        }
        /* (g) ПОЛЕ 04.10.2026, 11:39: апдейтер Discord уже мерится своей
           формой TLS 1.2, но фейк-первый plan-680fbe00, рабочий на этой
           коробке для discord.com и rutracker, привязан только формой 1.3 —
           own_first_plans его не предлагал, поиск кончился «выведенные планы
           исчерпаны». Решение координатора: свои планы ДРУГОЙ формы TCP-TLS
           (1.3 <-> 1.2) — гипотезы ПОСЛЕ планов своей формы; проверяются
           зондом формы клиента и проверкой бюджета, привязка — формой
           клиента. TCP<->QUIC, ECH и HTTP не пересекаются. */
        {
            /* (g1) На коробке только план формы 1.3 — клиенту 1.2 он
               испытывается зондом TLS 1.2 и привязывается формой 1.2. */
            d2k_catalog c = {0};
            char pm[40], pq[40];
            own_box(&c, "box-cross-modern", pm, 51, 3, "rutracker.cross.own", 6, D2K_SHAPE_MODERN, 4,
                    1790000000, 0);
            own_box(&c, "box-cross-quic", pq, 52, 9, "quic.cross.own", 17, D2K_LINK_SHAPE_QUIC, 4,
                    1790000000, 0);
            tcp_answer = D2K_V_INCONCLUSIVE; ver_answer = D2K_VER_APPLICATION;
            ver_app_after_tcp_search = 0; base_blocked_answer = 1; ver_fail_first = 0;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            base_calls = tcp_calls = ver_calls = 0; ver_last_shape = 0;
            drain(); forget_sent();
            ver_answer_port = 42181;
            d2k_ev h = ev_hello(6, 42181, "updates.cross.own"); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 42181); su.client_shape = D2K_SHAPE_LEGACY;
            d2k_sched_event(s, &su);
            settle(s);
            d2k_ev ap = ev_applied(6, 42181); d2k_sched_event(s, &ap);
            spin(s, 40);
            CHECK(base_calls == 1 && said("пробую свои подтверждённые планы до полного замера: 1"),
                  "shape g1: план формы 1.3 не предложен клиенту 1.2 гипотезой");
            CHECK(tcp_calls == 0 && ver_calls >= 1 && ver_last_shape == (uint8_t)D2K_SHAPE_LEGACY,
                  "shape g1: гипотеза другой формы испытана не зондом TLS 1.2");
            const d2k_cat_binding *lg = binding_shape(&c, "updates.cross.own", 6, D2K_SHAPE_LEGACY);
            CHECK(lg != NULL && !strcmp(lg->plan_id, pm) && lg->level >= 3,
                  "shape g1: подтверждённая гипотеза привязана не формой клиента 1.2");
            CHECK(binding_shape(&c, "updates.cross.own", 6, D2K_SHAPE_MODERN) == NULL,
                  "shape g1: клиенту 1.2 записана привязка формы 1.3");
            CHECK(said_count("поставил план") == 1,
                  "shape g1: TCP-клиенту предложен план QUIC");
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
        }
        {
            /* (g2) Планы своей формы — первыми, даже при большем числе
               успехов у плана другой формы; гипотеза другой формы — после. */
            d2k_catalog c = {0};
            char pm[40], pl[40];
            own_box(&c, "box-order-modern", pm, 53, 9, "modern.order.own", 6, D2K_SHAPE_MODERN, 4,
                    1790000900, 0);
            own_box(&c, "box-order-legacy", pl, 54, 1, "legacy.order.own", 6, D2K_SHAPE_LEGACY, 4,
                    1790000000, 0);
            tcp_answer = D2K_V_INCONCLUSIVE; ver_answer = D2K_VER_APPLICATION;
            ver_app_after_tcp_search = 0; base_blocked_answer = 1; ver_fail_first = 1;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            base_calls = tcp_calls = ver_calls = 0; ver_last_shape = 0;
            drain(); forget_sent();
            ver_answer_port = 42182;
            d2k_ev h = ev_hello(6, 42182, "updates.order.own"); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 42182); su.client_shape = D2K_SHAPE_LEGACY;
            d2k_sched_event(s, &su);
            for (int i = 0; i < 40 && !said("ПОДТВЕРЖДЕНО"); i++) {
                spin(s, 200);
                d2k_ev ap = ev_applied(6, 42182); d2k_sched_event(s, &ap);
            }
            spin(s, 40);
            CHECK(said("пробую свои подтверждённые планы до полного замера: 2"),
                  "shape g2: в своих планах нет обеих форм");
            CHECK(sent_first_split_index(54) == 0 && sent_first_split_index(53) == 1,
                  "shape g2: гипотеза другой формы испытана раньше плана своей формы");
            const d2k_cat_binding *lg = binding_shape(&c, "updates.order.own", 6, D2K_SHAPE_LEGACY);
            CHECK(lg != NULL && !strcmp(lg->plan_id, pm) && ver_last_shape == (uint8_t)D2K_SHAPE_LEGACY,
                  "shape g2: гипотеза другой формы не подтверждена формой клиента");
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
            ver_fail_first = 0;
        }

        /* (e) База донора не показала блокировки рукопожатия — своих планов
           не пробуем, идёт полный замер как прежде (рабочий трафик не
           подбирается, подозрение не равно блокировке). */
        {
            d2k_catalog c = {0};
            char pid[40];
            own_box(&c, "box-clear", pid, 31, 3, "clear-first.own", 6, D2K_SHAPE_MODERN, 4,
                    1790000000, 0);
            tcp_answer = D2K_V_CLEAR; ver_answer = D2K_VER_APPLICATION;
            base_blocked_answer = 0;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            base_calls = tcp_calls = ver_calls = 0;
            d2k_ev h = ev_hello(6, 42141, "clear-second.own"); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 42141); d2k_sched_event(s, &su);
            settle(s);
            CHECK(base_calls == 1 && tcp_calls == 1 && ver_calls == 0 &&
                  !said("пробую свои подтверждённые"),
                  "own-first: свои планы испытаны без блокировки на рукопожатии");
            CHECK(said("напрямую проходит"), "own-first: вердикт CLEAR полного замера потерян");
            CHECK(!binding_of(&c, "clear-second.own", 6), "own-first: рабочей цели привязан план");
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
            base_blocked_answer = 1;
        }

        /* (f) Под своим планом рукопожатие проходит, а identity-тело дважды
           обрывается при полном gzip: план не подтверждается, полный замер
           продолжается (многоэтапный RX-путь испытания). */
        {
            d2k_catalog c = {0};
            char pid[40];
            own_box(&c, "box-rx", pid, 41, 3, "rx-first.own", 6, D2K_SHAPE_MODERN, 4,
                    1790000000, 0);
            tcp_answer = D2K_V_INCONCLUSIVE; ver_answer = D2K_VER_APPLICATION;
            base_blocked_answer = 1; layered_bad_control = 0;
            d2k_sched_rx_ver_hook = stub_layered_identity;
            d2k_sched_rx_gzip_ver_hook = stub_layered_gzip;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            base_calls = tcp_calls = ver_calls = 0;
            layered_identity_calls = layered_gzip_calls = 0;
            ver_answer_port = 42151;
            d2k_ev h = ev_hello(6, 42151, "rx-second.own"); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 42151); d2k_sched_event(s, &su);
            forget_sent();
            int installed = 0;
            for (int i = 0; i < 4000 && tcp_calls == 0; i++) {
                tick_once(s);
                int n = (int)sent_command_count(D2K_CMD_SET_NAME_PROBE, NULL, 0);
                if (n > installed) {
                    installed = n;
                    d2k_ev ap = ev_applied(6, 42151); d2k_sched_event(s, &ap);
                }
            }
            settle(s);
            CHECK(layered_identity_calls == 2 && layered_gzip_calls == 1,
                  "own-first: свой план испытан не многоэтапным RX-путём");
            CHECK(tcp_calls == 1 && !binding_of(&c, "rx-second.own", 6),
                  "own-first: план с обрывом тела подтверждён или полный замер не пошёл");
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
            d2k_sched_rx_ver_hook = saved_rx;
            d2k_sched_rx_gzip_ver_hook = saved_gzip;
        }

        /* (g) Снимок клиента приходит, пока задан базовый вопрос заготовкой
           (задача 31): вопрос бросается и задаётся заново байтами клиента,
           без вердикта и без покоя; затем — свои планы. */
        {
            d2k_catalog c = {0};
            char pid[40];
            own_box(&c, "box-snap", pid, 51, 3, "snap-first.own", 6, D2K_SHAPE_MODERN, 4,
                    1790000000, 0);
            tcp_answer = D2K_V_OPAQUE; ver_answer = D2K_VER_APPLICATION;
            base_blocked_answer = 1; base_wait_until_stop = 1;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            base_calls = tcp_calls = ver_calls = 0;
            ver_answer_port = 42161;
            d2k_ev h = ev_hello(6, 42161, "snap-second.own"); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 42161); d2k_sched_event(s, &su);
            for (int i = 0; i < 400 && base_calls == 0; i++) tick_once(s);
            d2k_ev sh;
            CHECK(tls_shape_event(&sh, "snap-second.own", D2K_SHAPE_MODERN) == 0,
                  "own-first: снимок не собран");
            d2k_sched_event(s, &sh);
            settle(s);
            d2k_ev ap = ev_applied(6, 42161); d2k_sched_event(s, &ap);
            spin(s, 40);
            CHECK(base_calls == 2 && tcp_last_wire == sh.shape_len,
                  "own-first: брошенный ради снимка базовый вопрос не задан заново его байтами");
            CHECK(!said("результат неубедителен") && !said("прямой замер не подтвердил"),
                  "own-first: брошенный базовый вопрос разобран как вердикт");
            CHECK(tcp_calls == 0 && said("пробую свои подтверждённые планы до полного замера: 1"),
                  "own-first: после снимка свои планы не испытаны до полного замера");
            const d2k_cat_binding *bd = binding_of(&c, "snap-second.own", 6);
            CHECK(bd && !strcmp(bd->plan_id, pid) && bd->input == D2K_INPUT_TRANSFER,
                  "own-first: после снимка свой план не подтвердился переносом");
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
            base_wait_until_stop = 0;
        }

        /* (h) I1: свой план из коробки без отпечатка — перенос не дарит ей
           отпечаток неизмеренной цели. */
        {
            d2k_catalog c = {0};
            char pid[40];
            own_box(&c, "box-без-приметы", pid, 61, 3, "nofp-first.own", 6, D2K_SHAPE_MODERN, 4,
                    1790000000, 0);
            memset(&c.boxes[0].fp, 0, sizeof c.boxes[0].fp);
            tcp_answer = D2K_V_OPAQUE; ver_answer = D2K_VER_APPLICATION; base_blocked_answer = 1;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            base_calls = tcp_calls = 0;
            ver_answer_port = 42171;
            d2k_ev h = ev_hello(6, 42171, "nofp-second.own"); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 42171); d2k_sched_event(s, &su);
            settle(s);
            d2k_ev ap = ev_applied(6, 42171); d2k_sched_event(s, &ap);
            spin(s, 40);
            const d2k_cat_binding *bd = binding_of(&c, "nofp-second.own", 6);
            CHECK(bd && bd->input == D2K_INPUT_TRANSFER, "own-first/I1: перенос не подтвердился");
            CHECK(c.n_boxes == 1 && c.boxes[0].fp.n_sig == 0,
                  "own-first/I1: перенос записал коробке без приметы чужой отпечаток");
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
        }

        /* (i) M1: отвергнутый исполнителем свой план опыта не имел — полный
           замер вправе предложить его снова (узнанная коробка); испытанный
           на проводе — нет. */
        for (int nak = 1; nak >= 0; nak--) {
            d2k_catalog c = {0};
            char pid[40];
            own_box(&c, "box-m1", pid, 71, 3, nak ? "m1a-first.own" : "m1b-first.own", 6,
                    D2K_SHAPE_MODERN, 4, 1790000000, 0);
            d2k_cat_fp *fp = &c.boxes[0].fp;
            fp->sig[0].ttl = 127; fp->sig[0].tos = 0x88; fp->sig[0].ipid = 54321;
            tcp_answer = D2K_V_PREFIX; ver_answer = D2K_VER_HANDSHAKE; base_blocked_answer = 1;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            base_calls = tcp_calls = 0;
            const char *name = nak ? "m1a-second.own" : "m1b-second.own";
            uint16_t port = (uint16_t)(nak ? 42181 : 42182);
            ver_answer_port = port;
            forget_sent();
            d2k_ev h = ev_hello(6, port, name); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, port); d2k_sched_event(s, &su);
            if (nak) {
                for (int i = 0; i < 400 && !said("поставил план 1 из 1"); i++) tick_frozen(s);
                uint8_t id[D2K_TRIAL_ID_LEN];
                CHECK(name_probe_trial(name, id), "own-first/M1: пробный план не найден");
                d2k_ev a = name_probe_ack(id, 0, D2K_ACK_BAD_PLAN);
                d2k_sched_event(s, &a);
                for (int i = 0; i < 20; i++) tick_frozen(s);
            }
            for (int i = 0; i < 30 && tcp_calls == 0; i++) { skip_ahead(s, 6000); spin(s, 40); }
            settle(s);
            CHECK(said("свои подтверждённые планы не подтвердились") && tcp_calls == 1,
                  "own-first/M1: полный замер не пошёл");
            CHECK(nak ? said("готовых планов узнанной коробки")
                      : !said("готовых планов узнанной коробки"),
                  nak ? "own-first/M1: отвергнутый исполнителем план помечен испытанным"
                      : "own-first/M1: испытанный на проводе план предложен второй раз");
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
        }

        /* (j) QUIC: базовый вопрос QUIC подтвердил блокировку — свой QUIC-план
           той же формы подтверждается зондом H3 до полного поиска; (k) не
           подтвердился — полный поиск получает ответ базы. */
        for (int miss = 0; miss < 2; miss++) {
            d2k_catalog c = {0};
            char pid[40], ptcp[40];
            own_box(&c, "box-quic-own", pid, 81, 3, "q-first.own", 17, D2K_LINK_SHAPE_QUIC, 4,
                    1790000000, 0);
            own_box(&c, "box-tcp-near", ptcp, 82, 9, "t-first.own", 6, D2K_SHAPE_MODERN, 4,
                    1790000000, 0);
            d2k_sched_quic_base_hook = stub_quic_base;
            d2k_sched_quic_seeded_hook = stub_quic_seeded;
            quic_answer = D2K_V_INCONCLUSIVE; base_blocked_answer = 1;
            ver_answer = miss ? D2K_VER_HANDSHAKE : D2K_VER_APPLICATION;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            quic_base_calls = quic_seeded_calls = quic_calls = base_calls = ver_calls = 0;
            quic_seeded_ctl = -2;
            const char *name = miss ? "q-miss.own" : "q-second.own";
            uint16_t port = (uint16_t)(42191 + miss);
            ver_answer_port = port;
            forget_sent();
            d2k_ev h = ev_hello(17, port, name); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(17, port); d2k_sched_event(s, &su);
            if (miss) {
                for (int i = 0; i < 30 && quic_calls == 0; i++) { skip_ahead(s, 6000); spin(s, 40); }
            } else {
                settle(s);
                d2k_ev ap = ev_applied(17, port); d2k_sched_event(s, &ap);
                spin(s, 40);
            }
            CHECK(quic_base_calls == 1 && base_calls == 0 &&
                  said("пробую свои подтверждённые планы до полного замера: 1"),
                  "own-first/QUIC: базовый вопрос QUIC и свой QUIC-план не взяты");
            CHECK(ver_calls >= 1 && ver_last_transport == 17,
                  "own-first/QUIC: свой план испытан не QUIC-зондом");
            if (!miss) {
                const d2k_cat_binding *bd = binding_of(&c, name, 17);
                CHECK(quic_calls == 0 && bd && !strcmp(bd->plan_id, pid) &&
                      bd->input == D2K_INPUT_TRANSFER && bd->shape == D2K_LINK_SHAPE_QUIC,
                      "own-first/QUIC: свой QUIC-план не подтверждён переносом до полного поиска");
                const char *owner = NULL;
                for (size_t i = 0; i < c.n_boxes; i++)
                    for (size_t j = 0; j < c.boxes[i].n_binds; j++)
                        if (!strcmp(c.boxes[i].binds[j].target, name)) owner = c.boxes[i].id;
                CHECK(owner && !strcmp(owner, "box-quic-own"),
                      "own-first/QUIC: привязка легла не под коробку QUIC-плана");
            } else {
                CHECK(quic_calls == 1 && quic_seeded_calls == 1 && quic_seeded_ctl == 3,
                      "own-first/QUIC: полный поиск не получил ответ базового вопроса");
                CHECK(!binding_of(&c, name, 17) && !binding_of(&c, name, 6),
                      "own-first/QUIC: неподтверждённый план привязан");
            }
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
            d2k_sched_quic_base_hook = NULL;
            d2k_sched_quic_seeded_hook = NULL;
        }
        quic_answer = D2K_V_OPAQUE;

        /* (l) Финальное ревью core, M1 + M3. Поиск со своими планами (свой
           не помог → полный замер подтвердил заготовкой), затем снимок
           клиента — перемер. Перемер — НОВЫЙ поиск: время на карточке от его
           начала (began_carry не переживает свой запуск), и фаза своих
           планов предлагает их заново (own_seen сброшен). */
        {
            d2k_catalog c = {0};
            char pid[40];
            own_box(&c, "box-remeasure", pid, 2, 3, "remeasure-first.own", 6, D2K_SHAPE_MODERN, 4,
                    1790000000, 0);
            tcp_answer = D2K_V_PREFIX; ver_answer = D2K_VER_APPLICATION;
            ver_app_after_tcp_search = 1; base_blocked_answer = 1;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            base_calls = tcp_calls = ver_calls = vol_calls = 0;
            ver_answer_port = 42201;
            const char *nm = "remeasure-second.own";
            d2k_ev h = ev_hello(6, 42201, nm); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 42201); d2k_sched_event(s, &su);
            char since0[64] = "", since1[64] = "";
            for (int i = 0; i < 400 && !said("пробую свои подтверждённые планы"); i++) tick_once(s);
            search_since(s, nm, since0, sizeof since0);
            for (int i = 0; i < 40 && !said("ПОДТВЕРЖДЕНО"); i++) {
                spin(s, 200);
                d2k_ev ap = ev_applied(6, 42201); d2k_sched_event(s, &ap);
                spin(s, 5);
            }
            const d2k_cat_binding *bd = binding_of(&c, nm, 6);
            CHECK(tcp_calls == 1 && bd && bd->input == D2K_INPUT_PROFILE,
                  "remeasure: стенд — полный замер не подтвердил заготовкой после своих планов");
            skip_ahead(s, 5 * 60 * 1000);
            spin(s, 5);
            d2k_ev sh;
            CHECK(tls_shape_event(&sh, nm, D2K_SHAPE_MODERN) == 0, "remeasure: снимок не собран");
            d2k_sched_event(s, &sh);
            for (int i = 0; i < 400 && !said("перемеряю снимком"); i++) tick_once(s);
            CHECK(said("перемеряю снимком"), "remeasure: перемер снимком не начался");
            search_since(s, nm, since1, sizeof since1);
            for (int i = 0; i < 400 && said_count("пробую свои подтверждённые планы до") < 2 &&
                            tcp_calls < 2; i++) tick_once(s);
            CHECK(since0[0] && since1[0] && strcmp(since0, since1) != 0,
                  "remeasure/M1: перемер унаследовал начало прошлого поиска (began_carry)");
            /* Перемер предлагает И свой план чужой коробки (уже испытанный
               прошлым поиском), И только что подтверждённый план цели. */
            CHECK(said("пробую свои подтверждённые планы до полного замера: 2"),
                  "remeasure/M3: перемер не предложил свои планы заново (own_seen не сброшен)");
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
            ver_app_after_tcp_search = 0;
        }

        /* (m) Финальное ревью core, I2: фаза своих планов упёрлась в срок
           жизни задачи. Фаза кончается и идёт полный замер (со своим сроком),
           а не отдых и повтор тех же своих планов следующей задачей. */
        {
            int n_own = 40;
            d2k_catalog c = {0};
            for (int k = 0; k < n_own; k++) {
                char box[32], tgt[48], id[40];
                snprintf(box, sizeof box, "box-lifecap-%d", k);
                snprintf(tgt, sizeof tgt, "l%d.lifecap.own", k);
                own_box(&c, box, id, (unsigned)(200 + k), 1, tgt, 6, D2K_SHAPE_MODERN, 4,
                        1790003000 - k, 0);
            }
            tcp_answer = D2K_V_INCONCLUSIVE; ver_answer = D2K_VER_HANDSHAKE;
            ver_app_after_tcp_search = 0; base_blocked_answer = 1;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            spin(s, 5);
            base_calls = tcp_calls = ver_calls = vol_calls = 0;
            ver_answer_port = 42211;
            d2k_ev h = ev_hello(6, 42211, "lifecap.target.own"); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 42211); d2k_sched_event(s, &su);
            for (int i = 0; i < 400 && tcp_calls == 0; i++) { skip_ahead(s, 30000); spin(s, 3); }
            settle(s);
            CHECK(ver_calls < n_own, "own-first life cap: стенд — свои планы уложились в срок");
            CHECK(tcp_calls == 1, "own-first life cap: после срока своих планов полный замер не пошёл");
            CHECK(said_count("пробую свои подтверждённые планы до полного замера") == 1,
                  "own-first life cap: свои планы проиграны заново");
            CHECK(!said("не уложился") && !said("временно отложен"),
                  "own-first life cap: срок фазы своих планов провалил задачу в отдых");
            CHECK(said("срок фазы своих планов"), "own-first life cap: конец фазы по сроку не сказан");
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
        }

        /* ---- ЗАДАЧА 55: проверка бюджета потока (поле 04.10, Cloudflare) ----
           (n1) cdn.discordapp.com: план без приманки (только разрез) отвечает
           403, а посреди повторов сервер замолкает на 25 пакетах — НЕ
           подтверждён; план с приманкой первым держит поток — подтверждён,
           привязка помечена «бюджет пройден». Бюджет без замера коробки — 25. */
        {
            d2k_catalog c = {0};
            char p_split[40], p_fake[40];
            own_box(&c, "box-428176d8", p_split, 61, 9, "media.budget.own", 6, D2K_SHAPE_MODERN, 4,
                    1790000500, 0);
            own_box(&c, "box-e67d8c22", p_fake, 62, 2, "discord.budget.own", 6, D2K_SHAPE_MODERN, 4,
                    1790000000, 0);
            tcp_answer = D2K_V_INCONCLUSIVE; ver_answer = D2K_VER_APPLICATION;
            ver_app_after_tcp_search = 0; base_blocked_answer = 1; ver_fail_first = 0;
            ver_budget_n = 2; ver_budget_seq[0] = D2K_BUDGET_CUT; ver_budget_seq[1] = D2K_BUDGET_PASSED;
            ver_budget_status = 403;
            memset(ver_budget_seen, 0, sizeof ver_budget_seen);
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            spin(s, 5); forget_sent();
            base_calls = tcp_calls = ver_calls = vol_calls = 0;
            ver_answer_port = 42301;
            d2k_ev h = ev_hello(6, 42301, "cdn.budget.own"); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 42301); d2k_sched_event(s, &su);
            for (int i = 0; i < 60 && !said("ПОДТВЕРЖДЕНО"); i++) {
                spin(s, 100);
                d2k_ev ap = ev_applied(6, 42301); d2k_sched_event(s, &ap);
                spin(s, 5);
            }
            CHECK(sent_first_split_index(61) == 0 && sent_first_split_index(62) == 1,
                  "budget: стенд — свои планы не в порядке «успехи, затем свежесть»");
            CHECK(said("посреди повторов") && said("не подтверждаю"),
                  "budget: обрыв посреди повторов не назван под кандидатом");
            const d2k_cat_binding *bd = binding_of(&c, "cdn.budget.own", 6);
            CHECK(bd && !strcmp(bd->plan_id, p_fake) && bd->budget == D2K_CAT_BUDGET_PASSED,
                  "budget: подтверждён план, не прошедший бюджет, или отметка не записана");
            CHECK(ver_budget_seen[0] == D2K_BUDGET_FIELD_PACKETS && ver_budget_seen[1] == D2K_BUDGET_FIELD_PACKETS,
                  "budget: без замера коробки бюджет зонда не 25 (поле 04.10)");
            CHECK(said("бюджет потока пройден") && said("50"),
                  "budget: строка подтверждения без числа пакетов и исхода");
            CHECK(tcp_calls == 0, "budget: полный замер пошёл, хотя свой план прошёл бюджет");
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
            ver_budget_n = 0; ver_budget_status = 200;
        }

        /* (n2) Keep-alive не дают («не применимо»): подтверждение прежнее,
           привязка помечена «бюджет не проверен». */
        {
            d2k_catalog c = {0};
            char pid[40];
            own_box(&c, "box-ka", pid, 63, 3, "ka.budget.own", 6, D2K_SHAPE_MODERN, 4, 1790000000, 0);
            tcp_answer = D2K_V_INCONCLUSIVE; ver_answer = D2K_VER_APPLICATION;
            ver_app_after_tcp_search = 0; base_blocked_answer = 1; ver_fail_first = 0;
            ver_budget_n = 1; ver_budget_seq[0] = D2K_BUDGET_NOT_APPLICABLE;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            spin(s, 5); forget_sent();
            base_calls = tcp_calls = ver_calls = vol_calls = 0;
            ver_answer_port = 42302;
            d2k_ev h = ev_hello(6, 42302, "close.budget.own"); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 42302); d2k_sched_event(s, &su);
            for (int i = 0; i < 60 && !said("ПОДТВЕРЖДЕНО"); i++) {
                spin(s, 100);
                d2k_ev ap = ev_applied(6, 42302); d2k_sched_event(s, &ap);
                spin(s, 5);
            }
            const d2k_cat_binding *bd = binding_of(&c, "close.budget.own", 6);
            CHECK(bd && !strcmp(bd->plan_id, pid) && bd->budget == D2K_CAT_BUDGET_UNCHECKED,
                  "budget n/a: подтверждение не прежнее или привязка не помечена «не проверен»");
            CHECK(said("бюджет потока не проверен"), "budget n/a: исход не назван");
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
            ver_budget_n = 0;
        }

        /* (n3) Установка: из двух включённых привязок одного ключа ставится
           прошедшая бюджет, а не новейшая непроверенная; без отметок —
           новейшая, как прежде. Каталог не правится. */
        for (int marked = 0; marked < 2; marked++) {
            d2k_catalog c = {0};
            char p_old[40], p_new[40];
            own_box(&c, "box-sel-old", p_old, 71, 5, "sel.budget.own", 6, D2K_SHAPE_MODERN, 4,
                    1790000000, 0);
            own_box(&c, "box-sel-new", p_new, 72, 1, "sel.budget.own", 6, D2K_SHAPE_MODERN, 4,
                    1790000900, 0);
            if (marked) c.boxes[0].binds[0].budget = D2K_CAT_BUDGET_PASSED;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            drain(); forget_sent(); d2k_sched_sync(s); sync_out(s);
            int old_at = sent_first_split_index(71), new_at = sent_first_split_index(72);
            CHECK(marked ? (old_at >= 0 && new_at < 0) : (old_at < 0 && new_at >= 0),
                  marked ? "budget install: поставлена новейшая непроверенная, а не прошедшая бюджет"
                         : "budget install: без отметок поставлена не новейшая");
            CHECK(c.n_boxes == 2 && c.boxes[0].n_binds == 1 && c.boxes[1].n_binds == 1,
                  "budget install: каталог правился выбором установки");
            d2k_sched_free(s); d2k_catalog_free(&c);
        }

        /* (n4) Подозрение с потока ПОД планом: привязанный план не исключается
           вслепую, а испытывается ПЕРВЫМ с бюджетом. Прошёл — подозрение
           ложное, привязка переподтверждена, другие планы не пробуются.
           (n5) Оборвался (применение доказано) — исключён, его отметка
           «пройден» снята (ревью I-3), дальше свои планы; замена в другой
           коробке с «не применимо» — на провод идёт она, а не оборванный.
           (n5b) «Не применимо» на привязанном — не доказательство (ревью
           I-2): поиск не кончается «ложным подозрением», план не
           переподтверждается, дальше свои планы без него. */
        for (int variant = 0; variant < 3; variant++) {
            d2k_catalog c = {0};
            char p_bound[40], p_other[40];
            const char *name = variant == 1 ? "gw-cut.bound.own" :
                               variant == 2 ? "gw-na.bound.own" : "gw.bound.own";
            own_box(&c, "box-bound", p_bound, 81, 2, name, 6, D2K_SHAPE_MODERN, 4, 1790000000, 0);
            own_box(&c, "box-other", p_other, 82, 9, "other.bound.own", 6, D2K_SHAPE_MODERN, 4,
                    1790000500, 0);
            c.boxes[0].binds[0].budget = D2K_CAT_BUDGET_PASSED;
            tcp_answer = D2K_V_INCONCLUSIVE; ver_answer = D2K_VER_APPLICATION;
            ver_app_after_tcp_search = 0; base_blocked_answer = 1; ver_fail_first = 0;
            ver_budget_n = 2;
            ver_budget_seq[0] = variant == 0 ? D2K_BUDGET_PASSED :
                                variant == 1 ? D2K_BUDGET_CUT : D2K_BUDGET_NOT_APPLICABLE;
            ver_budget_seq[1] = variant == 1 ? D2K_BUDGET_NOT_APPLICABLE : D2K_BUDGET_PASSED;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            spin(s, 5); forget_sent();
            base_calls = tcp_calls = ver_calls = vol_calls = 0;
            uint16_t port = (uint16_t)(42310 + variant);
            ver_answer_port = port;
            d2k_ev h = ev_hello(6, port, name); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, port); su.planned = D2K_LINK_PLANNED_YES;
            d2k_sched_event(s, &su);
            for (int i = 0; i < 60 && !said("ПОДТВЕРЖДЕНО"); i++) {
                spin(s, 100);
                d2k_ev ap = ev_applied(6, port); d2k_sched_event(s, &ap);
                spin(s, 5);
            }
            CHECK(sent_first_split_index(81) == 0,
                  "budget suspicion: план, под которым пришло подозрение, не испытан первым");
            const d2k_cat_binding *bound_bd = &c.boxes[0].binds[0];
            const d2k_cat_binding *other_bd = NULL;
            for (size_t i = 0; i < c.n_boxes; i++)
                for (size_t j = 0; j < c.boxes[i].n_binds; j++)
                    if (!strcmp(c.boxes[i].binds[j].target, name) &&
                        !strcmp(c.boxes[i].binds[j].plan_id, p_other)) other_bd = &c.boxes[i].binds[j];
            if (variant == 0) {
                CHECK(ver_calls == 1 && sent_first_split_index(82) < 0 && tcp_calls == 0,
                      "budget suspicion: после прохода бюджета пробовались другие планы");
                CHECK(!strcmp(bound_bd->plan_id, p_bound) && bound_bd->successes >= 3 &&
                      bound_bd->budget == D2K_CAT_BUDGET_PASSED,
                      "budget suspicion: привязка не переподтверждена с отметкой бюджета");
                CHECK(said("подозрение было ложным"), "budget suspicion: ложное подозрение не названо");
            } else {
                CHECK(sent_first_split_index(82) == 1 && ver_calls == 2,
                      "budget suspicion: после неудачи привязанного плана свои не пошли по порядку");
                CHECK(other_bd && other_bd->budget == (variant == 1 ? D2K_CAT_BUDGET_UNCHECKED
                                                                    : D2K_CAT_BUDGET_PASSED),
                      "budget suspicion: замена своим планом не подтверждена");
                CHECK(!said("подозрение было ложным") && bound_bd->successes == 2,
                      "budget suspicion: без пройденного бюджета привязанный план переподтверждён");
                if (variant == 1) {
                    CHECK(bound_bd->budget == D2K_CAT_BUDGET_CUT,
                          "budget suspicion: у оборванного плана осталась отметка «пройден»");
                    drain(); forget_sent(); d2k_sched_sync(s); sync_out(s);
                    CHECK(sent_first_split_index(82) >= 0 && sent_first_split_index(81) < 0,
                          "budget suspicion: на провод снова идёт оборванный план (ревью I-3)");
                } else {
                    CHECK(said("бюджет не проверен") && bound_bd->budget == D2K_CAT_BUDGET_PASSED,
                          "budget suspicion: «не проверено» не названо или отметка тронута без улики");
                }
            }
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
            ver_budget_n = 0;
        }

        /* (n4b) Обрыв без доказанного применения плана к потоку зонда — не
           улика (ревью I-1): кандидат не отвергается как «оборван», отметка
           его привязки не трогается, итог — «не засчитано». */
        {
            d2k_catalog c = {0};
            char pid[40];
            own_box(&c, "box-unapplied", pid, 65, 3, "unapplied.budget.own", 6, D2K_SHAPE_MODERN, 4,
                    1790000000, 0);
            c.boxes[0].binds[0].budget = D2K_CAT_BUDGET_PASSED;
            tcp_answer = D2K_V_INCONCLUSIVE; ver_answer = D2K_VER_APPLICATION;
            ver_app_after_tcp_search = 0; base_blocked_answer = 1; ver_fail_first = 0;
            ver_budget_n = 1; ver_budget_seq[0] = D2K_BUDGET_CUT;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            spin(s, 5); forget_sent();
            base_calls = tcp_calls = ver_calls = vol_calls = 0;
            ver_answer_port = 42315;
            d2k_ev h = ev_hello(6, 42315, "noapply.budget.own"); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 42315); d2k_sched_event(s, &su);
            for (int i = 0; i < 30 && tcp_calls == 0; i++) { skip_ahead(s, 6000); spin(s, 40); }
            CHECK(ver_calls >= 1 && !said("поток оборван посреди повторов"),
                  "budget unapplied: обрыв без применения плана засчитан против кандидата");
            CHECK(said("не засчитано"), "budget unapplied: «не измерено» не сказано");
            CHECK(c.boxes[0].binds[0].budget == D2K_CAT_BUDGET_PASSED,
                  "budget unapplied: отметка привязки тронута без улики");
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
            ver_budget_n = 0;
        }

        /* (n6) QUIC: то же по новым потокам HTTP/3. abc2b3eb (одна короткая
           приманка) режется на 25 датаграммах — не подтверждён; 389a3920
           (приманки Initial) проходит — подтверждён с отметкой. */
        {
            d2k_catalog c = {0};
            char p_min[40], p_fakes[40];
            own_box(&c, "box-q-min", p_min, 91, 7, "media.qbudget.own", 17, D2K_LINK_SHAPE_QUIC, 4,
                    1790000500, 0);
            own_box(&c, "box-q-fakes", p_fakes, 92, 3, "rutracker.qbudget.own", 17, D2K_LINK_SHAPE_QUIC, 4,
                    1790000000, 0);
            d2k_sched_quic_base_hook = stub_quic_base;
            d2k_sched_quic_seeded_hook = stub_quic_seeded;
            quic_answer = D2K_V_INCONCLUSIVE; base_blocked_answer = 1;
            ver_answer = D2K_VER_APPLICATION; ver_fail_first = 0;
            ver_budget_n = 2; ver_budget_seq[0] = D2K_BUDGET_CUT; ver_budget_seq[1] = D2K_BUDGET_PASSED;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            quic_base_calls = quic_seeded_calls = quic_calls = base_calls = ver_calls = 0;
            ver_answer_port = 42320;
            forget_sent();
            d2k_ev h = ev_hello(17, 42320, "cdn.qbudget.own"); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(17, 42320); d2k_sched_event(s, &su);
            for (int i = 0; i < 60 && !said("ПОДТВЕРЖДЕНО"); i++) {
                spin(s, 100);
                d2k_ev ap = ev_applied(17, 42320); d2k_sched_event(s, &ap);
                spin(s, 5);
            }
            const d2k_cat_binding *bd = binding_of(&c, "cdn.qbudget.own", 17);
            CHECK(ver_calls == 2 && ver_last_transport == 17 && said("посреди повторов"),
                  "budget QUIC: обрыв посреди потоков HTTP/3 не отверг первый план");
            CHECK(bd && !strcmp(bd->plan_id, p_fakes) && bd->budget == D2K_CAT_BUDGET_PASSED,
                  "budget QUIC: подтверждён не прошедший бюджет план");
            CHECK(ver_budget_seen[0] == D2K_BUDGET_FIELD_PACKETS,
                  "budget QUIC: зонд QUIC позван без бюджета");
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
            d2k_sched_quic_base_hook = NULL;
            d2k_sched_quic_seeded_hook = NULL;
            quic_answer = D2K_V_OPAQUE;
            ver_budget_n = 0;
        }

        /* (n7) Бюджет — свойство коробки: у коробки плана записан замер
           обрыва identity (26 пакетов) — зонд зовётся с ним, а не с 25. */
        {
            d2k_catalog c = {0};
            char pid[40];
            own_box(&c, "box-measured", pid, 64, 3, "measured.budget.own", 6, D2K_SHAPE_MODERN, 4,
                    1790000000, 0);
            d2k_cat_signal *rv = &c.boxes[0].fp.sig[c.boxes[0].fp.n_sig++];
            memset(rv, 0, sizeof *rv);
            snprintf(rv->kind, sizeof rv->kind, "rx-volume");
            rv->volume = 20; rv->seen = 1; rv->packets = 26;
            tcp_answer = D2K_V_INCONCLUSIVE; ver_answer = D2K_VER_APPLICATION;
            ver_app_after_tcp_search = 0; base_blocked_answer = 1; ver_fail_first = 0;
            ver_budget_n = 1; ver_budget_seq[0] = D2K_BUDGET_PASSED;
            memset(ver_budget_seen, 0, sizeof ver_budget_seen);
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            spin(s, 5); forget_sent();
            base_calls = tcp_calls = ver_calls = vol_calls = 0;
            ver_answer_port = 42330;
            d2k_ev h = ev_hello(6, 42330, "box.budget.own"); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, 42330); d2k_sched_event(s, &su);
            for (int i = 0; i < 60 && !said("ПОДТВЕРЖДЕНО"); i++) {
                spin(s, 100);
                d2k_ev ap = ev_applied(6, 42330); d2k_sched_event(s, &ap);
                spin(s, 5);
            }
            CHECK(ver_budget_seen[0] == 26 && said("замер коробки box-measured"),
                  "budget box: бюджет зонда не взят из замера коробки");
            if (fails) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
            ver_budget_n = 0;
        }

        /* ---- ПОЛЕ 04.10 12:24, updates.discord.com (TLS 1.2): замер нашёл
           разрез без приманки, он снимает блок рукопожатия, но поток режется
           бюджетом на 10-м запросе. Решение координатора: это ЧАСТИЧНЫЙ
           обход, не провал.
           (p1) Ничего лучше нет — частичный подтверждается с отметкой «оборван»
           (3), «частичный обход» в журнале, ставится на провод.
           (p2) После частичного нашёлся проходящий бюджет — берётся он.
           (p3) Оборванный бюджетом замеренный приём не отправляет цель на
           отдых: дальше идут запасные кандидаты оригинала. */
        for (int variant = 0; variant < 2; variant++) {
            d2k_catalog c = {0};
            tcp_owns_search = 1; tcp_found_arm = 0; tcp_answer = D2K_V_PREFIX;
            ver_answer = D2K_VER_APPLICATION; ver_fail_first = 0;
            ver_app_after_tcp_search = 0; base_blocked_answer = 1;
            ver_budget_n = 2; ver_budget_seq[0] = D2K_BUDGET_CUT;
            ver_budget_seq[1] = D2K_BUDGET_PASSED; ver_budget_status = 404;
            ver_fail_after = variant == 0 ? 1 : 0;
            d2k_sched *s = d2k_sched_new(&c, sv[0], 0x2d);
            saidbuf[0] = '\0';
            d2k_sched_set_say(s, collect_say, NULL);
            spin(s, 5); forget_sent();
            base_calls = tcp_calls = ver_calls = vol_calls = 0;
            uint16_t port = (uint16_t)(42340 + variant);
            ver_answer_port = port;
            const char *name = variant ? "updates2.partial.own" : "updates.partial.own";
            d2k_ev h = ev_hello(6, port, name); d2k_sched_event(s, &h);
            d2k_ev su = ev_suspect(6, port); d2k_sched_event(s, &su);
            for (int i = 0; i < 400 && !said("ПОДТВЕРЖДЕНО") && !said("цель отдыхает"); i++) {
                spin(s, 20);
                d2k_ev ap = ev_applied(6, port); d2k_sched_event(s, &ap);
                spin(s, 2);
            }
            CHECK(ver_calls >= 2 && said("запасного перебора"),
                  "partial: оборванный бюджетом замеренный приём кончил поиск (не пошли запасные)");
            const d2k_cat_binding *bd = binding_of(&c, name, 6);
            if (variant == 0) {
                CHECK(bd && bd->budget == D2K_CAT_BUDGET_CUT && said("частичный обход: рукопожатие снято") &&
                      said("ПОДТВЕРЖДЕНО"),
                      "partial: без лучшего частичный обход не подтверждён с отметкой «оборван»");
                CHECK(!said("цель отдыхает"), "partial: цель ушла в отдых без плана");
                drain(); forget_sent(); d2k_sched_sync(s); sync_out(s);
                CHECK(sent_command_count(D2K_CMD_SET_NAME, NULL, 0) >= 1,
                      "partial: частичный обход не поставлен на провод");
            } else {
                CHECK(bd && bd->budget == D2K_CAT_BUDGET_PASSED && !said("частичный обход: рукопожатие снято"),
                      "partial: частичный выбран вместо прошедшего бюджет");
            }
            if (fails || getenv("T55_SHOW")) fprintf(stderr, "%s\n", saidbuf);
            d2k_sched_free(s); d2k_catalog_free(&c);
            ver_budget_n = 0; ver_budget_status = 200; ver_fail_after = 0;
            tcp_owns_search = 0; tcp_answer = D2K_V_OPAQUE;
        }

        d2k_sched_tcp_base_hook = saved_base;
        d2k_sched_rx_ver_hook = saved_rx;
        d2k_sched_rx_gzip_ver_hook = saved_gzip;
        tcp_answer = D2K_V_OPAQUE; ver_answer = D2K_VER_APPLICATION;
        if (own_first_only) { goto voice_only_done; }
    }

voice_only_done:
    close(sv[0]);
    close(sv[1]);
    d2k_catalog_free(&cat);
    d2k_sched_mark_hook = saved_mark;

    if (fails) { printf("ПРОВАЛОВ: %d\n", fails); return 1; }
    printf(voice_only ? "voice scheduler: all checks passed\n" :
                        "планировщик: все проверки прошли\n");
    return 0;
}
