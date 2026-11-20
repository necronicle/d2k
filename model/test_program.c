#include "d2km_program.h"
#include "test.h"
#include <string.h>

static void base(d2km_program *p)
{
    memset(p, 0, sizeof(*p));
    p->transport = D2KM_TCP;
    p->protocol = D2KM_P_TLS13;
    p->payload_count = 1;
    p->payloads[0].length = 3;
    memcpy(p->payloads[0].bytes, "\x16\x03\x01", 3);
    strcpy(p->payloads[0].why, "фальшивое приветствие по форме клиента, имя из F20 (E52), зерно 42");
    p->fake_count = 1;
    p->fakes[0].payload = 0;
    p->fakes[0].repeats = 1;
    p->fakes[0].poison.ttl = 5;
    strcpy(p->fakes[0].why, "TTL 5: коробка реагирует с хопа 5 (F12, E40), сервер на хопе 11 (F13, E41)");
    p->split_count = 1;
    p->splits[0].anchor = D2KM_AT_SNI_START;
    p->splits[0].offset = 1;
    strcpy(p->splits[0].why, "коробка не собирает сегменты (F21, E53); граница имени — начало SNI");
    p->seed = 42;
}

int main(void)
{
    d2km_program p, q;
    base(&p);
    CHECK(d2km_program_check(&p) == D2KM_PC_OK);
    char text[8192];
    size_t n = d2km_program_text(&p, text, sizeof(text));
    CHECK(n > 0 && n == strlen(text));
    CHECK(strncmp(text, "d2k-plan 1 13\nid ", 17) == 0);
    CHECK(strstr(text, "proto tcp tls\npayload 1 160301\npoison 1 ttl=5\nsplit sni_start 1\n"
                       "fake payload=1 poison=1 repeats=1 gap_us=0 place=before\norder forward\n") != NULL);
    /* Ни подбора TTL исполнителем, ни изменения байтов исполнителем. */
    CHECK(strstr(text, "autottl") == NULL && strstr(text, "tlsmod") == NULL);
    /* Записи «почему» — в журнал, не в план. */
    CHECK(strstr(text, "F12") == NULL);

    /* Каждый элемент — с «почему». */
    q = p; q.payloads[0].why[0] = 0;   CHECK(d2km_program_check(&q) == D2KM_PC_NO_WHY);
    q = p; q.fakes[0].why[0] = 0;      CHECK(d2km_program_check(&q) == D2KM_PC_NO_WHY);
    q = p; q.splits[0].why[0] = 0;     CHECK(d2km_program_check(&q) == D2KM_PC_NO_WHY);
    q = p; q.reverse = 1;              CHECK(d2km_program_check(&q) == D2KM_PC_NO_WHY);
    strcpy(q.order_why, "коробка читает только первый сегмент (F22)");
    CHECK(d2km_program_check(&q) == D2KM_PC_OK);
    CHECK(d2km_program_text(&q, text, sizeof(text)) && strstr(text, "order reverse\n"));
    q = p; q.fakes[0].why[0] = 0;
    CHECK(d2km_program_text(&q, text, sizeof(text)) == 0);   /* без «почему» плана нет */

    /* Фальшивка, которую сервер примет, запрещена. */
    q = p; memset(&q.fakes[0].poison, 0, sizeof(q.fakes[0].poison));
    CHECK(d2km_program_check(&q) == D2KM_PC_SERVER_ACCEPTS);
    q.fakes[0].poison.badsum = 1;      CHECK(d2km_program_check(&q) == D2KM_PC_OK);
    q.transport = D2KM_UDP; q.protocol = D2KM_P_QUIC1;
    CHECK(d2km_program_check(&q) == D2KM_PC_BAD_VALUE);  /* у UDP нет TCP-полей */

    /* Ссылки и значения. */
    q = p; q.fakes[0].payload = 1;     CHECK(d2km_program_check(&q) == D2KM_PC_BAD_PAYLOAD);
    q = p; q.payloads[0].length = 0;   CHECK(d2km_program_check(&q) == D2KM_PC_BAD_PAYLOAD);
    q = p; q.fakes[0].repeats = 0;     CHECK(d2km_program_check(&q) == D2KM_PC_BAD_VALUE);
    q = p; q.split_count = 0; q.fakes[0].between = 1;
    CHECK(d2km_program_check(&q) == D2KM_PC_BAD_VALUE);
    q = p; q.splits[0].anchor = D2KM_ANCHOR_END;
    CHECK(d2km_program_check(&q) == D2KM_PC_BAD_VALUE);
    q = p; q.fake_count = 0; q.split_count = 0;
    CHECK(d2km_program_check(&q) == D2KM_PC_EMPTY);
    q = p; q.protocol = D2KM_P_DNS;    CHECK(d2km_program_check(&q) == D2KM_PC_BAD_PROTOCOL);
    q = p; q.transport = D2KM_UDP;     CHECK(d2km_program_check(&q) == D2KM_PC_BAD_PROTOCOL);

    /* Хэш — от содержания, не от «почему» и не от зерна. */
    uint64_t h = d2km_program_hash(&p);
    CHECK(h != 0);
    q = p; strcpy(q.fakes[0].why, "другие слова"); q.seed = 7;
    CHECK(d2km_program_hash(&q) == h);
    q = p; q.fakes[0].poison.ttl = 6;  CHECK(d2km_program_hash(&q) != h);
    q = p; q.payloads[0].bytes[2] = 3; CHECK(d2km_program_hash(&q) != h);
    q = p; q.fakes[0].why[0] = 0;      CHECK(d2km_program_hash(&q) == 0);

    /* MD5 исполняется только в detect-tcp-v1 wire: TLV parser требует
       явное объявление, одного poison md5 недостаточно. */
    q = p;
    q.fakes[0].poison.ttl = 0;
    q.fakes[0].poison.md5 = 1;
    CHECK(d2km_program_text(&q, text, sizeof(text)) > 0);
    CHECK(strstr(text, "wire detect-tcp-v1\n") != NULL);

    /* Длинная нагрузка и малый буфер. */
    q = p; q.payloads[0].length = D2KM_PROG_PAYLOAD_MAX;
    memset(q.payloads[0].bytes, 0xab, D2KM_PROG_PAYLOAD_MAX);
    n = d2km_program_text(&q, text, sizeof(text));
    CHECK(n > 2 * D2KM_PROG_PAYLOAD_MAX && n < sizeof(text));
    char small[64];
    CHECK(d2km_program_text(&q, small, sizeof(small)) == 0 && small[0] == 0);
    DONE("test_program");
}
