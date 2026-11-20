#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include "d2km_store.h"
#include "fixture.h"
#include "test.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

/* Внедрение только на границе ОС; продуктовый API не знает о тестах.
 * Каждый write (включая короткий), fchmod, fsync, close, rename/mkstemp
 * проверяется реальным файлом и каталогом, а не счётчиком вызовов mock. */
static int fail_at = -1, io_step;
static int short_writes;
static int fail(void) { return io_step++ == fail_at; }
static ssize_t fault_write(int fd, const void *p, size_t n)
{
    if (fail()) { errno = ENOSPC; return -1; }
    if (short_writes && n > 3) n = 3;
    return write(fd, p, n);
}
static int fault_mkstemp(char *p) { if (fail()) { errno = EACCES; return -1; } return mkstemp(p); }
static int fault_fchmod(int fd, mode_t m) { if (fail()) { errno = EACCES; return -1; } return fchmod(fd, m); }
static int fault_fsync(int fd) { if (fail()) { errno = EIO; return -1; } return fsync(fd); }
static int fault_close(int fd) { int rc = close(fd); if (fail()) { errno = EIO; return -1; } return rc; }
static int fault_rename(const char *a, const char *b) { if (fail()) { errno = EIO; return -1; } return rename(a, b); }
#define write fault_write
#define mkstemp fault_mkstemp
#define fchmod fault_fchmod
#define fsync fault_fsync
#define close fault_close
#define rename fault_rename
#include "store.c"
#undef write
#undef mkstemp
#undef fchmod
#undef fsync
#undef close
#undef rename

static d2km_store source, loaded, before;
static void fixture(void)
{
    d2km_store_init(&source);
    source.next_experiment = 101;
    source.next_fact = 21;
    source.boxes.count = 1;
    d2km_box *b = &source.boxes.entries[0];
    d2km_box_init(b, 7);
    b->version = 9;
    b->fact_count = 2;
    fixture_context(&b->facts[0].context);
    d2km_fact *f = &b->facts[0];
    f->id = 20; f->kind = D2KM_F_PATH; f->level = D2KM_LEVEL_ESTABLISHED;
    f->numeric = 1; f->model_version = 8;
    f->a = (d2km_arm){.has_action = 1, .action = {.op = D2KM_OP_LIMIT_DELIVERY, .field = 123, .value = 4},
        .has_expected = 1, .expected = {.kind = D2KM_R_RST, .value = -42}};
    f->b = (d2km_arm){.has_action = 1, .action = {.op = D2KM_OP_LIMIT_DELIVERY, .field = 123, .value = 5}};
    f->ra = (d2km_result){.kind = D2KM_R_HELLO_SILENT, .value = -1};
    f->rb = (d2km_result){.kind = D2KM_R_RST, .value = 3};
    f->source_count = 3; f->sources[0] = 41; f->sources[1] = 42; f->sources[2] = 43;
    f->context.form.segment_count = 2; f->context.form.segments[0] = 2; f->context.form.segments[1] = 4;
    f->context.form.tcp_options_length = 3;
    memcpy(f->context.form.tcp_options, "\2\1\3", 3);
    f->context.form.ech = 1; f->context.form.grease = 1;
    b->facts[1] = *f; b->facts[1].id = 19; b->facts[1].numeric = 0;
    b->facts[1].invariant = 1; b->facts[1].rb = f->ra;
    b->hypotheses[D2KM_H_HELLO_NAME] = D2KM_HYP_CONFIRMED;
    b->hypotheses[D2KM_H_HELLO_FIELD] = D2KM_HYP_REFUTED;
    b->hypotheses[D2KM_H_HELLO_FORM] = D2KM_HYP_LIVE;
    b->target_count = 1; b->targets[0] = f->context.target;
    b->counter_count = 1;
    b->counters[0] = (d2km_counterexample){.candidate = 12345, .experiment = 44, .receipt = 987,
        .result = {.kind = D2KM_R_CUT, .value = 65537}, .target = f->context.target, .context = f->context};
    source.knowledge.count = 2;
    d2km_knowledge *k = &source.knowledge.entries[0];
    k->id = 2; k->context = f->context; k->binding = D2KM_BIND_NAME;
    k->experiment = 45; k->model_version = 9; k->box = 7; k->last_success_ms = 1794352345123ULL;
    k->history_count = 2;
    k->history[0] = (d2km_knowledge_history){.time_ms = 1234, .previous_hash = 9, .experiment = 39, .outcome = D2KM_DEGRADED};
    k->history[1] = (d2km_knowledge_history){.time_ms = 2345, .previous_hash = 10, .experiment = 40, .outcome = D2KM_APPLIED};
    strcpy(k->why, "{\"id\":\"W17\",\"reason\":\"почему: ёж 🦔\\n\",\"links\":[\"W16\"]}\n");
    d2km_program *p = &k->program;
    p->transport = D2KM_TCP; p->protocol = D2KM_P_TLS13; p->seed = UINT64_MAX;
    p->payload_count = 2;
    p->payloads[0].length = D2KM_PROG_PAYLOAD_MAX;
    for (size_t i = 0; i < D2KM_PROG_PAYLOAD_MAX; i++) p->payloads[0].bytes[i] = (uint8_t)i;
    strcpy(p->payloads[0].why, "нагрузка: все байты 00..ff, F20, E41\nвторая строка");
    p->payloads[1].length = 3; memcpy(p->payloads[1].bytes, "\0\xff\1", 3);
    strcpy(p->payloads[1].why, "второе сообщение");
    p->fake_count = 2;
    p->fakes[0] = (d2km_fake){.payload = 1, .poison = {.ttl = 5, .badsum = 1, .md5 = 1, .tcpts = 1, .seqshift = INT32_MIN},
        .repeats = 255, .gap_us = UINT32_MAX, .between = 1};
    strcpy(p->fakes[0].why, "порча и порядок: F20");
    p->fakes[1] = (d2km_fake){.payload = 0, .poison = {.seqshift = INT32_MAX}, .repeats = 1};
    strcpy(p->fakes[1].why, "порча: E42");
    p->split_count = 2;
    p->splits[0] = (d2km_split){.anchor = D2KM_AT_SNI_START, .offset = INT16_MIN};
    p->splits[1] = (d2km_split){.anchor = D2KM_AT_RECORD_END, .offset = INT16_MAX};
    strcpy(p->splits[0].why, "разрез первый"); strcpy(p->splits[1].why, "разрез второй");
    p->reverse = 1; strcpy(p->order_why, "обратный порядок — F19");
    k->hash = d2km_program_hash(p);
    source.knowledge.entries[1] = *k;
    k = &source.knowledge.entries[1]; k->id = 3; k->binding = D2KM_BIND_ADDRESS;
    uint8_t ip[16] = {0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9};
    CHECK(d2km_target_address(&k->context.target, D2KM_IPV6, ip, 443) == 0);
    k->context.family = D2KM_IPV6; k->context.protocol = D2KM_P_TLS12;
    k->program.protocol = D2KM_P_TLS12; k->hash = d2km_program_hash(&k->program);
}

static int file_count(const char *path)
{
    DIR *d = opendir(path); int n = 0;
    struct dirent *e;
    while (d && (e = readdir(d))) if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) n++;
    if (d) closedir(d);
    return n;
}
static void put_file(const char *path, const char *data)
{
    FILE *f = fopen(path, "w"); CHECK(f != NULL);
    if (f) { CHECK(fputs(data, f) >= 0); CHECK(fclose(f) == 0); }
}
static void refused(const char *path, d2km_store_code want)
{
    d2km_store_error err = {0};
    loaded = before;
    CHECK(d2km_store_load(path, &loaded, &err) == want);
    CHECK(err.reason[0]);
    CHECK(memcmp(&loaded, &before, sizeof loaded) == 0);
}
int main(void)
{
    char dir[] = "/tmp/d2km-store-XXXXXX", path[128];
    CHECK(mkdtemp(dir) != NULL); snprintf(path, sizeof path, "%s/store", dir);
    fixture(); before = source;
    d2km_store_error err = {0};
    CHECK(d2km_store_save(path, &source, &err) == D2KM_STORE_OK);
    CHECK(d2km_store_load(path, &loaded, &err) == D2KM_STORE_OK);
    /* Все активные поля заданы, неиспользуемые байты и padding обнулены. */
    CHECK(memcmp(&source, &loaded, sizeof source) == 0);
    struct stat st; CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);
    put_file(path, "d2km-store 99\n"); refused(path, D2KM_STORE_VERSION);
    put_file(path, "d2km-store 1\nmeta 1 1 0 0\nbroken in middle\n"); refused(path, D2KM_STORE_INVALID);
    CHECK(d2km_store_save(path, &source, &err) == D2KM_STORE_OK);
    /* Отказ каждого шага: прежний файл остаётся пригодным, tmp нет. */
    io_step = 0; fail_at = -1;
    CHECK(d2km_store_save(path, &source, &err) == D2KM_STORE_OK);
    int steps = io_step;
    source.next_experiment++;
    for (int i = 0; i < steps; i++) {
        io_step = 0; fail_at = i;
        CHECK(d2km_store_save(path, &source, &err) == D2KM_STORE_IO);
        CHECK(err.reason[0]); fail_at = -1;
        CHECK(file_count(dir) == 1);
        CHECK(d2km_store_load(path, &loaded, &err) == D2KM_STORE_OK);
        CHECK(memcmp(&loaded, &before, sizeof loaded) == 0);
    }
    short_writes = 1;
    fail_at = 2; io_step = 0;
    CHECK(d2km_store_save(path, &source, &err) == D2KM_STORE_IO);
    CHECK(file_count(dir) == 1);
    fail_at = -1;
    CHECK(d2km_store_load(path, &loaded, &err) == D2KM_STORE_OK);
    CHECK(memcmp(&loaded, &before, sizeof loaded) == 0);
    CHECK(d2km_store_save(path, &source, &err) == D2KM_STORE_OK);
    short_writes = 0;
    CHECK(d2km_store_load(path, &loaded, &err) == D2KM_STORE_OK);
    CHECK(loaded.next_experiment == 102); /* повторная запись действительно заменила файл */
    source.boxes.count = D2KM_STORE_BOXES_MAX + 1;
    CHECK(d2km_store_save(path, &source, &err) == D2KM_STORE_NO_RESOURCES);
    source = before; source.knowledge.count = D2KM_STORE_KNOWLEDGE_MAX + 1;
    CHECK(d2km_store_save(path, &source, &err) == D2KM_STORE_NO_RESOURCES);
    source = before; source.boxes.entries[0].fact_count = D2KM_BOX_FACTS_MAX + 1;
    CHECK(d2km_store_save(path, &source, &err) == D2KM_STORE_NO_RESOURCES);
    CHECK(file_count(dir) == 1);
    /* Пределы памяти проверяются до доступа к массивам при записи. */
    source = before; source.boxes.entries[0].facts[0].source_count = D2KM_FACT_SOURCES_MAX + 1;
    CHECK(d2km_store_save(path, &source, &err) == D2KM_STORE_NO_RESOURCES);
    source = before; source.boxes.entries[0].counter_count = D2KM_BOX_COUNTER_MAX + 1;
    CHECK(d2km_store_save(path, &source, &err) == D2KM_STORE_NO_RESOURCES);
    source = before; source.knowledge.entries[0].history_count = D2KM_KNOWLEDGE_HISTORY_MAX + 1;
    CHECK(d2km_store_save(path, &source, &err) == D2KM_STORE_NO_RESOURCES);
    /* Повреждаем настоящий файл после первой коробки: назначение не меняется
       даже после того, как парсер успешно прочитал несколько объектов. */
    source = before;
    CHECK(d2km_store_save(path, &source, &err) == D2KM_STORE_OK);
    FILE *file = fopen(path, "r+"); CHECK(file != NULL);
    if (file) {
        char line[STORE_LINE_MAX]; long offset = 0;
        while (fgets(line, sizeof line, file)) {
            if (!strncmp(line, "knowledge ", 10)) {
                CHECK(fseek(file, offset, SEEK_SET) == 0);
                CHECK(fputc('X', file) != EOF); break;
            }
            offset = ftell(file);
        }
        CHECK(fclose(file) == 0);
    }
    refused(path, D2KM_STORE_INVALID);
    CHECK(d2km_store_save(path, &source, &err) == D2KM_STORE_OK);
    CHECK(stat(path, &st) == 0);
    CHECK(truncate(path, st.st_size - 3) == 0);
    refused(path, D2KM_STORE_INVALID);
    CHECK(d2km_store_save(path, &source, &err) == D2KM_STORE_OK);
    file = fopen(path, "a"); CHECK(file != NULL);
    if (file) { fputs("extra\n", file); fclose(file); }
    refused(path, D2KM_STORE_INVALID);
    put_file(path, "d2km-store 1\nmeta 1 1 999 0\n");
    refused(path, D2KM_STORE_NO_RESOURCES);
    CHECK(d2km_store_load("/this/path/does/not/exist", &loaded, &err) == D2KM_STORE_IO);
    unlink(path); rmdir(dir);
    DONE("test_store");
}
