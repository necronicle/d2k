#define _DARWIN_C_SOURCE
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Count allocations by the HTTP implementation itself. The fixture and the
   output file use libc normally, even when simulating a small router heap. */
static size_t requested, budget;

static void *budget_malloc(size_t size) {
    requested += size;
    return requested <= budget ? malloc(size) : NULL;
}

#define malloc budget_malloc
#include "server.c"
#undef malloc

int main(int argc, char **argv) {
    assert(argc == 2);
    int status = strcmp(argv[1], "status") == 0;
    char dir[] = "/tmp/d2k-panel-memory-XXXXXX", path[256];
    assert(mkdtemp(dir));
    snprintf(path, sizeof path, "%s/file", dir);
    FILE *file = fopen(path, "wb");
    assert(file);
    const char *prefix = "{\"linked\":true,\"blob\":\"";
    const char *suffix = "\"}";
    size_t filler = BODY_MAX - strlen(prefix) - strlen(suffix);
    assert(fputs(prefix, file) >= 0);
    for (size_t i = 0; i < filler; i++) assert(fputc('a' + i % 26, file) != EOF);
    assert(fputs(suffix, file) >= 0 && fclose(file) == 0);

    d2k_panel_config cfg = { .asset_dir = dir, .live_path = path };
    FILE *out = tmpfile();
    assert(out);
    budget = (status ? BODY_MAX : 0) + 16384;
    int rc = status ? api_status(fileno(out), &cfg, NULL) :
                      static_file(fileno(out), &cfg, NULL, "file", "text/plain");
    fprintf(stderr, "%s: %zu bytes requested for a %u-byte file\n", argv[1], requested, BODY_MAX);
    assert(rc == 0 && requested <= budget);
    rewind(out);
    char line[1024];
    size_t content_length = 0;
    assert(fgets(line, sizeof line, out) && strstr(line, "200 OK"));
    while (fgets(line, sizeof line, out) && strcmp(line, "\r\n") != 0) {
        (void)sscanf(line, "Content-Length: %zu", &content_length);
    }
    char *body = malloc(content_length + 1);
    assert(body && fread(body, 1, content_length, out) == content_length && fgetc(out) == EOF);
    body[content_length] = 0;
    const char *payload = body;
    size_t payload_len = content_length;
    if (status) {
        assert(json_valid_object(body, body + content_length));
        assert(json_top_value(body, "knowledge", &payload, &payload_len));
    }
    assert(payload_len == BODY_MAX && !memcmp(payload, prefix, strlen(prefix)));
    for (size_t i = 0; i < filler; i++) assert(payload[strlen(prefix) + i] == (char)('a' + i % 26));
    assert(!memcmp(payload + payload_len - strlen(suffix), suffix, strlen(suffix)));
    free(body);
    fclose(out);
    assert(unlink(path) == 0 && rmdir(dir) == 0);
    return 0;
}
