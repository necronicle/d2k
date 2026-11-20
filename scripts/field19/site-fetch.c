/* Diagnostic persistent libcurl-impersonate worker. No shell execution.
 * Build: cc -std=c99 -O2 -Wall -Wextra -Werror site-fetch.c -o site-fetch [-ldl]
 * Run: site-fetch /absolute/libcurl-impersonate.so chrome150|safari260 CA_FILE
 * stdin: absolute URL line, then Referer line (empty for navigation). stdout: JSON line, headers, decoded body
 * (lengths in JSON); one easy handle/cookie jar/connection cache for the visit.
 * Library MUST export curl_easy_impersonate; stock curl is refused.
 * curl headers are build-only; shared library is opened explicitly at runtime.
 */
#define _POSIX_C_SOURCE 200809L
#include <curl/curl.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct buffer { char *data; size_t size; };
static size_t append(char *ptr, size_t size, size_t count, void *arg)
{
    struct buffer *b = arg;
    size_t n;
    char *p;
    if (size && count > SIZE_MAX / size) return 0;
    n = size * count;
    if (b->size > SIZE_MAX - n - 1) return 0;
    p = realloc(b->data, b->size + n + 1);
    if (!p) return 0;
    b->data = p;
    memcpy(p + b->size, ptr, n);
    b->size += n;
    p[b->size] = 0;
    return n;
}
#define LOAD(var, symbol) do { *(void **)(&var) = dlsym(lib, symbol); \
    if (!var) { fprintf(stderr, "missing %s\n", symbol); return 2; } } while (0)
#define SET(option, value) do { if (setopt(easy, option, value) != CURLE_OK) { \
    fprintf(stderr, "unsupported %s\n", #option); return 2; } } while (0)
int main(int argc, char **argv)
{
    void *lib;
    CURL *easy;
    CURL *(*init)(void);
    CURLcode (*global_init)(long), (*setopt)(CURL *, CURLoption, ...);
    CURLcode (*perform)(CURL *), (*getinfo)(CURL *, CURLINFO, ...);
    CURLcode (*impersonate)(CURL *, const char *, int);
    void (*cleanup)(CURL *), (*global_cleanup)(void);
    char *line = NULL;
    size_t cap = 0;
    struct buffer body = {NULL, 0}, headers = {NULL, 0};
    if (argc == 2 && !strcmp(argv[1], "--version")) {
        puts("field19-site-fetch 1"); return 0;
    }
    if (argc != 4 || argv[1][0] != '/' ||
        (strcmp(argv[2], "chrome150") && strcmp(argv[2], "safari260") && strcmp(argv[2], "chrome150-h3"))) return 2;
    lib = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!lib) { fprintf(stderr, "libcurl-impersonate: %s\n", dlerror()); return 2; }
    LOAD(global_init, "curl_global_init"); LOAD(init, "curl_easy_init");
    LOAD(setopt, "curl_easy_setopt"); LOAD(perform, "curl_easy_perform");
    LOAD(getinfo, "curl_easy_getinfo"); LOAD(cleanup, "curl_easy_cleanup");
    LOAD(global_cleanup, "curl_global_cleanup");
    LOAD(impersonate, "curl_easy_impersonate");
    if (global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK || !(easy = init())) return 2;
    if (impersonate(easy, !strcmp(argv[2], "chrome150-h3") ? "chrome150" : argv[2], 1) != CURLE_OK) return 2;
    SET(CURLOPT_CAINFO, argv[3]);
    SET(CURLOPT_IPRESOLVE, (long)CURL_IPRESOLVE_V4);
    SET(CURLOPT_DOH_URL, "https://1.1.1.1/dns-query");
    SET(CURLOPT_ACCEPT_ENCODING, ""); SET(CURLOPT_COOKIEFILE, "");
    /* Serialize requests on one connection per origin. Never claim reuse merely
     * from reusing an easy handle: host checks NUM_CONNECTS and endpoints. */
    SET(CURLOPT_HTTP_VERSION, !strcmp(argv[2], "chrome150-h3") ? 31L : (long)CURL_HTTP_VERSION_2TLS);
    SET(CURLOPT_PROXY, ""); SET(CURLOPT_TIMEOUT, 20L);
    SET(CURLOPT_FOLLOWLOCATION, 0L);
    SET(CURLOPT_WRITEFUNCTION, append); SET(CURLOPT_WRITEDATA, &body);
    SET(CURLOPT_HEADERFUNCTION, append); SET(CURLOPT_HEADERDATA, &headers);
    if (!strncmp(argv[2], "chrome150", 9)) SET((CURLoption)10325, "true"); /* CURLOPT_ECH */
    puts("{\"ready\":1,\"schema\":1}"); fflush(stdout);
    while (getline(&line, &cap, stdin) >= 0) {
        long code = 0, connects = 0, port = 0, remote_port = 0, version = 0;
        char *ip = NULL;
        CURLcode rc;
        line[strcspn(line, "\r\n")] = 0;
        if (strncmp(line, "http://", 7) && strncmp(line, "https://", 8)) return 2;
        body.size = headers.size = 0;
        SET(CURLOPT_URL, line);
        if (getline(&line, &cap, stdin) < 0) return 2;
        line[strcspn(line, "\r\n")] = 0;
        if (*line && strncmp(line, "http://", 7) && strncmp(line, "https://", 8)) return 2;
        SET(CURLOPT_REFERER, *line ? line : NULL);
        rc = perform(easy);
        if (getinfo(easy, CURLINFO_RESPONSE_CODE, &code) ||
            getinfo(easy, CURLINFO_NUM_CONNECTS, &connects) ||
            getinfo(easy, CURLINFO_LOCAL_PORT, &port) ||
            getinfo(easy, CURLINFO_PRIMARY_PORT, &remote_port) ||
            getinfo(easy, CURLINFO_HTTP_VERSION, &version) ||
            getinfo(easy, CURLINFO_PRIMARY_IP, &ip)) return 2;
        /* IPv4 address is supplied by libcurl (IPRESOLVE_V4), safe JSON text. */
        printf("{\"rc\":%d,\"code\":%ld,\"size\":%zu,\"header_size\":%zu,"
               "\"connects\":%ld,\"local_port\":%ld,\"remote_port\":%ld,\"http_version\":%ld,\"ip\":\"%s\"}\n",
               (int)rc, code, body.size, headers.size, connects, port, remote_port, version, ip ? ip : "");
        if (headers.size) fwrite(headers.data, 1, headers.size, stdout);
        if (body.size) fwrite(body.data, 1, body.size, stdout);
        if (fflush(stdout)) return 2;
    }
    free(line); free(body.data); free(headers.data);
    cleanup(easy); global_cleanup(); dlclose(lib);
    return ferror(stdin) ? 2 : 0;
}
