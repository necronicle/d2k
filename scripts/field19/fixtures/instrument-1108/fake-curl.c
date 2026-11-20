/* Socket-free RPC fixture: first response is HTML, second is a portal.
 * No libcurl linkage: implements the narrow ABI consumed by site-fetch.c. */
#define _POSIX_C_SOURCE 200809L
#include <curl/curl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#undef curl_easy_setopt
#undef curl_easy_getinfo
struct fake {
    size_t (*body)(char *, size_t, size_t, void *);
    size_t (*header)(char *, size_t, size_t, void *);
    void *body_arg, *header_arg;
    int requests;
};
CURLcode curl_global_init(long flags) { (void)flags; return CURLE_OK; }
void curl_global_cleanup(void) {}
CURL *curl_easy_init(void) { return (CURL *)calloc(1, sizeof(struct fake)); }
void curl_easy_cleanup(CURL *c) { free(c); }
#ifndef OMIT_IMPERSONATE
CURLcode curl_easy_impersonate(CURL *c, const char *profile, int headers)
{ (void)c; (void)headers; return !strcmp(profile, "chrome150") || !strcmp(profile, "safari260") ? CURLE_OK : CURLE_FAILED_INIT; }
#endif
CURLcode curl_easy_setopt(CURL *c, CURLoption opt, ...)
{
    struct fake *f = (struct fake *)c;
    va_list args;
    va_start(args, opt);
    if (opt == CURLOPT_WRITEFUNCTION) f->body = va_arg(args, size_t (*)(char *, size_t, size_t, void *));
    else if (opt == CURLOPT_HEADERFUNCTION) f->header = va_arg(args, size_t (*)(char *, size_t, size_t, void *));
    else if (opt == CURLOPT_WRITEDATA) f->body_arg = va_arg(args, void *);
    else if (opt == CURLOPT_HEADERDATA) f->header_arg = va_arg(args, void *);
    va_end(args);
    return CURLE_OK;
}
CURLcode curl_easy_perform(CURL *c)
{
    struct fake *f = (struct fake *)c;
    char *body = f->requests ? "" : "<link rel=\"stylesheet\" href=\"/next.css\">";
    char *header = f->requests ? "HTTP/1.1 302 Found\r\nLocation: http://warning.rt.ru/\r\n\r\n" :
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
    f->requests++;
    if (f->header(header, 1, strlen(header), f->header_arg) != strlen(header) ||
        f->body(body, 1, strlen(body), f->body_arg) != strlen(body)) return CURLE_WRITE_ERROR;
    return CURLE_OK;
}
CURLcode curl_easy_getinfo(CURL *c, CURLINFO info, ...)
{
    struct fake *f = (struct fake *)c;
    va_list args;
    va_start(args, info);
    if (info == CURLINFO_PRIMARY_IP) *va_arg(args, char **) = "192.0.2.1";
    else {
        long *value = va_arg(args, long *);
        if (info == CURLINFO_RESPONSE_CODE) *value = f->requests == 1 ? 200 : 302;
        else if (info == CURLINFO_NUM_CONNECTS) *value = f->requests == 1;
        else if (info == CURLINFO_LOCAL_PORT) *value = 1234;
        else if (info == CURLINFO_PRIMARY_PORT) *value = 80;
        else if (info == CURLINFO_HTTP_VERSION) *value = CURL_HTTP_VERSION_1_1;
        else { va_end(args); return CURLE_UNKNOWN_OPTION; }
    }
    va_end(args);
    return CURLE_OK;
}
