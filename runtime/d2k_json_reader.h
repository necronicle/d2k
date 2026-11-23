#ifndef D2K_JSON_READER_H
#define D2K_JSON_READER_H
#include <string.h>

typedef struct { const char *p, *end; unsigned depth; } json_reader;

static void json_ws(json_reader *r) {
    while (r->p < r->end && (*r->p == ' ' || *r->p == '\t' ||
                              *r->p == '\r' || *r->p == '\n')) { r->p++; }
}

static int json_string(json_reader *r) {
    if (r->p >= r->end || *r->p++ != '"') { return -1; }
    while (r->p < r->end) {
        unsigned char c = (unsigned char)*r->p++;
        if (c == '"') { return 0; }
        if (c < 0x20) { return -1; }
        if (c != '\\') { continue; }
        if (r->p >= r->end) { return -1; }
        c = (unsigned char)*r->p++;
        if (c == '"' || c == '\\' || c == '/' || c == 'b' || c == 'f' ||
            c == 'n' || c == 'r' || c == 't') { continue; }
        if (c != 'u' || r->end - r->p < 4) { return -1; }
        for (int i = 0; i < 4; i++) {
            unsigned char h = (unsigned char)*r->p++;
            if (!((h >= '0' && h <= '9') || (h >= 'a' && h <= 'f') ||
                  (h >= 'A' && h <= 'F'))) { return -1; }
        }
    }
    return -1;
}

static int json_value(json_reader *r);

static int json_compound(json_reader *r, char open, char close, int object) {
    if (++r->depth > 64 || r->p >= r->end || *r->p++ != open) {
        r->depth--;
        return -1;
    }
    json_ws(r);
    if (r->p < r->end && *r->p == close) { r->p++; r->depth--; return 0; }
    for (;;) {
        if (object) {
            if (json_string(r) != 0) { r->depth--; return -1; }
            json_ws(r);
            if (r->p >= r->end || *r->p++ != ':') { r->depth--; return -1; }
            json_ws(r);
        }
        if (json_value(r) != 0) { r->depth--; return -1; }
        json_ws(r);
        if (r->p >= r->end) { r->depth--; return -1; }
        char c = *r->p++;
        if (c == close) { r->depth--; return 0; }
        if (c != ',') { r->depth--; return -1; }
        json_ws(r);
    }
}

static int json_number(json_reader *r) {
    const char *p = r->p;
    if (p < r->end && *p == '-') { p++; }
    if (p >= r->end) { return -1; }
    if (*p == '0') { p++; }
    else {
        if (*p < '1' || *p > '9') { return -1; }
        do { p++; } while (p < r->end && *p >= '0' && *p <= '9');
    }
    if (p < r->end && *p == '.') {
        p++;
        if (p >= r->end || *p < '0' || *p > '9') { return -1; }
        do { p++; } while (p < r->end && *p >= '0' && *p <= '9');
    }
    if (p < r->end && (*p == 'e' || *p == 'E')) {
        p++;
        if (p < r->end && (*p == '+' || *p == '-')) { p++; }
        if (p >= r->end || *p < '0' || *p > '9') { return -1; }
        do { p++; } while (p < r->end && *p >= '0' && *p <= '9');
    }
    r->p = p;
    return 0;
}

static int json_value(json_reader *r) {
    json_ws(r);
    if (r->p >= r->end) { return -1; }
    switch (*r->p) {
    case '"': return json_string(r);
    case '{': return json_compound(r, '{', '}', 1);
    case '[': return json_compound(r, '[', ']', 0);
    case 't': if (r->end - r->p >= 4 && memcmp(r->p, "true", 4) == 0) { r->p += 4; return 0; } return -1;
    case 'f': if (r->end - r->p >= 5 && memcmp(r->p, "false", 5) == 0) { r->p += 5; return 0; } return -1;
    case 'n': if (r->end - r->p >= 4 && memcmp(r->p, "null", 4) == 0) { r->p += 4; return 0; } return -1;
    default: return json_number(r);
    }
}

static int json_valid_object(const char *p, const char *end) {
    json_reader r = { .p = p, .end = end, .depth = 0 };
    json_ws(&r);
    if (r.p >= r.end || *r.p != '{' || json_value(&r) != 0) { return 0; }
    json_ws(&r);
    return r.p == r.end;
}

static inline int json_member(json_reader r, const char *wanted,
                              const char **value, size_t *value_len) {
    json_ws(&r);
    if (r.p >= r.end || *r.p++ != '{') { return 0; }
    json_ws(&r);
    while (r.p < r.end && *r.p != '}') {
        const char *key_start = r.p;
        if (json_string(&r) != 0) { return 0; }
        size_t key_len = (size_t)(r.p - key_start);
        json_ws(&r);
        if (r.p >= r.end || *r.p++ != ':') { return 0; }
        json_ws(&r);
        const char *value_start = r.p;
        int match = strlen(wanted) + 2 == key_len && key_start[0] == '"' &&
                    key_start[key_len - 1] == '"' &&
                    memcmp(key_start + 1, wanted, strlen(wanted)) == 0;
        if (json_value(&r) != 0) { return 0; }
        if (match) {
            *value = value_start;
            *value_len = (size_t)(r.p - value_start);
            return 1;
        }
        json_ws(&r);
        if (r.p >= r.end || *r.p == '}') { break; }
        if (*r.p++ != ',') { return 0; }
        json_ws(&r);
    }
    return 0;
}

static inline int json_top_value(const char *json, const char *wanted,
                                 const char **value, size_t *value_len) {
    json_reader r = { .p = json, .end = json + strlen(json) };
    return json_member(r, wanted, value, value_len);
}
#endif
