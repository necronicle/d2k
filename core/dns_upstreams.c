#include "d2k_dns_upstreams.h"
#include "d2k_domain.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static int copy(char *out, size_t capacity, const char *p, size_t n) {
    if (n >= capacity) return -1;
    memcpy(out, p, n); out[n] = 0;
    return 0;
}
static int numeric(const char *in, char out[64]) {
    unsigned char bytes[16];
    int family = strchr(in, ':') ? AF_INET6 : AF_INET;
    return inet_pton(family, in, bytes) == 1 && inet_ntop(family, bytes, out, 64) ? 0 : -1;
}
static int host(const char *in, char out[254], char address[64]) {
    char norm[256];
    if (!numeric(in, address)) return copy(out, 254, address, strlen(address));
    address[0] = 0;
    if (d2k_domain_normalize(in, norm)) return -1;
    return copy(out, 254, norm, strlen(norm));
}
static int port(const char *text, uint16_t *out) {
    unsigned value = 0;
    if (!*text) return -1;
    for (; *text; text++) {
        if (*text < '0' || *text > '9') return -1;
        value = value * 10 + (unsigned)(*text - '0');
        if (value > UINT16_MAX) return -1;
    }
    if (!value) return -1;
    *out = (uint16_t)value;
    return 0;
}
int d2k_dns_http_authority(const char *identity,uint16_t number,char *out,size_t capacity) {
    char normalized[254],address[64],value[262];
    if(!identity || !out || !number || host(identity,normalized,address) || strcmp(identity,normalized))
        return D2K_DNS_PARSE_INVALID;
    int v6=strchr(normalized,':')!=NULL;
    int n=number==443?snprintf(value,sizeof value,"%s%s%s",v6?"[":"",normalized,v6?"]":""):
        snprintf(value,sizeof value,"%s%s%s:%u",v6?"[":"",normalized,v6?"]":"",(unsigned)number);
    if(n<0 || (size_t)n>=sizeof value || (size_t)n>=capacity)return D2K_DNS_PARSE_LIMIT;
    memcpy(out,value,(size_t)n+1);return D2K_DNS_PARSE_OK;
}
static int authority(char *text, d2k_dns_endpoint *e) {
    char *end = NULL, *port_text = NULL;
    if (*text == '[') {
        end = strchr(++text, ']');
        if (!end || (end[1] && end[1] != ':')) return -1;
        if (end[1]) port_text = end + 2;
        *end = 0;
        if (!strchr(text, ':')) return -1;
    } else {
        char *colon = strchr(text, ':');
        if (colon && !strchr(colon + 1, ':')) {
            *colon = 0; port_text = colon + 1;
        }
    }
    if (port_text && port(port_text, &e->port)) return -1;
    return host(text, e->host, e->address);
}
int d2k_dns_endpoint_parse(const char *input, enum d2k_dns_transport hint,
                          d2k_dns_endpoint *out) {
    if (!input || !out || hint < D2K_DNS_PLAIN || hint > D2K_DNS_QUIC)
        return D2K_DNS_PARSE_INVALID;
    size_t n = strlen(input);
    char value[1408]; /* Host+port+opaque path fit the public field capacities. */
    if (!n || copy(value, sizeof value, input, n)) return D2K_DNS_PARSE_INVALID;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)value[i] <= 32 || (unsigned char)value[i] >= 127 || value[i] == '#')
            return D2K_DNS_PARSE_INVALID;
    d2k_dns_endpoint e = {0}; e.transport = hint;
    char *p = value;
    if (!strncmp(p, "https://", 8)) {e.transport = D2K_DNS_HTTPS; p += 8;}
    else if (!strncmp(p, "tls://", 6)) {e.transport = D2K_DNS_TLS; p += 6;}
    else if (!strncmp(p, "quic://", 7)) {e.transport = D2K_DNS_QUIC; p += 7;}
    else if (!strncmp(p, "udp://", 6) || !strncmp(p, "tcp://", 6)) {
        e.transport = p[0] == 't' ? D2K_DNS_TCP : D2K_DNS_PLAIN; p += 6;
    } else if (strstr(p, "://")) return D2K_DNS_PARSE_INVALID;
    /* RFC9250 section4.1.1: dedicated DNS-over-QUIC port853. */
    e.port = e.transport == D2K_DNS_HTTPS ? 443 :
        (e.transport == D2K_DNS_TLS || e.transport == D2K_DNS_QUIC) ? 853 : 53;
    if (e.transport == D2K_DNS_HTTPS) {
        char *path = strpbrk(p, "/?");
        if (path) {
            if (*path == '?') {
                e.path[0] = '/';
                if (copy(e.path + 1, sizeof e.path - 1, path, strlen(path)))
                    return D2K_DNS_PARSE_INVALID;
            } else if (copy(e.path, sizeof e.path, path, strlen(path)))
                return D2K_DNS_PARSE_INVALID;
            *path = 0;
        } else strcpy(e.path, "/");
        if (strchr(p, '@')) return D2K_DNS_PARSE_INVALID; /* No URL userinfo. */
    } else {
        if (strpbrk(p, "/?")) return D2K_DNS_PARSE_INVALID;
        char *identity = strchr(p, '@');
        if (identity) {
            if (e.transport != D2K_DNS_TLS || strchr(identity + 1, '@'))
                return D2K_DNS_PARSE_INVALID;
            *identity++ = 0;
            if (authority(p, &e) || !e.address[0]) return D2K_DNS_PARSE_INVALID;
            char bootstrap[64]; strcpy(bootstrap, e.address);
            if (host(identity, e.host, e.address)) return D2K_DNS_PARSE_INVALID;
            strcpy(e.address, bootstrap);
            *out = e; return D2K_DNS_PARSE_OK;
        }
    }
    if (authority(p, &e)) return D2K_DNS_PARSE_INVALID;
    *out = e;
    return D2K_DNS_PARSE_OK;
}
int d2k_dns_endpoint_equal(const d2k_dns_endpoint *a, const d2k_dns_endpoint *b) {
    return a && b && a->transport == b->transport && a->port == b->port &&
        !strcmp(a->host, b->host) && !strcmp(a->path, b->path) && !strcmp(a->address, b->address);
}
static char *trim(char *text) {
    while (*text == ' ' || *text == '\t' || *text == '\r') text++;
    size_t n = strlen(text);
    while (n && (text[n-1] == ' ' || text[n-1] == '\t' || text[n-1] == '\r')) text[--n] = 0;
    return text;
}
static int local(const d2k_dns_endpoint *e) {
    unsigned char a[16];
    if (inet_pton(AF_INET, e->host, a) == 1) return a[0] == 127 || !memcmp(a, "\0\0\0\0", 4);
    if (inet_pton(AF_INET6, e->host, a) == 1) {
        static const unsigned char loop[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        static const unsigned char zero[16] = {0};
        return !memcmp(a, loop, 16) || !memcmp(a, zero, 16);
    }
    return !strcmp(e->host, "localhost");
}
static char *word(char **remaining) {
    char *p = trim(*remaining), *end = p;
    if (!*p) return NULL;
    while (*end && *end != ' ' && *end != '\t' && *end != '\r') end++;
    if (*end) *end++ = 0;
    *remaining = end;
    return p;
}
static int owner_line(char *line, d2k_dns_endpoint *out) {
    char *comment = strchr(line, '#'); if (comment) *comment = 0;
    char *cursor = line, *h = word(&cursor), *p = word(&cursor);
    char *path = word(&cursor), *address = word(&cursor);
    if (!h) return 0;
    if (!p || !path || !address || word(&cursor)) return -1;
    d2k_dns_endpoint e = {0}; e.transport = D2K_DNS_HTTPS;
    if (host(h, e.host, e.address) || port(p, &e.port) || path[0] != '/' ||
        strchr(path, '#') || copy(e.path, sizeof e.path, path, strlen(path)) ||
        numeric(address, e.address)) return -1;
    *out = e; return 1;
}
static int proxy_line(char *line, d2k_dns_endpoint *out) {
    char *text = trim(line), *value;
    int server = 0;
    if (!strncmp(text, "upstream", 8) &&
        (!text[8] || text[8] == ' ' || text[8] == '\t')) {
        value = trim(text + 8);
        char *comment = strchr(value, '#');
        if (comment && comment != value && comment[-1] != ' ' && comment[-1] != '\t') return -1;
        if (comment) *comment = 0;
        if (d2k_dns_endpoint_parse(trim(value), D2K_DNS_PLAIN, out) != D2K_DNS_PARSE_OK)
            return -1;
        return local(out) ? 0 : 1;
    }
    if (!strncmp(text, "dns_server", 10) && (text[10] == ' ' || text[10] == '=')) {
        server = 1; value = text + 10;
    } else if (!strncmp(text, "uri", 3) && (text[3] == ' ' || text[3] == ':' || text[3] == '=')) {
        value = text + 3;
    } else return 0;
    value = trim(value);
    if (*value != '=' && *value != ':') return -1;
    value = trim(value + 1);
    enum d2k_dns_transport hint = D2K_DNS_HTTPS;
    if (server) {
        char *comment = strchr(value, '#');
        if (comment && *trim(comment + 1)) {
            value = trim(comment + 1);
            size_t n = strlen(value);
            if (n >= 5 && !strcmp(value + n - 5, "@dnsm")) value[n - 5] = 0;
            hint = !strncmp(value, "https://", 8) ? D2K_DNS_HTTPS : D2K_DNS_TLS;
        } else {
            if (comment) *comment = 0;
            char *cursor = value; value = word(&cursor);
            if (!value) return -1;
            hint = D2K_DNS_PLAIN;
        }
    }
    if (d2k_dns_endpoint_parse(trim(value), hint, out) != D2K_DNS_PARSE_OK) return -1;
    return local(out) ? 0 : 1;
}
static int bootstrap_line(char *line, d2k_dns_endpoint *out) {
    char *text = trim(line);
    if (strncmp(text, "bootstrap", 9) ||
        (text[9] && text[9] != ' ' && text[9] != '\t')) return 0;
    char *value = trim(text + 9), *comment = strchr(value, '#');
    if (comment && comment != value && comment[-1] != ' ' && comment[-1] != '\t') return -1;
    if (comment) *comment = 0;
    if (d2k_dns_endpoint_parse(trim(value), D2K_DNS_PLAIN, out) != D2K_DNS_PARSE_OK ||
        !out->address[0] || out->transport != D2K_DNS_PLAIN || local(out)) return -1;
    return 1;
}
static int key_line(const char *p, size_t n) {
    size_t i = 0;
    while (i < n && ((p[i] >= 'a' && p[i] <= 'z') ||
        (p[i] >= 'A' && p[i] <= 'Z') || (p[i] >= '0' && p[i] <= '9') ||
        p[i] == '_' || p[i] == '-')) i++;
    if (!i) return 0;
    while (i < n && (p[i] == ' ' || p[i] == '\t')) i++;
    return i < n && (p[i] == ':' || p[i] == '=');
}
/* Keenetic's CLI folds a long uri at its value column. Rejoin that declared
 * continuation only; a following configuration key must never become URL data. */
static int uri_continuations(const char *text, size_t length, size_t *at,
                              char *line, size_t capacity) {
    char *key = trim(line);
    if (strncmp(key, "uri", 3) || (key[3] != ' ' && key[3] != ':' && key[3] != '=')) return 0;
    char *value = trim(key + 3);
    if (*value != ':' && *value != '=') return 0;
    value = trim(value + 1);
    size_t column = (size_t)(value - line), used = strlen(line);
    while (*at < length) {
        const char *p = text + *at;
        const char *newline = memchr(p, '\n', length - *at);
        size_t n = newline ? (size_t)(newline - p) : length - *at;
        size_t indent = 0;
        while (indent < n && p[indent] == ' ') indent++;
        if (indent != column || indent == n || key_line(p + indent, n - indent)) break;
        size_t tail = n - indent;
        while (tail && (p[indent + tail - 1] == '\r' || p[indent + tail - 1] == ' ')) tail--;
        if (tail >= capacity - used) return -1;
        memcpy(line + used, p + indent, tail);
        used += tail; line[used] = 0;
        *at += n + !!newline;
    }
    return 0;
}
static int parse(const char *text, size_t length, d2k_dns_endpoint *out, size_t capacity,
                 size_t *count, int owner) {
    if ((!text && length) || (!out && capacity) || !count ||
        capacity > SIZE_MAX / sizeof(*out) || (length && memchr(text, 0, length)))
        return D2K_DNS_PARSE_INVALID;
    d2k_dns_endpoint *pending = capacity ? calloc(capacity, sizeof(*pending)) : NULL;
    if (capacity && !pending) return D2K_DNS_PARSE_LOCAL;
    size_t used = 0, at = 0;
    int rc = D2K_DNS_PARSE_OK;
    while (at < length) {
        const char *newline = memchr(text + at, '\n', length - at);
        size_t n = newline ? (size_t)(newline - text - at) : length - at;
        char line[2048];
        if (copy(line, sizeof line, text + at, n)) {rc = D2K_DNS_PARSE_INVALID; break;}
        size_t next = at + n + !!newline;
        if (!owner && uri_continuations(text, length, &next, line, sizeof line)) {
            rc = D2K_DNS_PARSE_INVALID; break;
        }
        d2k_dns_endpoint e = {0};
        int present = owner == 1 ? owner_line(line, &e) :
            owner == 2 ? bootstrap_line(line, &e) : proxy_line(line, &e);
        if (present < 0) {rc = D2K_DNS_PARSE_INVALID; break;}
        if (present) {
            size_t i;
            for (i = 0; i < used; i++) if (d2k_dns_endpoint_equal(pending + i, &e)) break;
            if (i == used) {
                if (used == capacity) {rc = D2K_DNS_PARSE_LIMIT; break;}
                pending[used++] = e;
            }
        }
        at = next;
    }
    if (rc == D2K_DNS_PARSE_OK) {
        if (used) memcpy(out, pending, used * sizeof(*out));
        *count = used;
    }
    free(pending);
    return rc;
}
int d2k_dns_upstreams_parse(const char *text, size_t length, d2k_dns_endpoint *out,
                           size_t capacity, size_t *count) {
    return parse(text, length, out, capacity, count, 0);
}
int d2k_dns_owner_targets_parse(const char *text, size_t length, d2k_dns_endpoint *out,
                               size_t capacity, size_t *count) {
    return parse(text, length, out, capacity, count, 1);
}
int d2k_dns_bootstrap_parse(const char *text, size_t length, d2k_dns_endpoint *out,
                           size_t capacity, size_t *count) {
    return parse(text, length, out, capacity, count, 2);
}

/* With no observed question, ask about the configured server itself. A
 * numeric identity has a reverse DNS name rather than an invented hostname. */
uint16_t d2k_dns_probe_question_name(const char *server,char result[256]) {
    uint8_t ip[16];
    if (inet_pton(AF_INET,server,ip)==1) {
        snprintf(result,256,"%u.%u.%u.%u.in-addr.arpa",ip[3],ip[2],ip[1],ip[0]);
        return 12;
    }
    if (inet_pton(AF_INET6,server,ip)==1) {
        static const char hex[]="0123456789abcdef";
        size_t end=0;
        for (size_t i=16;i>0;i--) {
            uint8_t byte=ip[i-1];
            result[end++]=hex[byte&15];result[end++]='.';
            result[end++]=hex[byte>>4];result[end++]='.';
        }
        memcpy(result+end,"ip6.arpa",sizeof "ip6.arpa");
        return 12;
    }
    return d2k_domain_normalize(server,result) ? 0 : 1;
}
