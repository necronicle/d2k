#ifndef D2KM_FIXTURE_H
#define D2KM_FIXTURE_H
#include "d2km_context.h"
#include <string.h>
static void fixture_context(d2km_context *c)
{
    memset(c, 0, sizeof(*c));
    d2km_target_name(&c->target, "example.com");
    c->transport = D2KM_TCP;
    c->protocol = D2KM_P_TLS13;
    c->family = D2KM_IPV4;
    static const uint8_t hello[6] = {0x16, 3, 1, 0, 1, 1};
    d2km_form_set(&c->form, hello, sizeof(hello), NULL, 0, NULL, 0, 0, 0);
    strcpy(c->path.ifname, "ppp0");
    c->path.mtu = 1500;
}
#endif
