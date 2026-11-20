/* test_routemark.c — which client marks select a policy route (task 47 fix
 * round 1, review I2).  Pure matcher and RTM_GETRULE dump parser; the
 * netlink socket itself is Linux-only (routemark_nl.c). */
#include <stdio.h>
#include <string.h>

#include "d2k_routemark.h"

static int fails;
#define CHECK(x, m) do { if (!(x)) { fprintf(stderr, "routemark:%d: %s\n", __LINE__, m); fails++; } } while (0)

static void w16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }   /* host order */
static void w32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }

/* One RTM_NEWRULE message: fib_rule_hdr + optional FRA_FWMARK/FRA_FWMASK +
 * FRA_TABLE (always, to prove unrelated attributes are skipped). */
static uint32_t next_flags;          /* fib_rule_hdr.flags of the next rule_msg */
static size_t rule_msg(uint8_t *o, uint8_t family, int have_mark, uint32_t mark,
                       int have_mask, uint32_t mask, uint8_t action) {
    size_t n = 16 + 12;
    memset(o, 0, 128);
    w16(o + 4, 32);                 /* RTM_NEWRULE */
    o[16] = family;
    w32(o + 16 + 8, next_flags);
    next_flags = 0;
    o[16 + 4] = 252;                /* table (compat byte) */
    o[16 + 7] = action;             /* FR_ACT_TO_TBL=1, BLACKHOLE=6 */
    w16(o + n, 8); w16(o + n + 2, 15); w32(o + n + 4, 4096); n += 8;  /* FRA_TABLE */
    if (have_mark) { w16(o + n, 8); w16(o + n + 2, 10); w32(o + n + 4, mark); n += 8; }
    if (have_mask) { w16(o + n, 8); w16(o + n + 2, 16); w32(o + n + 4, mask); n += 8; }
    w32(o, (uint32_t)n);
    return n;
}

static size_t done_msg(uint8_t *o) {
    memset(o, 0, 20);
    w32(o, 20); w16(o + 4, 3);       /* NLMSG_DONE */
    return 20;
}

/* One RTM_NEWROUTE message: rtmsg + RTA_TABLE + optional RTA_DST, RTA_OIF,
 * or an RTA_MULTIPATH with two nexthops. */
static size_t route_msg(uint8_t *o, uint8_t family, uint8_t dst_len, uint8_t rtm_table,
                        uint32_t table_attr, uint8_t type, uint32_t oif,
                        uint32_t mp1, uint32_t mp2) {
    size_t n = 16 + 12;
    memset(o, 0, 160);
    w16(o + 4, 24);                 /* RTM_NEWROUTE */
    o[16] = family;
    o[17] = dst_len;
    o[16 + 4] = rtm_table;
    o[16 + 7] = type;               /* RTN_UNICAST=1, RTN_UNREACHABLE=7 */
    if (table_attr) { w16(o + n, 8); w16(o + n + 2, 15); w32(o + n + 4, table_attr); n += 8; }
    if (dst_len) {
        size_t al = family == 10 ? 16 : 4;
        w16(o + n, (uint16_t)(4 + al)); w16(o + n + 2, 1);
        memset(o + n + 4, 0x0a, al); n += 4 + al;
    }
    if (oif) { w16(o + n, 8); w16(o + n + 2, 4); w32(o + n + 4, oif); n += 8; }
    if (mp1) {
        /* RTA_MULTIPATH: two struct rtnexthop {len16, flags8, hops8, ifindex32},
           the second with a nested RTA_GATEWAY to prove its length is used. */
        size_t a = n;
        n += 4;
        w16(o + n, 8); o[n + 2] = 0; o[n + 3] = 0; w32(o + n + 4, mp1); n += 8;
        w16(o + n, 16); o[n + 2] = 0; o[n + 3] = 0; w32(o + n + 4, mp2);
        w16(o + n + 8, 8); w16(o + n + 10, 5); w32(o + n + 12, 0x01020304); n += 16;
        w16(o + a, (uint16_t)(n - a)); w16(o + a + 2, 9);
    }
    w32(o, (uint32_t)n);
    return n;
}

static int has_oif(const uint32_t *v, size_t n, uint32_t x) {
    for (size_t i = 0; i < n; i++) { if (v[i] == x) { return 1; } }
    return 0;
}

int main(void) {
    uint8_t buf[1024];
    size_t len = 0;
    /* Keenetic 03.10: 100 fwmark 0xffffaaa lookup 4096; 101 same -> blackhole;
       1170 from <wan> lookup 16394 (no mark); IPv6 fwmark 0x100/0xff00. */
    len += rule_msg(buf + len, 2, 1, 0xffffaaa, 1, 0xffffffff, 1);
    len += rule_msg(buf + len, 2, 1, 0xffffaaa, 1, 0xffffffff, 6);
    len += rule_msg(buf + len, 2, 0, 0, 0, 0, 1);
    len += rule_msg(buf + len, 10, 1, 0x100, 1, 0xff00, 1);
    len += rule_msg(buf + len, 2, 1, 0x200, 0, 0, 1);   /* old kernels: no mask -> full */
    len += done_msg(buf + len);

    d2k_fwsel sel[D2K_ROUTEMARK_MAX];
    size_t n = 0;
    CHECK(d2k_routemark_parse(sel, D2K_ROUTEMARK_MAX, &n, buf, len, NULL) == 1, "dump parsed to DONE");
    CHECK(n == 4, "four fwmark selectors (the address rule is not one)");

    d2k_routemark rm;
    d2k_routemark_init(&rm);
    /* Final review M-2: before the first successful read nothing is known,
       so every foreign nonzero mark counts as routed (fail closed). */
    CHECK(d2k_routemark_routed(&rm, 4, 0xffffaaa) && d2k_routemark_routed(&rm, 6, 0x1),
          "no rules read yet: any foreign mark is routed");
    CHECK(!d2k_routemark_routed(&rm, 4, 0), "no rules read yet: no mark is still not routed");
    CHECK(d2k_routemark_set(&rm, sel, n) == 1, "first load is a change");
    CHECK(d2k_routemark_set(&rm, sel, n) == 0, "same set again: no change (no log line)");
    CHECK(d2k_routemark_routed(&rm, 4, 0xffffaaa), "DNSRT mark with its rule: routed");
    CHECK(!d2k_routemark_routed(&rm, 4, 0x1), "PPPoE-style 0x1 without a rule: not routed");
    CHECK(!d2k_routemark_routed(&rm, 4, 0x989), "a stray mark without a rule: not routed");
    CHECK(!d2k_routemark_routed(&rm, 4, 0), "no mark: never routed");
    CHECK(d2k_routemark_routed(&rm, 6, 0x1ff), "masked selector 0x100/0xff00 matches 0x1ff");
    CHECK(!d2k_routemark_routed(&rm, 6, 0x2ff), "masked selector does not match 0x2ff");
    CHECK(d2k_routemark_routed(&rm, 4, 0x200) && !d2k_routemark_routed(&rm, 4, 0x201),
          "a mark without a mask attribute is matched exactly");

    char text[256];
    CHECK(d2k_routemark_describe(&rm, text, sizeof text) > 0 && strstr(text, "0xffffaaa"),
          "selectors can be logged");

    /* The caller's gate: own marks never count, routed marks pass through. */
    CHECK(d2k_routemark_client(&rm, 4, 1, 0xffffaaa, 0x2e, 0x2d) == 0xffffaaa, "routed client mark");
    CHECK(d2k_routemark_client(&rm, 4, 1, 0x1, 0x2e, 0x2d) == 0, "unrouted mark: d2k works");
    CHECK(d2k_routemark_client(&rm, 4, 0, 0xffffaaa, 0x2e, 0x2d) == 0, "no mark attribute");

    /* Rule removed: refresh with a dump that lacks it. */
    len = 0;
    len += rule_msg(buf + len, 2, 0, 0, 0, 0, 1);
    len += done_msg(buf + len);
    n = 0;
    CHECK(d2k_routemark_parse(sel, D2K_ROUTEMARK_MAX, &n, buf, len, NULL) == 1 && n == 0,
          "dump without fwmark rules");
    CHECK(d2k_routemark_set(&rm, sel, n) == 1, "removal is a change");
    CHECK(!d2k_routemark_routed(&rm, 4, 0xffffaaa), "rule removed: no longer routed after refresh");

    /* Malformed input never reads past the buffer and is reported. */
    uint8_t bad[24];
    memset(bad, 0, sizeof bad);
    w32(bad, 200); w16(bad + 4, 32);
    n = 0;
    CHECK(d2k_routemark_parse(sel, D2K_ROUTEMARK_MAX, &n, bad, sizeof bad, NULL) == -1, "garbage refused");
    uint8_t req[64];
    size_t rl = d2k_routemark_request(req, sizeof req, 2, 7);
    CHECK(rl >= 28 && req[16] == 2, "dump request for AF_INET");

    /* --- fix round 2 ---------------------------------------------------- */
    d2k_fwsel v4[D2K_ROUTEMARK_MAX], v6[D2K_ROUTEMARK_MAX];
    size_t n4 = 0, n6 = 0;

    /* m1: `not fwmark X` (FIB_RULE_INVERT) does not route X. */
    len = 0;
    next_flags = 0x2;
    len += rule_msg(buf + len, 2, 1, 0x77, 1, 0xffffffff, 1);
    len += rule_msg(buf + len, 2, 1, 0xffffaaa, 1, 0xffffffff, 1);
    len += done_msg(buf + len);
    CHECK(d2k_routemark_parse(v4, D2K_ROUTEMARK_MAX, &n4, buf, len, NULL) == 1 && n4 == 1 &&
          v4[0].mark == 0xffffaaa, "an inverted fwmark rule is not a selector");

    /* m5: a dump split over two reads; then NLMSG_ERROR; overrun; mask-only. */
    n4 = 0;
    size_t l1 = rule_msg(buf, 2, 1, 0xffffaaa, 1, 0xffffffff, 1);
    CHECK(d2k_routemark_parse(v4, D2K_ROUTEMARK_MAX, &n4, buf, l1, NULL) == 0 && n4 == 1,
          "first part of a multipart dump: more to come");
    size_t l2 = rule_msg(buf, 2, 1, 0x300, 1, 0xff00, 1);
    l2 += done_msg(buf + l2);
    CHECK(d2k_routemark_parse(v4, D2K_ROUTEMARK_MAX, &n4, buf, l2, NULL) == 1 && n4 == 2,
          "second part ends with DONE");
    uint8_t er[36];
    memset(er, 0, sizeof er);
    w32(er, 36); w16(er + 4, 2); w32(er + 16, (uint32_t)-97);   /* -EAFNOSUPPORT */
    n6 = 0;
    int32_t kerr = 0;
    CHECK(d2k_routemark_parse(v6, D2K_ROUTEMARK_MAX, &n6, er, sizeof er, &kerr) == -1 &&
          kerr == -97, "NLMSG_ERROR fails that family's dump and names the error");
    uint8_t ov[128];
    size_t ol = rule_msg(ov, 2, 1, 0x5, 1, 0xff, 1);
    w16(ov + 28, 200);                       /* first attribute claims 200 bytes */
    size_t on = 0;
    CHECK(d2k_routemark_parse(v6, D2K_ROUTEMARK_MAX, &on, ov, ol, NULL) == -1,
          "an attribute overrunning its message is refused");
    len = rule_msg(buf, 2, 0, 0, 1, 0xff00, 1);          /* fwmark 0/0xff00 */
    len += done_msg(buf + len);
    on = 0;
    CHECK(d2k_routemark_parse(v6, D2K_ROUTEMARK_MAX, &on, buf, len, NULL) == 1 && on == 1 &&
          v6[0].mark == 0 && v6[0].mask == 0xff00, "mask-only selector kept");

    /* I-A: an IPv6 dump failure keeps the IPv4 selectors. */
    d2k_routemark_init(&rm);
    d2k_routemark_status st;
    v4[0].mark = 0xffffaaa; v4[0].mask = 0xffffffff; v4[0].family = 2; n4 = 1;
    CHECK(d2k_routemark_merge(&rm, v4, n4, 1, v6, 0, 0, &st) == 1 && !st.v6_ok,
          "v4 loaded although v6 failed");
    CHECK(d2k_routemark_routed(&rm, 4, 0xffffaaa), "the IPv4 gate survives a v6 failure");
    CHECK(d2k_routemark_merge(&rm, v4, 0, 0, v6, 0, 1, &st) == 0 && !st.v4_ok &&
          d2k_routemark_routed(&rm, 4, 0xffffaaa), "a v4 failure keeps the previous v4 set");

    /* m2: the family of the rule is the family of the packet. */
    CHECK(!d2k_routemark_routed(&rm, 6, 0xffffaaa), "a v4-only selector does not route IPv6");
    v6[0].mark = 0x500; v6[0].mask = 0xffffffff; v6[0].family = 10;
    CHECK(d2k_routemark_merge(&rm, v4, n4, 1, v6, 1, 1, &st) == 1 && st.v6_ok, "v4+v6");
    CHECK(d2k_routemark_routed(&rm, 6, 0x500) && !d2k_routemark_routed(&rm, 4, 0x500),
          "a v6 selector routes only IPv6");

    /* m4: more selectors than the table holds is reported. */
    d2k_fwsel many[D2K_ROUTEMARK_MAX + 3];
    for (size_t i = 0; i < D2K_ROUTEMARK_MAX + 3; i++) {
        many[i].mark = (uint32_t)(0x1000 + i); many[i].mask = 0xffffffff; many[i].family = 2;
    }
    (void)d2k_routemark_merge(&rm, many, D2K_ROUTEMARK_MAX + 3, 1, v6, 0, 1, &st);
    CHECK(st.truncated && st.found == D2K_ROUTEMARK_MAX + 3 && rm.n == D2K_ROUTEMARK_MAX,
          "truncation reported");
    len = 0;
    for (int i = 0; i < 3; i++) { len += rule_msg(buf + len, 2, 1, (uint32_t)(0x10 + i), 1, 0xffffffff, 1); }
    len += done_msg(buf + len);
    n4 = 0;
    CHECK(d2k_routemark_parse(v4, 2, &n4, buf, len, NULL) == 1 && n4 == 3,
          "parse counts selectors past its cap");


    /* --- final review I-1: the output interface gate ---------------------- */
    {
        /* Review I-A: no table dumps on the packet thread.  One non-dump
           RTM_GETROUTE per family for a fixed probe address answers which
           device a raw send would leave through. */
        uint8_t rq[128];
        size_t rql = d2k_routemark_lookup_request(rq, sizeof rq, 2, 5);
        uint16_t rflags;
        memcpy(&rflags, rq + 6, 2);
        CHECK(rql >= 36 && rq[4] == 26 && rq[16] == 2 && rq[17] == 32 && rflags == 1,
              "IPv4 lookup: RTM_GETROUTE, request only (no dump), dst/32");
        CHECK(rq[28 + 2] == 1 && rq[32] == 192 && rq[33] == 0 && rq[34] == 2 && rq[35] == 1,
              "IPv4 lookup carries RTA_DST 192.0.2.1");
        rql = d2k_routemark_lookup_request(rq, sizeof rq, 10, 6);
        memcpy(&rflags, rq + 6, 2);
        CHECK(rql >= 48 && rq[16] == 10 && rq[17] == 128 && rflags == 1 &&
              rq[32] == 0x20 && rq[33] == 0x01 && rq[34] == 0x0d && rq[35] == 0xb8,
              "IPv6 lookup: dst/128, RTA_DST 2001:db8::1");
        CHECK(d2k_routemark_lookup_request(rq, 8, 2, 1) == 0, "small buffer refused");

        uint32_t oifs[D2K_ROUTEMARK_OIF_MAX];
        size_t no = 0;
        int32_t rk = 0;
        /* The answer: a unicast route through ppp0 (5), cloned flag set. */
        len = route_msg(buf, 2, 32, 254, 254, 1, 5, 0, 0);
        w32(buf + 16 + 8, 0x200);
        CHECK(d2k_routemark_lookup_parse(oifs, D2K_ROUTEMARK_OIF_MAX, &no, buf, len, &rk) == 1 &&
              no == 1 && oifs[0] == 5, "lookup answer: the device of the route");
        no = 0;
        len = route_msg(buf, 2, 32, 254, 254, 1, 0, 6, 8);
        CHECK(d2k_routemark_lookup_parse(oifs, D2K_ROUTEMARK_OIF_MAX, &no, buf, len, &rk) == 1 &&
              no == 2 && has_oif(oifs, no, 6) && has_oif(oifs, no, 8),
              "a multipath answer gives every hop");
        no = 0;
        len = route_msg(buf, 10, 128, 254, 254, 7, 1, 0, 0);    /* unreachable, dev lo */
        CHECK(d2k_routemark_lookup_parse(oifs, D2K_ROUTEMARK_OIF_MAX, &no, buf, len, &rk) == 2 &&
              no == 0, "an unreachable answer: no route");
        no = 0;
        len = route_msg(buf, 2, 32, 254, 254, 1, 0, 0, 0);      /* nexthop object, no OIF */
        CHECK(d2k_routemark_lookup_parse(oifs, D2K_ROUTEMARK_OIF_MAX, &no, buf, len, &rk) == 1 &&
              no == 0, "a unicast answer without a device: route exists, device unknown");
        uint8_t ne[36];
        memset(ne, 0, sizeof ne);
        w32(ne, 36); w16(ne + 4, 2); w32(ne + 16, (uint32_t)-101);
        no = 0;
        CHECK(d2k_routemark_lookup_parse(oifs, D2K_ROUTEMARK_OIF_MAX, &no, ne, sizeof ne, &rk) == -1 &&
              rk == -101, "a kernel error is reported with its errno");
        no = 0;
        CHECK(d2k_routemark_lookup_parse(oifs, D2K_ROUTEMARK_OIF_MAX, &no, bad, sizeof bad, &rk) == -1,
              "garbage refused");

        /* Notifications: rules always; routes only for defaults (dst/0). */
        len = rule_msg(buf, 2, 1, 0x5, 1, 0xff, 1);
        CHECK(d2k_routemark_watch_relevant(buf, len) == 1, "a rule change is relevant");
        w16(buf + 4, 33);
        CHECK(d2k_routemark_watch_relevant(buf, len) == 1, "a rule removal is relevant");
        len = route_msg(buf, 2, 24, 254, 254, 1, 3, 0, 0);
        CHECK(d2k_routemark_watch_relevant(buf, len) == 0, "a /24 route change is not");
        len = route_msg(buf, 2, 32, 252, 1000, 1, 9, 0, 0);
        w16(buf + 4, 25);
        CHECK(d2k_routemark_watch_relevant(buf, len) == 0, "a host route removal is not");
        size_t l2r = route_msg(buf, 2, 24, 254, 254, 1, 3, 0, 0);
        l2r += route_msg(buf + l2r, 2, 0, 254, 254, 1, 5, 0, 0);
        CHECK(d2k_routemark_watch_relevant(buf, l2r) == 1, "a default among others is relevant");
        len = route_msg(buf, 10, 0, 254, 254, 1, 5, 0, 0);
        w16(buf + 4, 25);
        CHECK(d2k_routemark_watch_relevant(buf, len) == 1, "a default removal is relevant");
        memset(buf, 0, 40); w32(buf, 40); w16(buf + 4, 28);     /* RTM_NEWNEIGH */
        CHECK(d2k_routemark_watch_relevant(buf, 40) == 0, "other messages are not");
        CHECK(d2k_routemark_watch_relevant(bad, sizeof bad) == 1,
              "an unreadable notification: refresh to be safe");

        /* The device set the gate compares with. */
        no = 0;
        len = route_msg(buf, 2, 32, 254, 254, 1, 5, 0, 0);
        (void)d2k_routemark_lookup_parse(oifs, D2K_ROUTEMARK_OIF_MAX, &no, buf, len, &rk);
        len = route_msg(buf, 2, 32, 254, 254, 1, 0, 6, 8);
        CHECK(d2k_routemark_lookup_parse(oifs, D2K_ROUTEMARK_OIF_MAX, &no, buf, len, &rk) == 1 &&
              no == 3, "answers accumulate distinct devices");
        d2k_routemark g;
        d2k_routemark_init(&g);
        /* Routes unknown: no outdev gate (nothing to compare with). */
        CHECK(d2k_routemark_gate(&g, 4, 1, 0, 0, 0x2e, 0x2d, 1, 9) == 0,
              "default devices unknown: an unmarked packet is not gated");
        CHECK(d2k_routemark_set_oifs(&g, 2, oifs, no, 1) == 1, "first route read is a change");
        CHECK(d2k_routemark_set_oifs(&g, 2, oifs, no, 1) == 0, "same set: no change");
        CHECK(d2k_routemark_gate(&g, 4, 1, 0, 0, 0x2e, 0x2d, 1, 5) == 0,
              "out through the default device: d2k works");
        CHECK(d2k_routemark_gate(&g, 4, 1, 0, 0, 0x2e, 0x2d, 1, 8) == 0,
              "a multipath default hop is a default device");
        CHECK(d2k_routemark_gate(&g, 4, 1, 0, 0, 0x2e, 0x2d, 1, 9) == D2K_ROUTE_OTHER_DEV,
              "source/iif-routed client leaving through a VPN device: routed");
        CHECK(d2k_routemark_gate(&g, 4, 0, 0, 0, 0x2e, 0x2d, 1, 3) == 0,
              "a reply (FORWARD/INPUT, out to the LAN) is never gated by its device");
        CHECK(d2k_routemark_gate(&g, 4, 1, 0, 0, 0x2e, 0x2d, 0, 0) == 0,
              "no outdev attribute: no device gate");

        /* ТОЛЬКО ПОЛИТИКА KEENETIC (задача 59). Метка политики 0xffffaaa
           выбирает свою таблицу правилом ip rule — как у владельца, — и
           именно её трафик обслуживается; всё прочее исходящее идёт ядром. */
        d2k_routemark pol = g;
        d2k_fwsel ps = { 0xffffaaa, 0xffffffff, 2 };
        (void)d2k_routemark_set(&pol, &ps, 1);
        CHECK(d2k_routemark_gate(&pol, 4, 1, 1, 0xffffaaa, 0x2e, 0x2d, 1, 5) == 0xffffaaa,
              "policy: before the mode the policy mark reads as routed (the old exclusion)");
        d2k_routemark_set_policy(&pol, 0, 0xffffaaa, 0xffffffff);
        CHECK(d2k_routemark_gate(&pol, 4, 1, 1, 0xffffaaa, 0x2e, 0x2d, 1, 5) == 0,
              "policy: a client with the policy mark is served");
        CHECK(!d2k_routemark_routed(&pol, 4, 0xffffaaa),
              "policy: its own mark is not 'routed away' for the UDP output either");
        CHECK(d2k_routemark_gate(&pol, 4, 1, 1, 0xffffaaa, 0x2e, 0x2d, 1, 9) == D2K_ROUTE_OTHER_DEV,
              "policy: a policy leaving through another device (VPN) stays on the kernel path");
        CHECK(d2k_routemark_gate(&pol, 4, 1, 0, 0, 0x2e, 0x2d, 1, 5) == D2K_ROUTE_OUTSIDE,
              "policy: an unmarked client (or the router's own traffic) is outside");
        CHECK(d2k_routemark_gate(&pol, 4, 1, 1, 0x40, 0x2e, 0x2d, 1, 5) == D2K_ROUTE_OUTSIDE,
              "policy: another mark is outside");
        CHECK(d2k_routemark_gate(&pol, 4, 1, 1, 0x2e, 0x2e, 0x2d, 1, 5) == 0 &&
              d2k_routemark_gate(&pol, 4, 1, 1, 0x2d, 0x2e, 0x2d, 1, 5) == 0,
              "policy: the controller's probes and the datapath's own sends are still served");
        CHECK(d2k_routemark_gate(&pol, 4, 0, 0, 0, 0x2e, 0x2d, 1, 3) == 0,
              "policy: a reply carries no mark and follows its flow, never gated here");
        CHECK(d2k_routemark_routed(&pol, 4, D2K_ROUTE_OUTSIDE),
              "policy: outside reads as routed (the UDP output keeps it on the kernel path)");
        (void)d2k_routemark_set(&pol, &ps, 1);
        CHECK(d2k_routemark_gate(&pol, 4, 1, 0, 0, 0x2e, 0x2d, 1, 5) == D2K_ROUTE_OUTSIDE &&
              d2k_routemark_gate(&pol, 4, 1, 1, 0xffffaaa, 0x2e, 0x2d, 1, 5) == 0,
              "policy: the mode survives a rule refresh");
        d2k_routemark_set_policy(&pol, 0, 0x10000, 0xff0000);
        CHECK(d2k_routemark_gate(&pol, 4, 1, 1, 0x10040, 0x2e, 0x2d, 1, 5) == 0,
              "OpenWrt group: unrelated bits do not exclude a selected client");
        CHECK(d2k_routemark_gate(&pol, 4, 1, 1, 0x20040, 0x2e, 0x2d, 1, 5) == D2K_ROUTE_OUTSIDE,
              "OpenWrt group: other groups stay outside");
        d2k_routemark_set_policy(&pol, 1, 0, 0);
        CHECK(d2k_routemark_gate(&pol, 4, 1, 1, 0xffffaaa, 0x2e, 0x2d, 1, 5) == D2K_ROUTE_OUTSIDE &&
              d2k_routemark_gate(&pol, 4, 1, 0, 0, 0x2e, 0x2d, 1, 5) == D2K_ROUTE_OUTSIDE,
              "policy not found: no client is served");
        CHECK(d2k_routemark_gate(&pol, 4, 1, 1, 0x2e, 0x2e, 0x2d, 1, 5) == 0,
              "policy not found: the controller's own probes still work");
        CHECK(d2k_routemark_gate(&g, 6, 1, 0, 0, 0x2e, 0x2d, 1, 9) == 0,
              "IPv6 default devices unknown: no IPv6 device gate");
        CHECK(d2k_routemark_routed(&g, 4, D2K_ROUTE_OTHER_DEV),
              "the device verdict reads as routed to the UDP output");

        /* A failed route read keeps the previous devices. */
        CHECK(d2k_routemark_set_oifs(&g, 2, oifs, 0, 0) == 0 &&
              d2k_routemark_gate(&g, 4, 1, 0, 0, 0x2e, 0x2d, 1, 9) == D2K_ROUTE_OTHER_DEV,
              "route read error: previous default devices kept");
        /* IPv6 with no default route in main: every outbound v6 device is
           elsewhere — a raw send could not follow it. */
        CHECK(d2k_routemark_set_oifs(&g, 10, oifs, 0, 1) == 1 &&
              d2k_routemark_gate(&g, 6, 1, 0, 0, 0x2e, 0x2d, 1, 5) == D2K_ROUTE_OTHER_DEV,
              "no IPv6 route: outbound IPv6 is routed elsewhere");
        /* Review minor: a route exists but no device is known (nexthop
           objects): no device gate for that family, the mark gate only. */
        CHECK(d2k_routemark_clear_oifs(&g, 10) == 1 &&
              d2k_routemark_gate(&g, 6, 1, 0, 0, 0x2e, 0x2d, 1, 5) == 0,
              "device unknown: no IPv6 device gate");
        CHECK(d2k_routemark_clear_oifs(&g, 10) == 0, "clearing again is no change");

        /* Marks: own and probe marks never gate by mark; a routed fwmark wins
           (its own value is logged). */
        d2k_fwsel one = {0xffffaaa, 0xffffffff, 2};
        (void)d2k_routemark_merge(&g, &one, 1, 1, NULL, 0, 1, &st);
        CHECK(d2k_routemark_gate(&g, 4, 1, 1, 0xffffaaa, 0x2e, 0x2d, 1, 9) == 0xffffaaa,
              "a routing fwmark is reported as the mark");
        CHECK(d2k_routemark_gate(&g, 4, 1, 1, 0x2e, 0x2e, 0x2d, 1, 5) == 0,
              "the probe mark through the default device: not routed");
        CHECK(d2k_routemark_gate(&g, 4, 1, 1, 0x1, 0x2e, 0x2d, 1, 5) == 0,
              "an unrouted foreign mark through the default device: not routed");
        CHECK(d2k_routemark_gate(&g, 4, 1, 1, 0x1, 0x2e, 0x2d, 1, 9) == D2K_ROUTE_OTHER_DEV,
              "an unrouted mark leaving through another device: routed by device");
    }

    /* --- final review M-2: per-family keep-previous ------------------------ */
    {
        d2k_routemark k;
        d2k_routemark_init(&k);
        d2k_fwsel a4 = {0xffffaaa, 0xffffffff, 2}, a6 = {0x500, 0xffffffff, 10};
        CHECK(d2k_routemark_merge(&k, &a4, 1, 1, &a6, 1, 1, &st) == 1, "both families read");
        CHECK(d2k_routemark_merge(&k, NULL, 0, 1, NULL, 0, 0, &st) == 1 && !st.v6_ok,
              "v4 now empty, v6 read failed");
        CHECK(!d2k_routemark_routed(&k, 4, 0xffffaaa), "v4 rule removed");
        CHECK(d2k_routemark_routed(&k, 6, 0x500), "a v6 read error keeps the v6 selectors");
        CHECK(d2k_routemark_merge(&k, NULL, 0, 0, NULL, 0, 0, &st) == 0 &&
              d2k_routemark_routed(&k, 6, 0x500), "both failed: nothing changes");
        CHECK(!d2k_routemark_routed(&k, 4, 0x77), "v4 read once: an unrouted mark is neutral");

        d2k_routemark u;
        d2k_routemark_init(&u);
        CHECK(d2k_routemark_merge(&u, &a4, 1, 1, NULL, 0, 0, &st) == 1, "v4 read, v6 not");
        CHECK(!d2k_routemark_routed(&u, 4, 0x77) && d2k_routemark_routed(&u, 6, 0x77),
              "a family never read keeps failing closed for foreign marks");
        CHECK(d2k_routemark_client(&u, 6, 1, 0x2e, 0x2e, 0x2d) == 0,
              "own/probe marks are never foreign");
    }
    if (!fails) puts("routemark: selectors, matcher and refresh passed");
    return fails != 0;
}
