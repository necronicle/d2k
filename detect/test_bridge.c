/* Contract tests for the production scheduler adapter, without network.
 * The classifier itself is exercised by test_tree; here its input/output
 * is intercepted so a correct classifier cannot hide a broken adapter. */
#include "d2k_detect.h"
#include "d2k_verdict.h"
#include <stdio.h>
#include <string.h>

d2k_vres d2k_detect_sched_tcp(const char *, uint16_t, d2k_hello, d2k_hello,
                             uint32_t, int, uint32_t, uint32_t);
int d2k_arm_from_poison(const d2k_poison *, d2k_arm *, char *, size_t);

static d2k_opts seen;
static d2k_result answer;
static int failures;
#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "bridge:%d: %s\n", __LINE__, #c); failures++; \
} } while (0)

void d2k_classify_run(const char *addr, const d2k_trigger *tr,
                      d2k_opts *opt, d2k_result *res)
{
    CHECK(strcmp(addr, "192.0.2.1:443") == 0);
    CHECK(tr->len == 2 && tr->payload[0] == 0x16);
    seen = *opt;
    *res = answer;
}

static d2k_vres measure(void)
{
    uint8_t hello[] = {0x16, 0x03};
    uint8_t ctl[] = {0x16, 0x03, 0x01};
    d2k_hello tr = {hello, sizeof hello}, control = {ctl, sizeof ctl};
    return d2k_detect_sched_tcp("192.0.2.1", 443, tr, control,
                                0x2d, 2, 12000, 321);
}

int main(void)
{
    d2k_vres r;
    d2k_arm arm;
    d2k_poison p;
    char why[160];
    {
        d2k_hello empty = {0};
        r = d2k_detect_sched_tcp("192.0.2.1", 443, empty, empty, 0x2d, 2, 12000, 321);
        CHECK(r.owns_search && !r.have_arm && r.verdict == D2K_V_FLAKY);
    }
    answer.verdict = D2K_DV_INCONCLUSIVE;
    r = measure();
    CHECK(seen.control.len == 3);
    CHECK(seen.control_vouched == 0); /* automatic control != operator promise */
    CHECK(seen.mark == 0x2d && seen.repeats == 2);
    CHECK(seen.write_gap_ms == 12 && seen.timeout_ms == 321);
    CHECK(r.verdict == D2K_V_INCONCLUSIVE);
    CHECK(r.owns_search && r.split_gap_us == 12000);

    answer.verdict = D2K_DV_POISONABLE;
    answer.has_hit = 1;
    strcpy(answer.hit.name, "seqovl-1");
    answer.hit.seqovl = 1;
    r = measure();
    CHECK(r.have_arm && r.arm.seqovl == 1);
    CHECK(strcmp(r.arm_name, "seqovl-1") == 0);
    /* d2k_vres is returned and repeatedly copied by value. No pointer into
     * the adapter's dead stack frame may escape with the result. */
    CHECK(r.arm.name == NULL);
    CHECK(r.arm_input.trigger_len == 2);
    {
        uint8_t decoy[] = {0xa1, 0, 0x7f};
        answer.hit.decoy = decoy;
        answer.hit.decoy_len = sizeof decoy;
        r = measure();
        decoy[0] = 0xff;
        CHECK(r.arm_input.decoy_len == 3 && r.arm_input.decoy[0] == 0xa1);
        CHECK(r.arm_input.decoy[1] == 0); /* binary, not a C string */
        d2k_vres copied = r;
        memset(&r, 0, sizeof r);
        CHECK(copied.arm_input.decoy[0] == 0xa1);
        answer.hit.decoy_len = D2K_ARM_DECOY_MAX + 1;
        r = measure();
        CHECK(!r.have_arm); /* fail before dereferencing an oversized prefix */
        answer.hit.decoy = NULL; answer.hit.decoy_len = 0;
    }

    memset(&p, 0, sizeof p);
    p.ttl = 8;
    CHECK(d2k_arm_from_poison(&p, &arm, why, sizeof why) == 0);
    CHECK(arm.repeats == 1 && arm.ttl == 8); /* TTL-only poison still emits a fake */
    p.ttl = 0;
    p.seq_shift = -66000;
    CHECK(d2k_arm_from_poison(&p, &arm, why, sizeof why) == 0);
    CHECK(arm.repeats == 1 && arm.seq_out);
    p.seq_shift = -123;
    CHECK(d2k_arm_from_poison(&p, &arm, why, sizeof why) != 0);
    p.seq_shift = 0;
    p.syn_data = 1;
    CHECK(d2k_arm_from_poison(&p, &arm, why, sizeof why) != 0);
    p.syn_data = 0; p.oob = 1;
    CHECK(d2k_arm_from_poison(&p, &arm, why, sizeof why) != 0);
    p.oob = 0; p.md5 = 1;
    CHECK(d2k_arm_from_poison(&p, &arm, why, sizeof why) != 0);
    if (failures) { return 1; }
    puts("bridge: scheduler adapter contracts passed");
    return 0;
}
