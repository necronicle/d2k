#ifndef D2K_APPLICATION_POLICY_H
#define D2K_APPLICATION_POLICY_H
#include "application_archive.h"
#include "application_trial.h"
#include "path_work.h"
/* One worker-owned policy. Base identity, seed, input, reference and FILE are
 * borrowed until destroy; the path session must be freed first. Owns only
 * trial tape/model/program/witness. Archive witness and required query horizon
 * are selected at init. Caller may raise required_queries to a known question
 * horizon BEFORE creating a path session; thereafter the contract is immutable
 * until destroy. New evidence requires a new policy/model contract. */
typedef struct {
    d2k_raw_tape *tape;
    uint64_t experience,generation;
    d2k_application_owner *owner;
    d2k_application_model *model;
    const d2k_application_model *reference;
    const d2k_application_model *baseline_reference;
    d2k_application_model *witness;
    d2k_application_question comparison;
    const d2k_synthesis_feedback *base;
    d2k_synthesis_feedback trial;
    const d2k_tls_probe_seed *seed;
    const uint8_t *input;
    size_t input_length;
    char *program;
    d2k_ver_result result;
    unsigned required_queries,completed_queries;
    int qualified;
    FILE *archive;
    int evidence_error;
    int timeout_ms;
    size_t hello_wire;
} d2k_application_policy;
int d2k_application_policy_init(d2k_application_policy *,const d2k_synthesis_feedback *,
    const d2k_application_model *,const d2k_tls_probe_seed *,const uint8_t *,size_t,
    uint64_t,int,size_t,FILE *);
void d2k_application_policy_destroy(d2k_application_policy *);
int d2k_application_policy_sink(void *,d2k_raw_tls_sink *);
d2k_tls_application d2k_application_policy_callbacks(d2k_application_policy *);
int d2k_application_save(FILE *,const d2k_application_model *,d2k_ver_result *);
int d2k_application_query_complete(const d2k_ver_result *);
int d2k_application_identify_trial(d2k_synthesis_feedback *,char *);
#endif
