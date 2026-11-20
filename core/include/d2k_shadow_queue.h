/* Bounded, best-effort observation queue. No network or model dependencies.
 * All cooperating writers and the consumer lock the same inode with F_SETLK;
 * contention drops a record instead of delaying the live controller. */
#ifndef D2K_SHADOW_QUEUE_H
#define D2K_SHADOW_QUEUE_H
#include <stddef.h>
#include <stdint.h>
#include "d2k_plans.h"
#define D2K_SHADOW_QUEUE_MAX (64u * 1024u)
#define D2K_SHADOW_RECORD_MAX 2048u
#define D2K_SHADOW_HELLO_MAX 16384u
/* Cover every possible queued snapshot reference, four dispatched records
 * awaiting their stack copy, and the producer's publication. Even a legacy
 * nine-field snapshot record needs >=19 bytes (eight tabs, newline, valid
 * IPv6 "::", one-byte name/integers). Charge actual allocation units, not a file count.
 * Field I: minimum MemAvailable 186512 KiB, largest observed <=60s fall
 * 42408 KiB. At 4 KiB this declaration is 67.46 MiB; including an equal
 * startup reserve leaves 47.22 MiB, exceeding the measured 41.41 MiB fall.
 * Queue capacity, not question count or traffic rate, determines this cap. */
#define D2K_SHADOW_SNAPSHOT_RECORD_MIN 19u
#define D2K_SHADOW_SNAPSHOT_BUDGET_UNITS (D2K_SHADOW_QUEUE_MAX/D2K_SHADOW_SNAPSHOT_RECORD_MIN+5u)
#define D2K_SHADOW_RECENT_MAX 128u
#define D2K_SHADOW_HOUR 3600u

typedef struct {
    char doh_path[512];
    uint8_t priority; /* 2 owner, 1 degradation, 0 new suspicion */
    uint8_t degradation, protocol; /* 0 legacy TLS13; 1 TLS12; 2 TLS13 */
    uint32_t knowledge;
    uint64_t program_hash;
    d2k_binding_context binding; /* exact client execution, never current-name guess */
    uint64_t time;
    uint64_t snapshot, history_time;
    int snapshot_errno; /* producer persistence failure, not missing protocol support */
    uint64_t form_key; /* observed greeting/options, excluding fresh connection fields */
    uint64_t clean_source; /* passive flow identity; never evidence of APP_OK */
    char history_name[254];
    char host[254];
    char ip[46];
    uint16_t port;
    uint16_t signal;
    uint8_t family;
} d2k_shadow_record;

typedef struct {
    char path[512]; /* empty: disabled, no filesystem access */
    size_t limit;
    uint64_t written, dropped;
} d2k_shadow_writer;
typedef struct {
    uint64_t malformed, errors;
    /* Within one priority, unseen targets precede additional forms of
       targets already dispatched. The catalog owner supplies that history. */
    unsigned (*rank)(void *,const d2k_shadow_record *);
    void *rank_ctx;
    int (*discard)(void *,const d2k_shadow_record *);
    void *discard_ctx;
} d2k_shadow_reader;
int d2k_shadow_record_normalize(d2k_shadow_record *);
uint64_t d2k_shadow_form_key(const uint8_t *,size_t,const uint8_t *,size_t);
int d2k_shadow_writer_set(d2k_shadow_writer *, const char *path);
/* 1 written, 0 disabled, -1 dropped (including invalid input or lock busy). */
int d2k_shadow_queue_append(d2k_shadow_writer *, const d2k_shadow_record *);
/* Exact observed form already queued with bytes. Unknown/missing forms never
 * suppress a usable observation. Nonblocking: -1 error, 0 absent/busy, 1 found. */
int d2k_shadow_queue_pending(const char *,const d2k_shadow_record *);
/* 1 record, 0 empty/busy, -1 I/O failure. Malformed/torn lines are discarded.
 * Consumed bytes are reclaimed in place while locked: appends cannot be lost
 * to an unlink/rename race. A consumer must never replace the queue inode. */
int d2k_shadow_queue_next(const char *path, d2k_shadow_record *, d2k_shadow_reader *);
/* Reclaim unexecutable records and their unshared snapshots without dispatch. */
int d2k_shadow_queue_prune(const char *,d2k_shadow_reader *);
typedef struct {
    uint8_t hello[D2K_SHADOW_HELLO_MAX], options[40];
    size_t hello_len, options_len;
} d2k_shadow_snapshot;
typedef struct { d2k_shadow_record entries[D2K_SHADOW_RECENT_MAX]; size_t count; } d2k_shadow_recent;
int d2k_shadow_snapshot_write(const char *,d2k_shadow_record *,const uint8_t *,size_t,
                               const uint8_t *,size_t,uint64_t now);
int d2k_shadow_snapshot_read(const char *,const d2k_shadow_record *,d2k_shadow_snapshot *);
void d2k_shadow_snapshot_remove(const char *,const d2k_shadow_record *);
unsigned d2k_shadow_snapshot_cleanup(const char *,uint64_t now);
void d2k_shadow_recent_note(d2k_shadow_recent *,const d2k_shadow_record *,uint64_t now);
int d2k_shadow_recent_clean(const d2k_shadow_recent *,const d2k_shadow_record *,uint64_t now);
int d2k_shadow_recent_load(const char *queue,const char *producer,d2k_shadow_recent *,uint64_t now);
int d2k_shadow_recent_save(const char *queue,const char *producer,const d2k_shadow_recent *,uint64_t now);
#endif
