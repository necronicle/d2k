#ifndef D2K_NEWCHAIN_H
#define D2K_NEWCHAIN_H
#include "d2k_link.h"
#include "d2k_hello.h"
#include "d2k_shadow_queue.h"
#include "../../model/include/d2km_store.h"
#include <stdio.h>
#include <sys/types.h>
typedef struct {
    char name[254],source[16];
    uint32_t knowledge,box;
    uint64_t hash,last_success,authority;
    uint8_t family,shape,plan_id[16];
} d2k_newchain_value;
typedef struct {
    d2k_newchain_value active,desired;
    d2k_binding_context binding;
    uint8_t token[16];
    int pending; /* SET or conditional DEL; only ACK acquires/releases ownership */
} d2k_newchain_entry;
typedef struct {
    int (*allow_knowledge)(void *,const d2km_knowledge *);
    void *allow_ctx;
    char path[512];
    d2km_store *cached; /* last completely validated read-only snapshot */
    int reconcile;
    char *pending_hex; /* one unacknowledged SET, freed on ACK/destruction */
    d2k_newchain_entry entries[D2KM_STORE_KNOWLEDGE_MAX];
    size_t count;
    int polled,loaded;
    int64_t last_poll;
    time_t mtime;
    long mtime_ns;
    off_t size;
} d2k_newchain;
typedef void (*d2k_newchain_log)(void *,const char *);
int d2k_newchain_set(d2k_newchain *,const char *);
int d2k_newchain_poll(d2k_newchain *,int fd,int64_t now,d2k_newchain_log,void *);
int d2k_newchain_event(d2k_newchain *,const d2k_ev *,d2k_newchain_log,void *);
int d2k_newchain_protects(const d2k_newchain *,const char *,uint8_t tr,uint8_t family,uint8_t shape);
int d2k_newchain_signal(const d2k_newchain *,const char *,const d2k_ev *,d2k_shadow_record *);
size_t d2k_newchain_count(const d2k_newchain *);
void d2k_newchain_json(const d2k_newchain *,FILE *);
#endif
