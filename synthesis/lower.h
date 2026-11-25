#ifndef D2K_LOWER_H
#define D2K_LOWER_H
#include <stddef.h>
#include <stdint.h>
typedef struct {size_t offset,length;uint32_t delay_us;} d2k_payload_piece;
typedef enum {D2K_LOWER_ERROR=-1,D2K_LOWER_OK=0,D2K_LOWER_INVALID=1,
              D2K_LOWER_UNSUPPORTED=2} d2k_lower_status;
/* Lower original-payload slices in emission order into the shared Plan
 * format. No recipes, byte replacement, missing tail, overlap, or silent
 * approximation. This is compilation, not evidence that a bypass works.
 * Caller frees *text. Unsupported sequences require extending Plan. */
d2k_lower_status d2k_lower_partition(size_t,const d2k_payload_piece *,size_t,
                                    const char *protocol,char **text,char *err,size_t);
/* Same byte-preserving compilation, bound to an observed SNI position and
 * length when the caller derived a boundary from that field. */
d2k_lower_status d2k_lower_partition_observed(size_t,const d2k_payload_piece *,size_t,
    const char *protocol,size_t sni_offset,size_t sni_length,char **text,char *err,size_t);
/* Compose an observed original partition with a caller-supplied left-hand TCP
 * overlap. The caller supplies both the overlap bytes and the input shape. */
d2k_lower_status d2k_lower_partition_overlap_observed(size_t,const d2k_payload_piece *,size_t,
    const char *protocol,size_t sni_offset,size_t sni_length,
    const uint8_t *overlap,size_t overlap_length,char **text,char *err,size_t);
/* Compile one caller-supplied TLS prefix, then the unchanged original stream.
 * The prefix uses the existing stale-timestamp operation; this compiler does
 * not establish remote rejection or application success. Caller supplies the
 * measured segment size and content. tls_mod: bit0 random, bit1 copy session ID.
 * No domain, payload template, repeat ladder or candidate list is stored here. */
d2k_lower_status d2k_lower_tls_prefix(const uint8_t *,size_t,size_t,unsigned,
                                    char **text,char *err,size_t);
/* Compose the prefix with a complete, byte-preserving original partition.
 * Boundaries/order/delays are caller measurements, not compiler defaults. */
d2k_lower_status d2k_lower_tls_prefix_partition(const uint8_t *,size_t,size_t,unsigned,
    size_t,const d2k_payload_piece *,size_t,char **,char *,size_t);
/* Decode only the exact prefix form emitted above; a measured nonzero ID is
 * permitted. Canonical round trip prevents dropping extra operations. Caller
 * frees bytes. No execution or evidence claim. */
d2k_lower_status d2k_lower_tls_prefix_read(const char *,uint8_t **,size_t *,size_t *,unsigned *,char *,size_t);
/* Decode the complete canonical composite for a known original input length.
 * Caller frees both byte and piece arrays. No extra operation is discarded. */
d2k_lower_status d2k_lower_tls_prefix_partition_read(const char *,size_t,uint8_t **,
    size_t *,size_t *,unsigned *,d2k_payload_piece **,size_t *,char *,size_t);
#endif
