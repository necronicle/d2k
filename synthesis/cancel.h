#ifndef D2K_INFERENCE_CANCEL_H
#define D2K_INFERENCE_CANCEL_H
typedef struct { int (*cancelled)(void *); void *context; } d2k_inference_control;
static inline int d2k_inference_stopped(const d2k_inference_control *c) {
    return c && c->cancelled && c->cancelled(c->context);
}
#endif
