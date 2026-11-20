/* Linux-only static integration regression: use the daemon's real drain gate. */
#define main d2kd_program_main
#include "d2kd.c"
#undef main
int main(void) {
    postnat_context c = {0};
    postnat_side *s = &c.side[0];
    s->used = 1; s->ready_at = 200; s->wait_scheduler = 1;
    c.now = 300;
    c.drained_at = 100;
    postnat_finish_ready(&c, s);
    if (!s->used) {
        fprintf(stderr, "postnat tail released beyond scheduler drain watermark\n");
        return 1;
    }
    c.drained_at = 200;
    postnat_finish_ready(&c, s);
    if (s->used) return 1;
    puts("postnat daemon: scheduler watermark gates original completion");
    return 0;
}
