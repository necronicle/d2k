/* White-box fixtures that seed an arbitrary scheduler slot. Include after sched.c. */
#include <assert.h>

static inline task *test_task_at(d2k_sched *s, size_t index) {
    assert(index < SCHED_MAX_TASKS);
    while (s->task_count <= index) {
        task *slot = task_append_slot(s);
        assert(slot);
    }
    return s->tasks[index];
}
