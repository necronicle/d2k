/* Compile the production parser with the executor-17 capability ceiling.
 * The wire schema and rejection path are unchanged. No runtime override. */
#include "d2k_plan.h"
#undef D2K_EXEC_VERSION
#define D2K_EXEC_VERSION 17
#include "plan_parse.c"
