#ifndef D2KM_TEST_H
#define D2KM_TEST_H
#include <stdio.h>
#include <stdlib.h>
static int test_failures;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #c); test_failures++; } } while (0)
#define DONE(name) do { if (test_failures) { fprintf(stderr, "%s: %d провалов\n", name, test_failures); return 1; } printf("%s: ok\n", name); return 0; } while (0)
#endif
