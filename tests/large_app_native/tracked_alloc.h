#ifndef WB_TEST_TRACKED_ALLOC_H
#define WB_TEST_TRACKED_ALLOC_H
#include <stddef.h>
#include <stdlib.h>
void *wb_test_malloc(size_t);
void *wb_test_calloc(size_t,size_t);
void wb_test_free(void *);
#define malloc wb_test_malloc
#define calloc wb_test_calloc
#define free wb_test_free
#endif
