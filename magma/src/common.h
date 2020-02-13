#include <stddef.h>
#include <stdbool.h>

static const char NAME[] = MAGMA_STORAGE; // compile-time constant -DMAGMA_STORAGE
#define SIZE 2048

typedef enum {
    REACHED = 0,
    TRIGGERED,
    CANARY_TYPE_COUNT
} canary_type_e;
typedef unsigned long long canary_storage_t;

typedef union {
    struct {
        canary_storage_t reached;
        canary_storage_t triggered;
    };
    canary_storage_t raw[CANARY_TYPE_COUNT];
} canary_t;

// The `2` in the denominator is for splitting the region between producer and
// consumer buffers. It has nothing to do with CANARY_TYPE_COUNT.
typedef canary_t data_t[(SIZE-sizeof(max_align_t))/sizeof(canary_t)/2];
typedef struct {
    bool consumed;
    data_t producer_buffer;
    data_t consumer_buffer;
} shared_data_t, *pshared_data_t;