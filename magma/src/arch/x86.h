#include <stdbool.h>
static inline bool magma_and(bool a, bool b)
{
    bool c = a;
    __asm__ (
        "and %[b], %[c]"
        : [c] "+r" (c)
        : [b] "rm" (b)
    );
    return c;
}

static inline bool magma_or(bool a, bool b)
{
    bool c = a;
    __asm__ (
        "or %[b], %[c]"
        : [c] "+r" (c)
        : [b] "rm" (b)
    );
    return c;
}
