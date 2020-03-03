#include "storage.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

pcanary_t stor_get(data_t buffer, const char *name)
{
    pcanary_t cur;
    size_t i;
    for (i = 0, cur = buffer; \
        i < BUFFERLEN && *cur->name != '\0'; \
        ++i, ++cur) {
        if (strncmp(name, cur->name, sizeof(cur->name)) == 0) {
            return cur;
        }
    }

    // Bug record does not exist, create it
    strncpy(cur->name, name, sizeof(cur->name));
    cur->reached = 0;
    cur->triggered = 0;
    return cur;
}

bool stor_put(data_t buffer, const char *name, const pcanary_t value)
{
    pcanary_t cur;
    size_t i;
    for (i = 0, cur = buffer; \
            i < BUFFERLEN && *cur->name != '\0'; \
            ++i, ++cur) {
        if (strncmp(name, cur->name, sizeof(cur->name)) == 0) {
            break;
        }
    }
    if (i >= BUFFERLEN) {
        return false;
    }
    memcpy(cur, value, sizeof(canary_t));
    return true;
}

size_t stor_forall(data_t buffer, void * (* func)(pcanary_t,void *), \
    void *arg, void **results, size_t length)
{
    pcanary_t cur;
    size_t i;
    for (i = 0, cur = buffer; \
            i < BUFFERLEN && *cur->name != '\0'; \
            ++i, ++cur) {
        if (results == NULL) {
            func(cur, arg);
        } else if (i < length) {
            results[i] = func(cur, arg);
        } else {
            break;
        }
    }
    return i;
}
