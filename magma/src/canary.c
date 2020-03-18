#ifdef __cplusplus
extern "C" {
#endif

#include "canary.h"
#include "common.h"
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>

static pstored_data_t data_ptr = NULL;
static int magma_faulty = 0;

static void magma_protect(int write)
{
    if (write == 0) {
        mprotect(data_ptr, FILESIZE, PROT_READ);
    } else {
        mprotect(data_ptr, FILESIZE, PROT_READ | PROT_WRITE);
    }
}

static bool magma_init(void)
{
    static bool init_called = false;
    if (init_called) {
        // if init is called more than once, then the first call failed, so
        // we assume every following call will fail.
        return false;
    }
    init_called = true;
    const char *file = getenv("MAGMA_STORAGE");
    if (file == NULL) {
        file = NAME;
    }
    int fd = open(file, O_RDWR);
    if (fd == -1) {
        fprintf(stderr, "Monitor not running. Canaries will be disabled.\n");
        data_ptr = NULL;
        return false;
    } else {
        data_ptr = mmap(0, FILESIZE, PROT_WRITE, MAP_SHARED, fd, 0);
        close(fd);

#ifdef MAGMA_HARDEN_CANARIES
        magma_protect(0);
#endif
        return true;
    }
}

void magma_log(const char *bug, int condition)
{
#ifndef MAGMA_DISABLE_CANARIES
    if (!data_ptr && !magma_init()) {
        goto fatal;
    }

#ifdef MAGMA_HARDEN_CANARIES
    magma_protect(1);
#endif

    pcanary_t prod_canary   = stor_get(data_ptr->producer_buffer, bug);
    prod_canary->reached   += 1         & (magma_faulty ^ 1);
    prod_canary->triggered += (bool)condition & (magma_faulty ^ 1);
    if (data_ptr->consumed) {
        memcpy(data_ptr->consumer_buffer, data_ptr->producer_buffer, sizeof(data_t));
        // memory barrier
        __sync_synchronize();
        data_ptr->consumed = false;
    }

    magma_faulty = magma_faulty | (bool)condition;

#ifdef MAGMA_HARDEN_CANARIES
    magma_protect(0);
#endif

fatal: (void)0;
#ifdef MAGMA_FATAL_CANARIES
    // send SIGSEGV to self
    static pid_t pid = 0;
    if (pid == 0) {
        pid = getpid();
    }
    kill(pid, ((bool)condition)*11);
#endif
#endif
    return;
}

#ifdef __cplusplus
}
#endif