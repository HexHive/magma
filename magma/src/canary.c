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

static pshared_data_t data_ptr = NULL;
static int magma_faulty = 0;

static void magma_protect(int write)
{
	if (write == 0) {
		mprotect(data_ptr, SIZE, PROT_READ);
	} else {
		mprotect(data_ptr, SIZE, PROT_READ | PROT_WRITE);
	}
}

static bool magma_update(int bug, canary_type_e type, int delta)
{
    // update the producer buffer
    // this should be up-to-date regardless if there is a slot in the bufer
    data_ptr->producer_buffer[bug].raw[type] += delta;
    if (data_ptr->consumed) {
        // TODO find a way to update consumer buffer without full copy (deltas?)
        memcpy(data_ptr->consumer_buffer, data_ptr->producer_buffer, sizeof(data_t));
        // memory barrier
        __sync_synchronize();
        data_ptr->consumed = false;
        return true;
    }
    return false;
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
	int fd = open(NAME, O_RDWR);
	if (fd == -1) {
		fprintf(stderr, "Monitor not running. Canaries will be disabled.\n");
		data_ptr = NULL;
        return false;
	} else {
		data_ptr = (pshared_data_t)mmap(0, SIZE, PROT_WRITE, MAP_SHARED, fd, 0);
		close(fd);
        magma_update(0, REACHED, 1); // counts executions

#ifdef MAGMA_HARDEN_CANARIES
		magma_protect(0);
#endif
        return true;
	}
}

void magma_log(int bug, int condition)
{
#ifndef MAGMA_DISABLE_CANARIES
    if (!data_ptr && !magma_init()) {
        goto fatal;
    }

#ifdef MAGMA_HARDEN_CANARIES
    magma_protect(1);
#endif

    magma_update(bug, REACHED,           1 & (magma_faulty ^ 1));
    magma_update(bug, TRIGGERED, condition & (magma_faulty ^ 1));
    magma_faulty = magma_faulty | condition;

#ifdef MAGMA_HARDEN_CANARIES
    magma_protect(0);
#endif

fatal: (void)0;
#ifdef MAGMA_FATAL_CANARIES
    // send SIGSEGV to self
    kill(getpid(), (condition)*11);
#endif
#endif
    return;
}

#ifdef __cplusplus
}
#endif