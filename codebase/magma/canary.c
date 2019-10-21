#include "canary.h"
#include "monitor.h"
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h> 
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>

struct canary *magma_buf = NULL;
int magma_faulty = 0;

void magma_protect(int write)
{
	if (write == 0) {
		mprotect(magma_buf, SIZE, PROT_READ);
	} else {
		mprotect(magma_buf, SIZE, PROT_READ | PROT_WRITE);
	}
}

void magma_init(void)
{
	int fd = shm_open(NAME, O_RDWR, 0660);
	if (fd == -1) {
		fprintf(stderr, "Monitor process not running. Canaries will be disabled.\n");
		magma_buf = NULL;
	} else {
		magma_buf = (struct canary*)mmap(0, SIZE, PROT_WRITE, MAP_SHARED, fd, 0);
		close(fd);
		magma_buf[0].r += 1; // counts executions

#ifdef MAGMA_HARDEN_CANARIES
		magma_protect(0);
#endif
	}
}