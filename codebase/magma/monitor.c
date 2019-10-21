#include "monitor.h"
#include "canary.h"
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h> 
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>

static struct canary *sto;

int main(int argc, char **argv)
{
	if (argc > 1) {
		shm_unlink(NAME);
		return 0;
	}

	int fd = shm_open(NAME, O_RDONLY, 0660);
	if (fd == -1) {
		printf("Creating memory object.\n");
		fd = shm_open(NAME, O_CREAT | O_RDWR, 0660);
		ftruncate(fd, SIZE);
		
		sto = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		memset(sto, 0, SIZE);
	} else {
		sto = mmap(0, SIZE, PROT_READ, MAP_SHARED, fd, 0);
	}

	for (int i = 0; i < SIZE / (sizeof(int) * 2); ++i) {
		printf("Bug %d: R %d T %d\n", i, sto[i].r, sto[i].t);
	}
	return 0;
}