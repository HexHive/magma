#define _POSIX_C_SOURCE 200112L

#include "canary.h"
#include "common.h"
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>

static pshared_data_t data_ptr = NULL;

int main(int argc, char **argv)
{
    if (argc > 1) {
        unlink(NAME);
        return 0;
    }

    int fd = open(NAME, O_RDWR);
    if (fd == -1) {
        fd = open(NAME, O_CREAT | O_RDWR, 0666);
        if (ftruncate(fd, SIZE) != 0)
            return 1;

        data_ptr = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        memset(data_ptr, 0, SIZE);
    } else {
        data_ptr = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    }

    if (!data_ptr->consumed) {
        fwrite(data_ptr->consumer_buffer, sizeof(canary_t), \
            sizeof(data_t)/sizeof(canary_t), stdout);
        __sync_synchronize();
        data_ptr->consumed = true;
    } else {
        return 1;
    }

    return 0;
}