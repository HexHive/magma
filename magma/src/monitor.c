#define _POSIX_C_SOURCE 200112L
#define _GNU_SOURCE

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
#include <strings.h>

#include <sys/wait.h>
#include <linux/limits.h>

/**
 * Argument parsing infrastructure
 */
struct arg_definition {
    char *name; // string identifier in the list of program arguments
    bool flag; // if true, the argument does not expect a subsequent parameter
    char *dflt; // the default parameter value (if not present in the arg list)
    char *help;
};

struct arg_item {
    const struct arg_definition *def;
    char *value;
    void *args;
};

enum ARG_NUMS {
    ARG_DUMP = 0,
    ARG_FETCH,
    ARG_HELP,

    ARG_COUNT
};

const struct arg_definition ARG_LIST[] = {
    {"--dump", false, "raw", "The format to use when dumping canary structs:\n"
                             "- raw: dumps the raw bytes\n"
                             "- row: writes a CSV-style header and data row\n"
                             "- human: writes a human-readable output"},
    {"--fetch", false, "file", "The source from which to fetch canary data:\n"
                               "- file: reads data from FILE\n"
                               "- watch: runs COMMAND and collects data"},
    {"--help", true, NULL, "Prints this help message"}
};

const char USAGE[] = "monitor [--dump {raw|row|human}] [--fetch {file|watch}] FILE|COMMAND";

// TODO replace this by calls to getopt()

struct arg_item *parse_args(int *argc, char ***argv)
{
    struct arg_node {
        struct arg_item item;
        struct arg_node *next;
    };
    int i, count = 0;
    struct arg_node *cur, *head = NULL;
    for (i = 1; i < *argc; ++i) {
        char *keyword = (*argv)[i];
        int j;
        for (j = 0; j < sizeof(ARG_LIST) / sizeof(*ARG_LIST); ++j) {
            if (strcmp(keyword, ARG_LIST[j].name)) {
                continue;
            }
            cur = calloc(1, sizeof(struct arg_node));
            cur->item.def = &ARG_LIST[j];
            if (!cur->item.def->flag) {
                cur->item.value = (*argv)[++i];
            }
            break;
        }
        if (j == sizeof(ARG_LIST) / sizeof(*ARG_LIST)) {
            break; // this assumes that either FILE or COMMAND will follow
        } else {
            cur->next = head;
            head = cur;
            ++count;
        }
    }
    // Decrement `i` since we start with 1
    // --i;
    *argc -= i;
    *argv += i;

    struct arg_item *retarr = malloc(count * sizeof(struct arg_item) + 1);
    for (i = count - 1; i >= 0; --i) {
        memcpy(&retarr[i], &head->item, sizeof(struct arg_item));
        cur = head->next;
        free(head);
        head = cur;
    }
    retarr[count].def = NULL;
    return retarr;
}

void print_help()
{
    puts(USAGE);
    puts("");
    for (int i = 0; i < sizeof(ARG_LIST) / sizeof(*ARG_LIST); ++i) {
        puts(ARG_LIST[i].name);
        puts("");
        puts(ARG_LIST[i].help);
        puts("");
    }
}

void dump_raw(const data_t *data)
{
    fwrite(*data, sizeof(canary_t), sizeof(data_t)/sizeof(canary_t), stdout);
}

void dump_row(const data_t *data)
{
    int bugs = sizeof(data_t) / sizeof(canary_t);
    for (int i = 0; i < bugs; ++i) {
        fprintf(stdout, "%1$03d_R,%1$03d_T", i);
        if (i < bugs - 1) {
            putc(',', stdout);
        }
    }
    putc('\n', stdout);

    for (int i = 0; i < bugs; ++i) {
        int len = fprintf(stdout, "%llu,%llu", \
            (*data)[i].reached, (*data)[i].triggered);
        if (i < bugs - 1) {
            putc(',', stdout);
        }
    }
    putc('\n', stdout);
}

void dump_human(const data_t *data)
{
    int bugs = sizeof(data_t) / sizeof(canary_t);
    for (int i = 0; i < bugs; ++i) {
        printf("B%03d reached %llu triggered %llu\n", \
            i, (*data)[i].reached, (*data)[i].triggered);
    }
}

bool fetch_file(data_t *data, const char *fname)
{
    bool success = true;
    pshared_data_t data_ptr;
    int fd = open(fname, O_RDWR);
    if (fd == -1) {
        fd = open(fname, O_CREAT | O_RDWR, 0666);
        if (ftruncate(fd, SIZE) != 0) {
            success = false;
            goto exit;
        }

        data_ptr = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        memset(data_ptr, 0, SIZE);
    } else {
        data_ptr = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    }

    /* Since the file may be updated by a live producer, we follow protocol*/
    if (!data_ptr->consumed) {
        memcpy(*data, data_ptr->consumer_buffer, sizeof(data_t));
        __sync_synchronize();
        data_ptr->consumed = true;
    } else {
        success = false;
        goto exit;
    }
exit:
    munmap(data_ptr, SIZE);
    close(fd);
    return success;
}

bool fetch_watch(data_t *data, int *status, int argc, char **argv)
{
    bool success = true;
    char fname[PATH_MAX];
    getcwd(fname, sizeof(fname));
    strcat(strcat(fname, "/"), "monitor_XXXXXX");
    int fd = mkstemp(fname);
    if (ftruncate(fd, SIZE) != 0) {
        success = false;
        goto exit;
    }

    if (fork() == 0) {
        char envname[] = "MAGMA_STORAGE";
        int envsz = strlen(envname) + 1 + strlen(fname) + 1;
        char *envvar = malloc(envsz);
        snprintf(envvar, envsz, "%s=%s", envname, fname);
        putenv(envvar);
        exit(execve(argv[0], argv, environ));
    }
    wait(status);

    pshared_data_t data_ptr;
    data_ptr = mmap(0, SIZE, PROT_READ, MAP_SHARED, fd, 0);

    /* Since the producer is dead, we can fetch its buffer directly */
    memcpy(*data, data_ptr->producer_buffer, sizeof(data_t));

exit:
    unlink(fname);
    return success;
}

int main(int argc, char **argv)
{
    int err = 0;
    struct arg_item *args = parse_args(&argc, &argv), *tmp;
    for (tmp = args; tmp->def != NULL; ++tmp) {
        if (tmp->def == &ARG_LIST[ARG_HELP]) {
            print_help();
            goto exit;
        }
    }

    struct arg_item *dump_itm = NULL, *fetch_itm = NULL;
    for (tmp = args; tmp->def != NULL; ++tmp) {
        if (tmp->def == &ARG_LIST[ARG_DUMP]) {
            dump_itm = tmp;
        } else if (tmp->def == &ARG_LIST[ARG_FETCH]) {
            fetch_itm = tmp;
        }
    }

    data_t data;
    if (fetch_itm == NULL || \
            strcmp(fetch_itm->value, fetch_itm->def->dflt) == 0) {
        const char *fname = NAME;
        if (argc > 0) {
            fname = argv[0];
        }
        if (!fetch_file(&data, fname)) {
            err = 1;
            goto exit;
        }
    } else if (strcmp(fetch_itm->value, "watch") == 0) {
        if (argc == 0) {
            fputs("Error: No command specified", stderr);
            err = 2;
            goto exit;
        }
        int status;
        if (!fetch_watch(&data, &status, argc, argv)) {
            err = 3;
            goto exit;
        }
        if (WIFEXITED(status)) {
            err = WEXITSTATUS(status);
        }
    } else {
        fputs("Error: Invalid fetch method", stderr);
        err = 4;
        goto exit;
    }

    if (dump_itm == NULL || \
            strcmp(dump_itm->value, dump_itm->def->dflt) == 0) {
        dump_raw(&data);
    } else if (strcmp(dump_itm->value, "row") == 0) {
        dump_row(&data);
    } else if (strcmp(dump_itm->value, "human") == 0) {
        dump_human(&data);
    } else {
        fputs("Error: Invalid dump method", stderr);
        err = 5;
        goto exit;
    }

exit:
    free(args);
    return err;
}