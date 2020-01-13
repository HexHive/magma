#ifdef __cplusplus
extern "C" {
#endif

struct canary {
    int r;
    int t;
};

extern void magma_init(void);
extern void magma_protect(int);

extern struct canary *magma_buf;
extern int magma_faulty;

static inline __attribute__ ((always_inline))
void magma_log(int bug, int condition)
{
#ifdef __cplusplus
    if (!magma_buf) {
#else
    if (magma_buf == (void *)0) {
#endif
        goto fatal;
    }

#ifdef MAGMA_HARDEN_CANARIES
    magma_protect(1);
#endif

    magma_buf[bug].r += 1 & (magma_faulty ^ 1);
    magma_buf[bug].t += condition & (magma_faulty ^ 1);
    magma_faulty = magma_faulty | condition;

#ifdef MAGMA_HARDEN_CANARIES
    magma_protect(0);
#endif

fatal: (void)0;
#ifdef MAGMA_FATAL_CANARIES
#ifdef __cplusplus
    #define __THROW throw()
#else
    #define __THROW
#endif

    extern int getpid(void) __THROW;
    extern int kill(int, int) __THROW;

    // send SIGSEGV to self
    kill(getpid(), (condition)*11);
#endif
    return;
}

#ifdef __cplusplus
}
#endif
