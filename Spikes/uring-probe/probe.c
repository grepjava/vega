// Phase 0: which io_uring features does this kernel (and sandbox) allow?
// Raw syscalls only, so it runs without liburing installed.
#define _GNU_SOURCE
#include <errno.h>
#include <linux/io_uring.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

static int setup(unsigned entries, struct io_uring_params *p) {
    return (int)syscall(__NR_io_uring_setup, entries, p);
}

static void try_flags(const char *name, unsigned flags) {
    struct io_uring_params p; memset(&p, 0, sizeof p); p.flags = flags;
    int fd = setup(64, &p);
    if (fd >= 0) { printf("  %-34s ok\n", name); close(fd); }
    else printf("  %-34s FAIL (%s)\n", name, strerror(errno));
}

int main(void) {
    struct utsname u; uname(&u);
    printf("kernel %s\n", u.release);
    FILE *f = fopen("/proc/sys/kernel/io_uring_disabled", "r");
    if (f) { int v = -1; if (fscanf(f, "%d", &v) == 1) printf("io_uring_disabled = %d\n", v); fclose(f); }

    struct io_uring_params p; memset(&p, 0, sizeof p);
    int fd = setup(64, &p);
    if (fd < 0) { printf("io_uring_setup: FAIL (%s) -> Vega must fall back to epoll\n", strerror(errno)); return 1; }
    printf("io_uring_setup ok, features=0x%x\n", p.features);
    printf("  NODROP %d  FAST_POLL %d  EXT_ARG %d  NATIVE_WORKERS %d  RECVSEND_BUNDLE %d\n",
           !!(p.features & IORING_FEAT_NODROP), !!(p.features & IORING_FEAT_FAST_POLL),
           !!(p.features & IORING_FEAT_EXT_ARG), !!(p.features & IORING_FEAT_NATIVE_WORKERS),
#ifdef IORING_FEAT_RECVSEND_BUNDLE
           !!(p.features & IORING_FEAT_RECVSEND_BUNDLE)
#else
           -1
#endif
    );

    // Opcode support via IORING_REGISTER_PROBE.
    char buf[sizeof(struct io_uring_probe) + 256 * sizeof(struct io_uring_probe_op)];
    memset(buf, 0, sizeof buf);
    struct io_uring_probe *pr = (struct io_uring_probe *)buf;
    if (syscall(__NR_io_uring_register, fd, IORING_REGISTER_PROBE, pr, 256) == 0) {
        struct { int op; const char *name; } ops[] = {
            {IORING_OP_ACCEPT, "ACCEPT"}, {IORING_OP_RECV, "RECV"}, {IORING_OP_SEND, "SEND"},
            {IORING_OP_SEND_ZC, "SEND_ZC"}, {IORING_OP_MSG_RING, "MSG_RING"},
            {IORING_OP_ASYNC_CANCEL, "ASYNC_CANCEL"}, {IORING_OP_LINK_TIMEOUT, "LINK_TIMEOUT"},
            {IORING_OP_RECVMSG, "RECVMSG"}, {IORING_OP_SENDMSG_ZC, "SENDMSG_ZC"},
            {IORING_OP_CONNECT, "CONNECT"}, {IORING_OP_SPLICE, "SPLICE"}, {IORING_OP_FUTEX_WAIT, "FUTEX_WAIT"},
        };
        printf("opcodes (last_op=%d):", pr->last_op);
        for (unsigned i = 0; i < sizeof ops / sizeof ops[0]; i++) {
            int sup = ops[i].op <= pr->last_op && (pr->ops[ops[i].op].flags & IO_URING_OP_SUPPORTED);
            printf(" %s=%s", ops[i].name, sup ? "y" : "n");
        }
        printf("\n");
    } else printf("REGISTER_PROBE: FAIL (%s)\n", strerror(errno));
    close(fd);

    printf("setup flags Vega wants:\n");
    try_flags("SINGLE_ISSUER|DEFER_TASKRUN", IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN);
    try_flags("COOP_TASKRUN|TASKRUN_FLAG", IORING_SETUP_COOP_TASKRUN | IORING_SETUP_TASKRUN_FLAG);
    try_flags("SUBMIT_ALL", IORING_SETUP_SUBMIT_ALL);
    try_flags("CQSIZE", IORING_SETUP_CQSIZE);
    try_flags("SQPOLL", IORING_SETUP_SQPOLL);
#ifdef IORING_SETUP_NO_SQARRAY
    try_flags("NO_SQARRAY", IORING_SETUP_NO_SQARRAY);
#endif
    return 0;
}
