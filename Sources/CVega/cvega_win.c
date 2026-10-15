// Sockets on Windows: the cv_* socket API of cvega.c over Winsock. Sockets
// are non-blocking and not inherited by child processes; failures come back
// as errno values (WSAEWOULDBLOCK as EAGAIN), as the POSIX code returns them.
#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <afunix.h>
#include <mstcpip.h>
#include <mswsock.h>
#include <iphlpapi.h>
#include <winioctl.h>
#include <windows.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cvega.h"

static BOOL CALLBACK wsa_start(PINIT_ONCE once, PVOID param, PVOID *ctx) {
    (void)once, (void)param, (void)ctx;
    WSADATA data;
    return WSAStartup(MAKEWORD(2, 2), &data) == 0;
}

static void wsa_init(void) {
    static INIT_ONCE once = INIT_ONCE_STATIC_INIT;
    InitOnceExecuteOnce(&once, wsa_start, NULL, NULL);
}

/// A Winsock error as the errno value the POSIX code would report.
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif

static int map_error(int e) {
    switch (e) {
    case WSAEWOULDBLOCK: return EAGAIN;
    case WSAEINPROGRESS: case WSAEALREADY: return EALREADY;
    case WSAEINTR: return EINTR;
    case WSAECONNRESET: return ECONNRESET;
    case WSAECONNABORTED: return ECONNABORTED;
    case WSAECONNREFUSED: return ECONNREFUSED;
    case WSAEADDRINUSE: return EADDRINUSE;
    case WSAEADDRNOTAVAIL: return EADDRNOTAVAIL;
    case WSAENETDOWN: return ENETDOWN;
    case WSAENETUNREACH: return ENETUNREACH;
    case WSAENETRESET: return ENETRESET;
    case WSAEHOSTUNREACH: case WSAEHOSTDOWN: return EHOSTUNREACH;
    case WSAETIMEDOUT: return ETIMEDOUT;
    case WSAENOTCONN: return ENOTCONN;
    case WSAEISCONN: return EISCONN;
    case WSAESHUTDOWN: return EPIPE;
    case WSAEMSGSIZE: return EMSGSIZE;
    case WSAENOBUFS: return ENOBUFS;
    case WSAEMFILE: return EMFILE;
    case WSAEACCES: return EACCES;
    case WSAEINVAL: return EINVAL;
    case WSAEFAULT: return EFAULT;
    case WSAEAFNOSUPPORT: case WSAEPFNOSUPPORT: return EAFNOSUPPORT;
    case WSAENOPROTOOPT: return ENOPROTOOPT;
    case WSAEPROTONOSUPPORT: return EPROTONOSUPPORT;
    case WSAEOPNOTSUPP: return EOPNOTSUPP;
    case WSAENOTSOCK: return ENOTSOCK;
    case WSAEDESTADDRREQ: return EDESTADDRREQ;
    case WSAENAMETOOLONG: return ENAMETOOLONG;
    case WSAHOST_NOT_FOUND: case WSANO_DATA: return EADDRNOTAVAIL;
    case 0: return 0;
    default: return EIO;
    }
}

static int last_error(void) { return map_error(WSAGetLastError()); }

/// A SOCKET in the int the API passes around. Kernel handles fit in 32
/// bits (Windows keeps them so for 32-bit interop).
static int as_fd(SOCKET s) { return s == INVALID_SOCKET ? -1 : (int)(intptr_t)s; }
static SOCKET as_socket(int fd) { return (SOCKET)(intptr_t)fd; }

static int prepare(SOCKET s) {
    u_long on = 1;
    if (ioctlsocket(s, FIONBIO, &on) != 0) return last_error();
    SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0);
    return 0;
}

static SOCKET new_socket(int family, int type, int *err) {
    wsa_init();
    SOCKET s = WSASocketW(family, type, family == AF_UNIX ? 0 : (type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP),
                          NULL, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
    if (s == INVALID_SOCKET) {
        *err = last_error();
        return INVALID_SOCKET;
    }
    int e = prepare(s);
    if (e) {
        closesocket(s);
        *err = e;
        return INVALID_SOCKET;
    }
    return s;
}

void cv_close_socket(int fd) {
    // Pipe ends come here too (an adopted one that failed to register).
    if (closesocket(as_socket(fd)) != 0 && WSAGetLastError() == WSAENOTSOCK) CloseHandle((HANDLE)(intptr_t)fd);
}

static struct addrinfo *resolve(const char *host, int port, int passive, int type, int *err) {
    wsa_init();
    char service[8];
    snprintf(service, sizeof service, "%d", port);
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = type;
    hints.ai_flags = AI_NUMERICSERV | (passive ? AI_PASSIVE : 0);
    if (getaddrinfo(host && *host ? host : NULL, service, &hints, &res) != 0) {
        *err = EADDRNOTAVAIL;
        return NULL;
    }
    return res;
}

int cv_tcp_listen(const char *host, int port, int backlog, int reuse_port, int *err) {
    (void)reuse_port; // no SO_REUSEPORT; Windows' SO_REUSEADDR would let others steal the port
    struct addrinfo *res = resolve(host, port, 1, SOCK_STREAM, err);
    if (!res) return -1;
    SOCKET s = INVALID_SOCKET;
    *err = EADDRNOTAVAIL;
    for (struct addrinfo *a = res; a; a = a->ai_next) {
        s = new_socket(a->ai_family, SOCK_STREAM, err);
        if (s == INVALID_SOCKET) continue;
        if (bind(s, a->ai_addr, (int)a->ai_addrlen) == 0 && (backlog < 0 || listen(s, backlog) == 0)) {
            *err = 0;
            break;
        }
        *err = last_error();
        closesocket(s);
        s = INVALID_SOCKET;
    }
    freeaddrinfo(res);
    return as_fd(s);
}

int cv_connect_new(const cv_sockaddr *addr, int type, int *err) {
    const struct sockaddr *sa = (const struct sockaddr *)addr->storage;
    SOCKET s = new_socket(sa->sa_family, type, err);
    if (s == INVALID_SOCKET) return -1;
    if (type == SOCK_STREAM && sa->sa_family != AF_UNIX) {
        BOOL one = TRUE;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
    }
    if (connect(s, sa, (int)addr->len) == 0) {
        *err = 0;
        return as_fd(s);
    }
    int e = WSAGetLastError();
    if (e == WSAEWOULDBLOCK) {
        *err = EINPROGRESS; // as POSIX says it: wait for writability
        return as_fd(s);
    }
    *err = map_error(e);
    closesocket(s);
    return -1;
}

static int accept_nb(int fd, int *err) {
    SOCKET c = accept(as_socket(fd), NULL, NULL);
    if (c == INVALID_SOCKET) {
        *err = last_error();
        return -1;
    }
    int e = prepare(c);
    if (e) {
        closesocket(c);
        *err = e;
        return -1;
    }
    return as_fd(c);
}

int cv_tcp_accept(int fd, int *err) {
    int c = accept_nb(fd, err);
    if (c < 0) return -1;
    BOOL one = TRUE;
    setsockopt(as_socket(c), IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
    return c;
}

void cv_tcp_accepted(int fd) {
    BOOL one = TRUE;
    setsockopt(as_socket(fd), IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
}

int cv_socket_error(int fd) {
    int e = 0;
    int len = sizeof e;
    if (getsockopt(as_socket(fd), SOL_SOCKET, SO_ERROR, (char *)&e, &len) != 0) return last_error();
    return map_error(e);
}

int cv_shutdown_write(int fd) {
    return shutdown(as_socket(fd), SD_SEND) == 0 ? 0 : last_error();
}

int cv_resolve_all(const char *host, int port, int numeric_only, cv_sockaddr *out, int max,
                   int *count) {
    wsa_init();
    char service[8];
    snprintf(service, sizeof service, "%d", port);
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV | (numeric_only ? AI_NUMERICHOST : 0);
    *count = 0;
    int rc = getaddrinfo(host && *host ? host : NULL, service, &hints, &res);
    if (rc != 0) {
        if (numeric_only && (rc == EAI_NONAME || rc == WSAHOST_NOT_FOUND)) return -1;
        return EADDRNOTAVAIL;
    }
    for (struct addrinfo *a = res; a && *count < max; a = a->ai_next) {
        if (a->ai_addrlen > sizeof out->storage) continue;
        memcpy(out[*count].storage, a->ai_addr, a->ai_addrlen);
        out[*count].len = (uint32_t)a->ai_addrlen;
        ++*count;
    }
    freeaddrinfo(res);
    return *count > 0 ? 0 : EADDRNOTAVAIL;
}

int cv_sockaddr_family(const cv_sockaddr *a) { return ((const struct sockaddr *)a->storage)->sa_family; }

int cv_sockaddr_port(const cv_sockaddr *a) {
    const struct sockaddr *sa = (const struct sockaddr *)a->storage;
    if (sa->sa_family == AF_INET) return ntohs(((const struct sockaddr_in *)sa)->sin_port);
    if (sa->sa_family == AF_INET6) return ntohs(((const struct sockaddr_in6 *)sa)->sin6_port);
    return -1;
}

int cv_sockaddr_host(const cv_sockaddr *a, char *buf, int buflen) {
    const struct sockaddr *sa = (const struct sockaddr *)a->storage;
    const void *src = sa->sa_family == AF_INET ? (const void *)&((const struct sockaddr_in *)sa)->sin_addr
                    : sa->sa_family == AF_INET6 ? (const void *)&((const struct sockaddr_in6 *)sa)->sin6_addr
                    : NULL;
    if (!src || !inet_ntop(sa->sa_family, src, buf, (size_t)buflen)) return -1;
    return 0;
}

int cv_sockaddr_ip(cv_sockaddr *out, const uint8_t *ip, int len, int port) {
    memset(out, 0, sizeof *out);
    if (len == 4) {
        struct sockaddr_in *sa = (struct sockaddr_in *)out->storage;
        sa->sin_family = AF_INET;
        sa->sin_port = htons((uint16_t)port);
        memcpy(&sa->sin_addr, ip, 4);
        out->len = sizeof *sa;
        return 0;
    }
    if (len == 16) {
        struct sockaddr_in6 *sa = (struct sockaddr_in6 *)out->storage;
        sa->sin6_family = AF_INET6;
        sa->sin6_port = htons((uint16_t)port);
        memcpy(&sa->sin6_addr, ip, 16);
        out->len = sizeof *sa;
        return 0;
    }
    return -1;
}

int cv_sockaddr_ip_bytes(const cv_sockaddr *a, uint8_t *ip) {
    const struct sockaddr *sa = (const struct sockaddr *)a->storage;
    if (sa->sa_family == AF_INET) {
        memcpy(ip, &((const struct sockaddr_in *)sa)->sin_addr, 4);
        return 4;
    }
    if (sa->sa_family == AF_INET6) {
        memcpy(ip, &((const struct sockaddr_in6 *)sa)->sin6_addr, 16);
        return 16;
    }
    return -1;
}

int cv_local_address(int fd, cv_sockaddr *out) {
    int len = sizeof out->storage;
    if (getsockname(as_socket(fd), (struct sockaddr *)out->storage, &len) != 0) return last_error();
    out->len = (uint32_t)len;
    return 0;
}

int cv_peer_address(int fd, cv_sockaddr *out) {
    int len = sizeof out->storage;
    if (getpeername(as_socket(fd), (struct sockaddr *)out->storage, &len) != 0) return last_error();
    out->len = (uint32_t)len;
    return 0;
}

int cv_input_waiting(int fd) {
    WSAPOLLFD p = {.fd = as_socket(fd), .events = POLLRDNORM};
    return WSAPoll(&p, 1, 0) > 0 ? 1 : 0;
}

int cv_local_port(int fd) {
    cv_sockaddr a;
    return cv_local_address(fd, &a) == 0 ? cv_sockaddr_port(&a) : -1;
}

static int clamp_len(intptr_t len) { return len > INT_MAX ? INT_MAX : (int)len; }

intptr_t cv_recv(int fd, void *buf, intptr_t len) {
    int n = recv(as_socket(fd), buf, clamp_len(len), 0);
    return n >= 0 ? (intptr_t)n : -(intptr_t)last_error();
}

intptr_t cv_sendfile(int fd, int file, int64_t offset, intptr_t count) {
    (void)fd; (void)file; (void)offset; (void)count;
    return -ENOSYS;
}

int cv_open_beneath(const char *root, const char *relative) {
    (void)root; (void)relative;
    return -ENOSYS;
}

intptr_t cv_peek(int fd) {
    char c;
    int n = recv(as_socket(fd), &c, 1, MSG_PEEK);
    return n >= 0 ? (intptr_t)n : -(intptr_t)last_error();
}

intptr_t cv_send(int fd, const void *buf, intptr_t len) {
    int n = send(as_socket(fd), buf, clamp_len(len), 0);
    return n >= 0 ? (intptr_t)n : -(intptr_t)last_error();
}

int cv_udp_bind(const char *host, int port, int reuse_port, int *err) {
    (void)reuse_port;
    struct addrinfo *res = resolve(host, port, 1, SOCK_DGRAM, err);
    if (!res) return -1;
    SOCKET s = INVALID_SOCKET;
    *err = EADDRNOTAVAIL;
    for (struct addrinfo *a = res; a; a = a->ai_next) {
        s = new_socket(a->ai_family, SOCK_DGRAM, err);
        if (s == INVALID_SOCKET) continue;
        // Don't let an ICMP port-unreachable for an earlier send fail the
        // next recv with WSAECONNRESET (Windows' default for UDP).
        BOOL off = FALSE;
        DWORD bytes = 0;
        WSAIoctl(s, SIO_UDP_CONNRESET, &off, sizeof off, NULL, 0, &bytes, NULL, NULL);
        if (bind(s, a->ai_addr, (int)a->ai_addrlen) == 0) {
            *err = 0;
            break;
        }
        *err = last_error();
        closesocket(s);
        s = INVALID_SOCKET;
    }
    freeaddrinfo(res);
    return as_fd(s);
}

int cv_connect_address(int fd, const cv_sockaddr *a) {
    return connect(as_socket(fd), (const struct sockaddr *)a->storage, (int)a->len) == 0 ? 0 : last_error();
}

intptr_t cv_sendto(int fd, const void *buf, intptr_t len, const cv_sockaddr *to) {
    int n = sendto(as_socket(fd), buf, clamp_len(len), 0, (const struct sockaddr *)to->storage, (int)to->len);
    return n >= 0 ? (intptr_t)n : -(intptr_t)last_error();
}

intptr_t cv_recvfrom(int fd, void *buf, intptr_t len, cv_sockaddr *from) {
    int alen = sizeof from->storage;
    int n = recvfrom(as_socket(fd), buf, clamp_len(len), 0, (struct sockaddr *)from->storage, &alen);
    if (n < 0) {
        int e = WSAGetLastError();
        // A datagram longer than the buffer: Windows fails the call, but
        // fills the buffer; POSIX returns the truncated bytes.
        if (e != WSAEMSGSIZE) return -(intptr_t)map_error(e);
        n = clamp_len(len);
    }
    from->len = (uint32_t)alen;
    return (intptr_t)n;
}

// The registration the uring path makes (no ring on Windows, but the Swift
// code that would use one still links against these).
int cv_count_load(int *count) { return __atomic_load_n(count, __ATOMIC_ACQUIRE); }

cv_io *cv_uring_io_new(int fd, int *count) {
    cv_io *io = calloc(1, sizeof *io);
    if (!io) return NULL;
    io->count = count;
    __atomic_add_fetch(count, 1, __ATOMIC_RELAXED);
    io->fd = fd;
    io->refs = 1;
    return io;
}

void cv_uring_io_release(cv_io *io) {
    if (__atomic_sub_fetch(&io->refs, 1, __ATOMIC_ACQ_REL) != 0) return;
    int *count = io->count;
    if (io->fd >= 0) closesocket(as_socket(io->fd));
    free(io);
    __atomic_sub_fetch(count, 1, __ATOMIC_RELEASE);
}

// ---- system DNS configuration ---------------------------------------------

static void append(char *out, int len, int *used, const char *s) {
    int n = (int)strlen(s);
    if (*used + n + 1 > len) return;
    memcpy(out + *used, s, (size_t)n);
    *used += n;
    out[*used] = 0;
}

int cv_system_dns_config(char *out, int len) {
    if (len < 1) return -1;
    out[0] = 0;
    ULONG size = 16 * 1024;
    IP_ADAPTER_ADDRESSES *list = NULL;
    ULONG rc = ERROR_BUFFER_OVERFLOW;
    for (int tries = 0; tries < 3 && rc == ERROR_BUFFER_OVERFLOW; tries++) {
        free(list);
        list = malloc(size);
        if (!list) return -1;
        rc = GetAdaptersAddresses(AF_UNSPEC,
                                  GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                      GAA_FLAG_SKIP_FRIENDLY_NAME,
                                  NULL, list, &size);
    }
    if (rc != NO_ERROR) {
        free(list);
        return -1;
    }
    int used = 0;
    char search[1024] = "";
    int search_used = 0;
    for (IP_ADAPTER_ADDRESSES *a = list; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp || a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        for (IP_ADAPTER_DNS_SERVER_ADDRESS *d = a->FirstDnsServerAddress; d; d = d->Next) {
            const struct sockaddr *sa = d->Address.lpSockaddr;
            char host[INET6_ADDRSTRLEN] = "";
            const void *src = sa->sa_family == AF_INET ? (const void *)&((const struct sockaddr_in *)sa)->sin_addr
                            : sa->sa_family == AF_INET6 ? (const void *)&((const struct sockaddr_in6 *)sa)->sin6_addr
                            : NULL;
            if (!src || !inet_ntop(sa->sa_family, src, host, sizeof host)) continue;
            // Windows' placeholder for "ask by site-local anycast": never answers.
            if (strncmp(host, "fec0:0:0:ffff::", 15) == 0) continue;
            char line[INET6_ADDRSTRLEN + 16];
            snprintf(line, sizeof line, "nameserver %s\n", host);
            if (!strstr(out, line)) append(out, len, &used, line);
        }
        if (a->DnsSuffix && a->DnsSuffix[0]) {
            char suffix[256];
            if (WideCharToMultiByte(CP_UTF8, 0, a->DnsSuffix, -1, suffix, sizeof suffix, NULL, NULL) > 0 &&
                !strstr(search, suffix)) {
                append(search, sizeof search, &search_used, " ");
                append(search, sizeof search, &search_used, suffix);
            }
        }
    }
    free(list);
    if (search_used > 0) {
        append(out, len, &used, "search");
        append(out, len, &used, search);
        append(out, len, &used, "\n");
    }
    return used;
}

// ---- console control events as signals -----------------------------------
// Windows has no signals to catch; its console sends control events, each to
// a fresh thread running the handler. SIGINT is Ctrl-C, SIGBREAK Ctrl-Break,
// SIGTERM the console closing, the user logging off or the system shutting
// down. The handler counts the event and wakes the dispatcher.

#define CV_NSIG 32
static volatile LONG64 sig_count[CV_NSIG];
static volatile LONG sig_installed[CV_NSIG];
static HANDLE sig_wake; // a semaphore: one release per delivery
static INIT_ONCE sig_once = INIT_ONCE_STATIC_INIT;

static int ctrl_signal(DWORD type) {
    switch (type) {
    case CTRL_C_EVENT: return 2;     // SIGINT
    case CTRL_BREAK_EVENT: return 21; // SIGBREAK
    case CTRL_CLOSE_EVENT: case CTRL_LOGOFF_EVENT: case CTRL_SHUTDOWN_EVENT: return 15; // SIGTERM
    default: return 0;
    }
}

static void sig_deliver(int signo) {
    InterlockedIncrement64(&sig_count[signo]);
    ReleaseSemaphore(sig_wake, 1, NULL);
}

static BOOL WINAPI ctrl_handler(DWORD type) {
    int signo = ctrl_signal(type);
    if (!signo || !InterlockedCompareExchange(&sig_installed[signo], 0, 0)) return FALSE; // default action
    sig_deliver(signo);
    return TRUE;
}

static BOOL CALLBACK sig_setup(PINIT_ONCE once, PVOID param, PVOID *ctx) {
    (void)once, (void)param, (void)ctx;
    sig_wake = CreateSemaphoreW(NULL, 0, LONG_MAX, NULL);
    return sig_wake && SetConsoleCtrlHandler(ctrl_handler, TRUE);
}

int cv_signal_install(int signo) {
    if (signo != 2 && signo != 21 && signo != 15) return EINVAL;
    if (!InitOnceExecuteOnce(&sig_once, sig_setup, NULL, NULL)) return EIO;
    InterlockedExchange(&sig_installed[signo], 1);
    return 0;
}

uint64_t cv_signal_count(int signo) {
    return signo > 0 && signo < CV_NSIG ? (uint64_t)InterlockedCompareExchange64(&sig_count[signo], 0, 0) : 0;
}

void cv_signal_wait(void) { WaitForSingleObject(sig_wake, INFINITE); }

int cv_signal_raise(int signo) {
    // Tests: as if the console sent it, without touching the real console
    // (which would reach every process attached to it).
    if (signo <= 0 || signo >= CV_NSIG || !InterlockedCompareExchange(&sig_installed[signo], 0, 0)) return EINVAL;
    sig_deliver(signo);
    return 0;
}

// ---- files (VegaFS) -------------------------------------------------------
// Files as Win32 handles (they fit the int descriptor, as sockets do), with
// paths in UTF-8 converted to UTF-16. Errors come back as errno values.

int cv_win_errno(unsigned long e) {
    switch (e) {
    case ERROR_FILE_NOT_FOUND: case ERROR_PATH_NOT_FOUND: case ERROR_INVALID_DRIVE:
    case ERROR_BAD_NETPATH: case ERROR_BAD_PATHNAME: return ENOENT;
    case ERROR_ACCESS_DENIED: case ERROR_SHARING_VIOLATION: case ERROR_LOCK_VIOLATION:
    case ERROR_PRIVILEGE_NOT_HELD: return EACCES;
    case ERROR_FILE_EXISTS: case ERROR_ALREADY_EXISTS: return EEXIST;
    case ERROR_DIR_NOT_EMPTY: return ENOTEMPTY;
    case ERROR_DIRECTORY: return ENOTDIR;
    case ERROR_INVALID_NAME: case ERROR_INVALID_PARAMETER: return EINVAL;
    case ERROR_FILENAME_EXCED_RANGE: return ENAMETOOLONG;
    case ERROR_DISK_FULL: case ERROR_HANDLE_DISK_FULL: return ENOSPC;
    case ERROR_NOT_ENOUGH_MEMORY: case ERROR_OUTOFMEMORY: return ENOMEM;
    case ERROR_TOO_MANY_OPEN_FILES: return EMFILE;
    case ERROR_NOT_SAME_DEVICE: return EXDEV;
    case ERROR_INVALID_HANDLE: return EBADF;
    case ERROR_NOT_SUPPORTED: case ERROR_NOT_A_REPARSE_POINT: return EINVAL;
    case ERROR_NOT_READY: return EAGAIN;
    case ERROR_BROKEN_PIPE: case ERROR_NO_DATA: case ERROR_PIPE_NOT_CONNECTED: return EPIPE;
    case ERROR_BAD_EXE_FORMAT: case ERROR_EXE_MACHINE_TYPE_MISMATCH: return ENOEXEC;
    case ERROR_OPERATION_ABORTED: return ECANCELED;
    default: return EIO;
    }
}

static int map_win_error(DWORD e) { return cv_win_errno(e); }
static int last_win_error(void) { return cv_win_errno(GetLastError()); }

/// UTF-8 to a malloc'd UTF-16 string, forward slashes turned back (some
/// calls, symbolic link targets among them, take the path as written).
static wchar_t *wide(const char *s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0) return NULL;
    wchar_t *w = malloc((size_t)n * sizeof(wchar_t));
    if (!w) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    for (wchar_t *p = w; *p; p++)
        if (*p == L'/') *p = L'\\';
    return w;
}

/// UTF-16 to UTF-8 in out; the length, or -1 if it doesn't fit.
static int narrow(const wchar_t *w, int wlen, char *out, int len) {
    int n = WideCharToMultiByte(CP_UTF8, 0, w, wlen, out, len - 1, NULL, NULL);
    if (n <= 0 && wlen != 0) return -1;
    out[n] = 0;
    return n;
}

static HANDLE as_handle(int fd) { return (HANDLE)(intptr_t)fd; }

int cv_file_open(const char *path, int flags, unsigned mode, int *fd) {
    wchar_t *w = wide(path);
    if (!w) return EINVAL;
    DWORD access = 0;
    if (flags & CV_FILE_READ) access |= GENERIC_READ;
    // Appending: data goes to the end however the position moves.
    if (flags & CV_FILE_APPEND) access |= FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE;
    else if (flags & CV_FILE_WRITE) access |= GENERIC_WRITE;
    DWORD disposition;
    if (flags & CV_FILE_EXCL) disposition = CREATE_NEW;
    else if ((flags & CV_FILE_CREATE) && (flags & CV_FILE_TRUNC)) disposition = CREATE_ALWAYS;
    else if (flags & CV_FILE_CREATE) disposition = OPEN_ALWAYS;
    else if (flags & CV_FILE_TRUNC) disposition = TRUNCATE_EXISTING;
    else disposition = OPEN_EXISTING;
    // Without write permission bits, a new file is read-only.
    DWORD attrs = (mode & 0222) ? FILE_ATTRIBUTE_NORMAL : FILE_ATTRIBUTE_READONLY;
    HANDLE h = CreateFileW(w, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           disposition, attrs | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    free(w);
    if (h == INVALID_HANDLE_VALUE) return last_win_error();
    BY_HANDLE_FILE_INFORMATION info;
    if ((flags & (CV_FILE_WRITE | CV_FILE_APPEND)) && GetFileInformationByHandle(h, &info) &&
        (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        CloseHandle(h);
        return EISDIR;
    }
    *fd = (int)(intptr_t)h;
    return 0;
}

int cv_file_close(int fd) { return CloseHandle(as_handle(fd)) ? 0 : last_win_error(); }

int cv_file_dup(int fd, int *out) {
    HANDLE dup;
    if (!DuplicateHandle(GetCurrentProcess(), as_handle(fd), GetCurrentProcess(), &dup, 0, FALSE,
                         DUPLICATE_SAME_ACCESS))
        return last_win_error();
    *out = (int)(intptr_t)dup;
    return 0;
}

intptr_t cv_file_read(int fd, void *buf, intptr_t len, int64_t offset) {
    HANDLE h = as_handle(fd);
    DWORD want = len > 0x7ffff000 ? 0x7ffff000 : (DWORD)len, got = 0;
    if (offset < 0) {
        if (!ReadFile(h, buf, want, &got, NULL)) {
            DWORD e = GetLastError();
            return e == ERROR_HANDLE_EOF || e == ERROR_BROKEN_PIPE ? 0 : -(intptr_t)map_win_error(e);
        }
        return (intptr_t)got;
    }
    // At an offset, leaving the position where it was (as pread does): a
    // synchronous handle moves it to the end of what was read.
    LARGE_INTEGER zero = {0}, pos;
    if (!SetFilePointerEx(h, zero, &pos, FILE_CURRENT)) return -(intptr_t)last_win_error();
    OVERLAPPED ov = {0};
    ov.Offset = (DWORD)offset;
    ov.OffsetHigh = (DWORD)((uint64_t)offset >> 32);
    BOOL ok = ReadFile(h, buf, want, &got, &ov);
    DWORD e = ok ? 0 : GetLastError();
    SetFilePointerEx(h, pos, NULL, FILE_BEGIN);
    if (!ok) return e == ERROR_HANDLE_EOF ? 0 : -(intptr_t)map_win_error(e);
    return (intptr_t)got;
}

intptr_t cv_file_write(int fd, const void *buf, intptr_t len, int64_t offset) {
    HANDLE h = as_handle(fd);
    DWORD want = len > 0x7ffff000 ? 0x7ffff000 : (DWORD)len, done = 0;
    if (offset < 0) {
        if (!WriteFile(h, buf, want, &done, NULL)) return -(intptr_t)last_win_error();
        return (intptr_t)done;
    }
    LARGE_INTEGER zero = {0}, pos;
    if (!SetFilePointerEx(h, zero, &pos, FILE_CURRENT)) return -(intptr_t)last_win_error();
    OVERLAPPED ov = {0};
    ov.Offset = (DWORD)offset;
    ov.OffsetHigh = (DWORD)((uint64_t)offset >> 32);
    BOOL ok = WriteFile(h, buf, want, &done, &ov);
    DWORD e = ok ? 0 : GetLastError();
    SetFilePointerEx(h, pos, NULL, FILE_BEGIN);
    return ok ? (intptr_t)done : -(intptr_t)map_win_error(e);
}

int64_t cv_file_seek(int fd, int64_t offset, int whence) {
    LARGE_INTEGER d, out;
    d.QuadPart = offset;
    DWORD method = whence == 0 ? FILE_BEGIN : whence == 1 ? FILE_CURRENT : FILE_END;
    if (!SetFilePointerEx(as_handle(fd), d, &out, method)) return -(int64_t)last_win_error();
    return out.QuadPart;
}

int cv_file_sync(int fd) { return FlushFileBuffers(as_handle(fd)) ? 0 : last_win_error(); }

int cv_file_set_length(int fd, int64_t length) {
    FILE_END_OF_FILE_INFO info;
    info.EndOfFile.QuadPart = length;
    return SetFileInformationByHandle(as_handle(fd), FileEndOfFileInfo, &info, sizeof info) ? 0 : last_win_error();
}

static void file_time(FILETIME ft, int64_t *sec, int32_t *nsec) {
    // 100 ns ticks since 1601 to the Unix epoch.
    uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    int64_t since = (int64_t)(t - 116444736000000000ull);
    *sec = since / 10000000;
    *nsec = (int32_t)(since % 10000000) * 100;
    if (*nsec < 0) {
        *nsec += 1000000000;
        *sec -= 1;
    }
}

static void fill_stat(const BY_HANDLE_FILE_INFORMATION *info, int is_link, cv_file_stat *out) {
    memset(out, 0, sizeof *out);
    DWORD a = info->dwFileAttributes;
    out->kind = is_link ? CV_FILE_KIND_LINK : (a & FILE_ATTRIBUTE_DIRECTORY) ? CV_FILE_KIND_DIR : CV_FILE_KIND_FILE;
    out->size = ((uint64_t)info->nFileSizeHigh << 32) | info->nFileSizeLow;
    // Windows has one permission bit to show: read-only.
    unsigned perm = (a & FILE_ATTRIBUTE_READONLY) ? 0444 : 0666;
    if (out->kind == CV_FILE_KIND_DIR) perm |= 0111;
    out->mode = perm;
    out->nlink = info->nNumberOfLinks;
    out->device = info->dwVolumeSerialNumber;
    out->inode = ((uint64_t)info->nFileIndexHigh << 32) | info->nFileIndexLow;
    file_time(info->ftLastAccessTime, &out->atime_s, &out->atime_ns);
    file_time(info->ftLastWriteTime, &out->mtime_s, &out->mtime_ns);
    file_time(info->ftLastWriteTime, &out->ctime_s, &out->ctime_ns);
}

int cv_file_fstat(int fd, cv_file_stat *out) {
    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle(as_handle(fd), &info)) return last_win_error();
    fill_stat(&info, 0, out);
    return 0;
}

static int is_symlink_attrs(const wchar_t *w, DWORD *attrs_out) {
    WIN32_FIND_DATAW fd;
    HANDLE f = FindFirstFileW(w, &fd);
    if (f == INVALID_HANDLE_VALUE) return 0;
    FindClose(f);
    if (attrs_out) *attrs_out = fd.dwFileAttributes;
    return (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
           (fd.dwReserved0 == IO_REPARSE_TAG_SYMLINK || fd.dwReserved0 == IO_REPARSE_TAG_MOUNT_POINT);
}

int cv_file_stat_path(const char *path, int follow, cv_file_stat *out) {
    wchar_t *w = wide(path);
    if (!w) return EINVAL;
    int link = !follow && is_symlink_attrs(w, NULL);
    HANDLE h = CreateFileW(w, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | (link ? FILE_FLAG_OPEN_REPARSE_POINT : 0),
                           NULL);
    free(w);
    if (h == INVALID_HANDLE_VALUE) return last_win_error();
    BY_HANDLE_FILE_INFORMATION info;
    BOOL ok = GetFileInformationByHandle(h, &info);
    int e = ok ? 0 : last_win_error();
    CloseHandle(h);
    if (ok) fill_stat(&info, link, out);
    return e;
}

static int set_readonly(const wchar_t *w, unsigned mode) {
    DWORD a = GetFileAttributesW(w);
    if (a == INVALID_FILE_ATTRIBUTES) return last_win_error();
    DWORD next = (mode & 0222) ? (a & ~(DWORD)FILE_ATTRIBUTE_READONLY) : (a | FILE_ATTRIBUTE_READONLY);
    if (next == 0) next = FILE_ATTRIBUTE_NORMAL;
    return next == a || SetFileAttributesW(w, next) ? 0 : last_win_error();
}

int cv_fs_chmod(const char *path, unsigned mode) {
    wchar_t *w = wide(path);
    if (!w) return EINVAL;
    int e = set_readonly(w, mode);
    free(w);
    return e;
}

int cv_file_chmod(int fd, unsigned mode) {
    FILE_BASIC_INFO info;
    if (!GetFileInformationByHandleEx(as_handle(fd), FileBasicInfo, &info, sizeof info)) return last_win_error();
    DWORD a = info.FileAttributes;
    DWORD next = (mode & 0222) ? (a & ~(DWORD)FILE_ATTRIBUTE_READONLY) : (a | FILE_ATTRIBUTE_READONLY);
    if (next == a) return 0;
    info.FileAttributes = next ? next : FILE_ATTRIBUTE_NORMAL;
    return SetFileInformationByHandle(as_handle(fd), FileBasicInfo, &info, sizeof info) ? 0 : last_win_error();
}

#define PATH_OP(name, call)                                                                                    \
    int name(const char *path) {                                                                               \
        wchar_t *w = wide(path);                                                                               \
        if (!w) return EINVAL;                                                                                 \
        int e = (call) ? 0 : last_win_error();                                                                 \
        free(w);                                                                                               \
        return e;                                                                                              \
    }

PATH_OP(cv_fs_mkdir, CreateDirectoryW(w, NULL))
PATH_OP(cv_fs_rmdir, RemoveDirectoryW(w))

int cv_fs_unlink(const char *path) {
    wchar_t *w = wide(path);
    if (!w) return EINVAL;
    DWORD attrs = 0;
    int e = 0;
    // A link to a directory is removed as a directory; a read-only file
    // can't be deleted until it isn't.
    if (is_symlink_attrs(w, &attrs) && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        if (!RemoveDirectoryW(w)) e = last_win_error();
    } else if (!DeleteFileW(w)) {
        e = last_win_error();
        if (e == EACCES && set_readonly(w, 0666) == 0) e = DeleteFileW(w) ? 0 : last_win_error();
        else if (e == EACCES && (GetFileAttributesW(w) & FILE_ATTRIBUTE_DIRECTORY)) e = EISDIR;
    }
    free(w);
    return e;
}

int cv_fs_rename(const char *from, const char *to) {
    wchar_t *a = wide(from), *b = wide(to);
    int e = a && b ? (MoveFileExW(a, b, MOVEFILE_REPLACE_EXISTING) ? 0 : last_win_error()) : EINVAL;
    free(a);
    free(b);
    return e;
}

int cv_fs_link(const char *existing, const char *link) {
    wchar_t *a = wide(existing), *b = wide(link);
    int e = a && b ? (CreateHardLinkW(b, a, NULL) ? 0 : last_win_error()) : EINVAL;
    free(a);
    free(b);
    return e;
}

int cv_fs_symlink(const char *target, const char *link) {
    wchar_t *t = wide(target), *l = wide(link);
    if (!t || !l) {
        free(t);
        free(l);
        return EINVAL;
    }
    // Whether the target is a directory decides the kind of link; a relative
    // target is relative to the link's directory.
    DWORD flags = SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
    DWORD ta;
    int relative = !(t[0] == L'\\' || (t[0] && t[1] == L':'));
    if (relative) {
        wchar_t *slash = wcsrchr(l, L'\\');
        size_t dir = slash ? (size_t)(slash - l) + 1 : 0;
        size_t n = dir + wcslen(t) + 1;
        wchar_t *full = malloc(n * sizeof(wchar_t));
        if (full) {
            memcpy(full, l, dir * sizeof(wchar_t));
            wcscpy(full + dir, t);
            ta = GetFileAttributesW(full);
            free(full);
        } else {
            ta = INVALID_FILE_ATTRIBUTES;
        }
    } else {
        ta = GetFileAttributesW(t);
    }
    if (ta != INVALID_FILE_ATTRIBUTES && (ta & FILE_ATTRIBUTE_DIRECTORY)) flags |= SYMBOLIC_LINK_FLAG_DIRECTORY;
    int e = CreateSymbolicLinkW(l, t, flags) ? 0 : last_win_error();
    free(t);
    free(l);
    return e;
}

// The reparse data of a symbolic link (from ntifs.h).
typedef struct {
    ULONG ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG Flags;
            WCHAR PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR PathBuffer[1];
        } MountPointReparseBuffer;
    };
} cv_reparse_data;

int cv_fs_readlink(const char *path, char *out, int len) {
    wchar_t *w = wide(path);
    if (!w) return -EINVAL;
    HANDLE h = CreateFileW(w, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    free(w);
    if (h == INVALID_HANDLE_VALUE) return -last_win_error();
    union {
        cv_reparse_data data;
        char bytes[MAXIMUM_REPARSE_DATA_BUFFER_SIZE];
    } buf;
    DWORD got = 0;
    BOOL ok = DeviceIoControl(h, FSCTL_GET_REPARSE_POINT, NULL, 0, &buf, sizeof buf, &got, NULL);
    int e = ok ? 0 : last_win_error();
    CloseHandle(h);
    if (!ok) return -(e == EIO ? EINVAL : e);
    const WCHAR *name;
    USHORT bytes;
    if (buf.data.ReparseTag == IO_REPARSE_TAG_SYMLINK) {
        name = buf.data.SymbolicLinkReparseBuffer.PathBuffer + buf.data.SymbolicLinkReparseBuffer.PrintNameOffset / 2;
        bytes = buf.data.SymbolicLinkReparseBuffer.PrintNameLength;
    } else if (buf.data.ReparseTag == IO_REPARSE_TAG_MOUNT_POINT) {
        name = buf.data.MountPointReparseBuffer.PathBuffer + buf.data.MountPointReparseBuffer.PrintNameOffset / 2;
        bytes = buf.data.MountPointReparseBuffer.PrintNameLength;
    } else {
        return -EINVAL;
    }
    int n = narrow(name, bytes / 2, out, len);
    return n < 0 ? -ENAMETOOLONG : n;
}

int cv_fs_realpath(const char *path, char *out, int len) {
    wchar_t *w = wide(path);
    if (!w) return -EINVAL;
    HANDLE h = CreateFileW(w, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                           FILE_FLAG_BACKUP_SEMANTICS, NULL);
    free(w);
    if (h == INVALID_HANDLE_VALUE) return -last_win_error();
    wchar_t full[32768];
    DWORD n = GetFinalPathNameByHandleW(h, full, 32768, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    CloseHandle(h);
    if (n == 0 || n >= 32768) return -EIO;
    // \\?\C:\x → C:\x; \\?\UNC\server\share → \\server\share.
    const wchar_t *p = full;
    wchar_t unc[32768];
    if (wcsncmp(p, L"\\\\?\\UNC\\", 8) == 0) {
        unc[0] = L'\\';
        wcscpy(unc + 1, p + 7);
        p = unc;
    } else if (wcsncmp(p, L"\\\\?\\", 4) == 0) {
        p += 4;
    }
    int m = narrow(p, (int)wcslen(p), out, len);
    return m < 0 ? -ENAMETOOLONG : m;
}

int cv_fs_list(const char *path, cv_dir_entry **entries, int *count) {
    *entries = NULL;
    *count = 0;
    size_t plen = strlen(path);
    char *pattern = malloc(plen + 3);
    if (!pattern) return ENOMEM;
    memcpy(pattern, path, plen);
    size_t k = plen;
    if (k == 0 || (pattern[k - 1] != '/' && pattern[k - 1] != '\\')) pattern[k++] = '\\';
    pattern[k++] = '*';
    pattern[k] = 0;
    wchar_t *w = wide(pattern);
    free(pattern);
    if (!w) return EINVAL;
    WIN32_FIND_DATAW fd;
    HANDLE f = FindFirstFileW(w, &fd);
    free(w);
    if (f == INVALID_HANDLE_VALUE) {
        int e = last_win_error();
        return e == ENOENT && GetLastError() == ERROR_FILE_NOT_FOUND ? 0 : e; // empty
    }
    int cap = 16;
    cv_dir_entry *list = malloc((size_t)cap * sizeof *list);
    if (!list) {
        FindClose(f);
        return ENOMEM;
    }
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        if (*count == cap) {
            cap *= 2;
            cv_dir_entry *bigger = realloc(list, (size_t)cap * sizeof *list);
            if (!bigger) {
                cv_fs_list_free(list, *count);
                FindClose(f);
                return ENOMEM;
            }
            list = bigger;
        }
        char name[1024];
        if (narrow(fd.cFileName, -1, name, sizeof name) < 0) continue;
        list[*count].name = _strdup(name);
        int link = (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
                   (fd.dwReserved0 == IO_REPARSE_TAG_SYMLINK || fd.dwReserved0 == IO_REPARSE_TAG_MOUNT_POINT);
        list[*count].kind = link ? CV_FILE_KIND_LINK
                          : (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? CV_FILE_KIND_DIR
                          : CV_FILE_KIND_FILE;
        ++*count;
    } while (FindNextFileW(f, &fd));
    FindClose(f);
    *entries = list;
    return 0;
}

void cv_fs_list_free(cv_dir_entry *entries, int count) {
    for (int i = 0; i < count; i++) free(entries[i].name);
    free(entries);
}

int cv_fs_temp_dir(const char *prefix, char *out, int len) {
    wchar_t base[MAX_PATH + 1];
    DWORD n = GetTempPathW(MAX_PATH + 1, base);
    if (n == 0 || n > MAX_PATH) return EIO;
    while (n > 3 && base[n - 1] == L'\\') base[--n] = 0;
    char dir[MAX_PATH * 3];
    if (narrow(base, (int)n, dir, sizeof dir) < 0) return ENAMETOOLONG;
    for (int tries = 0; tries < 100; tries++) {
        uint8_t r[6];
        cv_random_bytes(r, sizeof r);
        char path[MAX_PATH * 3 + 64];
        snprintf(path, sizeof path, "%s\\%s%02x%02x%02x%02x%02x%02x", dir, prefix, r[0], r[1], r[2], r[3], r[4], r[5]);
        int e = cv_fs_mkdir(path);
        if (e == EEXIST) continue;
        if (e) return e;
        if ((int)strlen(path) >= len) return ENAMETOOLONG;
        strcpy(out, path);
        return 0;
    }
    return EEXIST;
}

int64_t cv_fs_copy(const char *from, const char *to) {
    wchar_t *a = wide(from), *b = wide(to);
    if (!a || !b) {
        free(a);
        free(b);
        return -EINVAL;
    }
    // CopyFile keeps the attributes (read-only among them) and replaces
    // the destination; a read-only destination has to stop being one first.
    set_readonly(b, 0666);
    BOOL ok = CopyFileW(a, b, FALSE);
    int64_t result;
    if (!ok) {
        result = -(int64_t)last_win_error();
    } else {
        WIN32_FILE_ATTRIBUTE_DATA d;
        result = GetFileAttributesExW(b, GetFileExInfoStandard, &d)
                     ? (int64_t)(((uint64_t)d.nFileSizeHigh << 32) | d.nFileSizeLow)
                     : 0;
    }
    free(a);
    free(b);
    return result;
}

// ---- Unix domain sockets (AF_UNIX, Windows 10 1803 and later) -------------

static int unix_address(const char *path, struct sockaddr_un *un, int *len) {
    size_t n = strlen(path);
    if (n == 0 || n >= sizeof un->sun_path) return ENAMETOOLONG;
    memset(un, 0, sizeof *un);
    un->sun_family = AF_UNIX;
    memcpy(un->sun_path, path, n);
    *len = (int)(offsetof(struct sockaddr_un, sun_path) + n + 1);
    return 0;
}

int cv_unix_listen(const char *path, int backlog, int *err) {
    struct sockaddr_un un;
    int len;
    if ((*err = unix_address(path, &un, &len)) != 0) return -1;
    SOCKET s = new_socket(AF_UNIX, SOCK_STREAM, err);
    if (s == INVALID_SOCKET) return -1;
    if (bind(s, (struct sockaddr *)&un, len) != 0 || listen(s, backlog) != 0) {
        *err = last_error();
        closesocket(s);
        return -1;
    }
    return as_fd(s);
}

int cv_unix_connect(const char *path, int *err) {
    struct sockaddr_un un;
    int len;
    if ((*err = unix_address(path, &un, &len)) != 0) return -1;
    SOCKET s = new_socket(AF_UNIX, SOCK_STREAM, err);
    if (s == INVALID_SOCKET) return -1;
    if (connect(s, (struct sockaddr *)&un, len) == 0) return as_fd(s);
    int e = WSAGetLastError();
    if (e == WSAEWOULDBLOCK) {
        *err = EINPROGRESS;
        return as_fd(s);
    }
    // Refused for a path nobody bound: say so as POSIX does.
    if (e == WSAECONNREFUSED && GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
        *err = ENOENT;
    } else {
        *err = map_error(e);
    }
    closesocket(s);
    return -1;
}

int cv_unix_accept(int fd, int *err) { return accept_nb(fd, err); }

int cv_unix_pair(int fds[2]) {
    // No socketpair: a listener on a fresh name in the temp directory,
    // connected to once and removed.
    char dir[MAX_PATH], path[MAX_PATH];
    DWORD n = GetTempPathA(sizeof dir, dir);
    if (n == 0 || n >= sizeof dir) return EIO;
    uint8_t r[8];
    cv_random_bytes(r, sizeof r);
    snprintf(path, sizeof path, "%svega-%02x%02x%02x%02x%02x%02x%02x%02x.sock", dir, r[0], r[1], r[2], r[3],
             r[4], r[5], r[6], r[7]);
    int err = 0;
    int l = cv_unix_listen(path, 1, &err);
    if (l < 0) return err;
    // Blocking for the handshake: it's local and immediate.
    SOCKET c = WSASocketW(AF_UNIX, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
    struct sockaddr_un un;
    int len;
    unix_address(path, &un, &len);
    if (c == INVALID_SOCKET || connect(c, (struct sockaddr *)&un, len) != 0) {
        err = last_error();
        if (c != INVALID_SOCKET) closesocket(c);
        closesocket(as_socket(l));
        DeleteFileA(path);
        return err ? err : EIO;
    }
    // The listener is non-blocking; the connection is queued by now.
    SOCKET a = INVALID_SOCKET;
    for (int i = 0; i < 1000 && a == INVALID_SOCKET; i++) {
        a = accept(as_socket(l), NULL, NULL);
        if (a == INVALID_SOCKET && WSAGetLastError() == WSAEWOULDBLOCK) Sleep(0);
        else break;
    }
    err = a == INVALID_SOCKET ? last_error() : 0;
    closesocket(as_socket(l));
    DeleteFileA(path);
    if (!err) err = prepare(c);
    if (!err) err = prepare(a);
    if (err) {
        closesocket(c);
        if (a != INVALID_SOCKET) closesocket(a);
        return err;
    }
    fds[0] = as_fd(c);
    fds[1] = as_fd(a);
    return 0;
}

// ---- socket options ------------------------------------------------------

#ifndef TCP_KEEPIDLE
#define TCP_KEEPIDLE TCP_KEEPALIVE
#endif

static int sockopt_name(int opt, int *level, int *name) {
    switch (opt) {
    case CV_OPT_TCP_NODELAY: *level = IPPROTO_TCP; *name = TCP_NODELAY; return 0;
    case CV_OPT_KEEPALIVE: *level = SOL_SOCKET; *name = SO_KEEPALIVE; return 0;
    case CV_OPT_TCP_KEEPIDLE: *level = IPPROTO_TCP; *name = TCP_KEEPIDLE; return 0;
    case CV_OPT_TCP_KEEPINTVL: *level = IPPROTO_TCP; *name = TCP_KEEPINTVL; return 0;
    case CV_OPT_TCP_KEEPCNT: *level = IPPROTO_TCP; *name = TCP_KEEPCNT; return 0;
    case CV_OPT_TCP_FASTOPEN: *level = IPPROTO_TCP; *name = TCP_FASTOPEN; return 0;
    case CV_OPT_RCVBUF: *level = SOL_SOCKET; *name = SO_RCVBUF; return 0;
    case CV_OPT_SNDBUF: *level = SOL_SOCKET; *name = SO_SNDBUF; return 0;
    case CV_OPT_REUSEADDR: *level = SOL_SOCKET; *name = SO_REUSEADDR; return 0;
    case CV_OPT_BROADCAST: *level = SOL_SOCKET; *name = SO_BROADCAST; return 0;
    case CV_OPT_IPV6_V6ONLY: *level = IPPROTO_IPV6; *name = IPV6_V6ONLY; return 0;
    case CV_OPT_IP_TTL: *level = IPPROTO_IP; *name = IP_TTL; return 0;
    case CV_OPT_IP_TOS: *level = IPPROTO_IP; *name = IP_TOS; return 0;
    case CV_OPT_IPV6_UNICAST_HOPS: *level = IPPROTO_IPV6; *name = IPV6_UNICAST_HOPS; return 0;
    case CV_OPT_IP_MULTICAST_TTL: *level = IPPROTO_IP; *name = IP_MULTICAST_TTL; return 0;
    case CV_OPT_IP_MULTICAST_LOOP: *level = IPPROTO_IP; *name = IP_MULTICAST_LOOP; return 0;
    case CV_OPT_IPV6_MULTICAST_HOPS: *level = IPPROTO_IPV6; *name = IPV6_MULTICAST_HOPS; return 0;
    case CV_OPT_IPV6_MULTICAST_LOOP: *level = IPPROTO_IPV6; *name = IPV6_MULTICAST_LOOP; return 0;
    default: return ENOPROTOOPT;
    }
}

static int is_flag(int opt) {
    switch (opt) {
    case CV_OPT_TCP_NODELAY: case CV_OPT_KEEPALIVE: case CV_OPT_REUSEADDR: case CV_OPT_BROADCAST:
    case CV_OPT_IPV6_V6ONLY: case CV_OPT_IP_MULTICAST_LOOP: case CV_OPT_IPV6_MULTICAST_LOOP:
    case CV_OPT_TCP_FASTOPEN:
        return 1;
    default:
        return 0;
    }
}

int cv_sockopt_set(int fd, int opt, int value) {
    SOCKET s = as_socket(fd);
    if (opt == CV_OPT_LINGER) {
        struct linger l = {(u_short)(value >= 0), (u_short)(value >= 0 ? value : 0)};
        return setsockopt(s, SOL_SOCKET, SO_LINGER, (const char *)&l, sizeof l) == 0 ? 0 : last_error();
    }
    int level, name, e = sockopt_name(opt, &level, &name);
    if (e) return e;
    if (is_flag(opt)) value = value != 0;
    return setsockopt(s, level, name, (const char *)&value, sizeof value) == 0 ? 0 : last_error();
}

int cv_sockopt_get(int fd, int opt, int *value) {
    SOCKET s = as_socket(fd);
    if (opt == CV_OPT_LINGER) {
        struct linger l = {0};
        int len = sizeof l;
        if (getsockopt(s, SOL_SOCKET, SO_LINGER, (char *)&l, &len) != 0) return last_error();
        *value = l.l_onoff ? l.l_linger : -1;
        return 0;
    }
    int level, name, e = sockopt_name(opt, &level, &name);
    if (e) return e;
    int v = 0;
    int len = sizeof v;
    if (getsockopt(s, level, name, (char *)&v, &len) != 0) return last_error();
    *value = len == 1 ? (int)*(unsigned char *)&v : v;
    if (is_flag(opt)) *value = *value != 0;
    return 0;
}

int cv_multicast(int fd, const cv_sockaddr *group, unsigned interface, int join) {
    SOCKET s = as_socket(fd);
    const struct sockaddr *sa = (const struct sockaddr *)group->storage;
    if (sa->sa_family == AF_INET) {
        struct ip_mreq m = {0};
        m.imr_multiaddr = ((const struct sockaddr_in *)sa)->sin_addr;
        (void)interface;
        int op = join ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP;
        return setsockopt(s, IPPROTO_IP, op, (const char *)&m, sizeof m) == 0 ? 0 : last_error();
    }
    if (sa->sa_family == AF_INET6) {
        struct ipv6_mreq m = {0};
        m.ipv6mr_multiaddr = ((const struct sockaddr_in6 *)sa)->sin6_addr;
        m.ipv6mr_interface = interface;
        int op = join ? IPV6_ADD_MEMBERSHIP : IPV6_DROP_MEMBERSHIP;
        return setsockopt(s, IPPROTO_IPV6, op, (const char *)&m, sizeof m) == 0 ? 0 : last_error();
    }
    return EAFNOSUPPORT;
}

// ---- vectored and batched I/O --------------------------------------------

intptr_t cv_sendv(int fd, const cv_iovec *iov, int count) {
    WSABUF bufs[64];
    if (count > 64) count = 64;
    for (int i = 0; i < count; i++) {
        bufs[i].buf = (CHAR *)iov[i].base;
        bufs[i].len = (ULONG)(iov[i].len > ULONG_MAX ? ULONG_MAX : iov[i].len);
    }
    DWORD sent = 0;
    if (WSASend(as_socket(fd), bufs, (DWORD)count, &sent, 0, NULL, NULL) != 0) return -(intptr_t)last_error();
    return (intptr_t)sent;
}

// No per-datagram path on Windows yet (that needs WSARecvMsg): local
// addresses read as unknown and a send's path is ignored.
int cv_udp_path_info(int fd, int on) {
    (void)fd;
    (void)on;
    return EOPNOTSUPP;
}

int cv_udp_dont_fragment(int fd, int on) {
    DWORD v = on ? 1 : 0;
    int ok = 0;
    if (setsockopt(as_socket(fd), IPPROTO_IP, IP_DONTFRAGMENT, (const char *)&v, sizeof v) == 0) ok = 1;
    if (setsockopt(as_socket(fd), IPPROTO_IPV6, IPV6_DONTFRAG, (const char *)&v, sizeof v) == 0) ok = 1;
    return ok ? 0 : map_error(WSAGetLastError());
}

intptr_t cv_recv_batch(int fd, void *base, intptr_t stride, int count, cv_sockaddr *from,
                   uint32_t *lens, uint32_t *flags, cv_dgram_path *paths) {
    int got = 0;
    for (; got < count; got++) {
        char *p = (char *)base + (size_t)got * (size_t)stride;
        int alen = sizeof from[got].storage;
        int n = recvfrom(as_socket(fd), p, clamp_len(stride), 0, (struct sockaddr *)from[got].storage, &alen);
        flags[got] = 0;
        if (n < 0) {
            int e = WSAGetLastError();
            if (e == WSAEMSGSIZE) {
                n = clamp_len(stride);
                flags[got] = CV_DGRAM_TRUNCATED;
            } else {
                if (got > 0) break;
                return -(intptr_t)map_error(e);
            }
        }
        from[got].len = (uint32_t)alen;
        lens[got] = (uint32_t)n;
        if (paths) {
            paths[got].local.len = 0;
            paths[got].ecn = 0;
        }
    }
    return got;
}

intptr_t cv_send_batch(int fd, const void *base, intptr_t stride, const uint32_t *lens,
                   const cv_sockaddr *to, int count, const cv_dgram_path *paths) {
    (void)paths;
    int sent = 0;
    for (; sent < count; sent++) {
        const char *p = (const char *)base + (size_t)sent * (size_t)stride;
        int n = to && to[sent].len
            ? sendto(as_socket(fd), p, (int)lens[sent], 0, (const struct sockaddr *)to[sent].storage,
                     (int)to[sent].len)
            : send(as_socket(fd), p, (int)lens[sent], 0);
        if (n < 0) {
            if (sent > 0) break;
            return -(intptr_t)last_error();
        }
    }
    return sent;
}

intptr_t cv_send_segments_split(int fd, const void *buf, intptr_t len, int segment, const cv_sockaddr *to,
                                const cv_dgram_path *path) {
    (void)path;
    if (segment <= 0 || len <= segment) segment = len > 0 ? (int)len : 1;
    int have_to = to && to->len;
    enum { CHUNK = 64 };
    uint32_t lens[CHUNK];
    cv_sockaddr tos[CHUNK];
    intptr_t done = 0;
    do {
        int k = 0;
        for (intptr_t off = done; k < CHUNK && (off < len || (len == 0 && k == 0)); k++) {
            intptr_t l = len - off < segment ? len - off : segment;
            lens[k] = (uint32_t)l;
            off += l;
            if (have_to) tos[k] = *to;
        }
        intptr_t n = cv_send_batch(fd, (const char *)buf + done, segment, lens, have_to ? tos : NULL, k, NULL);
        if (n < 0) return done > 0 ? done : n;
        for (intptr_t i = 0; i < n; i++) done += lens[i];
        if (n < k) break;
    } while (done < len);
    return done;
}

intptr_t cv_send_segments(int fd, const void *buf, intptr_t len, int segment, const cv_sockaddr *to,
                          const cv_dgram_path *path) {
    return cv_send_segments_split(fd, buf, len, segment, to, path);
}

int cv_udp_gso_supported(int fd) {
    (void)fd;
    return 0;
}

intptr_t cv_recv_segments(int fd, void *buf, intptr_t len, cv_sockaddr *from, int *segment,
                      uint32_t *flags) {
    *segment = 0;
    *flags = 0;
    cv_sockaddr ignored;
    cv_sockaddr *f = from ? from : &ignored;
    int alen = sizeof f->storage;
    int n = recvfrom(as_socket(fd), buf, clamp_len(len), 0, (struct sockaddr *)f->storage, &alen);
    if (n < 0) {
        int e = WSAGetLastError();
        if (e != WSAEMSGSIZE) return -(intptr_t)map_error(e);
        n = clamp_len(len);
        *flags = CV_DGRAM_TRUNCATED;
    }
    f->len = (uint32_t)alen;
    return (intptr_t)n;
}
// ---- pipes and processes (VegaProcess) --------------------------------------
// A pipe is a named pipe with a unique name, as Rust's std makes them: only
// those can be overlapped, which the driver needs. The child's end of a
// child's pipe stays synchronous, as programs expect of their stdio.

int cv_pipe_win(int fds[2], int child_end) {
    static volatile LONG serial;
    WCHAR name[128];
    for (int attempt = 0; attempt < 8; attempt++) {
        unsigned long long r;
        cv_random_bytes(&r, sizeof r);
        swprintf(name, 128, L"\\\\.\\pipe\\vega-anonymous-pipe.%lu.%ld.%016llx", GetCurrentProcessId(),
                 InterlockedIncrement(&serial), r);
        HANDLE server = CreateNamedPipeW(name,
                                         PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE |
                                             (child_end == 0 ? 0 : FILE_FLAG_OVERLAPPED),
                                         PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                                         1, 64 * 1024, 64 * 1024, 0, NULL);
        if (server == INVALID_HANDLE_VALUE) {
            DWORD e = GetLastError();
            if (e == ERROR_ACCESS_DENIED || e == ERROR_PIPE_BUSY) continue; // the name is taken
            return cv_win_errno(e);
        }
        HANDLE client = CreateFileW(name, GENERIC_WRITE | FILE_READ_ATTRIBUTES, 0, NULL, OPEN_EXISTING,
                                    child_end == 1 ? 0 : FILE_FLAG_OVERLAPPED, NULL);
        if (client == INVALID_HANDLE_VALUE) {
            int e = last_win_error();
            CloseHandle(server);
            return e;
        }
        fds[0] = (int)(intptr_t)server;
        fds[1] = (int)(intptr_t)client;
        return 0;
    }
    return EEXIST;
}

int cv_pipe(int fds[2]) { return cv_pipe_win(fds, -1); }

int cv_pipe_prepare(int fd) {
    (void)fd; // created non-inheritable and overlapped already
    return 0;
}

int cv_spawn_win(const wchar_t *app, const wchar_t *cmdline, const wchar_t *env, const wchar_t *cwd,
                 const int stdio[3], int new_group, intptr_t *process, int *pid) {
    static const DWORD std_ids[3] = {STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE};
    HANDLE handles[3] = {NULL, NULL, NULL}; // inheritable copies, closed here
    HANDLE list[3];
    int listed = 0, err = 0;
    HANDLE nul = INVALID_HANDLE_VALUE;
    wchar_t *line = NULL;
    LPPROC_THREAD_ATTRIBUTE_LIST attrs = NULL;
    int attrs_ready = 0;
    for (int i = 0; i < 3; i++) {
        HANDLE h;
        if (stdio[i] == CV_STDIO_INHERIT) {
            h = GetStdHandle(std_ids[i]);
        } else if (stdio[i] == CV_STDIO_NULL) {
            if (nul == INVALID_HANDLE_VALUE) {
                nul = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                  OPEN_EXISTING, 0, NULL);
                if (nul == INVALID_HANDLE_VALUE) {
                    err = last_win_error();
                    goto done;
                }
            }
            h = nul;
        } else {
            h = (HANDLE)(intptr_t)stdio[i];
        }
        if (h == NULL || h == INVALID_HANDLE_VALUE) continue; // the parent has none (a GUI app)
        if (!DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &handles[i], 0, TRUE,
                             DUPLICATE_SAME_ACCESS)) {
            handles[i] = NULL;
            err = last_win_error();
            goto done;
        }
        list[listed++] = handles[i];
    }
    size_t n = wcslen(cmdline) + 1; // CreateProcessW may write to it
    line = malloc(n * sizeof(wchar_t));
    if (!line) {
        err = ENOMEM;
        goto done;
    }
    memcpy(line, cmdline, n * sizeof(wchar_t));

    STARTUPINFOEXW si;
    memset(&si, 0, sizeof si);
    si.StartupInfo.cb = sizeof si.StartupInfo;
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = handles[0];
    si.StartupInfo.hStdOutput = handles[1];
    si.StartupInfo.hStdError = handles[2];
    DWORD flags = CREATE_UNICODE_ENVIRONMENT | (new_group ? CREATE_NEW_PROCESS_GROUP : 0);
    if (listed) {
        // Only these handles, so a spawn on another thread can't leak its
        // pipe ends into this child (which would keep them open).
        SIZE_T size = 0;
        InitializeProcThreadAttributeList(NULL, 1, 0, &size);
        attrs = malloc(size);
        if (!attrs || !InitializeProcThreadAttributeList(attrs, 1, 0, &size)) {
            err = attrs ? last_win_error() : ENOMEM;
            goto done;
        }
        attrs_ready = 1;
        if (!UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, list,
                                       (SIZE_T)listed * sizeof(HANDLE), NULL, NULL)) {
            err = last_win_error();
            goto done;
        }
        si.StartupInfo.cb = sizeof si;
        si.lpAttributeList = attrs;
        flags |= EXTENDED_STARTUPINFO_PRESENT;
    }
    PROCESS_INFORMATION pi;
    if (!CreateProcessW(app, line, NULL, NULL, listed > 0, flags, (LPVOID)env, cwd, &si.StartupInfo, &pi)) {
        err = last_win_error();
        goto done;
    }
    CloseHandle(pi.hThread);
    *process = (intptr_t)pi.hProcess;
    *pid = (int)pi.dwProcessId;
done:
    if (attrs_ready) DeleteProcThreadAttributeList(attrs);
    free(attrs);
    free(line);
    for (int i = 0; i < 3; i++)
        if (handles[i]) CloseHandle(handles[i]);
    if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
    return err;
}

int cv_process_wait(intptr_t process, int nohang, uint32_t *code) {
    DWORD r = WaitForSingleObject((HANDLE)process, nohang ? 0 : INFINITE);
    if (r == WAIT_TIMEOUT) return 0;
    if (r != WAIT_OBJECT_0) return -last_win_error();
    DWORD c = 0;
    if (!GetExitCodeProcess((HANDLE)process, &c)) return -last_win_error();
    *code = c;
    return 1;
}

int cv_process_kill(intptr_t process) {
    if (TerminateProcess((HANDLE)process, 1)) return 0;
    int e = last_win_error();
    // Refused once it has exited.
    return WaitForSingleObject((HANDLE)process, 0) == WAIT_OBJECT_0 ? 0 : e;
}

void cv_process_close(intptr_t process) { CloseHandle((HANDLE)process); }

#endif
