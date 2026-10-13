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

void cv_close_socket(int fd) { closesocket(as_socket(fd)); }

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

int cv_local_port(int fd) {
    cv_sockaddr a;
    return cv_local_address(fd, &a) == 0 ? cv_sockaddr_port(&a) : -1;
}

static int clamp_len(intptr_t len) { return len > INT_MAX ? INT_MAX : (int)len; }

intptr_t cv_recv(int fd, void *buf, intptr_t len) {
    int n = recv(as_socket(fd), buf, clamp_len(len), 0);
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

intptr_t cv_recv_batch(int fd, void *base, intptr_t stride, int count, cv_sockaddr *from,
                   uint32_t *lens, uint32_t *flags) {
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
    }
    return got;
}

intptr_t cv_send_batch(int fd, const void *base, intptr_t stride, const uint32_t *lens,
                   const cv_sockaddr *to, int count) {
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

intptr_t cv_send_segments_split(int fd, const void *buf, intptr_t len, int segment, const cv_sockaddr *to) {
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
        intptr_t n = cv_send_batch(fd, (const char *)buf + done, segment, lens, have_to ? tos : NULL, k);
        if (n < 0) return done > 0 ? done : n;
        for (intptr_t i = 0; i < n; i++) done += lens[i];
        if (n < k) break;
    } while (done < len);
    return done;
}

intptr_t cv_send_segments(int fd, const void *buf, intptr_t len, int segment, const cv_sockaddr *to) {
    return cv_send_segments_split(fd, buf, len, segment, to);
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
#endif
