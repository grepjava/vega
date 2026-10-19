// TLS over the system's OpenSSL, or BoringSSL with the BoringSSL trait, through
// a BIO of our own: the library never sees a socket. A call is handed the
// peer's ciphertext where the Swift side read it, and the engine takes from
// it in place; what the engine writes collects in a buffer the Swift side
// sends from. Neither direction copies through the library's memory BIOs.
//
// The library's per-thread error queue must be empty when SSL_get_error is
// asked about a failure, and a connection's calls come from any worker
// thread, after anything else that used the library there. A call that may
// fail empties the queue first when it isn't already (see clean_queue); every
// failure path empties it before returning.
#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h> // before OpenSSL, whose headers undo its X509_NAME macros
#if defined(VEGA_TLS_BORINGSSL)
// BoringSSL's headers leave that to their includer.
#undef X509_NAME
#undef X509_EXTENSIONS
#undef X509_CERT_PAIR
#undef PKCS7_ISSUER_AND_SERIAL
#undef PKCS7_SIGNER_INFO
#undef OCSP_REQUEST
#undef OCSP_RESPONSE
#endif
#endif
#include "cvega_tls.h"

#if defined(VEGA_TLS_BORINGSSL)
// The BoringSSL trait: the vendored copy, whose public names carry the
// CVegaBoringSSL prefix.
#include "CVegaBoringSSL_err.h"
#include "CVegaBoringSSL_evp.h"
#include "CVegaBoringSSL_hmac.h"
#include "CVegaBoringSSL_pem.h"
#include "CVegaBoringSSL_ssl.h"
#include "CVegaBoringSSL_x509v3.h"
#define CV_HAVE_TLS 1
#elif defined(VEGA_TLS_OPENSSL) && __has_include(<openssl/ssl.h>) // none on iOS and the like: VegaTLS is empty there
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#define CV_HAVE_TLS 1
#endif

#if CV_HAVE_TLS
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(OPENSSL_IS_BORINGSSL)
// OpenSSL 3 calls BoringSSL doesn't have.
#if defined(_WIN32)
#define CRYPTO_RWLOCK SRWLOCK
static SRWLOCK *cv_lock_new(void) {
    SRWLOCK *m = malloc(sizeof *m);
    if (m) InitializeSRWLock(m);
    return m;
}
static void cv_lock_free(SRWLOCK *m) { free(m); }
static int cv_lock(SRWLOCK *m) {
    AcquireSRWLockExclusive(m);
    return 1;
}
static int cv_unlock(SRWLOCK *m) {
    ReleaseSRWLockExclusive(m);
    return 1;
}
#define CRYPTO_THREAD_write_lock cv_lock
#define CRYPTO_THREAD_unlock cv_unlock
#else
#include <pthread.h>
#define CRYPTO_RWLOCK pthread_mutex_t
static pthread_mutex_t *cv_lock_new(void) {
    pthread_mutex_t *m = malloc(sizeof *m);
    if (m) pthread_mutex_init(m, NULL);
    return m;
}
static void cv_lock_free(pthread_mutex_t *m) {
    pthread_mutex_destroy(m);
    free(m);
}
#define CRYPTO_THREAD_write_lock pthread_mutex_lock
#define CRYPTO_THREAD_unlock pthread_mutex_unlock
#endif
#define CRYPTO_THREAD_lock_new cv_lock_new
#define CRYPTO_THREAD_lock_free cv_lock_free
#define SSL_R_UNEXPECTED_EOF_WHILE_READING (-1) // BoringSSL reports SSL_ERROR_SYSCALL
static EVP_PKEY *cv_keygen_p256(void) {
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EVP_PKEY *key = EVP_PKEY_new();
    if (!ec || !key || !EC_KEY_generate_key(ec) || !EVP_PKEY_assign_EC_KEY(key, ec)) {
        EC_KEY_free(ec);
        EVP_PKEY_free(key);
        return NULL;
    }
    return key;
}
#define EVP_PKEY_Q_keygen(lib, props, type, curve) cv_keygen_p256()
static int cv_write_ex(SSL *ssl, const void *buf, size_t len, size_t *n) {
    int r = SSL_write(ssl, buf, len > INT_MAX ? INT_MAX : (int)len);
    if (r <= 0) return 0;
    *n = (size_t)r;
    return 1;
}
#define SSL_write_ex cv_write_ex
#define SSL_get1_peer_certificate SSL_get_peer_certificate // a new reference in BoringSSL too
// BoringSSL's sessions are immutable once made, so sharing one is a copy.
static SSL_SESSION *cv_session_dup(SSL_SESSION *s) {
    SSL_SESSION_up_ref(s);
    return s;
}
#define SSL_SESSION_dup cv_session_dup
// The vendored copy's prefix list misses X509V3_EXT_conf_nid, a wrapper.
#define X509V3_EXT_conf_nid(conf, ctx, nid, value) X509V3_EXT_nconf_nid(NULL, ctx, nid, value)
#else
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#error "VegaTLS needs OpenSSL 3.0 or later"
#endif
#endif

#if defined(_WIN32)
#define strtok_r strtok_s
#endif

// Kernel TLS: Linux's, where its header is.
#if defined(__linux__) && __has_include(<linux/tls.h>)
#define CV_KTLS 1
#include <errno.h>
#include <linux/tls.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#ifndef TCP_ULP
#define TCP_ULP 31
#endif
#ifndef SOL_TLS
#define SOL_TLS 282
#endif
struct cv_ktls;
#endif

#define MAX_NAMES 64

struct cv_tls_ctx {
    SSL_CTX *ssl;
    int server;
    int verify;
    unsigned char *alpn;
    unsigned int alpn_len;
    struct {
        char *name;
        SSL_CTX *ssl;
    } names[MAX_NAMES];
    int name_count;
    // Client sessions to resume, by server name.
    CRYPTO_RWLOCK *lock;
    struct cache_entry {
        char *host;
        SSL_SESSION *session;
        uint64_t used;
    } *cache;
    int cache_size;
    uint64_t tick;
    // Server: the ClientHello hook.
    cv_tls_hello_fn hello;
    void *hello_arg;
};

/// Ciphertext for the peer.
struct cv_out {
    unsigned char *p;
    size_t len, cap;
};

struct cv_tls {
    SSL *ssl;
    cv_tls_ctx *ctx;
    char *host;
    // The peer's ciphertext for the call in progress: the caller's bytes,
    // set on entry and cleared before returning, so the engine never holds
    // a pointer into them between calls (nor reads them in a call made by
    // the other half of a split stream).
    const unsigned char *in;
    size_t in_len;
    int eof; // and after in, the end of the peer's ciphertext
    // What the engine wrote, and the buffer taken to be sent meanwhile.
    struct cv_out out, taken;
#if CV_KTLS
    // Kernel TLS asked for: what handing the records to the kernel needs.
    struct cv_ktls *k;
#endif
    char err[256];
};

// MARK: - Errors

/// Empty the error queue before a call SSL_get_error may be asked about:
/// errors something else left on this thread would make it report
/// SSL_ERROR_SSL for a mere "want more input". Peeking costs a fifth of
/// clearing (about 20 ns against 120 with OpenSSL 3.0, which clears all
/// sixteen slots), and the queue is nearly always empty already: our own
/// failure paths empty it before returning.
static inline void clean_queue(void) {
    if (ERR_peek_error() != 0) ERR_clear_error();
}

/// "what: reason" from OpenSSL's queue (or just what), then clear it.
static void describe(char *err, int errlen, const char *what) {
    if (!err || errlen <= 0) {
        ERR_clear_error();
        return;
    }
    unsigned long e = ERR_peek_last_error();
    const char *reason = e ? ERR_reason_error_string(e) : NULL;
    if (reason)
        snprintf(err, (size_t)errlen, "%s: %s", what, reason);
    else
        snprintf(err, (size_t)errlen, "%s", what);
    ERR_clear_error();
}

/// A failed handshake or record: the certificate check's verdict if that
/// was it, else OpenSSL's reason.
static void record_error(cv_tls *t, const char *what) {
    long v = SSL_get_verify_result(t->ssl);
    if (v != X509_V_OK) {
        snprintf(t->err, sizeof t->err, "certificate verify failed: %s", X509_verify_cert_error_string(v));
        ERR_clear_error();
        return;
    }
    describe(t->err, sizeof t->err, what);
}

// MARK: - Configurations

static int alpn_select(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
                       unsigned int inlen, void *arg) {
    (void)ssl;
    cv_tls_ctx *c = arg;
    unsigned char *chosen = NULL;
    if (SSL_select_next_proto(&chosen, outlen, c->alpn, c->alpn_len, in, inlen) == OPENSSL_NPN_NEGOTIATED) {
        *out = chosen;
        return SSL_TLSEXT_ERR_OK;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL; // no_application_protocol (RFC 7301)
}

/// "*.example.com" matches one label in front; otherwise case-insensitive
/// equality.
static int name_matches(const char *pattern, const char *name) {
    if (pattern[0] == '*' && pattern[1] == '.') {
        const char *dot = strchr(name, '.');
        if (!dot || dot == name) return 0;
        return OPENSSL_strcasecmp(dot + 1, pattern + 2) == 0;
    }
    return OPENSSL_strcasecmp(pattern, name) == 0;
}

static int servername_select(SSL *ssl, int *alert, void *arg) {
    (void)alert;
    cv_tls_ctx *c = arg;
    // The ClientHello hook chose already: its choice stands.
    if (SSL_get_SSL_CTX(ssl) != c->ssl) return SSL_TLSEXT_ERR_OK;
    const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (!name) return SSL_TLSEXT_ERR_OK;
    for (int i = 0; i < c->name_count; i++) {
        if (name_matches(c->names[i].name, name)) {
            SSL_set_SSL_CTX(ssl, c->names[i].ssl);
            break;
        }
    }
    return SSL_TLSEXT_ERR_OK;
}

/// The host name in a server_name extension's body, or "".
static void parse_server_name(const uint8_t *p, size_t n, char *out, size_t outlen) {
    out[0] = 0;
    if (n < 5) return;
    size_t list = (size_t)p[0] << 8 | p[1];
    if (list + 2 > n || p[2] != 0) return; // host_name entries only
    size_t len = (size_t)p[3] << 8 | p[4];
    if (len + 5 > n || len == 0 || len >= outlen) return;
    memcpy(out, p + 5, len);
    out[len] = 0;
    if (strlen(out) != len) out[0] = 0; // an embedded NUL: no name
}

/// Ask the hook, and switch to the context it returns.
static void hello_select(SSL *ssl, cv_tls_ctx *c, const uint8_t *sni, size_t sni_len, const uint8_t *alpn,
                         size_t alpn_len) {
    char name[256];
    name[0] = 0;
    if (sni) parse_server_name(sni, sni_len, name, sizeof name);
    const uint8_t *protocols = NULL;
    int protocols_len = 0;
    if (alpn && alpn_len >= 2) {
        size_t list = (size_t)alpn[0] << 8 | alpn[1];
        if (list + 2 <= alpn_len) {
            protocols = alpn + 2;
            protocols_len = (int)list;
        }
    }
    cv_tls_ctx *chosen = c->hello(c->hello_arg, name[0] ? name : NULL, protocols, protocols_len);
    if (chosen && chosen->ssl != SSL_get_SSL_CTX(ssl)) SSL_set_SSL_CTX(ssl, chosen->ssl);
}

#if defined(OPENSSL_IS_BORINGSSL)
static enum ssl_select_cert_result_t client_hello(const SSL_CLIENT_HELLO *h) {
    cv_tls_ctx *c = SSL_CTX_get_app_data(SSL_get_SSL_CTX(h->ssl));
    if (!c || !c->hello) return ssl_select_cert_success;
    const uint8_t *sni = NULL, *alpn = NULL;
    size_t sni_len = 0, alpn_len = 0;
    if (!SSL_early_callback_ctx_extension_get(h, TLSEXT_TYPE_server_name, &sni, &sni_len)) sni = NULL;
    if (!SSL_early_callback_ctx_extension_get(h, TLSEXT_TYPE_application_layer_protocol_negotiation, &alpn,
                                              &alpn_len))
        alpn = NULL;
    hello_select(h->ssl, c, sni, sni_len, alpn, alpn_len);
    return ssl_select_cert_success;
}
#else
static int client_hello(SSL *ssl, int *alert, void *arg) {
    (void)alert;
    cv_tls_ctx *c = arg;
    const unsigned char *sni = NULL, *alpn = NULL;
    size_t sni_len = 0, alpn_len = 0;
    if (!SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name, &sni, &sni_len)) sni = NULL;
    if (!SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_application_layer_protocol_negotiation, &alpn, &alpn_len))
        alpn = NULL;
    hello_select(ssl, c, sni, sni_len, alpn, alpn_len);
    return SSL_CLIENT_HELLO_SUCCESS;
}
#endif

void cv_tls_ctx_set_hello(cv_tls_ctx *c, cv_tls_hello_fn fn, void *arg) {
    c->hello = fn;
    c->hello_arg = arg;
#if defined(OPENSSL_IS_BORINGSSL)
    SSL_CTX_set_select_certificate_cb(c->ssl, fn ? client_hello : NULL);
#else
    SSL_CTX_set_client_hello_cb(c->ssl, fn ? client_hello : NULL, c);
#endif
}

int cv_tls_ctx_set_ticket_key(cv_tls_ctx *c, const uint8_t *key, int len, char *err, int errlen) {
    if (len != 80) {
        snprintf(err, (size_t)errlen, "a session-ticket key is 80 bytes");
        return -1;
    }
#if defined(OPENSSL_IS_BORINGSSL)
    long n = 48;
#else
    long n = 80;
#endif
    if (SSL_CTX_set_tlsext_ticket_keys(c->ssl, (void *)key, n) != 1) {
        describe(err, errlen, "SSL_CTX_set_tlsext_ticket_keys");
        return -1;
    }
    return 0;
}

static int new_session(SSL *ssl, SSL_SESSION *session) {
    cv_tls *t = SSL_get_app_data(ssl);
    cv_tls_ctx *c = SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl));
    if (!t || !c || !t->host || c->cache_size == 0) return 0;
    CRYPTO_THREAD_write_lock(c->lock);
    // The host's own entry, else an empty one, else the least recently used.
    struct cache_entry *slot = NULL, *empty = NULL, *oldest = NULL;
    for (int i = 0; i < c->cache_size && !slot; i++) {
        struct cache_entry *e = &c->cache[i];
        if (!e->host) {
            if (!empty) empty = e;
        } else if (strcmp(e->host, t->host) == 0) {
            slot = e;
        } else if (!oldest || e->used < oldest->used) {
            oldest = e;
        }
    }
    if (!slot) {
        slot = empty ? empty : oldest;
        OPENSSL_free(slot->host);
        slot->host = OPENSSL_strdup(t->host);
        if (!slot->host) {
            if (slot->session) SSL_SESSION_free(slot->session);
            slot->session = NULL;
            CRYPTO_THREAD_unlock(c->lock);
            return 0;
        }
    }
    // A copy: OpenSSL marks the connection's own session unresumable if
    // the connection ends without our close_notify.
    if (slot->session) SSL_SESSION_free(slot->session);
    slot->session = SSL_SESSION_dup(session);
    slot->used = ++c->tick;
    CRYPTO_THREAD_unlock(c->lock);
    return 0;
}

cv_tls_ctx *cv_tls_ctx_new(int server, char *err, int errlen) {
    ERR_clear_error();
    cv_tls_ctx *c = calloc(1, sizeof *c);
    if (!c) {
        snprintf(err, (size_t)errlen, "out of memory");
        return NULL;
    }
    c->server = server;
    c->lock = CRYPTO_THREAD_lock_new();
    c->ssl = SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());
    if (!c->ssl || !c->lock) {
        describe(err, errlen, "SSL_CTX_new");
        cv_tls_ctx_free(c);
        return NULL;
    }
    SSL_CTX_set_app_data(c->ssl, c);
    SSL_CTX_set_min_proto_version(c->ssl, TLS1_2_VERSION);
    SSL_CTX_set_options(c->ssl, SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_COMPRESSION);
    if (server) {
        SSL_CTX_set_session_id_context(c->ssl, (const unsigned char *)"vega", 4);
        cv_tls_ctx_set_verify(c, CV_TLS_VERIFY_NONE);
    } else {
        cv_tls_ctx_set_verify(c, CV_TLS_VERIFY_REQUIRED);
        cv_tls_ctx_set_session_cache(c, 256);
    }
    return c;
}

void cv_tls_ctx_free(cv_tls_ctx *c) {
    if (!c) return;
    for (int i = 0; i < c->name_count; i++) {
        OPENSSL_free(c->names[i].name); // OPENSSL_strdup's
        SSL_CTX_free(c->names[i].ssl);
    }
    for (int i = 0; i < c->cache_size; i++) {
        OPENSSL_free(c->cache[i].host);
        if (c->cache[i].session) SSL_SESSION_free(c->cache[i].session);
    }
    free(c->cache);
    free(c->alpn);
    if (c->ssl) SSL_CTX_free(c->ssl);
    if (c->lock) CRYPTO_THREAD_lock_free(c->lock);
    free(c);
}

int cv_tls_ctx_use_certificate(cv_tls_ctx *c, const char *chain_pem, int chain_len, const char *key_pem,
                               int key_len, char *err, int errlen) {
    ERR_clear_error();
    BIO *b = BIO_new_mem_buf(chain_pem, chain_len);
    X509 *leaf = b ? PEM_read_bio_X509_AUX(b, NULL, NULL, NULL) : NULL;
    if (!leaf || SSL_CTX_use_certificate(c->ssl, leaf) != 1) {
        X509_free(leaf);
        BIO_free(b);
        describe(err, errlen, "certificate");
        return -1;
    }
    X509_free(leaf);
    SSL_CTX_clear_chain_certs(c->ssl);
    X509 *extra;
    while ((extra = PEM_read_bio_X509(b, NULL, NULL, NULL))) {
        if (SSL_CTX_add0_chain_cert(c->ssl, extra) != 1) { // takes it on success
            X509_free(extra);
            BIO_free(b);
            describe(err, errlen, "certificate chain");
            return -1;
        }
    }
    BIO_free(b);
    ERR_clear_error(); // the end of the PEM data
    b = BIO_new_mem_buf(key_pem, key_len);
    EVP_PKEY *key = b ? PEM_read_bio_PrivateKey(b, NULL, NULL, NULL) : NULL;
    BIO_free(b);
    int ok = key && SSL_CTX_use_PrivateKey(c->ssl, key) == 1 && SSL_CTX_check_private_key(c->ssl) == 1;
    EVP_PKEY_free(key);
    if (!ok) {
        describe(err, errlen, "private key");
        return -1;
    }
    return 0;
}

int cv_tls_ctx_add_trust(cv_tls_ctx *c, const char *pem, int len, char *err, int errlen) {
    ERR_clear_error();
    X509_STORE *store = SSL_CTX_get_cert_store(c->ssl);
    BIO *b = BIO_new_mem_buf(pem, len);
    int n = 0;
    X509 *x;
    while (b && (x = PEM_read_bio_X509(b, NULL, NULL, NULL))) {
        if (X509_STORE_add_cert(store, x) == 1) n++;
        X509_free(x);
    }
    BIO_free(b);
    ERR_clear_error();
    if (n == 0) {
        snprintf(err, (size_t)errlen, "trust roots: no certificate in the PEM data");
        return -1;
    }
#if defined(OPENSSL_IS_BORINGSSL)
    // Trust a given leaf itself, as OpenSSL does: BoringSSL otherwise looks
    // for its issuer, and a self-signed leaf can't sign certificates.
    X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN);
#endif
    return 0;
}

#if defined(_WIN32)
/// The roots in Windows' certificate store, which OpenSSL doesn't read.
static int add_windows_roots(X509_STORE *store) {
    HCERTSTORE h = CertOpenSystemStoreW(0, L"ROOT");
    if (!h) return 0;
    int n = 0;
    PCCERT_CONTEXT cert = NULL;
    while ((cert = CertEnumCertificatesInStore(h, cert))) {
        const unsigned char *p = cert->pbCertEncoded;
        X509 *x = d2i_X509(NULL, &p, (long)cert->cbCertEncoded);
        if (x) {
            if (X509_STORE_add_cert(store, x) == 1) n++;
            X509_free(x);
        }
    }
    CertCloseStore(h, 0);
    ERR_clear_error(); // duplicates
    return n;
}
#endif

int cv_tls_ctx_use_system_trust(cv_tls_ctx *c, char *err, int errlen) {
    ERR_clear_error();
    int ok = SSL_CTX_set_default_verify_paths(c->ssl) == 1;
#if defined(_WIN32)
    ok = add_windows_roots(SSL_CTX_get_cert_store(c->ssl)) > 0 || ok;
#endif
    if (!ok) {
        describe(err, errlen, "system trust roots");
        return -1;
    }
    ERR_clear_error();
    return 0;
}

void cv_tls_ctx_set_verify(cv_tls_ctx *c, int mode) {
    c->verify = mode;
    int flags = SSL_VERIFY_NONE;
    if (mode != CV_TLS_VERIFY_NONE) flags = SSL_VERIFY_PEER;
    if (c->server && mode == CV_TLS_VERIFY_REQUIRED) flags |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    SSL_CTX_set_verify(c->ssl, flags, NULL);
}

int cv_tls_ctx_set_versions(cv_tls_ctx *c, int min, int max, char *err, int errlen) {
    ERR_clear_error();
    if (SSL_CTX_set_min_proto_version(c->ssl, min) != 1 || SSL_CTX_set_max_proto_version(c->ssl, max) != 1) {
        describe(err, errlen, "TLS versions");
        return -1;
    }
    return 0;
}

int cv_tls_ctx_set_ciphers(cv_tls_ctx *c, const char *list, char *err, int errlen) {
    ERR_clear_error();
    if (SSL_CTX_set_cipher_list(c->ssl, list) != 1) {
        describe(err, errlen, "TLS cipher list");
        return -1;
    }
    return 0;
}

int cv_tls_ctx_set_alpn(cv_tls_ctx *c, const uint8_t *wire, int len, char *err, int errlen) {
    ERR_clear_error();
    if (len <= 0) return 0;
    if (c->server) {
        unsigned char *copy = malloc((size_t)len);
        if (!copy) {
            snprintf(err, (size_t)errlen, "out of memory");
            return -1;
        }
        memcpy(copy, wire, (size_t)len);
        free(c->alpn);
        c->alpn = copy;
        c->alpn_len = (unsigned int)len;
        SSL_CTX_set_alpn_select_cb(c->ssl, alpn_select, c);
    } else if (SSL_CTX_set_alpn_protos(c->ssl, wire, (unsigned int)len) != 0) { // 0 is success here
        describe(err, errlen, "ALPN");
        return -1;
    }
    return 0;
}

int cv_tls_ctx_add_server_name(cv_tls_ctx *c, const char *name, cv_tls_ctx *other, char *err, int errlen) {
    if (c->name_count == MAX_NAMES) {
        snprintf(err, (size_t)errlen, "more than %d server names", MAX_NAMES);
        return -1;
    }
    char *copy = OPENSSL_strdup(name);
    if (!copy || SSL_CTX_up_ref(other->ssl) != 1) {
        OPENSSL_free(copy);
        snprintf(err, (size_t)errlen, "out of memory");
        return -1;
    }
    SSL_CTX_set_tlsext_servername_callback(c->ssl, servername_select);
    SSL_CTX_set_tlsext_servername_arg(c->ssl, c);
    c->names[c->name_count].name = copy;
    c->names[c->name_count].ssl = other->ssl;
    c->name_count++;
    return 0;
}

void cv_tls_ctx_set_session_cache(cv_tls_ctx *c, int entries) {
    if (c->server) return; // servers resume through stateless tickets
    for (int i = 0; i < c->cache_size; i++) {
        OPENSSL_free(c->cache[i].host);
        if (c->cache[i].session) SSL_SESSION_free(c->cache[i].session);
    }
    free(c->cache);
    c->cache = entries > 0 ? calloc((size_t)entries, sizeof *c->cache) : NULL;
    c->cache_size = c->cache ? entries : 0;
    if (c->cache_size) {
        SSL_CTX_set_session_cache_mode(c->ssl, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
        SSL_CTX_sess_set_new_cb(c->ssl, new_session);
    } else {
        SSL_CTX_set_session_cache_mode(c->ssl, SSL_SESS_CACHE_OFF);
    }
}

/// Take the session cached for host, if any: TLS 1.3 tickets are for one
/// use, and the new connection is sent fresh ones.
static SSL_SESSION *take_session(cv_tls_ctx *c, const char *host) {
    SSL_SESSION *s = NULL;
    if (c->cache_size == 0) return NULL;
    CRYPTO_THREAD_write_lock(c->lock);
    for (int i = 0; i < c->cache_size; i++) {
        if (c->cache[i].host && strcmp(c->cache[i].host, host) == 0) {
            s = c->cache[i].session;
            c->cache[i].session = NULL;
            OPENSSL_free(c->cache[i].host);
            c->cache[i].host = NULL;
            break;
        }
    }
    CRYPTO_THREAD_unlock(c->lock);
    return s;
}

// MARK: - Kernel TLS
//
// After the handshake the kernel can take over a direction's records
// (TCP_ULP "tls", then TLS_TX or TLS_RX): it is handed that direction's key,
// IV and next sequence number, and from then on the socket carries
// plaintext for this process. The engine runs over a BIO of our own, so
// OpenSSL's own kernel TLS, which needs its socket BIO, is out of reach, and
// BoringSSL has none. Both libraries give the secrets, though: TLS 1.3's
// application traffic secrets through the key log, expanded here into key
// and IV (RFC 8446 7.3), and TLS 1.2's master secret, expanded into the key
// block (RFC 5246 6.3). BoringSSL says the sequence numbers; with OpenSSL they
// are counted, from the records that went through the BIO since the key took
// effect: that is why the BIO watches record boundaries while a connection
// may still hand a direction over.
#if CV_KTLS
/// Records one way, counted as their bytes pass the BIO.
struct cv_records {
    uint64_t count;     // whole records
    uint64_t since_ccs; // whole records since the last ChangeCipherSpec
    uint8_t head[5];
    int head_len; // header bytes of the record under way
    size_t left;  // its body bytes still to come
    int type;
};

struct cv_ktls {
    int want;        // CV_KTLS_TX | CV_KTLS_RX
    int on;          // the directions the kernel has
    int stale;       // directions the engine rekeyed (KeyUpdate) before the kernel took them
    int update_owed; // the peer asked for our KeyUpdate: the kernel's to send
    struct cv_records tx, rx;
    uint64_t tx_base, rx_base; // TLS 1.3: counts when the application keys took effect
    int tx_based;
    uint8_t tx_secret[48], rx_secret[48]; // TLS 1.3 application traffic secrets
    size_t tx_secret_len, rx_secret_len;
};

static void record_done(struct cv_records *r) {
    r->count++;
    r->since_ccs = r->type == 20 ? 0 : r->since_ccs + 1;
}

static void records_track(struct cv_records *r, const unsigned char *p, size_t n) {
    while (n > 0) {
        if (r->left > 0) {
            size_t m = n < r->left ? n : r->left;
            r->left -= m;
            p += m;
            n -= m;
            if (r->left == 0) record_done(r);
            continue;
        }
        r->head[r->head_len++] = *p++;
        n--;
        if (r->head_len == 5) {
            r->type = r->head[0];
            r->left = (size_t)r->head[3] << 8 | r->head[4];
            r->head_len = 0;
            if (r->left == 0) record_done(r);
        }
    }
}

static inline int records_whole(const struct cv_records *r) { return r->head_len == 0 && r->left == 0; }

static void ktls_track_in(cv_tls *t, const unsigned char *p, size_t n) {
    if (!(t->k->on & CV_KTLS_RX)) records_track(&t->k->rx, p, n);
}

/// 1: the kernel sends now, and the engine's output is dropped.
static int ktls_track_out(cv_tls *t, const char *p, size_t n) {
    if (t->k->on & CV_KTLS_TX) return 1;
    records_track(&t->k->tx, (const unsigned char *)p, n);
    return 0;
}

/// TLS 1.3 records the peer sends after its Finished are under the
/// application key, and the handshake has read nothing past that Finished.
static void ktls_handshake_done(cv_tls *t) { t->k->rx_base = t->k->rx.count; }

static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/// "LABEL <client random> <secret>": keep the application traffic secrets.
/// OpenSSL logs our direction's secret as its key takes effect, so the
/// records written by then are the ones under earlier keys.
static void keylog(const SSL *ssl, const char *line) {
    cv_tls *t = SSL_get_app_data(ssl);
    if (!t || !t->k) return;
    static const char client[] = "CLIENT_TRAFFIC_SECRET_0 ", server[] = "SERVER_TRAFFIC_SECRET_0 ";
    int ours;
    if (strncmp(line, client, sizeof client - 1) == 0)
        ours = !t->ctx->server;
    else if (strncmp(line, server, sizeof server - 1) == 0)
        ours = t->ctx->server;
    else
        return;
    const char *p = strchr(line + sizeof client - 1, ' ');
    if (!p) return;
    p++;
    uint8_t secret[48];
    size_t n = 0;
    while (n < sizeof secret && hex_digit(p[0]) >= 0 && hex_digit(p[1]) >= 0) {
        secret[n++] = (uint8_t)(hex_digit(p[0]) << 4 | hex_digit(p[1]));
        p += 2;
    }
    struct cv_ktls *k = t->k;
    if (n == 32 || n == 48) {
        if (ours) {
            memcpy(k->tx_secret, secret, n);
            k->tx_secret_len = n;
            k->tx_base = k->tx.count;
            k->tx_based = 1;
        } else {
            memcpy(k->rx_secret, secret, n);
            k->rx_secret_len = n;
        }
    }
    OPENSSL_cleanse(secret, sizeof secret);
}

/// Handshake messages the engine sends and reads: a KeyUpdate before the
/// kernel has a direction leaves what we know of that direction's key
/// stale; one the peer sends asking for ours, once the kernel sends, is
/// the kernel's to answer.
static void ktls_message(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl,
                         void *arg) {
    (void)version;
    (void)arg;
    const uint8_t *m = buf;
    if (content_type != SSL3_RT_HANDSHAKE || len < 1 || m[0] != 24) return; // KeyUpdate
    cv_tls *t = SSL_get_app_data(ssl);
    if (!t || !t->k) return;
    struct cv_ktls *k = t->k;
    if (write_p) {
        if (!(k->on & CV_KTLS_TX)) k->stale |= CV_KTLS_TX;
    } else {
        if (!(k->on & CV_KTLS_RX)) k->stale |= CV_KTLS_RX;
        if ((k->on & CV_KTLS_TX) && len >= 5 && m[4] == 1) __atomic_store_n(&k->update_owed, 1, __ATOMIC_RELEASE);
    }
}

void cv_tls_ctx_set_ktls(cv_tls_ctx *c) { SSL_CTX_set_keylog_callback(c->ssl, keylog); }

void cv_tls_ktls_want(cv_tls *t, int directions) {
    if (t->k || !(directions & CV_KTLS_TX)) return;
    t->k = calloc(1, sizeof *t->k);
    if (!t->k) return;
    t->k->want = directions & (CV_KTLS_TX | CV_KTLS_RX);
    SSL_set_msg_callback(t->ssl, ktls_message);
}

/// No kernel TLS for this connection after all: stop watching for it.
static void ktls_drop(cv_tls *t) {
    if (!t->k) return;
    SSL_set_msg_callback(t->ssl, NULL);
    OPENSSL_cleanse(t->k, sizeof *t->k);
    free(t->k);
    t->k = NULL;
}

int cv_tls_ktls_state(cv_tls *t) { return t->k ? t->k->on : 0; }

intptr_t cv_tls_ktls_rx_short(cv_tls *t) {
    struct cv_ktls *k = t->k;
    if (!k || (k->on & CV_KTLS_RX) || !(k->want & CV_KTLS_RX)) return 0;
    return k->rx.head_len ? 5 - k->rx.head_len : (intptr_t)k->rx.left;
}

/// The suites the kernel takes, by IANA number: the AEAD, its key length,
/// the IV the key schedule makes (TLS 1.2's AES-GCM makes only the 4-byte
/// salt, and sends the rest of the nonce), and SHA-384 or SHA-256.
static const struct ktls_suite {
    uint16_t id, cipher;
    uint8_t key_len, iv_len, sha384;
} ktls_suites[] = {
    {0x1301, TLS_CIPHER_AES_GCM_128, 16, 12, 0},       // TLS_AES_128_GCM_SHA256
    {0x1302, TLS_CIPHER_AES_GCM_256, 32, 12, 1},       // TLS_AES_256_GCM_SHA384
    {0x1303, TLS_CIPHER_CHACHA20_POLY1305, 32, 12, 0}, // TLS_CHACHA20_POLY1305_SHA256
    {0xC02B, TLS_CIPHER_AES_GCM_128, 16, 4, 0},        // ECDHE-ECDSA-AES128-GCM-SHA256
    {0xC02F, TLS_CIPHER_AES_GCM_128, 16, 4, 0},        // ECDHE-RSA-AES128-GCM-SHA256
    {0x009C, TLS_CIPHER_AES_GCM_128, 16, 4, 0},        // AES128-GCM-SHA256
    {0x009E, TLS_CIPHER_AES_GCM_128, 16, 4, 0},        // DHE-RSA-AES128-GCM-SHA256
    {0xC02C, TLS_CIPHER_AES_GCM_256, 32, 4, 1},        // ECDHE-ECDSA-AES256-GCM-SHA384
    {0xC030, TLS_CIPHER_AES_GCM_256, 32, 4, 1},        // ECDHE-RSA-AES256-GCM-SHA384
    {0x009D, TLS_CIPHER_AES_GCM_256, 32, 4, 1},        // AES256-GCM-SHA384
    {0x009F, TLS_CIPHER_AES_GCM_256, 32, 4, 1},        // DHE-RSA-AES256-GCM-SHA384
    {0xCCA8, TLS_CIPHER_CHACHA20_POLY1305, 32, 12, 0}, // ECDHE-RSA-CHACHA20-POLY1305
    {0xCCA9, TLS_CIPHER_CHACHA20_POLY1305, 32, 12, 0}, // ECDHE-ECDSA-CHACHA20-POLY1305
    {0xCCAA, TLS_CIPHER_CHACHA20_POLY1305, 32, 12, 0}, // DHE-RSA-CHACHA20-POLY1305
};

static const struct ktls_suite *ktls_suite(cv_tls *t, int *v13) {
    int v = SSL_version(t->ssl);
    if (v != TLS1_2_VERSION && v != TLS1_3_VERSION) return NULL;
    *v13 = v == TLS1_3_VERSION;
    const SSL_CIPHER *c = SSL_get_current_cipher(t->ssl);
    if (!c) return NULL;
    uint16_t id = SSL_CIPHER_get_protocol_id(c);
    for (size_t i = 0; i < sizeof ktls_suites / sizeof ktls_suites[0]; i++) {
        if (ktls_suites[i].id == id && ((id >> 8) == 0x13) == *v13) return &ktls_suites[i];
    }
    return NULL;
}

/// HKDF-Expand-Label(secret, label, "", out_len): RFC 8446 7.1.
static int hkdf_expand_label(const EVP_MD *md, const uint8_t *secret, size_t secret_len, const char *label,
                             uint8_t *out, size_t out_len) {
    uint8_t info[4 + 6 + 32];
    size_t label_len = strlen(label), n = 0;
    if (label_len > 32 || out_len > 255 * (size_t)EVP_MD_size(md)) return 0;
    info[n++] = (uint8_t)(out_len >> 8);
    info[n++] = (uint8_t)out_len;
    info[n++] = (uint8_t)(6 + label_len);
    memcpy(info + n, "tls13 ", 6);
    n += 6;
    memcpy(info + n, label, label_len);
    n += label_len;
    info[n++] = 0; // no context
    // HKDF-Expand: T(i) = HMAC(secret, T(i-1) | info | i).
    uint8_t block[EVP_MAX_MD_SIZE], in[EVP_MAX_MD_SIZE + sizeof info + 1];
    unsigned int block_len = 0;
    int ok = 1;
    for (size_t done = 0, i = 1; done < out_len; i++) {
        size_t m = block_len;
        memcpy(in, block, block_len);
        memcpy(in + m, info, n);
        m += n;
        in[m++] = (uint8_t)i;
        if (!HMAC(md, secret, (int)secret_len, in, m, block, &block_len)) {
            ok = 0;
            break;
        }
        size_t take = out_len - done < block_len ? out_len - done : block_len;
        memcpy(out + done, block, take);
        done += take;
    }
    OPENSSL_cleanse(block, sizeof block);
    OPENSSL_cleanse(in, sizeof in);
    return ok;
}

/// TLS 1.2's PRF(secret, label, seed) over md: RFC 5246 5.
static int tls12_prf(const EVP_MD *md, const uint8_t *secret, size_t secret_len, const char *label,
                     const uint8_t *seed, size_t seed_len, uint8_t *out, size_t out_len) {
    uint8_t ls[32 + 64], a[EVP_MAX_MD_SIZE], in[EVP_MAX_MD_SIZE + sizeof ls], block[EVP_MAX_MD_SIZE];
    size_t label_len = strlen(label);
    if (label_len + seed_len > sizeof ls) return 0;
    memcpy(ls, label, label_len);
    memcpy(ls + label_len, seed, seed_len);
    size_t ls_len = label_len + seed_len;
    unsigned int a_len = 0, block_len = 0;
    int ok = HMAC(md, secret, (int)secret_len, ls, ls_len, a, &a_len) != NULL; // A(1)
    for (size_t done = 0; ok && done < out_len;) {
        memcpy(in, a, a_len);
        memcpy(in + a_len, ls, ls_len);
        if (!HMAC(md, secret, (int)secret_len, in, a_len + ls_len, block, &block_len)) {
            ok = 0;
            break;
        }
        size_t take = out_len - done < block_len ? out_len - done : block_len;
        memcpy(out + done, block, take);
        done += take;
        memcpy(in, a, a_len);
        ok = HMAC(md, secret, (int)secret_len, in, a_len, a, &a_len) != NULL; // A(i+1)
    }
    OPENSSL_cleanse(a, sizeof a);
    OPENSSL_cleanse(in, sizeof in);
    OPENSSL_cleanse(block, sizeof block);
    return ok;
}

/// The key and IV one way: ours (tx) or the peer's.
static int ktls_keys(cv_tls *t, const struct ktls_suite *s, int v13, int tx, uint8_t *key, uint8_t *iv) {
    const EVP_MD *md = s->sha384 ? EVP_sha384() : EVP_sha256();
    struct cv_ktls *k = t->k;
    if (v13) {
        const uint8_t *secret = tx ? k->tx_secret : k->rx_secret;
        size_t n = tx ? k->tx_secret_len : k->rx_secret_len;
        if (n != (size_t)EVP_MD_size(md)) return 0;
        return hkdf_expand_label(md, secret, n, "key", key, s->key_len) &&
               hkdf_expand_label(md, secret, n, "iv", iv, s->iv_len);
    }
    // The key block: client_write_key, server_write_key, client_write_IV,
    // server_write_IV (an AEAD has no MAC keys).
    uint8_t master[48], seed[64], block[2 * 32 + 2 * 12];
    SSL_SESSION *session = SSL_get_session(t->ssl);
    int ok = session && SSL_SESSION_get_master_key(session, master, sizeof master) == sizeof master &&
             SSL_get_server_random(t->ssl, seed, 32) == 32 && SSL_get_client_random(t->ssl, seed + 32, 32) == 32 &&
             tls12_prf(md, master, sizeof master, "key expansion", seed, sizeof seed, block,
                       2 * (size_t)s->key_len + 2 * (size_t)s->iv_len);
    if (ok) {
        int client = tx == !t->ctx->server; // the client's keys, or the server's
        memcpy(key, block + (client ? 0 : s->key_len), s->key_len);
        memcpy(iv, block + 2 * s->key_len + (client ? 0 : s->iv_len), s->iv_len);
    }
    OPENSSL_cleanse(master, sizeof master);
    OPENSSL_cleanse(block, sizeof block);
    return ok;
}

/// The sequence number of the next record one way.
static int ktls_sequence(cv_tls *t, int v13, int tx, uint64_t *seq) {
#if defined(OPENSSL_IS_BORINGSSL)
    (void)v13;
    *seq = tx ? SSL_get_write_sequence(t->ssl) : SSL_get_read_sequence(t->ssl);
    return 1;
#else
    struct cv_ktls *k = t->k;
    if (!v13) {
        // TLS 1.2's keys take effect after a ChangeCipherSpec.
        *seq = tx ? k->tx.since_ccs : k->rx.since_ccs;
        return 1;
    }
    if (tx) {
        if (!k->tx_based) return 0;
        *seq = k->tx.count - k->tx_base;
    } else {
        *seq = k->rx.count - k->rx_base;
    }
    return 1;
#endif
}

/// Hand one direction to the kernel: 0, or -errno.
static int ktls_install(int fd, int direction, const struct ktls_suite *s, int v13, const uint8_t *key,
                        const uint8_t *iv, uint64_t seq) {
    union {
        struct tls12_crypto_info_aes_gcm_128 g128;
        struct tls12_crypto_info_aes_gcm_256 g256;
        struct tls12_crypto_info_chacha20_poly1305 chacha;
    } info;
    memset(&info, 0, sizeof info);
    uint8_t rec_seq[8];
    for (int i = 0; i < 8; i++) rec_seq[i] = (uint8_t)(seq >> (56 - 8 * i));
    uint16_t version = v13 ? TLS_1_3_VERSION : TLS_1_2_VERSION;
    socklen_t size = 0;
    // AES-GCM: a 4-byte salt, then 8 bytes of nonce. TLS 1.3 makes all 12
    // from the IV; TLS 1.2 sends the 8 with each record, here the sequence
    // number, as OpenSSL and BoringSSL do.
    switch (s->cipher) {
    case TLS_CIPHER_AES_GCM_128:
        info.g128.info.version = version;
        info.g128.info.cipher_type = s->cipher;
        memcpy(info.g128.key, key, 16);
        memcpy(info.g128.salt, iv, 4);
        memcpy(info.g128.iv, v13 ? iv + 4 : rec_seq, 8);
        memcpy(info.g128.rec_seq, rec_seq, 8);
        size = sizeof info.g128;
        break;
    case TLS_CIPHER_AES_GCM_256:
        info.g256.info.version = version;
        info.g256.info.cipher_type = s->cipher;
        memcpy(info.g256.key, key, 32);
        memcpy(info.g256.salt, iv, 4);
        memcpy(info.g256.iv, v13 ? iv + 4 : rec_seq, 8);
        memcpy(info.g256.rec_seq, rec_seq, 8);
        size = sizeof info.g256;
        break;
    default: // ChaCha20-Poly1305: all 12 bytes of IV, in both versions
        info.chacha.info.version = version;
        info.chacha.info.cipher_type = s->cipher;
        memcpy(info.chacha.key, key, 32);
        memcpy(info.chacha.iv, iv, 12);
        memcpy(info.chacha.rec_seq, rec_seq, 8);
        size = sizeof info.chacha;
        break;
    }
    int r = setsockopt(fd, SOL_TLS, direction, &info, size) == 0 ? 0 : -errno;
    OPENSSL_cleanse(&info, sizeof info);
    return r;
}

/// Hand a direction to the kernel at the key and record the engine is at.
static int ktls_direction(cv_tls *t, int fd, int tx) {
    int v13 = 0;
    const struct ktls_suite *s = ktls_suite(t, &v13);
    uint8_t key[32], iv[12];
    uint64_t seq = 0;
    int r = -ENOTSUP;
    if (s && ktls_sequence(t, v13, tx, &seq) && ktls_keys(t, s, v13, tx, key, iv))
        r = ktls_install(fd, tx ? TLS_TX : TLS_RX, s, v13, key, iv, seq);
    OPENSSL_cleanse(key, sizeof key);
    OPENSSL_cleanse(iv, sizeof iv);
    ERR_clear_error();
    return r;
}

int cv_tls_ktls_enable_tx(cv_tls *t, int fd) {
    struct cv_ktls *k = t->k;
    if (!k) return 0;
    if (k->on & CV_KTLS_TX) return 1;
    // All our ciphertext sent, in whole records, and the key the handshake
    // made still ours: else the connection stays in userspace.
    int v13 = 0;
    if (!(k->stale & CV_KTLS_TX) && !t->out.len && !t->taken.p && records_whole(&k->tx) && ktls_suite(t, &v13)) {
        int ulp = setsockopt(fd, IPPROTO_TCP, TCP_ULP, "tls", sizeof "tls") == 0 || errno == EEXIST;
        if (ulp && ktls_direction(t, fd, 1) == 0) {
            k->on |= CV_KTLS_TX;
            return 1;
        }
    }
    ktls_drop(t);
    return 0;
}

int cv_tls_ktls_enable_rx(cv_tls *t, int fd) {
    struct cv_ktls *k = t->k;
    if (!k || !(k->on & CV_KTLS_TX) || !(k->want & CV_KTLS_RX) || (k->stale & CV_KTLS_RX)) return -1;
    if (k->on & CV_KTLS_RX) return 1;
    // Not while the engine holds part of a record or plaintext not yet
    // read: the kernel must start at a record's first byte.
    if (!records_whole(&k->rx) || SSL_has_pending(t->ssl) || t->eof) return 0;
    // A TLS 1.3 client keeping sessions waits for a record after the
    // handshake: the server's tickets come first, and the kernel would only
    // hand them over.
    if (SSL_version(t->ssl) == TLS1_3_VERSION && !t->ctx->server && t->ctx->cache_size > 0 &&
        k->rx.count == k->rx_base)
        return 0;
    if (ktls_direction(t, fd, 0) != 0) {
        k->want &= ~CV_KTLS_RX;
        return -1;
    }
    k->on |= CV_KTLS_RX;
    return 1;
}

int cv_tls_ktls_update(cv_tls *t, int fd, int tx) {
    struct cv_ktls *k = t->k;
    int v13 = 0;
    const struct ktls_suite *s = k ? ktls_suite(t, &v13) : NULL;
    if (!s || !v13 || !(k->on & (tx ? CV_KTLS_TX : CV_KTLS_RX))) return -EINVAL;
    const EVP_MD *md = s->sha384 ? EVP_sha384() : EVP_sha256();
    uint8_t *secret = tx ? k->tx_secret : k->rx_secret;
    size_t n = tx ? k->tx_secret_len : k->rx_secret_len;
    // RFC 8446 7.2: the next secret, its key and IV, sequence numbers from 0.
    uint8_t next[48], key[32], iv[12];
    int r = -EINVAL;
    if (n <= sizeof next && hkdf_expand_label(md, secret, n, "traffic upd", next, n)) {
        memcpy(secret, next, n);
        if (hkdf_expand_label(md, secret, n, "key", key, s->key_len) &&
            hkdf_expand_label(md, secret, n, "iv", iv, s->iv_len))
            r = ktls_install(fd, tx ? TLS_TX : TLS_RX, s, 1, key, iv, 0);
    }
    OPENSSL_cleanse(next, sizeof next);
    OPENSSL_cleanse(key, sizeof key);
    OPENSSL_cleanse(iv, sizeof iv);
    ERR_clear_error();
    return r;
}

void cv_tls_ktls_owe_update(cv_tls *t) {
    if (t->k) __atomic_store_n(&t->k->update_owed, 1, __ATOMIC_RELEASE);
}

int cv_tls_ktls_take_owed_update(cv_tls *t) {
    return t->k && __atomic_load_n(&t->k->update_owed, __ATOMIC_ACQUIRE) &&
           __atomic_exchange_n(&t->k->update_owed, 0, __ATOMIC_ACQ_REL);
}

intptr_t cv_ktls_send_record(int fd, int type, const void *buf, intptr_t len) {
    union {
        char buf[CMSG_SPACE(sizeof(unsigned char))];
        struct cmsghdr align;
    } control;
    memset(&control, 0, sizeof control);
    struct iovec iov = {(void *)buf, (size_t)len};
    struct msghdr mh;
    memset(&mh, 0, sizeof mh);
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control = control.buf;
    mh.msg_controllen = sizeof control.buf;
    struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
    c->cmsg_level = SOL_TLS;
    c->cmsg_type = TLS_SET_RECORD_TYPE;
    c->cmsg_len = CMSG_LEN(sizeof(unsigned char));
    *CMSG_DATA(c) = (unsigned char)type;
    mh.msg_controllen = c->cmsg_len;
    ssize_t n = sendmsg(fd, &mh, MSG_DONTWAIT | MSG_NOSIGNAL);
    return n >= 0 ? (intptr_t)n : -(intptr_t)errno;
}

/// recvmsg, with room for the record's type.
static ssize_t recv_typed(int fd, void *buf, size_t len, int flags, int *type) {
    union {
        char buf[CMSG_SPACE(sizeof(unsigned char))];
        struct cmsghdr align;
    } control;
    struct iovec iov = {buf, len};
    struct msghdr mh;
    memset(&mh, 0, sizeof mh);
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control = control.buf;
    mh.msg_controllen = sizeof control.buf;
    *type = 0;
    ssize_t n = recvmsg(fd, &mh, flags | MSG_DONTWAIT);
    if (n < 0) return -errno;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh); c; c = CMSG_NXTHDR(&mh, c)) {
        if (c->cmsg_level == SOL_TLS && c->cmsg_type == TLS_GET_RECORD_TYPE) *type = *CMSG_DATA(c);
    }
    return n;
}

intptr_t cv_ktls_recv_record(int fd, void *buf, intptr_t len, int *type) {
    // A look first: application data is left for the plain reads.
    ssize_t n = recv_typed(fd, buf, (size_t)len, MSG_PEEK, type);
    if (n <= 0) return n;
    if (*type == 23) return 0;
    return recv_typed(fd, buf, (size_t)len, 0, type);
}
#else
void cv_tls_ctx_set_ktls(cv_tls_ctx *c) { (void)c; }
void cv_tls_ktls_want(cv_tls *t, int directions) {
    (void)t;
    (void)directions;
}
int cv_tls_ktls_state(cv_tls *t) {
    (void)t;
    return 0;
}
intptr_t cv_tls_ktls_rx_short(cv_tls *t) {
    (void)t;
    return 0;
}
int cv_tls_ktls_enable_tx(cv_tls *t, int fd) {
    (void)t;
    (void)fd;
    return 0;
}
int cv_tls_ktls_enable_rx(cv_tls *t, int fd) {
    (void)t;
    (void)fd;
    return -1;
}
int cv_tls_ktls_update(cv_tls *t, int fd, int tx) {
    (void)t;
    (void)fd;
    (void)tx;
    return -1;
}
void cv_tls_ktls_owe_update(cv_tls *t) { (void)t; }
int cv_tls_ktls_take_owed_update(cv_tls *t) {
    (void)t;
    return 0;
}
intptr_t cv_ktls_send_record(int fd, int type, const void *buf, intptr_t len) {
    (void)fd;
    (void)type;
    (void)buf;
    (void)len;
    return -1;
}
intptr_t cv_ktls_recv_record(int fd, void *buf, intptr_t len, int *type) {
    (void)fd;
    (void)buf;
    (void)len;
    *type = 0;
    return -1;
}
#endif

// MARK: - The BIO

/// Room for `more` bytes after the ones in o. Sizes go 4.25 KiB, 8.5, 17,
/// 34, 68: 17 KiB holds a full record (16 KiB of plaintext, and well under
/// 256 bytes of framing), and 68 KiB the four records of a 64 KiB write
/// where powers of two would take 128.
static int out_reserve(struct cv_out *o, size_t more) {
    if (o->cap - o->len >= more) return 1;
    size_t cap = o->cap ? o->cap : 4352;
    while (cap - o->len < more) cap *= 2;
    unsigned char *p = realloc(o->p, cap);
    if (!p) return 0;
    o->p = p;
    o->cap = cap;
    return 1;
}

/// The peer's ciphertext: what the call in progress was handed, then "retry"
/// (SSL_ERROR_WANT_READ), or 0 at the end the Swift side reported.
static int bio_read(BIO *b, char *buf, int len) {
    cv_tls *t = BIO_get_data(b);
    BIO_clear_retry_flags(b);
    if (len <= 0) return 0;
    if (t->in_len == 0) {
        if (t->eof) return 0;
        BIO_set_retry_read(b);
        return -1;
    }
    size_t n = (size_t)len < t->in_len ? (size_t)len : t->in_len;
    memcpy(buf, t->in, n);
#if CV_KTLS
    if (t->k) ktls_track_in(t, t->in, n);
#endif
    t->in += n;
    t->in_len -= n;
    return (int)n;
}

/// Ciphertext for the peer: always all of it, into t->out.
static int bio_write(BIO *b, const char *buf, int len) {
    cv_tls *t = BIO_get_data(b);
    BIO_clear_retry_flags(b);
    if (len <= 0) return 0;
#if CV_KTLS
    // The kernel encrypts now: what the engine still writes (a KeyUpdate's
    // answer, an alert) is its own business, and goes nowhere.
    if (t->k && ktls_track_out(t, buf, (size_t)len)) return len;
#endif
    if (!out_reserve(&t->out, (size_t)len)) return -1; // out of memory: the engine fails the call
    memcpy(t->out.p + t->out.len, buf, (size_t)len);
    t->out.len += (size_t)len;
    return len;
}

/// OpenSSL 3.0 asks this some nine times a record written and three times
/// one read, nearly always whether the BIO does kernel TLS (it doesn't), so
/// the answers that need the connection fetch it themselves.
static long bio_ctrl(BIO *b, int cmd, long num, void *ptr) {
    (void)num;
    (void)ptr;
    switch (cmd) {
    case BIO_CTRL_FLUSH: return 1; // the engine flushes after a flight
    case BIO_CTRL_EOF: { // how OpenSSL tells a truncation
        cv_tls *t = BIO_get_data(b);
        return t->eof && t->in_len == 0;
    }
    case BIO_CTRL_PENDING: return (long)((cv_tls *)BIO_get_data(b))->in_len;
    case BIO_CTRL_WPENDING: return (long)((cv_tls *)BIO_get_data(b))->out.len;
    default: return 0;
    }
}

static BIO_METHOD *bio_method;

static void make_bio_method(void) {
    int index = BIO_get_new_index();
    BIO_METHOD *m = BIO_meth_new((index > 0 ? index : 0) | BIO_TYPE_SOURCE_SINK, "vega");
    if (m && BIO_meth_set_read(m, bio_read) == 1 && BIO_meth_set_write(m, bio_write) == 1 &&
        BIO_meth_set_ctrl(m, bio_ctrl) == 1) {
        bio_method = m;
        return;
    }
    if (m) BIO_meth_free(m);
}

#if defined(OPENSSL_IS_BORINGSSL) && defined(_WIN32)
static INIT_ONCE bio_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK bio_method_init(PINIT_ONCE once, PVOID param, PVOID *context) {
    (void)once;
    (void)param;
    (void)context;
    make_bio_method();
    return TRUE;
}
static void bio_method_once(void) { InitOnceExecuteOnce(&bio_once, bio_method_init, NULL, NULL); }
#elif defined(OPENSSL_IS_BORINGSSL)
static pthread_once_t bio_once = PTHREAD_ONCE_INIT;
static void bio_method_once(void) { pthread_once(&bio_once, make_bio_method); }
#else
static CRYPTO_ONCE bio_once = CRYPTO_ONCE_STATIC_INIT;
static void bio_method_once(void) { CRYPTO_THREAD_run_once(&bio_once, make_bio_method); }
#endif

// MARK: - Connections

cv_tls *cv_tls_new(cv_tls_ctx *c, const char *host, char *err, int errlen) {
    ERR_clear_error();
    bio_method_once();
    cv_tls *t = calloc(1, sizeof *t);
    if (!t) {
        snprintf(err, (size_t)errlen, "out of memory");
        return NULL;
    }
    t->ctx = c;
    t->ssl = SSL_new(c->ssl);
    BIO *bio = bio_method ? BIO_new(bio_method) : NULL;
    if (!t->ssl || !bio) {
        describe(err, errlen, "SSL_new");
        BIO_free(bio);
        SSL_free(t->ssl);
        free(t);
        return NULL;
    }
    BIO_set_data(bio, t);
    BIO_set_init(bio, 1);
    SSL_set_bio(t->ssl, bio, bio); // one reference, for both directions
    SSL_set_app_data(t->ssl, t);
    // The engine's record buffers go while it holds nothing in them: an
    // idle connection keeps none.
    SSL_set_mode(t->ssl, SSL_MODE_RELEASE_BUFFERS);
    if (c->server) {
        SSL_set_accept_state(t->ssl);
        return t;
    }
    SSL_set_connect_state(t->ssl);
    if (host && *host) {
        t->host = OPENSSL_strdup(host);
        X509_VERIFY_PARAM *param = SSL_get0_param(t->ssl);
        // An IP address is checked as one, and isn't sent as SNI.
        int ip = X509_VERIFY_PARAM_set1_ip_asc(param, host) == 1;
        ERR_clear_error();
        if (!ip) {
            if (SSL_set_tlsext_host_name(t->ssl, host) != 1 ||
                (c->verify != CV_TLS_VERIFY_NONE && SSL_set1_host(t->ssl, host) != 1)) {
                describe(err, errlen, "server name");
                cv_tls_free(t);
                return NULL;
            }
        }
        SSL_SESSION *s = take_session(c, host);
        if (s) {
            SSL_set_session(t->ssl, s);
            SSL_SESSION_free(s);
        }
    }
    return t;
}

void cv_tls_free(cv_tls *t) {
    if (!t) return;
#if CV_KTLS
    if (t->k) {
        OPENSSL_cleanse(t->k, sizeof *t->k);
        free(t->k);
    }
#endif
    SSL_free(t->ssl); // and the BIO
    OPENSSL_free(t->host);
    free(t->out.p);
    free(t->taken.p);
    free(t);
}

void cv_tls_feed_eof(cv_tls *t) { t->eof = 1; }

const uint8_t *cv_tls_take_output(cv_tls *t, intptr_t *len) {
    *len = 0;
    if (t->out.len == 0 || t->taken.p) return NULL;
    t->taken = t->out;
    t->out = (struct cv_out){0};
    *len = (intptr_t)t->taken.len;
    return t->taken.p;
}

void cv_tls_return_output(cv_tls *t) {
    if (!t->taken.p) return;
    if (!t->out.p) {
        // The usual case: use it again.
        t->out.p = t->taken.p;
        t->out.cap = t->taken.cap;
        t->out.len = 0;
    } else {
        // The engine wrote more meanwhile (for the other half of a split
        // stream), into a buffer of its own: keep that one.
        free(t->taken.p);
    }
    t->taken = (struct cv_out){0};
}

void cv_tls_release_idle(cv_tls *t) {
    if (t->out.len || t->taken.p || !t->out.p) return;
    free(t->out.p);
    t->out = (struct cv_out){0};
}

/// A call's start: the peer's ciphertext it may take from, and an error
/// queue SSL_get_error can trust.
static inline void enter(cv_tls *t, const void *in, intptr_t in_len) {
    t->in = in;
    t->in_len = in && in_len > 0 ? (size_t)in_len : 0;
    clean_queue();
}

/// A call's end: what it took and left, and no pointer kept into the input.
static inline void leave(cv_tls *t, intptr_t in_len, cv_tls_status *st) {
    st->used = (t->in ? in_len : 0) - (intptr_t)t->in_len;
    st->pending = (intptr_t)t->out.len;
    t->in = NULL;
    t->in_len = 0;
}

static int handshake_step(cv_tls *t) {
    int r = SSL_do_handshake(t->ssl);
    if (r == 1) return 1;
    int e = SSL_get_error(t->ssl, r);
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) return CV_TLS_WANT_READ;
    if (e == SSL_ERROR_SYSCALL || e == SSL_ERROR_ZERO_RETURN) {
        snprintf(t->err, sizeof t->err, "handshake: the peer closed the connection");
        ERR_clear_error();
        return CV_TLS_ERROR;
    }
    record_error(t, "handshake");
    return CV_TLS_ERROR;
}

int cv_tls_handshake(cv_tls *t, const void *in, intptr_t in_len, cv_tls_status *st) {
    enter(t, in, in_len);
    int r = handshake_step(t);
#if CV_KTLS
    if (r == 1 && t->k) ktls_handshake_done(t);
#endif
    st->drained = 0;
    leave(t, in_len, st);
    return r;
}

static intptr_t read_step(cv_tls *t, void *buf, intptr_t len, int *drained) {
    *drained = 0;
    size_t n = 0;
#if defined(OPENSSL_IS_BORINGSSL)
    // SSL_get_error needs SSL_read's own result here: 0 is a close
    // (close_notify or EOF), -1 is "retry" or an error.
    int r = SSL_read(t->ssl, buf, len > INT_MAX ? INT_MAX : (int)len);
    if (r > 0) n = (size_t)r;
#else
    int r = SSL_read_ex(t->ssl, buf, (size_t)len, &n); // 1, or 0 to give SSL_get_error
#endif
    if (r > 0) {
        // Nothing left of the input and nothing buffered, decrypted or not:
        // the engine can't make progress until it's given more, so the
        // next read can go to the transport first.
        *drained = t->in_len == 0 && !SSL_has_pending(t->ssl);
        return (intptr_t)n;
    }
    switch (SSL_get_error(t->ssl, r)) {
    case SSL_ERROR_ZERO_RETURN: return 0;
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE: return CV_TLS_WANT_READ; // the BIO said "retry": all input taken
    case SSL_ERROR_SYSCALL:
        ERR_clear_error();
        return CV_TLS_TRUNCATED;
    default:
        if (ERR_GET_REASON(ERR_peek_last_error()) == SSL_R_UNEXPECTED_EOF_WHILE_READING) {
            ERR_clear_error();
            return CV_TLS_TRUNCATED;
        }
        record_error(t, "read");
        return CV_TLS_ERROR;
    }
}

intptr_t cv_tls_read(cv_tls *t, const void *in, intptr_t in_len, void *buf, intptr_t len, cv_tls_status *st) {
    enter(t, in, in_len);
    intptr_t r = read_step(t, buf, len, &st->drained);
    leave(t, in_len, st);
    return r;
}

intptr_t cv_tls_write(cv_tls *t, const void *buf, intptr_t len, cv_tls_status *st) {
    enter(t, NULL, 0);
    size_t n = 0;
    intptr_t r = 0;
    if (len > 0) {
        if (SSL_write_ex(t->ssl, buf, (size_t)len, &n) == 1) {
            r = (intptr_t)n;
        } else {
            record_error(t, "write");
            r = CV_TLS_ERROR;
        }
    }
    st->drained = 0;
    leave(t, 0, st);
    return r;
}

void cv_tls_close(cv_tls *t) {
    clean_queue();
    SSL_shutdown(t->ssl);
    ERR_clear_error();
}

int cv_tls_key_update(cv_tls *t, int request, cv_tls_status *st) {
    enter(t, NULL, 0);
    int r = 0;
    if (SSL_version(t->ssl) != TLS1_3_VERSION) {
        snprintf(t->err, sizeof t->err, "key update: TLS 1.3 only");
        r = CV_TLS_ERROR;
    } else if (SSL_key_update(t->ssl, request ? SSL_KEY_UPDATE_REQUESTED : SSL_KEY_UPDATE_NOT_REQUESTED) != 1) {
        record_error(t, "key update");
        r = CV_TLS_ERROR;
    } else {
        // Queued: a write sends it (BoringSSL's, of nothing), or OpenSSL's
        // handshake call.
#if defined(OPENSSL_IS_BORINGSSL)
        int sent = SSL_write(t->ssl, "", 0) >= 0;
#else
        int sent = SSL_do_handshake(t->ssl) == 1;
#endif
        if (!sent) {
            record_error(t, "key update");
            r = CV_TLS_ERROR;
        }
    }
    st->drained = 0;
    leave(t, 0, st);
    return r;
}

void cv_tls_ktls_settle(cv_tls *t, cv_tls_status *st) {
    enter(t, NULL, 0);
#if defined(OPENSSL_IS_BORINGSSL) && CV_KTLS
    // A BoringSSL server keeps its TLS 1.3 tickets until it writes; the
    // kernel will do the writing, so out with them now.
    if (t->k && SSL_write(t->ssl, "", 0) < 0) ERR_clear_error();
#endif
    st->drained = 0;
    leave(t, 0, st);
}

const char *cv_tls_error(cv_tls *t) { return t->err; }

static int copy_out(const unsigned char *p, size_t n, char *out, int len) {
    if (!p || n == 0 || len <= 0) return 0;
    if (n >= (size_t)len) n = (size_t)len - 1;
    memcpy(out, p, n);
    out[n] = 0;
    return (int)n;
}

int cv_tls_alpn(cv_tls *t, char *out, int len) {
    const unsigned char *p = NULL;
    unsigned int n = 0;
    SSL_get0_alpn_selected(t->ssl, &p, &n);
    return copy_out(p, n, out, len);
}

int cv_tls_server_name(cv_tls *t, char *out, int len) {
    const char *name = SSL_get_servername(t->ssl, TLSEXT_NAMETYPE_host_name);
    return name ? copy_out((const unsigned char *)name, strlen(name), out, len) : 0;
}

int cv_tls_version(cv_tls *t) { return SSL_version(t->ssl); }

int cv_tls_resumed(cv_tls *t) { return SSL_session_reused(t->ssl); }

int cv_tls_buffered(cv_tls *t) { return SSL_pending(t->ssl) > 0; }

int cv_tls_peer_certificate(cv_tls *t, uint8_t *out, int len) {
    X509 *x = SSL_get1_peer_certificate(t->ssl);
    if (!x) return 0;
    int n = i2d_X509(x, NULL);
    if (n > 0 && out && len >= n) {
        unsigned char *p = out;
        i2d_X509(x, &p);
    }
    X509_free(x);
    return n > 0 ? n : 0;
}

// MARK: - Self-signed certificates

static int pem_out(BIO *b, char *out, int *len) {
    char *data = NULL;
    long n = BIO_get_mem_data(b, &data);
    if (n <= 0 || n >= *len) return -1;
    memcpy(out, data, (size_t)n);
    out[n] = 0;
    *len = (int)n;
    return 0;
}

int cv_tls_self_signed(const char *names, int days, char *cert_pem, int *cert_len, char *key_pem, int *key_len) {
    ERR_clear_error();
    int rc = -1;
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    X509 *x = X509_new();
    BIGNUM *serial = BN_new();
    BIO *b = NULL;
    char *list = OPENSSL_strdup(names);
    char san[4096] = "";
    if (!key || !x || !serial || !list) goto done;

    // subjectAltName from the names; the first is also the CN.
    char *first = NULL, *save = NULL;
    for (char *name = strtok_r(list, ",", &save); name; name = strtok_r(NULL, ",", &save)) {
        while (*name == ' ') name++;
        if (!*name) continue;
        if (!first) first = name;
        ASN1_OCTET_STRING *ip = a2i_IPADDRESS(name);
        size_t used = strlen(san);
        snprintf(san + used, sizeof san - used, "%s%s:%s", used ? "," : "", ip ? "IP" : "DNS", name);
        ASN1_OCTET_STRING_free(ip);
    }
    ERR_clear_error();
    if (!first) goto done;

    X509_set_version(x, X509_VERSION_3);
    if (!BN_rand(serial, 63, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) ||
        !BN_to_ASN1_INTEGER(serial, X509_get_serialNumber(x)))
        goto done;
    X509_gmtime_adj(X509_getm_notBefore(x), -3600);
    X509_gmtime_adj(X509_getm_notAfter(x), (long)days * 86400);
    X509_set_pubkey(x, key);
    X509_NAME *subject = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_UTF8, (const unsigned char *)first, -1, -1, 0);
    X509_set_issuer_name(x, subject);
    X509V3_CTX v3;
    X509V3_set_ctx_nodb(&v3);
    X509V3_set_ctx(&v3, x, x, NULL, NULL, 0);
    const struct {
        int nid;
        const char *value;
    } exts[] = {
        {NID_subject_alt_name, san},
        {NID_basic_constraints, "critical,CA:FALSE"},
        {NID_key_usage, "critical,digitalSignature"},
        {NID_ext_key_usage, "serverAuth,clientAuth"},
    };
    for (size_t i = 0; i < sizeof exts / sizeof exts[0]; i++) {
        X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &v3, exts[i].nid, exts[i].value);
        if (!ext) goto done;
        X509_add_ext(x, ext, -1);
        X509_EXTENSION_free(ext);
    }
    if (!X509_sign(x, key, EVP_sha256())) goto done;

    b = BIO_new(BIO_s_mem());
    if (!b || !PEM_write_bio_X509(b, x) || pem_out(b, cert_pem, cert_len) != 0) goto done;
    BIO_free(b);
    b = BIO_new(BIO_s_mem());
    if (!b || !PEM_write_bio_PrivateKey(b, key, NULL, NULL, 0, NULL, NULL) || pem_out(b, key_pem, key_len) != 0)
        goto done;
    rc = 0;
done:
    if (rc != 0 && cert_pem && *cert_len > 0) describe(cert_pem, *cert_len, "self-signed certificate");
    BIO_free(b);
    OPENSSL_free(list);
    BN_free(serial);
    X509_free(x);
    EVP_PKEY_free(key);
    return rc;
}
#endif
