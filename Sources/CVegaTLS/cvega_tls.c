// TLS over the system's OpenSSL, through memory BIOs: OpenSSL never sees a
// socket. Every call clears OpenSSL's per-thread error queue first, since a
// connection's calls may come from any worker thread.
#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h> // before OpenSSL, whose headers undo its X509_NAME macros
#endif
#include "cvega_tls.h"

#if __has_include(<openssl/ssl.h>) // none on iOS and the like: VegaTLS is empty there
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#error "VegaTLS needs OpenSSL 3.0 or later"
#endif

#if defined(_WIN32)
#define strtok_r strtok_s
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
};

struct cv_tls {
    SSL *ssl;
    BIO *rbio, *wbio;
    cv_tls_ctx *ctx;
    char *host;
    char err[256];
};

// MARK: - Errors

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
        free(c->names[i].name);
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

// MARK: - Connections

cv_tls *cv_tls_new(cv_tls_ctx *c, const char *host, char *err, int errlen) {
    ERR_clear_error();
    cv_tls *t = calloc(1, sizeof *t);
    if (!t) {
        snprintf(err, (size_t)errlen, "out of memory");
        return NULL;
    }
    t->ctx = c;
    t->ssl = SSL_new(c->ssl);
    t->rbio = BIO_new(BIO_s_mem());
    t->wbio = BIO_new(BIO_s_mem());
    if (!t->ssl || !t->rbio || !t->wbio) {
        describe(err, errlen, "SSL_new");
        BIO_free(t->rbio);
        BIO_free(t->wbio);
        SSL_free(t->ssl);
        free(t);
        return NULL;
    }
    BIO_set_mem_eof_return(t->rbio, -1); // empty: "retry", until the peer's end is fed
    SSL_set_bio(t->ssl, t->rbio, t->wbio);
    SSL_set_app_data(t->ssl, t);
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
    SSL_free(t->ssl); // and both BIOs
    OPENSSL_free(t->host);
    free(t);
}

void cv_tls_feed(cv_tls *t, const void *buf, intptr_t len) {
    const char *p = buf;
    while (len > 0) {
        int n = len > INT_MAX ? INT_MAX : (int)len;
        if (BIO_write(t->rbio, p, n) != n) return; // out of memory: the record layer will fail
        p += n;
        len -= n;
    }
}

void cv_tls_feed_eof(cv_tls *t) { BIO_set_mem_eof_return(t->rbio, 0); }

intptr_t cv_tls_pending(cv_tls *t) { return (intptr_t)BIO_ctrl_pending(t->wbio); }

intptr_t cv_tls_drain(cv_tls *t, void *buf, intptr_t len) {
    int n = BIO_read(t->wbio, buf, len > INT_MAX ? INT_MAX : (int)len);
    return n > 0 ? n : 0;
}

int cv_tls_handshake(cv_tls *t) {
    ERR_clear_error();
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

intptr_t cv_tls_read(cv_tls *t, void *buf, intptr_t len) {
    ERR_clear_error();
    size_t n = 0;
    if (SSL_read_ex(t->ssl, buf, (size_t)len, &n) == 1) return (intptr_t)n;
    int e = SSL_get_error(t->ssl, 0);
    switch (e) {
    case SSL_ERROR_ZERO_RETURN: return 0;
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE: return CV_TLS_WANT_READ;
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

intptr_t cv_tls_write(cv_tls *t, const void *buf, intptr_t len) {
    ERR_clear_error();
    size_t n = 0;
    if (len == 0) return 0;
    if (SSL_write_ex(t->ssl, buf, (size_t)len, &n) == 1) return (intptr_t)n;
    record_error(t, "write");
    return CV_TLS_ERROR;
}

void cv_tls_close(cv_tls *t) {
    ERR_clear_error();
    SSL_shutdown(t->ssl);
    ERR_clear_error();
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
