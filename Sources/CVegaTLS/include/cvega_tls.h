// TLS for VegaTLS: a sans-I/O engine over the system's OpenSSL (3.0 or
// later). The calls that run the engine are handed the peer's ciphertext and
// take what they need of it in place; what the engine writes is taken with
// cv_tls_take_output. The Swift side moves both over whatever stream it has.
// No OpenSSL type appears here, so Swift never imports OpenSSL's headers.
#ifndef CVEGA_TLS_H
#define CVEGA_TLS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cv_tls_ctx cv_tls_ctx;
typedef struct cv_tls cv_tls;

/// What a call that runs the engine left: how many of the peer's ciphertext
/// bytes it was handed it took (the rest are for the next call), the
/// ciphertext waiting to go to the peer, and for cv_tls_read whether the
/// engine is drained: sure to want more of the peer's ciphertext before it
/// can return anything.
typedef struct cv_tls_status {
    intptr_t used;
    intptr_t pending;
    int drained;
} cv_tls_status;

/// Results besides a byte count.
#define CV_TLS_WANT_READ (-1) // feed more ciphertext (after sending what's pending)
#define CV_TLS_ERROR (-2)     // failed: cv_tls_error says why
#define CV_TLS_TRUNCATED (-3) // the peer's ciphertext ended without close_notify

#define CV_TLS_VERIFY_NONE 0     // don't check the peer's certificate
#define CV_TLS_VERIFY_OPTIONAL 1 // server: ask for a client certificate, check it if sent
#define CV_TLS_VERIFY_REQUIRED 2 // check it; a server refuses clients without one

/// A configuration shared by connections: thread-safe once set up. The
/// setters return 0, or -1 with a message in err (errlen bytes).
cv_tls_ctx *cv_tls_ctx_new(int server, char *err, int errlen);
void cv_tls_ctx_free(cv_tls_ctx *ctx);
/// Our certificate chain (leaf first) and private key, as PEM.
int cv_tls_ctx_use_certificate(cv_tls_ctx *ctx, const char *chain_pem, int chain_len, const char *key_pem,
                               int key_len, char *err, int errlen);
/// Trust the certificates in pem (one or more) as roots.
int cv_tls_ctx_add_trust(cv_tls_ctx *ctx, const char *pem, int len, char *err, int errlen);
/// Trust the system's roots: OpenSSL's default paths (SSL_CERT_FILE,
/// SSL_CERT_DIR), and on Windows the certificate store's.
int cv_tls_ctx_use_system_trust(cv_tls_ctx *ctx, char *err, int errlen);
void cv_tls_ctx_set_verify(cv_tls_ctx *ctx, int mode);
/// TLS versions as 0x0303 (1.2) and 0x0304 (1.3); max 0 for the newest.
int cv_tls_ctx_set_versions(cv_tls_ctx *ctx, int min, int max, char *err, int errlen);
/// ALPN protocols in wire form (length-prefixed), in preference order.
/// A server picks its first that the client offers, and refuses a client
/// that offers protocols but none of these.
int cv_tls_ctx_set_alpn(cv_tls_ctx *ctx, const uint8_t *wire, int len, char *err, int errlen);
/// Server: use `other`'s certificate for clients asking for `name` (SNI;
/// "*.example.com" matches one label). ctx keeps a reference to other.
int cv_tls_ctx_add_server_name(cv_tls_ctx *ctx, const char *name, cv_tls_ctx *other, char *err, int errlen);
/// Client: keep sessions to resume, per server name (0 turns it off).
void cv_tls_ctx_set_session_cache(cv_tls_ctx *ctx, int entries);
/// Server: the session-ticket key, 80 bytes of secret (BoringSSL uses the
/// first 48). Servers sharing it resume each other's sessions.
int cv_tls_ctx_set_ticket_key(cv_tls_ctx *ctx, const uint8_t *key, int len, char *err, int errlen);
/// Server: called with each ClientHello's server name (NULL: none) and the
/// ALPN protocols it offers (wire form; NULL, 0: none), before the
/// certificate is chosen. A context returned replaces ctx for that
/// connection, its certificate and ALPN with it; NULL keeps ctx (and its
/// server names). The returned context must outlive the connection.
typedef cv_tls_ctx *(*cv_tls_hello_fn)(void *arg, const char *server_name, const uint8_t *alpn, int alpn_len);
void cv_tls_ctx_set_hello(cv_tls_ctx *ctx, cv_tls_hello_fn fn, void *arg);

/// A connection. Client: host is the server name to send (SNI) and to
/// check the certificate against (an IP address is checked as one); NULL
/// for neither. NULL on failure, with a message in err.
cv_tls *cv_tls_new(cv_tls_ctx *ctx, const char *host, char *err, int errlen);
void cv_tls_free(cv_tls *t);
/// The peer's ciphertext has ended (after what calls are still handed).
void cv_tls_feed_eof(cv_tls *t);
/// The ciphertext waiting to go to the peer, to send: NULL (and len 0) if
/// there is none. The engine writes anything more into a new buffer until
/// cv_tls_return_output; one taker at a time.
const uint8_t *cv_tls_take_output(cv_tls *t, intptr_t *len);
/// Sent (or given up on): the buffer is the engine's again.
void cv_tls_return_output(cv_tls *t);
/// One handshake step over the peer's ciphertext in (in_len bytes; NULL,
/// 0 for none): 1 done, CV_TLS_WANT_READ, or CV_TLS_ERROR. Send what's
/// pending after every step, an alert after an error too.
int cv_tls_handshake(cv_tls *t, const void *in, intptr_t in_len, cv_tls_status *st);
/// Plaintext, decrypted from the peer's ciphertext in: bytes, 0 once the
/// peer sent close_notify, CV_TLS_WANT_READ (all of in was taken),
/// CV_TLS_TRUNCATED or CV_TLS_ERROR. May leave ciphertext pending (a key
/// update's answer).
intptr_t cv_tls_read(cv_tls *t, const void *in, intptr_t in_len, void *buf, intptr_t len, cv_tls_status *st);
/// Encrypt all of buf (into pending): len, or CV_TLS_ERROR.
intptr_t cv_tls_write(cv_tls *t, const void *buf, intptr_t len, cv_tls_status *st);
/// Queue close_notify.
void cv_tls_close(cv_tls *t);
/// Why the last call failed.
const char *cv_tls_error(cv_tls *t);
/// The protocol ALPN chose, the server name the client asked for, the
/// version (0x0304...), whether the session was resumed.
int cv_tls_alpn(cv_tls *t, char *out, int len);
int cv_tls_server_name(cv_tls *t, char *out, int len);
int cv_tls_version(cv_tls *t);
int cv_tls_resumed(cv_tls *t);
/// Whether the engine holds decrypted plaintext not yet read.
int cv_tls_buffered(cv_tls *t);
/// The peer's certificate as DER: its length (call with len 0 to size), or
/// 0 if there is none.
int cv_tls_peer_certificate(cv_tls *t, uint8_t *out, int len);

/// A self-signed certificate and its P-256 key, as PEM, for tests and
/// development: names is a comma-separated list of DNS names and IP
/// addresses (the first is also the subject's CN). 0, or -1 with a message
/// in cert_pem. Lengths in/out.
int cv_tls_self_signed(const char *names, int days, char *cert_pem, int *cert_len, char *key_pem, int *key_len);

/// Digests, from the TLS library or, on Apple's platforms, CommonCrypto:
/// 1 if there is one to use. The others return 0, or -1 on failure or
/// with none; out is 32 bytes, or out_len for PBKDF2.
int cv_digest_available(void);
int cv_sha256(const void *data, intptr_t len, uint8_t *out);
int cv_hmac_sha256(const void *key, intptr_t key_len, const void *data, intptr_t len, uint8_t *out);
int cv_pbkdf2_sha256(const void *password, intptr_t password_len, const void *salt, intptr_t salt_len,
                     uint32_t iterations, uint8_t *out, intptr_t out_len);

#ifdef __cplusplus
}
#endif
#endif
