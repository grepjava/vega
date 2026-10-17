// Certificate chain verification for handshakes that are ours rather than the
// TLS library's (QUIC's TLS 1.3): the chain a server sent, as DER, checked
// against a trust store and for the name the client asked for -- what
// SSL_VERIFY_PEER and SSL_set1_host do inside VegaTLS's TCP handshakes, done
// here with the same library's X509_STORE and X509_verify_cert.
//
// A store is built once (the system's roots are thousands of certificates) and
// shared: X509_STORE is locked internally, so many verifications may run on it
// at once from any thread.
#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h> // before OpenSSL, whose headers undo its X509_NAME macros
#if defined(VEGA_TLS_BORINGSSL)
#undef X509_NAME
#undef X509_EXTENSIONS
#undef X509_CERT_PAIR
#undef PKCS7_ISSUER_AND_SERIAL
#undef PKCS7_SIGNER_INFO
#undef OCSP_REQUEST
#undef OCSP_RESPONSE
#endif
#endif
#include "cvega_crypto.h"

#if defined(VEGA_TLS_BORINGSSL)
#include "CVegaBoringSSL_bio.h"
#include "CVegaBoringSSL_err.h"
#include "CVegaBoringSSL_pem.h"
#include "CVegaBoringSSL_x509.h"
#include "CVegaBoringSSL_x509v3.h"
#define CV_HAVE_VERIFY 1
#elif defined(VEGA_TLS_OPENSSL) && __has_include(<openssl/x509.h>)
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#define CV_HAVE_VERIFY 1
#endif

#if CV_HAVE_VERIFY
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct cv_verifier {
    X509_STORE *store;
};

static void verify_message(char *err, size_t len, const char *message) {
    if (err && len > 0) snprintf(err, len, "%s", message);
}

#if defined(_WIN32)
/// The roots in Windows' certificate store, which OpenSSL doesn't read (as
/// cvega_tls.c's, for a store of our own).
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

cv_verifier *cv_verifier_new(int system_roots, const char *pem, size_t pem_len, char *err, size_t err_len) {
    ERR_clear_error();
    X509_STORE *store = X509_STORE_new();
    if (!store) {
        verify_message(err, err_len, "trust roots: out of memory");
        return NULL;
    }
    if (system_roots) {
        int ok = X509_STORE_set_default_paths(store) == 1;
#if defined(_WIN32)
        ok = add_windows_roots(store) > 0 || ok;
#endif
        ERR_clear_error();
        if (!ok) {
            verify_message(err, err_len, "system trust roots: none found");
            X509_STORE_free(store);
            return NULL;
        }
    }
    if (pem && pem_len > 0) {
        if (pem_len > INT_MAX) {
            verify_message(err, err_len, "trust roots: PEM data too long");
            X509_STORE_free(store);
            return NULL;
        }
        BIO *b = BIO_new_mem_buf(pem, (int)pem_len);
        int n = 0;
        X509 *x;
        while (b && (x = PEM_read_bio_X509(b, NULL, NULL, NULL))) {
            if (X509_STORE_add_cert(store, x) == 1) n++;
            X509_free(x);
        }
        BIO_free(b);
        ERR_clear_error();
        if (n == 0) {
            verify_message(err, err_len, "trust roots: no certificate in the PEM data");
            X509_STORE_free(store);
            return NULL;
        }
#if defined(OPENSSL_IS_BORINGSSL)
        // Trust a given leaf itself, as OpenSSL does: BoringSSL otherwise
        // looks for its issuer, and a self-signed leaf can't sign
        // certificates (the same as cv_tls_ctx_add_trust).
        X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN);
#endif
    }
    if (!system_roots && !(pem && pem_len > 0)) {
        verify_message(err, err_len, "trust roots: none given");
        X509_STORE_free(store);
        return NULL;
    }
    cv_verifier *v = malloc(sizeof *v);
    if (!v) {
        verify_message(err, err_len, "trust roots: out of memory");
        X509_STORE_free(store);
        return NULL;
    }
    v->store = store;
    return v;
}

void cv_verifier_free(cv_verifier *v) {
    if (!v) return;
    X509_STORE_free(v->store);
    free(v);
}

int cv_verifier_verify(cv_verifier *v, const uint8_t *const *certs, const size_t *lens, int count, const char *host,
                       size_t host_len, char *err, size_t err_len) {
    if (!v || !certs || !lens || count <= 0) {
        verify_message(err, err_len, "certificate verify failed: no certificate");
        return 0;
    }
    // A DNS name is at most 253 bytes; a NUL inside one is an attempt to
    // make the name checked differ from the name shown.
    char name[256];
    if (host_len >= sizeof name || (host_len > 0 && memchr(host, 0, host_len))) {
        verify_message(err, err_len, "certificate verify failed: the server name is not a host name");
        return 0;
    }
    if (host_len > 0) memcpy(name, host, host_len);
    name[host_len] = 0;

    ERR_clear_error();
    int ok = 0;
    X509 *leaf = NULL;
    X509_VERIFY_PARAM *param = NULL;
    STACK_OF(X509) *untrusted = sk_X509_new_null();
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (!untrusted || !ctx) {
        verify_message(err, err_len, "certificate verify failed: out of memory");
        goto done;
    }
    for (int i = 0; i < count; i++) {
        if (!certs[i] || lens[i] == 0 || lens[i] > LONG_MAX) {
            verify_message(err, err_len, "certificate verify failed: an empty certificate");
            goto done;
        }
        const uint8_t *p = certs[i];
        X509 *x = d2i_X509(NULL, &p, (long)lens[i]);
        if (!x || p != certs[i] + lens[i]) {
            X509_free(x);
            verify_message(err, err_len, "certificate verify failed: a certificate that doesn't parse");
            goto done;
        }
        if (i == 0) {
            leaf = x;
        } else if (!sk_X509_push(untrusted, x)) {
            X509_free(x);
            verify_message(err, err_len, "certificate verify failed: out of memory");
            goto done;
        }
    }
    if (X509_STORE_CTX_init(ctx, v->store, leaf, untrusted) != 1) {
        verify_message(err, err_len, "certificate verify failed: can't start");
        goto done;
    }
    // A TLS server's certificate: its purpose and trust settings, as an
    // SSL client's verification sets them.
    X509_STORE_CTX_set_default(ctx, "ssl_server");
    param = X509_STORE_CTX_get0_param(ctx);
    if (host_len > 0) {
        // An address is checked against the IP subject alternative names, a
        // name against the DNS ones (and the common name only without any).
        if (X509_VERIFY_PARAM_set1_ip_asc(param, name) != 1) {
            ERR_clear_error();
            X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
            if (X509_VERIFY_PARAM_set1_host(param, name, host_len) != 1) {
                verify_message(err, err_len, "certificate verify failed: the server name is not a host name");
                goto done;
            }
        }
    }
    if (X509_verify_cert(ctx) == 1) {
        ok = 1;
    } else if (err && err_len > 0) {
        snprintf(err, err_len, "certificate verify failed: %s",
                 X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
    }

done:
    X509_STORE_CTX_free(ctx);
    sk_X509_pop_free(untrusted, X509_free);
    X509_free(leaf);
    ERR_clear_error();
    return ok;
}

#endif
