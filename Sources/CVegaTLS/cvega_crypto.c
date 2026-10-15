// VegaCrypto's primitives over the TLS library: the system's OpenSSL (3.0 or
// later), or the vendored BoringSSL with the BoringSSL trait. Where the two
// differ -- AEADs, header protection, building keys from their numbers --
// each has its own few lines; everything else is the EVP API they share.
// Failures clear nothing: cv_crypto_error takes the reason off the queue.
#include "cvega_crypto.h"

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/// "*.example.com" covers one label in front of example.com: not
/// example.com, not a.b.example.com. Otherwise case-insensitive equality.
static int ascii_casecmp(const char *a, const char *b) {
    for (;; a++, b++) {
        int x = tolower((unsigned char)*a), y = tolower((unsigned char)*b);
        if (x != y) return x - y;
        if (!x) return 0;
    }
}

int cv_host_matches(const char *pattern, const char *host) {
    if (!pattern || !host || !*pattern || !*host) return 0;
    if (pattern[0] == '*' && pattern[1] == '.') {
        if (!pattern[2]) return 0;
        const char *dot = strchr(host, '.');
        if (!dot || dot == host) return 0;
        return ascii_casecmp(dot + 1, pattern + 2) == 0;
    }
    return ascii_casecmp(pattern, host) == 0;
}

#if defined(VEGA_TLS_BORINGSSL)
#include "CVegaBoringSSL_aead.h"
#include "CVegaBoringSSL_aes.h"
#include "CVegaBoringSSL_bio.h"
#include "CVegaBoringSSL_bn.h"
#include "CVegaBoringSSL_chacha.h"
#include "CVegaBoringSSL_crypto.h"
#include "CVegaBoringSSL_ec.h"
#include "CVegaBoringSSL_ec_key.h"
#include "CVegaBoringSSL_ecdh.h"
#include "CVegaBoringSSL_ecdsa.h"
#include "CVegaBoringSSL_err.h"
#include "CVegaBoringSSL_evp.h"
#include "CVegaBoringSSL_hmac.h"
#include "CVegaBoringSSL_mem.h"
#include "CVegaBoringSSL_nid.h"
#include "CVegaBoringSSL_pem.h"
#include "CVegaBoringSSL_rand.h"
#include "CVegaBoringSSL_rsa.h"
#include "CVegaBoringSSL_x509.h"
#include "CVegaBoringSSL_x509v3.h"
#define CV_HAVE_CRYPTO 1
#elif defined(VEGA_TLS_OPENSSL) && __has_include(<openssl/evp.h>)
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#define CV_HAVE_CRYPTO 1
#endif

#if CV_HAVE_CRYPTO

#if defined(OPENSSL_IS_BORINGSSL)
#define EVP_PKEY_get_bits EVP_PKEY_bits
#define EVP_PKEY_get_base_id EVP_PKEY_id
#define EVP_PKEY_get_size EVP_PKEY_size
#ifndef RSA_PSS_SALTLEN_DIGEST
#define RSA_PSS_SALTLEN_DIGEST (-1) // BoringSSL's "the digest's length", unnamed
#endif
#endif

int cv_crypto_error(char *out, size_t len) {
    unsigned long e = ERR_peek_last_error();
    int n = 0;
    if (e && out && len) {
        ERR_error_string_n(e, out, len);
        n = (int)strlen(out);
    } else if (out && len) {
        out[0] = 0;
    }
    ERR_clear_error();
    return n;
}

int cv_crypto_random(void *out, size_t len) {
    uint8_t *p = out;
    while (len > 0) {
        size_t n = len > INT_MAX ? INT_MAX : len;
        if (RAND_bytes(p, (int)n) != 1) return -1;
        p += n;
        len -= n;
    }
    return 0;
}

int cv_crypto_memeq(const void *a, const void *b, size_t n) {
    if (n == 0) return 1;
    return CRYPTO_memcmp(a, b, n) == 0;
}

// MARK: - Hashes

static const EVP_MD *md_for(int alg) {
    switch (alg) {
    case CV_SHA256: return EVP_sha256();
    case CV_SHA384: return EVP_sha384();
    case CV_SHA512: return EVP_sha512();
    default: return NULL;
    }
}

int cv_hash_len(int alg) {
    switch (alg) {
    case CV_SHA256: return 32;
    case CV_SHA384: return 48;
    case CV_SHA512: return 64;
    default: return -1;
    }
}

int cv_hash(int alg, const void *data, size_t len, uint8_t *out) {
    const EVP_MD *md = md_for(alg);
    if (!md) return -1;
    unsigned int n = 0;
    static const uint8_t empty = 0;
    if (EVP_Digest(len ? data : &empty, len, out, &n, md, NULL) != 1) return -1;
    return (int)n;
}

struct cv_hasher {
    EVP_MD_CTX *ctx;
    const EVP_MD *md;
};

cv_hasher *cv_hash_new(int alg) {
    const EVP_MD *md = md_for(alg);
    if (!md) return NULL;
    cv_hasher *h = calloc(1, sizeof *h);
    if (!h) return NULL;
    h->md = md;
    h->ctx = EVP_MD_CTX_new();
    if (!h->ctx || EVP_DigestInit_ex(h->ctx, md, NULL) != 1) {
        cv_hash_free(h);
        return NULL;
    }
    return h;
}

void cv_hash_free(cv_hasher *h) {
    if (!h) return;
    EVP_MD_CTX_free(h->ctx);
    free(h);
}

int cv_hash_update(cv_hasher *h, const void *data, size_t len) {
    if (!h) return -1;
    if (len == 0) return 0;
    return EVP_DigestUpdate(h->ctx, data, len) == 1 ? 0 : -1;
}

int cv_hash_snapshot(cv_hasher *h, uint8_t *out) {
    if (!h) return -1;
    EVP_MD_CTX *copy = EVP_MD_CTX_new();
    if (!copy) return -1;
    unsigned int n = 0;
    int ok = EVP_MD_CTX_copy_ex(copy, h->ctx) == 1 && EVP_DigestFinal_ex(copy, out, &n) == 1;
    EVP_MD_CTX_free(copy);
    return ok ? (int)n : -1;
}

int cv_hash_final(cv_hasher *h, uint8_t *out) {
    if (!h) return -1;
    unsigned int n = 0;
    if (EVP_DigestFinal_ex(h->ctx, out, &n) != 1) return -1;
    if (EVP_DigestInit_ex(h->ctx, h->md, NULL) != 1) return -1;
    return (int)n;
}

cv_hasher *cv_hash_copy(const cv_hasher *h) {
    if (!h) return NULL;
    cv_hasher *c = calloc(1, sizeof *c);
    if (!c) return NULL;
    c->md = h->md;
    c->ctx = EVP_MD_CTX_new();
    if (!c->ctx || EVP_MD_CTX_copy_ex(c->ctx, h->ctx) != 1) {
        cv_hash_free(c);
        return NULL;
    }
    return c;
}

// MARK: - HMAC, PBKDF2, HKDF

int cv_hmac(int alg, const void *key, size_t key_len, const void *data, size_t len, uint8_t *out) {
    const EVP_MD *md = md_for(alg);
    if (!md || key_len > INT_MAX) return -1;
    unsigned int n = 0;
    // A zero-length key or message still wants a pointer.
    static const uint8_t empty = 0;
    if (!HMAC(md, key_len ? key : &empty, (int)key_len, len ? data : &empty, len, out, &n)) return -1;
    return (int)n;
}

#if defined(OPENSSL_IS_BORINGSSL)
struct cv_hmac_key {
    HMAC_CTX keyed;
};

cv_hmac_key *cv_hmac_new(int alg, const void *key, size_t key_len) {
    const EVP_MD *md = md_for(alg);
    if (!md) return NULL;
    cv_hmac_key *m = malloc(sizeof *m);
    if (!m) return NULL;
    HMAC_CTX_init(&m->keyed);
    static const uint8_t empty = 0;
    if (HMAC_Init_ex(&m->keyed, key_len ? key : &empty, key_len, md, NULL) != 1) {
        cv_hmac_free(m);
        return NULL;
    }
    return m;
}

void cv_hmac_free(cv_hmac_key *m) {
    if (!m) return;
    HMAC_CTX_cleanup(&m->keyed);
    free(m);
}

int cv_hmac_compute(const cv_hmac_key *m, const void *data, size_t len, uint8_t *out) {
    if (!m) return -1;
    HMAC_CTX c;
    HMAC_CTX_init(&c);
    unsigned int n = 0;
    int ok = HMAC_CTX_copy_ex(&c, &m->keyed) == 1 && (len == 0 || HMAC_Update(&c, data, len) == 1) &&
             HMAC_Final(&c, out, &n) == 1;
    HMAC_CTX_cleanup(&c);
    return ok ? (int)n : -1;
}
#else
struct cv_hmac_key {
    EVP_MAC_CTX *keyed;
};

cv_hmac_key *cv_hmac_new(int alg, const void *key, size_t key_len) {
    const char *digest = alg == CV_SHA256 ? "SHA256" : alg == CV_SHA384 ? "SHA384" : alg == CV_SHA512 ? "SHA512" : NULL;
    if (!digest) return NULL;
    EVP_MAC *hmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!hmac) return NULL;
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(hmac);
    EVP_MAC_free(hmac); // the context holds its own reference
    if (!ctx) return NULL;
    OSSL_PARAM params[2] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)digest, 0),
        OSSL_PARAM_construct_end(),
    };
    static const uint8_t empty = 0;
    cv_hmac_key *m = malloc(sizeof *m);
    if (!m || EVP_MAC_init(ctx, key_len ? key : &empty, key_len, params) != 1) {
        free(m);
        EVP_MAC_CTX_free(ctx);
        return NULL;
    }
    m->keyed = ctx;
    return m;
}

void cv_hmac_free(cv_hmac_key *m) {
    if (!m) return;
    EVP_MAC_CTX_free(m->keyed);
    free(m);
}

int cv_hmac_compute(const cv_hmac_key *m, const void *data, size_t len, uint8_t *out) {
    if (!m) return -1;
    EVP_MAC_CTX *c = EVP_MAC_CTX_dup(m->keyed);
    if (!c) return -1;
    size_t n = 0;
    int ok = (len == 0 || EVP_MAC_update(c, data, len) == 1) && EVP_MAC_final(c, out, &n, 64) == 1;
    EVP_MAC_CTX_free(c);
    return ok ? (int)n : -1;
}
#endif

int cv_pbkdf2(int alg, const void *password, size_t password_len, const void *salt, size_t salt_len,
              uint32_t iterations, uint8_t *out, size_t out_len) {
    const EVP_MD *md = md_for(alg);
    if (!md || iterations == 0 || iterations > INT_MAX || out_len == 0 || password_len > INT_MAX ||
        salt_len > INT_MAX || out_len > INT_MAX)
        return -1;
    static const uint8_t empty = 0;
    return PKCS5_PBKDF2_HMAC(password_len ? password : (const void *)&empty, (int)password_len,
                             salt_len ? salt : &empty, (int)salt_len, (int)iterations, md, (int)out_len,
                             out) == 1
               ? 0
               : -1;
}

int cv_hkdf_extract(int alg, const void *salt, size_t salt_len, const void *ikm, size_t ikm_len, uint8_t *out) {
    int n = cv_hash_len(alg);
    if (n < 0) return -1;
    uint8_t zeros[64] = {0};
    if (!salt || salt_len == 0) {
        salt = zeros;
        salt_len = (size_t)n;
    }
    return cv_hmac(alg, salt, salt_len, ikm, ikm_len, out) == n ? n : -1;
}

int cv_hkdf_expand(int alg, const void *prk, size_t prk_len, const void *info, size_t info_len, uint8_t *out,
                   size_t out_len) {
    int hl = cv_hash_len(alg);
    if (hl < 0 || out_len > 255u * (size_t)hl || info_len > (1u << 20)) return -1;
    // T(i) = HMAC(PRK, T(i-1) || info || i). A TLS label fits on the stack.
    uint8_t stack[64 + 512 + 1];
    uint8_t *round = stack;
    if (64 + info_len + 1 > sizeof stack) {
        round = malloc(64 + info_len + 1);
        if (!round) return -1;
    }
    uint8_t block[64];
    size_t done = 0, block_len = 0;
    uint8_t counter = 1;
    int rc = 0;
    while (done < out_len) {
        size_t n = 0;
        if (block_len) {
            memcpy(round, block, block_len);
            n = block_len;
        }
        if (info_len) {
            memcpy(round + n, info, info_len);
            n += info_len;
        }
        round[n++] = counter++;
        if (cv_hmac(alg, prk, prk_len, round, n, block) != hl) {
            rc = -1;
            break;
        }
        block_len = (size_t)hl;
        size_t take = out_len - done < block_len ? out_len - done : block_len;
        memcpy(out + done, block, take);
        done += take;
    }
    OPENSSL_cleanse(block, sizeof block);
    if (round != stack) free(round);
    return rc;
}

// MARK: - AEAD

int cv_aead_key_len(int alg) {
    switch (alg) {
    case CV_AEAD_AES128GCM: return 16;
    case CV_AEAD_AES256GCM: return 32;
    case CV_AEAD_CHACHA20POLY1305: return 32;
    default: return -1;
    }
}

#if defined(OPENSSL_IS_BORINGSSL)
// EVP_AEAD: one context, const once keyed.
struct cv_aead {
    EVP_AEAD_CTX ctx;
};

cv_aead *cv_aead_new(int alg, const uint8_t *key, size_t key_len) {
    const EVP_AEAD *aead = alg == CV_AEAD_AES128GCM          ? EVP_aead_aes_128_gcm()
                           : alg == CV_AEAD_AES256GCM        ? EVP_aead_aes_256_gcm()
                           : alg == CV_AEAD_CHACHA20POLY1305 ? EVP_aead_chacha20_poly1305()
                                                             : NULL;
    if (!aead || (int)key_len != cv_aead_key_len(alg)) return NULL;
    cv_aead *a = malloc(sizeof *a);
    if (!a) return NULL;
    if (EVP_AEAD_CTX_init(&a->ctx, aead, key, key_len, 16, NULL) != 1) {
        free(a);
        return NULL;
    }
    return a;
}

void cv_aead_free(cv_aead *a) {
    if (!a) return;
    EVP_AEAD_CTX_cleanup(&a->ctx);
    free(a);
}

intptr_t cv_aead_seal(cv_aead *a, const uint8_t nonce[12], const void *aad, size_t aad_len, const void *pt,
                      size_t pt_len, uint8_t *out) {
    if (!a || pt_len > (size_t)INTPTR_MAX - 16) return -1;
    size_t n = 0;
    if (EVP_AEAD_CTX_seal(&a->ctx, out, &n, pt_len + 16, nonce, 12, pt, pt_len, aad, aad_len) != 1) return -1;
    return (intptr_t)n;
}

intptr_t cv_aead_open(cv_aead *a, const uint8_t nonce[12], const void *aad, size_t aad_len, const void *ct,
                      size_t ct_len, uint8_t *out) {
    if (!a || ct_len < 16) return -1;
    size_t n = 0;
    if (EVP_AEAD_CTX_open(&a->ctx, out, &n, ct_len - 16, nonce, 12, ct, ct_len, aad, aad_len) != 1) {
        ERR_clear_error();
        return -1;
    }
    return (intptr_t)n;
}
#else
// EVP_CIPHER: the key is bound once in a context per direction, and only
// the nonce is set per message.
struct cv_aead {
    EVP_CIPHER_CTX *enc, *dec;
};

cv_aead *cv_aead_new(int alg, const uint8_t *key, size_t key_len) {
    const EVP_CIPHER *c = alg == CV_AEAD_AES128GCM          ? EVP_aes_128_gcm()
                          : alg == CV_AEAD_AES256GCM        ? EVP_aes_256_gcm()
                          : alg == CV_AEAD_CHACHA20POLY1305 ? EVP_chacha20_poly1305()
                                                            : NULL;
    if (!c || (int)key_len != cv_aead_key_len(alg)) return NULL;
    cv_aead *a = calloc(1, sizeof *a);
    if (!a) return NULL;
    a->enc = EVP_CIPHER_CTX_new();
    a->dec = EVP_CIPHER_CTX_new();
    if (!a->enc || !a->dec || EVP_EncryptInit_ex(a->enc, c, NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(a->enc, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1 ||
        EVP_EncryptInit_ex(a->enc, NULL, NULL, key, NULL) != 1 || EVP_DecryptInit_ex(a->dec, c, NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(a->dec, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1 ||
        EVP_DecryptInit_ex(a->dec, NULL, NULL, key, NULL) != 1) {
        cv_aead_free(a);
        return NULL;
    }
    return a;
}

void cv_aead_free(cv_aead *a) {
    if (!a) return;
    EVP_CIPHER_CTX_free(a->enc);
    EVP_CIPHER_CTX_free(a->dec);
    free(a);
}

intptr_t cv_aead_seal(cv_aead *a, const uint8_t nonce[12], const void *aad, size_t aad_len, const void *pt,
                      size_t pt_len, uint8_t *out) {
    if (!a || pt_len > INT_MAX || aad_len > INT_MAX) return -1;
    int len = 0, total = 0;
    if (EVP_EncryptInit_ex(a->enc, NULL, NULL, NULL, nonce) != 1) return -1;
    if (aad_len && EVP_EncryptUpdate(a->enc, NULL, &len, aad, (int)aad_len) != 1) return -1;
    if (pt_len) {
        if (EVP_EncryptUpdate(a->enc, out, &len, pt, (int)pt_len) != 1) return -1;
        total = len;
    }
    if (EVP_EncryptFinal_ex(a->enc, out + total, &len) != 1) return -1;
    total += len;
    if (EVP_CIPHER_CTX_ctrl(a->enc, EVP_CTRL_AEAD_GET_TAG, 16, out + total) != 1) return -1;
    return (intptr_t)total + 16;
}

intptr_t cv_aead_open(cv_aead *a, const uint8_t nonce[12], const void *aad, size_t aad_len, const void *ct,
                      size_t ct_len, uint8_t *out) {
    if (!a || ct_len < 16 || ct_len - 16 > INT_MAX || aad_len > INT_MAX) return -1;
    size_t body = ct_len - 16;
    uint8_t tag[16];
    memcpy(tag, (const uint8_t *)ct + body, 16); // before out (maybe ct) is written
    int len = 0, total = 0;
    if (EVP_DecryptInit_ex(a->dec, NULL, NULL, NULL, nonce) != 1) return -1;
    if (aad_len && EVP_DecryptUpdate(a->dec, NULL, &len, aad, (int)aad_len) != 1) return -1;
    if (body) {
        if (EVP_DecryptUpdate(a->dec, out, &len, ct, (int)body) != 1) return -1;
        total = len;
    }
    if (EVP_CIPHER_CTX_ctrl(a->dec, EVP_CTRL_AEAD_SET_TAG, 16, tag) != 1) return -1;
    if (EVP_DecryptFinal_ex(a->dec, out + total, &len) != 1) {
        ERR_clear_error();
        return -1;
    }
    return (intptr_t)total + len;
}
#endif

// MARK: - Header protection

#if defined(OPENSSL_IS_BORINGSSL)
struct cv_hp {
    int chacha;
    AES_KEY aes;
    uint8_t key[32];
};

cv_hp *cv_hp_new(int alg, const uint8_t *key, size_t key_len) {
    if (cv_aead_key_len(alg) < 0 || (int)key_len != cv_aead_key_len(alg)) return NULL;
    cv_hp *h = calloc(1, sizeof *h);
    if (!h) return NULL;
    if (alg == CV_AEAD_CHACHA20POLY1305) {
        h->chacha = 1;
        memcpy(h->key, key, 32);
    } else if (AES_set_encrypt_key(key, (unsigned)key_len * 8, &h->aes) != 0) {
        free(h);
        return NULL;
    }
    return h;
}

void cv_hp_free(cv_hp *h) {
    if (!h) return;
    OPENSSL_cleanse(h, sizeof *h);
    free(h);
}

int cv_hp_mask(cv_hp *h, const uint8_t sample[16], uint8_t mask[5]) {
    if (!h) return -1;
    if (h->chacha) {
        // RFC 9001 5.4.4: the sample's first four bytes are the block
        // counter (little-endian), the other twelve the nonce.
        static const uint8_t zeros[5] = {0};
        uint32_t counter = (uint32_t)sample[0] | (uint32_t)sample[1] << 8 | (uint32_t)sample[2] << 16 |
                           (uint32_t)sample[3] << 24;
        CRYPTO_chacha_20(mask, zeros, 5, h->key, sample + 4, counter);
        return 0;
    }
    uint8_t block[16];
    AES_encrypt(sample, block, &h->aes);
    memcpy(mask, block, 5);
    return 0;
}
#else
struct cv_hp {
    EVP_CIPHER_CTX *ctx;
    int chacha;
};

cv_hp *cv_hp_new(int alg, const uint8_t *key, size_t key_len) {
    if (cv_aead_key_len(alg) < 0 || (int)key_len != cv_aead_key_len(alg)) return NULL;
    const EVP_CIPHER *c = alg == CV_AEAD_AES128GCM   ? EVP_aes_128_ecb()
                          : alg == CV_AEAD_AES256GCM ? EVP_aes_256_ecb()
                                                     : EVP_chacha20();
    cv_hp *h = calloc(1, sizeof *h);
    if (!h) return NULL;
    h->chacha = alg == CV_AEAD_CHACHA20POLY1305;
    h->ctx = EVP_CIPHER_CTX_new();
    if (!h->ctx || EVP_EncryptInit_ex(h->ctx, c, NULL, key, NULL) != 1) {
        cv_hp_free(h);
        return NULL;
    }
    EVP_CIPHER_CTX_set_padding(h->ctx, 0);
    return h;
}

void cv_hp_free(cv_hp *h) {
    if (!h) return;
    EVP_CIPHER_CTX_free(h->ctx);
    free(h);
}

int cv_hp_mask(cv_hp *h, const uint8_t sample[16], uint8_t mask[5]) {
    if (!h) return -1;
    int len = 0;
    if (h->chacha) {
        // OpenSSL's ChaCha20 IV is the counter (little-endian) then the
        // nonce: the sample as it is.
        static const uint8_t zeros[5] = {0};
        if (EVP_EncryptInit_ex(h->ctx, NULL, NULL, NULL, sample) != 1) return -1;
        return EVP_EncryptUpdate(h->ctx, mask, &len, zeros, 5) == 1 ? 0 : -1;
    }
    uint8_t block[32];
    if (EVP_EncryptUpdate(h->ctx, block, &len, sample, 16) != 1 || len < 5) return -1;
    memcpy(mask, block, 5);
    return 0;
}
#endif

// MARK: - EC helpers: the parts OpenSSL 3 and BoringSSL spell differently

static int curve_nid(int type) {
    switch (type) {
    case CV_KEY_EC_P256: return NID_X9_62_prime256v1;
    case CV_KEY_EC_P384: return NID_secp384r1;
    case CV_KEY_EC_P521: return NID_secp521r1;
    default: return NID_undef;
    }
}

static size_t curve_size(int type) {
    switch (type) {
    case CV_KEY_EC_P256: return 32;
    case CV_KEY_EC_P384: return 48;
    case CV_KEY_EC_P521: return 66;
    default: return 0;
    }
}

static int bn_to_padded(const BIGNUM *bn, uint8_t *out, size_t len) {
#if defined(OPENSSL_IS_BORINGSSL)
    return BN_bn2bin_padded(out, len, bn) == 1;
#else
    return BN_bn2binpad(bn, out, (int)len) == (int)len;
#endif
}

#if defined(OPENSSL_IS_BORINGSSL)
static int ec_type_of(EVP_PKEY *pkey) {
    const EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
    if (!ec) return -1;
    switch (EC_GROUP_get_curve_name(EC_KEY_get0_group(ec))) {
    case NID_X9_62_prime256v1: return CV_KEY_EC_P256;
    case NID_secp384r1: return CV_KEY_EC_P384;
    case NID_secp521r1: return CV_KEY_EC_P521;
    default: return -1;
    }
}

/// A public key from an uncompressed point on the curve.
static EVP_PKEY *ec_from_point(int type, const uint8_t *point, size_t len) {
    EC_KEY *ec = EC_KEY_new_by_curve_name(curve_nid(type));
    if (!ec) return NULL;
    const EC_GROUP *group = EC_KEY_get0_group(ec);
    EC_POINT *p = EC_POINT_new(group);
    EVP_PKEY *pkey = NULL;
    if (p && EC_POINT_oct2point(group, p, point, len, NULL) == 1 && EC_KEY_set_public_key(ec, p) == 1 &&
        EC_KEY_check_key(ec) == 1 && (pkey = EVP_PKEY_new()) && EVP_PKEY_assign_EC_KEY(pkey, ec) == 1) {
        EC_POINT_free(p);
        return pkey;
    }
    EC_POINT_free(p);
    EVP_PKEY_free(pkey);
    EC_KEY_free(ec);
    return NULL;
}

static size_t ec_point_of(EVP_PKEY *pkey, uint8_t *out, size_t cap) {
    const EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
    if (!ec || !EC_KEY_get0_public_key(ec)) return 0;
    return EC_POINT_point2oct(EC_KEY_get0_group(ec), EC_KEY_get0_public_key(ec), POINT_CONVERSION_UNCOMPRESSED, out,
                              cap, NULL);
}

static EVP_PKEY *rsa_from_numbers(const uint8_t *n, size_t n_len, const uint8_t *e, size_t e_len) {
    RSA *rsa = RSA_new();
    BIGNUM *bn_n = BN_bin2bn(n, n_len, NULL);
    BIGNUM *bn_e = BN_bin2bn(e, e_len, NULL);
    EVP_PKEY *pkey = NULL;
    if (rsa && bn_n && bn_e && RSA_set0_key(rsa, bn_n, bn_e, NULL) == 1) {
        bn_n = bn_e = NULL; // rsa's now
        if ((pkey = EVP_PKEY_new()) && EVP_PKEY_assign_RSA(pkey, rsa) == 1) return pkey;
    }
    EVP_PKEY_free(pkey);
    RSA_free(rsa);
    BN_free(bn_n);
    BN_free(bn_e);
    return NULL;
}

static int rsa_numbers_of(EVP_PKEY *pkey, uint8_t *n, size_t *n_len, uint8_t *e, size_t *e_len) {
    const RSA *rsa = EVP_PKEY_get0_RSA(pkey);
    if (!rsa) return -1;
    const BIGNUM *bn_n = NULL, *bn_e = NULL;
    RSA_get0_key(rsa, &bn_n, &bn_e, NULL);
    size_t nn = BN_num_bytes(bn_n), ne = BN_num_bytes(bn_e);
    if (nn > *n_len || ne > *e_len) return -1;
    BN_bn2bin(bn_n, n);
    BN_bn2bin(bn_e, e);
    *n_len = nn;
    *e_len = ne;
    return 0;
}
#else
static const char *curve_group_name(int type) {
    switch (type) {
    case CV_KEY_EC_P256: return "prime256v1";
    case CV_KEY_EC_P384: return "secp384r1";
    case CV_KEY_EC_P521: return "secp521r1";
    default: return NULL;
    }
}

static int ec_type_of(EVP_PKEY *pkey) {
    char name[64];
    size_t len = 0;
    if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, name, sizeof name, &len) != 1) return -1;
    if (strcmp(name, "prime256v1") == 0 || strcmp(name, "P-256") == 0) return CV_KEY_EC_P256;
    if (strcmp(name, "secp384r1") == 0 || strcmp(name, "P-384") == 0) return CV_KEY_EC_P384;
    if (strcmp(name, "secp521r1") == 0 || strcmp(name, "P-521") == 0) return CV_KEY_EC_P521;
    return -1;
}

static EVP_PKEY *from_params(const char *type, OSSL_PARAM *params) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, type, NULL);
    EVP_PKEY *pkey = NULL;
    if (ctx && EVP_PKEY_fromdata_init(ctx) == 1) {
        if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) pkey = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static EVP_PKEY *ec_from_point(int type, const uint8_t *point, size_t len) {
    const char *group = curve_group_name(type);
    if (!group) return NULL;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)group, 0),
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)(uintptr_t)point, len),
        OSSL_PARAM_construct_end(),
    };
    return from_params("EC", params);
}

static size_t ec_point_of(EVP_PKEY *pkey, uint8_t *out, size_t cap) {
    size_t len = 0;
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, out, cap, &len) != 1) return 0;
    return len;
}

static EVP_PKEY *rsa_from_numbers(const uint8_t *n, size_t n_len, const uint8_t *e, size_t e_len) {
    BIGNUM *bn_n = BN_bin2bn(n, (int)n_len, NULL);
    BIGNUM *bn_e = BN_bin2bn(e, (int)e_len, NULL);
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    EVP_PKEY *pkey = NULL;
    if (bn_n && bn_e && bld && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn_n) &&
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, bn_e) && (params = OSSL_PARAM_BLD_to_param(bld)))
        pkey = from_params("RSA", params);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(bn_n);
    BN_free(bn_e);
    return pkey;
}

static int bn_param(EVP_PKEY *pkey, const char *name, uint8_t *out, size_t *len) {
    BIGNUM *bn = NULL;
    if (EVP_PKEY_get_bn_param(pkey, name, &bn) != 1) return -1;
    size_t size = (size_t)BN_num_bytes(bn);
    int rc = -1;
    if (size <= *len) {
        BN_bn2bin(bn, out);
        *len = size;
        rc = 0;
    }
    BN_free(bn);
    return rc;
}

static int rsa_numbers_of(EVP_PKEY *pkey, uint8_t *n, size_t *n_len, uint8_t *e, size_t *e_len) {
    if (bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, n, n_len) != 0) return -1;
    return bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, e, e_len);
}
#endif

/// A new key pair: RSA (bits), an EC curve, Ed25519 or X25519, by the EVP
/// calls both libraries have.
static EVP_PKEY *keygen(int id, int nid, int bits) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(id, NULL);
    if (!ctx) return NULL;
    EVP_PKEY *pkey = NULL;
    int ok = EVP_PKEY_keygen_init(ctx) == 1;
    if (ok && id == EVP_PKEY_EC) ok = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) == 1;
    if (ok && id == EVP_PKEY_RSA) ok = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) == 1;
    if (!ok || EVP_PKEY_keygen(ctx, &pkey) != 1) pkey = NULL;
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

// MARK: - Key exchange

struct cv_kex {
    EVP_PKEY *key;
    int group;
    uint8_t pub[1 + 2 * 66];
    size_t pub_len;
};

cv_kex *cv_kex_new(int group, const uint8_t *private_key, size_t private_len) {
    EVP_PKEY *key = NULL;
    switch (group) {
    case CV_KEX_X25519:
        if (private_key) {
            if (private_len != 32) return NULL;
            key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, private_key, private_len);
        } else {
            key = keygen(EVP_PKEY_X25519, 0, 0);
        }
        break;
    case CV_KEX_P256:
    case CV_KEX_P384:
        if (private_key) return NULL;
        key = keygen(EVP_PKEY_EC, group == CV_KEX_P256 ? NID_X9_62_prime256v1 : NID_secp384r1, 0);
        break;
    default: return NULL;
    }
    if (!key) return NULL;
    cv_kex *k = calloc(1, sizeof *k);
    if (!k) {
        EVP_PKEY_free(key);
        return NULL;
    }
    k->key = key;
    k->group = group;
    if (group == CV_KEX_X25519) {
        k->pub_len = sizeof k->pub;
        if (EVP_PKEY_get_raw_public_key(key, k->pub, &k->pub_len) != 1) k->pub_len = 0;
    } else {
        k->pub_len = ec_point_of(key, k->pub, sizeof k->pub);
    }
    if (k->pub_len == 0) {
        cv_kex_free(k);
        return NULL;
    }
    return k;
}

void cv_kex_free(cv_kex *k) {
    if (!k) return;
    EVP_PKEY_free(k->key);
    free(k);
}

intptr_t cv_kex_public(const cv_kex *k, uint8_t *out, size_t cap) {
    if (!k || cap < k->pub_len) return -1;
    memcpy(out, k->pub, k->pub_len);
    return (intptr_t)k->pub_len;
}

intptr_t cv_kex_derive(const cv_kex *k, const uint8_t *peer, size_t peer_len, uint8_t *out, size_t cap) {
    if (!k || !peer) return -1;
    EVP_PKEY *pub = NULL;
    if (k->group == CV_KEX_X25519) {
        if (peer_len != 32) return -1;
        pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer, peer_len);
    } else {
        // An uncompressed point, on the right curve.
        if (peer_len != k->pub_len || peer[0] != 0x04) return -1;
        pub = ec_from_point(k->group == CV_KEX_P256 ? CV_KEY_EC_P256 : CV_KEY_EC_P384, peer, peer_len);
    }
    if (!pub) return -1;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(k->key, NULL);
    intptr_t rc = -1;
    size_t n = cap;
    if (ctx && EVP_PKEY_derive_init(ctx) == 1 && EVP_PKEY_derive_set_peer(ctx, pub) == 1 &&
        EVP_PKEY_derive(ctx, out, &n) == 1)
        rc = (intptr_t)n;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pub);
    return rc;
}

// MARK: - Keys

struct cv_key {
    EVP_PKEY *pkey;
    int type;
    int has_private;
};

static int classify(EVP_PKEY *pkey) {
    switch (EVP_PKEY_get_base_id(pkey)) {
    case EVP_PKEY_RSA: return CV_KEY_RSA;
    case EVP_PKEY_ED25519: return CV_KEY_ED25519;
    case EVP_PKEY_EC: return ec_type_of(pkey);
    default: return -1;
    }
}

/// Takes pkey: a key of a kind we know, or NULL (pkey freed).
static cv_key *wrap(EVP_PKEY *pkey, int has_private) {
    if (!pkey) return NULL;
    int type = classify(pkey);
    // An RSA key too small to be safe is refused rather than trusted.
    if (type < 0 || (type == CV_KEY_RSA && EVP_PKEY_get_bits(pkey) < 2048)) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    cv_key *k = calloc(1, sizeof *k);
    if (!k) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    k->pkey = pkey;
    k->type = type;
    k->has_private = has_private;
    return k;
}

cv_key *cv_key_from_pem(const char *pem, size_t len) {
    if (!pem || len == 0 || len > (1 << 20)) return NULL;
    BIO *bio = BIO_new_mem_buf(pem, (int)len);
    EVP_PKEY *pkey = bio ? PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL) : NULL;
    BIO_free(bio);
    if (pkey) return wrap(pkey, 1);
    ERR_clear_error();
    bio = BIO_new_mem_buf(pem, (int)len);
    pkey = bio ? PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL) : NULL;
    BIO_free(bio);
    if (!pkey) {
        ERR_clear_error();
        bio = BIO_new_mem_buf(pem, (int)len);
        X509 *cert = bio ? PEM_read_bio_X509(bio, NULL, NULL, NULL) : NULL;
        BIO_free(bio);
        if (cert) {
            pkey = X509_get_pubkey(cert);
            X509_free(cert);
        }
    }
    return wrap(pkey, 0);
}

cv_key *cv_key_from_certificate(const uint8_t *der, size_t len) {
    if (!der || len == 0 || len > LONG_MAX) return NULL;
    const uint8_t *p = der;
    X509 *cert = d2i_X509(NULL, &p, (long)len);
    if (!cert) return NULL;
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    X509_free(cert);
    return wrap(pkey, 0);
}

cv_key *cv_key_from_rsa(const uint8_t *n, size_t n_len, const uint8_t *e, size_t e_len) {
    if (!n || !e || n_len == 0 || e_len == 0 || n_len > 2048 || e_len > 16) return NULL;
    return wrap(rsa_from_numbers(n, n_len, e, e_len), 0);
}

cv_key *cv_key_from_ec(int type, const uint8_t *x, size_t x_len, const uint8_t *y, size_t y_len) {
    size_t size = curve_size(type);
    if (!size || !x || !y || x_len != size || y_len != size) return NULL;
    uint8_t point[1 + 2 * 66];
    point[0] = 0x04;
    memcpy(point + 1, x, size);
    memcpy(point + 1 + size, y, size);
    return wrap(ec_from_point(type, point, 1 + 2 * size), 0);
}

cv_key *cv_key_from_ed25519(const uint8_t *public_key, size_t len) {
    if (!public_key || len != 32) return NULL;
    return wrap(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, public_key, len), 0);
}

cv_key *cv_key_from_ed25519_private(const uint8_t *seed, size_t len) {
    if (!seed || len != 32) return NULL;
    return wrap(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, len), 1);
}

cv_key *cv_key_generate(int type, int bits) {
    switch (type) {
    case CV_KEY_RSA: return wrap(keygen(EVP_PKEY_RSA, 0, bits >= 2048 ? bits : 2048), 1);
    case CV_KEY_EC_P256:
    case CV_KEY_EC_P384:
    case CV_KEY_EC_P521: return wrap(keygen(EVP_PKEY_EC, curve_nid(type), 0), 1);
    case CV_KEY_ED25519: return wrap(keygen(EVP_PKEY_ED25519, 0, 0), 1);
    default: return NULL;
    }
}

void cv_key_free(cv_key *k) {
    if (!k) return;
    EVP_PKEY_free(k->pkey);
    free(k);
}

cv_key *cv_key_retain(cv_key *k) {
    if (!k) return NULL;
    cv_key *c = calloc(1, sizeof *c);
    if (!c) return NULL;
    EVP_PKEY_up_ref(k->pkey);
    *c = *k;
    return c;
}

int cv_key_type(const cv_key *k) { return k ? k->type : -1; }
int cv_key_has_private(const cv_key *k) { return k ? k->has_private : 0; }
int cv_key_bits(const cv_key *k) { return k ? EVP_PKEY_get_bits(k->pkey) : -1; }
int cv_key_signature_max(const cv_key *k) { return k ? EVP_PKEY_get_size(k->pkey) : -1; }

intptr_t cv_key_pem(const cv_key *k, int private_key, char *out, size_t cap) {
    if (!k || (private_key && !k->has_private)) return -1;
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) return -1;
    int ok = private_key ? PEM_write_bio_PrivateKey(bio, k->pkey, NULL, NULL, 0, NULL, NULL)
                         : PEM_write_bio_PUBKEY(bio, k->pkey);
    intptr_t rc = -1;
    if (ok) {
        char *data = NULL;
        long len = BIO_get_mem_data(bio, &data);
        if (!out) {
            rc = len;
        } else if (len >= 0 && (size_t)len <= cap) {
            memcpy(out, data, (size_t)len);
            rc = len;
        }
    }
    BIO_free(bio);
    return rc;
}

int cv_key_rsa_numbers(const cv_key *k, uint8_t *n, size_t *n_len, uint8_t *e, size_t *e_len) {
    if (!k || k->type != CV_KEY_RSA) return -1;
    return rsa_numbers_of(k->pkey, n, n_len, e, e_len);
}

int cv_key_ec_point(const cv_key *k, uint8_t *x, size_t *x_len, uint8_t *y, size_t *y_len) {
    size_t size = k ? curve_size(k->type) : 0;
    if (!size || *x_len < size || *y_len < size) return -1;
    uint8_t point[1 + 2 * 66];
    size_t len = ec_point_of(k->pkey, point, sizeof point);
    if (len != 1 + 2 * size || point[0] != 0x04) return -1;
    memcpy(x, point + 1, size);
    memcpy(y, point + 1 + size, size);
    *x_len = size;
    *y_len = size;
    return 0;
}

int cv_key_raw_public(const cv_key *k, uint8_t *out, size_t *out_len) {
    if (!k || k->type != CV_KEY_ED25519) return -1;
    return EVP_PKEY_get_raw_public_key(k->pkey, out, out_len) == 1 ? 0 : -1;
}

// MARK: - Signatures

#define PAD_NONE 0
#define PAD_PKCS1 1
#define PAD_PSS 2

/// What a signature needs: the key type it's for, the digest, the padding.
struct sig_params {
    int key_type; // CV_KEY_EC_* for ECDSA, CV_KEY_RSA, CV_KEY_ED25519
    const EVP_MD *md;
    int padding;
};

static int jws_params(int alg, struct sig_params *p) {
    p->padding = PAD_NONE;
    switch (alg) {
    case CV_JWS_RS256: *p = (struct sig_params){CV_KEY_RSA, EVP_sha256(), PAD_PKCS1}; return 0;
    case CV_JWS_RS384: *p = (struct sig_params){CV_KEY_RSA, EVP_sha384(), PAD_PKCS1}; return 0;
    case CV_JWS_RS512: *p = (struct sig_params){CV_KEY_RSA, EVP_sha512(), PAD_PKCS1}; return 0;
    case CV_JWS_PS256: *p = (struct sig_params){CV_KEY_RSA, EVP_sha256(), PAD_PSS}; return 0;
    case CV_JWS_PS384: *p = (struct sig_params){CV_KEY_RSA, EVP_sha384(), PAD_PSS}; return 0;
    case CV_JWS_PS512: *p = (struct sig_params){CV_KEY_RSA, EVP_sha512(), PAD_PSS}; return 0;
    case CV_JWS_ES256: *p = (struct sig_params){CV_KEY_EC_P256, EVP_sha256(), PAD_NONE}; return 0;
    case CV_JWS_ES384: *p = (struct sig_params){CV_KEY_EC_P384, EVP_sha384(), PAD_NONE}; return 0;
    case CV_JWS_ES512: *p = (struct sig_params){CV_KEY_EC_P521, EVP_sha512(), PAD_NONE}; return 0;
    case CV_JWS_EDDSA: *p = (struct sig_params){CV_KEY_ED25519, NULL, PAD_NONE}; return 0;
    default: return -1;
    }
}

static int tls_params(uint16_t scheme, struct sig_params *p) {
    switch (scheme) {
    case CV_SIG_ECDSA_SECP256R1_SHA256: *p = (struct sig_params){CV_KEY_EC_P256, EVP_sha256(), PAD_NONE}; return 0;
    case CV_SIG_ECDSA_SECP384R1_SHA384: *p = (struct sig_params){CV_KEY_EC_P384, EVP_sha384(), PAD_NONE}; return 0;
    case CV_SIG_ECDSA_SECP521R1_SHA512: *p = (struct sig_params){CV_KEY_EC_P521, EVP_sha512(), PAD_NONE}; return 0;
    case CV_SIG_RSA_PSS_RSAE_SHA256: *p = (struct sig_params){CV_KEY_RSA, EVP_sha256(), PAD_PSS}; return 0;
    case CV_SIG_RSA_PSS_RSAE_SHA384: *p = (struct sig_params){CV_KEY_RSA, EVP_sha384(), PAD_PSS}; return 0;
    case CV_SIG_RSA_PSS_RSAE_SHA512: *p = (struct sig_params){CV_KEY_RSA, EVP_sha512(), PAD_PSS}; return 0;
    case CV_SIG_ED25519: *p = (struct sig_params){CV_KEY_ED25519, NULL, PAD_NONE}; return 0;
    default: return -1;
    }
}

static EVP_MD_CTX *digest_context(const cv_key *k, const struct sig_params *p, int signing) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int ok = signing ? EVP_DigestSignInit(ctx, &pctx, p->md, NULL, k->pkey)
                     : EVP_DigestVerifyInit(ctx, &pctx, p->md, NULL, k->pkey);
    if (ok == 1 && p->padding == PAD_PSS) {
        // RFC 7518 3.5 and RFC 8446 4.2.3: the salt is as long as the hash.
        ok = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0 &&
             EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) > 0;
    } else if (ok == 1 && p->padding == PAD_PKCS1) {
        ok = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) > 0;
    }
    if (ok != 1) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

static int is_ec(int type) { return type == CV_KEY_EC_P256 || type == CV_KEY_EC_P384 || type == CV_KEY_EC_P521; }

/// The signature, as the library makes it (ECDSA in DER).
static intptr_t sign_raw(const cv_key *k, const struct sig_params *p, const void *data, size_t len, uint8_t *out,
                         size_t cap) {
    if (!k || !k->has_private || k->type != p->key_type) return -1;
    EVP_MD_CTX *ctx = digest_context(k, p, 1);
    if (!ctx) return -1;
    static const uint8_t empty = 0;
    size_t n = cap;
    intptr_t rc = -1;
    if (EVP_DigestSign(ctx, out, &n, len ? data : &empty, len) == 1) rc = (intptr_t)n;
    EVP_MD_CTX_free(ctx);
    return rc;
}

static int verify_raw(const cv_key *k, const struct sig_params *p, const void *data, size_t len, const uint8_t *sig,
                      size_t sig_len) {
    EVP_MD_CTX *ctx = digest_context(k, p, 0);
    if (!ctx) return 0;
    static const uint8_t empty = 0;
    int ok = EVP_DigestVerify(ctx, sig, sig_len, len ? data : &empty, len) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok) ERR_clear_error();
    return ok;
}

intptr_t cv_key_sign_jws(const cv_key *k, int alg, const void *data, size_t len, uint8_t *out, size_t cap) {
    struct sig_params p;
    if (!k || jws_params(alg, &p) != 0 || k->type != p.key_type) return -1;
    if (!is_ec(k->type)) return sign_raw(k, &p, data, len, out, cap);
    // JWS has r and s at the curve's size, not DER.
    size_t size = curve_size(k->type);
    if (cap < 2 * size) return -1;
    uint8_t der[160];
    intptr_t n = sign_raw(k, &p, data, len, der, sizeof der);
    if (n <= 0) return -1;
    const uint8_t *q = der;
    ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &q, (long)n);
    intptr_t rc = -1;
    if (sig) {
        const BIGNUM *r = NULL, *s = NULL;
        ECDSA_SIG_get0(sig, &r, &s);
        if (bn_to_padded(r, out, size) && bn_to_padded(s, out + size, size)) rc = (intptr_t)(2 * size);
        ECDSA_SIG_free(sig);
    }
    return rc;
}

int cv_key_verify_jws(const cv_key *k, int alg, const void *data, size_t len, const uint8_t *sig, size_t sig_len) {
    struct sig_params p;
    if (!k || jws_params(alg, &p) != 0 || k->type != p.key_type) return -1;
    if (!sig) return 0;
    if (!is_ec(k->type)) return verify_raw(k, &p, data, len, sig, sig_len);
    size_t size = curve_size(k->type);
    if (sig_len != 2 * size) return 0;
    ECDSA_SIG *es = ECDSA_SIG_new();
    BIGNUM *r = BN_bin2bn(sig, (int)size, NULL);
    BIGNUM *s = BN_bin2bn(sig + size, (int)size, NULL);
    if (!es || !r || !s || ECDSA_SIG_set0(es, r, s) != 1) {
        ECDSA_SIG_free(es);
        BN_free(r);
        BN_free(s);
        return 0;
    }
    uint8_t *der = NULL;
    int der_len = i2d_ECDSA_SIG(es, &der);
    ECDSA_SIG_free(es);
    if (der_len <= 0) return 0;
    int ok = verify_raw(k, &p, data, len, der, (size_t)der_len);
    OPENSSL_free(der);
    return ok;
}

int cv_key_tls_schemes(const cv_key *k, uint16_t *out, int max) {
    if (!k || max <= 0) return 0;
    int n = 0;
    switch (k->type) {
    case CV_KEY_RSA:
        if (n < max) out[n++] = CV_SIG_RSA_PSS_RSAE_SHA256;
        if (n < max) out[n++] = CV_SIG_RSA_PSS_RSAE_SHA384;
        if (n < max) out[n++] = CV_SIG_RSA_PSS_RSAE_SHA512;
        break;
    // The curve fixes the digest.
    case CV_KEY_EC_P256: out[n++] = CV_SIG_ECDSA_SECP256R1_SHA256; break;
    case CV_KEY_EC_P384: out[n++] = CV_SIG_ECDSA_SECP384R1_SHA384; break;
    case CV_KEY_EC_P521: out[n++] = CV_SIG_ECDSA_SECP521R1_SHA512; break;
    case CV_KEY_ED25519: out[n++] = CV_SIG_ED25519; break;
    default: break;
    }
    return n;
}

intptr_t cv_key_sign_tls(const cv_key *k, uint16_t scheme, const void *msg, size_t len, uint8_t *out, size_t cap) {
    struct sig_params p;
    if (!k || tls_params(scheme, &p) != 0) return -1;
    return sign_raw(k, &p, msg, len, out, cap);
}

int cv_key_verify_tls(const cv_key *k, uint16_t scheme, const void *msg, size_t len, const uint8_t *sig,
                      size_t sig_len) {
    struct sig_params p;
    if (!k || tls_params(scheme, &p) != 0 || k->type != p.key_type) return -1;
    if (!sig) return 0;
    return verify_raw(k, &p, msg, len, sig, sig_len);
}

// MARK: - Certificate keys

#define MAX_CHAIN 16

struct cv_certkey {
    X509 *chain[MAX_CHAIN];
    int count;
    cv_key *key;
};

static void load_error(char *err, size_t err_len, const char *what) {
    if (!err || !err_len) {
        ERR_clear_error();
        return;
    }
    unsigned long e = ERR_peek_last_error();
    const char *reason = e ? ERR_reason_error_string(e) : NULL;
    if (reason)
        snprintf(err, err_len, "%s: %s", what, reason);
    else
        snprintf(err, err_len, "%s", what);
    ERR_clear_error();
}

static BIO *open_pem(const char *source, size_t len, int from_files) {
    if (from_files) return BIO_new_file(source, "r");
    if (len > INT_MAX) return NULL;
    return BIO_new_mem_buf(source, (int)len);
}

cv_certkey *cv_certkey_load(const char *chain, size_t chain_len, const char *key, size_t key_len, int from_files,
                            char *err, size_t err_len) {
    ERR_clear_error();
    if (err && err_len) err[0] = 0;
    if (!chain || !key) {
        load_error(err, err_len, "no certificate or key");
        return NULL;
    }
    cv_certkey *ck = calloc(1, sizeof *ck);
    if (!ck) return NULL;
    BIO *bio = open_pem(chain, chain_len, from_files);
    if (!bio) {
        load_error(err, err_len, "cannot read the certificate chain");
        free(ck);
        return NULL;
    }
    while (ck->count < MAX_CHAIN) {
        X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (!cert) break;
        ck->chain[ck->count++] = cert;
    }
    BIO_free(bio);
    if (ck->count == 0) {
        load_error(err, err_len, "no certificate in the chain");
        free(ck);
        return NULL;
    }
    ERR_clear_error(); // the end of the PEM reads as an error

    EVP_PKEY *pkey = NULL;
    bio = open_pem(key, key_len, from_files);
    if (bio) {
        pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        BIO_free(bio);
    }
    if (!pkey) {
        load_error(err, err_len, "cannot read the private key");
        cv_certkey_free(ck);
        return NULL;
    }
    if (X509_check_private_key(ck->chain[0], pkey) != 1) {
        EVP_PKEY_free(pkey);
        load_error(err, err_len, "the private key is not the certificate's");
        cv_certkey_free(ck);
        return NULL;
    }
    ck->key = wrap(pkey, 1);
    if (!ck->key) {
        load_error(err, err_len, "unsupported key (RSA of 2048 bits or more, P-256, P-384, P-521 or Ed25519)");
        cv_certkey_free(ck);
        return NULL;
    }
    return ck;
}

void cv_certkey_free(cv_certkey *ck) {
    if (!ck) return;
    for (int i = 0; i < ck->count; i++) X509_free(ck->chain[i]);
    cv_key_free(ck->key);
    free(ck);
}

int cv_certkey_chain_count(const cv_certkey *ck) { return ck ? ck->count : 0; }

intptr_t cv_certkey_cert_der(const cv_certkey *ck, int index, uint8_t *out, size_t cap) {
    if (!ck || index < 0 || index >= ck->count) return -1;
    int n = i2d_X509(ck->chain[index], NULL);
    if (n <= 0) return -1;
    if (!out) return n;
    if ((size_t)n > cap) return -1;
    uint8_t *p = out;
    return i2d_X509(ck->chain[index], &p);
}

cv_key *cv_certkey_key(const cv_certkey *ck) { return ck ? cv_key_retain(ck->key) : NULL; }

int cv_certkey_matches(const cv_certkey *ck, const char *host, size_t host_len) {
    if (!ck || ck->count == 0 || !host || host_len == 0) return 0;
    // A DNS name is at most 253 bytes; a NUL inside matches nothing.
    char name[256];
    if (host_len >= sizeof name || memchr(host, 0, host_len)) return 0;
    memcpy(name, host, host_len);
    name[host_len] = 0;

    X509 *cert = ck->chain[0];
    int matched = 0, dns_names = 0;
    GENERAL_NAMES *sans = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (sans) {
        size_t n = sk_GENERAL_NAME_num(sans);
        for (size_t i = 0; i < n && !matched; i++) {
            const GENERAL_NAME *entry = sk_GENERAL_NAME_value(sans, i);
            if (!entry || entry->type != GEN_DNS) continue;
            dns_names++;
            const unsigned char *bytes = ASN1_STRING_get0_data(entry->d.dNSName);
            int length = ASN1_STRING_length(entry->d.dNSName);
            if (length <= 0 || (size_t)length >= sizeof name || memchr(bytes, 0, (size_t)length)) continue;
            char pattern[256];
            memcpy(pattern, bytes, (size_t)length);
            pattern[length] = 0;
            matched = cv_host_matches(pattern, name);
        }
        GENERAL_NAMES_free(sans);
    }
    ERR_clear_error();
    // Subject alternative names, when there are any, say it all.
    if (dns_names > 0) return matched;
    char common[256];
    int length = X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, common, sizeof common);
    ERR_clear_error();
    if (length <= 0) return 0;
    return cv_host_matches(common, name);
}

int cv_certkey_name(const cv_certkey *ck, int index, char *out, size_t cap) {
    if (!ck || ck->count == 0 || index < 0 || !out || cap == 0) return -1;
    X509 *cert = ck->chain[0];
    int dns_names = 0, found = -1;
    GENERAL_NAMES *sans = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (sans) {
        size_t n = sk_GENERAL_NAME_num(sans);
        for (size_t i = 0; i < n; i++) {
            const GENERAL_NAME *entry = sk_GENERAL_NAME_value(sans, i);
            if (!entry || entry->type != GEN_DNS) continue;
            if (dns_names++ != index) continue;
            const unsigned char *bytes = ASN1_STRING_get0_data(entry->d.dNSName);
            int length = ASN1_STRING_length(entry->d.dNSName);
            if (length >= 0 && (size_t)length < cap) {
                memcpy(out, bytes, (size_t)length);
                out[length] = 0;
                found = length;
            }
            break;
        }
        GENERAL_NAMES_free(sans);
    }
    ERR_clear_error();
    // As matching reads it: the common name only when there are no DNS
    // subject alternative names.
    if (dns_names > 0 || index > 0) return found;
    int length = X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, out, (int)cap);
    ERR_clear_error();
    return length > 0 ? length : -1;
}

#endif // CV_HAVE_CRYPTO
