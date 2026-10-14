// SHA-256, HMAC-SHA-256 and PBKDF2-HMAC-SHA-256: what a protocol's
// authentication needs (PostgreSQL's SCRAM, signed cookies), from the TLS
// library where there is one, and from CommonCrypto on Apple's platforms,
// which have it whether or not there is.
#include "cvega_tls.h"

#if defined(__APPLE__)
#include <CommonCrypto/CommonCryptoError.h>
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonKeyDerivation.h>
#define CV_DIGEST_COMMONCRYPTO 1
#elif defined(VEGA_TLS_BORINGSSL)
#include "CVegaBoringSSL_evp.h"
#include "CVegaBoringSSL_hmac.h"
#include "CVegaBoringSSL_sha.h"
#define CV_DIGEST_LIBCRYPTO 1
#elif defined(VEGA_TLS_OPENSSL) && __has_include(<openssl/evp.h>)
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#define CV_DIGEST_LIBCRYPTO 1
#endif

#include <limits.h>

int cv_digest_available(void) {
#if CV_DIGEST_COMMONCRYPTO || CV_DIGEST_LIBCRYPTO
    return 1;
#else
    return 0;
#endif
}

int cv_sha256(const void *data, intptr_t len, uint8_t *out) {
    if (len < 0) return -1;
#if CV_DIGEST_COMMONCRYPTO
    if (len > UINT32_MAX) return -1;
    CC_SHA256(data, (CC_LONG)len, out);
    return 0;
#elif CV_DIGEST_LIBCRYPTO
    return SHA256(data, (size_t)len, out) ? 0 : -1;
#else
    (void)data; (void)out;
    return -1;
#endif
}

int cv_hmac_sha256(const void *key, intptr_t key_len, const void *data, intptr_t len, uint8_t *out) {
    if (key_len < 0 || len < 0) return -1;
#if CV_DIGEST_COMMONCRYPTO
    CCHmac(kCCHmacAlgSHA256, key, (size_t)key_len, data, (size_t)len, out);
    return 0;
#elif CV_DIGEST_LIBCRYPTO
    if (key_len > INT_MAX) return -1;
    unsigned int n = 0;
    return HMAC(EVP_sha256(), key, (int)key_len, data, (size_t)len, out, &n) && n == 32 ? 0 : -1;
#else
    (void)key; (void)data; (void)out;
    return -1;
#endif
}

int cv_pbkdf2_sha256(const void *password, intptr_t password_len, const void *salt, intptr_t salt_len,
                     uint32_t iterations, uint8_t *out, intptr_t out_len) {
    if (password_len < 0 || salt_len < 0 || out_len <= 0 || iterations == 0) return -1;
#if CV_DIGEST_COMMONCRYPTO
    return CCKeyDerivationPBKDF(kCCPBKDF2, password, (size_t)password_len, salt, (size_t)salt_len,
                                kCCPRFHmacAlgSHA256, iterations, out, (size_t)out_len) == kCCSuccess ? 0 : -1;
#elif CV_DIGEST_LIBCRYPTO
    if (password_len > INT_MAX || salt_len > INT_MAX || out_len > INT_MAX || iterations > INT_MAX) return -1;
    return PKCS5_PBKDF2_HMAC(password, (int)password_len, salt, (int)salt_len, (int)iterations, EVP_sha256(),
                             (int)out_len, out) == 1 ? 0 : -1;
#else
    (void)password; (void)salt; (void)out;
    return -1;
#endif
}
