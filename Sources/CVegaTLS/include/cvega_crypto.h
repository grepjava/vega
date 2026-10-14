// Cryptographic primitives for VegaCrypto, over the same library as VegaTLS
// (the system's OpenSSL 3, or the vendored BoringSSL with the BoringSSL
// trait): hashes, HMAC, PBKDF2, HKDF, AEAD, QUIC header protection, key
// exchange, signing keys and certificate keys. No library type appears here.
//
// Functions return 0 or a byte count on success and a negative number on
// failure, NULL for constructors. Buffers belong to the caller. A failure
// leaves the reason for cv_crypto_error, which takes it (per thread).
#ifndef CVEGA_CRYPTO_H
#define CVEGA_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// The library's reason for the last failure on this thread, into out
/// (NUL-terminated): its length, or 0 with none. Clears the queue.
int cv_crypto_error(char *out, size_t len);

/// Cryptographically secure random bytes: 0, or -1.
int cv_crypto_random(void *out, size_t len);
/// 1 if a and b (n bytes each) are equal, in time that doesn't depend on
/// where they differ.
int cv_crypto_memeq(const void *a, const void *b, size_t n);

// MARK: Hashes, HMAC, PBKDF2, HKDF

#define CV_SHA256 0
#define CV_SHA384 1
#define CV_SHA512 2

/// The digest's length, or -1 for an unknown algorithm.
int cv_hash_len(int alg);
int cv_hash(int alg, const void *data, size_t len, uint8_t *out);

/// An incremental hash. snapshot is the digest so far, leaving the context
/// running (a handshake transcript); final is the digest, and starts over.
typedef struct cv_hasher cv_hasher;
cv_hasher *cv_hash_new(int alg);
void cv_hash_free(cv_hasher *h);
int cv_hash_update(cv_hasher *h, const void *data, size_t len);
int cv_hash_snapshot(cv_hasher *h, uint8_t *out);
int cv_hash_final(cv_hasher *h, uint8_t *out);
/// A copy, with what was hashed so far.
cv_hasher *cv_hash_copy(const cv_hasher *h);

int cv_hmac(int alg, const void *key, size_t key_len, const void *data, size_t len, uint8_t *out);

/// An HMAC keyed once for many MACs. compute works from a copy of the keyed
/// state, so threads may share one.
typedef struct cv_hmac_key cv_hmac_key;
cv_hmac_key *cv_hmac_new(int alg, const void *key, size_t key_len);
void cv_hmac_free(cv_hmac_key *m);
int cv_hmac_compute(const cv_hmac_key *m, const void *data, size_t len, uint8_t *out);

/// PBKDF2 (RFC 8018) over HMAC with alg: out_len bytes.
int cv_pbkdf2(int alg, const void *password, size_t password_len, const void *salt, size_t salt_len,
              uint32_t iterations, uint8_t *out, size_t out_len);

/// HKDF (RFC 5869). An empty salt is a string of zeros. extract writes
/// cv_hash_len(alg) bytes; expand at most 255 times that.
int cv_hkdf_extract(int alg, const void *salt, size_t salt_len, const void *ikm, size_t ikm_len, uint8_t *out);
int cv_hkdf_expand(int alg, const void *prk, size_t prk_len, const void *info, size_t info_len, uint8_t *out,
                   size_t out_len);

// MARK: AEAD and QUIC header protection

#define CV_AEAD_AES128GCM 0
#define CV_AEAD_AES256GCM 1
#define CV_AEAD_CHACHA20POLY1305 2

/// The key's length, or -1. Nonces are 12 bytes and tags 16.
int cv_aead_key_len(int alg);

/// A key bound once, used for many messages: one thread at a time.
typedef struct cv_aead cv_aead;
cv_aead *cv_aead_new(int alg, const uint8_t *key, size_t key_len);
void cv_aead_free(cv_aead *a);
/// out takes pt_len + 16 bytes (and may be pt itself): the length written.
intptr_t cv_aead_seal(cv_aead *a, const uint8_t nonce[12], const void *aad, size_t aad_len, const void *pt,
                      size_t pt_len, uint8_t *out);
/// out takes ct_len - 16 bytes (and may be ct itself): the plaintext's
/// length, or -1 if the tag doesn't verify.
intptr_t cv_aead_open(cv_aead *a, const uint8_t nonce[12], const void *aad, size_t aad_len, const void *ct,
                      size_t ct_len, uint8_t *out);

/// QUIC header protection (RFC 9001 5.4) for an AEAD's packets: a 5-byte
/// mask from a 16-byte sample of ciphertext. One thread at a time.
typedef struct cv_hp cv_hp;
cv_hp *cv_hp_new(int alg, const uint8_t *key, size_t key_len);
void cv_hp_free(cv_hp *h);
int cv_hp_mask(cv_hp *h, const uint8_t sample[16], uint8_t mask[5]);

// MARK: Key exchange

#define CV_KEX_X25519 0
#define CV_KEX_P256 1
#define CV_KEX_P384 2

/// A key pair for one exchange: a new one, or (X25519 only) from the
/// 32-byte private key. Threads may share it.
typedef struct cv_kex cv_kex;
cv_kex *cv_kex_new(int group, const uint8_t *private_key, size_t private_len);
void cv_kex_free(cv_kex *k);
/// The public key in TLS's form: 32 bytes for X25519, an uncompressed
/// point for the curves. The length.
intptr_t cv_kex_public(const cv_kex *k, uint8_t *out, size_t cap);
/// The shared secret with the peer's public key: its length, or -1 when
/// that key is bad.
intptr_t cv_kex_derive(const cv_kex *k, const uint8_t *peer, size_t peer_len, uint8_t *out, size_t cap);

// MARK: Signing keys

#define CV_KEY_RSA 1
#define CV_KEY_EC_P256 2
#define CV_KEY_EC_P384 3
#define CV_KEY_EC_P521 4
#define CV_KEY_ED25519 5

/// Algorithms as JWS names them (RFC 7518, RFC 8037).
#define CV_JWS_RS256 4
#define CV_JWS_RS384 5
#define CV_JWS_RS512 6
#define CV_JWS_PS256 7
#define CV_JWS_PS384 8
#define CV_JWS_PS512 9
#define CV_JWS_ES256 10
#define CV_JWS_ES384 11
#define CV_JWS_ES512 12
#define CV_JWS_EDDSA 13

/// TLS 1.3 signature schemes, as on the wire.
#define CV_SIG_ECDSA_SECP256R1_SHA256 0x0403
#define CV_SIG_ECDSA_SECP384R1_SHA384 0x0503
#define CV_SIG_ECDSA_SECP521R1_SHA512 0x0603
#define CV_SIG_RSA_PSS_RSAE_SHA256 0x0804
#define CV_SIG_RSA_PSS_RSAE_SHA384 0x0805
#define CV_SIG_RSA_PSS_RSAE_SHA512 0x0806
#define CV_SIG_ED25519 0x0807

/// A public or private key; immutable, so threads may share one. RSA keys
/// under 2048 bits are refused.
typedef struct cv_key cv_key;
/// From PEM: a private key (PKCS #8, or the traditional RSA and EC forms), a
/// public key (SubjectPublicKeyInfo) or a certificate's.
cv_key *cv_key_from_pem(const char *pem, size_t len);
/// A certificate's public key, from DER.
cv_key *cv_key_from_certificate(const uint8_t *der, size_t len);
/// Public keys from JWK members, unsigned big-endian.
cv_key *cv_key_from_rsa(const uint8_t *n, size_t n_len, const uint8_t *e, size_t e_len);
cv_key *cv_key_from_ec(int type, const uint8_t *x, size_t x_len, const uint8_t *y, size_t y_len);
cv_key *cv_key_from_ed25519(const uint8_t *public_key, size_t len);
/// An Ed25519 private key from its 32-byte seed.
cv_key *cv_key_from_ed25519_private(const uint8_t *seed, size_t len);
/// A new private key: RSA of bits (at least 2048), a curve, or Ed25519.
cv_key *cv_key_generate(int type, int bits);
void cv_key_free(cv_key *k);
/// A second reference to the same key.
cv_key *cv_key_retain(cv_key *k);

int cv_key_type(const cv_key *k);
int cv_key_has_private(const cv_key *k);
int cv_key_bits(const cv_key *k);
/// The most a signature by this key takes.
int cv_key_signature_max(const cv_key *k);
/// The public key as SubjectPublicKeyInfo PEM, or the private key as
/// PKCS #8 PEM: the length, or the length needed with out NULL.
intptr_t cv_key_pem(const cv_key *k, int private_key, char *out, size_t cap);
/// JWK members, unsigned big-endian: n and e, x and y (each the curve's
/// size), or Ed25519's x. Lengths in and out; 0.
int cv_key_rsa_numbers(const cv_key *k, uint8_t *n, size_t *n_len, uint8_t *e, size_t *e_len);
int cv_key_ec_point(const cv_key *k, uint8_t *x, size_t *x_len, uint8_t *y, size_t *y_len);
int cv_key_raw_public(const cv_key *k, uint8_t *out, size_t *out_len);

/// JWS: a signature by a private key (ECDSA as JWS has it, r || s at the
/// curve's size; PS* with the salt the hash's length): its length.
intptr_t cv_key_sign_jws(const cv_key *k, int alg, const void *data, size_t len, uint8_t *out, size_t cap);
/// 1 if sig is data signed with alg by k, 0 if not, -1 if the algorithm
/// isn't one for this key.
int cv_key_verify_jws(const cv_key *k, int alg, const void *data, size_t len, const uint8_t *sig, size_t sig_len);

/// TLS 1.3 schemes this key signs with, best first: how many were written.
int cv_key_tls_schemes(const cv_key *k, uint16_t *out, int max);
/// A TLS signature (ECDSA in DER): its length.
intptr_t cv_key_sign_tls(const cv_key *k, uint16_t scheme, const void *msg, size_t len, uint8_t *out, size_t cap);
int cv_key_verify_tls(const cv_key *k, uint16_t scheme, const void *msg, size_t len, const uint8_t *sig,
                      size_t sig_len);

// MARK: Certificate keys

/// A certificate chain (leaf first) and the leaf's private key, from PEM
/// files (from_files 1: chain and key are paths) or PEM text. NULL with a
/// message in err on failure.
typedef struct cv_certkey cv_certkey;
cv_certkey *cv_certkey_load(const char *chain, size_t chain_len, const char *key, size_t key_len, int from_files,
                            char *err, size_t err_len);
void cv_certkey_free(cv_certkey *ck);
int cv_certkey_chain_count(const cv_certkey *ck);
/// One certificate's DER: its length, or the length needed with out NULL.
intptr_t cv_certkey_cert_der(const cv_certkey *ck, int index, uint8_t *out, size_t cap);
/// The private key: a new reference.
cv_key *cv_certkey_key(const cv_certkey *ck);
/// Whether the leaf is for host (not NUL-terminated): its DNS subject
/// alternative names, or its common name when it has none.
int cv_certkey_matches(const cv_certkey *ck, const char *host, size_t host_len);

/// RFC 6125 matching, case-insensitive; "*.example.com" covers exactly one
/// label in front. Both NUL-terminated.
int cv_host_matches(const char *pattern, const char *host);

#ifdef __cplusplus
}
#endif
#endif
