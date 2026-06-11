#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include "config.h"

/* Forward-declare OpenSSL type to avoid pulling EVP headers everywhere */
typedef struct evp_pkey_st EVP_PKEY;

/* ── Key types ──────────────────────────────────────────────────────────── */

/* Ephemeral P-256 ECDH key pair.
 * pkey         - OpenSSL private+public key object.
 * pubkey_bytes - 65-byte uncompressed public key, safe to send over the wire. */
typedef struct {
    EVP_PKEY *pkey;
    uint8_t   pubkey_bytes[EC_PUBKEY_LEN];
} ecdh_keypair_t;

/* AES-256 symmetric key derived from ECDHE via HKDF-SHA256. */
typedef struct {
    uint8_t key[AES_KEY_LEN];
} aes_key_t;

/* ── ECDHE ──────────────────────────────────────────────────────────────── */

/* Generate a fresh ephemeral P-256 key pair.
 * Returns 0 on success, -1 on failure. */
int crypto_ecdh_keygen(ecdh_keypair_t *kp);

/* Compute ECDH shared secret from local private key + remote 65-byte public key,
 * then derive a 32-byte AES-256 key via HKDF-SHA256.
 * Returns 0 on success, -1 on failure. */
int crypto_ecdh_derive(const ecdh_keypair_t *local_kp,
                       const uint8_t        *remote_pubkey,
                       aes_key_t            *out_key);

/* Release OpenSSL key memory. */
void crypto_ecdh_free(ecdh_keypair_t *kp);

/* Write/read a node's 65-byte public key to/from a binary file.
 * Nodes call save at startup; client calls load before path creation. */
int crypto_pubkey_save(const ecdh_keypair_t *kp, const char *path);
int crypto_pubkey_load(uint8_t out[EC_PUBKEY_LEN], const char *path);

/* ── AES-256-GCM ────────────────────────────────────────────────────────────
 *
 * Wire layout of every encrypted blob:
 *   [ nonce : 12 bytes ] [ ciphertext : plaintext_len bytes ] [ tag : 16 bytes ]
 *
 * GCM_OVERHEAD = 28 bytes added per encryption.
 * A fresh random nonce is generated on every encrypt call.
 * Tags are always 128-bit — never truncated.
 */

/* Encrypt plaintext → out.
 * out_size must be >= plaintext_len + GCM_OVERHEAD.
 * Returns total bytes written, or -1 on error. */
int crypto_aes_encrypt(const aes_key_t *key,
                       const uint8_t   *plaintext,     size_t plaintext_len,
                       uint8_t         *out,           size_t out_size);

/* Decrypt and authenticate in → out.
 * Returns plaintext byte count, or -1 on authentication failure.
 * Always treat -1 as fatal — never forward a packet that fails auth. */
int crypto_aes_decrypt(const aes_key_t *key,
                       const uint8_t   *in,            size_t in_len,
                       uint8_t         *out,           size_t out_size);

/* ── Utilities ──────────────────────────────────────────────────────────── */

/* Print label + hex to stderr. Debug only — remove before benchmarking. */
void crypto_hexdump(const char *label, const uint8_t *data, size_t len);

/* Constant-time memory compare. Returns 0 if equal, non-zero otherwise. */
int crypto_memcmp(const void *a, const void *b, size_t n);

#endif /* CRYPTO_H */
