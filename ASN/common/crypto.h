#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include "config.h"

/* Forward-declare OpenSSL type to avoid pulling EVP headers everywhere */
typedef struct evp_pkey_st EVP_PKEY;

/* Key types */

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

/* ECDHE */

/* Generate a fresh ephemeral P-256 key pair.
 * Returns 0 on success, -1 on failure. */
int crypto_ecdh_keygen(ecdh_keypair_t *kp);

/* Compute ECDH shared secret from local private key + remote 65-byte public key,
 * then derive a 32-byte AES-256 key via HKDF-SHA256.
 * Returns 0 on success, -1 on failure. */
int crypto_ecdh_derive(const ecdh_keypair_t *local_kp,
                       const uint8_t        *remote_pubkey,
                       aes_key_t            *out_key);

/* crypto_ecdh_derive() above binds only the raw ECDH shared secret into
 * the HKDF, not either party's public key, the port, or the session
 * role, which is unknown-key-share vulnerable and makes a descriptor
 * replay cleanly exploitable. This variant additionally binds
 * client_pub || node_pub || port || role into HKDF's `info` parameter,
 * so a key can only ever be valid for the exact (client, node, port,
 * role) transcript it was derived under. client_pub/node_pub are the
 * client's ephemeral pubkey and the node's own pubkey respectively,
 * always in that fixed role order regardless of which side (client or
 * node) is the caller, so both sides compute byte-identical info strings.
 * port must be the value BOTH sides agree the node is reachable at (the
 * client's ports[i], matching the node's own listening port); role is
 * SESSION_ROLE_A/B. Used by the real client/mix-node/service-gateway/
 * sender session-establishment paths; the Tor-equivalent baseline and
 * benchmark/instrumented harnesses intentionally keep using the plain
 * crypto_ecdh_derive() above, matching this codebase's existing practice
 * of not carrying every hardening change into comparison baselines or
 * simplified measurement harnesses (see e.g. mix_node_instrumented.c's
 * own simplified hint scheme). Returns 0 on success, -1 on failure. */
int crypto_ecdh_derive_bound(const ecdh_keypair_t *local_kp,
                             const uint8_t        *remote_pubkey,
                             const uint8_t         client_pub[EC_PUBKEY_LEN],
                             const uint8_t         node_pub[EC_PUBKEY_LEN],
                             uint16_t              port,
                             uint8_t               role,
                             aes_key_t            *out_key);

/* Release OpenSSL key memory. */
void crypto_ecdh_free(ecdh_keypair_t *kp);

/* Write/read a node's 65-byte public key to/from a binary file.
 * Nodes call save at startup; client calls load before path creation. */
int crypto_pubkey_save(const ecdh_keypair_t *kp, const char *path);
int crypto_pubkey_load(uint8_t out[EC_PUBKEY_LEN], const char *path);

/* Trust-on-first-use pubkey pinning: the first
 * connection to a given port pins the pubkey it presents in
 * "<pin_dir>/pinned_<port>.pub"; every later connection to that same
 * port must present an EXACT match or the call fails. This detects an
 * active on-path adversary substituting its own ECDH key on any
 * connection after the first, there is still no protection for the
 * very first connection (no pre-shared root of trust exists in this
 * prototype's synthetic consensus; a real deployment would need a
 * signed consensus with pre-distributed node keys, a larger follow-up
 * not attempted here). pin_dir is created if missing.
 * Returns 0 if the pubkey matches (or was freshly pinned), -1 on a
 * pin mismatch or I/O failure, callers should treat -1 as a hard
 * connection failure, not fall back to trusting the key anyway. */
int crypto_pubkey_pin_check(uint16_t port, const uint8_t pubkey[EC_PUBKEY_LEN],
                             const char *pin_dir);

/* Node identity signing.
 *
 * crypto_pubkey_pin_check() above pins whatever ECDH pubkey a node
 * presents: but mix nodes generate a FRESH ephemeral ECDH keypair on
 * every process restart, so that pin is only meaningful within a single
 * process lifetime; a restarted node looks exactly like a MITM
 * substituting a new key, which is why pinning was deliberately kept
 * out of the benchmark harness (nodes restart between measurements).
 *
 * This closes that gap with a second, STABLE keypair per node: a
 * long-term identity signing key, generated once and persisted to disk
 * (crypto_identity_load_or_create()), reused across every future
 * restart. On each MODE_EXTEND handshake a node now signs its current
 * (fresh, ephemeral) ECDH pubkey under this stable identity key
 * (crypto_sign()); the connecting client verifies that signature
 * (crypto_verify()) against the identity pubkey it TOFU-pins via
 * crypto_pubkey_pin_check(): but now pinning the STABLE identity key,
 * not the rotating ephemeral one, so the pin survives restarts and the
 * benchmark harness can safely use it too.
 *
 * This is trust-on-first-use applied one layer up the trust chain, not
 * a full PKI: the very first-ever connection to a node still has no
 * pre-distributed root of trust to check against (a real deployment
 * would need directory authorities whose keys ship with the client, the
 * way Tor's do, out of scope for this prototype's synthetic
 * consensus). What it buys over the plain ephemeral-key pinning above:
 * an active MITM substituting its own ephemeral key on any connection
 *, including the very next one after a legitimate node restart, is
 * now detected, because it cannot produce a valid signature under the
 * node's already-pinned, stable identity key. Before this, a restart
 * was indistinguishable from a MITM from the pinning code's point of
 * view. */

/* Deliberately reuses the ecdh_keypair_t generation mechanism (P-256 EC
 * key, sound for both ECDH and ECDSA) but MUST NOT be used
 * interchangeably with an ecdh_keypair_t obtained from
 * crypto_ecdh_keygen(): this key is signed with (crypto_sign) and never
 * fed to crypto_ecdh_derive(), the ephemeral session key is
 * ECDH-derived with and never fed to crypto_sign(), purpose
 * separation between signing and key-agreement keys. */
int crypto_sign_keygen(ecdh_keypair_t *kp);

/* Loads the identity keypair at `path` if it already exists (a prior
 * process's crypto_sign_keygen() output), or generates a fresh one and
 * saves it there if not, unlike crypto_ecdh_keygen(), which is always
 * called fresh, this is the one keypair in this codebase meant to
 * outlive a single process's lifetime. Private key file is written with
 * 0600 permissions. Returns 0 on success, -1 on failure. */
int crypto_identity_load_or_create(ecdh_keypair_t *kp, const char *path);

#define SIGNATURE_MAX_LEN 80  /* DER-encoded ECDSA-P256-SHA256, worst case */

/* Sign msg under identity_kp's private key (ECDSA, SHA-256). Writes a
 * DER-encoded signature to sig (buffer must be >= SIGNATURE_MAX_LEN).
 * Returns the actual signature length, or -1 on failure. */
int crypto_sign(const ecdh_keypair_t *identity_kp,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t *sig, size_t sig_buf_len);

/* Verify a DER-encoded ECDSA-P256-SHA256 signature over msg under a
 * 65-byte uncompressed P-256 public key. Returns 0 if valid, -1
 * otherwise (including malformed input), always treat -1 as reject,
 * never a soft failure. */
int crypto_verify(const uint8_t identity_pubkey[EC_PUBKEY_LEN],
                   const uint8_t *msg, size_t msg_len,
                   const uint8_t *sig, size_t sig_len);

/* AES-256-GCM
 *
 * Wire layout of every encrypted blob:
 *   [ nonce : 12 bytes ] [ ciphertext : plaintext_len bytes ] [ tag : 16 bytes ]
 *
 * GCM_OVERHEAD = 28 bytes added per encryption.
 * A fresh random nonce is generated on every encrypt call.
 * Tags are always 128-bit, never truncated.
 */

/* Encrypt plaintext -> out.
 * out_size must be >= plaintext_len + GCM_OVERHEAD.
 * Returns total bytes written, or -1 on error. */
int crypto_aes_encrypt(const aes_key_t *key,
                       const uint8_t   *plaintext,     size_t plaintext_len,
                       uint8_t         *out,           size_t out_size);

/* Decrypt and authenticate in -> out.
 * Returns plaintext byte count, or -1 on authentication failure.
 * Always treat -1 as fatal, never forward a packet that fails auth. */
int crypto_aes_decrypt(const aes_key_t *key,
                       const uint8_t   *in,            size_t in_len,
                       uint8_t         *out,           size_t out_size);

/* Utilities */

/* Constant-time memory compare. Returns 0 if equal, non-zero otherwise. */
int crypto_memcmp(const void *a, const void *b, size_t n);

#endif /* CRYPTO_H */
