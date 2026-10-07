#include "config.h"
#include "crypto.h"
#include "packet.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <string.h>
#include <stdio.h>

/* AES-CTR XOR */

int packet_aes_ctr_xor(const uint8_t *key, size_t key_len,
                        const uint8_t *in,  size_t len,
                        uint8_t       *out) {
    if (!key || !in || !out || key_len != 32) return -1;
    /* ctr_out below is a fixed WIRE_PACKET_SIZE+16 stack buffer, so
     * reject anything that wouldn't fit before writing to it. */
    if (len > WIRE_PACKET_SIZE) return -1;

    /* Zero nonce, safe because each key is used for exactly one purpose
     * (derived via HKDF with a unique label) and never reused.            */
    uint8_t nonce[16] = {0};
    uint8_t ctr_out[WIRE_PACKET_SIZE + 16];  /* EVP needs some headroom    */
    int     outl = 0, final_outl = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int rc = -1;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, nonce) != 1)
        goto done;
    if (EVP_EncryptUpdate(ctx, ctr_out, &outl, in, (int)len) != 1)
        goto done;
    if (EVP_EncryptFinal_ex(ctx, ctr_out + outl, &final_outl) != 1)
        goto done;

    memcpy(out, ctr_out, len);
    rc = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

/* Same as packet_aes_ctr_xor() but with an explicit 16-byte IV instead of
 * an implicit zero nonce. Used where the same key encrypts more than one
 * message and a fixed nonce would make ciphertext bytes repeat across
 * messages: see packet_sphinx_build()'s per-packet header IV
 * derivation (a fixed zero nonce would make per-session header bytes a
 * stable per-flow fingerprint). */
static int packet_aes_ctr_xor_iv(const uint8_t *key, size_t key_len,
                                  const uint8_t iv[16],
                                  const uint8_t *in, size_t len,
                                  uint8_t *out) {
    if (!key || !iv || !in || !out || key_len != 32) return -1;
    /* Same stack-buffer bound as packet_aes_ctr_xor() above. */
    if (len > WIRE_PACKET_SIZE) return -1;

    uint8_t ctr_out[WIRE_PACKET_SIZE + 16];
    int     outl = 0, final_outl = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int rc = -1;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) != 1)
        goto done;
    if (EVP_EncryptUpdate(ctx, ctr_out, &outl, in, (int)len) != 1)
        goto done;
    if (EVP_EncryptFinal_ex(ctx, ctr_out + outl, &final_outl) != 1)
        goto done;

    memcpy(out, ctr_out, len);
    rc = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

/* Derive a per-packet CTR IV from bytes that are already unique per
 * packet and already on the wire (the encrypted per-hop replay nonce),
 * so no new wire-format bytes are needed. SHA-256 just spreads the
 * input bytes across a full 16-byte IV, not a security boundary by
 * itself, the actual per-packet entropy comes from the caller's fresh
 * RAND_bytes() nonce. Takes an explicit length since the forward path's
 * nonce (NONCE_BYTES=8) and the return path's (RETURN_NONCE_BYTES=4)
 * are different sizes, a fixed
 * NONCE_BYTES read here would over-read a 4-byte return-path buffer.
 * Every OpenSSL call is checked: EVP_MD_CTX_new() can return NULL under
 * allocation failure, and a silently-skipped EVP_DigestInit_ex/Update/
 * Final would leave iv_out holding uninitialized stack bytes, silently
 * breaking the per-packet IV uniqueness this function exists for.
 * Returns -1 and leaves iv_out untouched on any failure, propagated by
 * every caller. */
static int derive_ctr_iv(const uint8_t *nonce, size_t nonce_len,
                          uint8_t iv_out[16]) {
    uint8_t hash[32];
    unsigned int hlen = 32;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) return -1;
    int rc = -1;
    if (EVP_DigestInit_ex(mctx, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(mctx, nonce, nonce_len) == 1 &&
        EVP_DigestFinal_ex(mctx, hash, &hlen) == 1) {
        memcpy(iv_out, hash, 16);
        rc = 0;
    }
    EVP_MD_CTX_free(mctx);
    return rc;
}

static int derive_header_iv(const uint8_t enc_nonce[NONCE_BYTES],
                             uint8_t iv_out[16]) {
    return derive_ctr_iv(enc_nonce, NONCE_BYTES, iv_out);
}

/* HMAC-SHA256 truncated to MAC_BYTES */

int packet_hmac(const uint8_t *key,  size_t key_len,
                const uint8_t *data, size_t data_len,
                uint8_t        out[MAC_BYTES]) {
    if (!key || !data || !out) return -1;

    uint8_t full[32];
    unsigned int full_len = 0;

    if (!HMAC(EVP_sha256(), key, (int)key_len,
              data, data_len, full, &full_len)) return -1;

    memcpy(out, full, MAC_BYTES);
    return 0;
}

/* Derive the SG-side O(1) session hint */

int packet_derive_sg_hint(const aes_key_t *master, sg_hint_t *out) {
    if (!master || !out) return -1;
    /* SG_HINT_BYTES == MAC_BYTES (config.h), packet_hmac's native output
     * width is used directly, no truncation/padding needed. A distinct
     * label from LABEL_HEADER_ENC/MAC/BLIND_KEY keeps this independent of
     * those (labelled-PRF separation, same principle as
     * packet_derive_hop_keys) even though it shares the same input
     * secret. */
    return packet_hmac(master->key, AES_KEY_LEN,
                       (const uint8_t *)LABEL_SG_HINT, strlen(LABEL_SG_HINT),
                       out->bytes);
}

/* Forward-path rotating hint derivation */

int packet_derive_hint_seed(const aes_key_t *master, aes_key_t *out) {
    if (!master || !out) return -1;
    /* Full 32-byte HMAC-SHA256 output, not packet_hmac's truncated 16,
     * AES_KEY_LEN(32) matches the native width exactly. */
    unsigned int full_len = 0;
    if (!HMAC(EVP_sha256(), master->key, AES_KEY_LEN,
              (const uint8_t *)LABEL_HINT_SEED, strlen(LABEL_HINT_SEED),
              out->key, &full_len)) return -1;
    return (full_len == AES_KEY_LEN) ? 0 : -1;
}

int packet_derive_hop_hint(const aes_key_t *hint_seed, uint64_t pkt_counter,
                            uint8_t out[HINT_BYTES]) {
    if (!hint_seed || !out) return -1;
    uint8_t counter_be[8];
    for (int i = 0; i < 8; i++)
        counter_be[i] = (uint8_t)(pkt_counter >> (8 * (7 - i)));
    /* HINT_BYTES(32) == native HMAC-SHA256 width, so the full output is
     * the hint directly, no truncation, matching packet_derive_hint_seed
     * above. */
    unsigned int full_len = 0;
    if (!HMAC(EVP_sha256(), hint_seed->key, AES_KEY_LEN,
              counter_be, sizeof(counter_be), out, &full_len)) return -1;
    return (full_len == HINT_BYTES) ? 0 : -1;
}

/* Two-key binding tag
 *
 * Proves the client established BOTH K_R-SG-A and K_R-SG-B with the SG in
 * the same setup, binding the two independently-negotiated paths into one
 * session. A plain XOR combiner (HMAC(K_R-SG-A XOR K_R-SG-B, "binding"))
 * would be linear and algebraically invertible (knowing one key and the
 * combined value trivially yields the other). Uses a proper two-secret
 * combiner instead: nest one key as an HMAC key over the other, then
 * label-derive the tag from that, matching the labelled-PRF pattern
 * already used everywhere else in this file. `a_key` and `b_key`
 * must be passed in the SAME order by every caller (K_R-SG-A first, then
 * K_R-SG-B, the protocol always knows which is which via
 * SESSION_ROLE_A/B, so an explicit convention costs nothing, unlike
 * XOR's "either order" property, which was convenient but not load-
 * bearing: no caller here ever had ambiguity about which key was which).
 * Returns 0 on success, -1 on error. */
int packet_derive_binding_tag(const aes_key_t *a_key, const aes_key_t *b_key,
                               uint8_t out[MAC_BYTES]) {
    if (!a_key || !b_key || !out) return -1;
    aes_key_t combined = {0};
    unsigned int full_len = 0;
    if (!HMAC(EVP_sha256(), a_key->key, AES_KEY_LEN,
              b_key->key, AES_KEY_LEN, combined.key, &full_len)) return -1;
    if (full_len != AES_KEY_LEN) return -1;
    int rc = packet_hmac(combined.key, AES_KEY_LEN,
                         (const uint8_t *)LABEL_BINDING, strlen(LABEL_BINDING),
                         out);
    explicit_bzero(&combined, sizeof(combined));
    return rc;
}

/* Derive sub-keys from a per-hop ECDHE master
 *
 * Every principal (client, sender, mix node) derives three keys per hop
 * from the shared ECDHE secret:
 *   header_enc_key:  for AES-CTR encrypting addr+bkey in the header
 *   header_mac_key:  for HMAC over the header block
 *   blind_key:       for AES-CTR blinding the payload
 *
 * Each is derived via a labelled PRF with a unique label string so no two
 * purposes share a key even though they share the same master shared
 * secret: unlike a naive byte-rotation (the original bug: an earlier
 * version of this codebase set header_enc_key=master and rotated it for
 * the other two, so any one of the three keys trivially yields the other
 * two). Call this identically from every principal on the same shared
 * ECDHE master, see packet.h's declaration for the cross-file contract.
 */

int packet_derive_hop_keys(const aes_key_t *master,
                           aes_key_t       *henc,
                           aes_key_t       *hmac_key,
                           aes_key_t       *bkey) {
    /* Uses HKDF-Expand (empty salt is standard for the "derive multiple
     * subkeys from one high-entropy master" use case, master is
     * already the output of a proper HKDF-SHA256 extract over the ECDH
     * shared secret, so this call is Expand-only, matching RFC 5869's
     * own two-call composition), using each label string as the `info`
     * parameter so the three outputs are domain-separated: three
     * 32-byte AES-256 keys derived from one 32-byte master key. */
    struct { const char *label; aes_key_t *out; } derivations[] = {
        { LABEL_HEADER_ENC, henc      },
        { LABEL_HEADER_MAC, hmac_key  },
        { LABEL_BLIND_KEY,  bkey      },
    };

    for (int i = 0; i < 3; i++) {
        EVP_KDF     *kdf  = EVP_KDF_fetch(NULL, "HKDF", NULL);
        EVP_KDF_CTX *kctx = kdf ? EVP_KDF_CTX_new(kdf) : NULL;
        if (!kctx) { EVP_KDF_free(kdf); return -1; }

        static const uint8_t empty_salt[1] = {0};
        OSSL_PARAM params[] = {
            OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0),
            OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, (void *)master->key,
                                    AES_KEY_LEN),
            OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, (void *)empty_salt, 0),
            OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO,
                                    (void *)derivations[i].label,
                                    strlen(derivations[i].label)),
            OSSL_PARAM_int(OSSL_KDF_PARAM_MODE, &(int){EVP_KDF_HKDF_MODE_EXPAND_ONLY}),
            OSSL_PARAM_END
        };
        int rc = EVP_KDF_derive(kctx, derivations[i].out->key, AES_KEY_LEN,
                                params);
        EVP_KDF_CTX_free(kctx);
        EVP_KDF_free(kdf);
        if (rc <= 0) return -1;
    }
    return 0;
}

/* packet_sphinx_build
 *
 * packet_sphinx_build_ex() is the real implementation; the public
 * packet_sphinx_build() below is a thin wrapper that always passes
 * drop_at_hop = -1 (no hop terminates the packet early, every hop's
 * enc_flags byte is HOP_FLAG_FORWARD, identical to every build before
 * ASN_HOP_DECOY existed). Kept as a separate internal function rather than
 * changing packet_sphinx_build()'s signature so every existing caller
 * (client.c/sender.c's real-traffic and SG-reaching-cover call sites)
 * needs no changes and keeps its exact prior behavior. */

static int packet_sphinx_build_ex(const sphinx_path_t *path,
                        const uint8_t       *payload,
                        uint16_t             payload_len,
                        uint8_t              flags,
                        uint64_t             pkt_counter,
                        int                  drop_at_hop,
                        wire_packet_t       *out) {
    if (!path || !payload || !out) return -1;
    if (drop_at_hop < -1 || drop_at_hop >= N_PATH_HOPS) return -1;
    if (payload_len > MAX_INNER_PAYLOAD) {
        fprintf(stderr, "[packet] payload too large: %u > %d\n",
                payload_len, MAX_INNER_PAYLOAD);
        return -1;
    }

    memset(out->data, 0, WIRE_PACKET_SIZE);

 /* Step 1: Build inner payload buffer (padded to PAYLOAD_SECTION_SIZE)
     * Layout: [flags(1)][payload_len(2)][payload][padding]               */
    /* Inner layout: [flags(1)][payload_len(2)][payload][padding]
     * Total inner_len = INNER_HDR_BYTES + payload_len                    */
    uint8_t inner[INNER_HDR_BYTES + MAX_INNER_PAYLOAD];
    memset(inner, 0, sizeof(inner));
    inner[0] = flags;
    inner[1] = (uint8_t)(payload_len >> 8);
    inner[2] = (uint8_t)(payload_len & 0xFF);
    memcpy(inner + INNER_HDR_BYTES, payload, payload_len);
    size_t inner_len = INNER_HDR_BYTES + payload_len;

 /* Step 2: Encrypt payload end-to-end under e2e_key (AES-256-GCM) *
     * Layout: [enc_len(2)][GCM ciphertext][zero padding]. The explicit
     * length prefix avoids guessing where the ciphertext ends from a
     * trailing-zero scan, which would corrupt ~1/256 packets whenever
     * the real tag's own last byte(s) happened to be 0x00. No wire
     * growth needed: these 2 bytes come out of what was already-zero
     * padding (max ciphertext 494 bytes vs. 739 available). Blinding
     * (Step 3, below) XORs this whole buffer position-independently, so
     * a 2-byte prefix survives the blind/unblind chain unchanged in
     * position, just like the rest of the buffer. */
    uint8_t e2e_ct[PAYLOAD_SECTION_SIZE];
    memset(e2e_ct, 0, sizeof(e2e_ct));

    int enc_len = crypto_aes_encrypt(&path->e2e.e2e_key,
                                     inner, inner_len,
                                     e2e_ct + 2, sizeof(e2e_ct) - 2);
    if (enc_len < 0) {
        fprintf(stderr, "[packet] e2e encrypt failed\n"); return -1;
    }
    e2e_ct[0] = (uint8_t)(((uint16_t)enc_len) >> 8);
    e2e_ct[1] = (uint8_t)(((uint16_t)enc_len) & 0xFF);
    /* Remaining bytes in e2e_ct are already zero-padded                   */

    /* Write the SG-side O(1) session hint into the
     * last SG_HINT_BYTES of the buffer, always clear of the ciphertext
     * above (max enc_len leaves the ciphertext ending well before this
     * point, see config.h's SG_HINT_BYTES comment for the exact byte
     * accounting), so find_a_session() can read it straight off the
     * wire before attempting any GCM trial-decrypt. Written here, before
     * Step 3's blinding pass below, so it goes through the identical
     * 3-hop blind/unblind XOR treatment as the ciphertext next to it and
     * stays opaque to every mix hop, emerging in the clear only once MN3
     * forwards the fully-unblinded packet to the SG. */
    memcpy(e2e_ct + PAYLOAD_SECTION_SIZE - SG_HINT_BYTES,
          path->sg_hint.bytes, SG_HINT_BYTES);

 /* Step 2b: Precompute each hop's per-packet nonce/IV up front.
     * `blind_key` is session-constant, so Step 3 below derives a
     * per-packet CTR IV from a fresh nonce rather than XOR-ing with a
     * fixed zero nonce, otherwise any session-constant region of the
     * payload (the zero padding beyond the GCM ciphertext, plus the
     * sg_hint tail) would appear as a ~697-byte constant pattern on the
     * wire across every packet of a session, a passive per-flow
     * fingerprint requiring no compromise, contradicting this file's own
     * "bitwise different on every link" claim (packet.h's blind_key
     * comment). The nonce/IV are generated here, before Step 3, so Step
     * 3's payload blinding and Step 4's
     * header block for the SAME hop share the same per-packet IV,
     * doesn't matter cryptographically (different keys), and needs no new
     * wire-format bytes (the nonce still only travels once, in the header,
     * exactly as it already did). */
    uint8_t hop_enc_nonce[N_PATH_HOPS][NONCE_BYTES];
    uint8_t hop_iv[N_PATH_HOPS][16];
    for (int hop = 0; hop < N_PATH_HOPS; hop++) {
        uint8_t nonce_plain[NONCE_BYTES];
        if (RAND_bytes(nonce_plain, NONCE_BYTES) != 1) {
            fprintf(stderr, "[packet] nonce generation failed\n"); return -1;
        }
        if (packet_aes_ctr_xor(path->hops[hop].header_enc_key.key, AES_KEY_LEN,
                                nonce_plain, NONCE_BYTES, hop_enc_nonce[hop]) != 0) {
            fprintf(stderr, "[packet] nonce encrypt failed\n"); return -1;
        }
        if (derive_header_iv(hop_enc_nonce[hop], hop_iv[hop]) != 0) {
            fprintf(stderr, "[packet] header IV derivation failed\n"); return -1;
        }
    }

 /* Step 3: Apply blinding in REVERSE hop order (MN3, MN2, MN1)
     * When the packet travels MN1->MN2->MN3, each node XORs its keystream,
     * progressively cancelling the pre-applied blinding.
     * After MN3 processes it, e2e_ct is recovered at the SG.             */
    uint8_t blinded[PAYLOAD_SECTION_SIZE];
    memcpy(blinded, e2e_ct, PAYLOAD_SECTION_SIZE);

    for (int hop = N_PATH_HOPS - 1; hop >= 0; hop--) {
        uint8_t tmp[PAYLOAD_SECTION_SIZE];
        if (packet_aes_ctr_xor_iv(path->hops[hop].blind_key.key, AES_KEY_LEN,
                                   hop_iv[hop],
                                   blinded, PAYLOAD_SECTION_SIZE, tmp) != 0) {
            fprintf(stderr, "[packet] blinding failed at hop %d\n", hop);
            return -1;
        }
        memcpy(blinded, tmp, PAYLOAD_SECTION_SIZE);
    }

 /* Step 4: Build header blocks for each hop
     * Each block: [enc_addr(6)][enc_bkey(32)][mac(16)][hint(32)]
     * enc_addr and enc_bkey are AES-CTR encrypted under header_enc_key.
     * mac covers enc_addr||enc_bkey.                                      */
    uint8_t header[HEADER_SIZE];
    memset(header, 0, sizeof(header));

    for (int hop = 0; hop < N_PATH_HOPS; hop++) {
        uint8_t *block = header + hop * HEADER_BLOCK_SIZE;

        /* header_enc_key/header_mac_key/blind_key were already derived
         * independently (packet_derive_hop_keys) when this hop's session
         * was set up, see client.c::derive_hop() / sender.c::derive_hop()
         * / mix_node.c::split_master_keys(). No re-derivation here. */

        /* Build plaintext for enc_addr (6 bytes):
         * For prototype: store next-hop port as uint16 LE, zero-pad to 6 */
        uint8_t addr_plain[ADDR_BYTES] = {0};
        /* For localhost: IP = 127.0.0.1 = 0x7F000001                     */
        addr_plain[0] = 127; addr_plain[1] = 0;
        addr_plain[2] = 0;   addr_plain[3] = 1;
        /* Port of next hop:
         *   hop 0 (MN1) -> next is MN2 = PORT_MIX_2
         *   hop 1 (MN2) -> next is MN3 = PORT_MIX_3
         *   hop 2 (MN3) -> next is SG  = PORT_SERVICE_GW               */
        /* Use path-specific next hop ports */
        uint16_t next_port;
        if (hop < N_PATH_HOPS - 1)
            next_port = path->hop_ports[hop + 1];
        else
            next_port = path->sg_port ? path->sg_port : PORT_SERVICE_GW;
        addr_plain[4] = (uint8_t)(next_port >> 8);
        addr_plain[5] = (uint8_t)(next_port & 0xFF);

        uint8_t bkey_plain[BLIND_KEY_BYTES];
        memcpy(bkey_plain, path->hops[hop].blind_key.key, BLIND_KEY_BYTES);

        /* Per-packet nonce/IV for this hop (real or cover) for replay
         * detection: see header_block_t's comment in packet.h. Already
         * generated in Step 2b above, together with Step 3's payload
         * blinding IV for this same hop: a fixed zero CTR nonce against
         * session-constant plaintext would make both the header fields
         * and the payload padding repeat identically across a session's
         * packets, a stable per-flow fingerprint for a passive link
         * observer. */
        const uint8_t *enc_nonce = hop_enc_nonce[hop];
        const uint8_t *iv = hop_iv[hop];

        uint8_t rest_plain[ADDR_BYTES + BLIND_KEY_BYTES + FLAG_BYTES];
        uint8_t rest_enc[ADDR_BYTES + BLIND_KEY_BYTES + FLAG_BYTES];
        memcpy(rest_plain,              addr_plain, ADDR_BYTES);
        memcpy(rest_plain + ADDR_BYTES, bkey_plain, BLIND_KEY_BYTES);
        /* This byte is always 0 for every hop, real or cover,
         * packet_sphinx_build() takes no is_cover parameter, so there's
         * no value to write here that would distinguish cover from real
         * to a mix node decrypting this block. Field kept at its
         * existing size/position and still MAC'd like the rest of the
         * block, just permanently zero. The signal that actually gates
         * cover delivery is the end-to-end PKT_DUMMY flag inside the
         * e2e-GCM payload (see the `flags` param above and
         * packet_sphinx_unwrap()), encrypted under e2e_key, which no mix
         * node holds. */
        /* ASN_HOP_DECOY extends this same byte: still only ever non-zero
         * for a decoy at its own caller-chosen termination hop. Every
         * real packet and every other hop of a decoy still gets 0 here.
         * See config.h's HOP_DROP_MARKER comment. */
        rest_plain[ADDR_BYTES + BLIND_KEY_BYTES] =
            (hop == drop_at_hop) ? HOP_DROP_MARKER : HOP_FLAG_FORWARD;

        if (packet_aes_ctr_xor_iv(path->hops[hop].header_enc_key.key, AES_KEY_LEN,
                                  iv, rest_plain, sizeof(rest_plain), rest_enc) != 0) {
            fprintf(stderr, "[packet] combined encrypt failed\n"); return -1;
        }

        memcpy(block,                             rest_enc, ADDR_BYTES);
        memcpy(block + ADDR_BYTES,                rest_enc + ADDR_BYTES, BLIND_KEY_BYTES);
        memcpy(block + ADDR_BYTES + BLIND_KEY_BYTES, rest_enc + ADDR_BYTES + BLIND_KEY_BYTES, FLAG_BYTES);
        memcpy(block + ADDR_BYTES + BLIND_KEY_BYTES + FLAG_BYTES,
               enc_nonce, NONCE_BYTES);

        /* MAC over enc_addr || enc_bkey || enc_flags || enc_nonce */
        if (packet_hmac(path->hops[hop].header_mac_key.key, AES_KEY_LEN,
                        block, ADDR_BYTES + BLIND_KEY_BYTES + FLAG_BYTES + NONCE_BYTES,
                        block + ADDR_BYTES + BLIND_KEY_BYTES + FLAG_BYTES + NONCE_BYTES) != 0) {
            fprintf(stderr, "[packet] MAC failed\n"); return -1;
        }

        /* Hint: derived fresh from this hop's hint_seed + pkt_counter,
         * see config.h's HINT_WINDOW comment for why this is safe for
         * the mix node to still find in O(1)-ish time despite changing
         * every packet. */
        if (packet_derive_hop_hint(&path->hops[hop].hint_seed, pkt_counter,
                                   block + ADDR_BYTES + BLIND_KEY_BYTES + FLAG_BYTES + NONCE_BYTES + MAC_BYTES) != 0) {
            fprintf(stderr, "[packet] hint derivation failed\n"); return -1;
        }
    }

 /* Step 5: Assemble wire packet [header][blinded_payload] */
    memcpy(out->data,               header,  HEADER_SIZE);
    memcpy(out->data + HEADER_SIZE, blinded, PAYLOAD_SECTION_SIZE);

    return 0;
}

int packet_sphinx_build(const sphinx_path_t *path,
                        const uint8_t       *payload,
                        uint16_t             payload_len,
                        uint8_t              flags,
                        uint64_t             pkt_counter,
                        wire_packet_t       *out) {
    return packet_sphinx_build_ex(path, payload, payload_len, flags,
                                   pkt_counter, -1, out);
}

int packet_sphinx_decoy_hop(const sphinx_path_t *path, uint64_t pkt_counter,
                             int drop_at_hop, wire_packet_t *out) {
    if (drop_at_hop < 0 || drop_at_hop >= N_PATH_HOPS) return -1;

    /* Random payload, same as packet_sphinx_dummy(), size alone gives
     * nothing away either way, and this decoy never reaches the SG (it
     * terminates at drop_at_hop), so there is no return-header-in-payload
     * trick to apply here unlike build_outbound_cover_with_spare_return()
     * in client.c. */
    uint8_t rand_payload[MAX_INNER_PAYLOAD];
    if (RAND_bytes(rand_payload, MAX_INNER_PAYLOAD) != 1) return -1;

    return packet_sphinx_build_ex(path, rand_payload, MAX_INNER_PAYLOAD,
                                   PKT_DUMMY | PKT_DEST_SERVICE,
                                   pkt_counter, drop_at_hop, out);
}

/* packet_sphinx_peel */

int packet_sphinx_peel(const wire_packet_t *pkt,
                       const aes_key_t     *header_enc_key,
                       const aes_key_t     *header_mac_key,
                       const uint8_t        hint[HINT_BYTES],
                       hop_info_t          *out_hop,
                       wire_packet_t       *out_pkt) {
    if (!pkt || !header_enc_key || !header_mac_key || !out_hop || !out_pkt)
        return -1;

    /* Outermost header block is at bytes 0..HEADER_BLOCK_SIZE-1           */
    const uint8_t *block = pkt->data;

    /* Verify MAC */
    uint8_t computed_mac[MAC_BYTES];
    if (packet_hmac(header_mac_key->key, AES_KEY_LEN,
                    block, ADDR_BYTES + BLIND_KEY_BYTES + FLAG_BYTES + NONCE_BYTES,
                    computed_mac) != 0) return -1;

    if (crypto_memcmp(computed_mac,
                      block + ADDR_BYTES + BLIND_KEY_BYTES + FLAG_BYTES + NONCE_BYTES,
                      MAC_BYTES) != 0) {
        fprintf(stderr, "[packet] peel: MAC verification failed, drop\n");
        return -1;
    }

 /* Decrypt enc_addr || enc_bkey || enc_flags, then enc_nonce
     * Mirrors packet_sphinx_build()'s two-pass scheme:
     * the nonce ciphertext is read directly off the wire (no decryption
     * needed to know its bytes) and used to derive the IV for the rest of
     * the block, exactly as the sender derived it when encrypting. */
    uint8_t enc_nonce[NONCE_BYTES];
    memcpy(enc_nonce, block + ADDR_BYTES + BLIND_KEY_BYTES + FLAG_BYTES, NONCE_BYTES);

    uint8_t nonce_plain[NONCE_BYTES];
    if (packet_aes_ctr_xor(header_enc_key->key, AES_KEY_LEN,
                            enc_nonce, NONCE_BYTES, nonce_plain) != 0) return -1;

    uint8_t iv[16];
    if (derive_header_iv(enc_nonce, iv) != 0) return -1;

    uint8_t rest_enc[ADDR_BYTES + BLIND_KEY_BYTES + FLAG_BYTES];
    uint8_t rest_plain[ADDR_BYTES + BLIND_KEY_BYTES + FLAG_BYTES];
    memcpy(rest_enc, block, sizeof(rest_enc));

    if (packet_aes_ctr_xor_iv(header_enc_key->key, AES_KEY_LEN, iv,
                              rest_enc, sizeof(rest_enc), rest_plain) != 0) return -1;

    memcpy(out_hop->next_ip, rest_plain, 4);
    out_hop->next_port = (uint16_t)((rest_plain[4] << 8) |
                                     rest_plain[5]);
    memcpy(out_hop->blind_key, rest_plain + ADDR_BYTES, BLIND_KEY_BYTES);
    /* rest_plain[ADDR_BYTES+BLIND_KEY_BYTES]: ASN_HOP_DECOY's
     * position-randomized termination signal in this wire slot (see
     * config.h's HOP_DROP_MARKER comment), always HOP_FLAG_FORWARD
     * except at a decoy's own chosen termination hop, for every caller,
     * whether or not that caller was built with ASN_HOP_DECOY. Exposing
     * it here unconditionally (rather than behind an ifdef in this file)
     * keeps packet.c a plain wire/crypto layer; whether anything acts on
     * out_hop->hop_flag is entirely mix_node.c's decision. */
    out_hop->hop_flag = rest_plain[ADDR_BYTES + BLIND_KEY_BYTES];
    memcpy(out_hop->nonce, nonce_plain, NONCE_BYTES);

    /* Apply blinding to payload (XOR with this hop's keystream), using the
     * SAME per-packet IV (derived above from this hop's own enc_nonce) the
     * sender used to apply it, a fixed zero-nonce keystream here would
     * make session-constant payload regions repeat identically across
     * every packet, a passive per-flow fingerprint at every link. See
     * packet_sphinx_build_ex()'s Step 2b/3 for the sender-side half. */
    const uint8_t *payload_in = pkt->data + HEADER_SIZE;
    uint8_t        payload_out[PAYLOAD_SECTION_SIZE];

    if (packet_aes_ctr_xor_iv(out_hop->blind_key, BLIND_KEY_BYTES, iv,
                              payload_in, PAYLOAD_SECTION_SIZE,
                              payload_out) != 0) return -1;

 /* Build output packet: shift header left by one block, copy payload */
    /*
     * Layout of the OUTPUT wire packet (for the next hop), must match the
     * layout packet_sphinx_build() produces and packet_sphinx_unwrap() (and
     * this very function, on the next hop) expects to read:
     *
     *   [0 .. HEADER_SIZE-1]      : header region, fixed size every hop.
     *                                Remaining header blocks (hops i+1..N-1)
     *                                are shifted to the front; the freed
     *                                block(s) at the tail of this region are
     *                                random-padded, not zero-padded (see
     *                                below). Nothing ever reads this
     *                                freed tail as header data, every hop
     *                                only reads its own block at offset 0,
     *                                so the padding's content is inert
     *                                to this code; the random-vs-zero
     *                                choice below is about what an
     *                                outside observer sees on the wire.
     *   [HEADER_SIZE .. 1023]     : blinded payload (PAYLOAD_SECTION_SIZE
     *                                bytes, currently 739), ALWAYS at
     *                                the fixed HEADER_SIZE offset. A
     *                                previous version shifted this earlier
     *                                each hop (to "use" the freed header
     *                                slot), which desynced it from
     *                                packet_sphinx_build()'s and
     *                                packet_sphinx_peel()'s own payload_in
     *                                read above (both fixed at HEADER_SIZE),
     *                                silently corrupting the payload for
     *                                every hop after the first.
     *
     * The freed tail block(s) are filled with random bytes, not zero: a
     * literal run of zero bytes at the tail is
     * plaintext on the wire (this region is not part of any encrypted
     * layer), and its LENGTH grows by one block per hop (0 at the
     * client, one block after MN1's peel, two after MN2's), a passive
     * observer positioned at multiple points along the path could read
     * a packet's hop position directly off the wire without decrypting
     * anything. Random filler is indistinguishable from ciphertext and
     * carries no such signal; nothing ever reads this region as data
     * either way (see above), so its contents genuinely do not matter
     * except for what they look like to an outside observer.
     */
    if (RAND_bytes(out_pkt->data, WIRE_PACKET_SIZE) != 1) {
        fprintf(stderr, "[packet] peel: random padding failed\n"); return -1;
    }

    size_t remaining_header = HEADER_SIZE - HEADER_BLOCK_SIZE; /* currently 190 bytes */
    if (remaining_header > 0)
        memcpy(out_pkt->data,
               pkt->data + HEADER_BLOCK_SIZE,
               remaining_header);

    /* Payload stays at the fixed HEADER_SIZE offset every hop. */
    memcpy(out_pkt->data + HEADER_SIZE, payload_out, PAYLOAD_SECTION_SIZE);

    (void)hint; /* hint used externally for key lookup before calling peel  */
    return 0;
}

/* packet_sphinx_unwrap */

int packet_sphinx_unwrap(const wire_packet_t *pkt,
                         const aes_key_t     *e2e_key,
                         uint8_t             *payload_out,
                         uint16_t            *payload_len,
                         uint8_t             *flags) {
    if (!pkt || !e2e_key || !payload_out || !payload_len || !flags) return -1;

    /* At the SG, all blinding operations have been cancelled.
     * The payload section holds [enc_len(2)][GCM ciphertext][padding]. */
    const uint8_t *sect = pkt->data + HEADER_SIZE;

    /* Explicit length prefix avoids a trailing-zero scan, which would
     * mis-trim (and corrupt decryption of) ~1/256 packets whenever the
     * real GCM tag's own last byte(s) were 0x00. No scanning, no
     * guessing: read the length build() wrote. */
    uint16_t enc_len = (uint16_t)((sect[0] << 8) | sect[1]);
    if (enc_len < GCM_OVERHEAD + INNER_HDR_BYTES ||
        (size_t)enc_len > PAYLOAD_SECTION_SIZE - 2) {
        fprintf(stderr, "[packet] unwrap: implausible enc_len %u\n", enc_len);
        return -1;
    }
    const uint8_t *ct = sect + 2;

    uint8_t plain[PAYLOAD_SECTION_SIZE];
    int n = crypto_aes_decrypt(e2e_key, ct, enc_len, plain, sizeof(plain));
    if (n < 0) {
        fprintf(stderr, "[packet] unwrap: GCM decryption failed\n");
        return -1;
    }

    if (n < INNER_HDR_BYTES) {
        fprintf(stderr, "[packet] unwrap: decrypted payload too short\n");
        return -1;
    }

    *flags       = plain[0];
    *payload_len = (uint16_t)((plain[1] << 8) | plain[2]);

    if (*payload_len > (uint16_t)(n - INNER_HDR_BYTES)) {
        fprintf(stderr, "[packet] unwrap: payload_len %u > available %d\n",
                *payload_len, n - INNER_HDR_BYTES);
        return -1;
    }

    /* payload_out is the caller's MAX_INNER_PAYLOAD-sized buffer, not
     * PAYLOAD_SECTION_SIZE: a modified client can claim a payload_len up
     * to ~708 (n - INNER_HDR_BYTES) even though the buffer only holds 463. */
    if (*payload_len > MAX_INNER_PAYLOAD) {
        fprintf(stderr, "[packet] unwrap: payload_len %u exceeds MAX_INNER_PAYLOAD %d\n",
                *payload_len, MAX_INNER_PAYLOAD);
        return -1;
    }

    memcpy(payload_out, plain + INNER_HDR_BYTES, *payload_len);
    return 0;
}

/* packet_sphinx_dummy */

int packet_sphinx_dummy(const sphinx_path_t *path, uint64_t pkt_counter,
                        wire_packet_t *out) {
    if (!path || !out) return -1;

    /* Random payload, max size so even payload_len gives nothing away     */
    uint8_t rand_payload[MAX_INNER_PAYLOAD];
    if (RAND_bytes(rand_payload, MAX_INNER_PAYLOAD) != 1) return -1;

    return packet_sphinx_build(path, rand_payload, MAX_INNER_PAYLOAD,
                               PKT_DUMMY | PKT_DEST_SERVICE,
                               pkt_counter, out);
}

/* ================================================================
 * Return header: build and peel
 * ================================================================ */

int packet_build_return_header(
    const aes_key_t  hop_enc_keys[N_PATH_HOPS],
    const aes_key_t  hop_mac_keys[N_PATH_HOPS],
    const uint8_t    hop_hints[N_PATH_HOPS][HINT_BYTES],
    const uint8_t    addrs[N_PATH_HOPS][ADDR_BYTES],
    return_header_t *out) {

    if (!hop_enc_keys || !hop_mac_keys || !hop_hints || !addrs || !out)
        return -1;

    memset(out, 0, sizeof(*out));

    /* Build blocks in order: [0]=MNc, [1]=MNb, [2]=MNa
     * addrs[0] = MNb addr (MNc learns this)
     * addrs[1] = MNa addr (MNb learns this)
     * addrs[2] = Client addr (MNa learns this)             */
    for (int i = 0; i < N_PATH_HOPS; i++) {
        return_block_t *blk = &out->blocks[i];

        /* Fresh per-packet nonce for replay detection at this hop, see
         * return_block_t's comment in packet.h. `addrs[i]` is session-
         * static (same routing target every call, see client.c's
         * build_return_header_into() comment), so, the same fixed-
         * zero-nonce root cause as the forward-path payload issue above
         * (that fix only scoped the forward-path payload, but the
         * identical root cause applies here): encrypting addr and nonce
         * TOGETHER in one fixed-zero-nonce CTR call left `enc_addr`
         * session-constant across every call regardless of the nonce
         * portion varying, because CTR keystream bytes depend only on
         * (key, nonce, byte position), not on the plaintext at that
         * position. Split into two passes, mirroring
         * packet_sphinx_build_ex()'s header fix exactly: encrypt the fresh
         * nonce first under the fixed zero IV (safe, its own plaintext
         * is fresh every call), then derive a per-packet IV from that
         * ciphertext and use it to encrypt the session-static addr. No
         * wire-format change: enc_addr/enc_nonce are already separate
         * fields. */
        uint8_t nonce_plain[RETURN_NONCE_BYTES];
        if (RAND_bytes(nonce_plain, RETURN_NONCE_BYTES) != 1) {
            fprintf(stderr, "[packet] return nonce generation failed\n"); return -1;
        }

        uint8_t enc_nonce[RETURN_NONCE_BYTES];
        if (packet_aes_ctr_xor(hop_enc_keys[i].key, AES_KEY_LEN,
                                nonce_plain, RETURN_NONCE_BYTES,
                                enc_nonce) != 0) return -1;

        uint8_t iv[16];
        if (derive_ctr_iv(enc_nonce, RETURN_NONCE_BYTES, iv) != 0) return -1;

        uint8_t enc_addr[ADDR_BYTES];
        if (packet_aes_ctr_xor_iv(hop_enc_keys[i].key, AES_KEY_LEN, iv,
                                   addrs[i], ADDR_BYTES, enc_addr) != 0) return -1;

        memcpy(blk->enc_addr,  enc_addr,  ADDR_BYTES);
        memcpy(blk->enc_nonce, enc_nonce, RETURN_NONCE_BYTES);

        /* MAC over enc_addr || enc_nonce */
        if (packet_hmac(hop_mac_keys[i].key, AES_KEY_LEN,
                        blk->enc_addr, ADDR_BYTES + RETURN_NONCE_BYTES,
                        blk->mac) != 0) return -1;

        /* Hint */
        memcpy(blk->hint, hop_hints[i], HINT_BYTES);
    }
    return 0;
}

int packet_peel_return_header(
    const return_header_t *rhdr,
    const aes_key_t       *header_enc_key,
    const aes_key_t       *header_mac_key,
    return_next_t         *out_next,
    return_header_t       *out_rhdr) {

    if (!rhdr || !header_enc_key || !header_mac_key || !out_next || !out_rhdr)
        return -1;

    const return_block_t *blk = &rhdr->blocks[0];

    /* Verify MAC (covers enc_addr || enc_nonce) */
    uint8_t computed_mac[MAC_BYTES];
    if (packet_hmac(header_mac_key->key, AES_KEY_LEN,
                    blk->enc_addr, ADDR_BYTES + RETURN_NONCE_BYTES,
                    computed_mac) != 0) return -1;

    if (crypto_memcmp(computed_mac, blk->mac, MAC_BYTES) != 0) {
        fprintf(stderr, "[packet] return header: MAC failed\n");
        return -1;
    }

    /* Decrypt nonce, then addr, mirrors packet_build_return_header()'s
     * two-pass H-1 fix exactly: enc_nonce is read straight off the wire
     * (no decryption needed to know its bytes) and used to derive the
     * per-packet IV the sender used for addr, instead of decrypting both
     * together under the fixed zero nonce (which left enc_addr
     * session-constant). */
    uint8_t enc_nonce[RETURN_NONCE_BYTES];
    memcpy(enc_nonce, blk->enc_nonce, RETURN_NONCE_BYTES);

    uint8_t nonce_plain[RETURN_NONCE_BYTES];
    if (packet_aes_ctr_xor(header_enc_key->key, AES_KEY_LEN,
                            enc_nonce, RETURN_NONCE_BYTES, nonce_plain) != 0) return -1;

    uint8_t iv[16];
    if (derive_ctr_iv(enc_nonce, RETURN_NONCE_BYTES, iv) != 0) return -1;

    uint8_t addr_plain[ADDR_BYTES];
    if (packet_aes_ctr_xor_iv(header_enc_key->key, AES_KEY_LEN, iv,
                              blk->enc_addr, ADDR_BYTES, addr_plain) != 0) return -1;

    memcpy(out_next->next_ip, addr_plain, 4);
    out_next->next_port = (uint16_t)((addr_plain[4] << 8) | addr_plain[5]);
    memcpy(out_next->nonce, nonce_plain, RETURN_NONCE_BYTES);

    /* Shift remaining blocks left. The freed tail block is filled with
     * random bytes, not zero, same rationale as packet_sphinx_peel():
     * this struct is copied directly onto the wire by the caller, so a
     * literal zero tail would leak hop position to a passive
     * multi-point observer. */
    if (RAND_bytes((uint8_t *)out_rhdr, sizeof(*out_rhdr)) != 1) {
        fprintf(stderr, "[packet] return header: random padding failed\n");
        return -1;
    }
    for (int i = 1; i < N_PATH_HOPS; i++)
        out_rhdr->blocks[i-1] = rhdr->blocks[i];

    return 0;
}
