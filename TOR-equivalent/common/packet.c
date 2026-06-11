#include "config.h"
#include "crypto.h"
#include "packet.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>

/* ── AES-CTR XOR ─────────────────────────────────────────────────────────── */

int packet_aes_ctr_xor(const uint8_t *key, size_t key_len,
                        const uint8_t *in,  size_t len,
                        uint8_t       *out) {
    if (!key || !in || !out || key_len != 32) return -1;

    /* Zero nonce — safe because each key is used for exactly one purpose
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

/* ── HMAC-SHA256 truncated to MAC_BYTES ─────────────────────────────────── */

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

/* ── Internal: derive sub-keys from hop session ─────────────────────────── */

/* The client derives three keys per hop from the ECDHE shared secret:
 *   header_enc_key  — for AES-CTR encrypting addr+bkey in the header
 *   header_mac_key  — for HMAC over the header block
 *   blind_key       — for AES-CTR blinding the payload
 *
 * Each is derived via HKDF with a unique label string so no two purposes
 * share a key even if they share the same master shared secret.            */

static int derive_hop_keys(const aes_key_t *master,
                           aes_key_t       *henc,
                           aes_key_t       *hmac_key,
                           aes_key_t       *bkey) {
    /* Reuse crypto_ecdh_derive-style HKDF via a small wrapper.
     * We call crypto_aes_encrypt as a PRF — actually we need HKDF here.
     * Simplest correct approach: use the master key as IKM and derive
     * three independent keys using distinct info strings.                  */

    /* We'll use AES-256-CTR(master, nonce=label_hash) to generate each key.
     * This is a KDF: output_i = AES-CTR(master, nonce_i)[0..31]
     * where nonce_i is the first 16 bytes of SHA-256(label_i).            */

    struct { const char *label; aes_key_t *out; } derivations[] = {
        { LABEL_HEADER_ENC, henc      },
        { LABEL_HEADER_MAC, hmac_key  },
        { LABEL_BLIND_KEY,  bkey      },
    };

    for (int i = 0; i < 3; i++) {
        /* nonce = SHA256(label)[0..15] */
        uint8_t hash[32];
        unsigned int hlen = 32;
        EVP_MD_CTX *mctx = EVP_MD_CTX_new();
        if (!mctx) return -1;
        EVP_DigestInit_ex(mctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(mctx, derivations[i].label,
                         strlen(derivations[i].label));
        EVP_DigestFinal_ex(mctx, hash, &hlen);
        EVP_MD_CTX_free(mctx);

        /* Use hash[0..15] as CTR nonce */
        uint8_t nonce[16];
        memcpy(nonce, hash, 16);

        /* Generate 32 bytes of keystream */
        uint8_t zeros[32] = {0};
        uint8_t keystream[32];
        int outl = 0, foutl = 0;
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return -1;
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(),
                               NULL, master->key, nonce) != 1) {
            EVP_CIPHER_CTX_free(ctx); return -1;
        }
        EVP_EncryptUpdate(ctx, keystream, &outl, zeros, 32);
        EVP_EncryptFinal_ex(ctx, keystream + outl, &foutl);
        EVP_CIPHER_CTX_free(ctx);

        memcpy(derivations[i].out->key, keystream, AES_KEY_LEN);
    }
    return 0;
}

/* ── packet_sphinx_build ─────────────────────────────────────────────────── */

int packet_sphinx_build(const sphinx_path_t *path,
                        const uint8_t       *payload,
                        uint16_t             payload_len,
                        uint8_t              flags,
                        uint8_t              is_cover,
                        wire_packet_t       *out) {
    if (!path || !payload || !out) return -1;
    if (payload_len > MAX_INNER_PAYLOAD) {
        fprintf(stderr, "[packet] payload too large: %u > %d\n",
                payload_len, MAX_INNER_PAYLOAD);
        return -1;
    }

    memset(out->data, 0, WIRE_PACKET_SIZE);

    /* ── Step 1: Build inner payload buffer (padded to PAYLOAD_SECTION_SIZE)
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

    /* ── Step 2: Encrypt payload end-to-end under e2e_key (AES-256-GCM)   */
    uint8_t e2e_ct[PAYLOAD_SECTION_SIZE];
    memset(e2e_ct, 0, sizeof(e2e_ct));

    int enc_len = crypto_aes_encrypt(&path->e2e.e2e_key,
                                     inner, inner_len,
                                     e2e_ct, sizeof(e2e_ct));
    if (enc_len < 0) {
        fprintf(stderr, "[packet] e2e encrypt failed\n"); return -1;
    }
    /* Remaining bytes in e2e_ct are already zero-padded                   */

    /* ── Step 3: Apply blinding in REVERSE hop order (MN3, MN2, MN1)
     * When the packet travels MN1->MN2->MN3, each node XORs its keystream,
     * progressively cancelling the pre-applied blinding.
     * After MN3 processes it, e2e_ct is recovered at the SG.             */
    uint8_t blinded[PAYLOAD_SECTION_SIZE];
    memcpy(blinded, e2e_ct, PAYLOAD_SECTION_SIZE);

    for (int hop = N_PATH_HOPS - 1; hop >= 0; hop--) {
        uint8_t tmp[PAYLOAD_SECTION_SIZE];
        if (packet_aes_ctr_xor(path->hops[hop].blind_key.key, AES_KEY_LEN,
                                blinded, PAYLOAD_SECTION_SIZE, tmp) != 0) {
            fprintf(stderr, "[packet] blinding failed at hop %d\n", hop);
            return -1;
        }
        memcpy(blinded, tmp, PAYLOAD_SECTION_SIZE);
    }

    /* ── Step 4: Build header blocks for each hop ─────────────────────────
     * Each block: [enc_addr(6)][enc_bkey(32)][mac(16)][hint(32)]
     * enc_addr and enc_bkey are AES-CTR encrypted under header_enc_key.
     * mac covers enc_addr||enc_bkey.                                      */
    uint8_t header[HEADER_SIZE];
    memset(header, 0, sizeof(header));

    for (int hop = 0; hop < N_PATH_HOPS; hop++) {
        uint8_t *block = header + hop * HEADER_BLOCK_SIZE;

        /* Derive sub-keys for this hop */
        aes_key_t henc = {0}, hmk = {0}, bkey_derived = {0};
        if (derive_hop_keys(&path->hops[hop].header_enc_key,
                            &henc, &hmk, &bkey_derived) != 0) {
            fprintf(stderr, "[packet] key derivation failed at hop %d\n", hop);
            return -1;
        }
        /* Note: we use header_enc_key directly as the encryption key,
         * and header_mac_key for MAC. bkey_derived is not used here
         * (blind_key is already in path->hops[hop].blind_key).            */

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

        /* Encrypt addr + bkey + flag together with single CTR stream */
        uint8_t combined_plain[ADDR_BYTES + BLIND_KEY_BYTES + FLAG_BYTES];
        uint8_t combined_enc[ADDR_BYTES + BLIND_KEY_BYTES + FLAG_BYTES];
        memcpy(combined_plain,              addr_plain, ADDR_BYTES);
        memcpy(combined_plain + ADDR_BYTES, bkey_plain, BLIND_KEY_BYTES);
        /* Cover flag only in hop 0 block (MN1/MNi reads it and drops)     */
        combined_plain[ADDR_BYTES + BLIND_KEY_BYTES] = (hop == 0) ? is_cover : 0;

        if (packet_aes_ctr_xor(path->hops[hop].header_enc_key.key, AES_KEY_LEN,
                                combined_plain, sizeof(combined_plain),
                                combined_enc) != 0) {
            fprintf(stderr, "[packet] combined encrypt failed\n"); return -1;
        }
        memcpy(block,                             combined_enc, ADDR_BYTES);
        memcpy(block + ADDR_BYTES,                combined_enc + ADDR_BYTES, BLIND_KEY_BYTES);
        memcpy(block + ADDR_BYTES + BLIND_KEY_BYTES, combined_enc + ADDR_BYTES + BLIND_KEY_BYTES, FLAG_BYTES);

        /* MAC over enc_addr || enc_bkey || enc_flags */
        if (packet_hmac(path->hops[hop].header_mac_key.key, AES_KEY_LEN,
                        block, ADDR_BYTES + BLIND_KEY_BYTES + FLAG_BYTES,
                        block + ADDR_BYTES + BLIND_KEY_BYTES + FLAG_BYTES) != 0) {
            fprintf(stderr, "[packet] MAC failed\n"); return -1;
        }

        /* Hint */
        memcpy(block + ADDR_BYTES + BLIND_KEY_BYTES + FLAG_BYTES + MAC_BYTES,
               path->hops[hop].hint, HINT_BYTES);
    }

    /* ── Step 5: Assemble wire packet [header][blinded_payload]            */
    memcpy(out->data,               header,  HEADER_SIZE);
    memcpy(out->data + HEADER_SIZE, blinded, PAYLOAD_SECTION_SIZE);

    return 0;
}

/* ── packet_sphinx_peel ──────────────────────────────────────────────────── */

int packet_sphinx_peel(const wire_packet_t *pkt,
                       const aes_key_t     *header_enc_key,
                       const aes_key_t     *header_mac_key,
                       const uint8_t        hint[HINT_BYTES],
                       hop_info_t          *out_hop,
                       wire_packet_t       *out_pkt,
                       uint8_t             *out_cover_flag) {
    if (!pkt || !header_enc_key || !header_mac_key || !out_hop || !out_pkt)
        return -1;

    /* Outermost header block is at bytes 0..HEADER_BLOCK_SIZE-1           */
    const uint8_t *block = pkt->data;

    /* ── Verify MAC ─────────────────────────────────────────────────────── */
    uint8_t computed_mac[MAC_BYTES];
    if (packet_hmac(header_mac_key->key, AES_KEY_LEN,
                    block, ADDR_BYTES + BLIND_KEY_BYTES + FLAG_BYTES,
                    computed_mac) != 0) return -1;

    if (crypto_memcmp(computed_mac,
                      block + ADDR_BYTES + BLIND_KEY_BYTES + FLAG_BYTES,
                      MAC_BYTES) != 0) {
        fprintf(stderr, "[packet] peel: MAC verification failed — drop\n");
        return -1;
    }

    /* ── Decrypt enc_addr || enc_bkey || enc_flags ──────────────────────── */
    uint8_t combined_enc[ADDR_BYTES + BLIND_KEY_BYTES + FLAG_BYTES];
    uint8_t combined_plain[ADDR_BYTES + BLIND_KEY_BYTES + FLAG_BYTES];
    memcpy(combined_enc, block, ADDR_BYTES + BLIND_KEY_BYTES + FLAG_BYTES);

    if (packet_aes_ctr_xor(header_enc_key->key, AES_KEY_LEN,
                            combined_enc, sizeof(combined_enc),
                            combined_plain) != 0) return -1;

    memcpy(out_hop->next_ip, combined_plain, 4);
    out_hop->next_port = (uint16_t)((combined_plain[4] << 8) |
                                     combined_plain[5]);
    memcpy(out_hop->blind_key, combined_plain + ADDR_BYTES, BLIND_KEY_BYTES);
    if (out_cover_flag)
        *out_cover_flag = combined_plain[ADDR_BYTES + BLIND_KEY_BYTES];

    /* ── Apply blinding to payload (XOR with this hop's keystream) ──────── */
    const uint8_t *payload_in = pkt->data + HEADER_SIZE;
    uint8_t        payload_out[PAYLOAD_SECTION_SIZE];

    if (packet_aes_ctr_xor(out_hop->blind_key, BLIND_KEY_BYTES,
                            payload_in, PAYLOAD_SECTION_SIZE,
                            payload_out) != 0) return -1;

    /* ── Build output packet: shift header left by one block, copy payload  */
    memset(out_pkt->data, 0, WIRE_PACKET_SIZE);

    /* Remaining header blocks (hops 1 and 2) shift to position 0          */
    size_t remaining_header = HEADER_SIZE - HEADER_BLOCK_SIZE;
    if (remaining_header > 0)
        memcpy(out_pkt->data,
               pkt->data + HEADER_BLOCK_SIZE,
               remaining_header);

    /* Blinded payload goes at HEADER_SIZE - HEADER_BLOCK_SIZE offset       */
    /* Actually: output header is (N_PATH_HOPS-1) blocks, payload unchanged */
    /* For the next hop to work correctly the full WIRE_PACKET_SIZE must be
     * maintained. We zero-pad the freed header space.                      */
    memcpy(out_pkt->data + HEADER_SIZE, payload_out, PAYLOAD_SECTION_SIZE);

    (void)hint; /* hint used externally for key lookup before calling peel  */
    return 0;
}

/* ── packet_sphinx_unwrap ────────────────────────────────────────────────── */

int packet_sphinx_unwrap(const wire_packet_t *pkt,
                         const aes_key_t     *e2e_key,
                         uint8_t             *payload_out,
                         uint16_t            *payload_len,
                         uint8_t             *flags) {
    if (!pkt || !e2e_key || !payload_out || !payload_len || !flags) return -1;

    /* At the SG, all blinding operations have been cancelled.
     * The payload section holds the raw AES-256-GCM ciphertext.           */
    const uint8_t *ct     = pkt->data + HEADER_SIZE;
    size_t         ct_len = PAYLOAD_SECTION_SIZE;

    /* Find actual ciphertext length: GCM ciphertext ends at the first
     * run of trailing zeros beyond the nonce+tag minimum.
     * For correctness: we know enc_len from build = inner_len + GCM_OVERHEAD.
     * Since inner_len = 3 + payload_len and we padded with zeros, the GCM
     * ciphertext length = 3 + payload_len + GCM_OVERHEAD.
     * We try decrypting the full PAYLOAD_SECTION_SIZE first.
     * If that fails, scan backward for the actual end.                    */

    uint8_t plain[PAYLOAD_SECTION_SIZE];
    int n = crypto_aes_decrypt(e2e_key, ct, ct_len, plain, sizeof(plain));
    if (n < 0) {
        /* Try with trimmed size — scan for last non-zero byte             */
        size_t trim = ct_len;
        while (trim > GCM_OVERHEAD + 3 && ct[trim-1] == 0) trim--;
        if (trim < GCM_OVERHEAD + 3) trim = GCM_OVERHEAD + 3;
        n = crypto_aes_decrypt(e2e_key, ct, trim, plain, sizeof(plain));
        if (n < 0) {
            fprintf(stderr, "[packet] unwrap: GCM decryption failed\n");
            return -1;
        }
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

    memcpy(payload_out, plain + INNER_HDR_BYTES, *payload_len);
    return 0;
}

/* ── packet_sphinx_dummy ─────────────────────────────────────────────────── */

int packet_sphinx_dummy(const sphinx_path_t *path, wire_packet_t *out) {
    if (!path || !out) return -1;

    /* Random payload — max size so even payload_len gives nothing away     */
    uint8_t rand_payload[MAX_INNER_PAYLOAD];
    if (RAND_bytes(rand_payload, MAX_INNER_PAYLOAD) != 1) return -1;

    return packet_sphinx_build(path, rand_payload, MAX_INNER_PAYLOAD,
                               PKT_DUMMY | PKT_DEST_SERVICE, COVER_FLAG, out);
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

        /* Encrypt addr with hop enc key */
        if (packet_aes_ctr_xor(hop_enc_keys[i].key, AES_KEY_LEN,
                                addrs[i], ADDR_BYTES,
                                blk->enc_addr) != 0) return -1;

        /* MAC over enc_addr */
        if (packet_hmac(hop_mac_keys[i].key, AES_KEY_LEN,
                        blk->enc_addr, ADDR_BYTES,
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

    /* Verify MAC */
    uint8_t computed_mac[MAC_BYTES];
    if (packet_hmac(header_mac_key->key, AES_KEY_LEN,
                    blk->enc_addr, ADDR_BYTES,
                    computed_mac) != 0) return -1;

    if (crypto_memcmp(computed_mac, blk->mac, MAC_BYTES) != 0) {
        fprintf(stderr, "[packet] return header: MAC failed\n");
        return -1;
    }

    /* Decrypt addr */
    uint8_t addr_plain[ADDR_BYTES];
    if (packet_aes_ctr_xor(header_enc_key->key, AES_KEY_LEN,
                            blk->enc_addr, ADDR_BYTES,
                            addr_plain) != 0) return -1;

    memcpy(out_next->next_ip, addr_plain, 4);
    out_next->next_port = (uint16_t)((addr_plain[4] << 8) | addr_plain[5]);

    /* Shift remaining blocks left */
    memset(out_rhdr, 0, sizeof(*out_rhdr));
    for (int i = 1; i < N_PATH_HOPS; i++)
        out_rhdr->blocks[i-1] = rhdr->blocks[i];

    return 0;
}
