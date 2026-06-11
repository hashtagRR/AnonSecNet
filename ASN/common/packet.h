#ifndef PACKET_H
#define PACKET_H

#include "config.h"
#include "crypto.h"
#include <stdint.h>
#include <stddef.h>

/* ── Wire packet ─────────────────────────────────────────────────────────── */
typedef struct {
    uint8_t data[WIRE_PACKET_SIZE];
} wire_packet_t;

/* ── Header block (one per hop, stored consecutively) ───────────────────────
 *
 * Layout within header section of wire packet:
 *   Block 0 (hop 0 = MN1): bytes   0 .. 85
 *   Block 1 (hop 1 = MN2): bytes  86 .. 171
 *   Block 2 (hop 2 = MN3): bytes 172 .. 257
 *
 * Within each block:
 *   [0..5]   enc_addr    : AES-CTR encrypted next-hop address (IP+port)
 *   [6..37]  enc_bkey    : AES-CTR encrypted blinding key
 *   [38..53] mac         : HMAC-SHA256[:16] over enc_addr||enc_bkey
 *   [54..85] hint        : unencrypted x-coordinate of ephemeral ECDHE key
 *                          used by the mix node for O(1) key lookup
 *
 * The hint is not secret — it reveals nothing about the Receiver, the SG,
 * or any other path component. It allows the mix node to find its session
 * key in O(1) by matching the hint against stored ephemeral keys.
 */
typedef struct {
    uint8_t enc_addr[ADDR_BYTES];         /* encrypted next-hop IP:port    */
    uint8_t enc_bkey[BLIND_KEY_BYTES];    /* encrypted blinding key        */
    uint8_t enc_flags[FLAG_BYTES];        /* encrypted cover flag          */
    uint8_t mac[MAC_BYTES];              /* MAC over enc_addr+enc_bkey+enc_flags */
    uint8_t hint[HINT_BYTES];             /* unencrypted ECDHE x-coord     */
} header_block_t;   /* sizeof == HEADER_BLOCK_SIZE (87) */

/* ── Decoded hop info (returned by packet_peel_header) ─────────────────── */
typedef struct {
    uint8_t  next_ip[4];     /* next hop IPv4 address                      */
    uint16_t next_port;      /* next hop port (host byte order)            */
    uint8_t  blind_key[BLIND_KEY_BYTES]; /* AES-CTR key for payload XOR   */
} hop_info_t;

/* ── Per-hop session state (held by client during path construction) ─────── */
typedef struct {
    aes_key_t  header_enc_key;  /* for encrypting addr+bkey in header block */
    aes_key_t  header_mac_key;  /* for MAC over header block                */
    aes_key_t  blind_key;       /* AES-CTR blinding key for payload         */
    uint8_t    hint[HINT_BYTES];/* x-coord of ephemeral key, sent in header */
} hop_session_t;

/* ── End-to-end session (client <-> SG) ─────────────────────────────────── */
typedef struct {
    aes_key_t e2e_key;       /* K_R-SG-A or K_R-SG-B (AES-256-GCM)        */
} e2e_session_t;

/* ── Path descriptor ─────────────────────────────────────────────────────── */
typedef struct {
    hop_session_t hops[N_PATH_HOPS];  /* per-hop state for MN1, MN2, MN3   */
    e2e_session_t e2e;                /* end-to-end key to SG               */
    uint8_t       next_ip[4];         /* MN1 IP (entry point)               */
    uint16_t      next_port;          /* MN1 port                           */
    uint16_t      hop_ports[N_PATH_HOPS]; /* ports of each hop              */
    uint16_t      sg_port;            /* SG port                            */
} sphinx_path_t;

/* ================================================================
 * API
 * ================================================================ */

/* Build a Sphinx-style wire packet.
 *
 * path        : fully constructed path (from telescoping handshake)
 * payload     : plaintext message (<= MAX_INNER_PAYLOAD bytes)
 * payload_len : byte count
 * flags       : PKT_REAL/PKT_DUMMY | PKT_DEST_SERVICE/PKT_DEST_PUBLIC
 * out         : filled with 1024-byte wire packet
 *
 * Returns 0 on success, -1 on error.
 *
 * Internally:
 *   1. Encrypt payload under e2e_key (AES-256-GCM) -> e2e_ct
 *   2. Apply blinding: blind_2(blind_1(blind_0(e2e_ct))) -> blinded
 *      (all three blinding keys applied before sending so SG can undo)
 *      Wait — see note below on blinding direction.
 *   3. Build header blocks for MN1, MN2, MN3
 *   4. Assemble: [header_blocks][blinded_payload]
 *
 * Blinding note: The CLIENT applies blinding in REVERSE order
 * (MN3's key first, then MN2's, then MN1's) so that as the packet
 * travels MN1->MN2->MN3, each node XORs its own keystream and the
 * payload is progressively un-blinded. When the SG receives it, all
 * three blinidng operations have been applied once (XOR is self-inverse),
 * leaving the raw AES-GCM ciphertext, which the SG decrypts with e2e_key.
 */
int packet_sphinx_build(const sphinx_path_t *path,
                        const uint8_t       *payload,
                        uint16_t             payload_len,
                        uint8_t              flags,
                        uint8_t              is_cover,
                        wire_packet_t       *out);

/* Peel the outermost header block at a mix node.
 *
 * Called by each mix node upon receiving a MODE_DATA packet.
 *
 * pkt         : incoming wire packet (1024 bytes)
 * header_enc_key : this node's AES-CTR key for decrypting addr+bkey
 * header_mac_key : this node's HMAC key for verifying MAC
 * hint        : the x-coord the client embedded for this hop
 *               (node looks up its session using the hint)
 * out_hop     : filled with next-hop address and blinding key
 * out_pkt     : output packet with outermost header block removed
 *               and payload XORed with this hop's blinding key
 *               (shifted header + blinded payload, still 1024 bytes)
 *
 * Returns 0 on success, -1 on MAC failure (drop packet).
 */
int packet_sphinx_peel(const wire_packet_t *pkt,
                       const aes_key_t     *header_enc_key,
                       const aes_key_t     *header_mac_key,
                       const uint8_t        hint[HINT_BYTES],
                       hop_info_t          *out_hop,
                       wire_packet_t       *out_pkt,
                       uint8_t             *out_cover_flag);

/* Unwrap the payload at the Service Gateway.
 *
 * At the SG, all three blinding operations have been cancelled by
 * MN1, MN2, MN3. The payload section now holds the raw AES-GCM
 * ciphertext. The SG decrypts it with e2e_key to recover the plaintext.
 *
 * pkt         : incoming wire packet from MN3
 * e2e_key     : K_R-SG-A (end-to-end key)
 * payload_out : filled with decrypted plaintext
 * payload_len : filled with plaintext byte count
 * flags       : filled with PKT_REAL/PKT_DUMMY flag
 *
 * Returns 0 on success, -1 on GCM authentication failure.
 */
int packet_sphinx_unwrap(const wire_packet_t *pkt,
                         const aes_key_t     *e2e_key,
                         uint8_t             *payload_out,
                         uint16_t            *payload_len,
                         uint8_t             *flags);

/* Build a dummy packet (indistinguishable from real at every mix node).
 * Returns 0 on success, -1 on error. */
int packet_sphinx_dummy(const sphinx_path_t *path, wire_packet_t *out);

/* ── Utility ─────────────────────────────────────────────────────────────── */

/* AES-CTR XOR: keystream(key, nonce=0) XOR data -> out
 * Used for header field encryption and payload blinding.
 * Self-inverse: applying twice recovers original.
 * Returns 0 on success, -1 on error. */
int packet_aes_ctr_xor(const uint8_t *key, size_t key_len,
                        const uint8_t *in,  size_t len,
                        uint8_t       *out);

/* HMAC-SHA256 truncated to MAC_BYTES (16).
 * Returns 0 on success, -1 on error. */
int packet_hmac(const uint8_t *key, size_t key_len,
                const uint8_t *data, size_t data_len,
                uint8_t        out[MAC_BYTES]);

#endif /* PACKET_H */

/* ================================================================
 * Return path packet API
 * ================================================================
 *
 * The client pre-builds the return header during session setup and
 * embeds it in every outbound payload. The SG extracts it and
 * prepends it to the response. MNc/MNb/MNa each peel one block.
 *
 * Return header block layout (RETURN_BLOCK_SIZE = 54 bytes):
 *   enc_addr[6]   -- AES-CTR encrypted next-hop IP:port
 *   mac[16]       -- HMAC-SHA256[:16] over enc_addr
 *   hint[32]      -- unencrypted x-coord of client's ephemeral key
 *                    (same hint used during path A/B construction)
 *
 * No blinding key -- return path payload is not blinded.
 * Response stays encrypted under K_R-SG-B from SG to Client.
 */

typedef struct {
    uint8_t enc_addr[ADDR_BYTES];
    uint8_t mac[MAC_BYTES];
    uint8_t hint[HINT_BYTES];
} return_block_t;   /* sizeof == RETURN_BLOCK_SIZE (54) */

typedef struct {
    return_block_t blocks[N_PATH_HOPS];
} return_header_t;  /* sizeof == RETURN_HEADER_SIZE (162) */

/* return_next_t: decoded result from peeling one return header block */
typedef struct {
    uint8_t  next_ip[4];
    uint16_t next_port;
} return_next_t;

/* Build the return header (called by client during session setup).
 *
 * hop_enc_keys[0] = SK_R-MNc  (outermost, SG-facing)
 * hop_enc_keys[1] = SK_R-MNb
 * hop_enc_keys[2] = SK_R-MNa  (innermost, Receiver-facing)
 * hop_mac_keys[i] = matching MAC key per hop
 * hop_hints[i]    = ECDHE x-coord hint per hop
 * addrs[0]        = MNb IP:port  (what MNc learns after peeling)
 * addrs[1]        = MNa IP:port  (what MNb learns)
 * addrs[2]        = Client IP:port (what MNa learns)
 *
 * Returns 0 on success, -1 on error. */
int packet_build_return_header(
    const aes_key_t  hop_enc_keys[N_PATH_HOPS],
    const aes_key_t  hop_mac_keys[N_PATH_HOPS],
    const uint8_t    hop_hints[N_PATH_HOPS][HINT_BYTES],
    const uint8_t    addrs[N_PATH_HOPS][ADDR_BYTES],
    return_header_t *out);

/* Peel one return header block (called by MNc, MNb, MNa).
 *
 * rhdr          -- incoming return_header_t (first block is ours)
 * header_enc_key -- our AES-CTR key for decrypting enc_addr
 * header_mac_key -- our HMAC key for verifying MAC
 * out_next      -- filled with next-hop address
 * out_rhdr      -- remaining header (blocks shifted left by one)
 *
 * Returns 0 on success, -1 on MAC failure. */
int packet_peel_return_header(
    const return_header_t *rhdr,
    const aes_key_t       *header_enc_key,
    const aes_key_t       *header_mac_key,
    return_next_t         *out_next,
    return_header_t       *out_rhdr);
