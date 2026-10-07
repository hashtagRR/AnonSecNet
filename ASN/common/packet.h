#ifndef PACKET_H
#define PACKET_H

#include "config.h"
#include "crypto.h"
#include <stdint.h>
#include <stddef.h>

/* Wire packet */
typedef struct {
    uint8_t data[WIRE_PACKET_SIZE];
} wire_packet_t;

/* Header block (one per hop, stored consecutively)
 *
 * Layout within header section of wire packet:
 *   Block 0 (hop 0 = MN1): bytes   0 .. 94
 *   Block 1 (hop 1 = MN2): bytes  95 .. 189
 *   Block 2 (hop 2 = MN3): bytes 190 .. 284
 *
 * Within each block:
 *   [0..5]   enc_addr    : AES-CTR encrypted next-hop address (IP+port)
 *   [6..37]  enc_bkey    : AES-CTR encrypted blinding key
 *   [38]     enc_flags   : AES-CTR encrypted cover flag
 *   [39..46] enc_nonce   : AES-CTR encrypted per-packet random nonce
 *   [47..62] mac         : HMAC-SHA256[:16] over enc_addr||enc_bkey||
 *                          enc_flags||enc_nonce
 *   [63..94] hint        : unencrypted x-coordinate of ephemeral ECDHE key
 *                          used by the mix node for O(1) key lookup
 *
 * The hint is not secret, it reveals nothing about the Receiver, the SG,
 * or any other path component. It allows the mix node to find its session
 * key in O(1) by matching the hint against stored ephemeral keys.
 *
 * enc_nonce carries a fresh RAND_bytes() value generated per packet (real
 * or cover) so each mix node can maintain a small seen-nonce cache and
 * reject an exact resend of a previously-forwarded packet, the paper's
 * §4.4 replay-protection claim. Bounded to a per-session sliding window
 * (see mix_node.c); a replay delayed past the window's retention is not
 * caught by this mechanism, which is a real, documented limitation, not
 * a claim of unconditional replay-resistance.
 */
typedef struct {
    uint8_t enc_addr[ADDR_BYTES];         /* encrypted next-hop IP:port    */
    uint8_t enc_bkey[BLIND_KEY_BYTES];    /* encrypted blinding key        */
    uint8_t enc_flags[FLAG_BYTES];        /* encrypted cover flag          */
    uint8_t enc_nonce[NONCE_BYTES];       /* encrypted per-packet nonce    */
    uint8_t mac[MAC_BYTES];              /* MAC over enc_addr+enc_bkey+enc_flags+enc_nonce */
    uint8_t hint[HINT_BYTES];             /* unencrypted ECDHE x-coord     */
} header_block_t;   /* sizeof == HEADER_BLOCK_SIZE (95) */

/* Decoded hop info (returned by packet_peel_header) */
typedef struct {
    uint8_t  next_ip[4];     /* next hop IPv4 address                      */
    uint16_t next_port;      /* next hop port (host byte order)            */
    uint8_t  blind_key[BLIND_KEY_BYTES]; /* AES-CTR key for payload XOR   */
    uint8_t  nonce[NONCE_BYTES];         /* per-packet nonce, for replay check */
    uint8_t  hop_flag;       /* this hop's own decrypted enc_flags byte,
                               * HOP_FLAG_FORWARD for every real packet and
                               * every hop of a decoy that isn't terminating
                               * here, HOP_DROP_MARKER only at a decoy's own
                               * chosen termination hop. Only meaningful to
                               * callers built with ASN_HOP_DECOY, see
                               * config.h's comment for what this can and
                               * cannot see. */
} hop_info_t;

/* Per-hop session state (held by client during path construction) */
typedef struct {
    aes_key_t  header_enc_key;  /* for encrypting addr+bkey in header block */
    aes_key_t  header_mac_key;  /* for MAC over header block                */
    aes_key_t  blind_key;       /* AES-CTR blinding key for payload         */
    aes_key_t  hint_seed;       /* Rotating hint seed for this hop, both
                                  * forward (see packet_sphinx_build())
                                  * and return (see client.c's
                                  * build_fresh_return_header()) paths;
                                  * see packet_derive_hint_seed(). */
} hop_session_t;

/* End-to-end session (client <-> SG) */
typedef struct {
    aes_key_t e2e_key;       /* K_R-SG-A or K_R-SG-B (AES-256-GCM)        */
} e2e_session_t;

/* SG-side O(1) session hint.
 * See config.h's SG_HINT_BYTES comment for the full design/security
 * rationale. Only meaningful for role-A paths (the ones that ever send
 * MODE_DATA packets to the SG); role-B's e2e_key never needs this. */
typedef struct {
    uint8_t bytes[SG_HINT_BYTES];
} sg_hint_t;

/* Path descriptor */
typedef struct {
    hop_session_t hops[N_PATH_HOPS];  /* per-hop state for MN1, MN2, MN3   */
    e2e_session_t e2e;                /* end-to-end key to SG               */
    uint8_t       next_ip[4];         /* MN1 IP (entry point)               */
    uint16_t      next_port;          /* MN1 port                           */
    uint16_t      hop_ports[N_PATH_HOPS]; /* ports of each hop              */
    uint16_t      sg_port;            /* SG port                            */
    sg_hint_t     sg_hint;            /* see above */
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
 *      Wait, see note below on blinding direction.
 *   3. Build header blocks for MN1, MN2, MN3
 *   4. Assemble: [header_blocks][blinded_payload]
 *
 * Blinding note: The CLIENT applies blinding in REVERSE order
 * (MN3's key first, then MN2's, then MN1's) so that as the packet
 * travels MN1->MN2->MN3, each node XORs its own keystream and the
 * payload is progressively un-blinded. When the SG receives it, all
 * three blinidng operations have been applied once (XOR is self-inverse),
 * leaving the raw AES-GCM ciphertext, which the SG decrypts with e2e_key.
 *
 * pkt_counter : caller's per-session forward-path
 *               packet counter (shared by real AND cover packets, see
 *               client.c/sender.c), used to derive each hop's per-packet
 *               `hint` fresh (HMAC(hop.hint_seed, pkt_counter)) instead
 *               of reusing the session-constant value that used to sit
 *               in hop.hint. Caller must increment this by exactly 1 per
 *               packet built for this path (real or dummy) and never
 *               reuse a value, or the mix node's hint window will not
 *               match: see config.h's HINT_WINDOW comment.
 */
int packet_sphinx_build(const sphinx_path_t *path,
                        const uint8_t       *payload,
                        uint16_t             payload_len,
                        uint8_t              flags,
                        uint64_t             pkt_counter,
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
                       wire_packet_t       *out_pkt);

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
 * pkt_counter : same shared per-session counter as packet_sphinx_build()
 *               (cover packets consume a counter
 *               value from the same sequence as real ones, so their hint
 *               is indistinguishable from a real packet's to an observer,
 *               and so they still land in the mix node's hint window).
 * Returns 0 on success, -1 on error. */
int packet_sphinx_dummy(const sphinx_path_t *path, uint64_t pkt_counter,
                        wire_packet_t *out);

/* Build a per-hop-terminating decoy (ASN_HOP_DECOY): identical to
 * packet_sphinx_dummy(): same size, same PKT_DUMMY end-to-end flag, same
 * random payload, except `drop_at_hop` (0..N_PATH_HOPS-1) selects one hop
 * whose enc_flags byte carries HOP_DROP_MARKER instead of
 * HOP_FLAG_FORWARD, so that hop terminates the decoy instead of relaying
 * it onward. Caller (client.c/sender.c) chooses drop_at_hop, typically via
 * a weighted random draw, see config.h's HOP_DECOY_*_WEIGHT_PCT. This
 * function does not itself decide where decoys terminate; it only builds
 * the wire packet for a caller-chosen termination point.
 * Returns 0 on success, -1 on error (including drop_at_hop out of range). */
int packet_sphinx_decoy_hop(const sphinx_path_t *path, uint64_t pkt_counter,
                             int drop_at_hop, wire_packet_t *out);

/* Utility */

/* AES-CTR XOR: keystream(key, nonce=0) XOR data -> out
 * Self-inverse: applying twice recovers original.
 * Returns 0 on success, -1 on error.
 *
 * SAFE ONLY when either the key is genuinely single-use, or the plaintext
 * is fresh/random on every call (so ciphertext varies even with a fixed
 * nonce). UNSAFE for a key reused across multiple calls against
 * session-constant plaintext, the fixed zero nonce makes every such call
 * produce the identical keystream, so any session-constant plaintext
 * region repeats identically on the wire across every packet, a passive
 * per-flow fingerprint (this was exactly how `blind_key` payload blinding
 * leaked before it was fixed to use `packet_aes_ctr_xor_iv()` with a
 * per-packet IV instead, see
 * packet_sphinx_build_ex()'s Step 2b/3 and packet_sphinx_peel()). Before
 * adding a new caller with a multi-use key, use packet_aes_ctr_xor_iv()
 * with a per-packet-derived IV instead of this function. */
int packet_aes_ctr_xor(const uint8_t *key, size_t key_len,
                        const uint8_t *in,  size_t len,
                        uint8_t       *out);

/* HMAC-SHA256 truncated to MAC_BYTES (16).
 * Returns 0 on success, -1 on error. */
int packet_hmac(const uint8_t *key, size_t key_len,
                const uint8_t *data, size_t data_len,
                uint8_t        out[MAC_BYTES]);

/* Derive header_enc_key, header_mac_key, blind_key from a per-hop ECDHE
 * shared secret via a labelled PRF (AES-256-CTR(master, nonce=SHA256(label)[0..15])),
 * so the three outputs are cryptographically independent even though they
 * share one input secret, unlike a byte-rotation, no one output key
 * yields another. Every principal that needs a hop's keys (client, sender,
 * mix node) MUST call this on the same shared ECDHE master rather than
 * deriving its own ad-hoc split, or the MACs/decryption between them will
 * disagree. Returns 0 on success, -1 on error. */
int packet_derive_hop_keys(const aes_key_t *master,
                            aes_key_t       *header_enc_key,
                            aes_key_t       *header_mac_key,
                            aes_key_t       *blind_key);

/* Derive the SG-side O(1) session hint from the same shared ECDH master
 * (K_R-SG-A/K_S-SG-A, role A's raw ECDH result, stored unsplit as
 * e2e_key, unlike the per-hop keys above) that the client/sender and the
 * SG each independently hold after the MODE_EXTEND handshake, see
 * config.h's SG_HINT_BYTES comment. Both sides MUST call this on the same
 * master (client.c/sender.c right after establishing K_*_SG-A; the SG in
 * its MODE_EXTEND handler right after crypto_ecdh_derive()) or the hint
 * will not match and find_a_session()'s pre-filter will reject every packet.
 * Returns 0 on success, -1 on error. */
int packet_derive_sg_hint(const aes_key_t *master, sg_hint_t *out);

/* Derive a hop's forward-path rotating-hint seed from
 * the same per-hop ECDH master used for header_enc_key/header_mac_key/
 * blind_key (a distinct label keeps it independent, same principle as
 * packet_derive_hop_keys()). Both the client/sender and the mix node
 * that owns this hop MUST call this on the same master, at the same
 * point client.c's derive_hop()/mix_node.c's split_master_keys() already
 * call packet_derive_hop_keys(), or the two sides' hint sequences will
 * never agree. Returns 0 on success, -1 on error. */
int packet_derive_hint_seed(const aes_key_t *master, aes_key_t *out);

/* Derive the per-packet forward-path hint for counter
 * value `pkt_counter` from a hop's hint_seed, HMAC-SHA256(hint_seed,
 * pkt_counter as 8 bytes big-endian), the full 32-byte output used
 * directly as the hint (HINT_BYTES == the native HMAC-SHA256 width, no
 * truncation). Deterministic and stateless: the same (hint_seed,
 * pkt_counter) pair always yields the same hint, which is what lets a
 * mix node precompute a forward-looking window of upcoming values (see
 * config.h's HINT_WINDOW comment) rather than needing the client to
 * transmit anything extra. Returns 0 on success, -1 on error. */
int packet_derive_hop_hint(const aes_key_t *hint_seed, uint64_t pkt_counter,
                            uint8_t out[HINT_BYTES]);

/* Two-key binding tag, proves the client
 * established both K_R-SG-A and K_R-SG-B in the same setup. `a_key` and
 * `b_key` must be passed in the same order (A then B) by every caller,
 * see packet.c's comment for the full rationale (replaces an earlier
 * XOR-of-keys combiner). Returns 0 on success, -1 on error. */
int packet_derive_binding_tag(const aes_key_t *a_key, const aes_key_t *b_key,
                               uint8_t out[MAC_BYTES]);

/* ================================================================
 * Return path packet API
 * ================================================================
 *
 * The client pre-builds the return header during session setup and
 * embeds it in every outbound payload. The SG extracts it and
 * prepends it to the response. MNc/MNb/MNa each peel one block.
 *
 * Return header block layout (RETURN_BLOCK_SIZE = 58 bytes):
 *   enc_addr[6]:    AES-CTR encrypted next-hop IP:port
 *   enc_nonce[4]:   AES-CTR encrypted per-packet random nonce (replay
 *                     detection only, see mix_node.c's
 *                     seen_return_nonces; smaller than the forward
 *                     path's 8-byte NONCE_BYTES purely to fit the
 *                     TYPE_SETUP payload's remaining byte budget, see
 *                     config.h's RETURN_NONCE_BYTES comment)
 *   mac[16]:        HMAC-SHA256[:16] over enc_addr||enc_nonce
 *   hint[32]:       unencrypted, rotates every request:
 *                     HMAC(hint_seed, ctr). See
 *                     build_fresh_return_header() (client.c/sender.c).
 *
 * No blinding key IN THE HEADER BLOCK, unlike the forward path, the
 * return-path blinding key is never transmitted at all. It's the same
 * deterministic function of the ECDH master, the labelled-PRF KDF
 * (packet_derive_hop_keys(); not a byte-rotation,
 * which would make one output key trivially yield the others), that
 * mix_node.c's split_master_keys() already derives as
 * blind_key for every session; a receiving-path session stores it as
 * return_blind_key and the client independently derives and sends the
 * identical value to the SG as recv_blind[i]. See
 * service_gateway.c::send_response() and mix_node.c::handle_return().
 */

typedef struct {
    uint8_t enc_addr[ADDR_BYTES];
    uint8_t enc_nonce[RETURN_NONCE_BYTES];
    uint8_t mac[MAC_BYTES];
    uint8_t hint[HINT_BYTES];
} return_block_t;   /* sizeof == RETURN_BLOCK_SIZE (58) */

typedef struct {
    return_block_t blocks[N_PATH_HOPS];
} return_header_t;  /* sizeof == RETURN_HEADER_SIZE (174) */

/* return_next_t: decoded result from peeling one return header block */
typedef struct {
    uint8_t  next_ip[4];
    uint16_t next_port;
    uint8_t  nonce[RETURN_NONCE_BYTES]; /* per-packet nonce, for replay check */
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
 * Generates a fresh random enc_nonce per block internally (RAND_bytes),
 * callers do not supply one.
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
 * rhdr: incoming return_header_t (first block is ours)
 * header_enc_key: our AES-CTR key for decrypting enc_addr
 * header_mac_key: our HMAC key for verifying MAC
 * out_next: filled with next-hop address and nonce
 * out_rhdr: remaining header (blocks shifted left by one)
 *
 * Returns 0 on success, -1 on MAC failure. */
int packet_peel_return_header(
    const return_header_t *rhdr,
    const aes_key_t       *header_enc_key,
    const aes_key_t       *header_mac_key,
    return_next_t         *out_next,
    return_header_t       *out_rhdr);

#endif /* PACKET_H */
