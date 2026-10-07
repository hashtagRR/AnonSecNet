#ifndef CONFIG_H
#define CONFIG_H

/*
 * Anon-Sec-Net v2, Configuration
 *
 * Client paths:
 *   Sending:   Client -> MN1(9004) -> MN2(9005) -> MN3(9006) -> SvcGW(9010)
 *   Receiving: SvcGW  -> MNa(9007) -> MNb(9008) -> MNc(9009) -> Client
 *
 * Sender paths:
 *   Sending:   Sender -> MNi(9040) -> MNii(9041) -> MNiii(9042) -> SvcGW(9010)
 *   Receiving: SvcGW  -> MNx(9043) -> MNy(9044)  -> MNz(9045)  -> Sender
 *
 * SvcGW(9010) -> Cache(9012)
 *
 * No border nodes. MN1 and MNi are the only nodes that see Client/Sender IP.
 */

/*, Client sending path -------------------------------------------------- */
#define PORT_MIX_1            9004
#define PORT_MIX_2            9005
#define PORT_MIX_3            9006

/*, Client receiving path ------------------------------------------------ */
#define PORT_MIX_A            9007
#define PORT_MIX_B            9008
#define PORT_MIX_C            9009

/*, Gateways ------------------------------------------------------------- */
#define PORT_SERVICE_GW       9010
#define PORT_CACHE_SERVER     9012

/*, Sender sending path -------------------------------------------------- */
/* 9040-9045: outside CLIENT_RESPONSE_PORT..+CLIENT_RESPONSE_PORT_COUNT
 * (9020-9039), so handle_return()'s is_final() check can't confuse a
 * mix node port in this range with a legitimate client response port. */
#define PORT_MIX_I            9040
#define PORT_MIX_II           9041
#define PORT_MIX_III          9042

/*, Sender receiving path ------------------------------------------------ */
#define PORT_MIX_X            9043
#define PORT_MIX_Y            9044
#define PORT_MIX_Z            9045

/*, Response ports ------------------------------------------------------- */
#define PORT_CLIENT           9001
#define PORT_SENDER           9015
#define CLIENT_RESPONSE_PORT  9020

/* Gives the Sender SENDER_RESPONSE_PORT_COUNT independent response
 * ports/mailboxes (same bounded, fully-enumerable allowlist pattern as
 * CLIENT_RESPONSE_PORT_COUNT above, mix_node.c's is_allowed_next_hop()/
 * is_final checks accept the whole range), so up to this many real
 * sends can be genuinely in flight at once instead of one at a time.
 * In the free gap between the sender's own fixed mix ports
 * (PORT_MIX_I..Z, ending at 9045) and the node_pool range
 * (common/node_pool.h's POOL_PORT_BASE=9100). */
#define SENDER_RESPONSE_PORT   9046
#define SENDER_RESPONSE_PORT_COUNT 16

/* The reference client can pick its response port from this small,
 * fixed, enumerated range instead of a single constant, see client.c's
 * response_port(): so multiple simultaneous client identities can run
 * locally at once; mix_node.c's is_allowed_next_hop()/is_final checks
 * accept the whole range. Still a bounded, fully-enumerable allowlist,
 * not an arbitrary-port opening: exactly CLIENT_RESPONSE_PORT_COUNT
 * fixed local ports, all loopback-only, same as every other port in
 * this prototype's allowlist. */
#define CLIENT_RESPONSE_PORT_COUNT 20

#define LOCALHOST             "127.0.0.1"
#define PUBKEY_DIR            "/tmp/ansn"

/*, Protocol modes ------------------------------------------------------- */
#define MODE_EXTEND           0x01
#define MODE_DATA             0x02
#define MODE_RETURN           0x03

/*, Sphinx outbound packet layout ----------------------------------------
 *
 * Outbound (Client -> MN1 -> MN2 -> MN3 -> SG):
 *
 *   HEADER: 3 x HEADER_BLOCK_SIZE = 3 x 95 = 285 bytes
 *     Each block: enc_addr(6) + enc_bkey(32) + enc_flags(1) + enc_nonce(8)
 *       + mac(16) + hint(32) = 95
 *
 *   PAYLOAD: 739 bytes
 *     enc_K_R-SG-A(
 *       flags(1) + payload_len(2) +
 *       MNc_pubkey(65) + MNc_IP(6) +
 *       return_header(174) +          <- pre-built nested return header
 *       app_data(variable)
 *     )
 *     Each mix node XORs payload with AES-CTR blinding key.
 *     SG reverses all three blindings then decrypts with K_R-SG-A.
 *
 * Return packet (SG -> MNc -> MNb -> MNa -> Client):
 *
 *   RETURN HEADER: 3 x RETURN_BLOCK_SIZE = 3 x 58 = 174 bytes
 *     Each block: enc_addr(6) + enc_nonce(4) + mac(16) + hint(32) = 58
 *     No blinding key IN the header block, return-path payload
 *     blinding uses a key derived from the ECDH master instead (see
 *     mix_node.c::split_master_keys()'s return_blind_key and
 *     service_gateway.c::send_response()), so nothing extra travels on
 *     the wire for it. enc_nonce is for replay detection only (see
 *     mix_node.c::handle_return()'s seen_return_nonces).
 *
 *   RETURN PAYLOAD: 850 bytes = enc_len(2) + enc_K_R-SG-B(response)(<=848)
 *     The first 2 bytes are a length prefix for the ciphertext that
 *     follows (service_gateway.c::send_response() writes it, client.c/
 *     sender.c read it back), the actual K_R-SG-B ciphertext capacity
 *     is RETURN_PAYLOAD_SIZE-2, not RETURN_PAYLOAD_SIZE; send_response()
 *     sizes its encrypt-output buffer accordingly. Then blinded by the
 *     SG and unblinded one layer per hop by MNc/MNb/MNa (see
 *     return_blind_key above), blinding covers the full 850-byte
 *     region including the length prefix, which is harmless since XOR
 *     is applied and cancelled identically regardless of what the bytes
 *     mean.
 */

#define N_PATH_HOPS           3
#define ADDR_BYTES            6
#define BLIND_KEY_BYTES       32
#define MAC_BYTES             16
#define HINT_BYTES            32
/* Header block layout per hop:
 *   enc_addr(6) + enc_bkey(32) + enc_flags(1) + enc_nonce(8) + mac(16) +
 *   hint(32) = 95
 *   enc_flags: bit0 = cover packet (MN1 drops without forwarding)
 *   enc_nonce: fresh random per-packet value (RAND_bytes), MAC-covered.
 *     Lets each mix node detect and reject an exact resend of a
 *     previously-forwarded packet, see session_entry_t.seen_nonces in
 *     mix_node.c. Random rather than a monotonic counter so the client
 *     does not need per-session sequence state; collision probability
 *     within any one session's lifetime is negligible (2^-64 space).    */
#define FLAG_BYTES            1
#define NONCE_BYTES            8
#define HEADER_BLOCK_SIZE     95     /* 6+32+1+8+16+32 */
#define HEADER_SIZE           285    /* 3 x 95       */
#define WIRE_PACKET_SIZE      1024
#define PAYLOAD_SECTION_SIZE  739    /* 1024 - 285   */

#define GCM_NONCE_LEN         12
#define GCM_TAG_LEN           16
#define GCM_OVERHEAD          28     /* 12+16      */

/* Return header block has no blinding key (blinding for the return path
 * is applied separately, see return_blind_key in mix_node.c and
 * service_gateway.c::send_response()). It does carry a per-packet nonce
 * for replay detection, at RETURN_NONCE_BYTES rather than the forward
 * path's NONCE_BYTES(8), kept smaller purely to fit the TYPE_SETUP
 * payload's remaining budget (see MAX_INNER_PAYLOAD below); 4 bytes is
 * still ample given a session's replay cache only ever needs to
 * distinguish among the couple hundred return packets a session
 * realistically sees, nowhere near the ~65536-packet birthday bound for
 * a 32-bit space. */
#define RETURN_NONCE_BYTES    4

/* sender.c's slot pool (send_app_request()/
 * sender_wait_response()) tags TYPE_PUT/TYPE_HEARTBEAT/
 * TYPE_HANDSHAKE_RESPOND requests with this many random bytes,
 * echoed back by service_gateway.c, so a stale response from a
 * timed-out request's PREVIOUS occupant of a slot can never be
 * mistaken for the current occupant's genuine answer. Deliberately
 * small (2 bytes, not e.g. 8): MAX_INNER_PAYLOAD is architecturally
 * fixed (tied to the Sphinx packet size) and TYPE_HANDSHAKE_RESPOND's
 * payload: eph_pubkey + enc(K_content) + a variable-length DER
 * ECDSA signature (up to SIGNATURE_MAX_LEN=80 bytes), already has
 * only single-digit bytes of margin; a bigger nonce measurably
 * increased "payload too large" failures in live testing. This isn't
 * defending against a guessing adversary (the race window it closes
 * is a timing coincidence, not something to brute-force), so 65536
 * values is ample headroom over the actual risk. */
#define SLOT_NONCE_BYTES      2

#define RETURN_BLOCK_SIZE     58     /* 6+4+16+32  */
#define RETURN_HEADER_SIZE    174    /* 3 x 58     */
#define RETURN_PAYLOAD_SIZE   850    /* 1024 - 174 */

/* Payload breakdown:
 *   flags(1) + payload_len(2) = INNER_HDR_BYTES(3)
 *   MNc_pubkey(65) + MNc_IP(6) + return_header(174) = RETURN_HDR_IN_PAYLOAD(245)
 *   GCM overhead(28)
 *   Remaining for app_data = 739 - 3 - 245 - 28 = 463 bytes
 *   (shrunk again, from 475, when RETURN_NONCE_BYTES was added to the
 *   return header block, the TYPE_SETUP payload, the largest single
 *   payload ever sent, is now 454 bytes, leaving 9 bytes of margin.)
 */
#define EC_PUBKEY_LEN         65
#define INNER_HDR_BYTES       3
#define RETURN_HDR_IN_PAYLOAD 245    /* 65+6+174   */
#define MAX_INNER_PAYLOAD     463    /* 739-3-245-28 */

/*, Flags ---------------------------------------------------------------- */
/* No per-hop cover flag: packet_sphinx_build() takes no is_cover
 * parameter, and the outer per-hop wire byte that could carry one is
 * always 0 (see packet.c), a mix node holds the key for that byte, so
 * any such flag there would be readable by a compromised node. PKT_DUMMY
 * below: inside the end-to-end GCM payload, encrypted under e2e_key,
 * which no mix node holds, is the only cover signal, and it's
 * genuinely inaccessible to every mix node on the path. */
#define PKT_REAL              0x00
#define PKT_DUMMY             0x01
#define PKT_DEST_SERVICE      0x00
#define PKT_DEST_PUBLIC       0x02

/*, Per-hop decoy termination (ASN_HOP_DECOY build) -----------------------
 * A per-hop analogue of PKT_DUMMY, deliberately narrower in scope: instead
 * of the end-to-end flag above (real-vs-dummy for the WHOLE packet,
 * resolved only at the SG), this is a per-hop "drop HERE" instruction that
 * lets exactly one hop along a decoy's path terminate it early, chosen
 * once per decoy at build time (client.c/sender.c) and carried in each
 * hop's own enc_flags byte, the same wire field zeroed out above and
 * not otherwise exposed to callers.
 *
 * This is safe against the same class of exposure the flag above closes:
 * HOP_FLAG_FORWARD is written for every hop of every REAL packet, and
 * for every hop of a decoy packet *before* its chosen termination point
 *, so seeing HOP_FLAG_FORWARD tells any hop nothing (indistinguishable
 * from both real traffic and a
 * decoy that simply isn't terminating there). Only HOP_DROP_MARKER, seen
 * only by whichever single hop a given decoy happens to terminate at,
 * carries information, and this is an intentional, unavoidable cost of
 * letting SOME hop legitimately decide to drop a decoy at all (a value no
 * hop is allowed to read is a value no hop can act on). The mitigation is
 * where termination lands, not whether it's ever visible anywhere: caller
 * policy (see HOP_DECOY_MID_WEIGHT_PCT below) concentrates it away from
 * the first/last hop, the entry/exit positions the paper's D1 threat
 * model assumes are the ones actually compromised, so the two nodes
 * that matter most for that specific threat see it least. It is not a
 * general fix against "whichever node ends up compromised": if D1's own
 * assumption about which positions are compromised doesn't hold, this
 * concentration works against the defender instead. Not yet measured
 * against the paper's flow-correlation classifiers. */
#define HOP_FLAG_FORWARD      0x00
#define HOP_DROP_MARKER       0xC3

/* Weighted-random termination hop for a per-hop decoy (client.c/sender.c
 * policy, not mix-node behavior, every mix node runs identical code
 * regardless of these weights). Percent chance of terminating at
 * hop 0 (entry) / hop 1 (middle) / hop 2 (exit) for N_PATH_HOPS==3;
 * must sum to 100. Biased toward the middle hop deliberately, see
 * HOP_DROP_MARKER's comment above for why. */
#define HOP_DECOY_ENTRY_WEIGHT_PCT   10
#define HOP_DECOY_MID_WEIGHT_PCT     80
#define HOP_DECOY_EXIT_WEIGHT_PCT    10

/* Fraction of existing cover-traffic slots (client.c/sender.c's Poisson
 * clock) that build a hop-terminating decoy instead of the normal
 * SG-reaching cover packet. Deliberately NOT an additional, independently
 * clocked stream, an earlier, unrelated attempt at additive cover on its
 * own clock (see g_mailbox's comment in client.c) was measured to make
 * Task C's activity/idle leak WORSE, not better, by breaking the
 * shared-clock bound on aggregate observable rate. Substituting within
 * the existing budget keeps that bound intact. Cost: fewer SG-reaching
 * cover packets means fewer spare return-header deliveries (the mechanism
 * build_outbound_cover_with_spare_return() depends on), a real,
 * deliberate tradeoff, not a bug, sized modestly (30%) for that reason. */
#define HOP_DECOY_FRACTION_PCT       30

/*, Crypto --------------------------------------------------------------- */
#define AES_KEY_LEN           32
#define HMAC_KEY_LEN          32
#define PATH_HOPS             4      /* MN1/MNi, MN2/MNii, MN3/MNiii, SG  */

/*, Timing --------------------------------------------------------------- */
#define DUMMY_INTERVAL_MS     100

/*, Cover-traffic rate tiers ----------------------------------------------
 *
 * A single network-wide rate (DUMMY_INTERVAL_MS above) is brittle: clients
 * on slow links can't sustain it and stand out, but per-client rate
 * configurability is worse, a client-chosen rate is a direct fingerprint
 * (a stable per-session pkt/s value observed at both MN1 and MN3 links
 * without needing any content correlation), so per-client rate
 * configurability is rejected for this reason.
 *
 * Compromise: a small fixed set of NETWORK-WIDE ENUMERATED rates. Every
 * client draws one tier uniformly at random on first run (real entropy,
 * not user input, see client.c/sender.c's rate_tier_init()) and persists
 * it for its identity's lifetime, the same pattern already used for guard
 * sets (node_pool.h's guard_set_load_or_create()). Uniformity of the
 * client's own send rate now only needs to hold *within* its tier's
 * population, not across the whole network, an anonymity-set argument,
 * not an exponent, and it must never be written as one. The tier
 * assignment itself is not user-facing or configurable; only the set of
 * tier values is a compile-time constant. */
#define N_RATE_TIERS          3
#define RATE_TIER_INTERVALS_MS { 60.0, 100.0, 160.0 }
#define CONNECT_TIMEOUT_S     5
#define BACKLOG               1024

/*, Loopix-style mixing delay (ASN_LOOPIX_MIXING build) ------------------ */
/* Independent exponential per-hop forwarding delay at each mix node,
 * matching Loopix's continuous-time mixing model (mean-parametrized,
 * capped). Only active when ASN_LOOPIX_MIXING is defined at build time,
 * see mix_node.c::mix_delay_sleep(). Not a derived constant: worth a
 * sensitivity sweep against Figure 3, not a fixed choice.
 *
 * The claim that a bounded aggregate rate gives a 1/k anonymity set on
 * top of the f² routing-level correlation depends on this build's
 * shared-clock, constant-rate dispatch (client.c/sender.c's g_mailbox
 * mechanism, gated by this same flag). Decision: stays opt-in, NOT
 * promoted to the default build. Two reasons, both concrete, not just
 * caution: (1) this exact mechanism already has one documented history of
 * a first attempt that made the measured leak WORSE, not better, before
 * the corrected design shipped, promoting it to the default path for
 * every build without that same scrutiny repeated would be the single
 * riskiest change available here; (2) doing so would invalidate every
 * plain-mode Table 2/Figure 2/Figure 3/Figure 5/7 measurement already
 * collected, forcing a full re-benchmark for a change that isn't
 * required: the paper can instead state the anonymity-set claim as a
 * hardened-build property, exactly like this mixing-delay's own existing
 * caveats, without needing it to be universal. Revisit only as a
 * deliberate, separately-scoped decision, not a default flip bundled
 * into an unrelated fix. */
#define MIX_DELAY_MEAN_MS     50.0
#define MIX_DELAY_MAX_MS      500.0

/*, Packet types --------------------------------------------------------- */
#define TYPE_SETUP            0x00   /* session setup: send keys to SG      */
#define TYPE_GET              0x01
#define TYPE_PUT              0x02
/* K_session/K_content confidentiality handshake: relayed
 * opaquely through SG to CS, same [type][klen][key][dlen][data] wire
 * framing as GET/PUT above, see cache_server.c's handle_connection()
 * and service_gateway.c's TYPE_HANDSHAKE_INIT/POLL branches. */
#define TYPE_HANDSHAKE_INIT    0x03   /* R: data = r_ephemeral_pub(65)       */
#define TYPE_HANDSHAKE_POLL    0x04   /* R: data empty (dlen=0)              */
#define TYPE_HEARTBEAT         0x05   /* S, relayed via SG like PUT, dlen=0  */
#define TYPE_HANDSHAKE_RESPOND 0x06   /* S, relayed via SG, data = s_pub+enc_k_content */

/*, Session roles (sent in MODE_EXTEND to identify A vs B path) --------- */
#define SESSION_ROLE_A        0x01   /* sending path session (K_R-SG-A)    */
#define SESSION_ROLE_B        0x02   /* receiving path session (K_R-SG-B)  */

/*, Labels --------------------------------------------------------------- */
#define LABEL_HEADER_ENC      "ansn-hdrenc-v1"
#define LABEL_HEADER_MAC      "ansn-hdrmac-v1"
#define LABEL_BLIND_KEY       "ansn-blind-v1"
#define LABEL_BINDING         "binding"
#define LABEL_SG_HINT         "ansn-sghint-v1"
#define LABEL_HINT_SEED       "ansn-hintseed-v1"

/*, Forward-path rotating per-hop hint --------------
 *
 * Each hop's `hint` field is HMAC(hint_seed, packet_counter), see
 * packet_derive_hint_seed()/packet_derive_hop_hint(), a fresh-looking
 * 32 bytes on every packet, rather than a session-constant value a
 * passive observer could use to group a session's packets together.
 *
 * A mix node can't index sessions by a single stored hint value, since
 * the value to match changes every packet. Instead each session stores
 * a HINT_WINDOW-sized forward-looking window of precomputed hint values
 * (hint_seed's next HINT_WINDOW counters), matching a packet slides
 * the window forward past whatever counter matched (see mix_node.c's
 * session_advance_hint_window()). This keeps the lookup a bounded
 * number of cheap memcmp's per session, at the cost of a bounded
 * tolerance for out-of-order arrival: a packet numbered more than
 * HINT_WINDOW behind the highest counter already matched for its
 * session is dropped, the same class of bounded-window tradeoff this
 * codebase accepts for REPLAY_WINDOW (mix_node.c).
 *
 * Real and cover packets use disjoint counter domains (see
 * HINT_COVER_COUNTER_BASE below), each session tracking two independent
 * windows (mix_node.c's session_entry_t hint_base[2]/hint_window[2][...]),
 * so a hop that sees a long run of one type doesn't have its other
 * domain's window disturbed.
 *
 * Scope: forward-path hint only. The return-path header's own per-hop
 * `hint` (return_block_t.hint, built once by packet_build_return_header()
 * and reused unchanged for the session's whole lifetime) has the same
 * underlying session-constant exposure and isn't covered by this
 * mechanism: a disclosed, separate residual.
 *
 * 64 (raised from 16 for ASN_POOL_MIXING): pool-mixing's batch-scale
 * reordering needs a wider tolerance than a single client process's
 * own serialized send timing does. Costs 3KB more per session
 * (hint_window[2][64][32] vs [2][16][32]), negligible at this
 * project's session-count scale. See HINT_SAFETY_MARGIN below for the
 * complementary fix to the reordering itself. */
#define HINT_WINDOW           64

/* session_advance_hint_window() (mix_node.c) tracks the highest counter
 * position ever matched (session_entry_t.hint_high_water) and only
 * advances hint_base far enough to stay HINT_SAFETY_MARGIN behind it,
 * never past a position that might still be in flight behind a later
 * packet that arrived and matched first, which pool-mixing's batching
 * does routinely. 32 is half of HINT_WINDOW=64, leaving the other half
 * for genuine forward lookahead as new counters are needed. */
#define HINT_SAFETY_MARGIN     32

/* Cover-domain counter values are offset into their own numeric range,
 * disjoint from the real-domain range (0..), so a real packet's counter
 * and a cover packet's counter can never collide on the same value for
 * the same session/hop (which would otherwise alias their HMAC outputs).
 * 2^62 leaves both domains room for far more packets than any session
 * (or this codebase's 32-bit InterlockedIncrement-based counters, which
 * wrap at 2^32) will ever produce. */
#define HINT_COVER_COUNTER_BASE ((uint64_t)1 << 62)

/*, SG-side O(1) session hint -----------------------
 *
 * A session-constant value HMAC-derived from K_R-SG-A/K_S-SG-A (the same
 * shared ECDH master client/sender and SG already independently hold after
 * the MODE_EXTEND handshake, see packet_derive_sg_hint()), embedded in
 * the last SG_HINT_BYTES of every MODE_DATA packet's payload section. It
 * lets find_a_session() filter role-A sessions by a cheap memcmp before
 * attempting the expensive AES-GCM trial-decrypt, instead of trial-
 * decrypting every in-use role-A session on every packet, the same
 * "cheap comparison before expensive crypto" pattern mix_node.c's
 * session_find() already uses for its own per-hop hint, just one hop
 * further out. Reuses MAC_BYTES's width so packet_hmac()'s existing
 * 16-byte output can be used directly with no new crypto primitive.
 *
 * No wire-packet growth: it is written into bytes that are always
 * zero-padding today (max ciphertext = INNER_HDR_BYTES + MAX_INNER_PAYLOAD
 * + GCM_OVERHEAD = 494 bytes of a PAYLOAD_SECTION_SIZE=739 buffer, so the
 * hint lives at [739-16, 739), 227 bytes clear of the ciphertext's worst
 * case), MAX_INNER_PAYLOAD is unchanged, so this does not affect
 * WIRE_PACKET_SIZE, Table 2 throughput, or Figure 2/3 timing.
 *
 * Security note: like the per-hop `hint` field, this value is
 * session-constant and, once fully unblinded by the last mix hop,
 * travels in the clear on the final mix-hop-to-SG link, a disclosed
 * fixed-vantage flow identifier on that one link. It cannot be used to
 * decrypt or forge anything: matching a
 * session's hint only selects which session's key to *attempt* GCM
 * decryption with; the GCM tag remains the actual authentication
 * boundary. */
#define SG_HINT_BYTES         MAC_BYTES

#endif /* CONFIG_H */
