/* client.c: User / Receiver  (Anon-Sec-Net v2)
 *
 * Outbound packet payload (enc_K_R-SG-A):
 *   [flags(1)][payload_len(2)]
 *   [MNc_pubkey(65)][MNc_IP:port(6)]
 *   [return_header(174)]     <- enc_SK_R-MNc(MNb + enc_SK_R-MNb(MNa + enc_SK_R-MNa(Client)))
 *   [app_data(variable)]     <- TYPE_GET/PUT + key + content
 *
 * Return packet received from MNa (enc_K_R-SG-B):
 *   [return_header(174)]     <- shifted down as MNc/MNb/MNa peel
 *   [enc_K_R-SG-B(response)]
 */

#include "common/net.h"
#include "common/crypto.h"
#include "common/packet.h"
#include "common/config.h"
#include "common/node_pool.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common/posix_compat.h"
#include <math.h>
#include <ctype.h>
#include <openssl/rand.h>

/* Node-pool selection state (Task 1: guard-set entry + weighted
 * middle/last hops, replacing the fixed PORT_MIX_* topology) */
static consensus_t g_consensus;
static guard_set_t g_guard_a, g_guard_b;
static uint64_t    g_path_rng;


/* Session state */

typedef struct {
    /* Sending path A: Client -> MN1 -> MN2 -> MN3 -> SG */
    sphinx_path_t send_path;
    aes_key_t     k_r_sg_a;       /* end-to-end key, path A               */

    /* Receiving path B: SG -> MNc -> MNb -> MNa -> Client */
    /* Per-hop sessions for MNc, MNb, MNa (used to build return header)   */
    hop_session_t recv_hops[N_PATH_HOPS]; /* [0]=MNc [1]=MNb [2]=MNa     */
    aes_key_t     k_r_sg_b;       /* end-to-end key, path B               */

    /* MNc info embedded in every outbound payload */
    uint8_t  mnc_pubkey[EC_PUBKEY_LEN];
    uint8_t  mnc_addr[ADDR_BYTES]; /* MNc IP:port                         */

    /* Return header, rebuilt fresh before every request, not just once
     * per session (see build_fresh_return_header()):
     * packet_build_return_header() generates a fresh RAND_bytes nonce
     * per block internally, but that's only useful if it's actually
     * called again for each request rather than reused verbatim, or
     * every response after the first in a session would look like a
     * replay of the first to the outermost return-path hop. */
    return_header_t return_hdr;
    /* Static per-session inputs to the rebuild above (only the nonces
     * inside return_hdr change per request; addrs/keys/hints do not),
     * stored once here so build_fresh_return_header() does not need
     * recv_ports (a build_paths()-local) passed back in. */
    uint8_t  return_addrs[N_PATH_HOPS][ADDR_BYTES];

    /* Client response address (embedded in return header innermost layer) */
    uint8_t  client_addr[ADDR_BYTES];

    int ready;
} client_state_t;

static client_state_t g_state = {0};

/* Parallel striping (research option, off by default). With
 * ASN_STRIPE_LEGS=k (2..MAX_STRIPE_LEGS) the client builds k sending paths
 * to the SG. Each extra leg enters through a different guard of guard set
 * A, uses middle and last hops disjoint from every node already in use,
 * and is bound to the same receiving path B, so the SG plays the role of
 * the common exit. Each real packet goes out on one leg chosen by
 * ASN_STRIPE_POLICY, with the same policies as AnonTestLab's
 * emulator/splitting.py:
 *   iid          leg i with probability w_i (ASN_STRIPE_WEIGHTS="0.8,0.2";
 *                equal weights by default)
 *   round_robin  legs in turn; smooth weighted round-robin with weights
 *   batch        exponential batches, mean ASN_STRIPE_BATCH_MS (default
 *                2000); every packet in a batch uses one leg drawn by weight
 *   latency      lowest-RTT leg with fewer than ASN_STRIPE_WINDOW (default
 *                8) packets sent within its last RTT; otherwise the leg with
 *                the lowest share of its window. RTTs from
 *                ASN_STRIPE_RTT_MS="50,100", or else the probed entry
 *                connect time.
 * Leg 0 is the ordinary path A (g_state.send_path). Each leg is its own
 * session at its hops and keeps its own packet counter, so one leg's
 * packets never leave gaps in another leg's hint window. Cover traffic
 * stays on leg 0, and ASN_COVER_OFF=1 disables it. ASN_STRIPE_LOG names a
 * CSV that receives one row per real packet: t_ms,leg,entry_port (same
 * monotonic clock as the mix-node trace probe). The ASN_LOOPIX_MIXING
 * mailbox drains on leg 0 only, so striping is refused in that build. */
#define MAX_STRIPE_LEGS    GUARD_SET_SIZE
#define STRIPE_RECENT_MAX  256

enum { STRIPE_IID, STRIPE_ROUND_ROBIN, STRIPE_BATCH, STRIPE_LATENCY };

typedef struct {
    sphinx_path_t *path;
    aes_key_t     *k_r_sg_a;
    volatile LONG  counter;      /* legs >= 1; leg 0 uses g_send_pkt_counter */
    double         weight;
    double         credit;
    double         rtt_ms;
    uint64_t       recent[STRIPE_RECENT_MAX]; /* send times within the last RTT */
    int            recent_head, recent_n;
} stripe_leg_t;

static sphinx_path_t g_extra_paths[MAX_STRIPE_LEGS];
static aes_key_t     g_extra_keys[MAX_STRIPE_LEGS];
static stripe_leg_t  g_legs[MAX_STRIPE_LEGS];
static int      g_n_legs = 1;
static int      g_stripe_policy = STRIPE_IID;
static int      g_stripe_equal_weights = 1;
static int      g_rr_next = 0;
static double   g_batch_mean_ms = 2000.0;
static uint64_t g_batch_end_ms = 0;
static int      g_batch_leg = 0;
static int      g_batch_open = 0;
static int      g_stripe_window = 8;
static int      g_stripe_rtt_from_env = 0;
static FILE    *g_stripe_log = NULL;

/* Per-session forward-path packet counter for real traffic
 * (packet_sphinx_build() call sites only), draws the next value
 * atomically, so two threads (outbound_cover_thread vs the
 * main/interactive thread) never hand out the same counter twice.
 * Starts at 0 to match mix_node.c's session_advance_hint_window()
 * initializing each session's real-domain window from counter 0.
 *
 * Cover packets (packet_sphinx_dummy() call sites) draw from a
 * separate counter (g_send_cover_pkt_counter below), in its own
 * disjoint numeric domain (config.h's HINT_COVER_COUNTER_BASE),
 * mix_node.c tracks the two domains' windows independently per
 * session, so a hop that sees a long run of one type doesn't desync
 * its window for the other. */
static volatile LONG g_send_pkt_counter = 0;
static uint64_t next_send_pkt_counter(void) {
    return (uint64_t)(InterlockedIncrement(&g_send_pkt_counter) - 1);
}

/* Separate counter for cover (dummy) packets, offset into its own
 * domain so it can never collide with a real packet's counter value
 * for the same session/hop. */
static volatile LONG g_send_cover_pkt_counter = 0;
static uint64_t next_cover_pkt_counter(void) {
    return HINT_COVER_COUNTER_BASE +
           (uint64_t)(InterlockedIncrement(&g_send_cover_pkt_counter) - 1);
}

/* Counter for the return-path hint, one value per
 * build_fresh_return_header() call (i.e. per request), shared across
 * all N_PATH_HOPS return blocks in that call the same way a single
 * forward pkt_counter is shared across all forward hops for one
 * packet. No cover-domain split needed here: the return path has no
 * hint-matched cover traffic, inbound cover is raw bytes injected
 * locally at the last return hop, never looked up by hint, so
 * there's nothing for a real request's counter to be desynced from. */
static volatile LONG g_return_pkt_counter = 0;
static uint64_t next_return_pkt_counter(void) {
    return (uint64_t)(InterlockedIncrement(&g_return_pkt_counter) - 1);
}

/* Response synchronisation */
static uint8_t          g_resp_buf[WIRE_PACKET_SIZE];
static volatile int     g_resp_ready = 0;
static CRITICAL_SECTION g_resp_lock;
static HANDLE           g_resp_event;

static void log_msg(const char *m) { printf("[Client] %s\n", m); fflush(stdout); }
static void log_err(const char *m) { fprintf(stderr,"[Client] ERROR: %s\n",m); fflush(stderr); }


/* v17 calibration instrumentation. Disabled unless ASN_V17_CALIB_CSV is set. */
static FILE *g_v17_cal = NULL;
static unsigned long g_v17_exchange_id = 0;
static double v17_now_s(void) {
    LARGE_INTEGER c, f;
    QueryPerformanceCounter(&c); QueryPerformanceFrequency(&f);
    return (double)c.QuadPart / (double)f.QuadPart;
}
static void v17_cal_open(void) {
    const char *path = getenv("ASN_V17_CALIB_CSV");
    if (!path || !*path) return;
    g_v17_cal = fopen(path, "w");
    if (g_v17_cal) {
        fprintf(g_v17_cal, "exchange_id,start_s,end_s,response_time_s,response_wire_bytes\n");
        fflush(g_v17_cal);
    }
}
static void v17_cal_log(double start_s, double end_s, unsigned response_bytes) {
    if (!g_v17_cal) return;
    fprintf(g_v17_cal, "%lu,%.9f,%.9f,%.9f,%u\n",
            g_v17_exchange_id++, start_s, end_s, end_s-start_s, response_bytes);
    fflush(g_v17_cal);
}

/* Forward declarations, defined later in this file, but needed by
 * perform_content_handshake() (K_session/K_content finding) above
 * their definitions. */
static int send_app_request(uint8_t type, const char *key,
                             const uint8_t *data, size_t data_len,
                             const char *log_label);
static int wait_response(uint8_t *out, uint16_t *out_len, DWORD timeout_ms);

/* Trust-on-first-use pubkey pin directory, relative
 * to cwd, alongside the guard-set files (client_guard_a.txt etc). Detects
 * an active MITM substituting its key on any connection after the first;
 * does not protect the very first connection (no pre-shared root of
 * trust in this prototype's synthetic consensus, see crypto.h's
 * crypto_pubkey_pin_check() comment for the full scope/limits). */
#define PIN_DIR "client_pins"

/* Reads a signed node descriptor off `s`: [65B ephemeral pubkey][65B
 * identity pubkey][1B sig_len][sig_len bytes signature], verifies the
 * signature covers the ephemeral pubkey under the claimed identity key,
 * then pins the IDENTITY key (not the ephemeral one) via
 * crypto_pubkey_pin_check(). Pinning the identity
 * key instead of the ephemeral one means the pin survives the node's own
 * restarts (identity keys are load-or-create, ephemeral keys are fresh
 * every process start, see crypto.h), so a legitimate restart is no
 * longer indistinguishable from a MITM to the pinning check. Returns 0
 * and writes the verified ephemeral pubkey to out_node_pub, or -1 on any
 * read/verify/pin failure, never falls back to trusting an unverified
 * key. */
static int recv_signed_descriptor(SOCKET s, uint16_t port,
                                   uint8_t out_node_pub[EC_PUBKEY_LEN]) {
    uint8_t identity_pub[EC_PUBKEY_LEN];
    uint8_t sig_len_byte;
    uint8_t sig[SIGNATURE_MAX_LEN];

    /* Reply is one padded frame now (see net_send_padded_frame's comment
     * in common/net.c): [node_pub(65)][identity_pub(65)][sig_len(1)][sig]. */
    uint8_t reply_buf[EC_PUBKEY_LEN + EC_PUBKEY_LEN + 1 + SIGNATURE_MAX_LEN];
    size_t  reply_len = 0;
    if (net_recv_padded_frame(s, reply_buf, &reply_len, sizeof(reply_buf)) != 0) return -1;
    if (reply_len < EC_PUBKEY_LEN + EC_PUBKEY_LEN + 1) return -1;
    size_t off = 0;
    memcpy(out_node_pub, reply_buf + off, EC_PUBKEY_LEN); off += EC_PUBKEY_LEN;
    memcpy(identity_pub, reply_buf + off, EC_PUBKEY_LEN); off += EC_PUBKEY_LEN;
    sig_len_byte = reply_buf[off++];
    if (sig_len_byte == 0 || sig_len_byte > SIGNATURE_MAX_LEN) return -1;
    if (off + sig_len_byte > reply_len) return -1;
    memcpy(sig, reply_buf + off, sig_len_byte);

    if (crypto_verify(identity_pub, out_node_pub, EC_PUBKEY_LEN,
                       sig, sig_len_byte) != 0) {
        fprintf(stderr,
                "[client] descriptor signature verification FAILED for "
                "port %u, rejecting (this is what a MITM presenting a "
                "self-signed but unpinned key looks like, or a node bug)\n",
                (unsigned)port);
        return -1;
    }
    return crypto_pubkey_pin_check(port, identity_pub, PIN_DIR);
}

/* TOFU-pin a content-key's Sender identity key, mirroring
 * recv_signed_descriptor()/crypto_pubkey_pin_check()'s pattern above
 * (same first-connection-trust caveat, see that function's comment)
 * but keyed by the content KEY STRING rather than a port number, since
 * content keys aren't ports. A separate hand-rolled pin here (not a
 * reuse of crypto_pubkey_pin_check()'s uint16_t-port signature)
 * specifically to avoid hashing an arbitrary string key down to 16 bits
 * for a security-relevant pin file, a collision there would let two
 * different content keys share a pin and silently cross-trust each
 * other's Sender identity. Returns 0 if the key matches the pin (or
 * was freshly pinned), -1 on mismatch or I/O failure, never falls back
 * to trusting an unpinned/mismatched key. */
#define SENDER_PIN_DIR "sender_pins"

/* Shared by pin_sender_key() and load_existing_sender_pin(), sanitizes
 * the untrusted content-key string into a safe filename component
 * (rules out path traversal via e.g. "../../etc/passwd" as a content
 * key) and builds the pin file path. */
static void sender_pin_path(const char *content_key, char *path, size_t path_size) {
    char safe[128];
    size_t i = 0;
    for (; content_key[i] != '\0' && i < sizeof(safe) - 1; i++) {
        char c = content_key[i];
        safe[i] = (isalnum((unsigned char)c) || c == '-' || c == '_') ? c : '_';
    }
    safe[i] = '\0';
    snprintf(path, path_size, "%s/pinned_%s.pub", SENDER_PIN_DIR, safe);
}

/* Read-only lookup, no mkdir/save/mismatch
 * side effects, used by perform_content_handshake() to check whether
 * a pin ALREADY exists for this content-key BEFORE the handshake
 * response is even parsed, so a signature over it can be checked
 * against a real prior identity when one exists. Returns 0 and fills
 * out_pub if a pin exists, -1 if none does (not an error, just means
 * this is the first-ever retrieval for this key, TOFU applies same as
 * content signing itself). */
static int load_existing_sender_pin(const char *content_key, uint8_t out_pub[EC_PUBKEY_LEN]) {
    char path[512];
    sender_pin_path(content_key, path, sizeof(path));
    return crypto_pubkey_load(out_pub, path);
}

static int pin_sender_key(const char *content_key, const uint8_t pubkey[EC_PUBKEY_LEN]) {
    if (mkdir(SENDER_PIN_DIR, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "[client] mkdir(%s) failed: %s\n", SENDER_PIN_DIR, strerror(errno));
    }

    char path[512];
    sender_pin_path(content_key, path, sizeof(path));

    uint8_t existing[EC_PUBKEY_LEN];
    if (crypto_pubkey_load(existing, path) == 0) {
        if (crypto_memcmp(existing, pubkey, EC_PUBKEY_LEN) != 0) {
            fprintf(stderr,
                    "[client] SENDER PIN MISMATCH for key '%s', the signing "
                    "identity differs from the one pinned on first retrieval. "
                    "Rejecting: this is what a different (possibly malicious) "
                    "Sender or a substituted identity looks like. Delete %s to "
                    "re-pin if the Sender's identity legitimately changed.\n",
                    content_key, path);
            return -1;
        }
        return 0;
    }

    /* No existing pin, trust-on-first-use. */
    ecdh_keypair_t tmp = {0};
    memcpy(tmp.pubkey_bytes, pubkey, EC_PUBKEY_LEN);
    if (crypto_pubkey_save(&tmp, path) != 0) {
        fprintf(stderr, "[client] failed to save sender pin to %s\n", path);
        return -1;
    }
    return 0;
}

/* Parses the signed-content wire format sender.c's
 * upload_content() builds,
 *   [sender_pubkey(65)][sig_len(1)][sig(sig_len)][ciphertext(remaining)]
 *, pins the Sender's identity key per content-key (pin_sender_key()
 * above), decrypts the ciphertext under the K_content just negotiated
 * via perform_content_handshake() below, verifies the signature over
 * the RECOVERED PLAINTEXT (matching sender.c's signing order, it
 * signs before encrypting), and only then treats the content as
 * authentic. `raw`/`raw_len` is whatever wait_response() returned for
 * a GET; `plain_out`/`plain_out_size` is caller-owned scratch space for
 * the decrypted plaintext (decryption can't be done in place into
 * `raw`, since ciphertext and plaintext lengths differ by
 * GCM_OVERHEAD); `out_content`/`out_content_len` receive a pointer into
 * `plain_out` (no further copy) plus the verified content's length.
 * Returns 0 and fills out_content/out_content_len on success, -1 on any
 * parse/pin/decrypt/signature failure, callers MUST NOT display `raw`
 * or `plain_out` as if it were valid content on a -1 return; that is
 * precisely the silent-tampering gap this closes. */
static int verify_signed_content(const char *content_key,
                                  const uint8_t *raw, size_t raw_len,
                                  const aes_key_t *k_content,
                                  uint8_t *plain_out, size_t plain_out_size,
                                  const uint8_t **out_content, size_t *out_content_len) {
    if (raw_len < EC_PUBKEY_LEN + 1) {
        log_err("signed-content response too short to contain a signature"); return -1;
    }
    size_t off = 0;
    const uint8_t *sender_pub = raw + off; off += EC_PUBKEY_LEN;
    uint8_t sig_len = raw[off++];
    if (sig_len == 0 || sig_len > SIGNATURE_MAX_LEN || off + sig_len > raw_len) {
        log_err("signed-content response has an invalid signature length"); return -1;
    }
    const uint8_t *sig = raw + off; off += sig_len;
    const uint8_t *ciphertext = raw + off;
    size_t ciphertext_len = raw_len - off;

    if (pin_sender_key(content_key, sender_pub) != 0) {
        return -1; /* pin_sender_key() already logged the specific reason */
    }

    int n = crypto_aes_decrypt(k_content, ciphertext, ciphertext_len,
                               plain_out, plain_out_size);
    if (n < 0) {
        fprintf(stderr,
                "[client] CONTENT DECRYPTION FAILED for key '%s', ciphertext "
                "does not authenticate under the K_content just negotiated with "
                "the Sender. Rejecting: treat this exactly like a tampering "
                "detection (a compromised Cache Server or Service Gateway "
                "substituting different ciphertext looks exactly like this).\n",
                content_key);
        return -1;
    }

    if (crypto_verify(sender_pub, plain_out, (size_t)n, sig, sig_len) != 0) {
        fprintf(stderr,
                "[client] CONTENT TAMPERING DETECTED for key '%s', signature "
                "does not verify under the pinned Sender identity. Rejecting: "
                "the content was altered somewhere between the Sender and here "
                "(a compromised Cache Server or Service Gateway looks exactly "
                "like this).\n", content_key);
        return -1;
    }
    *out_content = plain_out;
    *out_content_len = (size_t)n;
    return 0;
}

/* Live, per-request ECDHE handshake with an online Sender, relayed
 * opaquely through SG/CS (neither ever derives the shared secret, see
 * cache_server.c/service_gateway.c's TYPE_HANDSHAKE_* relay branches
 * and sender.c's heartbeat_thread()).
 * Returns 0 and fills *out_k_content on success; -1 on timeout/failure
 * (most likely explanation: no Sender is currently online servicing
 * this key, distinct from "key doesn't exist", which only the
 * subsequent GET can determine). */
#define HANDSHAKE_POLL_MAX_TRIES   20
#define HANDSHAKE_POLL_INTERVAL_MS 500
static int perform_content_handshake(const char *key, aes_key_t *out_k_content) {
    ecdh_keypair_t eph = {0};
    if (crypto_ecdh_keygen(&eph) != 0) {
        log_err("ephemeral keygen failed"); return -1;
    }

    /* Use a per-request WIRE key (content key + "#" + a nonce suffix)
     * for INIT/POLL instead of the bare content key, so two Receivers
     * racing a handshake for the same content land in different Cache
     * Server pending-table slots by construction, see cache_server.c's
     * pending_handshake_t struct comment. Suffix bytes come from the
     * ephemeral pubkey's X
     * coordinate (pubkey_bytes[1..2], byte 0 is the constant 0x04
     * uncompressed-point tag and carries no entropy), which is already
     * fresh and effectively random per call; sender.c's heartbeat_thread()
     * strips the suffix back off before its own content-key lookup and
     * echoes the full wire key back on RESPOND. */
    char wire_key[64 + 6]; /* content key (<=63, send_app_request's own cap) + "#" + 4 hex digits */
    if (snprintf(wire_key, sizeof(wire_key), "%s#%02x%02x", key,
                 eph.pubkey_bytes[1], eph.pubkey_bytes[2]) >= (int)sizeof(wire_key)) {
        log_err("key too long for handshake"); crypto_ecdh_free(&eph); return -1;
    }

    if (send_app_request(TYPE_HANDSHAKE_INIT, wire_key, eph.pubkey_bytes, EC_PUBKEY_LEN,
                         "HANDSHAKE_INIT") != 0) {
        crypto_ecdh_free(&eph); return -1;
    }
    uint8_t  ack[MAX_INNER_PAYLOAD]; uint16_t ack_len = 0;
    if (wait_response(ack, &ack_len, 5000) != 0 || ack_len < 1 || ack[0] != 0x01) {
        log_err("handshake init rejected by Cache Server");
        crypto_ecdh_free(&eph); return -1;
    }

    for (int tries = 0; tries < HANDSHAKE_POLL_MAX_TRIES; tries++) {
        Sleep(HANDSHAKE_POLL_INTERVAL_MS);

        if (send_app_request(TYPE_HANDSHAKE_POLL, wire_key, NULL, 0, "HANDSHAKE_POLL") != 0) {
            crypto_ecdh_free(&eph); return -1;
        }
        uint8_t  poll_resp[MAX_INNER_PAYLOAD]; uint16_t poll_len = 0;
        if (wait_response(poll_resp, &poll_len, 5000) != 0 || poll_len < 1) {
            continue; /* transient, keep polling */
        }
        if (poll_resp[0] == 0x00) continue; /* not ready yet */

        if (poll_len < 1 + EC_PUBKEY_LEN + 2) {
            log_err("malformed handshake-poll ready response");
            crypto_ecdh_free(&eph); return -1;
        }
        size_t off = 1;
        const uint8_t *s_pub = poll_resp + off; off += EC_PUBKEY_LEN;
        uint16_t enc_len = (uint16_t)((poll_resp[off] << 8) | poll_resp[off + 1]); off += 2;
        if (off + enc_len > poll_len) {
            log_err("malformed handshake-poll enc_k_content length");
            crypto_ecdh_free(&eph); return -1;
        }

        /* Parse and, if we already hold a
         * pin for this key, verify the identity signature over
         * s_pub||enc_len||enc_k_content (the exact bytes at
         * poll_resp[1..sig_off)) that sender.c now appends, see that
         * file's matching comment. Rejects a spoofed
         * TYPE_HANDSHAKE_RESPOND outright for any key retrieved
         * before; a brand-new key's first-ever retrieval is still
         * TOFU-exposed here, matching content signing's own
         * already-accepted limitation (the later GET response's
         * signature check still protects content integrity even in
         * that case). */
        size_t sig_off = off + enc_len;
        if (sig_off + 1 > poll_len) {
            log_err("malformed handshake-respond: missing signature");
            crypto_ecdh_free(&eph); return -1;
        }
        uint8_t resp_sig_len = poll_resp[sig_off++];
        if (resp_sig_len == 0 || resp_sig_len > SIGNATURE_MAX_LEN ||
            sig_off + resp_sig_len > poll_len) {
            log_err("malformed handshake-respond: invalid signature length");
            crypto_ecdh_free(&eph); return -1;
        }
        const uint8_t *resp_sig = poll_resp + sig_off;

        uint8_t existing_pub[EC_PUBKEY_LEN];
        if (load_existing_sender_pin(key, existing_pub) == 0) {
            size_t signed_len = off + enc_len - 1; /* poll_resp[1] .. sig_off-1-resp_sig_len */
            if (crypto_verify(existing_pub, poll_resp + 1, signed_len,
                              resp_sig, resp_sig_len) != 0) {
                fprintf(stderr,
                        "[client] HANDSHAKE RESPONSE FORGERY DETECTED for key '%s', "
                        "signature does not verify under the pinned Sender identity. "
                        "Rejecting: this is what a spoofed TYPE_HANDSHAKE_RESPOND "
                        "(K_content poisoning) looks like.\n", key);
                crypto_ecdh_free(&eph); return -1;
            }
        }

        aes_key_t k_session;
        if (crypto_ecdh_derive(&eph, s_pub, &k_session) != 0) {
            log_err("K_session derivation failed");
            crypto_ecdh_free(&eph); return -1;
        }
        crypto_ecdh_free(&eph);

        uint8_t k_content_buf[AES_KEY_LEN + GCM_OVERHEAD];
        int n = crypto_aes_decrypt(&k_session, poll_resp + off, enc_len,
                                   k_content_buf, sizeof(k_content_buf));
        if (n != AES_KEY_LEN) {
            log_err("K_content decryption failed, possible tampering in transit");
            return -1;
        }
        memcpy(out_k_content->key, k_content_buf, AES_KEY_LEN);
        return 0;
    }

    crypto_ecdh_free(&eph);
    log_err("handshake poll timed out, Sender may be offline or never uploaded this key");
    return -1;
}

/* Telescoped ECDHE through an entry node
 *
 * Opens exactly ONE connection, to ports[0] (the entry/guard). Every
 * subsequent hop's ECDH handshake is relayed through the previous hops
 * rather than connected to directly, using mix_node.c's existing
 * MODE_EXTEND relay mechanism (tport != 0 -> relay one more length-
 * prefixed frame, then become a blind bidirectional pipe for anything
 * deeper: see mix_node.c::proxy_bidirectional()). The result: only
 * ports[0] ever sees a live connection carrying the client's real IP;
 * ports[1..n-1] each only see a connection FROM the previous hop.
 *
 * Only ports[0] ever sees the client's real IP; every real network
 * deployment (not just this loopback prototype) benefits from that.
 *
 * build_paths() below also appends the SG itself as one more
 * telescoped target at the END of each ports[] array (the mix hops
 * relay the client's ECDH handshake with the SG one hop further,
 * rather than the client dialing the SG directly), this function
 * doesn't need to know or care that the final "hop" happens to be the
 * SG rather than another mix node; service_gateway.c's MODE_EXTEND
 * handler speaks the identical relay-target wire protocol mix_node.c's
 * does (same signed-descriptor reply shape). No code path opens a
 * direct client->SG connection; every ECDH handshake this binary
 * performs is relayed through at least one mix hop. */
static int ecdhe_telescoped_path(const uint16_t *ports, int n_hops,
                                  uint8_t role,
                                  aes_key_t masters[],
                                  uint8_t (*hints)[HINT_BYTES],
                                  uint8_t (*node_pubs)[EC_PUBKEY_LEN]) {
    SOCKET s = net_connect(LOCALHOST, ports[0]);
    if (s == INVALID_SOCKET) return -1;

    int ok = -1;
    for (int i = 0; i < n_hops; i++) {
        ecdh_keypair_t kp = {0};
        if (crypto_ecdh_keygen(&kp) != 0) goto done;
        memcpy(hints[i], kp.pubkey_bytes + 1, HINT_BYTES);

        uint16_t next_port = (i + 1 < n_hops) ? ports[i + 1] : 0;
        uint8_t  tport[2] = { (uint8_t)(next_port >> 8),
                               (uint8_t)(next_port & 0xFF) };

        /* [role(1)][tport(2)][pubkey(65)], sent as one padded frame (see
         * net_send_padded_frame's comment in common/net.c) either way,
         * hop 0 sends it directly after the MODE_EXTEND dispatch byte;
         * hops 1+ send the identical frame shape over the same
         * already-open connection, relayed opaquely by every hop in
         * between (mix_node.c's handle_extend() no longer needs to
         * parse a separate length prefix for it, since a padded frame
         * is always exactly WIRE_PACKET_SIZE). */
        uint8_t req_buf[1 + 2 + EC_PUBKEY_LEN];
        req_buf[0] = role;
        req_buf[1] = tport[0];
        req_buf[2] = tport[1];
        memcpy(req_buf + 3, kp.pubkey_bytes, EC_PUBKEY_LEN);

        if (i == 0) {
            uint8_t mode = MODE_EXTEND;
            net_send_all(s, &mode, 1);
            net_send_padded_frame(s, req_buf, sizeof(req_buf));
        } else {
            net_send_padded_frame(s, req_buf, sizeof(req_buf));
        }

        if (recv_signed_descriptor(s, ports[i], node_pubs[i]) != 0) {
            crypto_ecdh_free(&kp); goto done;
        }
        /* See crypto_ecdh_derive_bound()'s
         * comment in crypto.h, client_pub/node_pub/port/role must match
         * exactly what the node side (mix_node.c/service_gateway.c
         * handle_extend()) binds. */
        int rc = crypto_ecdh_derive_bound(&kp, node_pubs[i],
                                          kp.pubkey_bytes, node_pubs[i],
                                          ports[i], role, &masters[i]);
        crypto_ecdh_free(&kp);
        if (rc != 0) goto done;
    }
    ok = 0;
done:
    net_close(s);
    return ok;
}

/* Derive hop_session_t from ECDHE master.
 *
 * Must match mix_node.c::split_master_keys() exactly (both call the same
 * packet_derive_hop_keys() KDF on the same shared master), or every MAC
 * the mix node checks on our packets will fail.
 */
static void derive_hop(const aes_key_t *master, hop_session_t *hop) {
    packet_derive_hop_keys(master, &hop->header_enc_key,
                            &hop->header_mac_key, &hop->blind_key);
    /* Rotating-hint seed, used by both send_path's
     * hops (MODE_DATA hint, see packet_sphinx_build()) and recv_hops
     * (return-path hint, see build_fresh_return_header()). */
    if (packet_derive_hint_seed(master, &hop->hint_seed) != 0) {
        log_err("hint_seed derivation failed");
    }
}

/* Build IP:port addr bytes */
static void make_addr_bytes(const char *ip, uint16_t port,
                             uint8_t out[ADDR_BYTES]) {
    /* Parse dotted-decimal IP */
    unsigned a, b, c, d;
    sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d);
    out[0] = (uint8_t)a; out[1] = (uint8_t)b;
    out[2] = (uint8_t)c; out[3] = (uint8_t)d;
    out[4] = (uint8_t)(port >> 8);
    out[5] = (uint8_t)(port & 0xFF);
}

static int node_pool_init(void) {
    consensus_generate(&g_consensus);
    node_pool_seed_from_urandom(&g_path_rng);

    if (guard_set_load_or_create(&g_guard_a, &g_consensus, "client_guard_a.txt",
                                  GUARD_SET_SIZE, NULL, 0, &g_path_rng) != 0) {
        log_err("failed to load/create guard set A"); return -1;
    }
    if (guard_set_load_or_create(&g_guard_b, &g_consensus, "client_guard_b.txt",
                                  GUARD_SET_SIZE,
                                  g_guard_a.guard_ids, g_guard_a.count,
                                  &g_path_rng) != 0) {
        log_err("failed to load/create guard set B"); return -1;
    }
    return 0;
}

/* Rebuilds g_state.return_hdr with fresh per-block nonces and a fresh
 * per-block hint. addrs/keys are static for the session
 * (g_state.return_addrs / g_state.recv_hops), so only the nonces
 * (generated internally by packet_build_return_header()) and the hints
 * (derived fresh here, one shared counter value per call across all
 * N_PATH_HOPS blocks, same as a forward packet's single pkt_counter
 * shared across its hops) change between calls, must be invoked
 * before every send_get()/send_setup()/upload_content()-equivalent
 * send, not just once at session start. The return hint rotates via
 * HMAC(hint_seed, counter) rather than a session-constant value, same
 * property as the forward-path hint but simpler here: one counter, one
 * domain (see next_return_pkt_counter()'s comment for why no
 * cover-domain split is needed on this leg). */
/* Shared by build_fresh_return_header() (writes into g_state.return_hdr,
 * for the next real request) and build_spare_return_header() below
 * (writes into a caller-supplied buffer, for return-path cover). Same
 * per-hop enc/mac keys and addrs every call (session-static); only the
 * nonces/hints (via a fresh counter value) differ per call, which is
 * exactly what makes each output, real or spare, a genuinely fresh,
 * MAC-valid return header indistinguishable from any other to every
 * return-path mix node. */
static int build_return_header_into(return_header_t *out) {
    aes_key_t enc_keys[N_PATH_HOPS], mac_keys[N_PATH_HOPS];
    uint8_t   hints[N_PATH_HOPS][HINT_BYTES];
    uint64_t  ctr = next_return_pkt_counter();
    for (int i = 0; i < N_PATH_HOPS; i++) {
        enc_keys[i] = g_state.recv_hops[i].header_enc_key;
        mac_keys[i] = g_state.recv_hops[i].header_mac_key;
        if (packet_derive_hop_hint(&g_state.recv_hops[i].hint_seed, ctr, hints[i]) != 0) {
            log_err("return hint derivation failed"); return -1;
        }
    }
    return packet_build_return_header(enc_keys, mac_keys, hints,
                                      g_state.return_addrs, out);
}

static int build_fresh_return_header(void) {
    return build_return_header_into(&g_state.return_hdr);
}

/* Builds one "spare" return header the SG can fire autonomously as an
 * indistinguishable return-path cover packet, without disturbing
 * g_state.return_hdr (reserved for the next real request). Deliberately
 * draws from the SAME single counter as real return headers
 * (next_return_pkt_counter()) rather than a separate domain: the return
 * path has no forward-path-style cover-drops-at-MN1 problem to motivate
 * a split, so real and spare headers interleave in one domain/window. */
static int build_spare_return_header(return_header_t *out) {
    return build_return_header_into(out);
}

/* Lets multiple client identities run concurrently on this one loopback
 * testbed, each listening on its own port, to measure genuine
 * simultaneous load on shared mix nodes (see config.h's
 * CLIENT_RESPONSE_PORT_COUNT comment). ASN_CLIENT_RESPONSE_PORT env var
 * overrides the default; falls back to CLIENT_RESPONSE_PORT unchanged
 * when unset, so a normal single-client run is unaffected. Gated to
 * the fixed, enumerated CLIENT_RESPONSE_PORT_COUNT range mix_node.c's
 * allowlist accepts, not an open port choice. */
static uint16_t client_response_port(void) {
    const char *env = getenv("ASN_CLIENT_RESPONSE_PORT");
    if (!env) return CLIENT_RESPONSE_PORT;
    long v = atol(env);
    if (v < CLIENT_RESPONSE_PORT ||
        v >= CLIENT_RESPONSE_PORT + CLIENT_RESPONSE_PORT_COUNT) {
        return CLIENT_RESPONSE_PORT;
    }
    return (uint16_t)v;
}

/* Build both paths */
/* Probes TCP connect time to a candidate entry node as a proxy for that
 * physical path's round-trip responsiveness. Returns elapsed
 * milliseconds, or -1 on connect failure (treated as "arbitrarily slow"
 * by the caller, so a dead/unreachable candidate never wins the "faster
 * path" comparison).
 *
 * Deliberately a proxy, not a literal post-hoc reassignment: SESSION_
 * ROLE_A/B is sent as the first byte of the very first EXTEND message
 * to every hop (ecdhe_telescoped_path() above) and gets cryptographically
 * bound into each hop's derived key via crypto_ecdh_derive_bound()'s role
 * parameter. A path's key material literally differs depending which
 * role it was built under, so role can't be decided after a path is
 * built without re-deriving it, and the raw ephemeral ECDH material
 * needed to do that is deliberately zeroed the moment each hop's
 * role-bound key is derived, so there's nothing left to re-derive from
 * after the fact. A true post-hoc, SG-decided reassignment would need a
 * materially different protocol (retaining raw ECDH material past first
 * use, plus a new SG-to-client role-announcement round trip).
 *
 * This instead measures BEFORE any role is committed: probe connect
 * latency to each candidate path's entry node, then let the faster one
 * become the physical path that receives SESSION_ROLE_A (outbound),
 * same mechanism the paper's design defends against (steering attacks
 * by a malicious mix node that deliberately delays forwarding: a node
 * doing that measures slower here and gets assigned the less
 * traffic-sensitive B/inbound role instead), decided client-side via a
 * pre-handshake probe rather than SG-side via post-hoc reassignment. */
static int probe_rtt_ms(uint16_t port) {
    uint64_t t0 = GetTickCount64();
    SOCKET s = net_connect(LOCALHOST, port);
    if (s == INVALID_SOCKET) return -1;
    uint64_t t1 = GetTickCount64();
    net_close(s);
    return (int)(t1 - t0);
}

/* Telescoped ECDHE for one sending path (MN1 -> MN2 -> MN3 -> SG, SG
 * handshake tunneled through MN3). Used for path A and for every extra
 * striping leg. */
static int build_send_leg(const uint16_t ports[N_PATH_HOPS], sphinx_path_t *path,
                          aes_key_t *k_sg) {
    uint16_t ports_sg[N_PATH_HOPS + 1] = { ports[0], ports[1], ports[2], PORT_SERVICE_GW };
    /* Build sending path sphinx_path_t. Telescoped through MN1 (the
     * entry): only MN1 ever sees a connection carrying the client's real
     * IP; MN2 only sees a connection from MN1, MN3 only from MN2, and
     * the SG only sees a connection from MN3. */
    aes_key_t masters[N_PATH_HOPS + 1];
    uint8_t   hints[N_PATH_HOPS + 1][HINT_BYTES];
    uint8_t   node_pubs[N_PATH_HOPS + 1][EC_PUBKEY_LEN];

    if (ecdhe_telescoped_path(ports_sg, N_PATH_HOPS + 1, SESSION_ROLE_A,
                              masters, hints, node_pubs) != 0) {
        log_err("telescoped ECDHE failed on sending path"); return -1;
    }
    for (int i = 0; i < N_PATH_HOPS; i++) {
        derive_hop(&masters[i], &path->hops[i]);
        path->hop_ports[i] = ports[i];

        char logbuf[64];
        snprintf(logbuf, sizeof(logbuf),
                 "  sending hop %d ready (port %u)", i+1, ports[i]);
        log_msg(logbuf);
    }

    /* E2E session with SG via path A -> K_R-SG-A (last "hop" above) */
    *k_sg             = masters[N_PATH_HOPS];
    path->e2e.e2e_key = masters[N_PATH_HOPS];
    path->next_port   = ports[0];
    path->sg_port     = PORT_SERVICE_GW;
    /* SG-side O(1) lookup hint, derived from the
     * same master the SG independently re-derives at EXTEND time,
     * see packet_derive_sg_hint()'s comment. Role B never sends
     * MODE_DATA to the SG, so no hint is needed for K_R-SG-B. */
    if (packet_derive_sg_hint(&masters[N_PATH_HOPS],
                              &path->sg_hint) != 0) {
        log_err("failed to derive SG hint"); return -1;
    }
    log_msg("  K_R-SG-A established (tunneled through MN3)");

    /* Ephemeral ECDH masters are fully consumed above (derive_hop()
     * for the mix hops, direct copy for the SG's), zero them rather
     * than leaving them sitting in stack memory for the rest of the
     * process's life. explicit_bzero, not
     * memset, so the compiler can't optimize it away as a dead store
     * to a not-subsequently-read local. */
    explicit_bzero(masters, sizeof(masters));
    return 0;
}

/* Uniform double in [0, 1) from RAND_bytes, matching the rest of this
 * file's randomness convention. */
static double stripe_uniform01(void) {
    uint32_t r;
    if (RAND_bytes((uint8_t *)&r, sizeof(r)) != 1) r = 0;
    return (double)r / 4294967296.0;
}

/* Parses a comma-separated list of up to max doubles; returns the count. */
static int parse_double_list(const char *text, double *out, int max) {
    int n = 0;
    while (text && *text && n < max) {
        char *end = NULL;
        double v = strtod(text, &end);
        if (end == text) break;
        out[n++] = v;
        text = (*end == ',') ? end + 1 : end;
    }
    return n;
}

/* Reads the ASN_STRIPE_* settings (see the comment above stripe_leg_t).
 * Returns -1 on an invalid setting. */
static int stripe_config_init(void) {
    const char *legs = getenv("ASN_STRIPE_LEGS");
    g_n_legs = legs ? atoi(legs) : 1;
    if (g_n_legs < 1 || g_n_legs > MAX_STRIPE_LEGS) {
        log_err("ASN_STRIPE_LEGS must be between 1 and the guard set size"); return -1;
    }
#ifdef ASN_LOOPIX_MIXING
    if (g_n_legs > 1) { log_err("striping is not supported with ASN_LOOPIX_MIXING"); return -1; }
#endif
    const char *policy = getenv("ASN_STRIPE_POLICY");
    if (!policy || strcmp(policy, "iid") == 0)  g_stripe_policy = STRIPE_IID;
    else if (strcmp(policy, "round_robin") == 0) g_stripe_policy = STRIPE_ROUND_ROBIN;
    else if (strcmp(policy, "batch") == 0)       g_stripe_policy = STRIPE_BATCH;
    else if (strcmp(policy, "latency") == 0)     g_stripe_policy = STRIPE_LATENCY;
    else { log_err("unknown ASN_STRIPE_POLICY"); return -1; }

    double w[MAX_STRIPE_LEGS];
    int nw = parse_double_list(getenv("ASN_STRIPE_WEIGHTS"), w, MAX_STRIPE_LEGS);
    if (nw != 0 && nw != g_n_legs) { log_err("ASN_STRIPE_WEIGHTS needs one weight per leg"); return -1; }
    double total = 0.0;
    for (int i = 0; i < g_n_legs; i++) total += (nw ? w[i] : 1.0);
    if (total <= 0.0) { log_err("ASN_STRIPE_WEIGHTS must sum to a positive value"); return -1; }
    for (int i = 0; i < g_n_legs; i++) {
        g_legs[i].weight = (nw ? w[i] : 1.0) / total;
        if (nw && w[i] != w[0]) g_stripe_equal_weights = 0;
    }

    const char *batch = getenv("ASN_STRIPE_BATCH_MS");
    if (batch) g_batch_mean_ms = atof(batch);
    const char *window = getenv("ASN_STRIPE_WINDOW");
    if (window) g_stripe_window = atoi(window);
    if (g_batch_mean_ms <= 0.0 || g_stripe_window < 1 || g_stripe_window > STRIPE_RECENT_MAX) {
        log_err("invalid ASN_STRIPE_BATCH_MS or ASN_STRIPE_WINDOW"); return -1;
    }
    double rtt[MAX_STRIPE_LEGS];
    int nr = parse_double_list(getenv("ASN_STRIPE_RTT_MS"), rtt, MAX_STRIPE_LEGS);
    if (nr != 0 && nr != g_n_legs) { log_err("ASN_STRIPE_RTT_MS needs one value per leg"); return -1; }
    if (nr) {
        g_stripe_rtt_from_env = 1;
        for (int i = 0; i < g_n_legs; i++) g_legs[i].rtt_ms = rtt[i];
    }

    const char *log_path = getenv("ASN_STRIPE_LOG");
    if (log_path) {
        g_stripe_log = fopen(log_path, "a");
        if (!g_stripe_log) { log_err("cannot open ASN_STRIPE_LOG"); return -1; }
    }
    g_legs[0].path     = &g_state.send_path;
    g_legs[0].k_r_sg_a = &g_state.k_r_sg_a;
    return 0;
}

static int stripe_draw_by_weight(void) {
    double u = stripe_uniform01(), acc = 0.0;
    for (int i = 0; i < g_n_legs; i++) {
        acc += g_legs[i].weight;
        if (u < acc) return i;
    }
    return g_n_legs - 1;
}

/* Chooses the leg for the next real packet sent at now_ms. Called from
 * the interactive thread only (cover stays on leg 0), so no lock. */
static int stripe_pick_leg(uint64_t now_ms) {
    if (g_n_legs == 1) return 0;
    switch (g_stripe_policy) {
    case STRIPE_ROUND_ROBIN: {
        if (g_stripe_equal_weights) {
            int leg = g_rr_next;
            g_rr_next = (leg + 1) % g_n_legs;
            return leg;
        }
        int best = 0;
        for (int i = 0; i < g_n_legs; i++) {
            g_legs[i].credit += g_legs[i].weight;
            if (g_legs[i].credit > g_legs[best].credit) best = i;
        }
        g_legs[best].credit -= 1.0;
        return best;
    }
    case STRIPE_BATCH:
        if (!g_batch_open || now_ms >= g_batch_end_ms) {
            double u = stripe_uniform01();
            g_batch_leg = stripe_draw_by_weight();
            g_batch_end_ms = now_ms + (uint64_t)(-g_batch_mean_ms * log(1.0 - u));
            g_batch_open = 1;
        }
        return g_batch_leg;
    case STRIPE_LATENCY: {
        int order[MAX_STRIPE_LEGS];
        for (int i = 0; i < g_n_legs; i++) {
            stripe_leg_t *l = &g_legs[i];
            while (l->recent_n > 0 &&
                   (double)l->recent[l->recent_head] <= (double)now_ms - l->rtt_ms) {
                l->recent_head = (l->recent_head + 1) % STRIPE_RECENT_MAX;
                l->recent_n--;
            }
            order[i] = i;
        }
        for (int i = 1; i < g_n_legs; i++)          /* sort by RTT, k is tiny */
            for (int j = i; j > 0 && g_legs[order[j]].rtt_ms < g_legs[order[j - 1]].rtt_ms; j--) {
                int t = order[j]; order[j] = order[j - 1]; order[j - 1] = t;
            }
        int chosen = -1;
        for (int i = 0; i < g_n_legs && chosen < 0; i++)
            if (g_legs[order[i]].recent_n < g_stripe_window) chosen = order[i];
        if (chosen < 0) {
            chosen = order[0];
            for (int i = 1; i < g_n_legs; i++)
                if (g_legs[order[i]].recent_n < g_legs[chosen].recent_n) chosen = order[i];
        }
        stripe_leg_t *c = &g_legs[chosen];
        if (c->recent_n == STRIPE_RECENT_MAX) {        /* cannot happen with window <= max */
            c->recent_head = (c->recent_head + 1) % STRIPE_RECENT_MAX;
            c->recent_n--;
        }
        c->recent[(c->recent_head + c->recent_n) % STRIPE_RECENT_MAX] = now_ms;
        c->recent_n++;
        return chosen;
    }
    default:
        return stripe_draw_by_weight();
    }
}

static uint64_t stripe_next_counter(int leg) {
    if (leg == 0) return next_send_pkt_counter();
    return (uint64_t)(InterlockedIncrement(&g_legs[leg].counter) - 1);
}

/* Builds sending legs 1..k-1 after path A and path B exist. Each extra
 * leg takes a guard of guard set A not used by any earlier leg, and fresh
 * weighted middle/last hops disjoint from every node in use and from
 * guard set A. */
static int build_extra_legs(const session_path_t *sp) {
    int used[3 * MAX_STRIPE_LEGS + 3];
    int n_used = 0;
    used[n_used++] = sp->entry_a; used[n_used++] = sp->mid_a; used[n_used++] = sp->last_a;
    used[n_used++] = sp->entry_b; used[n_used++] = sp->mid_b; used[n_used++] = sp->last_b;
    if (!g_stripe_rtt_from_env)
        g_legs[0].rtt_ms = probe_rtt_ms(g_state.send_path.hop_ports[0]);

    for (int leg = 1; leg < g_n_legs; leg++) {
        session_path_t cand;
        int ok = 0;
        for (int attempt = 0; attempt < 500 && !ok; attempt++) {
            if (build_session_path(&g_consensus, &g_guard_a, &g_guard_b, &g_path_rng, &cand) != 0)
                return -1;
            ok = 1;
            for (int u = 0; u < n_used; u++)
                if (cand.entry_a == used[u] || cand.mid_a == used[u] || cand.last_a == used[u]) ok = 0;
            for (int g = 0; g < g_guard_a.count; g++)   /* keep guards free for later legs */
                if (cand.mid_a == g_guard_a.guard_ids[g] || cand.last_a == g_guard_a.guard_ids[g]) ok = 0;
        }
        if (!ok) { log_err("no disjoint path for an extra striping leg"); return -1; }
        used[n_used++] = cand.entry_a; used[n_used++] = cand.mid_a; used[n_used++] = cand.last_a;

        uint16_t ports[N_PATH_HOPS] = {
            pool_port(&g_consensus, cand.entry_a),
            pool_port(&g_consensus, cand.mid_a),
            pool_port(&g_consensus, cand.last_a),
        };
        char logbuf[128];
        snprintf(logbuf, sizeof(logbuf), "building striping leg %d: entry=%d mid=%d last=%d",
                 leg, cand.entry_a, cand.mid_a, cand.last_a);
        log_msg(logbuf);
        g_legs[leg].path     = &g_extra_paths[leg];
        g_legs[leg].k_r_sg_a = &g_extra_keys[leg];
        if (build_send_leg(ports, g_legs[leg].path, g_legs[leg].k_r_sg_a) != 0) return -1;
        if (!g_stripe_rtt_from_env) g_legs[leg].rtt_ms = probe_rtt_ms(ports[0]);
    }
    return 0;
}

/* 1 if any hop of sp other than path A's entry is a guard of guard set A. */
static int path_uses_other_guard_a(const session_path_t *sp) {
    int hops[5] = { sp->mid_a, sp->last_a, sp->entry_b, sp->mid_b, sp->last_b };
    for (int g = 0; g < g_guard_a.count; g++)
        for (int h = 0; h < 5; h++)
            if (hops[h] == g_guard_a.guard_ids[g]) return 1;
    return 0;
}

static int build_paths(void) {
    session_path_t sp;
    if (build_session_path(&g_consensus, &g_guard_a, &g_guard_b,
                            &g_path_rng, &sp) != 0) {
        log_err("build_session_path failed"); return -1;
    }
    /* Striping takes every extra leg's entry from guard set A, so the other
     * hops of this session must stay off guard set A's nodes. */
    for (int tries = 0; g_n_legs > 1 && path_uses_other_guard_a(&sp); tries++) {
        if (tries == 500 || build_session_path(&g_consensus, &g_guard_a, &g_guard_b,
                                               &g_path_rng, &sp) != 0) {
            log_err("no session path that leaves guard set A free for striping"); return -1;
        }
    }

    /* RTT-based channel assignment: probe both candidate paths' entry
     * nodes BEFORE either handshake begins (role is committed at the
     * first EXTEND message, see probe_rtt_ms()'s comment for why this
     * has to happen here, not after). Path A's candidate entry is
     * sp.entry_a; path B's is sp.last_b (the outermost/telescoping
     * entry for the receiving path, see the "Order [0]=MNc" comment
     * below). Whichever probes faster keeps its (entry,mid,last)
     * triple assigned to the A role; if B's candidate is faster, swap
     * the two triples so the actually-faster physical path ends up
     * built with SESSION_ROLE_A below, every line after this block is
     * unchanged and just reads whatever ended up in sp.*_a/sp.*_b. */
    {
        int rtt_a = probe_rtt_ms(pool_port(&g_consensus, sp.entry_a));
        int rtt_b = probe_rtt_ms(pool_port(&g_consensus, sp.last_b));
        int a_slower_or_dead = (rtt_a < 0) || (rtt_b >= 0 && rtt_b < rtt_a);
        if (a_slower_or_dead) {
            int tmp;
            tmp = sp.entry_a; sp.entry_a = sp.entry_b; sp.entry_b = tmp;
            tmp = sp.mid_a;   sp.mid_a   = sp.mid_b;   sp.mid_b   = tmp;
            tmp = sp.last_a;  sp.last_a  = sp.last_b;  sp.last_b  = tmp;
        }
        char logbuf[128];
        snprintf(logbuf, sizeof(logbuf),
                 "RTT probe: candidate-A=%dms candidate-B=%dms -> %s kept as outbound (A)",
                 rtt_a, rtt_b, a_slower_or_dead ? "candidate-B" : "candidate-A");
        log_msg(logbuf);
    }

    {
        char logbuf[128];
        snprintf(logbuf, sizeof(logbuf),
                 "session path: entry_a=%d mid_a=%d last_a=%d "
                 "entry_b=%d mid_b=%d last_b=%d",
                 sp.entry_a, sp.mid_a, sp.last_a,
                 sp.entry_b, sp.mid_b, sp.last_b);
        log_msg(logbuf);
    }

    log_msg("building sending path A (MN1->MN2->MN3->SG, SG handshake tunneled)...");

    uint16_t send_ports[N_PATH_HOPS] = {
        pool_port(&g_consensus, sp.entry_a),
        pool_port(&g_consensus, sp.mid_a),
        pool_port(&g_consensus, sp.last_a),
    };
    /* The SG's ECDH handshake is telescoped one hop
     * further than the mix path itself, through MN3, so the SG never
     * sees a connection carrying the client's real IP either. See the
     * comment above ecdhe_telescoped_path(). */
    if (build_send_leg(send_ports, &g_state.send_path, &g_state.k_r_sg_a) != 0) return -1;

    log_msg("building receiving path B (MNc->MNb->MNa->Client)...");

    /* Receiving path: establish ECDHE with MNc, MNb, MNa
     * Order [0]=MNc, [1]=MNb, [2]=MNa  (outermost to innermost) */
    uint16_t recv_ports[N_PATH_HOPS] = {
        pool_port(&g_consensus, sp.last_b),   /* MNc */
        pool_port(&g_consensus, sp.mid_b),    /* MNb */
        pool_port(&g_consensus, sp.entry_b),  /* MNa */
    };

    /* Telescoped through MNc (the entry for the receiving path), see
     * the sending-path comment above; same rationale. The SG's
     * K_R-SG-B handshake is tunneled one hop further, through MNa,
     * exactly as K_R-SG-A is tunneled through MN3 above,
     * this is purely a private-channel-establishment convenience (it has
     * no bearing on the actual runtime data-flow direction, which is
     * driven entirely by the encrypted return header built below). */
    uint16_t recv_ports_sg[N_PATH_HOPS + 1] = {
        recv_ports[0], recv_ports[1], recv_ports[2], PORT_SERVICE_GW,
    };
    {
        aes_key_t masters[N_PATH_HOPS + 1];
        uint8_t   hints[N_PATH_HOPS + 1][HINT_BYTES];
        uint8_t   node_pubs[N_PATH_HOPS + 1][EC_PUBKEY_LEN];

        if (ecdhe_telescoped_path(recv_ports_sg, N_PATH_HOPS + 1, SESSION_ROLE_B,
                                  masters, hints, node_pubs) != 0) {
            log_err("telescoped ECDHE failed on receiving path"); return -1;
        }
        for (int i = 0; i < N_PATH_HOPS; i++) {
            derive_hop(&masters[i], &g_state.recv_hops[i]);

            /* Store MNc pubkey and addr for embedding in outbound payload */
            if (i == 0) {
                memcpy(g_state.mnc_pubkey, node_pubs[0], EC_PUBKEY_LEN);
                make_addr_bytes(LOCALHOST, recv_ports[0], g_state.mnc_addr);
            }

            char logbuf[64];
            snprintf(logbuf, sizeof(logbuf),
                     "  receiving hop %d ready (port %u)", i, recv_ports[i]);
            log_msg(logbuf);
        }

        /* E2E session with SG via path B -> K_R-SG-B (last "hop" above) */
        g_state.k_r_sg_b = masters[N_PATH_HOPS];
        log_msg("  K_R-SG-B established (tunneled through MNa)");

        explicit_bzero(masters, sizeof(masters));
    }

    /* Build Client address bytes (127.0.0.1:<response port>) */
    make_addr_bytes(LOCALHOST, client_response_port(), g_state.client_addr);

    /* Return-header addrs are static for the session's lifetime (only the
     * nonces inside change per request, see build_fresh_return_header()):
     *   addrs[0] = MNb addr  (MNc learns this after peeling)
     *   addrs[1] = MNa addr  (MNb learns this)
     *   addrs[2] = Client addr (MNa learns this, final delivery)
     */
    make_addr_bytes(LOCALHOST, recv_ports[1], g_state.return_addrs[0]);  /* MNb */
    make_addr_bytes(LOCALHOST, recv_ports[2], g_state.return_addrs[1]);  /* MNa */
    memcpy(g_state.return_addrs[2], g_state.client_addr, ADDR_BYTES);

    if (build_fresh_return_header() != 0) {
        log_err("failed to build return header"); return -1;
    }

    if (g_n_legs > 1 && build_extra_legs(&sp) != 0) return -1;

    g_state.ready = 1;
    log_msg("both paths ready");
    return 0;
}

/* Response listener thread */
static DWORD WINAPI response_listener(LPVOID arg) {
    (void)arg;
    uint16_t port = client_response_port();
    SOCKET srv = net_listen(port);
    if (srv == INVALID_SOCKET) { log_err("response listener bind failed"); return 1; }

    char logbuf[64];
    snprintf(logbuf, sizeof(logbuf),
             "response listener on port %u", port);
    log_msg(logbuf);

    while (1) {
        SOCKET conn = net_accept(srv);
        if (conn == INVALID_SOCKET) break;

        uint8_t wire[WIRE_PACKET_SIZE];
        if (net_recv_all(conn, wire, WIRE_PACKET_SIZE) == 0) {
            /* Validate: try to decrypt before signalling.
             * Cover packets are random and will fail GCM auth.            */
            size_t enc_len = (size_t)((wire[RETURN_HEADER_SIZE] << 8) |
                                       wire[RETURN_HEADER_SIZE+1]);
            /* Real responses are small, filter obvious random cover packets */
            if (enc_len >= GCM_OVERHEAD && enc_len <= 512) {
                uint8_t tmp[RETURN_PAYLOAD_SIZE];
                int n = crypto_aes_decrypt(&g_state.k_r_sg_b,
                                           wire + RETURN_HEADER_SIZE + 2,
                                           enc_len, tmp, sizeof(tmp));
                /* M-c: return-path cover now decrypts successfully too
                 * (it's a genuine GCM ciphertext under the same k_r_sg_b,
                 * built by SG from a spare header this client itself
                 * supplied: see service_gateway.c). GCM success alone
                 * no longer means "real response"; the leading plaintext
                 * flags byte (mirrors the forward path's inner PKT_DUMMY,
                 * see packet_sphinx_unwrap()) is what distinguishes them
                 * now. The old "GCM failure = cover" case still applies
                 * to plain noise from a MITM or bug, so both checks stay. */
                if (n > 0 && (size_t)n >= 1 && tmp[0] == PKT_REAL) {
                    /* Real response, signal */
                    EnterCriticalSection(&g_resp_lock);
                    memcpy(g_resp_buf, wire, WIRE_PACKET_SIZE);
                    g_resp_ready = 1;
                    SetEvent(g_resp_event);
                    LeaveCriticalSection(&g_resp_lock);
                }
                /* else: cover packet (GCM failure, or GCM success with
                 * PKT_DUMMY flag), silently discard either way. */
            }
        }
        net_close(conn);
    }
    net_close(srv);
    return 0;
}


/* Cover traffic */

/* This client's persistent rate-tier mean, drawn once
 * by rate_tier_init() (called from main(), alongside node_pool_init()) and
 * held fixed thereafter, see config.h's RATE_TIER_INTERVALS_MS comment.
 * Initialized to the un-tiered legacy constant so any call before
 * rate_tier_init() runs still behaves sanely rather than reading garbage. */
static double g_rate_tier_interval_ms = DUMMY_INTERVAL_MS;

/* Persists this client identity's rate tier the same way node_pool.c
 * persists guard sets: drawn once from real entropy, reused verbatim on
 * every later run from the same cwd (client_pins/, client_guard_*.txt
 * live alongside it). Deliberately NOT user-settable, see config.h's
 * comment for why a per-client-chosen rate would reintroduce a
 * fingerprint the tiering is meant to remove. */
static int rate_tier_init(void) {
    static const double kTierMs[N_RATE_TIERS] = RATE_TIER_INTERVALS_MS;
    const char *path = "client_rate_tier.txt";

    int tier = -1;
    FILE *f = fopen(path, "r");
    if (f) {
        if (fscanf(f, "%d", &tier) != 1 || tier < 0 || tier >= N_RATE_TIERS)
            tier = -1;
        fclose(f);
    }
    if (tier < 0) {
        uint32_t r;
        if (RAND_bytes((uint8_t *)&r, sizeof(r)) != 1) r = 0;
        tier = (int)(r % N_RATE_TIERS);
        f = fopen(path, "w");
        if (f) { fprintf(f, "%d\n", tier); fclose(f); }
    }
    g_rate_tier_interval_ms = kTierMs[tier];
    return 0;
}

/* Poisson inter-packet interval in ms (rate = this client's assigned
 * rate-tier mean, see g_rate_tier_interval_ms above, rather than a
 * single network-wide mean shared by every client). */
static DWORD poisson_interval_ms(void) {
    /* Inverse CDF of Exponential: -mean * ln(U), U ~ Uniform(0,1).
     * RAND_bytes, not libc rand(), rand()/srand() is process-global,
     * non-thread-safe, and (seeded from GetTickCount()) guessable,
     * weakening the cover-traffic unlinkability property this interval
     * exists to provide. Matches mix_node.c's mix_delay_sleep() fix. */
    uint32_t r;
    if (RAND_bytes((uint8_t *)&r, sizeof(r)) != 1) r = 1;
    double u = ((double)r + 1.0) / (4294967296.0 + 1.0);  /* avoid 0 and 1 */
    double interval = -g_rate_tier_interval_ms * log(u);
    if (interval < 10.0)  interval = 10.0;
    if (interval > 1000.0) interval = 1000.0;
    return (DWORD)interval;
}

/* Counter: incremented for each real packet queued, decremented by cover
 * thread once per wakeup.  Each real packet suppresses one cover slot.
 * Legacy (!ASN_LOOPIX_MIXING) mechanism only, see g_mailbox below for
 * the hardened-mode replacement. */
static volatile LONG g_real_traffic_pending = 0;

#ifdef ASN_LOOPIX_MIXING
/* Loopix-style shared dispatch: real traffic is no longer sent the
 * instant it is built. It is queued in this single-slot mailbox and
 * drained by the SAME Poisson clock cover traffic uses (real preferred
 * over cover when both are ready), so the aggregate observable send
 * rate is bounded by that one clock instead of growing additively with
 * real traffic. An earlier attempt that generated cover on an
 * independent clock (additive, no shared ceiling) was measured to leak
 * MORE than the un-hardened mechanism, not less. This mailbox design is
 * the correction. */
static CRITICAL_SECTION g_mailbox_lock;
static wire_packet_t    g_pending_real_pkt;
static volatile LONG    g_pending_real_flag = 0;
#endif

/* Builds a forward-direction cover packet exactly like
 * packet_sphinx_dummy() (same flags, same overall shape, indistinguishable
 * to every mix node), except the random inner payload carries a spare
 * return_header_t in its
 * first RETURN_HEADER_SIZE bytes instead of being pure random filler. SG
 * extracts it (service_gateway.c's find_a_session()) and uses it to fire
 * a return-direction cover packet on its own schedule, see that file's
 * comment for the full mechanism. Total payload size, and therefore wire
 * packet size, is unchanged (still MAX_INNER_PAYLOAD, same as
 * packet_sphinx_dummy()), the return header replaces part of what would
 * otherwise be random bytes, not an addition to it, so this is invisible
 * to any mix node on size alone. */
static int build_outbound_cover_with_spare_return(uint64_t pkt_counter,
                                                    wire_packet_t *out) {
    return_header_t spare = {0};
    if (build_spare_return_header(&spare) != 0) return -1;

    uint8_t payload[MAX_INNER_PAYLOAD];
    if (RAND_bytes(payload, MAX_INNER_PAYLOAD) != 1) return -1;
    memcpy(payload, &spare, RETURN_HEADER_SIZE);

    return packet_sphinx_build(&g_state.send_path, payload, MAX_INNER_PAYLOAD,
                               PKT_DUMMY | PKT_DEST_SERVICE,
                               pkt_counter, out);
}

#ifdef ASN_HOP_DECOY
/* Weighted random termination hop for a per-hop decoy, see config.h's
 * HOP_DECOY_*_WEIGHT_PCT. RAND_bytes, not rand(), matching every other
 * unpredictability-critical draw in this file (poisson_interval_ms,
 * rate_tier_init). Pure client-side policy: mix_node.c's handling of
 * HOP_DROP_MARKER doesn't know or care how this was chosen, so this
 * weighting can change freely without touching any mix node's code. */
static int pick_weighted_drop_hop(void) {
    uint32_t r;
    if (RAND_bytes((uint8_t *)&r, sizeof(r)) != 1) r = 0;
    int pct = (int)(r % 100);
    if (pct < HOP_DECOY_ENTRY_WEIGHT_PCT) return 0;
    if (pct < HOP_DECOY_ENTRY_WEIGHT_PCT + HOP_DECOY_MID_WEIGHT_PCT) return 1;
    return 2;
}

/* Substitutes a fraction of cover slots (HOP_DECOY_FRACTION_PCT) with a
 * hop-terminating decoy instead of the usual SG-reaching cover packet,
 * same Poisson clock either way, see config.h's HOP_DECOY_FRACTION_PCT
 * comment for why this must stay a substitution, not an addition. */
static int build_cover_slot(uint64_t pkt_counter, wire_packet_t *out) {
    uint32_t r;
    if (RAND_bytes((uint8_t *)&r, sizeof(r)) != 1) r = 100;
    if ((int)(r % 100) < HOP_DECOY_FRACTION_PCT) {
        return packet_sphinx_decoy_hop(&g_state.send_path, pkt_counter,
                                        pick_weighted_drop_hop(), out);
    }
    return build_outbound_cover_with_spare_return(pkt_counter, out);
}
#else
#define build_cover_slot build_outbound_cover_with_spare_return
#endif

static DWORD WINAPI outbound_cover_thread(LPVOID arg) {
    (void)arg;

    while (1) {
        Sleep(poisson_interval_ms());
        if (!g_state.ready) continue;

        wire_packet_t out = {0};

#ifdef ASN_LOOPIX_MIXING
        int have_real = 0;
        EnterCriticalSection(&g_mailbox_lock);
        if (g_pending_real_flag) {
            memcpy(&out, &g_pending_real_pkt, sizeof(out));
            g_pending_real_flag = 0;
            have_real = 1;
        }
        LeaveCriticalSection(&g_mailbox_lock);

        if (!have_real) {
            if (build_cover_slot(
                    next_cover_pkt_counter(), &out) != 0) continue;
        }
#else
        /* Step 8.6: suppress this cover slot if a real packet was sent.
         * This adaptive credit-suppression mechanism leaks real-traffic
         * activity level once it exceeds the cover ceiling. */
        if (InterlockedDecrement(&g_real_traffic_pending) >= 0) {
            continue;   /* consumed one real-packet credit, skip cover */
        }
        /* No real-packet credit, restore counter to 0 floor and send cover */
        InterlockedIncrement(&g_real_traffic_pending);

        if (build_cover_slot(
                next_cover_pkt_counter(), &out) != 0) continue;
#endif

        SOCKET s = net_connect(LOCALHOST, g_state.send_path.hop_ports[0]);
        if (s == INVALID_SOCKET) continue;

        uint8_t mode = MODE_DATA;
        net_send_all(s, &mode,   1);
        net_send_all(s, out.data, WIRE_PACKET_SIZE);
        net_close(s);
    }
    return 0;
}

/* Generalized request sender, built by factoring the original
 * (byte-for-byte-preserved for the GET case, data==NULL) send_get()
 * below out to a `type`/`data` parameter, so
 * TYPE_HANDSHAKE_INIT/TYPE_HANDSHAKE_POLL requests reuse the exact same
 * path-building/dispatch machinery instead of duplicating it. When
 * `data` is non-NULL, appends [dlen(2)][data] after the key, the
 * same convention sender.c's PUT already uses, otherwise the app
 * section is exactly [type][klen][key], matching GET/POLL's shape. */
static int send_app_request(uint8_t type, const char *key,
                             const uint8_t *data, size_t data_len,
                             const char *log_label) {
    if (!g_state.ready) { log_err("paths not ready"); return -1; }

    /* Fresh nonces every request, not just once per session, see
     * build_fresh_return_header(). */
    if (build_fresh_return_header() != 0) {
        log_err("failed to refresh return header"); return -1;
    }

    size_t klen = strlen(key);
    if (klen > 63) { log_err("key too long"); return -1; }

    /* App data section */
    uint8_t app[MAX_INNER_PAYLOAD];
    memset(app, 0, sizeof(app));
    size_t aoff = 0;
    app[aoff++] = type;
    app[aoff++] = (uint8_t)klen;
    memcpy(app + aoff, key, klen); aoff += klen;
    if (data) {
        if (data_len > 0xFFFF) { log_err("request data too large"); return -1; }
        if (aoff + 2 + data_len > sizeof(app)) { log_err("request data too large"); return -1; }
        app[aoff++] = (uint8_t)(data_len >> 8);
        app[aoff++] = (uint8_t)(data_len & 0xFF);
        memcpy(app + aoff, data, data_len); aoff += data_len;
    }

    /* Full inner payload for packet_sphinx_build:
     * packet_sphinx_build prepends flags+len internally via INNER_HDR_BYTES
     * and also expects MNc_pubkey+addr+return_hdr to be in the payload.
     * We pack everything into the payload buffer.                         */
    uint8_t payload[MAX_INNER_PAYLOAD];
    memset(payload, 0, sizeof(payload));
    size_t poff = 0;

    /* MNc pubkey */
    memcpy(payload + poff, g_state.mnc_pubkey, EC_PUBKEY_LEN);
    poff += EC_PUBKEY_LEN;

    /* MNc IP:port */
    memcpy(payload + poff, g_state.mnc_addr, ADDR_BYTES);
    poff += ADDR_BYTES;

    /* Return header */
    memcpy(payload + poff, &g_state.return_hdr, RETURN_HEADER_SIZE);
    poff += RETURN_HEADER_SIZE;

    /* App data */
    memcpy(payload + poff, app, aoff);
    poff += aoff;

    if (poff > MAX_INNER_PAYLOAD) {
        log_err("payload too large"); return -1;
    }

    uint64_t now_ms = GetTickCount64();
    int leg = stripe_pick_leg(now_ms);
    wire_packet_t pkt = {0};
    if (packet_sphinx_build(g_legs[leg].path,
                            payload, (uint16_t)poff,
                            PKT_REAL | PKT_DEST_SERVICE,
                            stripe_next_counter(leg), &pkt) != 0) {
        log_err("packet_sphinx_build failed"); return -1;
    }

#ifdef ASN_LOOPIX_MIXING
    /* Queue for the shared dispatch clock instead of sending immediately,
     * see outbound_cover_thread() and g_mailbox above. Single-slot: safe
     * only because run_interactive() is strictly serial (every caller
     * always waits for wait_response() first) so this is never called
     * again before the previous packet is drained. A caller that fired
     * requests back-to-back without waiting would silently overwrite and
     * lose the undrained one, no such caller exists today, but this
     * assumption is not enforced here if one is ever added. */
    EnterCriticalSection(&g_mailbox_lock);
    memcpy(&g_pending_real_pkt, &pkt, sizeof(g_pending_real_pkt));
    g_pending_real_flag = 1;
    LeaveCriticalSection(&g_mailbox_lock);
#else
    /* Step 8.6: signal cover to suppress next slot BEFORE sending, so the
     * cover thread cannot race ahead and send a cover packet in this slot.  */
    InterlockedIncrement(&g_real_traffic_pending);

    /* Send directly to this leg's MN1 */
    SOCKET s = net_connect(LOCALHOST, g_legs[leg].path->hop_ports[0]);
    if (s == INVALID_SOCKET) { log_err("connect MN1"); return -1; }

    uint8_t mode = MODE_DATA;
    net_send_all(s, &mode,    1);
    net_send_all(s, pkt.data, WIRE_PACKET_SIZE);
    net_close(s);
#endif
    if (g_stripe_log) {
        fprintf(g_stripe_log, "%llu,%d,%u\n", (unsigned long long)now_ms, leg,
                (unsigned)g_legs[leg].path->hop_ports[0]);
        fflush(g_stripe_log);
    }

    char logbuf[128];
    snprintf(logbuf, sizeof(logbuf),
             "%s '%s' sent via MN1->MN2->MN3->SG (leg %d)", log_label, key, leg);
    log_msg(logbuf);
    return 0;
}

/* Send GET request */
static int send_get(const char *key) {
    return send_app_request(TYPE_GET, key, NULL, 0, "GET");
}

/* Wait for and decrypt response */
static int wait_response(uint8_t *out, uint16_t *out_len, DWORD timeout_ms) {
    if (WaitForSingleObject(g_resp_event, timeout_ms) != WAIT_OBJECT_0) {
        log_err("response timeout"); return -1;
    }

    EnterCriticalSection(&g_resp_lock);
    uint8_t wire[WIRE_PACKET_SIZE];
    memcpy(wire, g_resp_buf, WIRE_PACKET_SIZE);
    g_resp_ready = 0;
    ResetEvent(g_resp_event);
    LeaveCriticalSection(&g_resp_lock);

    /* Return packet layout:
     * [return_header(174)][enc_K_R-SG-B(response)]
     * After MNa peeled the last header block, return_header is all zeros.
     * The response payload starts at RETURN_HEADER_SIZE.                 */
    /* Read enc_len from first 2 bytes of payload section */
    size_t enc_len = (size_t)((wire[RETURN_HEADER_SIZE] << 8) |
                               wire[RETURN_HEADER_SIZE+1]);
    const uint8_t *enc_resp = wire + RETURN_HEADER_SIZE + 2;

    if (enc_len < GCM_OVERHEAD || enc_len > RETURN_PAYLOAD_SIZE - 2) {
        log_err("invalid enc_len in response"); return -1;
    }

    uint8_t plain[RETURN_PAYLOAD_SIZE];
    int n = crypto_aes_decrypt(&g_state.k_r_sg_b,
                               enc_resp, enc_len,
                               plain, sizeof(plain));
    if (n < 0) { log_err("response decrypt failed"); return -1; }
    if (n < 1) { log_err("response too short (no flags byte)"); return -1; }

    /* M-c: byte 0 is now a leading flags byte (PKT_REAL/PKT_DUMMY),
     * mirroring the forward path's inner flags, response_listener()
     * already filtered to PKT_REAL before signalling this event, so this
     * is always PKT_REAL here; skip it to recover the actual response
     * bytes, which now start at plain[1] instead of plain[0]. */
    n -= 1;
    if ((size_t)n > MAX_INNER_PAYLOAD) n = MAX_INNER_PAYLOAD;
    memcpy(out, plain + 1, (size_t)n);
    *out_len = (uint16_t)n;
    return 0;
}


/* Send session setup packet to SG */
/* SETUP for sending leg `leg` (0 = path A). Every leg proves, with its own
 * binding tag, that it belongs with the same receiving path B, so the SG
 * binds each leg's A session to that one B session. */
static int send_setup_leg(int leg) {
    sphinx_path_t *path = g_legs[leg].path;
    /* See send_get()'s matching
     * comment / build_fresh_return_header(). Redundant with build_paths()'s
     * own call immediately before this in practice, but kept here too so
     * this function does not depend on caller ordering to stay correct. */
    if (build_fresh_return_header() != 0) {
        log_err("failed to refresh return header"); return -1;
    }

    /* Compute binding tag, proves this session
     * established both K_R-SG-A and K_R-SG-B. Order matters here: A
     * first, then B, matching every other caller of this function. */
    uint8_t binding_tag[MAC_BYTES];
    if (packet_derive_binding_tag(g_legs[leg].k_r_sg_a, &g_state.k_r_sg_b,
                                  binding_tag) != 0) {
        log_err("binding tag derivation failed"); return -1;
    }

    /* Build setup payload */
    uint8_t payload[MAX_INNER_PAYLOAD];
    memset(payload, 0, sizeof(payload));
    size_t off = 0;

    payload[off++] = TYPE_SETUP;

    /* Sending-path blind keys (SK_R-MN1/MN2/MN3) are deliberately NOT
     * sent to the SG. The SG never reads them (it only pre-blinds the
     * RETURN path, using recv_blind[] below), transmitting them would
     * be gratuitous key exposure with no functional benefit, since keys
     * are independently derived (packet_derive_hop_keys). */

    /* SK_R-MNa, MNb, MNc (receiving path blind keys): [0]=MNc,[1]=MNb,[2]=MNa */
    for (int i = 0; i < N_PATH_HOPS; i++) {
        memcpy(payload + off, g_state.recv_hops[i].blind_key.key, AES_KEY_LEN);
        off += AES_KEY_LEN;
    }

    /* Binding tag */
    memcpy(payload + off, binding_tag, MAC_BYTES); off += MAC_BYTES;

    /* MNc pubkey + addr + return header (SG needs these for response routing) */
    memcpy(payload + off, g_state.mnc_pubkey, EC_PUBKEY_LEN); off += EC_PUBKEY_LEN;
    memcpy(payload + off, g_state.mnc_addr,   ADDR_BYTES);    off += ADDR_BYTES;
    memcpy(payload + off, &g_state.return_hdr, RETURN_HEADER_SIZE); off += RETURN_HEADER_SIZE;

    /* Under ASN_POOL_MIXING, SETUP itself can sit queued at each of its
     * 3 hops for up to POOL_MIX_FLUSH_MS(250ms) before that hop's batch
     * flushes: up to ~750ms before the SG ever processes it. Waiting
     * here for a genuine ack avoids a GET arriving before SETUP has
     * landed from being silently dropped at the SG: on successful
     * SETUP, service_gateway.c fires a small PKT_REAL response back
     * through path B immediately (bypassing the response mailbox on
     * purpose: see that file's comment on this exact call site for
     * why a setup ack doesn't carry the same real-activity-timing leak
     * the mailbox exists to protect against). 3000ms covers the ~750ms
     * worst case with real margin; a caller gets a clear, fast "session
     * setup failed" instead of silently hanging on its
     * first request. `payload` above is reused across retries (nothing
     * in it depends on the packet counter), but each attempt rebuilds
     * the Sphinx-encrypted wire packet fresh with a new counter,
     * resending the identical wire bytes would hit the mix nodes' own
     * replay protection and get silently dropped, defeating the retry. */
    for (int attempt = 0; attempt < 2; attempt++) {
        if (attempt > 0) {
            log_err("send_setup: no ack, retrying once");
        }

        wire_packet_t pkt = {0};
        if (packet_sphinx_build(path, payload, (uint16_t)off,
                                PKT_REAL | PKT_DEST_SERVICE,
                                stripe_next_counter(leg), &pkt) != 0) {
            log_err("send_setup: build failed"); return -1;
        }

        SOCKET s = net_connect(LOCALHOST, path->hop_ports[0]);
        if (s == INVALID_SOCKET) { log_err("send_setup: connect MN1"); return -1; }

        uint8_t mode = MODE_DATA;
        net_send_all(s, &mode, 1);
        net_send_all(s, pkt.data, WIRE_PACKET_SIZE);
        net_close(s);

        log_msg("session setup sent to SG, awaiting ack");

        uint8_t ack[MAX_INNER_PAYLOAD]; uint16_t ack_len = 0;
        if (wait_response(ack, &ack_len, 3000) == 0) {
            log_msg("session setup acknowledged by SG");
            return 0;
        }
    }
    log_err("send_setup: no ack after retry");
    return -1;
}

static int send_setup(void) {
    for (int leg = 0; leg < g_n_legs; leg++)
        if (send_setup_leg(leg) != 0) return -1;
    return 0;
}

/* STREAM <n> <rate> [wait]: n real requests at Poisson times with mean
 * rate `rate` per second, each on the leg the split policy picks.
 * Measurement aid for striping runs; the requests are GETs for a fixed
 * probe key. Send times follow an absolute schedule, so time spent
 * building a packet does not slow the rate. By default replies are not
 * awaited, so the SG's single-slot response mailbox coalesces them. With
 * wait=1 each request waits up to 2 s for its reply first (one request
 * outstanding, as the GET protocol expects), which exercises the return
 * path once per request. */
static void stream_run(int n, double rate, int wait_reply) {
    double next_ms = (double)GetTickCount64();
    int sent = 0, replies = 0;
    for (int i = 0; i < n; i++) {
        next_ms += -1000.0 / rate * log(1.0 - stripe_uniform01());
        double wait = next_ms - (double)GetTickCount64();
        if (wait > 0) Sleep((DWORD)wait);
        if (send_app_request(TYPE_GET, "stream-probe", NULL, 0, "STREAM") != 0) continue;
        sent++;
        if (wait_reply) {
            uint8_t resp[MAX_INNER_PAYLOAD]; uint16_t resp_len = 0;
            if (wait_response(resp, &resp_len, 2000) == 0) replies++;
            next_ms = (double)GetTickCount64();
        }
    }
    printf("[Client] STREAM done: %d of %d sent, %d replies awaited and received\n",
           sent, n, replies);
    fflush(stdout);
}

/* Interactive loop */
static void run_interactive(void) {
    printf("\n+==========================================+\n");
    printf("|   Anon-Sec-Net v2 Client Ready           |\n");
    printf("|   Dual path | Sphinx | Return header     |\n");
    printf("|   Commands:                              |\n");
    printf("|     GET <key>   Retrieve content         |\n");
    printf("|     STREAM <n> <rate> [wait]  Probe      |\n");
    printf("|     quit        Exit                     |\n");
    printf("+==========================================+\n\n");

    char line[512];
    while (1) {
        printf("client> "); fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;

        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') line[--len] = '\0';
        if (len > 0 && line[len-1] == '\r') line[--len] = '\0';

        if (strcmp(line, "quit") == 0) break;

        if (strncmp(line, "STREAM ", 7) == 0) {
            int n = 0, wait_reply = 0; double rate = 0.0;
            if (sscanf(line + 7, "%d %lf %d", &n, &rate, &wait_reply) < 2 || n <= 0 || rate <= 0.0) {
                printf("Usage: STREAM <packets> <rate_per_s> [wait]\n"); continue;
            }
            stream_run(n, rate, wait_reply);
            continue;
        }

        if (strncmp(line, "GET ", 4) == 0) {
            const char *key = line + 4;
            if (!strlen(key)) { printf("Usage: GET <key>\n"); continue; }

            /* Complete the live handshake with an online Sender before
             * fetching the (encrypted) stored blob, see
             * perform_content_handshake()'s comment. */
            double v17_req_start = v17_now_s();
            aes_key_t k_content;
            if (perform_content_handshake(key, &k_content) != 0) {
                printf("[Client] Could not establish a content key with the "
                       "Sender for '%s', it may be offline or never "
                       "uploaded this key (see error above).\n\n", key);
                continue;
            }

            if (send_get(key) != 0) {
                printf("[Client] Request failed.\n"); continue;
            }

            uint8_t  resp[MAX_INNER_PAYLOAD];
            uint16_t resp_len = 0;

            if (wait_response(resp, &resp_len, 10000) == 0) {
                v17_cal_log(v17_req_start, v17_now_s(), (unsigned)resp_len);
                /* Verify the Sender's signature and TOFU-pin before ever
                 * showing content as if it were authentic, see
                 * verify_signed_content()'s comment for what this closes. */
                static uint8_t g_decrypted_content[MAX_INNER_PAYLOAD];
                const uint8_t *content = NULL;
                size_t content_len = 0;
                if (verify_signed_content(key, resp, resp_len, &k_content,
                                          g_decrypted_content, sizeof(g_decrypted_content),
                                          &content, &content_len) == 0) {
                    printf("\n[Client] Response (%zu bytes, signature verified, "
                           "confidentiality-protected):\n", content_len);
                    printf("-------------------------------------\n");
                    printf("%.*s\n", (int)content_len, content);
                    printf("-------------------------------------\n\n");
                } else {
                    printf("[Client] Response REJECTED, integrity check failed, "
                           "content NOT shown (see error above).\n\n");
                }
            } else {
                printf("[Client] No response (timeout).\n\n");
            }
        } else if (len > 0) {
            printf("Unknown command.\n");
        }
    }
}

/* main */
int main(void) {
    SetConsoleOutputCP(65001);
    v17_cal_open();
    InitializeCriticalSection(&g_resp_lock);
#ifdef ASN_LOOPIX_MIXING
    InitializeCriticalSection(&g_mailbox_lock);
#endif
    g_resp_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!g_resp_event) return 1;

    if (net_init() != 0) return 1;
    CreateDirectoryA(PUBKEY_DIR, NULL);
    log_msg("Anon-Sec-Net v2 client starting...");

    if (node_pool_init() != 0) {
        log_err("node pool init failed"); net_cleanup(); return 1;
    }
    if (stripe_config_init() != 0) { net_cleanup(); return 1; }
    rate_tier_init();

    if (build_paths() != 0) {
        log_err("path build failed, ensure all mix nodes and SG are running");
        net_cleanup(); return 1;
    }

    /* Started ahead of send_setup(): send_setup() blocks
     * on wait_response() for a genuine SETUP acknowledgment (see its
     * comment for why), the listener has to already be running to
     * catch that ack, or every session would time out on its own first
     * request. g_state.k_r_sg_b (which response_listener() needs to
     * decrypt anything) is already set by build_paths(), so starting
     * the listener here is safe. */
    HANDLE lt = CreateThread(NULL, 0, response_listener, NULL, 0, NULL);
    if (!lt) { log_err("listener thread failed"); return 1; }
    CloseHandle(lt);

    if (send_setup() != 0) {
        log_err("session setup failed"); return 1;
    }

    if (!getenv("ASN_COVER_OFF")) {
        HANDLE ct = CreateThread(NULL, 0, outbound_cover_thread, NULL, 0, NULL);
        if (ct) CloseHandle(ct);
    }

    Sleep(200);
    run_interactive();

    DeleteCriticalSection(&g_resp_lock);
#ifdef ASN_LOOPIX_MIXING
    DeleteCriticalSection(&g_mailbox_lock);
#endif
    CloseHandle(g_resp_event);
    if (g_v17_cal) { fclose(g_v17_cal); g_v17_cal = NULL; }
    net_cleanup();
    return 0;
}