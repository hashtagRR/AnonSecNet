/* mix_node.c: Generic Mix Node (Anon-Sec-Net v2)
 *
 * One binary, twelve instances:
 *   Client sending path:    9004(MN1) 9005(MN2) 9006(MN3)
 *   Client receiving path:  9007(MNa) 9008(MNb) 9009(MNc)
 *   Sender sending path:    9040(MNi) 9041(MNii) 9042(MNiii)
 *   Sender receiving path:  9043(MNx) 9044(MNy) 9045(MNz)
 *
 * Modes:
 *   MODE_EXTEND (0x01), ECDHE handshake during path construction
 *   MODE_DATA   (0x02), Sphinx forward: peel header, blind payload
 *   MODE_RETURN (0x03), Return path: peel return header, forward
 */

#include "common/net.h"
#include "common/crypto.h"
#include "common/packet.h"
#include "common/config.h"
#include "common/node_pool.h"

#include <openssl/rand.h>
#include <math.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include "common/posix_compat.h"

/* Opt-in packet-order probe, off unless ASN_TRACKA_PROBE=1 is set.
 * Zero behavior change otherwise. */
static FILE            *g_order_fp   = NULL;
static CRITICAL_SECTION g_order_lock;

static void order_probe_init(uint16_t my_port) {
    if (!getenv("ASN_TRACKA_PROBE")) return;
    char fname[64];
    snprintf(fname, sizeof(fname), "packet_order_%u.csv", (unsigned)my_port);
    InitializeCriticalSection(&g_order_lock);
    g_order_fp = fopen(fname, "a");
    if (g_order_fp)
        fprintf(g_order_fp, "# node-sharing live-testbed probe, temporary, "
                             "not used by any figure\n"
                             "event,ts_us,sess_idx,port\n");
}

static void order_probe_log(const char *event, int sess_idx, uint16_t port) {
    if (!g_order_fp) return;
    LARGE_INTEGER freq, now;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&now);
    double ts_us = (double)now.QuadPart * 1e6 / (double)freq.QuadPart;
    EnterCriticalSection(&g_order_lock);
    fprintf(g_order_fp, "%s,%.3f,%d,%u\n", event, ts_us, sess_idx, (unsigned)port);
    fflush(g_order_fp);
    LeaveCriticalSection(&g_order_lock);
}

/* Session store */
#define MAX_SESSIONS 1024

/* Bounded per-session replay window: how many recent nonces a mix node
 * remembers before the oldest is evicted. A replay delayed past this
 * many real packets in the same session will not be caught, a real,
 * documented limitation of a fixed-memory cache, not a claim of
 * unconditional replay-resistance.
 *
 * A larger window requires more real packets' worth of session
 * activity to evict a target nonce before a delayed replay could slip
 * through, at a bounded, modest memory cost (MAX_SESSIONS * WINDOW *
 * (NONCE_BYTES + RETURN_NONCE_BYTES) =~ 12MB worst case, all sessions
 * live and full). The per-packet check is a linear memcmp scan over the
 * window (session_seen_nonce()/session_seen_return_nonce() below); this
 * runs once per matched session, not per session scanned, so it stays
 * microsecond-scale. */
#define REPLAY_WINDOW 1024

typedef struct {
    aes_key_t header_enc_key;
    aes_key_t header_mac_key;
    aes_key_t return_blind_key; /* == blind_key, derived from master via
                                  * packet_derive_hop_keys(): see
                                  * split_master_keys(); cancels one layer
                                  * of the SG's return-path pre-blinding
                                  * in handle_return().                  */
    uint8_t   role;
    /* Replay-detection: ring buffer of the last REPLAY_WINDOW nonces seen
     * on MODE_DATA packets for this session (see header_block_t's
     * enc_nonce field in packet.h). */
    uint8_t   seen_nonces[REPLAY_WINDOW][NONCE_BYTES];
    int       seen_count;
    int       seen_next;
    /* Same idea, separate cache, for MODE_RETURN packets (see
     * return_block_t's enc_nonce field in packet.h, a smaller
     * RETURN_NONCE_BYTES value, so a separate array/type). */
    uint8_t   seen_return_nonces[REPLAY_WINDOW][RETURN_NONCE_BYTES];
    int       seen_return_count;
    int       seen_return_next;
    int       in_use;
    DWORD     last_active_ms; /* GetTickCount() at alloc and every touch;
                                * used by session_alloc() to reclaim a
                                * stale slot once the table fills up,
                                * see SESSION_TTL_MS below. */
    /* Rotating hint state, for both role-A (forward-path, MODE_DATA) and
     * role-B (return-path, MODE_RETURN) sessions. See config.h's
     * HINT_WINDOW comment and session_init_hint_window()/
     * session_advance_hint_window() below.
     *
     * Two independent windows, not one: index 0 is the real-packet
     * counter domain (0..), index 1 is the cover-packet domain
     * (HINT_COVER_COUNTER_BASE..). A hop that never sees cover traffic
     * (MN2/MN3, since cover is dropped at the entry hop) never advances
     * domain 1, domain 0 then only ever slides on the real packets
     * this hop actually forwards, so it can't desync from them the way
     * a single shared window could. Role-B sessions have no
     * hint-matched cover traffic at all (see session_find()'s comment),
     * so domain 1 simply never matches for them. */
    aes_key_t hint_seed;
    uint64_t  hint_base[2];                       /* lowest counter still in the window, per domain */
    uint8_t   hint_window[2][HINT_WINDOW][HINT_BYTES]; /* precomputed hint_base..+WINDOW-1, per domain */
    uint64_t  hint_high_water[2];  /* Tracks the HIGHEST counter ever
                                     * matched (not just the last one), so
                                     * hint_base only slides forward far
                                     * enough to stay HINT_SAFETY_MARGIN
                                     * behind it, never past a position
                                     * that might still be in flight behind
                                     * a later packet that arrived and
                                     * matched first (pool-mixing's
                                     * batching can reorder packets this
                                     * way). Safe to leave matched
                                     * positions un-pruned: a hint value
                                     * can't legitimately recur
                                     * (HMAC(seed, counter), counter never
                                     * reused by an honest sender), and an
                                     * actual replay is caught by the
                                     * independent, nonce-based
                                     * session_seen_nonce() check
                                     * regardless of hint-window state. */
    uint32_t  generation;   /* Decouples "was this slot reclaimed for a
                              * different session" (the only thing that
                              * needs checking, see session_alloc()'s
                              * reclaim path) from re-validating against a
                              * single mutable last-matched-hint field,
                              * which breaks once pool-mixing releases
                              * many same-session packets via parallel
                              * worker threads: two concurrent threads
                              * processing different, both legitimate,
                              * packets for the same session would
                              * otherwise clobber each other's state and
                              * one would see a false "replay." Incremented
                              * once per allocation (session_alloc()),
                              * stable for a slot's entire lifetime
                              * regardless of how many concurrent packets
                              * for the same session are in flight,
                              * session_find() hands the caller
                              * (idx, generation) to carry forward instead
                              * of (idx, hint). */
} session_entry_t;

/* No session in this prototype's demo track lives anywhere near this
 * long in practice (a single GET/PUT round trip is milliseconds); this
 * is a backstop against unbounded slot exhaustion (a session that never
 * completes, or a client that vanishes mid-handshake), not a claim
 * about real-world session lifetime. */
#define SESSION_TTL_MS (5U * 60U * 1000U)

/* Returns 1 and drops nothing if `nonce` was already seen for `sess`
 * (caller should drop the packet); otherwise records it and returns 0. */
static int session_seen_nonce(session_entry_t *sess, const uint8_t nonce[NONCE_BYTES]) {
    for (int i = 0; i < sess->seen_count; i++) {
        if (memcmp(sess->seen_nonces[i], nonce, NONCE_BYTES) == 0)
            return 1;
    }
    memcpy(sess->seen_nonces[sess->seen_next], nonce, NONCE_BYTES);
    sess->seen_next = (sess->seen_next + 1) % REPLAY_WINDOW;
    if (sess->seen_count < REPLAY_WINDOW) sess->seen_count++;
    return 0;
}

/* Same as session_seen_nonce(), for the return-path nonce cache. */
static int session_seen_return_nonce(session_entry_t *sess,
                                     const uint8_t nonce[RETURN_NONCE_BYTES]) {
    for (int i = 0; i < sess->seen_return_count; i++) {
        if (memcmp(sess->seen_return_nonces[i], nonce, RETURN_NONCE_BYTES) == 0)
            return 1;
    }
    memcpy(sess->seen_return_nonces[sess->seen_return_next], nonce, RETURN_NONCE_BYTES);
    sess->seen_return_next = (sess->seen_return_next + 1) % REPLAY_WINDOW;
    if (sess->seen_return_count < REPLAY_WINDOW) sess->seen_return_count++;
    return 0;
}

static session_entry_t  g_sessions[MAX_SESSIONS];
static CRITICAL_SECTION g_session_lock;

/* Key material a caller needs after lookup, copied out while the lock is
 * held rather than read later from a raw pointer: a concurrent
 * session_alloc() reclaiming that exact slot (memset under lock) could
 * otherwise hand back a torn or entirely different session's keys.
 * Copying immutable key material out under the lock is safe regardless
 * of what happens to the slot afterward; anything that needs to touch
 * live/mutable session state (the nonce caches) re-validates the
 * slot's identity under lock again via
 * session_check_nonce_by_idx()/session_check_return_nonce_by_idx()
 * below, rather than trusting a stale pointer. */
typedef struct {
    aes_key_t header_enc_key;
    aes_key_t header_mac_key;
    aes_key_t return_blind_key;
} session_keys_t;

/* Rotating hint window. Caller must hold g_session_lock. See config.h's
 * HINT_WINDOW comment for the full design. */

/* Populate a freshly-allocated session's windows with the first
 * HINT_WINDOW precomputed hint values in each domain: real (counters
 * 0..HINT_WINDOW-1) and cover (HINT_COVER_COUNTER_BASE..+HINT_WINDOW-1).
 * See the comment on session_entry_t above for why there are two. */
static void session_init_hint_window(session_entry_t *sess,
                                      const aes_key_t *hint_seed) {
    sess->hint_seed = *hint_seed;
    sess->hint_base[0] = 0;
    sess->hint_base[1] = HINT_COVER_COUNTER_BASE;
    /* UINT64_MAX as an explicit "nothing matched yet" sentinel, NOT
     * hint_base-1, which underflows to UINT64_MAX anyway for domain 0
     * (hint_base[0]==0) and would then compare falsely-not-greater
     * against the genuine first match at counter 0, silently failing to
     * register it. Checked explicitly in session_advance_hint_window(). */
    sess->hint_high_water[0] = UINT64_MAX;
    sess->hint_high_water[1] = UINT64_MAX;
    for (int d = 0; d < 2; d++)
        for (int w = 0; w < HINT_WINDOW; w++)
            packet_derive_hop_hint(hint_seed, sess->hint_base[d] + (uint64_t)w,
                                   sess->hint_window[d][w]);
}

/* A packet matched at window offset `consumed_through` (0-based) in
 * domain `domain` (0=real, 1=cover). The other domain is untouched: this
 * keeps a hop that never sees cover traffic (MN2/MN3) from having its
 * real-domain window disturbed by cover packets it will never observe.
 *
 * High-water-mark policy (HINT_SAFETY_MARGIN, config.h): tracks the
 * highest counter ever matched, and only slides hint_base forward far
 * enough to stay HINT_SAFETY_MARGIN behind it, so a later packet
 * matching before an earlier one (which pool-mixing's batching does
 * routinely) never destroys a still-in-flight packet's hint slot. Only
 * recomputes the window when base actually moves. Safe to never prune
 * already-matched positions from the window: the hint value itself
 * can't legitimately recur, and genuine replays are caught
 * independently, by nonce, in
 * session_check_nonce_by_idx()/session_check_return_nonce_by_idx(). */
static void session_advance_hint_window(session_entry_t *sess, int domain,
                                        int consumed_through) {
    uint64_t matched_abs = sess->hint_base[domain] + (uint64_t)consumed_through;
    if (sess->hint_high_water[domain] == UINT64_MAX ||
        matched_abs > sess->hint_high_water[domain]) {
        sess->hint_high_water[domain] = matched_abs;
    }

    uint64_t desired_base = (sess->hint_high_water[domain] >= HINT_SAFETY_MARGIN)
        ? sess->hint_high_water[domain] - HINT_SAFETY_MARGIN + 1
        : 0;
    if (desired_base <= sess->hint_base[domain]) return;  /* no slide needed */

    sess->hint_base[domain] = desired_base;
    for (int w = 0; w < HINT_WINDOW; w++)
        packet_derive_hop_hint(&sess->hint_seed, desired_base + (uint64_t)w,
                               sess->hint_window[domain][w]);
}

/* Returns the session index (>=0) on match with *out_keys populated, or
 * -1 if not found. *out_generation is set to the slot's generation
 * counter at match time, see session_entry_t's comment for why this
 * replaced a last-matched-hint comparison. */
static int session_find(const uint8_t hint[HINT_BYTES], session_keys_t *out_keys,
                        int *out_domain, int *out_window_idx, uint32_t *out_generation) {
    EnterCriticalSection(&g_session_lock);
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_sessions[i].in_use) continue;

        /* Hint rotates every packet, both forward and return, scan
         * the precomputed window instead of one static value, for both
         * roles. Two independent domains (real, cover): try both,
         * advance only whichever one actually matched. Role B never
         * populates domain 1 (return-path has no hint-matched cover
         * traffic: inbound cover is raw bytes injected locally at the
         * last hop, never looked up by hint), so that domain simply
         * never matches for a role-B session. */
        int matched = 0;
        for (int d = 0; d < 2 && !matched; d++) {
            for (int w = 0; w < HINT_WINDOW; w++) {
                if (crypto_memcmp(g_sessions[i].hint_window[d][w], hint, HINT_BYTES) == 0) {
                    /* Do not advance the window here: if the packet then
                     * fails MAC verification in the caller, a forged
                     * packet that merely guessed/replayed a hint value
                     * would still have consumed a real window slot,
                     * shrinking the legitimate window's effective size.
                     * The caller calls session_confirm_hint_match() to
                     * perform the advance, only once MAC verification
                     * has actually succeeded. */
                    if (out_domain)     *out_domain     = d;
                    if (out_window_idx) *out_window_idx = w;
                    if (out_generation) *out_generation = g_sessions[i].generation;
                    matched = 1;
                    break;
                }
            }
        }

        if (matched) {
            g_sessions[i].last_active_ms = GetTickCount();
            if (out_keys) {
                out_keys->header_enc_key   = g_sessions[i].header_enc_key;
                out_keys->header_mac_key   = g_sessions[i].header_mac_key;
                out_keys->return_blind_key = g_sessions[i].return_blind_key;
            }
            int idx = i;
            LeaveCriticalSection(&g_session_lock);
            return idx;
        }
    }
    LeaveCriticalSection(&g_session_lock);
    return -1;
}

/* Called only after MAC verification of the matched packet has
 * succeeded, to perform the window advance session_find() itself
 * defers. Re-validates slot identity under lock first (the slot could
 * have been reclaimed for a different session between session_find()
 * and this call), so a stale idx/domain/window_idx triple is a safe
 * no-op rather than corrupting an unrelated session's window.
 *
 * Re-validates via `generation`, not a last-matched-hint comparison,
 * see session_entry_t's comment for why the hint-comparison version
 * broke under pool-mixing's concurrent same-session packet processing. */
static void session_confirm_hint_match(int idx, uint32_t generation,
                                       int domain, int window_idx) {
    EnterCriticalSection(&g_session_lock);
    if (g_sessions[idx].in_use && g_sessions[idx].generation == generation) {
        session_advance_hint_window(&g_sessions[idx], domain, window_idx);
    }
    LeaveCriticalSection(&g_session_lock);
}

/* Re-validates that g_sessions[idx] is still the same session (by
 * generation, not hint, see session_entry_t's comment) before checking/
 * recording the nonce, guarding against the slot having been reclaimed
 * for a different session between session_find() and this call. Returns
 * 1 if the packet should be dropped (replay, or the slot no longer
 * matches: treated the same way: do not forward), 0 if OK. */
static int session_check_nonce_by_idx(int idx, uint32_t generation,
                                       const uint8_t nonce[NONCE_BYTES]) {
    EnterCriticalSection(&g_session_lock);
    int drop = 1;
    int identity_ok = 0;
    if (g_sessions[idx].in_use) {
        identity_ok = (g_sessions[idx].generation == generation);
    }
    if (identity_ok) {
        drop = session_seen_nonce(&g_sessions[idx], nonce);
    }
    LeaveCriticalSection(&g_session_lock);
    return drop;
}

/* Same generation-based re-validation as session_check_nonce_by_idx()
 * above, for the return path. */
static int session_check_return_nonce_by_idx(int idx, uint32_t generation,
                                              const uint8_t nonce[RETURN_NONCE_BYTES]) {
    EnterCriticalSection(&g_session_lock);
    int drop = 1;
    if (g_sessions[idx].in_use && g_sessions[idx].generation == generation) {
        drop = session_seen_return_nonce(&g_sessions[idx], nonce);
    }
    LeaveCriticalSection(&g_session_lock);
    return drop;
}

/* Returns with g_session_lock HELD on a non-NULL return: handle_extend()
 * populates hint_seed/header_enc_key/etc after this, and a concurrent
 * session_find() table scan must not observe in_use=1 with those fields
 * still zeroed from the memset below. Caller MUST
 * LeaveCriticalSection(&g_session_lock) itself once population is done; a
 * NULL return means the lock has already been released (nothing to
 * populate). */
static session_entry_t *session_alloc(void) {
    EnterCriticalSection(&g_session_lock);
    DWORD now = GetTickCount();
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_sessions[i].in_use) {
            uint32_t gen = g_sessions[i].generation;
            memset(&g_sessions[i], 0, sizeof(g_sessions[i]));
            g_sessions[i].in_use = 1;
            g_sessions[i].last_active_ms = now;
            g_sessions[i].generation = gen + 1;
            return &g_sessions[i];
        }
    }
    /* Table full: reclaim the oldest slot past SESSION_TTL_MS rather than
     * refuse every subsequent client for the lifetime of the process,
     * a session that never completes (dead client, dropped setup) would
     * otherwise permanently burn a slot. Reclaiming the single oldest
     * expired slot (not all of them) keeps this a graceful degrade under
     * genuine load rather than a mass-eviction storm. */
    int oldest_idx = -1;
    DWORD oldest_age = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        DWORD age = now - g_sessions[i].last_active_ms; /* wraps safely (unsigned) */
        if (age >= SESSION_TTL_MS && age >= oldest_age) {
            oldest_age = age;
            oldest_idx = i;
        }
    }
    if (oldest_idx >= 0) {
        uint32_t gen = g_sessions[oldest_idx].generation;
        memset(&g_sessions[oldest_idx], 0, sizeof(g_sessions[oldest_idx]));
        g_sessions[oldest_idx].in_use = 1;
        g_sessions[oldest_idx].last_active_ms = now;
        g_sessions[oldest_idx].generation = gen + 1;
        return &g_sessions[oldest_idx];
    }
    LeaveCriticalSection(&g_session_lock);
    return NULL;
}

/* Node keypair */
static ecdh_keypair_t g_node_kp = {0};
static ecdh_keypair_t g_identity_kp = {0}; /* Stable across restarts,
                                             * unlike g_node_kp, see
                                             * crypto.h's comment above
                                             * crypto_identity_load_or_create(). */
static CRITICAL_SECTION g_node_kp_lock;

/* g_node_kp is rotated on a timer (node_key_rotation_thread() below)
 * for forward secrecy: the retired key is explicitly destroyed
 * (crypto_ecdh_free(), which zeroes the private key material via
 * OpenSSL's own EC key destructor) the moment it's replaced, so a later
 * compromise of the process can't recover sessions handshaked before
 * the last rotation. 5 minutes is a judgment call: short enough to
 * bound exposure meaningfully for this prototype's session-scale (a
 * single GET/PUT round trip is milliseconds), long enough that rotation
 * overhead (one ECDH keygen) stays negligible next to genuine traffic
 * volume. Every handshake (handle_extend()) that reads g_node_kp must
 * hold g_node_kp_lock for the duration of its crypto_ecdh_derive() call
 * (fast, pure computation, no I/O, cheap to hold a lock across), so a
 * rotation can never swap the key out from under a handshake that is
 * mid-computation. */
#define NODE_KEY_ROTATION_MS (5U * 60U * 1000U)
static char g_pubkey_path[256] = {0}; /* set once in main(), read by the
                                        * rotation thread to keep the
                                        * on-disk copy current, this
                                        * file is not actually read by any
                                        * client for the live protocol
                                        * (recv_signed_descriptor() always
                                        * fetches the pubkey fresh over
                                        * the wire per-connection), it is
                                        * kept in sync purely so a human/
                                        * tooling inspecting it sees the
                                        * node's actual current key. */

/* node_key_rotation_thread() itself is defined further down, after
 * log_msg()/g_my_port_global are declared, see there. */

/* Per-connection context */
typedef struct {
    SOCKET   client_sock;
    uint16_t my_port;
} conn_ctx_t;

/* Logging */
static void log_msg(uint16_t port, const char *msg) {
    printf("[MN:%u] %s\n", port, msg); fflush(stdout);
}
static void log_err(uint16_t port, const char *msg) {
    fprintf(stderr, "[MN:%u] ERROR: %s\n", port, msg); fflush(stderr);
}

/* Per-packet routing-decision logging (next-hop port for every
 * forwarded packet). On by default, opt out with ASN_QUIET_ROUTING=1. */
static int routing_log_enabled(void) {
    static int cached = -1;
    if (cached < 0) {
        const char *env = getenv("ASN_QUIET_ROUTING");
        cached = !(env && env[0] == '1' && env[1] == '\0');
    }
    return cached;
}
static void log_routing(uint16_t port, const char *msg) {
    if (routing_log_enabled()) log_msg(port, msg);
}

/* handle_data()/handle_return() connect() to whatever IP:port a peeled
 * routing block contains. The MAC gate alone doesn't bound this: the
 * client legitimately drives path construction and holds every hop's
 * header_mac_key by design (that's how Sphinx-style source routing
 * works), so it can produce a validly-MAC'd routing block naming an
 * arbitrary destination for any hop on its own path. Since this is a
 * loopback prototype with a small, fully-enumerable set of legitimate
 * destinations (every mix node, SG, CS, and the two client/sender
 * response ports, all bound to 127.0.0.1, see node_pool.h/config.h),
 * an allowlist bounds it directly. */
static int is_allowed_next_hop(const char *ip, uint16_t port) {
    if (strcmp(ip, LOCALHOST) != 0) return 0;
    if (port == PORT_SERVICE_GW || port == PORT_CACHE_SERVER) {
        return 1;
    }
    /* CLIENT_RESPONSE_PORT is the base of a small, fixed, enumerated
     * range (config.h's CLIENT_RESPONSE_PORT_COUNT), not a single
     * constant: still a bounded allowlist, not an arbitrary-port
     * opening. */
    if (port >= CLIENT_RESPONSE_PORT &&
        port <  CLIENT_RESPONSE_PORT + CLIENT_RESPONSE_PORT_COUNT) {
        return 1;
    }
    /* Same shape for SENDER_RESPONSE_PORT (config.h's
     * SENDER_RESPONSE_PORT_COUNT). */
    if (port >= SENDER_RESPONSE_PORT &&
        port <  SENDER_RESPONSE_PORT + SENDER_RESPONSE_PORT_COUNT) {
        return 1;
    }
    /* Sender's fixed-topology path (untouched by node_pool, see
     * start_nodes_pool.sh's own comment). */
    if (port == PORT_MIX_I || port == PORT_MIX_II || port == PORT_MIX_III ||
        port == PORT_MIX_X || port == PORT_MIX_Y  || port == PORT_MIX_Z) {
        return 1;
    }
    /* Legacy fixed 12-port topology, still used by the instrumented
     * benchmark harness's own build of this same handler logic paths,
     * not reachable through mix_node.c's own handle_return() in the
     * node_pool configuration, but harmless to also allow here since
     * these ports are never anything other than another mix node. */
    if (port == PORT_MIX_1 || port == PORT_MIX_2 || port == PORT_MIX_3 ||
        port == PORT_MIX_A || port == PORT_MIX_B || port == PORT_MIX_C) {
        return 1;
    }
    /* node_pool.h's dynamic pool: POOL_PORT_BASE..POOL_PORT_BASE+POOL_SIZE-1. */
    if (port >= POOL_PORT_BASE && port < POOL_PORT_BASE + POOL_SIZE) return 1;
    return 0;
}

/* Key splitting from ECDH master
 *
 * packet_sphinx_build() and packet_sphinx_peel() use header_enc_key,
 * header_mac_key, and blind_key DIRECTLY, no internal re-derivation.
 *
 * Both client and node do ECDH and arrive at the same 32-byte master.
 * Three independent keys are produced by packet_derive_hop_keys()
 * (labelled-PRF KDF: AES-256-CTR(master, SHA256(label)) per purpose,
 * see packet.c/.h), not byte-rotation of the master, which would be
 * invertible (any one of the three trivially yielding the other two).
 *
 * The client stores these in sphinx_path_t.hops[i] before calling
 * packet_sphinx_build(). The node stores the same values here so that
 * packet_sphinx_peel() MAC verification succeeds.
 *
 * For a receiving-path hop (MNc/MNb/MNa), this same blind_key is ALSO
 * used as the node's return-path unblinding key (stored as
 * session_entry_t.return_blind_key): the client sends the identical
 * value to the SG as one of the "recv_blind" pre-blinding keys (see
 * client.c::send_setup(), which sends g_state.recv_hops[i].blind_key,
 * the very same packet_derive_hop_keys() output, not a separate
 * derivation). Both sides compute this independently from the shared
 * ECDH master, so no extra key material needs to travel on the wire for
 * return-path blinding/unblinding to work, see
 * service_gateway.c::send_response() and this file's handle_return().
 *
 * This must stay in sync with client_instrumented.c::derive_hop_send()/
 * derive_hop_recv() and client.c::derive_hop().
 */
static void split_master_keys(const aes_key_t *master,
                              aes_key_t *henc,
                              aes_key_t *hmac_key,
                              aes_key_t *bkey) {
    /* Real independent-label KDF (packet_derive_hop_keys), not a
     * byte-rotation of master, a byte-rotation is invertible, so any
     * one of the three keys would yield the other two. See packet.c. */
    packet_derive_hop_keys(master, henc, hmac_key, bkey);
}

/* ASN_HOP_DECOY measurement probe (scratch, not gated by any build flag so
 * it works identically across plain/hardened/hopdecoy binaries for an
 * apples-to-apples comparison). Opt-in via ASN_HOPDECOY_TRACE=1, when
 * unset (the default, every existing measurement/deployment), this is a
 * single getenv() call and nothing else; no behavior change, no file I/O.
 * Logs one line per packet that reaches this point in handle_data() (i.e.
 * survived MAC verification and the replay check, the same point a
 * compromised node's own observation would begin), to
 * /tmp/hopdecoy_trace_<port>.csv, columns: sess_idx,t_ms. This captures
 * ARRIVAL, not the later forward/drop decision, what a compromised node
 * sees is what arrives at it, regardless of what it then chooses to do. */
static int hopdecoy_trace_enabled(void) {
    static int cached = -1;
    if (cached < 0) cached = (getenv("ASN_HOPDECOY_TRACE") != NULL) ? 1 : 0;
    return cached;
}

/* The return direction (handle_return) logs to its own file,
 * /tmp/hopdecoy_trace_ret_<port>.csv, same columns, so forward-only
 * scorers keep reading the forward file unchanged. */
static void hopdecoy_trace_log_to(const char *prefix, uint16_t my_port, int sess_idx) {
    if (!hopdecoy_trace_enabled()) return;
    /* ASN_TRACE_DIR moves the trace files off /tmp (a RAM-backed tmpfs on
     * some systems, where long runs exhaust memory); default /tmp. */
    const char *dir = getenv("ASN_TRACE_DIR");
    char path[512];
    snprintf(path, sizeof(path), "%s/%s_%u.csv", dir ? dir : "/tmp", prefix, (unsigned)my_port);
    FILE *f = fopen(path, "a");
    if (!f) return;
    fprintf(f, "%d,%llu\n", sess_idx, (unsigned long long)GetTickCount64());
    fclose(f);
}

static void hopdecoy_trace_log(uint16_t my_port, int sess_idx) {
    hopdecoy_trace_log_to("hopdecoy_trace", my_port, sess_idx);
}

/* Forward reference: actually defined (with its initializer) further
 * down, alongside log_msg(), see that declaration's own comment. A
 * plain re-declaration here (tentative definition, valid C) is enough
 * for pool_mix_worker() below to use it for logging. */
static uint16_t g_my_port_global;

#ifdef ASN_POOL_MIXING
/* Genuine batch/pool mixing: batches every packet that finishes peeling
 * within a fixed flush window, then releases the whole batch together
 * in RAND_bytes-shuffled order, reordering at the scale of the flush
 * window itself, not per-packet delay's much smaller scale.
 *
 * session_find() matches against a HINT_WINDOW-sized rotating
 * forward-looking window per session, a packet arriving more than
 * HINT_WINDOW counter positions behind the highest already matched for
 * its session is silently dropped (note_hint_miss()), not merely
 * delayed, so HINT_WINDOW and POOL_MIX_FLUSH_MS must stay tuned
 * together: HINT_WINDOW=64 (config.h) with a 250ms flush window keeps
 * reordering small enough per batch that this doesn't happen under
 * load. Re-verify actual note_hint_miss() counts under load after
 * changing either value. */
#define POOL_MIX_MAX_BATCH 8192
#ifndef POOL_MIX_FLUSH_MS
#define POOL_MIX_FLUSH_MS  250
#endif

typedef struct {
    wire_packet_t pkt;
    uint16_t      next_port;
    int           sess_idx;
} pool_entry_t;

static pool_entry_t     *g_pool = NULL;
static int               g_pool_count = 0;
static CRITICAL_SECTION  g_pool_lock;
static volatile int      g_pool_stop = 0;

static void pool_mix_init(void) {
    g_pool = malloc(sizeof(pool_entry_t) * POOL_MIX_MAX_BATCH);
    InitializeCriticalSection(&g_pool_lock);
}

/* Returns 0 on success, -1 if the pool is full (packet dropped). sess_idx
 * is needed only so the flush thread's shuffle (below) can preserve each
 * session's own relative packet order while still randomizing which
 * session's traffic is interleaved when, see pool_mix_shuffle_stratified()'s
 * comment for why that distinction is load-bearing, not cosmetic. */
static int pool_mix_enqueue(const wire_packet_t *pkt, uint16_t next_port, int sess_idx) {
    int ok = 0;
    EnterCriticalSection(&g_pool_lock);
    if (g_pool_count < POOL_MIX_MAX_BATCH) {
        g_pool[g_pool_count].pkt       = *pkt;
        g_pool[g_pool_count].next_port = next_port;
        g_pool[g_pool_count].sess_idx  = sess_idx;
        g_pool_count++;
        ok = 1;
    }
    LeaveCriticalSection(&g_pool_lock);
    return ok ? 0 : -1;
}

/* RAND_bytes, not rand(), see mix_delay_sleep()'s identical rationale
 * above: a predictable shuffle defeats the entire point of pool mixing,
 * since an adversary who can predict the permutation can just undo it. */
static uint32_t pool_mix_rand_u32(void) {
    uint32_t r;
    if (RAND_bytes((uint8_t *)&r, sizeof(r)) != 1) r = 1;
    return r;
}

/* Stratified shuffle: randomizes which SESSION's packet is released at
 * each output position, but preserves each session's own relative
 * order: a plain flat Fisher-Yates over the whole batch can release a
 * session's own later packet before its earlier one, and
 * session_advance_hint_window() slides the window forward to just past
 * whatever was just matched, so an out-of-order release would drop the
 * earlier packet regardless of window size.
 *
 * `batch`/`n` (input) are in arrival order, which approximates each
 * session's own counter order (the same assumption HINT_WINDOW already
 * relied on before pool-mixing existed), a per-session forward linked
 * list built directly over that order, then randomly interleaved across
 * sessions, is what keeps that assumption true for the FINAL release
 * order too. `out` receives the n reordered entries. Uses `static`
 * scratch arrays sized MAX_SESSIONS/POOL_MIX_MAX_BATCH, safe only
 * because pool_mix_flush_thread is the single, sole caller (one flush
 * thread per process, never called concurrently with itself). */
static void pool_mix_shuffle_stratified(pool_entry_t *batch, int n, pool_entry_t *out) {
    static int head[MAX_SESSIONS];
    static int tail[MAX_SESSIONS];
    static int next_link[POOL_MIX_MAX_BATCH];
    static int active[MAX_SESSIONS];
    int n_active = 0;

    for (int i = 0; i < MAX_SESSIONS; i++) { head[i] = -1; tail[i] = -1; }

    for (int i = 0; i < n; i++) {
        int s = batch[i].sess_idx;
        if (s < 0 || s >= MAX_SESSIONS) s = 0;  /* defensive only */
        next_link[i] = -1;
        if (head[s] == -1) {
            head[s] = i;
            active[n_active++] = s;
        } else {
            next_link[tail[s]] = i;
        }
        tail[s] = i;
    }

    static int cur[MAX_SESSIONS];
    for (int i = 0; i < n_active; i++) cur[active[i]] = head[active[i]];

    int out_count = 0;
    while (n_active > 0) {
        int pick = (int)(((double)pool_mix_rand_u32() / 4294967296.0) * n_active);
        if (pick >= n_active) pick = n_active - 1;
        int s   = active[pick];
        int idx = cur[s];
        out[out_count++] = batch[idx];
        int nxt = next_link[idx];
        if (nxt == -1) {
            active[pick] = active[n_active - 1];
            n_active--;
        } else {
            cur[s] = nxt;
        }
    }
}

/* Released across a worker-thread pool, not one thread looping
 * serially: loopback TCP connect/send/close overhead does not amortize
 * the way it does for organically-arriving traffic, and a serial
 * release of a large batch would take seconds against a sub-second
 * flush budget. The batch is already shuffled before this point, so
 * which worker sends which entry has no bearing on the randomization
 * already applied. */
#define POOL_MIX_MAX_WORKERS 64

typedef struct {
    pool_entry_t *batch;
    int           start, end;
    uint16_t      my_port;
} pool_mix_worker_arg_t;

/* Under heavy concurrent load (many mix_node processes running at once,
 * each with up to POOL_MIX_MAX_WORKERS threads all connect()-ing in a
 * burst at every flush), connect() can fail transiently. A bounded
 * retry plus visible counting, log every failure up to 10, then every
 * 100th: keeps this loss mode measurable rather than silent. */
static volatile LONG g_pool_connect_fail_count = 0;
static void note_pool_connect_fail(uint16_t port) {
    LONG n = InterlockedIncrement(&g_pool_connect_fail_count);
    if (n <= 10 || n % 100 == 0) {
        char buf[96];
        snprintf(buf, sizeof(buf), "pool-mix: connect failed after retries "
                 "(cumulative: %ld)", (long)n);
        log_err(port, buf);
    }
}

#define POOL_MIX_CONNECT_RETRIES 3

static DWORD WINAPI pool_mix_worker(LPVOID arg) {
    pool_mix_worker_arg_t *w = (pool_mix_worker_arg_t *)arg;
    for (int i = w->start; i < w->end; i++) {
        SOCKET s = INVALID_SOCKET;
        for (int attempt = 0; attempt < POOL_MIX_CONNECT_RETRIES; attempt++) {
            s = net_connect(LOCALHOST, w->batch[i].next_port);
            if (s != INVALID_SOCKET) break;
            Sleep(5);
        }
        if (s == INVALID_SOCKET) {
            note_pool_connect_fail(w->my_port);
            continue;
        }
        uint8_t mode = MODE_DATA;
        net_send_all(s, &mode, 1);
        net_send_all(s, w->batch[i].pkt.data, WIRE_PACKET_SIZE);
        net_close(s);
    }
    free(w);
    return 0;
}

static DWORD WINAPI pool_mix_flush_thread(LPVOID arg) {
    (void)arg;
    pool_entry_t *batch = malloc(sizeof(pool_entry_t) * POOL_MIX_MAX_BATCH);
    while (!g_pool_stop) {
        Sleep(POOL_MIX_FLUSH_MS);

        int n;
        EnterCriticalSection(&g_pool_lock);
        n = g_pool_count;
        if (n > 0) memcpy(batch, g_pool, (size_t)n * sizeof(pool_entry_t));
        g_pool_count = 0;
        LeaveCriticalSection(&g_pool_lock);

        if (n == 0) continue;
        static pool_entry_t shuffled[POOL_MIX_MAX_BATCH];
        pool_mix_shuffle_stratified(batch, n, shuffled);

        /* Splitting `shuffled` into CONTIGUOUS chunks (one per worker
         * thread) would reintroduce the same problem the stratified
         * shuffle just fixed: two entries from the same session, even in
         * correct relative order within `shuffled`, could land in
         * different chunks handled by different concurrently-running
         * threads with no ordering guarantee between them. Instead,
         * route every entry for a given session to the SAME worker
         * (hash(sess_idx) % n_workers) via a stable counting-sort-style
         * bucket pass, each worker then processes its own bucket
         * strictly in the order given, so a session's packets are always
         * sent by one thread, in the exact order pool_mix_shuffle_stratified()
         * produced. Different sessions still interleave freely, both by
         * the shuffle itself and by which worker happens to finish first. */
        int n_workers = n < POOL_MIX_MAX_WORKERS ? n : POOL_MIX_MAX_WORKERS;
        if (n_workers < 1) n_workers = 1;

        static int bucket_count[POOL_MIX_MAX_WORKERS];
        static int bucket_start[POOL_MIX_MAX_WORKERS];
        static int bucket_fill[POOL_MIX_MAX_WORKERS];
        static pool_entry_t bucketed[POOL_MIX_MAX_BATCH];
        for (int w = 0; w < n_workers; w++) bucket_count[w] = 0;
        for (int i = 0; i < n; i++)
            bucket_count[(unsigned)shuffled[i].sess_idx % (unsigned)n_workers]++;
        int running = 0;
        for (int w = 0; w < n_workers; w++) {
            bucket_start[w] = running;
            bucket_fill[w]  = 0;
            running += bucket_count[w];
        }
        for (int i = 0; i < n; i++) {
            int w = (unsigned)shuffled[i].sess_idx % (unsigned)n_workers;
            bucketed[bucket_start[w] + bucket_fill[w]] = shuffled[i];
            bucket_fill[w]++;
        }

        HANDLE handles[POOL_MIX_MAX_WORKERS];
        int actual_workers = 0;
        for (int w = 0; w < n_workers; w++) {
            if (bucket_count[w] == 0) continue;
            pool_mix_worker_arg_t *warg = malloc(sizeof(pool_mix_worker_arg_t));
            if (!warg) continue;
            warg->batch   = bucketed;
            warg->start   = bucket_start[w];
            warg->end     = bucket_start[w] + bucket_count[w];
            warg->my_port = g_my_port_global;
            HANDLE h = CreateThread(NULL, 0, pool_mix_worker, warg, 0, NULL);
            if (!h) { free(warg); continue; }
            handles[actual_workers] = h;
            actual_workers++;
        }
        for (int w = 0; w < actual_workers; w++) {
            WaitForSingleObject(handles[w], INFINITE);
            CloseHandle(handles[w]);
        }
    }
    free(batch);
    return 0;
}
#endif /* ASN_POOL_MIXING */

#ifdef ASN_LOOPIX_MIXING
/* Loopix-style continuous-time mixing: an independent exponential delay
 * applied before forwarding, per packet, per hop. Each accepted
 * connection already runs on its own thread (see handle_connection() /
 * main()'s accept loop below), so this sleep only delays this packet's
 * own forwarding, no queue or batching structure needed, matching
 * Loopix's per-message independent-delay model rather than threshold/
 * pool batching. See config.h's MIX_DELAY_MEAN_MS/MAX_MS. */
/* Task 3 (mixing-delay sensitivity sweep): mean delay is overridable at
 * runtime via ASN_MIX_DELAY_MEAN_MS, read once and cached, so the sweep
 * script can vary it across process launches without a rebuild per point.
 * Cap is held fixed at MIX_DELAY_MAX_MS for every sweep point (not scaled
 * with mean), a deliberate choice so only one variable moves at a time;
 * unset (the default), this is bit-identical to the un-swept behavior. */
/* Lazy-init caching races under concurrent handle_connection threads
 * (no lock around the check-then-set), disclosed, not fixed: every
 * racing thread reads the same env var and computes the same value, so
 * the worst case is a few redundant getenv()/atof() calls during
 * startup, never a torn or inconsistent read. Not worth a lock for a
 * write that's idempotent by construction. */
static double mix_delay_mean_ms(void) {
    static double cached = -1.0;
    if (cached < 0.0) {
        const char *env = getenv("ASN_MIX_DELAY_MEAN_MS");
        cached = (env != NULL) ? atof(env) : MIX_DELAY_MEAN_MS;
    }
    return cached;
}

static void mix_delay_sleep(void) {
    /* libc rand()/srand() is process-global, non-reentrant state, most
     * mix node roles (MN1/MN2/MN3) never call srand() anywhere in the
     * process, so every restart replayed the identical delay sequence
     * from the default seed, and concurrent handle_connection threads
     * raced on the same global state besides. Use RAND_bytes (already
     * linked, thread-safe, already relied on elsewhere in this file for
     * cover-packet payloads) instead, properly seeded and safe to call
     * from every connection thread with no coordination. */
    uint32_t r;
    if (RAND_bytes((uint8_t *)&r, sizeof(r)) != 1) r = 1;
    double u  = ((double)r + 1.0) / (4294967296.0 + 1.0);
    double ms = -mix_delay_mean_ms() * log(u);
    if (ms > MIX_DELAY_MAX_MS) ms = MIX_DELAY_MAX_MS;
    Sleep((DWORD)ms);
}
#endif

static uint16_t g_my_port_global = 0;

/* Every accepted connection runs on its own thread, so packets sent in
 * order can be processed out of order at the mix node's receive side.
 * Rather than guess at the real drop rate under concurrency, count it:
 * incremented every time a MODE_DATA/MODE_RETURN packet is dropped for
 * "no session for hint", logged periodically so the rate is visible
 * without separate tooling. */
static volatile LONG g_hint_miss_count = 0;
static void note_hint_miss(uint16_t port, const char *which) {
    LONG n = InterlockedIncrement(&g_hint_miss_count);
    /* Log every miss up to 10, then only every 100th, so a sustained
     * attack or a genuinely high concurrency-drop rate doesn't flood
     * the log. */
    if (n <= 10 || n % 100 == 0) {
        char buf[96];
        snprintf(buf, sizeof(buf), "%s: no session for hint, drop "
                 "(cumulative misses this process: %ld)", which, (long)n);
        log_err(port, buf);
    }
}

/* Regenerates g_node_kp on a timer, see the comment above
 * NODE_KEY_ROTATION_MS for the rationale. Runs for the life of the
 * process; there is no clean shutdown path for this thread, matching
 * every other background thread in this file, which all just die with
 * the process. */
static DWORD WINAPI node_key_rotation_thread(LPVOID arg) {
    (void)arg;
    while (1) {
        Sleep(NODE_KEY_ROTATION_MS);

        ecdh_keypair_t new_kp = {0};
        if (crypto_ecdh_keygen(&new_kp) != 0) {
            /* Keygen failure is rare (OpenSSL/entropy trouble) and
             * transient-ish, keep the current key rather than crash
             * the node, and just try again next interval. */
            continue;
        }

        ecdh_keypair_t old_kp;
        EnterCriticalSection(&g_node_kp_lock);
        old_kp    = g_node_kp;
        g_node_kp = new_kp;
        LeaveCriticalSection(&g_node_kp_lock);

        /* Destroy the retired key, this IS the forward-secrecy
         * guarantee: from this point on, even a full compromise of the
         * process cannot recover it. */
        crypto_ecdh_free(&old_kp);

        if (g_pubkey_path[0])
            crypto_pubkey_save(&g_node_kp, g_pubkey_path);

        log_msg(g_my_port_global, "node identity ECDH key rotated");
    }
    return 0;
}

/* Byte-blind bidirectional relay between two sockets, until either side
 * closes. Used to telescope EXTEND handshakes deeper than this node: once
 * this node has relayed the immediate next hop's frame and its pubkey
 * reply (see handle_extend below), it never needs to interpret anything
 * further: if the relayed node itself needs to relay again (its own
 * frame's tport != 0), that exchange happens entirely between the client
 * and the deeper node, with this node acting as a dumb pipe. This is what
 * makes N-hop telescoping work with no wire-format or protocol changes
 * beyond "do not close the relay socket after one round". */
static void proxy_bidirectional(SOCKET a, SOCKET b) {
    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(a, &rfds);
        FD_SET(b, &rfds);
        SOCKET maxfd = (a > b) ? a : b;

        int rc = select((int)maxfd + 1, &rfds, NULL, NULL, NULL);
        if (rc < 0) {
            if (errno == EINTR) continue;
            return;
        }

        for (int side = 0; side < 2; side++) {
            SOCKET src = side == 0 ? a : b;
            SOCKET dst = side == 0 ? b : a;
            if (!FD_ISSET(src, &rfds)) continue;

            uint8_t buf[4096];
            ssize_t n = recv(src, buf, sizeof(buf), 0);
            if (n <= 0) return; /* closed or error on either leg, done */
            if (net_send_all(dst, buf, (size_t)n) != 0) return;
        }
    }
}

/* MODE_EXTEND handler
 *
 * The direct request, the relayed request, and the signed-descriptor
 * reply are all now sent as fixed WIRE_PACKET_SIZE padded frames
 * (net_send_padded_frame/net_recv_padded_frame, common/net.c) instead of
 * their previous variable-length (69/70/up-to-211-byte) structures, so
 * path construction is not distinguishable by packet size from
 * steady-state MODE_DATA traffic. A useful side effect: since a relayed
 * request is now always exactly WIRE_PACKET_SIZE, this hop no longer
 * needs to parse the relay length prefix it used to, it already knows
 * the destination (target_port, parsed from its OWN direct request) and
 * can forward the next hop's opaque WIRE_PACKET_SIZE frame unchanged. */
static void handle_extend(SOCKET sock, uint16_t my_port) {
    uint8_t  req_buf[3 + EC_PUBKEY_LEN];   /* role(1) + tport(2) + pubkey(65) */
    size_t   req_len = 0;
    if (net_recv_padded_frame(sock, req_buf, &req_len, sizeof(req_buf)) != 0
        || req_len != sizeof(req_buf)) {
        log_err(my_port, "extend: read request frame"); return;
    }
    uint8_t role = req_buf[0];
    uint16_t target_port = (uint16_t)((req_buf[1] << 8) | req_buf[2]);
    uint8_t client_pub[EC_PUBKEY_LEN];
    memcpy(client_pub, req_buf + 3, EC_PUBKEY_LEN);

    /* Lock across the derive and the pubkey_bytes snapshot together,
     * both must come from the exact same keypair, even if
     * node_key_rotation_thread() swaps g_node_kp out immediately after
     * this unlocks. Lock hold time is one ECDH computation plus a
     * 65-byte memcpy, no I/O. */
    aes_key_t master = {0};
    uint8_t   node_pub_snapshot[EC_PUBKEY_LEN];
    EnterCriticalSection(&g_node_kp_lock);
    memcpy(node_pub_snapshot, g_node_kp.pubkey_bytes, EC_PUBKEY_LEN);
    /* Bind client_pub/node_pub/port/role into the derivation, see
     * crypto_ecdh_derive_bound()'s comment in crypto.h. */
    int ecdh_rc = crypto_ecdh_derive_bound(&g_node_kp, client_pub,
                                           client_pub, node_pub_snapshot,
                                           my_port, role, &master);
    LeaveCriticalSection(&g_node_kp_lock);
    if (ecdh_rc != 0) {
        log_err(my_port, "extend: ECDH failed"); return;
    }

    /* Split master into three independent keys matching what the client
     * stores in sphinx_path_t before calling packet_sphinx_build().      */
    aes_key_t henc = {0}, hmk = {0}, bkey = {0};
    split_master_keys(&master, &henc, &hmk, &bkey);

    /* Store session keyed by hint. Both role-A (forward/sending-path,
     * MODE_DATA) and role-B (receiving-path, MODE_RETURN) sessions carry
     * a rotating hint, derive hint_seed from the same master and
     * precompute the initial lookup window, instead of storing the raw
     * pubkey x-coord as a static match target. See config.h's
     * HINT_WINDOW comment. */
    session_entry_t *sess = session_alloc();
    if (!sess) { log_err(my_port, "extend: session store full"); return; }
    /* session_alloc() returns with g_session_lock HELD (see its own doc
     * comment) specifically so this population is atomic with respect to
     * a concurrent session_find() scan, released right below, once every
     * field session_find()'s callers can observe is fully populated. */
    {
        aes_key_t hint_seed = {0};
        if (packet_derive_hint_seed(&master, &hint_seed) != 0) {
            LeaveCriticalSection(&g_session_lock);
            log_err(my_port, "extend: hint_seed derivation failed"); return;
        }
        session_init_hint_window(sess, &hint_seed);
        explicit_bzero(&hint_seed, sizeof(hint_seed));
    }
    sess->header_enc_key   = henc;
    sess->header_mac_key   = hmk;
    sess->return_blind_key = bkey; /* same value client sends SG as recv_blind[i] */
    sess->role              = role;
    LeaveCriticalSection(&g_session_lock);

    /* The ECDH master and its rotation-derived intermediates are fully
     * copied into `sess` above; zero the stack copies rather than leaving
     * them sitting in memory for the rest of the process's life.
     * explicit_bzero, not memset, so it can't be optimized away as a
     * dead store. */
    explicit_bzero(&master, sizeof(master));
    explicit_bzero(&henc, sizeof(henc));
    explicit_bzero(&hmk, sizeof(hmk));
    explicit_bzero(&bkey, sizeof(bkey));

    /* Send our pubkey back, signed under our stable identity key so the
     * client can verify authenticity even across our own restarts,
     * [65B ephemeral pubkey][65B identity pubkey][1B sig_len][sig_len
     * bytes signature], sent as one padded frame (see
     * net_send_padded_frame's comment in common/net.c) so this reply
     * isn't distinguishable by size from a MODE_DATA packet either. */
    uint8_t sig[SIGNATURE_MAX_LEN];
    int sig_len = crypto_sign(&g_identity_kp, node_pub_snapshot, EC_PUBKEY_LEN,
                               sig, sizeof(sig));
    if (sig_len < 0) {
        log_err(my_port, "extend: failed to sign descriptor"); return;
    }
    {
        uint8_t reply_buf[EC_PUBKEY_LEN + EC_PUBKEY_LEN + 1 + SIGNATURE_MAX_LEN];
        size_t  off = 0;
        memcpy(reply_buf + off, node_pub_snapshot, EC_PUBKEY_LEN); off += EC_PUBKEY_LEN;
        memcpy(reply_buf + off, g_identity_kp.pubkey_bytes, EC_PUBKEY_LEN); off += EC_PUBKEY_LEN;
        reply_buf[off++] = (uint8_t)sig_len;
        memcpy(reply_buf + off, sig, (size_t)sig_len); off += (size_t)sig_len;
        if (net_send_padded_frame(sock, reply_buf, off) != 0) {
            log_err(my_port, "extend: send reply frame"); return;
        }
    }

    char logbuf[64];
    snprintf(logbuf, sizeof(logbuf), "extend: session ready (port %u)", my_port);
    log_msg(my_port, logbuf);

    /* Relay if target_port != 0. The relayed request and its reply are
     * each already a fixed WIRE_PACKET_SIZE padded frame by construction
     * (the client built the request that way, and the far hop's own
     * handle_extend() builds the reply that way), this hop does not
     * need to decode either one, only forward the opaque
     * WIRE_PACKET_SIZE block verbatim to/from the connection it already
     * knows to open (target_port, parsed from its own direct request
     * above). */
    if (target_port != 0) {
        uint8_t relay_req[WIRE_PACKET_SIZE];
        if (net_recv_all(sock, relay_req, WIRE_PACKET_SIZE) != 0) {
            log_err(my_port, "extend relay: read request frame"); return;
        }

        if (!is_allowed_next_hop(LOCALHOST, target_port)) {
            log_err(my_port, "extend relay: target_port not in allowlist, drop");
            return;
        }
        SOCKET next_sock = net_connect(LOCALHOST, target_port);
        if (next_sock == INVALID_SOCKET) {
            log_err(my_port, "extend relay: connect failed"); return;
        }

        uint8_t mode = MODE_EXTEND;
        net_send_all(next_sock, &mode,      1);
        net_send_all(next_sock, relay_req,  WIRE_PACKET_SIZE);

        uint8_t relay_reply[WIRE_PACKET_SIZE];
        if (net_recv_all(next_sock, relay_reply, WIRE_PACKET_SIZE) != 0) {
            net_close(next_sock); return;
        }
        net_send_all(sock, relay_reply, WIRE_PACKET_SIZE);

        /* Don't close yet: if this relayed hop itself needs to telescope
         * further (its own tport != 0), the client will drive that
         * exchange over the SAME two sockets, with us as a blind pipe,
         * see proxy_bidirectional()'s comment. If there is nothing more,
         * the client (or the relayed node) closes and this returns. */
        proxy_bidirectional(sock, next_sock);
        net_close(next_sock);
    }
}

/* MODE_DATA handler */
static void handle_data(SOCKET sock, uint16_t my_port) {
    wire_packet_t pkt = {0};
    if (net_recv_all(sock, pkt.data, WIRE_PACKET_SIZE) != 0) {
        log_err(my_port, "data: read packet"); return;
    }

    /* Extract hint from outermost header block */
    const uint8_t *hint = pkt.data + ADDR_BYTES + BLIND_KEY_BYTES + FLAG_BYTES
                                    + NONCE_BYTES + MAC_BYTES;

    session_keys_t keys;
    int hint_domain = 0, hint_window_idx = 0;
    uint32_t generation = 0;
    int sess_idx = session_find(hint, &keys, &hint_domain, &hint_window_idx, &generation);
    if (sess_idx < 0) {
        note_hint_miss(my_port, "data"); return;
    }

    hop_info_t    hop_info = {0};
    wire_packet_t out_pkt  = {0};

    /* Cover isn't dropped here: the per-hop outer flag that used to mark
     * it was removed at the source (packet_sphinx_build() always writes
     * 0 for that byte; packet_sphinx_peel() has no out-parameter for it
     * at all, see packet.c's comments), so no mix node can tell cover
     * from real traffic. Cover traverses every hop exactly like real
     * traffic: peeled, replay-checked, forwarded, and is only ever
     * discarded at the SG, via the PKT_DUMMY check inside its
     * end-to-end payload (gateway/service_gateway.c's find_a_session(),
     * `if (tf & PKT_DUMMY) continue`), which no mix node can decrypt. */
    if (packet_sphinx_peel(&pkt,
                           &keys.header_enc_key,
                           &keys.header_mac_key,
                           hint, &hop_info, &out_pkt) != 0) {
        log_err(my_port, "data: peel failed, drop"); return;
    }
    /* Only now, after MAC verification has succeeded, consume the
     * matched hint window slot. */
    session_confirm_hint_match(sess_idx, generation, hint_domain, hint_window_idx);
    order_probe_log("recv", sess_idx, my_port);

    /* Replay check: reject an exact resend of a packet already forwarded
     * in this session. See session_entry_t.seen_nonces and header_block_t's
     * comment in packet.h for the design and its bounded-window limits.
     * Re-validates the slot's identity under lock before touching it:
     * session_idx alone isn't enough, since the slot could have been
     * reclaimed for a different session since session_find() above. */
    int replayed = session_check_nonce_by_idx(sess_idx, generation, hop_info.nonce);
    if (replayed) {
        log_err(my_port, "data: replayed nonce, drop"); return;
    }

    hopdecoy_trace_log(my_port, sess_idx);

#ifdef ASN_HOP_DECOY
    /* This hop's own decrypted enc_flags byte (packet.h's hop_info_t),
     * HOP_FLAG_FORWARD for every real packet and every hop of a decoy
     * that isn't terminating here, HOP_DROP_MARKER only at a decoy's own
     * chosen termination hop. See config.h's comment for why reading this
     * is safe: seeing HOP_FLAG_FORWARD (the overwhelming majority of
     * traffic, real or not) tells this node nothing, and this code path
     * is identical on every mix node regardless of which position
     * (entry/middle/exit) it happens to be playing for this session.
     * Absorbed silently, same as the SG's PKT_DUMMY handling: no error, no
     * response, nothing forwarded. */
    if (hop_info.hop_flag == HOP_DROP_MARKER) {
        log_routing(my_port, "data: hop-decoy terminates here, absorb");
        return;
    }
#endif

    char logbuf[80];
    snprintf(logbuf, sizeof(logbuf),
             "data: peeled OK -> port %u", hop_info.next_port);
    log_routing(my_port, logbuf);

    /* The delay must precede the connect() that emits the TCP SYN a
     * network observer actually sees, sleeping after connect() delays
     * only the payload write on an already-established connection,
     * giving zero timing obfuscation. */
#ifdef ASN_LOOPIX_MIXING
    mix_delay_sleep();
#endif

    if (!is_allowed_next_hop(LOCALHOST, hop_info.next_port)) {
        log_err(my_port, "data: next_port not in allowlist, drop");
        return;
    }

#ifdef ASN_POOL_MIXING
    if (pool_mix_enqueue(&out_pkt, hop_info.next_port, sess_idx) != 0) {
        log_err(my_port, "data: pool full, drop");
    }
    return;
#else
    SOCKET next_sock = net_connect(LOCALHOST, hop_info.next_port);
    if (next_sock == INVALID_SOCKET) {
        log_err(my_port, "data: connect next hop"); return;
    }

    uint8_t mode = MODE_DATA;
    net_send_all(next_sock, &mode,        1);
    net_send_all(next_sock, out_pkt.data, WIRE_PACKET_SIZE);
    net_close(next_sock);
    order_probe_log("send", sess_idx, my_port);
#endif
}

/* MODE_RETURN handler */
static void handle_return(SOCKET sock, uint16_t my_port) {
    uint8_t wire[WIRE_PACKET_SIZE];
    if (net_recv_all(sock, wire, WIRE_PACKET_SIZE) != 0) {
        log_err(my_port, "return: read packet"); return;
    }

    /* Parse return header from front of wire packet */
    return_header_t rhdr = {0};
    memcpy(&rhdr, wire, RETURN_HEADER_SIZE);

    /* Look up session by hint in outermost block */
    const uint8_t *hint = rhdr.blocks[0].hint;
    session_keys_t keys;
    int hint_domain = 0, hint_window_idx = 0;
    uint32_t generation = 0;
    int sess_idx = session_find(hint, &keys, &hint_domain, &hint_window_idx, &generation);
    if (sess_idx < 0) {
        note_hint_miss(my_port, "return"); return;
    }

    /* Peel our return header block */
    return_next_t   next_addr = {0};
    return_header_t shifted   = {0};
    if (packet_peel_return_header(&rhdr,
                                  &keys.header_enc_key,
                                  &keys.header_mac_key,
                                  &next_addr, &shifted) != 0) {
        log_err(my_port, "return: MAC failed, drop"); return;
    }
    /* Only now, after MAC verification has succeeded, consume the
     * matched hint window slot. */
    session_confirm_hint_match(sess_idx, generation, hint_domain, hint_window_idx);
    order_probe_log("recv", sess_idx, my_port);

    /* Replay check: reject an exact resend of a return packet already
     * forwarded in this session. See session_entry_t.seen_return_nonces
     * and return_block_t's comment in packet.h for the design and its
     * bounded-window limits (same as the forward-path check). Re-
     * validates the slot's identity under lock, same as above. */
    int return_replayed = session_check_return_nonce_by_idx(sess_idx, generation, next_addr.nonce);
    if (return_replayed) {
        log_err(my_port, "return: replayed nonce, drop"); return;
    }

    hopdecoy_trace_log_to("hopdecoy_trace_ret", my_port, sess_idx);

    /* Cancel this hop's layer of the SG's return-path pre-blinding.
     * XOR is self-inverse, so this is the same operation the SG used to
     * apply it (see service_gateway.c::send_response()), after all
     * three hops (MNc, MNb, MNa) have each XORed their own
     * return_blind_key, the payload is back to the raw K_R-SG-B
     * ciphertext the client expects. Order among hops does not matter
     * (XOR is commutative); only that each hop's key is applied exactly
     * once, which the per-session return_blind_key guarantees. */
    uint8_t blinded_payload[WIRE_PACKET_SIZE - RETURN_HEADER_SIZE];
    if (packet_aes_ctr_xor(keys.return_blind_key.key, AES_KEY_LEN,
                           wire + RETURN_HEADER_SIZE,
                           sizeof(blinded_payload),
                           blinded_payload) != 0) {
        log_err(my_port, "return: unblind failed, drop"); return;
    }

    /* Build output: [shifted_header][payload with our blind cancelled] */
    uint8_t out_wire[WIRE_PACKET_SIZE];
    memset(out_wire, 0, sizeof(out_wire));
    memcpy(out_wire, &shifted, RETURN_HEADER_SIZE);
    memcpy(out_wire + RETURN_HEADER_SIZE,
           blinded_payload,
           sizeof(blinded_payload));

    /* Route by the destination peeled from the packet itself (matching
     * how handle_data() derives hop_info.next_port), not by my_port
     * against the legacy fixed PORT_MIX_A/B/C/X/Y/Z topology, that
     * static lookup never matches a node_pool-selected port and made
     * every pool node misclassify itself as the final hop, which
     * silently dropped the MODE_RETURN framing byte and corrupted the
     * next hop's mode read (broke every session using node_pool). The
     * two response ports are the only well-known constants left after
     * node_pool replaced the fixed mix-node topology, they're where
     * Client/Sender listen, never where another mix node listens. */
    int is_final = ((next_addr.next_port >= CLIENT_RESPONSE_PORT &&
                     next_addr.next_port <  CLIENT_RESPONSE_PORT + CLIENT_RESPONSE_PORT_COUNT) ||
                    (next_addr.next_port >= SENDER_RESPONSE_PORT &&
                     next_addr.next_port <  SENDER_RESPONSE_PORT + SENDER_RESPONSE_PORT_COUNT));

    char dest_ip[16];
    snprintf(dest_ip, sizeof(dest_ip), "%u.%u.%u.%u",
             next_addr.next_ip[0], next_addr.next_ip[1],
             next_addr.next_ip[2], next_addr.next_ip[3]);

    /* dest_ip/next_addr.next_port come straight from the peeled return
     * header: see is_allowed_next_hop()'s comment for why the MAC gate
     * alone doesn't bound who can choose this value. Covers both
     * branches below (forward and final-delivery both connect to this
     * same dest_ip:port). */
    if (!is_allowed_next_hop(dest_ip, next_addr.next_port)) {
        log_err(my_port, "return: destination not in allowlist, drop");
        return;
    }

    char logbuf[80];
    if (!is_final) {
        /* Intermediate node, forward to next mix node */
        snprintf(logbuf, sizeof(logbuf),
                 "return: forwarding -> %s:%u", dest_ip, next_addr.next_port);
        log_routing(my_port, logbuf);

        /* Delay before connect(), see the identical comment on the
         * MODE_DATA path above. */
#ifdef ASN_LOOPIX_MIXING
        mix_delay_sleep();
#endif
        SOCKET next_sock = net_connect(dest_ip, next_addr.next_port);
        if (next_sock == INVALID_SOCKET) {
            log_err(my_port, "return: connect next hop"); return;
        }
        uint8_t mode = MODE_RETURN;
        net_send_all(next_sock, &mode,    1);
        net_send_all(next_sock, out_wire, WIRE_PACKET_SIZE);
        net_close(next_sock);
    } else {
        /* Final node, deliver directly to Client/Sender */
        snprintf(logbuf, sizeof(logbuf),
                 "return: delivering to %s:%u", dest_ip, next_addr.next_port);
        log_routing(my_port, logbuf);

        /* Return cover originates at the SG and travels this same
         * "final node, deliver directly" path exactly like a real
         * response, with no special handling required at this hop. */

        /* Delay before connect(), see the identical comment on the
         * MODE_DATA path above. */
#ifdef ASN_LOOPIX_MIXING
        mix_delay_sleep();
#endif
        SOCKET dest = net_connect(dest_ip, next_addr.next_port);
        if (dest == INVALID_SOCKET) {
            log_err(my_port, "return: connect destination"); return;
        }
        net_send_all(dest, out_wire, WIRE_PACKET_SIZE);
        net_close(dest);
    }
}


/* Connection handler */
static DWORD WINAPI handle_connection(LPVOID arg) {
    conn_ctx_t *ctx  = (conn_ctx_t *)arg;
    SOCKET      sock = ctx->client_sock;
    uint16_t    port = ctx->my_port;
    free(ctx);

    uint8_t mode = 0;
    if (net_recv_all(sock, &mode, 1) != 0) {
        log_err(port, "read mode"); goto done;
    }

    switch (mode) {
        case MODE_EXTEND: handle_extend(sock, port); break;
        case MODE_DATA:   handle_data(sock, port);   break;
        case MODE_RETURN: handle_return(sock, port);  break;
        default: log_err(port, "unknown mode, drop"); break;
    }

done:
    net_close(sock);
    return 0;
}

/* main */
int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: mix_node.exe <port>\n"); return 1;
    }
    uint16_t port = (uint16_t)atoi(argv[1]);
    if (port < 1024) {
        fprintf(stderr, "Port must be >= 1024\n"); return 1;
    }

    SetConsoleOutputCP(65001);
    memset(g_sessions, 0, sizeof(g_sessions));
    InitializeCriticalSection(&g_session_lock);
    InitializeCriticalSection(&g_node_kp_lock);
    order_probe_init(port);

    if (net_init() != 0) return 1;

    if (crypto_ecdh_keygen(&g_node_kp) != 0) {
        fprintf(stderr, "[MN:%u] keygen failed\n", port);
        net_cleanup(); return 1;
    }

    CreateDirectoryA(PUBKEY_DIR, NULL);
    char pubkey_path[256];
    snprintf(pubkey_path, sizeof(pubkey_path), "%s/%u.pub", PUBKEY_DIR, port);
    if (crypto_pubkey_save(&g_node_kp, pubkey_path) != 0) {
        fprintf(stderr, "[MN:%u] save pubkey failed\n", port);
        net_cleanup(); return 1;
    }
    printf("[MN:%u] pubkey written to %s\n", port, pubkey_path);
    snprintf(g_pubkey_path, sizeof(g_pubkey_path), "%s", pubkey_path);

    /* Load-or-create this node's stable identity signing key (survives
     * restart, unlike g_node_kp above). */
    char identity_path[256];
    snprintf(identity_path, sizeof(identity_path), "%s/identity_%u.key", PUBKEY_DIR, port);
    if (crypto_identity_load_or_create(&g_identity_kp, identity_path) != 0) {
        fprintf(stderr, "[MN:%u] identity key load/create failed\n", port);
        net_cleanup(); return 1;
    }

    SOCKET server_sock = net_listen(port);
    if (server_sock == INVALID_SOCKET) { net_cleanup(); return 1; }

    printf("[MN:%u] ready\n", port); fflush(stdout);
    g_my_port_global = port;

    /* Periodic node-key rotation for forward secrecy. */
    {
        HANDLE rt = CreateThread(NULL, 0, node_key_rotation_thread, NULL, 0, NULL);
        if (rt) CloseHandle(rt);
    }

#ifdef ASN_POOL_MIXING
    pool_mix_init();
    {
        HANDLE pt = CreateThread(NULL, 0, pool_mix_flush_thread, NULL, 0, NULL);
        if (pt) CloseHandle(pt);
    }
#endif

    /* Return-path cover is genuine, Sphinx-return-header-valid, and
     * originates at the SG (service_gateway.c's PKT_DUMMY handling),
     * traversing every return hop exactly like a real response, same as
     * the forward path. */

    while (1) {
        SOCKET cs = net_accept(server_sock);
        if (cs == INVALID_SOCKET) continue;

        conn_ctx_t *ctx = malloc(sizeof(conn_ctx_t));
        if (!ctx) { net_close(cs); continue; }
        ctx->client_sock = cs;
        ctx->my_port     = port;

        HANDLE t = CreateThread(NULL, 0, handle_connection, ctx, 0, NULL);
        if (!t) { net_close(cs); free(ctx); continue; }
        CloseHandle(t);
    }

    net_close(server_sock);
    crypto_ecdh_free(&g_node_kp);
    DeleteCriticalSection(&g_session_lock);
    net_cleanup();
    return 0;
}
