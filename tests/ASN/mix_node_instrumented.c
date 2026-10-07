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
#include "common/measure.h"          /* P1: per-hop crypto timer */

#include <openssl/rand.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include "common/posix_compat.h"

/* Session store */
#define MAX_SESSIONS 1024

/* See mix_node.c's comment on the same constant. */
#define REPLAY_WINDOW 64

typedef struct {
    uint8_t   hint[HINT_BYTES];
    aes_key_t header_enc_key;
    aes_key_t header_mac_key;
    aes_key_t return_blind_key; /* == blind_key, derived from master via
                                  * packet_derive_hop_keys(): cancels
                                  * one layer of SG return-path blinding */
    uint8_t   role;
    /* Replay-detection caches, see mix_node.c for the full rationale. */
    uint8_t   seen_nonces[REPLAY_WINDOW][NONCE_BYTES];
    int       seen_count;
    int       seen_next;
    uint8_t   seen_return_nonces[REPLAY_WINDOW][RETURN_NONCE_BYTES];
    int       seen_return_count;
    int       seen_return_next;
    int       in_use;
    DWORD     last_active_ms; /* see mix_node.c's session_entry_t.last_active_ms
                                * / SESSION_TTL_MS for rationale, this is a
                                * separate, independently-duplicated copy of
                                * that same session table (this file is the
                                * benchmark-harness track: Table 2/Figure 3/
                                * Figure 5/7 all run against this binary, not
                                * mix_node.exe), so it needed the identical
                                * fix applied separately, found missing
                                * during a re-run audit after the first fix
                                * pass only touched mix_node.c. */
} session_entry_t;

#define SESSION_TTL_MS (5U * 60U * 1000U)

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

/* Copies key material out under lock rather than returning a raw
 * pointer: see production mix_node.c's identical comment for the
 * full rationale. */
typedef struct {
    aes_key_t header_enc_key;
    aes_key_t header_mac_key;
    aes_key_t return_blind_key;
} session_keys_t;

static int session_find(const uint8_t hint[HINT_BYTES], session_keys_t *out_keys) {
    EnterCriticalSection(&g_session_lock);
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i].in_use &&
            crypto_memcmp(g_sessions[i].hint, hint, HINT_BYTES) == 0) {
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

static int session_check_nonce_by_idx(int idx, const uint8_t hint[HINT_BYTES],
                                       const uint8_t nonce[NONCE_BYTES]) {
    EnterCriticalSection(&g_session_lock);
    int drop = 1;
    if (g_sessions[idx].in_use &&
        crypto_memcmp(g_sessions[idx].hint, hint, HINT_BYTES) == 0) {
        drop = session_seen_nonce(&g_sessions[idx], nonce);
    }
    LeaveCriticalSection(&g_session_lock);
    return drop;
}

static int session_check_return_nonce_by_idx(int idx, const uint8_t hint[HINT_BYTES],
                                              const uint8_t nonce[RETURN_NONCE_BYTES]) {
    EnterCriticalSection(&g_session_lock);
    int drop = 1;
    if (g_sessions[idx].in_use &&
        crypto_memcmp(g_sessions[idx].hint, hint, HINT_BYTES) == 0) {
        drop = session_seen_return_nonce(&g_sessions[idx], nonce);
    }
    LeaveCriticalSection(&g_session_lock);
    return drop;
}

static session_entry_t *session_alloc(void) {
    EnterCriticalSection(&g_session_lock);
    DWORD now = GetTickCount();
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_sessions[i].in_use) {
            memset(&g_sessions[i], 0, sizeof(g_sessions[i]));
            g_sessions[i].in_use = 1;
            g_sessions[i].last_active_ms = now;
            LeaveCriticalSection(&g_session_lock);
            return &g_sessions[i];
        }
    }
    /* Table full: reclaim the oldest slot past SESSION_TTL_MS, see
     * mix_node.c's session_alloc() for the identical fix and rationale. */
    int oldest_idx = -1;
    DWORD oldest_age = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        DWORD age = now - g_sessions[i].last_active_ms;
        if (age >= SESSION_TTL_MS && age >= oldest_age) {
            oldest_age = age;
            oldest_idx = i;
        }
    }
    if (oldest_idx >= 0) {
        memset(&g_sessions[oldest_idx], 0, sizeof(g_sessions[oldest_idx]));
        g_sessions[oldest_idx].in_use = 1;
        g_sessions[oldest_idx].last_active_ms = now;
        LeaveCriticalSection(&g_session_lock);
        return &g_sessions[oldest_idx];
    }
    LeaveCriticalSection(&g_session_lock);
    return NULL;
}

/* Node keypair */
static ecdh_keypair_t g_node_kp = {0};

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

/* Track-A probe (experimental, additive only, not one of measure.h's
 * standard P1-P5 probes, not used by any figure/table in the paper):
 * logs a high-resolution timestamp + session slot index for every
 * packet this node receives and every packet it forwards onward, so a
 * post-hoc analysis can check whether, under genuine concurrent
 * multi-session load, this node's SEND order is a scrambled permutation
 * of its RECV order (queueing-based mixing entropy) or strictly
 * preserves per-session order with only a fixed per-packet delay (no
 * cross-session mixing benefit). Reuses g_mctx.qpc_freq, populated by
 * measure_init() regardless of which P-flags are passed. */
static FILE            *g_order_fp   = NULL;
static CRITICAL_SECTION g_order_lock;

static void order_probe_init(uint16_t my_port) {
    /* Opt-in only (ASN_TRACKA_PROBE=1): this is an experimental probe for
     * one specific investigation, not part of the standard measure.h
     * probe set, and must not add file I/O or behavior to any of the
     * paper's actual figure/table benchmark runs unless explicitly
     * requested. */
    if (!getenv("ASN_TRACKA_PROBE")) return;
    char fname[64];
    snprintf(fname, sizeof(fname), "packet_order_%u.csv", (unsigned)my_port);
    InitializeCriticalSection(&g_order_lock);
    g_order_fp = fopen(fname, "a");
    if (g_order_fp)
        fprintf(g_order_fp, "# Track-A: per-packet recv/send order at this "
                             "node, experimental, not used by any figure\n"
                             "event,ts_us,sess_idx,port\n");
}

static void order_probe_log(const char *event, int sess_idx, uint16_t port) {
    if (!g_order_fp) return;
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    double ts_us = (double)now.QuadPart * 1e6 / (double)g_mctx.qpc_freq.QuadPart;
    EnterCriticalSection(&g_order_lock);
    fprintf(g_order_fp, "%s,%.3f,%d,%u\n", event, ts_us, sess_idx, (unsigned)port);
    fflush(g_order_fp);
    LeaveCriticalSection(&g_order_lock);
}

#ifdef ASN_POOL_MIXING
/* Track-B experimental pool mix (separate build flag from
 * ASN_LOOPIX_MIXING: orthogonal, not a replacement, so the existing
 * per-packet-delay hardened build and every figure measured against it
 * are untouched). Track A found that per-packet independent delay
 * produces only LOCAL reordering, bounded by the delay's own ~50ms
 * timescale, invisible to a correlator working in 500ms bins. This
 * mechanism batches every packet that FINISHES peeling within a fixed
 * flush window, then releases the whole batch together in randomized
 * order: reordering at the scale of the flush window itself, not the
 * per-packet delay, so it can be set to meet or exceed a correlator's
 * bin size directly instead of hoping enough concurrent load
 * incidentally produces the same effect.
 *
 * Safe to reorder here: this file's session_find() (unlike production
 * mix_node.c) matches a single static per-session hint with no rotating
 * window, so an arbitrarily large forwarding delay/reorder at THIS node
 * cannot desync anything at THIS node. It does increase how out-of-order
 * packets arrive at the NEXT hop relative to how the client originally
 * dispatched them, not a concern for this harness's own flat hint
 * matching either, but would need HINT_WINDOW re-tuning before porting
 * this to production mix_node.c's rotating-window session_find().
 *
 * All session-processing (session_find, replay check, Sphinx peel)
 * still happens synchronously in the per-connection thread, exactly as
 * before: only the final connect+forward step is deferred into the
 * pool. Enqueue failure (pool full) drops the packet and logs, rather
 * than blocking a connection-handler thread indefinitely. */
#define POOL_MIX_MAX_BATCH 8192
#ifndef POOL_MIX_FLUSH_MS
#define POOL_MIX_FLUSH_MS  500   /* matches the flow-correlation evaluation's own 500ms bin size */
#endif

typedef struct {
    wire_packet_t pkt;
    uint16_t      next_port;
    int           sess_idx;
} pool_entry_t;

static pool_entry_t     *g_pool = NULL;
static int               g_pool_count = 0;
static CRITICAL_SECTION  g_pool_lock;
static uint16_t          g_my_port = 0;
static volatile int      g_pool_stop = 0;

static void pool_mix_init(uint16_t my_port) {
    g_my_port = my_port;
    g_pool = malloc(sizeof(pool_entry_t) * POOL_MIX_MAX_BATCH);
    InitializeCriticalSection(&g_pool_lock);
}

/* Returns 0 on success, -1 if the pool is full (packet dropped). */
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

/* Fisher-Yates shuffle over the locally-owned batch (not the shared
 * pool: the flush thread swaps the pool out under lock first, then
 * shuffles and sends its own private copy, so connection-handler
 * threads are never blocked waiting for a batch of network sends).
 * Uses RAND_bytes, not libc rand(), unseeded/racy rand() produces a
 * deterministic, replayable sequence, which for a per-packet delay is a
 * disclosed weakness but for a SHUFFLE would be a direct break: a
 * predictable permutation defeats the entire point of pool mixing,
 * since an adversary who can predict it can just undo it. */
static uint32_t pool_mix_rand_u32(void) {
    uint32_t r;
    if (RAND_bytes((uint8_t *)&r, sizeof(r)) != 1) r = 1;
    return r;
}

static void pool_mix_shuffle(pool_entry_t *batch, int n) {
    for (int i = n - 1; i > 0; i--) {
        int j = (int)(((double)pool_mix_rand_u32() / (4294967296.0)) * (i + 1));
        if (j > i) j = i;   /* guard the vanishingly rare rounding edge case */
        pool_entry_t tmp = batch[i];
        batch[i] = batch[j];
        batch[j] = tmp;
    }
}

/* First implementation of this flush loop sent the whole batch
 * sequentially (one connect+send+close at a time) and measured 1-6
 * SECONDS to release a 200-800-packet batch against a 500ms budget,
 * serial per-connection TCP setup/teardown overhead, even on loopback,
 * does not amortize the way it does for organically-arriving traffic.
 * The flush thread fell further behind every cycle (batch sizes grew
 * 59->64->224->...->868 across one run), which is backlog, not mixing.
 * Fixed by releasing the batch across a small worker-thread pool
 * instead of one thread looping serially, the batch is already
 * shuffled before this point, so which worker sends which entry has no
 * bearing on the randomization already applied. */
#define POOL_MIX_MAX_WORKERS 64

typedef struct {
    pool_entry_t *batch;
    int           start, end;   /* [start, end) */
    uint16_t      my_port;
} pool_mix_worker_arg_t;

static DWORD WINAPI pool_mix_worker(LPVOID arg) {
    pool_mix_worker_arg_t *w = (pool_mix_worker_arg_t *)arg;
    for (int i = w->start; i < w->end; i++) {
        order_probe_log("send", w->batch[i].sess_idx, w->my_port);
        SOCKET s = net_connect(LOCALHOST, w->batch[i].next_port);
        if (s == INVALID_SOCKET) continue;
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
    int diag = getenv("ASN_TRACKB_DIAG") != NULL;
    while (!g_pool_stop) {
        Sleep(POOL_MIX_FLUSH_MS);

        int n;
        EnterCriticalSection(&g_pool_lock);
        n = g_pool_count;
        if (n > 0) memcpy(batch, g_pool, (size_t)n * sizeof(pool_entry_t));
        g_pool_count = 0;
        LeaveCriticalSection(&g_pool_lock);

        if (n == 0) continue;
        pool_mix_shuffle(batch, n);

        LARGE_INTEGER t0, t1;
        if (diag) QueryPerformanceCounter(&t0);

        int n_workers = n < POOL_MIX_MAX_WORKERS ? n : POOL_MIX_MAX_WORKERS;
        if (n_workers < 1) n_workers = 1;
        HANDLE handles[POOL_MIX_MAX_WORKERS];
        int per = (n + n_workers - 1) / n_workers;
        int actual_workers = 0;
        for (int w = 0; w < n_workers; w++) {
            int start = w * per;
            int end   = start + per;
            if (end > n) end = n;
            if (start >= end) break;
            pool_mix_worker_arg_t *warg = malloc(sizeof(pool_mix_worker_arg_t));
            if (!warg) continue;
            warg->batch = batch; warg->start = start; warg->end = end;
            warg->my_port = g_my_port;
            HANDLE h = CreateThread(NULL, 0, pool_mix_worker, warg, 0, NULL);
            if (!h) { free(warg); continue; }
            handles[actual_workers] = h;
            actual_workers++;
        }
        for (int w = 0; w < actual_workers; w++) {
            WaitForSingleObject(handles[w], INFINITE);
            CloseHandle(handles[w]);
        }

        if (diag) {
            QueryPerformanceCounter(&t1);
            double flush_ms = (double)(t1.QuadPart - t0.QuadPart) * 1e3
                               / (double)g_mctx.qpc_freq.QuadPart;
            fprintf(stderr, "[MN:%u] flush: n=%d workers=%d took=%.1fms budget=%dms\n",
                    g_my_port, n, actual_workers, flush_ms, POOL_MIX_FLUSH_MS);
        }
    }
    free(batch);
    return 0;
}
#endif /* ASN_POOL_MIXING */

/* Return path next-hop routing */
typedef struct { const char *addr; uint16_t port; } next_hop_t;

/* Returns next hop for return path packets.
 * addr=NULL means this is the final node, use address from peeled header. */
static next_hop_t return_next_hop(uint16_t my_port) {
    switch (my_port) {
        /* Client receiving path: MNc -> MNb -> MNa -> Client */
        case PORT_MIX_C: return (next_hop_t){ LOCALHOST, PORT_MIX_B };
        case PORT_MIX_B: return (next_hop_t){ LOCALHOST, PORT_MIX_A };
        case PORT_MIX_A: return (next_hop_t){ NULL, 0 };
        /* Sender receiving path: MNz -> MNy -> MNx -> Sender */
        case PORT_MIX_Z: return (next_hop_t){ LOCALHOST, PORT_MIX_Y };
        case PORT_MIX_Y: return (next_hop_t){ LOCALHOST, PORT_MIX_X };
        case PORT_MIX_X: return (next_hop_t){ NULL, 0 };
        default:         return (next_hop_t){ NULL, 0 };
    }
}

/* Key splitting from ECDH master
 *
 * packet_sphinx_build() and packet_sphinx_peel() use header_enc_key,
 * header_mac_key, and blind_key DIRECTLY, no internal re-derivation.
 *
 * Three independent keys from the 32-byte ECDH master via
 * packet_derive_hop_keys() (labelled-PRF KDF: AES-256-CTR(master,
 * SHA256(label)) per purpose, see packet.c/.h), not byte-rotation,
 * which would be invertible.
 *
 * For a receiving-path hop, blind_key is also stored as
 * session_entry_t.return_blind_key and reused to cancel the SG's
 * return-path pre-blinding in handle_return(), it is the exact same
 * value client_instrumented.c::derive_hop_recv() sends the SG as
 * recv_blind[i] (both sides derive it independently from the shared
 * ECDH master; see mix_node.c for the full rationale).
 *
 * Must match client_instrumented.c::split_master_keys() exactly.
 */
static void split_master_keys(const aes_key_t *master,
                              aes_key_t *henc,
                              aes_key_t *hmac_key,
                              aes_key_t *bkey) {
    packet_derive_hop_keys(master, henc, hmac_key, bkey);
}

#ifdef ASN_LOOPIX_MIXING
/* Mirrors mix_node.c's mix_delay_sleep(), see that file for the design
 * rationale (Loopix-style continuous-time per-hop mixing delay, no
 * batching structure needed since each connection already runs on its
 * own thread) and the RAND_bytes-over-rand() fix (unseeded/racy libc
 * rand() produced a deterministic, replayable delay sequence on most
 * mix node roles). Kept in sync with production, not shared via a
 * header, per this codebase's established hand-duplicated-file pattern. */
/* Mixing-delay sensitivity sweep: mean delay is overridable at
 * runtime via ASN_MIX_DELAY_MEAN_MS, read once and cached, so the sweep
 * script can vary it across process launches without a rebuild per point.
 * Cap is held fixed at MIX_DELAY_MAX_MS for every sweep point (not scaled
 * with mean), a deliberate choice so only one variable moves at a time;
 * unset (the default), this is bit-identical to the un-swept behavior. */
static double mix_delay_mean_ms(void) {
    static double cached = -1.0;
    if (cached < 0.0) {
        const char *env = getenv("ASN_MIX_DELAY_MEAN_MS");
        cached = (env != NULL) ? atof(env) : MIX_DELAY_MEAN_MS;
    }
    return cached;
}

static void mix_delay_sleep(void) {
    uint32_t r;
    if (RAND_bytes((uint8_t *)&r, sizeof(r)) != 1) r = 1;
    double u  = ((double)r + 1.0) / (4294967296.0 + 1.0);
    double ms = -mix_delay_mean_ms() * log(u);
    if (ms > MIX_DELAY_MAX_MS) ms = MIX_DELAY_MAX_MS;
    Sleep((DWORD)ms);
}
#endif

/* MODE_EXTEND handler */
/* Byte-blind bidirectional relay, see mix_node.c's copy of this
 * function for the full rationale. Independently-duplicated copy for
 * this benchmark-harness track. */
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
            if (n <= 0) return;
            if (net_send_all(dst, buf, (size_t)n) != 0) return;
        }
    }
}

static void handle_extend(SOCKET sock, uint16_t my_port) {
    /* Read role byte (SESSION_ROLE_A or SESSION_ROLE_B) */
    uint8_t role = 0;
    if (net_recv_all(sock, &role, 1) != 0) {
        log_err(my_port, "extend: read role"); return;
    }

    uint8_t tport_bytes[2];
    if (net_recv_all(sock, tport_bytes, 2) != 0) {
        log_err(my_port, "extend: read tport"); return;
    }
    uint16_t target_port = (uint16_t)((tport_bytes[0] << 8) | tport_bytes[1]);

    uint8_t client_pub[EC_PUBKEY_LEN];
    if (net_recv_all(sock, client_pub, EC_PUBKEY_LEN) != 0) {
        log_err(my_port, "extend: read pubkey"); return;
    }

    aes_key_t master = {0};
    if (crypto_ecdh_derive(&g_node_kp, client_pub, &master) != 0) {
        log_err(my_port, "extend: ECDH failed"); return;
    }

    /* Split master into keys matching what client_instrumented stores */
    aes_key_t henc = {0}, hmk = {0}, bkey = {0};
    split_master_keys(&master, &henc, &hmk, &bkey);

    /* Store session keyed by hint. MODE_DATA packets carry a rotating
     * hint derived from hint_seed, this benchmark binary intentionally
     * keeps client_instrumented.c's constant pkt_counter=0, so the
     * matching single expected value is HMAC(hint_seed, 0), computed
     * once here for both roles (matching client_instrumented.c's
     * build_paths(), which computes the return header's hints the
     * identical way via packet_derive_hop_hint()). */
    session_entry_t *sess = session_alloc();
    if (!sess) { log_err(my_port, "extend: session store full"); return; }
    {
        aes_key_t hint_seed = {0};
        if (packet_derive_hint_seed(&master, &hint_seed) != 0 ||
            packet_derive_hop_hint(&hint_seed, 0, sess->hint) != 0) {
            log_err(my_port, "extend: hint derivation failed"); return;
        }
    }
    sess->header_enc_key   = henc;
    sess->header_mac_key   = hmk;
    sess->return_blind_key = bkey; /* same value client sends SG as recv_blind[i] */
    sess->role              = role;

    /* Zero the stack copies of the ECDH master and its
     * rotation-derived intermediates now that they're fully copied into
     * `sess`. explicit_bzero, not memset, so it can't be optimized away. */
    explicit_bzero(&master, sizeof(master));
    explicit_bzero(&henc, sizeof(henc));
    explicit_bzero(&hmk, sizeof(hmk));
    explicit_bzero(&bkey, sizeof(bkey));

    /* Send our pubkey back */
    net_send_all(sock, g_node_kp.pubkey_bytes, EC_PUBKEY_LEN);

    char logbuf[64];
    snprintf(logbuf, sizeof(logbuf), "extend: session ready (port %u)", my_port);
    log_msg(my_port, logbuf);

    /* Relay if target_port != 0 */
    if (target_port != 0) {
        uint8_t rlen_bytes[2];
        if (net_recv_all(sock, rlen_bytes, 2) != 0) {
            log_err(my_port, "extend relay: read rlen"); return;
        }
        uint16_t rlen = (uint16_t)((rlen_bytes[0] << 8) | rlen_bytes[1]);

        uint8_t relay_buf[512];
        if (rlen > sizeof(relay_buf)) {
            log_err(my_port, "extend relay: payload too large"); return;
        }
        if (net_recv_all(sock, relay_buf, rlen) != 0) {
            log_err(my_port, "extend relay: read payload"); return;
        }

        SOCKET next_sock = net_connect(LOCALHOST, target_port);
        if (next_sock == INVALID_SOCKET) {
            log_err(my_port, "extend relay: connect failed"); return;
        }

        uint8_t mode = MODE_EXTEND;
        net_send_all(next_sock, &mode,     1);
        net_send_all(next_sock, relay_buf, rlen);

        uint8_t target_pub[EC_PUBKEY_LEN];
        if (net_recv_all(next_sock, target_pub, EC_PUBKEY_LEN) != 0) {
            net_close(next_sock); return;
        }
        net_send_all(sock, target_pub, EC_PUBKEY_LEN);

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
    /* P5: this hop's inbound link total, real+cover undifferentiated,
     * see measure.h's comment. */
    measure_hop_bytes((LONGLONG)WIRE_PACKET_SIZE);

    /* Extract hint from outermost header block */
    const uint8_t *hint = pkt.data + ADDR_BYTES + BLIND_KEY_BYTES + FLAG_BYTES
                                    + NONCE_BYTES + MAC_BYTES;

    session_keys_t keys;
    int sess_idx = session_find(hint, &keys);
    if (sess_idx < 0) {
        log_err(my_port, "data: no session for hint, drop"); return;
    }
    order_probe_log("recv", sess_idx, my_port);   /* Track-A probe */

    hop_info_t    hop_info = {0};
    wire_packet_t out_pkt  = {0};

    /* Cover isn't dropped here: it traverses every hop like real
     * traffic and is only discarded at the SG via the PKT_DUMMY check
     * inside the e2e payload (service_gateway_instrumented.c). This
     * file's session_find() matches a single static per-session hint
     * with no rotating window, unlike production mix_node.c, so there's
     * no hint-window domain-desync risk to reason about here when cover
     * reaches MN2/MN3. */
    MEASURE_HOP_BEGIN();                                  /* P1 start */
    int peel_rc = packet_sphinx_peel(&pkt,
                           &keys.header_enc_key,
                           &keys.header_mac_key,
                           hint, &hop_info, &out_pkt);
    MEASURE_HOP_END();                                    /* P1 end */
    if (peel_rc != 0) {
        log_err(my_port, "data: peel failed, drop"); return;
    }

    /* P4: count every successfully peeled packet at the entry node (MN1/MNi)
     * This includes cover packets, measures total throughput at network entry. */
    if (my_port == PORT_MIX_1 || my_port == PORT_MIX_I) {
        measure_sg_goodput((LONGLONG)WIRE_PACKET_SIZE);
    }

    /* Replay check: reject an exact resend of a packet already forwarded
     * in this session (see mix_node.c's handle_data() for the full
     * rationale). */
    int replayed = session_check_nonce_by_idx(sess_idx, hint, hop_info.nonce);
    if (replayed) {
        log_err(my_port, "data: replayed nonce, drop"); return;
    }

    char logbuf[80];
    snprintf(logbuf, sizeof(logbuf),
             "data: peeled OK -> port %u", hop_info.next_port);
    log_msg(my_port, logbuf);

#ifdef ASN_POOL_MIXING
    /* Track B: defer to the shared pool instead of forwarding
     * immediately: the flush thread sends this packet, in shuffled
     * order alongside whatever else is in the current batch, on its own
     * schedule. No mix_delay_sleep() here: the batch window itself is
     * the mixing mechanism, not a per-packet delay layered on top. */
    if (pool_mix_enqueue(&out_pkt, hop_info.next_port, sess_idx) != 0) {
        log_err(my_port, "data: pool full, drop");
    }
#else
    /* Delay before connect(), see
     * mix_node.c's matching comment for why (sleeping after connect() only
     * delays the payload write, not the SYN a network observer sees). */
#ifdef ASN_LOOPIX_MIXING
    mix_delay_sleep();
#endif

    /* Track-A probe: logged immediately before net_connect(), matching
     * this codebase's established convention that the TCP SYN, not the
     * later payload write, is the event a network observer actually
     * sees (see the Mixing-delay ordering discussion elsewhere in this
     * project). */
    order_probe_log("send", sess_idx, my_port);
    SOCKET next_sock = net_connect(LOCALHOST, hop_info.next_port);
    if (next_sock == INVALID_SOCKET) {
        log_err(my_port, "data: connect next hop"); return;
    }

    uint8_t mode = MODE_DATA;
    net_send_all(next_sock, &mode,        1);
    net_send_all(next_sock, out_pkt.data, WIRE_PACKET_SIZE);
    net_close(next_sock);
#endif /* ASN_POOL_MIXING */
}

/* MODE_RETURN handler */
static void handle_return(SOCKET sock, uint16_t my_port) {
    uint8_t wire[WIRE_PACKET_SIZE];
    if (net_recv_all(sock, wire, WIRE_PACKET_SIZE) != 0) {
        log_err(my_port, "return: read packet"); return;
    }
    /* P5: this hop's inbound return-link total (real+cover
     * undifferentiated, same reasoning as handle_data() above). */
    measure_hop_bytes((LONGLONG)WIRE_PACKET_SIZE);

    /* Parse return header from front of wire packet */
    return_header_t rhdr = {0};
    memcpy(&rhdr, wire, RETURN_HEADER_SIZE);

    /* Look up session by hint in outermost block */
    const uint8_t *hint = rhdr.blocks[0].hint;
    session_keys_t keys;
    int sess_idx = session_find(hint, &keys);
    if (sess_idx < 0) {
        log_err(my_port, "return: no session for hint, drop"); return;
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

    /* Replay check, see mix_node.c::handle_return() for the full
     * rationale. */
    int return_replayed = session_check_return_nonce_by_idx(sess_idx, hint, next_addr.nonce);
    if (return_replayed) {
        log_err(my_port, "return: replayed nonce, drop"); return;
    }

    /* Cancel this hop's layer of the SG's return-path pre-blinding,
     * see mix_node.c::handle_return() for the full rationale. */
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

    next_hop_t route = return_next_hop(my_port);

    char logbuf[80];
    if (route.addr != NULL) {
        /* Intermediate node, forward to next mix node */
        snprintf(logbuf, sizeof(logbuf),
                 "return: forwarding -> port %u", route.port);
        log_msg(my_port, logbuf);

        /* Delay before connect(). */
#ifdef ASN_LOOPIX_MIXING
        mix_delay_sleep();
#endif
        SOCKET next_sock = net_connect(route.addr, route.port);
        if (next_sock == INVALID_SOCKET) {
            log_err(my_port, "return: connect next hop"); return;
        }
        uint8_t mode = MODE_RETURN;
        net_send_all(next_sock, &mode,    1);
        net_send_all(next_sock, out_wire, WIRE_PACKET_SIZE);
        net_close(next_sock);
    } else {
        /* Final node (MNa or MNx), deliver directly to Client/Sender */
        char dest_ip[16];
        snprintf(dest_ip, sizeof(dest_ip), "%u.%u.%u.%u",
                 next_addr.next_ip[0], next_addr.next_ip[1],
                 next_addr.next_ip[2], next_addr.next_ip[3]);

        snprintf(logbuf, sizeof(logbuf),
                 "return: delivering to %s:%u", dest_ip, next_addr.next_port);
        log_msg(my_port, logbuf);

        /* Delay before connect(). */
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


static uint16_t g_my_port_global = 0;

/* Return-path cover is genuine and SG-originated
 * (service_gateway_instrumented.c), traversing every return hop like a
 * real response, mirroring production mix_node.c. */

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
    measure_init(MEASURE_P1 | MEASURE_P4 | MEASURE_P5); /* P1: hop timer | P4: entry throughput | P5: per-hop link bytes */
    order_probe_init(port);   /* Track-A probe: opt-in via env, see below */
#ifdef ASN_POOL_MIXING
    pool_mix_init(port);
    HANDLE pool_flush_thread = CreateThread(NULL, 0, pool_mix_flush_thread, NULL, 0, NULL);
    if (pool_flush_thread) CloseHandle(pool_flush_thread);
#endif

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

    SOCKET server_sock = net_listen(port);
    if (server_sock == INVALID_SOCKET) { net_cleanup(); return 1; }

    printf("[MN:%u] ready\n", port); fflush(stdout);

    g_my_port_global = port;

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