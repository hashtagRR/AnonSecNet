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
#include "common/measure.h"          /* P2: session timer | P3: link byte counter */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common/posix_compat.h"
#include <math.h>
#include <openssl/rand.h>
#include <stdatomic.h>


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

    /* Pre-built return header (rebuilt each session) */
    return_header_t return_hdr;
    /* M-c: addrs used to build return_hdr above, stashed so
     * build_spare_return_header() can build additional (cover) headers
     * without re-deriving them, see build_paths()'s comment. */
    uint8_t  return_addrs[N_PATH_HOPS][ADDR_BYTES];

    /* Client response address (embedded in return header innermost layer) */
    uint8_t  client_addr[ADDR_BYTES];

    int ready;
} client_state_t;

static client_state_t g_state = {0};

/* Response synchronisation */
static uint8_t          g_resp_buf[WIRE_PACKET_SIZE];
static volatile int     g_resp_ready = 0;
static CRITICAL_SECTION g_resp_lock;
static CRITICAL_SECTION g_send_path_lock;  /* guards g_state.send_path */
static HANDLE           g_resp_event;

static void log_msg(const char *m) { printf("[Client] %s\n", m); fflush(stdout); }
static void log_err(const char *m) { fprintf(stderr,"[Client] ERROR: %s\n",m); fflush(stderr); }

/* ECDHE with a single node */
static int ecdhe_with_node(const char *addr, uint16_t port,
                            uint8_t    role,
                            aes_key_t *out_master,
                            uint8_t    out_hint[HINT_BYTES],
                            uint8_t    out_node_pub[EC_PUBKEY_LEN]) {
    ecdh_keypair_t kp = {0};
    if (crypto_ecdh_keygen(&kp) != 0) return -1;

    memcpy(out_hint, kp.pubkey_bytes + 1, HINT_BYTES);

    SOCKET s = net_connect(addr, port);
    if (s == INVALID_SOCKET) { crypto_ecdh_free(&kp); return -1; }

    uint8_t mode = MODE_EXTEND, tport[2] = {0, 0};
    net_send_all(s, &mode,           1);
    net_send_all(s, &role,           1);
    net_send_all(s, tport,           2);
    net_send_all(s, kp.pubkey_bytes, EC_PUBKEY_LEN);

    int rc = net_recv_all(s, out_node_pub, EC_PUBKEY_LEN);
    net_close(s);

    if (rc != 0) { crypto_ecdh_free(&kp); return -1; }
    rc = crypto_ecdh_derive(&kp, out_node_pub, out_master);
    crypto_ecdh_free(&kp);
    return rc;
}

/* Telescoped ECDHE through an entry node
 * Same mechanism/rationale as production client.c::ecdhe_telescoped_path()
 *, see that file's comment. This benchmark client drives every Table 2/
 * Figure 5/6/7 measurement, so it needs the identical mechanism. */
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

        if (i == 0) {
            uint8_t mode = MODE_EXTEND;
            net_send_all(s, &mode,           1);
            net_send_all(s, &role,           1);
            net_send_all(s, tport,           2);
            net_send_all(s, kp.pubkey_bytes, EC_PUBKEY_LEN);
        } else {
            uint8_t relay_buf[1 + 2 + EC_PUBKEY_LEN];
            relay_buf[0] = role;
            relay_buf[1] = tport[0];
            relay_buf[2] = tport[1];
            memcpy(relay_buf + 3, kp.pubkey_bytes, EC_PUBKEY_LEN);
            uint16_t rlen = (uint16_t)sizeof(relay_buf);
            uint8_t  rlen_bytes[2] = { (uint8_t)(rlen >> 8),
                                        (uint8_t)(rlen & 0xFF) };
            net_send_all(s, rlen_bytes, 2);
            net_send_all(s, relay_buf,  rlen);
        }

        if (net_recv_all(s, node_pubs[i], EC_PUBKEY_LEN) != 0) {
            crypto_ecdh_free(&kp); goto done;
        }
        int rc = crypto_ecdh_derive(&kp, node_pubs[i], &masters[i]);
        crypto_ecdh_free(&kp);
        if (rc != 0) goto done;
    }
    ok = 0;
done:
    net_close(s);
    return ok;
}

/* Key splitting from ECDH master
 *
 * packet_sphinx_build() and packet_sphinx_peel() use header_enc_key,
 * header_mac_key, and blind_key DIRECTLY, no internal re-derivation.
 *
 * Three independent keys are produced by packet_derive_hop_keys(), a
 * labelled PRF over the 32-byte ECDH master, identical to
 * mix_node_instrumented.c::split_master_keys() (and production
 * mix_node.c), not a byte-rotation, which would be invertible (any one
 * of the three rotated keys trivially yielding the other two).
 *
 * Used for BOTH the sending path (stored in sphinx_path_t.hops[i] for
 * packet_sphinx_build) and the receiving path (stored in recv_hops[i]
 * for packet_build_return_header, which also uses keys directly).
 */
static void split_master_keys(const aes_key_t *master,
                              aes_key_t *henc,
                              aes_key_t *hmac_key,
                              aes_key_t *bkey) {
    packet_derive_hop_keys(master, henc, hmac_key, bkey);
}

/* Populate hop_session_t for the SENDING path (MN1/MN2/MN3).
 * Stores all three split keys; packet_sphinx_build uses them directly. */
static void derive_hop_send(const aes_key_t *master, hop_session_t *hop) {
    aes_key_t henc = {0}, hmac = {0}, bkey = {0};
    split_master_keys(master, &henc, &hmac, &bkey);
    hop->header_enc_key = henc;
    hop->header_mac_key = hmac;
    hop->blind_key      = bkey;
    /* This benchmark binary intentionally keeps a static-hint behavior
     * (every packet_sphinx_build() call below passes a constant
     * pkt_counter=0, unlike production client.c/sender.c which
     * increment a real per-session counter), Figure 2/3/Table 2
     * measure this unmodified path on purpose, see config.h's
     * HINT_WINDOW comment. hint_seed still needs deriving here (not
     * left zero) purely so each session's own hint value stays unique
     * to that session (HMAC(hint_seed, 0)) rather than every session
     * colliding on HMAC(zero-key, 0), mix_node_instrumented.c's own
     * matching mirrors this exact "derive once, match one static value"
     * scheme. */
    packet_derive_hint_seed(master, &hop->hint_seed);
}

/* Populate hop_session_t for the RECEIVING path (MNc/MNb/MNa).
 * packet_build_return_header uses header_enc_key and header_mac_key
 * directly. mix_node.c stores the same split keys after ECDH. */
static void derive_hop_recv(const aes_key_t *master, hop_session_t *hop) {
    aes_key_t henc = {0}, hmac = {0}, bkey = {0};
    split_master_keys(master, &henc, &hmac, &bkey);
    hop->header_enc_key = henc;
    hop->header_mac_key = hmac;
    hop->blind_key      = bkey;   /* unused on return path but populated */
    /* Same static-hint policy
     * as derive_hop_send() above, hint_seed still needs deriving (used
     * with a constant counter=0 at the one build_return_header() call
     * site below) purely so it is session-unique, not left zero. */
    packet_derive_hint_seed(master, &hop->hint_seed);
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

/* Lets multiple instrumented client
 * identities run concurrently on this one loopback testbed, each
 * listening on its own response port, so a shared mix node sees
 * genuinely interleaved traffic from distinct sessions instead of one
 * session at a time. Mirrors client.c's identical mechanism
 * (config.h's CLIENT_RESPONSE_PORT_COUNT). ASN_CLIENT_RESPONSE_PORT env
 * var overrides the default; falls back to CLIENT_RESPONSE_PORT
 * unchanged when unset, so a normal single-client run is unaffected. */
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
static int build_paths(void) {
    MEASURE_SESSION_BEGIN();             /* P2: start session timer */
    log_msg("building sending path A (MN1->MN2->MN3->SG)...");

    uint16_t send_ports[N_PATH_HOPS] = { PORT_MIX_1, PORT_MIX_2, PORT_MIX_3 };

    /* Build sending path sphinx_path_t. Telescoped through MN1, see
     * production client.c's identical comment. */
    {
        aes_key_t masters[N_PATH_HOPS];
        uint8_t   hints[N_PATH_HOPS][HINT_BYTES];
        uint8_t   node_pubs[N_PATH_HOPS][EC_PUBKEY_LEN];

        if (ecdhe_telescoped_path(send_ports, N_PATH_HOPS, SESSION_ROLE_A,
                                  masters, hints, node_pubs) != 0) {
            log_err("telescoped ECDHE failed on sending path"); return -1;
        }
        for (int i = 0; i < N_PATH_HOPS; i++) {
            derive_hop_send(&masters[i], &g_state.send_path.hops[i]);
            g_state.send_path.hop_ports[i] = send_ports[i];

            char logbuf[64];
            snprintf(logbuf, sizeof(logbuf),
                     "  sending hop %d ready (port %u)", i+1, send_ports[i]);
            log_msg(logbuf);
        }
        explicit_bzero(masters, sizeof(masters));
    }

    /* E2E session with SG via path A -> K_R-SG-A */
    {
        aes_key_t master = {0};
        uint8_t   hint[HINT_BYTES]      = {0};
        uint8_t   node_pub[EC_PUBKEY_LEN] = {0};
        if (ecdhe_with_node(LOCALHOST, PORT_SERVICE_GW, SESSION_ROLE_A,
                            &master, hint, node_pub) != 0) {
            log_err("ECDHE failed with SG (path A)"); return -1;
        }
        g_state.k_r_sg_a              = master;
        g_state.send_path.e2e.e2e_key = master;
        g_state.send_path.next_port   = PORT_MIX_1;
        g_state.send_path.sg_port     = PORT_SERVICE_GW;
        log_msg("  K_R-SG-A established");
    }

    log_msg("building receiving path B (MNc->MNb->MNa->Client)...");

    /* Receiving path: establish ECDHE with MNc, MNb, MNa
     * Order [0]=MNc, [1]=MNb, [2]=MNa  (outermost to innermost) */
    uint16_t recv_ports[N_PATH_HOPS] = { PORT_MIX_C, PORT_MIX_B, PORT_MIX_A };

    /* Telescoped through MNc, see production client.c. */
    {
        aes_key_t masters[N_PATH_HOPS];
        uint8_t   hints[N_PATH_HOPS][HINT_BYTES];
        uint8_t   node_pubs[N_PATH_HOPS][EC_PUBKEY_LEN];

        if (ecdhe_telescoped_path(recv_ports, N_PATH_HOPS, SESSION_ROLE_B,
                                  masters, hints, node_pubs) != 0) {
            log_err("telescoped ECDHE failed on receiving path"); return -1;
        }
        for (int i = 0; i < N_PATH_HOPS; i++) {
            derive_hop_recv(&masters[i], &g_state.recv_hops[i]);

            /* Store MNc pubkey and addr for embedding in outbound payload */
            if (i == 0) {
                memcpy(g_state.mnc_pubkey, node_pubs[0], EC_PUBKEY_LEN);
                make_addr_bytes(LOCALHOST, PORT_MIX_C, g_state.mnc_addr);
            }

            char logbuf[64];
            snprintf(logbuf, sizeof(logbuf),
                     "  receiving hop %d ready (port %u)", i, recv_ports[i]);
            log_msg(logbuf);
        }
        explicit_bzero(masters, sizeof(masters));
    }

    /* E2E session with SG via path B -> K_R-SG-B */
    {
        aes_key_t master = {0};
        uint8_t   hint[HINT_BYTES]      = {0};
        uint8_t   node_pub[EC_PUBKEY_LEN] = {0};
        if (ecdhe_with_node(LOCALHOST, PORT_SERVICE_GW, SESSION_ROLE_B,
                            &master, hint, node_pub) != 0) {
            log_err("ECDHE failed with SG (path B)"); return -1;
        }
        g_state.k_r_sg_b = master;
        log_msg("  K_R-SG-B established");
    }

    /* Build Client address bytes (127.0.0.1:client_response_port()) */
    make_addr_bytes(LOCALHOST, client_response_port(), g_state.client_addr);

    /* Build return header:
     *   addrs[0] = MNb addr  (MNc learns this after peeling)
     *   addrs[1] = MNa addr  (MNb learns this)
     *   addrs[2] = Client addr (MNa learns this, final delivery)
     *   enc keys[0] = SK_R-MNc, [1] = SK_R-MNb, [2] = SK_R-MNa
     */
    uint8_t addrs[N_PATH_HOPS][ADDR_BYTES];
    make_addr_bytes(LOCALHOST, PORT_MIX_B, addrs[0]);
    make_addr_bytes(LOCALHOST, PORT_MIX_A, addrs[1]);
    memcpy(addrs[2], g_state.client_addr, ADDR_BYTES);

    /* addrs/enc_keys/mac_keys are session-static; stash addrs for
     * build_spare_return_header() below (M-c) to reuse without
     * re-deriving them from scratch for every cover packet. */
    memcpy(g_state.return_addrs, addrs, sizeof(addrs));

    aes_key_t enc_keys[N_PATH_HOPS], mac_keys[N_PATH_HOPS];
    uint8_t   hints[N_PATH_HOPS][HINT_BYTES];
    for (int i = 0; i < N_PATH_HOPS; i++) {
        enc_keys[i] = g_state.recv_hops[i].header_enc_key;
        mac_keys[i] = g_state.recv_hops[i].header_mac_key;
        /* Constant counter=0,
         * matching derive_hop_send()'s deliberate static-hint policy for
         * this benchmark binary, see its comment. This binary never
         * rotates the return-path hint per request the way client.c
         * does; the spare cover headers (below) deliberately keep the
         * same policy (also counter=0) rather than reintroducing
         * rotation here, since packet_build_return_header() draws a
         * fresh RAND_bytes nonce internally on every call regardless of
         * the hint counter, that alone is enough for each spare header
         * to be distinct (and pass replay checks) while still matching
         * this binary's single, flat, non-windowed session hint at every
         * return hop (mix_node_instrumented.c's session_find(), unlike
         * production mix_node.c, has no rotating-hint window to match
         * against). */
        packet_derive_hop_hint(&g_state.recv_hops[i].hint_seed, 0, hints[i]);
    }

    if (packet_build_return_header(enc_keys, mac_keys, hints,
                                   addrs, &g_state.return_hdr) != 0) {
        log_err("failed to build return header"); return -1;
    }

    g_state.ready = 1;
    MEASURE_SESSION_END();               /* P2: stop session timer */
    log_msg("both paths ready");
    return 0;
}

/* M-c: builds one "spare" return header for the SG to fire autonomously
 * as an indistinguishable return-path cover packet, see client.c's
 * identical function and this file's build_paths() comment on why
 * counter=0 (not a rotating counter) is correct here. Does not touch
 * g_state.return_hdr (reserved for the real path). */
static int build_spare_return_header(return_header_t *out) {
    aes_key_t enc_keys[N_PATH_HOPS], mac_keys[N_PATH_HOPS];
    uint8_t   hints[N_PATH_HOPS][HINT_BYTES];
    for (int i = 0; i < N_PATH_HOPS; i++) {
        enc_keys[i] = g_state.recv_hops[i].header_enc_key;
        mac_keys[i] = g_state.recv_hops[i].header_mac_key;
        packet_derive_hop_hint(&g_state.recv_hops[i].hint_seed, 0, hints[i]);
    }
    return packet_build_return_header(enc_keys, mac_keys, hints,
                                      g_state.return_addrs, out);
}


/* Response listener thread */
static DWORD WINAPI response_listener(LPVOID arg) {
    (void)arg;
    SOCKET srv = net_listen(client_response_port());
    if (srv == INVALID_SOCKET) { log_err("response listener bind failed"); return 1; }

    char logbuf[64];
    snprintf(logbuf, sizeof(logbuf),
             "response listener on port %u", client_response_port());
    log_msg(logbuf);

    while (1) {
        SOCKET conn = net_accept(srv);
        if (conn == INVALID_SOCKET) break;

        uint8_t wire[WIRE_PACKET_SIZE];
        if (net_recv_all(conn, wire, WIRE_PACKET_SIZE) == 0) {
            /* P5: MNa->Client return-inbound link total, real+cover
             * undifferentiated: see measure.h's comment. Distinct from
             * P3's link_bytes.csv, which only ever counted this client's
             * own OUTBOUND (forward) send side. */
            measure_hop_bytes((LONGLONG)WIRE_PACKET_SIZE);
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
                /* M-c: see client.c's identical comment, leading
                 * plaintext flags byte, not GCM success/failure, is what
                 * distinguishes real from cover now. */
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


/* Cover traffic (Phase 8) */

/* libc rand()/srand() is process-global, non-reentrant state; this file
 * runs the Poisson dispatch clock (poisson_interval_ms) and, in hardened
 * builds, the real-arrival clock (real_interval_ms) on two DIFFERENT
 * threads with no coordination, concurrent unsynchronized rand() calls
 * are a data race, and most callers of this class of bug in mix_node.c
 * never called srand() at all. RAND_bytes is thread-safe and needs no
 * seeding: use it here too. */
static double uniform01(void) {
    uint32_t r;
    if (RAND_bytes((uint8_t *)&r, sizeof(r)) != 1) r = 1;
    return ((double)r + 1.0) / (4294967296.0 + 1.0);
}

/* This client's persistent rate-tier mean, drawn
 * once by rate_tier_init() (called from main()) and held fixed thereafter
 *, see common/config.h's RATE_TIER_INTERVALS_MS comment and client.c's
 * identical mechanism, which this mirrors. Initialized to the un-tiered
 * legacy constant so any call before rate_tier_init() runs still behaves
 * sanely rather than reading garbage. */
static double g_rate_tier_interval_ms = DUMMY_INTERVAL_MS;

/* Persists this client identity's rate tier the same way client.c does
 * (client_rate_tier.txt in cwd, drawn once from real entropy, reused
 * verbatim on every later run). */
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
    /* Inverse CDF of Exponential: -mean * ln(U), U ~ Uniform(0,1)        */
    double u = uniform01();
    double interval = -g_rate_tier_interval_ms * log(u);
    if (interval < 10.0)  interval = 10.0;
    if (interval > 1000.0) interval = 1000.0;
    return (DWORD)interval;
}

/* Step 8.6: Probabilistic slot replacement
 *
 * Each Poisson slot, draw U ~ Uniform(0,1).
 * If U < g_load_fraction  -> send real packet (pre-built by crypto_thread).
 * Otherwise               -> send cover packet.
 *
 * This directly implements Step 8.6: the aggregate rate is constant
 * (one packet per Poisson slot regardless of load), and the real/cover
 * split tracks the requested fraction exactly in expectation with no
 * timer drift, token accumulation, or rate mismatch.                       */

static int send_get(const char *key);   /* forward declaration */

/* Load fraction set by SET_RATE command.  0.0 = all cover, 1.0 = all real */
static _Atomic double g_load_fraction = 0.0;

/* Ring buffer per packet type: crypto_thread pre-builds, cover_thread consumes
 * Depth 64 absorbs Sphinx build jitter (~2-5ms each) at the Poisson clock
 * (usable capacity is 63, pq_free() reserves one sentinel slot)          */
#define PKT_QUEUE_DEPTH 64
typedef struct {
    wire_packet_t buf[PKT_QUEUE_DEPTH];
    int           head;     /* producer */
    int           tail;     /* consumer */
} pkt_queue_t;

static pkt_queue_t      g_real_q  = {0};
static pkt_queue_t      g_cover_q = {0};
static CRITICAL_SECTION g_pkt_lock;

/* Returns slots free in queue (0..DEPTH-1) */
static int pq_free(const pkt_queue_t *q) {
    int used = (q->head - q->tail + PKT_QUEUE_DEPTH) % PKT_QUEUE_DEPTH;
    return (PKT_QUEUE_DEPTH - 1) - used;
}

static int pq_push(pkt_queue_t *q, const wire_packet_t *pkt) {
    int next = (q->head + 1) % PKT_QUEUE_DEPTH;
    if (next == q->tail) return -1;   /* full */
    q->buf[q->head] = *pkt;
    q->head = next;
    return 0;
}

static int pq_pop(pkt_queue_t *q, wire_packet_t *out) {
    if (q->tail == q->head) return -1;   /* empty */
    *out = q->buf[q->tail];
    q->tail = (q->tail + 1) % PKT_QUEUE_DEPTH;
    return 0;
}

/* Builds one real (GET "bench") packet and pushes it to g_real_q if there is
 * room. Shared by crypto_thread (legacy mode, unconditional top-up) and
 * real_arrival_thread (hardened mode, load-scaled rate) so both modes
 * build the exact same packet. */
static void build_and_push_real(void) {
    const char *key = "bench";
    size_t klen = strlen(key);
    uint8_t payload[MAX_INNER_PAYLOAD];
    memset(payload, 0, sizeof(payload));
    size_t poff = 0;
    memcpy(payload+poff, g_state.mnc_pubkey,  EC_PUBKEY_LEN);      poff+=EC_PUBKEY_LEN;
    memcpy(payload+poff, g_state.mnc_addr,    ADDR_BYTES);         poff+=ADDR_BYTES;

    wire_packet_t pkt = {0};
    EnterCriticalSection(&g_send_path_lock);
    /* Pre-existing bug fix, found while verifying M-c end-to-end: this
     * used to embed g_state.return_hdr as built once at setup and never
     * refreshed, so every real GET after the first carried the byte-
     * identical return header, including its nonces, which
     * packet_build_return_header() only randomizes when actually called.
     * The return-path replay detector at the first return hop correctly
     * rejected every one of those as a replay, meaning this benchmark
     * client could never complete more than one real round trip and
     * nothing previously caught it (see mix_node_instrumented.c's
     * handle_extend() comment for why). Rebuilding here, under the same
     * lock used for the forward path, gives a fresh nonce per request
     * (the hint stays HMAC(hint_seed, 0), deliberately unchanged, see
     * build_paths()'s comment, so this hop's flat, non-windowed
     * session lookup still matches). */
    if (build_spare_return_header(&g_state.return_hdr) != 0) {
        LeaveCriticalSection(&g_send_path_lock); return;
    }
    memcpy(payload+poff, &g_state.return_hdr, RETURN_HEADER_SIZE); poff+=RETURN_HEADER_SIZE;
    payload[poff++] = TYPE_GET;
    payload[poff++] = (uint8_t)klen;
    memcpy(payload+poff, key, klen); poff+=klen;
    if (poff > MAX_INNER_PAYLOAD) { LeaveCriticalSection(&g_send_path_lock); return; }

    int ok = (packet_sphinx_build(&g_state.send_path, payload, (uint16_t)poff,
                                  PKT_REAL|PKT_DEST_SERVICE, 0, &pkt) == 0);
    LeaveCriticalSection(&g_send_path_lock);
    if (!ok) return;

    EnterCriticalSection(&g_pkt_lock);
    pq_push(&g_real_q, &pkt);   /* drop silently if full, see
                                  * real_arrival_thread()'s comment */
    LeaveCriticalSection(&g_pkt_lock);
}

/* crypto_thread: keep buffer stocked */
static DWORD WINAPI crypto_thread(LPVOID arg) {
    (void)arg;
    while (1) {
        if (!g_state.ready) { Sleep(5); continue; }

        EnterCriticalSection(&g_pkt_lock);
        int real_free  = pq_free(&g_real_q);
        int cover_free = pq_free(&g_cover_q);
        LeaveCriticalSection(&g_pkt_lock);

        if (real_free == 0 && cover_free == 0) { Sleep(1); continue; }

#ifndef ASN_LOOPIX_MIXING
        /* Legacy mode: keep g_real_q topped up unconditionally, the
         * Bernoulli-slot dispatch clock below decides the real/cover mix.
         * Under ASN_LOOPIX_MIXING, real_arrival_thread() builds real
         * packets itself at a load-scaled rate instead, so this thread
         * only tops up cover in that mode. */
        if (real_free > 0) build_and_push_real();
#endif

        /* Build one cover packet. M-c: carries a spare return header
         * (see client.c's build_outbound_cover_with_spare_return()) so
         * the SG can fire an indistinguishable return-path cover packet
         *, instead of packet_sphinx_dummy()'s pure-random payload. */
        if (cover_free > 0) {
            wire_packet_t pkt = {0};
            return_header_t spare = {0};
            int ok = 0;
            if (build_spare_return_header(&spare) == 0) {
                uint8_t payload[MAX_INNER_PAYLOAD];
                if (RAND_bytes(payload, MAX_INNER_PAYLOAD) == 1) {
                    memcpy(payload, &spare, RETURN_HEADER_SIZE);
                    EnterCriticalSection(&g_send_path_lock);
                    ok = (packet_sphinx_build(&g_state.send_path, payload,
                                              MAX_INNER_PAYLOAD,
                                              PKT_DUMMY | PKT_DEST_SERVICE,
                                              0, &pkt) == 0);
                    LeaveCriticalSection(&g_send_path_lock);
                }
            }
            if (ok) {
                EnterCriticalSection(&g_pkt_lock);
                pq_push(&g_cover_q, &pkt);
                LeaveCriticalSection(&g_pkt_lock);
            }
        }
    }
    return 0;
}

/* outbound_cover_thread: Poisson clock, probabilistic real/cover decision */
static volatile int g_slots_total = 0;
static volatile int g_slots_real  = 0;
static volatile int g_slots_cover = 0;
#ifndef ASN_LOOPIX_MIXING
static volatile int g_slots_fallback = 0;
#endif

#ifndef ASN_LOOPIX_MIXING
static DWORD WINAPI outbound_cover_thread(LPVOID arg) {
    (void)arg;

    while (1) {
        Sleep(poisson_interval_ms());
        if (!g_state.ready) continue;

        g_slots_total++;

        double u = uniform01();
        double load = atomic_load(&g_load_fraction);
        int want_real = (u < load);

        pkt_queue_t *primary = want_real ? &g_real_q : &g_cover_q;
        pkt_queue_t *fallback = want_real ? &g_cover_q : &g_real_q;

        wire_packet_t pkt = {0};
        int got = 0;

        /* Try primary queue */
        for (int i = 0; i < 50; i++) {
            EnterCriticalSection(&g_pkt_lock);
            got = (pq_pop(primary, &pkt) == 0);
            LeaveCriticalSection(&g_pkt_lock);
            if (got) break;
            Sleep(1);
        }

        int used_real = want_real;

        /* Fallback if needed */
        if (!got) {
            EnterCriticalSection(&g_pkt_lock);
            if (pq_pop(fallback, &pkt) == 0) {
                got = 1;
                used_real = !want_real;
                g_slots_fallback++;
            }
            LeaveCriticalSection(&g_pkt_lock);
        }

        if (!got) continue; // should never happen after warmup

        if (used_real) g_slots_real++;
        else           g_slots_cover++;

        SOCKET s = net_connect(LOCALHOST, PORT_MIX_1);
        if (s == INVALID_SOCKET) continue;

        uint8_t mode = MODE_DATA;
        net_send_all(s, &mode, 1);
        net_send_all(s, pkt.data, WIRE_PACKET_SIZE);

        if (used_real)
            measure_link_bytes(0, WIRE_PACKET_SIZE);
        else
            measure_link_bytes(1, WIRE_PACKET_SIZE);

        net_close(s);

        /* Debug every ~1000 packets */
        if (g_slots_total % 1000 == 0) {
            printf("[STATS] total=%d real=%d cover=%d fallback=%d load=%.3f\n",
                   g_slots_total, g_slots_real, g_slots_cover, g_slots_fallback,
                   atomic_load(&g_load_fraction));
            fflush(stdout);
        }
    }
    return 0;
}
#else
/* Loopix-style hardened harness: a single shared
 * Poisson dispatch clock (same poisson_interval_ms() as legacy mode)
 * drains g_real_q preferentially and falls back to g_cover_q, so the
 * aggregate observable send rate is bounded by that one fixed-rate
 * clock, not additive across two independent clocks. Matches
 * production client.c/sender.c's
 * mailbox-priority dispatch (real always wins the slot when available).
 *
 * real_arrival_thread() below only makes real packets AVAILABLE (at a
 * load-scaled Poisson rate, REAL_MAX_PPS matching
 * eval2/scripts/coverleak_run.py's R_MAX_PPS), it never talks to the
 * network directly. Actual sending is done exclusively by the shared
 * dispatch clock (outbound_cover_thread, unchanged name for minimal
 * diff against legacy mode). At high load, real arrivals can outpace
 * the fixed dispatch clock's drain rate (~1000/DUMMY_INTERVAL_MS pps);
 * g_real_q then backs up (bounded depth 64, oldest-preserved, newest
 * silently dropped once full) rather than the clock speeding up, this
 * is the honest, expected cost of a rate-bounded shared clock, not a
 * bug, and mirrors Loopix's own known cover/loop-rate provisioning
 * trade-off. */
#define REAL_MAX_PPS 30.0

static DWORD real_interval_ms(void) {
    double load = atomic_load(&g_load_fraction);
    if (load <= 0.0) return 1000;   /* idle poll interval, no real traffic requested */
    double rate = load * REAL_MAX_PPS;
    double u = uniform01();
    double iv = -1000.0 / rate * log(u);
    if (iv < 1.0)    iv = 1.0;
    if (iv > 2000.0) iv = 2000.0;
    return (DWORD)iv;
}

static DWORD WINAPI real_arrival_thread(LPVOID arg) {
    (void)arg;
    while (1) {
        Sleep(real_interval_ms());
        if (!g_state.ready) continue;
        if (atomic_load(&g_load_fraction) <= 0.0) continue;
        build_and_push_real();
    }
    return 0;
}

static DWORD WINAPI outbound_cover_thread(LPVOID arg) {
    (void)arg;
    while (1) {
        Sleep(poisson_interval_ms());   /* the one shared dispatch clock */
        if (!g_state.ready) continue;

        g_slots_total++;

        wire_packet_t pkt = {0};
        int used_real = 0;
        EnterCriticalSection(&g_pkt_lock);
        used_real = (pq_pop(&g_real_q, &pkt) == 0);
        LeaveCriticalSection(&g_pkt_lock);

        if (!used_real) {
            EnterCriticalSection(&g_pkt_lock);
            int got_cover = (pq_pop(&g_cover_q, &pkt) == 0);
            LeaveCriticalSection(&g_pkt_lock);
            if (!got_cover) continue;   /* both queues empty, rare, skip this slot */
        }

        if (used_real) g_slots_real++;
        else           g_slots_cover++;

        SOCKET s = net_connect(LOCALHOST, PORT_MIX_1);
        if (s == INVALID_SOCKET) continue;
        uint8_t mode = MODE_DATA;
        net_send_all(s, &mode, 1);
        net_send_all(s, pkt.data, WIRE_PACKET_SIZE);
        if (used_real) measure_link_bytes(0, WIRE_PACKET_SIZE);
        else            measure_link_bytes(1, WIRE_PACKET_SIZE);
        net_close(s);

        if (g_slots_total % 1000 == 0) {
            printf("[STATS] total=%d real=%d cover=%d load=%.3f\n",
                   g_slots_total, g_slots_real, g_slots_cover,
                   atomic_load(&g_load_fraction));
            fflush(stdout);
        }
    }
    return 0;
}
#endif

/* Send GET request */
static int send_get(const char *key) {
    if (!g_state.ready) { log_err("paths not ready"); return -1; }

    size_t klen = strlen(key);
    if (klen > 63) { log_err("key too long"); return -1; }

    /* Build inner payload:
     * [flags(1)][payload_len(2)][MNc_pubkey(65)][MNc_addr(6)]
     * [return_header(174)][TYPE_GET(1)][klen(1)][key]           */
    uint8_t inner[MAX_INNER_PAYLOAD + INNER_HDR_BYTES + RETURN_HDR_IN_PAYLOAD];
    memset(inner, 0, sizeof(inner));
    /* App data section */
    uint8_t app[MAX_INNER_PAYLOAD];
    memset(app, 0, sizeof(app));
    size_t aoff = 0;
    app[aoff++] = TYPE_GET;
    app[aoff++] = (uint8_t)klen;
    memcpy(app + aoff, key, klen); aoff += klen;

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

    wire_packet_t pkt = {0};
    EnterCriticalSection(&g_send_path_lock);
    int sphinx_ok = (packet_sphinx_build(&g_state.send_path,
                            payload, (uint16_t)poff,
                            PKT_REAL | PKT_DEST_SERVICE, 0, &pkt) == 0);
    LeaveCriticalSection(&g_send_path_lock);
    if (!sphinx_ok) {
        log_err("packet_sphinx_build failed"); return -1;
    }

    /* Send directly to MN1 */
    SOCKET s = net_connect(LOCALHOST, PORT_MIX_1);
    if (s == INVALID_SOCKET) { log_err("connect MN1"); return -1; }

    uint8_t mode = MODE_DATA;
    net_send_all(s, &mode,    1);
    net_send_all(s, pkt.data, WIRE_PACKET_SIZE);
    measure_link_bytes(0, WIRE_PACKET_SIZE);   /* P3: real bytes */
    net_close(s);

    char logbuf[128];
    snprintf(logbuf, sizeof(logbuf),
             "GET '%s' sent via MN1->MN2->MN3->SG", key);
    log_msg(logbuf);
    return 0;
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

    /* M-c: skip the leading flags byte, see client.c's wait_response()
     * for the identical change. response_listener() already filtered to
     * PKT_REAL before signalling this event. */
    n -= 1;
    if ((size_t)n > MAX_INNER_PAYLOAD) n = MAX_INNER_PAYLOAD;
    memcpy(out, plain + 1, (size_t)n);
    *out_len = (uint16_t)n;
    return 0;
}


/* Send session setup packet to SG */
static int send_setup(void) {
    /* See production client.c's matching comment.
     * Setup-phase only, not part of any timed benchmark loop, unlike
     * this binary's deliberately-static per-packet hint scheme, which
     * Figure 2/3/Table 2 do measure. */
    uint8_t binding_tag[MAC_BYTES];
    if (packet_derive_binding_tag(&g_state.k_r_sg_a, &g_state.k_r_sg_b,
                                  binding_tag) != 0) {
        log_err("binding tag derivation failed"); return -1;
    }

    /* Build setup payload */
    uint8_t payload[MAX_INNER_PAYLOAD];
    memset(payload, 0, sizeof(payload));
    size_t off = 0;

    payload[off++] = TYPE_SETUP;

    /* Sending-path blind keys (SK_R-MN1/MN2/MN3) are deliberately NOT
     * sent to the SG, it never reads them, only recv_blind[] below.
     * See production client.c::send_setup(). */

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

    wire_packet_t pkt = {0};
    if (packet_sphinx_build(&g_state.send_path, payload, (uint16_t)off,
                            PKT_REAL | PKT_DEST_SERVICE, 0, &pkt) != 0) {
        log_err("send_setup: build failed"); return -1;
    }

    SOCKET s = net_connect(LOCALHOST, PORT_MIX_1);
    if (s == INVALID_SOCKET) { log_err("send_setup: connect MN1"); return -1; }

    uint8_t mode = MODE_DATA;
    net_send_all(s, &mode, 1);
    net_send_all(s, pkt.data, WIRE_PACKET_SIZE);
    net_close(s);

    log_msg("session setup sent to SG");
    return 0;
}

/* Interactive loop */
static void run_interactive(void) {
    printf("\n+==========================================+\n");
    printf("|   Anon-Sec-Net v2 Client Ready           |\n");
    printf("|   Dual path | Sphinx | Return header     |\n");
    printf("|   Commands:                              |\n");
    printf("|     GET <key>   Retrieve content         |\n");
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

        if (strncmp(line, "GET ", 4) == 0) {
            const char *key = line + 4;
            if (!strlen(key)) { printf("Usage: GET <key>\n"); continue; }

            if (send_get(key) != 0) {
                printf("[Client] Request failed.\n"); continue;
            }

            uint8_t  resp[MAX_INNER_PAYLOAD];
            uint16_t resp_len = 0;

            if (wait_response(resp, &resp_len, 10000) == 0) {
                printf("\n[Client] Response (%u bytes):\n", resp_len);
                printf("-------------------------------------\n");
                printf("%.*s\n", (int)resp_len, resp);
                printf("-------------------------------------\n\n");
            } else {
                printf("[Client] No response (timeout).\n\n");
            }
        }  else if (len > 0) {
            printf("Unknown command.\n");
        }
    }
}

/* main */
int main(void) {
    SetConsoleOutputCP(65001);
    InitializeCriticalSection(&g_resp_lock);
    InitializeCriticalSection(&g_send_path_lock);
    InitializeCriticalSection(&g_pkt_lock);
    g_resp_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!g_resp_event) return 1;
    measure_init(MEASURE_P2 | MEASURE_P3 | MEASURE_P5);  /* P2: session timer | P3: outbound link bytes | P5: inbound (return) link bytes */

    if (net_init() != 0) return 1;
    CreateDirectoryA(PUBKEY_DIR, NULL);
    rate_tier_init();
    log_msg("Anon-Sec-Net v2 client starting...");

    if (build_paths() != 0) {
        log_err("path build failed, ensure all mix nodes and SG are running");
        net_cleanup(); return 1;
    }

	HANDLE lt = CreateThread(NULL, 0, response_listener, NULL, 0, NULL);
    if (!lt) { log_err("listener thread failed"); return 1; }
    CloseHandle(lt);
    Sleep(50);   /* give listener thread time to bind port 9020 */
    if (send_setup() != 0) {
        log_err("session setup failed"); return 1;
    }

    HANDLE ct = CreateThread(NULL, 0, outbound_cover_thread, NULL, 0, NULL);
    if (ct) CloseHandle(ct);
#ifdef ASN_LOOPIX_MIXING
    /* Hardened mode: real_arrival_thread only makes real packets
     * available (load-scaled rate); outbound_cover_thread above is the
     * single shared clock that actually sends. */
    HANDLE rt = CreateThread(NULL, 0, real_arrival_thread, NULL, 0, NULL);
    if (rt) CloseHandle(rt);
#endif

    /* Crypto workers: keep g_real_q / g_cover_q stocked */
    for (int i = 0; i < 4; i++) {
        HANDLE kp = CreateThread(NULL, 0, crypto_thread, NULL, 0, NULL);
        if (kp) CloseHandle(kp);
    }

    Sleep(200);

 /* Main thread: stdin command loop
     * Single reader (no race with any other thread).  This is the
     * benchmark client, there is no interactive GET prompt.
     *   SET_RATE <0.0 .. 1.0>   set Bernoulli load fraction
     *   quit                    exit cleanly                              */
    printf("[Client] Ready for SET_RATE commands\n"); fflush(stdout);

    char line[256];
    while (fgets(line, sizeof(line), stdin)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        if (len == 0) continue;

        if (strncmp(line, "SET_RATE ", 9) == 0) {
            double frac = atof(line + 9);
            if (frac < 0.0) frac = 0.0;
            if (frac > 1.0) frac = 1.0;
            atomic_store(&g_load_fraction, frac);
            printf("[RATE] %.3f\n", frac); fflush(stdout);
        } else if (strcmp(line, "quit") == 0) {
            measure_flush();
            Sleep(50);   // ensure file write completes
            break;
        } else {
            printf("[Client] unknown: %s\n", line); fflush(stdout);
        }
    }

    DeleteCriticalSection(&g_resp_lock);
    DeleteCriticalSection(&g_send_path_lock);
    DeleteCriticalSection(&g_pkt_lock);
    CloseHandle(g_resp_event);
    net_cleanup();
    return 0;
}