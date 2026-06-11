/* client.c  --  User / Receiver  (Anon-Sec-Net v2)
 *
 * Outbound packet payload (enc_K_R-SG-A):
 *   [flags(1)][payload_len(2)]
 *   [MNc_pubkey(65)][MNc_IP:port(6)]
 *   [return_header(162)]     <- enc_SK_R-MNc(MNb + enc_SK_R-MNb(MNa + enc_SK_R-MNa(Client)))
 *   [app_data(variable)]     <- TYPE_GET/PUT + key + content
 *
 * Return packet received from MNa (enc_K_R-SG-B):
 *   [return_header(162)]     <- shifted down as MNc/MNb/MNa peel
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
#include <windows.h>
#include <math.h>
#include <stdatomic.h>


/* ── Session state ──────────────────────────────────────────────────────── */

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

    /* Client response address (embedded in return header innermost layer) */
    uint8_t  client_addr[ADDR_BYTES];

    int ready;
} client_state_t;

static client_state_t g_state = {0};

/* ── Response synchronisation ───────────────────────────────────────────── */
static uint8_t          g_resp_buf[WIRE_PACKET_SIZE];
static volatile int     g_resp_ready = 0;
static CRITICAL_SECTION g_resp_lock;
static CRITICAL_SECTION g_send_path_lock;  /* guards g_state.send_path */
static HANDLE           g_resp_event;

static void log_msg(const char *m) { printf("[Client] %s\n", m); fflush(stdout); }
static void log_err(const char *m) { fprintf(stderr,"[Client] ERROR: %s\n",m); fflush(stderr); }

/* ── ECDHE with a single node ───────────────────────────────────────────── */
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

/* ── Key splitting from ECDH master ─────────────────────────────────────
 *
 * packet_sphinx_build() and packet_sphinx_peel() use header_enc_key,
 * header_mac_key, and blind_key DIRECTLY — no internal re-derivation.
 *
 * Three independent keys are produced by byte-rotation of the 32-byte
 * ECDH master — identical to mix_node.c::split_master_keys():
 *   header_enc_key = master
 *   header_mac_key = master rotated left 1 byte
 *   blind_key      = master rotated left 2 bytes
 *
 * Used for BOTH the sending path (stored in sphinx_path_t.hops[i] for
 * packet_sphinx_build) and the receiving path (stored in recv_hops[i]
 * for packet_build_return_header, which also uses keys directly).
 */
static void split_master_keys(const aes_key_t *master,
                              aes_key_t *henc,
                              aes_key_t *hmac_key,
                              aes_key_t *bkey) {
    *henc = *master;
    for (int b = 0; b < AES_KEY_LEN; b++) {
        hmac_key->key[b] = master->key[(b + 1) % AES_KEY_LEN];
        bkey->key[b]     = master->key[(b + 2) % AES_KEY_LEN];
    }
}

/* Populate hop_session_t for the SENDING path (MN1/MN2/MN3).
 * Stores all three split keys; packet_sphinx_build uses them directly. */
static void derive_hop_send(const aes_key_t *master, hop_session_t *hop,
                            const uint8_t hint[HINT_BYTES]) {
    aes_key_t henc = {0}, hmac = {0}, bkey = {0};
    split_master_keys(master, &henc, &hmac, &bkey);
    hop->header_enc_key = henc;
    hop->header_mac_key = hmac;
    hop->blind_key      = bkey;
    memcpy(hop->hint, hint, HINT_BYTES);
}

/* Populate hop_session_t for the RECEIVING path (MNc/MNb/MNa).
 * packet_build_return_header uses header_enc_key and header_mac_key
 * directly. mix_node.c stores the same split keys after ECDH. */
static void derive_hop_recv(const aes_key_t *master, hop_session_t *hop,
                            const uint8_t hint[HINT_BYTES]) {
    aes_key_t henc = {0}, hmac = {0}, bkey = {0};
    split_master_keys(master, &henc, &hmac, &bkey);
    hop->header_enc_key = henc;
    hop->header_mac_key = hmac;
    hop->blind_key      = bkey;   /* unused on return path but populated */
    memcpy(hop->hint, hint, HINT_BYTES);
}

/* ── Build IP:port addr bytes ───────────────────────────────────────────── */
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

/* ── Build both paths ───────────────────────────────────────────────────── */
static int build_paths(void) {
    MEASURE_SESSION_BEGIN();             /* P2: start session timer */
    log_msg("building sending path A (MN1->MN2->MN3->SG)...");

    uint16_t send_ports[N_PATH_HOPS] = { PORT_MIX_1, PORT_MIX_2, PORT_MIX_3 };

    /* Build sending path sphinx_path_t */
    for (int i = 0; i < N_PATH_HOPS; i++) {
        aes_key_t master = {0};
        uint8_t   hint[HINT_BYTES]      = {0};
        uint8_t   node_pub[EC_PUBKEY_LEN] = {0};

        if (ecdhe_with_node(LOCALHOST, send_ports[i], SESSION_ROLE_A,
                            &master, hint, node_pub) != 0) {
            char err[64];
            snprintf(err, sizeof(err), "ECDHE failed MN%d (port %u)",
                     i+1, send_ports[i]);
            log_err(err); return -1;
        }
        derive_hop_send(&master, &g_state.send_path.hops[i], hint);
        g_state.send_path.hop_ports[i] = send_ports[i];

        char logbuf[64];
        snprintf(logbuf, sizeof(logbuf),
                 "  sending hop %d ready (port %u)", i+1, send_ports[i]);
        log_msg(logbuf);
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

    for (int i = 0; i < N_PATH_HOPS; i++) {
        aes_key_t master = {0};
        uint8_t   hint[HINT_BYTES]      = {0};
        uint8_t   node_pub[EC_PUBKEY_LEN] = {0};

        if (ecdhe_with_node(LOCALHOST, recv_ports[i], SESSION_ROLE_B,
                            &master, hint, node_pub) != 0) {
            char err[64];
            snprintf(err, sizeof(err), "ECDHE failed recv hop %d (port %u)",
                     i, recv_ports[i]);
            log_err(err); return -1;
        }
        derive_hop_recv(&master, &g_state.recv_hops[i], hint);

        /* Store MNc pubkey and addr for embedding in outbound payload */
        if (i == 0) {
            memcpy(g_state.mnc_pubkey, node_pub, EC_PUBKEY_LEN);
            make_addr_bytes(LOCALHOST, PORT_MIX_C, g_state.mnc_addr);
        }

        char logbuf[64];
        snprintf(logbuf, sizeof(logbuf),
                 "  receiving hop %d ready (port %u)", i, recv_ports[i]);
        log_msg(logbuf);
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

    /* Build Client address bytes (127.0.0.1:CLIENT_RESPONSE_PORT) */
    make_addr_bytes(LOCALHOST, CLIENT_RESPONSE_PORT, g_state.client_addr);

    /* Build return header:
     *   addrs[0] = MNb addr  (MNc learns this after peeling)
     *   addrs[1] = MNa addr  (MNb learns this)
     *   addrs[2] = Client addr (MNa learns this -- final delivery)
     *   enc keys[0] = SK_R-MNc, [1] = SK_R-MNb, [2] = SK_R-MNa
     */
    uint8_t addrs[N_PATH_HOPS][ADDR_BYTES];
    make_addr_bytes(LOCALHOST, PORT_MIX_B, addrs[0]);
    make_addr_bytes(LOCALHOST, PORT_MIX_A, addrs[1]);
    memcpy(addrs[2], g_state.client_addr, ADDR_BYTES);

    aes_key_t enc_keys[N_PATH_HOPS], mac_keys[N_PATH_HOPS];
    uint8_t   hints[N_PATH_HOPS][HINT_BYTES];
    for (int i = 0; i < N_PATH_HOPS; i++) {
        enc_keys[i] = g_state.recv_hops[i].header_enc_key;
        mac_keys[i] = g_state.recv_hops[i].header_mac_key;
        memcpy(hints[i], g_state.recv_hops[i].hint, HINT_BYTES);
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


/* ── Response listener thread ───────────────────────────────────────────── */
static DWORD WINAPI response_listener(LPVOID arg) {
    (void)arg;
    SOCKET srv = net_listen(CLIENT_RESPONSE_PORT);
    if (srv == INVALID_SOCKET) { log_err("response listener bind failed"); return 1; }

    char logbuf[64];
    snprintf(logbuf, sizeof(logbuf),
             "response listener on port %u", CLIENT_RESPONSE_PORT);
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
            /* Real responses are small -- filter obvious random cover packets */
            if (enc_len >= GCM_OVERHEAD && enc_len <= 512) {
                uint8_t tmp[RETURN_PAYLOAD_SIZE];
                int n = crypto_aes_decrypt(&g_state.k_r_sg_b,
                                           wire + RETURN_HEADER_SIZE + 2,
                                           enc_len, tmp, sizeof(tmp));
                if (n > 0) {
                    /* Real response -- signal */
                    EnterCriticalSection(&g_resp_lock);
                    memcpy(g_resp_buf, wire, WIRE_PACKET_SIZE);
                    g_resp_ready = 1;
                    SetEvent(g_resp_event);
                    LeaveCriticalSection(&g_resp_lock);
                }
                /* else: cover packet -- silently discard */
            }
        }
        net_close(conn);
    }
    net_close(srv);
    return 0;
}


/* ── Cover traffic (Phase 8) ────────────────────────────────────────────── */

/* Poisson inter-packet interval in ms (rate = DUMMY_INTERVAL_MS mean)     */
static DWORD poisson_interval_ms(void) {
    /* Inverse CDF of Exponential: -mean * ln(U), U ~ Uniform(0,1)        */
    double u = (rand() + 1.0) / (RAND_MAX + 2.0);  /* avoid 0 and 1      */
    double interval = -DUMMY_INTERVAL_MS * log(u);
    if (interval < 10.0)  interval = 10.0;
    if (interval > 1000.0) interval = 1000.0;
    return (DWORD)interval;
}

/* ── Step 8.6: Probabilistic slot replacement ────────────────────────────
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
 * Depth 8 absorbs Sphinx build jitter (~2-5ms each) at the Poisson clock     */
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

/* ── crypto_thread: keep buffer stocked ──────────────────────────────────────── */
static DWORD WINAPI crypto_thread(LPVOID arg) {
    (void)arg;
    while (1) {
        if (!g_state.ready) { Sleep(5); continue; }

        EnterCriticalSection(&g_pkt_lock);
        int real_free  = pq_free(&g_real_q);
        int cover_free = pq_free(&g_cover_q);
        LeaveCriticalSection(&g_pkt_lock);

        if (real_free == 0 && cover_free == 0) { Sleep(1); continue; }

        /* Build one real packet */
        if (real_free > 0) {
            const char *key = "bench";
            size_t klen = strlen(key);
            uint8_t payload[MAX_INNER_PAYLOAD];
            memset(payload, 0, sizeof(payload));
            size_t poff = 0;
            memcpy(payload+poff, g_state.mnc_pubkey,  EC_PUBKEY_LEN);      poff+=EC_PUBKEY_LEN;
            memcpy(payload+poff, g_state.mnc_addr,    ADDR_BYTES);         poff+=ADDR_BYTES;
            memcpy(payload+poff, &g_state.return_hdr, RETURN_HEADER_SIZE); poff+=RETURN_HEADER_SIZE;
            payload[poff++] = TYPE_GET;
            payload[poff++] = (uint8_t)klen;
            memcpy(payload+poff, key, klen); poff+=klen;
            if (poff <= MAX_INNER_PAYLOAD) {
                wire_packet_t pkt = {0};
                EnterCriticalSection(&g_send_path_lock);
                int ok = (packet_sphinx_build(&g_state.send_path, payload, (uint16_t)poff,
                                              PKT_REAL|PKT_DEST_SERVICE, 0, &pkt) == 0);
                LeaveCriticalSection(&g_send_path_lock);
                if (ok) {
                    EnterCriticalSection(&g_pkt_lock);
                    pq_push(&g_real_q, &pkt);
                    LeaveCriticalSection(&g_pkt_lock);
                }
            }
        }

        /* Build one cover packet */
        if (cover_free > 0) {
            wire_packet_t pkt = {0};
            EnterCriticalSection(&g_send_path_lock);
            int ok = (packet_sphinx_dummy(&g_state.send_path, &pkt) == 0);
            LeaveCriticalSection(&g_send_path_lock);
            if (ok) {
                EnterCriticalSection(&g_pkt_lock);
                pq_push(&g_cover_q, &pkt);
                LeaveCriticalSection(&g_pkt_lock);
            }
        }
    }
    return 0;
}

/* ── outbound_cover_thread: Poisson clock, probabilistic real/cover decision ── */
static volatile int g_slots_total = 0;
static volatile int g_slots_real  = 0;
static volatile int g_slots_cover = 0;
static volatile int g_slots_fallback = 0;

static DWORD WINAPI outbound_cover_thread(LPVOID arg) {
    (void)arg;
    srand((unsigned)GetTickCount());

    while (1) {
        Sleep(poisson_interval_ms());
        if (!g_state.ready) continue;

        g_slots_total++;

        double u = (rand() + 1.0) / (RAND_MAX + 2.0);
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

/* ── Send GET request ───────────────────────────────────────────────────── */
static int send_get(const char *key) {
    if (!g_state.ready) { log_err("paths not ready"); return -1; }

    size_t klen = strlen(key);
    if (klen > 63) { log_err("key too long"); return -1; }

    /* Build inner payload:
     * [flags(1)][payload_len(2)][MNc_pubkey(65)][MNc_addr(6)]
     * [return_header(162)][TYPE_GET(1)][klen(1)][key]           */
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

/* ── Wait for and decrypt response ─────────────────────────────────────── */
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
     * [return_header(162)][enc_K_R-SG-B(response)]
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

    if ((size_t)n > MAX_INNER_PAYLOAD) n = MAX_INNER_PAYLOAD;
    memcpy(out, plain, (size_t)n);
    *out_len = (uint16_t)n;
    return 0;
}


/* ── Send session setup packet to SG ───────────────────────────────────── */
static int send_setup(void) {
    /* Compute binding tag: HMAC(K_R-SG-A XOR K_R-SG-B, "binding") */
    uint8_t xor_key[AES_KEY_LEN];
    for (int i = 0; i < AES_KEY_LEN; i++)
        xor_key[i] = g_state.k_r_sg_a.key[i] ^ g_state.k_r_sg_b.key[i];

    uint8_t binding_tag[MAC_BYTES];
    packet_hmac(xor_key, AES_KEY_LEN,
                (uint8_t *)LABEL_BINDING, strlen(LABEL_BINDING),
                binding_tag);

    /* Build setup payload */
    uint8_t payload[MAX_INNER_PAYLOAD];
    memset(payload, 0, sizeof(payload));
    size_t off = 0;

    payload[off++] = TYPE_SETUP;

    /* SK_R-MN1, MN2, MN3 (sending path blind keys) */
    for (int i = 0; i < N_PATH_HOPS; i++) {
        memcpy(payload + off, g_state.send_path.hops[i].blind_key.key, AES_KEY_LEN);
        off += AES_KEY_LEN;
    }

    /* SK_R-MNa, MNb, MNc (receiving path blind keys) -- [0]=MNc,[1]=MNb,[2]=MNa */
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

/* ── Interactive loop ───────────────────────────────────────────────────── */
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

/* ── main ───────────────────────────────────────────────────────────────── */
int main(void) {
    SetConsoleOutputCP(65001);
    InitializeCriticalSection(&g_resp_lock);
    InitializeCriticalSection(&g_send_path_lock);
    InitializeCriticalSection(&g_pkt_lock);
    g_resp_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!g_resp_event) return 1;
    measure_init(MEASURE_P2 | MEASURE_P3);  /* P2: session timer | P3: link bytes */

    if (net_init() != 0) return 1;
    CreateDirectoryA(PUBKEY_DIR, NULL);
    log_msg("Anon-Sec-Net v2 client starting...");

    if (build_paths() != 0) {
        log_err("path build failed — ensure all mix nodes and SG are running");
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

    /* Crypto workers: keep g_real_q / g_cover_q stocked */
    for (int i = 0; i < 4; i++) {
        HANDLE kp = CreateThread(NULL, 0, crypto_thread, NULL, 0, NULL);
        if (kp) CloseHandle(kp);
    }

    Sleep(200);

    /* ── Main thread: stdin command loop ──────────────────────────────────
     * Single reader (no race with any other thread).  This is the
     * benchmark client -- there is no interactive GET prompt.
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
        }
        if (strcmp(line, "quit") == 0) {
    measure_flush();
    Sleep(50);   // ensure file write completes
    break;
}
        
        else {
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