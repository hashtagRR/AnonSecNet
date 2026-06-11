/* mix_node.c  --  Generic Mix Node (Anon-Sec-Net v2)
 *
 * One binary, twelve instances:
 *   Client sending path:    9004(MN1) 9005(MN2) 9006(MN3)
 *   Client receiving path:  9007(MNa) 9008(MNb) 9009(MNc)
 *   Sender sending path:    9030(MNi) 9031(MNii) 9032(MNiii)
 *   Sender receiving path:  9033(MNx) 9034(MNy) 9035(MNz)
 *
 * Modes:
 *   MODE_EXTEND (0x01) -- ECDHE handshake during path construction
 *   MODE_DATA   (0x02) -- Sphinx forward: peel header, blind payload
 *   MODE_RETURN (0x03) -- Return path: peel return header, forward
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
#include <windows.h>

/* ── Session store ────────────────────────────────────────────────────── */
#define MAX_SESSIONS 1024

typedef struct {
    uint8_t   hint[HINT_BYTES];
    aes_key_t header_enc_key;
    aes_key_t header_mac_key;
    uint8_t   role;
    /* Learned on first return delivery -- used for inbound cover           */
    uint8_t   dest_ip[4];
    uint16_t  dest_port;
    int       dest_known;
    int       in_use;
} session_entry_t;

static session_entry_t  g_sessions[MAX_SESSIONS];
static CRITICAL_SECTION g_session_lock;

static session_entry_t *session_find(const uint8_t hint[HINT_BYTES]) {
    EnterCriticalSection(&g_session_lock);
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i].in_use &&
            crypto_memcmp(g_sessions[i].hint, hint, HINT_BYTES) == 0) {
            LeaveCriticalSection(&g_session_lock);
            return &g_sessions[i];
        }
    }
    LeaveCriticalSection(&g_session_lock);
    return NULL;
}

static session_entry_t *session_alloc(void) {
    EnterCriticalSection(&g_session_lock);
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_sessions[i].in_use) {
            g_sessions[i].in_use = 1;
            LeaveCriticalSection(&g_session_lock);
            return &g_sessions[i];
        }
    }
    LeaveCriticalSection(&g_session_lock);
    return NULL;
}

/* ── Node keypair ─────────────────────────────────────────────────────── */
static ecdh_keypair_t g_node_kp = {0};

/* ── Per-connection context ───────────────────────────────────────────── */
typedef struct {
    SOCKET   client_sock;
    uint16_t my_port;
} conn_ctx_t;

/* ── Logging ──────────────────────────────────────────────────────────── */
static void log_msg(uint16_t port, const char *msg) {
    printf("[MN:%u] %s\n", port, msg); fflush(stdout);
}
static void log_err(uint16_t port, const char *msg) {
    fprintf(stderr, "[MN:%u] ERROR: %s\n", port, msg); fflush(stderr);
}

/* ── Return path next-hop routing ─────────────────────────────────────── */
typedef struct { const char *addr; uint16_t port; } next_hop_t;

/* Returns next hop for return path packets.
 * addr=NULL means this is the final node -- use address from peeled header. */
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

/* ── Key splitting from ECDH master ──────────────────────────────────────
 *
 * packet_sphinx_build() and packet_sphinx_peel() use header_enc_key,
 * header_mac_key, and blind_key DIRECTLY — no internal re-derivation.
 *
 * Three keys from the 32-byte ECDH master via byte-rotation:
 *   header_enc_key = master
 *   header_mac_key = master rotated left 1 byte
 *   blind_key      = master rotated left 2 bytes
 *
 * Must match client_instrumented.c::split_master_keys() exactly.
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

/* ── MODE_EXTEND handler ──────────────────────────────────────────────── */
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

    /* Store session keyed by hint (x-coord of client pubkey) */
    session_entry_t *sess = session_alloc();
    if (!sess) { log_err(my_port, "extend: session store full"); return; }
    memcpy(sess->hint, client_pub + 1, HINT_BYTES);
    sess->header_enc_key = henc;
    sess->header_mac_key = hmk;
    sess->role           = role;

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
        if (net_recv_all(next_sock, target_pub, EC_PUBKEY_LEN) == 0)
            net_send_all(sock, target_pub, EC_PUBKEY_LEN);
        net_close(next_sock);
    }
}

/* ── MODE_DATA handler ────────────────────────────────────────────────── */
static void handle_data(SOCKET sock, uint16_t my_port) {
    wire_packet_t pkt = {0};
    if (net_recv_all(sock, pkt.data, WIRE_PACKET_SIZE) != 0) {
        log_err(my_port, "data: read packet"); return;
    }

    /* Extract hint from outermost header block */
    const uint8_t *hint = pkt.data + ADDR_BYTES + BLIND_KEY_BYTES + FLAG_BYTES + MAC_BYTES;

    session_entry_t *sess = session_find(hint);
    if (!sess) {
        log_err(my_port, "data: no session for hint -- drop"); return;
    }

    hop_info_t    hop_info = {0};
    wire_packet_t out_pkt  = {0};

    uint8_t cover_flag = 0;
    MEASURE_HOP_BEGIN();                                  /* P1 start */
    int peel_rc = packet_sphinx_peel(&pkt,
                           &sess->header_enc_key,
                           &sess->header_mac_key,
                           hint, &hop_info, &out_pkt, &cover_flag);
    MEASURE_HOP_END();                                    /* P1 end */
    if (peel_rc != 0) {
        log_err(my_port, "data: peel failed -- drop"); return;
    }

    /* P4: count every successfully peeled packet at the entry node (MN1/MNi)
     * This includes cover packets -- measures total throughput at network entry */
    if (my_port == PORT_MIX_1 || my_port == PORT_MIX_I) {
        measure_sg_goodput((LONGLONG)WIRE_PACKET_SIZE);
    }

    /* Step 8.3: MN1/MNi drops cover packets without forwarding */
    if (cover_flag & COVER_FLAG) {
        log_msg(my_port, "data: cover packet -- dropped");
        return;
    }

    char logbuf[80];
    snprintf(logbuf, sizeof(logbuf),
             "data: peeled OK -> port %u", hop_info.next_port);
    log_msg(my_port, logbuf);

    SOCKET next_sock = net_connect(LOCALHOST, hop_info.next_port);
    if (next_sock == INVALID_SOCKET) {
        log_err(my_port, "data: connect next hop"); return;
    }

    uint8_t mode = MODE_DATA;
    net_send_all(next_sock, &mode,        1);
    net_send_all(next_sock, out_pkt.data, WIRE_PACKET_SIZE);
    net_close(next_sock);
}

/* ── MODE_RETURN handler ──────────────────────────────────────────────── */
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
    session_entry_t *sess = session_find(hint);
    if (!sess) {
        log_err(my_port, "return: no session for hint -- drop"); return;
    }

    /* Peel our return header block */
    return_next_t   next_addr = {0};
    return_header_t shifted   = {0};
    if (packet_peel_return_header(&rhdr,
                                  &sess->header_enc_key,
                                  &sess->header_mac_key,
                                  &next_addr, &shifted) != 0) {
        log_err(my_port, "return: MAC failed -- drop"); return;
    }

    /* Build output: [shifted_header][payload unchanged] */
    uint8_t out_wire[WIRE_PACKET_SIZE];
    memset(out_wire, 0, sizeof(out_wire));
    memcpy(out_wire, &shifted, RETURN_HEADER_SIZE);
    memcpy(out_wire + RETURN_HEADER_SIZE,
           wire + RETURN_HEADER_SIZE,
           WIRE_PACKET_SIZE - RETURN_HEADER_SIZE);

    next_hop_t route = return_next_hop(my_port);

    char logbuf[80];
    if (route.addr != NULL) {
        /* Intermediate node -- forward to next mix node */
        snprintf(logbuf, sizeof(logbuf),
                 "return: forwarding -> port %u", route.port);
        log_msg(my_port, logbuf);

        SOCKET next_sock = net_connect(route.addr, route.port);
        if (next_sock == INVALID_SOCKET) {
            log_err(my_port, "return: connect next hop"); return;
        }
        uint8_t mode = MODE_RETURN;
        net_send_all(next_sock, &mode,    1);
        net_send_all(next_sock, out_wire, WIRE_PACKET_SIZE);
        net_close(next_sock);
    } else {
        /* Final node (MNa or MNx) -- deliver directly to Client/Sender */
        char dest_ip[16];
        snprintf(dest_ip, sizeof(dest_ip), "%u.%u.%u.%u",
                 next_addr.next_ip[0], next_addr.next_ip[1],
                 next_addr.next_ip[2], next_addr.next_ip[3]);

        snprintf(logbuf, sizeof(logbuf),
                 "return: delivering to %s:%u", dest_ip, next_addr.next_port);
        log_msg(my_port, logbuf);

        /* Store dest for inbound cover traffic */
        if (!sess->dest_known) {
            memcpy(sess->dest_ip, next_addr.next_ip, 4);
            sess->dest_port  = next_addr.next_port;
            sess->dest_known = 1;
        }

        SOCKET dest = net_connect(dest_ip, next_addr.next_port);
        if (dest == INVALID_SOCKET) {
            log_err(my_port, "return: connect destination"); return;
        }
        net_send_all(dest, out_wire, WIRE_PACKET_SIZE);
        net_close(dest);
    }
}


/* ── Inbound cover traffic thread (MNa and MNx only) ───────────────────── */
/* Sends dummy packets to Client/Sender to keep edge link bidirectional.    */

static uint16_t g_my_port_global = 0;

static DWORD WINAPI inbound_cover_thread(LPVOID arg) {
    (void)arg;
    srand((unsigned)(GetTickCount() + g_my_port_global));

    /* Derive destination from our port:
     * MNa (PORT_MIX_A=9007) -> Client response port (9020)
     * MNx (PORT_MIX_X=9033) -> Sender response port (9016)              */
    uint16_t dest_port   = (g_my_port_global == PORT_MIX_A)
                           ? CLIENT_RESPONSE_PORT
                           : SENDER_RESPONSE_PORT;

    while (1) {
        double u = (rand() + 1.0) / (RAND_MAX + 2.0);
        double iv = -DUMMY_INTERVAL_MS * log(u);
        if (iv < 10.0) iv = 10.0;
        if (iv > 1000.0) iv = 1000.0;
        Sleep((DWORD)iv);

        uint8_t cover_wire[WIRE_PACKET_SIZE];
        if (RAND_bytes(cover_wire, WIRE_PACKET_SIZE) != 1) continue;

        SOCKET s = net_connect(LOCALHOST, dest_port);
        if (s == INVALID_SOCKET) continue;
        char _cl[48];
        snprintf(_cl,sizeof(_cl),"inbound cover: sent to port %u",dest_port);
        log_msg(g_my_port_global, _cl);
        net_send_all(s, cover_wire, WIRE_PACKET_SIZE);
        net_close(s);
    }
    return 0;
}

/* ── Connection handler ───────────────────────────────────────────────── */
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
        default: log_err(port, "unknown mode -- drop"); break;
    }

done:
    net_close(sock);
    return 0;
}

/* ── main ─────────────────────────────────────────────────────────────── */
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
    measure_init(MEASURE_P1 | MEASURE_P4); /* P1: hop timer | P4: entry throughput */

    if (net_init() != 0) return 1;

    if (crypto_ecdh_keygen(&g_node_kp) != 0) {
        fprintf(stderr, "[MN:%u] keygen failed\n", port);
        net_cleanup(); return 1;
    }

    CreateDirectoryA(PUBKEY_DIR, NULL);
    char pubkey_path[256];
    snprintf(pubkey_path, sizeof(pubkey_path), "%s\\%u.pub", PUBKEY_DIR, port);
    if (crypto_pubkey_save(&g_node_kp, pubkey_path) != 0) {
        fprintf(stderr, "[MN:%u] save pubkey failed\n", port);
        net_cleanup(); return 1;
    }
    printf("[MN:%u] pubkey written to %s\n", port, pubkey_path);

    SOCKET server_sock = net_listen(port);
    if (server_sock == INVALID_SOCKET) { net_cleanup(); return 1; }

    printf("[MN:%u] ready\n", port); fflush(stdout);

    /* Start inbound cover thread on MNa and MNx (Receiver-facing nodes) */
    if (port == PORT_MIX_A || port == PORT_MIX_X) {
        g_my_port_global = port;
        HANDLE ct = CreateThread(NULL, 0, inbound_cover_thread, NULL, 0, NULL);
        if (ct) CloseHandle(ct);
        printf("[MN:%u] inbound cover thread started\n", port); fflush(stdout);
    }

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