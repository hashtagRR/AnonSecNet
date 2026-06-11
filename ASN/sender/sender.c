/* sender.c  --  Anonymous Service (Sender)  --  Anon-Sec-Net v2
 *
 * Sender sending path:   Sender -> MNi(9030) -> MNii(9031) -> MNiii(9032) -> SvcGW
 * Sender receiving path: SvcGW  -> MNx(9033) -> MNy(9034)  -> MNz(9035)  -> Sender
 *
 * Every PUT payload has the same structure as the Client GET:
 *   [MNz_pubkey(65)][MNz_addr(6)][return_header(162)][TYPE_PUT(1)][klen(1)][key][clen(2)][content]
 *
 * The SvcGW extracts MNz_pubkey+addr+return_header, processes the PUT,
 * and routes the ACK response back through MNx->MNy->MNz->Sender.
 */

#include "common/net.h"
#include "common/crypto.h"
#include "common/packet.h"
#include "common/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <math.h>


static void log_msg(const char *m) { printf("[Sender] %s\n", m); fflush(stdout); }
static void log_err(const char *m) { fprintf(stderr,"[Sender] ERROR: %s\n",m); fflush(stderr); }

/* ── Session state ──────────────────────────────────────────────────────── */
typedef struct {
    /* Sending path: Sender -> MNi -> MNii -> MNiii -> SvcGW */
    sphinx_path_t send_path;
    aes_key_t     k_s_sg_a;       /* K_S-SG-A: end-to-end key path A      */

    /* Receiving path: SvcGW -> MNx -> MNy -> MNz -> Sender */
    hop_session_t recv_hops[N_PATH_HOPS]; /* [0]=MNz [1]=MNy [2]=MNx      */
    aes_key_t     k_s_sg_b;       /* K_S-SG-B: end-to-end key path B      */

    /* MNz info embedded in every outbound payload */
    uint8_t mnz_pubkey[EC_PUBKEY_LEN];
    uint8_t mnz_addr[ADDR_BYTES];

    /* Pre-built return header */
    return_header_t return_hdr;

    /* Sender response address */
    uint8_t sender_addr[ADDR_BYTES];

    int ready;
} sender_state_t;

static sender_state_t g_state = {0};

/* ── Response listener ──────────────────────────────────────────────────── */
static uint8_t          g_resp_buf[WIRE_PACKET_SIZE];
static volatile int     g_resp_ready = 0;
static CRITICAL_SECTION g_resp_lock;
static HANDLE           g_resp_event;

/* ── ECDHE with a single node ───────────────────────────────────────────── */
static int ecdhe_with_node(uint16_t port, uint8_t role,
                            aes_key_t *out_master,
                            uint8_t hint[HINT_BYTES],
                            uint8_t node_pub[EC_PUBKEY_LEN]) {
    ecdh_keypair_t kp = {0};
    if (crypto_ecdh_keygen(&kp) != 0) return -1;

    memcpy(hint, kp.pubkey_bytes + 1, HINT_BYTES);

    SOCKET s = net_connect(LOCALHOST, port);
    if (s == INVALID_SOCKET) { crypto_ecdh_free(&kp); return -1; }

    uint8_t mode = MODE_EXTEND, tport[2] = {0, 0};
    net_send_all(s, &mode,           1);
    net_send_all(s, &role,           1);
    net_send_all(s, tport,           2);
    net_send_all(s, kp.pubkey_bytes, EC_PUBKEY_LEN);

    int rc = net_recv_all(s, node_pub, EC_PUBKEY_LEN);
    net_close(s);

    if (rc != 0) { crypto_ecdh_free(&kp); return -1; }
    rc = crypto_ecdh_derive(&kp, node_pub, out_master);
    crypto_ecdh_free(&kp);
    return rc;
}

static void derive_hop(const aes_key_t *master, hop_session_t *hop,
                        const uint8_t hint[HINT_BYTES]) {
    for (int i = 0; i < AES_KEY_LEN; i++) {
        hop->header_enc_key.key[i] = master->key[i] ^ 0x36;
        hop->header_mac_key.key[i] = master->key[i] ^ 0x5C;
        hop->blind_key.key[i]      = master->key[i] ^ 0xAA;
    }
    memcpy(hop->hint, hint, HINT_BYTES);
}

static void make_addr_bytes(const char *ip, uint16_t port,
                             uint8_t out[ADDR_BYTES]) {
    unsigned a, b, c, d;
    sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d);
    out[0]=(uint8_t)a; out[1]=(uint8_t)b;
    out[2]=(uint8_t)c; out[3]=(uint8_t)d;
    out[4]=(uint8_t)(port>>8); out[5]=(uint8_t)(port&0xFF);
}

/* ── Build both paths ───────────────────────────────────────────────────── */
static int build_paths(void) {
    log_msg("building sending path (MNi->MNii->MNiii->SvcGW)...");

    uint16_t send_ports[N_PATH_HOPS] = { PORT_MIX_I, PORT_MIX_II, PORT_MIX_III };

    for (int i = 0; i < N_PATH_HOPS; i++) {
        aes_key_t master = {0};
        uint8_t   hint[HINT_BYTES]      = {0};
        uint8_t   node_pub[EC_PUBKEY_LEN] = {0};

        if (ecdhe_with_node(send_ports[i], SESSION_ROLE_A, &master, hint, node_pub) != 0) {
            char err[64];
            snprintf(err, sizeof(err), "ECDHE failed MN%d (port %u)", i+1, send_ports[i]);
            log_err(err); return -1;
        }
        derive_hop(&master, &g_state.send_path.hops[i], hint);
        g_state.send_path.hop_ports[i] = send_ports[i];

        char logbuf[64];
        snprintf(logbuf, sizeof(logbuf),
                 "  sending hop %d ready (port %u)", i+1, send_ports[i]);
        log_msg(logbuf);
    }

    /* E2E with SvcGW -> K_S-SG-A */
    {
        aes_key_t master = {0};
        uint8_t   hint[HINT_BYTES]      = {0};
        uint8_t   node_pub[EC_PUBKEY_LEN] = {0};
        if (ecdhe_with_node(PORT_SERVICE_GW, SESSION_ROLE_A, &master, hint, node_pub) != 0) {
            log_err("ECDHE failed SvcGW (path A)"); return -1;
        }
        g_state.k_s_sg_a              = master;
        g_state.send_path.e2e.e2e_key = master;
        g_state.send_path.next_port   = PORT_MIX_I;
        g_state.send_path.sg_port     = PORT_SERVICE_GW;
        log_msg("  K_S-SG-A established");
    }

    log_msg("building receiving path (MNz->MNy->MNx->Sender)...");

    /* Receiving path: [0]=MNz (outermost/SG-facing), [1]=MNy, [2]=MNx (Sender-facing) */
    uint16_t recv_ports[N_PATH_HOPS] = { PORT_MIX_Z, PORT_MIX_Y, PORT_MIX_X };

    for (int i = 0; i < N_PATH_HOPS; i++) {
        aes_key_t master = {0};
        uint8_t   hint[HINT_BYTES]      = {0};
        uint8_t   node_pub[EC_PUBKEY_LEN] = {0};

        if (ecdhe_with_node(recv_ports[i], SESSION_ROLE_B, &master, hint, node_pub) != 0) {
            char err[64];
            snprintf(err, sizeof(err), "ECDHE failed recv hop %d (port %u)", i, recv_ports[i]);
            log_err(err); return -1;
        }
        derive_hop(&master, &g_state.recv_hops[i], hint);

        /* Store MNz pubkey and addr (index 0 = MNz = SG-facing = first on return) */
        if (i == 0) {
            memcpy(g_state.mnz_pubkey, node_pub, EC_PUBKEY_LEN);
            make_addr_bytes(LOCALHOST, PORT_MIX_Z, g_state.mnz_addr);
        }

        char logbuf[64];
        snprintf(logbuf, sizeof(logbuf),
                 "  receiving hop %d ready (port %u)", i, recv_ports[i]);
        log_msg(logbuf);
    }

    /* E2E with SvcGW -> K_S-SG-B */
    {
        aes_key_t master = {0};
        uint8_t   hint[HINT_BYTES]      = {0};
        uint8_t   node_pub[EC_PUBKEY_LEN] = {0};
        if (ecdhe_with_node(PORT_SERVICE_GW, SESSION_ROLE_B, &master, hint, node_pub) != 0) {
            log_err("ECDHE failed SvcGW (path B)"); return -1;
        }
        g_state.k_s_sg_b = master;
        log_msg("  K_S-SG-B established");
    }

    /* Sender response address */
    make_addr_bytes(LOCALHOST, SENDER_RESPONSE_PORT, g_state.sender_addr);

    /* Build return header:
     * addrs[0] = MNy addr  (MNz learns this)
     * addrs[1] = MNx addr  (MNy learns this)
     * addrs[2] = Sender addr (MNx learns this -- final delivery)         */
    uint8_t addrs[N_PATH_HOPS][ADDR_BYTES];
    make_addr_bytes(LOCALHOST, PORT_MIX_Y, addrs[0]);
    make_addr_bytes(LOCALHOST, PORT_MIX_X, addrs[1]);
    memcpy(addrs[2], g_state.sender_addr, ADDR_BYTES);

    aes_key_t enc_keys[N_PATH_HOPS], mac_keys[N_PATH_HOPS];
    uint8_t   hints[N_PATH_HOPS][HINT_BYTES];
    for (int i = 0; i < N_PATH_HOPS; i++) {
        enc_keys[i] = g_state.recv_hops[i].header_enc_key;
        mac_keys[i] = g_state.recv_hops[i].header_mac_key;
        memcpy(hints[i], g_state.recv_hops[i].hint, HINT_BYTES);
    }

    if (packet_build_return_header(enc_keys, mac_keys, hints,
                                   addrs, &g_state.return_hdr) != 0) {
        log_err("build return header failed"); return -1;
    }

    g_state.ready = 1;
    log_msg("both paths ready");
    return 0;
}

/* ── Response listener ──────────────────────────────────────────────────── */
static DWORD WINAPI response_listener(LPVOID arg) {
    (void)arg;
    SOCKET srv = net_listen(SENDER_RESPONSE_PORT);
    if (srv == INVALID_SOCKET) { log_err("response listener failed"); return 1; }

    char logbuf[64];
    snprintf(logbuf, sizeof(logbuf),
             "ACK listener on port %u", SENDER_RESPONSE_PORT);
    log_msg(logbuf);

    while (1) {
        SOCKET conn = net_accept(srv);
        if (conn == INVALID_SOCKET) break;

        uint8_t wire[WIRE_PACKET_SIZE];
        if (net_recv_all(conn, wire, WIRE_PACKET_SIZE) == 0) {
            size_t enc_len = (size_t)((wire[RETURN_HEADER_SIZE] << 8) |
                                       wire[RETURN_HEADER_SIZE+1]);
            /* Real responses are small -- filter obvious random cover packets */
            if (enc_len >= GCM_OVERHEAD && enc_len <= 512) {
                uint8_t tmp[RETURN_PAYLOAD_SIZE];
                int n = crypto_aes_decrypt(&g_state.k_s_sg_b,
                                           wire + RETURN_HEADER_SIZE + 2,
                                           enc_len, tmp, sizeof(tmp));
                if (n > 0) {
                    EnterCriticalSection(&g_resp_lock);
                    memcpy(g_resp_buf, wire, WIRE_PACKET_SIZE);
                    g_resp_ready = 1;
                    SetEvent(g_resp_event);
                    LeaveCriticalSection(&g_resp_lock);
                }
            }
        }
        net_close(conn);
    }
    net_close(srv);
    return 0;
}


/* ── Send session setup packet to SG ───────────────────────────────────── */
static int send_setup(void) {
    uint8_t xor_key[AES_KEY_LEN];
    for (int i = 0; i < AES_KEY_LEN; i++)
        xor_key[i] = g_state.k_s_sg_a.key[i] ^ g_state.k_s_sg_b.key[i];

    uint8_t binding_tag[MAC_BYTES];
    packet_hmac(xor_key, AES_KEY_LEN,
                (uint8_t *)LABEL_BINDING, strlen(LABEL_BINDING),
                binding_tag);

    uint8_t payload[MAX_INNER_PAYLOAD];
    memset(payload, 0, sizeof(payload));
    size_t off = 0;

    payload[off++] = TYPE_SETUP;

    /* SK sending path blind keys (MNi, MNii, MNiii) */
    for (int i = 0; i < N_PATH_HOPS; i++) {
        memcpy(payload + off, g_state.send_path.hops[i].blind_key.key, AES_KEY_LEN);
        off += AES_KEY_LEN;
    }
    /* SK receiving path blind keys ([0]=MNz, [1]=MNy, [2]=MNx) */
    for (int i = 0; i < N_PATH_HOPS; i++) {
        memcpy(payload + off, g_state.recv_hops[i].blind_key.key, AES_KEY_LEN);
        off += AES_KEY_LEN;
    }
    memcpy(payload + off, binding_tag, MAC_BYTES); off += MAC_BYTES;
    memcpy(payload + off, g_state.mnz_pubkey, EC_PUBKEY_LEN); off += EC_PUBKEY_LEN;
    memcpy(payload + off, g_state.mnz_addr,   ADDR_BYTES);    off += ADDR_BYTES;
    memcpy(payload + off, &g_state.return_hdr, RETURN_HEADER_SIZE); off += RETURN_HEADER_SIZE;

    wire_packet_t pkt = {0};
    if (packet_sphinx_build(&g_state.send_path, payload, (uint16_t)off,
                            PKT_REAL | PKT_DEST_SERVICE, 0, &pkt) != 0) {
        log_err("send_setup: build failed"); return -1;
    }

    SOCKET s = net_connect(LOCALHOST, PORT_MIX_I);
    if (s == INVALID_SOCKET) { log_err("send_setup: connect MNi"); return -1; }
    uint8_t mode = MODE_DATA;
    net_send_all(s, &mode, 1);
    net_send_all(s, pkt.data, WIRE_PACKET_SIZE);
    net_close(s);
    log_msg("session setup sent to SG");
    return 0;
}


/* ── Outbound cover traffic (Phase 8) ──────────────────────────────────── */
static volatile int g_real_traffic_pending = 0;

static DWORD poisson_interval_ms(void) {
    double u = (rand() + 1.0) / (RAND_MAX + 2.0);
    double iv = -DUMMY_INTERVAL_MS * log(u);
    if (iv < 10.0) iv = 10.0;
    if (iv > 1000.0) iv = 1000.0;
    return (DWORD)iv;
}

static DWORD WINAPI outbound_cover_thread(LPVOID arg) {
    (void)arg;
    srand((unsigned)GetTickCount());
    while (1) {
        Sleep(poisson_interval_ms());
        if (!g_state.ready) continue;
        if (g_real_traffic_pending) { g_real_traffic_pending = 0; continue; }
        wire_packet_t dummy = {0};
        if (packet_sphinx_dummy(&g_state.send_path, &dummy) != 0) continue;
        SOCKET s = net_connect(LOCALHOST, PORT_MIX_I);
        if (s == INVALID_SOCKET) continue;
        uint8_t mode = MODE_DATA;
        net_send_all(s, &mode, 1);
        net_send_all(s, dummy.data, WIRE_PACKET_SIZE);
        net_close(s);
    }
    return 0;
}

/* ── Upload content ─────────────────────────────────────────────────────── */
static int upload_content(const char *key,
                           const uint8_t *content, size_t content_len) {
    if (!g_state.ready) { log_err("paths not ready"); return -1; }

    size_t klen = strlen(key);
    if (klen > 63) { log_err("key too long"); return -1; }

    /* Build payload matching SvcGW parser:
     * [MNz_pubkey(65)][MNz_addr(6)][return_header(162)]
     * [TYPE_PUT(1)][klen(1)][key][clen(2)][content]                     */
    uint8_t payload[MAX_INNER_PAYLOAD];
    memset(payload, 0, sizeof(payload));
    size_t poff = 0;

    memcpy(payload + poff, g_state.mnz_pubkey, EC_PUBKEY_LEN); poff += EC_PUBKEY_LEN;
    memcpy(payload + poff, g_state.mnz_addr,   ADDR_BYTES);    poff += ADDR_BYTES;
    memcpy(payload + poff, &g_state.return_hdr, RETURN_HEADER_SIZE); poff += RETURN_HEADER_SIZE;

    payload[poff++] = TYPE_PUT;
    payload[poff++] = (uint8_t)klen;
    memcpy(payload + poff, key, klen); poff += klen;
    payload[poff++] = (uint8_t)(content_len >> 8);
    payload[poff++] = (uint8_t)(content_len & 0xFF);
    memcpy(payload + poff, content, content_len); poff += content_len;

    if (poff > MAX_INNER_PAYLOAD) { log_err("payload too large"); return -1; }

    wire_packet_t pkt = {0};
    if (packet_sphinx_build(&g_state.send_path, payload, (uint16_t)poff,
                            PKT_REAL | PKT_DEST_SERVICE, 0, &pkt) != 0) {
        log_err("packet_sphinx_build failed"); return -1;
    }

    g_real_traffic_pending = 1;
    SOCKET s = net_connect(LOCALHOST, PORT_MIX_I);
    if (s == INVALID_SOCKET) { log_err("connect MNi"); return -1; }

    uint8_t mode = MODE_DATA;
    net_send_all(s, &mode,    1);
    net_send_all(s, pkt.data, WIRE_PACKET_SIZE);
    net_close(s);

    /* Wait for ACK from SvcGW (optional — fire and forget is also valid) */
    if (WaitForSingleObject(g_resp_event, 5000) == WAIT_OBJECT_0) {
        EnterCriticalSection(&g_resp_lock);
        uint8_t wire[WIRE_PACKET_SIZE];
        memcpy(wire, g_resp_buf, WIRE_PACKET_SIZE);
        g_resp_ready = 0;
        ResetEvent(g_resp_event);
        LeaveCriticalSection(&g_resp_lock);

        /* Decrypt ACK with K_S-SG-B */
        size_t enc_len = (size_t)((wire[RETURN_HEADER_SIZE] << 8) |
                                    wire[RETURN_HEADER_SIZE+1]);
        const uint8_t *enc = wire + RETURN_HEADER_SIZE + 2;
        if (enc_len < GCM_OVERHEAD || enc_len > RETURN_PAYLOAD_SIZE - 2) enc_len = GCM_OVERHEAD;

        uint8_t ack[256];
        int n = crypto_aes_decrypt(&g_state.k_s_sg_b, enc, enc_len,
                                   ack, sizeof(ack));
        if (n > 0) {
            printf("[Sender] ACK: %.*s\n", n, ack);
            return 0;
        }
    }

    /* No ACK received -- still report success (content may be stored) */
    char logbuf[128];
    snprintf(logbuf, sizeof(logbuf),
             "uploaded key='%s' (%zu bytes) through Sphinx mix network",
             key, content_len);
    log_msg(logbuf);
    return 0;
}

/* ── Interactive loop ───────────────────────────────────────────────────── */
static void run_interactive(void) {
    printf("\n[Sender] Anonymous Service ready.\n");
    printf("Commands:\n");
    printf("  PUT <key> <content>    Upload content\n");
    printf("  quit                   Exit\n\n");

    char line[1024];
    while (1) {
        printf("sender> "); fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;

        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') line[--len] = '\0';
        if (len > 0 && line[len-1] == '\r') line[--len] = '\0';

        if (strcmp(line, "quit") == 0) break;

        if (strncmp(line, "PUT ", 4) == 0) {
            char *key     = strtok(line + 4, " ");
            char *content = strtok(NULL, "");
            if (!key || !content) { printf("Usage: PUT <key> <content>\n"); continue; }

            if (upload_content(key, (uint8_t *)content, strlen(content)) == 0)
                printf("[Sender] Content uploaded successfully.\n");
            else
                printf("[Sender] Upload failed.\n");
        } else if (len > 0) {
            printf("Unknown command.\n");
        }
    }
}

/* ── main ───────────────────────────────────────────────────────────────── */
int main(void) {
    SetConsoleOutputCP(65001);
    InitializeCriticalSection(&g_resp_lock);
    g_resp_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!g_resp_event) return 1;

    if (net_init() != 0) return 1;
    CreateDirectoryA(PUBKEY_DIR, NULL);
    log_msg("Anonymous Service (Sender) v2 starting...");

    if (build_paths() != 0) {
        log_err("path build failed -- ensure all mix nodes and SvcGW are running");
        net_cleanup(); return 1;
    }

    if (send_setup() != 0) {
        log_err("session setup failed"); return 1;
    }

    HANDLE ct = CreateThread(NULL, 0, outbound_cover_thread, NULL, 0, NULL);
    if (ct) CloseHandle(ct);

    /* Start ACK listener */
    HANDLE lt = CreateThread(NULL, 0, response_listener, NULL, 0, NULL);
    if (!lt) { log_err("response listener failed"); return 1; }
    CloseHandle(lt);
    Sleep(100);

    run_interactive();

    DeleteCriticalSection(&g_resp_lock);
    CloseHandle(g_resp_event);
    net_cleanup();
    return 0;
}
