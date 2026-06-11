/* tor_mix_node_instrumented.c  --  Tor-Equivalent Mix Node (Throughput Optimized)
 *
 * Based on tor_mix_node.c but optimized for Table 2 throughput benchmark:
 *   - Minimal per-cell logging (printf kills throughput at high N)
 *   - Exit node (TN3) sends to SG and closes -- no response wait
 *   - Same ECDHE, GCM decrypt, session lookup as original
 *
 * Usage:  tor_mix_node_instrumented.exe <port>
 *   9040 = TN1 (Guard), 9041 = TN2 (Middle), 9042 = TN3 (Exit)
 *
 * Build:
 *   gcc -O2 -o tor_mix_node_instrumented.exe tor_mix_node_instrumented.c \
 *       common/crypto.c common/net.c -lssl -lcrypto -lws2_32
 */

#include "common/net.h"
#include "common/crypto.h"
#include "tor_config.h"

#define TOR_MODE_RESET  0x1F

#ifdef TOR_MAX_SESSIONS
#undef TOR_MAX_SESSIONS
#endif
#define TOR_MAX_SESSIONS 2048

#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <ws2tcpip.h>

/* ---- Session store ------------------------------------------------------- */
typedef struct {
    uint8_t   hint[TOR_HINT_BYTES];
    aes_key_t session_key;
    uint16_t  next_port;
    int       is_exit;
    int       in_use;
} tor_session_t;

static tor_session_t    g_sessions[TOR_MAX_SESSIONS];
static CRITICAL_SECTION g_session_lock;

static tor_session_t *session_find(const uint8_t hint[TOR_HINT_BYTES]) {
    EnterCriticalSection(&g_session_lock);
    for (int i = 0; i < TOR_MAX_SESSIONS; i++) {
        if (g_sessions[i].in_use &&
            crypto_memcmp(g_sessions[i].hint, hint, TOR_HINT_BYTES) == 0) {
            LeaveCriticalSection(&g_session_lock);
            return &g_sessions[i];
        }
    }
    LeaveCriticalSection(&g_session_lock);
    return NULL;
}

static tor_session_t *session_alloc(void) {
    EnterCriticalSection(&g_session_lock);
    for (int i = 0; i < TOR_MAX_SESSIONS; i++) {
        if (!g_sessions[i].in_use) {
            g_sessions[i].in_use = 1;
            LeaveCriticalSection(&g_session_lock);
            return &g_sessions[i];
        }
    }
    LeaveCriticalSection(&g_session_lock);
    return NULL;
}

/* ---- Node keypair -------------------------------------------------------- */
static ecdh_keypair_t g_node_kp = {0};

/* ---- Per-connection context ---------------------------------------------- */
typedef struct {
    SOCKET   client_sock;
    uint16_t my_port;
} conn_ctx_t;

/* ---- EXTEND handler (same as original) ---------------------------------- */
static void handle_extend(SOCKET sock, uint16_t my_port) {
    uint8_t tport_bytes[2];
    if (net_recv_all(sock, tport_bytes, 2) != 0) return;
    uint16_t target_port = (uint16_t)((tport_bytes[0] << 8) | tport_bytes[1]);

    uint8_t client_pub[EC_PUBKEY_LEN];
    if (net_recv_all(sock, client_pub, EC_PUBKEY_LEN) != 0) return;

    aes_key_t master = {0};
    if (crypto_ecdh_derive(&g_node_kp, client_pub, &master) != 0) return;

    tor_session_t *sess = session_alloc();
    if (!sess) return;

    memcpy(sess->hint, client_pub + 1, TOR_HINT_BYTES);
    sess->session_key = master;
    sess->next_port   = target_port;
    sess->is_exit     = (target_port == 0 || target_port == TOR_PORT_SG);

    net_send_all(sock, g_node_kp.pubkey_bytes, EC_PUBKEY_LEN);

    /* Relay if needed */
    if (target_port != 0 && target_port != TOR_PORT_SG) {
        uint8_t rlen_bytes[2];
        if (net_recv_all(sock, rlen_bytes, 2) != 0) return;
        uint16_t rlen = (uint16_t)((rlen_bytes[0] << 8) | rlen_bytes[1]);

        uint8_t relay_buf[512];
        if (rlen > sizeof(relay_buf)) return;
        if (net_recv_all(sock, relay_buf, rlen) != 0) return;

        SOCKET next_sock = net_connect(TOR_LOCALHOST, target_port);
        if (next_sock == INVALID_SOCKET) return;

        uint8_t mode = TOR_MODE_EXTEND;
        net_send_all(next_sock, &mode, 1);
        net_send_all(next_sock, relay_buf, rlen);

        uint8_t target_pub[EC_PUBKEY_LEN];
        if (net_recv_all(next_sock, target_pub, EC_PUBKEY_LEN) == 0)
            net_send_all(sock, target_pub, EC_PUBKEY_LEN);
        net_close(next_sock);
    }
}

/* ---- DATA handler (optimized: minimal logging, no response wait) --------- */
static void handle_data(SOCKET sock, uint16_t my_port) {
    /* Read hint */
    uint8_t hint[TOR_HINT_BYTES];
    if (net_recv_all(sock, hint, TOR_HINT_BYTES) != 0) return;

    tor_session_t *sess = session_find(hint);
    if (!sess) return;  /* silent drop */

    /* Read cell length */
    uint8_t clen_bytes[2];
    if (net_recv_all(sock, clen_bytes, 2) != 0) return;
    uint16_t cell_len = (uint16_t)((clen_bytes[0] << 8) | clen_bytes[1]);

    if (cell_len < GCM_OVERHEAD + 2 || cell_len > TOR_MAX_CELL_SIZE) return;

    /* Read GCM cell */
    uint8_t *cell_buf = malloc(cell_len);
    if (!cell_buf) return;
    if (net_recv_all(sock, cell_buf, cell_len) != 0) {
        free(cell_buf); return;
    }

    /* GCM decrypt */
    size_t pt_max = cell_len;
    uint8_t *plaintext = malloc(pt_max);
    if (!plaintext) { free(cell_buf); return; }

    int pt_len = crypto_aes_decrypt(&sess->session_key,
                                     cell_buf, cell_len,
                                     plaintext, pt_max);
    free(cell_buf);
    if (pt_len < 2) { free(plaintext); return; }

    uint16_t next_port = (uint16_t)((plaintext[0] << 8) | plaintext[1]);
    uint8_t *inner     = plaintext + 2;
    int      inner_len = pt_len - 2;

    if (next_port == TOR_PORT_SG || next_port == 0) {
        /* EXIT NODE: forward to SG, close immediately, no response wait.
         * The SG counts the cell for goodput. We don't need the echo. */
        SOCKET sg_sock = net_connect(TOR_LOCALHOST, TOR_PORT_SG);
        if (sg_sock != INVALID_SOCKET) {
            int sg_buf_len = 1 + 2 + inner_len;
            uint8_t *sg_buf = malloc(sg_buf_len);
            if (sg_buf) {
                sg_buf[0] = TOR_MODE_DATA;
                sg_buf[1] = (uint8_t)(inner_len >> 8);
                sg_buf[2] = (uint8_t)(inner_len & 0xFF);
                memcpy(sg_buf + 3, inner, inner_len);

                int nd = 1;
                setsockopt(sg_sock, IPPROTO_TCP, TCP_NODELAY,
                           (const char *)&nd, sizeof(nd));
                net_send_all(sg_sock, sg_buf, sg_buf_len);
                free(sg_buf);
            }
            shutdown(sg_sock, SD_SEND);
            net_close(sg_sock);
        }
    } else {
        /* INTERMEDIATE NODE: forward to next hop */
        SOCKET next_sock = net_connect(TOR_LOCALHOST, next_port);
        if (next_sock != INVALID_SOCKET) {
            int nd = 1;
            setsockopt(next_sock, IPPROTO_TCP, TCP_NODELAY,
                       (const char *)&nd, sizeof(nd));

            int gcm_len = inner_len - TOR_HINT_BYTES;
            int out_len = 1 + TOR_HINT_BYTES + 2 + gcm_len;

            uint8_t *out_buf = malloc(out_len);
            if (out_buf) {
                out_buf[0] = TOR_MODE_DATA;
                memcpy(out_buf + 1, inner, TOR_HINT_BYTES);
                out_buf[1 + TOR_HINT_BYTES]     = (uint8_t)(gcm_len >> 8);
                out_buf[1 + TOR_HINT_BYTES + 1] = (uint8_t)(gcm_len & 0xFF);
                memcpy(out_buf + 1 + TOR_HINT_BYTES + 2,
                       inner + TOR_HINT_BYTES, gcm_len);

                net_send_all(next_sock, out_buf, out_len);
                free(out_buf);
            }
            net_close(next_sock);
        }
    }

    free(plaintext);
}

/* ---- RESET handler ------------------------------------------------------- */
static void handle_reset(uint16_t my_port) {
    EnterCriticalSection(&g_session_lock);
    memset(g_sessions, 0, sizeof(g_sessions));
    LeaveCriticalSection(&g_session_lock);
}

/* ---- Connection handler -------------------------------------------------- */
static DWORD WINAPI handle_connection(LPVOID arg) {
    conn_ctx_t *ctx  = (conn_ctx_t *)arg;
    SOCKET      sock = ctx->client_sock;
    uint16_t    port = ctx->my_port;
    free(ctx);

    uint8_t mode = 0;
    if (net_recv_all(sock, &mode, 1) != 0) goto done;

    switch (mode) {
        case TOR_MODE_EXTEND: handle_extend(sock, port); break;
        case TOR_MODE_DATA:   handle_data(sock, port);   break;
        case TOR_MODE_RESET:  handle_reset(port);        break;
        /* Ignore RESPONSE mode -- not needed for throughput benchmark */
        default: break;
    }

done:
    net_close(sock);
    return 0;
}

/* ---- main ---------------------------------------------------------------- */
int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: tor_mix_node_instrumented.exe <port>\n");
        return 1;
    }
    uint16_t port = (uint16_t)atoi(argv[1]);
    if (port < 1024) {
        fprintf(stderr, "Port must be >= 1024\n"); return 1;
    }

    SetConsoleOutputCP(65001);
    memset(g_sessions, 0, sizeof(g_sessions));
    InitializeCriticalSection(&g_session_lock);

    if (net_init() != 0) return 1;

    if (crypto_ecdh_keygen(&g_node_kp) != 0) {
        fprintf(stderr, "[TN:%u] keygen failed\n", port);
        net_cleanup(); return 1;
    }

    /* Save public key */
    CreateDirectoryA(TOR_PUBKEY_DIR, NULL);
    char pubkey_path[256];
    snprintf(pubkey_path, sizeof(pubkey_path),
             "%s\\%u.pub", TOR_PUBKEY_DIR, port);
    crypto_pubkey_save(&g_node_kp, pubkey_path);

    SOCKET server_sock = net_listen(port);
    if (server_sock == INVALID_SOCKET) { net_cleanup(); return 1; }

    printf("[TN:%u] ready (instrumented, throughput-optimized)\n", port);
    fflush(stdout);

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
