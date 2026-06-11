/* tor_mix_node.c  --  Tor-Equivalent Baseline Mix Node
 *
 * One binary, three instances:
 *   Guard  (TN1) : port 9040
 *   Middle (TN2) : port 9041
 *   Exit   (TN3) : port 9042
 *
 * KEY DIFFERENCE from Anon-Sec-Net mix_node.c:
 *   Each hop performs full AES-256-GCM decrypt then re-encrypt
 *   (Tor-style relay cell processing) rather than Sphinx-style
 *   XOR blinding.  This is the primary cost being benchmarked
 *   in Figure 2 of the manuscript.
 *
 * Same: OpenSSL P-256 ECDHE, HKDF-SHA256, Windows threads,
 *        loopback TCP, session store keyed by hint.
 *
 * Build:  gcc -O2 -o tor_mix_node.exe tor_mix_node.c common/crypto.c
 *             common/net.c -lssl -lcrypto -lws2_32
 */

#include "common/net.h"
#include "common/crypto.h"
#include "tor_config.h"

/* ── Benchmark reset mode ─────────────────────────────────────────────────
 * TOR_MODE_RESET (0x1F): wipes all sessions from the store.
 * Used by bench.exe between Figure 3 iterations so the 64-slot session
 * table never fills up.  Wire format: just the 1-byte mode, no payload.  */
#define TOR_MODE_RESET  0x1F

/* Raise session limit for the throughput benchmark (Table 2 uses up to 1000
 * concurrent sessions × 3 hops = 3000 slots needed across all nodes).
 * Each node handles 1000 sessions max so 1024 gives comfortable headroom.  */
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

/* ── Session store ────────────────────────────────────────────────────── */

typedef struct {
    uint8_t   hint[TOR_HINT_BYTES];   /* x-coord prefix of client pubkey */
    aes_key_t session_key;            /* per-circuit key for this hop    */
    uint16_t  next_port;              /* next hop (learned at extend)    */
    int       is_exit;                /* 1 if this is the exit node      */
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

/* ── Node keypair ─────────────────────────────────────────────────────── */
static ecdh_keypair_t g_node_kp = {0};

/* ── Logging ──────────────────────────────────────────────────────────── */
static void log_msg(uint16_t port, const char *msg) {
    printf("[TN:%u] %s\n", port, msg); fflush(stdout);
}
static void log_err(uint16_t port, const char *msg) {
    fprintf(stderr, "[TN:%u] ERROR: %s\n", port, msg); fflush(stderr);
}

/* ── Per-connection context ───────────────────────────────────────────── */
typedef struct {
    SOCKET   client_sock;
    uint16_t my_port;
} conn_ctx_t;

/* ── TOR_MODE_EXTEND handler ──────────────────────────────────────────── */
/*  Wire format:
 *    [target_port 2B][client_pubkey 65B]
 *    if target_port != 0:
 *      [relay_len 2B][relay_payload relay_len B]
 *
 *  Response:
 *    [node_pubkey 65B]
 *    if relayed: [target_pubkey 65B]
 */
static void handle_extend(SOCKET sock, uint16_t my_port) {
    /* Read target port (0 = this is the final hop in the telescope) */
    uint8_t tport_bytes[2];
    if (net_recv_all(sock, tport_bytes, 2) != 0) {
        log_err(my_port, "extend: read tport"); return;
    }
    uint16_t target_port = (uint16_t)((tport_bytes[0] << 8) | tport_bytes[1]);

    /* Read client's ephemeral public key */
    uint8_t client_pub[EC_PUBKEY_LEN];
    if (net_recv_all(sock, client_pub, EC_PUBKEY_LEN) != 0) {
        log_err(my_port, "extend: read pubkey"); return;
    }

    /* ECDHE -> master secret -> HKDF -> session key */
    aes_key_t master = {0};
    if (crypto_ecdh_derive(&g_node_kp, client_pub, &master) != 0) {
        log_err(my_port, "extend: ECDH failed"); return;
    }

    /* Store session */
    tor_session_t *sess = session_alloc();
    if (!sess) { log_err(my_port, "extend: session store full"); return; }

    /* Hint = first TOR_HINT_BYTES of client pubkey (after 0x04 prefix) */
    memcpy(sess->hint, client_pub + 1, TOR_HINT_BYTES);
    sess->session_key = master;   /* HKDF output is the session key     */
    sess->next_port   = target_port;
    sess->is_exit     = (target_port == 0 || target_port == TOR_PORT_SG);

    /* Send our public key back to the client */
    net_send_all(sock, g_node_kp.pubkey_bytes, EC_PUBKEY_LEN);

    char logbuf[80];
    snprintf(logbuf, sizeof(logbuf),
             "extend: session ready (next_port=%u, exit=%d)",
             sess->next_port, sess->is_exit);
    log_msg(my_port, logbuf);

    /* Relay to next hop if target_port != 0 */
    if (target_port != 0 && target_port != TOR_PORT_SG) {
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

        SOCKET next_sock = net_connect(TOR_LOCALHOST, target_port);
        if (next_sock == INVALID_SOCKET) {
            log_err(my_port, "extend relay: connect failed"); return;
        }

        uint8_t mode = TOR_MODE_EXTEND;
        net_send_all(next_sock, &mode,     1);
        net_send_all(next_sock, relay_buf, rlen);

        /* Read target's pubkey and relay back */
        uint8_t target_pub[EC_PUBKEY_LEN];
        if (net_recv_all(next_sock, target_pub, EC_PUBKEY_LEN) == 0)
            net_send_all(sock, target_pub, EC_PUBKEY_LEN);
        net_close(next_sock);
    }
}

/* ── TOR_MODE_DATA handler ────────────────────────────────────────────── */
/*
 * THIS IS THE KEY BENCHMARK TARGET (Figure 2).
 *
 * Tor-equivalent processing at each hop:
 *   1. Read hint (TOR_HINT_BYTES) -> session lookup
 *   2. Read GCM-encrypted cell remainder
 *   3. AES-256-GCM DECRYPT entire cell under session_key
 *      -> reveals: [next_port 2B][inner_cell_or_payload]
 *   4. If not exit: AES-256-GCM RE-ENCRYPT inner cell under
 *      next hop's perspective (here we just forward the decrypted
 *      inner cell which is already encrypted for the next hop)
 *   5. Forward to next hop
 *
 * Compare to Anon-Sec-Net which does:
 *   1. Peel one header block (small fixed-size decrypt)
 *   2. XOR-blind the payload with AES-CTR keystream
 *   -> Much cheaper: no full GCM decrypt of the whole payload
 *
 * Wire format (incoming cell):
 *   [hint TOR_HINT_BYTES][nonce 12B][encrypted_body NB][tag 16B]
 *   where encrypted_body = enc(session_key, next_port_2B + inner)
 */
static void handle_data(SOCKET sock, uint16_t my_port) {
    /* Read hint */
    uint8_t hint[TOR_HINT_BYTES];
    if (net_recv_all(sock, hint, TOR_HINT_BYTES) != 0) {
        log_err(my_port, "data: read hint"); return;
    }

    /* Session lookup (O(1) via hint, same as Anon-Sec-Net) */
    tor_session_t *sess = session_find(hint);
    if (!sess) {
        log_err(my_port, "data: no session for hint -- drop"); return;
    }

    /* Read cell length (2 bytes, big-endian) */
    uint8_t clen_bytes[2];
    if (net_recv_all(sock, clen_bytes, 2) != 0) {
        log_err(my_port, "data: read cell length"); return;
    }
    uint16_t cell_len = (uint16_t)((clen_bytes[0] << 8) | clen_bytes[1]);

    if (cell_len < GCM_OVERHEAD + 2 || cell_len > TOR_MAX_CELL_SIZE) {
        log_err(my_port, "data: invalid cell length"); return;
    }

    /* Read the GCM-encrypted cell (nonce + ciphertext + tag) */
    uint8_t *cell_buf = malloc(cell_len);
    if (!cell_buf) { log_err(my_port, "data: malloc"); return; }

    if (net_recv_all(sock, cell_buf, cell_len) != 0) {
        log_err(my_port, "data: read cell body");
        free(cell_buf); return;
    }

    /* ════════════════════════════════════════════════════════════════════
     *  FULL AES-256-GCM DECRYPT  (this is what makes Tor expensive)
     *  Decrypts the ENTIRE cell payload, not just a small header block.
     * ════════════════════════════════════════════════════════════════════ */
    size_t pt_max = cell_len;  /* plaintext is shorter, but this is safe */
    uint8_t *plaintext = malloc(pt_max);
    if (!plaintext) {
        log_err(my_port, "data: malloc plaintext");
        free(cell_buf); return;
    }

    int pt_len = crypto_aes_decrypt(&sess->session_key,
                                     cell_buf, cell_len,
                                     plaintext, pt_max);
    free(cell_buf);

    if (pt_len < 2) {
        log_err(my_port, "data: GCM decrypt failed -- drop");
        free(plaintext); return;
    }

    /* Parse next_port from decrypted plaintext */
    uint16_t next_port = (uint16_t)((plaintext[0] << 8) | plaintext[1]);
    uint8_t *inner     = plaintext + 2;
    int      inner_len = pt_len - 2;

    char logbuf[120];
    snprintf(logbuf, sizeof(logbuf),
             "data: decrypted %d bytes -> next port %u (SG=%u)",
             pt_len, next_port, TOR_PORT_SG);
    log_msg(my_port, logbuf);

    if (next_port == TOR_PORT_SG || next_port == 0) {
        /* Exit node: forward payload to SG and wait for response */
        SOCKET sg_sock = net_connect(TOR_LOCALHOST, TOR_PORT_SG);
        if (sg_sock == INVALID_SOCKET) {
            log_err(my_port, "data: connect SG");
            free(plaintext); return;
        }

        /* Send: [mode 1B][inner_len 2B][inner] */
        int sg_buf_len = 1 + 2 + inner_len;
        uint8_t *sg_buf = malloc(sg_buf_len);
        if (!sg_buf) {
            log_err(my_port, "data: malloc sg_buf");
            net_close(sg_sock); free(plaintext); return;
        }
        sg_buf[0] = TOR_MODE_DATA;
        sg_buf[1] = (uint8_t)(inner_len >> 8);
        sg_buf[2] = (uint8_t)(inner_len & 0xFF);
        memcpy(sg_buf + 3, inner, inner_len);

        net_send_all(sg_sock, sg_buf, sg_buf_len);
        free(sg_buf);
        free(plaintext);
        plaintext = NULL;

        /* Wait for SG's response on the same socket.
         * SG sends back: [resp_len 2B][response_data] */
        log_msg(my_port, "data: waiting for SG response...");

        uint8_t rlen_bytes[2];
        if (net_recv_all(sg_sock, rlen_bytes, 2) != 0) {
            log_err(my_port, "data: read SG response length");
            net_close(sg_sock); return;
        }
        uint16_t resp_len = (uint16_t)((rlen_bytes[0] << 8) | rlen_bytes[1]);

        if (resp_len == 0 || resp_len > TOR_CELL_PAYLOAD) {
            log_err(my_port, "data: invalid SG response length");
            net_close(sg_sock); return;
        }

        uint8_t *resp_data = malloc(resp_len);
        if (!resp_data) {
            log_err(my_port, "data: malloc resp");
            net_close(sg_sock); return;
        }
        if (net_recv_all(sg_sock, resp_data, resp_len) != 0) {
            log_err(my_port, "data: read SG response body");
            free(resp_data); net_close(sg_sock); return;
        }
        net_close(sg_sock);

        char rl[80];
        snprintf(rl, sizeof(rl), "data: SG response %u bytes, encrypting", resp_len);
        log_msg(my_port, rl);

        /* Encrypt response under our (TN3's) session key — first layer */
        size_t enc_size = resp_len + GCM_OVERHEAD;
        uint8_t *enc_buf = malloc(enc_size);
        if (!enc_buf) { free(resp_data); return; }

        int enc_len = crypto_aes_encrypt(&sess->session_key,
                                          resp_data, resp_len,
                                          enc_buf, enc_size);
        free(resp_data);
        if (enc_len < 0) {
            log_err(my_port, "data: response encrypt failed");
            free(enc_buf); return;
        }

        /* Determine previous hop port.
         * For the fixed 3-hop topology TN3 always sends back to TN2.
         * A general implementation would store prev_port in the session
         * (set during the extend handshake that reached this node).
         * For this baseline the topology is fixed so we use TOR_PORT_TN2. */
        uint16_t fwd_port = TOR_PORT_TN2;

        /* Build response wire: [mode 1B][hint TOR_HINT_BYTES][enc_len 2B][enc_data]
         * The hint travels with the response so each intermediate node can
         * do a hint-matched session lookup for re-encryption.             */
        int out_len = 1 + TOR_HINT_BYTES + 2 + enc_len;
        uint8_t *out_buf = malloc(out_len);
        if (!out_buf) { free(enc_buf); return; }

        out_buf[0] = TOR_MODE_RESPONSE;
        memcpy(out_buf + 1, sess->hint, TOR_HINT_BYTES);
        out_buf[1 + TOR_HINT_BYTES]     = (uint8_t)(enc_len >> 8);
        out_buf[1 + TOR_HINT_BYTES + 1] = (uint8_t)(enc_len & 0xFF);
        memcpy(out_buf + 1 + TOR_HINT_BYTES + 2, enc_buf, enc_len);
        free(enc_buf);

        SOCKET tn2_sock = net_connect(TOR_LOCALHOST, fwd_port);
        if (tn2_sock == INVALID_SOCKET) {
            log_err(my_port, "data: connect TN2 for response");
            free(out_buf); return;
        }
        int nodelay = 1;
        setsockopt(tn2_sock, IPPROTO_TCP, TCP_NODELAY,
                   (const char *)&nodelay, sizeof(nodelay));

        net_send_all(tn2_sock, out_buf, out_len);
        free(out_buf);
        net_close(tn2_sock);

        {
            char rl2[80];
            snprintf(rl2, sizeof(rl2),
                     "data: response forwarded (%d bytes) -> port %u",
                     enc_len, fwd_port);
            log_msg(my_port, rl2);
        }
        return;  /* plaintext already freed */
    } else {
        /* Intermediate node: forward inner cell (already encrypted
         * for next hop) to the next mix node.
         *
         * The inner cell starts with [hint_next 16B][GCM_envelope].
         * We send: [mode 1B][hint 16B][cell_len 2B][GCM_envelope]   */
        SOCKET next_sock = net_connect(TOR_LOCALHOST, next_port);
        if (next_sock == INVALID_SOCKET) {
            log_err(my_port, "data: connect next hop");
            free(plaintext); return;
        }


        /* Disable Nagle to send immediately */
        int nodelay = 1;
        setsockopt(next_sock, IPPROTO_TCP, TCP_NODELAY,
                   (const char *)&nodelay, sizeof(nodelay));

        /* Inner layout: [hint_next 16B][gcm_data (inner_len-16)B]
         * Build single output buffer to avoid send/close race:
         *   [mode 1B][hint 16B][gcm_len 2B][gcm_data]               */
        int gcm_len = inner_len - TOR_HINT_BYTES;
        int out_len = 1 + TOR_HINT_BYTES + 2 + gcm_len;

        char dbg[120];
        snprintf(dbg, sizeof(dbg),
                 "data: fwd inner_len=%d gcm_len=%d out_len=%d -> port %u",
                 inner_len, gcm_len, out_len, next_port);
        log_msg(my_port, dbg);

        uint8_t *out_buf = malloc(out_len);
        if (!out_buf) {
            log_err(my_port, "data: malloc out_buf");
            net_close(next_sock); free(plaintext); return;
        }

        out_buf[0] = TOR_MODE_DATA;
        memcpy(out_buf + 1, inner, TOR_HINT_BYTES);
        out_buf[1 + TOR_HINT_BYTES]     = (uint8_t)(gcm_len >> 8);
        out_buf[1 + TOR_HINT_BYTES + 1] = (uint8_t)(gcm_len & 0xFF);
        memcpy(out_buf + 1 + TOR_HINT_BYTES + 2,
               inner + TOR_HINT_BYTES, gcm_len);

        net_send_all(next_sock, out_buf, out_len);
        free(out_buf);
        net_close(next_sock);
    }

    free(plaintext);
}

/* ── TOR_MODE_RESPONSE handler ────────────────────────────────────────── */
/*
 * Response path (TN3 -> TN2 -> TN1 -> Client).
 * Each hop AES-256-GCM ENCRYPTS the cell under its session key
 * (adding one layer), the reverse of the forward path.
 *
 * Wire format: [hint TOR_HINT_BYTES][payload_len 2B][payload NB]
 *
 * The hint identifies which circuit's session key to use for
 * re-encryption. TN3 embeds the circuit's hint when initiating
 * the response; each intermediate node carries it forward unchanged.
 */
static void handle_response(SOCKET sock, uint16_t my_port) {
    /* Read circuit hint for session lookup */
    uint8_t hint[TOR_HINT_BYTES];
    if (net_recv_all(sock, hint, TOR_HINT_BYTES) != 0) {
        log_err(my_port, "response: read hint"); return;
    }

    uint8_t plen_bytes[2];
    if (net_recv_all(sock, plen_bytes, 2) != 0) {
        log_err(my_port, "response: read plen"); return;
    }
    uint16_t payload_len = (uint16_t)((plen_bytes[0] << 8) | plen_bytes[1]);

    if (payload_len == 0 || payload_len > TOR_MAX_CELL_SIZE) {
        log_err(my_port, "response: invalid payload length"); return;
    }

    uint8_t *payload = malloc(payload_len);
    if (!payload) { log_err(my_port, "response: malloc"); return; }
    if (net_recv_all(sock, payload, payload_len) != 0) {
        log_err(my_port, "response: read payload");
        free(payload); return;
    }

    /* Hint-matched session lookup (correct for concurrent circuits) */
    tor_session_t *sess = session_find(hint);
    if (!sess) {
        /* Fallback: first active session (single-circuit bench mode) */
        EnterCriticalSection(&g_session_lock);
        for (int i = 0; i < TOR_MAX_SESSIONS; i++) {
            if (g_sessions[i].in_use) { sess = &g_sessions[i]; break; }
        }
        LeaveCriticalSection(&g_session_lock);
    }

    if (!sess) {
        log_err(my_port, "response: no active session");
        free(payload); return;
    }

    /* AES-256-GCM ENCRYPT — add one layer */
    size_t enc_size = payload_len + GCM_OVERHEAD;
    uint8_t *enc_buf = malloc(enc_size);
    if (!enc_buf) { free(payload); return; }

    int enc_len = crypto_aes_encrypt(&sess->session_key,
                                      payload, payload_len,
                                      enc_buf, enc_size);
    free(payload);
    if (enc_len < 0) {
        log_err(my_port, "response: GCM encrypt failed");
        free(enc_buf); return;
    }

    uint16_t fwd_port;
    switch (my_port) {
        case TOR_PORT_TN3: fwd_port = TOR_PORT_TN2;   break;
        case TOR_PORT_TN2: fwd_port = TOR_PORT_TN1;   break;
        case TOR_PORT_TN1:
            /* Guard node: deliver to client response listener on TOR_PORT_CLIENT.
             * tor_client.c starts a response_listener thread on this port.
             * In bench mode (bench.exe) nothing listens here, so the connect
             * will fail silently — that is acceptable for throughput benchmarks
             * which only measure the forward path.                          */
            fwd_port = TOR_PORT_CLIENT;
            break;
        default:           fwd_port = TOR_PORT_CLIENT; break;
    }

    char logbuf[80];
    snprintf(logbuf, sizeof(logbuf),
             "response: encrypted %d bytes -> port %u", enc_len, fwd_port);
    log_msg(my_port, logbuf);

    /* Build: [mode 1B][hint TOR_HINT_BYTES][enc_len 2B][enc_data]
     * Pass the circuit hint so the next node can do hint-matched session lookup. */
    int out_len = 1 + TOR_HINT_BYTES + 2 + enc_len;
    uint8_t *out_buf = malloc(out_len);
    if (!out_buf) { free(enc_buf); return; }

    out_buf[0] = TOR_MODE_RESPONSE;
    memcpy(out_buf + 1, sess->hint, TOR_HINT_BYTES);
    out_buf[1 + TOR_HINT_BYTES]     = (uint8_t)(enc_len >> 8);
    out_buf[1 + TOR_HINT_BYTES + 1] = (uint8_t)(enc_len & 0xFF);
    memcpy(out_buf + 1 + TOR_HINT_BYTES + 2, enc_buf, enc_len);
    free(enc_buf);

	SOCKET next_sock = net_connect(TOR_LOCALHOST, fwd_port);
    if (next_sock == INVALID_SOCKET) {
        log_err(my_port, "response: connect next");
        free(out_buf); return;
    }
    int nd = 1;
    setsockopt(next_sock, IPPROTO_TCP, TCP_NODELAY,
               (const char *)&nd, sizeof(nd));
    net_send_all(next_sock, out_buf, out_len);
    free(out_buf);
    net_close(next_sock);
}

/* ── TOR_MODE_RESET handler ───────────────────────────────────────────── */
/* Wipes every session slot so bench iterations don't exhaust the store.   */
static void handle_reset(uint16_t my_port) {
    EnterCriticalSection(&g_session_lock);
    memset(g_sessions, 0, sizeof(g_sessions));
    LeaveCriticalSection(&g_session_lock);
    log_msg(my_port, "reset: all sessions cleared");
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
        case TOR_MODE_EXTEND:   handle_extend(sock, port);   break;
        case TOR_MODE_DATA:     handle_data(sock, port);     break;
        case TOR_MODE_RESPONSE: handle_response(sock, port); break;
        case TOR_MODE_RESET:    handle_reset(port);          break;
        default:
            { char lb[48]; snprintf(lb,sizeof(lb),"unknown mode 0x%02x",mode);
              log_err(port, lb); }
            break;
    }

done:
    net_close(sock);
    return 0;
}

/* ── main ─────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: tor_mix_node.exe <port>\n"); return 1;
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
    if (crypto_pubkey_save(&g_node_kp, pubkey_path) != 0) {
        fprintf(stderr, "[TN:%u] save pubkey failed\n", port);
        net_cleanup(); return 1;
    }
    printf("[TN:%u] pubkey written to %s\n", port, pubkey_path);

    SOCKET server_sock = net_listen(port);
    if (server_sock == INVALID_SOCKET) { net_cleanup(); return 1; }

    printf("[TN:%u] ready (Tor-equivalent baseline)\n", port); fflush(stdout);

    /* No cover traffic thread -- per spec Section 12.1 */

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