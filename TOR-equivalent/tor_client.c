/* tor_client.c  --  Tor-Equivalent Baseline Client
 *
 * Builds a 3-hop circuit (TN1 -> TN2 -> TN3) using direct ECDHE
 * handshakes to each node (same simplification as the Anon-Sec-Net
 * simulation -- noted in Section V.A of the manuscript).
 *
 * Then sends data through layered AES-256-GCM encryption
 * (one full encrypt per hop, outermost = TN1's key).
 *
 * Differences from Anon-Sec-Net client:
 *   - Single path, single end-to-end key
 *   - Full GCM layering (not Sphinx headers + XOR blinding)
 *   - No cover traffic emission
 *   - Response decryption = 3x GCM decrypt (peel layers)
 *
 * Build:  gcc -O2 -o tor_client.exe tor_client.c common/crypto.c
 *             common/net.c -lssl -lcrypto -lws2_32
 */

#include "common/net.h"
#include "common/crypto.h"
#include "tor_config.h"

#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

/* ── Per-hop session keys (established during circuit build) ──────────── */
typedef struct {
    aes_key_t key;
    uint8_t   hint[TOR_HINT_BYTES];
    uint16_t  port;
} hop_key_t;

static hop_key_t g_hops[TOR_MAX_HOPS];  /* [0]=TN1, [1]=TN2, [2]=TN3  */

/* ── Timing helpers ───────────────────────────────────────────────────── */
static double qpc_freq = 0.0;

static double time_now_ms(void) {
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart / qpc_freq * 1000.0;
}

/* ── Logging ──────────────────────────────────────────────────────────── */
static void log_msg(const char *msg) {
    printf("[TOR-CLIENT] %s\n", msg); fflush(stdout);
}
static void log_err(const char *msg) {
    fprintf(stderr, "[TOR-CLIENT] ERROR: %s\n", msg); fflush(stderr);
}

/* ── Extend to a single node (direct connection) ─────────────────────── */
/*
 * Wire format sent to node:
 *   [mode 1B = TOR_MODE_EXTEND]
 *   [target_port 2B = 0]   (don't relay further)
 *   [client_pubkey 65B]
 *
 * Wire format received:
 *   [node_pubkey 65B]
 */
static int extend_to_node(uint16_t node_port, ecdh_keypair_t *eph,
                           aes_key_t *out_key,
                           uint8_t out_hint[TOR_HINT_BYTES]) {
    SOCKET s = net_connect(TOR_LOCALHOST, node_port);
    if (s == INVALID_SOCKET) {
        log_err("extend: connect failed"); return -1;
    }

    uint8_t mode = TOR_MODE_EXTEND;
    net_send_all(s, &mode, 1);

    /* target_port = 0: no relay, just handshake with this node */
    uint8_t tport[2] = {0, 0};
    net_send_all(s, tport, 2);
    net_send_all(s, eph->pubkey_bytes, EC_PUBKEY_LEN);

    /* Read node's public key */
    uint8_t node_pub[EC_PUBKEY_LEN];
    if (net_recv_all(s, node_pub, EC_PUBKEY_LEN) != 0) {
        log_err("extend: read node pubkey");
        net_close(s); return -1;
    }
    net_close(s);

    /* Derive session key via ECDHE + HKDF */
    if (crypto_ecdh_derive(eph, node_pub, out_key) != 0) {
        log_err("extend: ECDH derive failed"); return -1;
    }

    /* Hint = first TOR_HINT_BYTES of our pubkey after 0x04 prefix */
    memcpy(out_hint, eph->pubkey_bytes + 1, TOR_HINT_BYTES);

    return 0;
}

/* ── Build circuit: direct ECDHE with each node ──────────────────────── */
static int build_circuit(void) {
    static const uint16_t ports[TOR_MAX_HOPS] = {
        TOR_PORT_TN1, TOR_PORT_TN2, TOR_PORT_TN3
    };
    static const char *names[TOR_MAX_HOPS] = {"TN1", "TN2", "TN3"};

    for (int hop = 0; hop < TOR_MAX_HOPS; hop++) {
        ecdh_keypair_t eph = {0};
        if (crypto_ecdh_keygen(&eph) != 0) {
            log_err("circuit: keygen failed"); return -1;
        }

        if (extend_to_node(ports[hop], &eph,
                            &g_hops[hop].key,
                            g_hops[hop].hint) != 0) {
            crypto_ecdh_free(&eph);
            log_err("circuit: extend failed"); return -1;
        }
        g_hops[hop].port = ports[hop];
        crypto_ecdh_free(&eph);

        char logbuf[64];
        snprintf(logbuf, sizeof(logbuf),
                 "circuit: %s session established", names[hop]);
        log_msg(logbuf);
    }

    log_msg("circuit: 3-hop circuit ready");
    return 0;
}

/* ── Layered encryption for forward path ──────────────────────────────── */
/*
 * Build a cell by wrapping payload in 3 layers of GCM encryption:
 *   Layer 3 (innermost, TN3's key): enc(key3, SG_port + payload)
 *   Layer 2 (TN2's key):            enc(key2, TN3_port + hint3 + layer2)
 *   Layer 1 (outermost, TN1's key): enc(key1, TN2_port + hint2 + layer1)
 *
 * On wire to TN1: [hint1][cell_len 2B][layer1]
 */
static int build_forward_cell(const uint8_t *payload, int payload_len,
                               uint8_t *out, int out_size) {
    /* Layer 3: innermost — tells TN3 to forward to SG */
    int l3_pt_len = 2 + payload_len;
    uint8_t *l3_pt = malloc(l3_pt_len);
    if (!l3_pt) return -1;

    l3_pt[0] = (uint8_t)(TOR_PORT_SG >> 8);
    l3_pt[1] = (uint8_t)(TOR_PORT_SG & 0xFF);
    memcpy(l3_pt + 2, payload, payload_len);

    int l3_enc_size = l3_pt_len + GCM_OVERHEAD;
    uint8_t *l3_enc = malloc(l3_enc_size);
    if (!l3_enc) { free(l3_pt); return -1; }

    int l3_len = crypto_aes_encrypt(&g_hops[2].key,
                                     l3_pt, l3_pt_len,
                                     l3_enc, l3_enc_size);
    free(l3_pt);
    if (l3_len < 0) { free(l3_enc); return -1; }

    /* Layer 2: wraps hint3 + layer3 — tells TN2 to forward to TN3 */
    int l2_pt_len = 2 + TOR_HINT_BYTES + l3_len;
    uint8_t *l2_pt = malloc(l2_pt_len);
    if (!l2_pt) { free(l3_enc); return -1; }

    l2_pt[0] = (uint8_t)(TOR_PORT_TN3 >> 8);
    l2_pt[1] = (uint8_t)(TOR_PORT_TN3 & 0xFF);
    memcpy(l2_pt + 2, g_hops[2].hint, TOR_HINT_BYTES);
    memcpy(l2_pt + 2 + TOR_HINT_BYTES, l3_enc, l3_len);
    free(l3_enc);

    int l2_enc_size = l2_pt_len + GCM_OVERHEAD;
    uint8_t *l2_enc = malloc(l2_enc_size);
    if (!l2_enc) { free(l2_pt); return -1; }

    int l2_len = crypto_aes_encrypt(&g_hops[1].key,
                                     l2_pt, l2_pt_len,
                                     l2_enc, l2_enc_size);
    free(l2_pt);
    if (l2_len < 0) { free(l2_enc); return -1; }

    /* Layer 1: wraps hint2 + layer2 — tells TN1 to forward to TN2 */
    int l1_pt_len = 2 + TOR_HINT_BYTES + l2_len;
    uint8_t *l1_pt = malloc(l1_pt_len);
    if (!l1_pt) { free(l2_enc); return -1; }

    l1_pt[0] = (uint8_t)(TOR_PORT_TN2 >> 8);
    l1_pt[1] = (uint8_t)(TOR_PORT_TN2 & 0xFF);
    memcpy(l1_pt + 2, g_hops[1].hint, TOR_HINT_BYTES);
    memcpy(l1_pt + 2 + TOR_HINT_BYTES, l2_enc, l2_len);
    free(l2_enc);

    int l1_enc_size = l1_pt_len + GCM_OVERHEAD;
    uint8_t *l1_enc = malloc(l1_enc_size);
    if (!l1_enc) { free(l1_pt); return -1; }

    int l1_len = crypto_aes_encrypt(&g_hops[0].key,
                                     l1_pt, l1_pt_len,
                                     l1_enc, l1_enc_size);
    free(l1_pt);
    if (l1_len < 0) { free(l1_enc); return -1; }

    /* Assemble wire: [hint1 16B][l1_len 2B][l1_enc] */
    int wire_len = TOR_HINT_BYTES + 2 + l1_len;
    if (wire_len > out_size) {
        free(l1_enc); return -1;
    }

    memcpy(out, g_hops[0].hint, TOR_HINT_BYTES);
    out[TOR_HINT_BYTES]     = (uint8_t)(l1_len >> 8);
    out[TOR_HINT_BYTES + 1] = (uint8_t)(l1_len & 0xFF);
    memcpy(out + TOR_HINT_BYTES + 2, l1_enc, l1_len);
    free(l1_enc);

    return wire_len;
}

/* ── Peel response layers ─────────────────────────────────────────────── */
static int peel_response(const uint8_t *enc_data, int enc_len,
                          uint8_t *out, int out_size) {
    uint8_t *cur = malloc(enc_len);
    if (!cur) return -1;
    memcpy(cur, enc_data, enc_len);
    int cur_len = enc_len;

    for (int hop = 0; hop < TOR_MAX_HOPS; hop++) {
        int pt_max = cur_len;
        uint8_t *pt = malloc(pt_max);
        if (!pt) { free(cur); return -1; }

        int pt_len = crypto_aes_decrypt(&g_hops[hop].key,
                                         cur, cur_len,
                                         pt, pt_max);
        free(cur);
        if (pt_len < 0) { free(pt); return -1; }

        cur = pt;
        cur_len = pt_len;
    }

    if (cur_len > out_size) { free(cur); return -1; }
    memcpy(out, cur, cur_len);
    free(cur);
    return cur_len;
}

/* ── Response listener thread ─────────────────────────────────────────── */
static DWORD WINAPI response_listener(LPVOID arg) {
    (void)arg;

    SOCKET server = net_listen(TOR_PORT_CLIENT);
    if (server == INVALID_SOCKET) {
        log_err("response listener: bind failed"); return 1;
    }
    log_msg("response listener ready");

    while (1) {
        SOCKET s = net_accept(server);
        if (s == INVALID_SOCKET) continue;

        uint8_t mode;
        if (net_recv_all(s, &mode, 1) != 0) { net_close(s); continue; }

        /* Response wire format (fixed): [hint TOR_HINT_BYTES][enc_len 2B][enc_data]
         * The hint identifies the circuit — we don't need it for decryption
         * (we only have one circuit in this client) but we read it to stay
         * in sync with the wire format.                                    */
        uint8_t hint[TOR_HINT_BYTES];
        if (net_recv_all(s, hint, TOR_HINT_BYTES) != 0) { net_close(s); continue; }
        (void)hint;  /* single-circuit client, hint not needed for key lookup */

        uint8_t plen_bytes[2];
        if (net_recv_all(s, plen_bytes, 2) != 0) { net_close(s); continue; }
        uint16_t plen = (uint16_t)((plen_bytes[0] << 8) | plen_bytes[1]);

        uint8_t *enc_buf = malloc(plen);
        if (!enc_buf) { net_close(s); continue; }
        if (net_recv_all(s, enc_buf, plen) != 0) {
            free(enc_buf); net_close(s); continue;
        }
        net_close(s);

        uint8_t plaintext[TOR_CELL_PAYLOAD];
        int pt_len = peel_response(enc_buf, plen,
                                    plaintext, sizeof(plaintext));
        free(enc_buf);

        if (pt_len > 0) {
            plaintext[pt_len < (int)sizeof(plaintext) - 1
                      ? pt_len : (int)sizeof(plaintext) - 1] = '\0';
            char logbuf[128];
            /* Limit preview to 80 chars to avoid truncation warning */
            snprintf(logbuf, sizeof(logbuf),
                     "response received (%d bytes): %.80s", pt_len, plaintext);
            log_msg(logbuf);
        } else {
            log_err("response: peel failed");
        }
    }

    net_close(server);
    return 0;
}

/* ── main ─────────────────────────────────────────────────────────────── */
int main(void) {
    SetConsoleOutputCP(65001);
    if (net_init() != 0) return 1;

    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    qpc_freq = (double)freq.QuadPart;

    /* Start response listener */
    HANDLE rl = CreateThread(NULL, 0, response_listener, NULL, 0, NULL);
    if (!rl) { log_err("response listener thread"); return 1; }
    CloseHandle(rl);
    Sleep(200);

    /* ── Build circuit ────────────────────────────────────────────────── */
    double t0 = time_now_ms();
    if (build_circuit() != 0) {
        log_err("circuit build failed"); net_cleanup(); return 1;
    }
    double t1 = time_now_ms();

    char tbuf[80];
    snprintf(tbuf, sizeof(tbuf), "circuit built in %.3f ms", t1 - t0);
    log_msg(tbuf);

    /* ── Send test data ───────────────────────────────────────────────── */
    const char *test_msg = "Hello from Tor-equivalent client!";
    int msg_len = (int)strlen(test_msg);

    uint8_t wire[TOR_MAX_CELL_SIZE + 256];
    double t2 = time_now_ms();
    int wire_len = build_forward_cell((const uint8_t *)test_msg, msg_len,
                                       wire, sizeof(wire));
    double t3 = time_now_ms();

    if (wire_len < 0) {
        log_err("build cell failed"); net_cleanup(); return 1;
    }

    snprintf(tbuf, sizeof(tbuf),
             "cell built (%d bytes) in %.3f ms", wire_len, t3 - t2);
    log_msg(tbuf);

    /* Send to TN1 */
    SOCKET s = net_connect(TOR_LOCALHOST, TOR_PORT_TN1);
    if (s == INVALID_SOCKET) {
        log_err("connect TN1"); net_cleanup(); return 1;
    }
    uint8_t mode = TOR_MODE_DATA;
    net_send_all(s, &mode, 1);
    net_send_all(s, wire, wire_len);
    net_close(s);

    log_msg("data cell sent through circuit");

    /* Wait for response */
    Sleep(2000);

    net_cleanup();
    return 0;
}