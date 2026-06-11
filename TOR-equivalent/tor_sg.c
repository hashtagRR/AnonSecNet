/* tor_sg.c  --  Tor-Equivalent Baseline Service Gateway (Destination)
 *
 * Simplified SG that:
 *   1. Receives plaintext payload from exit node (TN3)
 *   2. Echoes a response back through the circuit
 *
 * For benchmarking, this is intentionally minimal -- the SG
 * processing overhead is not part of the per-hop comparison.
 *
 * Build:  gcc -O2 -o tor_sg.exe tor_sg.c common/crypto.c
 *             common/net.c -lssl -lcrypto -lws2_32
 */

#include "common/net.h"
#include "common/crypto.h"
#include "tor_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

/* ── Per-circuit keys (set by client via a setup message) ─────────────── */
/* For the baseline, the SG holds the 3 per-hop hints so it can
 * address response cells back through TN3 -> TN2 -> TN1.
 * In a real Tor circuit the SG doesn't have hop keys; the exit
 * node handles the layering. Here we simplify: the response is
 * sent directly to TN3 which adds layers on the return path.     */

static void log_msg(const char *msg) {
    printf("[TOR-SG] %s\n", msg); fflush(stdout);
}
static void log_err(const char *msg) {
    fprintf(stderr, "[TOR-SG] ERROR: %s\n", msg); fflush(stderr);
}

/* ── Connection handler ───────────────────────────────────────────────── */
typedef struct {
    SOCKET sock;
} sg_conn_t;

static DWORD WINAPI handle_sg_conn(LPVOID arg) {
    sg_conn_t *ctx = (sg_conn_t *)arg;
    SOCKET sock = ctx->sock;
    free(ctx);

    uint8_t mode;
    if (net_recv_all(sock, &mode, 1) != 0) {
        log_err("read mode"); goto done;
    }

    if (mode == TOR_MODE_DATA) {
        /* Read payload length */
        uint8_t plen_bytes[2];
        if (net_recv_all(sock, plen_bytes, 2) != 0) {
            log_err("read plen"); goto done;
        }
        uint16_t plen = (uint16_t)((plen_bytes[0] << 8) | plen_bytes[1]);

        if (plen > TOR_CELL_PAYLOAD) {
            log_err("payload too large"); goto done;
        }

        uint8_t payload[TOR_CELL_PAYLOAD];
        if (net_recv_all(sock, payload, plen) != 0) {
            log_err("read payload"); goto done;
        }

        char logbuf[128];
        snprintf(logbuf, sizeof(logbuf),
                 "received %u bytes: %.64s", plen, payload);
        log_msg(logbuf);

        /* Build response -- echo back with a prefix */
        char response[TOR_CELL_PAYLOAD];
        int rlen = snprintf(response, sizeof(response),
                            "SG-ECHO: %.*s", plen, payload);
        if (rlen < 0) rlen = 0;

        /* Send response back on the SAME socket to TN3.
         * Wire format: [rlen 2B][response_data rlen B]
         * Single buffer to avoid partial send issues.  */
        int resp_buf_len = 2 + rlen;
        uint8_t *resp_buf = malloc(resp_buf_len);
        if (resp_buf) {
            resp_buf[0] = (uint8_t)(rlen >> 8);
            resp_buf[1] = (uint8_t)(rlen & 0xFF);
            memcpy(resp_buf + 2, response, rlen);
            net_send_all(sock, resp_buf, resp_buf_len);
            free(resp_buf);
        }

        log_msg("response sent back to TN3 on same socket");
    }

done:
    /* Flush send buffer before closing */
    shutdown(sock, SD_SEND);
    { uint8_t drain[1]; recv(sock, (char*)drain, 1, 0); }
    net_close(sock);
    return 0;
}

/* ── main ─────────────────────────────────────────────────────────────── */
int main(void) {
    SetConsoleOutputCP(65001);
    if (net_init() != 0) return 1;

    SOCKET server = net_listen(TOR_PORT_SG);
    if (server == INVALID_SOCKET) { net_cleanup(); return 1; }

    printf("[TOR-SG] ready on port %u\n", TOR_PORT_SG); fflush(stdout);

    while (1) {
        SOCKET cs = net_accept(server);
        if (cs == INVALID_SOCKET) continue;

        sg_conn_t *ctx = malloc(sizeof(sg_conn_t));
        if (!ctx) { net_close(cs); continue; }
        ctx->sock = cs;

        HANDLE t = CreateThread(NULL, 0, handle_sg_conn, ctx, 0, NULL);
        if (!t) { net_close(cs); free(ctx); continue; }
        CloseHandle(t);
    }

    net_close(server);
    net_cleanup();
    return 0;
}
