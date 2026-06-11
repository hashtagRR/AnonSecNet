/* tor_sg_instrumented.c  --  Tor-Equivalent Instrumented Service Gateway (v4)
 *
 * Fire-and-forget throughput measurement:
 *   - Receives cell, counts bytes, closes. No echo response.
 *   - This eliminates the response path bottleneck where TN3 blocked
 *     waiting for SG echo, then triggered 3 more TCP connections back
 *     through TN2->TN1->Client. At high N that caused 4x connection
 *     amplification and TCP accept queue exhaustion.
 *   - Matches ASN SG behavior: ASN SG counts WIRE_PACKET_SIZE per
 *     arrival and only responds to TYPE_SETUP/TYPE_GET, not bulk cells.
 *
 * Build:
 *   gcc -O2 -std=c11 -o tor_sg_instrumented.exe tor_sg_instrumented.c \
 *       common/crypto.c common/net.c -lssl -lcrypto -lws2_32
 */

#include "common/net.h"
#include "common/crypto.h"
#include "tor_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <windows.h>

#define TOR_WIRE_BYTES  TOR_CELL_PAYLOAD   /* 1024 -- matches ASN */

/* Atomic counters */
static atomic_llong g_window_bytes = 0;
static atomic_llong g_total_bytes  = 0;
static atomic_llong g_total_cells  = 0;

#define GOODPUT_CSV  "tor_sg_goodput.csv"
#define DEBUG_LOG    "tor_sg_debug.log"

/* ---- Timing -------------------------------------------------------------- */
static double qpc_freq = 0.0;

static double time_now_ms(void) {
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart / qpc_freq * 1000.0;
}

static void debug_log(const char *msg) {
    FILE *fp = fopen(DEBUG_LOG, "a");
    if (!fp) return;
    fprintf(fp, "[%.0f] %s\n", time_now_ms(), msg);
    fclose(fp);
}

/* ---- Goodput writer (per-second sample) --------------------------------- */
static DWORD WINAPI goodput_writer(LPVOID arg) {
    (void)arg;
    while (1) {
        Sleep(1000);
        long long bytes = atomic_exchange(&g_window_bytes, 0);
        double bps = (double)bytes * 8.0;
        double ts = time_now_ms();

        FILE *fp = fopen(GOODPUT_CSV, "a");
        if (fp) {
            fprintf(fp, "ts_ms,%.0f,bps,%.1f\n", ts, bps);
            fclose(fp);
        }
    }
    return 0;
}

/* ---- Debug stats (every 5s) --------------------------------------------- */
static DWORD WINAPI debug_stats(LPVOID arg) {
    (void)arg;
    while (1) {
        Sleep(5000);
        char buf[120];
        snprintf(buf, sizeof(buf), "STATS: cells=%lld bytes=%lld",
                 (long long)atomic_load(&g_total_cells),
                 (long long)atomic_load(&g_total_bytes));
        debug_log(buf);
    }
    return 0;
}

/* ---- Connection handler -------------------------------------------------- */
typedef struct { SOCKET sock; } sg_conn_t;

static DWORD WINAPI handle_sg_conn(LPVOID arg) {
    sg_conn_t *ctx = (sg_conn_t *)arg;
    SOCKET sock = ctx->sock;
    free(ctx);

    uint8_t mode;
    if (net_recv_all(sock, &mode, 1) != 0) goto done;

    if (mode == TOR_MODE_DATA) {
        uint8_t plen_bytes[2];
        if (net_recv_all(sock, plen_bytes, 2) != 0) goto done;
        uint16_t plen = (uint16_t)((plen_bytes[0] << 8) | plen_bytes[1]);

        if (plen > TOR_CELL_PAYLOAD) goto done;

        uint8_t payload[TOR_CELL_PAYLOAD];
        if (net_recv_all(sock, payload, plen) != 0) goto done;

        /* Count and done. No echo response -- fire and forget.
         * This matches ASN SG which counts WIRE_PACKET_SIZE per
         * arrival without echoing back on every cell. */
        atomic_fetch_add(&g_window_bytes, (long long)TOR_WIRE_BYTES);
        atomic_fetch_add(&g_total_bytes,  (long long)TOR_WIRE_BYTES);
        atomic_fetch_add(&g_total_cells,  1);
    }

done:
    net_close(sock);
    return 0;
}

/* ---- main --------------------------------------------------------------- */
int main(void) {
    SetConsoleOutputCP(65001);
    if (net_init() != 0) return 1;

    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    qpc_freq = (double)freq.QuadPart;

    SOCKET server = net_listen(TOR_PORT_SG);
    if (server == INVALID_SOCKET) { net_cleanup(); return 1; }

    printf("[TOR-SG-I] ready on port %u\n", TOR_PORT_SG); fflush(stdout);
    debug_log("SG started (fire-and-forget mode)");

    HANDLE gw = CreateThread(NULL, 0, goodput_writer, NULL, 0, NULL);
    if (gw) CloseHandle(gw);
    HANDLE ds = CreateThread(NULL, 0, debug_stats, NULL, 0, NULL);
    if (ds) CloseHandle(ds);

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