/* entry_node.c  —  Entry Node x  (:9002)  —  Anon-Sec-Net v2
 *
 * The client's ingress into the mix network.
 * Receives MODE_DATA packets and forwards unchanged to MN1.
 * Does not participate in path construction (MODE_EXTEND goes
 * directly to each mix node from the client).
 */

#include "common/net.h"
#include "common/packet.h"
#include "common/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

static void log_msg(const char *m) { printf("[EntryX] %s\n", m); fflush(stdout); }
static void log_err(const char *m) { fprintf(stderr, "[EntryX] ERROR: %s\n", m); fflush(stderr); }

typedef struct { SOCKET s; } conn_ctx_t;

static DWORD WINAPI handle_connection(LPVOID arg) {
    conn_ctx_t *ctx = (conn_ctx_t *)arg;
    SOCKET sock = ctx->s; free(ctx);

    uint8_t mode = 0;
    if (net_recv_all(sock, &mode, 1) != 0) { log_err("read mode"); goto done; }

    if (mode == MODE_DATA) {
        wire_packet_t pkt = {0};
        if (net_recv_all(sock, pkt.data, WIRE_PACKET_SIZE) != 0) {
            log_err("read packet"); goto done;
        }

        log_msg("forwarding to MN1");

        SOCKET mn1 = net_connect(LOCALHOST, PORT_MIX_1);
        if (mn1 == INVALID_SOCKET) { log_err("connect MN1"); goto done; }

        net_send_all(mn1, &mode,      1);
        net_send_all(mn1, pkt.data,   WIRE_PACKET_SIZE);
        net_close(mn1);

    } else {
        log_err("unexpected mode byte");
    }

done:
    net_close(sock); return 0;
}

int main(void) {
    SetConsoleOutputCP(65001);
    if (net_init() != 0) return 1;

    SOCKET srv = net_listen(PORT_ENTRY_X);
    if (srv == INVALID_SOCKET) { net_cleanup(); return 1; }
    log_msg("ready — waiting for client connections");

    while (1) {
        SOCKET cs = net_accept(srv);
        if (cs == INVALID_SOCKET) continue;
        conn_ctx_t *ctx = malloc(sizeof(conn_ctx_t));
        if (!ctx) { net_close(cs); continue; }
        ctx->s = cs;
        HANDLE t = CreateThread(NULL, 0, handle_connection, ctx, 0, NULL);
        if (!t) { net_close(cs); free(ctx); continue; }
        CloseHandle(t);
    }
    net_close(srv); net_cleanup(); return 0;
}
