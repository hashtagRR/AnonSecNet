/* exit_node.c  —  Exit Node x  (:9003)  —  Anon-Sec-Net v2
 *
 * Receives MODE_RESPONSE packets from MNc and delivers them
 * to the client's response port.
 */

#include "common/net.h"
#include "common/packet.h"
#include "common/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

static void log_msg(const char *m) { printf("[ExitX] %s\n", m); fflush(stdout); }
static void log_err(const char *m) { fprintf(stderr, "[ExitX] ERROR: %s\n", m); fflush(stderr); }

typedef struct { SOCKET s; } conn_ctx_t;

static DWORD WINAPI handle_connection(LPVOID arg) {
    conn_ctx_t *ctx = (conn_ctx_t *)arg;
    SOCKET sock = ctx->s; free(ctx);

    uint8_t mode = 0;
    if (net_recv_all(sock, &mode, 1) != 0) { log_err("read mode"); goto done; }

    if (mode == MODE_RESPONSE) {
        /* Read client response port (2 bytes big-endian) */
        uint8_t port_bytes[2];
        if (net_recv_all(sock, port_bytes, 2) != 0) {
            log_err("read client port"); goto done;
        }
        uint16_t client_port = (uint16_t)((port_bytes[0] << 8) | port_bytes[1]);

        /* Read the response packet */
        wire_packet_t pkt = {0};
        if (net_recv_all(sock, pkt.data, WIRE_PACKET_SIZE) != 0) {
            log_err("read response packet"); goto done;
        }

        char logbuf[64];
        snprintf(logbuf, sizeof(logbuf),
                 "delivering response to client port %u", client_port);
        log_msg(logbuf);

        SOCKET client_sock = net_connect(LOCALHOST, client_port);
        if (client_sock == INVALID_SOCKET) {
            log_err("connect client"); goto done;
        }

        net_send_all(client_sock, pkt.data, WIRE_PACKET_SIZE);
        net_close(client_sock);

    } else {
        log_err("unexpected mode byte");
    }

done:
    net_close(sock); return 0;
}

int main(void) {
    SetConsoleOutputCP(65001);
    if (net_init() != 0) return 1;

    SOCKET srv = net_listen(PORT_EXIT_X);
    if (srv == INVALID_SOCKET) { net_cleanup(); return 1; }
    log_msg("ready");

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
