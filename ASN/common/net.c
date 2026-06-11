#include "net.h"
#include "config.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>

/* -- Init / cleanup ------------------------------------------------------- */

int net_init(void) {
    WSADATA wsa;
    int rc = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (rc != 0) {
        fprintf(stderr, "[net] WSAStartup failed: %d\n", rc);
        return -1;
    }
    return 0;
}

void net_cleanup(void) {
    WSACleanup();
}

/* -- Internal helper ------------------------------------------------------ */

/* Fill a sockaddr_in for 127.0.0.1:port */
static void make_addr(struct sockaddr_in *addr, uint16_t port) {
    memset(addr, 0, sizeof(*addr));
    addr->sin_family      = AF_INET;
    addr->sin_port        = htons(port);
    addr->sin_addr.s_addr = INADDR_ANY;  /* bind on all interfaces */
}

/* -- Server side ---------------------------------------------------------- */

SOCKET net_listen(uint16_t port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        fprintf(stderr, "[net] socket() failed: %d\n", WSAGetLastError());
        return INVALID_SOCKET;
    }

    /* Allow quick restart without waiting for TIME_WAIT */
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));

    struct sockaddr_in addr;
    make_addr(&addr, port);

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        fprintf(stderr, "[net] bind() on port %u failed: %d\n",
                port, WSAGetLastError());
        closesocket(s);
        return INVALID_SOCKET;
    }

    if (listen(s, BACKLOG) == SOCKET_ERROR) {
        fprintf(stderr, "[net] listen() failed: %d\n", WSAGetLastError());
        closesocket(s);
        return INVALID_SOCKET;
    }

    printf("[net] listening on 0.0.0.0:%u\n", port);
    return s;
}

SOCKET net_accept(SOCKET server_sock) {
    struct sockaddr_in client_addr;
    int addr_len = sizeof(client_addr);

    SOCKET client = accept(server_sock,
                           (struct sockaddr *)&client_addr,
                           &addr_len);
    if (client == INVALID_SOCKET) {
        fprintf(stderr, "[net] accept() failed: %d\n", WSAGetLastError());
        return INVALID_SOCKET;
    }
    return client;
}

/* -- Client side ---------------------------------------------------------- */

SOCKET net_connect(const char *addr_str, uint16_t port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        fprintf(stderr, "[net] socket() failed: %d\n", WSAGetLastError());
        return INVALID_SOCKET;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    addr.sin_addr.s_addr = inet_addr(addr_str ? addr_str : LOCALHOST);

    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        fprintf(stderr, "[net] connect() to %s:%u failed: %d\n",
                addr_str ? addr_str : LOCALHOST, port, WSAGetLastError());
        closesocket(s);
        return INVALID_SOCKET;
    }

    return s;
}

/* -- Data transfer -------------------------------------------------------- */

int net_send_all(SOCKET s, const uint8_t *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = send(s, (const char *)buf + sent, (int)(len - sent), 0);
        if (n == SOCKET_ERROR || n == 0) {
            fprintf(stderr, "[net] send() failed: %d\n", WSAGetLastError());
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

int net_recv_all(SOCKET s, uint8_t *buf, size_t len) {
    size_t recvd = 0;
    while (recvd < len) {
        int n = recv(s, (char *)buf + recvd, (int)(len - recvd), 0);
        if (n == SOCKET_ERROR) {
            fprintf(stderr, "[net] recv() failed: %d\n", WSAGetLastError());
            return -1;
        }
        if (n == 0) {
            fprintf(stderr, "[net] connection closed by peer\n");
            return -1;
        }
        recvd += (size_t)n;
    }
    return 0;
}

/* -- Teardown ------------------------------------------------------------- */

void net_close(SOCKET s) {
    if (s != INVALID_SOCKET)
        closesocket(s);
}
