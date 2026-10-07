#include "net.h"
#include "config.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

/*, Init / cleanup ------------------------------------------------------- */

int net_init(void) {
    /* No global initialisation needed for POSIX sockets. */
    return 0;
}

void net_cleanup(void) {
    /* No-op on POSIX. */
}

/*, Internal helper ------------------------------------------------------ */

/* Disable Nagle's algorithm, same fix and same reasoning as the ASN
 * side (ASN/common/net.c), applied here too for a fair, apples-to-apples
 * comparison rather than leaving a stall bug on only one side of the
 * measurement. */
static void set_nodelay(SOCKET s) {
    int opt = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
}

/* Fill a sockaddr_in for 127.0.0.1:port, matches this header's own
 * documented contract (net_listen: "bind + listen on 127.0.0.1:port").
 * Previously bound INADDR_ANY (all interfaces) despite the doc comment
 * claiming loopback-only, the same mismatch already fixed on the ASN
 * side (ASN/common/net.c), missed here since this is a separate,
 * independently-duplicated copy for the TOR-equivalent baseline. */
static void make_addr(struct sockaddr_in *addr, uint16_t port) {
    memset(addr, 0, sizeof(*addr));
    addr->sin_family      = AF_INET;
    addr->sin_port        = htons(port);
    addr->sin_addr.s_addr = inet_addr(LOCALHOST);
}

/*, Server side ---------------------------------------------------------- */

SOCKET net_listen(uint16_t port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        fprintf(stderr, "[net] socket() failed: %s\n", strerror(errno));
        return INVALID_SOCKET;
    }

    /* Allow quick restart without waiting for TIME_WAIT */
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    make_addr(&addr, port);

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        fprintf(stderr, "[net] bind() on port %u failed: %s\n",
                port, strerror(errno));
        closesocket(s);
        return INVALID_SOCKET;
    }

    if (listen(s, BACKLOG) == SOCKET_ERROR) {
        fprintf(stderr, "[net] listen() failed: %s\n", strerror(errno));
        closesocket(s);
        return INVALID_SOCKET;
    }

    printf("[net] listening on 127.0.0.1:%u\n", port);
    return s;
}

SOCKET net_accept(SOCKET server_sock) {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    SOCKET client = accept(server_sock,
                           (struct sockaddr *)&client_addr,
                           &addr_len);
    if (client == INVALID_SOCKET) {
        fprintf(stderr, "[net] accept() failed: %s\n", strerror(errno));
        return INVALID_SOCKET;
    }
    set_nodelay(client);
    return client;
}

/*, Client side ---------------------------------------------------------- */

SOCKET net_connect(const char *addr_str, uint16_t port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        fprintf(stderr, "[net] socket() failed: %s\n", strerror(errno));
        return INVALID_SOCKET;
    }

    /* Prevent TIME_WAIT port exhaustion on rapid connect/close cycles */
    int reuse = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct linger ling = {1, 0};  /* hard close, no TIME_WAIT */
    setsockopt(s, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    if (inet_pton(AF_INET, addr_str ? addr_str : LOCALHOST, &addr.sin_addr) != 1) {
        fprintf(stderr, "[net] invalid address: %s\n",
                addr_str ? addr_str : LOCALHOST);
        closesocket(s);
        return INVALID_SOCKET;
    }
    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        fprintf(stderr, "[net] connect() to %s:%u failed: %s\n",
                addr_str ? addr_str : LOCALHOST, port, strerror(errno));
        closesocket(s);
        return INVALID_SOCKET;
    }
    set_nodelay(s);
    return s;
}

/*, Data transfer -------------------------------------------------------- */

int net_send_all(SOCKET s, const uint8_t *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(s, buf + sent, len - sent, 0);
        if (n == SOCKET_ERROR || n == 0) {
            fprintf(stderr, "[net] send() failed: %s\n", strerror(errno));
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

int net_recv_all(SOCKET s, uint8_t *buf, size_t len) {
    size_t recvd = 0;
    while (recvd < len) {
        ssize_t n = recv(s, buf + recvd, len - recvd, 0);
        if (n == SOCKET_ERROR) {
            fprintf(stderr, "[net] recv() failed: %s\n", strerror(errno));
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

/*, Teardown ------------------------------------------------------------- */

void net_close(SOCKET s) {
    if (s != INVALID_SOCKET)
        closesocket(s);
}
