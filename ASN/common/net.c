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
#include <openssl/rand.h>

/*, Init / cleanup ------------------------------------------------------- */

int net_init(void) {
    /* No global initialisation needed for POSIX sockets. */
    return 0;
}

void net_cleanup(void) {
    /* No-op on POSIX. */
}

/*, Internal helper ------------------------------------------------------ */

/* Disable Nagle's algorithm. Without this, the many small handshake/relay
 * writes on this codebase's telescoped multi-hop connections (see
 * mix_node.c's proxy_bidirectional()) interact with
 * the peer's delayed-ACK timer and stall for tens of milliseconds per
 * hop: confirmed by measurement, not a hypothetical concern. */
static void set_nodelay(SOCKET s) {
    int opt = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
}

/* Fill a sockaddr_in for 127.0.0.1:port, matches this header's own
 * documented contract (net_listen: "bind + listen on 127.0.0.1:port")
 * and every actual net_connect() call site in this codebase, all of
 * which target LOCALHOST/derived-from-LOCALHOST addresses (this is a
 * single-host loopback testbed, not a multi-host deployment, see
 * anosecnet.tex's own "External validity" limitation). Previously bound
 * INADDR_ANY (all interfaces) despite the doc comment claiming
 * loopback-only, a real, previously undocumented mismatch between
 * net.h's contract and net.c's implementation: every server component
 * (mix_node, service_gateway, and especially the unauthenticated
 * cache_server) was reachable from any host that could route to its
 * port, not just localhost. */
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

/*, Padded control frames -------------------------------------------------
 *
 * Session-establishment (MODE_EXTEND-family) messages, the hop-0 EXTEND
 * request, the relayed per-hop EXTEND frame, and the signed-descriptor
 * reply: were all sent as their bare, variable-length structures
 * (69/70/up-to-211 bytes), unlike every steady-state MODE_DATA packet,
 * which is always exactly WIRE_PACKET_SIZE. That made path construction
 * trivially fingerprintable by size alone, independent of any timing
 * analysis: a passive observer sees a burst of small (<220-byte) frames,
 * then a switch to a sustained stream of exactly-1024-byte packets, and
 * that transition alone reveals "a new circuit is being built right now"
 * regardless of how well the steady-state traffic is disguised.
 *
 * These two functions give every EXTEND-family message the same
 * fixed-WIRE_PACKET_SIZE treatment MODE_DATA already has: a small
 * [len(2)][payload] header, then RAND_bytes (not zero) padding out to
 * WIRE_PACKET_SIZE: random padding for the same reason
 * packet.c's packet_sphinx_peel() uses it: a zero-run is itself a
 * distinguishable pattern, plaintext on the wire either way. Combined
 * with the existing 1-byte mode dispatch every message already sends
 * first (MODE_EXTEND/MODE_DATA/MODE_RETURN), a padded EXTEND message is
 * now byte-for-byte the same total size as a MODE_DATA message: 1 + 1024
 * bytes, either way. */
#define PADDED_FRAME_LEN_BYTES 2

int net_send_padded_frame(SOCKET s, const uint8_t *payload, size_t payload_len) {
    if (payload_len > WIRE_PACKET_SIZE - PADDED_FRAME_LEN_BYTES) {
        fprintf(stderr, "[net] send_padded_frame: payload too large\n");
        return -1;
    }
    uint8_t buf[WIRE_PACKET_SIZE];
    if (RAND_bytes(buf, WIRE_PACKET_SIZE) != 1) {
        fprintf(stderr, "[net] send_padded_frame: random padding failed\n");
        return -1;
    }
    buf[0] = (uint8_t)(payload_len >> 8);
    buf[1] = (uint8_t)(payload_len & 0xFF);
    if (payload_len > 0) memcpy(buf + PADDED_FRAME_LEN_BYTES, payload, payload_len);
    return net_send_all(s, buf, WIRE_PACKET_SIZE);
}

int net_recv_padded_frame(SOCKET s, uint8_t *payload, size_t *out_len, size_t max_len) {
    uint8_t buf[WIRE_PACKET_SIZE];
    if (net_recv_all(s, buf, WIRE_PACKET_SIZE) != 0) return -1;
    size_t len = ((size_t)buf[0] << 8) | (size_t)buf[1];
    if (len > max_len || len > WIRE_PACKET_SIZE - PADDED_FRAME_LEN_BYTES) {
        fprintf(stderr, "[net] recv_padded_frame: bad length\n");
        return -1;
    }
    if (len > 0) memcpy(payload, buf + PADDED_FRAME_LEN_BYTES, len);
    *out_len = len;
    return 0;
}

/*, Teardown ------------------------------------------------------------- */

void net_close(SOCKET s) {
    if (s != INVALID_SOCKET)
        closesocket(s);
}
