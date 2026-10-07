#ifndef NET_H
#define NET_H

/* POSIX sockets port (originally Winsock2). */
#include "posix_compat.h"   /* SOCKET, INVALID_SOCKET, closesocket() */
#include <stdint.h>
#include <stddef.h>

/* Initialisation
 * Call net_init() once at process startup before any socket operations.
 * Call net_cleanup() before process exit.                               */
int  net_init(void);
void net_cleanup(void);

/* Server side
 * net_listen: bind + listen on 127.0.0.1:port. Returns SOCKET or INVALID_SOCKET.
 * net_accept: blocking accept. Returns connected SOCKET or INVALID_SOCKET. */
SOCKET net_listen(uint16_t port);
SOCKET net_accept(SOCKET server_sock);

/* Client side
 * net_connect: connect to 127.0.0.1:port. Returns SOCKET or INVALID_SOCKET. */
SOCKET net_connect(const char *addr, uint16_t port);

/* Data transfer
 * Both functions loop internally until all bytes are sent/received
 * or an error occurs. They are NOT non-blocking.
 *
 * net_send_all: send exactly len bytes. Returns 0 on success, -1 on error.
 * net_recv_all: receive exactly len bytes. Returns 0 on success, -1 on error.
 *
 * Use these for all packet I/O, never call send()/recv() directly,
 * as they may transfer fewer bytes than requested.                      */
int net_send_all(SOCKET s, const uint8_t *buf, size_t len);
int net_recv_all(SOCKET s, uint8_t       *buf, size_t len);

/* Padded control frames (session-establishment / MODE_EXTEND-family
 * messages): fixed WIRE_PACKET_SIZE on the wire, [len(2)][payload][random
 * padding], so path construction is not distinguishable by packet size
 * from steady-state MODE_DATA traffic. See net.c for the full rationale.
 *
 * net_send_padded_frame: payload_len must be <= WIRE_PACKET_SIZE-2.
 *   Returns 0 on success, -1 on error.
 * net_recv_padded_frame: reads exactly WIRE_PACKET_SIZE bytes, writes the
 *   real payload (up to max_len bytes) to `payload` and its length to
 *   *out_len. Returns 0 on success, -1 on error (including a length
 *   field that exceeds max_len, caller-supplied buffer is never
 *   overrun). */
int net_send_padded_frame(SOCKET s, const uint8_t *payload, size_t payload_len);
int net_recv_padded_frame(SOCKET s, uint8_t *payload, size_t *out_len, size_t max_len);

/* Teardown */
void net_close(SOCKET s);

#endif /* NET_H */
