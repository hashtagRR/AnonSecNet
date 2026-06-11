#ifndef NET_H
#define NET_H

/* IMPORTANT: winsock2.h must be included before windows.h.
 * Always include net.h before any other Windows headers.    */
#include <winsock2.h>
#include <stdint.h>
#include <stddef.h>

/* ── Initialisation ─────────────────────────────────────────────────────
 * Call net_init() once at process startup before any socket operations.
 * Call net_cleanup() before process exit.                               */
int  net_init(void);
void net_cleanup(void);

/* ── Server side ────────────────────────────────────────────────────────
 * net_listen: bind + listen on 127.0.0.1:port. Returns SOCKET or INVALID_SOCKET.
 * net_accept: blocking accept. Returns connected SOCKET or INVALID_SOCKET. */
SOCKET net_listen(uint16_t port);
SOCKET net_accept(SOCKET server_sock);

/* ── Client side ────────────────────────────────────────────────────────
 * net_connect: connect to 127.0.0.1:port. Returns SOCKET or INVALID_SOCKET. */
SOCKET net_connect(const char *addr, uint16_t port);

/* ── Data transfer ──────────────────────────────────────────────────────
 * Both functions loop internally until all bytes are sent/received
 * or an error occurs. They are NOT non-blocking.
 *
 * net_send_all: send exactly len bytes. Returns 0 on success, -1 on error.
 * net_recv_all: receive exactly len bytes. Returns 0 on success, -1 on error.
 *
 * Use these for all packet I/O — never call send()/recv() directly,
 * as they may transfer fewer bytes than requested.                      */
int net_send_all(SOCKET s, const uint8_t *buf, size_t len);
int net_recv_all(SOCKET s, uint8_t       *buf, size_t len);

/* ── Teardown ────────────────────────────────────────────────────────── */
void net_close(SOCKET s);

#endif /* NET_H */
