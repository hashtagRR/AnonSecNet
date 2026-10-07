/* cache_server.c: Cache Server (:9012), Anon-Sec-Net v2
 * In-memory key-value store. Identical protocol to v1.
 *
 * KNOWN LIMITATION: this server has no application-layer authentication
 * of its own. net.c's make_addr() binds loopback instead of INADDR_ANY,
 * so it is not reachable by any host that could route to the port, but
 * any process with local access can still GET/PUT arbitrary keys with no
 * credential check. Not fixed here: doing so would mean changing the
 * wire protocol (type/klen/key/dlen/data below) across every caller,
 * service_gateway.c, service_gateway_instrumented.c, and
 * scripts/seed_cache.py: all of which are the exact code paths behind
 * this project's benchmark numbers, and that is a real design decision
 * (which auth scheme, whose threat model) rather than a drop-in fix.
 * Flagged as a stated limitation, not silently fixed.
 */

#include "common/net.h"
#include "common/config.h"
#include "common/crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common/posix_compat.h"

/* TYPE_GET, TYPE_PUT, TYPE_HANDSHAKE_INIT, TYPE_HANDSHAKE_POLL,
 * TYPE_HEARTBEAT, and TYPE_HANDSHAKE_RESPOND are all defined in
 * common/config.h. CS never needs to understand the handshake types'
 * semantics: it stays a content-agnostic opaque store/relay for
 * GET/PUT, same as before, and these four new types add a SEPARATE
 * relay function (pending-handshake bookkeeping) that never touches
 * stored content. Wire framing deliberately reuses the EXISTING
 * type/klen/key/dlen/data shape unchanged for all of them
 * (handle_connection()'s read logic below is untouched),
 * distinguished only by type and by what's packed into data. */
#define MAX_KEY_LEN     64
#define MAX_CONTENT_LEN (MAX_INNER_PAYLOAD - 4)
#define MAX_ENTRIES     256
#define MAX_PENDING     64
#define MAX_ENC_K_CONTENT 96 /* AES_KEY_LEN(32) + GCM_OVERHEAD(28), generous */
/* s_ephemeral_pub(65) + enc_len(2) + enc_k_content(<=96) + sig_len(1) +
 * sig(<=SIGNATURE_MAX_LEN(80)) = 244 worst case; rounded up for margin. */
#define MAX_RESP_DATA   256

static void log_msg(const char *m) { printf("[Cache] %s\n", m); fflush(stdout); }
static void log_err(const char *m) { fprintf(stderr, "[Cache] ERROR: %s\n", m); fflush(stderr); }

typedef struct {
    char    key[MAX_KEY_LEN + 1];
    uint8_t content[MAX_CONTENT_LEN];
    size_t  content_len;
} cache_entry_t;

static cache_entry_t    g_store[MAX_ENTRIES];
static int              g_count = 0;
static CRITICAL_SECTION g_lock;

static cache_entry_t *store_find(const char *key) {
    for (int i = 0; i < g_count; i++)
        if (strcmp(g_store[i].key, key) == 0)
            return &g_store[i];
    return NULL;
}

/* Pending per-request Sender<->Receiver ECDHE handshake state. One
 * entry per wire key, matched by plain strcmp, the wire key for a
 * handshake request isn't necessarily the plain content key. Each
 * Receiver suffixes its own per-request nonce onto the wire key it uses
 * for INIT/POLL (e.g. "mykey#a1b2"), so concurrent requests for the
 * same content land in different slots by construction, CS itself
 * stays a dumb opaque string-keyed table, unaware content keys and wire
 * keys can differ. sender.c's heartbeat_thread() strips the suffix back
 * off before doing its own content-key lookup, and echoes the untouched
 * wire key back on RESPOND so it still matches here. */
typedef struct {
    char    key[MAX_KEY_LEN + 1];
    uint8_t r_ephemeral_pub[EC_PUBKEY_LEN];
    int     ready;
    /* Stored fully opaquely, CS never parses s_ephemeral_pub/
     * enc_k_content individually (pure relay); the Sender's response
     * (including an identity signature over s_ephemeral_pub||
     * enc_k_content, letting the Receiver detect a spoofed
     * TYPE_HANDSHAKE_RESPOND against any pin it already holds, see
     * client.c's perform_content_handshake()) is carried as one opaque
     * blob, same as PUT's content. */
    uint8_t resp_data[MAX_RESP_DATA];
    size_t  resp_data_len;
    int     in_use;
    /* created_ms lets a stale slot (older than PENDING_TTL_MS,
     * regardless of ready/in_use) be reclaimed for a new key, the
     * backstop for a slot whose Receiver never comes back to poll it
     * (gave up, crashed, or the response was lost in transit). The
     * common case, a Receiver that successfully polls its ready
     * response, clears in_use immediately at the TYPE_HANDSHAKE_POLL
     * site instead of waiting out the full TTL. */
    DWORD   created_ms;
} pending_handshake_t;

/* Generous relative to the Receiver's own poll timeout (20 tries x
 * 500ms = 10s, client.c's HANDSHAKE_POLL_MAX_TRIES/INTERVAL_MS) and
 * the Sender's 500ms heartbeat cycle, reclaims abandoned entries
 * well after any legitimate in-flight handshake would have finished,
 * never a live one. */
#define PENDING_TTL_MS 30000

static pending_handshake_t g_pending[MAX_PENDING];
static CRITICAL_SECTION    g_pending_lock;

static pending_handshake_t *pending_find(const char *key) {
    for (int i = 0; i < MAX_PENDING; i++)
        if (g_pending[i].in_use && strcmp(g_pending[i].key, key) == 0)
            return &g_pending[i];
    return NULL;
}

static int store_put(const char *key, const uint8_t *data, size_t len) {
    EnterCriticalSection(&g_lock);
    cache_entry_t *e = store_find(key);
    if (e) {
        memcpy(e->content, data, len);
        e->content_len = len;
        LeaveCriticalSection(&g_lock);
        return 0;
    }
    if (g_count >= MAX_ENTRIES) {
        LeaveCriticalSection(&g_lock);
        return -1;
    }
    e = &g_store[g_count++];
    strncpy(e->key, key, MAX_KEY_LEN);
    e->key[MAX_KEY_LEN] = '\0';
    memcpy(e->content, data, len);
    e->content_len = len;
    LeaveCriticalSection(&g_lock);
    return 0;
}

typedef struct { SOCKET s; } conn_ctx_t;

static DWORD WINAPI handle_connection(LPVOID arg) {
    conn_ctx_t *ctx = (conn_ctx_t *)arg;
    SOCKET sock = ctx->s; free(ctx);

    uint8_t type = 0;
    if (net_recv_all(sock, &type, 1) != 0) { log_err("read type"); goto done; }

    uint8_t klen = 0;
    if (net_recv_all(sock, &klen, 1) != 0) { log_err("read klen"); goto done; }
    if (klen == 0 || klen > MAX_KEY_LEN) { log_err("bad klen"); goto done; }

    char key[MAX_KEY_LEN + 1] = {0};
    if (net_recv_all(sock, (uint8_t *)key, klen) != 0) { log_err("read key"); goto done; }
    key[klen] = '\0';

    uint8_t dlen_b[2];
    if (net_recv_all(sock, dlen_b, 2) != 0) { log_err("read dlen"); goto done; }
    uint16_t dlen = (uint16_t)((dlen_b[0] << 8) | dlen_b[1]);

    uint8_t data[MAX_CONTENT_LEN];
    memset(data, 0, sizeof(data));
    if (dlen > 0) {
        if (dlen > MAX_CONTENT_LEN) { log_err("data too large"); goto done; }
        if (net_recv_all(sock, data, dlen) != 0) { log_err("read data"); goto done; }
    }

    if (type == TYPE_PUT) {
        char logbuf[128];
        snprintf(logbuf, sizeof(logbuf), "PUT key='%s' len=%u", key, dlen);
        log_msg(logbuf);
        int rc = store_put(key, data, dlen);
        uint8_t ack[3] = { 0, 1, (rc == 0) ? 0x01 : 0x00 };
        net_send_all(sock, ack, 3);

    } else if (type == TYPE_GET) {
        char logbuf[128];
        snprintf(logbuf, sizeof(logbuf), "GET key='%s'", key);
        log_msg(logbuf);

        EnterCriticalSection(&g_lock);
        cache_entry_t *e = store_find(key);
        if (!e) {
            LeaveCriticalSection(&g_lock);
            uint8_t resp[2] = {0, 0};
            net_send_all(sock, resp, 2);
            goto done;
        }
        uint16_t rlen = (uint16_t)e->content_len;
        uint8_t  rbuf[MAX_CONTENT_LEN];
        memcpy(rbuf, e->content, rlen);
        LeaveCriticalSection(&g_lock);

        uint8_t rlen_b[2] = { (uint8_t)(rlen >> 8), (uint8_t)(rlen & 0xFF) };
        net_send_all(sock, rlen_b, 2);
        net_send_all(sock, rbuf,   rlen);

    } else if (type == TYPE_HANDSHAKE_INIT) {
        /* R: register/refresh a pending handshake request for `key`,
         * carrying R's fresh ephemeral ECDH pubkey in `data`. */
        char logbuf[96];
        snprintf(logbuf, sizeof(logbuf), "HANDSHAKE_INIT key='%s'", key);
        log_msg(logbuf);
        int ok = (dlen == EC_PUBKEY_LEN);
        if (ok) {
            EnterCriticalSection(&g_pending_lock);
            pending_handshake_t *p = pending_find(key);
            if (!p) {
                DWORD now = GetTickCount();
                for (int i = 0; i < MAX_PENDING; i++) {
                    /* Reclaim a free slot or one stale beyond
                     * PENDING_TTL_MS, not just a never-used one. */
                    if (!g_pending[i].in_use ||
                        (now - g_pending[i].created_ms) > PENDING_TTL_MS) {
                        p = &g_pending[i]; break;
                    }
                }
            }
            if (!p) {
                ok = 0; /* table full, every slot in_use and still fresh */
            } else {
                strncpy(p->key, key, MAX_KEY_LEN); p->key[MAX_KEY_LEN] = '\0';
                memcpy(p->r_ephemeral_pub, data, EC_PUBKEY_LEN);
                p->ready = 0;
                p->in_use = 1;
                p->created_ms = GetTickCount();
            }
            LeaveCriticalSection(&g_pending_lock);
        }
        uint8_t ack[3] = { 0, 1, ok ? 0x01 : 0x00 };
        net_send_all(sock, ack, 3);

    } else if (type == TYPE_HANDSHAKE_POLL) {
        /* R: "is a Sender response ready for this key's pending
         * handshake yet?", same [rlen(2)][data(rlen)] response shape
         * as GET, so relaying code needs no new framing logic. `key`
         * here is R's own composite wire key (content key + per-request
         * nonce suffix, see the pending_handshake_t struct comment
         * above), already unique per requester, so no extra data is
         * needed to disambiguate concurrent pollers. */
        char logbuf[96];
        snprintf(logbuf, sizeof(logbuf), "HANDSHAKE_POLL key='%s'", key);
        log_msg(logbuf);

        EnterCriticalSection(&g_pending_lock);
        pending_handshake_t *p = pending_find(key);
        uint8_t rbuf[1 + MAX_RESP_DATA];
        uint16_t rlen;
        if (!p || !p->ready) {
            rbuf[0] = 0x00;
            rlen = 1;
        } else {
            rbuf[0] = 0x01;
            memcpy(rbuf + 1, p->resp_data, p->resp_data_len);
            rlen = (uint16_t)(1 + p->resp_data_len);
            /* Free this slot immediately rather than waiting out the
             * TTL: this wire key is single-use by construction (each
             * perform_content_handshake() call mints a fresh
             * nonce-suffixed key, see client.c's comment on wire_key),
             * so once its ready response has been handed back to the
             * one Receiver that will ever ask for it, nothing legitimate
             * polls this slot again. */
            p->in_use = 0;
        }
        LeaveCriticalSection(&g_pending_lock);

        uint8_t rlen_b[2] = { (uint8_t)(rlen >> 8), (uint8_t)(rlen & 0xFF) };
        net_send_all(sock, rlen_b, 2);
        net_send_all(sock, rbuf,   rlen);

    } else if (type == TYPE_HEARTBEAT) {
        /* S: "list every pending (not-yet-ready) handshake request, so
         * I can locally check which ones are for keys I own." `key`
         * itself is an unused dummy (klen>=1 enforced above). Response:
         * [count(1)][per-entry: klen(1)][key][r_ephemeral_pub(65)]...,
         * wrapped in the same [rlen(2)][data(rlen)] shape as GET/POLL. */
        log_msg("HEARTBEAT");
        uint8_t rbuf[MAX_INNER_PAYLOAD];
        size_t  off2 = 1; /* reserve rbuf[0] for count */
        uint8_t count = 0;

        EnterCriticalSection(&g_pending_lock);
        for (int i = 0; i < MAX_PENDING && count < 255; i++) {
            if (!g_pending[i].in_use || g_pending[i].ready) continue;
            size_t klen2 = strlen(g_pending[i].key);
            size_t need = 1 + klen2 + EC_PUBKEY_LEN;
            if (off2 + need > sizeof(rbuf)) break; /* out of room this round */
            rbuf[off2++] = (uint8_t)klen2;
            memcpy(rbuf + off2, g_pending[i].key, klen2); off2 += klen2;
            memcpy(rbuf + off2, g_pending[i].r_ephemeral_pub, EC_PUBKEY_LEN); off2 += EC_PUBKEY_LEN;
            count++;
        }
        LeaveCriticalSection(&g_pending_lock);
        rbuf[0] = count;

        uint16_t rlen = (uint16_t)off2;
        uint8_t rlen_b[2] = { (uint8_t)(rlen >> 8), (uint8_t)(rlen & 0xFF) };
        net_send_all(sock, rlen_b, 2);
        net_send_all(sock, rbuf,   rlen);

    } else if (type == TYPE_HANDSHAKE_RESPOND) {
        /* S: deliver its ephemeral pubkey + K_content encrypted under
         * the just-derived K_session, plus an identity signature over
         * that pair, for a specific key's pending request. data =
         * s_ephemeral_pub(65) + enc_len(2) + enc_k_content + sig_len(1)
         * + sig, stored and relayed fully opaquely; only the Receiver
         * (client.c) parses/verifies it, against a pin it may already
         * hold for this key. `key` here is the composite wire key
         * sender.c echoed back verbatim from HEARTBEAT (see the
         * pending_handshake_t struct comment above), already routes
         * to the correct requester's slot with plain strcmp. */
        char logbuf[96];
        snprintf(logbuf, sizeof(logbuf), "HANDSHAKE_RESPOND key='%s'", key);
        log_msg(logbuf);
        int ok = 0;
        if (dlen >= EC_PUBKEY_LEN + 2 && dlen <= MAX_RESP_DATA) {
            EnterCriticalSection(&g_pending_lock);
            pending_handshake_t *p = pending_find(key);
            if (p) {
                memcpy(p->resp_data, data, dlen);
                p->resp_data_len = dlen;
                p->ready = 1;
                ok = 1;
            }
            LeaveCriticalSection(&g_pending_lock);
        }
        uint8_t ack[3] = { 0, 1, ok ? 0x01 : 0x00 };
        net_send_all(sock, ack, 3);
    }

done:
    net_close(sock); return 0;
}

int main(void) {
    SetConsoleOutputCP(65001);
    if (net_init() != 0) return 1;
    InitializeCriticalSection(&g_lock);
    InitializeCriticalSection(&g_pending_lock);

    SOCKET srv = net_listen(PORT_CACHE_SERVER);
    if (srv == INVALID_SOCKET) { net_cleanup(); return 1; }
    log_msg("ready, in-memory store initialised");

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
    DeleteCriticalSection(&g_lock);
    net_close(srv); net_cleanup(); return 0;
}
