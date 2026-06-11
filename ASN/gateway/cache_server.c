/* cache_server.c  —  Cache Server  (:9012)  —  Anon-Sec-Net v2
 * In-memory key-value store. Identical protocol to v1.
 */

#include "common/net.h"
#include "common/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define TYPE_GET        0x01
#define TYPE_PUT        0x02
#define MAX_KEY_LEN     64
#define MAX_CONTENT_LEN (MAX_INNER_PAYLOAD - 4)
#define MAX_ENTRIES     256

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
    }

done:
    net_close(sock); return 0;
}

int main(void) {
    SetConsoleOutputCP(65001);
    if (net_init() != 0) return 1;
    InitializeCriticalSection(&g_lock);

    SOCKET srv = net_listen(PORT_CACHE_SERVER);
    if (srv == INVALID_SOCKET) { net_cleanup(); return 1; }
    log_msg("ready — in-memory store initialised");

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
