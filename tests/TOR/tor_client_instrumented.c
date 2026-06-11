/* tor_client_instrumented.c  --  Tor-Equivalent Instrumented Client (v4)
 *
 * Mirrors ASN client_instrumented.c architecture exactly:
 *   - 4 crypto worker threads pre-build cells into a ring buffer
 *   - Poisson-timed send thread pops from queue and sends (no inline crypto)
 *   - SET_RATE 1.0 -> every slot sends a real cell
 *   - Payload sized to produce ~1024 byte wire cells (matches ASN WIRE_PACKET_SIZE)
 *   - C11 atomics for shared state
 *   - Per-PID debug log
 *
 * Build:
 *   gcc -O2 -std=c11 -o tor_client_instrumented.exe tor_client_instrumented.c \
 *       common/crypto.c common/net.c -lssl -lcrypto -lws2_32
 */

#include "common/net.h"
#include "common/crypto.h"
#include "tor_config.h"

#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdatomic.h>
#include <windows.h>
#include <ws2tcpip.h>

/* ---- Per-hop session keys ------------------------------------------------ */
typedef struct {
    aes_key_t key;
    uint8_t   hint[TOR_HINT_BYTES];
} hop_key_t;

static hop_key_t g_hops[TOR_MAX_HOPS];

/* ---- Shared state (C11 atomics, matches ASN) ----------------------------- */
static atomic_int    g_running       = 1;
static atomic_int    g_send_active   = 0;
static atomic_int    g_circuit_ready = 0;
static atomic_long   g_cells_sent    = 0;
static atomic_long   g_send_errors   = 0;
static atomic_long   g_build_errors  = 0;
static atomic_long   g_slots_total   = 0;
static atomic_long   g_queue_empty   = 0;

/* ---- Timing -------------------------------------------------------------- */
static double qpc_freq = 0.0;

static double time_now_ms(void) {
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart / qpc_freq * 1000.0;
}

/* ---- Poisson interval (identical to ASN client) -------------------------- */
#define SEND_INTERVAL_MS  100

static DWORD poisson_interval_ms(void) {
    double u = (rand() + 1.0) / (RAND_MAX + 2.0);
    double interval = -(double)SEND_INTERVAL_MS * log(u);
    if (interval < 10.0)   interval = 10.0;
    if (interval > 1000.0) interval = 1000.0;
    return (DWORD)interval;
}

/* ---- Debug log (per-PID file) -------------------------------------------- */
static char g_debug_path[64];

static void debug_init(void) {
    DWORD pid = GetCurrentProcessId();
    snprintf(g_debug_path, sizeof(g_debug_path),
             "tor_client_%lu.log", (unsigned long)pid);
}

static void debug_log(const char *msg) {
    FILE *fp = fopen(g_debug_path, "a");
    if (!fp) return;
    fprintf(fp, "[%.0f] %s\n", time_now_ms(), msg);
    fclose(fp);
}

/* ---- Extend to a single node --------------------------------------------- */
static int extend_to_node(uint16_t node_port, ecdh_keypair_t *eph,
                           aes_key_t *out_key,
                           uint8_t out_hint[TOR_HINT_BYTES]) {
    SOCKET s = net_connect(TOR_LOCALHOST, node_port);
    if (s == INVALID_SOCKET) return -1;

    uint8_t mode = TOR_MODE_EXTEND;
    net_send_all(s, &mode, 1);

    uint8_t tport[2] = {0, 0};
    net_send_all(s, tport, 2);
    net_send_all(s, eph->pubkey_bytes, EC_PUBKEY_LEN);

    uint8_t node_pub[EC_PUBKEY_LEN];
    if (net_recv_all(s, node_pub, EC_PUBKEY_LEN) != 0) {
        net_close(s); return -1;
    }
    net_close(s);

    if (crypto_ecdh_derive(eph, node_pub, out_key) != 0) return -1;
    memcpy(out_hint, eph->pubkey_bytes + 1, TOR_HINT_BYTES);
    return 0;
}

/* ---- Build circuit ------------------------------------------------------- */
static int build_circuit(void) {
    static const uint16_t ports[TOR_MAX_HOPS] = {
        TOR_PORT_TN1, TOR_PORT_TN2, TOR_PORT_TN3
    };

    for (int hop = 0; hop < TOR_MAX_HOPS; hop++) {
        ecdh_keypair_t eph = {0};
        if (crypto_ecdh_keygen(&eph) != 0) return -1;

        if (extend_to_node(ports[hop], &eph,
                            &g_hops[hop].key,
                            g_hops[hop].hint) != 0) {
            crypto_ecdh_free(&eph);
            return -1;
        }
        crypto_ecdh_free(&eph);
    }
    return 0;
}

/* ---- Layered encryption (forward cell) ----------------------------------- */
static int build_forward_cell(const uint8_t *payload, int payload_len,
                               uint8_t *out, int out_size) {
    /* Layer 3: innermost */
    int l3_pt_len = 2 + payload_len;
    uint8_t *l3_pt = malloc(l3_pt_len);
    if (!l3_pt) return -1;
    l3_pt[0] = (uint8_t)(TOR_PORT_SG >> 8);
    l3_pt[1] = (uint8_t)(TOR_PORT_SG & 0xFF);
    memcpy(l3_pt + 2, payload, payload_len);

    int l3_enc_size = l3_pt_len + GCM_OVERHEAD;
    uint8_t *l3_enc = malloc(l3_enc_size);
    if (!l3_enc) { free(l3_pt); return -1; }
    int l3_len = crypto_aes_encrypt(&g_hops[2].key, l3_pt, l3_pt_len,
                                     l3_enc, l3_enc_size);
    free(l3_pt);
    if (l3_len < 0) { free(l3_enc); return -1; }

    /* Layer 2 */
    int l2_pt_len = 2 + TOR_HINT_BYTES + l3_len;
    uint8_t *l2_pt = malloc(l2_pt_len);
    if (!l2_pt) { free(l3_enc); return -1; }
    l2_pt[0] = (uint8_t)(TOR_PORT_TN3 >> 8);
    l2_pt[1] = (uint8_t)(TOR_PORT_TN3 & 0xFF);
    memcpy(l2_pt + 2, g_hops[2].hint, TOR_HINT_BYTES);
    memcpy(l2_pt + 2 + TOR_HINT_BYTES, l3_enc, l3_len);
    free(l3_enc);

    int l2_enc_size = l2_pt_len + GCM_OVERHEAD;
    uint8_t *l2_enc = malloc(l2_enc_size);
    if (!l2_enc) { free(l2_pt); return -1; }
    int l2_len = crypto_aes_encrypt(&g_hops[1].key, l2_pt, l2_pt_len,
                                     l2_enc, l2_enc_size);
    free(l2_pt);
    if (l2_len < 0) { free(l2_enc); return -1; }

    /* Layer 1 */
    int l1_pt_len = 2 + TOR_HINT_BYTES + l2_len;
    uint8_t *l1_pt = malloc(l1_pt_len);
    if (!l1_pt) { free(l2_enc); return -1; }
    l1_pt[0] = (uint8_t)(TOR_PORT_TN2 >> 8);
    l1_pt[1] = (uint8_t)(TOR_PORT_TN2 & 0xFF);
    memcpy(l1_pt + 2, g_hops[1].hint, TOR_HINT_BYTES);
    memcpy(l1_pt + 2 + TOR_HINT_BYTES, l2_enc, l2_len);
    free(l2_enc);

    int l1_enc_size = l1_pt_len + GCM_OVERHEAD;
    uint8_t *l1_enc = malloc(l1_enc_size);
    if (!l1_enc) { free(l1_pt); return -1; }
    int l1_len = crypto_aes_encrypt(&g_hops[0].key, l1_pt, l1_pt_len,
                                     l1_enc, l1_enc_size);
    free(l1_pt);
    if (l1_len < 0) { free(l1_enc); return -1; }

    int wire_len = TOR_HINT_BYTES + 2 + l1_len;
    if (wire_len > out_size) { free(l1_enc); return -1; }

    memcpy(out, g_hops[0].hint, TOR_HINT_BYTES);
    out[TOR_HINT_BYTES]     = (uint8_t)(l1_len >> 8);
    out[TOR_HINT_BYTES + 1] = (uint8_t)(l1_len & 0xFF);
    memcpy(out + TOR_HINT_BYTES + 2, l1_enc, l1_len);
    free(l1_enc);

    return wire_len;
}

/* ---- Pre-built cell queue (matches ASN pkt_queue_t, depth 64) ----------- */
#define CELL_QUEUE_DEPTH 64

typedef struct {
    uint8_t data[TOR_MAX_CELL_SIZE + 256];
    int     len;
} cell_buf_t;

typedef struct {
    cell_buf_t buf[CELL_QUEUE_DEPTH];
    int        head;
    int        tail;
} cell_queue_t;

static cell_queue_t     g_cell_q = {0};
static CRITICAL_SECTION g_cell_lock;

static int cq_free(const cell_queue_t *q) {
    int used = (q->head - q->tail + CELL_QUEUE_DEPTH) % CELL_QUEUE_DEPTH;
    return (CELL_QUEUE_DEPTH - 1) - used;
}

static int cq_push(cell_queue_t *q, const cell_buf_t *c) {
    int next = (q->head + 1) % CELL_QUEUE_DEPTH;
    if (next == q->tail) return -1;
    q->buf[q->head] = *c;
    q->head = next;
    return 0;
}

static int cq_pop(cell_queue_t *q, cell_buf_t *out) {
    if (q->tail == q->head) return -1;
    *out = q->buf[q->tail];
    q->tail = (q->tail + 1) % CELL_QUEUE_DEPTH;
    return 0;
}

/* ---- Crypto worker threads (matches ASN's 4 workers) -------------------- */
/* Use a payload size that produces wire cells close to ASN's 1024-byte
 * WIRE_PACKET_SIZE. With 3 layers of GCM overhead (28 bytes each) plus
 * hint (16B) and port (2B) per layer, plus outer hint+len:
 *   payload P -> layer3: 2+P+28 -> layer2: 2+16+(2+P+28)+28 -> ...
 * To reach ~1024 wire: P ~= 886 bytes (TOR_MAX_PAYLOAD from tor_config.h) */
#define BENCH_PAYLOAD_SIZE  TOR_MAX_PAYLOAD   /* 886 bytes */

static DWORD WINAPI crypto_thread(LPVOID arg) {
    (void)arg;
    uint8_t payload[BENCH_PAYLOAD_SIZE];
    RAND_bytes(payload, sizeof(payload));

    while (atomic_load(&g_running)) {
        if (!atomic_load(&g_circuit_ready)) { Sleep(5); continue; }

        EnterCriticalSection(&g_cell_lock);
        int nfree = cq_free(&g_cell_q);
        LeaveCriticalSection(&g_cell_lock);

        if (nfree == 0) { Sleep(1); continue; }

        cell_buf_t cell = {0};
        cell.len = build_forward_cell(payload, sizeof(payload),
                                       cell.data, sizeof(cell.data));
        if (cell.len > 0) {
            EnterCriticalSection(&g_cell_lock);
            cq_push(&g_cell_q, &cell);
            LeaveCriticalSection(&g_cell_lock);
        } else {
            atomic_fetch_add(&g_build_errors, 1);
            Sleep(5);
        }
    }
    return 0;
}

/* ---- Poisson send thread (matches ASN outbound_cover_thread) ------------ */
static DWORD WINAPI send_thread(LPVOID arg) {
    (void)arg;
    srand((unsigned)GetTickCount() ^ (unsigned)GetCurrentProcessId());

    while (atomic_load(&g_running)) {
        Sleep(poisson_interval_ms());
        if (!atomic_load(&g_circuit_ready)) continue;

        atomic_fetch_add(&g_slots_total, 1);

        /* At SET_RATE 1.0 every slot sends. At 0.0 nothing sends.
         * Tor has no cover traffic -- idle slots are silent. */
        if (!atomic_load(&g_send_active)) continue;

        /* Pop pre-built cell from queue (retry up to 50ms like ASN) */
        cell_buf_t cell = {0};
        int got = 0;
        for (int i = 0; i < 50; i++) {
            EnterCriticalSection(&g_cell_lock);
            got = (cq_pop(&g_cell_q, &cell) == 0);
            LeaveCriticalSection(&g_cell_lock);
            if (got) break;
            Sleep(1);
        }
        if (!got) {
            atomic_fetch_add(&g_queue_empty, 1);
            continue;
        }

        /* Send to TN1 */
        SOCKET s = net_connect(TOR_LOCALHOST, TOR_PORT_TN1);
        if (s == INVALID_SOCKET) {
            atomic_fetch_add(&g_send_errors, 1);
            continue;
        }

        int nd = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY,
                   (const char *)&nd, sizeof(nd));

        uint8_t mode = TOR_MODE_DATA;
        int ok = (net_send_all(s, &mode, 1) == 0) &&
                 (net_send_all(s, cell.data, cell.len) == 0);

        if (ok) {
            /* Half-close to flush data before linger-0 RST */
            shutdown(s, SD_SEND);
            atomic_fetch_add(&g_cells_sent, 1);
        } else {
            atomic_fetch_add(&g_send_errors, 1);
        }
        net_close(s);
    }
    return 0;
}

/* ---- Debug stats (every 5s) --------------------------------------------- */
static DWORD WINAPI debug_stats(LPVOID arg) {
    (void)arg;
    while (atomic_load(&g_running)) {
        Sleep(5000);
        char buf[200];
        snprintf(buf, sizeof(buf),
                 "STATS: active=%d slots=%ld sent=%ld "
                 "send_err=%ld build_err=%ld qempty=%ld",
                 atomic_load(&g_send_active),
                 atomic_load(&g_slots_total),
                 atomic_load(&g_cells_sent),
                 atomic_load(&g_send_errors),
                 atomic_load(&g_build_errors),
                 atomic_load(&g_queue_empty));
        debug_log(buf);
    }
    return 0;
}

/* ---- Response listener (best-effort) ------------------------------------ */
static DWORD WINAPI response_listener(LPVOID arg) {
    (void)arg;
    SOCKET server = net_listen(TOR_PORT_CLIENT);
    if (server == INVALID_SOCKET) return 1;

    while (atomic_load(&g_running)) {
        SOCKET s = net_accept(server);
        if (s == INVALID_SOCKET) continue;
        uint8_t drain[2048];
        while (recv(s, (char *)drain, sizeof(drain), 0) > 0) ;
        net_close(s);
    }
    net_close(server);
    return 0;
}

/* ---- main --------------------------------------------------------------- */
int main(void) {
    SetConsoleOutputCP(65001);
    InitializeCriticalSection(&g_cell_lock);
    if (net_init() != 0) return 1;

    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    qpc_freq = (double)freq.QuadPart;

    debug_init();
    debug_log("client starting");

    HANDLE rl = CreateThread(NULL, 0, response_listener, NULL, 0, NULL);
    if (rl) CloseHandle(rl);
    Sleep(50);

    /* Build circuit */
    double t0 = time_now_ms();
    if (build_circuit() != 0) {
        debug_log("circuit build FAILED");
        net_cleanup(); return 1;
    }
    double t1 = time_now_ms();

    FILE *fp = fopen("tor_session_setup.csv", "a");
    if (fp) { fprintf(fp, "%.3f\n", t1 - t0); fclose(fp); }

    char tbuf[80];
    snprintf(tbuf, sizeof(tbuf), "circuit built in %.3f ms", t1 - t0);
    debug_log(tbuf);

    atomic_store(&g_circuit_ready, 1);

    /* Start 4 crypto workers (matches ASN) to keep queue stocked */
    for (int i = 0; i < 4; i++) {
        HANDLE ct = CreateThread(NULL, 0, crypto_thread, NULL, 0, NULL);
        if (ct) CloseHandle(ct);
    }

    /* Let queue fill before starting send thread */
    Sleep(500);

    /* Start send thread */
    HANDLE st = CreateThread(NULL, 0, send_thread, NULL, 0, NULL);
    if (st) CloseHandle(st);

    /* Start debug stats */
    HANDLE dt = CreateThread(NULL, 0, debug_stats, NULL, 0, NULL);
    if (dt) CloseHandle(dt);

    debug_log("ready for SET_RATE");

    /* stdin command loop */
    char line[256];
    while (atomic_load(&g_running) && fgets(line, sizeof(line), stdin)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        if (len == 0) continue;

        if (strncmp(line, "SET_RATE", 8) == 0) {
            double rate = atof(line + 8);
            atomic_store(&g_send_active, (rate > 0.0) ? 1 : 0);
            char rb[64];
            snprintf(rb, sizeof(rb), "SET_RATE -> active=%d", (rate > 0.0));
            debug_log(rb);
        } else if (strcmp(line, "quit") == 0) {
            debug_log("quit");
            atomic_store(&g_running, 0);
            break;
        }
    }

    atomic_store(&g_running, 0);
    Sleep(200);
    debug_log("exiting");
    DeleteCriticalSection(&g_cell_lock);
    net_cleanup();
    return 0;
}