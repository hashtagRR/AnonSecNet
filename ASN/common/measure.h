/*
 * measure.h  --  Anon-Sec-Net v2 Measurement Harness
 *
 * Provides four probes:
 *   P1  MEASURE_HOP_BEGIN / MEASURE_HOP_END   per-hop crypto timer  (Figure 2)
 *   P2  MEASURE_SESSION_BEGIN / END            session setup timer   (Figure 3)
 *   P3  measure_link_bytes(is_cover, n)        byte counter          (Figure 5)
 *   P4  measure_sg_goodput(n)                  goodput counter       (Table 2)
 *
 * Include this header in mix_node.c, client.c, and service_gateway.c.
 * Call measure_init() once at the start of main() in each process.
 * Call measure_flush() before exit (optional -- atexit also flushes).
 *
 * Output files (written to current working directory):
 *   hop_timing.csv       -- us,<microseconds>
 *   session_setup.csv    -- ms,<milliseconds>
 *   link_bytes.csv       -- ts_ms,<epoch_ms>,cover,<n>,real,<n>
 *   sg_goodput.csv       -- ts_ms,<epoch_ms>,bps,<bits_per_second>
 *
 * Thread safety: all functions are safe to call from multiple threads.
 */

#ifndef MEASURE_H
#define MEASURE_H

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

/* ── Internal state (one instance per process) ─────────────────────────── */

typedef struct {
    /* P1: per-hop crypto timer */
    FILE            *hop_fp;
    CRITICAL_SECTION hop_lock;

    /* P2: session setup timer */
    FILE            *sess_fp;
    CRITICAL_SECTION sess_lock;
    LARGE_INTEGER    sess_t0;    /* set by MEASURE_SESSION_BEGIN */
    int              sess_active;

    /* P3: link byte counters (Receiver-to-MN1 edge) */
    FILE            *link_fp;
    CRITICAL_SECTION link_lock;
    volatile LONGLONG link_cover;
    volatile LONGLONG link_real;

    /* P4: SG goodput counter */
    FILE            *gp_fp;
    CRITICAL_SECTION gp_lock;
    volatile LONGLONG gp_bytes;

    /* QPC frequency, cached once */
    LARGE_INTEGER    qpc_freq;

    /* Sampler thread handle */
    HANDLE           sampler_thread;
    volatile int     sampler_stop;
} measure_ctx_t;

/* Single global instance -- each process has its own copy */
static measure_ctx_t g_mctx;

/* ── Sampler thread: snapshots P3 and P4 every second ──────────────────── */
static DWORD WINAPI _measure_sampler(LPVOID arg) {
    (void)arg;
    LONGLONG prev_cover = 0, prev_real = 0, prev_gp = 0;

    while (!g_mctx.sampler_stop) {
        Sleep(200);

        LONGLONG now_ms = (LONGLONG)(GetTickCount64());

        /* P3: link bytes snapshot */
        EnterCriticalSection(&g_mctx.link_lock);
        LONGLONG cover = g_mctx.link_cover;
        LONGLONG real  = g_mctx.link_real;
        LeaveCriticalSection(&g_mctx.link_lock);

        if (g_mctx.link_fp) {
            fprintf(g_mctx.link_fp,
                    "ts_ms,%lld,cover,%lld,real,%lld\n",
                    (long long)now_ms,
                    (long long)((cover - prev_cover) * 5),   /* scale to per-second */
					(long long)((real  - prev_real)  * 5));
            fflush(g_mctx.link_fp);
        }
        prev_cover = cover;
        prev_real  = real;

        /* P4: goodput snapshot */
        EnterCriticalSection(&g_mctx.gp_lock);
        LONGLONG gp = g_mctx.gp_bytes;
        LeaveCriticalSection(&g_mctx.gp_lock);

        if (g_mctx.gp_fp) {
            LONGLONG delta_bytes = gp - prev_gp;
            LONGLONG bps         = delta_bytes * 8 * 5;   /* bits per second */
            fprintf(g_mctx.gp_fp,
                    "ts_ms,%lld,bps,%lld\n",
                    (long long)now_ms,
                    (long long)bps);
            fflush(g_mctx.gp_fp);
        }
        prev_gp = gp;
    }
    return 0;
}

/* ── measure_init ────────────────────────────────────────────────────────
 * Call once in main().
 * pass_flags selects which probes to activate:
 *   MEASURE_P1  -- open hop_timing.csv     (use in mix_node)
 *   MEASURE_P2  -- open session_setup.csv  (use in client)
 *   MEASURE_P3  -- open link_bytes.csv     (use in client)
 *   MEASURE_P4  -- open sg_goodput.csv     (use in service_gateway)
 *
 * Example:
 *   measure_init(MEASURE_P1);                   // mix_node
 *   measure_init(MEASURE_P2 | MEASURE_P3);      // client
 *   measure_init(MEASURE_P4);                   // service_gateway
 */
#define MEASURE_P1  0x01
#define MEASURE_P2  0x02
#define MEASURE_P3  0x04
#define MEASURE_P4  0x08

static inline void measure_init(unsigned flags) {
    QueryPerformanceFrequency(&g_mctx.qpc_freq);

    InitializeCriticalSection(&g_mctx.hop_lock);
    InitializeCriticalSection(&g_mctx.sess_lock);
    InitializeCriticalSection(&g_mctx.link_lock);
    InitializeCriticalSection(&g_mctx.gp_lock);

    if (flags & MEASURE_P1) {
        g_mctx.hop_fp  = fopen("hop_timing.csv", "a");
        if (g_mctx.hop_fp)
            fprintf(g_mctx.hop_fp, "# per-hop crypto latency\nus\n");
    }
    if (flags & MEASURE_P2) {
        g_mctx.sess_fp = fopen("session_setup.csv", "a");
        if (g_mctx.sess_fp)
            fprintf(g_mctx.sess_fp, "# session setup time (first connect -> both paths ready)\nms\n");
    }
    if (flags & MEASURE_P3) {
        g_mctx.link_fp = fopen("link_bytes.csv", "a");
        if (g_mctx.link_fp)
            fprintf(g_mctx.link_fp,
                    "# byte counts at Receiver-to-MN1 edge, sampled every 1s\n"
                    "ts_ms,cover_bytes_delta,real_bytes_delta\n");
    }
    if (flags & MEASURE_P4) {
        g_mctx.gp_fp   = fopen("sg_goodput.csv", "a");
        if (g_mctx.gp_fp)
            fprintf(g_mctx.gp_fp,
                    "# SG goodput sampled every 1s\n"
                    "ts_ms,bps\n");
    }

    /* Start sampler for P3 / P4 if either is active */
    if ((flags & MEASURE_P3) || (flags & MEASURE_P4)) {
        g_mctx.sampler_stop = 0;
        g_mctx.sampler_thread =
            CreateThread(NULL, 0, _measure_sampler, NULL, 0, NULL);
    }
}

/* ── measure_flush / measure_close ─────────────────────────────────────── */
static inline void measure_flush(void) {
    if (g_mctx.hop_fp)  fflush(g_mctx.hop_fp);
    if (g_mctx.sess_fp) fflush(g_mctx.sess_fp);
    if (g_mctx.link_fp) fflush(g_mctx.link_fp);
    if (g_mctx.gp_fp)   fflush(g_mctx.gp_fp);
}

static inline void measure_close(void) {
    g_mctx.sampler_stop = 1;
    if (g_mctx.sampler_thread)
        WaitForSingleObject(g_mctx.sampler_thread, 2000);
    measure_flush();
    if (g_mctx.hop_fp)  { fclose(g_mctx.hop_fp);  g_mctx.hop_fp  = NULL; }
    if (g_mctx.sess_fp) { fclose(g_mctx.sess_fp); g_mctx.sess_fp = NULL; }
    if (g_mctx.link_fp) { fclose(g_mctx.link_fp); g_mctx.link_fp = NULL; }
    if (g_mctx.gp_fp)   { fclose(g_mctx.gp_fp);   g_mctx.gp_fp   = NULL; }
    DeleteCriticalSection(&g_mctx.hop_lock);
    DeleteCriticalSection(&g_mctx.sess_lock);
    DeleteCriticalSection(&g_mctx.link_lock);
    DeleteCriticalSection(&g_mctx.gp_lock);
}

/* ── P1: per-hop crypto timer macros ────────────────────────────────────── */

/* Place MEASURE_HOP_BEGIN immediately before packet_sphinx_peel()
 * and MEASURE_HOP_END immediately after.                                   */
#define MEASURE_HOP_BEGIN()                     \
    LARGE_INTEGER _hop_t0, _hop_t1;             \
    QueryPerformanceCounter(&_hop_t0)

#define MEASURE_HOP_END()                                                     \
    do {                                                                       \
        QueryPerformanceCounter(&_hop_t1);                                     \
        double _us = (double)(_hop_t1.QuadPart - _hop_t0.QuadPart)            \
                     * 1e6 / (double)g_mctx.qpc_freq.QuadPart;                \
        if (g_mctx.hop_fp) {                                                   \
            EnterCriticalSection(&g_mctx.hop_lock);                            \
            fprintf(g_mctx.hop_fp, "%.2f\n", _us);                            \
            LeaveCriticalSection(&g_mctx.hop_lock);                            \
        }                                                                      \
    } while (0)

/* ── P2: session setup timer ────────────────────────────────────────────── */

/* Call MEASURE_SESSION_BEGIN() just before the first ecdhe_with_node().
 * Call MEASURE_SESSION_END() right after g_state.ready = 1.               */
#define MEASURE_SESSION_BEGIN()                     \
    do {                                            \
        EnterCriticalSection(&g_mctx.sess_lock);    \
        QueryPerformanceCounter(&g_mctx.sess_t0);   \
        g_mctx.sess_active = 1;                     \
        LeaveCriticalSection(&g_mctx.sess_lock);    \
    } while (0)

#define MEASURE_SESSION_END()                                                   \
    do {                                                                        \
        LARGE_INTEGER _s1;                                                      \
        QueryPerformanceCounter(&_s1);                                          \
        EnterCriticalSection(&g_mctx.sess_lock);                                \
        if (g_mctx.sess_active && g_mctx.sess_fp) {                            \
            double _ms = (double)(_s1.QuadPart - g_mctx.sess_t0.QuadPart)      \
                         * 1e3 / (double)g_mctx.qpc_freq.QuadPart;             \
            fprintf(g_mctx.sess_fp, "%.3f\n", _ms);                            \
            fflush(g_mctx.sess_fp);                                             \
            g_mctx.sess_active = 0;                                             \
        }                                                                       \
        LeaveCriticalSection(&g_mctx.sess_lock);                                \
    } while (0)

/* ── P3: link byte counter ──────────────────────────────────────────────── */

/* Call after every net_send_all() on the client outbound edge to MN1.
 * is_cover: 1 for dummy/cover packets, 0 for real packets.
 * nbytes:   number of bytes sent (typically WIRE_PACKET_SIZE = 1024).      */
static inline void measure_link_bytes(int is_cover, LONGLONG nbytes) {
    EnterCriticalSection(&g_mctx.link_lock);
    if (is_cover)
        g_mctx.link_cover += nbytes;
    else
        g_mctx.link_real  += nbytes;
    LeaveCriticalSection(&g_mctx.link_lock);
}

/* ── P4: SG goodput counter ─────────────────────────────────────────────── */

/* Call in service_gateway.c after a successful send_response().
 * nbytes: size of the plaintext response delivered.                        */
static inline void measure_sg_goodput(LONGLONG nbytes) {
    EnterCriticalSection(&g_mctx.gp_lock);
    g_mctx.gp_bytes += nbytes;
    LeaveCriticalSection(&g_mctx.gp_lock);
}

#endif /* MEASURE_H */
