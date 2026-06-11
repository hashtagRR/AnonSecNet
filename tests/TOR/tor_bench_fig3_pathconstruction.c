/* tor_bench_fig3_pathconstruction.c  --  Figure 3: Path Construction Time (Tor-equivalent)
 *
 * Section 13.2 of AnonSecNet_Implementation_Spec:
 *   "Path construction time for Anon-Sec-Net (two paths, eight ECDHE
 *    handshakes total) versus the Tor-equivalent (one path, three
 *    telescoping handshakes plus one end-to-end handshake)."
 *   "Methodology: time the complete path construction phase across
 *    1000 sessions per variant. Report mean construction time with
 *    95% confidence intervals."
 *
 * Tor architecture alignment (Tor spec §5.1, ntor handshake):
 *   - Tor builds a 3-hop circuit via incremental / telescoping EXTEND cells.
 *   - Each extend = one ntor (Curve25519-based) handshake.
 *   - We use P-256 ECDHE (same as the rest of the codebase) as a conservative
 *     equivalent; P-256 keygen+derive cost is similar to ntor.
 *   - Total for Tor: 3 telescoping handshakes + 1 end-to-end (to rendezvous
 *     point or hidden service) = 4 ECDHE handshakes.
 *   - Total for ASN: 6 telescoping (3 per path) + 2 end-to-end = 8 handshakes.
 *
 * This file is standalone (no sockets, no threads). It measures pure
 * cryptographic construction cost, isolating protocol design from network
 * latency (as required by spec Section 11 "Localhost Simulation Setup").
 *
 * Output: CSV rows to append to ASN_figure3.csv
 *   protocol,n,mean_ms,ci95_ms,median_ms,p5_ms,p95_ms,min_ms,max_ms
 *
 * Build (Windows/MinGW):
 *   gcc -O2 -o tor_bench_fig3.exe tor_bench_fig3_pathconstruction.c \
 *       crypto.c -lssl -lcrypto -lws2_32
 *
 * Build (Linux):
 *   gcc -O2 -o tor_bench_fig3 tor_bench_fig3_pathconstruction.c \
 *       crypto.c -lssl -lcrypto -lm
 */

#include "crypto.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#ifdef _WIN32
#include <windows.h>
static double g_freq = 0.0;
static void timer_init(void) {
    LARGE_INTEGER f; QueryPerformanceFrequency(&f);
    g_freq = (double)f.QuadPart;
}
static double timer_us(void) {
    LARGE_INTEGER t; QueryPerformanceCounter(&t);
    return (double)t.QuadPart / g_freq * 1e6;
}
#else
#include <time.h>
static void timer_init(void) {}
static double timer_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}
#endif

/* ── Configuration ───────────────────────────────────────────────────────── */
#define ITERATIONS       1000

/* Tor: 3 telescoping + 1 end-to-end = 4 total */
#define TOR_HANDSHAKES    4

/* ── Single ECDHE handshake (keygen + derive, both sides) ────────────────── *
 * Models one ntor (Curve25519) handshake: initiator keygen, responder keygen,
 * shared secret derivation.
 * Returns cost in microseconds.
 */
static double do_one_handshake(void) {
    ecdh_keypair_t client_kp = {0};
    ecdh_keypair_t server_kp = {0};
    aes_key_t shared_key     = {0};

    double t0 = timer_us();

    /* Initiator generates ephemeral key pair */
    if (crypto_ecdh_keygen(&client_kp) != 0) {
        fprintf(stderr, "[fig3] client keygen failed\n");
        return 0.0;
    }
    /* Responder generates ephemeral key pair */
    if (crypto_ecdh_keygen(&server_kp) != 0) {
        fprintf(stderr, "[fig3] server keygen failed\n");
        crypto_ecdh_free(&client_kp);
        return 0.0;
    }
    /* Derive shared secret (initiator side) */
    if (crypto_ecdh_derive(&client_kp, server_kp.pubkey_bytes, &shared_key) != 0) {
        fprintf(stderr, "[fig3] derive failed\n");
        crypto_ecdh_free(&client_kp);
        crypto_ecdh_free(&server_kp);
        return 0.0;
    }

    double t1 = timer_us();

    crypto_ecdh_free(&client_kp);
    crypto_ecdh_free(&server_kp);

    return t1 - t0;
}

/* ── Statistics ──────────────────────────────────────────────────────────── */
typedef struct {
    double mean_ms;
    double ci95_ms;
    double median_ms;
    double p5_ms;
    double p95_ms;
    double min_ms;
    double max_ms;
} stats_t;

static int cmp_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static stats_t compute_stats(double *s, int n) {
    stats_t st = {0};
    double sum = 0, sum2 = 0;
    st.min_ms = s[0]; st.max_ms = s[0];
    for (int i = 0; i < n; i++) {
        sum += s[i];
        if (s[i] < st.min_ms) st.min_ms = s[i];
        if (s[i] > st.max_ms) st.max_ms = s[i];
    }
    st.mean_ms = sum / n;
    for (int i = 0; i < n; i++) {
        double d = s[i] - st.mean_ms; sum2 += d*d;
    }
    double sd = sqrt(sum2 / (n - 1));
    st.ci95_ms = 1.96 * sd / sqrt((double)n);

    qsort(s, n, sizeof(double), cmp_double);
    st.median_ms = s[n / 2];
    st.p5_ms     = s[(int)(0.05 * n)];
    st.p95_ms    = s[(int)(0.95 * n)];
    return st;
}

/* ── Run one variant ─────────────────────────────────────────────────────── */
static void run_variant(const char *name, int n_handshakes,
                        double *samples, int n_iters) {
    fprintf(stderr, "[fig3] %s: %d ECDHE handshakes x %d iterations...\n",
            name, n_handshakes, n_iters);

    for (int i = 0; i < n_iters; i++) {
        double total_us = 0.0;
        for (int h = 0; h < n_handshakes; h++) {
            total_us += do_one_handshake();
        }
        samples[i] = total_us / 1000.0;   /* µs → ms */

        if ((i+1) % 100 == 0)
            fprintf(stderr, "  iter %d/%d  last=%.3f ms\n", i+1, n_iters, samples[i]);
    }
}

/* ── Main ───────────────────────────────────────────────────────────────── */
int main(void) {
    timer_init();

    double *samples = malloc(ITERATIONS * sizeof(double));
    if (!samples) { fprintf(stderr, "OOM\n"); return 1; }

    printf("# Tor-equivalent Figure 3: path construction time\n");
    printf("# Source: tor_bench_fig3_pathconstruction.c\n");
    printf("# Tor: 4 ECDHE handshakes (3 telescoping + 1 e2e)\n");
    printf("# Reference: Tor spec ss5.1 EXTEND cells / ntor handshake\n");
    printf("# Methodology: 1000 iterations, in-process, no sockets\n");
    printf("protocol,n,mean_ms,ci95_ms,median_ms,p5_ms,p95_ms,min_ms,max_ms\n");

    /* ── Tor-equivalent: 4 handshakes ──────────────────────────────────── */
    run_variant("tor_equivalent", TOR_HANDSHAKES, samples, ITERATIONS);
    {
        stats_t s = compute_stats(samples, ITERATIONS);
        printf("tor_equivalent,%d,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f\n",
               ITERATIONS, s.mean_ms, s.ci95_ms, s.median_ms,
               s.p5_ms, s.p95_ms, s.min_ms, s.max_ms);
        fflush(stdout);
        fprintf(stderr, "[fig3] tor: mean=%.3f ms ±%.3f ms (95%% CI)\n",
                s.mean_ms, s.ci95_ms);
    }

    /* ── No-anonymity: 0 handshakes (direct connect baseline) ─────────── */
    for (int i = 0; i < ITERATIONS; i++) samples[i] = 0.0;
    {
        stats_t s = compute_stats(samples, ITERATIONS);
        printf("no_anonymity,%d,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f\n",
               ITERATIONS, s.mean_ms, s.ci95_ms, s.median_ms,
               s.p5_ms, s.p95_ms, s.min_ms, s.max_ms);
        fflush(stdout);
        fprintf(stderr, "[fig3] baseline: 0 ms by design\n");
    }

    /* ── Print raw samples for the Tor variant ─────────────────────────── */
    printf("\n# raw tor_equivalent samples (ms)\n");
    run_variant("tor_equivalent_raw", TOR_HANDSHAKES, samples, ITERATIONS);
    for (int i = 0; i < ITERATIONS; i++) {
        printf("%.3f\n", samples[i]);
    }

    free(samples);
    fprintf(stderr, "[fig3] complete\n");
    return 0;
}
