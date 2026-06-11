/* tor_bench_fig2_perhop.c  --  Figure 2: Per-Hop Processing Latency (Tor-equivalent)
 *
 * Section 13.1 of AnonSecNet_Implementation_Spec:
 *   "Per-hop cryptographic processing overhead for Anon-Sec-Net versus the
 *    Tor-equivalent versus the no-anonymity baseline, plotted as a function
 *    of payload size (64 bytes to 64 KB)."
 *
 * Tor architecture alignment (spec.torproject.org / tor-spec.txt):
 *   - Each Tor relay processes a fixed-size RELAY cell (509-byte payload).
 *   - Per-hop operation: AES-256-CTR decrypt (onion skin removal), NOT GCM.
 *   - The Tor spec uses AES-128-CTR in practice; we use AES-256-CTR to match
 *     the key length used elsewhere in this codebase (same threat model).
 *   - GCM (authenticated encryption) is used in Tor for the *link* layer
 *     (tor-spec section 5.1), but NOT per-hop onion decryption.
 *   - Per-hop processing = one AES-256-CTR decrypt of the full payload.
 *
 * Output: CSV
 *   payload_bytes,protocol,n,mean_us,ci95_us,min_us,max_us,p50_us,p95_us
 *
 * This file produces the TOR rows to append to ASN_hop_timing_figure2.csv.
 * The ASN and nonanon rows already exist in that file.
 *
 * NOTE: The existing ASN_hop_timing_figure2.csv has "tor" rows using GCM
 * encrypt+decrypt (incorrect model). This benchmark uses CTR-only (correct
 * per Tor relay cell spec). Results should replace those rows.
 *
 * Build (Windows/MinGW):
 *   gcc -O2 -o tor_bench_fig2.exe tor_bench_fig2_perhop.c \
 *       crypto.c -lssl -lcrypto -lws2_32
 *
 * Build (Linux):
 *   gcc -O2 -o tor_bench_fig2 tor_bench_fig2_perhop.c \
 *       crypto.c -lssl -lcrypto -lm
 */

#include "crypto.h"
#include "config.h"

#include <openssl/rand.h>
#include <openssl/evp.h>
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
#define ITERATIONS    5000
#define NUM_SIZES     11

/* Payload sizes from spec Section 13.1: 64B to 64KB */
static const int PAYLOAD_SIZES[NUM_SIZES] = {
    64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536
};

/* ── Statistics ──────────────────────────────────────────────────────────── */
typedef struct {
    double mean;
    double ci95;
    double min_v;
    double max_v;
    double p50;
    double p95;
} stats_t;

static int cmp_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static stats_t compute_stats(double *s, int n) {
    stats_t st = {0};
    double sum = 0, sum2 = 0;
    st.min_v = s[0]; st.max_v = s[0];
    for (int i = 0; i < n; i++) {
        sum += s[i];
        if (s[i] < st.min_v) st.min_v = s[i];
        if (s[i] > st.max_v) st.max_v = s[i];
    }
    st.mean = sum / n;
    for (int i = 0; i < n; i++) { double d = s[i] - st.mean; sum2 += d*d; }
    double sd = sqrt(sum2 / (n - 1));
    st.ci95 = 1.96 * sd / sqrt((double)n);

    qsort(s, n, sizeof(double), cmp_double);
    st.p50 = s[n / 2];
    st.p95 = s[(int)(0.95 * n)];
    return st;
}

/* ── AES-256-CTR per-hop decrypt (Tor relay cell model) ──────────────────── *
 *
 * Tor relay cells use AES-128-CTR for onion decryption. We use AES-256-CTR
 * to match our codebase key length. The per-hop cost model is the same:
 *   - One CTR keystream generation over the full payload
 *   - No authentication tag on the payload (tag lives at the circuit level)
 *
 * Reference: Tor spec §5.4.3 "Sending relay cells" — each relay XORs
 * the cell body with the running AES-CTR keystream.
 */
static void tor_perhop_ctr(const uint8_t *key, const uint8_t *in,
                           uint8_t *out, int len, uint8_t *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outl = 0;
    /* iv is a running counter, incremented per cell in real Tor.
     * For benchmarking we pass a per-iteration IV to isolate crypto cost. */
    EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, out, &outl, in, len);
    EVP_DecryptFinal_ex(ctx, out + outl, &outl);
    EVP_CIPHER_CTX_free(ctx);
}

/* ── No-anonymity baseline: single AES-256-GCM encrypt ──────────────────── *
 * Represents an encrypted-but-not-anonymous forwarding hop.
 * This matches the existing nonanon rows in the CSV.
 */
static int nonanon_perhop(const aes_key_t *key, const uint8_t *in, int len,
                          uint8_t *out, size_t out_size) {
    return crypto_aes_encrypt(key, in, (size_t)len, out, out_size);
}

/* ── Main ───────────────────────────────────────────────────────────────── */
int main(void) {
    timer_init();

    /* Print header for new TOR rows (matches existing CSV column layout) */
    printf("# Tor-equivalent Figure 2: per-hop crypto latency\n");
    printf("# Source: tor_bench_fig2_perhop.c\n");
    printf("# Tor: AES-256-CTR per-hop cell decryption (correct Tor relay model)\n");
    printf("# Reference: Tor spec ss5.4.3 relay cell onion decryption\n");
    printf("payload_bytes,protocol,n,mean_us,ci95_us,min_us,max_us,p50_us,p95_us\n");

    double *samples = malloc(ITERATIONS * sizeof(double));
    if (!samples) { fprintf(stderr, "OOM\n"); return 1; }

    /* ── Tor-equivalent: AES-256-CTR per-hop ───────────────────────────── */
    {
        uint8_t key[AES_KEY_LEN];
        RAND_bytes(key, AES_KEY_LEN);

        for (int si = 0; si < NUM_SIZES; si++) {
            int psize = PAYLOAD_SIZES[si];
            uint8_t *in  = malloc(psize);
            uint8_t *out = malloc(psize);
            RAND_bytes(in, psize);

            for (int i = 0; i < ITERATIONS; i++) {
                /* Fresh IV per iteration (simulates per-cell counter) */
                uint8_t iv[16] = {0};
                iv[15] = (uint8_t)(i & 0xFF);
                iv[14] = (uint8_t)((i >> 8) & 0xFF);

                double t0 = timer_us();
                tor_perhop_ctr(key, in, out, psize, iv);
                double t1 = timer_us();
                samples[i] = t1 - t0;
            }

            stats_t s = compute_stats(samples, ITERATIONS);
            printf("%d,tor,%d,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f\n",
                   psize, ITERATIONS,
                   s.mean, s.ci95, s.min_v, s.max_v, s.p50, s.p95);
            fflush(stdout);
            free(in); free(out);
        }
        fprintf(stderr, "[fig2] tor CTR done\n");
    }

    /* ── No-anonymity baseline: GCM encrypt ────────────────────────────── *
     * Included so this binary is self-contained and can reproduce all rows.
     * These match the nonanon rows already in the CSV — use to verify
     * consistency between runs.
     */
    {
        aes_key_t key;
        RAND_bytes(key.key, AES_KEY_LEN);

        for (int si = 0; si < NUM_SIZES; si++) {
            int psize = PAYLOAD_SIZES[si];
            size_t out_size = (size_t)psize + GCM_OVERHEAD;
            uint8_t *in  = malloc(psize);
            uint8_t *out = malloc(out_size);
            RAND_bytes(in, psize);

            for (int i = 0; i < ITERATIONS; i++) {
                double t0 = timer_us();
                nonanon_perhop(&key, in, psize, out, out_size);
                double t1 = timer_us();
                samples[i] = t1 - t0;
            }

            stats_t s = compute_stats(samples, ITERATIONS);
            printf("%d,nonanon_verify,%d,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f\n",
                   psize, ITERATIONS,
                   s.mean, s.ci95, s.min_v, s.max_v, s.p50, s.p95);
            fflush(stdout);
            free(in); free(out);
        }
        fprintf(stderr, "[fig2] nonanon verify done\n");
    }

    free(samples);
    fprintf(stderr, "[fig2] complete\n");
    return 0;
}
