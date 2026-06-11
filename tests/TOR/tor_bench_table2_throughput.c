/* tor_bench_table2_throughput.c  --  Table 2: Throughput Comparison (Tor-equivalent)
 *
 * Section 13.5 of AnonSecNet_Implementation_Spec:
 *   "End-to-end throughput for Anon-Sec-Net versus Tor-equivalent versus
 *    no-anonymity baseline, at various concurrent session counts
 *    (1, 5, 10, 50, 100, 200, 500)."
 *   "Methodology: measure aggregate throughput across all concurrent sessions
 *    for 60 seconds per configuration."
 *
 * Tor architecture alignment:
 *   - Each Tor cell is 514 bytes (2-byte length + 512-byte payload).
 *   - Per-hop: one AES-256-CTR decrypt (layer peel), no re-encryption.
 *   - 3-hop circuit: 3 CTR decrypts total per cell delivery.
 *   - Throughput is computed as (cells delivered x payload_bytes) / time.
 *
 * Methodology (matches ASN_table2_results approach):
 *   - For each N_CLIENTS value, simulate N concurrent circuits.
 *   - Each circuit processes TOR_CELL_PAYLOAD bytes per operation.
 *   - Measure total bytes delivered per second for 60 seconds.
 *   - Report mean, ci95, peak, n_samples (matching ASN CSV column layout).
 *
 * This is an in-process benchmark (no sockets, no threads) measuring the
 * pure per-hop cryptographic throughput, consistent with the spec's
 * "CPU overhead comparison" framing (Section 10).
 *
 * Output: CSV rows matching ASN_table2_results_n151050100_200_500.csv format
 *   n_clients,protocol,mean_bps,ci95_bps,peak_bps,mean_kbps,ci95_kbps,peak_kbps,n_samples
 *
 * Build (Windows/MinGW):
 *   gcc -O2 -o tor_bench_table2.exe tor_bench_table2_throughput.c \
 *       crypto.c -lssl -lcrypto -lws2_32
 *
 * Build (Linux):
 *   gcc -O2 -o tor_bench_table2 tor_bench_table2_throughput.c \
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
static double timer_sec(void) {
    LARGE_INTEGER t; QueryPerformanceCounter(&t);
    return (double)t.QuadPart / g_freq;
}
#else
#include <time.h>
static void timer_init(void) {}
static double timer_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}
#endif

/* ── Configuration ───────────────────────────────────────────────────────── */

/* Tor relay cell payload: 512 bytes (full 514-byte cell minus 2-byte header).
 * Reference: Tor spec §3 "Cell Packet format" */
#define TOR_CELL_PAYLOAD      512

/* Number of hops: Tor uses 3 */
#define TOR_HOPS              3

/* Measurement window per sample: 100ms buckets within the 60s run */
#define SAMPLE_WINDOW_SEC     0.1
#define TOTAL_DURATION_SEC    60.0
#define MAX_SAMPLES           ((int)(TOTAL_DURATION_SEC / SAMPLE_WINDOW_SEC) + 10)

static const int N_CLIENTS_LIST[] = {1, 5, 10, 50, 100, 200, 500};
#define NUM_N_CLIENTS ((int)(sizeof(N_CLIENTS_LIST)/sizeof(N_CLIENTS_LIST[0])))

/* ── Per-hop Tor operation: AES-256-CTR decrypt ──────────────────────────── */
static void tor_cell_perhop(const uint8_t *key, const uint8_t *in,
                            uint8_t *out, int len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    uint8_t iv[16] = {0};
    int outl = 0;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, out, &outl, in, len);
    EVP_DecryptFinal_ex(ctx, out + outl, &outl);
    EVP_CIPHER_CTX_free(ctx);
}

/* Process one Tor cell through a full 3-hop circuit */
static void tor_process_cell(const aes_key_t *keys, uint8_t *buf, uint8_t *tmp,
                              int payload_len, int hops) {
    for (int h = 0; h < hops; h++) {
        tor_cell_perhop(keys[h].key, buf, tmp, payload_len);
        memcpy(buf, tmp, payload_len);
    }
}

/* ── No-anonymity baseline: memcpy through hops ──────────────────────────── */
static void baseline_process(uint8_t *buf, uint8_t *tmp,
                              int payload_len, int hops) {
    for (int h = 0; h < hops; h++) {
        memcpy(tmp, buf, payload_len);
        memcpy(buf, tmp, payload_len);
    }
}

/* ── Statistics ──────────────────────────────────────────────────────────── */
typedef struct {
    double mean_bps;
    double ci95_bps;
    double peak_bps;
    int    n_samples;
} throughput_stats_t;

static throughput_stats_t compute_throughput_stats(double *bps_samples, int n) {
    throughput_stats_t st = {0};
    if (n == 0) return st;
    double sum = 0, sum2 = 0;
    st.peak_bps = bps_samples[0];
    for (int i = 0; i < n; i++) {
        sum += bps_samples[i];
        if (bps_samples[i] > st.peak_bps) st.peak_bps = bps_samples[i];
    }
    st.mean_bps = sum / n;
    for (int i = 0; i < n; i++) {
        double d = bps_samples[i] - st.mean_bps; sum2 += d*d;
    }
    double sd = (n > 1) ? sqrt(sum2 / (n - 1)) : 0.0;
    st.ci95_bps = (n > 1) ? (1.96 * sd / sqrt((double)n)) : 0.0;
    st.n_samples = n;
    return st;
}

/* ── Run throughput measurement ──────────────────────────────────────────── */
static throughput_stats_t run_throughput(
    const char *variant,
    int n_clients,
    int payload_len,
    int hops,
    aes_key_t *keys)   /* keys[0..hops-1] */
{
    double *bps_samples = malloc(MAX_SAMPLES * sizeof(double));
    int n_samples = 0;

    size_t buf_size = (size_t)payload_len + 64;
    uint8_t *payload_raw = malloc(payload_len);
    uint8_t *buf         = malloc(buf_size);
    uint8_t *tmp         = malloc(buf_size);

    RAND_bytes(payload_raw, payload_len);

    double t_start = timer_sec();
    double t_end   = t_start + TOTAL_DURATION_SEC;
    double window_start = t_start;
    long window_bytes = 0;

    while (timer_sec() < t_end) {
        for (int c = 0; c < n_clients; c++) {
            memcpy(buf, payload_raw, payload_len);

            if (strcmp(variant, "tor_equivalent") == 0) {
                tor_process_cell(keys, buf, tmp, payload_len, hops);
            } else {
                baseline_process(buf, tmp, payload_len, hops);
            }
            window_bytes += payload_len;
        }

        double t_now = timer_sec();
        double elapsed = t_now - window_start;
        if (elapsed >= SAMPLE_WINDOW_SEC && n_samples < MAX_SAMPLES) {
            bps_samples[n_samples++] = (double)window_bytes / elapsed;
            window_bytes = 0;
            window_start = t_now;
        }
    }

    free(payload_raw); free(buf); free(tmp);

    throughput_stats_t stats = compute_throughput_stats(bps_samples, n_samples);
    free(bps_samples);
    return stats;
}

/* ── Main ───────────────────────────────────────────────────────────────── */
int main(void) {
    timer_init();

    /* Generate per-hop keys */
    aes_key_t keys[5];
    for (int i = 0; i < 5; i++)
        RAND_bytes(keys[i].key, AES_KEY_LEN);

    printf("# Tor-equivalent Table 2: throughput vs concurrent sessions\n");
    printf("# Source: tor_bench_table2_throughput.c\n");
    printf("# Tor: AES-256-CTR per-hop (3 hops), %d-byte cell payload\n",
           TOR_CELL_PAYLOAD);
    printf("# Duration: %.0f seconds per configuration\n", TOTAL_DURATION_SEC);
    printf("n_clients,protocol,mean_bps,ci95_bps,peak_bps,"
           "mean_kbps,ci95_kbps,peak_kbps,n_samples\n");

    for (int ni = 0; ni < NUM_N_CLIENTS; ni++) {
        int n = N_CLIENTS_LIST[ni];
        fprintf(stderr, "[table2] N=%d clients...\n", n);

        const char *variants[] = {"tor_equivalent", "no_anonymity"};
        int payloads[]         = {TOR_CELL_PAYLOAD, TOR_CELL_PAYLOAD};

        for (int vi = 0; vi < 2; vi++) {
            const char *v = variants[vi];
            int plen      = payloads[vi];

            throughput_stats_t s = run_throughput(v, n, plen, TOR_HOPS, keys);

            printf("%d,%s,%.1f,%.1f,%.1f,%.3f,%.3f,%.3f,%d\n",
                   n, v,
                   s.mean_bps, s.ci95_bps, s.peak_bps,
                   s.mean_bps / 1000.0,
                   s.ci95_bps / 1000.0,
                   s.peak_bps / 1000.0,
                   s.n_samples);
            fflush(stdout);

            fprintf(stderr, "  %s: mean=%.1f kbps ±%.1f kbps  peak=%.1f kbps  n=%d\n",
                    v,
                    s.mean_bps / 1000.0, s.ci95_bps / 1000.0,
                    s.peak_bps / 1000.0, s.n_samples);
        }
    }

    fprintf(stderr, "[table2] complete\n");
    return 0;
}
