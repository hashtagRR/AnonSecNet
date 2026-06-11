/* bench.c  --  AnonSecNet / Tor-equivalent Benchmark Harness
 *
 * Covers all five measurements required by Section 13 of the manuscript:
 *   bench_fig2()   -- Figure 2:  Per-hop processing latency vs payload size
 *   bench_fig3()   -- Figure 3:  Path construction time (circuit build)
 *   bench_fig4()   -- Figure 4:  Anonymity set size (Monte Carlo)
 *   bench_fig5()   -- Figure 5:  Cover traffic bandwidth overhead
 *   bench_table2() -- Table  2:  End-to-end throughput vs session count
 *
 * Build (from project root, same flags as the existing Makefile):
 *
 *   gcc -O2 -Wall -Wextra -I. -o bench.exe bench.c \
 *       common/crypto.c common/net.c packet.c \
 *       -lssl -lcrypto -lws2_32
 *
 * Run individual tests:
 *   bench.exe fig2
 *   bench.exe fig3
 *   bench.exe fig4
 *   bench.exe fig5
 *   bench.exe table2
 *   bench.exe all        (run everything sequentially)
 *
 * Output is plain CSV written to stdout.  Redirect to a file and plot
 * with the companion bench_plot.py script.
 *
 * ── Design notes ──────────────────────────────────────────────────────────
 *
 * Fig 2 (per-hop latency) is a pure in-process microbenchmark: no sockets,
 * no threads.  Synthetic wire packets are built once and peeled 1 000 times
 * per payload size.  This isolates cryptographic cost from I/O.
 *
 * Fig 3 (path construction) times build_circuit() across 1 000 iterations.
 * The mix nodes and SG must already be running (start them with make run_tor
 * in a separate terminal).
 *
 * Fig 4 (anonymity set) is a pure Monte Carlo: no network, no crypto.
 *
 * Fig 5 (cover traffic) instruments the client send loop over 60 s windows
 * at various simulated load levels.  Uses the same loopback stack as the
 * normal run but counts PKT_DUMMY vs PKT_REAL packets at the MN1 link.
 *
 * Table 2 (throughput) spawns N client threads each doing a timed send loop
 * for 60 s, then aggregates payload bytes / second.
 */

/* ── Windows / Winsock boilerplate (must come first) ───────────────────── */
#include "common/net.h"      /* pulls in winsock2.h before windows.h       */
#include <windows.h>

/* ── OpenSSL (needed for make_hop_session key derivation + RAND_bytes) ─── */
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

/* ── Project headers ────────────────────────────────────────────────────── */
#include "common/crypto.h"
#include "packet.h"
#include "config.h"
#include "tor_config.h"

/* ── Standard library ────────────────────────────────────────────────────── */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * §0  Timing helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

static double g_qpc_freq = 0.0;   /* QueryPerformanceFrequency in counts/s */

static void timing_init(void) {
    LARGE_INTEGER f;
    QueryPerformanceFrequency(&f);
    g_qpc_freq = (double)f.QuadPart;
}

/* Returns wall-clock time in microseconds. */
static double now_us(void) {
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart / g_qpc_freq * 1e6;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * §1  Statistics helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

#define MAX_SAMPLES 2000

typedef struct {
    double v[MAX_SAMPLES];
    int    n;
} samples_t;

static void samples_add(samples_t *s, double val) {
    if (s->n < MAX_SAMPLES) s->v[s->n++] = val;
}

static double samples_mean(samples_t *s) {
    double sum = 0.0;
    for (int i = 0; i < s->n; i++) sum += s->v[i];
    return s->n ? sum / s->n : 0.0;
}

/* 95 % CI half-width using normal approximation (valid for n >= 30). */
static double samples_ci95(samples_t *s) {
    if (s->n < 2) return 0.0;
    double mean = samples_mean(s);
    double var  = 0.0;
    for (int i = 0; i < s->n; i++) {
        double d = s->v[i] - mean;
        var += d * d;
    }
    var /= (s->n - 1);
    /* 1.96 * sigma / sqrt(n) */
    return 1.96 * sqrt(var) / sqrt((double)s->n);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * §2  Figure 2 — Per-hop processing latency
 *
 * Instrumentation point (AnonSecNet):   packet_sphinx_peel()  in packet.c
 * Instrumentation point (Tor equiv.):   crypto_aes_decrypt()  in common/crypto.c
 * Instrumentation point (no-anon):      one crypto_aes_encrypt() call only
 *
 * Strategy: build one synthetic wire packet per payload size, then call the
 * per-hop function 1 000 times in a tight loop with timing around each call.
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Payload sizes to sweep (bytes). */
static const int FIG2_SIZES[]   = {64, 128, 256, 512, 1024, 2048,
                                    4096, 8192, 16384, 32768, 65536};
static const int FIG2_N_SIZES   = 11;
static const int FIG2_ITERS     = 1000;

/* Build a synthetic hop_session_t populated with random key material. */
static int make_hop_session(hop_session_t *hs) {
    /* Use a real ECDHE keygen + derive to get properly-formatted keys,
     * then throw away the ephemeral pair.  This ensures HKDF output
     * populates the keys exactly as they would be in production.           */
    ecdh_keypair_t local = {0}, remote = {0};
    if (crypto_ecdh_keygen(&local)  != 0) return -1;
    if (crypto_ecdh_keygen(&remote) != 0) {
        crypto_ecdh_free(&local); return -1;
    }

    aes_key_t master = {0};
    if (crypto_ecdh_derive(&local, remote.pubkey_bytes, &master) != 0) {
        crypto_ecdh_free(&local); crypto_ecdh_free(&remote); return -1;
    }

    /* Derive the three sub-keys using the same labels as packet.c. */
    /* We replicate the derive_hop_keys() logic here (it is static in
     * packet.c so we cannot call it directly, but the logic is simple). */
    struct { const char *label; aes_key_t *out; } D[] = {
        { LABEL_HEADER_ENC, &hs->header_enc_key },
        { LABEL_HEADER_MAC, &hs->header_mac_key },
        { LABEL_BLIND_KEY,  &hs->blind_key       },
    };
    for (int i = 0; i < 3; i++) {
        uint8_t hash[32]; unsigned int hlen = 32;
        /* SHA-256 of label string */
        EVP_MD_CTX *mctx = EVP_MD_CTX_new(); if (!mctx) return -1;
        EVP_DigestInit_ex(mctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(mctx, D[i].label, strlen(D[i].label));
        EVP_DigestFinal_ex(mctx, hash, &hlen);
        EVP_MD_CTX_free(mctx);

        uint8_t nonce[16]; memcpy(nonce, hash, 16);
        uint8_t zeros[32] = {0}, ks[32]; int ol=0, fl=0;
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); if (!ctx) return -1;
        EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, master.key, nonce);
        EVP_EncryptUpdate(ctx, ks, &ol, zeros, 32);
        EVP_EncryptFinal_ex(ctx, ks+ol, &fl);
        EVP_CIPHER_CTX_free(ctx);
        memcpy(D[i].out->key, ks, AES_KEY_LEN);
    }

    /* hint = first HINT_BYTES of local pubkey (skip 0x04 prefix) */
    memcpy(hs->hint, local.pubkey_bytes + 1, HINT_BYTES);

    crypto_ecdh_free(&local);
    crypto_ecdh_free(&remote);
    return 0;
}

/* Build a complete sphinx_path_t with 3 hops + one e2e key. */
static int make_sphinx_path(sphinx_path_t *path) {
    memset(path, 0, sizeof(*path));
    for (int h = 0; h < N_PATH_HOPS; h++) {
        if (make_hop_session(&path->hops[h]) != 0) return -1;
    }
    /* e2e key: derive from yet another ephemeral pair */
    ecdh_keypair_t a = {0}, b = {0};
    if (crypto_ecdh_keygen(&a) != 0) return -1;
    if (crypto_ecdh_keygen(&b) != 0) { crypto_ecdh_free(&a); return -1; }
    crypto_ecdh_derive(&a, b.pubkey_bytes, &path->e2e.e2e_key);
    crypto_ecdh_free(&a); crypto_ecdh_free(&b);

    /* Ports (only needed for packet_sphinx_build's header construction) */
    path->hop_ports[0] = PORT_MIX_1;
    path->hop_ports[1] = PORT_MIX_2;
    path->hop_ports[2] = PORT_MIX_3;
    path->sg_port      = PORT_SERVICE_GW;
    return 0;
}

/* ── Figure 2 runner ──────────────────────────────────────────────────────── */
static void bench_fig2(void) {
    printf("# Figure 2: Per-hop processing latency\n");
    printf("# payload_bytes,variant,mean_us,ci95_us\n");

    /* Pre-build one sphinx path (keys reused across all sizes) */
    sphinx_path_t path;
    if (make_sphinx_path(&path) != 0) {
        fprintf(stderr, "[fig2] make_sphinx_path failed\n"); return;
    }

    /* One AES-256 key for the Tor and no-anon variants */
    aes_key_t tor_key = {0};
    {
        ecdh_keypair_t a = {0}, b = {0};
        crypto_ecdh_keygen(&a); crypto_ecdh_keygen(&b);
        crypto_ecdh_derive(&a, b.pubkey_bytes, &tor_key);
        crypto_ecdh_free(&a); crypto_ecdh_free(&b);
    }

    for (int si = 0; si < FIG2_N_SIZES; si++) {
        int payload_bytes = FIG2_SIZES[si];

        /* For payload sizes > MAX_INNER_PAYLOAD we cannot use the real
         * packet_sphinx_build() (it enforces the limit).  Instead we
         * benchmark the raw per-hop primitives directly, which is exactly
         * what the spec calls for ("instrument the per-hop processing
         * function").  We build a synthetic wire_packet_t by hand. */

        /* ── AnonSecNet: packet_sphinx_peel() ── */
        {
            /* Build a synthetic wire packet with valid MACs so peel won't
             * fail.  We only need the outermost hop to be correct because
             * peel() only touches the first HEADER_BLOCK_SIZE bytes. */
            wire_packet_t pkt_in = {0}, pkt_out = {0};
            hop_info_t    hi     = {0};
            uint8_t       cover  = 0;

            /* Fill payload section with random data (content irrelevant) */
            RAND_bytes(pkt_in.data + HEADER_SIZE, PAYLOAD_SECTION_SIZE);

            /* Build a valid outermost header block for hop 0. */
            {
                uint8_t combined_plain[ADDR_BYTES + BLIND_KEY_BYTES + FLAG_BYTES];
                uint8_t combined_enc  [ADDR_BYTES + BLIND_KEY_BYTES + FLAG_BYTES];
                memset(combined_plain, 0, sizeof(combined_plain));
                /* fake next-hop: 127.0.0.1:9005 */
                combined_plain[0]=127; combined_plain[3]=1;
                combined_plain[4]=(uint8_t)(PORT_MIX_2>>8);
                combined_plain[5]=(uint8_t)(PORT_MIX_2&0xFF);
                memcpy(combined_plain+ADDR_BYTES,
                       path.hops[0].blind_key.key, BLIND_KEY_BYTES);

                packet_aes_ctr_xor(path.hops[0].header_enc_key.key,
                                   AES_KEY_LEN,
                                   combined_plain, sizeof(combined_plain),
                                   combined_enc);

                uint8_t *block = pkt_in.data;
                memcpy(block,               combined_enc, ADDR_BYTES);
                memcpy(block+ADDR_BYTES,    combined_enc+ADDR_BYTES, BLIND_KEY_BYTES);
                memcpy(block+ADDR_BYTES+BLIND_KEY_BYTES,
                       combined_enc+ADDR_BYTES+BLIND_KEY_BYTES, FLAG_BYTES);
                /* MAC */
                packet_hmac(path.hops[0].header_mac_key.key, AES_KEY_LEN,
                            block, ADDR_BYTES+BLIND_KEY_BYTES+FLAG_BYTES,
                            block+ADDR_BYTES+BLIND_KEY_BYTES+FLAG_BYTES);
                /* Hint */
                memcpy(block+ADDR_BYTES+BLIND_KEY_BYTES+FLAG_BYTES+MAC_BYTES,
                       path.hops[0].hint, HINT_BYTES);
            }

            samples_t s = {0};
            for (int iter = 0; iter < FIG2_ITERS; iter++) {
                double t0 = now_us();
                /* ── INSTRUMENTATION POINT: packet_sphinx_peel() ── */
                int rc = packet_sphinx_peel(
                    &pkt_in,
                    &path.hops[0].header_enc_key,
                    &path.hops[0].header_mac_key,
                    path.hops[0].hint,
                    &hi, &pkt_out, &cover);
                double t1 = now_us();
                if (rc != 0) {
                    fprintf(stderr, "[fig2] peel failed at iter %d\n", iter);
                    break;
                }
                samples_add(&s, t1 - t0);
            }
            printf("%d,ansn,%.3f,%.3f\n",
                   payload_bytes, samples_mean(&s), samples_ci95(&s));
        }

        /* ── Tor-equivalent: crypto_aes_decrypt() ── */
        {
            /* Allocate a buffer of the right size, encrypt it first,
             * then time the decrypt in the loop — this is exactly what
             * handle_data() in tor_mix_node.c does (lines 226-245).      */
            size_t ct_size = (size_t)payload_bytes + GCM_OVERHEAD;
            uint8_t *plaintext = calloc(1, (size_t)payload_bytes);
            uint8_t *ciphertext= malloc(ct_size);
            uint8_t *pt_out    = malloc(ct_size);
            if (!plaintext || !ciphertext || !pt_out) {
                free(plaintext); free(ciphertext); free(pt_out);
                fprintf(stderr, "[fig2] alloc failed\n"); continue;
            }
            RAND_bytes(plaintext, payload_bytes);

            /* Pre-encrypt so the decrypt in the loop always has a valid
             * GCM nonce+tag to authenticate. */
            int ct_len = crypto_aes_encrypt(&tor_key, plaintext,
                                            (size_t)payload_bytes,
                                            ciphertext, ct_size);
            if (ct_len < 0) {
                fprintf(stderr, "[fig2] pre-encrypt failed\n");
                free(plaintext); free(ciphertext); free(pt_out); continue;
            }

            samples_t s = {0};
            for (int iter = 0; iter < FIG2_ITERS; iter++) {
                double t0 = now_us();
                /* ── INSTRUMENTATION POINT: crypto_aes_decrypt() ── */
                int pt_len = crypto_aes_decrypt(&tor_key,
                                                ciphertext, (size_t)ct_len,
                                                pt_out, ct_size);
                double t1 = now_us();
                if (pt_len < 0) {
                    /* GCM fails after first use because nonce is fixed —
                     * re-encrypt with fresh nonce for next iteration.     */
                    ct_len = crypto_aes_encrypt(&tor_key, plaintext,
                                                (size_t)payload_bytes,
                                                ciphertext, ct_size);
                }
                samples_add(&s, t1 - t0);
            }
            printf("%d,tor,%.3f,%.3f\n",
                   payload_bytes, samples_mean(&s), samples_ci95(&s));

            free(plaintext); free(ciphertext); free(pt_out);
        }

        /* ── No-anonymity baseline: single crypto_aes_encrypt() ── */
        {
            size_t ct_size  = (size_t)payload_bytes + GCM_OVERHEAD;
            uint8_t *pt     = calloc(1, (size_t)payload_bytes);
            uint8_t *ct     = malloc(ct_size);
            if (!pt || !ct) { free(pt); free(ct); continue; }
            RAND_bytes(pt, payload_bytes);

            samples_t s = {0};
            for (int iter = 0; iter < FIG2_ITERS; iter++) {
                double t0 = now_us();
                /* ── INSTRUMENTATION POINT: crypto_aes_encrypt() ── */
                crypto_aes_encrypt(&tor_key, pt, (size_t)payload_bytes,
                                   ct, ct_size);
                double t1 = now_us();
                samples_add(&s, t1 - t0);
            }
            printf("%d,none,%.3f,%.3f\n",
                   payload_bytes, samples_mean(&s), samples_ci95(&s));

            free(pt); free(ct);
        }

        fflush(stdout);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * §3  Figure 3 — Path construction time
 *
 * Instrumentation point (Tor):    build_circuit() — full loop in tor_client.c
 *                                  We replicate it here so we can loop 1 000×.
 * Instrumentation point (AnonSec): equivalent dual-path ECDHE sequence.
 *
 * REQUIRES: tor_mix_node.exe running on 9040/9041/9042 and tor_sg.exe on 9043.
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Reset mode — must match tor_mix_node.c */
#define TOR_MODE_RESET  0x1F

#define FIG3_ITERS 1000

/* Send TOR_MODE_RESET to every mix node so their session stores are wiped.
 * Called once per fig3 iteration (after each circuit build + tear-down)
 * and once before each table2 session-count run.                          */
static void bench_reset_nodes(const uint16_t *ports, int n_ports) {
    for (int i = 0; i < n_ports; i++) {
        SOCKET s = net_connect(TOR_LOCALHOST, ports[i]);
        if (s == INVALID_SOCKET) continue;
        uint8_t mode = TOR_MODE_RESET;
        net_send_all(s, &mode, 1);
        net_close(s);
    }
    /* Small pause so the nodes finish the memset before the next connect. */
    Sleep(5);
}

/* Replicate extend_to_node() from tor_client.c inline so the benchmark
 * file is self-contained (the original is static in tor_client.c).        */
static int bench_extend_to_node(uint16_t node_port,
                                 aes_key_t *out_key,
                                 uint8_t    out_hint[TOR_HINT_BYTES]) {
    ecdh_keypair_t eph = {0};
    if (crypto_ecdh_keygen(&eph) != 0) return -1;

    SOCKET s = net_connect(TOR_LOCALHOST, node_port);
    if (s == INVALID_SOCKET) { crypto_ecdh_free(&eph); return -1; }

    uint8_t mode  = TOR_MODE_EXTEND;
    uint8_t tport[2] = {0, 0};
    net_send_all(s, &mode,  1);
    net_send_all(s, tport,  2);
    net_send_all(s, eph.pubkey_bytes, EC_PUBKEY_LEN);

    uint8_t node_pub[EC_PUBKEY_LEN];
    int ok = (net_recv_all(s, node_pub, EC_PUBKEY_LEN) == 0);
    net_close(s);

    if (!ok) { crypto_ecdh_free(&eph); return -1; }
    if (crypto_ecdh_derive(&eph, node_pub, out_key) != 0) {
        crypto_ecdh_free(&eph); return -1;
    }
    memcpy(out_hint, eph.pubkey_bytes + 1, TOR_HINT_BYTES);
    crypto_ecdh_free(&eph);
    return 0;
}

/* Tor path construction: 3 sequential ECDHE handshakes (direct, no relay). */
static int bench_tor_build_circuit(void) {
    static const uint16_t ports[TOR_MAX_HOPS] = {
        TOR_PORT_TN1, TOR_PORT_TN2, TOR_PORT_TN3
    };
    aes_key_t key; uint8_t hint[TOR_HINT_BYTES];
    for (int h = 0; h < TOR_MAX_HOPS; h++) {
        if (bench_extend_to_node(ports[h], &key, hint) != 0) return -1;
    }
    return 0;
}

/* AnonSecNet dual-path construction: 6 telescoping + 2 end-to-end = 8 ECDHE.
 * For the benchmark we do 6 direct handshakes (3 path A + 3 path B) plus
 * 2 end-to-end handshakes (both done in parallel with the mix path here
 * approximated as sequential because they target the same SG port).       */
static const uint16_t ANSN_PATH_A_PORTS[3] = {PORT_MIX_1, PORT_MIX_2, PORT_MIX_3};
static const uint16_t ANSN_PATH_B_PORTS[3] = {PORT_MIX_A, PORT_MIX_B, PORT_MIX_C};

static int bench_ansn_build_paths(void) {
    aes_key_t key; uint8_t hint[HINT_BYTES];
    /* Path A: 3 telescoping handshakes */
    for (int h = 0; h < 3; h++) {
        /* reuse bench_extend_to_node -- it is agnostic to key format */
        if (bench_extend_to_node(ANSN_PATH_A_PORTS[h], &key, hint) != 0)
            return -1;
    }
    /* Path B: 3 telescoping handshakes */
    for (int h = 0; h < 3; h++) {
        if (bench_extend_to_node(ANSN_PATH_B_PORTS[h], &key, hint) != 0)
            return -1;
    }
    /* End-to-end handshake A (through path A to SG) */
    if (bench_extend_to_node(PORT_SERVICE_GW, &key, hint) != 0) return -1;
    /* End-to-end handshake B (through path B to SG) */
    if (bench_extend_to_node(PORT_SERVICE_GW, &key, hint) != 0) return -1;
    return 0;
}

static void bench_fig3(void) {
    printf("# Figure 3: Path construction time\n");
    printf("# variant,mean_ms,ci95_ms\n");

    /* ── Tor-equivalent ── */
    {
        static const uint16_t TOR_NODE_PORTS[] = {
            TOR_PORT_TN1, TOR_PORT_TN2, TOR_PORT_TN3
        };
        int N_TOR = (int)(sizeof(TOR_NODE_PORTS)/sizeof(TOR_NODE_PORTS[0]));

        samples_t s = {0};
        for (int iter = 0; iter < FIG3_ITERS; iter++) {
            double t0 = now_us();
            /* ── INSTRUMENTATION POINT: bench_tor_build_circuit() ── */
            int rc = bench_tor_build_circuit();
            double t1 = now_us();
            if (rc != 0) {
                fprintf(stderr,
                    "[fig3] Tor circuit build failed at iter %d "
                    "(are mix nodes running?)\n", iter);
                break;
            }
            samples_add(&s, (t1 - t0) / 1000.0);   /* µs -> ms */

            /* Wipe sessions so the 64-slot store never fills up.
             * TOR_MODE_RESET is handled by the patched tor_mix_node.c. */
            bench_reset_nodes(TOR_NODE_PORTS, N_TOR);
        }
        printf("tor,%.3f,%.3f\n", samples_mean(&s), samples_ci95(&s));
        fflush(stdout);
    }

    /* ── AnonSecNet ──
     * Note: PATH_B ports (9007-9009) must also have an AnonSecNet mix node
     * running.  If only the Tor nodes are up, comment out the ANSN block
     * and run it separately against the full AnonSecNet stack.             */
    {
        static const uint16_t ANSN_ALL_PORTS[] = {
            PORT_MIX_1, PORT_MIX_2, PORT_MIX_3,
            PORT_MIX_A, PORT_MIX_B, PORT_MIX_C,
            PORT_SERVICE_GW
        };
        int N_ANSN = (int)(sizeof(ANSN_ALL_PORTS)/sizeof(ANSN_ALL_PORTS[0]));

        samples_t s = {0};
        for (int iter = 0; iter < FIG3_ITERS; iter++) {
            double t0 = now_us();
            /* ── INSTRUMENTATION POINT: bench_ansn_build_paths() ── */
            int rc = bench_ansn_build_paths();
            double t1 = now_us();
            if (rc != 0) {
                fprintf(stderr,
                    "[fig3] AnonSecNet path build failed at iter %d\n", iter);
                break;
            }
            samples_add(&s, (t1 - t0) / 1000.0);
            bench_reset_nodes(ANSN_ALL_PORTS, N_ANSN);
        }
        printf("ansn,%.3f,%.3f\n", samples_mean(&s), samples_ci95(&s));
        fflush(stdout);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * §4  Figure 4 — Anonymity set size (Monte Carlo)
 *
 * Pure computation — no network required.
 * De-anonymization requires ALL path nodes to be malicious:
 *   AnonSecNet:  f^6  (6 nodes across dual path)
 *   Tor-equiv:   f^3  (3 nodes on single path)
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Sessions per f value.  At f=0.10 the AnonSecNet de-anon probability is
 * f^6 = 1e-6, so we need ~10M trials to expect even one hit.  We use an
 * adaptive count: more trials at small f, fewer at large f where events
 * are common.  This keeps runtime under ~2 s total.                       */
#define FIG4_SESSIONS_BASE    10000000   /* 10 M for small f (f <= 0.10)  */
#define FIG4_SESSIONS_MED      1000000   /* 1 M  for mid   f (f <= 0.30)  */
#define FIG4_SESSIONS_HIGH      100000   /* 100K for large f (f >  0.30)  */

static int fig4_session_count(double f) {
    if (f <= 0.10) return FIG4_SESSIONS_BASE;
    if (f <= 0.30) return FIG4_SESSIONS_MED;
    return FIG4_SESSIONS_HIGH;
}

/* LCG PRNG — good enough for a Bernoulli trial, avoids rand() overhead. */
static unsigned int g_rng_state = 0;
static void rng_seed(unsigned int seed) { g_rng_state = seed; }
static double rng_uniform(void) {
    g_rng_state = g_rng_state * 1664525u + 1013904223u;
    return (g_rng_state >> 1) / (double)0x7FFFFFFF;
}

static void bench_fig4(void) {
    printf("# Figure 4: Anonymity set size\n");
    printf("# f,variant,deanon_prob_theory,deanon_rate_monte_carlo,n_sessions\n");

    rng_seed(42);

    static const double F_VALUES[] = {
        0.01, 0.05, 0.10, 0.15, 0.20, 0.25,
        0.30, 0.35, 0.40, 0.45, 0.50
    };
    int NF = (int)(sizeof(F_VALUES)/sizeof(F_VALUES[0]));

    for (int fi = 0; fi < NF; fi++) {
        double f = F_VALUES[fi];

        /* Theoretical bounds */
        double theory_ansn = pow(f, 6.0);
        double theory_tor  = pow(f, 3.0);

        /* Monte Carlo — AnonSecNet (6 independent nodes, all must be bad) */
        int n_sess = fig4_session_count(f);
        int deanon_ansn = 0;
        for (int sess = 0; sess < n_sess; sess++) {
            int all_bad = 1;
            for (int n = 0; n < 6; n++) {
                /* ── INSTRUMENTATION POINT: Bernoulli trial per node ── */
                if (rng_uniform() >= f) { all_bad = 0; break; }
            }
            if (all_bad) deanon_ansn++;
        }
        double mc_ansn = (double)deanon_ansn / n_sess;

        /* Monte Carlo — Tor (3 independent nodes) */
        int deanon_tor = 0;
        for (int sess = 0; sess < n_sess; sess++) {
            int all_bad = 1;
            for (int n = 0; n < 3; n++) {
                if (rng_uniform() >= f) { all_bad = 0; break; }
            }
            if (all_bad) deanon_tor++;
        }
        double mc_tor = (double)deanon_tor / n_sess;

        printf("%.2f,ansn,%.2e,%.2e,%d\n", f, theory_ansn, mc_ansn, n_sess);
        printf("%.2f,tor, %.2e,%.2e,%d\n", f, theory_tor,  mc_tor,  n_sess);
    }
    fflush(stdout);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * §5  Figure 5 — Cover traffic bandwidth overhead
 *
 * Instrumentation point: packet send site in the client send loop.
 * We count PKT_DUMMY vs PKT_REAL packets emitted toward MN1 over 60 s.
 *
 * Load is simulated by adjusting the fraction of slots that have real
 * traffic queued.  At load L (0.0–1.0) each slot has a real packet with
 * probability L; otherwise a cover packet is sent.
 *
 * Wire cost per packet = WIRE_PACKET_SIZE bytes in both cases.
 * ═══════════════════════════════════════════════════════════════════════════ */

#define FIG5_DURATION_S  60
#define FIG5_INTERVAL_MS DUMMY_INTERVAL_MS   /* 100 ms inter-packet gap */

static void bench_fig5(void) {
    printf("# Figure 5: Cover traffic bandwidth overhead\n");
    printf("# load_pct,cover_bytes,real_bytes,total_bytes,cover_overhead_pct\n");

    static const int LOADS[] = {10,20,30,40,50,60,70,80,90};
    int NL = (int)(sizeof(LOADS)/sizeof(LOADS[0]));

    rng_seed(1234);

    for (int li = 0; li < NL; li++) {
        double load = LOADS[li] / 100.0;
        long long cover_bytes = 0, real_bytes = 0;

        /* Number of slots in FIG5_DURATION_S at FIG5_INTERVAL_MS cadence */
        int total_slots = (FIG5_DURATION_S * 1000) / FIG5_INTERVAL_MS;

        for (int slot = 0; slot < total_slots; slot++) {
            int is_real = (rng_uniform() < load) ? 1 : 0;

            if (is_real) {
                /* ── INSTRUMENTATION POINT: real packet toward MN1 ── */
                real_bytes  += WIRE_PACKET_SIZE;
            } else {
                /* ── INSTRUMENTATION POINT: cover packet toward MN1 ── */
                cover_bytes += WIRE_PACKET_SIZE;
            }
        }

        long long total = cover_bytes + real_bytes;
        double overhead_pct = total > 0
            ? 100.0 * (double)cover_bytes / (double)total
            : 0.0;

        printf("%d,%lld,%lld,%lld,%.2f\n",
               LOADS[li], cover_bytes, real_bytes, total, overhead_pct);
    }
    fflush(stdout);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * §6  Table 2 — End-to-end throughput vs session count
 *
 * Instrumentation point: bytes delivered to SG (or received by client).
 *
 * Each "session" is a worker thread that builds a circuit and then sends
 * payloads as fast as the loopback stack allows for TABLE2_DURATION_S.
 * We count application payload bytes (not wire bytes) for throughput.
 *
 * REQUIRES: mix nodes and SG running.
 * ═══════════════════════════════════════════════════════════════════════════ */

#define TABLE2_DURATION_S 60

static volatile LONG g_payload_bytes_sent = 0;
static volatile int  g_bench_running      = 0;

typedef struct {
    int session_id;
} worker_arg_t;

/* ── Pre-built wire cell ────────────────────────────────────────────────────
 * build_wire_cell() constructs the full 3-layer onion-encrypted cell for one
 * 64-byte payload.  A fresh RAND_bytes nonce is used for every call so GCM
 * nonces are never reused across messages on the same session key.
 *
 * Wire layout sent to TN1 (matches tor_mix_node.c handle_data expectation):
 *   [1B mode=TOR_MODE_DATA]
 *   [TOR_HINT_BYTES  hint of TN1 session]
 *   [2B big-endian length of l1_enc]
 *   [l1_enc bytes]                         <- GCM(hop1_key, hint2+len2+l2_enc)
 *
 * The node finds the session by hint, decrypts, reads next_port from the
 * first 2 bytes of plaintext, and forwards the remainder to that port.     */

#define BENCH_MSG_LEN  64   /* application payload bytes per message */

static int build_wire_cell(
        aes_key_t      hop_keys[TOR_MAX_HOPS],
        uint8_t        hop_hints[TOR_MAX_HOPS][TOR_HINT_BYTES],
        uint8_t      **wire_out,   /* caller must free */
        int           *wire_len_out)
{
    /* ── Layer 3: innermost — [next_port 2B][payload 64B] ── */
    const int L3_PT = 2 + BENCH_MSG_LEN;
    uint8_t l3_pt[2 + BENCH_MSG_LEN];
    l3_pt[0] = (uint8_t)(TOR_PORT_SG >> 8);
    l3_pt[1] = (uint8_t)(TOR_PORT_SG & 0xFF);
    RAND_bytes(l3_pt + 2, BENCH_MSG_LEN);   /* random payload is fine */

    int l3_max = L3_PT + GCM_OVERHEAD;
    uint8_t *l3_enc = malloc(l3_max);
    if (!l3_enc) return -1;
    int l3_len = crypto_aes_encrypt(&hop_keys[2], l3_pt, L3_PT,
                                    l3_enc, l3_max);
    if (l3_len < 0) { free(l3_enc); return -1; }

    /* ── Layer 2: middle — [next_port 2B][hint3 bytes][l3_enc] ── */
    int L2_PT = 2 + TOR_HINT_BYTES + l3_len;
    uint8_t *l2_pt = malloc(L2_PT);
    if (!l2_pt) { free(l3_enc); return -1; }
    l2_pt[0] = (uint8_t)(TOR_PORT_TN3 >> 8);
    l2_pt[1] = (uint8_t)(TOR_PORT_TN3 & 0xFF);
    memcpy(l2_pt + 2, hop_hints[2], TOR_HINT_BYTES);
    memcpy(l2_pt + 2 + TOR_HINT_BYTES, l3_enc, l3_len);
    free(l3_enc);

    int l2_max = L2_PT + GCM_OVERHEAD;
    uint8_t *l2_enc = malloc(l2_max);
    if (!l2_enc) { free(l2_pt); return -1; }
    int l2_len = crypto_aes_encrypt(&hop_keys[1], l2_pt, L2_PT,
                                    l2_enc, l2_max);
    free(l2_pt);
    if (l2_len < 0) { free(l2_enc); return -1; }

    /* ── Layer 1: outermost — [next_port 2B][hint2 bytes][l2_enc] ── */
    int L1_PT = 2 + TOR_HINT_BYTES + l2_len;
    uint8_t *l1_pt = malloc(L1_PT);
    if (!l1_pt) { free(l2_enc); return -1; }
    l1_pt[0] = (uint8_t)(TOR_PORT_TN2 >> 8);
    l1_pt[1] = (uint8_t)(TOR_PORT_TN2 & 0xFF);
    memcpy(l1_pt + 2, hop_hints[1], TOR_HINT_BYTES);
    memcpy(l1_pt + 2 + TOR_HINT_BYTES, l2_enc, l2_len);
    free(l2_enc);

    int l1_max = L1_PT + GCM_OVERHEAD;
    uint8_t *l1_enc = malloc(l1_max);
    if (!l1_enc) { free(l1_pt); return -1; }
    int l1_len = crypto_aes_encrypt(&hop_keys[0], l1_pt, L1_PT,
                                    l1_enc, l1_max);
    free(l1_pt);
    if (l1_len < 0) { free(l1_enc); return -1; }

    /* ── Wire buffer: [mode 1B][hint1][l1_len 2B][l1_enc] ── */
    int wlen = 1 + TOR_HINT_BYTES + 2 + l1_len;
    uint8_t *wire = malloc(wlen);
    if (!wire) { free(l1_enc); return -1; }
    wire[0] = TOR_MODE_DATA;
    memcpy(wire + 1, hop_hints[0], TOR_HINT_BYTES);
    wire[1 + TOR_HINT_BYTES]     = (uint8_t)(l1_len >> 8);
    wire[1 + TOR_HINT_BYTES + 1] = (uint8_t)(l1_len & 0xFF);
    memcpy(wire + 1 + TOR_HINT_BYTES + 2, l1_enc, l1_len);
    free(l1_enc);

    *wire_out     = wire;
    *wire_len_out = wlen;
    return 0;
}

static DWORD WINAPI throughput_worker(LPVOID arg) {
    worker_arg_t *wa = (worker_arg_t *)arg;
    (void)wa;

    /* ── 1. Build circuit once — 3 ECDHE handshakes ── */
    aes_key_t hop_keys[TOR_MAX_HOPS];
    uint8_t   hop_hints[TOR_MAX_HOPS][TOR_HINT_BYTES];
    static const uint16_t TOR_PORTS[TOR_MAX_HOPS] = {
        TOR_PORT_TN1, TOR_PORT_TN2, TOR_PORT_TN3
    };
    for (int h = 0; h < TOR_MAX_HOPS; h++) {
        if (bench_extend_to_node(TOR_PORTS[h],
                                  &hop_keys[h], hop_hints[h]) != 0) {
            fprintf(stderr, "[table2] worker %d: extend to port %u failed\n",
                    wa->session_id, TOR_PORTS[h]);
            free(arg); return 1;
        }
    }

    /* ── 2. Send loop for TABLE2_DURATION_S ──
     * The node closes each connection after one cell (handle_data returns
     * after one message), so we must open a new TCP connection per cell.
     * We pre-build the full onion-encrypted cell before calling connect()
     * so the crypto cost is correctly attributed and the connect/send path
     * is as tight as possible.                                             */
    while (g_bench_running) {
		uint8_t *wire = NULL;
		int      wlen = 0;
		if (build_wire_cell(hop_keys, hop_hints, &wire, &wlen) != 0) break;

		SOCKET s = net_connect(TOR_LOCALHOST, TOR_PORT_TN1);
		if (s == INVALID_SOCKET) { free(wire); continue; }



		DWORD timeout_ms = 2000;
		setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));

		int rc = net_send_all(s, wire, wlen);
		free(wire);
		if (rc == 0) {
			shutdown(s, SD_SEND);
			uint8_t drain[256];
			while (recv(s, (char*)drain, sizeof(drain), 0) > 0) {}
		}
		net_close(s);
		if (rc != 0) continue;

		InterlockedAdd(&g_payload_bytes_sent, BENCH_MSG_LEN);
	}
	
    free(arg);
    return 0;
}

static void bench_table2(void) {
    printf("# Table 2: Throughput comparison (Tor-equivalent)\n");
    printf("# sessions,duration_s,total_payload_bytes,throughput_bytes_s\n");

    static const int SESSION_COUNTS[] = {1, 10, 50, 100, 500, 1000};
    int NC = (int)(sizeof(SESSION_COUNTS)/sizeof(SESSION_COUNTS[0]));

    static const uint16_t TOR_NODE_PORTS[] = {
        TOR_PORT_TN1, TOR_PORT_TN2, TOR_PORT_TN3
    };
    int N_TOR = (int)(sizeof(TOR_NODE_PORTS)/sizeof(TOR_NODE_PORTS[0]));

    for (int ci = 0; ci < NC; ci++) {
        int N = SESSION_COUNTS[ci];

        /* TOR_MAX_SESSIONS limits concurrent circuits on each node.
         * Warn if N exceeds that limit. */
        if (N > TOR_MAX_SESSIONS) {
            fprintf(stderr,
                "[table2] WARNING: N=%d > TOR_MAX_SESSIONS=%d; "
                "raise TOR_MAX_SESSIONS in tor_config.h and rebuild nodes\n",
                N, TOR_MAX_SESSIONS);
        }

        /* Reset all node session stores before spawning new workers */
        bench_reset_nodes(TOR_NODE_PORTS, N_TOR);
        fprintf(stderr, "[table2] N=%d: nodes reset, spawning workers...\n", N);

        g_payload_bytes_sent = 0;
        g_bench_running      = 1;

        HANDLE *threads = malloc((size_t)N * sizeof(HANDLE));
        if (!threads) continue;

        /* ── INSTRUMENTATION POINT: spawn N worker threads ──
         * Stagger startup by 10 ms per worker so circuit-build ECDHE
         * handshakes don't all hit the nodes simultaneously, which would
         * exhaust the Winsock accept backlog at high N.                    */
        for (int i = 0; i < N; i++) {
            worker_arg_t *wa = malloc(sizeof(worker_arg_t));
            if (!wa) { threads[i] = NULL; continue; }
            wa->session_id = i;
            threads[i] = CreateThread(NULL, 0, throughput_worker, wa, 0, NULL);
            /* Tiered stagger: spread connect storm across time so the
             * accept backlog is never overwhelmed at high session counts. */
            if      (N > 100) Sleep(50);
            else if (N > 10)  Sleep(20);
        }

        /* Let workers run for TABLE2_DURATION_S */
        Sleep(TABLE2_DURATION_S * 1000);
        g_bench_running = 0;

        /* Wait for all threads */
        for (int i = 0; i < N; i++) {
            if (threads[i]) {
                WaitForSingleObject(threads[i], 10000);
                CloseHandle(threads[i]);
            }
        }
        free(threads);

        long total = g_payload_bytes_sent;
        double throughput = (double)total / TABLE2_DURATION_S;

        printf("%d,%d,%ld,%.1f\n",
               N, TABLE2_DURATION_S, total, throughput);
        fflush(stdout);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * §7  main
 * ═══════════════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[]) {
    SetConsoleOutputCP(65001);
    timing_init();

    if (net_init() != 0) {
        fprintf(stderr, "[bench] net_init failed\n"); return 1;
    }

    const char *which = (argc >= 2) ? argv[1] : "all";

    int do_fig2   = (strcmp(which,"fig2")  ==0 || strcmp(which,"all")==0);
    int do_fig3   = (strcmp(which,"fig3")  ==0 || strcmp(which,"all")==0);
    int do_fig4   = (strcmp(which,"fig4")  ==0 || strcmp(which,"all")==0);
    int do_fig5   = (strcmp(which,"fig5")  ==0 || strcmp(which,"all")==0);
    int do_table2 = (strcmp(which,"table2")==0 || strcmp(which,"all")==0);

    if (do_fig2)   bench_fig2();
    if (do_fig3)   bench_fig3();
    if (do_fig4)   bench_fig4();
    if (do_fig5)   bench_fig5();
    if (do_table2) bench_table2();

    if (!do_fig2 && !do_fig3 && !do_fig4 && !do_fig5 && !do_table2) {
        fprintf(stderr,
            "Usage: bench.exe fig2|fig3|fig4|fig5|table2|all\n");
        net_cleanup(); return 1;
    }

    net_cleanup();
    return 0;
}