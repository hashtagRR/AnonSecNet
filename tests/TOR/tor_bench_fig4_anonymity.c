/* tor_bench_fig4_anonymity.c  --  Figure 4: Anonymity Set Size (Tor-equivalent)
 *
 * Section 13.3 of AnonSecNet_Implementation_Spec:
 *   "Anonymity set size as a function of malicious node fraction f,
 *    plotted for Anon-Sec-Net (f^6 bound) and Tor-equivalent (f^3 bound)."
 *   "At f=0.1, Anon-Sec-Net achieves 10^-6 per session while
 *    Tor-equivalent achieves 10^-3."
 *
 * NOTE ON SPEC vs ATTACK MODEL:
 *   The spec cites f^3 as the Tor-equivalent bound for Figure 4 (all 3 hops
 *   controlled). The existing bench_anonymity_set.c correctly implements f^2
 *   (entry-exit correlation, the dominant real-world Tor attack from the
 *   original Dingledine et al. paper). This file implements BOTH:
 *
 *   tor_f3  : adversary controls all 3 hops  => P(deanon) = f^3
 *             (this is the bound used in the spec Figure 4 comparison)
 *
 *   tor_f2  : adversary controls entry + exit => P(deanon) = f^2
 *             (this is the standard Tor entry-exit correlation attack,
 *              also called the "predecessor attack" or "timing correlation")
 *
 *   Both are reported so the manuscript can choose the appropriate bound.
 *   The spec's f^3 claim is a worst-case (all hops compromised); the f^2
 *   entry-exit attack is the practically dominant threat in real deployments.
 *
 * Tor architecture alignment:
 *   - Tor uses a 3-hop circuit: Guard, Middle, Exit.
 *   - Entry-exit attack: a GPA observing both Guard and Exit can correlate
 *     traffic timing (reference: Murdoch & Danezis 2005, Dingledine 2004).
 *   - Full-path attack: all 3 nodes malicious = full circuit compromise.
 *   - ASN dual-path: adversary must compromise ALL 6 nodes (3 on each path).
 *
 * Output: CSV rows to append to ASN_montecarlo_figure4.csv
 *   f,asn_theory,tor_f2_theory,tor_f3_theory,
 *   asn_mc,asn_mc_ci95,tor_f2_mc,tor_f2_mc_ci95,tor_f3_mc,tor_f3_mc_ci95,n_sessions
 *
 * Build (any platform):
 *   gcc -O2 -o tor_bench_fig4.exe tor_bench_fig4_anonymity.c -lm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

/* ── Configuration ───────────────────────────────────────────────────────── */
#define NUM_NODES      100
#define SESSIONS       10000
/* f from 0.00 to 0.50, step 0.01 */
#define NUM_F_VALUES   51

/* ── Wilson score confidence interval ───────────────────────────────────── */
static double wilson_ci95(int k, int n) {
    if (n == 0) return 0.0;
    double p = (double)k / n;
    double z = 1.96;
    double denom = 1.0 + z*z/n;
    double centre = (p + z*z/(2*n)) / denom;
    double spread = z * sqrt(p*(1-p)/n + z*z/(4*n*n)) / denom;
    (void)centre;  /* we return the half-width */
    return spread;
}

/* ── Unique random node selection (Tor circuits only) ────────────────────── */
static int rand_node(int n) { return rand() % n; }

/* ── Main ───────────────────────────────────────────────────────────────── */
int main(void) {
    srand((unsigned)time(NULL));

    printf("# Tor-equivalent Figure 4: Anonymity set Monte Carlo\n");
    printf("# Source: tor_bench_fig4_anonymity.c\n");
    printf("# tor_f2: entry-exit correlation attack (dominant real-world Tor threat)\n");
    printf("# tor_f3: full-path compromise (all 3 hops malicious, used in spec Fig4)\n");
    printf("# n_nodes=%d, sessions=%d per f-value\n", NUM_NODES, SESSIONS);
    printf("f,tor_f2_theory,tor_f3_theory,"
           "tor_f2_mc,tor_f2_mc_ci95,"
           "tor_f3_mc,tor_f3_mc_ci95,n_sessions\n");

    for (int fi = 0; fi < NUM_F_VALUES; fi++) {
        double f = fi * 0.01;
        int num_malicious = (int)(f * NUM_NODES);

        /* Assign malicious nodes */
        int is_malicious[NUM_NODES];
        memset(is_malicious, 0, sizeof(is_malicious));
        int used[NUM_NODES];
        memset(used, 0, sizeof(used));
        int assigned = 0;
        while (assigned < num_malicious) {
            int idx = rand_node(NUM_NODES);
            if (!used[idx]) { used[idx] = 1; is_malicious[idx] = 1; assigned++; }
        }

        int tor_f2_deanon = 0;   /* entry + exit compromised */
        int tor_f3_deanon = 0;   /* all 3 hops compromised */

        for (int s = 0; s < SESSIONS; s++) {

            /* ── Tor circuit: 3 distinct hops ─────────────────────────── */
            int tor_nodes[3];
            tor_nodes[0] = rand_node(NUM_NODES);  /* guard */
            do { tor_nodes[1] = rand_node(NUM_NODES); }
            while (tor_nodes[1] == tor_nodes[0]);
            do { tor_nodes[2] = rand_node(NUM_NODES); }
            while (tor_nodes[2] == tor_nodes[0] || tor_nodes[2] == tor_nodes[1]);

            /* Entry-exit: guard AND exit compromised */
            if (is_malicious[tor_nodes[0]] && is_malicious[tor_nodes[2]])
                tor_f2_deanon++;

            /* Full-path: all 3 compromised */
            if (is_malicious[tor_nodes[0]] && is_malicious[tor_nodes[1]] &&
                is_malicious[tor_nodes[2]])
                tor_f3_deanon++;
        }

        double tor_f2_emp = (double)tor_f2_deanon / SESSIONS;
        double tor_f3_emp = (double)tor_f3_deanon / SESSIONS;

        double tor_f2_ci95 = wilson_ci95(tor_f2_deanon, SESSIONS);
        double tor_f3_ci95 = wilson_ci95(tor_f3_deanon, SESSIONS);

        double tor_f2_theory = f * f;
        double tor_f3_theory = f * f * f;

        printf("%.2f,%.8e,%.8e,%.8e,%.8e,%.8e,%.8e,%d\n",
               f,
               tor_f2_theory, tor_f3_theory,
               tor_f2_emp,    tor_f2_ci95,
               tor_f3_emp,    tor_f3_ci95,
               SESSIONS);

        if ((fi+1) % 10 == 0)
            fprintf(stderr, "[fig4] f=%.2f done\n", f);
    }

    fprintf(stderr, "[fig4] complete\n");
    return 0;
}
