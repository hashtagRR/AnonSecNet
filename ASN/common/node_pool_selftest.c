/* node_pool_selftest.c: committed test binary checking the four
 * properties `node_pool_selftest()` verifies (20,000 simulated sessions
 * against the M=100/G=3 pool): (a) entry always drawn from the persisted guard set,
 * (b) all six nodes in a session are distinct, (c) path A and path B
 * selections are disjoint, (d) middle/last-hop frequency tracks
 * bandwidth weights. Uses a fixed literal RNG seed (not
 * node_pool_seed_from_urandom(), per that function's own header comment
 * on why self-tests shouldn't use it) so results are reproducible
 * run-to-run. Writes its guard-set files under a temp-prefixed name and
 * removes them on exit, so it never touches a real client's
 * client_guard_a.txt/client_guard_b.txt. */
#include "node_pool.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 20,000 sessions is too close to a 25% tolerance boundary to be a
 * reliable regression check: the max-relative-error-over-97-nodes
 * statistic is a noisy tail quantity. 100,000 sessions gives real
 * margin while still running in well under a second. */
#define N_SESSIONS 100000
#define FREQ_TOLERANCE 0.25

static int contains(const int *arr, int n, int v) {
    for (int i = 0; i < n; i++) if (arr[i] == v) return 1;
    return 0;
}

int main(void) {
    const char *guard_a_path = "node_pool_selftest_guard_a.tmp";
    const char *guard_b_path = "node_pool_selftest_guard_b.tmp";
    remove(guard_a_path);
    remove(guard_b_path);

    consensus_t c;
    consensus_generate(&c);

    uint64_t rng_state = 20260822ULL; /* fixed literal, reproducible */
    guard_set_t guard_a, guard_b;
    if (guard_set_load_or_create(&guard_a, &c, guard_a_path, GUARD_SET_SIZE,
                                  NULL, 0, &rng_state) != 0) {
        fprintf(stderr, "FAIL: guard_set_load_or_create (A)\n");
        return 1;
    }
    if (guard_set_load_or_create(&guard_b, &c, guard_b_path, GUARD_SET_SIZE,
                                  guard_a.guard_ids, guard_a.count,
                                  &rng_state) != 0) {
        fprintf(stderr, "FAIL: guard_set_load_or_create (B)\n");
        return 1;
    }

    int pass_a = 1, pass_b = 1, pass_c = 1;
    double freq[POOL_SIZE] = {0};
    long n_nonguard_picks = 0;

    for (int s = 0; s < N_SESSIONS; s++) {
        session_path_t p;
        if (build_session_path(&c, &guard_a, &guard_b, &rng_state, &p) != 0) {
            fprintf(stderr, "FAIL: build_session_path returned error at session %d\n", s);
            return 1;
        }

        /* (a) entry always drawn from the persisted guard set */
        if (!contains(guard_a.guard_ids, guard_a.count, p.entry_a)) pass_a = 0;
        if (!contains(guard_b.guard_ids, guard_b.count, p.entry_b)) pass_a = 0;

        /* (b) all six nodes distinct */
        int all6[6] = {p.entry_a, p.mid_a, p.last_a, p.entry_b, p.mid_b, p.last_b};
        for (int i = 0; i < 6 && pass_b; i++)
            for (int j = i + 1; j < 6; j++)
                if (all6[i] == all6[j]) { pass_b = 0; break; }

        /* (c) path A and path B selections disjoint */
        int path_a[3] = {p.entry_a, p.mid_a, p.last_a};
        int path_b[3] = {p.entry_b, p.mid_b, p.last_b};
        for (int i = 0; i < 3 && pass_c; i++)
            if (contains(path_b, 3, path_a[i])) { pass_c = 0; break; }

        /* (d) middle/last-hop frequency tracks bandwidth weights,
         * only mid_a/last_a/mid_b/last_b are freshly weighted-drawn
         * each session (entry_a/entry_b come from the fixed guard set,
         * excluded from this check). */
        freq[p.mid_a]++;  freq[p.last_a]++;
        freq[p.mid_b]++;  freq[p.last_b]++;
        n_nonguard_picks += 4;
    }

    double total_weight = 0.0;
    for (int i = 0; i < c.count; i++) total_weight += c.nodes[i].bandwidth_weight;

    int pass_d = 1;
    double max_rel_err = 0.0;
    int max_rel_err_node = -1;
    for (int i = 0; i < c.count; i++) {
        /* Guard-set members are structurally excluded from mid/last
         * draws (build_session_path excludes both guard sets' entry
         * picks), skip them, their expected non-guard frequency isn't
         * comparable to the weight-proportional baseline. */
        if (contains(guard_a.guard_ids, guard_a.count, i)) continue;
        if (contains(guard_b.guard_ids, guard_b.count, i)) continue;

        double expected_frac = c.nodes[i].bandwidth_weight / total_weight;
        double observed_frac = freq[i] / (double)n_nonguard_picks;
        double rel_err = (expected_frac > 0.0)
            ? fabs(observed_frac - expected_frac) / expected_frac
            : 0.0;
        if (rel_err > max_rel_err) { max_rel_err = rel_err; max_rel_err_node = i; }
        if (rel_err > FREQ_TOLERANCE) pass_d = 0;
    }

    printf("%s (a) entry always drawn from persisted guard set\n", pass_a ? "PASS" : "FAIL");
    printf("%s (b) six nodes in a session are distinct\n", pass_b ? "PASS" : "FAIL");
    printf("%s (c) path A and path B selections are disjoint\n", pass_c ? "PASS" : "FAIL");
    printf("%s (d) middle/last-hop frequency tracks bandwidth weights (max rel. err %.1f%% at node %d, tolerance %.0f%%)\n",
           pass_d ? "PASS" : "FAIL", max_rel_err * 100.0, max_rel_err_node, FREQ_TOLERANCE * 100.0);

    remove(guard_a_path);
    remove(guard_b_path);

    return (pass_a && pass_b && pass_c && pass_d) ? 0 : 1;
}
