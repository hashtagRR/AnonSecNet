/* node_pool.c: see node_pool.h for design rationale. */
#include "node_pool.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/rand.h>

/* ---- splitmix64: deterministic PRNG, used ONLY for consensus_generate
 * (which must be bit-identical across every client from CONSENSUS_SEED)
 * and as the update step for caller-supplied rng_state in the weighted
 * draws below. NOT used anywhere a real client's actual randomness
 * matters cryptographically, guard/session draws seed rng_state from
 * RAND_bytes (node_pool_seed_from_urandom), matching this project's
 * established RAND_bytes convention for security-relevant randomness;
 * splitmix64 only stretches that one CSPRNG-derived 64-bit seed into a
 * stream, it does not replace it. */
static uint64_t splitmix64_next(uint64_t *state) {
    uint64_t z = (*state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static double rng_uniform01(uint64_t *state) {
    /* 53 bits of the 64-bit stream -> double in [0, 1). */
    return (double)(splitmix64_next(state) >> 11) * (1.0 / 9007199254740992.0);
}

void node_pool_seed_from_urandom(uint64_t *state) {
    uint64_t seed = 0;
    if (RAND_bytes((uint8_t *)&seed, sizeof(seed)) != 1 || seed == 0) {
        seed = 0x2A2A2A2A2A2A2A2AULL; /* defensive fallback, never silently 0 */
    }
    *state = seed;
}

void consensus_generate(consensus_t *c) {
    uint64_t state = CONSENSUS_SEED;
    /* Burn a few values so the first weight is not a direct function of
     * the raw seed bit pattern. */
    splitmix64_next(&state);
    splitmix64_next(&state);

    /* Pareto-tail bandwidth distribution (alpha=1.5), the standard
     * heavy-tailed shape used to approximate real relay/AS bandwidth
     * skew in the mix-network literature: weight = x_min / u^(1/alpha),
     * u ~ Uniform(0,1). x_min=1.0 is an arbitrary scale, only RELATIVE
     * weights matter for weighted sampling. */
    const double alpha = 1.5;
    for (int i = 0; i < POOL_SIZE; i++) {
        double u = rng_uniform01(&state);
        if (u < 1e-9) u = 1e-9; /* avoid division blowup */
        double weight = pow(u, -1.0 / alpha);
        c->nodes[i].id = i;
        c->nodes[i].port = (uint16_t)(POOL_PORT_BASE + i);
        c->nodes[i].bandwidth_weight = weight;
    }
    c->count = POOL_SIZE;
}

uint16_t pool_port(const consensus_t *c, int node_id) {
    return c->nodes[node_id].port;
}

static int id_in_set(int id, const int *set, int count) {
    for (int i = 0; i < count; i++) if (set[i] == id) return 1;
    return 0;
}

/* Weighted draw of one node id from `c`, excluding any id in
 * (excl1 union excl2), two exclusion lists so callers do not need to
 * concatenate arrays for the common "exclude guard set + exclude
 * already-picked-this-session" case. Rejection sampling: at POOL_SIZE=100
 * and at most ~9 excluded ids in any call this project makes, expected
 * iterations stay small (<2 on average). */
static int weighted_draw_excluding(const consensus_t *c, uint64_t *rng_state,
                                    const int *excl1, int excl1_count,
                                    const int *excl2, int excl2_count) {
    double total = 0.0;
    for (int i = 0; i < c->count; i++) {
        if (id_in_set(i, excl1, excl1_count)) continue;
        if (id_in_set(i, excl2, excl2_count)) continue;
        total += c->nodes[i].bandwidth_weight;
    }
    if (total <= 0.0) return -1;

    for (int attempt = 0; attempt < 10000; attempt++) {
        double target = rng_uniform01(rng_state) * total;
        double cum = 0.0;
        for (int i = 0; i < c->count; i++) {
            if (id_in_set(i, excl1, excl1_count)) continue;
            if (id_in_set(i, excl2, excl2_count)) continue;
            cum += c->nodes[i].bandwidth_weight;
            if (target <= cum) return i;
        }
        /* Floating-point edge case: target landed past the last
         * cumulative bucket by epsilon. Retry. */
    }
    return -1;
}

/* Writes to a PID-suffixed temp file in the same directory, then
 * rename()s into place. rename() is atomic on POSIX filesystems when
 * source and destination are on the same filesystem (guaranteed here,
 * same directory), so a reader never observes a partially-written
 * file, and two concurrent writers each produce a complete file,
 * whichever rename() lands last wins outright rather than either
 * process observing a torn read. This does not by itself prevent two
 * concurrent first-run processes from independently drawing DIFFERENT
 * guard sets (see guard_set_load_or_create's caller-facing note on
 * that race); it only guarantees whichever draw is saved is never
 * corrupt. */
static int save_guard_set(const guard_set_t *g, const char *path) {
    char tmp_path[512];
    int n = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d", path, (int)getpid());
    if (n < 0 || (size_t)n >= sizeof(tmp_path)) return -1;

    FILE *fp = fopen(tmp_path, "w");
    if (!fp) return -1;
    fprintf(fp, "%d\n", g->count);
    for (int i = 0; i < g->count; i++) fprintf(fp, "%d\n", g->guard_ids[i]);
    if (fclose(fp) != 0) { remove(tmp_path); return -1; }

    if (rename(tmp_path, path) != 0) { remove(tmp_path); return -1; }
    return 0;
}

static int load_guard_set(guard_set_t *g, const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    if (fscanf(fp, "%d", &g->count) != 1 ||
        g->count <= 0 || g->count > GUARD_SET_SIZE) {
        fclose(fp);
        return -1;
    }
    for (int i = 0; i < g->count; i++) {
        if (fscanf(fp, "%d", &g->guard_ids[i]) != 1) {
            fclose(fp);
            return -1;
        }
        /* Bounds-check every id read from disk: a corrupted, hand-edited,
         * or stale file (e.g. left over from a build with a different
         * POOL_SIZE) could otherwise inject an out-of-range id that
         * later indexes straight into consensus_t.nodes[POOL_SIZE] with
         * no further check anywhere on the call path (pool_port() et
         * al.), an out-of-bounds struct read, not caught until it is
         * already undefined behavior. */
        if (g->guard_ids[i] < 0 || g->guard_ids[i] >= POOL_SIZE) {
            fprintf(stderr, "node_pool: rejecting %s, guard id %d at index %d "
                            "is out of range [0,%d)\n",
                    path, g->guard_ids[i], i, POOL_SIZE);
            fclose(fp);
            return -1;
        }
    }
    fclose(fp);
    return 0;
}

int guard_set_load_or_create(guard_set_t *g, const consensus_t *c,
                              const char *path, int guard_size,
                              const int *exclude, int exclude_count,
                              uint64_t *rng_state) {
    if (load_guard_set(g, path) == 0) return 0;

    /* No valid persisted set found, drawing a fresh one. `path` is
     * caller-supplied and typically relative to the process's current
     * working directory (see client.c's call site), so launching the
     * client from a different cwd than a previous run will silently
     * look like "first run" here and produce a brand-new guard set
     * with no error. This log line is the mitigation: it cannot fix the
     * cwd dependency itself (that is a caller-side path-anchoring
     * decision), but it makes an unexpected fresh draw visible in the
     * client's own output rather than fully silent. */
    fprintf(stderr, "node_pool: no valid guard set at %s, drawing a new one "
                    "(expected on first run; unexpected if this is meant to "
                    "resume a prior client identity from a different cwd)\n",
            path);

    if (guard_size > GUARD_SET_SIZE) guard_size = GUARD_SET_SIZE;
    g->count = 0;
    for (int k = 0; k < guard_size; k++) {
        int picked = weighted_draw_excluding(c, rng_state,
                                              exclude, exclude_count,
                                              g->guard_ids, g->count);
        if (picked < 0) return -1;
        g->guard_ids[g->count++] = picked;
    }
    return save_guard_set(g, path);
}

int build_session_path(const consensus_t *c,
                        const guard_set_t *guard_a,
                        const guard_set_t *guard_b,
                        uint64_t *rng_state,
                        session_path_t *out) {
    if (guard_a->count < 1 || guard_b->count < 1) return -1;

    /* Entry hops: uniform pick WITHIN the persisted guard set, fresh
     * each session, this is the "select the session's entry from that
     * set" step; which specific guard is used can vary session to
     * session, but the set itself never changes. */
    int idx_a = (int)(rng_uniform01(rng_state) * guard_a->count);
    if (idx_a >= guard_a->count) idx_a = guard_a->count - 1;
    int idx_b = (int)(rng_uniform01(rng_state) * guard_b->count);
    if (idx_b >= guard_b->count) idx_b = guard_b->count - 1;
    out->entry_a = guard_a->guard_ids[idx_a];
    out->entry_b = guard_b->guard_ids[idx_b];

    /* Fresh, weighted, mutually disjoint middle/last picks, also
     * disjoint from both entries actually in use this session. */
    int used[6];
    int used_count = 0;
    used[used_count++] = out->entry_a;
    used[used_count++] = out->entry_b;

    out->mid_a = weighted_draw_excluding(c, rng_state, used, used_count, NULL, 0);
    if (out->mid_a < 0) return -1;
    used[used_count++] = out->mid_a;

    out->last_a = weighted_draw_excluding(c, rng_state, used, used_count, NULL, 0);
    if (out->last_a < 0) return -1;
    used[used_count++] = out->last_a;

    out->mid_b = weighted_draw_excluding(c, rng_state, used, used_count, NULL, 0);
    if (out->mid_b < 0) return -1;
    used[used_count++] = out->mid_b;

    out->last_b = weighted_draw_excluding(c, rng_state, used, used_count, NULL, 0);
    if (out->last_b < 0) return -1;

    return 0;
}

