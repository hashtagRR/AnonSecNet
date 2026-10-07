/* node_pool.h: Anon-Sec-Net v2  Task 1: guard-set entry policy +
 * weighted-random middle/last-hop selection.
 *
 * Replaces the fixed PORT_MIX_1..PORT_MIX_C compile-time topology
 * (config.h) with:
 *   - a synthetic M-node consensus document (population size POOL_SIZE),
 *     deterministic and identical for every client, standing in for the
 *     directory-operator-signed consensus described in the paper's
 *     "Consensus Document and Bootstrap" section, which this testbed has
 *     no directory service to actually produce;
 *   - a per-client persistent guard set of size GUARD_SET_SIZE for each
 *     of MN1 and MNa, drawn once and reused every session;
 *   - fresh, bandwidth-weighted, disjoint selection of the four
 *     remaining positions (MN2, MN3, MNb, MNc) every session, matching
 *     the Uniformity assumption for those positions only.
 *
 * See eval2/scripts/asn_guard_policy_n50.py for the repeated-use risk
 * analysis this design was chosen to support.
 */
#ifndef NODE_POOL_H
#define NODE_POOL_H

#include <stdint.h>

#define POOL_SIZE        100   /* M: total mix-node population           */
#define GUARD_SET_SIZE     3   /* G: default guard set size per entry    */
#define POOL_PORT_BASE   9100  /* consensus-assigned ports: 9100..9199   */
#define CONSENSUS_SEED   20260718u  /* fixed: same population for every
                                        client, matching this project's
                                        established seed convention */

typedef struct {
    int      id;                 /* 0..POOL_SIZE-1                       */
    uint16_t port;                /* PORT_POOL_BASE + id                  */
    double   bandwidth_weight;    /* synthetic, Pareto-tail distributed   */
} pool_node_t;

typedef struct {
    pool_node_t nodes[POOL_SIZE];
    int         count;
} consensus_t;

typedef struct {
    int guard_ids[GUARD_SET_SIZE];
    int count;
} guard_set_t;

typedef struct {
    int entry_a, mid_a, last_a;   /* path A: MN1, MN2, MN3 (as node ids)  */
    int entry_b, mid_b, last_b;   /* path B: MNa, MNb, MNc (as node ids)  */
} session_path_t;

/* Deterministically generates the M-node synthetic consensus (fixed
 * CONSENSUS_SEED, identical every call/every client, this stands in
 * for a real fetched-and-verified directory consensus). */
void consensus_generate(consensus_t *c);

/* Seeds an rng_state from OpenSSL RAND_bytes (real entropy) for actual
 * client use. Self-tests instead use a fixed literal seed directly, for
 * reproducibility: do not call this in a test that needs to compare
 * output across runs. */
void node_pool_seed_from_urandom(uint64_t *state);

/* Returns the port for a given node id (0..POOL_SIZE-1). */
uint16_t pool_port(const consensus_t *c, int node_id);

/* Loads a persisted guard set from `path` if it exists; otherwise draws
 * `guard_size` distinct nodes from `c` by bandwidth-weighted sampling
 * without replacement, excluding any id present in `exclude`
 * (exclude_count entries; pass NULL/0 for none, used to keep path A's
 * and path B's guard sets disjoint), persists the draw to `path`, and
 * returns it. `rng_state` seeds the weighted draw only (the file, once
 * written, is authoritative from then on, rng_state does not affect
 * an already-persisted guard set). Returns 0 on success, -1 on error. */
int guard_set_load_or_create(guard_set_t *g, const consensus_t *c,
                              const char *path, int guard_size,
                              const int *exclude, int exclude_count,
                              uint64_t *rng_state);

/* One session's full 6-node path selection. entry_a/entry_b are drawn
 * uniformly at random from guard_a/guard_b (persisted, unchanged across
 * the call). mid_a/last_a/mid_b/last_b are drawn fresh this call,
 * bandwidth-weighted, mutually disjoint and disjoint from both guard
 * sets' entry pick. Returns 0 on success, -1 if the pool is too small
 * for six disjoint picks (cannot happen at POOL_SIZE=100, checked
 * defensively). */
int build_session_path(const consensus_t *c,
                        const guard_set_t *guard_a,
                        const guard_set_t *guard_b,
                        uint64_t *rng_state,
                        session_path_t *out);

#endif
