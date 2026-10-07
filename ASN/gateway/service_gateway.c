/* service_gateway.c: Service Gateway (:9010), Anon-Sec-Net v2 */

#include "common/net.h"
#include "common/crypto.h"
#include "common/packet.h"
#include "common/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include "common/posix_compat.h"

static void log_msg(const char *m){printf("[SvcGW] %s\n",m);fflush(stdout);}
static void log_err(const char *m){fprintf(stderr,"[SvcGW] ERROR: %s\n",m);fflush(stderr);}

/* Session store. Matches mix_node.c's MAX_SESSIONS. */
#define MAX_SESSIONS 1024

/* One queued real response (see sg_session_t.pending). */
#define PENDING_RESP_QUEUE 32
typedef struct {
    uint8_t resp[MAX_INNER_PAYLOAD];
    size_t  len;
    uint8_t hdr[RETURN_HEADER_SIZE];
    DWORD   since_ms;
} pending_resp_t;

typedef struct {
    uint8_t   hint[HINT_BYTES];
    aes_key_t e2e_key;
    uint8_t   role;
    /* O(1) pre-filter hint for find_a_session(), set for role-A sessions
     * only (role B never sends MODE_DATA to the SG). See config.h's
     * SG_HINT_BYTES comment / packet_derive_sg_hint(). */
    sg_hint_t sg_hint;
    /* Set by TYPE_SETUP (role=A session only). Sending-path blind keys
     * (SK_R-MN1/2/3) aren't stored here, the SG only needs recv_blind[]
     * below, to pre-blind the return path. */
    aes_key_t recv_blind[N_PATH_HOPS]; /* SK_R-MNc/b/a: pre-blind outgoing*/
    uint8_t   binding_tag[MAC_BYTES];
    uint8_t   mnc_pubkey[EC_PUBKEY_LEN];
    uint8_t   mnc_addr[ADDR_BYTES];
    uint8_t   return_hdr[RETURN_HEADER_SIZE];
    aes_key_t b_key;    /* K_R-SG-B, found after binding tag verified */
    int       setup_done;
    int       in_use;
    int       bound_b_idx; /* g_sessions[] index of this A session's
                             * cryptographically-verified B partner, set
                             * once the binding-tag check below succeeds;
                             * -1 until then. find_b_for_a() uses this
                             * instead of re-deriving the pairing by
                             * array position on every call, see its
                             * comment for why position alone is wrong
                             * under concurrent session churn. */
    DWORD     last_active_ms; /* GetTickCount() at alloc and on every
                                * find_a_session() match; see
                                * SESSION_TTL_MS / sess_alloc()'s reclaim
                                * path, matching mix_node.c's fix. */
    int       in_flight; /* Reference count: incremented under
                           * g_sess_lock by find_a_session()/find_b_for_a()
                           * right before handing a raw pointer to the
                           * caller, decremented under lock at
                           * handle_connection()'s `done:` cleanup.
                           * sess_alloc()'s TTL-reclaim scan skips any
                           * slot with in_flight > 0, so a pinned slot
                           * can't be reclaimed out from under an
                           * in-progress request. */

    /* Return-path mailbox: a real response is queued here instead of
     * dispatched immediately, and drained by this session's next
     * cover-trigger (below), which sends it with PKT_REAL/return_hdr in
     * place of the usual PKT_DUMMY junk, keeps a real response from
     * adding an extra packet on top of the steady cover cadence.
     * pending_resp_flush_thread() (below) is a bounded fallback:
     * if no cover trigger arrives within PENDING_RESPONSE_MAX_WAIT_MS,
     * it dispatches directly rather than stall the client indefinitely.
     * A FIFO of PENDING_RESP_QUEUE entries, so a client with several
     * requests in flight (striping, STREAM probe traffic) gets one reply
     * per request instead of only the latest. Each entry keeps the
     * return header that came with its own request and its own enqueue
     * time, so replies leave in request order with consecutive return
     * hints, and a later request does not postpone an earlier reply.
     * Protected by g_sess_lock like every other mutable field in this
     * struct, since a real response and this session's next
     * cover-trigger run on two unrelated connection threads that can
     * race. */
    pending_resp_t pending[PENDING_RESP_QUEUE];
    int            pending_head;
    int            pending_count;
} sg_session_t;

/* See sg_session_t.pending's comment. */
#define PENDING_RESPONSE_MAX_WAIT_MS (400U)

/* See mix_node.c's SESSION_TTL_MS for rationale, same backstop against
 * unbounded slot exhaustion, same value. */
#define SESSION_TTL_MS (5U * 60U * 1000U)

static sg_session_t     g_sessions[MAX_SESSIONS];
static CRITICAL_SECTION g_sess_lock;
static ecdh_keypair_t   g_node_kp = {0};
static CRITICAL_SECTION g_node_kp_lock; /* see mix_node.c's identical field */
static ecdh_keypair_t   g_identity_kp = {0}; /* see mix_node.c's identical field */
static char g_pubkey_path[256] = {0}; /* see mix_node.c's identical field */

#define NODE_KEY_ROTATION_MS (5U * 60U * 1000U)

/* See mix_node.c's node_key_rotation_thread(); identical mechanism here. */
static DWORD WINAPI node_key_rotation_thread(LPVOID arg) {
    (void)arg;
    while (1) {
        Sleep(NODE_KEY_ROTATION_MS);

        ecdh_keypair_t new_kp = {0};
        if (crypto_ecdh_keygen(&new_kp) != 0) continue;

        ecdh_keypair_t old_kp;
        EnterCriticalSection(&g_node_kp_lock);
        old_kp    = g_node_kp;
        g_node_kp = new_kp;
        LeaveCriticalSection(&g_node_kp_lock);

        crypto_ecdh_free(&old_kp);
        if (g_pubkey_path[0]) crypto_pubkey_save(&g_node_kp, g_pubkey_path);
        log_msg("node identity ECDH key rotated");
    }
    return 0;
}

/* Exit-side measurement probe, opt-in via ASN_SG_TRACE=1 (same pattern as
 * mix_node.c's ASN_HOPDECOY_TRACE). Logs one line per real request that
 * reaches the TYPE_GET/PUT handler with a bound B session, to
 * sg_trace.csv in ASN_TRACE_DIR (default /tmp), columns: b_idx,a_idx,t_ms. The SG is the common exit
 * of every sending leg, and all legs of one client share one B session,
 * so grouping by b_idx gives the merged exit-side flow of that client. */
static int sg_trace_enabled(void) {
    static int cached = -1;
    if (cached < 0) cached = (getenv("ASN_SG_TRACE") != NULL) ? 1 : 0;
    return cached;
}

static void sg_trace_log(int b_idx, int a_idx) {
    if (!sg_trace_enabled()) return;
    const char *dir = getenv("ASN_TRACE_DIR");   /* see mix_node.c's trace probe */
    char path[512];
    snprintf(path, sizeof(path), "%s/sg_trace.csv", dir ? dir : "/tmp");
    FILE *f = fopen(path, "a");
    if (!f) return;
    fprintf(f, "%d,%d,%llu\n", b_idx, a_idx, (unsigned long long)GetTickCount64());
    fclose(f);
}

/* Try every in-use B session (not just a single positional guess) and
 * return the one whose binding-tag HMAC actually matches, or NULL if
 * none does. Caller must hold g_sess_lock. Used both by find_a_session's
 * TYPE_SETUP pre-check and by find_b_for_a's unbound fallback. */
static sg_session_t *find_verified_b(const aes_key_t *a_key,
                                      const uint8_t *want_tag,
                                      const sg_session_t *skip) {
    for (int j = 0; j < MAX_SESSIONS; j++) {
        if (!g_sessions[j].in_use) continue;
        if (g_sessions[j].role != SESSION_ROLE_B) continue;
        if (&g_sessions[j] == skip) continue;
        /* See client.c's matching comment. */
        uint8_t computed[MAC_BYTES];
        if (packet_derive_binding_tag(a_key, &g_sessions[j].e2e_key,
                                      computed) != 0) continue;
        if (crypto_memcmp(computed, want_tag, MAC_BYTES) == 0)
            return &g_sessions[j];
    }
    return NULL;
}

/* Returns with g_sess_lock HELD on a non-NULL return (same pattern as
 * mix_node.c's session_alloc()): the MODE_EXTEND caller populates
 * hint/e2e_key/role/sg_hint after this, so the lock must stay held until
 * that's done, or a concurrent MODE_DATA packet scanning g_sessions[]
 * could observe in_use=1 with those fields still zeroed. Caller MUST
 * LeaveCriticalSection(&g_sess_lock) once population is done; a NULL
 * return means the lock is already released. */
static sg_session_t *sess_alloc(void) {
    EnterCriticalSection(&g_sess_lock);
    DWORD now = GetTickCount();
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_sessions[i].in_use) {
            memset(&g_sessions[i], 0, sizeof(g_sessions[i]));
            g_sessions[i].in_use = 1;
            g_sessions[i].last_active_ms = now;
            g_sessions[i].bound_b_idx = -1;
            return &g_sessions[i];
        }
    }
    /* Table full: reclaim the single oldest slot past SESSION_TTL_MS
     * instead of refusing every subsequent client for the process's
     * lifetime: see mix_node.c's session_alloc() for the identical
     * approach. Slots with in_flight > 0 (a request actively mid-flight
     * against this session, see the struct comment) are never eligible,
     * regardless of age. */
    int oldest_idx = -1;
    DWORD oldest_age = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i].in_flight > 0) continue;
        DWORD age = now - g_sessions[i].last_active_ms;
        if (age >= SESSION_TTL_MS && age >= oldest_age) {
            oldest_age = age;
            oldest_idx = i;
        }
    }
    if (oldest_idx >= 0) {
        memset(&g_sessions[oldest_idx], 0, sizeof(g_sessions[oldest_idx]));
        g_sessions[oldest_idx].in_use = 1;
        g_sessions[oldest_idx].last_active_ms = now;
        g_sessions[oldest_idx].bound_b_idx = -1;
        return &g_sessions[oldest_idx];
    }
    LeaveCriticalSection(&g_sess_lock);
    return NULL;
}

/* Find session by trying to unwrap packet.
 *
 * Snapshots (index, e2e_key) for every candidate under a brief lock,
 * then runs the GCM trial-decrypt UNLOCKED so concurrent connections'
 * packets can decrypt in parallel. On a match, re-acquires the lock to
 * validate against live session state (a slot can be reclaimed between
 * snapshot and match, so this re-checks via e2e_key equality, not just
 * index) before returning.
 *
 * A session-hint field (sg_hint, see config.h's SG_HINT_BYTES comment)
 * survives the full 3-hop Sphinx peel by riding in the payload
 * section's own always-unused zero-padding tail, no wire-packet
 * growth. The candidate loop below skips straight past any session
 * whose stored sg_hint doesn't match the packet's (a cheap memcmp)
 * before attempting the GCM trial-decrypt, so a genuine packet costs
 * one GCM decrypt (its own session's), not one per in-use role-A
 * session. Disclosed tradeoff: like the per-hop `hint` field, sg_hint
 * is session-constant and travels in the clear on the MN3-to-SG link
 * once fully unblinded, see config.h's comment for the full analysis.
 */
static sg_session_t *find_a_session(const wire_packet_t *pkt,
                                     uint8_t *payload_out,
                                     uint16_t *plen_out,
                                     uint8_t  *flags_out) {
    typedef struct { int idx; aes_key_t e2e_key; } candidate_t;
    candidate_t candidates[MAX_SESSIONS];
    int n_candidates = 0;

    /* The SG-side O(1) hint sits in the last SG_HINT_BYTES of the wire
     * packet: always the fully-unblinded payload section by the time
     * it reaches here (see packet_sphinx_unwrap's comment), so it's
     * readable directly off the wire with no decryption. Filtering
     * candidates by this cheap memcmp before the expensive GCM
     * trial-decrypt below means a genuine packet costs one memcmp per
     * in-use role-A session plus exactly one GCM decrypt (its own), not
     * a GCM decrypt attempt against every one of them. */
    const uint8_t *pkt_hint = pkt->data + WIRE_PACKET_SIZE - SG_HINT_BYTES;

    EnterCriticalSection(&g_sess_lock);
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_sessions[i].in_use) continue;
        if (g_sessions[i].role != SESSION_ROLE_A) continue;
        if (crypto_memcmp(g_sessions[i].sg_hint.bytes, pkt_hint, SG_HINT_BYTES) != 0)
            continue;
        candidates[n_candidates].idx     = i;
        candidates[n_candidates].e2e_key = g_sessions[i].e2e_key;
        n_candidates++;
    }
    LeaveCriticalSection(&g_sess_lock);

    for (int c = 0; c < n_candidates; c++) {
        int i = candidates[c].idx;

        uint8_t  tmp[MAX_INNER_PAYLOAD];
        uint16_t tlen = 0; uint8_t tf = 0;
        if (packet_sphinx_unwrap(pkt, &candidates[c].e2e_key,
                                 tmp, &tlen, &tf) != 0) continue;
        /* Cover traffic is discovered here, via the e2e-GCM payload's
         * PKT_DUMMY flag, which no mix node on the path can read. A
         * cover packet reaches here having been forwarded identically
         * to a real one at every hop, and is returned to the caller
         * (below), not dropped, its payload carries a spare return
         * header the client pre-supplied (see client.c's
         * build_outbound_cover_with_spare_return()), which
         * handle_connection() uses to fire an indistinguishable
         * return-path cover packet. The ptype/TYPE_SETUP/GET/PUT parsing
         * below doesn't apply to cover payloads and is skipped entirely
         * for this branch. */
        if (tf & PKT_DUMMY) {
            if (tlen < RETURN_HEADER_SIZE) continue; /* too short to carry a spare header */
            EnterCriticalSection(&g_sess_lock);
            if (!g_sessions[i].in_use ||
                crypto_memcmp(g_sessions[i].e2e_key.key, candidates[c].e2e_key.key,
                              AES_KEY_LEN) != 0) {
                LeaveCriticalSection(&g_sess_lock); continue;
            }
            memcpy(payload_out, tmp, tlen);
            *plen_out  = tlen;
            *flags_out = tf;
            g_sessions[i].last_active_ms = GetTickCount();
            g_sessions[i].in_flight++; /* pinned, caller must unpin at done: */
            LeaveCriticalSection(&g_sess_lock);
            return &g_sessions[i];
        }
        if (tlen < 1) continue;

        /* Determine packet type:
         * TYPE_SETUP: payload[0] == 0x00
         * GET/PUT:    payload[0] == 0x04 (EC pubkey prefix),
         *             actual type at offset EC_PUBKEY_LEN+ADDR_BYTES+RETURN_HEADER_SIZE */
        uint8_t ptype = 0xFF;
        if (tmp[0] == TYPE_SETUP) {
            ptype = TYPE_SETUP;
        } else if (tmp[0] == 0x04 && tlen > EC_PUBKEY_LEN + ADDR_BYTES + RETURN_HEADER_SIZE) {
            size_t toff = EC_PUBKEY_LEN + ADDR_BYTES + RETURN_HEADER_SIZE;
            /* HANDSHAKE_INIT/POLL (from R) and HEARTBEAT/HANDSHAKE_RESPOND
             * (from S) are app-data packets with the same envelope shape
             * as GET/PUT, so they're included in this whitelist for
             * find_a_session() to recognize and match. HEARTBEAT/
             * HANDSHAKE_RESPOND arrive as ordinary real packets from
             * Sender's own send_path, relayed opaquely to CS below like
             * everything else, CS/SG never see a Sender's real network
             * address directly, only an edge mix node's. */
            if (tmp[toff] == TYPE_GET || tmp[toff] == TYPE_PUT ||
                tmp[toff] == TYPE_HANDSHAKE_INIT || tmp[toff] == TYPE_HANDSHAKE_POLL ||
                tmp[toff] == TYPE_HEARTBEAT || tmp[toff] == TYPE_HANDSHAKE_RESPOND)
                ptype = tmp[toff];
        }
        if (ptype == 0xFF) continue;

        /* Re-acquire the lock for anything touching live session state. */
        EnterCriticalSection(&g_sess_lock);

        /* Slot may have been reclaimed for a different session since the
         * snapshot: re-verify identity via e2e_key, not just index. */
        if (!g_sessions[i].in_use ||
            crypto_memcmp(g_sessions[i].e2e_key.key, candidates[c].e2e_key.key,
                          AES_KEY_LEN) != 0) {
            LeaveCriticalSection(&g_sess_lock); continue;
        }

        /* Extra validation for GET/PUT: localhost IP check +
         * verify the embedded addr matches this session's stored addr */
        if (ptype != TYPE_SETUP) {
            if (tmp[EC_PUBKEY_LEN] != 127) { LeaveCriticalSection(&g_sess_lock); continue; }
            /* Only accept if setup is done for this session */
            if (!g_sessions[i].setup_done) { LeaveCriticalSection(&g_sess_lock); continue; }
            /* Check embedded addr port matches stored mnc_addr port */
            uint16_t pkt_port = (uint16_t)((tmp[EC_PUBKEY_LEN+4]<<8)|tmp[EC_PUBKEY_LEN+5]);
            uint16_t ses_port = (uint16_t)((g_sessions[i].mnc_addr[4]<<8)|
                                            g_sessions[i].mnc_addr[5]);
            if (pkt_port != ses_port) { LeaveCriticalSection(&g_sess_lock); continue; }
        }

        /* For TYPE_SETUP: verify binding tag to ensure correct session
         * match. binding_tag is at offset 1 + 3*AES_KEY_LEN = 1 + 96 = 97
         *, sending-path blind keys aren't transmitted, since the SG
         * never needs them. */
        if (ptype == TYPE_SETUP) {
            size_t btag_off = 1 + N_PATH_HOPS * AES_KEY_LEN;
            if (tlen < btag_off + MAC_BYTES) { LeaveCriticalSection(&g_sess_lock); continue; }

            /* Try every in-use B session, not just the next positional
             * slot: see find_verified_b()'s comment. */
            if (!find_verified_b(&g_sessions[i].e2e_key, tmp + btag_off,
                                  &g_sessions[i])) {
                LeaveCriticalSection(&g_sess_lock);
                continue; /* no B session's tag matches, wrong session, try next */
            }
        }

        memcpy(payload_out, tmp, tlen);
        *plen_out  = tlen;
        *flags_out = tf;
        g_sessions[i].last_active_ms = GetTickCount();
        g_sessions[i].in_flight++; /* pinned, caller must unpin at done: */
        LeaveCriticalSection(&g_sess_lock);
        return &g_sessions[i];
    }
    return NULL;
}

/* Once an A session's binding tag has been verified against a specific B
 * session (TYPE_SETUP handler below, on tag match), that pairing is
 * committed to a_sess->bound_b_idx and this function returns it
 * directly: no re-derivation. Before that first successful binding,
 * bound_b_idx is -1 and this falls back to find_verified_b(), which
 * tries every in-use B session against the binding-tag HMAC rather than
 * a single positional guess. */
static sg_session_t *find_b_for_a(sg_session_t *a_sess) {
    EnterCriticalSection(&g_sess_lock);
    sg_session_t *result = NULL;

    if (a_sess->bound_b_idx >= 0 && a_sess->bound_b_idx < MAX_SESSIONS) {
        sg_session_t *b = &g_sessions[a_sess->bound_b_idx];
        if (b->in_use && b->role == SESSION_ROLE_B) {
            b->in_flight++; /* pinned, caller must unpin at done: */
            LeaveCriticalSection(&g_sess_lock);
            return b;
        }
        /* Bound B slot was reclaimed (TTL expiry), fall through and
         * treat this A as unbound; the next positional guess will be
         * re-verified by the binding-tag check as usual. */
    }

    /* Unbound: verify against every in-use B session rather than a
     * single positional guess, see find_verified_b()'s comment. Only
     * reachable pre-setup (TYPE_SETUP handler, binding_tag/e2e_key
     * already populated by the caller before this is invoked); GET/PUT
     * always has bound_b_idx set by the time setup_done is checked. */
    result = find_verified_b(&a_sess->e2e_key, a_sess->binding_tag, a_sess);
    if (result) result->in_flight++; /* pinned, caller must unpin at done: */
    LeaveCriticalSection(&g_sess_lock);
    return result;
}

/* Send response through return path.
 *
 * use_hdr : the return header to embed, normally a_sess->return_hdr
 *           (the header the client most recently supplied with its real
 *           request), but the cover dispatch below passes a spare
 *           header the client pre-supplied via a forward-cover packet
 *           instead, without touching a_sess->return_hdr (which must
 *           stay reserved for the next real response).
 * flags   : leading plaintext byte of the (still end-to-end encrypted)
 *           response payload, PKT_REAL for a genuine response,
 *           PKT_DUMMY for cover. Mirrors the forward path's inner
 *           PKT_DUMMY flag inside packet_sphinx_unwrap()'s payload:
 *           encrypted under e2e_key (here, b_sess->e2e_key / k_r_sg_b),
 *           so invisible to MNc/MNb/MNa exactly the same way. */
static int send_response_ex(sg_session_t *a_sess, sg_session_t *b_sess,
                             const uint8_t use_hdr[RETURN_HEADER_SIZE],
                             uint8_t flags,
                             const uint8_t *resp, size_t resp_len) {
    /* Snapshot every a_sess field read below (recv_blind[]/mnc_addr)
     * under g_sess_lock before using them: a concurrent TYPE_SETUP or
     * TYPE_GET/PUT handler for this same session can mutate both fields
     * via a live pointer while this function is mid-read. Callers
     * already snapshot use_hdr the same way (see
     * pending_resp_flush_thread's local.hdr). */
    aes_key_t recv_blind_snap[N_PATH_HOPS];
    uint8_t   mnc_addr_snap[ADDR_BYTES];
    EnterCriticalSection(&g_sess_lock);
    memcpy(recv_blind_snap, a_sess->recv_blind, sizeof(recv_blind_snap));
    memcpy(mnc_addr_snap,   a_sess->mnc_addr,   sizeof(mnc_addr_snap));
    LeaveCriticalSection(&g_sess_lock);

    /* Step 5.2: encrypt under K_R-SG-B.
     * enc[]'s capacity is RETURN_PAYLOAD_SIZE - 2, not RETURN_PAYLOAD_SIZE
     *, the wire packet reserves the first 2 bytes of the
     * RETURN_PAYLOAD_SIZE-sized region (below) for the enc_len prefix, so
     * the actual ciphertext budget is 2 bytes smaller. crypto_aes_encrypt()
     * itself rejects a plaintext that would not fit (out_size check against
     * plaintext_len + GCM_OVERHEAD), so the memcpy below cannot overrun,
     * but that protection lives in the callee, not here, so make the bound
     * explicit at the call site too rather than relying on it implicitly.
     * -1 for the leading flags byte. */
    if (resp_len > (size_t)(RETURN_PAYLOAD_SIZE - 2 - GCM_OVERHEAD - 1)) {
        log_err("response too large"); return -1;
    }
    uint8_t plain[RETURN_PAYLOAD_SIZE - 2];
    plain[0] = flags;
    memcpy(plain + 1, resp, resp_len);

    uint8_t enc[RETURN_PAYLOAD_SIZE - 2];
    memset(enc, 0, sizeof(enc));
    int enc_len = crypto_aes_encrypt(&b_sess->e2e_key,
                                     plain, resp_len + 1,
                                     enc, sizeof(enc));
    if (enc_len < 0) { log_err("response encrypt failed"); return -1; }

    /* Build wire packet: [return_header][enc_len(2)][enc_payload] */
    uint8_t wire[WIRE_PACKET_SIZE];
    memset(wire, 0, sizeof(wire));
    memcpy(wire, use_hdr, RETURN_HEADER_SIZE);
    wire[RETURN_HEADER_SIZE]   = (uint8_t)(enc_len >> 8);
    wire[RETURN_HEADER_SIZE+1] = (uint8_t)(enc_len & 0xFF);
    memcpy(wire + RETURN_HEADER_SIZE + 2, enc, (size_t)enc_len);

    /* Step 5.4: pre-apply all three return-path blindings (MNa, MNb, MNc)
     * so each mix node cancels exactly one layer in handle_return(), and
     * the payload looks bitwise different on every path-B link, mirrors
     * packet_sphinx_build()'s "apply in reverse hop order" for the
     * forward direction. a_sess->recv_blind[i] is the same deterministic
     * function of the ECDH master that mix node i independently derives
     * as its own return_blind_key (see mix_node.c::split_master_keys()),
     * so no extra key material needs to travel on the wire for this. */
    size_t blind_len = WIRE_PACKET_SIZE - RETURN_HEADER_SIZE;
    for (int hop = N_PATH_HOPS - 1; hop >= 0; hop--) {
        uint8_t tmp[WIRE_PACKET_SIZE - RETURN_HEADER_SIZE];
        if (packet_aes_ctr_xor(recv_blind_snap[hop].key, AES_KEY_LEN,
                               wire + RETURN_HEADER_SIZE, blind_len,
                               tmp) != 0) {
            log_err("response pre-blind failed"); return -1;
        }
        memcpy(wire + RETURN_HEADER_SIZE, tmp, blind_len);
    }

    /* Extract MNc addr */
    char mnc_ip[16];
    snprintf(mnc_ip, sizeof(mnc_ip), "%u.%u.%u.%u",
             mnc_addr_snap[0], mnc_addr_snap[1],
             mnc_addr_snap[2], mnc_addr_snap[3]);
    uint16_t mnc_port = (uint16_t)((mnc_addr_snap[4]<<8)|mnc_addr_snap[5]);

    char logbuf2[80];
    snprintf(logbuf2, sizeof(logbuf2), "connecting to MNc at %s:%u", mnc_ip, mnc_port);
    log_msg(logbuf2);
    SOCKET s = net_connect(mnc_ip, mnc_port);
    if (s == INVALID_SOCKET) { log_err("connect MNc"); return -1; }

    uint8_t mode = MODE_RETURN;
    net_send_all(s, &mode, 1);
    net_send_all(s, wire,  WIRE_PACKET_SIZE);
    net_close(s);

    log_msg("response dispatched");
    return 0;
}

/* Queues a response rather than dispatching it immediately, see
 * sg_session_t.pending's comment. Drained either by this
 * session's next cover-trigger (below) or by
 * pending_resp_flush_thread()'s bounded fallback. b_sess is still
 * needed up front: find_b_for_a() must run (and pin/validate) on this
 * thread, before handle_connection()'s `done:` unpins it.
 *
 * Not gated behind any build flag: service_gateway.exe is a single
 * binary shared across every build variant (plain/hopdecoy/hardened),
 * so this mailbox is always active. Plain builds pay a small added
 * round-trip latency for it with no security benefit of their own,
 * an accepted tradeoff of sharing one SG binary across variants. */
static int send_response(sg_session_t *a_sess, sg_session_t *b_sess,
                          const uint8_t req_hdr[RETURN_HEADER_SIZE],
                          const uint8_t *resp, size_t resp_len) {
    (void)b_sess;
    if (resp_len > MAX_INNER_PAYLOAD) {
        log_err("response too large for mailbox"); return -1;
    }
    EnterCriticalSection(&g_sess_lock);
    if (a_sess->pending_count == PENDING_RESP_QUEUE) {
        /* Full: drop the oldest. The client's return hint window
         * tolerates the gap this leaves (it only needs the next reply
         * within HINT_WINDOW counter positions). */
        a_sess->pending_head = (a_sess->pending_head + 1) % PENDING_RESP_QUEUE;
        a_sess->pending_count--;
        log_err("response mailbox full, oldest response dropped");
    }
    pending_resp_t *e = &a_sess->pending[(a_sess->pending_head + a_sess->pending_count)
                                         % PENDING_RESP_QUEUE];
    memcpy(e->resp, resp, resp_len);
    e->len      = resp_len;
    memcpy(e->hdr, req_hdr, RETURN_HEADER_SIZE);
    e->since_ms = GetTickCount();
    a_sess->pending_count++;
    LeaveCriticalSection(&g_sess_lock);
    return 0;
}

/* Takes the oldest queued response of `sess` into `out` if there is one
 * and, when max_age_ms is non-zero, it has waited at least that long.
 * Caller must hold g_sess_lock. Returns 1 if an entry was taken. */
static int pending_pop(sg_session_t *sess, DWORD max_age_ms, pending_resp_t *out) {
    if (sess->pending_count == 0) return 0;
    pending_resp_t *e = &sess->pending[sess->pending_head];
    if (max_age_ms && GetTickCount() - e->since_ms < max_age_ms) return 0;
    memcpy(out, e, sizeof(*out));
    sess->pending_head = (sess->pending_head + 1) % PENDING_RESP_QUEUE;
    sess->pending_count--;
    return 1;
}

/* Bounded fallback for the return-path mailbox (leak fix), see
 * sg_session_t.pending's comment. Runs on its own thread
 * (mirrors node_key_rotation_thread() above) because, unlike that
 * mailbox's normal drain path (this same session's next M-c
 * cover-trigger, in the MODE_DATA handler below), nothing else is
 * guaranteed to touch an idle session again in bounded time, a
 * client that has gone quiet after firing its GET/PUT keeps sending
 * cover, but if this SG happens to route none of it as a cover-trigger
 * (e.g. hop-decoy diverted a run of the client's cover packets away
 * from the SG entirely) the mailbox would otherwise sit un-drained
 * indefinitely, hanging the client's own response wait. Polls every
 * PENDING_RESPONSE_MAX_WAIT_MS/4 so worst-case added latency over a
 * direct send stays within about one extra poll period, not a full
 * wait window. */
static DWORD WINAPI pending_resp_flush_thread(LPVOID arg) {
    (void)arg;
    while (1) {
        Sleep(PENDING_RESPONSE_MAX_WAIT_MS / 4);

        for (int i = 0; i < MAX_SESSIONS; i++) {
            /* Send every queued response of this session that has waited
             * PENDING_RESPONSE_MAX_WAIT_MS, oldest first. */
            while (1) {
                pending_resp_t local;
                int fire = 0;

                EnterCriticalSection(&g_sess_lock);
                if (g_sessions[i].in_use && g_sessions[i].role == SESSION_ROLE_A &&
                    pending_pop(&g_sessions[i], PENDING_RESPONSE_MAX_WAIT_MS, &local)) {
                    g_sessions[i].in_flight++; /* pin, matches find_a_session()'s
                                                 * convention; unpinned below. */
                    fire = 1;
                }
                LeaveCriticalSection(&g_sess_lock);
                if (!fire) break;

                sg_session_t *a_sess = &g_sessions[i];
                sg_session_t *b_sess = find_b_for_a(a_sess); /* pins b_sess too */
                if (b_sess) {
                    send_response_ex(a_sess, b_sess, local.hdr, PKT_REAL,
                                     local.resp, local.len);
                    EnterCriticalSection(&g_sess_lock);
                    b_sess->in_flight--;
                    LeaveCriticalSection(&g_sess_lock);
                } else {
                    log_err("mailbox flush: no bound B session, response dropped");
                }
                EnterCriticalSection(&g_sess_lock);
                a_sess->in_flight--;
                LeaveCriticalSection(&g_sess_lock);
            }
        }
    }
    return 0;
}

typedef struct { SOCKET s; } conn_ctx_t;

static DWORD WINAPI handle_connection(LPVOID arg) {
    conn_ctx_t *ctx = (conn_ctx_t *)arg;
    SOCKET sock = ctx->s; free(ctx);

    /* Declared here (function scope, NULL-initialized before any goto)
     * so the `done:` cleanup below can unpin whichever of these
     * find_a_session()/find_b_for_a() pinned, regardless of which path
     * through this function was taken, see sg_session_t.in_flight's
     * comment. Not used for the MODE_EXTEND branch's freshly
     * sess_alloc()'d session below (that one is a brand-new,
     * never-pinned session on a disjoint code path, kept as its own
     * `new_sess` local so it's never mistaken for a pinned session at
     * cleanup). */
    sg_session_t *sess = NULL, *b_sess = NULL;

    uint8_t mode = 0;
    if (net_recv_all(sock, &mode, 1) != 0) goto done;

    /* MODE_EXTEND */
    if (mode == MODE_EXTEND) {
        /* [role(1)][tport(2)][pubkey(65)] as one padded frame, see
         * mix_node.c::handle_extend() and net_send_padded_frame's
         * comment in common/net.c for the full rationale. The SG is
         * always the terminal hop, so tport is unused here (kept only
         * because it's part of the frame shape every hop, mix node or
         * SG: reads identically). */
        uint8_t req_buf[3 + EC_PUBKEY_LEN];
        size_t  req_len = 0;
        if (net_recv_padded_frame(sock, req_buf, &req_len, sizeof(req_buf)) != 0
            || req_len != sizeof(req_buf)) goto done;
        uint8_t role = req_buf[0];
        uint8_t client_pub[EC_PUBKEY_LEN];
        memcpy(client_pub, req_buf + 3, EC_PUBKEY_LEN);

        /* Lock across the derive and the pubkey snapshot together,
         * see mix_node.c::handle_extend()'s matching comment. */
        aes_key_t master = {0};
        uint8_t   node_pub_snapshot[EC_PUBKEY_LEN];
        EnterCriticalSection(&g_node_kp_lock);
        memcpy(node_pub_snapshot, g_node_kp.pubkey_bytes, EC_PUBKEY_LEN);
        /* See mix_node.c's matching comment / crypto_ecdh_derive_bound()'s
         * comment in crypto.h. */
        int ecdh_rc = crypto_ecdh_derive_bound(&g_node_kp, client_pub,
                                               client_pub, node_pub_snapshot,
                                               PORT_SERVICE_GW, role, &master);
        LeaveCriticalSection(&g_node_kp_lock);
        if (ecdh_rc != 0) goto done;

        sg_session_t *new_sess = sess_alloc();
        if (!new_sess) { log_err("extend: session store full"); goto done; }
        /* sess_alloc() returns with g_sess_lock HELD (see its own doc
         * comment) so this population is atomic w.r.t. a concurrent
         * MODE_DATA scan, released on every exit path below. */
        memcpy(new_sess->hint, client_pub + 1, HINT_BYTES);
        new_sess->e2e_key = master;
        new_sess->role    = role;
        /* Derive the same O(1) lookup hint the client/sender independently
         * derives from this same master, see packet_derive_sg_hint()'s
         * comment. Only meaningful for role A (the only role that ever
         * sends MODE_DATA to the SG); computed unconditionally anyway
         * since it's cheap and harmless for role B. */
        if (packet_derive_sg_hint(&master, &new_sess->sg_hint) != 0) {
            LeaveCriticalSection(&g_sess_lock);
            log_err("extend: failed to derive SG hint"); goto done;
        }
        LeaveCriticalSection(&g_sess_lock);

        char logbuf[64];
        snprintf(logbuf, sizeof(logbuf), "extend: session established (role=%u)", role);
        log_msg(logbuf);

        /* Signed descriptor, one padded frame, see mix_node.c::
         * handle_extend() for the exact wire layout and full rationale. */
        uint8_t sig[SIGNATURE_MAX_LEN];
        int sig_len = crypto_sign(&g_identity_kp, node_pub_snapshot,
                                   EC_PUBKEY_LEN, sig, sizeof(sig));
        if (sig_len < 0) { log_err("extend: failed to sign descriptor"); goto done; }
        {
            uint8_t reply_buf[EC_PUBKEY_LEN + EC_PUBKEY_LEN + 1 + SIGNATURE_MAX_LEN];
            size_t  off = 0;
            memcpy(reply_buf + off, node_pub_snapshot, EC_PUBKEY_LEN); off += EC_PUBKEY_LEN;
            memcpy(reply_buf + off, g_identity_kp.pubkey_bytes, EC_PUBKEY_LEN); off += EC_PUBKEY_LEN;
            reply_buf[off++] = (uint8_t)sig_len;
            memcpy(reply_buf + off, sig, (size_t)sig_len); off += (size_t)sig_len;
            net_send_padded_frame(sock, reply_buf, off);
        }
        goto done;
    }

    /* MODE_DATA */
    if (mode != MODE_DATA) goto done;

    wire_packet_t pkt = {0};
    if (net_recv_all(sock, pkt.data, WIRE_PACKET_SIZE) != 0) goto done;

    uint8_t  payload[MAX_INNER_PAYLOAD];
    uint16_t plen = 0;
    uint8_t  flags = 0;

    sess = find_a_session(&pkt, payload, &plen, &flags);
    if (!sess) { log_err("no matching session, drop"); goto done; }

    /* Return-path cover. `payload` holds a spare return_header_t this
     * client pre-supplied on a forward-cover packet (see client.c's
     * build_outbound_cover_with_spare_return() and this file's
     * find_a_session() PKT_DUMMY branch above), fire an
     * indistinguishable return-direction cover packet using it, through
     * the same dispatch a real response uses (send_response_ex()), just
     * with a spare header and PKT_DUMMY instead of this session's own
     * return_hdr and PKT_REAL. Requires setup_done: before setup
     * completes, recv_blind[]/mnc_addr (which send_response_ex() needs
     * to route and blind the packet) are still zero. No log_err on the
     * skip paths, a dropped cover packet is not an error condition. */
    if (flags & PKT_DUMMY) {
        if (sess->setup_done) {
            b_sess = find_b_for_a(sess);
            if (b_sess) {
                /* Drain this session's return-path mailbox first, using
                 * this cover-trigger's normal cadence to carry the real
                 * response instead of adding an extra packet on top of
                 * it: see sg_session_t.pending's comment.
                 * Uses the queued entry's header/PKT_REAL (the real
                 * response's own header), not the spare header this cover packet
                 * carried: the spare header is only needed when this
                 * slot is used for actual cover. */
                pending_resp_t local;
                EnterCriticalSection(&g_sess_lock);
                int have_pending = pending_pop(sess, 0, &local);
                LeaveCriticalSection(&g_sess_lock);

                if (have_pending) {
                    send_response_ex(sess, b_sess, local.hdr, PKT_REAL,
                                     local.resp, local.len);
                } else if (plen >= RETURN_HEADER_SIZE) {
                    uint8_t junk[32];
                    if (RAND_bytes(junk, sizeof(junk)) == 1) {
                        send_response_ex(sess, b_sess, payload, PKT_DUMMY,
                                         junk, sizeof(junk));
                    }
                }
            }
        }
        goto done;
    }

    /* TYPE_SETUP */
    if (payload[0] == TYPE_SETUP) {
        /* Payload doesn't carry sending-path blind keys (SK_R-MN1/2/3)
         *, the SG never uses them, only recv_blind[] below. See
         * client.c::send_setup(). */
        char _s[80]; snprintf(_s,sizeof(_s),"setup: plen=%u min=%zu", plen, (size_t)(1+N_PATH_HOPS*AES_KEY_LEN+MAC_BYTES+EC_PUBKEY_LEN+ADDR_BYTES+RETURN_HEADER_SIZE)); log_msg(_s);
        if (plen < 1 + N_PATH_HOPS*AES_KEY_LEN + MAC_BYTES + EC_PUBKEY_LEN + ADDR_BYTES + RETURN_HEADER_SIZE) {
            log_err("setup: payload too short"); goto done;
        }
        size_t off = 1;

        /* Locked: a concurrent MODE_DATA packet for this same session
         * (a cover-trigger or a real GET/PUT racing setup) can read
         * recv_blind[]/mnc_addr/return_hdr via send_response_ex() while
         * this write is in progress. */
        uint8_t setup_hdr_snap[RETURN_HEADER_SIZE];
        EnterCriticalSection(&g_sess_lock);
        /* Pre-blind outgoing: MNc, MNb, MNa */
        for (int i = 0; i < N_PATH_HOPS; i++) {
            memcpy(sess->recv_blind[i].key, payload + off, AES_KEY_LEN);
            off += AES_KEY_LEN;
        }
        memcpy(sess->binding_tag, payload + off, MAC_BYTES); off += MAC_BYTES;
        memcpy(sess->mnc_pubkey,  payload + off, EC_PUBKEY_LEN); off += EC_PUBKEY_LEN;
        memcpy(sess->mnc_addr,    payload + off, ADDR_BYTES); off += ADDR_BYTES;
        memcpy(sess->return_hdr,  payload + off, RETURN_HEADER_SIZE);
        memcpy(setup_hdr_snap,    sess->return_hdr, RETURN_HEADER_SIZE);
        LeaveCriticalSection(&g_sess_lock);

        /* Verify binding tag */
        b_sess = find_b_for_a(sess);
        if (b_sess) {
            uint8_t computed[MAC_BYTES];
            packet_derive_binding_tag(&sess->e2e_key, &b_sess->e2e_key, computed);
            if (crypto_memcmp(computed, sess->binding_tag, MAC_BYTES) == 0) {
                /* Locked for the same reason as the write above:
                 * setup_done is read both under g_sess_lock
                 * (find_a_session()) and without it elsewhere in this
                 * file. */
                EnterCriticalSection(&g_sess_lock);
                sess->b_key    = b_sess->e2e_key;
                sess->setup_done = 1;
                sess->bound_b_idx = (int)(b_sess - g_sessions);
                LeaveCriticalSection(&g_sess_lock);
                log_msg("setup: binding tag verified, session active");

                /* Acknowledges setup completion directly so the client
                 * can wait for it instead of guessing when it's safe to
                 * send GET/PUT, ASN_POOL_MIXING's own queueing delay on
                 * the SETUP packet can otherwise let a GET arrive before
                 * SETUP has landed. Uses send_response_ex() directly,
                 * not send_response()'s mailbox, since a setup ack should
                 * fire immediately rather than wait on the mailbox's
                 * cover-trigger cadence. Content is a fixed marker; only
                 * its arrival matters to the client. */
                {
                    static const uint8_t ack_payload[] = "SETUP_OK";
                    send_response_ex(sess, b_sess, setup_hdr_snap, PKT_REAL,
                                     ack_payload, sizeof(ack_payload) - 1);
                }
            } else {
                log_err("setup: binding tag MISMATCH");
                /* Log first 4 bytes of each for comparison */
                char _m[128];
                snprintf(_m,sizeof(_m),"computed: %02x%02x%02x%02x stored: %02x%02x%02x%02x",
                    computed[0],computed[1],computed[2],computed[3],
                    sess->binding_tag[0],sess->binding_tag[1],
                    sess->binding_tag[2],sess->binding_tag[3]);
                log_msg(_m);
            }
        } else {
            EnterCriticalSection(&g_sess_lock);
            sess->setup_done = 0;
            LeaveCriticalSection(&g_sess_lock);
            log_err("setup: B session not found, stored pending");
        }
        goto done;
    }

    /* TYPE_GET / TYPE_PUT */
    if (!sess->setup_done) {
        log_err("data before setup complete, drop"); goto done;
    }

    /* Step 4.9: reverse blinding chain using SK_R-MN1/2/3
     * Client pre-applied: blind(blind(blind(P0, MN3), MN2), MN1)
     * MN1 XOR'd MN1, MN2 XOR'd MN2, MN3 XOR'd MN3, all cancelled.
     * payload is already P0 after packet_sphinx_unwrap.
     * The unwrap already used the E2E key correctly.
     * No additional unblinding needed here, Sphinx handles it.        */

    b_sess = find_b_for_a(sess);
    if (!b_sess) { log_err("no B session"); goto done; }
    sg_trace_log((int)(b_sess - g_sessions), (int)(sess - g_sessions));

    if (plen < EC_PUBKEY_LEN + ADDR_BYTES + RETURN_HEADER_SIZE + 2) {
        log_err("payload too short"); goto done;
    }

    /* Use routing info from payload (same each request, but update stored) */
    size_t off = 0;
    uint8_t mnc_pubkey[EC_PUBKEY_LEN];
    memcpy(mnc_pubkey, payload + off, EC_PUBKEY_LEN); off += EC_PUBKEY_LEN;
    uint8_t mnc_addr[ADDR_BYTES];
    memcpy(mnc_addr, payload + off, ADDR_BYTES); off += ADDR_BYTES;
    /* Update stored return header and addr from this packet, locked,
     * see the matching TYPE_SETUP comment above. */
    const uint8_t *req_hdr = payload + off; /* this request's own return header */
    EnterCriticalSection(&g_sess_lock);
    memcpy(sess->return_hdr, payload + off, RETURN_HEADER_SIZE); off += RETURN_HEADER_SIZE;
    memcpy(sess->mnc_addr,   mnc_addr, ADDR_BYTES);
    LeaveCriticalSection(&g_sess_lock);

    uint8_t type = payload[off++];

    /* TYPE_PUT/TYPE_HEARTBEAT/TYPE_HANDSHAKE_RESPOND are the only
     * request types sender.c's slot-pool sends (see that file's
     * send_app_request() and send_slot_t.pending_nonce), these three
     * carry a 4-byte nonce right after `type` that gets echoed back in
     * the response so sender_wait_response() can tell a genuine answer
     * to this request apart from a stale one left over from a previous
     * occupant of the same response slot. TYPE_GET/TYPE_HANDSHAKE_INIT/
     * TYPE_HANDSHAKE_POLL (client.c requests) never carry one,
     * client.c has no slot-pool reacquire race to protect against. */
    uint8_t req_nonce[SLOT_NONCE_BYTES] = {0};
    int has_nonce = (type == TYPE_PUT || type == TYPE_HEARTBEAT ||
                      type == TYPE_HANDSHAKE_RESPOND);
    if (has_nonce) {
        if (off + sizeof(req_nonce) > plen) { log_err("missing request nonce"); goto done; }
        memcpy(req_nonce, payload + off, sizeof(req_nonce)); off += sizeof(req_nonce);
    }

    uint8_t klen = payload[off++];
    char _dbg2[80];
    snprintf(_dbg2, sizeof(_dbg2), "parsed: type=0x%02x klen=%u off=%zu plen=%u",
             type, klen, off, plen);
    log_msg(_dbg2);
    if (klen == 0 || klen > 64 || off + klen > plen) { log_err("bad klen"); goto done; }

    char key[65] = {0};
    memcpy(key, payload + off, klen); key[klen] = '\0'; off += klen;

    char logbuf[128];
    snprintf(logbuf, sizeof(logbuf), "type=%u key='%s'", type, key);
    log_msg(logbuf);

    uint8_t resp[MAX_INNER_PAYLOAD]; size_t rlen = 0;
    /* Nonce prefix reserved up front, every capacity check below
     * against the cache server's own response length must leave room
     * for it. */
    size_t resp_cap = sizeof(resp) - (has_nonce ? sizeof(req_nonce) : 0);

    if (type == TYPE_GET) {
        SOCKET cs = net_connect(LOCALHOST, PORT_CACHE_SERVER);
        if (cs == INVALID_SOCKET) goto done;
        uint8_t req[2] = {TYPE_GET, klen};
        uint8_t dz[2]  = {0,0};
        net_send_all(cs, req, 2);
        net_send_all(cs, (uint8_t*)key, klen);
        net_send_all(cs, dz, 2);
        uint8_t rb[2]; net_recv_all(cs, rb, 2);
        uint16_t rl = (uint16_t)((rb[0]<<8)|rb[1]);
        net_close(cs);

        if (rl == 0) {
            const char *nf = "ERROR: key not found";
            rlen = strlen(nf); memcpy(resp, nf, rlen);
        } else {
            cs = net_connect(LOCALHOST, PORT_CACHE_SERVER);
            if (cs == INVALID_SOCKET) goto done;
            net_send_all(cs, req, 2);
            net_send_all(cs, (uint8_t*)key, klen);
            net_send_all(cs, dz, 2);
            net_recv_all(cs, rb, 2);
            rl = (uint16_t)((rb[0]<<8)|rb[1]);
            /* Bound rl against resp[]'s actual capacity before the recv.
             * Currently always <= MAX_CONTENT_LEN because cache_server.c
             * enforces that cap on its own stored values, but that is
             * an upstream invariant this code was trusting implicitly,
             * not something this recv itself verified. Without this
             * check, a differently-capped or compromised cache server
             * response would overflow resp[MAX_INNER_PAYLOAD] here. */
            if (rl > sizeof(resp)) {
                log_err("cache response length exceeds buffer, drop");
                net_close(cs);
                goto done;
            }
            net_recv_all(cs, resp, rl);
            net_close(cs);
            rlen = rl;
        }
    } else if (type == TYPE_PUT) {
        uint16_t clen = 0;
        if (off + 2 <= plen) {
            clen = (uint16_t)((payload[off]<<8)|payload[off+1]); off+=2;
        }
        if (off + clen > plen) { log_err("bad clen"); goto done; }
        SOCKET cs = net_connect(LOCALHOST, PORT_CACHE_SERVER);
        if (cs == INVALID_SOCKET) goto done;
        uint8_t req[2] = {TYPE_PUT, klen};
        uint8_t dlb[2] = {(uint8_t)(clen>>8),(uint8_t)(clen&0xFF)};
        net_send_all(cs, req, 2);
        net_send_all(cs, (uint8_t*)key, klen);
        net_send_all(cs, dlb, 2);
        if (clen > 0) net_send_all(cs, payload+off, clen);
        uint8_t ack[3]; net_recv_all(cs, ack, 3);
        net_close(cs);
        const char *ok = "Content stored successfully";
        rlen = strlen(ok); memcpy(resp, ok, rlen);

    } else if (type == TYPE_HANDSHAKE_INIT) {
        /* R -> CS relay: data = [dlen(2)][r_ephemeral_pub(65)], same
         * length-prefix convention as TYPE_PUT's content field. SG
         * never inspects the ephemeral key itself, it's opaque
         * routing payload as far as this hop is concerned, exactly
         * like TYPE_PUT's content bytes above. */
        uint16_t dlen = 0;
        if (off + 2 <= plen) {
            dlen = (uint16_t)((payload[off]<<8)|payload[off+1]); off+=2;
        }
        if (off + dlen > plen) { log_err("bad handshake-init dlen"); goto done; }
        SOCKET cs = net_connect(LOCALHOST, PORT_CACHE_SERVER);
        if (cs == INVALID_SOCKET) goto done;
        uint8_t req[2] = {TYPE_HANDSHAKE_INIT, klen};
        uint8_t dlb[2] = {(uint8_t)(dlen>>8),(uint8_t)(dlen&0xFF)};
        net_send_all(cs, req, 2);
        net_send_all(cs, (uint8_t*)key, klen);
        net_send_all(cs, dlb, 2);
        if (dlen > 0) net_send_all(cs, payload+off, dlen);
        uint8_t ack[3]; net_recv_all(cs, ack, 3);
        net_close(cs);
        resp[0] = ack[2]; rlen = 1;

    } else if (type == TYPE_HANDSHAKE_POLL) {
        /* R -> CS relay: no request data (dlen=0). `key` is R's own
         * composite wire key (content key + per-request nonce suffix,
         * see cache_server.c's pending_handshake_t struct comment),
         * already unique per requester, so nothing else needs to be
         * relayed here to disambiguate concurrent pollers. CS's response
         * is already the exact [rlen(2)][data(rlen)] shape this function
         * forwards verbatim, single round trip, no two-phase probe
         * needed (unlike TYPE_GET above, which re-checks length before
         * a second fetch; CS's poll response is small and fixed-cap by
         * construction, so that dance isn't needed here). */
        SOCKET cs = net_connect(LOCALHOST, PORT_CACHE_SERVER);
        if (cs == INVALID_SOCKET) goto done;
        uint8_t req[2] = {TYPE_HANDSHAKE_POLL, klen};
        uint8_t dz[2]  = {0,0};
        net_send_all(cs, req, 2);
        net_send_all(cs, (uint8_t*)key, klen);
        net_send_all(cs, dz, 2);
        uint8_t rb[2]; net_recv_all(cs, rb, 2);
        uint16_t rl = (uint16_t)((rb[0]<<8)|rb[1]);
        if (rl > sizeof(resp)) {
            log_err("handshake-poll response length exceeds buffer, drop");
            net_close(cs);
            goto done;
        }
        if (rl > 0) net_recv_all(cs, resp, rl);
        net_close(cs);
        rlen = rl;

    } else if (type == TYPE_HEARTBEAT) {
        /* S -> CS relay: an ordinary real packet from Sender's own
         * send_path, relayed the same way TYPE_HANDSHAKE_POLL relays R's
         * poll: single round trip, CS's response is already the
         * [rlen(2)][data(rlen)] shape this forwards verbatim. `key` is
         * an unused dummy the Sender sends only because the generic
         * wire framing requires klen>=1. */
        SOCKET cs = net_connect(LOCALHOST, PORT_CACHE_SERVER);
        if (cs == INVALID_SOCKET) goto done;
        uint8_t req[2] = {TYPE_HEARTBEAT, klen};
        uint8_t dz[2]  = {0,0};
        net_send_all(cs, req, 2);
        net_send_all(cs, (uint8_t*)key, klen);
        net_send_all(cs, dz, 2);
        uint8_t rb[2]; net_recv_all(cs, rb, 2);
        uint16_t rl = (uint16_t)((rb[0]<<8)|rb[1]);
        if (rl > resp_cap) {
            log_err("heartbeat response length exceeds buffer, drop");
            net_close(cs);
            goto done;
        }
        if (rl > 0) net_recv_all(cs, resp, rl);
        net_close(cs);
        rlen = rl;

    } else if (type == TYPE_HANDSHAKE_RESPOND) {
        /* S -> CS relay: same shape as TYPE_HEARTBEAT above. data =
         * s_ephemeral_pub(65)+enc_len(2)+enc_k_content+sig_len(1)+sig
         * (sig binds this response to S's identity key), same
         * [dlen(2)][data] convention as PUT/HANDSHAKE_INIT, entirely
         * opaque to SG either way, no size assumption baked in here.
         * CS's 3-byte ack is reduced to the single ok-flag byte,
         * matching TYPE_HANDSHAKE_INIT's ack handling. */
        uint16_t dlen = 0;
        if (off + 2 <= plen) {
            dlen = (uint16_t)((payload[off]<<8)|payload[off+1]); off+=2;
        }
        if (off + dlen > plen) { log_err("bad handshake-respond dlen"); goto done; }
        SOCKET cs = net_connect(LOCALHOST, PORT_CACHE_SERVER);
        if (cs == INVALID_SOCKET) goto done;
        uint8_t req[2] = {TYPE_HANDSHAKE_RESPOND, klen};
        uint8_t dlb[2] = {(uint8_t)(dlen>>8),(uint8_t)(dlen&0xFF)};
        net_send_all(cs, req, 2);
        net_send_all(cs, (uint8_t*)key, klen);
        net_send_all(cs, dlb, 2);
        if (dlen > 0) net_send_all(cs, payload+off, dlen);
        uint8_t ack[3]; net_recv_all(cs, ack, 3);
        net_close(cs);
        resp[0] = ack[2]; rlen = 1;
    }

    if (rlen > 0) {
        if (has_nonce) {
            /* resp_cap already reserved this room above, rlen can never
             * exceed it, so this memmove cannot overrun resp[]. */
            memmove(resp + sizeof(req_nonce), resp, rlen);
            memcpy(resp, req_nonce, sizeof(req_nonce));
            rlen += sizeof(req_nonce);
        }
        send_response(sess, b_sess, req_hdr, resp, rlen);
    }

done:
    /* Unpin whichever of sess/b_sess find_a_session()/find_b_for_a()
     * pinned: both NULL-safe no-ops if this path never reached them,
     * and never touches the MODE_EXTEND branch's separate,
     * never-pinned new_sess. */
    if (sess || b_sess) {
        EnterCriticalSection(&g_sess_lock);
        if (sess)   sess->in_flight--;
        if (b_sess) b_sess->in_flight--;
        LeaveCriticalSection(&g_sess_lock);
    }
    net_close(sock); return 0;
}

int main(void) {
    SetConsoleOutputCP(65001);
    memset(g_sessions, 0, sizeof(g_sessions));
    InitializeCriticalSection(&g_sess_lock);
    InitializeCriticalSection(&g_node_kp_lock);
    if (net_init() != 0) return 1;

    if (crypto_ecdh_keygen(&g_node_kp) != 0) return 1;
    CreateDirectoryA(PUBKEY_DIR, NULL);
    char p[256];
    snprintf(p, sizeof(p), "%s/%u.pub", PUBKEY_DIR, (unsigned)PORT_SERVICE_GW);
    crypto_pubkey_save(&g_node_kp, p);
    printf("[SvcGW] pubkey written to %s\n", p);
    snprintf(g_pubkey_path, sizeof(g_pubkey_path), "%s", p);

    /* Stable identity key, survives restart unlike g_node_kp above,
     * see mix_node.c's identical mechanism. */
    char identity_path[256];
    snprintf(identity_path, sizeof(identity_path), "%s/identity_%u.key",
             PUBKEY_DIR, (unsigned)PORT_SERVICE_GW);
    if (crypto_identity_load_or_create(&g_identity_kp, identity_path) != 0) {
        fprintf(stderr, "[SvcGW] identity key load/create failed\n");
        return 1;
    }

    SOCKET srv = net_listen(PORT_SERVICE_GW);
    if (srv == INVALID_SOCKET) return 1;
    log_msg("ready");

    /* Periodic node-key rotation for forward secrecy. */
    {
        HANDLE rt = CreateThread(NULL, 0, node_key_rotation_thread, NULL, 0, NULL);
        if (rt) CloseHandle(rt);
    }

    /* Return-path mailbox bounded fallback, see pending_resp_flush_
     * thread()'s comment. */
    {
        HANDLE ft = CreateThread(NULL, 0, pending_resp_flush_thread, NULL, 0, NULL);
        if (ft) CloseHandle(ft);
    }

    while (1) {
        SOCKET cs = net_accept(srv);
        if (cs == INVALID_SOCKET) continue;
        conn_ctx_t *ctx = malloc(sizeof(conn_ctx_t));
        if (!ctx) { net_close(cs); continue; }
        ctx->s = cs;
        HANDLE t = CreateThread(NULL,0,handle_connection,ctx,0,NULL);
        if (!t) { net_close(cs); free(ctx); continue; }
        CloseHandle(t);
    }
    return 0;
}
