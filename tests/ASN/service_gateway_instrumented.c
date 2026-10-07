/* service_gateway.c: Service Gateway (:9010), Anon-Sec-Net v2 */

#include "common/net.h"
#include "common/crypto.h"
#include "common/packet.h"
#include "common/config.h"
#include "common/measure.h"          /* P4: SG goodput counter */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include "common/posix_compat.h"

static void log_msg(const char *m){printf("[SvcGW] %s\n",m);fflush(stdout);}
static void log_err(const char *m){fprintf(stderr,"[SvcGW] ERROR: %s\n",m);fflush(stderr);}

/* Session store */
#define MAX_SESSIONS 1024

typedef struct {
    uint8_t   hint[HINT_BYTES];
    aes_key_t e2e_key;
    uint8_t   role;
    /* Set by TYPE_SETUP (role=A session only). Sending-path blind keys
     * (SK_R-MN1/2/3) are deliberately not received/stored, see
     * service_gateway.c's sg_session_t for the full rationale: the SG
     * never uses them, only recv_blind[] below. */
    aes_key_t recv_blind[N_PATH_HOPS]; /* SK_R-MNc/b/a: pre-blind outgoing*/
    uint8_t   binding_tag[MAC_BYTES];
    uint8_t   mnc_pubkey[EC_PUBKEY_LEN];
    uint8_t   mnc_addr[ADDR_BYTES];
    uint8_t   return_hdr[RETURN_HEADER_SIZE];
    aes_key_t b_key;    /* K_R-SG-B, found after binding tag verified */
    int       setup_done;
    int       in_use;
    int       bound_b_idx; /* see service_gateway.c's sg_session_t for full
                             * rationale: this is a separate,
                             * independently-duplicated copy of that same
                             * session table (this file is the
                             * benchmark-harness track: Table 2/Figure 3/
                             * Figure 5/7 all run against this binary, not
                             * service_gateway.exe). */
    DWORD     last_active_ms;
    int       in_flight; /* see service_gateway.c's sg_session_t for full
                           * rationale: identical
                           * mechanism in this independently-duplicated
                           * copy, since this is the binary every
                           * benchmark in this paper actually runs. */
} sg_session_t;

/* See service_gateway.c's SESSION_TTL_MS for rationale. */
#define SESSION_TTL_MS (5U * 60U * 1000U)

static sg_session_t     g_sessions[MAX_SESSIONS];
static CRITICAL_SECTION g_sess_lock;
static ecdh_keypair_t   g_node_kp = {0};

/* See service_gateway.c's find_verified_b() for the full rationale,
 * identical mechanism in this independently-duplicated copy. Caller
 * must hold g_sess_lock. */
static sg_session_t *find_verified_b(const aes_key_t *a_key,
                                      const uint8_t *want_tag,
                                      const sg_session_t *skip) {
    for (int j = 0; j < MAX_SESSIONS; j++) {
        if (!g_sessions[j].in_use) continue;
        if (g_sessions[j].role != SESSION_ROLE_B) continue;
        if (&g_sessions[j] == skip) continue;
        /* See production service_gateway.c. */
        uint8_t computed[MAC_BYTES];
        if (packet_derive_binding_tag(a_key, &g_sessions[j].e2e_key,
                                      computed) != 0) continue;
        if (crypto_memcmp(computed, want_tag, MAC_BYTES) == 0)
            return &g_sessions[j];
    }
    return NULL;
}

static sg_session_t *sess_alloc(void) {
    EnterCriticalSection(&g_sess_lock);
    DWORD now = GetTickCount();
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_sessions[i].in_use) {
            memset(&g_sessions[i], 0, sizeof(g_sessions[i]));
            g_sessions[i].in_use = 1;
            g_sessions[i].last_active_ms = now;
            g_sessions[i].bound_b_idx = -1;
            LeaveCriticalSection(&g_sess_lock);
            return &g_sessions[i];
        }
    }
    /* Table full: reclaim the single oldest slot past SESSION_TTL_MS,
     * see service_gateway.c's sess_alloc() for the identical mechanism.
     * Slots with in_flight > 0 are never eligible. */
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
        LeaveCriticalSection(&g_sess_lock);
        return &g_sessions[oldest_idx];
    }
    LeaveCriticalSection(&g_sess_lock);
    return NULL;
}

/* Find session by trying to unwrap packet.
 * See service_gateway.c's find_a_session() for
 * the full rationale. This benchmark-harness track uses the
 * identical mechanism, since it is what every Table 2 sweep runs
 * against. */
static sg_session_t *find_a_session(const wire_packet_t *pkt,
                                     uint8_t *payload_out,
                                     uint16_t *plen_out,
                                     uint8_t  *flags_out) {
    typedef struct { int idx; aes_key_t e2e_key; } candidate_t;
    candidate_t candidates[MAX_SESSIONS];
    int n_candidates = 0;

    EnterCriticalSection(&g_sess_lock);
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_sessions[i].in_use) continue;
        if (g_sessions[i].role != SESSION_ROLE_A) continue;
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
        /* M-c: see service_gateway.c's identical find_a_session() branch
         * for the full rationale, a matched cover packet carries a
         * spare return header (payload_out) instead of app data, and is
         * returned to the caller (not skipped) so handle_connection() can
         * fire an indistinguishable return-path cover response with it. */
        if (tf & PKT_DUMMY) {
            if (tlen < RETURN_HEADER_SIZE) continue;
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
            /* Known limitation: this benchmark
             * harness only understands TYPE_GET/TYPE_PUT, not the
             * K_session/K_content handshake types (TYPE_HANDSHAKE_INIT/
             * POLL, TYPE_HEARTBEAT, TYPE_HANDSHAKE_RESPOND) the
             * production gateway/service_gateway.c handles. Adding those
             * types to this whitelist alone, without matching relay
             * logic below, would let such packets past this gate only to
             * be silently dropped further down. Currently inert either
             * way: client_instrumented.c never constructs these packet
             * types. If this harness is ever extended to benchmark
             * handshake traffic, both this whitelist and the
             * corresponding relay branches need to be added together. */
            if (tmp[toff] == TYPE_GET || tmp[toff] == TYPE_PUT)
                ptype = tmp[toff];
        }
        if (ptype == 0xFF) continue;

        EnterCriticalSection(&g_sess_lock);

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

        /* For TYPE_SETUP: verify binding tag to ensure correct session match.
         * binding_tag is at offset 1 + 3*AES_KEY_LEN = 1 + 96 = 97,
         * sending-path blind keys aren't transmitted. */
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

/* See service_gateway.c's find_b_for_a() for the full rationale: once an
 * A session's binding tag has been verified against a specific B session
 * (below, on tag match), that pairing is committed to a_sess->bound_b_idx
 * and returned directly here, no re-derivation. Before that first
 * successful binding, bound_b_idx is -1 and this falls back to
 * find_verified_b(), trying every in-use B session against the
 * binding-tag HMAC rather than a single positional guess. */
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
    }

    result = find_verified_b(&a_sess->e2e_key, a_sess->binding_tag, a_sess);
    if (result) result->in_flight++; /* pinned, caller must unpin at done: */
    LeaveCriticalSection(&g_sess_lock);
    return result;
}

/* Send response through return path. See service_gateway.c's
 * send_response_ex() for the full rationale on use_hdr/flags (M-c). */
static int send_response_ex(sg_session_t *a_sess, sg_session_t *b_sess,
                             const uint8_t use_hdr[RETURN_HEADER_SIZE],
                             uint8_t flags,
                             const uint8_t *resp, size_t resp_len) {
    /* Step 5.2: encrypt under K_R-SG-B. Capacity is RETURN_PAYLOAD_SIZE-2,
     * not RETURN_PAYLOAD_SIZE, see service_gateway.c::send_response()
     * for why (2-byte enc_len prefix reserved in the same wire region).
     * Explicit bound here rather than relying only on crypto_aes_encrypt's
     * own out_size check, see service_gateway.c::send_response().
     * -1 for the new leading flags byte (M-c). */
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

    /* Step 5.4: pre-apply all three return-path blindings, see
     * service_gateway.c::send_response() for the full rationale. */
    size_t blind_len = WIRE_PACKET_SIZE - RETURN_HEADER_SIZE;
    for (int hop = N_PATH_HOPS - 1; hop >= 0; hop--) {
        uint8_t tmp[WIRE_PACKET_SIZE - RETURN_HEADER_SIZE];
        if (packet_aes_ctr_xor(a_sess->recv_blind[hop].key, AES_KEY_LEN,
                               wire + RETURN_HEADER_SIZE, blind_len,
                               tmp) != 0) {
            log_err("response pre-blind failed"); return -1;
        }
        memcpy(wire + RETURN_HEADER_SIZE, tmp, blind_len);
    }

    /* Extract MNc addr */
    char mnc_ip[16];
    snprintf(mnc_ip, sizeof(mnc_ip), "%u.%u.%u.%u",
             a_sess->mnc_addr[0], a_sess->mnc_addr[1],
             a_sess->mnc_addr[2], a_sess->mnc_addr[3]);
    uint16_t mnc_port = (uint16_t)((a_sess->mnc_addr[4]<<8)|a_sess->mnc_addr[5]);

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

static int send_response(sg_session_t *a_sess, sg_session_t *b_sess,
                          const uint8_t *resp, size_t resp_len) {
    return send_response_ex(a_sess, b_sess, a_sess->return_hdr, PKT_REAL,
                            resp, resp_len);
}

typedef struct { SOCKET s; } conn_ctx_t;

static DWORD WINAPI handle_connection(LPVOID arg) {
    conn_ctx_t *ctx = (conn_ctx_t *)arg;
    SOCKET sock = ctx->s; free(ctx);

    /* See service_gateway.c's handle_connection() for the full
     * rationale: function-scoped so `done:` can unpin
     * whichever of these find_a_session()/find_b_for_a() pinned,
     * regardless of path taken. Not used for MODE_EXTEND's own
     * never-pinned `new_sess` below. */
    sg_session_t *sess = NULL, *b_sess = NULL;

    uint8_t mode = 0;
    if (net_recv_all(sock, &mode, 1) != 0) goto done;

    /* MODE_EXTEND */
    if (mode == MODE_EXTEND) {
        uint8_t role = 0;
        net_recv_all(sock, &role, 1);
        uint8_t tport[2]; net_recv_all(sock, tport, 2);
        uint8_t client_pub[EC_PUBKEY_LEN];
        if (net_recv_all(sock, client_pub, EC_PUBKEY_LEN) != 0) goto done;

        aes_key_t master = {0};
        if (crypto_ecdh_derive(&g_node_kp, client_pub, &master) != 0) goto done;

        sg_session_t *new_sess = sess_alloc();
        if (!new_sess) goto done;
        memcpy(new_sess->hint, client_pub + 1, HINT_BYTES);
        new_sess->e2e_key = master;
        new_sess->role    = role;

        char logbuf[64];
        snprintf(logbuf, sizeof(logbuf), "extend: session established (role=%u)", role);
        log_msg(logbuf);
        net_send_all(sock, g_node_kp.pubkey_bytes, EC_PUBKEY_LEN);
        goto done;
    }

    /* MODE_DATA */
    if (mode != MODE_DATA) goto done;

    wire_packet_t pkt = {0};
    if (net_recv_all(sock, pkt.data, WIRE_PACKET_SIZE) != 0) goto done;

    /* P5: MN3->SG forward-inbound link total, real+cover undifferentiated
     *, see measure.h's comment. */
    measure_hop_bytes((LONGLONG)WIRE_PACKET_SIZE);

    /* P4: count every wire packet that arrives at the SG, regardless of
     * type.  This measures raw processing throughput, the metric for
     * Table 2.  Cover packets (PKT_DUMMY) are dropped by find_a_session
     * but we still count their arrival since the SG processed the receive. */
    measure_sg_goodput((LONGLONG)WIRE_PACKET_SIZE);

    uint8_t  payload[MAX_INNER_PAYLOAD];
    uint16_t plen = 0;
    uint8_t  flags = 0;

    sess = find_a_session(&pkt, payload, &plen, &flags);
    if (!sess) { goto done; }   /* drop silently, already counted above */

    /* Return-path cover, see service_gateway.c's identical branch
     * for the full rationale. */
    if (flags & PKT_DUMMY) {
        if (sess->setup_done) {
            b_sess = find_b_for_a(sess);
            if (b_sess && plen >= RETURN_HEADER_SIZE) {
                uint8_t junk[32];
                if (RAND_bytes(junk, sizeof(junk)) == 1) {
                    send_response_ex(sess, b_sess, payload, PKT_DUMMY,
                                     junk, sizeof(junk));
                }
            }
        }
        goto done;
    }

    /* TYPE_SETUP */
    if (payload[0] == TYPE_SETUP) {
        /* Payload doesn't carry sending-path blind keys. */
        char _s[80]; snprintf(_s,sizeof(_s),"setup: plen=%u min=%zu", plen, (size_t)(1+N_PATH_HOPS*AES_KEY_LEN+MAC_BYTES+EC_PUBKEY_LEN+ADDR_BYTES+RETURN_HEADER_SIZE)); log_msg(_s);
        if (plen < 1 + N_PATH_HOPS*AES_KEY_LEN + MAC_BYTES + EC_PUBKEY_LEN + ADDR_BYTES + RETURN_HEADER_SIZE) {
            log_err("setup: payload too short"); goto done;
        }
        size_t off = 1;

        /* Pre-blind outgoing: MNc, MNb, MNa */
        for (int i = 0; i < N_PATH_HOPS; i++) {
            memcpy(sess->recv_blind[i].key, payload + off, AES_KEY_LEN);
            off += AES_KEY_LEN;
        }
        memcpy(sess->binding_tag, payload + off, MAC_BYTES); off += MAC_BYTES;
        memcpy(sess->mnc_pubkey,  payload + off, EC_PUBKEY_LEN); off += EC_PUBKEY_LEN;
        memcpy(sess->mnc_addr,    payload + off, ADDR_BYTES); off += ADDR_BYTES;
        memcpy(sess->return_hdr,  payload + off, RETURN_HEADER_SIZE);

        /* Verify binding tag */
        b_sess = find_b_for_a(sess);
        if (b_sess) {
            uint8_t computed[MAC_BYTES];
            packet_derive_binding_tag(&sess->e2e_key, &b_sess->e2e_key, computed);
            if (crypto_memcmp(computed, sess->binding_tag, MAC_BYTES) == 0) {
                sess->b_key    = b_sess->e2e_key;
                sess->setup_done = 1;
                sess->bound_b_idx = (int)(b_sess - g_sessions);
                log_msg("setup: binding tag verified, session active");
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
            sess->setup_done = 0;
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

    if (plen < EC_PUBKEY_LEN + ADDR_BYTES + RETURN_HEADER_SIZE + 2) {
        log_err("payload too short"); goto done;
    }

    /* Use routing info from payload (same each request, but update stored) */
    size_t off = 0;
    uint8_t mnc_pubkey[EC_PUBKEY_LEN];
    memcpy(mnc_pubkey, payload + off, EC_PUBKEY_LEN); off += EC_PUBKEY_LEN;
    uint8_t mnc_addr[ADDR_BYTES];
    memcpy(mnc_addr, payload + off, ADDR_BYTES); off += ADDR_BYTES;
    /* Update stored return header and addr from this packet */
    memcpy(sess->return_hdr, payload + off, RETURN_HEADER_SIZE); off += RETURN_HEADER_SIZE;
    memcpy(sess->mnc_addr,   mnc_addr, ADDR_BYTES);

    uint8_t type = payload[off++];
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
            /* Bound check, see service_gateway.c's identical fix. */
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
    }

    if (rlen > 0) {
        send_response(sess, b_sess, resp, rlen);
    }

done:
    /* Unpin whichever of sess/b_sess find_a_session()/find_b_for_a()
     * pinned: see service_gateway.c's identical
     * cleanup for the full rationale. */
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
    measure_init(MEASURE_P4 | MEASURE_P5);  /* P4: sg_goodput.csv | P5: per-hop link bytes */
    if (net_init() != 0) return 1;

    if (crypto_ecdh_keygen(&g_node_kp) != 0) return 1;
    CreateDirectoryA(PUBKEY_DIR, NULL);
    char p[256];
    snprintf(p, sizeof(p), "%s/%u.pub", PUBKEY_DIR, (unsigned)PORT_SERVICE_GW);
    crypto_pubkey_save(&g_node_kp, p);
    printf("[SvcGW] pubkey written to %s\n", p);

    SOCKET srv = net_listen(PORT_SERVICE_GW);
    if (srv == INVALID_SOCKET) return 1;
    log_msg("ready");

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
