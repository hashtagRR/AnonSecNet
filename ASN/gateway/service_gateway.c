/* service_gateway.c  --  Service Gateway (:9010)  --  Anon-Sec-Net v2 */

#include "common/net.h"
#include "common/crypto.h"
#include "common/packet.h"
#include "common/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

static void log_msg(const char *m){printf("[SvcGW] %s\n",m);fflush(stdout);}
static void log_err(const char *m){fprintf(stderr,"[SvcGW] ERROR: %s\n",m);fflush(stderr);}

/* ── Session store ──────────────────────────────────────────────────────── */
#define MAX_SESSIONS 32

typedef struct {
    uint8_t   hint[HINT_BYTES];
    aes_key_t e2e_key;
    uint8_t   role;
    /* Set by TYPE_SETUP (role=A session only) */
    aes_key_t send_blind[N_PATH_HOPS]; /* SK_R-MN1/2/3: unblind incoming  */
    aes_key_t recv_blind[N_PATH_HOPS]; /* SK_R-MNc/b/a: pre-blind outgoing*/
    uint8_t   binding_tag[MAC_BYTES];
    uint8_t   mnc_pubkey[EC_PUBKEY_LEN];
    uint8_t   mnc_addr[ADDR_BYTES];
    uint8_t   return_hdr[RETURN_HEADER_SIZE];
    aes_key_t b_key;    /* K_R-SG-B, found after binding tag verified */
    int       setup_done;
    int       in_use;
} sg_session_t;

static sg_session_t     g_sessions[MAX_SESSIONS];
static CRITICAL_SECTION g_sess_lock;
static ecdh_keypair_t   g_node_kp = {0};

static sg_session_t *sess_alloc(void) {
    EnterCriticalSection(&g_sess_lock);
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_sessions[i].in_use) {
            memset(&g_sessions[i], 0, sizeof(g_sessions[i]));
            g_sessions[i].in_use = 1;
            LeaveCriticalSection(&g_sess_lock);
            return &g_sessions[i];
        }
    }
    LeaveCriticalSection(&g_sess_lock);
    return NULL;
}

/* ── Find session by trying to unwrap packet ────────────────────────────── */
static sg_session_t *find_a_session(const wire_packet_t *pkt,
                                     uint8_t *payload_out,
                                     uint16_t *plen_out,
                                     uint8_t  *flags_out) {
    EnterCriticalSection(&g_sess_lock);
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_sessions[i].in_use) continue;
        if (g_sessions[i].role != SESSION_ROLE_A) continue;

        uint8_t  tmp[MAX_INNER_PAYLOAD];
        uint16_t tlen = 0; uint8_t tf = 0;
        if (packet_sphinx_unwrap(pkt, &g_sessions[i].e2e_key,
                                 tmp, &tlen, &tf) != 0) continue;
        if (tf & PKT_DUMMY) continue;
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
            if (tmp[toff] == TYPE_GET || tmp[toff] == TYPE_PUT)
                ptype = tmp[toff];
        }
        if (ptype == 0xFF) continue;

        /* Extra validation for GET/PUT: localhost IP check +
         * verify the embedded addr matches this session's stored addr */
        if (ptype != TYPE_SETUP) {
            if (tmp[EC_PUBKEY_LEN] != 127) continue;
            /* Only accept if setup is done for this session */
            if (!g_sessions[i].setup_done) continue;
            /* Check embedded addr port matches stored mnc_addr port */
            uint16_t pkt_port = (uint16_t)((tmp[EC_PUBKEY_LEN+4]<<8)|tmp[EC_PUBKEY_LEN+5]);
            uint16_t ses_port = (uint16_t)((g_sessions[i].mnc_addr[4]<<8)|
                                            g_sessions[i].mnc_addr[5]);
            if (pkt_port != ses_port) continue;
        }

        /* For TYPE_SETUP: verify binding tag to ensure correct session match.
         * binding_tag is at offset 1 + 6*AES_KEY_LEN = 1 + 192 = 193 */
        if (ptype == TYPE_SETUP) {
            size_t btag_off = 1 + 6 * AES_KEY_LEN;
            if (tlen < btag_off + MAC_BYTES) continue;

            /* Find B session immediately after this A session */
            sg_session_t *b_cand = NULL;
            for (int j = i+1; j < MAX_SESSIONS; j++) {
                if (g_sessions[j].in_use &&
                    g_sessions[j].role == SESSION_ROLE_B) {
                    b_cand = &g_sessions[j]; break;
                }
            }
            if (!b_cand) continue; /* no B session yet -- skip */

            uint8_t xk[AES_KEY_LEN];
            for (int k = 0; k < AES_KEY_LEN; k++)
                xk[k] = g_sessions[i].e2e_key.key[k] ^ b_cand->e2e_key.key[k];
            uint8_t computed[MAC_BYTES];
            packet_hmac(xk, AES_KEY_LEN,
                        (uint8_t *)LABEL_BINDING, strlen(LABEL_BINDING),
                        computed);
            if (crypto_memcmp(computed, tmp + btag_off, MAC_BYTES) != 0)
                continue; /* binding tag mismatch -- wrong session, try next */
        }

        memcpy(payload_out, tmp, tlen);
        *plen_out  = tlen;
        *flags_out = tf;
        LeaveCriticalSection(&g_sess_lock);
        return &g_sessions[i];
    }
    LeaveCriticalSection(&g_sess_lock);
    return NULL;
}

static sg_session_t *find_b_for_a(sg_session_t *a_sess) {
    EnterCriticalSection(&g_sess_lock);
    int found_a = 0;
    sg_session_t *result = NULL;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_sessions[i].in_use) continue;
        if (&g_sessions[i] == a_sess) { found_a = 1; continue; }
        if (found_a && g_sessions[i].role == SESSION_ROLE_B) {
            result = &g_sessions[i]; break;
        }
    }
    if (!result) {
        for (int i = 0; i < MAX_SESSIONS; i++) {
            if (g_sessions[i].in_use &&
                g_sessions[i].role == SESSION_ROLE_B &&
                &g_sessions[i] != a_sess) {
                result = &g_sessions[i]; break;
            }
        }
    }
    LeaveCriticalSection(&g_sess_lock);
    return result;
}

/* ── Send response through return path ─────────────────────────────────── */
static int send_response(sg_session_t *a_sess, sg_session_t *b_sess,
                          const uint8_t *resp, size_t resp_len) {
    /* Step 5.2: encrypt under K_R-SG-B */
    uint8_t enc[RETURN_PAYLOAD_SIZE];
    memset(enc, 0, sizeof(enc));
    int enc_len = crypto_aes_encrypt(&b_sess->e2e_key,
                                     resp, resp_len,
                                     enc, sizeof(enc));
    if (enc_len < 0) { log_err("response encrypt failed"); return -1; }

    /* Step 5.4: pre-blinding deferred -- return path nodes do not
     * yet apply blinding. Response is enc_K_R-SG-B only.
     * TODO: enable when handle_return applies matching unblinding. */

    /* Build wire packet: [return_header][enc_len(2)][enc_payload] */
    uint8_t wire[WIRE_PACKET_SIZE];
    memset(wire, 0, sizeof(wire));
    memcpy(wire, a_sess->return_hdr, RETURN_HEADER_SIZE);
    wire[RETURN_HEADER_SIZE]   = (uint8_t)(enc_len >> 8);
    wire[RETURN_HEADER_SIZE+1] = (uint8_t)(enc_len & 0xFF);
    memcpy(wire + RETURN_HEADER_SIZE + 2, enc, (size_t)enc_len);

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

typedef struct { SOCKET s; } conn_ctx_t;

static DWORD WINAPI handle_connection(LPVOID arg) {
    conn_ctx_t *ctx = (conn_ctx_t *)arg;
    SOCKET sock = ctx->s; free(ctx);

    uint8_t mode = 0;
    if (net_recv_all(sock, &mode, 1) != 0) goto done;

    /* ── MODE_EXTEND ──────────────────────────────────────────────────── */
    if (mode == MODE_EXTEND) {
        uint8_t role = 0;
        net_recv_all(sock, &role, 1);
        uint8_t tport[2]; net_recv_all(sock, tport, 2);
        uint8_t client_pub[EC_PUBKEY_LEN];
        if (net_recv_all(sock, client_pub, EC_PUBKEY_LEN) != 0) goto done;

        aes_key_t master = {0};
        if (crypto_ecdh_derive(&g_node_kp, client_pub, &master) != 0) goto done;

        sg_session_t *sess = sess_alloc();
        if (!sess) goto done;
        memcpy(sess->hint, client_pub + 1, HINT_BYTES);
        sess->e2e_key = master;
        sess->role    = role;

        char logbuf[64];
        snprintf(logbuf, sizeof(logbuf), "extend: session established (role=%u)", role);
        log_msg(logbuf);
        net_send_all(sock, g_node_kp.pubkey_bytes, EC_PUBKEY_LEN);
        goto done;
    }

    /* ── MODE_DATA ────────────────────────────────────────────────────── */
    if (mode != MODE_DATA) goto done;

    wire_packet_t pkt = {0};
    if (net_recv_all(sock, pkt.data, WIRE_PACKET_SIZE) != 0) goto done;

    uint8_t  payload[MAX_INNER_PAYLOAD];
    uint16_t plen = 0;
    uint8_t  flags = 0;

    sg_session_t *sess = find_a_session(&pkt, payload, &plen, &flags);
    if (!sess) { log_err("no matching session -- drop"); goto done; }

    /* ── TYPE_SETUP ───────────────────────────────────────────────────── */
    if (payload[0] == TYPE_SETUP) {
        char _s[80]; snprintf(_s,sizeof(_s),"setup: plen=%u min=%zu", plen, (size_t)(1+6*AES_KEY_LEN+MAC_BYTES+EC_PUBKEY_LEN+ADDR_BYTES+RETURN_HEADER_SIZE)); log_msg(_s);
        if (plen < 1 + 6*AES_KEY_LEN + MAC_BYTES + EC_PUBKEY_LEN + ADDR_BYTES + RETURN_HEADER_SIZE) {
            log_err("setup: payload too short"); goto done;
        }
        size_t off = 1;

        /* Unblind incoming: reverse order MN3, MN2, MN1 */
        for (int i = 0; i < N_PATH_HOPS; i++) {
            memcpy(sess->send_blind[i].key, payload + off, AES_KEY_LEN);
            off += AES_KEY_LEN;
        }
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
        sg_session_t *b_sess = find_b_for_a(sess);
        if (b_sess) {
            uint8_t xor_key[AES_KEY_LEN];
            for (int i = 0; i < AES_KEY_LEN; i++)
                xor_key[i] = sess->e2e_key.key[i] ^ b_sess->e2e_key.key[i];
            uint8_t computed[MAC_BYTES];
            packet_hmac(xor_key, AES_KEY_LEN,
                        (uint8_t *)LABEL_BINDING, strlen(LABEL_BINDING),
                        computed);
            if (crypto_memcmp(computed, sess->binding_tag, MAC_BYTES) == 0) {
                sess->b_key    = b_sess->e2e_key;
                sess->setup_done = 1;
                log_msg("setup: binding tag verified -- session active");
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
            log_err("setup: B session not found -- stored pending");
        }
        goto done;
    }

    /* ── TYPE_GET / TYPE_PUT ──────────────────────────────────────────── */
    if (!sess->setup_done) {
        log_err("data before setup complete -- drop"); goto done;
    }

    /* Step 4.9: reverse blinding chain using SK_R-MN1/2/3
     * Client pre-applied: blind(blind(blind(P0, MN3), MN2), MN1)
     * MN1 XOR'd MN1, MN2 XOR'd MN2, MN3 XOR'd MN3 -- all cancelled.
     * payload is already P0 after packet_sphinx_unwrap.
     * The unwrap already used the E2E key correctly.
     * No additional unblinding needed here -- Sphinx handles it.        */

    sg_session_t *b_sess = find_b_for_a(sess);
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
    if (klen == 0 || off + klen > plen) { log_err("bad klen"); goto done; }

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
            net_recv_all(cs, resp, rl);
            net_close(cs);
            rlen = rl;
        }
    } else if (type == TYPE_PUT) {
        uint16_t clen = 0;
        if (off + 2 <= plen) {
            clen = (uint16_t)((payload[off]<<8)|payload[off+1]); off+=2;
        }
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

    if (rlen > 0) send_response(sess, b_sess, resp, rlen);

done:
    net_close(sock); return 0;
}

int main(void) {
    SetConsoleOutputCP(65001);
    memset(g_sessions, 0, sizeof(g_sessions));
    InitializeCriticalSection(&g_sess_lock);
    if (net_init() != 0) return 1;

    if (crypto_ecdh_keygen(&g_node_kp) != 0) return 1;
    CreateDirectoryA(PUBKEY_DIR, NULL);
    char p[256];
    snprintf(p, sizeof(p), "%s\\%u.pub", PUBKEY_DIR, (unsigned)PORT_SERVICE_GW);
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
