/* sender.c: Anonymous Service (Sender), Anon-Sec-Net v2
 *
 * Sender sending path:   Sender -> MNi(9040) -> MNii(9041) -> MNiii(9042) -> SvcGW
 * Sender receiving path: SvcGW  -> MNx(9043) -> MNy(9044)  -> MNz(9045)  -> Sender
 *
 * Every PUT payload has the same structure as the Client GET:
 *   [MNz_pubkey(65)][MNz_addr(6)][return_header(174)][TYPE_PUT(1)][klen(1)][key][clen(2)][content]
 *
 * The SvcGW extracts MNz_pubkey+addr+return_header, processes the PUT,
 * and routes the ACK response back through MNx->MNy->MNz->Sender.
 */

#include "common/net.h"
#include "common/crypto.h"
#include "common/packet.h"
#include "common/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common/posix_compat.h"
#include <math.h>
#include <openssl/rand.h>


static void log_msg(const char *m) { printf("[Sender] %s\n", m); fflush(stdout); }
static void log_err(const char *m) { fprintf(stderr,"[Sender] ERROR: %s\n",m); fflush(stderr); }

/* Session state */
typedef struct {
    /* Sending path: Sender -> MNi -> MNii -> MNiii -> SvcGW */
    sphinx_path_t send_path;
    aes_key_t     k_s_sg_a;       /* K_S-SG-A: end-to-end key path A      */

    /* Receiving path: SvcGW -> MNx -> MNy -> MNz -> Sender */
    hop_session_t recv_hops[N_PATH_HOPS]; /* [0]=MNz [1]=MNy [2]=MNx      */
    aes_key_t     k_s_sg_b;       /* K_S-SG-B: end-to-end key path B      */

    /* MNz info embedded in every outbound payload */
    uint8_t mnz_pubkey[EC_PUBKEY_LEN];
    uint8_t mnz_addr[ADDR_BYTES];

    /* Return header, rebuilt fresh before every request, not just
     * once per session. See client.c's identical fields/comment. */
    return_header_t return_hdr;
    uint8_t  return_addrs[N_PATH_HOPS][ADDR_BYTES];

    /* Sender response address */
    uint8_t sender_addr[ADDR_BYTES];

    /* Long-term content-signing identity: stable across restarts, unlike
     * send_path/recv_hops' per-session ECDH keys, so a Receiver's TOFU
     * pin of this key (see client.c's pin_sender_key()) survives the
     * Sender restarting. Reuses crypto_identity_load_or_create() exactly
     * as service_gateway.c/mix_node.c already do for node identity,
     * same mechanism, different purpose (signing uploaded content, not
     * ECDH handshake pubkeys). */
    ecdh_keypair_t identity_kp;

    int ready;
} sender_state_t;

static sender_state_t g_state = {0};

/* A fresh, random K_content is generated per uploaded key and used to
 * encrypt the content itself before it ever reaches CS, the content
 * signature alone isn't sufficient, since SG/CS would otherwise see
 * plaintext. This registry lets the heartbeat
 * thread (below) recall which K_content belongs to which key, so it
 * can answer a Receiver's live per-request ECDHE handshake without
 * needing to keep the original plaintext around. Guarded by
 * g_owned_keys_lock since upload_content() (main thread, via
 * run_interactive()) and heartbeat_thread() both touch it. */
#define MAX_OWNED_KEYS 64
typedef struct {
    char     key[65];
    aes_key_t k_content;
    int      in_use;
} owned_key_t;
static owned_key_t       g_owned_keys[MAX_OWNED_KEYS];
static CRITICAL_SECTION  g_owned_keys_lock;

static void remember_owned_key(const char *key, const aes_key_t *k_content) {
    EnterCriticalSection(&g_owned_keys_lock);
    owned_key_t *slot = NULL;
    for (int i = 0; i < MAX_OWNED_KEYS; i++) {
        if (g_owned_keys[i].in_use && strcmp(g_owned_keys[i].key, key) == 0) {
            slot = &g_owned_keys[i]; break;
        }
    }
    if (!slot) {
        for (int i = 0; i < MAX_OWNED_KEYS; i++) {
            if (!g_owned_keys[i].in_use) { slot = &g_owned_keys[i]; break; }
        }
    }
    if (slot) {
        strncpy(slot->key, key, sizeof(slot->key) - 1);
        slot->key[sizeof(slot->key) - 1] = '\0';
        memcpy(&slot->k_content, k_content, sizeof(aes_key_t));
        slot->in_use = 1;
    } else {
        log_err("owned-key registry full, cannot service future handshakes for this key");
    }
    LeaveCriticalSection(&g_owned_keys_lock);
}

/* Returns 1 and fills *out on a match, 0 if this Sender doesn't own `key`. */
static int lookup_owned_key(const char *key, aes_key_t *out) {
    int found = 0;
    EnterCriticalSection(&g_owned_keys_lock);
    for (int i = 0; i < MAX_OWNED_KEYS; i++) {
        if (g_owned_keys[i].in_use && strcmp(g_owned_keys[i].key, key) == 0) {
            memcpy(out, &g_owned_keys[i].k_content, sizeof(aes_key_t));
            found = 1;
            break;
        }
    }
    LeaveCriticalSection(&g_owned_keys_lock);
    return found;
}

/* See client.c's matching comment. Used for slot 0's session
 * (outbound_cover_thread()/send_setup(), unchanged), see
 * next_send_pkt_counter_for_slot() below for slots 1..N-1. */
static volatile LONG g_send_pkt_counter = 0;
static uint64_t next_send_pkt_counter(void) {
    return (uint64_t)(InterlockedIncrement(&g_send_pkt_counter) - 1);
}

/* Same reasoning as next_return_pkt_counter_for_slot()'s comment, just
 * the send direction instead of the return direction: mix_node.c's
 * session_confirm_hint_match() is called from both handle_data()
 * (forward/send path) and handle_return() (return path), and both use
 * the identical per-session rotating-hint-window mechanism, so each
 * slot needs its own independent send-path session and counter too. */
static volatile LONG g_slot_send_pkt_counter[SENDER_RESPONSE_PORT_COUNT] = {0};
static uint64_t next_send_pkt_counter_for_slot(int slot) {
    if (slot == 0) return next_send_pkt_counter();
    return (uint64_t)(InterlockedIncrement(&g_slot_send_pkt_counter[slot]) - 1);
}

static volatile LONG g_send_cover_pkt_counter = 0;
static uint64_t next_cover_pkt_counter(void) {
    return HINT_COVER_COUNTER_BASE +
           (uint64_t)(InterlockedIncrement(&g_send_cover_pkt_counter) - 1);
}

/* See client.c's matching
 * comment on next_return_pkt_counter(). Used for slot 0's session
 * (send_setup()/cover traffic/build_return_header_into(), all
 * pre-existing, unchanged), see next_return_pkt_counter_for_slot()
 * below for why slots 1..N-1 do NOT share this counter. */
static volatile LONG g_return_pkt_counter = 0;
static uint64_t next_return_pkt_counter(void) {
    return (uint64_t)(InterlockedIncrement(&g_return_pkt_counter) - 1);
}

/* Each slot needs its own independent counter, starting at 0, matching
 * what its own session's window actually expects: mix_node.c's
 * session_init_hint_window() anchors a fresh session's hint window at
 * counter 0, so a newly-created slot-N session's first-ever packet must
 * also start at 0, not wherever a counter shared across slots happened
 * to be. Slot 0 keeps using the shared g_return_pkt_counter above
 * (unchanged, pre-existing behavior for send_setup()/cover traffic). */
static volatile LONG g_slot_return_pkt_counter[SENDER_RESPONSE_PORT_COUNT] = {0};
static uint64_t next_return_pkt_counter_for_slot(int slot) {
    if (slot == 0) return next_return_pkt_counter();
    return (uint64_t)(InterlockedIncrement(&g_slot_return_pkt_counter[slot]) - 1);
}

/* Response mailbox pool, see SENDER_RESPONSE_PORT_COUNT's comment in
 * config.h. SENDER_RESPONSE_PORT_COUNT independent slots, each with its
 * own listener port/mailbox/lock, so that many real sends can be
 * genuinely in flight concurrently. A caller acquires
 * a free slot (acquire_slot()), builds its return header FOR THAT SLOT's
 * port (build_return_header_for_slot(), so the response actually lands
 * in the right mailbox), sends, waits on that slot's own event, then
 * releases it (release_slot()), no cross-caller lock needed beyond
 * the slot-pool bookkeeping itself. */
typedef struct {
    uint8_t          resp_buf[WIRE_PACKET_SIZE];
    volatile int     resp_ready;
    CRITICAL_SECTION resp_lock;
    HANDLE           resp_event;
    volatile int     in_use;
    /* A request that times out releases its slot while its
     * response may still be in flight (multi-hop relay, no cancellation).
     * If a new request reacquires the same slot before that stale
     * response arrives, response_listener() needs a way to tell it apart
     * from the new request's genuine answer. send_app_request()
     * stamps a fresh nonce here per send; sender_wait_response() only
     * accepts a response whose echoed nonce (service_gateway.c prepends
     * it back, see that file's `has_nonce`/`req_nonce`) matches, discarding
     * and continuing to wait on anything else. */
    uint8_t          pending_nonce[SLOT_NONCE_BYTES];
} send_slot_t;

static send_slot_t      g_slots[SENDER_RESPONSE_PORT_COUNT];
static CRITICAL_SECTION g_slot_pool_lock;
/* Precomputed per-slot [ip][port] address bytes, see build_paths(),
 * populated once at startup, read-only thereafter (safe for concurrent
 * reads from every worker thread). */
static uint8_t           g_slot_addr[SENDER_RESPONSE_PORT_COUNT][ADDR_BYTES];

/* Each slot needs its own receiving-path session, not just its own
 * port/mailbox: the hint-window matching (config.h's own comment)
 * assumes roughly in-order arrival on a given session, so packets from
 * multiple slots sharing one receiving-path session (g_state.recv_hops/
 * k_s_sg_b) can get silently dropped when a later-allocated packet's
 * match slides the window's base forward past an earlier one still in
 * flight. Reproduced live: a ~20% PUT-ACK loss rate with
 * only sequential PUTs plus an idle heartbeat_thread() sharing the one
 * session's counter, before this fix. Fixed the textbook-correct way,
 * not by re-serializing: each slot gets its OWN independent receiving-
 * path session (its own telescoped ECDHE handshake, own hint_seed/
 * counter/window at every hop), so concurrent slots can never race for
 * the same session's ordering. */
typedef struct {
    hop_session_t recv_hops[N_PATH_HOPS];
    aes_key_t     k_s_sg_b;
    uint8_t       mnz_pubkey[EC_PUBKEY_LEN];
    uint8_t       mnz_addr[ADDR_BYTES];
} slot_recv_session_t;
static slot_recv_session_t g_slot_recv[SENDER_RESPONSE_PORT_COUNT];

/* Send-path counterpart to g_slot_recv, see
 * next_send_pkt_counter_for_slot()'s comment for why the forward
 * direction needs the identical independent-session treatment. Each
 * slot gets its own full sphinx_path_t (own hops[], own e2e key, own
 * sg_hint) instead of sharing g_state.send_path. */
static sphinx_path_t g_slot_send[SENDER_RESPONSE_PORT_COUNT];

/* Simple polling acquire (5ms granularity) rather than a condition
 * variable: this codebase's Win32-style primitives (CRITICAL_SECTION/
 * Event, common/posix_compat.h) don't expose one, and 5ms is negligible
 * next to the ~150-200ms round trips this pool exists to overlap. Blocks
 * until a slot frees rather than failing, matches the old lock's own
 * blocking-wait behavior, just bounded at N-way concurrency instead of
 * 1-way. */
static int acquire_slot(void) {
    for (;;) {
        EnterCriticalSection(&g_slot_pool_lock);
        for (int i = 0; i < SENDER_RESPONSE_PORT_COUNT; i++) {
            if (!g_slots[i].in_use) {
                g_slots[i].in_use = 1;
                LeaveCriticalSection(&g_slot_pool_lock);
                return i;
            }
        }
        LeaveCriticalSection(&g_slot_pool_lock);
        Sleep(5);
    }
}

static void release_slot(int slot) {
    EnterCriticalSection(&g_slot_pool_lock);
    g_slots[slot].in_use = 0;
    LeaveCriticalSection(&g_slot_pool_lock);
}

/* Trust-on-first-use pubkey pinning, see
 * client.c's identical comment for the full scope/limits. Only applied
 * to this production binary, not the benchmark harness: mix nodes
 * generate a fresh ECDH keypair every restart, and the sweep scripts
 * restart nodes between every measurement point, so naive pinning there
 * would reject every run after the first as a false "MITM". */
#define PIN_DIR "sender_pins"

/* Same mechanism/rationale as client.c::recv_signed_descriptor(), see
 * that file's comment. */
static int recv_signed_descriptor(SOCKET s, uint16_t port,
                                   uint8_t out_node_pub[EC_PUBKEY_LEN]) {
    uint8_t identity_pub[EC_PUBKEY_LEN];
    uint8_t sig_len_byte;
    uint8_t sig[SIGNATURE_MAX_LEN];

    /* Reply is one padded frame now, see client.c::recv_signed_descriptor()
     * and net_send_padded_frame's comment in common/net.c. */
    uint8_t reply_buf[EC_PUBKEY_LEN + EC_PUBKEY_LEN + 1 + SIGNATURE_MAX_LEN];
    size_t  reply_len = 0;
    if (net_recv_padded_frame(s, reply_buf, &reply_len, sizeof(reply_buf)) != 0) return -1;
    if (reply_len < EC_PUBKEY_LEN + EC_PUBKEY_LEN + 1) return -1;
    size_t off = 0;
    memcpy(out_node_pub, reply_buf + off, EC_PUBKEY_LEN); off += EC_PUBKEY_LEN;
    memcpy(identity_pub, reply_buf + off, EC_PUBKEY_LEN); off += EC_PUBKEY_LEN;
    sig_len_byte = reply_buf[off++];
    if (sig_len_byte == 0 || sig_len_byte > SIGNATURE_MAX_LEN) return -1;
    if (off + sig_len_byte > reply_len) return -1;
    memcpy(sig, reply_buf + off, sig_len_byte);

    if (crypto_verify(identity_pub, out_node_pub, EC_PUBKEY_LEN,
                       sig, sig_len_byte) != 0) {
        fprintf(stderr,
                "[sender] descriptor signature verification FAILED for "
                "port %u, rejecting\n", (unsigned)port);
        return -1;
    }
    return crypto_pubkey_pin_check(port, identity_pub, PIN_DIR);
}

/* Telescoped ECDHE through an entry node.
 * Same mechanism/rationale as client.c::ecdhe_telescoped_path(), see
 * that file's comment. build_paths() below also
 * appends the SG as one more telescoped target at the end of each
 * ports[] array, see client.c's identical comment. */
static int ecdhe_telescoped_path(const uint16_t *ports, int n_hops,
                                  uint8_t role,
                                  aes_key_t masters[],
                                  uint8_t (*hints)[HINT_BYTES],
                                  uint8_t (*node_pubs)[EC_PUBKEY_LEN]) {
    SOCKET s = net_connect(LOCALHOST, ports[0]);
    if (s == INVALID_SOCKET) return -1;

    int ok = -1;
    for (int i = 0; i < n_hops; i++) {
        ecdh_keypair_t kp = {0};
        if (crypto_ecdh_keygen(&kp) != 0) goto done;
        memcpy(hints[i], kp.pubkey_bytes + 1, HINT_BYTES);

        uint16_t next_port = (i + 1 < n_hops) ? ports[i + 1] : 0;
        uint8_t  tport[2] = { (uint8_t)(next_port >> 8),
                               (uint8_t)(next_port & 0xFF) };

        /* [role(1)][tport(2)][pubkey(65)] as one padded frame, see
         * client.c::ecdhe_telescoped_path() and net_send_padded_frame's
         * comment in common/net.c. */
        uint8_t req_buf[1 + 2 + EC_PUBKEY_LEN];
        req_buf[0] = role;
        req_buf[1] = tport[0];
        req_buf[2] = tport[1];
        memcpy(req_buf + 3, kp.pubkey_bytes, EC_PUBKEY_LEN);

        if (i == 0) {
            uint8_t mode = MODE_EXTEND;
            net_send_all(s, &mode, 1);
            net_send_padded_frame(s, req_buf, sizeof(req_buf));
        } else {
            net_send_padded_frame(s, req_buf, sizeof(req_buf));
        }

        if (recv_signed_descriptor(s, ports[i], node_pubs[i]) != 0) {
            crypto_ecdh_free(&kp); goto done;
        }
        /* See client.c's matching
         * comment / crypto_ecdh_derive_bound()'s comment in crypto.h. */
        int rc2 = crypto_ecdh_derive_bound(&kp, node_pubs[i],
                                           kp.pubkey_bytes, node_pubs[i],
                                           ports[i], role, &masters[i]);
        crypto_ecdh_free(&kp);
        if (rc2 != 0) goto done;
    }
    ok = 0;
done:
    net_close(s);
    return ok;
}

/* Must match mix_node.c::split_master_keys() exactly (both call the same
 * packet_derive_hop_keys() KDF on the same shared master), or every MAC
 * the mix node checks on our packets will fail.
 */
static void derive_hop(const aes_key_t *master, hop_session_t *hop) {
    packet_derive_hop_keys(master, &hop->header_enc_key,
                            &hop->header_mac_key, &hop->blind_key);
    /* See client.c's matching comment. */
    if (packet_derive_hint_seed(master, &hop->hint_seed) != 0) {
        log_err("hint_seed derivation failed");
    }
}

static void make_addr_bytes(const char *ip, uint16_t port,
                             uint8_t out[ADDR_BYTES]) {
    unsigned a, b, c, d;
    sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d);
    out[0]=(uint8_t)a; out[1]=(uint8_t)b;
    out[2]=(uint8_t)c; out[3]=(uint8_t)d;
    out[4]=(uint8_t)(port>>8); out[5]=(uint8_t)(port&0xFF);
}

/* See client.c's identical function for the full rationale. */
static int build_return_header_into(return_header_t *out) {
    aes_key_t enc_keys[N_PATH_HOPS], mac_keys[N_PATH_HOPS];
    uint8_t   hints[N_PATH_HOPS][HINT_BYTES];
    uint64_t  ctr = next_return_pkt_counter();
    for (int i = 0; i < N_PATH_HOPS; i++) {
        enc_keys[i] = g_state.recv_hops[i].header_enc_key;
        mac_keys[i] = g_state.recv_hops[i].header_mac_key;
        if (packet_derive_hop_hint(&g_state.recv_hops[i].hint_seed, ctr, hints[i]) != 0) {
            log_err("return hint derivation failed"); return -1;
        }
    }
    return packet_build_return_header(enc_keys, mac_keys, hints,
                                      g_state.return_addrs, out);
}

static int build_fresh_return_header(void) {
    return build_return_header_into(&g_state.return_hdr);
}

/* Like build_return_header_into(), but the
 * final-delivery address (addrs[2]) is overridden to point at `slot`'s
 * own response port instead of the fixed g_state.sender_addr, so this
 * request's response lands in that slot's mailbox and not some other
 * concurrent request's. Builds a LOCAL copy of g_state.return_addrs
 * (read-only, so this is safe to call from multiple worker threads at
 * once) rather than mutating the shared array. */
static int build_return_header_for_slot(int slot, return_header_t *out) {
    uint8_t addrs[N_PATH_HOPS][ADDR_BYTES];
    memcpy(addrs, g_state.return_addrs, sizeof(addrs));
    memcpy(addrs[2], g_slot_addr[slot], ADDR_BYTES);

    /* Uses g_slot_recv[slot]'s own independent session (own hint_seed)
     * AND its own independent counter (next_return_pkt_counter_for_slot())
     *, see g_slot_recv's comment and that function's own comment for
     * why BOTH are needed: a shared session OR a shared counter each
     * independently break mix_node.c's per-session hint-window ordering
     * once multiple slots can be in flight concurrently. */
    aes_key_t enc_keys[N_PATH_HOPS], mac_keys[N_PATH_HOPS];
    uint8_t   hints[N_PATH_HOPS][HINT_BYTES];
    uint64_t  ctr = next_return_pkt_counter_for_slot(slot);
    for (int i = 0; i < N_PATH_HOPS; i++) {
        enc_keys[i] = g_slot_recv[slot].recv_hops[i].header_enc_key;
        mac_keys[i] = g_slot_recv[slot].recv_hops[i].header_mac_key;
        if (packet_derive_hop_hint(&g_slot_recv[slot].recv_hops[i].hint_seed, ctr, hints[i]) != 0) {
            log_err("return hint derivation failed"); return -1;
        }
    }
    return packet_build_return_header(enc_keys, mac_keys, hints, addrs, out);
}

/* See client.c's identical function. */
static int build_spare_return_header(return_header_t *out) {
    return build_return_header_into(out);
}

/* See client.c's
 * probe_rtt_ms() for the full rationale (why this is a pre-handshake
 * probe-and-swap rather than the paper's literal post-hoc SG-decided
 * reassignment, which role's cryptographic binding into the wire
 * protocol makes infeasible without a larger redesign). Sender's two
 * candidate paths are fixed port sets (PORT_MIX_I vs PORT_MIX_Z),
 * unlike client.c's fresh-per-session pool selection, but the same
 * probe-then-swap mechanism applies identically. */
static int probe_rtt_ms(uint16_t port) {
    uint64_t t0 = GetTickCount64();
    SOCKET s = net_connect(LOCALHOST, port);
    if (s == INVALID_SOCKET) return -1;
    uint64_t t1 = GetTickCount64();
    net_close(s);
    return (int)(t1 - t0);
}

/* Build both paths */
static int build_paths(void) {
    /* RTT probe BEFORE either path's role is committed, swap which
     * fixed port set becomes the outbound (A) candidate if MNz's entry
     * (the receiving path's telescoping entry) probes faster than
     * MNi's (the sending path's). */
    uint16_t a_ports[N_PATH_HOPS] = { PORT_MIX_I,   PORT_MIX_II, PORT_MIX_III };
    uint16_t b_ports[N_PATH_HOPS] = { PORT_MIX_Z,   PORT_MIX_Y,  PORT_MIX_X   };
    {
        int rtt_a = probe_rtt_ms(PORT_MIX_I);
        int rtt_b = probe_rtt_ms(PORT_MIX_Z);
        int a_slower_or_dead = (rtt_a < 0) || (rtt_b >= 0 && rtt_b < rtt_a);
        if (a_slower_or_dead) {
            uint16_t tmp[N_PATH_HOPS];
            memcpy(tmp, a_ports, sizeof(tmp));
            memcpy(a_ports, b_ports, sizeof(tmp));
            memcpy(b_ports, tmp, sizeof(tmp));
        }
        char logbuf[128];
        snprintf(logbuf, sizeof(logbuf),
                 "RTT probe: candidate-A(MNi)=%dms candidate-B(MNz)=%dms -> %s kept as outbound (A)",
                 rtt_a, rtt_b, a_slower_or_dead ? "MNz-side" : "MNi-side");
        log_msg(logbuf);
    }

    log_msg("building sending path (MNi->MNii->MNiii->SvcGW)...");

    uint16_t send_ports[N_PATH_HOPS] = { a_ports[0], a_ports[1], a_ports[2] };
    /* SG handshake tunneled through MNiii, same as
     * client.c's send path. */
    uint16_t send_ports_sg[N_PATH_HOPS + 1] = {
        send_ports[0], send_ports[1], send_ports[2], PORT_SERVICE_GW,
    };

    /* Telescoped through MNi, see client.c. One independent
     * telescoped handshake per slot, same rationale as the receiving
     * path's own loop below: mix_node.c's session_confirm_hint_match()
     * is called from handle_data(), the forward-path handler, just as
     * much as from handle_return(), so the forward path's
     * MNi/MNii/MNiii hops need the identical per-slot session
     * treatment. g_state.send_path/k_s_sg_a still get slot 0's copy,
     * for outbound_cover_thread()/send_setup()'s continued use. */
    for (int slot = 0; slot < SENDER_RESPONSE_PORT_COUNT; slot++) {
        aes_key_t masters[N_PATH_HOPS + 1];
        uint8_t   hints[N_PATH_HOPS + 1][HINT_BYTES];
        uint8_t   node_pubs[N_PATH_HOPS + 1][EC_PUBKEY_LEN];

        if (ecdhe_telescoped_path(send_ports_sg, N_PATH_HOPS + 1, SESSION_ROLE_A,
                                  masters, hints, node_pubs) != 0) {
            log_err("telescoped ECDHE failed on sending path"); return -1;
        }
        for (int i = 0; i < N_PATH_HOPS; i++) {
            derive_hop(&masters[i], &g_slot_send[slot].hops[i]);
            g_slot_send[slot].hop_ports[i] = send_ports[i];
        }

        /* E2E with SvcGW -> K_S-SG-A (last "hop" above) */
        g_slot_send[slot].e2e.e2e_key = masters[N_PATH_HOPS];
        /* Was a hardcoded PORT_MIX_I, must track send_ports[0], which
         * a probe-driven swap above may have set to PORT_MIX_Z instead. */
        g_slot_send[slot].next_port   = send_ports[0];
        g_slot_send[slot].sg_port     = PORT_SERVICE_GW;
        /* SG-side O(1) lookup hint, see client.c's
         * matching comment / packet_derive_sg_hint(). Static (derived
         * once from the E2E master, not counter-rotating), so unlike
         * the per-hop hints above it wouldn't strictly need to be
         * per-slot for correctness, built per-slot anyway since each
         * slot already has its own independent masters[] here, for
         * consistency with the rest of this loop rather than reasoning
         * about which one field could safely stay shared. */
        if (packet_derive_sg_hint(&masters[N_PATH_HOPS],
                                  &g_slot_send[slot].sg_hint) != 0) {
            log_err("failed to derive SG hint"); return -1;
        }

        if (slot == 0) {
            g_state.k_s_sg_a = masters[N_PATH_HOPS];
            memcpy(&g_state.send_path, &g_slot_send[0], sizeof(g_state.send_path));
        }

        char logbuf[80];
        snprintf(logbuf, sizeof(logbuf),
                 "  sending path ready for slot %d (MNi->MNii->MNiii->SvcGW)", slot);
        log_msg(logbuf);

        explicit_bzero(masters, sizeof(masters));
    }
    log_msg("  K_S-SG-A established (all slots, tunneled through MNiii)");

    log_msg("building receiving path (MNz->MNy->MNx->Sender)...");

    /* Receiving path: [0]=MNz (outermost/SG-facing), [1]=MNy, [2]=MNx (Sender-facing),
     * b_ports (possibly swapped above) replaces the old hardcoded triple. */
    uint16_t recv_ports[N_PATH_HOPS] = { b_ports[0], b_ports[1], b_ports[2] };
    /* SG handshake tunneled through MNx, same
     * rationale as client.c's receiving path. */
    uint16_t recv_ports_sg[N_PATH_HOPS + 1] = {
        recv_ports[0], recv_ports[1], recv_ports[2], PORT_SERVICE_GW,
    };

    /* Telescoped through MNz, see client.c. One independent
     * telescoped handshake per slot, not one shared by all of them,
     * see g_slot_recv's own comment for why (hint-window ordering).
     * Each slot's session lives on the
     * same physical MNz/MNy/MNx nodes but is otherwise a completely
     * separate session (own master keys, own hint_seed), exactly like
     * any two unrelated clients getting independent sessions on the
     * same node today. g_state.recv_hops/k_s_sg_b/mnz_pubkey/mnz_addr
     * still get slot 0's copy, for send_setup()'s one-time use. */
    for (int slot = 0; slot < SENDER_RESPONSE_PORT_COUNT; slot++) {
        aes_key_t masters[N_PATH_HOPS + 1];
        uint8_t   hints[N_PATH_HOPS + 1][HINT_BYTES];
        uint8_t   node_pubs[N_PATH_HOPS + 1][EC_PUBKEY_LEN];

        if (ecdhe_telescoped_path(recv_ports_sg, N_PATH_HOPS + 1, SESSION_ROLE_B,
                                  masters, hints, node_pubs) != 0) {
            log_err("telescoped ECDHE failed on receiving path"); return -1;
        }
        for (int i = 0; i < N_PATH_HOPS; i++) {
            derive_hop(&masters[i], &g_slot_recv[slot].recv_hops[i]);

            /* Store MNz pubkey and addr (index 0 = MNz = SG-facing = first on return),
             * recv_ports[0], not a hardcoded PORT_MIX_Z, so this stays
             * correct after a probe-driven swap. */
            if (i == 0) {
                memcpy(g_slot_recv[slot].mnz_pubkey, node_pubs[0], EC_PUBKEY_LEN);
                make_addr_bytes(LOCALHOST, recv_ports[0], g_slot_recv[slot].mnz_addr);
            }
        }

        /* E2E with SvcGW -> K_S-SG-B (last "hop" above) */
        g_slot_recv[slot].k_s_sg_b = masters[N_PATH_HOPS];

        if (slot == 0) {
            memcpy(g_state.recv_hops, g_slot_recv[0].recv_hops, sizeof(g_state.recv_hops));
            g_state.k_s_sg_b = g_slot_recv[0].k_s_sg_b;
            memcpy(g_state.mnz_pubkey, g_slot_recv[0].mnz_pubkey, EC_PUBKEY_LEN);
            memcpy(g_state.mnz_addr, g_slot_recv[0].mnz_addr, ADDR_BYTES);
        }

        char logbuf[80];
        snprintf(logbuf, sizeof(logbuf),
                 "  receiving path ready for slot %d (MNz->MNy->MNx->Sender)", slot);
        log_msg(logbuf);

        explicit_bzero(masters, sizeof(masters));
    }
    log_msg("  K_S-SG-B established (all slots, tunneled through MNx)");

    /* Sender response address(es): SENDER_RESPONSE_PORT_COUNT
     * independent ports/slots instead of one, see config.h's comment.
     * g_state.sender_addr keeps slot 0's address
     * for send_setup()'s one-time, single-threaded use (unchanged, still
     * the fixed base port), every other real send goes through
     * build_return_header_for_slot() instead, which uses g_slot_addr[]. */
    make_addr_bytes(LOCALHOST, SENDER_RESPONSE_PORT, g_state.sender_addr);
    for (int i = 0; i < SENDER_RESPONSE_PORT_COUNT; i++) {
        make_addr_bytes(LOCALHOST, (uint16_t)(SENDER_RESPONSE_PORT + i), g_slot_addr[i]);
    }

    /* Return-header addrs are static for the session's lifetime:
     * addrs[0] = MNy addr  (MNz learns this)
     * addrs[1] = MNx addr  (MNy learns this)
     * addrs[2] = Sender addr (MNx learns this, final delivery); the
     * shared g_state.return_addrs[2] below is only a placeholder used by
     * send_setup()'s one-time build_fresh_return_header() call (slot 0),
     * every per-request send overrides addrs[2] itself via
     * build_return_header_for_slot(). recv_ports[1]/[2], not hardcoded
     * PORT_MIX_Y/X, so this stays correct after a probe-driven swap. */
    make_addr_bytes(LOCALHOST, recv_ports[1], g_state.return_addrs[0]);
    make_addr_bytes(LOCALHOST, recv_ports[2], g_state.return_addrs[1]);
    memcpy(g_state.return_addrs[2], g_state.sender_addr, ADDR_BYTES);

    if (build_fresh_return_header() != 0) {
        log_err("build return header failed"); return -1;
    }

    g_state.ready = 1;
    log_msg("both paths ready");
    return 0;
}

/* Response listener: one thread per slot, each bound to its own port
 * (SENDER_RESPONSE_PORT + slot) and writing into its own mailbox, so
 * concurrent in-flight requests never collide. Decryption uses
 * g_slot_recv[slot].k_s_sg_b, this slot's own independent E2E key, not
 * a shared one (see g_slot_recv's own comment for why sharing breaks
 * the hint-window ordering once slots can be concurrent). `arg` is
 * the slot index, passed via CreateThread. */
static DWORD WINAPI response_listener(LPVOID arg) {
    int slot = (int)(intptr_t)arg;
    uint16_t port = (uint16_t)(SENDER_RESPONSE_PORT + slot);
    SOCKET srv = net_listen(port);
    if (srv == INVALID_SOCKET) { log_err("response listener failed"); return 1; }

    char logbuf[64];
    snprintf(logbuf, sizeof(logbuf), "ACK listener on port %u (slot %d)", port, slot);
    log_msg(logbuf);

    while (1) {
        SOCKET conn = net_accept(srv);
        if (conn == INVALID_SOCKET) break;

        uint8_t wire[WIRE_PACKET_SIZE];
        if (net_recv_all(conn, wire, WIRE_PACKET_SIZE) == 0) {
            size_t enc_len = (size_t)((wire[RETURN_HEADER_SIZE] << 8) |
                                       wire[RETURN_HEADER_SIZE+1]);
            /* Real responses are small, filter obvious random cover packets */
            if (enc_len >= GCM_OVERHEAD && enc_len <= 512) {
                uint8_t tmp[RETURN_PAYLOAD_SIZE];
                int n = crypto_aes_decrypt(&g_slot_recv[slot].k_s_sg_b,
                                           wire + RETURN_HEADER_SIZE + 2,
                                           enc_len, tmp, sizeof(tmp));
                /* M-c: see client.c's identical comment, leading
                 * plaintext flags byte, not GCM success/failure, is what
                 * distinguishes real from cover now. */
                if (n > 0 && (size_t)n >= 1 && tmp[0] == PKT_REAL) {
                    EnterCriticalSection(&g_slots[slot].resp_lock);
                    memcpy(g_slots[slot].resp_buf, wire, WIRE_PACKET_SIZE);
                    g_slots[slot].resp_ready = 1;
                    SetEvent(g_slots[slot].resp_event);
                    LeaveCriticalSection(&g_slots[slot].resp_lock);
                }
            }
        }
        net_close(conn);
    }
    net_close(srv);
    return 0;
}


/* Send session setup packet to SG, for one slot's session.
 *
 * Each slot's independent E2E master key (see g_slot_send's comment)
 * means each slot is a genuinely different role-A session on the SG,
 * keyed by its own sg_hint (service_gateway.c's sg_session_t table,
 * derived from that slot's own E2E master via packet_derive_sg_hint()).
 * TYPE_SETUP registers a role-A session's receiving-path info
 * (recv_blind[]/binding_tag/mnz_pubkey/mnz_addr/return_hdr) with the SG
 * so it knows how to route that session's replies, this runs once per
 * slot, not just once, so every slot's session gets registered and the
 * SG has somewhere correct to send each one's replies. */
static int send_setup_for_slot(int slot) {
    return_header_t hdr;
    if (build_return_header_for_slot(slot, &hdr) != 0) {
        log_err("failed to refresh return header"); return -1;
    }

    /* See client.c's matching comment. */
    uint8_t binding_tag[MAC_BYTES];
    aes_key_t k_s_sg_a = g_slot_send[slot].e2e.e2e_key;
    if (packet_derive_binding_tag(&k_s_sg_a, &g_slot_recv[slot].k_s_sg_b,
                                  binding_tag) != 0) {
        log_err("binding tag derivation failed"); return -1;
    }

    uint8_t payload[MAX_INNER_PAYLOAD];
    memset(payload, 0, sizeof(payload));
    size_t off = 0;

    payload[off++] = TYPE_SETUP;

    /* Sending-path blind keys (SK_S-MNi/MNii/MNiii) are deliberately NOT
     * sent to the SG, it never reads them (it only pre-blinds the
     * RETURN path, using the receiving-path keys below). Including them
     * would shift every following field 96 bytes past where
     * service_gateway.c's TYPE_SETUP parser reads them (fixed
     * btag_off = 1 + N_PATH_HOPS*AES_KEY_LEN), breaking the binding-tag
     * HMAC check. */
    /* SK receiving path blind keys ([0]=MNz, [1]=MNy, [2]=MNx) */
    for (int i = 0; i < N_PATH_HOPS; i++) {
        memcpy(payload + off, g_slot_recv[slot].recv_hops[i].blind_key.key, AES_KEY_LEN);
        off += AES_KEY_LEN;
    }
    memcpy(payload + off, binding_tag, MAC_BYTES); off += MAC_BYTES;
    memcpy(payload + off, g_slot_recv[slot].mnz_pubkey, EC_PUBKEY_LEN); off += EC_PUBKEY_LEN;
    memcpy(payload + off, g_slot_recv[slot].mnz_addr,   ADDR_BYTES);    off += ADDR_BYTES;
    memcpy(payload + off, &hdr, RETURN_HEADER_SIZE); off += RETURN_HEADER_SIZE;

    /* Waits for a genuine SETUP ack before returning, see client.c's
     * matching comment for the full rationale. service_gateway.c can't
     * tell a sender's SETUP from a client's, so it acks every one; this
     * must consume that ack here (mirroring upload_content()'s own
     * g_resp_event handling further down in this file), or it would sit
     * unconsumed on g_resp_event and get wrongly picked up by
     * upload_content()'s own ACK wait later, corrupting its PUT-success
     * signal. */
    for (int attempt = 0; attempt < 2; attempt++) {
        if (attempt > 0) {
            log_err("send_setup: no ack, retrying once");
        }

        wire_packet_t pkt = {0};
        if (packet_sphinx_build(&g_slot_send[slot], payload, (uint16_t)off,
                                PKT_REAL | PKT_DEST_SERVICE,
                                next_send_pkt_counter_for_slot(slot), &pkt) != 0) {
            log_err("send_setup: build failed"); return -1;
        }

        SOCKET s = net_connect(LOCALHOST, g_slot_send[slot].hop_ports[0]);
        if (s == INVALID_SOCKET) { log_err("send_setup: connect MNi"); return -1; }
        uint8_t mode = MODE_DATA;
        net_send_all(s, &mode, 1);
        net_send_all(s, pkt.data, WIRE_PACKET_SIZE);
        net_close(s);

        char logbuf[64];
        snprintf(logbuf, sizeof(logbuf), "session setup sent to SG for slot %d, awaiting ack", slot);
        log_msg(logbuf);

        /* One-time, single-threaded call (before heartbeat_thread()/
         * run_interactive() start), uses this slot's mailbox directly
         * rather than the acquire_slot() pool, since every slot's setup
         * happens sequentially at startup, before any concurrent use
         * begins. */
        if (WaitForSingleObject(g_slots[slot].resp_event, 3000) == WAIT_OBJECT_0) {
            EnterCriticalSection(&g_slots[slot].resp_lock);
            g_slots[slot].resp_ready = 0;
            ResetEvent(g_slots[slot].resp_event);
            LeaveCriticalSection(&g_slots[slot].resp_lock);
            char okbuf[64];
            snprintf(okbuf, sizeof(okbuf), "session setup acknowledged by SG for slot %d", slot);
            log_msg(okbuf);
            return 0;
        }
    }
    log_err("send_setup: no ack after retry");
    return -1;
}


/* Outbound cover traffic */
/* volatile LONG + InterlockedIncrement/Decrement, not a plain volatile
 * int with separate read-then-write: a read followed by a separate
 * write would race against the sender's own "flag = 1", letting a real
 * packet queued in that gap have its suppression signal silently lost.
 * Matches client.c's equivalent mechanism. */
static volatile LONG g_real_traffic_pending = 0;

#ifdef ASN_LOOPIX_MIXING
/* Loopix-style shared dispatch mailbox, see client.c's matching comment
 * for the full rationale (an earlier independent-clock design was
 * measured to leak more than the un-hardened mechanism). */
static CRITICAL_SECTION g_mailbox_lock;
static wire_packet_t    g_pending_real_pkt;
static volatile LONG    g_pending_real_flag = 0;
#endif

/* Mirrors client.c's rate_tier_init()/
 * g_rate_tier_interval_ms: see config.h's RATE_TIER_INTERVALS_MS
 * comment and client.c's matching functions for the full rationale. */
static double g_rate_tier_interval_ms = DUMMY_INTERVAL_MS;

static int rate_tier_init(void) {
    static const double kTierMs[N_RATE_TIERS] = RATE_TIER_INTERVALS_MS;
    const char *path = "sender_rate_tier.txt";

    int tier = -1;
    FILE *f = fopen(path, "r");
    if (f) {
        if (fscanf(f, "%d", &tier) != 1 || tier < 0 || tier >= N_RATE_TIERS)
            tier = -1;
        fclose(f);
    }
    if (tier < 0) {
        uint32_t r;
        if (RAND_bytes((uint8_t *)&r, sizeof(r)) != 1) r = 0;
        tier = (int)(r % N_RATE_TIERS);
        f = fopen(path, "w");
        if (f) { fprintf(f, "%d\n", tier); fclose(f); }
    }
    g_rate_tier_interval_ms = kTierMs[tier];
    return 0;
}

static DWORD poisson_interval_ms(void) {
    /* RAND_bytes, not libc rand(), rand()/srand() is process-global,
     * non-thread-safe, and (seeded from GetTickCount()) guessable,
     * weakening the cover-traffic unlinkability property this interval
     * exists to provide. Matches mix_node.c's mix_delay_sleep() fix. */
    uint32_t r;
    if (RAND_bytes((uint8_t *)&r, sizeof(r)) != 1) r = 1;
    double u = ((double)r + 1.0) / (4294967296.0 + 1.0);
    double iv = -g_rate_tier_interval_ms * log(u);
    if (iv < 10.0) iv = 10.0;
    if (iv > 1000.0) iv = 1000.0;
    return (DWORD)iv;
}

/* See client.c's identical function. */
static int build_outbound_cover_with_spare_return(uint64_t pkt_counter,
                                                    wire_packet_t *out) {
    return_header_t spare = {0};
    if (build_spare_return_header(&spare) != 0) return -1;

    uint8_t payload[MAX_INNER_PAYLOAD];
    if (RAND_bytes(payload, MAX_INNER_PAYLOAD) != 1) return -1;
    memcpy(payload, &spare, RETURN_HEADER_SIZE);

    return packet_sphinx_build(&g_state.send_path, payload, MAX_INNER_PAYLOAD,
                               PKT_DUMMY | PKT_DEST_SERVICE,
                               pkt_counter, out);
}

#ifdef ASN_HOP_DECOY
/* See client.c's identical functions. */
static int pick_weighted_drop_hop(void) {
    uint32_t r;
    if (RAND_bytes((uint8_t *)&r, sizeof(r)) != 1) r = 0;
    int pct = (int)(r % 100);
    if (pct < HOP_DECOY_ENTRY_WEIGHT_PCT) return 0;
    if (pct < HOP_DECOY_ENTRY_WEIGHT_PCT + HOP_DECOY_MID_WEIGHT_PCT) return 1;
    return 2;
}

static int build_cover_slot(uint64_t pkt_counter, wire_packet_t *out) {
    uint32_t r;
    if (RAND_bytes((uint8_t *)&r, sizeof(r)) != 1) r = 100;
    if ((int)(r % 100) < HOP_DECOY_FRACTION_PCT) {
        return packet_sphinx_decoy_hop(&g_state.send_path, pkt_counter,
                                        pick_weighted_drop_hop(), out);
    }
    return build_outbound_cover_with_spare_return(pkt_counter, out);
}
#else
#define build_cover_slot build_outbound_cover_with_spare_return
#endif

static DWORD WINAPI outbound_cover_thread(LPVOID arg) {
    (void)arg;
    while (1) {
        Sleep(poisson_interval_ms());
        if (!g_state.ready) continue;

        wire_packet_t out = {0};

#ifdef ASN_LOOPIX_MIXING
        int have_real = 0;
        EnterCriticalSection(&g_mailbox_lock);
        if (g_pending_real_flag) {
            memcpy(&out, &g_pending_real_pkt, sizeof(out));
            g_pending_real_flag = 0;
            have_real = 1;
        }
        LeaveCriticalSection(&g_mailbox_lock);

        if (!have_real) {
            if (build_cover_slot(
                    next_cover_pkt_counter(), &out) != 0) continue;
        }
#else
        /* Adaptive suppression, see client.c's matching comment.
         * Atomic test-and-clear in one operation. */
        if (InterlockedExchange(&g_real_traffic_pending, 0)) { continue; }

        if (build_cover_slot(
                next_cover_pkt_counter(), &out) != 0) continue;
#endif
        SOCKET s = net_connect(LOCALHOST, g_state.send_path.hop_ports[0]);
        if (s == INVALID_SOCKET) continue;
        uint8_t mode = MODE_DATA;
        net_send_all(s, &mode, 1);
        net_send_all(s, out.data, WIRE_PACKET_SIZE);
        net_close(s);
    }
    return 0;
}

/* Generalized request sender, factored out of upload_content()'s own
 * payload-building/dispatch logic so heartbeat_thread() below can
 * reuse the exact same "send through the actual mix circuit" path
 * instead of connecting to CS directly.
 *
 * `slot` selects which of the
 * SENDER_RESPONSE_PORT_COUNT response ports this request's response
 * should land in, caller must have acquired it via acquire_slot()
 * first and release it via release_slot() after sender_wait_response(),
 * see g_slots' own comment. Builds its return header LOCALLY
 * (build_return_header_for_slot(), a stack variable) instead of the old
 * shared g_state.return_hdr, so concurrent callers on different slots
 * never race each other. When `data` is non-NULL, appends [dlen(2)]
 * [data] after the key, the same convention PUT already uses,
 * otherwise the app section is exactly [type][klen][key], matching
 * HEARTBEAT/POLL's shape. */
static int send_app_request(uint8_t type, const char *key,
                             const uint8_t *data, size_t data_len,
                             const char *log_label, int slot) {
    if (!g_state.ready) { log_err("paths not ready"); return -1; }

    return_header_t local_return_hdr;
    if (build_return_header_for_slot(slot, &local_return_hdr) != 0) {
        log_err("failed to refresh return header"); return -1;
    }

    size_t klen = strlen(key);
    if (klen > 63) { log_err("key too long"); return -1; }

    /* See send_slot_t.pending_nonce's comment. send_app_request() is only
     * ever called for TYPE_PUT/TYPE_HEARTBEAT/TYPE_HANDSHAKE_RESPOND (the
     * three request types service_gateway.c echoes a nonce back for), so
     * every call here needs one. */
    if (RAND_bytes(g_slots[slot].pending_nonce, sizeof(g_slots[slot].pending_nonce)) != 1) {
        log_err("send_app_request: nonce generation failed"); return -1;
    }

    uint8_t app[MAX_INNER_PAYLOAD];
    memset(app, 0, sizeof(app));
    size_t aoff = 0;
    app[aoff++] = type;
    memcpy(app + aoff, g_slots[slot].pending_nonce, sizeof(g_slots[slot].pending_nonce));
    aoff += sizeof(g_slots[slot].pending_nonce);
    app[aoff++] = (uint8_t)klen;
    memcpy(app + aoff, key, klen); aoff += klen;
    if (data) {
        if (data_len > 0xFFFF) { log_err("request data too large"); return -1; }
        if (aoff + 2 + data_len > sizeof(app)) { log_err("request data too large"); return -1; }
        app[aoff++] = (uint8_t)(data_len >> 8);
        app[aoff++] = (uint8_t)(data_len & 0xFF);
        memcpy(app + aoff, data, data_len); aoff += data_len;
    }

    uint8_t payload[MAX_INNER_PAYLOAD];
    memset(payload, 0, sizeof(payload));
    size_t poff = 0;
    memcpy(payload + poff, g_slot_recv[slot].mnz_pubkey, EC_PUBKEY_LEN); poff += EC_PUBKEY_LEN;
    memcpy(payload + poff, g_slot_recv[slot].mnz_addr,   ADDR_BYTES);    poff += ADDR_BYTES;
    memcpy(payload + poff, &local_return_hdr, RETURN_HEADER_SIZE); poff += RETURN_HEADER_SIZE;
    memcpy(payload + poff, app, aoff); poff += aoff;

    if (poff > MAX_INNER_PAYLOAD) { log_err("payload too large"); return -1; }

    wire_packet_t pkt = {0};
    if (packet_sphinx_build(&g_slot_send[slot], payload, (uint16_t)poff,
                            PKT_REAL | PKT_DEST_SERVICE,
                            next_send_pkt_counter_for_slot(slot), &pkt) != 0) {
        log_err("packet_sphinx_build failed"); return -1;
    }

#ifdef ASN_LOOPIX_MIXING
    /* Known limitation: this dispatch-side mailbox is single-slot under
     * ASN_LOOPIX_MIXING: unlike the response side above, giving it the
     * same N-slot treatment would need a genuine pending-send queue, not
     * just a bigger single value. Concurrent callers can race here: two
     * overlapping real sends under this build could have the second
     * overwrite the first before outbound_cover_thread() picks it up,
     * silently dropping one. */
    EnterCriticalSection(&g_mailbox_lock);
    memcpy(&g_pending_real_pkt, &pkt, sizeof(g_pending_real_pkt));
    g_pending_real_flag = 1;
    LeaveCriticalSection(&g_mailbox_lock);
#else
    InterlockedExchange(&g_real_traffic_pending, 1);
    SOCKET s = net_connect(LOCALHOST, g_slot_send[slot].hop_ports[0]);
    if (s == INVALID_SOCKET) { log_err("connect MNi"); return -1; }

    uint8_t mode = MODE_DATA;
    net_send_all(s, &mode,    1);
    net_send_all(s, pkt.data, WIRE_PACKET_SIZE);
    net_close(s);
#endif

    char logbuf[128];
    snprintf(logbuf, sizeof(logbuf),
             "%s '%s' sent via MNi->MNii->MNiii->SvcGW", log_label, key);
    log_msg(logbuf);
    return 0;
}

/* Wait for and decrypt a response, factored out of upload_content()'s
 * own ACK-wait logic. Returns the response bytes past the leading
 * PKT_REAL flags byte (response_listener() already filtered to PKT_REAL
 * before signalling the slot's event); NOT printed/interpreted here,
 * callers decide what the bytes mean for their own request type.
 * `slot` must be the same one passed to the matching send_app_request()
 * call (or 0 for send_setup()'s one-time startup use). */
static int sender_wait_response(uint8_t *out, uint16_t *out_len, DWORD timeout_ms, int slot) {
    /* See send_slot_t.pending_nonce's comment. Loops, re-waiting on whatever
     * timeout budget remains, whenever a response's echoed nonce doesn't
     * match this call's own pending_nonce, such a response is a stale
     * one from a PREVIOUS occupant of this slot (a timed-out request
     * whose late answer is only now arriving), not this request's
     * genuine answer, so it's discarded rather than accepted or treated
     * as a hard failure (the real answer may still be in flight). */
    DWORD deadline = GetTickCount() + timeout_ms;
    for (;;) {
        DWORD now = GetTickCount();
        if ((int32_t)(deadline - now) <= 0) return -1;
        DWORD remaining = deadline - now;

        if (WaitForSingleObject(g_slots[slot].resp_event, remaining) != WAIT_OBJECT_0) {
            return -1;
        }
        EnterCriticalSection(&g_slots[slot].resp_lock);
        uint8_t wire[WIRE_PACKET_SIZE];
        memcpy(wire, g_slots[slot].resp_buf, WIRE_PACKET_SIZE);
        g_slots[slot].resp_ready = 0;
        ResetEvent(g_slots[slot].resp_event);
        LeaveCriticalSection(&g_slots[slot].resp_lock);

        size_t enc_len = (size_t)((wire[RETURN_HEADER_SIZE] << 8) |
                                    wire[RETURN_HEADER_SIZE+1]);
        const uint8_t *enc = wire + RETURN_HEADER_SIZE + 2;
        if (enc_len < GCM_OVERHEAD || enc_len > RETURN_PAYLOAD_SIZE - 2) continue;

        uint8_t plain[RETURN_PAYLOAD_SIZE];
        int n = crypto_aes_decrypt(&g_slot_recv[slot].k_s_sg_b, enc, enc_len, plain, sizeof(plain));
        if (n < 1) continue;

        /* plain[0] = PKT_REAL/PKT_DUMMY flags byte; plain[1..SLOT_NONCE_BYTES]
         * = echoed nonce (service_gateway.c's has_nonce/req_nonce);
         * plain[1+SLOT_NONCE_BYTES..] = the actual app response bytes
         * callers expect. */
        if ((size_t)n < 1 + SLOT_NONCE_BYTES) continue;
        if (memcmp(plain + 1, g_slots[slot].pending_nonce, SLOT_NONCE_BYTES) != 0) {
            continue; /* stale response from a previous occupant, discard, keep waiting */
        }

        n -= 1 + SLOT_NONCE_BYTES;
        if ((size_t)n > MAX_INNER_PAYLOAD) n = MAX_INNER_PAYLOAD;
        memcpy(out, plain + 1 + SLOT_NONCE_BYTES, (size_t)n);
        *out_len = (uint16_t)n;
        return 0;
    }
}

/* Upload content */
static int upload_content(const char *key,
                           const uint8_t *content, size_t content_len) {
    if (!g_state.ready) { log_err("paths not ready"); return -1; }

    /* Return header is built per-slot inside send_app_request()
     * itself: no separate call needed here. */

    size_t klen = strlen(key);
    if (klen > 63) { log_err("key too long"); return -1; }

    /* The Cache Server is an unauthenticated key/value store
     * (gateway/cache_server.c's own documented limitation) and the
     * Service Gateway sees this content in the clear while relaying it
     * (K_S-SG-A/K_R-SG-B are transport keys to the SG, not a
     * Sender-Receiver secret), so content needs its own integrity and
     * confidentiality layer independent of those transport keys.
     *
     * Wire format: the CS's own GET/PUT protocol is untouched (still a
     * content-agnostic opaque blob store), the signed blob below is
     * simply what gets carried in the existing [clen(2)][content] slot:
     *   [sender_pubkey(65)][sig_len(1)][sig(sig_len)][ciphertext]
     * The Receiver (client.c) parses this same layout on GET, completes
     * the K_session/K_content handshake below to recover the plaintext,
     * then verifies before ever showing content to the user. Real,
     * disclosed cost: this eats up to 65+1+80=146 bytes of the
     * already-small 459-byte content budget (MAX_CONTENT_LEN), plus
     * GCM_OVERHEAD(28) for the ciphertext, typical ECDSA-P256
     * signatures are closer to 70-72 bytes than the 80-byte DER worst
     * case, but this budgets for the worst case.
     *
     * The signature alone gives integrity (tamper -> instant detection)
     * but not confidentiality, since SG/CS would still see plaintext. A
     * fresh, random K_content is generated per upload, the content is
     * AES-GCM-encrypted under it before ever leaving the Sender, and the
     * signature above is computed over the plaintext, the Receiver
     * verifies the signature after decrypting, over the recovered
     * plaintext. The key itself (K_content) is handed to the Receiver
     * later via a live per-request ECDHE handshake relayed opaquely
     * through SG/CS (see heartbeat_thread() below), neither SG nor CS
     * ever derives or sees K_content, only ciphertext. */
    uint8_t sig_buf[SIGNATURE_MAX_LEN];
    int sig_len = crypto_sign(&g_state.identity_kp, content, content_len,
                              sig_buf, sizeof(sig_buf));
    if (sig_len < 0) { log_err("content signing failed"); return -1; }

    aes_key_t k_content;
    if (RAND_bytes(k_content.key, AES_KEY_LEN) != 1) {
        log_err("K_content generation failed"); return -1;
    }
    uint8_t ciphertext[MAX_INNER_PAYLOAD];
    if (content_len + GCM_OVERHEAD > sizeof(ciphertext)) {
        log_err("content too large to encrypt"); return -1;
    }
    int ct_len = crypto_aes_encrypt(&k_content, content, content_len,
                                    ciphertext, sizeof(ciphertext));
    if (ct_len < 0) { log_err("content encryption failed"); return -1; }

    uint8_t signed_blob[EC_PUBKEY_LEN + 1 + SIGNATURE_MAX_LEN + MAX_INNER_PAYLOAD];
    size_t  sboff = 0;
    memcpy(signed_blob + sboff, g_state.identity_kp.pubkey_bytes, EC_PUBKEY_LEN); sboff += EC_PUBKEY_LEN;
    signed_blob[sboff++] = (uint8_t)sig_len;
    memcpy(signed_blob + sboff, sig_buf, (size_t)sig_len); sboff += (size_t)sig_len;
    memcpy(signed_blob + sboff, ciphertext, (size_t)ct_len); sboff += (size_t)ct_len;
    size_t signed_len = sboff;

    /* Remember K_content BEFORE uploading, a poll can arrive the
     * instant the PUT's ACK is seen, so the registry must be populated
     * first, not after this function returns. */
    remember_owned_key(key, &k_content);

    /* signed_blob is what goes in the existing [clen(2)][content] slot
     *, see send_app_request(), which builds the rest of the envelope
     * ([MNz_pubkey][MNz_addr][return_header][TYPE_PUT][klen][key]) the
     * same way for every request type. Acquires its own slot from the
     * pool, so a PUT (rare, run_interactive()'s own thread only)
     * doesn't block or get blocked by heartbeat_thread()'s concurrent
     * RESPOND workers. */
    if (signed_len > 0xFFFF) { log_err("signed content too large"); return -1; }

    int slot = acquire_slot();
    if (send_app_request(TYPE_PUT, key, signed_blob, signed_len, "PUT", slot) != 0) {
        release_slot(slot); return -1;
    }

    /* Wait for ACK from SvcGW (optional, fire and forget is also valid) */
    uint8_t  ack[MAX_INNER_PAYLOAD];
    uint16_t ack_len = 0;
    int got_ack = (sender_wait_response(ack, &ack_len, 5000, slot) == 0 && ack_len > 0);
    release_slot(slot);

    if (got_ack) {
        printf("[Sender] ACK: %.*s\n", (int)ack_len, ack);
        return 0;
    }

    /* No ACK received, still report success (content may be stored) */
    char logbuf[128];
    snprintf(logbuf, sizeof(logbuf),
             "uploaded key='%s' (%zu bytes) through Sphinx mix network",
             key, content_len);
    log_msg(logbuf);
    return 0;
}

/* Completes
 * the design's "the Sender heartbeats to the CS at a regular interval"
 * requirement so a live Receiver can find an
 * online Sender to hand K_content to.
 *
 * Heartbeat and handshake-respond route through Sender's own
 * send_path exactly like PUT (send_app_request()/sender_wait_response()
 * above), relayed opaquely by SG to CS (service_gateway.c's
 * TYPE_HEARTBEAT/TYPE_HANDSHAKE_RESPOND branches). A fully exposed
 * CS/SG only ever sees this heartbeat arrive from an edge mix node
 * (MNiii), never from Sender's real network address. Content and
 * K_content are protected regardless: CS only ever relays opaque
 * ephemeral pubkeys and an encrypted key blob it cannot decrypt.
 *
 * Each pending entry CS reports is dispatched to its own worker
 * thread (respond_worker(), below), so up to SENDER_RESPONSE_PORT_COUNT
 * of them run their full derive+encrypt+sign+send+wait round trip
 * genuinely concurrently instead of sequentially, a batch of 5
 * costs ~1x a round trip (the slowest one), not 5x. */
typedef struct {
    char    key[65];
    uint8_t r_pub[EC_PUBKEY_LEN];
} respond_work_t;

static DWORD WINAPI respond_worker(LPVOID arg) {
    respond_work_t *w = (respond_work_t *)arg;

    /* `w->key` here is the REQUESTER's
     * wire key, which per client.c's perform_content_handshake()
     * is content_key + "#" + a per-request nonce suffix (see
     * cache_server.c's pending_handshake_t struct comment for why
     *, disambiguates concurrent Receivers requesting the same
     * content). Strip the suffix to get the real content key for
     * our own ownership lookup; RESPOND below still echoes back
     * the untouched, full key so CS can route the response to
     * the correct requester's slot. */
    char content_key[65];
    strncpy(content_key, w->key, sizeof(content_key) - 1);
    content_key[sizeof(content_key) - 1] = '\0';
    char *nonce_sep = strchr(content_key, '#');
    if (nonce_sep) *nonce_sep = '\0';

    aes_key_t k_content;
    if (!lookup_owned_key(content_key, &k_content)) { free(w); return 0; } /* not ours */

    ecdh_keypair_t eph = {0};
    if (crypto_ecdh_keygen(&eph) != 0) { free(w); return 0; }

    aes_key_t k_session;
    if (crypto_ecdh_derive(&eph, w->r_pub, &k_session) != 0) {
        crypto_ecdh_free(&eph); free(w); return 0;
    }

    uint8_t enc_k_content[AES_KEY_LEN + GCM_OVERHEAD];
    int enc_len = crypto_aes_encrypt(&k_session, k_content.key, AES_KEY_LEN,
                                     enc_k_content, sizeof(enc_k_content));
    if (enc_len < 0) { crypto_ecdh_free(&eph); free(w); return 0; }

    /* Without a binding to the Sender's identity, any local
     * party could race the legitimate Sender's heartbeat with a
     * spoofed response and poison K_content for a key
     * (an unauthenticated DoS, not a confidentiality break, but
     * real). Sign s_ephemeral_pub||enc_k_content with the same
     * identity key already used for content signing, so a
     * Receiver that already holds a TOFU pin for this key (any
     * retrieval after the first) can reject a forged response
     * outright: see client.c's perform_content_handshake(). A
     * brand-new key's very first-ever retrieval is still
     * TOFU-exposed, matching the identical, already-accepted
     * limitation of content signing itself. */
    uint8_t data[EC_PUBKEY_LEN + 2 + AES_KEY_LEN + GCM_OVERHEAD + 1 + SIGNATURE_MAX_LEN];
    size_t  doff = 0;
    memcpy(data + doff, eph.pubkey_bytes, EC_PUBKEY_LEN); doff += EC_PUBKEY_LEN;
    data[doff++] = (uint8_t)(enc_len >> 8);
    data[doff++] = (uint8_t)(enc_len & 0xFF);
    memcpy(data + doff, enc_k_content, (size_t)enc_len); doff += (size_t)enc_len;
    crypto_ecdh_free(&eph);

    uint8_t resp_sig[SIGNATURE_MAX_LEN];
    int resp_sig_len = crypto_sign(&g_state.identity_kp, data, doff,
                                   resp_sig, sizeof(resp_sig));
    if (resp_sig_len < 0) { free(w); return 0; } /* signing failed, skip this entry */
    data[doff++] = (uint8_t)resp_sig_len;
    memcpy(data + doff, resp_sig, (size_t)resp_sig_len); doff += (size_t)resp_sig_len;

    int slot = acquire_slot();
    int sent_ok = (send_app_request(TYPE_HANDSHAKE_RESPOND, w->key, data, doff,
                                    "HANDSHAKE_RESPOND", slot) == 0);
    uint8_t  ack[MAX_INNER_PAYLOAD];
    uint16_t ack_len = 0;
    int got_ack = sent_ok && (sender_wait_response(ack, &ack_len, 3000, slot) == 0);
    release_slot(slot);

    char logbuf[160];
    snprintf(logbuf, sizeof(logbuf), "handshake responded for key='%s' slot=%d (ok=%u)",
             w->key, slot, (got_ack && ack_len >= 1) ? ack[0] : 0);
    log_msg(logbuf);

    free(w);
    return 0;
}

/* cache_server.c's TYPE_HEARTBEAT reply is capped by MAX_INNER_PAYLOAD,
 * fitting only ~5-6 pending entries per response for typical composite
 * wire keys; under real load there can consistently be more than that
 * many pending, so draining repeatedly per tick (below) rather than
 * waiting for the next 500ms heartbeat keeps the Sender from being
 * limited by how fast it learns about pending requests rather than how
 * many it can service in parallel once it knows about them. */
#define HEARTBEAT_DRAIN_MAX 20

static DWORD WINAPI heartbeat_thread(LPVOID arg) {
    (void)arg;
    for (;;) {
        Sleep(500);
        if (!g_state.ready) continue;

        for (int drain_round = 0; drain_round < HEARTBEAT_DRAIN_MAX; drain_round++) {
        int hb_slot = acquire_slot();
        if (send_app_request(TYPE_HEARTBEAT, "hb", NULL, 0, "HEARTBEAT", hb_slot) != 0) {
            release_slot(hb_slot); break;
        }
        uint8_t  rbuf[MAX_INNER_PAYLOAD];
        uint16_t rlen = 0;
        int got = (sender_wait_response(rbuf, &rlen, 3000, hb_slot) == 0);
        release_slot(hb_slot);
        if (!got || rlen < 1) break;

        size_t off = 0;
        uint8_t count = rbuf[off++];

        /* Dispatch every entry to its own worker thread, then wait for
         * all of them to finish before this tick's own processing is
         * considered done (keeps this tick's semantics identical to the
         * old sequential version, CS won't re-report an entry until
         * this Sender either services it or it TTLs out, just with
         * the workers' round trips overlapped instead of serialized). */
        HANDLE workers[255];
        int    n_workers = 0;

        for (uint8_t i = 0; i < count; i++) {
            if (off + 1 > rlen) break;
            uint8_t klen = rbuf[off++];
            /* klen must be bounded against both the response length
             * (rlen, up to MAX_INNER_PAYLOAD=463) and the destination
             * buffer's own size before this memcpy, a klen of 65-255
             * that satisfies only the rlen check would overflow it. Not
             * reachable from an honest CS today (it caps every key at
             * 64 bytes on write), but CS is a documented, unauthenticated
             * trust boundary, a compromised/buggy/substituted CS
             * shouldn't be able to smash this stack. */
            if (klen > sizeof(((respond_work_t *)0)->key) - 1 ||
                off + klen + EC_PUBKEY_LEN > rlen) break;

            respond_work_t *w = malloc(sizeof(*w));
            if (!w) break;
            memset(w, 0, sizeof(*w));
            memcpy(w->key, rbuf + off, klen); off += klen;
            memcpy(w->r_pub, rbuf + off, EC_PUBKEY_LEN); off += EC_PUBKEY_LEN;

            HANDLE t = CreateThread(NULL, 0, respond_worker, w, 0, NULL);
            if (!t) { free(w); continue; }
            workers[n_workers++] = t;
        }

        for (int i = 0; i < n_workers; i++) {
            WaitForSingleObject(workers[i], 10000);
            CloseHandle(workers[i]);
        }

        /* Likely-truncated heuristic: if this response came back within
         * one entry's worth of the wire budget, cache_server.c's own
         * loop almost certainly stopped on "out of room this round"
         * (its own comment), not because it ran out of genuinely
         * pending entries, drain again immediately instead of waiting
         * out the normal 500ms. 80 bytes comfortably covers one more
         * entry (1 + up to 64-byte key + 65-byte pubkey = up to 130,
         * but real keys are far shorter in practice; err toward
         * draining an extra round too many over leaving a real backlog
         * unaddressed for another half-second). */
        if (rlen < MAX_INNER_PAYLOAD - 80) break;
        }
    }
    return 0;
}

/* Interactive loop */
static void run_interactive(void) {
    printf("\n[Sender] Anonymous Service ready.\n");
    printf("Commands:\n");
    printf("  PUT <key> <content>    Upload content\n");
    printf("  quit                   Exit\n\n");

    char line[1024];
    while (1) {
        printf("sender> "); fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;

        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') line[--len] = '\0';
        if (len > 0 && line[len-1] == '\r') line[--len] = '\0';

        if (strcmp(line, "quit") == 0) break;

        if (strncmp(line, "PUT ", 4) == 0) {
            char *key     = strtok(line + 4, " ");
            char *content = strtok(NULL, "");
            if (!key || !content) { printf("Usage: PUT <key> <content>\n"); continue; }

            if (upload_content(key, (uint8_t *)content, strlen(content)) == 0)
                printf("[Sender] Content uploaded successfully.\n");
            else
                printf("[Sender] Upload failed.\n");
        } else if (len > 0) {
            printf("Unknown command.\n");
        }
    }
}

/* main */
int main(void) {
    SetConsoleOutputCP(65001);
    InitializeCriticalSection(&g_slot_pool_lock);
    InitializeCriticalSection(&g_owned_keys_lock);
#ifdef ASN_LOOPIX_MIXING
    InitializeCriticalSection(&g_mailbox_lock);
#endif
    for (int i = 0; i < SENDER_RESPONSE_PORT_COUNT; i++) {
        InitializeCriticalSection(&g_slots[i].resp_lock);
        g_slots[i].resp_event = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (!g_slots[i].resp_event) return 1;
    }

    if (net_init() != 0) return 1;
    CreateDirectoryA(PUBKEY_DIR, NULL);
    log_msg("Anonymous Service (Sender) v2 starting...");
    rate_tier_init();

    /* Stable signing identity, loaded/created once and persisted, see
     * sender_state_t's identity_kp comment. Must exist before the first
     * upload_content() call. */
    {
        char identity_path[256];
        snprintf(identity_path, sizeof(identity_path), "%s/sender_identity.key", PUBKEY_DIR);
        if (crypto_identity_load_or_create(&g_state.identity_kp, identity_path) != 0) {
            log_err("identity key load/create failed"); net_cleanup(); return 1;
        }
    }

    if (build_paths() != 0) {
        log_err("path build failed, ensure all mix nodes and SvcGW are running");
        net_cleanup(); return 1;
    }

    /* Started ahead of send_setup_for_slot() below, see that function's
     * comment: it blocks waiting for a genuine SETUP ack, so the
     * listener has to already be running to catch it. Matches the
     * identical ordering in client.c's main(); g_state.k_s_sg_b is
     * already set by build_paths() by this point, same as there. One
     * listener per slot, see response_listener()'s own comment. */
    for (int i = 0; i < SENDER_RESPONSE_PORT_COUNT; i++) {
        HANDLE lt = CreateThread(NULL, 0, response_listener,
                                 (LPVOID)(intptr_t)i, 0, NULL);
        if (!lt) { log_err("response listener failed"); return 1; }
        CloseHandle(lt);
    }

    /* Every slot is an independent SG
     * session (own sg_hint) and needs its own TYPE_SETUP registration,
     * see send_setup_for_slot()'s own comment. */
    for (int i = 0; i < SENDER_RESPONSE_PORT_COUNT; i++) {
        if (send_setup_for_slot(i) != 0) {
            log_err("session setup failed"); return 1;
        }
    }

    HANDLE ct = CreateThread(NULL, 0, outbound_cover_thread, NULL, 0, NULL);
    if (ct) CloseHandle(ct);

    HANDLE ht = CreateThread(NULL, 0, heartbeat_thread, NULL, 0, NULL);
    if (ht) CloseHandle(ht);
    Sleep(100);

    run_interactive();

    for (int i = 0; i < SENDER_RESPONSE_PORT_COUNT; i++) {
        DeleteCriticalSection(&g_slots[i].resp_lock);
        CloseHandle(g_slots[i].resp_event);
    }
    DeleteCriticalSection(&g_slot_pool_lock);
#ifdef ASN_LOOPIX_MIXING
    DeleteCriticalSection(&g_mailbox_lock);
#endif
    net_cleanup();
    return 0;
}
