/* tor_config.h  --  Tor-Equivalent Baseline Configuration
 *
 * Three-hop single-path circuit:
 *   Guard  (TN1) : port 9040
 *   Middle (TN2) : port 9041
 *   Exit   (TN3) : port 9042
 *
 * Differences from Anon-Sec-Net (per spec Section 12.1):
 *   - Single path (no dual-path)
 *   - Full AES-256-GCM re-encryption at each hop (not Sphinx blinding)
 *   - Single end-to-end session key (not two independent keys)
 *   - Per-circuit state at each node (not stateless)
 *   - No cover traffic
 *   - No return header mechanism
 */

#ifndef TOR_CONFIG_H
#define TOR_CONFIG_H

/* ── Ports ─────────────────────────────────────────────────────────────── */
#define TOR_PORT_TN1          9040    /* Guard node   */
#define TOR_PORT_TN2          9041    /* Middle node  */
#define TOR_PORT_TN3          9042    /* Exit node    */
#define TOR_PORT_SG           9043    /* Simulated destination / SG       */
#define TOR_PORT_CLIENT       9044    /* Client listener for responses    */

/* ── Protocol modes (first byte on wire) ──────────────────────────────── */
#define TOR_MODE_EXTEND       0x10    /* Telescoping ECDHE handshake      */
#define TOR_MODE_DATA         0x11    /* Forward relay cell (full re-enc) */
#define TOR_MODE_RESPONSE     0x12    /* Backward relay cell              */

/* ── Crypto sizes ─────────────────────────────────────────────────────── */
/*    Reuses EC_PUBKEY_LEN, AES_KEY_LEN, GCM_* from common/crypto.h      */
#define TOR_HINT_BYTES        16      /* Session lookup hint              */
#define TOR_CELL_PAYLOAD      1024    /* Fixed relay cell payload size    */

/* ── Cell layout ──────────────────────────────────────────────────────── */
/*    On the wire a relay cell is:
 *      [hint 16B][GCM_NONCE 12B][ciphertext N][GCM_TAG 16B]
 *    where ciphertext = encrypted(next_port_2B + inner_cell_or_payload)
 *
 *    Overhead per hop:
 *      next_port  : 2 bytes  (embedded in plaintext of each layer)
 *      hint_next  : TOR_HINT_BYTES bytes (embedded in plaintext, forwarded to next hop)
 *      GCM nonce  : 12 bytes
 *      GCM tag    : 16 bytes
 *      Total      : 2 + 16 + 12 + 16 = 46 bytes per hop
 *
 *    With 3 hops the outermost cell carries 3*46 = 138 bytes of overhead
 *    plus the application payload.
 *
 *    NOTE: TOR_CELL_PAYLOAD is the total wire budget (matching Tor's 512-byte
 *    cell size scaled up).  Maximum APPLICATION payload that fits:
 *      TOR_MAX_PAYLOAD = TOR_CELL_PAYLOAD - TOR_MAX_HOPS * TOR_CELL_OVERHEAD
 */
#define TOR_PORT_BYTES        2
#define TOR_CELL_OVERHEAD     (TOR_PORT_BYTES + TOR_HINT_BYTES + GCM_OVERHEAD) /* 2+16+28 = 46 */
#define TOR_MAX_HOPS          3
#define TOR_MAX_PAYLOAD       (TOR_CELL_PAYLOAD - TOR_MAX_HOPS * TOR_CELL_OVERHEAD) /* 1024-138 = 886 */
#define TOR_MAX_CELL_SIZE     (TOR_CELL_PAYLOAD + TOR_MAX_HOPS * TOR_CELL_OVERHEAD) /* 1024+138 = 1162 */

/* ── Session limits ───────────────────────────────────────────────────── */
#define TOR_MAX_SESSIONS      1024

/* ── Network ──────────────────────────────────────────────────────────── */
#define TOR_LOCALHOST          "127.0.0.1"

/* ── Pubkey directory (same convention as Anon-Sec-Net) ────────────────── */
#define TOR_PUBKEY_DIR         "tor_pubkeys"

#endif /* TOR_CONFIG_H */
