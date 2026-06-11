#ifndef CONFIG_H
#define CONFIG_H

/*
 * Anon-Sec-Net v2 -- Configuration
 *
 * Client paths:
 *   Sending:   Client -> MN1(9004) -> MN2(9005) -> MN3(9006) -> SvcGW(9010)
 *   Receiving: SvcGW  -> MNa(9007) -> MNb(9008) -> MNc(9009) -> Client
 *
 * Sender paths:
 *   Sending:   Sender -> MNi(9030) -> MNii(9031) -> MNiii(9032) -> SvcGW(9010)
 *   Receiving: SvcGW  -> MNx(9033) -> MNy(9034)  -> MNz(9035)  -> Sender
 *
 * SvcGW(9010) -> Cache(9012)
 *
 * No border nodes. MN1 and MNi are the only nodes that see Client/Sender IP.
 */

/* -- Client sending path -------------------------------------------------- */
#define PORT_MIX_1            9004
#define PORT_MIX_2            9005
#define PORT_MIX_3            9006

/* -- Client receiving path ------------------------------------------------ */
#define PORT_MIX_A            9007
#define PORT_MIX_B            9008
#define PORT_MIX_C            9009

/* -- Gateways ------------------------------------------------------------- */
#define PORT_SERVICE_GW       9010
#define PORT_CACHE_SERVER     9012

/* -- Sender sending path -------------------------------------------------- */
#define PORT_MIX_I            9030
#define PORT_MIX_II           9031
#define PORT_MIX_III          9032

/* -- Sender receiving path ------------------------------------------------ */
#define PORT_MIX_X            9033
#define PORT_MIX_Y            9034
#define PORT_MIX_Z            9035

/* -- Response ports ------------------------------------------------------- */
#define PORT_CLIENT           9001
#define PORT_SENDER           9015
#define CLIENT_RESPONSE_PORT  9020
#define SENDER_RESPONSE_PORT  9016

#define LOCALHOST             "127.0.0.1"
#define PUBKEY_DIR            "C:\\Temp\\ansn"

/* -- Protocol modes ------------------------------------------------------- */
#define MODE_EXTEND           0x01
#define MODE_DATA             0x02
#define MODE_RETURN           0x03

/* -- Sphinx outbound packet layout ----------------------------------------
 *
 * Outbound (Client -> MN1 -> MN2 -> MN3 -> SG):
 *
 *   HEADER: 3 x HEADER_BLOCK_SIZE = 3 x 86 = 258 bytes
 *     Each block: enc_addr(6) + enc_bkey(32) + mac(16) + hint(32) = 86
 *
 *   PAYLOAD: 766 bytes
 *     enc_K_R-SG-A(
 *       flags(1) + payload_len(2) +
 *       MNc_pubkey(65) + MNc_IP(6) +
 *       return_header(162) +          <- pre-built nested return header
 *       app_data(variable)
 *     )
 *     Each mix node XORs payload with AES-CTR blinding key.
 *     SG reverses all three blinidngs then decrypts with K_R-SG-A.
 *
 * Return packet (SG -> MNc -> MNb -> MNa -> Client):
 *
 *   RETURN HEADER: 3 x RETURN_BLOCK_SIZE = 3 x 54 = 162 bytes
 *     Each block: enc_addr(6) + mac(16) + hint(32) = 54
 *     No blinding key -- return path has no payload blinding.
 *
 *   RETURN PAYLOAD: 862 bytes
 *     enc_K_R-SG-B( response )
 *     Stays encrypted under K_R-SG-B throughout. Not blinded.
 */

#define N_PATH_HOPS           3
#define ADDR_BYTES            6
#define BLIND_KEY_BYTES       32
#define MAC_BYTES             16
#define HINT_BYTES            32
/* Header block layout per hop:
 *   enc_addr(6) + enc_bkey(32) + enc_flags(1) + mac(16) + hint(32) = 87
 *   enc_flags: bit0 = cover packet (MN1 drops without forwarding)        */
#define FLAG_BYTES            1
#define HEADER_BLOCK_SIZE     87     /* 6+32+1+16+32 */
#define HEADER_SIZE           261    /* 3 x 87       */
#define WIRE_PACKET_SIZE      1024
#define PAYLOAD_SECTION_SIZE  763    /* 1024 - 261   */

#define GCM_NONCE_LEN         12
#define GCM_TAG_LEN           16
#define GCM_OVERHEAD          28     /* 12+16      */

/* Return header block has no blinding key */
#define RETURN_BLOCK_SIZE     54     /* 6+16+32    */
#define RETURN_HEADER_SIZE    162    /* 3 x 54     */
#define RETURN_PAYLOAD_SIZE   862    /* 1024 - 162 */

/* Payload breakdown:
 *   flags(1) + payload_len(2) = INNER_HDR_BYTES(3)
 *   MNc_pubkey(65) + MNc_IP(6) + return_header(162) = RETURN_HDR_IN_PAYLOAD(233)
 *   GCM overhead(28)
 *   Remaining for app_data = 766 - 3 - 233 - 28 = 502 bytes
 */
#define EC_PUBKEY_LEN         65
#define INNER_HDR_BYTES       3
#define RETURN_HDR_IN_PAYLOAD 233    /* 65+6+162   */
#define MAX_INNER_PAYLOAD     499    /* 763-3-233-28 */

/* -- Flags ---------------------------------------------------------------- */
#define COVER_FLAG            0x01   /* header flag: MN1 drops cover pkt  */
#define PKT_REAL              0x00
#define PKT_DUMMY             0x01
#define PKT_DEST_SERVICE      0x00
#define PKT_DEST_PUBLIC       0x02

/* -- Crypto --------------------------------------------------------------- */
#define AES_KEY_LEN           32
#define HMAC_KEY_LEN          32
#define PATH_HOPS             4      /* MN1/MNi, MN2/MNii, MN3/MNiii, SG  */

/* -- Timing --------------------------------------------------------------- */
#define DUMMY_INTERVAL_MS     100
#define CONNECT_TIMEOUT_S     5
#define BACKLOG               32

/* -- Packet types --------------------------------------------------------- */
#define TYPE_SETUP            0x00   /* session setup: send keys to SG      */
#define TYPE_GET              0x01
#define TYPE_PUT              0x02

/* -- Session roles (sent in MODE_EXTEND to identify A vs B path) --------- */
#define SESSION_ROLE_A        0x01   /* sending path session (K_R-SG-A)    */
#define SESSION_ROLE_B        0x02   /* receiving path session (K_R-SG-B)  */

/* -- Labels --------------------------------------------------------------- */
#define LABEL_HEADER_ENC      "ansn-hdrenc-v1"
#define LABEL_HEADER_MAC      "ansn-hdrmac-v1"
#define LABEL_BLIND_KEY       "ansn-blind-v1"
#define LABEL_BINDING         "binding"

#endif /* CONFIG_H */
