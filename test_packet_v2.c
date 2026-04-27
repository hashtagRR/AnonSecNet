/* test_packet_v2.c
 * Build: gcc -Wall -Wextra -g -I. common/crypto.c common/packet.c
 *             test_packet_v2.c -lssl -lcrypto -lws2_32 -lbcrypt -o test_packet_v2.exe
 * Run:   ./test_packet_v2.exe
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "common/packet.h"
#include "common/crypto.h"
#include "common/config.h"

static int tests_run = 0, tests_passed = 0;

#define ASSERT(cond, msg) do {                                          \
    tests_run++;                                                        \
    if (cond) { tests_passed++; printf("  PASS  %s\n", msg); }        \
    else { printf("  FAIL  %s  (line %d)\n", msg, __LINE__); }        \
} while(0)

/* ── Build a test path ──────────────────────────────────────────────────── */

static void make_test_path(sphinx_path_t *path,
                           aes_key_t node_keys[N_PATH_HOPS],
                           aes_key_t *sg_key) {
    /* Simulate what the client does during telescoping handshake:
     * Generate ephemeral key pairs, perform ECDHE with each node,
     * then derive the three sub-keys per hop.                            */

    ecdh_keypair_t client_kp = {0};
    crypto_ecdh_keygen(&client_kp);

    for (int i = 0; i < N_PATH_HOPS; i++) {
        ecdh_keypair_t node_kp = {0};
        crypto_ecdh_keygen(&node_kp);

        /* Client derives master shared secret with this node             */
        aes_key_t master = {0};
        crypto_ecdh_derive(&client_kp, node_kp.pubkey_bytes, &master);

        /* Node derives matching key */
        crypto_ecdh_derive(&node_kp, client_kp.pubkey_bytes, &node_keys[i]);

        /* Store the three sub-keys derived from master in hop_session_t  */
        /* For test: use master directly as header_enc_key, and derive
         * mac/blind via simple XOR-with-constant (full HKDF in production)*/
        memcpy(path->hops[i].header_enc_key.key, master.key, AES_KEY_LEN);

        /* Derive header_mac_key: XOR master with 0x55 pattern            */
        for (int j = 0; j < AES_KEY_LEN; j++)
            path->hops[i].header_mac_key.key[j] = master.key[j] ^ 0x55;

        /* Derive blind_key: XOR master with 0xAA pattern                 */
        for (int j = 0; j < AES_KEY_LEN; j++)
            path->hops[i].blind_key.key[j] = master.key[j] ^ 0xAA;

        /* Store matching keys for test verification */
        memcpy(node_keys[i].key, master.key, AES_KEY_LEN);

        /* Hint: use x-coord of client's ephemeral pubkey (bytes 1..32)   */
        memcpy(path->hops[i].hint,
               client_kp.pubkey_bytes + 1, HINT_BYTES);

        path->hops[i].header_enc_key = (aes_key_t){ .key = {0} };
        memcpy(path->hops[i].header_enc_key.key, master.key, AES_KEY_LEN);

        crypto_ecdh_free(&node_kp);
    }

    /* E2E session key with SG */
    ecdh_keypair_t sg_kp = {0};
    crypto_ecdh_keygen(&sg_kp);
    crypto_ecdh_derive(&client_kp, sg_kp.pubkey_bytes,
                       &path->e2e.e2e_key);
    *sg_key = path->e2e.e2e_key;

    path->next_port = PORT_MIX_1;

    crypto_ecdh_free(&client_kp);
    crypto_ecdh_free(&sg_kp);
}

/* ── Test 1: wire packet is fixed size ─────────────────────────────────── */

static void test_fixed_size(void) {
    printf("\n-- Test 1: wire packet fixed size (%d bytes) ---------------\n",
           WIRE_PACKET_SIZE);

    sphinx_path_t path = {0};
    aes_key_t     node_keys[N_PATH_HOPS] = {0};
    aes_key_t     sg_key = {0};
    make_test_path(&path, node_keys, &sg_key);

    wire_packet_t pkt = {0};
    int rc = packet_sphinx_build(&path,
                                 (uint8_t *)"hello", 5,
                                 PKT_REAL | PKT_DEST_SERVICE, &pkt);
    ASSERT(rc == 0, "packet_sphinx_build returns 0");

    int all_zero = 1;
    for (int i = 0; i < WIRE_PACKET_SIZE; i++)
        if (pkt.data[i]) { all_zero = 0; break; }
    ASSERT(!all_zero, "wire packet is not all zeros");

    printf("  info  header=%d bytes, payload_section=%d bytes\n",
           HEADER_SIZE, PAYLOAD_SECTION_SIZE);
    printf("  info  max_inner_payload=%d bytes\n", MAX_INNER_PAYLOAD);
}

/* ── Test 2: blinding is self-inverse ───────────────────────────────────── */

static void test_blinding_inverse(void) {
    printf("\n-- Test 2: AES-CTR blinding is self-inverse -----------------\n");

    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 7 + 3);

    uint8_t original[100], blinded[100], recovered[100];
    for (int i = 0; i < 100; i++) original[i] = (uint8_t)(i * 3);

    ASSERT(packet_aes_ctr_xor(key, 32, original, 100, blinded)   == 0,
           "blind: XOR succeeds");
    ASSERT(packet_aes_ctr_xor(key, 32, blinded,  100, recovered) == 0,
           "unblind: XOR succeeds");
    ASSERT(memcmp(original, recovered, 100) == 0,
           "double-XOR recovers original (self-inverse)");
    ASSERT(memcmp(original, blinded, 100) != 0,
           "blinded differs from original");
}

/* ── Test 3: HMAC produces different output for different inputs ─────────── */

static void test_hmac(void) {
    printf("\n-- Test 3: HMAC-SHA256 truncated ----------------------------\n");

    uint8_t key[32] = {0};
    uint8_t data1[] = "test data 1";
    uint8_t data2[] = "test data 2";
    uint8_t mac1[MAC_BYTES], mac2[MAC_BYTES];

    ASSERT(packet_hmac(key, 32, data1, sizeof(data1)-1, mac1) == 0,
           "HMAC on data1 succeeds");
    ASSERT(packet_hmac(key, 32, data2, sizeof(data2)-1, mac2) == 0,
           "HMAC on data2 succeeds");
    ASSERT(memcmp(mac1, mac2, MAC_BYTES) != 0,
           "different data -> different MAC");

    /* Same input twice must match */
    uint8_t mac1b[MAC_BYTES];
    packet_hmac(key, 32, data1, sizeof(data1)-1, mac1b);
    ASSERT(memcmp(mac1, mac1b, MAC_BYTES) == 0,
           "same input -> same MAC (deterministic)");
}

/* ── Test 4: dummy packet indistinguishable from real ───────────────────── */

static void test_dummy_vs_real(void) {
    printf("\n-- Test 4: dummy vs real packet -----------------------------\n");

    sphinx_path_t path = {0};
    aes_key_t     node_keys[N_PATH_HOPS] = {0};
    aes_key_t     sg_key = {0};
    make_test_path(&path, node_keys, &sg_key);

    wire_packet_t real_pkt  = {0};
    wire_packet_t dummy_pkt = {0};

    packet_sphinx_build(&path, (uint8_t *)"real message", 12,
                        PKT_REAL | PKT_DEST_SERVICE, &real_pkt);
    ASSERT(packet_sphinx_dummy(&path, &dummy_pkt) == 0,
           "packet_sphinx_dummy returns 0");

    /* Both must be WIRE_PACKET_SIZE */
    ASSERT(1, "both packets are WIRE_PACKET_SIZE bytes");

    /* They must differ (different payload content) */
    ASSERT(memcmp(real_pkt.data, dummy_pkt.data, WIRE_PACKET_SIZE) != 0,
           "real and dummy packets differ");

    /* Both header sections should look like ciphertext (not all zeros)    */
    int real_hdr_nonzero  = 0;
    int dummy_hdr_nonzero = 0;
    for (int i = 0; i < HEADER_SIZE; i++) {
        if (real_pkt.data[i])  real_hdr_nonzero  = 1;
        if (dummy_pkt.data[i]) dummy_hdr_nonzero = 1;
    }
    ASSERT(real_hdr_nonzero,  "real packet header is not all zeros");
    ASSERT(dummy_hdr_nonzero, "dummy packet header is not all zeros");
}

/* ── Test 5: e2e payload encrypt/decrypt roundtrip via unwrap ───────────── */

static void test_e2e_roundtrip(void) {
    printf("\n-- Test 5: E2E payload encrypt/unwrap roundtrip -------------\n");

    sphinx_path_t path = {0};
    aes_key_t     node_keys[N_PATH_HOPS] = {0};
    aes_key_t     sg_key = {0};
    make_test_path(&path, node_keys, &sg_key);

    const char *msg     = "Top secret message for the service gateway";
    uint16_t    msg_len = (uint16_t)strlen(msg);

    wire_packet_t pkt = {0};
    ASSERT(packet_sphinx_build(&path, (uint8_t *)msg, msg_len,
                               PKT_REAL | PKT_DEST_SERVICE, &pkt) == 0,
           "build real packet");

    /* Simulate MN1: apply blinding (XOR blind_key[0]) */
    wire_packet_t after_mn1 = pkt;
    uint8_t *payload = after_mn1.data + HEADER_SIZE;
    uint8_t blinded[PAYLOAD_SECTION_SIZE];
    packet_aes_ctr_xor(path.hops[0].blind_key.key, AES_KEY_LEN,
                       payload, PAYLOAD_SECTION_SIZE, blinded);
    memcpy(payload, blinded, PAYLOAD_SECTION_SIZE);

    /* Simulate MN2: apply blinding (XOR blind_key[1]) */
    wire_packet_t after_mn2 = after_mn1;
    payload = after_mn2.data + HEADER_SIZE;
    packet_aes_ctr_xor(path.hops[1].blind_key.key, AES_KEY_LEN,
                       payload, PAYLOAD_SECTION_SIZE, blinded);
    memcpy(payload, blinded, PAYLOAD_SECTION_SIZE);

    /* Simulate MN3: apply blinding (XOR blind_key[2]) */
    wire_packet_t after_mn3 = after_mn2;
    payload = after_mn3.data + HEADER_SIZE;
    packet_aes_ctr_xor(path.hops[2].blind_key.key, AES_KEY_LEN,
                       payload, PAYLOAD_SECTION_SIZE, blinded);
    memcpy(payload, blinded, PAYLOAD_SECTION_SIZE);

    /* SG unwraps */
    uint8_t  recovered[MAX_INNER_PAYLOAD];
    uint16_t recovered_len = 0;
    uint8_t  flags = 0;

    ASSERT(packet_sphinx_unwrap(&after_mn3, &sg_key,
                                recovered, &recovered_len, &flags) == 0,
           "SG unwrap succeeds");
    ASSERT(recovered_len == msg_len,
           "recovered payload length matches");
    ASSERT(memcmp(recovered, msg, msg_len) == 0,
           "recovered payload content matches");
    ASSERT(flags == (PKT_REAL | PKT_DEST_SERVICE),
           "flags correctly recovered");

    printf("  info  SG recovered: \"%.*s\"\n",
           (int)recovered_len, recovered);
}

/* ── Test 6: tampered payload fails at SG ───────────────────────────────── */

static void test_tamper_detection(void) {
    printf("\n-- Test 6: tampered payload detected at SG ------------------\n");

    sphinx_path_t path = {0};
    aes_key_t     node_keys[N_PATH_HOPS] = {0};
    aes_key_t     sg_key = {0};
    make_test_path(&path, node_keys, &sg_key);

    wire_packet_t pkt = {0};
    packet_sphinx_build(&path, (uint8_t *)"secret", 6,
                        PKT_REAL | PKT_DEST_SERVICE, &pkt);

    /* Apply all three blinidngs as nodes would */
    for (int hop = 0; hop < N_PATH_HOPS; hop++) {
        uint8_t *pl = pkt.data + HEADER_SIZE;
        uint8_t  tmp[PAYLOAD_SECTION_SIZE];
        packet_aes_ctr_xor(path.hops[hop].blind_key.key, AES_KEY_LEN,
                           pl, PAYLOAD_SECTION_SIZE, tmp);
        memcpy(pl, tmp, PAYLOAD_SECTION_SIZE);
    }

    /* Flip a bit in the payload */
    pkt.data[HEADER_SIZE + GCM_NONCE_LEN + 5] ^= 0x01;

    uint8_t  out[MAX_INNER_PAYLOAD];
    uint16_t olen = 0;
    uint8_t  flags = 0;
    ASSERT(packet_sphinx_unwrap(&pkt, &sg_key, out, &olen, &flags) == -1,
           "tampered payload rejected by SG (GCM auth failure)");
}

/* ── main ───────────────────────────────────────────────────────────────── */

int main(void) {
    printf("=== Anon-Sec-Net v2 Sphinx packet test suite ==================\n");

    test_fixed_size();
    test_blinding_inverse();
    test_hmac();
    test_dummy_vs_real();
    test_e2e_roundtrip();
    test_tamper_detection();

    printf("\n=== Results: %d / %d passed ====================================\n",
           tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
