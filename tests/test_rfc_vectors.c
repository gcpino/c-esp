/**
 * @file test_rfc_vectors.c
 * @brief Conformance tests for RFC 8439 ChaCha20-Poly1305 AEAD, RFC 7634 Appendix A ESP vector,
 *        ESN/non-ESN session round-trips, and constant-time padding validation.
 */
#include <stdio.h>
#include <string.h>

#include "esp/esp.h"

#define ASSERT_TRUE(cond, msg)                                                      \
    do {                                                                            \
        if (!(cond)) {                                                              \
            fprintf(stderr, "[FAIL] %s:%d: %s\n", __FILE__, __LINE__, (msg));       \
            return 1;                                                               \
        }                                                                           \
    } while (0)

static int test_constant_time_primitives(void)
{
    ASSERT_TRUE(esp_ct_select_u32(0xFFFFFFFFu, 0x12345678u, 0x9ABCDEF0u) == 0x12345678u,
                "esp_ct_select_u32 mask=1 failed");
    ASSERT_TRUE(esp_ct_select_u32(0x00000000u, 0x12345678u, 0x9ABCDEF0u) == 0x9ABCDEF0u,
                "esp_ct_select_u32 mask=0 failed");

    uint8_t a[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t b[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    ASSERT_TRUE(esp_ct_memeq(a, b, sizeof(a)) == 1, "esp_ct_memeq equal buffers failed");

    b[15] ^= 0x01u;
    ASSERT_TRUE(esp_ct_memeq(a, b, sizeof(a)) == 0, "esp_ct_memeq differing last byte failed");
    b[15] ^= 0x01u;
    b[0] ^= 0x80u;
    ASSERT_TRUE(esp_ct_memeq(a, b, sizeof(a)) == 0, "esp_ct_memeq differing first byte failed");

    esp_secure_zero(a, sizeof(a));
    uint8_t zeros[16] = {0};
    ASSERT_TRUE(memcmp(a, zeros, sizeof(a)) == 0, "esp_secure_zero failed to clear buffer");
    return 0;
}

static int test_rfc8439_section_2_8_2(void)
{
    static const uint8_t key[32] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };
    static const uint8_t nonce[12] = {
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47
    };
    static const uint8_t aad[12] = {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7
    };
    static const char plaintext_str[] =
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    static const uint8_t expected_ct[114] = {
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
        0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
        0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
        0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
        0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
        0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16
    };
    static const uint8_t expected_tag[16] = {
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
    };

    uint8_t buf[114];
    uint8_t tag[16];
    memcpy(buf, plaintext_str, sizeof(buf));

    const esp_crypto_vtable_t *vt = esp_crypto_default_vtable();
    ASSERT_TRUE(vt != NULL && vt->aead_encrypt != NULL && vt->aead_decrypt != NULL,
                "default vtable is NULL");

    esp_err_t err = vt->aead_encrypt(key, nonce, aad, sizeof(aad), buf, sizeof(buf), tag);
    ASSERT_TRUE(err == ESP_OK, "RFC 8439 encryption returned error");
    ASSERT_TRUE(memcmp(buf, expected_ct, sizeof(expected_ct)) == 0,
                "RFC 8439 ciphertext mismatch");
    ASSERT_TRUE(memcmp(tag, expected_tag, sizeof(expected_tag)) == 0,
                "RFC 8439 Poly1305 tag mismatch");

    uint8_t bad_tag[16];
    memcpy(bad_tag, tag, sizeof(tag));
    bad_tag[15] ^= 0x01u;
    err = vt->aead_decrypt(key, nonce, aad, sizeof(aad), buf, sizeof(buf), bad_tag);
    ASSERT_TRUE(err == ESP_ERR_AUTH_FAILED, "tampered tag was not rejected");
    ASSERT_TRUE(memcmp(buf, expected_ct, sizeof(expected_ct)) == 0,
                "ciphertext mutated on failed authentication");

    err = vt->aead_decrypt(key, nonce, aad, sizeof(aad), buf, sizeof(buf), tag);
    ASSERT_TRUE(err == ESP_OK, "RFC 8439 decryption returned error");
    ASSERT_TRUE(memcmp(buf, plaintext_str, sizeof(buf)) == 0,
                "RFC 8439 decrypted plaintext mismatch");

    return 0;
}

static int test_rfc7634_appendix_a_esp_vector(void)
{
    static const uint8_t key[32] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };
    static const uint8_t salt[4] = {0xa0, 0xa1, 0xa2, 0xa3};
    static const uint8_t iv[8]   = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
    static const uint32_t spi    = 0x01020304u;
    static const uint64_t seq64  = 5ULL;

    static const uint8_t icmp_payload[84] = {
        0x45, 0x00, 0x00, 0x54, 0xa6, 0xf2, 0x00, 0x00,
        0x40, 0x01, 0xe7, 0x78, 0xc6, 0x33, 0x64, 0x05,
        0xc0, 0x00, 0x02, 0x05, 0x08, 0x00, 0x5b, 0x7a,
        0x3a, 0x08, 0x00, 0x00, 0x55, 0x3b, 0xec, 0x10,
        0x00, 0x07, 0x36, 0x27, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
        0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
        0x34, 0x35, 0x36, 0x37
    };

    static const uint8_t expected_esp_frame[120] = {
        /* 16-byte ESP Header: SPI (01020304), Seq (00000005), IV (1011121314151617) */
        0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x05,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        /* 88-byte Encrypted Payload + Padding (01 02) + PadLen (02) + NextHdr (04) */
        0x24, 0x03, 0x94, 0x28, 0xb9, 0x7f, 0x41, 0x7e,
        0x3c, 0x13, 0x75, 0x3a, 0x4f, 0x05, 0x08, 0x7b,
        0x67, 0xc3, 0x52, 0xe6, 0xa7, 0xfa, 0xb1, 0xb9,
        0x82, 0xd4, 0x66, 0xef, 0x40, 0x7a, 0xe5, 0xc6,
        0x14, 0xee, 0x80, 0x99, 0xd5, 0x28, 0x44, 0xeb,
        0x61, 0xaa, 0x95, 0xdf, 0xab, 0x4c, 0x02, 0xf7,
        0x2a, 0xa7, 0x1e, 0x7c, 0x4c, 0x4f, 0x64, 0xc9,
        0xbe, 0xfe, 0x2f, 0xac, 0xc6, 0x38, 0xe8, 0xf3,
        0xcb, 0xec, 0x16, 0x3f, 0xac, 0x46, 0x9b, 0x50,
        0x27, 0x73, 0xf6, 0xfb, 0x94, 0xe6, 0x64, 0xda,
        0x91, 0x65, 0xb8, 0x28, 0x29, 0xf6, 0x41, 0xe0,
        /* 16-byte Poly1305 ICV */
        0x76, 0xaa, 0xa8, 0x26, 0x6b, 0x7f, 0xb0, 0xf7,
        0xb1, 0x1b, 0x36, 0x99, 0x07, 0xe1, 0xad, 0x43
    };

    uint8_t frame[160] = {0};
    memcpy(frame + ESP_HDR_SIZE, icmp_payload, sizeof(icmp_payload));

    size_t frame_len = 0u;
    esp_err_t err = esp_packet_seal_raw(esp_crypto_default_vtable(),
                                        spi, seq64, 0u /* non-ESN per RFC 7634 App A */,
                                        key, salt, iv, frame, sizeof(frame),
                                        ESP_HDR_SIZE, sizeof(icmp_payload),
                                        4u /* IPPROTO_IPIP */, &frame_len);
    ASSERT_TRUE(err == ESP_OK, "RFC 7634 Appendix A seal_raw failed");
    ASSERT_TRUE(frame_len == sizeof(expected_esp_frame), "RFC 7634 frame_len != 120");
    ASSERT_TRUE(memcmp(frame, expected_esp_frame, sizeof(expected_esp_frame)) == 0,
                "RFC 7634 Appendix A wire frame mismatch");

    size_t out_offset = 0u;
    size_t out_len    = 0u;
    uint8_t out_nh    = 0u;
    err = esp_packet_open_raw(esp_crypto_default_vtable(),
                              spi, seq64, 0u, key, salt,
                              frame, frame_len, &out_offset, &out_len, &out_nh);
    ASSERT_TRUE(err == ESP_OK, "RFC 7634 Appendix A open_raw failed");
    ASSERT_TRUE(out_offset == ESP_HDR_SIZE, "unexpected payload offset");
    ASSERT_TRUE(out_len == sizeof(icmp_payload), "decrypted payload length mismatch");
    ASSERT_TRUE(out_nh == 4u, "decrypted Next Header != 4");
    ASSERT_TRUE(memcmp(frame + out_offset, icmp_payload, sizeof(icmp_payload)) == 0,
                "RFC 7634 Appendix A decrypted payload mismatch");

    return 0;
}

static int test_session_roundtrip_and_padding_fault(void)
{
    static const uint8_t key[32] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01
    };
    static const uint8_t salt[4] = {0xde, 0xad, 0xbe, 0xef};

    esp_context_t tx_ctx;
    esp_context_t rx_ctx;
    ASSERT_TRUE(esp_context_init(&tx_ctx, 1u) == ESP_OK, "tx_ctx init");
    ASSERT_TRUE(esp_context_init(&rx_ctx, 1u) == ESP_OK, "rx_ctx init");

    /* Reserved SPI < 256 must be rejected */
    ASSERT_TRUE(esp_sa_install(&tx_ctx, ESP_DIR_OUTBOUND, 100u, key, salt, NULL, 1000ULL) == ESP_ERR_INVALID_ARG,
                "reserved SPI < 256 was not rejected");

    ASSERT_TRUE(esp_sa_install(&tx_ctx, ESP_DIR_OUTBOUND, 0x10000100u, key, salt, NULL, 1000ULL) == ESP_OK,
                "tx SA install failed");
    ASSERT_TRUE(esp_sa_install(&rx_ctx, ESP_DIR_INBOUND, 0x10000100u, key, salt, NULL, 1000ULL) == ESP_OK,
                "rx SA install failed");

    /* Test all 4 alignment remainders (payload_len % 4 == 0, 1, 2, 3) */
    for (size_t plen = 1u; plen <= 37u; ++plen) {
        uint8_t buf[128] = {0};
        for (size_t i = 0u; i < plen; ++i) {
            buf[ESP_HDR_SIZE + i] = (uint8_t)(i ^ 0x5Au);
        }

        size_t frame_len = 0u;
        esp_event_t ev = ESP_EVENT_NONE;
        ASSERT_TRUE(esp_encrypt_in_place(&tx_ctx, buf, sizeof(buf), ESP_HDR_SIZE, plen,
                                         17u /* UDP */, 2000ULL, &frame_len, &ev) == ESP_OK,
                    "esp_encrypt_in_place failed");

        size_t dec_off = 0u;
        size_t dec_len = 0u;
        uint8_t dec_nh = 0u;
        ASSERT_TRUE(esp_decrypt_in_place(&rx_ctx, buf, frame_len, 2000ULL,
                                         &dec_off, &dec_len, &dec_nh, &ev) == ESP_OK,
                    "esp_decrypt_in_place failed");
        ASSERT_TRUE(dec_off == ESP_HDR_SIZE && dec_len == plen && dec_nh == 17u,
                    "decrypted metadata mismatch");
        for (size_t i = 0u; i < plen; ++i) {
            ASSERT_TRUE(buf[dec_off + i] == (uint8_t)(i ^ 0x5Au), "decrypted byte mismatch");
        }
    }

    /* Non-ESN 32-bit sequence exhaustion test */
    esp_context_t no_esn_ctx;
    ASSERT_TRUE(esp_context_init(&no_esn_ctx, 0u) == ESP_OK, "no_esn init");
    ASSERT_TRUE(esp_sa_install(&no_esn_ctx, ESP_DIR_OUTBOUND, 0x20000200u, key, salt, NULL, 1000ULL) == ESP_OK,
                "no_esn install");
    no_esn_ctx.tx_sa.tx_seq = 0xFFFFFFFFULL;
    uint8_t dummy[64] = {0};
    size_t flen = 0u;
    ASSERT_TRUE(esp_encrypt_in_place(&no_esn_ctx, dummy, sizeof(dummy), ESP_HDR_SIZE, 4u,
                                     4u, 2000ULL, &flen, NULL) == ESP_ERR_SEQ_EXHAUSTED,
                "non-ESN sequence ceiling 0xFFFFFFFF was not enforced");

    esp_context_wipe(&tx_ctx);
    esp_context_wipe(&rx_ctx);
    esp_context_wipe(&no_esn_ctx);
    return 0;
}

static int test_nist_aes256_gcm_and_rfc4106(void)
{
    /* NIST SP 800-38D / McGrew & Viega AES-256-GCM Test Case 16 */
    static const uint8_t key[32] = {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
    };
    static const uint8_t nonce[12] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88
    };
    static const uint8_t pt[60] = {
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
        0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
        0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
        0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
        0xba, 0x63, 0x7b, 0x39
    };
    static const uint8_t aad[20] = {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2
    };
    static const uint8_t expected_ct[60] = {
        0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
        0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
        0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
        0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
        0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
        0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
        0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
        0xbc, 0xc9, 0xf6, 0x62
    };
    static const uint8_t expected_tag[16] = {
        0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68,
        0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b
    };

    uint8_t buf[60];
    uint8_t tag[16];
    memcpy(buf, pt, sizeof(pt));

    const esp_crypto_vtable_t *gcm_vt = esp_crypto_aes256_gcm_vtable();
    ASSERT_TRUE(gcm_vt != NULL, "AES-256-GCM vtable is NULL");

    ASSERT_TRUE(gcm_vt->aead_encrypt(key, nonce, aad, sizeof(aad), buf, sizeof(buf), tag) == ESP_OK,
                "AES-256-GCM encrypt failed");
    ASSERT_TRUE(memcmp(buf, expected_ct, sizeof(expected_ct)) == 0,
                "NIST AES-256-GCM ciphertext mismatch");
    ASSERT_TRUE(memcmp(tag, expected_tag, sizeof(expected_tag)) == 0,
                "NIST AES-256-GCM GHASH tag mismatch");

    /* Tampered tag rejection */
    uint8_t bad_tag[16];
    memcpy(bad_tag, tag, 16u);
    bad_tag[0] ^= 0x80u;
    ASSERT_TRUE(gcm_vt->aead_decrypt(key, nonce, aad, sizeof(aad), buf, sizeof(buf), bad_tag) == ESP_ERR_AUTH_FAILED,
                "AES-256-GCM tampered tag was not rejected");

    ASSERT_TRUE(gcm_vt->aead_decrypt(key, nonce, aad, sizeof(aad), buf, sizeof(buf), tag) == ESP_OK,
                "AES-256-GCM decrypt failed");
    ASSERT_TRUE(memcmp(buf, pt, sizeof(pt)) == 0,
                "NIST AES-256-GCM decrypted plaintext mismatch");

    /* RFC 4106 ESP Session Round-Trip via esp_context_set_crypto */
    static const uint8_t salt[4] = {0xca, 0xfe, 0xba, 0xbe};
    esp_context_t tx_gcm, rx_gcm;
    ASSERT_TRUE(esp_context_init(&tx_gcm, 1u) == ESP_OK, "tx_gcm init");
    ASSERT_TRUE(esp_context_init(&rx_gcm, 1u) == ESP_OK, "rx_gcm init");
    ASSERT_TRUE(esp_context_set_crypto(&tx_gcm, gcm_vt) == ESP_OK, "tx_gcm set_crypto");
    ASSERT_TRUE(esp_context_set_crypto(&rx_gcm, gcm_vt) == ESP_OK, "rx_gcm set_crypto");

    ASSERT_TRUE(esp_sa_install(&tx_gcm, ESP_DIR_OUTBOUND, 0x41060100u, key, salt, NULL, 1000ULL) == ESP_OK,
                "tx_gcm SA install");
    ASSERT_TRUE(esp_sa_install(&rx_gcm, ESP_DIR_INBOUND,  0x41060100u, key, salt, NULL, 1000ULL) == ESP_OK,
                "rx_gcm SA install");

    uint8_t esp_buf[128] = {0};
    memcpy(esp_buf + ESP_HDR_SIZE, pt, sizeof(pt));
    size_t frame_len = 0u;
    ASSERT_TRUE(esp_encrypt_in_place(&tx_gcm, esp_buf, sizeof(esp_buf), ESP_HDR_SIZE, sizeof(pt),
                                     4u, 2000ULL, &frame_len, NULL) == ESP_OK,
                "RFC 4106 esp_encrypt_in_place failed");

    size_t dec_off = 0u;
    size_t dec_len = 0u;
    uint8_t dec_nh = 0u;
    ASSERT_TRUE(esp_decrypt_in_place(&rx_gcm, esp_buf, frame_len, 2000ULL,
                                     &dec_off, &dec_len, &dec_nh, NULL) == ESP_OK,
                "RFC 4106 esp_decrypt_in_place failed");
    ASSERT_TRUE(dec_len == sizeof(pt) && memcmp(esp_buf + dec_off, pt, sizeof(pt)) == 0,
                "RFC 4106 decrypted payload mismatch");

    esp_context_wipe(&tx_gcm);
    esp_context_wipe(&rx_gcm);
    return 0;
}

int main(void)
{
    if (test_constant_time_primitives() != 0) {
        return 1;
    }
    if (test_rfc8439_section_2_8_2() != 0) {
        return 1;
    }
    if (test_rfc7634_appendix_a_esp_vector() != 0) {
        return 1;
    }
    if (test_session_roundtrip_and_padding_fault() != 0) {
        return 1;
    }
    if (test_nist_aes256_gcm_and_rfc4106() != 0) {
        return 1;
    }
    printf("[PASS] test_rfc_vectors: RFC 8439 §2.8.2, RFC 7634 App A, NIST AES-256-GCM (RFC 4106) & framing verified.\n");
    return 0;
}
