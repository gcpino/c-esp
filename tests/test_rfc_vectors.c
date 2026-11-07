/**
 * @file test_rfc_vectors.c
 * @brief Conformance tests for RFC 8439 ChaCha20-Poly1305 AEAD and constant-time primitives.
 */
#include <stdio.h>
#include <string.h>

#include "esp/esp_crypto.h"

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

    /* Tampered tag must be rejected without mutating ciphertext buffer */
    uint8_t bad_tag[16];
    memcpy(bad_tag, tag, sizeof(tag));
    bad_tag[15] ^= 0x01u;
    err = vt->aead_decrypt(key, nonce, aad, sizeof(aad), buf, sizeof(buf), bad_tag);
    ASSERT_TRUE(err == ESP_ERR_AUTH_FAILED, "tampered tag was not rejected");
    ASSERT_TRUE(memcmp(buf, expected_ct, sizeof(expected_ct)) == 0,
                "ciphertext mutated on failed authentication");

    /* Valid tag must decrypt back to original plaintext */
    err = vt->aead_decrypt(key, nonce, aad, sizeof(aad), buf, sizeof(buf), tag);
    ASSERT_TRUE(err == ESP_OK, "RFC 8439 decryption returned error");
    ASSERT_TRUE(memcmp(buf, plaintext_str, sizeof(buf)) == 0,
                "RFC 8439 decrypted plaintext mismatch");

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
    printf("[PASS] test_rfc_vectors: RFC 8439 §2.8.2 AEAD & constant-time primitives verified.\n");
    return 0;
}
