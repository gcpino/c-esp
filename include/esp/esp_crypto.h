/**
 * @file esp_crypto.h
 * @brief Pluggable AEAD vtable, RFC 8439 ChaCha20-Poly1305, and constant-time primitives.
 */
#ifndef ESP_CRYPTO_H
#define ESP_CRYPTO_H

#include "esp/esp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Pluggable AEAD function pointer table for in-place encryption and decryption.
 */
typedef struct {
    esp_err_t (*aead_encrypt)(const uint8_t key[32], const uint8_t nonce[12],
                              const uint8_t *aad, size_t aad_len,
                              uint8_t *buf, size_t len, uint8_t tag[16]);
    esp_err_t (*aead_decrypt)(const uint8_t key[32], const uint8_t nonce[12],
                              const uint8_t *aad, size_t aad_len,
                              uint8_t *buf, size_t len, const uint8_t tag[16]);
} esp_crypto_vtable_t;

/**
 * @brief Return a pointer to the built-in RFC 8439 ChaCha20-Poly1305 AEAD vtable.
 */
const esp_crypto_vtable_t *esp_crypto_default_vtable(void);

/**
 * @brief Return a pointer to the built-in RFC 4106 / NIST SP 800-38D AES-256-GCM AEAD vtable.
 */
const esp_crypto_vtable_t *esp_crypto_aes256_gcm_vtable(void);

/**
 * @brief Encrypt `buf[0..len-1]` in place using RFC 8439 ChaCha20-Poly1305 and write the 16-byte tag.
 */
esp_err_t esp_chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                                        const uint8_t *aad, size_t aad_len,
                                        uint8_t *buf, size_t len, uint8_t tag[16]);

/**
 * @brief Verify `tag[0..15]` in constant time over the ciphertext and AAD, then decrypt `buf[0..len-1]` in place.
 *        If authentication fails, `buf` is left untouched and `ESP_ERR_AUTH_FAILED` is returned.
 */
esp_err_t esp_chacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                                        const uint8_t *aad, size_t aad_len,
                                        uint8_t *buf, size_t len, const uint8_t tag[16]);

/**
 * @brief Encrypt `buf[0..len-1]` in place using RFC 4106 / NIST SP 800-38D AES-256-GCM and write the 16-byte tag.
 *        Implemented with table-free constant-time GF(2^8) S-box evaluation and bitwise GF(2^128) GHASH.
 */
esp_err_t esp_aes256_gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                                 const uint8_t *aad, size_t aad_len,
                                 uint8_t *buf, size_t len, uint8_t tag[16]);

/**
 * @brief Verify `tag[0..15]` in constant time via GHASH over the ciphertext and AAD, then decrypt `buf[0..len-1]` in place.
 *        If authentication fails, `buf` is left untouched and `ESP_ERR_AUTH_FAILED` is returned.
 */
esp_err_t esp_aes256_gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                                 const uint8_t *aad, size_t aad_len,
                                 uint8_t *buf, size_t len, const uint8_t tag[16]);

/**
 * @brief Constant-time 32-bit bitwise multiplexer with compiler optimization barrier.
 * @param mask 0xFFFFFFFFu to select `a`, or 0x00000000u to select `b`.
 */
uint32_t esp_ct_select_u32(uint32_t mask, uint32_t a, uint32_t b);

/**
 * @brief Constant-time byte buffer equality comparison.
 * @return 1 if `a[0..n-1]` and `b[0..n-1]` are identical, 0 otherwise.
 */
int esp_ct_memeq(const void *a, const void *b, size_t n);

/**
 * @brief Zero sensitive memory in a manner that will not be elided by dead-store elimination.
 */
void esp_secure_zero(void *p, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* ESP_CRYPTO_H */
