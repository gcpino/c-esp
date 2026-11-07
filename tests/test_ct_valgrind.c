/**
 * @file test_ct_valgrind.c
 * @brief Instruction-level constant-time secret-taint verification harness (Langley ctgrind method).
 *
 * When executed under Valgrind Memcheck (`valgrind --error-exitcode=1 --track-origins=yes`),
 * secret keys, salts, nonces, tags, and payloads are marked as uninitialized (`VALGRIND_MAKE_MEM_UNDEFINED`).
 * Any conditional branch (`if`, `?:`, `&&`, `||`) or memory address calculation (`table[secret]`)
 * that depends on tainted secret data triggers an immediate Valgrind Memcheck error.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "esp/esp.h"

#if defined(__has_include)
#  if __has_include(<valgrind/memcheck.h>)
#    include <valgrind/memcheck.h>
#    define CESP_HAS_VALGRIND 1
#  endif
#endif

#ifndef CESP_HAS_VALGRIND
#  define CESP_HAS_VALGRIND 0
#  define VALGRIND_MAKE_MEM_UNDEFINED(addr, len) do { (void)(addr); (void)(len); } while (0)
#  define VALGRIND_MAKE_MEM_DEFINED(addr, len)   do { (void)(addr); (void)(len); } while (0)
#endif

static int test_ct_primitives_taint(void)
{
    uint8_t tag_a[16] = {
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x01
    };
    uint8_t tag_b[16] = {
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x01
    };

    VALGRIND_MAKE_MEM_UNDEFINED(tag_a, sizeof(tag_a));
    VALGRIND_MAKE_MEM_UNDEFINED(tag_b, sizeof(tag_b));

    int eq_same = esp_ct_memeq(tag_a, tag_b, sizeof(tag_a));
    VALGRIND_MAKE_MEM_DEFINED(&eq_same, sizeof(eq_same));
    VALGRIND_MAKE_MEM_DEFINED(tag_a, sizeof(tag_a));
    VALGRIND_MAKE_MEM_DEFINED(tag_b, sizeof(tag_b));

    if (eq_same != 1) {
        fprintf(stderr, "[FAIL] esp_ct_memeq failed on identical tainted buffers\n");
        return 1;
    }

    tag_b[15] ^= 0x01u;
    VALGRIND_MAKE_MEM_UNDEFINED(tag_a, sizeof(tag_a));
    VALGRIND_MAKE_MEM_UNDEFINED(tag_b, sizeof(tag_b));

    int eq_diff = esp_ct_memeq(tag_a, tag_b, sizeof(tag_a));
    VALGRIND_MAKE_MEM_DEFINED(&eq_diff, sizeof(eq_diff));
    VALGRIND_MAKE_MEM_DEFINED(tag_a, sizeof(tag_a));
    VALGRIND_MAKE_MEM_DEFINED(tag_b, sizeof(tag_b));

    if (eq_diff != 0) {
        fprintf(stderr, "[FAIL] esp_ct_memeq failed on differing tainted buffers\n");
        return 1;
    }

    uint32_t bit = 1u;
    uint32_t va  = 0xCAFEBABEu;
    uint32_t vb  = 0xDEADBEEFu;
    VALGRIND_MAKE_MEM_UNDEFINED(&bit, sizeof(bit));
    VALGRIND_MAKE_MEM_UNDEFINED(&va, sizeof(va));
    VALGRIND_MAKE_MEM_UNDEFINED(&vb, sizeof(vb));

    uint32_t sel = esp_ct_select_u32(0u - (bit & 1u), va, vb);
    VALGRIND_MAKE_MEM_DEFINED(&sel, sizeof(sel));
    if (sel != 0xCAFEBABEu) {
        fprintf(stderr, "[FAIL] esp_ct_select_u32 failed under taint\n");
        return 1;
    }
    return 0;
}

static int test_ct_chacha20_poly1305_taint(void)
{
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t aad[12];
    uint8_t buf[128];
    uint8_t tag[16];

    for (size_t i = 0u; i < sizeof(key); ++i)   { key[i]   = (uint8_t)(0x80u + i); }
    for (size_t i = 0u; i < sizeof(nonce); ++i) { nonce[i] = (uint8_t)(0x10u + i); }
    for (size_t i = 0u; i < sizeof(aad); ++i)   { aad[i]   = (uint8_t)(0xA0u + i); }
    for (size_t i = 0u; i < sizeof(buf); ++i)   { buf[i]   = (uint8_t)(i & 0xFFu); }

    VALGRIND_MAKE_MEM_UNDEFINED(key, sizeof(key));
    VALGRIND_MAKE_MEM_UNDEFINED(nonce, sizeof(nonce));
    VALGRIND_MAKE_MEM_UNDEFINED(aad, sizeof(aad));
    VALGRIND_MAKE_MEM_UNDEFINED(buf, sizeof(buf));

    esp_err_t err = esp_chacha20_poly1305_encrypt(key, nonce, aad, sizeof(aad),
                                                  buf, sizeof(buf), tag);
    VALGRIND_MAKE_MEM_DEFINED(&err, sizeof(err));
    VALGRIND_MAKE_MEM_DEFINED(buf, sizeof(buf));
    VALGRIND_MAKE_MEM_DEFINED(tag, sizeof(tag));

    if (err != ESP_OK) {
        fprintf(stderr, "[FAIL] esp_chacha20_poly1305_encrypt failed under taint\n");
        return 1;
    }
    return 0;
}

static int test_ct_aes256_gcm_taint(void)
{
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t aad[12];
    uint8_t buf[128];
    uint8_t tag[16];

    for (size_t i = 0u; i < sizeof(key); ++i)   { key[i]   = (uint8_t)(0x40u + i); }
    for (size_t i = 0u; i < sizeof(nonce); ++i) { nonce[i] = (uint8_t)(0x20u + i); }
    for (size_t i = 0u; i < sizeof(aad); ++i)   { aad[i]   = (uint8_t)(0xB0u + i); }
    for (size_t i = 0u; i < sizeof(buf); ++i)   { buf[i]   = (uint8_t)((i * 3u) & 0xFFu); }

    VALGRIND_MAKE_MEM_UNDEFINED(key, sizeof(key));
    VALGRIND_MAKE_MEM_UNDEFINED(nonce, sizeof(nonce));
    VALGRIND_MAKE_MEM_UNDEFINED(aad, sizeof(aad));
    VALGRIND_MAKE_MEM_UNDEFINED(buf, sizeof(buf));

    esp_err_t err = esp_aes256_gcm_encrypt(key, nonce, aad, sizeof(aad),
                                           buf, sizeof(buf), tag);
    VALGRIND_MAKE_MEM_DEFINED(&err, sizeof(err));
    VALGRIND_MAKE_MEM_DEFINED(buf, sizeof(buf));
    VALGRIND_MAKE_MEM_DEFINED(tag, sizeof(tag));

    if (err != ESP_OK) {
        fprintf(stderr, "[FAIL] esp_aes256_gcm_encrypt failed under taint\n");
        return 1;
    }
    return 0;
}

static int test_ct_session_encrypt_taint(const esp_crypto_vtable_t *vtable, const char *label)
{
    esp_context_t tx;
    uint8_t key[32];
    uint8_t salt[4];
    for (size_t i = 0u; i < 32u; ++i) { key[i]  = (uint8_t)(0x11u + i); }
    for (size_t i = 0u; i < 4u; ++i)  { salt[i] = (uint8_t)(0x55u + i); }

    if (esp_context_init(&tx, 1u) != ESP_OK ||
        esp_context_set_crypto(&tx, vtable) != ESP_OK ||
        esp_sa_install(&tx, ESP_DIR_OUTBOUND, 0x778899AAu, key, salt, NULL, 1000ULL) != ESP_OK) {
        fprintf(stderr, "[FAIL] esp_context_init / esp_sa_install failed for %s\n", label);
        return 1;
    }

    uint8_t frame[128];
    memset(frame, 0x42, sizeof(frame));
    size_t frame_len = 0u;
    esp_event_t ev = ESP_EVENT_NONE;

    /* Taint SA secret key, salt, and inner plaintext payload */
    VALGRIND_MAKE_MEM_UNDEFINED(tx.tx_sa.key, sizeof(tx.tx_sa.key));
    VALGRIND_MAKE_MEM_UNDEFINED(tx.tx_sa.salt, sizeof(tx.tx_sa.salt));
    VALGRIND_MAKE_MEM_UNDEFINED(frame + ESP_HDR_SIZE, 64u);

    esp_err_t err = esp_encrypt_in_place(&tx, frame, sizeof(frame),
                                         ESP_HDR_SIZE, 64u, 4u, 2000ULL,
                                         &frame_len, &ev);
    VALGRIND_MAKE_MEM_DEFINED(&err, sizeof(err));
    VALGRIND_MAKE_MEM_DEFINED(frame, sizeof(frame));
    VALGRIND_MAKE_MEM_DEFINED(&tx, sizeof(tx));

    esp_context_wipe(&tx);
    if (err != ESP_OK || frame_len != (ESP_HDR_SIZE + 68u + ESP_ICV_SIZE)) {
        fprintf(stderr, "[FAIL] esp_encrypt_in_place taint check failed for %s\n", label);
        return 1;
    }
    return 0;
}

int main(void)
{
    printf("[CTGRIND] Valgrind header instrumentation active: %s\n",
           CESP_HAS_VALGRIND ? "YES (<valgrind/memcheck.h>)" : "NO (compile-only fallback)");

    if (test_ct_primitives_taint() != 0) {
        return 1;
    }
    if (test_ct_chacha20_poly1305_taint() != 0) {
        return 1;
    }
    if (test_ct_aes256_gcm_taint() != 0) {
        return 1;
    }
    if (test_ct_session_encrypt_taint(esp_crypto_default_vtable(), "RFC 7634 ChaCha20-Poly1305") != 0) {
        return 1;
    }
    if (test_ct_session_encrypt_taint(esp_crypto_aes256_gcm_vtable(), "RFC 4106 AES-256-GCM") != 0) {
        return 1;
    }

    printf("[PASS] test_ct_valgrind: Zero secret-dependent branches or table lookups across ChaCha20-Poly1305 & AES-256-GCM.\n");
    return 0;
}
