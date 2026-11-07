/**
 * @file test_rekey_fsm.c
 * @brief Unit tests for RFC 4301 SA lifetimes, colliding SPI fallback in rx_sa_ring[4],
 *        make-before-break SA rollover, and deterministic key zeroization.
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

static int test_soft_and_hard_lifetimes_and_key_wipe(void)
{
    static const uint8_t key1[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };
    static const uint8_t salt1[4] = {0xaa, 0xbb, 0xcc, 0xdd};
    static const uint8_t zeros32[32] = {0};

    esp_context_t ctx;
    ASSERT_TRUE(esp_context_init(&ctx, 1u) == ESP_OK, "ctx init");

    esp_sa_lifetime_t lt = {
        .soft_bytes   = 0ULL,
        .hard_bytes   = 0ULL,
        .soft_packets = 2ULL,
        .hard_packets = 3ULL,
        .soft_time_ns = 0ULL,
        .hard_time_ns = 0ULL
    };

    ASSERT_TRUE(esp_sa_install(&ctx, ESP_DIR_OUTBOUND, 0x10000101u, key1, salt1, &lt, 100ULL) == ESP_OK,
                "install outbound SA");

    uint8_t buf[128] = {0};
    size_t flen = 0u;
    esp_event_t ev = ESP_EVENT_NONE;

    /* Packet 1: stays ESP_SA_ACTIVE */
    ASSERT_TRUE(esp_encrypt_in_place(&ctx, buf, sizeof(buf), ESP_HDR_SIZE, 16u,
                                     4u, 200ULL, &flen, &ev) == ESP_OK, "pkt 1");
    ASSERT_TRUE(ev == ESP_EVENT_NONE && ctx.tx_sa.state == ESP_SA_ACTIVE, "pkt 1 state");

    /* Packet 2: hits soft_packets == 2 -> emits ESP_EVENT_SA_SOFT_EXPIRE */
    ASSERT_TRUE(esp_encrypt_in_place(&ctx, buf, sizeof(buf), ESP_HDR_SIZE, 16u,
                                     4u, 300ULL, &flen, &ev) == ESP_OK, "pkt 2");
    ASSERT_TRUE(ev == ESP_EVENT_SA_SOFT_EXPIRE && ctx.tx_sa.state == ESP_SA_REKEYING_SOFT,
                "pkt 2 must trigger soft expire");

    /* Packet 3: allowed while in ESP_SA_REKEYING_SOFT (up to hard_packets == 3) */
    ASSERT_TRUE(esp_encrypt_in_place(&ctx, buf, sizeof(buf), ESP_HDR_SIZE, 16u,
                                     4u, 400ULL, &flen, &ev) == ESP_OK, "pkt 3");

    /* Packet 4: exceeds hard_packets == 3 -> rejected with ESP_ERR_SA_EXPIRED and keys wiped */
    ASSERT_TRUE(esp_encrypt_in_place(&ctx, buf, sizeof(buf), ESP_HDR_SIZE, 16u,
                                     4u, 500ULL, &flen, &ev) == ESP_ERR_SA_EXPIRED,
                "pkt 4 must be rejected by hard packet limit");
    ASSERT_TRUE(ev == ESP_EVENT_SA_HARD_EXPIRE && ctx.tx_sa.state == ESP_SA_EXPIRED_HARD,
                "pkt 4 must transition SA to ESP_SA_EXPIRED_HARD");
    ASSERT_TRUE(memcmp(ctx.tx_sa.key, zeros32, 32u) == 0,
                "expired SA key was not zeroed via esp_secure_zero");

    return 0;
}

static int test_make_before_break_rollover_and_colliding_spi(void)
{
    static const uint8_t key_old[32] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
    };
    static const uint8_t salt_old[4] = {0x11, 0x22, 0x33, 0x44};

    static const uint8_t key_new[32] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
        0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
        0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef
    };
    static const uint8_t salt_new[4] = {0x55, 0x66, 0x77, 0x88};
    static const uint8_t zeros32[32] = {0};

    /* Intentionally pick two SPIs that collide on the lowest 2 bits ((spi & 0x3u) == 0) */
    const uint32_t spi_old = 0x10000100u;
    const uint32_t spi_new = 0x20000100u;

    esp_context_t tx_old;
    esp_context_t tx_new;
    esp_context_t rx;

    ASSERT_TRUE(esp_context_init(&tx_old, 1u) == ESP_OK, "tx_old init");
    ASSERT_TRUE(esp_context_init(&tx_new, 1u) == ESP_OK, "tx_new init");
    ASSERT_TRUE(esp_context_init(&rx, 1u) == ESP_OK, "rx init");

    ASSERT_TRUE(esp_sa_install(&tx_old, ESP_DIR_OUTBOUND, spi_old, key_old, salt_old, NULL, 1000ULL) == ESP_OK,
                "tx_old install");
    ASSERT_TRUE(esp_sa_install(&tx_new, ESP_DIR_OUTBOUND, spi_new, key_new, salt_new, NULL, 1000ULL) == ESP_OK,
                "tx_new install");
    ASSERT_TRUE(esp_sa_install(&rx, ESP_DIR_INBOUND, spi_old, key_old, salt_old, NULL, 1000ULL) == ESP_OK,
                "rx install spi_old");

    /* Trigger make-before-break rollover on rx with a 5000ns overlap window */
    ASSERT_TRUE(esp_sa_rekey(&rx, ESP_DIR_INBOUND, spi_new, key_new, salt_new, NULL,
                             5000ULL /* overlap_ns */, 2000ULL /* now_ns */) == ESP_OK,
                "rx rekey with colliding SPI failed");

    /* Encrypt one packet under old SA and one under new SA */
    uint8_t pkt_old[128] = {0};
    uint8_t pkt_new[128] = {0};
    memcpy(pkt_old + ESP_HDR_SIZE, "OLD_SA_PAYLOAD!", 16u);
    memcpy(pkt_new + ESP_HDR_SIZE, "NEW_SA_PAYLOAD!", 16u);

    size_t len_old = 0u;
    size_t len_new = 0u;
    ASSERT_TRUE(esp_encrypt_in_place(&tx_old, pkt_old, sizeof(pkt_old), ESP_HDR_SIZE, 16u,
                                     17u, 2500ULL, &len_old, NULL) == ESP_OK, "enc old");
    ASSERT_TRUE(esp_encrypt_in_place(&tx_new, pkt_new, sizeof(pkt_new), ESP_HDR_SIZE, 16u,
                                     17u, 2500ULL, &len_new, NULL) == ESP_OK, "enc new");

    /* Receive new SA packet first, then delayed old SA packet within overlap window (t = 3000 < 7000) */
    size_t off = 0u;
    size_t plen = 0u;
    uint8_t nh = 0u;
    ASSERT_TRUE(esp_decrypt_in_place(&rx, pkt_new, len_new, 3000ULL, &off, &plen, &nh, NULL) == ESP_OK,
                "decrypt new SA packet failed");
    ASSERT_TRUE(memcmp(pkt_new + off, "NEW_SA_PAYLOAD!", 16u) == 0, "new payload mismatch");

    ASSERT_TRUE(esp_decrypt_in_place(&rx, pkt_old, len_old, 3000ULL, &off, &plen, &nh, NULL) == ESP_OK,
                "decrypt delayed old SA packet during overlap window failed");
    ASSERT_TRUE(memcmp(pkt_old + off, "OLD_SA_PAYLOAD!", 16u) == 0, "old payload mismatch");

    /* Advance clock past overlap deadline (t = 7000ns) via esp_context_poll */
    uint64_t next_dl = 0ULL;
    esp_event_t ev = ESP_EVENT_NONE;
    ASSERT_TRUE(esp_context_poll(&rx, 7000ULL, &next_dl, &ev) == ESP_OK, "poll failed");
    ASSERT_TRUE(ev == ESP_EVENT_SA_OVERLAP_EXPIRED, "expected ESP_EVENT_SA_OVERLAP_EXPIRED");
    ASSERT_TRUE(rx.rx_sa_ring[0].state == ESP_SA_EXPIRED_HARD, "old slot not expired");
    ASSERT_TRUE(memcmp(rx.rx_sa_ring[0].key, zeros32, 32u) == 0,
                "retired overlap SA key was not zeroed after overlap timeout");

    /* Subsequent packet on expired old SA must be rejected with ESP_ERR_SA_EXPIRED */
    ASSERT_TRUE(esp_encrypt_in_place(&tx_old, pkt_old, sizeof(pkt_old), ESP_HDR_SIZE, 16u,
                                     17u, 7100ULL, &len_old, NULL) == ESP_OK, "enc old 2");
    ASSERT_TRUE(esp_decrypt_in_place(&rx, pkt_old, len_old, 7100ULL, &off, &plen, &nh, NULL) == ESP_ERR_SA_EXPIRED,
                "packet on expired overlap SA was not rejected");

    return 0;
}

int main(void)
{
    if (test_soft_and_hard_lifetimes_and_key_wipe() != 0) {
        return 1;
    }
    if (test_make_before_break_rollover_and_colliding_spi() != 0) {
        return 1;
    }
    printf("[PASS] test_rekey_fsm: SA lifetimes, colliding SPI fallback, rollover, and key wipe verified.\n");
    return 0;
}
