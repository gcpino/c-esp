/**
 * @file fuzz_esp_decrypt.c
 * @brief libFuzzer + ASan/UBSan harness for esp_decrypt_in_place().
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "esp/esp.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const uint8_t key1[32] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };
    static const uint8_t salt1[4] = {0xa0, 0xa1, 0xa2, 0xa3};

    if (size > 2048u) {
        return 0;
    }

    esp_context_t ctx;
    (void)esp_context_init(&ctx, 1u);
    (void)esp_sa_install(&ctx, ESP_DIR_INBOUND, 0x01020304u, key1, salt1, NULL, 1000ULL);
    (void)esp_sa_rekey(&ctx, ESP_DIR_INBOUND, 0x10000100u, key1, salt1, NULL, 500000ULL, 2000ULL);

    uint8_t buf[2048];
    if (size > 0u) {
        memcpy(buf, data, size);
    }

    size_t off = 0u;
    size_t len = 0u;
    uint8_t nh = 0u;
    esp_event_t ev = ESP_EVENT_NONE;
    (void)esp_decrypt_in_place(&ctx, buf, size, 3000ULL, &off, &len, &nh, &ev);
    esp_context_wipe(&ctx);

    esp_spd_t spd;
    esp_spd_init(&spd);
    esp_spd_rule_t rule = {
        .rule_id = 1u, .priority = 10u, .src_ip = 0x0A000000u, .src_mask = 0xFF000000u,
        .dst_ip = 0xC0A80000u, .dst_mask = 0xFFFF0000u, .src_port_min = 0u, .src_port_max = 65535u,
        .dst_port_min = 0u, .dst_port_max = 65535u, .protocol = 0u, .action = ESP_SPD_ACTION_PROTECT,
        .bound_spi = 0x01020304u
    };
    (void)esp_spd_add_rule(&spd, &rule);
    esp_spd_action_t act = ESP_SPD_ACTION_DISCARD;
    uint32_t b_spi = 0u;
    uint16_t m_id  = 0u;
    (void)esp_spd_classify_ipv4(&spd, data, size, &act, &b_spi, &m_id);
    esp_spd_zeroize(&spd);
    return 0;
}
