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
    return 0;
}
