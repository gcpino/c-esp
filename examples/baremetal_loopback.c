/**
 * @file baremetal_loopback.c
 * @brief Freestanding static memory-ring loopback example for c-esp with SA rollover
 *        and binary flight-recorder inspection.
 */
#include <stdio.h>
#include <string.h>

#include "esp/esp.h"

int main(void)
{
    static const uint8_t key_a[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };
    static const uint8_t salt_a[4] = {0x11, 0x22, 0x33, 0x44};

    static const uint8_t key_b[32] = {
        0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
        0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x00,
        0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8,
        0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0x01
    };
    static const uint8_t salt_b[4] = {0xaa, 0xbb, 0xcc, 0xdd};

    static esp_context_t node_tx;
    static esp_context_t node_rx;
    static uint8_t wire_arena[128];

    (void)esp_context_init(&node_tx, 1u);
    (void)esp_context_init(&node_rx, 1u);

    (void)esp_sa_install(&node_tx, ESP_DIR_OUTBOUND, 0x10000100u, key_a, salt_a, NULL, 1000ULL);
    (void)esp_sa_install(&node_rx, ESP_DIR_INBOUND,  0x10000100u, key_a, salt_a, NULL, 1000ULL);

    const char telemetry[] = "BAREMETAL_TELEMETRY_FRAME_01";
    memcpy(wire_arena + ESP_HDR_SIZE, telemetry, sizeof(telemetry));

    size_t frame_len = 0u;
    esp_event_t ev = ESP_EVENT_NONE;
    if (esp_encrypt_in_place(&node_tx, wire_arena, sizeof(wire_arena),
                             ESP_HDR_SIZE, sizeof(telemetry), 4u, 2000ULL,
                             &frame_len, &ev) != ESP_OK) {
        return 1;
    }

    /* Perform make-before-break rekey on receiver before the in-flight frame arrives */
    (void)esp_sa_rekey(&node_rx, ESP_DIR_INBOUND, 0x10000201u, key_b, salt_b,
                       NULL, 50000ULL, 2500ULL);

    size_t off = 0u;
    size_t plen = 0u;
    uint8_t nh = 0u;
    if (esp_decrypt_in_place(&node_rx, wire_arena, frame_len, 3000ULL,
                             &off, &plen, &nh, &ev) != ESP_OK) {
        return 1;
    }

    esp_trace_entry_t entries[8];
    size_t n_trace = esp_trace_get(&node_rx.trace, entries, 8u);

    printf("[baremetal_loopback] Decrypted %zu B (NextHdr=%u): \"%s\" | Trace entries: %zu\n",
           plen, (unsigned int)nh, (const char *)(wire_arena + off), n_trace);

    esp_context_wipe(&node_tx);
    esp_context_wipe(&node_rx);
    return 0;
}
