/**
 * @file esp_trace.c
 * @brief Embedded binary flight-recorder ring buffer implementation.
 */
#include "esp/esp_trace.h"

void esp_trace_init(esp_trace_ring_t *ring)
{
    if (ring == NULL) {
        return;
    }
    for (size_t i = 0u; i < ESP_TRACE_CAPACITY; ++i) {
        ring->entries[i].ts_delta_us = 0u;
        ring->entries[i].spi         = 0u;
        ring->entries[i].seq_low     = 0u;
        ring->entries[i].event_type  = 0u;
        ring->entries[i].status_code = 0;
    }
    ring->last_ts_ns = 0ULL;
    ring->head       = 0u;
    ring->count      = 0u;
}

void esp_trace_record(esp_trace_ring_t *ring, uint64_t now_ns,
                      uint32_t spi, uint32_t seq_low,
                      esp_event_t event_type, esp_err_t status_code)
{
    if (ring == NULL) {
        return;
    }

    uint32_t delta_us = 0u;
    if (ring->count > 0u && now_ns >= ring->last_ts_ns) {
        uint64_t delta_ns = now_ns - ring->last_ts_ns;
        uint64_t us = delta_ns / 1000ULL;
        delta_us = (us > 0xFFFFFFFFULL) ? 0xFFFFFFFFu : (uint32_t)us;
    }

    uint32_t slot = ring->head & (ESP_TRACE_CAPACITY - 1u);
    ring->entries[slot].ts_delta_us = delta_us;
    ring->entries[slot].spi         = spi;
    ring->entries[slot].seq_low     = seq_low;
    ring->entries[slot].event_type  = (uint16_t)event_type;
    ring->entries[slot].status_code = (int16_t)status_code;

    ring->last_ts_ns = now_ns;
    ring->head      += 1u;
    if (ring->count < ESP_TRACE_CAPACITY) {
        ring->count += 1u;
    }
}

size_t esp_trace_get(const esp_trace_ring_t *ring,
                     esp_trace_entry_t *out_entries, size_t max_entries)
{
    if (ring == NULL || out_entries == NULL || max_entries == 0u) {
        return 0u;
    }

    size_t n = (size_t)ring->count;
    if (n > max_entries) {
        n = max_entries;
    }

    /* Oldest entry of the most recent `n` entries */
    uint32_t start = ring->head - (uint32_t)n;
    for (size_t i = 0u; i < n; ++i) {
        uint32_t slot = (start + (uint32_t)i) & (ESP_TRACE_CAPACITY - 1u);
        out_entries[i] = ring->entries[slot];
    }
    return n;
}
