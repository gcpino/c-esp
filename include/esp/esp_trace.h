/**
 * @file esp_trace.h
 * @brief Embedded binary flight-recorder ring buffer (528 bytes total, zero I/O or heap dependencies).
 */
#ifndef ESP_TRACE_H
#define ESP_TRACE_H

#include "esp/esp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 16-byte binary telemetry record stored inside `esp_trace_ring_t`.
 */
typedef struct {
    uint32_t ts_delta_us; /**< Microseconds elapsed since the previous trace event. */
    uint32_t spi;         /**< Security Parameters Index associated with the event. */
    uint32_t seq_low;     /**< Low 32 bits of the packet sequence number (0 if not packet-bound). */
    uint16_t event_type;  /**< `esp_event_t` enumeration value. */
    int16_t  status_code; /**< `esp_err_t` status code. */
} esp_trace_entry_t;

/**
 * @brief 528-byte circular flight-recorder ring buffer (32 entries x 16 bytes + 16-byte header).
 */
typedef struct {
    esp_trace_entry_t entries[ESP_TRACE_CAPACITY]; /**< 32 * 16B = 512 bytes. */
    uint64_t          last_ts_ns;                  /**< Timestamp of most recent event (8B). */
    uint32_t          head;                        /**< Monotonic write index (4B). */
    uint32_t          count;                       /**< Number of valid entries <= 32 (4B). */
} esp_trace_ring_t;

_Static_assert(sizeof(esp_trace_entry_t) == 16u, "esp_trace_entry_t must be 16 bytes");
_Static_assert(sizeof(esp_trace_ring_t) == 528u, "esp_trace_ring_t must be 528 bytes");

/**
 * @brief Reset all entries and indices in the binary flight-recorder ring buffer.
 */
void esp_trace_init(esp_trace_ring_t *ring);

/**
 * @brief Append a 16-byte binary telemetry event in O(1) time.
 */
void esp_trace_record(esp_trace_ring_t *ring, uint64_t now_ns,
                      uint32_t spi, uint32_t seq_low,
                      esp_event_t event_type, esp_err_t status_code);

/**
 * @brief Copy up to `max_entries` recorded events in chronological order (oldest to newest).
 * @return Number of entries written to `out_entries`.
 */
size_t esp_trace_get(const esp_trace_ring_t *ring,
                     esp_trace_entry_t *out_entries, size_t max_entries);

#ifdef __cplusplus
}
#endif

#endif /* ESP_TRACE_H */
