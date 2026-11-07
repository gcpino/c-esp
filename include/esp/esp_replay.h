/**
 * @file esp_replay.h
 * @brief RFC 6479 1024-bit sliding-window anti-replay bitmap and RFC 4303 Appendix A 64-bit ESN reconstruction.
 */
#ifndef ESP_REPLAY_H
#define ESP_REPLAY_H

#include "esp/esp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief RFC 6479 1024-bit circular anti-replay window with 64-bit Extended Sequence Number state.
 */
typedef struct {
    uint64_t bitmap[ESP_REPLAY_BLOCKS]; /**< 16 x 64-bit ring blocks (1024 bits total). */
    uint64_t highest_seq;               /**< Highest authenticated 64-bit sequence number. */
    uint8_t  initialized;               /**< 1 after first authenticated packet, 0 initially. */
    uint8_t  reserved[7];               /**< Explicit 64-bit alignment padding. */
} esp_replay_window_t;

/**
 * @brief Initialize or reset an anti-replay window to its uninitialized state.
 */
void esp_replay_init(esp_replay_window_t *win);

/**
 * @brief Phase 1a (Read-Only): Reconstruct the 64-bit sequence number from the 32-bit wire `seq_low`.
 *
 * Uses signed 32-bit modular offset (`int32_t delta = (int32_t)(seq_low - (uint32_t)win->highest_seq)`)
 * per RFC 4303 Appendix A when `enable_esn == 1` and `win->initialized == 1`.
 *
 * @param win        Pointer to the anti-replay window (not mutated).
 * @param seq_low    32-bit sequence number parsed from the ESP header.
 * @param enable_esn 1 if 64-bit Extended Sequence Numbers are enabled, 0 for 32-bit sequence numbers.
 * @param out_seq64  Output pointer receiving the reconstructed 64-bit sequence number.
 * @return ESP_OK on valid reconstruction, ESP_ERR_REPLAY if `seq64 == 0` or underflows below 1,
 *         or ESP_ERR_INVALID_ARG if `win` or `out_seq64` is NULL.
 */
esp_err_t esp_replay_reconstruct_esn(const esp_replay_window_t *win,
                                     uint32_t seq_low, uint8_t enable_esn,
                                     uint64_t *out_seq64);

/**
 * @brief Phase 1b (Read-Only): Check whether `seq64` is eligible for authentication without mutating state.
 *
 * @param win   Pointer to the anti-replay window (not mutated).
 * @param seq64 Reconstructed 64-bit sequence number to check.
 * @return ESP_OK if `seq64` is ahead of the window or within the window and unseen;
 *         ESP_ERR_REPLAY if `seq64 == 0`, behind `highest_seq - ESP_REPLAY_WINDOW_SIZE`, or already seen.
 */
esp_err_t esp_replay_precheck(const esp_replay_window_t *win, uint64_t seq64);

/**
 * @brief Phase 2 (Mutating): Advance the RFC 6479 circular bitmap and set the bit for `seq64`.
 *        MUST only be called after Poly1305 AEAD tag verification succeeds.
 */
void esp_replay_commit(esp_replay_window_t *win, uint64_t seq64);

#ifdef __cplusplus
}
#endif

#endif /* ESP_REPLAY_H */
