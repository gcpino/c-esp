/**
 * @file esp_replay.c
 * @brief RFC 6479 1024-bit anti-replay bitmap and RFC 4303 Appendix A 64-bit ESN reconstruction.
 */
#include "esp/esp_replay.h"

void esp_replay_init(esp_replay_window_t *win)
{
    if (win == NULL) {
        return;
    }
    for (size_t i = 0u; i < ESP_REPLAY_BLOCKS; ++i) {
        win->bitmap[i] = 0ULL;
    }
    win->highest_seq = 0ULL;
    win->initialized = 0u;
    for (size_t i = 0u; i < sizeof(win->reserved); ++i) {
        win->reserved[i] = 0u;
    }
}

esp_err_t esp_replay_reconstruct_esn(const esp_replay_window_t *win,
                                     uint32_t seq_low, uint8_t enable_esn,
                                     uint64_t *out_seq64)
{
    if (win == NULL || out_seq64 == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (enable_esn == 0u || win->initialized == 0u) {
        if (seq_low == 0u) {
            return ESP_ERR_REPLAY;
        }
        *out_seq64 = (uint64_t)seq_low;
        return ESP_OK;
    }

    uint32_t h_low = (uint32_t)(win->highest_seq & 0xFFFFFFFFULL);
    int32_t delta = (int32_t)(seq_low - h_low);

    if (delta >= 0) {
        uint64_t adv = (uint64_t)(uint32_t)delta;
        if (UINT64_MAX - win->highest_seq < adv) {
            return ESP_ERR_REPLAY;
        }
        uint64_t seq64 = win->highest_seq + adv;
        if (seq64 == 0ULL) {
            return ESP_ERR_REPLAY;
        }
        *out_seq64 = seq64;
        return ESP_OK;
    } else {
        uint64_t back = (uint64_t)(0u - (uint32_t)delta);
        if (win->highest_seq <= back) {
            return ESP_ERR_REPLAY;
        }
        *out_seq64 = win->highest_seq - back;
        return ESP_OK;
    }
}

esp_err_t esp_replay_precheck(const esp_replay_window_t *win, uint64_t seq64)
{
    if (win == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (seq64 == 0ULL) {
        return ESP_ERR_REPLAY;
    }
    if (win->initialized == 0u) {
        return ESP_OK;
    }
    if (seq64 > win->highest_seq) {
        return ESP_OK;
    }

    uint64_t diff = win->highest_seq - seq64;
    if (diff >= (uint64_t)ESP_REPLAY_WINDOW_SIZE) {
        return ESP_ERR_REPLAY;
    }

    uint32_t block_idx = (uint32_t)((seq64 >> 6u) & (ESP_REPLAY_BLOCKS - 1u));
    uint32_t bit_idx   = (uint32_t)(seq64 & 63u);

    if ((win->bitmap[block_idx] & (1ULL << bit_idx)) != 0ULL) {
        return ESP_ERR_REPLAY;
    }
    return ESP_OK;
}

void esp_replay_commit(esp_replay_window_t *win, uint64_t seq64)
{
    if (win == NULL || seq64 == 0ULL) {
        return;
    }

    uint32_t block_idx = (uint32_t)((seq64 >> 6u) & (ESP_REPLAY_BLOCKS - 1u));
    uint32_t bit_idx   = (uint32_t)(seq64 & 63u);

    if (win->initialized == 0u) {
        for (size_t i = 0u; i < ESP_REPLAY_BLOCKS; ++i) {
            win->bitmap[i] = 0ULL;
        }
        win->initialized = 1u;
        win->highest_seq = seq64;
        win->bitmap[block_idx] = (1ULL << bit_idx);
        return;
    }

    if (seq64 > win->highest_seq) {
        uint64_t old_block  = win->highest_seq >> 6u;
        uint64_t new_block  = seq64 >> 6u;
        uint64_t block_diff = new_block - old_block;

        if (block_diff >= (uint64_t)ESP_REPLAY_BLOCKS) {
            for (size_t i = 0u; i < ESP_REPLAY_BLOCKS; ++i) {
                win->bitmap[i] = 0ULL;
            }
        } else {
            for (uint64_t i = 1ULL; i <= block_diff; ++i) {
                uint32_t clear_idx = (uint32_t)((old_block + i) & (ESP_REPLAY_BLOCKS - 1u));
                win->bitmap[clear_idx] = 0ULL;
            }
        }
        win->highest_seq = seq64;
    }

    win->bitmap[block_idx] |= (1ULL << bit_idx);
}
