/**
 * @file test_replay_esn.c
 * @brief Unit tests for RFC 6479 1024-bit anti-replay bitmap, RFC 4303 Appendix A 64-bit ESN,
 *        and the binary flight-recorder ring buffer.
 */
#include <stdio.h>
#include <string.h>

#include "esp/esp_replay.h"
#include "esp/esp_trace.h"

#define ASSERT_TRUE(cond, msg)                                                      \
    do {                                                                            \
        if (!(cond)) {                                                              \
            fprintf(stderr, "[FAIL] %s:%d: %s\n", __FILE__, __LINE__, (msg));       \
            return 1;                                                               \
        }                                                                           \
    } while (0)

static int test_first_packet_and_zero_rejection(void)
{
    esp_replay_window_t win;
    uint64_t seq64 = 0ULL;

    esp_replay_init(&win);
    ASSERT_TRUE(win.initialized == 0u && win.highest_seq == 0ULL, "init state invalid");

    /* Sequence 0 is forbidden by RFC 4303 §3.3.3 */
    ASSERT_TRUE(esp_replay_reconstruct_esn(&win, 0u, 1u, &seq64) == ESP_ERR_REPLAY,
                "seq_low=0 must be rejected in ESN mode");
    ASSERT_TRUE(esp_replay_reconstruct_esn(&win, 0u, 0u, &seq64) == ESP_ERR_REPLAY,
                "seq_low=0 must be rejected in non-ESN mode");
    ASSERT_TRUE(esp_replay_precheck(&win, 0ULL) == ESP_ERR_REPLAY,
                "precheck(0) must be rejected");

    /* First valid packet (even if > 1 due to initial packet loss) initializes the window */
    ASSERT_TRUE(esp_replay_reconstruct_esn(&win, 42u, 1u, &seq64) == ESP_OK,
                "first packet reconstruct failed");
    ASSERT_TRUE(seq64 == 42ULL, "first packet seq64 != 42");
    ASSERT_TRUE(esp_replay_precheck(&win, seq64) == ESP_OK,
                "first packet precheck failed");
    ASSERT_TRUE(win.initialized == 0u, "precheck must not mutate initialized flag");

    esp_replay_commit(&win, seq64);
    ASSERT_TRUE(win.initialized == 1u && win.highest_seq == 42ULL,
                "commit failed to initialize window");

    /* Duplicate of packet 42 must be rejected */
    ASSERT_TRUE(esp_replay_precheck(&win, 42ULL) == ESP_ERR_REPLAY,
                "duplicate packet 42 not rejected");

    /* Earlier packet 10 arriving out-of-order after first packet 42 is within window */
    ASSERT_TRUE(esp_replay_reconstruct_esn(&win, 10u, 1u, &seq64) == ESP_OK,
                "reconstruct of seq_low=10 failed");
    ASSERT_TRUE(seq64 == 10ULL, "seq64 != 10");
    ASSERT_TRUE(esp_replay_precheck(&win, seq64) == ESP_OK,
                "out-of-order packet 10 rejected");
    esp_replay_commit(&win, seq64);
    ASSERT_TRUE(win.highest_seq == 42ULL, "highest_seq mutated on older packet");
    ASSERT_TRUE(esp_replay_precheck(&win, 10ULL) == ESP_ERR_REPLAY,
                "duplicate packet 10 not rejected");

    return 0;
}

static int test_esn_wrap_and_underflow_rejection(void)
{
    esp_replay_window_t win;
    uint64_t seq64 = 0ULL;

    esp_replay_init(&win);

    /* Underflow rejection in Epoch 0: highest_seq = 1000, spoofed seq_low = 0xFFFFFC00 (delta = -2024) */
    ASSERT_TRUE(esp_replay_reconstruct_esn(&win, 1000u, 1u, &seq64) == ESP_OK, "init 1000");
    esp_replay_commit(&win, seq64);
    ASSERT_TRUE(esp_replay_reconstruct_esn(&win, 0xFFFFFC00u, 1u, &seq64) == ESP_ERR_REPLAY,
                "underflow below sequence 1 in Epoch 0 must return ESP_ERR_REPLAY in Phase 1a");

    /*Behind-window packet in Epoch 0: highest_seq = 1000, seq_low = 10 (diff = 990 >= 960) */
    ASSERT_TRUE(esp_replay_reconstruct_esn(&win, 10u, 1u, &seq64) == ESP_OK,
                "reconstruct seq_low=10 in Epoch 0");
    ASSERT_TRUE(seq64 == 10ULL, "expected seq64=10");
    ASSERT_TRUE(esp_replay_precheck(&win, seq64) == ESP_ERR_REPLAY,
                "packet 10 (diff=990 >= 960) must be rejected by precheck");

    /* Exact window boundary check: highest_seq = 1000 -> 41 (diff=959) accepted, 40 (diff=960) rejected */
    ASSERT_TRUE(esp_replay_precheck(&win, 41ULL) == ESP_OK,
                "packet at highest_seq - 959 must be accepted");
    ASSERT_TRUE(esp_replay_precheck(&win, 40ULL) == ESP_ERR_REPLAY,
                "packet at highest_seq - 960 must be rejected");

    /* Advance near 32-bit boundary in < 2^31 steps: 1000 -> 0x70000000 -> 0xE0000000 -> 0xFFFFFFF0 */
    ASSERT_TRUE(esp_replay_reconstruct_esn(&win, 0x70000000u, 1u, &seq64) == ESP_OK,
                "advance to 0x70000000");
    esp_replay_commit(&win, seq64);
    ASSERT_TRUE(esp_replay_reconstruct_esn(&win, 0xE0000000u, 1u, &seq64) == ESP_OK,
                "advance to 0xE0000000");
    esp_replay_commit(&win, seq64);
    ASSERT_TRUE(esp_replay_reconstruct_esn(&win, 0xFFFFFFF0u, 1u, &seq64) == ESP_OK,
                "advance to 0xFFFFFFF0");
    ASSERT_TRUE(seq64 == 0x00000000FFFFFFF0ULL, "unexpected seq64 at 0xFFFFFFF0");
    esp_replay_commit(&win, seq64);

    /* Wrap across 32-bit boundary to 0x00000005 -> Epoch 1 (0x0000000100000005ULL) */
    ASSERT_TRUE(esp_replay_reconstruct_esn(&win, 0x00000005u, 1u, &seq64) == ESP_OK,
                "ESN wrap to 0x00000005 failed");
    ASSERT_TRUE(seq64 == 0x0000000100000005ULL,
                "ESN wrap did not increment high 32-bit epoch");
    ASSERT_TRUE(esp_replay_precheck(&win, seq64) == ESP_OK, "precheck after wrap failed");
    esp_replay_commit(&win, seq64);

    /* Late packet from Epoch 0 (seq_low = 0xFFFFFFFE) arriving after wrap into Epoch 1 */
    ASSERT_TRUE(esp_replay_reconstruct_esn(&win, 0xFFFFFFFEu, 1u, &seq64) == ESP_OK,
                "late pre-wrap packet reconstruction failed");
    ASSERT_TRUE(seq64 == 0x00000000FFFFFFFEULL,
                "late pre-wrap packet reconstructed wrong epoch");
    ASSERT_TRUE(esp_replay_precheck(&win, seq64) == ESP_OK,
                "late pre-wrap packet rejected by precheck");
    esp_replay_commit(&win, seq64);
    ASSERT_TRUE(win.highest_seq == 0x0000000100000005ULL,
                "highest_seq regressed on pre-wrap packet");
    ASSERT_TRUE(esp_replay_precheck(&win, 0x00000000FFFFFFFEULL) == ESP_ERR_REPLAY,
                "duplicate pre-wrap packet not rejected");

    return 0;
}

static int test_spoofed_high_sequence_immutability(void)
{
    esp_replay_window_t win;
    esp_replay_window_t snapshot;
    uint64_t seq64 = 0ULL;

    esp_replay_init(&win);
    for (uint32_t s = 1u; s <= 128u; ++s) {
        ASSERT_TRUE(esp_replay_reconstruct_esn(&win, s, 1u, &seq64) == ESP_OK, "reconstruct");
        ASSERT_TRUE(esp_replay_precheck(&win, seq64) == ESP_OK, "precheck");
        esp_replay_commit(&win, seq64);
    }
    memcpy(&snapshot, &win, sizeof(win));

    /* Attacker injects unauthenticated packet with seq_low = 0x7FFFFFFF (passes Phase 1, fails AEAD) */
    ASSERT_TRUE(esp_replay_reconstruct_esn(&win, 0x7FFFFFFFu, 1u, &seq64) == ESP_OK,
                "attacker reconstruct");
    ASSERT_TRUE(esp_replay_precheck(&win, seq64) == ESP_OK,
                "attacker precheck");
    /* Do NOT call esp_replay_commit because AEAD fails */
    ASSERT_TRUE(memcmp(&win, &snapshot, sizeof(win)) == 0,
                "window state mutated during Phase 1 precheck!");

    return 0;
}

static int test_trace_ring(void)
{
    esp_trace_ring_t ring;
    esp_trace_entry_t out[ESP_TRACE_CAPACITY];

    esp_trace_init(&ring);
    ASSERT_TRUE(esp_trace_get(&ring, out, ESP_TRACE_CAPACITY) == 0u, "initial trace not empty");

    /* Record 40 events (wrapping the 32-entry ring) */
    for (uint32_t i = 1u; i <= 40u; ++i) {
        esp_trace_record(&ring, (uint64_t)i * 10000ULL, 0x10000100u, i,
                         ESP_EVENT_SA_INSTALLED, ESP_OK);
    }

    size_t n = esp_trace_get(&ring, out, ESP_TRACE_CAPACITY);
    ASSERT_TRUE(n == ESP_TRACE_CAPACITY, "expected 32 entries after wrap");
    ASSERT_TRUE(out[0].seq_low == 9u, "oldest entry after 40 writes must be seq_low=9");
    ASSERT_TRUE(out[31].seq_low == 40u, "newest entry after 40 writes must be seq_low=40");
    ASSERT_TRUE(out[1].ts_delta_us == 10u, "expected 10us delta between events");

    return 0;
}

int main(void)
{
    if (test_first_packet_and_zero_rejection() != 0) {
        return 1;
    }
    if (test_esn_wrap_and_underflow_rejection() != 0) {
        return 1;
    }
    if (test_spoofed_high_sequence_immutability() != 0) {
        return 1;
    }
    if (test_trace_ring() != 0) {
        return 1;
    }
    printf("[PASS] test_replay_esn: RFC 6479 1024-bit window, 64-bit ESN wrap, and binary trace verified.\n");
    return 0;
}
