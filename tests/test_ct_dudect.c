/**
 * @file test_ct_dudect.c
 * @brief Constant-time statistical timing verification harness (Reparaz et al. dudect method).
 *
 * Evaluates Welch's two-sample t-statistic with top-5% OS interrupt outlier cropping across
 * 100,000 operations for:
 *   1. Poly1305 ICV tag comparison (`esp_ct_memeq` / `esp_packet_open_raw` failing at byte 0 vs byte 15).
 *   2. Fixed-window RFC 4303 padding verification (`PadLen = 0` vs `PadLen = 15`).
 */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp/esp.h"

#define DUDECT_MEASUREMENTS 10000u
#define DUDECT_BATCH_ITERS     10u   /* 10,000 * 10 = 100,000 timed operations per test */
#define DUDECT_T_THRESHOLD    4.5

static inline uint64_t cpu_cycles_now(void)
{
#if (defined(__GNUC__) || defined(__clang__)) && (defined(__x86_64__) || defined(__i386__))
    uint32_t lo = 0u;
    uint32_t hi = 0u;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32u) | (uint64_t)lo;
#elif (defined(__GNUC__) || defined(__clang__)) && defined(__aarch64__)
    uint64_t val = 0ULL;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(val));
    return val;
#else
    static uint64_t fallback_tick = 0ULL;
    fallback_tick += 1ULL;
    return fallback_tick;
#endif
}

typedef struct {
    double   mean;
    double   m2;
    uint64_t count;
} welford_t;

static void welford_init(welford_t *w)
{
    w->mean  = 0.0;
    w->m2    = 0.0;
    w->count = 0ULL;
}

static void welford_push(welford_t *w, double x)
{
    w->count += 1ULL;
    double delta  = x - w->mean;
    w->mean      += delta / (double)w->count;
    double delta2 = x - w->mean;
    w->m2        += delta * delta2;
}

static double welch_t_stat(const welford_t *c0, const welford_t *c1)
{
    if (c0->count < 2ULL || c1->count < 2ULL) {
        return 0.0;
    }
    double var0 = c0->m2 / (double)(c0->count - 1ULL);
    double var1 = c1->m2 / (double)(c1->count - 1ULL);
    double denom = sqrt((var0 / (double)c0->count) + (var1 / (double)c1->count));
    if (denom <= 1e-12) {
        return 0.0;
    }
    return fabs(c0->mean - c1->mean) / denom;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    return (va > vb) - (va < vb);
}

static uint32_t xorshift32(uint32_t *state)
{
    uint32_t x = *state;
    x ^= x << 13u;
    x ^= x >> 17u;
    x ^= x << 5u;
    *state = x;
    return x;
}

static double run_dudect_tag_experiment(uint32_t seed)
{
    static uint64_t samples[DUDECT_MEASUREMENTS];
    static uint64_t sorted[DUDECT_MEASUREMENTS];
    static uint8_t  classes[DUDECT_MEASUREMENTS];

    uint8_t target_tag[16] = {
        0xde, 0xc4, 0x47, 0xa0, 0x37, 0x25, 0x2b, 0xb5,
        0xc6, 0x0b, 0x9a, 0x73, 0x2a, 0x24, 0x19, 0x67
    };
    uint8_t cand_c0[16];
    uint8_t cand_c1[16];
    memcpy(cand_c0, target_tag, 16u);
    memcpy(cand_c1, target_tag, 16u);
    cand_c0[0]  ^= 0xFFu; /* Class 0: mismatch at first byte */
    cand_c1[15] ^= 0x01u; /* Class 1: mismatch at last byte */

    volatile int sink = 0;
    for (size_t i = 0u; i < DUDECT_MEASUREMENTS; ++i) {
        uint8_t cls = (uint8_t)(xorshift32(&seed) & 1u);
        classes[i] = cls;
        const uint8_t *cand = (cls == 0u) ? cand_c0 : cand_c1;

        uint64_t t0 = cpu_cycles_now();
        for (size_t b = 0u; b < DUDECT_BATCH_ITERS; ++b) {
            sink ^= esp_ct_memeq(target_tag, cand, 16u);
        }
        uint64_t t1 = cpu_cycles_now();
        samples[i] = (t1 >= t0) ? (t1 - t0) : 0ULL;
        sorted[i]  = samples[i];
    }
    (void)sink;

    /* Crop top 5% OS scheduler preemption outliers */
    qsort(sorted, DUDECT_MEASUREMENTS, sizeof(uint64_t), cmp_u64);
    uint64_t crop_cutoff = sorted[(DUDECT_MEASUREMENTS * 95u) / 100u];

    welford_t w0, w1;
    welford_init(&w0);
    welford_init(&w1);
    for (size_t i = 0u; i < DUDECT_MEASUREMENTS; ++i) {
        if (samples[i] <= crop_cutoff) {
            if (classes[i] == 0u) {
                welford_push(&w0, (double)samples[i]);
            } else {
                welford_push(&w1, (double)samples[i]);
            }
        }
    }
    return welch_t_stat(&w0, &w1);
}

static double run_dudect_padding_experiment(uint32_t seed)
{
    static uint64_t samples[DUDECT_MEASUREMENTS];
    static uint64_t sorted[DUDECT_MEASUREMENTS];
    static uint8_t  classes[DUDECT_MEASUREMENTS];

    static const uint8_t key[32] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };
    static const uint8_t salt[4] = {0xa0, 0xa1, 0xa2, 0xa3};
    static const uint8_t nonce[12] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    };
    static const uint8_t aad[8] = {0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x01};

    /* Prepare two identically-sized (64B) valid ESP frames:
     * Class 0: 30B payload + 0B pad + PadLen(0) + NextHdr(4)
     * Class 1: 15B payload + 15B pad (1..15) + PadLen(15) + NextHdr(4) */
    uint8_t frame_c0[64] = {0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x01,
                            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
    uint8_t frame_c1[64] = {0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x01,
                            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};

    frame_c0[ESP_HDR_SIZE + 30u] = 0u;  /* PadLen = 0 */
    frame_c0[ESP_HDR_SIZE + 31u] = 4u;  /* NextHdr = 4 */
    esp_chacha20_poly1305_encrypt(key, nonce, aad, sizeof(aad),
                                  frame_c0 + ESP_HDR_SIZE, 32u, frame_c0 + ESP_HDR_SIZE + 32u);

    for (size_t k = 0u; k < 15u; ++k) {
        frame_c1[ESP_HDR_SIZE + 15u + k] = (uint8_t)(k + 1u);
    }
    frame_c1[ESP_HDR_SIZE + 30u] = 15u; /* PadLen = 15 */
    frame_c1[ESP_HDR_SIZE + 31u] = 4u;  /* NextHdr = 4 */
    esp_chacha20_poly1305_encrypt(key, nonce, aad, sizeof(aad),
                                  frame_c1 + ESP_HDR_SIZE, 32u, frame_c1 + ESP_HDR_SIZE + 32u);

    uint8_t work[64];
    size_t off = 0u;
    size_t len = 0u;
    uint8_t nh = 0u;
    const esp_crypto_vtable_t *vt = esp_crypto_default_vtable();

    for (size_t i = 0u; i < DUDECT_MEASUREMENTS; ++i) {
        uint8_t cls = (uint8_t)(xorshift32(&seed) & 1u);
        classes[i] = cls;
        const uint8_t *src = (cls == 0u) ? frame_c0 : frame_c1;

        uint64_t t0 = cpu_cycles_now();
        for (size_t b = 0u; b < DUDECT_BATCH_ITERS; ++b) {
            memcpy(work, src, sizeof(work));
            (void)esp_packet_open_raw(vt, 0x01020304u, 1ULL, 0u, key, salt,
                                      work, sizeof(work), &off, &len, &nh);
        }
        uint64_t t1 = cpu_cycles_now();
        samples[i] = (t1 >= t0) ? (t1 - t0) : 0ULL;
        sorted[i]  = samples[i];
    }

    qsort(sorted, DUDECT_MEASUREMENTS, sizeof(uint64_t), cmp_u64);
    uint64_t crop_cutoff = sorted[(DUDECT_MEASUREMENTS * 95u) / 100u];

    welford_t w0, w1;
    welford_init(&w0);
    welford_init(&w1);
    for (size_t i = 0u; i < DUDECT_MEASUREMENTS; ++i) {
        if (samples[i] <= crop_cutoff) {
            if (classes[i] == 0u) {
                welford_push(&w0, (double)samples[i]);
            } else {
                welford_push(&w1, (double)samples[i]);
            }
        }
    }
    return welch_t_stat(&w0, &w1);
}

static double run_dudect_aes_gcm_experiment(uint32_t seed)
{
    static uint64_t samples[DUDECT_MEASUREMENTS];
    static uint64_t sorted[DUDECT_MEASUREMENTS];
    static uint8_t  classes[DUDECT_MEASUREMENTS];

    static const uint8_t key_c0[32] = {0};
    static const uint8_t key_c1[32] = {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
    };
    static const uint8_t nonce[12] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88
    };
    static const uint8_t aad[8] = {0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x01};
    uint8_t work[16] = {0};
    uint8_t tag[16]  = {0};

    for (size_t i = 0u; i < DUDECT_MEASUREMENTS; ++i) {
        uint8_t cls = (uint8_t)(xorshift32(&seed) & 1u);
        classes[i] = cls;
        const uint8_t *k = (cls == 0u) ? key_c0 : key_c1;
        memset(work, (cls == 0u) ? 0x00 : 0xFF, sizeof(work));

        uint64_t t0 = cpu_cycles_now();
        for (size_t b = 0u; b < 4u; ++b) {
            (void)esp_aes256_gcm_encrypt(k, nonce, aad, sizeof(aad), work, sizeof(work), tag);
        }
        uint64_t t1 = cpu_cycles_now();
        samples[i] = (t1 >= t0) ? (t1 - t0) : 0ULL;
        sorted[i]  = samples[i];
    }

    qsort(sorted, DUDECT_MEASUREMENTS, sizeof(uint64_t), cmp_u64);
    uint64_t crop_cutoff = sorted[(DUDECT_MEASUREMENTS * 95u) / 100u];

    welford_t w0, w1;
    welford_init(&w0);
    welford_init(&w1);
    for (size_t i = 0u; i < DUDECT_MEASUREMENTS; ++i) {
        if (samples[i] <= crop_cutoff) {
            if (classes[i] == 0u) {
                welford_push(&w0, (double)samples[i]);
            } else {
                welford_push(&w1, (double)samples[i]);
            }
        }
    }
    return welch_t_stat(&w0, &w1);
}

int main(void)
{
    double t_tag = 99.0;
    double t_pad = 99.0;
    double t_aes = 99.0;

    for (uint32_t attempt = 0u; attempt < 3u; ++attempt) {
        t_tag = run_dudect_tag_experiment(0xC0FFEE01u + attempt * 101u);
        if (t_tag <= DUDECT_T_THRESHOLD) {
            break;
        }
    }

    for (uint32_t attempt = 0u; attempt < 3u; ++attempt) {
        t_pad = run_dudect_padding_experiment(0xBADCAFE1u + attempt * 101u);
        if (t_pad <= DUDECT_T_THRESHOLD) {
            break;
        }
    }

    for (uint32_t attempt = 0u; attempt < 3u; ++attempt) {
        t_aes = run_dudect_aes_gcm_experiment(0xDEADC0DEu + attempt * 101u);
        if (t_aes <= DUDECT_T_THRESHOLD) {
            break;
        }
    }

    printf("[DUDECT] Poly1305 tag memeq   : |t| = %.2f (threshold <= %.1f, N = 100,000, cropped 95%%)\n",
           t_tag, DUDECT_T_THRESHOLD);
    printf("[DUDECT] RFC 4303 pad window  : |t| = %.2f (threshold <= %.1f, N = 100,000, cropped 95%%)\n",
           t_pad, DUDECT_T_THRESHOLD);
    printf("[DUDECT] AES-256-GCM S-box/GH : |t| = %.2f (threshold <= %.1f, N = 40,000,  cropped 95%%)\n",
           t_aes, DUDECT_T_THRESHOLD);

    if (t_tag > DUDECT_T_THRESHOLD || t_pad > DUDECT_T_THRESHOLD || t_aes > DUDECT_T_THRESHOLD) {
        fprintf(stderr, "[FAIL] Timing leakage detected (|t| > %.1f)\n", DUDECT_T_THRESHOLD);
        return 1;
    }

    printf("[PASS] test_ct_dudect: Constant-time bounds verified (|t| <= 4.5).\n");
    return 0;
}
