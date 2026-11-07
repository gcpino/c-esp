/**
 * @file sim_channel.c
 * @brief Gilbert-Elliott Markov burst-loss & Gamma reordering channel simulator and DLT_RAW PCAP generator.
 */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp/esp.h"

/* --------------------------------------------------------------------------
 * Deterministic PRNG & Gamma / Box-Muller Sampling
 * -------------------------------------------------------------------------- */

static uint64_t splitmix64(uint64_t *state)
{
    uint64_t z = (*state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30u)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27u)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31u);
}

static double prng_uniform01(uint64_t *state)
{
    return (double)(splitmix64(state) >> 11u) * (1.0 / 9007199254740992.0);
}

static double prng_standard_normal(uint64_t *state)
{
    double u1 = prng_uniform01(state);
    double u2 = prng_uniform01(state);
    if (u1 < 1e-12) {
        u1 = 1e-12;
    }
    return sqrt(-2.0 * log(u1)) * cos(6.28318530717958647692 * u2);
}

/**
 * @brief Marsaglia-Tsang Gamma(k, theta) sampler for heavy-tailed network jitter.
 */
static double prng_gamma(uint64_t *state, double shape_k, double scale_theta)
{
    if (shape_k <= 0.0 || scale_theta <= 0.0) {
        return 0.0;
    }
    if (shape_k < 1.0) {
        double u = prng_uniform01(state);
        if (u < 1e-12) {
            u = 1e-12;
        }
        return prng_gamma(state, shape_k + 1.0, scale_theta) * pow(u, 1.0 / shape_k);
    }

    double d = shape_k - (1.0 / 3.0);
    double c = 1.0 / sqrt(9.0 * d);
    for (;;) {
        double x = prng_standard_normal(state);
        double v = 1.0 + c * x;
        if (v <= 0.0) {
            continue;
        }
        v = v * v * v;
        double u = prng_uniform01(state);
        if (u < 1.0 - 0.0331 * (x * x) * (x * x)) {
            return d * v * scale_theta;
        }
        if (log(u) < 0.5 * x * x + d * (1.0 - v + log(v))) {
            return d * v * scale_theta;
        }
    }
}

/* --------------------------------------------------------------------------
 * Channel Simulation & Multi-Window Comparison (--benchmark)
 * -------------------------------------------------------------------------- */

#define SIM_NUM_PACKETS 5000u

typedef struct {
    uint64_t arrival_order;
    uint32_t seq_idx;
    uint8_t  dropped_in_channel;
    uint8_t  frame[128];
    size_t   frame_len;
} sim_pkt_t;

static int cmp_sim_pkt(const void *a, const void *b)
{
    const sim_pkt_t *pa = (const sim_pkt_t *)a;
    const sim_pkt_t *pb = (const sim_pkt_t *)b;
    if (pa->arrival_order < pb->arrival_order) {
        return -1;
    }
    if (pa->arrival_order > pb->arrival_order) {
        return 1;
    }
    return (pa->seq_idx > pb->seq_idx) - (pa->seq_idx < pb->seq_idx);
}

static int run_benchmark(void)
{
    static const uint8_t key1[32] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };
    static const uint8_t salt1[4] = {0xa0, 0xa1, 0xa2, 0xa3};

    static const uint8_t key2[32] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
    };
    static const uint8_t salt2[4] = {0xb0, 0xb1, 0xb2, 0xb3};

    static sim_pkt_t pkts[SIM_NUM_PACKETS];
    const double sigmas[4] = {0.0, 32.0, 128.0, 384.0};

    printf("====================================================================================\n");
    printf(" c-esp Channel Physics Benchmark: Gilbert-Elliott Burst Loss + Gamma Reordering\n");
    printf(" Packets/Run: %u | Live SA Rekey at Pkt 2500 | Context Size: %zu B (<= 4096 B)\n",
           SIM_NUM_PACKETS, sizeof(esp_context_t));
    printf("====================================================================================\n");
    printf(" Reorder Jitter | Legacy 64-Bit Win | Legacy 256-Bit Win | c-esp RFC 6479 (1024-Bit)\n");
    printf(" (sigma pkts)   | False Replay Drop | False Replay Drop  | False Replay Drop\n");
    printf("----------------+-------------------+--------------------+--------------------------\n");

    for (size_t s_idx = 0u; s_idx < 4u; ++s_idx) {
        double sigma = sigmas[s_idx];
        uint64_t rng = 0x20261107ULL + (uint64_t)s_idx * 997ULL;

        esp_context_t tx;
        esp_context_t rx;
        (void)esp_context_init(&tx, 1u);
        (void)esp_context_init(&rx, 1u);

        (void)esp_sa_install(&tx, ESP_DIR_OUTBOUND, 0x10000101u, key1, salt1, NULL, 1000ULL);
        (void)esp_sa_install(&rx, ESP_DIR_INBOUND,  0x10000101u, key1, salt1, NULL, 1000ULL);

        /* Gilbert-Elliott 2-state Markov chain: Good (0) vs Burst-Fade (1) */
        int ge_state = 0;
        const double p_g2b = 0.002;
        const double p_b2g = 0.250;
        const double loss_good = 0.0005;
        const double loss_bad  = 0.1500;

        for (uint32_t i = 0u; i < SIM_NUM_PACKETS; ++i) {
            if (i == (SIM_NUM_PACKETS / 2u)) {
                /* Make-before-break SA rollover mid-flight */
                (void)esp_sa_rekey(&tx, ESP_DIR_OUTBOUND, 0x10000202u, key2, salt2,
                                   NULL, 1000000000ULL, 50000ULL);
                (void)esp_sa_rekey(&rx, ESP_DIR_INBOUND,  0x10000202u, key2, salt2,
                                   NULL, 1000000000ULL, 50000ULL);
            }

            memset(&pkts[i], 0, sizeof(sim_pkt_t));
            pkts[i].seq_idx = i + 1u;

            for (size_t b = 0u; b < 48u; ++b) {
                pkts[i].frame[ESP_HDR_SIZE + b] = (uint8_t)((i + b) & 0xFFu);
            }

            (void)esp_encrypt_in_place(&tx, pkts[i].frame, sizeof(pkts[i].frame),
                                       ESP_HDR_SIZE, 48u, 17u, 10000ULL + (uint64_t)i * 10ULL,
                                       &pkts[i].frame_len, NULL);

            /* Update Gilbert-Elliott state */
            double u_trans = prng_uniform01(&rng);
            if (ge_state == 0 && u_trans < p_g2b) {
                ge_state = 1;
            } else if (ge_state == 1 && u_trans < p_b2g) {
                ge_state = 0;
            }

            double loss_p = (ge_state == 0) ? loss_good : loss_bad;
            pkts[i].dropped_in_channel = (prng_uniform01(&rng) < loss_p) ? 1u : 0u;

            uint64_t jitter_offset = 0ULL;
            if (sigma > 0.0) {
                /* Gamma(k=2.0, theta = sigma / sqrt(2)) has standard deviation = sigma */
                double delay = prng_gamma(&rng, 2.0, sigma * 0.7071067811865475);
                jitter_offset = (uint64_t)(delay * 100.0);
            }
            pkts[i].arrival_order = (uint64_t)i * 100ULL + jitter_offset;
        }

        qsort(pkts, SIM_NUM_PACKETS, sizeof(sim_pkt_t), cmp_sim_pkt);

        uint32_t delivered = 0u;
        uint32_t drop_w64  = 0u;
        uint32_t drop_w256 = 0u;
        uint32_t drop_cesp = 0u;

        uint32_t highest_w64[2]  = {0u, 0u};
        uint32_t highest_w256[2] = {0u, 0u};

        for (uint32_t i = 0u; i < SIM_NUM_PACKETS; ++i) {
            if (pkts[i].dropped_in_channel != 0u) {
                continue;
            }
            delivered += 1u;

            /* Identify SA epoch (0 for first half, 1 for second half) */
            size_t sa_epoch = (pkts[i].seq_idx > (SIM_NUM_PACKETS / 2u)) ? 1u : 0u;
            uint32_t sa_seq = (sa_epoch == 0u)
                                  ? pkts[i].seq_idx
                                  : (pkts[i].seq_idx - (SIM_NUM_PACKETS / 2u));

            /* Reference W=64 window check */
            if (sa_seq > highest_w64[sa_epoch]) {
                highest_w64[sa_epoch] = sa_seq;
            } else if ((highest_w64[sa_epoch] - sa_seq) >= 64u) {
                drop_w64 += 1u;
            }

            /* Reference W=256 window check */
            if (sa_seq > highest_w256[sa_epoch]) {
                highest_w256[sa_epoch] = sa_seq;
            } else if ((highest_w256[sa_epoch] - sa_seq) >= 256u) {
                drop_w256 += 1u;
            }

            /* Actual c-esp full decapsulation + RFC 6479 1024-bit window */
            size_t off = 0u;
            size_t plen = 0u;
            uint8_t nh = 0u;
            esp_err_t err = esp_decrypt_in_place(&rx, pkts[i].frame, pkts[i].frame_len,
                                                 60000ULL + (uint64_t)i * 10ULL,
                                                 &off, &plen, &nh, NULL);
            if (err == ESP_ERR_REPLAY) {
                drop_cesp += 1u;
            } else if (err != ESP_OK) {
                fprintf(stderr, "[FAIL] Unexpected decrypt error %d in benchmark\n", (int)err);
                return 1;
            }
        }

        double pct64   = (delivered > 0u) ? (100.0 * (double)drop_w64 / (double)delivered) : 0.0;
        double pct256  = (delivered > 0u) ? (100.0 * (double)drop_w256 / (double)delivered) : 0.0;
        double pct1024 = (delivered > 0u) ? (100.0 * (double)drop_cesp / (double)delivered) : 0.0;

        printf(" sigma = %5.1f  | %6.2f%% (%4u)    | %6.2f%% (%4u)     | %6.2f%% (%4u)\n",
               sigma, pct64, drop_w64, pct256, drop_w256, pct1024, drop_cesp);
    }
    printf("====================================================================================\n");
    return 0;
}

static inline uint64_t bench_cycles_now(void)
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
    return 0ULL;
#endif
}

static int run_throughput_benchmark(void)
{
    static const uint8_t key[32] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };
    static const uint8_t salt[4] = {0xa0, 0xa1, 0xa2, 0xa3};
    static const size_t payload_sizes[5] = {64u, 256u, 512u, 1024u, 1400u};
    const uint32_t iters = 2000u;

    printf("\n====================================================================================\n");
    printf(" c-esp In-Place Data-Plane Throughput Sweep (Encrypt + Anti-Replay + Decrypt)\n");
    printf(" Iterations/Size: %u | Zero-Copy Arena Buffer | ESN: 64-Bit Enabled\n", iters);
    printf("====================================================================================\n");
    printf(" Payload Size | RFC 7634 ChaCha20-Poly1305 | RFC 4106 Table-Free AES-256-GCM\n");
    printf(" (Bytes)      | (Cycles/Byte Round-Trip)   | (Cycles/Byte Round-Trip)\n");
    printf("--------------+----------------------------+----------------------------------------\n");

    for (size_t s = 0u; s < 5u; ++s) {
        size_t plen = payload_sizes[s];
        uint8_t buf[1536] = {0};

        /* 1. RFC 7634 ChaCha20-Poly1305 */
        esp_context_t tx_cc, rx_cc;
        (void)esp_context_init(&tx_cc, 1u);
        (void)esp_context_init(&rx_cc, 1u);
        (void)esp_sa_install(&tx_cc, ESP_DIR_OUTBOUND, 0x10000100u, key, salt, NULL, 1000ULL);
        (void)esp_sa_install(&rx_cc, ESP_DIR_INBOUND,  0x10000100u, key, salt, NULL, 1000ULL);

        uint64_t c0 = bench_cycles_now();
        for (uint32_t i = 0u; i < iters; ++i) {
            size_t flen = 0u, off = 0u, dlen = 0u;
            uint8_t nh = 0u;
            (void)esp_encrypt_in_place(&tx_cc, buf, sizeof(buf), ESP_HDR_SIZE, plen,
                                       4u, 2000ULL, &flen, NULL);
            (void)esp_decrypt_in_place(&rx_cc, buf, flen, 2000ULL, &off, &dlen, &nh, NULL);
        }
        uint64_t c1 = bench_cycles_now();
        double cpb_chacha = (double)(c1 - c0) / ((double)iters * (double)plen * 2.0);

        /* 2. RFC 4106 Table-Free AES-256-GCM */
        esp_context_t tx_gcm, rx_gcm;
        (void)esp_context_init(&tx_gcm, 1u);
        (void)esp_context_init(&rx_gcm, 1u);
        (void)esp_context_set_crypto(&tx_gcm, esp_crypto_aes256_gcm_vtable());
        (void)esp_context_set_crypto(&rx_gcm, esp_crypto_aes256_gcm_vtable());
        (void)esp_sa_install(&tx_gcm, ESP_DIR_OUTBOUND, 0x20000200u, key, salt, NULL, 1000ULL);
        (void)esp_sa_install(&rx_gcm, ESP_DIR_INBOUND,  0x20000200u, key, salt, NULL, 1000ULL);

        uint32_t gcm_iters = 200u;
        uint64_t g0 = bench_cycles_now();
        for (uint32_t i = 0u; i < gcm_iters; ++i) {
            size_t flen = 0u, off = 0u, dlen = 0u;
            uint8_t nh = 0u;
            (void)esp_encrypt_in_place(&tx_gcm, buf, sizeof(buf), ESP_HDR_SIZE, plen,
                                       4u, 2000ULL, &flen, NULL);
            (void)esp_decrypt_in_place(&rx_gcm, buf, flen, 2000ULL, &off, &dlen, &nh, NULL);
        }
        uint64_t g1 = bench_cycles_now();
        double cpb_gcm = (double)(g1 - g0) / ((double)gcm_iters * (double)plen * 2.0);

        printf(" %7zu B    | %10.2f cpb             | %10.2f cpb (bit-sliced/algebraic)\n",
               plen, cpb_chacha, cpb_gcm);
    }
    printf("====================================================================================\n");
    return 0;
}

/* --------------------------------------------------------------------------
 * DLT_RAW (101) IPv4 + ESP PCAP & Wireshark Keyfile Generator (--pcap)
 * -------------------------------------------------------------------------- */

static uint16_t ipv4_checksum(const uint8_t hdr[20])
{
    uint32_t sum = 0u;
    for (size_t i = 0u; i < 20u; i += 2u) {
        uint16_t word = (uint16_t)(((uint16_t)hdr[i] << 8u) | (uint16_t)hdr[i + 1u]);
        sum += (uint32_t)word;
    }
    while ((sum >> 16u) != 0u) {
        sum = (sum & 0xFFFFu) + (sum >> 16u);
    }
    return (uint16_t)(~sum & 0xFFFFu);
}

static void write_u32_le(uint8_t d[4], uint32_t v)
{
    d[0] = (uint8_t)(v & 0xFFu);
    d[1] = (uint8_t)((v >> 8u) & 0xFFu);
    d[2] = (uint8_t)((v >> 16u) & 0xFFu);
    d[3] = (uint8_t)((v >> 24u) & 0xFFu);
}

static void write_u16_le(uint8_t d[2], uint16_t v)
{
    d[0] = (uint8_t)(v & 0xFFu);
    d[1] = (uint8_t)((v >> 8u) & 0xFFu);
}

static int generate_pcap(const char *pcap_path, const char *keys_path)
{
    static const uint8_t key[32] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };
    static const uint8_t salt[4] = {0xa0, 0xa1, 0xa2, 0xa3};
    const uint32_t spi = 0x01020304u;

    FILE *fp = fopen(pcap_path, "wb");
    if (fp == NULL) {
        fprintf(stderr, "[FAIL] Could not open %s for writing\n", pcap_path);
        return 1;
    }

    /* 24-byte libpcap global header (DLT_RAW = 101) */
    uint8_t ghdr[24] = {0};
    write_u32_le(ghdr +  0u, 0xa1b2c3d4u); /* magic */
    write_u16_le(ghdr +  4u, 2u);          /* version_major */
    write_u16_le(ghdr +  6u, 4u);          /* version_minor */
    write_u32_le(ghdr +  8u, 0u);          /* thiszone */
    write_u32_le(ghdr + 12u, 0u);          /* sigfigs */
    write_u32_le(ghdr + 16u, 65535u);      /* snaplen */
    write_u32_le(ghdr + 20u, 101u);        /* network = DLT_RAW (raw IPv4/IPv6) */
    (void)fwrite(ghdr, 1u, sizeof(ghdr), fp);

    esp_context_t tx;
    (void)esp_context_init(&tx, 0u);
    (void)esp_sa_install(&tx, ESP_DIR_OUTBOUND, spi, key, salt, NULL, 1000ULL);

    for (uint32_t p = 0u; p < 8u; ++p) {
        uint8_t esp_buf[128] = {0};
        const char msg[] = "c-esp RFC 4303 + RFC 7634 ChaCha20-Poly1305 wire frame";
        memcpy(esp_buf + ESP_HDR_SIZE, msg, sizeof(msg));

        size_t esp_len = 0u;
        (void)esp_encrypt_in_place(&tx, esp_buf, sizeof(esp_buf), ESP_HDR_SIZE,
                                   sizeof(msg), 17u /* UDP */, 1000ULL + p * 1000ULL,
                                   &esp_len, NULL);

        uint16_t ip_total_len = (uint16_t)(20u + esp_len);
        uint8_t ip_hdr[20] = {
            0x45, 0x00,
            (uint8_t)(ip_total_len >> 8u), (uint8_t)(ip_total_len & 0xFFu),
            0x00, (uint8_t)(p + 1u), 0x40, 0x00,
            64u,  50u /* IPPROTO_ESP */, 0x00, 0x00,
            10u,  0u, 0u, 1u, /* src: 10.0.0.1 */
            10u,  0u, 0u, 2u  /* dst: 10.0.0.2 */
        };
        uint16_t csum = ipv4_checksum(ip_hdr);
        ip_hdr[10] = (uint8_t)(csum >> 8u);
        ip_hdr[11] = (uint8_t)(csum & 0xFFu);

        uint8_t phdr[16] = {0};
        write_u32_le(phdr +  0u, 1700000000u + p);
        write_u32_le(phdr +  4u, p * 1000u);
        write_u32_le(phdr +  8u, (uint32_t)ip_total_len);
        write_u32_le(phdr + 12u, (uint32_t)ip_total_len);

        (void)fwrite(phdr, 1u, sizeof(phdr), fp);
        (void)fwrite(ip_hdr, 1u, sizeof(ip_hdr), fp);
        (void)fwrite(esp_buf, 1u, esp_len, fp);
    }
    fclose(fp);

    FILE *kf = fopen(keys_path, "w");
    if (kf == NULL) {
        fprintf(stderr, "[FAIL] Could not open %s for writing\n", keys_path);
        return 1;
    }
    fprintf(kf, "\"IPv4\",\"10.0.0.1\",\"10.0.0.2\",\"0x%08x\",\"CHACHA20-POLY1305 [RFC7634]\",\"0x", spi);
    for (size_t i = 0u; i < 32u; ++i) {
        fprintf(kf, "%02x", key[i]);
    }
    for (size_t i = 0u; i < 4u; ++i) {
        fprintf(kf, "%02x", salt[i]);
    }
    fprintf(kf, "\"\n");
    fclose(kf);

    printf("[PCAP] Generated %s (DLT_RAW = 101, 8 IPv4/ESP packets) and %s\n", pcap_path, keys_path);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "--benchmark") == 0) {
        if (run_benchmark() != 0) {
            return 1;
        }
        return run_throughput_benchmark();
    }
    if (argc >= 4 && strcmp(argv[1], "--pcap") == 0 && strcmp(argv[3], "--keys") == 0 && argc >= 5) {
        return generate_pcap(argv[2], argv[4]);
    }
    if (run_benchmark() != 0) {
        return 1;
    }
    return run_throughput_benchmark();
}
