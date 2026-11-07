/**
 * @file test_spd.c
 * @brief Unit tests for RFC 4301 §4.4.1 Security Policy Database (SPD) 5-tuple selector engine.
 */
#include <stdio.h>
#include <string.h>

#include "esp/esp.h"

#define ASSERT_TRUE(cond, msg)                                                      \
    do {                                                                            \
        if (!(cond)) {                                                              \
            fprintf(stderr, "[FAIL] %s:%d: %s\n", __FILE__, __LINE__, (msg));       \
            return 1;                                                               \
        }                                                                           \
    } while (0)

static int test_spd_priority_and_5tuple_matching(void)
{
    esp_spd_t spd;
    esp_spd_init(&spd, ESP_SPD_DISCARD);

    /* Rule A (priority 20): Protect all traffic between 10.1.0.0/16 and 10.2.0.0/16 under SPI 0x10000100 */
    esp_spd_rule_t r_subnet = {
        .src_ip       = 0x0A010000u,
        .src_mask     = 0xFFFF0000u,
        .dst_ip       = 0x0A020000u,
        .dst_mask     = 0xFFFF0000u,
        .src_port_min = 0u,
        .src_port_max = 65535u,
        .dst_port_min = 0u,
        .dst_port_max = 65535u,
        .protocol     = 0u, /* ANY */
        .priority     = 20u,
        .spi          = 0x10000100u,
        .action       = ESP_SPD_PROTECT
    };

    /* Rule B (priority 5): Bypass IKEv2 UDP port 500 between the same subnets */
    esp_spd_rule_t r_ike_bypass = {
        .src_ip       = 0x0A010000u,
        .src_mask     = 0xFFFF0000u,
        .dst_ip       = 0x0A020000u,
        .dst_mask     = 0xFFFF0000u,
        .src_port_min = 500u,
        .src_port_max = 500u,
        .dst_port_min = 500u,
        .dst_port_max = 500u,
        .protocol     = 17u, /* UDP */
        .priority     = 5u,
        .spi          = 0u,
        .action       = ESP_SPD_BYPASS
    };

    /* Rule C (priority 10): Discard Telnet (TCP port 23) */
    esp_spd_rule_t r_telnet_drop = {
        .src_ip       = 0x00000000u,
        .src_mask     = 0x00000000u,
        .dst_ip       = 0x00000000u,
        .dst_mask     = 0x00000000u,
        .src_port_min = 0u,
        .src_port_max = 65535u,
        .dst_port_min = 23u,
        .dst_port_max = 23u,
        .protocol     = 6u, /* TCP */
        .priority     = 10u,
        .spi          = 0u,
        .action       = ESP_SPD_DISCARD
    };

    /* Insert out of priority order (20, then 5, then 10) */
    ASSERT_TRUE(esp_spd_add_rule(&spd, &r_subnet) == ESP_OK, "add r_subnet");
    ASSERT_TRUE(esp_spd_add_rule(&spd, &r_ike_bypass) == ESP_OK, "add r_ike_bypass");
    ASSERT_TRUE(esp_spd_add_rule(&spd, &r_telnet_drop) == ESP_OK, "add r_telnet_drop");

    /* 1. IKEv2 UDP 500 must match Rule B (BYPASS) despite Rule A covering the subnet */
    esp_spd_tuple4_t ike_pkt = {
        .src_ip = 0x0A010005u, .dst_ip = 0x0A020009u,
        .src_port = 500u, .dst_port = 500u, .protocol = 17u
    };
    uint32_t spi = 0u;
    ASSERT_TRUE(esp_spd_lookup(&spd, &ike_pkt, &spi) == ESP_SPD_BYPASS && spi == 0u,
                "IKEv2 UDP/500 did not match higher-priority BYPASS rule");

    /* 2. TCP port 23 between subnets must match Rule C (DISCARD) */
    esp_spd_tuple4_t telnet_pkt = {
        .src_ip = 0x0A010005u, .dst_ip = 0x0A020009u,
        .src_port = 51234u, .dst_port = 23u, .protocol = 6u
    };
    ASSERT_TRUE(esp_spd_lookup(&spd, &telnet_pkt, &spi) == ESP_SPD_DISCARD,
                "Telnet TCP/23 did not match DISCARD rule");

    /* 3. HTTPS TCP port 443 between subnets must match Rule A (PROTECT, SPI = 0x10000100) */
    esp_spd_tuple4_t https_pkt = {
        .src_ip = 0x0A010005u, .dst_ip = 0x0A020009u,
        .src_port = 51234u, .dst_port = 443u, .protocol = 6u
    };
    ASSERT_TRUE(esp_spd_lookup(&spd, &https_pkt, &spi) == ESP_SPD_PROTECT && spi == 0x10000100u,
                "HTTPS TCP/443 did not match PROTECT rule");

    /* 4. Unmatched external subnet falls back to default_action (DISCARD) */
    esp_spd_tuple4_t ext_pkt = {
        .src_ip = 0xC0A80101u, .dst_ip = 0x0A020009u,
        .src_port = 51234u, .dst_port = 443u, .protocol = 6u
    };
    ASSERT_TRUE(esp_spd_lookup(&spd, &ext_pkt, &spi) == ESP_SPD_DISCARD,
                "unmatched packet did not fall back to default DISCARD");

    return 0;
}

static int test_ipv4_packet_classification_and_malformed_drop(void)
{
    esp_spd_t spd;
    esp_spd_init(&spd, ESP_SPD_DISCARD);

    esp_spd_rule_t r_udp = {
        .src_ip       = 0x0A000100u, /* 10.0.1.0/24 */
        .src_mask     = 0xFFFFFF00u,
        .dst_ip       = 0x0A000200u, /* 10.0.2.0/24 */
        .dst_mask     = 0xFFFFFF00u,
        .src_port_min = 1024u,
        .src_port_max = 65535u,
        .dst_port_min = 8080u,
        .dst_port_max = 8080u,
        .protocol     = 17u,
        .priority     = 10u,
        .spi          = 0x20000200u,
        .action       = ESP_SPD_PROTECT
    };
    ASSERT_TRUE(esp_spd_add_rule(&spd, &r_udp) == ESP_OK, "add r_udp");

    /* Construct a valid 28-byte IPv4 + UDP header (10.0.1.42:40000 -> 10.0.2.99:8080) */
    uint8_t ipv4_udp[28] = {
        0x45, 0x00, 0x00, 0x1C, 0x12, 0x34, 0x40, 0x00,
        0x40, 0x11 /* UDP */, 0x00, 0x00,
        10u, 0u, 1u, 42u, /* 10.0.1.42 */
        10u, 0u, 2u, 99u, /* 10.0.2.99 */
        0x9C, 0x40,       /* src_port = 40000 */
        0x1F, 0x90,       /* dst_port = 8080 */
        0x00, 0x08, 0x00, 0x00
    };

    uint32_t spi = 0u;
    ASSERT_TRUE(esp_spd_classify_ipv4(&spd, ipv4_udp, sizeof(ipv4_udp), &spi) == ESP_SPD_PROTECT,
                "valid IPv4/UDP packet did not classify as PROTECT");
    ASSERT_TRUE(spi == 0x20000200u, "classified SPI mismatch");

    /* Malformed version (IPv6 nibble 0x65) must be discarded */
    uint8_t bad_ver[28];
    memcpy(bad_ver, ipv4_udp, sizeof(ipv4_udp));
    bad_ver[0] = 0x65u;
    ASSERT_TRUE(esp_spd_classify_ipv4(&spd, bad_ver, sizeof(bad_ver), &spi) == ESP_SPD_DISCARD,
                "malformed IPv4 version was not discarded");

    /* Truncated packet (< 20B) must be discarded */
    ASSERT_TRUE(esp_spd_classify_ipv4(&spd, ipv4_udp, 14u, &spi) == ESP_SPD_DISCARD,
                "truncated IPv4 packet was not discarded");

    return 0;
}

int main(void)
{
    if (test_spd_priority_and_5tuple_matching() != 0) {
        return 1;
    }
    if (test_ipv4_packet_classification_and_malformed_drop() != 0) {
        return 1;
    }
    printf("[PASS] test_spd: RFC 4301 §4.4.1 Security Policy Database 5-tuple selector engine verified.\n");
    return 0;
}
