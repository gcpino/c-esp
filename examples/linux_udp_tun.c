/**
 * @file linux_udp_tun.c
 * @brief Userspace RFC 3948 UDP-encapsulated ESP & Linux /dev/net/tun data-plane driver example.
 *
 * Demonstrates:
 *   1. RFC 4301 outbound SPD 5-tuple classification (`esp_spd_classify_ipv4`) prior to ESP encapsulation.
 *   2. RFC 3948 UDP-encapsulated ESP framing (distinguishing NAT-Keepalive `0xFF`, IKEv2 Non-ESP Marker
 *      `0x00000000`, and ESP data frames).
 *   3. RFC 4301 §5.2 inbound post-decapsulation SPD verification on the inner IPv4 packet.
 *   4. Optional Linux `/dev/net/tun` (`IFF_TUN | IFF_NO_PI`) device opening (`--tun <ifname>`).
 */
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET sock_fd_t;
typedef int sock_len_arg_t;
#define CLOSE_SOCK(s) closesocket(s)
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int sock_fd_t;
typedef size_t sock_len_arg_t;
#define CLOSE_SOCK(s) close(s)
#if defined(__linux__)
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#endif
#endif

#include "esp/esp.h"

/**
 * @brief RFC 3948 §2 UDP-encapsulated packet type on port 4500.
 */
typedef enum {
    UDP_NATT_INVALID   = 0,
    UDP_NATT_KEEPALIVE = 1, /**< 1-byte 0xFF NAT-keepalive packet (RFC 3948 §2.3). */
    UDP_NATT_IKEV2     = 2, /**< Starts with 4-byte 0x00000000 Non-ESP Marker (RFC 3948 §2.2). */
    UDP_NATT_ESP       = 3  /**< Standard ESP frame (SPI >= 256). */
} udp_natt_type_t;

static udp_natt_type_t classify_rfc3948_udp(const uint8_t *buf, size_t len)
{
    if (buf == NULL || len == 0u) {
        return UDP_NATT_INVALID;
    }
    if (len == 1u && buf[0] == 0xFFu) {
        return UDP_NATT_KEEPALIVE;
    }
    if (len >= 4u && buf[0] == 0u && buf[1] == 0u && buf[2] == 0u && buf[3] == 0u) {
        return UDP_NATT_IKEV2;
    }
    if (len >= (ESP_HDR_SIZE + 2u + ESP_ICV_SIZE)) {
        return UDP_NATT_ESP;
    }
    return UDP_NATT_INVALID;
}

#if defined(__linux__)
static int open_linux_tun(const char *dev_name)
{
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        return -1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = (short)(IFF_TUN | IFF_NO_PI);
    if (dev_name != NULL) {
        strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1u);
    }
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}
#endif

int main(int argc, char **argv)
{
#if defined(__linux__)
    if (argc >= 3 && strcmp(argv[1], "--tun") == 0) {
        int tun_fd = open_linux_tun(argv[2]);
        if (tun_fd >= 0) {
            printf("[linux_udp_tun] Opened Linux TUN interface %s (fd=%d)\n", argv[2], tun_fd);
            close(tun_fd);
        }
    }
#else
    (void)argc;
    (void)argv;
#endif

#if defined(_WIN32)
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return 1;
    }
#endif

    static const uint8_t key[32] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };
    static const uint8_t salt[4] = {0xa0, 0xa1, 0xa2, 0xa3};

    esp_context_t tx_ctx;
    esp_context_t rx_ctx;
    (void)esp_context_init(&tx_ctx, 1u);
    (void)esp_context_init(&rx_ctx, 1u);

    esp_spd_t spd;
    esp_spd_init(&spd, ESP_SPD_DISCARD);
    esp_spd_rule_t rule = {
        .src_ip       = 0x0A000100u, /* 10.0.1.0/24 */
        .src_mask     = 0xFFFFFF00u,
        .dst_ip       = 0x0A000200u, /* 10.0.2.0/24 */
        .dst_mask     = 0xFFFFFF00u,
        .src_port_min = 0u,
        .src_port_max = 65535u,
        .dst_port_min = 0u,
        .dst_port_max = 65535u,
        .protocol     = 17u, /* UDP */
        .priority     = 10u,
        .spi          = 0x01020304u,
        .action       = ESP_SPD_PROTECT
    };
    (void)esp_spd_add_rule(&spd, &rule);

    esp_sa_lifetime_t lt = {
        .soft_bytes   = 65536ULL,
        .hard_bytes   = 131072ULL,
        .soft_packets = 1000ULL,
        .hard_packets = 2000ULL,
        .soft_time_ns = 30000000000ULL,
        .hard_time_ns = 60000000000ULL
    };

    (void)esp_sa_install(&tx_ctx, ESP_DIR_OUTBOUND, 0x01020304u, key, salt, &lt, 1000000ULL);
    (void)esp_sa_install(&rx_ctx, ESP_DIR_INBOUND,  0x01020304u, key, salt, &lt, 1000000ULL);

    sock_fd_t s_rx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sock_fd_t s_tx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = htons(0u);

    if (bind(s_rx, (struct sockaddr *)&addr, (socklen_t)sizeof(addr)) == 0) {
        socklen_t alen = (socklen_t)sizeof(addr);
        (void)getsockname(s_rx, (struct sockaddr *)&addr, &alen);

        /* Inner IPv4/UDP packet (10.0.1.10:5000 -> 10.0.2.20:8080) */
        uint8_t inner_ipv4[28] = {
            0x45, 0x00, 0x00, 0x1C, 0x00, 0x01, 0x40, 0x00,
            64u,  17u /* UDP */, 0x00, 0x00,
            10u,  0u, 1u, 10u,
            10u,  0u, 2u, 20u,
            0x13, 0x88, 0x1F, 0x90, 0x00, 0x08, 0x00, 0x00
        };

        uint32_t matched_spi = 0u;
        if (esp_spd_classify_ipv4(&spd, inner_ipv4, sizeof(inner_ipv4), &matched_spi) == ESP_SPD_PROTECT) {
            uint8_t pkt[256] = {0};
            memcpy(pkt + ESP_HDR_SIZE, inner_ipv4, sizeof(inner_ipv4));

            size_t flen = 0u;
            esp_event_t ev = ESP_EVENT_NONE;
            if (esp_encrypt_in_place(&tx_ctx, pkt, sizeof(pkt), ESP_HDR_SIZE,
                                     sizeof(inner_ipv4), 4u /* IPPROTO_IPIP */,
                                     2000000ULL, &flen, &ev) == ESP_OK) {
                (void)sendto(s_tx, (const char *)pkt, (sock_len_arg_t)flen, 0,
                             (const struct sockaddr *)&addr, (socklen_t)sizeof(addr));

                uint8_t rx_buf[256] = {0};
                int rlen = (int)recvfrom(s_rx, (char *)rx_buf, (sock_len_arg_t)sizeof(rx_buf), 0, NULL, NULL);
                if (rlen > 0 && classify_rfc3948_udp(rx_buf, (size_t)rlen) == UDP_NATT_ESP) {
                    size_t off = 0u;
                    size_t plen = 0u;
                    uint8_t nh = 0u;
                    if (esp_decrypt_in_place(&rx_ctx, rx_buf, (size_t)rlen, 3000000ULL,
                                             &off, &plen, &nh, &ev) == ESP_OK) {
                        uint32_t in_spi = 0u;
                        esp_spd_action_t in_act = esp_spd_classify_ipv4(&spd, rx_buf + off, plen, &in_spi);
                        uint64_t next_deadline = 0ULL;
                        (void)esp_context_poll(&rx_ctx, 3000000ULL, &next_deadline, &ev);
                        printf("[linux_udp_tun] RFC 3948 UDP-ESP + RFC 4301 SPD verified (%zu B inner IPv4, SPI=0x%08x, act=%d)\n",
                               plen, in_spi, (int)in_act);
                    }
                }
            }
        }
    }

    CLOSE_SOCK(s_tx);
    CLOSE_SOCK(s_rx);
    esp_context_wipe(&tx_ctx);
    esp_context_wipe(&rx_ctx);

#if defined(_WIN32)
    WSACleanup();
#endif
    return 0;
}
