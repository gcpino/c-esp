/**
 * @file linux_udp_tun.c
 * @brief Userspace UDP socket encapsulation/decapsulation example driving c-esp.
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
#endif

#include "esp/esp.h"

int main(void)
{
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

        uint8_t pkt[256] = {0};
        const char payload[] = "UDP_ENCAPSULATED_ESP_DATAGRAM";
        memcpy(pkt + ESP_HDR_SIZE, payload, sizeof(payload));

        size_t flen = 0u;
        esp_event_t ev = ESP_EVENT_NONE;
        if (esp_encrypt_in_place(&tx_ctx, pkt, sizeof(pkt), ESP_HDR_SIZE,
                                 sizeof(payload), 4u, 2000000ULL, &flen, &ev) == ESP_OK) {
            (void)sendto(s_tx, (const char *)pkt, (sock_len_arg_t)flen, 0,
                         (const struct sockaddr *)&addr, (socklen_t)sizeof(addr));

            uint8_t rx_buf[256] = {0};
            int rlen = (int)recvfrom(s_rx, (char *)rx_buf, (sock_len_arg_t)sizeof(rx_buf), 0, NULL, NULL);
            if (rlen > 0) {
                size_t off = 0u;
                size_t plen = 0u;
                uint8_t nh = 0u;
                if (esp_decrypt_in_place(&rx_ctx, rx_buf, (size_t)rlen, 3000000ULL,
                                         &off, &plen, &nh, &ev) == ESP_OK) {
                    uint64_t next_deadline = 0ULL;
                    (void)esp_context_poll(&rx_ctx, 3000000ULL, &next_deadline, &ev);
                    printf("[linux_udp_tun] Decrypted %zu B over localhost UDP: \"%s\"\n",
                           plen, (const char *)(rx_buf + off));
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
