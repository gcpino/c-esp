/**
 * @file esp_spd.h
 * @brief RFC 4301 §4.4.1 Zero-Allocation Security Policy Database (SPD) 5-Tuple Selector Engine.
 */
#ifndef ESP_SPD_H
#define ESP_SPD_H

#include "esp/esp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Maximum number of static selector rules per `esp_spd_t` table. */
#define ESP_SPD_MAX_RULES 16u

/**
 * @brief RFC 4301 §4.4.1 Security Policy Database disposition actions.
 */
typedef enum {
    ESP_SPD_DISCARD = 0, /**< Drop packet immediately (do not transmit or deliver). */
    ESP_SPD_BYPASS  = 1, /**< Allow packet in cleartext without ESP processing. */
    ESP_SPD_PROTECT = 2  /**< Encapsulate/verify packet under the bound Security Association SPI. */
} esp_spd_action_t;

/**
 * @brief Extracted IPv4 5-tuple (addresses and ports in host byte order).
 */
typedef struct {
    uint32_t src_ip;   /**< Source IPv4 address (host order, e.g. 0x0A000101 for 10.0.1.1). */
    uint32_t dst_ip;   /**< Destination IPv4 address (host order). */
    uint16_t src_port; /**< Source L4 port (host order; 0 for ICMP or non-initial fragments). */
    uint16_t dst_port; /**< Destination L4 port (host order; 0 for ICMP or non-initial fragments). */
    uint8_t  protocol; /**< IPv4 protocol number (6 = TCP, 17 = UDP, 1 = ICMP, etc.). */
} esp_spd_tuple4_t;

/**
 * @brief RFC 4301 traffic selector rule entry.
 */
typedef struct {
    uint32_t         src_ip;       /**< Source IPv4 prefix (host byte order). */
    uint32_t         src_mask;     /**< Source IPv4 subnet mask (0x00000000 = ANY). */
    uint32_t         dst_ip;       /**< Destination IPv4 prefix (host byte order). */
    uint32_t         dst_mask;     /**< Destination IPv4 subnet mask (0x00000000 = ANY). */
    uint16_t         src_port_min; /**< Minimum source port (inclusive, 0 = ANY). */
    uint16_t         src_port_max; /**< Maximum source port (inclusive, 65535 = ANY). */
    uint16_t         dst_port_min; /**< Minimum destination port (inclusive, 0 = ANY). */
    uint16_t         dst_port_max; /**< Maximum destination port (inclusive, 65535 = ANY). */
    uint8_t          protocol;     /**< IP protocol selector (0 = ANY, 6 = TCP, 17 = UDP, 1 = ICMP). */
    uint8_t          reserved;     /**< Alignment byte. */
    uint16_t         priority;     /**< Rule evaluation priority (lower value = higher priority). */
    uint32_t         spi;          /**< Bound ESP SPI (>= 256) when action == ESP_SPD_PROTECT. */
    esp_spd_action_t action;       /**< Policy action (DISCARD, BYPASS, or PROTECT). */
} esp_spd_rule_t;

/**
 * @brief Caller-allocated static Security Policy Database table.
 */
typedef struct {
    esp_spd_rule_t   rules[ESP_SPD_MAX_RULES]; /**< Priority-ordered selector rules. */
    size_t           count;                    /**< Number of active rules (<= 16). */
    esp_spd_action_t default_action;           /**< Fallback action when no rule matches. */
} esp_spd_t;

/**
 * @brief Initialize a static Security Policy Database table.
 */
void esp_spd_init(esp_spd_t *spd, esp_spd_action_t default_action);

/**
 * @brief Insert a traffic selector rule into `spd`, maintaining ascending `priority` order.
 */
esp_err_t esp_spd_add_rule(esp_spd_t *spd, const esp_spd_rule_t *rule);

/**
 * @brief Evaluate `tuple` against priority-ordered rules in `spd`.
 * @param out_spi Optional output pointer receiving the bound SPI when `ESP_SPD_PROTECT` is returned.
 */
esp_spd_action_t esp_spd_lookup(const esp_spd_t *spd,
                                const esp_spd_tuple4_t *tuple,
                                uint32_t *out_spi);

/**
 * @brief Safely parse an inner IPv4 packet buffer and extract its 5-tuple.
 */
esp_err_t esp_spd_extract_ipv4(const uint8_t *pkt, size_t pkt_len,
                               esp_spd_tuple4_t *out_tuple);

/**
 * @brief Parse an inner IPv4 packet and return its RFC 4301 SPD policy action in one step.
 *        Malformed IPv4 packets always return `ESP_SPD_DISCARD`.
 */
esp_spd_action_t esp_spd_classify_ipv4(const esp_spd_t *spd,
                                       const uint8_t *pkt, size_t pkt_len,
                                       uint32_t *out_spi);

#ifdef __cplusplus
}
#endif

#endif /* ESP_SPD_H */
