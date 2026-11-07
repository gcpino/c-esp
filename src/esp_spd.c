/**
 * @file esp_spd.c
 * @brief RFC 4301 §4.4.1 Zero-Allocation Security Policy Database (SPD) 5-Tuple Selector Engine.
 */
#include "esp/esp_spd.h"
#include "esp/esp_crypto.h"

static inline uint16_t load16_be(const uint8_t s[2])
{
    return (uint16_t)(((uint16_t)s[0] << 8u) | (uint16_t)s[1]);
}

static inline uint32_t load32_be(const uint8_t s[4])
{
    return ((uint32_t)s[0] << 24u) |
           ((uint32_t)s[1] << 16u) |
           ((uint32_t)s[2] << 8u)  |
           ((uint32_t)s[3]);
}

void esp_spd_init(esp_spd_t *spd, esp_spd_action_t default_action)
{
    if (spd == NULL) {
        return;
    }
    esp_secure_zero(spd, sizeof(*spd));
    spd->default_action = default_action;
}

esp_err_t esp_spd_add_rule(esp_spd_t *spd, const esp_spd_rule_t *rule)
{
    if (spd == NULL || rule == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (spd->count >= ESP_SPD_MAX_RULES) {
        return ESP_ERR_BUFFER_TOO_SMALL;
    }
    if (rule->src_port_min > rule->src_port_max ||
        rule->dst_port_min > rule->dst_port_max) {
        return ESP_ERR_INVALID_ARG;
    }
    if (rule->action == ESP_SPD_PROTECT && rule->spi < ESP_MIN_VALID_SPI) {
        return ESP_ERR_INVALID_ARG;
    }

    /* Insert while preserving ascending priority order */
    size_t insert_idx = spd->count;
    for (size_t i = 0u; i < spd->count; ++i) {
        if (rule->priority < spd->rules[i].priority) {
            insert_idx = i;
            break;
        }
    }

    for (size_t j = spd->count; j > insert_idx; --j) {
        spd->rules[j] = spd->rules[j - 1u];
    }

    spd->rules[insert_idx] = *rule;
    spd->count += 1u;
    return ESP_OK;
}

esp_spd_action_t esp_spd_lookup(const esp_spd_t *spd,
                                const esp_spd_tuple4_t *tuple,
                                uint32_t *out_spi)
{
    if (out_spi != NULL) {
        *out_spi = 0u;
    }
    if (spd == NULL || tuple == NULL) {
        return ESP_SPD_DISCARD;
    }

    for (size_t i = 0u; i < spd->count; ++i) {
        const esp_spd_rule_t *r = &spd->rules[i];

        if (((tuple->src_ip & r->src_mask) != (r->src_ip & r->src_mask)) ||
            ((tuple->dst_ip & r->dst_mask) != (r->dst_ip & r->dst_mask))) {
            continue;
        }
        if (r->protocol != 0u && r->protocol != tuple->protocol) {
            continue;
        }
        if (tuple->src_port < r->src_port_min || tuple->src_port > r->src_port_max) {
            continue;
        }
        if (tuple->dst_port < r->dst_port_min || tuple->dst_port > r->dst_port_max) {
            continue;
        }

        if (out_spi != NULL && r->action == ESP_SPD_PROTECT) {
            *out_spi = r->spi;
        }
        return r->action;
    }

    return spd->default_action;
}

esp_err_t esp_spd_extract_ipv4(const uint8_t *pkt, size_t pkt_len,
                               esp_spd_tuple4_t *out_tuple)
{
    if (pkt == NULL || out_tuple == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (pkt_len < 20u) {
        return ESP_ERR_BUFFER_TOO_SMALL;
    }

    uint8_t ver = (uint8_t)(pkt[0] >> 4u);
    uint8_t ihl = (uint8_t)(pkt[0] & 0x0Fu);
    if (ver != 4u || ihl < 5u) {
        return ESP_ERR_INVALID_ARG;
    }

    size_t hdr_len   = (size_t)ihl * 4u;
    size_t total_len = (size_t)load16_be(pkt + 2u);
    if (pkt_len < hdr_len || total_len < hdr_len || total_len > pkt_len) {
        return ESP_ERR_INVALID_ARG;
    }

    uint16_t frag_field = load16_be(pkt + 6u);
    uint16_t frag_off   = (uint16_t)(frag_field & 0x1FFFu);
    uint8_t  proto      = pkt[9];

    out_tuple->src_ip   = load32_be(pkt + 12u);
    out_tuple->dst_ip   = load32_be(pkt + 16u);
    out_tuple->protocol = proto;
    out_tuple->src_port = 0u;
    out_tuple->dst_port = 0u;

    /* Extract TCP/UDP ports only on non-fragmented or initial fragment (offset == 0) */
    if (frag_off == 0u && (proto == 6u || proto == 17u)) {
        if (total_len < (hdr_len + 4u)) {
            return ESP_ERR_INVALID_ARG;
        }
        out_tuple->src_port = load16_be(pkt + hdr_len + 0u);
        out_tuple->dst_port = load16_be(pkt + hdr_len + 2u);
    }

    return ESP_OK;
}

esp_spd_action_t esp_spd_classify_ipv4(const esp_spd_t *spd,
                                       const uint8_t *pkt, size_t pkt_len,
                                       uint32_t *out_spi)
{
    if (out_spi != NULL) {
        *out_spi = 0u;
    }
    esp_spd_tuple4_t tuple;
    if (esp_spd_extract_ipv4(pkt, pkt_len, &tuple) != ESP_OK) {
        return ESP_SPD_DISCARD;
    }
    return esp_spd_lookup(spd, &tuple, out_spi);
}
