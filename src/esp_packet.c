/**
 * @file esp_packet.c
 * @brief RFC 4303 and RFC 7634 in-place ESP packet encapsulation and decapsulation.
 */
#include "esp/esp.h"

static inline uint32_t load32_be(const uint8_t s[4])
{
    return ((uint32_t)s[0] << 24u) |
           ((uint32_t)s[1] << 16u) |
           ((uint32_t)s[2] << 8u)  |
           ((uint32_t)s[3]);
}

static inline void store32_be(uint8_t d[4], uint32_t v)
{
    d[0] = (uint8_t)((v >> 24u) & 0xFFu);
    d[1] = (uint8_t)((v >> 16u) & 0xFFu);
    d[2] = (uint8_t)((v >> 8u) & 0xFFu);
    d[3] = (uint8_t)(v & 0xFFu);
}

static size_t esp_build_aad(uint32_t spi, uint64_t seq64, uint8_t enable_esn, uint8_t aad[12])
{
    uint32_t seq_low  = (uint32_t)(seq64 & 0xFFFFFFFFULL);
    uint32_t seq_high = (uint32_t)(seq64 >> 32u);

    store32_be(aad + 0u, spi);
    if (enable_esn != 0u) {
        /* RFC 4303 Appendix A2.2 & RFC 7634 §2.1: 96-bit ESN AAD = SPI (32b) || SeqHigh (32b) || SeqLow (32b) */
        store32_be(aad + 4u, seq_high);
        store32_be(aad + 8u, seq_low);
        return 12u;
    } else {
        /* Standard 64-bit AAD = SPI (32b) || SeqLow (32b) */
        store32_be(aad + 4u, seq_low);
        return 8u;
    }
}

esp_err_t esp_packet_seal_raw(const esp_crypto_vtable_t *crypto,
                              uint32_t spi, uint64_t seq64, uint8_t enable_esn,
                              const uint8_t key[32], const uint8_t salt[4],
                              const uint8_t iv[8], uint8_t *buf, size_t buf_cap,
                              size_t payload_offset, size_t payload_len,
                              uint8_t next_hdr, size_t *out_frame_len)
{
    if (crypto == NULL || crypto->aead_encrypt == NULL ||
        key == NULL || salt == NULL || iv == NULL ||
        buf == NULL || out_frame_len == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (spi < ESP_MIN_VALID_SPI || payload_offset != ESP_HDR_SIZE) {
        return ESP_ERR_INVALID_ARG;
    }
    if (seq64 == 0ULL || (enable_esn == 0u && seq64 > 0xFFFFFFFFULL)) {
        return ESP_ERR_INVALID_ARG;
    }

    /* RFC 7634 §2: Pad so (payload_len + pad_len + 2) is a multiple of 4 bytes */
    size_t rem     = (payload_len + 2u) & 3u;
    size_t pad_len = (4u - rem) & 3u;
    size_t pt_len  = payload_len + pad_len + 2u;

    if (payload_len > buf_cap || pt_len < payload_len ||
        (ESP_HDR_SIZE + pt_len + ESP_ICV_SIZE) > buf_cap) {
        return ESP_ERR_BUFFER_TOO_SMALL;
    }

    /* 1. Write 16-byte ESP Header: SPI (4B BE) || SeqLow (4B BE) || IV (8B) */
    store32_be(buf + 0u, spi);
    store32_be(buf + 4u, (uint32_t)(seq64 & 0xFFFFFFFFULL));
    for (size_t i = 0u; i < ESP_IV_SIZE; ++i) {
        buf[8u + i] = iv[i];
    }

    /* 2. Append monotonic padding (1..pad_len), PadLen, and NextHdr */
    uint8_t *pt = buf + ESP_HDR_SIZE;
    for (size_t i = 0u; i < pad_len; ++i) {
        pt[payload_len + i] = (uint8_t)(i + 1u);
    }
    pt[payload_len + pad_len]      = (uint8_t)pad_len;
    pt[payload_len + pad_len + 1u] = next_hdr;

    /* 3. Assemble 96-bit Nonce (Salt || IV) and 64-bit/96-bit AAD */
    uint8_t nonce[12];
    uint8_t aad[12];
    for (size_t i = 0u; i < 4u; ++i) {
        nonce[i] = salt[i];
    }
    for (size_t i = 0u; i < 8u; ++i) {
        nonce[4u + i] = iv[i];
    }
    size_t aad_len = esp_build_aad(spi, seq64, enable_esn, aad);

    /* 4. Encrypt payload + trailer in place and append 16-byte ICV tag */
    uint8_t *icv_ptr = pt + pt_len;
    esp_err_t err = crypto->aead_encrypt(key, nonce, aad, aad_len, pt, pt_len, icv_ptr);

    esp_secure_zero(nonce, sizeof(nonce));
    esp_secure_zero(aad, sizeof(aad));

    if (err != ESP_OK) {
        return err;
    }

    *out_frame_len = ESP_HDR_SIZE + pt_len + ESP_ICV_SIZE;
    return ESP_OK;
}

esp_err_t esp_packet_open_raw(const esp_crypto_vtable_t *crypto,
                              uint32_t expected_spi, uint64_t seq64, uint8_t enable_esn,
                              const uint8_t key[32], const uint8_t salt[4],
                              uint8_t *buf, size_t frame_len,
                              size_t *out_payload_offset, size_t *out_payload_len,
                              uint8_t *out_next_hdr)
{
    if (crypto == NULL || crypto->aead_decrypt == NULL ||
        key == NULL || salt == NULL || buf == NULL ||
        out_payload_offset == NULL || out_payload_len == NULL || out_next_hdr == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (expected_spi < ESP_MIN_VALID_SPI || seq64 == 0ULL ||
        (enable_esn == 0u && seq64 > 0xFFFFFFFFULL)) {
        return ESP_ERR_INVALID_ARG;
    }

    /* Minimum ESP frame: 16B header + 2B trailer + 16B ICV = 34 bytes */
    if (frame_len < (ESP_HDR_SIZE + 2u + ESP_ICV_SIZE)) {
        return ESP_ERR_BUFFER_TOO_SMALL;
    }

    uint32_t pkt_spi     = load32_be(buf + 0u);
    uint32_t pkt_seq_low = load32_be(buf + 4u);
    if (pkt_spi != expected_spi || pkt_seq_low != (uint32_t)(seq64 & 0xFFFFFFFFULL)) {
        return ESP_ERR_INVALID_ARG;
    }

    size_t ct_len = frame_len - ESP_HDR_SIZE - ESP_ICV_SIZE;
    uint8_t *pt   = buf + ESP_HDR_SIZE;
    const uint8_t *icv_ptr = pt + ct_len;

    uint8_t nonce[12];
    uint8_t aad[12];
    for (size_t i = 0u; i < 4u; ++i) {
        nonce[i] = salt[i];
    }
    for (size_t i = 0u; i < 8u; ++i) {
        nonce[4u + i] = buf[8u + i];
    }
    size_t aad_len = esp_build_aad(expected_spi, seq64, enable_esn, aad);

    esp_err_t err = crypto->aead_decrypt(key, nonce, aad, aad_len, pt, ct_len, icv_ptr);

    esp_secure_zero(nonce, sizeof(nonce));
    esp_secure_zero(aad, sizeof(aad));

    if (err != ESP_OK) {
        return ESP_ERR_AUTH_FAILED;
    }

    /* Fixed-window constant-time RFC 4303 §2.4 monotonic padding verification */
    uint32_t pad_len  = (uint32_t)pt[ct_len - 2u];
    uint8_t  next_hdr = pt[ct_len - 1u];

    size_t max_possible_pad = ct_len - 2u;
    size_t scan_window = (max_possible_pad < ESP_MAX_PAD_SIZE) ? max_possible_pad : ESP_MAX_PAD_SIZE;

    /* Set bad_mask non-zero if pad_len > scan_window */
    uint32_t bad_mask = (uint32_t)(((uint64_t)scan_window - (uint64_t)pad_len) >> 63u);

    for (size_t k = 1u; k <= scan_window; ++k) {
        /* in_pad = 1 when k <= pad_len, 0 when k > pad_len */
        uint32_t in_pad   = 1u ^ (uint32_t)(((uint64_t)pad_len - (uint64_t)k) >> 63u);
        uint32_t mask     = 0u - in_pad;
        uint32_t expected = (pad_len + 1u - (uint32_t)k) & 0xFFu;
        uint32_t actual   = (uint32_t)pt[ct_len - 2u - k];
        bad_mask |= esp_ct_select_u32(mask, actual ^ expected, 0u);
    }

    uint32_t zero_u32 = 0u;
    if (esp_ct_memeq(&bad_mask, &zero_u32, sizeof(uint32_t)) == 0) {
        esp_secure_zero(pt, ct_len);
        return ESP_ERR_BAD_PADDING;
    }

    *out_payload_offset = ESP_HDR_SIZE;
    *out_payload_len    = ct_len - 2u - (size_t)pad_len;
    *out_next_hdr       = next_hdr;
    return ESP_OK;
}
