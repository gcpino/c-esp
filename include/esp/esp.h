/**
 * @file esp.h
 * @brief Umbrella public header for the c-esp zero-allocation Sans-IO IPsec ESP engine.
 */
#ifndef ESP_H
#define ESP_H

#include "esp/esp_crypto.h"
#include "esp/esp_replay.h"
#include "esp/esp_trace.h"
#include "esp/esp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Security Association (SA) state structure for outbound or inbound ESP processing.
 */
typedef struct {
    uint8_t             key[32];           /**< 256-bit ChaCha20-Poly1305 AEAD key. */
    uint8_t             salt[4];           /**< 32-bit RFC 7634 AEAD salt. */
    uint32_t            spi;               /**< 32-bit Security Parameters Index (host order, >= 256). */
    uint64_t            tx_seq;            /**< Outbound 64-bit monotonic sequence counter. */
    esp_replay_window_t replay;            /**< Inbound RFC 6479 1024-bit anti-replay window. */
    esp_sa_lifetime_t   lifetime;          /**< Configured soft and hard byte/packet/time thresholds. */
    uint64_t            bytes_processed;   /**< Cumulative payload bytes processed under this SA. */
    uint64_t            packets_processed; /**< Cumulative packets processed under this SA. */
    uint64_t            installed_at_ns;   /**< Caller-supplied monotonic timestamp at SA installation. */
    uint64_t            overlap_until_ns;  /**< Expiration timestamp when in `ESP_SA_DEPR_OVERLAP`. */
    esp_sa_state_t      state;             /**< Current lifecycle state of this SA. */
    esp_dir_t           dir;               /**< Traffic direction (`ESP_DIR_OUTBOUND` or `ESP_DIR_INBOUND`). */
} esp_sa_t;

/**
 * @brief Complete caller-allocated Sans-IO ESP engine context (< 4 KB static footprint).
 */
typedef struct {
    esp_sa_t                   tx_sa;                          /**< Active outbound SA. */
    esp_sa_t                   rx_sa_ring[ESP_SA_RING_SLOTS];  /**< 4-slot inbound SA rollover ring. */
    const esp_crypto_vtable_t *crypto;                         /**< Active AEAD vtable. */
    esp_trace_ring_t           trace;                          /**< 528-byte binary flight recorder. */
    uint8_t                    enable_esn;                     /**< 1 for 64-bit ESN, 0 for 32-bit Seq. */
    uint8_t                    reserved[7];                    /**< Explicit alignment padding. */
} esp_context_t;

_Static_assert(sizeof(esp_context_t) <= 4096u, "esp_context_t exceeds 4KB budget");

/* --------------------------------------------------------------------------
 * Low-Level Stateless In-Place Packet Framing (Explicit IV / Test Vectors)
 * -------------------------------------------------------------------------- */

/**
 * @brief Encapsulate and authenticate a payload in place using an explicit 8-byte IV.
 *
 * Requires `payload_offset == ESP_HDR_SIZE` (16 bytes of leading headroom) and at least
 * `ESP_TRL_MAX_SIZE` (34 bytes) or `(pad_len + 2 + ESP_ICV_SIZE)` of trailing tailroom.
 */
esp_err_t esp_packet_seal_raw(const esp_crypto_vtable_t *crypto,
                              uint32_t spi, uint64_t seq64, uint8_t enable_esn,
                              const uint8_t key[32], const uint8_t salt[4],
                              const uint8_t iv[8], uint8_t *buf, size_t buf_cap,
                              size_t payload_offset, size_t payload_len,
                              uint8_t next_hdr, size_t *out_frame_len);

/**
 * @brief Authenticate, decrypt, and validate RFC 4303 monotonic padding in place.
 *
 * Performs Poly1305 verification before decrypting and uses a fixed-window constant-time
 * padding check over up to `ESP_MAX_PAD_SIZE` (16) bytes. If padding is invalid, the
 * plaintext region is zeroed via `esp_secure_zero()` and `ESP_ERR_BAD_PADDING` is returned.
 */
esp_err_t esp_packet_open_raw(const esp_crypto_vtable_t *crypto,
                              uint32_t expected_spi, uint64_t seq64, uint8_t enable_esn,
                              const uint8_t key[32], const uint8_t salt[4],
                              uint8_t *buf, size_t frame_len,
                              size_t *out_payload_offset, size_t *out_payload_len,
                              uint8_t *out_next_hdr);

/* --------------------------------------------------------------------------
 * Sans-IO Session Context & SA Lifecycle API
 * -------------------------------------------------------------------------- */

/**
 * @brief Initialize an `esp_context_t` instance with the default RFC 8439 crypto vtable.
 * @param ctx        Caller-allocated context structure.
 * @param enable_esn 1 to enable RFC 4303 Appendix A 64-bit ESN, 0 for standard 32-bit sequence numbers.
 */
esp_err_t esp_context_init(esp_context_t *ctx, uint8_t enable_esn);

/**
 * @brief Cryptographically wipe all keys, salts, and state in `ctx` via `esp_secure_zero()`.
 */
void esp_context_wipe(esp_context_t *ctx);

/**
 * @brief Override the AEAD vtable for hardware offload or custom crypto backends.
 */
esp_err_t esp_context_set_crypto(esp_context_t *ctx, const esp_crypto_vtable_t *vtable);

/**
 * @brief Install an initial outbound or inbound Security Association.
 * @param spi Must be >= 256 (0..255 reserved by RFC 4303 §2.1).
 */
esp_err_t esp_sa_install(esp_context_t *ctx, esp_dir_t dir, uint32_t spi,
                         const uint8_t key[32], const uint8_t salt[4],
                         const esp_sa_lifetime_t *lifetime, uint64_t now_ns);

/**
 * @brief Perform make-before-break SA rollover.
 *
 * For `ESP_DIR_INBOUND`, transitions currently active inbound SAs to `ESP_SA_DEPR_OVERLAP`
 * for `overlap_ns` nanoseconds while activating `new_spi` in an available `rx_sa_ring[4]` slot.
 * For `ESP_DIR_OUTBOUND`, securely wipes the old `tx_sa` and activates `new_spi`.
 */
esp_err_t esp_sa_rekey(esp_context_t *ctx, esp_dir_t dir, uint32_t new_spi,
                       const uint8_t new_key[32], const uint8_t new_salt[4],
                       const esp_sa_lifetime_t *lifetime,
                       uint64_t overlap_ns, uint64_t now_ns);

/**
 * @brief Encrypt and frame an outbound packet in place.
 */
esp_err_t esp_encrypt_in_place(esp_context_t *ctx, uint8_t *buf, size_t buf_cap,
                               size_t payload_offset, size_t payload_len,
                               uint8_t next_hdr, uint64_t now_ns,
                               size_t *out_frame_len, esp_event_t *out_event);

/**
 * @brief Authenticate, anti-replay check, and decrypt an inbound ESP frame in place.
 */
esp_err_t esp_decrypt_in_place(esp_context_t *ctx, uint8_t *buf, size_t frame_len,
                               uint64_t now_ns, size_t *out_payload_offset,
                               size_t *out_payload_len, uint8_t *out_next_hdr,
                               esp_event_t *out_event);

/**
 * @brief Advance time-based SA lifetimes and overlap windows using caller-injected monotonic time.
 */
esp_err_t esp_context_poll(esp_context_t *ctx, uint64_t now_ns,
                           uint64_t *out_next_deadline_ns, esp_event_t *out_event);

#ifdef __cplusplus
}
#endif

#endif /* ESP_H */
