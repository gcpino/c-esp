/**
 * @file esp_types.h
 * @brief Fixed-width C11 protocol constants, error codes, and lifecycle types for c-esp.
 *
 * Standards:
 *   - RFC 4303: IP Encapsulating Security Payload (ESP)
 *   - RFC 4301: Security Architecture for the Internet Protocol (Lifetimes)
 *   - RFC 7634: ChaCha20, Poly1305, and Their Use in the Internet Key Exchange Protocol (IKE) and IPsec
 *   - RFC 6479: IPsec Anti-Replay Algorithm without Bit Shifting
 */
#ifndef ESP_TYPES_H
#define ESP_TYPES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Wire size of the RFC 4303 + RFC 7634 ESP header: 4B SPI + 4B SeqLow + 8B IV. */
#define ESP_HDR_SIZE           16u

/** @brief Wire size of the RFC 7634 explicit Initialization Vector (IV). */
#define ESP_IV_SIZE             8u

/** @brief Wire size of the RFC 7634 Poly1305 Integrity Check Value (ICV). */
#define ESP_ICV_SIZE           16u

/** @brief Maximum supported ESP alignment padding length (constant-time scan window). */
#define ESP_MAX_PAD_SIZE       16u

/** @brief Maximum wire trailer + ICV overhead: 16B max pad + 1B PadLen + 1B NextHdr + 16B ICV. */
#define ESP_TRL_MAX_SIZE       34u

/** @brief Number of 64-bit blocks in the RFC 6479 1024-bit circular bitmap. */
#define ESP_REPLAY_BLOCKS      16u

/** @brief Guaranteed RFC 6479 anti-replay window span in packets ((16 - 1) * 64 = 960). */
#define ESP_REPLAY_WINDOW_SIZE 960u

/** @brief Number of inbound Security Association slots in the static rollover ring. */
#define ESP_SA_RING_SLOTS       4u

/** @brief Number of binary entries in the embedded flight-recorder ring buffer. */
#define ESP_TRACE_CAPACITY     32u

/** @brief Minimum valid RFC 4303 Security Parameters Index (0..255 reserved by IANA). */
#define ESP_MIN_VALID_SPI     256u

/**
 * @brief Return status codes for all c-esp operations.
 */
typedef enum {
    ESP_OK                   =  0, /**< Operation succeeded. */
    ESP_ERR_INVALID_ARG      = -1, /**< NULL pointer, invalid offset, or reserved SPI (< 256). */
    ESP_ERR_BUFFER_TOO_SMALL = -2, /**< Insufficient buffer capacity for header/trailer/ICV. */
    ESP_ERR_NO_SA            = -3, /**< No matching active or overlap SA for the SPI/direction. */
    ESP_ERR_SA_EXPIRED       = -4, /**< SA exceeded its hard byte, packet, or time lifetime. */
    ESP_ERR_REPLAY           = -5, /**< Packet sequence is 0, behind window, or duplicate. */
    ESP_ERR_AUTH_FAILED      = -6, /**< Poly1305 ICV tag verification failed. */
    ESP_ERR_BAD_PADDING      = -7, /**< RFC 4303 §2.4 monotonic padding verification failed. */
    ESP_ERR_SEQ_EXHAUSTED    = -8  /**< Outbound sequence counter reached ceiling. */
} esp_err_t;

/**
 * @brief Traffic direction for a Security Association.
 */
typedef enum {
    ESP_DIR_OUTBOUND = 0, /**< Outbound encapsulation SA (tx_sa). */
    ESP_DIR_INBOUND  = 1  /**< Inbound decapsulation SA (rx_sa_ring[4]). */
} esp_dir_t;

/**
 * @brief Deterministic lifecycle state machine states for a Security Association.
 */
typedef enum {
    ESP_SA_UNINITIALIZED = 0, /**< Slot is empty and zeroed. */
    ESP_SA_ACTIVE        = 1, /**< Primary SA for outbound/inbound traffic. */
    ESP_SA_REKEYING_SOFT = 2, /**< Soft lifetime crossed; rekey requested while still active. */
    ESP_SA_DEPR_OVERLAP  = 3, /**< Deprecated inbound SA accepting in-flight packets during overlap. */
    ESP_SA_EXPIRED_HARD  = 4  /**< Hard lifetime reached; keys zeroed and traffic rejected. */
} esp_sa_state_t;

/**
 * @brief Lifecycle and security telemetry events emitted to the caller and flight recorder.
 */
typedef enum {
    ESP_EVENT_NONE               = 0, /**< No lifecycle transition occurred. */
    ESP_EVENT_SA_INSTALLED       = 1, /**< New SA installed or promoted via rekey. */
    ESP_EVENT_SA_SOFT_EXPIRE     = 2, /**< SA crossed soft byte/packet/time threshold. */
    ESP_EVENT_SA_HARD_EXPIRE     = 3, /**< SA crossed hard byte/packet/time threshold; keys wiped. */
    ESP_EVENT_SA_OVERLAP_EXPIRED = 4, /**< Inbound overlap window elapsed; retiring SA wiped. */
    ESP_EVENT_ESN_WRAP           = 5, /**< 32-bit wire sequence counter wrapped into next ESN epoch. */
    ESP_EVENT_REPLAY_REJECT      = 6, /**< Inbound packet rejected by anti-replay precheck. */
    ESP_EVENT_AUTH_REJECT        = 7  /**< Inbound packet rejected due to invalid ICV or padding. */
} esp_event_t;

/**
 * @brief RFC 4301 §4.4.2.1 Security Association soft and hard lifetime thresholds.
 *        A threshold value of 0 indicates no limit for that dimension.
 */
typedef struct {
    uint64_t soft_bytes;   /**< Soft byte limit (0 = unlimited). */
    uint64_t hard_bytes;   /**< Hard byte limit (0 = unlimited). */
    uint64_t soft_packets; /**< Soft packet count limit (0 = unlimited). */
    uint64_t hard_packets; /**< Hard packet count limit (0 = unlimited). */
    uint64_t soft_time_ns; /**< Soft monotonic elapsed duration in nanoseconds (0 = unlimited). */
    uint64_t hard_time_ns; /**< Hard monotonic elapsed duration in nanoseconds (0 = unlimited). */
} esp_sa_lifetime_t;

#ifdef __cplusplus
}
#endif

#endif /* ESP_TYPES_H */
