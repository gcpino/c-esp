/**
 * @file esp_session.c
 * @brief Sans-IO IPsec ESP session context, O(1) SA rollover ring, and RFC 4301 lifetime engine.
 */
#include "esp/esp.h"

static inline uint32_t load32_be(const uint8_t s[4])
{
    return ((uint32_t)s[0] << 24u) |
           ((uint32_t)s[1] << 16u) |
           ((uint32_t)s[2] << 8u)  |
           ((uint32_t)s[3]);
}

static inline void store64_le(uint8_t d[8], uint64_t v)
{
    for (size_t i = 0u; i < 8u; ++i) {
        d[i] = (uint8_t)((v >> (i * 8u)) & 0xFFu);
    }
}

static void esp_sa_init_slot(esp_sa_t *sa, esp_dir_t dir, uint32_t spi,
                             const uint8_t key[32], const uint8_t salt[4],
                             const esp_sa_lifetime_t *lifetime, uint64_t now_ns)
{
    esp_secure_zero(sa, sizeof(*sa));
    for (size_t i = 0u; i < 32u; ++i) {
        sa->key[i] = key[i];
    }
    for (size_t i = 0u; i < 4u; ++i) {
        sa->salt[i] = salt[i];
    }
    sa->spi = spi;
    sa->tx_seq = 0ULL;
    esp_replay_init(&sa->replay);
    if (lifetime != NULL) {
        sa->lifetime = *lifetime;
    }
    sa->bytes_processed   = 0ULL;
    sa->packets_processed = 0ULL;
    sa->installed_at_ns   = now_ns;
    sa->overlap_until_ns  = 0ULL;
    sa->state             = ESP_SA_ACTIVE;
    sa->dir               = dir;
}

static void esp_sa_expire_hard(esp_sa_t *sa)
{
    esp_secure_zero(sa->key, sizeof(sa->key));
    esp_secure_zero(sa->salt, sizeof(sa->salt));
    sa->state = ESP_SA_EXPIRED_HARD;
}

static esp_err_t esp_sa_check_hard_limits(esp_sa_t *sa, size_t add_bytes,
                                          uint64_t now_ns, esp_event_t *out_ev)
{
    if (sa->state == ESP_SA_EXPIRED_HARD) {
        return ESP_ERR_SA_EXPIRED;
    }

    if (sa->state == ESP_SA_DEPR_OVERLAP &&
        sa->overlap_until_ns > 0ULL && now_ns >= sa->overlap_until_ns) {
        esp_sa_expire_hard(sa);
        if (out_ev != NULL) {
            *out_ev = ESP_EVENT_SA_OVERLAP_EXPIRED;
        }
        return ESP_ERR_SA_EXPIRED;
    }

    if (sa->lifetime.hard_time_ns > 0ULL && now_ns >= sa->installed_at_ns &&
        (now_ns - sa->installed_at_ns) >= sa->lifetime.hard_time_ns) {
        esp_sa_expire_hard(sa);
        if (out_ev != NULL) {
            *out_ev = ESP_EVENT_SA_HARD_EXPIRE;
        }
        return ESP_ERR_SA_EXPIRED;
    }

    if (sa->lifetime.hard_packets > 0ULL &&
        (sa->packets_processed + 1ULL) > sa->lifetime.hard_packets) {
        esp_sa_expire_hard(sa);
        if (out_ev != NULL) {
            *out_ev = ESP_EVENT_SA_HARD_EXPIRE;
        }
        return ESP_ERR_SA_EXPIRED;
    }

    if (sa->lifetime.hard_bytes > 0ULL &&
        (sa->bytes_processed + (uint64_t)add_bytes) > sa->lifetime.hard_bytes) {
        esp_sa_expire_hard(sa);
        if (out_ev != NULL) {
            *out_ev = ESP_EVENT_SA_HARD_EXPIRE;
        }
        return ESP_ERR_SA_EXPIRED;
    }

    return ESP_OK;
}

static esp_event_t esp_sa_check_soft_limits(esp_sa_t *sa, uint64_t now_ns)
{
    if (sa->state != ESP_SA_ACTIVE) {
        return ESP_EVENT_NONE;
    }

    int soft_hit = 0;
    if (sa->lifetime.soft_bytes > 0ULL &&
        sa->bytes_processed >= sa->lifetime.soft_bytes) {
        soft_hit = 1;
    }
    if (sa->lifetime.soft_packets > 0ULL &&
        sa->packets_processed >= sa->lifetime.soft_packets) {
        soft_hit = 1;
    }
    if (sa->lifetime.soft_time_ns > 0ULL && now_ns >= sa->installed_at_ns &&
        (now_ns - sa->installed_at_ns) >= sa->lifetime.soft_time_ns) {
        soft_hit = 1;
    }

    if (soft_hit) {
        sa->state = ESP_SA_REKEYING_SOFT;
        return ESP_EVENT_SA_SOFT_EXPIRE;
    }
    return ESP_EVENT_NONE;
}

static esp_sa_t *esp_lookup_inbound_sa(esp_context_t *ctx, uint32_t spi)
{
    /* Fast path: direct-mapped slot (spi & 0x3u) */
    size_t primary = (size_t)(spi & (ESP_SA_RING_SLOTS - 1u));
    if (ctx->rx_sa_ring[primary].state != ESP_SA_UNINITIALIZED &&
        ctx->rx_sa_ring[primary].spi == spi) {
        return &ctx->rx_sa_ring[primary];
    }

    /* 4-way unrolled fallback for colliding SPI low bits */
    for (size_t i = 0u; i < ESP_SA_RING_SLOTS; ++i) {
        if (ctx->rx_sa_ring[i].state != ESP_SA_UNINITIALIZED &&
            ctx->rx_sa_ring[i].spi == spi) {
            return &ctx->rx_sa_ring[i];
        }
    }
    return NULL;
}

static esp_sa_t *esp_alloc_inbound_slot(esp_context_t *ctx, uint32_t spi)
{
    size_t primary = (size_t)(spi & (ESP_SA_RING_SLOTS - 1u));
    if (ctx->rx_sa_ring[primary].state == ESP_SA_UNINITIALIZED ||
        ctx->rx_sa_ring[primary].state == ESP_SA_EXPIRED_HARD) {
        return &ctx->rx_sa_ring[primary];
    }

    for (size_t i = 0u; i < ESP_SA_RING_SLOTS; ++i) {
        if (ctx->rx_sa_ring[i].state == ESP_SA_UNINITIALIZED ||
            ctx->rx_sa_ring[i].state == ESP_SA_EXPIRED_HARD) {
            return &ctx->rx_sa_ring[i];
        }
    }
    return NULL;
}

esp_err_t esp_context_init(esp_context_t *ctx, uint8_t enable_esn)
{
    if (ctx == NULL || enable_esn > 1u) {
        return ESP_ERR_INVALID_ARG;
    }
    esp_secure_zero(ctx, sizeof(*ctx));
    ctx->crypto     = esp_crypto_default_vtable();
    ctx->enable_esn = enable_esn;
    esp_trace_init(&ctx->trace);
    return ESP_OK;
}

void esp_context_wipe(esp_context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    esp_secure_zero(ctx, sizeof(*ctx));
}

esp_err_t esp_context_set_crypto(esp_context_t *ctx, const esp_crypto_vtable_t *vtable)
{
    if (ctx == NULL || vtable == NULL ||
        vtable->aead_encrypt == NULL || vtable->aead_decrypt == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    ctx->crypto = vtable;
    return ESP_OK;
}

esp_err_t esp_sa_install(esp_context_t *ctx, esp_dir_t dir, uint32_t spi,
                         const uint8_t key[32], const uint8_t salt[4],
                         const esp_sa_lifetime_t *lifetime, uint64_t now_ns)
{
    if (ctx == NULL || key == NULL || salt == NULL || spi < ESP_MIN_VALID_SPI) {
        return ESP_ERR_INVALID_ARG;
    }

    if (dir == ESP_DIR_OUTBOUND) {
        esp_sa_init_slot(&ctx->tx_sa, ESP_DIR_OUTBOUND, spi, key, salt, lifetime, now_ns);
        esp_trace_record(&ctx->trace, now_ns, spi, 0u, ESP_EVENT_SA_INSTALLED, ESP_OK);
        return ESP_OK;
    } else if (dir == ESP_DIR_INBOUND) {
        /* Reject duplicate active/overlap SPI */
        for (size_t i = 0u; i < ESP_SA_RING_SLOTS; ++i) {
            esp_sa_state_t st = ctx->rx_sa_ring[i].state;
            if ((st == ESP_SA_ACTIVE || st == ESP_SA_REKEYING_SOFT || st == ESP_SA_DEPR_OVERLAP) &&
                ctx->rx_sa_ring[i].spi == spi) {
                return ESP_ERR_INVALID_ARG;
            }
        }
        esp_sa_t *slot = esp_alloc_inbound_slot(ctx, spi);
        if (slot == NULL) {
            return ESP_ERR_NO_SA;
        }
        esp_sa_init_slot(slot, ESP_DIR_INBOUND, spi, key, salt, lifetime, now_ns);
        esp_trace_record(&ctx->trace, now_ns, spi, 0u, ESP_EVENT_SA_INSTALLED, ESP_OK);
        return ESP_OK;
    }

    return ESP_ERR_INVALID_ARG;
}

esp_err_t esp_sa_rekey(esp_context_t *ctx, esp_dir_t dir, uint32_t new_spi,
                       const uint8_t new_key[32], const uint8_t new_salt[4],
                       const esp_sa_lifetime_t *lifetime,
                       uint64_t overlap_ns, uint64_t now_ns)
{
    if (ctx == NULL || new_key == NULL || new_salt == NULL || new_spi < ESP_MIN_VALID_SPI) {
        return ESP_ERR_INVALID_ARG;
    }

    if (dir == ESP_DIR_OUTBOUND) {
        esp_sa_init_slot(&ctx->tx_sa, ESP_DIR_OUTBOUND, new_spi, new_key, new_salt, lifetime, now_ns);
        esp_trace_record(&ctx->trace, now_ns, new_spi, 0u, ESP_EVENT_SA_INSTALLED, ESP_OK);
        return ESP_OK;
    } else if (dir == ESP_DIR_INBOUND) {
        for (size_t i = 0u; i < ESP_SA_RING_SLOTS; ++i) {
            esp_sa_state_t st = ctx->rx_sa_ring[i].state;
            if ((st == ESP_SA_ACTIVE || st == ESP_SA_REKEYING_SOFT || st == ESP_SA_DEPR_OVERLAP) &&
                ctx->rx_sa_ring[i].spi == new_spi) {
                return ESP_ERR_INVALID_ARG;
            }
        }

        /* If overlap_ns == 0, retire active SAs immediately to free their slots */
        if (overlap_ns == 0ULL) {
            for (size_t i = 0u; i < ESP_SA_RING_SLOTS; ++i) {
                if (ctx->rx_sa_ring[i].state == ESP_SA_ACTIVE ||
                    ctx->rx_sa_ring[i].state == ESP_SA_REKEYING_SOFT) {
                    esp_sa_expire_hard(&ctx->rx_sa_ring[i]);
                }
            }
        }

        esp_sa_t *slot = esp_alloc_inbound_slot(ctx, new_spi);
        if (slot == NULL) {
            return ESP_ERR_NO_SA;
        }

        /* Transition previously active inbound SAs to ESP_SA_DEPR_OVERLAP */
        if (overlap_ns > 0ULL) {
            for (size_t i = 0u; i < ESP_SA_RING_SLOTS; ++i) {
                if (ctx->rx_sa_ring[i].state == ESP_SA_ACTIVE ||
                    ctx->rx_sa_ring[i].state == ESP_SA_REKEYING_SOFT) {
                    ctx->rx_sa_ring[i].state = ESP_SA_DEPR_OVERLAP;
                    ctx->rx_sa_ring[i].overlap_until_ns = now_ns + overlap_ns;
                }
            }
        }

        esp_sa_init_slot(slot, ESP_DIR_INBOUND, new_spi, new_key, new_salt, lifetime, now_ns);
        esp_trace_record(&ctx->trace, now_ns, new_spi, 0u, ESP_EVENT_SA_INSTALLED, ESP_OK);
        return ESP_OK;
    }

    return ESP_ERR_INVALID_ARG;
}

esp_err_t esp_encrypt_in_place(esp_context_t *ctx, uint8_t *buf, size_t buf_cap,
                               size_t payload_offset, size_t payload_len,
                               uint8_t next_hdr, uint64_t now_ns,
                               size_t *out_frame_len, esp_event_t *out_event)
{
    if (out_event != NULL) {
        *out_event = ESP_EVENT_NONE;
    }
    if (ctx == NULL || buf == NULL || out_frame_len == NULL || payload_offset != ESP_HDR_SIZE) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_sa_t *sa = &ctx->tx_sa;
    if (sa->state == ESP_SA_UNINITIALIZED) {
        return ESP_ERR_NO_SA;
    }

    esp_event_t hard_ev = ESP_EVENT_NONE;
    esp_err_t lim_err = esp_sa_check_hard_limits(sa, payload_len, now_ns, &hard_ev);
    if (lim_err != ESP_OK) {
        if (hard_ev != ESP_EVENT_NONE) {
            esp_trace_record(&ctx->trace, now_ns, sa->spi, (uint32_t)sa->tx_seq, hard_ev, lim_err);
            if (out_event != NULL) {
                *out_event = hard_ev;
            }
        }
        return lim_err;
    }

    uint64_t max_seq = (ctx->enable_esn != 0u) ? UINT64_MAX : 0xFFFFFFFFULL;
    if (sa->tx_seq >= max_seq) {
        return ESP_ERR_SEQ_EXHAUSTED;
    }

    uint64_t prev_seq = sa->tx_seq;
    uint64_t next_seq = prev_seq + 1ULL;

    uint8_t iv[ESP_IV_SIZE];
    store64_le(iv, next_seq);

    esp_err_t err = esp_packet_seal_raw(ctx->crypto, sa->spi, next_seq, ctx->enable_esn,
                                        sa->key, sa->salt, iv, buf, buf_cap,
                                        payload_offset, payload_len, next_hdr, out_frame_len);
    if (err != ESP_OK) {
        return err;
    }

    sa->tx_seq             = next_seq;
    sa->packets_processed += 1ULL;
    sa->bytes_processed   += (uint64_t)payload_len;

    if (prev_seq > 0ULL && (next_seq >> 32u) > (prev_seq >> 32u)) {
        esp_trace_record(&ctx->trace, now_ns, sa->spi, (uint32_t)next_seq, ESP_EVENT_ESN_WRAP, ESP_OK);
        if (out_event != NULL) {
            *out_event = ESP_EVENT_ESN_WRAP;
        }
    }

    esp_event_t soft_ev = esp_sa_check_soft_limits(sa, now_ns);
    if (soft_ev != ESP_EVENT_NONE) {
        esp_trace_record(&ctx->trace, now_ns, sa->spi, (uint32_t)next_seq, soft_ev, ESP_OK);
        if (out_event != NULL) {
            *out_event = soft_ev;
        }
    }

    return ESP_OK;
}

esp_err_t esp_decrypt_in_place(esp_context_t *ctx, uint8_t *buf, size_t frame_len,
                               uint64_t now_ns, size_t *out_payload_offset,
                               size_t *out_payload_len, uint8_t *out_next_hdr,
                               esp_event_t *out_event)
{
    if (out_event != NULL) {
        *out_event = ESP_EVENT_NONE;
    }
    if (ctx == NULL || buf == NULL ||
        out_payload_offset == NULL || out_payload_len == NULL || out_next_hdr == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (frame_len < (ESP_HDR_SIZE + 2u + ESP_ICV_SIZE)) {
        return ESP_ERR_BUFFER_TOO_SMALL;
    }

    uint32_t pkt_spi     = load32_be(buf + 0u);
    uint32_t pkt_seq_low = load32_be(buf + 4u);

    esp_sa_t *sa = esp_lookup_inbound_sa(ctx, pkt_spi);
    if (sa == NULL) {
        return ESP_ERR_NO_SA;
    }

    /* Check time and packet hard limits before cryptographic processing */
    esp_event_t hard_ev = ESP_EVENT_NONE;
    esp_err_t lim_err = esp_sa_check_hard_limits(sa, 0u, now_ns, &hard_ev);
    if (lim_err != ESP_OK) {
        if (hard_ev != ESP_EVENT_NONE) {
            esp_trace_record(&ctx->trace, now_ns, pkt_spi, pkt_seq_low, hard_ev, lim_err);
            if (out_event != NULL) {
                *out_event = hard_ev;
            }
        }
        return lim_err;
    }

    /* Phase 1 Anti-Replay: Read-only 64-bit ESN reconstruction and bitmap precheck */
    uint64_t seq64 = 0ULL;
    esp_err_t rep_err = esp_replay_reconstruct_esn(&sa->replay, pkt_seq_low, ctx->enable_esn, &seq64);
    if (rep_err == ESP_OK) {
        rep_err = esp_replay_precheck(&sa->replay, seq64);
    }
    if (rep_err != ESP_OK) {
        esp_trace_record(&ctx->trace, now_ns, pkt_spi, pkt_seq_low, ESP_EVENT_REPLAY_REJECT, ESP_ERR_REPLAY);
        if (out_event != NULL) {
            *out_event = ESP_EVENT_REPLAY_REJECT;
        }
        return ESP_ERR_REPLAY;
    }

    /* Constant-Time AEAD Tag Verification, Decryption, and Fixed-Window Padding Check */
    esp_err_t open_err = esp_packet_open_raw(ctx->crypto, pkt_spi, seq64, ctx->enable_esn,
                                             sa->key, sa->salt, buf, frame_len,
                                             out_payload_offset, out_payload_len, out_next_hdr);
    if (open_err != ESP_OK) {
        esp_trace_record(&ctx->trace, now_ns, pkt_spi, pkt_seq_low, ESP_EVENT_AUTH_REJECT, open_err);
        if (out_event != NULL) {
            *out_event = ESP_EVENT_AUTH_REJECT;
        }
        return open_err;
    }

    /* Check hard byte lifetime against authenticated payload length before committing */
    if (sa->lifetime.hard_bytes > 0ULL &&
        (sa->bytes_processed + (uint64_t)(*out_payload_len)) > sa->lifetime.hard_bytes) {
        esp_secure_zero(buf + *out_payload_offset, *out_payload_len);
        esp_sa_expire_hard(sa);
        esp_trace_record(&ctx->trace, now_ns, pkt_spi, pkt_seq_low,
                         ESP_EVENT_SA_HARD_EXPIRE, ESP_ERR_SA_EXPIRED);
        if (out_event != NULL) {
            *out_event = ESP_EVENT_SA_HARD_EXPIRE;
        }
        return ESP_ERR_SA_EXPIRED;
    }

    /* Phase 2 Anti-Replay Commit */
    uint64_t prev_highest = sa->replay.highest_seq;
    uint8_t  was_init     = sa->replay.initialized;
    esp_replay_commit(&sa->replay, seq64);

    sa->packets_processed += 1ULL;
    sa->bytes_processed   += (uint64_t)(*out_payload_len);

    if (was_init != 0u && (seq64 >> 32u) > (prev_highest >> 32u)) {
        esp_trace_record(&ctx->trace, now_ns, pkt_spi, pkt_seq_low, ESP_EVENT_ESN_WRAP, ESP_OK);
        if (out_event != NULL) {
            *out_event = ESP_EVENT_ESN_WRAP;
        }
    }

    esp_event_t soft_ev = esp_sa_check_soft_limits(sa, now_ns);
    if (soft_ev != ESP_EVENT_NONE) {
        esp_trace_record(&ctx->trace, now_ns, pkt_spi, pkt_seq_low, soft_ev, ESP_OK);
        if (out_event != NULL) {
            *out_event = soft_ev;
        }
    }

    return ESP_OK;
}

static void esp_poll_single_sa(esp_context_t *ctx, esp_sa_t *sa, uint64_t now_ns,
                               uint64_t *min_deadline, esp_event_t *out_event)
{
    if (sa->state == ESP_SA_UNINITIALIZED || sa->state == ESP_SA_EXPIRED_HARD) {
        return;
    }

    if (sa->state == ESP_SA_DEPR_OVERLAP && sa->overlap_until_ns > 0ULL) {
        if (now_ns >= sa->overlap_until_ns) {
            esp_sa_expire_hard(sa);
            esp_trace_record(&ctx->trace, now_ns, sa->spi, 0u,
                             ESP_EVENT_SA_OVERLAP_EXPIRED, ESP_ERR_SA_EXPIRED);
            if (out_event != NULL) {
                *out_event = ESP_EVENT_SA_OVERLAP_EXPIRED;
            }
            return;
        } else if (*min_deadline == 0ULL || sa->overlap_until_ns < *min_deadline) {
            *min_deadline = sa->overlap_until_ns;
        }
    }

    if (sa->lifetime.hard_time_ns > 0ULL) {
        uint64_t hard_deadline = sa->installed_at_ns + sa->lifetime.hard_time_ns;
        if (now_ns >= hard_deadline) {
            esp_sa_expire_hard(sa);
            esp_trace_record(&ctx->trace, now_ns, sa->spi, 0u,
                             ESP_EVENT_SA_HARD_EXPIRE, ESP_ERR_SA_EXPIRED);
            if (out_event != NULL) {
                *out_event = ESP_EVENT_SA_HARD_EXPIRE;
            }
            return;
        } else if (*min_deadline == 0ULL || hard_deadline < *min_deadline) {
            *min_deadline = hard_deadline;
        }
    }

    if (sa->state == ESP_SA_ACTIVE && sa->lifetime.soft_time_ns > 0ULL) {
        uint64_t soft_deadline = sa->installed_at_ns + sa->lifetime.soft_time_ns;
        if (now_ns >= soft_deadline) {
            sa->state = ESP_SA_REKEYING_SOFT;
            esp_trace_record(&ctx->trace, now_ns, sa->spi, 0u,
                             ESP_EVENT_SA_SOFT_EXPIRE, ESP_OK);
            if (out_event != NULL && *out_event == ESP_EVENT_NONE) {
                *out_event = ESP_EVENT_SA_SOFT_EXPIRE;
            }
        } else if (*min_deadline == 0ULL || soft_deadline < *min_deadline) {
            *min_deadline = soft_deadline;
        }
    }
}

esp_err_t esp_context_poll(esp_context_t *ctx, uint64_t now_ns,
                           uint64_t *out_next_deadline_ns, esp_event_t *out_event)
{
    if (ctx == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (out_event != NULL) {
        *out_event = ESP_EVENT_NONE;
    }

    uint64_t min_deadline = 0ULL;
    esp_poll_single_sa(ctx, &ctx->tx_sa, now_ns, &min_deadline, out_event);
    for (size_t i = 0u; i < ESP_SA_RING_SLOTS; ++i) {
        esp_poll_single_sa(ctx, &ctx->rx_sa_ring[i], now_ns, &min_deadline, out_event);
    }

    if (out_next_deadline_ns != NULL) {
        *out_next_deadline_ns = min_deadline;
    }
    return ESP_OK;
}
