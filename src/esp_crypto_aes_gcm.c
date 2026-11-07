/**
 * @file esp_crypto_aes_gcm.c
 * @brief RFC 4106 / NIST SP 800-38D AES-256-GCM AEAD backend in table-free, constant-time C11.
 *
 * Security Properties:
 *   - Table-free AES S-box via algebraic inversion (x^254) in GF(2^8) + FIPS 197 affine transform:
 *     zero secret-indexed memory lookups and zero cache-timing leakage.
 *   - Branchless 128-bit GHASH multiplication in GF(2^128) modulo x^128 + x^7 + x^2 + x + 1
 *     guarded by `esp_ct_select_u32()`.
 *   - Verify-then-decrypt: GHASH tag is verified via `esp_ct_memeq()` prior to AES-CTR decryption.
 */
#include "esp/esp_crypto.h"

/* --------------------------------------------------------------------------
 * Endianness Helpers
 * -------------------------------------------------------------------------- */

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

static inline uint64_t load64_be(const uint8_t s[8])
{
    return ((uint64_t)load32_be(s) << 32u) | (uint64_t)load32_be(s + 4u);
}

static inline void store64_be(uint8_t d[8], uint64_t v)
{
    store32_be(d, (uint32_t)(v >> 32u));
    store32_be(d + 4u, (uint32_t)(v & 0xFFFFFFFFULL));
}

/* --------------------------------------------------------------------------
 * Table-Free Constant-Time GF(2^8) Arithmetic & AES-256 (FIPS 197)
 * -------------------------------------------------------------------------- */

static inline uint8_t gf256_xtime(uint8_t x)
{
    uint32_t hi  = ((uint32_t)x >> 7u) & 1u;
    uint32_t red = esp_ct_select_u32(0u - hi, 0x1Bu, 0u);
    return (uint8_t)((((uint32_t)x << 1u) ^ red) & 0xFFu);
}

static inline uint8_t gf256_mul(uint8_t a, uint8_t b)
{
    uint32_t p     = 0u;
    uint8_t  cur_a = a;
    uint32_t cur_b = b;

    for (unsigned int i = 0u; i < 8u; ++i) {
        uint32_t bit = cur_b & 1u;
        p ^= esp_ct_select_u32(0u - bit, (uint32_t)cur_a, 0u);
        cur_a = gf256_xtime(cur_a);
        cur_b >>= 1u;
    }
    return (uint8_t)(p & 0xFFu);
}

/**
 * @brief Compute FIPS 197 AES S-box in constant time without lookup tables via x^254 in GF(2^8).
 */
static uint8_t aes_sbox_ct(uint8_t x)
{
    uint8_t x2   = gf256_mul(x, x);
    uint8_t x3   = gf256_mul(x2, x);
    uint8_t x6   = gf256_mul(x3, x3);
    uint8_t x12  = gf256_mul(x6, x6);
    uint8_t x14  = gf256_mul(x12, x2);
    uint8_t x15  = gf256_mul(x14, x);
    uint8_t x30  = gf256_mul(x15, x15);
    uint8_t x60  = gf256_mul(x30, x30);
    uint8_t x120 = gf256_mul(x60, x60);
    uint8_t x240 = gf256_mul(x120, x120);
    uint8_t inv  = gf256_mul(x240, x14);

    uint8_t s = inv;
    s ^= (uint8_t)((inv << 1u) | (inv >> 7u));
    s ^= (uint8_t)((inv << 2u) | (inv >> 6u));
    s ^= (uint8_t)((inv << 3u) | (inv >> 5u));
    s ^= (uint8_t)((inv << 4u) | (inv >> 4u));
    return (uint8_t)(s ^ 0x63u);
}

static void aes256_expand_key(const uint8_t key[32], uint8_t rk[240])
{
    for (size_t i = 0u; i < 32u; ++i) {
        rk[i] = key[i];
    }

    uint8_t rcon = 0x01u;
    uint8_t temp[4];

    for (size_t i = 8u; i < 60u; ++i) {
        size_t prev = (i - 1u) * 4u;
        temp[0] = rk[prev + 0u];
        temp[1] = rk[prev + 1u];
        temp[2] = rk[prev + 2u];
        temp[3] = rk[prev + 3u];

        if ((i & 7u) == 0u) {
            uint8_t t = temp[0];
            temp[0] = (uint8_t)(aes_sbox_ct(temp[1]) ^ rcon);
            temp[1] = aes_sbox_ct(temp[2]);
            temp[2] = aes_sbox_ct(temp[3]);
            temp[3] = aes_sbox_ct(t);
            rcon = gf256_xtime(rcon);
        } else if ((i & 7u) == 4u) {
            temp[0] = aes_sbox_ct(temp[0]);
            temp[1] = aes_sbox_ct(temp[1]);
            temp[2] = aes_sbox_ct(temp[2]);
            temp[3] = aes_sbox_ct(temp[3]);
        }

        size_t base = i * 4u;
        size_t back = (i - 8u) * 4u;
        rk[base + 0u] = (uint8_t)(rk[back + 0u] ^ temp[0]);
        rk[base + 1u] = (uint8_t)(rk[back + 1u] ^ temp[1]);
        rk[base + 2u] = (uint8_t)(rk[back + 2u] ^ temp[2]);
        rk[base + 3u] = (uint8_t)(rk[back + 3u] ^ temp[3]);
    }

    esp_secure_zero(temp, sizeof(temp));
}

static void aes256_encrypt_block(const uint8_t rk[240], const uint8_t in[16], uint8_t out[16])
{
    uint8_t s[16];
    for (size_t i = 0u; i < 16u; ++i) {
        s[i] = (uint8_t)(in[i] ^ rk[i]);
    }

    for (size_t r = 1u; r <= 14u; ++r) {
        /* SubBytes */
        for (size_t i = 0u; i < 16u; ++i) {
            s[i] = aes_sbox_ct(s[i]);
        }

        /* ShiftRows */
        uint8_t t;
        t = s[1];  s[1]  = s[5];  s[5]  = s[9];  s[9]  = s[13]; s[13] = t;
        t = s[2];  s[2]  = s[10]; s[10] = t;     t     = s[6];  s[6]  = s[14]; s[14] = t;
        t = s[15]; s[15] = s[11]; s[11] = s[7];  s[7]  = s[3];  s[3]  = t;

        /* MixColumns (omitted on final round 14) */
        if (r < 14u) {
            for (size_t c = 0u; c < 16u; c += 4u) {
                uint8_t a0 = s[c + 0u];
                uint8_t a1 = s[c + 1u];
                uint8_t a2 = s[c + 2u];
                uint8_t a3 = s[c + 3u];
                uint8_t xr = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);

                s[c + 0u] ^= (uint8_t)(xr ^ gf256_xtime((uint8_t)(a0 ^ a1)));
                s[c + 1u] ^= (uint8_t)(xr ^ gf256_xtime((uint8_t)(a1 ^ a2)));
                s[c + 2u] ^= (uint8_t)(xr ^ gf256_xtime((uint8_t)(a2 ^ a3)));
                s[c + 3u] ^= (uint8_t)(xr ^ gf256_xtime((uint8_t)(a3 ^ a0)));
            }
        }

        /* AddRoundKey */
        const uint8_t *rkey = rk + (r * 16u);
        for (size_t i = 0u; i < 16u; ++i) {
            s[i] ^= rkey[i];
        }
    }

    for (size_t i = 0u; i < 16u; ++i) {
        out[i] = s[i];
    }
    esp_secure_zero(s, sizeof(s));
}

/* --------------------------------------------------------------------------
 * Constant-Time GF(2^128) GHASH & AES-256-CTR (NIST SP 800-38D)
 * -------------------------------------------------------------------------- */

static inline uint64_t ct_select_u64(uint32_t mask, uint64_t a, uint64_t b)
{
    uint32_t lo = esp_ct_select_u32(mask, (uint32_t)(a & 0xFFFFFFFFULL), (uint32_t)(b & 0xFFFFFFFFULL));
    uint32_t hi = esp_ct_select_u32(mask, (uint32_t)(a >> 32u), (uint32_t)(b >> 32u));
    return ((uint64_t)hi << 32u) | (uint64_t)lo;
}

static void ghash_mul_block(uint8_t y[16], const uint8_t h[16])
{
    uint64_t x_hi = load64_be(y);
    uint64_t x_lo = load64_be(y + 8u);
    uint64_t v_hi = load64_be(h);
    uint64_t v_lo = load64_be(h + 8u);
    uint64_t z_hi = 0ULL;
    uint64_t z_lo = 0ULL;

    for (unsigned int i = 0u; i < 64u; ++i) {
        uint32_t bit  = (uint32_t)((x_hi >> (63u - i)) & 1ULL);
        uint32_t mask = 0u - bit;
        z_hi ^= ct_select_u64(mask, v_hi, 0ULL);
        z_lo ^= ct_select_u64(mask, v_lo, 0ULL);

        uint32_t lsb = (uint32_t)(v_lo & 1ULL);
        v_lo = (v_lo >> 1u) | (v_hi << 63u);
        v_hi = (v_hi >> 1u) ^ ((uint64_t)esp_ct_select_u32(0u - lsb, 0xE1000000u, 0u) << 32u);
    }

    for (unsigned int i = 0u; i < 64u; ++i) {
        uint32_t bit  = (uint32_t)((x_lo >> (63u - i)) & 1ULL);
        uint32_t mask = 0u - bit;
        z_hi ^= ct_select_u64(mask, v_hi, 0ULL);
        z_lo ^= ct_select_u64(mask, v_lo, 0ULL);

        uint32_t lsb = (uint32_t)(v_lo & 1ULL);
        v_lo = (v_lo >> 1u) | (v_hi << 63u);
        v_hi = (v_hi >> 1u) ^ ((uint64_t)esp_ct_select_u32(0u - lsb, 0xE1000000u, 0u) << 32u);
    }

    store64_be(y, z_hi);
    store64_be(y + 8u, z_lo);
}

static void ghash_update_padded(uint8_t y[16], const uint8_t h[16],
                                const uint8_t *data, size_t len)
{
    size_t offset = 0u;
    while (offset + 16u <= len) {
        for (size_t i = 0u; i < 16u; ++i) {
            y[i] ^= data[offset + i];
        }
        ghash_mul_block(y, h);
        offset += 16u;
    }

    size_t rem = len - offset;
    if (rem > 0u) {
        for (size_t i = 0u; i < rem; ++i) {
            y[i] ^= data[offset + i];
        }
        ghash_mul_block(y, h);
    }
}

static void aes256_ctr_xor(const uint8_t rk[240], const uint8_t nonce[12],
                           uint32_t initial_counter, uint8_t *buf, size_t len)
{
    uint8_t cb[16];
    uint8_t ks[16];

    for (size_t i = 0u; i < 12u; ++i) {
        cb[i] = nonce[i];
    }

    uint32_t ctr = initial_counter;
    size_t offset = 0u;
    while (offset < len) {
        size_t chunk = len - offset;
        if (chunk > 16u) {
            chunk = 16u;
        }
        store32_be(cb + 12u, ctr);
        aes256_encrypt_block(rk, cb, ks);
        for (size_t i = 0u; i < chunk; ++i) {
            buf[offset + i] ^= ks[i];
        }
        offset += chunk;
        ctr += 1u;
    }

    esp_secure_zero(cb, sizeof(cb));
    esp_secure_zero(ks, sizeof(ks));
}

static void aes256_gcm_compute_tag(const uint8_t rk[240], const uint8_t nonce[12],
                                   const uint8_t *aad, size_t aad_len,
                                   const uint8_t *ct, size_t ct_len,
                                   uint8_t out_tag[16])
{
    uint8_t h[16]     = {0};
    uint8_t y[16]     = {0};
    uint8_t j0[16]    = {0};
    uint8_t ej0[16]   = {0};
    uint8_t len_b[16] = {0};

    /* H = AES_K(0^128) */
    aes256_encrypt_block(rk, h, h);

    if (aad != NULL && aad_len > 0u) {
        ghash_update_padded(y, h, aad, aad_len);
    }
    if (ct != NULL && ct_len > 0u) {
        ghash_update_padded(y, h, ct, ct_len);
    }

    /* Length block in bits: [len(A)64_BE || len(C)64_BE] */
    store64_be(len_b + 0u, (uint64_t)aad_len * 8ULL);
    store64_be(len_b + 8u, (uint64_t)ct_len * 8ULL);
    for (size_t i = 0u; i < 16u; ++i) {
        y[i] ^= len_b[i];
    }
    ghash_mul_block(y, h);

    /* J0 = nonce[0..11] || 0x00000001 */
    for (size_t i = 0u; i < 12u; ++i) {
        j0[i] = nonce[i];
    }
    store32_be(j0 + 12u, 1u);
    aes256_encrypt_block(rk, j0, ej0);

    for (size_t i = 0u; i < 16u; ++i) {
        out_tag[i] = (uint8_t)(y[i] ^ ej0[i]);
    }

    esp_secure_zero(h, sizeof(h));
    esp_secure_zero(y, sizeof(y));
    esp_secure_zero(j0, sizeof(j0));
    esp_secure_zero(ej0, sizeof(ej0));
}

esp_err_t esp_aes256_gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                                 const uint8_t *aad, size_t aad_len,
                                 uint8_t *buf, size_t len, uint8_t tag[16])
{
    if (key == NULL || nonce == NULL || tag == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if ((len > 0u && buf == NULL) || (aad_len > 0u && aad == NULL)) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t rk[240];
    aes256_expand_key(key, rk);

    if (len > 0u) {
        aes256_ctr_xor(rk, nonce, 2u, buf, len);
    }
    aes256_gcm_compute_tag(rk, nonce, aad, aad_len, buf, len, tag);

    esp_secure_zero(rk, sizeof(rk));
    return ESP_OK;
}

esp_err_t esp_aes256_gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                                 const uint8_t *aad, size_t aad_len,
                                 uint8_t *buf, size_t len, const uint8_t tag[16])
{
    if (key == NULL || nonce == NULL || tag == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if ((len > 0u && buf == NULL) || (aad_len > 0u && aad == NULL)) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t rk[240];
    uint8_t computed_tag[16];
    aes256_expand_key(key, rk);

    aes256_gcm_compute_tag(rk, nonce, aad, aad_len, buf, len, computed_tag);
    int eq = esp_ct_memeq(computed_tag, tag, 16u);
    esp_secure_zero(computed_tag, sizeof(computed_tag));

    if (!eq) {
        esp_secure_zero(rk, sizeof(rk));
        return ESP_ERR_AUTH_FAILED;
    }

    if (len > 0u) {
        aes256_ctr_xor(rk, nonce, 2u, buf, len);
    }

    esp_secure_zero(rk, sizeof(rk));
    return ESP_OK;
}

static const esp_crypto_vtable_t k_aes256_gcm_vtable = {
    .aead_encrypt = esp_aes256_gcm_encrypt,
    .aead_decrypt = esp_aes256_gcm_decrypt
};

const esp_crypto_vtable_t *esp_crypto_aes256_gcm_vtable(void)
{
    return &k_aes256_gcm_vtable;
}
