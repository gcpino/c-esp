# DO-178C-Style Requirements Traceability Matrix (`c-esp`)

This document maps normative requirements from IETF IPsec and AEAD specifications (**RFC 4303**, **RFC 7634**, **RFC 6479**, **RFC 8439**, and **RFC 4301**) and structural safety invariants to their C11 implementation modules (`src/*.c`, `include/esp/*.h`) and verification test procedures (`tests/*.c`).

---

## 1. Normative RFC Requirements Traceability

| Req ID | Standard & Section | Normative Requirement Summary | Implementation Module & Function | Verification Test Case |
| :--- | :--- | :--- | :--- | :--- |
| **REQ-ESP-001** | RFC 4303 §2.1 | SPI values `0..255` are reserved by IANA and must not be assigned to active SAs. | `src/esp_session.c`: `esp_sa_install()`, `esp_sa_rekey()`; `src/esp_packet.c`: `esp_packet_seal_raw()` | `tests/test_rfc_vectors.c`: `test_session_roundtrip_and_padding_fault()` |
| **REQ-ESP-002** | RFC 4303 §2.2, §3.3.3 | Outbound sequence number is initialized to `0` at SA establishment and incremented to `1` prior to first packet transmission; sequence `0` is invalid on the wire. | `src/esp_session.c`: `esp_sa_init_slot()`, `esp_encrypt_in_place()`; `src/esp_replay.c`: `esp_replay_reconstruct_esn()`, `esp_replay_precheck()` | `tests/test_replay_esn.c`: `test_first_packet_and_zero_rejection()` |
| **REQ-ESP-003** | RFC 4303 §2.2.1, Appendix A | Extended Sequence Numbers (64-bit ESN) transmit only the low 32 bits (`SeqLow`) on the wire while maintaining a 64-bit counter across both peers. | `src/esp_replay.c`: `esp_replay_reconstruct_esn()`; `src/esp_packet.c`: `esp_packet_seal_raw()` | `tests/test_replay_esn.c`: `test_esn_wrap_and_underflow_rejection()` |
| **REQ-ESP-004** | RFC 4303 §2.4 & RFC 7634 §2 | Plaintext plus `Padding` (`1, 2, ..., PadLen`), `Pad Length` (1B), and `Next Header` (1B) must align to a 4-octet boundary; receiver must verify monotonic padding bytes. | `src/esp_packet.c`: `esp_packet_seal_raw()`, `esp_packet_open_raw()` | `tests/test_rfc_vectors.c`: `test_rfc7634_appendix_a_esp_vector()`, `test_session_roundtrip_and_padding_fault()` |
| **REQ-ESP-005** | RFC 4303 §3.3.3 | Outbound sequence counter must not wrap; if `tx_seq` reaches ceiling (`2^32 - 1` for 32-bit or `2^64 - 1` for ESN), transmission must abort with `ESP_ERR_SEQ_EXHAUSTED`. | `src/esp_session.c`: `esp_encrypt_in_place()` | `tests/test_rfc_vectors.c`: `test_session_roundtrip_and_padding_fault()` |
| **REQ-ESP-006** | RFC 4303 §3.4.3, §3.4.4 | Anti-replay window state (`highest_seq` and bitmap) must only be updated after Integrity Check Value (ICV) verification succeeds. | `src/esp_replay.c`: `esp_replay_precheck()`, `esp_replay_commit()`; `src/esp_session.c`: `esp_decrypt_in_place()` | `tests/test_replay_esn.c`: `test_spoofed_high_sequence_immutability()` |
| **REQ-AEAD-001** | RFC 7634 §2 | ChaCha20-Poly1305 KEYMAT is 36 octets (256-bit key + 32-bit salt); 96-bit nonce is `Salt (32b) || IV (64b)`; explicit wire IV is 8 octets; ICV is 16 octets. | `src/esp_packet.c`: `esp_packet_seal_raw()`, `esp_packet_open_raw()` | `tests/test_rfc_vectors.c`: `test_rfc7634_appendix_a_esp_vector()` |
| **REQ-AEAD-002** | RFC 7634 §2.1 & RFC 4303 App A2.2 | AAD is 8 octets (`SPI || SeqLow`) when ESN is disabled, and 12 octets (`SPI || SeqHigh || SeqLow`) when ESN is enabled. | `src/esp_packet.c`: `esp_build_aad()` | `tests/test_rfc_vectors.c`: `test_rfc7634_appendix_a_esp_vector()`, `test_session_roundtrip_and_padding_fault()` |
| **REQ-AEAD-003** | RFC 8439 §2.4, §2.5, §2.8 | ChaCha20 uses block counter `0` to derive the 256-bit Poly1305 one-time key and block counter `1` for payload encryption; Poly1305 authenticates padded AAD, padded ciphertext, and 64-bit LE lengths. | `src/esp_crypto.c`: `chacha20_block()`, `poly1305_init()`, `poly1305_block()`, `esp_chacha20_poly1305_encrypt()`, `esp_chacha20_poly1305_decrypt()` | `tests/test_rfc_vectors.c`: `test_rfc8439_section_2_8_2()` |
| **REQ-REP-001** | RFC 6479 §3 | Block-indexed circular bitmap (`16 x 64-bit` words = 1024 bits, safe window span `W = 960` packets) advances by zeroing newly entered 64-bit words without bit-shifting the entire window. | `src/esp_replay.c`: `esp_replay_precheck()`, `esp_replay_commit()` | `tests/test_replay_esn.c`: `test_esn_wrap_and_underflow_rejection()`; `tests/sim_channel.c`: `run_benchmark()` |
| **REQ-SA-001** | RFC 4301 §4.4.2.1 | Enforce soft and hard byte, packet, and time lifetimes; emit soft-expiry notification at soft threshold and reject packets + wipe keys at hard threshold. | `src/esp_session.c`: `esp_sa_check_hard_limits()`, `esp_sa_check_soft_limits()`, `esp_context_poll()` | `tests/test_rekey_fsm.c`: `test_soft_and_hard_lifetimes_and_key_wipe()` |
| **REQ-SA-002** | RFC 4301 §4.4.1 | Support make-before-break SA rollover across concurrent inbound SAs (`rx_sa_ring[4]`) with `spi & 0x3u` fast lookup and 4-way associative collision fallback. | `src/esp_session.c`: `esp_sa_rekey()`, `esp_lookup_inbound_sa()`, `esp_alloc_inbound_slot()` | `tests/test_rekey_fsm.c`: `test_make_before_break_rollover_and_colliding_spi()` |

---

## 2. Structural, Memory-Safety & Constant-Time Invariants

| Req ID | Category | Invariant Specification | Implementation Artifact | Verification Gate |
| :--- | :--- | :--- | :--- | :--- |
| **INV-MEM-001** | Zero Dynamic Allocation | Compiled library (`libcesp.a`) must contain zero references to `malloc`, `calloc`, `realloc`, `free`, or OS I/O syscalls. | `src/*.c`, `include/esp/*.h` | `make symbol-check` (`nm -u build/libcesp.a`) |
| **INV-MEM-002** | Static Memory Budget | `sizeof(esp_context_t) <= 4096` bytes (`1944` bytes actual) and `sizeof(esp_trace_ring_t) == 528` bytes. | `include/esp/esp.h`, `include/esp/esp_trace.h` (`_Static_assert`) | Compile-time `_Static_assert` in `make all` |
| **INV-SEC-001** | Constant-Time Tag & Padding Check | Tag comparison (`esp_ct_memeq`) and fixed-window (`ESP_MAX_PAD_SIZE = 16`) padding scan must exhibit Welch's $\|t\| \le 4.5$ over $10^5$ trials. | `src/esp_crypto.c`: `esp_ct_select_u32()`, `esp_ct_memeq()`; `src/esp_packet.c`: `esp_packet_open_raw()` | `make ct-check` (`tests/test_ct_dudect.c`) |
| **INV-SEC-002** | Cryptographic Zeroization | Retired, expired, or wiped keys and failed-padding plaintext buffers must be erased through a DSE-resistant barrier (`esp_secure_zero`). | `src/esp_crypto.c`: `esp_secure_zero()`; `src/esp_session.c`: `esp_sa_expire_hard()` | `tests/test_rekey_fsm.c`: `test_soft_and_hard_lifetimes_and_key_wipe()` |
