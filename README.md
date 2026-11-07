# `c-esp` — Zero-Allocation Sans-IO IPsec ESP Data-Plane Engine in C11

[![CI Verification Gates](https://github.com/gcpino/c-esp/actions/workflows/ci.yml/badge.svg)](https://github.com/gcpino/c-esp/actions/workflows/ci.yml)
[![Language: C11](https://img.shields.io/badge/std-C11%20(freestanding)-b25d3b.svg)](#)
[![Heap Allocations: 0](https://img.shields.io/badge/malloc%2Ffree-0%20bytes-4f785e.svg)](#)
[![Standards: RFC 4303 / 7634 / 6479 / 8439](https://img.shields.io/badge/IETF-RFC%204303%20%7C%207634%20%7C%206479%20%7C%208439-48697a.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-6e6557.svg)](LICENSE)

`c-esp` is a standalone, zero-allocation, **Sans-IO IPsec Encapsulating Security Payload (ESP)** data-plane and Security Association (SA) lifecycle engine implemented in strict ISO C11 (`-std=c11 -Wall -Wextra -Werror -Wpedantic`).

It separates cryptographic packet framing, two-phase anti-replay protection, and deterministic SA rollover from operating system sockets, timers, and heap allocators, running identically on bare-metal/RTOS targets and high-throughput userspace network paths.

---

## Core Engineering Highlights

* **Zero Dynamic Memory Allocation (`1944 B` Total Context):** All runtime state—outbound SA, 4-slot inbound SA rollover ring, five 1024-bit anti-replay windows, and a 32-event binary flight recorder—lives inside a single caller-allocated `esp_context_t` (`sizeof(esp_context_t) == 1944` bytes, verified via `_Static_assert(sizeof(esp_context_t) <= 4096)`). Zero references to `malloc`, `calloc`, `realloc`, or `free` exist in `libcesp.a`.
* **In-Place Zero-Copy Wire Framing (RFC 4303 & RFC 7634):** Encapsulates and decapsulates packets directly inside caller-supplied buffers (`16 B` leading ESP header headroom + `<= 34 B` trailing trailer/ICV tailroom) using RFC 8439 / RFC 7634 **ChaCha20-Poly1305 AEAD**. Supports both Tunnel and Transport mode payloads (`next_hdr = 4 / 41 / 6 / 17`) and both 96-bit Extended Sequence Number (ESN) AAD and 64-bit standard AAD.
* **Two-Phase RFC 6479 1024-Bit Anti-Replay with 64-Bit ESN:**
  * **Phase 1 (Read-Only Precheck):** Reconstructs 64-bit Extended Sequence Numbers across 32-bit wire wrap-arounds using signed 32-bit modular offsets (`RFC 4303 Appendix A`) and checks a 16-word (`uint64_t bitmap[16]`) circular ring without mutating receiver state. Unauthenticated spoofed packets can never advance `highest_seq` or blind the receiver.
  * **Phase 2 (Post-AEAD Commit):** Advances 64-bit bitmap blocks in $O(1)$ time without multi-word bit shifting (`RFC 6479`) strictly after constant-time Poly1305 ICV verification succeeds.
* **$O(1)$ Make-Before-Break SA Rollover (`tx_sa` & `rx_sa_ring[4]`):** Enforces RFC 4301 soft and hard byte, packet, and time lifetimes. During rekeying, retiring inbound SAs transition to `ESP_SA_DEPR_OVERLAP` for a configurable overlap window while new SAs activate in `rx_sa_ring[4]` (`spi & 0x3u` fast path with 4-way associative collision fallback), preventing rollover packet drops. Expired SAs automatically erase keys via DSE-resistant `esp_secure_zero()`.
* **Constant-Time Verification (`dudect`):** Compiler-barrier-hardened `esp_ct_select_u32()`, `esp_ct_memeq()`, and fixed-window (`ESP_MAX_PAD_SIZE = 16`) monotonic padding scans prevent timing side-channels, verified empirically via Welch's two-sample $t$-test ($|t| \le 4.5$ over $10^5$ trials).

---

## Architecture & In-Place Packet Layout

```text
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ---
 |               Security Parameters Index (SPI)                 |  ^
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  | 16-Byte ESP Header
 |                      Sequence Number (Low 32b)                |  | (ESP_HDR_SIZE)
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
 |                    Initialization Vector (IV)                 |  |
 |                         (64 bits, RFC 7634)                   |  v
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ---
 |                    Payload Data (Variable)                    |  ^
 +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  | Encrypted Region
 |               |         Padding (0-15 bytes: 1, 2, ... N)     |  | (ChaCha20 Stream)
 +-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
 |                               |  Pad Length   | Next Header   |  v
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ---
 |                  Integrity Check Value - ICV                  |  ^ 16-Byte ICV
 |                    (128-bit Poly1305 Tag)                     |  v (ESP_ICV_SIZE)
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ---
```

### Static Memory Footprint Breakdown (`x86_64` / `ARM64`)

| Structure | Count | Size (Bytes) | Role |
| :--- | :---: | :---: | :--- |
| `esp_sa_t tx_sa` | `1` | `280 B` | Active outbound Security Association + RFC 4301 lifetime counters |
| `esp_sa_t rx_sa_ring[4]` | `4` | `1,120 B` | 4-slot inbound SA rollover ring + four 1024-bit RFC 6479 windows |
| `esp_trace_ring_t trace` | `1` | `528 B` | 32-entry $\times$ 16 B binary flight-recorder ring buffer |
| Metadata & Vtable Pointer | `1` | `16 B` | Pluggable AEAD vtable pointer + ESN configuration flags |
| **Total `esp_context_t`** | **`1`** | **`1,944 B`** | **Complete Sans-IO ESP Engine (`<= 4,096 B` static budget)** |

---

## Channel Physics Benchmark & Verification Results

`tests/sim_channel.c` subjects `c-esp` to a **Gilbert-Elliott two-state Markov burst-loss and Gamma-distributed delay/reordering simulator** across 5,000 packets with a live mid-stream SA rollover at packet 2,500:

```text
====================================================================================
 c-esp Channel Physics Benchmark: Gilbert-Elliott Burst Loss + Gamma Reordering
 Packets/Run: 5000 | Live SA Rekey at Pkt 2500 | Context Size: 1944 B (<= 4096 B)
====================================================================================
 Reorder Jitter | Legacy 64-Bit Win | Legacy 256-Bit Win | c-esp RFC 6479 (1024-Bit)
 (sigma pkts)   | False Replay Drop | False Replay Drop  | False Replay Drop
----------------+-------------------+--------------------+--------------------------
 sigma =   0.0  |   0.00% (   0)    |   0.00% (   0)     |   0.00% (   0)
 sigma =  32.0  |  13.64% ( 680)    |   0.00% (   0)     |   0.00% (   0)
 sigma = 128.0  |  68.52% (3422)    |  14.80% ( 739)     |   0.04% (   2)
 sigma = 384.0  |  88.64% (4426)    |  58.94% (2943)     |   6.45% ( 322)
====================================================================================
```

### Constant-Time Statistical Verification (`test_ct_dudect`)

```text
[DUDECT] Poly1305 tag memeq   : |t| = 0.42 (threshold <= 4.5, N = 100,000, cropped 95%)
[DUDECT] RFC 4303 pad window  : |t| = 0.08 (threshold <= 4.5, N = 100,000, cropped 95%)
[PASS] test_ct_dudect: Constant-time bounds verified (|t| <= 4.5).
```

---

## Build & Verification Gates

```bash
# 1. Build static library (build/libcesp.a) and examples
make all

# 2. Run RFC 8439, RFC 7634 Appendix A, RFC 6479 ESN wrap, and SA rollover unit tests
make test

# 3. Verify zero dynamic memory allocation or OS symbols in build/libcesp.a
make symbol-check

# 4. Run dudect constant-time timing analysis (|t| <= 4.5) and ASan/UBSan checks
make ct-check

# 5. Generate DLT_RAW IPv4/ESP PCAP capture + Wireshark keyfile and run channel benchmark
make pcap benchmark
```

---

## Repository Structure & Traceability

* `include/esp/` — Freestanding C11 public headers (`esp.h`, `esp_types.h`, `esp_crypto.h`, `esp_replay.h`, `esp_trace.h`).
* `src/` — Zero-dependency C11 implementation (`esp_crypto.c`, `esp_replay.c`, `esp_packet.c`, `esp_session.c`, `esp_trace.c`).
* `tests/` — RFC test vectors (`test_rfc_vectors.c`), ESN & anti-replay torture tests (`test_replay_esn.c`), SA lifecycle & rollover tests (`test_rekey_fsm.c`), `dudect` harness (`test_ct_dudect.c`), and channel simulator (`sim_channel.c`).
* `fuzz/` — `libFuzzer` + AddressSanitizer/UndefinedBehaviorSanitizer harness (`fuzz_esp_decrypt.c`).
* `examples/` — Freestanding memory-ring loopback (`baremetal_loopback.c`) and userspace UDP tunnel (`linux_udp_tun.c`).
* [`docs/TRACEABILITY.md`](docs/TRACEABILITY.md) — DO-178C-style requirements-to-test traceability matrix.
