# `c-esp` — Zero-Allocation Sans-IO IPsec ESP Data-Plane Engine in C11

[![CI Verification Gates](https://github.com/gcpino/c-esp/actions/workflows/ci.yml/badge.svg)](https://github.com/gcpino/c-esp/actions/workflows/ci.yml)
[![Release: v1.1.0](https://img.shields.io/badge/release-v1.1.0-c86446.svg)](https://github.com/gcpino/c-esp/releases)
[![Language: C11](https://img.shields.io/badge/std-C11%20(freestanding)-b25d3b.svg)](#)
[![Heap Allocations: 0](https://img.shields.io/badge/malloc%2Ffree-0%20bytes-4f785e.svg)](#)
[![Standards: RFC 4303 / 7634 / 4106 / 6479 / 4301 / 3948](https://img.shields.io/badge/IETF-RFC%204303%20%7C%207634%20%7C%204106%20%7C%206479%20%7C%204301-48697a.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-6e6557.svg)](LICENSE)

`c-esp` is a standalone, zero-allocation, **Sans-IO IPsec Encapsulating Security Payload (ESP)** data-plane, Security Association (SA) lifecycle, and **RFC 4301 Security Policy Database (SPD)** engine implemented in strict ISO C11 (`-std=c11 -Wall -Wextra -Werror -Wpedantic`).

It separates cryptographic packet framing, dual constant-time AEAD backends (**RFC 7634 ChaCha20-Poly1305** and **RFC 4106 AES-256-GCM**), two-phase anti-replay protection, and deterministic SA rollover from operating system sockets, timers, and heap allocators, running identically on bare-metal/RTOS targets and high-throughput userspace network paths.

---

## Core Engineering Highlights

* **Zero Dynamic Memory Allocation (`1944 B` Context + `516 B` SPD):** All runtime state—outbound SA, 4-slot inbound SA rollover ring, five 1024-bit anti-replay windows, and a 32-event binary flight recorder—lives inside a single caller-allocated `esp_context_t` (`sizeof(esp_context_t) == 1944` bytes, verified via `_Static_assert(sizeof(esp_context_t) <= 4096)`). Zero references to `malloc`, `calloc`, `realloc`, or `free` exist in `libcesp.a`.
* **Dual Pluggable Constant-Time AEAD Backends (RFC 7634 & RFC 4106):**
  * **RFC 7634 / RFC 8439 ChaCha20-Poly1305 (`esp_crypto_default_vtable()`):** 20-round ARX stream cipher + 5-limb radix-$2^{26}$ Poly1305 MAC achieving **6.81 Cycles-Per-Byte (`cpb`)** end-to-end ESP encapsulation + decapsulation at 1400 B MTU.
  * **RFC 4106 / NIST SP 800-38D AES-256-GCM (`esp_crypto_aes256_gcm_vtable()`):** Table-free constant-time AES-256 computing the FIPS 197 S-box algebraically via $x^{254} \in \text{GF}(2^8)$ and 128-bit GHASH via branchless bitwise multiplication in $\text{GF}(2^{128})$ modulo $1 + \alpha + \alpha^2 + \alpha^7 + \alpha^{128}$ (zero secret-indexed lookup tables, zero cache-timing leakage).
* **RFC 4301 §4.4.1 Security Policy Database (`esp_spd_t`):** Zero-allocation 16-rule priority-ordered 5-tuple selector classifier (`SrcIP/Mask`, `DstIP/Mask`, `SrcPort`, `DstPort`, `Protocol`) evaluating inner IPv4 packets into `ESP_SPD_ACTION_PROTECT` (with outbound/inbound SPI binding), `ESP_SPD_ACTION_BYPASS`, or default-deny `ESP_SPD_ACTION_DISCARD`, including non-initial IPv4 fragment handling.
* **Two-Phase RFC 6479 1024-Bit Anti-Replay with 64-Bit ESN:**
  * **Phase 1 (Read-Only Precheck):** Reconstructs 64-bit Extended Sequence Numbers across 32-bit wire wrap-arounds using signed 32-bit modular offsets (`RFC 4303 Appendix A`) and checks a 16-word (`uint64_t bitmap[16]`) circular ring without mutating receiver state. Unauthenticated spoofed packets can never advance `highest_seq` or blind the receiver.
  * **Phase 2 (Post-AEAD Commit):** Advances 64-bit bitmap blocks in $O(1)$ time without multi-word bit shifting (`RFC 6479`) strictly after constant-time ICV verification succeeds.
* **$O(1)$ Make-Before-Break SA Rollover (`tx_sa` & `rx_sa_ring[4]`):** Enforces RFC 4301 soft and hard byte, packet, and time lifetimes. During rekeying, retiring inbound SAs transition to `ESP_SA_DEPR_OVERLAP` for a configurable overlap window while new SAs activate in `rx_sa_ring[4]` (`spi & 0x3u` fast path with 4-way associative collision fallback), preventing rollover packet drops. Expired SAs automatically erase keys via DSE-resistant `esp_secure_zero()`.
* **Dual Constant-Time Verification (`dudect` + Valgrind `ctgrind`):** Compiler-barrier-hardened `esp_ct_select_u32()`, `esp_ct_memeq()`, fixed-window (`ESP_MAX_PAD_SIZE = 16`) monotonic padding scans, and both AEAD engines are verified statistically via Welch's two-sample $t$-test ($|t| \le 4.5$ over $10^5$ trials) and instruction-by-instruction under Valgrind Memcheck secret tainting (`VALGRIND_MAKE_MEM_UNDEFINED`).

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
 |                   (64 bits, RFC 7634 / RFC 4106)              |  v
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ---
 |                    Payload Data (Variable)                    |  ^
 +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  | Encrypted Region
 |               |         Padding (0-15 bytes: 1, 2, ... N)     |  | (ChaCha20 / AES-CTR)
 +-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
 |                               |  Pad Length   | Next Header   |  v
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ---
 |                  Integrity Check Value - ICV                  |  ^ 16-Byte ICV
 |                 (128-bit Poly1305 / GHASH Tag)                |  v (ESP_ICV_SIZE)
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
| **Optional `esp_spd_t`** | **`1`** | **`516 B`** | **16-Rule Priority-Ordered RFC 4301 SPD (`<= 1,024 B` static budget)** |

---

## Channel Physics & Cycles-Per-Byte (`cpb`) Benchmarks

`tests/sim_channel.c` subjects `c-esp` to a **Gilbert-Elliott two-state Markov burst-loss and Gamma-distributed delay/reordering simulator** across 5,000 packets with a live mid-stream SA rollover at packet 2,500, followed by an MTU throughput sweep measuring hardware CPU cycles per byte (`RDTSC` / `CNTVCT_EL0`):

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

====================================================================================
 c-esp End-to-End Throughput Sweep (Encrypt + Anti-Replay + Decrypt In-Place)
====================================================================================
 Payload Size   | RFC 7634 ChaCha20-Poly1305     | RFC 4106 AES-256-GCM (Table-Free)
 (Bytes)        | Cycles/Pkt      Cycles/Byte    | Cycles/Pkt      Cycles/Byte
----------------+--------------------------------+----------------------------------
    64 B        |     1661 cyc      25.95 cpb    |   243922 cyc    3811.29 cpb
   256 B        |     3210 cyc      12.54 cpb    |   578283 cyc    2258.92 cpb
   512 B        |     5268 cyc      10.29 cpb    |  1020266 cyc    1992.71 cpb
  1024 B        |     7845 cyc       7.66 cpb    |  1919449 cyc    1874.46 cpb
  1400 B        |     9531 cyc       6.81 cpb    |  2585077 cyc    1846.48 cpb
====================================================================================
```

### Constant-Time Statistical & Instruction-Taint Verification (`make ct-check`)

```text
[DUDECT] Poly1305 tag memeq   : |t| = 1.95 (threshold <= 4.5, N = 100,000, cropped 95%)
[DUDECT] RFC 4303 pad window  : |t| = 0.20 (threshold <= 4.5, N = 100,000, cropped 95%)
[DUDECT] AES-256-GCM S-box/GH : |t| = 0.39 (threshold <= 4.5, N = 40,000,  cropped 95%)
[PASS] test_ct_dudect: Constant-time bounds verified (|t| <= 4.5).
[CTGRIND] Valgrind header instrumentation active: YES (<valgrind/memcheck.h>)
[PASS] test_ct_valgrind: Zero secret-dependent branches or table lookups across ChaCha20-Poly1305 & AES-256-GCM.
```

---

## Build & Verification Gates

```bash
# 1. Build static library (build/libcesp.a) and examples
make all

# 2. Run RFC 8439, RFC 7634 App A, RFC 4106 AES-GCM, RFC 6479 ESN, SA rollover & RFC 4301 SPD tests
make test

# 3. Verify zero dynamic memory allocation or OS symbols in build/libcesp.a
make symbol-check

# 4. Run dudect timing analysis (|t| <= 4.5), Valgrind ctgrind taint check, and ASan/UBSan suite
make ct-check

# 5. Generate DLT_RAW IPv4/ESP PCAP capture + Wireshark keyfile and run cpb + channel benchmark
make pcap benchmark

# 6. Build and run Clang libFuzzer + ASan/UBSan harness
make fuzz && ./build/fuzz_esp_decrypt -max_total_time=10
```

---

## Repository Structure & Traceability

* `include/esp/` — Freestanding C11 public headers (`esp.h`, `esp_types.h`, `esp_crypto.h`, `esp_replay.h`, `esp_spd.h`, `esp_trace.h`).
* `src/` — Zero-dependency C11 implementation (`esp_crypto.c`, `esp_crypto_aes_gcm.c`, `esp_replay.c`, `esp_packet.c`, `esp_session.c`, `esp_spd.c`, `esp_trace.c`).
* `tests/` — RFC test vectors (`test_rfc_vectors.c`), ESN & anti-replay torture tests (`test_replay_esn.c`), SA lifecycle & rollover tests (`test_rekey_fsm.c`), RFC 4301 SPD selector tests (`test_spd.c`), `dudect` harness (`test_ct_dudect.c`), Valgrind `ctgrind` taint harness (`test_ct_valgrind.c`), and channel/throughput simulator (`sim_channel.c`).
* `fuzz/` — `libFuzzer` + AddressSanitizer/UndefinedBehaviorSanitizer harness (`fuzz_esp_decrypt.c`).
* `examples/` — Freestanding memory-ring loopback (`baremetal_loopback.c`) and RFC 3948 UDP-encapsulated ESP + Linux `/dev/net/tun` tunnel (`linux_udp_tun.c`).
* [`docs/TRACEABILITY.md`](docs/TRACEABILITY.md) — DO-178C-style requirements-to-test traceability matrix.
