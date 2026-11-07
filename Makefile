CC      ?= gcc
AR      ?= ar
NM      ?= nm
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Werror -Wpedantic -Wconversion -Wshadow -Wvla -fno-common -Iinclude

ifeq ($(OS),Windows_NT)
    export PATH := C:/Program Files/Git/usr/bin;$(PATH)
    SHELL := sh.exe
    EXE := .exe
    UDP_LIBS := -lws2_32
else
    EXE :=
    UDP_LIBS :=
endif

BUILD_DIR := build
LIB_A     := $(BUILD_DIR)/libcesp.a

SRCS      := $(sort $(wildcard src/*.c))
OBJS      := $(patsubst src/%.c,$(BUILD_DIR)/%.o,$(SRCS))

EXAMPLES :=
ifneq ($(wildcard examples/baremetal_loopback.c),)
    EXAMPLES += $(BUILD_DIR)/baremetal_loopback$(EXE)
endif
ifneq ($(wildcard examples/linux_udp_tun.c),)
    EXAMPLES += $(BUILD_DIR)/linux_udp_tun$(EXE)
endif

TESTS :=
ifneq ($(wildcard tests/test_rfc_vectors.c),)
    TESTS += $(BUILD_DIR)/test_rfc_vectors$(EXE)
endif
ifneq ($(wildcard tests/test_replay_esn.c),)
    TESTS += $(BUILD_DIR)/test_replay_esn$(EXE)
endif
ifneq ($(wildcard tests/test_rekey_fsm.c),)
    TESTS += $(BUILD_DIR)/test_rekey_fsm$(EXE)
endif
ifneq ($(wildcard tests/test_spd.c),)
    TESTS += $(BUILD_DIR)/test_spd$(EXE)
endif

.PHONY: all test symbol-check ct-check pcap benchmark fuzz clean

all: $(LIB_A) $(EXAMPLES)

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB_A): $(OBJS) | $(BUILD_DIR)
	$(AR) rcs $@ $(OBJS)

$(BUILD_DIR)/baremetal_loopback$(EXE): examples/baremetal_loopback.c $(LIB_A) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< $(LIB_A) -o $@

$(BUILD_DIR)/linux_udp_tun$(EXE): examples/linux_udp_tun.c $(LIB_A) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< $(LIB_A) $(UDP_LIBS) -o $@

$(BUILD_DIR)/test_%$(EXE): tests/test_%.c $(LIB_A) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< $(LIB_A) -lm -o $@

$(BUILD_DIR)/sim_channel$(EXE): tests/sim_channel.c $(LIB_A) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< $(LIB_A) -lm -o $@

test: $(TESTS)
	@for t in $(TESTS); do \
		echo "[TEST] Running $$t..."; \
		./$$t || exit 1; \
	done

symbol-check: $(LIB_A)
	@echo "[GATE] Checking $(LIB_A) for forbidden heap and OS symbols..."
	@if $(NM) -u $(LIB_A) | grep -E '(_?malloc|_?calloc|_?realloc|_?free|_?printf|_?fprintf|_?fopen|_?clock_gettime|_?socket|_?recv|_?send)'; then \
		echo "[FAIL] Forbidden dynamic allocation or OS symbol found in $(LIB_A)"; \
		exit 1; \
	else \
		echo "[PASS] Zero heap/OS symbols in $(LIB_A)"; \
	fi

ct-check: $(BUILD_DIR)/test_ct_dudect$(EXE)
	@echo "[GATE] Running dudect constant-time verification..."
	./$(BUILD_DIR)/test_ct_dudect$(EXE)
	@if $(CC) $(CFLAGS) -fsanitize=address,undefined -x c -E /dev/null >/dev/null 2>&1; then \
		echo "[GATE] Running unit tests with ASan + UBSan..."; \
		for src in $(wildcard tests/test_rfc_vectors.c tests/test_replay_esn.c tests/test_rekey_fsm.c tests/test_spd.c); do \
			bin="$(BUILD_DIR)/$$(basename $$src .c)_asan$(EXE)"; \
			if $(CC) $(CFLAGS) -fsanitize=address,undefined $$src $(SRCS) -o $$bin 2>/dev/null; then \
				./$$bin || exit 1; \
			fi; \
		done; \
	else \
		echo "[INFO] Host compiler does not provide libasan/libubsan runtime; skipping sanitizer binary link."; \
	fi

pcap: $(BUILD_DIR)/sim_channel$(EXE)
	./$(BUILD_DIR)/sim_channel$(EXE) --pcap esp_capture.pcap --keys esp_sa_keys
	@if command -v tshark >/dev/null 2>&1; then \
		echo "[GATE] Dissecting esp_capture.pcap with tshark..."; \
		tshark -r - < esp_capture.pcap; \
	else \
		echo "[INFO] tshark not in PATH; verified esp_capture.pcap and esp_sa_keys generation."; \
	fi

benchmark: $(BUILD_DIR)/sim_channel$(EXE)
	./$(BUILD_DIR)/sim_channel$(EXE) --benchmark

fuzz: fuzz/fuzz_esp_decrypt.c $(SRCS) | $(BUILD_DIR)
	clang -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=fuzzer,address,undefined -Iinclude fuzz/fuzz_esp_decrypt.c $(SRCS) -o $(BUILD_DIR)/fuzz_esp_decrypt$(EXE)

clean:
	rm -rf $(BUILD_DIR) esp_capture.pcap esp_sa_keys
