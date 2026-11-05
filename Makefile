# Makefile for dkgen
#
# Builds src/main.c -> bin/dkgen, linking against OpenSSL (libcrypto).
# Requires OpenSSL 3.x (EVP_KDF + Argon2id provider).

CC      ?= cc
BIN_DIR := bin
SRC_DIR := src
TARGET  := $(BIN_DIR)/dkgen
SRC     := $(SRC_DIR)/main.c

# OpenSSL 3.x is required for EVP_KDF_fetch("ARGON2ID").
OPENSSL_PKG := libcrypto
OPENSSL_CFLAGS := $(shell pkg-config --cflags $(OPENSSL_PKG) 2>/dev/null)
OPENSSL_LIBS   := $(shell pkg-config --libs   $(OPENSSL_PKG) 2>/dev/null)

# Fallback if pkg-config is unavailable or libcrypto.pc is missing.
ifeq ($(strip $(OPENSSL_LIBS)),)
OPENSSL_CFLAGS :=
OPENSSL_LIBS   := -lcrypto
endif

CPPFLAGS += $(OPENSSL_CFLAGS)
CFLAGS   ?= -O2
CFLAGS   += -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wconversion \
            -Wformat=2 -Wstrict-prototypes -Wmissing-prototypes
LDLIBS   += $(OPENSSL_LIBS)

# --- Test Variables ---
TEST_SCRIPT := test_generator.py

.PHONY: all clean distclean run test test-asan

all: $(TARGET)

$(TARGET): $(SRC) | $(BIN_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS) $(LDLIBS)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

run: $(TARGET)
	./$(TARGET)

# --- Test Execution Pipelines ---

# 1. Standard regression tests against your normal build binary
test: $(TARGET)
	@echo "==> Running functional regression test suite..."
	python3 $(TEST_SCRIPT)

# 2. Automated compiler runtime instrumentation to flag hidden memory bugs or leaks
test-asan: clean | $(BIN_DIR)
	@echo "==> Compiling temporary instrumented binary with ASan/UBSan..."
	$(CC) $(CPPFLAGS) $(CFLAGS) -fsanitize=address,undefined -g -o $(TARGET) $(SRC) $(LDFLAGS) $(LDLIBS)
	@echo "==> Executing tests under live sanitizer inspection..."
	python3 $(TEST_SCRIPT)
	@echo "==> Diagnostics clean. Restoring production binary..."
	@$(MAKE) clean
	@$(MAKE) all

clean:
	rm -f $(TARGET)

distclean: clean
	rmdir $(BIN_DIR) 2>/dev/null || true
