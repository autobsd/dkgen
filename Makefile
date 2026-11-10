# Makefile for dkgen and libdkgen static library
#
# Builds:
#   src/dkgen.c -> lib/libdkgen.a (Static Engine Library)
#   src/main.c   -> bin/dkgen (CLI wrapper linked against libdkgen)
#
# Requires OpenSSL 3.x (EVP_KDF + Argon2id provider).

CC      ?= cc
BIN_DIR := bin
LIB_DIR := lib
SRC_DIR := src

TARGET  := $(BIN_DIR)/dkgen
LIB_A   := $(LIB_DIR)/libdkgen.a

SRC_LIB := $(SRC_DIR)/dkgen.c
SRC_BIN := $(SRC_DIR)/main.c
OBJ_LIB := $(SRC_DIR)/dkgen.o

# OpenSSL 3.x configuration
OPENSSL_PKG := libcrypto
OPENSSL_CFLAGS := $(shell pkg-config --cflags $(OPENSSL_PKG) 2>/dev/null)
OPENSSL_LIBS   := $(shell pkg-config --libs   $(OPENSSL_PKG) 2>/dev/null)

# Fallback if pkg-config is unavailable
ifeq ($(strip $(OPENSSL_LIBS)),)
OPENSSL_CFLAGS :=
OPENSSL_LIBS   := -lcrypto
endif

CPPFLAGS += $(OPENSSL_CFLAGS) -Iinclude -I$(SRC_DIR)
CFLAGS   ?= -O2
CFLAGS   += -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wconversion \
            -Wformat=2 -Wstrict-prototypes -Wmissing-prototypes
LDLIBS   += -L$(LIB_DIR) -ldkgen $(OPENSSL_LIBS)

# --- Test Variables ---
TEST_SCRIPT := test_generator.py

.PHONY: all build clean distclean run test test-asan

all: build

build: $(TARGET)

# 1. Compile the Library Object
$(OBJ_LIB): $(SRC_LIB)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# 2. Package the Static Archive
$(LIB_A): $(OBJ_LIB) | $(LIB_DIR)
	$(AR) rcs $@ $(OBJ_LIB)

# 3. Link the Final Executable against our static archive
$(TARGET): $(SRC_BIN) $(LIB_A) | $(BIN_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SRC_BIN) -o $@ $(LDFLAGS) $(LDLIBS)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(LIB_DIR):
	mkdir -p $(LIB_DIR)

run: $(TARGET)
	./$(TARGET)

# --- Test Execution Pipelines ---

# 1. Standard regression tests
test: $(TARGET)
	@echo "==> Running functional regression test suite..."
	python3 $(TEST_SCRIPT)

# 2. Automated instrumentation verification (ASan/UBSan)
test-asan: clean | $(BIN_DIR) $(LIB_DIR)
	@echo "==> Compiling temporary library and binary with ASan/UBSan..."
	$(CC) $(CPPFLAGS) $(CFLAGS) -fsanitize=address,undefined -g -c $(SRC_LIB) -o $(OBJ_LIB)
	$(AR) rcs $(LIB_A) $(OBJ_LIB)
	$(CC) $(CPPFLAGS) $(CFLAGS) -fsanitize=address,undefined -g $(SRC_BIN) -o $(TARGET) $(LDFLAGS) $(LDLIBS)
	@echo "==> Executing tests under live sanitizer inspection..."
	python3 $(TEST_SCRIPT)
	@echo "==> Diagnostics clean. Restoring production binary..."
	@$(MAKE) clean
	@$(MAKE) all

clean:
	rm -f $(TARGET) $(LIB_A) $(OBJ_LIB)

distclean: clean
	rmdir $(BIN_DIR) $(LIB_DIR) 2>/dev/null || true
