#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include "dkgen.h"

#define MAX_LINE_LEN 512

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_to_bytes_exact(const char *hex, unsigned char *buf, size_t want) {
    if (strlen(hex) != want * 2) return 0;
    for (size_t i = 0; i < want * 2; i += 2) {
        int hi = hexval(hex[i]), lo = hexval(hex[i + 1]);
        if (hi < 0 || lo < 0) return 0;
        buf[i / 2] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

static void fail(const char *msg) {
    fprintf(stderr, "STATUS:FAILURE\nERROR:%s\n", msg);
}

static int bio_write_str(BIO *payload, const char *s) {
    size_t len = strlen(s);
    return BIO_write(payload, s, (int)len) == (int)len;
}

static int bio_write_hex(BIO *payload, const unsigned char *buf, size_t len) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        if (BIO_write(payload, &digits[buf[i] >> 4], 1) != 1 ||
            BIO_write(payload, &digits[buf[i] & 0x0f], 1) != 1) return 0;
    }
    return 1;
}

static int commit_payload(BIO *payload) {
    char *data = NULL;
    long len = BIO_get_mem_data(payload, &data);
    if (len <= 0 || !data) return 0;
    if (fwrite(data, 1, (size_t)len, stdout) != (size_t)len) return 0;
    return (fflush(stdout) == 0 && !ferror(stdout));
}

int main(void) {
    char line[MAX_LINE_LEN], algo_str[32] = {0};
    unsigned char seed[DKGEN_SEED_LEN] = {0}, salt[DKGEN_SALT_LEN] = {0};
    int has_algo = 0, has_seed = 0, has_salt = 0, ok = 0;
    BIO *payload = NULL;

    while (fgets(line, sizeof(line), stdin)) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] != '\n') {
            int c = getchar();
            if (c != EOF && c != '\n') {
                int drain;
                while ((drain = getchar()) != EOF && drain != '\n');
                fail("Line too long");
                continue;
            }
        }
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0') continue;

        if (strncmp(line, "ALGO:", 5) == 0) {
            if (has_algo) { fail("Duplicate ALGO field"); goto cleanup; }
            if (strlen(line + 5) >= sizeof(algo_str)) { fail("ALGO value too long"); goto cleanup; }
            snprintf(algo_str, sizeof(algo_str), "%s", line + 5);
            has_algo = 1;
        } else if (strncmp(line, "SEED:", 5) == 0) {
            if (has_seed) { fail("Duplicate SEED field"); goto cleanup; }
            if (!hex_to_bytes_exact(line + 5, seed, DKGEN_SEED_LEN)) { fail("Invalid SEED"); goto cleanup; }
            has_seed = 1;
        } else if (strncmp(line, "SALT:", 5) == 0) {
            if (has_salt) { fail("Duplicate SALT field"); goto cleanup; }
            if (!hex_to_bytes_exact(line + 5, salt, DKGEN_SALT_LEN)) { fail("Invalid SALT"); goto cleanup; }
            has_salt = 1;
        } else {
            fail("Unknown line in input");
            goto cleanup;
        }
    }

    if (!has_algo || !has_seed || !has_salt) { fail("Missing required fields"); goto cleanup; }

    dkgen_algo_t algo;
    if (strcmp(algo_str, "ED25519") == 0) algo = DKGEN_ALGO_ED25519;
    else if (strcmp(algo_str, "P-256") == 0) algo = DKGEN_ALGO_P256;
    else if (strcmp(algo_str, "ARGON2ID_20") == 0) algo = DKGEN_ALGO_ARGON2ID_20;
    else if (strcmp(algo_str, "ARGON2ID_32") == 0) algo = DKGEN_ALGO_ARGON2ID_32;
    else { fail("Unsupported algorithm profile"); goto cleanup; }

    dkgen_sym_out_t sym_out = {0};
    dkgen_asym_out_t asym_out = {0};
    dkgen_result_t res = dkgen_derive(algo, seed, salt, &sym_out, &asym_out);

    if (res != DKGEN_SUCCESS) {
        fail(dkgen_strerror(res));
        goto cleanup;
    }

    payload = BIO_new(BIO_s_mem());
    if (!payload) { fail("Failed to allocate output buffer"); goto cleanup; }

    if (algo == DKGEN_ALGO_ARGON2ID_20 || algo == DKGEN_ALGO_ARGON2ID_32) {
        if (!bio_write_str(payload, "KEY:\n") || 
            !bio_write_hex(payload, sym_out.key, sym_out.len)) goto cleanup;
    } else {
        if (!bio_write_str(payload, "PRIVATE_KEY:\n") ||
            !bio_write_hex(payload, asym_out.private_key, asym_out.private_len) ||
            !bio_write_str(payload, "\nPUBLIC_KEY:\n") ||
            !bio_write_hex(payload, asym_out.public_key, asym_out.public_len)) goto cleanup;
    }

    if (!bio_write_str(payload, "\nSTATUS:SUCCESS\n") || !commit_payload(payload)) goto cleanup;
    ok = 1;

cleanup:
    if (payload) {
        char *p; long l = BIO_get_mem_data(payload, &p);
        if (p && l > 0) OPENSSL_cleanse(p, (size_t)l);
        BIO_free(payload);
    }
    OPENSSL_cleanse(seed, sizeof(seed));
    OPENSSL_cleanse(salt, sizeof(salt));
    OPENSSL_cleanse(&sym_out, sizeof(sym_out));
    OPENSSL_cleanse(&asym_out, sizeof(asym_out));
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}

