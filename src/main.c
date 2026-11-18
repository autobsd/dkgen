#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include "dkgen.h"

#define MAX_LINE_LEN 4096

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
    /* Text values are copied into cleansed buffers so we can wipe them. */
    char passphrase[MAX_LINE_LEN] = {0};
    char salt[MAX_LINE_LEN]       = {0};
    char pepper[MAX_LINE_LEN]     = {0};
    int has_algo = 0, has_pass = 0, has_salt = 0, has_pepper = 0, ok = 0;
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
        } else if (strncmp(line, "PASSPHRASE:", 11) == 0) {
            if (has_pass) { fail("Duplicate PASSPHRASE field"); goto cleanup; }
            /* Everything after the colon is significant, including spaces. */
            snprintf(passphrase, sizeof(passphrase), "%s", line + 11);
            has_pass = 1;
        } else if (strncmp(line, "SALT:", 5) == 0) {
            if (has_salt) { fail("Duplicate SALT field"); goto cleanup; }
            snprintf(salt, sizeof(salt), "%s", line + 5);
            has_salt = 1;
        } else if (strncmp(line, "PEPPER:", 7) == 0) {
            if (has_pepper) { fail("Duplicate PEPPER field"); goto cleanup; }
            snprintf(pepper, sizeof(pepper), "%s", line + 7);
            has_pepper = 1;
        } else {
            fail("Unknown line in input");
            goto cleanup;
        }
    }

    if (!has_algo || !has_pass || !has_salt) { fail("Missing required fields"); goto cleanup; }

    dkgen_algo algo;
    if (strcmp(algo_str, "ED25519") == 0) algo = DKGEN_ALGO_ED25519;
    else if (strcmp(algo_str, "P-256") == 0) algo = DKGEN_ALGO_P256;
    else if (strcmp(algo_str, "ARGON2ID_20") == 0) algo = DKGEN_ALGO_ARGON2ID_20;
    else if (strcmp(algo_str, "ARGON2ID_32") == 0) algo = DKGEN_ALGO_ARGON2ID_32;
    else { fail("Unsupported algorithm profile"); goto cleanup; }

    /* Caller-provided output buffers sized with public header macros. */
    uint8_t priv_out[DKGEN_MAX_PRIV_LEN] = {0};
    uint8_t pub_out[DKGEN_MAX_PUB_LEN]   = {0};
    size_t  priv_len = sizeof(priv_out);
    size_t  pub_len  = sizeof(pub_out);

    /* Passphrase and salt are text; pepper is optional. */
    dkgen_result res = dkgen_derive(
        algo,
        (const uint8_t *)passphrase, strlen(passphrase),
        (const uint8_t *)salt,       strlen(salt),
        has_pepper ? (const uint8_t *)pepper : NULL,
        has_pepper ? strlen(pepper) : 0,
        priv_out, &priv_len,
        pub_out,  &pub_len);

    if (res != DKGEN_OK) {
        fail(dkgen_strerror(res));
        goto cleanup;
    }

    payload = BIO_new(BIO_s_mem());
    if (!payload) { fail("Failed to allocate output buffer"); goto cleanup; }

    if (algo == DKGEN_ALGO_ARGON2ID_20 || algo == DKGEN_ALGO_ARGON2ID_32) {
        /* Argon2id: emit the derived key material as KEY. */
        if (!bio_write_str(payload, "PRIVATE_KEY:\n") ||
            !bio_write_hex(payload, priv_out, priv_len)) goto cleanup;
    } else {
        /* Asymmetric: emit private and public key material. */
        if (!bio_write_str(payload, "PRIVATE_KEY:\n") ||
            !bio_write_hex(payload, priv_out, priv_len) ||
            !bio_write_str(payload, "\nPUBLIC_KEY:\n") ||
            !bio_write_hex(payload, pub_out, pub_len)) goto cleanup;
    }

    if (!bio_write_str(payload, "\nSTATUS:SUCCESS\n") || !commit_payload(payload)) goto cleanup;
    ok = 1;

cleanup:
    if (payload) {
        char *p; long l = BIO_get_mem_data(payload, &p);
        if (p && l > 0) OPENSSL_cleanse(p, (size_t)l);
        BIO_free(payload);
    }
    OPENSSL_cleanse(passphrase, sizeof(passphrase));
    OPENSSL_cleanse(salt, sizeof(salt));
    OPENSSL_cleanse(pepper, sizeof(pepper));
    OPENSSL_cleanse(priv_out, sizeof(priv_out));
    OPENSSL_cleanse(pub_out, sizeof(pub_out));
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
