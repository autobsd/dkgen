#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#define MAX_LINE_LEN 512
#define SEED_LEN     32
#define SALT_LEN     32

/* Ed25519 raw private key is exactly 32 bytes; the Argon2id output is used
 * directly as the Ed25519 seed. If SEED_LEN ever changes, this build breaks
 * rather than silently producing a mismatched key. */
_Static_assert(SEED_LEN == 32, "Ed25519 raw private key must be 32 bytes");

/* Named Argon2id profile constants. */
#define ARGON2_LANES      4u
#define ARGON2_MEM_KB     65536u   /* 64 MiB */
#define ARGON2_ITERATIONS 3u

/* Return 0-15 for a hex digit, -1 otherwise. */
static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Convert hex string to raw bytes. Rejects odd length or overflow. */
static int hex_to_bytes(const char *hex, unsigned char *buf, size_t max_len) {
    size_t len = strlen(hex);
    if (len % 2 != 0 || (len / 2) > max_len) return 0;

    for (size_t i = 0; i < len; i += 2) {
        int hi = hexval(hex[i]);
        int lo = hexval(hex[i + 1]);
        if (hi < 0 || lo < 0) return 0;
        buf[i / 2] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

/* Strict variant: require exactly `want` bytes of hex (2*want chars). */
static int hex_to_bytes_exact(const char *hex, unsigned char *buf, size_t want) {
    if (strlen(hex) != want * 2) return 0;
    return hex_to_bytes(hex, buf, want);
}

/* Return 1 if the buffer is not entirely zero (i.e. has at least one
 * non-zero byte), 0 otherwise. Used to reject trivially degenerate inputs. */
static int not_all_zero(const unsigned char *buf, size_t len) {
    unsigned char acc = 0;
    for (size_t i = 0; i < len; i++) acc |= buf[i];
    return acc != 0;
}

/* Report failure on stderr. Always followed by `goto cleanup` at call sites. */
static void fail(const char *msg) {
    fprintf(stderr, "STATUS:FAILURE\nERROR:%s\n", msg);
}

/* Write the whole staged payload to stdout as a single logical commit.
 * Returns 1 on success, 0 on failure.
 *
 * NOTE: a mid-write I/O error on stdout cannot be undone atomically; in that
 * case a truncated payload may already have been emitted before this function
 * reports failure. The failure marker is written to stderr, so a consumer
 * that only trusts stdout payloads ending in STATUS:SUCCESS remains safe. */
static int commit_payload(BIO *payload) {
    char *data = NULL;
    long  len  = BIO_get_mem_data(payload, &data);
    if (len <= 0 || data == NULL) return 0;
    if (fwrite(data, 1, (size_t)len, stdout) != (size_t)len) return 0;
    if (fflush(stdout) != 0 || ferror(stdout)) return 0;
    return 1;
}

/* Write a fixed string into the payload BIO and fail hard if the write did
 * not fully succeed. Returns 1 on success, 0 on failure. */
static int bio_write_str(BIO *payload, const char *s) {
    int n = BIO_printf(payload, "%s", s);
    return n >= 0;
}

int main(void) {
    char line[MAX_LINE_LEN];
    char algo[32] = {0};
    unsigned char input_seed[SEED_LEN] = {0};
    unsigned char input_salt[SALT_LEN] = {0};
    unsigned char derived_key[SEED_LEN] = {0};

    int has_algo = 0, has_seed = 0, has_salt = 0;
    int ok = 0;

    EVP_PKEY *pkey = NULL;
    EVP_KDF_CTX *kdf_ctx = NULL;
    BIO *payload = NULL;

    while (fgets(line, sizeof(line), stdin)) {
        /* Truncation detection. A full buffer with no newline can mean one of
         * three things:
         *   1. The line is genuinely too long (more input remains beyond the
         *      buffer, and it isn't just a terminator).
         *   2. The final line ended exactly at EOF with no trailing newline,
         *      and happens to be exactly MAX_LINE_LEN-1 chars.
         *   3. The final line ended exactly at MAX_LINE_LEN-1 chars with its
         *      newline left unread (fgets stores at most MAX_LINE_LEN-1 chars
         *      plus NUL, so a newline at position MAX_LINE_LEN would remain).
         *
         * We distinguish by draining up to the next '\n' or EOF: if we consume
         * anything other than an immediate '\n' or EOF, the line was too long.
         * The drain step itself settles the ambiguity; we deliberately do not
         * consult feof() here, since feof() is only set after a failed read. */
        if (!strchr(line, '\n')) {
            int c;
            int overflowed = 0;
            while ((c = getchar()) != EOF && c != '\n') overflowed = 1;
            if (overflowed) {
                fail("Line too long");
                goto cleanup;
            }
            /* else: either the leftover was just '\n' (case 3) or we hit EOF
             * (case 2); fall through and process the line. */
        }
        line[strcspn(line, "\r\n")] = '\0';

        if (line[0] == '\0') continue;  /* skip blank lines */

        if (strncmp(line, "ALGO:", 5) == 0) {
            if (has_algo) { fail("Duplicate ALGO field"); goto cleanup; }
            if (strlen(line + 5) >= sizeof(algo)) {
                fail("ALGO value too long"); goto cleanup;
            }
            snprintf(algo, sizeof(algo), "%s", line + 5);
            has_algo = 1;
        } else if (strncmp(line, "SEED:", 5) == 0) {
            if (has_seed) { fail("Duplicate SEED field"); goto cleanup; }
            if (!hex_to_bytes_exact(line + 5, input_seed, SEED_LEN)) {
                fail("Invalid SEED (must be 32 hex bytes)");
                goto cleanup;
            }
            has_seed = 1;
        } else if (strncmp(line, "SALT:", 5) == 0) {
            if (has_salt) { fail("Duplicate SALT field"); goto cleanup; }
            if (!hex_to_bytes_exact(line + 5, input_salt, SALT_LEN)) {
                fail("Invalid SALT (must be 32 hex bytes)");
                goto cleanup;
            }
            has_salt = 1;
        } else {
            fail("Unknown line in input");
            goto cleanup;
        }
    }

    if (!has_algo || !has_seed || !has_salt) {
        fail("Missing required fields (ALGO, SEED, or SALT)");
        goto cleanup;
    }

    if (strcmp(algo, "ED25519") != 0) {
        fail("Unsupported algorithm profile");
        goto cleanup;
    }

    /* Reject trivially degenerate inputs. An all-zero seed or salt provides
     * no entropy and almost certainly indicates a caller bug. */
    if (!not_all_zero(input_seed, SEED_LEN)) {
        fail("SEED is all zeros");
        goto cleanup;
    }
    if (!not_all_zero(input_salt, SALT_LEN)) {
        fail("SALT is all zeros");
        goto cleanup;
    }

    {
        EVP_KDF *kdf = EVP_KDF_fetch(NULL, "ARGON2ID", NULL);
        if (!kdf) {
            fail("Failed to fetch ARGON2ID KDF provider");
            goto cleanup;
        }
        kdf_ctx = EVP_KDF_CTX_new(kdf);
        EVP_KDF_free(kdf);
        if (!kdf_ctx) {
            fail("Failed to create KDF context");
            goto cleanup;
        }
    }

    {
        uint32_t lanes      = ARGON2_LANES;
        uint32_t mem_kb     = ARGON2_MEM_KB;
        uint32_t iterations = ARGON2_ITERATIONS;
	

	OSSL_PARAM params[] = {
            OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, input_seed, SEED_LEN),
            OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, input_salt, SALT_LEN),
            OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes),
            OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &mem_kb),
            OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iterations),
            OSSL_PARAM_construct_end()
        };


        if (EVP_KDF_derive(kdf_ctx, derived_key, sizeof(derived_key), params) <= 0) {
            fail("Key derivation failed");
            goto cleanup;
        }
    }
    EVP_KDF_CTX_free(kdf_ctx);
    kdf_ctx = NULL;

    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                        derived_key, sizeof(derived_key));
    if (!pkey) {
        fail("Asymmetric key synthesis failed");
        goto cleanup;
    }

    /* Stage the entire protocol output in one in-memory BIO. Nothing reaches
     * stdout until every step has succeeded AND the full payload is ready.
     * STATUS:SUCCESS is emitted last so a truncated stream can never end on a
     * success marker. */
    payload = BIO_new(BIO_s_mem());
    if (!payload) {
        fail("Failed to allocate output buffer");
        goto cleanup;
    }

    if (!bio_write_str(payload, "PRIVATE_KEY:\n")) {
        fail("Failed to stage private key header");
        goto cleanup;
    }
    if (!PEM_write_bio_PKCS8PrivateKey(payload, pkey, NULL, NULL, 0, NULL, NULL)) {
        fail("Failed to write private key");
        goto cleanup;
    }
    if (!bio_write_str(payload, "PUBLIC_KEY:\n")) {
        fail("Failed to stage public key header");
        goto cleanup;
    }
    if (!PEM_write_bio_PUBKEY(payload, pkey)) {
        fail("Failed to write public key");
        goto cleanup;
    }
    if (!bio_write_str(payload, "STATUS:SUCCESS\n")) {
        fail("Failed to stage status footer");
        goto cleanup;
    }

    if (!commit_payload(payload)) {
        fail("stdout error");
        goto cleanup;
    }

    ok = 1;

cleanup:
    if (pkey)    EVP_PKEY_free(pkey);
    if (kdf_ctx) EVP_KDF_CTX_free(kdf_ctx);
    if (payload) BIO_free(payload);

    OPENSSL_cleanse(input_seed, sizeof(input_seed));
    OPENSSL_cleanse(input_salt, sizeof(input_salt));
    OPENSSL_cleanse(derived_key, sizeof(derived_key));
    OPENSSL_cleanse(line, sizeof(line));

    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
