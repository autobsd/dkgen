#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/param_build.h>

#define MAX_LINE_LEN 512
#define SEED_LEN     32
#define SALT_LEN     32

/* Ed25519 raw private key is exactly 32 bytes; the Argon2id output is used
 * directly as the Ed25519 seed. If SEED_LEN ever changes, this build breaks
 * rather than silently producing a mismatched key. */
_Static_assert(SEED_LEN == 32, "Ed25519 raw private key must be 32 bytes");


/* P-256 private scalar length (32 bytes). Public key uncompressed length is 65. */
#define P256_PRIV_LEN 32
#define P256_PUB_LEN  65

/* Named Argon2id profile constants. */
#define ARGON2_LANES      4u
#define ARGON2_MEM_KB     65536u   /* 64 MiB */
#define ARGON2_ITERATIONS 3u

/* Output lengths for the raw Argon2id profiles. */
#define ARGON2ID_20_LEN 20
#define ARGON2ID_32_LEN 32

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
    size_t len = strlen(s);
    return BIO_write(payload, s, (int)len) == (int)len;
}

/* Append the lowercase hex encoding of `len` bytes from `buf` to `payload`. */
static int bio_write_hex(BIO *payload, const unsigned char *buf, size_t len) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        if (BIO_write(payload, &digits[buf[i] >> 4], 1) != 1) return 0;
        if (BIO_write(payload, &digits[buf[i] & 0x0f], 1) != 1) return 0;
    }
    return 1;
}

/* Construct an EVP_PKEY for P-256 from a raw 32-byte private scalar.
 * Returns NULL on failure. */
static EVP_PKEY *p256_key_from_private(const unsigned char *priv_scalar) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    BIGNUM *bn_priv = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *pub_point = NULL;
    unsigned char pub_buf[P256_PUB_LEN];
    size_t pub_len = sizeof(pub_buf);
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    int ok = 0;

    /* 1. Convert raw scalar to BIGNUM. */
    bn_priv = BN_bin2bn(priv_scalar, P256_PRIV_LEN, NULL);
    if (!bn_priv) goto err;

    BN_set_flags(bn_priv, BN_FLG_CONSTTIME);

    /* 2. Get P-256 group and compute public point = priv * G. */
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group) goto err;

    const BIGNUM *order = EC_GROUP_get0_order(group);
    if (BN_is_zero(bn_priv) || BN_cmp(bn_priv, order) >= 0) {
        goto err;
    }
    pub_point = EC_POINT_new(group);
    if (!pub_point) goto err;

    if (!EC_POINT_mul(group, pub_point, bn_priv, NULL, NULL, NULL)) goto err;

    /* 3. Serialize public point (uncompressed). */
    pub_len = EC_POINT_point2oct(group, pub_point,
                                 POINT_CONVERSION_UNCOMPRESSED,
                                 pub_buf, sizeof(pub_buf), NULL);
    if (pub_len != P256_PUB_LEN) goto err;

    /* 4. Build OSSL_PARAM array with group name, private scalar, public point. */
    bld = OSSL_PARAM_BLD_new();
    if (!bld) goto err;

    if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0)) goto err;
    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, bn_priv)) goto err;
    if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub_buf, pub_len)) goto err;

    params = OSSL_PARAM_BLD_to_param(bld);
    if (!params) goto err;

    /* 5. Create EVP_PKEY from the assembled parameters. */
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!ctx) goto err;

    if (EVP_PKEY_fromdata_init(ctx) <= 0) goto err;
    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) goto err;

    ok = 1;

err:
    if (!ok) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EC_POINT_free(pub_point); // Safe to call with NULL
    EC_GROUP_free(group);     // Safe to call with NULL
    if (bn_priv) BN_clear_free(bn_priv);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* Extract the raw private scalar and uncompressed public point from a
 * P-256 EVP_PKEY. Returns 1 on success, 0 on failure. */
static int p256_extract_keys(EVP_PKEY *pkey,
                             unsigned char *priv_out, size_t *priv_len,
                             unsigned char *pub_out, size_t *pub_len) {
    BIGNUM *bn_priv = NULL;
    int ok = 0;

    /* 1. Extract the private key BIGNUM. */
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bn_priv) <= 0) {
        goto done;
    }

    int bn_bytes = BN_num_bytes(bn_priv);
    /* Defensive check: Ensure the private scalar fits perfectly within 
     * a 32-byte P-256 allocation without causing negative pointer offsets. */
    if (bn_bytes <= 0 || bn_bytes > P256_PRIV_LEN) {
        goto done;
    }
    
    /* Left-pad with zeros to exactly 32 bytes (BN_bn2bin omits leading zeros). */
    memset(priv_out, 0, P256_PRIV_LEN);
    if (BN_bn2bin(bn_priv, priv_out + (P256_PRIV_LEN - (size_t)bn_bytes)) != bn_bytes) {
        goto done;
    }
    *priv_len = P256_PRIV_LEN;

    /* 2. Extract the encoded public key (uncompressed point). */
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                        pub_out, *pub_len, pub_len) <= 0) {
        goto done;
    }

    if (*pub_len != P256_PUB_LEN) {
	goto done;
    }

    ok = 1;

done:
    if (!ok) OPENSSL_cleanse(priv_out, P256_PRIV_LEN);

    if (bn_priv) BN_clear_free(bn_priv);
    return ok;
}

int main(void) {
    char line[MAX_LINE_LEN];
    char algo[32] = {0};
    unsigned char input_seed[SEED_LEN] = {0};
    unsigned char input_salt[SALT_LEN] = {0};
    /* Large enough to hold the longest Argon2id output we support (32 bytes),
     * which also matches the Ed25519 seed and P-256 scalar sizes. */
    unsigned char derived_key[SEED_LEN] = {0};
    size_t derived_key_len = 0;

    unsigned char priv_raw[P256_PUB_LEN] = {0}; /* large enough for either */
    unsigned char pub_raw[P256_PUB_LEN] = {0};
    size_t priv_len = 0;
    size_t pub_len  = 0;


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
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] != '\n') {
            int c = getchar();
            if (c != EOF && c != '\n') {
                /* The line is truly too long. Drain the rest of it. */
                int drain;
                while ((drain = getchar()) != EOF && drain != '\n');
                
                fail("Line too long");
                continue; /* Skip this malformed line and keep processing input! */
            }
            /* If c was '\n', we safely consumed the trailing newline. 
             * If c was EOF, we safely hit the end of the stream. */
        }

        line[strcspn(line, "\r\n")] = '\0';

        if (line[0] == '\0') continue;  /* skip blank lines */

        if (strncmp(line, "ALGO:", 5) == 0) {
            if (has_algo) { fail("Duplicate ALGO field"); goto cleanup; }
            if (strlen(line + 5) >= sizeof(algo)) {
                fail("ALGO value too long");
		goto cleanup;
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

    if (strcmp(algo, "ED25519") != 0 &&
        strcmp(algo, "P-256") != 0 &&
        strcmp(algo, "ARGON2ID_20") != 0 &&
        strcmp(algo, "ARGON2ID_32") != 0) {
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

    /* Determine how many bytes of Argon2id output this profile needs. */
    if (strcmp(algo, "ARGON2ID_20") == 0) {
        derived_key_len = ARGON2ID_20_LEN;
    } else {
        /* ED25519, P-256 and ARGON2ID_32 all use a 32-byte derived key. */
        derived_key_len = ARGON2ID_32_LEN;
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

        if (EVP_KDF_derive(kdf_ctx, derived_key, derived_key_len, params) <= 0) {
            fail("Key derivation failed");
            goto cleanup;
        }
    }
    EVP_KDF_CTX_free(kdf_ctx);
    kdf_ctx = NULL;

    /* Raw Argon2id profiles output the derived key directly, with no
     * asymmetric key material. */
    if (strcmp(algo, "ARGON2ID_20") == 0 || strcmp(algo, "ARGON2ID_32") == 0) {
        payload = BIO_new(BIO_s_mem());
        if (!payload) {
            fail("Failed to allocate output buffer");
            goto cleanup;
        }

        if (!bio_write_str(payload, "KEY:\n")) {
            fail("Failed to stage derived key header");
            goto cleanup;
        }
        if (!bio_write_hex(payload, derived_key, derived_key_len)) {
            fail("Failed to write derived key");
            goto cleanup;
        }
        if (!bio_write_str(payload, "\nSTATUS:SUCCESS\n")) {
            fail("Failed to stage status footer");
            goto cleanup;
        }

        if (!commit_payload(payload)) {
            fail("stdout error");
            goto cleanup;
        }

        ok = 1;
        goto cleanup;
    }

    /* Build the asymmetric key based on the algorithm. */
    if (strcmp(algo, "ED25519") == 0) {
        /* Original Ed25519 path: raw private key is supported directly. */
        pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                            derived_key, derived_key_len);
        if (!pkey) {
            fail("Asymmetric key synthesis failed");
            goto cleanup;
        }


	/* Stage the entire protocol output in one in-memory BIO. Nothing reaches
	 * stdout until every step has succeeded AND the full payload is ready.
	 * STATUS:SUCCESS is emitted last so a truncated stream can never end on a
	 * success marker. */

	priv_len = sizeof(priv_raw);
        pub_len  = sizeof(pub_raw);


	/* Extract the raw key material for hex output. */
	if (EVP_PKEY_get_raw_private_key(pkey, priv_raw, &priv_len) <= 0) {
            fail("Failed to extract raw private key");
            goto cleanup;
        }
        if (EVP_PKEY_get_raw_public_key(pkey, pub_raw, &pub_len) <= 0) {
            fail("Failed to extract raw public key");
            goto cleanup;
        }
    } else {
        /* P-256 path: construct key via provider API, extract via BN + param API. */
        pkey = p256_key_from_private(derived_key);
        if (!pkey) {
            fail("P-256 key synthesis failed");
            goto cleanup;
        }

        priv_len = sizeof(priv_raw);
        pub_len  = sizeof(pub_raw);

        if (!p256_extract_keys(pkey, priv_raw, &priv_len, pub_raw, &pub_len)) {
            fail("Failed to extract P-256 key material");
            goto cleanup;
        }
    }
    
    payload = BIO_new(BIO_s_mem());
    if (!payload) {
        fail("Failed to allocate output buffer");
        goto cleanup;
    }

    if (!bio_write_str(payload, "PRIVATE_KEY:\n")) {
        fail("Failed to stage private key header");
        goto cleanup;
    }
    if (!bio_write_hex(payload, priv_raw, priv_len)) {
        fail("Failed to write private key");
        goto cleanup;
    }
    if (!bio_write_str(payload, "\nPUBLIC_KEY:\n")) {
        fail("Failed to stage public key header");
        goto cleanup;
    }
    if (!bio_write_hex(payload, pub_raw, pub_len)) {
        fail("Failed to write public key");
        goto cleanup;
    }
    if (!bio_write_str(payload, "\nSTATUS:SUCCESS\n")) {
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
    if (payload) {
	char *p; long l = BIO_get_mem_data(payload, &p);
	if (p && l > 0) OPENSSL_cleanse(p, (size_t)l);
	BIO_free(payload);
    }

    OPENSSL_cleanse(input_seed, sizeof(input_seed));
    OPENSSL_cleanse(input_salt, sizeof(input_salt));
    OPENSSL_cleanse(derived_key, sizeof(derived_key));
    OPENSSL_cleanse(line, sizeof(line));

    OPENSSL_cleanse(priv_raw, sizeof(priv_raw));
    OPENSSL_cleanse(pub_raw, sizeof(pub_raw));
    
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
