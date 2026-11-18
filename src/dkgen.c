#include "dkgen.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/param_build.h>

#define ARGON2_LANES      4u
#define ARGON2_MEM_KB     65536u
#define ARGON2_ITERATIONS 3u

#define DKGEN_P256_PRIV_LEN 32
#define DKGEN_P256_PUB_LEN  65
#define DKGEN_ED25519_PRIV_LEN 32
#define DKGEN_ED25519_PUB_LEN  32

/* Largest derived-key size any selector currently produces.  Sized
 * defensively so a future 64-byte selector (e.g. Ed448) does not
 * silently overflow the stack buffer.  See static_assert below. */
#define DKGEN_MAX_DERIVED_KEY_LEN 64

static EVP_PKEY *p256_key_from_private(const unsigned char *priv_scalar, size_t priv_scalar_len) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    BIGNUM *bn_priv = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *pub_point = NULL;
    unsigned char pub_buf[DKGEN_P256_PUB_LEN];
    size_t pub_len = sizeof(pub_buf);
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    int ok = 0;

    bn_priv = BN_bin2bn(priv_scalar, (int)priv_scalar_len, NULL);
    if (!bn_priv) goto err;
    BN_set_flags(bn_priv, BN_FLG_CONSTTIME);

    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group) goto err;

    const BIGNUM *order = EC_GROUP_get0_order(group);
    if (BN_is_zero(bn_priv) || BN_cmp(bn_priv, order) >= 0) goto err;

    pub_point = EC_POINT_new(group);
    if (!pub_point) goto err;
    if (!EC_POINT_mul(group, pub_point, bn_priv, NULL, NULL, NULL)) goto err;

    pub_len = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED,
                                 pub_buf, sizeof(pub_buf), NULL);
    if (pub_len != DKGEN_P256_PUB_LEN) goto err;

    bld = OSSL_PARAM_BLD_new();
    if (!bld) goto err;
    if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0)) goto err;
    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, bn_priv)) goto err;
    if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub_buf, pub_len)) goto err;

    params = OSSL_PARAM_BLD_to_param(bld);
    if (!params) goto err;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!ctx) goto err;

    if (EVP_PKEY_fromdata_init(ctx) <= 0) goto err;
    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) goto err;
    ok = 1;

err:
    if (!ok) { EVP_PKEY_free(pkey); pkey = NULL; }
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EC_POINT_free(pub_point);
    EC_GROUP_free(group);
    if (bn_priv) BN_clear_free(bn_priv);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* Fix 2: on any failure, restore the caller-supplied *priv_len and
 * *pub_len so the caller never sees a partially-updated length with a
 * failure return.  Capacity is validated before writing priv_out. */
static int p256_extract_keys(EVP_PKEY *pkey,
                             unsigned char *priv_out, size_t *priv_len,
                             unsigned char *pub_out, size_t *pub_len) {
    BIGNUM *bn_priv = NULL;
    int ok = 0;
    int priv_written = 0;   /* nonzero only once priv_out has been fully populated */
    const size_t priv_cap_in = *priv_len;
    const size_t pub_cap_in  = *pub_len;

    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bn_priv) <= 0) goto done;
    int bn_bytes = BN_num_bytes(bn_priv);
    if (bn_bytes <= 0 || bn_bytes > DKGEN_P256_PRIV_LEN) goto done;

    /* Validate caller-supplied capacity before touching priv_out. */
    if (priv_cap_in < DKGEN_P256_PRIV_LEN) goto done;

    memset(priv_out, 0, DKGEN_P256_PRIV_LEN);
    priv_written = 1;
    if (BN_bn2bin(bn_priv, priv_out + (DKGEN_P256_PRIV_LEN - (size_t)bn_bytes)) != bn_bytes)
        goto done;
    *priv_len = DKGEN_P256_PRIV_LEN;

    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                        pub_out, *pub_len, pub_len) <= 0) goto done;
    if (*pub_len != DKGEN_P256_PUB_LEN) goto done;
    ok = 1;

done:
    if (!ok) {
        if (priv_written) {
            /* Only wipe what we actually wrote, and only within the
             * caller's validated capacity. */
            OPENSSL_cleanse(priv_out, DKGEN_P256_PRIV_LEN);
        }
        /* Fix 2: restore caller-visible lengths on failure. */
        *priv_len = priv_cap_in;
        *pub_len  = pub_cap_in;
    }
    if (bn_priv) BN_clear_free(bn_priv);
    return ok;
}

dkgen_result dkgen_derive(
    dkgen_algo  algo,
    const uint8_t *passphrase, size_t passphrase_len,
    const uint8_t *salt,     size_t salt_len,
    const uint8_t *pepper,   size_t pepper_len,
    uint8_t       *priv_out, size_t *priv_len,
    uint8_t       *pub_out,  size_t *pub_len)
{
    if (!passphrase || !salt || passphrase_len == 0 || salt_len == 0)
        return DKGEN_ERR_INVALID_ARG;
    if (!pepper && pepper_len > 0)
        return DKGEN_ERR_INVALID_ARG;
    if (!priv_out || !priv_len)
        return DKGEN_ERR_INVALID_ARG;

    if (algo != DKGEN_ALGO_ED25519 && algo != DKGEN_ALGO_P256 &&
        algo != DKGEN_ALGO_ARGON2ID_20 && algo != DKGEN_ALGO_ARGON2ID_32)
        return DKGEN_ERR_UNKNOWN_ALGO;

    /* Fix 10: pub_out/pub_len are only required for the key-pair
     * selectors; the Argon2id selectors produce no public key. */
    const int needs_pub = (algo == DKGEN_ALGO_ED25519 || algo == DKGEN_ALGO_P256);
    if (needs_pub && (!pub_out || !pub_len))
        return DKGEN_ERR_INVALID_ARG;


    /* Determine required sizes upfront before running Argon2id */
    size_t derived_key_len = 0;
    size_t req_priv_len = 0;
    size_t req_pub_len = 0;

    switch (algo) {
        case DKGEN_ALGO_ARGON2ID_20:
            derived_key_len = 20;
            req_priv_len = 20;
            break;
        case DKGEN_ALGO_ARGON2ID_32:
            derived_key_len = 32;
            req_priv_len = 32;
            break;
        case DKGEN_ALGO_ED25519:
            derived_key_len = 32;
            req_priv_len = DKGEN_ED25519_PRIV_LEN;
            req_pub_len  = DKGEN_ED25519_PUB_LEN;
            break;
        case DKGEN_ALGO_P256:
            derived_key_len = 32;
            req_priv_len = DKGEN_P256_PRIV_LEN;
            req_pub_len  = DKGEN_P256_PUB_LEN;
            break;
        default:
            return DKGEN_ERR_UNKNOWN_ALGO;
    }

    /* Fail fast with DKGEN_ERR_BUFFER_TOO_SMALL across ALL algorithms */
    if (*priv_len < req_priv_len)
        return DKGEN_ERR_BUFFER_TOO_SMALL;
    if (needs_pub && *pub_len < req_pub_len)
        return DKGEN_ERR_BUFFER_TOO_SMALL;

    /* Guard against 32-bit truncation inside OpenSSL's Argon2 provider */
    if (passphrase_len > UINT32_MAX || salt_len > UINT32_MAX || pepper_len > UINT32_MAX)
        return DKGEN_ERR_INVALID_ARG;

    unsigned char derived_key[DKGEN_MAX_DERIVED_KEY_LEN] = {0};
    if (derived_key_len > sizeof(derived_key))
        return DKGEN_ERR_INTERNAL;

    dkgen_result res = DKGEN_OK;
    EVP_PKEY *pkey = NULL;

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "ARGON2ID", NULL);
    if (!kdf) return DKGEN_ERR_INTERNAL;
    EVP_KDF_CTX *kdf_ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kdf_ctx) return DKGEN_ERR_INTERNAL;

    uint32_t lanes = ARGON2_LANES, mem_kb = ARGON2_MEM_KB, iterations = ARGON2_ITERATIONS;
    /* 7 = passphrase, salt, pepper, lanes, memcost, iter, end-marker.
     * Update this size if a parameter is added. */
    OSSL_PARAM params[7];
    OSSL_PARAM *p = params;

    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (void *)passphrase, passphrase_len);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, salt_len);
    if (pepper != NULL && pepper_len > 0) {
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, (void *)pepper, pepper_len);
    }
    *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes);
    *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &mem_kb);
    *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iterations);
    *p = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kdf_ctx, derived_key, derived_key_len, params) <= 0) {
        res = DKGEN_ERR_DERIVE;
        goto cleanup;
    }

    if (algo == DKGEN_ALGO_ARGON2ID_20 || algo == DKGEN_ALGO_ARGON2ID_32) {
        if (*priv_len < derived_key_len) { res = DKGEN_ERR_BUFFER_TOO_SMALL; goto cleanup; }
        memcpy(priv_out, derived_key, derived_key_len);
        *priv_len = derived_key_len;
        /* Fix 10: pub_out may be NULL here; only touch *pub_len if given. */
        if (pub_len) *pub_len = 0;
        goto cleanup;
    }

    if (algo == DKGEN_ALGO_ED25519) {
        /* Fix 1: validate capacities up front so we never write the
         * private key and then fail on the public key, leaving the
         * caller's lengths stale and priv_out populated. */
        if (*priv_len < DKGEN_ED25519_PRIV_LEN || *pub_len < DKGEN_ED25519_PUB_LEN) {
            res = DKGEN_ERR_BUFFER_TOO_SMALL;
            goto cleanup;
        }

        pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, derived_key, derived_key_len);
        if (!pkey) { res = DKGEN_ERR_DERIVE; goto cleanup; }

        size_t plen = *priv_len, qlen = *pub_len;
        int priv_ok = (EVP_PKEY_get_raw_private_key(pkey, priv_out, &plen) > 0);
        int pub_ok  = priv_ok &&
                      (EVP_PKEY_get_raw_public_key(pkey, pub_out, &qlen) > 0);
        if (!priv_ok || !pub_ok) {
            /* Fix 1: cleanse any partial private-key material before
             * returning; leave the caller's lengths untouched. */
            if (priv_ok)
                OPENSSL_cleanse(priv_out, DKGEN_ED25519_PRIV_LEN);
            res = DKGEN_ERR_INTERNAL;
            goto cleanup;
        }
        *priv_len = plen;
        *pub_len  = qlen;
    } else { /* DKGEN_ALGO_P256 */
        pkey = p256_key_from_private(derived_key, derived_key_len);
        if (!pkey) { res = DKGEN_ERR_DERIVE; goto cleanup; }

        if (!p256_extract_keys(pkey, priv_out, priv_len, pub_out, pub_len)) {
            res = DKGEN_ERR_INTERNAL;
            goto cleanup;
        }
    }

cleanup:
    if (pkey) EVP_PKEY_free(pkey);
    EVP_KDF_CTX_free(kdf_ctx);
    OPENSSL_cleanse(derived_key, sizeof(derived_key));
    return res;
}
