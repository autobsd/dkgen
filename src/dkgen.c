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

static int not_all_zero(const unsigned char *buf, size_t len) {
    unsigned char acc = 0;
    for (size_t i = 0; i < len; i++) acc |= buf[i];
    return acc != 0;
}

static EVP_PKEY *p256_key_from_private(const unsigned char *priv_scalar) {
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

    bn_priv = BN_bin2bn(priv_scalar, DKGEN_P256_PRIV_LEN, NULL);
    if (!bn_priv) goto err;
    BN_set_flags(bn_priv, BN_FLG_CONSTTIME);

    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group) goto err;

    const BIGNUM *order = EC_GROUP_get0_order(group);
    if (BN_is_zero(bn_priv) || BN_cmp(bn_priv, order) >= 0) goto err;

    pub_point = EC_POINT_new(group);
    if (!pub_point) goto err;
    if (!EC_POINT_mul(group, pub_point, bn_priv, NULL, NULL, NULL)) goto err;

    pub_len = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED, pub_buf, sizeof(pub_buf), NULL);
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

static int p256_extract_keys(EVP_PKEY *pkey, unsigned char *priv_out, size_t *priv_len, unsigned char *pub_out, size_t *pub_len) {
    BIGNUM *bn_priv = NULL;
    int ok = 0;

    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bn_priv) <= 0) goto done;
    int bn_bytes = BN_num_bytes(bn_priv);
    if (bn_bytes <= 0 || bn_bytes > DKGEN_P256_PRIV_LEN) goto done;

    memset(priv_out, 0, DKGEN_P256_PRIV_LEN);
    if (BN_bn2bin(bn_priv, priv_out + (DKGEN_P256_PRIV_LEN - (size_t)bn_bytes)) != bn_bytes) goto done;
    *priv_len = DKGEN_P256_PRIV_LEN;

    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, pub_out, *pub_len, pub_len) <= 0) goto done;
    if (*pub_len != DKGEN_P256_PUB_LEN) goto done;
    ok = 1;

done:
    if (!ok) OPENSSL_cleanse(priv_out, DKGEN_P256_PRIV_LEN);
    if (bn_priv) BN_clear_free(bn_priv);
    return ok;
}

dkgen_result_t dkgen_derive(dkgen_algo_t algo, const unsigned char seed[DKGEN_SEED_LEN], const unsigned char salt[DKGEN_SALT_LEN], dkgen_sym_out_t *sym_out, dkgen_asym_out_t *asym_out) {
    if (!seed || !salt) return DKGEN_ERR_INVALID_PARAM;
    if (!not_all_zero(seed, DKGEN_SEED_LEN)) return DKGEN_ERR_SEED_ALL_ZEROS;
    if (!not_all_zero(salt, DKGEN_SALT_LEN)) return DKGEN_ERR_SALT_ALL_ZEROS;

    size_t derived_key_len = (algo == DKGEN_ALGO_ARGON2ID_20) ? 20 : 32;
    unsigned char derived_key[DKGEN_SEED_LEN] = {0};
    dkgen_result_t res = DKGEN_SUCCESS;

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "ARGON2ID", NULL);
    if (!kdf) return DKGEN_ERR_KDF_FETCH;
    EVP_KDF_CTX *kdf_ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kdf_ctx) return DKGEN_ERR_KDF_CONTEXT;

    uint32_t lanes = ARGON2_LANES, mem_kb = ARGON2_MEM_KB, iterations = ARGON2_ITERATIONS;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (void*)seed, DKGEN_SEED_LEN),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void*)salt, DKGEN_SALT_LEN),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &mem_kb),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iterations),
        OSSL_PARAM_construct_end()
    };

    if (EVP_KDF_derive(kdf_ctx, derived_key, derived_key_len, params) <= 0) {
        res = DKGEN_ERR_KDF_FAILED;
        goto cleanup;
    }

    if (algo == DKGEN_ALGO_ARGON2ID_20 || algo == DKGEN_ALGO_ARGON2ID_32) {
        if (!sym_out) { res = DKGEN_ERR_INVALID_PARAM; goto cleanup; }
        memcpy(sym_out->key, derived_key, derived_key_len);
        sym_out->len = derived_key_len;
        goto cleanup;
    }

    if (!asym_out) { res = DKGEN_ERR_INVALID_PARAM; goto cleanup; }
    EVP_PKEY *pkey = NULL;

    if (algo == DKGEN_ALGO_ED25519) {
        pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, derived_key, derived_key_len);
        if (!pkey) { res = DKGEN_ERR_SYNTHESIS_FAILED; goto cleanup; }

        asym_out->private_len = sizeof(asym_out->private_key);
        asym_out->public_len  = sizeof(asym_out->public_key);

        if (EVP_PKEY_get_raw_private_key(pkey, asym_out->private_key, &asym_out->private_len) <= 0 ||
            EVP_PKEY_get_raw_public_key(pkey, asym_out->public_key, &asym_out->public_len) <= 0) {
            res = DKGEN_ERR_EXTRACTION_FAILED;
        }
    } else if (algo == DKGEN_ALGO_P256) {
        pkey = p256_key_from_private(derived_key);
        if (!pkey) { res = DKGEN_ERR_SYNTHESIS_FAILED; goto cleanup; }

        asym_out->private_len = sizeof(asym_out->private_key);
        asym_out->public_len  = sizeof(asym_out->public_key);

        if (!p256_extract_keys(pkey, asym_out->private_key, &asym_out->private_len, asym_out->public_key, &asym_out->public_len)) {
            res = DKGEN_ERR_EXTRACTION_FAILED;
        }
    }
    if (pkey) EVP_PKEY_free(pkey);

cleanup:
    EVP_KDF_CTX_free(kdf_ctx);
    OPENSSL_cleanse(derived_key, sizeof(derived_key));
    return res;
}

const char *dkgen_strerror(dkgen_result_t result) {
    switch(result) {
	case DKGEN_SUCCESS: return "Success";
        case DKGEN_ERR_INVALID_PARAM: return "Invalid parameter configuration";
        case DKGEN_ERR_SEED_ALL_ZEROS: return "SEED is all zeros";
        case DKGEN_ERR_SALT_ALL_ZEROS: return "SALT is all zeros";
        case DKGEN_ERR_KDF_FETCH: return "Failed to fetch Argon2id provider";
        case DKGEN_ERR_KDF_CONTEXT: return "KDF setup failed";
        case DKGEN_ERR_KDF_FAILED: return "Key derivation runtime failure";
        case DKGEN_ERR_SYNTHESIS_FAILED: return "Keypair structural synthesis failed";
        case DKGEN_ERR_EXTRACTION_FAILED: return "Failed to extract public/private keys";
        default: return "Unknown structural library error";
    }
}
