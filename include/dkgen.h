#ifndef DKGEN_H
#define DKGEN_H

#include <stddef.h>

#define DKGEN_SEED_LEN     32
#define DKGEN_SALT_LEN     32
#define DKGEN_P256_PRIV_LEN 32
#define DKGEN_P256_PUB_LEN  65
#define DKGEN_ED25519_PRIV_LEN 32
#define DKGEN_ED25519_PUB_LEN  32

typedef enum {
    DKGEN_ALGO_ED25519,
    DKGEN_ALGO_P256,
    DKGEN_ALGO_ARGON2ID_20,
    DKGEN_ALGO_ARGON2ID_32
} dkgen_algo_t;

typedef enum {
    DKGEN_SUCCESS = 0,
    DKGEN_ERR_INVALID_PARAM,
    DKGEN_ERR_SEED_ALL_ZEROS,
    DKGEN_ERR_SALT_ALL_ZEROS,
    DKGEN_ERR_KDF_FETCH,
    DKGEN_ERR_KDF_CONTEXT,
    DKGEN_ERR_KDF_FAILED,
    DKGEN_ERR_SYNTHESIS_FAILED,
    DKGEN_ERR_EXTRACTION_FAILED
} dkgen_result_t;

/* Holds asymmetric raw keys */
typedef struct {
    unsigned char private_key[DKGEN_P256_PUB_LEN]; /* Large enough for either */
    size_t private_len;
    unsigned char public_key[DKGEN_P256_PUB_LEN];
    size_t public_len;
} dkgen_asym_out_t;

/* Holds raw symmetric derived keys */
typedef struct {
    unsigned char key[32];
    size_t len;
} dkgen_sym_out_t;

/**
 * Derives keys using the specified algorithm profile.
 */
dkgen_result_t dkgen_derive(
    dkgen_algo_t algo,
    const unsigned char seed[DKGEN_SEED_LEN],
    const unsigned char salt[DKGEN_SALT_LEN],
    dkgen_sym_out_t *sym_out,
    dkgen_asym_out_t *asym_out
);

/**
 * Helper utility to get a string description of errors.
 */
const char *dkgen_strerror(dkgen_result_t result);

#endif /* DKGEN_H */
