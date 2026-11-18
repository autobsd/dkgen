#ifndef DKGEN_H
#define DKGEN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * dkgen - deterministic key generation from passphrases
 *
 * Derives a private/public key pair from a passphrase, salt, and pepper
 * using the selected algorithm.
 */

/* Algorithm selectors */
typedef enum dkgen_algo {
    DKGEN_ALGO_ED25519     = 0, /* Ed25519 signing key pair                */
    DKGEN_ALGO_P256        = 1, /* NIST P-256 (secp256r1) ECDSA key pair   */
    DKGEN_ALGO_ARGON2ID_20 = 2, /* Argon2id KDF, 20 byte output            */
    DKGEN_ALGO_ARGON2ID_32 = 3  /* Argon2id KDF, 32 byte output            */
} dkgen_algo;

/* Result status codes */
typedef enum dkgen_result {
    DKGEN_OK                 = 0,  /* Success                               */
    DKGEN_ERR_INVALID_ARG    = 1,  /* NULL or invalid argument              */
    DKGEN_ERR_UNKNOWN_ALGO   = 2,  /* Unrecognized algorithm selector       */
    DKGEN_ERR_BUFFER_TOO_SMALL = 3, /* Output buffer too small              */
    DKGEN_ERR_DERIVE         = 4,  /* Underlying derivation failure         */
    DKGEN_ERR_INTERNAL       = 5   /* Internal/unexpected error             */
} dkgen_result;

const char *dkgen_strerror(dkgen_result res);

    
#define DKGEN_ED25519_PRIV_LEN     32
#define DKGEN_ED25519_PUB_LEN      32
#define DKGEN_P256_PRIV_LEN        32
#define DKGEN_P256_PUB_LEN         65
#define DKGEN_ARGON2ID_20_LEN      20
#define DKGEN_ARGON2ID_32_LEN      32
#define DKGEN_MAX_PRIV_LEN         32
#define DKGEN_MAX_PUB_LEN          65

/*
 * dkgen_derive
 *
 * Derive a private/public key pair from a passphrase, salt, and pepper
 * byte string using the given algorithm.
 *
 * Parameters:
 *   algo        - algorithm selector (see dkgen_algo)
 *   passphrase  - passphrase byte string
 *   passphrase_len - length of passphrase in bytes
 *   salt        - salt byte string
 *   salt_len    - length of salt in bytes
 *   pepper      - pepper byte string
 *   pepper_len  - length of pepper in bytes
 *   priv_out    - output buffer for the private key (or KDF output for
 *                 the Argon2id selectors)
 *   priv_len    - in: capacity of priv_out in bytes;
 *                 out: number of bytes written
 *   pub_out     - output buffer for the public key.  For the Argon2id
 *                 selectors (DKGEN_ALGO_ARGON2ID_20 / _32) no public key
 *                 is produced: pub_out is not written; if pub_len is non-NULL,
 *                 pub_len is set to 0.  pub_out may be NULL and
 *                 pub_len may be NULL for these selectors only.
 *   pub_len     - in: capacity of pub_out in bytes;
 *                 out: number of bytes written (0 for Argon2id)
 *
 * Per-algorithm output sizes (required capacity / bytes written):
 *   DKGEN_ALGO_ED25519     priv=32, pub=32
 *   DKGEN_ALGO_P256        priv=32, pub=65
 *   DKGEN_ALGO_ARGON2ID_20 priv=20, pub unused (0)
 *   DKGEN_ALGO_ARGON2ID_32 priv=32, pub unused (0)
 *
 * On failure, *priv_len and *pub_len are left at their caller-supplied
 * values, and any partial private-key material written to priv_out is
 * cleansed before return.
 *
 * Returns:
 *   DKGEN_OK on success, or an error code (see dkgen_result).
 */
dkgen_result dkgen_derive(
    dkgen_algo  algo,
    const uint8_t *passphrase, size_t passphrase_len,
    const uint8_t *salt,     size_t salt_len,
    const uint8_t *pepper,   size_t pepper_len,
    uint8_t       *priv_out, size_t *priv_len,
    uint8_t       *pub_out,  size_t *pub_len);

#ifdef __cplusplus
}
#endif

#endif /* DKGEN_H */
