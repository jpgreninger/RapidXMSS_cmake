#ifndef XMSS_WOTS_H
#define XMSS_WOTS_H

#include <stdint.h>
#include "params.h"

/**
 * WOTS key generation. Takes a 32 byte seed for the private key, expands it to
 * a full WOTS private key and computes the corresponding public key.
 * It requires the seed pub_seed (used to generate bitmasks and hash keys)
 * and the address of this WOTS key pair.
 *
 * Writes the computed public key to 'pk'.
 */
void wots_pkgen(const xmss_params *params,
                uint8_t *pk,
                const uint8_t *seed,
                const uint8_t *pub_seed,
                uint32_t addr[8]);

/**
 * Takes a n-byte message and the 32-byte seed for the private key to compute a
 * signature that is placed at 'sig'.
 */
void wots_sign(const xmss_params *params,
               uint8_t *sig,
               const uint8_t *msg,
               const uint8_t *seed,
               const uint8_t *pub_seed,
               uint32_t addr[8]);

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
void wots_pk_from_sig(const xmss_params *params,
                      uint8_t *pk,
                      const uint8_t *sig,
                      const uint8_t *msg,
                      const uint8_t *pub_seed,
                      uint32_t addr[8]);

/**
 * computes LEN1.
 */
int wots_getlengths1(const xmss_params *params, const uint8_t *msg);

/**
 * computes LEN2.
 */
int wots_getlengths2(const xmss_params *params, const uint8_t *msg);

/**
 * computes LEN1+LEN2
 */
void chain_lengths(const xmss_params *params,
                   int *lengths,
                   const uint8_t *msg);

#endif
