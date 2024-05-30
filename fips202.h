#ifndef XMSS_FIPS202_H
#define XMSS_FIPS202_H

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136

#include <stdint.h>

/* Evaluates SHAKE-128 on `inlen' bytes in `in', according to FIPS-202.
 * Writes the first `outlen` bytes of output to `out`.
 */
void shake128(uint8_t *out,
              uint64_t outlen,
              const uint8_t *in,
              uint64_t inlen);

/* Evaluates SHAKE-256 on `inlen' bytes in `in', according to FIPS-202.
 * Writes the first `outlen` bytes of output to `out`.
 */
void shake256(uint8_t *out,
              uint64_t outlen,
              const uint8_t *in,
              uint64_t inlen);

#endif
