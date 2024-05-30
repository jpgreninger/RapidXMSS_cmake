#ifndef XMSS_UTILS_H
#define XMSS_UTILS_H

#include <stdint.h>

/**
 * Converts the value of 'in' to 'outlen' bytes in big-endian byte order.
 */
void ull_to_bytes(uint8_t *out,
                  uint32_t outlen,
                  uint64_t in);

/**
 * Converts the inlen bytes in 'in' from big-endian byte order to an integer.
 */
uint64_t bytes_to_ull(const uint8_t *in, uint32_t inlen);

#endif
