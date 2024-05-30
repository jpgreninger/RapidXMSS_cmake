#ifndef XMSS_RANDOMBYTES_H
#define XMSS_RANDOMBYTES_H

#include <stdint.h>

/**
 * Tries to read xlen bytes from a source of randomness, and writes them to x.
 */
void randombytes(uint8_t *x, uint64_t xlen);

#endif
