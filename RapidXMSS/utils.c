#include "utils.h"

/**
 * Converts the value of 'in' to 'outlen' bytes in big-endian byte order.
 */
void ull_to_bytes(uint8_t *out,
                  uint32_t outlen,
                  uint64_t in)
{
    /* Iterate over out in decreasing order, for big-endianness. */
    for (int i = outlen - 1; i >= 0; i--) {
        out[i] = in & 0xff;
        in = in >> 8;
    }
}

/**
 * Converts the inlen bytes in 'in' from big-endian byte order to an integer.
 */
uint64_t bytes_to_ull(const uint8_t *in, uint32_t inlen)
{
    uint64_t retval = 0;

    for (int i = 0; i < inlen; i++) {
        retval |= ((uint64_t)in[i]) << (8*(inlen - 1 - i));
    }
    return retval;
}
