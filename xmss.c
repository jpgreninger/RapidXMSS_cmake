#include <stdint.h>

#include "params.h"
#include "xmss_core.h"

/* This file provides wrapper functions that take keys that include OIDs to
identify the parameter set to be used. After setting the parameters accordingly
it falls back to the regular XMSS core functions. */

int xmss_keypair(uint8_t *pk,
                 uint8_t *sk,
                 const uint32_t oid)
{
    xmss_params params;
    unsigned int i;

    if (xmss_parse_oid(&params, oid)) {
        return -1;
    }
    for (i = 0; i < XMSS_OID_LEN; i++) {
        pk[XMSS_OID_LEN - i - 1] = (oid >> (8 * i)) & 0xFF;
        /* For an implementation that uses runtime parameters, it is crucial
        that the OID is part of the secret key as well;
        i.e. not just for interoperability, but also for internal use. */
        sk[XMSS_OID_LEN - i - 1] = (oid >> (8 * i)) & 0xFF;
    }
    return xmss_core_keypair(&params, pk + XMSS_OID_LEN, sk + XMSS_OID_LEN);
}

int xmss_sign(uint8_t *sk,
              uint8_t *sm,
              uint64_t *smlen,
              const uint8_t *m,
              uint64_t mlen)
{
    xmss_params params;
    uint32_t oid = 0;
    unsigned int i;

    for (i = 0; i < XMSS_OID_LEN; i++) {
        oid |= sk[XMSS_OID_LEN - i - 1] << (i * 8);
    }
    if (xmss_parse_oid(&params, oid)) {
        return -1;
    }
    return xmss_core_sign(&params, sk + XMSS_OID_LEN, sm, smlen, m, mlen);
}

int xmss_sign_open(uint8_t *m,
                   uint64_t *mlen,
                   const uint8_t *sm,
                   uint64_t smlen,
                   const uint8_t *pk)
{
    xmss_params params;
    uint32_t oid = 0;
    unsigned int i;

    for (i = 0; i < XMSS_OID_LEN; i++) {
        oid |= pk[XMSS_OID_LEN - i - 1] << (i * 8);
    }
    if (xmss_parse_oid(&params, oid)) {
        return -1;
    }
    return xmss_core_sign_open(&params, m, mlen, sm, smlen, pk + XMSS_OID_LEN);
}

int xmssmt_keypair(uint8_t *pk,
                   uint8_t *sk,
                   const uint32_t oid)
{
    xmss_params params;
    unsigned int i;

    if (xmssmt_parse_oid(&params, oid)) {
        return -1;
    }
    for (i = 0; i < XMSS_OID_LEN; i++) {
        pk[XMSS_OID_LEN - i - 1] = (oid >> (8 * i)) & 0xFF;
        sk[XMSS_OID_LEN - i - 1] = (oid >> (8 * i)) & 0xFF;
    }
    return xmssmt_core_keypair(&params, pk + XMSS_OID_LEN, sk + XMSS_OID_LEN);
}

int xmssmt_sign(uint8_t *sk,
                uint8_t *sm,
                uint64_t *smlen,
                const uint8_t *m,
                uint64_t mlen)
{
    xmss_params params;
    uint32_t oid = 0;
    unsigned int i;

    for (i = 0; i < XMSS_OID_LEN; i++) {
        oid |= sk[XMSS_OID_LEN - i - 1] << (i * 8);
    }
    if (xmssmt_parse_oid(&params, oid)) {
        return -1;
    }
    return xmssmt_core_sign(&params, sk + XMSS_OID_LEN, sm, smlen, m, mlen);
}

int xmssmt_sign_open(uint8_t *m,
                     uint64_t *mlen,
                     const uint8_t *sm,
                     uint64_t smlen,
                     const uint8_t *pk)
{
    xmss_params params;
    uint32_t oid = 0;
    unsigned int i;

    for (i = 0; i < XMSS_OID_LEN; i++) {
        oid |= pk[XMSS_OID_LEN - i - 1] << (i * 8);
    }
    if (xmssmt_parse_oid(&params, oid)) {
        return -1;
    }
    return xmssmt_core_sign_open(&params, m, mlen, sm, smlen, pk + XMSS_OID_LEN);
}
