#ifndef XMSS_HASH_H
#define XMSS_HASH_H

#include <stdint.h>
#include "params.h"
#include "sha2.h"

#define SHA256(in,inlen,out) sha256(out,in,inlen)

void addr_to_bytes(uint8_t *bytes,
                   const uint32_t addr[8]);

int prf(const xmss_params *params,
        uint8_t *out,
        const uint8_t in[32],
        const uint8_t *key);

int prf2(const xmss_params *params,
         uint8_t *out,
         const uint8_t in[32],
         const uint8_t *key,
         const uint8_t extra[4]);

int h_msg(const xmss_params *params,
          uint8_t *out,
          const uint8_t *in,
          uint64_t inlen,
          const uint8_t *key,
          const uint32_t keylen);

int thash_h(const xmss_params *params,
            uint8_t *out,
            const uint8_t *in,
            const uint8_t *pub_seed,
            uint32_t addr[8]);

int thash_f(const xmss_params *params,
            uint8_t *out,
            const uint8_t *in,
            const uint8_t *pub_seed,
            uint32_t addr[8]);

int hash_message(const xmss_params *params,
                 uint8_t *out,
                 const uint8_t *R,
                 const uint8_t *root,
                 uint64_t idx,
                 uint8_t *m_with_prefix,
                 uint64_t mlen);

#endif
