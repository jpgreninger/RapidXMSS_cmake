#include <stdint.h>
#include <string.h>

#include "hash_address.h"
#include "utils.h"
#include "params.h"
#include "hash.h"
#include "fips202.h"

#define XMSS_HASH_PADDING_F 0
#define XMSS_HASH_PADDING_H 1
#define XMSS_HASH_PADDING_HASH 2
#define XMSS_HASH_PADDING_PRF 3

#if PRECOMP
#define PRF prf_precomp
#else
#define PRF prf
#endif

void addr_to_bytes(uint8_t *bytes, const uint32_t addr[8])
{
  int i;
  for (i = 0; i < 8; i++) {
    ull_to_bytes(bytes + i * 4, 4, addr[i]);
  }
}

static int core_hash(const xmss_params *params,
                     uint8_t *out,
                     const uint8_t *in,
                     uint64_t inlen)
{
  if (params->n == 32 && params->func == XMSS_SHA2) {
    SHA256(in, inlen, out);
  }
  else {
    return -1;
  }
  return 0;
}

#if PRECOMP
/*
* Computes PRF(key, in), for a key of params->n bytes, and a 32-byte input.
*/
int prf_precomp(const xmss_params *params,
                uint8_t *out,
                const uint8_t in[32],
                const uint8_t *key)
{
  static uint8_t buf[2 * 32 + 32];
  static int init = 1;
  static sha256ctx state1, state2;

  if (init) {
    init = 0;

    sha256_inc_init(&state1);
    sha256_inc_init(&state2);

    ull_to_bytes(buf, params->n, XMSS_HASH_PADDING_PRF);
    memcpy(buf + params->n, key, params->n);
    memcpy(buf + 2 * params->n, in, 32);

    sha256_inc_blocks(&state1, buf, 1);
  }
  else {
    memcpy(buf + 2 * params->n, in, 32);
  }

  memcpy(state2.ctx, state1.ctx, PQC_SHA256CTX_BYTES);
  sha256_inc_finalize(out, &state1, buf + 2 * params->n, 32);
  memcpy(state1.ctx, state2.ctx, PQC_SHA256CTX_BYTES);
  return 1;
}
#endif

int prf(const xmss_params *params,
        uint8_t *out,
        const uint8_t in[32],
        const uint8_t *key)
{
  uint8_t buf[2 * 32 + 32];
  ull_to_bytes(buf, params->n, XMSS_HASH_PADDING_PRF);
  memcpy(buf + params->n, key, params->n);
  memcpy(buf + 2 * params->n, in, 32);

  return core_hash(params, out, buf, 2 * params->n + 32);
}

/*
* Computes the message hash using R, the public root, the index of the leaf
* node, and the message. Notably, it requires m_with_prefix to have 4*n bytes
* of space before the message, to use for the prefix. This is necessary to
* prevent having to move the message around (and thus allocate memory for it).
*/
int hash_message(const xmss_params *params,
                 uint8_t *out,
                 const uint8_t *R,
                 const uint8_t *root,
                 uint64_t idx,
                 uint8_t *m_with_prefix,
                 uint64_t mlen)
{
  /* We're creating a hash using input of the form:
  toByte(X, 32) || R || root || index || M */
  ull_to_bytes(m_with_prefix, params->n, XMSS_HASH_PADDING_HASH);
  memcpy(m_with_prefix + params->n, R, params->n);
  memcpy(m_with_prefix + 2 * params->n, root, params->n);
  ull_to_bytes(m_with_prefix + 3 * params->n, params->n, idx);

  return core_hash(params, out, m_with_prefix, mlen + 4 * params->n);
}

/**
* We assume the left half is in in[0]...in[n-1]
*/
int thash_h(const xmss_params *params,
            uint8_t *out,
            const uint8_t *in,
            const uint8_t *pub_seed,
            uint32_t addr[8])
{
  uint8_t buf[4 * params->n];
  uint8_t bitmask[2 * params->n];
  uint8_t addr_as_bytes[32];
  uint32_t i;

  /* Set the function padding. */
  ull_to_bytes(buf, params->n, XMSS_HASH_PADDING_H);

  /* Generate the n-byte key. */
  set_key_and_mask(addr, 0);
  addr_to_bytes(addr_as_bytes, addr);

  PRF(params, buf + params->n, addr_as_bytes, pub_seed);

  /* Generate the 2n-byte mask. */
  set_key_and_mask(addr, 1);
  addr_to_bytes(addr_as_bytes, addr);

  PRF(params, bitmask, addr_as_bytes, pub_seed);

  set_key_and_mask(addr, 2);
  addr_to_bytes(addr_as_bytes, addr);

  PRF(params, bitmask + params->n, addr_as_bytes, pub_seed);

  for (i = 0; i < 2 * params->n; i++) {
    buf[2 * params->n + i] = in[i] ^ bitmask[i];
  }
  return core_hash(params, out, buf, 4 * params->n);
}

int thash_f(const xmss_params *params,
            uint8_t *out,
            const uint8_t *in,
            const uint8_t *pub_seed,
            uint32_t addr[8])
{
  uint8_t buf[3 * params->n];
  uint8_t bitmask[params->n];
  uint8_t addr_as_bytes[32];
  uint32_t i;

  /* Set the function padding. */
  ull_to_bytes(buf, params->n, XMSS_HASH_PADDING_F);

  /* Generate the n-byte key. */
  set_key_and_mask(addr, 0);
  addr_to_bytes(addr_as_bytes, addr);

  PRF(params, buf + params->n, addr_as_bytes, pub_seed);

  /* Generate the n-byte mask. */
  set_key_and_mask(addr, 1);
  addr_to_bytes(addr_as_bytes, addr);

  PRF(params, bitmask, addr_as_bytes, pub_seed);

  for (i = 0; i < params->n; i++) {
    buf[2 * params->n + i] = in[i] ^ bitmask[i];
  }
  return core_hash(params, out, buf, 3 * params->n);
}
