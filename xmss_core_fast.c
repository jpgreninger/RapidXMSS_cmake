#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "hash.h"
#include "hash_address.h"
#include "params.h"
#include "randombytes.h"
#include "wots.h"
#include "utils.h"
#include "xmss_commons.h"
#include "xmss_core.h"

#if PRINT_SIGN
#include <stdio.h>
#endif

typedef struct {
  uint8_t h;
  unsigned long next_idx;
  uint8_t stackusage;
  uint8_t completed;
  uint8_t *node;
} treehash_inst;

typedef struct {
  uint8_t *stack;
  uint32_t stackoffset;
  uint8_t *stacklevels;
  uint8_t *auth;
  uint8_t *keep;
  treehash_inst *treehash;
  uint8_t *retain;
  uint32_t next_leaf;
} bds_state;

uint64_t besti = 0;
uint8_t msg_h_best1[32], msg_h_best2[32];

/* These serialization functions provide a transition between the current
way of storing the state in an exposed struct, and storing it as part of the
byte array that is the secret key.
They will probably be refactored in a non-backwards-compatible way, soon. */

static void xmssmt_serialize_state(const xmss_params *params,
                                   uint8_t *sk,
                                   bds_state *states)
{
  uint32_t i, j;

  /* Skip past the 'regular' sk */
  sk += params->index_bytes + 4 * params->n;

  for (i = 0; i < 2 * params->d - 1; i++) {
    sk += (params->tree_height + 1) * params->n; /* stack */

    ull_to_bytes(sk, 4, states[i].stackoffset);
    sk += 4;

    sk += params->tree_height + 1; /* stacklevels */
    sk += params->tree_height * params->n; /* auth */
    sk += (params->tree_height >> 1) * params->n; /* keep */

    for (j = 0; j < params->tree_height - params->bds_k; j++) {
      ull_to_bytes(sk, 1, states[i].treehash[j].h);
      sk += 1;

      ull_to_bytes(sk, 4, states[i].treehash[j].next_idx);
      sk += 4;

      ull_to_bytes(sk, 1, states[i].treehash[j].stackusage);
      sk += 1;

      ull_to_bytes(sk, 1, states[i].treehash[j].completed);
      sk += 1;

      sk += params->n; /* node */
    }

    /* retain */
    sk += ((1 << params->bds_k) - params->bds_k - 1) * params->n;

    ull_to_bytes(sk, 4, states[i].next_leaf);
    sk += 4;
  }
}

static void xmssmt_deserialize_state(const xmss_params *params,
                                     bds_state *states,
                                     uint8_t **wots_sigs,
                                     uint8_t *sk)
{
  uint32_t i, j;

  /* Skip past the 'regular' sk */
  sk += params->index_bytes + 4 * params->n;

  // TODO These data sizes follow from the (former) test xmss_core_fast.c
  // TODO They should be reconsidered / motivated more explicitly

  for (i = 0; i < 2 * params->d - 1; i++) {
    states[i].stack = sk;
    sk += (params->tree_height + 1) * params->n;

    states[i].stackoffset = bytes_to_ull(sk, 4);
    sk += 4;

    states[i].stacklevels = sk;
    sk += params->tree_height + 1;

    states[i].auth = sk;
    sk += params->tree_height * params->n;

    states[i].keep = sk;
    sk += (params->tree_height >> 1) * params->n;

    for (j = 0; j < params->tree_height - params->bds_k; j++) {
      states[i].treehash[j].h = bytes_to_ull(sk, 1);
      sk += 1;

      states[i].treehash[j].next_idx = bytes_to_ull(sk, 4);
      sk += 4;

      states[i].treehash[j].stackusage = bytes_to_ull(sk, 1);
      sk += 1;

      states[i].treehash[j].completed = bytes_to_ull(sk, 1);
      sk += 1;

      states[i].treehash[j].node = sk;
      sk += params->n;
    }

    states[i].retain = sk;
    sk += ((1 << params->bds_k) - params->bds_k - 1) * params->n;

    states[i].next_leaf = bytes_to_ull(sk, 4);
    sk += 4;
  }

  if (params->d > 1) {
    *wots_sigs = sk;
  }
}

static void xmss_serialize_state(const xmss_params *params,
                                 uint8_t *sk,
                                 bds_state *state)
{
  xmssmt_serialize_state(params, sk, state);
}

static void xmss_deserialize_state(const xmss_params *params,
                                   bds_state *state,
                                   uint8_t *sk)
{
  xmssmt_deserialize_state(params, state, NULL, sk);
}

static void memswap(void *a, void *b, void *t, uint64_t len)
{
  memcpy(t, a, len);
  memcpy(a, b, len);
  memcpy(b, t, len);
}

/**
* Swaps the content of two bds_state objects, swapping actual memory rather
* than pointers.
* As we're mapping memory chunks in the secret key to bds state objects,
* it is now necessary to make swaps 'real swaps'. This could be done in the
* serialization function as well, but that causes more overhead
*/
// TODO this should not be necessary if we keep better track of the states
static void deep_state_swap(const xmss_params *params,
                            bds_state *a,
                            bds_state *b)
{
  // TODO this is extremely ugly and should be refactored
  // TODO right now, this ensures that both 'stack' and 'retain' fit
  uint8_t t[
    ((params->tree_height + 1) > ((1 << params->bds_k) - params->bds_k - 1)
      ? (params->tree_height + 1)
      : ((1 << params->bds_k) - params->bds_k - 1))
      * params->n];
  uint32_t i;

  memswap(a->stack, b->stack, t, (params->tree_height + 1) * params->n);
  memswap(&a->stackoffset, &b->stackoffset, t, sizeof(a->stackoffset));
  memswap(a->stacklevels, b->stacklevels, t, params->tree_height + 1);
  memswap(a->auth, b->auth, t, params->tree_height * params->n);
  memswap(a->keep, b->keep, t, (params->tree_height >> 1) * params->n);

  for (i = 0; i < params->tree_height - params->bds_k; i++) {
    memswap(&a->treehash[i].h, &b->treehash[i].h, t, sizeof(a->treehash[i].h));
    memswap(&a->treehash[i].next_idx, &b->treehash[i].next_idx, t, sizeof(a->treehash[i].next_idx));
    memswap(&a->treehash[i].stackusage, &b->treehash[i].stackusage, t, sizeof(a->treehash[i].stackusage));
    memswap(&a->treehash[i].completed, &b->treehash[i].completed, t, sizeof(a->treehash[i].completed));
    memswap(a->treehash[i].node, b->treehash[i].node, t, params->n);
  }

  memswap(a->retain, b->retain, t, ((1 << params->bds_k) - params->bds_k - 1) * params->n);
  memswap(&a->next_leaf, &b->next_leaf, t, sizeof(a->next_leaf));
}

static int treehash_minheight_on_stack(const xmss_params *params,
                                       bds_state *state,
                                       const treehash_inst *treehash)
{
  uint32_t r = params->tree_height, i;

  for (i = 0; i < treehash->stackusage; i++) {
    if (state->stacklevels[state->stackoffset - i - 1] < r) {
      r = state->stacklevels[state->stackoffset - i - 1];
    }
  }
  return r;
}

/**
* Merkle's TreeHash algorithm. The address only needs to initialize the first 78 bits of addr. Everything else will be set by treehash.
* Currently only used for key generation.
*
*/
static void treehash_init(const xmss_params *params,
                          uint8_t *node,
                          int height,
                          int index,
                          bds_state *state,
                          const uint8_t *sk_seed,
                          const uint8_t *pub_seed,
                          const uint32_t addr[8])
{
  uint32_t idx = index;
  // use three different addresses because at this point we use all three formats in parallel
  uint32_t ots_addr[8] = { 0 };
  uint32_t ltree_addr[8] = { 0 };
  uint32_t node_addr[8] = { 0 };
  // only copy layer and tree address parts
  copy_subtree_addr(ots_addr, addr);
  // type = ots
  set_type(ots_addr, 0);
  copy_subtree_addr(ltree_addr, addr);
  set_type(ltree_addr, 1);
  copy_subtree_addr(node_addr, addr);
  set_type(node_addr, 2);

  uint32_t lastnode, i;
  uint8_t stack[(height + 1)*params->n];
  uint32_t stacklevels[height + 1];
  uint32_t stackoffset = 0;
  uint32_t nodeh;

  lastnode = idx + (1 << height);

  for (i = 0; i < params->tree_height - params->bds_k; i++) {
    state->treehash[i].h = i;
    state->treehash[i].completed = 1;
    state->treehash[i].stackusage = 0;
  }

  i = 0;
  for (; idx < lastnode; idx++) {
    set_ltree_addr(ltree_addr, idx);
    set_ots_addr(ots_addr, idx);
    gen_leaf_wots(params, stack + stackoffset * params->n, sk_seed, pub_seed, ltree_addr, ots_addr);
    stacklevels[stackoffset] = 0;
    stackoffset++;
    if (params->tree_height - params->bds_k > 0 && i == 3) {
      memcpy(state->treehash[0].node, stack + stackoffset * params->n, params->n);
    }
    while (stackoffset>1 && stacklevels[stackoffset - 1] == stacklevels[stackoffset - 2]) {
      nodeh = stacklevels[stackoffset - 1];
      if (i >> nodeh == 1) {
        memcpy(state->auth + nodeh * params->n, stack + (stackoffset - 1)*params->n, params->n);
      }
      else {
        if (nodeh < params->tree_height - params->bds_k && i >> nodeh == 3) {
          memcpy(state->treehash[nodeh].node, stack + (stackoffset - 1)*params->n, params->n);
        }
        else if (nodeh >= params->tree_height - params->bds_k) {
          memcpy(state->retain + ((1 << (params->tree_height - 1 - nodeh)) + nodeh - params->tree_height + (((i >> nodeh) - 3) >> 1)) * params->n, stack + (stackoffset - 1)*params->n, params->n);
        }
      }
      set_tree_height(node_addr, stacklevels[stackoffset - 1]);
      set_tree_index(node_addr, (idx >> (stacklevels[stackoffset - 1] + 1)));
      thash_h(params, stack + (stackoffset - 2)*params->n, stack + (stackoffset - 2)*params->n, pub_seed, node_addr);
      stacklevels[stackoffset - 2]++;
      stackoffset--;
    }
    i++;
  }

  for (i = 0; i < params->n; i++) {
    node[i] = stack[i];
  }
}

static void treehash_update(const xmss_params *params,
                            treehash_inst *treehash,
                            bds_state *state,
                            const uint8_t *sk_seed,
                            const uint8_t *pub_seed,
                            const uint32_t addr[8])
{
  uint32_t ots_addr[8] = { 0 };
  uint32_t ltree_addr[8] = { 0 };
  uint32_t node_addr[8] = { 0 };
  // only copy layer and tree address parts
  copy_subtree_addr(ots_addr, addr);
  // type = ots
  set_type(ots_addr, 0);
  copy_subtree_addr(ltree_addr, addr);
  set_type(ltree_addr, 1);
  copy_subtree_addr(node_addr, addr);
  set_type(node_addr, 2);

  set_ltree_addr(ltree_addr, treehash->next_idx);
  set_ots_addr(ots_addr, treehash->next_idx);

  uint8_t nodebuffer[2 * params->n];
  uint32_t nodeheight = 0;
  gen_leaf_wots(params, nodebuffer, sk_seed, pub_seed, ltree_addr, ots_addr);
  while (treehash->stackusage > 0 && state->stacklevels[state->stackoffset - 1] == nodeheight) {
    memcpy(nodebuffer + params->n, nodebuffer, params->n);
    memcpy(nodebuffer, state->stack + (state->stackoffset - 1)*params->n, params->n);
    set_tree_height(node_addr, nodeheight);
    set_tree_index(node_addr, (treehash->next_idx >> (nodeheight + 1)));
    thash_h(params, nodebuffer, nodebuffer, pub_seed, node_addr);
    nodeheight++;
    treehash->stackusage--;
    state->stackoffset--;
  }
  if (nodeheight == treehash->h) { // this also implies stackusage == 0
    memcpy(treehash->node, nodebuffer, params->n);
    treehash->completed = 1;
  }
  else {
    memcpy(state->stack + state->stackoffset*params->n, nodebuffer, params->n);
    treehash->stackusage++;
    state->stacklevels[state->stackoffset] = nodeheight;
    state->stackoffset++;
    treehash->next_idx++;
  }
}

/**
* Performs treehash updates on the instance that needs it the most.
* Returns the updated number of available updates.
**/
static char bds_treehash_update(const xmss_params *params,
                                bds_state *state,
                                uint32_t updates,
                                const uint8_t *sk_seed,
                                uint8_t *pub_seed,
                                const uint32_t addr[8])
{
  uint32_t i, j;
  uint32_t level, l_min, low;
  uint32_t used = 0;

  for (j = 0; j < updates; j++) {
    l_min = params->tree_height;
    level = params->tree_height - params->bds_k;
    for (i = 0; i < params->tree_height - params->bds_k; i++) {
      if (state->treehash[i].completed) {
        low = params->tree_height;
      }
      else if (state->treehash[i].stackusage == 0) {
        low = i;
      }
      else {
        low = treehash_minheight_on_stack(params, state, &(state->treehash[i]));
      }
      if (low < l_min) {
        level = i;
        l_min = low;
      }
    }
    if (level == params->tree_height - params->bds_k) {
      break;
    }
    treehash_update(params, &(state->treehash[level]), state, sk_seed, pub_seed, addr);
    used++;
  }
  return updates - used;
}

/**
* Updates the state (typically NEXT_i) by adding a leaf and updating the stack
* Returns -1 if all leaf nodes have already been processed
**/
static char bds_state_update(const xmss_params *params,
                             bds_state *state,
                             const uint8_t *sk_seed,
                             const uint8_t *pub_seed,
                             const uint32_t addr[8])
{
  uint32_t ltree_addr[8] = { 0 };
  uint32_t node_addr[8] = { 0 };
  uint32_t ots_addr[8] = { 0 };

  uint32_t nodeh;
  int idx = state->next_leaf;
  if (idx == 1 << params->tree_height) {
    return -1;
  }

  // only copy layer and tree address parts
  copy_subtree_addr(ots_addr, addr);
  // type = ots
  set_type(ots_addr, 0);
  copy_subtree_addr(ltree_addr, addr);
  set_type(ltree_addr, 1);
  copy_subtree_addr(node_addr, addr);
  set_type(node_addr, 2);

  set_ots_addr(ots_addr, idx);
  set_ltree_addr(ltree_addr, idx);

  gen_leaf_wots(params, state->stack + state->stackoffset*params->n, sk_seed, pub_seed, ltree_addr, ots_addr);

  state->stacklevels[state->stackoffset] = 0;
  state->stackoffset++;
  if (params->tree_height - params->bds_k > 0 && idx == 3) {
    memcpy(state->treehash[0].node, state->stack + state->stackoffset*params->n, params->n);
  }
  while (state->stackoffset>1 && state->stacklevels[state->stackoffset - 1] == state->stacklevels[state->stackoffset - 2]) {
    nodeh = state->stacklevels[state->stackoffset - 1];
    if (idx >> nodeh == 1) {
      memcpy(state->auth + nodeh * params->n, state->stack + (state->stackoffset - 1)*params->n, params->n);
    }
    else {
      if (nodeh < params->tree_height - params->bds_k && idx >> nodeh == 3) {
        memcpy(state->treehash[nodeh].node, state->stack + (state->stackoffset - 1)*params->n, params->n);
      }
      else if (nodeh >= params->tree_height - params->bds_k) {
        memcpy(state->retain + ((1 << (params->tree_height - 1 - nodeh)) + nodeh - params->tree_height + (((idx >> nodeh) - 3) >> 1)) * params->n, state->stack + (state->stackoffset - 1)*params->n, params->n);
      }
    }
    set_tree_height(node_addr, state->stacklevels[state->stackoffset - 1]);
    set_tree_index(node_addr, (idx >> (state->stacklevels[state->stackoffset - 1] + 1)));
    thash_h(params, state->stack + (state->stackoffset - 2)*params->n, state->stack + (state->stackoffset - 2)*params->n, pub_seed, node_addr);

    state->stacklevels[state->stackoffset - 2]++;
    state->stackoffset--;
  }
  state->next_leaf++;
  return 0;
}

/**
* Returns the auth path for node leaf_idx and computes the auth path for the
* next leaf node, using the algorithm described by Buchmann, Dahmen and Szydlo
* in "Post Quantum Cryptography", Springer 2009.
*/
static void bds_round(const xmss_params *params,
                      bds_state *state,
                      const unsigned long leaf_idx,
                      const uint8_t *sk_seed,
                      const uint8_t *pub_seed,
                      uint32_t addr[8])
{
  uint32_t i;
  uint32_t tau = params->tree_height;
  uint32_t startidx;
  uint32_t offset, rowidx;
  uint8_t buf[2 * params->n];

  uint32_t ots_addr[8] = { 0 };
  uint32_t ltree_addr[8] = { 0 };
  uint32_t node_addr[8] = { 0 };

  // only copy layer and tree address parts
  copy_subtree_addr(ots_addr, addr);
  // type = ots
  set_type(ots_addr, 0);
  copy_subtree_addr(ltree_addr, addr);
  set_type(ltree_addr, 1);
  copy_subtree_addr(node_addr, addr);
  set_type(node_addr, 2);

  for (i = 0; i < params->tree_height; i++) {
    if (!((leaf_idx >> i) & 1)) {
      tau = i;
      break;
    }
  }

  if (tau > 0) {
    memcpy(buf, state->auth + (tau - 1) * params->n, params->n);
    // we need to do this before refreshing state->keep to prevent overwriting
    memcpy(buf + params->n, state->keep + ((tau - 1) >> 1) * params->n, params->n);
  }
  if (!((leaf_idx >> (tau + 1)) & 1) && (tau < params->tree_height - 1)) {
    memcpy(state->keep + (tau >> 1)*params->n, state->auth + tau * params->n, params->n);
  }
  if (tau == 0) {
    set_ltree_addr(ltree_addr, leaf_idx);
    set_ots_addr(ots_addr, leaf_idx);
    gen_leaf_wots(params, state->auth, sk_seed, pub_seed, ltree_addr, ots_addr);
  }
  else {
    set_tree_height(node_addr, (tau - 1));
    set_tree_index(node_addr, leaf_idx >> tau);
    thash_h(params, state->auth + tau * params->n, buf, pub_seed, node_addr);
    for (i = 0; i < tau; i++) {
      if (i < params->tree_height - params->bds_k) {
        memcpy(state->auth + i * params->n, state->treehash[i].node, params->n);
      }
      else {
        offset = (1 << (params->tree_height - 1 - i)) + i - params->tree_height;
        rowidx = ((leaf_idx >> i) - 1) >> 1;
        memcpy(state->auth + i * params->n, state->retain + (offset + rowidx) * params->n, params->n);
      }
    }

    for (i = 0; i < ((tau < params->tree_height - params->bds_k) ? tau : (params->tree_height - params->bds_k)); i++) {
      startidx = leaf_idx + 1 + 3 * (1 << i);
      if (startidx < 1U << params->tree_height) {
        state->treehash[i].h = i;
        state->treehash[i].next_idx = startidx;
        state->treehash[i].completed = 0;
        state->treehash[i].stackusage = 0;
      }
    }
  }
}

/**
* Given a set of parameters, this function returns the size of the secret key.
* This is implementation specific, as varying choices in tree traversal will
* result in varying requirements for state storage.
*
* This function handles both XMSS and XMSSMT parameter sets.
*/
uint64_t xmss_xmssmt_core_sk_bytes(const xmss_params *params)
{
  return params->index_bytes + 4 * params->n
    + (2 * params->d - 1) * (
    (params->tree_height + 1) * params->n
      + 4
      + params->tree_height + 1
      + params->tree_height * params->n
      + (params->tree_height >> 1) * params->n
      + (params->tree_height - params->bds_k) * (7 + params->n)
      + ((1 << params->bds_k) - params->bds_k - 1) * params->n
      + 4
      )
    + (params->d - 1) * params->wots_sig_bytes;
}

/*
* Generates a XMSS key pair for a given parameter set.
* Format sk: [(32bit) idx || SK_SEED || SK_PRF || root || PUB_SEED]
* Format pk: [root || PUB_SEED] omitting algo oid.
*/
int xmss_core_keypair(const xmss_params *params,
                      uint8_t *pk,
                      uint8_t *sk)
{
  uint32_t addr[8] = { 0 };

  // TODO refactor BDS state not to need separate treehash instances
  bds_state state;
  treehash_inst treehash[params->tree_height - params->bds_k];
  state.treehash = treehash;

  xmss_deserialize_state(params, &state, sk);

  state.stackoffset = 0;
  state.next_leaf = 0;

  // Set idx = 0
  sk[0] = 0;
  sk[1] = 0;
  sk[2] = 0;
  sk[3] = 0;
  // Init SK_SEED (n byte) and SK_PRF (n byte)
  randombytes(sk + params->index_bytes, 2 * params->n);

  // Init PUB_SEED (n byte)
  randombytes(sk + params->index_bytes + 3 * params->n, params->n);
  // Copy PUB_SEED to public key
  memcpy(pk + params->n, sk + params->index_bytes + 3 * params->n, params->n);

  // Compute root
  treehash_init(params, pk, params->tree_height, 0, &state, sk + params->index_bytes, sk + params->index_bytes + 3 * params->n, addr);
  // copy root to sk
  memcpy(sk + params->index_bytes + 2 * params->n, pk, params->n);

  /* Write the BDS state into sk. */
  xmss_serialize_state(params, sk, &state);

  return 0;
}

/**
* Signs a message.
* Returns
* 1. an array containing the signature followed by the message AND
* 2. an updated secret key!
*
*/

#if ORIG
/**
* Signs a message.
* Returns
* 1. an array containing the signature followed by the message AND
* 2. an updated secret key!
*
*/
int xmss_core_sign(const xmss_params *params,
                   uint8_t *sk,
                   uint8_t *sm,
                   uint64_t *smlen,
                   const uint8_t *m,
                   uint64_t mlen)
{
  const uint8_t *pub_root = sk + params->index_bytes + 2 * params->n;

  uint16_t i = 0;

  // TODO refactor BDS state not to need separate treehash instances
  bds_state state;
  treehash_inst treehash[params->tree_height - params->bds_k];
  state.treehash = treehash;

  /* Load the BDS state from sk. */
  xmss_deserialize_state(params, &state, sk);

  // Extract SK
  unsigned long idx = ((unsigned long)sk[0] << 24) | ((unsigned long)sk[1] << 16) | ((unsigned long)sk[2] << 8) | sk[3];
  uint8_t sk_seed[params->n];
  memcpy(sk_seed, sk + params->index_bytes, params->n);
  uint8_t sk_prf[params->n];
  memcpy(sk_prf, sk + params->index_bytes + params->n, params->n);
  uint8_t pub_seed[params->n];
  memcpy(pub_seed, sk + params->index_bytes + 3 * params->n, params->n);

  // index as 32 bytes string
  uint8_t idx_bytes_32[32];
  ull_to_bytes(idx_bytes_32, 32, idx);

  // Update SK
  sk[0] = ((idx + 1) >> 24) & 255;
  sk[1] = ((idx + 1) >> 16) & 255;
  sk[2] = ((idx + 1) >> 8) & 255;
  sk[3] = (idx + 1) & 255;
  // Secret key for this non-forward-secure version is now updated.
  // A production implementation should consider using a file handle instead,
  //  and write the updated secret key at this point!

  // Init working params
  uint8_t R[params->n];
  uint8_t msg_h[params->n];
  uint8_t ots_seed[params->n];
  uint32_t ots_addr[8] = { 0 };

  // ---------------------------------
  // Message Hashing
  // ---------------------------------

  // Message Hash:
  // First compute pseudorandom value
  prf(params, R, idx_bytes_32, sk_prf);

  /* Already put the message in the right place, to make it easier to prepend
  * things when computing the hash over the message. */
  memcpy(sm + params->sig_bytes, m, mlen);

  /* Compute the message hash. */
  hash_message(params, msg_h, R, pub_root, idx,
    sm + params->sig_bytes - 4 * params->n, mlen);

  // Start collecting signature
  *smlen = 0;

  // Copy index to signature
  sm[0] = (idx >> 24) & 255;
  sm[1] = (idx >> 16) & 255;
  sm[2] = (idx >> 8) & 255;
  sm[3] = idx & 255;

  sm += 4;
  *smlen += 4;

  // Copy R to signature
  for (i = 0; i < params->n; i++) {
    sm[i] = R[i];
  }

  sm += params->n;
  *smlen += params->n;

  // ----------------------------------
  // Now we start to "really sign"
  // ----------------------------------

  // Prepare Address
  set_type(ots_addr, 0);
  set_ots_addr(ots_addr, idx);

  // Compute seed for OTS key pair
  get_seed(params, ots_seed, sk_seed, ots_addr);

  // Compute WOTS signature
  wots_sign(params, sm, msg_h, ots_seed, pub_seed, ots_addr);

  sm += params->wots_sig_bytes;
  *smlen += params->wots_sig_bytes;

  // the auth path was already computed during the previous round
  memcpy(sm, state.auth, params->tree_height*params->n);

  if (idx < (1U << params->tree_height) - 1) {
    bds_round(params, &state, idx, sk_seed, pub_seed, ots_addr);
    bds_treehash_update(params, &state, (params->tree_height - params->bds_k) >> 1, sk_seed, pub_seed, ots_addr);
  }

  sm += params->tree_height*params->n;
  *smlen += params->tree_height*params->n;

  memcpy(sm, m, mlen);
  *smlen += mlen;

  /* Write the updated BDS state back into sk. */
  xmss_serialize_state(params, sk, &state);

  return 0;
}
#endif

#if COUNTER
/**
* Signs a message.
* Returns
* 1. an array containing the signature followed by the message AND
* 2. an updated secret key!
*
*/
int xmss_core_sign(const xmss_params *params,
                   uint8_t *sk,
                   uint8_t *sm,
                   uint64_t *smlen,
                   const uint8_t *m,
                   uint64_t mlen)
{
  const uint8_t *pub_root = sk + params->index_bytes + 2 * params->n;

  uint64_t i = 0;

  // TODO refactor BDS state not to need separate treehash instances
  bds_state state;
  treehash_inst treehash[params->tree_height - params->bds_k];
  state.treehash = treehash;

  /* Load the BDS state from sk. */
  xmss_deserialize_state(params, &state, sk);

  // Extract SK
  unsigned long idx = ((unsigned long)sk[0] << 24) | ((unsigned long)sk[1] << 16) | ((unsigned long)sk[2] << 8) | sk[3];
  uint8_t sk_seed[params->n];
  memcpy(sk_seed, sk + params->index_bytes, params->n);
  uint8_t sk_prf[params->n];
  memcpy(sk_prf, sk + params->index_bytes + params->n, params->n);
  uint8_t pub_seed[params->n];
  memcpy(pub_seed, sk + params->index_bytes + 3 * params->n, params->n);

  // index as 32 bytes string
  uint8_t idx_bytes_32[32];
  ull_to_bytes(idx_bytes_32, 32, idx);

  // Update SK
  sk[0] = ((idx + 1) >> 24) & 255;
  sk[1] = ((idx + 1) >> 16) & 255;
  sk[2] = ((idx + 1) >> 8) & 255;
  sk[3] = (idx + 1) & 255;
  // Secret key for this non-forward-secure version is now updated.
  // A production implementation should consider using a file handle instead,
  //  and write the updated secret key at this point!

  // Init working params
  uint8_t R[params->n];
  uint8_t msg_h[params->n];
  uint8_t ots_seed[params->n];
  uint32_t ots_addr[8] = { 0 };

  // ---------------------------------
  // Message Hashing
  // ---------------------------------

  // Message Hash:
  // First compute pseudorandom value
  prf(params, R, idx_bytes_32, sk_prf);

  /* Already put the message in the right place, to make it easier to prepend
  * things when computing the hash over the message. */
  memcpy(sm + params->sig_bytes, m, mlen);

  /* Compute the message hash. */

  /* Below the original code from the RDC implementation. */
  //hash_message(params, msg_h, R, pub_root, idx,
  //             (sm + params->sig_bytes - 4*params->n), mlen);

#define XMSS_HASH_PADDING_HASH 2

  ull_to_bytes((sm + params->sig_bytes - 4 * params->n), params->n, XMSS_HASH_PADDING_HASH);
  memcpy((sm + params->sig_bytes - 4 * params->n) + params->n, R, params->n);
  memcpy((sm + params->sig_bytes - 4 * params->n) + 2 * params->n, pub_root, params->n);
  ull_to_bytes((sm + params->sig_bytes - 4 * params->n) + 3 * params->n, params->n, idx);
  *(uint64_t*)(sm + params->sig_bytes + 32) = 0;

  SHA256((sm + params->sig_bytes - 4 * params->n), mlen + 4 * params->n, msg_h);

  /* Number of blocks, hardcoded for this example. */
#define BLOCK 2

  /* Enable or disable the precomputation of the hash blocks. */
#define FASTHASH 1

  {
    uint8_t h2[258 / 8];
    int orig1 = wots_getlengths1(params, msg_h),
        orig2 = wots_getlengths2(params, msg_h),
        new1, new2;

    memcpy(msg_h_best1, msg_h, params->n);
    memcpy(msg_h_best2, msg_h, params->n);

#if FASTHASH
    sha256ctx state1, state2;
    sha256_inc_init(&state1);

    // Message = 32+8 bytes
    // Rest = 128 bytes
    // Total 168 bytes
    // SHA256 has 64 byte blocks so process two blocks first
    sha256_inc_blocks(&state1, (sm + params->sig_bytes - 4 * params->n), BLOCK);
#endif

    /* we already processed counter number 0 */
    for (i = 1; i < ((uint64_t)1 << 10); i++) {
      *(uint64_t*)(sm + params->sig_bytes + 32) = i;
#if FASTHASH
      memcpy(state2.ctx, state1.ctx, PQC_SHA256CTX_BYTES);
      sha256_inc_finalize(h2, &state1, (sm + params->sig_bytes - 4 * params->n) + BLOCK * 64, mlen + 4 * params->n - BLOCK * 64);
      memcpy(state1.ctx, state2.ctx, PQC_SHA256CTX_BYTES);
#else
      /* Do the full hash over and over again */
      SHA256((sm + params->sig_bytes - 4 * params->n), mlen + 4 * params->n, h2);
#endif
      
      new1 = wots_getlengths1(params, h2);
      new2 = wots_getlengths2(params, h2);
      
      /* Keep the l1 and l2 values for reporting. */
      if (new1 > orig1) {
        orig1 = new1;
        memcpy(msg_h_best1, h2, params->n);
      }
      if (new2 > orig2) {
        orig2 = new2;
        besti = i;
        memcpy(msg_h_best2, h2, params->n);
      }
    }

#if 0
    /* Output findings to generate graphs, in real
     * settings this should be commented out.
     */
    {
      int lengths[params->wots_len];
      double sum = 0;

      chain_lengths(params, lengths, msg_h_best1);
      for (i = 0; i < params->wots_len1; i++) {
        printf("%d ", lengths[i]);
        sum += lengths[i];
      }
      printf("%f\n", sum / params->wots_len1);

      sum = 0;
      chain_lengths(params, lengths, msg_h_best2);
      for (i = 0; i < params->wots_len; i++) {
        fprintf(stderr, "%d ", lengths[i]);
        sum += lengths[i];
      }
      fprintf(stderr, "%f\n", sum / params->wots_len);
    }
#endif

#if PRINT_SIGN
    fprintf(stderr, "%d, ", (int)besti);
#endif

    // Copy the winner over
    memcpy(msg_h, msg_h_best2, 256 / 8);
  }

  // Start collecting signature
  *smlen = 0;

  // Copy index to signature
  sm[0] = (idx >> 24) & 255;
  sm[1] = (idx >> 16) & 255;
  sm[2] = (idx >> 8) & 255;
  sm[3] = idx & 255;

  sm += 4;
  *smlen += 4;

  // Copy R to signature
  for (i = 0; i < params->n; i++) {
    sm[i] = R[i];
  }

  sm += params->n;
  *smlen += params->n;

  // ----------------------------------
  // Now we start to "really sign"
  // ----------------------------------

  // Prepare Address
  set_type(ots_addr, 0);
  set_ots_addr(ots_addr, idx);

  // Compute seed for OTS key pair
  get_seed(params, ots_seed, sk_seed, ots_addr);

  // Compute WOTS signature
  wots_sign(params, sm, msg_h, ots_seed, pub_seed, ots_addr);

  sm += params->wots_sig_bytes;
  *smlen += params->wots_sig_bytes;

  // the auth path was already computed during the previous round
  memcpy(sm, state.auth, params->tree_height*params->n);

  if (idx < (1U << params->tree_height) - 1) {
    bds_round(params, &state, idx, sk_seed, pub_seed, ots_addr);
    bds_treehash_update(params, &state, (params->tree_height - params->bds_k) >> 1, sk_seed, pub_seed, ots_addr);
  }

  sm += params->tree_height*params->n;
  *smlen += params->tree_height*params->n;

  memcpy(sm, m, mlen);
  *smlen += mlen;

  /* Write the updated BDS state back into sk. */
  xmss_serialize_state(params, sk, &state);

  return 0;
}
#endif

/*
* Generates a XMSSMT key pair for a given parameter set.
* Format sk: [(ceil(h/8) bit) idx || SK_SEED || SK_PRF || root || PUB_SEED]
* Format pk: [root || PUB_SEED] omitting algo oid.
*/
int xmssmt_core_keypair(const xmss_params *params,
                        uint8_t *pk,
                        uint8_t *sk)
{
  uint8_t ots_seed[params->n];
  uint32_t addr[8] = { 0 };
  uint32_t i;
  uint8_t *wots_sigs;

  // TODO refactor BDS state not to need separate treehash instances
  bds_state states[2 * params->d - 1];
  treehash_inst treehash[(2 * params->d - 1) * (params->tree_height - params->bds_k)];
  for (i = 0; i < 2 * params->d - 1; i++) {
    states[i].treehash = treehash + i * (params->tree_height - params->bds_k);
  }

  xmssmt_deserialize_state(params, states, &wots_sigs, sk);

  for (i = 0; i < 2 * params->d - 1; i++) {
    states[i].stackoffset = 0;
    states[i].next_leaf = 0;
  }

  // Set idx = 0
  for (i = 0; i < params->index_bytes; i++) {
    sk[i] = 0;
  }
  // Init SK_SEED (params->n byte) and SK_PRF (params->n byte)
  randombytes(sk + params->index_bytes, 2 * params->n);

  // Init PUB_SEED (params->n byte)
  randombytes(sk + params->index_bytes + 3 * params->n, params->n);
  // Copy PUB_SEED to public key
  memcpy(pk + params->n, sk + params->index_bytes + 3 * params->n, params->n);

  // Start with the bottom-most layer
  set_layer_addr(addr, 0);
  // Set up state and compute wots signatures for all but topmost tree root
  for (i = 0; i < params->d - 1; i++) {
    // Compute seed for OTS key pair
    treehash_init(params, pk, params->tree_height, 0, states + i, sk + params->index_bytes, pk + params->n, addr);
    set_layer_addr(addr, (i + 1));
    get_seed(params, ots_seed, sk + params->index_bytes, addr);
    wots_sign(params, wots_sigs + i * params->wots_sig_bytes, pk, ots_seed, pk + params->n, addr);
  }
  // Address now points to the single tree on layer d-1
  treehash_init(params, pk, params->tree_height, 0, states + i, sk + params->index_bytes, pk + params->n, addr);
  memcpy(sk + params->index_bytes + 2 * params->n, pk, params->n);

  xmssmt_serialize_state(params, sk, states);

  return 0;
}

/**
* Signs a message.
* Returns
* 1. an array containing the signature followed by the message AND
* 2. an updated secret key!
*
*/
int xmssmt_core_sign(const xmss_params *params,
                     uint8_t *sk,
                     uint8_t *sm,
                     uint64_t *smlen,
                     const uint8_t *m,
                     uint64_t mlen)
{
  const uint8_t *pub_root = sk + params->index_bytes + 2 * params->n;

  uint64_t idx_tree;
  uint32_t idx_leaf;
  uint64_t i, j;
  int needswap_upto = -1;
  uint32_t updates;

  uint8_t sk_seed[params->n];
  uint8_t sk_prf[params->n];
  uint8_t pub_seed[params->n];
  // Init working params
  uint8_t R[params->n];
  uint8_t msg_h[params->n];
  uint8_t ots_seed[params->n];
  uint32_t addr[8] = { 0 };
  uint32_t ots_addr[8] = { 0 };
  uint8_t idx_bytes_32[32];

  uint8_t *wots_sigs;

  // TODO refactor BDS state not to need separate treehash instances
  bds_state states[2 * params->d - 1];
  treehash_inst treehash[(2 * params->d - 1) * (params->tree_height - params->bds_k)];
  for (i = 0; i < 2 * params->d - 1; i++) {
    states[i].treehash = treehash + i * (params->tree_height - params->bds_k);
  }

  xmssmt_deserialize_state(params, states, &wots_sigs, sk);

  // Extract SK
  uint64_t idx = 0;
  for (i = 0; i < params->index_bytes; i++) {
    idx |= ((uint64_t)sk[i]) << 8 * (params->index_bytes - 1 - i);
  }

  memcpy(sk_seed, sk + params->index_bytes, params->n);
  memcpy(sk_prf, sk + params->index_bytes + params->n, params->n);
  memcpy(pub_seed, sk + params->index_bytes + 3 * params->n, params->n);

  // Update SK
  for (i = 0; i < params->index_bytes; i++) {
    sk[i] = ((idx + 1) >> 8 * (params->index_bytes - 1 - i)) & 255;
  }
  // Secret key for this non-forward-secure version is now updated.
  // A production implementation should consider using a file handle instead,
  //  and write the updated secret key at this point!

  // ---------------------------------
  // Message Hashing
  // ---------------------------------

  // Message Hash:
  // First compute pseudorandom value
  ull_to_bytes(idx_bytes_32, 32, idx);
  prf(params, R, idx_bytes_32, sk_prf);

  /* Already put the message in the right place, to make it easier to prepend
  * things when computing the hash over the message. */
  memcpy(sm + params->sig_bytes, m, mlen);

  /* Compute the message hash. */
  hash_message(params, msg_h, R, pub_root, idx,
    sm + params->sig_bytes - 4 * params->n, mlen);

  // Start collecting signature
  *smlen = 0;

  // Copy index to signature
  for (i = 0; i < params->index_bytes; i++) {
    sm[i] = (idx >> 8 * (params->index_bytes - 1 - i)) & 255;
  }

  sm += params->index_bytes;
  *smlen += params->index_bytes;

  // Copy R to signature
  for (i = 0; i < params->n; i++) {
    sm[i] = R[i];
  }

  sm += params->n;
  *smlen += params->n;

  // ----------------------------------
  // Now we start to "really sign"
  // ----------------------------------

  // Handle lowest layer separately as it is slightly different...

  // Prepare Address
  set_type(ots_addr, 0);
  idx_tree = idx >> params->tree_height;
  idx_leaf = (idx & ((1 << params->tree_height) - 1));
  set_layer_addr(ots_addr, 0);
  set_tree_addr(ots_addr, idx_tree);
  set_ots_addr(ots_addr, idx_leaf);

  // Compute seed for OTS key pair
  get_seed(params, ots_seed, sk_seed, ots_addr);

  // Compute WOTS signature
  wots_sign(params, sm, msg_h, ots_seed, pub_seed, ots_addr);

  sm += params->wots_sig_bytes;
  *smlen += params->wots_sig_bytes;

  memcpy(sm, states[0].auth, params->tree_height*params->n);
  sm += params->tree_height*params->n;
  *smlen += params->tree_height*params->n;

  // prepare signature of remaining layers
  for (i = 1; i < params->d; i++) {
    // put WOTS signature in place
    memcpy(sm, wots_sigs + (i - 1)*params->wots_sig_bytes, params->wots_sig_bytes);

    sm += params->wots_sig_bytes;
    *smlen += params->wots_sig_bytes;

    // put AUTH nodes in place
    memcpy(sm, states[i].auth, params->tree_height*params->n);
    sm += params->tree_height*params->n;
    *smlen += params->tree_height*params->n;
  }

  updates = (params->tree_height - params->bds_k) >> 1;

  set_tree_addr(addr, (idx_tree + 1));
  // mandatory update for NEXT_0 (does not count towards h-k/2) if NEXT_0 exists
  if ((1 + idx_tree) * (1 << params->tree_height) + idx_leaf < (1ULL << params->full_height)) {
    bds_state_update(params, &states[params->d], sk_seed, pub_seed, addr);
  }

  for (i = 0; i < params->d; i++) {
    // check if we're not at the end of a tree
    if (!(((idx + 1) & ((1ULL << ((i + 1)*params->tree_height)) - 1)) == 0)) {
      idx_leaf = (idx >> (params->tree_height * i)) & ((1 << params->tree_height) - 1);
      idx_tree = (idx >> (params->tree_height * (i + 1)));
      set_layer_addr(addr, i);
      set_tree_addr(addr, idx_tree);
      if (i == (uint32_t)(needswap_upto + 1)) {
        bds_round(params, &states[i], idx_leaf, sk_seed, pub_seed, addr);
      }
      updates = bds_treehash_update(params, &states[i], updates, sk_seed, pub_seed, addr);
      set_tree_addr(addr, (idx_tree + 1));
      // if a NEXT-tree exists for this level;
      if ((1 + idx_tree) * (1 << params->tree_height) + idx_leaf < (1ULL << (params->full_height - params->tree_height * i))) {
        if (i > 0 && updates > 0 && states[params->d + i].next_leaf < (1ULL << params->full_height)) {
          bds_state_update(params, &states[params->d + i], sk_seed, pub_seed, addr);
          updates--;
        }
      }
    }
    else if (idx < (1ULL << params->full_height) - 1) {
      deep_state_swap(params, states + params->d + i, states + i);

      set_layer_addr(ots_addr, (i + 1));
      set_tree_addr(ots_addr, ((idx + 1) >> ((i + 2) * params->tree_height)));
      set_ots_addr(ots_addr, (((idx >> ((i + 1) * params->tree_height)) + 1) & ((1 << params->tree_height) - 1)));

      get_seed(params, ots_seed, sk + params->index_bytes, ots_addr);
      wots_sign(params, wots_sigs + i * params->wots_sig_bytes, states[i].stack, ots_seed, pub_seed, ots_addr);

      states[params->d + i].stackoffset = 0;
      states[params->d + i].next_leaf = 0;

      updates--; // WOTS-signing counts as one update
      needswap_upto = i;
      for (j = 0; j < params->tree_height - params->bds_k; j++) {
        states[i].treehash[j].completed = 1;
      }
    }
  }

  memcpy(sm, m, mlen);
  *smlen += mlen;

  xmssmt_serialize_state(params, sk, states);

  return 0;
}
