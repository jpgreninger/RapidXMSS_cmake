#ifndef XMSS_PARAMS_H
#define XMSS_PARAMS_H

#include <stdint.h>

/* Use the original method from the RFC */
#define ORIG 0

/*
 * Use the hash precomputation trick as described in:
 * Cryptology ePrint Archive: Report 2020/470
 * LMS vs XMSS: Comparison of Stateful Hash-Based Signature Schemes on ARM Cortex-M4
 * Fabio Campos and Tim Kohlstadt and Steffen Reith and Marc Stoettinger
 */
#define PRECOMP 1

#define PRINT_SIGN  0
#define VERIFY_ONLY 0

#if PRINT_SIGN
#define DO_SIGN     1
#define PRINT_SIGN  1
#define USE_SIGN    0
#define VERIFY_ONLY 0
#endif

#if VERIFY_ONLY
#define DO_SIGN     0
#define PRINT_SIGN  0
#define USE_SIGN    1
#define PRINT_SIGN  0
#endif

#if ORIG
#define COUNTER    0
#define DO_SIGN    1
#define USE_SIGN   0
#define PRINT_SIGN 0
#else
#define COUNTER 1
#endif

#if (VERIFY_ONLY == 0 && PRINT_SIGN == 0)
#define DO_SIGN    1
#define USE_SIGN   0
#endif

/* These are merely internal identifiers for the supported hash functions. */
#define XMSS_SHA2 0
#define XMSS_SHAKE 1

/* This is a result of the OID definitions in the draft; needed for parsing. */
#define XMSS_OID_LEN 4

/* This structure will be populated when calling xmss[mt]_parse_oid. */
typedef struct {
    uint32_t func;
    uint32_t n;
    uint32_t wots_w;
    uint32_t wots_log_w;
    uint32_t wots_len1;
    uint32_t wots_len2;
    uint32_t wots_len;
    uint32_t wots_sig_bytes;
    uint32_t full_height;
    uint32_t tree_height;
    uint32_t d;
    uint32_t index_bytes;
    uint32_t sig_bytes;
    uint32_t pk_bytes;
    uint64_t sk_bytes;
    uint32_t bds_k;
} xmss_params;

/**
 * Accepts strings such as "XMSS-SHA2_10_256"
 *  and outputs OIDs such as 0x01000001.
 * Returns -1 when the parameter set is not found, 0 otherwise
 */
int xmss_str_to_oid(uint32_t *oid, const char *s);

/**
 * Accepts takes strings such as "XMSSMT-SHA2_20/2_256"
 *  and outputs OIDs such as 0x01000001.
 * Returns -1 when the parameter set is not found, 0 otherwise
 */
int xmssmt_str_to_oid(uint32_t *oid, const char *s);

/**
 * Accepts OIDs such as 0x01000001, and configures params accordingly.
 * Returns -1 when the OID is not found, 0 otherwise.
 */
int xmss_parse_oid(xmss_params *params, const uint32_t oid);

/**
 * Accepts OIDs such as 0x01000001, and configures params accordingly.
 * Returns -1 when the OID is not found, 0 otherwise.
 */
int xmssmt_parse_oid(xmss_params *params, const uint32_t oid);


/* Given a params struct where the following properties have been initialized;
    - full_height; the height of the complete (hyper)tree
    - n; the number of bytes of hash function output
    - d; the number of layers (d > 1 implies XMSSMT)
    - func; one of {XMSS_SHA2, XMSS_SHAKE}
    - wots_w; the Winternitz parameter
    - optionally, bds_k; the BDS traversal trade-off parameter,
    this function initializes the remainder of the params structure. */
int xmss_xmssmt_initialize_params(xmss_params *params);

#endif
