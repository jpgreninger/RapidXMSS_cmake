#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "xmss.h"
#include "params.h"
#include "randombytes.h"

/* Include space for the additional counter. */
#define XMSS_MLEN (32+8)

#define XMSS_SIGNATURES 1

#define XMSS_PARSE_OID xmss_parse_oid
#define XMSS_STR_TO_OID xmss_str_to_oid
#define XMSS_KEYPAIR xmss_keypair
#define XMSS_SIGN xmss_sign
#define XMSS_SIGN_OPEN xmss_sign_open
#define XMSS_VARIANT "XMSS-SHA2_10_256"

#if COUNTER
extern uint64_t besti;
#endif

int main()
{
    xmss_params params;
    uint32_t oid;
    int ret = 0;
    int i;

    // TODO test more different variants
    XMSS_STR_TO_OID(&oid, XMSS_VARIANT);
    XMSS_PARSE_OID(&params, oid);

/* Use pre-generated keys or generate them on the fly. */
#define GENKEYS 0
    
#if GENKEYS
    printf("%d and %d bytes.\n", (int)(XMSS_OID_LEN + params.pk_bytes), (int)(XMSS_OID_LEN + params.sk_bytes));

    uint8_t pk[XMSS_OID_LEN + params.pk_bytes];
    uint8_t sk[XMSS_OID_LEN + params.sk_bytes];
#else
#include "keys.h"
#endif
    
    uint8_t *m = malloc(XMSS_MLEN);
    uint8_t *sm = malloc(params.sig_bytes + XMSS_MLEN);
    uint8_t *mout = malloc(params.sig_bytes + XMSS_MLEN);
    uint64_t smlen;
    uint64_t mlen;
    

    // randombytes(m, XMSS_MLEN);
    for (i = 0; i < XMSS_MLEN - 8; i++) m[i] = i;
    for (i = XMSS_MLEN - 8; i < XMSS_MLEN; i++) m[i] = 0;
    
    
#if GENKEYS
    XMSS_KEYPAIR(pk, sk, oid);

    printf("uint8_t pk[%d] = { ", (int)(XMSS_OID_LEN + params.pk_bytes));
    for (i = 0; i < (int)(XMSS_OID_LEN + params.pk_bytes); i++) {
      printf("%d", (int)pk[i]);
      if (i == (int)(XMSS_OID_LEN + params.pk_bytes - 1)) printf(" };\n");
      else printf(", ");
    }

    printf("uint8_t sk[%d] = { ", (int)(XMSS_OID_LEN + params.sk_bytes));
    for (i = 0; i < (int)(XMSS_OID_LEN + params.sk_bytes); i++) {
      printf("%d", (int)sk[i]);
      if (i == (int)(XMSS_OID_LEN + params.sk_bytes - 1)) printf(" };\n");
      else printf(", ");
    }
    return 0;
#endif


#if PRINT_SIGN
    fprintf(stderr, "uint32_t sig_c[100*(2540+1)] = { ");
#endif

#if USE_SIGN
#include "sign.h"
#endif

    for (i = 0; i < 100; i++) {      
        
#if DO_SIGN
        /* For testing one can dump signatures and read them in on an embedded device. */
        XMSS_SIGN(sk, sm, &smlen, m, XMSS_MLEN);
        if (smlen != params.sig_bytes + XMSS_MLEN) {
          printf("  X smlen incorrect [%lu != %u]!\n",
            smlen, params.sig_bytes);
          ret = -1;
        }
        else {
          printf("    smlen as expected [%lu].\n", smlen);
        }
#endif

#if PRINT_SIGN
        for (int j = 0; j < (int)smlen; j++) fprintf(stderr, "%d, ", (int)sm[j]);
#endif

#if USE_SIGN
        // len = 2540
        besti = sig_c[i * 2541 + 0];
        smlen = 2540;
        for (int j = 0; j < 2540; j++) {
          sm[j] = sig_c[i * 2541 + 1 + j];
        }
#endif

        /* Test if signature is valid. */
        if (XMSS_SIGN_OPEN(mout, &mlen, sm, smlen, pk)) {
            printf("  X verification failed!\n");
            ret = -1;
            return ret;
        }
        else {
          printf("    verification succeeded.\n");
        }

        /* Test if the correct message was recovered. */
        if (mlen != XMSS_MLEN) {
            printf("  X mlen incorrect [%lu != %u]!\n", mlen, XMSS_MLEN);
            ret = -1;
            return ret;
        }
        else {
          printf("    mlen as expected [%lu].\n", mlen);
        }
        if (memcmp(m, mout, XMSS_MLEN)) {
            printf("  X output message incorrect!\n");
            ret = -1;
            return ret;
        }
        else {
          printf("    output message as expected.\n");
        }

        /* Test if flipping bits invalidates the signature (it should). */

        /* Flip the first bit of the message. Should invalidate. */
        sm[0] ^= 1;
        if (!XMSS_SIGN_OPEN(mout, &mlen, sm, smlen, pk)) {
            printf("  X flipping a bit of m DID NOT invalidate signature!\n");
            ret = -1;
            return ret;
        }
        else {
          printf("    flipping a bit of m invalidates signature.\n");
        }
        sm[0] ^= 1;

#ifdef XMSS_TEST_INVALIDSIG
        int j;
        /* Flip one bit per hash; the signature is almost entirely hashes.
           This also flips a bit in the index, which is also a useful test. */
        for (j = 0; j < (int)(smlen - XMSS_MLEN); j += params.n) {
            sm[j] ^= 1;
            if (!XMSS_SIGN_OPEN(mout, &mlen, sm, smlen, pk)) {
                printf("  X flipping bit %d DID NOT invalidate sig + m!\n", j);
                sm[j] ^= 1;
                ret = -1;
                break;
            }
            sm[j] ^= 1;
        }
        if (j >= (int)(smlen - XMSS_MLEN)) {
            printf("    changing any signature hash invalidates signature.\n");
        }
#endif
    }

#if PRINT_SIGN
    fprintf(stderr, "}; \n");
#endif


    free(m);
    free(sm);
    free(mout);

    return ret;
}
