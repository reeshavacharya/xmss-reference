#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "../xmss.h"
#include "../params.h"
#include "../randombytes.h"

#define XMSS_MLEN 32

#ifndef NTESTS
#define NTESTS 10
#endif

#ifdef XMSSMT
    #define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_STR_TO_OID xmssmt_str_to_oid
    #define XMSS_KEYPAIR xmssmt_keypair
    #define XMSS_SIGN xmssmt_sign
    #define XMSS_SIGN_OPEN xmssmt_sign_open
    #define XMSS_VARIANT "XMSSMT-SHA2_20/2_256"
#else
    #define XMSS_PARSE_OID xmss_parse_oid
    #define XMSS_STR_TO_OID xmss_str_to_oid
    #define XMSS_KEYPAIR xmss_keypair
    #define XMSS_SIGN xmss_sign
    #define XMSS_SIGN_OPEN xmss_sign_open
    #define XMSS_VARIANT "XMSS-SHA2_10_256"
#endif

int main()
{
    xmss_params params;
    uint32_t oid;
    int ret = 0;
    int i;
    struct timespec start, stop;
    double result;

    printf("Testing variant %s\n", XMSS_VARIANT);
    printf("Running %d iterations\n\n", NTESTS);

    // Set up parameters
    XMSS_STR_TO_OID(&oid, XMSS_VARIANT);
    XMSS_PARSE_OID(&params, oid);

    // Allocate memory for keys and messages
    unsigned char pk[XMSS_OID_LEN + params.pk_bytes];
    unsigned char sk[XMSS_OID_LEN + params.sk_bytes];
    unsigned char *m = malloc(XMSS_MLEN);
    unsigned char *sm = malloc(params.sig_bytes + XMSS_MLEN);
    unsigned char *mout = malloc(params.sig_bytes + XMSS_MLEN);
    unsigned long long smlen;
    unsigned long long mlen;

    // Arrays to store timing results
    double *keygen_times = malloc(sizeof(double) * NTESTS);
    double *sign_times = malloc(sizeof(double) * NTESTS);
    double *verify_times = malloc(sizeof(double) * NTESTS);

    if (!m || !sm || !mout || !keygen_times || !sign_times || !verify_times) {
        printf("Allocation failed!\n");
        return -1;
    }

    // Fill the message with random data
    randombytes(m, XMSS_MLEN);

    // Test iterations
    printf("Running %d iterations...\n", NTESTS);
    
    for (i = 0; i < NTESTS; i++) {
        // Time key generation
        clock_gettime(CLOCK_MONOTONIC, &start);
        ret = XMSS_KEYPAIR(pk, sk, oid);
        clock_gettime(CLOCK_MONOTONIC, &stop);
        if (ret) {
            printf("Keygen failed!\n");
            return -1;
        }
        keygen_times[i] = (stop.tv_sec - start.tv_sec) * 1e3 + 
                         (stop.tv_nsec - start.tv_nsec) / 1e6;

        // Time signing
        clock_gettime(CLOCK_MONOTONIC, &start);
        ret = XMSS_SIGN(sk, sm, &smlen, m, XMSS_MLEN);
        clock_gettime(CLOCK_MONOTONIC, &stop);
        if (ret) {
            printf("Signing failed!\n");
            return -1;
        }
        sign_times[i] = (stop.tv_sec - start.tv_sec) * 1e3 + 
                       (stop.tv_nsec - start.tv_nsec) / 1e6;        // Time verification
        clock_gettime(CLOCK_MONOTONIC, &start);
        ret = XMSS_SIGN_OPEN(mout, &mlen, sm, smlen, pk);
        clock_gettime(CLOCK_MONOTONIC, &stop);
        verify_times[i] = (stop.tv_sec - start.tv_sec) * 1e3 + 
                         (stop.tv_nsec - start.tv_nsec) / 1e6;

        if (ret || mlen != XMSS_MLEN || memcmp(m, mout, XMSS_MLEN)) {
            printf("Verification failed!\n");
            return -1;
        }
    }

    // Calculate and print averages
    double avg_keygen = 0, avg_sign = 0, avg_verify = 0;
    for (i = 0; i < NTESTS; i++) {
        avg_keygen += keygen_times[i];
        avg_sign += sign_times[i];
        avg_verify += verify_times[i];
    }
    avg_keygen /= NTESTS;
    avg_sign /= NTESTS;
    avg_verify /= NTESTS;

    printf("\nResults for %s\n", XMSS_VARIANT);
    printf("Average times over %d iterations:\n", NTESTS);
    printf("Key Generation: %.2f ms\n", avg_keygen);
    printf("Signing:       %.2f ms\n", avg_sign);
    printf("Verification:  %.2f ms\n\n", avg_verify);

    printf("Sizes:\n");
    printf("Signature: %d bytes (%.2f KiB)\n", params.sig_bytes, params.sig_bytes / 1024.0);
    printf("Public key: %d bytes (%.2f KiB)\n", params.pk_bytes, params.pk_bytes / 1024.0);
    printf("Secret key: %llu bytes (%.2f KiB)\n", params.sk_bytes, params.sk_bytes / 1024.0);

    // Clean up
    free(m);
    free(sm);
    free(mout);
    free(keygen_times);
    free(sign_times);
    free(verify_times);

    return 0;
}