/*
 * rsa_perf_test.c
 *
 * performance test for rsa
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#if !defined( __RTOS_LINUX__) && !defined( __RTOS_OSX__) && !defined(__RTOS_CYGWIN__) && !defined(__RTOS_IRIX__) && !defined (__RTOS_SOLARIS__) && !defined (__RTOS_OPENBSD__)
#error Timing Performance test only for linux, darwin, cygwin, irix, solaris, openbsd
#endif

/* ans1 redefine in parseasn1.h doesn't work, redefine here */
#ifdef __ENABLE_PERF_TEST_OPENSSL__
#define ASN1_ITEM MOC_ASN1_ITEM
#endif

#include "../../common/initmocana.h"
#include "../../common/random.h"
#include "../../common/vlong.h"
#include "../../common/mstdlib.h"
#include "../../crypto/mocasym.h"
#include "../../crypto/rsa.h"
#include "../../crypto/sha1.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../../crypto_interface/crypto_interface_rsa.h"
#endif

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

static MocCtx gpMocCtx = NULL;

#include <stdio.h>
#include <sys/types.h>
#include <sys/times.h>
#include <unistd.h>
#include <signal.h>

#ifdef __ENABLE_PERF_TEST_OPENSSL__
#undef ASN1_ITEM
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#endif

static volatile int mContinueTest;

#ifndef TEST_SECONDS
#define TEST_SECONDS (3)
#endif

#ifndef PRIME_TEST_SEC
#define PRIME_TEST_SEC 60  /*(180*60)*/
#endif

#define START_ALARM(secs) { signal(SIGALRM, stop_test); \
mContinueTest = 1;          \
alarm(secs);                }

#define ALARM_OFF         (mContinueTest)

/*------------------------------------------------------------------*/
/* SIGALRM signal handler */
static void stop_test( int sig)
{
    (void) sig; /* to get rid of unused warnings */
    mContinueTest = 0;
}

/* Copy of genr1r2Length from rsa.c */
static MSTATUS
genr1r2Length(randomContext *pRandomContext,
              ubyte4 nlen, ubyte4 *pRetR1Len, ubyte4 *pRetR2Len,
              MSTATUS (*completeDigest)(const ubyte *pData, ubyte4 dataLen, ubyte *pDigestOutput),
              ubyte4 hashResultSize)
{
    ubyte*  pRngBuf = NULL;
    ubyte4  minLen;
    ubyte4  maxLen;
    ubyte4  r1Len = 0;
    ubyte4  r2Len = 0;
    MSTATUS status;

    if (OK != (status = DIGI_MALLOC((void **)&pRngBuf, hashResultSize)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pRngBuf);

    /* FIPS 186-4 table B.1 */
    if (3072 <= nlen)
    {
        minLen = 170;
        maxLen = 1518;
    }
    else if (2048 <= nlen)
    {
        minLen = 140;
        maxLen = 1007;
    }
    else if (1024 <= nlen)
    {
        minLen = 100;
        maxLen = 496;
    }
    else
    {
        status = ERR_RSA_KEY_LENGTH_TOO_SMALL;
        goto exit;
    }

    /* generate random len */
    do
    {
        if (OK > (status = RANDOM_numberGenerator(pRandomContext, pRngBuf, hashResultSize)))
            goto exit;

        if (OK > (status = completeDigest(MOC_HASH(hwAccelCtx) pRngBuf, hashResultSize, pRngBuf)))
            goto exit;

        r1Len  = pRngBuf[0] ^ pRngBuf[hashResultSize - 1]; r1Len <<= 8;
        r1Len |= pRngBuf[1] ^ pRngBuf[hashResultSize - 2]; r1Len <<= 8;
        r1Len |= pRngBuf[2] ^ pRngBuf[hashResultSize - 3]; r1Len <<= 8;
        r1Len |= pRngBuf[3] ^ pRngBuf[hashResultSize - 4];

        r2Len  = pRngBuf[4] ^ pRngBuf[0]; r2Len <<= 8;
        r2Len |= pRngBuf[5] ^ pRngBuf[1]; r2Len <<= 8;
        r2Len |= pRngBuf[6] ^ pRngBuf[2]; r2Len <<= 8;
        r2Len |= pRngBuf[7] ^ pRngBuf[3];

        r1Len %= (maxLen - minLen + pRngBuf[8]);
        r2Len %= (maxLen - pRngBuf[9]);
    }
    while ((maxLen <= (r1Len + r2Len)) || (minLen >= r1Len) || (minLen >= r2Len));

    if (OK > (status = DIGI_MEMSET(pRngBuf, 0x00, hashResultSize)))
        goto exit;

    *pRetR1Len = r1Len;
    *pRetR2Len = r2Len;

exit:
    DIGI_FREE((void**) &pRngBuf);

    return status;
}

#define PREDEFINED_E        (65537)

static int perfTestPrimeGen(ubyte4 primeSize, randomContext *pRandomContext, ubyte4 testSec)
{
    vlong *pP = NULL;
    vlong *pX = NULL;
    vlong *pX1 = NULL;
    vlong *pX2 = NULL;
    vlong *pE = NULL;
    intBoolean  isFail = TRUE;
    ubyte4      r1Len = 0;
    ubyte4      r2Len = 0;
    ubyte*      pInputSeed = NULL;
    ubyte4      inputSeedLength = 64; /* from rsa.c */
    ubyte4      keySize = primeSize * 2;
    MSTATUS     status;

    struct tms tstart, tend;
    double diffTime;
    ubyte4 counter = 0;

    if (OK > (status = VLONG_makeVlongFromUnsignedValue(PREDEFINED_E, &pE, NULL)))
        goto exit;

    if (OK > (status = genr1r2Length(pRandomContext, keySize, &r1Len, &r2Len, SHA1_completeDigest, SHA1_RESULT_SIZE)))
        goto exit;

    if (OK != (status = DIGI_MALLOC((void **)&pInputSeed, inputSeedLength)))
        goto exit;

    if (0 == testSec)
    {
        if (primeSize >= 4096)
        {
            testSec = 180 * TEST_SECONDS;
        }
        else if (primeSize >= 3072)
        {
            testSec = 90 * TEST_SECONDS;
        }
        else if (primeSize >= 2048)
        {
            testSec = 40 * TEST_SECONDS;
        }
        else if (primeSize >= 1536)
        {
            testSec = 20 * TEST_SECONDS;
        }
        else
        {
            testSec = 10 * TEST_SECONDS;
        }
    }

    /* key gen is much slower, run more time */
    START_ALARM(testSec);
    times(&tstart);
    while( ALARM_OFF)
    {
        do
        {
            /* We don't check status in the timed steps */
            RANDOM_numberGenerator(pRandomContext, pInputSeed, inputSeedLength);

            VLONG_freeVlong(&pP, NULL);
            VLONG_freeVlong(&pX1, NULL);
            VLONG_freeVlong(&pX2, NULL);
            VLONG_freeVlong(&pX, NULL);

            RSA_generateKeyFipsSteps(pRandomContext, keySize, pE, NULL, r1Len, r2Len, &pX1, &pX2, &pX, &pP,
                                     pInputSeed, inputSeedLength, NULL, NULL,
                                     &isFail, SHA1_completeDigest, SHA1_RESULT_SIZE, NULL);
        }
        while (TRUE == isFail);

        counter++;
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);

    printf("TESTING RSA Prime Generation, %d bits\n", primeSize);
    
    printf("Result:\n\t%d primes in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g primes/second\n\n", counter/diffTime);

exit:

    VLONG_freeVlong(&pP, NULL);
    VLONG_freeVlong(&pX1, NULL);
    VLONG_freeVlong(&pX2, NULL);
    VLONG_freeVlong(&pX, NULL);
    VLONG_freeVlong(&pE, NULL);
    DIGI_FREE((void**) &pInputSeed);
    
    if (OK == status)
        return 0;
    return 1;
}

#ifdef __ENABLE_PERF_TEST_OPENSSL__
int ossl_rsa_sp800_56b_generate_key(RSA *rsa, int nbits, const BIGNUM *efixed, BN_GENCB *cb);
int ossl_bn_rsa_fips186_4_gen_prob_primes(BIGNUM *p, BIGNUM *Xpout,
                                          BIGNUM *p1, BIGNUM *p2,
                                          const BIGNUM *Xp, const BIGNUM *Xp1,
                                          const BIGNUM *Xp2, int nlen,
                                          const BIGNUM *e, BN_CTX *ctx,
                                          BN_GENCB *cb);

static int perfTestPrime1864OSSL(ubyte4 primeSize, ubyte4 testSec)
{
    BIGNUM *p = NULL;
    BIGNUM *Xpout = NULL;
    int nlen = (int) (primeSize * 2);
    BIGNUM *e = NULL;
    BN_CTX *ctx = NULL;

    struct tms tstart, tend;
    double diffTime;
    ubyte4 counter = 0;

    ctx = BN_CTX_new();
    e = BN_new();
    BN_set_word(e, PREDEFINED_E);

    START_ALARM(testSec);
    times(&tstart);
    while( ALARM_OFF)
    {
        BN_free(p);
        BN_free(Xpout);
        p = BN_new();
        Xpout = BN_new();
        ossl_bn_rsa_fips186_4_gen_prob_primes(p, Xpout, NULL, NULL, NULL, NULL, NULL, nlen, e, ctx, NULL);
        counter++;
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);

    printf("TESTING OSSL Prime Generation, %d bits\n", primeSize);
    
    printf("Result:\n\t%d primes in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g primes/second\n\n", counter/diffTime);

    BN_free(p);
    BN_free(e);
    BN_free(Xpout);
    BN_CTX_free(ctx);

    return 0;
}

static int perfTestKeyGenOSSL(ubyte4 primeSize, ubyte4 testSec)
{
    RSA *rsa = NULL;
    int keySize = (int) (primeSize * 2);

    struct tms tstart, tend;
    double diffTime;
    ubyte4 counter = 0;

    START_ALARM(testSec);
    times(&tstart);
    while( ALARM_OFF)
    {
        RSA_free(rsa);
        rsa = RSA_new();
        ossl_rsa_sp800_56b_generate_key(rsa, keySize, NULL, NULL);
        counter++;
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);

    printf("TESTING OSSL Key Generation, %d bits\n", keySize);
    
    printf("Result:\n\t%d keys in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g primes/second\n\n", counter/diffTime);

    RSA_free(rsa);

    return 0;
}

static int perfTestPrimeGenOSSL(ubyte4 primeSize, ubyte4 testSec, ubyte4 safe)
{
    BIGNUM *pPrime = NULL;

    struct tms tstart, tend;
    double diffTime;
    ubyte4 counter = 0;

    START_ALARM(testSec);
    times(&tstart);
    while( ALARM_OFF)
    {
        BN_free(pPrime);
        pPrime = BN_new();
        BN_generate_prime_ex(pPrime, (int) primeSize, (int) safe, NULL, NULL, NULL);
        counter++;
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);

    printf("TESTING OSSL Prime Generation, %d bits\n", primeSize);
    
    printf("Result:\n\t%d primes in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g primes/second\n\n", counter/diffTime);

    BN_free(pPrime);

    return 0;
}
#endif

static int perfTestKeyGen(ubyte4 keySize, randomContext *pRandomContext)
{
    RSAKey *pKey = NULL;
    
    struct tms tstart, tend;
    double diffTime;
    ubyte4 counter = 0;
    
    /* key gen is much slower, run more time */
    START_ALARM(TEST_SECONDS * (4096 == keySize ? 20 : 10));
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_RSA_createKeyAux(&pKey);
        CRYPTO_INTERFACE_RSA_generateKey(pRandomContext, pKey, keySize, NULL);
        CRYPTO_INTERFACE_RSA_freeKeyAux(&pKey, NULL);
#else
        RSA_createKey(&pKey);
        RSA_generateKey(pRandomContext, pKey, keySize, NULL);
        RSA_freeKey(&pKey, NULL);
#endif
        counter++;
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);

    printf("TESTING RSA Key Generation, %d bits\n", keySize);
    
    printf("Result:\n\t%d keys in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g keys/second\n\n", counter/diffTime);

    /* keep pKey as is for future tests */
    
exit:
    
    if (NULL != pKey) /* sanity check */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_RSA_freeKeyAux(&pKey, NULL);
#else
        RSA_freeKey(&pKey, NULL);
#endif

    return 0;
}

static int perfTestEncDec(ubyte4 keySize, RSAKey *pKey, ubyte4 plainLen, randomContext *pRandomContext)
{
    /* max plain size for 4096 bits (including padding) */
    ubyte pPlain[512];
    ubyte pCipher[512];
    ubyte4 cipherLen = keySize/8;
    ubyte4 recLen = 0;
    ubyte4 i;
    
    struct tms tstart, tend;
    double diffTime, kbytes;
    ubyte4 counter = 0;

    /* set the plaintext to something nonzero */
    for (i = 0; i < plainLen; ++i)
        pPlain[i] = (ubyte) (i + 1);

    /* Encrypt */
    pKey->privateKey = FALSE;
    
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_RSA_encryptAux(pKey, pPlain, plainLen, pCipher, RANDOM_rngFun, pRandomContext, NULL);
#else
        RSA_encrypt(pKey, pPlain, plainLen, pCipher, RANDOM_rngFun, pRandomContext, NULL);
#endif
        counter++;
    }

    times(&tend);

    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = plainLen * (counter / 1024.0);
    
    printf("TESTING RSA Encryption, %d bit key, %d byte input\n", keySize, plainLen);
    
    printf("Result:\n\t%d encryptions in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g encryptions/second\n", counter/diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);
    
    /* Decrypt */
    counter = 0;
    pKey->privateKey = TRUE;
    
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status */
        RSA_decrypt(pKey, pCipher, pPlain, &recLen, NULL, NULL, NULL);
        counter++;
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = cipherLen * (counter / 1024.0);
    
    printf("TESTING RSA Decryption, %d bit key, %d byte input\n", keySize, cipherLen);
    
    printf("Result:\n\t%d decryptions in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g decryptions/second\n", counter/diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);
    
    return 0;
}

static int perfTestSignVerify(ubyte4 keySize, RSAKey *pKey, ubyte4 digestLen)
{
    /* big enough for SHA512 digest length, output digest needs full buffer len */
    ubyte pDigest[512];
    ubyte pSig[512];
    ubyte4 recLen = 0;
    ubyte4 i;
    
    struct tms tstart, tend;
    double diffTime, kbytes;
    ubyte4 counter = 0;

    /* set the digest to something nonzero */
    for (i = 0; i < digestLen; ++i)
        pDigest[i] = (ubyte) (i + 1);
    
    /* Sign */
    pKey->privateKey = TRUE;
    
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status, this API actually signs a digest */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_RSA_signMessageAux(pKey, pDigest, digestLen, pSig, NULL);
#else
        RSA_signMessage(pKey, pDigest, digestLen, pSig, NULL);
#endif
        counter++;
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = digestLen * (counter / 1024.0);
    
    printf("TESTING RSA Signs, %d bit key, %d byte digest\n", keySize, digestLen);
    
    printf("Result:\n\t%d signatures in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g signatures/second\n", counter/diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);
    
    /* Verify */
    counter = 0;
    pKey->privateKey = FALSE;
    
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_RSA_verifySignatureAux(pKey, pSig, pDigest, &recLen, NULL);
#else
        RSA_verifySignature(pKey, pSig, pDigest, &recLen, NULL);
#endif
        counter++;
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = digestLen * (counter / 1024.0);
    
    printf("TESTING RSA Verification, %d bit key, %d byte digest\n", keySize, digestLen);
    
    printf("Result:\n\t%d verifications in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g verifications/second\n", counter/diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);
    
    return 0;
}

static int gen_primes(ubyte4 primeSize)
{
    MSTATUS status;
    int retVal = 0;
    randomContext *pRandomContext = NULL;
    
    InitMocanaSetupInfo setupInfo = {
        .MocSymRandOperator = NULL,
        .pOperatorInfo = NULL,
        /**********************************************************
         *************** DO NOT USE MOC_NO_AUTOSEED ***************
         ***************** in any production code. ****************
         **********************************************************/
        .flags = MOC_NO_AUTOSEED,
        .pStaticMem = NULL,
        .staticMemSize = 0,
        .pDigestOperators = NULL,
        .digestOperatorCount = 0,
        .pSymOperators = NULL,
        .symOperatorCount = 0,
        .pKeyOperators = NULL,
        .keyOperatorCount = 0
    };
    
    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    retVal += UNITTEST_INT(__MOC_LINE__, status, OK);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
    
    status = RANDOM_acquireContext(&pRandomContext);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
    
    /* Test prime generation first */
    retVal += perfTestPrimeGen(primeSize, pRandomContext, PRIME_TEST_SEC);

exit:

    if (NULL != pRandomContext)
        RANDOM_releaseContext(&pRandomContext);
    
    DIGICERT_free(&gpMocCtx);
    
    return retVal;
}

int rsa_perf_test_primes_1024()
{
    return gen_primes(1024);
}

int rsa_perf_test_primes_1536()
{
    return gen_primes(1536);
}

int rsa_perf_test_primes_2048()
{
    return gen_primes(2048);
}

int rsa_perf_test_primes_3072()
{
    return gen_primes(3072);
}

int rsa_perf_test_primes_4096()
{
    return gen_primes(4096);
}

int rsa_perf_test_primes_ossl_1024()
{
#ifdef __ENABLE_PERF_TEST_OPENSSL__
    return perfTestPrimeGenOSSL(1024, PRIME_TEST_SEC, 1);
#else
    printf("WARNING: not an openssl comparison build, test rsa_perf_test_primes_ossl_1024 is disabled\n");
    return 0;
#endif
}

int rsa_perf_test_primes_ossl_nonsafe_1024()
{
#ifdef __ENABLE_PERF_TEST_OPENSSL__    
    return perfTestPrimeGenOSSL(1024, PRIME_TEST_SEC, 0);
#else
    printf("WARNING: not an openssl comparison build, test rsa_perf_test_primes_ossl_nonsafe_1024 is disabled\n");
    return 0;
#endif
}

int rsa_perf_test_primes_ossl_1536()
{
#ifdef __ENABLE_PERF_TEST_OPENSSL__
    return perfTestPrimeGenOSSL(1536, PRIME_TEST_SEC, 1);
#else
    printf("WARNING: not an openssl comparison build, test rsa_perf_test_primes_ossl_1536 is disabled\n");
    return 0;
#endif
}

int rsa_perf_test_primes_ossl_2048()
{
#ifdef __ENABLE_PERF_TEST_OPENSSL__    
    return perfTestPrimeGenOSSL(2048, PRIME_TEST_SEC, 1);
#else
    printf("WARNING: not an openssl comparison build, test rsa_perf_test_primes_ossl_2048 is disabled\n");
    return 0;
#endif
}

int rsa_perf_test_ossl_key_gen()
{
#ifdef __ENABLE_PERF_TEST_OPENSSL__    
    return perfTestKeyGenOSSL(2048, PRIME_TEST_SEC);
#else
    printf("WARNING: not an openssl comparison build, test rsa_perf_test_ossl_key_gen is disabled\n");
    return 0;
#endif
}

int rsa_perf_test_ossl_p1864_gen()
{
#ifdef __ENABLE_PERF_TEST_OPENSSL__    
    return perfTestPrime1864OSSL(2048, PRIME_TEST_SEC);
#else
    printf("WARNING: not an openssl comparison build, test rsa_perf_test_ossl_p1864_gen is disabled\n");
    return 0;
#endif
}

int rsa_perf_test_primes_ossl_nonsafe_2048()
{
#ifdef __ENABLE_PERF_TEST_OPENSSL__    
    return perfTestPrimeGenOSSL(2048, PRIME_TEST_SEC, 0);
#else
    printf("WARNING: not an openssl comparison build, test rsa_perf_test_primes_ossl_nonsafe_2048 is disabled\n");
    return 0;
#endif
}

int rsa_perf_test_primes_ossl_3072()
{
#ifdef __ENABLE_PERF_TEST_OPENSSL__
    return perfTestPrimeGenOSSL(3072, PRIME_TEST_SEC, 1);
#else
    printf("WARNING: not an openssl comparison build, test rsa_perf_test_primes_ossl_3072 is disabled\n");
    return 0;
#endif
}

int rsa_perf_test_primes_ossl_4096()
{
#ifdef __ENABLE_PERF_TEST_OPENSSL__
    return perfTestPrimeGenOSSL(4096, PRIME_TEST_SEC, 1);
#else
    printf("WARNING: not an openssl comparison build, test rsa_perf_test_primes_ossl_4096 is disabled\n");
    return 0;
#endif
}

int rsa_perf_test_all()
{
    MSTATUS status;
    int retVal = 0;
    RSAKey *pKey = NULL;
    randomContext *pRandomContext = NULL;
    
    InitMocanaSetupInfo setupInfo = {
        .MocSymRandOperator = NULL,
        .pOperatorInfo = NULL,
        /**********************************************************
         *************** DO NOT USE MOC_NO_AUTOSEED ***************
         ***************** in any production code. ****************
         **********************************************************/
        .flags = MOC_NO_AUTOSEED,
        .pStaticMem = NULL,
        .staticMemSize = 0,
        .pDigestOperators = NULL,
        .digestOperatorCount = 0,
        .pSymOperators = NULL,
        .symOperatorCount = 0,
        .pKeyOperators = NULL,
        .keyOperatorCount = 0
    };
    
    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    retVal += UNITTEST_INT(__MOC_LINE__, status, OK);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
    
    status = RANDOM_acquireContext(&pRandomContext);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
    
    /* Test prime generation first */
    retVal += perfTestPrimeGen(1024, pRandomContext, 0);
    retVal += perfTestPrimeGen(1536, pRandomContext, 0);
    retVal += perfTestPrimeGen(2048, pRandomContext, 0);
#ifdef __ENABLE_LARGE_PRIME_TESTS__
    retVal += perfTestPrimeGen(3072, pRandomContext, 0);
    retVal += perfTestPrimeGen(4096, pRandomContext, 0);
#endif

    /* Test 1024 */
    retVal += perfTestKeyGen(1024, pRandomContext);

    /* create another key for enc/dec/sign/v */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_RSA_createKeyAux(&pKey);
#else
    status = RSA_createKey(&pKey);
#endif
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_RSA_generateKey(pRandomContext, pKey, 1024, NULL);
#else
    status = RSA_generateKey(pRandomContext, pKey, 1024, NULL);
#endif
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

    retVal += perfTestEncDec(1024, pKey, 122, pRandomContext);
    retVal += perfTestSignVerify(1024, pKey, 16);

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_RSA_freeKeyAux(&pKey, NULL);
#else
    status = RSA_freeKey(&pKey, NULL);
#endif
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

    /* Test 2048 */
    retVal += perfTestKeyGen(2048, pRandomContext);
    
    /* create another key for enc/dec/sign/v */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_RSA_createKeyAux(&pKey);
#else
    status = RSA_createKey(&pKey);
#endif
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_RSA_generateKey(pRandomContext, pKey, 2048, NULL);
#else
    status = RSA_generateKey(pRandomContext, pKey, 2048, NULL);
#endif
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

    retVal += perfTestEncDec(2048, pKey, 245, pRandomContext);
    retVal += perfTestSignVerify(2048, pKey, 32);

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_RSA_freeKeyAux(&pKey, NULL);
#else
    status = RSA_freeKey(&pKey, NULL);
#endif
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

    /* Test 3072 */
    retVal += perfTestKeyGen(3072, pRandomContext);

    /* create another key for enc/dec/sign/v */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_RSA_createKeyAux(&pKey);
#else
    status = RSA_createKey(&pKey);
#endif
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_RSA_generateKey(pRandomContext, pKey, 3072, NULL);
#else
    status = RSA_generateKey(pRandomContext, pKey, 3072, NULL);
#endif
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

    retVal += perfTestEncDec(3072, pKey, 373, pRandomContext);
    retVal += perfTestSignVerify(3072, pKey, 48);

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_RSA_freeKeyAux(&pKey, NULL);
#else
    status = RSA_freeKey(&pKey, NULL);
#endif
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_RSA_ALL_KEYSIZE__
    /* Test 4096 */

    retVal += perfTestKeyGen(4096, pRandomContext);

    /* create another key for enc/dec/sign/v */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_RSA_createKeyAux(&pKey);
#else
    status = RSA_createKey(&pKey);
#endif
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_RSA_generateKey(pRandomContext, pKey, 4096, NULL);
#else
    status = RSA_generateKey(pRandomContext, pKey, 4096, NULL);
#endif
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

    retVal += perfTestEncDec(4096, pKey, 501, pRandomContext);
    retVal += perfTestSignVerify(4096, pKey, 64);
#endif

exit:

    if (NULL != pKey)
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_RSA_freeKeyAux(&pKey, NULL);
#else
        RSA_freeKey(&pKey, NULL);
#endif

    if (NULL != pRandomContext)
        RANDOM_releaseContext(&pRandomContext);
    
    DIGICERT_free(&gpMocCtx);
    
    return retVal;
}
