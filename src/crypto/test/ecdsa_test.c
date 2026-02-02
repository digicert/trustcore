/*
 *  ecdsa_test.c
 *
 *   unit test for ECDSA
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
#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__)
#include <stdio.h>
#include <sys/types.h>
#include <sys/times.h>
#include <unistd.h>
#include <signal.h>
#endif

#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mstdlib.h"
#include "../../common/mrtos.h"
#include "../../common/random.h"
#ifdef __ENABLE_DIGICERT_VLONG_ECC_CONVERSION__
#include "../../common/vlong.h"
#endif
#include "../../common/initmocana.h"
#include "../../crypto/primefld.h"
#include "../../crypto/primeec.h"
#include "../../crypto/sha1.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"
#include "../../../unit_tests/unittest.h"


extern moctime_t gStartTime;


/*------------------------------------------------------------------*/

#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__)

static volatile int mContinueTest;

#ifndef TEST_SECONDS
#define TEST_SECONDS (10)
#endif

#define START_ALARM(secs) { signal(SIGALRM, stop_test); \
                             mContinueTest = 1;          \
                             alarm(secs);                }

#define ALARM_OFF         (mContinueTest)

/*------------------------------------------------------------------*/
/* SIGALRM signal handler */
static void stop_test( int sig)
{
    sig; /* to get rid of unused warnings */
    mContinueTest = 0;
}

#endif   /* defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__)   */


#ifndef __ENABLE_DIGICERT_SMALL_CODE_FOOTPRINT__
/*---------------------------------------------------------------------------*/

static int PrecomputeTest( sbyte4 hint, randomContext* pRandomContext,
                          const ubyte* hash, ubyte4 hashLen,
                          PFEPtr r, PFEPtr s, ECCKey* pNewKey)
{
    int retVal;
    PFEPtr pCurvePC = 0;
    PFEPtr pKeyPC = 0;
    PrimeFieldPtr pPF;
    PFEPtr k = 0, t= 0, u = 0;

    pPF = EC_getUnderlyingField( pNewKey->pCurve);

    if ((retVal = UNITTEST_STATUS(hint, PRIMEFIELD_newElement( pPF, &k))))
        goto exit;

    if ((retVal = UNITTEST_STATUS(hint, PRIMEFIELD_newElement( pPF, &t))))
        goto exit;

    if ((retVal = UNITTEST_STATUS(hint, PRIMEFIELD_newElement( pPF, &u))))
        goto exit;

    if ((retVal = UNITTEST_STATUS(hint, EC_precomputeCombOfCurve( pNewKey->pCurve, 4, &pCurvePC))))
    {
        goto exit;
    }

    if ((retVal = UNITTEST_STATUS(hint, EC_verifyKeyPair( pNewKey->pCurve, pNewKey->k,
                                                        pNewKey->Qx, pNewKey->Qy))))
    {
        goto exit;
    }

    if ((retVal = UNITTEST_STATUS(hint, EC_precomputeComb( pPF, pNewKey->Qx, pNewKey->Qy,
                                                           4, &pKeyPC))))
    {
        goto exit;
    }

    /* verify the signature generated with the normal method */
    retVal += UNITTEST_STATUS(hint, ECDSA_verifySignatureEx( pNewKey->pCurve, pNewKey->Qx, pNewKey->Qy,
                                                            hash, hashLen, 4, pCurvePC, 4, pKeyPC, r, s));

    /* don't use the precompute for the public key */
    retVal += UNITTEST_STATUS(hint, ECDSA_verifySignatureEx( pNewKey->pCurve, pNewKey->Qx, pNewKey->Qy,
                                                            hash, hashLen, 4, pCurvePC, 0, 0, r, s));

    if (UNITTEST_STATUS(hint, ECDSA_signDigestAux( pNewKey->pCurve, pNewKey->k, RANDOM_rngFun,
                                         pRandomContext, hash, hashLen, t, u)))
    {
        ++retVal;
        goto exit;
    }

    retVal += UNITTEST_STATUS(hint, ECDSA_verifySignatureEx( pNewKey->pCurve, pNewKey->Qx, pNewKey->Qy,
                                                            hash, hashLen, 4, pCurvePC, 4, pKeyPC, t, u));

    retVal += UNITTEST_STATUS(hint, ECDSA_verifySignatureEx( pNewKey->pCurve, pNewKey->Qx, pNewKey->Qy,
                                                            hash, hashLen, 4, pCurvePC, 0, 0, t, u));

#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__)
    if ( SHA1_RESULT_SIZE == hashLen)
    {
        struct tms tstart, tend;
        double diffTime;
        int i;

        START_ALARM(TEST_SECONDS);
        times(&tstart);
        for (i = 0; ALARM_OFF; ++i)
        {
            ECDSA_signDigestAux( pNewKey->pCurve, pNewKey->k, RANDOM_rngFun,
                        pRandomContext, hash, SHA1_RESULT_SIZE, t, u);
        }
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);

        printf("\t%d signatures in %g seconds of CPU time \n", i, diffTime);
        printf("Curve P-%d: %g signatures/second (CPU time)\n",
               hint, i/diffTime);

        START_ALARM(TEST_SECONDS);
        times(&tstart);
        for (i = 0; ALARM_OFF; ++i)
        {
            ECDSA_verifySignatureEx( pNewKey->pCurve,
                                    pNewKey->Qx, pNewKey->Qy, hash, SHA1_RESULT_SIZE,
                                    4, pCurvePC, 4, pKeyPC, t, u);
        }
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
        printf("\t%d verifications in %g seconds of CPU time (Comb2 = 4)\n", i, diffTime);
        printf("Curve P-%d: %g verifications/second (CPU time) (Comb2 = 4)\n",
               hint, i/diffTime);

        START_ALARM(TEST_SECONDS);
        times(&tstart);
        for (i = 0; ALARM_OFF; ++i)
        {
            ECDSA_verifySignatureEx( pNewKey->pCurve,
                                    pNewKey->Qx, pNewKey->Qy, hash, SHA1_RESULT_SIZE,
                                    4, pCurvePC, 0, 0, t, u);
        }
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
        printf("\t%d verifications in %g seconds of CPU time (Comb = 4)\n", i, diffTime);
        printf("Curve P-%d: %g verifications/second (CPU time) (Comb = 4)\n",
               hint, i/diffTime);

    }
#endif

exit:

    PRIMEFIELD_deleteElement( pPF, &k);
    PRIMEFIELD_deleteElement( pPF, &t);
    PRIMEFIELD_deleteElement( pPF, &u);
    if ( pCurvePC)
    {
        FREE(pCurvePC);
    }
    if ( pKeyPC)
    {
        FREE(pKeyPC);
    }


    return retVal;
}

#endif

/*------------------------------------------------------------------*/

static int SignatureTest( randomContext* pRandomContext, ECCKey* pNewKey,
                         ubyte* hash, ubyte4 hashSize, int hint)
{
    int retVal = 0;
    PFEPtr r = 0, s = 0;
    PrimeFieldPtr pPF;

    pPF = EC_getUnderlyingField( pNewKey->pCurve);

    if ( retVal = UNITTEST_STATUS( hint, EC_generateKeyPair( pNewKey->pCurve,
            RANDOM_rngFun, pRandomContext, pNewKey->k, pNewKey->Qx, pNewKey->Qy)))
    {
        goto exit;
    }

    if (retVal = UNITTEST_STATUS(hint, PRIMEFIELD_newElement( pPF, &r)))
        goto exit;

    if (retVal = UNITTEST_STATUS(hint, PRIMEFIELD_newElement( pPF, &s)))
        goto exit;

    if (retVal = UNITTEST_STATUS(hint, ECDSA_signDigestAux( pNewKey->pCurve, pNewKey->k, RANDOM_rngFun,
                                     pRandomContext, hash, hashSize,
                                     r, s)))
    {
        goto exit;
    }

    if ( retVal = UNITTEST_STATUS( hint, ECDSA_verifySignature( pNewKey->pCurve,
                                    pNewKey->Qx, pNewKey->Qy, hash, hashSize,
                                    r, s)))
    {
        goto exit;
    }

    /* for linux we do a speed test that will be captured in the logs */
#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__)
    if ( SHA1_RESULT_SIZE == hashSize)
    {
        struct tms tstart, tend;
        double diffTime;
        int i;

        START_ALARM(TEST_SECONDS);
        times(&tstart);
        for (i = 0; ALARM_OFF; ++i)
        {
            ECDSA_signDigestAux( pNewKey->pCurve, pNewKey->k, RANDOM_rngFun,
                        pRandomContext, hash, SHA1_RESULT_SIZE,
                        r, s);
        }
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);

        printf("\n\n\t%d signatures in %g seconds of CPU time\n", i, diffTime);
        printf("Curve P-%d: %g signatures/second (CPU time)\n",
               hint, i/diffTime);

        START_ALARM(TEST_SECONDS);
        times(&tstart);
        for (i = 0; ALARM_OFF; ++i)
        {
            ECDSA_verifySignature( pNewKey->pCurve,
                                   pNewKey->Qx, pNewKey->Qy, hash,
                                   SHA1_RESULT_SIZE, r, s);
        }
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
        printf("\t%d verifications in %g seconds of CPU time\n", i, diffTime);
        printf("Curve P-%d: %g verifications/second (CPU time)\n\n",
               hint, i/diffTime);

    }
#endif

#ifndef __ENABLE_DIGICERT_SMALL_CODE_FOOTPRINT__
    retVal += PrecomputeTest( hint, pRandomContext, hash, hashSize, r , s, pNewKey);
#endif

exit:

    PRIMEFIELD_deleteElement( pPF, &r);
    PRIMEFIELD_deleteElement( pPF, &s);


    return retVal;
}


/*---------------------------------------------------------------------------*/

int CloneTest( int hint, ECCKey* pSrcKey)
{
    int retVal = 0;
    MSTATUS status;
    ECCKey* pCloneKey = 0;
    PrimeFieldPtr pPF;

    pPF = EC_getUnderlyingField( pSrcKey->pCurve);

    if (OK > ( status = EC_cloneKey( &pCloneKey, pSrcKey)))
    {
        retVal += UNITTEST_STATUS( hint, status);
        goto exit;
    }

    retVal += UNITTEST_TRUE( hint, 0 == PRIMEFIELD_cmp( pPF, pCloneKey->Qx, pSrcKey->Qx));
    retVal += UNITTEST_TRUE( hint, 0 == PRIMEFIELD_cmp( pPF, pCloneKey->Qy, pSrcKey->Qy));
    retVal += UNITTEST_TRUE( hint, 0 == PRIMEFIELD_cmp( pPF, pCloneKey->k, pSrcKey->k));
    retVal += UNITTEST_TRUE( hint, pCloneKey->pCurve == pSrcKey->pCurve);
    retVal += UNITTEST_TRUE( hint, pCloneKey->privateKey == pSrcKey->privateKey);

exit:

    EC_deleteKey( &pCloneKey);

    return retVal;
}


/*---------------------------------------------------------------------------*/

int ecdsa_test_all_curves()
{
    int retVal = 0;
    MSTATUS status;
    ECCKey* pNewKey = 0;
    ubyte hash[SHA1_RESULT_SIZE];
    ubyte hash256[SHA256_RESULT_SIZE];
    sbyte* msg = (sbyte*) "WHERE IS RPT WHERE IS TASK FORCE THIRTY-FOUR RR THE WORLD WONDERS";
    hwAccelDescr hwAccelCtx;
    
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
    
    if (OK > (MSTATUS)(retVal = DIGICERT_initialize(&setupInfo, NULL)))
        return retVal;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        goto exit;

    SHA1_completeDigest(MOC_HASH(hwAccelCtx) (ubyte*)msg, DIGI_STRLEN(msg), hash);
    SHA256_completeDigest(MOC_HASH(hwAccelCtx) (ubyte*)msg, DIGI_STRLEN(msg), hash256);

#ifdef __ENABLE_DIGICERT_ECC_P192__
    /* 192 */
    if ( OK > (status = UNITTEST_STATUS( 0, EC_newKey( EC_P192, &pNewKey))))
    {
        retVal += UNITTEST_STATUS( 0, status);
        goto exit;
    }

    retVal += SignatureTest( g_pRandomContext, pNewKey, hash, SHA1_RESULT_SIZE, 192);
    retVal += CloneTest( 192, pNewKey);

    EC_deleteKey( &pNewKey);
#endif

    /* 224 */
    if ( OK > (status = UNITTEST_STATUS( 0, EC_newKey( EC_P224, &pNewKey))))
    {
        retVal += UNITTEST_STATUS( 0, status);
        goto exit;
    }

    retVal += SignatureTest( g_pRandomContext, pNewKey, hash, SHA1_RESULT_SIZE, 224);
    retVal += CloneTest( 224, pNewKey);

    EC_deleteKey( &pNewKey);

    /* 256 */
    if ( OK > (status = UNITTEST_STATUS( 0, EC_newKey( EC_P256, &pNewKey))))
    {
        retVal += UNITTEST_STATUS( 0, status);
        goto exit;
    }

    retVal += SignatureTest( g_pRandomContext, pNewKey, hash, SHA1_RESULT_SIZE, 256);
    retVal += SignatureTest( g_pRandomContext, pNewKey, hash256, SHA256_RESULT_SIZE, 256 + 256);
    retVal += CloneTest( 256, pNewKey);

    EC_deleteKey( &pNewKey);

    /* 384 */
    if ( OK > (status = UNITTEST_STATUS( 0, EC_newKey( EC_P384, &pNewKey))))
    {
        retVal += UNITTEST_STATUS( 0, status);
        goto exit;
    }

    retVal += SignatureTest( g_pRandomContext, pNewKey, hash, SHA1_RESULT_SIZE, 384);
    retVal += CloneTest( 384, pNewKey);

    EC_deleteKey( &pNewKey);

    /* 521 */
    if ( OK > (status = UNITTEST_STATUS( 0, EC_newKey( EC_P521, &pNewKey))))
    {
        retVal += UNITTEST_STATUS( 0, status);
        goto exit;
    }

    retVal += SignatureTest( g_pRandomContext, pNewKey, hash, SHA1_RESULT_SIZE, 521);
    retVal += CloneTest( 521, pNewKey);

    EC_deleteKey( &pNewKey);

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    DIGICERT_freeDigicert();

    return retVal;
}


/*---------------------------------------------------------------------------*/

typedef struct SignatureVerifyTest
{
    const ubyte* hash;
    int hashLen;
    const ubyte* r_bytes;
    int r_len;
    const ubyte* s_bytes;
    int s_len;
} SignatureVerifyTest;

SignatureVerifyTest gSignatureVerifyTestsIOT_617[] =
{
    {
        (const ubyte*)
        "\x00\x26\x68\x2d\xef\x32\xe9\x4f\x4f\xfa\x0a\x87\x6d\xfe\x19\x0a"
        "\xc2\x2d\x08\x33\xc9\x89\x49\x5d\x8d\x4a\xbc\x7e\x33\x73\x9a\x86"
        "\x53\x88\x75\x09\xb9\x5b\xe6\xfe\x17\x16\xc1\x6d\xc5\x97\xf0\xef"
        "\x34\x80\xd0\x8d\x1a\x6d\x0b\xb8\x00\x0d\x69\x60\xae\xcd\x89\x29",
        64,
        (const ubyte*)
        "\x7d\x8b\x20\xf9\xeb\xbe\xf6\x4b\xa1\xa1\xca\xc8\x4f\x87\xdb\xa4"
        "\x8f\xa1\xef\x9a\x29\xad\x30\x12\x60\xba\x39\x29\x90\x15\xac\x35",
        32,
        (const ubyte*)
        "\x04\xbe\x75\x36\x54\xb6\xdd\x65\x11\x26\xae\x02\x80\xb9\x2a\x66"
        "\xc5\x25\xd1\xf3\x37\x7d\x7f\x4a\x50\x68\x76\x88\xbf\xca\xeb\xcf",
        32
    },

    {
        (const ubyte*)
        "\x00\x55\xfc\xee\x94\x4e\x26\x69\xee\xfb\xc7\xc0\xcd\x80\x97\xeb"
        "\xb4\x83\x72\xc5\x46\x32\x34\xe8\xac\xb1\xd8\x1d\x12\x7d\xf9\xcc"
        "\x66\xc1\xfa\x72\x60\x66\x7c\x68\x3a\xe0\xb5\x2a\x9b\x1f\x3b\x4a"
        "\x2d\xf5\xa3\x41\xe1\x8a\x1c\x1c\x4a\x05\xb2\xc6\xe6\x49\x14\xce",
        64,
        (const ubyte*)
        "\x59\xc3\x6d\xad\xb1\x43\x7f\x66\xf5\xdb\xcb\x7a\x54\x4c\x00\x65"
        "\x40\xb4\x33\x04\xd0\x6f\xf1\xf4\x28\x47\x98\x31\x73\x9d\x5a\x01",
        32,
        (const ubyte*)
        "\x00\xde\x25\xc8\xb9\x9c\x5c\xf5\xb4\x27\x57\xf3\x52\x1e\x3f\xb3"
        "\x9b\xb3\xf3\x34\xb7\xe6\x11\xfa\x58\x04\xbc\x44\x8b\xdd\xd1\xb5"
        "\x98",
        33
    },

    {
        (const ubyte*)
        "\x00\x4d\x6c\x02\x47\xcf\x76\xd2\x94\x47\xb9\x83\x0d\xee\x09\xe8"
        "\xd5\xfa\x97\xb4\x0f\x9a\x2d\x9f\x75\x89\x81\x0f\x65\x9e\x58\x81"
        "\x38\x6a\x51\x20\x1d\x6b\xa5\xaf\x55\x2e\x8e\xde\x8a\xd6\xa5\x9d"
        "\x95\xcd\x09\x57\x62\x87\xa7\xc2\x25\xb9\x11\xf0\x17\xa9\x2e\xd1",
        64,
        (const ubyte*)
        "\x68\x8a\x1c\x08\x9c\x69\x0d\x1f\xf4\x87\x0c\xb6\x33\xf9\x40\xcd"
        "\xc3\xb0\x29\x5f\x96\x3e\x32\xeb\x64\xb7\x5f\x11\x42\xdf\x55\x99",
        32,
        (const ubyte*)
        "\x12\x06\x02\xc8\x9f\x4b\xcb\x51\x18\x05\xe6\x36\x5f\xbd\x0e\x02"
        "\x06\xb0\x4c\x74\x69\x7e\x00\x15\x85\xac\x46\xd9\xf1\x48\x0c\x1c",
        32
    },

    {
        (const ubyte*)
        "\x00\xfc\x91\x04\x8c\x9f\x88\x51\xd1\xce\x54\xa8\x8e\x98\x1f\x29"
        "\x44\xaa\x05\x99\x4d\x8b\x50\xb9\xaf\x74\x03\x9e\x95\xae\xff\x3b"
        "\x41\x4f\x6a\x40\x23\x1e\x72\x64\xe6\x1a\x18\x18\x12\x75\x4e\xac"
        "\x4f\x54\x0b\x05\x1a\xfa\xd4\xec\x3c\xd2\x3a\x4f\x31\xe0\xa7\x15",
        64,
        (const ubyte*)
        "\x1b\x35\xb4\x8f\x19\xfc\x73\xc4\xc4\x76\xf4\x6c\x0b\x92\x68\xbe"
        "\x8e\x92\x45\xc5\x1a\x7f\x2b\x53\x18\xce\x74\x70\xc0\x37\x41\x40",
        32,
        (const ubyte*)
        "\x00\xd2\x2b\x0f\xdf\x9d\x44\x54\xa2\xe4\xa2\xe9\x4a\xe6\x67\xf4"
        "\x34\x77\xa6\xb3\xb8\x1f\xeb\x30\x9a\x49\x9f\xcb\xcc\x44\x82\x8e"
        "\x1b",
        33
    },
};

/*---------------------------------------------------------------------------*/

int ecdsa_test_bug_IOT_617()
{

    ubyte Qx_bytes[] = {
       0xaf, 0x3c, 0x63, 0xa5, 0xbb, 0xbe, 0xc9, 0x9f, 0x83, 0x89, 0x5c, 0xc5, 0xd5, 0x0a, 0xa9, 0x4c,
       0x98, 0x33, 0x37, 0x2a, 0x5c, 0x80, 0xf3, 0x95, 0x75, 0x86, 0x34, 0xc2, 0x89, 0xe5, 0xe5, 0x9c
    };


    ubyte Qy_bytes[] = {
       0x8e, 0x59, 0x66, 0x13, 0x53, 0xfc, 0xc8, 0x71, 0x82, 0xdc, 0xb5, 0xcd, 0x0a, 0xdf, 0x52, 0x1f,
       0x68, 0xca, 0xc3, 0x3b, 0x03, 0xb5, 0xe9, 0x6f, 0x82, 0xe2, 0xc5, 0x2e, 0xce, 0x50, 0x65, 0x36
    };

    PFEPtr Qx = 0, Qy = 0, r = 0, s = 0;
    int retVal = 0, i;
    PrimeFieldPtr pPF = EC_getUnderlyingField(EC_P256);

    UNITTEST_STATUS_GOTO(0, PRIMEFIELD_newElement(pPF, &Qx), retVal, exit);
    UNITTEST_STATUS_GOTO(0, PRIMEFIELD_newElement(pPF, &Qy), retVal, exit);
    UNITTEST_STATUS_GOTO(0, PRIMEFIELD_newElement(pPF, &r), retVal, exit);
    UNITTEST_STATUS_GOTO(0, PRIMEFIELD_newElement(pPF, &s), retVal, exit);

    UNITTEST_STATUS_GOTO(0, PRIMEFIELD_setToByteString(pPF, Qx, Qx_bytes,
                                                       COUNTOF(Qx_bytes)),
                         retVal, exit);


    UNITTEST_STATUS_GOTO(0, PRIMEFIELD_setToByteString(pPF, Qy, Qy_bytes,
                                                       COUNTOF(Qy_bytes)),
                         retVal, exit);


    for (i = 0; i < COUNTOF(gSignatureVerifyTestsIOT_617); ++i)
    {
        SignatureVerifyTest* pSVTest = gSignatureVerifyTestsIOT_617 + i;

        UNITTEST_STATUS_GOTO(i, PRIMEFIELD_setToByteString(pPF, r,
                                                           pSVTest->r_bytes,
                                                           pSVTest->r_len),
                             retVal, exit);


        UNITTEST_STATUS_GOTO(i, PRIMEFIELD_setToByteString(pPF, s,
                                                          pSVTest->s_bytes,
                                                           pSVTest->s_len),
                             retVal, exit);


        retVal += UNITTEST_STATUS(i, ECDSA_verifySignature(EC_P256, Qx, Qy,
                                                          pSVTest->hash,
                                                          pSVTest->hashLen,
                                                          r, s));
    }

exit:

    PRIMEFIELD_deleteElement(pPF, &Qx);
    PRIMEFIELD_deleteElement(pPF, &Qy);
    PRIMEFIELD_deleteElement(pPF, &r);
    PRIMEFIELD_deleteElement(pPF, &s);

    return retVal;
}
