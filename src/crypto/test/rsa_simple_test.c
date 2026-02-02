/*
 *  rsa_simple_test.c
 *
 *   unit test for rsa_simple.c
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

#include "../rsa_simple.c"

#include "../../common/mstdlib.h"
#include "../../common/vlong.h"
#include "../../common/random.h"
#include "../../common/initmocana.h"
#include "../rsa.h"

#include "../../../unit_tests/unittest.h"

#ifdef __ENABLE_DIGICERT_RSA_SIMPLE__

#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__)
#include <stdio.h>
#include <sys/types.h>
#include <sys/times.h>
#if defined(__USE_TOD__)
#include <sys/resource.h>
#endif
#include <unistd.h>
#include <signal.h>

static volatile int mContinueTest;

#ifndef TEST_SECONDS
#define TEST_SECONDS (30)
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

#endif   /* defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined( __RTOS_SOLARIS__) || defined(__RTOS_OPENBSD__) */



/* in rsa_test.c */
int ReadKey(MOC_HASH(hwAccelDescr hwAccelCtx) RSAKey** ppRetKey, const sbyte* fileName, int hint);

/*---------------------------------------------------------------------------*/

int rsa_simple_signature_verification(int hint, RSAKey* pRSAKey, const sbyte* msg, 
                           const ubyte* cipherText, sbyte4 cipherTextLen)
{
    int retVal = 0;
    sbyte4 modulusLen;
    sbyte4 muLen;
    pf_unit *mu = 0;
    pf_unit *modulus = 0;
    ubyte4 e;
    vlong* pModulus;
    vlong* pMu = 0;
    sbyte4 i, cmpRes;
    ubyte4 msgLen;

    if (sizeof(pf_unit) != sizeof(vlong_unit))
    {
        unittest_write("bypassing rsa_simple_test since sizeof(pf_unit) != sizeof(vlong_unit)\n");
        return 0;
    }

    pModulus = RSA_N( pRSAKey);
    e = (ubyte4) (RSA_E( pRSAKey)->pUnits[0]);

    if (retVal = UNITTEST_STATUS( hint, VLONG_newBarrettMu( &pMu, pModulus, NULL)))
        goto exit;

    muLen = pMu->numUnitsUsed;

    /* modulus length */
    if (retVal = UNITTEST_STATUS( hint, VLONG_byteStringFromVlong( pModulus, NULL, &modulusLen)))
        goto exit;

    mu = (pf_unit*) MALLOC( muLen * 2 * sizeof(pf_unit));
    if (retVal = UNITTEST_VALIDPTR(hint, mu))
        goto exit;
        
    modulus = mu + muLen;

    /* copy the vlong_units into the pf_units, padding with zero */
    for (i = 0; i < muLen; ++i)
    {
        mu[i] = pMu->pUnits[i];
    }

    for (i = 0; i < pModulus->numUnitsUsed; ++i)
    {
        modulus[i] = pModulus->pUnits[i];
    }
    for (; i < muLen; ++i)
    {
        modulus[i] = 0;
    }

    msgLen = DIGI_STRLEN(msg)+1;
    retVal = UNITTEST_STATUS( hint, 
        RSA_SIMPLE_verifySignature(muLen-1, modulus, mu, modulusLen, e, cipherText,
                                   msg, msgLen));
    
    #if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__)
    if (0 == retVal)
    {
#if defined(__USE_TOD__)
        struct rusage tstart,tend;
        long tmp;
#else
        struct tms tstart, tend;
#endif

        double diffTime;

        START_ALARM(TEST_SECONDS);

#if defined(__USE_TOD__)
        getrusage(RUSAGE_SELF, &tstart);
#else
        times(&tstart);
#endif

        for (i = 0; ALARM_OFF; ++i)
        {
            RSA_SIMPLE_verifySignature(muLen-1, modulus, mu, modulusLen, e, cipherText,
                                   msg, msgLen);
        }

#if defined(__USE_TOD__)
    	getrusage(RUSAGE_SELF,&tend);
		tmp=(long)tend.ru_utime.tv_usec-(long)tstart.ru_utime.tv_usec;
		diffTime=((double)(tend.ru_utime.tv_sec-tstart.ru_utime.tv_sec))
			  +((double)tmp)/1000000.0;
#else
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
#endif
        printf("\t%d verifications in %g seconds of CPU time\n", i, diffTime);
        printf("%d bits key: %g verifications/second (CPU time)\n",
               hint, i/diffTime);

    }
#endif

exit:

    if (mu)
    {
        FREE(mu);
    }

    if (pMu)
    {
        VLONG_freeVlong( &pMu, NULL);
    }

    return retVal;
}


/*---------------------------------------------------------------------------*/

int rsa_simple_signature_sign(MOC_RSA(hwAccelDescr hwAccelCtx) int hint, 
                                RSAKey* pRSAKey, const sbyte* msg, 
                                const ubyte* cipherText, sbyte4 cipherTextLen)
{
    int retVal = 0;
    sbyte4 i, n, resCmp;
    pf_unit* p;     /* n/2+1 */
    pf_unit* q;     /* n/2+1 */  /* n+2*/
    pf_unit* dp;    /* n/2 */    
    pf_unit* dq;    /* n/2 */    /* 2*n+2 */
    pf_unit* qinv;  /* n/2 */
    pf_unit* p_mu;  /* n/2+1 */  /* 3*n+3 */
    pf_unit* q_mu;  /* n/2+1 */  /* 7*(n/2)+4*/
    ubyte* signature; /* n */    /* 9*(n/2)+4*/
    ubyte* cmpSignature;
    ubyte4 msgLen;

    if (sizeof(pf_unit) != sizeof(vlong_unit))
    {
        unittest_write("bypassing rsa_simple_test since sizeof(pf_unit) != sizeof(vlong_unit)\n");
        return 0;
    }

    n = RSA_N(pRSAKey)->numUnitsUsed;

    /* allocate memory */ 
    p = (pf_unit*) MALLOC( (9*(n/2)+4) * sizeof(pf_unit) );
    /* just zero out the key params for test */
    DIGI_MEMSET( (ubyte*) p, 0, (7*(n/2)+4) * sizeof(pf_unit) );
    q = p + n/2 + 1;
    dp = q + n/2 + 1;
    dq = dp + n/2;
    qinv = dq + n/2;
    p_mu = qinv + n/2;
    q_mu = p_mu + n/2 + 1;
    signature = (ubyte*) (q_mu + n/2 + 1);

    RSA_prepareKey(MOC_RSA(hwAccelCtx) pRSAKey, NULL);

    DIGI_MEMCPY( p, RSA_P(pRSAKey)->pUnits, RSA_P(pRSAKey)->numUnitsUsed * sizeof(vlong_unit));
    DIGI_MEMCPY( q, RSA_Q(pRSAKey)->pUnits, RSA_Q(pRSAKey)->numUnitsUsed * sizeof(vlong_unit));
    DIGI_MEMCPY( dp, RSA_DP(pRSAKey)->pUnits, RSA_DP(pRSAKey)->numUnitsUsed * sizeof(vlong_unit));
    DIGI_MEMCPY( dq, RSA_DQ(pRSAKey)->pUnits, RSA_DQ(pRSAKey)->numUnitsUsed * sizeof(vlong_unit));
    DIGI_MEMCPY( qinv, RSA_QINV(pRSAKey)->pUnits, RSA_QINV(pRSAKey)->numUnitsUsed * sizeof(vlong_unit));
    
    /* get the mu */
    BI_barrettMu( n/2, p_mu, p);
    BI_barrettMu( n/2, q_mu, q);

    msgLen = DIGI_STRLEN(msg)+1;
    retVal += UNITTEST_STATUS( hint, RSA_SIMPLE_sign(n, signature, msg, msgLen,
                    p, p_mu, dp, q, q_mu, dq, qinv));

    cmpSignature = signature;
    while ( 0 == *cmpSignature)
    {
        ++cmpSignature;
    }
    
    DIGI_MEMCMP( cmpSignature, cipherText, cipherTextLen, &resCmp);

    retVal += UNITTEST_TRUE( hint, 0 == resCmp);    

#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__)
    if (0 == retVal)
    {
#if defined(__USE_TOD__)
        struct rusage tstart,tend;
        long tmp;
#else
        struct tms tstart, tend;
#endif

        double diffTime;

        START_ALARM(TEST_SECONDS);

#if defined(__USE_TOD__)
        getrusage(RUSAGE_SELF, &tstart);
#else
        times(&tstart);
#endif

        for (i = 0; ALARM_OFF; ++i)
        {
            RSA_SIMPLE_sign(n, signature, msg, msgLen,
                    p, p_mu, dp, q, q_mu, dq, qinv);
        }

#if defined(__USE_TOD__)
    	getrusage(RUSAGE_SELF,&tend);
		tmp=(long)tend.ru_utime.tv_usec-(long)tstart.ru_utime.tv_usec;
		diffTime=((double)(tend.ru_utime.tv_sec-tstart.ru_utime.tv_sec))
			  +((double)tmp)/1000000.0;
#else
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
#endif
        printf("\t%d signatures in %g seconds of CPU time\n", i, diffTime);
        printf("%d bits key: %g signatures/second (CPU time)\n",
               hint, i/diffTime);

        cmpSignature = signature;
        while ( 0 == *cmpSignature)
        {
            ++cmpSignature;
        }
    
        DIGI_MEMCMP( cmpSignature, cipherText, cipherTextLen, &resCmp);

        retVal += UNITTEST_TRUE( hint, 0 == resCmp);    
    }
#endif
exit:

    if (p)
    {
        FREE(p);
    }

    return retVal;
}


/*---------------------------------------------------------------------------*/

int rsa_simple_signature_sign_blind(MOC_RSA(hwAccelDescr hwAccelCtx) int hint, 
                                RSAKey* pRSAKey, const sbyte* msg, 
                                const ubyte* cipherText, sbyte4 cipherTextLen,
                                randomContext* pRandomContext)
{
    int retVal = 0;
    sbyte4 i, n, resCmp;
    pf_unit* p;     /* n/2+1 */
    pf_unit* q;     /* n/2+1 */  /* n+2*/
    pf_unit* dp;    /* n/2 */    
    pf_unit* dq;    /* n/2 */    /* 2*n+2 */
    pf_unit* qinv;  /* n/2 */
    pf_unit* p_mu;  /* n/2+1 */  /* 3*n+3 */
    pf_unit* q_mu;  /* n/2+1 */  /* 7*(n/2)+4*/
    pf_unit* modulus;    /* n+1 */  /* 9*(n/2)+5*/
    pf_unit* modulus_mu; /* n+1 */  /* 11*(n/2)+6*/
    pf_unit* re;         /* n */    /* 13*(n/2)+6*/
    pf_unit* r1;         /* n */    /* 15*(n/2)+6*/
    pf_unit* signature;  /* n */    /* 17*(n/2)+6*/
    ubyte* cmpSignature;

    ubyte4 msgLen;

    if (sizeof(pf_unit) != sizeof(vlong_unit))
    {
        unittest_write("bypassing rsa_simple_test since sizeof(pf_unit) != sizeof(vlong_unit)\n");
        return 0;
    }

    n = RSA_N(pRSAKey)->numUnitsUsed;

    /* allocate memory */ 
    p = (pf_unit*) MALLOC( (17*(n/2)+6) * sizeof(pf_unit) );
    /* just zero out the key params for test */
    DIGI_MEMSET( (ubyte*) p, 0, (15*(n/2)+4) * sizeof(pf_unit) );
    q = p + n/2 + 1;
    dp = q + n/2 + 1;
    dq = dp + n/2;
    qinv = dq + n/2;
    p_mu = qinv + n/2;
    q_mu = p_mu + n/2 + 1;
    modulus = q_mu + n/2 + 1;
    modulus_mu = modulus + n + 1;
    re = modulus_mu + n + 1;
    r1 = re + n;
    signature = (r1 + n);

    RSA_prepareKey(MOC_RSA(hwAccelCtx) pRSAKey, NULL);

    DIGI_MEMCPY( modulus, RSA_N(pRSAKey)->pUnits, RSA_N(pRSAKey)->numUnitsUsed * sizeof(vlong_unit));
    DIGI_MEMCPY( p, RSA_P(pRSAKey)->pUnits, RSA_P(pRSAKey)->numUnitsUsed * sizeof(vlong_unit));
    DIGI_MEMCPY( q, RSA_Q(pRSAKey)->pUnits, RSA_Q(pRSAKey)->numUnitsUsed * sizeof(vlong_unit));
    DIGI_MEMCPY( dp, RSA_DP(pRSAKey)->pUnits, RSA_DP(pRSAKey)->numUnitsUsed * sizeof(vlong_unit));
    DIGI_MEMCPY( dq, RSA_DQ(pRSAKey)->pUnits, RSA_DQ(pRSAKey)->numUnitsUsed * sizeof(vlong_unit));
    DIGI_MEMCPY( qinv, RSA_QINV(pRSAKey)->pUnits, RSA_QINV(pRSAKey)->numUnitsUsed * sizeof(vlong_unit));

    /* get the mu */
    BI_barrettMu( n/2, p_mu, p);
    BI_barrettMu( n/2, q_mu, q);
    BI_barrettMu( n, modulus_mu, modulus);

    /* blinding factors */
    RANDOM_numberGenerator( pRandomContext, (ubyte*) signature, (n) * sizeof(pf_unit)); /* make sure it's less than N */
    if ( signature[n-1] > modulus[n-1])
    {
        signature[n-1] -= modulus[n-1];
    }
    BI_modExp( n, re, signature, RSA_E(pRSAKey)->pUnits[0], modulus, modulus_mu); 
    /* compute r1 */
    BI_modularInverse(n, signature, modulus, r1);

    msgLen = DIGI_STRLEN(msg)+1;

    retVal += UNITTEST_STATUS( hint, RSA_SIMPLE_sign_blind(n, (ubyte*) signature, msg, msgLen,
                    p, p_mu, dp, q, q_mu, dq, qinv, modulus, modulus_mu, re, r1));

    cmpSignature = (ubyte*) signature;
    while ( 0 == *cmpSignature)
    {
        ++cmpSignature;
    }
    
    DIGI_MEMCMP( cmpSignature, cipherText, cipherTextLen, &resCmp);

    retVal += UNITTEST_TRUE( hint, 0 == resCmp);    

    /* another round -- blinding factors have changed */
    retVal += UNITTEST_STATUS( hint, RSA_SIMPLE_sign_blind(n, (ubyte*) signature, msg, msgLen,
                    p, p_mu, dp, q, q_mu, dq, qinv, modulus, modulus_mu, re, r1));

    cmpSignature = (ubyte*) signature;
    while ( 0 == *cmpSignature)
    {
        ++cmpSignature;
    }
    
    DIGI_MEMCMP( cmpSignature, cipherText, cipherTextLen, &resCmp);

    retVal += UNITTEST_TRUE( hint, 0 == resCmp);    


#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__)
    if (0 == retVal)
    {
#if defined(__USE_TOD__)
        struct rusage tstart,tend;
        long tmp;
#else
        struct tms tstart, tend;
#endif

        double diffTime;

        START_ALARM(TEST_SECONDS);

#if defined(__USE_TOD__)
        getrusage(RUSAGE_SELF, &tstart);
#else
        times(&tstart);
#endif

        for (i = 0; ALARM_OFF; ++i)
        {
            RSA_SIMPLE_sign_blind(n, signature, msg, msgLen,
                    p, p_mu, dp, q, q_mu, dq, qinv, modulus, modulus_mu, re, r1);
        }

#if defined(__USE_TOD__)
    	getrusage(RUSAGE_SELF,&tend);
		tmp=(long)tend.ru_utime.tv_usec-(long)tstart.ru_utime.tv_usec;
		diffTime=((double)(tend.ru_utime.tv_sec-tstart.ru_utime.tv_sec))
			  +((double)tmp)/1000000.0;
#else
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);
#endif
        printf("\t%d blinded signatures in %g seconds of CPU time\n", i, diffTime);
        printf("%d bits key: %g blinded signatures/second (CPU time)\n",
               hint, i/diffTime);

        /* verify again */
        cmpSignature = signature;
        while ( 0 == *cmpSignature)
        {
            ++cmpSignature;
        }
        
        DIGI_MEMCMP( cmpSignature, cipherText, cipherTextLen, &resCmp);

        retVal += UNITTEST_TRUE( hint, 0 == resCmp);    
    }
#endif
exit:

    if (p)
    {
        FREE(p);
    }

    return retVal;
}


/*---------------------------------------------------------------------------*/

int rsa_simple_signature_test(randomContext* pRandomContext, 
                              const sbyte* fileName, int hint)
{
    ubyte*  cipherText = 0;
    ubyte*  plainText = 0;
    sbyte4  cipherTextLen, plainTextLen;
    sbyte4  cmpRes;
    sbyte4  retVal = 0;
    vlong*  pQueue = 0;
    RSAKey* pRSAKey = NULL;
    const sbyte* msg = "Attack at dawn!";
    hwAccelDescr hwAccelCtx;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    if (retVal = ReadKey(MOC_HASH(hwAccelCtx) &pRSAKey, fileName, hint))
        goto exit;

    if (retVal = UNITTEST_STATUS(hint,
        RSA_getCipherTextLength( pRSAKey, &cipherTextLen)))
    {
        goto exit;
    }

    cipherText = MALLOC( cipherTextLen);
    if ( retVal = UNITTEST_VALIDPTR(hint, cipherText))
        goto exit;

    plainText = MALLOC( cipherTextLen);
    if ( retVal = UNITTEST_VALIDPTR(hint, plainText))
        goto exit;

    if ( retVal = UNITTEST_STATUS( hint,
            RSA_signMessage(MOC_RSA(hwAccelCtx) pRSAKey, msg, 
                            DIGI_STRLEN(msg)+1, cipherText, &pQueue)))
    {
        goto exit;
    }

    if ( retVal = UNITTEST_STATUS( hint,
            RSA_verifySignature(MOC_RSA(hwAccelCtx) pRSAKey, cipherText, 
                                plainText, &plainTextLen, &pQueue)))
    {
        goto exit;
    }

    retVal += UNITTEST_INT( hint, plainTextLen, DIGI_STRLEN(msg)+1);
    DIGI_MEMCMP(msg, plainText, plainTextLen, &cmpRes);

    retVal += UNITTEST_INT( hint, 0, cmpRes);

    retVal += rsa_simple_signature_verification(hint, pRSAKey, msg, cipherText, cipherTextLen);

    retVal += rsa_simple_signature_sign(MOC_RSA(hwAccelCtx) hint, pRSAKey, msg, cipherText, cipherTextLen);

    retVal += rsa_simple_signature_sign_blind(MOC_RSA(hwAccelCtx) hint, pRSAKey, msg, cipherText, 
                                                cipherTextLen, pRandomContext);

exit:

    FREE( cipherText);
    FREE( plainText);
    RSA_freeKey( &pRSAKey, 0);
    VLONG_freeVlongQueue(&pQueue);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;

}


#endif

/*---------------------------------------------------------------------------*/

int rsa_simple_test_all()
{
    int retVal = 0;

#ifdef __ENABLE_DIGICERT_RSA_SIMPLE__
    /* Init digicert for the rng */
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

    retVal += rsa_simple_signature_test(g_pRandomContext, FILE_PATH("key1024.der"), 1024);
    retVal += rsa_simple_signature_test(g_pRandomContext, FILE_PATH("key2048.der"), 2048);
    retVal += rsa_simple_signature_test(g_pRandomContext, FILE_PATH("key4096.der"), 4096);

    DIGICERT_freeDigicert();

#endif

    return retVal;
}
