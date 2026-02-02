/*
 *  ecdhtest.c
 *
 *   unit test for ECDH
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

#if defined(__RTOS_OSX__) || defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__)
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
#include "../../common/initmocana.h"
#ifdef __ENABLE_DIGICERT_VLONG_ECC_CONVERSION__
#include "../../common/vlong.h"
#endif
#include "../../crypto/primefld.h"
#include "../../crypto/primeec.h"
#include "../../../unit_tests/unittest.h"


/*------------------------------------------------------------------*/

#if defined(__RTOS_OSX__) || defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__)

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

#endif   /* defined(__RTOS_OSX__) || defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__)   */


/*---------------------------------------------------------------------------*/

int ECDHTest( int hint, PEllipticCurvePtr pEC, randomContext* pRandomContext)
{
    int retVal = 0;
    MSTATUS status;
    ECCKey* pKey1 = 0;
    ECCKey* pKey2 = 0;
    ubyte* sharedSecret1 = 0;
    ubyte* sharedSecret2 = 0;
    ubyte4 sharedSecret1Len;
    ubyte4 sharedSecret2Len;
    sbyte4 res;

    if ( OK > (status = UNITTEST_STATUS( hint, EC_newKey( pEC, &pKey1))))
    {
        retVal += UNITTEST_STATUS( 0, status);
        goto exit;
    }
    if ( OK > (status = UNITTEST_STATUS( hint, EC_newKey( pEC, &pKey2))))
    {
        retVal += UNITTEST_STATUS( 0, status);
        goto exit;
    }

    if ( retVal = UNITTEST_STATUS( hint, EC_generateKeyPair( pEC,
            RANDOM_rngFun, pRandomContext, pKey1->k, pKey1->Qx, pKey1->Qy)))
    {
        goto exit;
    }

    if ( retVal = UNITTEST_STATUS( hint, EC_generateKeyPair( pEC,
            RANDOM_rngFun, pRandomContext, pKey2->k, pKey2->Qx, pKey2->Qy)))
    {
        goto exit;
    }

    if (retVal = UNITTEST_STATUS( hint, ECDH_generateSharedSecretAux(pEC,
                            pKey1->Qx,  pKey1->Qy, pKey2->k,
                            &sharedSecret2, &sharedSecret2Len, 1)))
    {
        goto exit;
    }

    if (retVal = UNITTEST_STATUS( hint, ECDH_generateSharedSecretAux(pEC,
                            pKey2->Qx,  pKey2->Qy, pKey1->k,
                            &sharedSecret1, &sharedSecret1Len, 1)))
    {
        goto exit;
    }

    retVal += UNITTEST_TRUE( hint, sharedSecret1Len == sharedSecret2Len);
    DIGI_MEMCMP(sharedSecret1, sharedSecret2, sharedSecret1Len, &res);
    retVal += UNITTEST_TRUE( hint, res == 0);

    /* for linux we do a speed test that will be captured in the logs */
#if defined(__RTOS_OSX__) || defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__)
    {
        struct tms tstart, tend;
        double diffTime;
        int i;

        FREE(sharedSecret2);
        sharedSecret2 = 0;

        START_ALARM(TEST_SECONDS);
        times(&tstart);
        for (i = 0; ALARM_OFF; ++i)
        {
            ECDH_generateSharedSecretAux(pEC,
                                         pKey1->Qx,  pKey1->Qy, pKey2->k,
                                         &sharedSecret2, &sharedSecret2Len, 1);
            FREE( sharedSecret2);
            sharedSecret2 = 0;
        }
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);

        printf("\n\n\t%d ECDH in %g seconds of CPU time\n", i, diffTime);
        printf("Curve P-%d: %g ECDH/second (CPU time)\n",
               hint, i/diffTime);
    }
#endif

exit:

    EC_deleteKey(&pKey1);
    EC_deleteKey(&pKey2);

    FREE( sharedSecret1);
    FREE( sharedSecret2);

    return retVal;
}


/*---------------------------------------------------------------------------*/

int ecdh_test_all_curves()
{
    int retVal;
    hwAccelDescr hwAccelCtx;

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

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        goto exit;

#ifdef __ENABLE_DIGICERT_ECC_P192__
    retVal += ECDHTest( 192, EC_P192, g_pRandomContext);
#endif
    retVal += ECDHTest( 224, EC_P224, g_pRandomContext);
    retVal += ECDHTest( 256, EC_P256, g_pRandomContext);
    retVal += ECDHTest( 384, EC_P384, g_pRandomContext);
    retVal += ECDHTest( 521, EC_P521, g_pRandomContext);

exit:

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    DIGICERT_freeDigicert();

    return retVal;
}
