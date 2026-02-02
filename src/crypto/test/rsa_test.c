/*
 * rsa_test.c
 *
 * unit test for rsa.c
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

#include "../../common/moptions.h"

#if defined(__RTOS_WINCE__) || defined(__RTOS_WIN32__)
#include <windows.h>
#include <stdio.h>
#endif

#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../common/vlong.h"
#include "../../common/random.h"
#include "../../common/prime.h"
#include "../../common/debug_console.h"
#include "../../common/memory_debug.h"
#include "../../common/initmocana.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/rsa.h"
#include "../../crypto/dsa.h"
#include "../../crypto/primefld.h"
#include "../../crypto/primeec.h"
#include "../../crypto/keyblob.h"
#include "../../crypto/ca_mgmt.h"
#include "../../crypto/sha1.h"

#include <string.h> /* strncmp */

#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__) || defined (__RTOS_OSX__)
#include <stdio.h>
#include <sys/types.h>
#include <sys/times.h>
#if defined(__USE_TOD__)
#include <sys/resource.h>
#endif
#include <unistd.h>
#include <signal.h>
#endif

#include "../secmod.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../primefld.h"
#include "../primeec.h"
#endif
#include "../pubcrypto.h"
#include "../pkcs_key.h"
#include "../../common/absstream.h"
#include "../../asn1/parsecert.h"

#include "../../../unit_tests/unittest.h"

#include "../../common/test/print_vlong.c"

extern moctime_t gStartTime;
#define MAX_LINE_LEN (4096)  /* can have pretty big lines */
#define MAX_KEY_SIZE (512)      /* 4096 / 8 */
#define CERT_MAXDIGESTSIZE         (64)

/*------------------------------------------------------------------*/

#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined(__RTOS_OPENBSD__) || defined (__RTOS_OSX__)

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

#endif   /* defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined( __RTOS_SOLARIS__) || defined(__RTOS_OPENBSD__) || defined (__RTOS_OSX__) */


/*------------------------------------------------------------------*/

#ifdef CUSTOM_RSA_BLIND_FUNC

MSTATUS CUSTOM_RSA_BLIND_FUNC( MOC_RSA(hwAccelDescr hwAccelCtx)
                              const RSAKey* pRSAKeyInt,
                              const vlong* pCipher,
                              RNGFun rngFun, void* rngFunArg,
                              RSADecryptFunc rsaDecryptPrimitive,
                              vlong** ppRetDecrypt,
                              vlong** ppVlongQueue)
{
    /* test: we don't do anything just call the provided callback */
    return rsaDecryptPrimitive( MOC_RSA( hwAccelCtx)
                                pRSAKeyInt, pCipher,
                                ppRetDecrypt, ppVlongQueue);
}

#endif /* CUSTOM_RSABLIND_FUNC */


/*------------------------------------------------------------------*/

sbyte4 MyRandom(void* rngFunArg, ubyte4 length, ubyte *buffer)
{
    static ubyte next;
    unsigned i;

    if ( 0 == next)
    {
        next = (ubyte)(1 + RTOS_deltaMS(&gStartTime, NULL));
    }

    for ( i = 0; i < length; ++i)
    {
        buffer[i] = next++;
    }
    return 0;
}


/*------------------------------------------------------------------*/

int rsa_test_blinding()
{
    const sbyte testmsg[] = "Attack at dawn";
    RSAKey* pRSAKey;
    ubyte*  cipherText = 0;
    ubyte*  plainText = 0;
    sbyte4  testMsgLen;
    sbyte4  cipherTextLen, plainTextLen;
    sbyte4  cmpRes;
    sbyte4  retVal = 0;
    vlong*  pQueue = 0;
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
    
    retVal += UNITTEST_STATUS( 0, DIGICERT_initialize(&setupInfo, NULL));
    if (retVal) return retVal;
    
    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        goto exit;

    if ( 0 != (retVal = UNITTEST_STATUS(0, RSA_createKey( &pRSAKey))))
        goto exit;

    if ( 0 != (retVal = UNITTEST_STATUS(0, RSA_generateKey(MOC_SYM(hwAccelCtx)
                                                g_pRandomContext,
                                                pRSAKey,
                                                2048,
                                                NULL))))
    {
        goto exit;
    }

    print_vlong("e = ", RSA_E(pRSAKey));
    print_vlong("n = ", RSA_N(pRSAKey));
    print_vlong("p = ", RSA_P(pRSAKey));
    print_vlong("q = ", RSA_Q(pRSAKey));

    if (OK > RSA_getCipherTextLength( pRSAKey, &cipherTextLen))
        goto exit;

    cipherText = MALLOC( cipherTextLen);

    testMsgLen = DIGI_STRLEN(testmsg)+1;

    if ( 0 != (retVal = UNITTEST_STATUS(0, RSA_encrypt(MOC_SYM(hwAccelCtx)
                                                pRSAKey, testmsg,
                                                testMsgLen,
                                                cipherText, MyRandom,
                                                NULL, &pQueue))))
    {
        goto exit;
    }

    plainText = MALLOC( cipherTextLen);

    /* decrypt without blinding */
    if ( 0 != (retVal = UNITTEST_STATUS(0, RSA_decrypt(MOC_SYM(hwAccelCtx)
                                                pRSAKey, cipherText,
                                                plainText,
                                                &plainTextLen, NULL,
                                                NULL, &pQueue))))
    {
        goto exit;
    }

    retVal += UNITTEST_INT( 0, plainTextLen, testMsgLen);
    DIGI_MEMCMP( plainText, testmsg, plainTextLen, &cmpRes);
    retVal += UNITTEST_INT(0, cmpRes, 0);

    /* decrypt with blinding */
    if ( 0 != (retVal =
               UNITTEST_STATUS(0, RSA_decrypt(MOC_SYM(hwAccelCtx)pRSAKey,
                                              cipherText, plainText,
                                              &plainTextLen, MyRandom,
                                              NULL, &pQueue))))
    {
        goto exit;
    }

    retVal += UNITTEST_INT( 0, plainTextLen, testMsgLen);
    DIGI_MEMCMP( plainText, testmsg, plainTextLen, &cmpRes);
    retVal += UNITTEST_INT(0, cmpRes, 0);

exit:

    if ( cipherText)
    {
        FREE( cipherText);
    }
    if ( plainText)
    {
        FREE( plainText);
    }

    RSA_freeKey( &pRSAKey, 0);
    VLONG_freeVlongQueue(&pQueue);
    
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
    DIGICERT_freeDigicert();

    return retVal;
}


/*-------------------------------------------------------------------------*/

int rsa_test_blob_tests()
{
    int retVal = 0;
    randomContext* pRndCtx = NULL;
    RSAKey* pKey1 = 0;
    RSAKey* pKey2 = 0;
    vlong* pQueue = 0;
    ubyte4  buffLen;
    ubyte*  buffer = NULL;
    sbyte4 i;

#ifdef __ALTIVEC__
    typedef struct myMonty
    {
        vlong*  v[4];
    } myMonty;
#else
    typedef struct myMonty
    {
        vlong_unit  rho;
        vlong*  v[3];
    } myMonty;
#endif

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
    
    retVal += UNITTEST_STATUS( 0, DIGICERT_initialize(&setupInfo, NULL));
    if (retVal) return retVal;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        goto exit;

    if ( UNITTEST_STATUS(0, RSA_createKey( &pKey1)))
    {
        retVal = 1;
        goto exit;
    }

    if ( UNITTEST_STATUS(0, RSA_generateKey(MOC_RSA(hwAccelCtx)g_pRandomContext, pKey1,
                                            2048, &pQueue)))
    {
        retVal = 1;
        goto exit;
    }

    if ( UNITTEST_STATUS( 0, RSA_byteStringFromKey(MOC_RSA(hwAccelCtx) pKey1,
                                                   0, &buffLen)))
    {
        retVal = 1;
        goto exit;
    }

    buffer = MALLOC( buffLen + 10);
    if ( UNITTEST_VALIDPTR(0, buffer))
    {
        retVal = 1;
        goto exit;
    }

    /** add some sentinels at the end of buffer */
    for (i = 0; i < 10; ++i)
    {
        buffer[buffLen+i] = 0xFA;
    }

    if ( UNITTEST_STATUS( 0, RSA_byteStringFromKey(MOC_RSA(hwAccelCtx) pKey1,
                                                   buffer, &buffLen)))
    {
        retVal = 1;
        goto exit;
    }

    /** verify the sentinels */
    for (i = 0; i < 10; ++i)
    {
        retVal += UNITTEST_INT(i, buffer[buffLen+i], 0xFA);
    }

    if (UNITTEST_STATUS( 0, RSA_keyFromByteString(MOC_RSA(hwAccelCtx)
                                                  &pKey2, buffer, buffLen,
                                                  &pQueue)))
    {
        retVal += 1;
        goto exit;
    }

    /** compare the keys */
    for (i = 0; i < NUM_RSA_VLONG; ++i)
    {
        retVal += UNITTEST_INT(i, 0,
                      VLONG_compareSignedVlongs(pKey1->v[i], pKey2->v[i]));
    }

    for (i = 0; i < NUM_RSA_MODEXP; ++i)
    {
        sbyte4 j;
        myMonty* pMyMonty1 = (myMonty*) pKey1->modExp[i];
        myMonty* pMyMonty2 = (myMonty*) pKey2->modExp[i];

#ifndef __ALTIVEC__
        retVal += UNITTEST_TRUE( i, pMyMonty1->rho == pMyMonty2->rho);
#endif
        for (j = 0; j < 3; ++j)
        {
            retVal += UNITTEST_INT( (i << 16) + j, 0,
                                VLONG_compareSignedVlongs(pMyMonty1->v[j],
                                                          pMyMonty2->v[j]));
        }
    }

exit:
    RSA_freeKey(&pKey1, 0);
    RSA_freeKey(&pKey2, 0);
    VLONG_freeVlongQueue( &pQueue);
    if (buffer)
    {
        FREE(buffer);
    }
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
    DIGICERT_freeDigicert();

    return retVal;
}


/*---------------------------------------------------------------------------*/

/* This tests CA_MGMT_convertRSAPublicKeyInfoDER
 */
int rsa_test_pubKeyInfo ()
{
  MSTATUS status;
  int retVal;
  ubyte4 keyBlobLen, initFlag;
  ubyte *pKeyBlob = NULL;
  AsymmetricKey pubKey;
  ubyte publicDer[162] = {
    0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81,
    0x89, 0x02, 0x81, 0x81, 0x00, 0x99, 0xff, 0xbc,
    0xb3, 0xbe, 0x9d, 0xb4, 0x32, 0xb8, 0x9c, 0xd7,
    0x51, 0x14, 0x7f, 0xa3, 0x93, 0xab, 0xa2, 0x12,
    0x5f, 0x7c, 0x83, 0x37, 0x76, 0x57, 0x4d, 0xaa,
    0x02, 0xb2, 0x96, 0x79, 0x0e, 0xec, 0x21, 0x8b,
    0x9b, 0x5d, 0x02, 0x34, 0x77, 0x4e, 0x63, 0x56,
    0x52, 0x44, 0x74, 0x36, 0xc3, 0x93, 0xca, 0x5d,
    0x9f, 0x27, 0xfb, 0xbb, 0x44, 0x90, 0x06, 0x0b,
    0xb4, 0xcc, 0x92, 0x3c, 0xb7, 0xea, 0xdc, 0xfd,
    0xed, 0x10, 0xc5, 0x54, 0xef, 0x63, 0x4e, 0x8e,
    0x23, 0xa7, 0x31, 0x22, 0xd4, 0x18, 0x19, 0x14,
    0xc9, 0x64, 0x75, 0xdd, 0x1b, 0x13, 0x38, 0x09,
    0x3d, 0x28, 0xcf, 0xec, 0xd6, 0xd0, 0x5b, 0xa9,
    0x48, 0x72, 0x71, 0x7e, 0xb1, 0x0d, 0x39, 0xc0,
    0x51, 0x4c, 0xbb, 0x34, 0xbf, 0xa1, 0xbb, 0xd9,
    0xe7, 0x4b, 0x1b, 0x3f, 0xd4, 0x83, 0x98, 0x75,
    0x9f, 0x4f, 0x63, 0x88, 0x13, 0x02, 0x03, 0x01,
    0x00, 0x01
  };

  retVal = 0;

  /* Get the key blob.
   */
  status = CA_MGMT_convertRSAPublicKeyInfoDER (
    (ubyte *)publicDer, sizeof (publicDer), &pKeyBlob, &keyBlobLen);
  retVal += UNITTEST_STATUS (1, status);
  if (OK != status)
    goto exit;

  /* Now verify that it is a valid key blob by trying to load it into an
   * AsymmetricKey object.
   */
  status = CRYPTO_initAsymmetricKey (&pubKey);
  retVal += UNITTEST_STATUS (2, status);
  if (OK != status)
    goto exit;

  initFlag = 1;

  status = KEYBLOB_extractKeyBlobEx (
    pKeyBlob, keyBlobLen, &pubKey);
  retVal += UNITTEST_STATUS (3, status);
  if (OK != status)
    goto exit;

  /* Did it build an RSA key?
   */
  retVal += UNITTEST_INT (4, pubKey.type, akt_rsa);

exit:

  if (initFlag != 0)
  {
    status = CRYPTO_uninitAsymmetricKey (&pubKey, (vlong **)0);
    retVal += UNITTEST_STATUS (10, status);
  }
  if (NULL != pKeyBlob)
  {
    status = DIGI_FREE ((void **)&pKeyBlob);
    retVal += UNITTEST_STATUS (11, status);
  }

#ifdef __ENABLE_DIGICERT_DEBUG_MEMORY__
  dbg_dump ();
#endif

  return (retVal);
}

/*---------------------------------------------------------------------------*/

int
ReadKey(MOC_HASH(hwAccelDescr hwAccelCtx) RSAKey** ppRetKey, const sbyte* fileName, int hint)
{
    ubyte* buffer = NULL;
    ubyte4 bufferLen;
    AsymmetricKey key = {0, 0};
    int retVal = 0;

    if (retVal = UNITTEST_STATUS(hint, DIGICERT_readFile( fileName, &buffer,
                                                        &bufferLen)))
    {
        goto exit;
    }

    if (retVal = UNITTEST_STATUS(hint, PKCS_getPKCS1Key(MOC_HASH(hwAccelCtx) buffer, bufferLen,
                                                         &key)))
    {
        goto exit;
    }

    *ppRetKey = key.key.pRSA;

exit:

    if (buffer)
    {
        FREE( buffer);
    }

    return retVal;
}

/*------------------------------------------------------------------*/

static int SignatureTest( RSAKey* pRSAKey, int iter, int hint)
{
    ubyte*  cipherText = 0;
    ubyte*  plainText = 0;
    sbyte4  cipherTextLen, plainTextLen;
    sbyte4  i, cmpRes;
    sbyte4  retVal = 0;
    vlong*  pQueue = 0;
    const sbyte* msg = "Attack at dawn!";
    hwAccelDescr hwAccelCtx;
    MSTATUS status;
    vlong* pEncrypted = 0;
    vlong* pDecrypted = 0;
    ModExpHelper meh;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

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

    if (OK > ( status = VLONG_vlongFromByteString(cipherText, cipherTextLen,
                                                    &pEncrypted, &pQueue)))
    {
        retVal += UNITTEST_STATUS(hint, status);
        goto exit;
    }
    if (OK > ( status = VLONG_newModExpHelper(MOC_MOD(hwAccelCtx) &meh,
                                                RSA_N(pRSAKey), &pQueue)))
    {
        retVal += UNITTEST_STATUS(hint, status);
        goto exit;
    }

    if (OK > ( status = VLONG_modExp(MOC_MOD(hwAccelCtx)
                                     meh, pEncrypted, RSA_E(pRSAKey),
                                     &pDecrypted, &pQueue)))
    {
        retVal += UNITTEST_STATUS(hint, status);
        goto exit;
    }
    VLONG_freeVlong( &pDecrypted, &pQueue);

    /* for linux we do a speed test that will be captured in the logs */
#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__) || defined (__RTOS_OSX__)
    if (iter)
    {
        int numIters = iter;
#if defined(__USE_TOD__)
        struct rusage tstart,tend;
        long tmp;
#else
        struct tms tstart, tend;
#endif
        double diffTime;

        for (;;)
        {
            START_ALARM(TEST_SECONDS);

#if defined(__USE_TOD__)
            getrusage(RUSAGE_SELF, &tstart);
#else
            times(&tstart);
#endif

            for (i = 0; i < numIters && ALARM_OFF; ++i)
            {
                RSA_signMessage(MOC_RSA(hwAccelCtx) pRSAKey, msg,
                                DIGI_STRLEN(msg)+1, cipherText, &pQueue);
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
            if (diffTime > 1.0)
            {
                printf("\t%d signatures in %g seconds of CPU time\n", i, diffTime);
                printf("%d bits key: %g signatures/second (CPU time)\n",
                       hint, i/diffTime);
                break;
            }
            else
            {
                numIters *= 2;
            }
        }

        numIters = iter;

        for (;;)
        {
            START_ALARM(TEST_SECONDS);

#if defined(__USE_TOD__)
            getrusage(RUSAGE_SELF, &tstart);
#else
            times(&tstart);
#endif

            for (i = 0; i < numIters && ALARM_OFF; ++i)
            {
                RSA_verifySignature(MOC_RSA(hwAccelCtx) pRSAKey, cipherText,
                                    plainText, &plainTextLen, &pQueue);
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
            if (diffTime > 1.0)
            {
                printf("\t%d verifications in %g seconds of CPU time\n", i, diffTime);
                printf("%d bits key: %g verifications/second (CPU time)\n",
                   hint, i/diffTime);
                break;
            }
            else
            {
                numIters *= 2;
            }
        }

        numIters = iter;
        for (;;)
        {
            START_ALARM(TEST_SECONDS);

#if defined(__USE_TOD__)
            getrusage(RUSAGE_SELF, &tstart);
#else
            times(&tstart);
#endif
            for (i = 0; i < numIters && ALARM_OFF; ++i)
            {
                VLONG_modExp(MOC_MOD(hwAccelCtx) meh,
                             pEncrypted, RSA_E(pRSAKey),
                             &pDecrypted, &pQueue);
                VLONG_freeVlong( &pDecrypted, &pQueue);
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
            if (diffTime > 1.0)
            {
                printf("\t%d verifications (openssl) in %g seconds of CPU time\n", i, diffTime);
                printf("%d bits key: %g openssl verifications/second (CPU time)\n",
                       hint, i/diffTime);
                break;
            }
            else
            {
                numIters *= 2;
            }
        }
    }
#endif

/* windows performance -- not very precise but helpful nonetheless */
#if defined( __RTOS_WIN32__) || defined(__RTOS_WINCE__)
    if (iter)
    {
        DWORD ticks;
        double result;
        int maxIter = iter;

        /* let's do one first to see how long it takes */
        ticks = GetTickCount();
        RSA_signMessage(MOC_RSA(hwAccelCtx) pRSAKey, msg,
                            DIGI_STRLEN(msg)+1, cipherText, &pQueue);
        ticks = GetTickCount() - ticks;
        if (ticks)
        {
            iter = ( 30000 / ticks); /* about thirty seconds */
            if (0 == iter)
            {
                iter = 2;  /* at least two */
            }
        }
        if (iter > maxIter)
        {
            iter = maxIter;
        }

        ticks = GetTickCount();
        for (i = 0; i < iter; ++i)
        {
            RSA_signMessage(MOC_RSA(hwAccelCtx) pRSAKey, msg,
                            DIGI_STRLEN(msg)+1, cipherText, &pQueue);
        }
        ticks = GetTickCount() - ticks;
        result = (1000.0 * iter) / ticks;
        printf("%d bits key: %g signatures/second (CPU time)\n",
               hint, result);

        /* let's do one first to see how long it takes */

        ticks = GetTickCount();
        RSA_verifySignature(MOC_RSA(hwAccelCtx) pRSAKey, cipherText,
                                plainText, &plainTextLen, &pQueue);
        ticks = GetTickCount() - ticks;
        if (ticks)
        {
            iter = ( 30000 / ticks); /* about thirty seconds */
            if (0 == iter)
            {
                iter = 2;  /* at least two */
            }
        }
        if (iter > maxIter)
        {
            iter = maxIter;
        }

        ticks = GetTickCount();
        for (i = 0; i < iter; ++i)
        {
            RSA_verifySignature(MOC_RSA(hwAccelCtx) pRSAKey, cipherText,
                                plainText, &plainTextLen, &pQueue);
        }
        ticks = GetTickCount() - ticks;
        result = (1000.0 * iter) / ticks;
        printf("%d bits key: %g verifications/second (CPU time)\n",
               hint, result);

    }
#endif


exit:

    if ( cipherText)
    {
        FREE( cipherText);
    }

    if (plainText)
    {
        FREE( plainText);
    }

    VLONG_freeVlong(&pEncrypted, 0);
    VLONG_freeVlong(&pDecrypted, 0);
    VLONG_freeVlongQueue(&pQueue);

    VLONG_deleteModExpHelper(&meh, NULL);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}


/*------------------------------------------------------------------*/

static int EncryptTest(RSAKey* pRSAKey, int iter, int hint)
{
    ubyte*  cipherText = 0;
    ubyte*  plainText = 0;
    sbyte4  cipherTextLen, plainTextLen;
    sbyte4  i;
    sbyte4  retVal = 0;
    vlong*  pQueue = 0;
    const sbyte* msg = "Attack at dawn!";
    hwAccelDescr hwAccelCtx;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    if (retVal = UNITTEST_STATUS( hint,
            RSA_getCipherTextLength( pRSAKey, &cipherTextLen)))
    {
        goto exit;
    }

    cipherText = MALLOC( cipherTextLen);
    if ( retVal = UNITTEST_VALIDPTR(hint, cipherText))
        goto exit;


    if (retVal = UNITTEST_STATUS( hint,
            RSA_encrypt(MOC_RSA(hwAccelCtx)  pRSAKey, msg, DIGI_STRLEN(msg)+1,
                           cipherText, MyRandom, NULL, &pQueue)))
    {
        goto exit;
    }

    plainText = MALLOC( cipherTextLen);
    if ( retVal = UNITTEST_VALIDPTR(hint, plainText))
        goto exit;

    /* decrypt without blinding */
    if (retVal = UNITTEST_STATUS( hint,
            RSA_decrypt(MOC_RSA(hwAccelCtx) pRSAKey, cipherText, plainText,
                        &plainTextLen, NULL, NULL, &pQueue)))
    {
        goto exit;
    }

    /* verify we get the correct text ... */
    retVal += UNITTEST_INT(hint, 0, DIGI_STRCMP( plainText, msg));

    /* decrypt with blinding */
    for (i = 0; i < 10; ++i)
    {
        if ( UNITTEST_STATUS( hint,
                RSA_decrypt(MOC_RSA(hwAccelCtx) pRSAKey, cipherText, plainText,
                            &plainTextLen, MyRandom, NULL, &pQueue)))
        {
            ++retVal;
            goto exit;
        }

        retVal += UNITTEST_INT(hint, 0, DIGI_STRCMP( plainText, msg));
    }

    /* for linux speed test with blinding */
#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__) || defined (__RTOS_OSX__)
    if (iter)
    {
        int numIters  = iter;
        for (;;)
        {
            struct tms tstart, tend;
            double diffTime;

            START_ALARM(TEST_SECONDS);
            times(&tstart);
            for (i = 0; i < numIters && ALARM_OFF; ++i)
            {
                RSA_decrypt(MOC_RSA(hwAccelCtx) pRSAKey, cipherText, plainText,
                            &plainTextLen, MyRandom, NULL, &pQueue);
            }
            times(&tend);
            diffTime = tend.tms_utime-tstart.tms_utime;
            diffTime /= sysconf(_SC_CLK_TCK);

            /* repeat the test if less than 1.0 sec of CPU time */
            if (diffTime > 1.0)
            {
                printf("\t%d decryptions in %g seconds of CPU time\n",
                   i, diffTime);
                printf("%d bits key: %g decryptions/second (CPU time)\n",
                   hint, i/diffTime);
                break;
            }
            else
            {
                numIters *= 2;
            }
        }
    }
#endif

exit:

    if ( cipherText)
    {
        FREE( cipherText);
    }
    if ( plainText)
    {
        FREE( plainText);
    }

    VLONG_freeVlongQueue(&pQueue);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}


/*---------------------------------------------------------------------------*/

int rsa_test_all_key_size()
{
    int retVal = 0;
    int hint;
    RSAKey* pKey = NULL;
    hwAccelDescr hwAccelCtx;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    retVal += ReadKey(MOC_HASH(hwAccelCtx) &pKey, FILE_PATH("key512.der"), hint = 512);
    if (pKey)
    {
        retVal += EncryptTest( pKey, 1000, hint);
        retVal += SignatureTest( pKey, 1000, hint);
        RSA_freeKey(&pKey,NULL);
    }

    retVal += ReadKey(MOC_HASH(hwAccelCtx) &pKey, FILE_PATH("key1024.der"), hint = 1024);
    if (pKey)
    {
        retVal += EncryptTest( pKey, 1000, hint);
        retVal += SignatureTest( pKey, 1000, hint);
        RSA_freeKey(&pKey,NULL);
    }

    retVal += ReadKey(MOC_HASH(hwAccelCtx) &pKey, FILE_PATH("key2048.der"), hint = 2048);
    if (pKey)
    {
        retVal += EncryptTest( pKey, 1000, hint);
        retVal += SignatureTest( pKey, 1000, hint);
        RSA_freeKey(&pKey, NULL);
    }

    retVal += ReadKey(MOC_HASH(hwAccelCtx) &pKey, FILE_PATH("key4096.der"), hint = 4096);
    if (pKey)
    {
        retVal += EncryptTest( pKey, 1000, hint);
        retVal += SignatureTest( pKey, 1000, hint);
        RSA_freeKey(&pKey, NULL);
    }

    /* odd key sizes */
    retVal += ReadKey(MOC_HASH(hwAccelCtx) &pKey, FILE_PATH("key1025.der"), hint = 1025);
    if (pKey)
    {
        retVal += EncryptTest( pKey, 0, hint);
        retVal += SignatureTest( pKey, 0, hint);
        RSA_freeKey(&pKey, NULL);
    }

    retVal += ReadKey(MOC_HASH(hwAccelCtx) &pKey, FILE_PATH("key1026.der"), hint = 1026);
    if (pKey)
    {
        retVal += EncryptTest( pKey, 0, hint);
        retVal += SignatureTest( pKey, 0, hint);
        RSA_freeKey(&pKey, NULL);
    }

    retVal += ReadKey(MOC_HASH(hwAccelCtx) &pKey, FILE_PATH("key1027.der"), hint = 1027);
    if (pKey)
    {
        retVal += EncryptTest( pKey, 0, hint);
        retVal += SignatureTest( pKey, 0, hint);
        RSA_freeKey(&pKey, NULL);
    }

    retVal += ReadKey(MOC_HASH(hwAccelCtx) &pKey, FILE_PATH("key1028.der"), hint = 1028);
    if (pKey)
    {
        retVal += EncryptTest( pKey, 0, hint);
        retVal += SignatureTest( pKey, 0, hint);
        RSA_freeKey(&pKey, NULL);
    }

    retVal += ReadKey(MOC_HASH(hwAccelCtx) &pKey, FILE_PATH("key1029.der"), hint = 1029);
    if (pKey)
    {
        retVal += EncryptTest( pKey, 0, hint);
        retVal += SignatureTest( pKey, 0, hint);
        RSA_freeKey(&pKey, NULL);
    }

    retVal += ReadKey(MOC_HASH(hwAccelCtx) &pKey, FILE_PATH("key1030.der"), hint = 1030);
    if (pKey)
    {
        retVal += EncryptTest( pKey, 0, hint);
        retVal += SignatureTest( pKey, 0, hint);
        RSA_freeKey(&pKey, NULL);
    }

    retVal += ReadKey(MOC_HASH(hwAccelCtx) &pKey, FILE_PATH("key1031.der"), hint = 1031);
    if (pKey)
    {
        retVal += EncryptTest( pKey, 0, hint);
        retVal += SignatureTest( pKey, 0, hint);
        RSA_freeKey(&pKey, NULL);
    }

    retVal += ReadKey(MOC_HASH(hwAccelCtx) &pKey, FILE_PATH("key1032.der"), hint = 1032);
    if (pKey)
    {
        retVal += EncryptTest( pKey, 0, hint);
        retVal += SignatureTest( pKey, 0, hint);
        RSA_freeKey(&pKey, NULL);
    }

    retVal += ReadKey(MOC_HASH(hwAccelCtx) &pKey, FILE_PATH("key1033.der"), hint = 1033);
    if (pKey)
    {
        retVal += EncryptTest( pKey, 0, hint);
        retVal += SignatureTest( pKey, 0, hint);
        RSA_freeKey(&pKey, NULL);
    }

    retVal += ReadKey(MOC_HASH(hwAccelCtx) &pKey, FILE_PATH("key1055.der"), hint = 1055);
    if (pKey)
    {
        retVal += EncryptTest( pKey, 0, hint);
        retVal += SignatureTest( pKey, 0, hint);
        RSA_freeKey(&pKey, NULL);
    }

    retVal += ReadKey(MOC_HASH(hwAccelCtx) &pKey, FILE_PATH("key1023.der"), hint = 1023);
    if (pKey)
    {
        retVal += EncryptTest( pKey, 0, hint);
        retVal += SignatureTest( pKey, 0, hint);
        RSA_freeKey(&pKey, NULL);
    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}

/*---------------------------------------------------------------------*/

static int IsHexDigit( sbyte c)
{
    if ('0' <= c && c <= '9')
    {
        return 1;
    }
    else if ( 'A' <= c && c <= 'F')
    {
        return 1;
    }
    else if ( 'a' <= c && c <= 'f')
    {
        return 1;
    }
    return 0; /* ??? */
}



/*---------------------------------------------------------------------*/

static ubyte ValOfHexChar( sbyte c)
{
    if ('0' <= c && c <= '9')
    {
        return (ubyte) (c - '0');
    }
    else if ( 'A' <= c && c <= 'F')
    {
        return (ubyte) ( c + 10 - 'A');
    }
    else if ( 'a' <= c && c <= 'f')
    {
        return (ubyte) ( c + 10 - 'a');
    }
    return 0; /* ??? */
}


/*---------------------------------------------------------------------*/

static ubyte ConvertHexCharString(const sbyte* str)
{
    return (ubyte) ((16 * ValOfHexChar(str[0])) + ValOfHexChar(str[1]));
}


/*---------------------------------------------------------------------*/

static void OddCharNumber( ubyte* hexValue, int last, ubyte lastNibble)
{
    for (; last > 0; --last)
    {
        ubyte b = hexValue[last-1];

        hexValue[last] = (((b & 0x0F) << 4) | lastNibble);
        lastNibble = ( b >> 4);
    }
    hexValue[0] = lastNibble;
}

static int ReadHexValue( const char* line, ubyte* hexValue, int max, char* header)
{
    enum {
        BegOfLine,
        EqualSeen,
        ReadHex1,
        ReadHex2,
        EndOfLine
    };
    /* read a FIPS hex value */
    char c;
    int state = BegOfLine;
    char hexChars[2];
    int i = 0;

    while (EndOfLine != state )
    {
        c = *line++;
        if ( 0 == c )
        {
        	return i;
        }
        switch (state)
        {
        case BegOfLine:
            if ( '=' == c)
            {
                *header++ = '\0';
                state = EqualSeen;
            }
            else if ( '\n' == c)
            {
                state = EndOfLine;
            }
            else
            {
                *header++ = c;
            }
            break;

        case EqualSeen:
            if ( IsHexDigit(c))
            {
                state = ReadHex1;
                hexChars[0] = c;
            }
            else if ( '\n' == c)
            {
                state = EndOfLine;
            }
            break;

        case ReadHex1:
            if ( IsHexDigit(c))
            {
                state = ReadHex2;
                hexChars[1] = c;
                if( i < max)
                {
                	ubyte val = ConvertHexCharString(hexChars);
                    hexValue[i++] = val;
                }
            }
            else if ( '\n' == c)
            {
                if (i < max)
                {
                	OddCharNumber( hexValue, i++, ValOfHexChar(hexChars[0]));
                }
                state = EndOfLine;
            }
            break;

        case ReadHex2:
            if ( IsHexDigit(c))
            {
                state = ReadHex1;
                hexChars[0] = c;
            }
            else if ( '\n' == c)
            {
                state = EndOfLine;
            }
            break;
        }
    }
    return i;
}

int rsa_test_verify_pkcs15forgedsignature_test()
{
	int result = 0;
    static ubyte hexValue[MAX_KEY_SIZE];
    static ubyte decSig[MAX_KEY_SIZE];
    ubyte4 decSigSize;
    static char header[255];
    ubyte   decryptedHash[CERT_MAXDIGESTSIZE];
	ubyte4  decryptedHashType;
	sbyte4  decryptedHashLen;
    ubyte4 algNum = 256;
    char currentLine[MAX_LINE_LEN]; /* buffer used to get lines */
    const sbyte* msg = "Now, here, you see, it takes all the running you can do, to keep in the same place. If you want to get somewhere else, you must run at least twice as fast as that";
    FILE* fin = 0;

    // this forged signature is taken for example from url http://www.intelsecurity.com/resources/wp-berserk-analysis-part-1.pdf

    hwAccelDescr hwAccelCtx;

    if (OK > (MSTATUS)(result = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return result;

    fin = fopen( "BerserkForgeryTest.req", "r");
	if ( 0 == fin)
	{
		printf("Unable to open file for reading\n");
		result = -1; // -1 = file open error
        goto exit;
	}

    while (!feof(fin))
    {
        if (fgets( currentLine, MAX_LINE_LEN, fin))
        {
            if ( 0 == strncmp( currentLine, "S = ", 3))
            {
                int sigSize;
                RSAKey* pRSAKey = NULL;
                int hint = 0;
                // this key file is created by using openssl command with public exponent = 3
                // the openssl command is
                // openssl genpkey -algorithm RSA -outform DER -out mykey.der -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:3

                ReadKey(MOC_HASH(hwAccelCtx) &pRSAKey, FILE_PATH("BerserkForgerySignature.der"), hint = 2048);

//                print_vlong("e = ", RSA_E(pRSAKey));
//				print_vlong("n = ", RSA_N(pRSAKey));
//				print_vlong("p = ", RSA_P(pRSAKey));
//				print_vlong("q = ", RSA_Q(pRSAKey));

				if (!pRSAKey)
				{
					result = -1; // key read from file error
                    goto exit;
//					printf("Key read from file successfully \n");
				}

                /* read the signature from file*/
                sigSize = ReadHexValue( currentLine, hexValue, MAX_KEY_SIZE, header);
//                printf("sigSize = %d \n", sigSize);

                /* decrypt and verify the signature */
                result = X509_decryptRSASignatureBuffer(MOC_RSA(hwAccelCtx) pRSAKey,
                										hexValue,
                										sigSize,
                										decryptedHash,
                										&decryptedHashLen,
                										&decryptedHashType);
                RSA_freeKey( &pRSAKey, NULL);

                if(result == ERR_ASN_BAD_LENGTH_FIELD)
                {
                	// this is expected error code for this forged signature
                	// hence marking the result of this test case as OK
                	result = 0;
                }
//                printf("Result = %d \n", result);
            }
        }
    }
//	printf( "Result = %s\n",  result==0 ? "P" : "F  \n");

exit:
	if ( fin)
	{
		fclose(fin);
	}

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

	return result;
}

