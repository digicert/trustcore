/*
* crypto_interface_aes_cmac_test.c
*
* test file for AES-CMAC
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
#include "../../common/initmocana.h"
#include "../../crypto/mocasym.h"
#include "../../crypto/aes.h"
#include "../../crypto/aes_ecb.h"
#include "../../crypto/aes_cmac.h"
#include "../../crypto_interface/crypto_interface_priv.h"
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
#include "../../crypto_interface/crypto_interface_aes_cmac.h"
#endif

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#if (!defined(__DISABLE_AES_CIPHERS__)) && (!defined(__DISABLE_AES_CMAC__))

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

/* Test vectors from RFC 4493 ***********************************
 --------------------------------------------------
   Subkey Generation
   K              2b7e1516 28aed2a6 abf71588 09cf4f3c
   AES-128(key,0) 7df76b0c 1ab899b3 3e42f047 b91b546f
   K1             fbeed618 35713366 7c85e08f 7236a8de
   K2             f7ddac30 6ae266cc f90bc11e e46d513b
   --------------------------------------------------

   --------------------------------------------------
   Example 1: len = 0
   M              <empty string>
   AES-CMAC       bb1d6929 e9593728 7fa37d12 9b756746
   --------------------------------------------------

   Example 2: len = 16
   M              6bc1bee2 2e409f96 e93d7e11 7393172a
   AES-CMAC       070a16b4 6b4d4144 f79bdd9d d04a287c
   --------------------------------------------------

   Example 3: len = 40
   M              6bc1bee2 2e409f96 e93d7e11 7393172a
                  ae2d8a57 1e03ac9c 9eb76fac 45af8e51
                  30c81c46 a35ce411
   AES-CMAC       dfa66747 de9ae630 30ca3261 1497c827
   --------------------------------------------------

   Example 4: len = 64
   M              6bc1bee2 2e409f96 e93d7e11 7393172a
                  ae2d8a57 1e03ac9c 9eb76fac 45af8e51
                  30c81c46 a35ce411 e5fbc119 1a0a52ef
                  f69f2445 df4f9b17 ad2b417b e66c3710
   AES-CMAC       51f0bebf 7e3b9d92 fc497417 79363cfe
   --------------------------------------------------

****************************************************************/

typedef struct AES_CMAC_TestVector
{
    const ubyte*    message;
    sbyte4          messageLen;
    const ubyte     mac[AES_BLOCK_SIZE];
} AES_CMAC_TestVector;


static AES_CMAC_TestVector cmacTV[] =
{
    /* 1 */
    {
        (const ubyte *) "\x00",
        0,
        {
            0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
            0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46
        }
    },
    /* 2 */
    {
        (const ubyte *) "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96"
        "\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
        16,
        {
            0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
            0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c
        }
    },

    /* 3 */
    {

        (const ubyte *) "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96"
        "\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
        "\xae\x2d\x8a\x57\x1e\x03\xac\x9c"
        "\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
        "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11",
        40,
        {
            0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
            0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27
        }
    },

    /* 4 */
    {

        (const ubyte *) "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96"
        "\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
        "\xae\x2d\x8a\x57\x1e\x03\xac\x9c"
        "\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
        "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11"
        "\xe5\xfb\xc1\x19\x1a\x0a\x52\xef"
        "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17"
        "\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
        64,
        {
            0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
            0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe
        }
    }
};

static const ubyte K[] = { 0x2b, 0x7e, 0x15, 0x16,
                            0x28, 0xae, 0xd2, 0xa6,
                            0xab, 0xf7, 0x15, 0x88,
                            0x09, 0xcf, 0x4f, 0x3c };


/*---------------------------------------------------------------------------*/

static int
test_vector_test(  AES_CMAC_TestVector* pWhichTest, int hint)
{
    AESCMAC_Ctx ctx;
    int         errors = 0;
    sbyte4      i, cmpRes;
    ubyte       mac[CMAC_RESULT_SIZE];
    MSTATUS     status;

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)
    AESCMAC_Ctx clone = {0};
#endif

    /* special case */
    if (  0 == pWhichTest->messageLen)
    {
        status = AESCMAC_init(MOC_SYM(gpHwAccelCtx) K, 16, &ctx);
        errors += UNITTEST_STATUS( hint, status);

        status = AESCMAC_final(MOC_SYM(gpHwAccelCtx) mac, &ctx);
        errors += UNITTEST_STATUS( hint, status);

        DIGI_MEMCMP( mac, pWhichTest->mac, CMAC_RESULT_SIZE, &cmpRes);
        errors += UNITTEST_INT( hint, cmpRes, 0);

        goto exit;
    }

    /* send the message byte by byte, 2 bytes by 2 bytes, etc... */
    for ( i = 1; i <= pWhichTest->messageLen; ++i)
    {
        sbyte4 sent = 0;

        status = AESCMAC_init(MOC_SYM(gpHwAccelCtx) K, 16, &ctx);

        errors += UNITTEST_STATUS( hint, status);
        while ( sent < pWhichTest->messageLen)
        {
            sbyte4 toSend;
            toSend = i;
            if ( toSend > pWhichTest->messageLen - sent)
            {
                toSend = pWhichTest->messageLen - sent;
            }
            status = AESCMAC_update(MOC_SYM(gpHwAccelCtx)
                        pWhichTest->message + sent, toSend, &ctx);
            errors += UNITTEST_STATUS( hint, status);
            sent += toSend;
        }
        DIGI_MEMSET(mac, 0, CMAC_RESULT_SIZE);

        /* test clone if not export. Clone can be added to mbed operator at a later date */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)
        status = CRYPTO_INTERFACE_AESCMAC_cloneCtx(MOC_SYM(gpHwAccelCtx) &clone, &ctx);
        errors += UNITTEST_STATUS( hint, status);

        /* must call final on the original context to free data */
        status = CRYPTO_INTERFACE_AESCMAC_final(MOC_SYM(gpHwAccelCtx) mac, &ctx);
        errors += UNITTEST_STATUS( hint, status);

        DIGI_MEMCMP( mac, pWhichTest->mac, CMAC_RESULT_SIZE, &cmpRes);
        errors += UNITTEST_INT( hint, cmpRes + i, i); /* trick to get the i info in error message */

        DIGI_MEMSET(mac, 0, CMAC_RESULT_SIZE);

        /* now continue again with the clone */
        status = CRYPTO_INTERFACE_AESCMAC_finalAndReset(MOC_SYM(gpHwAccelCtx) mac, &clone);
        errors += UNITTEST_STATUS( hint, status);

        DIGI_MEMCMP( mac, pWhichTest->mac, CMAC_RESULT_SIZE, &cmpRes);
        errors += UNITTEST_INT( hint, cmpRes + i, i); /* trick to get the i info in error message */

        /* do everything again with the reset ctx */
        sent = 0;
        while ( sent < pWhichTest->messageLen)
        {
            sbyte4 toSend;
            toSend = i;
            if ( toSend > pWhichTest->messageLen - sent)
            {
                toSend = pWhichTest->messageLen - sent;
            }
            status = CRYPTO_INTERFACE_AESCMAC_update(MOC_SYM(gpHwAccelCtx)
                        pWhichTest->message + sent, toSend, &clone);
            errors += UNITTEST_STATUS( hint, status);
            sent += toSend;
        }
        DIGI_MEMSET(mac, 0, CMAC_RESULT_SIZE);

        status = CRYPTO_INTERFACE_AESCMAC_final(MOC_SYM(gpHwAccelCtx) mac, &clone);
        errors += UNITTEST_STATUS( hint, status);
#else
        status = AESCMAC_final(MOC_SYM(gpHwAccelCtx) mac, &ctx);
        errors += UNITTEST_STATUS( hint, status);
#endif
        DIGI_MEMCMP( mac, pWhichTest->mac, CMAC_RESULT_SIZE, &cmpRes);
        errors += UNITTEST_INT( hint, cmpRes + i, i); /* trick to get the i info in error message */
    }

exit:
    
    return errors;
}

static int testErrorCases()
{
    MSTATUS status;
    int retVal = 0;
    
    AESCMAC_Ctx ctx = {0};
    
    ubyte pCmac[CMAC_RESULT_SIZE] = {0};
    ubyte pData[32] = {0};
    ubyte pKey[32] = {0};
    
    /******* AESCMAC_init *******/

    /* null params */
    status = AESCMAC_init(MOC_SYM(gpHwAccelCtx) NULL, 32, &ctx);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = AESCMAC_init(MOC_SYM(gpHwAccelCtx) pKey, 32, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* invalid keyLen */
    status = AESCMAC_init(MOC_SYM(gpHwAccelCtx) pKey, 0, &ctx);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_CMAC__) && defined(__ENABLE_DIGICERT_AES_CMAC_MBED__)
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
#else
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_AES);
#endif
    
    status = AESCMAC_init(MOC_SYM(gpHwAccelCtx) pKey, 15, &ctx);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_CMAC__) && defined(__ENABLE_DIGICERT_AES_CMAC_MBED__)
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_AES_BAD_KEY_LENGTH);
#else
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_AES);
#endif
    
    status = AESCMAC_init(MOC_SYM(gpHwAccelCtx) pKey, 17, &ctx);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_CMAC__) && defined(__ENABLE_DIGICERT_AES_CMAC_MBED__)
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_AES_BAD_KEY_LENGTH);
#else
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_AES);
#endif
    
    status = AESCMAC_init(MOC_SYM(gpHwAccelCtx) pKey, 31, &ctx);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_CMAC__) && defined(__ENABLE_DIGICERT_AES_CMAC_MBED__)
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_AES_BAD_KEY_LENGTH);
#else
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_AES);
#endif
    
    status = AESCMAC_init(MOC_SYM(gpHwAccelCtx) pKey, 33, &ctx);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_CMAC__) && defined(__ENABLE_DIGICERT_AES_CMAC_MBED__)
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_AES_BAD_KEY_LENGTH);
#else
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_AES);
#endif

    /* uninitialized ctx */
    status = AESCMAC_update(MOC_SYM(gpHwAccelCtx) pData, 32, &ctx);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_CMAC__) && defined(__ENABLE_DIGICERT_AES_CMAC_MBED__)
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE);
#else
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
#endif

    status = AESCMAC_final(MOC_SYM(gpHwAccelCtx) pCmac, &ctx);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_CMAC__) && defined(__ENABLE_DIGICERT_AES_CMAC_MBED__)
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE);
#else
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
#endif

    /* properly initialize for further tests */
    
    status = AESCMAC_init(MOC_SYM(gpHwAccelCtx) pKey, 32, &ctx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /******* AESCMAC_update *******/

    /* null params */
    status = AESCMAC_update(MOC_SYM(gpHwAccelCtx) NULL, 32, &ctx);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = AESCMAC_update(MOC_SYM(gpHwAccelCtx) pData, 32, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = AESCMAC_update(MOC_SYM(gpHwAccelCtx) pData, 0, &ctx);  /* ok to call update with zero length data */
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    
    /******* AESCMAC_final *******/
    
    status = AESCMAC_final(MOC_SYM(gpHwAccelCtx) NULL, &ctx);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = AESCMAC_final(MOC_SYM(gpHwAccelCtx) pCmac, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

exit:
    
    /* properly call final to free internal aes ctx */
    status = AESCMAC_final(MOC_SYM(gpHwAccelCtx) pCmac, &ctx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

    return retVal;
}

#endif /* (!defined(__DISABLE_AES_CIPHERS__)) && (!defined(__DISABLE_AES_CMAC__)) */

/*---------------------------------------------------------------------------*/

int crypto_interface_aes_cmac_test_vectors()
{
    int retVal = 0;
    
#if (!defined(__DISABLE_AES_CIPHERS__)) && (!defined(__DISABLE_AES_CMAC__))
    
    MSTATUS status;
    int i;

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
    
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    status = (MSTATUS) HARDWARE_ACCEL_INIT();
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
    
    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
#endif

    for (i = 0; i < COUNTOF(cmacTV); ++i)
    {
        retVal +=  test_vector_test( cmacTV+i, i);
    }

    retVal += testErrorCases();

exit:
    
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif
    
    status = DIGICERT_free(&gpMocCtx);
    retVal += UNITTEST_INT(__MOC_LINE__, status, OK);
    
#endif /* (!defined(__DISABLE_AES_CIPHERS__)) && (!defined(__DISABLE_AES_CMAC__)) */
    return retVal;
}
