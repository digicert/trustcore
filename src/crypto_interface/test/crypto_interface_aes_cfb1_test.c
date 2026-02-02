/*
* crypto_interface_aescfb1_test.c
*
* test file for AES in CFB1 mode
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
#include "../../../unit_tests/unittest.h"

#include "../../common/initmocana.h"
#include "../../crypto/mocasym.h"
#include "../../crypto/aes.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../../crypto_interface/crypto_interface_aes.h"
#endif

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

static MocCtx gpMocCtx = NULL;

typedef struct aesTest{
    ubyte pKey[32];
    sbyte4 keyLen;
    ubyte pIv[16];
    sbyte4 ivLen;
    ubyte pPlain[48];
    sbyte4 plainLen;
    ubyte pCipher[48];
    sbyte4 cipherLen;
} aesTest;

/* Tests from NIST SP800-38 */
static aesTest gTests[3] = 
{
    {
        {
            0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
        },
        16,
        {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
        },
        16,
        {
            0x6b, 0xc1
        },
        2,
        {
            0x68, 0xb3
        },
        2
    },
    {
        {
            0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b
        },
        24,
        {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
        },
        16,
        {
            0x6b, 0xc1
        },
        2,
        {
            0x93, 0x59
        },
        2
    },
    {
        {
            0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
            0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
        },
        32,
        {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
        },
        16,
        {
            0x6b, 0xc1
        },
        2,
        {
            0x90, 0x29
        },
        2
    }
};
  
/*----------------------------------------------------------------------------*/

static int runTest(aesTest *pTest)
{
    int errorCount = 0;

    MSTATUS status = ERR_NULL_POINTER;

    /* buffer for DoAES operations */

    sbyte4 ivLen;
    ubyte pIv[16] = { 0 };
    sbyte4 dataLen = 48;
    ubyte pData[48] = { 0 };

    sbyte4 cmpRes = -1;
    aesCipherContext *pAesCtx = NULL;

    ivLen = pTest->ivLen;
    status = DIGI_MEMCPY(pIv, pTest->pIv, ivLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    dataLen = pTest->plainLen;
    status = DIGI_MEMCPY(pData, pTest->pPlain, dataLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    pAesCtx = (aesCipherContext*)CreateAESCFB1Ctx( MOC_SYM(gpHwAccelCtx) pTest->pKey, pTest->keyLen, TRUE);
    if(NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DoAES(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData, dataLen, TRUE, pIv);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DIGI_MEMCMP(pData, pTest->pCipher, dataLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    if(0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DeleteAESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pAesCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;


    /* do decryption step */
    pAesCtx = (aesCipherContext*)CreateAESCFB1Ctx( MOC_SYM(gpHwAccelCtx) pTest->pKey, pTest->keyLen, FALSE);
    if(NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DIGI_MEMCPY(pIv, pTest->pIv, ivLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DoAES(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData, dataLen, FALSE, pIv);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DIGI_MEMCMP(pData, pTest->pPlain, dataLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    if(0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:

    if (NULL != pAesCtx)
    {
        DeleteAESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx *)&pAesCtx);
    }

    if(OK != status)
        return 1;
    return 0;
}

/*----------------------------------------------------------------------------*/

int crypto_interface_aes_cfb1_test_init()
{
    int errorCount = 0;

#if !defined(__DISABLE_AES_CIPHERS__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__) && !defined(__ENABLE_DIGICERT_FIPS_MODULE__)

    MSTATUS status = ERR_NULL_POINTER;
    InitMocanaSetupInfo setupInfo = { 0 };
    /**********************************************************
     *************** DO NOT USE MOC_NO_AUTOSEED ***************
     ***************** in any production code. ****************
     **********************************************************/
    setupInfo.flags = MOC_NO_AUTOSEED;

    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    if (OK != status)
    {
        errorCount = 1;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    status = (MSTATUS) HARDWARE_ACCEL_INIT();
    if (OK != status)
    {
        errorCount = 1;
        goto exit;
    }
    
    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    if (OK != status)
    {
        errorCount = 1;
        goto exit;
    }
#endif
    
    errorCount = (errorCount + runTest(&gTests[0]));
    errorCount = (errorCount + runTest(&gTests[1]));
    errorCount = (errorCount + runTest(&gTests[2]));

exit:
    
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

    DIGICERT_free(&gpMocCtx);

#endif /* !defined(__DISABLE_AES_CIPHERS__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__) && !defined(__ENABLE_DIGICERT_FIPS_MODULE__) */
    return errorCount;
}
