/*
 * crypto_interface_blowfish_test.c
 *
 * Blowfish CBC Encryption Test
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

#include "../../common/initmocana.h"
#include "../../crypto/mocasym.h"
#include "../../crypto/blowfish.h"
#include "../../crypto_interface/crypto_interface_priv.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#ifdef __ENABLE_BLOWFISH_CIPHERS__

#define BF_TEST_MAX_KEY_SIZE 16
#define BF_TEST_MAX_TXT_SIZE 32

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

typedef struct bf_test
{
    ubyte pKey[BF_TEST_MAX_KEY_SIZE];
    ubyte4 keyLen;
    ubyte pIv[BLOWFISH_BLOCK_SIZE];
    ubyte pPlain[BF_TEST_MAX_TXT_SIZE];
    ubyte4 plainLen;
    ubyte pCipher[BF_TEST_MAX_TXT_SIZE];
    
} bf_test;

static bf_test gBFTests[] =
{
    /* Test vector 0 */
    {
        {
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        },
        8,
        {
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        },
        {
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        },
        8,
        {
            0x4E,0xF9,0x97,0x45,0x61,0x98,0xDD,0x78
        }
    },
    {
        {
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
        },
        8,
        {
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
        },
        {
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        },
        8,
        {
            0x51,0x86,0x6F,0xD5,0xB8,0x5E,0xCB,0x8A
        }
    },
    {
        {
            0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0xF0,0xE1,0xD2,0xC3,0xB4,0xA5,0x96,0x87
        },
        16,
        {
            0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10
        },
        {   /* "7654321 Now is the time for " with \0 and 3 0x00 padding bytes*/
            0x37,0x36,0x35,0x34,0x33,0x32,0x31,0x20,0x4E,0x6F,0x77,0x20,0x69,0x73,0x20,0x74,
            0x68,0x65,0x20,0x74,0x69,0x6D,0x65,0x20,0x66,0x6F,0x72,0x20,0x00,0x00,0x00,0x00
        },
        32,
        {
            0x6B,0x77,0xB4,0xD6,0x30,0x06,0xDE,0xE6,0x05,0xB1,0x56,0xE2,0x74,0x03,0x97,0x93,
            0x58,0xDE,0xB9,0xE7,0x15,0x46,0x16,0xD9,0x59,0xF1,0x65,0x2B,0xD5,0xFF,0x92,0xCC
        }
    }
};

/*---------------------------------------------------------------------*/

static int test_blowfish(bf_test *pTest, int updateMode)
{
    int retVal = 0;
    MSTATUS status;
    BulkCtx pCtx = NULL;
    BulkCtx pCtxCopy = NULL;
    sbyte4 cmp;
    ubyte pTemp[BF_TEST_MAX_TXT_SIZE];
    ubyte pIv[BLOWFISH_BLOCK_SIZE];

    /* Make a mutable copy of the input and iv*/
    status = DIGI_MEMCPY(pTemp, pTest->pPlain, pTest->plainLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = DIGI_MEMCPY(pIv, pTest->pIv, BLOWFISH_BLOCK_SIZE);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /* Test encryption */
    pCtx = CreateBlowfishCtx(MOC_SYM(gpHwAccelCtx) pTest->pKey, pTest->keyLen, 1);
    if (NULL == pCtx)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
        goto exit;
    }
    
    if (updateMode && pTest->plainLen >= 32)
    {
        /* our api is inplace so only supports full blocks of data at a time */
        status = DoBlowfish(MOC_SYM(gpHwAccelCtx) pCtx, pTemp, 8, 1, pIv);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        /* test the clone API */
        status = CloneBlowfishCtx(MOC_SYM(gpHwAccelCtx) pCtx, &pCtxCopy);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        status = DoBlowfish(MOC_SYM(gpHwAccelCtx) pCtxCopy, pTemp + 8, 16, 1, pIv);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        status = DoBlowfish(MOC_SYM(gpHwAccelCtx) pCtxCopy, pTemp + 24, pTest->plainLen - 24, 1, pIv);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = DoBlowfish(MOC_SYM(gpHwAccelCtx) pCtx, pTemp, pTest->plainLen, 1, pIv);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }
    
    status = DIGI_MEMCMP(pTemp, pTest->pCipher, pTest->plainLen, &cmp);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    if (cmp)
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
    
    status = DeleteBlowfishCtx(MOC_SYM(gpHwAccelCtx) &pCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /* Test decryption, reset the iv again */
    status = DIGI_MEMCPY(pIv, pTest->pIv, BLOWFISH_BLOCK_SIZE);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    pCtx = CreateBlowfishCtx(MOC_SYM(gpHwAccelCtx) pTest->pKey, pTest->keyLen, 0);
    if (NULL == pCtx)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
        goto exit;
    }
    
    if (updateMode && pTest->plainLen >= 32)
    {
        status = DoBlowfish(MOC_SYM(gpHwAccelCtx) pCtx, pTemp, 8, 0, pIv);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        status = DoBlowfish(MOC_SYM(gpHwAccelCtx) pCtx, pTemp + 8, 16, 0, pIv);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        status = DoBlowfish(MOC_SYM(gpHwAccelCtx) pCtx, pTemp + 24, pTest->plainLen - 24, 0, pIv);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = DoBlowfish(MOC_SYM(gpHwAccelCtx) pCtx, pTemp, pTest->plainLen, 0, pIv);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }
    
    status = DIGI_MEMCMP(pTemp, pTest->pPlain, pTest->plainLen, &cmp);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    if (cmp)
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);

exit:
    
    if (NULL != pCtx)
    {
        status = DeleteBlowfishCtx(MOC_SYM(gpHwAccelCtx) &pCtx);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    
    if (NULL != pCtxCopy)
    {
        status = DeleteBlowfishCtx(MOC_SYM(gpHwAccelCtx) &pCtxCopy);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}
#endif /* __ENABLE_BLOWFISH_CIPHERS__ */

/*---------------------------------------------------------------------------*/

int crypto_interface_blowfish_test()
{
    int retVal = 0;
    
#ifdef __ENABLE_BLOWFISH_CIPHERS__
    
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
    
    for (i = 0; i < COUNTOF(gBFTests); ++i)
    {
        retVal += test_blowfish( gBFTests+i, 0);
        retVal += test_blowfish( gBFTests+i, 1);
    }
    
exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif
    
    status = DIGICERT_free(&gpMocCtx);
    retVal += UNITTEST_INT(__MOC_LINE__, status, OK);
    
#endif /* __ENABLE_BLOWFISH_CIPHERS__ */
    
    return retVal;
}
