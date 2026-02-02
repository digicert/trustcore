/*
* crypto_interface_aesofb_test.c
*
* test file for AES in OFB mode
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
#include "../../crypto/aes_ctr.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../../crypto_interface/crypto_interface_aes.h"

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TPM2__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
#include "crypto_interface_tap_example.h"
#include "../../crypto/mocsymalgs/tap/symtap.h"
#include "../../crypto_interface/crypto_interface_sym_tap.h"
#include "../../crypto_interface/crypto_interface_aes_tap.h"
#endif
#endif

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_UNITTEST_SPEEDTEST__

#include <sys/types.h>
#include <sys/times.h>
#include <unistd.h>
#include <stdio.h>

#define ENCRYPT_ITERATIONS 10000000
#define DECRYPT_ITERATIONS 10000000

#endif

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

static aesTest pMultiBlockTests[3] = {
    {
        {
            0xc4, 0xc7, 0xfa, 0xd6, 0x53, 0x5c, 0xb8, 0x71, 0x4a, 0x5c,
            0x40, 0x77, 0x9a, 0x8b, 0xa1, 0xd2, 0x53, 0x3e, 0x23, 0xb4,
            0xb2, 0x58, 0x73, 0x2a, 0x5b, 0x78, 0x01, 0xf4, 0xe3, 0x71,
            0xa7, 0x94
        },
        32,
        {
            0x5e, 0xb9, 0x33, 0x13, 0xb8, 0x71, 0xff, 0x16, 0xb9, 0x8a,
            0x9b, 0xcb, 0x43, 0x33, 0x0d, 0x6f
        },
        16,
        {
            0x6d, 0x0b, 0xb0, 0x79, 0x63, 0x84, 0x71, 0xe9, 0x39, 0xd4,
            0x53, 0x14, 0x86, 0xc1, 0x4c, 0x25, 0x9a, 0xee, 0xc6, 0xf3,
            0xc0, 0x0d, 0xfd, 0xd6, 0xc0, 0x50, 0xa8, 0xba, 0xa8, 0x20,
            0xdb, 0x71, 0xcc, 0x12, 0x2c, 0x4e, 0x0c, 0x17, 0x15, 0xef,
            0x55, 0xf3, 0x99, 0x5a, 0x6b, 0xf0, 0x2a, 0x4c
        },
        48,
        {
            0x0f, 0x54, 0x61, 0x71, 0x59, 0xd0, 0x3f, 0xfc, 0x1b, 0xfa,
            0xfb, 0x60, 0x29, 0x30, 0xd7, 0x00, 0xf4, 0xa4, 0xa8, 0xe6,
            0xdd, 0x93, 0x94, 0x46, 0x64, 0xd2, 0x19, 0xc4, 0xc5, 0x4d,
            0xde, 0x1b, 0x04, 0x53, 0xe1, 0x73, 0xf5, 0x18, 0x74, 0xae,
            0xfd, 0x64, 0xa2, 0xe1, 0xe2, 0x76, 0x13, 0xb0
        },
        48
    },
    {
        {
            0x15, 0x5f, 0x12, 0x74, 0x4f, 0x6c, 0xf7, 0xe1, 0xf1, 0x08,
            0xdf, 0x34, 0x1c, 0x5e, 0x9c, 0x02, 0xdd, 0xd4, 0x48, 0x12,
            0xb2, 0x85, 0xe4, 0x6f
        },
        24,
        {
            0x85, 0x5a, 0x58, 0x99, 0x18, 0x04, 0x72, 0x42, 0x7a, 0x10,
            0x02, 0xc0, 0xba, 0x5a, 0x3d, 0xff
        },
        16,
        {
            0xe7, 0xef, 0xcd, 0x84, 0xd5, 0x2e, 0x30, 0x37, 0x6d, 0x96,
            0xac, 0xe9, 0x21, 0x60, 0xe2, 0xce, 0x24, 0x7e, 0x4b, 0x82,
            0x74, 0x8c, 0x67, 0x9d, 0x18, 0x04, 0x18, 0x87, 0xa6, 0xb1,
            0x48, 0x8e, 0x09, 0x66, 0xd2, 0x35, 0x81, 0xef, 0xa0, 0xcf,
            0xeb, 0x48, 0x11, 0x4d, 0x43, 0x0d, 0x9d, 0x55
        },
        48,
        {
            0xd6, 0x07, 0x9c, 0x22, 0xd7, 0x40, 0x63, 0x7b, 0x24, 0xfd,
            0x80, 0x1e, 0xb0, 0x2a, 0xb2, 0x4e, 0x6d, 0x0f, 0x32, 0xa9,
            0xae, 0x7c, 0x0e, 0xaf, 0xb1, 0x3b, 0x5f, 0xcf, 0xdf, 0x05,
            0xe1, 0x81, 0x1c, 0x2e, 0xd7, 0xf3, 0x37, 0xe1, 0xb9, 0x64,
            0xed, 0x0d, 0xa1, 0x09, 0x90, 0xb5, 0x0d, 0xe6
        },
        48
    },
    {
        {
            0x7a, 0x70, 0xcc, 0x6b, 0x26, 0x1e, 0xec, 0xcb, 0x05, 0xc5,
            0x71, 0x17, 0xd5, 0x76, 0x31, 0x97
        },
        16,
        {
            0xbb, 0x7b, 0x96, 0x67, 0xfb, 0xd7, 0x6d, 0x5e, 0xe2, 0x04,
            0x82, 0x87, 0x69, 0xa3, 0x41, 0xb1
        },
        16,
        {
            0x82, 0x3c, 0xba, 0xae, 0x37, 0x60, 0xc8, 0x55, 0x12, 0xa3,
            0xc8, 0x3f, 0xd6, 0x0b, 0xb5, 0x4b, 0x7c, 0xfc, 0x73, 0x9b,
            0x29, 0x5b, 0x63, 0xe0, 0x5e, 0xf4, 0x35, 0xd8, 0x6e, 0x19,
            0xfd, 0x15, 0x36, 0x8c, 0x89, 0xff, 0x08, 0xa0, 0xf2, 0x1c,
            0xe8, 0x9a, 0x72, 0x8f, 0xfb, 0x5d, 0x75, 0xdf
        },
        48,
        {
            0xf5, 0xc4, 0x9a, 0xae, 0x8a, 0x02, 0x6b, 0xf0, 0x5e, 0x52,
            0x5a, 0x12, 0xab, 0x7e, 0x19, 0x5e, 0xea, 0x8a, 0x1b, 0x71,
            0xa8, 0xd3, 0x2a, 0x51, 0x13, 0xaa, 0x89, 0x74, 0x85, 0x8f,
            0x2c, 0xfc, 0x03, 0x39, 0x80, 0x50, 0x03, 0xa0, 0xcb, 0x1a,
            0x7b, 0xe1, 0x9f, 0x37, 0x6d, 0x46, 0x04, 0xeb
        },
        48
    }
};

static aesTest pSingleBlockTests[3] = {
    {
        {
            0x6f, 0x41, 0x9b, 0x4c, 0x68, 0x3a, 0x44, 0xd6, 0x7d, 0x23,
            0x4e, 0xaa, 0x6b, 0x57, 0xf6, 0x22, 0xf9, 0x12, 0xde, 0x65,
            0x7d, 0xdd, 0xb2, 0x80, 0xa1, 0x4d, 0x0c, 0xb9, 0x67, 0xed,
            0x95, 0x1f
        },
        32,
        {
            0x19, 0xb8, 0x88, 0x80, 0x0f, 0xf1, 0xd0, 0x11, 0x61, 0x24,
            0xf7, 0x9d, 0xfa, 0xe5, 0x4f, 0xfe
        },
        16,
        {
            0x3d, 0x12, 0x98, 0x9f, 0xaf, 0x41, 0xba, 0x75, 0xbf, 0xa7,
            0x0e, 0x2b, 0xcc, 0x2f, 0xa2, 0x22
        },
        16,
        {
            0x2d, 0x6b, 0x00, 0x5e, 0x8d, 0x3b, 0xc6, 0xea, 0x9f, 0x62,
            0xdc, 0xa3, 0x6d, 0x47, 0xae, 0xa5
        },
        16
    },
    {
        {
            0x29, 0x43, 0xe3, 0xed, 0xfa, 0x81, 0x52, 0x60, 0xa8, 0xa6,
            0x97, 0xb3, 0x86, 0xca, 0x3a, 0xe3, 0xee, 0xe9, 0x14, 0xf2,
            0x2b, 0x38, 0x57, 0xdc
        },
        24,
        {
            0xc6, 0x99, 0x5f, 0x00, 0x31, 0x8c, 0x24, 0x12, 0x17, 0xcd,
            0xc8, 0x2c, 0xf2, 0xfa, 0x43, 0xf9
        },
        16,
        {
            0x67, 0xe2, 0xcf, 0x5d, 0x63, 0x33, 0x4a, 0xe0, 0x3d, 0xbd,
            0xa9, 0x11, 0x00, 0xab, 0x78, 0x1b
        },
        16,
        {
            0x22, 0x5e, 0x8b, 0xfb, 0x13, 0x3c, 0x43, 0x32, 0xba, 0x6e,
            0x95, 0xdd, 0xb8, 0x41, 0x37, 0x0d
        },
        16
    },
    {
        {
            0xd7, 0xd5, 0x7b, 0xd8, 0x47, 0x15, 0x4a, 0xf9, 0x72, 0x2a,
            0x8d, 0xf0, 0x96, 0xe6, 0x1a, 0x42
        },
        16,
        {
            0xfd, 0xde, 0x20, 0x1c, 0x91, 0xe4, 0x01, 0xd9, 0x72, 0x38,
            0x68, 0xc2, 0xa6, 0x12, 0xb7, 0x7a
        },
        16,
        {
            0x81, 0x88, 0x3f, 0x22, 0x16, 0x52, 0x82, 0xba, 0x6a, 0x44,
            0x2a, 0x8d, 0xd2, 0xa7, 0x68, 0xd4
        },
        16,
        {
            0x84, 0xcc, 0x13, 0x0b, 0x68, 0x67, 0x62, 0x36, 0x96, 0xaa,
            0x8f, 0x52, 0x3d, 0x96, 0x8a, 0xde
        },
        16
    }
};

/* prototypes for arrays defined at end of file */
static aesTest pMultiBlockTests[3];
static aesTest pSingleBlockTests[3];

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES__))
/*----------------------------------------------------------------------------*/
static int testCryptoInterface(aesTest test)
{
    MSTATUS status = OK;

    aesCipherContext *pAesCtx = NULL;;
    MocSymCtx pTest = NULL;
    ubyte enabled ='\0';

#if (defined(__ENABLE_DIGICERT_MBED_SYM_OPERATORS__) && \
    (defined(__ENABLE_DIGICERT_AES_OFB_MBED__)))
    pAesCtx = (aesCipherContext*)CreateAESOFBCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, TRUE);
    if(NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    pTest = pAesCtx->pMocSymCtx;
    enabled = pAesCtx->enabled;
    if(NULL == pTest)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if(FALSE == enabled)
    {
        status = ERR_INVALID_ARG;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

#endif

exit:

    if (NULL != pAesCtx)
    {
        DeleteAESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx *)&pAesCtx);
    }

    if(OK != status)
        return 1;
    return 0;
}
#endif


/*----------------------------------------------------------------------------*/

static int negativeTestsAesAlgo()
{
    MSTATUS status = ERR_NULL_POINTER;
    int errorCount = 0;

    aesCipherContext *pCtx = NULL;
    ubyte pIv[16];
    sbyte4 keyLen = 32;
    ubyte pKey[32] = {0x00};
    ubyte pMsg[10];
    sbyte4 outLen = 0;
    ubyte pOut[500];
    sbyte4 cipherMode = MODE_OFB;

    pCtx = (aesCipherContext*)CreateAESOFBCtx(MOC_SYM(gpHwAccelCtx) pKey, keyLen, TRUE);
    if(NULL == pCtx)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        errorCount = 1;
        goto exit;
    }

    status = AESALGO_makeAesKeyEx(MOC_SYM(gpHwAccelCtx) NULL, keyLen, pKey, TRUE, cipherMode);
    if(OK == status)
    {
        errorCount += UNITTEST_STATUS(__MOC_LINE__, ERR_NULL_POINTER);
    }

    if(OK == status)
    {
        errorCount += UNITTEST_STATUS(__MOC_LINE__, ERR_NULL_POINTER);
    }

    status = AESALGO_makeAesKeyEx(MOC_SYM(gpHwAccelCtx) pCtx, keyLen, NULL, TRUE, cipherMode);
    if(OK == status)
    {
        errorCount += UNITTEST_STATUS(__MOC_LINE__, ERR_NULL_POINTER);
    }

    status = AESALGO_makeAesKeyEx(MOC_SYM(gpHwAccelCtx) pCtx, 0, pKey, TRUE, cipherMode);
    if(OK == status)
    {
        errorCount += UNITTEST_STATUS(__MOC_LINE__, ERR_NULL_POINTER);
    }

    /* 11111 is an invalid mode */
    status = AESALGO_makeAesKeyEx(MOC_SYM(gpHwAccelCtx) pCtx, 0, pKey, TRUE, 11111);
    if(OK == status)
    {
        errorCount += UNITTEST_STATUS(__MOC_LINE__, ERR_NULL_POINTER);
    }

    status = AESALGO_clearKey(NULL);
    if(OK == status)
    {
        errorCount += UNITTEST_STATUS(__MOC_LINE__, ERR_NULL_POINTER);
    }

    status = AESALGO_blockEncryptEx(MOC_SYM(gpHwAccelCtx) NULL, pIv, pMsg, 128, pOut, &outLen);
    if(OK == status)
    {
        errorCount += UNITTEST_STATUS(__MOC_LINE__, ERR_NULL_POINTER);
    }

    status = AESALGO_blockEncryptEx(MOC_SYM(gpHwAccelCtx) pCtx, NULL, pMsg, 128, pOut, &outLen);
    if(OK == status)
    {
        errorCount += UNITTEST_STATUS(__MOC_LINE__, ERR_NULL_POINTER);
    }

    status = AESALGO_blockEncryptEx(MOC_SYM(gpHwAccelCtx) pCtx, pIv, NULL, 128, pOut, &outLen);
    if(OK == status)
    {
        errorCount += UNITTEST_STATUS(__MOC_LINE__, ERR_NULL_POINTER);
    }

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES__))

    /* set mode to an invalid value for negative test */
    pCtx->mode = 10101;
    status = AESALGO_blockEncryptEx(MOC_SYM(gpHwAccelCtx) pCtx, pIv, pMsg, 128, pOut, &outLen);
    if(OK == status)
    {
        errorCount += UNITTEST_STATUS(__MOC_LINE__, ERR_NULL_POINTER);
    }

    /* return mode to valid value */
    pCtx->mode = MODE_OFB;
#endif
    /* set encrypt value to FALSE for AESALGO_blockDecrypt tests */
    pCtx->encrypt = FALSE;
    status = AESALGO_blockDecryptEx(MOC_SYM(gpHwAccelCtx) NULL, pIv, pMsg, 128, pOut, &outLen);
    if(OK == status)
    {
        errorCount += UNITTEST_STATUS(__MOC_LINE__, ERR_NULL_POINTER);
    }

    status = AESALGO_blockDecryptEx(MOC_SYM(gpHwAccelCtx) pCtx, NULL, pMsg, 128, pOut, &outLen);
    if(OK == status)
    {
        errorCount += UNITTEST_STATUS(__MOC_LINE__, ERR_NULL_POINTER);
    }

    status = AESALGO_blockDecryptEx(MOC_SYM(gpHwAccelCtx) pCtx, pIv, NULL, 128, pOut, &outLen);
    if(OK == status)
    {
        errorCount += UNITTEST_STATUS(__MOC_LINE__, ERR_NULL_POINTER);
    }

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES__))
    /* set mode to an invalid value for negative test */
    pCtx->mode = 10101;
    status = AESALGO_blockDecryptEx(MOC_SYM(gpHwAccelCtx) pCtx, pIv, pMsg, 128, pOut, &outLen);
    if(OK == status)
    {
        errorCount += UNITTEST_STATUS(__MOC_LINE__, ERR_NULL_POINTER);
    }

    pCtx->mode = MODE_OFB;
#endif

exit:
    DeleteAESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pCtx);
    return errorCount;
}

/*----------------------------------------------------------------------------*/

static int negativeTest()
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 errorCount = 0;

    ubyte pKey[24] = { 0 };
    sbyte4 keyLen = 24;

    ubyte pIv[16] = { 0 };
    ubyte pPlain[48] = { 0 };

    aesCipherContext *pAesCtx;

    pAesCtx = (aesCipherContext*)CreateAESCtx(MOC_SYM(gpHwAccelCtx) pKey, keyLen, TRUE);
    if(NULL == pAesCtx)
    {
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DoAES(MOC_SYM(gpHwAccelCtx) pAesCtx, pPlain, 16, FALSE, pIv);
    if(OK != status)
    {
        errorCount = (errorCount + 1);
    }
    else
    {
        status = ERR_INVALID_INPUT;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = DoAES(MOC_SYM(gpHwAccelCtx) pAesCtx, pPlain, 15, FALSE, pIv);
    if(OK != status)
    {
        errorCount = (errorCount + 1);
    }
    else
    {
        status = ERR_INVALID_INPUT;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = DoAES(MOC_SYM(gpHwAccelCtx) NULL, pPlain, 15, FALSE, pIv);
    if(OK != status)
    {
        errorCount = (errorCount + 1);
    }
    else
    {
        status = ERR_INVALID_INPUT;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = DoAES(MOC_SYM(gpHwAccelCtx) pAesCtx, NULL, 15, FALSE, pIv);
    if(OK != status)
    {
        errorCount = (errorCount + 1);
    }
    else
    {
        status = ERR_INVALID_INPUT;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = DoAES(MOC_SYM(gpHwAccelCtx) pAesCtx, NULL, 16, TRUE, pIv);
    if(OK != status)
    {
        errorCount = (errorCount + 1);
    }
    else
    {
        status = ERR_INVALID_INPUT;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = DoAES(MOC_SYM(gpHwAccelCtx) pAesCtx, pPlain, 16, TRUE, NULL);
    if(OK != status)
    {
        errorCount = (errorCount + 1);
    }
    else
    {
        status = ERR_INVALID_INPUT;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = DoAES(MOC_SYM(gpHwAccelCtx) pAesCtx, NULL, 16, TRUE, NULL);
    if(OK != status)
    {
        errorCount = (errorCount + 1);
    }
    else
    {
        status = ERR_INVALID_INPUT;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = DeleteAESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pAesCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    pAesCtx = (aesCipherContext*)CreateAESCFBCtx(MOC_SYM(gpHwAccelCtx) pKey, keyLen, FALSE);
    if(NULL == pAesCtx)
    {
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DoAES(MOC_SYM(gpHwAccelCtx) pAesCtx, pPlain, 16, TRUE, pIv);
    if(OK != status)
    {
        errorCount = (errorCount + 1);
    }
    else
    {
        status = ERR_INVALID_INPUT;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = DoAES(MOC_SYM(gpHwAccelCtx) pAesCtx, NULL, 16, FALSE, pIv);
    if(OK != status)
    {
        errorCount = (errorCount + 1);
    }
    else
    {
        status = ERR_INVALID_INPUT;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = DoAES(MOC_SYM(gpHwAccelCtx) pAesCtx, pPlain, 16, FALSE, NULL);
    if(OK != status)
    {
        errorCount = (errorCount + 1);
    }
    else
    {
        status = ERR_INVALID_INPUT;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    DeleteAESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx *)&pAesCtx);

    /* give invalid keyLen */
    pAesCtx = (aesCipherContext*)CreateAESOFBCtx(MOC_SYM(gpHwAccelCtx) pKey, 100, TRUE);
    if(NULL != pAesCtx)
    {
        errorCount += UNITTEST_STATUS(__MOC_LINE__, ERR_NULL_POINTER);
    }

exit:

    if (NULL != pAesCtx)
    {
        DeleteAESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx *)&pAesCtx);
    }

    if(10 != errorCount)
        return 1;
    return 0;
}

/*----------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_UNITTEST_SPEEDTEST__

static int speedTestAesOfb(aesTest test)
{
    MSTATUS status = ERR_NULL_POINTER;

    /* use multi block test for 32 byte key length */
    ubyte pData[48];
    sbyte dataLen;

    ubyte pIv[16];
    sbyte4 ivLen;

    sbyte4 cmpRes = -1;
    aesCipherContext *pAesCtx;

    struct tms tstart;
    struct tms tend;
    double diffTime = 0.0;

    ubyte *pOutputFormat = "%-25s: %g seconds\n";
    FILE *pFile = NULL;

    if(NULL == (pFile = fopen(
        "../../../projects/cryptointerface_unittest/speed_test.txt", "a")))
    {
        printf("failed to open file\n");
        goto exit;
    }

    pAesCtx = (aesCipherContext*)CreateAESOFBCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, TRUE);
    if(NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    for(int i = 0;i < ENCRYPT_ITERATIONS; i++)
    {
        dataLen = test.plainLen;
        status =  DIGI_MEMCPY(pData, test.pPlain, dataLen);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;

        ivLen = test.ivLen;
        status =  DIGI_MEMCPY(pIv, test.pIv, ivLen);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;

        times(&tstart);
        status = DoAES(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData, dataLen, TRUE, pIv);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;
        times(&tend);

        status = DIGI_MEMCMP(pData, test.pCipher, dataLen, &cmpRes);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;

        if(0 != cmpRes)
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
        diffTime += tend.tms_utime - tstart.tms_utime;
    }
    fprintf(pFile, pOutputFormat, "aes-ofb encrypt speed",
        diffTime / sysconf(_SC_CLK_TCK));
    printf(pOutputFormat, "aes-ofb encrypt speed",
        diffTime / sysconf(_SC_CLK_TCK));

    status = DeleteAESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pAesCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* do decryption step */
    pAesCtx = (aesCipherContext*)CreateAESOFBCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, FALSE);
    if(NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* reset variable for decrypt step */
    diffTime = 0.0;
    for(int i = 0;i < DECRYPT_ITERATIONS; i++)
    {
        dataLen = test.cipherLen;
        status =  DIGI_MEMCPY(pData, test.pCipher, dataLen);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;

        ivLen = test.ivLen;
        status =  DIGI_MEMCPY(pIv, test.pIv, ivLen);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;

        times(&tstart);
        status = DoAES(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData, dataLen, FALSE, pIv);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;
        times(&tend);

        status = DIGI_MEMCMP(pData, test.pPlain, dataLen, &cmpRes);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;

        if(0 != cmpRes)
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
        diffTime += tend.tms_utime - tstart.tms_utime;
    }
    fprintf(pFile, pOutputFormat, "aes-ofb decrypt speed",
        diffTime / sysconf(_SC_CLK_TCK));
    printf(pOutputFormat, "aes-ofb decrypt speed",
        diffTime / sysconf(_SC_CLK_TCK));

exit:

    if (NULL != pAesCtx)
    {
        DeleteAESCtx((BulkCtx *)&pAesCtx);
    }

    if(OK != status)
        return 1;
    return 0;
}
#endif /* ifdef __ENABLE_DIGICERT_UNITTEST_SPEEDTEST__ */

/*----------------------------------------------------------------------------*/

static int runMultiBlockTest(aesTest test)
{
    MSTATUS status = ERR_NULL_POINTER;

    /* buffer for DoAES operations */
    sbyte4 ivLen;
    ubyte pIv[16] = { 0 };
    sbyte4 dataLen = 48;
    ubyte pData[48] = { 0 };

    sbyte4 cmpRes = -1;
    aesCipherContext *pAesCtx = NULL;

    ivLen = test.ivLen;
    status = DIGI_MEMCPY(pIv, test.pIv, ivLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    dataLen = test.plainLen;
    status = DIGI_MEMCPY(pData, test.pPlain, dataLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    pAesCtx = (aesCipherContext*)CreateAESOFBCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, TRUE);
    if(NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_MBED_SYM_OPERATORS__) && \
     defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES__))
    if(NULL == pAesCtx->pMocSymCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if(TRUE != pAesCtx->enabled)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }
#endif

    status = DoAES(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData, 16, TRUE, pIv);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DoAES(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData + 16, 16, TRUE, pIv);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DoAES(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData + 32, 16, TRUE, pIv);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DIGI_MEMCMP(pData, test.pCipher, dataLen, &cmpRes);
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
    pAesCtx = (aesCipherContext*)CreateAESOFBCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, FALSE);
    if(NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DIGI_MEMCPY(pIv, test.pIv, ivLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DoAES(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData, 16, FALSE, pIv);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DoAES(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData + 16, 16, FALSE, pIv);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DoAES(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData + 32, 16, FALSE, pIv);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DIGI_MEMCMP(pData, test.pPlain, dataLen, &cmpRes);
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

static int runCloneTest(aesTest test)
{
    MSTATUS status = ERR_NULL_POINTER;

    /* buffer for DoAES operations */
    sbyte4 ivLen;
    ubyte pIv[16] = { 0 };
    sbyte4 dataLen = 48;
    ubyte pData[48] = { 0 };

    sbyte4 cmpRes = -1;
    aesCipherContext *pAesCtx = NULL;
    aesCipherContext *pCloneCtx = NULL;

    ivLen = test.ivLen;
    status = DIGI_MEMCPY(pIv, test.pIv, ivLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    dataLen = test.plainLen;
    status = DIGI_MEMCPY(pData, test.pPlain, dataLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    pAesCtx = (aesCipherContext*)CreateAESOFBCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, TRUE);
    if(NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_MBED_SYM_OPERATORS__) && \
     defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES__))
    if(NULL == pAesCtx->pMocSymCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if(TRUE != pAesCtx->enabled)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }
#endif

    /* Encrypt the first block */
    status = DoAES(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData, 16, TRUE, pIv);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* Clone the context in this state */
    status = CloneAESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, (BulkCtx *)&pCloneCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* Complete the rest of the processing with the clone context */
    status = DoAES(MOC_SYM(gpHwAccelCtx) (BulkCtx)pCloneCtx, pData + 16, 32, TRUE, pIv);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DIGI_MEMCMP(pData, test.pCipher, dataLen, &cmpRes);
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

    status = DeleteAESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pCloneCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* do decryption step */
    pAesCtx = (aesCipherContext*)CreateAESOFBCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, FALSE);
    if(NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DIGI_MEMCPY(pIv, test.pIv, ivLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DoAES(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData, 16, FALSE, pIv);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* Clone the context in this state */
    status = CloneAESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, (BulkCtx *)&pCloneCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DoAES(MOC_SYM(gpHwAccelCtx) (BulkCtx)pCloneCtx, pData + 16, 32, FALSE, pIv);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DIGI_MEMCMP(pData, test.pPlain, dataLen, &cmpRes);
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
    if(NULL != pCloneCtx)
    {
        DeleteAESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pCloneCtx);
    }

    if(OK != status)
        return 1;
    return 0;
}

/*----------------------------------------------------------------------------*/

static int runMultiBlockTestResetAES(aesTest test)
{
    MSTATUS status = ERR_NULL_POINTER;

    /* buffer for DoAES operations */
    sbyte4 ivLen;
    ubyte pIv[16] = { 0 };
    sbyte4 dataLen = 48;
    ubyte pData[48] = { 0 };

    sbyte4 cmpRes = -1;
    aesCipherContext *pAesCtx = NULL;

    ivLen = test.ivLen;
    status = DIGI_MEMCPY(pIv, test.pIv, ivLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    dataLen = test.plainLen;
    status = DIGI_MEMCPY(pData, test.pPlain, dataLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    pAesCtx = (aesCipherContext*)CreateAESOFBCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, TRUE);
    if(NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_MBED_SYM_OPERATORS__) && \
     defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES__))
    if(NULL == pAesCtx->pMocSymCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if(TRUE != pAesCtx->enabled)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }
#endif

    status = DoAES(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData, 16, TRUE, pIv);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DoAES(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData + 16, 16, TRUE, pIv);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* Now reset the context and make the above calls to DoAES again */

    status = ResetAESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx *)&pAesCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    status = DIGI_MEMCPY(pIv, test.pIv, ivLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DIGI_MEMCPY(pData, test.pPlain, dataLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DoAES(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData, 16, TRUE, pIv);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DoAES(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData + 16, 16, TRUE, pIv);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    status = DoAES(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData + 32, 16, TRUE, pIv);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DIGI_MEMCMP(pData, test.pCipher, dataLen, &cmpRes);
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
    pAesCtx = (aesCipherContext*)CreateAESOFBCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, FALSE);
    if(NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DIGI_MEMCPY(pIv, test.pIv, ivLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DoAES(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData, 16, FALSE, pIv);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DoAES(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData + 16, 16, FALSE, pIv);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DoAES(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData + 32, 16, FALSE, pIv);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DIGI_MEMCMP(pData, test.pPlain, dataLen, &cmpRes);
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

static int runNonAlignedSingleBlockTest(aesTest test)
{
    MSTATUS status = ERR_NULL_POINTER;

    /* copy of iv, used to reinitialize pIv for decryption step */
    ubyte pIv[18] = { 0 };
    sbyte4 ivLen;

    /* buffer used to DoAES operations */
    ubyte pData[52] = { 0 };
    sbyte4 dataLen;

    sbyte4 cmpRes = -1;
    aesCipherContext *pAesCtx = NULL;

    dataLen = test.plainLen;
    status = DIGI_MEMCPY(pData + 1, test.pPlain, dataLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    ivLen = test.ivLen;
    status = DIGI_MEMCPY(pIv, test.pIv, ivLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    pAesCtx = (aesCipherContext*)CreateAESOFBCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, TRUE);
    if(NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DoAES(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData + 1, dataLen, TRUE, pIv);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DIGI_MEMCMP(pData + 1, test.pCipher, dataLen, &cmpRes);
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
    pAesCtx = (aesCipherContext*)CreateAESOFBCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, FALSE);
    if(NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DIGI_MEMCPY(pIv + 1, test.pIv, ivLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DoAES(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData + 1, dataLen, FALSE, pIv + 1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DIGI_MEMCMP(pData + 1, test.pPlain, dataLen, &cmpRes);
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
    if(NULL != pAesCtx)
    {
        DeleteAESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pAesCtx);
    }

    if(OK != status)
        return 1;
    return 0;
}


/*----------------------------------------------------------------------------*/
static int runSingleBlockTest(aesTest test)
{
    MSTATUS status = ERR_NULL_POINTER;

    /* copy of iv, used to reinitialize pIv for decryption step */
    ubyte pIv[16] = { 0 };
    sbyte4 ivLen;

    /* buffer used to DoAES operations */
    ubyte pData[48] = { 0 };
    sbyte4 dataLen;

    sbyte4 cmpRes = -1;
    aesCipherContext *pAesCtx = NULL;

    dataLen = test.plainLen;
    status = DIGI_MEMCPY(pData, test.pPlain, dataLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    ivLen = test.ivLen;
    status = DIGI_MEMCPY(pIv, test.pIv, ivLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    pAesCtx = (aesCipherContext*)CreateAESOFBCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, TRUE);
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

    status = DIGI_MEMCMP(pData, test.pCipher, dataLen, &cmpRes);
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
    pAesCtx = (aesCipherContext*)CreateAESOFBCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, FALSE);
    if(NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DIGI_MEMCPY(pIv, test.pIv, ivLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DoAES(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData, dataLen, FALSE, pIv);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DIGI_MEMCMP(pData, test.pPlain, dataLen, &cmpRes);
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

static int runPartialBlockTest(aesTest *pVector, ubyte4 initialBlocksTotal)
{
    ubyte4          retVal = 0;
    BulkCtx         ctx = NULL;
    sbyte4          i, cmpResult;
    MSTATUS         status;
    ubyte           pTextCopy[48] = {0};
    ubyte           pIvCopy[16] = {0};

    for (i = 1; i < 16; i++)
    {
        /* cipher operation is inplace so make a mutable copy of the text */
        if (OK > (status = DIGI_MEMCPY(pTextCopy, pVector->pPlain, initialBlocksTotal + i)))
        {
            retVal++;
            goto exit;
        }

        /* and also the iv gets overwritten, so make a mutable copy */
        if (OK > (status = DIGI_MEMCPY(pIvCopy, pVector->pIv, 16)))
        {
            retVal++;
            goto exit;
        }

        /* encrypt initialBlocksTotal + i bytes */
        if (NULL == (ctx = CreateAESOFBCtx(MOC_SYM(gpHwAccelCtx) pVector->pKey, pVector->keyLen, TRUE)))
        {
            retVal++;
            goto exit;
        }

        if (OK > (status = DoAES(MOC_SYM(gpHwAccelCtx) ctx, pTextCopy, initialBlocksTotal + i, TRUE, pIvCopy)))
        {
            retVal++;
            goto exit;
        }

        if (OK > (status = DeleteAESCtx(MOC_SYM(gpHwAccelCtx) &ctx)))
        {
            retVal++;
            goto exit;
        }

        /* verify encryption */
        if (OK > (status = DIGI_MEMCPY(pIvCopy, pVector->pIv, 16)))
        {
            retVal++;
            goto exit;
        }

        if (OK > (status = DIGI_MEMCMP(pTextCopy, pVector->pCipher, initialBlocksTotal + i, &cmpResult)))
        {
            retVal++;
            goto exit;
        }

        if (0 != cmpResult)
        {
            retVal++;
        }

        /* decrypt initialBlocksTotal + i bytes */
        if (NULL == (ctx = CreateAESOFBCtx(MOC_SYM(gpHwAccelCtx) pVector->pKey, pVector->keyLen, FALSE)))
        {
            retVal++;
            goto exit;
        }

        if (OK > (status = DoAES(MOC_SYM(gpHwAccelCtx) ctx, pTextCopy, initialBlocksTotal + i, FALSE, pIvCopy)))
        {
            retVal++;
            goto exit;
        }

        if (OK > (status = DeleteAESCtx(MOC_SYM(gpHwAccelCtx) &ctx)))
        {
            retVal++;
            goto exit;
        }

        /* verify decryption */
        if (OK > (status = DIGI_MEMCMP(pTextCopy, pVector->pPlain, initialBlocksTotal + i, &cmpResult)))
        {
            retVal++;
            goto exit;
        }

        if (0 != cmpResult)
        {
            retVal++;
        }
    }

exit:

    return retVal;
}

/*----------------------------------------------------------------------------*/

static int runTests()
{
    int errorCount = 0;
    int i = 0;

    for(i = 0;i < 3; i++)
        errorCount = (errorCount + runSingleBlockTest(pSingleBlockTests[i]));

    for(i = 0;i < 3; i++)
        errorCount = (errorCount + runNonAlignedSingleBlockTest(pSingleBlockTests[i]));

    for(i = 0;i < 3; i++)
        errorCount = (errorCount + runMultiBlockTest(pMultiBlockTests[i]));

    for(i = 0;i < 3; i++)
        errorCount = (errorCount + runMultiBlockTestResetAES(pMultiBlockTests[i]));

    for(i = 0;i < 3; i++)
        errorCount = (errorCount + runCloneTest(pMultiBlockTests[i]));

    errorCount += runPartialBlockTest(&pSingleBlockTests[0], 0);
    errorCount += runPartialBlockTest(&pMultiBlockTests[0], 16);
    errorCount += runPartialBlockTest(&pMultiBlockTests[0], 32);

    return errorCount;
}

/*----------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TPM2__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
static int genKeyTest(ubyte4 keySize)
{
    int retVal = 0;
    MSTATUS status = 0;
    sbyte4 compare = -1;
    int i;

    BulkCtx pCtx = NULL;
    ubyte *pSerKey = NULL;
    ubyte4 serLen = 0;
    SymmetricKey *pSymWrapper = NULL;

    ubyte pIv[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x00};
    ubyte pPlain[64];
    ubyte pCipher[64] = {0};
    ubyte pRecPlain[64] = {0};
    sbyte4 retLen = 0;

    MSymTapKeyGenArgs aesTapArgs = {0};
    void *pAesTapArgs = (void *) &aesTapArgs;

    aesTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    aesTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    aesTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);
    aesTapArgs.keyAlgorithm = TAP_KEY_ALGORITHM_AES;

    /* make a pseduo random looking plaintext of 4 blocks */
    for (i = 0; i < sizeof(pPlain); ++i)
    {
        pPlain[i] = (ubyte) ((17 * (i + 1)) & 0xff);
    }

    status = CRYPTO_INTERFACE_TAP_GenerateSymKey(&pSymWrapper, keySize, pAesTapArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* serialize the key while we still have it as a SymmetricKey */
    status = CRYPTO_INTERFACE_TAP_serializeSymKey(pSymWrapper, &pSerKey, &serLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Transfer control of the SymmetricKey underlying data into a usable AES context.
     * The SymmetricKey is now just a wrapper that still needs to be freed. */
    status = CRYPTO_INTERFACE_TAP_getAesCtxFromSymmetricKeyAlloc (
        pSymWrapper, &pCtx, MODE_OFB, MOCANA_SYM_TAP_ENCRYPT);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_AESALGO_blockEncrypt((aesCipherContext *) pCtx, pIv, pPlain, 16 * 8, pCipher, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 16 * 8);

    status = CRYPTO_INTERFACE_AESALGO_blockEncrypt((aesCipherContext *) pCtx, pIv, pPlain + 16, 32 * 8, pCipher + 16, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 32 * 8);

    status = CRYPTO_INTERFACE_AESALGO_blockEncrypt((aesCipherContext *) pCtx, pIv, pPlain + 48, 16 * 8, pCipher + 48, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 16 * 8);

    /* delete the context */
    status = CRYPTO_INTERFACE_DeleteAESCtx (MOC_SYM(gpHwAccelCtx) &pCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Free the SymmetricKey wrapper */
    status = CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* deserialize into a SymmetricKey wrapper */
    status = CRYPTO_INTERFACE_TAP_deserializeSymKey(&pSymWrapper, pSerKey, serLen, (void *) pAesTapArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Transfer control of the SymmetricKey underlying data into a usable AES context.
     * The SymmetricKey is now just a wrapper that still needs to be freed. */
    status = CRYPTO_INTERFACE_TAP_getAesCtxFromSymmetricKeyAlloc (
        pSymWrapper, &pCtx, MODE_OFB, MOCANA_SYM_TAP_DECRYPT);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx, pIv, pCipher, 16 * 8, pRecPlain, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 16 * 8);

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx, pIv, pCipher + 16, 32 * 8, pRecPlain + 16, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 32 * 8);

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx, pIv, pCipher + 48, 16 * 8, pRecPlain + 48, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 16 * 8);

    status = DIGI_MEMCMP(pPlain, pRecPlain, 64, &compare);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, compare, 0);

    /* test Reset context and decrypt again */
    status = CRYPTO_INTERFACE_ResetAESCtx(&pCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx, pIv, pCipher, 16 * 8, pRecPlain, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 16 * 8);

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx, pIv, pCipher + 16, 32 * 8, pRecPlain + 16, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 32 * 8);

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx, pIv, pCipher + 48, 16 * 8, pRecPlain + 48, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 16 * 8);

    status = DIGI_MEMCMP(pPlain, pRecPlain, 64, &compare);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, compare, 0);

exit:

    status = CRYPTO_INTERFACE_DeleteAESCtx(MOC_SYM(gpHwAccelCtx) &pCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

    if (NULL != pSymWrapper)
    {
        (void) CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    }

    if (NULL != pSerKey)
    {
        (void) DIGI_FREE((void **) &pSerKey);
    }

    return retVal;
}
#endif

/*----------------------------------------------------------------------------*/

int crypto_interface_aes_ofb_test_init()
{

    MSTATUS status = ERR_NULL_POINTER;
    int errorCount = 0;

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

    /* TESTS GO HERE */

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES__))

    errorCount = (errorCount + testCryptoInterface(pSingleBlockTests[0]));
#endif

#ifdef __ENABLE_DIGICERT_UNITTEST_SPEEDTEST__
    /* errorCount = (errorCount + speedTestAesOfb(pMultiBlockTests[0])); */
#else

    errorCount = (errorCount + runTests());
    errorCount = (errorCount + negativeTest());
    errorCount = (errorCount + negativeTestsAesAlgo());

/* TO DO if we get a pkcs11 smp that supports ofb we can change this 
   to the proper macro, also change below where TAP_EXAMPLE_clean is called */
#if 0
    ubyte4 modNum = 1;
    status = TAP_EXAMPLE_init(&modNum, 1);
    if (OK != status)
    {
        errorCount += 1;
        goto exit;
    }

    errorCount = (errorCount + genKeyTest(128));
    errorCount = (errorCount + genKeyTest(192));
    errorCount = (errorCount + genKeyTest(256));

#endif /* 0 */
#endif

exit:
    
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

#if 0
    TAP_EXAMPLE_clean();
#endif

    DIGICERT_free(&gpMocCtx);
    return errorCount;
}
