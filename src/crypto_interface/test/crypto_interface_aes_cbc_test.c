/*
 * crypto_interface_aes_cbc_test.c
 *
 * test file for AES in CBC mode.
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
#include "../../crypto_interface/cryptointerface.h"
#include "../../crypto_interface/crypto_interface_sym_tap.h"
#include "../../crypto_interface/crypto_interface_aes_tap.h"
#endif
#endif

#ifdef __ENABLE_DIGICERT_PKCS11_DEBUG_PURGE_ALL_OBJ__
MSTATUS TAP_freeKeyEx(TAP_Key **ppKey);
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
            0xfe, 0x89, 0x01, 0xfe, 0xcd, 0x3c, 0xcd, 0x2e, 0xc5, 0xfd,
            0xc7, 0xc7, 0xa0, 0xb5, 0x05, 0x19, 0xc2, 0x45, 0xb4, 0x2d,
            0x61, 0x1a, 0x5e, 0xf9, 0xe9, 0x02, 0x68, 0xd5, 0x9f, 0x3e,
            0xdf, 0x33
        },
        32,
        {
            0xbd, 0x41, 0x6c, 0xb3, 0xb9, 0x89, 0x22, 0x28, 0xd8, 0xf1,
            0xdf, 0x57, 0x56, 0x92, 0xe4, 0xd0
        },
        16,
        {
            0x8d, 0x3a, 0xa1, 0x96, 0xec, 0x3d, 0x7c, 0x9b, 0x5b, 0xb1,
            0x22, 0xe7, 0xfe, 0x77, 0xfb, 0x12, 0x95, 0xa6, 0xda, 0x75,
            0xab, 0xe5, 0xd3, 0xa5, 0x10, 0x19, 0x4d, 0x3a, 0x8a, 0x41,
            0x57, 0xd5, 0xc8, 0x9d, 0x40, 0x61, 0x97, 0x16, 0x61, 0x98,
            0x59, 0xda, 0x3e, 0xc9, 0xb2, 0x47, 0xce, 0xd9
        },
        48,
        {
            0x60, 0x8e, 0x82, 0xc7, 0xab, 0x04, 0x00, 0x7a, 0xdb, 0x22,
            0xe3, 0x89, 0xa4, 0x47, 0x97, 0xfe, 0xd7, 0xde, 0x09, 0x0c,
            0x8c, 0x03, 0xca, 0x8a, 0x2c, 0x5a, 0xcd, 0x9e, 0x84, 0xdf,
            0x37, 0xfb, 0xc5, 0x8c, 0xe8, 0xed, 0xb2, 0x93, 0xe9, 0x8f,
            0x02, 0xb6, 0x40, 0xd6, 0xd1, 0xd7, 0x24, 0x64
        },
        48
    },
    {
        {
            0x16, 0xc9, 0x3b, 0xb3, 0x98, 0xf1, 0xfc, 0x0c, 0xf6, 0xd6,
            0x8f, 0xc7, 0xa5, 0x67, 0x3c, 0xdf, 0x43, 0x1f, 0xa1, 0x47,
            0x85, 0x2b, 0x4a, 0x2d
        },
        24,
        {
            0xea, 0xae, 0xca, 0x2e, 0x07, 0xdd, 0xed, 0xf5, 0x62, 0xf9,
            0x4d, 0xf6, 0x3f, 0x0a, 0x65, 0x0f
        },
        16,
        {
            0xc5, 0xce, 0x95, 0x86, 0x13, 0xbf, 0x74, 0x17, 0x18, 0xc1,
            0x74, 0x44, 0x48, 0x4e, 0xba, 0xf1, 0x05, 0x0d, 0xdc, 0xac,
            0xb5, 0x9b, 0x95, 0x90, 0x17, 0x8c, 0xbe, 0x69, 0xd7, 0xad,
            0x79, 0x19, 0x60, 0x8c, 0xb0, 0x3a, 0xf1, 0x3b, 0xbe, 0x04,
            0xf3, 0x50, 0x6b, 0x71, 0x8a, 0x30, 0x1e, 0xa0
        },
        48,
        {
            0xed, 0x6a, 0x50, 0xe0, 0xc6, 0x92, 0x1d, 0x52, 0xd6, 0x64,
            0x7f, 0x75, 0xd6, 0x7b, 0x4f, 0xd5, 0x6a, 0xce, 0x1f, 0xed,
            0xb8, 0xb5, 0xa6, 0xa9, 0x97, 0xb4, 0xd1, 0x31, 0x64, 0x05,
            0x47, 0xd2, 0x2c, 0x5d, 0x88, 0x4a, 0x75, 0xe6, 0x75, 0x2b,
            0x58, 0x46, 0xb5, 0xb3, 0x3a, 0x51, 0x81, 0xf4
        },
        48
    },
    {
        {
            0x33, 0x48, 0xaa, 0x51, 0xe9, 0xa4, 0x5c, 0x2d, 0xbe, 0x33,
            0xcc, 0xc4, 0x7f, 0x96, 0xe8, 0xde
        },
        16,
        {
            0x19, 0x15, 0x3c, 0x67, 0x31, 0x60, 0xdf, 0x2b, 0x1d, 0x38,
            0xc2, 0x80, 0x60, 0xe5, 0x9b, 0x96
        },
        16,
        {
            0x9b, 0x7c, 0xee, 0x82, 0x7a, 0x26, 0x57, 0x5a, 0xfd, 0xbb,
            0x7c, 0x7a, 0x32, 0x9f, 0x88, 0x72, 0x38, 0x05, 0x2e, 0x36,
            0x01, 0xa7, 0x91, 0x74, 0x56, 0xba, 0x61, 0x25, 0x1c, 0x21,
            0x47, 0x63, 0xd5, 0xe1, 0x84, 0x7a, 0x6a, 0xd5, 0xd5, 0x41,
            0x27, 0xa3, 0x99, 0xab, 0x07, 0xee, 0x35, 0x99
        },
        48,
        {
            0xd5, 0xae, 0xd6, 0xc9, 0x62, 0x2e, 0xc4, 0x51, 0xa1, 0x5d,
            0xb1, 0x28, 0x19, 0x95, 0x2b, 0x67, 0x52, 0x50, 0x1c, 0xf0,
            0x5c, 0xdb, 0xf8, 0xcd, 0xa3, 0x4a, 0x45, 0x77, 0x26, 0xde,
            0xd9, 0x78, 0x18, 0xe1, 0xf1, 0x27, 0xa2, 0x8d, 0x72, 0xdb,
            0x56, 0x52, 0x74, 0x9f, 0x0c, 0x6a, 0xfe, 0xe5
        },
        48
    }
};

static aesTest pSingleBlockTests[3] = {
    {
        {
            0x6e, 0xd7, 0x6d, 0x2d, 0x97, 0xc6, 0x9f, 0xd1, 0x33, 0x95,
            0x89, 0x52, 0x39, 0x31, 0xf2, 0xa6, 0xcf, 0xf5, 0x54, 0xb1,
            0x5f, 0x73, 0x8f, 0x21, 0xec, 0x72, 0xdd, 0x97, 0xa7, 0x33,
            0x09, 0x07
        },
        32,
        {
            0x85, 0x1e, 0x87, 0x64, 0x77, 0x6e, 0x67, 0x96, 0xaa, 0xb7,
            0x22, 0xdb, 0xb6, 0x44, 0xac, 0xe8
        },
        16,
        {
            0x62, 0x82, 0xb8, 0xc0, 0x5c, 0x5c, 0x15, 0x30, 0xb9, 0x7d,
            0x48, 0x16, 0xca, 0x43, 0x47, 0x62
        },
        16,
        {
            0x6a, 0xcc, 0x04, 0x14, 0x2e, 0x10, 0x0a, 0x65, 0xf5, 0x1b,
            0x97, 0xad, 0xf5, 0x17, 0x2c, 0x41
        },
        16
    },
    {
        {
            0xba, 0x75, 0xf4, 0xd1, 0xd9, 0xd7, 0xcf, 0x7f, 0x55, 0x14,
            0x45, 0xd5, 0x6c, 0xc1, 0xa8, 0xab, 0x2a, 0x07, 0x8e, 0x15,
            0xe0, 0x49, 0xdc, 0x2c
        },
        24,
        {
            0x53, 0x1c, 0xe7, 0x81, 0x76, 0x40, 0x16, 0x66, 0xaa, 0x30,
            0xdb, 0x94, 0xec, 0x4a, 0x30, 0xeb
        },
        16,
        {
            0xc5, 0x1f, 0xc2, 0x76, 0x77, 0x4d, 0xad, 0x94, 0xbc, 0xdc,
            0x1d, 0x28, 0x91, 0xec, 0x86, 0x68
        },
        16,
        {
            0x70, 0xdd, 0x95, 0xa1, 0x4e, 0xe9, 0x75, 0xe2, 0x39, 0xdf,
            0x36, 0xff, 0x4a, 0xee, 0x1d, 0x5d
        },
        16
    },
    {
        {
            0x1f, 0x8e, 0x49, 0x73, 0x95, 0x3f, 0x3f, 0xb0, 0xbd, 0x6b,
            0x16, 0x66, 0x2e, 0x9a, 0x3c, 0x17
        },
        16,
        {
            0x2f, 0xe2, 0xb3, 0x33, 0xce, 0xda, 0x8f, 0x98, 0xf4, 0xa9,
            0x9b, 0x40, 0xd2, 0xcd, 0x34, 0xa8
        },
        16,
        {
            0x45, 0xcf, 0x12, 0x96, 0x4f, 0xc8, 0x24, 0xab, 0x76, 0x61,
            0x6a, 0xe2, 0xf4, 0xbf, 0x08, 0x22
        },
        16,
        {
            0x0f, 0x61, 0xc4, 0xd4, 0x4c, 0x51, 0x47, 0xc0, 0x3c, 0x19,
            0x5a, 0xd7, 0xe2, 0xcc, 0x12, 0xb2
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
    (defined(__ENABLE_DIGICERT_AES_CBC_MBED__)))
    pAesCtx = (aesCipherContext*)CreateAESCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, TRUE);
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
    sbyte4 ivLen = 16;
    ubyte pIv[16] = {0};
    sbyte4 keyLen = 32;
    ubyte pKey[32] = {0};
    sbyte4 msgLen = 10;
    ubyte pMsg[10] = {0};
    sbyte4 outLen = 0;
    ubyte pOut[500] = {0};
    sbyte4 encryptMode = FALSE;
    sbyte4 cipherMode = MODE_CBC;

    pCtx = (aesCipherContext*)CreateAESCtx(MOC_SYM(gpHwAccelCtx) pKey, keyLen, TRUE);
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

    /* msgLen that isn't a multiple of 128 (16 bytes) should return error
     * status */
    status = AESALGO_blockEncryptEx(MOC_SYM(gpHwAccelCtx) pCtx, pIv, pMsg, 80, pOut, &outLen);
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
    pCtx->mode = MODE_CBC;
#endif
    /* set encrypt value to FALSE for AESALGO_blockDecryptEx(MOC_SYM(gpHwAccelCtx))  tests */
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

    /* msgLen that isn't a multiple of 128 (16 bytes) should return error
     * status */
    status = AESALGO_blockDecryptEx(MOC_SYM(gpHwAccelCtx) pCtx, pIv, pMsg, 77, pOut, &outLen);
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

    pCtx->mode = MODE_CBC;
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
    sbyte4 ivLen = 16;

    ubyte pPlain[48] = { 0 };
    sbyte4 plainLen;

    aesCipherContext *pAesCtx;

    pAesCtx = (aesCipherContext*)CreateAESCtx(MOC_SYM(gpHwAccelCtx) pKey, keyLen, TRUE);
    if(NULL == pAesCtx)
    {
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DoAES(MOC_SYM(gpHwAccelCtx) pAesCtx, pPlain, 15, TRUE, pIv);
    if(OK != status)
    {
        errorCount = (errorCount + 1);
    }
    else
    {
        status = ERR_INVALID_INPUT;
        UNITTEST_STATUS(__MOC_LINE__, status);
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

    pAesCtx = (aesCipherContext*)CreateAESCtx(MOC_SYM(gpHwAccelCtx) pKey, keyLen, FALSE);
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

    status = DoAES(MOC_SYM(gpHwAccelCtx) pAesCtx, pPlain, 17, FALSE, pIv);
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
    pAesCtx = (aesCipherContext*)CreateAESCtx(MOC_SYM(gpHwAccelCtx) pKey, 100, TRUE);
    if(NULL != pAesCtx)
    {
        errorCount += UNITTEST_STATUS(__MOC_LINE__, ERR_NULL_POINTER);
    }

exit:

    if (NULL != pAesCtx)
    {
        DeleteAESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx *)&pAesCtx);
    }

    if(12 != errorCount)
        return 1;
    return 0;
}

/*----------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_UNITTEST_SPEEDTEST__

static int speedTestAesCbc(aesTest test)
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

    pAesCtx = (aesCipherContext*)CreateAESCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, TRUE);
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
    fprintf(pFile, pOutputFormat, "aes-cbc encrypt speed",
        diffTime / sysconf(_SC_CLK_TCK));
    printf(pOutputFormat, "aes-cbc encrypt speed",
        diffTime / sysconf(_SC_CLK_TCK));

    status = DeleteAESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pAesCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* do decryption step */
    pAesCtx = (aesCipherContext*)CreateAESCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, FALSE);
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
    fprintf(pFile, pOutputFormat, "aes-cbc decrypt speed",
        diffTime / sysconf(_SC_CLK_TCK));
    printf(pOutputFormat, "aes-cbc decrypt speed",
        diffTime / sysconf(_SC_CLK_TCK));

exit:

    if (NULL != pAesCtx)
    {
        DeleteAESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx *)&pAesCtx);
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
    aesCipherContext *pAesCtx;

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

    pAesCtx = (aesCipherContext*)CreateAESCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, TRUE);
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
    pAesCtx = (aesCipherContext*)CreateAESCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, FALSE);
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

    if(NULL != pAesCtx)
    {
        DeleteAESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pAesCtx);
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

    pAesCtx = (aesCipherContext*)CreateAESCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, TRUE);
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
    pAesCtx = (aesCipherContext*)CreateAESCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, FALSE);
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

    if(NULL != pAesCtx)
    {
        DeleteAESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pAesCtx);
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

static int runNonAlignedSingleBlockTest(aesTest test)
{
    MSTATUS status = ERR_NULL_POINTER;

    /* copy of iv, used to reinitialize pIv for decryption step */
    ubyte pIv[18] = { 0 };
    sbyte4 ivLen;

    /* buffer used to DoAES operations */
    ubyte pData[52] = { 0 };
    sbyte4 dataLen;

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

    sbyte4 cmpRes = -1;
    aesCipherContext *pAesCtx;

    pAesCtx = (aesCipherContext*)CreateAESCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, TRUE);
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
    pAesCtx = (aesCipherContext*)CreateAESCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, FALSE);
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

    sbyte4 cmpRes = -1;
    aesCipherContext *pAesCtx;

    pAesCtx = (aesCipherContext*)CreateAESCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, TRUE);
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
    pAesCtx = (aesCipherContext*)CreateAESCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, FALSE);
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
    if(NULL != pAesCtx)
    {
        DeleteAESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pAesCtx);
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
    aesCipherContext *pAesCtx;

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

    pAesCtx = (aesCipherContext*)CreateAESCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, TRUE);
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

    /* Now reset the context and do the above calls to DoAES again */

    status = ResetAESCtx (MOC_SYM(gpHwAccelCtx) (BulkCtx *)&pAesCtx);
    UNITTEST_STATUS (__MOC_LINE__, status);
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
    pAesCtx = (aesCipherContext*)CreateAESCtx(MOC_SYM(gpHwAccelCtx) test.pKey, test.keyLen, FALSE);
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

    if(NULL != pAesCtx)
    {
        DeleteAESCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pAesCtx);
    }

    if(OK != status)
        return 1;
    return 0;
}

/*----------------------------------------------------------------------------*/

static int runTests()
{
    MSTATUS status = ERR_NULL_POINTER;
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

    return errorCount;
}

/*----------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TPM2__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
#ifdef __ENABLE_DIGICERT_PKCS11_DEBUG_PURGE_ALL_OBJ__
static int createKeyTestEx(ubyte4 keySize)
{
    int retVal = 0;
    MSTATUS status = 0;
    sbyte4 compare = -1;
    int i;

    BulkCtx pCtx = NULL;
    BulkCtx pCtx2 = NULL;
    ubyte *pSerKey = NULL;
    ubyte4 serLen = 0;
    SymmetricKey *pSymWrapper = NULL;
    TAP_KeyHandle keyHandle = 0;
    TAP_TokenHandle tokenHandle = 0;

    /* Pointers for a special free on ctx1 */
    aesCipherContext *pAesCtx = NULL;
    MocSymCtx pMocSymCtx = NULL;
    MTapKeyData *pTapData = NULL;

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

    TAP_KeyInfo keyInfo = {0};
    MSymTapCreateArgs createArgs = {0};
    ubyte pKey[32] = {0};
    for (i = 0; i < 32; ++i)
    {
        pKey[i] = (ubyte) (i+1);
    }

    switch(keySize)
    {
        case 128:
            keyInfo.algKeyInfo.aesInfo.keySize = TAP_KEY_SIZE_128;
            break;

        case 192:
            keyInfo.algKeyInfo.aesInfo.keySize = TAP_KEY_SIZE_192;
            break;

        case 256:
            keyInfo.algKeyInfo.aesInfo.keySize = TAP_KEY_SIZE_256;
            break;

        default:
            goto exit;
    }

    keyInfo.keyAlgorithm = TAP_KEY_ALGORITHM_AES;
    keyInfo.keyUsage = TAP_KEY_USAGE_DECRYPT;
    keyInfo.algKeyInfo.aesInfo.symMode = TAP_SYM_KEY_MODE_UNDEFINED;
    createArgs.pKeyInfo = &keyInfo;
    createArgs.pKeyData = (ubyte *)pKey;
    createArgs.keyDataLen = keySize/8;
    createArgs.token = FALSE;

    status = CRYPTO_INTERFACE_TAP_SymImportExternalKey(&pSymWrapper, pAesTapArgs, (void *)&createArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_TAP_SymKeyDeferUnload(pSymWrapper, TRUE);
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
        pSymWrapper, &pCtx, MODE_CBC, MOCANA_SYM_TAP_ENCRYPT);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_AESALGO_blockEncrypt((aesCipherContext *) pCtx, pIv, pPlain, 16 * 8, pCipher, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 16 * 8);

    status = CRYPTO_INTERFACE_TAP_AesGetKeyInfo (pCtx, &tokenHandle, &keyHandle);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

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

    /* Free the SymmetricKey wrapper */
    status = CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_ResetAESCtx (MOC_SYM(gpHwAccelCtx) &pCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* deserialize into a SymmetricKey wrapper */
    status = CRYPTO_INTERFACE_TAP_deserializeSymKey(&pSymWrapper, pSerKey, serLen, (void *) pAesTapArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Defer again */
    status = CRYPTO_INTERFACE_TAP_SymKeyDeferUnload(pSymWrapper, TRUE);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Transfer control of the SymmetricKey underlying data into a usable AES context.
     * The SymmetricKey is now just a wrapper that still needs to be freed. */
    status = CRYPTO_INTERFACE_TAP_getAesCtxFromSymmetricKeyAlloc (
        pSymWrapper, &pCtx2, MODE_CBC, MOCANA_SYM_TAP_DECRYPT);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx2, pIv, pCipher, 16 * 8, pRecPlain, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 16 * 8);

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx2, pIv, pCipher + 16, 32 * 8, pRecPlain + 16, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 32 * 8);

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx2, pIv, pCipher + 48, 16 * 8, pRecPlain + 48, &retLen);
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

    if (NULL != pCtx2)
    {
        (void *)CRYPTO_INTERFACE_DeleteAESCtx (MOC_SYM(gpHwAccelCtx) &pCtx2);
    }

    /* Special free code since we have two aes ctxs with two TAP keys each pointing to the same
     * underlying SMP resource, the above deletion deletes the actual object that this ctx also
     * points to, so to avoid errors manually free all the containers */
    if (NULL != pCtx)
    {
        pAesCtx = (aesCipherContext *)pCtx;
        pMocSymCtx = pAesCtx->pMocSymCtx;
        if (NULL != pMocSymCtx)
        {
            pTapData = (MTapKeyData *) pMocSymCtx->pLocalData;
            if (NULL != pTapData)
            {
                if (NULL != pTapData->pKey)
                {
                    TAP_freeKeyEx(&(pTapData->pKey));
                }

                DIGI_FREE((void **)&pTapData);
            }

            DIGI_FREE((void **)&pMocSymCtx);
        }

        DIGI_FREE((void **)&pCtx);
    }

    if (0 != keyHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapKey(TAP_EXAMPLE_getTapContext(1), tokenHandle, keyHandle);
        retVal += UNITTEST_STATUS(keySize, status);
    }

    if (0 != tokenHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapToken(TAP_EXAMPLE_getTapContext(1), tokenHandle);
        retVal += UNITTEST_STATUS(keySize, status);
    }

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

static int createKeyTest(ubyte4 keySize)
{
    int retVal = 0;
    MSTATUS status = 0;
    sbyte4 compare = -1;
    int i;

    BulkCtx pCtx = NULL;
    BulkCtx pCtx2 = NULL;
    ubyte *pSerKey = NULL;
    ubyte4 serLen = 0;
    SymmetricKey *pSymWrapper = NULL;
    TAP_KeyHandle keyHandle = 0;
    TAP_TokenHandle tokenHandle = 0;

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

    TAP_KeyInfo keyInfo = {0};
    MSymTapCreateArgs createArgs = {0};
    ubyte pKey[32] = {0};
    for (i = 0; i < 32; ++i)
    {
        pKey[i] = (ubyte) (i+1);
    }

    switch(keySize)
    {
        case 128:
            keyInfo.algKeyInfo.aesInfo.keySize = TAP_KEY_SIZE_128;
            break;

        case 192:
            keyInfo.algKeyInfo.aesInfo.keySize = TAP_KEY_SIZE_192;
            break;

        case 256:
            keyInfo.algKeyInfo.aesInfo.keySize = TAP_KEY_SIZE_256;
            break;

        default:
            goto exit;
    }

    keyInfo.keyAlgorithm = TAP_KEY_ALGORITHM_AES;
    keyInfo.keyUsage = TAP_KEY_USAGE_DECRYPT;
    keyInfo.algKeyInfo.aesInfo.symMode = TAP_SYM_KEY_MODE_UNDEFINED;
    createArgs.pKeyInfo = &keyInfo;
    createArgs.pKeyData = (ubyte *)pKey;
    createArgs.keyDataLen = keySize/8;
    createArgs.token = FALSE;

    status = CRYPTO_INTERFACE_TAP_SymImportExternalKey(&pSymWrapper, pAesTapArgs, (void *)&createArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_TAP_SymKeyDeferUnload(pSymWrapper, TRUE);
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
        pSymWrapper, &pCtx, MODE_CBC, MOCANA_SYM_TAP_ENCRYPT);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_AESALGO_blockEncrypt((aesCipherContext *) pCtx, pIv, pPlain, 16 * 8, pCipher, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 16 * 8);

    status = CRYPTO_INTERFACE_TAP_AesGetKeyInfo (pCtx, &tokenHandle, &keyHandle);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

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

    /* Free the SymmetricKey wrapper */
    status = CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_DeleteAESCtx (MOC_SYM(gpHwAccelCtx) &pCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* deserialize into a SymmetricKey wrapper */
    status = CRYPTO_INTERFACE_TAP_deserializeSymKey(&pSymWrapper, pSerKey, serLen, (void *) pAesTapArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Defer again */
    status = CRYPTO_INTERFACE_TAP_SymKeyDeferUnload(pSymWrapper, TRUE);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Transfer control of the SymmetricKey underlying data into a usable AES context.
     * The SymmetricKey is now just a wrapper that still needs to be freed. */
    status = CRYPTO_INTERFACE_TAP_getAesCtxFromSymmetricKeyAlloc (
        pSymWrapper, &pCtx2, MODE_CBC, MOCANA_SYM_TAP_DECRYPT);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx2, pIv, pCipher, 16 * 8, pRecPlain, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 16 * 8);

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx2, pIv, pCipher + 16, 32 * 8, pRecPlain + 16, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 32 * 8);

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx2, pIv, pCipher + 48, 16 * 8, pRecPlain + 48, &retLen);
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

    if (NULL != pCtx)
    {
        (void *)CRYPTO_INTERFACE_DeleteAESCtx (MOC_SYM(gpHwAccelCtx) &pCtx);
    }
    if (NULL != pCtx2)
    {
        (void *)CRYPTO_INTERFACE_DeleteAESCtx (MOC_SYM(gpHwAccelCtx) &pCtx2);
    }
    if (0 != keyHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapKey(TAP_EXAMPLE_getTapContext(1), tokenHandle, keyHandle);
        retVal += UNITTEST_STATUS(keySize, status);
    }

    if (0 != tokenHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapToken(TAP_EXAMPLE_getTapContext(1), tokenHandle);
        retVal += UNITTEST_STATUS(keySize, status);
    }

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

/* known answer test by comparing TAP (Hw) results with Sw results */
static int tapKAT(ubyte4 keySize, byteBoolean isEnc)
{
    int retVal = 0;
    MSTATUS status = 0;
    sbyte4 compare = -1;
    sbyte4 retLen = 0;
    int i;

    BulkCtx pCtxHw = NULL;
    BulkCtx pCtxSw = NULL;

    SymmetricKey *pSymWrapper = NULL;

    ubyte pIv[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x00};
    ubyte pInput[64];
    ubyte pOutputHw[64] = {0};
    ubyte pOutputSw[64] = {0};

    MSymTapKeyGenArgs aesTapArgs = {0};
    void *pAesTapArgs = (void *) &aesTapArgs;

    aesTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    aesTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    aesTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);
    aesTapArgs.keyAlgorithm = TAP_KEY_ALGORITHM_AES;

    /* make a pseduo random looking plaintext of 4 blocks */
    for (i = 0; i < sizeof(pInput); ++i)
    {
        pInput[i] = (ubyte) ((17 * (i + 1)) & 0xff);
    }

    TAP_KeyInfo keyInfo = {0};
    MSymTapCreateArgs createArgs = {0};
    ubyte pKey[32] = {0}; /* big enough for all tests */
    for (i = 0; i < keySize/8; ++i)
    {
        pKey[i] = (ubyte) (i+1);
    }

    switch(keySize)
    {
        case 128:
            keyInfo.algKeyInfo.aesInfo.keySize = TAP_KEY_SIZE_128;
            break;

        case 192:
            keyInfo.algKeyInfo.aesInfo.keySize = TAP_KEY_SIZE_192;
            break;

        case 256:
            keyInfo.algKeyInfo.aesInfo.keySize = TAP_KEY_SIZE_256;
            break;

        default:
            goto exit;
    }

    keyInfo.keyAlgorithm = TAP_KEY_ALGORITHM_AES;
    keyInfo.keyUsage = TAP_KEY_USAGE_DECRYPT;
    keyInfo.algKeyInfo.aesInfo.symMode = TAP_SYM_KEY_MODE_UNDEFINED;
    createArgs.pKeyInfo = &keyInfo;
    createArgs.pKeyData = (ubyte *)pKey;
    createArgs.keyDataLen = keySize/8;
    createArgs.token = FALSE;

    status = CRYPTO_INTERFACE_TAP_SymImportExternalKey(&pSymWrapper, pAesTapArgs, (void *)&createArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_TAP_getAesCtxFromSymmetricKeyAlloc (
        pSymWrapper, &pCtxHw, MODE_CBC, isEnc ? MOCANA_SYM_TAP_ENCRYPT : MOCANA_SYM_TAP_DECRYPT);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    pCtxSw = CRYPTO_INTERFACE_CreateAESCtx (MOC_SYM(gpHwAccelCtx) pKey, keySize/8, isEnc ? 1 : 0);
    if (NULL == pCtxSw)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
        goto exit;
    }

    if (isEnc)
    {
        status = CRYPTO_INTERFACE_AESALGO_blockEncrypt((aesCipherContext *) pCtxHw, pIv, pInput, 64 * 8, pOutputHw, &retLen);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        retVal += UNITTEST_INT(__MOC_LINE__, retLen, 64 * 8);

        status = CRYPTO_INTERFACE_AESALGO_blockEncrypt((aesCipherContext *) pCtxSw, pIv, pInput, 64 * 8, pOutputSw, &retLen);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        retVal += UNITTEST_INT(__MOC_LINE__, retLen, 64 * 8);

    }
    else
    {
        status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtxHw, pIv, pInput, 64 * 8, pOutputHw, &retLen);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        retVal += UNITTEST_INT(__MOC_LINE__, retLen, 64 * 8);

        status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtxSw, pIv, pInput, 64 * 8, pOutputSw, &retLen);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        retVal += UNITTEST_INT(__MOC_LINE__, retLen, 64 * 8);
    }

    status = DIGI_MEMCMP(pOutputSw, pOutputHw, 64, &compare);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, compare, 0);

exit:

    if (NULL != pCtxSw)
    {
        (void *)CRYPTO_INTERFACE_DeleteAESCtx (MOC_SYM(gpHwAccelCtx) &pCtxSw);
    }
    if (NULL != pCtxHw)
    {
        (void *)CRYPTO_INTERFACE_DeleteAESCtx (MOC_SYM(gpHwAccelCtx) &pCtxHw);
    }

    if (NULL != pSymWrapper)
    {
        (void) CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    }

    return retVal;
}

#ifdef __ENABLE_DIGICERT_PKCS11_DEBUG_PURGE_ALL_OBJ__

static int genKeyTestEx(ubyte4 keySize, intBoolean testDeferredUnload)
{
    int retVal = 0;
    MSTATUS status = 0;
    sbyte4 compare = -1;
    int i;

    BulkCtx pCtx = NULL;
    BulkCtx pCtx2 = NULL;
    ubyte *pSerKey = NULL;
    ubyte4 serLen = 0;
    SymmetricKey *pSymWrapper = NULL;

    /* Pointers for a special free on ctx1 */
    aesCipherContext *pAesCtx = NULL;
    MocSymCtx pMocSymCtx = NULL;
    MTapKeyData *pTapData = NULL;

    TAP_KeyHandle keyHandle = 0;
    TAP_TokenHandle tokenHandle = 0;

    ubyte pIv[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x00};
    ubyte pPlain[64];
    ubyte pCipher[64] = {0};
    ubyte pCipher2[64] = {0}; /* for a ResetCtx test */
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
        pSymWrapper, &pCtx, MODE_CBC, MOCANA_SYM_TAP_ENCRYPT);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_AesDeferKeyUnload(pCtx, TRUE);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

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

    /* test Reset context and encrypt again */
    status = CRYPTO_INTERFACE_ResetAESCtx(&pCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_AESALGO_blockEncrypt((aesCipherContext *) pCtx, pIv, pPlain, 64 * 8, pCipher2, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 64 * 8);

    /* make sure we got the same cipher text */
    status = DIGI_MEMCMP(pCipher, pCipher2, 64, &compare);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, compare, 0);

    /* Free the SymmetricKey wrapper */
    status = CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_AesGetKeyInfo (pCtx, &tokenHandle, &keyHandle);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

    status = CRYPTO_INTERFACE_ResetAESCtx(&pCtx);
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
        pSymWrapper, &pCtx2, MODE_CBC, MOCANA_SYM_TAP_DECRYPT);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_AesDeferKeyUnload(pCtx2, TRUE);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx2, pIv, pCipher, 16 * 8, pRecPlain, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 16 * 8);

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx2, pIv, pCipher + 16, 32 * 8, pRecPlain + 16, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 32 * 8);

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx2, pIv, pCipher + 48, 16 * 8, pRecPlain + 48, &retLen);
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
    status = CRYPTO_INTERFACE_ResetAESCtx(&pCtx2);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx2, pIv, pCipher, 16 * 8, pRecPlain, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 16 * 8);

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx2, pIv, pCipher + 16, 32 * 8, pRecPlain + 16, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 32 * 8);

    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt((aesCipherContext *) pCtx2, pIv, pCipher + 48, 16 * 8, pRecPlain + 48, &retLen);
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

    if (NULL != pCtx2)
    {
        (void *)CRYPTO_INTERFACE_DeleteAESCtx (MOC_SYM(gpHwAccelCtx) &pCtx2);
    }

    /* Special free code since we have two aes ctxs with two TAP keys each pointing to the same
     * underlying SMP resource, the above deletion deletes the actual object that this ctx also
     * points to, so to avoid errors manually free all the containers */
    if (NULL != pCtx)
    {
        pAesCtx = (aesCipherContext *)pCtx;
        pMocSymCtx = pAesCtx->pMocSymCtx;
        if (NULL != pMocSymCtx)
        {
            pTapData = (MTapKeyData *) pMocSymCtx->pLocalData;
            if (NULL != pTapData)
            {
                if (NULL != pTapData->pKey)
                {
                    TAP_freeKeyEx(&(pTapData->pKey));
                }

                DIGI_FREE((void **)&pTapData);
            }

            DIGI_FREE((void **)&pMocSymCtx);
        }

        DIGI_FREE((void **)&pCtx);
    }

    if (0 != keyHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapKey(TAP_EXAMPLE_getTapContext(1), tokenHandle, keyHandle);
        retVal += UNITTEST_STATUS(keySize, status);
    }

    if (0 != tokenHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapToken(TAP_EXAMPLE_getTapContext(1), tokenHandle);
        retVal += UNITTEST_STATUS(keySize, status);
    }

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

static int genKeyTest(ubyte4 keySize, intBoolean testDeferredUnload)
{
    int retVal = 0;
    MSTATUS status = 0;
    sbyte4 compare = -1;
    int i;

    BulkCtx pCtx = NULL;
    ubyte *pSerKey = NULL;
    ubyte4 serLen = 0;
    SymmetricKey *pSymWrapper = NULL;

    TAP_KeyHandle keyHandle = 0;
    TAP_TokenHandle tokenHandle = 0;

    ubyte pIv[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x00};
    ubyte pPlain[64];
    ubyte pCipher[64] = {0};
    ubyte pCipher2[64] = {0}; /* for a ResetCtx test */
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
        pSymWrapper, &pCtx, MODE_CBC, MOCANA_SYM_TAP_ENCRYPT);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_AesDeferKeyUnload(pCtx, TRUE);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

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

    /* test Reset context and encrypt again */
    status = CRYPTO_INTERFACE_ResetAESCtx(&pCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_AESALGO_blockEncrypt((aesCipherContext *) pCtx, pIv, pPlain, 64 * 8, pCipher2, &retLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, retLen, 64 * 8);

    /* make sure we got the same cipher text */
    status = DIGI_MEMCMP(pCipher, pCipher2, 64, &compare);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, compare, 0);

    /* Free the SymmetricKey wrapper */
    status = CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_AesGetKeyInfo (pCtx, &tokenHandle, &keyHandle);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

    status = CRYPTO_INTERFACE_DeleteAESCtx (MOC_SYM(gpHwAccelCtx) &pCtx);
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
        pSymWrapper, &pCtx, MODE_CBC, MOCANA_SYM_TAP_DECRYPT);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_AesDeferKeyUnload(pCtx, TRUE);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

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

    if (NULL != pCtx)
    {
        (void *)CRYPTO_INTERFACE_DeleteAESCtx (MOC_SYM(gpHwAccelCtx) &pCtx);
    }

    if (0 != keyHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapKey(TAP_EXAMPLE_getTapContext(1), tokenHandle, keyHandle);
        retVal += UNITTEST_STATUS(keySize, status);
    }

    if (0 != tokenHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapToken(TAP_EXAMPLE_getTapContext(1), tokenHandle);
        retVal += UNITTEST_STATUS(keySize, status);
    }

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

int crypto_interface_aes_cbc_test_init()
{
    MSTATUS status = ERR_NULL_POINTER;
    int errorCount = 0;
    ubyte4 modNum = 1;

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
        UNITTEST_STATUS(__MOC_LINE__, status);
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
    errorCount = (errorCount + speedTestAesCbc(pMultiBlockTests[0]));
#else

    errorCount = (errorCount + runTests());
    errorCount = (errorCount + negativeTest());
    errorCount = (errorCount + negativeTestsAesAlgo());

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TPM2__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
    status = TAP_EXAMPLE_init(&modNum, 1);
    if (OK != status)
    {
        errorCount += 1;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DEBUG_PURGE_ALL_OBJ__
    errorCount = (errorCount + genKeyTestEx(128, FALSE));
    errorCount = (errorCount + genKeyTestEx(192, FALSE));
    errorCount = (errorCount + genKeyTestEx(256, FALSE));

    errorCount = (errorCount + genKeyTestEx(128, TRUE));
    errorCount = (errorCount + genKeyTestEx(192, TRUE));
    errorCount = (errorCount + genKeyTestEx(256, TRUE));

    errorCount = (errorCount + createKeyTestEx(128));
    errorCount = (errorCount + createKeyTestEx(192));
    errorCount = (errorCount + createKeyTestEx(256));
#else
    errorCount = (errorCount + genKeyTest(128, FALSE));
    errorCount = (errorCount + genKeyTest(192, FALSE));
    errorCount = (errorCount + genKeyTest(256, FALSE));

    errorCount = (errorCount + genKeyTest(128, TRUE));
    errorCount = (errorCount + genKeyTest(192, TRUE));
    errorCount = (errorCount + genKeyTest(256, TRUE));

    errorCount = (errorCount + createKeyTest(128));
    errorCount = (errorCount + createKeyTest(192));
    errorCount = (errorCount + createKeyTest(256));
#endif

    errorCount += tapKAT(128, TRUE);
    errorCount += tapKAT(192, TRUE);
    errorCount += tapKAT(256, TRUE);

    errorCount += tapKAT(128, FALSE);
    errorCount += tapKAT(192, FALSE);
    errorCount += tapKAT(256, FALSE);

#endif /* __ENABLE_DIGICERT_TAP__ */
#endif /* __ENABLE_DIGICERT_UNITTEST_SPEEDTEST__ */

exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TPM2__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
    TAP_EXAMPLE_clean();
#endif

    DIGICERT_free(&gpMocCtx);
    return errorCount;
}
