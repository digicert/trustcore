/*
* crypto_interface_aes_ctr_test.c
*
* test file for AES in CTR mode.
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
#include "../../crypto_interface/crypto_interface_aes_ctr.h"

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TPM2__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
#include "crypto_interface_tap_example.h"
#include "../../crypto/mocsymalgs/tap/symtap.h"
#include "../../crypto_interface/cryptointerface.h"
#include "../../crypto_interface/crypto_interface_aes_tap.h"
#include "../../crypto_interface/crypto_interface_aes_ctr_tap.h"
#endif
#endif

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

#ifdef __ENABLE_DIGICERT_UNITTEST_SPEEDTEST__

#include <sys/types.h>
#include <sys/times.h>
#include <unistd.h>
#include <stdio.h>

#define ENCRYPT_ITERATIONS 10000000
#define DECRYPT_ITERATIONS 10000000

#endif

static MocCtx gpMocCtx = NULL;

typedef struct aesTest{
    ubyte pKey[32];
    sbyte4 keyLen;
    ubyte pInitCounter[16];
    ubyte4 initCounterLen;
    ubyte pPlain[48];
    sbyte4 plainLen;
    ubyte pCipher[48];
    sbyte4 cipherLen;
    ubyte pFirstCounter[16];
    ubyte pSecondCounter[16];
    ubyte pFinalCounter[16];
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
            0x92, 0x60, 0x13, 0xf7, 0xbb, 0x37, 0x0c, 0x8f, 0xe8, 0x45,
            0xba, 0xe2, 0x23, 0x98, 0x98, 0x22, 0x73, 0xff, 0x3f, 0x7d,
            0x77, 0x87, 0x58, 0xb8, 0xa5, 0xa3, 0xe6, 0x48, 0x67, 0x1e,
            0x8f, 0x9f, 0x9c, 0xc0, 0x4a, 0x1e, 0xb5, 0xa1, 0x2f, 0xac,
            0x5c, 0xb8, 0x5c, 0xf2, 0x6b, 0x0b, 0x9e, 0x93
        },
        48,
        {
            0xbd, 0x41, 0x6c, 0xb3, 0xb9, 0x89, 0x22, 0x28, 0xd8, 0xf1,
            0xdf, 0x57, 0x56, 0x92, 0xe4, 0xd1
        },
        {
            0xbd, 0x41, 0x6c, 0xb3, 0xb9, 0x89, 0x22, 0x28, 0xd8, 0xf1,
            0xdf, 0x57, 0x56, 0x92, 0xe4, 0xd2
        },
        {
            0xbd, 0x41, 0x6c, 0xb3, 0xb9, 0x89, 0x22, 0x28, 0xd8, 0xf1,
            0xdf, 0x57, 0x56, 0x92, 0xe4, 0xd3
        }
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
            0xe5, 0xcb, 0xe0, 0x4d, 0x8d, 0x11, 0xf4, 0xd0, 0x55, 0x27,
            0x28, 0xdf, 0x22, 0x90, 0x28, 0x62, 0x16, 0x77, 0x41, 0x69,
            0x54, 0xb8, 0xda, 0x9f, 0x1a, 0x96, 0x73, 0x93, 0x87, 0x02,
            0xeb, 0x12, 0x23, 0x85, 0x0d, 0xe1, 0x8f, 0x0d, 0x2a, 0xfe,
            0x3e, 0x0b, 0xee, 0x6b, 0xd3, 0xa8, 0x86, 0x90
        },
        48,
        {
            0xea, 0xae, 0xca, 0x2e, 0x07, 0xdd, 0xed, 0xf5, 0x62, 0xf9,
            0x4d, 0xf6, 0x3f, 0x0a, 0x65, 0x10
        },
        {
            0xea, 0xae, 0xca, 0x2e, 0x07, 0xdd, 0xed, 0xf5, 0x62, 0xf9,
            0x4d, 0xf6, 0x3f, 0x0a, 0x65, 0x11
        },
        {
            0xea, 0xae, 0xca, 0x2e, 0x07, 0xdd, 0xed, 0xf5, 0x62, 0xf9,
            0x4d, 0xf6, 0x3f, 0x0a, 0x65, 0x12
        }
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
            0xe6, 0x3c, 0xfe, 0x48, 0xac, 0x04, 0x04, 0xe1, 0xb9, 0xe9,
            0x8f, 0x42, 0xb5, 0x49, 0x15, 0xbf, 0xe8, 0xcd, 0xa3, 0x52,
            0x6a, 0x58, 0x05, 0xdf, 0x75, 0x88, 0x48, 0x8a, 0x72, 0x5b,
            0x7e, 0xa0, 0x5c, 0x40, 0x6b, 0x36, 0xd6, 0xcc, 0xf0, 0x56,
            0x1c, 0x4b, 0xc9, 0x67, 0x00, 0xb9, 0xe9, 0xfd
        },
        48,
        {
            0x19, 0x15, 0x3c, 0x67, 0x31, 0x60, 0xdf, 0x2b, 0x1d, 0x38,
            0xc2, 0x80, 0x60, 0xe5, 0x9b, 0x97
        },
        {
            0x19, 0x15, 0x3c, 0x67, 0x31, 0x60, 0xdf, 0x2b, 0x1d, 0x38,
            0xc2, 0x80, 0x60, 0xe5, 0x9b, 0x98
        },
        {
            0x19, 0x15, 0x3c, 0x67, 0x31, 0x60, 0xdf, 0x2b, 0x1d, 0x38,
            0xc2, 0x80, 0x60, 0xe5, 0x9b, 0x99
        }
    }
};


static aesTest pSingleBlockTests[4] = {
    {

        {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
            0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        },
        16,
        {
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
            0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
        },
        16,
        {
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d,
            0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
        },
        16,
        {
            0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef,
            0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce
        },
        16
    },
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
            0x3e, 0xb7, 0x53, 0x15, 0x57, 0x64, 0xdf, 0x1e, 0xdb, 0xfa,
            0x57, 0x93, 0xf9, 0x5d, 0x88, 0x67
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
            0xd9, 0x68, 0xc3, 0x21, 0xbe, 0xda, 0x57, 0x28, 0xe6, 0xbd,
            0x14, 0x4f, 0x04, 0xfe, 0x06, 0x13
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
            0xa5, 0x85, 0x71, 0xb5, 0xef, 0xb6, 0xc8, 0x1d, 0xcc, 0x69,
            0x8c, 0x18, 0x38, 0x1c, 0xb5, 0x72
        },
        16
    }
};


#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_CTR__))
/*----------------------------------------------------------------------------*/

static int testCryptoInterface(aesTest test)
{
    MSTATUS status = OK;

    aesCTRCipherContext *pAesCtx = NULL;;
    MocSymCtx pTest = NULL;
    ubyte enabled = 0;

    ubyte *pKeyBuffer = NULL;
    ubyte4 keyBufferLen = AES_BLOCK_SIZE + test.keyLen;

    status = DIGI_MALLOC((void**)&pKeyBuffer, keyBufferLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pKeyBuffer, test.pKey, test.keyLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pKeyBuffer + test.keyLen, test.pInitCounter, AES_BLOCK_SIZE);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

#if (defined(__ENABLE_DIGICERT_MBED_SYM_OPERATORS__) && \
    (defined(__ENABLE_DIGICERT_AES_CTR_MBED__)))
    pAesCtx = (aesCTRCipherContext*)CreateAESCTRCtx(MOC_SYM(gpHwAccelCtx) (const ubyte *) pKeyBuffer, keyBufferLen, TRUE);
    if (NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    pTest = pAesCtx->pMocSymCtx;
    enabled = pAesCtx->enabled;
    if (NULL == pTest)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (FALSE == enabled)
    {
        status = ERR_INVALID_ARG;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }
#endif

exit:

    if (NULL != pAesCtx)
        DeleteAESCTRCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx *)&pAesCtx);

    if (NULL != pKeyBuffer)
        DIGI_FREE((void**)&pKeyBuffer);

    if (OK != status)
        return 1;
    return 0;
}
#endif


/*----------------------------------------------------------------------------*/

static int negativeTest()
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 errorCount = 0;

    ubyte pKey[32] = { 0 };
    sbyte4 keyLen = 32;

    ubyte pPlain[48] = { 0 };

    aesCTRCipherContext *pAesCtx;

    pAesCtx = (aesCTRCipherContext*)CreateAESCTRCtx(MOC_SYM(gpHwAccelCtx) (const ubyte *) pKey, keyLen, TRUE);
    if (NULL == pAesCtx)
    {
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DoAESCTR(MOC_SYM(gpHwAccelCtx) NULL, pPlain, 16, TRUE, NULL);
    if (OK != status)
    {
        errorCount = (errorCount + 1);
    }
    else
    {
        status = ERR_INVALID_INPUT;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = DoAESCTR(MOC_SYM(gpHwAccelCtx) pAesCtx, NULL, 16, TRUE, NULL);
    if (OK != status)
    {
        errorCount = (errorCount + 1);
    }
    else
    {
        status = ERR_INVALID_INPUT;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = DeleteAESCTRCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pAesCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    pAesCtx = (aesCTRCipherContext*)CreateAESCTRCtx(MOC_SYM(gpHwAccelCtx) (const ubyte *) pKey, keyLen, FALSE);
    if (NULL == pAesCtx)
    {
        errorCount += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DoAESCTR(MOC_SYM(gpHwAccelCtx) pAesCtx, NULL, 16, FALSE, NULL);
    if (OK != status)
    {
        errorCount = (errorCount + 1);
    }
    else
    {
        status = ERR_INVALID_INPUT;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = DoAESCTR(MOC_SYM(gpHwAccelCtx) NULL, pPlain, 16, FALSE, NULL);
    if (OK != status)
    {
        errorCount = (errorCount + 1);
    }
    else
    {
        status = ERR_INVALID_INPUT;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    DeleteAESCTRCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx *)&pAesCtx);

    /* give invalid keyLen */
    pAesCtx = (aesCTRCipherContext*)CreateAESCTRCtx(MOC_SYM(gpHwAccelCtx) (const ubyte *) pKey, 100, TRUE);
    if (NULL != pAesCtx)
    {
        errorCount += UNITTEST_STATUS(__MOC_LINE__, ERR_NULL_POINTER);
    }

exit:

    if (NULL != pAesCtx)
    {
        DeleteAESCTRCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx *)&pAesCtx);
    }

    if (4 != errorCount)
        return 1;
    return 0;
}


/*----------------------------------------------------------------------------*/

static int runSingleBlockTest(aesTest test)
{
    MSTATUS status = ERR_NULL_POINTER;

    /* copy of iv, used to reinitialize pInitCounter for decryption step */

    /* buffer used to DoAES operations */
    ubyte *pData = NULL;
    sbyte4 dataLen = 0;

    sbyte4 cmpRes = -1;
    aesCTRCipherContext *pAesCtx = NULL;

    ubyte *pKeyBuffer = NULL;
    ubyte4 keyBufferLen = AES_BLOCK_SIZE + test.keyLen;

    status = DIGI_MALLOC((void**)&pKeyBuffer, keyBufferLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pKeyBuffer, test.pKey, test.keyLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pKeyBuffer + test.keyLen, test.pInitCounter, AES_BLOCK_SIZE);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* last 4 bytes should contain counter */
    dataLen = test.plainLen;
    status = DIGI_MALLOC((void**)&pData, dataLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pData, test.pPlain, dataLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;


    pAesCtx = (aesCTRCipherContext*)CreateAESCTRCtx(MOC_SYM(gpHwAccelCtx) (const ubyte *) pKeyBuffer, keyBufferLen, TRUE);
    if (NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DoAESCTR(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData, dataLen, TRUE, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pData, test.pCipher, dataLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DeleteAESCTRCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pAesCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* copy both just to be safe */
    status = DIGI_MEMCPY(pKeyBuffer, test.pKey, test.keyLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pKeyBuffer + test.keyLen, test.pInitCounter, AES_BLOCK_SIZE);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* copy the counter back into the last 4 bytes */
    /* do decryption step */
    pAesCtx = (aesCTRCipherContext*)CreateAESCTRCtx(MOC_SYM(gpHwAccelCtx) (const ubyte *) pKeyBuffer, keyBufferLen, FALSE);
    if (NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DoAESCTR(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData, dataLen, FALSE, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pData, test.pPlain, dataLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:
    if (NULL != pData)
    {
        DIGI_FREE((void**)&pData);
    }

    if (NULL != pAesCtx)
    {
        DeleteAESCTRCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pAesCtx);
    }

    if (NULL != pKeyBuffer)
    {
        DIGI_FREE((void**)&pKeyBuffer);
    }

    if (OK != status)
        return 1;
    return 0;
}


/*----------------------------------------------------------------------------*/

static int runNonAlignedSingleBlockTest(aesTest test)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte4 cmpRes = -1;
    aesCTRCipherContext *pAesCtx = NULL;

    /* buffer used to DoAES operations */
    ubyte pData[52] = { 0 };
    sbyte4 dataLen;

    ubyte *pKeyBuffer = NULL;
    ubyte4 keyBufferLen = test.keyLen + AES_BLOCK_SIZE;

    status = DIGI_MALLOC((void**)&pKeyBuffer, keyBufferLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pKeyBuffer, test.pKey, test.keyLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pKeyBuffer + test.keyLen, test.pInitCounter, AES_BLOCK_SIZE);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    dataLen = test.plainLen;
    status = DIGI_MEMCPY(pData + 1, test.pPlain, dataLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    pAesCtx = (aesCTRCipherContext*)CreateAESCTRCtx(MOC_SYM(gpHwAccelCtx) (const ubyte *) pKeyBuffer, keyBufferLen, TRUE);
    if (NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DoAESCTR(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData + 1, dataLen, TRUE, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pData + 1, test.pCipher, dataLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:
    if (NULL != pAesCtx)
    {
        DeleteAESCTRCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pAesCtx);
    }

    if (NULL != pKeyBuffer)
        DIGI_FREE((void**)&pKeyBuffer);

    if (OK != status)
        return 1;
    return 0;
}


/*----------------------------------------------------------------------------*/

static int runMultiBlockTest(aesTest test)
{
    MSTATUS status = ERR_NULL_POINTER;

    /* buffer for DoAES operations */

    sbyte4 dataLen = 48;
    ubyte pData[48] = { 0 };

    sbyte4 cmpRes = -1;
    aesCTRCipherContext *pAesCtx = NULL;

    ubyte *pKeyBuffer = NULL;
    ubyte4 keyBufferLen = AES_BLOCK_SIZE + test.keyLen;

    status = DIGI_MALLOC((void**)&pKeyBuffer, keyBufferLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pKeyBuffer, test.pKey, test.keyLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pKeyBuffer + test.keyLen, test.pInitCounter, AES_BLOCK_SIZE);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    dataLen = test.plainLen;
    status = DIGI_MEMCPY(pData, test.pPlain, dataLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    pAesCtx = (aesCTRCipherContext*)CreateAESCTRCtx(MOC_SYM(gpHwAccelCtx) (const ubyte *) pKeyBuffer, keyBufferLen, TRUE);
    if (NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_MBED_SYM_OPERATORS__) && \
     defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_CTR__))
    if (NULL == pAesCtx->pMocSymCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (TRUE != pAesCtx->enabled)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }
#endif

    status = DoAESCTR(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData, 16, TRUE, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DoAESCTR(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData + 16, 16, TRUE, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DoAESCTR(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData + 32, 16, TRUE, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pData, test.pCipher, dataLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DeleteAESCTRCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pAesCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* do decryption step */
    pAesCtx = (aesCTRCipherContext*)CreateAESCTRCtx(MOC_SYM(gpHwAccelCtx) (const ubyte *) pKeyBuffer, keyBufferLen, FALSE);
    if (NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* copy both just to be safe */
    status = DIGI_MEMCPY(pKeyBuffer, test.pKey, test.keyLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pKeyBuffer + test.keyLen, test.pInitCounter, AES_BLOCK_SIZE);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DoAESCTR(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData, 16, FALSE, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DoAESCTR(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData + 16, 16, FALSE, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DoAESCTR(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData + 32, 16, FALSE, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pData, test.pPlain, dataLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:

    if (NULL != pAesCtx)
    {
        DeleteAESCTRCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pAesCtx);
    }

    if (NULL != pKeyBuffer)
        DIGI_FREE((void**)&pKeyBuffer);

    if (OK != status)
        return 1;
    return 0;
}

/*----------------------------------------------------------------------------*/

static int runCloneTest(aesTest test)
{
    MSTATUS status = ERR_NULL_POINTER;

    /* buffer for DoAES operations */

    sbyte4 dataLen = 48;
    ubyte pData[48] = { 0 };

    sbyte4 cmpRes = -1;
    aesCTRCipherContext *pAesCtx = NULL;
    aesCTRCipherContext *pCloneCtx = NULL;

    ubyte *pKeyBuffer = NULL;
    ubyte4 keyBufferLen = AES_BLOCK_SIZE + test.keyLen;

    status = DIGI_MALLOC((void**)&pKeyBuffer, keyBufferLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pKeyBuffer, test.pKey, test.keyLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pKeyBuffer + test.keyLen, test.pInitCounter, AES_BLOCK_SIZE);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    dataLen = test.plainLen;
    status = DIGI_MEMCPY(pData, test.pPlain, dataLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    pAesCtx = (aesCTRCipherContext*)CreateAESCTRCtx(MOC_SYM(gpHwAccelCtx) (const ubyte *) pKeyBuffer, keyBufferLen, TRUE);
    if (NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_MBED_SYM_OPERATORS__) && \
     defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_CTR__))
    if (NULL == pAesCtx->pMocSymCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (TRUE != pAesCtx->enabled)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }
#endif

    /* Encrypt the first block */
    status = DoAESCTR(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData, 16, TRUE, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Clone the context in this state */
    status = CloneAESCTRCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, (BulkCtx *)&pCloneCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* Complete the rest of the processing with the clone context */
    status = DoAESCTR(MOC_SYM(gpHwAccelCtx) (BulkCtx)pCloneCtx, pData + 16, 32, TRUE, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pData, test.pCipher, dataLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = DeleteAESCTRCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pAesCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DeleteAESCTRCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pCloneCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* do decryption step */
    pAesCtx = (aesCTRCipherContext*)CreateAESCTRCtx(MOC_SYM(gpHwAccelCtx) (const ubyte *) pKeyBuffer, keyBufferLen, FALSE);
    if (NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* copy both just to be safe */
    status = DIGI_MEMCPY(pKeyBuffer, test.pKey, test.keyLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pKeyBuffer + test.keyLen, test.pInitCounter, AES_BLOCK_SIZE);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DoAESCTR(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData, 16, FALSE, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Clone the context in this state */
    status = CloneAESCTRCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, (BulkCtx *)&pCloneCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DoAESCTR(MOC_SYM(gpHwAccelCtx) (BulkCtx)pCloneCtx, pData + 16, 32, FALSE, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pData, test.pPlain, dataLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:

    if (NULL != pAesCtx)
    {
        DeleteAESCTRCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pAesCtx);
    }
    if (NULL != pCloneCtx)
    {
        DeleteAESCTRCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pCloneCtx);
    }

    if (NULL != pKeyBuffer)
        DIGI_FREE((void**)&pKeyBuffer);

    if (OK != status)
        return 1;
    return 0;
}

/*----------------------------------------------------------------------------*/

static int testGetCounterBLock(aesTest test)
{
    MSTATUS status;
    sbyte4 dataLen = 48;
    ubyte pData[48] = { 0 };
    ubyte pCounterBlock[AES_BLOCK_SIZE] = { 0 };

    sbyte4 cmpRes = -1;
    aesCTRCipherContext *pAesCtx = NULL;

    ubyte *pKeyBuffer = NULL;
    ubyte4 keyBufferLen = AES_BLOCK_SIZE + test.keyLen;

    status = DIGI_MALLOC((void**)&pKeyBuffer, keyBufferLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pKeyBuffer, test.pKey, test.keyLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pKeyBuffer + test.keyLen, test.pInitCounter, AES_BLOCK_SIZE);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    dataLen = test.plainLen;
    status = DIGI_MEMCPY(pData, test.pPlain, dataLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    pAesCtx = (aesCTRCipherContext*)CreateAESCTRCtx(MOC_SYM(gpHwAccelCtx) (const ubyte *) pKeyBuffer, keyBufferLen, TRUE);
    if (NULL == pAesCtx)
    {
        status = ERR_NULL_POINTER;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }
    status = GetCounterBlockAESCTR(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pCounterBlock);
    if (OK != status)
        goto exit;

    status = DoAESCTR(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData, AES_BLOCK_SIZE, TRUE, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Get first counter block */
    status = GetCounterBlockAESCTR(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pCounterBlock);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pCounterBlock, test.pFirstCounter, AES_BLOCK_SIZE, &cmpRes);
    if (OK != status)
        goto exit;

    status = DoAESCTR(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData + AES_BLOCK_SIZE, AES_BLOCK_SIZE, TRUE, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Get second counter block */
    status = GetCounterBlockAESCTR(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pCounterBlock);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pCounterBlock, test.pSecondCounter, AES_BLOCK_SIZE, &cmpRes);
    if (OK != status)
        goto exit;

    status = DoAESCTR(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pData + AES_BLOCK_SIZE + AES_BLOCK_SIZE, AES_BLOCK_SIZE, TRUE, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pData, test.pCipher, dataLen, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = GetCounterBlockAESCTR(MOC_SYM(gpHwAccelCtx) (BulkCtx)pAesCtx, pCounterBlock);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pCounterBlock, test.pFinalCounter, AES_BLOCK_SIZE, &cmpRes);
    if (OK != status)
        goto exit;

    if (0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:

    if (NULL != pAesCtx)
    {
        DeleteAESCTRCtx(MOC_SYM(gpHwAccelCtx) (BulkCtx*)&pAesCtx);
    }

    if (NULL != pKeyBuffer)
        DIGI_FREE((void**)&pKeyBuffer);

    if (OK != status)
        return 1;
    return 0;
}


/*----------------------------------------------------------------------------*/

static int runTests()
{
    int errorCount = 0;
    int i = 0;

    for (i = 0;i < 4; i++)
        errorCount = (errorCount + runSingleBlockTest(pSingleBlockTests[i]));

    for (i = 0;i < 3; i++)
        errorCount = (errorCount + runMultiBlockTest(pMultiBlockTests[i]));

    for (i = 0;i < 3; i++)
        errorCount = (errorCount + runCloneTest(pMultiBlockTests[i]));

    for (i = 0;i < 3; i++)
        errorCount = (errorCount + runNonAlignedSingleBlockTest(pSingleBlockTests[i]));

    for (i = 0;i < 3; i++)
        errorCount = (errorCount + testGetCounterBLock(pMultiBlockTests[i]));
    return errorCount;
}

/*----------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_IPSEC_SERVICE__

typedef struct
{
    ubyte pKeyMat[36];
    ubyte4 keyMatLen;
    ubyte pIv[8];
    ubyte *pPlainText;
    ubyte *pCipherText;
    ubyte4 dataLen;
} AesCtrIpsecTV;

#define TEST_VECTOR_SIZE 6

static AesCtrIpsecTV gpTestVector[TEST_VECTOR_SIZE] = {
    {
        .pKeyMat = {
            0xAE, 0x68, 0x52, 0xF8, 0x12, 0x10, 0x67, 0xCC,
            0x4B, 0xF7, 0xA5, 0x76, 0x55, 0x77, 0xF3, 0x9E,
            0x00, 0x00, 0x00, 0x30
        },
        .keyMatLen = 20,
        .pIv = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        .pPlainText = (ubyte *) "Single block msg",
        .pCipherText = (ubyte *)
        "\x0E4\x009\x05D\x04F\x0B7\x0A7\x0B3\x079"
        "\x02D\x061\x075\x0A3\x026\x013\x011\x0B8",
        .dataLen = 16
    },
    {
        .pKeyMat = {
            0x7E, 0x24, 0x06, 0x78, 0x17, 0xFA, 0xE0, 0xD7,
            0x43, 0xD6, 0xCE, 0x1F, 0x32, 0x53, 0x91, 0x63,
            0x00, 0x6C, 0xB6, 0xDB
        },
        .keyMatLen = 20,
        .pIv = {
            0xC0, 0x54, 0x3B, 0x59, 0xDA, 0x48, 0xD9, 0x0B
        },
        .pPlainText = (ubyte *)
        "\x000\x001\x002\x003\x004\x005\x006\x007"
        "\x008\x009\x00A\x00B\x00C\x00D\x00E\x00F"
        "\x010\x011\x012\x013\x014\x015\x016\x017"
        "\x018\x019\x01A\x01B\x01C\x01D\x01E\x01F",
        .pCipherText = (ubyte *)
        "\x051\x004\x0A1\x006\x016\x08A\x072\x0D9"
        "\x079\x00D\x041\x0EE\x08E\x0DA\x0D3\x088"
        "\x0EB\x02E\x01E\x0FC\x046\x0DA\x057\x0C8"
        "\x0FC\x0E6\x030\x0DF\x091\x041\x0BE\x028",
        .dataLen = 32
    },
    {
        .pKeyMat = {
            0x16, 0xAF, 0x5B, 0x14, 0x5F, 0xC9, 0xF5, 0x79,
            0xC1, 0x75, 0xF9, 0x3E, 0x3B, 0xFB, 0x0E, 0xED,
            0x86, 0x3D, 0x06, 0xCC, 0xFD, 0xB7, 0x85, 0x15,
            0x00, 0x00, 0x00, 0x48
        },
        .keyMatLen = 28,
        .pIv = {
            0x36, 0x73, 0x3C, 0x14, 0x7D, 0x6D, 0x93, 0xCB
        },
        .pPlainText = (ubyte *) "Single block msg",
        .pCipherText = (ubyte *)
        "\x04B\x055\x038\x04F\x0E2\x059\x0C9\x0C8"
        "\x04E\x079\x035\x0A0\x003\x0CB\x0E9\x028",
        .dataLen = 16
    },
    {
        .pKeyMat = {
            0x7C, 0x5C, 0xB2, 0x40, 0x1B, 0x3D, 0xC3, 0x3C,
            0x19, 0xE7, 0x34, 0x08, 0x19, 0xE0, 0xF6, 0x9C,
            0x67, 0x8C, 0x3D, 0xB8, 0xE6, 0xF6, 0xA9, 0x1A,
            0x00, 0x96, 0xB0, 0x3B
        },
        .keyMatLen = 28,
        .pIv = {
            0x02, 0x0C, 0x6E, 0xAD, 0xC2, 0xCB, 0x50, 0x0D
        },
        .pPlainText = (ubyte *)
        "\x000\x001\x002\x003\x004\x005\x006\x007"
        "\x008\x009\x00A\x00B\x00C\x00D\x00E\x00F"
        "\x010\x011\x012\x013\x014\x015\x016\x017"
        "\x018\x019\x01A\x01B\x01C\x01D\x01E\x01F",
        .pCipherText = (ubyte *)
        "\x045\x032\x043\x0FC\x060\x09B\x023\x032"
        "\x07E\x0DF\x0AA\x0FA\x071\x031\x0CD\x09F"
        "\x084\x090\x070\x01C\x05A\x0D4\x0A7\x09C"
        "\x0FC\x01F\x0E0\x0FF\x042\x0F4\x0FB\x000",
        .dataLen = 32
    },
    {
        .pKeyMat = {
            0x77, 0x6B, 0xEF, 0xF2, 0x85, 0x1D, 0xB0, 0x6F,
            0x4C, 0x8A, 0x05, 0x42, 0xC8, 0x69, 0x6F, 0x6C,
            0x6A, 0x81, 0xAF, 0x1E, 0xEC, 0x96, 0xB4, 0xD3,
            0x7F, 0xC1, 0xD6, 0x89, 0xE6, 0xC1, 0xC1, 0x04,
            0x00, 0x00, 0x00, 0x60
        },
        .keyMatLen = 36,
        .pIv = {
            0xDB, 0x56, 0x72, 0xC9, 0x7A, 0xA8, 0xF0, 0xB2
        },
        .pPlainText = (ubyte *) "Single block msg",
        .pCipherText = (ubyte *)
        "\x014\x05A\x0D0\x01D\x0BF\x082\x04E\x0C7"
        "\x056\x008\x063\x0DC\x071\x0E3\x0E0\x0C0",
        .dataLen = 16
    },
    {
        .pKeyMat = {
            0xF6, 0xD6, 0x6D, 0x6B, 0xD5, 0x2D, 0x59, 0xBB,
            0x07, 0x96, 0x36, 0x58, 0x79, 0xEF, 0xF8, 0x86,
            0xC6, 0x6D, 0xD5, 0x1A, 0x5B, 0x6A, 0x99, 0x74,
            0x4B, 0x50, 0x59, 0x0C, 0x87, 0xA2, 0x38, 0x84,
            0x00, 0xFA, 0xAC, 0x24
        },
        .keyMatLen = 36,
        .pIv = {
            0xC1, 0x58, 0x5E, 0xF1, 0x5A, 0x43, 0xD8, 0x75
        },
        .pPlainText = (ubyte *)
        "\x000\x001\x002\x003\x004\x005\x006\x007"
        "\x008\x009\x00A\x00B\x00C\x00D\x00E\x00F"
        "\x010\x011\x012\x013\x014\x015\x016\x017"
        "\x018\x019\x01A\x01B\x01C\x01D\x01E\x01F",
        .pCipherText = (ubyte *)
        "\x0F0\x05E\x023\x01B\x038\x094\x061\x02C"
        "\x049\x0EE\x000\x00B\x080\x04E\x0B2\x0A9"
        "\x0B8\x030\x06B\x050\x08F\x083\x09D\x06A"
        "\x055\x030\x083\x01D\x093\x044\x0AF\x01C",
        .dataLen = 32
    }
};

static int runIpSecServiceTest()
{
    int retVal = 0;
    MSTATUS status = OK;
    ubyte4 index;
    sbyte4 cmpRes;
    AesCtrIpsecTV *pCurTest = NULL;
    BulkCtx pAesCtrCtx = NULL;
    ubyte pIv[8];
    ubyte *pOutput = NULL;
    ubyte4 outLen;

    for (index = 0; index < TEST_VECTOR_SIZE; ++index)
    {
        pCurTest = gpTestVector + index;

        outLen = pCurTest->dataLen;

        status = DIGI_MALLOC((void **) &pOutput, outLen);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(pOutput, pCurTest->pPlainText, outLen);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(pIv, pCurTest->pIv, sizeof(pIv));
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        pAesCtrCtx = CreateAesCtrCtx(MOC_SYM(gpHwAccelCtx) pCurTest->pKeyMat, pCurTest->keyMatLen, 1);
        if (NULL == pAesCtrCtx)
        {
            retVal += UNITTEST_STATUS(__MOC_LINE__, -1); /* force error */
            goto exit;
        }

        status = DoAesCtrEx(MOC_SYM(gpHwAccelCtx) pAesCtrCtx, pOutput, outLen, 1, pIv);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCMP(pOutput, pCurTest->pCipherText, outLen, &cmpRes);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        retVal += UNITTEST_INT(__MOC_LINE__, cmpRes, 0);

        status = DeleteAESCTRCtx(MOC_SYM(gpHwAccelCtx) &pAesCtrCtx);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(pIv, pCurTest->pIv, sizeof(pIv));
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        pAesCtrCtx = CreateAesCtrCtx(MOC_SYM(gpHwAccelCtx) pCurTest->pKeyMat, pCurTest->keyMatLen, 0);
        if (NULL == pAesCtrCtx)
        {
            retVal += UNITTEST_STATUS(__MOC_LINE__, -1); /* force error */
            goto exit;
        }

        status = DoAesCtrEx(MOC_SYM(gpHwAccelCtx) pAesCtrCtx, pOutput, outLen, 0, pIv);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        status = DeleteAESCTRCtx(MOC_SYM(gpHwAccelCtx) &pAesCtrCtx);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCMP(pOutput, pCurTest->pPlainText, outLen, &cmpRes);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        retVal += UNITTEST_INT(__MOC_LINE__, cmpRes, 0);

        status = DIGI_FREE((void **) &pOutput);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }

exit:

    if (NULL != pOutput)
    {
        status = DIGI_FREE((void **) &pOutput);
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}

#endif /* __ENABLE_DIGICERT_IPSEC_SERVICE__ */

/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TPM2__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
/* known answer test by comparing TAP (Hw) results with Sw results */
static int tapKAT(ubyte4 keySize, ubyte4 inputLen)
{
    int retVal = 0;
    MSTATUS status = 0;
    ubyte4 keyLen = keySize/8;
    sbyte4 compare = -1;
    sbyte4 bytesWritten = 0;
    ubyte *pOutPtr = NULL;
    int i;

    BulkCtx pCtxHw = NULL;
    BulkCtx pCtxSw = NULL;

    SymmetricKey *pSymWrapper = NULL;

    ubyte *pDataHw = NULL;
    ubyte *pDataSw = NULL;
    ubyte *pIv = NULL;

    MSymTapKeyGenArgs aesTapArgs = {0};
    void *pAesTapArgs = (void *) &aesTapArgs;

    TAP_KeyInfo keyInfo = {0};
    MSymTapCreateArgs createArgs = {0};
    ubyte pKey[48] = {0}; /* big enough for all tests */

    aesTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    aesTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    aesTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);
    aesTapArgs.keyAlgorithm = TAP_KEY_ALGORITHM_AES;

    status = DIGI_MALLOC((void **) &pDataHw, inputLen);
    retVal += UNITTEST_STATUS(inputLen, status);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **) &pDataSw, inputLen);
    retVal += UNITTEST_STATUS(inputLen, status);
    if (OK != status)
        goto exit;

    /* make a pseduo random looking plaintext of 4 blocks */
    for (i = 0; i < inputLen; ++i)
    {
        pDataHw[i] = pDataSw[i] = (ubyte) ((17 * (i + 1)) & 0xff);
    }

    for (i = 0; i < keyLen + 16; ++i)
    {
        pKey[i] = (ubyte) ((11 * (i + 1)) & 0xff);
    }

    /* The IV is after the key */
    pIv = (ubyte *) &pKey[keyLen];

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
    createArgs.keyDataLen = keyLen;
    createArgs.token = FALSE;

    status = CRYPTO_INTERFACE_TAP_SymImportExternalKey(&pSymWrapper, pAesTapArgs, (void *)&createArgs);
    retVal += UNITTEST_STATUS(inputLen, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_TAP_getAesCtrCtxFromSymmetricKeyAlloc (
        pSymWrapper, &pCtxHw, pIv);
    retVal += UNITTEST_STATUS(inputLen, status);
    if (OK != status)
        goto exit;

    pCtxSw = CRYPTO_INTERFACE_CreateAESCTRCtx (MOC_SYM(gpHwAccelCtx) pKey, keyLen + 16, 0); /* initial iv is here for sw */
    if (NULL == pCtxSw)
    {
        retVal += UNITTEST_STATUS(inputLen, -1);
        goto exit;
    }

    if (inputLen >= 16)
    {
        pOutPtr = pDataHw;

        status = CRYPTO_INTERFACE_UpdateAesCtrEx (MOC_SYM(gpHwAccelCtx) pCtxHw, pDataHw, 15, pOutPtr, &bytesWritten);
        retVal += UNITTEST_STATUS(inputLen, status);
        if (OK != status)
            goto exit;

        pOutPtr += bytesWritten;

        status = CRYPTO_INTERFACE_UpdateAesCtrEx (MOC_SYM(gpHwAccelCtx) pCtxHw, pDataHw + 15, inputLen - 15, pOutPtr, &bytesWritten);
        retVal += UNITTEST_STATUS(inputLen, status);
        if (OK != status)
            goto exit;

        pOutPtr += bytesWritten;

        status = CRYPTO_INTERFACE_FinalAesCtrEx (MOC_SYM(gpHwAccelCtx) pCtxHw, pOutPtr, &bytesWritten);
        retVal += UNITTEST_STATUS(inputLen, status);
        if (OK != status)
            goto exit;

        pOutPtr += bytesWritten;

        /* make sure total bytes written is correct */
        status = UNITTEST_INT(inputLen, (ubyte4) (pOutPtr - pDataHw) , inputLen);
    }
    else
    {
        pOutPtr = pDataHw;

        status = CRYPTO_INTERFACE_UpdateAesCtrEx (MOC_SYM(gpHwAccelCtx) pCtxHw, pDataHw, inputLen, pOutPtr, &bytesWritten);
        retVal += UNITTEST_STATUS(inputLen, status);
        if (OK != status)
            goto exit;

        pOutPtr += bytesWritten;

        status = CRYPTO_INTERFACE_FinalAesCtrEx (MOC_SYM(gpHwAccelCtx) pCtxHw, pOutPtr, &bytesWritten);
        retVal += UNITTEST_STATUS(inputLen, status);
        if (OK != status)
            goto exit;

        pOutPtr += bytesWritten;

        /* make sure total bytes written is correct */
        status = UNITTEST_INT(inputLen, (ubyte4) (pOutPtr - pDataHw) , inputLen);
    }

    status = CRYPTO_INTERFACE_DoAESCTR (MOC_SYM(gpHwAccelCtx) pCtxSw, pDataSw, inputLen, 0, NULL);
    retVal += UNITTEST_STATUS(inputLen, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pDataHw, pDataSw, inputLen, &compare);
    retVal += UNITTEST_STATUS(inputLen, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(inputLen, compare, 0);

exit:

    if (NULL != pCtxSw)
    {
        (void *)CRYPTO_INTERFACE_DeleteAESCTRCtx (MOC_SYM(gpHwAccelCtx) &pCtxSw);
    }
    if (NULL != pCtxHw)
    {
        (void *)CRYPTO_INTERFACE_DeleteAESCTRCtx (MOC_SYM(gpHwAccelCtx) &pCtxHw);
    }

    if (NULL != pSymWrapper)
    {
        (void) CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    }

    if (NULL != pDataHw)
    {
        (void) DIGI_FREE((void **) &pDataHw);
    }

    if (NULL != pDataSw)
    {
        (void) DIGI_FREE((void **) &pDataSw);
    }

    return retVal;
}

static int tapTest(ubyte4 keySize, intBoolean testDeferredUnload)
{
    BulkCtx pCtx = NULL;
    MSymTapKeyGenArgs aesTapArgs = {0};
    int retVal = 0;
    MSTATUS status = 0;
    sbyte4 compare = -1;
    int i;

    ubyte *pSerKey = NULL;
    ubyte4 serLen = 0;
    SymmetricKey *pSymWrapper = NULL;

    TAP_KeyHandle keyHandle = 0;
    TAP_TokenHandle tokenHandle = 0;

    ubyte pIv[16] = {0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    ubyte pPlain[64];
    ubyte pPlainCopy[64] = {0};
    sbyte4 retLen = 0;
    void *pAesTapArgs = (void *) &aesTapArgs;

    /* make a pseduo random looking plaintext of 4 blocks */
    for (i = 0; i < sizeof(pPlain); ++i)
    {
        pPlain[i] = pPlainCopy[i] = (ubyte) ((17 * (i + 1)) & 0xff);
    }

    aesTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    aesTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    aesTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);
    aesTapArgs.keyAlgorithm = TAP_KEY_ALGORITHM_AES;

    status = CRYPTO_INTERFACE_TAP_GenerateSymKey(&pSymWrapper, keySize, pAesTapArgs);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    /* serialize the key while we still have it as a SymmetricKey */
    status = CRYPTO_INTERFACE_TAP_serializeSymKey(pSymWrapper, &pSerKey, &serLen);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    /* Transfer control of the SymmetricKey underlying data into a usable AES context.
     * The SymmetricKey is now just a wrapper that still needs to be freed. */
    status = CRYPTO_INTERFACE_TAP_getAesCtrCtxFromSymmetricKeyAlloc (
        pSymWrapper, &pCtx, pIv);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_AesCtrDeferKeyUnload(pCtx, TRUE);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

    status = CRYPTO_INTERFACE_DoAESCTR (MOC_SYM(gpHwAccelCtx) pCtx, pPlain, 16, 0, NULL);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_DoAESCTR (MOC_SYM(gpHwAccelCtx) pCtx, pPlain + 16, 16, 0, NULL);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_DoAESCTR (MOC_SYM(gpHwAccelCtx) pCtx, pPlain + 32, 32, 0, NULL);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_AesCtrGetKeyInfo (pCtx, &tokenHandle, &keyHandle);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

    /* delete the context */
    status = CRYPTO_INTERFACE_DeleteAESCTRCtx (MOC_SYM(gpHwAccelCtx) &pCtx);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    /* Free the SymmetricKey wrapper */
    status = CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    /* deserialize into a SymmetricKey wrapper */
    status = CRYPTO_INTERFACE_TAP_deserializeSymKey(&pSymWrapper, pSerKey, serLen, (void *) pAesTapArgs);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    /* Transfer control of the SymmetricKey underlying data into a usable AES context.
     * The SymmetricKey is now just a wrapper that still needs to be freed. */
    status = CRYPTO_INTERFACE_TAP_getAesCtrCtxFromSymmetricKeyAlloc (
        pSymWrapper, &pCtx, pIv);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_AesCtrDeferKeyUnload(pCtx, TRUE);
        retVal += UNITTEST_STATUS(keySize, status);
        if (OK != status)
            goto exit;
    }

    status = CRYPTO_INTERFACE_DoAESCTR (MOC_SYM(gpHwAccelCtx) pCtx, pPlain, 32, 0, NULL);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_DoAESCTR (MOC_SYM(gpHwAccelCtx) pCtx, pPlain + 32, 16, 0, NULL);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_DoAESCTR (MOC_SYM(gpHwAccelCtx) pCtx, pPlain + 48, 16, 0, NULL);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pPlain, pPlainCopy, sizeof(pPlain), &compare);
    retVal += UNITTEST_STATUS(keySize, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(keySize, compare, 0);

exit:

    status = CRYPTO_INTERFACE_DeleteAESCTRCtx(MOC_SYM(gpHwAccelCtx) &pCtx);
    retVal += UNITTEST_STATUS(keySize, status);

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

int crypto_interface_aes_ctr_test_init()
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

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_CTR__))
    errorCount = (errorCount + testCryptoInterface(pSingleBlockTests[0]));
#endif

    errorCount = (errorCount + runTests());
    errorCount = (errorCount + negativeTest());

#ifdef __ENABLE_DIGICERT_IPSEC_SERVICE__
    errorCount += runIpSecServiceTest();
#endif

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TPM2__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
    status = TAP_EXAMPLE_init(&modNum, 1);
    if (OK != status)
    {
        errorCount += 1;
        goto exit;
    }

    errorCount = (errorCount + tapTest(128, FALSE));
    errorCount = (errorCount + tapTest(192, FALSE));
    errorCount = (errorCount + tapTest(256, FALSE));

    errorCount = (errorCount + tapTest(128, TRUE));
    errorCount = (errorCount + tapTest(192, TRUE));
    errorCount = (errorCount + tapTest(256, TRUE));

    errorCount += tapKAT(128, 1);
    errorCount += tapKAT(192, 15);
    errorCount += tapKAT(256, 16);

    errorCount += tapKAT(128, 16);
    errorCount += tapKAT(192, 17);
    errorCount += tapKAT(256, 32);

    errorCount += tapKAT(128, 99);

#endif

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
