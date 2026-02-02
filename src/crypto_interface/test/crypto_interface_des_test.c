/*
 * crypto_interface_des_test.c
 *
 * test file for DES
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
#include "../../crypto/des.h"

#ifdef __ENABLE_DES_CIPHER__

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

#define TEST_TEXT_STRING       32
#define TEST_BLOCK_SIZE         8
#define TEST_KEY_SIZE           8

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../../crypto_interface/crypto_interface_des.h"

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TPM2__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
#include "crypto_interface_tap_example.h"
#include "../../crypto/mocsymalgs/tap/symtap.h"
#include "../../crypto_interface/cryptointerface.h"
#include "../../crypto_interface/crypto_interface_sym_tap.h"
#include "../../crypto_interface/crypto_interface_des_tap.h"
#endif
#endif

/*
 * Plain text and cipher text buffers are
 * the size of the largest test passed
 */
typedef struct
{
    ubyte           key[TEST_TEXT_STRING];
    ubyte           iv[TEST_BLOCK_SIZE];
    ubyte           text[TEST_TEXT_STRING];

    /* for test verification */
    ubyte           encrypt[TEST_TEXT_STRING];
    ubyte           final_iv[TEST_BLOCK_SIZE];

} DesCbcTestVector;


typedef struct
{
    ubyte           key[TEST_KEY_SIZE];
    ubyte           text[TEST_TEXT_STRING];
    ubyte           encrypt[TEST_TEXT_STRING];
    ubyte4          textLen;

} DesEcbTestVector;


/*------------------------------------------------------------------*/

DesCbcTestVector desCbcTestVectors56[] =
{
    { "00112233001122330011223300112233", "00112233", "The eagle flies at midnight.1234", "\x46\x4a\x34\x79\xd5\xaf\x08\x1d\xe2\x88\x25\xcc\x84\x45\xba\x66\xb0\xd6\x40\x91\xeb\xa6\xd2\x48\x7f\x4b\x84\x98\xa2\x89\x88\xa1", "\x7f\x4b\x84\x98\xa2\x89\x88\xa1" },
    { "ss1d33001122330011223300112233dd", "aa11223d", "One test to rule them. Muwhaaaaa", "\x5c\x7f\x5f\x2f\xef\x23\x26\x8b\x96\xf8\x37\x37\x1c\xbc\x02\x10\xc8\x7a\x81\x3a\x2c\xbe\x3e\x1a\x6f\x42\x28\x48\x8e\xe6\x23\x6b", "\x6f\x42\x28\x48\x8e\xe6\x23\x6b" },
    { "01122330011223300112233001122330", "bb112233", "They dance at dawn from the West", "\xee\x2c\xcb\xe3\x24\x0b\x42\x09\x76\x25\x22\x73\x2c\xbb\xdd\x44\xe1\x89\x70\xf8\xe0\x04\xbe\xf3\xec\xc0\xfd\x9d\xca\x42\x15\xcb", "\xec\xc0\xfd\x9d\xca\x42\x15\xcb" },
    { "zzz12233001122xxx01122330011qqq3", "0ccc2233", "One last hillarious test vector!", "\xaf\x27\xd0\x3a\xb1\x2c\xec\xec\xb0\x2e\x87\x77\x26\x32\x7b\x93\x71\x18\xc1\x9d\x8c\xd7\xab\x30\x2f\x12\x8d\xf4\xbe\x7c\x0c\xe8", "\x2f\x12\x8d\xf4\xbe\x7c\x0c\xe8" }
};

DesEcbTestVector desEcbTestVectors[] =
{
    {
        {
            0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01
        },
        {
            0x95,0xF8,0xA5,0xE5,0xDD,0x31,0xD9,0x00
        },
        {
            0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        },
        8
    },
    {
        {
            0x80,0x01,0x01,0x01,0x01,0x01,0x01,0x01
        },
        {
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        },
        {
            0x95,0xA8,0xD7,0x28,0x13,0xDA,0xA9,0x4D
        },
        8
    },
    {
        {
            0x01,0x31,0xD9,0x61,0x9D,0xC1,0x37,0x6E
        },
        {
            0x5C,0xD5,0x4C,0xA8,0x3D,0xEF,0x57,0xDA
        },
        {
            0x7A,0x38,0x9D,0x10,0x35,0x4B,0xD2,0x71
        },
        8
    },
    {
        {
            0x7C,0xA1,0x10,0x45,0x4A,0x1A,0x6E,0x57
        },
        {
            0x01,0xA1,0xD6,0xD0,0x39,0x77,0x67,0x42
        },
        {
            0x69,0x0F,0x5B,0x0D,0x9A,0x26,0x93,0x9B
        },
        8
    },
    {
        {
            0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01
        },
        {
            0x95,0xF8,0xA5,0xE5,0xDD,0x31,0xD9,0x00,0xDD,0x7F,0x12,0x1C,0xA5,0x01,0x56,0x19,
            0x2E,0x86,0x53,0x10,0x4F,0x38,0x34,0xEA,0x4B,0xD3,0x88,0xFF,0x6C,0xD8,0x1D,0x4F
        },
        {
            0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        },
        32
    }
};


/*------------------------------------------------------------------*/

static int generic_des_cbc_test(DesCbcTestVector *pDesCbcTestVector, int updateMode)
{
    ubyte4          retVal = 0;
    BulkCtx         ctx;
    sbyte4          cmpResult;
    MSTATUS         status;

    ubyte pText[TEST_TEXT_STRING];
    ubyte pIv[TEST_BLOCK_SIZE];

    /* make a mutable copy of the text and iv */
    if (OK > (status = DIGI_MEMCPY(pText, pDesCbcTestVector->text, TEST_TEXT_STRING)))
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (OK > (status = DIGI_MEMCPY(pIv, pDesCbcTestVector->iv, TEST_BLOCK_SIZE)))
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* encrypt test */
    if (NULL == (ctx = CreateDESCtx(MOC_SYM(gpHwAccelCtx) pDesCbcTestVector->key, TEST_KEY_SIZE, TRUE)))
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
        goto exit;
    }

    if (updateMode)
    {
        /* Our operator allows for non-block size buffering but our high level API DoDES inplace and doesn't */
        if (OK > (status = DoDES(MOC_SYM(gpHwAccelCtx) ctx, pText, 8, TRUE, pIv)))
        {
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }

        if (OK > (status = DoDES(MOC_SYM(gpHwAccelCtx) ctx, pText + 8, 16, TRUE, pIv)))
        {
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }

        if (OK > (status = DoDES(MOC_SYM(gpHwAccelCtx) ctx, pText + 24, 8, TRUE, pIv)))
        {
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }

    }
    else
    {
        if (OK > (status = DoDES(MOC_SYM(gpHwAccelCtx) ctx, pText, TEST_TEXT_STRING, TRUE, pIv)))
        {
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }

    if (OK > (status = DeleteDESCtx(MOC_SYM(gpHwAccelCtx) &ctx)))
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* verify encryption */
    if (OK > (status = DIGI_MEMCMP(pText, (ubyte *)(pDesCbcTestVector->encrypt), TEST_TEXT_STRING, &cmpResult)))
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (0 != cmpResult)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
        goto exit;
    }

#if !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_DES__) || !defined(__ENABLE_DIGICERT_DES_MBED__)

    /* test that the final iv is correct */
    if (OK > (status = DIGI_MEMCMP(pIv, pDesCbcTestVector->final_iv, TEST_BLOCK_SIZE, &cmpResult)))
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (0 != cmpResult)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
        goto exit;
    }

#endif

    /* decrypt test */
    if (NULL == (ctx = CreateDESCtx(MOC_SYM(gpHwAccelCtx) pDesCbcTestVector->key, TEST_KEY_SIZE, FALSE)))
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
        goto exit;
    }

    if (OK > (status = DIGI_MEMCPY(pIv, pDesCbcTestVector->iv, TEST_BLOCK_SIZE)))
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (updateMode)
    {
        /* Our operator allows for non-block size buffering but our high level API is inplace and doesn't */
        if (OK > (status = DoDES(MOC_SYM(gpHwAccelCtx) ctx, pText, 8, FALSE, pIv)))
        {
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }

        if (OK > (status = DoDES(MOC_SYM(gpHwAccelCtx) ctx, pText + 8, 16, FALSE, pIv)))
        {
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }

        if (OK > (status = DoDES(MOC_SYM(gpHwAccelCtx) ctx, pText + 24, 8, FALSE, pIv)))
        {
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }
    else
    {
        if (OK > (status = DoDES(MOC_SYM(gpHwAccelCtx) ctx, pText, TEST_TEXT_STRING, FALSE, pIv)))
        {
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }

    if (OK > (status = DeleteDESCtx(MOC_SYM(gpHwAccelCtx) &ctx)))
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* verify decryption */
    if (OK > (status = DIGI_MEMCMP(pText, (ubyte *)(pDesCbcTestVector->text), TEST_TEXT_STRING, &cmpResult)))
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (0 != cmpResult)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
        goto exit;
    }

exit:

    if (NULL != ctx)
        DeleteDESCtx(MOC_SYM(gpHwAccelCtx) &ctx); /* here on error only, ignore return */

    return retVal;
}

/*------------------------------------------------------------------*/

static int generic_des_cbc_clone_test(DesCbcTestVector *pDesCbcTestVector, int updateMode)
{
    ubyte4          retVal = 0;
    BulkCtx         ctx = NULL;
    BulkCtx         cloneCtx = NULL;
    sbyte4          cmpResult;
    MSTATUS         status;

    ubyte pText[TEST_TEXT_STRING];
    ubyte pIv[TEST_BLOCK_SIZE];

    /* make a mutable copy of the text and iv */
    if (OK > (status = DIGI_MEMCPY(pText, pDesCbcTestVector->text, TEST_TEXT_STRING)))
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (OK > (status = DIGI_MEMCPY(pIv, pDesCbcTestVector->iv, TEST_BLOCK_SIZE)))
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* encrypt test */
    if (NULL == (ctx = CreateDESCtx(MOC_SYM(gpHwAccelCtx) pDesCbcTestVector->key, TEST_KEY_SIZE, TRUE)))
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
        goto exit;
    }

    if (updateMode)
    {
        /* Our operator allows for non-block size buffering but our high level API DoDES inplace and doesn't */
        if (OK > (status = DoDES(MOC_SYM(gpHwAccelCtx) ctx, pText, 8, TRUE, pIv)))
        {
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }

        if (OK > (status = CloneDESCtx(MOC_SYM(gpHwAccelCtx) ctx, &cloneCtx)))
        {
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }

        if (OK > (status = DeleteDESCtx(MOC_SYM(gpHwAccelCtx) &ctx)))
        {
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }

        if (OK > (status = DoDES(MOC_SYM(gpHwAccelCtx) cloneCtx, pText + 8, 16, TRUE, pIv)))
        {
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }

        if (OK > (status = DoDES(MOC_SYM(gpHwAccelCtx) cloneCtx, pText + 24, 8, TRUE, pIv)))
        {
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }

    }
    else
    {
        if (OK > (status = CloneDESCtx(MOC_SYM(gpHwAccelCtx) ctx, &cloneCtx)))
        {
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }

        if (OK > (status = DeleteDESCtx(MOC_SYM(gpHwAccelCtx) &ctx)))
        {
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }

        if (OK > (status = DoDES(MOC_SYM(gpHwAccelCtx) cloneCtx, pText, TEST_TEXT_STRING, TRUE, pIv)))
        {
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }

    if (OK > (status = DeleteDESCtx(MOC_SYM(gpHwAccelCtx) &cloneCtx)))
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* verify encryption */
    if (OK > (status = DIGI_MEMCMP(pText, (ubyte *)(pDesCbcTestVector->encrypt), TEST_TEXT_STRING, &cmpResult)))
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (0 != cmpResult)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
        goto exit;
    }

#if !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_DES__) || !defined(__ENABLE_DIGICERT_DES_MBED__)

    /* test that the final iv is correct */
    if (OK > (status = DIGI_MEMCMP(pIv, pDesCbcTestVector->final_iv, TEST_BLOCK_SIZE, &cmpResult)))
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (0 != cmpResult)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
        goto exit;
    }

#endif

    /* decrypt test */
    if (NULL == (ctx = CreateDESCtx(MOC_SYM(gpHwAccelCtx) pDesCbcTestVector->key, TEST_KEY_SIZE, FALSE)))
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
        goto exit;
    }

    if (OK > (status = DIGI_MEMCPY(pIv, pDesCbcTestVector->iv, TEST_BLOCK_SIZE)))
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (updateMode)
    {
        /* Our operator allows for non-block size buffering but our high level API is inplace and doesn't */
        if (OK > (status = DoDES(MOC_SYM(gpHwAccelCtx) ctx, pText, 8, FALSE, pIv)))
        {
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }

        if (OK > (status = CloneDESCtx(MOC_SYM(gpHwAccelCtx) ctx, &cloneCtx)))
        {
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }

        if (OK > (status = DeleteDESCtx(MOC_SYM(gpHwAccelCtx) &ctx)))
        {
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }

        if (OK > (status = DoDES(MOC_SYM(gpHwAccelCtx) cloneCtx, pText + 8, 16, FALSE, pIv)))
        {
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }

        if (OK > (status = DoDES(MOC_SYM(gpHwAccelCtx) cloneCtx, pText + 24, 8, FALSE, pIv)))
        {
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }
    else
    {
        if (OK > (status = CloneDESCtx(MOC_SYM(gpHwAccelCtx) ctx, &cloneCtx)))
        {
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }

        if (OK > (status = DeleteDESCtx(MOC_SYM(gpHwAccelCtx) &ctx)))
        {
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }

        if (OK > (status = DoDES(MOC_SYM(gpHwAccelCtx) cloneCtx, pText, TEST_TEXT_STRING, FALSE, pIv)))
        {
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }

    if (OK > (status = DeleteDESCtx(MOC_SYM(gpHwAccelCtx) &cloneCtx)))
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* verify decryption */
    if (OK > (status = DIGI_MEMCMP(pText, (ubyte *)(pDesCbcTestVector->text), TEST_TEXT_STRING, &cmpResult)))
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (0 != cmpResult)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
        goto exit;
    }

exit:

    if (NULL != ctx)
        DeleteDESCtx(MOC_SYM(gpHwAccelCtx) &ctx); /* here on error only, ignore return */

    if (NULL != cloneCtx)
        DeleteDESCtx(MOC_SYM(gpHwAccelCtx) &cloneCtx); /* here on error only, ignore return */

    return retVal;
}

/*------------------------------------------------------------------*/

static int generic_des_ecb_test(DesEcbTestVector *pDesEcbTestVector)
{
    ubyte4          retVal = 0;
    DES_CTX         ctx = {0};
    sbyte4          cmpResult;
    MSTATUS         status;

    ubyte pResult[TEST_TEXT_STRING];


    /* encrypt test */
    if (OK > (status = DES_initKey(&ctx, pDesEcbTestVector->key, TEST_KEY_SIZE)))
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (OK > (status = DES_encipher(&ctx, pDesEcbTestVector->text, pResult, pDesEcbTestVector->textLen)))
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (OK > (status = DES_clearKey(&ctx)))
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* verify encryption */
    if (OK > (status = DIGI_MEMCMP(pResult, (ubyte *)(pDesEcbTestVector->encrypt), pDesEcbTestVector->textLen, &cmpResult)))
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (0 != cmpResult)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
        goto exit;
    }

    /* decrypt test */
    if (OK > (status = DES_initKey(&ctx, pDesEcbTestVector->key, TEST_KEY_SIZE)))
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (OK > (status = DES_decipher(&ctx, pDesEcbTestVector->encrypt, pResult, pDesEcbTestVector->textLen)))
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (OK > (status = DES_clearKey(&ctx)))
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* verify decryption */
    if (OK > (status = DIGI_MEMCMP(pResult, (ubyte *)(pDesEcbTestVector->text), pDesEcbTestVector->textLen, &cmpResult)))
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (0 != cmpResult)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
        goto exit;
    }

exit:

    /* clear key here too in case of error, ok to ignore return code */
    DES_clearKey(&ctx);

    return retVal;
}

/*----------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TPM2__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
/* known answer test by comparing TAP (Hw) results with Sw results */
static int tapKATCbc(byteBoolean isEnc)
{
    int retVal = 0;
    MSTATUS status = 0;
    sbyte4 compare = -1;
    sbyte4 retLen = 0;
    int i;

    BulkCtx pCtxHw = NULL;
    BulkCtx pCtxSw = NULL;

    SymmetricKey *pSymWrapper = NULL;

    ubyte pInput[64];
    ubyte pInputCopy[64];
    ubyte pIv[8] = {0xff, 0xee, 0xee, 0xdd, 0xaa, 0xbb, 0xcc, 0xdd};

    MSymTapKeyGenArgs aesTapArgs = {0};
    void *pAesTapArgs = (void *) &aesTapArgs;

    TAP_KeyInfo keyInfo = {0};
    MSymTapCreateArgs createArgs = {0};
    ubyte pKey[8] = {0}; 

    aesTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    aesTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    aesTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);
    aesTapArgs.keyAlgorithm = TAP_KEY_ALGORITHM_DES;

    /* make a pseduo random looking plaintext of 8 blocks */
    for (i = 0; i < sizeof(pInput); ++i)
    {
        pInput[i] = pInputCopy[i] = (ubyte) ((17 * (i + 1)) & 0xff);
    }

    for (i = 0; i < 8; ++i)
    {
        pKey[i] = (ubyte) (i+1);
    }

    keyInfo.keyAlgorithm = TAP_KEY_ALGORITHM_DES;
    keyInfo.keyUsage = TAP_KEY_USAGE_DECRYPT;
    keyInfo.algKeyInfo.desInfo.symMode = TAP_SYM_KEY_MODE_UNDEFINED;
    createArgs.pKeyInfo = &keyInfo;
    createArgs.pKeyData = (ubyte *)pKey;
    createArgs.keyDataLen = 8;
    createArgs.token = FALSE;

    status = CRYPTO_INTERFACE_TAP_SymImportExternalKey(&pSymWrapper, pAesTapArgs, (void *)&createArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_TAP_getDesCbcCtxFromSymmetricKeyAlloc (
        pSymWrapper, &pCtxHw, isEnc ? MOCANA_SYM_TAP_ENCRYPT : MOCANA_SYM_TAP_DECRYPT);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    pCtxSw = CRYPTO_INTERFACE_CreateDESCtx (MOC_SYM(gpHwAccelCtx) pKey, 8, isEnc ? 1 : 0);
    if (NULL == pCtxSw)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
        goto exit;
    }

    status = CRYPTO_INTERFACE_DoDES (MOC_SYM(gpHwAccelCtx) pCtxHw, pInput, 8, isEnc ? 1 : 0, pIv);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_DoDES (MOC_SYM(gpHwAccelCtx) pCtxHw, pInput + 8, 16, isEnc ? 1 : 0, pIv);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_DoDES (MOC_SYM(gpHwAccelCtx) pCtxHw, pInput + 24, 40, isEnc ? 1 : 0, pIv);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_DoDES (MOC_SYM(gpHwAccelCtx) pCtxSw, pInputCopy, 16, isEnc ? 1 : 0, pIv);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_DoDES (MOC_SYM(gpHwAccelCtx) pCtxSw, pInputCopy + 16, 40, isEnc ? 1 : 0, pIv);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_DoDES (MOC_SYM(gpHwAccelCtx) pCtxSw, pInputCopy + 56, 8, isEnc ? 1 : 0, pIv);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pInput, pInputCopy, 64, &compare);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, compare, 0);

exit:

    if (NULL != pCtxSw)
    {
        (void) CRYPTO_INTERFACE_DeleteDESCtx (MOC_SYM(gpHwAccelCtx) &pCtxSw);
    }
    if (NULL != pCtxHw)
    {
        (void) CRYPTO_INTERFACE_DeleteDESCtx (MOC_SYM(gpHwAccelCtx) &pCtxHw);
    }

    if (NULL != pSymWrapper)
    {
        (void) CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    }

    return retVal;
}

static int tapKATEcb(byteBoolean isEnc)
{
    int retVal = 0;
    MSTATUS status = 0;
    sbyte4 compare = -1;
    sbyte4 retLen = 0;
    int i;

    DES_CTX ctxHw = {0};
    DES_CTX ctxSw = {0};

    SymmetricKey *pSymWrapper = NULL;

    ubyte pInput[64];
    ubyte pOutputHw[64];
    ubyte pOutputSw[64];

    MSymTapKeyGenArgs aesTapArgs = {0};
    void *pAesTapArgs = (void *) &aesTapArgs;

    TAP_KeyInfo keyInfo = {0};
    MSymTapCreateArgs createArgs = {0};
    ubyte pKey[8] = {0}; 

    aesTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    aesTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    aesTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);
    aesTapArgs.keyAlgorithm = TAP_KEY_ALGORITHM_DES;

    /* make a pseduo random looking plaintext of 8 blocks */
    for (i = 0; i < sizeof(pInput); ++i)
    {
        pInput[i] = (ubyte) ((17 * (i + 1)) & 0xff);
    }

    for (i = 0; i < 8; ++i)
    {
        pKey[i] = (ubyte) (i+1);
    }

    keyInfo.keyAlgorithm = TAP_KEY_ALGORITHM_DES;
    keyInfo.keyUsage = TAP_KEY_USAGE_DECRYPT;
    keyInfo.algKeyInfo.desInfo.symMode = TAP_SYM_KEY_MODE_UNDEFINED;
    createArgs.pKeyInfo = &keyInfo;
    createArgs.pKeyData = (ubyte *)pKey;
    createArgs.keyDataLen = 8;
    createArgs.token = FALSE;

    status = CRYPTO_INTERFACE_TAP_SymImportExternalKey(&pSymWrapper, pAesTapArgs, (void *)&createArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_TAP_initDesEcbCtxFromSymmetricKey (
        pSymWrapper, &ctxHw);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_DES_initKey(&ctxSw, pKey, 8);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (isEnc)
    {
        status = CRYPTO_INTERFACE_DES_encipher (&ctxHw, pInput, pOutputHw, 64); 
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_DES_encipher (&ctxSw, pInput, pOutputSw, 64); 
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = CRYPTO_INTERFACE_DES_decipher (&ctxHw, pInput, pOutputHw, 64); 
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_DES_decipher (&ctxSw, pInput, pOutputSw, 64); 
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }

    status = DIGI_MEMCMP(pOutputSw, pOutputHw, 64, &compare);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, compare, 0);

exit:

    status = CRYPTO_INTERFACE_DES_clearKey (MOC_SYM(gpHwAccelCtx) &ctxSw);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

    status = CRYPTO_INTERFACE_DES_clearKey (MOC_SYM(gpHwAccelCtx) &ctxHw);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

    if (NULL != pSymWrapper)
    {
        (void) CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    }

    return retVal;
}

static int tapTestCbc(intBoolean testDeferredUnload)
{
    int retVal = 0;
    MSTATUS status = 0;
    sbyte4 compare = -1;
    int i;

    BulkCtx pCtx = NULL;
    ubyte *pSerKey = NULL;
    ubyte4 serLen = 0;
    SymmetricKey *pSymWrapper = NULL;

    ubyte pIv[8] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
    ubyte pIvCopy[8] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
    ubyte pPlain[64];
    ubyte pData[64];

    MSymTapKeyGenArgs tapArgs = {0};
    void *pTapArgs = (void *) &tapArgs;

    TAP_KeyHandle keyHandle = 0;
    TAP_TokenHandle tokenHandle = 0;

    tapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    tapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    tapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);
    tapArgs.keyAlgorithm = TAP_KEY_ALGORITHM_DES;

    /* make a pseduo random looking plaintext of 4 blocks */
    for (i = 0; i < sizeof(pPlain); ++i)
    {
        pPlain[i] = (ubyte) ((17 * (i + 1)) & 0xff);
    }

    /* Make a copy so we can test the recovered plaintext */
    status = DIGI_MEMCPY(pData, pPlain, sizeof(pPlain));
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_TAP_GenerateSymKey(&pSymWrapper, 8 * 8 /* in bits */, pTapArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* serialize the key while we still have it as a SymmetricKey */
    status = CRYPTO_INTERFACE_TAP_serializeSymKey(pSymWrapper, &pSerKey, &serLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Transfer control of the SymmetricKey underlying data into a usable TDES context.
     * The SymmetricKey is now just a wrapper that still needs to be freed. */
    status = CRYPTO_INTERFACE_TAP_getDesCbcCtxFromSymmetricKeyAlloc (pSymWrapper, &pCtx, TRUE);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_DesDeferKeyUnload(pCtx, TRUE);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }

    status = CRYPTO_INTERFACE_DoDES (MOC_SYM(gpHwAccelCtx) pCtx, pData, 8, TRUE, pIv);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;   

    status = CRYPTO_INTERFACE_DoDES (MOC_SYM(gpHwAccelCtx) pCtx, pData + 8, 16, TRUE, pIv);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_DoDES (MOC_SYM(gpHwAccelCtx) pCtx, pData + 24, 40, TRUE, pIv);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;   

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_DesGetKeyInfo (pCtx, &tokenHandle, &keyHandle);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }

    status = CRYPTO_INTERFACE_DeleteDESCtx(MOC_SYM(gpHwAccelCtx) &pCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Free the SymmetricKey wrapper */
    status = CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* deserialize into a SymmetricKey wrapper */
    status = CRYPTO_INTERFACE_TAP_deserializeSymKey(&pSymWrapper, pSerKey, serLen, (void *) pTapArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_SymKeyDeferUnload(pSymWrapper, TRUE);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }

    /* Transfer control of the SymmetricKey underlying data into a usable TDES context.
     * The SymmetricKey is now just a wrapper that still needs to be freed. */
    status = CRYPTO_INTERFACE_TAP_getDesCbcCtxFromSymmetricKeyAlloc (pSymWrapper, &pCtx, FALSE);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_DoDES (MOC_SYM(gpHwAccelCtx) pCtx, pData, 48, FALSE, pIvCopy);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;   

    status = CRYPTO_INTERFACE_DoDES (MOC_SYM(gpHwAccelCtx) pCtx, pData + 48, 16, FALSE, pIvCopy);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pData, pPlain, sizeof(pPlain), &compare);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, compare, 0);

exit:

    if (NULL != pCtx)
    {
        status = CRYPTO_INTERFACE_DeleteDESCtx(MOC_SYM(gpHwAccelCtx) &pCtx);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    if (NULL != pSymWrapper)
    {
        status = CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    if (NULL != pSerKey)
    {
        (void) DIGI_FREE((void **) &pSerKey);
    }

    return retVal;
}

static int tapTestEcb(intBoolean testDeferredUnload)
{
    int retVal = 0;
    MSTATUS status = 0;
    sbyte4 compare = -1;
    int i;

    DES_CTX ctx = {0};
    ubyte *pSerKey = NULL;
    ubyte4 serLen = 0;
    SymmetricKey *pSymWrapper = NULL;

    ubyte pPlain[64];
    ubyte pCipher[64] = {0};
    ubyte pRecPlain[64] = {0};

    MSymTapKeyGenArgs tapArgs = {0};
    void *pTapArgs = (void *) &tapArgs;

    TAP_KeyHandle keyHandle = 0;
    TAP_TokenHandle tokenHandle = 0;

    tapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    tapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    tapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);
    tapArgs.keyAlgorithm = TAP_KEY_ALGORITHM_DES;

    /* make a pseduo random looking plaintext of 4 blocks */
    for (i = 0; i < sizeof(pPlain); ++i)
    {
        pPlain[i] = (ubyte) ((17 * (i + 1)) & 0xff);
    }

    status = CRYPTO_INTERFACE_TAP_GenerateSymKey(&pSymWrapper, 8 * 8 /* in bits */, pTapArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* serialize the key while we still have it as a SymmetricKey */
    status = CRYPTO_INTERFACE_TAP_serializeSymKey(pSymWrapper, &pSerKey, &serLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Transfer control of the SymmetricKey underlying data into a usable TDES context.
     * The SymmetricKey is now just a wrapper that still needs to be freed. */
    status = CRYPTO_INTERFACE_TAP_initDesEcbCtxFromSymmetricKey (pSymWrapper, &ctx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_DesDeferKeyUnload(&ctx, TRUE);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }

    status = CRYPTO_INTERFACE_DES_encipher(&ctx, pPlain, pCipher, 8);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_DES_encipher(&ctx, pPlain + 8, pCipher + 8, 16);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_DES_encipher(&ctx, pPlain + 24, pCipher + 24, 40);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_DesGetKeyInfo (&ctx, &tokenHandle, &keyHandle);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }

    /* clear the context */
    status = CRYPTO_INTERFACE_DES_clearKey (&ctx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Free the SymmetricKey wrapper */
    status = CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* deserialize into a SymmetricKey wrapper */
    status = CRYPTO_INTERFACE_TAP_deserializeSymKey(&pSymWrapper, pSerKey, serLen, (void *) pTapArgs);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Transfer control of the SymmetricKey underlying data into a usable TDES context.
     * The SymmetricKey is now just a wrapper that still needs to be freed. */
    status = CRYPTO_INTERFACE_TAP_initDesEcbCtxFromSymmetricKey (pSymWrapper, &ctx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_DesDeferKeyUnload(&ctx, TRUE);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }

    status = CRYPTO_INTERFACE_DES_decipher(&ctx, pCipher, pRecPlain, 48);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_DES_decipher(&ctx, pCipher + 48, pRecPlain + 48, 16);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
 
    status = DIGI_MEMCMP(pRecPlain, pPlain, sizeof(pPlain), &compare);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = UNITTEST_INT(__MOC_LINE__, compare, 0);

exit:

    status = CRYPTO_INTERFACE_DES_clearKey(&ctx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

    if (NULL != pSymWrapper)
    {
        status = CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymWrapper);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    if (NULL != pSerKey)
    {
        (void) DIGI_FREE((void **) &pSerKey);
    }

    if (0 != keyHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapKey(TAP_EXAMPLE_getTapContext(1), tokenHandle, keyHandle);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    if (0 != tokenHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapToken(TAP_EXAMPLE_getTapContext(1), tokenHandle);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}
#endif /* __ENABLE_DIGICERT_TAP__ */
#endif /* __ENABLE_DES_CIPHER__ */

/*------------------------------------------------------------------*/

int crypto_interface_des_test_init()
{
    int errorCount = 0;

#ifdef __ENABLE_DES_CIPHER__

    MSTATUS status = ERR_NULL_POINTER;
    int i;
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

    for (i = 0; i < sizeof(desCbcTestVectors56)/sizeof(DesCbcTestVector); ++i)
    {
        errorCount += generic_des_cbc_test(&desCbcTestVectors56[i], 0);
        errorCount += generic_des_cbc_test(&desCbcTestVectors56[i], 1);
        errorCount += generic_des_cbc_clone_test(&desCbcTestVectors56[i], 0);
        errorCount += generic_des_cbc_clone_test(&desCbcTestVectors56[i], 1);
    }

    for (i = 0; i < sizeof(desEcbTestVectors)/sizeof(DesEcbTestVector); ++i)
    {
        errorCount += generic_des_ecb_test(&desEcbTestVectors[i]);
    }

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TPM2__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
    status = TAP_EXAMPLE_init(&modNum, 1);
    if (OK != status)
    {
        errorCount += 1;
        goto exit;
    }

    errorCount = (errorCount + tapTestCbc(FALSE));
    errorCount = (errorCount + tapTestEcb(FALSE));
    
    errorCount = (errorCount + tapTestCbc(TRUE));
    errorCount = (errorCount + tapTestEcb(TRUE));

    errorCount += tapKATCbc(TRUE);
    errorCount += tapKATCbc(FALSE);

    errorCount += tapKATEcb(TRUE);
    errorCount += tapKATEcb(FALSE);

#endif /* __ENABLE_DIGICERT_TAP__ */

exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

#if defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TPM2__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
    TAP_EXAMPLE_clean();
#endif

    DIGICERT_free(&gpMocCtx);

#endif
    return errorCount;
}

