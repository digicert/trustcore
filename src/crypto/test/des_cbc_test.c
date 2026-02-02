/*
 * des_cbc_test.c
 *
 * unit test for des.c
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
#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"

#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../common/debug_console.h"
#include "../../crypto/des.h"
#include "../../harness/harness.h"
#include "../../../unit_tests/unittest.h"


/*------------------------------------------------------------------*/

//#define __ENABLE_DES_CBC_TEST_DEBUG__

#if (defined(__ENABLE_DES_CBC_TEST_DEBUG__))
#include <stdio.h>
#endif


/*------------------------------------------------------------------*/

#define MAX_DES_TEXT_STRING     128
#define TEST_BLOCK_SIZE         8


/*------------------------------------------------------------------*/

typedef struct TestDescr
{
    ubyte           key[32];
    ubyte           iv[TEST_BLOCK_SIZE];
    ubyte           text[32];

    /* for test verification */
    ubyte           encrypt[32];
    ubyte           final_iv[TEST_BLOCK_SIZE];

} TestDescr;


/*------------------------------------------------------------------*/

TestDescr desCbcTestVectors56[] = 
{
    { "00112233001122330011223300112233", "00112233", "The eagle flies at midnight.1234", "\x46\x4a\x34\x79\xd5\xaf\x08\x1d\xe2\x88\x25\xcc\x84\x45\xba\x66\xb0\xd6\x40\x91\xeb\xa6\xd2\x48\x7f\x4b\x84\x98\xa2\x89\x88\xa1", "\x7f\x4b\x84\x98\xa2\x89\x88\xa1" },
    { "ss1d33001122330011223300112233dd", "aa11223d", "One test to rule them. Muwhaaaaa", "\x5c\x7f\x5f\x2f\xef\x23\x26\x8b\x96\xf8\x37\x37\x1c\xbc\x02\x10\xc8\x7a\x81\x3a\x2c\xbe\x3e\x1a\x6f\x42\x28\x48\x8e\xe6\x23\x6b", "\x6f\x42\x28\x48\x8e\xe6\x23\x6b" },
    { "01122330011223300112233001122330", "bb112233", "They dance at dawn from the West", "\xee\x2c\xcb\xe3\x24\x0b\x42\x09\x76\x25\x22\x73\x2c\xbb\xdd\x44\xe1\x89\x70\xf8\xe0\x04\xbe\xf3\xec\xc0\xfd\x9d\xca\x42\x15\xcb", "\xec\xc0\xfd\x9d\xca\x42\x15\xcb" },
    { "zzz12233001122xxx01122330011qqq3", "0ccc2233", "One last hillarious test vector!", "\xaf\x27\xd0\x3a\xb1\x2c\xec\xec\xb0\x2e\x87\x77\x26\x32\x7b\x93\x71\x18\xc1\x9d\x8c\xd7\xab\x30\x2f\x12\x8d\xf4\xbe\x7c\x0c\xe8", "\x2f\x12\x8d\xf4\xbe\x7c\x0c\xe8" }
};


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DES_CBC_TEST_DEBUG__))
static void
dumpHex(char *pMesg, ubyte *pData, ubyte4 length)
{
    ubyte4 index;

    printf("%s[length = %u] =\n", pMesg, length);

    for (index = 0; index < length; index++)
        printf("\\x%02x", pData[index]);

    printf("\n");
}
#endif


/*------------------------------------------------------------------*/

static int
generic_des_cbc_test(TestDescr desCbcTestVectors[], sbyte4 numVectors, sbyte4 keySize)
{
    ubyte4          retVal = 1;
    BulkCtx         ctx;
    sbyte4          i, cmpResult;
    ubyte*          pKey  = NULL;
    ubyte*          pIvEncrypt = NULL;
    ubyte*          pIvDecrypt = NULL;
    ubyte*          pText = NULL;
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    /* for harness test... */
    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, 32, TRUE, &pKey)))
        goto exit;

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, TEST_BLOCK_SIZE, TRUE, &pIvEncrypt)))
        goto exit;

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, TEST_BLOCK_SIZE, TRUE, &pIvDecrypt)))
        goto exit;

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, MAX_DES_TEXT_STRING, TRUE, &pText)))
        goto exit;

    retVal = 0;

    for (i = 0; i < numVectors; ++i)
    {
        /* clone data for test */
        DIGI_MEMCPY(pKey,       (ubyte *)(desCbcTestVectors[i].key), keySize);
        DIGI_MEMCPY(pIvEncrypt, (ubyte *)(desCbcTestVectors[i].iv), TEST_BLOCK_SIZE);
        DIGI_MEMCPY(pIvDecrypt, (ubyte *)(desCbcTestVectors[i].iv), TEST_BLOCK_SIZE);
        DIGI_MEMCPY(pText,      (ubyte *)(desCbcTestVectors[i].text), 32);

#if (defined(__ENABLE_DES_CBC_TEST_DEBUG__))
        printf("{\n");
        dumpHex("plain text", pText, 32);
        printf("======\n");
#endif

        /* encrypt test */
        if (NULL == (ctx = CreateDESCtx(MOC_SYM(hwAccelCtx) pKey, keySize, TRUE)))
        {
            retVal++;
            continue;
        }

        if (OK > (status = DoDES(MOC_SYM(hwAccelCtx) ctx, pText, 32, TRUE, pIvEncrypt)))
        {
            retVal++;
            continue;
        }

        if (OK > (status = DeleteDESCtx(MOC_SYM(hwAccelCtx) &ctx)))
        {
            retVal++;
            continue;
        }

#if (defined(__ENABLE_DES_CBC_TEST_DEBUG__))
        dumpHex("encrypted text", pText, 32);
        dumpHex("key", pKey, keySize);
        dumpHex("iv", pIvEncrypt, TEST_BLOCK_SIZE);
        printf("======\n");
#endif

        /* verify encryption */
        if (OK > (status = DIGI_MEMCMP((ubyte *)(desCbcTestVectors[i].encrypt), pText, 32, &cmpResult)))
        {
            retVal++;
            continue;
        }

        if (0 != cmpResult)
        {
#if (defined(__ENABLE_DES_CBC_TEST_DEBUG__))
            printf("generic_des_cbc_test: encryption test failed, keySize = %d.\n", keySize);
#endif
            retVal++;
        }

        if (OK > (status = DIGI_MEMCMP((ubyte *)(desCbcTestVectors[i].final_iv), pIvEncrypt, TEST_BLOCK_SIZE, &cmpResult)))
        {
            retVal++;
            continue;
        }

        if (0 != cmpResult)
        {
#if (defined(__ENABLE_DES_CBC_TEST_DEBUG__))
            printf("generic_des_cbc_test: encryption iv test failed, keySize = %d.\n", keySize);
#endif
            retVal++;
        }

        /* decrypt test */
        if (NULL == (ctx = CreateDESCtx(MOC_SYM(hwAccelCtx) pKey, keySize, FALSE)))
        {
            retVal++;
            continue;
        }

        if (OK > (status = DoDES(MOC_SYM(hwAccelCtx) ctx, pText, 32, FALSE, pIvDecrypt)))
        {
            retVal++;
            continue;
        }

        if (OK > (status = DeleteDESCtx(MOC_SYM(hwAccelCtx) &ctx)))
        {
            retVal++;
            continue;
        }

#if (defined(__ENABLE_DES_CBC_TEST_DEBUG__))
        dumpHex("decrypted text", pText, 32);
        dumpHex("key", pKey, keySize);
        dumpHex("iv", pIvDecrypt, TEST_BLOCK_SIZE);
        printf("}\n");
#endif

        /* verify decryption */
        if (OK > (status = DIGI_MEMCMP((ubyte *)(desCbcTestVectors[i].text), pText, 32, &cmpResult)))
        {
            retVal++;
            continue;
        }

        if (0 != cmpResult)
        {
#if (defined(__ENABLE_DES_CBC_TEST_DEBUG__))
            printf("generic_des_cbc_test: decryption test failed, keySize = %d.\n", keySize);
#endif
            retVal++;
        }

        if (OK > (status = DIGI_MEMCMP((ubyte *)(desCbcTestVectors[i].final_iv), pIvDecrypt, TEST_BLOCK_SIZE, &cmpResult)))
        {
            retVal++;
            continue;
        }

        if (0 != cmpResult)
        {
#if (defined(__ENABLE_DES_CBC_TEST_DEBUG__))
            printf("generic_des_cbc_test: decryption iv test failed, keySize = %d.\n", keySize);
#endif
            retVal++;
        }
    }

exit:

    if (OK > (status = CRYPTO_FREE(hwAccelCtx, TRUE, &pKey)))
        goto exit;

    if (OK > (status = CRYPTO_FREE(hwAccelCtx, TRUE, &pIvEncrypt)))
        goto exit;

    if (OK > (status = CRYPTO_FREE(hwAccelCtx, TRUE, &pIvDecrypt)))
        goto exit;

    if (OK > (status = CRYPTO_FREE(hwAccelCtx, TRUE, &pText)))
        goto exit;

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}


/*------------------------------------------------------------------*/

int des_cbc_test_vectors56()
{
    return generic_des_cbc_test(desCbcTestVectors56, (sizeof(desCbcTestVectors56)/ sizeof(TestDescr)), 8);
}

