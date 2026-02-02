/*
 * crypto_interface_hmac_kdf_test.c
 *
 * Unit Test for HMAC-KDF.
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
#include "../../crypto/hmac_kdf.h"
#include "../../crypto_interface/crypto_interface_priv.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#include "../../crypto/sha1.h"
#ifndef __DISABLE_DIGICERT_SHA256__
#include "../../crypto/sha256.h"
#endif

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

static BulkHashAlgo SHA1Suite = {
    SHA1_RESULT_SIZE,
    SHA1_BLOCK_SIZE,
    SHA1_allocDigest,
    SHA1_freeDigest,
    (BulkCtxInitFunc) SHA1_initDigest,
    (BulkCtxUpdateFunc) SHA1_updateDigest,
    (BulkCtxFinalFunc) SHA1_finalDigest,
    NULL,
    NULL,
    NULL,
    ht_sha1
};

#ifndef __DISABLE_DIGICERT_SHA256__
static BulkHashAlgo SHA256Suite = {
    SHA256_RESULT_SIZE,
    SHA256_BLOCK_SIZE,
    SHA256_allocDigest,
    SHA256_freeDigest,
    (BulkCtxInitFunc) SHA256_initDigest,
    (BulkCtxUpdateFunc) SHA256_updateDigest,
    (BulkCtxFinalFunc) SHA256_finalDigest,
    NULL,
    NULL,
    NULL,
    ht_sha256
};
#endif


typedef struct
{
    BulkHashAlgo *pDigest;
    ubyte4 inputKeyLen;
    ubyte *pInputKey;
    ubyte4 saltLen;
    ubyte *pSalt;
    ubyte4 pseudoKeyLen;
    ubyte *pPseudoKey;
    ubyte4 contextLen;
    ubyte *pContext;
    ubyte4 outputKeyLen;
    ubyte *pOutputKey;
} HmacKdfTestVector;


static HmacKdfTestVector pHmacKdfVectors[] = {
#ifndef __DISABLE_DIGICERT_SHA256__
    {
        .pDigest = &SHA256Suite,
        .inputKeyLen = 22,
        .pInputKey = (ubyte *)
            "\x00b\x00b\x00b\x00b\x00b\x00b\x00b\x00b"
            "\x00b\x00b\x00b\x00b\x00b\x00b\x00b\x00b"
            "\x00b\x00b\x00b\x00b\x00b\x00b",
        .saltLen = 13,
        .pSalt = (ubyte *)
            "\x000\x001\x002\x003\x004\x005\x006\x007"
            "\x008\x009\x00a\x00b\x00c",
        .pseudoKeyLen = 32,
        .pPseudoKey = (ubyte *)
            "\x007\x077\x009\x036\x02c\x02e\x032\x0df"
            "\x00d\x0dc\x03f\x00d\x0c4\x07b\x0ba\x063"
            "\x090\x0b6\x0c7\x03b\x0b5\x00f\x09c\x031"
            "\x022\x0ec\x084\x04a\x0d7\x0c2\x0b3\x0e5",
        .contextLen = 10,
        .pContext = (ubyte *)
            "\x0f0\x0f1\x0f2\x0f3\x0f4\x0f5\x0f6\x0f7"
            "\x0f8\x0f9",
        .outputKeyLen = 42,
        .pOutputKey = (ubyte *)
            "\x03c\x0b2\x05f\x025\x0fa\x0ac\x0d5\x07a"
            "\x090\x043\x04f\x064\x0d0\x036\x02f\x02a"
            "\x02d\x02d\x00a\x090\x0cf\x01a\x05a\x04c"
            "\x05d\x0b0\x02d\x056\x0ec\x0c4\x0c5\x0bf"
            "\x034\x000\x072\x008\x0d5\x0b8\x087\x018"
            "\x058\x065"
    },
    {
        .pDigest = &SHA256Suite,
        .inputKeyLen = 80,
        .pInputKey = (ubyte *)
            "\x000\x001\x002\x003\x004\x005\x006\x007"
            "\x008\x009\x00a\x00b\x00c\x00d\x00e\x00f"
            "\x010\x011\x012\x013\x014\x015\x016\x017"
            "\x018\x019\x01a\x01b\x01c\x01d\x01e\x01f"
            "\x020\x021\x022\x023\x024\x025\x026\x027"
            "\x028\x029\x02a\x02b\x02c\x02d\x02e\x02f"
            "\x030\x031\x032\x033\x034\x035\x036\x037"
            "\x038\x039\x03a\x03b\x03c\x03d\x03e\x03f"
            "\x040\x041\x042\x043\x044\x045\x046\x047"
            "\x048\x049\x04a\x04b\x04c\x04d\x04e\x04f",
        .saltLen = 80,
        .pSalt = (ubyte *)
            "\x060\x061\x062\x063\x064\x065\x066\x067"
            "\x068\x069\x06a\x06b\x06c\x06d\x06e\x06f"
            "\x070\x071\x072\x073\x074\x075\x076\x077"
            "\x078\x079\x07a\x07b\x07c\x07d\x07e\x07f"
            "\x080\x081\x082\x083\x084\x085\x086\x087"
            "\x088\x089\x08a\x08b\x08c\x08d\x08e\x08f"
            "\x090\x091\x092\x093\x094\x095\x096\x097"
            "\x098\x099\x09a\x09b\x09c\x09d\x09e\x09f"
            "\x0a0\x0a1\x0a2\x0a3\x0a4\x0a5\x0a6\x0a7"
            "\x0a8\x0a9\x0aa\x0ab\x0ac\x0ad\x0ae\x0af",
        .pseudoKeyLen = 32,
        .pPseudoKey = (ubyte *)
            "\x006\x0a6\x0b8\x08c\x058\x053\x036\x01a"
            "\x006\x010\x04c\x09c\x0eb\x035\x0b4\x05c"
            "\x0ef\x076\x000\x014\x090\x046\x071\x001"
            "\x04a\x019\x03f\x040\x0c1\x05f\x0c2\x044",
        .contextLen = 80,
        .pContext = (ubyte *)
            "\x0b0\x0b1\x0b2\x0b3\x0b4\x0b5\x0b6\x0b7"
            "\x0b8\x0b9\x0ba\x0bb\x0bc\x0bd\x0be\x0bf"
            "\x0c0\x0c1\x0c2\x0c3\x0c4\x0c5\x0c6\x0c7"
            "\x0c8\x0c9\x0ca\x0cb\x0cc\x0cd\x0ce\x0cf"
            "\x0d0\x0d1\x0d2\x0d3\x0d4\x0d5\x0d6\x0d7"
            "\x0d8\x0d9\x0da\x0db\x0dc\x0dd\x0de\x0df"
            "\x0e0\x0e1\x0e2\x0e3\x0e4\x0e5\x0e6\x0e7"
            "\x0e8\x0e9\x0ea\x0eb\x0ec\x0ed\x0ee\x0ef"
            "\x0f0\x0f1\x0f2\x0f3\x0f4\x0f5\x0f6\x0f7"
            "\x0f8\x0f9\x0fa\x0fb\x0fc\x0fd\x0fe\x0ff",
        .outputKeyLen = 82,
        .pOutputKey = (ubyte *)
            "\x0b1\x01e\x039\x08d\x0c8\x003\x027\x0a1"
            "\x0c8\x0e7\x0f7\x08c\x059\x06a\x049\x034"
            "\x04f\x001\x02e\x0da\x02d\x04e\x0fa\x0d8"
            "\x0a0\x050\x0cc\x04c\x019\x0af\x0a9\x07c"
            "\x059\x004\x05a\x099\x0ca\x0c7\x082\x072"
            "\x071\x0cb\x041\x0c6\x05e\x059\x00e\x009"
            "\x0da\x032\x075\x060\x00c\x02f\x009\x0b8"
            "\x036\x077\x093\x0a9\x0ac\x0a3\x0db\x071"
            "\x0cc\x030\x0c5\x081\x079\x0ec\x03e\x087"
            "\x0c1\x04c\x001\x0d5\x0c1\x0f3\x043\x04f"
            "\x01d\x087"
    },
    {
        .pDigest = &SHA256Suite,
        .inputKeyLen = 22,
        .pInputKey = (ubyte *)
            "\x00b\x00b\x00b\x00b\x00b\x00b\x00b\x00b"
            "\x00b\x00b\x00b\x00b\x00b\x00b\x00b\x00b"
            "\x00b\x00b\x00b\x00b\x00b\x00b",
        .saltLen = 0,
        .pSalt = NULL,
        .pseudoKeyLen = 32,
        .pPseudoKey = (ubyte *)
            "\x019\x0ef\x024\x0a3\x02c\x071\x07b\x016"
            "\x07f\x033\x0a9\x01d\x06f\x064\x08b\x0df"
            "\x096\x059\x067\x076\x0af\x0db\x063\x077"
            "\x0ac\x043\x04c\x01c\x029\x03c\x0cb\x004",
        .contextLen = 0,
        .pContext = NULL,
        .outputKeyLen = 42,
        .pOutputKey = (ubyte *)
            "\x08d\x0a4\x0e7\x075\x0a5\x063\x0c1\x08f"
            "\x071\x05f\x080\x02a\x006\x03c\x05a\x031"
            "\x0b8\x0a1\x01f\x05c\x05e\x0e1\x087\x09e"
            "\x0c3\x045\x04e\x05f\x03c\x073\x08d\x02d"
            "\x09d\x020\x013\x095\x0fa\x0a4\x0b6\x01a"
            "\x096\x0c8"
    },
#endif
    {
        .pDigest = &SHA1Suite,
        .inputKeyLen = 11,
        .pInputKey = (ubyte *)
            "\x00b\x00b\x00b\x00b\x00b\x00b\x00b\x00b"
            "\x00b\x00b\x00b",
        .saltLen = 13,
        .pSalt = (ubyte *)
            "\x000\x001\x002\x003\x004\x005\x006\x007"
            "\x008\x009\x00a\x00b\x00c",
        .pseudoKeyLen = 20,
        .pPseudoKey = (ubyte *)
            "\x09b\x06c\x018\x0c4\x032\x0a7\x0bf\x08f"
            "\x00e\x071\x0c8\x0eb\x088\x0f4\x0b3\x00b"
            "\x0aa\x02b\x0a2\x043",
        .contextLen = 10,
        .pContext = (ubyte *)
            "\x0f0\x0f1\x0f2\x0f3\x0f4\x0f5\x0f6\x0f7"
            "\x0f8\x0f9",
        .outputKeyLen = 42,
        .pOutputKey = (ubyte *)
            "\x008\x05a\x001\x0ea\x01b\x010\x0f3\x069"
            "\x033\x006\x08b\x056\x0ef\x0a5\x0ad\x081"
            "\x0a4\x0f1\x04b\x082\x02f\x05b\x009\x015"
            "\x068\x0a9\x0cd\x0d4\x0f1\x055\x0fd\x0a2"
            "\x0c2\x02e\x042\x024\x078\x0d3\x005\x0f3"
            "\x0f8\x096"
    },
    {
        .pDigest = &SHA1Suite,
        .inputKeyLen = 80,
        .pInputKey = (ubyte *)
            "\x000\x001\x002\x003\x004\x005\x006\x007"
            "\x008\x009\x00a\x00b\x00c\x00d\x00e\x00f"
            "\x010\x011\x012\x013\x014\x015\x016\x017"
            "\x018\x019\x01a\x01b\x01c\x01d\x01e\x01f"
            "\x020\x021\x022\x023\x024\x025\x026\x027"
            "\x028\x029\x02a\x02b\x02c\x02d\x02e\x02f"
            "\x030\x031\x032\x033\x034\x035\x036\x037"
            "\x038\x039\x03a\x03b\x03c\x03d\x03e\x03f"
            "\x040\x041\x042\x043\x044\x045\x046\x047"
            "\x048\x049\x04a\x04b\x04c\x04d\x04e\x04f",
        .saltLen = 80,
        .pSalt = (ubyte *)
            "\x060\x061\x062\x063\x064\x065\x066\x067"
            "\x068\x069\x06a\x06b\x06c\x06d\x06e\x06f"
            "\x070\x071\x072\x073\x074\x075\x076\x077"
            "\x078\x079\x07a\x07b\x07c\x07d\x07e\x07f"
            "\x080\x081\x082\x083\x084\x085\x086\x087"
            "\x088\x089\x08a\x08b\x08c\x08d\x08e\x08f"
            "\x090\x091\x092\x093\x094\x095\x096\x097"
            "\x098\x099\x09a\x09b\x09c\x09d\x09e\x09f"
            "\x0a0\x0a1\x0a2\x0a3\x0a4\x0a5\x0a6\x0a7"
            "\x0a8\x0a9\x0aa\x0ab\x0ac\x0ad\x0ae\x0af",
        .pseudoKeyLen = 20,
        .pPseudoKey = (ubyte *)
            "\x08a\x0da\x0e0\x09a\x02a\x030\x070\x059"
            "\x047\x08d\x030\x09b\x026\x0c4\x011\x05a"
            "\x022\x04c\x0fa\x0f6",
        .contextLen = 80,
        .pContext = (ubyte *)
            "\x0b0\x0b1\x0b2\x0b3\x0b4\x0b5\x0b6\x0b7"
            "\x0b8\x0b9\x0ba\x0bb\x0bc\x0bd\x0be\x0bf"
            "\x0c0\x0c1\x0c2\x0c3\x0c4\x0c5\x0c6\x0c7"
            "\x0c8\x0c9\x0ca\x0cb\x0cc\x0cd\x0ce\x0cf"
            "\x0d0\x0d1\x0d2\x0d3\x0d4\x0d5\x0d6\x0d7"
            "\x0d8\x0d9\x0da\x0db\x0dc\x0dd\x0de\x0df"
            "\x0e0\x0e1\x0e2\x0e3\x0e4\x0e5\x0e6\x0e7"
            "\x0e8\x0e9\x0ea\x0eb\x0ec\x0ed\x0ee\x0ef"
            "\x0f0\x0f1\x0f2\x0f3\x0f4\x0f5\x0f6\x0f7"
            "\x0f8\x0f9\x0fa\x0fb\x0fc\x0fd\x0fe\x0ff",
        .outputKeyLen = 82,
        .pOutputKey = (ubyte *)
            "\x00b\x0d7\x070\x0a7\x04d\x011\x060\x0f7"
            "\x0c9\x0f1\x02c\x0d5\x091\x02a\x006\x0eb"
            "\x0ff\x06a\x0dc\x0ae\x089\x09d\x092\x019"
            "\x01f\x0e4\x030\x056\x073\x0ba\x02f\x0fe"
            "\x08f\x0a3\x0f1\x0a4\x0e5\x0ad\x079\x0f3"
            "\x0f3\x034\x0b3\x0b2\x002\x0b2\x017\x03c"
            "\x048\x06e\x0a3\x07c\x0e3\x0d3\x097\x0ed"
            "\x003\x04c\x07f\x09d\x0fe\x0b1\x05c\x05e"
            "\x092\x073\x036\x0d0\x044\x01f\x04c\x043"
            "\x000\x0e2\x0cf\x0f0\x0d0\x090\x00b\x052"
            "\x0d3\x0b4"
    },
    {
        .pDigest = &SHA1Suite,
        .inputKeyLen = 22,
        .pInputKey = (ubyte *)
            "\x00b\x00b\x00b\x00b\x00b\x00b\x00b\x00b"
            "\x00b\x00b\x00b\x00b\x00b\x00b\x00b\x00b"
            "\x00b\x00b\x00b\x00b\x00b\x00b",
        .saltLen = 0,
        .pSalt = NULL,
        .pseudoKeyLen = 20,
        .pPseudoKey = (ubyte *)
            "\x0da\x08c\x08a\x073\x0c7\x0fa\x077\x028"
            "\x08e\x0c6\x0f5\x0e7\x0c2\x097\x078\x06a"
            "\x0a0\x0d3\x02d\x001",
        .contextLen = 0,
        .pContext = NULL,
        .outputKeyLen = 42,
        .pOutputKey = (ubyte *)
            "\x00a\x0c1\x0af\x070\x002\x0b3\x0d7\x061"
            "\x0d1\x0e5\x052\x098\x0da\x09d\x005\x006"
            "\x0b9\x0ae\x052\x005\x072\x020\x0a3\x006"
            "\x0e0\x07b\x06b\x087\x0e8\x0df\x021\x0d0"
            "\x0ea\x000\x003\x03d\x0e0\x039\x084\x0d3"
            "\x049\x018"
    },
    {
        .pDigest = &SHA1Suite,
        .inputKeyLen = 22,
        .pInputKey = (ubyte *)
            "\x00c\x00c\x00c\x00c\x00c\x00c\x00c\x00c"
            "\x00c\x00c\x00c\x00c\x00c\x00c\x00c\x00c"
            "\x00c\x00c\x00c\x00c\x00c\x00c",
        .saltLen = 0,
        .pSalt = NULL,
        .pseudoKeyLen = 20,
        .pPseudoKey = (ubyte *)
            "\x02a\x0dc\x0ca\x0da\x018\x077\x09e\x07c"
            "\x020\x077\x0ad\x02e\x0b1\x09d\x03f\x03e"
            "\x073\x013\x085\x0dd",
        .contextLen = 0,
        .pContext = NULL,
        .outputKeyLen = 42,
        .pOutputKey = (ubyte *)
            "\x02c\x091\x011\x072\x004\x0d7\x045\x0f3"
            "\x050\x00d\x063\x06a\x062\x0f6\x04f\x00a"
            "\x0b3\x0ba\x0e5\x048\x0aa\x053\x0d4\x023"
            "\x0b0\x0d1\x0f2\x07e\x0bb\x0a6\x0f5\x0e5"
            "\x067\x03a\x008\x01d\x070\x0cc\x0e7\x0ac"
            "\x0fc\x048"
    }
};

static int HmacKdfTestVectors()
{
    MSTATUS status;
    ubyte4 vectorCount = sizeof(pHmacKdfVectors)/sizeof(HmacKdfTestVector);
    ubyte4 count, outputLen;
    int errorCount = 0;
    HmacKdfTestVector *pCurTest = NULL;
    ubyte *pOutput = NULL;
    sbyte4 cmpRes;

    for (count = 0; count < vectorCount; ++count)
    {
        pCurTest = pHmacKdfVectors + count;

        outputLen = pCurTest->pseudoKeyLen;

        DIGI_FREE((void **) &pOutput);
        status = DIGI_MALLOC((void **) &pOutput, outputLen);
        UNITTEST_STATUS_GOTO(OK, status, errorCount, exit)

        status = HmacKdfExtract(MOC_HASH(gpHwAccelCtx) 
            pCurTest->pDigest, pCurTest->pSalt, pCurTest->saltLen,
            pCurTest->pInputKey, pCurTest->inputKeyLen, pOutput,
            outputLen);
        UNITTEST_STATUS_GOTO(OK, status, errorCount, exit)

        status = DIGI_MEMCMP(pOutput, pCurTest->pPseudoKey, outputLen, &cmpRes);
        UNITTEST_STATUS_GOTO(OK, status, errorCount, exit)

        if (0 != cmpRes)
            status = ERR_CMP;
        UNITTEST_STATUS_GOTO(OK, status, errorCount, exit)

        status = DIGI_FREE((void **) &pOutput);
        UNITTEST_STATUS_GOTO(OK, status, errorCount, exit)

        outputLen = pCurTest->outputKeyLen;

        DIGI_FREE((void **) &pOutput);
        status = DIGI_MALLOC((void **) &pOutput, outputLen);
        UNITTEST_STATUS_GOTO(OK, status, errorCount, exit)

        status = HmacKdfExpand(MOC_HASH(gpHwAccelCtx) 
            pCurTest->pDigest, pCurTest->pPseudoKey, pCurTest->pseudoKeyLen,
            pCurTest->pContext, pCurTest->contextLen, NULL, 0, pOutput,
            pCurTest->outputKeyLen);
        UNITTEST_STATUS_GOTO(OK, status, errorCount, exit)

        status = DIGI_MEMCMP(pOutput, pCurTest->pOutputKey, outputLen, &cmpRes);
        UNITTEST_STATUS_GOTO(OK, status, errorCount, exit)

        if (0 != cmpRes)
            status = ERR_CMP;
        UNITTEST_STATUS_GOTO(OK, status, errorCount, exit)
    }

exit:

    if (NULL != pOutput)
        UNITTEST_STATUS(OK, DIGI_FREE((void **) &pOutput));

    return errorCount;
}

static int HmacKdfExtractTestErrors()
{
    MSTATUS status;
    int errorCount = 0;
    ubyte pSmallOutput[1];
    ubyte pOutput[20];
    ubyte pSalt[1];
    ubyte pKey[1];

    status = HmacKdfExtract(MOC_HASH(gpHwAccelCtx) NULL, NULL, 0, NULL, 0, NULL, 0);
    errorCount += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = HmacKdfExtract(MOC_HASH(gpHwAccelCtx) &SHA1Suite, NULL, 0, NULL, 0, NULL, 0);
    errorCount += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = HmacKdfExtract(MOC_HASH(gpHwAccelCtx) 
        &SHA1Suite, NULL, 0, NULL, 0, pSmallOutput, sizeof(pSmallOutput));
    errorCount += UNITTEST_INT(__MOC_LINE__, status, ERR_BAD_LENGTH);

    status = HmacKdfExtract(MOC_HASH(gpHwAccelCtx) 
        &SHA1Suite, NULL, sizeof(pSalt), NULL, 0,
        pSmallOutput, sizeof(pSmallOutput));
    errorCount += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = HmacKdfExtract(MOC_HASH(gpHwAccelCtx) 
        &SHA1Suite, pSalt, 0, NULL, 0,
        pSmallOutput, sizeof(pSmallOutput));
    errorCount += UNITTEST_INT(__MOC_LINE__, status, ERR_BAD_LENGTH);

    status = HmacKdfExtract(MOC_HASH(gpHwAccelCtx) 
        &SHA1Suite, pSalt, sizeof(pSalt), NULL, 0,
        pSmallOutput, sizeof(pSmallOutput));
    errorCount += UNITTEST_INT(__MOC_LINE__, status, ERR_BAD_LENGTH);

    status = HmacKdfExtract(MOC_HASH(gpHwAccelCtx) 
        &SHA1Suite, pSalt, sizeof(pSalt), NULL, sizeof(pKey),
        pOutput, sizeof(pOutput));
    errorCount += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

exit:

    return errorCount;
}

static int HmacKdfExpandTestErrors()
{
    MSTATUS status;
    int errorCount = 0;
    ubyte pData[10];
    ubyte pDigestLen[20];

    status = HmacKdfExpand(MOC_HASH(gpHwAccelCtx) NULL, NULL, 0, NULL, 0, NULL, 0, NULL, 0);
    errorCount += UNITTEST_INT(ERR_NULL_POINTER, ERR_NULL_POINTER, status);

    status = HmacKdfExpand(MOC_HASH(gpHwAccelCtx) &SHA1Suite, NULL, 0, NULL, 0, NULL, 0, NULL, 0);
    errorCount += UNITTEST_INT(ERR_NULL_POINTER, ERR_NULL_POINTER, status);

    status = HmacKdfExpand(MOC_HASH(gpHwAccelCtx) &SHA1Suite, pData, 0, NULL, 0, NULL, 0, NULL, 0);
    errorCount += UNITTEST_INT(ERR_NULL_POINTER, ERR_NULL_POINTER, status);

    status = HmacKdfExpand(MOC_HASH(gpHwAccelCtx) &SHA1Suite, pData, 0, NULL, 0, NULL, 10, pData, 0);
    errorCount += UNITTEST_TRUE(OK, status != OK);

    status = HmacKdfExpand(MOC_HASH(gpHwAccelCtx) 
        &SHA1Suite, pDigestLen, sizeof(pDigestLen), NULL, 0, NULL, 0, pData, 0);
    errorCount += UNITTEST_INT(OK, OK, status);

exit:

    return errorCount;
}

int crypto_interface_hmac_kdf_test_all()
{
    MSTATUS status;
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

    errorCount += HmacKdfTestVectors();
    errorCount += HmacKdfExtractTestErrors();
    errorCount += HmacKdfExpandTestErrors();

exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

    status = DIGICERT_free(&gpMocCtx);
    errorCount += UNITTEST_STATUS(__MOC_LINE__, status);

    return errorCount;
}
