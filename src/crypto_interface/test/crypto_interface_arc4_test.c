/*
 * crypto_interface_arc4_test.c
 *
 * ARC4 Encryption Test
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
#include "../../crypto/rc4algo.h"
#include "../../crypto_interface/crypto_interface_priv.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#ifndef __DISABLE_ARC4_CIPHERS__

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

typedef struct arc4_test
{
    ubyte4  keyLen;
    const char* key;
    ubyte4  msgLen;
    const char* input;
    const char* output;
} arc4_test;

static arc4_test gArc4Tests[] =
{
    /* Test vector 0 */
    {
        8, "\x01\x23\x45\x67\x89\xab\xcd\xef",
        8, "\x01\x23\x45\x67\x89\xab\xcd\xef",
        "\x75\xb7\x87\x80\x99\xe0\xc5\x96",
    },

    /* Test vector 1 */
    {
        8, "\x01\x23\x45\x67\x89\xab\xcd\xef",
        8, "\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x74\x94\xc2\xe7\x10\x4b\x08\x79"
    },


    /* Test vector 2 */
    {
        8, "\x00\x00\x00\x00\x00\x00\x00\x00",
        8, "\x00\x00\x00\x00\x00\x00\x00\x00",
        "\xde\x18\x89\x41\xa3\x37\x5d\x3a"
    },

/* operators through crypto interface check that the key is at least 40 bits */
#if !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) || !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_ARC4__) || !defined(__ENABLE_DIGICERT_ARC4_MBED__)
    /* Test vector 3 */
    {
        4,  "\xef\x01\x23\x45",
        10, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "\xd6\xa1\x41\xa7\xec\x3c\x38\xdf\xbd\x61"
    },
#endif

    /* Test vector 4 */
    {
        8, "\x01\x23\x45\x67\x89\xab\xcd\xef",
        512, "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" /*11 */
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" /*21 */
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" /*51*/
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" /*101*/
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" /* 151 */
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" /* 201*/
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" /**/
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" /* 301*/
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" /**/
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" /* 401 */
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" /* 501 */
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01",                                             /* 512 */
        "\x75\x95\xc3\xe6\x11\x4a\x09\x78\x0c\x4a\xd4"
        "\x52\x33\x8e\x1f\xfd\x9a\x1b\xe9\x49\x8f"
        "\x81\x3d\x76\x53\x34\x49\xb6\x77\x8d\xca"
        "\xd8\xc7\x8a\x8d\x2b\xa9\xac\x66\x08\x5d"
        "\x0e\x53\xd5\x9c\x26\xc2\xd1\xc4\x90\xc1"
        "\xeb\xbe\x0c\xe6\x6d\x1b\x6b\x1b\x13\xb6"
        "\xb9\x19\xb8\x47\xc2\x5a\x91\x44\x7a\x95"
        "\xe7\x5e\x4e\xf1\x67\x79\xcd\xe8\xbf\x0a"
        "\x95\x85\x0e\x32\xaf\x96\x89\x44\x4f\xd3"
        "\x77\x10\x8f\x98\xfd\xcb\xd4\xe7\x26\x56"
        "\x75\x00\x99\x0b\xcc\x7e\x0c\xa3\xc4\xaa"
        "\xa3\x04\xa3\x87\xd2\x0f\x3b\x8f\xbb\xcd"
        "\x42\xa1\xbd\x31\x1d\x7a\x43\x03\xdd\xa5"
        "\xab\x07\x88\x96\xae\x80\xc1\x8b\x0a\xf6"
        "\x6d\xff\x31\x96\x16\xeb\x78\x4e\x49\x5a"
        "\xd2\xce\x90\xd7\xf7\x72\xa8\x17\x47\xb6"
        "\x5f\x62\x09\x3b\x1e\x0d\xb9\xe5\xba\x53"
        "\x2f\xaf\xec\x47\x50\x83\x23\xe6\x71\x32"
        "\x7d\xf9\x44\x44\x32\xcb\x73\x67\xce\xc8"
        "\x2f\x5d\x44\xc0\xd0\x0b\x67\xd6\x50\xa0"
        "\x75\xcd\x4b\x70\xde\xdd\x77\xeb\x9b\x10"
        "\x23\x1b\x6b\x5b\x74\x13\x47\x39\x6d\x62"
        "\x89\x74\x21\xd4\x3d\xf9\xb4\x2e\x44\x6e"
        "\x35\x8e\x9c\x11\xa9\xb2\x18\x4e\xcb\xef"
        "\x0c\xd8\xe7\xa8\x77\xef\x96\x8f\x13\x90"
        "\xec\x9b\x3d\x35\xa5\x58\x5c\xb0\x09\x29"
        "\x0e\x2f\xcd\xe7\xb5\xec\x66\xd9\x08\x4b"
        "\xe4\x40\x55\xa6\x19\xd9\xdd\x7f\xc3\x16"
        "\x6f\x94\x87\xf7\xcb\x27\x29\x12\x42\x64"
        "\x45\x99\x85\x14\xc1\x5d\x53\xa1\x8c\x86"
        "\x4c\xe3\xa2\xb7\x55\x57\x93\x98\x81\x26"
        "\x52\x0e\xac\xf2\xe3\x06\x6e\x23\x0c\x91"
        "\xbe\xe4\xdd\x53\x04\xf5\xfd\x04\x05\xb3"
        "\x5b\xd9\x9c\x73\x13\x5d\x3d\x9b\xc3\x35"
        "\xee\x04\x9e\xf6\x9b\x38\x67\xbf\x2d\x7b"
        "\xd1\xea\xa5\x95\xd8\xbf\xc0\x06\x6f\xf8"
        "\xd3\x15\x09\xeb\x0c\x6c\xaa\x00\x6c\x80"
        "\x7a\x62\x3e\xf8\x4c\x3d\x33\xc1\x95\xd2"
        "\x3e\xe3\x20\xc4\x0d\xe0\x55\x81\x57\xc8"
        "\x22\xd4\xb8\xc5\x69\xd8\x49\xae\xd5\x9d"
        "\x4e\x0f\xd7\xf3\x79\x58\x6b\x4b\x7f\xf6"
        "\x84\xed\x6a\x18\x9f\x74\x86\xd4\x9b\x9c"
        "\x4b\xad\x9b\xa2\x4b\x96\xab\xf9\x24\x37"
        "\x2c\x8a\x8f\xff\xb1\x0d\x55\x35\x49\x00"
        "\xa7\x7a\x3d\xb5\xf2\x05\xe1\xb9\x9f\xcd"
        "\x86\x60\x86\x3a\x15\x9a\xd4\xab\xe4\x0f"
        "\xa4\x89\x34\x16\x3d\xdd\xe5\x42\xa6\x58"
        "\x55\x40\xfd\x68\x3c\xbf\xd8\xc0\x0f\x12"
        "\x12\x9a\x28\x4d\xea\xcc\x4c\xde\xfe\x58"
        "\xbe\x71\x37\x54\x1c\x04\x71\x26\xc8\xd4"
        "\x9e\x27\x55\xab\x18\x1a\xb7\xe9\x40\xb0"
        "\xc0"
    }
};

/*---------------------------------------------------------------------*/

static int test_arc4_clone(arc4_test *pTest)
{
    int retVal = 0;
    MSTATUS status;
    BulkCtx pCtx = NULL;
    BulkCtx pCloneCtx = NULL;
    sbyte4 cmp;
    ubyte pTemp[512];

    /* Make a mutable copy of the input */
    status = DIGI_MEMCPY(pTemp, pTest->input, pTest->msgLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    pCtx = CreateRC4Ctx(MOC_SYM(gpHwAccelCtx) (ubyte *) pTest->key, pTest->keyLen, 0);
    if (NULL == pCtx)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
        goto exit;
    }

    /* No update functionality, simply clone it as is */
    status = CloneRC4Ctx(MOC_SYM(gpHwAccelCtx) pCtx, &pCloneCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DoRC4(MOC_SYM(gpHwAccelCtx) pCloneCtx, pTemp, pTest->msgLen, 0, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pTemp, (ubyte *) pTest->output, pTest->msgLen, &cmp);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (cmp)
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);

exit:

    if (NULL != pCtx)
    {
        status = DeleteRC4Ctx(MOC_SYM(gpHwAccelCtx) &pCtx);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pCloneCtx)
    {
        status = DeleteRC4Ctx(MOC_SYM(gpHwAccelCtx) &pCloneCtx);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}

/*---------------------------------------------------------------------*/

static int test_arc4(arc4_test *pTest)
{
    int retVal = 0;
    MSTATUS status;
    BulkCtx pCtx = NULL;
    sbyte4 cmp;
    ubyte pTemp[512];

    /* Make a mutable copy of the input */
    status = DIGI_MEMCPY(pTemp, pTest->input, pTest->msgLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    pCtx = CreateRC4Ctx(MOC_SYM(gpHwAccelCtx) (ubyte *) pTest->key, pTest->keyLen, 0);
    if (NULL == pCtx)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
        goto exit;
    }

    status = DoRC4(MOC_SYM(gpHwAccelCtx) pCtx, pTemp, pTest->msgLen, 0, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pTemp, (ubyte *) pTest->output, pTest->msgLen, &cmp);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (cmp)
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);

exit:

    if (NULL != pCtx)
    {
        status = DeleteRC4Ctx(MOC_SYM(gpHwAccelCtx) &pCtx);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}
#endif /* __DISABLE_ARC4_CIPHERS__ */

/*---------------------------------------------------------------------------*/

int crypto_interface_arc4_test()
{
    int retVal = 0;

#ifndef __DISABLE_ARC4_CIPHERS__

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

    for (i = 0; i < COUNTOF(gArc4Tests); ++i)
    {
        retVal += test_arc4( gArc4Tests+i);
        retVal += test_arc4_clone( gArc4Tests+i);
    }

exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif
    status = DIGICERT_free(&gpMocCtx);
    retVal += UNITTEST_INT(__MOC_LINE__, status, OK);

#endif /* __DISABLE_ARC4_CIPHERS__ */

    return retVal;
}
