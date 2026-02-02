/*
* crypto_interface_md4_test.c
*
* test cases for crypto interface API for md4.h
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
#include "../../crypto/crypto.h"
#include "../../crypto/md4.h"
#include <stdio.h>

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

/*----------------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) &&     \
        defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_MD4__))
static int testCryptoInterface()
{
    MSTATUS status = OK;

    MD4_CTX *pCtx = NULL;
    MocSymCtx pMocCtx = NULL;

    ubyte pKey[24] = { 0 };
    ubyte4 keyLen = 24;


#ifdef __ENABLE_DIGICERT_MD4_MBED__

    /* create context for encryption step, TRUE for encryption */
    status  = MD4Alloc(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = MD4Init(MOC_HASH(gpHwAccelCtx) pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;


    pMocCtx = pCtx->pMocSymCtx;
    if(NULL == pMocCtx)
    {
        status = ERR_INVALID_ARG;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if(FALSE == pCtx->enabled)
    {
        status = ERR_INVALID_ARG;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

#endif

exit:
    if(NULL != pCtx)
        MD4Free(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pCtx);

    if(OK != status)
        return 1;
    return 0;
}
#endif


/*----------------------------------------------------------------------------*/

static int testMD4Complete()
{
    MSTATUS status = ERR_NULL_POINTER;

    ubyte pDigest[MD4_DIGESTSIZE];

    ubyte pText[3] = "abc";
    ubyte4 textLen = 3;

    ubyte pExpected[] =
    {
		0xa4,0x48,0x01,0x7a,0xaf,0x21,0xd8,0x52,0x5f,0xc1,0x0a,0xe8,0x7a,0xa6,0x72,0x9d
	};

	sbyte4 cmpRes = -1;

    status = MD4_completeDigest(MOC_HASH(gpHwAccelCtx) pText, textLen, pDigest);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;


    cmpRes = -1;
    status = DIGI_MEMCMP(pExpected, pDigest, MD4_DIGESTSIZE, &cmpRes);
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
    if(OK != status)
        return 1;
    return 0;
}

static int testMD4()
{
    MSTATUS status = ERR_NULL_POINTER;

    MD4_CTX *pCtx = NULL;
    ubyte pDigest[MD4_DIGESTSIZE];

    ubyte pText[26] = "abcdefghijklmnopqrstuvwxyz";
    ubyte4 textLen = 26;

    ubyte pExpected[] =
    {
		0xd7,0x9e,0x1c,0x30,0x8a,0xa5,0xbb,0xcd,0xee,0xa8,0xed,0x63,0xdf,0x41,0x2d,0xa9
	};

	sbyte4 cmpRes = -1;

    status = MD4Alloc(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = MD4Init(MOC_HASH(gpHwAccelCtx) pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = MD4Update(MOC_HASH(gpHwAccelCtx) pCtx, pText, 11);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = MD4Update(MOC_HASH(gpHwAccelCtx) pCtx, pText + 11, textLen - 11);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = MD4Final(MOC_HASH(gpHwAccelCtx) pCtx, pDigest);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    cmpRes = -1;
    status = DIGI_MEMCMP(pExpected, pDigest, MD4_DIGESTSIZE, &cmpRes);
	UNITTEST_STATUS(__MOC_LINE__, status);
	if(OK != status)
		goto exit;

	if(0 != cmpRes)
	{
		status = ERR_CMP;
		UNITTEST_STATUS(__MOC_LINE__, status);
		goto exit;
	}

    status = MD4Free(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

exit:
    if(OK != status)
        return 1;
    return 0;
}


/*----------------------------------------------------------------------------*/

static int testClone()
{
    MSTATUS status = ERR_NULL_POINTER, fstatus = OK;

    MD4_CTX *pCtx = NULL;
    MD4_CTX *pCtxCopy = NULL;
    ubyte pDigest[MD4_DIGESTSIZE];

    ubyte pText[26] = "abcdefghijklmnopqrstuvwxyz";
    ubyte4 textLen = 26;

    ubyte pExpected[] =
    {
		0xd7,0x9e,0x1c,0x30,0x8a,0xa5,0xbb,0xcd,0xee,0xa8,0xed,0x63,0xdf,0x41,0x2d,0xa9
	};

	sbyte4 cmpRes = -1;

    status = MD4Alloc(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = MD4Alloc(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pCtxCopy);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = MD4Init(MOC_HASH(gpHwAccelCtx) pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = MD4Update(MOC_HASH(gpHwAccelCtx) pCtx, pText, 11);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = MD4_cloneCtx(MOC_HASH(gpHwAccelCtx) pCtxCopy, pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = MD4Update(MOC_HASH(gpHwAccelCtx) pCtxCopy, pText + 11, textLen - 11);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = MD4Final(MOC_HASH(gpHwAccelCtx) pCtxCopy, pDigest);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    cmpRes = -1;
    status = DIGI_MEMCMP(pExpected, pDigest, MD4_DIGESTSIZE, &cmpRes);
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

    if (NULL != pCtx)
    {
        fstatus = MD4Free(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pCtx);
        UNITTEST_STATUS(__MOC_LINE__, fstatus);
        if (OK == status)
            status = fstatus;
    }

    if (NULL != pCtxCopy)
    {
        fstatus = MD4Free(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pCtxCopy);
        UNITTEST_STATUS(__MOC_LINE__, fstatus);
        if (OK == status)
            status = fstatus;
    }

    if(OK != status)
        return 1;
    return 0;
}

/*----------------------------------------------------------------------------*/

int crypto_interface_md4_test_init()
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

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) &&     \
        defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_MD4__))
    errorCount = (errorCount + testCryptoInterface());
#endif

    /* TESTS GO HERE */
    errorCount = (errorCount + testMD4());
    errorCount = (errorCount + testMD4Complete());
    errorCount = (errorCount + testClone());

exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

    DIGICERT_free(&gpMocCtx);
    return errorCount;
}
