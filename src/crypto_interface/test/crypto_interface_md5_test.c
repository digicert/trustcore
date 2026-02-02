
/*
* crypto_interface_md5_test.c
*
* test cases for crypto interface API for md5.h
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
#include "../../crypto/md5.h"
#include <stdio.h>

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

/*----------------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) &&     \
        defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_MD5__))
static int testCryptoInterface()
{
    MSTATUS status = OK;

    MD5_CTX *pCtx = NULL;
    MocSymCtx pMocCtx = NULL;

    ubyte pKey[24] = { 0 };
    ubyte4 keyLen = 24;


#ifdef __ENABLE_DIGICERT_MD5_MBED__

    /* create context for encryption step, TRUE for encryption */
    status  = MD5Alloc_m(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = MD5Init_m(MOC_HASH(gpHwAccelCtx) pCtx);
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
        MD5Free_m(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pCtx);

    if(OK != status)
        return 1;
    return 0;
}
#endif


/*----------------------------------------------------------------------------*/

int testMD5Complete()
{
    MSTATUS status = ERR_NULL_POINTER;

    MD5_CTX pCtx;
    ubyte pDigest[MD5_DIGESTSIZE];

    ubyte pText[33] = "012345678901234567890123456789012";
    ubyte4 textLen = 33;

    ubyte pExpected[] = {
		0xcf, 0x09, 0xb5, 0xcb, 0x76, 0x9d, 0x06, 0x8e, 0x70, 0xd2, 0x48, 0xac,
		0x7e, 0x01, 0x3a, 0xc9
	};
	ubyte4 expectedLen = 16;

	sbyte4 cmpRes = -1;

    status = MD5_completeDigest(MOC_HASH(gpHwAccelCtx) pText, textLen, pDigest);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;


    cmpRes = -1;
    status = DIGI_MEMCMP(pExpected, pDigest, MD5_DIGESTSIZE, &cmpRes);
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

int testMD5()
{
    MSTATUS status = ERR_NULL_POINTER;

    MD5_CTX *pCtx = NULL;
    ubyte pDigest[MD5_DIGESTSIZE];

    ubyte pText[33] = "012345678901234567890123456789012";
    ubyte4 textLen = 33;

    ubyte pExpected[] = {
		0xcf, 0x09, 0xb5, 0xcb, 0x76, 0x9d, 0x06, 0x8e, 0x70, 0xd2, 0x48, 0xac,
		0x7e, 0x01, 0x3a, 0xc9
	};
	ubyte4 expectedLen = 16;

	sbyte4 cmpRes = -1;

    status = MD5Alloc_m(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = MD5Init_m(MOC_HASH(gpHwAccelCtx) pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = MD5Update_m(MOC_HASH(gpHwAccelCtx) pCtx, pText, 11);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = MD5Update_m(MOC_HASH(gpHwAccelCtx) pCtx, pText + 11, textLen - 11);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = MD5Final_m(MOC_HASH(gpHwAccelCtx) pCtx, pDigest);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    cmpRes = -1;
    status = DIGI_MEMCMP(pExpected, pDigest, MD5_DIGESTSIZE, &cmpRes);
	UNITTEST_STATUS(__MOC_LINE__, status);
	if(OK != status)
		goto exit;

	if(0 != cmpRes)
	{
		status = ERR_CMP;
		UNITTEST_STATUS(__MOC_LINE__, status);
		goto exit;
	}

    status = MD5Free_m(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pCtx);
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

    MD5_CTX *pCtx = NULL;
    MD5_CTX *pCtxCopy = NULL;
    ubyte pDigest[MD5_DIGESTSIZE];

    ubyte pText[33] = "012345678901234567890123456789012";
    ubyte4 textLen = 33;

    ubyte pExpected[] = {
		0xcf, 0x09, 0xb5, 0xcb, 0x76, 0x9d, 0x06, 0x8e, 0x70, 0xd2, 0x48, 0xac,
		0x7e, 0x01, 0x3a, 0xc9
	};

	sbyte4 cmpRes = -1;

    status = MD5Alloc_m(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = MD5Alloc_m(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pCtxCopy);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = MD5Init_m(MOC_HASH(gpHwAccelCtx) pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = MD5Update_m(MOC_HASH(gpHwAccelCtx) pCtx, pText, 11);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = MD5_cloneCtx(MOC_HASH(gpHwAccelCtx) pCtxCopy, pCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = MD5Update_m(MOC_HASH(gpHwAccelCtx) pCtxCopy, pText + 11, textLen - 11);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = MD5Final_m(MOC_HASH(gpHwAccelCtx) pCtxCopy, pDigest);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    cmpRes = -1;
    status = DIGI_MEMCMP(pExpected, pDigest, MD5_DIGESTSIZE, &cmpRes);
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
        fstatus = MD5Free_m(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pCtx);
        UNITTEST_STATUS(__MOC_LINE__, fstatus);
        if (OK == status)
            status = fstatus;
    }

    if (NULL != pCtxCopy)
    {
        fstatus = MD5Free_m(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pCtxCopy);
        UNITTEST_STATUS(__MOC_LINE__, fstatus);
        if (OK == status)
            status = fstatus;
    }

    if(OK != status)
        return 1;
    return 0;
}

/*----------------------------------------------------------------------------*/

int crypto_interface_md5_test_init()
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
        defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_MD5__))
    errorCount = (errorCount + testCryptoInterface());
#endif

    /* TESTS GO HERE */
    errorCount = (errorCount + testMD5());
    errorCount = (errorCount + testMD5Complete());
    errorCount = (errorCount + testClone());

exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

    DIGICERT_free(&gpMocCtx);
    return errorCount;
}
