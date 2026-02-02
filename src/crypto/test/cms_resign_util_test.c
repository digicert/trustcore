/*
 * cms_resign_util_test.c
 *
 * Unit tests for Mocana CMS Resign Utility - cms_resign_util.c
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
#include "../../asn1/mocasn1.h"
#include "../../asn1/oiddefs.h"

#include "../../../unit_tests/unittest.h"

#include "../../common/utils.h"
#include "../../common/memfile.h"
#include "../../common/absstream.h"
#include "../../common/mrtos.h"

#include "../../crypto/aes.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/ca_mgmt.h"
#include "../../crypto/pkcs_common.h"
#include "../../crypto/pkcs_key.h"
#include "../../crypto/pkcs7.h"
#include "../../crypto/cms.h"
#include "../../crypto/des.h"
#include "../../crypto/moccms.h"
#include "../../crypto/moccms_util.h"

#include <stdio.h>

/* File under test */
#include "../../crypto/cms_resign_util.c"

static MSTATUS
CMS_RESIGN_TEST_GetCertFun(const void* arg,
                           ubyte* pSerialNumber,
                           ubyte4 serialNumberLen,
                           ubyte* pIssuer,
                           ubyte4 issuerLen,
                           ubyte** ppCertificate,
                           ubyte4* pCertificateLen);

static MSTATUS
CMS_RESIGN_TEST_ValCertFun(const void* arg,
                           ubyte* pCertificate,
                           ubyte4 certificateLen);

static MSTATUS
CMS_RESIGN_TEST_GetPrivateKey(const void* arg,
                              ubyte* pSerialNumber,
                              ubyte4 serialNumberLen,
                              ubyte* pIssuer,
                              ubyte4 issuerLen,
                              struct AsymmetricKey* pKey);

static MSTATUS
CMS_RESIGN_TEST_GetPrivateKeyFun(const void* arg,
                                 const MOC_CMS_RecipientId* pRecipientId,
                                 struct AsymmetricKey* pKey);

static MSTATUS
CMS_RESIGN_TEST_CMSCallback(const void* arg,
                            MOC_CMS_context pCtx,
                            MOC_CMS_UpdateType type,
                            ubyte* pBuf,
                            ubyte4 bufLen);

/************************************************************************/

static int gTestScenario = 0;

#define CMS_RESIGN_TEST_LOCATECERT 1
#define CMS_RESIGN_TEST_VALIDATECERT 1

/*----------------------------------------------------------------------*/

int cms_resign_util_test_AcquireContext()
{
    MSTATUS status;
    int retval = 0;

    CMS_ResignData_CTX ctx = NULL;

    status = CMS_RESIGN_AcquireContext (&ctx);
    retval += UNITTEST_STATUS (10, status);
    if (retval > 0)
        goto exit;

    retval += UNITTEST_VALIDPTR(11, ctx);

exit:
    CMS_RESIGN_ReleaseContext (&ctx);
    return retval;
}

/*----------------------------------------------------------------------*/

int cms_resign_util_test_setExtractedData()
{
    MSTATUS status;
    int    retval = 0;
    sbyte4 cmpResult = -1;

    CMS_ResignData_CTX ctx = NULL;
    static const ubyte payload[] = {
            0x1, 0x2, 0x3, 0x4
    };

    ubyte  *pStored = NULL;
    ubyte4 storedLen;

    status = CMS_RESIGN_AcquireContext (&ctx);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    /* This will make an internal copy */
    status = CMS_RESIGN_setExtractedData (ctx,
                                          payload, sizeof(payload));
    retval += UNITTEST_STATUS (10, status);
    if (retval > 0)
        goto exit;

    /* Access the copy */
    CMS_RESIGN_getExtractedData (ctx,
                                 &pStored, &storedLen);

    retval += UNITTEST_INT (20, storedLen, sizeof(payload));
    retval += UNITTEST_TRUE (20, pStored != payload);
    if (retval > 0)
        goto exit;

    /* Compare the actual data */
    status = DIGI_MEMCMP (pStored, payload, storedLen, &cmpResult);
    retval += UNITTEST_STATUS (21, status);
    if (retval > 0)
        goto exit;
    retval += UNITTEST_INT (21, cmpResult, 0);

exit:
    CMS_RESIGN_ReleaseContext (&ctx);
    return retval;
}

/*----------------------------------------------------------------------*/

int cms_resign_util_test_setExtractedCertificates()
{
    MSTATUS status;
    int    retval = 0;
    sbyte4 cmpResult = -1;

    CMS_ResignData_CTX ctx = NULL;
    static const ubyte payload[] = {
            0x1, 0x2, 0x3, 0x4
    };

    ubyte  *pStored = NULL;
    ubyte4 storedLen;

    status = CMS_RESIGN_AcquireContext (&ctx);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    status = CMS_RESIGN_setExtractedCertificates (ctx,
                                                  payload, sizeof(payload));
    retval += UNITTEST_STATUS (10, status);
    if (retval > 0)
        goto exit;

    /* Access the copy */
    CMS_RESIGN_getExtractedCertificates (ctx,
                                         &pStored, &storedLen);

    retval += UNITTEST_INT (20, storedLen, sizeof(payload));
    retval += UNITTEST_TRUE (20, pStored != payload);
    if (retval > 0)
        goto exit;

    /* Compare the actual data */
    status = DIGI_MEMCMP (pStored, payload, storedLen, &cmpResult);
    retval += UNITTEST_STATUS (21, status);
    if (retval > 0)
        goto exit;
    retval += UNITTEST_INT (21, cmpResult, 0);

exit:
    CMS_RESIGN_ReleaseContext (&ctx);
    return retval;
}

/*----------------------------------------------------------------------*/

int cms_resign_util_test_setExtractedSignature()
{
    MSTATUS status;
    int     retval = 0;
    sbyte4  cmpResult = -1;

    CMS_ResignData_CTX ctx = NULL;
    static const ubyte payload[] = {
            0x1, 0x2, 0x3, 0x4
    };

    ubyte  *pStored = NULL;
    ubyte4 storedLen;

    status = CMS_RESIGN_AcquireContext (&ctx);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    status = CMS_RESIGN_setExtractedSignature (ctx,
                                               payload, sizeof(payload));
    retval += UNITTEST_STATUS (10, status);
    if (retval > 0)
        goto exit;

    /* Access the copy */
    CMS_RESIGN_getExtractedSignature (ctx,
                                      &pStored, &storedLen);

    retval += UNITTEST_INT (20, storedLen, sizeof(payload));
    retval += UNITTEST_TRUE (20, pStored != payload);
    if (retval > 0)
        goto exit;

    /* Compare the actual data */
    status = DIGI_MEMCMP (pStored, payload, storedLen, &cmpResult);
    retval += UNITTEST_STATUS (21, status);
    if (retval > 0)
        goto exit;
    retval += UNITTEST_INT (21, cmpResult, 0);

exit:
    CMS_RESIGN_ReleaseContext (&ctx);
    return retval;
}

/*----------------------------------------------------------------------*/

int cms_resign_util_test_setExtractedSignatureClear()
{
    MSTATUS status;
    int    retval = 0;

    CMS_ResignData_CTX ctx = NULL;
    static const ubyte payload[] = {
            0x1, 0x2, 0x3, 0x4
    };

    ubyte  *pStored = NULL;
    ubyte4 storedLen;

    status = CMS_RESIGN_AcquireContext (&ctx);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    status = CMS_RESIGN_setExtractedSignature (ctx,
                                               payload, sizeof(payload));
    retval += UNITTEST_STATUS (10, status);
    if (retval > 0)
        goto exit;

    /* Access the copy */
    CMS_RESIGN_getExtractedSignature (ctx,
                                      &pStored, &storedLen);

    retval += UNITTEST_INT (20, storedLen, sizeof(payload));
    retval += UNITTEST_VALIDPTR (20, pStored);
    if (retval > 0)
        goto exit;

    /* Clear */
    CMS_RESIGN_clearExtractedSignature (ctx);

    /* Access the copy */
    CMS_RESIGN_getExtractedSignature (ctx,
                                      &pStored, &storedLen);

    retval += UNITTEST_INT (30, storedLen, 0);
    retval += UNITTEST_TRUE (30, NULL == pStored);

exit:
    CMS_RESIGN_ReleaseContext (&ctx);
    return retval;
}

/*----------------------------------------------------------------------*/

int cms_resign_util_test_setExtractedSignatureHashType()
{
    MSTATUS status;
    int    retval = 0, idx;

    CMS_ResignData_CTX ctx = NULL;

    static ubyte4 hashes[] = {
            4, 5, 11, 12, 13, 14
    };

    status = CMS_RESIGN_AcquireContext (&ctx);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    /* Ensure all hash ids are valid */
    for (idx = 0; idx < (sizeof(hashes)/sizeof(ubyte4)); ++idx)
    {
        ubyte** pArr = NULL;
        int     numA = 0, counter;

        status = CMS_RESIGN_setExtractedSignatureHashType (ctx, hashes[idx]);
        retval += UNITTEST_STATUS (10+idx, status);
        if (retval > 0)
            goto exit;

        /* Read back */
        CMS_RESIGN_getExtractedSignature_OIDs (ctx, &pArr);
        retval += UNITTEST_VALIDPTR (20+idx, pArr);
        if (retval > 0)
            goto exit;

        numA = CMS_RESIGN_getNumSigningAlgos ();
        retval += UNITTEST_TRUE (30+idx, numA > 0);
        if (retval > 0)
            goto exit;

        /* Count entries */
        counter = 0;
        while (0 < numA)
        {
            --numA;
            if (NULL != pArr[numA])
                counter++;
        }

        /* Should find exactly the 'idx'+1 value */
        retval += UNITTEST_INT (40+idx, counter, idx+1);
    }

exit:
    CMS_RESIGN_ReleaseContext (&ctx);
    return retval;
}

/*----------------------------------------------------------------------*/

int cms_resign_util_test_setExtractedSignatureHashTypeFail()
{
    MSTATUS status;
    int    retval = 0, idx;

    CMS_ResignData_CTX ctx = NULL;

    status = CMS_RESIGN_AcquireContext (&ctx);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    status = CMS_RESIGN_setExtractedSignatureHashType (ctx, 0);
    retval += UNITTEST_TRUE (10, OK != status);

    status = CMS_RESIGN_setExtractedSignatureHashType (ctx, 8);
    retval += UNITTEST_TRUE (11, OK != status);

    status = CMS_RESIGN_setExtractedSignatureHashType (ctx, 45678);
    retval += UNITTEST_TRUE (12, OK != status);

exit:
    CMS_RESIGN_ReleaseContext (&ctx);
    return retval;
}

/*----------------------------------------------------------------------*/

int cms_resign_util_test_clearExtractedSignature_OID()
{
    MSTATUS status;
    int    retval = 0, idx;

    CMS_ResignData_CTX ctx = NULL;
    int                numA = 0;

    static ubyte4 hashes[] = {
            4, 5, 11, 12, 13, 14
    };

    status = CMS_RESIGN_AcquireContext (&ctx);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    /* Set all hash ids */
    for (idx = 0; idx < (sizeof(hashes)/sizeof(ubyte4)); ++idx)
    {
        status = CMS_RESIGN_setExtractedSignatureHashType (ctx, hashes[idx]);
        retval += UNITTEST_STATUS (10+idx, status);
        if (retval > 0)
            goto exit;
    }

    /* Save off total */
    numA = CMS_RESIGN_getNumSigningAlgos (/*pCtx*/);
    retval += UNITTEST_TRUE (20, numA > 0);
    if (retval > 0)
        goto exit;

    /* Clear one OID after another */
    for (idx = 0; idx < numA; ++idx)
    {
        ubyte** pArr = NULL;
        int     counter, num;

        /* Clear the 'idx' entry */
        CMS_RESIGN_clearExtractedSignature_OID (ctx, idx);

        /* Read back */
        CMS_RESIGN_getExtractedSignature_OIDs (ctx, &pArr);
        retval += UNITTEST_VALIDPTR (30+idx, pArr);
        if (retval > 0)
            goto exit;

        /* Count entries */
        counter = 0;
        num = numA;
        while (0 < num)
        {
            --num;
            if (NULL != pArr[num])
                counter++;
        }

        /* Should find exactly the 'numA'-'idx+1' value */
        retval += UNITTEST_INT (40+idx, counter, numA-(idx+1));
    }

exit:
    CMS_RESIGN_ReleaseContext (&ctx);
    return retval;
}
