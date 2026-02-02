/*
 * moccms_util_test.c
 *
 * Unit tests for CMS Utility/Shim - moccms_util.c
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
#include "../../crypto/mocasym.h"

#include "../../harness/harness.h"

#include <stdio.h>

/* File under test */
#include "../../crypto/moccms_util.c"


/*----------------------------------------------------------------------*/

int moccms_util_test_parseX509()
{
    MSTATUS status;
    int retval = 0;

    MAsn1Element *pRoot = NULL;
    MAsn1Element *pTBS = NULL;
    ubyte        *pCert = NULL;
    ubyte4       certLen;

    /* Read test CA cert from file */
    status = DIGICERT_readFile("CS_RSACertCA.der", &pCert, &certLen);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    status = DIGI_CMS_U_parseX509 (pCert, certLen,
                                  &pRoot, &pTBS);
    retval += UNITTEST_STATUS (10, status);
    if (retval > 0)
        goto exit;

    retval += UNITTEST_VALIDPTR(11, pRoot);
    retval += UNITTEST_VALIDPTR(11, pTBS);

exit:
    MAsn1FreeElementArray (&pTBS);
    MAsn1FreeElementArray (&pRoot);
    DIGI_FREE ((void**)&pCert);
    return retval;
}

/*----------------------------------------------------------------------*/

int moccms_util_test_parseX509Fail()
{
    MSTATUS status;
    int retval = 0;

    MAsn1Element *pRoot = NULL;
    MAsn1Element *pTBS = NULL;
    ubyte        *pCert = NULL;
    ubyte4       certLen;

    /* Read test file that contains NO valid X509 data */
    status = DIGICERT_readFile("ecc_enveloped.der", &pCert, &certLen);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    /* This should FAIL */
    status = DIGI_CMS_U_parseX509 (pCert, certLen,
                                  &pRoot, &pTBS);
    retval += UNITTEST_TRUE (10, OK != status);

exit:
    MAsn1FreeElementArray (&pTBS);
    MAsn1FreeElementArray (&pRoot);
    DIGI_FREE ((void**)&pCert);
    return retval;
}

/*----------------------------------------------------------------------*/

int moccms_util_test_getCertificateExtensions()
{
    MSTATUS status;
    int retval = 0;

    ubyte        *pCert = NULL, *pExt = NULL;
    ubyte4       certLen, extLen;

    /* Read test CA cert from file that has extensions */
    status = DIGICERT_readFile("CS_RSACertCA.der", &pCert, &certLen);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    status = DIGI_CMS_U_getCertificateExtensions (pCert, certLen,
                                                 &pExt, &extLen);
    retval += UNITTEST_STATUS (10, status);
    if (retval > 0)
        goto exit;

    retval += UNITTEST_VALIDPTR(11, pExt);
    retval += UNITTEST_TRUE(11, 0 < extLen);

exit:
    DIGI_FREE ((void**)&pCert);
    return retval;
}

/*----------------------------------------------------------------------*/

int moccms_util_test_locateExtensionByOID()
{
    MSTATUS status;
    int retval = 0;

    ubyte      *pCert = NULL, *pExt = NULL;
    ubyte4     certLen, extLen;

    intBoolean crit = FALSE;
    ubyte      *pVal;
    ubyte4     valLen;

    /* Basic Constraints OID: 2.5.29.19 */
    static ubyte pOID[] = { 0x06, 0x03, 0x55, 0x1D, 0x13 };

    /* Read test CA cert from file that has extensions */
    status = DIGICERT_readFile("CS_RSACertCA.der", &pCert, &certLen);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    status = DIGI_CMS_U_getCertificateExtensions (pCert, certLen,
                                                 &pExt, &extLen);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    retval += UNITTEST_VALIDPTR(1, pExt);
    retval += UNITTEST_TRUE(1, 0 < extLen);
    if (retval > 0)
        goto exit;

    /* Locate an entry with OID */
    status = DIGI_CMS_U_locateExtensionByOID (pExt, extLen,
                                             pOID, sizeof(pOID),
                                             &crit, &pVal, &valLen);
    retval += UNITTEST_STATUS (10, status);
    if (retval > 0)
        goto exit;

    /* Critical BOOL = 0xFF */
    retval += UNITTEST_INT(11, crit, 0xFF);
    /* SEQ of len 5 */
    retval += UNITTEST_INT(11, valLen, 5);

exit:
    DIGI_FREE ((void**)&pCert);
    return retval;
}

/*----------------------------------------------------------------------*/

int moccms_util_test_locateExtensionByOIDDefaultBool()
{
    MSTATUS status;
    int retval = 0;

    ubyte      *pCert = NULL, *pExt = NULL;
    ubyte4     certLen, extLen;

    intBoolean crit = FALSE;
    ubyte      *pVal;
    ubyte4     valLen;

    /* Subject Key Identifier OID: 2.5.29.14 */
    static ubyte pOID[] = { 0x06, 0x03, 0x55, 0x1D, 0x0E };

    /* Read test CA cert from file that has extensions */
    status = DIGICERT_readFile("dsacert.der", &pCert, &certLen);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    status = DIGI_CMS_U_getCertificateExtensions (pCert, certLen,
                                                 &pExt, &extLen);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    retval += UNITTEST_VALIDPTR(1, pExt);
    retval += UNITTEST_TRUE(1, 0 < extLen);
    if (retval > 0)
        goto exit;

    /* Locate an entry with OID, which has no BOOL field */
    status = DIGI_CMS_U_locateExtensionByOID (pExt, extLen,
                                             pOID, sizeof(pOID),
                                             &crit, &pVal, &valLen);
    retval += UNITTEST_STATUS (10, status);
    if (retval > 0)
        goto exit;

    /* Critical BOOL = DEFAULT = 0 */
    retval += UNITTEST_INT(11, crit, 0);

exit:
    DIGI_FREE ((void**)&pCert);
    return retval;
}

/*----------------------------------------------------------------------*/

int moccms_util_test_locateExtensionByOIDFail()
{
    MSTATUS status;
    int retval = 0;

    ubyte      *pCert = NULL, *pExt = NULL;
    ubyte4     certLen, extLen;

    intBoolean crit = FALSE;
    ubyte      *pVal;
    ubyte4     valLen;

    /* Missing OID: 2.5.29.1 */
    static ubyte pOID[] = { 0x06, 0x03, 0x55, 0x1D, 0x1 };

    /* Read test CA cert from file that has extensions */
    status = DIGICERT_readFile("CS_RSACertCA.der", &pCert, &certLen);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    status = DIGI_CMS_U_getCertificateExtensions (pCert, certLen,
                                                 &pExt, &extLen);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    retval += UNITTEST_VALIDPTR(1, pExt);
    retval += UNITTEST_TRUE(1, 0 < extLen);
    if (retval > 0)
        goto exit;

    /* Locate an entry with the unused OID */
    status = DIGI_CMS_U_locateExtensionByOID (pExt, extLen,
                                             pOID, sizeof(pOID),
                                             &crit, &pVal, &valLen);
    retval += UNITTEST_TRUE (10, OK != status);

exit:
    DIGI_FREE ((void**)&pCert);
    return retval;
}

/*----------------------------------------------------------------------*/

int moccms_util_test_checkCertificateIssuerBoundary()
{
    MSTATUS status;
    int retval = 0;

    ubyte  *pASN = (ubyte*)0xFACE;
    ubyte4 asnLen = 4;

    status = DIGI_CMS_U_checkCertificateIssuer (NULL, 0,
                                               pASN, asnLen);
    retval += UNITTEST_TRUE(10, OK != status);

    status = DIGI_CMS_U_checkCertificateIssuer (pASN, asnLen,
                                               NULL, 0);
    retval += UNITTEST_TRUE(11, OK != status);

    return retval;
}

/*----------------------------------------------------------------------*/

int moccms_util_test_checkCertificateIssuer()
{
    MSTATUS status;
    int retval = 0;

    ubyte  *pParent = NULL, *pChild = NULL;
    ubyte4 parentLen, childLen;

    /* Read parent cert from file */
    status = DIGICERT_readFile("CS_RSACertCA.der", &pParent, &parentLen);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    /* Read child cert from file */
    status = DIGICERT_readFile("CS_RSACert_2.der", &pChild, &childLen);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    /* check relationship: Parent -> Child */
    status = DIGI_CMS_U_checkCertificateIssuer (pParent, parentLen,
                                               pChild, childLen);
    retval += UNITTEST_TRUE(10, OK == status);

    /* check relationship: Child -> Parent */
    status = DIGI_CMS_U_checkCertificateIssuer (pChild, childLen,
                                               pParent, parentLen);
    retval += UNITTEST_TRUE(11, ERR_FALSE == status);

    /* check relationship: Child -> Child */
    status = DIGI_CMS_U_checkCertificateIssuer (pChild, childLen,
                                               pChild, childLen);
    retval += UNITTEST_TRUE(12, ERR_FALSE == status);

exit:
    DIGI_FREE ((void**)&pChild);
    DIGI_FREE ((void**)&pParent);
    return retval;
}

/*----------------------------------------------------------------------*/

int moccms_util_test_parseX509CertForPublicKeyBoundary()
{
    MSTATUS status;
    int     retval = 0;

    ubyte   *pCert = (ubyte*)0xFACE;
    ubyte4  certLen = 0;
    ubyte   *pKey;
    ubyte4  keyLen;

    status = DIGI_CMS_U_parseX509CertForPublicKey (NULL, certLen,
                                                  &pKey, &keyLen);
    retval += UNITTEST_TRUE (10, OK != status);

    status = DIGI_CMS_U_parseX509CertForPublicKey (pCert, certLen,
                                                  NULL, &keyLen);
    retval += UNITTEST_TRUE (11, OK != status);

    status = DIGI_CMS_U_parseX509CertForPublicKey (pCert, certLen,
                                                  &pKey, NULL);
    retval += UNITTEST_TRUE (12, OK != status);

    return retval;
}

/*----------------------------------------------------------------------*/

int moccms_util_test_parseX509CertForPublicKey()
{
    MSTATUS status;
    int     retval = 0;
    sbyte4  cmpResult = -1;

    ubyte   *pCert = NULL;
    ubyte4  certLen;
    ubyte   *pKey;
    ubyte4  keyLen;

    static ubyte expectedKey[] = {
            0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
            0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
            0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xe7, 0x14, 0x4d,
            0xca, 0x7b, 0xed, 0x54, 0x01, 0x7d, 0x35, 0x97, 0x41, 0x64, 0xe5, 0xc2,
            0x59, 0xb9, 0x82, 0x1f, 0xd7, 0xa6, 0xb7, 0x4e, 0x62, 0xa9, 0x5d, 0x3d,
            0xcd, 0x0d, 0xd9, 0xba, 0x98, 0xfc, 0x71, 0x56, 0x6e, 0x94, 0x0d, 0x46,
            0xdf, 0x75, 0x6b, 0x20, 0xaa, 0xf3, 0x1f, 0xcb, 0x78, 0x99, 0x1c, 0xd6,
            0xe5, 0xf4, 0x7e, 0xa3, 0x7d, 0x5d, 0x76, 0x48, 0xc5, 0x5f, 0x4f, 0xf9,
            0x3f, 0xca, 0x2b, 0x90, 0x71, 0xf5, 0x40, 0x35, 0xaf, 0x4f, 0x32, 0xdf,
            0x50, 0x80, 0x8f, 0x11, 0x07, 0x66, 0x13, 0xd6, 0x82, 0x18, 0xdc, 0xad,
            0xc0, 0xac, 0x2d, 0x4f, 0xcd, 0x28, 0x2d, 0xe2, 0x21, 0x46, 0x9e, 0xce,
            0x07, 0x70, 0x41, 0xde, 0x1d, 0x19, 0xd6, 0x82, 0x8c, 0x87, 0xdb, 0x33,
            0xc6, 0x5c, 0xee, 0xdc, 0x2e, 0xc9, 0x46, 0x32, 0x9a, 0x60, 0x7c, 0xbf,
            0x85, 0xe7, 0x93, 0x58, 0xae, 0x84, 0xe4, 0x0d, 0x85, 0xad, 0x3a, 0xe5,
            0xbe, 0x0c, 0xb3, 0xe5, 0x10, 0xfc, 0x54, 0x5b, 0xb2, 0xd8, 0x0a, 0x95,
            0xf2, 0x20, 0x30, 0x6d, 0x64, 0xd4, 0x21, 0xc8, 0xbb, 0x62, 0x89, 0xdf,
            0xed, 0xf5, 0x31, 0x1a, 0xca, 0x3d, 0x85, 0x1c, 0x40, 0x70, 0x9f, 0x45,
            0xe2, 0x2f, 0x76, 0xf6, 0x16, 0x01, 0xae, 0xcc, 0xfa, 0x18, 0x04, 0x03,
            0x64, 0xcd, 0xe9, 0x12, 0xb5, 0xd0, 0x82, 0x07, 0x91, 0x01, 0x40, 0x56,
            0x13, 0xac, 0x78, 0x6a, 0x24, 0x14, 0xd5, 0x30, 0xce, 0x79, 0xd8, 0x06,
            0x18, 0x2b, 0x4d, 0x6b, 0xc0, 0xd6, 0xd4, 0xed, 0x92, 0x8f, 0xfb, 0x91,
            0x15, 0x97, 0xae, 0x5f, 0x23, 0x5a, 0xbb, 0x83, 0xd3, 0x1f, 0x55, 0x2e,
            0x5b, 0xbb, 0x97, 0xf2, 0x1e, 0xbe, 0xea, 0x6b, 0xde, 0x3b, 0x9b, 0x7d,
            0x78, 0xef, 0x80, 0x22, 0x9a, 0x94, 0xa3, 0xf3, 0x97, 0x64, 0x33, 0x45,
            0xe1, 0x02, 0x03, 0x01, 0x00, 0x01
    };

    /* Read test CA cert from file */
    status = DIGICERT_readFile("CS_RSACertCA.der", &pCert, &certLen);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    /* Try to read public key data */
    status = DIGI_CMS_U_parseX509CertForPublicKey (pCert, certLen,
                                                  &pKey, &keyLen);
    retval += UNITTEST_STATUS (10, status);
    if (retval > 0)
        goto exit;

    /* Confirm we found it */
    retval += UNITTEST_INT (11, keyLen, sizeof (expectedKey));
    if (retval > 0)
        goto exit;

    status = DIGI_MEMCMP (pKey, expectedKey, sizeof (expectedKey), &cmpResult);
    retval += UNITTEST_STATUS (12, status);
    if (retval > 0)
        goto exit;

    retval += UNITTEST_INT (12, cmpResult, 0);

exit:
    DIGI_FREE ((void**)&pCert);
    return retval;
}

/*----------------------------------------------------------------------*/

int moccms_util_test_parseX509CertForSubjectBoundary()
{
    MSTATUS status;
    int     retval = 0;

    ubyte   *pCert = (ubyte*)0xFACE;
    ubyte4  certLen = 0;
    ubyte   *pSubj;
    ubyte4  subjLen;

    status = DIGI_CMS_U_parseX509CertForSubject (NULL, certLen,
                                                &pSubj, &subjLen);
    retval += UNITTEST_TRUE (10, OK != status);

    status = DIGI_CMS_U_parseX509CertForSubject (pCert, certLen,
                                                NULL, &subjLen);
    retval += UNITTEST_TRUE (11, OK != status);

    status = DIGI_CMS_U_parseX509CertForSubject (pCert, certLen,
                                                &pSubj, NULL);
    retval += UNITTEST_TRUE (12, OK != status);

    return retval;
}

/*----------------------------------------------------------------------*/

int moccms_util_test_parseX509CertForSubject()
{
    MSTATUS status;
    int     retval = 0;
    sbyte4  cmpResult = -1;

    ubyte   *pCert = NULL;
    ubyte4  certLen;
    ubyte   *pSubj;
    ubyte4  subjLen;

    static ubyte expectedSubj[] = {
            0x30, 0x81, 0xb8, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
            0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04,
            0x08, 0x13, 0x0a, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69,
            0x61, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x0d,
            0x53, 0x61, 0x6e, 0x20, 0x46, 0x72, 0x61, 0x6e, 0x63, 0x69, 0x73, 0x63,
            0x6f, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x12,
            0x4d, 0x6f, 0x63, 0x61, 0x6e, 0x61, 0x20, 0x43, 0x6f, 0x72, 0x70, 0x6f,
            0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x31, 0x22, 0x30, 0x20, 0x06, 0x03,
            0x55, 0x04, 0x0b, 0x13, 0x19, 0x45, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x65,
            0x72, 0x69, 0x6e, 0x67, 0x20, 0x43, 0x41, 0x20, 0x28, 0x52, 0x53, 0x41,
            0x20, 0x32, 0x30, 0x34, 0x38, 0x29, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03,
            0x55, 0x04, 0x03, 0x13, 0x12, 0x73, 0x73, 0x6c, 0x74, 0x65, 0x73, 0x74,
            0x2e, 0x6d, 0x6f, 0x63, 0x61, 0x6e, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x31,
            0x1e, 0x30, 0x1c, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
            0x09, 0x01, 0x16, 0x0f, 0x69, 0x6e, 0x66, 0x6f, 0x40, 0x6d, 0x6f, 0x63,
            0x61, 0x6e, 0x61, 0x2e, 0x63, 0x6f, 0x6d
    };

    /* Read test CA cert from file */
    status = DIGICERT_readFile("CS_RSACertCA.der", &pCert, &certLen);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    /* Try to read subject name */
    status = DIGI_CMS_U_parseX509CertForSubject (pCert, certLen,
                                                &pSubj, &subjLen);
    retval += UNITTEST_STATUS (10, status);
    if (retval > 0)
        goto exit;

    /* Confirm we found it */
    retval += UNITTEST_INT (11, subjLen, sizeof (expectedSubj));
    if (retval > 0)
        goto exit;

    status = DIGI_MEMCMP (pSubj, expectedSubj, sizeof (expectedSubj), &cmpResult);
    retval += UNITTEST_STATUS (12, status);
    if (retval > 0)
        goto exit;

    retval += UNITTEST_INT (12, cmpResult, 0);

exit:
    DIGI_FREE ((void**)&pCert);
    return retval;
}

/*----------------------------------------------------------------------*/

int moccms_util_test_parseX509CertForIssuerNameBoundary()
{
    MSTATUS status;
    int     retval = 0;

    ubyte   *pCert = (ubyte*)0xFACE;
    ubyte4  certLen = 0;
    ubyte   *pIssuer;
    ubyte4  issuerLen;

    status = DIGI_CMS_U_parseX509CertForIssuerName (NULL, certLen,
                                                   &pIssuer, &issuerLen);
    retval += UNITTEST_TRUE (10, OK != status);

    status = DIGI_CMS_U_parseX509CertForIssuerName (pCert, certLen,
                                                   NULL, &issuerLen);
    retval += UNITTEST_TRUE (11, OK != status);

    status = DIGI_CMS_U_parseX509CertForIssuerName (pCert, certLen,
                                                   &pIssuer, NULL);
    retval += UNITTEST_TRUE (12, OK != status);

    return retval;
}

/*----------------------------------------------------------------------*/

int moccms_util_test_parseX509CertForIssuerName()
{
    MSTATUS status;
    int     retval = 0;
    sbyte4  cmpResult = -1;

    ubyte   *pCert = NULL;
    ubyte4  certLen;
    ubyte   *pIssuer;
    ubyte4  issuerLen;

    static ubyte expectedIssuer[] = {
            0x30, 0x81, 0xb8, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
            0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04,
            0x08, 0x13, 0x0a, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69,
            0x61, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x0d,
            0x53, 0x61, 0x6e, 0x20, 0x46, 0x72, 0x61, 0x6e, 0x63, 0x69, 0x73, 0x63,
            0x6f, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x12,
            0x4d, 0x6f, 0x63, 0x61, 0x6e, 0x61, 0x20, 0x43, 0x6f, 0x72, 0x70, 0x6f,
            0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x31, 0x22, 0x30, 0x20, 0x06, 0x03,
            0x55, 0x04, 0x0b, 0x13, 0x19, 0x45, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x65,
            0x72, 0x69, 0x6e, 0x67, 0x20, 0x43, 0x41, 0x20, 0x28, 0x52, 0x53, 0x41,
            0x20, 0x32, 0x30, 0x34, 0x38, 0x29, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03,
            0x55, 0x04, 0x03, 0x13, 0x12, 0x73, 0x73, 0x6c, 0x74, 0x65, 0x73, 0x74,
            0x2e, 0x6d, 0x6f, 0x63, 0x61, 0x6e, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x31,
            0x1e, 0x30, 0x1c, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
            0x09, 0x01, 0x16, 0x0f, 0x69, 0x6e, 0x66, 0x6f, 0x40, 0x6d, 0x6f, 0x63,
            0x61, 0x6e, 0x61, 0x2e, 0x63, 0x6f, 0x6d
    };

    /* Read test CA cert from file */
    status = DIGICERT_readFile("CS_RSACertCA.der", &pCert, &certLen);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    /* Try to read issuer name */
    status = DIGI_CMS_U_parseX509CertForIssuerName (pCert, certLen,
                                                   &pIssuer, &issuerLen);
    retval += UNITTEST_STATUS (10, status);
    if (retval > 0)
        goto exit;

    /* Confirm we found it */
    retval += UNITTEST_INT (11, issuerLen, sizeof (expectedIssuer));
    if (retval > 0)
        goto exit;

    status = DIGI_MEMCMP (pIssuer, expectedIssuer, sizeof (expectedIssuer), &cmpResult);
    retval += UNITTEST_STATUS (12, status);
    if (retval > 0)
        goto exit;

    retval += UNITTEST_INT (12, cmpResult, 0);

exit:
    DIGI_FREE ((void**)&pCert);
    return retval;
}

/*----------------------------------------------------------------------*/

int moccms_util_test_parseX509CertForISerialNumberBoundary()
{
    MSTATUS status;
    int     retval = 0;

    ubyte   *pCert = (ubyte*)0xFACE;
    ubyte4  certLen;
    ubyte   *pSerial;
    ubyte4  serialLen;

    status = DIGI_CMS_U_parseX509CertForSerialNumber (NULL, certLen,
                                                     &pSerial, &serialLen);
    retval += UNITTEST_TRUE (10, OK != status);

    status = DIGI_CMS_U_parseX509CertForSerialNumber (pCert, certLen,
                                                     NULL, &serialLen);
    retval += UNITTEST_TRUE (11, OK != status);

    status = DIGI_CMS_U_parseX509CertForSerialNumber (pCert, certLen,
                                                     &pSerial, NULL);
    retval += UNITTEST_TRUE (12, OK != status);

    return retval;
}

/*----------------------------------------------------------------------*/

int moccms_util_test_parseX509CertForSerialNumber()
{
    MSTATUS status;
    int     retval = 0;
    sbyte4  cmpResult = -1;

    ubyte   *pCert = NULL;
    ubyte4  certLen;
    ubyte   *pSerial;
    ubyte4  serialLen;

    static ubyte expectedSerial[] = {
            0x41, 0x6d, 0xd4, 0xc2, 0x91, 0x8f, 0x5a, 0xa6, 0x99, 0xab,
            0x85, 0x43, 0x81, 0x95, 0x99, 0xb4, 0xb8, 0x0e, 0x9a, 0x26
    };

    /* Read test CA cert from file */
    status = DIGICERT_readFile("CS_RSACertCA.der", &pCert, &certLen);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    /* Try to read serial number */
    status = DIGI_CMS_U_parseX509CertForSerialNumber (pCert, certLen,
                                                     &pSerial, &serialLen);
    retval += UNITTEST_STATUS (10, status);
    if (retval > 0)
        goto exit;

    /* Confirm we found it */
    retval += UNITTEST_INT (11, serialLen, sizeof (expectedSerial));
    if (retval > 0)
        goto exit;

    status = DIGI_MEMCMP (pSerial, expectedSerial, sizeof (expectedSerial), &cmpResult);
    retval += UNITTEST_STATUS (12, status);
    if (retval > 0)
        goto exit;

    retval += UNITTEST_INT (12, cmpResult, 0);

exit:
    DIGI_FREE ((void**)&pCert);
    return retval;
}

/*----------------------------------------------------------------------*/

int moccms_util_test_setKeyFromSubjectPublicKeyInfoBoundary()
{
    MSTATUS status;
    int     retval = 0;

    ubyte   *pCert = (ubyte*)0xFACE;
    ubyte4  certLen;
    AsymmetricKey key = { 0 };

    status = DIGI_CMS_U_setKeyFromSubjectPublicKeyInfo (NULL, certLen,
                                                       &key);
    retval += UNITTEST_TRUE (10, OK != status);

    status = DIGI_CMS_U_setKeyFromSubjectPublicKeyInfo (pCert, certLen,
                                                       NULL);
    retval += UNITTEST_TRUE (11, OK != status);

    return retval;
}

/*----------------------------------------------------------------------*/

int moccms_util_test_setKeyFromSubjectPublicKeyInfo()
{
    MSTATUS status;
    int     retval = 0;

    ubyte   *pCert = NULL;
    ubyte4  certLen;
    AsymmetricKey key = { 0 };

    /* Read RSA cert from file */
    status = DIGICERT_readFile("CS_RSACert_2.der", &pCert, &certLen);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    status = DIGI_CMS_U_setKeyFromSubjectPublicKeyInfo (pCert, certLen,
                                                       &key);
    retval += UNITTEST_STATUS (10, status);
    if (retval > 0)
        goto exit;

    /* RSA? */
    retval += UNITTEST_INT (11, key.type, akt_rsa);
    if (retval > 0)
        goto exit;

#ifdef __ENABLE_DIGICERT_ECC__
    /* clean up */
    CRYPTO_uninitAsymmetricKey (&key, NULL);
    DIGI_FREE ((void**)&pCert);

    /* Read ECDH cert from file */
    status = DIGICERT_readFile("CS_ECDHCert384.der", &pCert, &certLen);
    retval += UNITTEST_STATUS (20, status);
    if (retval > 0)
        goto exit;

    status = DIGI_CMS_U_setKeyFromSubjectPublicKeyInfo (pCert, certLen,
                                                       &key);
    retval += UNITTEST_STATUS (30, status);
    if (retval > 0)
        goto exit;

    /* ECC? */
    retval += UNITTEST_INT (31, key.type, akt_ecc);
    if (retval > 0)
        goto exit;
#else
    printf("ECC Disabled: 'setKeyFromSubjectPublicKeyInfo' skipped reading ECC key!\n");
#endif

#ifdef __ENABLE_DIGICERT_DSA__
    /* clean up */
    CRYPTO_uninitAsymmetricKey (&key, NULL);
    DIGI_FREE ((void**)&pCert);

    /* Read DSA cert from file */
    status = DIGICERT_readFile("dsacert.der", &pCert, &certLen);
    retval += UNITTEST_STATUS (40, status);
    if (retval > 0)
        goto exit;

    status = DIGI_CMS_U_setKeyFromSubjectPublicKeyInfo (pCert, certLen,
                                                       &key);
    retval += UNITTEST_STATUS (50, status);
    if (retval > 0)
        goto exit;

    /* DSA? */
    retval += UNITTEST_INT (51, key.type, akt_dsa);
    if (retval > 0)
        goto exit;
#else
    printf("DSA Disabled: 'setKeyFromSubjectPublicKeyInfo' skipped reading DSA key!\n");
#endif

exit:
    CRYPTO_uninitAsymmetricKey (&key, NULL);
    DIGI_FREE ((void**)&pCert);
    return retval;
}

/*----------------------------------------------------------------------*/

int moccms_util_test_verifyCertificateSignatureBoundary()
{
    MSTATUS status;
    int retval = 0;

    ubyte  *pChild = (ubyte*)0xFACE;
    ubyte4 childLen = 0;

    AsymmetricKey parentKey = {0};
    intBoolean    invalid = -1;

    status = DIGI_CMS_U_verifyCertificateSignature (NULL, childLen,
                                                   &parentKey,
                                                   &invalid);
    retval += UNITTEST_TRUE(10, OK != status);

    status = DIGI_CMS_U_verifyCertificateSignature (pChild, childLen,
                                                   NULL,
                                                   &invalid);
    retval += UNITTEST_TRUE(11, OK != status);

    status = DIGI_CMS_U_verifyCertificateSignature (pChild, childLen,
                                                   &parentKey,
                                                   NULL);
    retval += UNITTEST_TRUE(12, OK != status);

    return retval;
}

/*----------------------------------------------------------------------*/

int moccms_util_test_verifyCertificateSignature()
{
    MSTATUS status;
    int retval = 0;

    ubyte  *pParent = NULL, *pChild = NULL;
    ubyte4 parentLen, childLen;

    AsymmetricKey parentKey = {0};
    intBoolean    invalid = -1;

    /* Read parent cert from file */
    status = DIGICERT_readFile("CS_RSACertCA.der", &pParent, &parentLen);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    /* Read child cert from file */
    status = DIGICERT_readFile("CS_RSACert_2.der", &pChild, &childLen);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    /* Get public key from parent */
    status = DIGI_CMS_U_setKeyFromSubjectPublicKeyInfo (pParent, parentLen,
                                                       &parentKey);
    retval += UNITTEST_STATUS (1, status);
    if (retval > 0)
        goto exit;

    /* Check signature */
    status = DIGI_CMS_U_verifyCertificateSignature (pChild, childLen,
                                                   &parentKey,
                                                   &invalid);
    retval += UNITTEST_STATUS (10, status);
    if (retval > 0)
        goto exit;

    /* Signature should not fail */
    retval += UNITTEST_INT(11, invalid, 0);

exit:
    CRYPTO_uninitAsymmetricKey (&parentKey, NULL);
    DIGI_FREE ((void**)&pChild);
    DIGI_FREE ((void**)&pParent);
    return retval;
}

/*----------------------------------------------------------------------*/

int moccms_util_test_verifyCertificateSignatureFail()
{
    MSTATUS status;
    int retval = 0;

    ubyte  *pParent = NULL, *pChild = NULL;
    ubyte4 parentLen, childLen;

    AsymmetricKey parentKey = {0};
    intBoolean    invalid = -1;

    /* Read parent cert from file */
    status = DIGICERT_readFile("CS_RSACertCA.der", &pParent, &parentLen);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    /* Read child cert from file */
    status = DIGICERT_readFile("CS_RSACert_2.der", &pChild, &childLen);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    /* Try to change public key string: Locate INTEGER field with 256 bytes key value */
    if ((0x2 == pChild[481]) && (0x82 == pChild[482]) &&
        (0x1 == pChild[483]) && (0x1 == pChild[484]))
    {
        pChild[485+128] = 0x00;
        pChild[485+129] = 0x00;
    }
    else
    {
        printf("Unexpected CERT data! FAIL!\n");
        retval++;
    }

    /* Get public key from parent */
    status = DIGI_CMS_U_setKeyFromSubjectPublicKeyInfo (pParent, parentLen,
                                                       &parentKey);
    retval += UNITTEST_STATUS (1, status);
    if (retval > 0)
        goto exit;

    /* Check signature */
    status = DIGI_CMS_U_verifyCertificateSignature (pChild, childLen,
                                                   &parentKey,
                                                   &invalid);
    /* Signature should fail */
    retval += UNITTEST_TRUE (10, ERR_CERT_INVALID_SIGNATURE == status);

exit:
    CRYPTO_uninitAsymmetricKey (&parentKey, NULL);
    DIGI_FREE ((void**)&pChild);
    DIGI_FREE ((void**)&pParent);
    return retval;
}

/*----------------------------------------------------------------------*/

int moccms_util_test_validateLinkBoundary()
{
    MSTATUS status;
    int retval = 0;

    ubyte  *pRoot = (ubyte*)0xFACE;
    ubyte4 rootLen = 10;

    status = DIGI_CMS_U_validateLink (NULL, 0,
                                     pRoot, rootLen);
    retval += UNITTEST_TRUE (10, OK != status);

    status = DIGI_CMS_U_validateLink (pRoot, rootLen,
                                     NULL, 0);
    retval += UNITTEST_TRUE (11, OK != status);

    return retval;
}

/*----------------------------------------------------------------------*/

int moccms_util_test_validateLink()
{
    MSTATUS status;
    int retval = 0;

    ubyte      *pParent = NULL, *pChild = NULL;
    ubyte4     parentLen, childLen;
    intBoolean invalid = -1;

    /* Read parent cert from file */
    status = DIGICERT_readFile("CS_RSACertCA.der", &pParent, &parentLen);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    /* Read child cert from file */
    status = DIGICERT_readFile("CS_RSACert_2.der", &pChild, &childLen);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    status = DIGI_CMS_U_validateLink (pChild, childLen,
                                     pParent, parentLen);
    retval += UNITTEST_STATUS (10, status);

exit:
    DIGI_FREE ((void**)&pChild);
    DIGI_FREE ((void**)&pParent);
    return retval;
}

/*----------------------------------------------------------------------*/

int moccms_util_test_validateLinkFail()
{
    MSTATUS status;
    int retval = 0;

    ubyte      *pParent = NULL, *pChild = NULL;
    ubyte4     parentLen, childLen;

    intBoolean invalid = -1;

    /* Read parent cert from file */
    status = DIGICERT_readFile("CS_RSACertCA.der", &pParent, &parentLen);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    /* Read child cert from file */
    status = DIGICERT_readFile("CS_RSACert_2.der", &pChild, &childLen);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    /* Try to change public key string: Locate INTEGER field with 256 bytes key value */
    if ((0x2 == pChild[481]) && (0x82 == pChild[482]) &&
        (0x1 == pChild[483]) && (0x1 == pChild[484]))
    {
        pChild[485+128] = 0x00;
        pChild[485+129] = 0x00;
    }
    else
    {
        printf("Unexpected CERT data! FAIL!\n");
        retval++;
    }

    status = DIGI_CMS_U_validateLink (pChild, childLen,
                                     pParent, parentLen);
    /* Signature should fail */
    retval += UNITTEST_TRUE (10, ERR_CERT_INVALID_SIGNATURE == status);

exit:
    DIGI_FREE ((void**)&pChild);
    DIGI_FREE ((void**)&pParent);
    return retval;
}

/*----------------------------------------------------------------------*/

int moccms_util_test_isRootCertificateBoundary()
{
    MSTATUS status;
    int retval = 0;

    ubyte  *pRoot = (ubyte*)0xFACE;
    ubyte4 rootLen;

    status = DIGI_CMS_U_isRootCertificate (NULL, rootLen);
    retval += UNITTEST_TRUE (10, OK != status);

    return retval;
}

/*----------------------------------------------------------------------*/

int moccms_util_test_isRootCertificate()
{
    MSTATUS status;
    int retval = 0;

    ubyte  *pRoot = NULL;
    ubyte4 rootLen;

    /* Read CA root cert from file: Has no 'Subject Key Extension' */
    status = DIGICERT_readFile("CS_RSACertCA.der", &pRoot, &rootLen);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    /* This should pass */
    status = DIGI_CMS_U_isRootCertificate (pRoot, rootLen);
    retval += UNITTEST_STATUS (10, status);

    /* clean up */
    DIGI_FREE ((void**)&pRoot);

    /* Read CA root cert from file: Has 'Subject Key Extension' */
    status = DIGICERT_readFile("openssl_cert1.der", &pRoot, &rootLen);
    retval += UNITTEST_STATUS (20, status);
    if (retval > 0)
        goto exit;

    /* This should pass */
    status = DIGI_CMS_U_isRootCertificate (pRoot, rootLen);
    retval += UNITTEST_STATUS (30, status);

exit:
    DIGI_FREE ((void**)&pRoot);
    return retval;
}

/*----------------------------------------------------------------------*/

int moccms_util_test_isRootCertificateFail()
{
    MSTATUS status;
    int retval = 0;

    ubyte  *pRoot = NULL;
    ubyte4 rootLen;

    /* Read child cert from file */
    status = DIGICERT_readFile("CS_RSACert_2.der", &pRoot, &rootLen);
    retval += UNITTEST_STATUS (0, status);
    if (retval > 0)
        goto exit;

    /* This should not pass */
    status = DIGI_CMS_U_isRootCertificate (pRoot, rootLen);
    retval += UNITTEST_TRUE (10, ERR_FALSE == status);

exit:
    DIGI_FREE ((void**)&pRoot);
    return retval;
}
