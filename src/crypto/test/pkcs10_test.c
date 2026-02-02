/*
 * pkcs10_test.c
 *
 * unit test for pkcs10.c
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

#include "../pkcs10.c"
#include "../../common/initmocana.h"
#include "../../asn1/ASN1TreeWalker.h"

#include "../../../unit_tests/unittest.h"

static nameAttr pNames1[] =
{
    {countryName_OID, 0, (ubyte*)"US", 2}                                /* country */
};
static nameAttr pNames2[] =
{
    {stateOrProvinceName_OID, 0, (ubyte*)"California", 10}                       /* state or providence */
};
static nameAttr pNames3[] =
{
    {localityName_OID, 0, (ubyte*)"Menlo Park", 10}                       /* locality */
};
static nameAttr pNames4[] =
{
    {organizationName_OID, 0, (ubyte*)"Mocana Corporation", 18}               /* company name */
};
static nameAttr pNames5[] =
{
    {organizationalUnitName_OID, 0, (ubyte*)"Engineering", 11}                      /* organizational unit */
};
static nameAttr pNames6[] =
{
    {commonName_OID, 0, (ubyte*)"sslexample.mocana.com", 21}            /* common name */
};
static nameAttr pNames7[] =
{
    {pkcs9_emailAddress_OID, 0, (ubyte*)"info@mocana.com", 15}          /* pkcs-9-at-emailAddress */
};

static relativeDN pRDNs[] =
{
    {pNames1, 1},
    {pNames2, 1},
    {pNames3, 1},
    {pNames4, 1},
    {pNames5, 1},
    {pNames6, 1},
    {pNames7, 1}
};

static certDistinguishedName gCertInfo =
{
    pRDNs,
    7,
/* Note: Internet Explorer limits a 30 year lifetime for certificates */

                                                /* time format yymmddhhmmss */
    (sbyte*) "060828000126Z",                   /* certificate start date */
    (sbyte*) "160827230126Z"                    /* certificate end date */

/* above start example, May 26th, 2006 12:01:26 AM */
/* above end example, May 24th, 2008 11:01:26 PM */

};

static certExtensions gExts2 =
{
		1, /* has basicconstraint */
		1, /* isCA? */
		5, /* certPathLen */
		0, /* has keyUsage */
		0, /* keyUsage */
        NULL, /* no other extensions */
        0
};

static certExtensions gExts =
{
		1, /* has basicconstraint */
		1, /* isCA? */
		5, /* certPathLen */
		1, /* has keyUsage */
		15, /* keyUsage */
        NULL, /* no other extensions */
        0
};

static requestAttributes gReqAttrs =
{
	/* challengePassword */
	(sbyte*) "password", 8,
	/* certExtensions */
	&gExts
};

const ubyte msEnrollNameValuePair_OID[];

const ubyte msEnrollNameValuePair_OID[] =
  { 10, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0D, 0x01, 0x01 };

const ubyte pMsEnrollValue[52] =
{
  0x30, 0x32, 0x1e, 0x26, 0x00, 0x43, 0x00, 0x65,
  0x00, 0x72, 0x00, 0x74, 0x00, 0x69, 0x00, 0x66,
  0x00, 0x69, 0x00, 0x63, 0x00, 0x61, 0x00, 0x74,
  0x00, 0x65, 0x00, 0x54, 0x00, 0x65, 0x00, 0x6d,
  0x00, 0x70, 0x00, 0x6c, 0x00, 0x61, 0x00, 0x74,
  0x00, 0x65, 0x1e, 0x08, 0x00, 0x55, 0x00, 0x73,
  0x00, 0x65, 0x00, 0x72
};

static MocRequestAttr moreAttr =
{
  (ubyte *)msEnrollNameValuePair_OID,
  (ubyte *)pMsEnrollValue,
  52
};

static requestAttributesEx gReqAttrsEx =
{
  /* challengePassword */
  (sbyte*) "password", 8,
  /* certExtensions */
  &gExts,
  /* other attributes */
  &moreAttr, 1
};


static int GenerateCertReq(int hint, const char* outFileName, ubyte signAlgo, AsymmetricKey* pKey)
{
    MSTATUS status = OK;
    ubyte* pCertReq = NULL;
    ubyte4 certReqLen;
    MemFile memFile;
    CStream cs;
    ASN1_ITEMPTR pCertReqRoot=NULL, pCertReqInfo, pFound;
    int retVal = 0;

    /* verify CertificationRequest structure, stop at CertificationRequestInfo node */
    static WalkerStep verifyCertReqPart1[] =
    {
        { GoFirstChild, 0, 0},
        { VerifyType, SEQUENCE, 0},
        { GoFirstChild, 0, 0},
        { VerifyType, SEQUENCE, 0}, /* certificationRequestInfo is a SEQUENCE */
        { GoNextSibling, 0, 0},
        { VerifyType, SEQUENCE, 0}, /* signatureAlgorithm */
        { GoFirstChild, 0, 0},
        { VerifyType, OID, 0},
        { GoParent, 0, 0},
        { GoNextSibling, 0, 0},
        { VerifyType, BITSTRING, 0}, /* signature */
        { GoParent, 0, 0},
        { GoFirstChild, 0, 0},
        { Complete, 0, 0}
    };

    /* verify the CertificationRequestInfo structure */
    static WalkerStep verifyCertReqPart2[] =
    {
        { GoFirstChild, 0, 0},
        { VerifyInteger, 0, 0}, /* version is an integer of 0 */
        { GoNextSibling, 0, 0},
        { VerifyType, SEQUENCE, 0}, /* subject */
        { GoNextSibling, 0, 0}, /* should be a subjectPKInfo structure */
        { VerifyType, SEQUENCE, 0},
        { GoFirstChild, 0, 0},
        { VerifyType, SEQUENCE, 0},
        { GoFirstChild, 0,0 },
        { VerifyType, OID, 0},
        { GoParent, 0, 0},
        { GoNextSibling, 0, 0},
        { VerifyType, BITSTRING, 0}, /* subjectPublicKey is a bitstring */
        { GoParent, 0, 0},
        { GoNextSibling, 0, 0},
        { VerifyTag, 0, 0}, /* attributes has tag 0, one challengePassord, one extReq */
        { GoFirstChild, 0, 0},
        { VerifyType, SEQUENCE, 0},
        { GoFirstChild, 0, 0}, /* first attribute is challengePassword */
        { VerifyOID, 0, (ubyte *)pkcs9_challengePassword_OID},
        { GoNextSibling, 0, 0},
        { VerifyType, MOC_SET, 0},
        { GoParent, 0, 0},
        { GoNextSibling, 0, 0},
        { GoFirstChild, 0, 0},
        { VerifyOID, 0, (ubyte *)pkcs9_extensionRequest_OID}, /* second attribute is extReq */
        { GoNextSibling, 0, 0},
        { VerifyType, MOC_SET, 0},
        { Complete, 0, 0}
    };

    retVal += UNITTEST_STATUS(hint, PKCS10_GenerateCertReqFromDN(pKey, signAlgo,
                                                                 &gCertInfo,
                                                                 &gReqAttrs,
                                                                 &pCertReq,
                                                                 &certReqLen));

	if (retVal) goto exit;

    /* verify certificate request format by walking the tree */
    MF_attach(&memFile, certReqLen, (ubyte*) pCertReq);
    CS_AttachMemFile(&cs, &memFile);

    ASN1_Parse(cs, &pCertReqRoot);

    retVal += UNITTEST_STATUS(hint, ASN1_WalkTree( pCertReqRoot, cs, verifyCertReqPart1, &pCertReqInfo));
	if (retVal) goto exit;

    retVal += UNITTEST_STATUS(hint, ASN1_WalkTree( pCertReqInfo, cs, verifyCertReqPart2, &pFound));
	if (retVal) goto exit;

    /* write it to a file just so one can look at it */
    retVal += UNITTEST_STATUS(hint, DIGICERT_writeFile(outFileName, pCertReq, certReqLen));

exit:
    if (pCertReq)
    {
        FREE(pCertReq);
    }
    if (pCertReqRoot)
    {
        TREE_DeleteTreeItem((TreeItem*) pCertReqRoot);
    }

    return retVal;
}

static int GenerateCertReqEx (
  int hint, const char* outFileName, ubyte signAlgo, AsymmetricKey* pKey)
{
  ubyte* pCertReq = NULL;
  ubyte4 certReqLen;
  MemFile memFile;
  CStream cs;
  ASN1_ITEMPTR pCertReqRoot=NULL, pCertReqInfo, pFound;
  int retVal = 0;

  /* verify CertificationRequest structure, stop at CertificationRequestInfo node */
  static WalkerStep verifyCertReqPart1[] =
  {
    { GoFirstChild, 0, 0},
      { VerifyType, SEQUENCE, 0},
      { GoFirstChild, 0, 0},
      { VerifyType, SEQUENCE, 0}, /* certificationRequestInfo is a SEQUENCE */
      { GoNextSibling, 0, 0},
      { VerifyType, SEQUENCE, 0}, /* signatureAlgorithm */
      { GoFirstChild, 0, 0},
      { VerifyType, OID, 0},
      { GoParent, 0, 0},
      { GoNextSibling, 0, 0},
      { VerifyType, BITSTRING, 0}, /* signature */
      { GoParent, 0, 0},
      { GoFirstChild, 0, 0},
      { Complete, 0, 0}
  };

  /* verify the CertificationRequestInfo structure */
  static WalkerStep verifyCertReqPart2[] =
  {
    { GoFirstChild, 0, 0},
      { VerifyInteger, 0, 0}, /* version is an integer of 0 */
      { GoNextSibling, 0, 0},
      { VerifyType, SEQUENCE, 0}, /* subject */
      { GoNextSibling, 0, 0}, /* should be a subjectPKInfo structure */
      { VerifyType, SEQUENCE, 0},
      { GoFirstChild, 0, 0},
      { VerifyType, SEQUENCE, 0},
      { GoFirstChild, 0,0 },
      { VerifyType, OID, 0},
      { GoParent, 0, 0},
      { GoNextSibling, 0, 0},
      { VerifyType, BITSTRING, 0}, /* subjectPublicKey is a bitstring */
      { GoParent, 0, 0},
      { GoNextSibling, 0, 0},
      { VerifyTag, 0, 0}, /* attributes has tag 0, three attributes */
      { GoFirstChild, 0, 0},
      { VerifyType, SEQUENCE, 0},
      { GoFirstChild, 0, 0}, /* first attribute is challengePassword */
      { VerifyOID, 0, (ubyte *)pkcs9_challengePassword_OID},
      { GoNextSibling, 0, 0},
      { VerifyType, MOC_SET, 0},
      { GoParent, 0, 0},
      { GoNextSibling, 0, 0},
      { GoFirstChild, 0, 0},
      { VerifyOID, 0, (ubyte *)msEnrollNameValuePair_OID}, /* second attribute is msEnroll */
      { GoNextSibling, 0, 0},
      { VerifyType, MOC_SET, 0},
      { GoParent, 0, 0},
      { GoNextSibling, 0, 0},
      { GoFirstChild, 0, 0},
      { VerifyOID, 0, (ubyte *)pkcs9_extensionRequest_OID}, /* second attribute is extReq */
      { GoNextSibling, 0, 0},
      { VerifyType, MOC_SET, 1},
      { Complete, 0, 0}
  };

  retVal += UNITTEST_STATUS(hint, PKCS10_GenerateCertReqFromDNEx (
    pKey, signAlgo,
    &gCertInfo,
    &gReqAttrsEx,
    &pCertReq,
    &certReqLen));

  if (retVal) goto exit;

  /* verify certificate request format by walking the tree */
  MF_attach(&memFile, certReqLen, (ubyte*) pCertReq);
  CS_AttachMemFile(&cs, &memFile);

  ASN1_Parse(cs, &pCertReqRoot);

  retVal += UNITTEST_STATUS(hint, ASN1_WalkTree( pCertReqRoot, cs, verifyCertReqPart1, &pCertReqInfo));
  if (retVal) goto exit;

  retVal += UNITTEST_STATUS(hint, ASN1_WalkTree( pCertReqInfo, cs, verifyCertReqPart2, &pFound));
  if (retVal) goto exit;

  /* write it to a file just so one can look at it */
  retVal += UNITTEST_STATUS(hint, DIGICERT_writeFile(outFileName, pCertReq, certReqLen));

exit:
  if (pCertReq)
  {
    FREE(pCertReq);
  }
  if (pCertReqRoot)
  {
    TREE_DeleteTreeItem((TreeItem*) pCertReqRoot);
  }

  return retVal;
}


int pkcs10_test_GenerateCertReq()
{
    MSTATUS status = OK;
    char* keyblobFile= FILE_PATH("keyblobFile.dat");
    ubyte* pKeyBlob = NULL;
    ubyte4 keyBlobLen;
    AsymmetricKey key = { 0 };
    int retVal = 0;
    hwAccelDescr hwAccelCtx;

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
    
    retVal += UNITTEST_STATUS(0, DIGICERT_initialize(&setupInfo, NULL));
    if (retVal) goto exit;

    retVal += UNITTEST_STATUS(0, (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx));
    if (retVal) goto exit;

    retVal += UNITTEST_STATUS(0, DIGICERT_readFile( keyblobFile, &pKeyBlob, &keyBlobLen));
    if (retVal) goto exit;

	/* load the key */
	CA_MGMT_extractKeyBlobEx(pKeyBlob, keyBlobLen, &key);


    retVal += GenerateCertReq(0, "cert_req_rsa_md5.der", ht_md5, &key);

    retVal += GenerateCertReq(1, "cert_req_rsa_sha1.der", ht_sha1, &key);

    retVal += GenerateCertReq(2, "cert_req_rsa_sha224.der", ht_sha224, &key);

    retVal += GenerateCertReq(3, "cert_req_rsa_sha256.der", ht_sha256, &key);

    retVal += GenerateCertReq(4, "cert_req_rsa_sha384.der", ht_sha384, &key);

    retVal += GenerateCertReq(5, "cert_req_rsa_sha512.der", ht_sha512, &key);

exit:
    if (pKeyBlob)
    {
        FREE(pKeyBlob);
    }

    CRYPTO_uninitAsymmetricKey(&key, NULL);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    DIGICERT_freeDigicert();

    return retVal;
}


int pkcs10_test_GenerateECCCertReq()
{
    MSTATUS status = OK;
    AsymmetricKey key;
    int retVal = 0;
    hwAccelDescr hwAccelCtx;
    ECCKey* pECCKey;

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
    
    retVal += UNITTEST_STATUS(0, DIGICERT_initialize(&setupInfo, NULL));
    if (retVal) goto exit;

    retVal += UNITTEST_STATUS(0, (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx));
    if (retVal) goto exit;

    retVal += UNITTEST_STATUS(0, CRYPTO_initAsymmetricKey(&key));
    if (retVal) goto exit;

    retVal += UNITTEST_STATUS(0, CRYPTO_createECCKey(&key, EC_P256));
    if (retVal) goto exit;

    pECCKey = key.key.pECC;

    retVal += UNITTEST_STATUS(0, EC_generateKeyPair(EC_P256, RANDOM_rngFun, g_pRandomContext,
                                                    pECCKey->k, pECCKey->Qx, pECCKey->Qy));
    if (retVal) goto exit;

    pECCKey->privateKey = TRUE;

    retVal += GenerateCertReq(11, "cert_req_ecc_sha1.der", ht_sha1, &key);

    retVal += GenerateCertReq(12, "cert_req_ecc_sha224.der", ht_sha224, &key);

    retVal += GenerateCertReq(13, "cert_req_ecc_sha256.der", ht_sha256, &key);

    retVal += GenerateCertReq(14, "cert_req_ecc_sha384.der", ht_sha384, &key);

    retVal += GenerateCertReq(15, "cert_req_ecc_sha512.der", ht_sha512, &key);

exit:


    CRYPTO_uninitAsymmetricKey(&key, NULL);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    DIGICERT_freeDigicert();

    return retVal;
}


int pkcs10_test_GenerateECCCertReqEx ()
{
  AsymmetricKey key;
  int retVal = 0;
  hwAccelDescr hwAccelCtx;
  ECCKey* pECCKey;

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
  
  retVal += UNITTEST_STATUS(0, DIGICERT_initialize(&setupInfo, NULL));
  if (retVal) goto exit;

  retVal += UNITTEST_STATUS(0, (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx));
  if (retVal) goto exit;

  retVal += UNITTEST_STATUS(0, CRYPTO_initAsymmetricKey(&key));
  if (retVal) goto exit;

  retVal += UNITTEST_STATUS(0, CRYPTO_createECCKey(&key, EC_P256));
  if (retVal) goto exit;

  pECCKey = key.key.pECC;

  retVal += UNITTEST_STATUS(0, EC_generateKeyPair(EC_P256, RANDOM_rngFun, g_pRandomContext,
    pECCKey->k, pECCKey->Qx, pECCKey->Qy));
  if (retVal) goto exit;

  pECCKey->privateKey = TRUE;

  retVal += GenerateCertReqEx(11, "cert_req_ecc_sha1.der", ht_sha1, &key);

  retVal += GenerateCertReqEx(12, "cert_req_ecc_sha224.der", ht_sha224, &key);

  retVal += GenerateCertReqEx(13, "cert_req_ecc_sha256.der", ht_sha256, &key);

  retVal += GenerateCertReqEx(14, "cert_req_ecc_sha384.der", ht_sha384, &key);

  retVal += GenerateCertReqEx(15, "cert_req_ecc_sha512.der", ht_sha512, &key);

exit:

  CRYPTO_uninitAsymmetricKey(&key, NULL);

  HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

  DIGICERT_freeDigicert();
  
  return retVal;
}

