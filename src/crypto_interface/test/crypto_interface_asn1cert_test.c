/*
 *  asn1cert_test.c
 *
 *   unit test for asn1cert.c
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

#if defined(__ENABLE_DIGICERT_DSA__) && defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__)
#undef __ENABLE_DIGICERT_DSA__
#endif
#include "../../crypto/asn1cert.c"
#include "../../common/memfile.h"
#include "../../crypto/ca_mgmt.h"
#include "../../common/initmocana.h"

extern MSTATUS
CA_MGMT_extractKeyBlobEx(const ubyte *pKeyBlob, ubyte4 keyBlobLength,
                         AsymmetricKey* pKey);

#include "../../../unit_tests/unittest.h"

static MocCtx gpMocCtx = NULL;

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
    (sbyte*) "150710080000Z",                   /* certificate start date */
    (sbyte*) "250710080000Z"                    /* certificate end date */

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

static int test_VerifyExtensions()
{
    MSTATUS status = OK;
    const char* keyblobFile= FILE_PATH("keyblobFile.dat");
    ubyte* pKeyBlob= NULL;
    ubyte4 keyBlobLen;
    AsymmetricKey key = { 0};
    ubyte* pSelfSignedCert = NULL;
    ubyte4 selfSignedCertLen;
    MemFile memFile;
    CStream cs;
    ASN1_ITEMPTR pSelfCertRoot = NULL;
    ASN1_ITEMPTR pExtensions = NULL;
    ASN1_ITEMPTR pExtension = NULL;
    intBoolean  critical = FALSE;

    hwAccelDescr        hwAccelCtx;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_INIT()))
        return status;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return status;

    if (OK > (status = DIGICERT_readFile( keyblobFile, &pKeyBlob, &keyBlobLen)))
        goto exit;

    /* load the key */
    if (OK > ( status = CA_MGMT_extractKeyBlobEx(pKeyBlob, keyBlobLen, &key)))
        goto exit;

    if ( OK > ( status = ASN1CERT_generateSelfSignedCertificate(MOC_ASYM(hwAccelCtx)
                                                      &key, &gCertInfo,
                                                      ht_sha256,
                                                      &gExts2,
                                                      RANDOM_rngFun, g_pRandomContext,
                                                      &pSelfSignedCert, &selfSignedCertLen)))
        goto exit;

    if ( OK > ( status = DIGICERT_writeFile( "mytestselfcert.der",
                                          pSelfSignedCert, selfSignedCertLen)))
        goto exit;

    /* verify certificate */
    MF_attach(&memFile, selfSignedCertLen, (ubyte*) pSelfSignedCert);
    CS_AttachMemFile(&cs, &memFile);

    ASN1_Parse(cs, &pSelfCertRoot);

    if (OK > ( status = X509_getCertificateExtensions( ASN1_FIRST_CHILD(pSelfCertRoot),
                                                      &pExtensions)))
    {
        goto exit;
    }

    if ( !pExtensions)
    {
        status = ERR_FALSE;
        goto exit;
    }

    /* verify basic constraint exists and is critical */
    if (OK > (status = X509_getCertExtension( pExtensions, cs,
                                             basicConstraints_OID,
                                             &critical, &pExtension)))
    {
        goto exit;
    }

    if ( !pExtension || (0xFF != (ubyte)critical))
    {
        status = ERR_FALSE;
        goto exit;
    }

exit:
    if (pKeyBlob)
    {
        FREE(pKeyBlob);
    }
    if (pSelfSignedCert)
    {
        FREE(pSelfSignedCert);
    }
    if (pSelfCertRoot)
    {
        TREE_DeleteTreeItem((TreeItem*) pSelfCertRoot);
    }

    CRYPTO_uninitAsymmetricKey( &key, NULL);

    (void) HARDWARE_ACCEL_UNINIT();
    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return UNITTEST_STATUS(3, status);
}

/*---------------------------------------------------------------------------*/

int crypto_interface_asn1cert_test_init()
{
  int errorCount = 0;
    
/* This test uses a keyblob with a 1023 bit key, this will not work with mbed */
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
  MSTATUS status = ERR_NULL_POINTER;

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

  /* START Tests */
  errorCount += test_VerifyExtensions ();
  /* END   Tests */

exit:
  DIGICERT_free(&gpMocCtx);
#endif
  return errorCount;
}

