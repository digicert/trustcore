/*
 * crypto_interface_cert_store_test.c
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
#include "../../common/moptions.h"

#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"

#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../common/tree.h"
#include "../../common/absstream.h"
#include "../../common/memfile.h"
#include "../../common/sizedbuffer.h"
#include "../../common/random.h"
#include "../../asn1/parseasn1.h"
#include "../../asn1/parsecert.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/ca_mgmt.h"
#include "../../crypto/cert_store.h"
#include "../../crypto/pqc/pqc_ser.h"
#include "../../common/initmocana.h"

#include "../../../unit_tests/unittest.h"

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

static const char* gRootCerts[] =
{
    FILE_PATH("Equifax_Secure_Certificate_Authority.der"), /* subject= /C=US/O=Equifax/OU=Equifax Secure Certificate Authority */
    FILE_PATH("VerisignClass3RootG5.der"),                 /* subject= /C=US/O=VeriSign, Inc./OU=VeriSign Trust Network/OU=(c) 2006 VeriSign, Inc. - For authorized use only/CN=VeriSign Class 3 Public Primary Certification Authority - G5 */
    FILE_PATH("VerisignClass3RootMD2.der"),                /* subject= /C=US/O=VeriSign, Inc./OU=Class 3 Public Primary Certification Authority */
    FILE_PATH("VerisignClass3RootSHA1.der"),               /* subject= /C=US/O=VeriSign, Inc./OU=Class 3 Public Primary Certification Authority */
    FILE_PATH("VerisignClass1PublicPrimaryCAMD2.der"),     /* subject= /C=US/O=VeriSign, Inc./OU=Class 1 Public Primary Certification Authority */
    FILE_PATH("VerisignClass1PublicPrimaryCASHA1.der"),    /* subject= /C=US/O=VeriSign, Inc./OU=Class 1 Public Primary Certification Authority */
/* These ones are fake trust points (issuer names are matches those of some above but keys are wrong) */
    FILE_PATH("FakeEquifax_Secure_Certificate_Authority.der"), /* subject= /C=US/O=Equifax/OU=Equifax Secure Certificate Authority */
    FILE_PATH("FakeVerisignClass3RootG5.der"),    /* subject= /C=US/O=VeriSign, Inc./OU=VeriSign Trust Network/OU=(c) 2006 VeriSign, Inc. - For authorized use only/CN=VeriSign Class 3 Public Primary Certification Authority - G5 */
    FILE_PATH("FakeVerisignClass3RootMD2.der"),   /* subject= /C=US/O=VeriSign, Inc./OU=Class 3 Public Primary Certification Authority */
    FILE_PATH("FakeVerisignClass3RootSHA1.der"),  /* subject= /C=US/O=VeriSign, Inc./OU=Class 3 Public Primary Certification Authority */

};

/* number of certificates in the store with the same subject when
 all certificates have been loaded */
static const sbyte4 gNumCertsWithSameSubject[] =
{
    2,
    2,
    4,
    4,
    2,
    2,
    2,
    2,
    4,
    4,
};


typedef struct CertStoreTestInfo
{
    ubyte* der;
    ubyte4 derLen;
    ubyte4 subjectOffset;
    ubyte4 subjectLen;

} CertStoreTestInfo;

static CertStoreTestInfo gCertStoreTestInfo[ COUNTOF(gRootCerts)];

#define TEST_SUBJECT_ARGS(i)  gCertStoreTestInfo[i].der + gCertStoreTestInfo[i].subjectOffset, \
    gCertStoreTestInfo[i].subjectLen


#define CERTIFICATE_INFO( cf) { cf".der", cf"Key.dat"}
#define LEAF_CERTIFICATE_INFO(cf, cacf) { cf".der", cf"Key.dat", cacf".der"}

typedef struct CertificateInfo
{
    const char* certFileName;
    const char* keyFileName;
    const char* parentCertFileName;
} CertificateInfo;

static CertificateInfo gCertificateInfos[] =
{
    LEAF_CERTIFICATE_INFO( FILE_PATH("CS_ECDHCert256"), FILE_PATH("CS_RSACertCA")),       /* digital Signature, Key Agreement */
    LEAF_CERTIFICATE_INFO( FILE_PATH("CS_ECDHCert384"), FILE_PATH("CS_RSACertCA")),       /* digital Signature, Key Agreement */
    LEAF_CERTIFICATE_INFO( FILE_PATH("CS_RSACert_2"), FILE_PATH("CS_RSACertCA")),         /* digital Signature, Key Encipherment */
    LEAF_CERTIFICATE_INFO( FILE_PATH("CS_ECDHCert256_2"), FILE_PATH("CS_RSACertCA")),     /* digital Signature, Key Agreement */
    LEAF_CERTIFICATE_INFO( FILE_PATH("CS_ECDHCert384_2"), FILE_PATH("CS_RSACertCA")),     /* digital Signature, Key Agreement */
    LEAF_CERTIFICATE_INFO( FILE_PATH("CS_ECDHCert256_3"), FILE_PATH("CS_ECDHCert256CA")), /* digital Signature, Key Agreement */
    LEAF_CERTIFICATE_INFO( FILE_PATH("CS_ECDHCert384_3"), FILE_PATH("CS_ECDHCert384CA")), /* digital Signature, Key Agreement */
    /* Note: we add the root certs at the end to test that we
     can retrieve the keys of these certificates with
     CERT_STORE_findCertificateByIssuerSerialNumber
     even if they were registered earlier without key */
    CERTIFICATE_INFO( FILE_PATH("CS_RSACertCA")),                              /* digital Signature, Key Encipherment, Certificate Sign, CRL Sign */
    CERTIFICATE_INFO( FILE_PATH("CS_ECDHCert256CA")),                          /* digital Signature, Key Agreement, Certificate Sign, CRL Sign */
    CERTIFICATE_INFO( FILE_PATH("CS_ECDHCert384CA")),                          /* digital Signature, Key Agreement, Certificate Sign, CRL Sign */
};

typedef struct IdentityTest
{
    ubyte pubKeyType;
    ubyte4 supportedAlgoFlags;
    int  numChains;
} IdentityTest;


typedef struct IdentityTestEx
{
    ubyte pubKeyType;
    ubyte4 supportedAlgoFlags;
    ubyte2 keyUsage;
    int  numChains;
} IdentityTestEx;

static IdentityTest gIdentityTests[] =
{
    { akt_rsa, 0xFFFFFF, 2 },  /* 2 RSA chains */
    { akt_ecc, 0xFFFFFF, 8 },  /* 8 ECC chains */
    { akt_ecc, (CERT_STORE_ALGO_FLAG_HASHALGO |
                CERT_STORE_ALGO_FLAG_SIGNKEYTYPE |
                CERT_STORE_ALGO_FLAG_EC192 | CERT_STORE_ALGO_FLAG_EC224 |
                CERT_STORE_ALGO_FLAG_EC521),
        0 }, /* 0 ECC chains with these curves */
    { akt_ecc, (CERT_STORE_ALGO_FLAG_HASHALGO |
                CERT_STORE_ALGO_FLAG_SIGNKEYTYPE |
                CERT_STORE_ALGO_FLAG_EC256),
        4 },
    { akt_ecc, (CERT_STORE_ALGO_FLAG_HASHALGO |
                CERT_STORE_ALGO_FLAG_SIGNKEYTYPE |
                CERT_STORE_ALGO_FLAG_EC384),
        4 },
    { akt_ecc, (CERT_STORE_ALGO_FLAG_HASHALGO |
                CERT_STORE_ALGO_FLAG_SIGNKEYTYPE |
                CERT_STORE_ALGO_FLAG_EC384 | CERT_STORE_ALGO_FLAG_EC256),
        8 },
    { akt_ecc, (CERT_STORE_ALGO_FLAG_HASHALGO |
                CERT_STORE_ALGO_FLAG_RSA |
                CERT_STORE_ALGO_FLAG_EC384 | CERT_STORE_ALGO_FLAG_EC256),
        4 },
    { akt_ecc, (CERT_STORE_ALGO_FLAG_HASHALGO |
                CERT_STORE_ALGO_FLAG_ECDSA |
                CERT_STORE_ALGO_FLAG_EC384 | CERT_STORE_ALGO_FLAG_EC256),
        4 },
    { akt_ecc, (CERT_STORE_ALGO_FLAG_HASHALGO |
                CERT_STORE_ALGO_FLAG_DSA |
                CERT_STORE_ALGO_FLAG_EC384 | CERT_STORE_ALGO_FLAG_EC256),
        0 },
};

static IdentityTestEx gIdentityTestExs[] =
{
    /* duplicated tests === same as IdentityTest keyUsage = 0 */
    { akt_rsa, 0xFFFFFF, 0, 2 },  /* 2 RSA chains */
    { akt_ecc, 0xFFFFFF, 0, 8 },  /* 8 ECC chains */
    { akt_ecc, (CERT_STORE_ALGO_FLAG_HASHALGO |
                CERT_STORE_ALGO_FLAG_SIGNKEYTYPE |
                CERT_STORE_ALGO_FLAG_EC192 | CERT_STORE_ALGO_FLAG_EC224 |
                CERT_STORE_ALGO_FLAG_EC521),
        0, 0 }, /* 0 ECC chains with these curves */
    { akt_ecc, (CERT_STORE_ALGO_FLAG_HASHALGO |
                CERT_STORE_ALGO_FLAG_SIGNKEYTYPE |
                CERT_STORE_ALGO_FLAG_EC256),
        0, 4 },
    { akt_ecc, (CERT_STORE_ALGO_FLAG_HASHALGO |
                CERT_STORE_ALGO_FLAG_SIGNKEYTYPE |
                CERT_STORE_ALGO_FLAG_EC384),
        0, 4 },
    { akt_ecc, (CERT_STORE_ALGO_FLAG_HASHALGO |
                CERT_STORE_ALGO_FLAG_SIGNKEYTYPE |
                CERT_STORE_ALGO_FLAG_EC384 | CERT_STORE_ALGO_FLAG_EC256),
        0, 8 },
    { akt_ecc, (CERT_STORE_ALGO_FLAG_HASHALGO |
                CERT_STORE_ALGO_FLAG_RSA |
                CERT_STORE_ALGO_FLAG_EC384 | CERT_STORE_ALGO_FLAG_EC256),
        0, 4 },
    { akt_ecc, (CERT_STORE_ALGO_FLAG_HASHALGO |
                CERT_STORE_ALGO_FLAG_ECDSA |
                CERT_STORE_ALGO_FLAG_EC384 | CERT_STORE_ALGO_FLAG_EC256),
        0, 4 },
    { akt_ecc, (CERT_STORE_ALGO_FLAG_HASHALGO |
                CERT_STORE_ALGO_FLAG_DSA |
                CERT_STORE_ALGO_FLAG_EC384 | CERT_STORE_ALGO_FLAG_EC256),
        0, 0 },
    /* now restrict things a bit with key Usage */
    { akt_rsa, 0xFFFFFF, (1 << digitalSignature | 1 << keyEncipherment), 2 },  /* 2 RSA chains */
    { akt_rsa, 0xFFFFFF, (1 << digitalSignature | 1 << keyAgreement), 0 },  /* no RSA chains */
    { akt_ecc, 0xFFFFFF, (1 << digitalSignature | 1 << keyAgreement), 8 },  /* 8 ECC chains */
    { akt_ecc, 0xFFFFFF, (1 << digitalSignature | 1 << keyEncipherment), 0 },  /* no ECC chains */
    { akt_rsa, 0xFFFFFF, (1 << cRLSign), 1 },  /* 1 RSA chain can sign CRL*/
    { akt_ecc, 0xFFFFFF, (1 << cRLSign), 2 },  /* 2 ECC chains can sign CRL */
    { akt_rsa, 0xFFFFFF, (1 << dataEncipherment), 0 },  /* no RSA chain can dataEncipher */
    { akt_ecc, 0xFFFFFF, (1 << dataEncipherment), 0 },  /* mo ECC chain can dataEncipher */

    /* all ECC chains can do keyAgreement */
    { akt_ecc, (CERT_STORE_ALGO_FLAG_HASHALGO |
                CERT_STORE_ALGO_FLAG_SIGNKEYTYPE |
                CERT_STORE_ALGO_FLAG_EC256),
        (1 << digitalSignature | 1 << keyAgreement), 4 },
    { akt_ecc, (CERT_STORE_ALGO_FLAG_HASHALGO |
                CERT_STORE_ALGO_FLAG_SIGNKEYTYPE |
                CERT_STORE_ALGO_FLAG_EC384),
        (1 << digitalSignature | 1 << keyAgreement), 4 },
    { akt_ecc, (CERT_STORE_ALGO_FLAG_HASHALGO |
                CERT_STORE_ALGO_FLAG_SIGNKEYTYPE |
                CERT_STORE_ALGO_FLAG_EC384 | CERT_STORE_ALGO_FLAG_EC256),
        (1 << digitalSignature | 1 << keyAgreement), 8 },
    { akt_ecc, (CERT_STORE_ALGO_FLAG_HASHALGO |
                CERT_STORE_ALGO_FLAG_RSA |
                CERT_STORE_ALGO_FLAG_EC384 | CERT_STORE_ALGO_FLAG_EC256),
        (1 << digitalSignature | 1 << keyAgreement), 4 },
    { akt_ecc, (CERT_STORE_ALGO_FLAG_HASHALGO |
                CERT_STORE_ALGO_FLAG_ECDSA |
                CERT_STORE_ALGO_FLAG_EC384 | CERT_STORE_ALGO_FLAG_EC256),
        (1 << digitalSignature | 1 << keyAgreement), 4 },

    /* asking for CRL sign filters out some certs */
    { akt_ecc, (CERT_STORE_ALGO_FLAG_HASHALGO |
                CERT_STORE_ALGO_FLAG_SIGNKEYTYPE |
                CERT_STORE_ALGO_FLAG_EC256),
        (1 << cRLSign), 1 },
    { akt_ecc, (CERT_STORE_ALGO_FLAG_HASHALGO |
                CERT_STORE_ALGO_FLAG_SIGNKEYTYPE |
                CERT_STORE_ALGO_FLAG_EC384),
        (1 << cRLSign), 1},
    { akt_ecc, (CERT_STORE_ALGO_FLAG_HASHALGO |
                CERT_STORE_ALGO_FLAG_SIGNKEYTYPE |
                CERT_STORE_ALGO_FLAG_EC384 | CERT_STORE_ALGO_FLAG_EC256),
        (1 << cRLSign), 2},
    { akt_ecc, (CERT_STORE_ALGO_FLAG_HASHALGO |
                CERT_STORE_ALGO_FLAG_RSA |
                CERT_STORE_ALGO_FLAG_EC384 | CERT_STORE_ALGO_FLAG_EC256),
        (1 << cRLSign), 0 },
    { akt_ecc, (CERT_STORE_ALGO_FLAG_HASHALGO |
                CERT_STORE_ALGO_FLAG_ECDSA |
                CERT_STORE_ALGO_FLAG_EC384 | CERT_STORE_ALGO_FLAG_EC256),
        (1 << cRLSign), 2},

};



/*---------------------------------------------------------------------------*/

static int load_certStoreTest( int hint, const char* rootCertFileName,
                                CertStoreTestInfo* certStoreTestInfo)
{
    int retVal = 0;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRootItem = 0;
    ASN1_ITEMPTR pSubject;

    UNITTEST_STATUS_GOTO(hint,
                         DIGICERT_readFile(rootCertFileName,
                                         &certStoreTestInfo->der,
                                         &certStoreTestInfo->derLen),
                         retVal, exit);

    MF_attach(&mf, certStoreTestInfo->derLen, certStoreTestInfo->der);
    CS_AttachMemFile(&cs, &mf);

    UNITTEST_STATUS_GOTO(hint, ASN1_Parse( cs, &pRootItem), retVal, exit);
    UNITTEST_STATUS_GOTO(hint, X509_getCertificateSubject( ASN1_FIRST_CHILD(pRootItem),
                                                          &pSubject),
                         retVal, exit);

    certStoreTestInfo->subjectOffset = pSubject->dataOffset;
    certStoreTestInfo->subjectLen = pSubject->length;

exit:

    if (pRootItem)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRootItem);
    }
    return retVal;
}

/*---------------------------------------------------------------------------*/

static int add_to_certStore( int hint, certStorePtr pCertStore,
                            const CertStoreTestInfo* certStoreTestInfo)
{
    int retVal = 0;

    UNITTEST_STATUS_GOTO(hint, CERT_STORE_addTrustPoint(pCertStore,
                                                        certStoreTestInfo->der,
                                                        certStoreTestInfo->derLen),
                         retVal, exit);

exit:
    return retVal;
}



/*---------------------------------------------------------------------------*/

static int test_not_found( int hint, const ubyte* foundCert, ubyte4 foundCertLen,
                          const void* iterator)
{
    int retVal = 0;

    retVal += UNITTEST_TRUE(hint, iterator == 0); /* no other cert with same subject */
    retVal += UNITTEST_INT(hint, foundCertLen, 0);
    retVal += UNITTEST_TRUE(hint, 0 == foundCert);
    return retVal;
}


/*---------------------------------------------------------------------------*/

static int test_match_test_info( int hint, int testInfoIndex,
                                const ubyte* foundCert, ubyte4 foundCertLen)
{
    int retVal = 0;
    sbyte4 resCmp;

    retVal += UNITTEST_INT(hint, foundCertLen, gCertStoreTestInfo[testInfoIndex].derLen);
    retVal += UNITTEST_INT(hint, (DIGI_MEMCMP(foundCert, gCertStoreTestInfo[testInfoIndex].der, foundCertLen, &resCmp), resCmp), 0);
    return retVal;
}




/*---------------------------------------------------------------------------*/

static int count_certificates_with_same_subject(int hint,
                                         const certStorePtr pCertStore,
                                         const ubyte* pSubject,
                                         ubyte4 subjectLen,
                                         sbyte4 expectedNum)
{
    int retVal = 0;
    sbyte4 numFound = 0;
    const void* iterator = 0;
    const ubyte* foundCert;
    ubyte4 foundCertLen;

    retVal += UNITTEST_STATUS(hint,
                              CERT_STORE_findTrustPointBySubjectFirst(pCertStore,
                                                                      pSubject,
                                                                      subjectLen,
                                                                      &foundCert,
                                                                      &foundCertLen,
                                                                      &iterator));

    if (foundCert && foundCertLen)
    {
        numFound = 1;
    }

    while (iterator)
    {
        retVal += UNITTEST_STATUS(hint,
                                  CERT_STORE_findTrustPointBySubjectNext(&iterator,
                                                                         &foundCert,
                                                                         &foundCertLen));
        if (foundCert && foundCertLen)
        {
            ++numFound;
        }
    }

    retVal += UNITTEST_INT(hint, numFound, expectedNum);

    return retVal;
}


/*---------------------------------------------------------------------------*/

static int retrieve_by_issuer_serial_number_test(int hint,
                                                 certStorePtr pCertStore,
                                                 const char* fileName,
                                                 const char* keyFileName)
{
    int retVal = 0;
    const ubyte* pCertificate = 0;
    ubyte4 certificateLength;
    const AsymmetricKey* key;
    AsymmetricKey refKey = { 0 };
    certDescriptor  certDesc = { 0};
    ASN1_ITEMPTR pRoot = 0;
    ASN1_ITEMPTR pIssuer, pSerialNumber;
    CStream cs;
    MemFile mf;
    sbyte4 resCmp;

    /* load the data we are supposed to retrieve */
    UNITTEST_STATUS_GOTO( hint, DIGICERT_readFile(fileName,
                                                &certDesc.pCertificate,
                                                &certDesc.certLength),
                         retVal, exit);
    if (keyFileName)
    {
        UNITTEST_STATUS_GOTO( hint, DIGICERT_readFile(keyFileName,
                                                    &certDesc.pKeyBlob,
                                                    &certDesc.keyBlobLength),
                             retVal, exit);

        UNITTEST_STATUS_GOTO(hint, CA_MGMT_extractKeyBlobEx(certDesc.pKeyBlob,
                                                            certDesc.keyBlobLength,
                                                            &refKey),
                             retVal, exit);
    }

    MF_attach(&mf, certDesc.certLength, certDesc.pCertificate);
    CS_AttachMemFile(&cs, &mf);

    UNITTEST_STATUS_GOTO(hint, ASN1_Parse(cs, &pRoot), retVal, exit);

    UNITTEST_STATUS_GOTO(hint, X509_getCertificateIssuerSerialNumber(ASN1_FIRST_CHILD(pRoot),
                                                                     &pIssuer,
                                                                     &pSerialNumber),
                         retVal, exit);

    UNITTEST_STATUS_GOTO( hint,
                         CERT_STORE_findCertificateByIssuerSerialNumber(pCertStore,
                                                                        certDesc.pCertificate + pIssuer->dataOffset,
                                                                        pIssuer->length,
                                                                        certDesc.pCertificate + pSerialNumber->dataOffset,
                                                                        pSerialNumber->length,
                                                                        &pCertificate,
                                                                        &certificateLength,
                                                                        &key),
                         retVal, exit);


    retVal += UNITTEST_INT( hint, certificateLength, certDesc.certLength);

    DIGI_MEMCMP(certDesc.pCertificate, pCertificate, certificateLength, &resCmp);
    retVal += UNITTEST_TRUE(hint, 0 == resCmp);

    if (keyFileName)
    {
        retVal += UNITTEST_TRUE(hint, OK == CRYPTO_matchPublicKey(key, &refKey));
    }
    else
    {
        retVal += UNITTEST_TRUE(hint, 0 == key );
    }

exit:

    CRYPTO_uninitAsymmetricKey(&refKey, NULL);
    CA_MGMT_freeCertificate(&certDesc);

    if (pRoot)
    {
        TREE_DeleteTreeItem((TreeItem*) pRoot);
    }

    return retVal;
}

/*---------------------------------------------------------------------------*/

static int test_trustpoints()
{
    int i, retVal = 0;
    certStorePtr pCertStore = 0;
    const void* iterator = 0;
    const ubyte* foundCert;
    ubyte4 foundCertLen;

    for (i = 0; i < COUNTOF(gRootCerts); ++i)
    {
        retVal += load_certStoreTest(i, gRootCerts[i], gCertStoreTestInfo+i);
    }

    UNITTEST_STATUS_GOTO(0, CERT_STORE_createStore(&pCertStore),
                         retVal, exit);

    /**** ADD THREE -- RETRIEVE THREE ************/
    /* load the first three which have 3 different subjects */
    for (i = 0; i < 3; ++i)
    {
        retVal += add_to_certStore(i, pCertStore, gCertStoreTestInfo+i);
    }

    /* verify we can retrieve all three */
    for (i = 0; i < 3; ++i)
    {
        retVal += UNITTEST_STATUS( i,
                                  CERT_STORE_findTrustPointBySubjectFirst(pCertStore,
                                                                          TEST_SUBJECT_ARGS(i),
                                                                          &foundCert,
                                                                          &foundCertLen,
                                                                          &iterator));
        retVal += UNITTEST_TRUE(i, iterator == 0); /* no other cert with same subject */
        retVal += test_match_test_info(__LINE__, i, foundCert, foundCertLen);
    }
    /* VERIFY WE CANNOT RETRIEVE A CERT THAT WAS NOT ADDED! */
    retVal += UNITTEST_STATUS( 0,
                              CERT_STORE_findTrustPointBySubjectFirst(pCertStore,
                                                                      TEST_SUBJECT_ARGS(4),
                                                                      &foundCert,
                                                                      &foundCertLen,
                                                                      &iterator));
    retVal += test_not_found(__LINE__, foundCert, foundCertLen, iterator);


    /**** ADD A FOURTH ONE WITH IDENTICAL SUBJECT: RETRIEVE 4 ************/
    /* load number 3 that has the same subject as number 2 */
    retVal += add_to_certStore(0, pCertStore, gCertStoreTestInfo+3);

    /* verify we can still retrieve first two */
    for (i = 0; i < 2; ++i)
    {
        retVal += UNITTEST_STATUS( i,
                                  CERT_STORE_findTrustPointBySubjectFirst(pCertStore,
                                                                          TEST_SUBJECT_ARGS(i),
                                                                          &foundCert,
                                                                          &foundCertLen,
                                                                          &iterator));
        retVal += UNITTEST_TRUE(i, iterator == 0); /* no other cert with same subject */
        retVal += test_match_test_info(__LINE__, i, foundCert, foundCertLen);
    }

    /* verify we can retrieve 2 for number 3 subject */
    retVal += UNITTEST_STATUS( 0,
                              CERT_STORE_findTrustPointBySubjectFirst(pCertStore,
                                                                      TEST_SUBJECT_ARGS(2),
                                                                      &foundCert,
                                                                      &foundCertLen,
                                                                      &iterator));
    retVal += UNITTEST_TRUE(0, iterator != 0); /* other cert with same subject */
    /* first one is number 2 we added first */
    retVal += test_match_test_info(__LINE__, 2, foundCert, foundCertLen);

    retVal += UNITTEST_STATUS( 0,
                              CERT_STORE_findTrustPointBySubjectNext(&iterator,
                                                                     &foundCert,
                                                                     &foundCertLen));
    /* second one is number 3 we just added */
    retVal += test_match_test_info(__LINE__, 3, foundCert, foundCertLen);
    retVal += UNITTEST_TRUE(0, iterator == 0); /* but no more */


    /**** TRY TO ADD DUPLICATES TO THE STORE: STILL RETRIEVE 4 ************/
    /* try to readd number 2 and number 3 */
    retVal += add_to_certStore(0, pCertStore, gCertStoreTestInfo+3);
    retVal += add_to_certStore(0, pCertStore, gCertStoreTestInfo+2);


    /* verify we can retrieve 2 for number 3 subject but duplicates
     were not saved */
    retVal += UNITTEST_STATUS( 0,
                              CERT_STORE_findTrustPointBySubjectFirst(pCertStore,
                                                                      TEST_SUBJECT_ARGS(2),
                                                                      &foundCert,
                                                                      &foundCertLen,
                                                                      &iterator));
    retVal += UNITTEST_TRUE(0, iterator != 0); /* other cert with same subject */
    /* first one is number 2 we added first */
    retVal += test_match_test_info(__LINE__, 2, foundCert, foundCertLen);

    retVal += UNITTEST_STATUS( 0,
                              CERT_STORE_findTrustPointBySubjectNext(&iterator,
                                                                     &foundCert,
                                                                     &foundCertLen));
    /* second one is number 3 we just added */
    retVal += test_match_test_info(__LINE__, 3, foundCert, foundCertLen);
    retVal += UNITTEST_TRUE(0, iterator == 0); /* but no more */


    /**** ADD THE REST OF THE CERTIFICATES AND VERIFY WE HAVE THE
     EXPECTED NUMBERS  FOR EACH SUBJECT ************/
    for (i = 0; i < COUNTOF(gRootCerts); ++i)
    {
        /* again add some more duplicates */
        retVal += add_to_certStore(i, pCertStore, gCertStoreTestInfo+i);
    }

    for (i = 0; i < COUNTOF(gRootCerts); ++i)
    {
        retVal += count_certificates_with_same_subject(i, pCertStore,
                                                       TEST_SUBJECT_ARGS(i),
                                                       gNumCertsWithSameSubject[i]);
    }

    /* verify we can retrieve them by issuer/serial number */
    for (i = 0; i < COUNTOF(gRootCerts); ++i)
    {
        retVal += retrieve_by_issuer_serial_number_test(i, pCertStore,
                                                        gRootCerts[i],
                                                        NULL);
    }

exit:

    CERT_STORE_releaseStore(&pCertStore);

    for (i = 0; i < COUNTOF(gRootCerts); ++i)
    {
        FREE( gCertStoreTestInfo[i].der);
    }

    return retVal;
}


/*---------------------------------------------------------------------------*/

static int load_certificateInfo( int hint, certStorePtr pCertStore,
                         const CertificateInfo* pCI)
{
    int             retVal = 0;
    certDescriptor  certDesc = { 0};
    ubyte4          len;
    ubyte4          numCertificate;
    SizedBuffer     certificates[2] = { 0};

    UNITTEST_STATUS_GOTO( hint, DIGICERT_readFile( pCI->certFileName,
                              &certDesc.pCertificate,
                              &certDesc.certLength),
                         retVal, exit);

    UNITTEST_STATUS_GOTO( hint, DIGICERT_readFile( pCI->keyFileName,
                             &certDesc.pKeyBlob,
                             &certDesc.keyBlobLength),
                         retVal, exit);
    certificates[0].data = certDesc.pCertificate;
    certificates[0].length = certDesc.certLength;
    numCertificate = 1;

    if ( pCI->parentCertFileName) /* it's a chain */
    {
        UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile(pCI->parentCertFileName,
                                                   &certificates[1].data,
                                                   &len), retVal, exit);

        certificates[1].length = len;
        numCertificate = 2;
    }

    /* conditionally add to certStore; some certificates are just created or loaded */
    UNITTEST_STATUS_GOTO(hint,
                         CERT_STORE_addIdentityWithCertificateChain(pCertStore,
                                                                    certificates, numCertificate,
                                                                    certDesc.pKeyBlob,
                                                                    certDesc.keyBlobLength),
                         retVal, exit);

exit:

    FREE( certificates[1].data);
    CA_MGMT_freeCertificate(&certDesc);

    return retVal;
}


/*---------------------------------------------------------------------------*/

static int identity_test(int hint, certStorePtr pCertStore, const IdentityTest* pIdentityTest)
{
    int retVal = 0;
    void* iterator = 0;
    const AsymmetricKey* identityKey;
    const SizedBuffer* certificates;
    ubyte4 numCertificates;
    int count = 0;

    retVal += UNITTEST_STATUS( hint,
                              CERT_STORE_findIdentityCertChainFirst(pCertStore,
                                          pIdentityTest->pubKeyType,
                                          pIdentityTest->supportedAlgoFlags,
                                          &identityKey,
                                          &certificates, &numCertificates,
                                          &iterator));
    if (retVal) goto exit;


    if (numCertificates>0)
    {
        ++count;
    }

    while (iterator)
    {
        retVal += UNITTEST_STATUS( hint,
                                  CERT_STORE_findIdentityCertChainNext(pCertStore,
                                                                        pIdentityTest->pubKeyType,
                                                                        pIdentityTest->supportedAlgoFlags,
                                                                        &identityKey,
                                                                        &certificates, &numCertificates,
                                                                        &iterator));
        if (numCertificates>0)
        {
            ++count;
        }
    }


    retVal += UNITTEST_INT(hint, count, pIdentityTest->numChains);

exit:

    return retVal;
}




/*---------------------------------------------------------------------------*/

static int identityex_test(int hint, certStorePtr pCertStore,
                    const IdentityTestEx* pIdentityTest)
{
    int retVal = 0;
    void* iterator = 0;
    const AsymmetricKey* identityKey;
    const SizedBuffer* certificates;
    ubyte4 numCertificates;
    int count = 0;

    retVal += UNITTEST_STATUS( hint,
                              CERT_STORE_findIdentityCertChainFirstEx(pCertStore,
                                                                      pIdentityTest->pubKeyType,
                                                                      pIdentityTest->keyUsage,
                                                                      pIdentityTest->supportedAlgoFlags,
                                                                      &identityKey,
                                                                      &certificates, &numCertificates,
                                                                      &iterator));
    if (retVal) goto exit;


    if (numCertificates>0)
    {
        ++count;
    }

    while (iterator)
    {
        retVal += UNITTEST_STATUS( hint,
                                  CERT_STORE_findIdentityCertChainNextEx(pCertStore,
                                                                         pIdentityTest->pubKeyType,
                                                                         pIdentityTest->keyUsage,
                                                                         pIdentityTest->supportedAlgoFlags,
                                                                         &identityKey,
                                                                         &certificates, &numCertificates,
                                                                         &iterator));
        if (numCertificates>0)
        {
            ++count;
        }
    }


    retVal += UNITTEST_INT(hint, count, pIdentityTest->numChains);

exit:

    return retVal;
}


/*---------------------------------------------------------------------------*/

static int test_identities()
{
    int i, retVal = 0;
    certStorePtr pCertStore = 0;

    /* load all the identifies into a cert store */
    UNITTEST_STATUS_GOTO(0, CERT_STORE_createStore(&pCertStore),
                         retVal, exit);

    for (i = 0; i < COUNTOF(gCertificateInfos); ++i)
    {
        retVal += load_certificateInfo( i, pCertStore, gCertificateInfos+i);
    }

    if (retVal) goto exit;

    /* now let's have some fun with this cert store */
    for (i = 0; i < COUNTOF(gIdentityTests); ++i)
    {
        retVal += identity_test(i, pCertStore, gIdentityTests+i);
    }

    for (i = 0; i < COUNTOF(gIdentityTestExs); ++i)
    {
        retVal += identityex_test(i, pCertStore, gIdentityTestExs+i);
    }

    /* verify we can retrieve them by issuer/serial number */
    for (i = 0; i < COUNTOF(gCertificateInfos); ++i)
    {
        retVal += retrieve_by_issuer_serial_number_test(100 + i, pCertStore,
                                                        gCertificateInfos[i].certFileName,
                                                        gCertificateInfos[i].keyFileName);
    }

exit:

    CERT_STORE_releaseStore(&pCertStore);

    return retVal;
}

/* Test to load in a certificate and test whether the certificate can be
 * searched for with RSA SSA-PSS.
 */
static int test_rsa_pss_cert_key_pair(char *pCertFile, char *pKeyFile)
{
    int ret = 0;
    certStorePtr pCertStore = NULL;
    ubyte *pCert = NULL, *pKey = NULL;
    ubyte4 certLen, keyLen, certCount;
    SizedBuffer certificate;
    const AsymmetricKey *pPrivateKey = NULL;
    const SizedBuffer *pCertificates = NULL;
    void *pIterator = NULL;

    UNITTEST_STATUS_GOTO(
        OK, CERT_STORE_createStore(&pCertStore), ret, exit);

    UNITTEST_STATUS_GOTO(
        OK, DIGICERT_readFile(pCertFile, &pCert, &certLen), ret,
        exit);

    UNITTEST_STATUS_GOTO(
        OK, DIGICERT_readFile(pKeyFile, &pKey, &keyLen), ret, exit);

    certificate.length = certLen;
    certificate.data = pCert;

    UNITTEST_STATUS_GOTO(
        OK, CERT_STORE_addIdentityWithCertificateChain(
            pCertStore, &certificate, 1, pKey, keyLen), ret, exit);

    UNITTEST_STATUS_GOTO(
        OK, CERT_STORE_addIdentityWithCertificateChain(
            pCertStore, &certificate, 1, pKey, keyLen), ret, exit);

    /* Call without the RSA PSS key type. This should not find any identities.
     */
    UNITTEST_STATUS_GOTO(
        OK, CERT_STORE_findIdentityCertChainFirstEx(
            pCertStore, akt_rsa, 1 << digitalSignature,
            CERT_STORE_ALGO_FLAG_RSA, &pPrivateKey, &pCertificates, &certCount,
            &pIterator), ret, exit);

    if ( (NULL != pPrivateKey) || (NULL != pCertificates) || (0 != certCount) )
    {
        UNITTEST_STATUS_GOTO(OK, ERR_CERT_STORE, ret, exit);
    }

    /* Call with the RSA PSS key type. This should find the certificate and key.
     */
    UNITTEST_STATUS_GOTO(
        OK, CERT_STORE_findIdentityCertChainFirstEx(
            pCertStore, akt_rsa_pss, 1 << digitalSignature,
            CERT_STORE_ALGO_FLAG_RSA | CERT_STORE_ALGO_FLAG_INTRINSIC,
            &pPrivateKey, &pCertificates, &certCount, &pIterator), ret, exit);

    if ( (NULL == pPrivateKey) || (NULL == pCertificates) || (0 == certCount) )
    {
        UNITTEST_STATUS_GOTO(OK, ERR_CERT_STORE, ret, exit);
    }

    pPrivateKey = NULL;
    pCertificates = NULL;
    certCount = 0;

    /* Get the next identity. The same identity was added twice so it should be
     * picked up again.
     */
    UNITTEST_STATUS_GOTO(
        OK, CERT_STORE_findIdentityCertChainNextEx(
            pCertStore, akt_rsa_pss, 1 << digitalSignature,
            CERT_STORE_ALGO_FLAG_RSA | CERT_STORE_ALGO_FLAG_INTRINSIC,
            &pPrivateKey, &pCertificates, &certCount, &pIterator), ret, exit);

    if ( (NULL == pPrivateKey) || (NULL == pCertificates) || (0 == certCount) )
    {
        UNITTEST_STATUS_GOTO(OK, ERR_CERT_STORE, ret, exit);
    }

    /* There should be no more identities.
     */
    UNITTEST_STATUS_GOTO(
        OK, CERT_STORE_findIdentityCertChainNextEx(
            pCertStore, akt_rsa_pss, 1 << digitalSignature,
            CERT_STORE_ALGO_FLAG_RSA, &pPrivateKey, &pCertificates, &certCount,
            &pIterator), ret, exit);

    if ( (NULL != pPrivateKey) || (NULL != pCertificates) || (0 != certCount) )
    {
        UNITTEST_STATUS_GOTO(OK, ERR_CERT_STORE, ret, exit);
    }

exit:

    ret += UNITTEST_STATUS(OK, DIGICERT_freeReadFile(&pKey));
    ret += UNITTEST_STATUS(OK, DIGICERT_freeReadFile(&pCert));
    ret += UNITTEST_STATUS(OK, CERT_STORE_releaseStore(&pCertStore));

    return ret;
}

static int test_rsa_pss()
{
    int ret = 0;

    ret += test_rsa_pss_cert_key_pair(
        FILE_PATH("rsa_pss_pss_leaf_cert.der"), FILE_PATH("rsa_pss_leaf_key.dat"));

    return ret;
}

#if defined(__ENABLE_DIGICERT_ECC_EDDSA__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)
static int test_ed_cert(
    const char *pCertFile
    )
{
    int ret = 0;
    MSTATUS status;
    certStorePtr pCertStore = NULL;
    ubyte *pCert = NULL, *pKey = NULL;
    ubyte4 curveId;
    ubyte4 algoFlag = 0;
    ubyte4 certLen, keyLen, certCount;
    SizedBuffer certificate;
    AsymmetricKey *pExtractedKey = NULL;
    AsymmetricKey pCertKey = { 0 };
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRoot;
    const SizedBuffer *pCertificates;
    ubyte4 certificateCount;
    ubyte *pIdentity;

    /* create certificate store */
    status = CERT_STORE_createStore(&pCertStore);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* read certificate from file */
    status = DIGICERT_readFile(pCertFile, &certificate.data, (ubyte4 *) &certificate.length);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    MF_attach(&mf, certificate.length, certificate.data);
    CS_AttachMemFile(&cs, &mf);

    status = ASN1_Parse(cs, &pRoot);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_initAsymmetricKey(&pCertKey);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* extract key as an AsymmetricKey */
    status = X509_setKeyFromSubjectPublicKeyInfo(MOC_ASYM(gpHwAccelCtx) ASN1_FIRST_CHILD(pRoot), cs, &pCertKey);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* serialize into digicert key blob */
    status = CRYPTO_serializeAsymKey(MOC_ASYM(gpHwAccelCtx) &pCertKey, mocanaBlobVersion2, &pKey, &keyLen);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    status = CERT_STORE_addIdentityWithCertificateChain(pCertStore, &certificate, 1, pKey, keyLen);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* get curve id for CERT_STORE_findIdentityCertChainFirstEx call */
    status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pCertKey.key.pECC, &curveId);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    algoFlag = CERT_STORE_ALGO_FLAG_INTRINSIC;
    if (cid_EC_Ed25519 == curveId)
    {
        algoFlag |= CERT_STORE_ALGO_FLAG_EDDSA_25519 | CERT_STORE_ALGO_FLAG_EC25519;
    }
    else if (cid_EC_Ed448 == curveId)
    {
        algoFlag |= CERT_STORE_ALGO_FLAG_EDDSA_448 | CERT_STORE_ALGO_FLAG_EC448;
    }

    status = CERT_STORE_findIdentityCertChainFirstEx(pCertStore, akt_ecc_ed, 1, algoFlag, (const struct AsymmetricKey **) &pExtractedKey,
            &pCertificates, &certificateCount, (void **) &pIdentity);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    if (0 == certificateCount)
    {
        status = ERR_NOT_FOUND;
        ret = UNITTEST_STATUS(OK, status);
        goto exit;
    }

    /* incorrect hash algo type with correct certificate algorithms */
    algoFlag = CERT_STORE_ALGO_FLAG_SHA512;
    if (cid_EC_Ed25519 == curveId)
    {
        algoFlag |= CERT_STORE_ALGO_FLAG_EDDSA_25519 | CERT_STORE_ALGO_FLAG_EC25519;
    }
    else if (cid_EC_Ed448 == curveId)
    {
        algoFlag |= CERT_STORE_ALGO_FLAG_EDDSA_448 | CERT_STORE_ALGO_FLAG_EC448;
    }

    certificateCount = 1;
    status = CERT_STORE_findIdentityCertChainFirstEx(pCertStore, akt_ecc_ed, 1, algoFlag, (const struct AsymmetricKey **) &pExtractedKey,
            &pCertificates, &certificateCount, (void **) &pIdentity);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* we should not find a certificate */
    if (0 < certificateCount)
    {
        status = ERR_GENERAL;
        ret = UNITTEST_STATUS(OK, status);
        goto exit;
    }

    /* correct hash algo type with incorrect Algorithm type */
    algoFlag = CERT_STORE_ALGO_FLAG_INTRINSIC;
    if (cid_EC_Ed25519 == curveId)
    {
        algoFlag |= CERT_STORE_ALGO_FLAG_EDDSA_448 | CERT_STORE_ALGO_FLAG_EC25519;
    }
    else if (cid_EC_Ed448 == curveId)
    {
        algoFlag |= CERT_STORE_ALGO_FLAG_EDDSA_25519 | CERT_STORE_ALGO_FLAG_EC448;
    }

    certificateCount = 1;
    status = CERT_STORE_findIdentityCertChainFirstEx(pCertStore, akt_ecc_ed, 1, algoFlag, (const struct AsymmetricKey **) &pExtractedKey,
            &pCertificates, &certificateCount, (void **) &pIdentity);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    if (0 < certificateCount)
    {
        status = ERR_GENERAL;
        ret = UNITTEST_STATUS(OK, status);
        goto exit;
    }

    /* correct hash algo type with correct Algorithm type but incorrect keyType */
    algoFlag = CERT_STORE_ALGO_FLAG_INTRINSIC;
    if (cid_EC_Ed25519 == curveId)
    {
        algoFlag |= CERT_STORE_ALGO_FLAG_ECDSA | CERT_STORE_ALGO_FLAG_EC25519;
    }
    else if (cid_EC_Ed448 == curveId)
    {
        algoFlag |= CERT_STORE_ALGO_FLAG_ECDSA | CERT_STORE_ALGO_FLAG_EC448;
    }

    certificateCount = 1;
    status = CERT_STORE_findIdentityCertChainFirstEx(pCertStore, akt_ecc, 1, algoFlag, (const struct AsymmetricKey **) &pExtractedKey,
            &pCertificates, &certificateCount, (void **) &pIdentity);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    if (0 < certificateCount)
    {
        status = ERR_GENERAL;
        ret = UNITTEST_STATUS(OK, status);
        goto exit;
    }

exit:
    if (NULL != certificate.data)
        DIGI_FREE((void**)&certificate.data);
    
    if (NULL != pKey)
        DIGI_FREE((void **)&pKey);

    CRYPTO_uninitAsymmetricKey(&pCertKey, NULL);
    CERT_STORE_releaseStore(&pCertStore);

    if (pRoot)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRoot);
    }

    return ret;
}


static int test_ed_cert_ex(
    const char *pCertFile
    )
{
    int ret = 0;
    MSTATUS status;
    certStorePtr pCertStore = NULL;
    ubyte *pCert = NULL, *pKey = NULL;
    ubyte4 curveId;
    ubyte4 algoFlag = 0;
    ubyte4 certLen, keyLen, certCount;
    SizedBuffer certificate;
    AsymmetricKey *pExtractedKey = NULL;
    AsymmetricKey pCertKey = { 0 };
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRoot;
    const SizedBuffer *pCertificates;
    ubyte4 certificateCount;
    ubyte *pIdentity;

    /* create certificate store */
    status = CERT_STORE_createStore(&pCertStore);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* read certificate from file */
    status = DIGICERT_readFile(pCertFile, &certificate.data, (ubyte4 *) &certificate.length);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    MF_attach(&mf, certificate.length, certificate.data);
    CS_AttachMemFile(&cs, &mf);

    status = ASN1_Parse(cs, &pRoot);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_initAsymmetricKey(&pCertKey);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* extract key as an AsymmetricKey */
    status = X509_setKeyFromSubjectPublicKeyInfo(MOC_ASYM(gpHwAccelCtx) ASN1_FIRST_CHILD(pRoot), cs, &pCertKey);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* serialize into digicert key blob */
    status = CRYPTO_serializeAsymKey(MOC_ASYM(gpHwAccelCtx) &pCertKey, mocanaBlobVersion2, &pKey, &keyLen);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        CRYPTO_uninitAsymmetricKey(&pCertKey, NULL);
        goto exit;
    }

    status = CERT_STORE_addIdentityWithCertificateChain(pCertStore, &certificate, 1, pKey, keyLen);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* get curve id for CERT_STORE_findIdentityCertChainFirstEx call */
    status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pCertKey.key.pECC, &curveId);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    algoFlag = CERT_STORE_ALGO_FLAG_SHA256;
    if (cid_EC_Ed25519 == curveId)
    {
        algoFlag |= CERT_STORE_ALGO_FLAG_ECDSA | CERT_STORE_ALGO_FLAG_EC25519;
    }
    else if (cid_EC_Ed448 == curveId)
    {
        algoFlag |= CERT_STORE_ALGO_FLAG_ECDSA | CERT_STORE_ALGO_FLAG_EC448;
    }

    status = CERT_STORE_findIdentityCertChainFirstEx(pCertStore, akt_ecc_ed, 1, algoFlag, (const struct AsymmetricKey **) &pExtractedKey,
            &pCertificates, &certificateCount, (void **) &pIdentity);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    if (0 == certificateCount)
    {
        status = ERR_NOT_FOUND;
        ret = UNITTEST_STATUS(OK, status);
        goto exit;
    }
    /* incorrect hash algo type with correct certificate algorithms */
    algoFlag = CERT_STORE_ALGO_FLAG_SHA256;
    if (cid_EC_Ed25519 == curveId)
    {
        algoFlag |= CERT_STORE_ALGO_FLAG_EDDSA_25519 | CERT_STORE_ALGO_FLAG_EC25519;
    }
    else if (cid_EC_Ed448 == curveId)
    {
        algoFlag |= CERT_STORE_ALGO_FLAG_EDDSA_448 | CERT_STORE_ALGO_FLAG_EC448;
    }

    certificateCount = 1;
    status = CERT_STORE_findIdentityCertChainFirstEx(pCertStore, akt_ecc_ed, 1, algoFlag, (const struct AsymmetricKey **) &pExtractedKey,
            &pCertificates, &certificateCount, (void **) &pIdentity);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* we should not find a certificate */
    if (0 < certificateCount)
    {
        status = ERR_GENERAL;
        ret = UNITTEST_STATUS(OK, status);
        goto exit;
    }

    /* correct hash algo type with incorrect Algorithm type */
    algoFlag = CERT_STORE_ALGO_FLAG_SHA256;
    if (cid_EC_Ed25519 == curveId)
    {
        algoFlag |= CERT_STORE_ALGO_FLAG_ECDSA | CERT_STORE_ALGO_FLAG_EC448;
    }
    else if (cid_EC_Ed448 == curveId)
    {
        algoFlag |= CERT_STORE_ALGO_FLAG_ECDSA | CERT_STORE_ALGO_FLAG_EC25519;
    }

    certificateCount = 1;
    status = CERT_STORE_findIdentityCertChainFirstEx(pCertStore, akt_ecc_ed, 1, algoFlag, (const struct AsymmetricKey **) &pExtractedKey,
            &pCertificates, &certificateCount, (void **) &pIdentity);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    if (0 < certificateCount)
    {
        status = ERR_GENERAL;
        ret = UNITTEST_STATUS(OK, status);
        goto exit;
    }

    /* correct hash algo type with correct Algorithm type but incorrect keyType */
    algoFlag = CERT_STORE_ALGO_FLAG_INTRINSIC;
    if (cid_EC_Ed25519 == curveId)
    {
        algoFlag |= CERT_STORE_ALGO_FLAG_EDDSA_25519 | CERT_STORE_ALGO_FLAG_EC25519;
    }
    else if (cid_EC_Ed448 == curveId)
    {
        algoFlag |= CERT_STORE_ALGO_FLAG_EDDSA_448 | CERT_STORE_ALGO_FLAG_EC448;
    }

    certificateCount = 1;
    status = CERT_STORE_findIdentityCertChainFirstEx(pCertStore, akt_ecc, 1, algoFlag, (const struct AsymmetricKey **) &pExtractedKey,
            &pCertificates, &certificateCount, (void **) &pIdentity);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    if (0 < certificateCount)
    {
        status = ERR_GENERAL;
        ret = UNITTEST_STATUS(OK, status);
        goto exit;
    }
exit:
    if (NULL != certificate.data)
        DIGI_FREE((void**)&certificate.data);
    
    if (NULL != pKey)
        DIGI_FREE((void **)&pKey);

    CRYPTO_uninitAsymmetricKey(&pCertKey, NULL);
    CERT_STORE_releaseStore(&pCertStore);

    if (pRoot)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRoot);
    }

    return ret;
}

static int test_ed_certCA(
    const char *pCertFile,
    const char *pKeyFile,
    ubyte4 signType
    )
{
    int ret = 0;
    MSTATUS status;
    certStorePtr pCertStore = NULL;
    ubyte *pKey = NULL;
    ubyte4 curveId;
    ubyte4 hashType;
    ubyte4 pubKeyType;
    ubyte4 curveType;
    ubyte4 algoFlag = 0;
    ubyte4 certLen, keyLen, certCount;
    SizedBuffer certificate = {0};
    AsymmetricKey *pExtractedKey = NULL;
    AsymmetricKey pCertKey = { 0 };
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pSignAlgoId;
    const SizedBuffer *pCertificates;
    ubyte4 certificateCount;
    ubyte *pIdentity;
    ubyte *pCertCopy = NULL;

    /* create certificate store */
    status = CERT_STORE_createStore(&pCertStore);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* read certificate from file */
    status = DIGICERT_readFile(pCertFile, &certificate.data, (ubyte4 *) &certificate.length);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* make a copy of the start of the cert so we can free it later, CERT_STORE_addIdentityWithCertificateChain moves the 
       pointer apparently */
    pCertCopy = certificate.data;

    /* read certificate from file */
    status = DIGICERT_readFile(pKeyFile, &pKey, &keyLen);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_initAsymmetricKey(&pCertKey);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* deserialize key as an AsymmetricKey */
    status = CRYPTO_deserializeAsymKey(MOC_ASYM(gpHwAccelCtx) pKey, keyLen, NULL, &pCertKey);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* free pKey for re-use */
    status = DIGI_FREE((void **) &pKey);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* serialize into digicert key blob */
    status = CRYPTO_serializeAsymKey(MOC_ASYM(gpHwAccelCtx) &pCertKey, mocanaBlobVersion2, &pKey, &keyLen);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    status = CERT_STORE_addIdentityWithCertificateChain(pCertStore, &certificate, 1, pKey, keyLen);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* get curve id for CERT_STORE_findIdentityCertChainFirstEx call */
    status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pCertKey.key.pECC, &curveId);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* we expect edwards CAs */
    algoFlag = CERT_STORE_ALGO_FLAG_INTRINSIC;
    /* set the signing algorithm we found in certificate */
    if (cid_EC_Ed25519 == signType)
    {
        algoFlag |= CERT_STORE_ALGO_FLAG_EDDSA_25519;
    }
    else if (cid_EC_Ed448 == signType)
    {
        algoFlag |= CERT_STORE_ALGO_FLAG_EDDSA_448;
    }

    /* assign key algorithm based on deserialized key file */
#ifdef __ENABLE_DIGICERT_ECC_P192__
    if (cid_EC_P192 == curveId)
    {
        algoFlag |= CERT_STORE_ALGO_FLAG_EC192;
    } else
#endif
#ifndef __DISABLE_DIGICERT_ECC_P224__
    if (cid_EC_P224 == curveId)
    {
        algoFlag |= CERT_STORE_ALGO_FLAG_EC224;
    } else
#endif
#ifndef __DISABLE_DIGICERT_ECC_P256__
    if (cid_EC_P256 == curveId)
    {
        algoFlag |= CERT_STORE_ALGO_FLAG_EC256;
    } else
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
    if (cid_EC_P384 == curveId)
    {
        algoFlag |= CERT_STORE_ALGO_FLAG_EC384;
    } else
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
    if (cid_EC_P521 == curveId)
    {
        algoFlag |= CERT_STORE_ALGO_FLAG_EC521;
    } else
#endif
    {
        status = ERR_CERT_STORE_UNSUPPORTED_ECCURVE;
        ret = UNITTEST_STATUS(OK, status);
        goto exit;
    }

    status = CERT_STORE_findIdentityCertChainFirstEx(pCertStore, akt_ecc, 1, algoFlag, (const struct AsymmetricKey **) &pExtractedKey,
            &pCertificates, &certificateCount, (void **) &pIdentity);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    if (0 == certificateCount)
    {
        status = ERR_NOT_FOUND;
        ret = UNITTEST_STATUS(OK, status);
        goto exit;
    }
    /* incorrect hash algo type with correct certificate algorithms */
    algoFlag = CERT_STORE_ALGO_FLAG_SHA256;
    if (cid_EC_Ed25519 == curveId)
    {
        algoFlag |= CERT_STORE_ALGO_FLAG_EDDSA_25519 | CERT_STORE_ALGO_FLAG_EC25519;
    }
    else if (cid_EC_Ed448 == curveId)
    {
        algoFlag |= CERT_STORE_ALGO_FLAG_EDDSA_448 | CERT_STORE_ALGO_FLAG_EC448;
    }

    certificateCount = 1;
    status = CERT_STORE_findIdentityCertChainFirstEx(pCertStore, akt_ecc_ed, 1, algoFlag, (const struct AsymmetricKey **) &pExtractedKey,
            &pCertificates, &certificateCount, (void **) &pIdentity);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* we should not find a certificate */
    if (0 < certificateCount)
    {
        status = ERR_GENERAL;
        ret = UNITTEST_STATUS(OK, status);
        goto exit;
    }

    /* correct hash algo type with incorrect Algorithm type */
    algoFlag = CERT_STORE_ALGO_FLAG_SHA256;
    if (cid_EC_Ed25519 == curveId)
    {
        algoFlag |= CERT_STORE_ALGO_FLAG_ECDSA | CERT_STORE_ALGO_FLAG_EC448;
    }
    else if (cid_EC_Ed448 == curveId)
    {
        algoFlag |= CERT_STORE_ALGO_FLAG_ECDSA | CERT_STORE_ALGO_FLAG_EC25519;
    }

    certificateCount = 1;
    status = CERT_STORE_findIdentityCertChainFirstEx(pCertStore, akt_ecc_ed, 1, algoFlag, (const struct AsymmetricKey **) &pExtractedKey,
            &pCertificates, &certificateCount, (void **) &pIdentity);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    if (0 < certificateCount)
    {
        status = ERR_GENERAL;
        ret = UNITTEST_STATUS(OK, status);
        goto exit;
    }

#if 0
    /* correct hash algo type with correct Algorithm type but incorrect keyType */
    algoFlag = CERT_STORE_ALGO_FLAG_INTRINSIC;
    if (cid_EC_Ed25519 == curveId)
    {
        algoFlag |= CERT_STORE_ALGO_FLAG_EDDSA_25519 | CERT_STORE_ALGO_FLAG_EC25519;
    }
    else if (cid_EC_Ed448 == curveId)
    {
        algoFlag |= CERT_STORE_ALGO_FLAG_EDDSA_448 | CERT_STORE_ALGO_FLAG_EC448;
    }

    certificateCount = 1;
    status = CERT_STORE_findIdentityCertChainFirstEx(pCertStore, akt_ecc, 1, algoFlag, (const struct AsymmetricKey **) &pExtractedKey,
            &pCertificates, &certificateCount, (void **) &pIdentity);
    ret = UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    if (0 < certificateCount)
    {
        status = ERR_GENERAL;
        ret = UNITTEST_STATUS(OK, status);
        goto exit;
    }
#endif
exit:
    if (NULL != pCertCopy)
        DIGI_FREE((void **) &pCertCopy);

    if (NULL != pKey)
        DIGI_FREE((void **) &pKey);

    CRYPTO_uninitAsymmetricKey(&pCertKey, NULL);
    CERT_STORE_releaseStore(&pCertStore);

    return ret;
}

static int test_different_supported_lists(const char *pCertFile)
{
    int ret = 0;
    MSTATUS status;
    certStorePtr pCertStore = NULL;
    ubyte *pKey = NULL;
    ubyte4 curveId;
    ubyte4 algoFlagsCertKey[2] = {0};
    ubyte4 algoFlagsSignAlgo[2] = {0};
    ubyte4 keyLen;
    SizedBuffer certificate;
    AsymmetricKey *pExtractedKey = NULL;
    AsymmetricKey pCertKey = { 0 };
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRoot;
    const SizedBuffer *pCertificates;
    ubyte4 certificateCount;
    ubyte *pIdentity;

    /* create certificate store */
    status = CERT_STORE_createStore(&pCertStore);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* read certificate from file */
    status = DIGICERT_readFile(pCertFile, &certificate.data, (ubyte4 *) &certificate.length);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    MF_attach(&mf, certificate.length, certificate.data);
    CS_AttachMemFile(&cs, &mf);

    status = ASN1_Parse(cs, &pRoot);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_initAsymmetricKey(&pCertKey);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* extract key as an AsymmetricKey */
    status = X509_setKeyFromSubjectPublicKeyInfo(MOC_ASYM(gpHwAccelCtx) ASN1_FIRST_CHILD(pRoot), cs, &pCertKey);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* serialize into digicert key blob */
    status = CRYPTO_serializeAsymKey(MOC_ASYM(gpHwAccelCtx) &pCertKey, mocanaBlobVersion2, &pKey, &keyLen);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        CRYPTO_uninitAsymmetricKey(&pCertKey, NULL);
        goto exit;
    }

    status = CERT_STORE_addIdentityWithCertificateChain(pCertStore, &certificate, 1, pKey, keyLen);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* get curve id for CERT_STORE_findIdentityCertChainFirstEx call */
    status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pCertKey.key.pECC, &curveId);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* NOTE: The signing algorithm for this cert is fixed to ECDSA on P256 with SHA256 */

    /******* TEST 1 Positive Test, two lists of a single item *******/
    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlagsCertKey[0], akt_ecc_ed);
    CERT_STORE_ALGO_ID_SET_CURVE(algoFlagsCertKey[0], curveId);

    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlagsSignAlgo[0], akt_ecc);
    CERT_STORE_ALGO_ID_SET_HASH(algoFlagsSignAlgo[0], ht_sha256);
    CERT_STORE_ALGO_ID_SET_CURVE(algoFlagsSignAlgo[0], cid_EC_P256);

    status = CERT_STORE_findIdentityCertChainFirstFromList(pCertStore, akt_ecc_ed, 1, algoFlagsCertKey, 1, algoFlagsSignAlgo, 1,
            (const struct AsymmetricKey **) &pExtractedKey, &pCertificates, &certificateCount, (void **) &pIdentity);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__, certificateCount, 1);
    if (ret)
        goto exit;

    /******* TEST 2 Positive Test, two lists including the right items *******/
    algoFlagsCertKey[0] = 0;
    algoFlagsCertKey[1] = 0;
    algoFlagsSignAlgo[0] = 0;
    algoFlagsSignAlgo[1] = 0;
    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlagsCertKey[0], akt_rsa);

    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlagsCertKey[1], akt_ecc_ed);
    CERT_STORE_ALGO_ID_SET_CURVE(algoFlagsCertKey[1], curveId);

    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlagsSignAlgo[0], akt_ecc);
    CERT_STORE_ALGO_ID_SET_HASH(algoFlagsSignAlgo[0], ht_sha512);
    CERT_STORE_ALGO_ID_SET_CURVE(algoFlagsSignAlgo[0], cid_EC_P521);

    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlagsSignAlgo[1], akt_ecc);
    CERT_STORE_ALGO_ID_SET_HASH(algoFlagsSignAlgo[1], ht_sha256);
    CERT_STORE_ALGO_ID_SET_CURVE(algoFlagsSignAlgo[1], cid_EC_P256);

    status = CERT_STORE_findIdentityCertChainFirstFromList(pCertStore, akt_ecc_ed, 1, algoFlagsCertKey, 2, algoFlagsSignAlgo, 2,
            (const struct AsymmetricKey **) &pExtractedKey, &pCertificates, &certificateCount, (void **) &pIdentity);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__, certificateCount, 1);
    if (ret)
        goto exit;

    /******* TEST 3 Positive Test, one list including both the right items *******/
    algoFlagsSignAlgo[0] = 0;
    algoFlagsSignAlgo[1] = 0;
    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlagsSignAlgo[0], akt_ecc_ed);
    CERT_STORE_ALGO_ID_SET_CURVE(algoFlagsSignAlgo[0], curveId);

    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlagsSignAlgo[1], akt_ecc);
    CERT_STORE_ALGO_ID_SET_HASH(algoFlagsSignAlgo[1], ht_sha256);
    CERT_STORE_ALGO_ID_SET_CURVE(algoFlagsSignAlgo[1], cid_EC_P256);

    status = CERT_STORE_findIdentityCertChainFirstFromList(pCertStore, akt_ecc_ed, 1, algoFlagsSignAlgo, 2, algoFlagsSignAlgo, 2,
            (const struct AsymmetricKey **) &pExtractedKey, &pCertificates, &certificateCount, (void **) &pIdentity);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__, certificateCount, 1);
    if (ret)
        goto exit;

    /******* TEST 4 Negative Test, one list including one right items *******/
    algoFlagsSignAlgo[0] = 0;
    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlagsSignAlgo[0], akt_ecc_ed);
    CERT_STORE_ALGO_ID_SET_CURVE(algoFlagsSignAlgo[0], curveId);

    status = CERT_STORE_findIdentityCertChainFirstFromList(pCertStore, akt_ecc_ed, 1, algoFlagsSignAlgo, 1, algoFlagsSignAlgo, 1,
            (const struct AsymmetricKey **) &pExtractedKey, &pCertificates, &certificateCount, (void **) &pIdentity);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__, certificateCount, 0);
    if (ret)
        goto exit;

    /******* TEST 5 Negative Test, one list including the other right items *******/
    algoFlagsSignAlgo[0] = 0;
    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlagsSignAlgo[0], akt_ecc);
    CERT_STORE_ALGO_ID_SET_HASH(algoFlagsSignAlgo[0], ht_sha256);
    CERT_STORE_ALGO_ID_SET_CURVE(algoFlagsSignAlgo[0], cid_EC_P256);
  
    status = CERT_STORE_findIdentityCertChainFirstFromList(pCertStore, akt_ecc_ed, 1, algoFlagsSignAlgo, 1, algoFlagsSignAlgo, 1,
            (const struct AsymmetricKey **) &pExtractedKey, &pCertificates, &certificateCount, (void **) &pIdentity);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__, certificateCount, 0);
    if (ret)
        goto exit;

    /******* TEST 6 Negative Test, two lists containing right items in wrong list *******/
    algoFlagsCertKey[0] = 0;
    algoFlagsCertKey[1] = 0;
    algoFlagsSignAlgo[0] = 0;
    algoFlagsSignAlgo[1] = 0;
    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlagsCertKey[0], akt_rsa);

    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlagsCertKey[1], akt_ecc);
    CERT_STORE_ALGO_ID_SET_HASH(algoFlagsCertKey[1], ht_sha256);
    CERT_STORE_ALGO_ID_SET_CURVE(algoFlagsCertKey[1], cid_EC_P256);

    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlagsSignAlgo[0], akt_ecc);
    CERT_STORE_ALGO_ID_SET_HASH(algoFlagsSignAlgo[0], ht_sha512);
    CERT_STORE_ALGO_ID_SET_CURVE(algoFlagsSignAlgo[0], cid_EC_P521);

    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlagsSignAlgo[1], akt_ecc_ed);
    CERT_STORE_ALGO_ID_SET_CURVE(algoFlagsSignAlgo[1], curveId);

    status = CERT_STORE_findIdentityCertChainFirstFromList(pCertStore, akt_ecc_ed, 1, algoFlagsCertKey, 2, algoFlagsSignAlgo, 2,
            (const struct AsymmetricKey **) &pExtractedKey, &pCertificates, &certificateCount, (void **) &pIdentity);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__, certificateCount, 0);
    if (ret)
        goto exit;

    /******* TEST 7 Negative Test, wrong keyType for cert key *******/
    algoFlagsSignAlgo[0] = 0;
    algoFlagsSignAlgo[1] = 0;
    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlagsSignAlgo[0], akt_ecc_ed);
    CERT_STORE_ALGO_ID_SET_CURVE(algoFlagsSignAlgo[0], curveId);

    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlagsSignAlgo[1], akt_ecc);
    CERT_STORE_ALGO_ID_SET_HASH(algoFlagsSignAlgo[1], ht_sha256);
    CERT_STORE_ALGO_ID_SET_CURVE(algoFlagsSignAlgo[1], cid_EC_P256);
 
    status = CERT_STORE_findIdentityCertChainFirstFromList(pCertStore, akt_ecc, 1, algoFlagsSignAlgo, 2, algoFlagsSignAlgo, 2,
            (const struct AsymmetricKey **) &pExtractedKey, &pCertificates, &certificateCount, (void **) &pIdentity);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__, certificateCount, 0);
    if (ret)
        goto exit;

    /******* TEST 8 Positive Test, certAlgo list NULL *******/
    algoFlagsSignAlgo[0] = 0;
    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlagsSignAlgo[0], akt_ecc);
    CERT_STORE_ALGO_ID_SET_HASH(algoFlagsSignAlgo[0], ht_sha256);
    CERT_STORE_ALGO_ID_SET_CURVE(algoFlagsSignAlgo[0], cid_EC_P256);

    status = CERT_STORE_findIdentityCertChainFirstFromList(pCertStore, akt_ecc_ed, 1, NULL, 0, algoFlagsSignAlgo, 1,
            (const struct AsymmetricKey **) &pExtractedKey, &pCertificates, &certificateCount, (void **) &pIdentity);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__, certificateCount, 1);
    if (ret)
        goto exit;

    /******* TEST 9 Positive Test, signAlgo list NULL *******/
    algoFlagsCertKey[0] = 0;
    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlagsCertKey[0], akt_ecc_ed);
    CERT_STORE_ALGO_ID_SET_CURVE(algoFlagsCertKey[0], curveId);

    status = CERT_STORE_findIdentityCertChainFirstFromList(pCertStore, akt_ecc_ed, 1, algoFlagsCertKey, 1, NULL, 0,
            (const struct AsymmetricKey **) &pExtractedKey, &pCertificates, &certificateCount, (void **) &pIdentity);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__, certificateCount, 1);
    if (ret)
        goto exit;

    /******* TEST 10 Positive Test, NULL for both lists *******/
    status = CERT_STORE_findIdentityCertChainFirstFromList(pCertStore, akt_ecc_ed, 1, NULL, 0, NULL, 0,
            (const struct AsymmetricKey **) &pExtractedKey, &pCertificates, &certificateCount, (void **) &pIdentity);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__, certificateCount, 1);
    if (ret)
        goto exit;
exit:

    (void) CRYPTO_uninitAsymmetricKey(&pCertKey, NULL);

    if (NULL != certificate.data)
    {
        (void) DIGI_FREE((void **) &certificate.data);
    }

    if (NULL != pKey)
        DIGI_FREE((void **)&pKey);

    (void ) CERT_STORE_releaseStore(&pCertStore);

    if (NULL != pRoot)
    {
        (void) TREE_DeleteTreeItem( (TreeItem*) pRoot);
    }

    return ret;
}

static int test_ed()
{
    int ret = 0;

    /* positive tests */
    ret += test_ed_cert(FILE_PATH("cert25519.der"));
    ret += test_ed_cert(FILE_PATH("cert448.der"));

    /* negative tests edwards leaf certificates
     * with ecdsa CA */
    ret += test_ed_cert_ex(FILE_PATH("ed25519_cert.der"));
    ret += test_ed_cert_ex(FILE_PATH("ed448_cert.der"));

    /* negative tests ecdsa certificates
     * with edwards curve CA */
    ret += test_ed_certCA(FILE_PATH("cert_p256_ed448CA.der"), FILE_PATH("key_p256.pem"), cid_EC_Ed448);
    ret += test_ed_certCA(FILE_PATH("cert_p256_ed25519CA.der"), FILE_PATH("key_p256.pem"), cid_EC_Ed25519);

    ret += test_different_supported_lists(FILE_PATH("ed25519_cert.der"));

    return ret;
}
#endif /* #if defined(__ENABLE_DIGICERT_ECC_EDDSA__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__) */

/* !sig_oqs flag can removed once oqs is updated to do mldsa rather than dilithium */
#if defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_PQC__) && !defined(__ENABLE_DIGICERT_SIG_OQS__)

static int test_single_hybrid_cert(void)
{
    int ret = 0;
    const char *pCertFile = FILE_PATH("mldsa65_p256_cert.der");
    MSTATUS status;
    certStorePtr pCertStore = NULL;
    ubyte *pKey = NULL;
    ubyte4 curveId;
    ubyte4 qsAlgId;
    ubyte4 algoFlags[1] = {0};
    ubyte4 algoFlagsLen = 1;
    ubyte4 keyLen;
    SizedBuffer certificate;
    AsymmetricKey *pExtractedKey = NULL;
    AsymmetricKey pCertKey = { 0 };
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRoot;
    const SizedBuffer *pCertificates;
    ubyte4 certificateCount;
    ubyte *pIdentity;

    /* create certificate store */
    status = CERT_STORE_createStore(&pCertStore);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* read certificate from file */
    status = DIGICERT_readFile(pCertFile, &certificate.data, (ubyte4 *) &certificate.length);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    MF_attach(&mf, certificate.length, certificate.data);
    CS_AttachMemFile(&cs, &mf);

    status = ASN1_Parse(cs, &pRoot);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_initAsymmetricKey(&pCertKey);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* extract key as an AsymmetricKey */
    status = X509_setKeyFromSubjectPublicKeyInfo(MOC_ASYM(gpHwAccelCtx) ASN1_FIRST_CHILD(pRoot), cs, &pCertKey);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* serialize into digicert key blob */
    status = CRYPTO_serializeAsymKey(MOC_ASYM(gpHwAccelCtx) &pCertKey, mocanaBlobVersion2, &pKey, &keyLen);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
    {
        CRYPTO_uninitAsymmetricKey(&pCertKey, NULL);
        goto exit;
    }

    status = CERT_STORE_addIdentityWithCertificateChain(pCertStore, &certificate, 1, pKey, keyLen);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* get curve id for CERT_STORE_findIdentityCertChainFirstEx call */
    status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pCertKey.key.pECC, &curveId);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_getAlg(pCertKey.pQsCtx, &qsAlgId);
    ret += UNITTEST_STATUS(OK, status);
    if(OK != status)
        goto exit;

    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlags[0], akt_hybrid);
    CERT_STORE_ALGO_ID_SET_QSALG(algoFlags[0], qsAlgId);
    CERT_STORE_ALGO_ID_SET_CLALG(algoFlags[0], curveId);

    status = CERT_STORE_findIdentityCertChainFirstFromList(pCertStore, akt_hybrid, 1, algoFlags, algoFlagsLen, algoFlags, algoFlagsLen,
            (const struct AsymmetricKey **) &pExtractedKey, &pCertificates, &certificateCount, (void **) &pIdentity);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    if (0 == certificateCount)
    {
        status = ERR_NOT_FOUND;
        ret += UNITTEST_STATUS(OK, status);
        goto exit;
    }

    /* incorrect algoFlag */
    algoFlags[0] = 0;
    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlags[0], akt_hybrid);
    CERT_STORE_ALGO_ID_SET_QSALG(algoFlags[0], qsAlgId + 1);
    CERT_STORE_ALGO_ID_SET_CLALG(algoFlags[0], curveId);
    
    certificateCount = 1;
    status = CERT_STORE_findIdentityCertChainFirstFromList(pCertStore, akt_ecc_ed, 1, algoFlags, algoFlagsLen, algoFlags, algoFlagsLen, 
            (const struct AsymmetricKey **) &pExtractedKey, &pCertificates, &certificateCount, (void **) &pIdentity);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* we should not find a certificate */
    if (0 < certificateCount)
    {
        status = ERR_GENERAL;
        ret += UNITTEST_STATUS(OK, status);
        goto exit;
    }

exit:

    (void) CRYPTO_uninitAsymmetricKey(&pCertKey, NULL);

    if (NULL != certificate.data)
    {
        (void) DIGI_FREE((void **) &certificate.data);
    }

    if (NULL != pKey)
        (void) DIGI_FREE((void **)&pKey);

    (void ) CERT_STORE_releaseStore(&pCertStore);

    if (NULL != pRoot)
    {
        (void) TREE_DeleteTreeItem( (TreeItem*) pRoot);
    }

    return ret;
}

static int test_multiple_certs(void)
{
    int ret = 0;
    MSTATUS status = OK;
    sbyte4 compare = 0;
    const char *pCertFile1 = FILE_PATH("mldsa65_p256_cert.der");
    const char *pCertFile2 = FILE_PATH("mldsa44_rsa2048_pss_cert.der");
    const char *pCertFile3 = FILE_PATH("cert25519.der");
    
    certStorePtr pCertStore = NULL;

    SizedBuffer pInitCertificates[3] = {0};

    /* for extracting the cert keys */
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRoot = NULL;
    AsymmetricKey pCertKey = { 0 };
    ubyte *pKey = NULL;
    ubyte4 keyLen = 0;

    ubyte4 algoFlags[3] = {0};

    AsymmetricKey *pExtractedKey = NULL;

    const SizedBuffer *pCertificates;
    ubyte4 certificateCount;
    ubyte *pIdentity;
    ubyte *pIdentityCopy;

    /* create certificate store */
    status = CERT_STORE_createStore(&pCertStore);
    ret += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* read certificates from file */
    status = DIGICERT_readFile(pCertFile1, &pInitCertificates[0].data, (ubyte4 *) &pInitCertificates[0].length);
    ret += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGICERT_readFile(pCertFile2, &pInitCertificates[1].data, (ubyte4 *) &pInitCertificates[1].length);
    ret += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGICERT_readFile(pCertFile3, &pInitCertificates[2].data, (ubyte4 *) &pInitCertificates[2].length);
    ret += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Extract the 1st public key */
    MF_attach(&mf, pInitCertificates[0].length, pInitCertificates[0].data);
    CS_AttachMemFile(&cs, &mf);

    status = ASN1_Parse(cs, &pRoot);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_initAsymmetricKey(&pCertKey);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    status = X509_setKeyFromSubjectPublicKeyInfo(MOC_ASYM(gpHwAccelCtx) ASN1_FIRST_CHILD(pRoot), cs, &pCertKey);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* serialize into digicert key blob */
    status = CRYPTO_serializeAsymKey(MOC_ASYM(gpHwAccelCtx) &pCertKey, mocanaBlobVersion2, &pKey, &keyLen);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* Add the identity pair */
    status = CERT_STORE_addIdentityWithCertificateChain(pCertStore, &pInitCertificates[0], 1, pKey, keyLen);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* Extract the 2nd public key */
    status = DIGI_FREE((void **) &pKey);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    MF_attach(&mf, pInitCertificates[1].length, pInitCertificates[1].data);
    CS_AttachMemFile(&cs, &mf);

    status = ASN1_Parse(cs, &pRoot);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_initAsymmetricKey(&pCertKey);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    status = X509_setKeyFromSubjectPublicKeyInfo(MOC_ASYM(gpHwAccelCtx) ASN1_FIRST_CHILD(pRoot), cs, &pCertKey);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* serialize into digicert key blob */
    status = CRYPTO_serializeAsymKey(MOC_ASYM(gpHwAccelCtx) &pCertKey, mocanaBlobVersion2, &pKey, &keyLen);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* Add the identity pair */
    status = CERT_STORE_addIdentityWithCertificateChain(pCertStore, &pInitCertificates[1], 1, pKey, keyLen);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* Extract the 3rd public key */
    status = DIGI_FREE((void **) &pKey);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    MF_attach(&mf, pInitCertificates[2].length, pInitCertificates[2].data);
    CS_AttachMemFile(&cs, &mf);

    status = ASN1_Parse(cs, &pRoot);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_initAsymmetricKey(&pCertKey);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    status = X509_setKeyFromSubjectPublicKeyInfo(MOC_ASYM(gpHwAccelCtx) ASN1_FIRST_CHILD(pRoot), cs, &pCertKey);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* serialize into digicert key blob */
    status = CRYPTO_serializeAsymKey(MOC_ASYM(gpHwAccelCtx) &pCertKey, mocanaBlobVersion2, &pKey, &keyLen);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /* Add the identity pair */
    status = CERT_STORE_addIdentityWithCertificateChain(pCertStore, &pInitCertificates[2], 1, pKey, keyLen);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    /******* TEST 1, look for only 1st cert *******/
    algoFlags[0] = 0;
    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlags[0], akt_hybrid);
    CERT_STORE_ALGO_ID_SET_QSALG(algoFlags[0], cid_PQC_MLDSA_65);
    CERT_STORE_ALGO_ID_SET_CLALG(algoFlags[0], cid_EC_P256);

    status = CERT_STORE_findIdentityCertChainFirstFromList(pCertStore, akt_hybrid, 1, algoFlags, 1, algoFlags, 1, 
            (const struct AsymmetricKey **) &pExtractedKey, &pCertificates, &certificateCount, (void **) &pIdentity);  /* save pIdentity for further tests of NextFromList */
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__, certificateCount, 1);
    if (ret)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__,  pCertificates[0].length,  pInitCertificates[0].length);

    status = DIGI_MEMCMP(pCertificates[0].data, pInitCertificates[0].data,  pInitCertificates[0].length, &compare);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__, compare, 0);

    /******* TEST 2, look for only 2nd cert *******/
    algoFlags[0] = 0;
    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlags[0], akt_hybrid);
    CERT_STORE_ALGO_ID_SET_QSALG(algoFlags[0], cid_PQC_MLDSA_44);
    CERT_STORE_ALGO_ID_SET_CLALG(algoFlags[0], cid_RSA_2048_PSS);

    status = CERT_STORE_findIdentityCertChainFirstFromList(pCertStore, akt_hybrid, 1, algoFlags, 1, algoFlags, 1, 
            (const struct AsymmetricKey **) &pExtractedKey, &pCertificates, &certificateCount, NULL);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__, certificateCount, 1);
    if (ret)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__,  pCertificates[0].length,  pInitCertificates[1].length);

    status = DIGI_MEMCMP(pCertificates[0].data, pInitCertificates[1].data,  pInitCertificates[1].length, &compare);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__, compare, 0);

    /******* TEST 3, look for only 3rd cert *******/
    algoFlags[0] = 0;
    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlags[0], akt_ecc_ed);
    CERT_STORE_ALGO_ID_SET_CURVE(algoFlags[0], cid_EC_Ed25519);

    status = CERT_STORE_findIdentityCertChainFirstFromList(pCertStore, akt_ecc_ed, 1, algoFlags, 1, algoFlags, 1, 
            (const struct AsymmetricKey **) &pExtractedKey, &pCertificates, &certificateCount, NULL);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__, certificateCount, 1);
    if (ret)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__,  pCertificates[0].length,  pInitCertificates[2].length);

    status = DIGI_MEMCMP(pCertificates[0].data, pInitCertificates[2].data,  pInitCertificates[2].length, &compare);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__, compare, 0);

    /******* TEST 4 Two on list but should find the first stored (dilithium) *******/
    algoFlags[0] = 0;
    algoFlags[1] = 0;
    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlags[0], akt_hybrid);
    CERT_STORE_ALGO_ID_SET_QSALG(algoFlags[0], cid_PQC_MLDSA_44);
    CERT_STORE_ALGO_ID_SET_CLALG(algoFlags[0], cid_RSA_2048_PSS);
     
    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlags[1], akt_hybrid);
    CERT_STORE_ALGO_ID_SET_QSALG(algoFlags[1], cid_PQC_MLDSA_65);
    CERT_STORE_ALGO_ID_SET_CLALG(algoFlags[1], cid_EC_P256);

    status = CERT_STORE_findIdentityCertChainFirstFromList(pCertStore, akt_hybrid, 1, algoFlags, 2, algoFlags, 2, 
            (const struct AsymmetricKey **) &pExtractedKey, &pCertificates, &certificateCount, NULL);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__, certificateCount, 1);
    if (ret)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__, pCertificates[0].length, pInitCertificates[0].length); 

    status = DIGI_MEMCMP(pCertificates[0].data, pInitCertificates[0].data,  pInitCertificates[0].length, &compare);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__, compare, 0);

    /******* TEST 5 Look for 1st hybrid on list with other supported algs *******/
    algoFlags[0] = 0;
    algoFlags[1] = 0;
    algoFlags[2] = 0;

    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlags[0], akt_ecc_ed);
    CERT_STORE_ALGO_ID_SET_CURVE(algoFlags[0], cid_EC_Ed25519);

    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlags[1], akt_hybrid);
    CERT_STORE_ALGO_ID_SET_QSALG(algoFlags[1], cid_PQC_MLDSA_65);
    CERT_STORE_ALGO_ID_SET_CLALG(algoFlags[1], cid_EC_P256);

    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlags[2], akt_hybrid);
    CERT_STORE_ALGO_ID_SET_QSALG(algoFlags[2], cid_PQC_MLDSA_44);
    CERT_STORE_ALGO_ID_SET_CLALG(algoFlags[2], cid_RSA_2048_PSS);
     
    status = CERT_STORE_findIdentityCertChainFirstFromList(pCertStore, akt_hybrid, 1, algoFlags, 3, algoFlags, 3, 
            (const struct AsymmetricKey **) &pExtractedKey, &pCertificates, &certificateCount, NULL);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__, certificateCount, 1);
    if (ret)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__,  pCertificates[0].length,  pInitCertificates[0].length);

    status = DIGI_MEMCMP(pCertificates[0].data, pInitCertificates[0].data,  pInitCertificates[0].length, &compare);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__, compare, 0);

    /******* TEST 6 Look for 1st akt_ecc_ed on list with other supported algs *******/
    algoFlags[0] = 0;
    algoFlags[1] = 0;
    algoFlags[2] = 0;

    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlags[0], akt_ecc_ed);
    CERT_STORE_ALGO_ID_SET_CURVE(algoFlags[0], cid_EC_Ed448);

    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlags[1], akt_hybrid);
    CERT_STORE_ALGO_ID_SET_QSALG(algoFlags[1], cid_PQC_MLDSA_65);
    CERT_STORE_ALGO_ID_SET_CLALG(algoFlags[1], cid_EC_P256);

    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlags[2], akt_ecc_ed);
    CERT_STORE_ALGO_ID_SET_CURVE(algoFlags[2], cid_EC_Ed25519);

    status = CERT_STORE_findIdentityCertChainFirstFromList(pCertStore, akt_ecc_ed, 1, algoFlags, 3, algoFlags, 3, 
            (const struct AsymmetricKey **) &pExtractedKey, &pCertificates, &certificateCount, NULL);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__, certificateCount, 1);
    if (ret)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__,  pCertificates[0].length,  pInitCertificates[2].length); /* should find Ed25510, index 2 */

    status = DIGI_MEMCMP(pCertificates[0].data, pInitCertificates[2].data,  pInitCertificates[2].length, &compare);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__, compare, 0);
   
    /****** TEST 7, CERT_STORE_findIdentityCertChainNextFromList *******/
    algoFlags[0] = 0;
    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlags[0], akt_hybrid);
    CERT_STORE_ALGO_ID_SET_QSALG(algoFlags[0], cid_PQC_MLDSA_65);
    CERT_STORE_ALGO_ID_SET_CLALG(algoFlags[0], cid_EC_P256);
    pIdentityCopy = pIdentity;

    status = CERT_STORE_findIdentityCertChainNextFromList(pCertStore, akt_hybrid, 1, algoFlags, 1, algoFlags, 1, 
            (const struct AsymmetricKey **) &pExtractedKey, &pCertificates, &certificateCount, (void **) &pIdentityCopy);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__, certificateCount, 0);  /* Should start looking after mldsa44 so shouldn't find anything */
    if (ret)
        goto exit;

    /****** TEST 8, CERT_STORE_findIdentityCertChainNextFromList *******/
    algoFlags[0] = 0;
    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlags[0], akt_hybrid);
    CERT_STORE_ALGO_ID_SET_QSALG(algoFlags[0], cid_PQC_MLDSA_44);
    CERT_STORE_ALGO_ID_SET_CLALG(algoFlags[0], cid_RSA_2048_PSS);
    pIdentityCopy = pIdentity;

    status = CERT_STORE_findIdentityCertChainNextFromList(pCertStore, akt_hybrid, 1, algoFlags, 1, algoFlags, 1, 
            (const struct AsymmetricKey **) &pExtractedKey, &pCertificates, &certificateCount, (void **) &pIdentityCopy);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__, certificateCount, 1);
    if (ret)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__,  pCertificates[0].length,  pInitCertificates[1].length); /* should find Falcon, index 1 */

    status = DIGI_MEMCMP(pCertificates[0].data, pInitCertificates[1].data,  pInitCertificates[1].length, &compare);
    ret += UNITTEST_STATUS(OK, status);
    if (OK != status)
        goto exit;

    ret += UNITTEST_INT(__MOC_LINE__, compare, 0);

exit:

    (void) CRYPTO_uninitAsymmetricKey(&pCertKey, NULL);

    if (NULL != pKey)
        (void) DIGI_FREE((void **) &pKey);

    if (NULL != pInitCertificates[0].data)
    {
        (void) DIGI_FREE((void **) &pInitCertificates[0].data);
    }

    if (NULL != pInitCertificates[1].data)
    {
        (void) DIGI_FREE((void **) &pInitCertificates[1].data);
    }

    if (NULL != pInitCertificates[2].data)
    {
        (void) DIGI_FREE((void **) &pInitCertificates[2].data);
    }

    if (NULL != pRoot)
    {
        (void) TREE_DeleteTreeItem( (TreeItem*) pRoot);
    }

    (void) CERT_STORE_releaseStore(&pCertStore);

    return ret;
}

#endif /* #if defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_PQC__) */

/*---------------------------------------------------------------------------*/

int crypto_interface_cert_store_test_init()
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

  /* START Tests */
 
  errorCount += test_trustpoints ();
  errorCount += test_identities ();
  errorCount += test_rsa_pss ();

#if defined(__ENABLE_DIGICERT_ECC_EDDSA__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)
  errorCount += test_ed ();
#endif

#if defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_PQC__) && !defined(__ENABLE_DIGICERT_SIG_OQS__)
  errorCount += test_single_hybrid_cert();
  /* test_multiple_certs uses falcon which we don't have and mldsa which oqs doesn't have, so disable
     until this is implemented/normalized */
#if 0
  errorCount += test_multiple_certs();
#endif
#endif

  /* END   Tests */
  
exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
  HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
  HARDWARE_ACCEL_UNINIT();
#endif

  DIGICERT_free(&gpMocCtx);
  return errorCount;
}


