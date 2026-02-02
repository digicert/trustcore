/*
 * cert_store_test.c
 *
 * unit test for cert_store.c
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

#include "../../../unit_tests/unittest.h"

static const char* gRootCerts[] =
{
    "Equifax_Secure_Certificate_Authority.der", /* subject= /C=US/O=Equifax/OU=Equifax Secure Certificate Authority */
    "VerisignClass3RootG5.der",                 /* subject= /C=US/O=VeriSign, Inc./OU=VeriSign Trust Network/OU=(c) 2006 VeriSign, Inc. - For authorized use only/CN=VeriSign Class 3 Public Primary Certification Authority - G5 */
    "VerisignClass3RootMD2.der",                /* subject= /C=US/O=VeriSign, Inc./OU=Class 3 Public Primary Certification Authority */
    "VerisignClass3RootSHA1.der",               /* subject= /C=US/O=VeriSign, Inc./OU=Class 3 Public Primary Certification Authority */
    "VerisignClass1PublicPrimaryCAMD2.der",     /* subject= /C=US/O=VeriSign, Inc./OU=Class 1 Public Primary Certification Authority */
    "VerisignClass1PublicPrimaryCASHA1.der",    /* subject= /C=US/O=VeriSign, Inc./OU=Class 1 Public Primary Certification Authority */
/* These ones are fake trust points (issuer names are matches those of some above but keys are wrong) */
    "FakeEquifax_Secure_Certificate_Authority.der", /* subject= /C=US/O=Equifax/OU=Equifax Secure Certificate Authority */
    "FakeVerisignClass3RootG5.der",    /* subject= /C=US/O=VeriSign, Inc./OU=VeriSign Trust Network/OU=(c) 2006 VeriSign, Inc. - For authorized use only/CN=VeriSign Class 3 Public Primary Certification Authority - G5 */
    "FakeVerisignClass3RootMD2.der",   /* subject= /C=US/O=VeriSign, Inc./OU=Class 3 Public Primary Certification Authority */
    "FakeVerisignClass3RootSHA1.der",  /* subject= /C=US/O=VeriSign, Inc./OU=Class 3 Public Primary Certification Authority */

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
    LEAF_CERTIFICATE_INFO( "CS_ECDHCert256", "CS_RSACertCA"),       /* digital Signature, Key Agreement */
    LEAF_CERTIFICATE_INFO( "CS_ECDHCert384", "CS_RSACertCA"),       /* digital Signature, Key Agreement */
    LEAF_CERTIFICATE_INFO( "CS_RSACert_2", "CS_RSACertCA"),         /* digital Signature, Key Encipherment */
    LEAF_CERTIFICATE_INFO( "CS_ECDHCert256_2", "CS_RSACertCA"),     /* digital Signature, Key Agreement */
    LEAF_CERTIFICATE_INFO( "CS_ECDHCert384_2", "CS_RSACertCA"),     /* digital Signature, Key Agreement */
    LEAF_CERTIFICATE_INFO( "CS_ECDHCert256_3", "CS_ECDHCert256CA"), /* digital Signature, Key Agreement */
    LEAF_CERTIFICATE_INFO( "CS_ECDHCert384_3", "CS_ECDHCert384CA"), /* digital Signature, Key Agreement */
    /* Note: we add the root certs at the end to test that we 
     can retrieve the keys of these certificates with 
     CERT_STORE_findCertificateByIssuerSerialNumber
     even if they were registered earlier without key */
    CERTIFICATE_INFO( "CS_RSACertCA"),                              /* digital Signature, Key Encipherment, Certificate Sign, CRL Sign */
    CERTIFICATE_INFO( "CS_ECDHCert256CA"),                          /* digital Signature, Key Agreement, Certificate Sign, CRL Sign */
    CERTIFICATE_INFO( "CS_ECDHCert384CA"),                          /* digital Signature, Key Agreement, Certificate Sign, CRL Sign */
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

int count_certificates_with_same_subject(int hint,
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

int cert_store_test_trustpoints()
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

int load_certificateInfo( int hint, certStorePtr pCertStore,
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

int load_certificateInfoAlias( int hint, certStorePtr pCertStore,
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

    /* conditionally add to certStore; some certificates are just created or loaded */
    UNITTEST_STATUS_GOTO(hint,
                         CERT_STORE_addIdentityWithCertificateChainEx(pCertStore,
                                                                      pCI->certFileName, DIGI_STRLEN(pCI->certFileName),
                                                                      certificates, numCertificate,
                                                                      certDesc.pKeyBlob,
                                                                      certDesc.keyBlobLength),
                         retVal, exit);

    if ( pCI->parentCertFileName) /* it's a chain */
    {
        UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile(pCI->parentCertFileName,
                                                   &certificates[1].data,
                                                   &len), retVal, exit);

        certificates[1].length = len;
        numCertificate = 2;
    }

    /* update alias with additional certificates */
    UNITTEST_STATUS_GOTO(hint,
                         CERT_STORE_updateIdentityByAlias(pCertStore,
                                                         pCI->certFileName, DIGI_STRLEN(pCI->certFileName),
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

int identity_test(int hint, certStorePtr pCertStore, const IdentityTest* pIdentityTest)
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

int identityex_test(int hint, certStorePtr pCertStore,
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

int cert_store_test_identities()
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

#ifdef __ENABLE_DIGICERT_PKCS1__
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
#endif

int cert_store_test_rsa_pss()
{
    int ret = 0;
    
#ifdef __ENABLE_DIGICERT_PKCS1__
    
    ret += test_rsa_pss_cert_key_pair(
        "rsa_pss_pss_leaf_cert.der", "rsa_pss_leaf_key.dat");
#endif
    
    return ret;
}

int cert_store_test_alias()
{
    int i, retVal = 0;
    certStorePtr pCertStore = 0;

    /* load all the identifies into a cert store */
    UNITTEST_STATUS_GOTO(0, CERT_STORE_createStore(&pCertStore),
                         retVal, exit);

    for (i = 0; i < COUNTOF(gCertificateInfos); ++i)
    {
        retVal += load_certificateInfoAlias( i, pCertStore, gCertificateInfos+i);
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

int cert_store_test_get_by_alias()
{
    int i, retVal = 0;
    certStorePtr pCertStore = 0;
    certDescriptor certDesc = {0};
    struct AsymmetricKey *pRetKey = NULL;
    const SizedBuffer *pRetCerts = NULL;
    ubyte4 numRetCerts = 0;
    void *pRetHint = NULL;
    sbyte4 cmp = -1;

    ubyte4 algoFlagsCertKey[1] = {0};
    ubyte4 algoFlagsSignAlgo[1] = {0};

    UNITTEST_STATUS_GOTO(0, CERT_STORE_createStore(&pCertStore),
                         retVal, exit);

    /* We test using the ECDH P256 cert, gCertificateInfos[0] */
    UNITTEST_STATUS_GOTO(0, DIGICERT_readFile( gCertificateInfos[0].certFileName,
                              &certDesc.pCertificate,
                              &certDesc.certLength),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(0, DIGICERT_readFile( gCertificateInfos[0].keyFileName,
                             &certDesc.pKeyBlob,
                             &certDesc.keyBlobLength),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(0, CERT_STORE_addIdentityEx(pCertStore, (ubyte *) "My Alias", 8, certDesc.pCertificate, certDesc.certLength, 
                         certDesc.pKeyBlob, certDesc.keyBlobLength), retVal, exit);

    /* Neg Test, wrong alias */
    UNITTEST_STATUS_GOTO(0, CERT_STORE_findIdentityByAliasAndAlgo (pCertStore, akt_ecc, 1, NULL, 0, NULL, 0, "My Wrong Alias", 14,
                         &pRetKey, &pRetCerts, &numRetCerts, &pRetHint), retVal, exit);

    if (NULL != pRetKey || NULL != pRetCerts || 0 != numRetCerts || NULL != pRetHint)
    {
        retVal += UNITTEST_STATUS(0, -1);
    }

    /* Neg Test, wrong key type */
    UNITTEST_STATUS_GOTO(0, CERT_STORE_findIdentityByAliasAndAlgo (pCertStore, akt_rsa, 1, NULL, 0, NULL, 0, "My Alias", 8,
                         &pRetKey, &pRetCerts, &numRetCerts, &pRetHint), retVal, exit);

    if (NULL != pRetKey || NULL != pRetCerts || 0 != numRetCerts || NULL != pRetHint)
    {
        retVal += UNITTEST_STATUS(0, -1);
    }

    /* Neg Test, wrong keyUsage */
    UNITTEST_STATUS_GOTO(0, CERT_STORE_findIdentityByAliasAndAlgo (pCertStore, akt_ecc, 2, NULL, 0, NULL, 0, "My Alias", 8,
                         &pRetKey, &pRetCerts, &numRetCerts, &pRetHint), retVal, exit);

    if (NULL != pRetKey || NULL != pRetCerts || 0 != numRetCerts || NULL != pRetHint)
    {
        retVal += UNITTEST_STATUS(0, -1);
    }

    /* Neg Test, wrong cert key */
    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlagsCertKey[0], akt_rsa);

    UNITTEST_STATUS_GOTO(0, CERT_STORE_findIdentityByAliasAndAlgo (pCertStore, akt_ecc, 1, algoFlagsCertKey, 1, NULL, 0, "My Alias", 8,
                         &pRetKey, &pRetCerts, &numRetCerts, &pRetHint), retVal, exit);

    if (NULL != pRetKey || NULL != pRetCerts || 0 != numRetCerts || NULL != pRetHint)
    {
        retVal += UNITTEST_STATUS(0, -1);
    }

    /* Neg Test, wrong sign key */
    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlagsSignAlgo[0], akt_rsa);

    UNITTEST_STATUS_GOTO(0, CERT_STORE_findIdentityByAliasAndAlgo (pCertStore, akt_ecc, 1, NULL, 0, algoFlagsSignAlgo, 1, "My Alias", 8,
                         &pRetKey, &pRetCerts, &numRetCerts, &pRetHint), retVal, exit);

    if (NULL != pRetKey || NULL != pRetCerts || 0 != numRetCerts || NULL != pRetHint)
    {
        retVal += UNITTEST_STATUS(0, -1);
    }

    /* positive tests */
    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlagsCertKey[0], akt_ecc);
    CERT_STORE_ALGO_ID_SET_CURVE(algoFlagsCertKey[0], cid_EC_P256);

    CERT_STORE_ALGO_ID_SET_KEYTYPE(algoFlagsSignAlgo[0], akt_ecc);
    CERT_STORE_ALGO_ID_SET_HASH(algoFlagsSignAlgo[0], ht_sha256);
    CERT_STORE_ALGO_ID_SET_CURVE(algoFlagsSignAlgo[0], cid_EC_P256);

    UNITTEST_STATUS_GOTO(0, CERT_STORE_findIdentityByAliasAndAlgo (pCertStore, akt_ecc, 1, NULL, 0, NULL, 0, "My Alias", 8,
                         &pRetKey, &pRetCerts, &numRetCerts, &pRetHint), retVal, exit);

    if (NULL == pRetKey || NULL == pRetCerts || 1 != numRetCerts || NULL == pRetHint)
    {
        UNITTEST_STATUS_GOTO(0, -1, retVal, exit);
    }

    if (pRetCerts[0].length != certDesc.certLength)
    {
        UNITTEST_STATUS_GOTO(0, -1, retVal, exit);
    }

    UNITTEST_STATUS_GOTO(0, DIGI_MEMCMP(pRetCerts[0].data, certDesc.pCertificate, certDesc.certLength, &cmp), retVal, exit);
    
    if (cmp)
    {
        retVal += UNITTEST_STATUS(0, -1);
    }

    pRetKey = NULL;
    pRetCerts = NULL;
    numRetCerts = 0;
    pRetHint = NULL;

    UNITTEST_STATUS_GOTO(0, CERT_STORE_findIdentityByAliasAndAlgo (pCertStore, akt_ecc, 1, algoFlagsCertKey, 1, algoFlagsSignAlgo, 1, "My Alias", 8,
                         &pRetKey, &pRetCerts, &numRetCerts, &pRetHint), retVal, exit);

/*  Test with lists obsolete since the certAgo and signAlgo don't get set in the identity via the API we called 
    
    if (NULL == pRetKey || NULL == pRetCerts || 1 != numRetCerts || NULL == pRetHint)
    {
        UNITTEST_STATUS_GOTO(0, -1, retVal, exit);
    }

    if (pRetCerts[0].length != certDesc.certLength)
    {
        UNITTEST_STATUS_GOTO(0, -1, retVal, exit);
    }

    UNITTEST_STATUS_GOTO(0, DIGI_MEMCMP(pRetCerts[0].data, certDesc.pCertificate, certDesc.certLength, &cmp), retVal, exit);
    
    if (cmp)
    {
        retVal += UNITTEST_STATUS(0, -1);
    }
*/

exit:

    (void) CERT_STORE_releaseStore(&pCertStore);
    (void) DIGI_FREE((void **) &certDesc.pCertificate);
    (void) DIGI_FREE((void **) &certDesc.pKeyBlob);

    return retVal;
}
