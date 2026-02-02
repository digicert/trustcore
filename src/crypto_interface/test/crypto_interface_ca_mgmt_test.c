/*
 *  crypto_interface_ca_mgmt_test.c
 *
 *   unit test for ca_mgmt.c
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

#include "../../common/moptions.h"

#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"

#include "../../common/mdefs.h"
#include "../../common/merrors.h"

#include "../../asn1/oiddefs.h"
#include "../../common/initmocana.h"

#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/mstdlib.h"

#include "../../crypto/pubcrypto.h"

#include "../../asn1/parseasn1.h"
#include "../../asn1/parsecert.h"
#include "../../asn1/derencoder.h"
#include "../../asn1/oiddefs.h"
#include "../../crypto/asn1cert.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#include "../../crypto/ecc.h"
#include "../../crypto_interface/crypto_interface_ecc.h"

#include "../../crypto/ca_mgmt.h"

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

/* used by the ca_mgmt_test_enumCRL test */
typedef struct ExpectedCRLValue {
    ubyte4          type;
    const char*    value;
} ExpectedCRLValue;

const ExpectedCRLValue kExpectedCRLValuesCert1[] =
{
    { 6, "http://crl.microsoft.com/pki/mscorp/crl/mswww(2).crl" },
    { 6, "http://corppki/crl/mswww(2).crl" }
};

const ExpectedCRLValue kExpectedCRLValues2000Remote[] =
{
    { 6, "ldap:///CN=Server2000CA.me06cas.intel.com,CN=win2000CA,CN=CDP,CN=Public%20Key%20Services,"
    "CN=Services,CN=Configuration,DC=me06cas,DC=intel,DC=com?certificateRevocationList?base?"
    "objectclass=cRLDistributionPoint" },
    { 6,  "http://win2000ca.me06cas.intel.com/CertEnroll/Server2000CA.me06cas.intel.com.crl" }
};

typedef struct MyEnumCrlCbArg
{
    ubyte4 hint;
    ubyte4 failures;
    ubyte4 numValues;
    const ExpectedCRLValue* pExpectedValues;
} MyEnumCrlCbArg;

MOC_EXTERN MSTATUS BASE64_initializeContext(void);
MOC_EXTERN MSTATUS BASE64_freeContext(void);

/* used by the ca_mgmt_test_generate_certificate_test */


/*--------------------------------------------------------------------------*/

sbyte4 MyEnumCallback( const ubyte* crlValue, ubyte4 crlValueLen, ubyte4 type,
                       ubyte4 index, void* userArg)
{
    MyEnumCrlCbArg* pTestInfo = (MyEnumCrlCbArg*) userArg;
    const ExpectedCRLValue* pEV;
    ubyte4 errors = 0;
    sbyte4 cmpRes;

    if ( index < pTestInfo->numValues)
    {
        pEV = pTestInfo->pExpectedValues + index;
        errors += UNITTEST_INT(pTestInfo->hint, type, pEV->type);
        errors += UNITTEST_INT(pTestInfo->hint, crlValueLen,
                            DIGI_STRLEN( (const sbyte*) pEV->value));

        DIGI_MEMCMP( crlValue, (const ubyte*) pEV->value, crlValueLen, &cmpRes);
        errors += UNITTEST_INT(pTestInfo->hint, cmpRes, 0);
    }
    else
    {
        errors += UNITTEST_TRUE( pTestInfo->hint, index < pTestInfo->numValues);
    }

    ++(pTestInfo->hint);

    pTestInfo->failures += errors;
    return 0;
}


/*------------------------------------------------------------------------*/
#ifndef __ENABLE_DIGICERT_TAP__

int enumCRL_test( const char* fileName, ubyte2 numCRLs,
                 const ExpectedCRLValue* expectedValues, ubyte4 hint)
{
    MSTATUS status;
    ubyte* pCert = 0;
    ubyte4 certLen;
    MyEnumCrlCbArg testInfo;
    int retVal = 0;

    testInfo.failures = 0;
    testInfo.hint = hint;
    testInfo.numValues = numCRLs;
    testInfo.pExpectedValues = expectedValues;

    status = DIGICERT_readFile( fileName, &pCert, &certLen);
    retVal += UNITTEST_STATUS(hint, status);
    if (status < OK) goto exit;

    status = (MSTATUS) CA_MGMT_enumCrl( pCert, certLen, MyEnumCallback, &testInfo);

    retVal += UNITTEST_STATUS(hint, status);
    retVal += testInfo.failures;

exit:

    if ( pCert)
    {
        FREE(pCert);
    }

    return retVal;
}

/*---------------------------------------------------------------------------*/

int test_enumCRL()
{
    int retVal = 0;
    retVal += enumCRL_test(FILE_PATH("2000Remote.cer"), COUNTOF(kExpectedCRLValues2000Remote),
                            kExpectedCRLValues2000Remote, 0);
    retVal += enumCRL_test(FILE_PATH("Cert1.cer"), COUNTOF(kExpectedCRLValuesCert1),
                            kExpectedCRLValuesCert1, COUNTOF(kExpectedCRLValues2000Remote));
    retVal += enumCRL_test(FILE_PATH("version1crt.der"), 0, NULL, 0);
    return retVal;
}
#endif /* __ENABLE_DIGICERT_TAP__ */

/*---------------------------------------------------------------------------*/

static int
TestKeyDER( const char* inputFileName, const char* resultFileName, int hint)
{
    ubyte* buffer = NULL;
    ubyte4 bufferLen;
    ubyte* keyblob = NULL;
    ubyte4 keyblobLen;
    ubyte* keyDER = NULL;
    ubyte4 keyDERLen;
    sbyte4 result = 1;
    int retVal = 0;

    if ((retVal = UNITTEST_STATUS(hint, DIGICERT_readFile( inputFileName, &buffer,
                                                        &bufferLen))))
    {
        goto exit;
    }

    /* convert DER to keyblob */
    if ((retVal = UNITTEST_STATUS(hint, CA_MGMT_convertKeyDER( buffer, bufferLen,
                                                              &keyblob, &keyblobLen))))
    {
        goto exit;
    }

    /* convert keyblob back to DER */
    if ((retVal = UNITTEST_STATUS(hint, CA_MGMT_keyBlobToDER( keyblob, keyblobLen,
                                                             &keyDER, &keyDERLen))))
    {
        goto exit;
    }

    if (NULL != buffer)
    {
        FREE( buffer);
        buffer = NULL;
    }

    if ((retVal = UNITTEST_STATUS(hint, DIGICERT_readFile( resultFileName, &buffer,
                                                        &bufferLen))))
    {
        goto exit;
    }

    if (bufferLen == keyDERLen)
        DIGI_MEMCMP(buffer, keyDER, bufferLen, &result);

    retVal = UNITTEST_INT(hint, result, 0);

#if 0
    if (retVal)
    {
        /* if test failed, saved converted key in "t"+fileName */
        ubyte name[50];
        DIGI_MEMSET(name, 0x00, 50);
        DIGI_MEMCPY(name+1, inputFileName, DIGI_STRLEN(inputFileName));
        name[0] = 't';
        DIGICERT_writeFile(name, keyDER, keyDERLen);
    }
#endif

exit:

    if (NULL != buffer)
        FREE( buffer);

    if (NULL != keyblob)
        FREE( keyblob);

    if (NULL != keyDER)
        FREE( keyDER);

    return retVal;
}


/*---------------------------------------------------------------------------*/

int test_convertDER()
{

    int retVal = 0;
    int hint;

#ifndef __ENABLE_DIGICERT_OPENSSL_PUBKEY_COMPATIBILITY__

    /* private key */
    retVal += TestKeyDER( FILE_PATH("key512.der"), FILE_PATH("rkey512.der"), hint = 512);
    retVal += TestKeyDER( FILE_PATH("key1024.der"), FILE_PATH("rkey1024.der"), hint = 1024);
    retVal += TestKeyDER( FILE_PATH("key1055.der"), FILE_PATH("rkey1055.der"), hint = 1055);
    retVal += TestKeyDER( FILE_PATH("key2048.der"), FILE_PATH("rkey2048.der"), hint = 2048);
    retVal += TestKeyDER( FILE_PATH("key4096.der"), FILE_PATH("rkey4096.der"), hint = 4096);
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    retVal += TestKeyDER( FILE_PATH("dsakey.der"), FILE_PATH("dsakey.der"), hint = 3);
#endif

    /* public key */
    retVal += TestKeyDER( FILE_PATH("pubkey4096.der"), FILE_PATH("pubkey4096.der"), hint = 4096);
#endif

    return retVal;
}

/*---------------------------------------------------------------------------*/

int TestKeyPEM(const char* inputFileName, const char* resultFileName, int hint)
{
    int retVal = 0;
    ubyte* buffer = NULL;
    ubyte4 bufferLen;
    ubyte* keyblob = NULL;
    ubyte4 keyblobLen;
    ubyte* keyDER = NULL;
    ubyte4 keyDERLen;
    sbyte4 result = 1;

    /* openssl generated public key */
    if ((retVal = UNITTEST_STATUS(hint, DIGICERT_readFile(inputFileName, &buffer,&bufferLen))))
    {
        goto exit;
    }

    BASE64_initializeContext();

    /* convert PEM to keyblob */
    if ((retVal = UNITTEST_STATUS(hint, CA_MGMT_convertKeyPEM( buffer, bufferLen,&keyblob, &keyblobLen))))
    {
        goto exit;
    }

    /* convert keyblob back to PEM */
    if ((retVal = UNITTEST_STATUS(hint, CA_MGMT_keyBlobToPEM(keyblob, keyblobLen, &keyDER, &keyDERLen))))
    {
         goto exit;
    }

    if (NULL != buffer)
    {
         FREE( buffer);
         buffer = NULL;
    }

    if ((retVal = UNITTEST_STATUS(hint, DIGICERT_readFile( resultFileName, &buffer, &bufferLen))))
    {
         goto exit;
    }

    if (bufferLen == keyDERLen)
        DIGI_MEMCMP(buffer, keyDER, bufferLen, &result);

    retVal = UNITTEST_INT(hint, result, 0);

exit:

    if (NULL != buffer)
        FREE( buffer);

    if (NULL != keyblob)
        FREE( keyblob);

    if (NULL != keyDER)
        FREE( keyDER);

    return retVal;

}


int test_convertPEM()
{
    int retVal = 0;
#ifdef __ENABLE_DIGICERT_OPENSSL_PUBKEY_COMPATIBILITY__
    int hint;

    /* public key */
    /* retVal += TestKeyPEM( FILE_PATH("opensslinpubkey512.pem"), FILE_PATH("openssloutpubkey512.pem"), hint = 512); */
    retVal += TestKeyPEM( FILE_PATH("opensslinpubkey1024.pem"), FILE_PATH("openssloutpubkey1024.pem"), hint = 1024);
    retVal += TestKeyPEM( FILE_PATH("opensslinpubkey1055.pem"), FILE_PATH("openssloutpubkey1055.pem"), hint = 1055);
    retVal += TestKeyPEM( FILE_PATH("opensslinpubkey2048.pem"), FILE_PATH("openssloutpubkey2048.pem"), hint = 2048);
#endif

    return retVal;
}

/*---------------------------------------------------------------------------*/

int DecodePEMTest( int hint, const char* fileName)
{
    int retVal = 0;
    MSTATUS status;
    ubyte* pemBuffer = 0;
    ubyte* derBuffer = 0;
    ubyte4 pemSize, derSize;
    MemFile mf;
    CStream cs;
    ASN1_ITEM* pRootItem = 0;

    status = DIGICERT_readFile(fileName, &pemBuffer, &pemSize);
    UNITTEST_STATUS_GOTO(hint, status, retVal, exit);

    status = CA_MGMT_decodeCertificate( pemBuffer, pemSize, &derBuffer, &derSize);
    UNITTEST_STATUS_GOTO(hint, status, retVal, exit);

    MF_attach( &mf, derSize, derBuffer);
    CS_AttachMemFile(&cs, &mf);

    status = ASN1_Parse( cs, &pRootItem);
    UNITTEST_STATUS_GOTO(hint, status, retVal, exit);

exit:

    if (pRootItem)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRootItem);
    }

    if ( pemBuffer)
    {
        FREE( pemBuffer);
    }

    if (derBuffer)
    {
        FREE( derBuffer);
    }

    return retVal;
}

/*---------------------------------------------------------------------------*/

int test_decode_PEM()
{
    int retVal = 0;

    retVal += UNITTEST_STATUS(0, BASE64_initializeContext());

#if 1
    retVal += DecodePEMTest( 0, FILE_PATH("cacert1.pem"));
#endif

    retVal += UNITTEST_STATUS(0, BASE64_freeContext());

    return retVal;
}

/*---------------------------------------------------------------------------*/

static int
VerifyCertWithKeyBlob( const char* certFileName, const char* keyFileName, int hint)
{
    certDescriptor certDescr = { 0 };
    ubyte* buffer = NULL;
    ubyte4 bufferLen;
    ubyte* keyblob = NULL;
    ubyte4 keyblobLen;
    int result = 0;
    int retVal = 0;

    if ((retVal = UNITTEST_STATUS(hint, DIGICERT_readFile( certFileName, &buffer,
                                                        &bufferLen))))
    {
        goto exit;
    }

    if ((retVal = UNITTEST_STATUS(hint, DIGICERT_readFile( keyFileName, &keyblob,
                                                        &keyblobLen))))
    {
        goto exit;
    }

    certDescr.pCertificate  = buffer;
    certDescr.certLength    = bufferLen;
    certDescr.pKeyBlob      = keyblob;
    certDescr.keyBlobLength = keyblobLen;

    if ((retVal = UNITTEST_STATUS(hint, CA_MGMT_verifyCertWithKeyBlob( &certDescr, &result))))
    {
        goto exit;
    }

    retVal = UNITTEST_INT(hint, result, 1);

exit:

    if (NULL != buffer)
        FREE( buffer);

    if (NULL != keyblob)
        FREE( keyblob);

    return retVal;
}


/*---------------------------------------------------------------------------*/

int test_verifyCertWithKeyBlob()
{
    int retVal = 0;
    int hint;

    retVal += VerifyCertWithKeyBlob( FILE_PATH("RSACert1024.der"), FILE_PATH("RSACert1024Key.dat"), hint = 0);
    retVal += VerifyCertWithKeyBlob( FILE_PATH("ECDHCert521.der"), FILE_PATH("ECDHCert521Key.dat"), hint = 1);

    return retVal;
}


/*---------------------------------------------------------------------------*/

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
    {localityName_OID, 0, (ubyte*)"San Francisco", 13}                       /* locality */
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
    {commonName_OID, 0, (ubyte*)"ssltest.mocana.com", 18}            /* common name */
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

static certDistinguishedName gCertNames =
{
    pRDNs, 7,
    /* Note: Internet Explorer limits a 30 year lifetime for certificates */
                                                /* time format yymmddhhmmss */
    (sbyte*) "251115110000Z",                            /* certificate start date */
    (sbyte*) "541115110000Z"                             /* certificate end date */
};

typedef struct CertificateInfo
{
    const char*    certFileName;
    const char*    certKeyFileName;
    const char*    orgUnit;
    certDescriptor  certDesc;
    ubyte4          keySize;
} CertificateInfo;


typedef struct SerialNumberTest
{
    Blob serialNumberInput;
    Blob serialNumberOutput;
} SerialNumberTest;

#define CERTIFICATE_INFO( cf, ou, ecc) { cf".der", cf"Key.dat", ou, { 0 }, ecc }

static CertificateInfo gCertificates1[] =
{
    CERTIFICATE_INFO( FILE_PATH("RSACertCA"), "Engineering CA (RSA 1024)", 1024),
    CERTIFICATE_INFO( FILE_PATH("ECDHCert192_RSA"), "Engineering CA (ECC 192)", 192),
    CERTIFICATE_INFO( FILE_PATH("ECDHCert224_RSA"), "Engineering CA (ECC 224)", 224),
    CERTIFICATE_INFO( FILE_PATH("ECDHCert256_RSA"), "Engineering CA (ECC 256)", 256),
    CERTIFICATE_INFO( FILE_PATH("ECDHCert384_RSA"), "Engineering CA (ECC 384)", 384),
    CERTIFICATE_INFO( FILE_PATH("ECDHCert521_RSA"), "Engineering CA (ECC 521)", 521),
};

static CertificateInfo gCertificates2[] =
{
    CERTIFICATE_INFO( FILE_PATH("ECCCertCA"), "Engineering CA (ECC 521)", 521),
    CERTIFICATE_INFO( FILE_PATH("ECDHCert192_ECC"), "Engineering CA (ECC 192)", 192),
    CERTIFICATE_INFO( FILE_PATH("ECDHCert224_ECC"), "Engineering CA (ECC 224)", 224),
    CERTIFICATE_INFO( FILE_PATH("ECDHCert256_ECC"), "Engineering CA (ECC 256)", 256),
    CERTIFICATE_INFO( FILE_PATH("ECDHCert384_ECC"), "Engineering CA (ECC 384)", 384),
    CERTIFICATE_INFO( FILE_PATH("ECDHCert521_ECC"), "Engineering CA (ECC 521)", 521),
};


static SerialNumberTest gSerialNumberTests1[] =
{
    {
        { 3, (ubyte*) "\x12\x34\x56" },
        { 3, (ubyte*) "\x12\x34\x56" }
    },

    {
        { 3, (ubyte*) "\x80\x12\x34" },
        { 4, (ubyte*) "\x00\x80\x12\x34" }
    },

    {
        { 20, (ubyte*) "\x80\x12\x34\x56\x78\x90\x12\x34\x56\x78\x90\x12\x34\x56\x78\x90\x12\x34\x56\x78" },
        { 20, (ubyte*) "\x00\x80\x12\x34\x56\x78\x90\x12\x34\x56\x78\x90\x12\x34\x56\x78\x90\x12\x34\x56" }
    },
    {
        { 20, (ubyte*) "\x12\x34\x56\x78\x90\x12\x34\x56\x78\x90\x12\x34\x56\x78\x90\x12\x34\x56\x78\x90" },
        { 20, (ubyte*) "\x12\x34\x56\x78\x90\x12\x34\x56\x78\x90\x12\x34\x56\x78\x90\x12\x34\x56\x78\x90" }
    },

};

static SubjectAltNameAttr gSanAttr[] =
{
    {{ 0, (ubyte*) "*.googleusercontent.com"}, 2 },
    {{ 0, (ubyte*) "*.blogspot.com"}, 2 },
    {{ 0, (ubyte*) "*.bp.blogspot.com"}, 2 },
    {{ 0, (ubyte*) "*.commondatastorage.googleapis.com"}, 2 },
    {{ 0, (ubyte*) "*.doubleclickusercontent.com"}, 2 },
    {{ 0, (ubyte*) "*.ggpht.com"}, 2 },
    {{ 0, (ubyte*) "*.googledrive.com"}, 2 },
    {{ 0, (ubyte*) "*.googlesyndication.com"}, 2 },
    {{ 0, (ubyte*) "*.googleweblight.com"}, 2 },
    {{ 0, (ubyte*) "*.safenup.googleusercontent.com"}, 2 },
    {{ 0, (ubyte*) "*.sandbox.googleusercontent.com"}, 2 },
    {{ 0, (ubyte*) "*.storage.googleapis.com"}, 2 },
    {{ 0, (ubyte*) "blogspot.com"}, 2 },
    {{ 0, (ubyte*) "bp.blogspot.com"}, 2 },
    {{ 0, (ubyte*) "commondatastorage.googleapis.com"}, 2 },
    {{ 0, (ubyte*) "doubleclickusercontent.com"}, 2 },
    {{ 0, (ubyte*) "ggpht.com"}, 2 },
    {{ 0, (ubyte*) "googledrive.com"}, 2 },
    {{ 0, (ubyte*) "googleusercontent.com"}, 2 },
    {{ 0, (ubyte*) "googleweblight.com"}, 2 },
    {{ 0, (ubyte*) "static.panoramio.com.storage.googleapis.com"}, 2 },
    {{ 0, (ubyte*) "storage.googleapis.com"}, 2}
};

/*---------------------------------------------------------------------------*/

/* create a certificate */
static MSTATUS
CreateCertificate( ubyte hashType, CertificateInfo* pCI, CertificateInfo* pParentCI)
{
    MSTATUS                 retVal;
    certExtensions          extensions;
    ubyte*                  publicKeyBlob = 0;
    ubyte4                  publicKeyBlobLength;
    ubyte4                  keyType;
    AsymmetricKey           pubKey, privKey;
    byteBoolean             equal;


    CRYPTO_initAsymmetricKey(&pubKey);
    CRYPTO_initAsymmetricKey(&privKey);

    /* free any allocated stuff to start from scratch */
    CA_MGMT_freeCertificate( &pCI->certDesc);

    extensions.hasBasicConstraints = TRUE;
    extensions.certPathLen = -1; /* omit */
    extensions.hasKeyUsage = TRUE;
    extensions.otherExts = NULL;
    extensions.otherExtCount = 0;

    if ( pParentCI) /* parent certificate */
    {
        /* find the parent certificate info by name */
        extensions.isCA = FALSE;
        extensions.keyUsage = 0x05; /* key encipherment, digital signature */
    }
    else
    {
        extensions.isCA = TRUE;
        extensions.keyUsage = 0x65; /*  key encipherment, digital signature,
                                        certificate and CRL signing */
    }

    /* change the certNames OU */
    (gCertNames.pDistinguishedName+3)->pNameAttr->value = (ubyte*) pCI->orgUnit;
    (gCertNames.pDistinguishedName+3)->pNameAttr->valueLen = DIGI_STRLEN((const sbyte*) pCI->orgUnit);

    if (OK > (retVal = CA_MGMT_generateCertificateEx( &pCI->certDesc, pCI->keySize,
                                    &gCertNames, hashType, &extensions,
                                    (pParentCI) ? &pParentCI->certDesc : NULL)))
    {
        goto exit;
    }

    /* save to file */
    if (OK > ( retVal = DIGICERT_writeFile( pCI->certFileName, pCI->certDesc.pCertificate,
                                pCI->certDesc.certLength)))
    {
        goto exit;
    }

    if (OK > ( retVal = DIGICERT_writeFile( pCI->certKeyFileName, pCI->certDesc.pKeyBlob,
                                pCI->certDesc.keyBlobLength)))
    {
        goto exit;
    }


    /* test for CA_MGMT_extractPublicKey */
    if (OK > ( retVal = CA_MGMT_extractPublicKey(pCI->certDesc.pKeyBlob, pCI->certDesc.keyBlobLength,
                                                    &publicKeyBlob, &publicKeyBlobLength, &keyType)))
    {
        goto exit;
    }

    if (OK > ( retVal = CA_MGMT_extractKeyBlobEx(publicKeyBlob, publicKeyBlobLength, &pubKey)))
    {
        goto exit;
    }

    if (OK > ( retVal = CA_MGMT_extractKeyBlobEx(pCI->certDesc.pKeyBlob,pCI->certDesc.keyBlobLength, &privKey)))
    {
        goto exit;
    }

    if (0 != UNITTEST_TRUE( 0, pubKey.type == privKey.type))
    {
        retVal = ERR_FALSE;
        goto exit;
    }


    switch ( pubKey.type)
    {
        case akt_rsa:
            if (OK > ( retVal = RSA_equalKey(MOC_RSA(gpHwAccelCtx) pubKey.key.pRSA, privKey.key.pRSA, &equal)))
            {
                goto exit;
            }
            break;

        case akt_ecc:
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            if (OK > ( retVal = CRYPTO_INTERFACE_EC_equalKeyAux(MOC_ECC(gpHwAccelCtx)  pubKey.key.pECC, privKey.key.pECC, &equal)))
#else
            if (OK > ( retVal = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) pubKey.key.pECC, privKey.key.pECC, &equal)))
#endif
            {
                goto exit;
            }
            break;

        default:
            retVal = ERR_CRYPTO_BAD_KEY_TYPE;
            break;
    }

    if ( 0 != UNITTEST_TRUE(0, FALSE != equal))
    {
        retVal = ERR_FALSE;
        goto exit;
    }

exit:

    if (publicKeyBlob)
    {
        FREE(publicKeyBlob);
    }

    CRYPTO_uninitAsymmetricKey(&pubKey, NULL);
    CRYPTO_uninitAsymmetricKey(&privKey, NULL);


    return retVal;
}

/*---------------------------------------------------------------------------*/

static int
CreateAllCertificates(int hint, ubyte hashType, CertificateInfo* pCerts, int certCount)
{
    MSTATUS status;
    int retVal = 0;
    int i;

    status = CreateCertificate( hashType, pCerts, NULL); /* first is root certificate */
    retVal += UNITTEST_STATUS(hint, status);
    if (retVal) return retVal;

    for (i = 1; i < certCount; ++i)
    {
        retVal += UNITTEST_STATUS(hint + i, CreateCertificate( hashType, pCerts+i, pCerts));
    }
    return retVal;
}


/*---------------------------------------------------------------------------*/

static int
VerifyCertificate(int hint, certDescriptor* cert, certDescriptor* parentCert)
{
    MSTATUS status;
    int retVal = 0;
    MemFile mf, parentMf;
    CStream cs, parentCs;
    ASN1_ITEMPTR pRootItem = 0, pParentRootItem = 0;
    hwAccelDescr hwAccelCtx;

    if (OK > (MSTATUS)(status = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return status;

    MF_attach( &mf, (sbyte4)cert->certLength, cert->pCertificate);
    CS_AttachMemFile(&cs, &mf);

    status = ASN1_Parse( cs, &pRootItem);
    retVal += UNITTEST_STATUS(hint, status);
    if (retVal) goto exit;

    if (parentCert)
    {
        MF_attach( &parentMf, (sbyte4)parentCert->certLength, parentCert->pCertificate);
        CS_AttachMemFile(&parentCs, &parentMf);

        status = ASN1_Parse( parentCs, &pParentRootItem);
        retVal += UNITTEST_STATUS(hint, status);
        if (retVal) goto exit;
    }
    else
    {
        pParentRootItem = pRootItem;
        parentCs = cs;
    }

    status = X509_validateLink(MOC_ASYM(hwAccelCtx)
                               ASN1_FIRST_CHILD(pRootItem), cs,
                               ASN1_FIRST_CHILD(pParentRootItem), parentCs,
                               0); /* chain length */

    if (OK <= status)
    {
        TimeDate td;
        RTOS_timeGMT( &td);
        status = X509_verifyValidityTime(ASN1_FIRST_CHILD(pRootItem), cs, &td);
    }

    if ( OK > status)
    {
        char fileName[255];
        /* save the certificates in separate files to look at */
        TimeDate td;
        RTOS_timeGMT( &td);

        UNITTEST_UTILS_make_file_name((sbyte*)"leaf", &td, (sbyte*) fileName);
        DIGICERT_writeFile(fileName, cert->pCertificate, cert->certLength);

        if (parentCert)
        {
            DIGI_MEMCPY(fileName, "root", 4);
            DIGICERT_writeFile(fileName, parentCert->pCertificate, parentCert->certLength);
        }

    }
    retVal += UNITTEST_STATUS(hint, status);

exit:

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    if (pRootItem)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRootItem);
    }

    if (parentCert && pParentRootItem)
    {
        TREE_DeleteTreeItem( (TreeItem*) pParentRootItem);
    }

    return retVal;
}


/*---------------------------------------------------------------------------*/

static int
VerifyAllCertificates(int hint, CertificateInfo* pCerts, int certCount)
{
    int retVal = 0;
    int i;

    retVal = VerifyCertificate(hint, &(pCerts[0].certDesc), NULL); /* first is root certificate */

    for (i = 1; i < certCount; ++i)
    {
        retVal += VerifyCertificate(hint + i, &(pCerts[i].certDesc), &(pCerts[0].certDesc));
    }
    return retVal;
}


/*--------------------------------------------------------------------------*/

sbyte4 AltNameEnumCallback( const ubyte* altNameValue, ubyte4 altNameLen,
                           ubyte4 type, ubyte4 index, void* userArg)
{
    int* pTestInfo = (int*) userArg;
    int errors = 0;
    int hint = pTestInfo[0];

    if ( index < COUNTOF(gSanAttr))
    {
        SubjectAltNameAttr* pCurrAltName = gSanAttr+index;

        errors += UNITTEST_INT(hint, type, pCurrAltName->subjectAltNameType);
        errors += UNITTEST_INT(hint, altNameLen, pCurrAltName->subjectAltNameValue.dataLen);

        if (altNameLen == pCurrAltName->subjectAltNameValue.dataLen)
        {
            int cmpRes;

            DIGI_MEMCMP( altNameValue, pCurrAltName->subjectAltNameValue.data,
                       altNameLen, &cmpRes);
            errors += UNITTEST_INT(pTestInfo[0], cmpRes, 0);
        }
    }
    else
    {
        errors += UNITTEST_TRUE( pTestInfo[0], index < COUNTOF(gSanAttr));
    }

    /* make sure we see all values */
    errors += UNITTEST_INT( pTestInfo[0], index, pTestInfo[2]);
    pTestInfo[2] = index+1; /* count */

    pTestInfo[1] += errors;
    return 0;
}

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_TAP__
static int
VerifySubjectAltNamesAux(int hint, certDescriptor* cert)
{
    int retVal = 0;
    int testInfo[3] = { 0 }; /* 0:hint, 1:errors, 2:count */

    testInfo[0] = hint;
    UNITTEST_STATUS_GOTO( hint, CA_MGMT_enumAltName( cert->pCertificate,
                                                    cert->certLength,
                                                    TRUE,
                                                    AltNameEnumCallback,
                                                    testInfo),
                                                    retVal, exit);

    retVal += UNITTEST_INT(hint, testInfo[2], COUNTOF(gSanAttr));

    retVal += testInfo[1];

  exit:

    return retVal;
}

/*---------------------------------------------------------------------------*/

static int
VerifySubjectAltNames(int hint, CertificateInfo* pCerts, int certCount)
{
    int retVal = 0;
    int i;

    for (i = 0; i < certCount; ++i)
    {
        retVal += VerifySubjectAltNamesAux(hint + i, &(pCerts[i].certDesc));
    }
    return retVal;
}
#endif

/*---------------------------------------------------------------------------*/

static void
FreeAllCertificates(CertificateInfo* pCerts, int certCount)
{
    int i;
    for (i = 0; i < certCount; ++i)
    {
        if (pCerts[i].certDesc.pCertificate)
        {
            FREE(pCerts[i].certDesc.pCertificate);
            pCerts[i].certDesc.pCertificate = 0;
        }
        if (pCerts[i].certDesc.pKeyBlob)
        {
            FREE(pCerts[i].certDesc.pKeyBlob);
            pCerts[i].certDesc.pKeyBlob = 0;
        }
    }
}

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_TAP__

/* create a certificate with an existing key and serial number; also
 uses all the Subject Alternative Names in gSanAttr */
static int
CreateCertificate2( int hint, ubyte hashType, CertificateInfo* pCI,
                   CertificateInfo* pParentCI, SerialNumberTest* pSNT)
{
    int                 retVal = 0;
    certExtensions      allExtensions;
    ubyte*              publicKeyBlob = 0;
    ubyte4              publicKeyBlobLength;
    ubyte4              keyType;
    AsymmetricKey       pubKey, privKey;
    byteBoolean         equal;
    CertProperties      certProperties = { 0};
    Blob                genSN = { 0, 0};
    sbyte4              resCmp;
    extensions          sanExtension = { 0};

    CRYPTO_initAsymmetricKey(&pubKey);
    CRYPTO_initAsymmetricKey(&privKey);

    /* free any allocated stuff to start from scratch */
    CA_MGMT_freeCertificate( &pCI->certDesc);

    allExtensions.hasBasicConstraints = TRUE;
    allExtensions.certPathLen = -1; /* omit */
    allExtensions.hasKeyUsage = TRUE;
    allExtensions.otherExts = &sanExtension;
    allExtensions.otherExtCount = 1;


    UNITTEST_STATUS_GOTO(hint,
                         CA_MGMT_makeSubjectAltNameExtension(&sanExtension,
                                                            gSanAttr,
                                                            COUNTOF(gSanAttr)),
                         retVal, exit);

    if ( pParentCI) /* parent certificate */
    {
        /* find the parent certificate info by name */
        allExtensions.isCA = FALSE;
        allExtensions.keyUsage = 0x05; /* key encipherment, digital signature */
    }
    else
    {
        allExtensions.isCA = TRUE;
        allExtensions.keyUsage = 0x65; /*  key encipherment, digital signature,
                                     certificate and CRL signing */
    }

    /* change the certNames OU */
    (gCertNames.pDistinguishedName+3)->pNameAttr->value = (ubyte*) pCI->orgUnit;
    (gCertNames.pDistinguishedName+3)->pNameAttr->valueLen = DIGI_STRLEN((const sbyte*) pCI->orgUnit);

    /* read the key from a blob created earlier */
    UNITTEST_STATUS_GOTO(hint, DIGICERT_readFile(pCI->certKeyFileName,
                                               &certProperties.keyProperty.keyBlob.data,
                                               &certProperties.keyProperty.keyBlob.dataLen),
                         retVal, exit);

    certProperties.keyPropertyType = kp_blob;

    certProperties.pExtensions = &allExtensions;
    certProperties.pParentCert = (pParentCI) ? &pParentCI->certDesc : NULL;
    certProperties.serialNumber = pSNT->serialNumberInput;
    certProperties.signAlgorithm = hashType;

    UNITTEST_STATUS_GOTO(hint, CA_MGMT_generateCertificateWithProperties(&pCI->certDesc,
                                                                 &gCertNames,
                                                                 &certProperties),
                         retVal, exit);

    /* save to file */
    UNITTEST_STATUS_GOTO(hint, DIGICERT_writeFile( pCI->certFileName, pCI->certDesc.pCertificate,
                                         pCI->certDesc.certLength),
                        retVal, exit);


    UNITTEST_STATUS_GOTO(hint, DIGICERT_writeFile( pCI->certKeyFileName, pCI->certDesc.pKeyBlob,
                                                pCI->certDesc.keyBlobLength),
                         retVal, exit);

    /* test for CA_MGMT_extractPublicKey */
    UNITTEST_STATUS_GOTO(hint, CA_MGMT_extractPublicKey(pCI->certDesc.pKeyBlob, pCI->certDesc.keyBlobLength,
                                                 &publicKeyBlob, &publicKeyBlobLength, &keyType),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(hint, CA_MGMT_extractKeyBlobEx(publicKeyBlob, publicKeyBlobLength, &pubKey),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(hint, CA_MGMT_extractKeyBlobEx(pCI->certDesc.pKeyBlob,pCI->certDesc.keyBlobLength, &privKey),
                         retVal, exit);

    retVal += UNITTEST_TRUE( 0, pubKey.type == privKey.type);

    switch ( pubKey.type)
    {
        case akt_rsa:
            UNITTEST_STATUS_GOTO(hint, RSA_equalKey(MOC_RSA(gpHwAccelCtx) pubKey.key.pRSA, privKey.key.pRSA, &equal),
                                 retVal, exit);
            break;

        case akt_ecc:
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            UNITTEST_STATUS_GOTO(
                hint, CRYPTO_INTERFACE_EC_equalKeyAux(MOC_ECC(gpHwAccelCtx) pubKey.key.pECC, privKey.key.pECC, &equal), retVal, exit);
#else
            UNITTEST_STATUS_GOTO(
                hint, EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) pubKey.key.pECC, privKey.key.pECC, &equal), retVal, exit);
#endif
            break;

        default:
            UNITTEST_STATUS_GOTO(hint, ERR_CRYPTO_BAD_KEY_TYPE, retVal, exit);
            break;
    }

    retVal += UNITTEST_TRUE(0, FALSE != equal);

    retVal += UNITTEST_STATUS( hint,
                              CA_MGMT_extractSerialNum(pCI->certDesc.pCertificate,
                                                       pCI->certDesc.certLength,
                                                       &genSN.data,
                                                       &genSN.dataLen));
    if (retVal) goto exit;


    retVal += UNITTEST_INT(hint, genSN.dataLen, pSNT->serialNumberOutput.dataLen);
    if (retVal) goto exit;

    DIGI_MEMCMP(pSNT->serialNumberOutput.data,
               genSN.data, genSN.dataLen, &resCmp);

    retVal += UNITTEST_TRUE(hint, 0 == resCmp);

exit:

    FREE( genSN.data);

    if (publicKeyBlob)
    {
        FREE(publicKeyBlob);
    }

    CRYPTO_uninitAsymmetricKey(&pubKey, NULL);
    CRYPTO_uninitAsymmetricKey(&privKey, NULL);

    FREE( sanExtension.value);

    FREE( certProperties.keyProperty.keyBlob.data);
    return retVal;
}

/*---------------------------------------------------------------------------*/

static int
CreateAllCertificates2(int hint, ubyte hashType, CertificateInfo* pCerts, int certCount)
{
    MSTATUS status;
    int retVal = 0;
    int i;

    status = CreateCertificate2( hint, hashType, pCerts, NULL, gSerialNumberTests1); /* first is root certificate */
    retVal += UNITTEST_STATUS(hint, status);
    if (retVal) return retVal;

    for (i = 1; i < certCount; ++i)
    {
        int serialNumberIndex = (i % COUNTOF(gSerialNumberTests1));

        retVal += CreateCertificate2( hint + i, hashType,
                                     pCerts+i, pCerts,
                                     gSerialNumberTests1 + serialNumberIndex);
    }
    return retVal;
}

/*---------------------------------------------------------------------------*/

int test_create_verify_certs()
{
    int i, retVal;
    int hint;

    hint = (1 << 16);
    retVal = CreateAllCertificates(hint, ht_sha1, gCertificates1, COUNTOF(gCertificates1));
    if (0 == retVal)
    {
        retVal += VerifyAllCertificates(hint, gCertificates1, COUNTOF(gCertificates1));
    }
    FreeAllCertificates(gCertificates1, COUNTOF(gCertificates1));

    hint = (2 << 16);
    retVal += CreateAllCertificates(hint, ht_sha1, gCertificates2,  COUNTOF(gCertificates2));
    if (0 == retVal)
    {
        retVal += VerifyAllCertificates(hint, gCertificates2, COUNTOF(gCertificates2));
    }
    FreeAllCertificates(gCertificates2, COUNTOF(gCertificates2));

    hint = (3 << 16);
    retVal = CreateAllCertificates(hint, ht_sha224, gCertificates1, COUNTOF(gCertificates1));
    if (0 == retVal)
    {
        retVal += VerifyAllCertificates(hint, gCertificates1, COUNTOF(gCertificates1));
    }
    FreeAllCertificates(gCertificates1, COUNTOF(gCertificates1));

    hint = (4 << 16);
    retVal += CreateAllCertificates(hint, ht_sha224, gCertificates2, COUNTOF(gCertificates2));
    if (0 == retVal)
    {
        retVal += VerifyAllCertificates(hint, gCertificates2, COUNTOF(gCertificates2));
    }
    FreeAllCertificates(gCertificates2, COUNTOF(gCertificates2));

    hint = (5 << 16);
    retVal = CreateAllCertificates(hint, ht_sha256, gCertificates1, COUNTOF(gCertificates1));
    if (0 == retVal)
    {
        retVal += VerifyAllCertificates(hint, gCertificates1, COUNTOF(gCertificates1));
    }
    FreeAllCertificates(gCertificates1, COUNTOF(gCertificates1));

    hint = (6 << 16);
    retVal += CreateAllCertificates(hint, ht_sha256, gCertificates2, COUNTOF(gCertificates2));
    if (0 == retVal)
    {
        retVal += VerifyAllCertificates(hint, gCertificates2, COUNTOF(gCertificates2));
    }
    FreeAllCertificates(gCertificates2, COUNTOF(gCertificates2));

    hint = (7 << 16);
    retVal = CreateAllCertificates(hint, ht_sha384, gCertificates1, COUNTOF(gCertificates1));
    if (0 == retVal)
    {
        retVal += VerifyAllCertificates(hint, gCertificates1, COUNTOF(gCertificates1));
    }
    FreeAllCertificates(gCertificates1, COUNTOF(gCertificates1));

    hint = (8 << 16);
    retVal += CreateAllCertificates(hint, ht_sha384, gCertificates2, COUNTOF(gCertificates2));
    if (0 == retVal)
    {
        retVal += VerifyAllCertificates(hint, gCertificates2, COUNTOF(gCertificates2));
    }
    FreeAllCertificates(gCertificates2, COUNTOF(gCertificates2));

    hint = (9 << 16);
    retVal = CreateAllCertificates(hint, ht_sha512, gCertificates1, COUNTOF(gCertificates1));
    if (0 == retVal)
    {
        retVal += VerifyAllCertificates(hint, gCertificates1, COUNTOF(gCertificates1));
    }
    FreeAllCertificates(gCertificates1, COUNTOF(gCertificates1));

    hint = (10 << 16);
    retVal += CreateAllCertificates(hint, ht_sha512, gCertificates2, COUNTOF(gCertificates2));
    if (0 == retVal)
    {
        retVal += VerifyAllCertificates(hint, gCertificates2, COUNTOF(gCertificates2));
    }
    FreeAllCertificates(gCertificates2, COUNTOF(gCertificates2));


    /* finish setting up the gSanAttr before calling CreateAllCertificates2 */
    for (i = 0; i < COUNTOF(gSanAttr); ++i)
    {
        gSanAttr[i].subjectAltNameValue.dataLen =
            DIGI_STRLEN((const sbyte*) gSanAttr[i].subjectAltNameValue.data);
    }

    hint = (11 << 16);
    retVal += CreateAllCertificates2(hint, ht_sha256, gCertificates1, COUNTOF(gCertificates1));
    if (0 == retVal)
    {
        retVal += VerifyAllCertificates(hint, gCertificates1, COUNTOF(gCertificates1));
        retVal += VerifySubjectAltNames(hint, gCertificates1, COUNTOF(gCertificates1));
    }
    FreeAllCertificates(gCertificates1, COUNTOF(gCertificates1));

    hint = (12 << 16);
    retVal += CreateAllCertificates2(hint, ht_sha256, gCertificates2, COUNTOF(gCertificates2));
    if (0 == retVal)
    {
        retVal += VerifyAllCertificates(hint, gCertificates2, COUNTOF(gCertificates2));
        retVal += VerifySubjectAltNames(hint, gCertificates2, COUNTOF(gCertificates2));
    }
    FreeAllCertificates(gCertificates2, COUNTOF(gCertificates2));

    return retVal;
}
#endif /* __ENABLE_DIGICERT_TAP__ */
/*---------------------------------------------------------------------------*/


#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)

#ifdef __EDWARDS_PRINT_CERT_AND_KEY__
#include <stdio.h>
#endif

static int test_edwards_certs(void)
{
    MSTATUS status;
    int retVal = 0;
    certDescriptor retCert = {0};
    certExtensions extensions = {0};

    ubyte *pPub = NULL;
    ubyte4 pubLen = 0;

    sbyte4 good;

    extensions.hasBasicConstraints = TRUE;
    extensions.certPathLen = -1; /* omit */
    extensions.hasKeyUsage = TRUE;
    extensions.otherExts = NULL;
    extensions.otherExtCount = 0;
    extensions.isCA = TRUE;
    extensions.keyUsage = 0x65; /*  key encipherment, digital signature,
                                 certificate and CRL signing */

#ifdef __EDWARDS_PRINT_CERT_AND_KEY__
    ubyte *pemKey = NULL;
    ubyte4 pemKeyLen = 0;

    FILE *pOutCa = NULL;
    FILE *pOutKey = NULL;
#endif

    /* Test a prime curve first just as a control sample */
    status = CA_MGMT_generateCertificateExType(&retCert, akt_ecc, 256, &gCertNames, ht_sha256, &extensions, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (retVal) goto exit;

#ifdef __EDWARDS_PRINT_CERT_AND_KEY__
    status = CA_MGMT_keyBlobToPEM(retCert.pKeyBlob, retCert.keyBlobLength, &pemKey, &pemKeyLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (retVal) goto exit;

    pOutCa = fopen("cert256.der", "wb");
    if (pOutCa != NULL)
    {
        fwrite(retCert.pCertificate, 1, retCert.certLength, pOutCa);
        fclose(pOutCa);
    }

    pOutKey = fopen("key256.pem", "w");
    if (pOutKey != NULL)
    {
        fwrite(pemKey, 1, pemKeyLen, pOutKey);
        fclose(pOutKey);
    }

    if (NULL != pemKey)
    {
        DIGI_FREE((void **) &pemKey);
        pemKeyLen = 0;
    }
#endif

    status = CA_MGMT_extractPublicKeyInfo(retCert.pCertificate, retCert.certLength, &pPub, &pubLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (retVal) goto exit;

    status = CA_MGMT_verifySignature(pPub, pubLen, retCert.pCertificate, retCert.certLength);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (retVal) goto exit;

    status = CA_MGMT_verifyCertWithKeyBlob(&retCert, &good);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (retVal) goto exit;

    if (!good)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
    }

    status = CA_MGMT_freeCertificate(&retCert);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (retVal) goto exit;

    if (NULL != pPub)
    {
        DIGI_FREE((void **) &pPub);
    }

    /**** Test curve 448 ****/

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__

    status = CA_MGMT_generateCertificateExType(&retCert, akt_ecc_ed, 448, &gCertNames, 0, &extensions, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (retVal) goto exit;

#ifdef __EDWARDS_PRINT_CERT_AND_KEY__
    status = CA_MGMT_keyBlobToPEM(retCert.pKeyBlob, retCert.keyBlobLength, &pemKey, &pemKeyLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (retVal) goto exit;

    pOutCa = fopen("cert448.der", "wb");
    if (pOutCa != NULL)
    {
        fwrite(retCert.pCertificate, 1, retCert.certLength, pOutCa);
        fclose(pOutCa);
    }

    pOutKey = fopen("key448.pem", "w");
    if (pOutKey != NULL)
    {
        fwrite(pemKey, 1, pemKeyLen, pOutKey);
        fclose(pOutKey);
    }

    if (NULL != pemKey)
    {
        DIGI_FREE((void **) &pemKey);
        pemKeyLen = 0;
    }
#endif
    status = CA_MGMT_extractPublicKeyInfo(retCert.pCertificate, retCert.certLength, &pPub, &pubLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (retVal) goto exit;

    status = CA_MGMT_verifySignature(pPub, pubLen, retCert.pCertificate, retCert.certLength);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (retVal) goto exit;

    status = CA_MGMT_verifyCertWithKeyBlob(&retCert, &good);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (retVal) goto exit;

    if (!good)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
    }

    status = CA_MGMT_freeCertificate(&retCert);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (retVal) goto exit;

    if (NULL != pPub)
    {
        DIGI_FREE((void **) &pPub);
    }

#endif

    /**** Test curve 25519 ****/

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__

    status = CA_MGMT_generateCertificateExType(&retCert, akt_ecc_ed, 255, &gCertNames, 0, &extensions, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (retVal) goto exit;

#ifdef __EDWARDS_PRINT_CERT_AND_KEY__
    status = CA_MGMT_keyBlobToPEM(retCert.pKeyBlob, retCert.keyBlobLength, &pemKey, &pemKeyLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (retVal) goto exit;

    pOutCa = fopen("cert25519.der", "wb");
    if (pOutCa != NULL)
    {
        fwrite(retCert.pCertificate, 1, retCert.certLength, pOutCa);
        fclose(pOutCa);
    }

    pOutKey = fopen("key25519.pem", "w");
    if (pOutKey != NULL)
    {
        fwrite(pemKey, 1, pemKeyLen, pOutKey);
        fclose(pOutKey);
    }
#endif

    status = CA_MGMT_extractPublicKeyInfo(retCert.pCertificate, retCert.certLength, &pPub, &pubLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (retVal) goto exit;

    status = CA_MGMT_verifySignature(pPub, pubLen, retCert.pCertificate, retCert.certLength);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (retVal) goto exit;

    status = CA_MGMT_verifyCertWithKeyBlob(&retCert, &good);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (retVal) goto exit;

    if (!good)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
    }

#endif

exit:

#ifdef __EDWARDS_PRINT_CERT_AND_KEY__
    if (NULL != pemKey)
    {
        DIGI_FREE((void **) &pemKey);
    }
#endif

    status = CA_MGMT_freeCertificate(&retCert);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

    if (NULL != pPub)
    {
        DIGI_FREE((void **) &pPub);
    }

    return retVal;
}
#endif

#ifdef __ENABLE_DIGICERT_PQC__
static int test_hybrid_certs(ubyte4 qsAlg, ubyte4 clAlg)
{
    MSTATUS status;
    int retVal = 0;
    certDescriptor retCert = {0};
    certExtensions extensions = {0};

    ubyte *pPub = NULL;
    ubyte4 pubLen = 0;

    extensions.hasBasicConstraints = TRUE;
    extensions.certPathLen = -1; /* omit */
    extensions.hasKeyUsage = TRUE;
    extensions.otherExts = NULL;
    extensions.otherExtCount = 0;
    extensions.isCA = TRUE;
    extensions.keyUsage = 0x65; /*  key encipherment, digital signature,
                                    certificate and CRL signing */

    status = CA_MGMT_generateCertificateHybrid(MOC_ASYM(gpHwAccelCtx) &retCert, clAlg, qsAlg, &gCertNames, &extensions, NULL);
    retVal += UNITTEST_STATUS(clAlg, status);
    if (retVal) goto exit;

    status = CA_MGMT_extractPublicKeyInfo(retCert.pCertificate, retCert.certLength, &pPub, &pubLen);
    retVal += UNITTEST_STATUS(clAlg, status);
    if (retVal) goto exit;

    status = CA_MGMT_verifySignature(pPub, pubLen, retCert.pCertificate, retCert.certLength);
    retVal += UNITTEST_STATUS(clAlg, status);

exit:

    status = CA_MGMT_freeCertificate(&retCert);
    retVal += UNITTEST_STATUS(clAlg, status);

    if (NULL != pPub)
    {
        DIGI_FREE((void **) &pPub);
    }

    return retVal;
}
#endif /* __ENABLE_DIGICERT_PQC__ */

/*---------------------------------------------------------------------------*/

int crypto_interface_ca_mgmt_test_init()
{
  int errorCount = 0;

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
#ifndef __ENABLE_DIGICERT_TAP__
  errorCount += test_enumCRL ();
#endif
  errorCount += test_convertDER ();
  errorCount += test_convertPEM ();
  errorCount += test_decode_PEM ();
  errorCount += test_verifyCertWithKeyBlob ();
#ifndef __ENABLE_DIGICERT_TAP__
  errorCount += test_create_verify_certs ();
#endif
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
  errorCount += test_edwards_certs();
#ifdef __ENABLE_DIGICERT_PQC__

  errorCount += test_hybrid_certs(cid_PQC_MLDSA_44, cid_RSA_2048_PSS);
  errorCount += test_hybrid_certs(cid_PQC_MLDSA_44, cid_RSA_2048_PKCS15);
  errorCount += test_hybrid_certs(cid_PQC_MLDSA_44, cid_EC_Ed25519);
  errorCount += test_hybrid_certs(cid_PQC_MLDSA_44, cid_EC_P256);

  errorCount += test_hybrid_certs(cid_PQC_MLDSA_65, cid_RSA_3072_PSS);
  errorCount += test_hybrid_certs(cid_PQC_MLDSA_65, cid_RSA_3072_PKCS15);
  errorCount += test_hybrid_certs(cid_PQC_MLDSA_65, cid_RSA_4096_PSS);
  errorCount += test_hybrid_certs(cid_PQC_MLDSA_65, cid_RSA_4096_PKCS15);
  errorCount += test_hybrid_certs(cid_PQC_MLDSA_65, cid_EC_P256);
  errorCount += test_hybrid_certs(cid_PQC_MLDSA_65, cid_EC_P384);
  errorCount += test_hybrid_certs(cid_PQC_MLDSA_65, cid_EC_Ed25519);

  errorCount += test_hybrid_certs(cid_PQC_MLDSA_87, cid_EC_P384);
  errorCount += test_hybrid_certs(cid_PQC_MLDSA_87, cid_EC_Ed448);
  errorCount += test_hybrid_certs(cid_PQC_MLDSA_87, cid_RSA_4096_PSS);

#endif /* __ENABLE_DIGICERT_PQC__ */
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
  /* END   Tests */

exit:
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

  DIGICERT_free(&gpMocCtx);

#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__ */

  return errorCount;
}
