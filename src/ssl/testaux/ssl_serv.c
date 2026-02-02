/*
    ssl_serv.c

    implementation of a server that supports all
    the possible ciphers

    this can be used to test the implementation
    of all the ciphers.

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
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../crypto/secmod.h"
#include "../../common/mrtos.h"
#include "../../common/mtcp.h"
#include "../../common/moc_net.h"
#include "../../common/mocana.h"
#include "../../common/absstream.h"
#include "../../common/debug_console.h"
#include "../../common/mstdlib.h"
#include "../../common/sizedbuffer.h"
#include "../../common/tree.h"
#include "../../crypto/hw_accel.h"
#include "../../crypto/crypto.h"
#include "../../common/vlong.h"
#include "../../common/random.h"
#include "../../common/hash_value.h"
#include "../../common/hash_table.h"
#include "../../crypto/primefld.h"
#include "../../crypto/primeec.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/ca_mgmt.h"
#include "../../crypto/cert_store.h"
#include "../../crypto/srp.h"
#include "../../asn1/oiddefs.h"
#include "../../asn1/parseasn1.h"
#include "../../asn1/parsecert.h"
#include "../../ssl/ssl.h"
#ifdef __ENABLE_DIGICERT_TAP__
#include "../../smp/smp_cc.h"
#include "../../tap/tap_api.h"
#include "../../tap/tap_utils.h"
#include "../../tap/tap_smp.h"
#include "../../crypto/mocasym.h"
#include "../../crypto/mocasymkeys/tap/rsatap.h"
#include "../../crypto/mocasymkeys/tap/ecctap.h"
#include "../../crypto_interface/cryptointerface.h"
#endif

#include <stdint.h> /* intptr_t */
#include <string.h>
#include <stdio.h>

#include "ssl_serv_request.h"

static certStorePtr pSslCertStore;
static certStorePtr pSslOcspCertStore;

#if defined(WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

sbyte4   setMinorVersion = TLS12_MINORVERSION;

#define MAX_SSL_CONNECTIONS_ALLOWED (10)

nameAttr pNames1[] =
{
    {countryName_OID, 0, (ubyte*)"US", 2}                                /* country */
};
nameAttr pNames2[] =
{
    {stateOrProvinceName_OID, 0, (ubyte*)"California", 10}                       /* state or providence */
};
nameAttr pNames3[] =
{
    {localityName_OID, 0, (ubyte*)"San Francisco", 13}                       /* locality */
};
nameAttr pNames4[] =
{
    {organizationName_OID, 0, (ubyte*)"Mocana Corporation", 18}               /* company name */
};
nameAttr pNames5[] =
{
    {organizationalUnitName_OID, 0, (ubyte*)"Engineering", 11}                      /* organizational unit */
};
nameAttr pNames6[] =
{
    {commonName_OID, 0, (ubyte*)"ssltest.mocana.com", 18}            /* common name */
};
nameAttr pNames7[] =
{
    {pkcs9_emailAddress_OID, 0, (ubyte*)"info@mocana.com", 15}          /* pkcs-9-at-emailAddress */
};

relativeDN pRDNs[] =
{
    {pNames1, 1},
    {pNames2, 1},
    {pNames3, 1},
    {pNames4, 1},
    {pNames5, 1},
    {pNames6, 1},
    {pNames7, 1}
};

certDistinguishedName certNames =
{
    pRDNs, 7,
    /* Note: Internet Explorer limits a 30 year lifetime for certificates */
                                                /* time format yymmddhhmmss */
    (sbyte*) "150529110000Z",                            /* certificate start date */
    (sbyte*) "450529110000Z"                             /* certificate end date */
};

#ifdef __SSLSERV_EXPIRED_CERTS__
certDistinguishedName expiredCertNames =
{
    pRDNs, 7,
    /* Note: Internet Explorer limits a 30 year lifetime for certificates */
                                                /* time format yymmddhhmmss */
    (sbyte*) "131115110000Z",                            /* certificate start date */
    (sbyte*) "141115110000Z"                             /* certificate end date */
};
#endif

/* Mutual authentication testing: client certificate */
nameAttr pClientNames6[] =
{
    {commonName_OID, 0, (ubyte*)"sales.mocana.com", 18}            /* common name */
};

relativeDN pClientRDNs[] =
{
    {pNames1, 1},
    {pNames2, 1},
    {pNames3, 1},
    {pNames4, 1},
    {pNames5, 1},
    {pClientNames6, 1},
    {pNames7, 1}
};

certDistinguishedName clientCertNames =
{
    pClientRDNs, 7,
    /* Note: Internet Explorer limits a 30 year lifetime for certificates */
    /* time format yymmddhhmmss */
    (sbyte*) "051115110000Z",                            /* certificate start date */
    (sbyte*) "251115110000Z"                             /* certificate end date */
};



/* certificates -- assuming the test client will accept any self-signed
certificate, we need the following set of certificates for testing
all combinations of ciphers/elliptic curves :
RSA 1024 or 2048 or 4096 SelfSigned ( RSACertCA.der/RSACertCAKey.dat)
ECDH-ECDSA 192 SelfSigned           ( ECDHCert192CA.der/ECDHCert192CAKey.dat)
ECDH-ECDSA 224 SelfSigned           ( ECDHCert224CA.der/ECDHCert224CAKey.dat)
ECDH-ECDSA 256 SelfSigned           ( ECDHCert256CA.der/ECDHCert256CAKey.dat)
ECDH-ECDSA 384 SelfSigned           ( ECDHCert384CA.der/ECDHCert384CAKey.dat)
ECDH-ECDSA 521 SelfSigned           ( ECDHCert521CA.der/ECDHCert521CAKey.dat)
ECDH-ECDSA 192 Signed by RSA        ( ECDHCert192.der/ECDHCert192Key.dat)
ECDH-ECDSA 224 Signed by RSA        ( ECDHCert224.der/ECDHCert224Key.dat)
ECDH-ECDSA 256 Signed by RSA        ( ECDHCert256.der/ECDHCert256Key.dat)
ECDH-ECDSA 384 Signed by RSA        ( ECDHCert384.der/ECDHCert384Key.dat)
ECDH-ECDSA 521 Signed by RSA        ( ECDHCert521.der/ECDHCert521Key.dat)

in the case of the non-self signed certificates, the RSA certificate is sent
as part of the certificate chain
*/
typedef struct CertificateInfo
{
    const char*     certFileName;
    const char*     certKeyFileName;
    const char*     caCertFileName;
    const char*     orgUnit;
    certDescriptor  certDesc;
    ubyte4          keySize;
    const char*     commonName;
} CertificateInfo;


#define CERTIFICATE_INFO( cf, ou, ecc) { cf".der", cf"Key.dat", NULL, ou, { 0 }, ecc }
#define CERTIFICATE_INFO_KEY_DER( cf, ou, ecc) { cf".der", cf"Key.der", NULL, ou, { 0 }, ecc }

#define LEAF_CERTIFICATE_INFO(cf, cacf, ou, ecc) { cf".der", cf"Key.dat", cacf".der", ou, { 0 }, ecc }
#define LEAF_CERTIFICATE_INFO_CN(cf, cacf, ou, ecc, cn) { cf".der", cf"Key.dat", cacf".der", ou, { 0 }, ecc, cn }


#define CERTIFICATE_INFO_PEM( cf, ou, ecc) { cf"cert.der", cf"key.pem", NULL, ou, { 0 }, ecc }
#define LEAF_CERTIFICATE_INFO_PEM(cf, cacf, ou, ecc) { cf"cert.der", cf"key.pem", cacf".der", ou, { 0 }, ecc }
#define LEAF_CERTIFICATE_INFO_CN_PEM(cf, cacf, ou, ecc, cn) { cf"cert.der", cf"key.pem", cacf".der", ou, { 0 }, ecc, cn }

#if defined(__TEST_ONE_CERT__)

static CertificateInfo gCertificateInfos[] =
{
    CERTIFICATE_INFO_KEY_DER("cert", "Don't create", 2048)
};

static CertificateInfo gClientCertificates[] =
{
};

static CertificateInfo gUnknownClientCertificates[] =
{
};

#else

#if defined( __SSLSERV_EXPIRED_CERTS__)
static CertificateInfo gCertificateInfos[] =
{
    CERTIFICATE_INFO( "ExpRSACertCA", "Engineering CA (RSA 2048)", 2048),
    CERTIFICATE_INFO( "ExpECDHCert256CA", "Engineering CA (ECC 256)", 256),
    CERTIFICATE_INFO( "ExpECDHCert192CA", "Engineering CA (ECC 192)", 192),
    CERTIFICATE_INFO( "ExpECDHCert224CA", "Engineering CA (ECC 224)", 224),
    CERTIFICATE_INFO( "ExpECDHCert384CA", "Engineering CA (ECC 384)", 384),
    CERTIFICATE_INFO( "ExpECDHCert521CA", "Engineering CA (ECC 521)", 521),
    LEAF_CERTIFICATE_INFO( "ExpECDHCert192", "ExpRSACertCA", "Engineering (ECC 192)", 192),
    LEAF_CERTIFICATE_INFO( "ExpECDHCert224", "ExpRSACertCA", "Engineering (ECC 224)", 224),
    LEAF_CERTIFICATE_INFO( "ExpECDHCert256", "ExpRSACertCA", "Engineering (ECC 256)", 256),
    LEAF_CERTIFICATE_INFO( "ExpECDHCert384", "ExpRSACertCA", "Engineering (ECC 384)", 384),
    LEAF_CERTIFICATE_INFO( "ExpECDHCert521", "ExpRSACertCA", "Engineering (ECC 521)", 521),
};

#else

static CertificateInfo gCertificateInfos[] =
{
    CERTIFICATE_INFO_PEM( "rsa_2048_signed_by_rsa_", "BU", 2048),
    CERTIFICATE_INFO_PEM( "ecc_256_signed_by_rsa_", "BU", 256),
    CERTIFICATE_INFO_PEM( "ecc_521_signed_by_rsa_", "BU", 521),
    CERTIFICATE_INFO_PEM( "ecc_384_signed_by_rsa_", "BU", 384),
    CERTIFICATE_INFO_PEM( "ecc_224_signed_by_rsa_", "BU", 224),
    LEAF_CERTIFICATE_INFO_PEM( "rsa_2048_signed_by_rsa_", "ca_rsa_cert", "BU", 2048),
    LEAF_CERTIFICATE_INFO_PEM( "ecc_256_signed_by_rsa_", "ca_rsa_cert", "BU", 256),
    LEAF_CERTIFICATE_INFO_PEM( "ecc_521_signed_by_rsa_", "ca_rsa_cert", "BU", 521),
    LEAF_CERTIFICATE_INFO_PEM( "ecc_384_signed_by_rsa_", "ca_rsa_cert", "BU", 384),
    LEAF_CERTIFICATE_INFO_PEM( "ecc_224_signed_by_rsa_", "ca_rsa_cert", "BU", 224),
    LEAF_CERTIFICATE_INFO_CN_PEM( "rsa_2048_signed_by_rsa_", "ca_rsa_cert", "BU", 2048, "*.mocanatest.com"),
    LEAF_CERTIFICATE_INFO_CN_PEM( "ecc_256_signed_by_rsa_", "ca_rsa_cert", "BU", 256, "*.mocanatest.com"),
    LEAF_CERTIFICATE_INFO_CN_PEM( "ecc_521_signed_by_rsa_", "ca_rsa_cert", "BU", 521, "*.mocanatest.com"),
    LEAF_CERTIFICATE_INFO_CN_PEM( "ecc_384_signed_by_rsa_", "ca_rsa_cert", "BU", 384, "*.mocanatest.com"),
    LEAF_CERTIFICATE_INFO_CN_PEM( "ecc_224_signed_by_rsa_", "ca_rsa_cert", "BU", 224, "*.mocanatest.com"),
    LEAF_CERTIFICATE_INFO_CN_PEM( "rsa_1024_signed_by_ecdsa_", "ca_ecdsa_cert", "BU", 2048, "*.mocanatest.com"),
    /*LEAF_CERTIFICATE_INFO_CN_PEM( "rsa_2048_signed_by_ecdsa_", "ca_ecdsa_cert", "BU", 1024, "*.mocanatest.com"),*/
    LEAF_CERTIFICATE_INFO_CN_PEM( "ecc_256_signed_by_ecdsa_", "ca_ecdsa_cert", "BU", 256, "*.mocanatest.com"),
    LEAF_CERTIFICATE_INFO_CN_PEM( "ecc_521_signed_by_ecdsa_", "ca_ecdsa_cert", "BU", 521, "*.mocanatest.com"),
    LEAF_CERTIFICATE_INFO_CN_PEM( "ecc_384_signed_by_ecdsa_", "ca_ecdsa_cert", "BU", 384, "*.mocanatest.com"),
    LEAF_CERTIFICATE_INFO_CN_PEM( "ecc_224_signed_by_ecdsa_", "ca_ecdsa_cert", "BU", 224, "*.mocanatest.com"),
    LEAF_CERTIFICATE_INFO_CN_PEM( "ecc_192_signed_by_ecdsa_", "ca_ecdsa_cert", "BU", 192, "*.mocanatest.com"),
    /*LEAF_CERTIFICATE_INFO_CN_PEM( "ed_25519_signed_by_rsa_", "ca_rsa_cert", "BU", 256, "*.mocanatest.com"),
    LEAF_CERTIFICATE_INFO_CN_PEM( "ed_448_signed_by_rsa_", "ca_rsa_cert", "BU", 256, "*.mocanatest.com"),*/
#ifdef __ENABLE_DIGICERT_PQC__
    CERTIFICATE_INFO_PEM( "ecc_256_mldsa44_", "BU", 256),
    CERTIFICATE_INFO_PEM( "ecc_256_fndsa512_", "BU", 256),
    CERTIFICATE_INFO_EM( "ecc_384_mldsa65_", "BU", 384),
    CERTIFICATE_INFO_PEM( "ecc_521_fndsa1024_", "BU", 521),
#endif
};
#endif /* __SSLSERV_EXPIRED_CERTS__ */

static CertificateInfo gClientCertificates[] =
{
    CERTIFICATE_INFO_PEM("ca_rsa_", "BU", 1024),
    CERTIFICATE_INFO_PEM("ca_ecdsa_", "BU", 256)
};

/* Mutual authentication testing: invalid client certificate  that will not
 go into the certificate store */
static CertificateInfo gUnknownClientCertificates[] =
{
    CERTIFICATE_INFO("UnknownClientECCCert", "Sales CA (ECC 256)", 256)
};

sbyte4   setSupportedGroup           = 0;
sbyte4   setNumTickets               = 0;
sbyte4   setKeyupdateTests           = 0;
sbyte4   setPosthandshakeAuthTests   = 0;
#endif /* __TEST_ONE_CERT__ */

typedef struct NamedCurveKeySize
{
    ubyte4 namedCurveFlag;
    ubyte4 keySize;
} NamedCurveKeySize;

const NamedCurveKeySize gCurvesPreferences[] =
{
    { (1 << tlsExtNamedCurves_secp256r1), 256},
    { (1 << tlsExtNamedCurves_secp384r1), 384},
    { (1 << tlsExtNamedCurves_secp521r1), 521},
    { (1 << tlsExtNamedCurves_secp224r1), 224},
    { (1 << tlsExtNamedCurves_secp192r1), 192},
};

typedef intBoolean (*CertInfoPredFun)( const CertificateInfo* pCI, void* arg);

intBoolean  mBreakSignalRequest;

/*------------------------------------------------------------------------*/

static CertificateInfo*
SSL_SERV_findCertificate( CertInfoPredFun predFun, void* arg)
{
    sbyte4 i;
    for ( i = 0; i < COUNTOF(gCertificateInfos); ++i)
    {
        if ( predFun(gCertificateInfos+i, arg))
        {
            return gCertificateInfos + i;
        }
    }
    return 0;
}


/*------------------------------------------------------------------------*/

static intBoolean
SSL_SERV_MatchCIName( const CertificateInfo* pCI, void* certFileName)
{
    return !DIGI_STRCMP( (sbyte*) pCI->certFileName, (const sbyte*) certFileName);
}

/*------------------------------------------------------------------------*/

/* create a certificate */
static sbyte4
SSL_SERV_createCertificate( CertificateInfo* pCI, certDistinguishedName* pCertNames)
{
    sbyte4                  retVal;
    certExtensions          extensions;
    const CertificateInfo*  pParentCI = 0;

    /* free any allocated stuff to start from scratch */
    CA_MGMT_freeCertificate( &pCI->certDesc);

    extensions.hasBasicConstraints = TRUE;
    extensions.certPathLen = -1; /* omit */
    extensions.hasKeyUsage = TRUE;
    extensions.otherExts = NULL;
    extensions.otherExtCount = 0;

    if (pCI->keySize < 1024) /* ECC */
    {
        extensions.keyUsage = (1 << digitalSignature) | ( 1 << keyAgreement);
    }
    else
    {
        extensions.keyUsage = (1 << digitalSignature) | ( 1 << keyEncipherment);
        /* key encipherment, digital signature */
    }

    if ( pCI->caCertFileName) /* parent certificate */
    {
        /* find the parent certificate info by name */
        pParentCI = SSL_SERV_findCertificate( SSL_SERV_MatchCIName, (void*) pCI->caCertFileName);
        if (!pParentCI || !pParentCI->certDesc.pCertificate)
        {
            retVal = ERR_FALSE; /* CA cert should have been loaded before*/
            goto exit;
        }
        extensions.isCA = FALSE;

#ifdef __SSLSERV_EXPIRED_CERTS__
        pCertNames = &expiredCertNames;
#endif

    }
    else
    {
        extensions.isCA = TRUE;
        extensions.keyUsage |=  (1 << keyCertSign) | ( 1 << cRLSign);
        /* certificate and CRL signing */
    }

    /* change the certNames OU */
    (certNames.pDistinguishedName+4)->pNameAttr->value = (ubyte*) pCI->orgUnit;
    (certNames.pDistinguishedName+4)->pNameAttr->valueLen = DIGI_STRLEN( (const sbyte*) pCI->orgUnit);

    /* if CN specified in CertificateInfo, use it */
    if (pCI->commonName)
    {
        (certNames.pDistinguishedName+5)->pNameAttr->value = (ubyte*) pCI->commonName;
        (certNames.pDistinguishedName+5)->pNameAttr->valueLen = DIGI_STRLEN( (const sbyte*) pCI->commonName);
    }

   if (OK > (retVal = CA_MGMT_generateCertificateEx( &pCI->certDesc, pCI->keySize,
                                            pCertNames, ht_sha384, &extensions,
                                            (pCI->caCertFileName) ? &pParentCI->certDesc : NULL)))
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

exit:

    return retVal;
}


/*------------------------------------------------------------------------*/

/* this function waits for the creation of a certificate by another process */
static sbyte4
SSL_SERV_waitForCertificate( CertificateInfo* pCI)
{
    sbyte4 count = 0;

    while (count < 10)
    {
        RTOS_sleepMS(1000); /* wait one second */
        ++count;
        if ( (DIGICERT_readFile( pCI->certFileName, &pCI->certDesc.pCertificate,
                             &pCI->certDesc.certLength) >= OK) &&
             (DIGICERT_readFile( pCI->certKeyFileName,
                               &pCI->certDesc.pKeyBlob,
                               &pCI->certDesc.keyBlobLength) >=OK ) )
        {
            return OK;
        }
    }

    return ERR_FALSE;
}



/*------------------------------------------------------------------------*/

static int strcmpends( const char* s1, const char* s2)
{
    size_t s1len = strlen(s1);
    size_t s2len = strlen(s2);

    if (s1len >= s2len)
    {
        return memcmp( s1 + s1len - s2len, s2, s2len);
    }
    else
    {
        return memcmp(s2 + s2len - s1len, s1, s1len);
    }
}


/*------------------------------------------------------------------------*/

static sbyte4
SSL_SERV_loadCertificate(certStorePtr pCertStore, CertificateInfo* pCI,
                         certDistinguishedName* pCertNames, sbyte4 identity)
{
    sbyte4                  retVal;
    const CertificateInfo*  pParentCI = 0;
    ubyte4                  numCertificate;
    SizedBuffer             certificates[2];
    ubyte*                  pContents = NULL;
    ubyte4                  contentsLen = 0;
    AsymmetricKey           asymKey = {0};

    retVal = OK;
    retVal = DIGICERT_readFile( pCI->certFileName,
                                &pCI->certDesc.pCertificate,
                                &pCI->certDesc.certLength);

    if (identity)
    {
        retVal += DIGICERT_readFile( pCI->certKeyFileName,
                                 &pContents, &contentsLen);
    }

    if (OK > retVal)
    {
        /* no certs -> either wait for them or create them */
        if (pCertNames)
        {
            retVal = SSL_SERV_createCertificate( pCI, pCertNames);
            if (OK > retVal)
                goto exit;

            retVal = DIGICERT_readFile( pCI->certFileName,
                                        &pCI->certDesc.pCertificate,
                                        &pCI->certDesc.certLength);

            if (identity)
            {
                retVal += DIGICERT_readFile( pCI->certKeyFileName,
                                         &pContents, &contentsLen);
            }
        }
        else
        {
            /*retVal = SSL_SERV_waitForCertificate( pCI);*/
        }
    }

    if ( OK > retVal)
    {
        goto exit;
    }

    /* Deal with the key only if we are loading an identity (cert-key pair) */
    if (identity)
    {
        retVal = CRYPTO_initAsymmetricKey (&asymKey);
        if (OK != retVal)
            goto exit;

        if (OK > (retVal = CRYPTO_deserializeAsymKey (
                MOC_ASYM(hwAccelCtx) pContents, contentsLen, NULL, &asymKey)))
        {
            goto exit;
        }

        if (OK > (retVal = CRYPTO_serializeAsymKey(MOC_ASYM(hwAccelCtx) &asymKey, mocanaBlobVersion2, &pCI->certDesc.pKeyBlob, &pCI->certDesc.keyBlobLength)))
        {
            goto exit;
        }

        CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
    }

    certificates[0].data = pCI->certDesc.pCertificate;
    certificates[0].length = pCI->certDesc.certLength;
    numCertificate = 1;

    if ( pCI->caCertFileName) /* it's a chain */
    {
        /* find the parent certificate info by name */
#if 0
        pParentCI = SSL_SERV_findCertificate( SSL_SERV_MatchCIName, (void*) pCI->caCertFileName);
        if (!pParentCI || !pParentCI->certDesc.pCertificate)
        {
            retVal = ERR_FALSE; /* CA cert should have been loaded before*/
            goto exit;
        }
#endif
        retVal = DIGICERT_readFile(pCI->caCertFileName, &certificates[1].data, &certificates[1].length);

        /* Able to load the correct CA cert */
        if (retVal >= OK)
            numCertificate = 2;
    }

    /* conditionally add to certStore; some certificates are just created or loaded */
    if (pCertStore)
    {
        if (identity)
        {
            if (OK > (retVal = CERT_STORE_addIdentityWithCertificateChain(pCertStore, certificates, numCertificate,
                                                            pCI->certDesc.pKeyBlob,pCI->certDesc.keyBlobLength)))
            {
                goto exit;
            }
        }
        else /* add root cert as trust point: mutual authentication */
        {
            if (OK > (retVal = CERT_STORE_addTrustPoint(pCertStore,
                                                        certificates[0].data,
                                                        certificates[0].length)))
            {
                goto exit;
            }
        }
    }

exit:
    return retVal;
}


/*------------------------------------------------------------------------*/

/* populate the certificate store */
static sbyte4
SSL_SERV_populateCertificateStore(certStorePtr *ppNewStore, sbyte4 canCreate)
{
    sbyte4 i;
    sbyte4 retVal;

    if (OK > (retVal = CERT_STORE_createStore(ppNewStore)))
        goto exit;

    /* our own certificates */
    for ( i = 0; i < COUNTOF( gCertificateInfos); ++i)
    {
        /* Expired certificates are generated by the server */
#if defined( __SSLSERV_EXPIRED_CERTS__)
        retVal = SSL_SERV_loadCertificate(*ppNewStore,
                                          gCertificateInfos + i,
                                          canCreate ? &certNames : 0, 1);
#else
        retVal = SSL_SERV_loadCertificate(*ppNewStore,
                                          gCertificateInfos + i,
                                          0, 1);
#endif
        if (OK > retVal)
        {
            goto exit;
        }
    }

    /* client certificate */
    for (i = 0; i < COUNTOF( gClientCertificates); ++i)
    {
        if (OK > (retVal = SSL_SERV_loadCertificate(*ppNewStore, gClientCertificates + i,
                                                    0, 0)))
        {
            goto exit;
        }
    }

    /* a client certificate that needs to be created too but will not go into
     the store -- it's going to be used by the client only for negative
     testing -- only do this if this process is in charge of creating those
     certs, i.e. the normal server */
#if 0
    if (2 == canCreate)
    {
        for (i = 0; i < COUNTOF( gUnknownClientCertificates); ++i)
        {
            if (OK > (retVal = SSL_SERV_loadCertificate(NULL, gUnknownClientCertificates +i,
                                                        canCreate ? &clientCertNames : 0, 0)))
            {
                goto exit;
            }
        }
    }
#endif

exit:
    return retVal;
}


/*------------------------------------------------------------------------*/

/* depopulate the certificate info arrays */
static sbyte4
SSL_SERV_releaseCertificateInfos()
{
    sbyte4 i;
    sbyte4 retVal = 0;

    for ( i = 0; i < COUNTOF( gCertificateInfos); ++i)
    {
        if (OK > ( retVal = CA_MGMT_freeCertificate(&gCertificateInfos[i].certDesc)))
            goto exit;
    }

    for ( i = 0; i < COUNTOF( gClientCertificates); ++i)
    {
        if (OK > ( retVal = CA_MGMT_freeCertificate(&gClientCertificates[i].certDesc)))
            goto exit;
    }

#if 0
    for ( i = 0; i < COUNTOF( gUnknownClientCertificates); ++i)
    {
        if (OK > ( retVal = CA_MGMT_freeCertificate(&gUnknownClientCertificates[i].certDesc)))
            goto exit;
    }
#endif

exit:

    return retVal;
}


#ifdef __ENABLE_DIGICERT_SSL_PSK_SUPPORT__  /* to prevent warning about unused function */
/*------------------------------------------------------------------------*/

static sbyte4
SSL_SERV_GetHintPSK(sbyte4 connectionInstance,
                    ubyte hintPSK[SSL_PSK_SERVER_IDENTITY_LENGTH],
                    ubyte4 *pRetHintLength)
{
    /* no hint */
    *pRetHintLength = 0;
    return 0;
}


/*------------------------------------------------------------------------*/

static sbyte4
SSL_SERV_LookupPSK(sbyte4 connectionInstance, ubyte *pIdentityPSK,
                   ubyte4 identityLengthPSK, ubyte retPSK[SSL_PSK_MAX_LENGTH],
                   ubyte4 *pRetLengthPSK)
{
    sbyte4 resCmp;

    /* verify this is the correct identity */
    if (15 != identityLengthPSK)
    {
        return ERR_FALSE;
    }

    DIGI_CTIME_MATCH((const ubyte*) "Client_identity", pIdentityPSK, 15, &resCmp);

    if (resCmp)
    {
        return ERR_FALSE;
    }

    DIGI_MEMCPY(retPSK,
               "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
               16);
    *pRetLengthPSK = 16;
    return 0;
}
#endif


#ifdef __ENABLE_DIGICERT_SSL_SRP__

/*------------------------------------------------------------------------*/

static sbyte4
SSL_SERV_SRPCallback(sbyte4 connectionInstance, const ubyte* identity,
                     ubyte4 identityLength, sbyte4* numBits,
                     ubyte salt[SSL_PSK_SERVER_IDENTITY_LENGTH],
                     ubyte4* saltLength,
                     ubyte** verifier, ubyte4* verifierLength)
{
    intBoolean differ;
    sbyte4 status;


    static const ubyte scott_salt[] =
    {
        0xa1, 0x45, 0xbe, 0x68, 0xf9, 0xec, 0x2c, 0xbe, 0xd7, 0x49, 0xc3, 0x61,
        0xa6, 0x57, 0xd1, 0x26, 0x8f, 0xdc, 0x6c, 0x3e, 0x7c, 0xee, 0x53, 0x4b,
    };


    /* support only one identity : scott/tiger, using 4096 group */
    /* verify this is the correct identity */
    if (5 != identityLength)
    {
        status = ERR_FALSE;
        goto exit;
    }

    DIGI_CTIME_MATCH((const ubyte*) "scott", identity, 5, &differ);

    if (differ)
    {
        status = ERR_FALSE;
        goto exit;
    }

    *numBits = 4096;
    *saltLength = sizeof(scott_salt);

    DIGI_MEMCPY( salt, scott_salt, *saltLength);

    /* in real implementations, the server does not know the password and
     would store only a precomputed verifier; for testing, computing the 
     verifiter on the fly is convenient */
    if (OK > ( status = SRP_computeVerifier(scott_salt, *saltLength,
                        (ubyte*) "scott", 5, (ubyte*) "tiger", 5, 4096,
                        verifier, verifierLength)))
    {
        goto exit;
    }

exit:

    return status;
}

#endif

/*------------------------------------------------------------------------*/

extern void
SSL_SERV_initUpcalls()
{
    /* allow more time for client connection */
    SSL_sslSettings()->sslTimeOutHello                  = 60000;
    SSL_sslSettings()->sslTimeOutReceive                = 60000;

#ifdef __ENABLE_DIGICERT_SSL_PSK_SUPPORT__
    SSL_sslSettings()->funcPtrGetHintPSK                = SSL_SERV_GetHintPSK;
    SSL_sslSettings()->funcPtrLookupPSK                 = SSL_SERV_LookupPSK;
#endif

#ifdef __ENABLE_DIGICERT_SSL_SRP__
    SSL_sslSettings()->funcPtrSRPCallback               = SSL_SERV_SRPCallback;
#endif
}


#if defined(WIN32)
/*------------------------------------------------------------------*/

static BOOL WINAPI HandlerRoutine(DWORD dw)
{
    MOC_UNUSED(dw);

    mBreakSignalRequest = TRUE;
    return TRUE;
}
#endif


/*------------------------------------------------------------------------*/

static void
SSL_SERV_handleConnection( void* arg)
{
    TCP_SOCKET  socketClient = (TCP_SOCKET)(intptr_t) arg;
    sbyte4      connectionInstance;
    sbyte4      status;
    intBoolean  stopRequest = FALSE;
    const char* protocols[] = { "super_secret_256", "http/1.1" };

#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__)
    if (0 > (connectionInstance = SSL_acceptConnection(socketClient, pSslOcspCertStore)))
    {
        DEBUG_ERROR(DEBUG_SSL_EXAMPLE, "SSL_SERV_handleConnection: SSL_acceptConnection failed. ", connectionInstance);
        goto exit;
    }
#else
    if (0 > (connectionInstance = SSL_acceptConnection(socketClient, pSslCertStore)))
    {
        DEBUG_ERROR(DEBUG_SSL_EXAMPLE, "SSL_SERV_handleConnection: SSL_acceptConnection failed. ", connectionInstance);
        goto exit;
    }
#endif

#if defined( __SSLSERV_VERSION_SET__)
    if (OK > SSL_ioctl(connectionInstance, SSL_SET_VERSION, setMinorVersion))
    {
        goto exit;
    }
#endif

#if defined(__SSLSERV_MUTUAL_AUTH_SUPPORT__)
    if (OK > SSL_setSessionFlags(connectionInstance, SSL_FLAG_REQUIRE_MUTUAL_AUTH))
    {
        goto exit;
    }
#else
    if (OK > SSL_setSessionFlags(connectionInstance, SSL_FLAG_NO_MUTUAL_AUTH_REQUEST))
    {
        goto exit;
    }
#endif

    if (OK > SSL_setApplicationLayerProtocol(connectionInstance, 2, protocols))
    {
        DEBUG_ERROR(DEBUG_SSL_EXAMPLE, "SSL_SERV_handleConnection: SSL_setApplicationLayerProtocol failed. ", status);
        SSL_closeConnection(connectionInstance);
        goto exit;
    }


#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__)

    /*Set the OCSP responder URL*/
    if (OK > (status = SSL_setOcspResponderUrl(connectionInstance, "http://127.0.0.1:9800")))
        DEBUG_ERROR(DEBUG_SSL_EXAMPLE, (sbyte *)"startHttpsThread: SSL_setOcspResponderUrl Failed ", status);

#endif /*__ENABLE_DIGICERT_OCSP_CLIENT__*/


    if (0 > (status = SSL_negotiateConnection(connectionInstance)))
    {
        DEBUG_ERROR(DEBUG_SSL_EXAMPLE, "SSL_SERV_handleConnection: SSL_negotiateConnection failed. ", status);
        SSL_closeConnection(connectionInstance);
        goto exit;
    }

    if (0 > ( status = SSL_SERV_doRequest(connectionInstance, &stopRequest)))
        DEBUG_ERROR(DEBUG_SSL_EXAMPLE, "SSL_SERV_handleConnection: SSL_SERV_getRequest failed. ", status);

    if (0 > ( status = SSL_closeConnection(connectionInstance)))
        DEBUG_ERROR(DEBUG_SSL_EXAMPLE, "SSL_EXAMPLE: SSL_closeConnection return error: ", status);

exit:

    TCP_CLOSE_SOCKET(socketClient);
    if ( stopRequest)
    {
        mBreakSignalRequest = TRUE;
    }
}


/*------------------------------------------------------------------------*/

static void
SSL_SERV_startServer( ubyte2 portNo)
{
    sbyte4     status = 0;
    TCP_SOCKET listenSocket;

    if (0 > (status = TCP_LISTEN_SOCKET(&listenSocket, portNo)))
    {
        DEBUG_PRINTNL(DEBUG_SSL_EXAMPLE, (sbyte*) "SSL_EXAMPLE: Could not create listen socket");
        goto exit;
    }

#if defined(WIN32)
    SetConsoleCtrlHandler( HandlerRoutine, TRUE);
#endif

    DEBUG_ERROR(DEBUG_SSL_EXAMPLE, "SSL_EXAMPLE: Server listening on port ", portNo);

    DIGICERT_log(MOCANA_SSL, LS_INFO, (sbyte*) "SSL server listening for clients");

    /* Loop forever accepting connections */
    while (TRUE)
    {
        RTOS_THREAD threadHandle;
        TCP_SOCKET socketClient;

        /* Block on accept() */
        status = TCP_ACCEPT_SOCKET(&socketClient, listenSocket, &mBreakSignalRequest);

        if ((mBreakSignalRequest) || (status < 0))
        {
            DEBUG_PRINTNL(DEBUG_SSL_EXAMPLE, (sbyte*) "SSL_SERV_startServer: accept failed.");
            break;
        }
        DEBUG_ERROR(DEBUG_SSL_EXAMPLE, "SSL_EXAMPLE: Connection accepted on socket: ", socketClient);

        if ( OK > (status = RTOS_createThread( SSL_SERV_handleConnection,
                                               (void*)socketClient, 0,
                                               &threadHandle)))
        {
            DEBUG_ERROR(DEBUG_SSL_EXAMPLE, "SSL_SERV_startServer: thread creation failed.", status);
            break;
        }

        RTOS_destroyThread( threadHandle); /* don't need to keep track of thread anymore */
    }

exit:
    TCP_CLOSE_SOCKET(listenSocket);

}

#ifdef __HTTP_SERVER__

/*------------------------------------------------------------------------*/

static void
HTTP_SERV_handleConnection( void* arg)
{
    TCP_SOCKET  socketClient = (TCP_SOCKET) arg;
    sbyte4      status;
    intBoolean  stopRequest = FALSE;


    if (0 > ( status = HTTP_SERV_doRequest(socketClient, &stopRequest)))
        DEBUG_ERROR(DEBUG_SSL_EXAMPLE, "SSL_SERV_handleConnection: SSL_SERV_getRequest failed. ", status);


    TCP_CLOSE_SOCKET(socketClient);
    if ( stopRequest)
    {
        mBreakSignalRequest = TRUE;
    }
}


/*------------------------------------------------------------------------*/

static void
HTTP_SERV_startServer( ubyte2 portNo )
{
    sbyte4     status = 0;
    TCP_SOCKET listenSocket;

    if (0 > (status = TCP_LISTEN_SOCKET(&listenSocket, portNo)))
    {
        DEBUG_PRINTNL(DEBUG_SSL_EXAMPLE, "SSL_EXAMPLE: Could not create listen socket");
        goto exit;
    }

#if defined(WIN32)
    SetConsoleCtrlHandler( HandlerRoutine, TRUE);
#endif

    DEBUG_ERROR(DEBUG_SSL_EXAMPLE, "SSL_EXAMPLE: Server listening on port ", portNo);

    DIGICERT_log(MOCANA_SSL, LS_INFO, "SSL server listening for clients");

    /* Loop forever accepting connections */
    while (TRUE)
    {
        RTOS_THREAD threadHandle;
        TCP_SOCKET socketClient;

        /* Block on accept() */
        status = TCP_ACCEPT_SOCKET(&socketClient, listenSocket, &mBreakSignalRequest);

        if ((mBreakSignalRequest) || (status < 0))
        {
            DEBUG_PRINTNL(DEBUG_SSL_EXAMPLE, "SSL_SERV_startServer: accept failed.");
            break;
        }
        DEBUG_ERROR(DEBUG_SSL_EXAMPLE, "SSL_EXAMPLE: Connection accepted on socket: ", socketClient);

        if ( OK > (status = RTOS_createThread( HTTP_SERV_handleConnection,
                                               (void*)socketClient, 0,
                                               &threadHandle)))
        {
            DEBUG_ERROR(DEBUG_SSL_EXAMPLE, "SSL_SERV_startServer: thread creation failed.", status);
            break;
        }

        RTOS_destroyThread( threadHandle); /* don't need to keep track of thread anymore */
    }

exit:
    TCP_CLOSE_SOCKET(listenSocket);

}
#endif

/*------------------------------------------------------------------------*/

static void
SSL_SERV_startOCSPServers()
{
    sbyte4     status = 0;
    TCP_SOCKET listenSocket;
    SizedBuffer certificates[2];
    ubyte4 numCertificate;
    ubyte*  pLeaf = NULL;
    ubyte4  leafLen = 0;
    ubyte*  pDerKey = NULL;
    ubyte4  derKeyLen;
    ubyte*  pKeyBlob = NULL;
    ubyte4  keyBlobLen;
    ubyte*  pPemKey;
    ubyte4  pemKeyLen;
    ubyte2 portNo;
    ubyte*  pIssuer = NULL;
    ubyte4  issuerLen = 0;

    CERT_STORE_createStore(&pSslOcspCertStore);

#if defined(__TEST_OCSP_MISSING_ISSUER_CERT__) /*SSL server using certificate issued by a CA. Issuer certificate not provided.*/

    portNo = 1466;

    /*Populate Cert Store with the certificate. Do not store CA.*/
    if (OK > (status = DIGICERT_readFile("ocsp_test_certs/RSAChild1.der", &pLeaf, &leafLen)))
        goto exit;

    if (OK > (status = DIGICERT_readFile("ocsp_test_certs/RSAChild1Key.der", &pDerKey, &derKeyLen)))
        goto exit;


    /* convert DER file key information to Digicert key blob*/
     if (OK > (status = CA_MGMT_convertKeyDER(pDerKey,derKeyLen, &pKeyBlob, &keyBlobLen)))
     goto exit;

    certificates[0].data = pLeaf;
    certificates[0].length = leafLen;
    numCertificate = 1;


#elif defined(__TEST_OCSP_CERT_CHAIN__) /*SSL server using certificate issued by a CA and sends entire certificate chain.*/

    portNo = 1465;

    /*Populate Cert Store with the certchain*/
    if (OK > (status = DIGICERT_readFile("ocsp_test_certs/RSAChild1.der", &pLeaf, &leafLen)))
        goto exit;

    if (OK > (status = DIGICERT_readFile("ocsp_test_certs/RSAChild1Key.der", &pDerKey, &derKeyLen)))
        goto exit;

    /* convert DER file key information to Digicert key blob*/
    if (OK > (status = CA_MGMT_convertKeyDER(pDerKey,derKeyLen, &pKeyBlob, &keyBlobLen)))
        goto exit;

    if (OK > (status = DIGICERT_readFile("ocsp_test_certs/RSACA.der", &pIssuer, &issuerLen)))
        goto exit;

    certificates[0].data = pLeaf;
    certificates[0].length = leafLen;
    certificates[1].data = pIssuer;
    certificates[1].length = issuerLen;
    numCertificate = 2;


#elif defined(__TEST_OCSP_REVOKED_CERT__) /* SSL server using REVOKED certificate. Issuer certificate provided as trust point.*/

    portNo = 1464;

    /* Populate Cert Store with REVOKED certs for OCSP. For this test the ECDHCert256CA is set to be revoked on the OCSP responder*/
    if (OK > (status = DIGICERT_readFile("ocsp_test_certs/RSAChild2.der", &pLeaf, &leafLen)))
        goto exit;

    if (OK > (status = DIGICERT_readFile("ocsp_test_certs/RSAChild2Key.der",&pDerKey, &derKeyLen)))
        goto exit;

    /* convert DER file key information to Digicert key blob*/
    if (OK > (status = CA_MGMT_convertKeyDER(pDerKey,derKeyLen, &pKeyBlob, &keyBlobLen)))
        goto exit;

    certificates[0].data = pLeaf;
    certificates[0].length = leafLen;
    numCertificate = 1;


    /*For OCSP request add the issuer cert to the server cert store.
     Note: This is also testing use case where the server cert is NOT the root cert OR the entire server cert chain is NOT added to cert store as an identity*/
    if (OK > (status = DIGICERT_readFile("ocsp_test_certs/RSACA.der",&pIssuer,&issuerLen)))
        goto exit;

    /*Add root cert as trust point*/
    if (OK > (status = CERT_STORE_addTrustPoint(pSslOcspCertStore,pIssuer,issuerLen)))
        goto exit;


#else /* SSL server using VALID self signed certificate that talks to OCSP responder and retrieves OCSP response*/

    portNo = 1463;

    /* Populate Cert Store with VALID certs for OCSP*/
    if (OK > (status = DIGICERT_readFile("ocsp_test_certs/RSACA.der", &pLeaf, &leafLen)))
        goto exit;

    if (OK > (status = DIGICERT_readFile("ocsp_test_certs/RSACAKey.der",&pDerKey, &derKeyLen)))
        goto exit;

    /* convert DER file key information to Digicert key blob*/
    if (OK > (status = CA_MGMT_convertKeyDER(pDerKey,derKeyLen, &pKeyBlob, &keyBlobLen)))
        goto exit;

    certificates[0].data = pLeaf;
    certificates[0].length = leafLen;
    numCertificate = 1;

#endif



    if (OK > (status = CERT_STORE_addIdentityWithCertificateChain(pSslOcspCertStore, certificates, numCertificate, pKeyBlob, keyBlobLen)))
        goto exit;


    if (0 > (status = TCP_LISTEN_SOCKET(&listenSocket, portNo)))
    {
        DEBUG_PRINTNL(DEBUG_SSL_EXAMPLE, (sbyte*) "SSL_EXAMPLE: Could not create listen socket");
        goto exit;
    }

    DEBUG_ERROR(DEBUG_SSL_EXAMPLE, "SSL_EXAMPLE: Server listening on port ", portNo);

    DIGICERT_log(MOCANA_SSL, LS_INFO, (sbyte*) "SSL server listening for clients");

    /* Loop forever accepting connections */
    while (TRUE)
    {
        RTOS_THREAD threadHandle;
        TCP_SOCKET socketClient;

        /* Block on accept() */
        status = TCP_ACCEPT_SOCKET(&socketClient, listenSocket, &mBreakSignalRequest);

        if ((mBreakSignalRequest) || (status < 0))
        {
            DEBUG_PRINTNL(DEBUG_SSL_EXAMPLE, (sbyte*) "SSL_SERV_startServer: accept failed.");
            break;
        }
        DEBUG_ERROR(DEBUG_SSL_EXAMPLE, "SSL_EXAMPLE: Connection accepted on socket: ", socketClient);

        if ( OK > (status = RTOS_createThread( SSL_SERV_handleConnection,
                                              (void*)socketClient, 0,
                                              &threadHandle)))
        {
            DEBUG_ERROR(DEBUG_SSL_EXAMPLE, "SSL_SERV_startServer: thread creation failed.", status);
            break;
        }

        RTOS_destroyThread( threadHandle); /* don't need to keep track of thread anymore */
    }

exit:
    TCP_CLOSE_SOCKET(listenSocket);


}
/*------------------------------------------------------------------------*/
#if defined(__ENABLE_DIGICERT_TAP__)

static TAP_EntityCredentialList *g_pTapEntityCred = NULL;
static TAP_CredentialList       *g_pTapKeyCred    = NULL;
static TAP_ModuleList            g_moduleList     = { 0 };
static char                     *pTapConfigFile   = TPM2_CONFIGURATION_FILE;
static int                      g_TapProvider     = TAP_PROVIDER_TPM2;

#define INIT_HASH   (0xab341c12)
    
static TAP_Context *g_pTapContext;
typedef struct tapContextHandle
{
    TAP_Context           *pTapCtx;
} tapContextHandle;

static hashTableOfPtrs *g_pTapCtxHashTable = NULL;
static tapContextHandle *g_pTapCtxList;

static MSTATUS
SSL_SERV_allocHashPtrElement(void *pHashCookie, hashTablePtrElement **ppRetNewHashElement)
{
    MSTATUS status = OK;

    if (NULL == (*ppRetNewHashElement = (hashTablePtrElement*) MALLOC(sizeof(hashTablePtrElement))))
        status = ERR_MEM_ALLOC_FAIL;

    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS
SSL_SERV_freeHashPtrElement(void *pHashCookie, hashTablePtrElement *pFreeHashElement)
{
    MSTATUS status = OK;
    struct tapContextHandle *pTempCtx = NULL;
    TAP_ErrorContext *pErrContext = NULL;
    if (NULL == pFreeHashElement)
        return ERR_NULL_POINTER;

    pTempCtx = (struct tapContextHandle *)pFreeHashElement->pAppData;

    if (OK > (status = TAP_uninitContext((TAP_Context **)&(pTempCtx->pTapCtx), pErrContext)))
        goto exit;

    FREE(pTempCtx);
    FREE(pFreeHashElement);

exit:
    return status;
}

static sbyte4 SSL_SERV_addTAPContext(TAP_Context *pTapCtx, void *pKey)
{
    MSTATUS status = OK;
    struct tapContextHandle *pTempCtx = NULL;
    sbyte4 cmpResult = -1;
    intBoolean ctxFound = FALSE;

    ubyte4 hashValue = 0;

    HASH_VALUE_hashGen(pKey, sizeof(MocAsymKey), INIT_HASH, &hashValue);

    if (OK > (status = HASH_TABLE_findPtr(g_pTapCtxHashTable, hashValue, NULL, NULL, (void **)&pTempCtx, &ctxFound)))
    {
        goto exit;
    }

    if (FALSE == ctxFound)
    {
        if (OK > (status = DIGI_MALLOC((void **)&pTempCtx, sizeof(struct tapContextHandle))))
            goto exit;

        pTempCtx->pTapCtx = pTapCtx;

        if (OK > (status = HASH_TABLE_addPtr(g_pTapCtxHashTable, hashValue, (void *)pTempCtx)))
        {
            goto exit;
        }
    }

exit:
    if (OK > status)
    {
        if (pTempCtx != NULL)
            DIGI_FREE((void **)&pTempCtx);

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, (sbyte*)"SSL_SERV_addTAPContext() returns status = ", status);
#endif
    }
    return status;
}

static sbyte4 SSL_SERV_findTAPContext(void *pKey, TAP_Context **ppTapCtx)
{
    ubyte4 hashValue = 0;
    struct tapContextHandle *pTempCtx = NULL;
    MSTATUS status = ERR_SSL;
    intBoolean ctxFound = FALSE;

    HASH_VALUE_hashGen(pKey, sizeof(MocAsymKey), INIT_HASH, &hashValue);

    if (OK > (status = HASH_TABLE_findPtr(g_pTapCtxHashTable, hashValue, NULL, NULL, (void **)&pTempCtx, &ctxFound)))
    {
        goto exit;
    }

    if (TRUE == ctxFound)
    {
        *ppTapCtx = pTempCtx->pTapCtx;
    }
exit:
    return status;
}

static sbyte4 SSL_SERV_clearTAPContext()
{
    struct tapContextHandle *pCurrCtx = NULL;
    TAP_ErrorContext *pErrContext = NULL;
    void *pRetHashCookie = NULL;
    MSTATUS status = OK;

    if (NULL != g_pTapCtxHashTable)
    {
        (void) HASH_TABLE_removePtrsTable(g_pTapCtxHashTable, &pRetHashCookie);
        g_pTapCtxHashTable = NULL;
    }
    return status;
}

static sbyte4 SSL_SERV_getTapContext(TAP_Context **ppTapContext,
                          TAP_EntityCredentialList **ppTapEntityCred,
                          TAP_CredentialList **ppTapKeyCred,
                          void *pKey, TapOperation op, ubyte getContext)
{
    MSTATUS status = OK;
    TAP_ErrorContext *pErrContext = NULL;
    TAP_Module *pModule = NULL;
    TAP_Context *pTempTAPCtx = NULL;
    int remain = 10, count = 0;
    if (pKey == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == g_pTapCtxHashTable)
    {
        while (remain > 0)
        {
            remain = remain >> 1;
            count++;
        }
        if (OK > (status = HASH_TABLE_createPtrsTable(&g_pTapCtxHashTable, (1 << count) - 1, NULL, SSL_SERV_allocHashPtrElement, SSL_SERV_freeHashPtrElement)))
            goto exit;
    }

    if (getContext)
    {
        if (g_TapProvider == TAP_PROVIDER_PKCS11)
        {
            int i = 0;
            for (i = 0; i < g_moduleList.numModules; i++)
            {
                /* moduleId:0 is for software */
                if (0 != g_moduleList.pModuleList[i].moduleId)
                {
                    pModule = &g_moduleList.pModuleList[i];
                    break;
                }
            }
        }
        else
        {
            pModule = &g_moduleList.pModuleList[0];
        }

        if (OK > (status = SSL_SERV_findTAPContext(pKey, &pTempTAPCtx)))
        {
            /* Initialize context on first module */
            status = TAP_initContext(pModule, g_pTapEntityCred,
                                        NULL, &g_pTapContext, pErrContext);
            if (OK != status)
            {
                printf("TAP_initContext : %d\n", status);
                goto exit;
            }
        }

        if (pTempTAPCtx == NULL)
        {
            /* Initialize context on first module */
            status = TAP_initContext(pModule, g_pTapEntityCred,
                                        NULL, &pTempTAPCtx, pErrContext);
            if (OK != status)
            {
                printf("TAP_initContext : %d\n", status);
                goto exit;
            }

            if (OK > (status = SSL_SERV_addTAPContext(pTempTAPCtx, pKey)))
            {
                goto exit;
            }
        }

        *ppTapContext    = pTempTAPCtx;
        *ppTapEntityCred = g_pTapEntityCred;
        *ppTapKeyCred    = g_pTapKeyCred;
    }
    else
    {
        /* Do NOT free the context. This application uses a global TAP Context */
#if 0
        /* Destroy the TAP context */
        if (OK > (status = TAP_uninitContext(ppTapContext, pErrContext)))
        {
            DEBUG_ERROR(DEBUG_SSL_SERV, (sbyte*)"SSL_SERV: TAP_uninitContext failed with status: ", status);
        }
#endif
    }

exit:
    return status;
}

static MSTATUS
SSL_SERV_TAPInit(ubyte *pTpm2ConfigFile,
                    TAP_EntityCredentialList **ppTapEntityCred,
                    TAP_CredentialList **ppTapKeyCred)
{
    MSTATUS status = OK;
    TAP_ConfigInfoList configInfoList = { 0, };
    TAP_ErrorContext *pErrContext = NULL;
    ubyte gotModuleList = FALSE;
    TAP_EntityCredentialList *pEntityCredentials = { 0 };
    TAP_CredentialList *pKeyCredentials = { 0 };
    TAP_Module *pModule = NULL;
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 };
#endif

#if (!defined(__ENABLE_DIGICERT_TAP_REMOTE__))
    status = DIGI_CALLOC((void **)&(configInfoList.pConfig), 1, sizeof(TAP_ConfigInfo));
    if (OK != status)
    {
        printf("Failed to allocate memory, status = %d", status);
        goto exit;
    }

    status = TAP_readConfigFile(pTpm2ConfigFile, &configInfoList.pConfig[0].configInfo, 0);
    if (OK != status)
    {
        printf("Failed to read config file, status = %d", status);
        goto exit;
    }

    configInfoList.count = 1;
    configInfoList.pConfig[0].provider = g_TapProvider;
#endif

    status = TAP_init(&configInfoList, pErrContext);
    if (OK != status)
    {
        printf("TAP_init : %d", status);
        goto exit;
    }

#if (defined(__ENABLE_DIGICERT_TAP_REMOTE__))

    connInfo.serverName.bufferLen = DIGI_STRLEN((sbyte *)taps_ServerName)+1;
    status = DIGI_CALLOC ((void **)&(connInfo.serverName.pBuffer), 1, connInfo.serverName.bufferLen);
    if (OK != status)
    goto exit;

    status = DIGI_MEMCPY ((void *)(connInfo.serverName.pBuffer), (void *)taps_ServerName, DIGI_STRLEN((sbyte *)taps_ServerName));
    if (OK != status)
    goto exit;

    connInfo.serverPort = taps_ServerPort;

    status = TAP_getModuleList(&connInfo, g_TapProvider, NULL,
                               &g_moduleList, pErrContext);
#else
    status = TAP_getModuleList(NULL, g_TapProvider, NULL,
                               &g_moduleList, pErrContext);
#endif
    if (OK != status)
    {
        printf("TAP_getModuleList : %d \n", status);
        goto exit;
    }
    gotModuleList = TRUE;
    if (0 == g_moduleList.numModules)
    {
        printf("No TPM2 modules found\n");
        goto exit;
    }

    if (g_TapProvider == TAP_PROVIDER_PKCS11)
    {
        int i = 0;
        for (i = 0; i < g_moduleList.numModules; i++)
        {
            /* moduleId:0 is for software */
            if (0 != g_moduleList.pModuleList[i].moduleId)
            {
                pModule = &g_moduleList.pModuleList[i];
                break;
            }
        }
    }
    else
    {
        pModule = &g_moduleList.pModuleList[0];
    }

    /* For local TAP, parse the config file and get the Entity Credentials */
#if (!defined(__ENABLE_DIGICERT_TAP_REMOTE__))
    status = TAP_getModuleCredentials(pModule,
                                      pTpm2ConfigFile, 0,
                                      &pEntityCredentials,
                                      pErrContext);

    if (OK != status)
    {
        printf("Failed to get credentials from Credential configuration file, status = %d", status);
        goto exit;
    }
#endif

    *ppTapEntityCred = pEntityCredentials;
    *ppTapKeyCred    = pKeyCredentials;

exit:
    /* Free config info */
    if (NULL != configInfoList.pConfig)
    {
        status = TAP_UTILS_freeConfigInfoList(&configInfoList);
        if (OK != status)
            printf("TAP_UTILS_freeConfigInfoList : %d\n", status);
    }

#if (defined(__ENABLE_DIGICERT_TAP_REMOTE__))
    if (connInfo.serverName.pBuffer != NULL)
    {
        DIGI_FREE((void **)&connInfo.serverName.pBuffer);
    }
#endif
    return status;

}
#endif


int main( int argc, char* argv[])
{
    sbyte4 retVal;
    sbyte4 canCreate;

    if (OK > ( retVal = DIGICERT_initDigicert()))
        goto exit;

/***********************************************************************************
IMPORTANT NOTE: IF YOU ADD A NEW SERVER THAT USES THE SAME CERTIFICATES AS THE
NORMAL ONE (port 1443), PLEASE MAKE SURE IT DOES NOT TRY TO CREATE THE CERTS
CF.ABOVE SETTING THE canCreate VARIABLE
************************************************************************************/
#if defined(__SSLSERV_NORMAL_CERTS__)
    canCreate = 2; /* normal server creates certificates */
#elif defined(__SSLSERV_EXPIRED_CERTS__)
    canCreate = 1; /*  expired or multiple server names have their own certificates */
#else
/* The other ones use the same certificates as the normal version -- it can
   lead to concurrency problems if they can create these */
    canCreate = 0;
#endif

#if !defined(__SSLSERV_EXPIRED_CERTS__)
#if (defined(__ENABLE_DIGICERT_TAP__) && !defined(__ENABLE_DIGICERT_TAP_EXTERN__))
    if (OK != (retVal = SSL_SERV_TAPInit(pTapConfigFile,
                                         &g_pTapEntityCred,
                                         &g_pTapKeyCred)))
    {
        printf("SSL_SERV_TAPInit failed::status: %d", retVal);
        goto exit;
    }

    if (OK > (retVal = CRYPTO_INTERFACE_registerTapCtxCallback((void *)&SSL_SERV_getTapContext)))
        goto exit;
#endif

#endif

    if (OK > (retVal = SSL_SERV_populateCertificateStore(&pSslCertStore, canCreate)))
        goto exit;
    SSL_SERV_releaseCertificateInfos();

    if (OK > (retVal = SSL_init(MAX_SSL_CONNECTIONS_ALLOWED, 0)))
        goto exit;

    SSL_SERV_initUpcalls();

/***********************************************************************************
IMPORTANT NOTE: IF YOU ADD A NEW SERVER THAT USES THE SAME CERTIFICATES AS THE
NORMAL ONE (port 1443), PLEASE MAKE SURE IT DOES NOT TRY TO CREATE THE CERTS
CF.ABOVE SETTING THE canCreate VARIABLE
************************************************************************************/

#if MIN_SSL_MINORVERSION==SSL3_MINORVERSION
    SSL_SERV_startServer(1460);
#elif defined(__ENABLE_HARDWARE_ACCEL_CRYPTO__)
    SSL_SERV_startServer(1461);
#elif defined(__ENABLE_DIGICERT_SSL_SRP__)
    SSL_SERV_startServer(1462);  /* since SRP takes precedence over other ciphers in our 
                                  implementation, we are using a dedicated SRP server
                                  for testing to make sure other tests are not affected */
#elif defined( __SSLSERV_VERSION_SET__)
    SSL_SERV_startServer(1449);
#elif defined( __SSLSERV_MUTUAL_AUTH_SUPPORT__)
    SSL_SERV_startServer(1447);
#elif defined( __SSLSERV_EXPIRED_CERTS__)
    SSL_SERV_startServer(1446);
#elif defined( __ENABLE_DIGICERT_IPV6__)
    SSL_SERV_startServer(1445); /* we want ipv6 server running on a different port number */
#elif defined( __TEST_ONE_CERT__)

     SSL_SERV_startServer(2443); /* this configuration not used by the test monkeys
                                 This allows to just test one certificate */
#elif defined(__HTTP_SERVER__)
    HTTP_SERV_startServer(8080);
#elif defined(__ENABLE_DIGICERT_OCSP_CLIENT__)
    SSL_SERV_startOCSPServers();
#else
    SSL_SERV_startServer(1443);
#endif

    if ( OK > (retVal = SSL_shutdownStack()))
    {
        DEBUG_ERROR( DEBUG_SSL_EXAMPLE, "SSL_shutdown return error: ", retVal);
    }

    if ( OK > (retVal = SSL_releaseTables()))
    {
        DEBUG_ERROR( DEBUG_SSL_EXAMPLE, "SSL_releaseTables return error: ", retVal);
    }

exit:
    CERT_STORE_releaseStore(&pSslCertStore);

    if (OK > DIGICERT_freeDigicert())
    {
        DEBUG_PRINTNL( DEBUG_SSL_EXAMPLE, (sbyte*) "DIGICERT_freeDigicert return error");
    }

    return retVal;
}
