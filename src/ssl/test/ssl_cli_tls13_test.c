/*
  ssl_cli_tls13_test.c

  implementation of a client that supports all
  the possible ciphers

  used to test the implementation
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

/* This file purposedly does not follow the usual rules for
   unit test files. This is because it implements a much higher
   level of tests
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
#include "../../common/debug_console.h"
#include "../../common/mstdlib.h"
#include "../../common/sizedbuffer.h"
#include "../../crypto/hw_accel.h"
#include "../../crypto/crypto.h"
#include "../../common/vlong.h"
#include "../../common/random.h"
#include "../../crypto/rsa.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../../crypto/primefld.h"
#include "../../crypto/primeec.h"
#endif
#include "../../crypto/pubcrypto.h"
#include "../../crypto/ca_mgmt.h"
#include "../../crypto/cert_store.h"
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

#include "../../../unit_tests/unittest.h"

#include <string.h> /* strstr */
#include <stdlib.h>
#include <stdio.h>

#define MAX_RESOURCES (10)
#ifdef __ENABLE_DIGICERT_IPV6__
#define LOOPBACK "::1"
#ifdef __ENABLE_DIGICERT_NO_MAPPING__
#define LOOPBACK_IPV4_MAPPED_V6_ADDR "::1"
#else
#define LOOPBACK_IPV4_MAPPED_V6_ADDR "::FFFF:127.0.0.1"
#endif
#else
#define LOOPBACK "127.0.0.1"
#endif

typedef struct CipherDesc
{
    ubyte2          cipherId;
    const char*    cipherName;
    ubyte           minSSLVer;
} CipherDesc;

#define CIPHER_DESC(a, n, v) { a, #n, v }

/* ordered by cipherId */
CipherDesc gtls13CipherDescs[] =
{
    CIPHER_DESC(0x1301, TLS_AES_128_GCM_SHA256,  4),
    CIPHER_DESC(0x1302, TLS_AES_256_GCM_SHA384,  4),
    CIPHER_DESC(0x1304, TLS_AES_128_CCM_SHA256,  4),
    CIPHER_DESC(0x1305, TLS_AES_128_CCM_8_SHA256, 4),
    CIPHER_DESC(0x1303, TLS_CHACHA20_POLY1305_SHA256, 4),
};

#define CIPHER_HINT(h,i)  ( ((h) << 16) | (gtls13CipherDescs[i].cipherId))
#define CIPHER_HINTX(h,i)  ( ((h) << 16) | (i))


/* we need to use 2 stores for testing purposes because openssl always
   request RSA certs first for mutual authentication and we want to
   test ECC certs for mutual authentication */
static certStorePtr pRSASslCertStore;
static certStorePtr pECCSslCertStore;

/* special test cert stores */
static certStorePtr pUnknownSslCertStore; /* a cert unknwown to the server */
static certStorePtr pBadChainSslCertStore; /* CA pathlen:1 (chain1_1_of_4.der) */
static certStorePtr pOCSPSslCertStore; /* Cert store for OCSP stapling tests*/
static certStorePtr pTAPSslCertStore; /* Cert Store with RSA and ECDSA TAP Keys */
static certStorePtr pQSSslCertStore; /* Cert Store with RSA and ECDSA TAP Keys */

static AsymmetricKey mRSAMutualAuthCertKey;

/* root certs */
typedef struct RootCertInfo
{
    int indexCheck;
    const char* fileName;
    ubyte* certData;
    ubyte4 certLength;
} RootCertInfo;

enum
{
    kRSACertIdx,
    kECC256CertIdx,
    kECC384CertIdx,
    kECC521CertIdx,
    Ed25519CertIdx,
    Ed448CertIdx,
    kQS256Mldsa44CertIdx,
    kQS256Fndsa512CertIdx,
    kQS384Mldsa65CertIdx,
    kExpCertIdx,
    kOpenSSLCertIdx,
    kOpenSSLECCCertIdx,
    kOpenSSLLongChainCertIdx,
};
typedef enum ServerType
{
    OPENSSL = 0,
    MOCANA = 1,
    MBEDTLS = 2,
} ServerType;

/* could use designated initializers if we are sure this will only be compiled
 with C99 compilers ... */
static RootCertInfo gRootCerts[] =
{
    {kRSACertIdx, "../testaux/ca_rsa_cert.der", 0, 0 },
    {kECC256CertIdx, "../testaux/ca_ecdsa_cert.der",  0, 0 },
    {kECC384CertIdx, "../testaux/ca_ecdsa_cert.der",  0, 0 },
    {kECC521CertIdx, "../testaux/ca_ecdsa_cert.der", 0, 0 },
#if 0
    {Ed25519CertIdx, "../testaux/ca_cert_rsa.der", 0, 0 },
    {Ed448CertIdx, "../testaux/ca_cert_rsa.der", 0, 0 },
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    {kQS256Mldsa44CertIdx,   "../testaux/ecc_256_mldsa44_cert.der",   0, 0 },
    {kQS256Fndsa512CertIdx,  "../testaux/ecc_256_fndsa512_cert.der",  0, 0 },
    {kQS384Mldsa65CertIdx,   "../testaux/ecc_384_mldsa65_cert.der",   0, 0 },
    {kQS521Fndsa1024CertIdx, "../testaux/ecc_521_fndsa1024_cert.der", 0, 0 },
#endif
};

enum TLS13_SignatureSchemeListType
{
    rsa_pkcs1_sha256                     = 0x401,
    ecdsa_secp256r1_sha256               = 0x403,
    ecdsa_secp384r1_sha384               = 0x503,
    ecdsa_secp521r1_sha512               = 0x603,
    rsa_pss_rsae_sha256                  = 0x804,
    ed25519                              = 0x807,
    ed448                                = 0x808,
#ifdef __ENABLE_DIGICERT_PQC__
    hybrid_p256_mldsa44               = 0x409,
    hybrid_p256_fndsa512                = 0x40a,
    hybrid_p384_mldsa65               = 0x40b,
    hybrid_p521_fndsa1024               = 0x40d,
#endif
};


/* special certificate used to test certificate chains */
const char* kRSABadCertChainCATls13 = "../testaux/chain1_1_of_4.der";

/* in ssl_cli_test_aux.c */
extern int SSL_CLI_VerifyECDHECurve(int  hint, sbyte4 connectionInstance, enum tlsExtNamedCurves curve);
extern int SSL_CLI_VerifyPublicKeyCurve(int hint, sbyte4 connectionInstance, enum tlsExtNamedCurves curve);
extern int SSL_CLI_GetLeafCertificate(int hint, sbyte4 connectionInstance,
                                      const ubyte** leafCert,
                                      ubyte4* leafCertLen);

extern int SSL_CLI_SendVersionCmd(ubyte4 hint,
                    const sbyte* serverIpAddress, ubyte2 serverPort,
                    const char* resourceName,
                    const char* serverCN, certStorePtr certStore,
                    sbyte4 serverCmd);

enum TLS13_cipherAlgorithmType
{
    TLS13_cipher                         = 0,
    TLS13_supportedGroups                = 1,
    TLS13_signatureAlgorithms            = 2,
    TLS13_certificateSignatureAlgorithms = 3
};

sbyte* serverSupportedConfigCmd              = "config SSL_setCipherAlgorithm #";
sbyte* serverNumTicketsConfigCmd             = "config SSL_setNumTickets #";
sbyte* serverKeyUpdateTestsConfigCmd         = "config keyUpdateTests #";
sbyte* serverPostHandshakeAuthTestsConfigCmd = "config postHandshakeTests #";

static int g0rttTest = 0;

extern sbyte4 SSL_CLI_SendCmdAux(ubyte4 hint, sbyte4 connectionInstance,
                   const char* pageName, sbyte* buffer,sbyte4* bufferSize );
/*------------------------------------------------------------------*/

static sbyte4
SSL_CLI_mutualAuthCertVerify(sbyte4 connectionInstance, const ubyte* hash,
                             ubyte4 hashLen, ubyte* result,
                             ubyte4 resultLength)
{
    MSTATUS status;
    hwAccelDescr hwAccelCtx;

    if (OK > (status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return status;

    status = RSA_signMessage(MOC_RSA(hwAccelCtx) mRSAMutualAuthCertKey.key.pRSA,
                             hash, hashLen, result, NULL);

    UNITTEST_STATUS(0, status);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return status;
}


/*------------------------------------------------------------------*/

sbyte4 SSL_CLI_tls13_choosePSK(sbyte4 connectionInstance, ubyte *pHintPSK,
                         ubyte4 hintLength,
                         ubyte retPskIdentity[SSL_PSK_SERVER_IDENTITY_LENGTH],
                         ubyte4 *pRetPskIdentity,
                         ubyte retPSK[SSL_PSK_MAX_LENGTH],
                         ubyte4 *pRetLengthPSK)
{
    /* identity expected by all the PSK enabled servers:
     OpenSSL, mbedTLS and ours */
    memcpy(retPskIdentity, "Client_identity", 15);
    *pRetPskIdentity = 15;

    memcpy(retPSK,
           "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
           16);
    *pRetLengthPSK = 16;
    return 0;
}


/*------------------------------------------------------------------------*/
#if defined (__ENABLE_DIGICERT_TAP__)
static TAP_Context *g_pTapContext = NULL;
static TAP_EntityCredentialList *g_pTapEntityCred = NULL;
static TAP_CredentialList       *g_pTapKeyCred    = NULL;
static TAP_ModuleList           g_moduleList      = { 0 };
static int                      g_TapProvider     = TAP_PROVIDER_TPM2;

static sbyte4
SSL_CLI_TEST_getTapContext(TAP_Context **ppTapContext,
                          TAP_EntityCredentialList **ppTapEntityCred,
                          TAP_CredentialList **ppTapKeyCred,
                          void *pKey, TapOperation op, ubyte getContext)
{
    MSTATUS status = OK;
    TAP_ErrorContext *pErrContext = NULL;
    TAP_Module *pModule = NULL;

    if (pKey == NULL)
    {
        status = ERR_NULL_POINTER;
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

        if (g_pTapContext == NULL)
        {
            /* Initialize context on first module */
            status = TAP_initContext(pModule, g_pTapEntityCred,
                                        NULL,&g_pTapContext, pErrContext);
            if (OK != status)
            {
                printf("TAP_initContext : %d\n", status);
                goto exit;
            }
        }

        /*ppTapContext    = g_pTapContext;*/
        *ppTapContext    = g_pTapContext;
        *ppTapEntityCred = g_pTapEntityCred;
        *ppTapKeyCred    = g_pTapKeyCred;
    }
    else
    {
#if 0
        /* Destroy the TAP context */
        if (OK > (status = TAP_uninitContext(ppTapContext, pErrContext)))
        {
            DEBUG_ERROR(DEBUG_SSL_EXAMPLE, (sbyte*)"SSL_EXAMPLE: TAP_uninitContext failed with status: ", status);
        }
#endif
    }

exit:
    return status;
}

static MSTATUS
SSL_CLI_TEST_TAPInit(ubyte *pTpm2ConfigFile,
                    TAP_EntityCredentialList **ppTapEntityCred,
                    TAP_CredentialList **ppTapKeyCred,
                    ubyte2 tapProvider)
{
    MSTATUS status = OK;
    TAP_ConfigInfoList configInfoList = { 0, };
    TAP_Context *pTapContext = NULL;
    TAP_ErrorContext *pErrContext = NULL;
    ubyte tapInit = FALSE;
    ubyte gotModuleList = FALSE;
    ubyte contextInit = FALSE;
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
    configInfoList.pConfig[0].provider = tapProvider;
#endif

    status = TAP_init(&configInfoList, pErrContext);
    if (OK != status)
    {
        printf("TAP_init : %d", status);
        goto exit;
    }
    tapInit = TRUE;

#if (defined(__ENABLE_DIGICERT_TAP_REMOTE__))

    connInfo.serverName.bufferLen = DIGI_STRLEN((char *)taps_ServerName)+1;
    status = DIGI_CALLOC ((void **)&(connInfo.serverName.pBuffer), 1, connInfo.serverName.bufferLen);
    if (OK != status)
    goto exit;

    status = DIGI_MEMCPY ((void *)(connInfo.serverName.pBuffer), (void *)taps_ServerName, DIGI_STRLEN(taps_ServerName));
    if (OK != status)
    goto exit;

    connInfo.serverPort = taps_ServerPort;

    status = TAP_getModuleList(&connInfo, tapProvider, NULL,
                               &g_moduleList, pErrContext);
#else
    status = TAP_getModuleList(NULL, tapProvider, NULL,
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

    if (tapProvider == TAP_PROVIDER_PKCS11)
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
        printf("Failed to get credentials from Credential configuration file status : %d", status);
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
            printf("TAP_UTILS_freeConfigInfoList : %d", status);
    }

#if (defined(__ENABLE_DIGICERT_TAP_REMOTE__))
    if (connInfo.serverName.pBuffer != NULL)
    {
        DIGI_FREE((void**)&connInfo.serverName.pBuffer);
    }
#endif
    return status;

}

static int populateTAPCertStore()
{
    int i, retVal = 0;
    certDescriptor certDesc = {0};
    SizedBuffer certificate;
    ubyte*      pContents = NULL;
    ubyte4      contentsLen = 0;
    AsymmetricKey asymKey = { 0 };
    char *pTapConfigFile = TPM2_CONFIGURATION_FILE;

    UNITTEST_STATUS_GOTO(0, SSL_CLI_TEST_TAPInit(pTapConfigFile,
                                                 &g_pTapEntityCred,
                                                 &g_pTapKeyCred, g_TapProvider),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(0, CRYPTO_INTERFACE_registerTapCtxCallback((void *)&SSL_CLI_TEST_getTapContext),
                         retVal, exit);
    UNITTEST_STATUS_GOTO(0, CERT_STORE_createStore(&pTAPSslCertStore),
                         retVal, exit);

    /* Add RSA TPM2 Keys */

    if (OK > (retVal = DIGICERT_readFile("../testaux/ClientRSATPM2Cert.der",
                             &certDesc.pCertificate,
                             &certDesc.certLength)))
    {
        goto exit;
    }

    UNITTEST_STATUS_GOTO(0,
                         DIGICERT_readFile("../testaux/ClientRSATPM2CertKey.pem",
                                         &pContents, &contentsLen),
                         retVal,exit);

    UNITTEST_STATUS_GOTO(0, CRYPTO_initAsymmetricKey (&asymKey), retVal, exit);

    UNITTEST_STATUS_GOTO(0, CRYPTO_deserializeAsymKey (MOC_ASYM(hwAccelCtx) pContents, contentsLen, NULL, &asymKey),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(0, CRYPTO_serializeAsymKey(MOC_ASYM(hwAccelCtx) &asymKey, mocanaBlobVersion2,
                                                    &certDesc.pKeyBlob, &certDesc.keyBlobLength),
                         retVal, exit);

    certificate.length = certDesc.certLength;
    certificate.data = certDesc.pCertificate;

    UNITTEST_STATUS_GOTO(0, CERT_STORE_addIdentityWithCertificateChain(pTAPSslCertStore,
                                                                       &certificate, 1,
                                                                       certDesc.pKeyBlob,
                                                                       certDesc.keyBlobLength),
                         retVal, exit);
    if (pContents)
    {
        DIGI_FREE((void **)&pContents);
        contentsLen = 0;
    }
    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

    FREE(certDesc.pCertificate); certDesc.pCertificate = 0;
    FREE(certDesc.pKeyBlob); certDesc.pKeyBlob = 0;

    /* Add ECDSA TPM2 Keys */

    if (OK > (retVal = DIGICERT_readFile("../testaux/ClientECDSATPM2Cert.der",
                             &certDesc.pCertificate,
                             &certDesc.certLength)))
    {
        goto exit;
    }

    UNITTEST_STATUS_GOTO(0,
                         DIGICERT_readFile("../testaux/ClientECDSATPM2CertKey.pem",
                                         &certDesc.pKeyBlob,
                                         &certDesc.keyBlobLength),
                         retVal,exit);

    UNITTEST_STATUS_GOTO(0, CRYPTO_initAsymmetricKey (&asymKey), retVal, exit);

    UNITTEST_STATUS_GOTO(0, CRYPTO_deserializeAsymKey (MOC_ASYM(hwAccelCtx) pContents, contentsLen, NULL, &asymKey),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(0, CRYPTO_serializeAsymKey(MOC_ASYM(hwAccelCtx) &asymKey, mocanaBlobVersion2,
                                                    &certDesc.pKeyBlob, &certDesc.keyBlobLength),
                         retVal, exit);

    certificate.length = certDesc.certLength;
    certificate.data = certDesc.pCertificate;

    UNITTEST_STATUS_GOTO(0, CERT_STORE_addIdentityWithCertificateChain(pTAPSslCertStore,
                                                                       &certificate, 1,
                                                                       certDesc.pKeyBlob,
                                                                       certDesc.keyBlobLength),
                         retVal, exit);

    if (pContents)
    {
        DIGI_FREE((void **)&pContents);
        contentsLen = 0;
    }
    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

    FREE(certDesc.pCertificate); certDesc.pCertificate = 0;
    FREE(certDesc.pKeyBlob); certDesc.pKeyBlob = 0;

exit:
    if (certDesc.pCertificate)
        FREE(certDesc.pCertificate);

    if (certDesc.pKeyBlob)
        FREE(certDesc.pKeyBlob);

    return retVal;
}
#endif


static int
SSL_CLI_tls13_initUpcallsAndCertStores()
{
    int i, retVal = 0;
    certDescriptor certDesc = {0};
    SizedBuffer certificate;
    MSTATUS status = OK;
    ubyte*                  pContents = NULL;
    ubyte4                  contentsLen = 0;
    AsymmetricKey           asymKey = {0};

    /* support for PSK */
    SSL_sslSettings()->funcPtrChoosePSK = SSL_CLI_tls13_choosePSK;

    /* load the information necessary for mutual authentication */
    /* RSA first...*/

    /* when the test first runs, the cert might not be there so if it
     fails, wait a little */
    for (i = 0; i < 10; ++i)
    {

        if (OK > (status = DIGICERT_readFile("../testaux/rsa_2048_signed_by_rsa_cert.der",
                                 &certDesc.pCertificate,
                                 &certDesc.certLength)))
        {
            RTOS_sleepMS(1000);
        }
        else
        {
            break;
        }
    }

    UNITTEST_STATUS_GOTO(0, status, retVal, exit);

    UNITTEST_STATUS_GOTO(0,
                         DIGICERT_readFile("../testaux/rsa_2048_signed_by_rsa_key.pem",
                                         &pContents, &contentsLen),
                         retVal,exit);

    if (OK > (retVal = CRYPTO_deserializeAsymKey (
            MOC_ASYM(hwAccelCtx) pContents, contentsLen, NULL, &asymKey)))
    {
        goto exit;
    }

    if (OK > (retVal = CRYPTO_serializeAsymKey(MOC_ASYM(hwAccelCtx) &asymKey, mocanaBlobVersion2, &certDesc.pKeyBlob, &certDesc.keyBlobLength)))
    {
        goto exit;
    }

    /* for RSA, we are mimicking a system where the key is not stored in
     the cert store but outside like a TM or smart card -> save the key */
    UNITTEST_STATUS_GOTO(0,
                         CA_MGMT_extractKeyBlobEx(certDesc.pKeyBlob,
                                                  certDesc.keyBlobLength,
                                                  &mRSAMutualAuthCertKey),
                         retVal, exit);


    UNITTEST_STATUS_GOTO(0, CERT_STORE_createStore(&pRSASslCertStore),
                         retVal, exit);


    certificate.length = certDesc.certLength;
    certificate.data = certDesc.pCertificate;

    /* for RSA we will use the callback to simulate a smart card so no key blob in cert store */
    UNITTEST_STATUS_GOTO(0, CERT_STORE_addIdentityWithCertificateChain(pRSASslCertStore,
                                                                       &certificate, 1,
                                                                       NULL, /* no key */
                                                                       0),
                         retVal, exit);
#ifdef __SSLCLIENT_MUTUAL_AUTH_SUPPORT__
    /* callback */
    SSL_sslSettings()->funcPtrMutualAuthCertificateVerify = SSL_CLI_mutualAuthCertVerify;
#endif

    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
    FREE(certDesc.pCertificate); certDesc.pCertificate = 0;
    FREE(certDesc.pKeyBlob); certDesc.pKeyBlob = 0;

    /* ... then ECC */
    UNITTEST_STATUS_GOTO(0,
                         DIGICERT_readFile("../testaux/ecc_256_signed_by_rsa_cert.der",
                                         &certDesc.pCertificate,
                                         &certDesc.certLength),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(0,
                         DIGICERT_readFile("../testaux/ecc_256_signed_by_rsa_key.pem",
                                         &pContents, &contentsLen),
                         retVal, exit);

    if (OK > (retVal = CRYPTO_deserializeAsymKey (
            MOC_ASYM(hwAccelCtx) pContents, contentsLen, NULL, &asymKey)))
    {
        goto exit;
    }

    if (OK > (retVal = CRYPTO_serializeAsymKey(MOC_ASYM(hwAccelCtx) &asymKey, mocanaBlobVersion2, &certDesc.pKeyBlob, &certDesc.keyBlobLength)))
    {
        goto exit;
    }

    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

    if (OK > (retVal = CERT_STORE_createStore(&pECCSslCertStore)))
        goto exit;

    certificate.length = certDesc.certLength;
    certificate.data = certDesc.pCertificate;
    /* for ECC we will store the cert and key in the cert store */
    UNITTEST_STATUS_GOTO(0,
                         CERT_STORE_addIdentityWithCertificateChain(pECCSslCertStore,
                                                                    &certificate, 1,
                                                                    certDesc.pKeyBlob,
                                                                    certDesc.keyBlobLength),
                         retVal,exit);

    FREE(certDesc.pCertificate); certDesc.pCertificate = 0;
    FREE(certDesc.pKeyBlob); certDesc.pKeyBlob = 0;

#if 0
    /* ... finally cert not in server cert store */
    UNITTEST_STATUS_GOTO(0,
                         DIGICERT_readFile( "../testaux/UnknownClientECCCert.der",
                                         &certDesc.pCertificate,
                                         &certDesc.certLength),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(0,
                         DIGICERT_readFile( "../testaux/UnknownClientECCCertKey.dat",
                                         &certDesc.pKeyBlob,
                                         &certDesc.keyBlobLength),
                         retVal,exit);

    UNITTEST_STATUS_GOTO(0, CERT_STORE_createStore(&pUnknownSslCertStore),
                         retVal, exit);


    certificate.length = certDesc.certLength;
    certificate.data = certDesc.pCertificate;

    /* also store cert and key in cert store for this one */
    UNITTEST_STATUS_GOTO(0, CERT_STORE_addIdentityWithCertificateChain(pUnknownSslCertStore,
                                                                       &certificate, 1,
                                                                       certDesc.pKeyBlob,
                                                                       certDesc.keyBlobLength),
                         retVal, exit);

    FREE(certDesc.pCertificate); certDesc.pCertificate = 0;
    FREE(certDesc.pKeyBlob); certDesc.pKeyBlob = 0;
#endif

#if defined(__ENABLE_DIGICERT_TAP__)
    retVal += populateTAPCertStore();
#endif

    /* now load the root certs as trust points in all three certificate stores */

    /* internal check */
    for (i = 0 ; i < COUNTOF(gRootCerts); ++i)
    {
        retVal += UNITTEST_TRUE(i, gRootCerts[i].indexCheck == i);
    }
    if (retVal) goto exit;

    for (i = 0 ; i < COUNTOF(gRootCerts); ++i)
    {

        retVal +=  UNITTEST_STATUS(i,
                                   DIGICERT_readFile( gRootCerts[i].fileName,
                                                   &gRootCerts[i].certData,
                                                   &gRootCerts[i].certLength));

        /* add to all cert stores */
        retVal += UNITTEST_STATUS(i, CERT_STORE_addTrustPoint(pRSASslCertStore,
                                                              gRootCerts[i].certData,
                                                              gRootCerts[i].certLength));
        retVal += UNITTEST_STATUS(i, CERT_STORE_addTrustPoint(pECCSslCertStore,
                                                              gRootCerts[i].certData,
                                                              gRootCerts[i].certLength));
#if 0
        retVal += UNITTEST_STATUS(i, CERT_STORE_addTrustPoint(pUnknownSslCertStore,
                                                              gRootCerts[i].certData,
                                                              gRootCerts[i].certLength));
#endif
#if defined(__ENABLE_DIGICERT_TAP__)
        retVal += UNITTEST_STATUS(i, CERT_STORE_addTrustPoint(pTAPSslCertStore,
                                                              gRootCerts[i].certData,
                                                              gRootCerts[i].certLength));
#endif
    }
    if (retVal) goto exit;

    /* the very special cert store used for cert chain testing */
    UNITTEST_STATUS_GOTO(0, CERT_STORE_createStore(&pBadChainSslCertStore),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(0, DIGICERT_readFile(kRSABadCertChainCATls13,
                                            &certDesc.pCertificate,
                                            &certDesc.certLength),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(0, CERT_STORE_addTrustPoint(pBadChainSslCertStore,
                                                     certDesc.pCertificate,
                                                     certDesc.certLength),
                         retVal, exit);
    FREE(certDesc.pCertificate); certDesc.pCertificate = 0;

exit:

    FREE(certDesc.pCertificate); certDesc.pCertificate = 0;
    FREE(certDesc.pKeyBlob); certDesc.pKeyBlob = 0;
    return retVal;
}


/* gather test results */
typedef struct TestResults
{
    ubyte2 cipherId;
    unsigned int openssl;
    unsigned int mocana;
    unsigned int mbedtls;
} TestResults;

TestResults gTestResults[COUNTOF(gtls13CipherDescs)];
#define CHK(a,b)  ( ( ( (a) >> (b) ) & 1 ) ? 'X' : ' ')

extern int FindCipherId(const void* key, const void* elem);
extern void SSL_CLI_storeTestResults(ubyte2 cipherId, int protocol, ServerType server);
extern void SSL_CLI_outputTestResults();
/*---------------------------------------------------------------------------

int FindCipherId(const void* key, const void* elem)
{
    ubyte2* cipherId = (ubyte2*) key;
    TestResults* el = (TestResults*) elem;

    return  (*cipherId)- el->cipherId;
}
*/

/*---------------------------------------------------------------------------

void SSL_CLI_storeTestResults(ubyte2 cipherId, int protocol, ServerType server)
{
    TestResults* pFound = (TestResults*) bsearch(&cipherId, gTestResults, COUNTOF(gTestResults),
                                                 sizeof(gTestResults[0]), FindCipherId);

    if (pFound)
    {
        switch (server)
        {
            case OPENSSL:
                pFound->openssl |= (1 << protocol);
                break;

            case MOCANA:
                pFound->mocana |= (1 << protocol);
                break;

            case MBEDTLS:
                pFound->mbedtls |= (1 << protocol);
                break;
        }
    }
}
*/

/*---------------------------------------------------------------------------

void SSL_CLI_outputTestResults()
{
    int i;

    printf("         %-50s |        OpenSSL        |          mbedTLS      |        Mocana               |\n", "");
    printf("  Id   | %-50s | 3.0 | 1.0 | 1.1 | 1.2 | 3.0 | 1.0 | 1.1 | 1.2 | 3.0 | 1.0 | 1.1 | 1.2 | 1.3 |\n", "cipher name");

    for (i = 0; i < COUNTOF(gTestResults); ++i)
    {
        TestResults* pTR = gTestResults+i;

        printf("0x%04x | %-50s |  %c  |  %c  |  %c  |  %c  |  %c  |  %c  |  %c  |  %c  |  %c  |  %c  |  %c  |  %c  |  %c  |\n",
               pTR->cipherId,
               gtls13CipherDescs[i].cipherName,
               CHK(pTR->openssl, SSL3_MINORVERSION),
               CHK(pTR->openssl, TLS10_MINORVERSION),
               CHK(pTR->openssl, TLS11_MINORVERSION),
               CHK(pTR->openssl, TLS12_MINORVERSION),
               CHK(pTR->mbedtls, SSL3_MINORVERSION),
               CHK(pTR->mbedtls, TLS10_MINORVERSION),
               CHK(pTR->mbedtls, TLS11_MINORVERSION),
               CHK(pTR->mbedtls, TLS12_MINORVERSION),
               CHK(pTR->mocana, SSL3_MINORVERSION),
               CHK(pTR->mocana, TLS10_MINORVERSION),
               CHK(pTR->mocana, TLS11_MINORVERSION),
               CHK(pTR->mocana, TLS12_MINORVERSION),
               CHK(pTR->mocana, TLS13_MINORVERSION)
        );
    }

}
*/
/*---------------------------------------------------------------------------*/

void SSL_CLI_tls13_initializeTestResults()
{
    int i;

    for (i = 0; i < COUNTOF(gtls13CipherDescs); ++i)
    {
        gTestResults[i].cipherId = gtls13CipherDescs[i].cipherId;
    }
}


/*------------------------------------------------------------------*/

static sbyte4
SSL_CLI_GetSecurePageAux(ubyte4 hint, sbyte4 connectionInstance,
                         const char* pageName, sbyte* buffer,
                         sbyte4* bufferSize)
{
    ubyte4 bytesSent;
    sbyte4 pageNameLen;
    int    result = 0;

    char *pEnv = NULL;
    ubyte verifyMocanaServerResposne = 1;

    pEnv = getenv("ENABLE_OPENSSL_INTEROPERABILITY_TEST");
    if (pEnv != NULL)
    {
        if (1 == atoi(pEnv))
            verifyMocanaServerResposne = 0;
    }

    pageNameLen = DIGI_STRLEN((sbyte*) pageName);

    /* build the request */
    DIGI_MEMCPY(buffer, "GET /", 5);
    DIGI_MEMCPY(buffer+5, pageName, pageNameLen);
    DIGI_MEMCPY(buffer + 5 + pageNameLen,
               " HTTP/1.0\r\n\r\n",
               14);

    bytesSent = SSL_send(connectionInstance, buffer, pageNameLen + 18);
    DIGI_MEMSET(buffer, 0x00, *bufferSize);

    result += UNITTEST_INT(hint, bytesSent, pageNameLen + 18);

    if (0 == result)
    {
        sbyte4 bytesReceived = 0;
        sbyte4 sslRecvRes = 0;
        sbyte4 totalReceived = 0;

        while (0 <= sslRecvRes && totalReceived < *bufferSize)
        {
            sslRecvRes = SSL_recv(connectionInstance,
                                  buffer + totalReceived,
                                  *bufferSize - totalReceived,
                                  &bytesReceived, 0);
            if (sslRecvRes>= OK)
            {
                totalReceived += bytesReceived;
            }
            if ((0 == DIGI_STRCMP((const sbyte*) "\r\n\r\n", buffer + totalReceived - 4)) ||
                (0 == DIGI_STRCMP((const sbyte*) "\n\n", buffer + totalReceived - 2)) ||
                (0 == DIGI_STRCMP((const sbyte*) "</body></html>\r\n\r\n", buffer + totalReceived - 18))
                    )
            {
                break;
            }
        }
        *bufferSize = totalReceived;
        return 0;
    }
    return result;
}

/*------------------------------------------------------------------------*/
int SSL_CLI_SendSupportedCmd(ubyte4 hint,
                             const sbyte* serverIpAddress, ubyte2 serverPort,
                             const char* resourceName,
                             const char* serverCN, certStorePtr certStore,
                             const char* serverConfigCmd,
                             sbyte4 serverCmd)
{
    /* connect to the host specified and set a simple GET */
    sbyte4          connectionInstance;
    TCP_SOCKET      mySocket;
    int             retVal = 0;
    const ubyte*    alpn = 0;
    ubyte4          alpnLen;
    sbyte           buffer[150] = {0};
    sbyte4          bufferSize;
    const sbyte*    found;
    char *pEnv = NULL;
    ubyte verifyMocanaServerResposne = 1;

    pEnv = getenv("ENABLE_OPENSSL_INTEROPERABILITY_TEST");
    if (pEnv != NULL)
    {
        if (1 == atoi(pEnv))
            verifyMocanaServerResposne = 0;
    }

    if (1 == verifyMocanaServerResposne)
    {
        /* retrieve the resource */
        retVal += UNITTEST_STATUS(hint, TCP_CONNECT(&mySocket,
                                                    (sbyte*)serverIpAddress,
                                                    serverPort));
        if (retVal) goto exit;

        retVal += UNITTEST_STATUS(hint,
                                  connectionInstance = SSL_connect(mySocket,
                                                                   0, NULL,
                                                                   NULL,
                                                                   (sbyte*) serverCN,
                                                                   certStore));
        if (retVal) goto exit_close;

        retVal += UNITTEST_STATUS(hint,
                                  SSL_negotiateConnection(connectionInstance));

        if (retVal) goto exit_close;

        bufferSize = 1;
        sprintf(buffer, "%s%d", serverConfigCmd, serverCmd);
        printf(" sent command is  ====> %s \n", buffer);
        retVal += SSL_CLI_SendCmdAux(hint, connectionInstance, buffer, (sbyte *)buffer, &bufferSize);

        if (retVal) goto exit_close;

        bufferSize = 2;
        printf(" received command is ====> %s \n", buffer);
        found = SSL_CLI_FindStr("a", buffer, bufferSize);
        retVal += UNITTEST_VALIDPTR(hint, found);
        if (!found) goto exit_close;

        exit_close:

        SSL_closeConnection(connectionInstance);

        TCP_CLOSE_SOCKET( mySocket);
    }
exit:

    return retVal;
}

/*------------------------------------------------------------------------*/
int SSL_CLI_Tls13_KeyUpdateTest(ubyte4 hint, const CipherDesc* pCipherDesc,
                    const sbyte* serverIpAddress, ubyte2 serverPort,
                    const char* resourceName, int rootCertIndex,
                    const char* serverCN, ServerType serverType,
                    sbyte4 sslProtocol, certStorePtr certStore)
{
    /* connect to the host specified and set a simple GET */
    sbyte4          connectionInstance;
    TCP_SOCKET      mySocket;
    ubyte           sessionIdLen;
    ubyte           sessionId[32 /* SSL_MAXSESSIONIDSIZE*/];
    ubyte           masterSecret[48 /*SSL_MASTERSECRETSIZE */];
    ubyte           buffer[8192];
    sbyte4          bufferSize;
    const char*     versionStr = 0;
    const char*     cipherName = (pCipherDesc) ? pCipherDesc->cipherName : 0;
    MSTATUS         status;
    int             retVal = 0;

    retVal += SSL_CLI_SendSupportedCmd(CIPHER_HINT(0x900, 0),
                                       serverIpAddress, serverPort,
                                       resourceName,
                                       serverCN, certStore, serverKeyUpdateTestsConfigCmd,
                                       1);

    /* retrieve the resource */
    retVal += UNITTEST_STATUS(hint, TCP_CONNECT(&mySocket,
                                                (sbyte*)serverIpAddress,
                                                serverPort));
    if (retVal) goto exit;

    retVal += UNITTEST_STATUS(hint,
                              connectionInstance = SSL_connect(mySocket,
                                                               0, NULL,
                                                               NULL,
                                                               (sbyte*) serverCN,
                                                               certStore));
    if (retVal) goto exit_close;

    /* pass in negative SSL version for protocol not to set the protocol */
    retVal += UNITTEST_STATUS(hint, SSL_ioctl( connectionInstance,
                                                SSL_SET_VERSION,
                                                (void*) sslProtocol));
    switch (sslProtocol)
    {
        case TLS13_MINORVERSION:
            versionStr = "TLSv1.3";
            break;
        default:
            versionStr = "an unknown version of SSL/TLS";
            break;
    }

    if (sslProtocol != SSL3_MINORVERSION)
    {
        /* set the server name indication */
        retVal += UNITTEST_STATUS(hint,
                                  SSL_setServerNameIndication(connectionInstance,
                                                              serverCN));
    }

    if (pCipherDesc)
    {
        retVal += UNITTEST_STATUS(hint, SSL_enableCiphers( connectionInstance,
                                                           &pCipherDesc->cipherId, 1));
    }

    if (retVal)
    {
        goto exit_close;
    }

    retVal += UNITTEST_STATUS(hint,
                              SSL_negotiateConnection(connectionInstance));

    if (retVal)
    {
        goto exit_close;
    }
    printf("\n----------sendkeyupdate test 1, value 0---------\n");
    /* ------------------- keyupdate test case 1--------------------------*/
    retVal += UNITTEST_STATUS(hint,
                              SSL_sendKeyUpdateRequest(connectionInstance, 0 /* update_request */));

    RTOS_sleepMS(10); /* sleep for a 0.01 second */

    bufferSize = sizeof(buffer);
    retVal += SSL_CLI_GetSecurePageAux(hint, connectionInstance,
                                       resourceName, (sbyte *)buffer, &bufferSize);

    switch (serverType)
    {
        case MOCANA:
            retVal += SSL_CLI_VerifyMocanaReply(hint, cipherName, resourceName,
                                             versionStr,
                                             (sbyte *)buffer, bufferSize);
            break;

        case OPENSSL:
            retVal += SSL_CLI_VerifyOpenSSLReply( hint, cipherName, versionStr,
                                                 (sbyte *)buffer, bufferSize);
            break;

        case MBEDTLS:
            retVal += SSL_CLI_VerifymbedReply( hint, cipherName, versionStr,
                                              (sbyte*) buffer, bufferSize);
            break;
    }

    printf("\n----------sendkeyupdate test 2, value 1---------\n");
    /* ------------------- keyupdate test case 2--------------------------*/
    /* key update requested */
    retVal += UNITTEST_STATUS(hint,
                              SSL_sendKeyUpdateRequest(connectionInstance, 1 /* update_request */));

    RTOS_sleepMS(10); /* sleep for a 0.01 second */

    printf("\n----------sendkeyupdate test 2, value 1, send the buffer ---------\n");
    bufferSize = sizeof(buffer);
    retVal += SSL_CLI_GetSecurePageAux(hint, connectionInstance,
                                       resourceName, (sbyte *)buffer, &bufferSize);

    printf("\n----------sendkeyupdate test 2, value 1, received the echo back from server ---------\n");
    switch (serverType)
    {
        case MOCANA:
            retVal += SSL_CLI_VerifyMocanaReply(hint, cipherName, resourceName,
                                                versionStr,
                                                (sbyte *)buffer, bufferSize);
            break;

        case OPENSSL:
            retVal += SSL_CLI_VerifyOpenSSLReply( hint, cipherName, versionStr,
                                                  (sbyte *)buffer, bufferSize);
            break;

        case MBEDTLS:
            retVal += SSL_CLI_VerifymbedReply( hint, cipherName, versionStr,
                                               (sbyte*) buffer, bufferSize);
            break;
    }

    printf("\n----------sendkeyupdate test 2, server value 0---------\n");
    /* ------------------- keyupdate test case 3--------------------------*/

    RTOS_sleepMS(100); /* sleep for a 0.1 second */

    bufferSize = sizeof(buffer);
    retVal += SSL_CLI_GetSecurePageAux(hint, connectionInstance,
                                       resourceName, (sbyte *)buffer, &bufferSize);

    switch (serverType)
    {
        case MOCANA:
            retVal += SSL_CLI_VerifyMocanaReply(hint, cipherName, resourceName,
                                                versionStr,
                                                (sbyte *)buffer, bufferSize);
            break;

        case OPENSSL:
            retVal += SSL_CLI_VerifyOpenSSLReply( hint, cipherName, versionStr,
                                                  (sbyte *)buffer, bufferSize);
            break;

        case MBEDTLS:
            retVal += SSL_CLI_VerifymbedReply( hint, cipherName, versionStr,
                                               (sbyte*) buffer, bufferSize);
            break;
    }
    printf("\n----------sendkeyupdate test 4, server value 1---------\n");
    /* ------------------- keyupdate test case 4--------------------------*/

    RTOS_sleepMS(100); /* sleep for a 0.1 second */

    bufferSize = sizeof(buffer);
    retVal += SSL_CLI_GetSecurePageAux(hint, connectionInstance,
                                       resourceName, (sbyte *)buffer, &bufferSize);

    switch (serverType)
    {
        case MOCANA:
            retVal += SSL_CLI_VerifyMocanaReply(hint, cipherName, resourceName,
                                                versionStr,
                                                (sbyte *)buffer, bufferSize);
            break;

        case OPENSSL:
            retVal += SSL_CLI_VerifyOpenSSLReply( hint, cipherName, versionStr,
                                                  (sbyte *)buffer, bufferSize);
            break;

        case MBEDTLS:
            retVal += SSL_CLI_VerifymbedReply( hint, cipherName, versionStr,
                                               (sbyte*) buffer, bufferSize);
            break;
    }

exit_close:

    SSL_closeConnection(connectionInstance);

    TCP_CLOSE_SOCKET( mySocket);

exit:

    return retVal;
}


int SSL_CLI_Tls13_PostAuthTest(ubyte4 hint, const CipherDesc* pCipherDesc,
                         const sbyte* serverIpAddress, ubyte2 serverPort,
                         const char* resourceName, int rootCertIndex,
                         const char* serverCN, ServerType serverType,
                         sbyte4 sslProtocol, certStorePtr certStore)
{
    /* connect to the host specified and set a simple GET */
    sbyte4          connectionInstance;
    TCP_SOCKET      mySocket;
    ubyte           sessionIdLen;
    ubyte           sessionId[32 /* SSL_MAXSESSIONIDSIZE*/];
    ubyte           masterSecret[48 /*SSL_MASTERSECRETSIZE */];
    ubyte           buffer[8192];
    sbyte4          bufferSize;
    const char*     versionStr = 0;
    const char*     cipherName = (pCipherDesc) ? pCipherDesc->cipherName : 0;
    MSTATUS         status;
    int             retVal = 0;

    retVal += SSL_CLI_SendSupportedCmd(CIPHER_HINT(0x900, 0),
                                       serverIpAddress, serverPort,
                                       resourceName,
                                       serverCN, certStore, serverPostHandshakeAuthTestsConfigCmd,
                                       1);

    /* retrieve the resource */
    retVal += UNITTEST_STATUS(hint, TCP_CONNECT(&mySocket,
                                                (sbyte*)serverIpAddress,
                                                serverPort));
    if (retVal) goto exit;

    retVal += UNITTEST_STATUS(hint,
                              connectionInstance = SSL_connect(mySocket,
                                                               0, NULL,
                                                               NULL,
                                                               (sbyte*) serverCN,
                                                               certStore));
    if (retVal) goto exit_close;

    /* pass in negative SSL version for protocol not to set the protocol */
    retVal += UNITTEST_STATUS(hint, SSL_ioctl( connectionInstance,
                                               SSL_SET_VERSION,
                                               (void*) sslProtocol));
    switch (sslProtocol)
    {
        case TLS13_MINORVERSION:
            versionStr = "TLSv1.3";
            break;
        default:
            versionStr = "an unknown version of SSL/TLS";
            break;
    }

    if (sslProtocol != SSL3_MINORVERSION)
    {
        /* set the server name indication */
        retVal += UNITTEST_STATUS(hint,
                                  SSL_setServerNameIndication(connectionInstance,
                                                              serverCN));
    }

    if (pCipherDesc)
    {
        retVal += UNITTEST_STATUS(hint, SSL_enableCiphers( connectionInstance,
                                                           &pCipherDesc->cipherId, 1));
    }

    /* ------------------- post handshake authentication test test case 1--------------------------*/
    retVal += UNITTEST_STATUS(hint,
                              SSL_setSessionFlags(connectionInstance, SSL_FLAG_ENABLE_POST_HANDSHAKE_AUTH));

    if (retVal)
    {
        goto exit_close;
    }

    retVal += UNITTEST_STATUS(hint,
                              SSL_negotiateConnection(connectionInstance));

    if (retVal)
    {
        goto exit_close;
    }

    RTOS_sleepMS(100); /* sleep for a 0.1 second */

    printf("\n-------- sending the buffer data to the server ----\n");
    bufferSize = sizeof(buffer);
    retVal += SSL_CLI_GetSecurePageAux(hint, connectionInstance,
                                       resourceName, (sbyte *)buffer, &bufferSize);

    switch (serverType)
    {
        case MOCANA:
            retVal += SSL_CLI_VerifyMocanaReply(hint, cipherName, resourceName,
                                                versionStr,
                                                (sbyte *)buffer, bufferSize);
            break;

        case OPENSSL:
            retVal += SSL_CLI_VerifyOpenSSLReply( hint, cipherName, versionStr,
                                                  (sbyte *)buffer, bufferSize);
            break;

        case MBEDTLS:
            retVal += SSL_CLI_VerifymbedReply( hint, cipherName, versionStr,
                                               (sbyte*) buffer, bufferSize);
            break;
    }

exit_close:

    SSL_closeConnection(connectionInstance);

    TCP_CLOSE_SOCKET( mySocket);

    exit:

    return retVal;
}

tls13PSKList *pSessionListHeader = NULL;
static int   count               = 0;
static int   testPskCounter      = 0;
static sbyte*  sslc_EarlyData    = NULL;
static tls13PSKList *g_pTls13PSKList = NULL;

void free_session_list()
{
    tls13PSKList *pTemp = NULL;
    tls13PSKList *pHead = g_pTls13PSKList;
    ubyte pPskFile[256] = { 0 };
    ubyte4 i = 0;

    if (NULL == g_pTls13PSKList)
        return;

    while (NULL != pHead)
    {
        pTemp = pHead;
        pHead = pHead->pNextPSK;
        if (NULL != pTemp->pPSK)
        {
            if (NULL != pTemp->pPSK->pskTLS13Identity)
            {
                DIGI_FREE((void **) &pTemp->pPSK->pskTLS13Identity);
            }
            DIGI_FREE((void **) &pTemp->pPSK);
        }

        if (NULL != pTemp->pPskData)
        {
            DIGI_FREE((void **) &pTemp->pPskData);
        }

        DIGI_FREE((void **) &pTemp);
    }

    /* Delete the PSKs on filesystem */
    for (i = 0; i < count; i++)
    {
        sprintf((char *) pPskFile, "client%d.psk", i);
        remove(pPskFile);
    }
    count = 0;
}

static sbyte4 SSL_CLI_Tls13_RetrievePSKCb(sbyte4 connectionInstance, ubyte* ServerInfo, ubyte4 serverInfoLen,
                               void *userData, void **ppPSKs, ubyte2 *pNumPSKs, ubyte *selectedIndex, intBoolean *pFreeMemory)
{
    MSTATUS status = OK;
    ubyte4 i = 0;
    ubyte pPskFile[256] = { 0 };
    tls13PSKList *pHead = NULL;
    tls13PSKList *pTemp = NULL;
    tls13PSKList **ppCur = &pHead;


    for (; i < count; i++)
    {
        status = DIGI_CALLOC((void **) ppCur, 1, sizeof(tls13PSKList));
        if (OK != status)
        {
            goto exit;
        }

        sprintf((char *) pPskFile, "client%d.psk", i);

        status = DIGICERT_readFile(
            (char *) pPskFile, &((*ppCur)->pPskData), &((*ppCur)->pskDataLen));
        if (OK != status)
        {
            goto exit;
        }

        ppCur = &((*ppCur)->pNextPSK);
    }

    g_pTls13PSKList = pHead;

    *pFreeMemory = FALSE;

    *ppPSKs = pHead;
    *pNumPSKs = i;
    *selectedIndex = 0;
exit:
    return status;
}

static sbyte4 SSL_CLI_Tls13_SavePSKCb(sbyte4 connectionIndtance, sbyte* pServerInfo,
                                      ubyte4 serverInfoLen, void *pUserData,
                                      void *pPsk, ubyte4 pskLen)
{
    MSTATUS status = OK;
    ubyte pPskFile[256] = { 0 };

    sprintf((char *) pPskFile, "client%d.psk", count);

    status = DIGICERT_writeFile((char *) pPskFile, pPsk, pskLen);
    if (OK != status)
    {
        goto exit;
    }

    count++;
  /*
    g_pServerInfo = pServerInfo;
    g_pUserData   = pUserData;
    count++;
  */
exit:

    return status;
}

int SSL_CLI_Tls13_0rttTest(ubyte4 hint, const CipherDesc* pCipherDesc,
                          const sbyte* serverIpAddress, ubyte2 serverPort,
                          const char* resourceName, int rootCertIndex,
                          const char* serverCN, ServerType serverType,
                          sbyte4 sslProtocol, certStorePtr certStore,
                          ubyte requestTicket, ubyte pskMode)
{
    /* connect to the host specified and set a simple GET */
    sbyte4          connectionInstance;
    TCP_SOCKET      mySocket;
    ubyte           sessionIdLen;
    ubyte           sessionId[32 /* SSL_MAXSESSIONIDSIZE*/];
    ubyte           masterSecret[48 /*SSL_MASTERSECRETSIZE */];
    ubyte           buffer[8192];
    sbyte4          bufferSize;
    const char*     versionStr = 0;
    const char*     cipherName = (pCipherDesc) ? pCipherDesc->cipherName : 0;
    MSTATUS         status;
    int             retVal = 0;

    /* retrieve the resource */
    retVal += UNITTEST_STATUS(hint, TCP_CONNECT(&mySocket,
                                                (sbyte*)serverIpAddress,
                                                serverPort));
    if (retVal) goto exit;

    retVal += UNITTEST_STATUS(hint,
                              connectionInstance = SSL_connect(mySocket,
                                                               0, NULL,
                                                               NULL,
                                                               (sbyte*) serverCN,
                                                               certStore));
    if (retVal) goto exit_close;

    /* pass in negative SSL version for protocol not to set the protocol */
    retVal += UNITTEST_STATUS(hint, SSL_ioctl( connectionInstance,
                                               SSL_SET_VERSION,
                                               (void*) sslProtocol));
    switch (sslProtocol)
    {
        case TLS13_MINORVERSION:
            versionStr = "TLSv1.3";
            break;
        default:
            versionStr = "an unknown version of SSL/TLS";
            break;
    }

    if (sslProtocol != SSL3_MINORVERSION)
    {
        /* set the server name indication */
        retVal += UNITTEST_STATUS(hint,
                                  SSL_setServerNameIndication(connectionInstance,
                                                              serverCN));
    }

    if (pCipherDesc)
    {
        retVal += UNITTEST_STATUS(hint, SSL_enableCiphers( connectionInstance,
                                                           &pCipherDesc->cipherId, 1));
    }

    /* ------------------- psk test case 1--------------------------*/
    retVal += UNITTEST_STATUS(hint, SSL_ioctl(connectionInstance,
                                              SSL_REQUEST_SESSION_TICKET, &requestTicket));

    retVal += UNITTEST_STATUS(hint, SSL_ioctl(connectionInstance,
                                              SSL_PSK_KEY_EXCHANGE_MODE, &pskMode));

    retVal += UNITTEST_STATUS(hint, SSL_setClientSavePSKCallback(connectionInstance, &SSL_CLI_Tls13_SavePSKCb));

    retVal += UNITTEST_STATUS(hint, SSL_CLIENT_setRetrievePSKCallback(connectionInstance, &SSL_CLI_Tls13_RetrievePSKCb));

    if (NULL != sslc_EarlyData)
    {
        retVal += UNITTEST_STATUS(hint, SSL_setEarlyData(connectionInstance, (ubyte*)sslc_EarlyData,
                                                         DIGI_STRLEN((sbyte*)sslc_EarlyData)));
    }

    if (retVal)
    {
        goto exit_close;
    }

    retVal += UNITTEST_STATUS(hint,
                              SSL_negotiateConnection(connectionInstance));

    if (retVal)
    {
        goto exit_close;
    }

    bufferSize = sizeof(buffer);
    retVal += SSL_CLI_GetSecurePageAux(hint, connectionInstance,
                                       resourceName, (sbyte *)buffer, &bufferSize);

    switch (serverType)
    {
        case MOCANA:
            retVal += SSL_CLI_VerifyMocanaReply(hint, cipherName, resourceName,
                                                versionStr,
                                                (sbyte *)buffer, bufferSize);
            break;

        case OPENSSL:
            retVal += SSL_CLI_VerifyOpenSSLReply( hint, cipherName, versionStr,
                                                  (sbyte *)buffer, bufferSize);
            break;

        case MBEDTLS:
            retVal += SSL_CLI_VerifymbedReply( hint, cipherName, versionStr,
                                               (sbyte*) buffer, bufferSize);
            break;
    }

    exit_close:

    SSL_closeConnection(connectionInstance);

    TCP_CLOSE_SOCKET(mySocket);

    exit:

    return retVal;
}

int SSL_CLI_Tls13_PskTest(ubyte4 hint, const CipherDesc* pCipherDesc,
                         const sbyte* serverIpAddress, ubyte2 serverPort,
                         const char* resourceName, int rootCertIndex,
                         const char* serverCN, ServerType serverType,
                         sbyte4 sslProtocol, certStorePtr certStore,
                         ubyte requestTicket, ubyte pskMode)
{
    /* connect to the host specified and set a simple GET */
    sbyte4          connectionInstance;
    TCP_SOCKET      mySocket;
    ubyte           sessionIdLen;
    ubyte           sessionId[32 /* SSL_MAXSESSIONIDSIZE*/];
    ubyte           masterSecret[48 /*SSL_MASTERSECRETSIZE */];
    ubyte           buffer[8192];
    sbyte4          bufferSize;
    const char*     versionStr = 0;
    const char*     cipherName = (pCipherDesc) ? pCipherDesc->cipherName : 0;
    MSTATUS         status;
    int             retVal = 0;

    /* retrieve the resource */
    retVal += UNITTEST_STATUS(hint, TCP_CONNECT(&mySocket,
                                                (sbyte*)serverIpAddress,
                                                serverPort));
    if (retVal) goto exit;

    retVal += UNITTEST_STATUS(hint,
                              connectionInstance = SSL_connect(mySocket,
                                                               0, NULL,
                                                               NULL,
                                                               (sbyte*) serverCN,
                                                               certStore));
    if (retVal) goto exit_close;

    /* pass in negative SSL version for protocol not to set the protocol */
    retVal += UNITTEST_STATUS(hint, SSL_ioctl( connectionInstance,
                                               SSL_SET_VERSION,
                                               (void*) sslProtocol));
    switch (sslProtocol)
    {
        case TLS13_MINORVERSION:
            versionStr = "TLSv1.3";
            break;
        default:
            versionStr = "an unknown version of SSL/TLS";
            break;
    }

    if (sslProtocol != SSL3_MINORVERSION)
    {
        /* set the server name indication */
        retVal += UNITTEST_STATUS(hint,
                                  SSL_setServerNameIndication(connectionInstance,
                                                              serverCN));
    }

    if (pCipherDesc)
    {
        retVal += UNITTEST_STATUS(hint, SSL_enableCiphers( connectionInstance,
                                                           &pCipherDesc->cipherId, 1));
    }

    /* ------------------- psk test case 1--------------------------*/
    retVal += UNITTEST_STATUS(hint, SSL_ioctl(connectionInstance,
                              SSL_REQUEST_SESSION_TICKET, &requestTicket));

    retVal += UNITTEST_STATUS(hint, SSL_ioctl(connectionInstance,
                              SSL_PSK_KEY_EXCHANGE_MODE, &pskMode));

    retVal += UNITTEST_STATUS(hint, SSL_setClientSavePSKCallback(connectionInstance, &SSL_CLI_Tls13_SavePSKCb));

    retVal += UNITTEST_STATUS(hint, SSL_CLIENT_setRetrievePSKCallback(connectionInstance, &SSL_CLI_Tls13_RetrievePSKCb));

    if (retVal)
    {
        goto exit_close;
    }

    retVal += UNITTEST_STATUS(hint,
                              SSL_negotiateConnection(connectionInstance));

/*    if (retVal)
    {
        goto exit_close;
    }*/

    bufferSize = sizeof(buffer);
    retVal += SSL_CLI_GetSecurePageAux(hint, connectionInstance,
                                       resourceName, (sbyte *)buffer, &bufferSize);

    switch (serverType)
    {
        case MOCANA:
            retVal += SSL_CLI_VerifyMocanaReply(hint, cipherName, resourceName,
                                                versionStr,
                                                (sbyte *)buffer, bufferSize);
            break;

        case OPENSSL:
            retVal += SSL_CLI_VerifyOpenSSLReply( hint, cipherName, versionStr,
                                                  (sbyte *)buffer, bufferSize);
            break;

        case MBEDTLS:
            retVal += SSL_CLI_VerifymbedReply( hint, cipherName, versionStr,
                                               (sbyte*) buffer, bufferSize);
            break;
    }

exit_close:

    SSL_closeConnection(connectionInstance);

    TCP_CLOSE_SOCKET( mySocket);

    exit:

    return retVal;
}

int SSL_CLI_Tls13_PskTestCases(ubyte4 hint, const CipherDesc* pCipherDesc,
                               const sbyte* serverIpAddress, ubyte2 serverPort,
                               const char* resourceName, int rootCertIndex,
                               const char* serverCN, ServerType serverType,
                               sbyte4 sslProtocol, certStorePtr certStore)
{
    int retVal = 0;
    ubyte requestTicket = 1;
    ubyte pskMode = 1;

    /* test case 1: request 1 session ticket  */
    free_session_list();
    printf("----------------- PSK Test First Connection -------------\n");
    retVal += SSL_CLI_Tls13_PskTest(hint, pCipherDesc, serverIpAddress, serverPort,
                                    resourceName, rootCertIndex, serverCN,
                                    serverType, sslProtocol, certStore, requestTicket, pskMode);

    RTOS_sleepMS(100); /* sleep for a second */

    printf("----------------- PSK Test Second Connection -------------\n");
    /* make connection using 1 session ticket */
    retVal += SSL_CLI_Tls13_PskTest(hint, pCipherDesc, serverIpAddress, serverPort,
                                    resourceName, rootCertIndex, serverCN,
                                    serverType, sslProtocol, certStore, requestTicket, pskMode);
#if 0
    /* test case 2: request 2 session tickets */
    requestTicket = 2;
    retVal += SSL_CLI_SendSupportedCmd(CIPHER_HINT(0x900, 0),
                                     serverIpAddress, serverPort,
                                     resourceName,
                                     serverCN, certStore, serverNumTicketsConfigCmd,
                                     requestTicket);

    pskMode = 1;
    free_session_list();
    retVal += SSL_CLI_Tls13_PskTest(hint, pCipherDesc, serverIpAddress, serverPort,
                                    resourceName, rootCertIndex, serverCN,
                                    serverType, sslProtocol, certStore, requestTicket, pskMode);

    /* make connection using 1 session tickets */
    retVal += SSL_CLI_Tls13_PskTest(hint, pCipherDesc, serverIpAddress, serverPort,
                                    resourceName, rootCertIndex, serverCN,
                                    serverType, sslProtocol, certStore, requestTicket, pskMode);

    /* test case 3: request 3 session tickets */
    requestTicket = 3;
    pskMode = 1;
    free_session_list();
    retVal += SSL_CLI_Tls13_PskTest(hint, pCipherDesc, serverIpAddress, serverPort,
                                    resourceName, rootCertIndex, serverCN,
                                    serverType, sslProtocol, certStore, requestTicket, pskMode);

    /* make connection using 1 session tickets */
    testPskCounter = 0; /* send all 3 session tickets */
    retVal += SSL_CLI_Tls13_PskTest(hint, pCipherDesc, serverIpAddress, serverPort,
                                    resourceName, rootCertIndex, serverCN,
                                    serverType, sslProtocol, certStore, requestTicket, pskMode);

    testPskCounter = 1; /* send 2 session tickets (it skips the fist session ticket and sends the last one*/
    retVal += SSL_CLI_Tls13_PskTest(hint, pCipherDesc, serverIpAddress, serverPort,
                                    resourceName, rootCertIndex, serverCN,
                                    serverType, sslProtocol, certStore, requestTicket, pskMode);

    testPskCounter = 2; /* send 1 session ticket( it sends the last one) */
    retVal += SSL_CLI_Tls13_PskTest(hint, pCipherDesc, serverIpAddress, serverPort,
                                    resourceName, rootCertIndex, serverCN,
                                    serverType, sslProtocol, certStore, requestTicket, pskMode);
#endif
    return  retVal;
}

/*------------------------------------------------------------------*/
static void
setStringParameter(char** param, char* value)
{
    *param = MALLOC((DIGI_STRLEN((const sbyte *)value))+1);
    if (NULL == *param)
        return;
    (void) DIGI_MEMCPY(*param, value, DIGI_STRLEN((const sbyte *)value));
    (*param)[DIGI_STRLEN((const sbyte *)value)] = '\0';
}

int SSL_CLI_Tls13_0rttTestCases(ubyte4 hint, const CipherDesc* pCipherDesc,
                               const sbyte* serverIpAddress, ubyte2 serverPort,
                               const char* resourceName, int rootCertIndex,
                               const char* serverCN, ServerType serverType,
                               sbyte4 sslProtocol, certStorePtr certStore)
{
    int retVal = 0;
    ubyte requestTicket = 1;
    ubyte pskMode = 1;

    free_session_list();

    /* test case 1: request 1 session ticket  */
    printf("----------------- 0RTT Test First Connection -------------\n");
    retVal += SSL_CLI_Tls13_0rttTest(hint, pCipherDesc, serverIpAddress, serverPort,
                                    resourceName, rootCertIndex, serverCN,
                                    serverType, sslProtocol, certStore, requestTicket, pskMode);

    RTOS_sleepMS(100); /* sleep for a second */

    /* make connection using 1 session ticket */
    /* s_server does not respond to https requests; This variable ignores the SSL_recv */

    printf("----------------- 0RTT Test Second Connection -------------\n");
    setStringParameter(&sslc_EarlyData, "sending 0rtt data");
    retVal += SSL_CLI_Tls13_0rttTest(hint, pCipherDesc, serverIpAddress, serverPort,
                                    resourceName, rootCertIndex, serverCN,
                                    serverType, sslProtocol, certStore, requestTicket, pskMode);
}


/*------------------------------------------------------------------------*/

int SSL_CLI_helloRetryTestPage(ubyte4 hint, const CipherDesc* pCipherDesc,
                               const sbyte* serverIpAddress, ubyte2 serverPort,
                               const char* resourceName, int rootCertIndex,
                               const char* serverCN, ServerType serverType,
                               sbyte4 sslProtocol, enum tlsExtNamedCurves curve,
                               ubyte2 *pSupportedList, ubyte4 SupportedListLength,
                               certStorePtr certStore)
{
    /* connect to the host specified and set a simple GET */
    sbyte4          connectionInstance;
    TCP_SOCKET      mySocket;
    MSTATUS         status;
    int             retVal = 0;
    ubyte           buffer[8192];
    sbyte4          bufferSize;
    const char*     versionStr = 0;
    const char*     cipherName = (pCipherDesc) ? pCipherDesc->cipherName : 0;
    ubyte2          cipherId = (pCipherDesc) ? pCipherDesc->cipherId : 0;

    /* retrieve the resource */
    retVal += UNITTEST_STATUS(hint, TCP_CONNECT(&mySocket,
                                                (sbyte*)serverIpAddress,
                                                serverPort));
    if (retVal) goto exit;

    retVal += UNITTEST_STATUS(hint,
                              connectionInstance = SSL_connect(mySocket,
                                                               0, NULL,
                                                               NULL,
                                                               serverCN,
                                                               certStore));
    if (retVal) goto exit_close;

    /* set the sslProtocol if not negative */
    if ( sslProtocol >= MIN_SSL_MINORVERSION)
    {

        retVal += UNITTEST_STATUS(hint, SSL_ioctl( connectionInstance,
                                                   SSL_SET_VERSION,
                                                   (void*) sslProtocol));
    }

    if (sslProtocol > SSL3_MINORVERSION)
    {
        retVal += UNITTEST_STATUS(hint,
                                  SSL_setServerNameIndication(connectionInstance,
                                                              serverCN));
    }

    retVal += UNITTEST_STATUS(hint, SSL_enableCiphers( connectionInstance,
                                                       &cipherId, 1));

    retVal += UNITTEST_STATUS(hint, SSL_setCipherAlgorithm( connectionInstance, pSupportedList, SupportedListLength,
                                                            TLS13_supportedGroups ));

    if (retVal)
    {
        goto exit_close;
    }

#if 0 == MIN_SSL_MINORVERSION

    if (MOCANA == serverType && 0 == sslProtocol )
    {
        /* make sure the server rejects a SSLv3.0 connection attempt */
        retVal += UNITTEST_TRUE(hint,
                                OK != SSL_negotiateConnection(connectionInstance));
        goto exit_close; /* always leave then */
    }

#endif

    status = (MSTATUS) SSL_negotiateConnection(connectionInstance);


    bufferSize = sizeof(buffer);
    retVal += SSL_CLI_GetSecurePageAux(hint, connectionInstance,
                                       resourceName, (sbyte *)buffer, &bufferSize);

    switch (serverType)
    {
        case MOCANA:
            retVal += SSL_CLI_VerifyMocanaReply(hint, cipherName, resourceName,
                                                versionStr,
                                                (sbyte *)buffer, bufferSize);
            break;

        case OPENSSL:
            retVal += SSL_CLI_VerifyOpenSSLReply( hint, cipherName, versionStr,
                                                  (sbyte *)buffer, bufferSize);
            break;

        case MBEDTLS:
            retVal += SSL_CLI_VerifymbedReply( hint, cipherName, versionStr,
                                               (sbyte*) buffer, bufferSize);
            break;
    }

exit_close:

    SSL_closeConnection(connectionInstance);

    TCP_CLOSE_SOCKET( mySocket);

    exit:

    return retVal;
}

/*------------------------------------------------------------------------*/

int SSL_CLI_SignatureAlgorthimTest(ubyte4 hint, ubyte2 cipherId,
                         const sbyte* serverIpAddress, ubyte2 serverPort,
                         const char* resourceName, int rootCertIndex,
                         const char* serverCN, ServerType serverType,
                         sbyte4 sslProtocol, enum tlsExtNamedCurves curve, ubyte2 signatureAlgos,
                         certStorePtr certStore)
{
    /* connect to the host specified and set a simple GET */
    sbyte4          connectionInstance;
    TCP_SOCKET      mySocket;
    MSTATUS         status;
    int             retVal = 0;

    /* retrieve the resource */
    retVal += UNITTEST_STATUS(hint, TCP_CONNECT(&mySocket,
                                                (sbyte*)serverIpAddress,
                                                serverPort));
    if (retVal) goto exit;

    retVal += UNITTEST_STATUS(hint,
                              connectionInstance = SSL_connect(mySocket,
                                                               0, NULL,
                                                               NULL,
                                                               serverCN,
                                                               certStore));
    if (retVal) goto exit_close;

    /* set the sslProtocol if not negative */
    if ( sslProtocol >= MIN_SSL_MINORVERSION)
    {

        retVal += UNITTEST_STATUS(hint, SSL_ioctl( connectionInstance,
                                                   SSL_SET_VERSION,
                                                   (void*) sslProtocol));
    }

    if (sslProtocol > SSL3_MINORVERSION)
    {
        retVal += UNITTEST_STATUS(hint,
                                  SSL_setServerNameIndication(connectionInstance,
                                                              serverCN));
    }


    retVal += UNITTEST_STATUS(hint, SSL_enableCiphers( connectionInstance,
                                                       &cipherId, 1));
/*
    retVal += UNITTEST_STATUS(hint, SSL_enableECCCurves( connectionInstance,
                                                         &curve, 1));
*/
    retVal += UNITTEST_STATUS(hint, SSL_setCipherAlgorithm( connectionInstance, &signatureAlgos, 1,
                                    TLS13_signatureAlgorithms ));

    retVal += UNITTEST_STATUS(hint, SSL_setCipherAlgorithm(connectionInstance, &curve, 1,
                                                           TLS13_supportedGroups));

    if (retVal)
    {
        goto exit_close;
    }

#if 0 == MIN_SSL_MINORVERSION

    if (MOCANA == serverType && 0 == sslProtocol )
    {
        /* make sure the server rejects a SSLv3.0 connection attempt */
        retVal += UNITTEST_TRUE(hint,
                                OK != SSL_negotiateConnection(connectionInstance));
        goto exit_close; /* always leave then */
    }

#endif

    status = (MSTATUS) SSL_negotiateConnection(connectionInstance);

exit_close:

    SSL_closeConnection(connectionInstance);

    TCP_CLOSE_SOCKET( mySocket);

exit:

    return retVal;
}


/*------------------------------------------------------------------------*/

int SSL_CLI_VerifyUnableToConnectSignauterAlgoTest(ubyte4 hint, const CipherDesc* pCipherDesc,
                                    const sbyte* serverIpAddress,
                                    ubyte2 serverPort, const char* serverCN,
                                    ubyte2 *pSupportedList, ubyte4 SupportedListLength,
                                    sbyte4 error,
                                    certStorePtr certStore)
{
    TCP_SOCKET  mySocket = 0;
    sbyte4      connectionInstance  = 0;
    MSTATUS     status              = OK;
    int         retVal           = 0;

    retVal += UNITTEST_STATUS(hint, TCP_CONNECT(&mySocket,
                                                (sbyte*)serverIpAddress,
                                                serverPort));
    if (retVal) goto exit;


    retVal += UNITTEST_STATUS(hint, connectionInstance = SSL_connect(mySocket, 0,
                                                                     NULL, NULL,
                                                                     serverCN,
                                                                     certStore));
    if (0 != retVal)
        goto exit;

    if (pCipherDesc)
    {
        retVal += UNITTEST_STATUS(hint, SSL_enableCiphers( connectionInstance,
                                                           &pCipherDesc->cipherId, 1));
    }

    retVal += UNITTEST_STATUS(hint, SSL_setCipherAlgorithm( connectionInstance, pSupportedList, SupportedListLength,
                                                            TLS13_supportedGroups ));

    status = (MSTATUS) SSL_negotiateConnection(connectionInstance);

    retVal += UNITTEST_INT( hint, status, error);

    exit:
    SSL_closeConnection(connectionInstance);
    TCP_CLOSE_SOCKET( mySocket);

    return retVal;
}


/*------------------------------------------------------------------------*/
#if 1
int SSL_CLI_helloRetryTest(ubyte4 hint, const CipherDesc* pCipherDesc,
                               const sbyte* serverIpAddress, ubyte2 serverPort,
                               const char* resourceName, int rootCertIndex,
                               const char* serverCN, ServerType serverType,
                               sbyte4 sslProtocol, certStorePtr certStore)
{
    /* hint 0x0900 - 0x09F0 */
    int retVal = 0;
    int i;
    MSTATUS status;
    TCP_SOCKET mySocket;
    ubyte2 pCertIndex[]     = { kECC256CertIdx, kECC256CertIdx, kECC384CertIdx,
                                kECC521CertIdx, kECC256CertIdx };
    ubyte2 pSupportedList[] = { tlsExtNamedCurves_secp256r1, tlsExtNamedCurves_secp384r1,
                                tlsExtNamedCurves_secp521r1 };

    /* test internal server to verify SSL_SET_VERSION works server on port portNo */
    for (i = 0; i < 20; ++i)
    {
        status = TCP_CONNECT(&mySocket, (sbyte*) serverIpAddress, serverPort);
        TCP_CLOSE_SOCKET(mySocket);
        if ( OK == status)
        {
            break;
        }
        RTOS_sleepMS(1000); /* sleep for a second */
    }
    retVal += UNITTEST_TRUE(0, i < 20);
    if ( retVal) goto exit;

    /* tests case 1 : */
     retVal += SSL_CLI_SendSupportedCmd(CIPHER_HINT(0x900, 0),
                                     serverIpAddress, serverPort,
                                     resourceName,
                                     serverCN, certStore, serverSupportedConfigCmd,
                                     tlsExtNamedCurves_secp521r1);

    retVal += SSL_CLI_helloRetryTestPage(hint, pCipherDesc,
                                         serverIpAddress,  serverPort,
                                         resourceName,  rootCertIndex,
                                         serverCN,  serverType,
                                         sslProtocol,  tlsExtNamedCurves_secp521r1,
                                         pSupportedList, 3, certStore);
#if 0
    retVal += SSL_CLI_helloRetryTestPage(hint,  cipherId,
                                         serverIpAddress,  serverPort,
                                         resourceName,  rootCertIndex,
                                         serverCN,  serverType,
                                         sslProtocol,  tlsExtNamedCurves_secp521r1,
                                         &pSupportedList[1], 2, certStore);

    retVal += SSL_CLI_VerifyUnableToConnectSignauterAlgoTest(CIPHER_HINT(0x900, 0), NULL,
                                              serverIpAddress, serverPort,
                                              resourceName,
                                              pSupportedList, 2,
                                              ERR_TCP_SOCKET_CLOSED,
                                              certStore);

    /* reset the signature */
    retVal += SSL_CLI_SendSupportedCmd(CIPHER_HINT(0x900, 0),
                                       serverIpAddress, serverPort,
                                       resourceName,
                                       serverCN, certStore, serverSupportedConfigCmd, 0xFFFF);
#endif
exit:

    return retVal;
}
#endif


/*------------------------------------------------------------------------*/
int SSL_CLI_TLS13_Test(const sbyte* pIpAddress4or6,
                                ubyte2 portNo,
                                const char* domainName,
                                char* resourceName )
{

    /* hint 0x1000 - 0x16F0 */
    int retVal = 0;
    int i, j = 0;
    MSTATUS status;
    TCP_SOCKET mySocket;
    char *pEnv = NULL;
    ubyte opensslTest = 0;
    ubyte2 hrrPort = portNo;

    pEnv = getenv("ENABLE_OPENSSL_INTEROPERABILITY_TEST");
    if (pEnv != NULL)
    {
        if (1 == atoi(pEnv))
           opensslTest = 1;
    }

    ubyte2 pCertIndex[] = {kECC256CertIdx, kECC384CertIdx,
                           kECC521CertIdx, kECC256CertIdx,
                           Ed25519CertIdx, Ed448CertIdx,
                           kECC256CertIdx, kECC256CertIdx,
                           kECC256CertIdx, kECC256CertIdx,
                           kECC256CertIdx,
#ifdef __ENABLE_DIGICERT_PQC__
                           kQS256Mldsa44CertIdx, kQS256Mldsa44CertIdx,
                           kQS256Mldsa44CertIdx, kQS256Mldsa44CertIdx,
                           kQS256Mldsa44CertIdx,
                           kQS384Mldsa65CertIdx, kQS384Mldsa65CertIdx,
                           kQS384Mldsa65CertIdx, kQS384Mldsa65CertIdx
#endif
    };

    ubyte2 pSignatureAlgos[] = {ecdsa_secp256r1_sha256, ecdsa_secp256r1_sha256,
                                ecdsa_secp256r1_sha256, ecdsa_secp256r1_sha256,
                                ecdsa_secp256r1_sha256, ecdsa_secp256r1_sha256,
                                ecdsa_secp256r1_sha256, ecdsa_secp256r1_sha256,
                                ecdsa_secp256r1_sha256, ecdsa_secp256r1_sha256,
                                ecdsa_secp256r1_sha256,
#ifdef __ENABLE_DIGICERT_PQC__
                                hybrid_p256_mldsa44, hybrid_p256_fndsa512,
                                hybrid_p256_mldsa44, hybrid_p256_fndsa512,
                                hybrid_p256_mldsa44,
                                hybrid_p384_mldsa65,
                                hybrid_p384_mldsa65,
                                hybrid_p521_fndsa1024, hybrid_p521_fndsa1024,
                                hybrid_p521_fndsa1024
#endif
    };

    ubyte2 pNamedCurve[] = {tlsExtNamedCurves_secp256r1, tlsExtNamedCurves_secp384r1,
                            tlsExtNamedCurves_secp521r1, tlsExtNamedCurves_secp256r1,
                            tlsExtNamedCurves_x25519, tlsExtNamedCurves_x448,
                            tlsExtNamedCurves_ffdhe2048, tlsExtNamedCurves_ffdhe3072,
                            tlsExtNamedCurves_ffdhe4096, tlsExtNamedCurves_ffdhe6144,
                            tlsExtNamedCurves_ffdhe8192,
#ifdef __ENABLE_DIGICERT_PQC__
                            tlsExtHybrid_p256_mlkem512,
                            tlsExtHybrid_p384_mlkem768,
                            tlsExtHybrid_p521_mlkem1024
#endif
    };

    for (i = 0; i < 20; ++i)
    {
        status = TCP_CONNECT(&mySocket, (sbyte*) pIpAddress4or6, portNo);

        TCP_CLOSE_SOCKET(mySocket);
        if ( OK == status)
        {
            break;
        }
        RTOS_sleepMS(1000); /* sleep for a second */
    }

    retVal += UNITTEST_TRUE(0, i < 20);
    if ( retVal) goto exit;

    /* test internal tls13 server that request key update = 1490 */
    for (i = COUNTOF(gtls13CipherDescs) - 1; i < COUNTOF(gtls13CipherDescs); ++i)
    {
        int rootCertIndex = kRSACertIdx;

        if(TLS13_MINORVERSION == gtls13CipherDescs[i].minSSLVer)
        {

            for (int k = 0; k < 11; k ++)
            {
                retVal += SSL_CLI_SignatureAlgorthimTest(CIPHER_HINT(0x1000+j,i),
                                                        gtls13CipherDescs[i].cipherId,
                                                        pIpAddress4or6, portNo, resourceName,
                                                        pCertIndex[k % 4],
                                                        domainName, MOCANA, TLS13_MINORVERSION,
                                                        pNamedCurve[k], pSignatureAlgos[k],
                                                        pECCSslCertStore);
            }
            /* switch to a ECC client certificate */
            retVal += SSL_CLI_Tls13_KeyUpdateTest(CIPHER_HINT(0x1010+j,i),
                                                  gtls13CipherDescs + i,
                                                  pIpAddress4or6,
                                                  portNo, resourceName,
                                                  rootCertIndex, domainName, MOCANA, TLS13_MINORVERSION,
                                                  pECCSslCertStore);
            retVal += SSL_CLI_Tls13_PostAuthTest(CIPHER_HINT(0x1000+j,i),
                                           gtls13CipherDescs + i,
                                           pIpAddress4or6,
                                           portNo, resourceName,
                                           rootCertIndex, domainName, MOCANA, TLS13_MINORVERSION,
                                           pECCSslCertStore);

            retVal += SSL_CLI_Tls13_PskTestCases(CIPHER_HINT(0x1000+j,i),
                                                 gtls13CipherDescs + i,
                                                 pIpAddress4or6,
                                                 portNo, resourceName,
                                                 rootCertIndex, domainName, MOCANA, TLS13_MINORVERSION,
                                                 pECCSslCertStore);

            /* When testing against s_server with -early_data option, -www is not supported;
             * We we get stay in SSL-recv loop waiting for a http response.
             * Needs more development, commenting this for now
             */
            if (0 == opensslTest)
            {
                retVal += SSL_CLI_Tls13_0rttTestCases(CIPHER_HINT(0x1000+j,i),
                                                     gtls13CipherDescs + i,
                                                     pIpAddress4or6,
                                                     portNo, resourceName,
                                                     rootCertIndex, domainName, MOCANA, TLS13_MINORVERSION,
                                                     pECCSslCertStore);
            }

            /* When running against openssl s_server, we set the server to support a group p=other than the default keyshare group;
             * Eg - default key share group sent by this client is prime256, s_server only support secp384;
             * This triggers HRR flow.
             * When testing against NanoSSL test monkey server, this is achieved by commands sent to server;
             * Command format is internal, so for openssl testing a new s_server is spawned listening on a differnt port
             */
            if (1 == opensslTest)
            {
                hrrPort += 1;
            }

            retVal += SSL_CLI_helloRetryTest(CIPHER_HINT(0x1000+j,i),
                                                     gtls13CipherDescs + i,
                                                     pIpAddress4or6, hrrPort, resourceName,
                                                     pCertIndex[0],
                                                     domainName, MOCANA, TLS13_MINORVERSION,
                                                     pECCSslCertStore);

        }
    }
exit:

    return retVal;
}

/*------------------------------------------------------------------------*/

#if defined(__SSLCLIENT_OCSP_CLIENT__)
static sbyte4
myTls13CertStatusCallback(sbyte4 connectionInstance, const ubyte *pCert,
                ubyte4 certLen, ubyte *pOcspResp, ubyte4 ocspRespLen, sbyte4 ocspStatus)
{
    MSTATUS *pOcspStatus = NULL;

    printf("\nOCSP Stapling status: %d\n", ocspStatus);


    SSL_getCookie(connectionInstance, (void **) &pOcspStatus);
    if ((NULL != pOcspStatus) && (0 != *pOcspStatus)) /* if we received a correct OCSP to leaf cert, do not throw an error for parent cert */
        *pOcspStatus = ocspStatus;

    return 0;
}

/*------------------------------------------------------------------------*/

int SSL_CLI_Tls13_OcspTest(ubyte4 hint, const sbyte* serverIpAddress,
                    ubyte2 serverPort, const char* resourceName, char* serverCN,
                    ServerType serverType, sbyte4 sslProtocol,
                    certStorePtr certStore)
{
    /* connect to the host specified and set a simple GET */
    sbyte4          connectionInstance;
    TCP_SOCKET      mySocket;
    MSTATUS         status;
    int             retVal = 0;
    int         i = 0;
    int         count = 0;
    ubyte2      pCipherIdList[COUNTOF(gtls13CipherDescs)];
    MSTATUS         ocspStatus = ERR_OCSP;

    char *pTrustedResponderCertsPath[] = {
        NULL
    };
    ubyte4 trustedRespondercertCount = 0;

    /* retrieve the resource */
    retVal += UNITTEST_STATUS(hint, TCP_CONNECT(&mySocket,
                                                (sbyte*)serverIpAddress,
                                                serverPort));
    if (retVal) goto exit;

    retVal += UNITTEST_STATUS(hint,
                              connectionInstance = SSL_connect(mySocket,
                                                               0, NULL,
                                                               NULL,
                                                               serverCN,
                                                               certStore));
    if (retVal) goto exit_close;


    /* Set the max version to TLS 1.3 */
    retVal += UNITTEST_STATUS(hint, SSL_setMaxProtoVersion(TLS13_MINORVERSION));

    /* set the sslProtocol if not negative */
    if ( sslProtocol >= MIN_SSL_MINORVERSION)
    {

        retVal += UNITTEST_STATUS(hint, SSL_ioctl( connectionInstance,
                                                   SSL_SET_VERSION,
                                                   (void*) sslProtocol));
        if (retVal) goto exit_close;
    }

    if (sslProtocol > SSL3_MINORVERSION)
    {
        retVal += UNITTEST_STATUS(hint,
                                  SSL_setServerNameIndication(connectionInstance,
                                                              serverCN));
        if (retVal) goto exit_close;
    }

    memset(pCipherIdList, 0x00, COUNTOF(gtls13CipherDescs));

    for (i = 0; i < COUNTOF(gtls13CipherDescs); ++i)
    {
        const char* cipherName = gtls13CipherDescs[i].cipherName;
        /* exclude the preshared keys and SRP ones */
        if (!strstr(cipherName, "_PSK_") &&
            !strstr(cipherName, "_SRP_"))
        {
            pCipherIdList[count] = gtls13CipherDescs[i].cipherId;
            count++;
        }
    }

    retVal += UNITTEST_STATUS(0, SSL_enableCiphers(connectionInstance, pCipherIdList, count));
    if (retVal) goto exit;

    /* Request OCSP response from server */
    retVal += UNITTEST_STATUS(hint, status = (MSTATUS) SSL_setCertifcateStatusRequestExtensions(
        connectionInstance, pTrustedResponderCertsPath, trustedRespondercertCount, NULL, 0));
    if (retVal) goto exit_close;

    retVal += UNITTEST_STATUS(hint, status = (MSTATUS) SSL_setCookie(connectionInstance, (void *) &ocspStatus));
    if (retVal) goto exit_close;

    retVal += UNITTEST_STATUS(hint, status = (MSTATUS) SSL_negotiateConnection(connectionInstance));
    if (retVal) goto exit_close;

    /* Check OCSP status */
    retVal += UNITTEST_STATUS(hint, ocspStatus);

exit_close:

    SSL_closeConnection(connectionInstance);

    TCP_CLOSE_SOCKET( mySocket);

exit:

    return retVal;
}

/*------------------------------------------------------------------------*/

int SSL_CLI_TLS13_OCSP_Test(const sbyte* pIpAddress4or6,
                                ubyte2 portNo,
                                const char* domainName,
                                char* resourceName )
{
    MSTATUS status;
    TCP_SOCKET mySocket;
    int i, retVal = 0;

    status = TCP_CONNECT(&mySocket, (sbyte*) pIpAddress4or6, portNo);
    TCP_CLOSE_SOCKET(mySocket);
    retVal += UNITTEST_STATUS(__MOC_LINE__, retVal);
    if (OK != status)
    {
        printf(
            "TCP connection to OCSP server %s on port %d failed with "
            "status = %d. Skipping TLS 1.3 OCSP tests...\n", pIpAddress4or6,
            portNo, status);
        goto exit;
    }

    /* Set callback to check for certStatus */
    SSL_sslSettings()->funcPtrSingleCertStatusCallback = myTls13CertStatusCallback;

    retVal += SSL_CLI_Tls13_OcspTest(__MOC_LINE__, pIpAddress4or6, portNo,
                                    resourceName, domainName, MOCANA,
                                    TLS13_MINORVERSION, pOCSPSslCertStore);

exit:

    SSL_sslSettings()->funcPtrCertStatusCallback = NULL;

    return retVal;
}

#endif
/*------------------------------------------------------------------------*/

int ssl_cli_tls13_test_ocsp()
{
    MSTATUS status;
    int retVal = 0;
#if defined(__SSLCLIENT_OCSP_CLIENT__)
    const char* domainName = "*.mydomain.com";
    char resourceName[20] = { 'T', 'e', 's', 't'}; /* need space at least 20 */
    sbyte pIpAddress4or6[80] = {LOOPBACK};
    ubyte2 portNum = 1490;
    char *pTLS13Env = NULL;
    ubyte runTLS13Test = 0;
    certDescriptor certDesc = {0};
    ubyte*  pLeaf = NULL;
    ubyte4  leafLen = 0;
    ubyte*  pDerKey = NULL;
    ubyte4  derKeyLen;
    ubyte*  pKeyBlob = NULL;
    ubyte4  keyBlobLen;
    AsymmetricKey asymKey = { 0 };
    SizedBuffer certificates[2];
    ubyte4 numCertificate;

    CRYPTO_initAsymmetricKey(&asymKey);

    pTLS13Env = getenv("ENABLE_TLS13_TESTS");
    if (pTLS13Env != NULL)
    {
        runTLS13Test = atoi(pTLS13Env);
    }

    if (1 == runTLS13Test)
    {
        retVal += UNITTEST_STATUS( 0, status = (MSTATUS) DIGICERT_initDigicert());
        if (OK > status)  goto exit;

        retVal += UNITTEST_STATUS(0, status = (MSTATUS) SSL_init(0, 5));
        if (OK > status)  goto exit;

        UNITTEST_STATUS_GOTO(0, CERT_STORE_createStore(&pOCSPSslCertStore),
                            retVal, exit);
        UNITTEST_STATUS_GOTO(0, DIGICERT_readFile("../testaux/ocsp_test_certs/RSAChild1.der",
                                                &pLeaf,
                                                &leafLen),
                            retVal, exit);
        UNITTEST_STATUS_GOTO(0, DIGICERT_readFile("../testaux/ocsp_test_certs/RSAChild1Key.pem",
                                                &pDerKey,
                                                &derKeyLen),
                            retVal, exit);
        UNITTEST_STATUS_GOTO(0, DIGICERT_readFile("../testaux/ocsp_test_certs/RSACA.der",
                                                &certDesc.pCertificate,
                                                &certDesc.certLength),
                            retVal, exit);

        UNITTEST_STATUS_GOTO(0, CERT_STORE_addTrustPoint(pOCSPSslCertStore,
                                                        certDesc.pCertificate,
                                                        certDesc.certLength),
                            retVal, exit);
        FREE(certDesc.pCertificate); certDesc.pCertificate = 0;

        UNITTEST_STATUS_GOTO(0, CRYPTO_deserializeAsymKey(pDerKey, derKeyLen, NULL, &asymKey), retVal, exit);

        UNITTEST_STATUS_GOTO(0, CRYPTO_serializeAsymKey(&asymKey, mocanaBlobVersion2, &pKeyBlob, &keyBlobLen), retVal, exit);

        certificates[0].data = pLeaf;
        certificates[0].length = leafLen;
        numCertificate = 1;

        UNITTEST_STATUS_GOTO(0, CERT_STORE_addIdentityWithCertificateChain(pOCSPSslCertStore, certificates, numCertificate, pKeyBlob, keyBlobLen), retVal, exit);

        /******* 1443-1449: Digicert server ports *****************/
        /******* 1450-1459: OpenSSL server ports ****************/
        /******* 1460-1469: Digicert server ports *****************/
        /******* 1470-1479: mbedTLS server ports ****************/
        /******* 1480-1489: OpenSSL server ports ****************/
        /******* 1490-1490: Digicert tls13 server ports *****************/

#ifndef __ENABLE_HARDWARE_ACCEL_CRYPTO__

        /* 1467: tls13 OCSP feature */
        retVal += SSL_CLI_TLS13_OCSP_Test(pIpAddress4or6, 1467,
                                     domainName, resourceName);
#endif

        if (0 == retVal)
        {
            printf("OCSP tests passed!\n");
        }
        else
        {
            printf("OCSP tests failed!\n");
        }

    exit:
        CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

        DIGI_FREE((void **) &pLeaf);
        DIGI_FREE((void **) &pDerKey);

        CERT_STORE_releaseStore(&pOCSPSslCertStore);

    }
    else
    {
        printf("TLS 1.3 OCSP feature testing is disabled \n");
    }
#endif
    return retVal;
}

/*------------------------------------------------------------------------*/

int ssl_cli_tls13_test_get_pages()
{
    MSTATUS status;
    int retVal = 0;
    int major, minor, revision;
    char* opensslVersionStr = 0;
    ubyte4 opensslVersionStrLen;
    const char* domainName = "ssltest.mocana.com";
    char resourceName[20] = { 'T', 'e', 's', 't'}; /* need space at least 20 */
    sbyte pIpAddress4or6[80] = {LOOPBACK};
    ubyte2 portNum = 1490;
    char *pTLS13Env = NULL;
    ubyte runTLS13Test = 0;

    pTLS13Env = getenv("ENABLE_TLS13_TESTS");
    if (pTLS13Env != NULL)
    {
        runTLS13Test = atoi(pTLS13Env);
    }

    if (1 == runTLS13Test)
    {
        retVal += UNITTEST_STATUS( 0, status = (MSTATUS) DIGICERT_initDigicert());
        if (OK > status)  goto exit;

        retVal += UNITTEST_STATUS(0, status = (MSTATUS) SSL_init(0, 5));
        if (OK > status)  goto exit;

        retVal = SSL_CLI_tls13_initUpcallsAndCertStores();
        if (retVal) goto exit;

        SSL_CLI_tls13_initializeTestResults();

        /******* 1443-1449: Digicert server ports *****************/
        /******* 1450-1459: OpenSSL server ports ****************/
        /******* 1460-1469: Digicert server ports *****************/
        /******* 1470-1479: mbedTLS server ports ****************/
        /******* 1480-1489: OpenSSL server ports ****************/
        /******* 1490-1490: Digicert tls13 server ports *****************/

#ifndef __ENABLE_HARDWARE_ACCEL_CRYPTO__

        /* 1490: tls13 features */
        retVal += SSL_CLI_TLS13_Test(pIpAddress4or6, 1490,
                                     domainName, resourceName);
#endif

        if (0 == retVal)
        {
            SSL_CLI_outputTestResults();
        }

    exit:
        CRYPTO_uninitAsymmetricKey(&mRSAMutualAuthCertKey, NULL);
        CERT_STORE_releaseStore(&pRSASslCertStore);
        CERT_STORE_releaseStore(&pECCSslCertStore);
        CERT_STORE_releaseStore(&pUnknownSslCertStore);

        FREE(opensslVersionStr);

        SSL_releaseTables();

        DIGICERT_freeDigicert();
    }
    else
    {
        printf("TLS 1.3 feature testing is disabled \n");
    }
    return retVal;
}
