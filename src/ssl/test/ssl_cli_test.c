/*
  ssl_cli.c

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
#include "../../crypto/sha1.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"
#include "../../crypto/rsa.h"
#include "../../crypto/pkcs1.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../../crypto/primefld.h"
#include "../../crypto/primeec.h"
#endif
#include "../../crypto/pubcrypto.h"
#include "../../crypto/ca_mgmt.h"
#include "../../crypto/cert_store.h"
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
#include "../../crypto_interface/cryptointerface.h"
#include "../../crypto_interface/crypto_interface_rsa.h"
#include "../../crypto_interface/crypto_interface_pkcs1.h"
#endif
#include "../../ssl/ssl.h"

#include "cipherdesc.h"

#include "../../../unit_tests/unittest.h"
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

#define CIPHER_HINT(h,i)  ( ((h) << 16) | (gCipherDescs[i].cipherId))
#define CIPHER_HINTX(h,i)  ( ((h) << 16) | (i))
#define SSL_CLI_TICKET_NAME "client.ticket"

typedef enum ServerType
{
    OPENSSL = 0,
    MOCANA = 1,
    MBEDTLS = 2,
} ServerType;

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
    kExpCertIdx,
    kOpenSSLCertIdx,
    kOpenSSLECCCertIdx,
    kOpenSSLLongChainCertIdx,
};


/* could use designated initializers if we are sure this will only be compiled
 with C99 compilers ... */
static RootCertInfo gRootCerts[] =
{
/*    {kRSACertIdx, "../testaux/RSACertCA.der", 0, 0 },
    {kECC256CertIdx, "../testaux/ECDHCert256CA.der",  0, 0 },
    {kECC384CertIdx, "../testaux/ECDHCert384CA.der",  0, 0 },
    {kECC521CertIdx, "../testaux/ECDHCert521CA.der", 0, 0 },
    {kExpCertIdx, "../testaux/ExpRSACertCA.der",  0, 0 },*/
/*    {kOpenSSLCertIdx, "../testaux/CA/cacert.der",  0, 0 },
    {kOpenSSLECCCertIdx, "../testaux/openssl_ec_cert.der",  0, 0 },
    {kOpenSSLLongChainCertIdx, "../testaux/chain2_1_of_4.der", 0, 0}, */
    {kRSACertIdx, "../testaux/ca_rsa_cert.der", 0, 0 },
    {kECC256CertIdx, "../testaux/ca_ecdsa_cert.der",  0, 0 },
    {kECC384CertIdx, "../testaux/ca_ecdsa_cert.der",  0, 0 },
    {kECC521CertIdx, "../testaux/ca_ecdsa_cert.der", 0, 0 },

};

/* gather test results */
typedef struct TestResults
{
    ubyte2 cipherId;
    unsigned int openssl;
    unsigned int mocana;
    unsigned int mbedtls;
} TestResults;

static TestResults gTestResults[COUNTOF(gCipherDescs)];
#define CHK(a,b)  ( ( ( (a) >> (b) ) & 1 ) ? 'X' : ' ')

/* special certificate used to test certificate chains */
const char* kRSABadCertChainCA = "../testaux/chain1_1_of_4.der";

sbyte* serverVersionConfigCmd = "config SSL_ioctl SSL_SET_VERSION #";
/* in ssl_cli_test_aux.c */
extern int SSL_CLI_VerifyECDHECurve(int  hint, sbyte4 connectionInstance, enum tlsExtNamedCurves curve);
extern int SSL_CLI_VerifyPublicKeyCurve(int hint, sbyte4 connectionInstance, enum tlsExtNamedCurves curve);
extern int SSL_CLI_GetLeafCertificate(int hint, sbyte4 connectionInstance,
                                      const ubyte** leafCert,
                                      ubyte4* leafCertLen);

static int g_sessionTicketTest = 0;

/*---------------------------------------------------------------------------*/

void SSL_CLI_initializeTestResults()
{
    int i;

    for (i = 0; i < COUNTOF(gCipherDescs); ++i)
    {
        gTestResults[i].cipherId = gCipherDescs[i].cipherId;
    }
}

/*---------------------------------------------------------------------------*/
#if 1
int FindCipherId(const void* key, const void* elem)
{
    ubyte2* cipherId = (ubyte2*) key;
    TestResults* el = (TestResults*) elem;

    return  (*cipherId)- el->cipherId;
}


/*---------------------------------------------------------------------------*/

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


/*---------------------------------------------------------------------------*/

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
               gCipherDescs[i].cipherName,
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

#endif
/*------------------------------------------------------------------*/

static sbyte4
SSL_CLI_mutualAuthCertVerify(sbyte4 connectionInstance, const ubyte* hash,
                             ubyte4 hashLen, ubyte* result,
                             ubyte4 resultLength)
{
    MSTATUS status;
    hwAccelDescr hwAccelCtx;
    ubyte4 version, bitLen;

    if (OK > (status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return status;

#if defined(__ENABLE_DIGICERT_TLS13__)
    status = SSL_getSSLTLSVersion(connectionInstance, &version);
    if (OK > status)
        return status;

    if (TLS13_MINORVERSION == version)
    {
        ubyte2 sigAlgo;
        ubyte hashId;
        ubyte4 saltLen;
        ubyte *pSig = NULL;
        ubyte4 sigLen;

        status = SSL_getSignatureAlgo(connectionInstance, &sigAlgo);
        if (OK != status)
            return status;

        switch (sigAlgo)
        {
            case 0x0805:
                hashId = ht_sha384;
                saltLen = SHA384_RESULT_SIZE;
                break;

            case 0x0806:
                hashId = ht_sha512;
                saltLen = SHA512_RESULT_SIZE;
                break;

            default:
                return ERR_RSA_SIGN_CALLBACK_FAIL;
        }

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
        status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux( MOC_RSA(hwAccelCtx)
            mRSAMutualAuthCertKey.key.pRSA, (ubyte4 *) &bitLen);
        if (OK != status)
        {
            return status;
        }
#else
        bitLen = VLONG_bitLength(RSA_N(mRSAMutualAuthCertKey.key.pRSA));
#endif
        if (bitLen == 1024 && saltLen == 64)
        {
            saltLen -= 2;
        }

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
            status = CRYPTO_INTERFACE_PKCS1_rsaPssSign(
                MOC_RSA(hwAccelCtx) g_pRandomContext, mRSAMutualAuthCertKey.key.pRSA,
                hashId, MOC_PKCS1_ALG_MGF1, hashId, hash, hashLen, saltLen,
                &pSig, &sigLen);
#else
            status = PKCS1_rsassaPssSign( MOC_RSA(hwAccelCtx)
                g_pRandomContext, mRSAMutualAuthCertKey.key.pRSA, hashId,
                PKCS1_MGF1_FUNC, hash, hashLen, saltLen,
                &pSig, &sigLen);
#endif
            if (OK != status)
                return status;

            if (resultLength != sigLen)
            {
                DIGI_FREE((void **) &pSig);
                return ERR_RSA_BAD_SIGNATURE;
            }

            status = DIGI_MEMCPY(result, pSig, sigLen);
            DIGI_FREE((void **) &pSig);
            if (OK != status)
                return status;
    }
    else
#endif /* __ENABLE_DIGICERT_TLS13__ */
    {
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
        status = CRYPTO_INTERFACE_RSA_signMessageAux(MOC_RSA(hwAccelCtx) mRSAMutualAuthCertKey.key.pRSA,
                             hash, hashLen, result, NULL);
#else
        status = RSA_signMessage(MOC_RSA(hwAccelCtx) mRSAMutualAuthCertKey.key.pRSA,
                             hash, hashLen, result, NULL);
#endif
    }

    UNITTEST_STATUS(0, status);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return status;
}


/*------------------------------------------------------------------*/

sbyte4 SSL_CLI_choosePSK(sbyte4 connectionInstance, ubyte *pHintPSK,
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
SSL_CLI_initUpcallsAndCertStores()
{
    int i, retVal = 0;
    certDescriptor certDesc = {0};
    SizedBuffer certificate;
    MSTATUS status = OK;
    ubyte*                  pContents = NULL;
    ubyte4                  contentsLen = 0;
    AsymmetricKey           asymKey = {0};

    /* support for PSK */
    SSL_sslSettings()->funcPtrChoosePSK = SSL_CLI_choosePSK;

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

    retVal = CRYPTO_initAsymmetricKey (&asymKey);
    if (OK != retVal)
        goto exit;

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
    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

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

    if (pContents)
    {
        FREE(pContents);
        contentsLen = 0;
    }

    /* ... then ECC */
    UNITTEST_STATUS_GOTO(0,
                         DIGICERT_readFile( "../testaux/ecc_256_signed_by_rsa_cert.der",
                                         &certDesc.pCertificate,
                                         &certDesc.certLength),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(0,
                         DIGICERT_readFile( "../testaux/ecc_256_signed_by_rsa_key.pem",
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

    UNITTEST_STATUS_GOTO(0, DIGICERT_readFile(kRSABadCertChainCA,
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


sbyte4
SSL_CLI_SendCmdAux(ubyte4 hint, sbyte4 connectionInstance,
                         const char* pageName, sbyte* buffer,sbyte4* bufferSize )
{
    ubyte4 bytesSent;
    sbyte4 pageNameLen;
    int    result = 0;

    pageNameLen = DIGI_STRLEN((sbyte*) pageName);

    /* build the request */
    DIGI_MEMCPY(buffer, pageName, pageNameLen);

    DIGI_MEMCPY(buffer + pageNameLen, " \r\n\r\n", 9);

    bytesSent = SSL_send(connectionInstance, buffer, pageNameLen + 5);

    result += UNITTEST_INT(hint, bytesSent, pageNameLen + 5);

    DIGI_MEMCPY(buffer, 0, pageNameLen);

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
        }
        *bufferSize = totalReceived;
        return 0;
    }
    return result;
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

    pageNameLen = DIGI_STRLEN((sbyte*) pageName);

    /* build the request */
    DIGI_MEMCPY(buffer, "GET /", 5);
    DIGI_MEMCPY(buffer+5, pageName, pageNameLen);
    DIGI_MEMCPY(buffer + 5 + pageNameLen,
               " HTTP/1.0\r\n\r\n",
               14);

    bytesSent = SSL_send(connectionInstance, buffer, pageNameLen + 18);

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
        }
        *bufferSize = totalReceived;
        return 0;
    }
    return result;
}


/*------------------------------------------------------------------------*/
#if 0
const sbyte* SSL_CLI_FindStr( const char* what, const sbyte* buffer,
                              sbyte4 bufferSize)
{
    sbyte4 i;
    sbyte4 whatLen;

    whatLen = DIGI_STRLEN((const sbyte*) what);
    i = 0;
    while( i < bufferSize - whatLen)
    {
        if (buffer[i] == *what)
        {
            sbyte4 cmpRes;
            DIGI_MEMCMP((ubyte *)(buffer + i), (const ubyte *)what, whatLen, &cmpRes);
            if (0 == cmpRes)
            {
                return buffer + i + whatLen;
            }
        }
        ++i;
    }
    return 0;
}
#endif

/*------------------------------------------------------------------------*/
#if 0
int SSL_CLI_VerifyOpenSSLReply(ubyte4 hint, const char* cipherName,
                               const char* versionStr,
                               const sbyte* buffer, sbyte4 bufferSize)
{
    int retVal = 0;
    const sbyte* found;


    /* look for "s_server" */
    found = SSL_CLI_FindStr("s_server", buffer, bufferSize);
    retVal += UNITTEST_VALIDPTR(hint, found);
    if (!found) goto exit;
    bufferSize -= (found - buffer);
    buffer = found;

    if (versionStr)
    {
        /* find "Protocol : <versionStr>" */
        found = SSL_CLI_FindStr("Protocol  : ", buffer, bufferSize);
        retVal += UNITTEST_VALIDPTR(hint, found);
        if (!found) goto exit;
        bufferSize -= (found - buffer);
        buffer = found;

        found = SSL_CLI_FindStr(versionStr, buffer, bufferSize);
        retVal += UNITTEST_VALIDPTR(hint, found);
        if (!found) goto exit;
    }

    /* cipher name are weird in OpenSSL: no test */

exit:

    return retVal;
}
#endif

/*------------------------------------------------------------------------*/
#if 0
int SSL_CLI_VerifyMocanaReply(ubyte4 hint, const char* cipherName,
                           const char* resourceName, const char* versionStr,
                           const sbyte* buffer, sbyte4 bufferSize)
{
    int retVal = 0;
    sbyte4 cmpRes;
    const sbyte* found;
    int isSrp = cipherName ? (strstr( cipherName, "_SRP_")) : 0;

    /* look for "<body>Congratulations!" */
    found = SSL_CLI_FindStr("<body>Congratulations!", buffer, bufferSize);
    retVal += UNITTEST_VALIDPTR(hint, found);
    if (!found) return retVal;
    bufferSize -= (found - buffer);
    buffer = found;

    if (versionStr)
    {
        /* look for the ssl protocol */
        found = SSL_CLI_FindStr(versionStr, buffer, bufferSize);
        retVal += UNITTEST_VALIDPTR(hint, found);
    }

    if ( cipherName)
    {
        /* look for "cipherName</b>" */
        found = SSL_CLI_FindStr(cipherName, buffer, bufferSize);
        retVal += UNITTEST_VALIDPTR(hint, found);
    }

    retVal += UNITTEST_TRUE( hint, (bufferSize >= 3));
    DIGI_MEMCMP((ubyte *)found, (ubyte *)"</b>", 4, &cmpRes);
    retVal += UNITTEST_TRUE( hint, (cmpRes == 0));


    /* look for "resourceName</b> */
    found = SSL_CLI_FindStr(resourceName, buffer, bufferSize);
    retVal += UNITTEST_VALIDPTR(hint, found);

    retVal += UNITTEST_TRUE( hint, (bufferSize >= 3));
    DIGI_MEMCMP((ubyte *)found, (ubyte *)"</b>", 4, &cmpRes);
    retVal += UNITTEST_TRUE( hint, (cmpRes == 0));


    if (isSrp)
    {
        /* look for identity */
        found = SSL_CLI_FindStr("<br>SRP Identity = scott</br>", buffer, bufferSize);
        retVal += UNITTEST_VALIDPTR(hint, found);
    }
    else
    {
        found = SSL_CLI_FindStr("<br>SRP Identity = </br>", buffer, bufferSize);
        retVal += UNITTEST_VALIDPTR(hint, found);
    }

    return retVal;
}
#endif
/*------------------------------------------------------------------------*/
#if 0
int SSL_CLI_VerifymbedReply(ubyte4 hint, const char* cipherName,
                            const char* versionStr,
                            const sbyte* buffer, sbyte4 bufferSize)
{
    int retVal = 0;
    const sbyte* found;
    char* s;
    char* mbdedCipherName = 0;

    if (cipherName)
    {
        /* replace all _ by - since this is what mbed uses */
        mbdedCipherName = strdup(cipherName);
        s = mbdedCipherName;
        while (*s)
        {
            if (*s == '_')
            {
                *s = '-';
            }
            ++s;
        }
    }

    /* look for "<body><h2>mbed TLS Test Server</h2>" */
    found = SSL_CLI_FindStr("<body><h2>mbed TLS Test Server</h2>",
                            buffer, bufferSize);
    retVal += UNITTEST_VALIDPTR(hint, found);
    if (!found) goto exit;
    bufferSize -= (found - buffer);
    buffer = found;

    if (mbdedCipherName)
    {
        /* look for "cipherName" */
        found = SSL_CLI_FindStr(mbdedCipherName, buffer, bufferSize);
        retVal += UNITTEST_VALIDPTR(hint, found);
        if (!found) goto exit;
        bufferSize -= (found - buffer);
        buffer = found;
    }

    if (versionStr)
    {
        /* ", protocol: " */
        found = SSL_CLI_FindStr(", protocol: ", buffer, bufferSize);
        retVal += UNITTEST_VALIDPTR(hint, found);
        if (!found) goto exit;
        bufferSize -= (found - buffer);
        buffer = found;

        /* look for "versionStr" */
        found = SSL_CLI_FindStr(versionStr, buffer, bufferSize);
        retVal += UNITTEST_VALIDPTR(hint, found);
        if (!found) goto exit;
        bufferSize -= (found - buffer);
        buffer = found;
    }

exit:
    free(mbdedCipherName);
    return retVal;
}

#endif

static sbyte4
SSL_CLI_TEST_saveTicket(sbyte4 connectionInstance, sbyte* pServerInfo,
                        ubyte4 serverInfoLen, void *pUserData,
                        ubyte *pTicket, ubyte4 ticketLen)
{
    ubyte pTicketFile[256];
    ubyte4 ticketFileLen = DIGI_STRLEN((sbyte *) SSL_CLI_TICKET_NAME);
    DIGI_MEMCPY(pTicketFile, SSL_CLI_TICKET_NAME, ticketFileLen);
    if (NULL != pServerInfo && 0 != serverInfoLen)
    {
        DIGI_MEMCPY(pTicketFile + ticketFileLen, pServerInfo, serverInfoLen);
        ticketFileLen += serverInfoLen;
    }
    pTicketFile[ticketFileLen] = '\0';

    DIGICERT_writeFile((char *)pTicketFile, pTicket, ticketLen);
    return OK;
}

static sbyte4
SSL_CLI_TEST_retrieveTicket(sbyte4 connectionInstance, sbyte *pServerInfo, ubyte4 serverInfoLen,
                            void *pUserData, ubyte **ppTicket, ubyte4 *pTicketLen,
                            intBoolean *pFreeMemory)
{
    ubyte pTicketFile[256];
    ubyte4 ticketFileLen = DIGI_STRLEN((sbyte *) SSL_CLI_TICKET_NAME);
    DIGI_MEMCPY(pTicketFile, SSL_CLI_TICKET_NAME, ticketFileLen);
    if (NULL != pServerInfo && 0 != serverInfoLen)
    {
        DIGI_MEMCPY(pTicketFile + ticketFileLen, pServerInfo, serverInfoLen);
        ticketFileLen += serverInfoLen;
    }
    pTicketFile[ticketFileLen] = '\0';

    *pFreeMemory = TRUE;
    DIGICERT_readFile((char *)pTicketFile, ppTicket, pTicketLen);
    remove(pTicketFile); /* Delete the ticket after one use */
    return OK;

}

/*------------------------------------------------------------------------*/

int SSL_CLI_Connect(ubyte4 hint, const CipherDesc* pCipherDesc,
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
    const char*     versionStr = 0;
    MSTATUS         status;
    int             retVal = 0;

    /* cannot be used with no pCipherDesc */
    retVal += UNITTEST_TRUE(hint, 0 != pCipherDesc);
    if (retVal) goto exit;

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
    if ( sslProtocol >= MIN_SSL_MINORVERSION)
    {
        retVal += UNITTEST_STATUS(hint, SSL_ioctl( connectionInstance,
                                                  SSL_SET_VERSION,
                                                  (void*) sslProtocol));
        switch (sslProtocol)
        {
            case SSL3_MINORVERSION:
                versionStr = "SSLv3";
                break;

            case TLS10_MINORVERSION:
                versionStr = "TLSv1";
                break;

            case TLS11_MINORVERSION:
                versionStr = "TLSv1.1";
                break;

            case TLS12_MINORVERSION:
                versionStr = "TLSv1.2";
                break;
            case TLS13_MINORVERSION:
                versionStr = "TLSv1.3";
                break;

            default:
                versionStr = "an unknown version of SSL/TLS";
                break;
        }
    }
    else
    {
        /* if no version set, should default to 1.2 unless
         special server is used (cf SSL_CLI_SSL3_Verify_635_Server_Test )*/
        switch (sslProtocol)
        {

            case -10:
                versionStr = "SSLv3";
                break;

            default:
                versionStr = "TLSv1.2";
                break;
        }
    }

    if (sslProtocol != SSL3_MINORVERSION)
    {
        /* set the server name indication */
        retVal += UNITTEST_STATUS(hint,
                                  SSL_setServerNameIndication(connectionInstance,
                                                              serverCN));
    }

    /* special set up for SRP ciphers: OPENSSL uses user3/pass3 */
    if (strstr(pCipherDesc->cipherName, "_SRP_")) /*(( TLS13_MINORVERSION == pCipherDesc->minSSLVer ))) */
    {
        retVal += UNITTEST_STATUS(hint, SSL_setClientSRPIdentity(connectionInstance,
                                                                 (ubyte*) "user3", 5,
                                                                 (ubyte*) "pass3", 5));
    }

    retVal += UNITTEST_STATUS(hint, SSL_enableCiphers( connectionInstance,
                                                       &pCipherDesc->cipherId, 1));

    if (retVal)
    {
        goto exit_close;
    }

    if (TLS13_MINORVERSION > sslProtocol)
        retVal += UNITTEST_STATUS(hint, SSL_setMaxProtoVersion(TLS12_MINORVERSION));
    else
        retVal += UNITTEST_STATUS(hint, SSL_setMaxProtoVersion(TLS13_MINORVERSION));


#if SSL3_MINORVERSION==MIN_SSL_MINORVERSION
    if (MOCANA == serverType && 0 == sslProtocol )
    {
        /* make sure the server rejects a SSLv3.0 connection attempt */
        retVal += UNITTEST_TRUE(hint,
                                OK != SSL_negotiateConnection(connectionInstance));
        goto exit_close; /* always leave then */
    }

#endif

    retVal += UNITTEST_STATUS(hint,
                              SSL_negotiateConnection(connectionInstance));

    if (retVal)
    {
        goto exit_close;
    }


    /* get the session info before closing the connection
     (SSL_closeConnection destroys SSLSocket) */
    SSL_getClientSessionInfo( connectionInstance, &sessionIdLen, sessionId,
                             masterSecret);
    SSL_closeConnection(connectionInstance);
    TCP_CLOSE_SOCKET( mySocket);


    /* resume session now */
    status = TCP_CONNECT(&mySocket, (sbyte*)serverIpAddress, serverPort);
    retVal += UNITTEST_STATUS( hint, status);
    if (OK > status)  goto exit;

    connectionInstance = SSL_connect(mySocket, sessionIdLen, sessionId,
                                     masterSecret, (sbyte*) serverCN, certStore);

    retVal += UNITTEST_STATUS(hint, connectionInstance);
    if (OK > connectionInstance)
    {
        goto exit_close;
    }

    if (sslProtocol >= MIN_SSL_MINORVERSION)
    {
        retVal += UNITTEST_STATUS(hint, SSL_ioctl( connectionInstance, SSL_SET_VERSION,
                                                  (void*) sslProtocol));
    }

    /* special set up for SRP ciphers: client must include SRP extension
     for session resumption */
    if (strstr(pCipherDesc->cipherName, "_SRP_")) /*(( TLS13_MINORVERSION == pCipherDesc->minSSLVer )))*/
    {
        retVal += UNITTEST_STATUS(hint, SSL_setClientSRPIdentity(connectionInstance,
                                                                 "user3", 5,
                                                                 "pass3", 5));
    }

#ifdef __SSLCLIENT_REHANDSHAKE__
    retVal += UNITTEST_STATUS(hint, SSL_enableCiphers( connectionInstance,
                                                          &pCipherDesc->cipherId, 1));

    if (retVal)
    {
        goto exit_close;
    }
#endif

    status = (MSTATUS) SSL_negotiateConnection(connectionInstance);
    retVal += UNITTEST_STATUS(hint, status);

    if (OK > status)
    {
        goto exit_close;
    }

    if (0 == retVal)
    {
        SSL_CLI_storeTestResults(pCipherDesc->cipherId, sslProtocol, serverType);
    }

exit_close:
    
    SSL_closeConnection(connectionInstance);
    
    TCP_CLOSE_SOCKET( mySocket);
    
exit:
    
    return retVal;
}



/*------------------------------------------------------------------------*/

int SSL_CLI_GetPage(ubyte4 hint, const CipherDesc* pCipherDesc,
                    const sbyte* serverIpAddress, ubyte2 serverPort,
                    const char* resourceName, int rootCertIndex, /* TODO : <- replace with leaf cert verification */
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
    if ( sslProtocol >= MIN_SSL_MINORVERSION)
    {
        retVal += UNITTEST_STATUS(hint, SSL_ioctl( connectionInstance,
                                                   SSL_SET_VERSION,
                                                   (void*) sslProtocol));
        switch (sslProtocol)
        {
            case SSL3_MINORVERSION:
                versionStr = "SSLv3";
                break;

            case TLS10_MINORVERSION:
                versionStr = "TLSv1";
                break;

            case TLS11_MINORVERSION:
                versionStr = "TLSv1.1";
                break;

            case TLS12_MINORVERSION:
                versionStr = "TLSv1.2";
                break;
            case TLS13_MINORVERSION:
                versionStr = "TLSv1.3";
                break;
            default:
                versionStr = "an unknown version of SSL/TLS";
                break;
        }
    }
    else
    {
        /* if no version set, should default to 1.2 unless
         special server is used (cf SSL_CLI_SSL3_Verify_635_Server_Test )*/
        switch (sslProtocol)
        {

            case -10:
                versionStr = "SSLv3";
                break;

            default:
                versionStr = "TLSv1.2";
                break;
        }
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
        /* special set up for SRP ciphers: our server uses scott/tiger */
        if ((strstr(pCipherDesc->cipherName, "_SRP_"))  ) /*(( TLS13_MINORVERSION == pCipherDesc->minSSLVer )))*/
        {
            retVal += UNITTEST_TRUE(hint, MOCANA == serverType);

            retVal += UNITTEST_STATUS(hint, SSL_setClientSRPIdentity(connectionInstance,
                                                                     (ubyte*) "scott", 5,
                                                                     (ubyte*) "tiger", 5));
        }

        retVal += UNITTEST_STATUS(hint, SSL_enableCiphers( connectionInstance,
                                                           &pCipherDesc->cipherId, 1));

        /* If the version is set to TLS 1.3 but the cipher is not supported for
         * TLS 1.3, set the version string to TLS 1.2.
         */
        if ((TLS13_MINORVERSION == sslProtocol) &&
            !(pCipherDesc->supportedSSLVer & TLS13_VB))
        {
            versionStr = "TLSv1.2";
        }
    }

    if (retVal)
    {
        goto exit_close;
    }

    if (TLS13_MINORVERSION > sslProtocol)
        retVal += UNITTEST_STATUS(hint, SSL_setMaxProtoVersion(TLS12_MINORVERSION));
    else
        retVal += UNITTEST_STATUS(hint, SSL_setMaxProtoVersion(TLS13_MINORVERSION));

#if SSL3_MINORVERSION==MIN_SSL_MINORVERSION
    if (MOCANA == serverType && 0 == sslProtocol )
    {
        /* make sure the server rejects a SSLv3.0 connection attempt */
        retVal += UNITTEST_TRUE(hint,
                                OK != SSL_negotiateConnection(connectionInstance));
        goto exit_close; /* always leave then */
    }

#endif
    if (1 == g_sessionTicketTest)
    {
        ubyte requestTicket = 1;
        retVal += UNITTEST_STATUS(hint, SSL_ioctl(connectionInstance, SSL_REQUEST_SESSION_TICKET, &requestTicket));
        retVal += UNITTEST_STATUS(hint, SSL_setClientSaveTicketCallback(connectionInstance, &SSL_CLI_TEST_saveTicket));
        retVal += UNITTEST_STATUS(hint, SSL_setClientRetrieveTicketCallback(connectionInstance, &SSL_CLI_TEST_retrieveTicket));

        if (retVal)
            goto exit_close;
    }
    else
    {
        ubyte requestTicket = 0;
        retVal += UNITTEST_STATUS(hint, SSL_ioctl(connectionInstance, SSL_REQUEST_SESSION_TICKET, &requestTicket));
    }

    retVal += UNITTEST_STATUS(hint,
                              SSL_negotiateConnection(connectionInstance));

    if (retVal)
    {
        goto exit_close;
    }

    /* TODO: use SSL_CLI_GetLeafCertificate to verify we got the
     expected leaf cert back */

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

    /* get the session info before closing the connection
       (SSL_closeConnection destroys SSLSocket) */
    SSL_getClientSessionInfo( connectionInstance, &sessionIdLen, sessionId,
                              masterSecret);
    SSL_closeConnection(connectionInstance);
    TCP_CLOSE_SOCKET( mySocket);

    /* resume session now */
    status = TCP_CONNECT(&mySocket, (sbyte*)serverIpAddress, serverPort);
    retVal += UNITTEST_STATUS( hint, status);
    if (OK > status)  goto exit;

    connectionInstance = SSL_connect(mySocket, sessionIdLen, sessionId,
                                     masterSecret, (sbyte*) serverCN, certStore);

    retVal += UNITTEST_STATUS(hint, connectionInstance);
    if (OK > connectionInstance)
    {
        goto exit_close;
    }

    if (sslProtocol >= MIN_SSL_MINORVERSION)
    {
        retVal += UNITTEST_STATUS(hint, SSL_ioctl( connectionInstance, SSL_SET_VERSION,
                                                   (void*) sslProtocol));
    }

#ifdef __SSLCLIENT_REHANDSHAKE__
    if (pCipherDesc)
    {
        /* special set up for SRP ciphers: our server uses scott/tiger */
        if (strstr(pCipherDesc->cipherName, "_SRP_")) /*(( TLS13_MINORVERSION == pCipherDesc->minSSLVer )))*/
        {
            retVal += UNITTEST_TRUE(hint, MOCANA == serverType);

            retVal += UNITTEST_STATUS(hint, SSL_setClientSRPIdentity(connectionInstance,
                                                                     (ubyte*) "scott", 5,
                                                                     (ubyte*) "tiger", 5));
        }

        retVal += UNITTEST_STATUS(hint, SSL_enableCiphers( connectionInstance,
                                                       &pCipherDesc->cipherId, 1));
    }


    if (retVal)
    {
        goto exit_close;
    }
#endif

    if (TLS13_MINORVERSION == pCipherDesc->minSSLVer)
    {
        /* set the server name indication */
        retVal += UNITTEST_STATUS(hint,
                                  SSL_setServerNameIndication(connectionInstance,
                                                              serverCN));
    }

    status = (MSTATUS) SSL_negotiateConnection(connectionInstance);
    retVal += UNITTEST_STATUS(hint, status);

    if (OK > status)
    {
        goto exit_close;
    }

    bufferSize = sizeof(buffer);
    retVal += SSL_CLI_GetSecurePageAux(hint, connectionInstance,
                                       resourceName,
                                       (sbyte *)buffer, &bufferSize);

    switch (serverType)
    {
        case MOCANA:
            retVal += SSL_CLI_VerifyMocanaReply(hint, cipherName, resourceName,
                                             versionStr, (sbyte *)buffer,
                                             bufferSize);
            break;

        case OPENSSL:
            retVal += SSL_CLI_VerifyOpenSSLReply( hint, cipherName,
                                                 versionStr, (sbyte *)buffer,
                                                 bufferSize);
            break;

        case MBEDTLS:
            break;
    }

    if (0 == retVal && pCipherDesc)
    {
        SSL_CLI_storeTestResults(pCipherDesc->cipherId, sslProtocol, serverType);
    }


exit_close:

    SSL_closeConnection(connectionInstance);

    TCP_CLOSE_SOCKET( mySocket);

exit:

    return retVal;
}



/*------------------------------------------------------------------------*/

int SSL_CLI_GetALPN(ubyte4 hint,
                    const sbyte* serverIpAddress, ubyte2 serverPort,
                    const char* resourceName,
                    const char* serverCN, certStorePtr certStore,
                    const char** protocols, int numProtocols,
                    int selectedProtocol, sbyte4 sslProtocol)
{
    /* connect to the host specified and set a simple GET */
    sbyte4          connectionInstance;
    TCP_SOCKET      mySocket;
    int             retVal = 0;
    const ubyte*    alpn = 0;
    ubyte4          alpnLen;
    sbyte           buffer[8192];
    sbyte4          bufferSize;
    const sbyte*    found;
    int             i = 0;
    int             count = 0;
    ubyte2          pCipherIdList[COUNTOF(gCipherDescs)];

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

    retVal += UNITTEST_STATUS(hint, SSL_ioctl( connectionInstance, SSL_SET_VERSION, sslProtocol));

    /* set the protocols */
    retVal += UNITTEST_STATUS(hint, SSL_setApplicationLayerProtocol(connectionInstance,
                                                                    numProtocols,
                                                                    protocols));
    if (retVal) goto exit_close;

    memset(pCipherIdList, 0x00, COUNTOF(gCipherDescs));

    for (i = 0; i < COUNTOF(gCipherDescs); ++i)
    {
        const char* cipherName = gCipherDescs[i].cipherName;
        /* exclude the preshared keys and SRP ones */
        if (!strstr(cipherName, "_PSK_") &&
            !strstr(cipherName, "_SRP_") &&
            (gCipherDescs[i].minSSLVer == sslProtocol))
        {
            pCipherIdList[count] = gCipherDescs[i].cipherId;
            count++;
        }
    }

    retVal += UNITTEST_STATUS(hint, SSL_enableCiphers(connectionInstance, pCipherIdList, count));

    retVal += UNITTEST_STATUS(hint,
                              SSL_negotiateConnection(connectionInstance));

    if (retVal) goto exit_close;

    /* verify the server selected the correct protocol */
    /* first way, retrieve the selected protocol */

    retVal += UNITTEST_STATUS(hint, SSL_getSelectedApplicationProtocol(connectionInstance,
                                                                       &alpn,
                                                                       &alpnLen));

    if (retVal) goto exit_close;

    retVal += UNITTEST_TRUE(hint, alpn != 0);
    retVal += UNITTEST_TRUE(hint, alpnLen != 0);

    if (retVal) goto exit_close;

    /* compare with expected value */
    retVal += UNITTEST_TRUE(hint,
                            DIGI_STRLEN( protocols[selectedProtocol]) == alpnLen);
    if (retVal) goto exit_close;

    retVal += UNITTEST_TRUE(hint, 0 == memcmp(protocols[selectedProtocol],
                                              alpn, alpnLen));
    if (retVal) goto exit_close;

    /* look in the produced web page */
    bufferSize = sizeof(buffer);
    retVal += SSL_CLI_GetSecurePageAux(hint, connectionInstance,
                                       "test", (sbyte *)buffer, &bufferSize);

    if (retVal) goto exit_close;

    found = SSL_CLI_FindStr(protocols[selectedProtocol], buffer, bufferSize);
    retVal += UNITTEST_VALIDPTR(hint, found);
    if (!found) goto exit_close;

exit_close:

    SSL_closeConnection(connectionInstance);

    TCP_CLOSE_SOCKET( mySocket);

exit:

    return retVal;
}


/*------------------------------------------------------------------------*/

int SSL_CLI_VerifyMutAuthRejected(ubyte4 hint, const CipherDesc* pCipherDesc,
                                  const char* cipherName,
                                  const sbyte* serverIpAddress, ubyte2 serverPort,
                                  const char* resourceName, int rootCertIndex,
                                  const char* serverCN, ServerType serverType,
                                  sbyte4 sslProtocol, certStorePtr certStore)
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

    if ( sslProtocol >= MIN_SSL_MINORVERSION)
    {
        retVal += UNITTEST_STATUS(hint, SSL_ioctl( connectionInstance,
                                                   SSL_SET_VERSION,
                                                   (void*) sslProtocol));
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

    if (TLS13_MINORVERSION > sslProtocol)
        retVal += UNITTEST_STATUS(hint, SSL_setMaxProtoVersion(TLS12_MINORVERSION));
    else
        retVal += UNITTEST_STATUS(hint, SSL_setMaxProtoVersion(TLS13_MINORVERSION));

#if SSL3_MINORVERSION==MIN_SSL_MINORVERSION

    if (MOCANA == serverType && 0 == sslProtocol )
    {
        /* make sure the server rejects a SSLv3.0 connection attempt */
        retVal += UNITTEST_TRUE(hint,
                                OK != SSL_negotiateConnection(connectionInstance));
        goto exit_close; /* always leave then */
    }

#endif

    status = (MSTATUS) SSL_negotiateConnection(connectionInstance);

    /*no mutual authentication for ANON cipher suites so they should work */
    if ( strstr( cipherName, "_ANON_"))
    {
        retVal += UNITTEST_INT(hint, status, OK);
    }
    else
    {
        /* fails, error code seems to differ between platforms:
           ERR_TCP_SOCKET_CLOSED or ERR_TCP_READ_ERROR */
        retVal += UNITTEST_TRUE( hint, status != OK);
    }

exit_close:

    SSL_closeConnection(connectionInstance);

    TCP_CLOSE_SOCKET( mySocket);

exit:

    return retVal;
}



/*------------------------------------------------------------------------*/

int SSL_CLI_VerifyExpiredCert(ubyte4 hint, const CipherDesc* pCipherDesc,
                              const sbyte* serverIpAddress, ubyte2 serverPort,
                              const char* resourceName, int rootCertIndex,
                              const char* serverCN, ServerType serverType,
                              sbyte4 sslProtocol, certStorePtr certStore)
{
    /* connect to the host specified and set a simple GET */
    sbyte4          connectionInstance;
    TCP_SOCKET      mySocket;
    MSTATUS         status;
    int             retVal = 0;
    int             expectedResult = 0;


    if (TLS13_MINORVERSION == sslProtocol)
    {
        expectedResult = ERR_CERT_CHAIN_NO_TRUST_ANCHOR;
    }
    else
    {
        expectedResult = ERR_CERT_EXPIRED;
    }
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

    if ( sslProtocol >= MIN_SSL_MINORVERSION)
    {
        retVal += UNITTEST_STATUS(hint, SSL_ioctl( connectionInstance,
                                                   SSL_SET_VERSION,
                                                   (void*) sslProtocol));
    }

    if (pCipherDesc)
    {
        retVal += UNITTEST_STATUS(hint, SSL_enableCiphers( connectionInstance,
                                                       &pCipherDesc->cipherId, 1));

        if (retVal)
        {
            goto exit_close;
        }
    }

    if (TLS13_MINORVERSION > sslProtocol)
        retVal += UNITTEST_STATUS(hint, SSL_setMaxProtoVersion(TLS12_MINORVERSION));
    else
        retVal += UNITTEST_STATUS(hint, SSL_setMaxProtoVersion(TLS13_MINORVERSION));

#if SSL3_MINORVERSION==MIN_SSL_MINORVERSION

    if (MOCANA == serverType && 0 == sslProtocol )
    {
        /* make sure the server rejects a SSLv3.0 connection attempt */
        retVal += UNITTEST_TRUE(hint,
                                OK != SSL_negotiateConnection(connectionInstance));
        goto exit_close; /* always leave then */
    }

#endif

    status = (MSTATUS) SSL_negotiateConnection(connectionInstance);

    // If cert time verify has been disabled, then this check of an expired
    // cert will pass.  So this test is not meaningful and to prevent a failing test
    // The check of the status code has been changed
#if defined(__DIGICERT_DISABLE_CERT_TIME_VERIFY__)
    retVal += UNITTEST_TRUE( hint, (status == OK));
#else
    retVal += UNITTEST_INT( hint, status, expectedResult);
#endif

exit_close:

    SSL_closeConnection(connectionInstance);

    TCP_CLOSE_SOCKET( mySocket);

exit:

    return retVal;
}


/*------------------------------------------------------------------------*/

int SSL_CLI_ECCCurveTest(ubyte4 hint, ubyte2 cipherId,
                         const sbyte* serverIpAddress, ubyte2 serverPort,
                         const char* resourceName, int rootCertIndex,
                         const char* serverCN, ServerType serverType,
                         sbyte4 sslProtocol, enum tlsExtNamedCurves curve,
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

    retVal += UNITTEST_STATUS(hint, SSL_enableECCCurves( connectionInstance,
                                                         &curve, 1));

    if (retVal)
    {
        goto exit_close;
    }

    if (TLS13_MINORVERSION > sslProtocol)
        retVal += UNITTEST_STATUS(hint, SSL_setMaxProtoVersion(TLS12_MINORVERSION));
    else
        retVal += UNITTEST_STATUS(hint, SSL_setMaxProtoVersion(TLS13_MINORVERSION));

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

    if ( kRSACertIdx == rootCertIndex)
    {
        retVal += UNITTEST_STATUS(hint, status);
    }
    else if ( (cipherId >= 0xC015 && cipherId <= 0xC019) || /* for ECDHE_ANON ciphers, it should succeed for any curves */
              (TLS13_MINORVERSION == sslProtocol) )
    {
        retVal += UNITTEST_STATUS(hint, status);

        /* but verify that the curve used is correct */
        retVal += SSL_CLI_VerifyECDHECurve( hint, connectionInstance, curve);
    }
    else
    {
        retVal += UNITTEST_STATUS(hint, status);

        /* we verified the certificate but verify the public key nonetheless */
        retVal += SSL_CLI_VerifyPublicKeyCurve( hint, connectionInstance, curve);
    }


exit_close:

    SSL_closeConnection(connectionInstance);

    TCP_CLOSE_SOCKET( mySocket);

exit:

    return retVal;
}


/*------------------------------------------------------------------------*/

int SSL_CLI_VerifyTrac345(const sbyte* serverIpAddress, ubyte2 serverPort)
{
    TCP_SOCKET  mySocket = 0;
    sbyte4      connectionInstance  = 0;
    MSTATUS     status              = OK;
    int         retVal              = 0;
    int         i                   = 0;

    /* Test connection for a while since the server takes some time to come up */
    for (i = 0; i < 20; ++i)
    {
        status = TCP_CONNECT(&mySocket, (sbyte*)serverIpAddress, serverPort);

        if (OK == status)
            break;
        RTOS_sleepMS(1000); /* sleep for a second */
    }

    retVal += UNITTEST_TRUE( 0, (OK == status));
    if (0 != retVal)
        goto exit;

    retVal += UNITTEST_STATUS(0, connectionInstance = SSL_connect(mySocket, 0,
                                                                  NULL, NULL,
                                                                  (sbyte*) "mocana.com",
                                                                  pRSASslCertStore));
    if (0 != retVal)
        goto exit;

    status = (MSTATUS)  SSL_negotiateConnection(connectionInstance);
    /* this returns different value depending on the platform
       just make sure we cannot connect */
    retVal += UNITTEST_TRUE( 0, (OK != status));
    if (0 != retVal)
        goto exit;

exit:
    SSL_closeConnection(connectionInstance);
    TCP_CLOSE_SOCKET( mySocket);

    return retVal;
}


/*------------------------------------------------------------------------*/

int SSL_CLI_VerifyUnableToConnectEx(ubyte4 hint, const CipherDesc* pCipherDesc,
                                    const sbyte* serverIpAddress,
                                    ubyte2 serverPort, const char* serverCN,
                                    sbyte4 sslProtocol, sbyte4 error,
                                    certStorePtr certStore)
{
    TCP_SOCKET  mySocket = 0;
    sbyte4      connectionInstance  = 0;
    MSTATUS     status              = OK;
    int         retVal           = 0;
    int             i = 0;
    int             count = 0;
    ubyte2          pCipherIdList[COUNTOF(gCipherDescs)];

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

    if ( sslProtocol >= MIN_SSL_MINORVERSION)
    {
        retVal += UNITTEST_STATUS(hint, SSL_ioctl(connectionInstance,
                                                  SSL_SET_VERSION,
                                                  (void*) sslProtocol));
    }
    else if (sslProtocol >=0 ) /* ssl is not -1 so is set but will */
    {
        goto exit; /* the test makes no sense in that case, so succeeds */
    }

    if (0 != retVal)
        goto exit;


    if (pCipherDesc)
    {
        retVal += UNITTEST_STATUS(hint, SSL_enableCiphers( connectionInstance,
                                                          &pCipherDesc->cipherId, 1));
    }
    else
    {
        memset(pCipherIdList, 0x00, COUNTOF(gCipherDescs));

        for (i = 0; i < COUNTOF(gCipherDescs); ++i)
        {
            const char* cipherName = gCipherDescs[i].cipherName;
            /* exclude the preshared keys and SRP ones */
            if (!strstr(cipherName, "_PSK_") &&
                !strstr(cipherName, "_SRP_"))
            {
                pCipherIdList[count] = gCipherDescs[i].cipherId;
                count++;
            }
        }

        retVal += UNITTEST_STATUS(hint, SSL_enableCiphers(connectionInstance, pCipherIdList, count));
        if (retVal) goto exit;
    }

    status = (MSTATUS) SSL_negotiateConnection(connectionInstance);

    retVal += UNITTEST_INT( hint, status, error);

exit:
    SSL_closeConnection(connectionInstance);
    TCP_CLOSE_SOCKET( mySocket);

    return retVal;
}


/*------------------------------------------------------------------------*/

int SSL_CLI_VerifyUnableToConnect(ubyte4 hint, const CipherDesc* pCipherDesc,
                                    const sbyte* serverIpAddress,
                                    ubyte2 serverPort, const char* serverCN,
                                    sbyte4 sslProtocol, certStorePtr certStore)
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

    if ( sslProtocol >= MIN_SSL_MINORVERSION)
    {
        retVal += UNITTEST_STATUS(hint, SSL_ioctl(connectionInstance,
                                                  SSL_SET_VERSION,
                                                  (void*) sslProtocol));
    }
    else if (sslProtocol >=0 ) /* ssl is not -1 so is set but will */
    {
        goto exit; /* the test makes no sense in that case, so succeeds */
    }

    if (0 != retVal)
        goto exit;


    if (pCipherDesc)
    {
        retVal += UNITTEST_STATUS(hint, SSL_enableCiphers( connectionInstance,
                                                          &pCipherDesc->cipherId, 1));
    }

    status = (MSTATUS)  SSL_negotiateConnection(connectionInstance);

    retVal += UNITTEST_TRUE( hint, 0!=status);

exit:
    SSL_closeConnection(connectionInstance);
    TCP_CLOSE_SOCKET( mySocket);

    return retVal;
}


/*------------------------------------------------------------------------*/

int SSL_CLI_Normal_Server_Test(const sbyte* pIpAddress,
                               ubyte2 portNo,
                               const char* domainName,
                               const int minSSLVersion,
                               char* resourceName)
{
    /* hint 0x0000 - 0x0020 */
    int retVal = 0;
    int i, j;
    MSTATUS status;
    TCP_SOCKET mySocket;
    certStorePtr pEmptyCertStore = 0;
    char *pEnv = NULL;
    ubyte opensslTest = 0;

    pEnv = getenv("ENABLE_OPENSSL_INTEROPERABILITY_TEST");
    if (pEnv != NULL)
    {
        if (1 == atoi(pEnv))
            opensslTest = 1;
    }

    UNITTEST_STATUS_GOTO(0, CERT_STORE_createStore(&pEmptyCertStore),
                         retVal, exit);

    /* test connection for a while since the server takes some time to come
       up ( rng initialization) on some platforms */
    for (i = 0; i < 20; ++i)
    {
        status = TCP_CONNECT(&mySocket, (sbyte*) pIpAddress, portNo);
        TCP_CLOSE_SOCKET(mySocket);
        if ( OK == status)
        {
            break;
        }
        RTOS_sleepMS(1000); /* sleep for a second */
    }

    retVal += UNITTEST_TRUE(0, i < 20);
    if ( retVal) goto exit;

    /* test internal server port = PORTNUM */
    /* IF YOU GET SOME RSA DECRYPTION ERRORS (-7702) WITH THE ECDH_RSA CRYPTOSUITES,
       THE PROBLEM IS PROBABLY THAT A NEW SERVER WAS ADDED TO THE TEST THAT USES THE SAME
       CERTIFICATES AS THE NORMAL SERVER AND IS ALSO TRYING TO CREATE THEM. SEE COMMENTS
       IN ssl_serv.c main() */
    printf("normal server test, cipher tests \n");
    for (i = 0; i < COUNTOF(gCipherDescs); ++i)
    {
        const char* cipherName = gCipherDescs[i].cipherName;
        /* exclude the preshared keys and SRP ones */
        if (!strstr(cipherName, "_PSK_") &&
            !strstr(cipherName, "_SRP_") )
        {
            int rootCertIndex = kRSACertIdx;
            /* for ECC crypto with no RSA certificates */
            if ( 0xC000 == (gCipherDescs[i].cipherId & 0xC000))
            {
                if ( !strstr( cipherName, "RSA"))
                {
                    rootCertIndex = kECC256CertIdx;
                }
            }

            for (j = gCipherDescs[i].minSSLVer; j <= TLS12_MINORVERSION; ++j)
            {
                /* OpenSSL s_server does not support ECDHE_*_NULL and ECDHE_*_3DES ciphers*/
                if ((j < minSSLVersion) ||
                    ((1 == opensslTest) && (!strstr(cipherName, "_ECDHE_") && (!strstr(cipherName, "_NULL_") || !strstr(cipherName, "_3DES_")))))
                {
                    continue;
                }

                /* Note: for TLS 1.2, the client send the signature extension so the server can return
                   any certificate it wants that matches the extension and the cipher.
                   In this test case, the server will return ECDHCert256CA.der for the ECDH_RSA cipher suites.
                   Bottom of p 49 of the RFC 5246: DH_DSS, DH_RSA, ECDH_ECDSA and ECDH_RSA are "historical" */
                if (TLS12_MINORVERSION == j &&
                    0xC000 == (gCipherDescs[i].cipherId & 0xC000))
                {
                    if ( 0 != strstr( cipherName, "ECDH_RSA"))
                    {
                        rootCertIndex = kECC256CertIdx;
                    }
                }
                printf("normal server test, cipher test %s\n", gCipherDescs[i].cipherName );

                retVal += SSL_CLI_GetPage(CIPHER_HINT(0x00+j,i),
                                          gCipherDescs+i,
                                          pIpAddress, portNo, resourceName,
                                          rootCertIndex, domainName, MOCANA, j,
                                          pRSASslCertStore);
                 if (TLS12_MINORVERSION == j)
                {
                    /* test to verify that we use 1.2 is the protocol is not set */
                    retVal += SSL_CLI_GetPage(CIPHER_HINT(0x0a,i),
                                              gCipherDescs + i,
                                              pIpAddress, portNo, resourceName,
                                              rootCertIndex, domainName, MOCANA, -1,
                                              pRSASslCertStore);
                }

                if ((0 == opensslTest) || (!strstr(cipherName, "_ECDHE_")))
                {
                    printf("normal server test, cipher test, ecc test secp256r1 is set %s\n", gCipherDescs[i].cipherName );
                    retVal += SSL_CLI_ECCCurveTest(CIPHER_HINT(0x00+j,i),
                                                   gCipherDescs[i].cipherId,
                                                   pIpAddress, portNo, resourceName,
                                                   rootCertIndex, domainName, MOCANA, j,
                                                   tlsExtNamedCurves_secp256r1,
                                                   pRSASslCertStore);
                    printf("normal server test, cipher test, ecc test , secp384r1 is set %s\n", gCipherDescs[i].cipherName );
                    retVal += SSL_CLI_ECCCurveTest(CIPHER_HINT(0x10+j,i),
                                                   gCipherDescs[i].cipherId,
                                                   pIpAddress, portNo, resourceName,
                                                   (kECC256CertIdx == rootCertIndex) ? kECC384CertIdx : rootCertIndex,
                                                   domainName, MOCANA, j,
                                                   tlsExtNamedCurves_secp384r1,
                                                   pRSASslCertStore);
                    printf("normal server test, cipher test, ecc test,secp 521 %s\n", gCipherDescs[i].cipherName );
                    retVal += SSL_CLI_ECCCurveTest(CIPHER_HINT(0x10+j,i),
                                                   gCipherDescs[i].cipherId,
                                                   pIpAddress, portNo, resourceName,
                                                   (kECC256CertIdx == rootCertIndex) ? kECC521CertIdx : rootCertIndex,
                                                   domainName, MOCANA, j,
                                                   tlsExtNamedCurves_secp521r1,
                                                   pRSASslCertStore);
                }
            }
            if(TLS13_MINORVERSION == gCipherDescs[i].minSSLVer)
            {

                retVal += SSL_CLI_GetPage(CIPHER_HINT(0x00+j,i),
                                          gCipherDescs+i,
                                          pIpAddress, portNo, resourceName,
                                          rootCertIndex, domainName, MOCANA, TLS13_MINORVERSION,
                                          pRSASslCertStore);

                printf("normal server test, cipher tests, ecc test,secp256 tls13 test %s\n", gCipherDescs[i].cipherName );
                retVal += SSL_CLI_ECCCurveTest(CIPHER_HINT(0x00+4,i),
                                               gCipherDescs[i].cipherId,
                                               pIpAddress, portNo, resourceName,
                                               kECC256CertIdx, domainName, MOCANA, TLS13_MINORVERSION,
                                               tlsExtNamedCurves_secp256r1,
                                               pRSASslCertStore);

                printf("normal server test, cipher tests, ecc test,secp384 tls13 test %s\n", gCipherDescs[i].cipherName );
                retVal += SSL_CLI_ECCCurveTest(CIPHER_HINT(0x10+4,i),
                                               gCipherDescs[i].cipherId,
                                               pIpAddress, portNo, resourceName,
                                               kECC384CertIdx,
                                               domainName, MOCANA, TLS13_MINORVERSION,
                                               tlsExtNamedCurves_secp384r1,
                                               pRSASslCertStore);

                printf("normal server test, cipher tests, ecc test,secp521 tls13 test %s\n", gCipherDescs[i].cipherName );
                retVal += SSL_CLI_ECCCurveTest(CIPHER_HINT(0x10+4,i),
                                               gCipherDescs[i].cipherId,
                                               pIpAddress, portNo, resourceName,
                                               kECC521CertIdx,
                                               domainName, MOCANA, TLS13_MINORVERSION,
                                               tlsExtNamedCurves_secp521r1,
                                               pRSASslCertStore);
            }
        }
    }
    printf("normal server test, padding test\n" );
    /* padding test. We take advantage of the fact that the server sends
       back part of the resource back as its message. By increasing the size,
       we should go through all the padding */

    for (i = 0; i < 8; ++i)
    {
        /* use 3DES (0x000A) as the cipher */
        /* append an X to the resourceName */
        resourceName[4+i] = (sbyte) ('A'+i);

        switch (minSSLVersion)
        {
            case SSL3_MINORVERSION:
                retVal += SSL_CLI_GetPage(CIPHER_HINTX(0x10, g3DESCipherDesc.cipherId),
                                          &g3DESCipherDesc,
                                          pIpAddress, portNo,
                                          resourceName, kRSACertIdx,
                                          domainName, MOCANA, SSL3_MINORVERSION,
                                          pRSASslCertStore);
                /* flows through */

            case TLS10_MINORVERSION:
                retVal += SSL_CLI_GetPage(CIPHER_HINTX(0x11, g3DESCipherDesc.cipherId),
                                          &g3DESCipherDesc,
                                          pIpAddress, portNo,
                                          resourceName, kRSACertIdx,
                                          domainName, MOCANA, TLS10_MINORVERSION,
                                          pRSASslCertStore);
                /* flows through */
            case TLS11_MINORVERSION:
                retVal += SSL_CLI_GetPage(CIPHER_HINTX(0x12, g3DESCipherDesc.cipherId),
                                          &g3DESCipherDesc,
                                          pIpAddress, portNo,
                                          resourceName, kRSACertIdx,
                                          domainName, MOCANA, TLS11_MINORVERSION,
                                          pRSASslCertStore);
                /* flows through */

            case TLS12_MINORVERSION:
                retVal += SSL_CLI_GetPage(CIPHER_HINTX(0x13, g3DESCipherDesc.cipherId),
                                          &g3DESCipherDesc,
                                          pIpAddress, portNo,
                                          resourceName, kRSACertIdx,
                                          domainName, MOCANA, TLS12_MINORVERSION,
                                          pRSASslCertStore);
            case TLS13_MINORVERSION:
                retVal += SSL_CLI_GetPage(CIPHER_HINTX(0x14, gTls13CipherDesc.cipherId),
                                          &gTls13CipherDesc,
                                          pIpAddress, portNo,
                                          resourceName, kRSACertIdx,
                                          domainName, MOCANA, TLS13_MINORVERSION,
                                          pRSASslCertStore);
                /* flows through */
            default:
                break;
        }
    }
    printf("normal server test, without specifying a cert store s\n"  );
    /* test that verifies we can connect without specifying a cert store;
     not recommended since any cert chain is then accepted */
    for (i = 0; i < COUNTOF(gCipherDescs); ++i)
    {
        const char* cipherName = gCipherDescs[i].cipherName;
        /* exclude the preshared keys and SRP ones */
        if (!strstr(cipherName, "_PSK_") &&
            !strstr(cipherName, "_SRP_") )
        {
            for (j = gCipherDescs[i].minSSLVer; j <= TLS12_MINORVERSION; ++j)
            {
                if ( j < minSSLVersion)
                {
                    continue;
                }

                retVal += SSL_CLI_GetPage(CIPHER_HINT(0x15+j,i),
                                          gCipherDescs+i,
                                          pIpAddress, portNo, resourceName,
                                          -1, domainName, MOCANA, j, NULL);
            }
            if(TLS13_MINORVERSION == gCipherDescs[i].minSSLVer)
            {
                retVal += SSL_CLI_GetPage(CIPHER_HINT(0x15+j,i),
                                          gCipherDescs+i,
                                          pIpAddress, portNo, resourceName,
                                          -1, domainName, MOCANA, TLS13_MINORVERSION, NULL);
            }
        }
    }
#if 0
    printf("normal server test, not able connect empty cert store \n" );
    /* test that verifies we can not connect with an empty cert store
     ( as example of a cert store that doesn't have the root ) except for
     ANON cipher suites. */
    for (i = 0; i < COUNTOF(gCipherDescs); ++i)
    {
        const char* cipherName = gCipherDescs[i].cipherName;
        /* exclude the preshared keys and SRP ones */
        if (!strstr(cipherName, "_PSK_") &&
            !strstr(cipherName, "_SRP_") )
        {

            for (j = gCipherDescs[i].minSSLVer; j <= TLS13_MINORVERSION; ++j)
            {
                int anonymousCipher = strstr( cipherName, "_ANON_") ? 1 : 0;

                /* Digicert server will reject a SSLv3.0 connection */
                if ( j < minSSLVersion || j  == SSL3_MINORVERSION)
                {
                    continue;
                }

                if (anonymousCipher)
                {
                    retVal += SSL_CLI_GetPage(CIPHER_HINT(0x15+j,i),
                                              gCipherDescs+i,
                                              pIpAddress, portNo, resourceName,
                                              -1, domainName, MOCANA, j,
                                              pEmptyCertStore);

                }
                else
                {
                    retVal += SSL_CLI_VerifyUnableToConnectEx( CIPHER_HINT(0x16+j,i),
                                                              gCipherDescs+i,
                                                              pIpAddress, portNo,
                                                              domainName, j,
                                                              ERR_CERT_CHAIN_NO_TRUST_ANCHOR,
                                                              pEmptyCertStore);
                }
            }
        }
    }
#endif

#ifdef __SSLCLIENT_REHANDSHAKE__
    for (i = 0; i < COUNTOF(gCipherDescs); ++i)
    {
        const char* cipherName = gCipherDescs[i].cipherName;
        /* exclude the preshared keys and SRP ones */
        if (!strstr(cipherName, "_PSK_") &&
            !strstr(cipherName, "_SRP_") &&
            !strstr(cipherName, "_3DES_") &&
            strstr(cipherName, "_AES_"))
        {

            printf("normal server test, rehandshake tests %s\n", gCipherDescs[i].cipherName );
            for (j = gCipherDescs[i].minSSLVer; j <= TLS12_MINORVERSION; ++j)
            {
                retVal += SSL_CLI_GetPage(CIPHER_HINTX(0x20+j, gCipherDescs[i].cipherId),
                                          &gCipherDescs[i],
                                          pIpAddress,
                                          portNo, "rehandshake",
                                          kRSACertIdx, domainName, MOCANA, j,
                                          pRSASslCertStore);
                break; /* Testing rehandshake for one connection is good */
            }
        }
    }
#endif

exit:


    CERT_STORE_releaseStore(&pEmptyCertStore);

    return retVal;
}



/*------------------------------------------------------------------------*/

int SSL_CLI_SessionTicket_TestCase(const sbyte* pIpAddress,
                                    ubyte2 portNo,
                                    const char* pDomainName,
                                    char* pResourceName)
{
    int i = 0;
    int retVal = 0;

    g_sessionTicketTest = 1;

    for (i = 0; i < COUNTOF(gCipherDescs); ++i)
    {
        const char* cipherName = gCipherDescs[i].cipherName;
        int rootCertIndex = (strstr(cipherName, "_RSA_") ?  kRSACertIdx: -1);
        /* exclude the PSK, SRP, ANON ones */
        if (!strstr(cipherName, "_PSK_") &&
            !strstr(cipherName, "_SRP_") &&
            !strstr(cipherName, "_ANON_") &&
            strstr(cipherName, "_RSA_") &&
            strstr(cipherName, "_DHE_") &&
            strstr(cipherName, "_AES_") &&
            gCipherDescs[i].minSSLVer == TLS12_MINORVERSION)
        {
            /* Establish a session ticket in the first connection */
            retVal += SSL_CLI_GetPage(CIPHER_HINT((0x800), i), gCipherDescs+i,
                                      pIpAddress, portNo, pResourceName,
                                      rootCertIndex, pDomainName, MOCANA,
                                      TLS12_MINORVERSION, pRSASslCertStore);

            /* Use the session ticket in the second connection */
            retVal += SSL_CLI_GetPage(CIPHER_HINT((0x800), i), gCipherDescs+i,
                                      pIpAddress, portNo, pResourceName,
                                      rootCertIndex, pDomainName, MOCANA,
                                      TLS12_MINORVERSION, pRSASslCertStore);

            goto exit; /* Testing for one cipher is enough */
        }
    }

exit:
    g_sessionTicketTest = 0;
    return retVal;
}

int SSL_CLI_PSK_Normal_Server_Test(const sbyte* pIpAddress,
                               ubyte2 portNo,
                               const char* domainName,
                               char* resourceName)
{
    /* hint 0x0100 - 0x0140 */
    int retVal = 0;
    int i, j;

    /* test internal server port = PORTNUM */
    /* IF YOU GET SOME RSA DECRYPTION ERRORS (-7702) WITH THE ECDH_RSA CRYPTOSUITES,
     THE PROBLEM IS PROBABLY THAT A NEW SERVER WAS ADDED TO THE TEST THAT USES THE SAME
     CERTIFICATES AS THE NORMAL SERVER AND IS ALSO TRYING TO CREATE THEM. SEE COMMENTS
     IN ssl_serv.c main() */

    for (i = 0; i < COUNTOF(gCipherDescs); ++i)
    {
        const char* cipherName = gCipherDescs[i].cipherName;
        /* only the preshared keys one */
        if (strstr(cipherName, "_PSK_"))
        {
            /* only RSA suites send certificates */
            int rootCertIndex = (strstr(cipherName, "_RSA_") ?  kRSACertIdx: -1);

            for (j = gCipherDescs[i].minSSLVer; j <= TLS12_MINORVERSION; ++j)
            {
                retVal += SSL_CLI_GetPage(CIPHER_HINT(0x100+j,i),
                                          gCipherDescs + i,
                                          pIpAddress, portNo, resourceName,
                                          rootCertIndex, domainName, MOCANA, j,
                                          pRSASslCertStore);
            }
        }
    }

    return retVal;
}


/*------------------------------------------------------------------------*/
int SSL_CLI_SendVersionCmd(ubyte4 hint,
                    const sbyte* serverIpAddress, ubyte2 serverPort,
                    const char* resourceName,
                    const char* serverCN, certStorePtr certStore,
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
    int             i = 0;
    int             count = 0;
    ubyte2          pCipherIdList[COUNTOF(gCipherDescs)];

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

    memset(pCipherIdList, 0x00, COUNTOF(gCipherDescs));

    for (i = 0; i < COUNTOF(gCipherDescs); ++i)
    {
        const char* cipherName = gCipherDescs[i].cipherName;
        /* exclude the preshared keys and SRP ones */
        if (!strstr(cipherName, "_PSK_") &&
            !strstr(cipherName, "_SRP_"))
        {
            pCipherIdList[count] = gCipherDescs[i].cipherId;
            count++;
        }
    }

    retVal += UNITTEST_STATUS(hint, SSL_enableCiphers(connectionInstance, pCipherIdList, count));
    if (retVal) goto exit_close;

    retVal += UNITTEST_STATUS(hint,
                              SSL_negotiateConnection(connectionInstance));

    if (retVal) goto exit_close;

    bufferSize = 2;
    sprintf(buffer, "%s%d", serverVersionConfigCmd, serverCmd);
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

    exit:

    return retVal;
}


/*------------------------------------------------------------------------*/

int SSL_CLI_ALPN_Normal_Server_Test(const sbyte* pIpAddress,
                                    ubyte2 portNo,
                                    const char* domainName,
                                    char* resourceName)
{
    /* hint 0x0150 - 0x0150 */
    int retVal = 0, j = 0;

    /* the server has "super_secret_256", "http/1.1" */
    const char* protocols[] = { "does_not_exist",
                                "super_secret_256",
                                "http/1.1",
                                "super_secret_256",
                                "does_not_exist"};
    char *pEnv = NULL;
    ubyte verifyMocanaServerResposne = 1;

    pEnv = getenv("ENABLE_OPENSSL_INTEROPERABILITY_TEST");
    if (pEnv != NULL)
    {
        if (1 == atoi(pEnv))
            verifyMocanaServerResposne = 0;
    }

    SSL_setMaxProtoVersion(TLS13_MINORVERSION);

    for(j = TLS12_MINORVERSION; j <= TLS13_MINORVERSION; j++)
    {
        /* OpenSSL s_server does not need setting of version */
        if (1 == verifyMocanaServerResposne)
        {
            /* First set the version on the server */
            retVal += SSL_CLI_SendVersionCmd(0,
                                             pIpAddress, portNo,
                                             resourceName,
                                             domainName, pRSASslCertStore, j);
        }

        retVal += SSL_CLI_GetALPN((0x1500000+(j*10)), pIpAddress, portNo,
                                  resourceName,
                                  domainName, pRSASslCertStore,
                                  protocols, 5, 1, j);

        retVal += SSL_CLI_GetALPN((0x1500001+(j*10)), pIpAddress, portNo,
                                  resourceName,
                                  domainName, pRSASslCertStore,
                                  protocols + 1, 4, 0, j);

        retVal += SSL_CLI_GetALPN((0x1500002+(j*10)), pIpAddress, portNo,
                                  resourceName,
                                  domainName, pRSASslCertStore,
                                  protocols + 2, 3, 1, j);

        retVal += SSL_CLI_GetALPN((0x1500003+(j*10)), pIpAddress, portNo,
                                  resourceName,
                                  domainName, pRSASslCertStore,
                                  protocols + 2, 1, 0, j);
    }

    return retVal;
}



/*------------------------------------------------------------------------*/

int SSL_CLI_SRP_Server_Test(const sbyte* pIpAddress,
                               ubyte2 portNo,
                               const char* domainName,
                               char* resourceName)
{
    /* hint 0x0016 - 0x0017 */
    int retVal = 0;
    int i, j;
    MSTATUS status;
    TCP_SOCKET mySocket;

    /* test connection for a while since the server takes some time to come
     up ( rng initialization) on some platforms */
    for (i = 0; i < 20; ++i)
    {
        status = TCP_CONNECT(&mySocket, (sbyte*) pIpAddress, portNo);
        TCP_CLOSE_SOCKET(mySocket);
        if ( OK == status)
        {
            break;
        }
        RTOS_sleepMS(1000); /* sleep for a second */
    }

    retVal += UNITTEST_TRUE(0, i < 20);
    if ( retVal) goto exit;

    /* test internal server port = PORTNUM */
    /* IF YOU GET SOME RSA DECRYPTION ERRORS (-7702) WITH THE ECDH_RSA CRYPTOSUITES,
     THE PROBLEM IS PROBABLY THAT A NEW SERVER WAS ADDED TO THE TEST THAT USES THE SAME
     CERTIFICATES AS THE NORMAL SERVER AND IS ALSO TRYING TO CREATE THEM. SEE COMMENTS
     IN ssl_serv.c main() */

    for (i = 0; i < COUNTOF(gCipherDescs); ++i)
    {
        const char* cipherName = gCipherDescs[i].cipherName;
        /* exclude the preshared keys and SRP ones */
        if (!strstr(gCipherDescs[i].cipherName, "_PSK_") &&
            strstr(gCipherDescs[i].cipherName, "_SRP_"))
        {
            int rootCertIndex = kRSACertIdx;
            /* for ECC crypto with no RSA certificates */
            if ( 0xC000 == (gCipherDescs[i].cipherId & 0xC000))
            {
                if ( !strstr( cipherName, "RSA"))
                {
                    rootCertIndex = kECC256CertIdx;
                }
            }

            for (j = gCipherDescs[i].minSSLVer; j <= TLS12_MINORVERSION; ++j)
            {
                /* Note: for TLS 1.2, the client send the signature extension so the server can return
                 any certificate it wants that matches the extension and the cipher.
                 In this test case, the server will return ECDHCert256CA.der for the ECDH_RSA cipher suites.
                 Bottom of p 49 of the RFC 5246: DH_DSS, DH_RSA, ECDH_ECDSA and ECDH_RSA are "historical" */
                if (TLS12_MINORVERSION == j &&
                    0xC000 == (gCipherDescs[i].cipherId & 0xC000))
                {
                    if ( 0 != strstr( cipherName, "ECDH_RSA"))
                    {
                        rootCertIndex = kECC256CertIdx;
                    }
                }
                if (!strstr(cipherName, "RSA"))
                {
                    retVal += SSL_CLI_GetPage(CIPHER_HINT(0x0015+j,i),
                                              gCipherDescs+i,
                                              pIpAddress, portNo, resourceName,
                                              rootCertIndex, domainName, MOCANA, j,
                                              pRSASslCertStore);
                }

                if (TLS12_MINORVERSION == j)
                {
                    /* test to verify that we use 1.2 is the protocol is not set */
                    retVal += SSL_CLI_GetPage(CIPHER_HINT(0x0016,i),
                                              gCipherDescs + i,
                                              pIpAddress, portNo, resourceName,
                                              rootCertIndex, domainName, MOCANA, -1,
                                              pRSASslCertStore);
                }
            }
        }
    }


exit:
    
    return retVal;
}


/*------------------------------------------------------------------------*/

int SSL_CLI_RSA_OpenSSL_Server_Test( ubyte4 opensslVersion,
                                 const sbyte* pIpAddress4or6,
                                 ubyte2 portNo,
                                 const char* domainName,
                                 char* resourceName)
{
    /* hint 0x0200 - 0x02F0 */

    int retVal = 0;
    int i, j, maxSSLVer, supportECC;

    if (opensslVersion >= 1000002)
    {
        maxSSLVer = TLS12_MINORVERSION;
        supportECC = 1;
    }
    else if  (opensslVersion >= 1000000) /* support for TLS1.0 and for ECC */
    {
        maxSSLVer = TLS10_MINORVERSION;
        supportECC = 1;
    }
    else
    {
        maxSSLVer = TLS10_MINORVERSION;
        supportECC = 0;
    }

    if (supportECC)
    {
        for (i = 0; i < COUNTOF(gCipherDescs); ++i)
        {
            const char* cipherName = gCipherDescs[i].cipherName;
            /* exclude the preshared keys, SRP, CCM and POLY1305 ones */
            if (!strstr(cipherName, "_PSK_") && !strstr(cipherName, "_SRP_") &&
                !strstr(cipherName, "_CCM") && !strstr(cipherName, "POLY1305"))
            {
                /* This server has a RSA cert -- all ciphers should succeed except
                 for the ones with either ECDSA or ECDH which requires an ECC cert
                 unless of course it's an ANON cipher */

                if ( !strstr(cipherName, "_ECDH_ANON_") &&
                    (strstr(cipherName, "_ECDH_") || strstr(cipherName, "_ECDSA_")))
                {
                    for (j = gCipherDescs[i].minSSLVer; j <= maxSSLVer; ++j)
                    {

                        retVal += SSL_CLI_VerifyUnableToConnectEx(CIPHER_HINT(0x200+j,i),
                                                                gCipherDescs + i,
                                                                pIpAddress4or6,
                                                                portNo, domainName, j,
                                                                ERR_TCP_SOCKET_CLOSED,
                                                                pRSASslCertStore);
                    }

                }
                else
                {
                    for (j = gCipherDescs[i].minSSLVer; j <= maxSSLVer; ++j)
                    {

                        retVal += SSL_CLI_GetPage(CIPHER_HINT(0x210+j,i),
                                                  gCipherDescs + i,
                                                  pIpAddress4or6,
                                                  portNo, resourceName,
                                                  kOpenSSLCertIdx,
                                                  domainName, OPENSSL, j,
                                                  pRSASslCertStore);
                    }
                }
            }
        }
#if MIN_SSL_MINORVERSION==SSL3_MINORVERSION
        /* test the ARC4 cipher */
        for (j = 0; j <= TLS10_MINORVERSION; ++j)
        {
            retVal += SSL_CLI_GetPage(CIPHER_HINT(0x220+j,i),
                                      &gArc4CipherDesc,
                                      pIpAddress4or6, portNo,
                                      resourceName,
                                      kOpenSSLCertIdx,
                                      domainName, OPENSSL, j,
                                      pRSASslCertStore);
        }
#endif
    }
    else
    {
        for (i = 0; i < COUNTOF(gCipherDescs); ++i)
        {
            if (gCipherDescs[i].cipherId <= 0x003A )
            {
                for (j = gCipherDescs[i].minSSLVer; j <= TLS10_MINORVERSION; ++j)
                {
                    retVal += SSL_CLI_GetPage(CIPHER_HINT(0x230+j,i),
                                              gCipherDescs + i,
                                              pIpAddress4or6,
                                              portNo, resourceName,
                                              kOpenSSLCertIdx,
                                              domainName, OPENSSL, j,
                                              pRSASslCertStore);
                }
            }
        }
#if MIN_SSL_MINORVERSION==SSL3_MINORVERSION
        /* test the ARC4 cipher */
        for (j = 0; j <= TLS10_MINORVERSION; ++j)
        {
            retVal += SSL_CLI_GetPage(CIPHER_HINT(0x240+j,i),
                                      &gArc4CipherDesc,
                                      pIpAddress4or6, portNo,
                                      resourceName, kOpenSSLCertIdx,
                                      domainName, OPENSSL, j,
                                      pRSASslCertStore);
        }
#endif

    }

    /* padding test. We take advantage of the fact that the server sends
       back part of the resource back as its message. By increasing the size,
       we should go through all the padding */

    for (i = 0; i < 8; ++i)
    {
        /* use 3DES (0x000A) as the cipher */
        /* append an X to the resourceName */
        resourceName[4+i] = (sbyte) ('A'+i);

        retVal += SSL_CLI_GetPage(CIPHER_HINTX(0x251, g3DESCipherDesc.cipherId),
                                  &g3DESCipherDesc,
                                  pIpAddress4or6,
                                  portNo, resourceName, kOpenSSLCertIdx,
                                  domainName, OPENSSL, TLS10_MINORVERSION,
                                  pRSASslCertStore);

        retVal += SSL_CLI_GetPage(CIPHER_HINTX(0x250, g3DESCipherDesc.cipherId),
                                  &g3DESCipherDesc,
                                  pIpAddress4or6,
                                  portNo, resourceName, kOpenSSLCertIdx,
                                  domainName, OPENSSL, SSL3_MINORVERSION,
                                  pRSASslCertStore);

    }


    return retVal;
}


/*------------------------------------------------------------------------*/

int SSL_CLI_ECC_OpenSSL_Server_Test( ubyte4 opensslVersion,
                                    const sbyte* pIpAddress4or6,
                                    ubyte2 portNo,
                                    const char* domainName,
                                    char* resourceName)
{
    /* hint 0x0300 - 0x03F0 */

    int retVal = 0;
    int i, j, maxSSLVer;

    if (opensslVersion >= 1000002)
    {
        maxSSLVer = TLS12_MINORVERSION;
    }
    else if  (opensslVersion >= 1000000) /* support for TLS1.0 and for ECC  */
    {
        maxSSLVer = TLS10_MINORVERSION;
    }
    else
    {
        return 0;
    }

    for (i = 0; i < COUNTOF(gCipherDescs); ++i)
    {
        const char* cipherName = gCipherDescs[i].cipherName;
        /* exclude the preshared keys, SRP, CCM and Poly1305 ones */
        if (!strstr(cipherName, "_PSK_") && !strstr(cipherName, "_SRP_")
            && !strstr(cipherName, "_CCM") && !strstr(cipherName, "POLY1305"))
        {
            /* This server has an ECC cert -- all ciphers should succeed except
             for the ones which requires an RSA cert and the ones not yet
             implemented by OpenSSL TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 0xC0AE */

            if (strstr(cipherName, "_RSA_"))
            {
                for (j = gCipherDescs[i].minSSLVer; j <= maxSSLVer; ++j)
                {

                    retVal += SSL_CLI_VerifyUnableToConnectEx(CIPHER_HINT(0x300+j,i),
                                                            gCipherDescs + i,
                                                            pIpAddress4or6,
                                                            portNo, domainName, j,
                                                            ERR_TCP_SOCKET_CLOSED,
                                                            pRSASslCertStore);
                }

            }
            else
            {
                for (j = gCipherDescs[i].minSSLVer; j <= maxSSLVer; ++j)
                {

                    retVal += SSL_CLI_GetPage(CIPHER_HINT(0x310+j,i),
                                              gCipherDescs + i,
                                              pIpAddress4or6,
                                              portNo, resourceName,
                                              kOpenSSLECCCertIdx,
                                              domainName, OPENSSL, j,
                                              pRSASslCertStore);
                }
            }
        }
    }


    return retVal;
}


/*------------------------------------------------------------------------*/

int SSL_CLI_PSK_OpenSSL_Server_Test( ubyte4 opensslVersion,
                                    const sbyte* pIpAddress4or6,
                                    ubyte2 portNo,
                                    const char* domainName,
                                    char* resourceName)
{
    /* hint 0x0400 - 0x0440 */

    int retVal = 0;
    int j, maxSSLVer;

    if (opensslVersion >= 1000002)
    {
        maxSSLVer = TLS12_MINORVERSION;
    }
    else
    {
        maxSSLVer = TLS10_MINORVERSION;
    }

    /* openssl has only 4 ciphers, 3 of which we support (no RC4 support) */
    /* so we don't iterate over ciphers */

    for (j = MIN_SSL_MINORVERSION; j <= maxSSLVer; ++j)
    {

        retVal += SSL_CLI_GetPage(CIPHER_HINT(0x400, 0) + j,
                                  NULL, /* no cipher set */
                                  pIpAddress4or6,
                                  portNo, resourceName,
                                  kRSACertIdx, domainName, OPENSSL, j,
                                  pRSASslCertStore);
    }
    return retVal;
}

/*------------------------------------------------------------------------*/

int SSL_CLI_Wildchar_OpenSSL_Server_Test( ubyte4 opensslVersion,
                                    const sbyte* pIpAddress4or6,
                                    ubyte2 portNo,
                                    const char* domainName,
                                    char* resourceName)
{
    /* hint 0x0450 - 0x04F0 */

    int retVal = 0;
    int j, maxSSLVer;

    if (opensslVersion >= 1000002)
    {
        maxSSLVer = TLS12_MINORVERSION;
    }
    else
    {
        maxSSLVer = TLS10_MINORVERSION;
    }

    /*  we don't iterate over ciphers -- that's not the point here */

    for (j = MIN_SSL_MINORVERSION; j <= maxSSLVer; ++j)
    {

        retVal += SSL_CLI_GetPage(CIPHER_HINT(0x400, 0) + j,
                                  NULL, /* no cipher set */
                                  pIpAddress4or6,
                                  portNo, resourceName,
                                  kOpenSSLCertIdx,
                                  domainName, OPENSSL, j,
                                  pRSASslCertStore);
    }
    return retVal;
}


/*------------------------------------------------------------------------*/

int SSL_CLI_Expired_Cert_Server_Test(const sbyte* pIpAddress4or6,
                                     ubyte2 portNo,
                                     const char* domainName,
                                     char* resourceName )
{
    /* hint 0x0500 - 0x05F0 */

    int retVal = 0;
    int i;
    MSTATUS status;
    TCP_SOCKET mySocket;

    for (i = 0; i < 20; ++i)
    {
        status = TCP_CONNECT(&mySocket, (sbyte *)pIpAddress4or6, portNo);

        TCP_CLOSE_SOCKET(mySocket);
        if ( OK == status)
        {
            break;
        }
        RTOS_sleepMS(1000); /* sleep for a second */
    }

    retVal += UNITTEST_TRUE(0, i < 20);
    if ( retVal) goto exit;

    /* test internal server with expired certificates port = 1446 */
    for (i = 0; i < COUNTOF(gCipherDescs); ++i)
    {
        /* only the leaf certificates are expired so test only the relevant configs */
        if (gCipherDescs[i].cipherId >= 0xC00B &&
            gCipherDescs[i].cipherId <= 0xC00F)
        {
            retVal += SSL_CLI_VerifyExpiredCert(CIPHER_HINT(0x500,i),
                                                gCipherDescs + i,
                                                (sbyte *)pIpAddress4or6,
                                                portNo, resourceName,
                                                kExpCertIdx, domainName, MOCANA,
                                                TLS10_MINORVERSION,
                                                pRSASslCertStore);
        }
        if(TLS13_MINORVERSION == gCipherDescs[i].minSSLVer)
        {
            retVal += SSL_CLI_VerifyExpiredCert(CIPHER_HINT(0x502,i),
                                                gCipherDescs + i,
                                                (sbyte *)pIpAddress4or6,
                                                portNo, resourceName,
                                                kExpCertIdx, domainName, MOCANA,
                                                TLS13_MINORVERSION,
                                                pRSASslCertStore);
        }
    }

exit:

    return retVal;
}


/*------------------------------------------------------------------------*/

int SSL_CLI_MutAuth_Server_Test(const sbyte* pIpAddress4or6,
                                ubyte2 portNo,
                                const char* domainName,
                                char* resourceName )
{

    /* hint 0x0600 - 0x06F0 */

    int retVal = 0;
    int i, j;
    MSTATUS status;
    TCP_SOCKET mySocket;
    char *pEnv = NULL;
    ubyte opensslTest = 0;

    pEnv = getenv("ENABLE_OPENSSL_INTEROPERABILITY_TEST");
    if (pEnv != NULL)
    {
        if (1 == atoi(pEnv))
            opensslTest = 1;
    }

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

    /* test internal server that request mutual authentication = 1447 */
    for (i = 0; i < COUNTOF(gCipherDescs); ++i)
    {
        const char* cipherName = gCipherDescs[i].cipherName;

        /* exclude the preshared keys and SRP ones */
        if (!strstr(cipherName, "_PSK_") && !strstr(cipherName, "_SRP_") && (!strstr(cipherName, "_ANON_") && (1 == opensslTest)))
        {
            int rootCertIndex = kRSACertIdx;

            /* for ECC crypto with no RSA certificates */
            if ( 0xC000 == (gCipherDescs[i].cipherId & 0xC000))
            {
                if ( !strstr( cipherName, "RSA"))
                {
                    rootCertIndex = kECC256CertIdx;
                }
            }

            for (j = gCipherDescs[i].minSSLVer; j <= TLS12_MINORVERSION; ++j)
            {
                /* Note: for TLS 1.2, the client send the signature extension so the server can return
                   any certificate it wants that matches the extension and the cipher.
                   In this test case, the server will return ECDHCert256CA.der for the ECDH_RSA cipher suites.
                   Bottom of p 49 of the RFC 5246: DH_DSS, DH_RSA, ECDH_ECDSA and ECDH_RSA are "historical" */
                if (3 == j &&  0xC000 == (gCipherDescs[i].cipherId & 0xC000))
                {
                    if ( 0 != strstr( cipherName, "ECDH_RSA"))
                    {
                        rootCertIndex = kECC256CertIdx;
                    }
                }

                retVal += SSL_CLI_GetPage(CIPHER_HINT(0x600+j,i),
                                          gCipherDescs + i,
                                          pIpAddress4or6,
                                          portNo, resourceName,
                                          rootCertIndex, domainName, MOCANA, j,
                                          pRSASslCertStore);
                /* switch to a ECC client certificate */
                retVal += SSL_CLI_GetPage(CIPHER_HINT(0x610+j,i),
                                          gCipherDescs + i,
                                          pIpAddress4or6,
                                          portNo, resourceName,
                                          rootCertIndex, domainName, MOCANA, j,
                                          pECCSslCertStore);
#if defined(__ENABLE_DIGICERT_TAP__)
                /* switch to a TAP client key and certificate */
                retVal += SSL_CLI_GetPage(CIPHER_HINT(0x610+j,i),
                                          gCipherDescs + i,
                                          pIpAddress4or6,
                                          portNo, resourceName,
                                          rootCertIndex, domainName, MOCANA, j,
                                          pTAPSslCertStore);
#endif
#if 0
                /* switch to an invalid client certificate */
                retVal += SSL_CLI_VerifyMutAuthRejected( CIPHER_HINT(0x620+j,i),
                                                         gCipherDescs + i,
                                                         gCipherDescs[i].cipherName,
                                                         pIpAddress4or6,
                                                         portNo, resourceName,
                                                         rootCertIndex, domainName,
                                                         MOCANA, j, pUnknownSslCertStore);
#endif
            }
        }
    }
exit:

    return retVal;
}


/*------------------------------------------------------------------------*/

int SSL_CLI_ECC_MutAuth_OpenSSL_Server_Test(ubyte4 opensslVersion,
                                        const sbyte* pIpAddress4or6,
                                        ubyte2 portNo,
                                        const char* domainName,
                                        char* resourceName )
{
    /* hint 0x0700 - 0x07F0 */

    int retVal = 0;
    int i, j, maxSSLVer;


    if (opensslVersion >= 1000002)
    {
        maxSSLVer = TLS12_MINORVERSION;
    }
    else if  (opensslVersion >= 1000000) /* support for TLS1.0 and for ECC */
    {
        maxSSLVer = TLS10_MINORVERSION;
    }
    else
    {
        return 0;
    }

    for (i = 0; i < COUNTOF(gCipherDescs); ++i)
    {
        const char* cipherName = gCipherDescs[i].cipherName;
        /* exclude the preshared keys, SRP, CCM and POLY1305 ones */
        if (!strstr(cipherName, "_PSK_") && !strstr(cipherName, "_SRP_")
            && !strstr(cipherName, "_CCM") && !strstr(cipherName, "POLY1305") )
        {
            /* This server has an ECC cert -- all ciphers should succeed except
             for the anonymous ones, the ones which requires an RSA cert and
             the ones not yet implemented by OpenSSL:
             TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 0xC0AE */

            if (strstr(cipherName, "_RSA_") || strstr( cipherName, "_ANON_"))
            {
                for (j = gCipherDescs[i].minSSLVer; j <= maxSSLVer; ++j)
                {

                    retVal += SSL_CLI_VerifyUnableToConnect(CIPHER_HINT(0x700+j,i),
                                                            gCipherDescs + i,
                                                            pIpAddress4or6,
                                                            portNo,
                                                            domainName, j,
                                                            pRSASslCertStore);
                }

            }
            else
            {
                for (j = gCipherDescs[i].minSSLVer; j <= maxSSLVer; ++j)
                {

                    retVal += SSL_CLI_GetPage(CIPHER_HINT(0x710+j,i),
                                              gCipherDescs + i,
                                              pIpAddress4or6,
                                              portNo, resourceName,
                                              kOpenSSLECCCertIdx,
                                              domainName, OPENSSL, j,
                                              pRSASslCertStore);
                }
            }
        }
    }


    /* switch to a ECC client certificate */

    for (i = 0; i < COUNTOF(gCipherDescs); ++i)
    {
        const char* cipherName = gCipherDescs[i].cipherName;
        /* exclude the preshared keys, SRP, CCM and POLY1305 ones */
        if (!strstr(cipherName, "_PSK_") &&
            !strstr(cipherName, "_SRP_") &&
            !strstr(cipherName, "_CCM") &&
            !strstr(cipherName, "POLY1305"))
        {
            /* This server has an ECC cert -- all ciphers should succeed except
             for the anonymous ones, the ones which requires an RSA cert and
             the ones not yet implemented by OpenSSL:
             TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 0xC0AE */

            if (strstr(cipherName, "_RSA_") || strstr( cipherName, "_ANON_"))
            {
                for (j = gCipherDescs[i].minSSLVer; j <= maxSSLVer; ++j)
                {

                    retVal += SSL_CLI_VerifyUnableToConnect(CIPHER_HINT(0x720+j,i),
                                                            gCipherDescs + i,
                                                            pIpAddress4or6,
                                                            portNo,
                                                            domainName, j,
                                                            pECCSslCertStore);
                }

            }
            else
            {
                for (j = gCipherDescs[i].minSSLVer; j <= maxSSLVer; ++j)
                {

                    retVal += SSL_CLI_GetPage(CIPHER_HINT(0x730+j,i),
                                              gCipherDescs + i,
                                              pIpAddress4or6,
                                              portNo, resourceName,
                                              kOpenSSLECCCertIdx,
                                              domainName, OPENSSL, j,
                                              pECCSslCertStore);
                }
            }
        }
    }


    return retVal;
}



/*------------------------------------------------------------------------*/

int SSL_CLI_RSA_MutAuth_OpenSSL_Server_Test(ubyte4 opensslVersion,
                                            const sbyte* pIpAddress4or6,
                                            ubyte2 portNo,
                                            const char* domainName,
                                            char* resourceName )
{
    /* hint 0x0800 - 0x08F0 */

    int retVal = 0;
    int i, j, maxSSLVer;


    if (opensslVersion >= 1000002)
    {
        maxSSLVer = TLS12_MINORVERSION;
    }
    else if  (opensslVersion >= 1000000) /* support for TLS1.0 and for ECC */
    {
        maxSSLVer = TLS10_MINORVERSION;
    }
    else
    {
        return 0;
    }

    for (i = 0; i < COUNTOF(gCipherDescs); ++i)
    {
        const char* cipherName = gCipherDescs[i].cipherName;
        /* exclude the preshared keys, SRP, CCM and POLY1305 ones */
        if (!strstr(cipherName, "_PSK_") &&
            !strstr(cipherName, "_SRP_") &&
            !strstr(cipherName, "_CCM") &&
            !strstr(cipherName, "POLY1305"))
        {
            /* This server has an RSA cert -- all ciphers should succeed except
             for the anonymous ones, the ones which requires an ECC cert and
             the ones not yet implemented by OpenSSL */
            /* exclude the preshared keys one */

            if (strstr(cipherName, "_ECDSA_") || strstr(cipherName, "_ECDH_") ||
                strstr( cipherName, "_ANON_") )
            {
                for (j = gCipherDescs[i].minSSLVer; j <= maxSSLVer; ++j)
                {

                    retVal += SSL_CLI_VerifyUnableToConnect(CIPHER_HINT(0x800+j,i),
                                                            gCipherDescs + i,
                                                            pIpAddress4or6,
                                                            portNo,
                                                            domainName, j,
                                                            pRSASslCertStore);
                }

            }
            else
            {
                for (j = gCipherDescs[i].minSSLVer; j <= maxSSLVer; ++j)
                {

                    retVal += SSL_CLI_GetPage(CIPHER_HINT(0x810+j,i),
                                              gCipherDescs + i,
                                              pIpAddress4or6,
                                              portNo, resourceName,
                                              kOpenSSLCertIdx,
                                              domainName, OPENSSL, j,
                                              pRSASslCertStore);
                }
            }
        }
    }


    /* switch to a ECC client certificate -- will work only for
     TLS1.0 and above */

    for (i = 0; i < COUNTOF(gCipherDescs); ++i)
    {
        const char* cipherName = gCipherDescs[i].cipherName;
        /* exclude the preshared keys, SRP, CCM and POLY1305 ones */
        if (!strstr(cipherName, "_PSK_") &&
            !strstr(cipherName, "_SRP_") &&
            !strstr(cipherName, "_CCM") &&
            !strstr(cipherName, "POLY1305"))
        {
            /* This server has an ECC cert -- all ciphers should succeed except
             for the anonymous ones, the ones which requires an ECC cert and
             the ones not yet implemented by OpenSSL */

            int startSSLVer = gCipherDescs[i].minSSLVer;

            /* if we are allowing SSL3, make sure we don't use SSL3
             for this test */
#if MIN_SSL_MINORVERSION==SSL3_MINORVERSION
            if ( gCipherDescs[i].minSSLVer == 0)
            {
                startSSLVer = TLS10_MINORVERSION;
            }
#endif
            if (strstr(cipherName, "_ECDSA_") || strstr(cipherName, "_ECDH_") ||
                strstr( cipherName, "_ANON_") )
            {
                for (j = startSSLVer; j <= maxSSLVer; ++j)
                {

                    retVal += SSL_CLI_VerifyUnableToConnect(CIPHER_HINT(0x820+j,i),
                                                            gCipherDescs + i,
                                                            pIpAddress4or6,
                                                            portNo,
                                                            domainName, j,
                                                            pECCSslCertStore);
                }

            }
            else
            {
                for (j = startSSLVer; j <= maxSSLVer; ++j)
                {

                    retVal += SSL_CLI_GetPage(CIPHER_HINT(0x830+j,i),
                                              gCipherDescs + i,
                                              pIpAddress4or6,
                                              portNo, resourceName,
                                              kOpenSSLCertIdx,
                                              domainName, OPENSSL, j,
                                              pECCSslCertStore);
                }
            }
        }
    }


    return retVal;
}


/*------------------------------------------------------------------------*/

int SSL_CLI_VersionSet_Server_Test(const sbyte* pIpAddress4or6,
                                   ubyte2 portNo,
                                   const char* domainName,
                                   char* resourceName)
{
    /* hint 0x0900 - 0x09F0 */

    int retVal = 0;
    int i;
    MSTATUS status;
    TCP_SOCKET mySocket;

    /* test internal server to verify SSL_SET_VERSION works server on port portNo */
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
    /* tests case 1 :
     * configure the server to accept the 1.3, should fail for version 0 and 1.0, 1.1, 1.2 */
    /* send tls1.3 config cmd */
    retVal += SSL_CLI_SendVersionCmd(CIPHER_HINT(0x900, 0),
                                     pIpAddress4or6, portNo,
                                     resourceName,
                                     domainName, pRSASslCertStore,
                                     TLS13_MINORVERSION);

    retVal += SSL_CLI_VerifyUnableToConnectEx(CIPHER_HINT(0x900, 0), NULL,
                                              pIpAddress4or6, portNo,
                                              domainName, SSL3_MINORVERSION,
                                              ERR_TCP_SOCKET_CLOSED,
                                              pRSASslCertStore);

    retVal += SSL_CLI_VerifyUnableToConnectEx(CIPHER_HINT(0x901, 0), NULL,
                                              pIpAddress4or6, portNo,
                                              domainName, TLS10_MINORVERSION,
                                              ERR_TCP_SOCKET_CLOSED,
                                              pRSASslCertStore);

    retVal += SSL_CLI_VerifyUnableToConnectEx(CIPHER_HINT(0x902, 0), NULL,
                                              pIpAddress4or6, portNo,
                                              domainName, TLS11_MINORVERSION,
                                              ERR_TCP_SOCKET_CLOSED,
                                              pRSASslCertStore);

    retVal += SSL_CLI_VerifyUnableToConnectEx(CIPHER_HINT(0x902, 0), NULL,
                                              pIpAddress4or6, portNo,
                                              domainName, TLS12_MINORVERSION,
                                              ERR_TCP_SOCKET_CLOSED,
                                              pRSASslCertStore);

    retVal += SSL_CLI_GetPage(CIPHER_HINTX(0x912, gTls13CipherDesc.cipherId),
                              &gTls13CipherDesc,
                              pIpAddress4or6, portNo,
                              resourceName, kRSACertIdx, domainName, MOCANA,
                              TLS13_MINORVERSION, pRSASslCertStore);

    /* tests case 2 :
     * configure the server to accept the 1.2, should fail for version 0 and 1.0, 1.1, 1.3 */
    /* send tls1.2 config cmd */
    retVal += SSL_CLI_SendVersionCmd(CIPHER_HINT(0x900, 0),
                                     pIpAddress4or6, portNo,
                                     resourceName,
                                     domainName, pRSASslCertStore,
                                     TLS12_MINORVERSION);

    retVal += SSL_CLI_VerifyUnableToConnectEx(CIPHER_HINT(0x900, 0), NULL,
                                              pIpAddress4or6, portNo,
                                              domainName, SSL3_MINORVERSION,
                                              ERR_TCP_SOCKET_CLOSED,
                                              pRSASslCertStore);

    retVal += SSL_CLI_VerifyUnableToConnectEx(CIPHER_HINT(0x901, 0), NULL,
                                              pIpAddress4or6, portNo,
                                              domainName, TLS10_MINORVERSION,
                                              ERR_TCP_SOCKET_CLOSED,
                                              pRSASslCertStore);

    retVal += SSL_CLI_VerifyUnableToConnectEx(CIPHER_HINT(0x902, 0), NULL,
                                              pIpAddress4or6, portNo,
                                              domainName, TLS11_MINORVERSION,
                                              ERR_TCP_SOCKET_CLOSED,
                                              pRSASslCertStore);

    retVal += SSL_CLI_GetPage(CIPHER_HINTX(0x911, gVersionSetCipherDesc.cipherId),
                              &gVersionSetCipherDesc,
                              pIpAddress4or6, portNo,
                              resourceName, kRSACertIdx, domainName, MOCANA,
                              TLS12_MINORVERSION, pRSASslCertStore);

    retVal += SSL_CLI_VerifyUnableToConnectEx(CIPHER_HINT(0x912, 0), NULL,
                              pIpAddress4or6, portNo,
                              domainName, TLS13_MINORVERSION,
                              ERR_TCP_SOCKET_CLOSED,
                              pRSASslCertStore);

    /* tests case 3 :
     * configure the server to accept the 1.1, should fail for version 0 and 1.0. 1.2 and 1.3 */
    /* send tls1.1 config cmd */
    retVal += SSL_CLI_SendVersionCmd(CIPHER_HINT(0x900, 0),
                                     pIpAddress4or6, portNo,
                                     resourceName,
                                     domainName, pRSASslCertStore,
                                     TLS11_MINORVERSION);

    /* the server at 1449 is set to accept only TLS1.1 */
    /* should fail for version 0 and 1 */
    retVal += SSL_CLI_VerifyUnableToConnectEx(CIPHER_HINT(0x900, 0), NULL,
                                              pIpAddress4or6, portNo,
                                              domainName, SSL3_MINORVERSION,
                                              ERR_TCP_SOCKET_CLOSED,
                                              pRSASslCertStore);

    retVal += SSL_CLI_VerifyUnableToConnectEx(CIPHER_HINT(0x901, 0), NULL,
                                              pIpAddress4or6, portNo,
                                              domainName, TLS10_MINORVERSION,
                                              ERR_TCP_SOCKET_CLOSED,
                                              pRSASslCertStore);

    retVal += SSL_CLI_GetPage(CIPHER_HINTX(0x911, gVersionSetCipherDesc.cipherId),
                              &gVersionSetCipherDesc,
                              pIpAddress4or6, portNo,
                              resourceName, kRSACertIdx, domainName, MOCANA,
                              TLS11_MINORVERSION, pRSASslCertStore);

    retVal += SSL_CLI_VerifyUnableToConnectEx(CIPHER_HINT(0x902, 0), NULL,
                                              pIpAddress4or6, portNo,
                                              domainName, TLS12_MINORVERSION,
                                              ERR_SSL_PROTOCOL_VERSION,
                                              pRSASslCertStore);

    retVal += SSL_CLI_VerifyUnableToConnectEx(CIPHER_HINT(0x912, 0), NULL,
                              pIpAddress4or6, portNo,
                              domainName, TLS13_MINORVERSION,
                              ERR_TCP_SOCKET_CLOSED,
                              pRSASslCertStore);

    /* tests case 4 :
     * configure the server to accept the 1.0, should fail for version 0 and 1.0, 1.1, 1.2, 1.3 */
    /* send tls1.0 config cmd */
    retVal += SSL_CLI_SendVersionCmd(CIPHER_HINT(0x900, 0),
                                     pIpAddress4or6, portNo,
                                     resourceName,
                                     domainName, pRSASslCertStore,
                                     TLS10_MINORVERSION);

    retVal += SSL_CLI_VerifyUnableToConnectEx(CIPHER_HINT(0x900, 0), NULL,
                                              pIpAddress4or6, portNo,
                                              domainName, SSL3_MINORVERSION,
                                              ERR_TCP_SOCKET_CLOSED,
                                              pRSASslCertStore);

    retVal += SSL_CLI_GetPage(CIPHER_HINTX(0x911, gVersionSetCipherDesc.cipherId),
                              &gVersionSetCipherDesc,
                              pIpAddress4or6, portNo,
                              resourceName, kRSACertIdx, domainName, MOCANA,
                              TLS10_MINORVERSION, pRSASslCertStore);

    retVal += SSL_CLI_VerifyUnableToConnectEx(CIPHER_HINT(0x902, 0), NULL,
                                              pIpAddress4or6, portNo,
                                              domainName, TLS11_MINORVERSION,
                                              ERR_SSL_PROTOCOL_VERSION,
                                              pRSASslCertStore);
    retVal += SSL_CLI_VerifyUnableToConnectEx(CIPHER_HINT(0x902, 0), NULL,
                                              pIpAddress4or6, portNo,
                                              domainName, TLS12_MINORVERSION,
                                              ERR_SSL_PROTOCOL_VERSION,
                                              pRSASslCertStore);

    retVal += SSL_CLI_VerifyUnableToConnectEx(CIPHER_HINT(0x912, 0), NULL,
                              pIpAddress4or6, portNo,
                              domainName, TLS13_MINORVERSION,
                              ERR_TCP_SOCKET_CLOSED,
                              pRSASslCertStore);

exit:

    return retVal;
}


/*------------------------------------------------------------------------*/

int SSL_CLI_SSL3_Verify_635_Server_Test(const sbyte* pIpAddress4or6,
                                        ubyte2 portNo,
                                        const char* domainName,
                                        char* resourceName )
{
    /* hint 0x0A00 - 0x0AF0 */

    int retVal = 0;
    int i;

    /* the 635 "server" can only talk SSLv3 */
    for (i = 0; i < COUNTOF(gCipherDescs); ++i)
    {
        /* only old v3 ciphers */
        if (gCipherDescs[i].cipherId <= 0x003A )
        {
            if (MIN_SSL_MINORVERSION <= 0)
            {
                retVal += SSL_CLI_GetPage(CIPHER_HINT(0xA00,i),
                                          gCipherDescs + i,
                                          pIpAddress4or6,
                                          portNo, resourceName,
                                          kOpenSSLCertIdx,
                                          domainName, OPENSSL, -10,
                                          pRSASslCertStore);
                /* note the special value of -10: don't set SSL version,
                 expect SSLv3 */
            }
            else
            {
                /* we should fail with ERR_SSL_PROTOCOL_VERSION since
                   this server only talks SSL 3.0 */
                retVal += SSL_CLI_VerifyUnableToConnectEx(CIPHER_HINTX(0xA00, i),
                                                          gCipherDescs + i,
                                                          pIpAddress4or6, portNo,
                                                          domainName, -1,
                                                          ERR_SSL_PROTOCOL_VERSION,
                                                          pRSASslCertStore);
            }
        }
    }

    return retVal;
}


/*------------------------------------------------------------------------*/

int SSL_CLI_SmallKeyServer_Test(const sbyte* pIpAddress4or6, ubyte2 portNo,
                                const char* domainName)
{
    /* hint 0x0B00 - 0x0BF0 */

    int retVal = 0;
    int i;
    MSTATUS status;
    TCP_SOCKET mySocket;

    /* test internal server to verify client rejects small key on port portNo */
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

    /* need to specify both domain name (otherwise we fail early because of non
     match with the cert) */
    /* make sure we select ciphers that can be signed with the small RSA key:
     no big hashes */
    for (i = 0; i < COUNTOF(gCipherDescs); ++i)
    {
        /* use only TLS1.0 and below ciphers that are supported by
         all versions of OpenSSL */
        if (gCipherDescs[i].minSSLVer <= 1)
        {
            const char* name = gCipherDescs[i].cipherName;

            /* only RSA ciphers. Filter out some other ciphers
             where the OpenSSL server repors no cipher in common */
            if ( strstr(name, "_RSA_") &&
                !strstr(name, "_SHA256") &&
                !strstr(name, "_SHA384") &&
                !strstr(name, "_PSK_") &&
                !strstr(name, "_SRP_") &&
                !strstr(name, "_ECDH"))
            {
                retVal += SSL_CLI_VerifyUnableToConnectEx(CIPHER_HINT(0xB00 + MIN_SSL_MINORVERSION, i),
                                                          gCipherDescs + i,
                                                          pIpAddress4or6,
                                                          portNo, domainName,
                                                          MIN_SSL_MINORVERSION,
                                                          ERR_SSL_RSA_KEY_SIZE,
                                                          pRSASslCertStore);
            }
        }
    }
exit:

    return retVal;
}



/*------------------------------------------------------------------------*/

int SSL_CLI_SmallDHKeyServer_Test(const sbyte* pIpAddress4or6, ubyte2 portNo,
                                  const char* domainName)
{
    /* hint 0x0C00 - 0x0CF0 */

    int retVal = 0;
    int i;
    MSTATUS status;
    TCP_SOCKET mySocket;

    /* test internal server to verify client rejects small key on port portNo */
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

    /* need to specify both domain name (otherwise we fail early because of non
     match with the cert) and the minimal SSL version (otherwise the OpenSSL
     server will gladly select a cipher with a big signature that cannot be
     signed with the small key it has and kills the SSL connection itself) */

    /* test all DH ciphers */
    for (i = 0; i < COUNTOF(gCipherDescs); ++i)
    {
        /* use only TLS1.0 and below ciphers that are supported by
         all versions of OpenSSL */
        if (gCipherDescs[i].minSSLVer <= 1)
        {
            const char* name = gCipherDescs[i].cipherName;

            if ((strstr(name, "_DHE_")  || strstr(name, "_DH_")) &&
                !strstr(name, "_PSK_") && !strstr(name, "_SRP_") )
            {
                retVal += SSL_CLI_VerifyUnableToConnectEx(CIPHER_HINT(0xC00 + MIN_SSL_MINORVERSION, i),
                                                          gCipherDescs + i,
                                                          pIpAddress4or6,
                                                          portNo, domainName,
                                                          MIN_SSL_MINORVERSION,
                                                          ERR_SSL_DH_KEY_SIZE,
                                                          pRSASslCertStore);
            }
        }
    }
exit:

    return retVal;
}


/*------------------------------------------------------------------------*/

int SSL_CLI_mbedTLS_Server_Test( const sbyte* pIpAddress4or6,
                                    ubyte2 portNo,
                                    const char* domainName,
                                    char* resourceName)
{
    /* hint 0x0D00 - 0x0DF0 */

    int retVal = 0;
    int i, j;

    for (i = 0; i < COUNTOF(gCipherDescs); ++i)
    {
        const char* cipherName = gCipherDescs[i].cipherName;

        /* nnon ECDSA ciphers only */
        if (!strstr(cipherName, "_ECDSA_") &&
            !strstr(cipherName, "_ECDH_") &&  /* cert has RSA public key */
            !strstr(cipherName, "DH_ANON_") &&  /* mbedTLS no support for DH_ANON and ECDH_ANON */
            !strstr(cipherName, "_SRP_") &&
            !strstr(cipherName, "POLY1305") )
        {
            for (j = gCipherDescs[i].minSSLVer; j <= TLS12_MINORVERSION; ++j)
            {
                if (gCipherDescs[i].cipherId >= 0x00AE &&
                    gCipherDescs[i].cipherId <= 0x00B9 &&
                    SSL3_MINORVERSION == j)
                {
                    /* these ciphers work properly for SSLv3 with our server -- however
                     they don't with mbedTLS server: they are disabled for SSLv3 and
                     attempts to activate them leads to an internal error --
                     contrarily with the ciphers 0x93, 0x94 and 0x95 --
                     so don't try them with SSLv3 */
                    continue;
                }

                retVal += SSL_CLI_GetPage(CIPHER_HINT(0xD00+j,i),
                                          gCipherDescs + i,
                                          pIpAddress4or6,
                                          portNo, resourceName,
                                          kOpenSSLCertIdx,
                                          domainName, MBEDTLS, j,
                                          pRSASslCertStore);
            }
        }
    }

    return retVal;
}


/*------------------------------------------------------------------------*/

int SSL_CLI_ECC_mbedTLS_Server_Test( const sbyte* pIpAddress4or6,
                                    ubyte2 portNo,
                                    const char* domainName,
                                    char* resourceName)
{
    /* hint 0x0E00 - 0x0EF0 */

    int retVal = 0;
    int i, j;

    for (i = 0; i < COUNTOF(gCipherDescs); ++i)
    {
        const char* cipherName = gCipherDescs[i].cipherName;

        /*  ECDSA ciphers only */
        if (strstr(cipherName, "_ECDSA_") && !strstr(cipherName, "POLY1305"))
        {
            for (j = gCipherDescs[i].minSSLVer; j <= TLS12_MINORVERSION; ++j)
            {

                retVal += SSL_CLI_GetPage(CIPHER_HINT(0xE00+j,i),
                                          gCipherDescs + i,
                                          pIpAddress4or6,
                                          portNo, resourceName,
                                          kOpenSSLECCCertIdx,
                                          domainName, MBEDTLS, j,
                                          pRSASslCertStore);
            }
        }
    }

    return retVal;
}


/*------------------------------------------------------------------------*/

int SSL_CLI_ECDH_RSA_OpenSSL_Server_Test( ubyte4 opensslVersion,
                                         const sbyte* pIpAddress4or6,
                                         ubyte2 portNo,
                                         const char* domainName,
                                         char* resourceName)
{
    /* hint 0x0F00 - 0x0FF0 */

    int retVal = 0;
    int i, j, maxSSLVer;

    if (opensslVersion >= 1000002)
    {
        maxSSLVer = TLS12_MINORVERSION;
    }
    else if  (opensslVersion >= 1000000) /* support for TLS1.0 and for ECC  */
    {
        maxSSLVer = TLS10_MINORVERSION;
    }
    else
    {
        return 0;
    }

    for (i = 0; i < COUNTOF(gCipherDescs); ++i)
    {
        const char* cipherName = gCipherDescs[i].cipherName;
        /* only ECDH-RSA ciphers */
        if (strstr(cipherName, "_ECDH_RSA_"))
        {
            for (j = gCipherDescs[i].minSSLVer; j <= maxSSLVer; ++j)
            {

                retVal += SSL_CLI_GetPage(CIPHER_HINT(0xF00+j,i),
                                          gCipherDescs + i,
                                          pIpAddress4or6,
                                          portNo, resourceName,
                                          kOpenSSLCertIdx,
                                          domainName, OPENSSL, j,
                                          pRSASslCertStore);
            }
        }
    }

    return retVal;
}


/*------------------------------------------------------------------------*/

int SSL_CLI_BadCertChain_Server_Test(const sbyte* pIpAddress4or6,
                                     ubyte2 portNo,
                                     const char* domainName)
{
    /* hint 0x0F00 - 0x0F0F */
    /* this server sends a whole certificate chain rooted at kRSABadCertChainCA
     which has a path length constraint of 1 */
    int retVal = 0;

    /* verify the path length constraint is checked if correct root cert */
    retVal += SSL_CLI_VerifyUnableToConnectEx(CIPHER_HINT(0xF00, 0),
                                              &g3DESCipherDesc,
                                              pIpAddress4or6, portNo,
                                              domainName, TLS10_MINORVERSION,
                                              ERR_CERT_INVALID_CERT_POLICY,
                                              pBadChainSslCertStore);

    /* the path length constraint is checked in another call if incorrect
     root cert  -- this is a way to verify that code path */
    retVal += SSL_CLI_VerifyUnableToConnectEx(CIPHER_HINT(0xF01, 0),
                                              &g3DESCipherDesc,
                                              pIpAddress4or6, portNo,
                                              domainName, TLS10_MINORVERSION,
                                              ERR_CERT_INVALID_CERT_POLICY,
                                              pRSASslCertStore);

    return retVal;
}


/*------------------------------------------------------------------------*/

int SSL_CLI_BadCertChain2_Server_Test(const sbyte* pIpAddress4or6,
                                      ubyte2 portNo,
                                      const char* domainName)
{
    /* hint 0x0F10 - 0x0F1F */

    int retVal = 0;

    /* this server sends a partial certificate chain rooted at kRSABadCertChainCA
     which has a path length constraint of 1. So even though we return that
     missing cert to the stack, it should still be rejected as invalid anchor */
    retVal += SSL_CLI_VerifyUnableToConnectEx(CIPHER_HINT(0xF10, 0),
                                              &g3DESCipherDesc,
                                              pIpAddress4or6, portNo,
                                              domainName, TLS10_MINORVERSION,
                                              ERR_CERT_CHAIN_NO_TRUST_ANCHOR,
                                              pBadChainSslCertStore);

    /* when we don't have the root cert, the connection should still fail
     but we cannot check the path length */
    retVal += SSL_CLI_VerifyUnableToConnectEx(CIPHER_HINT(0xF11, 0),
                                              &g3DESCipherDesc,
                                              pIpAddress4or6, portNo,
                                              domainName, TLS10_MINORVERSION,
                                              ERR_CERT_CHAIN_NO_TRUST_ANCHOR,
                                              pRSASslCertStore);
    return retVal;
}


/*------------------------------------------------------------------------*/

int SSL_CLI_BadCertChain3_Server_Test(const sbyte* pIpAddress4or6,
                                      ubyte2 portNo,
                                      const char* domainName)
{
    /* hint 0x0F20 - 0x0F2F */

    int retVal = 0;

    /* this server sends a partial certificate chain rooted at kRSABadCertChainCA
     but the root sent is not the correct one and has no path len.
     The real root h has a path length constraint of 1 */

    /* the correct CA cert for the chain is used here but is still rejected
     for the reason explained in test 0xF10 above */
    retVal += SSL_CLI_VerifyUnableToConnectEx(CIPHER_HINT(0xF20, 0),
                                              &g3DESCipherDesc,
                                              pIpAddress4or6, portNo,
                                              domainName, TLS10_MINORVERSION,
                                              ERR_CERT_CHAIN_NO_TRUST_ANCHOR,
                                              pBadChainSslCertStore);

    /* here, the root is trusted, not the real root. So error should be
     unknown certificate authority */
    retVal += SSL_CLI_VerifyUnableToConnectEx(CIPHER_HINT(0xF21, 0),
                                              &g3DESCipherDesc,
                                              pIpAddress4or6, portNo,
                                              domainName, TLS10_MINORVERSION,
                                              ERR_CERT_CHAIN_NO_TRUST_ANCHOR,
                                              pRSASslCertStore);


    return retVal;
}


/*------------------------------------------------------------------------*/

int SSL_CLI_CertChain_Server_Test( const sbyte* pIpAddress4or6,
                                  ubyte2 portNo,
                                  const char* domainName,
                                  const char* resourceName)
{
    /* hint 0x0F30 - 0x0F3F */
    int i, j, retVal = 0;

    for (i = 0; i < COUNTOF(gCipherDescs); ++i)
    {
        if (gCipherDescs[i].cipherId <= 0x003A )
        {
            for (j = gCipherDescs[i].minSSLVer; j <= TLS10_MINORVERSION; ++j)
            {
                retVal += SSL_CLI_GetPage(CIPHER_HINT(0xF30+j,i),
                                          gCipherDescs + i,
                                          pIpAddress4or6,
                                          portNo, resourceName,
                                          kOpenSSLLongChainCertIdx,
                                          domainName,
                                          OPENSSL, j,
                                          pRSASslCertStore);
            }
        }
    }

    return retVal;
}



/*------------------------------------------------------------------------*/

int SSL_CLI_SRP_OpenSSL_Server_Test( ubyte4 opensslVersion,
                                    const sbyte* pIpAddress4or6,
                                    ubyte2 portNo,
                                    const char* domainName,
                                    char* resourceName)
{
    /* hint 0x0F40 - 0x0F4F */
    int i, retVal = 0;

    for (i = 0; i < COUNTOF(gCipherDescs); ++i)
    {
        const char* cipherName = gCipherDescs[i].cipherName;
        /* only SRP ciphers */
        if (strstr(cipherName, "_SRP_"))
        {
            /* openssl only supports TLS 1.0 for SRP */
            retVal += SSL_CLI_Connect(CIPHER_HINT(0x0F40 + TLS10_MINORVERSION,i),
                                      gCipherDescs + i,
                                      pIpAddress4or6,
                                      portNo, resourceName,
                                      kOpenSSLCertIdx,
                                      domainName, OPENSSL,
                                      TLS10_MINORVERSION,
                                      pRSASslCertStore);
        }
    }

    return retVal;
}



/*------------------------------------------------------------------------*/

sbyte4
myCertStatusCallback(sbyte4 connectionInstance, intBoolean certStatus)
{

    sbyte4 status = 0;
    MOC_UNUSED(connectionInstance);


    printf("\nOCSP Stapling status: ");

    if (FALSE == certStatus)
    {
        status = ERR_SSL_EXTENSION_CERTIFICATE_STATUS_RESPONSE;
        printf("Server ignored cert_status extension\n");
    } else {
        printf("Server responded to cert_status extension\n");
    }

    return status;
}


/*------------------------------------------------------------------------*/

int ssl_cli_test_ocsp_stapling_1()
{

    /* CERT CHAIN GO DADDY OCSP RESPONDER
     Test against portal.mocana.com that uses GoDaddy's OCSP Responder
        Expect connection to succeed*/
#ifdef __xSSLCLIENT_OCSP_CLIENT__

    int         retVal = 0;
    MSTATUS     status;
    TCP_SOCKET  mySocket;
    sbyte4      connectionInstance;
    char*       pTrustedResponderCertsPath[] = {/*"gdroot-g2.der"*/};

    retVal += UNITTEST_STATUS( 0, status = (MSTATUS) DIGICERT_initDigicert());
    if (OK > status)  goto exit;

    retVal += UNITTEST_STATUS(0, status = (MSTATUS) SSL_init(0, 5));
    if (OK > status)  goto exit;


    /*Connect against portal.mocana.com */
    UNITTEST_STATUS(0,status = TCP_CONNECT(&mySocket, (sbyte*)"38.113.126.200",443));

    if (0 != retVal)
        goto exit;


    /*Establish SSL connection*/
    retVal += UNITTEST_STATUS(0, connectionInstance = SSL_connect(mySocket, 0,
                                                                  NULL, NULL,
                                                                  (sbyte*) "portal.mocana.com",
                                                                  pOCSPSslCertStore));
    if (0 != retVal)
        goto exit;

    /*Set callback to check for certStatus*/
    SSL_sslSettings()->funcPtrCertStatusCallback = myCertStatusCallback;


    /*Set OCSP parameters*/
    retVal += UNITTEST_STATUS(0, status = SSL_setCertifcateStatusRequestExtensions(connectionInstance,
                                                      pTrustedResponderCertsPath,0,NULL, 0));

    if (0 != retVal)
        goto exit;

    retVal += UNITTEST_STATUS(0, SSL_setMaxProtoVersion(TLS12_MINORVERSION));

    /*Negotiate Connection*/
    retVal += UNITTEST_STATUS(0,status = SSL_negotiateConnection(connectionInstance));

    if (0 != retVal)
        goto exit;

exit:

    return retVal;

#else

    return 0;

#endif /*__SSLCLIENT_OCSP_CLIENT__*/
}


/*------------------------------------------------------------------------*/

int ssl_cli_test_ocsp_stapling_2()
{

    /*  VALID CERT
     Test against Mocana SSL server (port 1463) w/ OpenSSL OCSP responder
        Server certificate is self signed and valid.
        Expect OCSP response to indicate certificate is valid and connection to succeed*/
#ifdef __SSLCLIENT_OCSP_CLIENT__

    int         retVal = 0;
    int         i = 0;
    int         count = 0;
    ubyte2      pCipherIdList[COUNTOF(gCipherDescs)];
    MSTATUS     status;
    TCP_SOCKET  mySocket;
    sbyte4      connectionInstance;
    char*       pTrustedResponderCertsPath[] = {/*"gdroot-g2.der"*/};
    char *pEnv = NULL;
    ubyte runTLS12Test = 1;

    pEnv = getenv("ENABLE_TLS13_TESTS");
    if (pEnv != NULL)
    {
        if (1 == atoi(pEnv))
            runTLS12Test = 0;
    }

    if (1 == runTLS12Test)
    {
        retVal += UNITTEST_STATUS( 0, status = (MSTATUS) DIGICERT_initDigicert());
        if (OK > status)  goto exit;

        retVal += UNITTEST_STATUS(0, status = (MSTATUS) SSL_init(0, 5));
        if (OK > status)  goto exit;


        /*Connect against Digicert SSL server */
        UNITTEST_STATUS(0,status = TCP_CONNECT(&mySocket, (sbyte*)"127.0.0.1", 1463));

        if (0 != retVal)
            goto exit;


        /*Establish SSL connection*/
        retVal += UNITTEST_STATUS(0, connectionInstance = SSL_connect(mySocket, 0,
                                                                      NULL, NULL,
                                                                      (sbyte*) "sslocsptest.mocana.com",
                                                                      pOCSPSslCertStore));
        if (0 != retVal)
            goto exit;

        memset(pCipherIdList, 0x00, COUNTOF(gCipherDescs));

        for (i = 0; i < COUNTOF(gCipherDescs); ++i)
        {
            const char* cipherName = gCipherDescs[i].cipherName;
            /* exclude the preshared keys and SRP ones */
            if (!strstr(cipherName, "_PSK_") &&
                !strstr(cipherName, "_SRP_"))
            {
                pCipherIdList[count] = gCipherDescs[i].cipherId;
                count++;
            }
        }

        retVal += UNITTEST_STATUS(0, SSL_enableCiphers(connectionInstance, pCipherIdList, count));
        if (retVal) goto exit;

        /*Set callback to check for certStatus*/
        SSL_sslSettings()->funcPtrCertStatusCallback = myCertStatusCallback;


        /*Set OCSP parameters*/
        retVal += UNITTEST_STATUS(0, status = SSL_setCertifcateStatusRequestExtensions(connectionInstance,
                                                                                       pTrustedResponderCertsPath,0,NULL, 0));

        if (0 != retVal)
            goto exit;

        retVal += UNITTEST_STATUS(0, SSL_setMaxProtoVersion(TLS12_MINORVERSION));

        /*Negotiate Connection*/
        retVal += UNITTEST_STATUS(0,status = SSL_negotiateConnection(connectionInstance));

        if (0 != retVal)
            goto exit;

exit:

        return retVal;
    }
    else
    {
        return retVal;
    }
#else

    return 0;

#endif /*__SSLCLIENT_OCSP_CLIENT__*/
}


/*------------------------------------------------------------------------*/

int ssl_cli_test_ocsp_stapling_3()
{

    /*  REVOKED CERT
     Test against Mocana SSL server w/ OpenSSL OCSP responder
     Server certificate is issued by CA and revoked. Server only sends the certificate. CA needs to be in client cert store.
     Expect OCSP response to indicate certificate is revoked and connection to fail*/
#ifdef __SSLCLIENT_OCSP_CLIENT__

    int         retVal = 0;
    MSTATUS     status;
    TCP_SOCKET  mySocket;
    sbyte4      connectionInstance;
    char*       pTrustedResponderCertsPath[] = {/*"gdroot-g2.der"*/};
    ubyte*      pIssuer = NULL;
    ubyte4      issuerLen = 0;
    int         i = 0;
    int         count = 0;
    ubyte2      pCipherIdList[COUNTOF(gCipherDescs)];
    char *pEnv = NULL;
    ubyte runTLS12Test = 1;

    pEnv = getenv("ENABLE_TLS13_TESTS");
    if (pEnv != NULL)
    {
        if (1 == atoi(pEnv))
            runTLS12Test = 0;
    }

    if (1 == runTLS12Test)
    {
        retVal += UNITTEST_STATUS( 0, status = (MSTATUS) DIGICERT_initDigicert());
        if (OK > status)  goto exit;

        retVal += UNITTEST_STATUS(0, status = (MSTATUS) SSL_init(0, 5));
        if (OK > status)  goto exit;

        /*Add CA/issuer in the SSL cert store*/
        retVal += UNITTEST_STATUS( 0, status = (MSTATUS) DIGICERT_readFile("../testaux/ocsp_test_certs/RSACA.der",&pIssuer,&issuerLen));
        if (OK > status)  goto exit;

        retVal += UNITTEST_STATUS( 0, status = (MSTATUS) CERT_STORE_createStore(&pOCSPSslCertStore));
        if (OK > status)  goto exit;

        retVal += UNITTEST_STATUS(0, status = (MSTATUS) CERT_STORE_addTrustPoint(pOCSPSslCertStore,pIssuer,issuerLen));
        if (OK > status)  goto exit;


        /*Connect against Digicert SSL server */
        UNITTEST_STATUS(0,status = TCP_CONNECT(&mySocket, (sbyte*)"127.0.0.1", 1464));

        if (0 != retVal)
            goto exit;


        /*Establish SSL connection*/
        retVal += UNITTEST_STATUS(0, connectionInstance = SSL_connect(mySocket, 0,
                                                                      NULL, NULL,
                                                                      (sbyte*) "sslocsptest3.mocana.com",
                                                                      pOCSPSslCertStore));
        if (0 != retVal)
            goto exit;

        memset(pCipherIdList, 0x00, COUNTOF(gCipherDescs));

        for (i = 0; i < COUNTOF(gCipherDescs); ++i)
        {
            const char* cipherName = gCipherDescs[i].cipherName;
            /* exclude the preshared keys and SRP ones */
            if (!strstr(cipherName, "_PSK_") &&
                !strstr(cipherName, "_SRP_"))
            {
                pCipherIdList[count] = gCipherDescs[i].cipherId;
                count++;
            }
        }

        retVal += UNITTEST_STATUS(0, SSL_enableCiphers(connectionInstance, pCipherIdList, count));
        if (retVal) goto exit;

        /*Set callback to check for certStatus*/
        SSL_sslSettings()->funcPtrCertStatusCallback = myCertStatusCallback;


        /*Set OCSP parameters*/
        retVal += UNITTEST_STATUS(0, status = SSL_setCertifcateStatusRequestExtensions(connectionInstance,
                                                                                       pTrustedResponderCertsPath,0,NULL, 0));

        if (0 != retVal)
            goto exit;

        retVal += UNITTEST_STATUS(0, SSL_setMaxProtoVersion(TLS12_MINORVERSION));

        /*Negotiate Connection*/
        status = (MSTATUS) SSL_negotiateConnection(connectionInstance);

        /*The certificate is revoked so the error should be revoked error*/
        retVal += UNITTEST_INT( 50, status, ERR_SSL_EXTENSION_CERTIFICATE_STATUS_RESPONSE);

        if (0 != retVal)
            goto exit;

exit:

        return retVal;
    }
    else
    {
        return retVal;
    }

#else

    return 0;

#endif /*__SSLCLIENT_OCSP_CLIENT__*/

}

/*------------------------------------------------------------------------*/

int ssl_cli_test_ocsp_stapling_4()
{

    /*  CERT CHAIN
     Test against Mocana SSL server w/ OpenSSL OCSP responder
     Server certificate is issued by CA and entire chain is passed to SSL Client. OCSP response is signed by the issuer cert.
     Expect OCSP response to indicate certificate is valid and connection to succeed.*/

#ifdef __SSLCLIENT_OCSP_CLIENT__

    int         retVal = 0;
    MSTATUS     status;
    TCP_SOCKET  mySocket;
    sbyte4      connectionInstance;
    char*       pTrustedResponderCertsPath[] = {/*"gdroot-g2.der"*/};
    int         i = 0;
    int         count = 0;
    ubyte2      pCipherIdList[COUNTOF(gCipherDescs)];

    char *pEnv = NULL;
    ubyte runTLS12Test = 1;

    pEnv = getenv("ENABLE_TLS13_TESTS");
    if (pEnv != NULL)
    {
        if (1 == atoi(pEnv))
            runTLS12Test = 0;
    }

    if (1 == runTLS12Test)
    {
        retVal += UNITTEST_STATUS( 0, status = (MSTATUS) DIGICERT_initDigicert());
        if (OK > status)  goto exit;

        retVal += UNITTEST_STATUS(0, status = (MSTATUS) SSL_init(0, 5));
        if (OK > status)  goto exit;


        /*Connect against Digicert SSL server */
        UNITTEST_STATUS(0,status = TCP_CONNECT(&mySocket, (sbyte*)"127.0.0.1", 1465));

        if (0 != retVal)
            goto exit;


        /*Establish SSL connection*/
        retVal += UNITTEST_STATUS(0, connectionInstance = SSL_connect(mySocket, 0,
                                                                      NULL, NULL,
                                                                      (sbyte*) "sslocsptest2.mocana.com",
                                                                      pOCSPSslCertStore));
        if (0 != retVal)
            goto exit;

        memset(pCipherIdList, 0x00, COUNTOF(gCipherDescs));

        for (i = 0; i < COUNTOF(gCipherDescs); ++i)
        {
            const char* cipherName = gCipherDescs[i].cipherName;
            /* exclude the preshared keys and SRP ones */
            if (!strstr(cipherName, "_PSK_") &&
                !strstr(cipherName, "_SRP_"))
            {
                pCipherIdList[count] = gCipherDescs[i].cipherId;
                count++;
            }
        }

        retVal += UNITTEST_STATUS(0, SSL_enableCiphers(connectionInstance, pCipherIdList, count));
        if (retVal) goto exit;

        /*Set callback to check for certStatus*/
        SSL_sslSettings()->funcPtrCertStatusCallback = myCertStatusCallback;


        /*Set OCSP parameters*/
        retVal += UNITTEST_STATUS(0, status = SSL_setCertifcateStatusRequestExtensions(connectionInstance,
                                                                                       pTrustedResponderCertsPath,0,NULL, 0));

        if (0 != retVal)
            goto exit;

        retVal += UNITTEST_STATUS(0, SSL_setMaxProtoVersion(TLS12_MINORVERSION));

        /*Negotiate Connection*/
        retVal += UNITTEST_STATUS(0,status = SSL_negotiateConnection(connectionInstance));

        if (0 != retVal)
            goto exit;

    exit:

        return retVal;
    }
    else
    {
        return retVal;
    }
#else

    return 0;

#endif /*__SSLCLIENT_OCSP_CLIENT__*/

}

/*------------------------------------------------------------------------*/

int ssl_cli_test_ocsp_stapling_5()
{

    /* MISSING ISSUER
     Test against Mocana SSL server w/ OpenSSL OCSP responder
     Server certificate is issued by CA. Server only sends server certificate and issuer is not provided to server.
     Server will be unable to generate OCSP request and continue with the connection; Fails when the client tries
     to get the OCSP response. */

#ifdef __SSLCLIENT_OCSP_CLIENT__

    int         retVal = 0;
    MSTATUS     status;
    TCP_SOCKET  mySocket;
    sbyte4      connectionInstance;
    char*       pTrustedResponderCertsPath[] = {/*"gdroot-g2.der"*/};
    int         i = 0;
    int         count = 0;
    ubyte2      pCipherIdList[COUNTOF(gCipherDescs)];

    char *pEnv = NULL;
    ubyte runTLS12Test = 1;

    pEnv = getenv("ENABLE_TLS13_TESTS");
    if (pEnv != NULL)
    {
        if (1 == atoi(pEnv))
            runTLS12Test = 0;
    }

    if (1 == runTLS12Test)
    {
        retVal += UNITTEST_STATUS( 0, status = (MSTATUS) DIGICERT_initDigicert());
        if (OK > status)  goto exit;

        retVal += UNITTEST_STATUS(0, status = (MSTATUS) SSL_init(0, 5));
        if (OK > status)  goto exit;


        /*Connect against Digicert SSL server */
        UNITTEST_STATUS(0,status = TCP_CONNECT(&mySocket, (sbyte*)"127.0.0.1", 1466));

        if (0 != retVal)
            goto exit;


        /*Establish SSL connection*/
        retVal += UNITTEST_STATUS(0, connectionInstance = SSL_connect(mySocket, 0,
                                                                      NULL, NULL,
                                                                      (sbyte*) "sslocsptest2.mocana.com",
                                                                      pOCSPSslCertStore));
        if (0 != retVal)
            goto exit;

        memset(pCipherIdList, 0x00, COUNTOF(gCipherDescs));

        for (i = 0; i < COUNTOF(gCipherDescs); ++i)
        {
            const char* cipherName = gCipherDescs[i].cipherName;
            /* exclude the preshared keys and SRP ones */
            if (!strstr(cipherName, "_PSK_") &&
                !strstr(cipherName, "_SRP_"))
            {
                pCipherIdList[count] = gCipherDescs[i].cipherId;
                count++;
            }
        }

        retVal += UNITTEST_STATUS(0, SSL_enableCiphers(connectionInstance, pCipherIdList, count));
        if (retVal) goto exit;

        /*Set callback to check for certStatus*/
        SSL_sslSettings()->funcPtrCertStatusCallback = myCertStatusCallback;


        /*Set OCSP parameters*/
        retVal += UNITTEST_STATUS(0, status = SSL_setCertifcateStatusRequestExtensions(connectionInstance,
                                                                                       pTrustedResponderCertsPath,0,NULL, 0));

        if (0 != retVal)
            goto exit;

        retVal += UNITTEST_STATUS(0, SSL_setMaxProtoVersion(TLS12_MINORVERSION));

        /*Negotiate Connection*/
        status = (MSTATUS) SSL_negotiateConnection(connectionInstance);

        /* Connection should fail; Throw and error if connection goes through */
        if (OK == status)
            retVal++;

        if (0 != retVal)
            goto exit;

exit:
        return retVal;
    }
    else
    {
        return retVal;
    }
#else

    return 0;

#endif /*__SSLCLIENT_OCSP_CLIENT__*/

}


/*------------------------------------------------------------------------*/

int ssl_cli_test_get_pages()
{
    MSTATUS status;
    int retVal = 0;
    int major, minor, revision;
    ubyte4 opensslVersion;
    char* opensslVersionStr = 0;
    ubyte4 opensslVersionStrLen;
    const char* domainName = "*.mydomain.com";
    char resourceName[20] = { 'T', 'e', 's', 't'}; /* need space at least 20 */
#if !defined (__ENABLE_DIGICERT_TLS13_TM_TESTS__)
#ifdef __ENABLE_DIGICERT_IPV6__
    sbyte pIpAddress4or6[80] = {LOOPBACK_IPV4_MAPPED_V6_ADDR};
    ubyte2 portNum = 1445;
#else
    sbyte pIpAddress4or6[80] = {LOOPBACK};
    ubyte2 portNum = 1443;
    ubyte2 newPortNum = 1443;
    ubyte2 mauthPort = 1447;
#endif

#ifdef __ENABLE_DIGICERT_IPV6__
#else
#endif

#ifdef __UNITTEST_REMOTE_SUPPORT__
    ubyte2         		peerPort;
    MOC_IP_ADDRESS_S 	peerAddr;
#endif

    char *pEnv = NULL;
    ubyte runTLS12Test = 1;
    char *pOpenSSLEnv = NULL;
    ubyte verifyMocanaServerResposne = 1;
    char *pOpenSSLVersionEnv = NULL;
    ubyte openssl102Version = 0;

    pEnv = getenv("ENABLE_TLS13_TESTS");
    if (pEnv != NULL)
    {
        if (1 == atoi(pEnv))
            runTLS12Test = 0;
    }

    pOpenSSLEnv = getenv("ENABLE_OPENSSL_INTEROPERABILITY_TEST");
    if (pOpenSSLEnv != NULL)
    {
        if (1 == atoi(pOpenSSLEnv))
            verifyMocanaServerResposne = 0;
    }

    pOpenSSLVersionEnv = getenv("ENABLE_OPENSSL_1_0_2_VERSION");
    if (pOpenSSLVersionEnv != NULL)
    {
        if (1 == atoi(pOpenSSLVersionEnv))
            openssl102Version = 1;
    }

    if (1 == runTLS12Test)
    {
        retVal += UNITTEST_STATUS( 0, status = (MSTATUS) DIGICERT_initDigicert());
        if (OK > status)  goto exit;

        retVal += UNITTEST_STATUS(0, status = (MSTATUS) SSL_init(0, 5));
        if (OK > status)  goto exit;

#ifdef __UNITTEST_REMOTE_SUPPORT__
        if (remote_target_socket != 0)
        {
            // Find the peer IP address so it can be used by remote targets to connect to host based testaux servers
            status = TCP_getPeerName(remote_target_socket, &peerPort, &peerAddr);
            status = DIGI_NET_IPADDR_TO_NAME(&peerAddr, pIpAddress);

            if ((status < OK))
            {
                DEBUG_PRINTNL(DEBUG_HTTP_MESSAGE, "ssl_cli_test_get_pages: getPeerName failed.");
            }
        }
#endif


#if 0
        /* OpenSSL version is written out by the makefile_openssl_server */
        if (OK > (status = (MSTATUS) DIGICERT_readFile("../testaux/openssl_version",
                                           (ubyte**) &opensslVersionStr,
                                           &opensslVersionStrLen)))
        {
            retVal += UNITTEST_STATUS(0, status);
            goto exit;
        }
        /* replace \n added by echo in the makefile by 0 */
        opensslVersionStr[opensslVersionStrLen-1] = 0;
        if (3 == sscanf(opensslVersionStr, "%d.%d.%d", &major, &minor, &revision))
        {
            opensslVersion = revision + minor * 1000 + major * 1000000;
        }
        else
        {
            opensslVersion = 9008; /* defaults to 0.9.8 */
        }
#endif
        retVal = SSL_CLI_initUpcallsAndCertStores();
        if (retVal) goto exit;

        SSL_CLI_initializeTestResults();

#ifdef __SSLCLIENT_OCSP_CLIENT__
    /* Unset the OCSP callback */
    SSL_sslSettings()->funcPtrCertStatusCallback = NULL;
#endif
        /******* 1443-1449: Digicert server ports *****************/
        /******* 1450-1459: OpenSSL server ports ****************/
        /******* 1460-1469: Digicert server ports *****************/
        /******* 1470-1479: mbedTLS server ports ****************/
        /******* 1480-1489: OpenSSL server ports ****************/


#ifndef __ENABLE_HARDWARE_ACCEL_CRYPTO__
        if (1 == openssl102Version)
        {
            newPortNum += 1000;
            mauthPort  += 1000;
        }

        printf("normal server test, ssl3 \n");
        /* our own server */
        retVal += SSL_CLI_Normal_Server_Test( pIpAddress4or6, newPortNum,
                                              domainName,
                                             SSL3_MINORVERSION,
                                             resourceName);
        printf("normal server test, tls10 \n");

        /* our own server with alternate domain name but limit
         to TLS10 since SNI is not supported for SSL 3.0 */
        retVal += SSL_CLI_Normal_Server_Test( pIpAddress4or6, newPortNum,
                                             "localhost",
                                             TLS10_MINORVERSION,
                                             resourceName);
        printf("alpn server test \n");
        /* our own server -- test the ALPN TLS extension */
        retVal += SSL_CLI_ALPN_Normal_Server_Test( pIpAddress4or6, portNum,
                                                  domainName, resourceName);
        printf("psk server test \n");
        /* our own server -- special functions for PSK ciphers */
        retVal += SSL_CLI_PSK_Normal_Server_Test( pIpAddress4or6, newPortNum,
                                                 domainName, resourceName);

        printf("Session Ticket test\n");
        retVal += SSL_CLI_SessionTicket_TestCase(pIpAddress4or6, portNum,
                                                 domainName, resourceName);
        printf("expired certs test \n");
        /* 1446: server with expired certs */
        retVal += SSL_CLI_Expired_Cert_Server_Test(pIpAddress4or6, 1446,
                                                   domainName, resourceName);
        printf("mutual authentication test \n");
        /* 1447: mutual authentication */
        retVal += SSL_CLI_MutAuth_Server_Test(pIpAddress4or6, mauthPort,
                                              domainName, resourceName);
        /* This test uses  */
        if (1 == verifyMocanaServerResposne)
        {
            printf("version test \n");
            /* 1449: version set */
            retVal += SSL_CLI_VersionSet_Server_Test(pIpAddress4or6, 1449, domainName,
                                                     resourceName);
        }
        printf("srp test \n");
        /* 1462: our own SRP server */
        retVal += SSL_CLI_SRP_Server_Test( pIpAddress4or6, 1462,
                                          domainName, resourceName);

        /* openssl and mbed servers tests*/
#if 0
        printf("test internal server that to verify Trac 345 \n");
        /* test internal server that to verify Trac 345 is fixed port 1448 */
        retVal += SSL_CLI_VerifyTrac345(pIpAddress4or6, 1448);

        /* 1450: OpenSSL with RSA cert */
        retVal += SSL_CLI_RSA_OpenSSL_Server_Test(opensslVersion,
                                                  pIpAddress4or6,
                                                  1450, domainName, resourceName);

        /* 1451: mutual authentication with openssl  -- this server
         also uses ECC certificates -- not always available depending
         on which version of openssl is present */
        retVal += SSL_CLI_ECC_MutAuth_OpenSSL_Server_Test(opensslVersion,
                                                          pIpAddress4or6, 1451,
                                                          domainName,
                                                          resourceName);

        /* test openssl server port = 1452 -- this uses only SSL3 verify bug 635 stays fixed */
        retVal += SSL_CLI_SSL3_Verify_635_Server_Test(pIpAddress4or6, 1452,
                                                      domainName, resourceName);

        /* 1453: openssl test server with small RSA key */
        retVal += SSL_CLI_SmallKeyServer_Test( pIpAddress4or6, 1453,
                                              "small_key_test.mocana.com");

        /* 1454: openssl test server with small DH key */
        retVal += SSL_CLI_SmallDHKeyServer_Test( pIpAddress4or6, 1454, domainName);

        /* 1455: OpenSSL with ECC cert */
        retVal += SSL_CLI_ECC_OpenSSL_Server_Test(opensslVersion,
                                                  pIpAddress4or6,
                                                  1455, domainName, resourceName);

        /* 1456: mutual authentication with openssl  -- this server
         also uses RSAcertificates -- always available depending
         on which version of openssl is present */
        retVal += SSL_CLI_RSA_MutAuth_OpenSSL_Server_Test(opensslVersion,
                                                          pIpAddress4or6, 1456,
                                                          domainName,
                                                          resourceName);

        /* 1457: openssl test server psk with hint */
        retVal += SSL_CLI_PSK_OpenSSL_Server_Test( opensslVersion,
                                                  pIpAddress4or6, 1457,
                                                  domainName, resourceName);

        /* 1458: openssl test server psk without hint */
        retVal += SSL_CLI_PSK_OpenSSL_Server_Test( opensslVersion,
                                                  pIpAddress4or6, 1458,
                                                  domainName, resourceName);

        /* 1459: openssl test server with a wildchar cert (CN=*.mocana.com) */
        retVal += SSL_CLI_Wildchar_OpenSSL_Server_Test( opensslVersion,
                                                       pIpAddress4or6, 1459,
                                                       domainName, resourceName);

        /* 1470: mbedTLS server: useful for PSK and CCM suites */
        retVal += SSL_CLI_mbedTLS_Server_Test( pIpAddress4or6, 1470,
                                               domainName, resourceName);

        /* 1471: mbedTLS server: useful for ECDSA PSK and CCM suites */
        retVal += SSL_CLI_ECC_mbedTLS_Server_Test( pIpAddress4or6, 1471,
                                                  domainName, resourceName);

        /* 1480: openssl test server for ECDH-RSA cipher suites1 */
        retVal += SSL_CLI_ECDH_RSA_OpenSSL_Server_Test( opensslVersion,
                                                       pIpAddress4or6, 1480,
                                                       "ecdh_rsa_ciphers_test.mocana.com",
                                                       resourceName);

        /* 1481: OpenSSL server: bad certificate chain length */
        retVal += SSL_CLI_BadCertChain_Server_Test( pIpAddress4or6, 1481,
                                                    "sslchaintest.mocana.com");

        /* 1482: OpenSSL server: bad certificate chain length, incomplete chain */
        retVal += SSL_CLI_BadCertChain2_Server_Test( pIpAddress4or6, 1482,
                                                     "sslchaintest.mocana.com");

        /* 1483: OpenSSL server: unrelated certificate chain length */
        retVal += SSL_CLI_BadCertChain3_Server_Test( pIpAddress4or6, 1483,
                                                    "sslchaintest.mocana.com");

        /* 1484: OpenSSL server: good chain with certificate chain length */
        retVal += SSL_CLI_CertChain_Server_Test( pIpAddress4or6, 1484,
                                                 "sslchaintest2.mocana.com",
                                                resourceName);
        
        /* 1485: OpenSSL server SRP */
        retVal += SSL_CLI_SRP_OpenSSL_Server_Test( opensslVersion,
                                                  pIpAddress4or6,
                                                  1485, domainName,
                                                  resourceName);
#endif
        
#else

        /* 1461: just test the __ENABLE_HARDWARE_ACCEL_CRYPTO__ server with
           the __ENABLE_HARDWARE_ACCEL_CRYPTO__ client */
        retVal += SSL_CLI_Normal_Server_Test( pIpAddress4or6, 1461,
                                              domainName,
                                             SSL3_MINORVERSION,
                                             resourceName);

#endif

        if (0 == retVal)
        {
            SSL_CLI_outputTestResults();
        }

    exit:
        CRYPTO_uninitAsymmetricKey(&mRSAMutualAuthCertKey, NULL);
        CERT_STORE_releaseStore(&pRSASslCertStore);
        CERT_STORE_releaseStore(&pECCSslCertStore);
/*        CERT_STORE_releaseStore(&pUnknownSslCertStore); */

        FREE(opensslVersionStr);

        SSL_releaseTables();

        DIGICERT_freeDigicert();
    }
#endif /* !defined (__ENABLE_DIGICERT_TLS13_TM_TESTS__) */
    return retVal;
}
