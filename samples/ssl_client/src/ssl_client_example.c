/*
 * ssl_client_example.c
 *
 * Implementation of a secure HTTP client
 *
 * Copyright Mocana Corp 2004-2019. All Rights Reserved.
 * Proprietary and Confidential Material.
 *
 */
#if defined(WIN32)

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0400
#include <winsock2.h>

#if defined(_DEBUG)
#include <crtdbg.h>
#endif

#endif  /*WIN32*/

#if defined(__ENABLE_DIGICERT_WIN_STUDIO_BUILD__)
#include <windows.h>
#endif /* __ENABLE_DIGICERT_WIN_STUDIO_BUILD__ */

#include "../common/moptions.h"

#if defined( __ENABLE_DIGICERT_SSL_CLIENT_EXAMPLE__ )
#if ((defined(__ENABLE_DIGICERT_EXAMPLES__) || defined(__ENABLE_DIGICERT_BIN_EXAMPLES__)) && !defined(__ENABLE_DIGICERT_SSL_SERVER_EXAMPLE__) && !defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)) || \
    defined(__DISABLE_DIGICERT_AUTO_EXAMPLES__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/moc_net.h"
#include "../common/random.h"
#include "../common/debug_console.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/tree.h"
#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../crypto/hw_accel.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/pkcs_key.h"
#if defined(__ENABLE_DIGICERT_SSL_EXAMPLE_SMART_CARD__) && defined(__ENABLE_DIGICERT_TLS13__)
#include "../crypto/sha512.h"
#include "../crypto/pkcs1.h"
#endif
#include "../common/sizedbuffer.h"
#include "../crypto/cert_store.h"
#include "../ssl/ssl.h"

#ifdef __ENABLE_DIGICERT_TAP__
#include "../smp/smp_cc.h"
#include "../tap/tap_api.h"
#include "../tap/tap_utils.h"
#include "../tap/tap_smp.h"
#include "../crypto/mocasym.h"
#include "../crypto/mocasymkeys/tap/rsatap.h"
#include "../crypto/mocasymkeys/tap/ecctap.h"
#include "../crypto_interface/cryptointerface.h"
#endif

#if defined(__ENABLE_DIGICERT_SSL_EXAMPLE_SMART_CARD__) && defined(__ENABLE_DIGICERT_TLS13__)
#include "../crypto_interface/crypto_interface_rsa.h"
#include "../crypto_interface/crypto_interface_pkcs1.h"
#endif

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "fips_utils.h"
#endif

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
#include "../data_protection/file_protect.h"
#endif
/*------------------------------------------------------------------*/

#include <stdio.h>
#include <string.h>
#include "ssl_cert_utils.h"

/*------------------------------------------------------------------*/

#define MAX_RECEIVE_LEN 1024 + 1
#define MAX_BUFFER_LEN 20*1024  + 1
#define MAX_PSK_FILE_LEN 256

#ifdef _MSC_VER /* Microsoft compiler */
#define SNPRINTF _snprintf
#else
#define SNPRINTF snprintf
#endif

/*------------------------------------------------------------------*/
/* Hard coded parameter defaults.                                   */
/*------------------------------------------------------------------*/
#define MAX_BUFFER_SIZE (2048)
#define MAX_SERVER_TRIES (20)

#if defined(WIN32)
#define DEFAULT_KEYSTORE_DIRECTIORY 	".\\KeyStore"
#else
#define DEFAULT_KEYSTORE_DIRECTIORY		"./keystore"
#endif
#define SSLC_DEF_IP            			"127.0.0.1"
/* #define SSLC_DEF_PORT        			SSL_DEFAULT_TCPIP_PORT */
#define SSLC_DEF_PORT          			(1440)
#define SSLC_DEF_SERVERNAME    			"webapptap.securitydemos.net"
#define SSLS_DEF_KEYSTORE      			DEFAULT_KEYSTORE_DIRECTIORY

#ifndef __DISABLE_DIGICERT_SSL_RSA_SUPPORT__
#define SSLC_DEF_SERVERCERT    			"RSACertCA.der" /* By default */
#define SSLC_DEF_CLIENTCERT    			"ClientRSACert.der"
#if (defined(__ENABLE_DIGICERT_PEM_DER_PRIVATE_KEY__))
#define SSLC_DEF_CLIENTBLOB             "ClientRSACertKey.pem"
#else
#define SSLC_DEF_CLIENTBLOB    			"ClientRSACertKey.dat"
#endif
#endif /* __DISABLE_DIGICERT_SSL_RSA_SUPPORT__ */

#ifdef __ENABLE_DIGICERT_ECC__
#undef  SSLC_DEF_SERVERCERT
#undef  SSLC_DEF_CLIENTCERT
#undef  SSLC_DEF_CLIENTBLOB
#define SSLC_DEF_SERVERCERT             "ECCCertCA384.der"
#define SSLC_DEF_CLIENTCERT             "ClientECCCertCA384.der"
#if (defined(__ENABLE_DIGICERT_PEM_DER_PRIVATE_KEY__))
#define SSLC_DEF_CLIENTBLOB             "ClientECCCertCA384Key.pem"
#else
#define SSLC_DEF_CLIENTBLOB             "ClientECCCertCA384Key.dat"
#endif
#endif

#if (defined(__ENABLE_DIGICERT_DSA__))
#undef SSLC_DEF_SERVERCERT
#define SSLC_DEF_SERVERCERT             "DSACertCA.der"
#endif

#if defined(__ENABLE_DIGICERT_TAP__)
#include "../common/tpm2_path.h"
#define DEF_TAP_KEYSOURCE          "TPM2"
#endif

#define SSLC_DEF_TICKET                 "client.ticket"

#ifdef __ENABLE_DIGICERT_MEM_PART__
extern memPartDescr *gMemPartDescr;
#endif

/*------------------------------------------------------------------*/
/* Parameters filled in from args (or elsewhere)                    */
/*------------------------------------------------------------------*/
static char * 		   sslc_ServerIpAddr   = NULL;
static unsigned short  sslc_ServerPort     = SSLC_DEF_PORT;
static char * 		   sslc_ServerName     = NULL;
static char * 		   sslc_KeyStore       = NULL;
static char * 		   sslc_ServerCert     = NULL;
static char * 		   sslc_ClientCert     = NULL;
static char * 		   sslc_ClientBlob     = NULL;
static char *          sslc_supportedGroup = NULL;
static unsigned short  sslc_ClientCertCb   = 0;
static intBoolean      sslc_getArgs_called = 0;
#if (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__))
static intBoolean      sslc_useExternalPsk = 0;
#if defined(__ENABLE_DIGICERT_TLS13_0RTT__)
static sbyte*          sslc_EarlyData          = NULL;
#endif /* __ENABLE_DIGICERT_TLS13_0RTT__ */
tls13PSK*              g_pPSK                  = NULL;
ubyte*                 g_pServerInfo           = NULL;
void*                  g_pUserData             = NULL;
static int             count                   = 0;
#endif
#if defined(__ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__)
static int             sslc_CipherSuiteTest    = 0;
#endif
#if (defined(__ENABLE_DIGICERT_TAP__))
#if (defined(__ENABLE_DIGICERT_TAP_REMOTE__))
static unsigned short  taps_ServerPort     = 0;
static char * 	       taps_ServerName     = NULL;
#endif
static char *          tap_ConfigFile      = NULL;
static sbyte *         tap_keySource       = NULL;
static ubyte2          sslc_TapProvider = 0;
#endif

/* Define this to use the "Test" & "ResumeTest" pages on HTTPS requests for NanoSSL tests.*/
#define TESTING_AGAINST_OUR_SERVERPAGES

#ifdef TESTING_AGAINST_OUR_SERVERPAGES
   #define TESTPAGE "Test"
   #define RESUMETESTPAGE "ResumeTest"
   #define ATESTPAGE "a"
#else
   /* Defining these if testing against a typical web-server */
   #define TESTPAGE "index.html"
   #define RESUMETESTPAGE "index.html"
   #define ATESTPAGE "index.html"
#endif

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_SSL_CLIENT_EXAMPLE_CERTSTORE_ALIAS__)
static ubyte* g_pAlias   = "testalias";
static ubyte4 g_aliasLen = 9;
#endif

#if defined(__ENABLE_DIGICERT_TLS13_PSK__)

static tls13PSK externalPsk = {
    .isExternal = 1,
    .isPSKavailable = 1,
    .pskTLS13LifetimeHint = 0,
    .pskTLS13AgeAdd = 0,
    .pskTLS13 = {
        0x65, 0x78, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c,
        0x20, 0x70, 0x73, 0x6b
    },
    .pskTLS13Length = 12,
    .pskTLS13Identity = (ubyte *) "External TLS 1.3 PSK",
    .pskTLS13IdentityLength = 20,
    .obfuscatedTicketAge = 0,
    .hashAlgo = TLS_SHA256,
    .startTime = { 0 },
    .maxEarlyDataSize = 10000,
    .pSelectedTlsVersion = (SSL3_MAJORVERSION << 8) | TLS13_MINORVERSION,
    .selectedCipherSuiteId = 0x1301
};

#endif /* __ENABLE_DIGICERT_TLS13_PSK__ */

/*------------------------------------------------------------------*/
/* Forward Declarations                                             */
/*------------------------------------------------------------------*/
static void setStringParameter(char** param, char* value);
MOC_EXTERN sbyte4  SSL_getClientSessionInfo(sbyte4 connectionInstance,
                                            ubyte* sessionIdLen,
                                            ubyte sessionId[SSL_MAXSESSIONIDSIZE],
                                            ubyte masterSecret[SSL_MASTERSECRETSIZE]);

static RootCertInfo gRootCerts[] =
{
		{kRSACertIdx, SSLC_DEF_SERVERCERT, 0, 0 }
};

static certStorePtr pClientSslCertStore;

#ifdef __ENABLE_DIGICERT_TAP__
static TAP_Context *g_pTapContext = NULL;
static TAP_EntityCredentialList *g_pTapEntityCred = NULL;
static TAP_CredentialList       *g_pTapKeyCred    = NULL;
static TAP_ModuleList g_moduleList                = { 0 };
#endif

#define myPrintNL(a) { \
	DEBUG_PRINTNL(DEBUG_SSL_EXAMPLE, (sbyte*)a); }
#define myPrintInt(a,b) { \
	DEBUG_PRINTSTR1INT1(DEBUG_SSL_EXAMPLE, (sbyte*)a, b); }
#define myPrintIntNL(a,b) { \
	DEBUG_PRINTSTR1INT1(DEBUG_SSL_EXAMPLE, \
	(sbyte*)a, b); DEBUG_PRINTNL(DEBUG_SSL_EXAMPLE, (sbyte*)""); }
#define myPrintStringNL(a,b) { \
	DEBUG_PRINT2(DEBUG_SSL_EXAMPLE, (sbyte*)a, \
	(sbyte*)b); DEBUG_PRINTNL(DEBUG_SSL_EXAMPLE, (sbyte*)""); }
#define myPrintError(a,b) { \
	DEBUG_PRINT(DEBUG_SSL_EXAMPLE, (sbyte*)"----------------> ERROR::"); \
	DEBUG_ERROR(DEBUG_SSL_EXAMPLE, a, b); }
#define myPrintStringError(a,b) { \
	DEBUG_PRINT(DEBUG_DTLS_EXAMPLE, (sbyte*)"----------------> ERROR::"); \
	DEBUG_PRINT2(DEBUG_DTLS_EXAMPLE, a, b); \
	DEBUG_PRINTNL(DEBUG_DTLS_EXAMPLE, (sbyte*)""); }

#define myPrintStatus(fmt, ...) \
    do {\
        printf(fmt"\n", ##__VA_ARGS__);\
    } while (0);

/*------------------------------------------------------------------*/

#if !defined(__DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__) && defined(__ENABLE_DIGICERT_SSL_CLIENT_CERTIFICATE_CALLBACK__)
/*
    After the stack has validated the cert chain, this callback
    will be called to perform any additional validations and/or
    override the stacks validation. The stack will pass its status in 
    as validationStatus.

    For the purposes of this example we will perform additional
    validation. We will validate that if a SAN extension is defined and
    a common name is defined, that the common name matches the 
    expression in the SAN. If SAN is not defined or common name
    is not defined we let the method pass */
static MSTATUS SSL_CLIENT_EXAMPLE_sslCertStatusCb(
    sbyte4 sslConnectionInstance,
    struct certChain *pCertChain,
    MSTATUS validationStatus)
{
    DEBUG_PRINTNL(DEBUG_SSL_EXAMPLE, (sbyte *)"Validating SSL certificate status using SSL_CLIENT_EXAMPLE_sslCertStatusCb callback...");
    
    MSTATUS status = OK;
    ubyte4 numCerts = 0;
    ubyte4 i = 0;
    const ubyte *pCert = NULL;
    ubyte4 certLen = 0;
    ubyte *pCNPtr = NULL;
    ubyte pCNBuffer[256] = {0}; /* make big enough for any common name, or allocate */

    ASN1_ITEMPTR pRoot = NULL, pCN = NULL, pExtensionsSeq = NULL, pSubjectAltNames = NULL;
    MemFile certMemFile = {0};
    CStream cs = {0};
    intBoolean critical = FALSE;

    MOC_UNUSED(sslConnectionInstance);

    /* If validation alreay failed then no need to do additional validation */
    if (OK != validationStatus)
        return validationStatus;

    /* For illustrative purposes We'll validate every certificate in the chain */
    status = CERTCHAIN_numberOfCertificates(pCertChain, &numCerts);
    if (OK != status)
        goto exit;
    
    for (; i < numCerts; i++)
    {
        /* re-use pRoot, free if allocated */
        if (NULL != pRoot)
        {
            (void) TREE_DeleteTreeItem((TreeItem *) pRoot);
        }

        /* get the i-th cert */
        status = CERTCHAIN_getCertificate(pCertChain, i, &pCert, &certLen);
        if (OK != status)
            goto exit;

#ifdef __ENABLE_DIGICERT_CV_CERT__
        /* If the first byte is 0x7F, this could be a CV Cert chain, skip validation */
        if (certLen > 0 && 0x7F == pCert[0])
        {
            goto exit;
        }
#endif

        /* set it up to be parsed in ASN1_ITEM form */
        MF_attach(&certMemFile, certLen, (ubyte *) pCert);
        CS_AttachMemFile( &cs, &certMemFile);

        status = X509_parseCertificate(cs, &pRoot);
        if (OK != status)
            goto exit;

        /* Retrieve the certificate common name, we start at first child of pRoot */
        status = X509_getSubjectCommonName(ASN1_FIRST_CHILD(pRoot), cs, &pCN);
        if (OK != status)
            goto exit;
        
        /* Get reference to common name buffer */
        pCNPtr = (ubyte *) CS_memaccess(cs, pCN->dataOffset, pCN->length);
        if (NULL == pCNPtr)
        {
            continue; /* No common name, nothing to validate. */
        }

        /* copy to a buffer where we can then treat it as a C string */
        status = DIGI_MEMCPY(pCNBuffer, pCNPtr, pCN->length);
        if (OK != status)
            goto free_pcn;

        pCNBuffer[pCN->length] = 0x00; /* '\0' charachter */

        /* Check if there is an Alt Name extension */
        status = X509_getCertificateExtensions( ASN1_FIRST_CHILD(pRoot), &pExtensionsSeq);
        if (OK != status || NULL == pExtensionsSeq)
            goto free_pcn;

        status = X509_getCertExtension( pExtensionsSeq, cs, subjectAltName_OID, 
                                        &critical, &pSubjectAltNames);
        if (OK != status || NULL == pSubjectAltNames)
            goto free_pcn;

        /* Now we can compare the Alt name found with common name 
           and this API returning an error status will mean there was no match */
        status = X509_compSubjectAltNames(ASN1_FIRST_CHILD(pRoot), cs, (sbyte *) pCNBuffer,
                                          ((1 << 2) | (1 << 6) | (1 << 7))); /* 1 << 2 for DNS
                                                                                1 << 6 for URI
                                                                                1 << 7 for IP  */
        /* release pCNPtr irregardless of status */
free_pcn:

        CS_stopaccess(cs, pCNPtr);
        if (OK != status)
            goto exit;
    }

exit:

    /* pCert is not allocated by CERTCHAIN_getCertificate, don't free */    

    if (NULL != pRoot)
    {
        (void) TREE_DeleteTreeItem((TreeItem *) pRoot);
    }

    return status;
}
#endif

static void SSL_CLIENT_EXAMPLE_sslFullCertCb(
    sbyte4 sslConnectionInstance,
    struct certChain *pCertChain)
{
    MSTATUS status = OK;
    ubyte4 numCerts = 0;
    ubyte4 i = 0;
    const ubyte *pCert = NULL;
    ubyte4 certLen = 0;
    ubyte *pCNPtr = NULL;
    ubyte pCNBuffer[256] = {0}; /* make big enough for any common name, or allocate */

    ASN1_ITEMPTR pRoot = NULL, pCN = NULL, pExtensionsSeq = NULL, pSubjectAltNames = NULL;
    MemFile certMemFile = {0};
    CStream cs = {0};
    intBoolean critical = FALSE;

    MOC_UNUSED(sslConnectionInstance);

    /* For illustrative purposes We'll validate every certificate in the chain */
    status = CERTCHAIN_numberOfCertificates(pCertChain, &numCerts);
    if (OK != status)
        goto exit;
    
    for (; i < numCerts; i++)
    {
        /* re-use pRoot, free if allocated */
        if (NULL != pRoot)
        {
            (void) TREE_DeleteTreeItem((TreeItem *) pRoot);
        }

        /* get the i-th cert */
        status = CERTCHAIN_getCertificate(pCertChain, i, &pCert, &certLen);
        if (OK != status)
            goto exit;

#ifdef __ENABLE_DIGICERT_CV_CERT__
        /* If the first byte is 0x7F, this could be a CV Cert chain, skip validation */
        if (certLen > 0 && 0x7F == pCert[0])
        {
            goto exit;
        }
#endif

        /* set it up to be parsed in ASN1_ITEM form */
        MF_attach(&certMemFile, certLen, (ubyte *) pCert);
        CS_AttachMemFile( &cs, &certMemFile);

        status = ASN1_Parse(cs, &pRoot);
        if (OK != status)
            goto exit;

        /* Retrieve the certificate common name, we start at first child of pRoot */
        status = X509_getSubjectCommonName(ASN1_FIRST_CHILD(pRoot), cs, &pCN);
        if (OK != status)
            goto exit;

        /* Get reference to common name buffer */
        pCNPtr = (ubyte *) CS_memaccess(cs, pCN->dataOffset, pCN->length);
        if (NULL == pCNPtr)
        {
            continue; /* No common name, nothing to validate. */
        }

        /* copy to a buffer where we can then treat it as a C string */
        status = DIGI_MEMCPY(pCNBuffer, pCNPtr, pCN->length);
        if (OK != status)
            goto free_pcn;

        pCNBuffer[pCN->length] = 0x00; /* '\0' charachter */

        printf("%i -> %s\n", i, pCNBuffer);
        /* release pCNPtr irregardless of status */
free_pcn:

        CS_stopaccess(cs, pCNPtr);
        if (OK != status)
            goto exit;
    }

exit:

    /* pCert is not allocated by CERTCHAIN_getCertificate, don't free */

    if (NULL != pRoot)
    {
        (void) TREE_DeleteTreeItem((TreeItem *) pRoot);
    }
}

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_SSL_EXAMPLE_SMART_CARD__)
static sbyte4
SSL_Client_mutualAuthCertVerify(sbyte4 connectionInstance, const ubyte* hash,
                             ubyte4 hashLen, ubyte* result,
                             ubyte4 resultLength)
{

DEBUG_PRINTNL(DEBUG_SSL_EXAMPLE, (sbyte *)"Authentication using SSL_sslSettings()->funcPtrMutualAuthCertificateVerify callback ...");

#if !defined(__DISABLE_DIGICERT_SSL_RSA_SUPPORT__)
    MSTATUS status = ERR_NULL_POINTER;
    char *pFullPath = NULL;
    ubyte *pKeyData = NULL;
    ubyte4 keyDataLen = 0;
    AsymmetricKey asymKey;
#if defined(__ENABLE_DIGICERT_TLS13__)
    ubyte4 version;
#endif
    MOC_RSA(hwAccelDescr hwAccelCtx)

    CRYPTO_initAsymmetricKey(&asymKey);


    SSL_CERT_UTILS_getFullPath(sslc_KeyStore, sslc_ClientBlob, &pFullPath);

    if (NULL != pFullPath)
    {
#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
        status = DIGICERT_readFileEx(pFullPath, &pKeyData, &keyDataLen, TRUE);
#else
        status = DIGICERT_readFile(pFullPath, &pKeyData, &keyDataLen);
#endif
        if (OK > status)
        {
            goto exit;
        }

        if (OK > (status = CRYPTO_deserializeAsymKey(
                pKeyData, keyDataLen, NULL, &asymKey)))
        {
            goto exit;
        }

#if defined(__ENABLE_DIGICERT_TLS13__)
        status = SSL_getSSLTLSVersion(connectionInstance, &version);
        if (OK > status)
        {
            goto exit;
        }

        if (TLS13_MINORVERSION == version)
        {
            ubyte2 sigAlgo;
            ubyte hashId;
            ubyte4 saltLen;
            ubyte *pSig = NULL;
            ubyte4 sigLen, bitLen;

            status = SSL_getSignatureAlgo(connectionInstance, &sigAlgo);
            if (OK != status)
            {
                goto exit;
            }

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
                    status = ERR_RSA_SIGN_CALLBACK_FAIL;
                    goto exit;
            }

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
            status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux( MOC_RSA(hwAccelCtx)
                asymKey.key.pRSA, (ubyte4 *) &bitLen);
            if (OK != status)
            {
                goto exit;
            }
#else
            bitLen = VLONG_bitLength(RSA_N(asymKey.key.pRSA));
#endif
            if (bitLen == 1024 && saltLen == 64)
            {
                saltLen -= 2;
            }

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
            status = CRYPTO_INTERFACE_PKCS1_rsaPssSign(
                MOC_RSA(hwAccelCtx) g_pRandomContext, asymKey.key.pRSA, hashId,
                MOC_PKCS1_ALG_MGF1, hashId, hash, hashLen, saltLen,
                &pSig, &sigLen);
#else
            status = PKCS1_rsassaPssSign(
                MOC_RSA(hwAccelCtx) g_pRandomContext, asymKey.key.pRSA, hashId,
                PKCS1_MGF1_FUNC, hash, hashLen, saltLen,
                &pSig, &sigLen);
#endif
            if (OK != status)
            {
                goto exit;
            }

            if (resultLength == sigLen)
            {
                status = DIGI_MEMCPY(result, pSig, sigLen);
            }
            else
            {
                status = ERR_RSA_BAD_SIGNATURE;
            }

            DIGI_FREE((void **) &pSig);
        }
        else
#endif /* __ENABLE_DIGICERT_TLS13__ */
        {
            switch (asymKey.type)
            {
                case akt_rsa:
                    status = RSA_signMessage(
                        MOC_RSA(hwAccelCtx) asymKey.key.pRSA, hash, hashLen, result,
                        NULL);
                    break;

                default:
                    status = ERR_SSL_UNSUPPORTED_ALGORITHM;
            }
        }
    }

exit:

    if (NULL != pFullPath)
    {
        FREE(pFullPath);
    }

    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

    if (NULL != pKeyData)
    {
        DIGI_MEMSET(pKeyData, 0x00, keyDataLen);
        DIGI_FREE((void **) &pKeyData);
    }

    return status;
#else
    return ERR_SSL_UNSUPPORTED_ALGORITHM;
#endif
}
#endif /* __ENABLE_DIGICERT_SSL_EXAMPLE_SMART_CARD__ */

/*------------------------------------------------------------------*/
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
static sbyte4
myAlertCallback(sbyte4 connectionInstance, sbyte4 alertId, sbyte4 alertClass)
{
    MOC_UNUSED(connectionInstance);

    DEBUG_PRINTNL(DEBUG_SSL_EXAMPLE, (sbyte *)"SSL_EXAMPLE: Sending Alert Back");
    DEBUG_ERROR(DEBUG_SSL_EXAMPLE, "AlertId: ", alertId);
    DEBUG_ERROR(DEBUG_SSL_EXAMPLE, "AlertClass: ", alertClass);

    return 0;
}
#endif /* __ENABLE_DIGICERT_SSL_ALERTS__ */

#if (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__))

static tls13PSKList *g_pTls13PSKList = NULL;

/* frees g_pTls13PSKList which contains all tls13PSKList objects
 * generated by myGetPSKCallback */
static void freePSKList()
{
    tls13PSKList *pTemp = NULL;
    tls13PSKList *pHead = g_pTls13PSKList;

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
}

/*------------------------------------------------------------------*/

static sbyte4 myGetPSKCallback(
    sbyte4 connectionInstance, sbyte* ServerInfo, ubyte4 serverInfoLen,
    void *pUserData, void **ppPSKs, ubyte2 *pNumPSKs,
    ubyte *selectedIndex, intBoolean *pFreeMemory)
{
    MSTATUS status = ERR_GENERAL;
    ubyte4 i = 0;
    ubyte pPskFile[MAX_PSK_FILE_LEN] = { 0 };
    tls13PSKList *pHead = NULL;
    tls13PSKList *pTemp = NULL;
    tls13PSKList **ppCur = &pHead;

    if (TRUE == sslc_useExternalPsk)
    {
        status = DIGI_CALLOC((void **) &pHead, 1, sizeof(tls13PSKList));
        if (OK != status)
        {
            goto exit;
        }

        status = SSL_serializePSK(
            &externalPsk, &(pHead->pPskData), &(pHead->pskDataLen));
        if (OK != status)
        {
            goto exit;
        }

        i = 1;
        *pFreeMemory = TRUE;
    }
    else
    {
        for (; i < count; i++)
        {
            status = DIGI_CALLOC((void **) ppCur, 1, sizeof(tls13PSKList));
            if (OK != status)
            {
                goto exit;
            }

            sprintf((char *) pPskFile, "client%d.psk", i);

#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
            status = DIGICERT_readFileEx((char *)pPskFile, &((*ppCur)->pPskData), &((*ppCur)->pskDataLen), TRUE);
#else
            status = DIGICERT_readFile((char *) pPskFile, &((*ppCur)->pPskData), &((*ppCur)->pskDataLen));
#endif
            if (OK != status)
            {
                goto exit;
            }

            ppCur = &((*ppCur)->pNextPSK);
        }

        if (NULL == g_pTls13PSKList)
        {
            g_pTls13PSKList = pHead;
        }
        else
        {
            /* Append new list to end of global list */
            pTemp = g_pTls13PSKList;
            while (NULL != pTemp->pNextPSK)
                pTemp = pTemp->pNextPSK;

            pTemp->pNextPSK = pHead;
        }

        *pFreeMemory = FALSE;
    }

    *ppPSKs = pHead;
    *pNumPSKs = i;
    *selectedIndex = 0;

exit:

    return status;
}

/*------------------------------------------------------------------*/

static sbyte4 SSL_CLIENT_savePSKCallback(
    sbyte4 connectionIndtance, sbyte* pServerInfo, ubyte4 serverInfoLen,
    void *pUserData, ubyte *pPsk, ubyte4 pskLen)
{
    MSTATUS status;
    ubyte pPskFile[MAX_PSK_FILE_LEN] = { 0 };

    sprintf((char *) pPskFile, "client%d.psk", count);

#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
    status = DIGICERT_writeFileEx((char*)pPskFile, pPsk, pskLen, TRUE);
#else
    status = DIGICERT_writeFile((char *) pPskFile, pPsk, pskLen);
#endif

    if (OK != status)
    {
        goto exit;
    }

    count++;

exit:

    return status;
}
#endif

#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
static sbyte4
SSL_CLIENT_EXAMPLE_saveTicket(sbyte4 connectionInstance, sbyte* pServerInfo,
                              ubyte4 serverInfoLen, void *pUserData,
                              ubyte *pTicket, ubyte4 ticketLen)
{
    MSTATUS status = OK;
    ubyte pTicketFile[MAX_PSK_FILE_LEN];
    ubyte4 ticketFileLen = DIGI_STRLEN((sbyte *) SSLC_DEF_TICKET);
    DIGI_MEMCPY(pTicketFile, SSLC_DEF_TICKET, ticketFileLen);
    if (NULL != pServerInfo && 0 != serverInfoLen)
    {
        DIGI_MEMCPY(pTicketFile + ticketFileLen, pServerInfo, serverInfoLen);
        ticketFileLen += serverInfoLen;
    }
    pTicketFile[ticketFileLen] = '\0';

#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
    status = DIGICERT_writeFileEx((char *)pTicketFile, pTicket, ticketLen, TRUE);
#else
    status = DIGICERT_writeFile((char *)pTicketFile, pTicket, ticketLen);
#endif
    return status;
}

static sbyte4
SSL_CLIENT_EXAMPLE_retrieveTicket(sbyte4 connectionInstance, sbyte *pServerInfo, ubyte4 serverInfoLen,
                                  void *pUserData, ubyte **ppTicket, ubyte4 *pTicketLen,
                                  intBoolean *pFreeMemory)
{
    MSTATUS status = OK;
    ubyte pTicketFile[MAX_PSK_FILE_LEN];
    ubyte4 ticketFileLen = DIGI_STRLEN((sbyte *) SSLC_DEF_TICKET);
    DIGI_MEMCPY(pTicketFile, SSLC_DEF_TICKET, ticketFileLen);
    if (NULL != pServerInfo && 0 != serverInfoLen)
    {
        DIGI_MEMCPY(pTicketFile + ticketFileLen, pServerInfo, serverInfoLen);
        ticketFileLen += serverInfoLen;
    }
    pTicketFile[ticketFileLen] = '\0';

    *pFreeMemory = TRUE;
#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
    status = DIGICERT_readFileEx((char *)pTicketFile, ppTicket, pTicketLen, TRUE);
#else
    status = DIGICERT_readFile((char *)pTicketFile, ppTicket, pTicketLen);
#endif
    return status;

}
#endif

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_TAP__

static sbyte4
SSL_EXAMPLE_getTapContext(TAP_Context **ppTapContext,
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
        if (sslc_TapProvider == TAP_PROVIDER_PKCS11)
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
SSL_EXAMPLE_TAPInit(ubyte *pTpm2ConfigFile,
                    TAP_EntityCredentialList **ppTapEntityCred,
                    TAP_CredentialList **ppTapKeyCred)
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
    configInfoList.pConfig[0].provider = sslc_TapProvider;
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

    status = TAP_getModuleList(&connInfo, sslc_TapProvider, NULL,
                               &g_moduleList, pErrContext);
#else
    status = TAP_getModuleList(NULL, sslc_TapProvider, NULL,
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

    if (sslc_TapProvider == TAP_PROVIDER_PKCS11)
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
        myPrintStatus("Failed to get credentials from Credential configuration file status : %d", status);
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
            myPrintStatus("TAP_UTILS_freeConfigInfoList : %d", status);
    }

#if (defined(__ENABLE_DIGICERT_TAP_REMOTE__))
    if (connInfo.serverName.pBuffer != NULL)
    {
        DIGI_FREE((void**)&connInfo.serverName.pBuffer);
    }
#endif
    return status;

}
#endif


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_OCSP_CLIENT__
sbyte4
myCertStatusCallback(sbyte4 connectionInstance, intBoolean certStatus)
{
    MOC_UNUSED(connectionInstance);


    DEBUG_PRINTNL(DEBUG_SSL_EXAMPLE, (sbyte *) "SSL_EXAMPLE: OCSP Stapling status");

    if (FALSE == certStatus)
    {
        DEBUG_PRINTNL(DEBUG_SSL_EXAMPLE, (sbyte *) "Server ignored cert_status extension");
    }
    else
    {
        DEBUG_PRINTNL(DEBUG_SSL_EXAMPLE, (sbyte *) "Server responded to cert_status extension");
    }

    return 0;
}

sbyte4 myOcspStatusCallback(
    sbyte4 connectionInstance, const ubyte *pCert, ubyte4 certLen,
    ubyte *pOcspResp, ubyte4 ocspRespLen, sbyte4 ocspStatus)
{
    MOC_UNUSED(connectionInstance);

    DEBUG_PRINTNL(DEBUG_SSL_EXAMPLE, (sbyte *) "SSL_EXAMPLE: OCSP Message status");

    if (NULL != pCert)
    {
        DEBUG_PRINTNL(DEBUG_SSL_EXAMPLE, (sbyte *) "Certificate provided");
    }
    else
    {
        DEBUG_PRINTNL(DEBUG_SSL_EXAMPLE, (sbyte *) "Certificate missing");
    }

    if (OK != ocspStatus)
    {
        DEBUG_PRINTNL(DEBUG_SSL_EXAMPLE, (sbyte *) "Received invalid OCSP message from peer");
    }
    else
    {
        DEBUG_PRINTNL(DEBUG_SSL_EXAMPLE, (sbyte *) "Received valid OCSP message from peer");
    }

    return ocspStatus;
}
#endif /* __ENABLE_DIGICERT_OCSP_CLIENT__ */

#if defined(__ENABLE_DIGICERT_SSL_HEARTBEAT_RFC_6520__)                                               
sbyte4 heartbeatCallback(sbyte4 connectionInstance, sbyte4 status, ubyte heartbeatType)
{
    MOC_UNUSED(connectionInstance);
    MOC_UNUSED(heartbeatType);

    return status;
}
#endif

/*------------------------------------------------------------------*/

static MSTATUS
readSecureChannel(sbyte4 connectionInstance, char* resultBuffer, sbyte4 bufferLen) {
	MSTATUS			status = (MSTATUS)OK;
	sbyte4			result = 0;
	sbyte			buffer[MAX_RECEIVE_LEN];
	int off = 0;

	(void) DIGI_MEMSET((ubyte *)resultBuffer, 0x00, bufferLen);

	while (0 <= result) {
		sbyte4 bytesReceived;
		(void) DIGI_MEMSET((ubyte *)buffer, 0x00, MAX_RECEIVE_LEN);
		result = SSL_recv(connectionInstance, buffer, MAX_RECEIVE_LEN, &bytesReceived, 0);
		if (OK > result)
		{
			return OK;
		}
		if (bytesReceived == -1) {
			myPrintStringNL("readString: Unexpected EOF!", "");
			return ERR_TCP_READ_ERROR;
		}

		if (bytesReceived > (bufferLen - off - 1))
		{
			bytesReceived = bufferLen - off - 1;
		}

        /* Skip data since received data is greater than the buffer remaining */
        if ((off + bytesReceived) >= bufferLen)
        {
            break;
        }

		(void) DIGI_MEMCPY(resultBuffer + off , buffer, bytesReceived);
		off += bytesReceived;

		if (off == (bufferLen - 1))
		{
			break;
		}
	}
	return status;
}

static MSTATUS
GetSecurePageAux(sbyte4 connectionInstance, const sbyte* pageName)
{
	sbyte			buffer[MAX_RECEIVE_LEN];
	ubyte4    		bytesSent;
	MSTATUS			status = (MSTATUS)OK;
	char* 			pResultBuffer;

#if 0
	/* Since we send SNI we can't use HTTP/1.0. Must use HTTP 1.1 and
	 * send Host HTTP header
	 */
	(void) sprintf((char  *)buffer, "GET /%s HTTP/1.0\r\n\r\n", pageName);
#endif
	(void) sprintf((char  *)buffer, "GET /%s HTTP/1.1\r\nHost:%s\r\n\r\n", pageName,
		sslc_ServerName);

        myPrintStringNL("------------------> Sending command:\n", buffer);

	bytesSent = SSL_send(connectionInstance, (sbyte*)buffer, DIGI_STRLEN((const sbyte*)buffer));

	if (bytesSent == DIGI_STRLEN((const sbyte*)buffer) && pageName[0] != 'q')
	{
		if (OK != (status = DIGI_MALLOC((void**)&pResultBuffer, MAX_BUFFER_LEN)))
		{
			goto exit;
		}

		if (OK != (status = readSecureChannel(connectionInstance, pResultBuffer, MAX_BUFFER_LEN)))
		{
			(void) DIGI_FREE((void**)&pResultBuffer);
			goto exit;
		}
		myPrintStringNL("------------------> resultBuffer:\n", pResultBuffer);
		if ((MAX_BUFFER_LEN - 1) == DIGI_STRLEN((sbyte *) pResultBuffer))
		{
			myPrintStringNL("------------------> resultBuffer is full!", "");
		}
		(void) DIGI_FREE((void**)&pResultBuffer);
		return status;
	}
	else
	{
	    status = bytesSent;
	}

	exit:

	return status;
}

#ifdef __ENABLE_DIGICERT_SSL_PSK_SUPPORT__
static sbyte4
SSL_LOOPBACK2_EXAMPLE_funcPtrChosePSK(sbyte4 connectionInstance,
		ubyte *pHintPSK, ubyte4 hintLength,
		ubyte retPskIdentity[SSL_PSK_SERVER_IDENTITY_LENGTH],
		ubyte4 *pRetPskIdentity,
		ubyte retPSK[SSL_PSK_MAX_LENGTH], ubyte4 *pRetLengthPSK)
{
	MOC_UNUSED(connectionInstance);
	MOC_UNUSED(pHintPSK);
	MOC_UNUSED(hintLength);

	/* this is a client side callback */

	/* according to the standard, the client choses the psk to use */
	/* the client must send back the identity (i.e. name) of the psk to use */
	DIGI_MEMCPY(retPskIdentity, "shalom", 6);
	*pRetPskIdentity = 6;

	/* here we return the preshared secret... keep this safe! */
	DIGI_MEMCPY(retPSK, "the eagle flies at midnight.", 28);
	*pRetLengthPSK = 28;    /* note: make sure your lengths are correct!  */

	/* return a negative value, if you want the session to abort */

	return 0;
}
#endif

#if defined(__ENABLE_DIGICERT_EXAMPLE_AESGCM_CIPHERS_ONLY__)
static sbyte4 setAESGCMCiphers(sbyte4 connectionInstance)
{
    sbyte4 status = OK;
    ubyte2 pCipherList[] = {0x1302, 0x1301, 0xC02B, 0xC030, 0xC02B, 0xC02F,
        0x009F, 0x009E, 0xC02E, 0xC032, 0xC02D, 0xC031, 0x009D, 0x009C};
    ubyte4 cipherListLen = 14;

    return SSL_setCipherAlgorithm(connectionInstance,
        pCipherList, cipherListLen, 0/* TLS13_cipher */ );
}
#endif

/*------------------------------------------------------------------*/
#ifdef __ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__
/* if __TEST_CLIENT_CIPHER_SELECT__ is defined then
it will select all the ciphers one at a time before connecting
to a server that should have all the ciphers enabled otherwise
it will connect repeatedly to the server -- this can be used with
a server test program that select ciphers at run time. i.e. roles
are reversed about where (client or server) servers are enabled
at runtime */
static void
SSL_CLIENTEXAMPLE_cipherSelectTest()
{
    sbyte4          connectionInstance;
    TCP_SOCKET      mySocket = -1;
    certStorePtr pSslClientCertStore = NULL;

#ifdef __ENABLE_DIGICERT_IPV6__
    sbyte*          serverIpAddress = (sbyte *) "::01";
#else
    sbyte*          serverIpAddress = (sbyte *) sslc_ServerIpAddr;
#endif
    const ubyte2    serverPort = sslc_ServerPort;

    ubyte2           cipherIds[] = {
        0x35, 0x2f, 0x04, 0x05, 0x0a, 0x09, 0x39, 0x33,
        0x16, 0x15, 0x3a, 0x34, 0x18, 0x1b, 0x1a, 0x8d,
        0x8c, 0x8a, 0x8b, 0x95, 0x94, 0x92, 0x93, 0x91,
        0x90, 0x8e, 0x8f, 0x02, 0x01, };
    ubyte4          i;

    for ( i = 0; i < COUNTOF( cipherIds); ++i)
    {
#ifdef __TEST_CLIENT_CIPHER_SELECT__
        (void) printf("---Testing cipher 0x%x-----\n", cipherIds[i]);
#endif
        if (OK > TCP_CONNECT(&mySocket, serverIpAddress, serverPort)){
            return;
        }

        if (OK > (connectionInstance = SSL_connect(mySocket, 0, NULL, NULL, (sbyte *) sslc_ServerName, pSslClientCertStore)))
        {
            TCP_CLOSE_SOCKET(mySocket);
            return;
        }

#ifdef __TEST_CLIENT_CIPHER_SELECT__
        if ( OK > SSL_enableCiphers( connectionInstance, cipherIds+i, 1))
        {
            (void) printf("Error enabling cipher 0x%x\n", cipherIds[i]);
            SSL_closeConnection(connectionInstance);
            TCP_CLOSE_SOCKET(mySocket);
            continue;
        }
#endif

        if (OK > SSL_negotiateConnection(connectionInstance))
        {
#ifdef __TEST_CLIENT_CIPHER_SELECT__
            (void) printf("Error connecting with cipher 0x%x\n", cipherIds[i]);
#endif
            SSL_closeConnection(connectionInstance);
            TCP_CLOSE_SOCKET(mySocket);
            continue;
        }

#ifdef __TEST_CLIENT_CIPHER_SELECT__
        GetSecurePageAux(connectionInstance, (sbyte *) "TestCipherClientEnabled");
#else
        GetSecurePageAux(connectionInstance, (sbyte *) "TestCipherServerEnabled");
#endif

        SSL_closeConnection(connectionInstance);
        TCP_CLOSE_SOCKET(mySocket);

        (void) printf("--------\n");

    }
}

#endif /* __ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__ */

#if defined(__RTOS_WIN32__)

static TCHAR
WIN32_getch()
{
    DWORD mode, cc;
    TCHAR c = 0;
    HANDLE h = GetStdHandle (STD_INPUT_HANDLE);

    if (h == NULL)
    {
        return 0; /* Error */
    }
    GetConsoleMode (h, &mode);
    SetConsoleMode (h, mode & ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT));

    ReadConsole (h, &c, 1, &cc, NULL);

    SetConsoleMode  (h, mode);
    return c;
}

static MSTATUS getPassword(
    ubyte *pBuffer,
    ubyte4 bufferLen,
    ubyte4 *pOutLen
    )
{
    ubyte4 i;
    int c = 0;

    printf ("Enter PEM pass phrase : ");

    i = 0;
    do
    {
        c = WIN32_getch();

        switch (c)
        {
            case 0x00:
                break;

            case 0x08:          /* backspace */
                if (i > 1)
                    --i;
                break;

            case 0x0D:
                break;

            default:
                if (c >= 20)
                {
                    if (i < bufferLen)
                    {
                        pBuffer[i++] = c;
                    }
                }
                break;
        }
    } while (c != 0x0D);

    printf("\n");

    *pOutLen = i;

    return OK;
}

#elif defined( __RTOS_LINUX__) || defined(__RTOS_VXWORKS__) || defined(__RTOS_CYGWIN__) || \
      defined(__RTOS_SOLARIS__) || defined(__RTOS_IRIX__) || defined(__RTOS_OPENBSD__) || \
      defined(__RTOS_ANDROID__) || defined(__RTOS_FREEBSD__) || defined(__RTOS_OSX__)

char *getpass(const char *);

static MSTATUS getPassword(
    ubyte *pBuffer,
    ubyte4 bufferLen,
    ubyte4 *pOutLen
    )
{
    MSTATUS status;
    sbyte *pPassword;
    ubyte4 passwordLen;

    *pOutLen = 0;

    /* The "getpass" function has been deprecated by GCC, however GCC
     * still has the implementation compiled into their libraries.
     * If this symbol is undefined during a build then it most likely
     * means that GCC has completely removed the function. In that case
     * the getpass function call should be updated.
     */
#ifdef __RTOS_ANDROID__
    pPassword = NULL;
#else
    pPassword = (sbyte *) getpass("Enter PEM pass phrase : ");
#endif

    status = ERR_NULL_POINTER;
    if (NULL == pPassword)
        goto exit;

    passwordLen = DIGI_STRLEN(pPassword);

    if (passwordLen > bufferLen)
        passwordLen = bufferLen;

    status = DIGI_MEMCPY(pBuffer, (ubyte *) pPassword, passwordLen);
    if (OK != status)
        goto exit;

    *pOutLen = passwordLen;

exit:

    if (pPassword)
    {
        DIGI_MEMSET((ubyte *)pPassword, 0, passwordLen);
    }
    return status;
}

#endif

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT_EXAMPLE__)
/* Reads a certificate in der format and key in pem formart */
static MSTATUS myClientCert(sbyte4 connInstance,
                           SizedBuffer **ppRetCert, ubyte4 *pRetNumCerts,
                           ubyte **ppRetKeyBlob, ubyte4 *pRetKeyBlobLen,
                           ubyte **ppRetCACert, ubyte4 *pRetNumCACerts)
{
	certDescriptor certDesc = {0};
	char * fullpath = NULL;
	AsymmetricKey asymKey = { 0 };
    MSTATUS status = OK;
	ubyte *pContents = NULL;
	ubyte4 contentsLen;
	SizedBuffer certificate;
    hwAccelDescr hwAccelCtx = 0;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
    {
        goto exit;
    }

    if( sslc_ClientCert )
    {
	    SSL_CERT_UTILS_getFullPath(sslc_KeyStore, sslc_ClientCert, &fullpath);

	    if(NULL != fullpath)
	    {
#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
            status = DPM_readSignedFile(fullpath, &certificate.data, (ubyte4 *)&certificate.length, TRUE, DPM_CERTS);
#else
            status = DIGICERT_readFile(fullpath, &certificate.data, (ubyte4 *)&certificate.length);
#endif

		    if (OK > status)
		    {
			    myPrintStringError("initUpcallsAndCertStores::DIGICERT_readFile()::file ", fullpath);
			    goto exit;
		    }

            *pRetNumCerts = 1;
            **ppRetCert = certificate;
	    }

	    SSL_CERT_UTILS_getFullPath(sslc_KeyStore, sslc_ClientBlob, &fullpath);

	    if(NULL != fullpath)
        {
            /* Key file can be either in PEM or DER format */
#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
            status = DIGICERT_readFileEx(fullpath, &pContents, &contentsLen, TRUE);
#else
            status = DIGICERT_readFile(fullpath, &pContents, &contentsLen);
#endif

            if (OK > status)
            {
                myPrintStringError("initUpcallsAndCertStores::DIGICERT_readFile()::file ", fullpath);
                goto exit;
            }

            status = CRYPTO_initAsymmetricKey (&asymKey);
            if (OK != status)
                goto exit;

            if (OK > (status = CRYPTO_deserializeAsymKey(
                MOC_ASYM(hwAccelCtx) pContents, contentsLen, NULL, &asymKey)))
            {
                goto exit;
            }

            status = KEYBLOB_makeKeyBlobEx(&asymKey, ppRetKeyBlob, pRetKeyBlobLen);
            if (OK != status)
                goto exit;

            CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
        }
    }

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
    if (pContents)
        FREE(pContents);

    return status;
}
#endif

/*------------------------------------------------------------------*/

#if 0
static const sbyte*
clientFindStr( const char* what, const sbyte* buffer, sbyte4 bufferSize)
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
    return NULL;
}
#endif  /* function not used in this file */

static int
initUpcallsAndCertStores()
{
	int i;
	certDescriptor certDesc = {0};
	SizedBuffer certificate;
	MSTATUS status;
	char * fullpath = NULL;
    ubyte* pw = NULL;
    ubyte4 pwLen = 0;
    AsymmetricKey asymKey = { 0 };
    ubyte *pKeyBlob = NULL;
    ubyte4 keyBlobLength = 0;
    hwAccelDescr hwAccelCtx = 0;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
    {
        goto exit;
    }

	if (OK > (status = CERT_STORE_createStore(&pClientSslCertStore))) {
		DEBUG_ERROR(DEBUG_SSL_EXAMPLE,
			"initUpcallsAndCertStores::CERT_STORE_createStore::status: ", status);
		goto exit;
	}

	/* Look for clientcert and fill the Keystore only if
	   __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT_EXAMPLE__ is defined;
	   sslc_ClientCert is NULL is the flag is not defined */
#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT_EXAMPLE__
    if((NULL != sslc_ClientCert) && (0 == sslc_ClientCertCb))
    {
	    SSL_CERT_UTILS_getFullPath(sslc_KeyStore, sslc_ClientCert, &fullpath);

	    if(NULL != fullpath)
	    {
#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
            status = DPM_readSignedFile(fullpath, &certDesc.pCertificate, &certDesc.certLength, TRUE, DPM_CERTS);
#else
            status = DIGICERT_readFile(fullpath, &certDesc.pCertificate, &certDesc.certLength);
#endif

		    if (OK > status)
		    {
			    myPrintStringError("initUpcallsAndCertStores::DIGICERT_readFile()::file ", fullpath);
			    goto exit;
		    }
	    }

#if !defined(__ENABLE_DIGICERT_SSL_EXAMPLE_SMART_CARD__)
    /* Get full path to the key data.
     */
    SSL_CERT_UTILS_getFullPath(sslc_KeyStore, sslc_ClientBlob, &fullpath);

    if(NULL != fullpath)
    {
#ifdef __ENABLE_DIGICERT_PEM_DER_PRIVATE_KEY__
        /* Perform TAP initialization.
         */
#ifdef __ENABLE_DIGICERT_TAP__

        if (OK != (status = SSL_EXAMPLE_TAPInit(tap_ConfigFile,
                                                &g_pTapEntityCred,
                                                &g_pTapKeyCred)))
        {
            DEBUG_ERROR(DEBUG_SSL_EXAMPLE,"SSL_EXAMPLE_TAPInit failed. status = %d\n", status);
            goto exit;
        }

        if (OK > (status = CRYPTO_INTERFACE_registerTapCtxCallback((void *)&SSL_EXAMPLE_getTapContext)))
            goto exit;
#endif

        ubyte4 contentsLen;
        ubyte *pContents = NULL;

        /* Key file can be either in PEM or DER format */
#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
        status = DIGICERT_readFileEx(fullpath, &pContents, &contentsLen, TRUE);
#else
        status = DIGICERT_readFile(fullpath, &pContents, &contentsLen);
#endif

        if (OK > status)
        {
            myPrintStringError("initUpcallsAndCertStores::DIGICERT_readFile()::file ", fullpath);
            goto exit;
        }

        status = CRYPTO_initAsymmetricKey (&asymKey);
        if (OK != status)
            goto exit1;

        /* Deserialize the key data.
         */
        status = CRYPTO_deserializeAsymKey (
            MOC_ASYM(hwAccelCtx) pContents, contentsLen, NULL, &asymKey);
        if (OK != status)
        {
            /* If the deserialization failed then it might be an encrypted key.
             * Convert the PEM to DER before calling PKCS8 function */
            if ( OK > (status = CA_MGMT_decodeCertificate( pContents, contentsLen,
                                            &pKeyBlob, &keyBlobLength)))
            {
                goto exit;
            }

            if (OK > (status = PKCS_getPKCS8KeyEx(MOC_HW(0) pKeyBlob,
                                        keyBlobLength, (ubyte*)"", 0, &asymKey)))
            {
                if (ERR_PKCS8_ENCRYPTED_KEY == status)
                {
                    if (OK > (status = DIGI_CALLOC((void**)&pw, 1, MAX_PASSWORD_SIZE)))
                    {
                        goto exit1;
                    }

                    /* Invoke the password callback. The callback will take care of casting the callback information
                     * into the appropriate type. Upon success the password should be placed in the buffer and
                     * the function should output the length of the password as well. If the operation failed then
                     * the output length should be 0 and the status should indicate the type of error that occured.
                     */
                    status = getPassword(pw, MAX_PASSWORD_SIZE, &pwLen);
                }
                if ( (OK != status) || (0 >= pwLen) )
                    goto exit1;

                if (OK > (status = PKCS_getPKCS8KeyEx(MOC_HW(0) pKeyBlob, keyBlobLength, pw, pwLen, &asymKey)))
                    goto exit1;
            }

        }

        status = CRYPTO_serializeAsymKey(MOC_ASYM(hwAccelCtx) &asymKey, mocanaBlobVersion2, &certDesc.pKeyBlob, &certDesc.keyBlobLength);
        if (OK != status)
            goto exit1;


exit1:

        if (pContents)
        {
            DIGI_FREE((void **)&pContents);
        }
        CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

        if (OK > status)
            goto exit;
#else
#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
        status = DIGICERT_readFileEx(fullpath, &certDesc.pKeyBlob, &certDesc.keyBlobLength, TRUE);
#else
        status = DIGICERT_readFile(fullpath, &certDesc.pKeyBlob, &certDesc.keyBlobLength);
#endif
        if (OK > status)
        {
            myPrintStringError("initUpcallsAndCertStores::DIGICERT_readFile()::file ", fullpath);
            goto exit;
        }
#endif
    }
#endif /* __ENABLE_DIGICERT_SSL_EXAMPLE_SMART_CARD__ */

    certificate.length = certDesc.certLength;
    certificate.data = certDesc.pCertificate;

#if defined(__ENABLE_DIGICERT_SSL_CLIENT_EXAMPLE_CERTSTORE_ALIAS__)
        if (OK > (status = CERT_STORE_addIdentityEx(pClientSslCertStore, g_pAlias, g_aliasLen,
                                                    certificate.data, certificate.length,
                                                    certDesc.pKeyBlob, certDesc.keyBlobLength)))
        {
            goto exit;
        }
#else
		if (OK > (status = CERT_STORE_addIdentityWithCertificateChain(pClientSslCertStore, &certificate, 1, certDesc.pKeyBlob, certDesc.keyBlobLength))) {
			myPrintError("initUpcallsAndCertStores::CERT_STORE_addIdentityWithCertificateChain::status ", status);
			goto exit;
		}
#endif
		/* callback */
#if defined(__ENABLE_DIGICERT_SSL_EXAMPLE_SMART_CARD__)
		SSL_sslSettings()->funcPtrMutualAuthCertificateVerify = SSL_Client_mutualAuthCertVerify;
#endif

		FREE(certDesc.pCertificate); certDesc.pCertificate = 0;
		FREE(certDesc.pKeyBlob); certDesc.pKeyBlob = 0;
	}
#endif /* __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT_EXAMPLE__ */

	if (sslc_ServerCert) {
	    ubyte*	certData = NULL;
	    ubyte4	certLength = 0;
        SSL_CERT_UTILS_getFullPath(sslc_KeyStore, sslc_ServerCert, &fullpath);
        if(NULL != fullpath)
        {
#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
            status = DPM_readSignedFile(fullpath, &certData, &certLength, TRUE, DPM_CA_CERTS);
#else
            status = DIGICERT_readFile(fullpath, &certData, &certLength);
#endif

	        if (OK > status)
		    {
		        myPrintStringError("initUpcallsAndCertStores::DIGICERT_readFile()::file ", fullpath);
		        goto exit;
		    }

#ifdef __ENABLE_DIGICERT_CV_CERT__
            if (0x7F == certData[0])
            {
                /* If the first byte is 0x7F, this could be a CV Cert. Try to add it as a
                    * trustpoint. */
                status = CERT_STORE_CVC_addTrustPoint(pClientSslCertStore, certData, certLength);
                if (OK != status)
                {
                    myPrintError("initUpcallsAndCertStores::CERT_STORE_CVC_addTrustPoint::status ", status);
                }
            }
            else
#endif
            {
                if (OK > (status = CERT_STORE_addTrustPoint(pClientSslCertStore, certData, certLength)))
                {

                        myPrintError("initUpcallsAndCertStores::CERT_STORE_addTrustPoint::status ", status);
                }
            }

            if (certData)
            {
                DIGI_FREE((void **)&certData);
            }

            if (OK > status)
                goto exit;
        }
	}
    else
    {
        for (i = 0 ; i < COUNTOF(gRootCerts); ++i)
        {
            if (sslc_ServerCert && !strcmp(gRootCerts[i].fileName, sslc_ServerCert))
            continue; /* already done in previous step */

            SSL_CERT_UTILS_getFullPath(sslc_KeyStore, gRootCerts[i].fileName, &fullpath);
            if(NULL != fullpath)
            {
                if (OK > (status = DIGICERT_readFile(fullpath,
                    &gRootCerts[i].certData, &gRootCerts[i].certLength)))
                {
                    myPrintStringError("initUpcallsAndCertStores::DIGICERT_readFile()::file ", fullpath);
                    goto exit;
                }
            }
#ifdef __ENABLE_DIGICERT_CV_CERT__
            if (0x7F == gRootCerts[i].certData[0])
            {
                /* If the first byte is 0x7F, this could be a CV Cert. Try to add it as a
                    * trustpoint. */
                status = CERT_STORE_CVC_addTrustPoint(pClientSslCertStore, gRootCerts[i].certData, gRootCerts[i].certLength);
                if (OK != status)
                {
                    myPrintError("initUpcallsAndCertStores::CERT_STORE_CVC_addTrustPoint::status ", status);
                    goto exit;
                }
            }
            else
#endif
            {
                if (OK > (status = CERT_STORE_addTrustPoint(pClientSslCertStore, gRootCerts[i].certData, gRootCerts[i].certLength)))
                {

                        myPrintError("initUpcallsAndCertStores::CERT_STORE_addTrustPoint::status ", status);
                        goto exit;
                }
            }
        }
    }
exit:
    if (fullpath)
        FREE(fullpath);

#ifdef __ENABLE_DIGICERT_TAP__
    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
#endif

    if (pw)
    {
        DIGI_MEMSET(pw, 0, pwLen);
        DIGI_FREE ((void**)&pw);
    }

    if (pKeyBlob)
        DIGI_FREE ((void**)&pKeyBlob);

    for (i = 0 ; i < COUNTOF(gRootCerts); ++i)
    {
        FREE(gRootCerts[i].certData);
    }

	FREE(certDesc.pCertificate); certDesc.pCertificate = 0;
	FREE(certDesc.pKeyBlob); certDesc.pKeyBlob = 0;

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

	return status;
}

static MSTATUS
uninitUpcallsAndCertStores()
{

    if(NULL != sslc_ServerIpAddr)
    {
        (void) DIGI_FREE((void **)&sslc_ServerIpAddr);
    }
    if(NULL != sslc_ServerName)
    {
        (void) DIGI_FREE((void **)&sslc_ServerName);
    }
    if(NULL != sslc_ServerCert)
    {
        (void) DIGI_FREE((void **)&sslc_ServerCert);
    }
    if(NULL != sslc_ClientCert)
    {
        (void) DIGI_FREE((void **)&sslc_ClientCert);
    }
    if(NULL != sslc_ClientBlob)
    {
        (void) DIGI_FREE((void **)&sslc_ClientBlob);
    }
    if(NULL != sslc_KeyStore)
    {
        (void) DIGI_FREE((void **)&sslc_KeyStore);
    }
    if (NULL != sslc_supportedGroup)
    {
        (void) DIGI_FREE((void **)&sslc_supportedGroup);
    }
    return CERT_STORE_releaseStore(&pClientSslCertStore);
}

#ifdef __ENABLE_DIGICERT_TAP__
static void uninitTAP()
{
    MSTATUS status = OK;
    TAP_ErrorContext *pErrContext = NULL;

#if defined(__ENABLE_DIGICERT_TAP_DEFER_UNLOADKEY__)
    (void) SSL_TAP_clearKeyAndToken();
#endif

#if (defined(__ENABLE_DIGICERT_TAP_REMOTE__))
    if (NULL != taps_ServerName)
    {
        DIGI_FREE((void **)&taps_ServerName);
    }
#endif
    if (NULL != tap_ConfigFile)
    {
        DIGI_FREE((void **)&tap_ConfigFile);
    }

    if (g_pTapContext != NULL)
	    TAP_uninitContext(&g_pTapContext, pErrContext);

    /* Free module list */
    status = TAP_freeModuleList(&g_moduleList);
    if (OK != status)
        myPrintStatus("TAP_freeModuleList : %d", status);

    if (g_pTapEntityCred)
    {
        TAP_UTILS_clearEntityCredentialList(g_pTapEntityCred);
        DIGI_FREE((void **)&g_pTapEntityCred);
    }

    if (g_pTapKeyCred)
    {
        TAP_UTILS_clearCredentialList(g_pTapKeyCred);
        DIGI_FREE((void **)&g_pTapKeyCred);
    }

    TAP_uninit(pErrContext);
}
#endif

sbyte4 setSupportedGroupForConnection(sbyte4 connectionInstance)
{
    MSTATUS status = OK;
    if (sslc_supportedGroup != NULL)
    {
        ubyte2 pSupportedGroupList[1] = {0};

        if (!strcmp("secp256r1", sslc_supportedGroup))
            pSupportedGroupList[0] = tlsExtNamedCurves_secp256r1;
        else if (!strcmp("secp384r1", sslc_supportedGroup))
            pSupportedGroupList[0] = tlsExtNamedCurves_secp384r1;
        else if (!strcmp("secp521r1", sslc_supportedGroup))
            pSupportedGroupList[0] = tlsExtNamedCurves_secp521r1;
        else if (!strcmp("secp224r1", sslc_supportedGroup))
            pSupportedGroupList[0] = tlsExtNamedCurves_secp224r1;
        else if (!strcmp("secp192r1", sslc_supportedGroup))
            pSupportedGroupList[0] = tlsExtNamedCurves_secp192r1;
        else if (!strcmp("x25519", sslc_supportedGroup))
            pSupportedGroupList[0] = tlsExtNamedCurves_x25519;
        else if (!strcmp("x448", sslc_supportedGroup))
            pSupportedGroupList[0] = tlsExtNamedCurves_x448;
        else if (!strcmp("ffdhe2048", sslc_supportedGroup))
            pSupportedGroupList[0] = tlsExtNamedCurves_ffdhe2048;
        else if (!strcmp("ffdhe3072", sslc_supportedGroup))
            pSupportedGroupList[0] = tlsExtNamedCurves_ffdhe3072;
        else if (!strcmp("ffdhe4096", sslc_supportedGroup))
            pSupportedGroupList[0] = tlsExtNamedCurves_ffdhe4096;
        else if (!strcmp("ffdhe6144", sslc_supportedGroup))
            pSupportedGroupList[0] = tlsExtNamedCurves_ffdhe6144;
        else if (!strcmp("ffdhe8192", sslc_supportedGroup))
            pSupportedGroupList[0] = tlsExtNamedCurves_ffdhe8192;
#ifdef __ENABLE_DIGICERT_PQC__
        else if (!strcmp("X25519MLKEM768", sslc_supportedGroup))
            pSupportedGroupList[0] = tlsExtHybrid_X25519MLKEM768;
        else if (!strcmp("secp256r1MLKEM768", sslc_supportedGroup))
            pSupportedGroupList[0] = tlsExtHybrid_SecP256r1MLKEM768;
#endif
        status = SSL_setCipherAlgorithm(connectionInstance, pSupportedGroupList, 1, 1/* TLS13_supportedGroups */ );
    }

    return status;
}

static int sendCommandToServer(sbyte4 connectionInstance, sbyte* serverIpAddress,
	const ubyte2 serverPort, ubyte sessionIdLen, ubyte sessionId[SSL_MAXSESSIONIDSIZE],
	ubyte masterSecret[SSL_MASTERSECRETSIZE], const sbyte* pageName)
{
	MSTATUS    status;
	TCP_SOCKET socket;
#if defined(__ENABLE_DIGICERT_TLS13__) || defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
    ubyte requestTicket = 1;
#endif
#if defined(__ENABLE_DIGICERT_TLS13__)
	ubyte pskMode       = 1;
#endif

	/* resume session now */
	if (OK > (status = TCP_CONNECT(&socket, serverIpAddress, serverPort)))
	{
		goto exit;
	}

#ifdef __ENABLE_DIGICERT_SSL_PSK_SUPPORT__
	SSL_sslSettings()->funcPtrChoosePSK  = SSL_LOOPBACK2_EXAMPLE_funcPtrChosePSK;
#endif

	if (OK > (connectionInstance = SSL_connect(socket, sessionIdLen, sessionId,
			masterSecret, (const sbyte *)sslc_ServerName, pClientSslCertStore)))
		goto exit;

#if (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__))
    if (TRUE == sslc_useExternalPsk)
    {
        if (OK > (status = SSL_setCipherAlgorithm(connectionInstance, &externalPsk.selectedCipherSuiteId, 1, 0)))
            goto exit;
    }
#endif

#if defined(__ENABLE_DIGICERT_EXAMPLE_AESGCM_CIPHERS_ONLY__)
    if (OK > (status = setAESGCMCiphers(connectionInstance)))
        goto exit;
#endif

    /* Defensics Test Scenario where Defensics is configured for DHE Groups and
     * we are sending 'PSK with ECDHE' for Forward Secrecy leading to Handshake Failure.
     * Making sure that we send what the SSL Client is initially configured with.
     */   
    if (strcmp(pageName, (const sbyte *)RESUMETESTPAGE) == 0)
    {
	if(OK > (setSupportedGroupForConnection(connectionInstance)))
	    goto exit;
    }

#if defined(__ENABLE_DIGICERT_TLS13__) || defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
    if (OK > SSL_ioctl(connectionInstance, SSL_REQUEST_SESSION_TICKET, &requestTicket))
        goto exit;
#endif

#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
    if (OK > (SSL_setClientSaveTicketCallback(connectionInstance, &SSL_CLIENT_EXAMPLE_saveTicket)))
    {
        goto exit;
    }

    if (OK > (SSL_setClientRetrieveTicketCallback(connectionInstance, &SSL_CLIENT_EXAMPLE_retrieveTicket)))
    {
        goto exit;
    }
#endif

#if (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__))
    if (OK > SSL_setClientSavePSKCallback(connectionInstance, &SSL_CLIENT_savePSKCallback))
        goto exit;

    if (OK > SSL_CLIENT_setRetrievePSKCallback(connectionInstance, &myGetPSKCallback))
        goto exit;

    if (OK > SSL_setServerNameIndication(connectionInstance, sslc_ServerName))
        goto exit;

    if (OK > SSL_ioctl(connectionInstance, SSL_PSK_KEY_EXCHANGE_MODE, &pskMode/*psk_dhe_ke*/))
        goto exit;

#if defined(__ENABLE_DIGICERT_TLS13_0RTT__)
    if (NULL != sslc_EarlyData)
    {
        if (OK > SSL_setEarlyData(connectionInstance, (ubyte*)sslc_EarlyData, DIGI_STRLEN((sbyte*)sslc_EarlyData)))
            goto exit;
    }
#endif /* __ENABLE_DIGICERT_TLS13_0RTT__ */
#endif

#ifdef __ENABLE_DIGICERT_SSL_SRP__
    if (OK > (status = SSL_setClientSRPIdentity(connectionInstance,
                                                (ubyte*) "scott", 5,
                                                (ubyte*) "tiger", 5)))
    {
        goto exit;
    }
#endif/* __ENABLE_DIGICERT_SSL_SRP__ */

#ifdef __ENABLE_DIGICERT_OCSP_CLIENT__
    /* Responder Ids; configure a list of trusted responder certificates */
    /* Note: Also set the correct trusted Responder Cert count */
    char *pTrustedResponderCertsPath[] = {
        /*"ca/demoCA/cacert.der",*/
        /*"../client/servercert.der",*/
        /*"ca/newcert4.der"*/
        /*"gdroot-g2.der"*/
        NULL
    };
    ubyte4 trustedRespondercertCount = 0;

    if (OK > (MSTATUS) SSL_setCertifcateStatusRequestExtensions(
            connectionInstance, pTrustedResponderCertsPath,
            trustedRespondercertCount, NULL, 0))
        goto exit;

    SSL_sslSettings()->funcPtrCertStatusCallback = myCertStatusCallback;
    SSL_setOCSPCallback(myOcspStatusCallback);
#endif /* __ENABLE_DIGICERT_OCSP_CLIENT__ */

#if defined(__ENABLE_DIGICERT_SSL_CLIENT_EXAMPLE_CERTSTORE_ALIAS__)
    if (OK > (status = SSL_setMutualAuthCertificateAlias(connectionInstance, g_pAlias, g_aliasLen)))
    {
        goto exit;
    }
#endif

#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
    {
        ubyte4 value = 1, version = 3/* TLS 1.2 */;
        SSL_ioctl(connectionInstance, SSL_SET_USE_EXTENDED_MASTERSECRET, (void *)((uintptr)value));
        SSL_ioctl(connectionInstance, SSL_SET_VERSION, (void *)((uintptr)version));
    }
#endif
#if defined(__ENABLE_DIGICERT_SSL_HEARTBEAT_RFC_6520__)
    {
        ubyte value = peerAllowedToSend;
        status = SSL_enableHeartbeatSupport(connectionInstance, value, heartbeatCallback);
    }
#endif
    if (OK > SSL_negotiateConnection(connectionInstance))
	{
		goto exit;
	}

#if defined(__ENABLE_DIGICERT_SSL_HEARTBEAT_RFC_6520__) && \
    !defined(__ENABLE_DIGICERT_SSL_EXAMPLE_INTEROP_TEST__)
    status = SSL_sendHeartbeatMessage(connectionInstance);
#endif
#if defined(__ENABLE_DIGICERT_SSL_EXAMPLE_INTEROP_TICKET_TEST__) || \
    defined(__ENABLE_DIGICERT_SSL_EXAMPLE_INTEROP_SESSIONID_TEST__) || \
    defined(__ENABLE_DIGICERT_SSL_HEARTBEAT_RFC_6520__)

    {
        ubyte buffer[MAX_BUFFER_LEN] = {0};
        if (OK != (status = readSecureChannel(connectionInstance, buffer, MAX_BUFFER_LEN)))
        {
            goto exit;
        }
    }
#endif

	status = GetSecurePageAux(connectionInstance, pageName);

    RTOS_sleepMS(1000);

exit:
	(void) SSL_closeConnection(connectionInstance);
	(void) TCP_CLOSE_SOCKET(socket);
	return (int)status;
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
/*------------------------------------------------------------------*/

static void
SSL_CLIENT_EXAMPLE_displayHelp(char *prog)
{

	(void) printf(" Usage: %s\n", prog);
	(void) printf(" <options>\n");
	(void) printf("  options:\n");
	(void) printf("    -h | ?                             Help\n");
	(void) printf("    -ssl_ip <IP>                       SSL server ip address\n");
	(void) printf("    -ssl_port <port>                   SSL server port\n");
	(void) printf("    -ssl_servername <server_name>      SSL server name\n");
	(void) printf("    -ssl_certpath <path_to_files>      directory path to the cert files\n");
	(void) printf("    -ssl_server_cert <cert_name>       name of the server cert\n");
	(void) printf("    -ssl_supported_group <group_name>  name of the supported group\n");
#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT_EXAMPLE__
	(void) printf("    -ssl_client_cert <cert_name>       name of the client cert\n");
	(void) printf("    -ssl_client_keyblob <blob_name>    name of the client keyblob file\n");
	(void) printf("    -ssl_enable_client_cert_cb <1/0>      Enable Client Cert Callback functionality\n");
#endif
#if defined(__ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__)
	(void) printf("    -ssl_client_cipher_test               specifies the client to run the cipher suite tests\n");
#endif
#if (defined(__ENABLE_DIGICERT_TLS13__) && (defined(__ENABLE_DIGICERT_TLS13_PSK__)))
	(void) printf("    -ssl_external_psk                     specifies to use an external PSK for TLS 1.3\n");
#if defined(__ENABLE_DIGICERT_TLS13_0RTT__)
    (void) printf("    -ssl_early_data     <early_data>      specifies the early data content to be send\n");
#endif
#endif
#if (defined(__ENABLE_DIGICERT_TAP__))
#if (defined(__ENABLE_DIGICERT_TAP_REMOTE__))
	(void) printf("    -tap_server_port <tap_server_port> TAP server port\n");
	(void) printf("    -tap_server_name <tap_server_name> TAP server name\n");
#endif
	(void) printf("    -tap_keysource <TPM2|TPM1.2|PKCS11> key source\n");
	(void) printf("    -tap_config_file <tap_config_file> TAP config file\n");
#endif
	(void) printf("\n");
} /* SSL_CLIENT_EXAMPLE_displayHelp */


extern sbyte4
SSL_CLIENTEXAMPLE_getArgs(int argc, char *argv[])
{
	sbyte4 status = 0;
	int i;
	char *temp;

	int ipSet=0, portSet=0, serverNameSet=0, keyStoreSet=0;
	int serverCertSet=0;

#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT_EXAMPLE__
    int clientCertSet=0, clientBlobSet=0, clientCertCbSet = 0;
#endif
#if (defined(__ENABLE_DIGICERT_TAP__))
    int keySourceSet=0;
    int tapConfigFileSet = 0;
#if (defined(__ENABLE_DIGICERT_TAP_REMOTE__))
    int tapServerPortSet = 0;
    int tapServerNameSet = 0;
#endif
#endif
    if ((2 <= argc) && (('?' == argv[1][0]) || (('-' == argv[1][0]) && ('h' == argv[1][1]))))
    {
        SSL_CLIENT_EXAMPLE_displayHelp(argv[0]);
        return -1;
    }

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
/*	myPrintIntNL("Argc= ", argc);            */
/*	for (i = 0; i < argc; i++) {             */
/*		myPrintInt("Argv[", i);          */
/*		myPrintStringNL("]= ", argv[i]); */
/*	}                                        */
#endif

	sslc_getArgs_called++;
	for (i = 1; i < argc; i++)
	{
		if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-ssl_ip") == 0)
		{
			if (++i < argc)
			{
				setStringParameter(&sslc_ServerIpAddr, argv[i]);
				ipSet = 1;
			}
			continue;
		}
		else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-ssl_port") == 0)
		{
			if (++i < argc)
			{
				temp = argv[i];
				sslc_ServerPort = (unsigned short) DIGI_ATOL((const sbyte *)temp,NULL);
				portSet = 1;
			}
			continue;
		}
		else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-ssl_servername") == 0)
		{
			{
				if (++i < argc)
				{
					setStringParameter(&sslc_ServerName, argv[i]);
					serverNameSet = 1;
				}
				continue;
			}
		}
		else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-ssl_certpath") == 0)
		{
			{
				if (++i < argc)
				{
					setStringParameter(&sslc_KeyStore, argv[i]);
					keyStoreSet = 1;
				}
				continue;
			}
		}
		else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-ssl_server_cert") == 0)
		{
			{
				if (++i < argc)
				{
					setStringParameter(&sslc_ServerCert, argv[i]);
					serverCertSet = 1;
				}
				continue;
			}
		}
		else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-ssl_supported_group") == 0)
		{
			{
				if (++i < argc)
				{
					setStringParameter(&sslc_supportedGroup, argv[i]);
					serverCertSet = 1;
				}
				continue;
			}
		}
#if defined(__ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__)
		else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-ssl_client_cipher_test") == 0)
		{
			sslc_CipherSuiteTest = 1;
			continue;
		}
#endif
#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT_EXAMPLE__
		else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-ssl_client_cert") == 0)
		{
			{
				if (++i < argc)
				{
					setStringParameter(&sslc_ClientCert, argv[i]);
					clientCertSet = 1;
				}
				continue;
			}
		}
		else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-ssl_client_keyblob") == 0)
		{
			{
				if (++i < argc)
				{
					setStringParameter(&sslc_ClientBlob, argv[i]);
					clientBlobSet = 1;
				}
				continue;
			}
		}
        else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-ssl_enable_client_cert_cb") == 0)
		{
			if (++i < argc)
			{
				temp = argv[i];
				sslc_ClientCertCb = (unsigned short) DIGI_ATOL((const sbyte *)temp,NULL);
				clientCertCbSet = 1;
			}
			continue;
		}
#endif
#if defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__)
        else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-ssl_external_psk") == 0)
        {
            {
                sslc_useExternalPsk = TRUE;
                continue;
            }
        }
#ifdef __ENABLE_DIGICERT_TLS13_0RTT__
        else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-ssl_early_data") == 0)
        {
            {
                if (++i < argc)
                {
                    setStringParameter((char **)&sslc_EarlyData, argv[i]);
                }
                continue;
            }
        }
#endif
#endif
#if (defined(__ENABLE_DIGICERT_TAP__))
#if (defined(__ENABLE_DIGICERT_TAP_REMOTE__))
		else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-tap_server_name") == 0)
		{
			{
				if (++i < argc)
				{
					setStringParameter(&taps_ServerName, argv[i]);
					tapServerNameSet = 1;
				}
				continue;
			}
		}
        else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-tap_server_port") == 0)
		{
			if (++i < argc)
			{
				temp = argv[i];
				taps_ServerPort = (unsigned short) DIGI_ATOL((const sbyte *)temp,NULL);
				tapServerPortSet = 1;
			}
			continue;
		}
#endif
        else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-tap_keysource") == 0)
        {
            if (++i < argc)
            {
                setStringParameter((char**)&tap_keySource, argv[i]);
                keySourceSet = 1;
            }
            continue;
        }
        else if (DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-tap_config_file") == 0)
		{
			{
				if (++i < argc)
				{
					setStringParameter(&tap_ConfigFile, argv[i]);
					tapConfigFileSet = 1;
				}
				continue;
			}
		}
#endif

	}

	/*Set defaults if nothing entered from command line*/
	if (!ipSet)
	{
		setStringParameter(&sslc_ServerIpAddr, SSLC_DEF_IP);
	}
	if (!portSet)
	{
		sslc_ServerPort = SSLC_DEF_PORT;
	}
	if (!serverNameSet)
	{
		setStringParameter(&sslc_ServerName, SSLC_DEF_SERVERNAME);
	}
	if (!keyStoreSet)
	{
		setStringParameter(&sslc_KeyStore, SSLS_DEF_KEYSTORE);
	}
	if (!serverCertSet)
	{
		setStringParameter(&sslc_ServerCert, SSLC_DEF_SERVERCERT);
	}

#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT_EXAMPLE__
	if (!clientCertSet)
	{
		setStringParameter(&sslc_ClientCert, SSLC_DEF_CLIENTCERT);
	}
	if (!clientBlobSet)
	{
		setStringParameter(&sslc_ClientBlob, SSLC_DEF_CLIENTBLOB);
	}
    if (!clientCertCbSet)
    {
        sslc_ClientCertCb = 0; /* This Flow is disabled by default */
    }
#endif

#if (defined(__ENABLE_DIGICERT_TAP__))
#if (defined(__ENABLE_DIGICERT_TAP_REMOTE__))
    if (!tapServerNameSet)
    {
    	myPrintNL("Mandatory argument tap_server_name NOT set");
        status = ERR_SSL;
    }
    if (!tapServerPortSet)
    {
    	myPrintNL("Mandatory argument tap_server_port NOT set");
        status = ERR_SSL;
    }
#endif
    if (!keySourceSet)
    {
        setStringParameter((char**)&tap_keySource, DEF_TAP_KEYSOURCE);
    }
    if (!tapConfigFileSet)
    {
        setStringParameter(&tap_ConfigFile, TPM2_CONFIGURATION_FILE);
    }
    if(DIGI_STRCMP((const sbyte *)tap_keySource, (const sbyte *)"TPM2") == 0)
    {
        sslc_TapProvider = TAP_PROVIDER_TPM2;
    }
    else if(DIGI_STRCMP((const sbyte *)tap_keySource, (const sbyte *)"PKCS11") == 0)
    {
        sslc_TapProvider = TAP_PROVIDER_PKCS11;
    }
    else
    {
        status = ERR_TAP_NO_PROVIDERS_AVAILABLE;
    }
#endif

	return status;
}

/*---------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_SSL_EXAMPLE_TEST_GET_CIPHER_LIST__)

static MSTATUS disableCipherTest(sbyte4 connectionInstance)
{
    MSTATUS status;
    ubyte2 *pCipherList = NULL;
    ubyte4 count = 0;
    ubyte2 *pUpdatedCipherList = NULL;
    ubyte4 updatedCount = 0;
    int i = 0;

    /* Obtain Current enabled Ciphers */
    status = SSL_getCipherList(connectionInstance, &pCipherList, &count);
    if (OK > status)
        goto exit1;

    if (count > 0)
    {
        pUpdatedCipherList = calloc(count * sizeof(ubyte2), 1);
        if (pUpdatedCipherList == NULL)
            goto exit1;

        for (i = 0; i < count; i++)
        {
            ubyte2 cipherId = pCipherList[i];
            switch(cipherId )
            { /* Skip TLS_RSA Ciphers */
                case 0xC09F:
                case 0xC09E:
                case 0xC0A3:
                case 0xC0A2:
                case 0x009D:
                case 0x009C:
                case 0x003D:
                case 0x0035:
                case 0x003C:
                case 0x002F:
                case 0xC09D:
                case 0xC09C:
                case 0xC0A1:
                case 0xC0A0:
                    break;
                default:
                    pUpdatedCipherList[updatedCount] = cipherId;
                    updatedCount++;
                    break;
            }
        }
    }
    /* Update the Ciphers with the new list */
    status = SSL_enableCiphers(connectionInstance, pUpdatedCipherList, updatedCount);

    exit1:
    if (pCipherList != NULL)
        free(pCipherList);
    if (pUpdatedCipherList != NULL)
        free(pUpdatedCipherList);
    return status;
}

#endif

/* This is only for build the SSL client using Microsoft Visual Studio project */
#ifdef __ENABLE_DIGICERT_WIN_STUDIO_BUILD__
int main(int argc, char *argv[])
{
	void* dummy = NULL;
#else
extern int
SSL_CLIENTEXAMPLE_main(void* dummy)
{
#endif
	MSTATUS         status = OK;
	sbyte4          connectionInstance = ERR_GENERAL;
	sbyte4          ret;
	TCP_SOCKET      mySocket = -1;
	ubyte           sessionIdLen=0;
	ubyte           sessionId[32    /* SSL_MAXSESSIONIDSIZE*/];
	ubyte           masterSecret[48 /*SSL_MASTERSECRETSIZE */];
#if defined(__ENABLE_DIGICERT_TLS13__) || defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
    ubyte           requestTicket = 1;
#endif
#if defined (__ENABLE_DIGICERT_TLS13__)
	ubyte           pskMode = 1;
#endif
#if defined(__ENABLE_DIGICERT_TAP__)
    TAP_ErrorContext *pErrContext = NULL;
#endif

#ifdef __ENABLE_DIGICERT_EAP_FAST__
	ubyte           pacKey[32] = { 0 };
#endif

#ifdef __ENABLE_DIGICERT_MEM_PART__
    if (NULL != gMemPartDescr)
    {
        /* make sure it's thread-safe! */
        MEM_PART_enableMutexGuard(gMemPartDescr);
    }
#endif

#ifdef __ENABLE_DIGICERT_WIN_STUDIO_BUILD__
	if (OK > ( status = SSL_CLIENTEXAMPLE_getArgs(argc, argv))) /* Initialize parameters to default values */
		goto endprog;
#else
	if (sslc_getArgs_called == 0)
	{
		status = (MSTATUS)SSL_CLIENTEXAMPLE_getArgs(0,NULL); /* Initialize parameters to default values */
                if (OK > status)
                    return (int)status;
	}
#endif

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
	myPrintNL("Entering SSL_CLIENTEXAMPLE_main...");
	myPrintStringNL("sslc_ServerIpAddr: ", sslc_ServerIpAddr);
	myPrintIntNL("sslc_ServerPort: ", sslc_ServerPort);
	myPrintStringNL("sslc_ServerName: ", sslc_ServerName);
	myPrintStringNL("sslc_KeyStore: ", sslc_KeyStore);
	myPrintStringNL("sslc_ServerCert: ", sslc_ServerCert);
    myPrintStringNL("sslc_supportedGroups: ", sslc_supportedGroup);
#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT_EXAMPLE__
	myPrintStringNL("sslc_ClientCert: ", sslc_ClientCert);
	myPrintStringNL("sslc_ClientBlob: ", sslc_ClientBlob);
	myPrintIntNL("sslc_ClientCertCb: ", sslc_ClientCertCb);
#endif
#endif

#if defined(__ENABLE_DIGICERT_WIN_STUDIO_BUILD__) && !defined(__DISABLE_DIGICERT_INIT__)
	if (OK > (status = DIGICERT_initDigicert()))
          goto exit;
#endif

	gMocanaAppsRunning++; /* key generation can take time */

	MOC_UNUSED(dummy);

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    if (OK > (status = FIPS_UTILS_initialize(g_pRandomContext)))
          goto exit;
#endif

    if (OK > (status = (MSTATUS) SSL_init(0, 5)))
    {
        return status;
    }

#ifndef __DISABLE_DIGICERT_CERTIFICATE_PARSING__
	if(OK > (status = (MSTATUS) initUpcallsAndCertStores())) {
		goto exitnocertstore;
	}
#endif

#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
	SSL_setFuncPtrAlertCallback(myAlertCallback);
#endif

    /* The mbedtls server example is written to only handle SSL_connect so
     * calling this SSL_CERT_UTILS_checkServerIsOnline followed by SSL_connect
     * will NOT work with a mbedtls server. Use this flag to disable this
     * function call so the mbedtls server can talk with the NanoSSL client.
     */
#ifndef __DISABLE_DIGICERT_SSL_CLIENT_EXAMPLE_CHECK__
	if(OK > (status = SSL_CERT_UTILS_checkServerIsOnline((const sbyte*)sslc_ServerIpAddr, sslc_ServerPort, MAX_SERVER_TRIES)))
	{
		myPrintError("SSL_CERT_UTILS_checkServerIsOnline::status: ", status);
		goto exitnoinstance;
	}
#endif

	if (OK > (status = TCP_CONNECT(&mySocket, (sbyte *)sslc_ServerIpAddr, sslc_ServerPort)))
	{
		myPrintError("TCP_CONNECT::status: ", status);
		goto exitnoinstance;
	}

	/*Establish a connection */
	if (OK > (connectionInstance = SSL_connect(mySocket, 0, NULL, NULL, (const sbyte *)sslc_ServerName, pClientSslCertStore)))
	{
		myPrintError("SSL_connect::status: ", connectionInstance);
		(void) TCP_CLOSE_SOCKET(mySocket);
		goto exit;
	}

#if !defined(__DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__) && defined(__ENABLE_DIGICERT_SSL_CLIENT_CERTIFICATE_CALLBACK__)
    if (OK > (status = SSL_setCertAndStatusCallback(connectionInstance, 
                       SSL_CLIENT_EXAMPLE_sslCertStatusCb)))
    {
        myPrintError("SSL_setCertAndStatusCallback::status: ", status);
        (void) TCP_CLOSE_SOCKET(mySocket);
        goto exit;
    }
#endif

    if (OK > (status = SSL_setFullCertChainCallback(connectionInstance, 
                       SSL_CLIENT_EXAMPLE_sslFullCertCb)))
    {
        myPrintError("SSL_setCertAndStatusCallback::status: ", status);
        (void) TCP_CLOSE_SOCKET(mySocket);
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_EXAMPLE_AESGCM_CIPHERS_ONLY__)
    if (OK > (status = setAESGCMCiphers(connectionInstance)))
        goto exit;
#endif

#if defined(__ENABLE_DIGICERT_SSL_EXAMPLE_TEST_GET_CIPHER_LIST__)
    if (OK > (status = disableCipherTest(connectionInstance)))
    {
        myPrintError("disableCipherTest::status: ", status);
        goto exit;
    }
#endif

#if defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT_EXAMPLE__)
    /* If this is enabled cert and key are not loaded into cert Store;
     * Stack will invoke this callback to get the certificate and key
     */
    if (1 == sslc_ClientCertCb)
    {
        SSL_setClientCertCallback(connectionInstance, myClientCert);
    }
#endif

#if defined(__ENABLE_DIGICERT_TLS13__) || defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
    if (OK > SSL_ioctl(connectionInstance, SSL_REQUEST_SESSION_TICKET, &requestTicket))
        goto exit;
#endif

#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
   if (OK > (SSL_setClientSaveTicketCallback(connectionInstance, &SSL_CLIENT_EXAMPLE_saveTicket)))
    {
        goto exit;
    }
#endif

#if defined (__ENABLE_DIGICERT_TLS13__)
#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT_EXAMPLE__
#ifdef __ENABLE_DIGICERT_SSL_POST_CLIENT_AUTH_EXAMPLE__
    status = SSL_setSessionFlags(connectionInstance, SSL_FLAG_ENABLE_POST_HANDSHAKE_AUTH);
#endif
#endif

    if (OK > (status = setSupportedGroupForConnection(connectionInstance)))
    {
	goto exit;
    }

#if 0
    {
        ubyte2 pCipherList[] = { 0x1302, 0x1301 };
        ubyte2 pSupportedGroups[] = { 0x0017, 0x0018 };
        ubyte2 pSignatureAlgos[] = { 0x0401, 0x0501, 0x0601, 0x0804, 0x0805, 0x0806 };
        ubyte2 pSignatureCertAlgos[] = { 0x0503, 0x0603, 0x0403 };
        if (OK > (status = SSL_setCipherAlgorithm(connectionInstance, pCipherList, 2, 0/* TLS13_cipher */ )))
        {
            goto exit;
        }

        if (OK > (status = SSL_setCipherAlgorithm(connectionInstance, pSupportedGroups, 2, 1/* TLS13_supportedGroups */ )))
        {
            goto exit;
        }

        if (OK > (status = SSL_setCipherAlgorithm(connectionInstance, pSignatureAlgos, 6, 2/* TLS13_signatureAlgorithms */ )))
        {
            goto exit;
        }

        if (OK > (status = SSL_setCipherAlgorithm(connectionInstance, pSignatureCertAlgos, 3, 3/* TLS13_signatureCertAlgos */)))
        {
            goto exit;
        }
    }
#endif

#if defined(__ENABLE_DIGICERT_TLS13_PSK__)
    if (OK > SSL_ioctl(connectionInstance, SSL_PSK_KEY_EXCHANGE_MODE, &pskMode/*psk_dhe_ke*/))
        goto exit;

    if (OK > SSL_setServerNameIndication(connectionInstance, sslc_ServerName))
        goto exit;

    if (OK > SSL_setClientSavePSKCallback(connectionInstance, &SSL_CLIENT_savePSKCallback))
    {
        goto exit;
    }

#endif /* __ENABLE_DIGICERT_TLS13_PSK__ */
#endif /* __ENABLE_DIGICERT_TLS13__ */

#ifdef __ENABLE_DIGICERT_SSL_PSK_SUPPORT__
    SSL_sslSettings()->funcPtrChoosePSK = SSL_LOOPBACK2_EXAMPLE_funcPtrChosePSK;
#endif

    /* Value in ms */
    if (OK > SSL_ioctl(connectionInstance, SSL_SET_RECV_TIMEOUT, (void *)((uintptr)15000)))
        goto exit;

    if (OK > SSL_setServerNameIndication(connectionInstance, sslc_ServerName))
		goto exit;

#ifdef __ENABLE_DIGICERT_SSL_SRP__
    if (OK > (status = SSL_setClientSRPIdentity(connectionInstance,
                                                (ubyte*) "scott", 5,
                                                (ubyte*) "tiger", 5)))
    {
        goto exit;
    }
#endif/* __ENABLE_DIGICERT_SSL_SRP__ */

#ifdef __ENABLE_DIGICERT_OCSP_CLIENT__
	/* Responder Ids; configure a list of trusted responder certificates */
	/* Note: Also set the correct trusted Responder Cert count    */
	char *pTrustedResponderCertsPath[]
	                                  = {
	                                		  /*"ca/demoCA/cacert.der",*/
	                                		  /*"../client/servercert.der",*/
	                                		  /*"ca/newcert4.der"*/
	                                		  /*"gdroot-g2.der"*/
                                        NULL
	};

	ubyte4 trustedRespondercertCount  = 0;

	if (OK > (MSTATUS) SSL_setCertifcateStatusRequestExtensions(connectionInstance,
			pTrustedResponderCertsPath, trustedRespondercertCount,
			NULL, 0))
		goto exit;

    SSL_sslSettings()->funcPtrCertStatusCallback = myCertStatusCallback;
    SSL_setOCSPCallback(myOcspStatusCallback);

	/* For OCSP requests add the issuer cert to the cert store. This is not */
	/* required if the server certificate is a root certificate or the entire */
	/* server cert chain is already added to the cert store as an identity. */
#if 0
	if (OK > (status = SSL_setOcspResponderUrl(connectionInstance, "http://127.0.0.1:8908")))
	{
		myPrintError("startHttpsThread: SSL_setOcspResponderUrl failed::status ", status);
	}

	ubyte *issuerCertData;
	ubyte4 issuerCertLen;
	if (OK > (status = DIGICERT_readFile("keystore/ca.der", &issuerCertData, &issuerCertLen)))
		goto exit;

	/* Add root certs as trust point*/
	if (OK > (status = CERT_STORE_addTrustPoint(pClientSslCertStore, issuerCertData, issuerCertLen)))
		goto exit;
#endif

#endif /*__ENABLE_DIGICERT_OCSP_CLIENT__*/

#if defined(__ENABLE_DIGICERT_SSL_HEARTBEAT_RFC_6520__)
    {
        ubyte value = peerAllowedToSend;
        status = SSL_enableHeartbeatSupport(connectionInstance, value, heartbeatCallback);
    }
#endif
#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
    {
        ubyte4 value = 1, version = 3/* TLS 1.2 */;
        SSL_ioctl(connectionInstance, SSL_SET_USE_EXTENDED_MASTERSECRET, (void *)((uintptr)value));
        SSL_ioctl(connectionInstance, SSL_SET_VERSION, (void *)((uintptr)version));
    }
#endif
#if (defined(__ENABLE_DIGICERT_SSL_EXAMPLE_INTEROP_EXTERNAL_PSK_TEST__) && defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__))
    if (OK > SSL_setClientSavePSKCallback(connectionInstance, &SSL_CLIENT_savePSKCallback))
        goto exit;

    if (OK > SSL_CLIENT_setRetrievePSKCallback(connectionInstance, &myGetPSKCallback))
        goto exit;

    if (OK > SSL_setServerNameIndication(connectionInstance, sslc_ServerName))
        goto exit;

    if (OK > SSL_ioctl(connectionInstance, SSL_PSK_KEY_EXCHANGE_MODE, &pskMode/*psk_dhe_ke*/))
        goto exit;

#if defined(__ENABLE_DIGICERT_TLS13_0RTT__)
    if (NULL != sslc_EarlyData)
    {
        if (OK > SSL_setEarlyData(connectionInstance, (ubyte*)sslc_EarlyData, DIGI_STRLEN((sbyte*)sslc_EarlyData)))
            goto exit;
    }
#endif /* __ENABLE_DIGICERT_TLS13_0RTT__ */
#endif

	if (OK > (status = (MSTATUS) SSL_negotiateConnection(connectionInstance)))
	{
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
		{
			/* example code for sending alerts on error/close */
			sbyte4  alertId;
			sbyte4  alertClass;

			if (0 <= SSL_lookupAlert(connectionInstance, status, &alertId, &alertClass))
			{
				status = (MSTATUS) SSL_sendAlert(connectionInstance, alertId, alertClass);
			}
		}
#endif

		(void) SSL_closeConnection(connectionInstance);
		(void) TCP_CLOSE_SOCKET(mySocket);
		goto exit;
	}

#if !defined(__ENABLE_DIGICERT_SSL_EXAMPLE_INTEROP_PSK_TEST__) && \
    !defined(__ENABLE_DIGICERT_SSL_EXAMPLE_INTEROP_TICKET_TEST__)
	/* get the session info before closing the connection (SSL_closeConnection destroys SSLSocket) */
	SSL_getClientSessionInfo( connectionInstance, &sessionIdLen, sessionId, masterSecret);
#endif

#if defined(__ENABLE_DIGICERT_SSL_EXAMPLE_INTEROP_PSK_TEST__) ||\
    defined(__ENABLE_DIGICERT_SSL_EXAMPLE_INTEROP_TICKET_TEST__) || \
    defined(__ENABLE_DIGICERT_SSL_EXAMPLE_INTEROP_SESSIONID_TEST__)
    {
        ubyte buffer[MAX_BUFFER_LEN] = {0};
        if (OK != (status = readSecureChannel(connectionInstance, buffer, MAX_BUFFER_LEN)))
        {
            goto exit;
        }
    }
#endif

#ifdef __RTOS_VXWORKS__
    /* Sent 'data' message to server and receive the response.  */
	if(OK > (status = GetSecurePageAux(connectionInstance, (const sbyte *)"data")))
	{
		myPrintError("GetSecurePageAux::status: ", connectionInstance);
		goto exit;
	}

    (void) SSL_closeConnection(connectionInstance);
	(void) TCP_CLOSE_SOCKET(mySocket);
#else
#if defined(__ENABLE_DIGICERT_SSL_HEARTBEAT_RFC_6520__) && \
    !defined(__ENABLE_DIGICERT_SSL_EXAMPLE_INTEROP_TEST__)
    status = SSL_sendHeartbeatMessage(connectionInstance);
#endif

#if defined(__ENABLE_DIGICERT_SSL_EXAMPLE_GRACEFUL_SHUTDOWN__)
    (void) SSL_sendAlert(connectionInstance, SSL_ALERT_CLOSE_NOTIFY, SSLALERTLEVEL_WARNING);
    (void) SSL_closeConnection(connectionInstance);
    (void) TCP_CLOSE_SOCKET(mySocket);
    goto exitnoinstance;
#endif

#if !defined(__ENABLE_DIGICERT_SSL_EXAMPLE_INTEROP_TEST__) || \
    (!defined(__ENABLE_DIGICERT_SSL_EXAMPLE_INTEROP_PSK_TEST__) && \
     !defined(__ENABLE_DIGICERT_SSL_EXAMPLE_INTEROP_TICKET_TEST__) && \
     !defined(__ENABLE_DIGICERT_SSL_EXAMPLE_INTEROP_SESSIONID_TEST__))
	/* Sent 'Test' message to server and receive the response.  */
	if(OK > (status = GetSecurePageAux(connectionInstance, (const sbyte *)TESTPAGE)))
	{
		myPrintError("GetSecurePageAux::status: ", connectionInstance);
		goto exit;
	}
#endif
	(void) SSL_closeConnection(connectionInstance);
	(void) TCP_CLOSE_SOCKET(mySocket);

#if !defined(__ENABLE_DIGICERT_SSL_EXAMPLE_INTEROP_TEST__) || \
    defined(__ENABLE_DIGICERT_SSL_EXAMPLE_INTEROP_PSK_TEST__) || \
    defined(__ENABLE_DIGICERT_SSL_EXAMPLE_INTEROP_TICKET_TEST__) || \
    defined(__ENABLE_DIGICERT_SSL_EXAMPLE_INTEROP_SESSIONID_TEST__)
	/* Send 'ResumeTest' command to Server. */
	if(OK > (status = (MSTATUS) sendCommandToServer(connectionInstance, (sbyte *)sslc_ServerIpAddr, sslc_ServerPort,
			sessionIdLen, sessionId, masterSecret, (const sbyte *)RESUMETESTPAGE)))
	{
		myPrintError("sendCommandToServer::ResumeTest::status: ", status);
		goto exit;
	}
#endif

#if !defined(__ENABLE_DIGICERT_SSL_EXAMPLE_INTEROP_TEST__)
	/* Send 'a' command to Server. */
	if(OK > (status = (MSTATUS) sendCommandToServer(connectionInstance, (sbyte *)sslc_ServerIpAddr, sslc_ServerPort,
			sessionIdLen, sessionId, masterSecret, (const sbyte *)ATESTPAGE)))
	{
		myPrintError("sendCommandToServer::a::status: ", status);
		goto exit;
	}

#endif /* !__ENABLE_DIGICERT_SSL_EXAMPLE_INTEROP_TEST__ */
#endif /* ifdef __RTOS_VXWORKS__ */

#if !defined(__ENABLE_DIGICERT_SSL_EXAMPLE_INTEROP_TEST__)
#ifdef __ENABLE_DIGICERT_EAP_FAST__
	if (OK > (status = TCP_CONNECT(&mySocket, sslc_ServerIpAddr, sslc_ServerPort)))
	{
		myPrintError("TCP_CONNECT::status: ", status);
		goto exit;
	}

	if (OK > (connectionInstance = SSL_connect(mySocket, 0, NULL, NULL, (const sbyte *)sslc_ServerName, pClientSslCertStore)))
	{
		myPrintError("SSL_connect::status: ", connectionInstance);
		goto exit;
	}

	if (OK > (status = SSL_setEAPFASTParams( connectionInstance, "", 1, pacKey)))
	{
		myPrintError("SSL_setEAPFASTParams::status: ", status);
		goto exit;
	}

	if (OK > (status = SSL_negotiateConnection(connectionInstance)))
	{
		myPrintError("SSL_negotiateConnection::status: ", status);
		SSL_closeConnection(connectionInstance);
		TCP_CLOSE_SOCKET(mySocket);
		goto exit;
	}

	GetSecurePageAux(connectionInstance, "EAPFAST_Test");

	/* get the session info before closing the connection (SSL_closeConnection destroys SSLSocket) */
	SSL_getClientSessionInfo( connectionInstance, &sessionIdLen, sessionId, masterSecret);

	SSL_closeConnection(connectionInstance);
	TCP_CLOSE_SOCKET(mySocket);

	/* resume session now */
	if (OK > TCP_CONNECT(&mySocket, sslc_ServerIpAddr, sslc_ServerPort))
		goto exit;

	if (OK > (connectionInstance = SSL_connect(mySocket, sessionIdLen, sessionId,
		masterSecret, sslc_ServerName, pClientSslCertStore)))
		goto exit;

	/* even though we set the EAPFASTParams, the sesssion should be using TLS resume */
	if (OK > SSL_setEAPFASTParams( connectionInstance, "", 1, pacKey))
		goto exit;

	if (OK > SSL_negotiateConnection(connectionInstance))
	{
		SSL_closeConnection(connectionInstance);
		TCP_CLOSE_SOCKET(mySocket);
		goto exit;
	}

	GetSecurePageAux(connectionInstance, "EAPFAST_ResumeTest");

	SSL_closeConnection(connectionInstance);
	TCP_CLOSE_SOCKET(mySocket);

	/* resume session now - bis */
	if (OK > TCP_CONNECT(&mySocket, sslc_ServerIpAddr, sslc_ServerPort))
		goto exit;

	if (OK > (connectionInstance = SSL_connect(mySocket, sessionIdLen, sessionId,
		masterSecret, sslc_ServerName, pClientSslCertStore)))
		goto exit;

	/* even though we set the EAPFASTParams, the sesssion should be using TLS resume */
	if (OK > SSL_setEAPFASTParams( connectionInstance, "", 1, pacKey))
		goto exit;

	if (OK > SSL_negotiateConnection(connectionInstance))
	{
		SSL_closeConnection(connectionInstance);
		TCP_CLOSE_SOCKET(mySocket);
		goto exit;
	}

	GetSecurePageAux(connectionInstance, "a");

	SSL_closeConnection(connectionInstance);
	TCP_CLOSE_SOCKET(mySocket);

#endif  /* __ENABLE_DIGICERT_EAP_FAST__ */

#ifdef __ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__
	if (sslc_CipherSuiteTest)
	{
		SSL_CLIENTEXAMPLE_cipherSelectTest();
	}
#endif
#endif /* !__ENABLE_DIGICERT_SSL_EXAMPLE_INTEROP_TEST__ */
exit:

	/* Send 'quit(q)'command to shutdown the Server. */
   if (OK <= connectionInstance && status == OK)
   {
#if !defined(__ENABLE_DIGICERT_SSL_EXAMPLE_INTEROP_TEST__)
      (void) sendCommandToServer(connectionInstance, (sbyte *)sslc_ServerIpAddr, sslc_ServerPort,
                                 sessionIdLen, sessionId, masterSecret, (const sbyte *)"q");
#endif /* !__ENABLE_DIGICERT_SSL_EXAMPLE_INTEROP_TEST__ */
   }
exitnoinstance:
#ifndef __DISABLE_DIGICERT_CERTIFICATE_PARSING__
	(void) uninitUpcallsAndCertStores();
#endif
exitnocertstore:
#if defined(__ENABLE_DIGICERT_TAP__)
    (void) uninitTAP();
#endif

#ifndef __DISABLE_DIGICERT_STACK_SHUTDOWN__
	ret = SSL_shutdownStack();
#endif

	if (0 > ret)
		DEBUG_ERROR(DEBUG_SSL_EXAMPLE, "SSL_EXAMPLE: SSL_shutdown return error: ", ret);

	/* in your design, you will want to wait for upper layer to signal it's dead */
	RTOS_sleepMS(2000);

#if (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_PSK__))
    freePSKList();
#endif

	(void) DIGI_FREE((void **)&sslc_ServerIpAddr);
	(void) DIGI_FREE((void **)&sslc_ServerName);
	(void) DIGI_FREE((void **)&sslc_ServerCert);
	(void) DIGI_FREE((void **)&sslc_supportedGroup);
	(void) DIGI_FREE((void **)&sslc_ClientCert);
	(void) DIGI_FREE((void **)&sslc_ClientBlob);
	(void) DIGI_FREE((void **)&sslc_KeyStore);
#if (defined(__ENABLE_DIGICERT_TLS13__) && (defined(__ENABLE_DIGICERT_TLS13_PSK__)) && (defined(__ENABLE_DIGICERT_TLS13_0RTT__)))
	(void) DIGI_FREE((void **)&sslc_EarlyData);
#endif

#if (defined(__ENABLE_DIGICERT_TAP__))
#if (defined(__ENABLE_DIGICERT_TAP_REMOTE__))
    if (NULL != taps_ServerName)
    {
        DIGI_FREE((void **)&taps_ServerName);
    }
#endif
    if (NULL != tap_ConfigFile)
    {
        DIGI_FREE((void **)&tap_ConfigFile);
    }
    if (tap_keySource != NULL) {
        FREE(tap_keySource);
        tap_keySource = NULL;
    }
#endif

    TCP_CLOSE_SOCKET(mySocket);
    gMocanaAppsRunning--;

#if defined(__ENABLE_DIGICERT_WIN_STUDIO_BUILD__)
endprog:
#endif

	return status;
}

#endif /* (defined(__ENABLE_DIGICERT_EXAMPLES__) && !defined(__ENABLE_DIGICERT_SSL_SERVER_EXAMPLE__)) */
#endif /* defined( __ENABLE_DIGICERT_SSL_CLIENT_EXAMPLE__) */
