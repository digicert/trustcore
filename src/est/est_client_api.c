/**
 * @file  est_client_api.c
 * @brief Implementation of EST Client API
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert's Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */
#if defined(WIN32)

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <Ws2tcpip.h>

#if defined(_DEBUG)
#include <crtdbg.h>
#endif

#endif  /*WIN32*/

#if defined(__ENABLE_DIGICERT_WIN_STUDIO_BUILD__)
#include <windows.h>
#endif /* __ENABLE_DIGICERT_WIN_STUDIO_BUILD__ */

#include "../common/moptions.h"

#if ( defined(__ENABLE_DIGICERT_EST_CLIENT__)  && ( defined(__ENABLE_DIGICERT_EXAMPLES__) || defined(__ENABLE_DIGICERT_BIN_EXAMPLES__) ) )

#if defined(__ENABLE_DIGICERT_TAP__)
#define __ENABLE_DIGICERT_TPM2__
#endif

#include "../common/moc_net_system.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../ssl/ssl.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mtcp_async.h"
#include "../common/sizedbuffer.h"
#include "../common/mstdlib.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../common/mime_parser.h"
#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../asn1/parsecert.h"
#include "../asn1/derencoder.h"
#include "../common/base64.h"
#include "../common/mfmgmt.h"
#include "../common/uri.h"
#include "../crypto/pkcs_common.h"
#include "../crypto/pkcs10.h"
#include "../cert_enroll/cert_enroll.h"
#include "../crypto/rsa.h"
#if (defined(__ENABLE_DIGICERT_DSA__))
#include "../crypto/dsa.h"
#include "../crypto/dsa2.h"
#endif
#if (defined(__ENABLE_DIGICERT_ECC__))
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif
#include "../crypto/aes.h"
#include "../crypto/des.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/three_des.h"
#include "../crypto/crypto.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/cert_store.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/asn1cert.h"
#include "../crypto/keyblob.h"
#include "../crypto/pkcs7.h"
#include "../crypto/cms.h"
#include "../http/http_context.h"
#include "../http/http_common.h"
#include "../http/http.h"
#include "../http/client/http_request.h"
#include "../http/client/http_client_process.h"
#include "../est/est_context.h"
#include "../est/est_utils.h"
#include "../asn1/ASN1TreeWalker.h"
#include "../common/memfile.h"
#include "../est/est_cert_utils.h"
#include "../est/est_message.h"
#ifdef  __ENABLE_DIGICERT_TAP__
#include "../tap/tap.h"
#include "../crypto/mocasymkeys/tap/rsatap.h"
#include "../crypto/mocasymkeys/tap/ecctap.h"
#ifdef __ENABLE_DIGICERT_TPM2__
#include "../smp/smp_tpm2/smp_tap_tpm2.h"
#endif
#endif
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/cryptointerface.h"
#include "../crypto_interface/crypto_interface_aes.h"
#include "../crypto_interface/crypto_interface_sha1.h"
#include "../crypto_interface/crypto_interface_sha256.h"
#endif
#include "../est/est_client_api.h"

/*------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if (!defined(__RTOS_WIN32__) && !defined(__RTOS_ZEPHYR__) && !defined(__RTOS_AZURE__) && !defined(__RTOS_FREERTOS__) || defined(__FREERTOS_SIMULATOR__))
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif /* __RTOS_WIN32__ */

#if defined(__RTOS_FREERTOS__) && !defined(__LWIP_STACK__) && !defined(__FREERTOS_SIMULATOR__)
#include <FreeRTOS.h>
#include "task.h"
#include "semphr.h"
#include <FreeRTOS_IP.h>
#include "FreeRTOS_Sockets.h"
#endif

#define VERBOSE_DEBUG   (0)
#define MAX_NUM_HTTP_CLIENT_SESSIONS    		(10)
#define MAX_NUM_HTTP_SERVER_SESSIONS            (10)
#define MAX_CSR_NAME_ATTRS                      (10)
#define MAX_NUM_SUBJECTALTNAMES                 (10)
#define MAX_SAN_ENTRY_ELEMENTS                  (3)
#define MAX_LINE_LENGTH                         (256)
#define MAX_TLS_UNIQUE_LENGTH                   (12)
#define MAX_SSL_SERVER_CONNECTIONS_ALLOWED       (0)
#define MAX_SSL_CLIENT_CONNECTIONS_ALLOWED      (10)
#define MAX_SSL_RECV_TIMEOUT                    (90000)
#define BEGIN_PKCS7_BLOCK   "-----BEGIN PKCS7-----\x0d\x0a"
#define END_PKCS7_BLOCK     "-----END PKCS7-----\x0d\x0a"
#define BEGIN_PKCS7_BLOCK_NEWLINE   "-----BEGIN PKCS7-----\x0a"
#define END_PKCS7_BLOCK_NEWLINE     "-----END PKCS7-----\x0a"
#define BEGIN_CERTIFICATE_BLOCK   "-----BEGIN CERTIFICATE-----\x0d\x0a"
#define END_CERTIFICATE_BLOCK     "-----END CERTIFICATE-----\x0d\x0a"
#define BEGIN_PKCS7_CSR_BLOCK 	"-----BEGIN CERTIFICATE REQUEST-----\x0d\x0a"
#define END_PKCS7_CSR_BLOCK 	"-----END CERTIFICATE REQUEST-----\x0d\x0a"
#define CSR_LINE_LENGTH     64
#define PEM_ARMOR                   1
#define BOUNDARY_TEXT "--boundary-text\x0a"
#define BEGIN_PRIVATEKEY_BLOCK "-----BEGIN PRIVATE KEY-----\x0a"
#define END_PRIVATEKEY_BLOCK "-----END PRIVATE KEY-----\x0a"
#define PKCS8_CONTENT_TYPE "application/pkcs8"
#define MAX_CONTENT_TYPE_LENGTH  (256)
#define MAX_OID_SIZE     (16)
#define BOUNDARY "boundary"
#define BLOCKSIZE 2000
#define SERVER_ADDR_BUFFER    100
#ifndef DEFAULT_USER_AGENT
#define DEFAULT_USER_AGENT    "EST Client"
#endif

#define EST_OTHERNAME_HARDWARE_MODULE_NAME      "hardwareModuleName"
#define EST_OTHERNAME_PERMANENT_IDENTIFIER      "permanentIdentifier"

#define SUPPORTED_DIGEST_ALGO_COUNT 6

#define CMC_ENROLL 1
#define CMC_REENROLL 2

#if defined(__ENABLE_DIGICERT_SSL_PROXY_CONNECT__) && !defined(__ENABLE_DIGICERT_HTTP_PROXY__)
#error Must define __ENABLE_DIGICERT_HTTP_PROXY__ if __ENABLE_DIGICERT_SSL_PROXY_CONNECT__ is defined
#endif

/**
 * @private
 * @internal
 *
 * @note	This typedef (DigestAlgoMap) is for Mocana internal
 * 			code use only, and should not be included in the API documentation.
 */
typedef struct DigestAlgoMap
{
    sbyte* digestName;
    sbyte4 digestType;

}DigestAlgoMap;

/**
 * @private
 * @internal
 *
 * @note	This typedef (HTTP context message body) is for Mocana internal
 * 			code use only, and should not be included in the API documentation.
 */
typedef struct requestBodyCookie
{
    ubyte* name;
    ubyte* data;
    ubyte4 dataLen;
    ubyte4 curPos;
} requestBodyCookie;

/**
 * @private
 * @internal
 *
 * @note This function pointer initializes the TPM1.2 KeyContext
 *
 */
EST_initTPM12KeyContext g_initTPM12KeyCtx = NULL;
/**
 * @private
 * @internal
 *
 * @note This function pointer deinitializes the TPM1.2 KeyContext
 *
 */
EST_deinitTPM12KeyContext g_deinitTPM12KeyCtx = NULL;

#ifdef __ENABLE_DIGICERT_TAP__
/**
 * @private
 * @internal
 *
 * @note This function pointer gets the tap context, entity credentials
 *       and key credentials.
 *
 */
EST_getTapContext g_pGetTapContext = NULL;
#define ATTEST "TPM2-ATTEST"
#endif

/* id-aa-decryptKeyID 1.2.840.113549.1.9.16.2.37 */
const ubyte decryptKeyIdentifider_OID[]     = {0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x25};
/* id-aa-asymmDecryptKeyID 1.2.840.113549.1.9.16.2.54 */
const ubyte asymDecryptKeyIdentifider_OID[] = {0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x36};

static MSTATUS
EST_convertHashType(ubyte *hashType, ubyte4 hashLen, ubyte4 *pHashOut);

static
MSTATUS EST_addSubjectKeyIdentifierExtension(MOC_ASYM(hwAccelDescr hwAccelCtx) requestAttributesEx *pPkcs10_attributes, AsymmetricKey *pAsymKey);

static MSTATUS
EST_getSubjectKeyIdentifierFromCSR(ASN1_ITEMPTR pRoot, CStream cs, byteBoolean withChallengePw, ASN1_ITEMPTR *ppSKI);

static
MSTATUS EST_calculateSubjectKeyIdentifier(MOC_ASYM(hwAccelDescr hwAccelCtx) AsymmetricKey *pAsymKey, ubyte **pPSubjectKeyId, ubyte4 *pSubjectKeyIdLen);

static MSTATUS EST_createPKCS10RequestFromConfig(
    MOC_HW(hwAccelDescr hwAccelCtx)
    ubyte* pConfigPath,
    ubyte *pExtendedAttrsFile,
    ubyte4 config_type,
    AsymmetricKey *pAsymKey,
    CertEnrollAlg keyAlgorithm,
    ubyte *pCert,
    ubyte4 certLen,
    ubyte hashType,
    ubyte* pKeyEncryptionAlgId,
    ubyte4 keyEncryptionAlgIdLen,
    ubyte *pKeyAlias,
    ubyte4 keyAliasLen,
    ubyte4 keyType,
    ubyte *pChallengePwd,
    ubyte4 challengePwdLength,
    sbyte4 connectionSSLInstance,
    ubyte *pAsymSmimeCert,
    ubyte4 asymSmimeCertLen,
    ubyte **pPCsr,
    ubyte4* pCsrLen,
    ubyte4 isReenroll,
    ExtendedEnrollFlow extFlow,
    EvalFunction evalFunction,
    void *pEvalFunctionArg);

static
MSTATUS EST_addServerKeyGenAttr(requestAttributesEx *pPkcs10_attributes, ubyte *pAlgId, ubyte4 algIdLen, ubyte *pKeyAlias, ubyte4 keyAliasLen, ubyte4 keyType, ubyte *pAsymSmimeCert, ubyte4 asymSmimeCertLen);

static
MSTATUS EST_setRequestBodyCookie(void **ppCookie, ubyte *pData, ubyte4 dataLen);

static
MSTATUS EST_releaseCookie(void *pCookieToRelease);

static
MSTATUS EST_getResponse(ubyte *pContentType, ubyte4 contentTypeLen, ubyte *pHttpResp, ubyte4 httpRespLen, ubyte **pPResponse, ubyte4 *pRespLen);

static
sbyte4 EST_http_requestBodyCallback (httpContext *pHttpContext, ubyte **ppDataToSend, ubyte4 *pDataLength, void *pRequestBodyCookie);

static
sbyte4 EST_http_responseBodyCallback(httpContext *pHttpContext, ubyte *pDataReceived, ubyte4 dataLength, sbyte4 isContinueFromBlock);

MOC_STATIC MSTATUS
EST_openSSLConnection(
    struct certStore *pCertStore,
    ubyte *pServerIdentity,
    ubyte4 serverIdentityLen,
    ubyte *pServerIpAddr,
    ubyte4 serverAddrLen,
    ubyte4 port,
    sbyte *pTLSCertAlias,
    ubyte4 tlsCertAliasLen,
    intBoolean ocspRequired,
    intBoolean enforcePQC,
    TCP_SOCKET *pSocket,
    sbyte4 *pSSLConnectionInstance)
{
    MOC_UNUSED(pTLSCertAlias);
    MOC_UNUSED(tlsCertAliasLen);
    MOC_UNUSED(ocspRequired);
    MSTATUS status = OK;
    ubyte *pServerName = NULL;
    sbyte *pServerAddr = NULL;
    sbyte *pServer = NULL;
    TCP_SOCKET socketServer = 0;
    TCP_SOCKET *pSocketServer = NULL;
    sbyte4 connInst = -1;
#ifdef __ENABLE_DIGICERT_HTTP_PROXY__
    char *pServerAndPort = NULL;
    ubyte4 serverAndPortLen;
    TCP_SOCKET socketProxy   = 0;
    sbyte4 proxyTransport   = -1;
#endif

    if ( (NULL == pServerIpAddr) || (NULL == pServerIdentity) ||
         (NULL == pCertStore) || (NULL == pSocket) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Copy server host name */
    status = DIGI_MALLOC((void **) &pServerName, serverIdentityLen + 1);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pServerName, pServerIdentity, serverIdentityLen);
    if (OK != status)
        goto exit;

    pServerName[serverIdentityLen] = '\0';

    /* Copy server IP */
    status = DIGI_MALLOC((void **) &pServerAddr, serverAddrLen + 1);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pServerAddr, pServerIpAddr, serverAddrLen);
    if (OK != status)
        goto exit;

    pServerAddr[serverAddrLen] = '\0';

#ifdef __ENABLE_DIGICERT_HTTP_PROXY__
    if (HTTP_PROXY_isProxyUrlSet())
    {
        serverAndPortLen = DIGI_STRLEN((sbyte *)pServerName) + 7;

        status = DIGI_CALLOC((void **)&pServerAndPort, 1, serverAndPortLen);
        if (OK != status)
            goto exit;

        (void) snprintf(pServerAndPort, serverAndPortLen, "%s:%d", (char *) pServerName, (int) port);

        /* The socketServer is associated with the SSL session the application
         * is going to create. In the case of HTTP proxy, the socketServer is
         * the phsyical socket. In the case of HTTPS proxy, the sockerServer is
         * virtual socket */
        status = HTTP_PROXY_connect(
            pServerAndPort, &socketServer, &socketProxy, &proxyTransport,
            pCertStore);
        DIGI_FREE((void **) &pServerAndPort);
        if (OK != status)
        {
            myPrintError("EST_openSSLConnection::HTTP_PROXY_connect::status: ", status);
            goto exit;
        }
        /* Point pSocketServer to socketServer, if pSocketServer is not NULL in
         * exit case then an error occurred and it must be closed */
        pSocketServer = &socketServer;
    }
    else
#endif
    {
        /* Resolve server address */
        status = HTTP_getHostIpAddr(pServerAddr, &pServer);
        if (OK != status)
        {
            myPrintError("EST_openSSLConnection::HTTP_getHostIpAddr::status: ", status);
            goto exit;
        }

        /* Create TCP connection to server */
        status = TCP_CONNECT(&socketServer, pServer, port);
        if (OK != status)
        {
            myPrintError("EST_openSSLConnection::TCP_CONNECT::status: ", status);
            goto exit;
        }
        /* Point pSocketServer to socketServer, if pSocketServer is not NULL in
         * exit case then an error occurred and it must be closed */
        pSocketServer = &socketServer;
    }

#ifdef __ENABLE_DIGICERT_SSL_PROXY_CONNECT__
    if (0 < proxyTransport)
    {
        connInst = SSL_PROXY_connect(
            socketProxy, proxyTransport, SSL_PROXY_send, SSL_PROXY_recv,
            socketServer, 0, NULL, NULL, pServerName, pCertStore);
        if (OK > connInst)
        {
            status = (MSTATUS) connInst;
            myPrintError("EST_openSSLConnection::SSL_PROXY_connect::status: ", status);
            goto exit;
        }
        /* TCP and SSL proxy session stored in SSL session created by
         * SSL_PROXY_connect. Set proxy to invalid value to avoid double close.
         */
        proxyTransport = -1;
    }
    else
#endif
    {
        connInst = SSL_connect(
            socketServer, 0, NULL, NULL, (sbyte *) pServerName, pCertStore);
        if (OK > connInst)
        {
            status = (MSTATUS) connInst;
            myPrintError("EST_openSSLConnection::SSL_connect::status: ", status);
            goto exit;
        }
    }

#ifdef __ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
    if (pTLSCertAlias)
    {
        status = SSL_setMutualAuthCertificateAlias(
            connInst, (ubyte *) pTLSCertAlias, tlsCertAliasLen);
        if (OK > status)
        {
            myPrintError("EST_openSSLConnection::SSL_setMutualAuthCertificateAlias::status: ", status);
            goto exit;
        }
    }
#endif

#if defined(__ENABLE_DIGICERT_PQC__)
    if (enforcePQC)
    {
        status = SSL_enforcePQCAlgorithm(connInst);
        if (OK > status)
        {
            myPrintError("EST_openSSLConnection::SSL_enforcePQCAlgorithm::status: ", status);
            goto exit;
        }
    }
#endif

    status = SSL_setServerNameIndication(connInst, (char *) pServerName);
    if (OK > status)
    {
        myPrintError("EST_openSSLConnection::SSL_setServerNameIndication::status: ", status);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_OCSP_CLIENT__
    if (ocspRequired)
    {
        status = SSL_setCertifcateStatusRequestExtensions(
            connInst, NULL, 0, NULL, 0);
        if (OK > status)
        {
            myPrintError("EST_openSSLConnection::SSL_setCertifcateStatusRequestExtensions::status: ", status);
            goto exit;
        }
    }
#endif

    status = SSL_negotiateConnection(connInst);
    if (OK > status)
    {
        myPrintError("EST_openSSLConnection::SSL_negotiateConnection::status: ", status);
        goto exit;
    }

    /* Return socket back to caller */
    *pSocket = *pSocketServer;
    pSocketServer = NULL;

    /* Return SSL connection instance back to caller */
    *pSSLConnectionInstance = connInst;
    connInst = -1;

exit:

    if (0 < connInst)
    {
        (void) SSL_closeConnection(connInst);
    }

    if (NULL != pSocketServer)
    {
        (void) TCP_CLOSE_SOCKET(*pSocketServer);
    }

#ifdef __ENABLE_DIGICERT_SSL_PROXY_CONNECT__
    if (0 < proxyTransport)
    {
        (void) SSL_closeConnection(proxyTransport);
        (void) TCP_CLOSE_SOCKET(socketProxy);
    }
#endif

    if (NULL != pServer)
        DIGI_FREE((void **) &pServer);

    if (NULL != pServerAddr)
        DIGI_FREE((void **) &pServerAddr);

    if (NULL != pServerName)
        DIGI_FREE((void **) &pServerName);

    return status;
}

/**
@brief      This function reopens SSLHandle Connection

@details    This functions will first close the current SSLHandle Connection,
             and then open a new SSL Connection.

@param pCertStore              Pointer to the native CertStore.
@param pHttpContext            Pointer to the httpContext.
@param pServerIdentity         Pointer to the server identity.
@param serverIdentityLen       Length of the server identity.
@param pServerIpAddr           Pointer to the server ip.
@param serverAddrLen           Length of the server ip.
@param portNo                  Port number.
@param pSSLConnectionInstance  On return, Pointer to connection state of SSL.

@inc_file   est_client_api.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.c
*/
MSTATUS EST_reOpenSSLConnection(
    struct certStore *pCertStore,
    httpContext *pHttpContext,
    sbyte *pServerIdentity,
    ubyte4 serverIdentityLen,
    ubyte *pServerIpAddr,
    ubyte4 serverAddrLen,
    ubyte4 portNo,
    sbyte4 *pSSLconnectionInstance,
    intBoolean ocspRequired,
    intBoolean enforcePQC)
{
    MSTATUS status = OK;
    TCP_SOCKET socketServer;

    if ( (NULL == pHttpContext) || (NULL == pServerIpAddr) ||
         (NULL == pServerIdentity) || (NULL == pCertStore) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    socketServer = pHttpContext->socket;

    SSL_closeConnection(*pSSLconnectionInstance);
    TCP_CLOSE_SOCKET(socketServer);

    status = EST_openSSLConnection(
        pCertStore, (ubyte *) pServerIdentity, serverIdentityLen, pServerIpAddr,
        serverAddrLen, portNo, NULL, 0, ocspRequired, enforcePQC,
        &socketServer, pSSLconnectionInstance);
    if (OK != status)
    {
        myPrintError("EST_reOpenSSLConnection::EST_openSSLConnection::status: ", status);
        goto exit;
    }

    HTTP_CONTEXT_setSocket(pHttpContext, socketServer);

exit:

    return status;
}



/**
@brief      Creates a synchronous client connection context.

@details    This functions creates a connection context for secure
             HTTP(S) synchronous connection with a remote server.

@param pCertStore              Pointer to the native CertStore.
@param pServerIpAddr           Pointer to server ip.
@param serverAddrLen           Server ip length.
@param port                    Port number.
@param pServerIdentity         Pointer to the server identity.
@param serverIdentityLen       Server identity length.
@param pConnectionSSLInstance  On return, Pointer to the SSL connection instance.
@param ppHttpContext           On return, Double Pointer to the httpContext.

@inc_file   est_client_api.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.c
*/
MSTATUS
EST_openConnection(
    struct certStore *pCertStore,
    ubyte *pServerIpAddr,
    ubyte4 serverAddrLen,
    ubyte4 port,
    ubyte *pServerIdentity,
    ubyte4 serverIdentityLen,
    sbyte4 *pConnectionSSLInstance,
    httpContext **ppHttpContext,
    sbyte *pTLSCertAlias,
    ubyte4 tlsCertAliasLen,
    intBoolean ocspRequired,
    intBoolean enforcePQC)
{
    MSTATUS status = OK;
    TCP_SOCKET socketServer = 0;

    if ( (NULL == ppHttpContext) || (NULL == pServerIpAddr) ||
         (NULL == pServerIdentity) || (NULL == pCertStore) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = EST_openSSLConnection(
        pCertStore, pServerIdentity, serverIdentityLen, pServerIpAddr,
        serverAddrLen, port, pTLSCertAlias, tlsCertAliasLen, ocspRequired,
        enforcePQC, &socketServer, pConnectionSSLInstance);
    if (OK != status)
    {
        myPrintError("EST_openConnection::EST_openSSLConnection::status: ", status);
        goto exit;
    }

    status = HTTP_connect(ppHttpContext, socketServer);
    if (OK > status)
    {
        (void) SSL_closeConnection(*pConnectionSSLInstance);
        (void) TCP_CLOSE_SOCKET(socketServer);
        myPrintError("EST_openConnection::HTTP_connect::status: ", status);
        goto exit;
    }

exit:

    return status;
}

/**
@brief      Closes the connection and release resources.

@details    This function closes a synchronous SSL session.

@param pHttpContext            Pointer to the httpContext.
@param connectionSSLInstance   Connection state of SSL.

@inc_file   est_client_api.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.c
*/
MSTATUS
EST_closeConnection(httpContext *pHttpContext, ubyte4 connectionSSLInstance)
{
    MSTATUS status = OK;
    TCP_SOCKET socketServer;

    if (NULL == pHttpContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    socketServer = pHttpContext->socket;
    SSL_closeConnection(connectionSSLInstance);
    TCP_CLOSE_SOCKET(socketServer);

    if (OK > (status = HTTP_CONTEXT_releaseContext(&pHttpContext)))
    {
        myPrintError("EST_CloseConnection::HTTP_CONTEXT_releaseContext::status_exit:  ", status);
        goto exit;
    }

exit:
    return status;

}

/* Internal functions */
static sbyte4
EST_receiveFromSSLSocket(sbyte4 serverConn, sbyte *pRetBuffer, ubyte4 bufferSize, ubyte4 *pNumBytesReceived, ubyte4 timeout)
{
    MSTATUS status = OK;
    sbyte4 result = 0;
    sbyte4 bytesReceived = -1;
    if ((NULL == pRetBuffer) || (NULL == pNumBytesReceived))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
	MOC_UNUSED(timeout);

    result = SSL_recv(serverConn, pRetBuffer, bufferSize, &bytesReceived, MAX_SSL_RECV_TIMEOUT);
    if (result >= OK) {
        if (bytesReceived == -1) {
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
            MSG_LOG_print(MSG_LOG_DEBUG, "%s\n", "EST_receiveFromSSLSocket: Unexpected EOF. returning READ_ERROR.");
#endif
            return ERR_TCP_READ_ERROR;
        } else {
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
            if (VERBOSE_DEBUG) MSG_LOG_print(MSG_LOG_DEBUG, "EST_receiveFromSSLSocket: returned byteRead= %d",bytesReceived);
            if (VERBOSE_DEBUG) DEBUG_HEXDUMP(DEBUG_EST_EXAMPLE, (ubyte*)pRetBuffer, bytesReceived);
#endif
            *pNumBytesReceived = bytesReceived;
            return OK;
        }
    } else {
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
        MSG_LOG_print(MSG_LOG_DEBUG, "EST_receiveFromSSLSocket: returned STATUS = %d",result);
#endif
        return result;
    }
exit:
    return status;
}

static MSTATUS
EST_preProcessPostRequest(httpContext *pHttpContext, sbyte *pContentType, ubyte *pServerName, ubyte4 postBodyLen, sbyte *pUserAgent)
{
    MSTATUS status = OK;
    ubyte4  index  = 0;
    sbyte *pUserAgentStr = pUserAgent ? pUserAgent : (sbyte*) DEFAULT_USER_AGENT;


    if (OK > (status = HTTP_REQUEST_setRequestMethodIfNotSet(pHttpContext, &mHttpMethods[POST])))
    {
        goto exit;
    }

    if (OK > (status = HTTP_COMMON_setHeaderIfNotSet(pHttpContext, index, (ubyte*)pUserAgentStr, DIGI_STRLEN(pUserAgentStr))))
    {
        goto exit;
    }

    index = Host;
    if (OK > (status = HTTP_COMMON_setHeaderIfNotSet(pHttpContext, index, (ubyte*)pServerName, DIGI_STRLEN((sbyte*)pServerName))))
    {
        goto exit;
    }

    index = Accept;
    if (OK > (status = HTTP_COMMON_setHeaderIfNotSet(pHttpContext, index, (ubyte*)"*/*", 3)))
    {
        goto exit;
    }



    if(NULL != pContentType)
    {
        index = NUM_HTTP_REQUESTS + ContentTransferEncoding;
        if (OK > (status = HTTP_COMMON_setHeaderIfNotSet(pHttpContext, index , (ubyte*)"base64", 6)))
            goto exit;

        index = NUM_HTTP_REQUESTS + NUM_HTTP_GENERALHEADERS + ContentType;
        if (OK > (status = HTTP_COMMON_setHeaderIfNotSet(pHttpContext, index, (ubyte *)pContentType, DIGI_STRLEN(pContentType))))
        {
            goto exit;
        }
    }

    if(0 != postBodyLen)
    {
        if (OK > (status = HTTP_REQUEST_setContentLengthIfNotSet(pHttpContext, postBodyLen)))
        {
            goto exit;
        }
    }

exit:
    return status;
}

static MSTATUS
EST_preProcessGetRequest(httpContext *pHttpContext, ubyte *pServerName, sbyte *pUserAgent)
{
    MSTATUS status = OK;
    ubyte4  index  = 0;
    sbyte *pUserAgentStr = pUserAgent ? pUserAgent : (sbyte*) DEFAULT_USER_AGENT;

    if (OK > (status = HTTP_REQUEST_setRequestMethodIfNotSet(pHttpContext, &mHttpMethods[GET])))
    {
        goto exit;
    }

    if (OK > (status = HTTP_COMMON_setHeaderIfNotSet(pHttpContext, index, (ubyte*)pUserAgentStr, DIGI_STRLEN(pUserAgentStr))))
    {
        goto exit;
    }

    index = Host;
    if (OK > (status = HTTP_COMMON_setHeaderIfNotSet(pHttpContext, index, (ubyte*)pServerName, DIGI_STRLEN((sbyte*)pServerName))))
    {
        goto exit;
    }

    index = Accept;
    if (OK > (status = HTTP_COMMON_setHeaderIfNotSet(pHttpContext, index, (ubyte*)"*/*", 3)))
    {
        goto exit;
    }

exit:
    return status;
}

static
MSTATUS EST_sendRequest(httpContext *pHttpContext, ubyte4 connectionSSLInstance, ubyte *pRequestUrl, ubyte4 requestUrlLen, ubyte *pServerIdentity, ubyte4 serverIdentityLen, byteBoolean isPost, int requestLength, sbyte *pContentType, sbyte *pUserAgent)
{
    MSTATUS         status           =  OK;
    sbyte           tcpBuffer[512];
    sbyte4          nRet;
    ubyte4          httpStatusCode;
    ubyte           *pUrl = NULL;
    ubyte           *pServerName = NULL;

    if (OK > (status = DIGI_MALLOC((void**)&pUrl, requestUrlLen+1)))
    {
        goto exit;
    }
    if (OK > (status = DIGI_MALLOC((void**)&pServerName, serverIdentityLen+1)))
    {
        goto exit;
    }
    if (OK > (status = DIGI_MEMSET(pUrl, 0x00, requestUrlLen+1)))
    {
        goto exit;
    }
    if (OK > (status = DIGI_MEMSET(pServerName, 0x00, serverIdentityLen+1)))
    {
        goto exit;
    }
    if (OK > (status = DIGI_MEMCPY(pUrl, pRequestUrl, requestUrlLen )))
    {
        goto exit;
    }
    if (OK > (status = DIGI_MEMCPY(pServerName, pServerIdentity, serverIdentityLen)))
    {
        goto exit;
    }


    if (TRUE == isPost)
    {
        if (OK > (status = EST_preProcessPostRequest(pHttpContext, pContentType, pServerName, requestLength, pUserAgent)))
        {
            goto exit;
        }
    }
    else
    {
        if (OK > (status = EST_preProcessGetRequest(pHttpContext, pServerName, pUserAgent)))
        {
            goto exit;
        }
    }

    if (OK > (status = HTTP_REQUEST_setRequestUriIfNotSet(pHttpContext, (sbyte*)pUrl)))
    {
        goto exit;
    }
    if (OK > (status = HTTP_recv(pHttpContext, NULL, 0)))
    {
        /* Caller has to handle this error */
        goto exit;
    }
    while (!HTTP_CLIENT_PROCESS_isDoneSendingRequest(pHttpContext))
    {
        if (OK > (status = HTTP_continue(pHttpContext)))
        {
            goto exit;
        }
    }

    while (!HTTP_isDone(pHttpContext))
    {
        if(OK != (status = (MSTATUS)EST_receiveFromSSLSocket(connectionSSLInstance, tcpBuffer, 512,(ubyte4 *) &nRet, 2000)))
        {
            /* caller has to handle this error */
            goto exit;
        }

        if(OK > (status = HTTP_recv(pHttpContext, (ubyte *)tcpBuffer, nRet)))
        {
            goto exit;
        }

        if (HTTP_CLIENT_STATE(pHttpContext) == finishedClientHttpState)
        {
            if (OK == (status = HTTP_REQUEST_getStatusCode(pHttpContext, &httpStatusCode)))
            {
                myPrintIntNL("EST_sendRequest::finishedClientHttpState::Server returned: ", httpStatusCode);
                /* Caller has to check the httpStatusCode using HTTP_REQUEST_getStatusCode() API
                 * and if it is observed that httpStatusCode is 401 then AuthStr has to be set to the
                 * httpHeader using HTTP_COMMON_setHeaderIfNotSet() API and then try sending request again
                 */
                if (httpStatusCode == 200)
                {
                    status = OK;
                }
                else
                {
                    /* httpStatusCode can be 401. Caller has to verify this */
                    status = ERR_HTTP;
                }
            }
            break;
        }
    }

exit:
    if (pUrl)
        DIGI_FREE((void**)&pUrl);
    if (pServerName)
        DIGI_FREE((void**)&pServerName);
    return status;
}

/**
@brief      Sends a cacerts request to the server.

@details    This function sends a cacerts request to the server.

@param pHttpContext            Pointer to the httpContext.
@param connectionSSLInstance   Connection state of SSL.
@param pRequestUrl             Pointer to request url.
@param requestUrlLen           Request url length.
@param pServerIdentity         Pointer to the server name.
@param serverIdentityLen       Server identity length.

@inc_file   est_client_api.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.c
*/
MSTATUS
EST_sendCaCertsRequest(httpContext *pHttpContext, ubyte4 connectionSSLInstance, ubyte *pRequestUrl, ubyte4 requestUrlLen, ubyte *pServerIdentity, ubyte4 serverIdentityLen, sbyte *pUserAgent)
{
    MSTATUS status = OK;

    if (OK > (status = EST_sendRequest(pHttpContext, connectionSSLInstance, pRequestUrl, requestUrlLen, pServerIdentity, serverIdentityLen, FALSE, 0, NULL, pUserAgent)))
    {
        if (VERBOSE_DEBUG)
        {
            myPrintError("EST_sendCaCertsRequest::EST_sendRequest::status ", status);
        }
        goto exit;
    }
exit:
    return status;
}

/**
@brief      Sends a csrAttrs request to the server.

@details    This function sends a csrattrs request to the server.

@param pHttpContext            Pointer to the httpContext.
@param connectionSSLInstance   Connection state of SSL.
@param pRequestUrl             Pointer to request url.
@param requestUrlLen           Length of the request url.
@param pServerIdentity         Pointer to the server name.
@param serverIdentityLen       Length of the server name.

@inc_file   est_client_api.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.c
*/
MSTATUS
EST_sendCsrAttrsRequest(httpContext *pHttpContext, ubyte4 connectionSSLInstance, ubyte *pRequestUrl, ubyte4 requestUrlLen, ubyte *pServerIdentity, ubyte4 serverIdentityLen, sbyte *pUserAgent)
{
    MSTATUS status = OK;

    if (OK > (status = EST_sendRequest(pHttpContext, connectionSSLInstance, pRequestUrl, requestUrlLen, pServerIdentity, serverIdentityLen, FALSE, 0, NULL, pUserAgent)))
    {
        if (VERBOSE_DEBUG)
        {
            myPrintError("EST_sendCsrAttrsRequest::EST_sendRequest::status ", status);
        }
        goto exit;
    }
exit:
    return status;
}

static MSTATUS
EST_setRequestBodyCookie(void **ppCookie, ubyte *pData, ubyte4 dataLen)
{
    MSTATUS status = OK;
    requestBodyCookie *pBodyCookie = NULL;

    if (ppCookie == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (*ppCookie = (requestBodyCookie*)MALLOC(sizeof(requestBodyCookie))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    if (OK > (status = DIGI_MEMSET(*ppCookie, 0x00, sizeof(requestBodyCookie))))
        goto exit;
    pBodyCookie = (requestBodyCookie*)*ppCookie;
    if (NULL == (pBodyCookie->data = MALLOC(dataLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    if (OK > (status = DIGI_MEMCPY(pBodyCookie->data, pData, dataLen)))
        goto exit;
    pBodyCookie->dataLen = dataLen;
    pBodyCookie->curPos = 0;

exit:
    if (OK > status)
    {
        if (pBodyCookie && pBodyCookie->data)
            FREE(pBodyCookie->data);

        if (ppCookie && *ppCookie)
            FREE(*ppCookie);
    }
    return status;
}

/**
@brief      Sets the cookie data.

@details    This function sets the cookie data.

@param pHttpContext Pointer to the httpContext.
@param RequestBody  Pointer to the request body.
@param reqBodyLen   Length of the request body.

@inc_file   est_client_api.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.c
*/
MSTATUS EST_setCookie(httpContext *pHttpContext, ubyte *pRequestBody, ubyte4 reqBodyLen)
{
    MSTATUS  status             = OK;
    void    *pRequestBodyCookie = NULL;

    if (NULL == pHttpContext || NULL == pRequestBody ||
            reqBodyLen == 0)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = EST_setRequestBodyCookie(&pRequestBodyCookie, pRequestBody, reqBodyLen)))
    {
        myPrintError("EST_setCookie::EST_setRequestBodyCookie::status: ", status);
        goto exit;
    }

    if (OK > (status = HTTP_setCookie(pHttpContext, pRequestBodyCookie)))
    {
        myPrintError("EST_setCookie::HTTP_setCookie::status: ", status);
        goto exit;
    }

exit:
    if (OK > status)
    {
        if (pRequestBodyCookie != NULL)
        {
            EST_releaseCookie(pRequestBodyCookie);
            pRequestBodyCookie = NULL;
        }
    }
    return status;
}

static
MSTATUS EST_releaseCookie(void *pCookieToRelease)
{
    requestBodyCookie *pCookie = pCookieToRelease;

    if (pCookie)
    {
        if (pCookie->data)
        {
            DIGI_FREE((void**)&(pCookie->data));
        }
        DIGI_FREE((void**)&pCookie);
    }
    return OK;
}

/**
@brief      Releases the cookie

@details    This function releases the request cookie.

@param pHttpContext  Pointer to the requestCookie.

@inc_file   est_client_api.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.c
*/
MSTATUS EST_freeCookie(httpContext *pHttpContext)
{
    MSTATUS  status          = OK;
    void    *pRequestCookie  = NULL;

    if (OK > (status = HTTP_getCookie(pHttpContext, &pRequestCookie)))
    {
        myPrintError("EST_freeCookie::HTTP_getCookie::status ", status);
        goto exit;
    }
    if (NULL == pRequestCookie)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = EST_releaseCookie(pRequestCookie)))
    {
        myPrintError("EST_freeCookie::EST_releaseCookie::status: ", status);
    }

    if (OK > (status = HTTP_setCookie(pHttpContext, NULL)))
    {
        myPrintError("EST_setCookie::HTTP_setCookie::status: ", status);
        goto exit;
    }

exit:
    return status;
}

static MSTATUS
EST_fetchLine(const ubyte *pSrc,  ubyte4 *pSrcIndex, const ubyte4 srcLength,
        ubyte *pDest, ubyte4 *pDestIndex)
{
    /* this is here for now... we will want to use the version in crypto/ca_mgmt.c */
    MSTATUS status = OK;

    pSrc += (*pSrcIndex);

    if ('-' == *pSrc)
    {
        /* handle '---- XXX ----' lines */
        /* seek MOC_CR or LF */
        while ((*pSrcIndex < srcLength) && ((0x0d != *pSrc) && (0x0a != *pSrc)))
        {
            (*pSrcIndex)++;
            pSrc++;
        }

        /* skip MOC_CR and LF */
        while ((*pSrcIndex < srcLength) && ((0x0d == *pSrc) || (0x0a == *pSrc)))
        {
            (*pSrcIndex)++;
            pSrc++;
        }
    }
    else
    {
        pDest += (*pDestIndex);

        /* handle base64 encoded data line */
        while ((*pSrcIndex < srcLength) &&
                ((0x20 != *pSrc) && (0x0d != *pSrc) && (0x0a != *pSrc)))
        {
            *pDest = *pSrc;

            (*pSrcIndex)++;
            (*pDestIndex)++;
            pSrc++;
            pDest++;
        }

        /* skip to next line */
        while ((*pSrcIndex < srcLength) &&
                ((0x20 == *pSrc) || (0x0d == *pSrc) || (0x0a == *pSrc) || (0x09 == *pSrc)))
        {
            (*pSrcIndex)++;
            pSrc++;
        }
    }

    return status;

} /* EST_fetchLine */

static MSTATUS
EST_breakIntoLinesPKCS7(ubyte* pLineCsr, ubyte4 lineCsrLength,
        ubyte **ppRetCsr, ubyte4 *p_retCsrLength, const ubyte *pStart, const ubyte *pEnd)
{
    ubyte  *pBlockCSR    = NULL;
    ubyte  *pTempLineCsr = NULL;
    ubyte4  numLines;

    /* break the data up into (CSR_LINE_LENGTH) sized blocks */
    numLines     = ((lineCsrLength + (CSR_LINE_LENGTH - 1)) / CSR_LINE_LENGTH);
    pTempLineCsr = pLineCsr;

    /* calculate the new block length */
#if PEM_ARMOR
    *p_retCsrLength = (DIGI_STRLEN((const sbyte*)pStart)) + lineCsrLength + numLines + numLines + (DIGI_STRLEN((const sbyte*)pEnd));
#else
    *p_retCsrLength = (lineCsrLength + numLines + numLines);
#endif

    /* allocate the new csr block */
    if (NULL == (*ppRetCsr = pBlockCSR = MALLOC(*p_retCsrLength)))
    {
        return ERR_MEM_ALLOC_FAIL;
    }

#if PEM_ARMOR
    /* copy the start of block identifier */
    DIGI_MEMCPY(pBlockCSR, (const ubyte *)pStart, (DIGI_STRLEN((const sbyte*)pStart)));
    pBlockCSR += (DIGI_STRLEN((const sbyte*)pStart));
#endif

    /* copy contiguous blocks of data */
    while (1 < numLines)
    {
        DIGI_MEMCPY(pBlockCSR, pTempLineCsr, CSR_LINE_LENGTH);
        pBlockCSR[CSR_LINE_LENGTH] = MOC_CR;
        pBlockCSR[CSR_LINE_LENGTH + 1] = LF;

        pBlockCSR += CSR_LINE_LENGTH + 2;
        pTempLineCsr += CSR_LINE_LENGTH;
        lineCsrLength -= CSR_LINE_LENGTH;

        numLines--;
    }

    /* copy any remaining bytes */
    if (lineCsrLength)
    {
        DIGI_MEMCPY(pBlockCSR, pTempLineCsr, lineCsrLength);
        pBlockCSR += lineCsrLength;

        *pBlockCSR = MOC_CR; pBlockCSR++;
        *pBlockCSR = LF; pBlockCSR++;
    }

#if PEM_ARMOR
    /* copy the end of block identifier */
    DIGI_MEMCPY(pBlockCSR, (const ubyte *)pEnd, (DIGI_STRLEN((const sbyte*)pEnd)));
#endif

    return OK;
}

static MSTATUS
EST_getCertificateFromCertStore (struct certStore *pCertStore,
        ubyte *pKeyAlias,
        ubyte4 keyAliasLen,
        ubyte4 keyType,
        ubyte **pPCertificate,
        ubyte4 *pCertificateLen)
{
    MSTATUS        status          = OK;

    if (NULL == pCertStore)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((akt_rsa == keyType) || (akt_ecc == keyType) || (akt_ecc_ed == keyType) ||
       (akt_tap_rsa == keyType) || (akt_tap_ecc == keyType))
    {
        /* Find the key in the cert store by its alias */
        if (OK > (status = CERT_STORE_findIdentityByAlias(pCertStore,
                        pKeyAlias, keyAliasLen,
                        NULL,
                        pPCertificate, pCertificateLen)))
        {
            goto exit;
        }
    }
    else
    {
        status = ERR_CERT_STORE_UNKNOWN_KEY_TYPE;
        goto exit;
    }


exit:
    return status;
}

/**
 @brief      This API generates the CSR Request from config file for simple-reenroll

 @details    This function generates the CSR Request from config file for simple-reenrol.

 @param      Pointer to the certstore.
 @param      Pointer to the csr config file.
 @param      Pointer to the extended attr config file.
 @param      Pointer to the keyalias with which csr has to be signed.
 param       length of the keyalias with which csr has to be signed.
 @param      key type of the above key.
 @param      Pointer to the keyalias with which certificate can be
             retrieved from the certstore. this is used in case of
             rekey scenario.
 @param      length of the keyalias with which certificate can be retrieved.
 @param      keyType type of the above key.
 @param      hashType to be used for signing.
 @param      Length of the hashtype.
 @param      ssl connection instance
 @param      Double pointer to get the final CSR.
 @param      Pointer to the get the CSR length.
 @param      requestType ENROLL, RENEW or REKEY.
 @param       which ,extendedAttributes,extendedAttributes, tells weather to verify the CSR request or not.

 @return     OK (0) if successful; otherwise a negative number error code.
 */
/*
    Example of Basic CSR Attributes
    --------------------------------
    {"ST":"California","C":"US","OU":"Engineering","CN":"ESTClient","L":"San Francisco","O":"Digicert Inc"}
 */
static MSTATUS EST_generateReenrollCSRRequestFromConfig(
    MOC_HW(hwAccelDescr hwAccelCtx)
    struct certStore *pCertStore,
    ubyte *pCsrConfig,
    ubyte *pExtendedAttrConfig,
    ubyte4 config_type,
    ubyte *pCurrentKeyAlias,
    ubyte4 currentKeyAliasLen,
    AsymmetricKey *pCurrentKey,
    ubyte4 currentKeyType,
    CertEnrollAlg keyAlgorithm,
    ubyte *pOldKeyAlias,
    ubyte4 oldKeyAliasLen,
    ubyte4 oldKeyType,
    ubyte *pHashType,
    ubyte4 hashTypeLen,
    sbyte4 connectionSSLInstance,
    ubyte **pPCsr,
    ubyte4* pCsrLen,
    ubyte4 requestType,
    ubyte4 flag,
    ExtendedEnrollFlow extFlow,
    EvalFunction evalFunction,
    void *pEvalFunctionArg)
{
    MSTATUS        status          = OK;
    AsymmetricKey *pRetIdentityKey = NULL;
    ubyte         *pOrigHash       = NULL;
    ubyte4         hash            = 0;
    ubyte         *pCertificate    = NULL;
    ubyte4         certificateLen  = 0;

    if ((NULL == pHashType) || (NULL == pCertStore) || (pCsrConfig == NULL) ||
            (pPCsr == NULL))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
	MOC_UNUSED(requestType);

    if (OK > (status = DIGI_MALLOC((void**)&pOrigHash, hashTypeLen+1)))
    {
        goto exit;
    }
    if (OK > (status = DIGI_MEMSET(pOrigHash, 0x00, hashTypeLen+1)))
    {
        goto exit;
    }
    if (OK > (status = DIGI_MEMCPY(pOrigHash, pHashType, hashTypeLen)))
    {
        goto exit;
    }
    if ((akt_rsa == currentKeyType) || (akt_ecc == currentKeyType) || (akt_ecc_ed == currentKeyType) ||
        (akt_tap_rsa == currentKeyType) || (akt_tap_ecc == currentKeyType) )
    {
        if (NULL == pCurrentKey)
        {
            /* Find the key in the cert store by its alias */
            if (OK > (status = CERT_STORE_findIdentityByAlias(pCertStore,
                                                            pCurrentKeyAlias, currentKeyAliasLen,
                                                            &pRetIdentityKey,
                                                            NULL, NULL)))
            {
                myPrintError("EST_generateReenrollCSRRequestFromConfig::CERT_STORE_findIdentityByAlias::status ", status);
                goto exit;
            }
        }
        else
        {
            pRetIdentityKey = pCurrentKey;
        }
    }
    else
    {
        status = ERR_CERT_STORE_UNKNOWN_KEY_TYPE;
        goto exit;
    }

    if (NULL == pRetIdentityKey)
    {
        status = ERR_NOT_FOUND;
        myPrintError("EST_generateReenrollCSRRequestFromConfig::Key not found in certstore::status ", status);
        goto exit;
    }

    /* Convert hashType */
    if (OK > (status = EST_convertHashType(pOrigHash, hashTypeLen, &hash)))
    {
        myPrintError("EST_generateReenrollCSRRequestFromConfig::EST_convertHashType::status ", status);
        goto exit;
    }

    (void) EST_getCertificateFromCertStore(
        pCertStore, pOldKeyAlias, oldKeyAliasLen, oldKeyType,
        &pCertificate, &certificateLen);

    if ((flag == CMC_ENROLL) || (pCertificate != NULL))
    {
        /* CreatePKCS10Request */
        if (OK > (status = EST_createPKCS10RequestFromConfig(MOC_HW(hwAccelCtx) pCsrConfig, pExtendedAttrConfig,
                                                          config_type, pRetIdentityKey, keyAlgorithm,
                                                          pCertificate, certificateLen,
                                                          (ubyte)hash,
                                                          NULL, 0, NULL, 0, 0,
                                                          NULL, 0, connectionSSLInstance,
                                                          NULL, 0,
                                                          pPCsr, pCsrLen,
                                                          flag, extFlow, evalFunction, pEvalFunctionArg)))
    	{
       	    myPrintError("EST_generateReenrollCSRRequestFromConfig::EST_createPKCS10Request::status ", status);
       	    goto exit;
        }
    }
    else
    {
        status = ERR_NOT_FOUND;
        myPrintError("EST_generateReenrollCSRRequestFromConfig:: Failed to find Certificate in CertStore::status ", status);
        goto exit;
    }

exit:
    if (NULL != pOrigHash)
        DIGI_FREE((void**)&pOrigHash);
    return status;
}

static MSTATUS
EST_getSubjectKeyIdentifierFromCSR(ASN1_ITEMPTR pRoot, CStream cs, byteBoolean withChallengePw, ASN1_ITEMPTR *ppSKI)
{
    MSTATUS      status           = OK;
    ASN1_ITEMPTR pExtensionsSeq   = NULL;
    intBoolean   critical         = 0;
    /*Traverse upto extensions sequence */
    WalkerStep   asn1WalkerStepWithChallengePw[] =
    {
        {GoFirstChild, 0, 0},
        {GoFirstChild, 0, 0},
        {GoChildWithTag, 0, 0},
        {GoNextSibling, 0, 0},
        {GoNthChild, 2, 0},
        {GoFirstChild, 0, 0},
        { Complete, 0, 0}
    };
    WalkerStep   asn1WalkerStep[] =
    {
        {GoFirstChild, 0, 0},
        {GoFirstChild, 0, 0},
        {GoChildWithTag, 0, 0},
        {GoNthChild, 2, 0},
        {GoFirstChild, 0, 0},
        { Complete, 0, 0}
    };
    WalkerStep *pAsn1WalkerStepPtr = (TRUE == withChallengePw) ? asn1WalkerStepWithChallengePw : asn1WalkerStep;

    if (OK > (status = ASN1_WalkTree(pRoot, cs, pAsn1WalkerStepPtr, &pExtensionsSeq)))
    {
        myPrintError("EST_getSubjectKeyIdentifierFromCSR::ASN1_WalkTree::status ", status);
        goto exit;
    }

    if (OK > ( status = X509_getCertExtension( pExtensionsSeq, cs,
                                              subjectKeyIdentifier_OID,
                                              &critical, ppSKI)))
    {
        myPrintError("EST_getSubjectKeyIdentifierFromCSR::X509_getCertExtension::status ", status);
        goto exit;
    }

exit:
    return status;

}

static MSTATUS
EST_getDigestAlgoOID(ubyte *pHashType, ubyte4 hashTypeLen, const ubyte **ppOID)
{
    ubyte4  hash   = 0;
    MSTATUS status = OK;

    if (OK > (status = EST_convertHashType(pHashType, hashTypeLen, &hash)))
    {
        myPrintError("EST_getDigestAlgoOID::EST_convertHashType::status ", status);
        goto exit;
    }

    switch(hash)
    {
        case ht_md5:
            *ppOID = md5_OID;
            break;
        case ht_sha1:
            *ppOID = sha1_OID;
            break;
        case ht_sha224:
            *ppOID = sha224_OID;
            break;
        case ht_sha256:
            *ppOID = sha256_OID;
            break;
        case ht_sha384:
            *ppOID = sha384_OID;
            break;
        case ht_sha512:
            *ppOID = sha512_OID;
            break;
        default:
            status = ERR_CRYPTO_BAD_HASH;
            break;
    }

exit:
    return status;
}

#ifdef __ENABLE_DIGICERT_TAP__
extern MSTATUS EST_CLIENT_registerTapCtxCallback(
    EST_getTapContext getTapContext)
{
    MSTATUS status = OK;
    if (getTapContext == NULL)
    {
        status = ERR_NULL_POINTER;
    }
    else
    {
        g_pGetTapContext = getTapContext;
    }

    return status;
}

static MSTATUS
EST_createPKIDataForAttestationFlow(MOC_ASYM(hwAccelDescr hwAccelCtx) AsymmetricKey *pTapAsymKey, ubyte *pReqData, ubyte4 reqDataLen, ubyte **ppOut, ubyte4 *pOutLen)
{
    MSTATUS status = OK;
	TAP_ErrorContext errContext;
	TAP_ErrorContext *pErrContext = &errContext;
    TAP_Context *pTapContext = NULL;
	TAP_Blob certificateBlob = {0};
	TAP_Blob validationAttrs = {0};
	TAP_ObjectInfo objectInfo = {0};
    DER_ITEMPTR   pContentInfo = NULL, pSignedData = NULL;
    ASN1_ITEMPTR  pCertificates[1];
    CStream       certStreams[1];
    ASN1_ITEMPTR  pEkCertificateItem = NULL;
    MemFile       ekCertMemFile;
    CStream       ekCertStream;
    ubyte*        pSigned = NULL;
    ubyte4        signedLen = 0;
    TAP_EntityCredentialList *pTapEntityCredentials = NULL;
    TAP_CredentialList *pKeyCreds = NULL;
	TAP_Key *pTapKey = NULL;
	DER_ITEMPTR pTempItem = NULL;
	ubyte *pAttestData = NULL;
	ubyte4 attestDataLen;
	ubyte *pBodyPartIdData = NULL;
	ubyte4 bodyPartIdDataLen;
	taggedContent taggedAttributeValues = {0};
	taggedContent taggedBodyPartIdValues = {0};
    taggedContent taggedContentData =  {0};
    taggedContent taggedMsgInfo = {0};
    const ubyte *pOid = mocana_attest_tpm2_oid;
    taggedAttribute attrs[] =
    {
        {
            .bodyPartId = 101,
            .pAttributeTypeOid = (ubyte*)pOid,
            .pTaggedAttributeValues = &taggedAttributeValues,
            .numAttributeValues = 1
        },
        {
            .bodyPartId = 102,
            .pAttributeTypeOid = (ubyte *) batchRequests_oid,
            .pTaggedAttributeValues = &taggedBodyPartIdValues,
            .numAttributeValues = 1
        }

    };
    taggedContentInfo contents[] =
    {
        {
            .bodyPartId = 103,
            .pTaggedContentInfo = &taggedContentData
        }
    };
    otherMsg otherMsgs[] =
    {
        {
            .bodyPartId = 104,
            .pOtherMsgTypeOid = (ubyte*)mocana_validation_attrs_oid,
            .pOtherMsgValue = &taggedMsgInfo
        }
    };

    if ( (NULL == pTapAsymKey) || (NULL == pReqData) ||
         (NULL == ppOut) || (NULL == pOutLen))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /*Prepare controlsequence */
	if (OK > (status = DER_AddItem( NULL, PRINTABLESTRING, 11, ATTEST, &pTempItem)))
	{
        myPrintError("EST_createPKIDataForAttestationFlow::DER_AddItem::status: ", status);
		goto exit;
	}

	if (OK > (status = DER_Serialize(pTempItem, &pAttestData, &attestDataLen)))
	{
        myPrintError("EST_createPKIDataForAttestationFlow::DER_Serialize::status: ", status);
		goto exit;
	}
    taggedAttributeValues.pData = pAttestData;
    taggedAttributeValues.dataLen = attestDataLen;

	if (pTempItem) TREE_DeleteTreeItem((TreeItem *)pTempItem);

    if (OK > (status = DER_AddSequence(NULL, &pTempItem)))
    {
        myPrintError("EST_createPKIDataForAttestationFlow::DER_AddSequence::status: ", status);
        goto exit;
    }

    if (OK > (status = DER_AddIntegerEx(pTempItem, 103, NULL)))
    {
        myPrintError("EST_createPKIDataForAttestationFlow::DER_AddIntegerEx::status: ", status);
        goto exit;
    }

	if (OK > (status = DER_Serialize(pTempItem, &pBodyPartIdData, &bodyPartIdDataLen)))
	{
        myPrintError("EST_createPKIDataForAttestationFlow::DER_Serialize::status: ", status);
		goto exit;
	}
    taggedBodyPartIdValues.pData = pBodyPartIdData;
    taggedBodyPartIdValues.dataLen = bodyPartIdDataLen;

	if (pTempItem) TREE_DeleteTreeItem((TreeItem *)pTempItem);

    /* Prepare cmcsequence */
    /* Get the EK Certificate */
#ifdef __ENABLE_DIGICERT_TPM2__
    if (EqualOID(pOid, mocana_attest_tpm2_oid))
        objectInfo.objectId = (TAP_ID)EK_OBJECT_ID;
#endif
    /* Get the TapContext, EntityCredentials and KeyCredentials from Client */
    if (NULL != g_pGetTapContext)
    {
        g_pGetTapContext(&pTapContext, &pTapEntityCredentials, &pKeyCreds, 1/*getContext */);
    }

    if (OK != (status = TAP_getRootOfTrustCertificate(pTapContext, &objectInfo, TAP_ROOT_OF_TRUST_TYPE_UNKNOWN,
                                        &certificateBlob, pErrContext)))
    {
        myPrintError("EST_createPKIDataForAttestationFlow::TAP_getRootOfTrustCertificate::status: ", status);
        goto exit;
    }
    if (certificateBlob.blob.pBuffer == NULL)
    {
        status = ERR_TAP;
        myPrintError("EST_createPKIDataForAttestationFlow::EK Certificate not found::status: ", status);
        goto exit;
    }

    /* wrap inside a ContentInfo */
    DER_AddSequence(NULL, &pContentInfo);
    DER_AddOID(pContentInfo, pkcs7_signedData_OID, NULL);
    DER_AddTag(pContentInfo, 0, &pSignedData);

    MF_attach(&ekCertMemFile, certificateBlob.blob.bufferLen, (ubyte*) certificateBlob.blob.pBuffer);
    CS_AttachMemFile(&ekCertStream, &ekCertMemFile );

    if (OK > (status = ASN1_Parse(ekCertStream, &pEkCertificateItem)))
    {
        myPrintError("EST_createPKCS7Request::ASN1_Parse::status: ", status);
        goto exit;
    }
    pCertificates[0] = pEkCertificateItem;
    certStreams[0] = ekCertStream;

    if (OK > (status = PKCS7_SignData(MOC_ASYM(hwAccelCtx) 0,
                    pContentInfo, pSignedData,
                    pCertificates, certStreams, 1,
                    NULL, NULL, 0, /* no crls */
                    NULL, 0,/* no signers*/
                    NULL, NULL, 0, /* no payload */
                    RANDOM_rngFun, g_pRandomContext,
                    &pSigned,
                    &signedLen)))

    {
        myPrintError("EST_createPKCS7Request::PKCS7_SignData::status: ", status);
        goto exit;
    }

    taggedContentData.pData = pSigned;
    taggedContentData.dataLen = signedLen;

    /* Prepare otherMsgSequence */
    /* Get certificate validation attributes */
    status = CRYPTO_INTERFACE_getTapKey(pTapAsymKey, &pTapKey);
    if (OK != status)
        goto exit;

    if (OK != (status = TAP_loadKey(pTapContext, pTapEntityCredentials, pTapKey, NULL, NULL, pErrContext)))
    {
        myPrintError("EST_createPKIDataForAttestationFlow::TAP_loadKey::status: ", status);
        goto exit;
    }

    /* This API returns the encoded blob of data, which is required for extended validation during certificate generation
       for an object which is used for attestation.*/
    if (OK != (status = TAP_getCertificateRequestValidationAttrs(pTapKey, NULL, &validationAttrs, pErrContext)))
    {
        myPrintError("EST_createPKIDataForAttestationFlow::TAP_getCertificateRequestValidationAttrs::status: ", status);
        goto exit;
    }

    if (OK > (status = TAP_unloadKey(pTapKey, pErrContext)))
    {
        myPrintError("EST_createPKIDataForAttestationFlow::TAP_unloadKey::status: ", status);
        goto exit;
    }

    taggedMsgInfo.pData = validationAttrs.blob.pBuffer;
    taggedMsgInfo.dataLen = validationAttrs.blob.bufferLen;

    if (OK != (status = CMC_createPKIDataEx(attrs, 2, pReqData, reqDataLen, contents, 1, otherMsgs, 1, ppOut, pOutLen)))
    {
        myPrintError("EST_createPKIDataForAttestationFlow::CMC_createPKIDataEx::status: ", status);
        goto exit;
    }

exit:
    if (pContentInfo)
    {
        TREE_DeleteTreeItem((TreeItem*)pContentInfo);
    }
    if (pEkCertificateItem)
    {
        TREE_DeleteTreeItem((TreeItem*)pEkCertificateItem);
    }
    if (NULL != g_pGetTapContext)
    {
        g_pGetTapContext(&pTapContext, &pTapEntityCredentials, &pKeyCreds, 0/*release Context */);
    }
    TAP_UTILS_freeBlob(&certificateBlob);
    TAP_UTILS_freeBlob(&validationAttrs);
    DIGI_FREE((void**)&pAttestData);
    DIGI_FREE((void**)&pBodyPartIdData);
    DIGI_FREE((void**)&pSigned);
    return status;
}
#endif

/**
@brief      Generates a fullcmc/PKCS7 request from config file.

@details    This function generates a fullcmc/PKCS7 request from config file.
            <p>
            This function creates a pkcs7 request in case if the request type is
            RENEW/REKEY. It creates a fullcmc request for ENROLL request type.
            We are generating pkcs7 request which includes extended
            attributes mentiond by Microsoft CA like certificateRenewal OID for
            RENEW/REKEY request types.

@param pCertStore              Pointer to the cert store handle.
@param pCsrConfig              Pointer to the csr config file.
@param pExtendedCsrAttrsConfig Pointer to the extended attrs config file.
@param config_type             Whether JSON or TOML CSR config.
@param pKeyAlias               Pointer to the keyalias with which csr has to be signed.
@param keyAliasLen             Length of the keyalias with which csr has to be signed.
@param keyType                 Type of the key. Possible values:
                               \var akt_undefined
                               \var akt_rsa
                               \var akt_ecc
                               \var akt_ecc_ed
                               \var akt_dsa
                               \var akt_custom.

@param pNewKeyAlias            Pointer to the keyalias with which the certificate can be retrieved.
@param newKeyAliasLen          Length of the keyalias.
@param newKeyType              Type of the key as mentioned above.
@param pHashType               Digest algorithm name Ex: "SHA256".
@param hashTypeLen             Length of the digest name.
@param connectionSSLInstance   SSL connection state.
@param requestType             Type of the request. Possible values:
                               \ref ENROLL
                               \ref RENEW
                               \ref REKEy
@param renewInlineCert         A flag to add old inline certificate in CSR.
                               If 0 old certificate will not be added to CSR otherwise included to CSR attributes.
@param pPOut                   On return, Double pointer to the fullcmc/pkcs7 request.
@param pOutLen                 On return, Pointer to the length of the request.

@inc_file   est_client_api.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.c
*/
MSTATUS EST_createPKCS7RequestFromConfig(
    MOC_HW(hwAccelDescr hwAccelCtx)
    struct certStore *pCertStore,
    ubyte *pCsrConfig,
    ubyte *pExtendedCsrAttrsConfig,
    ubyte4 config_type,
    ubyte *pKeyAlias,
    ubyte4 keyaliasLen,
    AsymmetricKey *pKey,
    ubyte4 keyType,
    CertEnrollAlg keyAlgorithm,
    ubyte *pNewKeyAlias,
    ubyte4 newKeyaliasLen,
    ubyte4 newKeyType,
    ubyte *pHashType,
    ubyte4 hashTypeLen,
    sbyte4 connectionSSLInstance,
    ubyte4 requestType,
    intBoolean renewInlineCert,
    ubyte **pPOut,
    ubyte4 *pOutLen)
{
    return EST_createPKCS7RequestFromConfigWithPolicy(
        MOC_HW(hwAccelCtx) pCertStore, pCsrConfig, pExtendedCsrAttrsConfig,
        config_type, pKeyAlias, keyaliasLen, pKey, keyType, keyAlgorithm, pNewKeyAlias,
        newKeyaliasLen, newKeyType, pHashType, hashTypeLen,
        connectionSSLInstance, requestType, renewInlineCert, pPOut, pOutLen,
        EXT_ENROLL_FLOW_NONE, NULL, NULL);
}

/**
@brief      Generates a fullcmc/PKCS7 request from config file.

@details    This function generates a fullcmc/PKCS7 request from config file.
            <p>
            This function creates a pkcs7 request in case if the request type is
            RENEW/REKEY. It creates a fullcmc request for ENROLL request type.
            We are generating pkcs7 request which includes extended
            attributes mentiond by Microsoft CA like certificateRenewal OID for
            RENEW/REKEY request types.

@param pCertStore              Pointer to the cert store handle.
@param pCsrConfig              Pointer to the csr config file.
@param pExtendedCsrAttrsConfig Pointer to the extended attrs config file.
@param config_type             Whether JSON or TOML CSR config.
@param pKeyAlias               Pointer to the keyalias with which csr has to be signed.
@param keyAliasLen             Length of the keyalias with which csr has to be signed.
@param keyType                 Type of the key. Possible values:
                               \var akt_undefined
                               \var akt_rsa
                               \var akt_ecc
                               \var akt_ecc_ed
                               \var akt_dsa
                               \var akt_custom.

@param pNewKeyAlias            Pointer to the keyalias with which the certificate can be retrieved.
@param newKeyAliasLen          Length of the keyalias.
@param newKeyType              Type of the key as mentioned above.
@param pHashType               Digest algorithm name Ex: "SHA256".
@param hashTypeLen             Length of the digest name.
@param connectionSSLInstance   SSL connection state.
@param requestType             Type of the request. Possible values:
                               \ref ENROLL
                               \ref RENEW
                               \ref REKEy
@param renewInlineCert         A flag to add old inline certificate in CSR.
                               If 0 old certificate will not be added to CSR otherwise included to CSR attributes.
@param pPOut                   On return, Double pointer to the fullcmc/pkcs7 request.
@param pOutLen                 On return, Pointer to the length of the request.
@param ppPolicyOids            Optional policy OIDs.

@inc_file   est_client_api.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.c
*/
MSTATUS EST_createPKCS7RequestFromConfigWithPolicy(
    MOC_HW(hwAccelDescr hwAccelCtx)
    struct certStore *pCertStore,
    ubyte *pCsrConfig,
    ubyte *pExtendedCsrAttrsConfig,
    ubyte4 config_type,
    ubyte *pKeyAlias,
    ubyte4 keyaliasLen,
    AsymmetricKey *pKey,
    ubyte4 keyType,
    CertEnrollAlg keyAlgorithm,
    ubyte *pNewKeyAlias,
    ubyte4 newKeyaliasLen,
    ubyte4 newKeyType,
    ubyte *pHashType,
    ubyte4 hashTypeLen,
    sbyte4 connectionSSLInstance,
    ubyte4 requestType,
    intBoolean renewInlineCert,
    ubyte **pPOut,
    ubyte4 *pOutLen,
    ExtendedEnrollFlow extFlow,
    EvalFunction evalFunction,
    void *pEvalFunctionArg)
{
    MSTATUS       status = OK;
    DER_ITEMPTR   pContentInfo = NULL, pSignedData = NULL;
    signerInfoPtr mySignerInfoPtr[1];
    signerInfo    mySignerInfo;
    ubyte*        pSigned = NULL;
    ubyte4        signedLen;
    CStream       certStream = {0};
    CStream       certStreams[1] = {{0}};
    MemFile       memFile;
    ASN1_ITEMPTR  pSelfCertificate = NULL, pIssuer = NULL, pSerialNumber = NULL;
    ASN1_ITEMPTR  pCertificates[1];
    ASN1_ITEMPTR  pSubjectKeyIdentifier = NULL;
    AsymmetricKey *pRetIdentityKey = NULL;
    ubyte         *pPkcs10Req = NULL;
    ubyte4        pkcs10ReqLen = 0;
    ubyte         *pDecodedReq = NULL;
    ubyte4        decodedReqLen = 0;
    ASN1_ITEMPTR  pReqRoot = NULL;
    ubyte         *pReqData = NULL;
    ubyte4        reqDataLen = 0;
    ubyte         *encodedSignData = NULL;
    ubyte4        encodedSignDataLen = 0;
    CStream       csrStream;
    MemFile       csrMemFile;
    ASN1_ITEMPTR  pSKIExtension = NULL;

    if (requestType == RENEW || requestType == ENROLL)
    {
        if (OK > (status = EST_generateReenrollCSRRequestFromConfig(MOC_HW(hwAccelCtx) pCertStore, pCsrConfig,
                                      pExtendedCsrAttrsConfig, config_type,
                                      pKeyAlias, keyaliasLen, pKey, keyType, keyAlgorithm,
                                      pKeyAlias, keyaliasLen, keyType,
                                      pHashType, hashTypeLen, connectionSSLInstance,
                                      &pPkcs10Req, &pkcs10ReqLen, requestType,
                                      (requestType == ENROLL) ? CMC_ENROLL : renewInlineCert ? CMC_REENROLL : CMC_ENROLL,
                                      extFlow, evalFunction, pEvalFunctionArg)))
        {
            myPrintError("EST_createPKCS7Request->EST_generateReenrollCSRRequest, status = ", status);
            goto exit;
        }
    }
    else if (requestType == REKEY)
    {
        if (OK > (status = EST_generateReenrollCSRRequestFromConfig(MOC_HW(hwAccelCtx) pCertStore, pCsrConfig,
                                      pExtendedCsrAttrsConfig, config_type,
                                      pNewKeyAlias, newKeyaliasLen, pKey, newKeyType, keyAlgorithm,
                                      pKeyAlias, keyaliasLen, keyType,
                                      pHashType, hashTypeLen, connectionSSLInstance,
                                      &pPkcs10Req, &pkcs10ReqLen, requestType, renewInlineCert ? CMC_REENROLL : CMC_ENROLL,
                                      extFlow, evalFunction, pEvalFunctionArg)))
        {
            myPrintError("EST_createPKCS7Request->EST_generateReenrollCSRRequest, status = ", status);
            goto exit;
        }
    }

    if (requestType == RENEW || requestType == REKEY || requestType == ENROLL)
    {
        ubyte *pCertificate = NULL;
        ubyte4 certificateLen = 0;
        const ubyte *digestOID = NULL;

        if ((akt_rsa == keyType) || (akt_ecc == keyType) || (akt_ecc_ed == keyType) ||
            (akt_tap_rsa == keyType) || (akt_tap_ecc == keyType))
        {
            if (NULL == pKey)
            {
                /* Find the key in the cert store by its alias */
                if (OK > (status = CERT_STORE_findIdentityByAlias(pCertStore,
                                pKeyAlias, keyaliasLen,
                                &pRetIdentityKey,
                                &pCertificate, &certificateLen)))
                {
                    myPrintError("EST_generateReenrollCSRRequest::CERT_STORE_findIdentityByAlias::status ", status);
                    goto exit;
                }
            }
            else
            {
                pRetIdentityKey = pKey;
            }
        }
        else
        {
            status = ERR_CERT_STORE_UNKNOWN_KEY_TYPE;
            goto exit;
        }

        /* pRetIdentityKey->key is a union. so check if any of the key
         * pRSA, pECC or pDSA is null.
         */
        if (NULL == pRetIdentityKey || (NULL == pRetIdentityKey->key.pRSA))
        {
            status = ERR_NOT_FOUND;
            myPrintError("EST_createPKCS7Request::Key not found in CertStore", status);
            goto exit;
        }
        if (requestType == RENEW || requestType == REKEY)
        {
            if (NULL == pCertificate)
            {
                status = ERR_NOT_FOUND;
                myPrintError("EST_createPKCS7Request::pCertificate is not found in CertStore", status);
                goto exit;
            }

            MF_attach(&memFile, certificateLen, (ubyte*) pCertificate);
            CS_AttachMemFile(&certStream, &memFile );

            if (OK > (status = ASN1_Parse(certStream, &pSelfCertificate)))
            {
                myPrintError("EST_createPKCS7Request::ASN1_Parse::status: ", status);
                goto exit;
            }
            /* get issuer and serial number of certificate */
            if (OK > (status = X509_getCertificateIssuerSerialNumber( ASN1_FIRST_CHILD(pSelfCertificate), &pIssuer, &pSerialNumber)))
            {
                myPrintError("EST_createPKCS7Request::X509_getCertificateIssuerSerialNumber::status: ", status);
                goto exit;
            }
        }
        if (OK > (status = DIGI_MEMSET((ubyte*)&mySignerInfo, 0x00, sizeof(signerInfo))))
        {
            myPrintError("EST_createPKCS7Request::DIGI_MEMSET::status: ", status);
            goto exit;
        }
        mySignerInfo.pIssuer = pIssuer;
        mySignerInfo.pSerialNumber = pSerialNumber;
        mySignerInfo.cs = certStream;
        if (OK > (status = EST_getDigestAlgoOID(pHashType, hashTypeLen, &digestOID)))
        {
            myPrintError("EST_createPKCS7Request::EST_getDigestAlgoOID::status: ", status);
            goto exit;
        }
        mySignerInfo.digestAlgoOID = digestOID;
        mySignerInfo.pKey = pRetIdentityKey;
        mySignerInfo.pUnauthAttrs = NULL;
        mySignerInfo.unauthAttrsLen = 0;

        mySignerInfo.pAuthAttrs = NULL;
        mySignerInfo.authAttrsLen = 0;
        mySignerInfoPtr[0] = &mySignerInfo;

        /* wrap inside a ContentInfo */
        DER_AddSequence(NULL, &pContentInfo);
        DER_AddOID(pContentInfo, pkcs7_signedData_OID, NULL);
        DER_AddTag(pContentInfo, 0, &pSignedData);

        pCertificates[0] = pSelfCertificate;
        certStreams[0] =  certStream;

        {
            /* Construct the PKI Data */
            /* Remove line feed and new line */
            /* Remove header and footer */
            /* Decode pkcs10Req */
            /* Create ASN1_ITEMPTR and CStream */
            if (OK > (status = CA_MGMT_decodeCertificate(pPkcs10Req, pkcs10ReqLen, &pReqData, &reqDataLen)))
            {
                myPrintError("EST_createPKCS7Request::CA_MGMT_decodeCertificate::status: ", status);
                goto exit;
            }

            MF_attach(&csrMemFile, reqDataLen, pReqData);
            CS_AttachMemFile(&csrStream, &csrMemFile);
            if (OK > (status = ASN1_Parse( csrStream, &pReqRoot)))
            {
                myPrintError("EST_createPKCS7Request::ASN1_Parse::status: ", status);
                goto exit;
            }

            if (OK > (status = EST_getSubjectKeyIdentifierFromCSR(pReqRoot, csrStream, (connectionSSLInstance > -1) ? TRUE : FALSE, &pSKIExtension)))
            {
                myPrintError("EST_createPKCS7Request::EST_getSubjectKeyIdentifierFromCSR::status: ", status);
                goto exit;
            }

            pSubjectKeyIdentifier = pSKIExtension;
            mySignerInfo.cs = csrStream;
#ifdef __ENABLE_DIGICERT_TAP__
            ubyte keyUsage = 0;
            if (OK != (status = CRYPTO_INTERFACE_getKeyUsage(pRetIdentityKey->key.pMocAsymKey,
                                        pRetIdentityKey->type, &keyUsage)))
            {
                goto exit;
            }
            if (keyUsage == TAP_KEY_USAGE_ATTESTATION)
            {
                if (OK != (status = EST_createPKIDataForAttestationFlow(MOC_ASYM(hwAccelCtx) pRetIdentityKey,
                                pReqData, reqDataLen,
                                &pDecodedReq, &decodedReqLen)))
                {
                    myPrintError("EST_createPKCS7Request::EST_createPKIDataForAttestationFlow::status: ", status);
                    goto exit;
                }

            }
            else
            {
#endif
                if (OK > (status = CMC_createPKIData(NULL, NULL, pReqRoot, &csrStream, &pDecodedReq, &decodedReqLen)))
                {
                    myPrintError("EST_createPKCS7Request::CMC_getPKIDataContent::status: ", status);
                    goto exit;
                }
#ifdef __ENABLE_DIGICERT_TAP__
            }
#endif
        }

    }

    if (g_initTPM12KeyCtx != NULL)
    {
        g_initTPM12KeyCtx(pRetIdentityKey);
    }

    {
        cmcSignerInfoPtr myCmcSignerInfoPtr[1];
        cmcSignerInfo myCmcSignerInfo;
        ubyte pkiData_oid[] = {8, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x0C, 0x02};

        myCmcSignerInfo.pSignerInfo = &mySignerInfo;
        myCmcSignerInfo.pSubjectKeyIdentifier = pSubjectKeyIdentifier;
        myCmcSignerInfoPtr[0] = &myCmcSignerInfo;

        if (OK > (status = CMC_SignData(MOC_ASYM(hwAccelCtx) 0,
                                        pContentInfo, pSignedData,
                                        NULL, NULL, 0, /* no Certificates */
                                        NULL, NULL, 0, /* no crls */
                                        myCmcSignerInfoPtr,
                                        1,
                                        pkiData_oid,
                                        pDecodedReq,
                                        decodedReqLen,
                                        RANDOM_rngFun, g_pRandomContext,
                                        &pSigned,
                                        &signedLen)))

        {
            myPrintError("EST_createPKCS7Request::CMC_SignData::status: ", status);
            goto exit;
        }

    }
    if (OK > (status = BASE64_encodeMessage(pSigned, signedLen, &encodedSignData, &encodedSignDataLen)))
    {
        myPrintError("EST_createPKCS7Request::BASE64_encodeMessage::status: ", status);
        goto exit;
    }

    if (OK > (status = EST_breakIntoLinesPKCS7(encodedSignData, encodedSignDataLen,
                    pPOut, pOutLen, (const ubyte*)BEGIN_PKCS7_CSR_BLOCK, (const ubyte*)END_PKCS7_CSR_BLOCK)))
    {
        myPrintError("EST_createPKCS7Request::EST_breakIntoLinesPKCS7::status: ", status);
        goto exit;
    }

exit:

    if (g_deinitTPM12KeyCtx != NULL)
    {
        g_deinitTPM12KeyCtx();
    }
    if (pReqRoot != NULL)
    {
        TREE_DeleteTreeItem((TreeItem*)pReqRoot);
    }
    if (pSelfCertificate != NULL)
    {
        TREE_DeleteTreeItem((TreeItem*)pSelfCertificate);
    }
    if (pContentInfo)
    {
        TREE_DeleteTreeItem((TreeItem*)pContentInfo);
    }
    if (pPkcs10Req != NULL)
        FREE(pPkcs10Req);
    if (pDecodedReq != NULL)
        FREE(pDecodedReq);
    if (pReqData != NULL)
        FREE(pReqData);
    if (pSigned != NULL)
        FREE(pSigned);
    if (encodedSignData != NULL)
        FREE(encodedSignData);
    return status;
}

/**
@brief      Sends a fullcmc request to the server.

@details    This function sends a fullcmc request to the server.

@param pHttpContext            Pointer to the httpContext.
@param connectionSSLInstance   Connection state of SSL.
@param pRequestUrl             Pointer to request url.
@param requestUrlLen           Length of the request url.
@param csrReqLen               Length of the csr request.
@param pServerIdentity         Pointer to the server name.
@param serverIdentityLen       Length of the server name.
@param requestType             Type of the request. Possible values:
                               \ref ENROLL
                               \ref RENEW
                               \ref REKEY

@inc_file   est_client_api.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.c
*/
MSTATUS
EST_sendFullCmcRequest(
        httpContext *pHttpContext,
        ubyte4 connectionSSLInstance,
        ubyte *pRequestUrl,
        ubyte4 requestUrlLen,
        ubyte4 csrReqLen,
        ubyte *pServerIdentity,
        ubyte4 serverIdentityLen,
        ubyte4 requestType,
        sbyte *pUserAgent)
{
    MSTATUS status = OK;

    if (OK > (status = EST_sendRequest(pHttpContext, connectionSSLInstance,
                                              pRequestUrl, requestUrlLen,
                                              pServerIdentity, serverIdentityLen,
                                              TRUE, csrReqLen,
                                              (requestType == ENROLL) ? (sbyte*)EST_FULL_CMC_MIME_PKCS : (sbyte*)EST_PKCS7_MIME, pUserAgent)))
    {
        if (VERBOSE_DEBUG)
        {
            myPrintError("EST_sendFullCmcRequest::EST_sendRequest::status ", status);
        }
    }

    return status;
}

/**
@brief      Sends a serverkeygen request to the server.

@details    This function sends a serverkeygen request to the server.

@param pHttpContext          Pointer to the httpContext.
@param connectionSSLInstance Connection state of SSL.
@param pRequestUrl           Pointer to request url.
@param requestUrlLen         Length of the request url.
@param csrReqLen             Length of the csr request.
@param pServerIdentity       Pointer to the server name.
@param serverIdentityLen     Length of the server name.

@inc_file   est_client_api.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.c
*/
MSTATUS
EST_sendServerKeyGenRequest(httpContext *pHttpContext, ubyte4 connectionSSLInstance, ubyte *pRequestUrl, ubyte4 requestUrlLen, ubyte4 csrReqLen, ubyte *pServerIdentity, ubyte4 serverIdentityLen, sbyte *pUserAgent)
{
    MSTATUS status = OK;

    if (OK > (status = EST_sendRequest(pHttpContext, connectionSSLInstance, pRequestUrl, requestUrlLen, pServerIdentity, serverIdentityLen, TRUE, csrReqLen, (sbyte*)EST_SIMPLE_ENROLL_PKCS, pUserAgent)))
    {
        if (VERBOSE_DEBUG)
        {
            myPrintError("EST_sendServerKeyGenRequest::EST_sendRequest::status ", status);
        }
    }

    return status;
}

/**
@brief      Sends a simpleenroll request to the server.

@details    This function sends a simpleenroll request to the server.

@param pHttpContext          Pointer to the httpContext.
@param connectionSSLInstance Connection state of SSL.
@param pRequestUrl           Pointer to request url.
@param requestUrlLen         Length of the request url.
@param csrReqLen             Length of the csr request.
@param pServerIdentity       Pointer to the server name.
@param serverIdentityLen     Length of the server name.

@inc_file   est_client_api.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.c
*/
MSTATUS
EST_sendSimpleEnrollRequest(httpContext *pHttpContext, ubyte4 connectionSSLInstance, ubyte *pRequestUrl, ubyte4 requestUrlLen, ubyte4 csrReqLen, ubyte *pServerIdentity, ubyte4 serverIdentityLen, sbyte *pUserAgent)
{
    MSTATUS status = OK;

    if (OK > (status = EST_sendRequest(pHttpContext, connectionSSLInstance, pRequestUrl, requestUrlLen, pServerIdentity, serverIdentityLen, TRUE, csrReqLen, (sbyte*)EST_SIMPLE_ENROLL_PKCS, pUserAgent)))
    {
        if (VERBOSE_DEBUG)
        {
            myPrintError("EST_sendSimpleEnrollRequest::EST_sendRequest::status ", status);
        }
        goto exit;
    }
exit:
    return status;
}

static MSTATUS
newExtensionAlloc(certExtensions **ppExtensions)
{
    MSTATUS status;
    extensions *pTemp = NULL;

    if (NULL == *ppExtensions)
    {
        status = DIGI_CALLOC((void **) ppExtensions, sizeof(certExtensions), 1);
        if (OK != status)
            goto exit;
    }

    if ((*ppExtensions)->otherExtCount > 0)
    {
        int oldCount = (*ppExtensions)->otherExtCount;
        int newCount = oldCount + 1;
        pTemp = (*ppExtensions)->otherExts;
        if (OK > (status = DIGI_MALLOC((void **)&((*ppExtensions)->otherExts), (newCount)*sizeof(extensions))))
        {
            goto exit;
        }
        if (OK > (status = DIGI_MEMSET((ubyte*)(*ppExtensions)->otherExts, 0x00, (newCount)*sizeof(extensions))))
        {
            goto exit;
        }
        if (OK > (status = DIGI_MEMCPY(((*ppExtensions)->otherExts), pTemp, oldCount * sizeof(extensions))))
        {
            goto exit;
        }
        (*ppExtensions)->otherExtCount = newCount;
    }
    else
    {
        if (OK > (status = DIGI_MALLOC((void **)&((*ppExtensions)->otherExts), sizeof(extensions))))
        {
            goto exit;
        }
        if (OK > (status = DIGI_MEMSET((ubyte*)(*ppExtensions)->otherExts, 0x00, sizeof(extensions))))
        {
            goto exit;
        }
        (*ppExtensions)->otherExtCount = 1;
    }

exit:
    if (pTemp != NULL)
        DIGI_FREE((void **)&pTemp);

    return status;
}

/*----------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TAP__)

static MSTATUS EST_getTapContextCb(
    TAP_Context **ppTapCtx,
    TAP_EntityCredentialList **ppTapEntityCred,
    TAP_CredentialList **ppTapKeyCred,
    void *pKey,
    TapOperation op,
    ubyte getContext)
{
    MSTATUS status;

    if (NULL != g_pGetTapContext)
    {
        status = g_pGetTapContext(
            ppTapCtx, ppTapEntityCred, ppTapKeyCred, getContext);
    }
    else
    {
        status = ERR_NULL_POINTER;
    }

    return status;
}

#endif

/*----------------------------------------------------------------------------*/

/*
Example of csr Attrs from config file
------------------------------------
#Subject
countryName=US
commonName=Estclient
stateOrProvinceName=California
localityName=San Francisco
organizationName=Digicert Inc
organizationalUnitName=Engineering
#Requested Extensions
hasBasicConstraints=true
isCA=false
certPathLen=-1
keyUsage=digitalSignature, keyEncipherment
serialNumber=EstclientSerialNumber
#subjectAltNames numSANS; value, type; value, type
subjectAltNames=2;*.googleusercontent.com, 2;*.blogspot.com, 2
*/

static MSTATUS EST_createPKCS10RequestFromConfig(
    MOC_HW(hwAccelDescr hwAccelCtx)
    ubyte* pConfigPath,
    ubyte *pExtendedAttrsFile,
    ubyte4 config_type,
    AsymmetricKey *pAsymKey,
    CertEnrollAlg keyAlgorithm,
    ubyte *pCert,
    ubyte4 certLen,
    ubyte hashType,
    ubyte* pKeyEncryptionAlgId,
    ubyte4 keyEncryptionAlgIdLen,
    ubyte *pKeyAlias,
    ubyte4 keyAliasLen,
    ubyte4 keyType,
    ubyte *pChallengePwd,
    ubyte4 challengePwdLength,
    sbyte4 connectionSSLInstance,
    ubyte *pAsymSmimeCert,
    ubyte4 asymSmimeCertLen,
    ubyte **pPCsr,
    ubyte4* pCsrLen,
    ubyte4 isReenroll,
    ExtendedEnrollFlow extFlow,
    EvalFunction evalFunction,
    void *pEvalFunctionArg)
{
    MSTATUS               status                            = OK;
    ubyte4                tlsUniqueLen                      = 12;
    ubyte                 *pTlsUnique                       = NULL;
    ubyte                 *pBase64TlsUnique                 = NULL;
    ubyte4                base64TlsUniqueLen                = 0;
    CertCsrCtx            *pCsrCtx                          = NULL;
    ubyte                 *pCertReq                         = NULL;
    ubyte4                certReqLen                        = 0;
    ubyte4                confBufLen                        = 0;
    ubyte                 *pFp                              = NULL;
    ubyte                 *pEncryptionAlgId                 = NULL;
    byteBoolean           excludeSignature                  = FALSE;

    if (pAsymKey == NULL)
    {
        /* This should be serverkeygen scenario */
        excludeSignature = TRUE;
    }

    if (EST_CONFIG_FILE == config_type)
    {
        status = DIGICERT_readFile(pConfigPath, &pFp, &confBufLen);
        if (OK != status)
        {
            myPrintError("EST_createPKCS10RequestFromConfig::DIGICERT_readFile failed to read CSR config", status);
            goto exit;
        }
    }
    else
    {
        confBufLen = DIGI_STRLEN(pConfigPath);
    }

    if (OK > (status = DIGI_CALLOC((void**)&(pCsrCtx), 1, sizeof(CertCsrCtx))))
    {
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_TAP__)
    status = CERT_ENROLL_setTAPCallback(pCsrCtx, EST_getTapContextCb);
    if (OK != status)
    {
        myPrintError("EST_createPKCS10RequestFromConfig::CERT_ENROLL_setTAPCallback", status);
        goto exit;
    }
#endif

    if (OK > (status = CERT_ENROLL_addCsrAttributes(pCsrCtx,
                            (EST_CONFIG_JSON == config_type) ? JSON : TOML,
                            0/*unused*/,
                            evalFunction,
                            pEvalFunctionArg,
                            pAsymKey,
                            keyAlgorithm,
                            FALSE,
                            hashType,
                            (EST_CONFIG_JSON == config_type) ? pConfigPath : pFp,
                            confBufLen,
                            NULL,
                            extFlow)))
    {
        myPrintError("EST_createPKCS10RequestFromConfig::CERT_ENROLL_addCsrAttributes", status);
        goto exit;
    }

    if (pKeyEncryptionAlgId != NULL)
    {
        /* ubyte* pKeyEncryptionAlgId, ubyte4 keyEncryptionAlgIdLen */
        if (OK > (status = DIGI_MALLOC((void**)&pEncryptionAlgId, keyEncryptionAlgIdLen+1)))
        {
            myPrintError("EST_createPKCS10RequestFromConfig::DIGI_MALLOC:", status);
            goto exit;
        }
        if (OK > (status = DIGI_MEMSET(pEncryptionAlgId, 0x00, keyEncryptionAlgIdLen+1)))
        {
            myPrintError("EST_createPKCS10RequestFromConfig::DIGI_MEMSET:", status);
            goto exit;
        }
        if (OK > (status = DIGI_MEMCPY(pEncryptionAlgId, pKeyEncryptionAlgId, keyEncryptionAlgIdLen)))
        {
            myPrintError("EST_createPKCS10RequestFromConfig::DIGI_MEMCPY:", status);
            goto exit;
        }
        /* Add Server keygen attributes*/
        if (OK > (status = EST_addServerKeyGenAttr(&pCsrCtx->reqAttr,
                                                          pEncryptionAlgId, keyEncryptionAlgIdLen,
                                                          pKeyAlias, keyAliasLen,
                                                          keyType,
                                                          pAsymSmimeCert, asymSmimeCertLen)))
        {
            myPrintError("EST_createPKCS10RequestFromConfig::EST_addServerKeyGenAttr:", status);
            goto exit;
        }
    }

    if (isReenroll == CMC_REENROLL)
    {
        /**
         * If it is a Microsoft CA, the Attributes field MUST include
         * the szOID_RENEWAL_CERTIFICATE (1.3.6.1.4.1.311.13.1) attribute.
         * If this attribute is not included, the CA assumes that this is a new certificate request.
         */
        ubyte renewalCertOid[] = {9, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0D, 0x01};
        ubyte4 attributesCount = 1;
        if (OK > (status = DIGI_MALLOC((void**)&(pCsrCtx->reqAttr.pOtherAttrs), attributesCount * sizeof(MocRequestAttr))))
        {
            myPrintError("EST_createPKCS10RequestFromConfig::DIGI_MALLOC:", status);
            goto exit;
        }
        if (OK > (status = DIGI_MEMSET((ubyte*)pCsrCtx->reqAttr.pOtherAttrs, 0x00, attributesCount * sizeof(MocRequestAttr))))
        {
            myPrintError("EST_createPKCS10RequestFromConfig::DIGI_MEMSET:", status);
            goto exit;
        }

        if (OK > (status = DIGI_MALLOC((void**)&(pCsrCtx->reqAttr.pOtherAttrs->oid), sizeof(renewalCertOid))))
        {
            myPrintError("EST_createPKCS10RequestFromConfig::DIGI_MALLOC:", status);
            goto exit;
        }

        if (OK > (status = DIGI_MEMSET(pCsrCtx->reqAttr.pOtherAttrs->oid, 0x00, sizeof(renewalCertOid))))
        {
            myPrintError("EST_createPKCS10RequestFromConfig::DIGI_MEMSET:", status);
            goto exit;
        }

        if (OK > (status = DIGI_MEMCPY(pCsrCtx->reqAttr.pOtherAttrs->oid, renewalCertOid, sizeof(renewalCertOid))))
        {
            myPrintError("EST_createPKCS10RequestFromConfig::DIGI_MEMCPY:", status);
            goto exit;
        }

        if (OK > (status = DIGI_MALLOC((void**)&(pCsrCtx->reqAttr.pOtherAttrs->pValue), certLen)))
        {
            myPrintError("EST_createPKCS10RequestFromConfig::DIGI_MALLOC:", status);
            goto exit;
        }

        if (OK > (status = DIGI_MEMSET(pCsrCtx->reqAttr.pOtherAttrs->pValue, 0x00, certLen)))
        {
            myPrintError("EST_createPKCS10RequestFromConfig::DIGI_MEMSET:", status);
            goto exit;
        }

        if (OK > (status = DIGI_MEMCPY(pCsrCtx->reqAttr.pOtherAttrs->pValue, pCert, certLen)))
        {
            myPrintError("EST_createPKCS10RequestFromConfig::DIGI_MEMCPY:", status);
            goto exit;
        }

        pCsrCtx->reqAttr.pOtherAttrs->valueLen = certLen;
        pCsrCtx->reqAttr.otherAttrCount = attributesCount;
    }
    else if (isReenroll == CMC_ENROLL)
    {
        if (pAsymKey == NULL)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }

        /* Add subjectKeyIdentifier Acc to RFC 3280 in the CSR */
        if (OK > (status = EST_addSubjectKeyIdentifierExtension(MOC_ASYM(hwAccelCtx) &pCsrCtx->reqAttr, pAsymKey)))
        {
            myPrintError("EST_createPKCS10RequestFromConfig::EST_addSubjectKeyIdentifierExtension:", status);
            goto exit;
        }
    }

    /* Add challenge password to the attributes */
    if (NULL != pChallengePwd)
    {
        /* Use challenge password provided by caller */
        if (OK > (status = DIGI_MALLOC((void**)&(pCsrCtx->reqAttr.pChallengePwd), challengePwdLength)))
        {
            myPrintError("EST_createPKCS10RequestFromConfig::DIGI_MALLOC:", status);
            goto exit;
        }

        if (OK > (status = DIGI_MEMCPY( pCsrCtx->reqAttr.pChallengePwd, pChallengePwd, challengePwdLength)))
        {
            myPrintError("EST_createPKCS10RequestFromConfig::DIGI_MEMCPY:", status);
            goto exit;
        }

        pCsrCtx->reqAttr.challengePwdLength = challengePwdLength;
    }
    else if (0 < connectionSSLInstance)
    {
        /* Use challenge password as TLS unique from SSL connection */
        SSL_getTlsUnique(connectionSSLInstance, &tlsUniqueLen, &pTlsUnique);

        if (OK > (status = BASE64_encodeMessage(pTlsUnique, tlsUniqueLen, &pBase64TlsUnique, &base64TlsUniqueLen)))
        {
            goto exit;
        }
        if (OK > (status = DIGI_MALLOC((void**)&(pCsrCtx->reqAttr.pChallengePwd), base64TlsUniqueLen + 1)))
        {
            myPrintError("EST_createPKCS10RequestFromConfig::DIGI_MALLOC:", status);
            goto exit;
        }
        DIGI_MEMSET((ubyte*)pCsrCtx->reqAttr.pChallengePwd, 0x00, base64TlsUniqueLen);
        DIGI_MEMCPY( pCsrCtx->reqAttr.pChallengePwd, pBase64TlsUnique, base64TlsUniqueLen);
        pCsrCtx->reqAttr.challengePwdLength = base64TlsUniqueLen;
    }
    else
    {
        /* No challenge password */
        pCsrCtx->reqAttr.pChallengePwd = NULL;
        pCsrCtx->reqAttr.challengePwdLength = 0;
    }

    /* Parse the Extended Attributes */
    if ((NULL != pExtendedAttrsFile))
    {
        if (OK > (status = EST_CERT_UTIL_makeExtensionsFromConfigFile((char *)pExtendedAttrsFile, &(pCsrCtx->reqAttr.pExtensions))))
        {
            goto exit;
        }
    }


    if (TRUE == excludeSignature)
    {
        /* Doesn't need to generate a signature and public Key ASN1 element */
        /* 5. Make a call to PKCS10_GenerateCertReqFromDNEx2 to generate CSR
         * with out signature and public key
         */
        if (OK > (status = PKCS10_GenerateCertReqFromDNEx2(NULL, ht_none, pCsrCtx->pCertSubjectInfo, &pCsrCtx->reqAttr,
                                                                          &pCertReq, &certReqLen)))
        {
            myPrintError("EST_createPKCS10RequestFromConfig::EST_GenerateCSRWithOutSignatureFromDNEx:", status);
            goto exit;
        }
    }
    else
    {
        if (g_initTPM12KeyCtx != NULL)
        {
            g_initTPM12KeyCtx(pAsymKey);
        }
        /* 5. Make a call to PKCS10_GenerateCertReqFromDNEx to generate CSR request */
        if (OK > (status = PKCS10_GenerateCertReqFromDNEx(pAsymKey, hashType,
                                                          pCsrCtx->pCertSubjectInfo, &pCsrCtx->reqAttr,
                                                          &pCertReq, &certReqLen)))
        {
            myPrintError("EST_createPKCS10RequestFromConfig::PKCS10_GenerateCertReqFromDNEx:", status);
            goto exit;
        }
    }

    /*6. Convert to CSR */
    if (OK > (status = EST_MESSAGE_CertReqToCSR(pCertReq, certReqLen, pPCsr, pCsrLen)))
    {
        goto exit;
    }

exit:

    if (NULL != pFp)
    {
        DIGICERT_freeReadFile(&pFp);
    }
    if (NULL != pTlsUnique)
    {
        DIGI_FREE((void **) &pTlsUnique);
    }
    if (g_deinitTPM12KeyCtx != NULL)
    {
        g_deinitTPM12KeyCtx();
    }
    if (pCertReq != NULL)
        FREE(pCertReq);
    if (NULL != pCsrCtx)
    {
        (void) CERT_ENROLL_cleanupCsrCtx(pCsrCtx);
        (void) DIGI_FREE((void **)&pCsrCtx);
    }
    if (pBase64TlsUnique)
        DIGI_FREE((void **)&pBase64TlsUnique);
    if(pEncryptionAlgId)
        DIGI_FREE((void **)&pEncryptionAlgId);
    return status;
}

static
MSTATUS EST_addIssuerAndSerialNumber(DER_ITEMPTR pParent,
        CStream cs,
        ASN1_ITEMPTR pIssuer,
        ASN1_ITEMPTR pSerialNumber,
        DER_ITEMPTR *ppIssuerAndSerialNumber)
{
    MSTATUS status;
    DER_ITEMPTR pIssuerAndSerialNumber;

    if (OK > (status = DER_AddSequence(pParent, &pIssuerAndSerialNumber)))
        goto exit;

    if ( OK > (status = DER_AddASN1Item( pIssuerAndSerialNumber, pIssuer, cs, NULL)))
        goto exit;

    if ( OK > (status = DER_AddASN1Item( pIssuerAndSerialNumber, pSerialNumber, cs, NULL)))
        goto exit;

    if (ppIssuerAndSerialNumber)
    {
        *ppIssuerAndSerialNumber = pIssuerAndSerialNumber;
    }

exit:

    return status;
}

static
MSTATUS EST_addServerKeyGenAttr(requestAttributesEx *pPkcs10_attributes, ubyte *pAlgId, ubyte4 algIdLen, ubyte *pKeyAlias, ubyte4 keyAliasLen, ubyte4 keyType, ubyte *pAsymSmimeCert, ubyte4 asymSmimeCertLen)
{
    MSTATUS        status              = OK;
    DER_ITEMPTR    pSmimeItemPtr       = NULL;
    DER_ITEMPTR    pTemp               = NULL;
    ubyte          *pSerializedData    = NULL;
    ubyte4         serializedDataLen   = 0;
    int            numAttrs            = 2;   /* 1. SMimeCapabilities, 2. KeyIdentifier */
    ubyte          *pOid               = NULL;
    ubyte4         oidLen              = 0;
    DER_ITEMPTR    pNewPtr             = NULL;
    DER_ITEMPTR    pIssuerSerialNumber = NULL;
    ubyte          *pSerializedKeyData = NULL;
    ubyte4         serializedKeyLength = 0;
    ubyte          smimeCapabilitiesOid[]         = {9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0F};
    ASN1_ITEMPTR  pSelfCertificate = NULL;

    if ( (NULL == pAlgId) || (NULL == pKeyAlias) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
	MOC_UNUSED(algIdLen);

    if (OK > (status = EST_CERT_UTIL_generateOIDFromString((const sbyte*)pAlgId, &pOid, &oidLen)))
    {
        myPrintError("EST_addServerKeyGenAttr::EST_CERT_UTIL_generateOIDFromString:", status);
        goto exit;
    }

    /* Allocate memory to the otherAttrs structure (Array of two)*/
    if (OK > (status = DIGI_MALLOC((void**)&(pPkcs10_attributes->pOtherAttrs), numAttrs * sizeof(MocRequestAttr))))
    {
        myPrintError("EST_addServerKeyGenAttr::DIGI_MALLOC:", status);
        goto exit;
    }
    if (OK > (status = DIGI_MEMSET((ubyte*)pPkcs10_attributes->pOtherAttrs, 0x00, numAttrs * sizeof(MocRequestAttr))))
    {
        myPrintError("EST_addServerKeyGenAttr::DIGI_MEMSET:", status);
        goto exit;
    }

    /* Copy the SMimeCapabalities in 0 position of the otherAttrs Array*/
    if (OK > (status = DIGI_MALLOC((void**)&((&(pPkcs10_attributes->pOtherAttrs[0]))->oid), sizeof(smimeCapabilitiesOid))))
    {
        myPrintError("EST_addServerKeyGenAttr::DIGI_MALLOC:", status);
        goto exit;
    }
    if (OK > (status = DIGI_MEMSET((ubyte*)(&(pPkcs10_attributes->pOtherAttrs[0]))->oid, 0x00, sizeof(smimeCapabilitiesOid))))
    {
        myPrintError("EST_addServerKeyGenAttr::DIGI_MEMSET:", status);
        goto exit;
    }
    if (OK > (status = DIGI_MEMCPY((&(pPkcs10_attributes->pOtherAttrs[0]))->oid, smimeCapabilitiesOid, sizeof(smimeCapabilitiesOid))))
    {
        myPrintError("EST_addServerKeyGenAttr::DIGI_MEMCPY:", status);
        goto exit;
    }
    if (OK > (status = DER_AddSequence (NULL, &pSmimeItemPtr)))
    {
        myPrintError("EST_addServerKeyGenAttr::DER_AddSequence:", status);
        goto exit;
    }
    if (OK > ( status = DER_AddSequence( pSmimeItemPtr, &pTemp)))
    {
        myPrintError("EST_addServerKeyGenAttr::DER_AddSequence:", status);
        goto exit;
    }
    if (OK > (status = DER_AddOID (pTemp, pOid, NULL)))
    {
        myPrintError("EST_addServerKeyGenAttr::DER_AddOID:", status);
        goto exit;
    }
    if (OK > (status = DER_Serialize(pSmimeItemPtr, &pSerializedData, &serializedDataLen)))
    {
        myPrintError("EST_addServerKeyGenAttr::DER_Serialize:", status);
        goto exit;
    }
    (&(pPkcs10_attributes->pOtherAttrs[0]))->pValue = pSerializedData;
    (&(pPkcs10_attributes->pOtherAttrs[0]))->valueLen = serializedDataLen;

    /* Copy the key in 1 position of the otherAttrs array*/
    if (keyType == akt_custom)
    {
        /* Add Symmetric key identifier */
        if (OK > (status = DIGI_MALLOC((void**)&((&(pPkcs10_attributes->pOtherAttrs[1]))->oid), sizeof(decryptKeyIdentifider_OID))))
        {
            myPrintError("EST_addServerKeyGenAttr::DIGI_MALLOC:", status);
            goto exit;
        }
        if (OK > (status = DIGI_MEMSET((ubyte*)(&(pPkcs10_attributes->pOtherAttrs[1]))->oid, 0x00, sizeof(decryptKeyIdentifider_OID))))
        {
            myPrintError("EST_addServerKeyGenAttr::DIGI_MEMSET:", status);
            goto exit;
        }
        if (OK > (status = DIGI_MEMCPY((&(pPkcs10_attributes->pOtherAttrs[1]))->oid, decryptKeyIdentifider_OID, sizeof(decryptKeyIdentifider_OID))))
        {
            myPrintError("EST_addServerKeyGenAttr::DIGI_MEMCPY:", status);
            goto exit;
        }
        if (OK > (status = DER_AddItem(NULL, OCTETSTRING, keyAliasLen, pKeyAlias, &pNewPtr)))
        {
            myPrintError("EST_addServerKeyGenAttr::DER_AddItem:", status);
            goto exit;
        }
        if (OK > (status = DER_Serialize(pNewPtr, &pSerializedKeyData, &serializedKeyLength)))
        {
            myPrintError("EST_addServerKeyGenAttr::DER_Serialize:", status);
            goto exit;
        }

    }
    else if (keyType == akt_rsa || keyType == akt_ecc || keyType == akt_ecc_ed)
    {
        CStream       certStream = {0};
        MemFile       memFile;
        ASN1_ITEMPTR  pIssuer = NULL;
        ASN1_ITEMPTR  pSerialNumber = NULL;
        /* Add ASymmetric key identifier */
        if (OK > (status = DIGI_MALLOC((void**)&((&(pPkcs10_attributes->pOtherAttrs[1]))->oid), sizeof(asymDecryptKeyIdentifider_OID))))
        {
            myPrintError("EST_addServerKeyGenAttr::DIGI_MALLOC:", status);
            goto exit;
        }
        if (OK > (status = DIGI_MEMSET((&(pPkcs10_attributes->pOtherAttrs[1]))->oid, 0x00, sizeof(asymDecryptKeyIdentifider_OID))))
        {
            myPrintError("EST_addServerKeyGenAttr::DIGI_MEMSET:", status);
            goto exit;
        }
        if (OK > (status = DIGI_MEMCPY((&(pPkcs10_attributes->pOtherAttrs[1]))->oid, asymDecryptKeyIdentifider_OID, sizeof(asymDecryptKeyIdentifider_OID))))
        {
            myPrintError("EST_addServerKeyGenAttr::DIGI_MEMCPY:", status);
            goto exit;
        }
        /* Get the client certificate from cert store using keyalias */
        MF_attach(&memFile, asymSmimeCertLen, (ubyte*) pAsymSmimeCert);
        CS_AttachMemFile(&certStream, &memFile );

        if (OK > (status = ASN1_Parse(certStream, &pSelfCertificate)))
        {
            myPrintError("EST_addServerKeyGenAttr::ASN1_Parse::status: ", status);
            goto exit;
        }
        /* get issuer and serial number of certificate */
        if (OK > (status = X509_getCertificateIssuerSerialNumber( ASN1_FIRST_CHILD(pSelfCertificate), &pIssuer, &pSerialNumber)))
        {
            myPrintError("EST_createPKCS7Request::X509_getCertificateIssuerSerialNumber::status: ", status);
            goto exit;
        }

        if (OK > (status = EST_addIssuerAndSerialNumber(NULL,
                        certStream,
                        pIssuer,
                        pSerialNumber,
                        &pIssuerSerialNumber)))
        {
            goto exit;
        }

        if (OK > (status = DER_Serialize(pIssuerSerialNumber, &pSerializedKeyData, &serializedKeyLength)))
        {
            myPrintError("EST_addServerKeyGenAttr::DER_Serialize:", status);
            goto exit;
        }

    }
    else
    {
        status = ERR_BAD_KEY_TYPE;
        goto exit;
    }

    (&(pPkcs10_attributes->pOtherAttrs[1]))->pValue = pSerializedKeyData;
    (&(pPkcs10_attributes->pOtherAttrs[1]))->valueLen = serializedKeyLength;
    pPkcs10_attributes->otherAttrCount = numAttrs;

exit:
    if (pSelfCertificate != NULL)
    {
        TREE_DeleteTreeItem((TreeItem*)pSelfCertificate);
    }
    if (pNewPtr != NULL)
        TREE_DeleteTreeItem ((TreeItem *)pNewPtr);
    if (pSmimeItemPtr != NULL)
        TREE_DeleteTreeItem ((TreeItem *)pSmimeItemPtr);
    if (pIssuerSerialNumber != NULL)
        TREE_DeleteTreeItem ((TreeItem *)pIssuerSerialNumber);
    if (pOid)
        FREE(pOid - 1); /* at the time of oid creation 1 byte is skiped but it should be freed. */
    return status;
}

static
MSTATUS EST_calculateSubjectKeyIdentifier(MOC_ASYM(hwAccelDescr hwAccelCtx) AsymmetricKey *pAsymKey, ubyte **pPSubjectKeyId, ubyte4 *pSubjectKeyIdLen)
{
    MSTATUS status = OK;
    ubyte *pRet = NULL;
    ubyte *ptBuffer = NULL;
    ubyte4 ptBufferLen = 0;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    MRsaKeyTemplate template = { 0 };
    vlong *pMod = NULL;
#endif
#ifdef __ENABLE_DIGICERT_TAP__
    TAP_Key *pTapKey = NULL;
    TAP_RSAPublicKey *pRsaTapPub = NULL;
#endif

    if (OK > (status = DIGI_MALLOC((void**)&pRet, SHA1_RESULT_SIZE+2)))
    {
        goto exit;
    }
    if (OK > (status = DIGI_MEMSET(pRet, 0x00, SHA1_RESULT_SIZE+2)))
    {
        goto exit;
    }
    *pRet = 0x04;
    *(pRet+1) = 0x14;
    /* Calculate SHA-1 Hash of the RSA public key */
    switch ( pAsymKey->type)
    {
#ifndef __DISABLE_DIGICERT_RSA__
        case akt_rsa:
        {
            /* serial number -> generated by SHA-1 hash of the RSA key modulus */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_RSA_getKeyParametersAlloc(MOC_RSA(hwAccelCtx)
                pAsymKey->key.pRSA, &template, MOC_GET_PUBLIC_KEY_DATA,
                pAsymKey->type);
            if (OK != status)
                goto exit;

            status = VLONG_vlongFromByteString(
                template.pN, template.nLen, &pMod, NULL);
            if (OK != status)
                goto exit;

            if (OK > (status = CRYPTO_INTERFACE_SHA1_completeDigest(
                    MOC_HASH(hwAccelCtx) (ubyte *) pMod->pUnits,
                    sizeof(vlong_unit) * pMod->numUnitsUsed, pRet+2)))
#else
            if (OK > (status = SHA1_completeDigest(MOC_HASH(hwAccelCtx)
                                    (ubyte *)RSA_N(pAsymKey->key.pRSA)->pUnits,
                                    sizeof(vlong_unit) * RSA_N(pAsymKey->key.pRSA)->numUnitsUsed, pRet+2)))
#endif
            {
                goto exit;
            }
            break;
        }
#endif
#if (defined(__ENABLE_DIGICERT_ECC__))
        case akt_ecc:
        case akt_ecc_ed:
        {
            /* serial number -> generated by SHA-1 hash of the point */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            if (OK > (status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAlloc(MOC_ECC(hwAccelCtx)
                    pAsymKey->key.pECC, &ptBuffer, &ptBufferLen, pAsymKey->type)))
            {
                goto exit;
            }
            if ( OK > ( status = CRYPTO_INTERFACE_SHA1_completeDigest( MOC_HASH(hwAccelCtx)
                                    ptBuffer, ptBufferLen, pRet+2)))
            {
                goto exit;
            }
#else
            if ( OK > ( status = EC_pointToByteString( pAsymKey->key.pECC->pCurve,
                                                    pAsymKey->key.pECC->Qx,
                                                    pAsymKey->key.pECC->Qy,
                                                    &ptBuffer,
                                                    (sbyte4*)&ptBufferLen)))
            {
                goto exit;
            }
            if ( OK > ( status = SHA1_completeDigest( MOC_HASH(hwAccelCtx)
                                    ptBuffer, ptBufferLen, pRet+2)))
            {
                goto exit;
            }
#endif
            break;
        }
#endif
#ifdef __ENABLE_DIGICERT_TAP__
        case akt_tap_rsa:
        {
            status = CRYPTO_INTERFACE_RSA_getTapKey(
                pAsymKey->key.pRSA, &pTapKey);
            if (OK != status)
                goto exit;

            pRsaTapPub = (TAP_RSAPublicKey *)(&(pTapKey->keyData.publicKey.publicKey.rsaKey));

            /* serial number -> generated by SHA-1 hash of the RSA key modulus */
            if (OK > (status = CRYPTO_INTERFACE_SHA1_completeDigest(MOC_HASH(hwAccelCtx)
                            (ubyte *)pRsaTapPub->pModulus,
                             pRsaTapPub->modulusLen, pRet+2)))
            {
                goto exit;
            }

            break;
        }
#if (defined(__ENABLE_DIGICERT_ECC__))
        case akt_tap_ecc:
        {

            /* serial number -> generated by SHA-1 hash of the point */
            if (OK > (status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAlloc(MOC_ECC(hwAccelCtx)
                    pAsymKey->key.pECC, &ptBuffer, &ptBufferLen, pAsymKey->type)))
            {
                goto exit;
            }
            if ( OK > ( status = CRYPTO_INTERFACE_SHA1_completeDigest( MOC_HASH(hwAccelCtx)
                                    ptBuffer, ptBufferLen, pRet+2)))
            {
                goto exit;
            }

            break;
        }
#endif
#endif

        default:
        {
            status = ERR_BAD_KEY_TYPE;
            goto exit;
        }
    }
    *pPSubjectKeyId = pRet;
    *pSubjectKeyIdLen = SHA1_RESULT_SIZE + 2;

exit:

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && !defined(__DISABLE_DIGICERT_RSA__)
    if (pAsymKey != NULL && pAsymKey->type == akt_rsa)
    {
        CRYPTO_INTERFACE_RSA_freeKeyTemplate(
            pAsymKey->key.pRSA, &template, pAsymKey->type);
    }
    if (NULL != pMod)
        VLONG_freeVlong(&pMod, NULL);
#endif

    if (ptBuffer)
    {
        FREE(ptBuffer);
    }
    return status;
}

static
MSTATUS EST_addSubjectKeyIdentifierExtension(MOC_ASYM(hwAccelDescr hwAccelCtx) requestAttributesEx *pPkcs10_attributes, AsymmetricKey *pAsymKey)
{
    MSTATUS status = OK;
    ubyte *pSKI = NULL;
    ubyte4 skiLength = 0;
    extensions *pSubjectKeyIdExt;

    if (OK > (status = EST_calculateSubjectKeyIdentifier(MOC_ASYM(hwAccelCtx) pAsymKey, &pSKI, &skiLength)))
    {
        goto exit;
    }

    status = newExtensionAlloc(&(pPkcs10_attributes->pExtensions));
    if (OK != status)
        goto exit;

    pSubjectKeyIdExt = &(pPkcs10_attributes->pExtensions->otherExts[pPkcs10_attributes->pExtensions->otherExtCount-1]);
    pSubjectKeyIdExt->oid = (ubyte*)subjectKeyIdentifier_OID;
    pSubjectKeyIdExt->isCritical = FALSE;
    pSubjectKeyIdExt->value = pSKI;
    pSubjectKeyIdExt->valueLen = skiLength;

exit:
    return status;
}

static MSTATUS
EST_convertHashType(ubyte *hashType, ubyte4 hashLen, ubyte4 *pHashOut)
{
    MSTATUS status = OK;
    int i = 0;
    DigestAlgoMap digestAlgos[SUPPORTED_DIGEST_ALGO_COUNT] =
    {       {(sbyte*)"MD5", ht_md5},
        {(sbyte*)"SHA1", ht_sha1},
        {(sbyte*)"SHA224", ht_sha224},
        {(sbyte*)"SHA256", ht_sha256},
        {(sbyte*)"SHA384", ht_sha384},
        {(sbyte*)"SHA512", ht_sha512}
    };

    for (; i < SUPPORTED_DIGEST_ALGO_COUNT; i++)
    {
        if ((hashLen == DIGI_STRLEN((const sbyte*)digestAlgos[i].digestName)) &&
                (0 == DIGI_STRNICMP((const sbyte*)digestAlgos[i].digestName, (const sbyte*)hashType, hashLen)) )
        {
            *pHashOut = digestAlgos[i].digestType;
            goto exit;
        }
    }

    status = ERR_CRYPTO_BAD_HASH;

exit:
    return status;
}

MSTATUS EST_generateCSRRequestFromConfig(
    MOC_HW(hwAccelDescr hwAccelCtx)
    struct certStore *pCertStore,
    sbyte4 connectionSSLInstance,
    ubyte *pConfigFile,
    ubyte *pExtendedAttrsFile,
    ubyte4 config_type,
    ubyte *pKeyAlias,
    ubyte4 keyAliasLen,
    AsymmetricKey *pKey,
    ubyte4 keyType,
    CertEnrollAlg keyAlgorithm,
    ubyte *pHashType,
    ubyte4 hashTypeLen,
    ubyte **pPCsr,
    ubyte4 *pCsrLen)
{
    return EST_generateCSRRequestFromConfigWithPolicy(
        MOC_HW(hwAccelCtx) pCertStore, connectionSSLInstance, pConfigFile,
        pExtendedAttrsFile, config_type, pKeyAlias, keyAliasLen, pKey, keyType, keyAlgorithm,
        pHashType, hashTypeLen, pPCsr, pCsrLen, EXT_ENROLL_FLOW_NONE, NULL, NULL);
}

/**
@brief      Generates the CSR Request from the config file provided.

@details    This function generates the CSR Request based on the
            configuration file passed.

@param pCertStore             Pointer to the certstore.
@param connectionSSLInstance  SSL connection instance
@param pConfigFile            Pointer to the configuration file path
                              <p>Example content of configuration file:
                              #Subject
                              countryName=US
                              commonName=Estclient
                              stateOrProvinceName=California
                              localityName=San Francisco
                              organizationName=Digicert Inc
                              organizationalUnitName=Engineering
                              #Requested Extensions
                              hasBasicConstraints=true
                              isCA=false
                              certPathLen=-1
                              keyUsage=digitalSignature, keyEncipherment
                              #subjectAltNames numSANS; value, type; value, type
                              subjectAltNames=2;*.googleusercontent.com, 2;*.blogspot.com, 2

@param pExtendedAttrsFile     Pointer to the file which contains extended attributes.
@param pKeyAlias              Pointer to the keyalias to be searched in.
@param keyAliasLen            Key alias length.
@param keyType                Type of the key. Possible values:
                              \ref akt_undefined
                              \ref akt_rsa
                              \ref akt_ecc
                              \ref akt_ecc_ed
                              \ref akt_dsa
                              \ref akt_custom.

@param pHashType              Name of the digest algorithm Ex: "SHA256".
@param hashTypeLen            Length of the digest name.
@param pPCsr                  On return, Double pointer to the CSR.
@param pCsrLen                On return, Pointer to the CSR length.
@param ppPolicyOids           Optional policy OIDs.

@inc_file   est_client_api.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.c
*/
MSTATUS EST_generateCSRRequestFromConfigWithPolicy(
    MOC_HW(hwAccelDescr hwAccelCtx)
    struct certStore *pCertStore,
    sbyte4 connectionSSLInstance,
    ubyte *pConfigFile,
    ubyte *pExtendedAttrsFile,
    ubyte4 config_type,
    ubyte *pKeyAlias,
    ubyte4 keyAliasLen,
    AsymmetricKey *pKey,
    ubyte4 keyType,
    CertEnrollAlg keyAlgorithm,
    ubyte *pHashType,
    ubyte4 hashTypeLen,
    ubyte **pPCsr,
    ubyte4 *pCsrLen,
    ExtendedEnrollFlow extFlow,
    EvalFunction evalFunction,
    void *pEvalFunctionArg)
{
    MSTATUS        status          = OK;
    AsymmetricKey *pRetIdentityKey = NULL;
    ubyte         *pOrigHash       = NULL;
    ubyte4         hash            = 0;

    if (OK > (status = DIGI_MALLOC((void**)&pOrigHash, hashTypeLen+1)))
    {
        goto exit;
    }
    if (OK > (status = DIGI_MEMSET(pOrigHash, 0x00, hashTypeLen+1)))
    {
        goto exit;
    }
    if (OK > (status = DIGI_MEMCPY(pOrigHash, pHashType, hashTypeLen)))
    {
        goto exit;
    }
    if ((akt_rsa == keyType) || (akt_ecc == keyType) || (akt_ecc_ed == keyType) ||
       (akt_tap_rsa == keyType) || (akt_tap_ecc == keyType))
    {
        if (NULL == pKey)
        {
            /* Find the key in the cert store by its alias */
            if (OK > (status = CERT_STORE_findIdentityByAlias(pCertStore,
                                                            pKeyAlias, keyAliasLen,
                                                            &pRetIdentityKey,
                                                            NULL, NULL)))
            {
                myPrintError("EST_generateCSRRequestFromConfigWithPolicy::CERT_STORE_findIdentityByAlias::status ", status);
                goto exit;
            }
        }
        else
        {
            pRetIdentityKey = pKey;
        }
    }

    if (NULL == pRetIdentityKey)
    {
        status = ERR_NOT_FOUND;
        myPrintError("EST_generateCSRRequestFromConfigWithPolicy::Key not found in cert store::status ", status);
        goto exit;
    }

    /* Convert hashType */
    if (OK > (status = EST_convertHashType(pOrigHash, hashTypeLen, &hash)))
    {
        myPrintError("EST_generateCSRRequestFromConfigWithPolicy::EST_convertHashType::status ", status);
        goto exit;
    }

    /* CreatePKCS10Request */
    if (OK > (status = EST_createPKCS10RequestFromConfig(MOC_HW(hwAccelCtx) pConfigFile,
                                                      pExtendedAttrsFile,
                                                      config_type,
                                                      pRetIdentityKey, keyAlgorithm, NULL, 0,
                                                      (ubyte)hash,
                                                      NULL, 0, NULL, 0, 0,
                                                      NULL, 0, connectionSSLInstance,
                                                      NULL, 0,
                                                      pPCsr, pCsrLen, 0, extFlow, evalFunction, pEvalFunctionArg)))
    {
        myPrintError("EST_generateCSRRequestFromConfigWithPolicy::EST_createPKCS10RequestFromConfig::status ", status);
        goto exit;
    }


exit:
    if(pOrigHash) DIGI_FREE((void **)&pOrigHash);
    return status;
}

MSTATUS EST_generateCSRRequestFromConfigEx(
    MOC_HW(hwAccelDescr hwAccelCtx)
    struct certStore *pCertStore,
    ubyte *pCsrConfig,
    ubyte *pExtendedAttrConfig,
    ubyte4 config_type,
    ubyte *pEncryptionAlgId,
    ubyte4 encryptionAlgIdLen,
    ubyte *pKeyAlias,
    ubyte4 keyAliasLen,
    ubyte4 keyType,
    CertEnrollAlg keyAlgorithm,
    ubyte *pHashType,
    ubyte4 hashTypeLen,
    sbyte4 connectionSSLInstance,
    ubyte **pPCsr,
    ubyte4 *pCsrLen)
{
    return EST_generateCSRRequestFromConfigExWithPolicy(
        MOC_HW(hwAccelCtx) pCertStore, pCsrConfig, pExtendedAttrConfig,
        config_type, pEncryptionAlgId, encryptionAlgIdLen, pKeyAlias,
        keyAliasLen, keyType, keyAlgorithm, pHashType, hashTypeLen, connectionSSLInstance,
        pPCsr, pCsrLen, EXT_ENROLL_FLOW_NONE, NULL, NULL);
}

/**
@brief      This API generates the CSR Request from the conf file.

@details    This function generates the CSR Request from config file.
            Use this API to generate a serverkey gen csr request.
            <p> To specify an asymmetric encryption key to be used to encrypt the
            server-generated private key, client has to sent the keyAlias parameter.
            This keyAlias is used to retrieve the certificate from the cert store.

@param pCertStore            Pointer to the certstore.
@param pCsrConfig            Pointer to the config file.
@param pExtendedAttrConfig   Pointer to the extended attr config file.
@param extendedAttrsLen      Length of the extended attributes.
@param pEncryptionAlgId      Pointer to keyEncryption algo id.
@param encryptionAlgIdlen    Length of the keyEncryption algo id.
@param pKeyAlias             Pointer to the key alias with which we retrieve the certificate
                             required to build the SMimeCapabilities for Asymmetric key.
@param pKeyAliasLen          Length of the keyalias.
@param keyType               Type of the key. Possible values:
                              \ref akt_undefined
                              \ref akt_rsa
                              \ref akt_ecc
                              \ref akt_ecc
                              \ref akt_dsa
                              \ref akt_custom.

@param pHashType             Pointer to the digest name Ex: "SHA256".
@param hashTypeLen           Length of the digest name.
@param connectionSSLInstance SSL connection instance
@param pPCsr                 On return, Double pointer to the CSR.
@param pCsrLen               On return, Pointer to the CSR length.
@param ppPolicyOids          Optional policy OIDs.

@inc_file   est_client_api.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This functions generates CSR with out signature and subject public key info.

@funcdoc    est_client_api.c
*/
MSTATUS EST_generateCSRRequestFromConfigExWithPolicy(
    MOC_HW(hwAccelDescr hwAccelCtx)
    struct certStore *pCertStore,
    ubyte *pCsrConfig,
    ubyte *pExtendedAttrConfig,
    ubyte4 config_type,
    ubyte *pEncryptionAlgId,
    ubyte4 encryptionAlgIdLen,
    ubyte *pKeyAlias,
    ubyte4 keyAliasLen,
    ubyte4 keyType,
    CertEnrollAlg keyAlgorithm,
    ubyte *pHashType,
    ubyte4 hashTypeLen,
    sbyte4 connectionSSLInstance,
    ubyte **pPCsr,
    ubyte4 *pCsrLen,
    ExtendedEnrollFlow extFlow,
    EvalFunction evalFunction,
    void *pEvalFunctionArg)
{
    MSTATUS        status           = OK;
    ubyte         *pOrigHash        = NULL;
    ubyte4         hash             = 0;
    ubyte         *pAsymSmimeCert   = NULL;
    ubyte4         asymSmimeCertLen = 0;

    if ((NULL == pHashType) || (NULL == pCertStore) || (pCsrConfig == NULL) ||
        (pPCsr == NULL))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = DIGI_MALLOC((void**)&pOrigHash, hashTypeLen+1)))
    {
        myPrintError("EST_generateCSRRequestFromConfigExWithPolicy::DIGI_MALLOC::status ", status);
        goto exit;
    }
    if (OK > (status = DIGI_MEMSET(pOrigHash, 0x00, hashTypeLen+1)))
    {
        myPrintError("EST_generateCSRRequestFromConfigExWithPolicy::DIGI_MEMSET::status ", status);
        goto exit;
    }
    if (OK > (status = DIGI_MEMCPY(pOrigHash, pHashType, hashTypeLen)))
    {
        myPrintError("EST_generateCSRRequestFromConfigExWithPolicy::DIGI_MEMCPY::status ", status);
        goto exit;
    }
    if ((akt_rsa == keyType) || (akt_ecc == keyType) || (akt_ecc_ed == keyType) ||
       (akt_tap_rsa == keyType) || (akt_tap_ecc == keyType))
    {
        /* Find the key in the cert store by its alias */
        if (OK > (status = CERT_STORE_findIdentityByAlias(pCertStore,
                                                          pKeyAlias, keyAliasLen,
                                                          NULL,
                                                          &pAsymSmimeCert, &asymSmimeCertLen)))
        {
            myPrintError("EST_generateCSRRequestFromConfigExWithPolicy::CERT_STORE_findIdentityByAlias::status ", status);
            goto exit;
        }
        /*
         * In case of Asymmetric key encryption of the private key, the certificate should be
         * present in the cert store. Check if certificate is found in cert store.
         */
        if (NULL == pAsymSmimeCert)
        {
            status = ERR_NOT_FOUND;
            goto exit;
        }
    }


    /* Convert hashType */
    if (OK > (status = EST_convertHashType(pOrigHash, hashTypeLen, &hash)))
    {
        myPrintError("EST_generateCSRRequestFromConfigExWithPolicy::EST_convertHashType::status ", status);
        goto exit;
    }
    /* CreatePKCS10Request */
    if (OK > (status = EST_createPKCS10RequestFromConfig(MOC_HW(hwAccelCtx) pCsrConfig,
                                                      pExtendedAttrConfig,
                                                      config_type,
                                                      NULL, keyAlgorithm, NULL, 0,
                                                      (ubyte)hash,
                                                      pEncryptionAlgId, encryptionAlgIdLen,
                                                      pKeyAlias, keyAliasLen,
                                                      keyType,
                                                      NULL, 0, connectionSSLInstance,
                                                      pAsymSmimeCert, asymSmimeCertLen,
                                                      pPCsr, pCsrLen, 0, extFlow, evalFunction, pEvalFunctionArg)))
    {
        myPrintError("EST_generateCSRRequestFromConfigExWithPolicy::EST_createPKCS10RequestFromConfig::status ", status);
        goto exit;
    }

exit:
    if (pOrigHash)
        DIGI_FREE((void**)&pOrigHash);
    return status;
}

static MSTATUS
getCryptoAlgoParams(const ubyte *pEncryptAlgoOID,
        BulkEncryptionAlgo *pBulkEncryptionAlgo,
        sbyte4 *pKeyLength)
{
#ifndef __DISABLE_3DES_CIPHERS__
    if (EqualOID(desEDE3CBC_OID, pEncryptAlgoOID))
    {
        *pKeyLength = THREE_DES_KEY_LENGTH;
        pBulkEncryptionAlgo->blockSize = THREE_DES_BLOCK_SIZE;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        pBulkEncryptionAlgo->createFunc = CRYPTO_INTERFACE_Create3DESCtx;
        pBulkEncryptionAlgo->cipherFunc = CRYPTO_INTERFACE_Do3DES;
        pBulkEncryptionAlgo->deleteFunc = CRYPTO_INTERFACE_Delete3DESCtx;
#else
        pBulkEncryptionAlgo->createFunc = Create3DESCtx;
        pBulkEncryptionAlgo->cipherFunc = Do3DES;
        pBulkEncryptionAlgo->deleteFunc = Delete3DESCtx;
#endif /*__ENABLE_DIGICERT_CRYPTO_INTERFACE__*/
    }
    else
#endif
#ifdef __ENABLE_DES_CIPHER__
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (EqualOID(desCBC_OID, pEncryptAlgoOID))
    {
        *pKeyLength = DES_KEY_LENGTH;
        pBulkEncryptionAlgo->blockSize = DES_BLOCK_SIZE;
        pBulkEncryptionAlgo->createFunc = CreateDESCtx;
        pBulkEncryptionAlgo->cipherFunc = DoDES;
        pBulkEncryptionAlgo->deleteFunc = DeleteDESCtx;
    }
    else
#endif /*__ENABLE_DIGICERT_CRYPTO_INTERFACE__*/
#endif
#ifndef __DISABLE_AES_CIPHERS__
    if (EqualOID(aes128CBC_OID, pEncryptAlgoOID))
    {
        *pKeyLength = MOC_AES_128_KEY_LEN;
        pBulkEncryptionAlgo->blockSize = AES_BLOCK_SIZE;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        pBulkEncryptionAlgo->createFunc = CRYPTO_INTERFACE_CreateAESCtx;
        pBulkEncryptionAlgo->cipherFunc = CRYPTO_INTERFACE_DoAES;
        pBulkEncryptionAlgo->deleteFunc = CRYPTO_INTERFACE_DeleteAESCtx;
#else
        pBulkEncryptionAlgo->createFunc = CreateAESCtx;
        pBulkEncryptionAlgo->cipherFunc = DoAES;
        pBulkEncryptionAlgo->deleteFunc = DeleteAESCtx;
#endif /*__ENABLE_DIGICERT_CRYPTO_INTERFACE__*/
    }
    else if (EqualOID(aes192CBC_OID, pEncryptAlgoOID))
    {
        *pKeyLength = MOC_AES_192_KEY_LEN;
        pBulkEncryptionAlgo->blockSize = AES_BLOCK_SIZE;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        pBulkEncryptionAlgo->createFunc = CRYPTO_INTERFACE_CreateAESCtx;
        pBulkEncryptionAlgo->cipherFunc = CRYPTO_INTERFACE_DoAES;
        pBulkEncryptionAlgo->deleteFunc = CRYPTO_INTERFACE_DeleteAESCtx;
#else
        pBulkEncryptionAlgo->createFunc = CreateAESCtx;
        pBulkEncryptionAlgo->cipherFunc = DoAES;
        pBulkEncryptionAlgo->deleteFunc = DeleteAESCtx;
#endif /*__ENABLE_DIGICERT_CRYPTO_INTERFACE__*/
    }
    else if (EqualOID(aes256CBC_OID, pEncryptAlgoOID))
    {
        *pKeyLength = MOC_AES_256_KEY_LEN;
        pBulkEncryptionAlgo->blockSize = AES_BLOCK_SIZE;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        pBulkEncryptionAlgo->createFunc = CRYPTO_INTERFACE_CreateAESCtx;
        pBulkEncryptionAlgo->cipherFunc = CRYPTO_INTERFACE_DoAES;
        pBulkEncryptionAlgo->deleteFunc = CRYPTO_INTERFACE_DeleteAESCtx;
#else
        pBulkEncryptionAlgo->createFunc = CreateAESCtx;
        pBulkEncryptionAlgo->cipherFunc = DoAES;
        pBulkEncryptionAlgo->deleteFunc = DeleteAESCtx;
#endif /*__ENABLE_DIGICERT_CRYPTO_INTERFACE__*/
    }
    else
#endif
    {
        return ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
    }

    return OK;
}

/* This callback function is used to retrieve the private key
 * from the cert store using the issuer and serialnumber.
 * This private is used to decrypt the CMS Signed data.
 */
static MSTATUS EST_getPrivateKeyCallback(const void* arg, CStream cs,
        const CMSRecipientId* pId,
        AsymmetricKey* pKey)
{
    MSTATUS          status            = OK;
    ASN1_ITEMPTR     pIssuer           = NULL;
    ASN1_ITEMPTR     pSerialNumber     = NULL;
    const void       *pBufSerialNumber = NULL;
    const void       *pBufIssuer       = NULL;
    AsymmetricKey    *pAsymKey         = NULL;
    struct certStore *pCertStore       = (struct certStore*)arg;

    if ( (NULL == pCertStore) || (NULL == pId) || (NULL == pKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch (pId->type)
    {
        case NO_TAG:
            if (NO_TAG == pId->ri.ktrid.type)
            {
                pIssuer = pId->ri.ktrid.u.issuerAndSerialNumber.pIssuer;
                pSerialNumber = pId->ri.ktrid.u.issuerAndSerialNumber.pSerialNumber;
            }
            else
            {
                status = ERR_FALSE;
                goto exit;
            }
            break;

        case 1:
            if (NO_TAG == pId->ri.karid.type)
            {
                pIssuer = pId->ri.ktrid.u.issuerAndSerialNumber.pIssuer;
                pSerialNumber = pId->ri.ktrid.u.issuerAndSerialNumber.pSerialNumber;
            }
            else
            {
                status = ERR_FALSE;
                goto exit;
            }
            break;

        default:
            status = ERR_FALSE;
            goto exit;
    }
    pBufSerialNumber = CS_memaccess(cs, pSerialNumber->dataOffset, pSerialNumber->length);
    pBufIssuer = CS_memaccess(cs, pIssuer->dataOffset, pIssuer->length);

    if (OK > (status = CERT_STORE_findCertificateByIssuerSerialNumber(pCertStore,
                                                                      pBufIssuer, pIssuer->length,
                                                                      pBufSerialNumber, pSerialNumber->length,
                                                                      NULL, NULL,
                                                                      (const struct AsymmetricKey**)&pAsymKey)))
    {
        myPrintError("EST_getCertificateCallback::CERT_STORE_findCertificateByIssuerSerialNumber::status: ", status);
        goto exit;
    }

    if (OK > (status = CRYPTO_copyAsymmetricKey(pKey, pAsymKey)))
    {
        goto exit;
    }

exit:
    return status;

}

static MSTATUS EST_validateCertificateCallback(const void* arg, CStream cs,
        ASN1_ITEM* pCertificate)
{
	MOC_UNUSED(arg);
	MOC_UNUSED(cs);
	MOC_UNUSED(pCertificate);
    return OK;
}

/* This callback function is used to retrieve the certificate
 * from the cert store using the issuer and serialnumber.
 * This certificate is used to verify the CMS Signed data.
 */
static MSTATUS EST_getCertificateCallback(const void* arg,
        CStream cs,
        ASN1_ITEM* pSerialNumber,
        ASN1_ITEM* pIssuerName,
        ubyte** ppCertificate,
        ubyte4* certLen)
{
    MSTATUS          status            = OK;
    const void       *pBufSerialNumber = NULL;
    const void       *pBufIssuer       = NULL;
    struct certStore *pCertStore       = (struct certStore*)arg;

    if ((pCertStore == NULL) || (pSerialNumber == NULL) || (pIssuerName == NULL))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pBufSerialNumber = CS_memaccess(cs, pSerialNumber->dataOffset, pSerialNumber->length);
    pBufIssuer = CS_memaccess(cs, pIssuerName->dataOffset, pIssuerName->length);

    if (OK > (status = CERT_STORE_findCertificateByIssuerSerialNumber(pCertStore,
                                                                      pBufIssuer, pIssuerName->length,
                                                                      pBufSerialNumber, pSerialNumber->length,
                                                                      (const ubyte**)ppCertificate, certLen,
                                                                      NULL)))
    {
        myPrintError("EST_getCertificateCallback::CERT_STORE_findCertificateByIssuerSerialNumber::status: ", status);
        goto exit;
    }
exit:
    return status;

}

static MSTATUS
EST_getKeyFromCmsStream(struct certStore *pCertStore, ubyte *pCmsSignedData, ubyte4 cmsSignedDataLen, ubyte **ppKeyBlob, ubyte4 *pKeyBlobLen)
{
    MSTATUS       status = OK;
    CMS_context   pCmsCtx = 0;
    CMS_Callbacks cmsCallback;
    intBoolean    done;

    if (NULL == pCertStore || NULL == pCmsSignedData || NULL == ppKeyBlob || NULL == pKeyBlobLen)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    cmsCallback.getCertFun = EST_getCertificateCallback;
    cmsCallback.valCertFun = EST_validateCertificateCallback;
    cmsCallback.getPrivKeyFun = NULL;


    if (OK > (status = CMS_newContext( &pCmsCtx, pCertStore, &cmsCallback)))
    {
        myPrintError("EST_getKeyFromCmsStream::CMS_newContext::status: ", status);
        goto exit;
    }

    if (pCmsCtx == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = CMS_updateContext( pCmsCtx, pCmsSignedData, cmsSignedDataLen, ppKeyBlob, pKeyBlobLen, &done)))
    {
        myPrintError("EST_getKeyFromCmsStream::CMS_updateContext::status: ", status);
        goto exit;
    }

exit:
    if (pCmsCtx != NULL)
        CMS_deleteContext(&pCmsCtx);
    return status;
}

static MSTATUS
EST_decryptCipherData(MOC_SYM(hwAccelDescr hwAccelCtx) struct certStore *pCertStore, ubyte *pSymmetricKey, ubyte4 symmetricKeyLen, ubyte *pAlgoOid, ubyte *pIv, ubyte4 ivLen, ubyte *pData, ubyte4 dataLen, ubyte *pKeyAlias, ubyte4 keyAliasLen, ubyte *pOid, ubyte4 oidLen, ubyte **ppDecryptedData, ubyte4 *pDecryptedDataLen)
{
    MSTATUS            status     = OK;
    ubyte4             keyLength  = 0;
    ubyte              *pPsk      = NULL;
    ubyte4             pskLen     = 0;
    ubyte4             i          = 0;
    byteBoolean        padding    = TRUE;
    BulkEncryptionAlgo bulkEncryptionAlgo;
    ubyte4             pad = 0;

    if ( (NULL == pAlgoOid) || (NULL == pIv) ||
            (NULL == pData) ||   (NULL == ppDecryptedData) ||
            (NULL == pDecryptedDataLen))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
	MOC_UNUSED(oidLen);
	MOC_UNUSED(ivLen);

    if (OK > (status = getCryptoAlgoParams(pAlgoOid, &bulkEncryptionAlgo, (sbyte4 *)&keyLength)))
    {
        myPrintError("EST_decryptCipherData::getCryptoAlgoParams::status: ", status);
        goto exit;
    }
    if (pSymmetricKey == NULL)
    {
        if (NULL == pCertStore)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }
        /* Get the key from the cert store */
        if (EqualOID(decryptKeyIdentifider_OID, pOid))
        {
            /* Symmetric */
            if (OK > (status = CERT_STORE_findPskByIdentity(pCertStore, pKeyAlias, keyAliasLen, &pPsk, &pskLen)))
            {
                myPrintError("EST_decryptCipherData::CERT_STORE_findPskByIdentity::status: ", status);
                goto exit;
            }
        }
        else
        {
            /* Asymmetric Key is handled inside
             * this function EST_getPemKeyFromCmsEnvelopeData
             */
            status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
            myPrintError("EST_decryptCipherData::Unknown OID::status: ", status);
            goto exit;

        }
    }
    else
    {
        pPsk = pSymmetricKey;
        pskLen = symmetricKeyLen;
    }

    /* decrypt in place */
    if (OK >(status = CRYPTO_Process(MOC_SYM(hwAccelCtx) &bulkEncryptionAlgo,
                    pPsk, pskLen, pIv, pData, dataLen, 0)))
    {
        myPrintError("EST_decryptCipherData::CRYPTO_Process::status: ", status);
        goto exit;
    }
    /* Get padding */
    pad = pData[dataLen-1];
    i = dataLen -1;
    for(; i >= (dataLen - pad); --i)
    {
        if(pData[i] != (ubyte)pad)
            padding = FALSE;
    }
    if (padding == TRUE)
    {
        *pDecryptedDataLen = dataLen - pad;
        if (OK > (status = DIGI_MALLOC((void**)ppDecryptedData, *pDecryptedDataLen)))
        {
            myPrintError("EST_decryptCipherData::DIGI_MALLOC::status: ", status);
            goto exit;
        }
        if (OK > (status = DIGI_MEMSET(*ppDecryptedData, 0x00, *pDecryptedDataLen)))
        {
            myPrintError("EST_decryptCipherData::DIGI_MEMSET::status: ", status);
            goto exit;
        }
        if (OK > (status = DIGI_MEMCPY(*ppDecryptedData, pData, *pDecryptedDataLen)))
        {
            myPrintError("EST_decryptCipherData::DIGI_MEMCPY::status: ", status);
            goto exit;
        }
    }

exit:
    return status;
}

static MSTATUS
EST_getKeyAliasFromPkcs7EnvelopeData(ASN1_ITEMPTR pRoot, CStream *pStream, ubyte **pPKeyAlias, ubyte4 *pKeyAliasLen, ubyte **pPOid, ubyte4 *pOidLen)
{
    MSTATUS status = OK;
    ASN1_ITEMPTR pOid = NULL;
    ASN1_ITEMPTR pChildTag = NULL;
    ASN1_ITEMPTR pKeyAliasItem = NULL;
    ubyte4 totalLen = 0;
    ubyte *pBuffer = NULL;
    WalkerStep asn1WalkerStep[] =
    {
        {GoChildWithTag, 0, 0},
        {GoNthChild, 2, 0},
        {GoNthChild, 1, 0},
        {GoNthChild, 2, 0},
        {Complete, 0, 0}
    };
    if ( (NULL == pRoot) || (NULL == pStream) || (NULL == pPKeyAlias) ||
            (NULL == pKeyAliasLen) || (NULL == pPOid) || (NULL == pOidLen))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = ASN1_WalkTree(ASN1_FIRST_CHILD(pRoot), *pStream,
                    asn1WalkerStep, &pChildTag)))
    {
        myPrintError("EST_getKeyAliasFromPkcs7EnvelopeData::ASN1_WalkTree::status: ", status);
        goto exit;
    }

    /* OID */
    if (OK > (status = ASN1_GetNthChild(pChildTag, 1, &pOid)))
    {
        myPrintError("EST_getKeyAliasFromPkcs7EnvelopeData::ASN1_GetNthChild(1)::status: ", status);
        goto exit;
    }
    /* KeyAlias */
    if (OK > (status = ASN1_GetNthChild(pChildTag, 2, &pChildTag)))
    {
        myPrintError("EST_getKeyAliasFromPkcs7EnvelopeData::ASN1_GetNthChild(2)::status: ", status);
        goto exit;
    }
    if (OK > (status = ASN1_GetNthChild(pChildTag, 1, &pKeyAliasItem)))
    {
        myPrintError("EST_getKeyAliasFromPkcs7EnvelopeData::ASN1_GetNthChild(1)::status: ", status);
        goto exit;
    }

    /* Copy the oid */
    totalLen = pOid->length + pOid->headerSize;
    pBuffer = (ubyte*)CS_memaccess(*pStream, (pOid->dataOffset - pOid->headerSize), totalLen);
    if (OK > (status = DIGI_MALLOC((void**)pPOid, totalLen)))
    {
        myPrintError("EST_getKeyAliasFromPkcs7EnvelopeData::DIGI_MALLOC::status: ", status);
        goto exit;
    }
    if (OK > (status = DIGI_MEMSET(*pPOid, 0x00, totalLen)))
    {
        myPrintError("EST_getKeyAliasFromPkcs7EnvelopeData::DIGI_MEMSET::status: ", status);
        goto exit;
    }
    if (OK > (status = DIGI_MEMCPY(*pPOid, pBuffer+1, totalLen)))
    {
        myPrintError("EST_getKeyAliasFromPkcs7EnvelopeData::DIGI_MEMCPY::status: ", status);
        goto exit;
    }
    *pOidLen = totalLen;

    /* Copy the keyAlias */
    totalLen = pKeyAliasItem->length;
    pBuffer = (ubyte*)CS_memaccess(*pStream, (pKeyAliasItem->dataOffset), totalLen);
    if (OK > (status = DIGI_MALLOC((void**)pPKeyAlias, totalLen)))
    {
        myPrintError("EST_getKeyAliasFromPkcs7EnvelopeData::DIGI_MALLOC::status: ", status);
        goto exit;
    }
    if (OK > (status = DIGI_MEMSET(*pPKeyAlias, 0x00, totalLen)))
    {
        myPrintError("EST_getKeyAliasFromPkcs7EnvelopeData::DIGI_MEMSET::status: ", status);
        goto exit;
    }
    if (OK > (status = DIGI_MEMCPY(*pPKeyAlias, pBuffer, totalLen)))
    {
        myPrintError("EST_getKeyAliasFromPkcs7EnvelopeData::DIGI_MEMCPY::status: ", status);
        goto exit;
    }
    *pKeyAliasLen = totalLen;

exit:
    return status;
}

/**
@brief   Get the Asymmetric key blob from CMS Envelop Data.

@details This APi extracts the key from CMS Envelop Data.
          <p> Call this APi when the CMS Signed data is encrypted with an
          Asymmetric key i.e when the serverkeygen request contains
          an AsymdecryptKeyIdentifier OID. When the Signed Data is encrypted
          with a Symmetric key then use the fucntion
          EST_getPemKeyFromPkcs7EnvelopeData() to get the private
          key from CMS Envelop Data. This is because CMS Apis only
          supports encryption/decryption with Asymmetric keys.
          <p> Cert store handle is required to get the certificate from
          the certStore which is used to verify the CMS Signed data and
          also to get the private key which is used to decrypt the encrypted
          Signed data inside Envelop Data.
          <p> It is mandatory for the client, calling this function to make
          sure to have the above required certificates and the private key to
          be in the cert store.

@param pCertStore     Pointer to the cert store.
@param pEnvelopData   Pointer to the PKCS7 Envelop Data.
@param envelopDataLen Length of the  PKCS7 envelop data.
@param ppPemKeyBlob   On return, Double pointer to the keyBlob.
@param pPemKeyBlobLen On return, Pointer to the keyBlob length.

@inc_file   est_client_api.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.c
*/
MSTATUS
EST_getPemKeyFromCmsEnvelopeData(MOC_HW(hwAccelDescr hwAccelCtx) struct certStore *pCertStore, ubyte *pEnvelopeData, ubyte4 envelopeDataLen, ubyte **ppPemKeyBlob, ubyte4 *pPemKeyBlobLen)
{
    MSTATUS       status         = OK;
    CMS_context   pCmsCtx        = 0;
    CMS_Callbacks cmsCallback;
    intBoolean    done           = 0;
    ubyte         *pOut          = NULL;
    ubyte4        outLen         = 0;
    AsymmetricKey asymKey;
    ubyte         *pKeyBlob      = NULL;
    ubyte4        keyBlobLen     = 0;
    ubyte         *pDecodedData  = NULL;
    ubyte4        decodedDataLen = 0;

    if ( (NULL == pCertStore) || ( NULL == pEnvelopeData) ||
            (NULL == ppPemKeyBlob) || (NULL == pPemKeyBlobLen))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    cmsCallback.getCertFun = NULL;
    cmsCallback.valCertFun = NULL;
    cmsCallback.getPrivKeyFun = EST_getPrivateKeyCallback;

    if (OK > (status = CA_MGMT_decodeCertificate(pEnvelopeData, envelopeDataLen, &pDecodedData, &decodedDataLen)))
    {
        myPrintError("EST_getPemKeyFromCmsEnvelopeData::CA_MGMT_decodeCertificate::status: ", status);
        goto exit;
    }


    if (OK > (status = CMS_newContext(&pCmsCtx, pCertStore, &cmsCallback)))
    {
        myPrintError("EST_getPemKeyFromCmsEnvelopeData::CMS_newContext::status: ", status);
        goto exit;
    }

    if (pCmsCtx == NULL)
    {
        status = ERR_NULL_POINTER;
        myPrintError("EST_getPemKeyFromCmsEnvelopeData::Failed to create CMS context::status: ", status);
        goto exit;
    }

    if (OK > (status = CMS_updateContext( pCmsCtx, pDecodedData, decodedDataLen, &pOut, &outLen, &done)))
    {
        myPrintError("EST_getPemKeyFromCmsEnvelopeData::CMS_updateContext::status: ", status);
        goto exit;
    }

    if (pOut != NULL)
    {
        if (OK > (status = EST_getKeyFromCmsStream(pCertStore, pOut, outLen, &pKeyBlob, &keyBlobLen)))
        {
            myPrintError("EST_getPemKeyFromCmsEnvelopeData::EST_getKeyFromCmsStream::status: ", status);
            goto exit;
        }
    }
    else
    {
        status = ERR_NULL_POINTER;
        myPrintError("EST_getPemKeyFromCmsEnvelopeData::Failed to the CMS Signed data::status: ", status);
        goto exit;
    }

    if (pKeyBlob != NULL)
    {
        if (OK > (status = CRYPTO_initAsymmetricKey (&asymKey)))
        {
            myPrintError("EST_getPemKeyFromCmsEnvelopeData::CRYPTO_initAsymmetricKey::status: ", status);
            goto exit;
        }

        /* Serialize the key to pem format */
        status = CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx)
            pKeyBlob, keyBlobLen, NULL, &asymKey);
        if (OK != status)
        {
            myPrintError("EST_getPemKeyFromCmsEnvelopeData::CRYPTO_deserializeAsymKey::status: ", status);
            goto exit;
        }

        status = CRYPTO_serializeAsymKey(MOC_ASYM(hwAccelCtx)
            &asymKey, privateKeyPem, ppPemKeyBlob, pPemKeyBlobLen);
        if (OK != status)
        {
            myPrintError("EST_getPemKeyFromCmsEnvelopeData::CRYPTO_serializeAsymKey::status: ", status);
            goto exit;
        }
    }

exit:

    if (pCmsCtx != NULL)
        CMS_deleteContext(&pCmsCtx);
    if (pOut != NULL)
        FREE(pOut);
    if (pKeyBlob != NULL)
    {
        CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
        DIGI_FREE((void**)&pKeyBlob);
    }
    if(pDecodedData)
        DIGI_FREE((void **)&pDecodedData);

    return status;
}

/*
EnvelopedData ::= SEQUENCE {
        version CMSVersion,
        originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
        recipientInfos RecipientInfos,
        encryptedContentInfo EncryptedContentInfo,
        unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }

      OriginatorInfo ::= SEQUENCE {
        certs [0] IMPLICIT CertificateSet OPTIONAL,
        crls [1] IMPLICIT RevocationInfoChoices OPTIONAL }

      RecipientInfos ::= MOC_SET SIZE (1..MAX) OF RecipientInfo

      EncryptedContentInfo ::= SEQUENCE {
        contentType ContentType,
        contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
        encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }

      EncryptedContent ::= OCTET STRING

      UnprotectedAttributes ::= MOC_SET SIZE (1..MAX) OF Attribute
 */
/**
@brief   Gets the Asymmetric key blob from PKCS7 Envelop Data.

@details This APi extracts the key from PKCS7 Envelop Data.
         <p> Call this APi when the Signed data is encrypted with a
         Symmetric key i.e when the serverkeygen request contains
         a decryptKeyIdentifier OID. When the Signed Data is encrypted
         with an Asymmetric key then use the fucntion
         EST_getPemKeyFromCmsEnvelopeData() to get the private
         key from CMS Envelop Data. This is because CMS Apis only
         supports encryption/decryption with Asymmetric keys.
         <p> Cert store handle is required to get the certificate from
         the certStore which is used to verify the CMS Signed data.

@param pCertStore     Pointer to the cert store.
@param pEnvelopData   Pointer to the PKCS7 Envelop Data.
@param envelopDataLen Length of the  PKCS7 envelop data.
@param ppKeyBlob      On return, Double pointer to the keyblob.
@param pKeyBlobLen    On return, Pointer to the keyblob length.

@inc_file   est_client_api.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.c
*/
MSTATUS
EST_getPemKeyFromPkcs7EnvelopeData(MOC_HW(hwAccelDescr hwAccelCtx) struct certStore *pCertStore, ubyte *pEnvelopData, ubyte4 envelopDataLen, ubyte **ppPemKeyBlob, ubyte4 *pPemKeyBlobLen)
{
    MSTATUS         status            = OK;
    MemFile         memFile;
    CStream         cStream;
    ubyte           *pDecodedData     = NULL;
    ubyte4          decodedDataLen    = 0;
    ASN1_ITEMPTR    pEnvelopDataRoot = NULL;
    ASN1_ITEMPTR    pChildTag         = NULL;
    ubyte           *pIv              = NULL;
    ubyte4           ivLen            = 0;
    ubyte           *pEncryptedData   = NULL;
    ubyte4           encryptedDataLen = 0;
    ubyte           *pDecryptedData   = NULL;
    ubyte4           decryptedDataLen = 0;
    const void      *pBuffer          = NULL;
    ubyte           *pKeyBlob         = NULL;
    ubyte4           keyBlobLen       = 0;
    ubyte           *pKeyAlias        = NULL;
    ubyte4           keyAliasLen      = 0;
    ubyte           *pOid             = NULL;
    ubyte4           oidLen           = 0;
    ubyte            algId[MAX_OID_SIZE] = {0};
    AsymmetricKey    asymKey;

    ASN1_ITEMPTR   pEncryptedDataItemPtr;
    ASN1_ITEMPTR   pIvItemPtr;
    ASN1_ITEMPTR   pObjItemPtr;
    ubyte4         totalLen;

    if ((NULL == pCertStore) || (NULL == pEnvelopData) ||
            (NULL == ppPemKeyBlob) || (NULL == pPemKeyBlobLen))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /*
     1. Get the pkcs7 Envelope data.
     2. Retrieve the iv, encrypted data, keyAlias and algoId from the envelope data.
     3. Retrieve the symmetric key(PSK) from the cert store with its alias name.
     4. Apply the decryption Algorithm with iv, key and data
     5. Remove the padding from the final data if any present.
     6. Now the decrypted content is again a PKCS7 Signed Data.
     7. use CMS APIs to get the keyblob from the signed data.
    */

    /* Decode the key data from Base64 */
    if (OK > (status = CA_MGMT_decodeCertificate(pEnvelopData, envelopDataLen, &pDecodedData, &decodedDataLen)))
    {
        myPrintError("EST_getKeyFromPkcs7EnvelopeData::CA_MGMT_decodeCertificate::status: ", status);
        goto exit;
    }

    MF_attach(&memFile, decodedDataLen, (ubyte*)pDecodedData );
    CS_AttachMemFile(&cStream, &memFile);
    if (OK > (status = ASN1_Parse( cStream, &pEnvelopDataRoot)))
    {
        myPrintError("EST_getKeyFromPkcs7EnvelopeData::ASN1_Parse::status: ", status);
        goto exit;
    }
    /* Get the keyalias and oid */
    if (OK > (status = EST_getKeyAliasFromPkcs7EnvelopeData(pEnvelopDataRoot, &cStream,
                                                                   &pKeyAlias, &keyAliasLen,
                                                                   &pOid, &oidLen)))
    {
        myPrintError("EST_getKeyFromPkcs7EnvelopeData::EST_getKeyAliasFromPkcs7EnvelopeData::status: ", status);
        goto exit;
    }

    /* Traverse to the nodes to get encrypted data, iv and encryption algorithm */
    if (OK > (status = ASN1_GetChildWithTag(ASN1_FIRST_CHILD(pEnvelopDataRoot), 0, &pChildTag)))
    {
        myPrintError("EST_getKeyFromPkcs7EnvelopeData::ASN1_GetChildWithTag::status: ", status);
        goto exit;
    }

    /* 3rd child contains the Algorithm , iv and encrypted data */
    if (OK > (status = ASN1_GetNthChild(pChildTag, 3, &pChildTag)))
    {
        myPrintError("EST_getKeyFromPkcs7EnvelopeData::ASN1_GetNthChild::status: ", status);
        goto exit;
    }

    if (OK > (status = ASN1_GetNthChild(pChildTag, 2, &pChildTag)))
    {
        myPrintError("EST_getKeyFromPkcs7EnvelopeData::ASN1_GetNthChild::status: ", status);
        goto exit;
    }
    /* Get the encryption algorithm */
    pObjItemPtr = ASN1_FIRST_CHILD(pChildTag);
    if (pObjItemPtr == NULL)
    {
        status = ERR_PKCS7_INVALID_STRUCT;
        goto exit;
    }

    totalLen = pObjItemPtr->headerSize + pObjItemPtr->length;
    pBuffer = CS_memaccess(cStream, (pObjItemPtr->dataOffset - pObjItemPtr->headerSize), totalLen);

    if (OK > (status = DIGI_MEMCPY(algId, ((ubyte *)pBuffer + 1), totalLen -1)))
    {
        myPrintError("EST_getKeyFromPkcs7EnvelopeData::DIGI_MEMCPY::status: ", status);
        goto exit;
    }
    /* Get the iv value */
    pIvItemPtr = ASN1_NEXT_SIBLING(pObjItemPtr);
    if (pIvItemPtr == NULL)
    {
        status = ERR_PKCS7_INVALID_STRUCT;
        goto exit;
    }
    totalLen = pIvItemPtr->length;
    pBuffer = CS_memaccess(cStream, (pIvItemPtr->dataOffset), totalLen);

    if (OK > (status = DIGI_MALLOC((void**)&pIv, totalLen)))
    {
        myPrintError("EST_getKeyFromPkcs7EnvelopeData::DIGI_MALLOC::status: ", status);
        goto exit;
    }
    if (OK > (status = DIGI_MEMSET(pIv, 0x00, totalLen)))
    {
        myPrintError("EST_getKeyFromPkcs7EnvelopeData::DIGI_MEMSET::status: ", status);
        goto exit;
    }
    if (OK > (status = DIGI_MEMCPY(pIv, pBuffer, totalLen)))
    {
        myPrintError("EST_getKeyFromPkcs7EnvelopeData::DIGI_MEMCPY::status: ", status);
        goto exit;
    }
    ivLen = totalLen;
    /* Get the encrypted data */
    pEncryptedDataItemPtr = ASN1_NEXT_SIBLING(pChildTag);
    if (pEncryptedDataItemPtr == NULL)
    {
        status = ERR_PKCS7_INVALID_STRUCT;
        goto exit;
    }
    pEncryptedDataItemPtr = ASN1_FIRST_CHILD(pEncryptedDataItemPtr);
    if (pEncryptedDataItemPtr == NULL)
        goto exit;
    totalLen = pEncryptedDataItemPtr->length;
    pBuffer = CS_memaccess(cStream, (pEncryptedDataItemPtr->dataOffset), totalLen);
    if (OK > (status = DIGI_MALLOC((void**)&pEncryptedData, totalLen)))
    {
        myPrintError("EST_getKeyFromPkcs7EnvelopeData::DIGI_MALLOC::status: ", status);
        goto exit;
    }
    if (OK > (status = DIGI_MEMSET(pEncryptedData, 0x00, totalLen)))
    {
        myPrintError("EST_getKeyFromPkcs7EnvelopeData::DIGI_MEMSET::status: ", status);
        goto exit;
    }
    if (OK > (status = DIGI_MEMCPY(pEncryptedData, pBuffer, totalLen)))
    {
        myPrintError("EST_getKeyFromPkcs7EnvelopeData::DIGI_MEMCPY::status: ", status);
        goto exit;
    }
    encryptedDataLen = totalLen;
    /* Do Decryption of CMS signed data */
    if (OK > (status = EST_decryptCipherData(MOC_SYM(hwAccelCtx) pCertStore, NULL, 0, algId, pIv, ivLen, pEncryptedData, encryptedDataLen,
                                                       pKeyAlias, keyAliasLen, pOid, oidLen,
                                                       &pDecryptedData, &decryptedDataLen)))
    {
        myPrintError("EST_getKeyFromPkcs7EnvelopeData::EST_decryptCipherData::status: ", status);
        goto exit;
    }

    if (NULL == pDecryptedData)
    {
	status = ERR_CRYPTO_FAILURE;
        myPrintError("EST_handleFullcmcEnrollResponse::EST_decryptCipherData::status ", status);
	goto exit;
    }

    /* Get the keyblob from the CMS Stream */
    if (OK > (status = EST_getKeyFromCmsStream(pCertStore, pDecryptedData, decryptedDataLen, &pKeyBlob, &keyBlobLen)))
    {
        myPrintError("EST_getKeyFromPkcs7EnvelopeData::EST_getKeyFromCmsStream::status: ", status);
        goto exit;
    }
    /* Serialize the key to pem format */
    if (pKeyBlob != NULL)
    {
        if (OK > (status = CRYPTO_initAsymmetricKey (&asymKey)))
        {
            myPrintError("EST_getKeyFromPkcs7EnvelopeData::CRYPTO_initAsymmetricKey::status: ", status);
            goto exit;
        }

       status = CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx)
            pKeyBlob, keyBlobLen, NULL, &asymKey);
        if (OK != status)
        {
            myPrintError("EST_getKeyFromPkcs7EnvelopeData::CRYPTO_deserializeAsymKey::status: ", status);
            goto exit;
        }

        status = CRYPTO_serializeAsymKey(MOC_ASYM(hwAccelCtx)
            &asymKey, privateKeyPem, ppPemKeyBlob, pPemKeyBlobLen);
        if (OK != status)
        {
            myPrintError("EST_getKeyFromPkcs7EnvelopeData::CRYPTO_serializeAsymKey::status: ", status);
            goto exit;
        }
    }

exit:

    if (pEnvelopDataRoot)
    {
        TREE_DeleteTreeItem((TreeItem*)pEnvelopDataRoot);
    }
    if (pEncryptedData != NULL)
        DIGI_FREE((void**)&pEncryptedData);
    if (pDecryptedData != NULL)
        DIGI_FREE((void**)&pDecryptedData);
    if (pDecodedData != NULL)
        FREE(pDecodedData);
    if (pKeyAlias != NULL)
        DIGI_FREE((void**)&pKeyAlias);
    if (pOid != NULL)
        DIGI_FREE((void**)&pOid);
    if (pIv != NULL)
        DIGI_FREE((void**)&pIv);
    if (pKeyBlob != NULL)
    {
        CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
        DIGI_FREE((void**)&pKeyBlob);
    }
    return status;
}

static MSTATUS
EST_getPemPrivateKey(ubyte *pKeyBlob, ubyte4 keyBlobLen, ubyte **ppPemKey, ubyte4 *pPemKeyLen)
{
    ubyte   *pBase64Mesg = NULL;
    ubyte4  srcIndex    = 0;
    ubyte4  destIndex   = 0;
    MSTATUS status      = OK;

    /* alloc temp memory for base64 decode buffer */
    if (OK > (status = DIGI_MALLOC((void**)&pBase64Mesg, keyBlobLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* strip our line feeds and comments lines from base64 text  */
    while (keyBlobLen > srcIndex)
    {
        if (OK > (status = EST_fetchLine(pKeyBlob, &srcIndex, keyBlobLen, pBase64Mesg, &destIndex)))
        {
            myPrintError("EST_getPemPrivateKey::EST_fetchLine::status: ", status);
            goto exit;
        }
    }

    if (OK > (status = EST_breakIntoLinesPKCS7(pBase64Mesg, destIndex,
                    ppPemKey, pPemKeyLen,
                    (const ubyte*)BEGIN_PRIVATEKEY_BLOCK, (const ubyte*)END_PRIVATEKEY_BLOCK)))
    {
        myPrintError("EST_getPemPrivateKey::EST_breakIntoLinesPKCS7::status: ", status);
        goto exit;
    }

exit:
    if (NULL != pBase64Mesg)
        DIGI_FREE((void**)&pBase64Mesg);
    return status;
}

#ifdef __ENABLE_DIGICERT_TAP__

static MSTATUS
EST_getEncryptedContentFromEnvelopData(ASN1_ITEM *pEnvelopRootItem, CStream envelopStream, ubyte **ppOut, ubyte4 *pOutLen)
{
    MSTATUS status = OK;
    ASN1_ITEM *pEncryptedCertItem = NULL;
    ubyte *pTemp = NULL;
    static WalkerStep walkInstructions[] =
    {
        { GoFirstChild, 0, 0},
        { VerifyOID, 0, (ubyte*)pkcs7_envelopedData_OID},
        { GoNextSibling, 0, 0},
        { VerifyTag, 0, 0},
        { GoFirstChild, 0, 0},
        { VerifyType, SEQUENCE, 0},
        { GoNthChild, 3, 0},
        { VerifyType, SEQUENCE, 0},
        { GoNthChild, 3, 0},
        { VerifyTag, 0, 0},
        { Complete, 0, 0}
    };
    /* Get the encrypted certificate */
    if (OK != (status = ASN1_WalkTree(pEnvelopRootItem, envelopStream, walkInstructions, &pEncryptedCertItem)))
    {
        goto exit;
    }
    if (OK != (status = DIGI_CALLOC((void**)ppOut, 1, pEncryptedCertItem->length)))
    {
        goto exit;
    }
    pTemp = (ubyte*)CS_memaccess(envelopStream, pEncryptedCertItem->dataOffset, pEncryptedCertItem->length);
    if (OK != (status = DIGI_MEMCPY((ubyte*)*ppOut, pTemp, pEncryptedCertItem->length)))
    {
        goto exit;
    }
    *pOutLen = pEncryptedCertItem->length;


exit:
    if (pEnvelopRootItem)
    {
        TREE_DeleteTreeItem((TreeItem*)pEnvelopRootItem);
    }
    return status;
}

static MSTATUS
EST_getAlgIdIvAndEncryptedKey(ASN1_ITEM *pEnvelopRootItem, CStream envelopStream, ubyte **ppEncryptedSymKey, ubyte4 *pEncryptedSymKeyLen, ubyte **ppOid, ubyte4 *pOidLen, ubyte **ppIv, ubyte4 *pIvLen)
{
    MSTATUS status = OK;
    ASN1_ITEM *pEncryptedKeyItem = NULL;
    ASN1_ITEM *pAlgorithmIdItem = NULL;
    ubyte *pTemp = NULL;
    static WalkerStep encryptedKeyWalkInstructions[] =
    {
        { GoFirstChild, 0, 0},
        { VerifyOID, 0, (ubyte*)pkcs7_envelopedData_OID},
        { GoNextSibling, 0, 0},
        { VerifyTag, 0, 0},
        { GoFirstChild, 0, 0},
        { VerifyType, SEQUENCE, 0},
        { GoNthChild, 2, 0},
        { VerifyType, MOC_SET, 0},
        { GoFirstChild, 0, 0},
        { VerifyTag, 2, 0},
        { GoNthChild, 4, 0},
        { Complete, 0, 0}
    };

    static WalkerStep algIdWalkInstructions[] =
    {
        { GoFirstChild, 0, 0},
        { VerifyOID, 0, (ubyte*)pkcs7_envelopedData_OID},
        { GoNextSibling, 0, 0},
        { VerifyTag, 0, 0},
        { GoFirstChild, 0, 0},
        { VerifyType, SEQUENCE, 0},
        { GoNthChild, 3, 0},
        { VerifyType, SEQUENCE, 0},
        { GoNthChild, 2, 0},
        { VerifyType, SEQUENCE, 0},
        { Complete, 0, 0}
    };
    ASN1_ITEM *pChild = NULL;

    /* Get the encrypted symmetric key */
    if (OK != (status = ASN1_WalkTree(pEnvelopRootItem, envelopStream, encryptedKeyWalkInstructions, &pEncryptedKeyItem)))
    {
        goto exit;
    }
    if (OK != (status = DIGI_CALLOC((void**)ppEncryptedSymKey, 1, pEncryptedKeyItem->length)))
    {
        goto exit;
    }
    pTemp = (ubyte*)CS_memaccess(envelopStream, pEncryptedKeyItem->dataOffset, pEncryptedKeyItem->length);
    if (OK != (status = DIGI_MEMCPY((ubyte*)*ppEncryptedSymKey, pTemp, pEncryptedKeyItem->length)))
    {
        goto exit;
    }
    *pEncryptedSymKeyLen = pEncryptedKeyItem->length;

    /* Get the Symmetric Algorithm id */
    if (OK != (status = ASN1_WalkTree(pEnvelopRootItem, envelopStream, algIdWalkInstructions, &pAlgorithmIdItem)))
    {
        goto exit;
    }
    pChild = ASN1_FIRST_CHILD(pAlgorithmIdItem);
    if (OK != (status = DIGI_CALLOC((void**)ppOid, 1, pChild->length+1)))
    {
        goto exit;
    }
    pTemp = (ubyte*)CS_memaccess(envelopStream, pChild->dataOffset-1, pChild->length+1);
    if (OK != (status = DIGI_MEMCPY((ubyte*)*ppOid, pTemp, pChild->length+1)))
    {
        goto exit;
    }
    *pOidLen = pChild->length+1;

    /* Get the iv */
    pChild = ASN1_NEXT_SIBLING(pChild);
    if (OK != (status = DIGI_CALLOC((void**)ppIv, 1, pChild->length)))
    {
        goto exit;
    }
    pTemp = (ubyte*)CS_memaccess(envelopStream, pChild->dataOffset, pChild->length);
    if (OK != (status = DIGI_MEMCPY((ubyte*)*ppIv, pTemp, pChild->length)))
    {
        goto exit;
    }
    *pIvLen = pChild->length;


exit:
    if (pEnvelopRootItem)
    {
        TREE_DeleteTreeItem((TreeItem*)pEnvelopRootItem);
    }
    return status;
}


MSTATUS
EST_handleFullcmcEnrollResponse(MOC_HW(hwAccelDescr hwAccelCtx) AsymmetricKey *pAsymKey, ubyte *pHttpResp, ubyte4 httpRespLen, ubyte *pContentType, ubyte4 contentTypeLen, struct SizedBuffer  **pPCertificates, ubyte4 *pNumCerts)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    ubyte *pResponse = NULL;
    ubyte4 responseLen = 0;
    ASN1_ITEMPTR  pCertRepSignedRoot = NULL;
    MemFile         certRepMemFile;
    CStream         certRepStream;
    ASN1_ITEMPTR pPKIResponseItem = NULL;
    byteBoolean attestFlow = TRUE;
    ASN1_ITEMPTR *pEnvelopDataItems = NULL;
    ubyte4 numEnvelopData = 0;
    TAP_Key *pRotKey = NULL;
    TAP_KeyInfo rootKeyInfo = {0};
    TAP_ErrorContext errContext;
    TAP_ErrorContext *pErrContext = &errContext;
    ubyte *pEncryptedSymKey = NULL;
    ubyte4 encryptedSymKeyLen = 0;
    ubyte *pAlgOid = NULL;
    ubyte4 algOidLen = 0;
    ubyte *pIv = NULL;
    ubyte4 ivLen = 0;
    TAP_Key *pTapKey = NULL;
    TAP_Blob blob = {0};
    TAP_Buffer symKey = {0};
    ubyte4 *pBodyPartsList = NULL;
    ubyte4 numBodyParts = 0;
    ubyte *pOid = NULL;
    TAP_Context *pTapContext = NULL;
    TAP_EntityCredentialList *pTapEntityCredentials = NULL;
    TAP_CredentialList *pKeyCreds = NULL;

    /*
       Check if its Attestation flow
       1. Parse the CMC Signed data to get the pki response.
       2. From the pki response, Check the control sequence to check if some data is present in controlsequence.
       3. if control sequence points about some data. then go to the cmssequence and get the envelop data.
       4. From the envelopdata Get the encrypted certficate
       5. Parse the KEKRecipientInfo to get the decryptkeyid, encrypted symmetric key.
       6  Decrypt the encrypted symmetric key using unwrapValiditySecret APi.
       7. Use the decrypted symmetric key to decrypt the encrypted certficate.
       If not Attestation flow call EST_receiveResponse API.
     */
    if ( (NULL == pHttpResp) || (NULL == pContentType) ||
        (NULL == pPCertificates) || (NULL == pNumCerts))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = EST_getResponse(pContentType, contentTypeLen, pHttpResp, httpRespLen,
                    &pResponse, &responseLen)))
    {
        myPrintError("EST_handleFullcmcEnrollResponse::EST_getResponse::status: ", status);
        goto exit;
    }
    if (pResponse != NULL)
    {
        ubyte4 i = 0;

        MF_attach(&certRepMemFile, responseLen, (ubyte*)pResponse );
        CS_AttachMemFile(&certRepStream, &certRepMemFile );
        if (OK > (status = ASN1_Parse( certRepStream, &pCertRepSignedRoot)))
        {
            myPrintError("EST_handleFullcmcEnrollResponse::ASN1_Parse::status: ", status);
            goto exit;
        }

        if (OK != (status = CMC_getPKIResponse(pCertRepSignedRoot, certRepStream, &pPKIResponseItem)))
        {
            myPrintError("EST_handleFullcmcEnrollResponse::CMC_getPKIResponse::status: ", status);
            goto exit;
        }

        /* Verify Attestation req type Ex: TPM2-ATTEST */
        if (OK != (status = CMC_verifyAttestationReqType(pPKIResponseItem, certRepStream, &attestFlow, &pOid)))
        {
            myPrintError("EST_handleFullcmcEnrollResponse::EST_verifyAttestationReqType::status: ", status);
            goto exit;
        }

        if (FALSE == attestFlow)
        {
            if (OK != (status = EST_receiveResponse(pContentType, contentTypeLen, pResponse, responseLen,
                            pAsymKey, pPCertificates, pNumCerts )))
            {
                myPrintError("EST_handleFullcmcEnrollResponse::EST_receiveResponse::status: ", status);
                goto exit;
            }
        }
        else
        {
            /* Attestation flow */
            if (OK != (status = CMC_processControlSequence(pPKIResponseItem, certRepStream, (ubyte *) batchResponses_oid,
                                            &pBodyPartsList, &numBodyParts)))
            {
                myPrintError("EST_handleFullcmcEnrollResponse::EST_processControlSequence::status: ", status);
                goto exit;
            }

            if ((pBodyPartsList == NULL) || (numBodyParts == 0))
            {
                status = ERR_EST_BAD_MESSAGE;
                goto exit;
            }

            if (OK != (status = CMC_processCmsSequence(pPKIResponseItem, certRepStream,
                                           pBodyPartsList, numBodyParts, TRUE,
                                           &pEnvelopDataItems, &numEnvelopData)))
            {
                myPrintError("EST_handleFullcmcEnrollResponse::EST_processCmsSequence::status: ", status);
                goto exit;
            }
            if ((pEnvelopDataItems == NULL) || (0 == numEnvelopData))
            {
                status = ERR_EST_BAD_MESSAGE;
                goto exit;
            }

            /* Get the keyIdentifier(Sym/Asym), AlgorithmId and encrypted Symmetric from the first list of envelop data
               Since all the list contains the same KEKRecipient information*/
            if (OK != (status = EST_getAlgIdIvAndEncryptedKey(pEnvelopDataItems[0], certRepStream,
                                               &pEncryptedSymKey, &encryptedSymKeyLen,
                                               &pAlgOid, &algOidLen,
                                               &pIv, &ivLen)))
            {
                myPrintError("EST_handleFullcmcEnrollResponse::EST_getAlgIdIvAndEncryptedKey::status: ", status);
                goto exit;
            }

            /* Get the symmetric key using this TAP_unwrapKeyValidatedSecret */
            status = CRYPTO_INTERFACE_getTapKey(pAsymKey, &pTapKey);
            if (OK != status)
                goto exit;

            blob.format = TAP_BLOB_FORMAT_MOCANA;
            blob.encoding = TAP_BLOB_ENCODING_BASE64;
            blob.blob.pBuffer = pEncryptedSymKey;
            blob.blob.bufferLen = encryptedSymKeyLen;

#ifdef __ENABLE_DIGICERT_TPM2__
            if (EqualOID(pOid, mocana_attest_tpm2_oid))
                rootKeyInfo.objectId = (TAP_ID)EK_OBJECT_ID;
#endif
            if (NULL != g_pGetTapContext)
            {
                g_pGetTapContext(&pTapContext, &pTapEntityCredentials, &pKeyCreds, 1/*get context */);
            }

#ifdef __ENABLE_DIGICERT_TPM2__
            if (OK != (status = TAP_getRootOfTrustKey(pTapContext, &rootKeyInfo, TAP_ROOT_OF_TRUST_TYPE_UNKNOWN, &pRotKey, pErrContext)))
            {
                myPrintError("EST_handleFullcmcEnrollResponse::TAP_getRootOfTrustKey::status ", status);
                goto exit;
            }
#endif
            if (OK != (status = TAP_loadKey(pTapContext, pTapEntityCredentials, pTapKey, pKeyCreds, NULL, pErrContext)))
            {
                myPrintError("EST_handleFullcmcEnrollResponse::TAP_loadKey::status ", status);
                goto exit;
            }

            if (OK != (status = TAP_unwrapKeyValidatedSecret(pTapContext, pTapEntityCredentials, pTapKey, pRotKey, &blob, &symKey, pErrContext)))
            {
                myPrintError("EST_handleFullcmcEnrollResponse::TAP_unwrapKeyValidatedSecret::status ", status);
                goto exit;
            }

            if (OK > (status = TAP_unloadKey(pTapKey, pErrContext)))
            {
                myPrintError("EST_handleFullcmcEnrollResponse::TAP_unloadKey::status ", status);
                goto exit;
            }

            if (OK > (status = DIGI_CALLOC((void**)pPCertificates, numEnvelopData, sizeof(struct SizedBuffer))))
            {
                myPrintError("EST_handleFullcmcEnrollResponse::DIGI_CALLOC::status: ", status);
                goto exit;
            }
            *pNumCerts = numEnvelopData;

            /* Get the list of encrypted certificates from envelop data and decrypt them using above symmetric key.*/
            for(i = 0; i < numEnvelopData; i++)
            {
                ubyte *pDecryptedCertData = NULL;
                ubyte4 decryptedCertDataLen = 0;
                ubyte *pEncryptedCertData = NULL;
                ubyte4 encryptedCertDataLen = 0;
                ubyte *pEncodedCert = NULL;
                ubyte4 encodedCertLen = 0;
                ubyte *pFinalOut = NULL;
                ubyte4 finalOutLen = 0;

                if (OK > (status = EST_getEncryptedContentFromEnvelopData(pEnvelopDataItems[i], certRepStream,
                                                   &pEncryptedCertData, &encryptedCertDataLen)))
                {
                    myPrintError("EST_handleFullcmcEnrollResponse::EST_getEncryptedContentFromEnvelopData::status ", status);
                    goto exit;
                }

                if (OK > (status = EST_decryptCipherData(MOC_SYM(hwAccelCtx) NULL, symKey.pBuffer,
                                symKey.bufferLen, pAlgOid, pIv, ivLen, pEncryptedCertData, encryptedCertDataLen,
                                NULL, 0, NULL, 0,
                                &pDecryptedCertData, &decryptedCertDataLen)))
                {
                    myPrintError("EST_handleFullcmcEnrollResponse::EST_decryptCipherData::status ", status);
                    goto exit;
                }

                if (NULL == pDecryptedCertData)
                {
                    status = ERR_CRYPTO_FAILURE;
                    myPrintError("EST_handleFullcmcEnrollResponse::EST_decryptCipherData::status ", status);
                    goto exit;
                }

                if (OK > (status = BASE64_encodeMessage(pDecryptedCertData, decryptedCertDataLen,
                                         &pEncodedCert, &encodedCertLen)))
                {
                    myPrintError("EST_handleFullcmcEnrollResponse::BASE64_encodeMessage::status ", status);
                    goto exit;
                }

                if (OK > (status = EST_breakIntoLinesPKCS7(pEncodedCert, encodedCertLen,
                                &pFinalOut, &finalOutLen, (const ubyte*)BEGIN_CERTIFICATE_BLOCK, (const ubyte*)END_CERTIFICATE_BLOCK)))
                {
                    myPrintError("EST_handleFullcmcEnrollResponse::EST_breakIntoLinesPKCS7::status ", status);
                    goto exit;
                }

                (*pPCertificates)[i].length = finalOutLen;
                (*pPCertificates)[i].data = pFinalOut;

                DIGI_FREE((void**)&pEncryptedCertData);
                DIGI_FREE((void**)&pDecryptedCertData);
                DIGI_FREE((void**)&pEncodedCert);
            }
        }
    }

exit:

    if (pCertRepSignedRoot)
    {
        TREE_DeleteTreeItem((TreeItem*)pCertRepSignedRoot);
    }
    if (numBodyParts > 0)
    {
        DIGI_FREE((void**)&pBodyPartsList);
    }
    if (NULL != g_pGetTapContext)
    {
        g_pGetTapContext(&pTapContext, &pTapEntityCredentials, &pKeyCreds, 0/*release Context */);
    }
    if (numEnvelopData > 0)
    {
        DIGI_FREE((void**)&pEnvelopDataItems);
    }
    DIGI_FREE((void**)&pEncryptedSymKey);
    DIGI_FREE((void**)&pAlgOid);
    DIGI_FREE((void**)&pIv);
    DIGI_FREE((void**)&pResponse);
    if (NULL != pRotKey)
    {
        if (OK != (exitStatus = TAP_unloadKey(pRotKey, pErrContext)))
        {
            myPrintError("EST_handleFullcmcEnrollResponse::TAP_unloadKey::status ", exitStatus);
        }
        TAP_freeKey(&pRotKey);
    }
    TAP_UTILS_freeBuffer(&symKey);
    DIGI_FREE((void**)&pOid);

    return status;
}
#endif

typedef struct
{
    ubyte **ppKey;
    ubyte4 *pKeyLength;
    ubyte **ppKeyContentType;
    ubyte4 *pKeyContentTypeLen;
    ubyte **ppPkcs7Cert;
    ubyte4 *pPkcs7CertLen;
    ubyte **ppCertContentType;
    ubyte4 *pCertContentTypeLen;
} EstServerKeygenMimePartArg;

static MSTATUS EST_processServerKeygenMimePart(
    MimePart *pPart,
    MimePartProcessArg *pArg)
{
    MSTATUS status = OK;
    EstServerKeygenMimePartArg *pSKGArg = (EstServerKeygenMimePartArg *)pArg;
    sbyte4 len;
    ubyte *pSanitizedData = NULL;
    ubyte4 sanitizedDataLen = 0;

    if (MIME_CONTENT_TYPE_PKCS8 == pPart->contentType)
    {
        /* PKCS#8 server generated private key */
        if (pPart->pData[0] != '-')
        {
            /* Add PKCS#8 header */
            status = CA_MGMT_decodeCertificate(
                pPart->pData, pPart->dataLen,
                &pSanitizedData, &sanitizedDataLen);
            if (OK != status)
            {
                myPrintError("EST_processServerKeygenMimePart::CA_MGMT_decodeCertificate::status: ", status);
                goto exit;
            }

            status = BASE64_makePemMessageAlloc(
                MOC_PEM_TYPE_PRI_KEY,
                pSanitizedData, sanitizedDataLen,
                pSKGArg->ppKey, pSKGArg->pKeyLength);
            if (OK != status)
            {
                myPrintError("EST_processServerKeygenMimePart::BASE64_makePemMessageAlloc::status: ", status);
                goto exit;
            }
        }
        else
        {
            status = DIGI_MALLOC_MEMCPY(
                (void **) pSKGArg->ppKey, pPart->dataLen,
                pPart->pData, pPart->dataLen);
            if (OK != status)
            {
                myPrintError("EST_processServerKeygenMimePart::DIGI_MALLOC_MEMCPY::status: ", status);
                goto exit;
            }
            *pSKGArg->pKeyLength = pPart->dataLen;
        }

        len = DIGI_STRLEN(MIME_CONTENT_TYPE_PKCS8_STR);
        status = DIGI_MALLOC_MEMCPY(
            (void **)pSKGArg->ppKeyContentType, len + 1,
            MIME_CONTENT_TYPE_PKCS8_STR, len);
        if (OK != status)
        {
            myPrintError("EST_processServerKeygenMimePart::DIGI_MALLOC_MEMCPY::status: ", status);
            goto exit;
        }
        (*pSKGArg->ppKeyContentType)[len] = '\0';
        *pSKGArg->pKeyContentTypeLen = len;
    }
    else if (MIME_CONTENT_TYPE_PKCS7_MIME == pPart->contentType)
    {
        /* degenerate PKCS#7 response containing issued certificate */
        status = DIGI_MALLOC_MEMCPY(
            (void **)pSKGArg->ppPkcs7Cert, pPart->dataLen,
            pPart->pData, pPart->dataLen);
        if (OK != status)
        {
            myPrintError("EST_processServerKeygenMimePart::DIGI_MALLOC_MEMCPY::status: ", status);
            goto exit;
        }
        *pSKGArg->pPkcs7CertLen = pPart->dataLen;

        len = DIGI_STRLEN(MIME_CONTENT_TYPE_PKCS7_MIME_STR);
        status = DIGI_MALLOC_MEMCPY(
            (void **)pSKGArg->ppCertContentType, len + 1,
            MIME_CONTENT_TYPE_PKCS7_MIME_STR, len);
        if (OK != status)
        {
            myPrintError("EST_processServerKeygenMimePart::DIGI_MALLOC_MEMCPY::status: ", status);
            goto exit;
        }
        (*pSKGArg->ppCertContentType)[len] = '\0';
        *pSKGArg->pCertContentTypeLen = len;
    }

exit:

    DIGI_FREE((void **) &pSanitizedData);

    return status;
}

/**
@brief   This API parses the multi-part content.

@details This APi parses the multi-part response and returns the
          certificates data, key data and their corresponding content types.
          <p> As per RFC 7030, the response content type from a serverkeygen response
          would be multipart/mixed. The response contains the key and
          enrolled certificate separated with a boundary.

@param pResponse              Pointer to the Multi-part response content.
@param responseLen            Length of the Multi-part response.
@param pContentType           Pointer to the content type.
@param contentTypeLen         Length of the content type.
@param pPKey                  On return, Double pointer to the key blob.
@param pKeyLength             On return, Pointer to the keyblob length.
@param pPkeyContentType       On return, Double pointer to the content type of the key.
@param pKeyContentTypeLen     On return, Pointer to key content type length.
@param pPPkcs7Cert            On return, Double pointer to the PKCS7 data.
@param pPPkcs7CertLen         On return, Pointer to length of the PKCS7 data.
@param pPCertContentType      On return, Double pointer to the PKCS7 content type.
@param pCertContentTypeLen    On return, Pointer to PKCS7 content type length.
@param isPendingRetry         Indicates if the scenario is pending retry.
@param httpStatusCode         Http response status associated with the httpContext in the response.

@inc_file   est_client_api.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.c
*/
MSTATUS
EST_filterMultiPartContent(ubyte *pResponse, ubyte4 responseLen, ubyte *pContentType, ubyte4 contentTypeLen, ubyte **pPKey, ubyte4 *pKeyLength, ubyte **pPKeyContentType, ubyte4 *pKeyContentTypeLen, ubyte **pPPkcs7Cert, ubyte4 *pPkcs7CertLen,
        ubyte **pPCertContentType, ubyte4 *pCertContentTypeLen, byteBoolean isPendingRetry, ubyte4 httpStatusCode)
{
    MSTATUS status = OK;
    MimePayload payloadData = { 0 };
    EstServerKeygenMimePartArg mimePartArg = { 0 };
    sbyte *pBoundary = NULL;

    if (TRUE == isPendingRetry)
    {
        if (202 == httpStatusCode)
        {
            /* Expect only key in this case.*/
            if ((pResponse == NULL) || (pContentType == NULL) || (pPKey == NULL) || (pKeyLength == NULL) ||
                    (pPKeyContentType == NULL) || (pKeyContentTypeLen == NULL))
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }
        }
        else if (200 == httpStatusCode)
        {
            /*Expect only certificate in this case */
            if ((pResponse == NULL) || (pContentType == NULL) || (pPPkcs7Cert == NULL) ||
                (pPkcs7CertLen == NULL) || (pPCertContentType == NULL) ||
                (pCertContentTypeLen == NULL))
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }
        }
    }
    else
    {
        if ((pResponse == NULL) || (pContentType == NULL) || (pPKey == NULL) || (pKeyLength == NULL) ||
                (pPKeyContentType == NULL) || (pKeyContentTypeLen == NULL) ||
                (pPPkcs7Cert == NULL) || (pPkcs7CertLen == NULL) || (pPCertContentType == NULL) ||
                (pCertContentTypeLen == NULL))
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }
    }

    status = MIME_getBoundaryFromLine(pContentType, contentTypeLen, &pBoundary);
    if (OK != status)
    {
        myPrintError("EST_filterMultiPartContent::MIME_getBoundaryFromLine::status: ", status);
        goto exit;
    }

    /* Set up mime payload to parse */
    payloadData.pPayLoad = pResponse;
    payloadData.payloadLen = responseLen;

    /* Set up output arguments */
    mimePartArg.ppKey = pPKey;
    mimePartArg.pKeyLength = pKeyLength;
    mimePartArg.ppKeyContentType = pPKeyContentType;
    mimePartArg.pKeyContentTypeLen = pKeyContentTypeLen;
    mimePartArg.ppPkcs7Cert = pPPkcs7Cert;
    mimePartArg.pPkcs7CertLen = pPkcs7CertLen;
    mimePartArg.ppCertContentType = pPCertContentType;
    mimePartArg.pCertContentTypeLen = pCertContentTypeLen;

    status = MIME_processBody(
        &payloadData, pBoundary, EST_processServerKeygenMimePart, &mimePartArg);
    if (OK != status)
    {
        myPrintError("EST_filterMultiPartContent::MIME_processBody::status: ", status);
        goto exit;
    }

exit:

    DIGI_FREE((void**) &pBoundary);

    return status;
}

/**
@brief    Removes the pkcs7 banner.

@details  This function filters the pkcs7 banner.

@param pQuery          Pointer to the input from which the baner to be removed.
@param queryLen        Length of the input.
@param ppRetPkcs7      On return, Double pointer to the filtered reponse.
@param pRetPkcs7Len    On return, Pointer to the length of filtered response.
@param pArmorDetected  On return, Pointer to the armour detected.
                       \c TRUE if banner detected; \c FALSE otherwise.

@inc_file   est_client_api.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.c
*/
MSTATUS
EST_filterPkcs7Banner(ubyte *pQuery, ubyte4 queryLen, ubyte **ppRetPkcs7,
        ubyte4 *p_retPkcs7Length, byteBoolean *p_armorDetected)
{
    ubyte *pPkcs7 = NULL;
    ubyte4  pkcs7Len = 0;
    sbyte *pBeginBlock = NULL;
    sbyte *pBeginCertBlock = NULL;
    sbyte *pBeginPkcs7NewlineBlock = NULL;
    MSTATUS status = OK;


    *p_armorDetected = FALSE;
    if (NULL == (pBeginBlock = MALLOC(sizeof(BEGIN_PKCS7_BLOCK) + 1)))
    {
       status = ERR_MEM_ALLOC_FAIL;
       goto exit;
    }
    DIGI_MEMSET((ubyte*)pBeginBlock, 0x00, sizeof(BEGIN_PKCS7_BLOCK) + 1);
    DIGI_STRCBCPY(pBeginBlock, sizeof(BEGIN_PKCS7_BLOCK), (const sbyte *)pQuery);

    if (NULL == (pBeginPkcs7NewlineBlock = MALLOC(sizeof(BEGIN_PKCS7_BLOCK_NEWLINE) + 1)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMSET((ubyte*)pBeginPkcs7NewlineBlock, 0x00, sizeof(BEGIN_PKCS7_BLOCK_NEWLINE) + 1);
    DIGI_STRCBCPY(pBeginPkcs7NewlineBlock, sizeof(BEGIN_PKCS7_BLOCK_NEWLINE), (const sbyte *)pQuery);


    if (NULL == (pBeginCertBlock = MALLOC(sizeof(BEGIN_CERTIFICATE_BLOCK) + 1)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMSET((ubyte*)pBeginCertBlock, 0x00, sizeof(BEGIN_CERTIFICATE_BLOCK) + 1);
    DIGI_STRCBCPY(pBeginCertBlock, sizeof(BEGIN_CERTIFICATE_BLOCK), (const sbyte *)pQuery) ;


    if(0 == DIGI_STRCMP((const sbyte*)pBeginBlock, (const sbyte*)BEGIN_PKCS7_BLOCK))
    {
        pkcs7Len = queryLen - (sizeof(BEGIN_PKCS7_BLOCK) - 1) - (sizeof(END_PKCS7_BLOCK) - 1);
        if (NULL == (pPkcs7 = MALLOC(queryLen)))
        {
            status =  ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        DIGI_MEMSET((ubyte*)pPkcs7, 0x00, queryLen);

        pQuery = pQuery + sizeof(BEGIN_PKCS7_BLOCK) - 1;
        DIGI_MEMCPY(pPkcs7, pQuery, pkcs7Len);
        *ppRetPkcs7 = pPkcs7;
        *p_retPkcs7Length = pkcs7Len;
        *p_armorDetected = TRUE;
    }
    else if(0 == DIGI_STRCMP((const sbyte*)pBeginPkcs7NewlineBlock, (const sbyte*)BEGIN_PKCS7_BLOCK_NEWLINE))
    {
        pkcs7Len = queryLen - (sizeof(BEGIN_PKCS7_BLOCK_NEWLINE) - 1) - (sizeof(END_PKCS7_BLOCK_NEWLINE) - 1);
        if (NULL == (pPkcs7 = MALLOC(queryLen)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        DIGI_MEMSET((ubyte*)pPkcs7, 0x00, queryLen);

        pQuery = pQuery + sizeof(BEGIN_PKCS7_BLOCK_NEWLINE) - 1;
        DIGI_MEMCPY(pPkcs7, pQuery, pkcs7Len);
        *ppRetPkcs7 = pPkcs7;
        *p_retPkcs7Length = pkcs7Len;
        *p_armorDetected = TRUE;
    }
    else if(0 == DIGI_STRCMP((const sbyte*)pBeginCertBlock, (const sbyte*)BEGIN_CERTIFICATE_BLOCK))
    {
        pkcs7Len = queryLen - (sizeof(BEGIN_CERTIFICATE_BLOCK) - 1) - (sizeof(END_CERTIFICATE_BLOCK) - 1);
        if (NULL == (pPkcs7 = MALLOC(queryLen)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        DIGI_MEMSET((ubyte*)pPkcs7, 0x00, queryLen);

        pQuery = pQuery + sizeof(BEGIN_CERTIFICATE_BLOCK) - 1;
        DIGI_MEMCPY(pPkcs7, pQuery, pkcs7Len);
        *ppRetPkcs7 = pPkcs7;
        *p_retPkcs7Length = pkcs7Len;
        *p_armorDetected = TRUE;
    }
    else
    {
        *ppRetPkcs7 = pQuery;
        *p_retPkcs7Length = queryLen;
    }

exit:
    if (pBeginBlock)
    {
        FREE(pBeginBlock);
    }
    if (pBeginCertBlock)
    {
        FREE(pBeginCertBlock);
    }
    if(pBeginPkcs7NewlineBlock)
    {
        FREE(pBeginPkcs7NewlineBlock);
    }
    return status;
}

/**
@brief      This API filters the new line and feed characters.

@details    This function filters the new line and feed characters.

@param pOrigMsg       Pointer to response received from the Server.
                      updated response would be updated to the same buffer.
@param origLen        Response length.
@param pFilteredLen   On return, Pointer to new length.

@inc_file   est_client_api.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.c
*/
MSTATUS
EST_filterPkcs7Message(ubyte *pOrigMsg, ubyte4 origLen, ubyte4 *pFilteredLen)
{
    *pFilteredLen = EST_UTILS_filterPkcs7Message(pOrigMsg, origLen);

    if (*pFilteredLen == 0)
        return ERR_PKCS7_INVALID_STRUCT;

    return OK;
}

static
MSTATUS EST_getResponse(ubyte *pContentType, ubyte4 contentTypeLen, ubyte *pHttpResp, ubyte4 httpRespLen, ubyte **pPResponse, ubyte4 *pRespLen)
{
    MSTATUS status = OK;
    ubyte4 type, subType;

    for (type = 0; type < NUM_EST_MEDIA_TYPES; type++)
    {
        /* Check for the media type */
        if ( (mEstContentTypeMediaTypes[type].nameLen == contentTypeLen) ||
             ((mEstContentTypeMediaTypes[type].nameLen < contentTypeLen) &&
              ((DIGI_ISSPACE(pContentType[mEstContentTypeMediaTypes[type].nameLen])) ||
               (pContentType[mEstContentTypeMediaTypes[type].nameLen] == EST_CONTENT_TYPE_SEPERATOR))))
        {
            /* Case insensitive match */
            if (0 == DIGI_STRNICMP((sbyte *) pContentType,(sbyte *) mEstContentTypeMediaTypes[type].name, mEstContentTypeMediaTypes[type].nameLen))
            {
                /* Found a match, move content type pointer past media type */
                pContentType += mEstContentTypeMediaTypes[type].nameLen;
                contentTypeLen -= mEstContentTypeMediaTypes[type].nameLen;
                break;
            }
        }
    }

    /* Did not find match for media type */
    if (NUM_EST_MEDIA_TYPES == type)
    {
        status = ERR_NOT_FOUND;
        myPrintError("EST_getResponse::Media Type in Content-Type Unrecognized::status ", status);
        goto exit;
    }

    /* Media type of "application/pkcs7-mime" can have parameter field set.
     * Search for optional parameter field if this media type is set. */
    if (x_pkcs7_cert == type)
    {
        while (contentTypeLen >= EST_SMIME_TYPE_LEN)
        {
            /* Case insensitive match */
            if (0 == DIGI_STRNICMP((sbyte *) pContentType, (sbyte *) EST_SMIME_TYPE, EST_SMIME_TYPE_LEN))
            {
                /* Found smime-type. Check the value */
                pContentType += EST_SMIME_TYPE_LEN;
                contentTypeLen -= EST_SMIME_TYPE_LEN;

                for (subType = 0; subType < NUM_EST_PKCS7_MIME_PARAMS; subType++)
                {
                    /* Check for the parameter value */
                    if ( (mEstContentTypePkcs7Parameter[subType].nameLen == contentTypeLen) ||
                         ((mEstContentTypePkcs7Parameter[subType].nameLen < contentTypeLen) &&
                          ((DIGI_ISSPACE(pContentType[mEstContentTypePkcs7Parameter[subType].nameLen])) ||
                           (pContentType[mEstContentTypePkcs7Parameter[subType].nameLen] == EST_CONTENT_TYPE_SEPERATOR))))
                    {
                        /* Case insensitive match */
                        if (0 == DIGI_STRNICMP((sbyte *) pContentType, (sbyte *) mEstContentTypePkcs7Parameter[subType].name, mEstContentTypePkcs7Parameter[subType].nameLen))
                        {
                            break;
                        }
                    }
                }

                if (subType == NUM_EST_PKCS7_MIME_PARAMS)
                {
                    /* Did not find match for parameter. Can't process unkonwn
                     * smime-type */
                    status = ERR_NOT_FOUND;
                    myPrintError("EST_getResponse::Parameter in Content-Type Unrecognized::status ", status);
                    goto exit;
                }
                else
                {
                    /* Found match, update type */
                    type = type + 1 + subType;
                    break;
                }
            }

            pContentType++;
            contentTypeLen--;
        }
    }

    switch (type)
    {
        case x_pkcs7_cert:
        case x_csrattrs:
        case x_pkcs7_simple_cert:
        case x_pkcs7_fullcmc_response:
        case x_pki_message:
            {
                if (OK > (status = EST_MESSAGE_parseResponse(type, pHttpResp, httpRespLen, pPResponse, pRespLen)))
                {
                    goto exit;
                }
                break;
            }
        default:
            status = ERR_EST_BAD_MESSAGE;
            myPrintError("EST_getResponse::Media type in Content-Type Unsupported::status ", status);
            break;
    }

exit:
    return status;
}



/**
@brief      This API parses pkcs7 response and returns the certificates.

@details    This function retrieves the certificates from the response.

@param pContentType    Pointer to the content type of the response.
@param contentTypeLen  Length of the content type.
@param pHttpResp       Pointer to PKCS7 response content from which the certificates
                       to be retrieved.
@param httpRespLen     Length of the response content.
@param pPCertificates  On return, Double pointer to the list of certificates.
@param pNumCerts       On return, Pointer to number of certificates.

@inc_file   est_client_api.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.c
*/
MSTATUS
EST_receiveResponse(ubyte *pContentType, ubyte4 contentTypeLen, ubyte *pHttpResp,
        ubyte4 httpRespLen, AsymmetricKey *pAsymKey,
        struct SizedBuffer  **pPCertificates, ubyte4 *pNumCerts)
{
    MSTATUS       status             = OK;
    ubyte         *pResponse         = NULL;
    ubyte4        responseLen        = 0;
    ubyte         *pEcodedSignData   = NULL;
    ubyte4        encodedSignDataLen = 0;
    ubyte         *pOut              = NULL;
    ubyte4        outLen             = 0;
    certDescriptor *pCertDescArray   = NULL;
    ubyte4        certDescArrayLen   = 0;
    ubyte4        i                  = 0;
    struct SizedBuffer  *pCertificates = NULL;

    if ( (NULL == pContentType) || (NULL == pHttpResp) ||
            (NULL == pPCertificates))
    {
        return ERR_NULL_POINTER;
    }
    if (OK > (status = EST_getResponse(pContentType, contentTypeLen, pHttpResp, httpRespLen,
                    &pResponse, &responseLen)))
    {
        goto exit;
    }

    if (responseLen > 0)
    {
        /* Use CERT_ENROLL_parseResponse to parse the PKCS7 response */
        /* If pAsymKey is provided, filter for chain only; otherwise return all certificates */
        if (OK > (status = CERT_ENROLL_parseResponse(pResponse, responseLen, pAsymKey, 
                                                      (pAsymKey != NULL) ? TRUE : FALSE,
                                                      &pCertDescArray, &certDescArrayLen)))
        {
            myPrintError("EST_receiveResponse::CERT_ENROLL_parseResponse::status: ", status);
            goto exit;
        }

        /* Convert certDescriptor array to SizedBuffer array with PEM encoding */
        if (certDescArrayLen > 0)
        {
            if (OK > (status = DIGI_MALLOC((void**)&pCertificates, certDescArrayLen * sizeof(struct SizedBuffer))))
            {
                goto exit;
            }
            if (OK > (status = DIGI_MEMSET((ubyte*)pCertificates, 0x00, certDescArrayLen * sizeof(struct SizedBuffer))))
            {
                goto exit;
            }

            for (i = 0; i < certDescArrayLen; i++)
            {
                /* Base64 encode the DER certificate */
                if (OK > (status = BASE64_encodeMessage(pCertDescArray[i].pCertificate, 
                                                        pCertDescArray[i].certLength, 
                                                        &pEcodedSignData, &encodedSignDataLen)))
                {
                    myPrintError("EST_receiveResponse::BASE64_encodeMessage::status: ", status);
                    goto exit;
                }

                /* Wrap with BEGIN/END CERTIFICATE blocks */
                if (OK > (status = EST_breakIntoLinesPKCS7(pEcodedSignData, encodedSignDataLen,
                                &pOut, &outLen, (const ubyte*)BEGIN_CERTIFICATE_BLOCK, (const ubyte*)END_CERTIFICATE_BLOCK)))
                {
                    myPrintError("EST_receiveResponse::EST_breakIntoLinesPKCS7::status: ", status);
                    goto exit;
                }

                pCertificates[i].length = outLen;
                pCertificates[i].data = pOut;
                pOut = NULL;

                if (pEcodedSignData != NULL)
                {
                    FREE(pEcodedSignData);
                    pEcodedSignData = NULL;
                }
            }

            *pPCertificates = pCertificates;
            pCertificates = NULL;
            *pNumCerts = certDescArrayLen;
        }
    }

exit:
    if (pCertDescArray)
    {
        for (i = 0; i < certDescArrayLen; i++)
        {
            CA_MGMT_freeCertificate(&pCertDescArray[i]);
        }
        DIGI_FREE((void**)&pCertDescArray);
    }

    if (pCertificates)
    {
        for (i = 0; i < certDescArrayLen; i++)
        {
            if (pCertificates[i].data)
            {
                FREE(pCertificates[i].data);
            }
        }
        DIGI_FREE((void**)&pCertificates);
    }

    if (pEcodedSignData != NULL)
    {
        FREE(pEcodedSignData);
    }

    if (pOut != NULL)
    {
        FREE(pOut);
    }

    if (pResponse)
        FREE(pResponse);

    return status;
}

static
sbyte4 EST_http_responseBodyCallback(httpContext *pHttpContext, ubyte *pDataReceived, ubyte4 dataLength, sbyte4 isContinueFromBlock)
{
    MSTATUS status = OK;
    sbyte *pContentLengthStr = NULL;
	MOC_UNUSED(isContinueFromBlock);

    /* the index for ContentLength */
    ubyte4 index = NUM_HTTP_RESPONSES + NUM_HTTP_GENERALHEADERS + ContentLength;

    /* if contentlength known, allocate memory only once */
    if (pHttpContext->receivedPendingDataLength <= 0 &&
            pHttpContext->responseBitmask[index/8] & (1<<(index & 7)))
    {
        sbyte *pStop;
        sbyte4 contentLength;
        HTTP_stringDescr *pStrDescr = &(pHttpContext->responses[index]);


        if (NULL == (pContentLengthStr = MALLOC(pStrDescr->httpStringLength+1)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        DIGI_MEMCPY(pContentLengthStr, pStrDescr->pHttpString, pStrDescr->httpStringLength);
        (pContentLengthStr)[pStrDescr->httpStringLength] = '\0';
        contentLength = DIGI_ATOL((sbyte*)pContentLengthStr, (const sbyte**)&pStop);
        FREE(pContentLengthStr);
        pContentLengthStr = NULL;
        if (pHttpContext->pReceivedPendingDataFree)
        {
            FREE(pHttpContext->pReceivedPendingDataFree);
        }
        pHttpContext->pReceivedPendingDataFree = pHttpContext->pReceivedPendingData = (ubyte*) MALLOC(contentLength);
    }

    /* accumulate response body in httpContext pReceivedDataPending */
    if (!(pHttpContext->responseBitmask[index/8] & (1<<(index & 7))))
    {
        ubyte *pNewBuffer = (ubyte*)MALLOC(pHttpContext->receivedPendingDataLength+dataLength);
        if (pHttpContext->receivedPendingDataLength > 0)
        {
            /* copy existing data */
            DIGI_MEMCPY(pNewBuffer, pHttpContext->pReceivedPendingDataFree, pHttpContext->receivedPendingDataLength);
        }
        DIGI_MEMCPY(pNewBuffer+pHttpContext->receivedPendingDataLength, pDataReceived, dataLength);
        if (pHttpContext->pReceivedPendingDataFree)
        {
            FREE(pHttpContext->pReceivedPendingDataFree);
        }
        pHttpContext->pReceivedPendingDataFree = pHttpContext->pReceivedPendingData = pNewBuffer;
    } else
    {
        DIGI_MEMCPY(pHttpContext->pReceivedPendingDataFree+pHttpContext->receivedPendingDataLength, pDataReceived, dataLength);
    }
    pHttpContext->receivedPendingDataLength += dataLength;

exit:
    return status;
}

/**
@brief      Handles the response data received from socket.

@details    This a callback function which handles the response data from
             http socket.

@param pHttpContext          Pointer to the http context.
@param pDataReceived         Pointer to the response data.
@param dataLength            Pointer to the response data length.
@param isContinueFromBlock   check if continue from block.

@inc_file   est_client_api.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.c
*/
MSTATUS EST_responseBodyCallbackHandle(httpContext *pHttpContext,
        ubyte *pDataReceived,
        ubyte4 dataLength,
        sbyte4 isContinueFromBlock)
{
    return EST_http_responseBodyCallback(pHttpContext, pDataReceived, dataLength, isContinueFromBlock);
}

static
sbyte4 EST_http_requestBodyCallback (httpContext *pHttpContext, ubyte **ppDataToSend, ubyte4 *pDataLength, void *pRequestBodyCookie)
{
    MSTATUS 				status = OK;
    requestBodyCookie 		*pCookie = NULL;

    if (pRequestBodyCookie)
    {
        pCookie = (requestBodyCookie*)pRequestBodyCookie;
        *pDataLength = (pCookie->dataLen - pCookie->curPos) > BLOCKSIZE ? BLOCKSIZE : (pCookie->dataLen - pCookie->curPos);
        if (NULL == (*ppDataToSend = MALLOC(*pDataLength)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        DIGI_MEMCPY(*ppDataToSend, pCookie->data + pCookie->curPos, *pDataLength);
        pCookie->curPos += (*pDataLength);
        if (pCookie->dataLen == pCookie->curPos)
        {
            pCookie->curPos = 0;
            pHttpContext->isBodyDone = TRUE;
        }
        else
        {
            pHttpContext->isBodyDone = FALSE;
        }
    }
    else
    {
        *ppDataToSend = NULL;
        *pDataLength = 0;
        pHttpContext->isBodyDone = TRUE;
    }

exit:
    return status;
}



/**
@brief      This API copies the request body.

@details    This a callback function which copies the request body.

@param pHttpContext        Pointer to the http context.
@param pPDataToSend        On return, Double pointer to the request.
@param pDataLength         On return, Pointer to the request length.
@param pRequestBodyCookie  Pointer to the cookie body.

@inc_file   est_client_api.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    est_client_api.c
*/
MSTATUS
EST_requestBodyCallback(httpContext *pHttpContext, ubyte **pPDataToSend, ubyte4 *pDataLength, void *pRequestBodyCookie)
{
    return EST_http_requestBodyCallback(pHttpContext, pPDataToSend, pDataLength, pRequestBodyCookie);
}

MOC_EXTERN MSTATUS
EST_validateReceivedCertificate(MOC_HW(hwAccelDescr hwAccelCtx)
    struct certStore *pCertStore, ubyte *pReceivedCertPem,
    ubyte4 receivedCertPemLen, TimeDate *pTime)
{
    MSTATUS         status;
    ubyte           *pReceivedCert = NULL;
    ubyte4          receivedCertLen;
    certDescriptor certDesc = {0};
    certChainPtr pCertChain = NULL;
    ValidationConfig vc = { 0 };
    TimeDate td = { 0 };

    if (!pReceivedCertPem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == receivedCertPemLen)
    {
        status = ERR_CERT_AUTH_BAD_CERT_LENGTH;
        goto exit;
    }

    if(OK > (status = CA_MGMT_decodeCertificate(pReceivedCertPem, receivedCertPemLen,
                          &pReceivedCert, &receivedCertLen)))
    {
        goto exit;
    }

    certDesc.pCertificate = pReceivedCert;
    certDesc.certLength = receivedCertLen;

    if (OK > (status = CERTCHAIN_createFromIKE(MOC_ASYM(hwAccelCtx) &pCertChain, &certDesc, 1)))
    {
        goto exit;
    }

    vc.keyUsage = 0;

    /* validate date & verify cert store */
    if (NULL == pTime)
    {
        if (OK > (status = RTOS_timeGMT(&td)))
            goto exit;

        pTime = &td;
    }

    vc.td = pTime;
    vc.pCertStore = pCertStore;

    if (OK > (status = CERTCHAIN_validate(MOC_ASYM(hwAccelCtx) pCertChain, &vc)))
    {
        goto exit;
    }

exit:

    if(pReceivedCert)
        DIGI_FREE((void **)&pReceivedCert);

    if(pCertChain)
        CERTCHAIN_delete(&pCertChain);

    return status;
}

MOC_EXTERN MSTATUS
EST_parseEndpoint(sbyte *pEndpoint, sbyte **ppServerName, sbyte **ppUrl)
{
    MSTATUS status = OK;
    URI *pUri = NULL;
    sbyte *pHost = NULL;
    sbyte *pFullPath = NULL;
    sbyte *pScheme = NULL;
    ubyte4 hostLen = 0;
    ubyte4 fullPathLen = 0;

    if (NULL == pEndpoint || NULL == ppServerName || NULL == ppUrl)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppServerName = NULL;
    *ppUrl = NULL;

    status = URI_ParseURI(pEndpoint, &pUri);
    if (OK != status)
    {
        myPrintError("EST_parseEndpoint::URI_ParseURI::status: ", status);
        goto exit;
    }

    status = URI_GetScheme(pUri, &pScheme);
    if (OK != status || NULL == pScheme)
    {
        myPrintError("EST_parseEndpoint::URI_GetScheme::status: ", status);
        goto exit;
    }

    if (0 != DIGI_STRCMP((const sbyte *)pScheme, EST_ENDPOINT_SCHEME))
    {
        status = ERR_INVALID_ARG;
        myPrintError("EST_parseEndpoint::Invalid scheme, must be 'https://'::status: ", status);
        goto exit;
    }

    status = URI_GetHost(pUri, &pHost);
    if (OK != status || NULL == pHost)
    {
        myPrintError("EST_parseEndpoint::Invalid server name::status: ", status);
        goto exit;
    }

    status = URI_GetFullPath(pUri, &pFullPath);
    if (OK != status || NULL == pFullPath)
    {
        myPrintError("EST_parseEndpoint::URI_GetFullPath::status: ", status);
        goto exit;
    }

    if (0 != DIGI_STRNCMP((const sbyte *)pFullPath, EST_ENDPOINT_WELL_KNOWN, DIGI_STRLEN(EST_ENDPOINT_WELL_KNOWN)))
    {
        status = ERR_INVALID_ARG;
        myPrintError("EST_parseEndpoint::Invalid path, must start with '/.well-known/est/'::status: ", status);
        goto exit;
    }

    hostLen = DIGI_STRLEN(pHost);
    status = DIGI_MALLOC_MEMCPY((void **)ppServerName, hostLen + 1, pHost, hostLen);
    if (OK != status)
    {
        myPrintError("EST_parseEndpoint::DIGI_MALLOC_MEMCPY::status: ", status);
        goto exit;
    }
    (*ppServerName)[hostLen] = '\0';

    fullPathLen = DIGI_STRLEN(pFullPath);
    status = DIGI_MALLOC_MEMCPY((void **)ppUrl, fullPathLen + 1, pFullPath, fullPathLen);
    if (OK != status)
    {
        myPrintError("EST_parseEndpoint::DIGI_MALLOC_MEMCPY::status: ", status);
        goto exit;
    }
    (*ppUrl)[fullPathLen] = '\0';

exit:

    if (NULL != pScheme)
        FREE(pScheme);
    if (NULL != pHost)
        FREE(pHost);
    if (NULL != pFullPath)
        FREE(pFullPath);
    if (NULL != pUri)
        URI_DELETE(pUri);
    if (OK != status)
    {
        if (NULL != ppServerName && NULL != *ppServerName)
        {
            DIGI_FREE((void **)ppServerName);
        }
        if (NULL != ppUrl && NULL != *ppUrl)
        {
            DIGI_FREE((void **)ppUrl);
        }
    }

    return status;
}

#endif /* (defined(__ENABLE_DIGICERT_EST_CLIENT__) && defined(__ENABLE_DIGICERT_EXAMPLES__)) */
