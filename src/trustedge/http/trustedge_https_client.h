/*
 * trustedge_https_client.h
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 *
 */


/*------------------------------------------------------------------*/

#ifndef __TRUSTEDGE_HTTPS_CLIENT_HEADER__
#define __TRUSTEDGE_HTTPS_CLIENT_HEADER__

#include "../../common/mjson.h"
#include "../../crypto/cert_store.h"

#include "../../http/http_context.h"

#define DEFAULT_TRANSACTION_TIMEOUT     (10)
#define DEFAULT_DOWNLOAD_TIMEOUT        (5 * 60)

#define DEFAULT_SERVER_RETRY_MAX_CNT    (2)
#define DEFAULT_SERVER_RETRY_DELAY_SECS (1 * 60)

typedef enum
{
    TRUSTEDGE_MSG_CUSTOM = 0
} TRUSTEDGE_RequestMsgType;

typedef struct HttpsClientCtx HttpsClientCtx;

typedef MSTATUS (*TRUSTEDGE_requestPrepareHeader)(
        HttpsClientCtx *pCtx, httpContext *pHttpContext);
typedef MSTATUS (*TRUSTEDGE_responseParse)(
        HttpsClientCtx *pCtx);

typedef struct HttpsClientCtx
{
    sbyte *                     serverAddress;
    sbyte *                     serverIPAddress;
    ubyte4                      serverPort;
    sbyte *                     serverRestPrefix;
    certStorePtr                pTrustStore;
    /* */
    intBoolean                  requireOSCPEnable;
    intBoolean                  mutualAuthEnable;
    sbyte *                     sslServerCertFileName;
    sbyte *                     sslClientCertFileName;
    sbyte *                     sslClientKeyFileName;
    sbyte *                     sslClientAlias;
    /* */
    sbyte *                     nonce;
    sbyte *                     signatureAlgoId;
    byteBoolean                 excludeChain;
    sbyte *                     serverURI;
    sbyte *                     signatureCertFileName;
    sbyte *                     signatureKeyFileName;
    sbyte *                     authType;
    sbyte *                     authValue;
    RTOS_THREAD                 threadHandle;
    MSTATUS                     workerStatus;
    ubyte4                      httpsTransactionTimeout;
    ubyte4                      httpsDownloadTimeout;
    void *                      pUserData;
    TRUSTEDGE_RequestMsgType           requestMsgType;
    TRUSTEDGE_requestPrepareHeader     requestPrepareHeader;
    sbyte *                     requestMsg;
    ubyte4                      requestMsgLen;
    ubyte4                      responseStatus;
    TRUSTEDGE_responseParse            responseParse;
    sbyte *                     responseMsg;
    ubyte4                      responseMsgLen;
    sbyte *                     responseMsgFileName;
    sbyte *                     responseBodyTempFileName;
    ubyte4                      responseBodyTempFD;
    ubyte4                      httpThreadRunning;
    RTOS_MUTEX                  httpThreadRunningLock;
    httpContext *               pCurrHttpContext;
    sbyte4                      connectionSSLInstance;
    intBoolean                  httpKillClient;
    sbyte *                     redirectURI;
    ubyte                       redirectURILen;
    intBoolean                  acceptOctetStream;
    sbyte *                     serverDownloadAddress;
    ubyte4                      serverDownloadPort;
    sbyte *                     serverDownloadURI;
    ubyte4                      serverRetryMaxCount;
    ubyte4                      serverRetryDelaySeconds;
    TCP_SOCKET                  serverSocket;
} HttpsClientCtx;

/*------------------------------------------------------------------*/

/* TRUSTEDGE_clientHttpsReleaseContext : de-initialize the context struct used
 *   for HTTPS operations in UM.
 *
 *   Parameters :
 *     HttpsClientCtx **ppContext :: The HTTPS context struct
 *       that is released by this call.
 *     MSTATUS *umStatus :: The supplemental status returned.
 */
MOC_EXTERN MSTATUS TRUSTEDGE_clientHttpsReleaseContext(
        HttpsClientCtx **ppContext,
        MSTATUS *umStatus);

/*------------------------------------------------------------------*/

/* TRUSTEDGE_clientHttpsLocalAcquireContext : Initialize the context struct used
 *   for local HTTPS operations
 *
 *   Parameters :
 *     sbyte *pRspDir :: Directory where HTTPS response is stored
 *     HttpsClientCtx **pNewContext :: The returned HTTPS
 *     context struct that is created by this call.
 */
MOC_EXTERN MSTATUS TRUSTEDGE_clientHttpsLocalAcquireContext(
        sbyte *pRspDir,
        HttpsClientCtx **ppNewContext);

/*------------------------------------------------------------------*/

/* TRUSTEDGE_clientHttpsLocalReleaseContext : de-initialize the context struct used
 *   for local HTTPS operations
 *
 *   Parameters :
 *     HttpsClientCtx **ppContext :: The HTTPS context struct
 *       that is released by this call.
 */
MOC_EXTERN MSTATUS TRUSTEDGE_clientHttpsLocalReleaseContext(
        HttpsClientCtx **ppContext);

/*------------------------------------------------------------------*/

/* TRUSTEDGE_clientHttpsLocalApplyServerConfig : apply server configuration to the
 *    local HTTPS context
 *
 *   Parameters :
 *     HttpsClientCtx *pCtx :: The HTTPS context struct
 *     sbyte *pHostName :: Host name to connect to
 *     ubyte4 port :: Port number to connect to
 *     certStorePtr pStore :: Certificate store used for SSL connection
 *     sbyte *pMutualAuthAlias :: Mutual authenticaion alias to pick up from the
 *       certificate store. If NULL, no mutual authentication is done.
 */
MOC_EXTERN MSTATUS TRUSTEDGE_clientHttpsLocalApplyServerConfig(
        HttpsClientCtx *pCtx,
        sbyte *pHostName,
        ubyte4 port,
        certStorePtr pStore,
        sbyte *pMutualAuthAlias);

/*------------------------------------------------------------------*/

/* TRUSTEDGE_clientHttpsLocalSetCustomMsg : set custom message and data/handlers for
 *    custom message in the local HTTPS context
 *
 *   Parameters :
 *     HttpsClientCtx *pCtx :: The HTTPS context struct
 *     ubyte *pMsg :: Message buffer
 *     ubyte4 msgLen :: Length of message in bytes
 *     void *pUserData :: User data provided to HTTP client callbacks
 *     TRUSTEDGE_requestPrepareHeader requestPrepareHeader :: HTTP header callback
 *     TRUSTEDGE_responseParse responseParse :: HTTP response callback
 */
MOC_EXTERN MSTATUS TRUSTEDGE_clientHttpsLocalSetCustomMsg(
        HttpsClientCtx *pCtx,
        ubyte *pMsg,
        ubyte4 msgLen,
        void *pUserData,
        TRUSTEDGE_requestPrepareHeader requestPrepareHeader,
        TRUSTEDGE_responseParse responseParse);

/*------------------------------------------------------------------*/

/* TRUSTEDGE_clientHttpsLocalGetUserData : get user data in the local HTTPS context
 *
 *   Parameters :
 *     HttpsClientCtx *pCtx :: The HTTPS context struct
 *     void **ppUserData :: Location where user data is stored
 */
MOC_EXTERN MSTATUS TRUSTEDGE_clientHttpsLocalGetUserData(
        HttpsClientCtx *pCtx,
        void **ppUserData);

/* TRUSTEDGE_clientHttpsAcquireContext : Initialize the context struct used
 *   for HTTPS operations in UM
 *
 *   Parameters :
 *     UM_DaemonCtx *ctx :: The context created for the UM daemon.
 *     JSON_ContextType *pConfigJson :: The context created for
 *       parsing the config.json file.
 *     UM_HttpsClientCtx **pNewContext :: The returned HTTPS
 *     context struct that is created by this call.
 *     MSTATUS *umStatus :: The supplemental status returned.
 */
MOC_EXTERN MSTATUS TRUSTEDGE_clientHttpsAcquireContext(
        HttpsClientCtx **ppNewContext,
        MSTATUS *umStatus);

/*------------------------------------------------------------------*/

#endif /* __TRUSTEDGE_HTTPS_CLIENT_HEADER__ */
